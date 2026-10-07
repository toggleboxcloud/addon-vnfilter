#!/usr/bin/env ruby

# -------------------------------------------------------------------------- #
# Copyright 2002-2022, StorPool                                              #
# Portion copyright OpenNebula Project, OpenNebula Systems                   #
#                                                                            #
# Licensed under the Apache License, Version 2.0 (the "License"); you may    #
# not use this file except in compliance with the License. You may obtain    #
# a copy of the License at                                                   #
#                                                                            #
# http://www.apache.org/licenses/LICENSE-2.0                                 #
#                                                                            #
# Unless required by applicable law or agreed to in writing, software        #
# distributed under the License is distributed on an "AS IS" BASIS,          #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   #
# See the License for the specific language governing permissions and        #
# limitations under the License.                                             #
#--------------------------------------------------------------------------- #

# NB! the hook is runnig on the KVM hosts so rubygem nokogiri must be installed
# on CentOS7: yum -y --enablerepo=epel install rubygem-nokogiri
#
# hook definition
#
#NAME = "vnfilter"
#TYPE = "state"
#ON = "CUSTOM"
#ARGUMENTS = "$TEMPLATE"
#ARGUMENTS_STDIN="YES"
#COMMAND="alias_ip/vnfilter.rb"
#REMOTE="YES"
#RESOURCE="VM"
#STATE="ACTIVE"
#LCM_STATE="HOTPLUG_NIC"
#

ONE_LOCATION = ENV['ONE_LOCATION']

if !ONE_LOCATION
    RUBY_LIB_LOCATION = '/usr/lib/one/ruby'
    GEMS_LOCATION     = '/usr/share/one/gems'
    PACKET_LOCATION   = '/usr/lib/one/ruby/vendors/packethost/lib'
    LOG_FILE          = '/var/log/one/hook-alias_ip.log'
else
    RUBY_LIB_LOCATION = ONE_LOCATION + '/lib/ruby'
    GEMS_LOCATION     = ONE_LOCATION + '/share/gems'
    PACKET_LOCATION   = ONE_LOCATION + '/ruby/vendors/packethost/lib'
    LOG_FILE          = ONE_LOCATION + '/var/net_fw_hook.log'
end

if File.directory?(GEMS_LOCATION)
    Gem.use_paths(GEMS_LOCATION)
end

$LOAD_PATH << RUBY_LIB_LOCATION
$LOAD_PATH << PACKET_LOCATION

require 'base64'
require 'nokogiri'
require 'open3'
require 'shellwords'
require 'syslog/logger'
require_relative '../../vnm/arp_guard'

###############################################################################
# Helpers

@slog = Syslog::Logger.new 'vnfilter_hook'

def log(msg, level = 'I')
    msg.lines do |line|
        puts(line)
        @slog.info "[#{level}] #{line}"
    end
end

def log_error(msg)
    log(msg, 'E')
end

def get_data(xpath, entries)
    data = Hash.new
    xentry = VM_XML.xpath(xpath)
    entries.each do |e|
        val = xentry.xpath(e)
        if !val.nil?
            key = e.downcase.to_sym
            if e.end_with?("_ID")
                data[key] = val.text.to_i
            else
                data[key] = val.text
            end
        end
    end
    data
end

def alias_nic_data()
    xpath = '//TEMPLATE/NIC_ALIAS[ATTACH="YES"]'
    entries = %w[ALIAS_ID PARENT_ID NAME IP IP6 IP6_GLOBAL IP6_LINK
                IPV6_PREFIX_LENGTH]
    get_data(xpath, entries)
end

def nic_data(nic_id)
    xpath = "//TEMPLATE/NIC[NIC_ID=#{nic_id}]"
    entries = %w[IP IP6 IP6_GLOBAL IP6_LINK VN_MAD ALIAS_IDS 
                 FILTER FILTER_IP_SPOOFING FILTER_MAC_SPOOFING
                 IPV6_PREFIX_LENGTH]
    get_data(xpath, entries)
end

def vm_data()
    vm = Hash.new
    data = get_data("//VM", %w[ID])
    vm[:id] = VM_XML.xpath('//VM/ID').text.to_i
    vm[:domain] = "one-#{vm[:id]}"
    vm[:a] = alias_nic_data()
    nic_id = vm[:a][:parent_id]
    vm[:n] = nic_data(nic_id)

    vm[:nicdev] = "#{vm[:domain]}-#{nic_id}"
    vm[:a][:idx] = vm[:a][:name].split('_ALIAS')[1].to_i

    vm[:action] = 'del'
    if !vm[:n][:alias_ids].nil? and !vm[:n][:alias_ids].empty?
        vm[:n][:alias_ids].split(',').each do |idx|
            if vm[:a][:idx] == idx.to_i
                vm[:action] = 'add'
            end
        end
    end
    #log("#{vm}")
    vm
end

# Capture argv directly: addresses and names must never become shell syntax.
def capture(cmds)
    stdout, stderr, status = Open3.capture3(*cmds)
    log("(#{status.exitstatus}) #{Shellwords.join(cmds)}")
    log_error("PID[#{status.pid}] #{stderr}") unless status.success?
    [stdout, stderr, status.success?]
end

def run(cmds)
    capture(cmds).last
end

# Share the VNM lifecycle driver's lock. Read/modify/read must serialize with
# chain rebuilds and other alias hooks, not just individual ebtables commands.
def with_vnfilter_lock(path = '/tmp/onevnm-vnfilter-lock')
    AddonFirewallSafety.with_lock(path) { yield }
end

# A failed read is not proof that a whitelist rule is absent. Only a complete
# nat-table dump may be used to decide whether a mutation is necessary.
def arp_rule_count(chain, rule, ip)
    stdout, _, success = capture(['sudo', '-n', 'ebtables-save'])
    return nil unless success

    inventory = AddonFirewallSafety::Inventory.new(stdout, table: 'nat', ebtables: true)
    inventory.matching(chain, ['-p', 'ARP', rule, ip, '-j', 'RETURN']).length
rescue AddonFirewallSafety::Error => e
    log_error("Invalid ebtables inventory: #{e.message}")
    nil
end

def transient_ebtables_error?(stderr)
    AddonFirewallSafety.transient?(stderr)
end

# Retry this rule only, and read back after each command. A backend can apply a
# mutation and still report an error; replaying successful -A commands blindly
# would duplicate rules. Deletion also removes duplicates left by older hooks.
def reconcile_arp_rule(chain, rule, ip, add, max_attempts: 5)
    max_attempts.times do |attempt|
        count = arp_rule_count(chain, rule, ip)
        return false if count.nil?
        return true if add ? count > 0 : count == 0

        action = add ? '-A' : '-D'
        _, stderr, success = capture(
            ['sudo', '-n', 'ebtables', '--concurrent', '-t', 'nat', action,
             chain, '-p', 'ARP', rule, ip, '-j', 'RETURN']
        )
        return false unless success || transient_ebtables_error?(stderr) ||
            (!add && AddonFirewallSafety.missing?(stderr))

        count = arp_rule_count(chain, rule, ip)
        return false if count.nil?
        return true if add ? count > 0 : count == 0

        sleep(0.2 * (attempt + 1)) if attempt + 1 < max_attempts
    end
    log_error("ARP whitelist did not converge for #{chain} #{ip}")
    false
end

def toggle_ebtables_filter(vm)
    return true if vm[:a][:ip].nil? || vm[:a][:ip].empty?

    success = true
    ['i', 'o'].each do |direction|
        rule = direction == 'o' ? '--arp-ip-dst' : '--arp-ip-src'
        chain = "#{vm[:nicdev]}-#{direction}-arp4"
        result = reconcile_arp_rule(chain, rule, vm[:a][:ip], vm[:action] == 'add')
        success = result && success
    end
    success
end

def toggle_ipset_filter(vm)
    success = true
    ['IP', 'IP6', 'IP6_GLOBAL'].each do |e|
        key = e.downcase.to_sym
        if !vm[:a][key].nil? and !vm[:a][key].empty?
            chain = "#{vm[:nicdev]}-#{e.split('_')[0].downcase}-spoofing"
            ipv6net = vm[:a][key]
            ipv6net += "/#{vm[:a][:ipset_prefix_length]}" \
                if !vm[:a][:ipset_prefix_length].nil? && \
                    !vm[:a][:ipset_prefix_length].empty? && \
                    key == :ip6
            result = run(['sudo', '-n', 'ipset', '-exist', vm[:action], chain, ipv6net])
            success = result && success
            if e == 'IP6_GLOBAL' and !vm[:a][:ip6_link].nil?
                link = vm[:a][:ip6_link]
                result = run(['sudo', '-n', 'ipset', '-exist', vm[:action], chain, link])
                success = result && success
            end
        end
    end
    success
end


###############################################################################
# Main
#

if $PROGRAM_NAME == __FILE__
    log("vnfilter hook BEGIN")

    mutations_ok = false
    begin
        vm_xml_raw = Base64.decode64(STDIN.read)
        vm_xml = Nokogiri::XML(vm_xml_raw)
        VM_XML = vm_xml

        vm = vm_data()

        with_vnfilter_lock do
            filters = Hash.new
            filters[:filter_ip_spoofing] = method(:toggle_ipset_filter)
            filters[:filter_mac_spoofing] = method(:toggle_ebtables_filter)

            mutations_ok = true
            filters.each do |key, method|
                next unless vm[:n][key] == 'YES'

                result = method.(vm)
                mutations_ok = result && mutations_ok
            end

            if mutations_ok
                mutations_ok = VnfilterArpGuard.reconcile(logger: @slog)
            else
                log_error('Alias mutation failed; forcing the ARP guard open')
                VnfilterArpGuard.fail_open(logger: @slog)
            end
        end

    rescue StandardError => e
        mutations_ok = false
        log_error("Alias hook failed: #{e.class}: #{e.message}")
        VnfilterArpGuard.fail_open(logger: @slog)
    end

    log('vnfilter hook END')

    exit(mutations_ok ? 0 : 1)
end
