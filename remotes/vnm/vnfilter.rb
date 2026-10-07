# rubocop:disable Naming/FileName
# vim: ts=4 sw=4 et
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

require 'vnmmad'
require 'syslog/logger'
require_relative 'arp_guard'
require_relative 'vnfilter_firewall_safety'

# IP filter for aliases
class VnFilter < VNMMAD::VNMDriver
    include AddonFirewallSafety::LifecycleLock

    def tap_name(vm_id, nic_id)
        unless vm_id.to_s.match?(/\A\d+\z/) && nic_id.to_s.match?(/\A\d+\z/)
            raise AddonFirewallSafety::Error, 'invalid VM or NIC identifier'
        end
        "one-#{vm_id}-#{nic_id}"
    end

    def firewall_lock_path
        '/tmp/onevnm-vnfilter-lock'
    end

    def iptables_inventory(ipv6)
        tool = ipv6 ? 'ip6tables' : 'iptables'
        prefix = Shellwords.split(VNMMAD::VNMNetwork::COMMANDS.fetch(tool.to_sym))
        AddonFirewallSafety::Backend.new(tool: tool, table: 'filter', prefix: prefix).inventory
    end

    def ebtables_backend
        @ebtables_backend ||= AddonFirewallSafety::Backend.new(tool: 'ebtables', table: 'nat', sleeper: method(:sleep))
    end

    class EbtablesCommandError < StandardError

        attr_reader :args, :stderr

        def initialize(command, args, stderr)
            @args = args
            @stderr = stderr

            super("Command Error: #{command} #{args}\n#{stderr}")
        end

    end

    DRIVER = 'vnfilter'
    XPATH_FILTER = 'TEMPLATE/NIC|TEMPLATE/NIC_ALIAS'

    def initialize(vm_template, xpath_filter = nil, deploy_id = nil)
        @locking = true
        @slog = Syslog::Logger.new 'vnfilter'
        xpath_filter ||= XPATH_FILTER
        @slog.info "initialize #{xpath_filter} //#{caller[-1]}"
        super(vm_template, xpath_filter, deploy_id)
        @locking = true
    end

    def reconcile_arp_guard
        raise AddonFirewallSafety::Error, 'ARP guard reconciliation failed' unless VnfilterArpGuard.reconcile(logger: @slog)
    end

    def ebtables_mutation_command
        'sudo -n ebtables --concurrent'
    end

    def add_ebtables_mutation(commands, args)
        if commands.respond_to?(:add)
            commands.add ebtables_mutation_command, args
        else
            commands << args
        end
    end

    def run_ebtables_mutation!(args, context)
        @slog.info "[#{context}] ebtables #{args}"
        tokens = Shellwords.split(args)
        raise AddonFirewallSafety::Error, 'expected nat mutation' unless tokens.shift(2) == ['-t', 'nat']
        ebtables_backend.reconcile(tokens)
    rescue AddonFirewallSafety::Error => e
        raise EbtablesCommandError.new(ebtables_mutation_command, args, e.message)
    end

    def execute_ebtables_commands!(chain, commands)
        ebtables_backend.inventory(refresh: true)
        commands.each { |command| run_ebtables_mutation!(command, "activate #{chain}") }
    end

    def build_mac_spoofing_ebtables_commands(chain, chain_i, chain_o, nic, nicdata)
        unless chain.match?(/\Aone-\d+-\d+\z/) && chain_i == "#{chain}-i" && chain_o == "#{chain}-o"
            raise AddonFirewallSafety::Error, 'invalid vnfilter chain names'
        end
        mac = Shellwords.escape(nic[:mac].to_s)
        commands = []

        add_ebtables_mutation(commands, "-t nat -N #{chain_i}-arp4 -P DROP")
        add_ebtables_mutation(commands, "-t nat -N #{chain_o}-arp4 -P DROP")

        if !nicdata[:ip4].nil? and !nicdata[:ip4].empty?
            nicdata[:ip4].each do |ip|
                ip = Shellwords.escape(ip)
                @slog.info "ARP whitelist #{ip} (#{chain})"
                add_ebtables_mutation(commands, "-t nat -A #{chain_i}-arp4 -p ARP "\
                    "--arp-ip-src #{ip} -j RETURN")
                add_ebtables_mutation(commands, "-t nat -A #{chain_o}-arp4 -p ARP "\
                    "--arp-ip-dst #{ip} -j RETURN")
            end
        end

        add_ebtables_mutation(commands, "-t nat -N #{chain_i}-arp -P DROP")
        add_ebtables_mutation(commands, "-t nat -A #{chain_i}-arp -p ARP "\
            "-s ! #{mac} -j DROP")
        add_ebtables_mutation(commands, "-t nat -A #{chain_i}-arp -p ARP "\
            "--arp-mac-src ! #{mac} -j DROP")
        add_ebtables_mutation(commands, "-t nat -A #{chain_i}-arp -p ARP "\
            "-j #{chain_i}-arp4")
        add_ebtables_mutation(commands, "-t nat -A #{chain_i}-arp -p ARP "\
            "--arp-op Request -j ACCEPT")
        add_ebtables_mutation(commands, "-t nat -A #{chain_i}-arp -p ARP "\
            "--arp-op Reply -j ACCEPT")
        add_ebtables_mutation(commands, "-t nat -N #{chain_i}-rarp -P DROP")
        add_ebtables_mutation(commands, "-t nat -A #{chain_i}-rarp -p 0x8035 "\
            "-s #{mac} -d Broadcast --arp-op Request_Reverse "\
            "--arp-ip-src 0.0.0.0 --arp-ip-dst 0.0.0.0 "\
            "--arp-mac-src #{mac} --arp-mac-dst #{mac} "\
            "-j ACCEPT")
        add_ebtables_mutation(commands, "-t nat -N #{chain_i} -P ACCEPT")
        add_ebtables_mutation(commands, "-t nat -A #{chain_i} -p IPv4 "\
            "-j ACCEPT")
        add_ebtables_mutation(commands, "-t nat -A #{chain_i} -p IPv6 "\
            "-j ACCEPT")
        add_ebtables_mutation(commands, "-t nat -A #{chain_i} -p ARP "\
            "-j #{chain_i}-arp")
        add_ebtables_mutation(commands, "-t nat -A #{chain_i} -p 0x8035 "\
            "-j #{chain_i}-rarp")
        add_ebtables_mutation(commands, "-t nat -A PREROUTING -i #{chain} "\
            "-j #{chain_i}")

        add_ebtables_mutation(commands, "-t nat -N #{chain_o}-arp -P DROP")
        add_ebtables_mutation(commands, "-t nat -A #{chain_o}-arp -p ARP "\
            "--arp-op Reply --arp-mac-dst ! #{mac} -j DROP")
        add_ebtables_mutation(commands, "-t nat -A #{chain_o}-arp -p ARP "\
            "-j #{chain_o}-arp4")
        add_ebtables_mutation(commands, "-t nat -A #{chain_o}-arp -p ARP "\
            "--arp-op Request -j ACCEPT")
        add_ebtables_mutation(commands, "-t nat -A #{chain_o}-arp -p ARP "\
            "--arp-op Reply -j ACCEPT")
        add_ebtables_mutation(commands, "-t nat -N #{chain_o}-rarp -P DROP")
        add_ebtables_mutation(commands, "-t nat -A #{chain_o}-rarp -p 0x8035 "\
            "-d Broadcast --arp-op Request_Reverse "\
            "--arp-ip-src 0.0.0.0 --arp-ip-dst 0.0.0.0 "\
            "--arp-mac-src #{mac} --arp-mac-dst #{mac} "\
            "-j ACCEPT")
        add_ebtables_mutation(commands, "-t nat -N #{chain_o} -P ACCEPT")
        add_ebtables_mutation(commands, "-t nat -A #{chain_o} -p IPv4 "\
            "-j ACCEPT")
        add_ebtables_mutation(commands, "-t nat -A #{chain_o} -p IPv6 "\
            "-j ACCEPT")
        add_ebtables_mutation(commands, "-t nat -A #{chain_o} -p ARP "\
            "-j #{chain_o}-arp")
        add_ebtables_mutation(commands, "-t nat -A #{chain_o} -p 0x8035 "\
            "-j #{chain_o}-rarp")
        add_ebtables_mutation(commands, "-t nat -A POSTROUTING -o #{chain} "\
            "-j #{chain_o}")

        commands
    end

    def run_ebtables_cleanup!(args)
        run_ebtables_mutation!(args, 'cleanup')
    end

    def append_ebtables(chain, ipv4)
        commands = %w[i o].map do |direction|
            address_option = direction == 'i' ? '--arp-ip-src' : '--arp-ip-dst'
            Shellwords.join(['-t', 'nat', '-A', "#{chain}-#{direction}-arp4", '-p', 'ARP', address_option, ipv4, '-j', 'RETURN'])
        end
        execute_ebtables_commands!(chain, commands)
        true
    end

    def activate
        ipv4_offset = 2
        ipv6_offset = 5
        lock
        vm_id = vm['ID']
        attach_nic_id = vm['TEMPLATE/NIC[ATTACH="YES"]/NIC_ID']
        parent_id = vm['TEMPLATE/NIC_ALIAS[ATTACH="YES"]/PARENT_ID']
        caller_mad = caller[-1].split('/')[-3]
        if parent_id
            parent_mac_spoofing = vm["TEMPLATE/NIC[NIC_ID=#{parent_id}]/FILTER_MAC_SPOOFING"]
            if !parent_mac_spoofing.nil? && !parent_mac_spoofing.empty?
                if parent_mac_spoofing.upcase != 'YES'
                    @slog.warn "activate() VM #{vm_id} Warning: parent NIC_ID #{parent_id} has FILTER_MAC_SPOOFING=#{parent_mac_spoofing}! //SKIP"
                    return
                end
            else
                @slog.warn "activate() VM #{vm_id} Warning: no FILTER_MAC_SPOOFING enabled on parent NIC_ID #{parent_id}! //SKIP"
                return
            end
            ipv4 = vm['TEMPLATE/NIC_ALIAS[ATTACH="YES"]/IP']
            if ipv4
                @slog.info "activate() VM #{vm_id} parent_id:#{parent_id} BEGIN"
                chain = tap_name(vm_id, parent_id)
                if append_ebtables(chain, ipv4)
                    @slog.info "activate() VM #{vm_id} parent_id:#{parent_id} END"
                    reconcile_arp_guard
                    return
                end
            end
        end
        @slog.info "activate() VM #{vm_id} (#{attach_nic_id}) parent_id:#{parent_id} BEGIN"
        # pre-process
        nics = Hash.new
        process do |nic|
            nic_id = nic[:nic_id]
            ip4 = Array.new
            ip6 = Array.new
            [:ip, :vrouter_ip].each do |key|
                if !nic[key].nil? && !nic[key].empty?
                    ip4 << nic[key]
                end
            end
            [:ip6, :ip6_global, :ip6_link].each do |key|
                # Skip IPv6 link local address for alias interfaces
                next if !nic[:alias_id].nil? && key == "ip6_link"
                if !nic[key].nil? && !nic[key].empty?
                    ipv6net = nic[key]
                    ipv6net += "/#{nic[:ipset_prefix_length]}"\
                        if key == :ip6 && !nic[:ipset_prefix_length].nil? &&\
                           !nic[:ipset_prefix_length].empty?
                    ip6 << ipv6net
                end
            end
            if !nic[:alias_id].nil?
                parent_id = nic[:parent_id]
                if nics[parent_id].nil?
                    nics[parent_id] = Hash.new
                    nics[parent_id][:ip4] = Array.new
                    nics[parent_id][:ip6] = Array.new
                end
                nics[parent_id][:ip4].push(*ip4)
                nics[parent_id][:ip6].push(*ip6)
                next
            end
            if nics[nic_id].nil?
                nics[nic_id] = Hash.new
                nics[nic_id][:ip4] = ip4
                nics[nic_id][:ip6] = ip6
            else
                nics[nic_id][:ip4].push(*ip4)
                nics[nic_id][:ip6].push(*ip6)
            end
            nics[nic_id][:nic] = nic
        end

        nics.each do |nic_id, nicdata|
            nic = nicdata[:nic]
            vn_mad = nic[:vn_mad]
            if caller_mad != vn_mad
                @slog.info "VM #{vm_id} nic_id #{nic_id} #{vn_mad} Skip caller VN_MAD is #{caller_mad}"
                next
            end
            @slog.info "VM #{vm_id} nic_id #{nic_id} attach_nic_id:#{attach_nic_id}"
            OpenNebula::DriverLogger.log_info "VM #{vm_id} nic_id #{nic_id} #{vn_mad} attach_nic_id #{attach_nic_id}"
            next if attach_nic_id and attach_nic_id != nic_id
            chain = tap_name(vm_id, nic_id)
            chain_i = "#{chain}-i"
            chain_o = "#{chain}-o"

            commands =  AddonFirewallSafety::Commands.new

            if nic[:filter_ip_spoofing] == "YES"
                @slog.info "VM #{vm_id} NIC #{nic_id} FILTER_IP_SPOOFING"
                ipv4_state = iptables_inventory(false)
                ipv6_state = iptables_inventory(true)
                raise AddonFirewallSafety::Error, "missing IPv6 chain #{chain_o}" unless ipv6_state.chains.key?(chain_o)
                raise AddonFirewallSafety::Error, "missing IPv4 chain #{chain_o}" unless ipv4_state.chains.key?(chain_o)
                spoof_rule = ['-m', 'set', '!', '--match-set', "#{chain}-ip-spoofing", 'src', '-j', 'DROP']
                if ipv4_state.matching(chain_o, spoof_rule).empty?
                    @slog.info "patching #{chain_o} to add #{chain}-ip-spoofing"
                    commands.add :ipset, "create -exist #{chain}-ip-spoofing hash:ip family inet"
                    commands.add :iptables, "-R #{chain_o} #{ipv4_offset} -m set ! --match-set #{chain}-ip-spoofing src -j DROP"
                    commands.add :iptables, "-I #{chain_o} #{ipv4_offset} -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp --sport 68 --dport 67 -j RETURN"
                end
                if !nicdata[:ip4].nil? and !nicdata[:ip4].empty?
                    nicdata[:ip4].each do |ip|
                        @slog.info "ipset add #{chain}-ip-spoofing #{ip}"
                        commands.add :ipset, "add -exist #{chain}-ip-spoofing #{Shellwords.escape(ip)}"
                    end
                end
                commands.run! if commands.any?
                if !nicdata[:ipset_prefix_length].nil? &&
                    !nicdata[:ipset_prefix_length].empty?
                    ipset_hash = "hash:net"
                else
                    ipset_hash = "hash:ip"
                end
                spoof_rule = ['-m', 'set', '!', '--match-set', "#{chain}-ip6-spoofing", 'src', '-j', 'DROP']
                if ipv6_state.matching(chain_o, spoof_rule).empty?
                    @slog.debug "altering #{chain_o} to add #{chain}-ip6-spoofing"
                    commands.add :ipset, "create -exist #{chain}-ip6-spoofing #{ipset_hash} family inet6"
                    commands.add :ip6tables, "-R #{chain_o} #{ipv6_offset} -m set ! --match-set #{chain}-ip6-spoofing src -j DROP"
                end
                if !nicdata[:ip6].nil? and !nicdata[:ip6].empty?
                    nicdata[:ip6].each do |ipv6|
                        @slog.info "ipset add #{chain}-ip6-spoofing #{ipv6}"
                        commands.add :ipset, "add -exist #{chain}-ip6-spoofing #{Shellwords.escape(ipv6)}"
                    end
                end
                commands.run! if commands.any?
            end

            if nic[:filter_mac_spoofing] == "YES"
                @slog.info "VM #{vm_id} NIC #{nic_id} FILTER_MAC_SPOOFING"
                deactivate_ebtables(chain)
                ebtables_commands = build_mac_spoofing_ebtables_commands(
                    chain,
                    chain_i,
                    chain_o,
                    nic,
                    nicdata
                )

                execute_ebtables_commands!(chain, ebtables_commands)
            end
        end
        @slog.info "activate() VM #{vm_id} END"
        reconcile_arp_guard
    rescue StandardError
        VnfilterArpGuard.fail_open(logger: @slog)
        raise
    ensure
        unlock
    end

    def deactivate
        lock
        vm_id = vm['ID']
        caller_mad = caller[-1].split('/')[-3]
        @slog.info "deactivate() VM #{vm_id} caller_mad:#{caller_mad} BEGIN"
        res = false
        attach = false
        nics = Hash.new
        process do |nic|
            next if caller_mad != nic[:vn_mad]
            nic_id = nic[:nic_id]
            chain = tap_name(vm_id, nic_id)
            if nic[:attach]
                @slog.info "VM #{vm_id} NIC #{nic_id} vn_mad=#{nic[:vn_mad]} parent=#{nic[:parent]} ip=#{nic[:ip]}"
                attach = true
                if nic[:parent].nil?
                    deactivate_ebtables(chain)
                else
                    deactivate_ebtables(chain, nic[:ip]) if !nic[:ip].nil?
                end
            else
                if nic[:parent].nil?
                    nics[nic_id] = nic
                end
            end
        end
        if !attach
            nics.each do |nic_id, nic|
                @slog.info "VM #{vm_id} NIC #{nic_id} vn_mad=#{nic[:vn_mad]} down"
                deactivate_ebtables(tap_name(vm_id, nic_id))
            end
        end
        @slog.info "deactivate() VM #{vm_id} END"
        reconcile_arp_guard
    rescue StandardError
        VnfilterArpGuard.fail_open(logger: @slog)
        raise
    ensure
        unlock
    end

    def owned_ebtables_chain?(name, tap)
        name.match?(/\A#{Regexp.escape(tap)}-[io](?:-arp4|-arp|-rarp)?\z/)
    end

    def collect_ebtables_cleanup_commands(chain, ebtables_nat, ipv4 = nil)
        state = ebtables_nat.is_a?(AddonFirewallSafety::Inventory) ? ebtables_nat :
            AddonFirewallSafety::Inventory.new(ebtables_nat, table: 'nat', ebtables: true)
        if ipv4
            return state.rules.filter_map do |rule|
                next unless ["#{chain}-i-arp4", "#{chain}-o-arp4"].include?(rule[1])
                option = rule[1] == "#{chain}-i-arp4" ? '--arp-ip-src' : '--arp-ip-dst'
                wanted = ['-p', 'ARP', option, ipv4, '-j', 'RETURN']
                next unless AddonFirewallSafety.rule_key(rule.drop(2)) == AddonFirewallSafety.rule_key(wanted)
                Shellwords.join(['-t', 'nat', '-D'] + rule.drop(1))
            end
        end

        owned = state.chains.keys.select { |name| owned_ebtables_chain?(name, chain) }
        commands = state.rules.filter_map do |rule|
            jump = rule.index('-j')
            next unless jump && owned.include?(rule[jump + 1])
            next if owned.include?(rule[1]) # flushing owned chains removes internal jumps
            expected = case rule[1]
                       when 'PREROUTING' then ['-i', chain, '-j', "#{chain}-i"]
                       when 'POSTROUTING' then ['-o', chain, '-j', "#{chain}-o"]
                       end
            next unless expected && AddonFirewallSafety.rule_key(rule.drop(2)) == AddonFirewallSafety.rule_key(expected)
            Shellwords.join(['-t', 'nat', '-D'] + rule.drop(1))
        end
        commands + owned.map { |name| Shellwords.join(['-t', 'nat', '-F', name]) } +
            owned.map { |name| Shellwords.join(['-t', 'nat', '-X', name]) }
    end

    def deactivate_ebtables(chain, ipv4 = nil)
        commands = collect_ebtables_cleanup_commands(chain, ebtables_backend.inventory(refresh: true), ipv4)
        commands.each { |command| run_ebtables_cleanup!(command) }
        remaining = collect_ebtables_cleanup_commands(chain, ebtables_backend.inventory, ipv4)
        raise AddonFirewallSafety::Error, "ebtables cleanup incomplete for #{chain}" unless remaining.empty?
    end
end
