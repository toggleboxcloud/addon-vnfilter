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

# IP filter for aliases
class VnFilter < VNMMAD::VNMDriver

    class EbtablesCommandError < StandardError

        attr_reader :args, :stderr

        def initialize(command, args, stderr)
            @args = args
            @stderr = stderr

            super("Command Error: #{command} #{args}\n#{stderr}")
        end

    end

    class EbtablesCleanupBusyError < EbtablesCommandError
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

    def read_ebtables_nat
        commands =  VNMMAD::VNMNetwork::Commands.new
        commands.add "sudo -n", "ebtables-save"
        commands.run!
    end

    def retryable_ebtables_activation_error?(command, stderr)
        return false unless command.match?(/ -[AN] /)
        return false if stderr.nil? || stderr.empty?

        stderr.include?('RULE_DELETE failed') &&
            stderr.include?('No such file or directory')
    end

    def busy_ebtables_cleanup_error?(command, stderr)
        return false unless command.match?(/ -[FX] /)
        return false if stderr.nil? || stderr.empty?

        stderr.include?('CHAIN_USER_DEL failed (Device or resource busy)')
    end

    def log_ebtables_chain_snapshot(chain, ebtables_nat = nil)
        ebtables_nat ||= read_ebtables_nat

        snapshot = ebtables_nat.each_line.select { |line| line.include?(chain) }

        if snapshot.empty?
            @slog.warn "[snapshot] no ebtables nat entries found for #{chain}"
            return
        end

        snapshot.each { |line| @slog.warn "[snapshot] #{line.strip}" }
    end

    def run_ebtables_mutation!(args, context)
        @slog.info "[#{context}] ebtables #{args}"
        stdout, stderr, status =
            VNMMAD::VNMNetwork::Command.run(ebtables_mutation_command, args)

        return stdout if status.success?

        @slog.warn "[#{context}] ebtables failed: #{args}"
        @slog.warn stderr unless stderr.nil? || stderr.empty?

        raise EbtablesCommandError.new(ebtables_mutation_command, args, stderr)
    end

    def execute_ebtables_commands!(chain, commands, retry_on_rule_delete: false, max_retries: 2)
        attempts = 0

        loop do
            last_successful = nil

            begin
            commands.each do |command|
                run_ebtables_mutation!(command, "activate #{chain}")
                last_successful = command
            end
                return
            rescue EbtablesCommandError => e
                @slog.warn "[activate #{chain}] last successful ebtables command: #{last_successful}" \
                    unless last_successful.nil?

                if retry_on_rule_delete &&
                   attempts < max_retries &&
                   retryable_ebtables_activation_error?(e.args, e.stderr)
                    attempts += 1
                    @slog.warn "[activate #{chain}] retrying after transient ebtables failure "\
                        "(attempt #{attempts} of #{max_retries}): #{e.args}"
                    log_ebtables_chain_snapshot(chain)
                    deactivate_ebtables(chain)
                    sleep attempts
                    next
                end

                raise
            end
        end
    end

    def build_mac_spoofing_ebtables_commands(chain, chain_i, chain_o, nic, nicdata)
        commands = []

        add_ebtables_mutation(commands, "-t nat -N #{chain_i}-arp4 -P DROP")
        add_ebtables_mutation(commands, "-t nat -N #{chain_o}-arp4 -P DROP")

        if !nicdata[:ip4].nil? and !nicdata[:ip4].empty?
            nicdata[:ip4].each do |ip|
                @slog.info "ARP whitelist #{ip} (#{chain})"
                add_ebtables_mutation(commands, "-t nat -A #{chain_i}-arp4 -p ARP "\
                    "--arp-ip-src #{ip} -j RETURN")
                add_ebtables_mutation(commands, "-t nat -A #{chain_o}-arp4 -p ARP "\
                    "--arp-ip-dst #{ip} -j RETURN")
            end
        end

        add_ebtables_mutation(commands, "-t nat -N #{chain_i}-arp -P DROP")
        add_ebtables_mutation(commands, "-t nat -A #{chain_i}-arp -p ARP "\
            "-s ! #{nic[:mac]} -j DROP")
        add_ebtables_mutation(commands, "-t nat -A #{chain_i}-arp -p ARP "\
            "--arp-mac-src ! #{nic[:mac]} -j DROP")
        add_ebtables_mutation(commands, "-t nat -A #{chain_i}-arp -p ARP "\
            "-j #{chain_i}-arp4")
        add_ebtables_mutation(commands, "-t nat -A #{chain_i}-arp -p ARP "\
            "--arp-op Request -j ACCEPT")
        add_ebtables_mutation(commands, "-t nat -A #{chain_i}-arp -p ARP "\
            "--arp-op Reply -j ACCEPT")
        add_ebtables_mutation(commands, "-t nat -N #{chain_i}-rarp -P DROP")
        add_ebtables_mutation(commands, "-t nat -A #{chain_i}-rarp -p 0x8035 "\
            "-s #{nic[:mac]} -d Broadcast --arp-op Request_Reverse "\
            "--arp-ip-src 0.0.0.0 --arp-ip-dst 0.0.0.0 "\
            "--arp-mac-src #{nic[:mac]} --arp-mac-dst #{nic[:mac]} "\
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
            "--arp-op Reply --arp-mac-dst ! #{nic[:mac]} -j DROP")
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
            "--arp-mac-src #{nic[:mac]} --arp-mac-dst #{nic[:mac]} "\
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

    def ignorable_ebtables_cleanup_error?(command, stderr)
        return false unless command.match?(/ -[DFX] /)
        return false if stderr.nil? || stderr.empty?

        missing_target = stderr.include?('No such file or directory') ||
                         stderr.include?('does not exist') ||
                         stderr.include?('No chain/target/match by that name')

        missing_target
    end

    def run_ebtables_cleanup!(args)
        @slog.info "[run] ebtables #{args}"
        stdout, stderr, status =
            VNMMAD::VNMNetwork::Command.run(ebtables_mutation_command, args)

        return stdout if status.success?

        if ignorable_ebtables_cleanup_error?(args, stderr)
            @slog.warn "Ignoring missing ebtables cleanup target: #{args}"
            @slog.warn stderr

            return stdout
        end

        if busy_ebtables_cleanup_error?(args, stderr)
            raise EbtablesCleanupBusyError.new(ebtables_mutation_command, args, stderr)
        end

        raise EbtablesCommandError.new(ebtables_mutation_command, args, stderr)
    end

    def append_ebtables(chain, ipv4)
        @slog.info "activate_ebtables(#{chain},#{ipv4})"
        dirs = { "i" => "src", "o" => "dst" }
        ret = false
        commands = []
        ebtables_nat = read_ebtables_nat
        if !ebtables_nat.nil?
            ebtables_nat.split("\n").each do |rule|
                if rule.match(/-A #{chain}-([io]{1})-arp4/)
                    dir = $+
                    rule_e = rule.split
                    ip = rule_e[5]
                    if ipv4 == rule_e[5]
                        @slog.info "[match] #{rule} // #{ip} #{dir}"
                        dirs.delete(dir)
                        ret = true
                    end
                end
            end
        end
        if dirs.any?
            dirs.each do |k,v|
                @slog.info "whitelist arp-ip-#{v} #{ipv4} (#{k})"
                add_ebtables_mutation(commands, "-t nat -A #{chain}-#{k}-arp4 -p ARP "\
                    "--arp-ip-#{v} #{ipv4} -j RETURN")
                ret = true
            end
            execute_ebtables_commands!(chain, commands)
        end
        return ret
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
                if parent_mac_spoofing.upcase! != 'YES'
                    @slog.warn "activate() VM #{vm_id} Warning: parent NIC_ID #{parent_id} has FILTER_MAC_SPOOFING=#{parent_mac_spoofing}! //SKIP"
                    unlock
                    return
                end
            else
                @slog.warn "activate() VM #{vm_id} Warning: no FILTER_MAC_SPOOFING enabled on parent NIC_ID #{parent_id}! //SKIP"
                unlock
                return
            end
            ipv4 = vm['TEMPLATE/NIC_ALIAS[ATTACH="YES"]/IP']
            if ipv4
                @slog.info "activate() VM #{vm_id} parent_id:#{parent_id} BEGIN"
                chain = "one-#{vm_id}-#{parent_id}"
                if append_ebtables(chain, ipv4)
                    @slog.info "activate() VM #{vm_id} parent_id:#{parent_id} END"
                    unlock
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
            chain = "one-#{vm_id}-#{nic_id}"
            chain_i = "#{chain}-i"
            chain_o = "#{chain}-o"

            commands =  VNMMAD::VNMNetwork::Commands.new

            if nic[:filter_ip_spoofing] == "YES"
                @slog.info "VM #{vm_id} NIC #{nic_id} FILTER_IP_SPOOFING"
                commands.add :iptables, "-S #{chain_o}"
                begin
                    iptables_s = commands.run!
                rescue
                    @slog.warn "Can't process chain #{chain_o} IPv4"
                    next
                end
                iptables_s.each_line { |c| @slog.info "[iptables -S] #{c}" }
                if iptables_s !~ /#{chain}-ip-spoofing/
                    @slog.info "patching #{chain_o} to add #{chain}-ip-spoofing"
                    commands.add :ipset, "create -exist #{chain}-ip-spoofing hash:ip family inet"
                    commands.add :iptables, "-R #{chain_o} #{ipv4_offset} -m set ! --match-set #{chain}-ip-spoofing src -j DROP"
                    commands.add :iptables, "-I #{chain_o} #{ipv4_offset} -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp --sport 68 --dport 67 -j RETURN"
                end
                if !nicdata[:ip4].nil? and !nicdata[:ip4].empty?
                    nicdata[:ip4].each do |ip|
                        @slog.info "ipset add #{chain}-ip-spoofing #{ip}"
                        commands.add :ipset, "add -exist #{chain}-ip-spoofing #{ip}"
                    end
                    commands.run!
                end
                commands.add :ip6tables, "-S #{chain_o}"
                begin
                    ip6tables_s = commands.run!
                rescue
                    @slog.warn "Can't process chain #{chain_o} IPv6"
                    next
                end
                if !nicdata[:ipset_prefix_length].nil? &&
                    !nicdata[:ipset_prefix_length].empty?
                    ipset_hash = "hash:net"
                else
                    ipset_hash = "hash:ip"
                end
                ip6tables_s.each_line { |c| @slog.info "[ip6tables -S] #{c}" }
                if ip6tables_s !~ /#{chain}-ip6-spoofing/
                    @slog.debug "altering #{chain_o} to add #{chain}-ip6-spoofing"
                    commands.add :ipset, "create -exist #{chain}-ip6-spoofing #{ipset_hash} family inet6"
                    commands.add :ip6tables, "-R #{chain_o} #{ipv6_offset} -m set ! --match-set #{chain}-ip6-spoofing src -j DROP"
                end
                if !nicdata[:ip6].nil? and !nicdata[:ip6].empty?
                    nicdata[:ip6].each do |ipv6|
                        @slog.info "ipset add #{chain}-ip6-spoofing #{ipv6}"
                        commands.add :ipset, "add -exist #{chain}-ip6-spoofing #{ipv6}"
                    end
                    commands.run!
                end
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

                execute_ebtables_commands!(
                    chain,
                    ebtables_commands,
                    retry_on_rule_delete: true,
                    max_retries: 4
                )
            end
        end
        @slog.info "activate() VM #{vm_id} END"
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
            chain = "one-#{vm_id}-#{nic_id}"
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
                deactivate_ebtables("one-#{vm_id}-#{nic_id}")
            end
        end
        @slog.info "deactivate() VM #{vm_id} END"
        unlock
    end

    def collect_ebtables_cleanup_commands(chain, ebtables_nat, ipv4 = nil)
        ebtables = Array.new
        chains = Array.new

        ebtables_nat.split("\n").each do |rule|
            if ipv4
                if rule.match(/-A #{chain}/)
                    rule_e = rule.split
                    @slog.info "[rule] #{rule}"
                    if rule_e[5] == ipv4
                        @slog.info "Delete #{rule}"
                        ebtables.push("-t nat -D #{rule_e[1..-1].join(" ")}")
                    end
                end

                next
            end

            if rule.match(/-j #{chain}/)
                rule_e = rule.split
                @slog.info "[rule] #{rule}"
                if rule_e[2] == "-p"
                    ebtables.push("-t nat -F #{rule_e[-1]}")
                    ebtables.push("-t nat -X #{rule_e[-1]}")
                    ebtables.unshift("-t nat -D #{rule_e[1..-1].join(" ")}")
                else
                    ebtables.push("-t nat -D #{rule_e[1..-1].join(" ")}")
                    ebtables.push("-t nat -F #{rule_e[-1]}")
                    ebtables.push("-t nat -X #{rule_e[-1]}")
                end
            end

            if rule.match(/:#{chain}/)
                rule_e = rule.split
                current_chain = rule_e[0][1..-1]
                @slog.info "[chain] #{current_chain}"
                chains.push(current_chain)
            end
        end

        chains.each do |current_chain|
            unless ebtables.include? "-t nat -X #{current_chain}"
                ebtables.push("-t nat -F #{current_chain}")
                ebtables.push("-t nat -X #{current_chain}")
            end
        end

        ebtables
    end

    def deactivate_ebtables(chain, ipv4 = nil)
        @slog.info "deactivate_ebtables(#{chain}, #{ipv4})"
        attempts = 0

        begin
            ebtables_nat = read_ebtables_nat
            return if ebtables_nat.nil? || ebtables_nat.empty?

            ebtables = collect_ebtables_cleanup_commands(chain, ebtables_nat, ipv4)
            return if ebtables.empty?

            ebtables.each { |command| run_ebtables_cleanup!(command) }
        rescue EbtablesCleanupBusyError => e
            attempts += 1

            if attempts <= 3
                @slog.warn "Retrying busy ebtables cleanup for #{chain} (attempt #{attempts}): #{e.args}"
                sleep 1
                retry
            end

            raise
        end
    end

end
