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

ONE_LOCATION = ENV['ONE_LOCATION']

if !ONE_LOCATION
    RUBY_LIB_LOCATION = '/usr/lib/one/ruby'
    GEMS_LOCATION     = '/usr/share/one/gems'
else
    RUBY_LIB_LOCATION = ONE_LOCATION + '/lib/ruby'
    GEMS_LOCATION     = ONE_LOCATION + '/share/gems'
end

if File.directory?(GEMS_LOCATION)
    Gem.use_paths(GEMS_LOCATION)
end

$LOAD_PATH << RUBY_LIB_LOCATION

require 'vnmmad'
require 'syslog/logger'

# IP filter for aliases
class VnFilter < VNMMAD::VNMDriver

    DRIVER = 'vnfilter'
    XPATH_FILTER = 'TEMPLATE/NIC|TEMPLATE/NIC_ALIAS'

    def initialize(vm_template, xpath_filter = nil, deploy_id = nil)
        @locking = true
        @slog = Syslog::Logger.new 'vnfilter'
        xpath_filter ||= XPATH_FILTER
        @slog.info "initialize #{xpath_filter} //#{caller[-1]}"
        super(vm_template, xpath_filter, deploy_id)
    end

    # Retry mechanism for transient failures
    def retry_command(max_attempts = 3, delay = 0.5, &block)
        attempt = 1
        while attempt <= max_attempts
            begin
                return block.call
            rescue => e
                transient_errors = [
                    "Device or resource busy",
                    "Resource temporarily unavailable",
                    "Cannot allocate memory",
                    "No such file or directory",
                    "Operation not permitted"
                ]

                is_transient = transient_errors.any? { |err| e.message.include?(err) }

                if is_transient && attempt < max_attempts
                    @slog.warn "Attempt #{attempt}/#{max_attempts} failed with transient error: #{e.message}. Retrying in #{delay}s..."
                    sleep(delay)
                    delay *= 2  # Exponential backoff
                    attempt += 1
                else
                    raise e
                end
            end
        end
    end

    # Extract VRRP configuration for a NIC from USER_TEMPLATE
    def get_vrrp_config(nic_id)
        vrrp_config = {
            :vips => [],
            :vmacs => []
        }
        
        # Access USER_TEMPLATE variables
        (0..9).each do |index|
            vip_key = "USER_TEMPLATE/VIP_NIC#{nic_id}_#{index}"
            vmac_key = "USER_TEMPLATE/VMAC_NIC#{nic_id}_#{index}"
            
            vip = vm[vip_key]
            vmac = vm[vmac_key]
            
            if !vip.nil? && !vip.empty?
                vrrp_config[:vips][index] = vip
                @slog.info "Found VIP_NIC#{nic_id}_#{index}: #{vip}"
            end
            
            if !vmac.nil? && !vmac.empty?
                vrrp_config[:vmacs][index] = vmac
                @slog.info "Found VMAC_NIC#{nic_id}_#{index}: #{vmac}"
            end
        end
        
        # Remove nil entries
        vrrp_config[:vips].compact!
        vrrp_config[:vmacs].compact!
        
        @slog.info "VRRP config for NIC #{nic_id}: VIPs=#{vrrp_config[:vips].join(',')}, VMACs=#{vrrp_config[:vmacs].join(',')}"
        vrrp_config
    end

    def append_ebtables(chain, ipv4)
        @slog.info "activate_ebtables(#{chain},#{ipv4})"
        dirs = { "i" => "src", "o" => "dst" }
        ret = false
        commands =  VNMMAD::VNMNetwork::Commands.new
        commands.add "sudo -n", "ebtables-save"
        ebtables_nat = commands.run!
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
                commands.add :ebtables, "--concurrent -t nat -A #{chain}-#{k}-arp4 -p ARP "\
                                            "--arp-ip-#{v} #{ipv4} -j RETURN"
                ret = true
            end
            commands.run!
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
            
            # Get VRRP configuration for this NIC
            nics[nic_id][:vrrp] = get_vrrp_config(nic_id)
        end

        nics.each do |nic_id, nicdata|
            nic = nicdata[:nic]
            vn_mad = nic[:vn_mad]
            if caller_mad != vn_mad
                @slog.info "VM #{vm_id} nic_id #{nic_id} #{vn_mad} Skip caller VN_MAD is #{caller_mad}"
                next
            end
            @slog.info "VM #{vm_id} nic_id #{nic_id} attach_nic_id:#{attach_nic_id}"
            OpenNebula.log_info "VM #{vm_id} nic_id #{nic_id} #{vn_mad} attach_nic_id #{attach_nic_id}"
            next if attach_nic_id and attach_nic_id != nic_id
            chain = "one-#{vm_id}-#{nic_id}"
            chain_i = "#{chain}-i"
            chain_o = "#{chain}-o"

            commands =  VNMMAD::VNMNetwork::Commands.new

            if nic[:filter_ip_spoofing] == "YES"
                @slog.info "VM #{vm_id} NIC #{nic_id} FILTER_IP_SPOOFING"
                commands.add :iptables, "-w 3 -W 20000 -S #{chain_o}"
                begin
                    iptables_s = commands.run!
                rescue
                    @slog.warn "Can't process chain #{chain_o} IPv4"
                    next
                end
                iptables_s.each_line { |c| @slog.info "[iptables -S] #{c}" }
                
                # Handle VRRP VMACs in iptables - this should be outside the ip-spoofing check
                if !nicdata[:vrrp][:vmacs].nil? && !nicdata[:vrrp][:vmacs].empty?
                    @slog.info "Processing VRRP VMACs for iptables"
                    # Find the MAC DROP rule position
                    mac_drop_pos = nil
                    iptables_s.split("\n").each_with_index do |rule, idx|
                        if rule =~ /-A .* -m mac ! --mac-source .* -j DROP/
                            mac_drop_pos = idx  
                            @slog.info "Found MAC DROP rule at line #{idx}: #{rule}"
                            break
                        end
                    end
                    
                    if mac_drop_pos
                        # Create new commands object for VMAC rules
                        vmac_commands = VNMMAD::VNMNetwork::Commands.new
                        # Insert RETURN rules for VMACs BEFORE the DROP rule
                        nicdata[:vrrp][:vmacs].each_with_index do |vmac, vmac_idx|
                            @slog.info "Inserting iptables RETURN rule for VRRP VMAC #{vmac} at position 1"
                            vmac_commands.add :iptables, "-w 3 -W 20000 -I #{chain_o} 1 -m mac --mac-source #{vmac} -j RETURN"
                        end
                        # Execute the VMAC commands immediately
                        vmac_commands.run!
                    else
                        @slog.warn "MAC DROP rule not found in chain #{chain_o}"
                    end
                end
                
                if iptables_s !~ /#{chain}-ip-spoofing/
                    @slog.info "patching #{chain_o} to add #{chain}-ip-spoofing"
                    commands.add :ipset, "create -exist #{chain}-ip-spoofing hash:ip family inet"
                    commands.add :iptables, "-w 3 -W 20000 -R #{chain_o} #{ipv4_offset} -m set ! --match-set #{chain}-ip-spoofing src -j DROP"
                    commands.add :iptables, "-w 3 -W 20000 -I #{chain_o} #{ipv4_offset} -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp --sport 68 --dport 67 -j RETURN"
                end
                if !nicdata[:ip4].nil? and !nicdata[:ip4].empty?
                    nicdata[:ip4].each do |ip|
                        @slog.info "ipset add #{chain}-ip-spoofing #{ip}"
                        commands.add :ipset, "add -exist #{chain}-ip-spoofing #{ip}"
                    end
                end
                # Add VRRP VIPs to the ipset
                if !nicdata[:vrrp][:vips].nil? and !nicdata[:vrrp][:vips].empty?
                    nicdata[:vrrp][:vips].each do |vip|
                        @slog.info "ipset add #{chain}-ip-spoofing #{vip} (VRRP VIP)"
                        commands.add :ipset, "add -exist #{chain}-ip-spoofing #{vip}"
                    end
                end
                commands.run!
                commands.add :ip6tables, "-w 3 -W 20000 -S #{chain_o}"
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
                    commands.add :ip6tables, "-w 3 -W 20000 -R #{chain_o} #{ipv6_offset} -m set ! --match-set #{chain}-ip6-spoofing src -j DROP"
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
                
                # Atomic chain creation - create if not exists or flush if exists
                ["#{chain_i}-arp4", "#{chain_o}-arp4"].each do |chain_name|
                    begin
                        # Try to create the chain first with retry
                        retry_command do
                            create_cmd = VNMMAD::VNMNetwork::Commands.new
                            create_cmd.add :ebtables, "--concurrent -t nat -N #{chain_name} -P DROP"
                            create_cmd.run!
                        end
                        @slog.info "Successfully created new chain: #{chain_name}"
                    rescue => e
                        if e.message.include?("File exists") || e.message.include?("Chain already exists")
                            # Chain exists, flush it with retry
                            begin
                                retry_command do
                                    flush_cmd = VNMMAD::VNMNetwork::Commands.new
                                    flush_cmd.add :ebtables, "--concurrent -t nat -F #{chain_name}"
                                    flush_cmd.run!
                                end
                                @slog.info "Successfully flushed existing chain: #{chain_name}"
                            rescue => flush_e
                                @slog.warn "Failed to flush chain #{chain_name} after retries: #{flush_e.message}"
                            end
                        else
                            @slog.warn "Failed to create chain #{chain_name} after retries: #{e.message}"
                        end
                    end
                end
                if !nicdata[:ip4].nil? and !nicdata[:ip4].empty?
                    nicdata[:ip4].each do |ip|
                        @slog.info "ARP whitelist #{ip} (#{chain})"
                        commands.add :ebtables, "--concurrent -t nat -A #{chain_i}-arp4 -p ARP "\
                            "--arp-ip-src #{ip} -j RETURN"
                        commands.add :ebtables, "--concurrent -t nat -A #{chain_o}-arp4 -p ARP "\
                            "--arp-ip-dst #{ip} -j RETURN"
                    end
                end
                # Add VRRP VIPs to ARP whitelist
                if !nicdata[:vrrp][:vips].nil? and !nicdata[:vrrp][:vips].empty?
                    nicdata[:vrrp][:vips].each do |vip|
                        @slog.info "ARP whitelist #{vip} (#{chain}) - VRRP VIP"
                        commands.add :ebtables, "--concurrent -t nat -A #{chain_i}-arp4 -p ARP "\
                            "--arp-ip-src #{vip} -j RETURN"
                        commands.add :ebtables, "--concurrent -t nat -A #{chain_o}-arp4 -p ARP "\
                            "--arp-ip-dst #{vip} -j RETURN"
                    end
                end
                # Input
                commands.add :ebtables, "--concurrent -t nat -N #{chain_i}-arp -P DROP"
                commands.add :ebtables, "--concurrent -t nat -A #{chain_i}-arp -p ARP "\
                    "-s ! #{nic[:mac]} -j DROP"
                commands.add :ebtables, "--concurrent -t nat -A #{chain_i}-arp -p ARP "\
                        "--arp-mac-src ! #{nic[:mac]} -j DROP"
                # Allow ARP from VRRP VMACs
                if !nicdata[:vrrp][:vmacs].nil? and !nicdata[:vrrp][:vmacs].empty?
                    nicdata[:vrrp][:vmacs].each do |vmac|
                        @slog.info "Allow ARP from VRRP VMAC #{vmac} - inserting before DROP"
                        # Insert BEFORE the DROP rules
                        commands.add :ebtables, "--concurrent -t nat -I #{chain_i}-arp 1 -p ARP "\
                            "-s #{vmac} --arp-mac-src #{vmac} -j #{chain_i}-arp4"
                    end
                end
                commands.add :ebtables, "--concurrent -t nat -A #{chain_i}-arp -p ARP "\
                    "-j #{chain_i}-arp4"
                commands.add :ebtables, "--concurrent -t nat -A #{chain_i}-arp -p ARP "\
                    "--arp-op Request -j ACCEPT"
                commands.add :ebtables, "--concurrent -t nat -A #{chain_i}-arp -p ARP "\
                    "--arp-op Reply -j ACCEPT"
                commands.add :ebtables, "--concurrent -t nat -N #{chain_i}-rarp -P DROP"
                commands.add :ebtables, "--concurrent -t nat -A #{chain_i}-rarp -p 0x8035 "\
                    "-s #{nic[:mac]} -d Broadcast --arp-op Request_Reverse "\
                    "--arp-ip-src 0.0.0.0 --arp-ip-dst 0.0.0.0 "\
                    "--arp-mac-src #{nic[:mac]} --arp-mac-dst #{nic[:mac]} "\
                    "-j ACCEPT"
                commands.add :ebtables, "--concurrent -t nat -N #{chain_i} -P ACCEPT"
#            commands.add :ebtables, "-t nat -N #{chain_i}-ip4 -P ACCEPT"
#            commands.add :ebtables, "-t nat -A #{chain_i}-ip4 "\
#                "-s ! #{nic[:mac]} -j DROP"
#            commands.add :ebtables, "-t nat -A #{chain_i} -p IPv4 "\
#                "-j #{chain_i}-ip4"
                commands.add :ebtables, "--concurrent -t nat -A #{chain_i} -p IPv4 "\
                    "-j ACCEPT"
                commands.add :ebtables, "--concurrent -t nat -A #{chain_i} -p IPv6 "\
                    "-j ACCEPT"
                commands.add :ebtables, "--concurrent -t nat -A #{chain_i} -p ARP "\
                    "-j #{chain_i}-arp"
                commands.add :ebtables, "--concurrent -t nat -A #{chain_i} -p 0x8035 "\
                    "-j #{chain_i}-rarp"
                commands.add :ebtables, "--concurrent -t nat -A PREROUTING -i #{chain} "\
                    "-j #{chain_i}"
                # Output
                commands.add :ebtables, "--concurrent -t nat -N #{chain_o}-arp -P DROP"
                commands.add :ebtables, "--concurrent -t nat -A #{chain_o}-arp -p ARP "\
                    "--arp-op Reply --arp-mac-dst ! #{nic[:mac]} -j DROP"
                # Allow ARP replies to VRRP VMACs
                if !nicdata[:vrrp][:vmacs].nil? and !nicdata[:vrrp][:vmacs].empty?
                    nicdata[:vrrp][:vmacs].each do |vmac|
                        @slog.info "Allow ARP reply to VRRP VMAC #{vmac}"
                        # Insert BEFORE the DROP rule
                        commands.add :ebtables, "--concurrent -t nat -I #{chain_o}-arp 1 -p ARP "\
                            "--arp-op Reply --arp-mac-dst #{vmac} -j #{chain_o}-arp4"
                    end
                end
                commands.add :ebtables, "--concurrent -t nat -A #{chain_o}-arp -p ARP "\
                    "-j #{chain_o}-arp4"
                commands.add :ebtables, "--concurrent -t nat -A #{chain_o}-arp -p ARP "\
                    "--arp-op Request -j ACCEPT"
                commands.add :ebtables, "--concurrent -t nat -A #{chain_o}-arp -p ARP "\
                    "--arp-op Reply -j ACCEPT"
                commands.add :ebtables, "--concurrent -t nat -N #{chain_o}-rarp -P DROP"
                commands.add :ebtables, "--concurrent -t nat -A #{chain_o}-rarp -p 0x8035 "\
                    "-d Broadcast --arp-op Request_Reverse "\
                    "--arp-ip-src 0.0.0.0 --arp-ip-dst 0.0.0.0 "\
                    "--arp-mac-src #{nic[:mac]} --arp-mac-dst #{nic[:mac]} "\
                    "-j ACCEPT"
                commands.add :ebtables, "--concurrent -t nat -N #{chain_o} -P ACCEPT"
#            commands.add :ebtables, "-t nat -N #{chain_o}-ip4 -P ACCEPT"
#            commands.add :ebtables, "-t nat -A #{chain_o} -p IPv4 "\
#                "-j #{chain_o}-ip4"
                commands.add :ebtables, "--concurrent -t nat -A #{chain_o} -p IPv4 "\
                    "-j ACCEPT"
                commands.add :ebtables, "--concurrent -t nat -A #{chain_o} -p IPv6 "\
                    "-j ACCEPT"
                commands.add :ebtables, "--concurrent -t nat -A #{chain_o} -p ARP "\
                    "-j #{chain_o}-arp"
                commands.add :ebtables, "--concurrent -t nat -A #{chain_o} -p 0x8035 "\
                    "-j #{chain_o}-rarp"
                commands.add :ebtables, "--concurrent -t nat -A POSTROUTING -o #{chain} "\
                    "-j #{chain_o}"

                commands.run!
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

    def deactivate_ebtables(chain, ipv4 = nil)
        commands =  VNMMAD::VNMNetwork::Commands.new
        @slog.info "deactivate_ebtables(#{chain}, #{ipv4})"
        commands.add "sudo -n", "ebtables-save"
        begin
            ebtables_nat = commands.run!
        rescue
            @slog.warn "Failed to run ebtables-save, skipping cleanup"
            return
        end
        
        if !ebtables_nat.nil?
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

                # flush chains only if not ipv4 defined (no alias nic)
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

                # save any chains found
                if rule.match(/:#{chain}/)
                    rule_e = rule.split
                    c = rule_e[0][1..-1]
                    @slog.info "[chain] #{c}"
                    chains.push(c)
                end
            end

            chains.each do |c|
                unless ebtables.include? "-t nat -X #{c}"
                    ebtables.push("-t nat -F #{c}")
                    ebtables.push("-t nat -X #{c}")
                end
            end

            if ebtables.any?
                ebtables.each { |c| @slog.info "[run] ebtables #{c}" }
                failed_commands = []
                ebtables.each do |c|
                    begin
                        retry_command do
                            single_command = VNMMAD::VNMNetwork::Commands.new
                            single_command.add :ebtables, "--concurrent #{c}"
                            single_command.run!
                        end
                        @slog.info "Successfully executed: ebtables #{c}"
                    rescue => e
                        @slog.warn "Failed to execute ebtables command after retries: #{c} - #{e.message}"
                        failed_commands << c
                    end
                end

                # Log summary of cleanup results
                if failed_commands.empty?
                    @slog.info "All ebtables cleanup commands executed successfully"
                else
                    @slog.warn "#{failed_commands.size}/#{ebtables.size} ebtables cleanup commands failed: #{failed_commands.join(', ')}"
                end
            end
        end
    end

end
