#!/usr/bin/env ruby

require_relative 'vnfilter_firewall_safety'

module VnfilterGratuitousArp
    LOCK_PATH = '/tmp/onevnm-vnfilter-lock'.freeze

    # The zero MAC mask deliberately enables the kernel ARP hardware-length
    # check without restricting the announcing MAC. --arp-gratuitous checks
    # protocol length and SPA == TPA; neither alone checks hardware length.
    def self.rules
        %w[Request Reply].map do |opcode|
            ['-p', 'ARP', '-d', 'Broadcast', '--arp-op', opcode,
             '--arp-htype', '1', '--arp-ptype', '0x800',
             '--arp-ip-src', '!', '0.0.0.0',
             '--arp-mac-src', '00:00:00:00:00:00/00:00:00:00:00:00',
             '--arp-gratuitous', '-j', 'ACCEPT']
        end
    end

    # Upgrade existing receive chains without rebuilding source filters. Refuse
    # unexpected layouts before the first mutation; foreign rules stay intact.
    def self.refresh(backend, action:)
        raise AddonFirewallSafety::Error, 'invalid GARP action' unless %w[--check --apply --remove].include?(action)

        state = backend.inventory(refresh: true)
        keys = rules.map { |rule| AddonFirewallSafety.rule_key(rule) }
        chains = state.chains.keys.grep(/\Aone-\d+-\d+-o-arp\z/)
        chains.each do |chain|
            entries = state.rules.select { |rule| rule[1] == chain }.map { |rule| rule.drop(2) }
            original = entries.reject { |rule| keys.include?(AddonFirewallSafety.rule_key(rule)) }
            mac_rule = original.first || []
            mac = mac_rule[mac_rule.index('--arp-mac-dst').to_i + 2]
            expected = [
                ['-p', 'ARP', '--arp-op', 'Reply', '--arp-mac-dst', '!', mac, '-j', 'DROP'],
                ['-p', 'ARP', '-j', "#{chain}4"],
                ['-p', 'ARP', '--arp-op', 'Request', '-j', 'ACCEPT'],
                ['-p', 'ARP', '--arp-op', 'Reply', '-j', 'ACCEPT']
            ]
            unless mac.to_s.match?(/\A[0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5}\z/) &&
                   state.chains[chain] == 'DROP' && state.chains["#{chain}4"] == 'DROP' &&
                   original.map { |rule| AddonFirewallSafety.rule_key(rule) } ==
                       expected.map { |rule| AddonFirewallSafety.rule_key(rule) }
                raise AddonFirewallSafety::Error, "unexpected receive chain #{chain}"
            end
        end
        chains.each do |chain|
            entries = state.rules.select { |rule| rule[1] == chain }.map { |rule| rule.drop(2) }
            present = entries.select { |rule| keys.include?(AddonFirewallSafety.rule_key(rule)) }
            correct = present.length == 2 && entries.first(2).map { |rule| AddonFirewallSafety.rule_key(rule) } == keys
            if action == '--check'
                raise AddonFirewallSafety::Error, "GARP refresh required for #{chain}" unless correct
                next
            end
            next if action == '--apply' && correct

            present.each { |rule| backend.reconcile(['-D', chain] + rule) }
            if action == '--apply'
                rules.each_with_index { |rule, index| backend.reconcile(['-I', chain, (index + 1).to_s] + rule) }
            end
        end
        chains.length
    end
end

if $PROGRAM_NAME == __FILE__
    begin
        raise AddonFirewallSafety::Error, 'usage: gratuitous_arp.rb --check|--apply|--remove' unless ARGV.length == 1
        AddonFirewallSafety.with_lock(VnfilterGratuitousArp::LOCK_PATH) do
            backend = AddonFirewallSafety::Backend.new(tool: 'ebtables', table: 'nat')
            count = VnfilterGratuitousArp.refresh(backend, action: ARGV.first)
            puts "GARP #{ARGV.first}: #{count} receive chains"
        end
    rescue AddonFirewallSafety::Error => e
        warn e.message
        exit 1
    end
end
