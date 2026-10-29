require 'minitest/autorun'
require_relative '../remotes/vnm/gratuitous_arp'
require_relative 'support/fake_firewall'

class GratuitousArpTest < Minitest::Test
    def setup
        @fake = FakeFirewall.new
        @backend = @fake.backend
        @chain = 'one-42-1-o-arp'
        @fake.chains[@chain] = 'DROP'
        @fake.chains["#{@chain}4"] = 'DROP'
        @original = [
            %w[-p ARP --arp-op Reply --arp-mac-dst ! 02:00:00:00:00:01 -j DROP],
            ['-p', 'ARP', '-j', "#{@chain}4"],
            %w[-p ARP --arp-op Request -j ACCEPT],
            %w[-p ARP --arp-op Reply -j ACCEPT]
        ].map { |rule| ['-A', @chain] + rule }
        @fake.rules.concat(@original)
        @fake.rules << %w[-A PREROUTING -i foreign -j ACCEPT]
    end

    def refresh(action = '--apply')
        VnfilterGratuitousArp.refresh(@backend, action: action)
    end

    def test_refresh_existing_vms_is_idempotent_and_rollback_restores_original_rules
        before = @fake.rules.dup
        assert_raises(AddonFirewallSafety::Error) { refresh('--check') }
        assert_empty @fake.mutations
        assert_equal 1, refresh
        assert_equal VnfilterGratuitousArp.rules, @fake.rules.first(2).map { |rule| rule.drop(2) }
        count = @fake.mutations.length
        refresh
        refresh('--check')
        assert_equal count, @fake.mutations.length
        refresh('--remove')
        assert_equal before, @fake.rules
    end

    def test_duplicate_and_misplaced_exceptions_converge
        2.times { @fake.rules << ['-A', @chain] + VnfilterGratuitousArp.rules.first }
        refresh
        assert_equal VnfilterGratuitousArp.rules, @fake.rules.first(2).map { |rule| rule.drop(2) }
        assert_equal 7, @fake.rules.length
        refresh('--check')
    end

    def test_applied_but_reported_failed_insertion_is_not_repeated
        @fake.failure = ->(args) { { applied: true, stderr: 'RULE_DELETE failed (No such file or directory)' } if args.first == '-I' }
        refresh
        assert_equal 2, @fake.mutations.length
        refresh('--check')
    end

    def test_matcher_failure_preserves_destination_checks_and_can_be_retried
        @fake.failure = ->(args) { { applied: false, stderr: 'unsupported arp matcher' } if args.include?('Reply') }
        assert_raises(AddonFirewallSafety::Error) { refresh }
        assert_equal @original, @fake.rules.select { |rule| @original.include?(rule) }
        @fake.failure = nil
        refresh
        refresh('--check')
    end

    def test_unexpected_chain_fails_preflight_without_any_mutation
        @fake.chains['one-43-1-o-arp'] = 'DROP'
        assert_raises(AddonFirewallSafety::Error) { refresh }
        assert_empty @fake.mutations
    end

    def test_real_backend_serialization_matches_exact_rules
        dump = File.read(File.join(__dir__, 'fixtures/ebtables-save/gratuitous-arp.txt'))
        state = AddonFirewallSafety::Inventory.new(dump, table: 'nat', ebtables: true)
        VnfilterGratuitousArp.rules.each do |rule|
            assert_equal 1, state.matching('one-42-1-o-arp', rule).length
        end
    end
end
