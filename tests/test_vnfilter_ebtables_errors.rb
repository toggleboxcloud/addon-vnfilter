require 'minitest/autorun'
require 'minitest/mock'
require 'tmpdir'

module VNMMAD
    class VNMDriver
        def vm; @template; end
        def process
            @nics.each do |nic|
                yield nic.merge(vn_mad: caller.last.split('/')[-3])
            end
        end
    end
    module VNMNetwork
        COMMANDS = { iptables: 'sudo -n iptables -w 3', ip6tables: 'sudo -n ip6tables -w 3', ipset: 'sudo -n ipset' }
    end
end
module OpenNebula
    module DriverLogger
        def self.log_info(*); end
    end
end
$LOADED_FEATURES << 'vnmmad.rb'
require_relative '../remotes/vnm/vnfilter'
require_relative 'support/fake_firewall'

class VnfilterEbtablesErrorsTest < Minitest::Test
    def setup
        @fake = FakeFirewall.new
        @filter = VnFilter.allocate
        @filter.instance_variable_set(:@ebtables_backend, @fake.backend)
        @filter.instance_variable_set(:@slog, Object.new.tap do |logger|
            %i[info warn error debug].each { |name| logger.define_singleton_method(name) { |*| } }
        end)
        @filter.instance_variable_set(:@template, { 'ID' => '42' })
        @filter.instance_variable_set(:@nics, [])
        @dir = Dir.mktmpdir
        path = File.join(@dir, 'lock')
        @filter.define_singleton_method(:firewall_lock_path) { path }
    end

    def teardown
        FileUtils.remove_entry(@dir)
    end

    def build
        @filter.build_mac_spoofing_ebtables_commands('one-42-1', 'one-42-1-i', 'one-42-1-o',
                                                  { mac: '02:00:00:00:00:01' }, { ip4: ['192.0.2.1'] })
    end

    def seed
        @filter.execute_ebtables_commands!('one-42-1', build)
    end

    def test_full_chain_build_and_cleanup_preserve_neighbour_nic_and_foreign_rules
        @fake.chains['one-42-10-o-arp4'] = 'DROP'
        @fake.rules << %w[-A one-42-10-o-arp4 -p ARP --arp-ip-dst 192.0.2.10 -j RETURN]
        @fake.rules << %w[-A PREROUTING -i foreign -j ACCEPT]
        seed
        @filter.deactivate_ebtables('one-42-1')
        assert_equal %w[PREROUTING POSTROUTING one-42-10-o-arp4], @fake.chains.keys
        assert_equal 2, @fake.rules.length
        assert @fake.rules.all? { |rule| rule[1] == 'one-42-10-o-arp4' || rule.include?('foreign') }
        commands = @fake.mutations.length
        @filter.deactivate_ebtables('one-42-1')
        assert_equal commands, @fake.mutations.length
    end

    def test_busy_cleanup_retries_current_delete_without_replaying_flushes
        seed
        failures = 0
        @fake.failure = lambda do |args|
            if args.first == '-X' && (failures += 1) == 1
                { applied: false, stderr: 'CHAIN_DEL failed (Device or resource busy)' }
            end
        end
        @filter.deactivate_ebtables('one-42-1')
        assert_equal [0.2], @fake.pauses
        assert_equal 8, @fake.mutations.count { |argv| argv.include?('-F') }
        refute @fake.chains.keys.any? { |chain| chain.start_with?('one-42-1-') }
    end

    def test_applied_creation_error_converges_without_cleanup_or_duplicate_append
        failed = false
        @fake.failure = lambda do |args|
            unless failed
                failed = true
                { applied: true, stderr: 'RULE_DELETE failed (No such file or directory)' }
            end
        end
        seed
        assert_equal 8, @fake.chains.keys.count { |chain| chain.start_with?('one-42-1-') }
        refute @fake.mutations.any? { |argv| argv.include?('-X') || argv.include?('-F') }
        assert_equal build.length, @fake.mutations.length
    end

    def test_cleanup_read_failure_and_truncation_fail_before_any_delete
        [nil, "*nat\n"].each do |dump|
            @fake = FakeFirewall.new
            @fake.raw_inventory = dump
            @fake.read_failure = 1 unless dump
            @filter.instance_variable_set(:@ebtables_backend, @fake.backend)
            assert_raises(AddonFirewallSafety::Error) { @filter.deactivate_ebtables('one-42-1') }
            assert_empty @fake.mutations
        end
    end

    def test_cleanup_permanent_failure_preserves_remaining_state
        seed
        @fake.failure = ->(_args) { { applied: false, stderr: 'Operation not permitted' } }
        before = @fake.rules.dup
        assert_raises(VnFilter::EbtablesCommandError) { @filter.deactivate_ebtables('one-42-1') }
        assert_equal before, @fake.rules
        assert_empty @fake.pauses
    end

    def test_alias_append_is_idempotent_and_verifies_both_directions
        seed
        before = @fake.mutations.length
        @filter.append_ebtables('one-42-1', '192.0.2.1')
        assert_equal before, @fake.mutations.length
        @filter.append_ebtables('one-42-1', '192.0.2.2')
        assert_equal before + 2, @fake.mutations.length
        @filter.append_ebtables('one-42-1', '192.0.2.2')
        assert_equal before + 2, @fake.mutations.length
    end

    def test_alias_cleanup_removes_duplicates_only_for_exact_address_and_chains
        seed
        @fake.rules << %w[-A one-42-1-o-arp4 -p ARP --arp-ip-dst 192.0.2.1 -j RETURN]
        @filter.append_ebtables('one-42-1', '192.0.2.2')
        @filter.deactivate_ebtables('one-42-1', '192.0.2.1')
        assert_equal 2, @fake.rules.count { |rule| rule.include?('192.0.2.2') }
        refute @fake.rules.any? { |rule| rule.include?('192.0.2.1') }
        assert @fake.chains.key?('one-42-1-i-arp4')
    end

    def test_unrelated_chain_reference_is_preserved_and_cleanup_fails
        seed
        @fake.chains['foreign'] = 'DROP'
        @fake.rules << %w[-A foreign -j one-42-1-o]
        @fake.failure = lambda do |args|
            { applied: false, stderr: 'CHAIN_DEL failed (Device or resource busy)' } if args == %w[-X one-42-1-o]
        end
        assert_raises(VnFilter::EbtablesCommandError) { @filter.deactivate_ebtables('one-42-1') }
        assert_includes @fake.rules, %w[-A foreign -j one-42-1-o]
    end

    def test_builtin_reference_with_unowned_conditions_is_preserved
        seed
        foreign_rule = %w[-A PREROUTING -i one-42-1 -p ARP -j one-42-1-i]
        @fake.rules << foreign_rule
        @fake.failure = lambda do |args|
            { applied: false, stderr: 'CHAIN_DEL failed (Device or resource busy)' } if args == %w[-X one-42-1-i]
        end
        assert_raises(VnFilter::EbtablesCommandError) { @filter.deactivate_ebtables('one-42-1') }
        assert_includes @fake.rules, foreign_rule
    end

    def test_values_with_shell_syntax_remain_single_arguments
        address = '192.0.2.1; --jump ACCEPT'
        commands = @filter.build_mac_spoofing_ebtables_commands('one-42-1', 'one-42-1-i', 'one-42-1-o',
                                                              { mac: '02:00:00:00:00:01' }, { ip4: [address] })
        @filter.execute_ebtables_commands!('one-42-1', commands)
        whitelist = @fake.mutations.select { |argv| argv.include?('--arp-ip-src') && argv.include?(address) }
        assert_equal 1, whitelist.length
        refute_includes whitelist.first, '--jump'
    end

    def test_lifecycle_exception_releases_lock_and_forces_guard_open
        @filter.define_singleton_method(:vm) { raise 'injected VM failure' }
        opened = 0
        VnfilterArpGuard.stub(:fail_open, ->(**_) { opened += 1; true }) do
            %i[activate deactivate].each do |operation|
                assert_raises(RuntimeError) { @filter.public_send(operation) }
                AddonFirewallSafety.with_lock(@filter.firewall_lock_path, nonblocking: true) { assert true }
            end
        end
        assert_equal 2, opened
    end

    def test_guard_failure_propagates_and_releases_lock
        VnfilterArpGuard.stub(:reconcile, false) do
            VnfilterArpGuard.stub(:fail_open, true) do
                assert_raises(AddonFirewallSafety::Error) { @filter.activate }
            end
        end
        AddonFirewallSafety.with_lock(@filter.firewall_lock_path, nonblocking: true) { assert true }
    end

    def test_lifecycle_spoofing_updates_use_complete_family_inventories_and_readback
        families = { 'iptables' => FakeFirewall.new(table: 'filter', ebtables: false),
                     'ip6tables' => FakeFirewall.new(table: 'filter', ebtables: false) }
        families.each_value do |fake|
            fake.chains['one-42-1-o'] = '-'
            %w[ACCEPT DROP ACCEPT ACCEPT DROP DROP RETURN].each do |target|
                fake.rules << ['-A', 'one-42-1-o', '-j', target]
            end
        end
        @filter.instance_variable_set(:@nics, [{ nic_id: '1', mac: '02:00:00:00:00:01', ip: '192.0.2.1',
                                               ip6: '2001:db8::1', filter_ip_spoofing: 'YES', filter_mac_spoofing: 'YES' }])
        ipset_calls = []
        runner = lambda do |*argv|
            assert @filter.instance_variable_get(:@locking_file), 'commands ran without lifecycle lock'
            if argv.include?('ipset')
                ipset_calls << argv
                ['', '', FakeFirewall::Status.new(true)]
            else
                tool = argv.find { |arg| families.key?(arg) || arg.end_with?('-save') }
                families.fetch(tool.delete_suffix('-save')).capture(argv)
            end
        end
        Open3.stub(:capture3, runner) do
            VnfilterArpGuard.stub(:reconcile, true) { @filter.activate }
        end
        assert_equal 2, families['iptables'].mutations.length
        assert_equal 1, families['ip6tables'].mutations.length
        assert_equal 4, ipset_calls.length
        assert @fake.chains.key?('one-42-1-o-arp4')
        rarp_commands = @fake.mutations.select { |argv| argv.include?('0x8035') }
        assert_equal 4, rarp_commands.length
        assert_equal 4, @fake.dump.lines.count { |line| line.include?('-p RARP') }
        assert_empty @fake.pauses
        assert_equal build.length, @fake.mutations.length
        AddonFirewallSafety.with_lock(@filter.firewall_lock_path, nonblocking: true) { assert true }
    end

    def test_lifecycle_failed_ipv6_inventory_prevents_ipv4_mutations
        families = { 'iptables' => FakeFirewall.new(table: 'filter', ebtables: false),
                     'ip6tables' => FakeFirewall.new(table: 'filter', ebtables: false) }
        families['iptables'].chains['one-42-1-o'] = '-'
        families['ip6tables'].read_failure = 1
        @filter.instance_variable_set(:@nics, [{ nic_id: '1', filter_ip_spoofing: 'YES' }])
        runner = lambda do |*argv|
            tool = argv.last.delete_suffix('-save')
            families.fetch(tool).capture(argv)
        end
        Open3.stub(:capture3, runner) do
            VnfilterArpGuard.stub(:fail_open, true) do
                assert_raises(AddonFirewallSafety::Error) { @filter.activate }
            end
        end
        families.each_value { |fake| assert_empty fake.mutations }
    end

    def test_alias_skip_releases_lifecycle_lock_without_backend_changes
        @filter.instance_variable_set(:@template, { 'ID' => '42', 'TEMPLATE/NIC_ALIAS[ATTACH="YES"]/PARENT_ID' => '1' })
        @filter.activate
        AddonFirewallSafety.with_lock(@filter.firewall_lock_path, nonblocking: true) { assert true }
        assert_empty @fake.calls
    end
end
