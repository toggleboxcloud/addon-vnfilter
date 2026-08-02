#!/usr/bin/env ruby

require 'tmpdir'
require_relative '../remotes/vnm/arp_guard'
load File.expand_path('../host/vnfilter_arp_guard_nft', __dir__)

module Assertions
    def assert(value, message = 'assertion failed')
        raise message unless value
    end

    def refute(value, message = 'refutation failed')
        raise message if value
    end

    def assert_equal(expected, actual)
        assert(expected == actual, "expected #{expected.inspect}, got #{actual.inspect}")
    end

    def assert_includes(collection, value)
        assert(collection.include?(value), "expected #{collection.inspect} to include #{value.inspect}")
    end

    def refute_includes(collection, value)
        refute(collection.include?(value), "expected #{collection.inspect} not to include #{value.inspect}")
    end
end

class FakeLogger
    attr_reader :messages

    def initialize
        @messages = []
    end

    %i[info warn error].each do |level|
        define_method(level) { |message| @messages << [level, message] }
    end
end

class FakeRunner
    attr_reader :calls, :max_active

    def initialize(ip_output: '', ebtables_output: '', &failure)
        @ip_output = ip_output
        @ebtables_output = ebtables_output
        @failure = failure
        @calls = []
        @mutex = Mutex.new
        @active = 0
        @max_active = 0
    end

    def capture(*command, stdin_data: nil)
        @mutex.synchronize { @calls << [command, stdin_data] }
        error = @failure&.call(command, stdin_data, @calls)
        raise error if error

        case command
        when ['/usr/sbin/ip', '-o', 'link', 'show', 'master', 'br0']
            track_active { @ip_output }
        when ['sudo', '-n', '/usr/sbin/ebtables-save']
            @ebtables_output
        else
            ''
        end
    end

    private

    def track_active
        @mutex.synchronize do
            @active += 1
            @max_active = [@max_active, @active].max
        end
        sleep 0.03
        yield
    ensure
        @mutex.synchronize { @active -= 1 }
    end
end

class FakeNftRunner
    attr_accessor :table_exists
    attr_reader :submissions

    def initialize(table_exists: false)
        @table_exists = table_exists
        @submissions = []
    end

    def table_exists?
        @table_exists
    end

    def submit(program, check_only:)
        @submissions << [program, check_only]
        @table_exists = true unless check_only
    end
end

class ArpGuardTest
    include Assertions
    IP_LINKS = <<~OUTPUT.freeze
        10: one-12-0@if9: <BROADCAST> mtu 1500 master br0 state UP
        11: one-13-1: <BROADCAST> mtu 1500 master br0 state UP
        12: vnet-unrelated: <BROADCAST> mtu 1500 master br0 state UP
    OUTPUT

    EBTABLES = <<~OUTPUT.freeze
        *nat
        :one-12-0-o-arp4 DROP
        :one-13-1-o-arp4 DROP
        :one-99-0-o-arp4 DROP
        -A one-12-0-o-arp4 -p ARP --arp-ip-dst 192.0.2.10 -j RETURN
        -A one-12-0-o-arp4 -p ARP --arp-ip-dst 192.0.2.11 -j RETURN
        -A one-13-1-o-arp4 -p ARP --arp-ip-dst 192.0.2.10 -j RETURN
        -A one-13-1-o-arp4 -p ARP --arp-ip-dst 192.0.2.12 -j RETURN
        -A one-99-0-o-arp4 -p ARP --arp-ip-dst 198.51.100.99 -j RETURN
        COMMIT
    OUTPUT

    def setup
        @directory = Dir.mktmpdir('arp-guard-test')
        @config_path = File.join(@directory, 'arp-guard.conf')
        @lock_path = File.join(@directory, 'arp-guard.lock')
        @logger = FakeLogger.new
    end

    def teardown
        FileUtils.remove_entry(@directory)
    end

    def write_config(mode, extra = '')
        File.write(@config_path, "mode=#{mode}\n#{extra}")
    end

    def reconciler(runner)
        VnfilterArpGuard::Reconciler.new(
            config_path: @config_path,
            lock_path: @lock_path,
            runner: runner,
            logger: @logger
        )
    end

    def guard_payloads(runner, check: false)
        action = check ? '--check' : '--apply'
        expected = ['sudo', '-n', VnfilterArpGuard::NFT_HELPER, action]
        runner.calls.filter_map do |command, input|
            JSON.parse(input) if command == expected
        end
    end

    def nft_manager(runner, directory = @directory)
        VnfilterArpGuardNft::Manager.new(
            runner: runner,
            state_directory: directory,
            state_path: File.join(directory, 'owner.json')
        )
    end

    def test_union_includes_primary_alias_and_shared_addresses_but_ignores_stale_chains
        write_config('observe')
        runner = FakeRunner.new(ip_output: IP_LINKS, ebtables_output: EBTABLES)

        assert reconciler(runner).reconcile

        payload = guard_payloads(runner).last
        assert_equal ['192.0.2.10', '192.0.2.11', '192.0.2.12'], payload['targets']
        refute_includes payload['targets'], '198.51.100.99'
    end

    def test_missing_live_tap_chain_fails_open
        write_config('enforce')
        ebtables = EBTABLES.lines.reject { |line| line.include?(':one-13-1-o-arp4') }.join
        runner = FakeRunner.new(ip_output: IP_LINKS, ebtables_output: ebtables)

        refute reconciler(runner).reconcile

        payloads = guard_payloads(runner)
        assert_equal 1, payloads.length
        assert_equal 'disabled', payloads.first['mode']
        assert @logger.messages.any? { |level, message| level == :error && message.include?('missing expected') }
    end

    def test_malformed_ebtables_address_fails_open
        write_config('observe')
        ebtables = EBTABLES.sub('192.0.2.11', '192.0.2.999')
        runner = FakeRunner.new(ip_output: IP_LINKS, ebtables_output: ebtables)

        refute reconciler(runner).reconcile
        assert_equal 'disabled', guard_payloads(runner).last['mode']
    end

    def test_command_failure_fails_open
        write_config('enforce')
        runner = FakeRunner.new(ip_output: IP_LINKS, ebtables_output: EBTABLES) do |command|
            if command == ['sudo', '-n', '/usr/sbin/ebtables-save']
                VnfilterArpGuard::CommandError.new('ebtables-save failed')
            end
        end

        refute reconciler(runner).reconcile
        assert_equal 1, guard_payloads(runner).length
        assert_equal 'disabled', guard_payloads(runner).last['mode']
    end

    def test_disabled_mode_does_not_inspect_interfaces_or_ebtables
        write_config('disabled')
        runner = FakeRunner.new

        assert reconciler(runner).reconcile

        commands = runner.calls.map(&:first)
        refute commands.any? { |command| command.first == '/usr/sbin/ip' }
        refute commands.any? { |command| command.include?('/usr/sbin/ebtables-save') }
        assert_equal 'disabled', guard_payloads(runner).last['mode']
    end

    def test_observe_mode_counts_without_a_drop_verdict
        write_config('observe')
        runner = FakeRunner.new(ip_output: '', ebtables_output: "*nat\nCOMMIT\n")

        assert reconciler(runner).reconcile

        payload = guard_payloads(runner).last
        assert_equal 'observe', payload['mode']
        assert_equal [], payload['targets']
    end

    def test_enforce_mode_counts_and_drops
        write_config('enforce', "temporary_targets=192.0.2.1,192.0.2.2\n")
        runner = FakeRunner.new(ip_output: '', ebtables_output: "*nat\nCOMMIT\n")

        assert reconciler(runner).reconcile

        payload = guard_payloads(runner).last
        assert_equal ['192.0.2.1', '192.0.2.2'], payload['targets']
        assert_equal 'enforce', payload['mode']
    end

    def test_invalid_config_is_rejected_without_interpolation
        write_config('enforce', "table_name=guard; flush ruleset\n")
        runner = FakeRunner.new

        refute reconciler(runner).reconcile

        payload = guard_payloads(runner).last
        assert_equal 'disabled', payload['mode']
        refute_includes JSON.generate(payload), 'flush ruleset'
    end

    def test_table_name_is_reserved_and_invalid_value_fails_open
        write_config('enforce', "table_name=another_table\n")
        runner = FakeRunner.new

        refute reconciler(runner).reconcile

        payload = guard_payloads(runner).last
        assert_equal 'disabled', payload['mode']
    end

    def test_failed_transaction_validation_is_not_applied_and_then_fails_open
        write_config('enforce')
        failed_once = false
        runner = FakeRunner.new(ip_output: '', ebtables_output: "*nat\nCOMMIT\n") do |command, input|
            next unless command == ['sudo', '-n', VnfilterArpGuard::NFT_HELPER, '--check']
            next unless JSON.parse(input)['mode'] == 'enforce' && !failed_once

            failed_once = true
            VnfilterArpGuard::CommandError.new('nft validation failed')
        end

        refute reconciler(runner).reconcile

        applied = guard_payloads(runner)
        assert_equal 1, applied.length
        assert_equal 'disabled', applied.first['mode']
    end

    def test_reconciliation_is_serialized_by_one_host_lock
        write_config('observe')
        runner = FakeRunner.new(ip_output: '', ebtables_output: "*nat\nCOMMIT\n")
        instances = 2.times.map { reconciler(runner) }

        results = instances.map { |instance| Thread.new { instance.reconcile } }.map(&:value)

        assert_equal [true, true], results
        assert_equal 1, runner.max_active
    end

    def test_matching_chain_outside_nat_does_not_satisfy_readiness
        write_config('enforce')
        ebtables = <<~OUTPUT
            *filter
            :one-12-0-o-arp4 DROP
            :one-13-1-o-arp4 DROP
            COMMIT
            *nat
            COMMIT
        OUTPUT
        runner = FakeRunner.new(ip_output: IP_LINKS, ebtables_output: ebtables)

        refute reconciler(runner).reconcile
        assert_equal 'disabled', guard_payloads(runner).last['mode']
    end

    def test_ebtables_save_format_without_commit_is_supported
        write_config('observe')
        runner = FakeRunner.new(ip_output: '', ebtables_output: "*nat\n")

        assert reconciler(runner).reconcile
        assert_equal 'observe', guard_payloads(runner).last['mode']
    end

    def test_nft_helper_refuses_an_unowned_existing_table
        runner = FakeNftRunner.new(table_exists: true)
        payload = JSON.generate(
            'version' => 1,
            'mode' => 'disabled',
            'ingress_interface' => 'bond0.1',
            'targets' => []
        )

        error = begin
            nft_manager(runner).apply(payload)
            nil
        rescue VnfilterArpGuardNft::Error => e
            e
        end

        assert error
        assert_includes error.message, 'unowned bridge table'
        assert_equal [], runner.submissions
    end

    def test_nft_helper_claims_only_reserved_table_and_applies_atomically
        runner = FakeNftRunner.new
        payload = JSON.generate(
            'version' => 1,
            'mode' => 'enforce',
            'ingress_interface' => 'bond0.1',
            'targets' => ['192.0.2.9']
        )

        nft_manager(runner).apply(payload)

        assert_equal [true, false], runner.submissions.map(&:last)
        program = runner.submissions.last.first
        assert_includes program, 'table bridge one_arp_guard'
        assert_includes program, 'counter drop'
        refute_includes program, 'flush ruleset'
        state = JSON.parse(File.read(File.join(@directory, 'owner.json')))
        assert_equal VnfilterArpGuardNft::OWNER_STATE, state
    end

    def test_nft_helper_builds_disabled_observe_and_enforce_modes
        manager = nft_manager(FakeNftRunner.new)
        base = {
            'version' => 1,
            'ingress_interface' => 'bond0.1',
            'targets' => []
        }

        disabled = manager.program(manager.parse_payload(JSON.generate(base.merge('mode' => 'disabled'))))
        observe = manager.program(manager.parse_payload(JSON.generate(base.merge('mode' => 'observe'))))
        enforce = manager.program(manager.parse_payload(JSON.generate(base.merge('mode' => 'enforce'))))

        refute_includes disabled, 'add chain'
        assert_includes observe, 'counter'
        refute_includes observe, 'counter drop'
        assert_includes enforce, 'counter drop'
    end

    def test_nft_helper_rejects_extra_fields_and_noncanonical_targets
        manager = nft_manager(FakeNftRunner.new)
        base = {
            'version' => 1,
            'mode' => 'observe',
            'ingress_interface' => 'bond0.1',
            'targets' => []
        }

        [base.merge('extra' => true), base.merge('targets' => ['192.0.2.1/32'])].each do |payload|
            error = begin
                manager.parse_payload(JSON.generate(payload))
                nil
            rescue VnfilterArpGuardNft::Error => e
                e
            end
            assert error
        end
    end

    def test_partial_alias_failure_forces_guard_open_and_exits_nonzero
        hook = File.read(File.expand_path('../remotes/hooks/alias_ip/vnfilter.rb', __dir__))

        assert_includes hook, 'VnfilterArpGuard.fail_open(logger: @slog)'
        assert_includes hook, 'exit(mutations_ok ? 0 : 1)'
    end

    def test_installer_preserves_ebtables_and_uses_constrained_helper
        installer = File.read(File.expand_path('../install.sh', __dir__))

        assert_includes installer, "'oneadmin ALL=(ALL) NOPASSWD: /usr/sbin/ebtables'"
        assert_includes installer, 'vnfilter-arp-guard-nft --check'
        assert_includes installer, 'vnfilter-arp-guard-nft --apply'
        refute_includes installer, '/usr/sbin/nft -f -'
    end

    def test_live_uninstall_requires_disabled_acknowledgement_and_removes_remote
        uninstaller = File.read(File.expand_path('../uninstall_vnfilter.sh', __dir__))

        assert_includes uninstaller, '--arp-guard-disabled'
        assert_includes uninstaller, 'remove_owned "$REMOTES/vnm/arp_guard.rb"'
    end
end

failures = []
tests = ArpGuardTest.instance_methods(false).grep(/\Atest_/).sort

tests.each do |name|
    test = ArpGuardTest.new
    begin
        test.setup
        test.public_send(name)
        print '.'
    rescue StandardError => e
        failures << [name, e]
        print 'F'
    ensure
        test.teardown
    end
end


puts "\n#{tests.length} tests, #{failures.length} failures"
failures.each do |name, error|
    warn "#{name}: #{error.class}: #{error.message}"
    warn error.backtrace.first(5).join("\n")
end
exit(failures.empty? ? 0 : 1)
