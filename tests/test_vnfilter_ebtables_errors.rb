#!/usr/bin/env ruby

module VNMMAD
    class VNMDriver
    end

    class VNMNetwork
        class Command
            class << self
                attr_accessor :events, :failure

                def run(command, args)
                    events << [:command, args]
                    stderr = failure.call(args)
                    ['', stderr, Struct.new(:success?).new(stderr.nil?)]
                end
            end
        end
    end
end

$LOADED_FEATURES << 'vnmmad.rb'
require_relative '../remotes/vnm/vnfilter'

module Assertions
    def assert(value, message = 'assertion failed')
        raise message unless value
    end

    def refute(value, message = 'refutation failed')
        raise message if value
    end
end

class TestLogger
    def info(_message); end
    def warn(_message); end
end

# Keep production command execution, classification, cleanup discovery and retry
# loops; replace only host I/O and sleeping.
class TestFilter < VnFilter
    def initialize(events)
        @events = events
        @slog = TestLogger.new
    end

    def read_ebtables_nat
        @events << [:inventory]
        "*nat\n:one-1-0-o-arp4 DROP\nCOMMIT\n"
    end

    def sleep(seconds)
        @events << [:sleep, seconds]
    end
end

class VnfilterEbtablesErrorsTest
    include Assertions

    def setup
        @events = []
        @filter = TestFilter.new(@events)
        VNMMAD::VNMNetwork::Command.events = @events
        VNMMAD::VNMNetwork::Command.failure = ->(_args) { nil }
    end

    def test_chain_creation_collision_is_retryable
        assert @filter.retryable_ebtables_activation_error?(
            '-t nat -N one-3223-0-o-arp4 -P DROP',
            'ebtables: Chain already exists'
        )
    end

    def test_rule_delete_race_remains_retryable
        assert @filter.retryable_ebtables_activation_error?(
            '-t nat -A one-3223-0-o-arp4 -p ARP -j RETURN',
            'RULE_DELETE failed (No such file or directory)'
        )
    end

    def test_unrelated_activation_error_is_not_retryable
        refute @filter.retryable_ebtables_activation_error?(
            '-t nat -N one-3223-0-o-arp4 -P DROP',
            'Operation not permitted'
        )
    end

    def test_both_busy_chain_delete_diagnostics_are_retryable
        [
            'CHAIN_USER_DEL failed (Device or resource busy)',
            'CHAIN_DEL failed (Device or resource busy)'
        ].each do |message|
            assert @filter.busy_ebtables_cleanup_error?(
                '-t nat -X one-3225-0-i',
                message
            )
        end
    end

    def test_non_busy_cleanup_error_is_not_retryable
        refute @filter.busy_ebtables_cleanup_error?(
            '-t nat -X one-3225-0-i',
            'No chain/target/match by that name'
        )
    end
    def commands
        @events.select { |event| event.first == :command }.map(&:last)
    end

    def expect_error(type)
        begin
            yield
        rescue type
            return
        end
        raise "expected #{type}"
    end

    def test_collision_cleans_partial_state_then_replays_all_commands
        create = '-t nat -N one-1-0-o-arp4 -P DROP'
        append = '-t nat -A one-1-0-o-arp4 -p ARP -j RETURN'
        attempts = 0
        VNMMAD::VNMNetwork::Command.failure = lambda do |args|
            next unless args == create

            attempts += 1
            'Chain already exists' if attempts == 1
        end

        @filter.execute_ebtables_commands!('one-1-0', [create, append], retry_on_rule_delete: true)

        assert commands == [create, '-t nat -F one-1-0-o-arp4',
                            '-t nat -X one-1-0-o-arp4', create, append]
        assert @events.count { |event| event == [:sleep, 1] } == 1
        assert @events.count { |event| event == [:inventory] } == 2
    end

    def test_persistent_collision_stops_at_activation_retry_limit
        create = '-t nat -N one-1-0-o-arp4 -P DROP'
        VNMMAD::VNMNetwork::Command.failure = ->(args) { 'Chain already exists' if args == create }

        expect_error(VnFilter::EbtablesCommandError) do
            @filter.execute_ebtables_commands!('one-1-0', [create], retry_on_rule_delete: true)
        end

        assert commands.count(create) == 3
        assert @events.select { |event| event.first == :sleep } == [[:sleep, 1], [:sleep, 2]]
    end

    def test_unrelated_error_and_disabled_retry_do_not_clean_or_replay
        create = '-t nat -N one-1-0-o-arp4 -P DROP'
        [['Operation not permitted', true], ['Chain already exists', false]].each do |error, retry_enabled|
            @events.clear
            VNMMAD::VNMNetwork::Command.failure = ->(_args) { error }
            expect_error(VnFilter::EbtablesCommandError) do
                @filter.execute_ebtables_commands!('one-1-0', [create], retry_on_rule_delete: retry_enabled)
            end
            assert @events == [[:command, create]]
        end
    end

    def test_busy_cleanup_refreshes_inventory_and_recovers
        ['CHAIN_USER_DEL', 'CHAIN_DEL'].each do |diagnostic|
            @events.clear
            attempts = 0
            VNMMAD::VNMNetwork::Command.failure = lambda do |args|
                next unless args.include?(' -X ')

                attempts += 1
                "#{diagnostic} failed (Device or resource busy)" if attempts == 1
            end
            @filter.deactivate_ebtables('one-1-0')
            assert @events.count { |event| event == [:inventory] } == 2
            assert commands == ['-t nat -F one-1-0-o-arp4', '-t nat -X one-1-0-o-arp4'] * 2
            assert @events.count { |event| event == [:sleep, 1] } == 1
        end
    end

    def test_persistent_busy_cleanup_stops_at_cleanup_retry_limit
        VNMMAD::VNMNetwork::Command.failure = lambda do |args|
            'CHAIN_DEL failed (Device or resource busy)' if args.include?(' -X ')
        end
        expect_error(VnFilter::EbtablesCleanupBusyError) { @filter.deactivate_ebtables('one-1-0') }
        assert @events.count { |event| event == [:inventory] } == 4
        assert @events.count { |event| event == [:sleep, 1] } == 3
    end

    def test_cleanup_failure_prevents_activation_replay
        create = '-t nat -N one-1-0-o-arp4 -P DROP'
        VNMMAD::VNMNetwork::Command.failure = lambda do |args|
            args == create ? 'Chain already exists' : 'Operation not permitted'
        end
        expect_error(VnFilter::EbtablesCommandError) do
            @filter.execute_ebtables_commands!('one-1-0', [create], retry_on_rule_delete: true)
        end
        assert commands == [create, '-t nat -F one-1-0-o-arp4']
        refute @events.any? { |event| event.first == :sleep }
    end

end

tests = VnfilterEbtablesErrorsTest.new
test_methods = VnfilterEbtablesErrorsTest.instance_methods(false).grep(/^test_/).sort
test_methods.each do |method|
    tests.setup
    tests.public_send(method)
    puts "#{method}: PASS"
end

puts "#{test_methods.length} tests, 0 failures"
