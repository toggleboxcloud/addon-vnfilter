#!/usr/bin/env ruby

module VNMMAD
    class VNMDriver
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

class VnfilterEbtablesErrorsTest
    include Assertions

    def setup
        @filter = VnFilter.allocate
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
end

tests = VnfilterEbtablesErrorsTest.new
test_methods = VnfilterEbtablesErrorsTest.instance_methods(false).grep(/^test_/).sort
test_methods.each do |method|
    tests.setup
    tests.public_send(method)
    puts "#{method}: PASS"
end

puts "#{test_methods.length} tests, 0 failures"
