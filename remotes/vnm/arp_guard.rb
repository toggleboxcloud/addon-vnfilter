#!/usr/bin/env ruby

require 'fileutils'
require 'ipaddr'
require 'json'
require 'open3'
require 'shellwords'
require 'syslog/logger'

module VnfilterArpGuard
    CONFIG_PATH = '/etc/one/vnfilter-arp-guard.conf'.freeze
    LOCK_PATH = '/var/tmp/one/.vnfilter-arp-guard.lock'.freeze
    NFT_HELPER = '/usr/local/sbin/vnfilter-arp-guard-nft'.freeze
    TABLE_NAME = 'one_arp_guard'.freeze

    DEFAULTS = {
        'mode' => 'disabled',
        'ingress_interface' => 'bond0.1',
        'bridge' => 'br0',
        'table_name' => TABLE_NAME,
        'temporary_targets' => ''
    }.freeze
    MODES = %w[disabled observe enforce].freeze
    CONFIG_KEYS = DEFAULTS.keys.freeze
    INTERFACE_PATTERN = /\A[a-zA-Z0-9_.:-]{1,15}\z/
    TAP_PATTERN = /\Aone-\d+-\d+\z/

    class Error < StandardError; end
    class ConfigError < Error; end
    class CommandError < Error; end
    class ReadinessError < Error; end

    Config = Struct.new(
        :mode,
        :ingress_interface,
        :bridge,
        :temporary_targets,
        keyword_init: true
    )

    class CommandRunner
        def capture(*command, stdin_data: nil)
            stdout, stderr, status = Open3.capture3(*command, stdin_data: stdin_data)
            return stdout if status.success?

            message = stderr.to_s.strip
            message = stdout.to_s.strip if message.empty?
            raise CommandError, "#{command.join(' ')} failed: #{message}"
        rescue SystemCallError => e
            raise CommandError, "#{command.join(' ')} failed: #{e.message}"
        end
    end

    class Reconciler
        def initialize(
            config_path: CONFIG_PATH,
            lock_path: LOCK_PATH,
            runner: CommandRunner.new,
            logger: Syslog::Logger.new('vnfilter_arp_guard')
        )
            @config_path = config_path
            @lock_path = lock_path
            @runner = runner
            @logger = logger
        end

        def reconcile
            with_lock do
                config = load_config

                if config.mode == 'disabled'
                    apply_state(disabled_payload)
                    @logger.info('ARP guard reconciled in disabled mode')
                    return true
                end

                taps = live_taps(config.bridge)
                targets = (discover_targets(taps) + config.temporary_targets).uniq.sort
                apply_state(payload(config.mode, config.ingress_interface, targets))
                @logger.info(
                    "ARP guard reconciled mode=#{config.mode} " \
                    "taps=#{taps.length} targets=#{targets.length}"
                )
                true
            rescue StandardError => e
                @logger.error("ARP guard reconciliation failed: #{e.message}")
                fail_open
                false
            end
        end

        def fail_open
            apply_state(disabled_payload)
            @logger.warn("ARP guard fail-open state applied to bridge table #{TABLE_NAME}")
            true
        rescue Error => e
            @logger.error("ARP guard fail-open update failed: #{e.message}")
            false
        end

        def force_fail_open
            with_lock { fail_open }
        end

        def load_config
            values = DEFAULTS.dup
            seen = {}

            if File.exist?(@config_path)
                File.readlines(@config_path, chomp: true).each_with_index do |line, index|
                    stripped = line.strip
                    next if stripped.empty? || stripped.start_with?('#')

                    key, value = stripped.split('=', 2)
                    unless key && value && CONFIG_KEYS.include?(key) && value == value.strip
                        raise ConfigError, "invalid configuration on line #{index + 1}"
                    end
                    raise ConfigError, "duplicate configuration key #{key}" if seen[key]

                    seen[key] = true
                    values[key] = value
                end
            end

            validate_config(values)
        rescue SystemCallError => e
            raise ConfigError, "cannot read #{@config_path}: #{e.message}"
        end

        def validate_config(values)
            unless MODES.include?(values['mode'])
                raise ConfigError, "unsupported mode #{values['mode'].inspect}"
            end
            unless values['ingress_interface'].match?(INTERFACE_PATTERN)
                raise ConfigError, 'invalid ingress_interface'
            end
            unless values['bridge'].match?(INTERFACE_PATTERN)
                raise ConfigError, 'invalid bridge'
            end
            unless values['table_name'] == TABLE_NAME
                raise ConfigError, "table_name must be #{TABLE_NAME}"
            end

            raw_targets = values['temporary_targets']
            addresses = raw_targets.empty? ? [] : raw_targets.split(',', -1)
            if addresses.any?(&:empty?)
                raise ConfigError, 'temporary_targets contains an empty address'
            end

            Config.new(
                mode: values['mode'],
                ingress_interface: values['ingress_interface'],
                bridge: values['bridge'],
                temporary_targets: addresses.map do |address|
                    parse_ipv4(address, 'temporary target')
                end.uniq.sort
            )
        end

        def live_taps(bridge)
            output = @runner.capture('/usr/sbin/ip', '-o', 'link', 'show', 'master', bridge)

            output.each_line.filter_map do |line|
                match = line.match(/\A\d+: ([^:]+):/)
                raise ReadinessError, "cannot parse ip link output: #{line.strip}" unless match

                interface = match[1].split('@', 2).first
                interface if interface.match?(TAP_PATTERN)
            end.uniq.sort
        end

        def discover_targets(taps)
            output = @runner.capture('sudo', '-n', '/usr/sbin/ebtables-save')
            declarations = {}
            rules = Hash.new { |hash, key| hash[key] = [] }
            current_table = nil
            saw_nat = false

            output.each_line.with_index(1) do |line, line_number|
                stripped = line.strip
                next if stripped.empty? || stripped.start_with?('#')

                if stripped.start_with?('*')
                    current_table = stripped.delete_prefix('*')
                    unless current_table.match?(/\A[a-zA-Z0-9_]+\z/)
                        raise ReadinessError, "invalid ebtables table on line #{line_number}"
                    end
                    if current_table == 'nat'
                        raise ReadinessError, 'duplicate ebtables nat table' if saw_nat

                        saw_nat = true
                    end
                    next
                end
                if stripped == 'COMMIT'
                    raise ReadinessError, "ebtables COMMIT without table on line #{line_number}" unless current_table

                    current_table = nil
                    next
                end
                next unless current_table == 'nat'

                tokens = Shellwords.split(stripped)
                if tokens.first&.start_with?(':')
                    declarations[tokens.first.delete_prefix(':')] = true
                    next
                end
                next unless tokens.first == '-A'

                chain = tokens[1]
                next unless taps.any? { |tap| chain == "#{tap}-o-arp4" }

                address_index = tokens.index('--arp-ip-dst')
                next unless address_index

                address = tokens[address_index + 1]
                raise ReadinessError, "missing ARP target on ebtables line #{line_number}" unless address

                rules[chain] << parse_ipv4(address, "ebtables line #{line_number}")
            rescue ArgumentError => e
                raise ReadinessError, "cannot parse ebtables line #{line_number}: #{e.message}"
            end

            raise ReadinessError, 'missing ebtables nat table' unless saw_nat

            taps.flat_map do |tap|
                chain = "#{tap}-o-arp4"
                raise ReadinessError, "missing expected ebtables nat chain #{chain}" unless declarations[chain]

                rules[chain]
            end.uniq.sort
        end

        def parse_ipv4(address, context)
            parsed = IPAddr.new(address)
            unless parsed.ipv4? && address == parsed.to_s
                raise ReadinessError, "invalid IPv4 address #{address.inspect} in #{context}"
            end

            parsed.to_s
        rescue IPAddr::InvalidAddressError
            raise ReadinessError, "invalid IPv4 address #{address.inspect} in #{context}"
        end

        def disabled_payload
            payload('disabled', DEFAULTS['ingress_interface'], [])
        end

        def payload(mode, ingress_interface, targets)
            JSON.generate(
                'version' => 1,
                'mode' => mode,
                'ingress_interface' => ingress_interface,
                'targets' => targets
            )
        end

        def apply_state(payload_json)
            @runner.capture('sudo', '-n', NFT_HELPER, '--check', stdin_data: payload_json)
            @runner.capture('sudo', '-n', NFT_HELPER, '--apply', stdin_data: payload_json)
        end

        def with_lock
            FileUtils.mkdir_p(File.dirname(@lock_path))
            File.open(@lock_path, File::RDWR | File::CREAT, 0o644) do |lock|
                lock.flock(File::LOCK_EX)
                yield
            end
        rescue SystemCallError => e
            @logger.error("ARP guard lock failed: #{e.message}")
            false
        end
    end

    def self.reconcile(logger: Syslog::Logger.new('vnfilter_arp_guard'))
        Reconciler.new(logger: logger).reconcile
    end

    def self.fail_open(logger: Syslog::Logger.new('vnfilter_arp_guard'))
        Reconciler.new(logger: logger).force_fail_open
    end
end

exit(VnfilterArpGuard.reconcile ? 0 : 1) if $PROGRAM_NAME == __FILE__
