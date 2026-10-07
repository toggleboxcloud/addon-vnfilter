# Shared firewall safety contract. Keep this file byte-identical to
# addon-smtp_filter's smtp_filter_firewall_safety.rb.
require 'open3'
require 'shellwords'

unless defined?(AddonFirewallSafety)
    module AddonFirewallSafety
        class Error < StandardError; end
        class LockBusy < Error; end

        REQUIRED_VALUES = {
            '-p' => 1, '-j' => 1, '-g' => 1, '-m' => 1, '-s' => 1, '-d' => 1,
            '-i' => 1, '-o' => 1, '--physdev-in' => 1, '--physdev-out' => 1,
            '--comment' => 1, '--dports' => 1, '--dport' => 1, '--sport' => 1,
            '--arp-ip-src' => 1, '--arp-ip-dst' => 1, '--arp-mac-src' => 1,
            '--arp-mac-dst' => 1, '--arp-op' => 1, '--match-set' => 2
        }.freeze

        def self.open_lock(path, nonblocking: false)
            file = File.open(path, File::RDWR | File::CREAT | File::NOFOLLOW | File::NONBLOCK, 0o600)
            begin
                stat = file.stat
                unless stat.file? && stat.uid == Process.euid && stat.nlink == 1 && (stat.mode & 0o022).zero?
                    raise Error, "unsafe firewall lock #{path}"
                end
                mode = File::LOCK_EX | (nonblocking ? File::LOCK_NB : 0)
                raise LockBusy, "firewall lock busy: #{path}" unless file.flock(mode)
                file
            rescue Exception
                file.close
                raise
            end
        end

        def self.with_lock(path, nonblocking: false)
            file = open_lock(path, nonblocking: nonblocking)
            begin
                yield
            ensure
                file.close
            end
        end

        # Compare option groups, allowing save tools to reorder matches/comments.
        # Negation belongs to its option, regardless of which side it is printed on.
        def self.rule_key(tokens)
            groups = []
            negate = false
            index = 0
            while index < tokens.length
                token = tokens[index]
                if token == '!'
                    negate = true
                    index += 1
                    next
                end
                raise Error, "invalid rule token #{token.inspect}" unless token.start_with?('-')
                group = [token]
                index += 1
                if token == '--comment'
                    raise Error, 'missing comment value' unless tokens[index]
                    group << tokens[index]
                    index += 1
                end
                while token != '--comment' && index < tokens.length && !tokens[index].start_with?('-')
                    value = tokens[index]
                    if value == '!'
                        break if tokens[index + 1]&.start_with?('-')
                        negate = true
                    else
                        value = value.delete_suffix('/32') if value.match?(/\A\d+\.\d+\.\d+\.\d+\/32\z/)
                        if %w[-s -d --arp-mac-src --arp-mac-dst].include?(token)
                            value = 'ff:ff:ff:ff:ff:ff' if value.casecmp('Broadcast').zero?
                            value = value.split(':').map { |part| part.rjust(2, '0') }.join(':').downcase if value.match?(/\A[0-9a-fA-F]{1,2}(:[0-9a-fA-F]{1,2}){5}\z/)
                        end
                        if token == '-p'
                            value = { '0x0800' => 'ipv4', '0x800' => 'ipv4', '0x0806' => 'arp', '0x806' => 'arp', '0x86dd' => 'ipv6', '0x8035' => 'rarp' }.fetch(value.downcase, value.downcase)
                        elsif token == '--arp-op'
                            value = { 'request' => '1', 'reply' => '2', 'request_reverse' => '3', 'reply_reverse' => '4' }.fetch(value.downcase, value)
                        end
                        group << value
                    end
                    index += 1
                end
                expected = REQUIRED_VALUES[token]
                raise Error, "missing or invalid values for #{token}" if expected && group.length != expected + 1
                group << '!' if negate
                negate = false
                groups << group
            end
            raise Error, 'dangling rule negation' if negate
            groups.sort
        end

        class Inventory
            attr_reader :chains, :rules

            def initialize(output, table:, ebtables: false)
                @chains = {}
                @rules = []
                current = nil
                seen = []
                output.each_line do |line|
                    text = line.strip
                    next if text.empty?
                    if text.start_with?('*')
                        raise Error, 'incomplete firewall table' if current
                        current = text.delete_prefix('*')
                        raise Error, 'invalid or duplicate firewall table' unless current.match?(/\A\w+\z/) && !seen.include?(current)
                        seen << current
                    elsif text == 'COMMIT'
                        raise Error, 'firewall terminator outside table' unless current
                        current = nil
                    elsif ebtables && text.match?(/\A# Completed on .+/)
                        current = nil
                    elsif text.start_with?('#')
                        next
                    else
                        raise Error, 'firewall data outside table' unless current
                        tokens = Shellwords.split(text)
                        if tokens[0]&.start_with?(':')
                            raise Error, 'invalid chain declaration' unless valid_chain_declaration?(tokens)
                            if current == table
                                name = tokens[0].delete_prefix(':')
                                raise Error, 'duplicate chain declaration' if @chains.key?(name)
                                @chains[name] = tokens[1]
                            end
                        elsif tokens[0] == '-A' && tokens.length >= 4
                            AddonFirewallSafety.rule_key(tokens.drop(2))
                            @rules << tokens if current == table
                        else
                            raise Error, "invalid firewall inventory line: #{text}"
                        end
                    end
                end
                raise Error, 'missing or incomplete firewall table' if current || !seen.include?(table)
                raise Error, 'rule in undeclared chain' unless @rules.all? { |rule| @chains.key?(rule[1]) }
            rescue ArgumentError => e
                raise Error, "invalid firewall inventory: #{e.message}"
            end

            def valid_chain_declaration?(tokens)
                (2..3).cover?(tokens.length) &&
                    tokens[0].match?(/\A:[\w.:-]+\z/) &&
                    %w[ACCEPT DROP RETURN -].include?(tokens[1]) &&
                    (tokens[2].nil? || tokens[2].match?(/\A\[\d+:\d+\]\z/))
            end
            private :valid_chain_declaration?

            def matching(chain, spec)
                key = AddonFirewallSafety.rule_key(spec)
                @rules.select { |rule| rule[1] == chain && AddonFirewallSafety.rule_key(rule.drop(2)) == key }
            end
        end

        def self.transient?(stderr)
            stderr.include?('Device or resource busy') ||
                stderr.include?('Resource temporarily unavailable') ||
                stderr.match?(/(?:xtables lock|another app is currently holding|temporarily unavailable)/i) ||
                (stderr.include?('RULE_DELETE failed') && stderr.include?('No such file or directory'))
        end

        def self.missing?(stderr)
            stderr.match?(/No such file or directory|does not exist|No chain\/target\/match by that name|Bad rule \(does a matching rule exist/)
        end

        class Backend
            attr_reader :table

            def initialize(tool:, table:, runner: nil, sleeper: Kernel.method(:sleep), prefix: nil)
                @tool = tool
                @table = table
                @runner = runner || ->(argv) { Open3.capture3(*argv) }
                @sleeper = sleeper
                locking_args = tool == 'ebtables' ? ['--concurrent'] : ['-w', '3']
                @prefix = prefix || ['sudo', '-n', tool, *locking_args]
            end

            def capture(argv)
                @runner.call(argv)
            rescue SystemCallError => e
                raise Error, "#{Shellwords.join(argv)}: #{e.message}"
            end

            def inventory(refresh: false)
                @inventory = nil if refresh
                @inventory ||= begin
                    output, stderr, status = capture(['sudo', '-n', "#{@tool}-save"])
                    raise Error, "#{@tool}-save failed: #{stderr}" unless status.success?
                    Inventory.new(output, table: @table, ebtables: @tool == 'ebtables')
                end
            end

            def desired?(state, args, before_count)
                operation, chain, *spec = args
                case operation
                when '-N'
                    state.chains.key?(chain) && (!spec.include?('-P') || state.chains[chain] == spec[spec.index('-P') + 1])
                when '-F'
                    state.rules.none? { |rule| rule[1] == chain }
                when '-X'
                    !state.chains.key?(chain)
                when '-A', '-I'
                    if operation == '-I' && spec.first&.match?(/\A\d+\z/)
                        position = Integer(spec.shift)
                        rule = state.rules.select { |entry| entry[1] == chain }[position - 1]
                        rule && AddonFirewallSafety.rule_key(rule.drop(2)) == AddonFirewallSafety.rule_key(spec)
                    else
                        !state.matching(chain, spec).empty?
                    end
                when '-D'
                    state.matching(chain, spec).length < before_count || before_count.zero?
                when '-R'
                    position = Integer(spec.shift)
                    rule = state.rules.select { |entry| entry[1] == chain }[position - 1]
                    rule && AddonFirewallSafety.rule_key(rule.drop(2)) == AddonFirewallSafety.rule_key(spec)
                else
                    raise Error, "unsupported firewall mutation #{operation}"
                end
            end

            # Retry only the current mutation. Readback resolves applied-but-failed
            # operations; a missing-target diagnostic alone never proves deletion.
            def reconcile(args, max_attempts: 5)
                state = inventory
                before_count = args[0] == '-D' ? state.matching(args[1], args.drop(2)).length : 0
                return state if desired?(state, args, before_count)
                max_attempts.times do |attempt|
                    _, stderr, status = capture(@prefix + ['-t', @table] + args)
                    retryable = AddonFirewallSafety.transient?(stderr) ||
                        (args[0] == '-N' && stderr.match?(/Chain already exists|File exists/)) ||
                        (%w[-D -F -X].include?(args[0]) && AddonFirewallSafety.missing?(stderr))
                    raise Error, "#{@tool} #{Shellwords.join(args)} failed: #{stderr}" unless status.success? || retryable
                    state = inventory(refresh: true)
                    return state if desired?(state, args, before_count)
                    @sleeper.call(0.2 * (attempt + 1)) if attempt + 1 < max_attempts
                end
                raise Error, "#{@tool} #{Shellwords.join(args)} did not converge after #{max_attempts} attempts"
            end
        end

        module LifecycleLock
            def lock
                @locking_file = AddonFirewallSafety.open_lock(firewall_lock_path)
            end

            def unlock
                @locking_file&.close unless @locking_file&.closed?
                @locking_file = nil
            end
        end

        # Addon-local replacement for shell command batches. Preserve OpenNebula's
        # version-aware command prefixes, but pass all arguments directly as argv.
        class Commands < Array
            def add(command, args)
                prefix = VNMMAD::VNMNetwork::COMMANDS.fetch(command) { command.to_s }
                self << [Shellwords.split(prefix), Shellwords.split(args)]
            end

            def run!
                output = map do |prefix, args|
                    tool = prefix.find { |token| %w[iptables ip6tables].include?(token) }
                    if tool && %w[-A -I -R -N -D -F -X].include?(args.first)
                        Backend.new(tool: tool, table: 'filter', prefix: prefix).reconcile(args)
                        ''
                    else
                        stdout, stderr, status = Open3.capture3(*(prefix + args))
                        raise Error, "#{Shellwords.join(prefix + args)} failed: #{stderr}" unless status.success?
                        stdout
                    end
                end.join
                clear
                output
            end
        end
    end
end
