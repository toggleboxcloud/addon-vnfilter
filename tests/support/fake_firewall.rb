# In-memory backend for offline regression tests. Never executes host commands.
class FakeFirewall
    Status = Struct.new(:success?)
    attr_reader :chains, :rules, :calls, :reads, :pauses
    attr_accessor :failure, :read_failure, :raw_inventory

    def initialize(table: 'nat', ebtables: true)
        @table = table
        @ebtables = ebtables
        @chains = ebtables ? { 'PREROUTING' => 'ACCEPT', 'POSTROUTING' => 'ACCEPT' } : { 'FORWARD' => 'ACCEPT' }
        @rules = []
        @calls = []
        @reads = 0
        @pauses = []
    end

    def backend(tool: @ebtables ? 'ebtables' : 'iptables', prefix: nil)
        AddonFirewallSafety::Backend.new(tool: tool, table: @table, runner: method(:capture), sleeper: ->(seconds) { @pauses << seconds }, prefix: prefix)
    end

    def dump
        "*#{@table}\n" + @chains.map { |chain, policy| ":#{chain} #{policy}\n" }.join +
            @rules.map { |rule| Shellwords.join(saved_rule(rule)) + "\n" }.join +
            (@ebtables ? "# Completed on test fixture\n" : "COMMIT\n")
    end

    # nft ebtables-save uses ethertype names even when commands used numbers.
    def saved_rule(rule)
        saved = rule.dup
        protocol = saved.index('-p')
        if @ebtables && protocol
            names = { '0x0800' => 'IPv4', '0x0806' => 'ARP', '0x8035' => 'RARP', '0x86dd' => 'IPv6' }
            saved[protocol + 1] = names.fetch(saved[protocol + 1].downcase, saved[protocol + 1])
        end
        saved
    end

    def capture(argv)
        @calls << argv
        if argv.last.end_with?('-save')
            @reads += 1
            return ['', 'Permission denied', Status.new(false)] if @read_failure == @reads
            return [@raw_inventory || dump, '', Status.new(true)]
        end
        args = argv.drop(argv.index('-t') + 2)
        failure = @failure&.call(args)
        apply(args) if failure.nil? || failure[:applied]
        ['', failure ? failure[:stderr] : '', Status.new(failure.nil?)]
    end

    def apply(args)
        action, chain, *spec = args
        case action
        when '-N'
            raise 'attempted duplicate chain creation' if @chains.key?(chain)
            @chains[chain] = spec.include?('-P') ? spec[spec.index('-P') + 1] : '-'
        when '-A', '-I'
            raise "missing chain #{chain}" unless @chains.key?(chain)
            position = action == '-I' && spec.first&.match?(/\A\d+\z/) ? Integer(spec.shift) : 1
            rule = ['-A', chain] + spec
            if action == '-I'
                indices = @rules.each_index.select { |index| @rules[index][1] == chain }
                index = indices[position - 1] || @rules.length
                @rules.insert(index, rule)
            else
                @rules << rule
            end
        when '-D'
            index = @rules.index(['-A', chain] + spec)
            raise 'attempted deletion of missing rule' unless index
            @rules.delete_at(index)
        when '-F'
            @rules.reject! { |rule| rule[1] == chain }
        when '-X'
            raise 'chain still referenced' if @rules.any? { |rule| rule[1] == chain || (rule.include?('-j') && rule[rule.index('-j') + 1] == chain) }
            @chains.delete(chain)
        when '-R'
            position = Integer(spec.shift)
            index = @rules.each_index.select { |idx| @rules[idx][1] == chain }[position - 1]
            raise 'missing replacement position' unless index
            @rules[index] = ['-A', chain] + spec
        else
            raise "unexpected mutation #{args.inspect}"
        end
    end

    def mutations
        @calls.reject { |argv| argv.last.end_with?('-save') }
    end
end
