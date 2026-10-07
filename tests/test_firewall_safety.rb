require 'minitest/autorun'
require 'minitest/mock'
require 'tmpdir'
require 'timeout'
helper = File.expand_path('../remotes/vnm/vnfilter_firewall_safety.rb', __dir__)
helper = File.expand_path('../smtp_filter_firewall_safety.rb', __dir__) unless File.file?(helper)
require helper
require_relative 'support/fake_firewall'

class FirewallSafetyTest < Minitest::Test
    def test_empty_complete_tables_are_valid_but_missing_and_truncated_tables_fail
        assert_empty AddonFirewallSafety::Inventory.new("*nat\nCOMMIT\n", table: 'nat', ebtables: true).rules
        ["", "*nat\n", "*filter\nCOMMIT\n", "*nat\n*filter\nCOMMIT\n", "*nat\nCOMMIT\n*nat\nCOMMIT\n", "*filter\n# Completed on yesterday\n*nat\n"].each do |dump|
            assert_raises(AddonFirewallSafety::Error) { AddonFirewallSafety::Inventory.new(dump, table: 'nat', ebtables: true) }
        end
    end

    def test_iptables_rejects_nft_ebtables_terminator_and_malformed_inventory
        ["*filter\n# Completed on today\n", "*filter\n:FORWARD ACCEPT\n-A FORWARD --comment \"broken\nCOMMIT\n", "*filter\n:FORWARD ACCEPT\n-A unknown -j DROP\nCOMMIT\n"].each do |dump|
            assert_raises(AddonFirewallSafety::Error) { AddonFirewallSafety::Inventory.new(dump, table: 'filter') }
        end
    end

    def test_exact_matching_preserves_nic_prefixes_and_quoted_comments
        dump = "*filter\n:smtp_filter - [0:0]\n-A smtp_filter -m comment --comment \"SMTP NIC 1's rule\" -m physdev --physdev-in one-42-10 -j REJECT\nCOMMIT\n"
        state = AddonFirewallSafety::Inventory.new(dump, table: 'filter')
        spec = ['-m', 'physdev', '--physdev-in', 'one-42-10', '-j', 'REJECT', '-m', 'comment', '--comment', "SMTP NIC 1's rule"]
        assert_equal 1, state.matching('smtp_filter', spec).length
        assert_empty state.matching('smtp_filter', spec.map { |token| token == 'one-42-10' ? 'one-42-1' : token })
    end

    def test_nft_normalizations_preserve_negation_and_exact_addresses
        original = %w[-p ARP --arp-ip-src 192.0.2.1 --arp-mac-src ! a:b:c:d:e:f --arp-op Request -j ACCEPT]
        saved = %w[-p 0x0806 --arp-ip-src 192.0.2.1/32 ! --arp-mac-src 0a:0b:0c:0d:0e:0f --arp-op 1 -j ACCEPT]
        assert_equal AddonFirewallSafety.rule_key(original), AddonFirewallSafety.rule_key(saved)
        refute_equal AddonFirewallSafety.rule_key(original), AddonFirewallSafety.rule_key(saved.reject { |token| token == '!' })
    end

    def test_rarp_ethertype_matches_saved_name
        assert_equal AddonFirewallSafety.rule_key(%w[-p 0x8035 -j ACCEPT]),
                     AddonFirewallSafety.rule_key(%w[-p RARP -j ACCEPT])
    end

    def test_all_backends_read_back_applied_errors_and_never_duplicate_adds
        %w[ebtables iptables ip6tables].each do |tool|
            fake = FakeFirewall.new(table: tool == 'ebtables' ? 'nat' : 'filter', ebtables: tool == 'ebtables')
            fake.chains['owned'] = 'DROP'
            fake.failure = ->(_args) { { applied: true, stderr: 'Device or resource busy' } }
            backend = fake.backend(tool: tool)
            2.times { backend.reconcile(%w[-A owned -j DROP]) }
            assert_equal 1, fake.rules.length
            assert_equal 1, fake.mutations.length
            assert_equal 2, fake.reads
            assert_includes fake.mutations.first, tool == 'ebtables' ? '--concurrent' : '-w'
            assert_equal ['sudo', '-n'], fake.mutations.first.take(2)
        end
    end

    def test_transient_before_application_retries_only_current_operation
        fake = FakeFirewall.new
        fake.chains['owned'] = 'DROP'
        failures = 0
        fake.failure = lambda do |args|
            if args.last == 'ACCEPT' && (failures += 1) == 1
                { applied: false, stderr: 'RULE_DELETE failed (No such file or directory)' }
            end
        end
        backend = fake.backend
        backend.reconcile(%w[-A owned -j DROP])
        backend.reconcile(%w[-A owned -j ACCEPT])
        assert_equal 2, fake.rules.length
        assert_equal 1, fake.mutations.count { |argv| argv.last == 'DROP' }
        assert_equal [0.2], fake.pauses
    end

    def test_permanent_error_is_immediate_and_exhaustion_is_bounded
        fake = FakeFirewall.new
        fake.failure = ->(_args) { { applied: false, stderr: 'Operation not permitted' } }
        assert_raises(AddonFirewallSafety::Error) { fake.backend.reconcile(%w[-N owned -P DROP]) }
        assert_equal 1, fake.mutations.length
        assert_empty fake.pauses
        fake = FakeFirewall.new
        fake.failure = ->(_args) { { applied: false, stderr: 'Device or resource busy' } }
        assert_raises(AddonFirewallSafety::Error) { fake.backend.reconcile(%w[-N owned -P DROP]) }
        assert_equal 5, fake.mutations.length
        assert_equal [0.2, 0.4, 0.6, 0.8].map { |n| n.round(1) }, fake.pauses.map { |n| n.round(1) }
    end

    def test_failed_reads_never_imply_absence_or_success
        [1, 2].each do |read|
            fake = FakeFirewall.new
            fake.read_failure = read
            assert_raises(AddonFirewallSafety::Error) { fake.backend.reconcile(%w[-N owned -P DROP]) }
            assert_equal read - 1, fake.mutations.length
        end
        fake = FakeFirewall.new
        fake.raw_inventory = "*nat\n"
        assert_raises(AddonFirewallSafety::Error) { fake.backend.reconcile(%w[-N owned -P DROP]) }
        assert_empty fake.mutations
    end

    def test_missing_diagnostic_requires_verified_deletion
        fake = FakeFirewall.new
        fake.chains['owned'] = 'DROP'
        fake.rules << %w[-A owned -j DROP]
        fake.failure = ->(_args) { { applied: false, stderr: 'No such file or directory' } }
        assert_raises(AddonFirewallSafety::Error) { fake.backend.reconcile(%w[-D owned -j DROP]) }
        assert_equal 1, fake.rules.length
        assert_equal 5, fake.mutations.length
        fake.failure = ->(_args) { { applied: true, stderr: 'No such file or directory' } }
        backend = fake.backend
        2.times { backend.reconcile(%w[-D owned -j DROP]) }
        assert_empty fake.rules
        assert_equal 6, fake.mutations.length
    end

    def test_duplicate_deletion_and_repeated_chain_cleanup_are_idempotent
        fake = FakeFirewall.new
        fake.chains['owned'] = 'DROP'
        3.times { fake.rules << %w[-A owned -j DROP] }
        backend = fake.backend
        3.times { backend.reconcile(%w[-D owned -j DROP]) }
        backend.reconcile(%w[-F owned])
        2.times { backend.reconcile(%w[-X owned]) }
        assert_empty fake.rules
        refute fake.chains.key?('owned')
        assert_equal 4, fake.mutations.length
    end

    def test_positional_insert_and_replace_verify_applied_errors_without_replay
        fake = FakeFirewall.new(table: 'filter', ebtables: false)
        fake.rules << %w[-A FORWARD -j DROP]
        fake.rules << %w[-A FORWARD -j ACCEPT]
        fake.failure = ->(_args) { { applied: true, stderr: 'Device or resource busy' } }
        backend = fake.backend(tool: 'iptables')
        2.times { backend.reconcile(%w[-I FORWARD 1 -j ACCEPT]) }
        assert_equal %w[-A FORWARD -j ACCEPT], fake.rules.first
        assert_equal 1, fake.mutations.length
        2.times { backend.reconcile(%w[-R FORWARD 2 -j RETURN]) }
        assert_equal %w[-A FORWARD -j RETURN], fake.rules[1]
        assert_equal 2, fake.mutations.length
    end

    def test_legacy_commit_followed_by_completion_comment_is_valid
        inventory = AddonFirewallSafety::Inventory.new("*nat\nCOMMIT\n# Completed on fixture\n", table: 'nat', ebtables: true)
        assert_empty inventory.rules
    end

    def test_missing_rule_value_and_unsafe_lock_permissions_are_rejected
        assert_raises(AddonFirewallSafety::Error) do
            AddonFirewallSafety::Inventory.new("*filter\n:FORWARD ACCEPT\n-A FORWARD -j\nCOMMIT\n", table: 'filter')
        end
        Dir.mktmpdir do |dir|
            path = File.join(dir, 'lock')
            File.write(path, 'preserved')
            File.chmod(0o666, path)
            assert_raises(AddonFirewallSafety::Error) { AddonFirewallSafety.with_lock(path) { flunk } }
            assert_equal 'preserved', File.read(path)
            File.chmod(0o600, path)
            Process.stub(:euid, Process.euid + 1) do
                assert_raises(AddonFirewallSafety::Error) { AddonFirewallSafety.with_lock(path) { flunk } }
            end
        end
    end

    def test_locks_reject_symlinks_fifos_and_hardlinks_without_touching_targets
        Dir.mktmpdir do |dir|
            target = File.join(dir, 'target')
            File.write(target, 'preserved')
            path = File.join(dir, 'lock')
            File.symlink(target, path)
            assert_raises(Errno::ELOOP) { AddonFirewallSafety.with_lock(path) { flunk } }
            assert_equal 'preserved', File.read(target)
            File.unlink(path)
            File.link(target, path)
            assert_raises(AddonFirewallSafety::Error) { AddonFirewallSafety.with_lock(path) { flunk } }
            File.unlink(path)
            system('mkfifo', path) or raise 'mkfifo failed'
            assert_raises(AddonFirewallSafety::Error) { AddonFirewallSafety.with_lock(path) { flunk } }
        end
    end

    def test_exception_releases_lock_and_separate_addon_locks_are_independent
        Dir.mktmpdir do |dir|
            path = File.join(dir, 'vnfilter')
            assert_raises(RuntimeError) { AddonFirewallSafety.with_lock(path) { raise 'injected' } }
            AddonFirewallSafety.with_lock(path, nonblocking: true) do
                AddonFirewallSafety.with_lock(File.join(dir, 'smtpfilter'), nonblocking: true) { assert true }
                assert_raises(AddonFirewallSafety::LockBusy) { AddonFirewallSafety.with_lock(path, nonblocking: true) { flunk } }
            end
        end
    end

    def test_competing_process_waits_for_transaction_lock
        Dir.mktmpdir do |dir|
            path = File.join(dir, 'lock')
            ready_r, ready_w = IO.pipe
            acquired_r, acquired_w = IO.pipe
            owner = AddonFirewallSafety.open_lock(path)
            pid = fork do
                owner.close
                ready_r.close
                acquired_r.close
                ready_w.write('ready')
                ready_w.close
                AddonFirewallSafety.with_lock(path) { acquired_w.write('acquired') }
                acquired_w.close
                exit! 0
            end
            ready_w.close
            acquired_w.close
            Timeout.timeout(2) { assert_equal 'ready', ready_r.read(5) }
            assert_nil IO.select([acquired_r], nil, nil, 0.05)
            owner.close
            Timeout.timeout(2) { assert_equal 'acquired', acquired_r.read }
            Timeout.timeout(2) { Process.waitpid(pid) }
            assert_predicate $?, :success?
        ensure
            owner&.close unless owner&.closed?
            [ready_r, ready_w, acquired_r, acquired_w].compact.each { |io| io.close unless io.closed? }
            if pid
                begin
                    Process.kill('KILL', pid)
                    Process.waitpid(pid)
                rescue Errno::ESRCH, Errno::ECHILD
                end
            end
        end
    end
end
