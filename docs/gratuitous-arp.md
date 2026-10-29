# Gratuitous ARP delivery

Receive filtering permits broadcast Ethernet/IPv4 ARP Requests and Replies
whose sender and target IPv4 addresses are equal and nonzero. Hardware and
protocol lengths must be 6 and 4. The target hardware address is unrestricted,
covering zero and broadcast forms. VM source MAC, ARP sender MAC and assigned
source-IP checks still run first. An alias uses its parent NIC's MAC; a shared
address grants no permission to other senders.

The exception precedes the receive-side reply-MAC check and target-IP whitelist.
It requires no shared-address inventory, so upstream router announcements work
too. Existing bridge/VLAN boundaries, ordinary ARP filtering and probe behavior
remain in place.

## Backend compatibility

On ebtables-nft 1.8.10, `--arp-gratuitous` uses the kernel ARP compatibility
matcher. A zero sender-MAC mask activates its hardware-length validation while
matching every hardware address. The IP and gratuitous matches validate protocol
length. See the [kernel matcher](https://github.com/torvalds/linux/blob/v6.12/net/bridge/netfilter/ebt_arp.c).
The sanitized `tests/fixtures/ebtables-save/gratuitous-arp.txt` records the actual
backend spelling used by exact rule reconciliation.

nftables 1.0.9 rejects `arp saddr ip == arp daddr ip`. The guard instead compares
eight four-bit groups against constant sets of equal pairs. A mismatch returns
to the ordinary suppression rule; all eight matches accept the announcement.
Both complete addresses must be read before entering this chain: a truncated
packet otherwise skips mismatch rules and could reach the final accept.
The transaction stays inside the owned `one_arp_guard` table, using no packet
marks, dynamic address learning or common ARP rate-limit bucket.

## Tests

Run the Ruby suites with the site's minitest gem path:

```sh
export GEM_PATH=/usr/share/one/gems-dist
ruby tests/test_gratuitous_arp.rb
ruby tests/test_vnfilter_ebtables_errors.rb
ruby tests/test_alias_hook_retries.rb
ruby tests/test_firewall_safety.rb
sudo ruby tests/test_arp_guard.rb
sudo bash tests/test_manifest_confinement.sh
```

The kernel test refuses any initial namespace containing an interface other
than loopback. It creates two virtual hosts and their clients, connected only
inside a new namespace. It applies the production builders, reconciliation and
privileged helper with temporary ownership state. Every child namespace is
removed on exit.

```sh
sudo unshare --net python3 tests/test_gratuitous_arp_netns.py
sudo unshare --net python3 tests/test_gratuitous_arp_netns.py \
  --keepalived /path/to/keepalived
```

Keepalived is optional for the packet suite and required for the election test.
An extracted compatible distribution RPM suffices; package installation and
service registration are unnecessary. Its runtime directory is mounted privately
and it logs only into the temporary lab directory. The test uses unicast VRRP.
Production multicast election policy needs separate validation.

The suite exercises shared-IP owners with different parent MACs, same-host and
cross-host clients with and without aliases, Request/Reply and zero/broadcast
target MAC forms, upstream addresses with no owner, all 32 unequal address bits,
all four-bit pair values, malformed lengths and truncated packets, probes,
source spoofing, VLAN/bridge isolation, 1,000 unowned requests, neighbor-cache
replacement, alias detach/rebuild, existing-chain refresh and rollback. With
Keepalived it also verifies one elected master, loss of that master's interface,
automatic takeover, received announcements and client reachability.

## Existing VM chains

Host sync copies code; it does not regenerate running VM rules. As `oneadmin`
on each approved host, after deploying the new files:

```sh
ruby /var/tmp/one/vnm/gratuitous_arp.rb --apply
ruby /var/tmp/one/vnm/gratuitous_arp.rb --check
ruby /var/tmp/one/vnm/arp_guard.rb
```

The refresh holds the same lock as VNM lifecycle operations, validates all
discovered receive-chain layouts before writing, and changes only exact GARP
exceptions. It preserves source filters and unrelated rules, resolves duplicate
or misplaced exceptions, and checks each mutation through backend readback.
A failure exits nonzero. Check the reported chain count against the host's
filtered NIC inventory; zero chains does not prove that VMs are protected.
Both `802.1Q` and `fw` lifecycle entrypoints use the same builder for new NICs.

## Ansible handoff and deployment order

The Ansible checkout is maintained separately by the operator. The persistent
configuration is `/etc/one/vnfilter-arp-guard.conf`. Observed on 2026-10-29:
hv66 enforces; hv68 and hv70 are disabled. All three use `br0` and `bond0.1`;
the uplink is VLAN 1 on each, but this alone does not prove a shared L2 domain.

Required changes to that owning role:

1. Pin the reviewed addon revision. Deploy `host/vnfilter_arp_guard_nft` through
   the owning host installer (`HOST_INSTALL=1 ./install.sh`) or the role's
   existing equivalent, to `/usr/local/sbin/vnfilter-arp-guard-nft`, root:root,
   mode 0755. Keep the constrained sudoers interface. The host installer checks
   prerequisites and can install gems if missing; confirm they are already
   present before scheduling it as a helper-only update.
2. Deploy frontend remotes with `./install.sh --no-hooks --no-sync`, then sync
   only the approved hosts. The manifest adds `vnm/gratuitous_arp.rb` and updates
   `vnm/vnfilter.rb`. Verify bytes and modes on each host, including the root
   helper; host sync does not install that helper.
3. Run the existing-VM refresh above on a canary. Test shared-IP announcements
   to an ordinary client and confirm unowned request suppression before
   proceeding. Preserve the current guard modes until each host passes.
4. In each host's existing configuration data, set `mode=enforce`. Preserve
   `ingress_interface=bond0.1`, `bridge=br0`, `table_name=one_arp_guard`, and
   `temporary_targets=` only after confirming they describe that host's intended
   domain. Render the file through Ansible and run the guard reconciler. Do not
   add VIPs as temporary targets to substitute for the packet exception.
5. Verify persistent configuration and `nft list table bridge one_arp_guard`,
   then repeat after Ansible convergence. Use an approved maintenance window
   for reboot persistence validation. Keep existing timers/handlers intact.

Before rollout, retain previous addon/helper bytes, configuration, ebtables and
nft inventories. Deployment, sync, firewall reconciliation and persistent mode
changes require explicit approval; these commands describe the handoff.

For rollback, run the new `gratuitous_arp.rb --remove` while it is still present,
restore the previous addon/helper and configuration through their installers
and Ansible, sync approved hosts and reconcile the guard. Verify the original
receive rules and client reachability. The old enforcing rules restore the
known GARP limitation. Do not run the broad broadcast-blocking script: it
flushes unrelated FORWARD rules.
