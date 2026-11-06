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

The authoritative Ansible checkout is `/home/ansible` on noc1. The persistent
configuration is `/etc/one/vnfilter-arp-guard.conf`. Before the cloud-dev rollout
on 2026-10-29, hv66 enforced and hv68/hv70 were disabled. All three now enforce.
All three use `br0` and `bond0.1`, with uplink VLAN 1. Revalidate each production
host's bridge, uplink and intended L2 domain before copying these settings.

Deployment order:

1. Pin the reviewed addon revision. Deploy `host/vnfilter_arp_guard_nft` through
   the owning host installer (`HOST_INSTALL=1 ./install.sh`) or the role's
   existing equivalent, to `/usr/local/sbin/vnfilter-arp-guard-nft`, root:root,
   mode 0755. Keep the constrained sudoers interface. The host installer checks
   prerequisites and can install gems if missing; confirm they are already
   present before scheduling it as a helper-only update.
2. Deploy frontend remotes with `./install.sh --no-hooks --no-sync`, then sync
   only the approved hosts with `onehost sync <approved-host-IDs> --force`.
   Resolve IDs against the intended controller first. SSH-mode sync (`--ssh`)
   failed on the development canary; standard scoped sync succeeded.
   The manifest adds `vnm/gratuitous_arp.rb` and updates
   `vnm/vnfilter.rb`. Verify bytes and modes on each host, including the root
   helper; host sync does not install that helper. Required modes are 0644 for
   `vnm/vnfilter.rb`, 0755 for `vnm/gratuitous_arp.rb`, and root:root 0755 for
   `/usr/local/sbin/vnfilter-arp-guard-nft`.
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


## Cloud-dev rollout evidence and production handoff

Deployed on 2026-10-29 from addon revision
`cbbe69eab092e5e191025d7281ea1b8d0ebcefcb`. The frontend installer passed its
content/mode check. hv66 passed the canary before serial deployment to hv68 and
hv70. All three enforce after Ansible convergence, with active, enabled timers
and verified GARP/suppression rules. Final receive-chain checks reported 22 on
hv66, 21 on hv68 and zero on hv70. Counts changed during VM lifecycle activity;
compare fresh NIC inventories at acceptance. hv70 had no br0 VM NICs.

### Ansible sources and helper promotion

The authoritative checkout on noc1 contains:

- `playbooks/deploy-cloud-dev-gratuitous-arp.yml`: frontend install, scoped
  sync, rollback captures, running-chain refresh and serial guard deployment.
  Its targets and controller IDs are specific to development. Create a
  separately scoped production rollout; `--limit` cannot retarget this playbook.
- `roles/opennebula_node/tasks/vnfilter_arp_guard.yml`: the owning role accepts
  the host variable `opennebula_vnfilter_arp_guard_helper_source`.
- hv66/hv68/hv70 pin that variable to
  `/home/ansible/files/vnfilter/cbbe69eab092e5e191025d7281ea1b8d0ebcefcb/vnfilter_arp_guard_nft`.
  The generic role default still uses the older
  `/home/ansible/files/vnfilter_arp_guard_nft`. Promote the reviewed helper pin
  explicitly for approved production hosts before role convergence; otherwise
  later Ansible runs can restore the older helper. Verify the production
  composition pin and frontend source independently.

The deployed helper SHA-256 is
`f0f895d33c1c7262bedeadf05e4f3e2411ec562a033aad9a3184bbc1b0976c71`.
Ansible changes were left uncommitted at handoff; review their current status
before preparing production deployment.

### Legacy-chain preflight

hv68's refresh initially stopped with
`unexpected receive chain one-10419-0-o-arp` before changing rules. Eighteen
legacy receive chains had no references, tap interfaces or libvirt domains.
Some were empty; others retained a three-rule layout without the IPv4 target
whitelist. The rollout validated every candidate under the VNM lifecycle lock
before flushing/deleting only those orphan chains, then reran the refresh.
Original files and firewall inventories were retained.

Inspect production receive-chain layouts before scheduling the refresh. If this
error occurs, establish current chain references, NIC/domain ownership and
lifecycle state. The hv68 cleanup is an exact development-only list, not a
production cleanup procedure. Preserve active or ambiguous chains; do not
weaken the refresh validator to accept an unknown layout.

### Acceptance evidence and remaining checks

- Ruby suites and root manifest-confinement tests passed. The isolated packet
  suite passed 90 cases, including 1,000/1,000 unowned requests suppressed,
  shared-IP neighbor replacement and refresh/rollback. It ran on hv66 because
  the cloud-dev frontend lacks ebtables. Keepalived was omitted.
- Retained lab VMs 18933 on hv66 and 18934 on hv68 received all four GARP
  Request/Reply and zero/broadcast target-MAC forms in both directions after
  enforcement and Ansible convergence. Each receiver lacked the announced
  primary address. Peer ping passed 2/2 in both directions; shared-VIP ping
  also passed 2/2. Guard drop counters rose during unowned-request probes;
  background traffic also contributed to those live counters.
- Nineteen focused Ansible tests passed. Five fake-backend checks covered orphan
  cleanup and refusal of referenced chains, existing domains and unknown
  layouts. Convergence showed no file drift; live runs reran the oneshot guard
  reconciler without changing files.
- Reboot persistence, Keepalived election/takeover and multicast VRRP were not
  validated during this rollout. Packet tests do not establish production
  switch policy or application HA behavior. Repeat canary traffic and
  suppression checks in the actual production domain.

Controller evidence is under
`/home/ansible/artifacts/vnfilter-garp-cbbe69e/`. Private rollback captures are
under `/var/tmp/vnfilter-garp-cbbe69e/` on cloud-dev and each node. Keep raw
firewall inventories and lab captures out of this repository. These paths and
VM IDs describe development; confirm they still exist before reuse and retain
fresh production rollback material.
