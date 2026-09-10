# `addon-vnfilter`

Own repository. Canonical path `/var/lib/one/repos/addon-vnfilter`.
`origin` is `toggleboxcloud/addon-vnfilter`; `upstream` is
`storpool/addon-vnfilter`, the project this was derived from — read-only in
practice.

Completes the anti-spoofing filter rules OpenNebula generates: alias IPv4/IPv6
spoof filtering on attach, detach and hotplug, and ARP filtering when
`FILTER_MAC_SPOOFING` is enabled. Supported VN MADs: `802.1Q` and `fw`.

## Branch model

- `master` — development trunk. This is our own repo, so trunk is authoritative.
- `site/cloud-<version>` — integrated composition pinned by the matching
  `opennebula-one` site branch.
- `deployed/<ref>` — older naming for the same role as `site/*`. Being retired.

The newest composition has the highest `site/cloud-<version>` branch. Production
currently installs from `site/cloud-7.2.1`. `deployed/cloud-7.0.1` is retired
naming for the same role, not a newer composition.

Confirm which commit a composition pins rather than assuming — the pin lives in
`components.tsv` on the `opennebula-one` branch that carries a component lock,
and nowhere else:

Registry-carrying compositions keep the lock on the matching `opennebula-one`
`site/cloud-<version>` branch. The deployed `site/cloud-7.2.1` branch carries no
lock; its historical lock is on `origin/site/cloud-7.2.1r`, and its composed
installer resolves this repository from `VNFILTER_REPO`.

This file and its `CLAUDE.md` symlink are committed on `master` and maintained
`site/*` branches and must stay byte-identical. Keep this text version-generic;
change it everywhere or nowhere.

## Layout

- `remotes/` — the driver files that get installed.
- `patches/` — patches against upstream OpenNebula files.
- `scripts/` — helpers.
- `host/vnfilter_arp_guard_nft` — constrained root-owned nft transaction helper.
- `install.sh`, `uninstall_vnfilter.sh` — install and removal.
- `vnfilter.hooktemplate` — hook registration template.
- `vncheck.sh`, `debug.sh`, `shellcheck.sh` — verification and linting.
- `FIX_RACE.md` — notes on the hotplug race this addon has to handle.

Tracked on the site branches only. These paths do **not** exist on `master`:

- `manifests/cloud-<version>.tsv` — the deployment manifest. One row per file or
  link `install.sh` writes, with its mode or link target.
- `safe-install.py` — the confined writer. Byte-identical across
  `addon-storpool-mc`, `addon-smtp_filter` and `addon-vnfilter` by design, so
  `sha256sum` across those three is an audit. Change it in all three or none.
  `opennebula-one`'s copy is deliberately outside that set: the primary site
  installer writes no symlinks, so it has no `--link`.
- `tests/test_manifest_confinement.sh` — the manifest confinement regression.

## Install

`sudo ./install.sh` installs the deployed files, creates the `802.1Q` and `fw`
post/clean links, registers or updates the `vnfilter` hook, and runs
`onehost sync --force`.

That last step touches every host, so it is a deployment action, not a test. Use
an isolated staging root and skip hooks and sync when validating. Run
`./shellcheck.sh` before committing shell changes.

On a site branch the installer takes that file list from
`manifests/cloud-<version>.tsv` rather than a hardcoded array, validates the
manifest in full — the file itself and every row — before the first write, and
writes through `safe-install.py`, which resolves against `O_NOFOLLOW` descriptors
beneath a trusted root and sets mode and owner on the descriptor rather than on a
pathname. No pathname `install`, `ln` or `chown` is involved. On `master` the
file list is still hardcoded and the writes are still pathname based.

Safe flags for validation:

- `./install.sh --dest-root DIR` — isolated staging root, never touches hooks or
  hosts. Use this for testing.
- `./install.sh --check` — verify the live installation, writes nothing.
- `--no-sync`, `--no-hooks` — disable those operations.
- `sudo HOST_INSTALL=1 ./install.sh` — validate and install host prerequisites.
  Combined with `--check` it reports host prerequisites only and compares no
  deployed file, so it is never a content check.

`HOST_INSTALL=1` is **not** a manifest operation. It returns before the manifest
is read at all, so nothing it does is inside the confinement boundary, and it is
the only path by which this addon touches anything outside the remotes tree. It
may install `opennebula-rubygems`, installs the root-owned helper at
`/usr/local/sbin/vnfilter-arp-guard-nft`, and writes the complete
`/etc/sudoers.d/vnfilter` policy at mode 0440 when its privilege checks fail.

On a site branch, `bash tests/test_manifest_confinement.sh` is the regression
suite for that boundary. Run it as root: the staging fault injection needs root
and is skipped otherwise, and the run prints the skips it took.

## Deployment boundary

`/var/lib/one/remotes` is the live deployment target, not a development tree.
Registering hooks, running `onehost sync`, altering firewall rules, restarting
services and changing API or database state each need explicit deployment
approval.
