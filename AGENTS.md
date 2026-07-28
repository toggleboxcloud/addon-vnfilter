# `addon-vnfilter`

Own repository (`toggleboxcloud/addon-vnfilter`). Canonical path
`/var/lib/one/repos/addon-vnfilter`.

Completes the anti-spoofing filter rules OpenNebula generates: alias IPv4/IPv6
spoof filtering on attach, detach and hotplug, and ARP filtering when
`FILTER_MAC_SPOOFING` is enabled. Supported VN MADs: `802.1Q` and `fw`.

Run every git command as `oneadmin`:
`su - oneadmin -c 'cd <path> && <git command>'`

## Branch model

- `master` - development trunk. This is our own repo, so trunk is authoritative.
- `site/cloud-<version>` - integrated composition pinned by the matching
  `opennebula-one` site branch.
- `deployed/<ref>` - older naming for the same role as `site/*`. Being retired.

`deployed/cloud-7.0.1` is the newest composition branch; there is **no
`site/cloud-7.2.1` yet**. Confirm which commit the 7.2.1 site composition pins
before assuming what production runs.

This file and its `CLAUDE.md` symlink are committed on `master`.

## Layout

- `remotes/` - the driver files that get installed.
- `patches/` - patches against upstream OpenNebula files.
- `scripts/` - helpers.
- `install.sh`, `uninstall_vnfilter.sh` - install and removal.
- `vnfilter.hooktemplate` - hook registration template.
- `vncheck.sh`, `debug.sh`, `shellcheck.sh` - verification and linting.
- `FIX_RACE.md` - notes on the hotplug race this addon has to handle.

## Install

`sudo ./install.sh` installs the deployed files, creates the `802.1Q` and `fw`
post/clean links, registers or updates the `vnfilter` hook, and runs
`onehost sync --force`.

That last step touches every host, so it is a deployment action, not a test.
Use an isolated staging root and skip hooks/sync when validating. Run
`./shellcheck.sh` before committing shell changes.

## Deployment boundary

`/var/lib/one/remotes` is the live production target and is retired as a
development repository. Never author changes there. Never register hooks, run
`onehost sync`, alter firewall rules, restart services, or change API/database
state without explicit deployment approval.
