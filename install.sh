#!/bin/bash
set -euo pipefail

PATH="/bin:/usr/bin:/sbin:/usr/sbin:${PATH}"

ACTION="install"
DEST_ROOT=""
NO_SYNC="${SKIP_HOSTS_SYNC:-}"
NO_HOOKS="${SKIP_ONEHOOK_REGISTRATION:-}"
ONE_USER="${ONE_USER:-oneadmin}"
ONE_GROUP="${ONE_GROUP:-oneadmin}"

usage()
{
    echo "Usage: $0 [--check] [--dest-root DIR] [--no-sync] [--no-hooks]"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check) ACTION="check" ;;
        --dest-root)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            DEST_ROOT="$2"
            shift
            ;;
        --no-sync) NO_SYNC=1 ;;
        --no-hooks) NO_HOOKS=1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
    shift
done

[[ "${0///}" != "$0" ]] && cd "${0%/*}"

if [[ -n "${HOST_INSTALL:-}" ]]; then
    if [[ "$ACTION" == "check" ]]; then
        # This mode verifies HOST PREREQUISITES ONLY. It does not compare any
        # deployed file against source. Say so unambiguously and exit non-zero
        # so a caller cannot mistake it for a content check: a stray
        # HOST_INSTALL in the environment previously turned --check into a
        # silent pass.
        command -v ruby >/dev/null
        command -v ebtables-save >/dev/null
        echo "Vnfilter host prerequisites are available"
        echo "NOT A CONTENT CHECK: HOST_INSTALL is set, so no deployed file was compared." >&2
        exit 3
    fi
    [[ -z "$DEST_ROOT" ]] || { echo "HOST_INSTALL cannot be combined with --dest-root" >&2; exit 2; }
    [[ $EUID -eq 0 ]] || { echo "HOST_INSTALL must run as root" >&2; exit 1; }
    if ! rpm -q opennebula-rubygems >/dev/null 2>&1; then
        dnf -y install opennebula-rubygems
    fi
    if ! runuser -u oneadmin -- sudo -n /usr/sbin/ebtables-save >/dev/null 2>&1; then
        printf '%s\n' 'oneadmin ALL=(ALL) NOPASSWD: /usr/sbin/ebtables-save' > /etc/sudoers.d/vnfilter
        chmod 0440 /etc/sudoers.d/vnfilter
        visudo -cf /etc/sudoers.d/vnfilter
    fi
    echo "Vnfilter host prerequisites installed"
    exit 0
fi

STAGING=0
if [[ -n "$DEST_ROOT" ]]; then
    DEST_ROOT="$(realpath -m -- "$DEST_ROOT")"
    [[ "$DEST_ROOT" != "/" ]] ||
        { echo "--dest-root must not resolve to /" >&2; exit 2; }
    STAGING=1
    ONE_VAR="$DEST_ROOT/var/lib/one"
elif [[ -n "${ONE_LOCATION:-}" ]]; then
    ONE_VAR="${ONE_LOCATION%/}/var"
else
    ONE_VAR="${ONE_VAR:-/var/lib/one}"
fi
REMOTES="$ONE_VAR/remotes"

as_oneadmin()
{
    if [[ $EUID -eq 0 ]]; then
        runuser -u "$ONE_USER" -- "$@"
    else
        "$@"
    fi
}

# Single source of truth, shared with the composition generator. Keeping a
# second copy here let install, --check and lock generation drift apart.
MANIFEST="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/manifests/cloud-7.2.1.tsv"
[[ -f "$MANIFEST" ]] || { echo "missing $MANIFEST" >&2; exit 2; }

FILES=()
LINKS=()
while IFS=$'\t' read -r kind source destination value; do
    [[ -n "$kind" && "${kind:0:1}" != "#" ]] || continue
    rel="${destination#/var/lib/one/remotes/}"
    [[ "$rel" != "$destination" ]] ||
        { echo "manifest destination outside remotes: $destination" >&2; exit 2; }
    case "$kind" in
        file) FILES+=("$source|$rel|$value") ;;
        link) LINKS+=("$rel|$value") ;;
        *)    echo "unknown manifest kind: $kind" >&2; exit 2 ;;
    esac
done < "$MANIFEST"

hook_matches()
{
    [[ $STAGING -eq 0 ]] || return 0
    as_oneadmin onehook show vnfilter >/dev/null 2>&1
}

check_install()
{
    local failed=0 entry src rel mode link_rel target actual
    for entry in "${FILES[@]}"; do
        IFS='|' read -r src rel mode <<< "$entry"
        if ! cmp -s "$src" "$REMOTES/$rel"; then
            echo "DIFF $REMOTES/$rel"
            failed=1
        fi
    done
    for entry in "${LINKS[@]}"; do
        IFS='|' read -r link_rel target <<< "$entry"
        actual=""
        [[ -L "$REMOTES/$link_rel" ]] && actual="$(readlink "$REMOTES/$link_rel")"
        if [[ "$actual" != "$target" ]]; then
            echo "LINK $REMOTES/$link_rel -> ${actual:-missing} (expected $target)"
            failed=1
        fi
    done
    if [[ -z "$NO_HOOKS" ]] && ! hook_matches; then
        echo "HOOK vnfilter missing"
        failed=1
    fi
    [[ $failed -eq 0 ]]
}

if [[ "$ACTION" == "check" ]]; then
    check_install
    echo "Vnfilter installation matches source"
    exit 0
fi

if [[ $STAGING -eq 0 && $EUID -ne 0 ]]; then
    echo "Live installation must run as root" >&2
    exit 1
fi

for entry in "${FILES[@]}"; do
    IFS='|' read -r src rel mode <<< "$entry"
    install -D -m "$mode" "$src" "$REMOTES/$rel"
    if [[ $STAGING -eq 0 ]]; then
        chown "$ONE_USER:$ONE_GROUP" "$REMOTES/$rel"
    fi
done

for entry in "${LINKS[@]}"; do
    IFS='|' read -r link_rel target <<< "$entry"
    mkdir -p "$(dirname "$REMOTES/$link_rel")"
    ln -sfn "$target" "$REMOTES/$link_rel"
    if [[ $STAGING -eq 0 ]]; then
        chown -h "$ONE_USER:$ONE_GROUP" "$REMOTES/$link_rel"
    fi
done

if [[ $STAGING -eq 0 && -z "$NO_HOOKS" ]]; then
    if as_oneadmin onehook show vnfilter >/dev/null 2>&1; then
        as_oneadmin onehook update vnfilter "$PWD/vnfilter.hooktemplate"
    else
        as_oneadmin onehook create "$PWD/vnfilter.hooktemplate"
    fi
fi

if [[ $STAGING -eq 0 && -z "$NO_SYNC" ]]; then
    runuser -u oneadmin -- onehost sync --force
fi

check_install
echo "Vnfilter installation completed"
