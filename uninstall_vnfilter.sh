#!/bin/bash
set -euo pipefail

STEP="all"
DEST_ROOT=""
NO_SYNC="${SKIP_HOSTS_SYNC:-}"

usage()
{
    echo "Usage: $0 [step1|step2|all] [--dest-root DIR] [--no-sync]"
}

if [[ $# -gt 0 && "$1" != --* ]]; then
    STEP="$1"
    shift
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dest-root)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            DEST_ROOT="$2"
            shift
            ;;
        --no-sync) NO_SYNC=1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
    shift
done

case "$STEP" in step1|step2|all) ;; *) usage >&2; exit 2 ;; esac

STAGING=0
if [[ -n "$DEST_ROOT" ]]; then
    STAGING=1
    ONE_VAR="${DEST_ROOT%/}/var/lib/one"
else
    ONE_VAR="${ONE_VAR:-/var/lib/one}"
    [[ $EUID -eq 0 ]] || { echo "Live uninstall must run as root" >&2; exit 1; }
fi
REMOTES="$ONE_VAR/remotes"

remove_owned()
{
    local path="$1"
    if [[ -e "$path" || -L "$path" ]]; then
        rm -f -- "$path"
    fi
}

if [[ "$STEP" == step1 || "$STEP" == all ]]; then
    if [[ $STAGING -eq 0 ]] && runuser -u oneadmin -- onehook show vnfilter >/dev/null 2>&1; then
        runuser -u oneadmin -- onehook delete vnfilter
    fi
    remove_owned "$REMOTES/vnm/802.1Q/post.d/vnfilter_post"
    remove_owned "$REMOTES/vnm/fw/post.d/vnfilter_post"
fi

if [[ "$STEP" == step2 || "$STEP" == all ]]; then
    remove_owned "$REMOTES/vnm/802.1Q/clean.d/vnfilter_clean"
    remove_owned "$REMOTES/vnm/fw/clean.d/vnfilter_clean"
    remove_owned "$REMOTES/vnm/vnfilter_post"
    remove_owned "$REMOTES/vnm/vnfilter_clean"
    remove_owned "$REMOTES/vnm/vnfilter.rb"
    remove_owned "$REMOTES/hooks/alias_ip/vnfilter.rb"
fi

if [[ $STAGING -eq 0 && -z "$NO_SYNC" ]]; then
    runuser -u oneadmin -- onehost sync --force
fi

if [[ "$STEP" == step1 ]]; then
    echo "Step 1 complete; migrate or restart affected VMs before step2"
else
    echo "Vnfilter uninstall $STEP complete"
fi

