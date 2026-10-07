#!/bin/bash
set -euo pipefail
[[ $# -eq 1 ]] || { echo "Usage: $0 OTHER_ADDON_REPO" >&2; exit 2; }
repo="$(cd "$(dirname "$0")/.." && pwd)"
helper_path()
{
    if [[ -f "$1/remotes/vnm/vnfilter_firewall_safety.rb" ]]; then
        printf '%s\n' "$1/remotes/vnm/vnfilter_firewall_safety.rb"
    else
        printf '%s\n' "$1/smtp_filter_firewall_safety.rb"
    fi
}
cmp -- "$(helper_path "$repo")" "$(helper_path "$1")"
echo "Firewall safety helpers are byte-identical"
