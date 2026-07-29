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
# safe-install.py descends its trusted root from "/" one component at a time, so
# the root has to be a path and not a cwd-relative fragment. A relative ONE_VAR
# used to be resolved against the working directory by install(1) and mkdir(1);
# resolve it the same way and up front, rather than with realpath(1), which
# would also collapse symlinked components.
[[ "$REMOTES" == /* ]] || REMOTES="$PWD/$REMOTES"

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
REPO_ROOT="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MANIFEST="$REPO_ROOT/manifests/cloud-7.4.0.tsv"
[[ -f "$MANIFEST" ]] || { echo "missing $MANIFEST" >&2; exit 2; }

# Manifest destinations are written as literal /var/lib/one/remotes/... paths,
# but the tree actually written is $REMOTES, which carries --dest-root or
# ONE_LOCATION. One place maps the one to the other; validation checks the
# literal string, every write and stat goes through here.
target_path()
{
    printf '%s/%s\n' "$REMOTES" "${1#"$ALLOWED_PREFIX"}"
}

# --- BEGIN manifest validation (extracted by tests/test_manifest_confinement.sh) ---
# This installer runs as root and takes both its sources and its destinations
# from a data file, so an unvalidated manifest is an arbitrary-write primitive.
# The previous check was a lexical prefix strip plus a test that the strip had
# changed the string, which is not confinement: a destination of
# /var/lib/one/remotes/../../../etc/pwn passes it and resolves outside the tree.
#
# Everything this addon installs lives under the remotes tree, so a single
# prefix describes every permitted destination.
ALLOWED_PREFIX="/var/lib/one/remotes/"

# Validated manifest rows, populated once by validate_manifest().
declare -a M_KIND=() M_SRC=() M_DEST=() M_VALUE=()

# Reject a destination whose parent chain traverses a symlink. Lexical checks on
# the path string are not enough: a pre-existing symlinked parent redirects the
# write while the string still looks confined.
parent_chain_is_safe()
{
    local target="$1" root="$2" dir
    dir="$(dirname "$target")"
    while [[ "$dir" != "/" && "$dir" != "." ]]; do
        if [[ -L "$dir" ]]; then
            echo "MANIFEST unsafe: $dir is a symlink on the path to $target" >&2
            return 1
        fi
        [[ "$dir" == "$root"* || "$root" == "$dir"* ]] || break
        dir="$(dirname "$dir")"
    done
    return 0
}

# Normalise an absolute path as a STRING: drop empty and "." components, and pop
# one component per "..". Nothing here stats or opens anything.
#
# Deliberately not realpath(1). realpath resolves existing symlinks, and every
# link row in this manifest installs a symlink AT its own destination, so a
# resolving check rejects the shipped manifest on any host it has already been
# installed on -- the exact bug hit and fixed in the StorPool port. What is being
# answered here is "where would this name point if nothing were a symlink", which
# is a question about the string, so the string is all this looks at.
lexical_normalise()
{
    local path="$1" comp out=""
    [[ "$path" == /* ]] || return 1
    while [[ -n "$path" ]]; do
        comp="${path%%/*}"
        if [[ "$comp" == "$path" ]]; then path=""; else path="${path#*/}"; fi
        case "$comp" in
            ""|.) ;;
            ..)
                # ".." at the root has nowhere left to go. Refuse rather than
                # clamp: POSIX clamping would silently turn an escape attempt
                # into a path that looks confined.
                [[ -n "$out" ]] || return 1
                out="${out%/*}"
                ;;
            *) out="$out/$comp" ;;
        esac
    done
    printf '%s\n' "${out:-/}"
}

validate_manifest()
{
    local bad=0 n=0 line kind source destination value resolved rest
    local -a fields
    local -A seen=() file_dests=()
    local -a link_dests=() link_lines=() link_targets=()

    # An unreadable or missing manifest makes the loop's redirection fail. The
    # function is called from an || list, so errexit is disabled inside it and
    # the run would continue to report "0 entries" and install nothing.
    [[ -f "$MANIFEST" && ! -L "$MANIFEST" && -r "$MANIFEST" ]] ||
        { echo "MANIFEST: $MANIFEST is not a readable regular file" >&2; return 1; }

    # read returns failure on a final record with no terminating newline, so the
    # loop body never sees it. A file truncated mid-row would then validate,
    # install and --check as though that row had never been written.
    [[ -s "$MANIFEST" && "$(tail -c1 -- "$MANIFEST" | wc -l)" -eq 1 ]] ||
        { echo "MANIFEST: $MANIFEST is empty or does not end with a newline" >&2; return 1; }

    # bash read silently drops NUL bytes, so "fi\0le" would reach the splitter
    # as "file" and validate: the fields checked would not be the bytes on disk.
    # Compare byte counts with and without NULs rather than trusting read.
    [[ "$(tr -d '\0' < "$MANIFEST" | wc -c)" -eq "$(wc -c < "$MANIFEST")" ]] ||
        { echo "MANIFEST: $MANIFEST contains NUL bytes" >&2; return 1; }

    while IFS= read -r line; do
        [[ -n "$line" && "${line:0:1}" != "#" ]] || continue
        n=$((n+1))

        # Tab is IFS whitespace to read(1), so "IFS=$'\t' read" folds a RUN of
        # tabs into a single delimiter: an empty field is never seen as empty,
        # it shifts every later column one to the left, and a row with an empty
        # source parses as a well-formed row with the wrong columns. Split by
        # hand, which keeps empty and trailing fields.
        #
        # Deliberately no sentinel byte: translating tabs to one would make a
        # field that already contains that byte indistinguishable from a
        # delimiter, so the accepted format would be wider than TSV and the
        # bytes validated would not be the bytes written.
        # Bounded at three splits: each one copies the shrinking remainder, so
        # an unbounded loop is quadratic in the tab count and a long junk line
        # costs seconds. Three splits is all a four-field row can need, and a
        # tab left in the remainder is exactly the "too many fields" case.
        fields=()
        rest="$line"
        while [[ "${#fields[@]}" -lt 3 && "$rest" == *$'\t'* ]]; do
            fields+=("${rest%%$'\t'*}")
            rest="${rest#*$'\t'}"
        done
        fields+=("$rest")

        [[ "${#fields[@]}" -eq 4 && "$rest" != *$'\t'* ]] ||
            { echo "MANIFEST line $n: expected 4 tab-separated fields" >&2; bad=1; continue; }
        kind="${fields[0]}"
        source="${fields[1]}"
        destination="${fields[2]}"
        value="${fields[3]}"
        case "$kind" in
            file|link) ;;
            *) echo "MANIFEST line $n: unknown kind: $kind" >&2; bad=1; continue ;;
        esac

        # destination: absolute, normalised, confined
        case "$destination" in
            /*) ;;
            *)  echo "MANIFEST line $n: destination not absolute: $destination" >&2; bad=1; continue ;;
        esac
        # Lexical only, for the reason given on lexical_normalise(): four rows
        # legitimately install a symlink AT their destination, so a check that
        # resolves symlinks rejects the shipped manifest once it is installed.
        # Symlinks are handled below, where the two kinds can differ.
        case "$destination" in
            *..*|*//*|*/|*/./*|*/.)
                echo "MANIFEST line $n: destination not normalised: $destination" >&2; bad=1; continue ;;
        esac
        # "?*" and not "*": the remotes root itself is not a destination.
        [[ "$destination" == "$ALLOWED_PREFIX"?* ]] ||
            { echo "MANIFEST line $n: destination outside $ALLOWED_PREFIX: $destination" >&2; bad=1; continue; }

        # duplicate destinations would make the result order-dependent
        [[ -z "${seen[$destination]:-}" ]] ||
            { echo "MANIFEST line $n: duplicate destination: $destination" >&2; bad=1; continue; }
        seen[$destination]=1

        case "$kind" in
            file)
                # source: repository-relative, normalised, no traversal
                case "$source" in
                    /*)      echo "MANIFEST line $n: absolute source: $source" >&2; bad=1; continue ;;
                    *..*)    echo "MANIFEST line $n: source contains ..: $source" >&2; bad=1; continue ;;
                    ""|*//*) echo "MANIFEST line $n: malformed source: $source" >&2; bad=1; continue ;;
                esac
                # Schema check: a manifest source is a regular file in the
                # repository, never a link. This is NOT protection for a mutable
                # worktree -- it sees only the leaf, and the source is opened
                # again later. What makes the source trustworthy is
                # install-all.sh reading it from a root-owned snapshot of a
                # verified commit.
                [[ -f "$REPO_ROOT/$source" && ! -L "$REPO_ROOT/$source" ]] ||
                    { echo "MANIFEST line $n: missing or non-regular source: $source" >&2; bad=1; continue; }
                [[ "$value" =~ ^0?[0-7][0-7][0-7]$ ]] ||
                    { echo "MANIFEST line $n: invalid mode: $value" >&2; bad=1; continue; }
                # A write follows a symlinked destination and lands on whatever
                # it points at. The remotes tree is oneadmin-writable, so a leaf
                # symlink planted there would redirect a root-run write. A link
                # row may replace a symlink -- it is renamed over, not followed
                # -- but a file row may not.
                if [[ -L "$(target_path "$destination")" ]]; then
                    echo "MANIFEST line $n: destination is an existing symlink: $destination" >&2
                    bad=1; continue
                fi
                # The set a link row's target has to be drawn from.
                file_dests[$destination]=1
                ;;
            link)
                [[ "$source" == "-" ]] ||
                    { echo "MANIFEST line $n: link source must be '-': $source" >&2; bad=1; continue; }
                # Unlike the StorPool manifest, these link targets are RELATIVE
                # (e.g. ../../vnfilter_post), so "must be absolute and under the
                # prefix" is the wrong rule. Resolve the target lexically
                # against the directory of its own destination and require the
                # result to stay inside the remotes tree. Creating a symlink is
                # not itself a write, but anything that later resolves through
                # it is.
                #
                # The join uses the manifest's literal destination, not the
                # $REMOTES-rooted one. A relative symlink resolves against its
                # own directory, so re-rooting the tree (--dest-root, or
                # ONE_LOCATION) moves both ends together and cannot change
                # whether the target stays inside remotes. Checking the literal
                # string keeps the verdict identical for a staged run, a live
                # run and a self-contained-mode run, and consults no filesystem.
                [[ -n "$value" ]] ||
                    { echo "MANIFEST line $n: empty link target" >&2; bad=1; continue; }
                case "$value" in
                    /*)  echo "MANIFEST line $n: link target must be relative: $value" >&2; bad=1; continue ;;
                    *//*) echo "MANIFEST line $n: link target not normalised: $value" >&2; bad=1; continue ;;
                    */)  echo "MANIFEST line $n: link target has a trailing slash: $value" >&2; bad=1; continue ;;
                esac
                resolved="$(lexical_normalise "${destination%/*}/$value")" ||
                    { echo "MANIFEST line $n: link target escapes the filesystem root: $value" >&2; bad=1; continue; }
                [[ "$resolved" == "$ALLOWED_PREFIX"?* ]] ||
                    { echo "MANIFEST line $n: link target leaves $ALLOWED_PREFIX: $value -> $resolved" >&2; bad=1; continue; }
                # Normalising under the prefix is necessary but NOT sufficient;
                # what the target may actually be is a cross-row question,
                # settled after every row has been parsed.
                link_dests+=("$destination")
                link_lines+=("$n"); link_targets+=("$resolved")
                ;;
        esac

        # Applies to staging as well: a symlink under DEST_ROOT redirects the
        # write outside the staging root just as effectively as under /.
        parent_chain_is_safe "$(target_path "$destination")" "$REMOTES" || bad=1

        # Retain the validated row. The install loop and --check use these
        # arrays, never a second read of the file, so the bytes that were
        # validated are the bytes that are used.
        M_KIND+=("$kind"); M_SRC+=("$source")
        M_DEST+=("$destination"); M_VALUE+=("$value")
    done < "$MANIFEST"

    # A manifest that installs nothing and still reports success is
    # indistinguishable from a completed deployment.
    [[ $n -gt 0 ]] ||
        { echo "MANIFEST: no entries in $MANIFEST" >&2; return 1; }

    # Validation completes before the first write, so a symlink this manifest is
    # about to create is not yet on disk for parent_chain_is_safe to see. A row
    # writing beneath a link row's destination would escape through it.
    local d l
    for d in "${M_DEST[@]}"; do
        for l in "${link_dests[@]}"; do
            [[ "$d" == "$l"/* ]] || continue
            echo "MANIFEST: $d is beneath link destination $l" >&2
            bad=1
        done
    done

    # A link target that merely NORMALISES under the remotes tree can still
    # resolve outside it. The per-row check above is lexical: if "redirect" is
    # already a symlink to /etc, then "redirect/payload" stays under the prefix
    # as a string while the installed link points at /etc/payload. So the
    # normalised target must be exactly the destination of a file row in THIS
    # manifest -- a path whose every component this manifest either installs or
    # has checked. Cross-row, and therefore here rather than inline: a link row
    # may precede the file row that installs its target.
    #
    # This is also why the target end is not left unchecked. It is a file row
    # destination, so it has already passed that row's own checks: confined and
    # normalised, no symlink anywhere on its parent chain, and not itself an
    # existing symlink.
    local i
    for i in "${!link_dests[@]}"; do
        [[ -z "${file_dests[${link_targets[$i]}]:-}" ]] || continue
        echo "MANIFEST line ${link_lines[$i]}: link target ${link_targets[$i]} is not installed as a file by this manifest: ${link_dests[$i]}" >&2
        bad=1
    done

    [[ $bad -eq 0 ]] || { echo "manifest validation failed" >&2; return 1; }
    echo "manifest validated: $n entries"
    return 0
}
# --- END manifest validation ---

hook_matches()
{
    [[ $STAGING -eq 0 ]] || return 0
    as_oneadmin onehook show vnfilter >/dev/null 2>&1
}

check_install()
{
    local failed=0 i target actual actual_mode
    for i in "${!M_DEST[@]}"; do
        target="$(target_path "${M_DEST[$i]}")"
        case "${M_KIND[$i]}" in
            file)
                if ! cmp -s "$REPO_ROOT/${M_SRC[$i]}" "$target"; then
                    echo "DIFF $target"
                    failed=1
                    continue
                fi
                # The manifest pins a mode, so --check has to verify one:
                # content alone would report a byte-identical but group- or
                # world-writable driver as matching, and the remotes tree is
                # exactly where that matters.
                actual_mode="$(stat -c '%a' "$target")"
                if [[ "$actual_mode" != "${M_VALUE[$i]#0}" ]]; then
                    echo "MODE $target is $actual_mode (expected ${M_VALUE[$i]#0})"
                    failed=1
                fi
                ;;
            link)
                actual=""
                [[ -L "$target" ]] && actual="$(readlink "$target")"
                if [[ "$actual" != "${M_VALUE[$i]}" ]]; then
                    echo "LINK $target -> ${actual:-missing} (expected ${M_VALUE[$i]})"
                    failed=1
                fi
                ;;
        esac
    done
    if [[ -z "$NO_HOOKS" ]] && ! hook_matches; then
        echo "HOOK vnfilter missing"
        failed=1
    fi
    [[ $failed -eq 0 ]]
}

validate_manifest || exit 1

if [[ "$ACTION" == "check" ]]; then
    check_install
    echo "Vnfilter installation matches source"
    exit 0
fi

if [[ $STAGING -eq 0 && $EUID -ne 0 ]]; then
    echo "Live installation must run as root" >&2
    exit 1
fi

# install(1), ln(1), mkdir(1) and chown(1) resolve their destination pathname
# themselves, so a parent swapped for a symlink after validation redirects the
# write; re-checking only narrows that window, and pathname chown(1) would hand
# ownership of whatever the name resolved to at that instant. safe-install.py
# resolves once against O_NOFOLLOW directory descriptors beneath the trusted
# root, and sets mode and owner on the descriptor rather than on a pathname.
SAFE_INSTALL="$REPO_ROOT/safe-install.py"
[[ -x "$SAFE_INSTALL" && ! -L "$SAFE_INSTALL" ]] ||
    { echo "missing or non-regular $SAFE_INSTALL" >&2; exit 1; }

for i in "${!M_DEST[@]}"; do
    target="$(target_path "${M_DEST[$i]}")"

    # A staged tree belongs to whoever ran the staging, exactly as before.
    owner=()
    if [[ $STAGING -eq 0 ]]; then
        owner=("$ONE_USER:$ONE_GROUP")
    fi

    case "${M_KIND[$i]}" in
        file)
            "$SAFE_INSTALL" "$REPO_ROOT/${M_SRC[$i]}" "$target" \
                "${M_VALUE[$i]}" "$REMOTES" "${owner[@]}"
            ;;
        link)
            "$SAFE_INSTALL" --link "${M_VALUE[$i]}" "$target" \
                "$REMOTES" "${owner[@]}"
            ;;
    esac
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
