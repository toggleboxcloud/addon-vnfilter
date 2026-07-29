#!/bin/bash
# Regression test: install.sh must reject a manifest that could make it write
# outside the remotes tree, write ambiguously, or write with a bogus mode.
#
# The installer runs as root and takes its destinations from a data file, so an
# unvalidated manifest is an arbitrary-write primitive. What it replaced was a
# lexical prefix strip plus a "did the string change" test, which accepts
# /var/lib/one/remotes/../../../etc/pwn.
#
# Unlike the StorPool manifest, this one's link targets are RELATIVE
# ("../../vnfilter_post"), so confinement is decided by joining the target to
# the directory of its own destination and folding the result lexically. Those
# cases are exercised explicitly below.
#
# Writes only into a temporary directory, never into the git worktree. Cases
# that need a source file get their own REPO_ROOT under $TMP. Safe on a live
# frontend.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALLER="$REPO_ROOT/install.sh"
REAL_MANIFEST="$REPO_ROOT/manifests/cloud-7.2.1.tsv"
failed=0

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Known-good entries, borrowed from the real manifest so the fixtures cannot
# drift away from what actually ships.
GOOD_FILE="$(grep -m1 -P '^file\t' "$REAL_MANIFEST")"
GOOD_LINK="$(grep -m1 -P '^link\t' "$REAL_MANIFEST")"
for v in GOOD_FILE GOOD_LINK; do
    [[ -n "${!v}" ]] || { echo "cannot read a sample $v line from $REAL_MANIFEST" >&2; exit 2; }
done
GOOD_SRC="$(cut -f2 <<<"$GOOD_FILE")"

# A clean, empty remotes root, so the on-disk checks (existing leaf symlink,
# symlinked parent) look at a controlled tree rather than the live one.
REMOTES_DEFAULT="$TMP/remotes"
mkdir -p "$REMOTES_DEFAULT"

VALIDATOR="$(sed -n '/^# --- BEGIN manifest validation/,/^# --- END manifest validation/p' "$INSTALLER")"
# A renamed or deleted marker would silently reduce every case below to "the
# empty block rejects everything", which reads as a pass.
grep -q 'validate_manifest()' <<<"$VALIDATOR" ||
    { echo "cannot extract the manifest validation block from $INSTALLER" >&2; exit 2; }
grep -q 'lexical_normalise()' <<<"$VALIDATOR" ||
    { echo "extracted block is missing lexical_normalise()" >&2; exit 2; }

# A link row is no longer valid on its own: its normalised target has to be the
# destination of a file row in the SAME manifest. Resolve GOOD_LINK's target
# with the validator's own lexical_normalise rather than a second copy of the
# folding rule, then find the shipped file row that installs it.
resolve_target()
{
    bash -c 'source /dev/stdin <<<"$3"; lexical_normalise "${1%/*}/$2"' \
        _ "$1" "$2" "$VALIDATOR"
}
GOOD_LINK_TGT="$(resolve_target "$(cut -f3 <<<"$GOOD_LINK")" "$(cut -f4 <<<"$GOOD_LINK")")"
GOOD_LINK_FILE="$(grep -m1 -P "^file\t[^\t]*\t\Q$GOOD_LINK_TGT\E\t" "$REAL_MANIFEST")"
[[ -n "$GOOD_LINK_TGT" && -n "$GOOD_LINK_FILE" ]] ||
    { echo "no file row in $REAL_MANIFEST installs $GOOD_LINK_TGT" >&2; exit 2; }

# Fixture builder: a link row plus the file row that installs its target, link
# row FIRST, so every accepted link case also exercises a link that precedes
# its own target. Arguments: link destination, link target, resolved target.
link_and_target()
{
    printf 'link\t-\t%s\t%s\nfile\t%s\t%s\t0644' "$1" "$2" "$GOOD_SRC" "$3"
}

# The validator depends on target_path(), REMOTES, REPO_ROOT and the M_* arrays
# from the installer. Supply them, otherwise every case aborts on an unbound
# variable and "rejected" would be reported even with the checks removed.
run_validator_in() {
    bash -c '
        set -uo pipefail
        REPO_ROOT="$1"; REMOTES="$2"; MANIFEST="$3"
        target_path() { printf "%s/%s\n" "$REMOTES" "${1#/var/lib/one/remotes/}"; }
        source /dev/stdin <<<"$4"
        validate_manifest
    ' _ "$1" "$2" "${3:-$TMP/manifest.tsv}" "$VALIDATOR" 2>&1
}

run_validator() { run_validator_in "$REPO_ROOT" "$REMOTES_DEFAULT"; }
run_validator_manifest() { run_validator_in "$REPO_ROOT" "$REMOTES_DEFAULT" "$1"; }

reject()
{
    local label="$1" line="$2" out rc
    printf '%s\n' "$line" > "$TMP/manifest.tsv"
    out="$(run_validator)"
    rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "ok   rejected: $label"
    else
        echo "FAIL accepted: $label"
        sed 's/^/       /' <<<"$out" | head -3
        failed=1
    fi
}

accept()
{
    local label="$1" line="$2" out rc
    printf '%s\n' "$line" > "$TMP/manifest.tsv"
    out="$(run_validator)"
    rc=$?
    if [[ $rc -eq 0 ]]; then echo "ok   accepted: $label"
    else echo "FAIL rejected a valid entry: $label"; sed 's/^/       /' <<<"$out" | head -3; failed=1; fi
}

P='/var/lib/one/remotes'

# Guard against the harness itself masking the result: the known-good entries
# must be accepted, which cannot happen if the validator aborts early.
accept "known-good file entry"        "$GOOD_FILE"
accept "known-good link entry with the file row it points at" \
    "$(printf '%s\n%s' "$GOOD_LINK" "$GOOD_LINK_FILE")"
accept "whole shipped manifest"       "$(cat "$REAL_MANIFEST")"

# --- confinement --------------------------------------------------------------
reject "destination traversal"        "$(printf 'file\t%s\t%s/../../../etc/pwn\t0644' "$GOOD_SRC" "$P")"
reject "sudoers drop-in"              "$(printf 'file\t%s\t/etc/sudoers.d/pwn\t0440' "$GOOD_SRC")"
reject "cron drop-in"                 "$(printf 'file\t%s\t/etc/cron.d/pwn\t0644' "$GOOD_SRC")"
reject "outside the remotes tree"     "$(printf 'file\t%s\t/root/.ssh/authorized_keys\t0600' "$GOOD_SRC")"
reject "a sibling of remotes"         "$(printf 'file\t%s\t/var/lib/one/remotes-evil/x\t0644' "$GOOD_SRC")"
reject "the remotes root itself"      "$(printf 'file\t%s\t%s\t0644' "$GOOD_SRC" "$P")"
reject "the remotes root with slash"  "$(printf 'file\t%s\t%s/\t0644' "$GOOD_SRC" "$P")"

# --- path shape ---------------------------------------------------------------
reject "absolute source"              "$(printf 'file\t/etc/passwd\t%s/x\t0644' "$P")"
reject "source traversal"             "$(printf 'file\t../../etc/passwd\t%s/x\t0644' "$P")"
# An empty field has to stay in its own column. read(1) treats tab as IFS
# whitespace and folds a RUN of tabs into a single delimiter, so under
# IFS=$'\t' the row below parses as three fields, the destination lands in the
# source column, and the empty-source guard never runs. The validator splits on
# tab by hand instead -- no sentinel byte, which would make a field already
# containing it indistinguishable from a delimiter -- so the guard is what
# fires here. (The
# "is it a regular file" test that follows would also reject it, so what the
# guard buys is the accurate message rather than the rejection itself.)
reject "empty source on a file row"   "$(printf 'file\t\t%s/x\t0644' "$P")"
# The same empty column with every later field shifted one to the right: a
# folding reader sees a well-formed four-field row here and ACCEPTS it.
reject "empty source shifting later columns" \
    "$(printf 'file\t\t%s\t%s/vnm/x\t0644' "$GOOD_SRC" "$P")"
reject "double slash in source"       "$(printf 'file\tremotes//vnm/vnfilter.rb\t%s/x\t0644' "$P")"
reject "destination not absolute"     "$(printf 'file\t%s\tremotes/x\t0644' "$GOOD_SRC")"
reject "double slash in destination"  "$(printf 'file\t%s\t%s//x\t0644' "$GOOD_SRC" "$P")"
reject "trailing slash"               "$(printf 'file\t%s\t%s/x/\t0644' "$GOOD_SRC" "$P")"
reject "dot component"                "$(printf 'file\t%s\t%s/./x\t0644' "$GOOD_SRC" "$P")"
reject "trailing dot"                 "$(printf 'file\t%s\t%s/x/.\t0644' "$GOOD_SRC" "$P")"
reject "missing source file"          "$(printf 'file\tnope/does/not/exist\t%s/x\t0644' "$P")"

# --- schema -------------------------------------------------------------------
reject "invalid mode (letters)"       "$(printf 'file\t%s\t%s/x\t0o644' "$GOOD_SRC" "$P")"
reject "invalid mode (digit 8)"       "$(printf 'file\t%s\t%s/x\t0688' "$GOOD_SRC" "$P")"
reject "invalid mode (empty)"         "$(printf 'file\t%s\t%s/x\t' "$GOOD_SRC" "$P")"
reject "missing mode (no field)"      "$(printf 'file\t%s\t%s/x' "$GOOD_SRC" "$P")"
reject "unknown kind"                 "$(printf 'symlink\t%s\t%s/x\t0644' "$GOOD_SRC" "$P")"
reject "too many fields"              "$(printf 'file\t%s\t%s/x\t0644\textra' "$GOOD_SRC" "$P")"
reject "duplicate destination"        "$(printf 'file\t%s\t%s/x\t0644\nfile\t%s\t%s/x\t0644' "$GOOD_SRC" "$P" "$GOOD_SRC" "$P")"
reject "duplicate across kinds"       "$(printf 'file\t%s\t%s/x\t0644\nlink\t-\t%s/x\ty' "$GOOD_SRC" "$P" "$P")"

# --- whole-file shape ---------------------------------------------------------
# reject() writes through printf '%s\n', so reject "" is a one-byte blank line,
# not an empty file -- the n==0 guard catches it and [[ -s ]] goes untested.
# Build the zero-byte and blank-line cases separately.
: > "$TMP/manifest.tsv"
if run_validator >/dev/null; then
    echo "FAIL accepted: zero-byte manifest"; failed=1
else
    echo "ok   rejected: zero-byte manifest"
fi

reject "manifest of one blank line"   ""
reject "manifest of comments only"    "$(printf '# kind\tsource\tdestination\tmode')"

# read returns failure on a final record with no terminating newline, so the
# loop body never sees it: a file truncated mid-row would otherwise validate and
# install as though that row had never existed.
printf 'file\t%s\t%s/x\t0644\nfile\t%s\t%s/y\t0644' \
    "$GOOD_SRC" "$P" "$GOOD_SRC" "$P" > "$TMP/manifest.tsv"
if run_validator >/dev/null; then
    echo "FAIL accepted: manifest with no trailing newline"; failed=1
else
    echo "ok   rejected: manifest with no trailing newline"
fi

# A symlinked manifest can be reaimed at another file between deployments while
# the path in the installer still looks right.
printf 'file\t%s\t%s/x\t0644\n' "$GOOD_SRC" "$P" > "$TMP/real-manifest.tsv"
ln -sfn "$TMP/real-manifest.tsv" "$TMP/manifest-link.tsv"
if run_validator_manifest "$TMP/manifest-link.tsv" >/dev/null; then
    echo "FAIL accepted: manifest that is a symlink"; failed=1
else
    echo "ok   rejected: manifest that is a symlink"
fi
# Control: the same bytes as a regular file are accepted, so the rejection above
# is attributable to the symlink and not to the fixture.
if run_validator_manifest "$TMP/real-manifest.tsv" >/dev/null; then
    echo "ok   accepted: the same bytes as a regular file"
else
    echo "FAIL rejected: the same bytes as a regular file"; failed=1
fi

if run_validator_manifest "$TMP/no-such-manifest.tsv" >/dev/null; then
    echo "FAIL accepted: missing manifest"; failed=1
else
    echo "ok   rejected: missing manifest"
fi
rm -f "$TMP/manifest.tsv"

# --- link rows: the RELATIVE-target rules -------------------------------------
# The four shipped link rows are "../../vnfilter_post" style, so an absolute
# target is not merely unnecessary here, it is the wrong shape entirely.
accept "relative target ../../x" \
    "$(link_and_target "$P/vnm/802.1Q/post.d/vnfilter_post" ../../vnfilter_post "$P/vnm/vnfilter_post")"
accept "relative target in same dir"  "$(link_and_target "$P/vnm/a" b "$P/vnm/b")"
accept "relative target via ./"       "$(link_and_target "$P/vnm/a" ./b "$P/vnm/b")"
accept "relative target down and up"  "$(link_and_target "$P/vnm/a" ../vnm/b "$P/vnm/b")"
accept "relative target interior .."  "$(link_and_target "$P/vnm/a" 802.1Q/../b "$P/vnm/b")"

reject "link source not '-'"          "$(printf 'link\t%s\t%s/x\ty' "$GOOD_SRC" "$P")"
reject "absolute link target"         "$(printf 'link\t-\t%s/x\t%s/y' "$P" "$P")"
reject "absolute link target to /etc" "$(printf 'link\t-\t%s/x\t/etc/shadow' "$P")"
reject "empty link target"            "$(printf 'link\t-\t%s/x\t' "$P")"
reject "empty link target (no field)" "$(printf 'link\t-\t%s/x' "$P")"
reject "double slash in link target"  "$(printf 'link\t-\t%s/vnm/a\t..//b' "$P")"
# lexical_normalise() must fail closed rather than clamp, and a directory-shaped
# target is refused rather than silently accepted -- the same contract the smtp
# sibling pins, so the two validators cannot drift apart.
reject "trailing slash in link target" "$(printf 'link\t-\t%s/vnm/a\tb/' "$P")"
reject "link target one step outside" "$(printf 'link\t-\t%s/x\t../pwn' "$P")"
reject "link target above the fs root" "$(printf 'link\t-\t%s/x\t../../../../../../../../../../pwn' "$P")"
# The case above would be rejected just the same by a normaliser that CLAMPED
# ".." at "/" rather than failing, because the clamped result is outside the
# tree either way. This one separates them: clamped, it folds back to a path
# under the remotes tree that this manifest does install, so only a normaliser
# that refuses to climb past the root rejects it.
reject "climbs past the root and lands back inside remotes" \
    "$(printf 'link\t-\t%s/x\t../../../../../../var/lib/one/remotes/pwn\nfile\t%s\t%s/pwn\t0644' "$P" "$GOOD_SRC" "$P")"
# The prefix ends in "/", so a resolved target landing in a sibling directory
# that shares its first characters must not slip through a "starts with" test.
reject "link target into a sibling"   "$(printf 'link\t-\t%s/x\t../remotes-evil/y' "$P")"

# One ".." too many. The escaping case is the whole point of joining the target
# to the directory of its own destination rather than to the remotes root: from
# vnm/802.1Q/post.d, three ".." lands back on remotes and is still confined, and
# only the fourth leaves the tree. A rule counting ".." would get both wrong.
reject "link target escapes by one"   "$(printf 'link\t-\t%s/vnm/802.1Q/post.d/x\t../../../../etc/passwd' "$P")"
accept "link target at exactly depth" \
    "$(link_and_target "$P/vnm/802.1Q/post.d/x" ../../../etc "$P/etc")"
reject "link target escapes far"      "$(printf 'link\t-\t%s/x\t../../../../../etc/shadow' "$P")"
reject "link target lands on remotes" "$(printf 'link\t-\t%s/vnm/a\t..' "$P")"
reject "link target lands above tree" "$(printf 'link\t-\t%s/vnm/a\t../..' "$P")"
# Folds back inside: a "../.." that is preceded by enough real components must
# still be judged on the result, not on the presence of "..".
accept "link target dips and returns" \
    "$(link_and_target "$P/vnm/802.1Q/post.d/x" ../../../vnm/y "$P/vnm/y")"

# --- link rows: the target must be a file THIS manifest installs --------------
# Normalising under the remotes tree is not confinement. The checks above are
# lexical, and lexical is all they can be before anything has been written; but
# if a component of the target is ALREADY a symlink on the host -- and the
# remotes tree is oneadmin-writable -- the installed link resolves elsewhere
# entirely. Requiring the normalised target to be the destination of a file row
# in the same manifest closes that: every component of it is then a path this
# manifest has itself checked and installs.
reject "link target not installed by this manifest" \
    "$(printf 'link\t-\t%s/vnm/a\tb' "$P")"
reject "known-good link row on its own" "$GOOD_LINK"
accept "link target installed by a file row" \
    "$(link_and_target "$P/vnm/a" b "$P/vnm/b")"
# ... in either order: the pass runs once every row has been parsed.
accept "file row before the link row that points at it" \
    "$(printf 'file\t%s\t%s/vnm/b\t0644\nlink\t-\t%s/vnm/a\tb' "$GOOD_SRC" "$P" "$P")"

# The escape this rule exists for. Nothing here establishes what "redirect" is,
# because this manifest does not install it; on a host where it is already a
# symlink to /etc, the row below installs a link resolving to /etc/payload
# while normalising to a path inside the remotes tree.
reject "link target through an uninstalled directory" \
    "$(printf 'link\t-\t%s/vnm/802.1Q/post.d/x\tredirect/payload' "$P")"
reject "link target through an uninstalled directory, other file rows present" \
    "$(printf 'file\t%s\t%s/vnm/other\t0644\nlink\t-\t%s/vnm/a\tredirect/payload' "$GOOD_SRC" "$P" "$P")"

# Exactly equal, not "starts with" and not "some other row lands nearby": a
# link may not point at another link's destination, and a file row that merely
# shares a prefix with the target is not that target.
reject "link target is another link row's destination" \
    "$(printf 'file\t%s\t%s/vnm/a\t0644\nlink\t-\t%s/vnm/b\ta\nlink\t-\t%s/vnm/c\tb' "$GOOD_SRC" "$P" "$P" "$P")"
reject "link target is a prefix of a file row destination" \
    "$(printf 'file\t%s\t%s/vnm/bb\t0644\nlink\t-\t%s/vnm/a\tb' "$GOOD_SRC" "$P" "$P")"

# A link row creates its symlink during the install loop, so it does not exist
# on disk while the parent chain is being checked. A later row writing beneath
# it would resolve through it. Both link rows below point at a file row of
# their own, so the only thing wrong with these manifests is the row beneath.
reject "write beneath a link row" \
    "$(printf 'link\t-\t%s/d\te\nfile\t%s\t%s/e\t0644\nfile\t%s\t%s/d/pwn\t0644' "$P" "$GOOD_SRC" "$P" "$GOOD_SRC" "$P")"
reject "link beneath a link row" \
    "$(printf 'link\t-\t%s/d\te\nfile\t%s\t%s/e\t0644\nlink\t-\t%s/d/s\t../e' "$P" "$GOOD_SRC" "$P" "$P")"

# --- pre-existing symlinked parent --------------------------------------------
# Lexically confined, but the parent redirects the write. Staged so the check
# has something real to look at.
STAGE="$TMP/stage"
mkdir -p "$STAGE/remotes/vnm" "$STAGE/outside"
ln -s "$STAGE/outside" "$STAGE/remotes/hooks"

run_validator_staged() { run_validator_in "$REPO_ROOT" "$STAGE/remotes"; }

# Control: the same row is accepted when its parent is a real directory, so the
# rejection below is attributable to the symlink and not to the staging setup.
printf 'file\t%s\t%s/vnm/pwn\t0644\n' "$GOOD_SRC" "$P" > "$TMP/manifest.tsv"
run_validator_staged >/dev/null \
    && echo "ok   accepted: staged destination with real parents" \
    || { echo "FAIL rejected: staged destination with real parents"; failed=1; }

printf 'file\t%s\t%s/hooks/pwn\t0644\n' "$GOOD_SRC" "$P" > "$TMP/manifest.tsv"
run_validator_staged >/dev/null \
    && { echo "FAIL accepted: destination under a symlinked parent"; failed=1; } \
    || echo "ok   rejected: destination under a symlinked parent"

# The link's target is installed by the file row beside it, so the only thing
# wrong with this pair is the symlinked parent on the link's own destination.
printf 'link\t-\t%s/hooks/pwn\t../vnm/y\nfile\t%s\t%s/vnm/y\t0644\n' \
    "$P" "$GOOD_SRC" "$P" > "$TMP/manifest.tsv"
run_validator_staged >/dev/null \
    && { echo "FAIL accepted: link under a symlinked parent"; failed=1; } \
    || echo "ok   rejected: link under a symlinked parent"

# A file row must refuse an existing leaf symlink, while a link row must still
# accept one -- otherwise the shipped manifest, whose four link rows install a
# symlink AT their destination, stops validating the moment it is installed.
# The decoy points inside the staging tree; never at a real system file.
echo decoy > "$STAGE/outside/decoy"
ln -s "$STAGE/outside/decoy" "$STAGE/remotes/leaf"
printf 'file\t%s\t%s/leaf\t0644\n' "$GOOD_SRC" "$P" > "$TMP/manifest.tsv"
run_validator_staged >/dev/null \
    && { echo "FAIL accepted: file row onto an existing symlink"; failed=1; } \
    || echo "ok   rejected: file row onto an existing symlink"

printf 'link\t-\t%s/leaf\tvnm/x\nfile\t%s\t%s/vnm/x\t0644\n' \
    "$P" "$GOOD_SRC" "$P" > "$TMP/manifest.tsv"
run_validator_staged >/dev/null \
    && echo "ok   accepted: link row replacing an existing symlink" \
    || { echo "FAIL rejected: link row replacing an existing symlink"; failed=1; }

# The already-installed tree: every shipped link row's destination IS a symlink
# on any host this has been deployed to. Reproduce that and re-validate the real
# manifest, which is the regression the StorPool port hit with realpath -m.
INST="$TMP/installed"
while IFS=$'\t' read -r kind src dest val; do
    [[ -n "$kind" && "${kind:0:1}" != "#" ]] || continue
    rel="${dest#/var/lib/one/remotes/}"
    mkdir -p "$INST/$(dirname "$rel")"
    case "$kind" in
        file) cp "$REPO_ROOT/$src" "$INST/$rel" ;;
        link) ln -sfn "$val" "$INST/$rel" ;;
    esac
done < "$REAL_MANIFEST"
cp "$REAL_MANIFEST" "$TMP/manifest.tsv"
run_validator_in "$REPO_ROOT" "$INST" >/dev/null \
    && echo "ok   accepted: shipped manifest against an already-installed tree" \
    || { echo "FAIL rejected: shipped manifest against an already-installed tree"; failed=1; }

# A source that is a symlink in the repository is not a manifest source.
FAKEREPO="$TMP/fakerepo-src"
mkdir -p "$FAKEREPO/remotes/vnm"
echo payload > "$FAKEREPO/remotes/vnm/real"
ln -s real "$FAKEREPO/remotes/vnm/linked"
printf 'file\tremotes/vnm/real\t%s/x\t0644\n' "$P" > "$TMP/manifest.tsv"
run_validator_in "$FAKEREPO" "$REMOTES_DEFAULT" >/dev/null \
    && echo "ok   accepted: regular source in a private repo root" \
    || { echo "FAIL rejected: regular source in a private repo root"; failed=1; }

printf 'file\tremotes/vnm/linked\t%s/x\t0644\n' "$P" > "$TMP/manifest.tsv"
run_validator_in "$FAKEREPO" "$REMOTES_DEFAULT" >/dev/null \
    && { echo "FAIL accepted: source that is a symlink"; failed=1; } \
    || echo "ok   rejected: source that is a symlink"

mkdir -p "$FAKEREPO/remotes/vnm/dir"
printf 'file\tremotes/vnm/dir\t%s/x\t0644\n' "$P" > "$TMP/manifest.tsv"
run_validator_in "$FAKEREPO" "$REMOTES_DEFAULT" >/dev/null \
    && { echo "FAIL accepted: source that is a directory"; failed=1; } \
    || echo "ok   rejected: source that is a directory"

# --- safe-install.py: the guard that actually performs the write --------------
# Validation runs earlier than the write, so these exercise the helper directly.
SI="$REPO_ROOT/safe-install.py"
ST="$TMP/si"; mkdir -p "$ST/root" "$ST/outside"; echo SRC > "$ST/src"

"$SI" "$ST/src" "$ST/root/a/b/f" 0644 "$ST/root" >/dev/null 2>&1 \
    && echo "ok   safe-install: normal write" \
    || { echo "FAIL safe-install: normal write"; failed=1; }

rm -rf "$ST/root/x"; ln -s "$ST/outside" "$ST/root/x"
"$SI" "$ST/src" "$ST/root/x/f" 0644 "$ST/root" >/dev/null 2>&1 \
    && { echo "FAIL safe-install: reported success through a symlinked parent"; failed=1; } \
    || { [[ ! -e "$ST/outside/f" ]] \
         && echo "ok   safe-install: symlinked parent refused, did not escape" \
         || { echo "FAIL safe-install: wrote through a symlinked parent"; failed=1; }; }

# The leaf is replaced rather than followed, so this must SUCCEED -- checking
# only that nothing appeared outside would also pass on a silent no-op.
ln -s "$ST/outside/leaf" "$ST/root/leafy"
"$SI" "$ST/src" "$ST/root/leafy" 0644 "$ST/root" >/dev/null 2>&1 \
    && { [[ ! -e "$ST/outside/leaf" && ! -L "$ST/root/leafy" \
            && "$(cat "$ST/root/leafy")" == SRC ]] \
         && echo "ok   safe-install: symlinked leaf replaced, not followed" \
         || { echo "FAIL safe-install: followed a symlinked leaf"; failed=1; }; } \
    || { echo "FAIL safe-install: could not replace a symlinked leaf"; failed=1; }

"$SI" "$ST/src" "$ST/outside/z" 0644 "$ST/root" >/dev/null 2>&1 \
    && { echo "FAIL safe-install: accepted a destination outside the root"; failed=1; } \
    || echo "ok   safe-install: destination outside root refused"

# A symlink planted in an ANCESTOR of the trusted root: passing the root to
# open() as one pathname would apply O_NOFOLLOW only to its last component.
mkdir -p "$ST/base"; ln -s "$ST/outside" "$ST/base/var"
"$SI" "$ST/src" "$ST/base/var/lib/f" 0644 "$ST/base/var/lib" >/dev/null 2>&1 \
    && { echo "FAIL safe-install: reported success through a symlinked root ancestor"; failed=1; } \
    || { [[ ! -e "$ST/outside/lib" ]] \
         && echo "ok   safe-install: symlinked root ancestor refused, did not escape" \
         || { echo "FAIL safe-install: followed a symlink in a root ancestor"; failed=1; }; }

# mkdir() is masked by umask; a 0700 parent is traversable by root but not by
# oneadmin or oned, so a root-run check would pass while the driver could not
# read its own files.
rm -rf "$ST/u"; mkdir -p "$ST/u"
( umask 077; "$SI" "$ST/src" "$ST/u/a/b/f" 0644 "$ST/u" >/dev/null 2>&1 )
[[ "$(stat -c %a "$ST/u/a" 2>/dev/null)" == "755" && "$(stat -c %a "$ST/u/a/b" 2>/dev/null)" == "755" ]] \
    && echo "ok   safe-install: created directories ignore umask" \
    || { echo "FAIL safe-install: umask leaked into created directories"; failed=1; }

# Replacement must be atomic and complete, leaving no temporary behind.
rm -rf "$ST/r"; mkdir -p "$ST/r"; head -c 1000000 /dev/urandom > "$ST/big"
"$SI" "$ST/big" "$ST/r/big" 0644 "$ST/r" >/dev/null 2>&1
[[ "$(stat -c %s "$ST/big")" == "$(stat -c %s "$ST/r/big")" \
   && "$(find "$ST/r" -name '.safe-install.*' | wc -l)" -eq 0 ]] \
    && echo "ok   safe-install: complete write, no temporary left" \
    || { echo "FAIL safe-install: short write or temporary left behind"; failed=1; }

# --- safe-install.py --link ---------------------------------------------------
# This addon's targets are relative, so that is what the helper is driven with.
rm -rf "$ST/l"; mkdir -p "$ST/l"
"$SI" --link ../../vnfilter_post "$ST/l/a/b/s" "$ST/l" >/dev/null 2>&1
[[ "$(readlink "$ST/l/a/b/s" 2>/dev/null)" == ../../vnfilter_post \
   && "$(find "$ST/l" -name '.safe-install.*' | wc -l)" -eq 0 ]] \
    && echo "ok   safe-install --link: relative target created, no temporary left" \
    || { echo "FAIL safe-install --link: not created, or temporary left behind"; failed=1; }

# ln without -n would descend into an existing symlink-to-directory and create
# the new name INSIDE the target rather than replacing it.
rm -rf "$ST/l2"; mkdir -p "$ST/l2/realdir"
ln -s "$ST/l2/realdir" "$ST/l2/s"
"$SI" --link ../tgt "$ST/l2/s" "$ST/l2" >/dev/null 2>&1 \
    && { [[ "$(readlink "$ST/l2/s" 2>/dev/null)" == ../tgt \
            && ! -e "$ST/l2/realdir/s" ]] \
         && echo "ok   safe-install --link: replaced a symlink to a directory" \
         || { echo "FAIL safe-install --link: descended into a symlinked directory"; failed=1; }; } \
    || { echo "FAIL safe-install --link: could not replace a symlink to a directory"; failed=1; }

rm -rf "$ST/l3"; mkdir -p "$ST/l3"; ln -s "$ST/outside" "$ST/l3/x"
"$SI" --link ../tgt "$ST/l3/x/s" "$ST/l3" >/dev/null 2>&1 \
    && { echo "FAIL safe-install --link: reported success through a symlinked parent"; failed=1; } \
    || { [[ ! -e "$ST/outside/s" ]] \
         && echo "ok   safe-install --link: symlinked parent refused, did not escape" \
         || { echo "FAIL safe-install --link: linked through a symlinked parent"; failed=1; }; }

"$SI" --link ../tgt "$ST/outside/z" "$ST/l3" >/dev/null 2>&1 \
    && { echo "FAIL safe-install --link: accepted a destination outside the root"; failed=1; } \
    || echo "ok   safe-install --link: destination outside root refused"

# The symlink is staged in a private directory rather than beside the target, so
# a failed rename must leave neither the staging directory nor a stray link in a
# tree the unprivileged user can see. A non-empty directory at the leaf makes
# rename(2) fail deterministically.
rm -rf "$ST/l4"; mkdir -p "$ST/l4/s/occupied"
"$SI" --link ../tgt "$ST/l4/s" "$ST/l4" >/dev/null 2>&1 \
    && { echo "FAIL safe-install --link: replaced a non-empty directory"; failed=1; } \
    || { [[ -d "$ST/l4/s/occupied" && "$(find "$ST/l4" -name '.safe-install.*' | wc -l)" -eq 0 ]] \
         && echo "ok   safe-install --link: failed rename left nothing behind" \
         || { echo "FAIL safe-install --link: staging residue after a failed rename"; failed=1; }; }

# An extreme umask makes mkdir() produce a mode-000 directory, which the open()
# that follows cannot enter -- so directory creation must suspend the umask
# rather than repair the mode afterwards. Only unprivileged runs feel this;
# root can enter a 000 directory regardless.
rm -rf "$ST/um"; mkdir -p "$ST/um"
( umask 0777; "$SI" "$ST/src" "$ST/um/a/b/f" 0644 "$ST/um" >/dev/null 2>&1 ) \
    && [[ "$(cat "$ST/um/a/b/f" 2>/dev/null)" == SRC ]] \
    && echo "ok   safe-install: file staging survives umask 0777" \
    || { echo "FAIL safe-install: umask 0777 broke directory creation"; failed=1; }

rm -rf "$ST/um2"; mkdir -p "$ST/um2"
( umask 0777; "$SI" --link ../tgt "$ST/um2/a/s" "$ST/um2" >/dev/null 2>&1 ) \
    && [[ "$(readlink "$ST/um2/a/s" 2>/dev/null)" == ../tgt ]] \
    && echo "ok   safe-install --link: link staging survives umask 0777" \
    || { echo "FAIL safe-install --link: umask 0777 broke link staging"; failed=1; }

# Fault injection for the staging-directory substitution guard. Only meaningful
# as root, where fchmod() would succeed on someone else's directory and so
# cannot be the check that catches it.
#
# exec_module() would byte-compile the helper and drop a __pycache__ beside it,
# i.e. inside the git worktree. Import a copy under $TMP, and with -B, so this
# test never writes into the checkout.
if [[ $EUID -eq 0 ]] && id -u oneadmin >/dev/null 2>&1; then
    rm -rf "$ST/fi"; mkdir -p "$ST/fi"
    cp "$SI" "$ST/safe-install.py"
    if python3 -B - "$ST/safe-install.py" "$ST/fi" 2>/dev/null <<'PY'
import importlib.util, os, pwd, sys

si_path, root = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("safe_install", si_path)
si = importlib.util.module_from_spec(spec)
spec.loader.exec_module(si)

victim = pwd.getpwnam("oneadmin").pw_uid
real_mkdir = si.mkdir_unmasked


def substituted(name, mode, dirfd):
    # Stand in for: oneadmin renames our directory away and puts one of its own
    # at the same name between mkdirat() and openat().
    real_mkdir(name, mode, dirfd)
    os.chown(name, victim, victim, dir_fd=dirfd)


si.mkdir_unmasked = substituted
try:
    si.install_link("../tgt", root + "/s", root, None)
except SystemExit as exc:
    sys.exit(0 if exc.code else 1)
sys.exit(1)
PY
    then
        [[ ! -e "$ST/fi/s" && -z "$(find "$ST/fi" -name '.safe-install.*')" ]] \
            && echo "ok   safe-install --link: substituted staging directory refused" \
            || { echo "FAIL safe-install --link: refused but left residue"; failed=1; }
    else
        echo "FAIL safe-install --link: accepted a substituted staging directory"; failed=1
    fi
else
    echo "skip safe-install --link: substitution fault injection (needs root)"
fi

# The same guard through install_file(). Both paths stage in the authenticated
# directory now, so a revert of only the file path has to fail here -- the
# --link case above would not notice it.
if [[ $EUID -eq 0 ]] && id -u oneadmin >/dev/null 2>&1; then
    rm -rf "$ST/fif"; mkdir -p "$ST/fif"
    cp "$SI" "$TMP/safe-install-fif.py"
    if python3 -B - "$TMP/safe-install-fif.py" "$ST/fif" "$ST/src" 2>/dev/null <<'PY'
import importlib.util, os, pwd, sys

si_path, root, src = sys.argv[1], sys.argv[2], sys.argv[3]
spec = importlib.util.spec_from_file_location("safe_install", si_path)
si = importlib.util.module_from_spec(spec)
spec.loader.exec_module(si)

victim = pwd.getpwnam("oneadmin").pw_uid
real_mkdir = si.mkdir_unmasked


def substituted(name, mode, dirfd):
    # Stand in for: oneadmin renames our directory away and puts one of its own
    # at the same name between mkdirat() and openat().
    real_mkdir(name, mode, dirfd)
    os.chown(name, victim, victim, dir_fd=dirfd)


si.mkdir_unmasked = substituted
try:
    si.install_file(src, root + "/f", 0o644, root, None)
except SystemExit as exc:
    sys.exit(0 if exc.code else 1)
sys.exit(1)
PY
    then
        [[ ! -e "$ST/fif/f" && -z "$(find "$ST/fif" -name '.safe-install.*')" ]] \
            && echo "ok   safe-install: substituted staging directory refused (file)" \
            || { echo "FAIL safe-install: refused but left residue (file)"; failed=1; }
    else
        echo "FAIL safe-install: accepted a substituted staging directory (file)"; failed=1
    fi
else
    echo "skip safe-install: substitution fault injection, file (needs root)"
fi

# --- end to end ---------------------------------------------------------------
# Everything above drives the extracted validator block, which would still pass
# if the installer stopped calling it, so run the real script too. The
# manifest-is-read-once property gets its own section further down. The copy
# lives under $TMP; nothing is written into the git worktree.
FAKE="$TMP/fakerepo"
mkdir -p "$FAKE/manifests" "$FAKE/remotes/vnm"
cp "$INSTALLER" "$FAKE/install.sh"
cp "$REPO_ROOT/safe-install.py" "$FAKE/safe-install.py"
chmod 0755 "$FAKE/install.sh" "$FAKE/safe-install.py"
echo PAYLOAD > "$FAKE/remotes/vnm/good"

e2e() {
    local dest="$1"; shift
    printf '%s\n' "$@" > "$FAKE/manifests/cloud-7.2.1.tsv"
    "$FAKE/install.sh" --dest-root "$dest" --no-hooks --no-sync >/dev/null 2>&1
}

# --check drives check_install() over the same validated rows. Leaves the tree
# untouched, so it can be run either side of a deliberate corruption.
e2e_check() {
    "$FAKE/install.sh" --check --dest-root "$1" --no-hooks --no-sync >/dev/null 2>&1
}

GOOD_ROW="$(printf 'file\tremotes/vnm/good\t%s/vnm/good\t0755' "$P")"
LINK_ROW="$(printf 'link\t-\t%s/vnm/802.1Q/post.d/good\t../../good' "$P")"

D1="$TMP/d1"
if e2e "$D1" "$GOOD_ROW" "$LINK_ROW" &&
   [[ "$(cat "$D1$P/vnm/good" 2>/dev/null)" == PAYLOAD ]] &&
   [[ "$(stat -c %a "$D1$P/vnm/good" 2>/dev/null)" == 755 ]] &&
   [[ "$(readlink "$D1$P/vnm/802.1Q/post.d/good" 2>/dev/null)" == ../../good ]] &&
   [[ "$(cat "$D1$P/vnm/802.1Q/post.d/good" 2>/dev/null)" == PAYLOAD ]]; then
    echo "ok   installer: installed a file and a working relative symlink"
else
    echo "FAIL installer: valid manifest did not install cleanly"; failed=1
fi

# --check drives check_install() over the validated rows, and it must actually
# compare: a staged install it just made has to pass.
if e2e_check "$D1"; then
    echo "ok   installer: --check passes on what it just installed"
else
    echo "FAIL installer: --check failed on its own installation"; failed=1
fi

# ... and a tree that does not match must fail, or --check is a rubber stamp.
D5="$TMP/d5"; mkdir -p "$D5"
if e2e_check "$D5"; then
    echo "FAIL installer: --check passed against an empty tree"; failed=1
else
    echo "ok   installer: --check fails against an empty tree"
fi

echo TAMPERED > "$D1$P/vnm/good"
if e2e_check "$D1"; then
    echo "FAIL installer: --check passed with drifted content"; failed=1
else
    echo "ok   installer: --check fails on drifted content"
fi

# Byte-identical, mode wrong. The manifest pins a mode, so --check has to
# compare one: otherwise a group- and world-writable driver in the remotes tree
# reports as matching its source.
echo PAYLOAD > "$D1$P/vnm/good"
chmod 0666 "$D1$P/vnm/good"
if e2e_check "$D1"; then
    echo "FAIL installer: --check passed with the right bytes at the wrong mode"; failed=1
else
    echo "ok   installer: --check fails on a wrong mode"
fi

ln -sfn ../../elsewhere "$D1$P/vnm/802.1Q/post.d/good"
if e2e_check "$D1"; then
    echo "FAIL installer: --check passed with a link pointing elsewhere"; failed=1
else
    echo "ok   installer: --check fails on a link pointing elsewhere"
fi

# Re-running must replace both in place rather than failing on what is there,
# and must repair the three corruptions above.
if e2e "$D1" "$GOOD_ROW" "$LINK_ROW" &&
   [[ "$(cat "$D1$P/vnm/good" 2>/dev/null)" == PAYLOAD ]] &&
   [[ "$(stat -c %a "$D1$P/vnm/good" 2>/dev/null)" == 755 ]] &&
   [[ "$(readlink "$D1$P/vnm/802.1Q/post.d/good" 2>/dev/null)" == ../../good ]] &&
   [[ -z "$(find "$D1" -name '.safe-install.*' 2>/dev/null)" ]]; then
    echo "ok   installer: idempotent, no temporary left behind"
else
    echo "FAIL installer: re-install failed or left a temporary"; failed=1
fi

if e2e_check "$D1"; then
    echo "ok   installer: --check passes again after the re-install"
else
    echo "FAIL installer: --check failed after the re-install"; failed=1
fi

# A hostile row must stop the run before ANY row is written -- validation is
# whole-manifest, so the valid row preceding it must not reach the disk either.
D2="$TMP/d2"
if e2e "$D2" "$GOOD_ROW" "$(printf 'file\tremotes/vnm/good\t%s/../../../etc/cron.d/pwn\t0644' "$P")"; then
    echo "FAIL installer: accepted a manifest escaping to /etc/cron.d"; failed=1
elif [[ -e "$D2/etc/cron.d/pwn" || -e "$D2$P/vnm/good" ]]; then
    echo "FAIL installer: refused but had already written"; failed=1
else
    echo "ok   installer: hostile row refused, nothing written"
fi

# The same for an escaping relative link target.
D4="$TMP/d4"
if e2e "$D4" "$GOOD_ROW" "$(printf 'link\t-\t%s/vnm/s\t../../../../../etc/shadow' "$P")"; then
    echo "FAIL installer: accepted an escaping relative link target"; failed=1
elif [[ -e "$D4$P/vnm/s" || -e "$D4$P/vnm/good" ]]; then
    echo "FAIL installer: refused but had already written"; failed=1
else
    echo "ok   installer: escaping link target refused, nothing written"
fi

# --- relative ONE_VAR / ONE_LOCATION -------------------------------------------
# $REMOTES is handed to safe-install.py as its trusted root, and that root has to
# be absolute -- it is descended from "/" one component at a time. A relative
# ONE_VAR or ONE_LOCATION used to be resolved against the working directory by
# install(1) and mkdir(1), and the installer cd's to its own directory first, so
# the effective base is the SCRIPT directory. Losing that turned every such run
# into "safe-install: root must be absolute" on the first write.
#
# These are live-mode runs (no --dest-root), so they need root for the EUID gate
# and for the chown to oneadmin. Both write only inside $FAKE, under $TMP.
if [[ $EUID -eq 0 ]] && id -u oneadmin >/dev/null 2>&1; then
    printf '%s\n' "$GOOD_ROW" "$LINK_ROW" > "$FAKE/manifests/cloud-7.2.1.tsv"

    # Launched from an unrelated working directory, so a base of "wherever the
    # caller happened to be" would land the tree somewhere else entirely.
    ELSEWHERE="$TMP/cwd"; mkdir -p "$ELSEWHERE"

    rm -rf "$FAKE/relvar"
    if ( cd "$ELSEWHERE" && ONE_VAR=relvar "$FAKE/install.sh" --no-hooks --no-sync ) >/dev/null 2>&1 &&
       [[ "$(cat "$FAKE/relvar/remotes/vnm/good" 2>/dev/null)" == PAYLOAD ]] &&
       [[ "$(readlink "$FAKE/relvar/remotes/vnm/802.1Q/post.d/good" 2>/dev/null)" == ../../good ]] &&
       [[ ! -e "$ELSEWHERE/relvar" ]]; then
        echo "ok   installer: relative ONE_VAR resolved against the script directory"
    else
        echo "FAIL installer: relative ONE_VAR did not install under the script directory"; failed=1
    fi

    rm -rf "$FAKE/relloc"
    if ( cd "$ELSEWHERE" && ONE_LOCATION=relloc "$FAKE/install.sh" --no-hooks --no-sync ) >/dev/null 2>&1 &&
       [[ "$(cat "$FAKE/relloc/var/remotes/vnm/good" 2>/dev/null)" == PAYLOAD ]] &&
       [[ "$(readlink "$FAKE/relloc/var/remotes/vnm/802.1Q/post.d/good" 2>/dev/null)" == ../../good ]] &&
       [[ ! -e "$ELSEWHERE/relloc" ]]; then
        echo "ok   installer: relative ONE_LOCATION resolved against the script directory"
    else
        echo "FAIL installer: relative ONE_LOCATION did not install under the script directory"; failed=1
    fi

    rm -rf "$FAKE/relvar" "$FAKE/relloc"
else
    echo "skip installer: relative ONE_VAR (needs root)"
    echo "skip installer: relative ONE_LOCATION (needs root)"
fi

# --- the manifest is read once, before anything is written ---------------------
# Nothing above would notice if the installer re-read the manifest after
# validating it: it would read back the same bytes. Swapping the file mid-run
# needs a hook between validation and use, and the installer offers exactly
# one -- it invokes safe-install.py for the first write. Stand in for that
# helper with a wrapper that rewrites the manifest and then delegates to the
# real one unchanged, so from the first write onward the rows on disk are NOT
# the rows that were validated. The install loop and the closing check_install
# both have to keep using the validated arrays: if either re-read, the run
# would install or look for "swapped" instead of "good" and fail.
SWAP="$TMP/swap"
mkdir -p "$SWAP/manifests" "$SWAP/remotes/vnm"
cp "$INSTALLER" "$SWAP/install.sh"
echo PAYLOAD > "$SWAP/remotes/vnm/good"
cat > "$SWAP/safe-install.py" <<EOF
#!/bin/bash
# Not safe-install.py: a stand-in that rewrites the manifest at the moment the
# installer starts writing, then hands over to the real helper untouched.
printf 'file\tremotes/vnm/good\t$P/vnm/swapped\t0755\n' \\
    > "$SWAP/manifests/cloud-7.2.1.tsv"
exec "$REPO_ROOT/safe-install.py" "\$@"
EOF
chmod 0755 "$SWAP/install.sh" "$SWAP/safe-install.py"
printf 'file\tremotes/vnm/good\t%s/vnm/good\t0755\n' "$P" > "$SWAP/manifests/cloud-7.2.1.tsv"

D6="$TMP/d6"
if "$SWAP/install.sh" --dest-root "$D6" --no-hooks --no-sync >/dev/null 2>&1 &&
   [[ "$(cat "$D6$P/vnm/good" 2>/dev/null)" == PAYLOAD ]] &&
   [[ ! -e "$D6$P/vnm/swapped" ]]; then
    echo "ok   installer: a manifest swapped mid-run is not re-read"
else
    echo "FAIL installer: used a manifest swapped after validation"; failed=1
fi

# The installer must not fall back to a silent no-op when the manifest is gone.
D3="$TMP/d3"
rm -f "$FAKE/manifests/cloud-7.2.1.tsv"
if "$FAKE/install.sh" --dest-root "$D3" --no-hooks --no-sync >/dev/null 2>&1; then
    echo "FAIL installer: reported success with no manifest"; failed=1
else
    echo "ok   installer: refused a missing manifest"
fi

echo
if [[ $failed -eq 0 ]]; then echo "vnfilter manifest confinement regression PASSED"; exit 0
else echo "vnfilter manifest confinement regression FAILED"; exit 1; fi
