#!/usr/bin/python3
"""Install one file or symlink beneath a trusted root without ever following a
symlink.

install(1), ln(1), mkdir(1) and chown(1) all resolve their destination pathname
themselves, so a root-run installer that merely checks the parent chain first is
racing: the remotes tree is oneadmin-owned, and a parent can be swapped for a
symlink between the check and the write. Re-checking narrows the window but
cannot close it. Pathname chown(1) is the worst of them -- it hands ownership of
whatever the name resolves to at that instant.

Every path component -- including those of the trusted root itself -- is opened
with O_NOFOLLOW|O_DIRECTORY from "/" downwards, so resolution happens once
against descriptors that cannot be substituted. Passing the root to open() as a
single pathname would only apply O_NOFOLLOW to its final component and would
still follow a symlink planted in an ancestor.

Replacement is atomic: the new file or symlink is created under an unpredictable
name inside a mode-0700 staging directory this process owns, given its final
mode and owner, then renamed over the target through the held directory
descriptor. A reader never sees the target missing or partially written, and the
rename source is never a name the tree's unprivileged owner could substitute.

This is the addon copy of the helper the primary site installer uses. It adds
--link, because addon manifests install symlinks as well as files. Byte-identical
copies live in addon-storpool-mc, addon-smtp_filter and addon-vnfilter -- keep
them that way, so `sha256sum` across the three is an audit. Change them together
or not at all.

The primary site installer's copy in opennebula-one is deliberately NOT in that
set: it installs no symlinks, so it has no --link and none of the staging this
file needs to create one safely. Expect it to differ; compare these three only.

Usage: safe-install.py SRC DEST MODE ROOT [OWNER:GROUP]
       safe-install.py --link TARGET DEST ROOT [OWNER:GROUP]
"""
import os
import secrets
import stat
import sys

DIR_MODE = 0o755


def fail(msg):
    print(f"safe-install: {msg}", file=sys.stderr)
    sys.exit(1)


def mkdir_unmasked(name, mode, dirfd):
    """mkdirat() with the caller's umask suspended.

    mkdir() is masked, which would leave a directory root can traverse but
    oneadmin and oned cannot -- and under an extreme umask such as 0777 the
    directory would be created mode 000, so the open() that follows fails before
    anything can repair it.
    """
    old = os.umask(0)
    try:
        os.mkdir(name, mode, dir_fd=dirfd)
    finally:
        os.umask(old)


def descend(dirfd, comps, base_is_owned):
    """Open each component with O_NOFOLLOW, creating directories as needed."""
    owned = base_is_owned
    for comp in comps:
        try:
            nxt = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                          dir_fd=dirfd)
        except FileNotFoundError:
            mkdir_unmasked(comp, DIR_MODE, dirfd)
            nxt = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                          dir_fd=dirfd)
            os.fchmod(nxt, DIR_MODE)
        except OSError as exc:
            if owned:
                os.close(dirfd)
            fail(f"refusing to descend into {comp!r}: {exc}")
        if owned:
            os.close(dirfd)
        dirfd, owned = nxt, True
    return dirfd


def resolve_owner(owner):
    if owner is None:
        return -1, -1
    import grp
    import pwd
    try:
        u, g = owner.split(":", 1)
        return pwd.getpwnam(u).pw_uid, grp.getgrnam(g).gr_gid
    except (ValueError, KeyError) as exc:
        fail(f"invalid owner {owner}: {exc}")


def open_dest_dir(dest, root):
    """Return (dirfd, leaf) for dest, resolved beneath root with O_NOFOLLOW."""
    root = os.path.normpath(root)
    dest = os.path.normpath(dest)
    if not os.path.isabs(root):
        fail(f"root must be absolute: {root}")
    if not dest.startswith(root.rstrip("/") + "/"):
        fail(f"destination {dest} is not beneath {root}")

    parts = os.path.relpath(dest, root).split(os.sep)
    if any(p in ("", ".", "..") for p in parts):
        fail(f"destination {dest} does not normalise cleanly")

    # "/" cannot itself be a symlink, so it is the only safe starting point.
    dirfd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    dirfd = descend(dirfd, [c for c in root.split(os.sep) if c], False)
    dirfd = descend(dirfd, parts[:-1], True)
    return dirfd, parts[-1]


def open_staging_dir(dirfd):
    """Create a mode-0700 staging directory inside dirfd; return (name, fd).

    Everything is staged here rather than directly in the destination
    directory, because the destination directory is one the unprivileged owner
    of the tree can write. A rename source staged there is a name they can
    replace between creation and rename -- so root would rename THEIR inode
    over the target. A name inside this directory cannot be substituted at all.

    mkdirat() and openat() are two operations on a name in that writable
    directory, so between them the new directory can be renamed away and one of
    theirs put in its place. O_NOFOLLOW accepts a real directory, and running as
    root fchmod() would set 0700 on someone else's just as readily. Authenticate
    what the descriptor actually refers to rather than trusting the name.
    """
    name = f".safe-install.{os.getpid()}.{secrets.token_hex(8)}"
    mkdir_unmasked(name, 0o700, dirfd)
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                     dir_fd=dirfd)
        os.fchmod(fd, 0o700)
        st = os.fstat(fd)
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid()
                or st.st_mode & 0o077):
            fail(f"staging directory {name} was substituted")
    except BaseException:
        if fd is not None:
            os.close(fd)
        try:
            os.rmdir(name, dir_fd=dirfd)
        except OSError:
            pass
        raise
    return name, fd


def close_staging_dir(name, fd, dirfd, leftover):
    if fd is not None:
        try:
            os.unlink(leftover, dir_fd=fd)
        except OSError:
            pass
        os.close(fd)
    # rmdir even when the open failed, or the staging directory would be left
    # behind in the deployed tree.
    if name is not None:
        try:
            os.rmdir(name, dir_fd=dirfd)
        except OSError:
            pass


def install_file(src, dest, mode, root, owner):
    uid, gid = resolve_owner(owner)

    with open(src, "rb") as fh:
        data = fh.read()

    dirfd, leaf = open_dest_dir(dest, root)
    name = None
    tdfd = None
    try:
        name, tdfd = open_staging_dir(dirfd)
        fd = os.open("file", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     mode, dir_fd=tdfd)
        try:
            view = memoryview(data)
            while view:
                # A single os.write may be short; a partial write would deploy
                # a truncated executable.
                view = view[os.write(fd, view):]
            os.fchmod(fd, mode)
            if uid != -1:
                os.fchown(fd, uid, gid)
        finally:
            os.close(fd)
        os.replace("file", leaf, src_dir_fd=tdfd, dst_dir_fd=dirfd)
    finally:
        close_staging_dir(name, tdfd, dirfd, "file")
        os.close(dirfd)


def install_link(target, dest, root, owner):
    uid, gid = resolve_owner(owner)

    dirfd, leaf = open_dest_dir(dest, root)
    name = None
    tdfd = None
    try:
        # A symlink cannot be opened, so unlike the file case every operation on
        # it is by name -- which is what would let the staged name be replaced
        # with a hardlink between symlink() and chown(), handing root's chown a
        # different inode. The staging directory closes that.
        name, tdfd = open_staging_dir(dirfd)

        # symlinkat() cannot replace an existing name, and unlinking the target
        # first would leave the driver path missing while hosts are syncing.
        # Rename over it instead; rename(2) is atomic within a filesystem, and
        # the staging directory is inside the destination directory.
        os.symlink(target, "link", dir_fd=tdfd)
        if uid != -1:
            # The symlink's own ownership, not that of what it points at.
            os.chown("link", uid, gid, dir_fd=tdfd, follow_symlinks=False)
        os.replace("link", leaf, src_dir_fd=tdfd, dst_dir_fd=dirfd)
    finally:
        close_staging_dir(name, tdfd, dirfd, "link")
        os.close(dirfd)


def main():
    argv = sys.argv[1:]

    if argv and argv[0] == "--link":
        argv = argv[1:]
        if len(argv) not in (3, 4):
            fail("usage: safe-install.py --link TARGET DEST ROOT [OWNER:GROUP]")
        target, dest, root = argv[:3]
        install_link(target, dest, root, argv[3] if len(argv) == 4 else None)
        return

    if len(argv) not in (4, 5):
        fail("usage: safe-install.py SRC DEST MODE ROOT [OWNER:GROUP]")
    src, dest, mode_s, root = argv[:4]
    try:
        mode = int(mode_s, 8)
    except ValueError:
        fail(f"invalid mode: {mode_s}")
    install_file(src, dest, mode, root, argv[4] if len(argv) == 5 else None)


if __name__ == "__main__":
    main()
