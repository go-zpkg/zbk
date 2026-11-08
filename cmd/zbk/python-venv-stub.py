#!/usr/bin/env python
#
# The launcher `zbk bkpyvenv seal` installs as $PREFIX/bin/<cmd>. Its first
# line is replaced with a pinned `zpkgx python@X.Y` shebang at install time.
#
# A virtualenv is not relocatable: pyvenv.cfg and every console script in
# venv/bin name the interpreter and the venv by ABSOLUTE path, and a bottle is
# installed wherever its store says. This launcher reconciles the two at run
# time and then execs the real entry point inside the venv.
#
# WRITTEN from the authoritative sources for what a venv contains:
#   - CPython Lib/venv/__init__.py:225-246, which writes pyvenv.cfg and is the
#     only statement of its key set: home, include-system-site-packages,
#     version, optionally prompt, executable, command.
#   - pip's console-script shebangs, which name the venv's interpreter as
#     `python`, `python3` or `python3.X`.
# CONSULTED, for facts rather than text: pkgx brewkit's stub of the same name,
# whose lock and idempotence check are the reason both appear here.
#
# ⛔⛔ THREE PROPERTIES THE COPY THIS REPLACES DID NOT HAVE, each a defect it
# shipped (go-zpkg/zbk#431):
#
#  1. IT DOES NOTHING WHEN THE VENV IS ALREADY CORRECT. The old one rewrote
#     pyvenv.cfg, every shebang and the python symlink on EVERY invocation of
#     every packaged tool. That made the repair window permanent instead of
#     once-per-relocation, and it meant a correct venv on a read-only
#     filesystem could not be run at all.
#
#  2. IT HOLDS AN EXCLUSIVE LOCK WHILE REPAIRING. Two concurrent invocations
#     could interleave inside the rewrite of one script, and between the
#     removal and the recreation of venv/bin/python there is a window in which
#     the interpreter does not exist. The symlink is still removed first and
#     recreated last, so an unlocked observer sees "not current" for the whole
#     repair and waits.
#
#     ⛔⛔ THE LOCK IS ON pyvenv.cfg, OPENED FOR WRITING, BECAUSE OF NFS. The
#     first version locked the bin DIRECTORY with O_RDONLY, reasoning that
#     nothing may be added to a packaged tree. That cannot work on a home
#     mounted over NFS, and not merely unreliably: flock(2) says "Since Linux
#     2.6.12, NFS clients support flock() locks by emulating them as fcntl(2)
#     byte-range locks on the entire file … in order to place an exclusive
#     lock, the file must be opened for writing" — and a directory cannot be
#     opened for writing at all (EISDIR, measured). So an exclusive flock on a
#     directory is impossible over NFS BY CONSTRUCTION. pyvenv.cfg is the right
#     token instead: it already exists, every repair rewrites it anyway, so
#     nothing is added to the tree and the fd can be O_RDWR.
#
#  3. IT REPLACES A SHEBANG ATOMICALLY. The old one wrote in place —
#     seek(0), write, truncate — so a script being read by an interpreter at
#     that moment could be read as garbage. os.replace() gives a running
#     process the old inode, which is exactly the guarantee needed here.
#
# And two smaller corrections. The old one rewrote pyvenv.cfg from three keys,
# silently DROPPING version, prompt and command every time; this one updates
# the keys it owns and preserves the rest. And it matched only shebangs ending
# exactly in "python", leaving a stale absolute path in any script pip wrote
# with `python3` or `python3.12`.

import fcntl
import glob
import os
import re
import sys
import tempfile

script_dir = os.path.dirname(os.path.realpath(__file__))
virtual_env = os.path.normpath(os.path.join(script_dir, '..', 'venv'))
bin_dir = os.path.join(virtual_env, 'bin')
cfg_path = os.path.join(virtual_env, 'pyvenv.cfg')
python_symlink = os.path.join(bin_dir, 'python')

arg0 = os.path.basename(sys.argv[0])
python_path = sys.executable
python_home = os.path.dirname(python_path)

# The keys this launcher owns. Everything else pyvenv.cfg holds is preserved.
OWNED = {
    'home': python_home,
    'executable': python_path,
    'include-system-site-packages': 'false',
}
OWNED_ORDER = ('home', 'include-system-site-packages', 'executable')

wanted_shebang = b'#!' + python_symlink.encode('utf-8') + b'\n'

# A shebang naming the venv's interpreter, as pip writes it.
PYTHON_SHEBANG = re.compile(rb'python(3(\.\d+)?)?$')


def same_file(a, b):
    """Compare RESOLVED paths, so v3 and v3.12.1 spellings of one interpreter
    are not mistaken for a move and do not provoke a rewrite."""
    return os.path.realpath(a) == os.path.realpath(b)


def cfg_lines():
    try:
        with open(cfg_path, 'r', encoding='utf-8') as f:
            return f.read().splitlines()
    except OSError:
        return None


def cfg_pairs(lines):
    out = {}
    for line in lines:
        if ' = ' in line:
            key, value = line.split(' = ', 1)
            out[key] = value
    return out


def cfg_text(lines):
    """The file with the owned keys set and every other line kept, in place."""
    seen = set()
    out = []
    for line in lines or []:
        if ' = ' in line:
            key = line.split(' = ', 1)[0]
            if key in OWNED:
                out.append('%s = %s' % (key, OWNED[key]))
                seen.add(key)
                continue
        out.append(line)
    for key in OWNED_ORDER:
        if key not in seen:
            out.append('%s = %s' % (key, OWNED[key]))
    return '\n'.join(out) + '\n'


def first_line(path):
    with open(path, 'rb') as f:
        return f.readline()


def stale_shebang(path):
    if not os.path.isfile(path) or os.path.islink(path):
        return False
    line = first_line(path)
    if not line.startswith(b'#!') or line == wanted_shebang:
        return False
    return PYTHON_SHEBANG.search(line.rstrip()) is not None


def scripts():
    return glob.glob(os.path.join(bin_dir, '*'))


def venv_is_current():
    lines = cfg_lines()
    if lines is None:
        return False
    pairs = cfg_pairs(lines)
    if pairs.get('include-system-site-packages') != 'false':
        return False
    for key in ('home', 'executable'):
        if key not in pairs or not same_file(pairs[key], OWNED[key]):
            return False
    if not os.path.lexists(python_symlink) or not same_file(python_symlink, python_path):
        return False
    return not any(stale_shebang(path) for path in scripts())


def replace_shebang(path):
    with open(path, 'rb') as f:
        f.readline()
        rest = f.read()

    # ⛔⛔ THE TEMPORARY FILE IS CREATED EXCLUSIVELY, AND THE FIRST VERSION OF
    # THIS WAS A SYMLINK ATTACK. It used `open(path + '.zpkg-new', 'wb')`,
    # which is O_WRONLY|O_CREAT|O_TRUNC: it FOLLOWS a symlink and reuses an
    # existing file, at a name anyone could predict. So a party able to create
    # a file in this directory before the launcher ran — a group-writable site
    # store, or a home shared over NFS — could point that name anywhere the
    # invoking user can write and have this function clobber it with the
    # script's body. mkstemp opens with O_CREAT|O_EXCL and a random suffix,
    # which refuses an existing path, cannot follow a link, and also survives
    # a stale temporary left by a crashed run.
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path),
                               prefix=os.path.basename(path) + '.zpkg-')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(wanted_shebang)
            f.write(rest)
        # ⛔ AND setuid/setgid ARE NOT CARRIED ACROSS A CONTENT REWRITE. The
        # first version preserved st_mode & 0o7777, so a script that was setuid
        # would be recreated setuid with a DIFFERENT interpreter line. Linux
        # ignores setuid on scripts; not every kernel this ships to has always
        # done so, and in no case is it ours to re-grant. 0o777 keeps the
        # permission bits that make it executable and drops the rest.
        os.chmod(tmp, os.stat(path).st_mode & 0o777)
        os.replace(tmp, path)
    except BaseException:
        # Nothing may be left behind in a packaged tree, including on the way
        # out of a failure.
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def repair():
    # The symlink goes FIRST and comes back LAST: until it is back, every
    # unlocked caller sees "not current" and waits on the lock rather than
    # running against a half-repaired venv.
    if os.path.lexists(python_symlink):
        os.remove(python_symlink)
    # ⛔ READ BEFORE OPENING FOR WRITE. `open(path, 'w')` truncates, so
    # `f.write(cfg_text(cfg_lines()))` reads a file it has already emptied and
    # preserves nothing — which is exactly the behaviour this launcher exists
    # to stop. The test that asserts `version` and `prompt` survive caught it.
    text = cfg_text(cfg_lines())
    with open(cfg_path, 'w', encoding='utf-8') as f:
        f.write(text)
    for path in scripts():
        if stale_shebang(path):
            replace_shebang(path)
    os.symlink(python_path, python_symlink)


if not venv_is_current():
    # O_CREAT because a venv whose pyvenv.cfg is missing is one this launcher
    # is about to write anyway, and O_RDWR because of the NFS rule above.
    # O_NOFOLLOW for the same reason the temporary file is exclusive: a
    # pyvenv.cfg that is a symlink is not a venv we should be writing through.
    try:
        fd = os.open(cfg_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o644)
    except OSError as err:
        sys.exit('%s: cannot lock %s: %s' % (arg0, cfg_path, err))
    try:
        # ⛔ flock ITSELF CAN FAIL, and the first version did not catch it. Over
        # NFS it is emulated with byte-range locks and can refuse; a traceback
        # at that point would be this launcher's own failure reported as the
        # program's.
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError as err:
            sys.exit('%s: cannot lock %s: %s' % (arg0, cfg_path, err))
        # Checked again under the lock: the holder we waited for has very
        # likely just done the repair, and doing it twice is the race.
        if not venv_is_current():
            try:
                repair()
            except OSError as err:
                sys.exit(
                    '%s: this virtualenv has to be rewritten for its location '
                    'and %s is not writable: %s' % (arg0, virtual_env, err)
                )
    finally:
        os.close(fd)

entry = os.path.join(bin_dir, arg0)
if not os.path.exists(entry):
    sys.exit('%s: %s has no entry point named %s' % (arg0, virtual_env, arg0))
os.execv(entry, [entry] + sys.argv[1:])
