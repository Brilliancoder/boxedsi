"""Exclusive advisory locks for files that several processes or threads update."""

import errno
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .platform import lock_exclusive, open_nofollow, unlock

# Seconds a lock that another process holds is waited for. No lock of boxed is waited for without an end: a process of the sandbox can
# hold a lock file through a descriptor that cannot write (flock asks for no right to write) and never let it go, and it would stop
# every boxed command, and the prompt hook, that needs the lock.
LOCK_TIMEOUT = 30.0
NOT_PLAIN = "a lock file of boxed is not a plain file"  # fixed: an error text never names the path or what is there
_NOT_PLAIN_ERRNOS = frozenset({errno.ELOOP, errno.ENXIO, errno.EISDIR, errno.EOPNOTSUPP})  # a link, a pipe nobody reads, a folder, a socket


@contextmanager
def file_lock(path: Path, timeout: float | None = None) -> Iterator[None]:
    """Holds an exclusive lock on `<path>.lock` while the block runs.

    The lock file must be a plain file, or this raises OSError with the fixed words NOT_PLAIN: it is opened without following a link and
    without waiting (opening a pipe for writing blocks until something reads it, which hung the host), then checked on the open
    descriptor. A file left by a crash is fine: the lock lives in the kernel and goes with its process. A lock that another holds for
    longer than `timeout` seconds (None: LOCK_TIMEOUT) is a LockTimeout (an OSError) instead of a wait with no end."""
    wait = LOCK_TIMEOUT if timeout is None else timeout
    lock = path.with_name(path.name + ".lock")
    try:
        fd = open_nofollow(lock, os.O_WRONLY | os.O_CREAT, 0o600)
    except OSError as e:
        if e.errno in _NOT_PLAIN_ERRNOS:
            raise OSError(e.errno, NOT_PLAIN) from None
        raise
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, NOT_PLAIN)
        lock_exclusive(fd, wait)
        try:
            yield
        finally:
            unlock(fd)
    finally:
        os.close(fd)
