"""Append-only journal of processing and sends: each record is hash-chained and signed with the device key."""

import errno
import hashlib
import json
import os
import re
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .keys import KeyStore
from .locks import file_lock
from .platform import open_nofollow

STATUSES = ("prepared", "sent", "received", "blocked", "error")
OPTIONAL = ("model", "usage")  # left out while empty, so records of other channels keep their shape
GENESIS = "0" * 64
MAX_SEQ = 2**53  # a record number from here on is not one boxed wrote: nine quadrillion records are a long way off
_DIGEST = re.compile(r"[0-9a-f]{64}")  # a SHA-256 in hex, as hexdigest() writes it
NOT_PLAIN = "the journal file is not a regular file"  # fixed: an error text never names the path or what is there
_NOT_PLAIN_ERRNOS = frozenset({errno.ELOOP, errno.ENXIO, errno.EISDIR, errno.EOPNOTSUPP})  # a link, a pipe nobody reads, a folder, a socket


class JournalError(OSError):
    """The journal path holds something that is not a plain file: a link, a pipe, a folder."""


@dataclass
class JournalEntry:
    channel: str
    provider: str
    account_type: str
    level: int
    markers_by_kind: dict[str, int]
    status: str
    payload_sha256: str
    coverage: str
    scope: str
    versions: dict[str, str] = field(default_factory=dict)
    note: str = ""
    model: str = ""  # the model that answered, when boxed sent the text itself
    usage: dict[str, int] = field(default_factory=dict)  # {"input": tokens, "output": tokens} as the provider reported them

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}, got {self.status!r}")


@dataclass
class VerifyReport:
    ok: bool
    count: int
    first_bad: int | None
    reason: str


def _parse(line: str | bytes) -> dict | None:
    """A journal record, or None for an empty or damaged line: not JSON, nested deeper than the parser reads, or with a seq
    or a hash that boxed could not have written. append builds the next record on both of the newest one, so a text, a
    number of thousands of digits or a lone surrogate there would stop every later append."""
    try:
        rec = json.loads(line)
    except (ValueError, TypeError, RecursionError):
        return None
    if not isinstance(rec, dict):
        return None
    seq, digest = rec.get("seq"), rec.get("hash")
    whole = type(seq) is int and 0 < seq < MAX_SEQ and type(digest) is str and _DIGEST.fullmatch(digest)
    return rec if whole else None


def _open_regular(path: Path, flags: int) -> int:
    """A descriptor for the journal file, known to be a regular file. It is opened as checks._read opens its file: without
    following a link and without waiting on a pipe (an open that waits keeps the lock around it, so every other writer waits
    too), then checked on the descriptor. Anything else is a JournalError; a missing file or a permission error passes as it is."""
    try:
        fd = open_nofollow(path, flags, 0o600)
    except OSError as e:
        if e.errno in _NOT_PLAIN_ERRNOS:
            raise JournalError(NOT_PLAIN) from None
        raise
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise JournalError(NOT_PLAIN)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _canonical(record: dict) -> bytes:
    body = {k: v for k, v in record.items() if k not in ("hash", "sig")}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class Journal:
    def __init__(self, path: Path, keys: KeyStore) -> None:
        self.path = path
        self._signer = Ed25519PrivateKey.from_private_bytes(keys.get_or_create("device-signing-key", 32))
        self._verifier = self._signer.public_key()
        self._reserved = threading.local()  # held is set in the thread that has the lock in reserved()

    def public_key_hex(self) -> str:
        """The device public key: whoever holds it can verify the records without our key store."""
        return self._verifier.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    def _lines(self) -> list[bytes]:
        """Raw lines split on \\n only, the way append writes them: bytes survive a write torn inside a character."""
        try:
            fd = _open_regular(self.path, os.O_RDONLY)
        except (FileNotFoundError, NotADirectoryError):
            return []
        with os.fdopen(fd, "rb") as f:
            return f.read().split(b"\n")

    def read(self) -> tuple[list[dict], int]:
        """Valid records and the number of damaged lines; verify() says which line and why."""
        lines = [line for line in self._lines() if line.strip()]
        records = [rec for rec in map(_parse, lines) if rec is not None]
        return records, len(lines) - len(records)

    def entries(self) -> list[dict]:
        return self.read()[0]

    def _tail(self) -> tuple[dict | None, bool]:
        """The newest valid record, read backwards in 4 KB blocks, and whether the file ends with a newline."""
        try:
            fd = _open_regular(self.path, os.O_RDONLY)
        except (FileNotFoundError, NotADirectoryError):
            return None, True
        with os.fdopen(fd, "rb") as f:
            pos = f.seek(0, os.SEEK_END)
            if pos == 0:
                return None, True
            f.seek(pos - 1)
            ends_clean = f.read(1) == b"\n"
            pending: list[bytes] = []  # later blocks of the line being assembled, newest first; joined once
            while pos > 0:
                step = min(4096, pos)
                pos -= step
                f.seek(pos)
                block = f.read(step)
                if b"\n" not in block and pos > 0:
                    pending.append(block)
                    continue
                parts = block.split(b"\n")
                parts[-1] += b"".join(reversed(pending))
                pending = [parts[0]] if pos > 0 else []
                complete = parts[1:] if pos > 0 else parts
                for line in reversed(complete):
                    if (rec := _parse(line)) is not None:
                        return rec, ends_clean
        return None, ends_clean

    @contextmanager
    def reserved(self) -> Iterator[None]:
        """Takes the lock of the journal and keeps it, after a check that a record can follow: the file is a plain file (or not there yet)
        that can be opened for appending, and its newest record can be read. append() in the block does not take the lock again. For a
        caller that changes things of the person between the check and the record (sync writes their files) and must not do it when
        the record cannot be made."""
        with file_lock(self.path):
            self._tail()
            os.close(_open_regular(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT))
            self._reserved.held = True
            try:
                yield
            finally:
                self._reserved.held = False

    def append(self, entry: JournalEntry) -> dict:
        # parallel writers must not reuse a seq or a prev_hash; the thread that has the lock in reserved() does not take it twice
        with nullcontext() if getattr(self._reserved, "held", False) else file_lock(self.path):
            last, ends_clean = self._tail()  # O(1): a long journal must not slow every send down
            record = {k: v for k, v in asdict(entry).items() if v or k not in OPTIONAL} | {
                "seq": (last["seq"] + 1) if last else 1,
                "ts": datetime.now(UTC).isoformat(),
                "prev_hash": last["hash"] if last else GENESIS,
            }
            record["hash"] = hashlib.sha256(_canonical(record)).hexdigest()
            record["sig"] = self._signer.sign(bytes.fromhex(record["hash"])).hex()
            # Opened by hand: a link, a pipe or a folder at the path is an error, never a way to write somewhere else or to wait,
            # and a new file is private from its first byte. The text is UTF-8 whatever the locale says: the chain is hashed over it.
            fd = _open_regular(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
            with os.fdopen(fd, "a", encoding="utf-8", newline="\n") as f:  # \n stays \n on Windows too: the chain is hashed over the line
                f.write(("" if ends_clean else "\n") + json.dumps(record, ensure_ascii=False) + "\n")  # after a torn write
        return record

    def verify(self) -> VerifyReport:
        """Damaged lines are reported, and the chain of whole records is still checked across them: a write torn
        by a crash keeps the chain whole, a deleted or edited record breaks it."""
        prev_hash, prev_seq, count, damaged = GENESIS, 0, 0, []
        for lineno, line in enumerate(self._lines(), start=1):
            if not line.strip():
                continue
            rec = _parse(line)
            if rec is None:
                damaged.append(lineno)
                continue
            seq = rec["seq"]
            try:
                digest = hashlib.sha256(_canonical(rec)).hexdigest()
            except (ValueError, TypeError, RecursionError):  # a lone surrogate or a monster value: not a record we wrote
                digest = None
            if digest != rec.get("hash"):
                return VerifyReport(False, count, seq, f"record {seq}: hash does not match content")
            try:
                self._verifier.verify(bytes.fromhex(rec["sig"]), bytes.fromhex(rec["hash"]))
            except (InvalidSignature, ValueError, KeyError, TypeError):
                return VerifyReport(False, count, seq, f"record {seq}: bad signature")
            if rec.get("prev_hash") != prev_hash or seq != prev_seq + 1:
                return VerifyReport(False, count, seq, f"record {seq}: chain break")
            prev_hash, prev_seq, count = rec["hash"], seq, count + 1
        if damaged:
            reason = f"line {damaged[0]} is not a journal record ({len(damaged)} damaged); the {count} whole records verify"
            return VerifyReport(False, count, damaged[0], reason)
        return VerifyReport(True, count, None, "ok")
