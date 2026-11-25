"""The "training on chats" checks: what the person told boxed about each chat account, kept in checks.json.

A file that cannot be trusted is an error, never a permissive answer: the caller falls back to "unknown". The file is signed
with the device key the journal signs with, so a file that boxed did not write, that was changed after it was written, or that
was written before files were signed is not believed. A copy of an older file that this device signed is believed too: nothing
numbers the versions of the file.
"""

import json
import os
import re
import stat
from dataclasses import asdict, dataclass, fields
from datetime import date
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .keys import KeyStore, default_keystore
from .locks import file_lock
from .platform import open_nofollow, private_enough, replace_file

SETTINGS = {
    "chatgpt": "https://chatgpt.com/#settings/DataControls",
    "claude": "https://claude.ai/settings/data-privacy-controls",
    "gemini": "https://myactivity.google.com/product/gemini",
    "deepseek": None,
    "zai": None,
}
STATES = ("on", "off", "unknown")
SOURCES = ("asked",)  # reading the settings page comes later
REMIND_DAYS = 30
NOTE = "Training off does not mean nothing is stored: providers still keep chats for a while."
ACCOUNT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}")  # a short name, never text
FILE_NAME = "checks.json"
MAX_BYTES = 64 * 1024  # a few accounts are a few KB: a bigger file is not one boxed wrote
VERSION = 1
DAMAGED = "checks.json is damaged"  # fixed: an error text never quotes the file
RECONFIRM = "training checks need to be confirmed again"  # fixed: no signature, a wrong one, or a file from before files were signed
SIGNING_KEY = "device-signing-key"  # the key the journal signs with
SIGNED_CONTEXT = b"boxed.si checks.json\n"  # the first bytes of what is signed here: a signature made for the journal never fits this file
_SIGNATURE = re.compile(r"[0-9a-f]{128}")  # an Ed25519 signature in hex, as .hex() writes it


@dataclass
class Check:
    provider: str
    account: str
    training: str
    memory: str
    source: str  # "asked"
    checked_at: str  # ISO date, UTC


class CheckError(Exception):
    """checks.json is damaged, cannot be read, or is not signed by this device: the checks are unknown."""


def _valid(check: Check) -> bool:
    """What save_check may write and load_checks accepts: nothing else is a check."""
    values = (check.provider, check.account, check.training, check.memory, check.source, check.checked_at)
    if not all(type(value) is str for value in values):
        return False
    try:
        canonical_date = date.fromisoformat(check.checked_at).isoformat() == check.checked_at  # not 20261001, not a time
    except ValueError:
        return False
    return (
        check.provider in SETTINGS
        and ACCOUNT_RE.fullmatch(check.account) is not None
        and check.training in STATES
        and check.memory in STATES
        and check.source in SOURCES
        and canonical_date
    )


def _checks_of(data: object) -> list[Check] | None:
    """The checks of a parsed document, or None when it is not exactly what save_check writes."""
    if type(data) is not dict or set(data) != {"version", "checks"}:
        return None
    if type(data["version"]) is not int or data["version"] != VERSION or type(data["checks"]) is not list:
        return None
    names = {f.name for f in fields(Check)}
    checks = []
    for item in data["checks"]:
        if type(item) is not dict or set(item) != names:
            return None
        check = Check(**item)
        if not _valid(check):
            return None
        checks.append(check)
    if len({(c.provider, c.account) for c in checks}) != len(checks):  # of two answers for one account, which is true?
        return None
    return checks


def _no_repeated_keys(pairs: list[tuple[str, object]]) -> dict:
    """A parser keeps the last of a key that stands twice; the earlier one would be in the file and outside the signature."""
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError("a key twice")
    return dict(pairs)


def _signer(keys: KeyStore | None) -> Ed25519PrivateKey:
    """The device key. A key store that fails raises its own error: that is no answer about the checks, and not a damaged file."""
    return Ed25519PrivateKey.from_private_bytes((default_keystore() if keys is None else keys).get_or_create(SIGNING_KEY, 32))


def _message(content: dict) -> bytes:
    """What the signature covers: the context line and the whole content in one canonical form (sorted keys, no spaces), so
    that the signature depends on what the file says and not on how it is laid out."""
    return SIGNED_CONTEXT + json.dumps(content, sort_keys=True, separators=(",", ":")).encode()


def _believed(data: dict, keys: KeyStore | None) -> dict:
    """The content of a parsed file (every key but "sig") when the device key signed exactly that; otherwise a CheckError: a
    missing signature is a file from before signing, or one that boxed did not write."""
    signature = data.get("sig")
    content = {key: value for key, value in data.items() if key != "sig"}
    if type(signature) is not str or _SIGNATURE.fullmatch(signature) is None:
        raise CheckError(RECONFIRM)
    public_key = _signer(keys).public_key()
    try:
        public_key.verify(bytes.fromhex(signature), _message(content))
    except InvalidSignature:
        raise CheckError(RECONFIRM) from None
    return content


def _read(path: Path) -> bytes:
    """The bytes of a plain file that only its owner can write and that is no larger than MAX_BYTES. Opening never waits
    (a FIFO would block it) and never follows a link, and at most MAX_BYTES + 1 bytes are read, whatever the size on disk."""
    fd = open_nofollow(path, os.O_RDONLY)
    with os.fdopen(fd, "rb") as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or not private_enough(info):  # a folder, a pipe, a file others could have changed
            raise CheckError(DAMAGED)
        data = f.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise CheckError(DAMAGED)
    return data


def load_checks(home: Path, keys: KeyStore | None = None) -> list[Check]:
    """The saved checks in the order they were saved; [] when there is no file; a CheckError for anything else that is
    not exactly what save_check writes: a damaged file, or one whose signature is missing or not the device key's over
    the whole content. `keys` is the key store of the device key (the default one when not given).

    Read under the lock the writers take, so that a file that is being replaced is never met half way (on Windows a read that
    meets the replace of a writer failed, and a good file read as damaged). Code that holds the lock reads with _load."""
    path = home / FILE_NAME
    if not os.path.lexists(path):  # nothing to read, so nothing to lock
        return []
    with file_lock(path):
        return _load(home, keys)


def _load(home: Path, keys: KeyStore | None = None) -> list[Check]:
    """load_checks for code that holds the lock of checks.json already: a second descriptor of the lock file would wait for the first."""
    try:
        data = json.loads(_read(home / FILE_NAME).decode("utf-8"), object_pairs_hook=_no_repeated_keys)
    except FileNotFoundError:
        return []
    except (OSError, ValueError, RecursionError):  # a bad byte, bad json, a key twice, a folder in place of the file
        raise CheckError(DAMAGED) from None
    if type(data) is not dict:
        raise CheckError(DAMAGED)
    checks = _checks_of(_believed(data, keys))
    if checks is None:
        raise CheckError(DAMAGED)
    return checks


def _write(path: Path, text: str, keys: KeyStore | None = None) -> None:
    """The one way checks.json is written. `text` is the document, {"version": ..., "checks": [...]} as json, and the file
    holds it with the signature of the device key; a document that load_checks would refuse is a ValueError, and nothing is
    written. The write goes through a fresh part file, mode 600 from the start, and is renamed into place: a symlink planted
    at either name is replaced, never followed, and a crash leaves the old file whole."""
    content = json.loads(text)
    if _checks_of(content) is None:
        raise ValueError("bad checks")
    signed = json.dumps(content | {"sig": _signer(keys).sign(_message(content)).hex()}, indent=2) + "\n"
    if len(signed.encode()) > MAX_BYTES:
        raise ValueError("too many checks")  # load_checks would refuse the file
    part = path.with_name(path.name + ".part")
    part.unlink(missing_ok=True)
    fd = open_nofollow(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", newline="\n") as f:  # \n stays \n on Windows too: the size counted above is the size on disk
        f.write(signed)
        f.flush()
        os.fsync(f.fileno())
    replace_file(part, path)


def save_check(home: Path, check: Check, keys: KeyStore | None = None) -> None:
    """One check per (provider, account): the one saved last replaces an earlier one and goes to the end of the list.
    A file that load_checks refuses (damaged, or not signed by this device) is a CheckError and stays as it is: nothing
    that was not believed is signed. A check, or a list of checks, that load_checks would refuse is a ValueError."""
    if not _valid(check):
        raise ValueError("bad check")  # what could not be loaded again must not be written
    path = home / FILE_NAME
    with file_lock(path):  # the browser may start several hosts: read, change and write must not interleave
        kept = [c for c in _load(home, keys) if (c.provider, c.account) != (check.provider, check.account)]
        _write(path, json.dumps({"version": VERSION, "checks": [asdict(c) for c in [*kept, check]]}, indent=2) + "\n", keys)


def due(checks: list[Check], today: date) -> list[Check]:
    """The checks to ask about again: an answer that is still unknown, older than REMIND_DAYS, or dated after `today`
    (a date that never comes would never ask again). `today` is the UTC date, the one checked_at is written in."""
    return [
        c
        for c in checks
        if "unknown" in (c.training, c.memory) or not 0 <= (today - date.fromisoformat(c.checked_at)).days <= REMIND_DAYS
    ]


def account_kind(check: Check | None) -> str:
    """The recipient kind for the policy: private only when the person said training is off, otherwise the stricter one."""
    return "personal-private" if check is not None and check.training == "off" else "personal-training"
