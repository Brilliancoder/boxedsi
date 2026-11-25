"""What boxed skills checked last: `<boxed home>/skills/record.json`, one private file that is read strictly and not signed.

The record keeps, per installed item, its content digest, the verdict, when and with which rules it was checked, and the rule, severity,
file and line of each finding (never the evidence, never a value from a config). It also holds the quarantine entries that quarantine.py
fills and the answers of the AI review, keyed by file hash, provider and model, so the same file is not sent twice: of each model
finding only the rule, severity, file and line, never its evidence or the model's reason.

It is not signed on purpose (docs/adr/0004-unsigned-check-record.md): code running as the same user could switch the hook off anyway, and an agent in a masked
copy cannot reach the file because "skills" is one of workspace.SENSITIVE_HOME_PARTS. The price of a forged record is one hidden warning.
A file that is not exactly what save_record writes is an error, never a permissive answer: the remedy is in the message."""

import hashlib
import json
import os
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, fields
from datetime import datetime
from pathlib import Path

from boxed.errors import UserError
from boxed.locks import file_lock
from boxed.platform import open_nofollow, private_enough, replace_file
from boxed.skills._shared import no_repeated_keys
from boxed.skills.rules import SEVERITIES, Finding

VERDICTS = ("dangerous", "suspicious", "ok")
FILE_NAME = "record.json"
FOLDER = "skills"
VERSION = 1
MAX_BYTES = 64 * 1024 * 1024  # a record of tens of thousands of items; anything larger is not one boxed wrote
DAMAGED = "record.json is damaged: move it aside and run boxed skills scan again (the quarantine folder keeps its files)"
_QUARANTINE_KEYS = frozenset({"item", "agent", "kind", "name", "method", "original", "at", "data"})
_FINDING_FIELDS = frozenset(f.name for f in fields(Finding))
_FINDING_REQUIRED = frozenset({"rule", "severity", "file", "line"})
_AI_KEPT = ("rule", "severity", "file", "line")  # all that is written of a model finding; an older record may hold more, never written again
_ITEM_KEYS = frozenset({"digest", "verdict", "checked_at", "rules_version", "findings"})
_HEX = frozenset("0123456789abcdef")
_MAX_DEPTH = 32


@dataclass(frozen=True)
class RecordItem:
    digest: str
    verdict: str
    checked_at: str  # ISO UTC
    rules_version: str
    findings: tuple[tuple[str, str, str, int], ...] = ()  # (rule, severity, file, line); no evidence


ID_MAX = 256  # an item id longer than this is stored under its hash: the name is an attacker's, the record must still be saved
FILE_MAX = 512  # of a finding's file name in the record; the report has the whole name
_LONG = "sha256:"


def _key(item_id: str) -> str:
    """The key an item id is stored under: the id itself, or `sha256:<hex>` when it is longer than ID_MAX."""
    if len(item_id) <= ID_MAX:
        return item_id
    return _LONG + hashlib.sha256(item_id.encode("utf-8", "backslashreplace")).hexdigest()


class _Items(dict):
    """The items of a record by id. A long id is looked up by its hash, so `id in record.items` and `record.items[id]` work for every id
    whether it was just scanned or read back from the file (where only the hash is kept)."""

    def __init__(self, data=()):
        super().__init__()
        for key, value in dict(data).items():
            self[key] = value

    def __getitem__(self, key):
        return super().__getitem__(_key(key))

    def __setitem__(self, key, value):
        super().__setitem__(_key(key), value)

    def __delitem__(self, key):
        super().__delitem__(_key(key))

    def __contains__(self, key):
        return super().__contains__(_key(key))

    def get(self, key, default=None):
        return super().get(_key(key), default)

    def pop(self, key, *default):
        return super().pop(_key(key), *default)

    def setdefault(self, key, default=None):
        return super().setdefault(_key(key), default)


@dataclass
class Record:
    items: dict[str, RecordItem] = field(default_factory=_Items)  # by item id (see _Items)
    quarantined: dict[str, dict] = field(default_factory=dict)  # by quarantine id, written by quarantine.py
    ai: dict[str, list[dict]] = field(default_factory=dict)  # "<file sha256>:<provider>:<model>" -> AI findings: rule, severity, file, line


    def __setattr__(self, name: str, value: object) -> None:
        if name == "items" and not isinstance(value, _Items):
            value = _Items(value)  # a plain dict assigned by a caller keeps the same lookups
        super().__setattr__(name, value)


class RecordError(UserError): ...


# ---- validation ----


def _text(value: object) -> bool:
    """A string of any length: names come from disk and config keys an attacker chose, and a limit here would let a long name stop the
    record from being saved. MAX_BYTES bounds the whole file."""
    return type(value) is str


def _int(value: object) -> bool:
    return type(value) is int and 0 <= value <= 10**9


def _when(value: object) -> bool:
    if not _text(value):
        return False
    try:
        datetime.fromisoformat(value)  # type: ignore[arg-type]
    except ValueError:
        return False
    return True


def _json_value(value: object, depth: int = 0) -> bool:
    """Anything json.loads can return, nested at most _MAX_DEPTH deep."""
    if depth > _MAX_DEPTH:
        return False
    if value is None or type(value) in (str, int, float, bool):
        return True
    if type(value) is list:
        return all(_json_value(v, depth + 1) for v in value)
    if type(value) is dict:
        return all(type(k) is str and _json_value(v, depth + 1) for k, v in value.items())
    return False


def _item_of(data: object) -> RecordItem | None:
    if type(data) is not dict or set(data) != _ITEM_KEYS:
        return None
    digest = data["digest"]
    if type(digest) is not str or len(digest) != 64 or not set(digest) <= _HEX:
        return None
    if data["verdict"] not in VERDICTS or not _when(data["checked_at"]) or not _text(data["rules_version"]):
        return None
    raw = data["findings"]
    if type(raw) is not list:
        return None
    findings = []
    for f in raw:
        if type(f) is not list or len(f) != 4:
            return None
        rule, severity, file, line = f
        if not (_text(rule) and severity in SEVERITIES and _text(file) and _int(line)):
            return None
        findings.append((rule, severity, file, line))
    return RecordItem(digest, data["verdict"], data["checked_at"], data["rules_version"], tuple(findings))


def _quarantine_ok(entry: object) -> bool:
    return (
        type(entry) is dict
        and set(entry) == _QUARANTINE_KEYS
        and all(_text(entry[k]) for k in _QUARANTINE_KEYS - {"data"})
        and _when(entry["at"])
        and type(entry["data"]) is dict
        and _json_value(entry["data"])
    )


def _ai_ok(entries: object) -> bool:
    if type(entries) is not list:
        return False
    for e in entries:
        if type(e) is not dict or not _FINDING_REQUIRED <= set(e) <= _FINDING_FIELDS:
            return False
        if not all(_text(v) for k, v in e.items() if k != "line") or not _int(e["line"]) or e["severity"] not in SEVERITIES:
            return False
    return True


def _record_of(data: object) -> Record | None:
    if type(data) is not dict or set(data) != {"version", "items", "quarantined", "ai"}:
        return None
    if type(data["version"]) is not int or data["version"] != VERSION:
        return None
    if not all(type(data[k]) is dict for k in ("items", "quarantined", "ai")):
        return None
    items = {}
    for key, value in data["items"].items():
        parsed = _item_of(value)
        if parsed is None or not _text(key):
            return None
        items[key] = parsed
    if not all(_text(k) and _quarantine_ok(v) for k, v in data["quarantined"].items()):
        return None
    if not all(_text(k) and _ai_ok(v) for k, v in data["ai"].items()):
        return None
    return Record(_Items(items), data["quarantined"], data["ai"])


# ---- reading and writing ----


def _path(home: Path) -> Path:
    return home / FOLDER / FILE_NAME


def _read(path: Path) -> bytes:
    """The bytes of a plain file that only its owner can change, at most MAX_BYTES. Opened without following a link or waiting."""
    fd = open_nofollow(path, os.O_RDONLY)
    with os.fdopen(fd, "rb") as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or not private_enough(info):
            raise RecordError(DAMAGED)
        data = f.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise RecordError(DAMAGED)
    return data


def _load(home: Path) -> Record:
    """load_record for code that holds the lock already."""
    try:
        data = json.loads(_read(_path(home)).decode("utf-8"), object_pairs_hook=no_repeated_keys)
    except FileNotFoundError:
        return Record()
    except (OSError, ValueError, RecursionError):  # a link, a folder, a bad byte, bad JSON, a key twice
        raise RecordError(DAMAGED) from None
    record = _record_of(data)
    if record is None:
        raise RecordError(DAMAGED)
    return record


def _dump(record: Record) -> str:
    """The document. Long ids are keys by hash and file names are cut (FILE_MAX), so one hostile name cannot make the record unsavable;
    a record still over MAX_BYTES keeps the digests and verdicts and drops the findings."""
    def build(with_findings: bool) -> str:
        items = {
            key: {"digest": i.digest, "verdict": i.verdict, "checked_at": i.checked_at, "rules_version": i.rules_version,
                  "findings": [[rule, sev, file[:FILE_MAX], line] for rule, sev, file, line in i.findings] if with_findings else []}
            for key, i in sorted(record.items.items())
        }
        ai = {key: [{k: row[k] for k in _AI_KEPT if k in row} for row in rows] for key, rows in record.ai.items()}
        return json.dumps({"version": VERSION, "items": items, "quarantined": record.quarantined, "ai": ai}, indent=1, ensure_ascii=True) + "\n"

    text = build(True)
    if len(text.encode()) > MAX_BYTES:
        text = build(False)
    if len(text.encode()) > MAX_BYTES or _record_of(json.loads(text)) is None:
        raise UserError("the record cannot be saved: it would not read back")
    return text


def _write(home: Path, record: Record) -> None:
    """A fresh part file (0600 from the start), flushed to the disk and renamed into place: a link planted at either name is replaced,
    never followed, and a crash leaves the old file whole."""
    text = _dump(record)
    path = _path(home)
    path.parent.mkdir(mode=0o700, exist_ok=True)
    part = path.with_name(path.name + ".part")
    part.unlink(missing_ok=True)
    fd = open_nofollow(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    replace_file(part, path)


def load_record(home: Path, *, timeout: float | None = None) -> Record:
    """The saved record; an empty one when there is no file; a RecordError for anything that is not exactly what save_record writes.
    Read under the lock the writers take, so a file being replaced is never met half way. `timeout` is the hook's short wait."""
    if not os.path.lexists(_path(home)):
        return Record()
    with file_lock(_path(home), timeout=timeout):
        return _load(home)


def save_record(home: Path, record: Record, *, timeout: float | None = None) -> None:
    (home / FOLDER).mkdir(mode=0o700, exist_ok=True)
    with file_lock(_path(home), timeout=timeout):
        _write(home, record)


def update_record(home: Path, change: Callable[[Record], None], *, timeout: float | None = None) -> Record:
    """Reads the record, lets `change` alter it and saves it, all under one lock, so two commands do not undo each other. Returns it."""
    (home / FOLDER).mkdir(mode=0o700, exist_ok=True)
    with file_lock(_path(home), timeout=timeout):
        record = _load(home)
        change(record)
        _write(home, record)
        return record


def changes(record: Record, digests: Mapping[str, str]) -> tuple[list[str], list[str]]:
    """(new ids, changed ids): items not in the record, and items whose digest is not the recorded one."""
    new = [i for i in digests if i not in record.items]
    changed = [i for i, d in digests.items() if i in record.items and record.items[i].digest != d]
    return new, changed
