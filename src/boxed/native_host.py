"""Native messaging host for the browser side panel: framed JSON on stdio, six commands."""

import hashlib
import json
import os
import re
import stat
import struct
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from . import __version__
from .checks import NOTE, SETTINGS, Check, CheckError, due, load_checks, save_check
from .config import CONFIG_NAME, ProjectConfig, read_config, to_detect_config
from .detect import ner
from .journal import Journal, JournalEntry
from .keys import default_keystore
from .mask import dictionary_kinds, mask_text, restore
from .observe import COVERAGE, SITES, ObservedJournal, observe, observed_journal
from .paths import boxed_home, boxed_home_path
from .platform import make_private, open_nofollow, owned_by_user
from .vault import Vault

HOST_NAME = "si.boxed.host"
MAX_MESSAGE = 1024 * 1024  # bytes of UTF-8 JSON, both directions (the browser's own limit for replies)
MAX_LEVEL = 2  # the panel offers levels 0-2; 3 and 4 need the program
SCOPE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")  # a short name, never text: scopes end up in the journal
LOG_NAME = "host-errors.log"  # in the boxed home; a mirror's agent may not read it (workspace.SENSITIVE_HOME_PARTS)
LOG_CAP = 64 * 1024


@dataclass
class HostContext:
    home: Path
    vault: Vault
    journal: Journal
    config: ProjectConfig
    observed: ObservedJournal  # observed.jsonl: what the browser sent without boxed, never mixed into the main journal


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    """Up to `size` bytes; fewer only at EOF (a pipe may hand them out in pieces)."""
    chunks: list[bytes] = []
    while size > 0:
        chunk = stream.read(size)
        if not chunk:
            break
        chunks.append(chunk)
        size -= len(chunk)
    return b"".join(chunks)


def _no_repeated_keys(pairs: list[tuple[str, object]]) -> dict:
    """A parser keeps the last of a key that stands twice, so {"cmd": "ping", "cmd": "mask"} would run mask while another reader of
    the same bytes ran ping. A request that can be read two ways is not read: the key twice is an error, at any depth."""
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError("a key twice")
    return dict(pairs)


def read_message(stream: BinaryIO, limit: int = MAX_MESSAGE, order: str = "=") -> dict | None:
    """One frame: 4-byte length (native order, or the struct `order` given), then a UTF-8 JSON object. None at EOF.
    A length over `limit` is refused from the header alone: the body stays unread.

    Every ValueError text is fixed: it never carries a piece of the message.
    """
    header = _read_exact(stream, 4)
    if not header:
        return None
    if len(header) < 4:
        raise ValueError("truncated frame")
    (size,) = struct.unpack(f"{order}I", header)
    if size > limit:
        raise ValueError("message too large")  # the body stays unread
    body = _read_exact(stream, size)
    if len(body) < size:
        raise ValueError("truncated frame")
    try:
        message = json.loads(body.decode("utf-8"), object_pairs_hook=_no_repeated_keys)
    except (ValueError, RecursionError):  # UnicodeDecodeError and JSONDecodeError are ValueErrors
        raise ValueError("bad json") from None
    if not isinstance(message, dict):
        raise ValueError("bad json")
    return message


def _encode(message: dict, limit: int = MAX_MESSAGE) -> bytes:
    try:
        body = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except UnicodeEncodeError:  # a lone surrogate; its message would quote the character
        raise ValueError("reply is not valid text") from None
    if len(body) > limit:
        raise ValueError("reply too large")
    return body


def write_message(stream: BinaryIO, message: dict, limit: int = MAX_MESSAGE, order: str = "=") -> None:
    body = _encode(message, limit)
    stream.write(struct.pack(f"{order}I", len(body)) + body)
    stream.flush()


class _Refused(Exception):
    """An error the extension may show. Its text is fixed in this module, never built from a message."""


def _log_failure(home: Path, event: str, error: BaseException) -> None:
    """Add a line to host-errors.log: the time, the failure ("host cannot start" or "internal error") and the class name of
    the exception. Never its message, its cause or its traceback: they can quote the text of a request.

    Best effort: a log that cannot be written changes nothing the person sees. The file is opened without following a link and
    without waiting for the reader of a pipe, and is written only when it is a plain file of ours with no other name (a hard link
    to another file of the same user would be that file), which is then made private. A line that would take it past LOG_CAP
    empties it first, so it holds the newest lines and never more than LOG_CAP bytes."""
    line = f"{datetime.now(UTC).isoformat(timespec='seconds')} {event}: {type(error).__name__}\n".encode()
    try:
        fd = open_nofollow(home / LOG_NAME, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    except OSError:
        return
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not owned_by_user(info):
            return
        make_private(fd)
        if info.st_size + len(line) > LOG_CAP:
            os.ftruncate(fd, 0)
        os.write(fd, line)
    except OSError:
        pass
    finally:
        os.close(fd)


def _text(message: dict) -> str:
    text = message.get("text")
    if not isinstance(text, str):
        raise _Refused("bad request")
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:  # a lone surrogate cannot travel back as UTF-8
        raise _Refused("bad request") from None
    return text


def _scope(message: dict, default: str | None = None) -> str:
    scope = message.get("scope")
    if scope is None:
        scope = default
    if not isinstance(scope, str) or not SCOPE_RE.fullmatch(scope):
        raise _Refused("bad request")
    return scope


def _level(message: dict, config: ProjectConfig) -> int:
    level = message.get("level")
    if level is None:
        return min(config.level, MAX_LEVEL)
    if type(level) is not int or level not in range(MAX_LEVEL + 1):
        raise _Refused("bad request")
    return level


def _checked(reply: dict) -> dict:
    """The reply, once it is known to fit in a frame: nothing is saved or journaled for one that cannot be sent."""
    try:
        _encode(reply)
    except ValueError as e:
        raise _Refused(str(e)) from None
    return reply


def _record(ctx: HostContext, *, scope: str, status: str, payload: str, level: int, counts: dict[str, int], note: str = "") -> None:
    ctx.journal.append(
        JournalEntry(
            channel="extension",
            provider="unknown",
            account_type="unknown",
            level=level,
            markers_by_kind=counts,
            status=status,
            payload_sha256=hashlib.sha256(payload.encode()).hexdigest(),
            coverage="full",
            scope=scope,
            versions={"boxed": __version__},
            note=note,
        )
    )


def _mask(message: dict, ctx: HostContext) -> dict:
    text = _text(message)
    scope = _scope(message, "web-" + datetime.now(UTC).strftime("%Y%m%d"))
    level = _level(message, ctx.config)
    with ctx.vault.transaction(scope) as markers:
        masked, counts = mask_text(text, markers, level=level, config=to_detect_config(ctx.config))
        reply = _checked({"ok": True, "text": masked, "scope": scope, "markers_by_kind": counts})  # a refusal skips the save
    _record(ctx, scope=scope, status="prepared", payload=masked, level=level, counts=counts)
    return reply


def _restore(message: dict, ctx: HostContext) -> dict:
    text = _text(message)
    scope = _scope(message)
    if scope not in ctx.vault.scopes():
        raise _Refused("unknown scope")
    result = restore(text, ctx.vault.load_map(scope), dictionary_kinds(ctx.config))
    reply = _checked({"ok": True, "text": result.text, "unknown": result.unknown, "suspicious": result.suspicious})
    note = f"restored={result.restored} unknown={len(result.unknown)} suspicious={len(result.suspicious)}"
    _record(ctx, scope=scope, status="received", payload=text, level=-1, counts={}, note=note)
    return reply


def _observe(message: dict, ctx: HostContext) -> dict:
    """Count what a page sent without boxed. The text is read, counted and dropped; only kinds, counts and its hash are kept.
    A text with a lone surrogate is not refused (_text would): observe() records the send as not checked."""
    text, site, coverage = message.get("text"), message.get("site"), message.get("coverage")
    if not isinstance(text, str) or site not in SITES or coverage not in COVERAGE or (coverage == "not checked" and text):
        raise _Refused("bad request")
    return {"ok": True, "found": observe(text, site, coverage, ctx.observed, to_detect_config(ctx.config))}


def _checks(message: dict, ctx: HostContext) -> dict:
    try:
        checks = load_checks(ctx.home)
    except CheckError:
        raise _Refused("checks unreadable") from None
    overdue = {(c.provider, c.account) for c in due(checks, datetime.now(UTC).date())}  # one per account: a set, not a scan
    rows = [asdict(c) | {"due": (c.provider, c.account) in overdue, "settings_url": SETTINGS[c.provider]} for c in checks]
    return {"ok": True, "checks": rows, "providers": list(SETTINGS), "settings": dict(SETTINGS), "note": NOTE}


def _check_set(message: dict, ctx: HostContext) -> dict:
    """The person's answer about one account. The host sets the source and the date: the page cannot back-date a check."""
    check = Check(
        message.get("provider"),
        message.get("account"),
        message.get("training"),
        message.get("memory"),
        "asked",
        datetime.now(UTC).date().isoformat(),
    )
    try:
        save_check(ctx.home, check)
    except ValueError:  # a value that is not a provider, a state or a plain account name
        raise _Refused("bad request") from None
    except CheckError:
        raise _Refused("checks unreadable") from None
    return {"ok": True}


_COMMANDS = {
    "ping": (frozenset(), lambda message, ctx: {"ok": True, "version": __version__}),
    "mask": (frozenset({"text", "scope", "level"}), _mask),
    "restore": (frozenset({"text", "scope"}), _restore),
    "observe": (frozenset({"site", "text", "coverage"}), _observe),
    "checks": (frozenset(), _checks),
    "check-set": (frozenset({"provider", "account", "training", "memory"}), _check_set),
}


def handle(message: dict, ctx: HostContext) -> dict:
    """{"ok": True, ...} or {"ok": False, "error": <fixed text>}; an error never quotes the message."""
    cmd = message.get("cmd")
    try:
        if not isinstance(cmd, str) or cmd not in _COMMANDS:
            raise _Refused("bad request")
        fields, run = _COMMANDS[cmd]
        if not set(message) <= fields | {"cmd"}:
            raise _Refused("bad request")
        return run(message, ctx)
    except _Refused as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:  # fail closed: the text of an exception may quote the input
        _log_failure(ctx.home, "internal error", e)
        return {"ok": False, "error": "internal error"}


def _answer_one(stdin: BinaryIO, stdout: BinaryIO, respond: Callable[[dict], dict]) -> int | None:
    """Read one frame and answer it. None: go on. A number: the exit code, once the input has ended or cannot be trusted.

    A function of its own so that the request and its answer end with its frame: the loop that calls it holds nothing of them
    while it waits for the next frame, which may be a minute away."""
    try:
        message = read_message(stdin)
    except ValueError as e:  # after a bad frame the stream cannot be trusted any more
        write_message(stdout, {"ok": False, "error": str(e)})
        return 1
    if message is None:
        return 0
    reply = respond(message)
    try:
        write_message(stdout, reply)
    except ValueError as e:  # a reply that cannot be sent: say so, keep serving
        write_message(stdout, {"ok": False, "error": str(e)})
    return None


def _serve(stdin: BinaryIO, stdout: BinaryIO, respond: Callable[[dict], dict], again: Callable[[], bool] = lambda: True) -> int:
    """Answer frames until the input ends or `again()` says no, which it is asked after each answer: the input is then left
    unread, and the browser starts the program again for what comes next."""
    while (code := _answer_one(stdin, stdout, respond)) is None:
        if not again():
            return 0
    return code


def serve(stdin: BinaryIO, stdout: BinaryIO, ctx: HostContext) -> int:
    """Reply to each message until EOF. A bad frame gets one error reply and ends the loop with 1.

    The browser keeps this process for as many requests as a panel makes, so each is answered as a new process would answer
    it: boxed.toml is read again first, which makes a dictionary entry added a moment ago apply to the next request, and a
    boxed.toml that cannot be read now stops the request ("host cannot start") until it is mended.

    Nothing of a text is meant to outlast its answer. If the tokenizer of GLiNER keeps the words it has read and the library gives
    no way to empty it (ner.words_kept), the only way to forget them is to end: the loop does, after the answer to the request that
    read them."""

    def respond(message: dict) -> dict:
        try:
            ctx.config = read_config(ctx.home / CONFIG_NAME)
        except Exception as e:  # what decides the masking cannot be read: do not mask with an old copy of it
            _log_failure(ctx.home, "host cannot start", e)
            return {"ok": False, "error": "host cannot start"}
        return handle(message, ctx)

    return _serve(stdin, stdout, respond, again=lambda: not ner.words_kept())


def open_context() -> HostContext:
    """The browser gives the host no project folder, so boxed.toml is read from the boxed home."""
    home = boxed_home()
    keys = default_keystore()
    # only the home's own boxed.toml: a file in a parent folder must not loosen masking for the browser
    return HostContext(
        home,
        Vault(home / "vault.db", keys),
        Journal(home / "journal.jsonl", keys),
        read_config(home / CONFIG_NAME),
        observed_journal(home, keys),
    )


def main() -> int:
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    sys.stdout = sys.stderr  # stdout carries frames only: a stray print would corrupt them
    try:
        ctx = open_context()
    except Exception as e:  # a locked keychain or a broken boxed.toml: tell the panel instead of just exiting
        _log_failure(boxed_home_path(), "host cannot start", e)  # once, however many messages the panel sends
        _serve(stdin, stdout, lambda message: {"ok": False, "error": "host cannot start"})
        return 1
    return serve(stdin, stdout, ctx)


if __name__ == "__main__":
    sys.exit(main())
