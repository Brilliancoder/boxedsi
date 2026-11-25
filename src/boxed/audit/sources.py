"""Readers for local transcripts: everything that went into the model context, line by line."""

import json
import os
import re
import stat
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import IO

from .. import platform
from . import paths


@dataclass
class SentItem:
    source: str
    provider: str
    project: str
    session: str
    ts: datetime | None
    role: str
    text: str
    locator: str


class _Malformed(ValueError):
    """A record that does not have the shape of a transcript, at any depth."""


def _ts(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _texts(content: object) -> list[str]:
    """The text of a content field: a string, or a list of strings and parts. A part with a `text` has it as a string; a
    tool_result part holds a content field of its own; other parts (an image) have no text. Anything else is _Malformed."""
    if content is None:
        return []
    if isinstance(content, str):
        return [content]
    if not isinstance(content, list):
        raise _Malformed
    out: list[str] = []
    for item in content:
        if isinstance(item, str):
            out.append(item)
        elif not isinstance(item, dict):
            raise _Malformed
        elif item.get("text") is not None:
            if not isinstance(item["text"], str):
                raise _Malformed
            out.append(item["text"])
        elif item.get("type") == "tool_result":
            out.extend(_texts(item.get("content")))
    return out


def _mounts(mounts: object) -> paths.Mounts | None:
    return paths.mount_table() if mounts is paths.READ else mounts  # type: ignore[return-value]


# why a file was not read, by what local_state said, and the keys of the stats for each kind of thing
_NOT_LOCAL = {paths.NETWORK: "not_local", paths.UNKNOWN: "disk_unknown"}


def _open_local(path: str, mounts: paths.Mounts | None, max_size: int | None = None) -> tuple[IO[str] | None, str]:
    """A file found in a folder or named by a transcript, opened for reading only when it is a plain file on a local disk: every
    link on the way is followed only once it is known to stay on a local disk (paths.local_state), the file is opened without
    waiting (a named pipe would wait for a writer) and its type is checked on the open descriptor. (file, "") or (None, why):
    missing, not_local, disk_unknown, access (no access, or no plain file), big."""
    state = paths.local_state(path, mounts)
    if state != paths.LOCAL:
        return None, _NOT_LOCAL[state]
    name = paths.os_path(path)  # a name the file system encoding cannot spell (the C locale) is read by its UTF-8 bytes
    try:
        before = os.stat(name)
    except (FileNotFoundError, NotADirectoryError):
        return None, "missing"
    except (OSError, UnicodeEncodeError):  # a name that is not even UTF-8 (see paths.os_path) is not read: a gap
        return None, "access"  # no way through a folder on the way is no missing file
    if not stat.S_ISREG(before.st_mode):
        return None, "access"
    if max_size is not None and before.st_size > max_size:
        return None, "big"
    try:
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    except (FileNotFoundError, NotADirectoryError):
        return None, "missing"
    except OSError:
        return None, "access"
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino):
            os.close(fd)
            return None, "access"  # changed between the look and the open
        return os.fdopen(fd, encoding="utf-8", errors="replace"), ""
    except OSError:
        os.close(fd)
        return None, "access"


def _transcripts(root: Path, stats: Counter, mounts: paths.Mounts | None) -> list[Path]:
    """The *.jsonl files under `root`, sorted. A folder that cannot be listed is counted (folders_unread), not passed over in
    silence as Path.rglob does; a folder on a network or unknown file system is not entered (folders_not_local,
    folders_disk_unknown). A missing root is no gap: there is nothing to read."""
    top = os.path.abspath(root)
    state = paths.local_state(top, mounts)
    if state != paths.LOCAL:
        stats[f"folders_{_NOT_LOCAL[state]}"] += 1
        return []

    def unread(error: OSError) -> None:
        if isinstance(error, FileNotFoundError | NotADirectoryError) and os.path.abspath(error.filename or "") == top:
            return
        stats["folders_unread"] += 1

    found: list[Path] = []
    for folder, subfolders, files in os.walk(top, onerror=unread):
        if not platform.IS_WINDOWS and mounts is not None:
            keep = []
            for name in subfolders:
                kind = paths._mount_kind(os.path.join(folder, name), mounts)
                if kind is False:
                    keep.append(name)
                else:
                    stats["folders_not_local" if kind else "folders_disk_unknown"] += 1
            subfolders[:] = keep
        found += [Path(folder, name) for name in files if name.endswith(".jsonl")]
    return sorted(found)


def _records(path: Path, stats: Counter, mounts: paths.Mounts | None) -> Iterator[tuple[int, dict]]:
    """The JSON objects of a transcript, with their line. A file that cannot be opened or read is counted as not checked."""
    fh, why = _open_local(str(path), mounts)
    if fh is None:
        stats["transcripts_" + ("unread" if why in ("missing", "access") else why)] += 1
        return
    try:
        with fh:
            for lineno, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except (ValueError, RecursionError):
                    stats["malformed"] += 1
                    continue
                if isinstance(rec, dict):
                    yield lineno, rec
                else:
                    stats["malformed"] += 1
    except OSError:
        stats["transcripts_unread"] += 1


def _str_or_none(rec: dict, *names: str) -> bool:
    """Are the fields, where present, strings? A line with another type there does not have the shape of a transcript."""
    return all(rec.get(name) is None or isinstance(rec.get(name), str) for name in names)


def _claude_texts(kind: str, message: object, rendered: object) -> list[tuple[str, str]]:
    """(role, text) of a user or attachment record of Claude Code; _Malformed when any part of it has the wrong shape."""
    out: list[tuple[str, str]] = []
    if kind == "user":
        if not isinstance(message, dict):
            raise _Malformed
        content = message.get("content")
        if isinstance(content, str):
            return [("user_prompt", content)] if content else []
        if content is not None and not isinstance(content, list):
            raise _Malformed
        for part in content or []:
            if not isinstance(part, dict) or not _str_or_none(part, "type"):
                raise _Malformed
            if part.get("type") == "tool_result":
                role, text = "tool_result", "\n".join(_texts(part.get("content")))
            elif part.get("type") == "text":
                if not _str_or_none(part, "text"):
                    raise _Malformed
                role, text = "user_prompt", part.get("text") or ""
            else:
                continue
            if text:
                out.append((role, text))
        return out
    if rendered is not None and not isinstance(rendered, list):
        raise _Malformed
    for part in rendered or []:
        if not isinstance(part, dict):
            raise _Malformed
        text = "\n".join(_texts(part.get("content")))
        if text:
            out.append(("attachment", text))
    return out


def iter_claude_code(root: Path, stats: Counter, projects: set[str] | None = None, mounts: object = paths.READ) -> Iterator[SentItem]:
    """The text of the records of type user (prompts, text parts, tool results) and attachment (their rendered content). Every
    folder a record names as `cwd` goes into `projects`, whatever the day and the type of the record. A record whose fields have
    the wrong type, at any depth, is counted as malformed and the next one is read. Without a `cwd` the project is the name of
    the transcript folder (paths.show_path shows it cleaned)."""
    mounts = _mounts(mounts)
    for path in _transcripts(root, stats, mounts):
        for lineno, rec in _records(path, stats, mounts):
            kind = rec.get("type")
            if not _str_or_none(rec, "cwd", "sessionId", "type"):
                stats["malformed"] += 1
                continue
            if projects is not None and rec.get("cwd"):
                projects.add(rec["cwd"])
            if kind not in ("user", "attachment"):
                continue
            try:
                texts = _claude_texts(kind, rec.get("message"), rec.get("rendered"))
            except (_Malformed, RecursionError):
                stats["malformed"] += 1
                continue
            for role, text in texts:
                yield SentItem(
                    source="claude-code",
                    provider="anthropic",
                    project=rec.get("cwd") or path.parent.name,
                    session=rec.get("sessionId") or path.stem,
                    ts=_ts(rec.get("timestamp")),
                    role=role,
                    text=text,
                    locator=f"{path}:{lineno}",
                )


def iter_codex(root: Path, stats: Counter, projects: set[str] | None = None, mounts: object = paths.READ) -> Iterator[SentItem]:
    """The text of the response items that go to the model: messages of the user (user_prompt) and of the developer (instructions:
    the permissions and the project instructions Codex adds), and the output of tool calls (tool_result). The folder of
    session_meta and turn_context goes into `projects` and is the project of the records after it in the session. A record whose
    fields have the wrong type, at any depth, is counted as malformed and the next one is read."""
    mounts = _mounts(mounts)
    for path in _transcripts(root, stats, mounts):
        project, session = "?", path.stem
        for lineno, rec in _records(path, stats, mounts):
            payload = rec.get("payload")
            if payload is None:
                payload = {}
            if not isinstance(payload, dict) or not _str_or_none(rec, "type") or not _str_or_none(payload, "type", "role", "cwd"):
                stats["malformed"] += 1
                continue
            if rec.get("type") in ("session_meta", "turn_context"):
                if not _str_or_none(payload, "id", "session_id"):
                    stats["malformed"] += 1
                    continue
                if projects is not None and payload.get("cwd"):
                    projects.add(payload["cwd"])
                project = payload.get("cwd") or project  # a turn in another folder moves the session there
                if rec.get("type") == "session_meta":
                    session = payload.get("id") or payload.get("session_id") or session
                continue
            if rec.get("type") != "response_item":
                continue
            ptype = payload.get("type")
            try:
                if ptype == "message" and payload.get("role") in ("user", "developer"):
                    role = "user_prompt" if payload["role"] == "user" else "instructions"
                    text = "\n".join(_texts(payload.get("content")))
                elif ptype in ("function_call_output", "custom_tool_call_output"):
                    role, text = "tool_result", "\n".join(_texts(payload.get("output")))
                else:
                    continue
            except (_Malformed, RecursionError):
                stats["malformed"] += 1
                continue
            if text:
                yield SentItem("codex", "openai", project, session, _ts(rec.get("timestamp")), role, text, f"{path}:{lineno}")


SETTINGS_SOURCE = "claude-settings"
SETTINGS_NAMES = ("settings.json", "settings.local.json")
_SETTINGS_MAX = 4 * 1024 * 1024  # a settings file is small; a bigger one is no settings file to read whole
_JSON_STRING = re.compile(r'"(?:[^"\\\n]|\\.)*"')
_JSON_SPACE = re.compile(r"[ \t\r\n]*")  # the whitespace JSON allows between tokens, all of it


def claude_settings_files(
    user_dir: Path | None, projects: Iterable[str], stats: Counter | None = None, mounts: object = paths.READ
) -> list[tuple[Path, str, str]]:
    """The Claude Code settings files to read, with the project each belongs to: the user's own (in `user_dir`, the project is the
    folder that holds it) and those of every project folder the transcripts named, each with its role: "user_settings" or
    "project_settings" (a file a project keeps, which can go into git with it). A project is a path the agent ran in; a name
    that is no absolute path (the folder name a transcript fell back to) names no folder. A transcript is no trusted input: a
    project on a network path or a network mount is not looked at, only counted in `stats` as projects_not_local, and one whose
    disk is not known (paths.local_state) as projects_disk_unknown. Each file once, whatever the spelling."""
    out: list[tuple[Path, str, str]] = []
    seen: set[str] = set()
    folders = [(user_dir, str(user_dir.parent), "user_settings")] if user_dir is not None else []
    named = sorted({p for p in projects if isinstance(p, str) and p})
    candidates = [p for p in named if paths.is_network_spelling(p) or Path(p).is_absolute()]
    table = _mounts(mounts) if candidates and not platform.IS_WINDOWS else []
    for p in candidates:
        state = paths.local_state(p, table)
        if state == paths.LOCAL:
            folders.append((Path(p) / ".claude", p, "project_settings"))
        elif stats is not None:
            stats[f"projects_{_NOT_LOCAL[state]}"] += 1
    for folder, project, role in folders:
        for name in SETTINGS_NAMES:
            path = folder / name
            key = os.path.normcase(os.path.abspath(path))
            if key not in seen:
                seen.add(key)
                out.append((path, project, role))
    return out


def _settings_strings(text: str) -> Iterator[tuple[int, str | None, str]]:
    """(offset, key or None, value) of every string value of a JSON text known to parse. A string is a key when the next token
    after it, past any whitespace, is ':'; a value is read with its key when the token before it is ':'."""
    key: str | None = None
    for m in _JSON_STRING.finditer(text):
        try:
            value = json.loads(m.group())
        except ValueError:
            continue
        after = _JSON_SPACE.match(text, m.end()).end()
        if text.startswith(":", after):  # a key: its value comes next
            key = value
            continue
        i = m.start() - 1
        while i >= 0 and text[i] in " \t\r\n":
            i -= 1
        named = key if i >= 0 and text[i] == ":" else None
        key = None
        if isinstance(value, str) and value:
            yield m.start(), named, value


def iter_claude_settings(files: Iterable[tuple[Path, str, str]], stats: Counter, mounts: object = paths.READ) -> Iterator[SentItem]:
    """Every string value of the settings files, with the line it is written on. A value of an object is read with its key in front
    ("DB_PASSWORD: ..."), as the rules of names want; a value in a list (a permission rule) is read alone. A missing file is skipped
    without a word, like a transcript folder that is not there. A file that is there but is not read is counted in `stats` by why:
    settings_big (too big), settings_json (no JSON object), settings_access (no access, no way through a folder on the way, or no
    plain file), settings_not_local (on or through a link to a network path), settings_disk_unknown (a disk not known to be local).
    The files of the user and of the projects alike. Reads only."""
    files = list(files)
    table = _mounts(mounts) if files else []
    for path, project, role in files:
        fh, why = _open_local(str(path), table, _SETTINGS_MAX)
        if why == "missing":
            continue
        if fh is None:
            stats[f"settings_{why}"] += 1
            continue
        try:
            with fh:
                text = fh.read(_SETTINGS_MAX + 1)
        except OSError:
            stats["settings_access"] += 1
            continue
        if len(text) > _SETTINGS_MAX:
            stats["settings_big"] += 1
            continue
        try:
            if not isinstance(json.loads(text), dict):
                raise ValueError
        except (ValueError, RecursionError):
            stats["settings_json"] += 1
            continue
        stats["settings_files"] += 1
        line, counted = 1, 0
        for start, named, value in _settings_strings(text):
            line, counted = line + text.count("\n", counted, start), start
            yield SentItem(
                SETTINGS_SOURCE, "", project, path.name, None, role, f"{named}: {value}" if named else value, f"{path}:{line}"
            )
