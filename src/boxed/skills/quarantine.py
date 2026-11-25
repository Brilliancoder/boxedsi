"""Quarantine on the person's command: take one installed extension out of use so its agent no longer loads it, and put it back.

Only `boxed skills quarantine` and `boxed skills restore` call this module; neither the scan nor the session hook ever does
(docs/adr/0003-quarantine-only-on-command.md). Each kind of item has its own way out that can be undone (`method` in the record):

- `move`: a skill folder, an agent, command, output style or prompt file is renamed into `<boxed home>/skills/quarantine/<qid>/payload`
  (the same volume only: a rename never copies, so nothing exists twice or half);
- `enabled-plugins`: a Claude Code plugin gets `enabledPlugins["p@m"] = false` (user settings, or the project's settings.local.json;
  a user plugin that the current project switches on for itself is switched off there by a second quarantine);
- `codex-enabled`: a Codex plugin or MCP server gets `enabled = false` in its table of config.toml, a text edit checked with tomllib;
- `claude-mcp`: a Claude Code MCP server of user or local scope is removed with `claude mcp remove` (its name is the only word of the
  entry on that command line) and put back by boxed itself, written into ~/.claude.json at its key like a json-entry, so its values
  never stand in the arguments of a process;
- `mcpjson-disabled`: a server of a project's .mcp.json is named in `disabledMcpjsonServers` of the project's .claude/settings.local.json;
- `json-entry`: a hook, a setting, or an MCP server of Claude Desktop, Cursor or Gemini is cut from its JSON file and saved;
- `toml-entry`: a Codex setting (`notify`, a `[model_providers.x]` table) is cut from config.toml as text and saved.

Nothing of the person's is deleted: a folder or file is moved, an entry is cut and saved first. Every saved thing sits in a 0700 folder
per quarantine id, in `entry.json` (0600) and, for an edited file, `original` (its bytes before the edit). A config file is rewritten
through a private part file, fsync and platform.replace_file, under one lock of boxed, and only after the file is read again and found
unchanged. A restore of a file nobody touched since writes `original` back, so it is the same byte for byte; a file that changed since
gets the entry back at its key, checked by parsing. A file that does not parse, that changed under the edit, a link where the file
should be, a file with a second name (a hard link, which a rename would split), or `claude` missing from PATH for a quarantine that
needs it is a refusal that changes nothing. Values from configs never reach the record, the journal or the arguments of a process:
they stay in entry.json."""

import copy
import errno
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from boxed import platform
from boxed.errors import UserError
from boxed.journal import Journal, JournalEntry
from boxed.locks import file_lock
from boxed.skills._shared import no_repeated_keys
from boxed.skills.inventory import KINDS, PLUGIN_PREFIX, Item
from boxed.skills.record import FOLDER, load_record, update_record

QUARANTINE = "quarantine"  # <boxed home>/skills/quarantine/<qid>/
ENTRY_FILE = "entry.json"
ORIGINAL_FILE = "original"
PAYLOAD = "payload"
NEW_FILE_LAYOUT = '{\n  "key": 0\n}\n'  # the indent and last newline of a settings file the quarantine makes
CLAUDE_TIMEOUT = 60  # seconds one `claude mcp` call may take
METHODS = ("move", "enabled-plugins", "codex-enabled", "claude-mcp", "mcpjson-disabled", "json-entry", "toml-entry")
FILE_KINDS = ("skill", "agent", "command", "output-style", "prompt")
SWITCHES = ("enabled-plugins", "codex-enabled", "mcpjson-disabled")  # methods that turn an item off rather than take it away

ALREADY = "this item is already in quarantine: run boxed skills list to see its quarantine id"
SWITCHED_OFF = "this item is already switched off: nothing to do"
FROM_PLUGIN = "this comes from a plugin: quarantine the plugin that declares it"
FROM_FILE = "this hook is declared in a skill, agent or command file: quarantine that file instead"
UNSUPPORTED = "this item cannot be taken out of use automatically: edit its config file by hand"
CHANGED = "the config file changed since it was read: run boxed skills list, then the command again"
GONE = "the item is no longer where it was found: run boxed skills list, then the command again"
NOT_PARSED = "the config file of this item does not parse: fix it by hand, then run the command again"
NOT_EDITABLE = "the config file of this item cannot be edited safely here: take the entry out by hand"
LINKED = "the config file of this item is a link: edit the file it points to by hand"
HARD_LINKED = "the config file of this item has another name on disk (a hard link): edit it by hand"
NOT_A_FILE = "the config file of this item is not a plain file: edit it by hand"
NO_CLAUDE = "claude is not on PATH: put it on PATH, or run claude mcp remove and claude mcp add-json by hand"
CLAUDE_FAILED = "claude mcp remove failed: run it by hand to see why; nothing was changed by boxed"
OTHER_VOLUME = "the item is on another volume than the boxed folder: move it aside by hand"
TAKEN_ANYWAY = "the step reported a failure or was stopped, but the item is no longer as it was: it is kept in quarantine, see boxed skills list"
STILL_ON = "the settings of this project still switch it on here: run the same command again to switch it off in this project too"
NOTHING ="nothing in quarantine matches: run boxed skills list to see the quarantine ids"
SEVERAL = "several quarantined items match: run boxed skills list and give one quarantine id"
TAKEN = "the original place is taken again: move what is there aside, then run boxed skills restore again"
MOVED_ON = "the config file changed too much since the quarantine: the saved entry stays in the quarantine folder; put it back by hand"
DAMAGED = "the quarantine folder of this item is missing or damaged: look into the quarantine folder of boxed"
NOT_PRIVATE = "a folder of boxed is not a plain private folder: move it aside"
UNDONE = "the record of boxed could not be saved, so the quarantine was undone: nothing was changed; once the disk has room, run the command again"
NOT_RECORDED = "the record of boxed could not be saved and the quarantine could not be undone: keep its quarantine id; boxed skills list shows it as not in the record"


# ---- small helpers ----


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canon(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _private_dir(path: Path) -> None:
    """A folder of the boxed home, made 0700; a link or a file planted at its name is refused, never followed."""
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode):
        raise UserError(NOT_PRIVATE)


def _write_private(path: Path, data: bytes) -> None:
    """A new file only its owner can read (O_EXCL: a name that is taken is an error, a link is never followed), flushed to the disk."""
    fd = platform.open_nofollow(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def _read_file(path: Path) -> bytes | None:
    """The bytes of a config file, or None when it is not there. A link is refused: replacing it would put a file where the person
    keeps a link (dotfiles), and the edit belongs to the file it points to. A hard link (a second name of the same file) is refused
    too: the rename that replaces the file would leave the other name holding the old content, and the two names apart for good."""
    try:
        fd = platform.open_nofollow(path, os.O_RDONLY)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise UserError(LINKED) from None
        raise
    with os.fdopen(fd, "rb") as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise UserError(NOT_A_FILE)
        if info.st_nlink > 1:
            raise UserError(HARD_LINKED)
        return f.read()


def _replace(path: Path, before: bytes | None, after: bytes | None) -> None:
    """Writes `after` at `path` (None: takes away a file boxed itself made) if the file still holds `before`; else CHANGED and nothing
    is written. A part file next to it, flushed and renamed into place, keeps the mode of the old file: a crash leaves either file whole."""
    if _read_file(path) != before:
        raise UserError(CHANGED)
    if after is None:
        path.unlink()
        return
    mode = stat.S_IMODE(os.lstat(path).st_mode) if before is not None else 0o600
    part = path.with_name(f".{path.name}.boxed-part-{secrets.token_hex(4)}")
    fd = platform.open_nofollow(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(after)
            f.flush()
            os.fsync(f.fileno())
        if not platform.IS_WINDOWS:
            os.chmod(part, mode)
        platform.replace_file(part, path)
    except BaseException:
        part.unlink(missing_ok=True)
        raise


def _json_of(raw: bytes, name: str) -> tuple[dict, str, str]:
    """(the object, the BOM if any, the text) of a strict JSON file: one object, no key twice."""
    try:
        text = raw.decode("utf-8")
        bom = "﻿" if text.startswith("﻿") else ""
        data = json.loads(text[len(bom):], object_pairs_hook=no_repeated_keys)
    except (ValueError, RecursionError):
        raise UserError(NOT_PARSED) from None
    if type(data) is not dict:
        raise UserError(NOT_PARSED)
    return data, bom, text


def _json_bytes(data: dict, bom: str, like: str) -> bytes:
    """The object in the layout of the file it came from: its indent and its last newline."""
    found = re.search(r"\n([ \t]+)\S", like)
    indent = None if found is None else ("\t" if found.group(1).startswith("\t") else len(found.group(1)))
    text = json.dumps(data, indent=indent, ensure_ascii=False)
    return (bom + text + ("\n" if like.endswith("\n") else "")).encode("utf-8")


def _toml_of(raw: bytes, name: str) -> tuple[dict, str]:
    try:
        text = raw.decode("utf-8")
        return tomllib.loads(text), text
    except (ValueError, RecursionError):
        raise UserError(NOT_PARSED) from None


def _step(node, key: str):
    if isinstance(node, dict) and key in node:
        return node[key]
    if isinstance(node, list) and key.isdigit() and int(key) < len(node):
        return node[int(key)]
    raise KeyError(key)


def _at(data, path) -> object:
    for key in path:
        data = _step(data, key)
    return data


def _has(data, path) -> bool:
    try:
        _at(data, path)
    except KeyError:
        return False
    return True


def _set(data: dict, path, value) -> None:
    for key in path[:-1]:
        data = data.setdefault(key, {})
    data[path[-1]] = value


def _drop(data: dict, path) -> None:
    del _at(data, path[:-1])[path[-1]]  # type: ignore[index]


# ---- TOML as text ----


def _header(line: str) -> tuple[tuple[str, ...], bool] | None:
    """(key path, is an array of tables) when the line is a table header, read by tomllib itself so quoting and spaces are its own."""
    text = line.strip()
    if not text.startswith("["):
        return None
    try:
        node = tomllib.loads(text)
    except (ValueError, RecursionError):
        return None
    path = []
    while isinstance(node, dict) and len(node) == 1:
        key = next(iter(node))
        path.append(key)
        node = node[key]
    if node == {}:
        return tuple(path), False
    if isinstance(node, list) and node == [{}]:
        return tuple(path), True
    return None


def _headers(lines: list[str]) -> list[tuple[int, tuple[str, ...], bool]]:
    found = []
    for i, line in enumerate(lines):
        head = _header(line)
        if head is not None:
            found.append((i, *head))
    return found


def _section(lines: list[str], table: tuple[str, ...]) -> tuple[int, int] | None:
    """(first line after the header, end) of a [table]; the top level for (); None when no header names it."""
    heads = _headers(lines)
    if not table:
        return 0, heads[0][0] if heads else len(lines)
    for n, (i, path, array) in enumerate(heads):
        if path == table and not array:
            return i + 1, heads[n + 1][0] if n + 1 < len(heads) else len(lines)
    return None


def _statement(lines: list[str], start: int, end: int, key: str) -> tuple[int, int] | None:
    """The lines [i, j) of the statement that sets `key` inside start..end: the shortest run of lines tomllib reads alone as that key."""
    i = start
    while i < end:
        line = lines[i].strip()
        if not line or line.startswith("#"):
            i += 1
            continue
        for j in range(i + 1, min(end, i + 500) + 1):
            try:
                parsed = tomllib.loads("".join(lines[i:j]))
            except (ValueError, RecursionError):
                continue
            if list(parsed) == [key]:
                return i, j
            i = j - 1
            break
        i += 1
    return None


def _toml_key(key: str) -> str:
    return key if re.fullmatch(r"[A-Za-z0-9_-]+", key) else json.dumps(key)


def _with_newline(lines: list[str]) -> list[str]:
    if lines and not lines[-1].endswith("\n"):
        lines = [*lines[:-1], lines[-1] + "\n"]
    return lines


# ---- what is done and undone ----


@dataclass
class _Plan:
    """What a quarantine will do: the record's `data`, the value kept in entry.json, the old bytes of an edited file, and the change."""

    data: dict
    value: object
    original: bytes | None
    apply: Callable[[], None]
    how: str
    # After `apply` failed or was stopped: could the item be out of its place? Only a "no" seen on disk lets the saved copy go.
    taken: Callable[[], bool]
    note: str | None = None  # a line said after it worked


def _method(item: Item) -> str:
    if item.scope == "target" or item.kind not in KINDS:
        raise UserError(UNSUPPORTED)
    if item.kind in ("mcp", "hook") and item.name.startswith(PLUGIN_PREFIX):
        raise UserError(FROM_PLUGIN)
    if item.kind in FILE_KINDS:
        return "move"
    if item.kind == "plugin":
        if item.agent == "claude":
            return "enabled-plugins"
        if item.agent == "codex":
            return "codex-enabled"
        raise UserError(UNSUPPORTED)
    cfg = item.config_path
    if cfg is None or not item.config_key:
        raise UserError(UNSUPPORTED)
    if item.kind == "hook" and cfg.suffix != ".json":
        raise UserError(FROM_FILE)
    if item.kind == "mcp" and item.agent == "codex":
        return "codex-enabled"
    if item.kind == "mcp" and item.agent == "claude":
        if cfg.name == ".mcp.json" and item.project is not None:
            return "mcpjson-disabled"
        if cfg.name == ".claude.json":
            return "claude-mcp"
        raise UserError(UNSUPPORTED)
    if cfg.suffix == ".json":
        return "json-entry"
    if cfg.suffix == ".toml" and item.agent == "codex":
        return "toml-entry"
    raise UserError(UNSUPPORTED)


def _same_entry(item: Item, data: dict, value) -> bool:
    """Does the value found at the item's key now hold what the inventory read? An item listed before an edit must not cut another."""
    if item.entry is None:
        return True
    if item.kind == "hook":
        key = item.config_key
        found = dict(value) if isinstance(value, dict) else {}
        found["event"] = key[1]
        group = _at(data, key[:3]) if len(key) == 5 else None
        if isinstance(group, dict) and isinstance(group.get("matcher"), str) and group["matcher"]:
            found["matcher"] = group["matcher"]
        return _canon(found) == _canon(item.entry)
    expected = item.entry
    if item.kind == "setting":
        try:
            expected = _at(item.entry, item.config_key)
        except KeyError:
            return False
    return _canon(value) == _canon(expected)


def _plan_move(item: Item, qdir: Path) -> _Plan:
    source = Path(item.root)
    if not os.path.lexists(source):
        raise UserError(GONE)

    def apply() -> None:
        try:
            os.rename(source, qdir / PAYLOAD)
        except OSError as e:
            if e.errno == errno.EXDEV:
                raise UserError(OTHER_VOLUME) from None
            raise

    return _Plan({"path": os.fspath(source)}, None, None, apply, "moved to the quarantine folder of boxed",
                 lambda: os.path.lexists(qdir / PAYLOAD) or not os.path.lexists(source))


def _edit_plan(path: Path, before: bytes | None, after: bytes, data: dict, value, how: str) -> _Plan:
    data = {"file": os.fspath(path), **data, "created": before is None, "before_sha256": _sha(before or b""), "after_sha256": _sha(after)}
    return _Plan(data, value, before, lambda: _replace(path, before, after), how, lambda: _read_file(path) == after)


def _flag(path: Path, pid: str):
    """What enabledPlugins of a settings file says about a plugin, or None."""
    raw = _read_file(path)
    flags = _json_of(raw, path.name)[0].get("enabledPlugins") if raw is not None else None
    return flags.get(pid) if isinstance(flags, dict) else None


def _plan_enabled_plugins(item: Item, qdir: Path) -> _Plan:
    """A user plugin is switched off in the person's settings first, for every folder; where the current project's own settings
    switch it on again (item.project, they win over the person's), a second quarantine switches it off in that project's
    settings.local.json, which wins over its settings.json. A plugin of one project is switched off there."""
    still_on = False
    if item.scope == "user":
        assert item.config_path is not None
        path = item.config_path.parent.parent / "settings.json"  # ~/.claude/plugins/installed_plugins.json -> ~/.claude/settings.json
        if item.project is not None:
            if _flag(path, item.name) is False:
                path = item.project / ".claude" / "settings.local.json"
            else:
                still_on = True
    elif item.project is not None:
        path = item.project / ".claude" / "settings.local.json"
    else:
        raise UserError(UNSUPPORTED)
    if not path.parent.is_dir():
        raise UserError(GONE)
    raw = _read_file(path)
    data, bom, text = _json_of(raw, path.name) if raw is not None else ({}, "", NEW_FILE_LAYOUT)
    made_key = "enabledPlugins" not in data
    flags = data.setdefault("enabledPlugins", {})
    if not isinstance(flags, dict):
        raise UserError(NOT_EDITABLE)
    pid = item.name
    if flags.get(pid) is False:
        raise UserError(SWITCHED_OFF)
    had, previous = pid in flags, flags.get(pid)
    flags[pid] = False
    plan = _edit_plan(path, raw, _json_bytes(data, bom, text), {"key": ["enabledPlugins", pid], "made_key": made_key},
                      {"had": had, "previous": previous}, "switched off in enabledPlugins of " + path.name)
    plan.note = STILL_ON if still_on else None
    return plan


def _plan_codex_enabled(item: Item, qdir: Path) -> _Plan:
    path = item.config_path
    assert path is not None
    raw = _read_file(path)
    if raw is None:
        raise UserError(GONE)
    parsed, text = _toml_of(raw, path.name)
    table = item.config_key
    try:
        current = _at(parsed, table)
    except KeyError:
        raise UserError(CHANGED) from None
    if not isinstance(current, dict) or not _same_entry(item, parsed, current):
        raise UserError(CHANGED)
    if current.get("enabled") is False:
        raise UserError(SWITCHED_OFF)
    lines = _with_newline(text.splitlines(keepends=True))
    where = _section(lines, table)
    if where is None:
        raise UserError(NOT_EDITABLE)
    found = _statement(lines, where[0], where[1], "enabled")
    if found is None:
        new, saved = [*lines[: where[0]], "enabled = false\n", *lines[where[0]:]], None
    else:
        new, saved = [*lines[: found[0]], "enabled = false\n", *lines[found[1]:]], "".join(lines[found[0]: found[1]])
    expected = copy.deepcopy(parsed)
    _at(expected, table)["enabled"] = False  # type: ignore[index]
    after = "".join(new)
    if _toml_of(after.encode("utf-8"), path.name)[0] != expected:
        raise UserError(NOT_EDITABLE)
    return _edit_plan(path, raw, after.encode("utf-8"), {"table": list(table)}, {"line": saved}, "switched off in " + path.name)


def _plan_mcpjson_disabled(item: Item, qdir: Path) -> _Plan:
    assert item.project is not None
    if item.enabled is False:
        raise UserError(SWITCHED_OFF)
    folder = item.project / ".claude"
    path = folder / "settings.local.json"
    raw = _read_file(path)
    data, bom, text = _json_of(raw, path.name) if raw is not None else ({}, "", NEW_FILE_LAYOUT)
    made_key = "disabledMcpjsonServers" not in data
    names = data.setdefault("disabledMcpjsonServers", [])
    name = item.config_key[-1]
    if not isinstance(names, list):
        raise UserError(NOT_EDITABLE)
    if name in names:
        raise UserError(SWITCHED_OFF)
    names.append(name)
    after = _json_bytes(data, bom, text)
    made_folder = not os.path.lexists(folder)
    plan = _edit_plan(path, raw, after, {"name": name, "made_key": made_key, "made_folder": made_folder}, None,
                      "named in disabledMcpjsonServers of the project's settings.local.json")
    if made_folder:
        inner = plan.apply

        def apply() -> None:
            folder.mkdir()
            try:
                inner()
            except BaseException:
                folder.rmdir()
                raise

        plan.apply = apply
    return plan


def _plan_json_entry(item: Item, qdir: Path) -> _Plan:
    path = item.config_path
    assert path is not None
    raw = _read_file(path)
    if raw is None:
        raise UserError(GONE)
    data, bom, text = _json_of(raw, path.name)
    key = item.config_key
    try:
        parent, value = _at(data, key[:-1]), _at(data, key)
    except KeyError:
        raise UserError(CHANGED) from None
    if not _same_entry(item, data, value):
        raise UserError(CHANGED)
    if isinstance(parent, dict):
        index = list(parent).index(key[-1])
        del parent[key[-1]]
    else:
        index = int(key[-1])
        del parent[index]  # type: ignore[union-attr]
    return _edit_plan(path, raw, _json_bytes(data, bom, text), {"key": list(key), "index": index}, value, "cut from " + path.name)


def _plan_toml_entry(item: Item, qdir: Path) -> _Plan:
    path = item.config_path
    assert path is not None
    raw = _read_file(path)
    if raw is None:
        raise UserError(GONE)
    parsed, text = _toml_of(raw, path.name)
    key = item.config_key
    try:
        value = _at(parsed, key)
    except KeyError:
        raise UserError(CHANGED) from None
    if not _same_entry(item, parsed, value):
        raise UserError(CHANGED)
    lines = _with_newline(text.splitlines(keepends=True))
    span, form = _table_span(lines, key), "table"
    if span is None:
        form = "key"
        where = _section(lines, key[:-1])
        span = _statement(lines, where[0], where[1], key[-1]) if where is not None else None
    if span is None:
        raise UserError(NOT_EDITABLE)
    after = "".join([*lines[: span[0]], *lines[span[1]:]])
    expected = copy.deepcopy(parsed)
    _drop(expected, key)
    pruned = copy.deepcopy(expected)  # a table that only held the cut one is gone with it when no header of its own names it
    for n in range(len(key) - 1, 0, -1):
        if _at(pruned, key[:n]) == {}:
            _drop(pruned, key[:n])
    if _toml_of(after.encode("utf-8"), path.name)[0] not in (expected, pruned):
        raise UserError(NOT_EDITABLE)
    return _edit_plan(path, raw, after.encode("utf-8"), {"key": list(key), "form": form}, {"text": "".join(lines[span[0]: span[1]])},
                      "cut from " + path.name)


def _table_span(lines: list[str], key: tuple[str, ...]) -> tuple[int, int] | None:
    """The lines of `[key]` and of the tables right under it (`[key.sub]`), up to the next other header."""
    heads = _headers(lines)
    for n, (i, path, array) in enumerate(heads):
        if path == key and not array:
            end = len(lines)
            for j, other, _ in heads[n + 1:]:
                if other[: len(key)] != key:
                    end = j
                    break
            return i, end
    return None


def _claude(item_args: list[str], cwd: str) -> None:
    claude = shutil.which("claude")
    if claude is None:
        raise UserError(NO_CLAUDE)
    try:
        done = subprocess.run([claude, "mcp", *item_args], cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True, timeout=CLAUDE_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        raise UserError(CLAUDE_FAILED) from None
    if done.returncode != 0:  # its output is not shown: it can echo the entry, secrets and all
        raise UserError(CLAUDE_FAILED)


def _claude_entry(path: Path, key: tuple[str, ...]):
    raw = _read_file(path)
    if raw is None:
        return None, False
    data = _json_of(raw, path.name)[0]
    return (_at(data, key), True) if _has(data, key) else (None, False)


def _plan_claude_mcp(item: Item, qdir: Path) -> _Plan:
    if shutil.which("claude") is None:
        raise UserError(NO_CLAUDE)
    path = item.config_path
    assert path is not None
    key = item.config_key
    value, there = _claude_entry(path, key)
    if not there:
        raise UserError(GONE)
    if not _same_entry(item, {}, value):
        raise UserError(CHANGED)
    scope = "user" if item.scope == "user" else "local"
    cwd = key[1] if scope == "local" else os.fspath(path.parent)
    name = key[-1]

    def apply() -> None:
        _claude(["remove", "--scope", scope, "--", name], cwd)
        if _claude_entry(path, key)[1]:
            raise UserError(CLAUDE_FAILED)

    def taken() -> bool:  # claude may have removed it and still failed, timed out or been stopped: only the entry seen in place is "no"
        now, there = _claude_entry(path, key)
        return not there or _canon(now) != _canon(value)

    data = {"config": os.fspath(path), "key": list(key), "name": name, "scope": scope, "cwd": cwd}
    return _Plan(data, value, None, apply, "removed with claude mcp remove", taken)


PLANS = {
    "move": _plan_move,
    "enabled-plugins": _plan_enabled_plugins,
    "codex-enabled": _plan_codex_enabled,
    "claude-mcp": _plan_claude_mcp,
    "mcpjson-disabled": _plan_mcpjson_disabled,
    "json-entry": _plan_json_entry,
    "toml-entry": _plan_toml_entry,
}


# ---- putting back ----


def _back_move(data: dict, value, original: bytes | None, qdir: Path) -> str:
    target, payload = Path(data["path"]), qdir / PAYLOAD
    if not os.path.lexists(payload):
        raise UserError(DAMAGED)
    if os.path.lexists(target):
        raise UserError(TAKEN)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.rename(payload, target)
    except OSError as e:
        if e.errno == errno.EXDEV:
            raise UserError(OTHER_VOLUME) from None
        raise
    return "moved back to its place"


def _back_file(data: dict, original: bytes | None, change: Callable[[bytes], bytes | None]) -> str:
    """Writes the old bytes back when the file still holds exactly what the quarantine wrote; else `change` puts the entry back into
    what is there now. Either way the file is read again just before it is replaced."""
    path = Path(data["file"])
    now = _read_file(path)
    if now is not None and _sha(now) == data["after_sha256"]:
        if data["created"]:
            _replace(path, now, None)
            return "put back as it was"
        if original is None or _sha(original) != data["before_sha256"]:
            raise UserError(DAMAGED)
        _replace(path, now, original)
        return "put back as it was"
    if now is None:
        raise UserError(MOVED_ON)
    _replace(path, now, change(now))
    return "put back into the file as it is now"


def _back_enabled_plugins(data: dict, value, original: bytes | None, qdir: Path) -> str:
    path = Path(data["file"])

    def change(now: bytes) -> bytes | None:
        obj, bom, text = _json_of(now, path.name)
        pid = data["key"][1]
        flags = obj.get("enabledPlugins")
        if not isinstance(flags, dict) or flags.get(pid) is not False:
            raise UserError(MOVED_ON)
        if value["had"]:
            flags[pid] = value["previous"]
        else:
            del flags[pid]
        if data["made_key"] and not flags:
            del obj["enabledPlugins"]
        return None if data["created"] and not obj else _json_bytes(obj, bom, text)

    return _back_file(data, original, change)


def _back_codex_enabled(data: dict, value, original: bytes | None, qdir: Path) -> str:
    path = Path(data["file"])
    table = tuple(data["table"])

    def change(now: bytes) -> bytes:
        parsed, text = _toml_of(now, path.name)
        lines = _with_newline(text.splitlines(keepends=True))
        where = _section(lines, table)
        found = _statement(lines, where[0], where[1], "enabled") if where is not None else None
        if found is None or not _has(parsed, (*table, "enabled")) or _at(parsed, (*table, "enabled")) is not False:
            raise UserError(MOVED_ON)
        line = value["line"]
        after = "".join([*lines[: found[0]], *([line] if line is not None else []), *lines[found[1]:]])
        expected = copy.deepcopy(parsed)
        if line is None:
            _drop(expected, (*table, "enabled"))
        else:
            _at(expected, table)["enabled"] = tomllib.loads(line)["enabled"]  # type: ignore[index]
        if _toml_of(after.encode("utf-8"), path.name)[0] != expected:
            raise UserError(MOVED_ON)
        return after.encode("utf-8")

    return _back_file(data, original, change)


def _back_mcpjson_disabled(data: dict, value, original: bytes | None, qdir: Path) -> str:
    path = Path(data["file"])

    def change(now: bytes) -> bytes | None:
        obj, bom, text = _json_of(now, path.name)
        names = obj.get("disabledMcpjsonServers")
        if not isinstance(names, list) or data["name"] not in names:
            raise UserError(MOVED_ON)
        names.remove(data["name"])
        if data["made_key"] and not names:
            del obj["disabledMcpjsonServers"]
        return None if data["created"] and not obj else _json_bytes(obj, bom, text)

    said = _back_file(data, original, change)
    if data["made_folder"] and not os.path.lexists(path):
        try:
            path.parent.rmdir()  # only the empty folder the quarantine made
        except OSError:
            pass
    return said


def _in_hook_group(key: tuple[str, ...]) -> bool:
    """A handler inside a group of hooks: ("hooks", <event>, <group>, "hooks", <handler>)."""
    return len(key) == 5 and key[0] == "hooks" and key[3] == "hooks" and key[2].isdigit() and key[4].isdigit()


def _same_group(now: dict, key: tuple[str, ...], original: bytes | None, name: str) -> bool:
    """Is the group at the hook's index still the group it was cut from: a group of the same event with the same matcher?"""
    if original is None:
        return False
    try:
        then, group = _at(_json_of(original, name)[0], key[:3]), _at(now, key[:3])
    except KeyError:
        return False
    return isinstance(group, dict) and isinstance(then, dict) and _canon(group.get("matcher")) == _canon(then.get("matcher"))


def _back_json_entry(data: dict, value, original: bytes | None, qdir: Path) -> str:
    path = Path(data["file"])
    key = tuple(data["key"])

    def change(now: bytes) -> bytes:
        obj, bom, text = _json_of(now, path.name)
        try:
            parent = _at(obj, key[:-1])
        except KeyError:
            raise UserError(MOVED_ON) from None
        if _in_hook_group(key) and not _same_group(obj, key, original, path.name):
            raise UserError(MOVED_ON)  # a group put before it or taken away: its index now names another group, with another matcher
        if isinstance(parent, dict):
            if key[-1] in parent:
                raise UserError(TAKEN)
            pairs = list(parent.items())
            pairs.insert(min(data["index"], len(pairs)), (key[-1], value))
            parent.clear()
            parent.update(pairs)
        elif isinstance(parent, list):
            parent.insert(min(data["index"], len(parent)), value)
        else:
            raise UserError(MOVED_ON)
        return _json_bytes(obj, bom, text)

    return _back_file(data, original, change)


def _back_toml_entry(data: dict, value, original: bytes | None, qdir: Path) -> str:
    path = Path(data["file"])
    key = tuple(data["key"])
    if original is None:
        raise UserError(DAMAGED)
    before = _toml_of(original, path.name)[0]

    def change(now: bytes) -> bytes:
        parsed, text = _toml_of(now, path.name)
        if _has(parsed, key):
            raise UserError(TAKEN)
        lines = _with_newline(text.splitlines(keepends=True))
        cut = value["text"] if value["text"].endswith("\n") else value["text"] + "\n"
        if data["form"] == "table":
            new = [*lines, *(["\n"] if lines and lines[-1].strip() else []), cut]
        else:
            where = _section(lines, key[:-1])
            if where is not None:
                new = [*lines[: where[0]], cut, *lines[where[0]:]] if key[:-1] else [*lines[: where[1]], cut, *lines[where[1]:]]
            else:
                head = "[" + ".".join(_toml_key(k) for k in key[:-1]) + "]\n"
                new = [*lines, "\n", head, cut]
        after = "".join(new)
        expected = copy.deepcopy(parsed)
        _set(expected, key, _at(before, key))
        if _toml_of(after.encode("utf-8"), path.name)[0] != expected:
            raise UserError(MOVED_ON)
        return after.encode("utf-8")

    return _back_file(data, original, change)


def _back_claude_mcp(data: dict, value, original: bytes | None, qdir: Path) -> str:
    """The saved entry goes back into .claude.json at its key, written by boxed like a json-entry (the file read strictly, checked
    unchanged just before a part file is renamed over it, its mode and layout kept). Not with `claude mcp add-json`: that would put
    the entry, env and header values included, on a command line that other processes of the computer can read while it runs."""
    path, key = Path(data["config"]), tuple(data["key"])
    now = _read_file(path)
    if now is None:
        raise UserError(MOVED_ON)
    obj, bom, text = _json_of(now, path.name)
    try:
        holder = _at(obj, key[:-2])  # the file itself for a user server, its project's entry for a local one
    except KeyError:
        raise UserError(MOVED_ON) from None
    servers = holder.setdefault(key[-2], {}) if isinstance(holder, dict) else None
    if not isinstance(servers, dict):
        raise UserError(MOVED_ON)
    if key[-1] in servers:
        if _canon(servers[key[-1]]) == _canon(value):
            return "already back in " + path.name  # put back before, and the record not told
        raise UserError(TAKEN)
    servers[key[-1]] = value
    _replace(path, now, _json_bytes(obj, bom, text))
    return "written back into " + path.name


BACKS = {
    "move": _back_move,
    "enabled-plugins": _back_enabled_plugins,
    "codex-enabled": _back_codex_enabled,
    "claude-mcp": _back_claude_mcp,
    "mcpjson-disabled": _back_mcpjson_disabled,
    "json-entry": _back_json_entry,
    "toml-entry": _back_toml_entry,
}


# ---- the two commands ----


def _base(home: Path) -> Path:
    _private_dir(home / FOLDER)
    base = home / FOLDER / QUARANTINE
    _private_dir(base)
    return base


def _journal(journal: Journal, item_id: str, note: str) -> None:
    """Kinds and a hash of the id, never a name, a path or a value."""
    journal.append(JournalEntry(
        channel="skills", provider="local", account_type="local", level=-1, markers_by_kind={}, status="prepared",
        payload_sha256=hashlib.sha256(item_id.encode("utf-8", "backslashreplace")).hexdigest(), coverage="full", scope="skills", note=note,
    ))


def _clear(qdir: Path) -> None:
    """Takes away what boxed itself wrote into a quarantine folder; anything else in it stays."""
    for name in (ENTRY_FILE, ORIGINAL_FILE):
        (qdir / name).unlink(missing_ok=True)
    try:
        qdir.rmdir()
    except OSError:
        pass


def quarantine_item(item: Item, *, home: Path, journal: Journal) -> list[str]:
    """Takes the item out of use in the way its kind allows, records it under a new quarantine id and journals it. Returns stdout lines.
    Only the command of the person calls this."""
    method = _method(item)
    base = _base(home)
    with file_lock(base):
        record = load_record(home)  # a damaged record stops it before anything is touched
        # An item handed in is installed: in quarantine it is only while it is switched off there. One that is back in use (a new
        # copy at its place, a switch turned on again) gets a quarantine of its own; the earlier one stays restorable.
        if item.enabled is False and any(q.get("item") == item.id for q in record.quarantined.values()):
            raise UserError(ALREADY)
        if item.enabled is False and method in SWITCHES:
            raise UserError(SWITCHED_OFF)
        qid = secrets.token_hex(4)
        while qid in record.quarantined or os.path.lexists(base / qid):
            qid = secrets.token_hex(4)
        plan = PLANS[method](item, base / qid)
        entry = {"item": item.id, "agent": item.agent, "kind": item.kind, "name": item.name, "method": method, "original": item.location,
                 "at": datetime.now(UTC).isoformat(), "data": plan.data}
        qdir = base / qid
        qdir.mkdir(mode=0o700)
        try:  # what is cut is saved before the file it is cut from changes
            _write_private(qdir / ENTRY_FILE, json.dumps({"qid": qid, "entry": entry, "value": plan.value}, ensure_ascii=True, default=str).encode())
            if plan.original is not None:
                _write_private(qdir / ORIGINAL_FILE, plan.original)
        except BaseException:
            _clear(qdir)
            raise
        lines = [f"quarantined {item.id}: {plan.how}", f"quarantine id {qid}: boxed skills restore {qid} puts it back"]
        try:
            plan.apply()
        except BaseException as failure:
            if not _maybe_taken(plan):
                _clear(qdir)  # the item is seen in its place, untouched: the saved copy is not the only one
                raise
            # it may be out of its place: the saved copy is kept and recorded, never dropped
            lines.append(_remember(home, journal, qid, entry, plan, qdir) or TAKEN_ANYWAY)
            if not isinstance(failure, Exception):  # stopped (Ctrl-C): the quarantine id is said before the stop goes on
                sys.stdout.write("".join(line + "\n" for line in lines))
                sys.stdout.flush()
                raise
            return lines
        said = _remember(home, journal, qid, entry, plan, qdir)
    return lines + [line for line in (said, plan.note) if line]


def _maybe_taken(plan: _Plan) -> bool:
    try:
        return plan.taken()
    except Exception:
        return True  # what cannot be looked at counts as taken: the saved copy stays


def _remember(home: Path, journal: Journal, qid: str, entry: dict, plan: _Plan, qdir: Path) -> str | None:
    """Records the quarantine and journals it. An item must not be out of use under an id that list and restore do not know: when the
    record cannot be saved (a full disk), the item is put back the way a restore would, and the command is a refusal that changed
    nothing. When even that fails, the folder stays and the line returned says so: restore finds the quarantine id by its entry.json."""
    try:
        update_record(home, lambda r: r.quarantined.__setitem__(qid, entry))
    except Exception:
        try:
            _put_back(entry, plan.value, plan.original, qdir)
        except Exception:
            return NOT_RECORDED
        _clear(qdir)
        raise UserError(UNDONE) from None
    _journal(journal, entry["item"], f"quarantine {entry['kind']}")
    return None


def _find(quarantined: dict[str, dict], query: str) -> list[str]:
    if query in quarantined:
        return [query]
    exact = [qid for qid, q in quarantined.items() if q.get("item") == query]
    if exact:
        return sorted(exact)
    return sorted(qid for qid, q in quarantined.items() if q.get("name") == query or str(q.get("item", "")).endswith(":" + query))


def _unrecorded(base: Path, query: str) -> list[str]:
    """A quarantine id the record lacks whose folder keeps its entry.json: a quarantine whose record could not be saved."""
    return [query] if re.fullmatch(r"[0-9a-f]{8}", query) and os.path.lexists(base / query / ENTRY_FILE) else []


def _entry_ok(entry) -> bool:
    """An entry a restore can act on. The record checks its own strictly; one read from an entry.json alone is checked here."""
    return (type(entry) is dict and entry.get("method") in METHODS and type(entry.get("data")) is dict
            and type(entry.get("item")) is str and type(entry.get("kind")) is str)


def _put_back(entry: dict, value, original: bytes | None, qdir: Path) -> str:
    try:
        return BACKS[entry["method"]](entry["data"], value, original, qdir)
    except (KeyError, TypeError):
        raise UserError(DAMAGED) from None


def _saved(qdir: Path, qid: str) -> tuple[dict, bytes | None]:
    try:
        raw = _read_file(qdir / ENTRY_FILE)
        saved = json.loads(raw.decode("utf-8")) if raw is not None else None
        original = _read_file(qdir / ORIGINAL_FILE)
    except (OSError, ValueError):
        raise UserError(DAMAGED) from None
    if not isinstance(saved, dict) or saved.get("qid") != qid or "value" not in saved:
        raise UserError(DAMAGED)
    return saved, original


def restore_item(query: str, *, home: Path, journal: Journal) -> list[str]:
    """Puts a quarantined item back (query: a quarantine id, an item id or a name), drops it from the record and journals it. A quarantine
    id the record lacks, because the record could not be saved after the item was taken, is found by the entry.json of its folder."""
    base = _base(home)
    with file_lock(base):
        record = load_record(home)
        found = _find(record.quarantined, query) or _unrecorded(base, query)
        if not found:
            raise UserError(NOTHING)
        if len(found) > 1:
            raise UserError(SEVERAL)
        qid = found[0]
        if not re.fullmatch(r"[0-9a-f]{8}", qid):
            raise UserError(DAMAGED)
        qdir = base / qid
        saved, original = _saved(qdir, qid)
        entry = record.quarantined.get(qid, saved.get("entry"))
        if not _entry_ok(entry) or _canon(saved.get("entry")) != _canon(entry):
            raise UserError(DAMAGED)
        how = _put_back(entry, saved["value"], original, qdir)
        if qid in record.quarantined:
            update_record(home, lambda r: r.quarantined.pop(qid, None))
        _clear(qdir)
        kind = entry["kind"] if entry["kind"] in KINDS else "item"
        _journal(journal, entry["item"], f"restore {kind}")
    return [f"restored {entry['item']}: {how}"]
