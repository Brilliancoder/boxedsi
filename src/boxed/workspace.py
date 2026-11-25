"""Masked mirror of a project for AI agents, and restore-on-sync of their edits back into the original."""

import difflib
import errno
import hashlib
import json
import os
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from collections import Counter
from contextlib import ExitStack
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .config import ProjectConfig, to_detect_config
from .errors import UserError
from .journal import Journal, JournalEntry
from .mask import RestoreResult, dictionary_kinds, mask_path, mask_text, restore
from .platform import LockTimeout, refuse_on_windows
from .vault import Vault

MARKER_FILE = ".boxed-workspace"
AGENT_SETTINGS = ".claude/settings.local.json"
RESERVED = frozenset({MARKER_FILE, AGENT_SETTINGS})
# BOXED_HOME parts an agent must never read; the mirror itself lives in BOXED_HOME/workspaces
SENSITIVE_HOME_PARTS = ("vault.db", "journal.jsonl", "state", "insecure-keys", "reports", "hook-errors.log", "bin", "observed.jsonl", "checks.json", "host-errors.log", "skills")
GUARDED_TOOLS_MATCHER = "Read|Write|Edit|MultiEdit|NotebookEdit|Grep|Glob|Bash|Monitor"
MAX_BYTES = 5 * 1024 * 1024
SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "__pycache__"})


@dataclass
class Workspace:
    id: str
    original: Path
    mirror: Path
    scope: str
    level: int
    created_at: str


@dataclass
class CreateReport:
    workspace: Workspace
    copied: int
    skipped: list[tuple[str, str]]
    markers_by_kind: dict[str, int]


@dataclass
class SyncReport:
    written: list[str] = field(default_factory=list)
    created: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    refused: list[tuple[str, RestoreResult]] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)  # deleted in the mirror, kept because delete was off
    diffs: dict[str, str] = field(default_factory=dict)  # original path -> unified diff, when asked
    unmatched: list[str] = field(default_factory=list)  # --only paths that are neither in the mirror nor in the state
    failed: list[tuple[str, str]] = field(default_factory=list)  # original path, what the file system said: no change was made
    unreadable: list[str] = field(default_factory=list)  # mirror folders boxed cannot look into: nothing in them was synced


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _state_path(home: Path, ws_id: str) -> Path:
    return home / "state" / f"{ws_id}.json"


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    path.write_text(text)
    os.chmod(path, 0o600)


def _read_state(home: Path, ws_id: str) -> dict:
    path = _state_path(home, ws_id)
    if not path.is_file():
        raise UserError("unknown workspace: boxed workspace list shows them")
    return json.loads(path.read_text())


def _workspace(state: dict) -> Workspace:
    return Workspace(
        id=state["id"],
        original=Path(state["original"]),
        mirror=Path(state["mirror"]),
        scope=state["scope"],
        level=state["level"],
        created_at=state["created_at"],
    )


def _in_skipped_dir(rel: str) -> bool:
    """Whether a "/" path has a SKIP_DIRS folder on the way, as the walks prune them. The file's own name does not count."""
    return any(part in SKIP_DIRS for part in rel.split("/")[:-1])


def _link_on_the_way(root: Path, rel: str) -> bool:
    """Whether a folder between root and the file named by a "/" path is a link: the path then leads to some other file."""
    folder = root
    for part in rel.split("/")[:-1]:
        folder = folder / part
        if os.path.islink(folder):  # False when the folder cannot be looked at: the callers do not take that as a go-ahead
            return True
    return False


def _why(error: OSError) -> str:
    """What the file system said, without the path it said it about."""
    return error.strerror or type(error).__name__


DENIED = os.strerror(errno.EACCES)  # what the file system says to a change the rights do not allow, and what a dry run foresees


def _may_write(dest: Path) -> bool:
    """What the rights say about writing dest, as a dry run can see them: a file that exists must be writable itself, a new file
    needs the nearest folder that exists to take a new name."""
    if os.path.lexists(dest):
        return os.access(dest, os.W_OK)
    folder = dest.parent
    while not os.path.lexists(folder):
        folder = folder.parent
    return os.access(folder, os.W_OK | os.X_OK)


def _may_delete(dest: Path) -> bool:
    return os.access(dest.parent, os.W_OK | os.X_OK)


def _non_folder_on_the_way(root: Path, rel: str) -> bool:
    """Whether a file, or any name that is no folder, lies where a folder of the "/" path must be: the file cannot be put there."""
    folder = root
    for part in rel.split("/")[:-1]:
        folder = folder / part
        if os.path.lexists(folder) and not os.path.isdir(folder):
            return True
    return False


def _gone_from(mirror: Path, rel: str) -> bool:
    """Whether a file of the list is gone from the mirror: the file system says nothing is at its path (not found, or a parent that
    is no folder) and no folder on the way is a link. Any other answer (permission denied, a loop of links, a link that leads
    where boxed did not copy) is no proof that the file is gone."""
    if _link_on_the_way(mirror, rel):
        return False
    try:
        os.lstat(mirror / rel)
    except (FileNotFoundError, NotADirectoryError):
        return True
    except OSError:
        return False
    return False


def _original_files(root: Path) -> list[str]:
    if (root / ".git").exists():
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-co", "--exclude-standard", "-z"], capture_output=True, check=True
        ).stdout
        # git lists tracked files under node_modules or .venv too, but the mirror walk of sync never looks there
        return sorted({p for p in out.decode("utf-8", "surrogateescape").split("\0") if p and not _in_skipped_dir(p)})
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        found += [(Path(dirpath) / name).relative_to(root).as_posix() for name in filenames]
    return sorted(found)


def _mirror_entries(mirror: Path, unreadable: list[str]) -> list[str]:
    """Every file in the mirror outside tool folders (.git, .venv...), plus symlinked directories (refused, never followed).
    A folder boxed cannot look into has its path put in unreadable: os.walk alone skips it without a word."""
    found = []

    def unseen(error: OSError) -> None:
        if not isinstance(error, (FileNotFoundError, NotADirectoryError)):  # a folder that went away on the way is not unreadable
            unreadable.append(Path(error.filename).relative_to(mirror).as_posix())

    for dirpath, dirnames, filenames in os.walk(mirror, onerror=unseen):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        found += [(Path(dirpath) / d).relative_to(mirror).as_posix() for d in dirnames if (Path(dirpath) / d).is_symlink()]
        found += [(Path(dirpath) / name).relative_to(mirror).as_posix() for name in filenames]
    return sorted(rel for rel in found if rel not in RESERVED)


def boxed_command() -> str:
    """The command of the hooks. Without boxed on the PATH it is Python with -I: a hook runs in the copy, and Python puts the folder it
    runs in at the head of its path, so two files of the agent in the copy (boxed/__init__.py, boxed/cli.py) would take the place of
    boxed and every hook would exit 0. Isolated mode leaves that folder, PYTHONPATH and the user's site folder out of the path."""
    exe = shutil.which("boxed")
    return shlex.quote(exe) if exe else f"{shlex.quote(sys.executable)} -I -m boxed.cli"


def write_agent_settings(ws: Workspace, home: Path) -> None:
    """Claude Code rules for the mirror: no reads of the original or of boxed data, hooks on every guarded tool."""
    h = home.resolve()
    original = str(ws.original)
    sensitive = [h / part for part in SENSITIVE_HOME_PARTS]
    rule_paths = [f"/{original}/**"] + [f"/{p}/**" if p.suffix == "" else f"/{p}" for p in sensitive]
    # Edit(path) covers every file write in Claude Code; Write(path) rules are ignored with a warning
    deny = [f"{verb}({path})" for path in rule_paths for verb in ("Read", "Edit")]
    cmd = boxed_command()

    def hook(event: str, guard: bool = True) -> list[dict]:
        # a guard hook that cannot start or times out blocks the call (Claude Code 2.1.295+)
        return [{"type": "command", "command": f"{cmd} hook {event}", **({"onFailure": "block"} if guard else {})}]

    settings = {
        "permissions": {"deny": deny, "blockReadsOutsideWorkingDirectories": True},
        "sandbox": {"enabled": True, "filesystem": {"denyRead": [original, *map(str, sensitive)]}},
        "hooks": {
            "SessionStart": [{"hooks": hook("session-start", guard=False)}],
            "UserPromptSubmit": [{"hooks": hook("user-prompt-submit")}],
            "PreToolUse": [{"matcher": GUARDED_TOOLS_MATCHER, "hooks": hook("pre-tool-use")}],
        },
    }
    path = ws.mirror / AGENT_SETTINGS
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2))


def _git_ignored(root: Path, rels: list[str]) -> set[str]:
    if not rels or not (root / ".git").exists():
        return set()
    out = subprocess.run(
        ["git", "-C", str(root), "check-ignore", "--stdin", "-z"], input="\0".join(rels).encode(), capture_output=True
    ).stdout
    return {p for p in out.decode("utf-8", "surrogateescape").split("\0") if p}


def _config_snapshot(config: ProjectConfig) -> dict:
    data = asdict(config)
    data["source"] = str(config.source) if config.source else None
    return data


def load_workspace_config(ws_id: str, home: Path) -> ProjectConfig:
    """The project config as it was when the mirror was made: hooks under the sandbox cannot read the original."""
    data = dict(_read_state(home, ws_id).get("config") or {})
    source = data.pop("source", None)
    return ProjectConfig(**data, source=Path(source) if source else None)


def project_folder(path: Path) -> Path:
    """The folder a workspace is made from, resolved. A path that does not exist or is a file is refused, before anything is written."""
    folder = path.resolve()
    if not folder.exists():
        raise UserError("the project folder does not exist")
    if not folder.is_dir():
        raise UserError("the project path is not a folder")
    return folder


def create_workspace(
    original: Path, *, level: int, config: ProjectConfig, vault: Vault, journal: Journal, home: Path
) -> CreateReport:
    refuse_on_windows("workspace")
    original = project_folder(original)
    ws_id = secrets.token_hex(4)
    scope = f"ws-{ws_id}"
    (home / "workspaces").mkdir(parents=True, exist_ok=True)
    os.chmod(home / "workspaces", 0o700)
    mirror = home / "workspaces" / scope
    mirror.mkdir()
    markers = vault.load_map(scope)
    detect_config = to_detect_config(config)
    copied, skipped, totals, files = 0, [], Counter(), {}
    try:
        for rel in _original_files(original):
            src = original / rel
            if rel in RESERVED:
                skipped.append((rel, "reserved"))
            elif src.is_symlink():
                skipped.append((rel, "symlink"))
            elif not src.is_file():
                skipped.append((rel, "missing"))
            elif src.stat().st_size > MAX_BYTES:
                skipped.append((rel, "too-large"))
            else:
                data = src.read_bytes()
                if b"\0" in data[:8192]:
                    skipped.append((rel, "binary"))
                    continue
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    skipped.append((rel, "non-utf8"))
                    continue
                mrel, name_counts = mask_path(rel, markers, level=level, config=detect_config)
                dest = mirror / mrel
                if os.path.lexists(dest) or _non_folder_on_the_way(mirror, mrel):
                    # Two files meet in one name: a.txt and A.txt of a case-sensitive project on a volume that reads them alike. The
                    # second would overwrite the first while the state listed both, and --delete would later remove both originals.
                    skipped.append((rel, "name-taken"))
                    continue
                masked, counts = mask_text(text, markers, level=level, config=detect_config)
                out = masked.encode("utf-8")
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(out)
                os.chmod(dest, stat.S_IMODE(src.stat().st_mode))
                files[mrel] = {"orig_sha": vault.mac(data), "masked_sha": _sha(out)}
                totals.update(name_counts)
                totals.update(counts)
                copied += 1
        vault.save_map(scope, markers)
    except BaseException:
        shutil.rmtree(mirror, ignore_errors=True)  # a half-masked mirror must not be left for an agent
        raise
    created_at = _now()
    (mirror / MARKER_FILE).write_text(json.dumps({"id": ws_id, "created_at": created_at}))
    state = {
        "id": ws_id,
        "original": str(original),
        "mirror": str(mirror),
        "scope": scope,
        "level": level,
        "created_at": created_at,
        "config": _config_snapshot(config),
        "files": files,
    }
    _write_private(_state_path(home, ws_id), json.dumps(state, indent=1))
    write_agent_settings(_workspace(state), home)
    journal.append(
        JournalEntry(
            channel="workspace",
            provider="local",
            account_type="local",
            level=level,
            markers_by_kind=dict(totals),
            status="prepared",
            payload_sha256=_sha(json.dumps(files, sort_keys=True).encode()),
            coverage=f"{copied} files masked, {len(skipped)} skipped",
            scope=scope,
            versions={"boxed": __version__},
        )
    )
    return CreateReport(_workspace(state), copied, skipped, dict(totals))


# refusals that --force cannot lift
NOT_MARKER_PROBLEMS = ("symlink", "not utf-8", "outside the project")


def _refused(reason: str) -> RestoreResult:
    return RestoreResult(text="", restored=0, unknown=[], suspicious=[reason])


def _diff(old: str, new: str, path: str) -> str:
    """Line by line, so CRLF files and files without a final newline diff cleanly."""
    lines = difflib.unified_diff(old.splitlines(), new.splitlines(), f"a/{path}", f"b/{path}", lineterm="")
    return "".join(line + "\n" for line in lines)


def _check_mirror(ws: Workspace) -> None:
    """The folder at the mirror path must be the one create made, or every file would read as deleted in it: not missing, not a link
    to some other folder, and with the marker of this workspace in it (a folder made again empty has none)."""
    if not ws.mirror.is_dir():
        raise UserError("the mirror folder of the workspace is missing; nothing was synced")
    try:
        mine = not ws.mirror.is_symlink() and json.loads((ws.mirror / MARKER_FILE).read_text(encoding="utf-8"))["id"] == ws.id
    except (OSError, ValueError, KeyError, TypeError):
        mine = False
    if not mine:
        raise UserError(
            "the mirror folder of the workspace is not the folder boxed made, or boxed cannot read it (it must be a plain folder "
            f"with a {MARKER_FILE} that names the workspace); nothing was synced"
        )


def sync_back(
    ws_id: str,
    *,
    vault: Vault,
    journal: Journal,
    home: Path,
    force: bool = False,
    delete: bool = False,
    dry_run: bool = False,
    only: set[str] | None = None,
    diff: bool = False,
) -> SyncReport:
    """Puts the changes of the copy into the project (see _sync_back). A real run takes the lock of the journal first, and checks that
    a record can follow, before it reads the state, let alone writes an original; it keeps the lock to the record. A lock that another
    process holds for too long, or a journal that cannot take a record (a folder or a link in its place, no right to write it), stops
    it with nothing changed. A dry run writes nothing, so it needs neither."""
    with ExitStack() as stack:
        if not dry_run:
            try:
                stack.enter_context(journal.reserved())
            except LockTimeout:
                raise UserError("another boxed process holds the journal; nothing was synced: try again, or stop that process") from None
            except OSError:
                raise UserError("boxed cannot write its journal, so nothing was synced") from None
        return _sync_back(ws_id, vault=vault, journal=journal, home=home, force=force, delete=delete, dry_run=dry_run, only=only, diff=diff)


def _sync_back(
    ws_id: str,
    *,
    vault: Vault,
    journal: Journal,
    home: Path,
    force: bool = False,
    delete: bool = False,
    dry_run: bool = False,
    only: set[str] | None = None,
    diff: bool = False,
) -> SyncReport:
    """only: mirror paths to consider; every other entry is left alone and not reported.

    delete: removes the original of a file only when the state lists it as mirrored (a file that create copied or sync made, never
    one added to the project since), nothing is at its path in the mirror now, and the original is still as it was."""
    state = _read_state(home, ws_id)
    ws = _workspace(state)
    if ws.scope not in vault.scopes():
        raise UserError("the vault has no markers for the workspace; nothing was synced")
    _check_mirror(ws)
    markers = vault.load_map(ws.scope)
    kinds = dictionary_kinds(load_workspace_config(ws_id, home))
    # The list of mirrored files, by mirror path. An earlier version also listed tracked files under tool folders, which it
    # copied but no walk of the mirror sees: they are not mirrored files, and a sync without dry_run drops them from the state.
    files: dict[str, dict] = {rel: info for rel, info in state["files"].items() if not _in_skipped_dir(rel)}
    report = SyncReport()
    all_entries = _mirror_entries(ws.mirror, report.unreadable)
    report.unreadable.sort()
    if only is not None:
        only = {os.path.normpath(p) for p in only}  # ./a.txt and a.txt are the same file
        report.unmatched = sorted(only - set(all_entries) - set(files))
        report.unreadable = [u for u in report.unreadable if any(p == u or p.startswith(u + "/") for p in only)]
    entries = [rel for rel in all_entries if only is None or rel in only]
    names = {rel: restore(rel, markers, kinds) for rel in {*entries, *files}}  # mirror path -> original path
    ignored = _git_ignored(ws.original, [names[rel].text for rel in entries if rel not in files])
    try:  # whatever stops the loops, the state and the journal say what was done before it
        for rel in entries:
            name = names[rel]
            try:  # the file system may say no to one file; the others still get their turn
                if rel not in files and name.text in ignored:
                    continue
                mpath = ws.mirror / rel
                if mpath.is_symlink():
                    report.refused.append((rel, _refused("symlink")))
                    continue
                data = mpath.read_bytes()
                base = files.get(rel)
                if base and _sha(data) == base["masked_sha"]:
                    continue
                if (name.unknown or name.suspicious) and not force:
                    report.refused.append((rel, name))
                    continue
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    report.refused.append((rel, _refused("not utf-8")))
                    continue
                result = restore(text, markers, kinds)
                if (result.unknown or result.suspicious) and not force:
                    report.refused.append((rel, result))
                    continue
                dest = ws.original / name.text
                if not dest.parent.resolve().is_relative_to(ws.original):
                    report.refused.append((rel, _refused("outside the project")))
                    continue
                if _link_on_the_way(ws.original, name.text):  # a link names some other file than the one the mirror held
                    report.conflicts.append(name.text)
                    continue
                if base:
                    if dest.is_symlink() or not dest.is_file() or vault.mac(dest.read_bytes()) != base["orig_sha"]:
                        report.conflicts.append(name.text)
                        continue
                elif dest.exists() or dest.is_symlink() or _non_folder_on_the_way(ws.original, name.text):
                    report.conflicts.append(name.text)  # the name is taken, or a folder of the path is a file in the project
                    continue
                if not _may_write(dest):  # the real run would meet the same answer, so a dry run says it first
                    report.failed.append((name.text, DENIED))
                    continue
                shown = _diff(dest.read_bytes().decode("utf-8") if base else "", result.text, name.text) if diff else None
                if not dry_run:
                    restored = result.text.encode("utf-8")
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(restored)
                    files[rel] = {"orig_sha": vault.mac(restored), "masked_sha": _sha(data)}  # at once: the file is changed now
                    try:
                        os.chmod(dest, stat.S_IMODE(mpath.stat().st_mode))
                    except OSError:
                        pass  # the mode is best effort: a file the person may write but does not own keeps the mode it has
                (report.written if base else report.created).append(name.text)
                if shown is not None:
                    report.diffs[name.text] = shown
            except OSError as e:
                report.failed.append((name.text, _why(e)))
        # Deleted in the mirror: on the list, and gone by _gone_from. The path is asked for itself and not looked up in the walk: a
        # link, a folder, a folder boxed cannot read, or the same name in other letters on a file system that reads them alike
        # (readme.txt, README.txt) is no deletion.
        gone = [rel for rel in sorted(files) if (only is None or rel in only) and _gone_from(ws.mirror, rel)]
        for rel in gone:
            text = names[rel].text
            try:
                if not delete:
                    report.missing.append(text)
                    continue
                dest = ws.original / text
                if not dest.parent.resolve().is_relative_to(ws.original):
                    report.refused.append((rel, _refused("outside the project")))
                elif (  # a link on the way is some other file now, even when it has the same text
                    not _link_on_the_way(ws.original, text)
                    and dest.is_file()
                    and not dest.is_symlink()
                    and vault.mac(dest.read_bytes()) == files[rel]["orig_sha"]
                ):
                    if not _may_delete(dest):
                        report.failed.append((text, DENIED))
                        continue
                    shown = _diff(dest.read_bytes().decode("utf-8"), "", text) if diff else None
                    if not dry_run:
                        dest.unlink()
                        del files[rel]
                    report.deleted.append(text)
                    if shown is not None:
                        report.diffs[text] = shown
                else:
                    report.conflicts.append(text)
            except OSError as e:
                report.failed.append((text, _why(e)))
    finally:
        if not dry_run:
            state["files"] = files
            _write_private(_state_path(home, ws_id), json.dumps(state, indent=1))
            journal.append(
                JournalEntry(
                    channel="workspace",
                    provider="local",
                    account_type="local",
                    level=ws.level,
                    markers_by_kind={},
                    status="received",
                    payload_sha256=_sha(json.dumps(files, sort_keys=True).encode()),
                    coverage=f"written {len(report.written)}, created {len(report.created)}, deleted {len(report.deleted)}",
                    scope=ws.scope,
                    versions={"boxed": __version__},
                    note=f"conflicts {len(report.conflicts)}, refused {len(report.refused)}, failed {len(report.failed)}",
                )
            )
    return report


def load_workspace(ws_id: str, home: Path) -> Workspace:
    return _workspace(_read_state(home, ws_id))


def list_workspaces(home: Path) -> list[Workspace]:
    states = sorted((home / "state").glob("*.json")) if (home / "state").is_dir() else []
    return sorted((_workspace(json.loads(p.read_text())) for p in states), key=lambda w: w.created_at)


def cache_folder(ws_id: str) -> Path:
    """Where boxed run keeps the caches of the agent of this copy (the wheels of uv, say): ~/.cache is read-only for the agent, and this
    is in the temporary folder of the person, where the profile lets it write."""
    return Path(tempfile.gettempdir()) / f"boxed-cache-{ws_id}"


def drop_workspace(ws_id: str, *, vault: Vault, home: Path) -> None:
    ws = load_workspace(ws_id, home)
    if ws.mirror.resolve().parent != (home / "workspaces").resolve():
        raise UserError("refusing to delete the mirror folder of the workspace: it is not a boxed mirror")
    shutil.rmtree(ws.mirror, ignore_errors=True)
    shutil.rmtree(cache_folder(ws_id), ignore_errors=True)
    _state_path(home, ws_id).unlink()
    vault.delete_scope(ws.scope)
