"""MCP server: masked read and search of files under allowed roots. The model never gets a restore tool."""

import hashlib
import os
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import __version__
from .config import ProjectConfig, to_detect_config
from .journal import Journal, JournalEntry
from .mask import BOXED_KINDS, MARKER_RE, dictionary_kinds, mask_path, mask_text, restore
from .platform import refuse_on_windows, sandboxed
from .vault import Vault
from .workspace import MAX_BYTES, SKIP_DIRS

INSTRUCTIONS = (
    "boxed.si gives masked read access to files outside the workspace, such as logs. Values like [EMAIL_1] "
    "are placeholders for real data that stays on the user's computer: keep them exactly as they are."
)
NOT_YET = "not available inside boxed run yet"  # the words the agent gets; fixed, they name no path


@dataclass
class ServerContext:
    home: Path
    config: ProjectConfig
    vault: Vault
    journal: Journal
    scope: str


def _roots(config: ProjectConfig) -> list[Path]:
    base = config.source.parent if config.source else Path.cwd()
    out = []
    for root in config.mcp_roots:
        p = Path(os.path.expanduser(root))
        out.append((p if p.is_absolute() else base / p).resolve())
    return out


def _allowed(path: str, ctx: ServerContext) -> Path:
    resolved = Path(os.path.expanduser(path)).resolve()
    for root in _roots(ctx.config):
        if resolved == root or resolved.is_relative_to(root):
            return resolved
    raise ValueError("path is not inside an allowed root (set mcp_roots in boxed.toml)")


def _load_text(path: Path) -> str:
    if not path.is_file():
        raise ValueError("not a file")
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("file is too large")
    data = path.read_bytes()
    if b"\0" in data[:8192]:
        raise ValueError("binary file")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError("file is not UTF-8") from e


def _journal(ctx: ServerContext, payload: str, coverage: str, note: str) -> None:
    kinds = BOXED_KINDS | dictionary_kinds(ctx.config)  # a file's own [GPIO_12] is text, not a marker
    counts = Counter(m.group(1) for m in MARKER_RE.finditer(payload) if m.group(1) in kinds)
    ctx.journal.append(
        JournalEntry(
            channel="mcp",
            provider="client",
            account_type="unknown",
            level=ctx.config.level,
            markers_by_kind=dict(counts),
            status="sent",
            payload_sha256=hashlib.sha256(payload.encode()).hexdigest(),
            coverage=coverage,
            scope=ctx.scope,
            versions={"boxed": __version__},
            note=note,
        )
    )


def _restore_path(path: str, ctx: ServerContext) -> str:
    """Search results show masked file names; reading one of them restores the name locally."""
    if not MARKER_RE.search(path):
        return path
    named = restore(path, ctx.vault.load_map(ctx.scope), dictionary_kinds(ctx.config))
    if named.unknown or named.suspicious:
        raise ValueError("unknown placeholder in the path")
    return named.text


def read_masked(path: str, *, ctx: ServerContext) -> str:
    text = _load_text(_allowed(_restore_path(path, ctx), ctx))
    with ctx.vault.transaction(ctx.scope) as markers:
        masked, _ = mask_text(text, markers, level=ctx.config.level, config=to_detect_config(ctx.config))
    _journal(ctx, masked, "file", "read_masked")
    return masked


def _walk(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        found += [Path(dirpath) / name for name in filenames]
    return sorted(found)


def search_masked(pattern: str, root: str, max_results: int = 200, *, ctx: ServerContext) -> str:
    """The pattern is matched against masked lines, so it cannot be used to probe hidden values."""
    base = _allowed(root, ctx)
    regex = re.compile(pattern)
    results: list[str] = []
    scanned = 0
    with ctx.vault.transaction(ctx.scope) as markers:
        scanned = _search(base, regex, max_results, markers, ctx, results)
    out = "\n".join(results) or "no matches"
    _journal(ctx, out, f"{scanned} files", "search_masked")
    return out


def _search(base: Path, regex: re.Pattern, max_results: int, markers, ctx: ServerContext, results: list[str]) -> int:
    scanned = 0
    for f in _walk(base):
        if f.is_symlink() or len(results) >= max_results:
            continue
        try:
            text = _load_text(f)
        except ValueError:
            continue
        scanned += 1
        masked, _ = mask_text(text, markers, level=ctx.config.level, config=to_detect_config(ctx.config))
        rel = f.relative_to(base).as_posix() if base.is_dir() else f.name
        shown = None  # the file name, masked on the first match
        for n, line in enumerate(masked.splitlines(), start=1):
            if regex.search(line):
                shown = shown or mask_path(rel, markers, level=ctx.config.level, config=to_detect_config(ctx.config))[0]
                results.append(f"{shown}:{n}: {line}")
                if len(results) >= max_results:
                    break
    return scanned


def _refuse_in_the_sandbox() -> None:
    """A call must save the placeholders it hands out in vault.db, and the profile of boxed run keeps the vault read-only. Without
    this the call ended in a PermissionError, which the server logs as a crash (about 50 KB of traceback on stderr) and tells the agent
    nothing about. A ToolError is a refusal: one line to the agent, nothing logged. A broker outside the sandbox is the planned fix."""
    if sandboxed():
        raise ToolError(NOT_YET)


def build_server(ctx: ServerContext) -> MCPServer:
    refuse_on_windows("mcp")
    server = MCPServer(name="boxed", instructions=INSTRUCTIONS, version=__version__)

    def read_masked_tool(path: str) -> str:
        _refuse_in_the_sandbox()
        return read_masked(path, ctx=ctx)

    def search_masked_tool(pattern: str, root: str, max_results: int = 200) -> str:
        _refuse_in_the_sandbox()
        return search_masked(pattern, root, max_results, ctx=ctx)

    server.add_tool(
        read_masked_tool,
        name="read_masked",
        description="Read a text file under an allowed root; secrets and personal data come back as placeholders.",
    )
    server.add_tool(
        search_masked_tool,
        name="search_masked",
        description="Regex search over masked lines of text files under an allowed root. Returns path:line: text.",
    )
    return server
