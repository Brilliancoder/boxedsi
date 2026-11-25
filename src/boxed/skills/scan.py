"""The scanner: joins the inventory (what is installed) and the rules (what looks malicious) into one verdict per item.

An item's files are read whole by `rules.check_file`, its links are judged by `rules.check_link`, and a config entry (an MCP server,
a hook, a setting) by `rules.check_entry`; the capabilities of everything are summed. A check that fails is a finding and never a pass.
Evidence is redacted here (`redact`) before it reaches a terminal, a report, the record or a prompt: the rules print what they matched,
and a hook command may carry a key. Nothing found is run, imported or followed."""

import os
import posixpath
import re
import stat
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath

from boxed import platform
from boxed.detect import DetectConfig, detect
from boxed.skills import rules
from boxed.skills.inventory import PLUGIN_PREFIX, Inventory, Item, Problem, is_agent_config, item_digest
from boxed.skills.record import VERDICTS, Record
from boxed.skills.rules import SEVERITIES, Finding

__all__ = ["VERDICTS", "ItemResult", "incomplete", "redact", "scan_inventory", "sort_results", "verdict_of", "with_links"]

_RANK = {s: i for i, s in enumerate(SEVERITIES)}
_VERDICT_RANK = {v: i for i, v in enumerate(VERDICTS)}
_ENTRY_KINDS = ("mcp", "hook", "setting")
_COMMON_HIDDEN = frozenset({".gitignore", ".gitattributes", ".gitkeep", ".DS_Store", ".editorconfig", ".npmignore", ".dockerignore"})
_WINDOWS_DRIVE = re.compile(r"[A-Za-z]:")
HIDDEN_MAX = 20  # hidden files reported for one item; the rest repeats what is shown
SKILL_MD_MAX = 4 * 1024 * 1024  # of SKILL.md, only to look for the names it mentions
HARMLESS_PROBLEMS = frozenset({"link to a missing target"})  # keeps nothing from being checked: such a link holds nothing
_LEFT_OUT = {  # the evidence of an `incomplete` finding, by the reason the inventory gives
    "too many files": "more files and links than one item may hold: the rest was not read",
    "too many scripts": "the command names more local scripts than are kept: the rest was not read",
    "unreadable": "this part of it could not be read",
    "behind a link": "the script it runs sits behind a link that leads out of what is checked, and no other item reads it",
}
VIEW_LABELS = re.compile(r"(?:\[(?:text in media|normalised|decoded base64(?: x\d+)?|decoded tags)\] )+")  # what rules put before evidence


@dataclass(frozen=True)
class ItemResult:
    item: Item
    digest: str
    verdict: str
    findings: tuple[Finding, ...]  # evidence already redacted; sorted by severity, then file, then line
    capabilities: frozenset[str]
    change: str  # "new" | "changed" | "same" against the record; "new" for targets


def verdict_of(findings: Iterable[Finding]) -> str:
    """Any critical finding is dangerous; any high or medium one is suspicious; else ok. Low and info alone are signs, not a verdict."""
    worst = max((_RANK[f.severity] for f in findings), default=-1)
    if worst >= _RANK["critical"]:
        return "dangerous"
    return "suspicious" if worst >= _RANK["medium"] else "ok"


def redact(text: str) -> str:
    """The text with every secret and personal datum (detector level 1, no name models) replaced by [KIND]. IP addresses stay: the
    address of an attacker's server is the evidence, not a datum of the person."""
    spans = sorted((d for d in detect(text, level=1, config=DetectConfig(ner=[]), ner=[]) if d.kind != "IP"), key=lambda d: d.start)
    out, pos = [], 0
    for d in spans:
        if d.start < pos:
            continue
        out += [text[pos:d.start], f"[{d.kind}]"]
        pos = d.end
    out.append(text[pos:])
    return "".join(out)


def _failed(rel: str) -> Finding:
    """What a check that crashed reports: the item is not clean because it could not be checked."""
    rule = next(r for r in rules.RULES if r.id == "unreadable")
    return Finding(rule.id, rule.severity, rule.title, rule.why, rule.advice, rel, 0, "the check of this file failed")


def _starred(evidence: str) -> str:
    """The evidence of a finding on the text of an agent config: its labels, then stars of the same length. A value may be spelled
    there in any form (escaped, decoded, normalised), so no part of the text shows (architecture: values from agent configs are never
    printed); the line of the finding says where to look, and the findings of its entries show the command with its values starred."""
    labels = VIEW_LABELS.match(evidence)
    keep = labels.end() if labels else 0
    return evidence[:keep] + "*" * (len(evidence) - keep)


def _incomplete(item: Item) -> list[Finding]:
    """What of an item was not read (a cap on files or scripts, a folder that cannot be read) is a finding of its own, high: an item
    that was not checked in full is never ok. Its place is the item's location, or the folder inside it."""
    return [Finding(*rules.INCOMPLETE, item.location if place == "." else place, 0, _LEFT_OUT.get(reason, reason)) for place, reason, _ in item.unchecked]


def incomplete(problems: Iterable[Problem]) -> bool:
    """Did a problem of the inventory keep something from being checked (a config that cannot be read or parsed, a folder that cannot
    be listed, a cap)? Every one does but a link to nowhere. Such a scan is never clean, whatever the verdicts."""
    return any(p.reason not in HARMLESS_PROBLEMS for p in problems)


def _rel(item: Item, path: Path) -> str:
    """The name of a file as shown: relative to the item's folder (the file's own name for a single-file item or a script of a config)."""
    for base in (item.root, item.root.parent):
        try:
            rel = path.relative_to(base).as_posix()
        except ValueError:
            continue
        if rel != ".":
            return rel
    return path.name


def _leaves(rel: str, target: str) -> bool:
    """Does a link at `rel` with this target text point out of the item? An absolute or home-relative target does; a relative one does
    when it climbs above the item's folder."""
    text = target.replace("\\", "/")
    if text.startswith(("/", "~")) or _WINDOWS_DRIVE.match(text):
        return True
    joined = posixpath.normpath(posixpath.join(posixpath.dirname(rel), text))
    return joined == ".." or joined.startswith("../")


def _skill_text(path: Path) -> str:
    try:
        fd = platform.open_nofollow(path, os.O_RDONLY)
    except OSError:
        return ""
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            return ""
        return f.read(SKILL_MD_MAX).decode("utf-8", "replace")


def _hidden_files(item: Item, rels: list[str]) -> list[Finding]:
    """Hidden files and folders in a skill that its SKILL.md never names (T13): the usual repository dotfiles are not news. One finding
    per hidden top-level name. Low on its own; the rules' combinations decide what is dangerous."""
    skill_md = item.root / "SKILL.md"
    if item.kind != "skill" or item.entry is not None or skill_md not in item.files:
        return []
    text = _skill_text(skill_md)
    rule = next(r for r in rules.RULES if r.id == "opaque-file")
    found: dict[str, None] = {}
    for rel in rels:
        parts = PurePosixPath(rel).parts
        hidden = next((i for i, p in enumerate(parts) if p.startswith(".")), None)
        if hidden is None:
            continue
        name = parts[hidden]
        if name in _COMMON_HIDDEN or name in text:
            continue
        found[PurePosixPath(*parts[: hidden + 1]).as_posix()] = None
    return [
        Finding(rule.id, "low", "Has a hidden file that SKILL.md never mentions",
                "A hidden file is easy to overlook and can carry code or instructions the skill does not admit to.",
                "Open it and check what it is for; remove it if nobody can say.", file, 0, "hidden file that SKILL.md does not name")
        for file in list(found)[:HIDDEN_MAX]
    ]


def _check_item(item: Item) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    caps: set[str] = set()
    rels = []
    for path in item.files:
        rel = _rel(item, path)
        rels.append(rel)
        try:
            report = rules.check_file(path, rel)
        except Exception:  # fail closed: a crash on hostile input must not read as clean
            findings.append(_failed(rel))
            continue
        found = report.findings
        if found and is_agent_config(path):  # the text of an agent config or a plugin manifest: no value of it ever shows in the evidence
            found = tuple(replace(f, evidence=_starred(f.evidence)) for f in found)
        findings += found
        caps |= report.capabilities
    for rel, target in item.links:
        place = rel  # a link that a command of a project names sits at its full path: whether it leads out is judged from the project
        if item.project is not None and os.path.isabs(rel) and Path(rel).is_relative_to(item.project):
            place = Path(rel).relative_to(item.project).as_posix()
        try:
            report = rules.check_link(rel, target, leaves_item=_leaves(place, target))
        except Exception:
            findings.append(_failed(rel))
            continue
        findings += report.findings
        caps |= report.capabilities
    if item.entry is not None and item.kind in _ENTRY_KINDS:
        plugin = item.kind in ("mcp", "hook") and item.name.startswith(PLUGIN_PREFIX)  # what a plugin declares is judged strictly
        try:
            report = rules.check_entry(item.entry, agent=item.agent, kind=item.kind, scope="plugin" if plugin else item.scope, locator=item.location)
        except Exception:
            findings.append(_failed(item.location))
        else:
            findings += report.findings
            caps |= report.capabilities
    findings += _hidden_files(item, rels)
    findings += _incomplete(item)
    return findings, caps


def _folder_name(part: str) -> str:
    """A folder name as a file system that ignores case and Unicode normalisation compares it (APFS on a Mac; NTFS ignores case)."""
    return unicodedata.normalize("NFD", unicodedata.normalize("NFD", part).casefold())


def with_links(inventory: Inventory, folder: Path, links: Iterable[tuple[str, str]]) -> Inventory:
    """The inventory of an unpacked archive plus the links the archive held (fetch.Fetched.links; they are not on disk). Each goes to the
    deepest item whose folder holds its place, folder names compared as a file system that ignores case and normalisation compares
    them: an unpacker there puts `SK/keys` into the item folder `sk`. Its path is made relative to that folder, so whether it leaves
    the item is judged from the item's root. A link no item holds goes to the first item under its archive path, so a link is always
    judged by `rules.check_link` and never dropped."""
    base = Path(os.path.abspath(folder))
    tree: dict = {}  # the item folders as nested names; the key None holds the item whose root a folder is
    for item in inventory.items:
        if item.root.is_dir() and item.root.is_relative_to(base):
            node = tree
            for part in item.root.relative_to(base).parts:
                node = node.setdefault(_folder_name(part), {})
            node.setdefault(None, item)
    extra: dict[str, list[tuple[str, str]]] = {}
    for rel, target in links:
        parts = rel.split("/")
        node, holder, depth = tree, tree.get(None), 0
        for depth_here, part in enumerate(parts[:-1], 1):
            node = node.get(_folder_name(part))
            if node is None:
                break
            if None in node:
                holder, depth = node[None], depth_here
        if holder is not None:
            extra.setdefault(holder.id, []).append(("/".join(parts[depth:]), target))
        elif inventory.items:
            extra.setdefault(inventory.items[0].id, []).append((rel, target))
    items = tuple(replace(i, links=tuple(sorted((*i.links, *extra.get(i.id, ()))))) for i in inventory.items)
    return Inventory(items, inventory.problems)


def _sorted(findings: Iterable[Finding]) -> tuple[Finding, ...]:
    return tuple(sorted(findings, key=lambda f: (-_RANK[f.severity], f.file, f.line, f.rule)))


def sort_results(results: Iterable[ItemResult]) -> list[ItemResult]:
    """The dangerous first, then the suspicious, then the rest; by id within a verdict."""
    return sorted(results, key=lambda r: (_VERDICT_RANK[r.verdict], r.item.id))


def scan_inventory(inventory: Inventory, record: Record | None) -> list[ItemResult]:
    """One result per item, the dangerous first. `change` compares the item's digest with the record (None: everything is new)."""
    results = []
    for item in inventory.items:
        findings, caps = _check_item(item)
        clean = _sorted(replace(f, evidence=redact(f.evidence)) for f in findings)
        digest = item_digest(item)
        known = None if record is None else record.items.get(item.id)
        change = "new" if known is None else ("same" if known.digest == digest else "changed")
        results.append(ItemResult(item, digest, verdict_of(clean), clean, frozenset(caps), change))
    return sort_results(results)
