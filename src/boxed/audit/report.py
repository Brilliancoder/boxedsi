"""Aggregate detections over sent items and render reports that never contain the values themselves."""

import hashlib
import hmac
import html
import secrets
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date, datetime

from ..detect import KINDS_BY_LEVEL, detect
from ..detect.patterns import is_known_format
from .paths import show_locator, show_path
from .sources import SETTINGS_SOURCE, SentItem

SECRET_KINDS = KINDS_BY_LEVEL[0]
AUDIT_TITLE = "<title>boxed audit</title>"
# A known format is a match of a pattern or a checksum: it says nothing of whether the value is real, still valid, or reached
# the provider. A card number is no key to rotate.
KNOWN_NOTE = "A pattern or checksum match: boxed does not check that a value is real or still valid."
ROTATE_ADVICE = "In a saved local record of a session: if real, rotate the credential or call the card issuer."
SETTINGS_ADVICE = "Remove these from the settings file. No match in the session records checked for this report."
REVIEW_ADVICE = "Review these: they look like secrets, but no rule of a known key format matched them."
GIT_HINT = "A secret in a project's .claude settings file can reach git with the project: check its history."
INCOMPLETE = "not checked (the report is incomplete):"
NOTHING_IN_WHAT_WAS_READ = "nothing found in what was read"  # instead of "found: nothing" when something was not checked
_DISK_UNKNOWN = "disk type not known"
DISK_UNKNOWN_HINT = "disk type not known: nothing on it was read; report the type at github.com/boxedsi/boxedsi/issues"
# what was there and was not read, by why: the keys the readers count in their stats
UNREAD = {
    "settings files": (
        ("settings_big", "too big"),
        ("settings_json", "not JSON"),
        ("settings_access", "no access"),
        ("settings_not_local", "not on a local disk"),
        ("settings_disk_unknown", _DISK_UNKNOWN),
    ),
    "project folders": (("projects_not_local", "not on a local disk"), ("projects_disk_unknown", _DISK_UNKNOWN)),
    "transcript folders": (
        ("folders_unread", "no access"),
        ("folders_not_local", "not on a local disk"),
        ("folders_disk_unknown", _DISK_UNKNOWN),
    ),
    "transcripts": (
        ("transcripts_unread", "no access"),
        ("transcripts_not_local", "not on a local disk"),
        ("transcripts_disk_unknown", _DISK_UNKNOWN),
    ),
}
UNREAD_KEYS = tuple(key for rows in UNREAD.values() for key, _ in rows)


@dataclass
class SecretHit:
    kind: str
    locator: str
    hmac_prefix: str
    source: str
    project: str
    ts: datetime | None
    known: bool = False  # a key of a known format: a provider's prefix, a PEM block, a JWT (detect.patterns.is_known_format)
    role: str = ""
    digest: str = ""  # the whole keyed hash: what groups the hits of one value; only its prefix is shown


@dataclass
class AuditSummary:
    items: int = 0
    malformed: int = 0
    settings_files: int = 0
    by_kind: Counter = field(default_factory=Counter)
    by_source: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    by_role: Counter = field(default_factory=Counter)  # findings in transcripts by the role of the item
    by_project: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    by_day: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    secrets: list[SecretHit] = field(default_factory=list)
    projects: set[str] = field(default_factory=set)  # every project the items came from, found or not, in the period or not
    unread: Counter = field(default_factory=Counter)  # what was there and not checked, by why (UNREAD)

    @property
    def incomplete(self) -> bool:
        """Something that was there was not checked: the report lists it, and boxed audit exits with the code of an anomaly."""
        return any(self.unread.values())


def run_audit(
    items: Iterable[SentItem],
    level: int = 2,
    since: date | None = None,
    stats: Counter | None = None,
    key: bytes | None = None,
    summary: AuditSummary | None = None,
) -> AuditSummary:
    """Secrets are grouped by a keyed hash: a shared report must not let anyone test guesses. Settings files are what is on disk
    now, not a send of some day: `since` leaves them in, and they have no day. A project is named whatever the period: its
    settings are on disk today. A `summary` given goes on counting; give both passes the same `key`."""
    key = key or secrets.token_bytes(32)
    s = summary or AuditSummary()
    for item in items:
        settings = item.source == SETTINGS_SOURCE
        if not settings:
            s.projects.add(item.project)
        if since and not settings and (item.ts is None or item.ts.date() < since):
            continue
        if not settings:
            s.items += 1
        day = item.ts.date().isoformat() if item.ts else "unknown"
        for d in detect(item.text, level=level):
            s.by_kind[d.kind] += 1
            s.by_source[item.source][d.kind] += 1
            s.by_project[item.project][d.kind] += 1
            if not settings:
                s.by_day[day][d.kind] += 1
                s.by_role[item.role] += 1
            if d.kind in SECRET_KINDS:
                digest = hmac.new(key, d.text.encode(), hashlib.sha256).hexdigest()
                known = is_known_format(d.detector, d.text)
                s.secrets.append(
                    SecretHit(d.kind, item.locator, digest[:12], item.source, item.project, item.ts, known, item.role, digest)
                )
    if stats is not None:
        s.malformed = stats["malformed"]
        s.settings_files = stats["settings_files"]
        s.unread = Counter({k: stats[k] for k in UNREAD_KEYS if stats[k]})
    return s


@dataclass
class Unique:
    hit: SecretHit  # the first hit: where the secret is listed
    kind: str  # the most specific kind any hit had (a JWT the rule of Bearer headers took is still a JWT)
    count: int
    known: bool
    in_session: bool  # found in a transcript, not only in a settings file


def _unique_secrets(s: AuditSummary) -> list[Unique]:
    """One entry per secret value, whatever kinds the rules gave it: known formats first."""
    groups: dict[str, list[SecretHit]] = defaultdict(list)
    for hit in s.secrets:
        groups[hit.digest or hit.hmac_prefix].append(hit)
    unique = []
    for hits in groups.values():
        kind = min(hits, key=lambda h: (h.kind == "SECRET", not h.known)).kind
        in_session = any(h.source != SETTINGS_SOURCE for h in hits)
        unique.append(Unique(hits[0], kind, len(hits), any(h.known for h in hits), in_session))
    return sorted(unique, key=lambda u: not u.known)


def _sections(unique: list[Unique]) -> list[tuple[str | None, list[str], str, list[Unique]]]:
    """(title, advice lines, css, entries): known formats found in a session record, then those found only in a settings file
    (under the same title, which says once what a known format is), then the possible ones."""
    known = [u for u in unique if u.known]
    possible = [u for u in unique if not u.known]
    out = []
    if known:
        sent = [u for u in known if u.in_session]
        kept = [u for u in known if not u.in_session]
        title = f"known key formats ({len(known)})"
        if sent:
            out.append((title, [KNOWN_NOTE, ROTATE_ADVICE], "warn", sent))
            title = None
        if kept:
            out.append((title, [SETTINGS_ADVICE] if title is None else [KNOWN_NOTE, SETTINGS_ADVICE], "warn", kept))
    if possible:
        out.append((f"possible ({len(possible)})", [REVIEW_ADVICE], "note", possible))
    return out


def _counts(c: Counter) -> str:
    return ", ".join(f"{k} {v}" for k, v in c.most_common()) or "nothing"


def _secret_line(unique: list[Unique], occurrences: int) -> str:
    known = sum(1 for u in unique if u.known)
    return f"{len(unique)} unique ({known} known key formats, {len(unique) - known} possible), {occurrences} occurrences"


def _settings_note(s: AuditSummary) -> str:
    n = s.settings_files
    return f", {n} Claude Code settings file{'' if n == 1 else 's'}" if n else ""


def _unread_lines(s: AuditSummary) -> list[str]:
    """One line per kind of thing that was there and was not checked: '1 too big, 2 no access'."""
    out = []
    for what, rows in UNREAD.items():
        parts = [f"{s.unread[key]} {why}" for key, why in rows if s.unread[key]]
        if parts:
            out.append(f"{what}: {', '.join(parts)}")
    if any(s.unread[key] for key in UNREAD_KEYS if key.endswith("_disk_unknown")):
        out.append(DISK_UNKNOWN_HINT)
    return out


def _project_settings_hit(s: AuditSummary) -> bool:
    return any(h.role == "project_settings" for h in s.secrets)


def render_terminal(s: AuditSummary) -> str:
    """Short lines, so that the report fits a terminal of 100 columns: each secret under the file it was first seen in. Every field
    from a transcript (a project, a file name) goes through paths.show_path: no user name, no value, no control character."""
    settings = _settings_note(s)
    lines = [
        f"boxed audit: {s.items} items checked{settings}, {s.malformed} malformed lines skipped",
    ]
    unread = _unread_lines(s)
    if unread:
        lines += [INCOMPLETE, *(f"  {line}" for line in unread)]
    lines.append(NOTHING_IN_WHAT_WAS_READ if s.incomplete and not s.by_kind else f"found: {_counts(s.by_kind)}")
    for source, c in sorted(s.by_source.items()):
        lines.append(f"  {source}: {_counts(c)}")
    if s.by_role:
        lines.append(f"by role: {_counts(s.by_role)}")
    top = sorted(s.by_project.items(), key=lambda kv: -sum(kv[1].values()))[:10]
    if top:
        lines.append("top projects:")
        lines += [f"  {show_path(project)}: {_counts(c)}" for project, c in top]
    unique = _unique_secrets(s)
    if unique:
        lines.append(f"secrets: {_secret_line(unique, len(s.secrets))}")
        for title, advice, _, group in _sections(unique):
            lines += ["", title, *advice] if title else advice
            files: dict[str, list[tuple[str, Unique]]] = defaultdict(list)
            for u in group:
                path, line = show_locator(u.hit.locator, u.hit.project)
                files[path].append((line, u))
            for path, rows in files.items():
                width = max(len(line) for line, _ in rows) + 1
                lines.append(path)  # at the left edge: a rollout of Codex has a long name
                lines += [f"  {':' + line:<{width}}  {u.kind} #{u.hit.hmac_prefix} x{u.count}" for line, u in rows]
        if _project_settings_hit(s):
            lines += ["", GIT_HINT]
    return "\n".join(lines) + "\n"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def render_html(s: AuditSummary) -> str:
    kinds = [k for k, _ in s.by_kind.most_common()]
    settings = _settings_note(s)
    unread = _unread_lines(s)
    sections = [
        f"<h1>boxed audit</h1><p>{s.items} items checked{settings}, {s.malformed} malformed lines skipped. "
        "The report holds counts and hashes only, never the values.</p>",
    ]
    if unread:
        sections.append(
            f"<p class=warn>{html.escape(INCOMPLETE)}</p><ul>" + "".join(f"<li>{html.escape(u)}</li>" for u in unread) + "</ul>"
        )
    projects = sorted(s.by_project.items(), key=lambda kv: show_path(kv[0]))
    nothing = f"<p class=warn>{html.escape(NOTHING_IN_WHAT_WAS_READ)}</p>" if s.incomplete and not s.by_kind else ""
    sections += [
        "<h2>Found</h2>" + nothing + _table(["kind", "count"], [[k, s.by_kind[k]] for k in kinds]),
        "<h2>By source</h2>"
        + _table(["source", *kinds], [[src, *[c[k] for k in kinds]] for src, c in sorted(s.by_source.items())]),
        "<h2>By role</h2>" + _table(["role", "found"], [[r, n] for r, n in s.by_role.most_common()]),
        "<h2>By project</h2>" + _table(["project", *kinds], [[show_path(p), *[c[k] for k in kinds]] for p, c in projects]),
        "<h2>By day</h2>" + _table(["day", *kinds], [[d, *[c[k] for k in kinds]] for d, c in sorted(s.by_day.items())]),
    ]
    unique = _unique_secrets(s)
    if unique:
        parts = [f"<h2>Secrets</h2><p>{html.escape(_secret_line(unique, len(s.secrets)))}</p>"]
        for title, advice, css, group in _sections(unique):
            rows = []
            for u in group:
                path, line = show_locator(u.hit.locator, u.hit.project)
                rows.append([u.kind, u.hit.hmac_prefix, u.count, u.hit.source, show_path(u.hit.project), f"{path}:{line}" if line else path])
            heading = f"<h3>{html.escape(title[0].upper() + title[1:])}</h3>" if title else ""
            parts.append(
                heading + "".join(f"<p class={css}>{html.escape(a)}</p>" for a in advice)
                + _table(["kind", "hash", "occurrences", "source", "project", "first seen at"], rows)
            )
        if _project_settings_hit(s):
            parts.append(f"<p class=warn>{html.escape(GIT_HINT)}</p>")
        sections.append("".join(parts))
    style = (
        "body{font:14px/1.5 system-ui,sans-serif;margin:24px;color:#1b1b1f;background:#fafafa}"
        "table{border-collapse:collapse;margin:8px 0 24px}th,td{border:1px solid #ddd;padding:4px 8px;text-align:left}"
        "th{background:#f0f0f3}.warn{color:#a40000;font-weight:600}.note{font-weight:600}"
        "@media (prefers-color-scheme:dark){body{color:#e6e6ea;background:#151518}th{background:#24242a}th,td{border-color:#3a3a42}"
        ".warn{color:#ff8a8a}}"
    )
    return (
        f"<!doctype html><html lang=en><head><meta charset=utf-8>{AUDIT_TITLE}<style>{style}</style></head>"
        f"<body>{''.join(sections)}</body></html>"
    )


def is_audit_report(head: bytes) -> bool:
    """Do the first bytes of a file belong to a page that `boxed audit --html` wrote? Only such a file is replaced by a new one."""
    text = head.decode("utf-8", "replace")
    return text.startswith("<!doctype html>") and AUDIT_TITLE in text
