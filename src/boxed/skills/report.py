"""The three faces of a scan: terminal text, a self-contained HTML page and JSON (`boxed-skills-report/1`).

Names, locations and evidence come from files someone else wrote. Every dynamic value is spelled out first (`_shared.escaped`: a character
a line cannot show, such as a control, format or separator character, becomes \\xNN, \\uNNNN or \\UNNNNNNNN, so a name cannot forge a line
or move a cursor) and the HTML escapes it too; the page has no script, no link and no external resource, and its CSS classes come from
fixed tables, never from data. Evidence reaches this module redacted by the scanner, and an item's own config entry (which may hold a
secret) is never rendered. The JSON is plain ASCII, so a lone surrogate in a file name cannot make the file unwritable."""

import html
import json
import re
from collections import Counter
from collections.abc import Iterable

from boxed.skills._shared import escaped
from boxed.skills.inventory import Problem
from boxed.skills.scan import VERDICTS, ItemResult, sort_results

REPORT_FORMAT = "boxed-skills-report/1"
SKILLS_TITLE = "<title>boxed skills</title>"
_JSON_HEAD = re.compile(r'\{\s*"format"\s*:\s*"boxed-skills-report/1"')
_VERDICT_CLASS = {"dangerous": "bad", "suspicious": "warn", "ok": "good"}
_SEVERITY_CLASS = {"critical": "bad", "high": "bad", "medium": "warn", "low": "muted", "info": "muted"}
_CHANGE_MARK = {"new": "[new]", "changed": "[changed]"}  # "same" says nothing
_STYLE = (
    ":root{--fg:#1b1b1f;--bg:#fafafa;--card:#fff;--line:#ddd;--muted:#6b6b76;--good:#1a7f37;--warn:#9a6700;--bad:#a40000}"
    "@media (prefers-color-scheme:dark){:root{--fg:#e6e6ea;--bg:#151518;--card:#1e1e23;--line:#3a3a42;--muted:#9a9aa6;--good:#5fd07f;--warn:#e3b341;--bad:#ff8a8a}}"
    "body{font:14px/1.5 system-ui,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;color:var(--fg);background:var(--bg)}"
    "h1{font-size:22px;margin:0 0 4px}h2{font-size:15px;margin:0 0 6px;overflow-wrap:anywhere}.muted{color:var(--muted)}"
    ".good{color:var(--good)}.warn{color:var(--warn)}.bad{color:var(--bad)}"
    ".cards{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}.card,section{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px 16px}"
    "section{margin:12px 0}.tag{font-weight:600;text-transform:uppercase;font-size:12px}"
    "table{border-collapse:collapse;width:100%}th,td{border:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}"
    "td.code{font-family:ui-monospace,monospace;font-size:12px}"
)


def _esc(value: object) -> str:
    return html.escape(escaped(value))


def _where(file: str, line: int) -> str:
    return f"{file}:{line}" if line > 0 else file


def _counts(results: list[ItemResult]) -> Counter:
    return Counter(r.verdict for r in results)


def _summary_line(results: list[ItemResult], target: str | None) -> str:
    counts = _counts(results)
    n = len(results)
    what = "" if target is None else f"{escaped(target)}: "
    return f"boxed skills: {what}{n} item{'' if n == 1 else 's'} checked: " + ", ".join(f"{counts[v]} {v}" for v in VERDICTS)


def _mark(result: ItemResult, target: str | None) -> str:
    return "" if target is not None or result.change not in _CHANGE_MARK else f"  {_CHANGE_MARK[result.change]}"


def render_terminal(results: list[ItemResult], problems: Iterable[Problem], *, target: str | None = None) -> str:
    results = sort_results(results)
    lines = [_summary_line(results, target)]
    for r in results:
        lines.append("")
        lines.append(f"{r.verdict.upper()}  {escaped(r.item.id)}{_mark(r, target)}")
        if r.verdict != "ok":
            lines.append(f"  where: {escaped(r.item.location)}")
            if r.capabilities:
                lines.append(f"  can: {', '.join(sorted(r.capabilities))}")
        for f in r.findings:
            lines.append(f"  {f.severity}  {escaped(f.rule)}  {escaped(_where(f.file, f.line))}")
            lines.append(f"    {escaped(f.title)}")
            lines.append(f"    why: {escaped(f.why)}")
            if f.evidence:
                lines.append(f"    evidence: {escaped(f.evidence)}")
            lines.append(f"    advice: {escaped(f.advice)}")
    for p in problems:
        lines.append(f"could not read: {escaped(p.location)} ({escaped(p.reason)})")
    return "\n".join(lines) + "\n"


def _td(value: object, cls: str = "") -> str:
    return f'<td class="{cls}">{_esc(value)}</td>' if cls else f"<td>{_esc(value)}</td>"


def _table(head: list[str], rows: list[list[str]]) -> str:
    heads = "".join(f"<th>{html.escape(h)}</th>" for h in head)
    return f"<table><thead><tr>{heads}</tr></thead><tbody>{''.join('<tr>' + ''.join(r) + '</tr>' for r in rows)}</tbody></table>"


def render_html(results: list[ItemResult], problems: Iterable[Problem], *, target: str | None = None) -> str:
    results = sort_results(results)
    counts = _counts(results)
    cards = "".join(f'<span class="card {_VERDICT_CLASS[v]}"><b>{counts[v]}</b> {v}</span>' for v in VERDICTS)
    heading = "boxed skills" if target is None else f"boxed skills: {_esc(target)}"
    parts = [
        f"<h1>{heading}</h1><p class=muted>{html.escape(_summary_line(results, None)[len('boxed skills: '):])}. "
        "Evidence has secrets and personal data replaced; the file names and places are real, so read it before you share it.</p>",
        f"<div class=cards>{cards}</div>",
    ]
    quiet = []
    for r in results:
        mark = _mark(r, target).strip()
        if r.verdict == "ok" and not r.findings:
            quiet.append([_td(r.item.id), _td(r.item.location), _td(mark)])
            continue
        can = f"<p>Can: {_esc(', '.join(sorted(r.capabilities)))}</p>" if r.capabilities else ""
        rows = [
            [_td(f.severity, _SEVERITY_CLASS[f.severity]), _td(f.rule), _td(_where(f.file, f.line)), _td(f"{f.title}. {f.why}"), _td(f.evidence, "code"), _td(f.advice)]
            for f in r.findings
        ]
        table = _table(["severity", "rule", "where", "why", "evidence", "advice"], rows) if rows else ""
        parts.append(
            f'<section><h2><span class="tag {_VERDICT_CLASS[r.verdict]}">{r.verdict}</span> {_esc(r.item.id)} <span class=muted>{_esc(mark)}</span></h2>'
            f"<p class=muted>{_esc(r.item.location)}</p>{can}{table}</section>"
        )
    if quiet:
        parts.append("<h2>Nothing found</h2>" + _table(["item", "where", "change"], quiet))
    problem_rows = [[_td(p.location), _td(p.reason)] for p in problems]
    if problem_rows:
        parts.append("<h2>Could not read</h2>" + _table(["where", "reason"], problem_rows))
    return (
        f"<!doctype html><html lang=en><head><meta charset=utf-8>{SKILLS_TITLE}<style>{_STYLE}</style></head>"
        f"<body>{''.join(parts)}</body></html>"
    )


def render_json(results: list[ItemResult], problems: Iterable[Problem], *, target: str | None = None) -> str:
    results = sort_results(results)
    counts = _counts(results)
    doc = {
        "format": REPORT_FORMAT,
        "target": target,
        "summary": {"items": len(results), **{v: counts[v] for v in VERDICTS}},
        "items": [
            {
                "id": r.item.id, "agent": r.item.agent, "kind": r.item.kind, "scope": r.item.scope, "name": r.item.name, "location": r.item.location,
                "origin": r.item.origin, "enabled": r.item.enabled, "verdict": r.verdict, "change": r.change, "digest": r.digest,
                "capabilities": sorted(r.capabilities),
                "findings": [
                    {"rule": f.rule, "severity": f.severity, "title": f.title, "why": f.why, "advice": f.advice, "file": f.file, "line": f.line,
                     "evidence": f.evidence, "source": f.source}
                    for f in r.findings
                ],
            }
            for r in results
        ],
        "problems": [{"location": p.location, "reason": p.reason} for p in problems],
    }
    return json.dumps(doc, indent=1, ensure_ascii=True) + "\n"


def is_skills_report(head: bytes) -> bool:
    """Do the first bytes of a file belong to a page or a JSON file that `boxed skills scan` wrote? Only such a file is replaced."""
    text = head.decode("utf-8", "replace")
    return (text.startswith("<!doctype html>") and SKILLS_TITLE in text) or _JSON_HEAD.match(text) is not None
