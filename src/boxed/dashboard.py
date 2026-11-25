"""Journal overview, a CSV of a period and the signed export for the security team: kinds, counts and hashes, never values."""

import csv
import hashlib
import html
import io
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .checks import NOTE
from .errors import UserError, one_of
from .journal import GENESIS, STATUSES, Journal, VerifyReport, _canonical  # the journal's own hashing: a copy of it could drift
from .policy import CATEGORIES, RECIPIENT_KINDS, Policy, PolicyError

EXPORT_FORMAT = "boxed-journal-export/1"
PERIOD_DAYS = {"day": 1, "week": 7, "month": 30}
REPORT_TITLE = "<title>boxed.si journal</title>"
MAX_COUNT = 10**9  # a count, a level or a record number beyond this, either way, is not a number boxed wrote
NAME_MAX = 64  # characters of any name or text taken from a record: the longest honest value is a 64-digit hash
KEY_KINDS = ("SECRET", "PRIVATE_KEY", "JWT")  # sent without boxed, these must be revoked: masking later cannot take a send back
CHECK_STATES = ("on", "off", "unknown")
CHECKS_FAIL_SAFE = "A check that is missing, unknown or shows training on is treated as personal-training, the stricter recipient."
STATE_CLASS = {"on": "bad", "off": "good", "unknown": "muted"}  # classes come from tables like this one, never from a record
VERDICT_CLASS = {"allow": "good", "deny": "bad"}
# the columns of the CSV: the stored fields except the chain (prev_hash, hash, sig); usage is split into token counts and cost
CSV_COLUMNS = (
    "seq", "ts", "channel", "provider", "model", "account_type", "level", "markers_by_kind",
    "tokens_in", "tokens_out", "cost_micro_usd", "status", "coverage", "scope", "versions", "payload_sha256", "note",
)
FORMULA_STARTS = ("=", "+", "-", "@", "\t", "\r")  # a spreadsheet reads a cell that starts with one of these as a formula
STYLE = (
    ":root{--fg:#1b1b1f;--bg:#fafafa;--card:#fff;--line:#ddd;--muted:#6b6b76;--bar:#4f6fa8;--good:#1a7f37;--bad:#a40000}"
    "@media (prefers-color-scheme:dark){:root{--fg:#e6e6ea;--bg:#151518;--card:#1e1e23;--line:#3a3a42;--muted:#9a9aa6;"
    "--bar:#7f9fd8;--good:#5fd07f;--bad:#ff8a8a}}"
    "body{font:14px/1.5 system-ui,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;color:var(--fg);background:var(--bg)}"
    "h1{font-size:22px;margin:0 0 4px}h2{font-size:15px;margin:0 0 8px}.muted{color:var(--muted)}"
    ".state{margin:16px 0;padding:10px 14px;border:1px solid;border-radius:6px}.good{color:var(--good)}.bad{color:var(--bad)}"
    ".cards{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}"
    ".card,.box{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px 16px}"
    ".card{min-width:120px}.card b{display:block;font-size:26px}"
    ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin-bottom:16px}"
    "table{border-collapse:collapse;width:100%}th,td{padding:3px 8px 3px 0;text-align:left}"
    ".n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}"
    "td.bar{width:45%}td.bar i{display:block;height:8px;border-radius:2px;background:var(--bar)}"
    "section{margin-top:28px}.sec{font-size:18px;margin:0 0 8px}.scroll{overflow-x:auto}.nw{white-space:nowrap}"
    "td.due{color:var(--bad);font-weight:600}"
)


@dataclass
class Summary:
    since: date | None = None
    until: date | None = None
    records: int = 0
    by_channel: Counter = field(default_factory=Counter)
    by_provider: Counter = field(default_factory=Counter)
    by_account_type: Counter = field(default_factory=Counter)  # the journal records the type of an account, not its name
    by_model: Counter = field(default_factory=Counter)  # only records that name a model: a plugin record has none
    by_level: Counter = field(default_factory=Counter)
    by_status: Counter = field(default_factory=Counter)
    markers_by_kind: Counter = field(default_factory=Counter)
    tokens_in: int = 0  # sums of what providers reported; records without usage add nothing
    tokens_out: int = 0
    spend_micro_usd: int = 0  # the sum of the costs providers reported (OpenRouter does), in millionths of a US dollar
    spend_records: int = 0  # how many records reported one: the sum is not the whole spend when others do not
    by_day: dict[str, Counter] = field(default_factory=dict)


def _day(rec: dict) -> date | None:
    """The UTC day a record was written on. The journal writes UTC, but a timestamp with another offset still counts on its
    UTC date, and one without an offset is read as UTC. A moment that has no UTC date (year 1 or 10000) is unreadable."""
    try:
        moment = datetime.fromisoformat(rec["ts"])
        if moment.tzinfo is not None:
            moment = moment.astimezone(UTC)
        return moment.date()
    except (KeyError, TypeError, ValueError, OverflowError):
        return None


def _in_period(rec: dict, since: date | None, until: date | None) -> bool:
    """Both ends are included; with a period set, a record without a readable day cannot belong to it."""
    if since is None and until is None:
        return True
    day = _day(rec)
    return day is not None and (since is None or since <= day) and (until is None or day <= until)


def _safe(text: str) -> str:
    """The text as UTF-8 can hold it: JSON lets a hand-edited record carry a lone surrogate, which shows as its escape."""
    return text.encode("utf-8", "backslashreplace").decode("utf-8")


def _cut(value: object) -> str:
    """Any text taken from a record, at most NAME_MAX characters: a name is a label, not a place to put a document."""
    return _safe(str(value)[:NAME_MAX])[:NAME_MAX]


def _text(rec: dict, key: str) -> str:
    value = rec.get(key)
    return _cut(value) if isinstance(value, str) and value else "unknown"


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _number(value: object) -> bool:
    """A number worth showing: a whole number within MAX_COUNT of zero. A bigger one is not a number boxed wrote, and cutting
    it would show a different number, so it reads as unknown."""
    return _is_int(value) and -MAX_COUNT <= value <= MAX_COUNT


def _whole(value: object) -> bool:
    """A count boxed could have written: a whole number from 0 to MAX_COUNT. Anything else is left out, not clamped."""
    return _number(value) and value >= 0


def _model(rec: dict) -> str:
    """The model a record names: "" when it names none (only records of API calls do), "unknown" when it cannot be read."""
    return "" if rec.get("model") in (None, "") else _text(rec, "model")


def _level(rec: dict) -> int | str:
    level = rec.get("level")
    return level if _number(level) else "unknown"


def _kinds(rec: dict) -> dict[str, int]:
    """The marker counts of a record that can be believed, most first."""
    found = rec.get("markers_by_kind")
    counts: Counter = Counter()
    for kind, n in found.items() if isinstance(found, dict) else ():
        if _whole(n):
            counts[_cut(kind)] += n  # two long names that differ only beyond the cut share a row
    return dict(_ranked(counts))


def _usage(rec: dict) -> dict[str, int]:
    """The token counts a record reports: "input" and "output", each only when it can be believed."""
    usage = rec.get("usage")
    return {key: usage[key] for key in ("input", "output") if isinstance(usage, dict) and _whole(usage.get(key))}


def _cost(rec: dict) -> int | None:
    """The cost in millionths of a dollar that a record reports, when it can be believed; None for no cost or a doubtful one."""
    usage = rec.get("usage")
    cost = usage.get("cost_micro_usd") if isinstance(usage, dict) else None
    return cost if _whole(cost) else None


def period_bounds(name: str, today: date) -> tuple[date, date]:
    """The first and the last day of a named period that ends today. Both days count: a week is seven days with today."""
    days = PERIOD_DAYS.get(name)
    if days is None:
        raise UserError(f"unknown period, expected {one_of(PERIOD_DAYS)}")
    return today - timedelta(days=days - 1), today


def summarize(entries: Iterable[dict], since: date | None = None, until: date | None = None) -> Summary:
    """Counts over journal records. A hand-edited record is counted as "unknown" where it is unreadable, never a crash."""
    s = Summary(since, until)
    by_day: dict[str, Counter] = {}
    for rec in entries:
        if not _in_period(rec, since, until):
            continue
        s.records += 1
        s.by_channel[_text(rec, "channel")] += 1
        s.by_provider[_text(rec, "provider")] += 1
        s.by_account_type[_text(rec, "account_type")] += 1
        if model := _model(rec):
            s.by_model[model] += 1
        s.by_level[_level(rec)] += 1
        status = _text(rec, "status")
        s.by_status[status] += 1
        day = _day(rec)
        by_day.setdefault(day.isoformat() if day else "unknown", Counter())[status] += 1
        s.markers_by_kind.update(_kinds(rec))
        usage = _usage(rec)
        s.tokens_in += usage.get("input", 0)
        s.tokens_out += usage.get("output", 0)
        if (cost := _cost(rec)) is not None:
            s.spend_micro_usd += cost
            s.spend_records += 1
    s.by_day = dict(sorted(by_day.items()))
    return s


def journal_rows(entries: Iterable[dict], since: date | None = None, until: date | None = None, limit: int = 500) -> list[dict]:
    """The newest `limit` records of a period, newest first, as plain values for a table. Newest is the last written:
    a clock that stepped back must not reorder the journal."""
    rows = []
    for rec in reversed(list(entries)):
        if len(rows) >= limit:
            break
        if _in_period(rec, since, until):
            seq = rec.get("seq")
            rows.append(
                {
                    "seq": seq if _number(seq) else "unknown",
                    "ts": _text(rec, "ts"),
                    "channel": _text(rec, "channel"),
                    "provider": _text(rec, "provider"),
                    "model": _model(rec),
                    "account_type": _text(rec, "account_type"),
                    "level": _level(rec),
                    "kinds": _kinds(rec),
                    "tokens": _usage(rec),
                    "status": _text(rec, "status"),
                }
            )
    return rows


def _plain(rec: dict, key: str) -> str:
    """A stored field as a cell: text and whole numbers as they are, nothing for a missing field, "unknown" for anything else."""
    value = rec.get(key)
    if value is None or value == "":
        return ""
    if isinstance(value, str):
        return _cut(value)
    return str(value) if _number(value) else "unknown"


def _pairs(items: Iterable[tuple[object, object]]) -> str:
    return " ".join(f"{_cut(name)}:{_cut(value)}" for name, value in items)


def _cell(text: str) -> str:
    """A CSV cell a spreadsheet will not run as a formula: a leading quote makes it plain text."""
    return "'" + text if text.startswith(FORMULA_STARTS) else text


def _csv_cells(rec: dict) -> list[str]:
    usage = _usage(rec)
    versions = rec.get("versions")
    level = rec.get("level")
    cells = {
        "level": "n/a" if _is_int(level) and level == -1 else _plain(rec, "level"),  # a restore has no level
        "markers_by_kind": _pairs(_kinds(rec).items()),
        "tokens_in": str(usage["input"]) if "input" in usage else "",
        "tokens_out": str(usage["output"]) if "output" in usage else "",
        "cost_micro_usd": "" if (cost := _cost(rec)) is None else str(cost),
        "versions": _pairs(versions.items()) if isinstance(versions, dict) else _plain(rec, "versions"),
    }
    return [_cell(cells[key] if key in cells else _plain(rec, key)) for key in CSV_COLUMNS]


def to_csv(entries: Iterable[dict], since: date | None = None, until: date | None = None) -> str:
    """The records of a period in journal order, one row each, without the chain fields (prev_hash, hash, sig): a spreadsheet
    cannot verify them. Every text is cut to NAME_MAX characters, and a cell that starts with = + - @ tab or CR gets a
    leading quote, so a hand-made value cannot run as a formula. Rows end with CRLF, as the csv module writes them: write the
    file as UTF-8 with newline=""."""
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(CSV_COLUMNS)
    for rec in entries:
        if _in_period(rec, since, until):
            writer.writerow(_csv_cells(rec))
    return out.getvalue()


def _esc(value: object) -> str:
    return html.escape(_safe(str(value)))


def _count(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _ranked(counts: Counter) -> list[tuple[object, int]]:
    return sorted(counts.items(), key=lambda kv: (-kv[1], str(kv[0])))


def _by_level(counts: Counter) -> list[tuple[object, int]]:
    """Levels in order, then -1 (a restore has no level), then records whose level could not be read."""
    return sorted(counts.items(), key=lambda kv: (kv[0] == "unknown", kv[0] == -1, kv[0] if isinstance(kv[0], int) else 0))


def _breakdown(title: str, items: list[tuple[object, int]], empty: str = "nothing") -> str:
    """A box with a row per name: its count and a bar scaled to the largest count."""
    top = max((n for _, n in items), default=0)
    rows = "".join(
        f"<tr><td>{_esc(name)}</td><td class=n>{n}</td>"
        f'<td class=bar><i style="width:{max(1, 100 * n // top) if n > 0 else 0}%"></i></td></tr>'
        for name, n in items
    )
    return f"<div class=box><h2>{_esc(title)}</h2><table>{rows or f'<tr><td class=muted>{_esc(empty)}</td></tr>'}</table></div>"


def _cards(items: Iterable[tuple[str, int]]) -> str:
    cards = "".join(f"<div class=card><span class=muted>{label}</span><b>{n}</b></div>" for label, n in items)
    return f"<div class=cards>{cards}</div>"


def _td(value: object, cls: str = "") -> str:
    """A table cell. `cls` is a class name of this page, never a value from a record."""
    return f"<td class={cls}>{_esc(value)}</td>" if cls else f"<td>{_esc(value)}</td>"


def _table(head: list[str], rows: list[list[str]]) -> str:
    """A table that scrolls sideways on a narrow screen. Head cells are plain text, the cells of a row come from _td."""
    heads = "".join(f"<th>{_esc(name)}</th>" for name in head)
    body = "".join(f"<tr>{''.join(cells)}</tr>" for cells in rows)
    return f"<div class=scroll><table><tr>{heads}</tr>{body}</table></div>"


def _tokens(usage: dict[str, int]) -> str:
    return " / ".join(f"{usage[key]} {label}" for key, label in (("input", "in"), ("output", "out")) if key in usage)


def _usd(micro: int) -> str:
    """Millionths of a dollar as dollars, exactly: at least two decimals, at most six, nothing rounded."""
    whole, part = divmod(micro, 1_000_000)
    return f"${whole}.{f'{part:06d}'.rstrip('0').ljust(2, '0')}"


def _spend(s: Summary) -> str:
    """The costs providers reported. Only a record that reports one is added, so this is not the whole spend: it says so."""
    return (
        "<div class=box><h2>Spend reported by the provider</h2>"
        f"<table><tr><td>{_esc(_usd(s.spend_micro_usd))}</td><td class=muted>{_count(s.spend_records, 'record')} reported a cost</td></tr></table>"
        "<p class=muted>Records without a reported cost are not counted.</p></div>"
    )


def _journal(rows: list[dict], total: int) -> str:
    """The journal table: `rows` come from journal_rows, `total` is the number of records in the period."""
    body = [
        [
            _td(r["seq"], "nw"), _td(r["ts"], "nw"), _td(r["channel"]), _td(r["provider"]), _td(r["model"] or "-"),
            _td(r["account_type"]), _td("n/a" if r["level"] == -1 else r["level"]), _td(_pairs(r["kinds"].items()) or "-"),
            _td(_tokens(r["tokens"]) or "-"), _td(r["status"]),
        ]
        for r in rows
    ]
    head = ["Seq", "Time", "Channel", "Provider", "Model", "Account type", "Level", "Markers", "Tokens", "Status"]
    cut = f"<p class=muted>Showing the newest {len(rows)} of {total} records.</p>" if len(rows) < total else ""
    return (
        "<section id=journal><h2 class=sec>Journal</h2>"
        f"<p class=muted>Tokens are as reported by the provider.</p>{_table(head, body)}{cut}</section>"
    )


def _doubt(rec: dict) -> tuple[set[str], bool]:
    """What the marker counts of a record leave in doubt: the kinds whose count cannot be believed, and whether there is no
    table of counts at all. Either way the record was not read."""
    found = rec.get("markers_by_kind")
    if not isinstance(found, dict):
        return set(), True
    return {kind for kind, n in found.items() if not _whole(n)}, False


def _observed(records: Iterable[dict], since: date | None, until: date | None, verify: VerifyReport | None, damaged: int) -> str:
    """Sends the browser extension saw while observation was on: nothing here is a claim about what was not seen.
    The observation log is a chain of its own, so its section states that chain and its damaged lines, whatever the main
    journal says; without a verdict it says that the log was not verified.
    A send is clean only when it is marked "checked" and every count in it can be read: anything else could not be checked,
    and a key kind whose count cannot be read still counts as sent, because it may have been."""
    sends = with_findings = gaps = 0
    kinds: Counter = Counter()
    sites: Counter = Counter()
    coverage: Counter = Counter()
    doubtful: set[str] = set()  # kinds that appear with a count nobody can believe
    for rec in records:
        if not _in_period(rec, since, until):
            continue
        sends += 1
        found = _kinds(rec)
        unreadable, no_counts = _doubt(rec)
        if any(found.values()):
            with_findings += 1
        if rec.get("coverage") != "checked" or no_counts or unreadable:
            gaps += 1
        doubtful |= unreadable
        kinds.update(found)
        sites[_text(rec, "provider")] += 1
        coverage[_text(rec, "coverage")] += 1
    log = _state(verify, "log") if verify is not None else "<p class=muted>The observation log was not verified.</p>"
    head = (
        "<h2 class=sec>Sent without boxed</h2>"
        "<p class=muted>Browser sends that observation mode saw: kinds and counts only, never the text. "
        "It sees only what it can read, so WebSocket messages and attachments are not checked.</p>"
        f"{log}{_skipped(damaged)}{_cards((('Sends', sends), ('Sends with findings', with_findings)))}"
    )
    if not sends:
        return (
            f"<section id=observed>{head}<p>No sends were observed in this period. This is not proof that nothing was sent: "
            "observation must be on, and it cannot read everything.</p></section>"
        )
    leaked = [kind for kind in KEY_KINDS if kinds[kind] > 0 or kind in doubtful]
    advice = (
        f"<p class=bad><b>Revoke and replace</b> the keys and tokens that were sent ({', '.join(leaked)}): "
        "masking later cannot undo a send.</p>"
        if leaked
        else ""
    )
    unchecked = f"<p class=muted>{_count(gaps, 'send')} could not be checked, so the counts may be too low.</p>" if gaps else ""
    boxes = "".join([_breakdown("Kinds", _ranked(kinds)), _breakdown("Sites", _ranked(sites)), _breakdown("Coverage", _ranked(coverage))])
    return f"<section id=observed>{head}<div class=grid>{boxes}</div>{advice}{unchecked}</section>"


def _state_of(value: object) -> str:
    """on, off or unknown: anything else, a missing value included, is unknown. Only exactly "off" reads as off."""
    return value if value in CHECK_STATES else "unknown"


def _check_row(check: object) -> list[str]:
    check = check if isinstance(check, dict) else {}
    training = _state_of(check.get("training"))
    return [
        _td(_text(check, "provider")), _td(_text(check, "account")),
        _td(training, STATE_CLASS[training]), _td(_state_of(check.get("memory"))),
        _td(_text(check, "source")), _td(_text(check, "checked_at")),
        _td(_text(check, "settings_url") if check.get("settings_url") else "-"),
        _td("due", "due") if check.get("due") is not False else _td(""),  # anything but a plain False is a reminder
    ]


def _checks(checks: Iterable[dict] | None) -> str:
    """None means the saved checks could not be read: that is not "none recorded", and no account then reads as training off."""
    if checks is None:
        body = "<p class=bad>The saved training checks could not be read, so no account is known to have training off.</p>"
    else:
        rows = [_check_row(check) for check in checks]
        head = ["Provider", "Account", "Training", "Memory", "Source", "Checked", "Settings page", "Due"]
        body = _table(head, rows) if rows else "<p>No training checks recorded yet.</p>"
    return f"<section id=checks><h2 class=sec>Training on chats</h2>{body}<p class=muted>{NOTE} {CHECKS_FAIL_SAFE}</p></section>"


def _policy(policy: Policy) -> str:
    body = []
    for category in CATEGORIES:
        cells = [_td(category)]
        for kind in RECIPIENT_KINDS:
            try:
                rule = policy.rule(category, kind)
            except PolicyError:
                cells.append(_td("no rule", "bad"))  # decide() refuses a pair without a rule
            else:
                cells.append(_td(rule, VERDICT_CLASS.get(rule.verdict, "")))
        body.append(cells)
    return (
        "<section id=policy><h2 class=sec>Policy</h2>"
        "<p class=muted>What may go to each kind of recipient, decided before masking. masked:N means masked at level N or stricter, "
        "local-only means a local model only, deny means nothing is sent.</p>"
        f"{_table(['Category', *RECIPIENT_KINDS], body)}</section>"
    )


def _days(by_day: dict[str, Counter]) -> str:
    seen = {status for counts in by_day.values() for status in counts}
    columns = [*STATUSES, *sorted(seen - set(STATUSES))]
    head = "".join(f"<th class=n>{_esc(c)}</th>" for c in columns)
    rows = ""
    for day, counts in sorted(by_day.items()):
        cells = "".join(f"<td class=n>{counts[c]}</td>" for c in columns)
        rows += f"<tr><td>{_esc(day)}</td>{cells}<td class=n>{sum(counts.values())}</td></tr>"
    table = f"<table><tr><th>Day</th>{head}<th class=n>Total</th></tr>{rows}</table>" if rows else "<p class=muted>nothing</p>"
    return f"<div class=box><h2>By day (UTC)</h2>{table}</div>"


def _period(s: Summary) -> str:
    if s.since and s.until:
        return f"{s.since} to {s.until}"
    if s.since:
        return f"since {s.since}"
    if s.until:
        return f"until {s.until}"
    return "all records"


def _state(verify: VerifyReport, what: str = "journal") -> str:
    """The verdict on one log. The main journal and the observation log are two chains: each says its own state."""
    chain = "Chain" if what == "journal" else "Observation chain"
    if verify.ok:
        return f'<p class="state good"><b>{chain} OK</b>: {_count(verify.count, "record")} verified (the whole {what}, not only this period).</p>'
    return (
        f'<p class="state bad"><b>{chain} BROKEN</b>: {_esc(_cut(verify.reason))}. {_count(verify.count, "record")} passed verification. '
        f"The numbers below come from a {what} that failed verification.</p>"
    )


def _skipped(damaged: int) -> str:
    return f"<p class=bad>{_count(damaged, 'damaged line')} skipped: not counted below.</p>" if damaged else ""


def render_html(
    summary: Summary,
    verify: VerifyReport,
    damaged: int = 0,
    *,
    rows: Iterable[dict] = (),
    observed: Iterable[dict] | None = None,
    observed_verify: VerifyReport | None = None,
    observed_damaged: int = 0,
    checks: Iterable[dict] | None = (),
    policy: Policy | None = None,
) -> str:
    """One self-contained page: no scripts, no external resources, and nothing from a record except kinds, counts and names.
    `verify` is the verdict on the whole journal; `damaged` is the number of unreadable lines Journal.read() reports.
    `rows` are journal_rows() of the same period: the journal table is left out without them. `observed` are the records of
    the observation journal (the shape of a journal record, channel "observed"), of which only the summary's period counts.
    observed=None leaves the section out altogether: a caller that shows the dashboard passes a list, an empty one when
    nothing was seen, together with `observed_verify` and `observed_damaged`, the observation log's own verdict and number of
    unreadable lines (the log is a chain of its own; without a verdict the section says that it was not verified).
    `checks` are the dicts the host's "checks" command replies with; no check reads as unknown, and None says that the saved
    checks could not be read. `policy` adds the matrix of categories and recipients. Every value that comes from a record or a
    check is escaped, and nothing is a link: the page loads and opens nothing."""
    s = summary
    rows = list(rows)
    cards = _cards(
        (
            ("Records", s.records),
            ("Sent", s.by_status["sent"]),
            ("Blocked", s.by_status["blocked"]),
            ("Markers", sum(s.markers_by_kind.values())),
        )
    )
    tokens =[("input", s.tokens_in), ("output", s.tokens_out)] if s.tokens_in or s.tokens_out else []
    boxes = "".join(
        [
            _breakdown("Markers by kind", _ranked(s.markers_by_kind)),
            _breakdown("By channel", _ranked(s.by_channel)),
            _breakdown("By provider", _ranked(s.by_provider)),
            _breakdown("By account type", _ranked(s.by_account_type)),
            _breakdown("By model", _ranked(s.by_model)),
            _breakdown("Tokens, as reported by the provider", tokens, empty="none reported"),
            *([_spend(s)] if s.spend_records else []),
            _breakdown("By level", [("n/a" if k == -1 else k, n) for k, n in _by_level(s.by_level)]),
            _breakdown("By status", _ranked(s.by_status)),
        ]
    )
    sections = [f"<section id=overview><h2 class=sec>Overview</h2>{cards}<div class=grid>{boxes}</div>{_days(s.by_day)}</section>"]
    if rows:
        sections.append(_journal(rows, s.records))
    if observed is not None:
        sections.append(_observed(observed, s.since, s.until, observed_verify, observed_damaged))
    sections.append(_checks(checks))
    if policy is not None:
        sections.append(_policy(policy))
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width,initial-scale=1">'
        f"{REPORT_TITLE}<style>{STYLE}</style></head><body>"
        f"<h1>boxed.si journal</h1><p class=muted>Period: {_esc(_period(s))}. Counts, kinds and names only, never the values.</p>"
        f"{_state(verify)}{_skipped(damaged)}{''.join(sections)}"
        "</body></html>"
    )


def is_report(head: bytes) -> bool:
    """Do the first bytes of a file belong to something the dashboard wrote: its page, or its CSV (a byte order mark first, and
    whatever columns a later version adds)? Only such a file is replaced by a new report."""
    text = head.decode("utf-8", "replace").removeprefix("\ufeff")
    return (text.startswith("<!doctype html>") and REPORT_TITLE in text) or text.startswith(",".join(CSV_COLUMNS[:4]) + ",")


def export_for_security(journal: Journal, since: date | None = None, until: date | None = None) -> dict:
    """The records of a period exactly as stored, and the device public key to check them with.
    "verify" is the journal's own verdict on the whole file: an unsigned claim, which verify_export never reads."""
    return {
        "format": EXPORT_FORMAT,
        "public_key": journal.public_key_hex(),
        "verify": asdict(journal.verify()),
        "entries": _period_run(journal.entries(), since, until),
    }


def _period_run(entries: list[dict], since: date | None, until: date | None) -> list[dict]:
    """From the first to the last record of the period: a clock that stepped back must not cut holes into the chain."""
    inside = [i for i, rec in enumerate(entries) if _in_period(rec, since, until)]
    return entries[inside[0] : inside[-1] + 1] if inside else []


def verify_export(export: dict) -> VerifyReport:
    """Checks an export from the file alone, the way Journal.verify checks the journal: every hash, every signature
    against export["public_key"], and the chain from the first record's own prev_hash, so a slice verifies too; only a
    first record numbered 1 must start at the genesis value, as Journal.verify demands.
    Limits: records cut off at either end of a slice cannot be noticed, and the key proves nothing by itself -
    compare it with the one on record for the device."""
    if not isinstance(export, dict) or export.get("format") != EXPORT_FORMAT:
        return VerifyReport(False, 0, None, "not a boxed journal export")
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(export["public_key"]))
    except (KeyError, TypeError, ValueError):
        return VerifyReport(False, 0, None, "export has no valid public key")
    entries = export.get("entries")
    if not isinstance(entries, list):
        return VerifyReport(False, 0, None, "export has no list of entries")
    prev, count = None, 0
    for position, rec in enumerate(entries, start=1):
        seq = rec.get("seq") if isinstance(rec, dict) else None
        if not isinstance(seq, int) or isinstance(seq, bool):
            return VerifyReport(False, count, position, f"entry {position}: not a journal record")
        try:
            digest = hashlib.sha256(_canonical(rec)).hexdigest()
        except (ValueError, TypeError, RecursionError):  # a lone surrogate or a monster value: not a record boxed wrote
            digest = None
        if digest != rec.get("hash"):
            return VerifyReport(False, count, seq, f"record {seq}: hash does not match content")
        try:
            key.verify(bytes.fromhex(rec["sig"]), bytes.fromhex(rec["hash"]))
        except (InvalidSignature, ValueError, KeyError, TypeError):
            return VerifyReport(False, count, seq, f"record {seq}: bad signature")
        if prev is None:
            if seq == 1 and rec.get("prev_hash") != GENESIS:  # a slice may begin anywhere, but nothing comes before record 1
                return VerifyReport(False, count, seq, f"record {seq}: chain break")
        elif rec.get("prev_hash") != prev["hash"] or seq != prev["seq"] + 1:
            return VerifyReport(False, count, seq, f"record {seq}: chain break")
        prev, count = rec, count + 1
    return VerifyReport(True, count, None, "ok")
