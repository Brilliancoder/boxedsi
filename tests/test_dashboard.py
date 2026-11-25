import csv
import hashlib
import html
import io
import json
import re
import shutil
from collections import Counter
from dataclasses import fields, replace
from datetime import UTC, date, datetime
from html.parser import HTMLParser
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from hypothesis import given, settings
from hypothesis import strategies as st

import boxed
from boxed import checks
from boxed.dashboard import (
    CSV_COLUMNS,
    Summary,
    export_for_security,
    journal_rows,
    period_bounds,
    render_html,
    summarize,
    to_csv,
    verify_export,
)
from boxed.journal import Journal, JournalEntry, VerifyReport
from boxed.keys import InsecureFileKeyStore
from boxed.policy import CATEGORIES, RECIPIENT_KINDS, Policy


def entry(channel="mcp", provider="client", account_type="unknown", level=2, status="sent", markers=None, **kw):
    return JournalEntry(
        channel=channel,
        provider=provider,
        account_type=account_type,
        level=level,
        markers_by_kind={"EMAIL": 1} if markers is None else markers,
        status=status,
        payload_sha256="ab" * 32,
        coverage="full",
        scope="ws-1",
        versions={"boxed": "0.1.0"},
        **kw,
    )


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal.jsonl", InsecureFileKeyStore(tmp_path / "keys"))


@pytest.fixture
def clock(monkeypatch):
    """clock(day, hour) sets the time the journal stamps on the next records (October 2026, UTC)."""
    now = [datetime(2026, 10, 19, 12, tzinfo=UTC)]

    class Fixed(datetime):
        @classmethod
        def now(cls, tz=None):
            return now[0]

    monkeypatch.setattr("boxed.journal.datetime", Fixed)

    def set_time(day, hour=12):
        now[0] = datetime(2026, 10, day, hour, tzinfo=UTC)

    return set_time


WEEK = [
    (19, entry("mcp", "client", "unknown", 2, "sent", {"EMAIL": 2, "SECRET": 1})),
    (19, entry("mcp", "client", "unknown", 2, "sent", {"EMAIL": 1})),
    (19, entry("claude-code", "anthropic", "unknown", 1, "blocked", {"SECRET": 1})),
    (20, entry("manual", "unknown", "unknown", 3, "prepared", {"PHONE": 3})),
    (20, entry("manual", "unknown", "unknown", -1, "received", {})),
    (20, entry("extension", "openai", "personal-training", 2, "sent", {"EMAIL": 1})),
    (21, entry("workspace", "local", "local", 4, "prepared", {"IP": 2})),
]


@pytest.fixture
def week(journal, clock):
    """Seven records over three days; the numbers in the tests below are counted from this table."""
    for day, e in WEEK:
        clock(day)
        journal.append(e)
    return journal


API_CALLS = [
    (19, entry("api", "openai", "personal-private", 2, "sent", {"EMAIL": 1}, model="gpt-5", usage={"input": 120, "output": 30})),
    (19, entry("api", "openai", "personal-private", 2, "received", {}, model="gpt-5", usage={"input": 80, "output": 20})),
    (20, entry("api", "deepseek", "personal-training", 3, "sent", {"PHONE": 2}, model="deepseek-chat", usage={"input": 50})),
    (20, entry("api", "anthropic", "personal-private", 2, "error", {}, model="claude-x")),
    (20, entry("mcp", "client", "unknown", 2, "sent", {"EMAIL": 1})),
]


@pytest.fixture
def api_calls(journal, clock):
    """Four API calls and one plugin record over two days; the model and token numbers in the tests are counted from this table."""
    for day, e in API_CALLS:
        clock(day)
        journal.append(e)
    return journal


def test_period_bounds():
    today = date(2026, 10, 21)
    assert period_bounds("day", today) == (today, today)
    assert period_bounds("week", today) == (date(2026, 10, 15), today)
    assert period_bounds("month", today) == (date(2026, 9, 22), today)
    assert period_bounds("week", date(2027, 1, 3)) == (date(2026, 12, 28), date(2027, 1, 3))
    for name, days in (("day", 1), ("week", 7), ("month", 30)):
        since, until = period_bounds(name, today)
        assert (until - since).days + 1 == days  # both ends count, so a week is seven calendar days including today
    with pytest.raises(ValueError, match="unknown period, expected day, week, month") as raised:
        period_bounds("year", today)
    assert "year" not in str(raised.value)


def test_summary_counts_channels_providers_accounts_models_and_tokens(api_calls):
    s = summarize(api_calls.entries())
    assert s.by_channel == Counter({"api": 4, "mcp": 1})
    assert s.by_provider == Counter({"openai": 2, "deepseek": 1, "anthropic": 1, "client": 1})
    assert s.by_account_type == Counter({"personal-private": 3, "personal-training": 1, "unknown": 1})
    assert s.by_model == Counter({"gpt-5": 2, "deepseek-chat": 1, "claude-x": 1})  # a record without a model is not "unknown"
    assert (s.tokens_in, s.tokens_out) == (250, 50)  # a provider that reported only input adds nothing to output
    day = date(2026, 10, 20)
    one_day = summarize(api_calls.entries(), since=day, until=day)
    assert one_day.by_model == Counter({"deepseek-chat": 1, "claude-x": 1})
    assert (one_day.tokens_in, one_day.tokens_out) == (50, 0)
    assert (summarize([]).tokens_in, summarize([]).tokens_out, summarize([]).by_model) == (0, 0, Counter())


def test_journal_rows_newest_first_and_capped(api_calls):
    entries = api_calls.entries()
    rows = journal_rows(entries)
    assert [r["seq"] for r in rows] == [5, 4, 3, 2, 1]
    assert rows[0] == {
        "seq": 5, "ts": "2026-10-20T12:00:00+00:00", "channel": "mcp", "provider": "client", "model": "",
        "account_type": "unknown", "level": 2, "kinds": {"EMAIL": 1}, "tokens": {}, "status": "sent",
    }
    assert rows[2] == {
        "seq": 3, "ts": "2026-10-20T12:00:00+00:00", "channel": "api", "provider": "deepseek", "model": "deepseek-chat",
        "account_type": "personal-training", "level": 3, "kinds": {"PHONE": 2}, "tokens": {"input": 50}, "status": "sent",
    }
    assert rows[4]["tokens"] == {"input": 120, "output": 30} and rows[4]["model"] == "gpt-5"
    assert [r["seq"] for r in journal_rows(entries, limit=2)] == [5, 4]
    assert journal_rows(entries, limit=0) == []
    day = date(2026, 10, 19)
    assert [r["seq"] for r in journal_rows(entries, since=day, until=day)] == [2, 1]
    assert [r["seq"] for r in journal_rows(entries, since=day, until=day, limit=1)] == [2]  # the cap counts rows of the period
    assert [r["seq"] for r in journal_rows(iter(entries), limit=1)] == [5]  # any iterable of records will do
    many = [{"seq": n, "hash": "h", "ts": "2026-10-19T12:00:00+00:00"} for n in range(1, 601)]
    default = journal_rows(many)
    assert (len(default), default[0]["seq"], default[-1]["seq"]) == (500, 600, 101)  # the cap is 500 unless asked otherwise


CSV_HEADER = [
    "seq", "ts", "channel", "provider", "model", "account_type", "level", "markers_by_kind",
    "tokens_in", "tokens_out", "cost_micro_usd", "status", "coverage", "scope", "versions", "payload_sha256", "note",
]


def csv_rows(text):
    """The header and the records of a CSV as dicts; strict zip: every row is as wide as the header."""
    table = list(csv.reader(io.StringIO(text, newline="")))
    return table[0], [dict(zip(table[0], row, strict=True)) for row in table[1:]]


def test_csv_has_no_hashes_and_neutralises_formulas(journal, clock):
    """No hashes means the chain fields prev_hash, hash and sig; formula prefixes are the leading = + - @ tab and CR."""
    clock(19)
    hostile = replace(
        entry("=cmd|' /C calc'!A0", "@SUM(1+1)", "+1", 2, "sent", {'=HYPERLINK("http://x")': 3}, model="-2+3", usage={"input": 5, "output": 6}),
        coverage="-1", scope="\t=1", note="\r=1",
    )
    journal.append(hostile)
    clock(20)
    journal.append(entry("manual", "unknown", "unknown", -1, "received", {}))
    text = to_csv(journal.entries())
    header, (first, second) = csv_rows(text)
    assert header == CSV_HEADER
    for rec in journal.entries():
        assert not [h for h in (rec["hash"], rec["prev_hash"], rec["sig"]) if h in text]
    assert first["channel"] == "'=cmd|' /C calc'!A0"
    assert first["provider"] == "'@SUM(1+1)" and first["account_type"] == "'+1" and first["model"] == "'-2+3"
    assert first["markers_by_kind"] == "'=HYPERLINK(\"http://x\"):3"
    assert (first["coverage"], first["scope"], first["note"]) == ("'-1", "'\t=1", "'\r=1")
    assert (first["seq"], first["level"], first["status"], first["tokens_in"], first["tokens_out"]) == ("1", "2", "sent", "5", "6")
    assert (second["level"], second["model"], second["tokens_in"], second["markers_by_kind"]) == ("n/a", "", "", "")  # -1 is a restore
    assert second["payload_sha256"] == "ab" * 32 and second["versions"] == "boxed:0.1.0"
    assert all(not cell.startswith(("=", "+", "-", "@", "\t", "\r")) for row in (first, second) for cell in row.values())


def test_csv_covers_the_period_in_journal_order(week):
    day = date(2026, 10, 20)
    _, rows = csv_rows(to_csv(week.entries(), since=day, until=day))
    assert [r["seq"] for r in rows] == ["4", "5", "6"]
    assert [r["seq"] for r in csv_rows(to_csv(week.entries()))[1]] == [str(n) for n in range(1, 8)]
    assert [r["seq"] for r in csv_rows(to_csv(week.entries(), since=day))[1]] == ["4", "5", "6", "7"]
    header, none = csv_rows(to_csv(week.entries(), since=date(2026, 10, 30)))
    assert header == CSV_HEADER and none == []  # an empty period is still a CSV with its header


def test_csv_has_a_column_for_every_journal_field():
    """The journal grows by JournalEntry fields: a new one must reach the CSV or be left out on purpose, here."""
    recorded = {f.name for f in fields(JournalEntry)} | {"seq", "ts"}
    assert recorded - {"usage"} <= set(CSV_COLUMNS)
    assert {"tokens_in", "tokens_out"} <= set(CSV_COLUMNS) and not {"prev_hash", "hash", "sig"} & set(CSV_COLUMNS)


def test_summarize_counts_and_period(week):
    s = summarize(week.entries())
    assert (s.since, s.until, s.records) == (None, None, 7)
    assert s.by_channel == Counter({"mcp": 2, "manual": 2, "claude-code": 1, "extension": 1, "workspace": 1})
    assert s.by_provider == Counter({"client": 2, "unknown": 2, "anthropic": 1, "openai": 1, "local": 1})
    assert s.by_account_type == Counter({"unknown": 5, "personal-training": 1, "local": 1})
    assert s.by_level == Counter({2: 3, 1: 1, 3: 1, 4: 1, -1: 1})
    assert s.by_status == Counter({"sent": 3, "prepared": 2, "blocked": 1, "received": 1})
    assert s.markers_by_kind == Counter({"EMAIL": 4, "PHONE": 3, "SECRET": 2, "IP": 2})
    assert s.by_day == {
        "2026-10-19": Counter({"sent": 2, "blocked": 1}),
        "2026-10-20": Counter({"prepared": 1, "received": 1, "sent": 1}),
        "2026-10-21": Counter({"prepared": 1}),
    }


def test_summarize_period_includes_both_end_days(week):
    day = date(2026, 10, 20)
    one_day = summarize(week.entries(), since=day, until=day)
    assert (one_day.since, one_day.until, one_day.records) == (day, day, 3)
    assert one_day.by_status == Counter({"prepared": 1, "received": 1, "sent": 1})
    assert one_day.markers_by_kind == Counter({"PHONE": 3, "EMAIL": 1})
    assert list(one_day.by_day) == ["2026-10-20"]
    assert summarize(week.entries(), since=day).records == 4
    assert summarize(week.entries(), until=day).records == 6
    assert summarize(week.entries(), since=date(2026, 10, 22)).records == 0


def test_summarize_empty_journal():
    assert summarize([]) == Summary()
    assert Summary().records == 0 and Summary().by_day == {}


def test_summarize_survives_damaged_records():
    """A hand-edited record must not stop the page that says the journal is broken."""
    odd = [
        {"seq": 1, "hash": "x"},
        {"seq": 2, "hash": "y", "ts": "not a time", "channel": 5, "level": "high", "status": None,
         "markers_by_kind": {"EMAIL": "many", "SECRET": 2, "IP": True, "PHONE": 1.5}},
        {"seq": 3, "hash": "z", "level": [1], "provider": ["a"], "markers_by_kind": [1, 2]},
    ]
    s = summarize(odd)
    assert s.records == 3
    assert s.by_channel == s.by_provider == s.by_account_type == s.by_status == Counter({"unknown": 3})
    assert s.by_level == Counter({"unknown": 3})
    assert s.markers_by_kind == Counter({"SECRET": 2})
    assert s.by_day == {"unknown": Counter({"unknown": 3})}
    assert summarize(odd, since=date(2026, 1, 1)).records == 0  # an undated record cannot sit in a period


def rewrite(path, fn):
    lines = path.read_text().splitlines()
    path.write_text("\n".join(fn(lines)) + "\n")


def edit_level(lines):
    rec = json.loads(lines[1])
    rec["level"] = 0
    lines[1] = json.dumps(rec)
    return lines


def page_of(journal, **period):
    records, damaged = journal.read()
    return render_html(summarize(records, **period), journal.verify(), damaged)


def page_text(page):
    """What a reader sees: tags dropped, whitespace collapsed."""
    return " ".join(re.sub(r"<[^>]*>", " ", page).split())


class Balanced(HTMLParser):
    def __init__(self):
        super().__init__()
        self.open, self.stray = [], []

    def handle_starttag(self, tag, attrs):
        if tag != "meta":
            self.open.append(tag)

    def handle_endtag(self, tag):
        if not self.open or self.open.pop() != tag:
            self.stray.append(tag)


EXTERNAL = ("http", "<script", "src=", "href=", "url(", "@import", "<link", "<img", "<iframe", "<object", "<embed", "<form")


def test_html_is_self_contained_and_shows_verify_state(week):
    page = page_of(week)
    assert not [needle for needle in EXTERNAL if needle in page.lower()]
    text = page_text(page)
    assert "Chain OK" in text and "BROKEN" not in page
    for shown in (
        "Records 7", "Sent 3", "Blocked 1", "Markers 11",
        "mcp 2", "claude-code 1", "openai 1", "personal-training 1",
        "EMAIL 4", "SECRET 2", "sent 3", "prepared 2",
        "By level 1 1 2 3 3 1 4 1 n/a 1",
        "By day (UTC) Day prepared sent received blocked error Total 2026-10-19 0 2 0 1 0 3",
    ):
        assert shown in text
    rewrite(week.path, edit_level)
    broken = page_text(page_of(week))
    assert "Chain BROKEN" in broken and "record 2: hash does not match content" in broken
    assert "failed verification" in broken and "Chain OK" not in broken


def test_html_markup_is_balanced(week):
    page = page_of(week)
    parser = Balanced()
    parser.feed(page)
    parser.close()
    assert parser.open == [] and parser.stray == []
    assert page.startswith("<!doctype html>")


@pytest.mark.parametrize(
    "since, until, shown",
    [
        (None, None, "all records"),
        (date(2026, 10, 13), None, "since 2026-10-13"),
        (None, date(2026, 10, 19), "until 2026-10-19"),
        (date(2026, 10, 13), date(2026, 10, 19), "2026-10-13 to 2026-10-19"),
    ],
)
def test_html_names_the_period_and_handles_an_empty_summary(since, until, shown):
    page = render_html(Summary(since=since, until=until), VerifyReport(True, 0, None, "ok"))
    text = page_text(page)
    assert f"Period: {shown}." in text and "Records 0" in text and "Chain OK" in text


def test_html_notes_damaged_lines_and_the_period(week):
    with week.path.open("a") as f:
        f.write('{"seq": 8, "torn')
    text = page_text(page_of(week, since=date(2026, 10, 20), until=date(2026, 10, 21)))
    assert "2026-10-20 to 2026-10-21" in text and "Records 4" in text
    assert "1 damaged line " in text and "Chain BROKEN" in text


def test_html_escapes_journal_text():
    nasty = {"seq": 1, "hash": "h", "ts": "2026-10-19T12:00:00+00:00", "channel": "<script>alert(1)</script>", "provider": "a&b"}
    page = render_html(summarize([nasty]), VerifyReport(False, 0, 1, "record <1>: bad"))
    assert "<script" not in page and "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "a&amp;b" in page and "record &lt;1&gt;: bad" in page


def test_html_shows_no_journal_text_beyond_counts(journal):
    journal.append(entry(note="ivan@acme.com asked about AKIAIOSFODNN7EXAMPLE"))
    page = page_of(journal)
    for hidden in ("ivan@acme.com", "AKIAIOSFODNN7EXAMPLE", "ws-1", "ab" * 32):
        assert hidden not in page


def section_of(page, name):
    found = re.search(rf"<section id={name}>(.*?)</section>", page, re.S)
    assert found, f"the page has no section {name}"
    return found.group(1)


class Cells(HTMLParser):
    """The text of every cell of every table, row by row."""

    def __init__(self):
        super().__init__()
        self.rows, self._cell = [], None

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self.rows.append([])
        elif tag in ("td", "th"):
            self._cell = []

    def handle_endtag(self, tag):
        if tag in ("td", "th"):
            self.rows[-1].append(" ".join("".join(self._cell).split()))
            self._cell = None

    def handle_data(self, data):
        if self._cell is not None:
            self._cell.append(data)


def rows_of(fragment):
    parser = Cells()
    parser.feed(fragment)
    parser.close()
    return parser.rows


def test_overview_shows_models_and_tokens_as_reported_by_the_provider(api_calls):
    text = page_text(section_of(page_of(api_calls), "overview"))
    assert "By model gpt-5 2 claude-x 1 deepseek-chat 1" in text
    assert "Tokens, as reported by the provider input 250 output 50" in text
    assert "By channel api 4 mcp 1" in text and "By account type personal-private 3" in text
    only_input = summarize(api_calls.entries(), since=date(2026, 10, 20), until=date(2026, 10, 20))  # deepseek reported no output
    text = page_text(section_of(render_html(only_input, OK_VERDICT), "overview"))
    assert "Tokens, as reported by the provider input 50 output 0" in text


OPENROUTER = dict(model="vendor/m")
SPEND_CALLS = [
    (19, entry("api", "openrouter", "personal-training", 2, "received", {}, usage={"input": 8, "output": 3, "cost_micro_usd": 1_500}, **OPENROUTER)),
    (19, entry("api", "openrouter", "api-zero-retention", 2, "received", {}, usage={"cost_micro_usd": 2_500}, **OPENROUTER)),
    (20, entry("api", "openrouter", "personal-training", 2, "received", {}, usage={"input": 1, "cost_micro_usd": 0}, **OPENROUTER)),
    (20, entry("api", "openai", "personal-private", 2, "received", {}, model="gpt-5", usage={"input": 5, "output": 5})),
    (20, entry("api", "openrouter", "personal-training", 2, "sent", {"EMAIL": 1}, **OPENROUTER)),
]


@pytest.fixture
def spend_calls(journal, clock):
    """Five API records over two days; the spend numbers in the tests below are counted from this table."""
    for day, e in SPEND_CALLS:
        clock(day)
        journal.append(e)
    return journal


def test_summary_adds_up_the_cost_the_provider_reported(spend_calls):
    s = summarize(spend_calls.entries())
    assert (s.spend_micro_usd, s.spend_records) == (4_000, 3)  # a cost of 0 was reported too; the OpenAI and "sent" records have none
    day = date(2026, 10, 20)
    assert (summarize(spend_calls.entries(), since=day, until=day).spend_micro_usd, summarize(spend_calls.entries(), since=day).spend_records) == (0, 1)
    assert (summarize([]).spend_micro_usd, summarize([]).spend_records) == (0, 0)
    assert (s.tokens_in, s.tokens_out) == (9 + 5, 3 + 5)  # the tokens are counted as before


def test_a_cost_that_nobody_could_have_reported_is_not_added():
    stamp = "2026-10-19T12:00:00+00:00"
    values = [-1, 10**9 + 1, "5", True, 2.5, None, [1], {"x": 1}]
    odd = [{"seq": n, "hash": "h", "ts": stamp, "usage": {"input": 1, "cost_micro_usd": value}} for n, value in enumerate(values, start=1)]
    odd += [{"seq": 20, "hash": "h", "ts": stamp, "usage": "lots"}, {"seq": 21, "hash": "h", "ts": stamp}]
    s = summarize(odd)
    assert (s.spend_micro_usd, s.spend_records) == (0, 0) and s.tokens_in == 8
    best = summarize([{"seq": 1, "hash": "h", "ts": stamp, "usage": {"cost_micro_usd": 10**9}}])
    assert (best.spend_micro_usd, best.spend_records) == (10**9, 1)  # the most one record is believed to hold


def spend_box(page):
    found = re.search(r"<div class=box><h2>Spend reported by the provider</h2>(.*?)</div>", page, re.S)
    return " ".join(re.sub(r"<[^>]*>", " ", found.group(1)).split()) if found else None


def test_overview_shows_the_spend_when_any_record_has_one(spend_calls):
    page = page_of(spend_calls)
    assert spend_box(page).startswith("$0.004 ") and "3 records reported a cost" in spend_box(page)
    assert "records without a reported cost are not counted" in spend_box(page).lower()
    overview = section_of(page, "overview")
    assert re.findall(r"<div class=box><h2>(.*?)</h2>", overview)[5:8] == [
        "Tokens, as reported by the provider", "Spend reported by the provider", "By level",
    ]
    parser = Balanced()
    parser.feed(page)
    parser.close()
    assert parser.open == [] and parser.stray == []
    plain = render_html(summarize([{"seq": 1, "hash": "h", "ts": STAMP, "model": "gpt-5", "usage": {"input": 5, "output": 5}}]), OK_VERDICT)
    assert spend_box(plain) is None and "Spend reported" not in plain  # no record has a cost: no box


@pytest.mark.parametrize(
    ("micro", "shown"),
    [(0, "$0.00"), (1, "$0.000001"), (4_000, "$0.004"), (999_999, "$0.999999"), (1_500_000, "$1.50"), (3_000_000, "$3.00"), (12_345_678, "$12.345678"),
     (10**9, "$1000.00")],
)
def test_the_spend_is_shown_in_dollars_without_rounding_it(micro, shown):
    s = summarize([{"seq": 1, "hash": "h", "ts": "2026-10-19T12:00:00+00:00", "usage": {"cost_micro_usd": micro}}])
    assert spend_box(render_html(s, OK_VERDICT)).startswith(shown + " ")


def test_csv_has_the_cost_of_a_record_when_it_reports_one(spend_calls):
    _, rows = csv_rows(to_csv(spend_calls.entries()))
    assert [r["cost_micro_usd"] for r in rows] == ["1500", "2500", "0", "", ""]
    bad = [{"seq": 1, "hash": "h", "ts": "2026-10-19T12:00:00+00:00", "usage": {"input": 4, "cost_micro_usd": -5}}]
    row = csv_rows(to_csv(bad))[1][0]
    assert (row["tokens_in"], row["cost_micro_usd"]) == ("4", "")  # a cost nobody could have reported is an empty cell


def test_overview_says_so_when_no_model_or_token_was_reported(week):
    text = page_text(section_of(page_of(week), "overview"))
    assert "By model nothing Tokens, as reported by the provider none reported By level" in text


def test_overview_lists_its_boxes_in_order(api_calls):
    overview = section_of(page_of(api_calls), "overview")
    assert re.findall(r"<div class=box><h2>(.*?)</h2>", overview) == [
        "Markers by kind", "By channel", "By provider", "By account type", "By model", "Tokens, as reported by the provider",
        "By level", "By status", "By day (UTC)",
    ]


def test_levels_are_listed_in_order_then_restores_then_unreadable_ones():
    recs = [{"seq": n, "hash": "h", "ts": STAMP, "level": level} for n, level in enumerate(["high", 4, -1, 0, 2, "high", 1], start=1)]
    text = page_text(section_of(render_html(summarize(recs), OK_VERDICT), "overview"))
    assert "By level 0 1 1 1 2 1 4 1 n/a 1 unknown 2" in text


def test_a_page_without_damaged_lines_says_nothing_about_them():
    assert "damaged" not in page_text(render_html(Summary(), OK_VERDICT))  # the default is none


JOURNAL_HEAD = ["Seq", "Time", "Channel", "Provider", "Model", "Account type", "Level", "Markers", "Tokens", "Status"]


def test_journal_table_lists_the_newest_rows_and_says_when_it_is_capped(api_calls):
    records = api_calls.entries()
    page = render_html(summarize(records), api_calls.verify(), rows=journal_rows(records, limit=3))
    table = rows_of(section_of(page, "journal"))
    assert table[0] == JOURNAL_HEAD
    assert table[1:] == [
        ["5", "2026-10-20T12:00:00+00:00", "mcp", "client", "-", "unknown", "2", "EMAIL:1", "-", "sent"],
        ["4", "2026-10-20T12:00:00+00:00", "api", "anthropic", "claude-x", "personal-private", "2", "-", "-", "error"],
        ["3", "2026-10-20T12:00:00+00:00", "api", "deepseek", "deepseek-chat", "personal-training", "3", "PHONE:2", "50 in", "sent"],
    ]
    assert "Showing the newest 3 of 5 records." in page_text(section_of(page, "journal"))
    assert "<td class=nw>3</td><td class=nw>2026-10-20T12:00:00+00:00</td>" in section_of(page, "journal")  # the numbers do not wrap
    whole = render_html(summarize(records), api_calls.verify(), rows=journal_rows(records))
    assert rows_of(section_of(whole, "journal"))[-1][8] == "120 in / 30 out" and "Showing" not in whole  # nothing was cut
    assert "id=journal" not in render_html(summarize(records), api_calls.verify())  # no rows given, no table


def test_journal_table_shows_a_restore_without_a_level(week):
    records = week.entries()
    page = render_html(summarize(records), week.verify(), rows=journal_rows(records))
    restore = next(row for row in rows_of(section_of(page, "journal")) if row[0] == "5")
    assert restore[JOURNAL_HEAD.index("Level")] == "n/a" and restore[JOURNAL_HEAD.index("Status")] == "received"


def watched(site, kinds, coverage="checked"):
    """A record of the observation journal: the shape of any journal record, channel "observed", the site as provider."""
    return JournalEntry(
        channel="observed", provider=site, account_type="unknown", level=0, markers_by_kind=kinds, status="sent",
        payload_sha256="cd" * 32, coverage=coverage, scope="", versions={"boxed": "0.1.0"},
    )


SEEN = [
    (19, watched("chatgpt", {"EMAIL": 2})),
    (19, watched("claude", {"SECRET": 1, "JWT": 1})),
    (20, watched("chatgpt", {})),
    (20, watched("deepseek", {}, "not checked")),
    (21, watched("gemini", {"PRIVATE_KEY": 1})),
]


@pytest.fixture
def seen(tmp_path, clock):
    """The observation journal: its own file, as the host keeps it; five sends over three days."""
    observed = Journal(tmp_path / "observed.jsonl", InsecureFileKeyStore(tmp_path / "keys"))
    for day, e in SEEN:
        clock(day)
        observed.append(e)
    return observed


OK_VERDICT = VerifyReport(True, 0, None, "ok")
THROUGH_THE_20TH = Summary(since=date(2026, 10, 19), until=date(2026, 10, 20))


def test_observed_section_advises_revoking_keys(seen):
    page = render_html(THROUGH_THE_20TH, OK_VERDICT, observed=seen.entries())
    text = page_text(section_of(page, "observed"))
    for shown in (
        "Sent without boxed", "Sends 4", "Sends with findings 2",
        "Kinds EMAIL 2 JWT 1 SECRET 1", "Sites chatgpt 2 claude 1 deepseek 1", "Coverage checked 3 not checked 1",
    ):
        assert shown in text
    assert "Revoke and replace the keys and tokens that were sent (SECRET, JWT)" in text
    assert "masking later cannot undo a send" in text
    assert "PRIVATE_KEY" not in text and "gemini" not in text  # a send of the 21st is outside the period
    assert "1 send could not be checked, so the counts may be too low" in text


def test_observed_section_gives_no_advice_without_keys_and_names_every_key_kind(seen):
    mails = [r for r in seen.entries() if "SECRET" not in r["markers_by_kind"] and "PRIVATE_KEY" not in r["markers_by_kind"]]
    assert "Revoke" not in page_text(section_of(render_html(Summary(), OK_VERDICT, observed=mails), "observed"))
    page = render_html(Summary(), OK_VERDICT, observed=seen.entries())  # no period: all five sends
    assert "(SECRET, PRIVATE_KEY, JWT)" in page_text(section_of(page, "observed"))


def test_a_send_has_findings_only_with_a_positive_count_and_gaps_show_only_when_there_are_some():
    """Observed records are plain data: dicts of the journal's shape are enough."""
    kinds = ({"EMAIL": 0}, {}, {"EMAIL": 1}, {"PHONE": 2, "IP": 0})
    plain = [{"provider": "chatgpt", "coverage": "checked", "markers_by_kind": k, "ts": "2026-10-19T12:00:00+00:00"} for k in kinds]
    text = page_text(section_of(render_html(Summary(), OK_VERDICT, observed=plain), "observed"))
    assert "Sends 4" in text and "Sends with findings 2" in text
    assert "could not be checked" not in text and "Revoke" not in text


def test_observed_section_with_nothing_seen_does_not_claim_nothing_was_sent():
    text = page_text(section_of(render_html(Summary(), OK_VERDICT, observed=[]), "observed"))
    assert "Sends 0" in text and "Sends with findings 0" in text and "Revoke" not in text
    assert "No sends were observed in this period" in text and "not proof that nothing was sent" in text
    assert "id=observed" not in render_html(Summary(), OK_VERDICT)  # not given: the section is left out


CHECKS = [
    {"provider": "chatgpt", "account": "personal", "training": "off", "memory": "off", "source": "asked",
     "checked_at": "2026-10-10", "due": False, "settings_url": "https://chatgpt.com/#settings/DataControls"},
    {"provider": "claude", "account": "work", "training": "unknown", "memory": "on", "source": "asked",
     "checked_at": "2026-08-01", "due": True, "settings_url": "https://claude.ai/settings/data-privacy-controls"},
    {"provider": "deepseek", "account": "main", "training": "on", "memory": "unknown", "source": "asked",
     "checked_at": "2026-10-20", "due": False, "settings_url": None},
]
CHECKS_HEAD = ["Provider", "Account", "Training", "Memory", "Source", "Checked", "Settings page", "Due"]
NOTE = "Training off does not mean nothing is stored: providers still keep chats for a while."
STRICTER = "treated as personal-training, the stricter recipient"


def test_checks_section_marks_due():
    section = section_of(render_html(Summary(), OK_VERDICT, checks=CHECKS), "checks")
    assert rows_of(section) == [
        CHECKS_HEAD,
        ["chatgpt", "personal", "off", "off", "asked", "2026-10-10", "https://chatgpt.com/#settings/DataControls", ""],
        ["claude", "work", "unknown", "on", "asked", "2026-08-01", "https://claude.ai/settings/data-privacy-controls", "due"],
        ["deepseek", "main", "on", "unknown", "asked", "2026-10-20", "-", ""],
    ]
    text = page_text(section)
    assert "Training on chats" in text and NOTE in text and STRICTER in text
    assert "href" not in section  # the settings page is text to copy: the page links to nothing


def test_unreadable_check_values_read_as_unknown_and_due():
    odd = [{"provider": "chatgpt", "account": "x", "training": "maybe", "memory": ["on"], "due": "no"}, "not a check", {}]
    table = rows_of(section_of(render_html(Summary(), OK_VERDICT, checks=odd), "checks"))
    assert table[1:] == [
        ["chatgpt", "x", "unknown", "unknown", "unknown", "unknown", "-", "due"],
        ["unknown", "unknown", "unknown", "unknown", "unknown", "unknown", "-", "due"],
        ["unknown", "unknown", "unknown", "unknown", "unknown", "unknown", "-", "due"],
    ]  # only exactly "off" is shown as off, and only exactly False is not due


def test_the_note_on_checks_has_one_home():
    """The page shows the sentence that checks.py defines for the host and the CLI too; a second copy could drift from it."""
    homes = sorted(path.name for path in Path(boxed.__file__).parent.glob("*.py") if NOTE in path.read_text(encoding="utf-8"))
    assert homes == ["checks.py"]
    assert NOTE == checks.NOTE


def test_no_checks_say_unknown_and_the_stricter_recipient():
    text = page_text(section_of(render_html(Summary(), OK_VERDICT), "checks"))  # the default is no checks
    assert "No training checks recorded yet" in text and NOTE in text and STRICTER in text


def test_unreadable_checks_say_so_and_stay_unknown():
    """None is what the caller passes when checks.json is damaged: not "none recorded", and never a state that reads as off."""
    section = section_of(render_html(Summary(), OK_VERDICT, checks=None), "checks")
    text = page_text(section)
    assert "could not be read" in text and "No training checks recorded yet" not in text
    assert NOTE in text and STRICTER in text and not rows_of(section)  # no row, so no account looks as if training were off


def test_policy_matrix_rendered():
    policy = Policy.from_config({"profile": "no-confidential", "rules": {"finance:personal-private": "deny"}})
    table = rows_of(section_of(render_html(Summary(), OK_VERDICT, policy=policy), "policy"))
    assert table[0] == ["Category", *RECIPIENT_KINDS]
    assert [row[0] for row in table[1:]] == list(CATEGORIES)
    by_category = {row[0]: dict(zip(RECIPIENT_KINDS, row[1:], strict=True)) for row in table[1:]}
    assert by_category["finance"] == {
        "personal-training": "masked:3", "personal-private": "deny", "corporate": "masked:3", "api-zero-retention": "masked:3", "local": "allow",
    }
    assert by_category["hr"]["personal-training"] == "local-only" and by_category["secrets"]["corporate"] == "masked:0"
    assert {row["local"] for row in by_category.values()} == {"allow"}
    assert "id=policy" not in render_html(Summary(), OK_VERDICT)  # no policy given, no matrix
    empty = section_of(render_html(Summary(), OK_VERDICT, policy=Policy({})), "policy")
    assert "no rule" in page_text(empty)  # a pair without a rule is shown as that: decide() refuses it


EVIL = "<script>alert(1)</script>\"'&"


@pytest.fixture
def make_page(journal, tmp_path, clock):
    """make_page(evil) renders every section with `evil` as each name that comes from a record or a check; no argument: real names."""

    def make(evil=None):
        def pick(real):
            return evil or real

        clock(19)
        journal.append(
            replace(
                entry(pick("api"), pick("openai"), pick("personal-private"), 2, "sent", {pick("EMAIL"): 2},
                      model=pick("gpt-5"), usage={"input": 5, "output": 6}),
                note=pick("fine"), coverage=pick("full"),
            )
        )
        records, damaged = journal.read()
        observed = Journal(tmp_path / "observed.jsonl", InsecureFileKeyStore(tmp_path / "keys"))
        observed.append(watched(pick("chatgpt"), {pick("EMAIL"): 1, "SECRET": 1}, pick("checked")))
        checks = [
            {"provider": pick("chatgpt"), "account": pick("personal"), "training": pick("off"), "memory": pick("off"),
             "source": pick("asked"), "checked_at": pick("2026-10-10"), "due": True if evil is None else evil,
             "settings_url": pick("https://chatgpt.com/#settings/DataControls")},
        ]
        return render_html(
            summarize(records), journal.verify(), damaged,
            rows=journal_rows(records), observed=observed.entries(), checks=checks, policy=Policy.from_profile("no-rules"),
        )

    return make


class Markup(HTMLParser):
    """Every tag and attribute of a page."""

    def __init__(self):
        super().__init__()
        self.tags, self.attrs = set(), []

    def handle_starttag(self, tag, attrs):
        self.tags.add(tag)
        self.attrs += attrs


def markup_of(page):
    parser = Markup()
    parser.feed(page)
    parser.close()
    return parser


OUR_TAGS = {"html", "head", "meta", "title", "style", "body", "h1", "h2", "p", "div", "span", "b", "i", "section", "table", "tr", "th", "td"}
OUR_ATTRS = {"lang", "charset", "name", "content", "class", "id", "style"}


def test_every_value_is_escaped(make_page):
    """EVIL stands as provider, site, account, model and kind: in the overview, the journal, the observed and the checks sections."""
    page = make_page(EVIL)
    assert EVIL not in page and "<script" not in page.lower()
    for name in ("overview", "journal", "observed", "checks"):
        assert html.escape(EVIL) in section_of(page, name), name
    markup = markup_of(page)
    assert markup.tags <= OUR_TAGS and {name for name, _ in markup.attrs} <= OUR_ATTRS  # nothing broke out into a tag or an attribute
    assert not [value for _, value in markup.attrs if value and ("alert" in value or "&" in value)]


def test_full_page_stays_self_contained_and_balanced(make_page):
    page = make_page()
    markup = markup_of(page)
    assert markup.tags <= OUR_TAGS and {name for name, _ in markup.attrs} <= OUR_ATTRS
    assert not [value for _, value in markup.attrs if value and ("http" in value or "/" in value)]
    assert not [needle for needle in ("<script", "src=", "href=", "url(", "@import", "<link", "<img", "<iframe", "<form") if needle in page.lower()]
    for section in ("overview", "journal", "observed", "checks", "policy"):
        assert f"<section id={section}>" in page
    parser = Balanced()
    parser.feed(page)
    parser.close()
    assert parser.open == [] and parser.stray == []


FORMAT = "boxed-journal-export/1"
STRANGER_KEY = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def received(export):
    """What the security team holds: a JSON file."""
    return json.loads(json.dumps(export))


def test_export_verifies_without_keys(week, tmp_path, monkeypatch):
    export = export_for_security(week)
    assert set(export) == {"format", "public_key", "verify", "entries"}
    assert export["format"] == FORMAT and export["public_key"] == week.public_key_hex()
    assert export["verify"] == {"ok": True, "count": 7, "first_bad": None, "reason": "ok"}
    assert export["entries"] == week.entries()
    sent = received(export)
    week.path.unlink()  # from here on only the file exists: no journal, no key store
    shutil.rmtree(tmp_path / "keys")
    monkeypatch.setattr(InsecureFileKeyStore, "get_or_create", lambda *a: pytest.fail("verify_export must not read keys"))
    report = verify_export(sent)
    assert (report.ok, report.count, report.first_bad, report.reason) == (True, 7, None, "ok")


def test_export_survives_unicode_notes_through_json(journal):
    journal.append(entry(note='Привет, мир   \U0001f600 "quoted" \\ back'))
    journal.append(entry())
    assert verify_export(received(export_for_security(journal))).ok


def swap_entries(export):
    export["entries"][1], export["entries"][2] = export["entries"][2], export["entries"][1]


def edit_and_rehash(export):
    """An editor who recomputes the hash by the documented rule still has no key to sign it with."""
    rec = export["entries"][1]
    rec["level"] = 0
    body = {k: v for k, v in rec.items() if k not in ("hash", "sig")}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    rec["hash"] = hashlib.sha256(canonical.encode()).hexdigest()


TAMPERS = {
    "edited field": (lambda e: e["entries"][1].update(level=0), 2, "hash does not match content"),
    "edited count": (lambda e: e["entries"][2]["markers_by_kind"].update(SECRET=0), 3, "hash does not match content"),
    "added field": (lambda e: e["entries"][1].update(note="x"), 2, "hash does not match content"),
    "hash recomputed without the key": (edit_and_rehash, 2, "bad signature"),
    "forged signature": (lambda e: e["entries"][1].update(sig="00" * 64), 2, "bad signature"),
    "missing signature": (lambda e: e["entries"][1].pop("sig"), 2, "bad signature"),
    "wrong key": (lambda e: e.update(public_key=STRANGER_KEY), 1, "bad signature"),
    "removed record": (lambda e: e["entries"].pop(2), 4, "chain break"),
    "swapped records": (swap_entries, 3, "chain break"),
    "duplicated record": (lambda e: e["entries"].insert(2, dict(e["entries"][1])), 2, "chain break"),
}


@pytest.mark.parametrize("tamper, first_bad, reason", list(TAMPERS.values()), ids=list(TAMPERS))
def test_tampered_export_fails(week, tamper, first_bad, reason):
    export = received(export_for_security(week))
    tamper(export)
    report = verify_export(export)
    assert not report.ok and report.first_bad == first_bad and reason in report.reason


@pytest.mark.parametrize(
    "broken",
    [
        None,
        [],
        "text",
        {},
        {"format": "boxed-journal-export/2", "public_key": STRANGER_KEY, "entries": []},
        {"format": FORMAT, "entries": []},
        {"format": FORMAT, "public_key": "zz", "entries": []},
        {"format": FORMAT, "public_key": "ab" * 5, "entries": []},
        {"format": FORMAT, "public_key": 7, "entries": []},
        {"format": FORMAT, "public_key": STRANGER_KEY},
        {"format": FORMAT, "public_key": STRANGER_KEY, "entries": {"seq": 1}},
        {"format": FORMAT, "public_key": STRANGER_KEY, "entries": [None]},
        {"format": FORMAT, "public_key": STRANGER_KEY, "entries": [{}]},
        {"format": FORMAT, "public_key": STRANGER_KEY, "entries": [{"seq": "1", "hash": "x"}]},
        {"format": FORMAT, "public_key": STRANGER_KEY, "entries": [{"seq": True, "hash": "x"}]},
        {"format": FORMAT, "public_key": STRANGER_KEY, "entries": [{"seq": 1, "hash": "x", "sig": 5}]},
    ],
)
def test_malformed_export_is_refused_without_crashing(broken):
    report = verify_export(broken)
    assert isinstance(report, VerifyReport) and not report.ok


def test_slice_export_verifies(week):
    until_19 = export_for_security(week, until=date(2026, 10, 19))
    only_20 = export_for_security(week, since=date(2026, 10, 20), until=date(2026, 10, 20))
    from_20 = export_for_security(week, since=date(2026, 10, 20))
    assert [r["seq"] for r in until_19["entries"]] == [1, 2, 3]
    assert [r["seq"] for r in only_20["entries"]] == [4, 5, 6]
    assert [r["seq"] for r in from_20["entries"]] == [4, 5, 6, 7]
    assert only_20["entries"][0]["prev_hash"] == week.entries()[2]["hash"]  # the slice hangs on the record before it
    for export in (until_19, only_20, from_20):
        report = verify_export(received(export))
        assert (report.ok, report.count, report.first_bad) == (True, len(export["entries"]), None)
        assert export["verify"]["count"] == 7  # the verdict is on the whole journal, not on the slice
    only_20["entries"].pop(1)
    assert verify_export(only_20).first_bad == 6
    empty = export_for_security(week, since=date(2026, 10, 30))
    assert empty["entries"] == [] and (verify_export(empty).ok, verify_export(empty).count) == (True, 0)


def test_export_of_a_tampered_journal_carries_the_verdict(week):
    rewrite(week.path, edit_level)
    export = export_for_security(week)
    assert export["verify"]["ok"] is False and export["verify"]["first_bad"] == 2
    assert export["entries"] == week.entries() and len(export["entries"]) == 7
    report = verify_export(received(export))
    assert (report.ok, report.first_bad) == (False, 2)


def test_export_leaves_out_damaged_lines_and_says_so(week):
    with week.path.open("a") as f:
        f.write('{"seq": 8, "torn')
    export = export_for_security(week)
    assert len(export["entries"]) == 7
    assert export["verify"]["ok"] is False and "damaged" in export["verify"]["reason"]
    assert verify_export(received(export)).ok  # the whole records still chain; the verdict above carries the damage


def swap_lines(lines):
    lines[1], lines[2] = lines[2], lines[1]
    return lines


def drop_a_line(lines):
    del lines[2]
    return lines


def repeat_a_line(lines):
    lines.insert(2, lines[1])
    return lines


@pytest.mark.parametrize("damage", [lambda lines: lines, edit_level, drop_a_line, swap_lines, repeat_a_line])
def test_export_check_agrees_with_the_journal_check(week, damage):
    """The two checks are written apart: whatever the journal calls broken, the export must call broken the same way."""
    rewrite(week.path, damage)
    assert verify_export(export_for_security(week)) == week.verify()


def test_verify_export_trusts_the_key_in_the_file(week, tmp_path):
    """A forger who signs with their own key gets a clean check: compare export["public_key"] with the key on record."""
    forger = Journal(tmp_path / "forged.jsonl", InsecureFileKeyStore(tmp_path / "forger-keys"))
    forger.append(entry())
    forged = export_for_security(forger)
    assert verify_export(forged).ok
    assert forged["public_key"] != week.public_key_hex()


def test_hostile_export_fields_give_a_failed_report(journal):
    journal.append(entry())
    surrogate = export_for_security(journal)
    surrogate["entries"][0]["note"] = "\ud800"
    deep = export_for_security(journal)
    node = deep["entries"][0]
    for _ in range(100_000):
        node["x"] = {}
        node = node["x"]
    assert not verify_export(surrogate).ok and not verify_export(deep).ok


def test_period_export_survives_a_clock_step_back(journal, clock):
    for day in (20, 20, 18, 20, 21):
        clock(day)
        journal.append(entry())
    export = export_for_security(journal, since=date(2026, 10, 19))
    assert [r["seq"] for r in export["entries"]] == [1, 2, 3, 4, 5] and verify_export(export).ok


# Smaller issues of the first dashboard: each test was written before its fix.


def rechain(journal, tmp_path, first_prev, edit=lambda rec, i: None):
    """Rewrite the journal as a chain that starts from `first_prev`, every record re-hashed and re-signed with the device key:
    what only the owner of the key can do. The links are set first, then edit(record, index) may break one of them."""
    key = Ed25519PrivateKey.from_private_bytes(InsecureFileKeyStore(tmp_path / "keys").get_or_create("device-signing-key", 32))
    prev, lines = first_prev, []
    for i, rec in enumerate(journal.entries()):
        rec = {k: v for k, v in rec.items() if k not in ("hash", "sig")} | {"prev_hash": prev}
        edit(rec, i)
        rec["hash"] = hashlib.sha256(json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        rec["sig"] = key.sign(bytes.fromhex(rec["hash"])).hex()
        prev = rec["hash"]
        lines.append(json.dumps(rec, ensure_ascii=False))
    journal.path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_first_record_must_start_at_genesis(week, tmp_path):
    rechain(week, tmp_path, first_prev="11" * 32)  # record 1 names a predecessor: no journal of this device starts so
    expected = VerifyReport(False, 0, 1, "record 1: chain break")
    assert week.verify() == expected
    assert verify_export(received(export_for_security(week))) == expected
    from_20 = export_for_security(week, since=date(2026, 10, 20))  # a slice does not start at record 1: nothing to compare it with
    assert verify_export(received(from_20)).ok
    rechain(week, tmp_path, first_prev="0" * 64)  # the same records chained from the genesis value
    assert week.verify().ok and verify_export(received(export_for_security(week))).ok


def test_ts_with_offset_counts_on_its_utc_date():
    def at(seq, ts):
        return {"seq": seq, "hash": f"h{seq}", "ts": ts, "status": "sent"}

    west = at(1, "2026-10-19T23:30:00-05:00")  # 04:30 UTC on the 20th
    east = at(2, "2026-10-20T01:30:00+05:00")  # 20:30 UTC on the 19th
    utc = at(3, "2026-10-20T12:00:00+00:00")
    bare = at(4, "2026-10-20T12:00:00")  # no offset: the journal writes UTC, so it reads as UTC
    records = [west, east, utc, bare]
    assert {day: sum(c.values()) for day, c in summarize(records).by_day.items()} == {"2026-10-19": 1, "2026-10-20": 3}
    day = date(2026, 10, 20)
    assert summarize(records, since=day, until=day).records == 3
    assert summarize(records, until=date(2026, 10, 19)).records == 1
    assert [r["seq"] for r in journal_rows(records, since=day, until=day)] == [4, 3, 1]
    assert [r["seq"] for r in csv_rows(to_csv(records, since=day, until=day))[1]] == ["1", "3", "4"]
    edge = [at(5, "0001-01-01T00:00:00+05:00"), at(6, "9999-12-31T23:59:59-05:00")]  # no UTC date exists: unreadable, not a crash
    assert summarize(edge).by_day == {"unknown": Counter({"sent": 2})} and summarize(edge, since=day).records == 0


def test_negative_or_huge_counts_are_ignored():
    stamp = "2026-10-19T12:00:00+00:00"
    odd = [
        {"seq": 1, "hash": "x", "ts": stamp, "markers_by_kind": {"EMAIL": -5, "PHONE": 10**30, "SECRET": 2, "IP": 10**9, "HOST": 10**9 + 1},
         "usage": {"input": -1, "output": 10**30}},
        {"seq": 2, "hash": "y", "ts": stamp, "usage": {"input": 7, "output": 3}},
        {"seq": 3, "hash": "z", "ts": stamp, "usage": {"input": 10**9, "output": 10**9 + 1}},
    ]
    s = summarize(odd)
    assert s.markers_by_kind == Counter({"SECRET": 2, "IP": 10**9})  # 10**9 is the most one record is believed to count
    assert (s.tokens_in, s.tokens_out) == (10**9 + 7, 3)
    rows = journal_rows(odd)
    assert rows[2]["kinds"] == {"IP": 10**9, "SECRET": 2} and rows[2]["tokens"] == {}
    assert rows[1]["tokens"] == {"input": 7, "output": 3} and rows[0]["tokens"] == {"input": 10**9}
    first = csv_rows(to_csv(odd))[1][0]
    assert (first["markers_by_kind"], first["tokens_in"], first["tokens_out"]) == ("IP:1000000000 SECRET:2", "", "")
    unbelievable = [{"provider": "chatgpt", "coverage": "checked", "markers_by_kind": {"EMAIL": -1, "SECRET": 10**30}}]
    text = page_text(section_of(render_html(s, OK_VERDICT, rows=rows, observed=unbelievable), "observed"))
    assert "Sends 1" in text and "Sends with findings 0" in text  # a count nobody could make is no finding ...
    assert "1 send could not be checked" in text and "(SECRET)" in text  # ... and no clean send either: it still warns about the key
    assert str(10**30) not in render_html(s, OK_VERDICT, rows=rows, observed=unbelievable)


def test_long_field_names_are_cut():
    rec = {
        "seq": 1, "hash": "h", "ts": "2026-10-19T12:00:00+00:00", "level": 1, "channel": "c" * 100, "provider": "p" * 100,
        "account_type": "a" * 100, "status": "s" * 100, "model": "m" * 100, "scope": "o" * 100, "note": "n" * 100,
        "coverage": "v" * 100, "versions": {"b" * 100: "w" * 100},
        "markers_by_kind": {"K" * 64 + "1": 1, "K" * 64 + "2": 2},  # two names that differ only beyond the cut share one row
    }
    s = summarize([rec])
    assert list(s.by_channel) == ["c" * 64] and list(s.by_provider) == ["p" * 64] and list(s.by_account_type) == ["a" * 64]
    assert list(s.by_model) == ["m" * 64] and list(s.by_status) == ["s" * 64] and list(s.by_day["2026-10-19"]) == ["s" * 64]
    assert s.markers_by_kind == Counter({"K" * 64: 3})
    row = journal_rows([rec])[0]
    assert [row[k] for k in ("channel", "provider", "model", "account_type", "status")] == ["c" * 64, "p" * 64, "m" * 64, "a" * 64, "s" * 64]
    assert row["kinds"] == {"K" * 64: 3}
    cells = csv_rows(to_csv([rec]))[1][0]
    assert [cells[k] for k in ("channel", "provider", "model", "account_type", "status", "scope", "note", "coverage")] == [
        c * 64 for c in "cpmasonv"
    ]
    assert cells["versions"] == "b" * 64 + ":" + "w" * 64 and cells["markers_by_kind"] == "K" * 64 + ":3"
    page = render_html(
        s, OK_VERDICT, rows=journal_rows([rec]), observed=[rec | {"provider": "S" * 100}],
        checks=[{"provider": "P" * 100, "account": "A" * 100, "source": "R" * 100, "checked_at": "D" * 100, "settings_url": "U" * 100}],
    )
    for letter in "cpamsKSPARDU":
        assert letter * 64 in page and not re.search(f"{letter}{{65}}", page), letter


def test_lone_surrogates_do_not_stop_the_page_or_the_csv_from_being_written():
    """JSON lets a hand-edited record hold a lone surrogate, and a page that cannot be written as UTF-8 is no page at all,
    least of all the one that says the journal is broken. The surrogate shows as its escape."""
    rec = json.loads(
        '{"seq": 1, "hash": "h", "ts": "2026-10-19T12:00:00+00:00", "channel": "a\\ud800", "provider": "\\udfff", '
        '"markers_by_kind": {"K\\ud800": 1}, "scope": "\\ud800", "note": "x\\ud800"}'
    )
    page = render_html(
        summarize([rec]), VerifyReport(False, 0, 1, "record \ud800: bad"),
        rows=journal_rows([rec]), observed=[rec], checks=[{"provider": "\ud800"}],
    )
    assert "a\\ud800" in page_text(page) and "record \\ud800: bad" in page_text(page)
    page.encode("utf-8")
    csv_text = to_csv([rec])
    csv_text.encode("utf-8")
    assert csv_rows(csv_text)[1][0]["note"] == "x\\ud800"
    assert [len(name) for name in summarize([{"channel": "\ud800" * 100}]).by_channel] == [64]  # the escapes count toward the cut


HOSTILE_CHARS = st.one_of(st.characters(), st.sampled_from([*"=+-@\t\r\n<>&\"' ", "\ud800", "\udfff"]))  # lone surrogates are rare
HOSTILE_TEXT = st.builds(
    lambda head, tail: head + tail, st.sampled_from(["", "=", "+", "-", "@", "\t", "\r", "<script>"]), st.lists(HOSTILE_CHARS, max_size=80).map("".join)
)
SCALARS = st.one_of(st.none(), st.booleans(), st.integers(-(10**12), 10**12), st.floats(), HOSTILE_TEXT)
VALUES = st.recursive(
    SCALARS, lambda inner: st.one_of(st.lists(inner, max_size=3), st.dictionaries(HOSTILE_TEXT, inner, max_size=3)), max_leaves=6
)
TIMES = st.sampled_from(
    ["2026-10-19T12:00:00+00:00", "2026-10-19T23:30:00-05:00", "2026-10-20T01:30:00+05:00", "2026-10-20T12:00:00", "0001-01-01T00:00:00+05:00"]
)
COUNTS = st.dictionaries(HOSTILE_TEXT, st.one_of(st.integers(-5, 20), st.integers(10**9 - 1, 10**9 + 1), VALUES), max_size=4)
RECORDS = st.fixed_dictionaries(
    {},
    optional={
        "seq": VALUES, "hash": VALUES, "channel": VALUES, "provider": VALUES, "account_type": VALUES, "status": VALUES,
        "coverage": VALUES, "scope": VALUES, "versions": VALUES, "note": VALUES, "model": VALUES, "level": st.one_of(VALUES, st.integers(-2, 5)),
        "ts": st.one_of(VALUES, TIMES), "markers_by_kind": st.one_of(VALUES, COUNTS),
        "usage": st.one_of(VALUES, st.fixed_dictionaries({"input": VALUES, "output": VALUES})),
    },
)


@settings(max_examples=100, deadline=None)
@given(
    st.lists(RECORDS, max_size=5), st.lists(RECORDS, max_size=4), st.lists(VALUES, max_size=3),
    st.sampled_from([(None, None), (date(2026, 10, 19), date(2026, 10, 20))]), HOSTILE_TEXT,
)
def test_hostile_records_cannot_break_the_page_or_the_csv(records, observed, checks, period, reason):
    """Whatever a record, an observed record, a check or the verdict's reason holds: nothing raises, the page has only our own
    tags and attributes and can be written as UTF-8, and no CSV cell can start a formula."""
    since, until = period
    s = summarize(records, since, until)
    names = [*s.by_channel, *s.by_provider, *s.by_account_type, *s.by_model, *s.by_status, *s.markers_by_kind]
    assert all(len(name) <= 64 for name in names)
    page = render_html(
        s, VerifyReport(False, 0, 1, reason), rows=journal_rows(records, since, until), observed=observed, checks=checks,
        policy=Policy.from_profile("no-rules"),
    )
    page.encode("utf-8")
    markup = markup_of(page)
    assert markup.tags <= OUR_TAGS and {name for name, _ in markup.attrs} <= OUR_ATTRS
    text = to_csv(records, since, until)
    text.encode("utf-8")
    table = list(csv.reader(io.StringIO(text, newline="")))
    assert all(len(row) == len(CSV_COLUMNS) for row in table)
    assert not [cell for row in table[1:] for cell in row if cell.startswith(("=", "+", "-", "@", "\t", "\r"))]


def test_rows_and_csv_survive_damaged_records():
    """A hand-edited record is read as far as it can be and shown as "unknown" beyond that, never a crash."""
    odd = [
        {"seq": 1, "hash": "x"},
        {"seq": 2, "hash": "y", "ts": "not a time", "channel": 5, "level": "high", "status": None, "model": 7, "usage": [1],
         "markers_by_kind": {"EMAIL": "many", "SECRET": 2, "IP": True, "PHONE": 1.5}, "versions": "boxed"},
        {"seq": 3.5, "hash": "z", "level": [1], "provider": ["a"], "markers_by_kind": [1, 2], "note": 1.5, "scope": True, "versions": {"v": [1]}},
        {"seq": -3, "hash": "n", "level": -5},  # a negative number is neutralised like any text; only -1 reads as a restore
    ]
    rows = journal_rows(odd)
    assert [r["seq"] for r in rows] == [-3, "unknown", 2, 1]
    assert (rows[2]["channel"], rows[2]["level"], rows[2]["model"], rows[2]["status"]) == ("unknown", "unknown", "unknown", "unknown")
    assert rows[2]["kinds"] == {"SECRET": 2} and rows[2]["tokens"] == {} and rows[1]["provider"] == "unknown"
    _, body = csv_rows(to_csv(odd))
    assert [r["seq"] for r in body] == ["1", "2", "unknown", "'-3"] and body[3]["level"] == "'-5"
    assert (body[0]["ts"], body[0]["channel"], body[0]["markers_by_kind"]) == ("", "", "")  # missing is empty, not "unknown"
    assert (body[1]["ts"], body[1]["channel"], body[1]["level"], body[1]["model"]) == ("not a time", "5", "high", "7")
    assert (body[1]["status"], body[1]["markers_by_kind"], body[1]["versions"]) == ("", "SECRET:2", "boxed")
    assert (body[2]["level"], body[2]["provider"], body[2]["note"], body[2]["scope"]) == ("unknown", "unknown", "unknown", "unknown")
    assert body[2]["versions"] == "v:[1]"


# Fixes to the first dashboard: each test was written, and seen to fail, before its fix.


def test_a_huge_verify_reason_is_cut_like_any_other_text():
    """The reason is built from a field of a hand-edited record, so it can be as long as the file."""
    page = render_html(Summary(), VerifyReport(False, 0, 1, "x" * 3_000_000))
    assert len(page) < 100_000 and "x" * 64 in page and "x" * 65 not in page


def observed_page(seen, **period):
    """The page as the CLI will build it: the observation log read, verified and counted for damage, next to a clean main journal."""
    records, damaged = seen.read()
    summary = Summary(**period)
    return render_html(summary, OK_VERDICT, observed=records, observed_verify=seen.verify(), observed_damaged=damaged)


def test_observed_section_shows_the_chain_of_the_observation_log(seen):
    page = observed_page(seen)
    ok = page_text(section_of(page, "observed"))
    assert "Observation chain OK" in ok and "5 records verified" in ok and "BROKEN" not in ok and "damaged" not in ok
    rewrite(seen.path, drop_a_line)  # record 3 is lost: the chain breaks at record 4
    page = observed_page(seen)
    broken = page_text(section_of(page, "observed"))
    assert "Observation chain BROKEN" in broken and "record 4: chain break. 2 records passed verification." in broken
    assert "The numbers below come from a log that failed verification." in broken
    assert "Chain OK" in page_text(page) and "Chain BROKEN" not in page_text(page)  # the main journal's banner is about the main journal


def test_observed_section_notes_the_damaged_lines_of_the_observation_log(seen):
    with seen.path.open("a") as f:
        f.write('{"seq": 6, "torn')
    text = page_text(section_of(observed_page(seen), "observed"))
    assert "1 damaged line skipped: not counted below." in text and "Observation chain BROKEN" in text and "Sends 5" in text
    assert "damaged" not in page_text(section_of(render_html(Summary(), OK_VERDICT, observed=[]), "observed"))  # none given, none said


def test_the_state_of_the_observation_log_shows_even_when_no_send_is_in_the_period(seen):
    rewrite(seen.path, drop_a_line)
    text = page_text(section_of(observed_page(seen, since=date(2026, 10, 30)), "observed"))
    assert "Sends 0" in text and "Observation chain BROKEN" in text  # the lost record may be the one that would have shown


def test_a_log_that_was_not_verified_says_so_and_its_reason_is_cut(seen):
    text = page_text(section_of(render_html(Summary(), OK_VERDICT, observed=seen.entries()), "observed"))
    assert "The observation log was not verified." in text and "Observation chain OK" not in text
    page = render_html(Summary(), OK_VERDICT, observed=[], observed_verify=VerifyReport(False, 0, 1, "y" * 3_000_000))
    assert len(page) < 100_000 and "y" * 64 in page and "y" * 65 not in page


STAMP = "2026-10-19T12:00:00+00:00"
UNREADABLE_KINDS = {
    "a count that is a string": {"EMAIL": "2"},
    "a count beyond a billion": {"EMAIL": 10**10},
    "a negative count": {"EMAIL": -1},
    "a float count": {"EMAIL": 1.5},
    "a boolean count": {"EMAIL": True},
    "a null count": {"EMAIL": None},
    "a list of kinds": ["EMAIL"],
    "a string of kinds": "EMAIL 2",
    "no kinds": None,
}


def observed_text(*records, **page):
    return page_text(section_of(render_html(Summary(), OK_VERDICT, observed=list(records), **page), "observed"))


@pytest.mark.parametrize("kinds", list(UNREADABLE_KINDS.values()), ids=list(UNREADABLE_KINDS))
def test_an_unreadable_observed_record_is_not_a_clean_send(kinds):
    text = observed_text({"provider": "chatgpt", "coverage": "checked", "ts": STAMP, "markers_by_kind": kinds})
    assert "Sends 1" in text and "Sends with findings 0" in text
    assert "1 send could not be checked, so the counts may be too low" in text
    assert "Revoke" not in text  # no key kind is named, so there is nothing to revoke by name


def test_an_observed_record_without_its_kinds_is_not_a_clean_send():
    text = observed_text({"provider": "chatgpt", "coverage": "checked", "ts": STAMP})  # the field is missing altogether
    assert "Sends 1" in text and "Sends with findings 0" in text and "1 send could not be checked" in text


MISSING = object()


@pytest.mark.parametrize("coverage", [MISSING, None, "", "unknown", "full", "Checked", ["checked"], 5, "not checked"])
def test_a_send_that_is_not_marked_checked_could_not_be_checked(coverage):
    rec = {"provider": "chatgpt", "markers_by_kind": {"EMAIL": 1}, "ts": STAMP}
    text = observed_text(rec if coverage is MISSING else rec | {"coverage": coverage})
    assert "Sends 1" in text and "Sends with findings 1" in text  # the counts it does hold are still counted
    assert "1 send could not be checked, so the counts may be too low" in text
    assert "could not be checked" not in observed_text(rec | {"coverage": "checked"})


@pytest.mark.parametrize("count", ["2", 10**10, -1, 1.5, True, None, [1], {"n": 1}])
@pytest.mark.parametrize("kind", ["SECRET", "PRIVATE_KEY", "JWT"])
def test_a_key_kind_with_an_unreadable_count_still_gets_the_revoke_advice(kind, count):
    text = observed_text({"provider": "chatgpt", "coverage": "checked", "ts": STAMP, "markers_by_kind": {kind: count}})
    assert f"Revoke and replace the keys and tokens that were sent ({kind})" in text
    assert "1 send could not be checked" in text and "Sends with findings 0" in text


def test_a_key_kind_counted_zero_is_readable_and_a_mixed_record_counts_both_ways():
    clean = observed_text({"provider": "chatgpt", "coverage": "checked", "ts": STAMP, "markers_by_kind": {"SECRET": 0, "EMAIL": 1}})
    assert "Revoke" not in clean and "could not be checked" not in clean and "Sends with findings 1" in clean
    mixed = observed_text({"provider": "chatgpt", "coverage": "checked", "ts": STAMP, "markers_by_kind": {"EMAIL": 2, "JWT": "x"}})
    assert "Sends with findings 1" in mixed and "1 send could not be checked" in mixed and "(JWT)" in mixed
    two = observed_text(
        {"provider": "a", "coverage": "checked", "ts": STAMP, "markers_by_kind": {"SECRET": "?"}},
        {"provider": "b", "coverage": "checked", "ts": STAMP, "markers_by_kind": {"JWT": 1, "PRIVATE_KEY": -1}},
    )
    assert "(SECRET, PRIVATE_KEY, JWT)" in two and "2 sends could not be checked" in two  # the fixed order, as with a readable count


def test_numbers_beyond_a_billion_are_unknown_not_cut():
    """A cut number is a different number: out of range it is unknown, in the level counts, the rows and the CSV alike."""
    huge = 10**4000  # 4001 digits, the most that JSON will parse
    rec = {"seq": huge, "hash": "h", "ts": STAMP, "level": huge, "channel": huge, "scope": -huge}
    s = summarize([rec])
    row = journal_rows([rec])[0]
    cells = csv_rows(to_csv([rec]))[1][0]
    assert s.by_level == Counter({"unknown": 1}) and (row["seq"], row["level"]) == ("unknown", "unknown")
    assert (cells["seq"], cells["level"], cells["channel"], cells["scope"]) == ("unknown",) * 4
    assert not re.search(r"\d{65}", render_html(s, OK_VERDICT, rows=[row]))
    edge = [{"seq": n, "hash": "h", "ts": STAMP, "level": n} for n in (10**9, 10**9 + 1, -(10**9), -(10**9) - 1)]
    assert [r["seq"] for r in journal_rows(edge)] == ["unknown", -(10**9), "unknown", 10**9]  # a billion either way still counts
    assert [r["level"] for r in journal_rows(edge)] == ["unknown", -(10**9), "unknown", 10**9]
    assert summarize(edge).by_level == Counter({10**9: 1, -(10**9): 1, "unknown": 2})
    body = csv_rows(to_csv(edge))[1]
    assert [r["seq"] for r in body] == ["1000000000", "unknown", "'-1000000000", "unknown"]
    assert [r["level"] for r in body] == ["1000000000", "unknown", "'-1000000000", "unknown"]


def test_training_states_are_coloured_by_what_they_mean():
    """Training on warns, off is good, unknown stays quiet; the memory column and the settings are not coloured at all."""
    section = section_of(render_html(Summary(), OK_VERDICT, checks=CHECKS), "checks")
    assert re.findall(r"<td class=(\w+)>(on|off|unknown)</td>", section) == [("good", "off"), ("muted", "unknown"), ("bad", "on")]
    assert re.findall(r"<td class=due>(\w*)</td>", section) == ["due"]  # the one check that is due, and only it


def test_policy_verdicts_are_coloured_by_what_they_mean():
    policy = Policy.from_config({"profile": "no-confidential", "rules": {"finance:personal-private": "deny"}})
    section = section_of(render_html(Summary(), OK_VERDICT, policy=policy), "policy")
    cells = re.findall(r"<td( class=\w+)?>(allow|deny|masked:\d|local-only)</td>", section)
    assert {text: {cls for cls, t in cells if t == text} for text in ("allow", "deny", "local-only")} == {
        "allow": {" class=good"}, "deny": {" class=bad"}, "local-only": {""},
    }
    assert {cls for cls, text in cells if text.startswith("masked")} == {""}  # masked is neither good nor bad
    assert "<td class=bad>no rule</td>" in section_of(render_html(Summary(), OK_VERDICT, policy=Policy({})), "policy")


def test_an_empty_name_reads_as_unknown_everywhere_but_the_csv():
    """An empty string is no name: the page says unknown, as it does for a missing field; the CSV leaves its cell empty."""
    rec = {"seq": 1, "hash": "h", "ts": STAMP, "channel": "", "provider": "", "account_type": "", "status": "", "model": ""}
    s = summarize([rec])
    assert s.by_channel == s.by_provider == s.by_account_type == s.by_status == Counter({"unknown": 1})
    assert not s.by_model  # an empty model is no model, not an unreadable one
    row = journal_rows([rec])[0]
    assert [row[k] for k in ("channel", "provider", "account_type", "status", "model")] == ["unknown"] * 4 + [""]
    assert [csv_rows(to_csv([rec]))[1][0][k] for k in ("channel", "provider", "account_type", "status", "model")] == [""] * 5
    text = observed_text({"provider": "", "coverage": "", "markers_by_kind": {}, "ts": STAMP})
    assert "Sites unknown 1" in text and "Coverage unknown 1" in text
    empty = {"provider": "", "account": "", "source": "", "checked_at": "", "settings_url": ""}
    checked = rows_of(section_of(render_html(Summary(), OK_VERDICT, checks=[empty]), "checks"))[1]
    assert checked == ["unknown", "unknown", "unknown", "unknown", "unknown", "unknown", "-", "due"]


def test_a_chain_breaks_on_a_gap_in_the_numbers_or_on_a_wrong_link_alone(week, tmp_path):
    """The links and the numbers are two checks: either one wrong while the other is right is still a chain break."""
    gap = VerifyReport(False, 3, 5, "record 5: chain break")
    rechain(week, tmp_path, "0" * 64, edit=lambda rec, i: rec.update(seq=i + 1 + (i >= 3)))  # numbers 1 2 3 5 6 7 8, every link right
    assert week.verify() == gap and verify_export(received(export_for_security(week))) == gap
    link = VerifyReport(False, 3, 4, "record 4: chain break")
    rechain(week, tmp_path, "0" * 64, edit=lambda rec, i: rec.update(seq=i + 1, **({"prev_hash": "ee" * 32} if i == 3 else {})))
    assert week.verify() == link and verify_export(received(export_for_security(week))) == link  # numbers 1..7, one link wrong


@pytest.mark.parametrize(
    "broken, expected",
    [
        (None, VerifyReport(False, 0, None, "not a boxed journal export")),
        ({"format": "boxed-journal-export/2", "public_key": STRANGER_KEY, "entries": []}, VerifyReport(False, 0, None, "not a boxed journal export")),
        ({"format": FORMAT, "entries": []}, VerifyReport(False, 0, None, "export has no valid public key")),
        ({"format": FORMAT, "public_key": "zz", "entries": []}, VerifyReport(False, 0, None, "export has no valid public key")),
        ({"format": FORMAT, "public_key": STRANGER_KEY}, VerifyReport(False, 0, None, "export has no list of entries")),
        ({"format": FORMAT, "public_key": STRANGER_KEY, "entries": [None]}, VerifyReport(False, 0, 1, "entry 1: not a journal record")),
    ],
)
def test_a_malformed_export_gets_the_report_that_names_what_is_wrong(broken, expected):
    assert verify_export(broken) == expected
