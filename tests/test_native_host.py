import gc
import hashlib
import hmac
import io
import json
import os
import re
import stat
import struct
import subprocess
import sys
import threading
import types
import weakref
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from boxed import __version__, native_host
from boxed.checks import Check, load_checks, save_check
from boxed.config import ProjectConfig
from boxed.detect import ner
from boxed.install import install_native_host
from boxed.journal import Journal
from boxed.keys import default_keystore
from boxed.native_host import MAX_MESSAGE, HostContext, handle, main, read_message, serve, write_message
from boxed.observe import observed_journal
from boxed.vault import Vault
from support import mode_is

EXTENSION = Path(__file__).resolve().parents[1] / "extension"
SITES = [
    "https://chatgpt.com/*",
    "https://claude.ai/*",
    "https://gemini.google.com/*",
    "https://chat.deepseek.com/*",
    "https://chat.z.ai/*",
]
TEXT = "mail ivan.petrov@acme.com, key AKIAIOSFODNN7EXAMPLE, call +7 (912) 345-67-89"
VALUES = ["ivan.petrov@acme.com", "AKIAIOSFODNN7EXAMPLE", "+7 (912) 345-67-89", "345-67-89"]


def frame(payload: bytes) -> bytes:
    return struct.pack("=I", len(payload)) + payload


def padded(size: int) -> bytes:
    """A JSON object of exactly `size` bytes."""
    base = len(json.dumps({"cmd": "ping", "pad": ""}).encode())
    return json.dumps({"cmd": "ping", "pad": "x" * (size - base)}).encode()


def test_frame_round_trip():
    stream = io.BytesIO()
    write_message(stream, {"cmd": "ping"})
    write_message(stream, {"ok": True, "text": "Привет, [EMAIL_1]"})
    raw = stream.getvalue()
    size = struct.unpack("=I", raw[:4])[0]
    assert json.loads(raw[4 : 4 + size]) == {"cmd": "ping"}
    stream.seek(0)
    assert read_message(stream) == {"cmd": "ping"}
    assert read_message(stream) == {"ok": True, "text": "Привет, [EMAIL_1]"}
    assert read_message(stream) is None


def test_frame_header_is_native_order_and_counts_bytes():
    stream = io.BytesIO()
    write_message(stream, {"text": "я"})
    raw = stream.getvalue()
    assert struct.unpack("=I", raw[:4])[0] == len(raw) - 4
    assert "я".encode() in raw  # UTF-8, not \u escapes: Cyrillic must not triple in size


def test_frame_at_the_limit_is_accepted_and_one_byte_over_is_not():
    assert read_message(io.BytesIO(frame(padded(MAX_MESSAGE))))["cmd"] == "ping"
    with pytest.raises(ValueError, match="too large"):
        read_message(io.BytesIO(frame(padded(MAX_MESSAGE + 1))))


def test_oversize_frame_is_refused_before_its_body_is_read():
    stream = io.BytesIO(struct.pack("=I", 0xFFFFFFFF) + b"x" * 64)
    with pytest.raises(ValueError, match="too large"):
        read_message(stream)
    assert stream.tell() == 4


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (struct.pack("=I", MAX_MESSAGE + 1), "too large"),
        (struct.pack("=I", 0xFFFFFFFF), "too large"),
        (b"\x05", "truncated"),
        (b"\x05\x00\x00", "truncated"),
        (struct.pack("=I", 10) + b'{"a":1', "truncated"),
        (struct.pack("=I", 2), "truncated"),
    ],
    ids=["one byte over", "4 GB", "one header byte", "three header bytes", "short body", "no body"],
)
def test_oversize_and_truncated_frames_rejected(raw, reason):
    with pytest.raises(ValueError, match=reason):
        read_message(io.BytesIO(raw))


@pytest.mark.parametrize(
    "payload",
    [b'{"cmd": "mask", "text": "ivan@acme.com"', b"", b"[1, 2]", b'"text"', b"\xff\xfe{}", b"[" * 600_000],
    ids=["cut json", "empty", "array", "string", "not utf-8", "nested too deep"],
)
def test_bad_payloads_raise_value_error_without_the_content(payload):
    with pytest.raises(ValueError) as caught:
        read_message(io.BytesIO(frame(payload)))
    assert "ivan" not in str(caught.value) and "acme" not in str(caught.value)


def test_write_refuses_an_oversize_message_and_writes_nothing():
    stream = io.BytesIO()
    with pytest.raises(ValueError, match="too large"):
        write_message(stream, {"ok": True, "text": "x" * MAX_MESSAGE})
    assert stream.getvalue() == b""


def test_write_counts_bytes_not_characters():
    stream = io.BytesIO()
    with pytest.raises(ValueError, match="too large"):
        write_message(stream, {"text": "я" * (MAX_MESSAGE // 2)})
    assert stream.getvalue() == b""


def test_write_refuses_text_that_is_not_valid_utf8_without_echoing_it():
    with pytest.raises(ValueError) as caught:
        write_message(io.BytesIO(), {"text": "ivan\ud800"})
    assert "ivan" not in str(caught.value) and "ud800" not in str(caught.value).lower()


@pytest.fixture
def ctx(boxed_env):
    boxed_env.mkdir(parents=True, exist_ok=True)
    keys = default_keystore()
    return HostContext(
        home=boxed_env,
        vault=Vault(boxed_env / "vault.db", keys),
        journal=Journal(boxed_env / "journal.jsonl", keys),
        config=ProjectConfig(),
        observed=observed_journal(boxed_env, keys),
    )


def test_ping(ctx):
    assert handle({"cmd": "ping"}, ctx) == {"ok": True, "version": __version__}


def test_mask_and_restore_through_handle(ctx):
    masked = handle({"cmd": "mask", "text": TEXT, "scope": "web-test", "level": 2}, ctx)
    assert masked == {
        "ok": True,
        "text": "mail [EMAIL_1], key [SECRET_1], call [PHONE_1]",
        "scope": "web-test",
        "markers_by_kind": {"EMAIL": 1, "SECRET": 1, "PHONE": 1},
    }
    answer = "Write to [EMAIL_1] about [SECRET_1] and [PHONE_1]; not [EMAIL_9], and [EMAIL-1] is odd."
    restored = handle({"cmd": "restore", "text": answer, "scope": "web-test"}, ctx)
    assert restored == {
        "ok": True,
        "text": "Write to ivan.petrov@acme.com about AKIAIOSFODNN7EXAMPLE and +7 (912) 345-67-89; not [EMAIL_9], and [EMAIL-1] is odd.",
        "unknown": ["[EMAIL_9]"],
        "suspicious": ["[EMAIL-1]"],
    }


def test_level_is_applied(ctx):
    reply = handle({"cmd": "mask", "text": TEXT, "scope": "s", "level": 0}, ctx)
    assert reply["text"] == "mail ivan.petrov@acme.com, key [SECRET_1], call +7 (912) 345-67-89"


@pytest.mark.parametrize(("configured", "used"), [(0, 0), (1, 1), (2, 2), (3, 2), (4, 2)])
def test_default_level_is_the_project_level_capped_at_2(ctx, configured, used):
    ctx.config = ProjectConfig(level=configured)
    handle({"cmd": "mask", "text": TEXT, "scope": "s"}, ctx)
    assert ctx.journal.entries()[-1]["level"] == used


def test_default_scope_is_web_and_the_utc_date(ctx):
    days = {datetime.now(UTC).strftime("%Y%m%d")}
    reply = handle({"cmd": "mask", "text": TEXT}, ctx)
    days.add(datetime.now(UTC).strftime("%Y%m%d"))
    assert reply["scope"] in {f"web-{day}" for day in days}
    assert ctx.vault.scopes() == [reply["scope"]]


def test_same_scope_keeps_numbering(ctx):
    first = handle({"cmd": "mask", "text": "a@x.io b@x.io", "scope": "s"}, ctx)
    second = handle({"cmd": "mask", "text": "b@x.io c@x.io", "scope": "s"}, ctx)
    assert first["text"] == "[EMAIL_1] [EMAIL_2]" and second["text"] == "[EMAIL_2] [EMAIL_3]"


def test_project_dictionary_applies_to_mask_and_restore(ctx):
    ctx.config = ProjectConfig(dictionary={"Acme Corp": "CLIENT"})
    assert handle({"cmd": "mask", "text": "Offer for Acme Corp", "scope": "s"}, ctx)["text"] == "Offer for [CLIENT_1]"
    handle({"cmd": "mask", "text": "a@x.io", "scope": "t"}, ctx)  # a map without any CLIENT yet
    assert handle({"cmd": "restore", "text": "Dear [CLIENT_1]", "scope": "t"}, ctx)["unknown"] == ["[CLIENT_1]"]


def test_mask_and_restore_are_journaled(ctx):
    masked = handle({"cmd": "mask", "text": TEXT, "scope": "web-test", "level": 1}, ctx)
    handle({"cmd": "restore", "text": "Mail [EMAIL_1] [EMAIL_9]", "scope": "web-test"}, ctx)
    prepared, received = ctx.journal.entries()
    assert (prepared["channel"], prepared["status"], prepared["level"], prepared["scope"]) == ("extension", "prepared", 1, "web-test")
    assert prepared["markers_by_kind"] == masked["markers_by_kind"]
    assert prepared["payload_sha256"] == hashlib.sha256(masked["text"].encode()).hexdigest()
    assert (received["channel"], received["status"], received["scope"]) == ("extension", "received", "web-test")
    assert received["note"] == "restored=1 unknown=1 suspicious=0"
    assert ctx.journal.verify().ok


BAD_REQUESTS = [
    {},
    {"cmd": "shell", "args": ["ls"]},
    {"cmd": "ping", "extra": 1},
    {"cmd": 7},
    {"cmd": ["mask"]},
    {"cmd": "mask"},
    {"cmd": "mask", "text": 5},
    {"cmd": "mask", "text": "x", "colour": "red"},
    {"cmd": "mask", "text": "x", "level": 3},
    {"cmd": "mask", "text": "x", "level": True},
    {"cmd": "mask", "text": "x", "level": "2"},
    {"cmd": "mask", "text": "x", "level": 1.0},
    {"cmd": "mask", "text": "x", "scope": ""},
    {"cmd": "mask", "text": "x", "scope": 5},
    {"cmd": "mask", "text": "x", "scope": "a" * 65},
    {"cmd": "mask", "text": "x", "scope": "a b"},
    {"cmd": "mask", "text": "x", "scope": "a@b.io"},
    {"cmd": "mask", "text": "x", "scope": ".hidden"},
    {"cmd": "mask", "text": "x", "scope": "web-1\n"},
    {"cmd": "mask", "text": "lone \ud800 surrogate"},
    {"cmd": "restore", "text": "x"},
    {"cmd": "restore", "scope": "s"},
    {"cmd": "restore", "text": "x", "scope": None},
    {"cmd": "restore", "text": "x", "scope": "s", "level": 2},
]


@pytest.mark.parametrize("message", BAD_REQUESTS, ids=[json.dumps(m)[:50] for m in BAD_REQUESTS])
def test_anything_else_is_a_bad_request(ctx, message):
    assert handle(message, ctx) == {"ok": False, "error": "bad request"}
    assert ctx.journal.entries() == [] and ctx.vault.scopes() == []


def test_unknown_scope_and_unknown_command(ctx):
    handle({"cmd": "mask", "text": TEXT, "scope": "web-test"}, ctx)
    reply = handle({"cmd": "restore", "text": "[EMAIL_1]", "scope": "web-other"}, ctx)
    assert reply == {"ok": False, "error": "unknown scope"}
    assert handle({"cmd": "export", "scope": "web-test"}, ctx) == {"ok": False, "error": "bad request"}
    assert [e["status"] for e in ctx.journal.entries()] == ["prepared"]  # neither refusal is journaled


def test_a_mask_reply_that_is_too_large_changes_nothing(ctx):
    reply = handle({"cmd": "mask", "text": "[IP_1]" * 100_000, "scope": "s"}, ctx)  # 6 bytes become 11
    assert reply == {"ok": False, "error": "reply too large"}
    assert ctx.vault.scopes() == [] and ctx.journal.entries() == []


def test_a_restore_reply_that_is_too_large_is_not_journaled(ctx):
    with ctx.vault.transaction("s") as markers:
        markers.marker_for("SECRET", "x" * 100_000)
    reply = handle({"cmd": "restore", "text": "[SECRET_1]" * 12, "scope": "s"}, ctx)
    assert reply == {"ok": False, "error": "reply too large"}
    assert ctx.journal.entries() == []


def test_errors_and_journal_hold_no_values(ctx, monkeypatch):
    ok = handle({"cmd": "mask", "text": TEXT, "scope": "web-test"}, ctx)
    ok_restore = handle({"cmd": "restore", "text": ok["text"], "scope": "web-test"}, ctx)
    assert ok_restore["text"] == TEXT  # the originals come back in the reply and nowhere else
    errors = [
        handle({"cmd": "restore", "text": TEXT, "scope": "web-other"}, ctx),
        handle({"cmd": "mask", "text": TEXT, "level": "AKIAIOSFODNN7EXAMPLE"}, ctx),
        handle({"cmd": "mask", "text": TEXT, "scope": "ivan.petrov@acme.com"}, ctx),
        handle({"cmd": TEXT}, ctx),
        handle({"cmd": "mask", "text": TEXT, "AKIAIOSFODNN7EXAMPLE": 1}, ctx),
    ]

    def boom(*args, **kwargs):
        raise RuntimeError(TEXT)

    monkeypatch.setattr(native_host, "mask_text", boom)
    errors.append(handle({"cmd": "mask", "text": TEXT, "scope": "web-test"}, ctx))
    monkeypatch.undo()
    assert all(e["ok"] is False for e in errors) and errors[-1]["error"] == "internal error"
    blob = json.dumps(errors) + ctx.journal.path.read_text()
    for value in VALUES:
        assert value not in blob


def observe_message(**changes):
    return {"cmd": "observe", "site": "chatgpt", "text": TEXT, "coverage": "checked"} | changes


def check_set_message(**changes):
    return {"cmd": "check-set", "provider": "claude", "account": "ivan.petrov@acme.com", "training": "off", "memory": "unknown"} | changes


def test_host_observe_replies_counts(ctx):
    reply = handle(observe_message(), ctx)
    assert reply == {"ok": True, "found": {"EMAIL": 1, "SECRET": 1, "PHONE": 1}}
    (record,) = ctx.observed.entries()
    assert (record["channel"], record["provider"], record["coverage"], record["status"]) == ("observed", "chatgpt", "checked", "sent")
    assert record["markers_by_kind"] == reply["found"]
    # an observed record keys the hash with the device's "observe-hmac" key; the main journal's hash stays a plain SHA-256
    assert record["payload_sha256"] == hmac.new(default_keystore().get_or_create("observe-hmac", 32), TEXT.encode(), hashlib.sha256).hexdigest()
    assert ctx.observed.verify().ok
    blob = json.dumps(reply) + ctx.observed.path.read_text()
    for value in VALUES:
        assert value not in blob
    assert ctx.journal.entries() == [] and ctx.vault.scopes() == []  # not the main journal, and nothing to restore later


def test_host_observe_records_a_send_that_was_not_checked(ctx):
    assert handle(observe_message(site="zai", text="", coverage="not checked"), ctx) == {"ok": True, "found": {}}
    (record,) = ctx.observed.entries()
    assert (record["provider"], record["coverage"], record["markers_by_kind"]) == ("zai", "not checked", {})


def test_host_observe_records_a_text_it_cannot_read_as_not_checked(ctx):
    reply = handle(observe_message(site="gemini", text="mail ivan.petrov@acme.com \ud800"), ctx)  # a cut emoji, say
    assert reply == {"ok": True, "found": {}}
    (record,) = ctx.observed.entries()
    assert (record["provider"], record["coverage"], record["markers_by_kind"]) == ("gemini", "not checked", {})
    assert "ivan" not in ctx.observed.path.read_text()


def test_host_observe_uses_the_home_config(ctx):
    ctx.config = ProjectConfig(dictionary={"Acme Corp": "CLIENT"}, allow=["a@x.io"])
    reply = handle(observe_message(text="Offer for Acme Corp to a@x.io and b@x.io"), ctx)
    assert reply["found"] == {"CLIENT": 1, "EMAIL": 1}


BAD_OBSERVE = [
    observe_message(site="bing"),
    observe_message(site="ChatGPT"),
    observe_message(site=""),
    observe_message(site=["chatgpt"]),
    observe_message(site=5),
    observe_message(site=None),
    observe_message(coverage="full"),
    observe_message(coverage=["checked"]),
    observe_message(coverage=None),
    observe_message(text=5),
    observe_message(text=None),
    observe_message(text="lone \ud800 surrogate", coverage="not checked"),
    observe_message(coverage="not checked"),  # TEXT stays on the page when it was not checked
    observe_message(level=2),
    observe_message(scope="s"),
    {"cmd": "observe", "site": "chatgpt", "coverage": "checked"},
    {"cmd": "observe", "text": "x", "coverage": "checked"},
    {"cmd": "observe", "site": "chatgpt", "text": "x"},
    {"cmd": "observe"},
]


@pytest.mark.parametrize("message", BAD_OBSERVE, ids=[json.dumps(m)[:60] for m in BAD_OBSERVE])
def test_host_observe_refuses_unknown_site_and_text_with_not_checked(ctx, message):
    assert handle(message, ctx) == {"ok": False, "error": "bad request"}
    assert ctx.observed.entries() == [] and ctx.journal.entries() == [] and ctx.vault.scopes() == []


SETTINGS_URLS = {  # every provider, whether or not a check was saved for it: the panel opens the page before the first answer
    "chatgpt": "https://chatgpt.com/#settings/DataControls",
    "claude": "https://claude.ai/settings/data-privacy-controls",
    "gemini": "https://myactivity.google.com/product/gemini",
    "deepseek": None,
    "zai": None,
}


def test_host_checks_lists_due_and_settings_url(ctx):
    today = datetime.now(UTC).date()
    save_check(ctx.home, Check("chatgpt", "me", "off", "off", "asked", today.isoformat()))
    save_check(ctx.home, Check("claude", "me", "on", "unknown", "asked", today.isoformat()))
    save_check(ctx.home, Check("deepseek", "old", "off", "off", "asked", (today - timedelta(days=90)).isoformat()))
    reply = handle({"cmd": "checks"}, ctx)
    assert reply == {
        "ok": True,
        "checks": [
            {"provider": "chatgpt", "account": "me", "training": "off", "memory": "off", "source": "asked",
             "checked_at": today.isoformat(), "due": False, "settings_url": "https://chatgpt.com/#settings/DataControls"},
            {"provider": "claude", "account": "me", "training": "on", "memory": "unknown", "source": "asked",
             "checked_at": today.isoformat(), "due": True, "settings_url": "https://claude.ai/settings/data-privacy-controls"},
            {"provider": "deepseek", "account": "old", "training": "off", "memory": "off", "source": "asked",
             "checked_at": (today - timedelta(days=90)).isoformat(), "due": True, "settings_url": None},
        ],
        "providers": ["chatgpt", "claude", "gemini", "deepseek", "zai"],
        "settings": SETTINGS_URLS,
        "note": "Training off does not mean nothing is stored: providers still keep chats for a while.",
    }


def test_host_checks_marks_overdue_ones_without_comparing_every_pair(ctx, monkeypatch):
    today = datetime.now(UTC).date().isoformat()
    many = [Check("chatgpt", f"a{i}", "off", "unknown" if i % 2 else "off", "asked", today) for i in range(2000)]
    monkeypatch.setattr(native_host, "load_checks", lambda home: many)
    compared = []
    equal = Check.__eq__
    monkeypatch.setattr(Check, "__eq__", lambda self, other: compared.append(1) or equal(self, other))
    reply = handle({"cmd": "checks"}, ctx)
    assert [row["due"] for row in reply["checks"]] == [i % 2 == 1 for i in range(2000)]
    assert len(compared) < len(many)  # looking each record up in the list of due ones takes 2000 x 1000 comparisons


def test_host_checks_without_a_file_lists_the_providers(ctx):
    reply = handle({"cmd": "checks"}, ctx)
    assert reply["ok"] is True and reply["checks"] == []
    assert reply["providers"] == ["chatgpt", "claude", "gemini", "deepseek", "zai"]
    assert reply["settings"] == SETTINGS_URLS
    assert not (ctx.home / "checks.json").exists()


def test_host_check_set_saves_the_answer_as_asked_today(ctx):
    days = {datetime.now(UTC).date().isoformat()}
    assert handle(check_set_message(), ctx) == {"ok": True}
    days.add(datetime.now(UTC).date().isoformat())
    (saved,) = load_checks(ctx.home)
    assert (saved.provider, saved.account, saved.training, saved.memory, saved.source) == (
        "claude", "ivan.petrov@acme.com", "off", "unknown", "asked",
    )
    assert saved.checked_at in days
    assert handle(check_set_message(training="on", memory="on"), ctx) == {"ok": True}  # the same account: replaced
    assert [(c.training, c.memory) for c in load_checks(ctx.home)] == [("on", "on")]


BAD_CHECK_SET = [
    check_set_message(training="maybe"),
    check_set_message(training="OFF"),
    check_set_message(training=True),
    check_set_message(training=None),
    check_set_message(memory="maybe"),
    check_set_message(memory=0),
    check_set_message(account="my account"),
    check_set_message(account=""),
    check_set_message(account=".hidden"),
    check_set_message(account="-x"),
    check_set_message(account="a" * 65),
    check_set_message(account="me\n"),
    check_set_message(account="lone \ud800 surrogate"),
    check_set_message(account=5),
    check_set_message(account=["me"]),
    check_set_message(provider="bing"),
    check_set_message(provider="Claude"),
    check_set_message(provider=["claude"]),
    check_set_message(provider=None),
    check_set_message(source="page"),  # the host decides how a check was made and when
    check_set_message(checked_at="2020-01-01"),
    {"cmd": "check-set"},
    {"cmd": "check-set", "provider": "claude", "account": "me", "training": "off"},
    {"cmd": "checks", "provider": "claude"},
]


@pytest.mark.parametrize("message", BAD_CHECK_SET, ids=[json.dumps(m)[:60] for m in BAD_CHECK_SET])
def test_host_check_set_validates_values(ctx, message):
    assert handle(message, ctx) == {"ok": False, "error": "bad request"}
    assert not (ctx.home / "checks.json").exists()


def test_host_damaged_checks_reply_is_fixed_text(ctx):
    damaged = b'{"version": 1, "checks": [{"provider": "ivan.petrov@acme.com", "account": "me"'
    (ctx.home / "checks.json").write_bytes(damaged)
    replies_ = [handle({"cmd": "checks"}, ctx), handle(check_set_message(), ctx)]
    assert replies_ == [{"ok": False, "error": "checks unreadable"}] * 2
    assert (ctx.home / "checks.json").read_bytes() == damaged  # nothing is repaired behind the person's back


@pytest.mark.parametrize(
    ("message", "function"),
    [(observe_message(), "observe"), ({"cmd": "checks"}, "load_checks"), (check_set_message(), "save_check")],
)
def test_a_failure_in_a_browser_command_quotes_nothing(ctx, monkeypatch, message, function):
    def boom(*args, **kwargs):
        raise RuntimeError(TEXT)

    monkeypatch.setattr(native_host, function, boom)
    reply = handle(message, ctx)
    assert reply == {"ok": False, "error": "internal error"}
    assert ctx.observed.entries() == [] and not (ctx.home / "checks.json").exists()


def frames(*messages: dict) -> bytes:
    out = io.BytesIO()
    for message in messages:
        write_message(out, message)
    return out.getvalue()


def replies(raw: bytes) -> list[dict]:
    stream, found = io.BytesIO(raw), []
    while (message := read_message(stream)) is not None:
        found.append(message)
    return found


def test_serve_loop_until_eof(ctx):
    stdin = io.BytesIO(
        frames(
            {"cmd": "ping"},
            {"cmd": "mask", "text": TEXT, "scope": "s"},
            {"cmd": "restore", "text": "[EMAIL_1] and [BAD_1]", "scope": "s"},
            {"cmd": "shell"},
        )
    )
    stdout = io.BytesIO()
    assert serve(stdin, stdout, ctx) == 0
    ping, masked, restored, refused = replies(stdout.getvalue())
    assert ping == {"ok": True, "version": __version__}
    assert masked["text"] == "mail [EMAIL_1], key [SECRET_1], call [PHONE_1]"
    assert restored["text"] == "ivan.petrov@acme.com and [BAD_1]"
    assert refused == {"ok": False, "error": "bad request"}  # a bad request does not end the loop


def test_serve_takes_an_observed_text_with_a_lone_surrogate_escape(ctx):
    body = b'{"cmd":"observe","site":"chatgpt","text":"a\\ud800b","coverage":"checked"}'  # json escapes a cut emoji like this
    stdout = io.BytesIO()
    assert serve(io.BytesIO(frame(body)), stdout, ctx) == 0
    assert replies(stdout.getvalue()) == [{"ok": True, "found": {}}]
    assert [e["coverage"] for e in ctx.observed.entries()] == ["not checked"]


def test_serve_with_no_input_returns_at_once(ctx):
    stdout = io.BytesIO()
    assert serve(io.BytesIO(), stdout, ctx) == 0 and stdout.getvalue() == b""


def test_bad_json_gets_an_error_reply(ctx):
    stdout = io.BytesIO()
    cut = frame(b'{"cmd": "mask", "text": "mail ivan.petrov@acme.com"')
    assert serve(io.BytesIO(cut), stdout, ctx) == 1
    assert replies(stdout.getvalue()) == [{"ok": False, "error": "bad json"}]
    assert b"ivan" not in stdout.getvalue()


BAD_FRAMES = {
    "cut json": (frame(b'{"cmd": "mask", "text": "ivan.petrov@acme.com"'), "bad json"),
    "not an object": (frame(b'["ivan.petrov@acme.com"]'), "bad json"),
    "oversize": (struct.pack("=I", MAX_MESSAGE + 1), "message too large"),
    "truncated": (struct.pack("=I", 90) + b'{"cmd":"mask","text":"ivan.petrov@acme.com"}', "truncated frame"),
}


@pytest.mark.parametrize(("raw", "error"), BAD_FRAMES.values(), ids=BAD_FRAMES.keys())
def test_bad_frame_gets_an_error_reply_and_ends_the_loop(ctx, raw, error):
    stdout = io.BytesIO()
    assert serve(io.BytesIO(frames({"cmd": "ping"}) + raw + frames({"cmd": "ping"})), stdout, ctx) == 1
    first, second = replies(stdout.getvalue())  # the ping after the bad frame is never answered
    assert first["ok"] is True and second == {"ok": False, "error": error}
    assert b"ivan" not in stdout.getvalue()


def test_a_reply_that_cannot_be_sent_gets_an_error_and_the_loop_goes_on(ctx, monkeypatch):
    big = {"ok": True, "text": "x" * MAX_MESSAGE}
    monkeypatch.setattr(native_host, "handle", lambda message, ctx: big if message["cmd"] == "big" else {"ok": True})
    stdout = io.BytesIO()
    assert serve(io.BytesIO(frames({"cmd": "big"}, {"cmd": "small"})), stdout, ctx) == 0
    assert replies(stdout.getvalue()) == [{"ok": False, "error": "reply too large"}, {"ok": True}]


# A host that stays up. The panel keeps one port, so the browser keeps one process for many requests, closes its input when
# the port closes, and the host ends. Every request is answered as a new process would answer it, and holds nothing back.

UNIQUE = "zebra-unicorn-4711"  # a word no detector touches: it travels through mask, restore and observe unchanged


class Held(dict):
    """A message or reply that a test can watch: a plain dict cannot be weakly referenced."""


def test_the_host_keeps_nothing_of_a_request_while_it_waits_for_the_next(monkeypatch):
    watched = []

    def read(stream):
        if not watched:  # the first request
            message = Held(cmd="ping", text=TEXT)
            watched.append(weakref.ref(message))
            return message
        gc.collect()  # from here on the host is waiting for the second request
        assert [ref() for ref in watched] == [None, None], "the request or its answer is still held"
        return None

    def respond(message):
        reply = Held(ok=True, text=message["text"])
        watched.append(weakref.ref(reply))
        return reply

    monkeypatch.setattr(native_host, "read_message", read)
    assert native_host._serve(io.BytesIO(), io.BytesIO(), respond) == 0
    assert len(watched) == 2


def held_strings(root, limit=500_000):
    """The str and bytes reachable from root through attributes, items and elements, not through modules or code."""
    seen, found, todo = set(), [], [root]
    while todo and len(seen) < limit:
        item = todo.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, str | bytes | bytearray):
            found.append(item)
        elif isinstance(item, dict):
            todo += [*item.keys(), *item.values()]
        elif isinstance(item, list | tuple | set | frozenset):
            todo += list(item)
        elif not isinstance(item, int | float | type | types.ModuleType | types.FunctionType | types.BuiltinFunctionType | Path):
            todo += list(getattr(item, "__dict__", {}).values())
    return found


def test_the_host_context_and_the_modules_hold_no_text_after_the_requests(ctx):
    text = f"{TEXT} {UNIQUE}"
    stdin = io.BytesIO(
        frames(
            {"cmd": "mask", "text": text, "scope": "s"},
            {"cmd": "restore", "text": f"mail [EMAIL_1] {UNIQUE}", "scope": "s"},
            observe_message(text=text),
            check_set_message(account=UNIQUE),
            {"cmd": "checks"},
        )
    )
    assert serve(stdin, io.BytesIO(), ctx) == 0
    stdin = None
    gc.collect()
    modules = [vars(module) for name, module in list(sys.modules.items()) if name.startswith("boxed") and module is not None]
    for needle in [*VALUES, UNIQUE, "ivan"]:
        for place, root in (("the context", ctx), ("the modules", modules)):
            held = [s for s in held_strings(root) if (needle in s if isinstance(s, str) else needle.encode() in s)]
            assert not held, f"{needle!r} is still held in {place}"


class LiveHost:
    """The real host program on pipes that stay open: what the browser does with a port."""

    def __init__(self) -> None:
        origin = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"
        self.process = subprocess.Popen(
            [sys.executable, "-P", "-m", "boxed.native_host", origin], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
        self.watchdog = threading.Timer(120, self.process.kill)  # a host that hangs fails the test instead of stopping the run
        self.watchdog.start()

    def ask(self, message: dict) -> dict:
        self.process.stdin.write(frames(message))
        self.process.stdin.flush()
        reply = read_message(self.process.stdout)
        assert reply is not None, "the host ended without answering"
        return reply

    def close(self) -> int:
        """What the browser does when the port closes."""
        self.process.stdin.close()
        return self.process.wait(timeout=30)


@pytest.fixture
def live_host():
    hosts = []

    def start() -> LiveHost:
        hosts.append(LiveHost())
        return hosts[-1]

    yield start
    for host in hosts:
        host.watchdog.cancel()
        host.process.kill()
        host.process.wait()
        host.process.stdout.close()


def test_one_process_answers_request_after_request_and_ends_when_the_port_closes(live_host):
    host = live_host()
    assert host.ask({"cmd": "ping"}) == {"ok": True, "version": __version__}
    masked = host.ask({"cmd": "mask", "text": TEXT, "scope": "s"})
    assert masked["text"] == "mail [EMAIL_1], key [SECRET_1], call [PHONE_1]"
    assert host.process.poll() is None  # still there, waiting for the next request
    assert host.ask({"cmd": "restore", "text": masked["text"], "scope": "s"})["text"] == TEXT
    assert host.ask({"cmd": "mask", "text": "a@x.io", "scope": "s"})["text"] == "[EMAIL_2]"  # one scope, one numbering
    assert host.close() == 0


def test_a_host_that_stays_up_reads_boxed_toml_again_for_each_request(boxed_env, live_host):
    ask = {"cmd": "mask", "text": "Offer for Acme Corp to a@x.io", "scope": "s"}
    host = live_host()
    assert host.ask(ask)["text"] == "Offer for Acme Corp to [EMAIL_1]"
    (boxed_env / "boxed.toml").write_text('[boxed.dictionary]\n"Acme Corp" = "CLIENT"\n')
    assert host.ask(ask)["text"] == "Offer for [CLIENT_1] to [EMAIL_1]"  # a new dictionary entry applies to the very next request
    (boxed_env / "boxed.toml").write_text("[boxed]\n")
    assert host.ask(ask)["text"] == "Offer for Acme Corp to [EMAIL_1]"  # and so does taking it out
    assert host.close() == 0


def test_a_boxed_toml_that_breaks_while_the_host_runs_stops_the_requests_until_it_is_mended(boxed_env, live_host):
    ask = {"cmd": "mask", "text": "Offer for Acme Corp to a@x.io", "scope": "s"}
    host = live_host()
    assert host.ask(ask)["ok"] is True
    (boxed_env / "boxed.toml").write_text('[boxed\ndictionary = {"Acme Corp"')
    assert host.ask(ask) == {"ok": False, "error": "host cannot start"}  # nothing is masked by a setting it could not read
    assert host.ask({"cmd": "ping"}) == {"ok": False, "error": "host cannot start"}  # as a program that starts on that file would say
    (boxed_env / "boxed.toml").write_text("[boxed]\n")
    assert host.ask(ask)["ok"] is True
    assert host.close() == 0
    lines = (boxed_env / HOST_LOG).read_text().splitlines()
    assert [line.split(" ", 1)[1] for line in lines] == ["host cannot start: UserError"] * 2  # config.py words a TOML error itself


def test_the_language_model_loads_once_for_a_host_that_stays_up(ctx, monkeypatch):
    from boxed import config

    loads = []

    class Model:  # stands in for Natasha, whose loading is what takes the time
        def __init__(self, tagger=None, *, cyrillic_only=False):
            loads.append(cyrillic_only)

        def find(self, text):
            return []

    monkeypatch.setattr("boxed.detect.ner.NatashaDetector", Model)
    config._ner_detectors.cache_clear()
    try:
        (ctx.home / "boxed.toml").write_text('[boxed]\nner = ["ru"]\n')
        stdout = io.BytesIO()
        assert serve(io.BytesIO(frames(*[{"cmd": "mask", "text": TEXT, "scope": "s"}] * 3)), stdout, ctx) == 0
        assert len(loads) == 1 and all(reply["ok"] for reply in replies(stdout.getvalue()))
    finally:
        config._ner_detectors.cache_clear()  # the stand-in must not reach another test


@pytest.fixture(autouse=True)
def no_other_gliner(monkeypatch):
    """A GLiNER detector that another test left alive must not make a host here end after its first answer."""
    monkeypatch.setattr(ner, "_loaded", weakref.WeakSet())


@pytest.fixture
def gliner_stand_in(monkeypatch):
    """ner = ["en"] builds a GLiNER with no model to load. Its tokenizer can be emptied, or the library has no call for it.
    Returns build(can_empty), which returns the list that fills with one item for every time the cache is emptied."""
    from boxed import config

    def build(can_empty):
        emptied = []
        cache = types.SimpleNamespace(_clear_cache=lambda: emptied.append(1)) if can_empty else types.SimpleNamespace()
        tokenizer = types.SimpleNamespace(backend_tokenizer=types.SimpleNamespace(model=cache))
        model = types.SimpleNamespace(
            data_processor=types.SimpleNamespace(transformer_tokenizer=tokenizer), predict_entities=lambda text, labels, threshold: []
        )
        real = ner.GlinerDetector
        monkeypatch.setattr(ner, "GlinerDetector", lambda: real(model=model))
        config._ner_detectors.cache_clear()
        return emptied

    yield build
    config._ner_detectors.cache_clear()


def test_a_host_empties_the_tokenizer_cache_after_each_request_and_stays_up(ctx, gliner_stand_in):
    emptied = gliner_stand_in(can_empty=True)
    (ctx.home / "boxed.toml").write_text('[boxed]\nner = ["en"]\n')
    stdout = io.BytesIO()
    assert serve(io.BytesIO(frames(*[{"cmd": "mask", "text": TEXT, "scope": "s"}] * 3, {"cmd": "ping"})), stdout, ctx) == 0
    assert [reply["ok"] for reply in replies(stdout.getvalue())] == [True] * 4
    assert len(emptied) == 3  # once for every text that was read


def test_a_host_that_cannot_empty_the_tokenizer_cache_ends_after_the_answer_that_used_it(ctx, gliner_stand_in):
    gliner_stand_in(can_empty=False)
    (ctx.home / "boxed.toml").write_text('[boxed]\nner = ["en"]\n')
    mask = {"cmd": "mask", "text": TEXT, "scope": "s"}
    stdin, stdout = io.BytesIO(frames({"cmd": "ping"}, mask, mask, {"cmd": "ping"})), io.BytesIO()
    assert serve(stdin, stdout, ctx) == 0
    ping, masked = replies(stdout.getvalue())  # the ping before the first use of GLiNER did not end the host, the mask did
    assert ping == {"ok": True, "version": __version__} and masked["text"] == "mail [EMAIL_1], key [SECRET_1], call [PHONE_1]"
    assert stdin.read() != b""  # the requests after it were not read: the browser starts the program again for them


class FakeStdout:
    def __init__(self) -> None:
        self.buffer = io.BytesIO()


@pytest.fixture
def run_main(capsys, monkeypatch):
    def run(*messages: dict) -> tuple[int, list[dict], str]:
        stdout = FakeStdout()
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(frames(*messages))))
        monkeypatch.setattr(sys, "stdout", stdout)
        code = main()
        return code, replies(stdout.buffer.getvalue()), capsys.readouterr().err

    return run


def test_main_serves_stdin_to_stdout_with_the_home_config(boxed_env, run_main):
    boxed_env.mkdir(parents=True, exist_ok=True)
    (boxed_env / "boxed.toml").write_text('[boxed.dictionary]\n"Acme Corp" = "CLIENT"\n')
    code, out, _ = run_main({"cmd": "ping"}, {"cmd": "mask", "text": "Offer for Acme Corp to a@x.io", "scope": "s"})
    assert code == 0
    assert out[0]["ok"] is True and out[1]["text"] == "Offer for [CLIENT_1] to [EMAIL_1]"


def test_main_keeps_observations_and_checks_in_the_boxed_home(boxed_env, run_main):
    code, out, _ = run_main(observe_message(site="claude"), check_set_message(account="me"), {"cmd": "checks"})
    assert code == 0
    assert out[0] == {"ok": True, "found": {"EMAIL": 1, "SECRET": 1, "PHONE": 1}} and out[1] == {"ok": True}
    assert [(c["provider"], c["account"], c["due"]) for c in out[2]["checks"]] == [("claude", "me", True)]  # memory unknown
    for name in ("checks.json", "observed.jsonl"):
        assert mode_is(boxed_env / name, 0o600)
    assert not (boxed_env / "journal.jsonl").exists()  # the main journal holds sends boxed made, not these


def test_main_keeps_stdout_for_frames_only(run_main, monkeypatch):
    def noisy(message, ctx):
        print("noise from a library")
        return {"ok": True}

    monkeypatch.setattr(native_host, "handle", noisy)
    code, out, err = run_main({"cmd": "ping"})
    assert (code, out) == (0, [{"ok": True}])
    assert "noise from a library" in err


def test_main_says_why_when_it_cannot_start(run_main, monkeypatch):
    def broken():
        raise RuntimeError("keychain is locked for ivan.petrov@acme.com")

    monkeypatch.setattr(native_host, "open_context", broken)
    code, out, err = run_main({"cmd": "ping"}, {"cmd": "mask", "text": TEXT})
    assert code == 1
    assert out == [{"ok": False, "error": "host cannot start"}] * 2
    assert "ivan" not in json.dumps(out)


# host-errors.log: what the person (or whoever helps them) can read when the panel says "cannot start" or "failed".

HOST_LOG = "host-errors.log"
LOG_CAP = 64 * 1024
LOG_LINE = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00 (?:internal error|host cannot start): \w+"


class Boom(Exception):
    pass


def fail_in_mask(monkeypatch, error=Boom):
    """mask_text raises, so a mask request ends in "internal error". The exception's text is the whole sensitive input."""

    def boom(*args, **kwargs):
        raise error(TEXT)

    monkeypatch.setattr(native_host, "mask_text", boom)


def mask_request(ctx):
    return handle({"cmd": "mask", "text": TEXT, "scope": "web-test"}, ctx)


def finishes(function, seconds=10):
    """function's result, or a failed test when it does not return: opening a pipe for writing waits for a reader."""
    done = []
    thread = threading.Thread(target=lambda: done.append(function()), daemon=True)
    thread.start()
    thread.join(seconds)
    assert not thread.is_alive(), "still waiting"
    return done[0]


def test_an_internal_error_leaves_one_line_with_the_class_name_and_nothing_else(ctx, monkeypatch):
    fail_in_mask(monkeypatch)
    assert mask_request(ctx) == {"ok": False, "error": "internal error"}
    log = ctx.home / HOST_LOG
    (line,) = log.read_text().splitlines()
    assert re.fullmatch(LOG_LINE, line) and line.endswith(" internal error: Boom")
    assert mode_is(log, 0o600)


def test_the_log_holds_no_message_no_text_and_not_the_cause(ctx, monkeypatch):
    def boom(*args, **kwargs):
        try:
            raise ValueError(TEXT)
        except ValueError as cause:
            raise Boom(TEXT, {"text": TEXT}) from cause

    monkeypatch.setattr(native_host, "mask_text", boom)
    mask_request(ctx)
    log = (ctx.home / HOST_LOG).read_text()
    for piece in [*VALUES, "ivan", "acme", "AKIA", "Traceback", "ValueError", "File "]:
        assert piece not in log, piece
    assert log.endswith(" internal error: Boom\n")


@pytest.mark.parametrize(
    ("message", "function"),
    [
        ({"cmd": "restore", "text": "[EMAIL_1]", "scope": "s"}, "restore"),
        (observe_message(), "observe"),
        ({"cmd": "checks"}, "load_checks"),
        (check_set_message(), "save_check"),
    ],
)
def test_every_command_that_fails_is_logged_the_same_way(ctx, monkeypatch, message, function):
    handle({"cmd": "mask", "text": TEXT, "scope": "s"}, ctx)  # a scope for restore to find

    def boom(*args, **kwargs):
        raise Boom(TEXT)

    monkeypatch.setattr(native_host, function, boom)
    assert handle(message, ctx) == {"ok": False, "error": "internal error"}
    (line,) = (ctx.home / HOST_LOG).read_text().splitlines()
    assert re.fullmatch(LOG_LINE, line) and line.endswith(" internal error: Boom")
    assert TEXT not in line


def test_a_refusal_is_not_a_failure_and_is_not_logged(ctx):
    assert handle({"cmd": "restore", "text": "x", "scope": "web-other"}, ctx) == {"ok": False, "error": "unknown scope"}
    assert handle({"cmd": "shell"}, ctx) == {"ok": False, "error": "bad request"}
    assert not (ctx.home / HOST_LOG).exists()


def test_a_host_that_cannot_start_logs_once_whatever_the_panel_asks(boxed_env, run_main, monkeypatch):
    boxed_env.mkdir(parents=True)

    def broken():
        raise RuntimeError("keychain is locked for ivan.petrov@acme.com")

    monkeypatch.setattr(native_host, "open_context", broken)
    code, out, _ = run_main({"cmd": "ping"}, {"cmd": "mask", "text": TEXT})
    assert (code, out) == (1, [{"ok": False, "error": "host cannot start"}] * 2)
    (line,) = (boxed_env / HOST_LOG).read_text().splitlines()
    assert re.fullmatch(LOG_LINE, line) and line.endswith(" host cannot start: RuntimeError")
    assert "ivan" not in line and "keychain" not in line


def test_logging_never_makes_the_boxed_home(boxed_env, run_main, monkeypatch):
    def broken():
        raise RuntimeError("no home yet")

    monkeypatch.setattr(native_host, "open_context", broken)
    code, out, _ = run_main({"cmd": "ping"})
    assert (code, out) == (1, [{"ok": False, "error": "host cannot start"}])
    assert not boxed_env.exists()  # a folder made here would have the default mode, not the 700 boxed_home() gives


def test_an_existing_log_is_added_to_and_made_private(ctx, monkeypatch):
    log = ctx.home / HOST_LOG
    log.write_text("an earlier line\n")
    log.chmod(0o644)
    fail_in_mask(monkeypatch)
    mask_request(ctx)
    assert log.read_text().startswith("an earlier line\n") and log.read_text().endswith(" internal error: Boom\n")
    assert mode_is(log, 0o600)


@pytest.mark.skipif(sys.platform == "win32", reason="a file mode means nothing on Windows: the folder decides who may read a file")
def test_a_new_log_is_private_under_any_umask(ctx, monkeypatch):
    fail_in_mask(monkeypatch)
    before = os.umask(0)
    try:
        mask_request(ctx)
    finally:
        os.umask(before)
    assert mode_is(ctx.home / HOST_LOG, 0o600)


def test_the_log_is_not_written_through_a_link(ctx, monkeypatch, tmp_path):
    fail_in_mask(monkeypatch)
    log = ctx.home / HOST_LOG
    kept = tmp_path / "somebody-elses-file.txt"
    kept.write_text("keep")
    log.symlink_to(kept)
    assert mask_request(ctx) == {"ok": False, "error": "internal error"}
    assert kept.read_text() == "keep"
    log.unlink()
    log.symlink_to(tmp_path / "not-there-yet.txt")  # a link to nothing must not be filled in either
    assert mask_request(ctx) == {"ok": False, "error": "internal error"}
    assert not (tmp_path / "not-there-yet.txt").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no pipe in the file system (os.mkfifo)")
def test_the_log_is_not_written_into_a_pipe_and_does_not_wait_for_one(ctx, monkeypatch):
    fail_in_mask(monkeypatch)
    log = ctx.home / HOST_LOG
    os.mkfifo(log)
    assert finishes(lambda: mask_request(ctx)) == {"ok": False, "error": "internal error"}  # nobody reads the pipe
    reader = os.open(log, os.O_RDONLY | os.O_NONBLOCK)  # now somebody does: a write would go through
    try:
        assert finishes(lambda: mask_request(ctx)) == {"ok": False, "error": "internal error"}
        assert os.read(reader, 4096) == b""
    finally:
        os.close(reader)


def test_a_folder_in_place_of_the_log_changes_nothing(ctx, monkeypatch):
    fail_in_mask(monkeypatch)
    (ctx.home / HOST_LOG).mkdir()
    assert mask_request(ctx) == {"ok": False, "error": "internal error"}
    assert list((ctx.home / HOST_LOG).iterdir()) == []


def test_a_log_that_is_also_another_file_is_left_alone(ctx, monkeypatch, tmp_path):
    """A hard link to a file of the same user passes every check of a plain file of one's own, and writing to it, or emptying it
    past the cap, changes that other file: 200 KB of somebody's notes became one line."""
    fail_in_mask(monkeypatch)
    other = tmp_path / "notes.txt"
    other.write_bytes(b"x" * 3 * LOG_CAP)
    other.chmod(0o644)
    os.link(other, ctx.home / HOST_LOG)
    assert mask_request(ctx) == {"ok": False, "error": "internal error"}
    assert other.read_bytes() == b"x" * 3 * LOG_CAP and mode_is(other, 0o644)


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no user number for a file (os.geteuid)")
def test_a_log_that_somebody_else_owns_is_left_alone(ctx, monkeypatch):
    log = ctx.home / HOST_LOG
    log.write_text("theirs\n")
    mine = log.stat().st_uid
    fail_in_mask(monkeypatch)
    monkeypatch.setattr(os, "geteuid", lambda: mine + 1)
    assert mask_request(ctx) == {"ok": False, "error": "internal error"}
    assert log.read_text() == "theirs\n"


@pytest.mark.skipif(sys.platform == "win32", reason="a folder that takes no new files is a mode, which means nothing on Windows (the next test refuses the write another way)")
def test_a_log_that_cannot_be_written_does_not_change_the_answer(ctx, monkeypatch):
    fail_in_mask(monkeypatch)
    ctx.home.chmod(0o500)  # no new files in the home
    try:
        assert mask_request(ctx) == {"ok": False, "error": "internal error"}
    finally:
        ctx.home.chmod(0o700)
    assert not (ctx.home / HOST_LOG).exists()


def test_a_log_that_is_read_only_does_not_change_the_answer(ctx, monkeypatch):
    """The refusal Windows has: the read-only mark of the file, which stops a write there as a mode does elsewhere."""
    log = ctx.home / HOST_LOG
    log.write_text("theirs\n")
    log.chmod(stat.S_IREAD)
    fail_in_mask(monkeypatch)
    try:
        assert mask_request(ctx) == {"ok": False, "error": "internal error"}
    finally:
        log.chmod(stat.S_IREAD | stat.S_IWRITE)
    assert log.read_text() == "theirs\n"


def test_the_log_stops_at_64_kib_and_keeps_the_newest_line(ctx):
    log = ctx.home / HOST_LOG

    def fail():
        native_host._log_failure(ctx.home, "internal error", Boom(TEXT))

    fail()
    line = log.stat().st_size  # every line of this error has this length
    log.write_bytes(b"x" * (LOG_CAP - line))  # one more line fills it exactly: allowed
    fail()
    assert log.stat().st_size == LOG_CAP and log.read_bytes().startswith(b"xxxx")
    fail()  # one line more than fits
    assert log.stat().st_size <= LOG_CAP and log.read_text().endswith(" internal error: Boom\n")
    for _ in range(2 * LOG_CAP // line + 10):  # twice over, and then some
        fail()
        assert log.stat().st_size <= LOG_CAP
    assert log.read_text().endswith(" internal error: Boom\n")


@pytest.mark.skipif(sys.platform == "win32", reason="boxed workspace is not supported on Windows yet")
def test_agents_in_a_mirror_cannot_read_the_host_log(ctx, tmp_path):
    from boxed.hooks import hook_pre_tool_use
    from boxed.workspace import SENSITIVE_HOME_PARTS, create_workspace

    assert HOST_LOG in SENSITIVE_HOME_PARTS
    project = tmp_path / "project"
    project.mkdir()
    (project / "notes.txt").write_text("hello\n")
    ws = create_workspace(project, level=2, config=ProjectConfig(), vault=ctx.vault, journal=ctx.journal, home=ctx.home).workspace
    (ctx.home / HOST_LOG).write_text("2026-10-23T09:00:00+00:00 internal error: Boom\n")
    for name, tool_input in (("Read", {"file_path": str(ctx.home / HOST_LOG)}), ("Bash", {"command": f"cat {ctx.home / HOST_LOG}"})):
        payload = {"hook_event_name": "PreToolUse", "tool_name": name, "tool_input": tool_input, "cwd": str(ws.mirror)}
        assert hook_pre_tool_use(payload, ctx.home).exit_code == 2, name


@pytest.mark.skipif(sys.platform == "win32", reason="pins the macOS folders, launcher and modes of the native host")
def test_launcher_runs_the_host_over_stdio(tmp_path, macos):
    extension_id = "abcdefghijklmnopabcdefghijklmnop"
    (manifest,) = install_native_host(extension_id, browsers=("chrome",), home=tmp_path / "user")
    launcher = json.loads(manifest.read_text())["path"]
    planted = tmp_path / "cwd"
    planted.mkdir()
    (planted / "json.py").write_text("raise RuntimeError('imported from the working directory')\n")
    request = frames({"cmd": "ping"}, {"cmd": "mask", "text": TEXT, "scope": "s"}, {"cmd": "restore", "text": "[EMAIL_1]", "scope": "s"})
    run = subprocess.run(
        [launcher, f"chrome-extension://{extension_id}/"], input=request, capture_output=True, cwd=planted, timeout=120
    )
    assert run.returncode == 0, run.stderr
    ping, masked, restored = replies(run.stdout)
    assert ping == {"ok": True, "version": __version__}
    assert masked["text"] == "mail [EMAIL_1], key [SECRET_1], call [PHONE_1]"
    assert restored["text"] == "ivan.petrov@acme.com"
    assert b"ivan" not in run.stderr


def test_extension_manifest_is_minimal():
    manifest = json.loads((EXTENSION / "manifest.json").read_text())
    assert manifest["manifest_version"] == 3 and manifest["version"] == __version__
    assert sorted(manifest["host_permissions"]) == sorted(SITES)
    # webRequest: read-only observation. Insert needs no activeTab (the host permissions of the five chats cover the tab it
    # fills) and Copy needs no clipboardWrite (it writes from the click on its button)
    assert sorted(manifest["permissions"]) == ["nativeMessaging", "scripting", "sidePanel", "storage", "webRequest"]
    assert "<all_urls>" not in json.dumps(manifest) and "tabs" not in manifest["permissions"]
    # nothing through which a page, another extension or a remote server could reach in
    assert not {
        "content_scripts",
        "externally_connectable",
        "web_accessible_resources",
        "optional_permissions",
        "optional_host_permissions",
        "update_url",
    } & manifest.keys()
    assert manifest["content_security_policy"] == {"extension_pages": "script-src 'self'; object-src 'self'"}
    assert manifest["background"] == {"service_worker": "background.js", "type": "module"}  # imports lib/ without importScripts
    assert manifest["side_panel"] == {"default_path": "sidepanel.html"}


def test_extension_panel_is_wired():
    manifest = json.loads((EXTENSION / "manifest.json").read_text())
    panel = (EXTENSION / "sidepanel.html").read_text()
    scripts = re.findall(r'<script src="([^"]+)">', panel)
    assert scripts == ["lib/protocol.js", "sidepanel.js"]  # the shared functions load first
    for name in [manifest["background"]["service_worker"], manifest["side_panel"]["default_path"], *scripts]:
        assert (EXTENSION / name).is_file(), name
    used = set(re.findall(r'\$\("([a-z-]+)"\)', (EXTENSION / "sidepanel.js").read_text()))
    defined = re.findall(r'\bid="([a-z-]+)"', panel)
    assert used and used <= set(defined)
    assert len(defined) == len(set(defined))
    labelled = set(re.findall(r'<label for="([a-z-]+)"', panel))
    assert set(re.findall(r'<(?:input|textarea|select) id="([a-z-]+)"', panel)) == labelled  # every field has a label


FORBIDDEN_IN_EXTENSION_CODE = [
    r"\beval\s*\(",
    r"\bnew\s+Function\b",
    r"\bimportScripts\b",
    r"\bimport\s*\(",
    r"\bfetch\s*\(",
    r"\bXMLHttpRequest\b",
    r"\bWebSocket\b",
    r"\bEventSource\b",
    r"\bsendBeacon\b",
    r"\binnerHTML\b",
    r"\bouterHTML\b",
    r"\binsertAdjacentHTML\b",
    r"\bdocument\.write\b",
    r"\bon[a-z]+\s*=\s*[\"']",  # inline event handlers
]


HOMEPAGE = "https://boxed.si"  # the one address outside SITES that manifest.json may name, as homepage_url


def extension_code() -> list[Path]:
    return [p for p in EXTENSION.rglob("*") if p.suffix in {".js", ".html", ".json"} and "test" not in p.relative_to(EXTENSION).parts]


def test_extension_has_no_remote_code_and_no_network():
    files = extension_code()
    assert {p.name for p in files} >= {"manifest.json", "protocol.js"}
    for path in files:
        text = path.read_text()
        for pattern in FORBIDDEN_IN_EXTENSION_CODE:
            assert not re.search(pattern, text), f"{path.name}: {pattern}"
        if path.name == "manifest.json" and path.parent == EXTENSION:  # the link on the browser's extensions page, not a request
            manifest = json.loads(text)
            assert manifest.pop("homepage_url", HOMEPAGE) == HOMEPAGE, f"{path.name}: homepage_url"
            text = json.dumps(manifest)
        for tag in re.findall(r"<script\b[^>]*>", text) if path.suffix == ".html" else []:
            assert re.fullmatch(r'<script src="[A-Za-z0-9_./-]+">', tag), f"{path.name}: {tag}"  # packaged, never inline
        for url in re.findall(r"https?://[^\s\"'`<>)]+", text):
            assert any(url.startswith(site.removesuffix("*")) for site in SITES), f"{path.name}: {url}"


def test_host_reads_only_the_boxed_home_config(tmp_path, monkeypatch):
    from boxed.native_host import handle, open_context

    (tmp_path / "boxed.toml").write_text('[boxed]\nallow = ["ivan@acme.com"]\n')
    monkeypatch.setenv("BOXED_HOME", str(tmp_path / "home"))
    reply = handle({"cmd": "mask", "text": "mail ivan@acme.com"}, open_context())
    assert reply["ok"] and "[EMAIL_1]" in reply["text"]


# ---- Windows: the same log, where os has no O_NOFOLLOW, O_NONBLOCK, geteuid or fchmod ----


def test_windows_the_log_is_written_where_os_has_none_of_the_posix_calls(ctx, windows_os, monkeypatch):
    fail_in_mask(monkeypatch)
    assert mask_request(ctx) == {"ok": False, "error": "internal error"}
    assert (ctx.home / HOST_LOG).read_text().endswith(" internal error: Boom\n")  # the line was written, and written once


def test_windows_a_reparse_point_in_place_of_the_log_is_left_alone(ctx, windows_os, see_as, monkeypatch):
    log = ctx.home / HOST_LOG
    log.write_text("theirs\n")
    see_as(log, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)  # a plain file by its mode, a junction or a placeholder for Windows
    fail_in_mask(monkeypatch)
    assert mask_request(ctx) == {"ok": False, "error": "internal error"}
    assert log.read_text() == "theirs\n"


def test_the_command_line_starts_the_host_for_a_program_that_has_no_dash_m(monkeypatch):
    """A frozen program cannot run `python -m boxed.native_host`: its launcher runs `boxed native-host`, without the arguments the browser adds."""
    from boxed.cli import main as boxed_main

    stdin, stdout = io.BytesIO(frames({"cmd": "ping"}, {"cmd": "mask", "text": "mail ivan@acme.com", "scope": "s"})), io.BytesIO()
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(buffer=stdin))
    monkeypatch.setattr(sys, "stdout", types.SimpleNamespace(buffer=stdout))
    assert boxed_main(["native-host"]) == 0
    answers = stdout.getvalue()
    stdout.seek(0)
    assert [read_message(stdout)["ok"], read_message(stdout)["text"]] == [True, "mail [EMAIL_1]"] and read_message(stdout) is None, answers
