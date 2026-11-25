"""The command line of ask, key, check and the dashboard flags. No test reaches the real network, the real
~/.boxed or the real keychain: a local server stands in for the provider, a memory backend for the keychain."""

import csv
import io
import json
import os
import re
import socket
import stat
import threading
from dataclasses import replace
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError

from boxed.channels import PROVIDERS
from boxed.checks import Check, load_checks, save_check
from boxed.cli import main
from boxed.journal import Journal, JournalEntry
from boxed.keys import default_keystore
from boxed.observe import observe, observed_journal
from support import mode_is

KEY = "sk-test-0123456789abcdef"
TEXT = "Write to ivan@acme.com about the invoice"
MASKED = "Write to [EMAIL_1] about the invoice"


def run(capsys, argv, stdin=None, monkeypatch=None):
    if stdin is not None:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    code = main(argv)
    out, err = capsys.readouterr()
    return code, out, err


class MemoryKeyring(KeyringBackend):
    priority = 1

    def __init__(self):
        super().__init__()
        self.store = {}

    def get_password(self, service, username):
        return self.store.get((service, username))

    def set_password(self, service, username, password):
        self.store[(service, username)] = password

    def delete_password(self, service, username):
        try:
            del self.store[(service, username)]
        except KeyError:
            raise PasswordDeleteError("not found") from None


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    """No proxy, no real keys, no relay from the developer's shell, a keychain in memory, and no connection but to this computer:
    a test that would reach a provider fails instead."""
    real_connect = socket.socket.connect

    def only_here(self, address):
        host = address[0] if isinstance(address, tuple) else address
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise AssertionError("a test tried to reach beyond this computer")
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", only_here)
    for name in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    for provider in PROVIDERS.values():
        monkeypatch.delenv(provider.env_key, raising=False)
        monkeypatch.delenv(f"BOXED_{provider.name.upper()}_BASE_URL", raising=False)
    previous = keyring.get_keyring()
    backend = MemoryKeyring()
    keyring.set_keyring(backend)
    yield backend
    keyring.set_keyring(previous)


@pytest.fixture
def memory_keyring(isolated):
    return isolated


@pytest.fixture
def start_api():
    """A local stand-in for a provider's API: it records what arrives and answers with what the test sets."""
    started = []

    def start(status=200, body=b"{}"):
        api = SimpleNamespace(requests=[], status=status, body=body)

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                lowered = {name.lower(): value for name, value in self.headers.items()}
                api.requests.append(SimpleNamespace(path=self.path, headers=lowered, body=raw))
                self.send_response(api.status)
                self.send_header("Content-Length", str(len(api.body)))
                self.end_headers()
                self.wfile.write(api.body)

            def log_message(self, *args):
                pass

        api.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        api.url = f"http://127.0.0.1:{api.server.server_address[1]}"
        threading.Thread(target=api.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
        started.append(api)
        return api

    yield start
    for api in started:
        api.server.shutdown()
        api.server.server_close()


def answer(text="Dear [EMAIL_1], noted.", **extra):
    """A body in the shape of the OpenAI Responses API."""
    body = {
        "model": "gpt-test-2026",
        "status": "completed",
        "output": [{"type": "message", "content": [{"type": "output_text", "text": text}]}],
        "usage": {"input_tokens": 12, "output_tokens": 5},
    }
    return json.dumps(body | extra).encode()


@pytest.fixture
def openai_api(start_api, monkeypatch):
    """OpenAI's endpoint replaced by a local server, and a key in the environment."""
    api = start_api(body=answer())
    monkeypatch.setitem(PROVIDERS, "openai", replace(PROVIDERS["openai"], base_url=api.url))
    monkeypatch.setenv("OPENAI_API_KEY", KEY)
    return api


def ask(capsys, extra=(), stdin=TEXT, monkeypatch=None, provider="openai"):
    argv = ["ask", "--provider", provider, "--model", "gpt-test", *extra, "-"]
    return run(capsys, argv, stdin=stdin, monkeypatch=monkeypatch)


def journal_records(boxed_env):
    path = boxed_env / "journal.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


# ---- ask ----


def test_ask_prints_the_restored_answer_and_sends_only_the_masked_text(capsys, monkeypatch, openai_api, boxed_env):
    code, out, err = ask(capsys, monkeypatch=monkeypatch)
    assert code == 0 and out == "Dear ivan@acme.com, noted."
    [request] = openai_api.requests
    assert request.path == "/responses" and request.headers["authorization"] == f"Bearer {KEY}"
    assert json.loads(request.body)["input"] == MASKED and b"ivan@acme.com" not in request.body
    sent, received = journal_records(boxed_env)
    assert (sent["channel"], sent["status"], sent["model"]) == ("api", "sent", "gpt-test")
    assert (received["status"], received["usage"]) == ("received", {"input": 12, "output": 5})
    assert KEY not in out + err + (boxed_env / "journal.jsonl").read_text()  # a key is never printed or journaled
    assert "ivan@acme.com" not in err + (boxed_env / "journal.jsonl").read_text()


def test_ask_reads_a_file_and_takes_a_scope_and_a_level(tmp_path, capsys, monkeypatch, openai_api, boxed_env):
    prompt = tmp_path / "prompt.txt"
    prompt.write_text(TEXT)
    argv = ["ask", "--provider", "openai", "--model", "gpt-test", "--scope", "deal-7", "--level", "3", str(prompt)]
    code, out, _ = run(capsys, argv)
    assert code == 0 and out == "Dear ivan@acme.com, noted."
    sent, _ = journal_records(boxed_env)
    assert (sent["scope"], sent["level"]) == ("deal-7", 3)
    code, restored, _ = run(capsys, ["restore", "--scope", "deal-7", "-"], stdin="mail [EMAIL_1]", monkeypatch=monkeypatch)
    assert code == 0 and restored == "mail ivan@acme.com"  # the scope of an ask is a scope like any other


def test_ask_without_a_scope_names_one_and_says_which(capsys, monkeypatch, openai_api, boxed_env):
    code, _, err = ask(capsys, monkeypatch=monkeypatch)
    [scope] = {record["scope"] for record in journal_records(boxed_env)}
    assert code == 0 and scope.startswith("ask-") and scope in err


def test_ask_prints_the_policy_warnings_on_stderr(capsys, monkeypatch, openai_api):
    code, out, err = ask(capsys, monkeypatch=monkeypatch)
    assert code == 0 and "EEA" in err and "EEA" not in out  # personal data leaving the EEA: the answer stays clean


def test_ask_exit_4_when_the_policy_blocks_and_nothing_is_sent(tmp_path, capsys, monkeypatch, openai_api, boxed_env):
    (tmp_path / "boxed.toml").write_text('[boxed]\n[boxed.policy]\nprofile = "ban"\n')
    monkeypatch.chdir(tmp_path)
    code, out, err = ask(capsys, monkeypatch=monkeypatch)
    assert code == 4 and out == "" and "deny" in err
    assert openai_api.requests == []
    [record] = journal_records(boxed_env)
    assert record["status"] == "blocked"
    assert "ivan@acme.com" not in err


@pytest.mark.parametrize("how", ["flag", "config"])
def test_ask_refuses_level_4_and_points_to_the_plan(tmp_path, capsys, monkeypatch, openai_api, boxed_env, how):
    """The detector treats 4 as 3: the text would go out masked at 3 and the journal would call it level 4."""
    if how == "config":
        (tmp_path / "boxed.toml").write_text("[boxed]\nlevel = 4\n")
        monkeypatch.chdir(tmp_path)
    code, out, err = ask(capsys, ["--level", "4"] if how == "flag" else [], monkeypatch=monkeypatch)
    assert code == 2 and out == ""
    assert err.strip() == "boxed: error: level 4 sends the task and the table schema only: use boxed plan, or ask at a level from 0 to 3"
    assert openai_api.requests == [] and journal_records(boxed_env) == []


def test_ask_at_level_3_goes_out_and_is_recorded_as_3(capsys, monkeypatch, openai_api, boxed_env):
    code, _, _ = ask(capsys, ["--level", "3"], monkeypatch=monkeypatch)
    assert code == 0 and journal_records(boxed_env)[0]["level"] == 3


def test_ask_exit_4_with_the_plan_hint_when_the_policy_needs_level_4(tmp_path, capsys, monkeypatch, openai_api, boxed_env):
    (tmp_path / "boxed.toml").write_text('[boxed]\n[boxed.policy.rules]\n"personal:personal-private" = "masked:4"\n')
    monkeypatch.chdir(tmp_path)
    code, out, err = ask(capsys, monkeypatch=monkeypatch)
    assert code == 4 and out == "" and openai_api.requests == []
    assert "boxed plan" in err and "reason: personal for personal-private: masked at level 4" in err
    [record] = journal_records(boxed_env)
    assert (record["status"], record["level"]) == ("blocked", 2)  # never 4: nothing was masked at 4


HOSTILE = "ok \x1b]52;c;aGk=\x07 \x1b[2J \x9b31m done\r\nsecond\tline\x7f end"  # OSC 52 (clipboard), clear screen, CSI, CR, DEL


def test_ask_shows_the_control_characters_of_an_answer_escaped_on_a_terminal(capsys, monkeypatch, openai_api):
    openai_api.body = answer(HOSTILE)
    screen = Terminal()
    monkeypatch.setattr("sys.stdin", io.StringIO(TEXT))
    monkeypatch.setattr("sys.stdout", screen)
    code = main(["ask", "--provider", "openai", "--model", "gpt-test", "-"])
    shown = screen.getvalue()
    assert code == 0 and "\x1b" not in shown and "\x07" not in shown and "\x9b" not in shown and "\r" not in shown and "\x7f" not in shown
    assert shown == "ok \\x1b]52;c;aGk=\\x07 \\x1b[2J \\x9b31m done\\x0d\nsecond\tline\\x7f end"  # the line feed and the tab stay
    capsys.readouterr()


def test_ask_keeps_the_answer_exactly_as_it_is_for_a_pipe_or_a_file(capsys, monkeypatch, openai_api):
    openai_api.body = answer(HOSTILE)
    code, out, _ = ask(capsys, monkeypatch=monkeypatch)  # the captured stdout is not a terminal
    assert code == 0 and out == HOSTILE


def test_ask_escapes_what_it_quotes_from_the_answer_on_a_terminal_too(capsys, monkeypatch, openai_api):
    openai_api.body = answer("see [\rEMAIL_1] and [EMAIL_9]")  # a near placeholder is quoted back in the warning
    warnings = Terminal()
    monkeypatch.setattr("sys.stdin", io.StringIO(TEXT))
    monkeypatch.setattr("sys.stderr", warnings)
    code = main(["ask", "--provider", "openai", "--model", "gpt-test", "-"])
    assert code == 3 and "\r" not in warnings.getvalue() and "[EMAIL_9]" in warnings.getvalue()
    capsys.readouterr()


CP1251 = "Привет, пароль: hunter2".encode("cp1251")  # a Windows text file; the first byte is 0xcf


@pytest.mark.parametrize("command", [["ask", "--provider", "openai", "--model", "gpt-test"], ["mask"], ["restore", "--scope", "s"]])
@pytest.mark.parametrize("source", ["stdin", "file"])
def test_input_that_is_not_utf_8_is_refused_without_quoting_a_byte_of_it(tmp_path, capsys, monkeypatch, openai_api, boxed_env, command, source):
    """Python's own error says "byte 0xcf in position 0": a byte of the prompt."""
    run(capsys, ["mask", "--scope", "s", "-"], stdin="mail ivan@acme.com", monkeypatch=monkeypatch)  # a scope for restore to find
    before = journal_records(boxed_env)
    if source == "stdin":
        monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(CP1251), encoding="utf-8"))
        argv = [*command, "-"]
    else:
        (tmp_path / "prompt.txt").write_bytes(CP1251)
        argv = [*command, str(tmp_path / "prompt.txt")]
    code, out, err = run(capsys, argv)
    assert code == 2 and out == "" and err.strip() == "boxed: error: the input is not UTF-8"
    assert openai_api.requests == [] and journal_records(boxed_env) == before


def test_ask_exit_4_also_when_the_policy_says_local_only(tmp_path, capsys, monkeypatch, openai_api, boxed_env):
    (tmp_path / "boxed.toml").write_text('[boxed]\n[boxed.policy]\nprofile = "no-confidential"\n')
    monkeypatch.chdir(tmp_path)
    code, out, err = ask(capsys, ["--category", "hr"], stdin="Review of the team", monkeypatch=monkeypatch)
    assert code == 4 and out == "" and "local only" in err and openai_api.requests == []
    assert [record["status"] for record in journal_records(boxed_env)] == ["blocked"]


def test_ask_exit_2_and_nothing_sent_when_the_journal_cannot_be_written(capsys, monkeypatch, openai_api, boxed_env):
    boxed_env.mkdir(parents=True, exist_ok=True)
    (boxed_env / "journal.jsonl").mkdir()  # the journal cannot be written
    code, out, err = ask(capsys, monkeypatch=monkeypatch)
    assert code == 2 and out == "" and openai_api.requests == []
    assert KEY not in err and "ivan@acme.com" not in err


def test_ask_masks_amounts_and_dates_with_the_level_the_policy_asks_for_and_restores_them(capsys, monkeypatch, openai_api, boxed_env):
    """No profile is set: finance still goes to a personal account at level 3 or higher, and an amount is finance."""
    openai_api.body = answer("Noted: [MONEY_1] due on [DATE_1].")
    code, out, err = ask(capsys, stdin="Total due: $1,200.50 on 21.10.2026", monkeypatch=monkeypatch)
    assert code == 0 and out == "Noted: $1,200.50 due on 21.10.2026."
    sent = json.loads(openai_api.requests[0].body)["input"]
    assert sent == "Total due: [MONEY_1] on [DATE_1]" and "1,200" not in sent and "2026" not in sent
    record = journal_records(boxed_env)[0]
    assert (record["level"], record["markers_by_kind"]) == (3, {"MONEY": 1, "DATE": 1})


def test_ask_exit_3_with_unknown_or_suspicious_placeholders_still_prints_the_answer(capsys, monkeypatch, openai_api):
    openai_api.body = answer("Mail [EMAIL_1], not [EMAIL_9], and [EMAIL-1] is odd.")
    code, out, err = ask(capsys, monkeypatch=monkeypatch)
    assert code == 3
    assert out == "Mail ivan@acme.com, not [EMAIL_9], and [EMAIL-1] is odd."  # a paid answer is not thrown away
    assert "[EMAIL_9]" in err and "[EMAIL-1]" in err and "check by hand" in err


def test_ask_exit_1_on_a_channel_error_with_its_fixed_text(capsys, monkeypatch, openai_api, boxed_env):
    openai_api.status = 401
    openai_api.body = json.dumps({"error": {"message": f"bad key {KEY} for {MASKED}", "code": "invalid_api_key"}}).encode()
    code, out, err = ask(capsys, monkeypatch=monkeypatch)
    assert code == 1 and out == ""
    assert err.strip() == "boxed: openai: HTTP 401 (invalid_api_key)"
    assert KEY not in err and MASKED not in err
    assert [record["status"] for record in journal_records(boxed_env)] == ["sent", "error"]


def test_ask_exit_2_when_no_key_is_set(capsys, monkeypatch, start_api, boxed_env):
    api = start_api(body=answer())
    monkeypatch.setitem(PROVIDERS, "openai", replace(PROVIDERS["openai"], base_url=api.url))
    code, out, err = ask(capsys, monkeypatch=monkeypatch)
    assert code == 2 and out == ""
    assert "no API key for openai: run boxed key set openai" in err
    assert api.requests == [] and journal_records(boxed_env) == []


def test_ask_takes_the_key_from_the_keychain(capsys, monkeypatch, openai_api, memory_keyring):
    monkeypatch.delenv("OPENAI_API_KEY")
    memory_keyring.set_password("boxed.si", "api-key:openai", "sk-from-keychain")
    code, _, _ = ask(capsys, monkeypatch=monkeypatch)
    assert code == 0 and openai_api.requests[0].headers["authorization"] == "Bearer sk-from-keychain"


def test_ask_says_when_the_answer_was_cut_off(capsys, monkeypatch, openai_api):
    openai_api.body = answer("Dear [EMAIL_1], and then", status="incomplete", incomplete_details={"reason": "max_output_tokens"})
    code, out, err = ask(capsys, monkeypatch=monkeypatch)
    assert code == 0 and out == "Dear ivan@acme.com, and then"  # the answer is usable: a warning, not a failure
    assert "the answer was cut off" in err


def test_ask_names_the_account(capsys, monkeypatch, openai_api, boxed_env):
    code, _, _ = ask(capsys, ["--account", "corporate"], monkeypatch=monkeypatch)
    assert code == 0 and journal_records(boxed_env)[0]["account_type"] == "corporate"


def test_ask_refuses_an_account_that_is_not_a_remote_recipient(capsys, monkeypatch, openai_api):
    with pytest.raises(SystemExit) as stop:
        ask(capsys, ["--account", "local"], monkeypatch=monkeypatch)
    assert stop.value.code == 2 and "argument --account: not one of personal-training, personal-private, corporate, api-zero-retention" in capsys.readouterr().err
    assert openai_api.requests == []


def test_ask_the_category_is_added_before_the_policy_decides(tmp_path, capsys, monkeypatch, openai_api, boxed_env):
    (tmp_path / "boxed.toml").write_text('[boxed]\n[boxed.policy]\nprofile = "approved-only"\n')
    monkeypatch.chdir(tmp_path)
    openai_api.body = answer("Noted.")
    code, _, _ = ask(capsys, stdin="Q3 plan", monkeypatch=monkeypatch)  # nothing in it raises a category
    assert code == 0 and len(openai_api.requests) == 1
    code, out, err = ask(capsys, ["--category", "finance"], stdin="Q3 plan", monkeypatch=monkeypatch)
    assert code == 4 and out == "" and "finance" in err
    assert len(openai_api.requests) == 1


def test_ask_the_category_can_be_repeated(tmp_path, capsys, monkeypatch, openai_api, boxed_env):
    (tmp_path / "boxed.toml").write_text('[boxed]\nlevel = 0\n[boxed.policy]\nprofile = "no-confidential"\n')
    monkeypatch.chdir(tmp_path)
    openai_api.body = answer("Noted.")
    code, _, _ = ask(capsys, ["--category", "finance", "--category", "hr"], stdin="Q3 plan", monkeypatch=monkeypatch)
    assert code == 4  # hr is local only under this profile
    code, _, _ = ask(capsys, ["--category", "strategy", "--category", "finance"], stdin="Q3 plan", monkeypatch=monkeypatch)
    assert code == 0 and journal_records(boxed_env)[-2]["level"] == 3


def test_ask_refuses_a_category_a_detector_raises(capsys, monkeypatch, openai_api):
    with pytest.raises(SystemExit) as stop:
        ask(capsys, ["--category", "secrets"], monkeypatch=monkeypatch)
    assert stop.value.code == 2 and "argument --category: not one of finance, strategy, hr, health" in capsys.readouterr().err
    assert openai_api.requests == []


def test_ask_sends_through_a_relay_named_in_the_environment(capsys, monkeypatch, start_api, boxed_env):
    relay = start_api(body=answer())
    monkeypatch.setenv("OPENAI_API_KEY", KEY)
    monkeypatch.setenv("BOXED_OPENAI_BASE_URL", relay.url + "/openai/v1")  # http is fine to this computer
    code, out, err = ask(capsys, monkeypatch=monkeypatch)
    assert code == 0 and out == "Dear ivan@acme.com, noted."
    [request] = relay.requests
    assert request.path == "/openai/v1/responses" and request.headers["authorization"] == f"Bearer {KEY}"
    assert b"ivan@acme.com" not in request.body
    assert [record["note"] for record in journal_records(boxed_env)][0] == "relay"
    assert KEY not in out + err
    [notice] = [line for line in err.splitlines() if "relay" in line]  # said once, on stderr, where the request goes
    assert relay.url.removeprefix("http://") in notice and "BOXED_OPENAI_BASE_URL" in notice
    assert "/openai/v1" not in notice and KEY not in notice and "ivan@acme.com" not in notice


def test_ask_says_nothing_of_a_relay_when_there_is_none(capsys, monkeypatch, openai_api):
    code, _, err = ask(capsys, monkeypatch=monkeypatch)
    assert code == 0 and "relay" not in err


def test_ask_says_nothing_of_a_relay_when_the_policy_stops_the_request(tmp_path, capsys, monkeypatch, start_api):
    relay = start_api(body=answer())
    monkeypatch.setenv("OPENAI_API_KEY", KEY)
    monkeypatch.setenv("BOXED_OPENAI_BASE_URL", relay.url)
    (tmp_path / "boxed.toml").write_text('[boxed]\n[boxed.policy]\nprofile = "ban"\n')
    monkeypatch.chdir(tmp_path)
    code, _, err = ask(capsys, monkeypatch=monkeypatch)
    assert code == 4 and "relay" not in err and relay.requests == []  # nothing went anywhere


def test_ask_says_where_the_request_went_even_when_the_relay_refuses_it(capsys, monkeypatch, start_api):
    relay = start_api(status=401, body=json.dumps({"error": {"code": "invalid_api_key"}}).encode())
    monkeypatch.setenv("OPENAI_API_KEY", KEY)
    monkeypatch.setenv("BOXED_OPENAI_BASE_URL", relay.url)
    code, _, err = ask(capsys, monkeypatch=monkeypatch)
    assert code == 1 and len([line for line in err.splitlines() if "relay" in line]) == 1
    assert "openai: HTTP 401 (invalid_api_key)" in err


def test_ask_exit_2_for_a_relay_address_a_key_must_not_go_to(capsys, monkeypatch, start_api, boxed_env):
    api = start_api(body=answer())
    monkeypatch.setenv("OPENAI_API_KEY", KEY)
    monkeypatch.setenv("BOXED_OPENAI_BASE_URL", "http://relay.example.com/v1")
    code, out, err = ask(capsys, monkeypatch=monkeypatch)
    assert code == 2 and out == ""
    assert "BOXED_OPENAI_BASE_URL must be an https address" in err and "relay.example.com" not in err
    assert api.requests == [] and journal_records(boxed_env) == []


def test_openrouter_zero_retention_and_the_reported_cost_run_through_to_the_dashboard(tmp_path, capsys, monkeypatch, start_api, boxed_env):
    usage = {"prompt_tokens": 8, "completion_tokens": 3, "cost": 0.000042}
    api = start_api(body=json.dumps({"model": "vendor/m", "choices": [{"message": {"content": "Dear [EMAIL_1]"}}], "usage": usage}).encode())
    monkeypatch.setenv("OPENROUTER_API_KEY", KEY)
    monkeypatch.setenv("BOXED_OPENROUTER_BASE_URL", api.url)
    argv = ["ask", "--provider", "openrouter", "--model", "vendor/m", "--account", "api-zero-retention", "-"]
    code, out, err = run(capsys, argv, stdin=TEXT, monkeypatch=monkeypatch)
    assert code == 0 and out == "Dear ivan@acme.com" and KEY not in err
    [request] = api.requests
    assert json.loads(request.body)["provider"] == {"data_collection": "deny", "zdr": True}  # the account asks for it
    assert json.loads(request.body)["usage"] == {"include": True}
    assert journal_records(boxed_env)[-1]["usage"] == {"input": 8, "output": 3, "cost_micro_usd": 42}
    page, table = tmp_path / "d.html", tmp_path / "d.csv"
    assert run(capsys, ["dashboard", "--html", str(page), "--csv", str(table)])[0] == 0
    box = re.search(r"<h2>Spend reported by the provider</h2>(.*?)</div>", page.read_text(encoding="utf-8"), re.S)
    assert box and "$0.000042" in box.group(1)
    assert [row["cost_micro_usd"] for row in csv_of(table)[1]] == ["", "42"]  # the send has none, the answer has


def test_ask_exit_2_for_a_model_name_that_is_not_one(capsys, monkeypatch, openai_api, boxed_env):
    code, out, err = run(capsys, ["ask", "--provider", "openai", "--model", "gpt 4", "-"], stdin=TEXT, monkeypatch=monkeypatch)
    assert code == 2 and out == "" and "bad model name" in err
    assert openai_api.requests == [] and journal_records(boxed_env) == []


# ---- policy check --category ----


def policy_check(capsys, monkeypatch, *extra, stdin="Q3 plan", recipient="openai:personal-private:US"):
    argv = ["policy", "check", *extra, "--recipient", recipient, "-"]
    return run(capsys, argv, stdin=stdin, monkeypatch=monkeypatch)


def test_policy_check_adds_the_named_categories_to_the_detected_ones(tmp_path, capsys, monkeypatch):
    (tmp_path / "boxed.toml").write_text('[boxed]\n[boxed.policy]\nprofile = "approved-only"\n')
    monkeypatch.chdir(tmp_path)
    code, out, _ = policy_check(capsys, monkeypatch)
    assert code == 0 and "categories: none found" in out  # the text alone raises nothing
    code, out, _ = policy_check(capsys, monkeypatch, "--category", "finance")
    assert code == 4 and "verdict: deny" in out and "categories: finance" in out
    assert "reason: finance for personal-private: denied" in out
    code, out, _ = policy_check(capsys, monkeypatch, "--category", "hr", stdin="mail ivan@acme.com")
    assert code == 4 and "categories: hr, personal" in out  # what the detectors found stays


def test_policy_check_category_can_be_repeated_and_raises_the_level(tmp_path, capsys, monkeypatch):
    (tmp_path / "boxed.toml").write_text('[boxed]\n[boxed.policy]\nprofile = "no-confidential"\n')
    monkeypatch.chdir(tmp_path)
    code, out, _ = policy_check(capsys, monkeypatch, "--category", "strategy", "--category", "finance")
    assert code == 0 and "categories: finance, strategy" in out
    assert "verdict: masked (level 3 or higher)" in out


def test_policy_check_finds_finance_in_an_amount_without_being_told(tmp_path, capsys, monkeypatch):
    (tmp_path / "boxed.toml").write_text('[boxed]\n[boxed.policy]\nprofile = "approved-only"\n')
    monkeypatch.chdir(tmp_path)
    code, out, _ = policy_check(capsys, monkeypatch, stdin="Total due: $1,200.50")
    assert code == 4 and "categories: finance" in out and "verdict: deny" in out
    code, out, _ = policy_check(capsys, monkeypatch, stdin="Total due: soon")
    assert code == 0 and "categories: none found" in out  # an amount is what raised it; the category can also be named


def test_policy_check_refuses_a_category_a_detector_raises(capsys, monkeypatch):
    with pytest.raises(SystemExit) as stop:
        policy_check(capsys, monkeypatch, "--category", "personal")
    assert stop.value.code == 2 and "argument --category: not one of finance, strategy, hr, health" in capsys.readouterr().err


# ---- key set, remove and status ----

SLOT = ("boxed.si", "api-key:openai")


class Terminal(io.StringIO):
    """A stdin that is a person at a keyboard."""

    def isatty(self):
        return True


class BrokenKeyring(KeyringBackend):
    """A keychain that refuses to store and, like some real backends, quotes the password in its error."""

    priority = 1

    def get_password(self, service, username):
        return None

    def set_password(self, service, username, password):
        raise RuntimeError(f"cannot store {password}")

    def delete_password(self, service, username):
        raise RuntimeError("cannot delete")


def key(capsys, monkeypatch, action, provider="openai", stdin=None):
    return run(capsys, ["key", action, provider], stdin=stdin, monkeypatch=monkeypatch)


def test_key_set_reads_the_key_from_stdin_and_never_prints_it(capsys, monkeypatch, memory_keyring):
    code, out, err = key(capsys, monkeypatch, "set", stdin=f"  {KEY}\n")
    assert code == 0 and memory_keyring.store == {SLOT: KEY}  # padding is dropped
    assert "openai" in out and KEY not in out + err


def test_key_set_asks_with_a_hidden_prompt_on_a_terminal(capsys, monkeypatch, memory_keyring):
    monkeypatch.setattr("sys.stdin", Terminal("never read\n"))
    asked = []

    def hidden(prompt="Password: ", stream=None):
        asked.append(prompt)
        return KEY

    monkeypatch.setattr("getpass.getpass", hidden)
    code, out, err = run(capsys, ["key", "set", "openai"])
    assert code == 0 and memory_keyring.store == {SLOT: KEY}
    assert len(asked) == 1 and "openai" in asked[0] and KEY not in asked[0]
    assert KEY not in out + err


@pytest.mark.parametrize("given", ["", "\n", "sk bad\n", "sk-ключ\n", "k" * 5000 + "\n"], ids=["eof", "blank", "space", "non-ascii", "long"])
def test_key_set_refuses_what_could_not_be_sent_as_a_key(capsys, monkeypatch, memory_keyring, given):
    code, out, err = key(capsys, monkeypatch, "set", stdin=given)
    assert code == 2 and out == "" and memory_keyring.store == {}
    assert "printable ASCII without spaces" in err
    if given.strip():
        assert given.strip() not in err  # a refused key is not quoted


def test_a_keychain_that_refuses_gives_a_fixed_error_without_the_key(capsys, monkeypatch):
    keyring.set_keyring(BrokenKeyring())  # the autouse fixture puts the memory one back afterwards
    code, out, err = key(capsys, monkeypatch, "set", stdin="sk-secret-value\n")
    assert code == 2 and out == ""
    assert "openai: cannot store the key in the keychain" in err and "sk-secret-value" not in err


def test_key_status_names_the_place_and_nothing_else(capsys, monkeypatch, memory_keyring):
    assert key(capsys, monkeypatch, "status") == (0, "not set\n", "")
    monkeypatch.setenv("OPENAI_API_KEY", KEY)
    assert key(capsys, monkeypatch, "status") == (0, "set (environment)\n", "")
    memory_keyring.set_password(*SLOT, "sk-from-keychain")
    assert key(capsys, monkeypatch, "status") == (0, "set (keychain)\n", "")  # the one ask would use
    assert key(capsys, monkeypatch, "status", provider="anthropic") == (0, "not set\n", "")


def test_key_remove_deletes_the_keychain_entry_and_says_what_it_cannot_touch(capsys, monkeypatch, memory_keyring):
    memory_keyring.set_password(*SLOT, "sk-from-keychain")
    monkeypatch.setenv("OPENAI_API_KEY", KEY)
    code, out, err = key(capsys, monkeypatch, "remove")
    assert code == 0 and memory_keyring.store == {}
    assert "OPENAI_API_KEY" in out + err and KEY not in out + err  # the variable is the person's: named, never read out
    assert key(capsys, monkeypatch, "status")[1] == "set (environment)\n"


def test_key_remove_with_nothing_to_remove_is_not_an_error(capsys, monkeypatch, memory_keyring):
    code, out, err = key(capsys, monkeypatch, "remove")
    assert code == 0 and "no key" in out + err and "OPENAI_API_KEY" not in out + err


def test_key_refuses_a_provider_it_does_not_know(capsys, monkeypatch, memory_keyring):
    with pytest.raises(SystemExit) as stop:
        key(capsys, monkeypatch, "set", provider="nope", stdin=KEY)
    err = capsys.readouterr().err
    assert stop.value.code == 2 and "argument provider: not one of openai, anthropic" in err and "nope" not in err
    assert memory_keyring.store == {}


def test_key_set_does_not_quote_a_byte_that_is_not_text(capsys, monkeypatch, memory_keyring):
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(b"sk-abc\xff\xfe\n"), encoding="utf-8"))
    code, out, err = run(capsys, ["key", "set", "openai"])
    assert code == 2 and out == "" and memory_keyring.store == {}
    assert "0xff" not in err and "codec" not in err and "sk-abc" not in err


# ---- check list, set, remove and reset ----

NOTE = "Training off does not mean nothing is stored: providers still keep chats for a while."


@pytest.fixture
def now(monkeypatch):
    """boxed.cli sees 2026-10-21 12:00:05 UTC, whatever the clock says."""

    class Fixed(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 10, 21, 12, 0, 5, tzinfo=UTC)

    monkeypatch.setattr("boxed.cli.datetime", Fixed)


def check(capsys, *argv):
    return run(capsys, ["check", *argv])


def check_set(capsys, provider="chatgpt", account="me@acme.com", training="off", memory="on"):
    return check(capsys, "set", "--provider", provider, "--account", account, "--training", training, "--memory", memory)


def keep(home, provider, account, training, memory, checked_at):
    home.mkdir(parents=True, exist_ok=True)
    save_check(home, Check(provider, account, training, memory, "asked", checked_at))


def test_check_set_then_list(capsys, now, boxed_env):
    code, out, err = check_set(capsys)
    assert code == 0 and "chatgpt" in out and "me@acme.com" in out and err == ""
    [saved] = load_checks(boxed_env)
    assert (saved.provider, saved.account, saved.training, saved.memory) == ("chatgpt", "me@acme.com", "off", "on")
    assert (saved.source, saved.checked_at) == ("asked", "2026-10-21")  # the day comes from the clock, not from the caller
    assert mode_is(boxed_env / "checks.json", 0o600)
    code, out, err = check(capsys, "list")
    assert code == 0 and err == ""
    assert "chatgpt  me@acme.com  training off  memory on  checked 2026-10-21 (asked)  recipient personal-private" in out
    assert "due" not in out and NOTE in out


def test_check_set_replaces_the_same_account_and_keeps_the_others(capsys, now, boxed_env):
    check_set(capsys, training="on")
    check_set(capsys, provider="claude", account="work", training="off", memory="off")
    check_set(capsys, training="off")
    saved = [(c.provider, c.account, c.training) for c in load_checks(boxed_env)]
    assert saved == [("claude", "work", "off"), ("chatgpt", "me@acme.com", "off")]


def test_check_list_exits_5_when_a_check_is_due(capsys, now, boxed_env):
    keep(boxed_env, "chatgpt", "me@acme.com", "off", "off", "2026-10-21")
    keep(boxed_env, "claude", "work", "off", "off", "2026-09-20")  # 31 days ago
    code, out, _ = check(capsys, "list")
    assert code == 5
    lines = out.splitlines()
    assert "due" not in lines[0] and lines[1].endswith("due")
    assert "https://claude.ai/settings/data-privacy-controls" in lines[2]  # where to look it up again


def test_a_check_30_days_old_is_not_due_and_an_unknown_one_always_is(capsys, now, boxed_env):
    keep(boxed_env, "chatgpt", "me@acme.com", "off", "off", "2026-09-21")  # 30 days ago
    assert check(capsys, "list")[0] == 0
    keep(boxed_env, "gemini", "me", "unknown", "off", "2026-10-21")
    code, out, _ = check(capsys, "list")
    assert code == 5
    assert "gemini  me  training unknown  memory off  checked 2026-10-21 (asked)  recipient personal-training  due" in out


def test_only_training_off_reads_as_a_private_account(capsys, now, boxed_env):
    keep(boxed_env, "chatgpt", "a", "on", "off", "2026-10-21")
    keep(boxed_env, "claude", "b", "unknown", "off", "2026-10-21")
    keep(boxed_env, "gemini", "c", "off", "off", "2026-10-21")
    _, out, _ = check(capsys, "list")
    kinds = {line.split("  ")[1]: line.split("  recipient ")[1].split()[0] for line in out.splitlines() if "  recipient " in line}
    assert kinds == {"a": "personal-training", "b": "personal-training", "c": "personal-private"}


def test_check_list_with_nothing_recorded(capsys, now):
    code, out, err = check(capsys, "list")
    assert code == 0 and "no checks recorded yet" in out and err == ""


def test_check_set_refuses_an_account_that_is_not_a_short_name(capsys, now, boxed_env):
    for bad in ("my account", "", "a" * 65, ".x", "x/y", "ivan petrov@acme.com"):
        code, out, err = check_set(capsys, account=bad)
        assert code == 2 and out == "" and "--account" in err
    assert not (boxed_env / "checks.json").exists()


@pytest.mark.parametrize("flag, value", [("--training", "maybe"), ("--memory", "yes"), ("--provider", "bing")])
def test_check_set_refuses_a_value_that_is_not_allowed(capsys, now, flag, value):
    argv = {"--provider": "chatgpt", "--account": "me", "--training": "off", "--memory": "off", flag: value}
    with pytest.raises(SystemExit) as stop:
        check(capsys, "set", *(item for pair in argv.items() for item in pair))
    err = capsys.readouterr().err
    assert stop.value.code == 2 and f"argument {flag}: not one of " in err and f" {value}" not in err.splitlines()[-1]


def test_check_remove_deletes_one_check(capsys, now, boxed_env):
    keep(boxed_env, "chatgpt", "me@acme.com", "off", "off", "2026-10-21")
    keep(boxed_env, "claude", "work", "off", "off", "2026-10-21")
    code, out, _ = check(capsys, "remove", "--provider", "chatgpt", "--account", "me@acme.com")
    assert code == 0 and "removed" in out
    assert [(c.provider, c.account) for c in load_checks(boxed_env)] == [("claude", "work")]
    assert mode_is(boxed_env / "checks.json", 0o600)
    code, _, _ = check(capsys, "remove", "--provider", "claude", "--account", "work")
    assert code == 0 and load_checks(boxed_env) == [] and check(capsys, "list")[0] == 0  # an empty file is still a good file


def test_check_remove_of_a_check_that_is_not_there_changes_nothing(capsys, now, boxed_env):
    keep(boxed_env, "chatgpt", "me@acme.com", "off", "off", "2026-10-21")
    before = (boxed_env / "checks.json").read_bytes()
    code, out, err = check(capsys, "remove", "--provider", "claude", "--account", "work")
    assert code == 1 and out == "" and "no check for claude work" in err
    assert (boxed_env / "checks.json").read_bytes() == before
    assert check(capsys, "remove", "--provider", "chatgpt", "--account", "me")[0] == 1  # the account must match exactly


def damage(home, content=b"{not json"):
    home.mkdir(parents=True, exist_ok=True)
    path = home / "checks.json"
    path.write_bytes(content)
    path.chmod(0o600)
    return path


def test_a_damaged_file_is_an_error_and_never_reads_as_training_off(capsys, now, boxed_env):
    path = damage(boxed_env, b'{"version": 1, "checks": [{"provider": "chatgpt", "account": "me", "training": "off"}]}')
    code, out, err = check(capsys, "list")
    assert code == 2 and out == ""  # nothing is listed: no line can look like "training off"
    assert "training checks need to be confirmed again" in err  # unsigned: written before files were signed, or by hand
    assert "boxed check reset" in err and "personal-training" in err
    before = path.read_bytes()
    assert check_set(capsys)[0] == 2 and path.read_bytes() == before
    assert check(capsys, "remove", "--provider", "chatgpt", "--account", "me")[0] == 2 and path.read_bytes() == before


def test_a_garbage_file_reads_as_damaged(capsys, now, boxed_env):
    damage(boxed_env, b"\x00garbage")
    code, out, err = check(capsys, "list")
    assert code == 2 and out == "" and "checks.json is damaged" in err and "boxed check reset" in err


def test_check_reset_moves_a_damaged_file_aside_and_keeps_it(capsys, now, boxed_env):
    path = damage(boxed_env, b"\x00garbage")
    code, out, err = check(capsys, "reset")
    aside = boxed_env / "checks.json.damaged-20261021T120005Z"
    assert code == 0 and err == "" and aside.name in out
    assert not path.exists() and aside.read_bytes() == b"\x00garbage"  # moved, not deleted
    assert check(capsys, "list")[0] == 0
    assert check_set(capsys)[0] == 0 and [c.provider for c in load_checks(boxed_env)] == ["chatgpt"]


def test_check_reset_moves_aside_whatever_stands_in_the_place_of_the_file(capsys, now, boxed_env):
    boxed_env.mkdir(parents=True, exist_ok=True)
    (boxed_env / "checks.json").mkdir()
    assert check(capsys, "reset")[0] == 0
    assert (boxed_env / "checks.json.damaged-20261021T120005Z").is_dir() and not (boxed_env / "checks.json").exists()


def test_check_reset_does_not_overwrite_an_earlier_file_moved_aside(capsys, now, boxed_env):
    boxed_env.mkdir(parents=True, exist_ok=True)
    earlier = boxed_env / "checks.json.damaged-20261021T120005Z"
    earlier.write_bytes(b"the first one")
    path = damage(boxed_env, b"the second one")
    code, _, err = check(capsys, "reset")
    assert code == 2 and "exists" in err
    assert earlier.read_bytes() == b"the first one" and path.read_bytes() == b"the second one"


def test_check_reset_leaves_a_good_file_alone(capsys, now, boxed_env):
    keep(boxed_env, "chatgpt", "me@acme.com", "off", "off", "2026-10-21")
    before = (boxed_env / "checks.json").read_bytes()
    code, out, err = check(capsys, "reset")
    assert code == 2 and out == "" and "nothing to reset" in err
    assert (boxed_env / "checks.json").read_bytes() == before and not list(boxed_env.glob("checks.json.damaged-*"))


def test_check_reset_without_a_file_says_so(capsys, now, boxed_env):
    code, out, _ = check(capsys, "reset")
    assert code == 0 and "nothing to reset" in out


# ---- dashboard: html, csv, periods ----

SECRET = "AKIAIOSFODNN7EXAMPLE"


def section(page, name):
    found = re.search(rf"<section id={name}>(.*?)</section>", page, re.S)
    assert found, f"the page has no section {name}"
    return " ".join(re.sub(r"<[^>]*>", " ", found.group(1)).split())


def see(home, text, site="chatgpt", coverage="checked"):
    """One send the browser observed, as the host records it."""
    home.mkdir(parents=True, exist_ok=True)
    observe(text if coverage == "checked" else "", site, coverage, observed_journal(home, default_keystore()), None)


def csv_of(path):
    table = list(csv.reader(io.StringIO(path.read_bytes().decode("utf-8-sig"), newline="")))
    return table[0], [dict(zip(table[0], row, strict=True)) for row in table[1:]]


@pytest.fixture
def journal_clock(monkeypatch):
    """clock(day) sets the day the journals stamp on the next records (October 2026, noon UTC)."""
    moment = [datetime(2026, 10, 21, 12, tzinfo=UTC)]

    class Fixed(datetime):
        @classmethod
        def now(cls, tz=None):
            return moment[0]

    monkeypatch.setattr("boxed.journal.datetime", Fixed)

    def set_day(day):
        moment[0] = datetime(2026, 10, day, 12, tzinfo=UTC)

    return set_day


def test_dashboard_html_carries_every_section(tmp_path, capsys, monkeypatch, now, boxed_env):
    (tmp_path / "boxed.toml").write_text('[boxed]\n[boxed.policy]\nprofile = "no-confidential"\n')
    monkeypatch.chdir(tmp_path)
    run(capsys, ["mask", "--scope", "d1", "-"], stdin="mail ivan@acme.com", monkeypatch=monkeypatch)
    see(boxed_env, f"key {SECRET} and mail ivan@acme.com")
    keep(boxed_env, "claude", "work", "off", "off", "2026-08-01")
    out_html = tmp_path / "reports" / "dash.html"
    code, out, _ = run(capsys, ["dashboard", "--html", str(out_html)])
    assert code == 0 and str(out_html) in out
    page = out_html.read_text(encoding="utf-8")
    assert "Chain OK" in page and "Observation chain OK" in page
    assert "Journal" in section(page, "journal") and "prepared" in section(page, "journal") and "EMAIL:1" in section(page, "journal")
    observed = section(page, "observed")
    assert "Sends 1" in observed and "Sends with findings 1" in observed and "SECRET 1" in observed and "EMAIL 1" in observed
    assert "Revoke and replace" in observed and "SECRET" in observed
    checks = section(page, "checks")
    assert "claude work off off asked 2026-08-01" in checks and "due" in checks and "https://claude.ai/settings/data-privacy-controls" in checks
    policy = section(page, "policy")
    assert "finance masked:3 masked:3 masked:3 masked:3 allow" in policy  # the matrix of the project's profile: finance from level 3 on
    assert SECRET not in page and "ivan@acme.com" not in page and "d1" not in page


def test_dashboard_without_any_observation_says_it_is_no_proof(tmp_path, capsys, now, boxed_env):
    out_html = tmp_path / "dash.html"
    code, _, _ = run(capsys, ["dashboard", "--html", str(out_html)])
    page = out_html.read_text(encoding="utf-8")
    assert code == 0 and "No sends were observed in this period. This is not proof that nothing was sent" in section(page, "observed")
    assert "No training checks recorded yet" in section(page, "checks")
    assert not (boxed_env / "observed.jsonl").exists()  # looking does not create the log


def test_dashboard_says_when_the_observation_log_is_damaged_or_broken(tmp_path, capsys, now, boxed_env):
    see(boxed_env, "mail ivan@acme.com")
    with (boxed_env / "observed.jsonl").open("a") as f:
        f.write('{"seq": 2, "torn\n')
    out_html = tmp_path / "dash.html"
    run(capsys, ["dashboard", "--html", str(out_html)])
    observed = section(out_html.read_text(encoding="utf-8"), "observed")
    assert "Observation chain BROKEN" in observed and "1 damaged line skipped" in observed and "Sends 1" in observed


def test_dashboard_says_when_the_checks_cannot_be_read(tmp_path, capsys, now, boxed_env):
    damage(boxed_env)
    out_html = tmp_path / "dash.html"
    code, _, _ = run(capsys, ["dashboard", "--html", str(out_html)])
    checks = section(out_html.read_text(encoding="utf-8"), "checks")
    assert code == 0 and "could not be read" in checks and "No training checks recorded yet" not in checks


def test_dashboard_csv_is_excel_ready_and_has_no_chain_fields(tmp_path, capsys, monkeypatch, boxed_env):
    run(capsys, ["mask", "--scope", "d1", "-"], stdin="mail ivan@acme.com", monkeypatch=monkeypatch)
    out_csv = tmp_path / "sub" / "journal.csv"
    code, out, _ = run(capsys, ["dashboard", "--csv", str(out_csv)])
    raw = out_csv.read_bytes()
    assert code == 0 and str(out_csv) in out
    assert raw.startswith(b"\xef\xbb\xbf")  # the BOM: Excel reads the file as UTF-8
    assert raw.count(b"\r\n") == 2 and b"\r\r" not in raw and b"\n" not in raw.replace(b"\r\n", b"")  # a header, a record, CRLF once
    header, [record] = csv_of(out_csv)
    assert header[:3] == ["seq", "ts", "channel"] and not {"prev_hash", "hash", "sig"} & set(header)
    assert (record["channel"], record["status"], record["markers_by_kind"], record["scope"]) == ("manual", "prepared", "EMAIL:1", "d1")
    assert "ivan@acme.com" not in raw.decode("utf-8")


def test_dashboard_says_on_stderr_when_it_skipped_damaged_journal_lines(tmp_path, capsys, monkeypatch, boxed_env):
    run(capsys, ["mask", "--scope", "d1", "-"], stdin="mail ivan@acme.com", monkeypatch=monkeypatch)
    code, _, err = run(capsys, ["dashboard", "--csv", str(tmp_path / "a.csv")])
    assert code == 0 and "damaged" not in err  # nothing to say about a whole journal
    with (boxed_env / "journal.jsonl").open("a") as f:
        f.write('{"seq": 2, "torn\n')
    for flag, name in (("--csv", "b.csv"), ("--html", "b.html")):  # a csv has no place to say it, so stderr does
        code, _, err = run(capsys, ["dashboard", flag, str(tmp_path / name)])
        assert code == 0 and "1 damaged line skipped" in err and "boxed journal verify" in err
    assert len(csv_of(tmp_path / "b.csv")[1]) == 1  # the whole record is in, the torn line is not


def test_dashboard_writes_html_and_csv_as_utf_8_bytes_whatever_the_locale(tmp_path, capsys, monkeypatch, boxed_env):
    """Bytes, not text in the locale's encoding: the page is UTF-8, the csv is UTF-8 with a byte order mark, and its rows end in
    CRLF once (a text file on Windows would turn the line feed of a CRLF into a second CR)."""
    boxed_env.mkdir(parents=True, exist_ok=True)
    journal = Journal(boxed_env / "journal.jsonl", default_keystore())
    journal.append(
        JournalEntry("api", "Яндекс", "personal-private", 2, {"EMAIL": 1}, "sent", "ab" * 32, "full", "s", {"boxed": "0.1.0"}, model="модель")
    )
    monkeypatch.setattr("locale.getpreferredencoding", lambda *args: "ascii")
    monkeypatch.setattr("locale.getencoding", lambda: "ascii")
    code, _, _ = run(capsys, ["dashboard", "--html", str(tmp_path / "d.html"), "--csv", str(tmp_path / "d.csv")])
    assert code == 0
    page, table = (tmp_path / "d.html").read_bytes(), (tmp_path / "d.csv").read_bytes()
    assert "Яндекс".encode() in page and "модель".encode() in page and not page.startswith(b"\xef\xbb\xbf")
    assert table.startswith(b"\xef\xbb\xbfseq,ts,") and "Яндекс".encode() in table
    assert table.count(b"\r\n") == 2 and b"\r\r" not in table and table.endswith(b"\r\n")  # the header and the one record
    assert csv_of(tmp_path / "d.csv")[1][0]["provider"] == "Яндекс"


def test_dashboard_periods_end_today(tmp_path, capsys, now, journal_clock, boxed_env):
    boxed_env.mkdir(parents=True, exist_ok=True)
    journal = Journal(boxed_env / "journal.jsonl", default_keystore())
    for day in (14, 15, 20, 21):  # today is the 21st
        journal_clock(day)
        journal.append(JournalEntry("manual", "unknown", "unknown", 2, {}, "prepared", "ab" * 32, "full", f"day-{day}", {}))
    days = {}
    for period in ("day", "week", "month"):
        out_csv = tmp_path / f"{period}.csv"
        assert run(capsys, ["dashboard", "--period", period, "--csv", str(out_csv)])[0] == 0
        days[period] = [r["scope"] for r in csv_of(out_csv)[1]]
    assert days == {"day": ["day-21"], "week": ["day-15", "day-20", "day-21"], "month": ["day-14", "day-15", "day-20", "day-21"]}
    page = tmp_path / "week.html"
    run(capsys, ["dashboard", "--period", "week", "--html", str(page)])
    assert "Period: 2026-10-15 to 2026-10-21." in page.read_text(encoding="utf-8").replace("\n", " ")


def test_dashboard_since_and_until_pick_the_days(tmp_path, capsys, journal_clock, boxed_env):
    boxed_env.mkdir(parents=True, exist_ok=True)
    journal = Journal(boxed_env / "journal.jsonl", default_keystore())
    for day in (14, 15, 20, 21):
        journal_clock(day)
        journal.append(JournalEntry("manual", "unknown", "unknown", 2, {}, "prepared", "ab" * 32, "full", f"day-{day}", {}))
    out_csv = tmp_path / "p.csv"
    assert run(capsys, ["dashboard", "--since", "2026-10-15", "--until", "2026-10-20", "--csv", str(out_csv)])[0] == 0
    assert [r["scope"] for r in csv_of(out_csv)[1]] == ["day-15", "day-20"]


def test_dashboard_needs_an_output_and_one_way_to_name_the_period(tmp_path, capsys, now, boxed_env):
    code, out, err = run(capsys, ["dashboard"])
    assert code == 2 and out == "" and "--html" in err and "--csv" in err
    code, out, err = run(capsys, ["dashboard", "--period", "week", "--since", "2026-10-01", "--csv", str(tmp_path / "x.csv")])
    assert code == 2 and "--period" in err and not (tmp_path / "x.csv").exists()
    with pytest.raises(SystemExit):
        run(capsys, ["dashboard", "--period", "year", "--csv", str(tmp_path / "x.csv")])


# ---- dashboard: what it may write over ----


@pytest.fixture
def data(tmp_path, capsys, monkeypatch, boxed_env):
    """A boxed home with a journal, a vault, and the files a report must never replace; their bytes before any report."""
    run(capsys, ["mask", "--scope", "d1", "-"], stdin="mail ivan@acme.com", monkeypatch=monkeypatch)
    check_set(capsys)
    see(boxed_env, "mail ivan@acme.com")
    names = ["journal.jsonl", "vault.db", "checks.json", "observed.jsonl", "insecure-keys/device-signing-key.key"]
    return {name: (boxed_env / name).read_bytes() for name in names}


@pytest.mark.parametrize("flag", ["--csv", "--html"])
def test_dashboard_never_writes_over_what_boxed_keeps_in_its_home(tmp_path, capsys, boxed_env, data, flag):
    for name in data:
        code, out, err = run(capsys, ["dashboard", flag, str(boxed_env / name)])
        assert code == 2 and out == "" and "boxed home" in err, name
    for how in ("reports/../journal.jsonl", "other/journal.csv", "journal.html", "."):  # a path that goes round, a folder, a new name
        code, _, err = run(capsys, ["dashboard", flag, str(boxed_env / how)])
        assert code == 2 and "boxed home" in err or "plain file" in err, how
    assert {name: (boxed_env / name).read_bytes() for name in data} == data  # not one byte of them changed
    assert not (boxed_env / "other").exists() and not (boxed_env / "journal.html").exists()


def test_dashboard_never_writes_through_a_link_to_what_boxed_keeps(tmp_path, capsys, boxed_env, data):
    (tmp_path / "friendly.csv").symlink_to(boxed_env / "journal.jsonl")
    (boxed_env / "reports").symlink_to(boxed_env)  # reports/ that leads back into the home is not the reports folder
    for target in (tmp_path / "friendly.csv", boxed_env / "reports" / "vault.db"):
        code, _, err = run(capsys, ["dashboard", "--csv", str(target)])
        assert code == 2 and "boxed home" in err, target
    assert {name: (boxed_env / name).read_bytes() for name in data} == data
    assert (tmp_path / "friendly.csv").is_symlink()


def test_dashboard_may_write_under_reports_in_the_home_where_the_docs_put_them(capsys, boxed_env, data):
    for flag, name in (("--html", "journal.html"), ("--csv", "journal.csv")):
        code, _, _ = run(capsys, ["dashboard", flag, str(boxed_env / "reports" / name)])
        assert code == 0 and (boxed_env / "reports" / name).stat().st_size > 0
    assert {name: (boxed_env / name).read_bytes() for name in data} == data


def test_dashboard_refuses_one_file_for_the_page_and_the_csv(tmp_path, capsys, data):
    (tmp_path / "sub").mkdir()
    for csv_name in ("x.out", "./x.out", "sub/../x.out", str(tmp_path / "x.out")):
        code, out, err = run(capsys, ["dashboard", "--html", str(tmp_path / "x.out"), "--csv", str(tmp_path / csv_name)])
        assert code == 2 and out == "" and "same file" in err, csv_name
    (tmp_path / "alias.out").symlink_to(tmp_path / "x.out")
    code, _, err = run(capsys, ["dashboard", "--html", str(tmp_path / "alias.out"), "--csv", str(tmp_path / "x.out")])
    assert code == 2 and "same file" in err
    assert not (tmp_path / "x.out").exists()  # nothing was written


def test_dashboard_checks_both_outputs_before_it_writes_one(tmp_path, capsys, boxed_env, data):
    code, _, err = run(capsys, ["dashboard", "--html", str(tmp_path / "ok.html"), "--csv", str(boxed_env / "journal.jsonl")])
    assert code == 2 and not (tmp_path / "ok.html").exists()


@pytest.mark.parametrize(("flag", "name"), [("--html", "notes.txt"), ("--csv", "notes.txt"), ("--html", "empty"), ("--csv", "empty")])
def test_dashboard_does_not_replace_a_file_that_is_not_a_boxed_report(tmp_path, capsys, data, flag, name):
    precious = tmp_path / name
    precious.write_bytes(b"" if name == "empty" else b"my notes, not a report\n")
    before = precious.read_bytes()
    code, out, err = run(capsys, ["dashboard", flag, str(precious)])
    assert code == 2 and out == "" and "the output file exists and boxed did not write it" in err and name not in err
    assert precious.read_bytes() == before


def test_dashboard_does_not_write_into_a_folder_or_a_pipe(tmp_path, capsys, data):
    (tmp_path / "folder").mkdir()
    code, _, err = run(capsys, ["dashboard", "--csv", str(tmp_path / "folder")])
    assert code == 2 and "plain file" in err
    if not hasattr(os, "mkfifo"):  # Windows has no pipe in the file system
        return
    pipe = tmp_path / "pipe.csv"
    os.mkfifo(pipe)
    reader = os.open(pipe, os.O_RDONLY | os.O_NONBLOCK)  # with a reader there, a write would not block: the test can fail instead of hanging
    try:
        code, _, err = run(capsys, ["dashboard", "--csv", str(pipe)])
        assert code == 2 and "plain file" in err
        assert os.read(reader, 100) == b""  # nothing went into it
    finally:
        os.close(reader)


@pytest.mark.parametrize("flag", ["--html", "--csv"])
def test_dashboard_replaces_a_report_of_its_own(tmp_path, capsys, monkeypatch, data, flag):
    target = tmp_path / "report.out"
    assert run(capsys, ["dashboard", flag, str(target)])[0] == 0
    first = target.read_bytes()
    run(capsys, ["mask", "--scope", "d2", "-"], stdin="mail anna@acme.com", monkeypatch=monkeypatch)
    assert run(capsys, ["dashboard", flag, str(target)])[0] == 0
    assert target.read_bytes() != first  # one more record


def test_dashboard_replaces_a_csv_of_an_earlier_boxed_with_other_columns(tmp_path, capsys, data):
    old = tmp_path / "old.csv"
    old.write_bytes(b"\xef\xbb\xbfseq,ts,channel,provider,model,tokens_in,whatever\r\n1,2026-10-01,manual,unknown,,,x\r\n")
    assert run(capsys, ["dashboard", "--csv", str(old)])[0] == 0
    assert csv_of(old)[1][0]["channel"] == "manual"


def test_dashboard_writes_through_a_part_file_and_replaces_the_old_one_whole(tmp_path, capsys, monkeypatch, data):
    """A hard link keeps the old report's bytes: the old file was replaced, not written into."""
    target, alias = tmp_path / "report.html", tmp_path / "old-report.html"
    assert run(capsys, ["dashboard", "--html", str(target)])[0] == 0
    os.link(target, alias)
    run(capsys, ["mask", "--scope", "d2", "-"], stdin="mail anna@acme.com", monkeypatch=monkeypatch)
    assert run(capsys, ["dashboard", "--html", str(target)])[0] == 0
    assert alias.read_bytes() != target.read_bytes() and b"boxed.si journal" in alias.read_bytes()
    assert mode_is(target, 0o600)
    assert sorted(path.name for path in tmp_path.iterdir() if path.name.startswith(".")) == []  # no part file is left


def test_dashboard_does_not_follow_a_link_planted_where_the_part_file_goes(tmp_path, capsys, boxed_env, data):
    (tmp_path / ".report.html.boxed-part").symlink_to(boxed_env / "journal.jsonl")
    assert run(capsys, ["dashboard", "--html", str(tmp_path / "report.html")])[0] == 0
    assert (boxed_env / "journal.jsonl").read_bytes() == data["journal.jsonl"]
    assert b"boxed.si journal" in (tmp_path / "report.html").read_bytes()


def test_dashboard_keeps_the_old_report_when_the_new_one_cannot_be_written(tmp_path, capsys, monkeypatch, data):
    target = tmp_path / "report.csv"
    assert run(capsys, ["dashboard", "--csv", str(target)])[0] == 0
    before = target.read_bytes()

    def disk_full(fd):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fsync", disk_full)
    code, _, _ = run(capsys, ["dashboard", "--csv", str(target)])
    assert code == 2 and target.read_bytes() == before
    assert sorted(path.name for path in tmp_path.iterdir() if path.name != "boxed-home") == ["report.csv"]  # no part file is left
