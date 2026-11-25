"""API-key channels: the HTTP layer against a local server, ask() with a fake transport, keys in the keyring."""

import functools
import hashlib
import io
import json
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.errors import NoKeyringError, PasswordDeleteError, PasswordSetError

from boxed import __version__
from boxed.channels import (
    PROVIDERS,
    Answer,
    AskResult,
    ChannelError,
    PolicyBlocked,
    api_key,
    ask,
    call,
    delete_api_key,
    key_source,
    set_api_key,
)
from boxed.channels import _opener
from boxed.config import ProjectConfig
from boxed.journal import Journal
from boxed.keys import InsecureFileKeyStore, default_keystore
from boxed.locks import file_lock
from boxed.policy import PolicyError
from boxed.vault import Vault, VaultError

KEY = "sk-test-0123456789abcdef"
PROMPT = "Write to [EMAIL_1] about the Globex contract"


@pytest.fixture(autouse=True)
def local_network_only(monkeypatch):
    """The local test servers are reached directly, whatever proxy the developer's shell sets."""
    for name in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")


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
def memory_keyring(monkeypatch):
    """No test touches the real keychain or sees the developer's real keys."""
    for provider in PROVIDERS.values():
        monkeypatch.delenv(provider.env_key, raising=False)
    previous = keyring.get_keyring()
    backend = MemoryKeyring()
    keyring.set_keyring(backend)
    yield backend
    keyring.set_keyring(previous)


def test_each_provider_is_kept_under_its_own_name():
    assert all(name == provider.name for name, provider in PROVIDERS.items())


def test_a_channel_error_is_a_user_error_whose_text_cli_prints():
    """Its words are read by tests/test_error_texts.py like those of any UserError, and they are what boxed prints."""
    from boxed import cli
    from boxed.errors import UserError

    failure = ChannelError("openai: timed out")
    assert isinstance(failure, UserError) and cli._error_text(failure) == "openai: timed out"


@pytest.fixture
def start_api():
    """Local stand-ins for a provider's API: they record what arrives and answer with what the test sets."""
    started = []

    def start(status=200, body=b"{}", headers=None, stall=None, drip=0, slow_start=0):
        api = SimpleNamespace(
            requests=[], status=status, body=body, headers=headers or {}, stall=stall, drip=drip, slow_start=slow_start, dropped=threading.Event()
        )

        class Handler(BaseHTTPRequestHandler):
            def handle_any(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                lowered = {name.lower(): value for name, value in self.headers.items()}
                api.requests.append(SimpleNamespace(method=self.command, path=self.path, headers=lowered, body=raw))
                if api.stall:
                    api.stall.wait(5)
                try:
                    for _ in range(api.slow_start):  # a status line that never ends: one byte at a time
                        self.wfile.write(b"X")
                        time.sleep(0.2)
                    self.send_response(api.status)
                    for name, value in api.headers.items():
                        self.send_header(name, value)
                    self.send_header("Content-Length", str(len(api.body) + api.drip))
                    self.end_headers()
                    self.wfile.write(api.body)
                    for _ in range(api.drip):  # promised in Content-Length, then trickled one byte at a time
                        time.sleep(0.2)
                        self.wfile.write(b" ")
                except OSError:  # the caller gave up and hung up
                    api.dropped.set()

            do_GET = do_POST = handle_any

            def log_message(self, *args):
                pass

        api.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        api.url = f"http://127.0.0.1:{api.server.server_address[1]}"
        threading.Thread(target=api.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()  # quick shutdown
        started.append(api)
        return api

    yield start
    for api in started:
        if api.stall:
            api.stall.set()
        api.server.shutdown()
        api.server.server_close()


@pytest.fixture
def api(start_api):
    return start_api()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---- call: one request shape per style ----


def test_call_responses_style(api):
    api.body = json.dumps(
        {
            "id": "resp_1",
            "object": "response",
            "status": "completed",
            "model": "gpt-5-2026-01-01",
            "output": [
                {"type": "reasoning", "id": "rs_1", "summary": []},
                {
                    "type": "message",
                    "id": "msg_1",
                    "role": "assistant",
                    "content": [
                        {"type": "output_text", "text": "Dear ", "annotations": []},
                        {"type": "summary_text", "text": "a summary"},
                        {"type": "reasoning_text", "text": "private thoughts"},
                        {"type": "output_text", "text": "[EMAIL_1]", "annotations": []},
                    ],
                },
            ],
            "usage": {"input_tokens": 11, "output_tokens": 7, "total_tokens": 18},
        }
    ).encode()
    answer = call(PROVIDERS["openai"], "gpt-5", PROMPT, KEY, base_url=api.url + "/v1")
    assert answer == Answer("Dear [EMAIL_1]", "gpt-5-2026-01-01", {"input": 11, "output": 7})
    [request] = api.requests
    assert (request.method, request.path) == ("POST", "/v1/responses")
    assert request.headers["authorization"] == f"Bearer {KEY}"
    assert request.headers["content-type"] == "application/json"
    assert "x-api-key" not in request.headers
    assert json.loads(request.body) == {"model": "gpt-5", "input": PROMPT, "store": False}  # the API would keep it 30 days


def test_call_messages_style(api):
    api.body = json.dumps(
        {
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": "claude-test-20260101",
            "content": [
                {"type": "thinking", "thinking": "hm", "signature": "s"},
                {"type": "text", "text": "Dear "},
                {"type": "tool_use", "id": "t1", "name": "x", "input": {}},
                {"type": "text", "text": "[EMAIL_1]"},
            ],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 9, "output_tokens": 4, "cache_read_input_tokens": 0},
        }
    ).encode()
    answer = call(PROVIDERS["anthropic"], "claude-test", PROMPT, KEY, base_url=api.url)
    assert answer == Answer("Dear [EMAIL_1]", "claude-test-20260101", {"input": 9, "output": 4})
    [request] = api.requests
    assert (request.method, request.path) == ("POST", "/messages")
    assert request.headers["x-api-key"] == KEY
    assert request.headers["anthropic-version"] == "2023-06-01"
    assert request.headers["content-type"] == "application/json"
    assert "authorization" not in request.headers
    body = {"model": "claude-test", "max_tokens": 4096, "messages": [{"role": "user", "content": PROMPT}]}
    assert json.loads(request.body) == body


@pytest.mark.parametrize(
    ("name", "extra"),
    [
        ("deepseek", {}),
        # OpenRouter is asked to route only to providers that keep and train on nothing, and to report what the call cost
        ("openrouter", {"provider": {"data_collection": "deny"}, "usage": {"include": True}}),
    ],
)
def test_call_chat_style(api, name, extra):
    api.body = json.dumps(
        {
            "id": "c1",
            "object": "chat.completion",
            "model": "vendor/chat-model-1",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "Dear [EMAIL_1]", "reasoning_content": "private thoughts"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
        }
    ).encode()
    answer = call(PROVIDERS[name], "vendor/chat-model", PROMPT, KEY, base_url=api.url)
    assert answer == Answer("Dear [EMAIL_1]", "vendor/chat-model-1", {"input": 5, "output": 3})
    [request] = api.requests
    assert (request.method, request.path) == ("POST", "/chat/completions")
    assert request.headers["authorization"] == f"Bearer {KEY}"
    assert "x-api-key" not in request.headers
    assert json.loads(request.body) == {"model": "vendor/chat-model", "messages": [{"role": "user", "content": PROMPT}], **extra}


def body_sent_to(api, provider, model="vendor/chat-model", **overrides):
    """The JSON body `call` posts to a local server that answers like a chat API."""
    api.body = json.dumps({"model": model, "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}).encode()
    call(replace(PROVIDERS[provider], **overrides), model, PROMPT, KEY, base_url=api.url)
    return json.loads(api.requests[-1].body)


def test_openrouter_is_asked_for_zero_retention_endpoints_only_when_the_request_says_so(api):
    assert body_sent_to(api, "openrouter")["provider"] == {"data_collection": "deny"}
    assert body_sent_to(api, "openrouter", zero_retention=True)["provider"] == {"data_collection": "deny", "zdr": True}


@pytest.mark.parametrize("name", ["openai", "anthropic", "deepseek"])
def test_zero_retention_is_an_agreement_on_the_account_not_a_field_of_other_requests(api, name):
    """Only OpenRouter takes a per-request routing rule: for the others the request is the same with or without."""
    api.body = json.dumps({"model": "m", "choices": [{"message": {"content": "ok"}}], "output": [], "content": []}).encode()
    call(PROVIDERS[name], "m", PROMPT, KEY, base_url=api.url)
    call(replace(PROVIDERS[name], zero_retention=True), "m", PROMPT, KEY, base_url=api.url)
    plain, zero = (json.loads(request.body) for request in api.requests)
    assert plain == zero and "provider" not in zero and "usage" not in zero


@pytest.mark.parametrize("name", ["openai", "anthropic", "deepseek"])
def test_only_openrouter_is_asked_for_usage_accounting(api, name):
    api.body = json.dumps({"model": "m", "choices": [{"message": {"content": "ok"}}], "output": [], "content": []}).encode()
    call(PROVIDERS[name], "m", PROMPT, KEY, base_url=api.url)
    assert "usage" not in json.loads(api.requests[0].body)


@pytest.mark.parametrize(
    ("name", "url"),
    [
        ("openai", "https://api.openai.com/v1/responses"),
        ("anthropic", "https://api.anthropic.com/v1/messages"),
        ("deepseek", "https://api.deepseek.com/chat/completions"),
        ("openrouter", "https://openrouter.ai/api/v1/chat/completions"),
    ],
)
def test_each_provider_posts_to_its_own_endpoint(monkeypatch, name, url):
    posted = []

    def refuse(self, request, data=None, timeout=None):
        posted.append((request.get_method(), request.full_url))
        raise urllib.error.URLError("no network in tests")

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", refuse)
    with pytest.raises(ChannelError):
        call(PROVIDERS[name], "m", PROMPT, KEY)
    assert posted == [("POST", url)]


def test_an_answer_without_text_is_empty_not_an_error(api):
    api.body = json.dumps(
        {"model": "gpt-5", "output": [{"type": "reasoning", "summary": []}], "usage": {"input_tokens": 3, "output_tokens": 1}}
    ).encode()
    assert call(PROVIDERS["openai"], "gpt-5", PROMPT, KEY, base_url=api.url) == Answer("", "gpt-5", {"input": 3, "output": 1})


# ---- call: what the provider reports is not trusted ----

SECRETS = f"{KEY} and {PROMPT}"
ECHO = f"Incorrect API key provided: {SECRETS}"


def unauthorized(body):
    return {"status": 401, "body": body if isinstance(body, bytes) else json.dumps(body).encode()}


@pytest.mark.parametrize(
    ("name", "body", "expected"),
    [
        ("openai", {"error": {"message": ECHO, "type": "invalid_request_error", "code": "invalid_api_key"}}, "openai: HTTP 401 (invalid_api_key)"),
        ("openai", {"error": {"message": ECHO, "code": KEY, "type": PROMPT}}, "openai: HTTP 401"),
        ("openai", {"error": ECHO}, "openai: HTTP 401"),
        ("openai", ECHO.encode(), "openai: HTTP 401"),
        ("openai", f"<html><body>{ECHO}</body></html>".encode(), "openai: HTTP 401"),
        # a word past the first 64 KiB is not read: an error body is never taken whole
        ("openai", json.dumps({"error": {"message": "x" * 100_000 + SECRETS, "code": "invalid_api_key"}}).encode(), "openai: HTTP 401"),
        ("openai", [ECHO], "openai: HTTP 401"),
        ("anthropic", {"type": "error", "error": {"type": "authentication_error", "message": ECHO}}, "anthropic: HTTP 401 (authentication_error)"),
        ("openrouter", {"error": {"code": 401, "message": ECHO, "metadata": {"raw": SECRETS}}}, "openrouter: HTTP 401"),
    ],
    ids=["known code", "echoed code and type", "error is text", "plain text", "html", "huge body", "list", "anthropic", "numeric code"],
)
def test_error_body_echoing_prompt_and_key_is_not_quoted(start_api, name, body, expected):
    api = start_api(**unauthorized(body))
    with pytest.raises(ChannelError) as caught:
        call(PROVIDERS[name], "m", PROMPT, KEY, base_url=api.url)
    assert str(caught.value) == expected
    assert caught.value.__cause__ is None and caught.value.__context__ is None  # a chained HTTPError would carry the body


@pytest.mark.parametrize(
    ("name", "body"),
    [
        ("openai", b"not json"),
        ("openai", b""),
        ("openai", b"[]"),
        ("openai", b'{"output": "text"}'),
        ("openai", b'{"output": ["text"]}'),
        ("openai", b'{"output": [{"type": "message", "content": "text"}]}'),
        ("openai", b'{"output": [{"type": "message", "content": [{"type": "output_text", "text": 5}]}]}'),
        ("openai", b'{"output": [{"type": "message", "content": [{"type": "output_text", "text": "\\ud800"}]}]}'),
        ("openai", b"[" * 100_000),
        ("anthropic", b'{"content": "text"}'),
        ("anthropic", b'{"content": [{"type": "text"}]}'),
        ("deepseek", b'{"choices": []}'),
        ("deepseek", b'{"choices": [{"message": "text"}]}'),
        ("deepseek", b'{"choices": [{"message": {"content": ["text"]}}]}'),
        ("openrouter", b'{"output": []}'),
    ],
    ids=[
        "not json",
        "empty",
        "list",
        "output is text",
        "output item is text",
        "content is text",
        "text is a number",
        "lone surrogate",
        "nested too deep",
        "anthropic content is text",
        "anthropic text missing",
        "no choices",
        "message is text",
        "content is a list",
        "wrong style",
    ],
)
def test_malformed_answer_is_a_channel_error(start_api, name, body):
    api = start_api(body=body)
    with pytest.raises(ChannelError) as caught:
        call(PROVIDERS[name], "m", PROMPT, KEY, base_url=api.url)
    assert str(caught.value) == f"{name}: malformed answer"
    assert caught.value.__cause__ is None and caught.value.__context__ is None  # a chained JSON error would quote the body


def test_missing_model_and_usage_fall_back_to_the_request_and_nothing(api):
    api.body = b'{"choices": [{"message": {"content": "hi"}}]}'
    assert call(PROVIDERS["deepseek"], "deepseek-chat", PROMPT, KEY, base_url=api.url) == Answer("hi", "deepseek-chat", {})


@pytest.mark.parametrize(
    ("usage", "expected"),
    [
        ({"prompt_tokens": -1, "completion_tokens": "7"}, {}),
        ({"prompt_tokens": True, "completion_tokens": 2.5}, {}),
        ({"prompt_tokens": 5}, {"input": 5}),
        ({"prompt_tokens": 0, "completion_tokens": 0}, {"input": 0, "output": 0}),
        ("many", {}),
        (["x"], {}),
        (None, {}),
    ],
)
def test_usage_that_is_not_a_count_is_dropped(api, usage, expected):
    api.body = json.dumps({"choices": [{"message": {"content": "hi"}}], "usage": usage}).encode()
    assert call(PROVIDERS["deepseek"], "m", PROMPT, KEY, base_url=api.url).usage == expected


def reported_by_openrouter(api, usage, name="openrouter"):
    api.body = json.dumps({"model": "vendor/m", "choices": [{"message": {"content": "hi"}}], "usage": usage}, allow_nan=True).encode()
    return call(PROVIDERS[name], "vendor/m", PROMPT, KEY, base_url=api.url).usage


@pytest.mark.parametrize(
    ("cost", "micro"),
    [
        (0.000123, 123),  # a float is read from its text, so 0.000123 is 123 and not 122.99999999999999
        (0.95, 950_000),
        (0, 0),
        (1, 1_000_000),
        (12.345678, 12_345_678),
        (1e-07, 0),
        (0.0000004, 0),
        (0.0000005, 1),  # halves go up
        (0.0000015, 2),
        (1000, 10**9),  # the most a single call is believed to cost
    ],
)
def test_openrouter_cost_is_kept_as_whole_micro_dollars(api, cost, micro):
    usage = reported_by_openrouter(api, {"prompt_tokens": 5, "completion_tokens": 3, "cost": cost})
    assert usage == {"input": 5, "output": 3, "cost_micro_usd": micro}
    assert all(type(n) is int for n in usage.values())


@pytest.mark.parametrize(
    "cost",
    [-0.01, "0.5", True, False, None, [0.5], {"credits": 1}, float("nan"), float("inf"), -float("inf"), 1000.000001, 2000, 10**400, 1e30],
    ids=["negative", "text", "true", "false", "null", "list", "object", "nan", "inf", "minus inf", "just over", "over", "huge int", "huge float"],
)
def test_a_cost_that_is_not_an_amount_is_dropped(api, cost):
    assert reported_by_openrouter(api, {"prompt_tokens": 5, "completion_tokens": 3, "cost": cost}) == {"input": 5, "output": 3}


def test_openrouter_cost_stands_without_token_counts_and_tokens_without_cost(api):
    assert reported_by_openrouter(api, {"cost": 0.01}) == {"cost_micro_usd": 10_000}
    assert reported_by_openrouter(api, {"prompt_tokens": 5}) == {"input": 5}
    assert reported_by_openrouter(api, {"total_cost": 0.01, "cost_details": {"upstream_inference_cost": 19}}) == {}  # only the field named "cost"


def test_only_openrouter_reports_a_cost(api):
    """A "cost" in another provider's usage is not a figure this code has agreed to read."""
    assert reported_by_openrouter(api, {"prompt_tokens": 5, "completion_tokens": 3, "cost": 0.5}, name="deepseek") == {"input": 5, "output": 3}


@pytest.mark.parametrize(
    ("reported", "expected"),
    [
        ("deepseek-chat-2026-01-01", "deepseek-chat-2026-01-01"),  # the requested name, extended: a dated version
        ("deepseek-chat", "deepseek-chat"),
        ("some-other-model", "deepseek-chat"),  # a model name, but not the model that was asked for
        (KEY, "deepseek-chat"),
        ("deepseek-chat" + KEY, "deepseek-chat"),  # extends the name and carries the key
        (f"<script> {PROMPT}", "deepseek-chat"),  # not even a name
        ("deepseek-chat <script>", "deepseek-chat"),  # starts right, is not a name
        (None, "deepseek-chat"),
        (5, "deepseek-chat"),
    ],
    ids=["dated version", "same", "other model", "the key", "name plus key", "not a name", "starts right", "null", "number"],
)
def test_a_reported_model_is_used_only_when_it_extends_the_requested_one(api, reported, expected):
    api.body = json.dumps({"model": reported, "choices": [{"message": {"content": "hi"}}]}).encode()
    assert call(PROVIDERS["deepseek"], "deepseek-chat", PROMPT, KEY, base_url=api.url).model == expected


# ---- call: a well-formed body is not always an answer ----

UNUSABLE = [
    ("openai", {"status": "failed", "error": {"code": "server_error", "message": SECRETS}, "output": [], "usage": None}, "the provider reported an error (server_error)"),
    ("openai", {"status": "failed", "output": []}, "the provider reported an error"),
    ("openai", {"error": {"message": SECRETS, "type": "invalid_request_error"}}, "the provider reported an error (invalid_request_error)"),
    ("openai", {"error": {"message": SECRETS, "code": KEY, "type": PROMPT}}, "the provider reported an error"),
    ("openai", {"status": "completed", "output": [{"type": "message", "content": [{"type": "refusal", "refusal": SECRETS}]}]}, "the model refused to answer"),
    ("openai", {"status": "incomplete", "incomplete_details": {"reason": "content_filter"}, "output": []}, "the answer was filtered"),
    ("anthropic", {"type": "error", "error": {"type": "overloaded_error", "message": SECRETS}}, "the provider reported an error (overloaded_error)"),
    ("anthropic", {"type": "message", "model": "m", "content": [], "stop_reason": "refusal", "usage": {"input_tokens": 9, "output_tokens": 0}}, "the model refused to answer"),
    ("deepseek", {"model": "m", "choices": [{"message": {"role": "assistant", "content": None, "refusal": SECRETS}, "finish_reason": "stop"}]}, "the model refused to answer"),
    ("deepseek", {"model": "m", "choices": [{"message": {"role": "assistant", "content": None}, "finish_reason": "content_filter"}]}, "the answer was filtered"),
    ("openrouter", {"model": "m", "choices": [{"finish_reason": "error", "error": {"code": 502, "message": SECRETS}, "message": {"role": "assistant", "content": ""}}]}, "the provider reported an error"),
    ("openrouter", {"error": {"code": 502, "message": SECRETS, "metadata": {"raw": SECRETS}}, "user_id": "u1"}, "the provider reported an error"),
]


@pytest.mark.parametrize(
    ("name", "body", "what"),
    UNUSABLE,
    ids=["failed with code", "failed", "error object", "error with unknown words", "refusal", "filtered", "anthropic error", "anthropic refusal", "chat refusal", "chat filter", "chat finish error", "chat error object"],
)
def test_a_failed_refused_or_filtered_answer_is_a_channel_error(start_api, name, body, what):
    api = start_api(body=json.dumps(body).encode())
    with pytest.raises(ChannelError) as caught:
        call(PROVIDERS[name], "m", PROMPT, KEY, base_url=api.url)
    assert str(caught.value) == f"{name}: {what}"  # fixed words: the messages in the body echo the key and the prompt
    assert caught.value.__cause__ is None and caught.value.__context__ is None


TRUNCATED = [
    ("openai", {"model": "m", "status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"}, "output": [{"type": "message", "content": [{"type": "output_text", "text": "A long answ"}]}], "usage": {"input_tokens": 5, "output_tokens": 4096}}, "A long answ"),
    ("openai", {"model": "m", "status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"}, "output": [{"type": "reasoning", "summary": []}], "usage": {"input_tokens": 5, "output_tokens": 4096}}, ""),
    ("openai", {"model": "m", "status": "cancelled", "output": [{"type": "message", "content": [{"type": "output_text", "text": "A long answ"}]}], "usage": {"input_tokens": 5, "output_tokens": 4096}}, "A long answ"),
    ("anthropic", {"type": "message", "model": "m", "content": [{"type": "text", "text": "A long answ"}], "stop_reason": "max_tokens", "usage": {"input_tokens": 5, "output_tokens": 4096}}, "A long answ"),
    ("anthropic", {"type": "message", "model": "m", "content": [{"type": "text", "text": "A long answ"}], "stop_reason": "model_context_window_exceeded", "usage": {"input_tokens": 5, "output_tokens": 4096}}, "A long answ"),
    ("deepseek", {"model": "m", "choices": [{"message": {"role": "assistant", "content": "A long answ"}, "finish_reason": "length"}], "usage": {"prompt_tokens": 5, "completion_tokens": 4096}}, "A long answ"),
    # a reason this code has never heard of is not a promise that the answer is whole
    ("deepseek", {"model": "m", "choices": [{"message": {"role": "assistant", "content": "A long answ"}, "finish_reason": "insufficient_system_resource"}], "usage": {"prompt_tokens": 5, "completion_tokens": 4096}}, "A long answ"),
]


@pytest.mark.parametrize(
    ("name", "body", "text"),
    TRUNCATED,
    ids=["responses max tokens", "responses max tokens while thinking", "responses unknown status", "anthropic max tokens", "anthropic context window", "chat length", "chat unknown reason"],
)
def test_a_truncated_answer_is_returned_and_flagged(start_api, name, body, text):
    api = start_api(body=json.dumps(body).encode())
    answer = call(PROVIDERS[name], "m", PROMPT, KEY, base_url=api.url)
    assert (answer.text, answer.model, answer.usage) == (text, "m", {"input": 5, "output": 4096})
    assert answer.complete is False


def test_a_whole_answer_and_one_that_says_nothing_about_it_are_complete(start_api):
    stated = start_api(body=json.dumps({"model": "m", "choices": [{"message": {"content": "hi"}, "finish_reason": "stop"}]}).encode())
    silent = start_api(body=json.dumps({"model": "m", "choices": [{"message": {"content": "hi"}}]}).encode())
    assert call(PROVIDERS["deepseek"], "m", PROMPT, KEY, base_url=stated.url).complete is True
    assert call(PROVIDERS["deepseek"], "m", PROMPT, KEY, base_url=silent.url).complete is True


# ---- call: it fails closed and says little ----


def test_a_redirect_is_not_followed_so_the_key_and_prompt_stay_put(start_api):
    elsewhere = start_api()
    api = start_api(status=302, headers={"Location": elsewhere.url + "/stolen"})
    with pytest.raises(ChannelError) as caught:
        call(PROVIDERS["openai"], "gpt-5", PROMPT, KEY, base_url=api.url)
    assert str(caught.value) == "openai: HTTP 302"
    assert len(api.requests) == 1 and elsewhere.requests == []


def test_the_proxy_from_the_environment_is_used(api, monkeypatch):
    monkeypatch.setenv("http_proxy", api.url)
    api.body = b'{"output": []}'
    answer = call(PROVIDERS["openai"], "gpt-5", PROMPT, KEY, base_url="http://api.example.test/v1")
    assert answer.text == ""
    [request] = api.requests
    assert request.path == "http://api.example.test/v1/responses"  # a proxy is asked for the whole URL


@pytest.fixture
def proxy_that_would_see_everything(start_api, monkeypatch):
    """http_proxy names a local server, and no_proxy says nothing: the autouse fixture's no_proxy would hide the problem."""
    proxy = start_api()
    monkeypatch.delenv("no_proxy")
    if sys.platform != "win32":  # there the two spellings are one variable, and the first call took it
        monkeypatch.delenv("NO_PROXY")
    monkeypatch.setenv("http_proxy", proxy.url)
    return proxy


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
def test_an_address_on_this_computer_is_never_handed_to_a_proxy(start_api, proxy_that_would_see_everything, host):
    """urllib would send it to http_proxy, and the key and the prompt would reach the proxy in the clear."""
    relay = start_api(body=b'{"output": []}')
    answer = call(PROVIDERS["openai"], "gpt-5", PROMPT, KEY, base_url=relay.url.replace("127.0.0.1", host) + "/v1")
    assert answer.text == ""
    assert [request.path for request in relay.requests] == ["/v1/responses"]
    assert proxy_that_would_see_everything.requests == []


def test_a_relay_from_the_environment_on_this_computer_does_not_go_through_the_proxy(
    vault, journal, start_api, proxy_that_would_see_everything, monkeypatch
):
    relay = start_api(body=json.dumps({"output": [{"type": "message", "content": [{"type": "output_text", "text": "Dear [EMAIL_1]"}]}]}).encode())
    monkeypatch.setenv("BOXED_OPENAI_BASE_URL", relay.url)
    result = run(vault, journal, call)
    assert result.text == "Dear ivan@acme.com"
    assert len(relay.requests) == 1 and relay.requests[0].headers["authorization"] == f"Bearer {KEY}"
    assert proxy_that_would_see_everything.requests == []  # neither the key nor the prompt reached it


def test_a_remote_address_keeps_the_proxies_of_the_environment_and_this_computer_has_none(monkeypatch):
    """https goes through a proxy by CONNECT, which the local stand-ins do not speak: look at the opener instead."""
    monkeypatch.delenv("no_proxy")
    if sys.platform != "win32":  # there the two spellings are one variable, and the first call took it
        monkeypatch.delenv("NO_PROXY")
    monkeypatch.setenv("https_proxy", "http://proxy.example.test:3128")

    def proxies_of(url):
        """Every proxy an opener for this address would use (an opener without a proxy handler uses none)."""
        return {name: address for h in _opener(url).handlers if isinstance(h, urllib.request.ProxyHandler) for name, address in h.proxies.items()}

    assert proxies_of("https://api.openai.com/v1/responses") == {"https": "http://proxy.example.test:3128"}
    assert proxies_of("https://relay.example.com/v1/responses") == {"https": "http://proxy.example.test:3128"}
    for url in ("http://127.0.0.1:8080/v1/responses", "https://127.0.0.1/v1/responses", "http://localhost:11434/x", "http://[::1]:9/x"):
        assert proxies_of(url) == {}


def test_a_refused_connection_is_a_channel_error_without_the_address():
    port = free_port()
    with pytest.raises(ChannelError) as caught:
        call(PROVIDERS["openai"], "gpt-5", PROMPT, KEY, base_url=f"http://127.0.0.1:{port}")
    assert str(caught.value) == "openai: network error"
    assert caught.value.__cause__ is None and caught.value.__context__ is None


def test_a_slow_server_times_out(start_api):
    api = start_api(stall=threading.Event())
    with pytest.raises(ChannelError) as caught:
        call(PROVIDERS["openai"], "gpt-5", PROMPT, KEY, base_url=api.url, timeout=0.2)
    assert str(caught.value) == "openai: timed out"


def test_one_deadline_covers_a_server_that_drips_its_answer(start_api):
    """Every byte arrives inside the per-read timeout; the call as a whole must still end when the deadline does."""
    api = start_api(body=b'{"output": []}', drip=25)  # five seconds of trickle after a body that is already whole
    started = time.monotonic()
    with pytest.raises(ChannelError) as caught:
        call(PROVIDERS["openai"], "gpt-5", PROMPT, KEY, base_url=api.url, timeout=0.5)
    assert str(caught.value) == "openai: timed out"
    assert time.monotonic() - started < 3
    assert api.dropped.wait(3)  # and the connection is closed, not read on in the background


def test_one_deadline_covers_a_server_that_drips_its_status_line(start_api):
    api = start_api(slow_start=25)  # each byte is quick, so no single read times out; the status line never completes
    started = time.monotonic()
    with pytest.raises(ChannelError) as caught:
        call(PROVIDERS["openai"], "gpt-5", PROMPT, KEY, base_url=api.url, timeout=0.5)
    assert str(caught.value) == "openai: timed out"
    assert time.monotonic() - started < 3


@pytest.mark.parametrize(("mebibytes", "refused"), [(9, False), (11, True)], ids=["under the cap", "over the cap"])
def test_an_answer_over_10_mib_is_refused(start_api, mebibytes, refused):
    text = "a" * (mebibytes * 1024 * 1024)
    api = start_api(body=json.dumps({"output": [{"type": "message", "content": [{"type": "output_text", "text": text}]}]}).encode())
    if not refused:
        assert call(PROVIDERS["openai"], "gpt-5", PROMPT, KEY, base_url=api.url).text == text
        return
    with pytest.raises(ChannelError) as caught:
        call(PROVIDERS["openai"], "gpt-5", PROMPT, KEY, base_url=api.url)
    assert str(caught.value) == "openai: answer too large"


@pytest.mark.parametrize(
    "key",
    ["sk-bad\r\nX-Evil: 1", "sk-ключ", "sk bad", " sk-padded", "", "k" * 5000],
    ids=["line break", "non-ascii", "space", "padding", "empty", "too long"],
)
def test_a_key_that_cannot_be_a_header_value_is_refused_without_quoting_it(api, key):
    with pytest.raises(ChannelError) as caught:
        call(PROVIDERS["openai"], "gpt-5", PROMPT, key, base_url=api.url)
    assert str(caught.value) == "openai: invalid API key format"
    assert api.requests == []


def test_a_prompt_with_a_lone_surrogate_is_refused_without_quoting_it(api):
    with pytest.raises(ChannelError) as caught:
        call(PROVIDERS["openai"], "gpt-5", "Ivan\ud800 Petrov", KEY, base_url=api.url)
    assert str(caught.value) == "openai: the request is not valid text"
    assert api.requests == []


# ---- ask: the order of the steps, with a fake transport ----

TEXT = "Write to ivan@acme.com about the invoice"
MASKED = "Write to [EMAIL_1] about the invoice"


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


@pytest.fixture
def vault(boxed_env):
    boxed_env.mkdir(parents=True, exist_ok=True)
    return Vault(boxed_env / "vault.db", default_keystore())


@pytest.fixture
def journal(boxed_env):
    boxed_env.mkdir(parents=True, exist_ok=True)
    return Journal(boxed_env / "journal.jsonl", default_keystore())


class Transport:
    """Stands in for the network: records what it is given and what the journal held at that moment."""

    def __init__(self, journal, answer=None, error=None):
        self.journal, self.answer, self.error = journal, answer, error
        self.calls = []

    def __call__(self, provider, model, prompt, key):
        statuses = [record["status"] for record in self.journal.entries()]
        self.calls.append(SimpleNamespace(provider=provider.name, model=model, prompt=prompt, key=key, journal=statuses))
        if self.error:
            raise self.error
        return self.answer


def run(vault, journal, transport, text=TEXT, **overrides):
    args = dict(provider="openai", model="gpt-test", key=KEY, scope="s1", vault=vault, journal=journal, config=ProjectConfig())
    return ask(text, **{**args, "transport": transport, **overrides})


def test_ask_masks_before_sending_and_restores_the_answer(vault, journal):
    transport = Transport(journal, Answer("Dear [EMAIL_1], noted.", "gpt-test-2026", {"input": 12, "output": 5}))
    result = run(vault, journal, transport)
    assert isinstance(result, AskResult)
    assert result.text == "Dear ivan@acme.com, noted."
    assert (result.level, result.verdict) == (2, "masked")
    assert (result.unknown, result.suspicious) == ([], [])
    assert (result.model, result.usage) == ("gpt-test-2026", {"input": 12, "output": 5})
    assert len(result.warnings) == 1 and "EEA" in result.warnings[0]  # the policy's warning for personal data going to the US
    [seen] = transport.calls  # the original never reaches the transport, and the key does
    assert (seen.provider, seen.model, seen.prompt, seen.key) == ("openai", "gpt-test", MASKED, KEY)
    assert seen.journal == ["sent"]  # the record was written before the request went out
    sent, received = journal.entries()
    assert (sent["channel"], sent["provider"], sent["account_type"], sent["status"]) == ("api", "openai", "personal-private", "sent")
    assert (sent["level"], sent["markers_by_kind"], sent["coverage"], sent["scope"]) == (2, {"EMAIL": 1}, "full", "s1")
    assert (sent["payload_sha256"], sent["model"], sent["versions"]) == (sha(MASKED), "gpt-test", {"boxed": __version__})
    assert "usage" not in sent
    assert (received["channel"], received["status"], received["level"], received["markers_by_kind"]) == ("api", "received", -1, {})
    assert (received["payload_sha256"], received["model"], received["usage"]) == (sha("Dear [EMAIL_1], noted."), "gpt-test-2026", {"input": 12, "output": 5})
    assert received["note"] == "restored=1 unknown=0 suspicious=0"
    assert journal.verify().ok
    blob = journal.path.read_text()
    assert "ivan@acme.com" not in blob and KEY not in blob
    assert vault.load_map("s1").original_for("[EMAIL_1]") == "ivan@acme.com"  # a later `boxed restore --scope s1` works


def test_nothing_is_sent_when_the_journal_cannot_be_written(tmp_path, vault):
    broken = tmp_path / "journal.jsonl"
    broken.mkdir()
    journal = Journal(broken, default_keystore())
    transport = Transport(journal, Answer("ok", "m", {}))
    with pytest.raises(OSError):
        run(vault, journal, transport)
    assert transport.calls == []


def test_nothing_is_recorded_or_sent_when_the_vault_cannot_be_read(tmp_path, vault, journal):
    with vault.transaction("s1") as markers:
        markers.marker_for("EMAIL", "old@acme.com")
    foreign = Vault(vault.path, InsecureFileKeyStore(tmp_path / "other-keys"))  # the map is there, under another key
    transport = Transport(journal, Answer("ok", "m", {}))
    with pytest.raises(VaultError):
        run(foreign, journal, transport)
    assert transport.calls == [] and not journal.path.exists()


@pytest.mark.parametrize(
    ("policy", "verdict"),
    [({"profile": "ban"}, "deny"), ({"rules": {"personal:personal-private": "local-only"}}, "local-only")],
    ids=["deny", "local-only"],
)
def test_policy_block_sends_nothing(vault, journal, policy, verdict):
    transport = Transport(journal, Answer("ok", "m", {}))
    with pytest.raises(PolicyBlocked) as blocked:
        run(vault, journal, transport, config=ProjectConfig(policy=policy))
    assert blocked.value.decision.verdict == verdict
    assert "ivan@acme.com" not in str(blocked.value)
    assert transport.calls == [] and vault.scopes() == []  # nothing was sent and nothing was masked
    [record] = journal.entries()
    assert (record["channel"], record["provider"], record["account_type"], record["status"]) == ("api", "openai", "personal-private", "blocked")
    assert (record["level"], record["markers_by_kind"], record["scope"]) == (2, {"EMAIL": 1}, "s1")
    assert record["payload_sha256"] == hashlib.sha256(b"").hexdigest()  # no payload went anywhere
    assert "ivan@acme.com" not in journal.path.read_text()


def test_transport_error_is_journaled(vault, journal):
    failure = ChannelError("openai: HTTP 429 (rate_limit_exceeded)")
    transport = Transport(journal, error=failure)
    with pytest.raises(ChannelError) as caught:
        run(vault, journal, transport)
    assert caught.value is failure
    sent, error = journal.entries()
    assert (sent["status"], error["status"]) == ("sent", "error")
    assert (error["payload_sha256"], error["level"]) == (sha(MASKED), 2)
    assert (sent["markers_by_kind"], error["markers_by_kind"]) == ({"EMAIL": 1}, {})  # `sent` counted the kinds: once is enough
    assert (error["channel"], error["provider"], error["model"], error["note"]) == ("api", "openai", "gpt-test", str(failure))
    assert journal.verify().ok


def test_an_unexpected_transport_failure_is_journaled_and_reported_without_its_text(vault, journal):
    transport = Transport(journal, error=RuntimeError(f"boom with {TEXT} and {KEY}"))
    with pytest.raises(ChannelError) as caught:
        run(vault, journal, transport)
    assert str(caught.value) == "openai: request failed"
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    error = journal.entries()[-1]
    assert (error["status"], error["note"]) == ("error", "openai: request failed")
    assert "ivan@acme.com" not in journal.path.read_text() and KEY not in journal.path.read_text()


@pytest.mark.parametrize(
    ("config_level", "asked", "used"),
    [(0, None, 1), (2, 0, 1), (2, None, 2), (0, 2, 2), (0, 3, 3), (4, 2, 2)],
    ids=["config below the policy", "asked below the policy", "config above", "asked above", "asked 3", "asked below a config of 4"],
)
def test_policy_raises_the_level(vault, journal, config_level, asked, used):
    transport = Transport(journal, Answer("ok", "m", {}))
    result = run(vault, journal, transport, config=ProjectConfig(level=config_level), level=asked)
    assert result.level == used
    assert transport.calls[0].prompt == MASKED  # the personal data rule means level 1 at least: the email is masked even at level 0
    assert journal.entries()[0]["level"] == used


# ---- ask: level 4 is a plan (the task and the table schema), not a prompt ----

PLAN_REFUSAL = "level 4 sends the task and the table schema only: use boxed plan, or ask at a level from 0 to 3"


@pytest.mark.parametrize(
    ("config_level", "asked"), [(2, 4), (4, None), (4, 4), (0, 4)], ids=["asked 4", "config 4", "both 4", "config 0, asked 4"]
)
def test_level_4_is_refused_before_anything_is_recorded(vault, journal, config_level, asked):
    """KINDS_BY_LEVEL treats 4 as 3, so the whole text would go out masked at 3 while the journal said 4."""
    transport = Transport(journal, Answer("ok", "m", {}))
    with pytest.raises(ValueError) as caught:
        run(vault, journal, transport, config=ProjectConfig(level=config_level), level=asked)
    assert str(caught.value) == PLAN_REFUSAL
    assert transport.calls == [] and vault.scopes() == [] and not journal.path.exists()


def test_no_record_of_ask_ever_says_level_4(vault, journal):
    transport = Transport(journal, Answer("ok", "m", {}))
    for level in (0, 1, 2, 3):
        run(vault, journal, transport, level=level, config=ProjectConfig(level=4))  # an explicit level beats the config
    levels = {record["level"] for record in journal.entries()}
    assert levels <= {-1, 1, 2, 3} and 4 not in levels


def test_a_policy_that_needs_level_4_blocks_ask_and_points_to_the_plan(vault, journal):
    transport = Transport(journal, Answer("ok", "m", {}))
    config = ProjectConfig(level=2, policy={"rules": {"personal:personal-private": "masked:4"}})
    with pytest.raises(PolicyBlocked) as blocked:
        run(vault, journal, transport, config=config)
    assert blocked.value.decision.verdict == "masked" and blocked.value.decision.min_level == 4
    assert "boxed plan" in str(blocked.value) and "ivan@acme.com" not in str(blocked.value)
    assert transport.calls == [] and vault.scopes() == []  # nothing was masked or sent
    [record] = journal.entries()
    assert (record["status"], record["level"], record["markers_by_kind"]) == ("blocked", 2, {"EMAIL": 1})  # the level asked, never 4
    assert record["note"] == "policy masked at level 4: use boxed plan"
    assert record["payload_sha256"] == hashlib.sha256(b"").hexdigest()


def test_a_policy_that_needs_level_3_still_lets_ask_through(vault, journal):
    transport = Transport(journal, Answer("ok", "m", {}))
    config = ProjectConfig(level=0, policy={"rules": {"personal:personal-private": "masked:3"}})
    assert run(vault, journal, transport, config=config).level == 3


@pytest.mark.parametrize(
    ("provider", "account", "prompt", "account_type"),
    [
        ("openai", None, "server at 10.1.2.3 is down", "personal-private"),
        ("anthropic", None, "server at 10.1.2.3 is down", "personal-private"),
        ("deepseek", None, "server at [IP_1] is down", "personal-training"),
        ("openrouter", None, "server at [IP_1] is down", "personal-training"),
        ("deepseek", "corporate", "server at 10.1.2.3 is down", "corporate"),
    ],
    ids=["openai", "anthropic", "deepseek", "openrouter", "named account"],
)
def test_default_accounts_fail_safe(vault, journal, provider, account, prompt, account_type):
    """no-confidential lets a private account see code and addresses but masks them for one that may train."""
    config = ProjectConfig(level=0, policy={"profile": "no-confidential"})
    transport = Transport(journal, Answer("ok", "m", {}))
    run(vault, journal, transport, text="server at 10.1.2.3 is down", provider=provider, account=account, config=config)
    assert transport.calls[0].prompt == prompt
    assert journal.entries()[0]["account_type"] == account_type


def test_the_providers_jurisdiction_and_account_reach_the_warnings(vault, journal):
    transport = Transport(journal, Answer("ok", "m", {}))
    deepseek = run(vault, journal, transport, provider="deepseek")
    openai = run(vault, journal, transport, provider="openai")
    assert any("China" in w for w in deepseek.warnings) and any("train" in w for w in deepseek.warnings)
    assert not any("China" in w or "train" in w for w in openai.warnings)


def test_a_client_from_the_project_dictionary_counts_for_the_policy(vault, journal):
    transport = Transport(journal, Answer("ok", "m", {}))
    strict = {"profile": "approved-only"}
    with pytest.raises(PolicyBlocked) as blocked:
        run(vault, journal, transport, text="Offer for Acme Corp", config=ProjectConfig(dictionary={"Acme Corp": "CLIENT"}, policy=strict))
    assert blocked.value.decision.verdict == "deny"
    assert transport.calls == []
    run(vault, journal, transport, text="Offer for Acme Corp", config=ProjectConfig(policy=strict))  # the same text, no dictionary
    assert transport.calls[0].prompt == "Offer for Acme Corp"


# ---- ask: categories no detector raises (finance, strategy, hr, health) are named by the caller ----


def test_a_category_named_by_the_caller_counts_for_the_policy(vault, journal):
    transport = Transport(journal, Answer("ok", "m", {}))
    strict = ProjectConfig(policy={"profile": "approved-only"})
    run(vault, journal, transport, text="Q3 plan", config=strict)  # nothing in the text raises a category: allowed
    assert len(transport.calls) == 1
    with pytest.raises(PolicyBlocked) as blocked:
        run(vault, journal, transport, text="Q3 plan", config=strict, categories=["finance"])
    assert blocked.value.decision.verdict == "deny"
    assert len(transport.calls) == 1  # the second one never left
    blocked_record = journal.entries()[-1]
    assert (blocked_record["status"], blocked_record["markers_by_kind"]) == ("blocked", {})  # the text held no marker: the category was named


def test_a_named_category_is_added_to_the_detected_ones(vault, journal):
    config = ProjectConfig(policy={"profile": "no-confidential"})
    with pytest.raises(PolicyBlocked) as blocked:
        run(vault, journal, Transport(journal, Answer("ok", "m", {})), config=config, categories=("hr",))  # hr is local-only here
    reasons = " ".join(blocked.value.decision.reasons)
    assert "hr" in reasons
    result = run(vault, journal, Transport(journal, Answer("ok", "m", {})), config=config, categories=("finance",))
    assert result.level == 3  # finance for a personal-private account is masked at level 3 or higher, and the email is a personal-data hit too
    assert [e["level"] for e in journal.entries() if e["status"] == "sent"] == [3]


def test_a_named_category_can_raise_the_level_of_a_clean_text(vault, journal):
    transport = Transport(journal, Answer("ok", "m", {}))
    config = ProjectConfig(level=0, policy={"profile": "no-confidential"})
    assert run(vault, journal, transport, text="Q3 plan", config=config).level == 0
    assert run(vault, journal, transport, text="Q3 plan", config=config, categories=["finance"]).level == 3
    assert run(vault, journal, transport, text="Q3 plan", config=config, categories=["finance", "strategy"]).level == 3  # duplicates and unions are fine


def test_a_category_that_does_not_exist_is_refused_before_anything_is_recorded(vault, journal):
    transport = Transport(journal, Answer("ok", "m", {}))
    with pytest.raises(PolicyError):
        run(vault, journal, transport, categories=["gold"])
    assert transport.calls == [] and vault.scopes() == [] and not journal.path.exists()


AMOUNT_TEXT = "Pay $1,200.50 to ivan@acme.com by 21.10.2026"


def test_an_amount_is_finance_for_the_policy_and_amounts_dates_and_emails_are_masked_from_level_3(vault, journal):
    transport = Transport(journal, Answer("Paid [MONEY_1] to [EMAIL_1] on [DATE_1].", "m", {}))
    config = ProjectConfig(level=0, policy={"profile": "no-confidential"})
    result = run(vault, journal, transport, text=AMOUNT_TEXT, config=config)
    assert result.level == 3  # finance: masked at level 3 or higher, whatever the config says
    assert transport.calls[0].prompt == "Pay [MONEY_1] to [EMAIL_1] by [DATE_1]"
    assert result.text == "Paid $1,200.50 to ivan@acme.com on 21.10.2026."
    sent = journal.entries()[0]
    assert (sent["level"], sent["markers_by_kind"]) == (3, {"MONEY": 1, "EMAIL": 1, "DATE": 1})


def test_an_amount_alone_makes_a_text_finance_and_a_strict_profile_denies_it(vault, journal):
    transport = Transport(journal, Answer("ok", "m", {}))
    strict = ProjectConfig(policy={"profile": "approved-only"})
    with pytest.raises(PolicyBlocked) as blocked:
        run(vault, journal, transport, text="Total due: $1,200.50", config=strict)
    assert blocked.value.decision.verdict == "deny" and transport.calls == []
    assert journal.entries()[-1]["markers_by_kind"] == {"MONEY": 1}
    run(vault, journal, transport, text="Total due: soon", config=strict)  # the same text without the amount
    assert len(transport.calls) == 1


def test_a_corporate_account_under_no_rules_keeps_the_amount_the_policy_does_not_ask_to_hide(vault, journal):
    """no-rules lets finance data go to a company plan as it is: level 2 hides the e-mail, level 3 would hide the rest."""
    transport = Transport(journal, Answer("ok", "m", {}))
    result = run(vault, journal, transport, text=AMOUNT_TEXT, account="corporate", config=ProjectConfig(policy={"profile": "no-rules"}))
    assert result.level == 2 and transport.calls[0].prompt == "Pay $1,200.50 to [EMAIL_1] by 21.10.2026"


def test_a_generator_of_categories_is_read_once(vault, journal):
    transport = Transport(journal, Answer("ok", "m", {}))
    config = ProjectConfig(level=0, policy={"profile": "no-confidential"})
    result = run(vault, journal, transport, text="Q3 plan", config=config, categories=(c for c in ["finance"]))
    assert result.level == 3


def test_an_incomplete_answer_is_restored_and_flagged_in_the_result(vault, journal):
    cut = run(vault, journal, Transport(journal, Answer("Dear [EMAIL_1], and then", "m", {}, complete=False)))
    whole = run(vault, journal, Transport(journal, Answer("Dear [EMAIL_1]", "m", {})))
    assert (cut.text, cut.complete) == ("Dear ivan@acme.com, and then", False)
    assert (whole.text, whole.complete) == ("Dear ivan@acme.com", True)


def test_a_refused_answer_is_journaled_as_an_error_and_not_as_received(vault, journal, start_api):
    refusal = {"status": "completed", "output": [{"type": "message", "content": [{"type": "refusal", "refusal": "no"}]}]}
    api = start_api(body=json.dumps(refusal).encode())
    with pytest.raises(ChannelError) as caught:
        run(vault, journal, functools.partial(call, base_url=api.url))
    assert str(caught.value) == "openai: the model refused to answer"
    sent, error = journal.entries()
    assert (sent["status"], error["status"], error["note"]) == ("sent", "error", "openai: the model refused to answer")


def test_an_answer_that_cannot_be_restored_is_an_error_not_a_send_without_an_end(vault, journal, monkeypatch):
    """Text from the network can break restore() after the request went out (a placeholder with 4,301 digits used to: it is plain
    text now), whatever the way: the end of the send is an error record, and nothing is chained to the error."""

    def broken(*args, **kwargs):
        raise ValueError("the reader broke on this answer")

    monkeypatch.setattr("boxed.channels.restore", broken)
    transport = Transport(journal, Answer("Sure. See [EMAIL_1] for details", "m", {"input": 3, "output": 4}))
    with pytest.raises(ChannelError) as caught:
        run(vault, journal, transport)
    assert str(caught.value) == "openai: the answer cannot be restored"
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    sent, error = journal.entries()
    assert (sent["status"], error["status"], error["note"]) == ("sent", "error", "openai: the answer cannot be restored")
    assert (error["payload_sha256"], error["level"], error["markers_by_kind"]) == (sha(MASKED), 2, {})


def test_an_answer_with_a_placeholder_of_more_digits_than_int_takes_comes_back_as_plain_text(vault, journal):
    token = "[EMAIL_" + "9" * 4301 + "]"
    result = run(vault, journal, Transport(journal, Answer(f"Sure. See {token} for details", "m", {"input": 3, "output": 4})))
    assert result.text == f"Sure. See {token} for details" and result.unknown == [] and result.suspicious == []
    assert [e["status"] for e in journal.entries()] == ["sent", "received"]


def test_an_answer_cannot_pull_in_the_placeholders_of_other_prompts_of_the_scope(vault, journal):
    run(vault, journal, Transport(journal, Answer("ok", "m", {})), text="deploy key AKIAIOSFODNN7EXAMPLE, contact ivan@acme.com")
    injected = Transport(journal, Answer("Here: [SECRET_1] and [EMAIL_1]", "m", {}))  # the scope holds both; this prompt has neither
    result = run(vault, journal, injected, text="Summarize: nothing sensitive here")
    assert injected.calls[0].prompt == "Summarize: nothing sensitive here"
    assert result.text == "Here: [SECRET_1] and [EMAIL_1]"
    assert result.unknown == ["[SECRET_1]", "[EMAIL_1]"]
    assert journal.entries()[-1]["note"] == "restored=0 unknown=2 suspicious=0"


def test_an_answer_gets_back_the_placeholders_of_its_own_prompt_only(vault, journal):
    run(vault, journal, Transport(journal, Answer("ok", "m", {})), text="deploy key AKIAIOSFODNN7EXAMPLE, contact ivan@acme.com")
    transport = Transport(journal, Answer("Mail [EMAIL_1] and key [SECRET_1]", "m", {}))
    result = run(vault, journal, transport, text="Write to ivan@acme.com")  # the same email, so the same placeholder
    assert transport.calls[0].prompt == "Write to [EMAIL_1]"
    assert result.text == "Mail ivan@acme.com and key [SECRET_1]"
    assert result.unknown == ["[SECRET_1]"]
    assert journal.entries()[-1]["note"] == "restored=1 unknown=1 suspicious=0"


def test_a_placeholder_shaped_string_of_the_text_still_comes_back(vault, journal):
    transport = Transport(journal, Answer("Keep [LITERAL_1] and mail [EMAIL_1]", "m", {}))
    result = run(vault, journal, transport, text="Keep [email_7] and mail ivan@acme.com")
    assert transport.calls[0].prompt == "Keep [LITERAL_1] and mail [EMAIL_1]"
    assert result.text == "Keep [email_7] and mail ivan@acme.com"
    assert result.unknown == []


class FailingJournal(Journal):
    """A journal that cannot write the records of some statuses, like a disk that fills up part way through."""

    def __init__(self, path, keys, cannot):
        super().__init__(path, keys)
        self.cannot = cannot

    def append(self, entry):
        if entry.status in self.cannot:
            raise OSError("No space left on device")
        return super().append(entry)


def test_a_journal_that_cannot_write_received_withholds_the_answer(boxed_env, vault):
    journal = FailingJournal(boxed_env / "journal.jsonl", default_keystore(), {"received"})
    transport = Transport(journal, Answer("Dear [EMAIL_1]", "m", {}))
    with pytest.raises(OSError):
        run(vault, journal, transport)
    assert len(transport.calls) == 1  # the request had gone out; the answer is not handed over without its record
    assert [record["status"] for record in journal.entries()] == ["sent"]


def test_a_journal_that_cannot_write_error_surfaces_the_journals_error(boxed_env, vault):
    journal = FailingJournal(boxed_env / "journal.jsonl", default_keystore(), {"error"})
    transport = Transport(journal, error=ChannelError("openai: HTTP 500"))
    with pytest.raises(OSError):
        run(vault, journal, transport)
    assert [record["status"] for record in journal.entries()] == ["sent"]


def test_unknown_and_suspicious_markers_are_reported_and_counted(vault, journal):
    transport = Transport(journal, Answer("Mail [EMAIL_1], not [EMAIL_9], and [EMAIL-1] is odd.", "m", {}))
    result = run(vault, journal, transport)
    assert result.text == "Mail ivan@acme.com, not [EMAIL_9], and [EMAIL-1] is odd."
    assert (result.unknown, result.suspicious) == (["[EMAIL_9]"], ["[EMAIL-1]"])
    assert journal.entries()[-1]["note"] == "restored=1 unknown=1 suspicious=1"


def test_the_vault_is_not_locked_while_the_request_is_in_flight(vault, journal):
    free = []

    def transport(provider, model, prompt, key):
        taken = threading.Event()

        def grab():
            with file_lock(vault.path):
                taken.set()

        threading.Thread(target=grab, daemon=True).start()
        free.append(taken.wait(2))
        return Answer("ok", "m", {})

    run(vault, journal, transport)
    assert free == [True]


PROVIDER_REFUSAL = "unknown provider, expected one of openai, anthropic, deepseek, openrouter"
LEVEL_REFUSAL = "level must be 0-3"
MODEL_REFUSAL = "bad model name"
KEY_REFUSAL = "the API key must be printable ASCII without spaces"
TEXT_REFUSAL = "the text is not valid Unicode"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"provider": "nope"}, PROVIDER_REFUSAL),
        ({"level": 5}, LEVEL_REFUSAL),
        ({"level": True}, LEVEL_REFUSAL),
        ({"level": "2"}, LEVEL_REFUSAL),
        ({"model": ""}, MODEL_REFUSAL),
        ({"model": "gpt 4"}, MODEL_REFUSAL),
        ({"model": "m" * 200}, MODEL_REFUSAL),
        ({"key": ""}, KEY_REFUSAL),
        ({"key": "sk bad"}, KEY_REFUSAL),
        ({"text": "Ivan\ud800 Petrov"}, TEXT_REFUSAL),
    ],
    ids=["provider", "level 5", "level True", "level text", "model empty", "model space", "model long", "key empty", "key space", "surrogate"],
)
def test_bad_arguments_are_refused_with_a_fixed_text_before_anything_is_recorded(vault, journal, overrides, message):
    transport = Transport(journal, Answer("ok", "m", {}))
    with pytest.raises(ValueError) as caught:
        run(vault, journal, transport, **overrides)
    assert str(caught.value) == message  # a key, a text or a name is never quoted back
    assert transport.calls == [] and vault.scopes() == [] and not journal.path.exists()


def test_an_account_that_is_not_a_recipient_kind_is_refused_before_anything_is_recorded(vault, journal):
    transport = Transport(journal, Answer("ok", "m", {}))
    with pytest.raises(PolicyError):
        run(vault, journal, transport, account="vip")
    assert transport.calls == [] and vault.scopes() == [] and not journal.path.exists()


@pytest.mark.parametrize("profile", ["ban", "approved-only", "no-rules"])
def test_a_remote_api_is_never_a_local_recipient(vault, journal, profile):
    """The policy lets everything go to a local recipient; an API call leaves the computer whatever the account is named."""
    transport = Transport(journal, Answer("ok", "m", {}))
    with pytest.raises(ValueError) as caught:
        run(vault, journal, transport, account="local", config=ProjectConfig(policy={"profile": profile}))
    assert str(caught.value) == "a remote API is never a local recipient"
    assert transport.calls == [] and vault.scopes() == [] and not journal.path.exists()


# ---- ask over real HTTP ----


def test_ask_over_http_sends_only_the_masked_text_and_restores_the_answer(vault, journal, start_api):
    api = start_api(
        body=json.dumps(
            {
                "model": "deepseek-chat-2026",
                "choices": [{"message": {"content": "Dear [EMAIL_1]"}}],
                "usage": {"prompt_tokens": 8, "completion_tokens": 3},
            }
        ).encode()
    )
    transport = functools.partial(call, base_url=api.url)
    result = run(vault, journal, transport, provider="deepseek", model="deepseek-chat")
    assert (result.text, result.model, result.usage) == ("Dear ivan@acme.com", "deepseek-chat-2026", {"input": 8, "output": 3})
    [request] = api.requests
    assert json.loads(request.body)["messages"] == [{"role": "user", "content": MASKED}]
    assert b"ivan@acme.com" not in request.body
    received = journal.entries()[-1]
    assert (received["model"], received["usage"]) == ("deepseek-chat-2026", {"input": 8, "output": 3})


@pytest.mark.parametrize(
    ("account", "zdr"),
    [(None, False), ("personal-training", False), ("personal-private", False), ("corporate", False), ("api-zero-retention", True)],
)
def test_the_zero_retention_account_asks_openrouter_for_zero_retention_endpoints(vault, journal, start_api, account, zdr):
    api = start_api(body=json.dumps({"model": "vendor/m", "choices": [{"message": {"content": "ok"}}]}).encode())
    run(vault, journal, functools.partial(call, base_url=api.url), provider="openrouter", model="vendor/m", account=account)
    sent = json.loads(api.requests[0].body)
    assert sent["provider"] == ({"data_collection": "deny", "zdr": True} if zdr else {"data_collection": "deny"})
    assert journal.entries()[0]["account_type"] == (account or "personal-training")


def test_the_cost_openrouter_reports_reaches_the_received_record(vault, journal, start_api):
    usage = {"prompt_tokens": 8, "completion_tokens": 3, "cost": 0.000042}
    api = start_api(body=json.dumps({"model": "vendor/m", "choices": [{"message": {"content": "Dear [EMAIL_1]"}}], "usage": usage}).encode())
    result = run(vault, journal, functools.partial(call, base_url=api.url), provider="openrouter", model="vendor/m")
    expected = {"input": 8, "output": 3, "cost_micro_usd": 42}
    assert (result.text, result.usage) == ("Dear ivan@acme.com", expected)
    sent, received = journal.entries()
    assert "usage" not in sent and received["usage"] == expected and journal.verify().ok


def test_the_zero_retention_account_adds_nothing_to_the_request_of_another_provider(vault, journal, start_api):
    api = start_api(body=json.dumps({"model": "m", "choices": [{"message": {"content": "ok"}}]}).encode())
    run(vault, journal, functools.partial(call, base_url=api.url), provider="deepseek", model="m", account="api-zero-retention")
    assert set(json.loads(api.requests[0].body)) == {"model", "messages"}


def test_an_error_body_echoing_the_prompt_and_key_never_reaches_the_journal_or_the_terminal(vault, journal, start_api, capsys):
    body = {"error": {"message": f"bad key {KEY}; your prompt was {MASKED} / {TEXT}", "code": "invalid_api_key"}}
    api = start_api(status=401, body=json.dumps(body).encode())
    with pytest.raises(ChannelError) as caught:
        run(vault, journal, functools.partial(call, base_url=api.url))
    assert str(caught.value) == "openai: HTTP 401 (invalid_api_key)"
    sent, error = journal.entries()
    assert (sent["status"], error["status"], error["note"]) == ("sent", "error", "openai: HTTP 401 (invalid_api_key)")
    blob = journal.path.read_text()
    assert KEY not in blob and TEXT not in blob and MASKED not in blob
    assert capsys.readouterr() == ("", "")


def test_the_default_transport_is_the_http_call(vault, journal, monkeypatch):
    posted = []

    def answer(self, request, data=None, timeout=None):
        posted.append((request.get_method(), request.full_url))
        return io.BytesIO(json.dumps({"output": [{"type": "message", "content": [{"type": "output_text", "text": "Dear [EMAIL_1]"}]}]}).encode())

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", answer)
    result = ask(TEXT, provider="openai", model="gpt-test", key=KEY, scope="s1", vault=vault, journal=journal, config=ProjectConfig())
    assert result.text == "Dear ivan@acme.com"
    assert posted == [("POST", "https://api.openai.com/v1/responses")]


# ---- ask: a relay named in BOXED_<PROVIDER>_BASE_URL ----

RELAY_REFUSAL = "BOXED_OPENAI_BASE_URL must be an https address (or http on this computer) without a login, query or fragment"
RELAYS_THAT_ARE_FINE = [
    "https://relay.example.com/v1",
    "https://relay.example.com:8443/api/v1/",
    "https://relay.example.com",
    "https://203.0.113.7/v1",
    "http://localhost:11434/v1",
    "http://127.0.0.1:8080",
    "http://127.0.0.2:8080/x",  # all of 127/8 is this computer
    "http://[::1]:8080/v1",
    "https://[2001:db8::1]/v1",
]
RELAYS_THAT_ARE_NOT = [
    "http://relay.example.com/v1",  # a key must not cross the network in the clear
    "http://localhost.evil.example.com/v1",
    "http://127.0.0.1.evil.example.com",
    "http://0.0.0.0:80",
    "ftp://relay.example.com",
    "file:///etc/passwd",
    "javascript:alert(1)",
    "relay.example.com/v1",
    "//relay.example.com/v1",
    "https://",
    "https:///v1",
    "https://user:secret-password@relay.example.com/v1",  # a login in an address ends up in logs and error texts
    "https://secret-user@relay.example.com",
    "https://relay.example.com/v1?key=secret-query",
    "https://relay.example.com/v1#secret-fragment",
    "https://relay.example.com/v1?",  # an empty query would still turn the path into /v1?/responses
    "https://relay.example.com/v1#",
    "https://relay.example.com?",
    "https://relay.example.com/v1?#",
    "https://relay example.com/v1",
    "https://relay.example.com:99999/v1",
    "https://relay.example.com:abc/v1",
    "https://relay!.example.com/v1",  # not a host name, though every character is visible ASCII
    "https://relay..example.com/v1",
    "https://-relay.example.com/v1",
    "https://relay.example.com/v1\nX-Evil: secret-header",
    "https://релей.example.com/v1",
    "https://[::1/v1",
]


class Hop:
    """A transport that only notes where the request would go."""

    def __init__(self):
        self.went_to = []

    def __call__(self, provider, model, prompt, key):
        self.went_to.append(provider.base_url)
        return Answer("ok", "m", {})


@pytest.mark.parametrize("address", RELAYS_THAT_ARE_FINE)
def test_a_relay_from_the_environment_replaces_the_base_url_and_the_record_says_so(vault, journal, monkeypatch, address):
    monkeypatch.setenv("BOXED_OPENAI_BASE_URL", address)
    hop = Hop()
    run(vault, journal, hop)
    assert hop.went_to == [address]
    sent = journal.entries()[0]
    assert sent["note"] == "relay" and sent["provider"] == "openai"  # still the provider as far as boxed knows, and marked as relayed


@pytest.mark.parametrize("address", RELAYS_THAT_ARE_NOT, ids=range(len(RELAYS_THAT_ARE_NOT)))
def test_an_address_a_key_must_not_be_sent_to_is_refused_before_anything_is_recorded(vault, journal, monkeypatch, address):
    monkeypatch.setenv("BOXED_OPENAI_BASE_URL", address)
    hop = Hop()
    with pytest.raises(ValueError) as caught:
        run(vault, journal, hop)
    assert str(caught.value) == RELAY_REFUSAL  # the address is not quoted back: it may hold a login
    assert hop.went_to == [] and vault.scopes() == [] and not journal.path.exists()


@pytest.mark.parametrize("value", ["", "   "], ids=["empty", "blank"])
def test_an_empty_relay_variable_is_no_relay(vault, journal, monkeypatch, value):
    monkeypatch.setenv("BOXED_OPENAI_BASE_URL", value)
    hop = Hop()
    run(vault, journal, hop)
    assert hop.went_to == ["https://api.openai.com/v1"] and journal.entries()[0]["note"] == ""


def test_a_relay_belongs_to_its_provider(vault, journal, monkeypatch):
    monkeypatch.setenv("BOXED_ANTHROPIC_BASE_URL", "https://relay.example.com/a")
    monkeypatch.setenv("BOXED_OPENROUTER_BASE_URL", "https://relay.example.com/or")
    hop = Hop()
    run(vault, journal, hop)
    run(vault, journal, hop, provider="anthropic")
    run(vault, journal, hop, provider="openrouter", model="vendor/m")
    run(vault, journal, hop, provider="deepseek", model="m")
    assert hop.went_to == [
        "https://api.openai.com/v1", "https://relay.example.com/a", "https://relay.example.com/or", "https://api.deepseek.com",
    ]
    assert [e["note"] for e in journal.entries() if e["status"] == "sent"] == ["", "relay", "relay", ""]


def test_the_relay_receives_the_request_and_the_real_provider_does_not(vault, journal, monkeypatch):
    posted = []

    def answer(self, request, data=None, timeout=None):
        posted.append((request.get_method(), request.full_url, request.get_header("Authorization")))
        return io.BytesIO(json.dumps({"output": [{"type": "message", "content": [{"type": "output_text", "text": "Dear [EMAIL_1]"}]}]}).encode())

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", answer)
    monkeypatch.setenv("BOXED_OPENAI_BASE_URL", "https://relay.example.test/openai/v1/")
    result = ask(TEXT, provider="openai", model="gpt-test", key=KEY, scope="s1", vault=vault, journal=journal, config=ProjectConfig())
    assert result.text == "Dear ivan@acme.com"
    assert posted == [("POST", "https://relay.example.test/openai/v1/responses", f"Bearer {KEY}")]


def test_a_relay_is_marked_only_on_the_record_of_the_send(vault, journal, monkeypatch):
    monkeypatch.setenv("BOXED_OPENAI_BASE_URL", "https://relay.example.com/v1")
    run(vault, journal, Hop())
    assert [(e["status"], e["note"]) for e in journal.entries()] == [("sent", "relay"), ("received", "restored=0 unknown=0 suspicious=0")]


# ---- keys ----


class BrokenKeyring(KeyringBackend):
    """A keychain that refuses everything and, like some real backends, quotes the password in its errors."""

    priority = 1

    def __init__(self, error):
        super().__init__()
        self.error = error

    def get_password(self, service, username):
        raise self.error("keychain locked")

    def set_password(self, service, username, password):
        raise self.error(f"cannot store {password}")

    def delete_password(self, service, username):
        raise self.error("cannot delete")


@pytest.mark.parametrize(
    ("provider", "variable"),
    [("openai", "OPENAI_API_KEY"), ("anthropic", "ANTHROPIC_API_KEY"), ("deepseek", "DEEPSEEK_API_KEY"), ("openrouter", "OPENROUTER_API_KEY")],
)
def test_api_key_prefers_keyring_then_env(memory_keyring, monkeypatch, provider, variable):
    assert api_key(provider) is None
    monkeypatch.setenv(variable, "sk-from-env")
    assert api_key(provider) == "sk-from-env"
    memory_keyring.set_password("boxed.si", f"api-key:{provider}", "sk-from-keyring")
    assert api_key(provider) == "sk-from-keyring"
    monkeypatch.delenv(variable)
    assert api_key(provider) == "sk-from-keyring"


def test_a_key_belongs_to_its_provider(memory_keyring, monkeypatch):
    memory_keyring.set_password("boxed.si", "api-key:openai", "sk-openai")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-deepseek")
    assert [api_key(name) for name in PROVIDERS] == ["sk-openai", None, "sk-deepseek", None]


def test_key_source_says_where_the_key_comes_from(memory_keyring, monkeypatch):
    assert key_source("openai") is None
    monkeypatch.setenv("OPENAI_API_KEY", "sk-from-env")
    assert key_source("openai") == "environment"
    memory_keyring.set_password("boxed.si", "api-key:openai", "sk-from-keyring")
    assert key_source("openai") == "keychain"  # the one api_key() would hand over
    monkeypatch.delenv("OPENAI_API_KEY")
    assert key_source("openai") == "keychain"
    assert key_source("anthropic") is None  # a key belongs to its provider


def test_key_source_ignores_blank_values_and_a_broken_keychain(memory_keyring, monkeypatch):
    memory_keyring.set_password("boxed.si", "api-key:openai", "  \n")
    monkeypatch.setenv("OPENAI_API_KEY", "  sk-env \n")
    assert key_source("openai") == "environment"
    monkeypatch.setenv("OPENAI_API_KEY", "   ")
    assert key_source("openai") is None
    keyring.set_keyring(BrokenKeyring(RuntimeError))
    monkeypatch.setenv("OPENAI_API_KEY", "sk-env")
    assert key_source("openai") == "environment"


def test_key_source_refuses_an_unknown_provider(memory_keyring):
    with pytest.raises(ValueError) as caught:
        key_source("nope")
    assert str(caught.value) == PROVIDER_REFUSAL


def test_padding_is_dropped_and_a_blank_value_means_unset(memory_keyring, monkeypatch):
    memory_keyring.set_password("boxed.si", "api-key:openai", "  \n")
    monkeypatch.setenv("OPENAI_API_KEY", "  sk-env \n")
    assert api_key("openai") == "sk-env"
    monkeypatch.setenv("OPENAI_API_KEY", "   ")
    assert api_key("openai") is None


@pytest.mark.parametrize("error", [NoKeyringError, PasswordSetError, RuntimeError])
def test_a_broken_keychain_reads_as_not_set_and_the_env_var_still_works(monkeypatch, error):
    keyring.set_keyring(BrokenKeyring(error))  # the autouse fixture puts the real one back afterwards
    assert api_key("openai") is None
    monkeypatch.setenv("OPENAI_API_KEY", "sk-env")
    assert api_key("openai") == "sk-env"


@pytest.mark.parametrize("error", [PasswordSetError, RuntimeError])
def test_keychain_errors_on_write_and_delete_are_fixed_text_without_the_key(error):
    keyring.set_keyring(BrokenKeyring(error))
    with pytest.raises(ChannelError) as stored:
        set_api_key("openai", "sk-secret-value")
    assert str(stored.value) == "openai: cannot store the key in the keychain"
    assert stored.value.__cause__ is None and stored.value.__context__ is None
    with pytest.raises(ChannelError) as removed:
        delete_api_key("openai")
    assert str(removed.value) == "openai: cannot remove the key from the keychain"
    assert removed.value.__cause__ is None and removed.value.__context__ is None


def test_set_and_delete_api_key(memory_keyring, monkeypatch):
    set_api_key("anthropic", "  sk-ant-123\n")
    assert memory_keyring.store == {("boxed.si", "api-key:anthropic"): "sk-ant-123"}
    assert api_key("anthropic") == "sk-ant-123"
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-from-env")
    delete_api_key("anthropic")
    assert memory_keyring.store == {}
    assert api_key("anthropic") == "sk-from-env"  # only the keychain entry went away
    delete_api_key("anthropic")  # nothing left to delete is not an error


@pytest.mark.parametrize("key", ["", "   ", "sk bad", "sk-ключ", "sk-bad\r\nX: 1", "k" * 2000], ids=["empty", "blank", "space", "non-ascii", "line break", "long"])
def test_a_key_that_could_not_be_sent_is_not_stored(memory_keyring, key):
    with pytest.raises(ValueError) as caught:
        set_api_key("openai", key)
    assert str(caught.value) == KEY_REFUSAL
    assert memory_keyring.store == {}


def test_the_key_functions_refuse_an_unknown_provider(memory_keyring):
    for refused in (lambda: api_key("nope"), lambda: delete_api_key("nope"), lambda: set_api_key("nope", "sk-x")):
        with pytest.raises(ValueError) as caught:
            refused()
        assert str(caught.value) == PROVIDER_REFUSAL
    assert memory_keyring.store == {}
