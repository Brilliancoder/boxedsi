"""boxed serve: the core as one long-running process for the desktop shell, framed JSON on stdin and stdout.

Every command is checked against the command line on the same input, and every refusal against the fixed text the shell may
show. No test touches the real ~/.boxed or the keychain: conftest.py points BOXED_HOME at a temp folder and the keys at files,
and a memory backend stands in for the OS keychain."""

import contextlib
import csv
import gc
import hashlib
import html
import importlib
import importlib.util
import io
import json
import os
import re
import shutil
import signal
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import threading
import time
import types
import weakref
import zipfile
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import keyring
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError

from boxed import __version__, dashboard
from boxed import cli as cli_module
from boxed import platform as boxed_platform
from boxed import serve as serve_module
from boxed.channels import PROVIDERS
from boxed.checks import Check, load_checks, save_check
from boxed.cli import main as cli_main
from boxed.detect import DetectConfig, ner
from boxed.formats import FileReport
from boxed.journal import Journal, JournalEntry
from boxed.keys import default_keystore
from boxed.native_host import read_message, write_message
from boxed.observe import observe, observed_journal
from boxed.platform import IS_WINDOWS
from boxed.policy import CATEGORIES, RECIPIENT_KINDS
from boxed.serve import MAX_REPLY, MAX_REQUEST, Session, handle, serve


def frame(payload: bytes) -> bytes:
    """A frame as the shell writes it, built here and not by the code under test: 4-byte little-endian length, then the payload."""
    return struct.pack("<I", len(payload)) + payload


def frames(*messages: dict) -> bytes:
    return b"".join(frame(json.dumps(m, ensure_ascii=False).encode("utf-8")) for m in messages)


def replies(raw: bytes) -> list[dict]:
    """The frames of a stream of replies, read the way the shell reads them."""
    found, at = [], 0
    while at < len(raw):
        (size,) = struct.unpack("<I", raw[at : at + 4])
        found.append(json.loads(raw[at + 4 : at + 4 + size].decode("utf-8")))
        at += 4 + size
    assert at == len(raw), "a frame is cut off"
    return found


def is_ping(reply: dict, request_id, ner=()) -> bool:
    """The answer to a ping: the version, the name detectors that run (`ner`), and those that could run, as the extras installed here."""
    return (
        set(reply) == {"id", "ok", "version", "ner", "ner_installed"}
        and (reply["id"], reply["ok"], reply["version"], reply["ner"]) == (request_id, True, __version__, list(ner))
        and set(reply["ner_installed"]) <= {"ru", "en"}
    )


def run_serve(session, *messages: dict, raw: bytes = b"") -> tuple[int, list[dict]]:
    stdout = io.BytesIO()
    code = serve(io.BytesIO(frames(*messages) + raw), stdout, session)
    return code, replies(stdout.getvalue())


class MemoryKeyring(KeyringBackend):
    """The OS keychain, in memory."""

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
def isolated(boxed_env, monkeypatch):
    """Nothing here reaches the real ~/.boxed, the real keychain, a proxy, a relay or any address but this computer.

    The folder and the file keys of conftest.py can be undone by a test (monkeypatch.undo() does it): every way into the data
    folder of `cli.Context` checks them first, with a patch of its own that undo() leaves alone, and a keychain in memory stands
    in for the real one whatever BOXED_KEYSTORE says."""
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
    real_init = cli_module.Context.__init__

    def checked(self):
        assert os.environ.get("BOXED_HOME") == str(boxed_env), "a test left the boxed home of conftest.py"
        assert os.environ.get("BOXED_KEYSTORE") == "insecure-file", "a test left the file keys of conftest.py"
        real_init(self)

    with pytest.MonkeyPatch.context() as guard:
        guard.setattr(cli_module.Context, "__init__", checked)
        yield backend
    keyring.set_keyring(previous)


@pytest.fixture
def memory_keyring(isolated):
    return isolated


@pytest.fixture
def session(boxed_env):
    return Session()


# ---- framing: 4-byte little-endian length, UTF-8 JSON, a cap per frame, the id echoed ----


def test_a_frame_is_a_little_endian_length_and_utf8_json(session):
    stdout = io.BytesIO()
    assert serve(io.BytesIO(frames({"id": 7, "cmd": "ping"})), stdout, session) == 0
    raw = stdout.getvalue()
    assert struct.unpack("<I", raw[:4])[0] == len(raw) - 4
    assert is_ping(json.loads(raw[4:].decode("utf-8")), 7)


def test_the_reply_carries_the_id_and_ok_first(session):
    _, [reply] = run_serve(session, {"id": 7, "cmd": "ping"})
    assert list(reply)[:2] == ["id", "ok"]


def test_cyrillic_travels_as_utf8_and_not_as_escapes():
    stream = io.BytesIO()
    write_message(stream, {"text": "я"}, MAX_REPLY, "<")
    assert "я".encode() in stream.getvalue()


@pytest.mark.parametrize("request_id", [0, 1, 2**32, 2**53 + 1, 2**64 - 1, "a", "req-0.1_x", "A" * 64])
def test_the_id_comes_back_exactly_as_it_was_sent(session, request_id):
    _, [reply] = run_serve(session, {"id": request_id, "cmd": "ping"})
    assert reply["id"] == request_id and type(reply["id"]) is type(request_id) and reply["ok"] is True


@pytest.mark.parametrize(
    "request_id",
    [None, True, False, -1, 2**64, 1.0, 1.5, "", "A" * 65, "a b", "a\n", "ключ", ["1"], {"id": 1}],
    ids=["null", "true", "false", "negative", "over u64", "float one", "float", "empty", "65 chars", "space", "newline", "cyrillic", "list", "object"],
)
def test_an_id_that_is_no_id_gets_a_null_id_and_a_bad_request_and_the_loop_goes_on(session, request_id):
    code, [bad, good] = run_serve(session, {"id": request_id, "cmd": "ping"}, {"id": 2, "cmd": "ping"})
    assert code == 0
    assert bad == {"id": None, "ok": False, "error": "bad request"}
    assert good["id"] == 2 and good["ok"] is True


def test_a_request_without_an_id_is_refused(session):
    _, [reply] = run_serve(session, {"cmd": "ping"})
    assert reply == {"id": None, "ok": False, "error": "bad request"}


@pytest.mark.parametrize(
    "message",
    [
        {"id": 1},
        {"id": 1, "cmd": None},
        {"id": 1, "cmd": 7},
        {"id": 1, "cmd": ["ping"]},
        {"id": 1, "cmd": "shell", "args": ["ls"]},
        {"id": 1, "cmd": "Ping"},
        {"id": 1, "cmd": "ping", "extra": 1},
        {"id": 1, "cmd": "ping", "version": "9"},
        {"id": 1, "cmd": "ping", "text": "mail ivan@acme.com"},
    ],
    ids=lambda m: json.dumps(m)[:50],
)
def test_an_unknown_command_or_an_unknown_field_is_refused_with_the_id(session, message):
    _, [reply] = run_serve(session, message)
    assert reply == {"id": 1, "ok": False, "error": "bad request"}


def test_a_refusal_changes_nothing_on_disk(boxed_env, session):
    run_serve(session, {"id": 1, "cmd": "ping", "extra": 1}, {"id": 2, "cmd": "nope"}, {"id": 3})
    assert not boxed_env.exists()  # no data folder, no vault, no key: a request that is refused opens nothing


def test_serve_with_no_input_ends_at_once_and_says_nothing(session):
    stdout = io.BytesIO()
    assert serve(io.BytesIO(), stdout, session) == 0 and stdout.getvalue() == b""


def test_a_request_of_exactly_the_cap_is_read_and_one_byte_more_is_not(session):
    def padded(size):
        base = len(json.dumps({"id": 1, "cmd": "ping", "pad": ""}).encode())
        return json.dumps({"id": 1, "cmd": "ping", "pad": "x" * (size - base)}).encode()

    code, [reply] = run_serve(session, raw=frame(padded(MAX_REQUEST)))
    assert code == 0 and reply == {"id": 1, "ok": False, "error": "bad request"}  # read whole, then refused for the pad field
    code, [reply] = run_serve(session, raw=frame(padded(MAX_REQUEST + 1)))
    assert code == 1 and reply == {"id": None, "ok": False, "error": "message too large"}


def test_an_oversize_frame_is_refused_from_its_header_and_its_body_stays_unread(session):
    stdin = io.BytesIO(struct.pack("<I", 0xFFFFFFFF) + b"x" * 64)
    stdout = io.BytesIO()
    assert serve(stdin, stdout, session) == 1
    assert replies(stdout.getvalue()) == [{"id": None, "ok": False, "error": "message too large"}]
    assert stdin.tell() == 4  # nothing but the header was read


def test_the_header_is_little_endian_and_not_big_endian(session):
    body = json.dumps({"id": 1, "cmd": "ping"}).encode()
    code, [reply] = run_serve(session, raw=struct.pack(">I", len(body)) + body)
    assert code == 1 and reply == {"id": None, "ok": False, "error": "message too large"}  # 0x1c000000 read the wrong way round


BAD_FRAMES = {
    "cut json": (frame(b'{"id": 1, "cmd": "mask", "text": "ivan.petrov@acme.com"'), "bad json"),
    "not an object": (frame(b'["ivan.petrov@acme.com"]'), "bad json"),
    "not utf-8": (frame(b'{"id": 1, "text": "\xff\xfe ivan"}'), "bad json"),
    "nested too deep": (frame(b"[" * 600_000), "bad json"),
    "a key twice": (frame(b'{"id": 1, "cmd": "ping", "cmd": "mask", "text": "mail ivan.petrov@acme.com"}'), "bad json"),
    "a key twice inside": (frame(b'{"id": 1, "cmd": "policy-check", "categories": [{"a": 1, "a": 2}], "text": "ivan.petrov@acme.com"}'), "bad json"),
    "the same key and value twice": (frame(b'{"id": 1, "id": 1, "cmd": "ping"}'), "bad json"),
    "short body": (struct.pack("<I", 90) + b'{"id":1,"cmd":"mask","text":"ivan.petrov@acme.com"}', "truncated frame"),
}


@pytest.mark.parametrize(("raw", "error"), BAD_FRAMES.values(), ids=BAD_FRAMES.keys())
def test_a_bad_frame_gets_one_error_frame_with_a_null_id_and_ends_the_loop_with_1(session, raw, error):
    stdout = io.BytesIO()
    assert serve(io.BytesIO(frames({"id": 1, "cmd": "ping"}) + raw + frames({"id": 3, "cmd": "ping"})), stdout, session) == 1
    first, second = replies(stdout.getvalue())  # the ping after the bad frame is never answered
    assert first["id"] == 1 and first["ok"] is True
    assert second == {"id": None, "ok": False, "error": error}
    assert b"ivan" not in stdout.getvalue()


def test_a_header_cut_off_by_the_end_of_the_input_is_a_truncated_frame(session):
    code, [first, second] = run_serve(session, {"id": 1, "cmd": "ping"}, raw=b"\x05\x00")
    assert code == 1 and first["ok"] is True and second == {"id": None, "ok": False, "error": "truncated frame"}


def test_a_reply_that_cannot_be_sent_gets_an_error_with_its_id_and_the_loop_goes_on(session, monkeypatch):
    big = {"id": 1, "ok": True, "text": "x" * MAX_REPLY}
    monkeypatch.setattr(serve_module, "handle", lambda message, session: big if message["id"] == 1 else {"id": 2, "ok": True})
    code, out = run_serve(session, {"id": 1, "cmd": "ping"}, {"id": 2, "cmd": "ping"})
    assert code == 0 and out == [{"id": 1, "ok": False, "error": "reply too large"}, {"id": 2, "ok": True}]


def test_a_reply_that_is_not_json_at_all_gets_an_internal_error_and_the_loop_goes_on(session, monkeypatch):
    """A bug in a command must cost one request, not the process: the shell would need seconds to load the models again."""
    monkeypatch.setattr(serve_module, "handle", lambda message, session: {"id": message["id"], "ok": True, "x": {1, 2}} if message["id"] == 1 else {"id": 2, "ok": True})
    code, out = run_serve(session, {"id": 1, "cmd": "ping"}, {"id": 2, "cmd": "ping"})
    assert code == 0 and out == [{"id": 1, "ok": False, "error": "internal error"}, {"id": 2, "ok": True}]


def test_a_reply_with_text_that_is_not_utf8_gets_an_error_without_quoting_it(session, monkeypatch):
    monkeypatch.setattr(serve_module, "handle", lambda message, session: {"id": 1, "ok": True, "text": "ivan\ud800"})
    stdout = io.BytesIO()
    assert serve(io.BytesIO(frames({"id": 1, "cmd": "ping"})), stdout, session) == 0
    assert replies(stdout.getvalue()) == [{"id": 1, "ok": False, "error": "reply is not valid text"}]
    assert b"ivan" not in stdout.getvalue()


DOUBLES = [
    b'{"cmd": "ping", "cmd": "mask", "text": "mail ivan.petrov@acme.com"}',  # the last one used to win: ping was read as mask
    b'{"cmd": "mask", "text": "x", "level": {"a": 1, "a": 2}}',
    b'{"cmd": "ping", "cmd": "ping"}',
]


@pytest.mark.parametrize("body", DOUBLES, ids=["last wins", "inside a value", "the same twice"])
def test_the_browser_host_refuses_a_key_that_stands_twice_as_serve_does(body):
    """The framing is shared: a request that two readers could read in two ways is not read at all."""
    with pytest.raises(ValueError) as caught:
        read_message(io.BytesIO(struct.pack("=I", len(body)) + body))
    assert str(caught.value) == "bad json" and "ivan" not in str(caught.value)


def test_a_key_in_two_different_objects_is_not_a_key_twice():
    body = b'{"cmd": "mask", "a": {"x": 1}, "b": {"x": 2}, "CMD": 3, "list": [{"x": 1}, {"x": 2}]}'
    message = read_message(io.BytesIO(struct.pack("=I", len(body)) + body))
    assert message["a"] == {"x": 1} and message["b"] == {"x": 2} and message["CMD"] == 3


def test_the_browser_host_still_frames_in_native_order_with_its_own_cap():
    """serve shares the framing helpers: the host's defaults must not move."""
    from boxed.native_host import MAX_MESSAGE

    stream = io.BytesIO()
    write_message(stream, {"cmd": "ping"})
    assert struct.unpack("=I", stream.getvalue()[:4])[0] == len(stream.getvalue()) - 4
    stream.seek(0)
    assert read_message(stream) == {"cmd": "ping"}
    with pytest.raises(ValueError, match="too large"):
        read_message(io.BytesIO(struct.pack("=I", MAX_MESSAGE + 1)))


# ---- a process that stays up keeps nothing of a request while it waits for the next one ----


class Held(dict):
    """A message or reply that a test can watch: a plain dict cannot be weakly referenced."""


def test_nothing_of_a_request_or_its_reply_is_held_while_waiting_for_the_next_frame(monkeypatch):
    watched = []

    def read(stream):
        if not watched:  # the first request
            message = Held(id=1, cmd="ping", text="mail ivan@acme.com")
            watched.append(weakref.ref(message))
            return message
        gc.collect()  # from here on the process is waiting for the second request
        assert [ref() for ref in watched] == [None, None], "the request or its answer is still held"
        return None

    def respond(message):
        reply = Held(id=message["id"], ok=True, text=message["text"])
        watched.append(weakref.ref(reply))
        return reply

    monkeypatch.setattr(serve_module, "read_request", read)
    assert serve_module._loop(io.BytesIO(), io.BytesIO(), respond) == 0
    assert len(watched) == 2


# ---- ending: EOF, SIGTERM, a library that cannot forget; stdout is for frames ----


def test_the_process_ends_after_the_answer_when_the_tokenizer_cache_could_not_be_emptied(session, monkeypatch):
    """The only way to forget the words GLiNER's tokenizer cached is to end: the shell starts the program again."""
    monkeypatch.setattr(ner, "words_kept", lambda: True)
    stdin, stdout = io.BytesIO(frames({"id": 1, "cmd": "ping"}, {"id": 2, "cmd": "ping"})), io.BytesIO()
    assert serve(stdin, stdout, session) == 0
    assert [reply["id"] for reply in replies(stdout.getvalue())] == [1]
    assert stdin.read() != b""  # the second request was not read


class FakeStdout:
    def __init__(self) -> None:
        self.buffer = io.BytesIO()


@pytest.fixture
def run_main(capsys, monkeypatch):
    def run(*messages: dict, raw: bytes = b"") -> tuple[int, list[dict], str]:
        stdout = FakeStdout()
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(frames(*messages) + raw)))
        monkeypatch.setattr(sys, "stdout", stdout)
        monkeypatch.setattr(signal, "signal", lambda *args: None)  # the handler of the test runner stays
        code = serve_module.main()
        return code, replies(stdout.buffer.getvalue()), capsys.readouterr().err

    return run


def test_main_serves_stdin_to_stdout(run_main):
    code, out, _ = run_main({"id": 1, "cmd": "ping"}, {"id": 2, "cmd": "ping"})
    assert code == 0 and [reply["id"] for reply in out] == [1, 2]


def test_main_keeps_stdout_for_frames_only(run_main, monkeypatch):
    def noisy(message, session):
        print("noise from a library")
        return {"id": message["id"], "ok": True}

    monkeypatch.setattr(serve_module, "handle", noisy)
    code, out, err = run_main({"id": 1, "cmd": "ping"})
    assert (code, out) == (0, [{"id": 1, "ok": True}])
    assert "noise from a library" in err


def test_main_asks_for_sigterm_and_a_stop_is_not_a_failure(monkeypatch):
    handlers = {}
    monkeypatch.setattr(signal, "signal", lambda number, handler: handlers.setdefault(number, handler))
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO()))
    monkeypatch.setattr(sys, "stdout", FakeStdout())

    def stopped(stream):
        handlers[signal.SIGTERM](signal.SIGTERM, None)  # SIGTERM while the loop waits
        raise AssertionError("not reached")

    monkeypatch.setattr(serve_module, "read_request", stopped)
    assert serve_module.main() == 0


def test_sigterm_in_the_middle_of_a_request_ends_the_process_at_once_without_an_answer(monkeypatch):
    """The app may quit while a request runs, and a request is not waited for: whatever it does is unwound where it stands."""
    handlers = {}
    monkeypatch.setattr(signal, "signal", lambda number, handler: handlers.setdefault(number, handler))
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(frames({"id": 1, "cmd": "ping"}, {"id": 2, "cmd": "ping"}))))
    stdout = FakeStdout()
    monkeypatch.setattr(sys, "stdout", stdout)

    def terminated(message, session):
        handlers[signal.SIGTERM](signal.SIGTERM, None)  # SIGTERM arrives while the request is being answered
        raise AssertionError("the request went on after SIGTERM")

    monkeypatch.setattr(serve_module, "handle", terminated)
    assert serve_module.main() == 0
    assert stdout.buffer.getvalue() == b""  # no answer, and the second request was not read


def test_a_shell_that_is_gone_ends_the_process_quietly(monkeypatch, capsys):
    class Gone:
        def __init__(self) -> None:
            def write(data):
                raise BrokenPipeError(32, "Broken pipe")

            self.buffer = types.SimpleNamespace(write=write, flush=lambda: None)

    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(frames({"id": 1, "cmd": "ping"}))))
    monkeypatch.setattr(sys, "stdout", Gone())
    monkeypatch.setattr(signal, "signal", lambda *args: None)
    assert serve_module.main() == 1
    assert capsys.readouterr().err == ""


def test_the_serve_subcommand_runs_main(monkeypatch):
    from boxed.cli import main as cli_main

    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(frames({"id": 5, "cmd": "ping"}))))
    stdout = FakeStdout()
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(signal, "signal", lambda *args: None)
    assert cli_main(["serve"]) == 0
    [reply] = replies(stdout.buffer.getvalue())
    assert is_ping(reply, 5)


def test_serve_takes_no_arguments_and_is_listed_in_the_help(capsys):
    from boxed.cli import main as cli_main

    with pytest.raises(SystemExit):
        cli_main(["serve", "--port", "1"])
    capsys.readouterr()
    with pytest.raises(SystemExit):
        cli_main(["--help"])
    assert "serve" in capsys.readouterr().out


# The real program on pipes that stay open: what the shell does with a sidecar.

START = "import sys; from boxed.cli import main; sys.exit(main(['serve']))"


class Live:
    def __init__(self, tmp_path, name="live", code=START, env=None) -> None:
        self.errors = open(tmp_path / f"{name}.err", "wb")
        env = {**os.environ, "PYTHON_KEYRING_BACKEND": "keyring.backends.null.Keyring", **(env or {})}  # a program of ours never asks the real keychain
        self.process = subprocess.Popen(
            [sys.executable, "-P", "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.errors, env=env
        )
        self.watchdog = threading.Timer(120, self.process.kill)  # a program that hangs fails the test instead of stopping the run
        self.watchdog.start()

    def send(self, message: dict) -> None:
        self.process.stdin.write(frames(message))
        self.process.stdin.flush()

    def read(self) -> dict | None:
        return read_message(self.process.stdout, MAX_REPLY, "<")

    def ask(self, message: dict) -> dict:
        self.send(message)
        reply = self.read()
        assert reply is not None, "the program ended without answering"
        return reply

    def close(self) -> int:
        """What the shell does when the app quits: close the input."""
        self.process.stdin.close()
        return self.process.wait(timeout=30)


@pytest.fixture
def live(tmp_path):
    started = []

    def start(code=START, env=None) -> Live:
        started.append(Live(tmp_path, f"live{len(started)}", code, env))
        return started[-1]

    yield start
    for one in started:
        one.watchdog.cancel()
        one.process.kill()
        one.process.wait()
        one.process.stdout.close()
        one.errors.close()


NOISY = """
import os, subprocess, sys
from boxed import serve
real = serve.handle
def noisy(message, session):
    os.write(1, b"RAW-WRITE-TO-FD-1\\n")                # a library in C, or os.write(1)
    subprocess.run(["echo", "CHILD-OF-THE-REQUEST"])    # a child inherits descriptor 1
    os.system("echo FROM-A-SHELL")
    sys.stdout.write("PYTHON-PRINT\\n")
    return real(message, session)
serve.handle = noisy
sys.exit(serve.main())
"""


def test_whatever_writes_to_descriptor_1_lands_on_stderr_and_not_between_frames(live, tmp_path):
    """Only sys.stdout was replaced, so os.write(1, ...), a child process or a C library wrote into the pipe of the frames, the
    shell took it for a bad frame and restarted the program."""
    sidecar = live(NOISY)
    assert is_ping(sidecar.ask({"id": 1, "cmd": "ping"}), 1)
    assert sidecar.ask({"id": 2, "cmd": "ping"})["id"] == 2
    assert sidecar.close() == 0
    assert sidecar.read() is None  # nothing on stdout but the two frames, and those were read whole
    noise = (tmp_path / "live0.err").read_text()
    for line in ("RAW-WRITE-TO-FD-1", "CHILD-OF-THE-REQUEST", "FROM-A-SHELL", "PYTHON-PRINT"):
        assert noise.count(line) == 2, line


def test_the_frames_get_a_private_descriptor_that_a_child_does_not_inherit(live, tmp_path):
    code = """
import os, subprocess, sys
from boxed import serve
real = serve.handle
def probe(message, session):
    # the descriptors a child gets: 0, 1, 2 and nothing else (fstat opens none of its own, a directory listing would)
    look = "import os\\nfound = []\\nfor n in range(3, 64):\\n    try:\\n        os.fstat(n)\\n        found.append(n)\\n    except OSError:\\n        pass\\nprint(found)"
    out = subprocess.run([sys.executable, "-c", look], capture_output=True, text=True, close_fds=False)  # only the flag decides
    print("CHILD-SAW", out.stdout.strip())
    return real(message, session)
serve.handle = probe
sys.exit(serve.main())
"""
    sidecar = live(code)
    assert sidecar.ask({"id": 1, "cmd": "ping"})["ok"] is True
    assert sidecar.close() == 0
    seen = [line for line in (tmp_path / "live0.err").read_text().splitlines() if line.startswith("CHILD-SAW")]
    assert seen == ["CHILD-SAW []"]  # not the private copy of the pipe of the frames, nor any other


def test_a_stdout_without_a_descriptor_is_used_as_it_is(monkeypatch):
    stdout = FakeStdout()
    monkeypatch.setattr(sys, "stdout", stdout)
    assert serve_module._claim_stdout() is stdout.buffer


def test_one_process_answers_request_after_request_and_ends_at_eof(live):
    sidecar = live()
    assert is_ping(sidecar.ask({"id": 1, "cmd": "ping"}), 1)
    assert sidecar.ask({"id": 2, "cmd": "ping"})["id"] == 2
    assert sidecar.process.poll() is None  # still there, waiting for the next request
    assert sidecar.close() == 0


def test_the_process_does_not_end_when_nothing_is_asked_for_a_while(live):
    sidecar = live()
    assert sidecar.ask({"id": 1, "cmd": "ping"})["ok"] is True
    time.sleep(2)
    assert sidecar.process.poll() is None
    assert sidecar.ask({"id": 2, "cmd": "ping"})["id"] == 2
    assert sidecar.close() == 0


def test_sigterm_ends_an_idle_process_cleanly(live, tmp_path):
    sidecar = live()
    assert sidecar.ask({"id": 1, "cmd": "ping"})["ok"] is True
    sidecar.process.send_signal(signal.SIGTERM)
    assert sidecar.process.wait(timeout=30) == 0
    assert sidecar.read() is None  # nothing more on stdout
    assert (tmp_path / "live0.err").read_bytes() == b""  # no traceback


def test_a_bad_frame_ends_the_real_process_with_1_after_one_error_frame(live):
    sidecar = live()
    sidecar.process.stdin.write(struct.pack("<I", MAX_REQUEST + 1))
    sidecar.process.stdin.flush()
    assert sidecar.read() == {"id": None, "ok": False, "error": "message too large"}
    assert sidecar.process.wait(timeout=30) == 1


# ---- a parent that has ended: nobody is left to read an answer, and a busy process would hold the vault for the next app ----

not_on_windows = pytest.mark.skipif(IS_WINDOWS, reason="Windows keeps the number of the parent it started with: only EOF ends a process there")


@not_on_windows
def test_a_process_whose_parent_has_ended_stops_after_the_answer_it_was_giving(session, monkeypatch):
    parent = os.getppid()
    real = serve_module.handle

    def answer_and_lose_the_parent(message, session):
        monkeypatch.setattr(os, "getppid", lambda: parent + 1)  # launchd or init adopts a process whose parent has ended
        return real(message, session)

    monkeypatch.setattr(serve_module, "handle", answer_and_lose_the_parent)
    stdin, stdout = io.BytesIO(frames({"id": 1, "cmd": "ping"}, {"id": 2, "cmd": "ping"})), io.BytesIO()
    assert serve(stdin, stdout, session, parent=parent) == 0
    assert [reply["id"] for reply in replies(stdout.getvalue())] == [1]
    assert stdin.read() != b""  # the second request was not read


@not_on_windows
def test_a_process_whose_parent_is_there_goes_on(session):
    stdin, stdout = io.BytesIO(frames({"id": 1, "cmd": "ping"}, {"id": 2, "cmd": "ping"})), io.BytesIO()
    assert serve(stdin, stdout, session, parent=os.getppid()) == 0
    assert [reply["id"] for reply in replies(stdout.getvalue())] == [1, 2]


# The shell between the test and the program: it starts the program on the pipes it was given, writes the number of the program to a file
# and waits for it. The test keeps the other end of the pipe open all along, so the program never reads EOF.
PARENT = """
import os, subprocess, sys
child = subprocess.Popen([sys.executable, "-P", "-c", os.environ["CHILD_CODE"]], stdin=0, stdout=1)
with open(os.environ["CHILD_PIDFILE"], "w") as f:
    f.write(str(child.pid))
child.wait()
"""
HANGS = """
import sys, time
from boxed import serve
serve._COMMANDS["ping"] = (frozenset(), lambda message, session: time.sleep(600))  # a request that never ends
sys.exit(serve.main())
"""


def process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    return bool(state) and not state.startswith("Z")  # a process that ended and is not collected yet is not there


@not_on_windows
@pytest.mark.parametrize("busy", [False, True], ids=["waiting for a request", "in a request that hangs"])
def test_a_process_whose_shell_was_killed_ends_by_itself_though_the_pipe_stays_open(live, tmp_path, busy):
    pidfile = tmp_path / "child.pid"
    shell = live(PARENT, env={"CHILD_CODE": HANGS if busy else START, "CHILD_PIDFILE": str(pidfile)})
    deadline = time.monotonic() + 60
    while not (pidfile.exists() and pidfile.read_text()) and time.monotonic() < deadline:
        time.sleep(0.02)
    pid = int(pidfile.read_text())
    try:
        if busy:
            shell.send({"id": 1, "cmd": "ping"})  # the program takes it and never answers
            time.sleep(1)
        else:
            assert shell.ask({"id": 1, "cmd": "ping"})["ok"] is True  # up, and now waiting for the next request
        shell.process.kill()  # the app is killed: its child is adopted by launchd or init
        shell.process.wait()
        deadline = time.monotonic() + 20
        while process_alive(pid) and time.monotonic() < deadline:
            time.sleep(0.1)
        assert not process_alive(pid), "the program outlived its parent"
    finally:
        if process_alive(pid):
            os.kill(pid, signal.SIGKILL)


# ---- mask and restore: the same text, scope, level, journal record and refusals as boxed mask and boxed restore ----

TEXT = "mail ivan.petrov@acme.com, key AKIAIOSFODNN7EXAMPLE, call +7 (912) 345-67-89"
MASKED = "mail [EMAIL_1], key [SECRET_1], call [PHONE_1]"
VALUES = ["ivan.petrov@acme.com", "AKIAIOSFODNN7EXAMPLE", "+7 (912) 345-67-89", "345-67-89"]
REFUSAL_LEVEL_4 = "level 4 sends the task and the table schema only: use boxed plan, or ask at a level from 0 to 3"


def request(session, cmd, **fields):
    return handle({"id": 1, "cmd": cmd, **fields}, session)


def journal_of(boxed_env):
    path = boxed_env / "journal.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def same_record(record, scope="*"):
    """A journal record without what differs by nature between two runs: the number, the time, the chain and the scope."""
    return {k: v for k, v in record.items() if k not in ("seq", "ts", "prev_hash", "hash", "sig")} | {"scope": scope}


def test_mask_returns_the_text_the_scope_the_level_and_the_counts(session):
    reply = request(session, "mask", text=TEXT, scope="web-test", level=2)
    assert reply == {
        "id": 1,
        "ok": True,
        "text": MASKED,
        "scope": "web-test",
        "level": 2,
        "markers_by_kind": {"EMAIL": 1, "SECRET": 1, "PHONE": 1},
    }


def test_restore_returns_the_text_and_what_it_could_not_put_back(session):
    request(session, "mask", text=TEXT, scope="s")
    answer = "Write to [EMAIL_1] about [SECRET_1] and [PHONE_1]; not [EMAIL_9], and [EMAIL-1] is odd."
    reply = request(session, "restore", text=answer, scope="s")
    assert reply == {
        "id": 1,
        "ok": True,
        "text": "Write to ivan.petrov@acme.com about AKIAIOSFODNN7EXAMPLE and +7 (912) 345-67-89; not [EMAIL_9], and [EMAIL-1] is odd.",
        "unknown": ["[EMAIL_9]"],
        "suspicious": ["[EMAIL-1]"],
        "restored": 3,
    }


def test_the_same_scope_keeps_its_numbering_across_requests(session):
    first = request(session, "mask", text="a@x.io b@x.io", scope="s")
    second = request(session, "mask", text="b@x.io c@x.io", scope="s")
    assert first["text"] == "[EMAIL_1] [EMAIL_2]" and second["text"] == "[EMAIL_2] [EMAIL_3]"


def test_mask_without_a_scope_names_one_by_the_utc_second(session):
    reply = request(session, "mask", text="mail a@x.io")
    assert re.fullmatch(r"manual-\d{8}T\d{6}", reply["scope"])
    assert session.context().vault.scopes() == [reply["scope"]]


@pytest.mark.parametrize(("configured", "used"), [(0, 0), (1, 1), (2, 2), (3, 3)])
def test_mask_without_a_level_uses_the_level_of_boxed_toml_in_the_boxed_home(boxed_env, session, configured, used):
    boxed_env.mkdir(parents=True)
    (boxed_env / "boxed.toml").write_text(f"[boxed]\nlevel = {configured}\n")
    reply = request(session, "mask", text=TEXT, scope="s")
    assert reply["level"] == used and journal_of(boxed_env)[-1]["level"] == used


def test_mask_without_boxed_toml_uses_level_2(boxed_env, session):
    assert request(session, "mask", text=TEXT, scope="s")["level"] == 2


@pytest.mark.parametrize("level", [0, 1, 2, 3])
def test_a_level_in_the_request_wins_over_boxed_toml(boxed_env, session, level):
    boxed_env.mkdir(parents=True)
    (boxed_env / "boxed.toml").write_text("[boxed]\nlevel = 4\n")
    assert request(session, "mask", text=TEXT, scope="s", level=level)["level"] == level
    assert journal_of(boxed_env)[-1]["level"] == level


def test_level_4_is_refused_in_the_words_ask_uses_and_nothing_is_made(boxed_env, session):
    assert request(session, "mask", text=TEXT, level=4) == {"id": 1, "ok": False, "error": REFUSAL_LEVEL_4}
    boxed_env.mkdir(parents=True)
    (boxed_env / "boxed.toml").write_text("[boxed]\nlevel = 4\n")
    assert request(session, "mask", text=TEXT) == {"id": 1, "ok": False, "error": REFUSAL_LEVEL_4}
    assert sorted(path.name for path in boxed_env.iterdir()) == ["boxed.toml"]  # no vault, no journal, no key


def test_a_broken_key_store_does_not_replace_the_level_refusal(boxed_env, session, monkeypatch):
    def broken():
        raise RuntimeError("no keyring backend")

    monkeypatch.setattr("boxed.cli.default_keystore", broken)
    assert request(session, "mask", text=TEXT, level=4)["error"] == REFUSAL_LEVEL_4
    assert not boxed_env.exists()


BAD_MASK = [
    {},
    {"text": 5},
    {"text": None},
    {"text": "x", "level": 5},
    {"text": "x", "level": -1},
    {"text": "x", "level": True},
    {"text": "x", "level": "2"},
    {"text": "x", "level": 1.0},
    {"text": "x", "scope": ""},
    {"text": "x", "scope": 5},
    {"text": "x", "scope": "a" * 65},
    {"text": "x", "scope": "a b"},
    {"text": "x", "scope": "a@b.io"},
    {"text": "x", "scope": ".hidden"},
    {"text": "x", "scope": "web-1\n"},
    {"text": "x", "colour": "red"},
    {"text": "lone \ud800 surrogate"},
]


@pytest.mark.parametrize("fields", BAD_MASK, ids=[json.dumps(m)[:50] for m in BAD_MASK])
def test_mask_refuses_what_is_not_a_request_before_anything_is_made(boxed_env, session, fields):
    assert request(session, "mask", **fields) == {"id": 1, "ok": False, "error": "bad request"}
    assert not boxed_env.exists()


BAD_RESTORE = [
    {"scope": "s"},
    {"text": "x"},
    {"text": 5, "scope": "s"},
    {"text": "x", "scope": None},
    {"text": "x", "scope": "a b"},
    {"text": "x", "scope": "s", "level": 2},
    {"text": "x", "scope": "s", "force": True},
    {"text": "lone \ud800 surrogate", "scope": "s"},
]


@pytest.mark.parametrize("fields", BAD_RESTORE, ids=[json.dumps(m)[:50] for m in BAD_RESTORE])
def test_restore_refuses_what_is_not_a_request_before_anything_is_made(boxed_env, session, fields):
    assert request(session, "restore", **fields) == {"id": 1, "ok": False, "error": "bad request"}
    assert not boxed_env.exists()


def test_restore_of_an_unknown_scope_is_refused_and_not_journaled(boxed_env, session):
    request(session, "mask", text=TEXT, scope="web-test")
    assert request(session, "restore", text="[EMAIL_1]", scope="web-other") == {"id": 1, "ok": False, "error": "unknown scope"}
    assert [e["status"] for e in journal_of(boxed_env)] == ["prepared"]


def test_a_scope_that_cannot_be_decrypted_is_a_fixed_error_that_does_not_name_it(boxed_env, session):
    request(session, "mask", text=TEXT, scope="ivan.petrov")
    with closing(sqlite3.connect(boxed_env / "vault.db")) as db, db:
        db.execute("UPDATE maps SET ciphertext = ?", (b"not what was stored",))  # tampered data: the tag will not fit
    reply = request(session, "restore", text="[EMAIL_1]", scope="ivan.petrov")
    assert reply == {"id": 1, "ok": False, "error": "cannot decrypt the scope: wrong key or tampered data"}
    assert request(session, "mask", text="x", scope="ivan.petrov")["error"] == reply["error"]
    assert [e["status"] for e in journal_of(boxed_env)] == ["prepared"]  # nothing was recorded for the refusals


def test_mask_and_restore_are_journaled_like_the_command_line_does(boxed_env, session):
    reply = request(session, "mask", text=TEXT, scope="web-test", level=1)
    request(session, "restore", text="Mail [EMAIL_1] [EMAIL_9]", scope="web-test")
    prepared, received = journal_of(boxed_env)
    assert (prepared["channel"], prepared["provider"], prepared["account_type"]) == ("manual", "unknown", "unknown")
    assert (prepared["status"], prepared["level"], prepared["scope"], prepared["coverage"]) == ("prepared", 1, "web-test", "full")
    assert prepared["markers_by_kind"] == reply["markers_by_kind"] and prepared["versions"] == {"boxed": __version__}
    assert prepared["payload_sha256"] == hashlib.sha256(reply["text"].encode()).hexdigest()
    assert (received["channel"], received["status"], received["level"], received["markers_by_kind"]) == ("manual", "received", -1, {})
    assert received["payload_sha256"] == hashlib.sha256(b"Mail [EMAIL_1] [EMAIL_9]").hexdigest()
    assert received["note"] == "restored=1 unknown=1 suspicious=0"
    assert Journal(boxed_env / "journal.jsonl", default_keystore()).verify().ok


COMPARED = {
    "plain": "hello world",
    "email key phone": TEXT,
    "cyrillic": "Привет, Иван Петров: ivan@acme.com, ИНН 7707083893",
    "amounts dates percent": "Pay 1 234,50 EUR by 2026-10-31 (12%) to Acme Corp",
    "marker-like": "keep [EMAIL_7] and [CLIENT_1] as they are, mail a@x.io, [email_7]",
    "crlf and tabs": "a@x.io\r\nb@x.io\t c@x.io\r\n",
    "empty": "",
}


def run_cli(capsys, monkeypatch, argv, stdin=None):
    if stdin is not None:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    code = cli_main(argv)
    out, err = capsys.readouterr()
    return code, out, err


@pytest.fixture
def same_config(boxed_env, monkeypatch):
    """The command line finds boxed.toml from the folder it runs in, serve in the boxed home: one folder for both."""
    boxed_env.mkdir(parents=True, exist_ok=True)
    (boxed_env / "boxed.toml").write_text('[boxed]\nlevel = 2\n[boxed.dictionary]\n"Acme Corp" = "CLIENT"\n')
    monkeypatch.chdir(boxed_env)
    return boxed_env


@pytest.mark.parametrize("level", [0, 1, 2, 3])
@pytest.mark.parametrize("text", COMPARED.values(), ids=COMPARED.keys())
def test_mask_gives_what_boxed_mask_gives_and_journals_the_same(same_config, session, capsys, monkeypatch, text, level):
    code, out, err = run_cli(capsys, monkeypatch, ["mask", "--scope", "c1", "--level", str(level), "-"], stdin=text)
    reply = request(session, "mask", text=text, scope="s1", level=level)
    assert code == 0 and reply["ok"] is True
    assert reply["text"] == out and err == "scope: c1\n"
    by_cli, by_serve = journal_of(same_config)
    assert same_record(by_cli) == same_record(by_serve)
    assert reply["markers_by_kind"] == by_serve["markers_by_kind"]


@pytest.mark.parametrize("answer", ["see [EMAIL_1] and [EMAIL_9]", "[EMAIL-1] and [email_1]", "nothing to put back", "[EMAIL_1][SECRET_1]"])
def test_restore_gives_what_boxed_restore_gives_and_journals_the_same(same_config, session, capsys, monkeypatch, answer):
    run_cli(capsys, monkeypatch, ["mask", "--scope", "c1", "-"], stdin=TEXT)
    request(session, "mask", text=TEXT, scope="s1")
    code, out, err = run_cli(capsys, monkeypatch, ["restore", "--scope", "c1", "--force", "-"], stdin=answer)
    reply = request(session, "restore", text=answer, scope="s1")
    assert code == 0 and reply["ok"] is True
    assert reply["text"] == out  # the command line prints the text with --force, the shell always gets it
    shown = ", ".join(reply["unknown"] + reply["suspicious"])
    assert err == (f"not restored, check by hand: {shown}\n" if shown else "")
    cli_records = [r for r in journal_of(same_config) if r["status"] == "received"]
    assert len(cli_records) == 2 and same_record(cli_records[0]) == same_record(cli_records[1])


def test_the_dictionary_of_boxed_toml_applies_to_mask_and_restore(boxed_env, session):
    boxed_env.mkdir(parents=True)
    (boxed_env / "boxed.toml").write_text('[boxed.dictionary]\n"Acme Corp" = "CLIENT"\n')
    assert request(session, "mask", text="Offer for Acme Corp", scope="s")["text"] == "Offer for [CLIENT_1]"
    request(session, "mask", text="a@x.io", scope="t")  # a map without any CLIENT yet
    assert request(session, "restore", text="Dear [CLIENT_1]", scope="t")["unknown"] == ["[CLIENT_1]"]


def test_boxed_toml_is_read_again_for_each_request(boxed_env, session):
    ask = {"text": "Offer for Acme Corp to a@x.io", "scope": "s"}
    boxed_env.mkdir(parents=True)
    assert request(session, "mask", **ask)["text"] == "Offer for Acme Corp to [EMAIL_1]"
    (boxed_env / "boxed.toml").write_text('[boxed.dictionary]\n"Acme Corp" = "CLIENT"\n')
    assert request(session, "mask", **ask)["text"] == "Offer for [CLIENT_1] to [EMAIL_1]"
    (boxed_env / "boxed.toml").write_text("[boxed]\n")
    assert request(session, "mask", **ask)["text"] == "Offer for Acme Corp to [EMAIL_1]"


def test_only_boxed_toml_of_the_boxed_home_counts_not_one_in_the_folder_the_program_runs_in(boxed_env, session, tmp_path, monkeypatch):
    (tmp_path / "boxed.toml").write_text('[boxed]\nallow = ["ivan@acme.com"]\nlevel = 0\n')
    monkeypatch.chdir(tmp_path)
    reply = request(session, "mask", text="mail ivan@acme.com", scope="s")
    assert reply["text"] == "mail [EMAIL_1]" and reply["level"] == 2


def test_a_boxed_toml_that_cannot_be_read_stops_the_commands_that_need_it_until_it_is_mended(boxed_env, session):
    assert request(session, "mask", text="a@x.io", scope="s")["ok"] is True  # a scope for restore to find
    (boxed_env / "boxed.toml").write_text('[boxed\ndictionary = {"Acme Corp"')
    expected = {"id": 1, "ok": False, "error": "boxed.toml cannot be read"}
    assert request(session, "mask", text="Offer for Acme Corp", scope="s") == expected
    assert request(session, "restore", text="x", scope="s") == expected
    assert request(session, "ping")["ok"] is True  # it does not depend on the settings
    (boxed_env / "boxed.toml").write_text("[boxed]\n")
    assert request(session, "mask", text="a@x.io", scope="s")["ok"] is True
    assert (boxed_env / "host-errors.log").read_text().count("cannot read boxed.toml: ") == 2
    assert "Acme" not in (boxed_env / "host-errors.log").read_text()


def test_the_data_folder_is_not_opened_by_a_request_that_does_not_need_it(boxed_env, session):
    request(session, "ping")
    request(session, "mask", text="x", level=4)
    request(session, "nope")
    assert not boxed_env.exists()


def test_a_key_store_that_cannot_be_opened_is_a_fixed_error_and_is_tried_again(boxed_env, session, monkeypatch):
    calls = []

    def broken():
        calls.append(1)
        raise RuntimeError("keychain is locked for ivan.petrov@acme.com")

    expected = {"id": 1, "ok": False, "error": "the boxed data folder or the key store cannot be opened"}
    with monkeypatch.context() as locked:  # only this change is taken back: the folder and the keys of the test stay as they were
        locked.setattr("boxed.cli.default_keystore", broken)
        assert request(session, "mask", text=TEXT, scope="s") == expected
        assert request(session, "restore", text="x", scope="s") == expected
    assert len(calls) == 2  # the failure is not remembered: the person unlocks the keychain and goes on
    assert request(session, "mask", text=TEXT, scope="s")["ok"] is True
    log = (boxed_env / "host-errors.log").read_text()
    assert "cannot open the key store: RuntimeError" in log and "ivan" not in log and "keychain" not in log


def test_the_journal_is_written_before_the_reply_leaves(session, monkeypatch):
    events = []
    real = Journal.append

    def spy(self, entry):
        events.append("journal")
        return real(self, entry)

    class Recording(io.BytesIO):
        def write(self, data):
            events.append("reply")
            return super().write(data)

    monkeypatch.setattr(Journal, "append", spy)
    stdin = io.BytesIO(frames({"id": 1, "cmd": "mask", "text": TEXT, "scope": "s"}, {"id": 2, "cmd": "restore", "text": MASKED, "scope": "s"}))
    assert serve(stdin, Recording(), session) == 0
    assert events == ["journal", "reply", "journal", "reply"]


@pytest.mark.parametrize("command", ["mask", "restore"])
def test_when_the_journal_cannot_be_written_no_text_leaves(boxed_env, session, command):
    request(session, "mask", text=TEXT, scope="s")
    (boxed_env / "journal.jsonl").unlink()
    (boxed_env / "journal.jsonl").mkdir()  # the journal cannot be written
    fields = {"text": TEXT, "scope": "s"} if command == "mask" else {"text": MASKED, "scope": "s"}
    reply = request(session, command, **fields)
    assert reply == {"id": 1, "ok": False, "error": "the journal file is not a regular file"}
    assert all(value not in json.dumps(reply) for value in VALUES)


def test_a_mask_reply_that_cannot_be_sent_saves_nothing_and_journals_nothing(boxed_env, session, monkeypatch):
    monkeypatch.setattr(serve_module, "MAX_REPLY", 2000)
    reply = request(session, "mask", text="[IP_1]" * 400, scope="s")  # six bytes become eleven
    assert reply == {"id": 1, "ok": False, "error": "reply too large"}
    assert session.context().vault.scopes() == [] and journal_of(boxed_env) == []


def test_a_restore_reply_that_cannot_be_sent_is_not_journaled(boxed_env, session):
    with session.context().vault.transaction("s") as markers:
        markers.marker_for("SECRET", "x" * 1024 * 1024)
    reply = request(session, "restore", text="[SECRET_1]" * 17, scope="s")  # 17 MiB of originals
    assert reply == {"id": 1, "ok": False, "error": "reply too large"}
    assert journal_of(boxed_env) == []


def test_errors_and_journal_hold_no_values(boxed_env, session, monkeypatch):
    ok = request(session, "mask", text=TEXT, scope="web-test")
    assert request(session, "restore", text=ok["text"], scope="web-test")["text"] == TEXT  # the originals come back in the reply only
    errors = [
        request(session, "restore", text=TEXT, scope="web-other"),
        request(session, "mask", text=TEXT, level="AKIAIOSFODNN7EXAMPLE"),
        request(session, "mask", text=TEXT, scope="ivan.petrov@acme.com"),
        request(session, "mask", text=TEXT, level=4),
        handle({"id": 1, "cmd": TEXT}, session),
        handle({"id": 1, "cmd": "mask", "text": TEXT, "AKIAIOSFODNN7EXAMPLE": 1}, session),
    ]

    def boom(*args, **kwargs):
        raise RuntimeError(TEXT)

    with monkeypatch.context() as failing:
        failing.setattr(serve_module, "mask_text", boom)
        errors.append(request(session, "mask", text=TEXT, scope="web-test"))
    assert all(e["ok"] is False for e in errors) and errors[-1]["error"] == "internal error"
    blob = json.dumps(errors) + (boxed_env / "journal.jsonl").read_text()
    for value in VALUES:
        assert value not in blob


def test_an_internal_error_leaves_one_line_with_the_class_name_and_nothing_else(boxed_env, session, monkeypatch):
    def boom(*args, **kwargs):
        try:
            raise ValueError(TEXT)
        except ValueError as cause:
            raise KeyError(TEXT, {"text": TEXT}) from cause

    monkeypatch.setattr(serve_module, "mask_text", boom)
    assert request(session, "mask", text=TEXT, scope="s") == {"id": 1, "ok": False, "error": "internal error"}
    (line,) = (boxed_env / "host-errors.log").read_text().splitlines()
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00 internal error: KeyError", line)
    assert stat.S_IMODE((boxed_env / "host-errors.log").stat().st_mode) == 0o600
    assert session.context().vault.scopes() == [] and journal_of(boxed_env) == []  # the map is saved only when the masking worked


UNIQUE = "zebra-unicorn-4711"  # a word no detector touches: it travels through mask and restore unchanged


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


def test_the_session_and_the_modules_hold_no_text_after_the_requests(session):
    stdin = io.BytesIO(
        frames(
            {"id": 1, "cmd": "mask", "text": f"{TEXT} {UNIQUE}", "scope": "s"},
            {"id": 2, "cmd": "restore", "text": f"mail [EMAIL_1] {UNIQUE}", "scope": "s"},
        )
    )
    assert serve(stdin, io.BytesIO(), session) == 0
    stdin = None
    gc.collect()
    modules = [vars(module) for name, module in list(sys.modules.items()) if name.startswith("boxed") and module is not None]
    for needle in [*VALUES, UNIQUE, "ivan"]:
        for place, root in (("the session", session), ("the modules", modules)):
            held = [s for s in held_strings(root) if (needle in s if isinstance(s, str) else needle.encode() in s)]
            assert not held, f"{needle!r} is still held in {place}"


def test_the_language_model_loads_once_for_a_process_that_stays_up(boxed_env, session, monkeypatch):
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
        boxed_env.mkdir(parents=True)
        (boxed_env / "boxed.toml").write_text('[boxed]\nner = ["ru"]\n')
        code, out = run_serve(session, *[{"id": i, "cmd": "mask", "text": TEXT, "scope": "s"} for i in range(3)])
        assert code == 0 and len(loads) == 1 and all(reply["ok"] for reply in out)
    finally:
        config._ner_detectors.cache_clear()  # the stand-in must not reach another test


@pytest.fixture(autouse=True)
def no_other_gliner(monkeypatch):
    """A GLiNER detector that another test left alive must not make a process here end after its first answer."""
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


def test_the_tokenizer_cache_is_emptied_after_each_text_and_the_process_stays_up(boxed_env, session, gliner_stand_in):
    emptied = gliner_stand_in(can_empty=True)
    boxed_env.mkdir(parents=True)
    (boxed_env / "boxed.toml").write_text('[boxed]\nner = ["en"]\n')
    code, out = run_serve(session, *[{"id": i, "cmd": "mask", "text": TEXT, "scope": "s"} for i in range(3)], {"id": 9, "cmd": "ping"})
    assert code == 0 and [reply["ok"] for reply in out] == [True] * 4
    assert len(emptied) == 3  # once for every text that was read


def test_a_process_that_cannot_empty_the_tokenizer_cache_ends_after_the_answer_that_used_it(boxed_env, session, gliner_stand_in):
    gliner_stand_in(can_empty=False)
    boxed_env.mkdir(parents=True)
    (boxed_env / "boxed.toml").write_text('[boxed]\nner = ["en"]\n')
    mask = {"id": 2, "cmd": "mask", "text": TEXT, "scope": "s"}
    stdin, stdout = io.BytesIO(frames({"id": 1, "cmd": "ping"}, mask, {**mask, "id": 3}, {"id": 4, "cmd": "ping"})), io.BytesIO()
    assert serve(stdin, stdout, session) == 0
    ping, masked = replies(stdout.getvalue())  # the ping before the first use of GLiNER did not end the process, the mask did
    assert ping["ok"] is True and masked["text"] == MASKED
    assert stdin.read() != b""  # the requests after it were not read: the shell starts the program again for them


# ---- mask-file and restore-file: a clean copy and a restored copy, written by the safe writer ----

CLIENTS = "name,email\nIvan,ivan.petrov@acme.com\n"
NOTES = b"my notes, not boxed output\n"


@pytest.fixture
def home(boxed_env, session):
    """A boxed home with a journal, a vault and a key: what a person who has used boxed has."""
    assert request(session, "mask", text="mail ivan@acme.com", scope="d1")["ok"] is True
    return boxed_env


SALES = "client;region;revenue;day\nRomashka;EU;1 234,50;21.10.2026\nLutik;US;99,5;22.10.2026\nRomashka;EU;10,00;23.10.2026\n"
PLAN = (
    '{"version": 1, "steps": [{"op": "group", "by": ["client"], "aggregates": {"total": ["sum", "revenue"]}}, '
    '{"op": "chart", "kind": "bar", "x": "client", "y": "total"}]}'
)


@pytest.fixture
def world(tmp_path, home, capsys, monkeypatch):
    """A file to mask, and a masked file with its scope (f1), a table with the scope of its plan prompt (p1) and a plan file,
    all made by the command line."""
    monkeypatch.chdir(tmp_path)
    src, masked, table, plan = (tmp_path / name for name in ("clients.csv", "masked.csv", "sales.csv", "plan.json"))
    src.write_text(CLIENTS)
    table.write_text(SALES)
    plan.write_text(PLAN)
    assert cli_main(["mask-file", "--scope", "f1", str(src), str(masked)]) == 0
    assert cli_main(["plan", "prompt", "--task", "top clients", "--scope", "p1", str(table)]) == 0
    capsys.readouterr()
    return types.SimpleNamespace(src=src, masked=masked, table=table, plan=plan, folder=tmp_path)


def mask_file(session, world, dest, **fields):
    return request(session, "mask-file", src=str(world.src), dest=str(dest), **fields)


def restore_file(session, world, dest, **fields):
    return request(session, "restore-file", src=str(world.masked), dest=str(dest), scope="f1", **fields)


def report_lines(report: dict, name: str) -> str:
    """What the command line prints for a report: boxed.cli's own function on the report the shell gets."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        cli_module._print_report(FileReport(**report), name)
    return out.getvalue()


def test_mask_file_writes_the_clean_copy_and_reports_what_was_checked(world, session):
    dest = world.folder / "out.csv"
    reply = mask_file(session, world, dest, scope="f2")
    assert reply == {
        "id": 1,
        "ok": True,
        "scope": "f2",
        "level": 2,
        "report": {
            "source": "clients.csv",
            "output": "out.csv",
            "format": "csv",
            "checked": reply["report"]["checked"],
            "dropped": [],
            "markers_by_kind": {"EMAIL": 1},
            "complete": True,
        },
    }
    assert reply["report"]["checked"] and dest.read_text() == "name,email\nIvan,[EMAIL_1]\n"
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600


def test_mask_file_gives_what_boxed_mask_file_gives_and_journals_the_same(world, home, session, capsys, tmp_path):
    (tmp_path / "by-cli").mkdir()
    (tmp_path / "by-serve").mkdir()
    code, out, err = run_cli(capsys, None, ["mask-file", "--scope", "c2", str(world.src), str(tmp_path / "by-cli" / "out.csv")])
    reply = mask_file(session, world, tmp_path / "by-serve" / "out.csv", scope="s2")
    assert code == 0 and reply["ok"] is True and err == "scope: c2\n"
    assert report_lines(reply["report"], reply["report"]["output"]) == out
    assert (tmp_path / "by-serve" / "out.csv").read_bytes() == (tmp_path / "by-cli" / "out.csv").read_bytes()
    by_cli, by_serve = [r for r in journal_of(home) if r["scope"] in ("c2", "s2")]
    assert same_record(by_cli) == same_record(by_serve)
    assert by_serve["status"] == "prepared" and by_serve["coverage"] == "csv file, complete"


def test_restore_file_writes_the_original_back_and_reports(world, session):
    dest = world.folder / "back.csv"
    reply = restore_file(session, world, dest)
    assert reply["ok"] is True and reply["scope"] == "f1" and reply["anomalies"] == []
    assert reply["report"]["markers_by_kind"] == {"EMAIL": 1} and reply["report"]["complete"] is True
    assert dest.read_text() == CLIENTS


def test_restore_file_gives_what_boxed_restore_file_gives_and_journals_the_same(world, home, session, capsys, tmp_path):
    (tmp_path / "by-cli").mkdir()
    (tmp_path / "by-serve").mkdir()
    code, out, err = run_cli(capsys, None, ["restore-file", "--scope", "f1", str(world.masked), str(tmp_path / "by-cli" / "back.csv")])
    reply = restore_file(session, world, tmp_path / "by-serve" / "back.csv")
    assert code == 0 and reply["ok"] is True and err == ""
    assert report_lines(reply["report"], "back.csv") == out
    assert (tmp_path / "by-serve" / "back.csv").read_bytes() == (tmp_path / "by-cli" / "back.csv").read_bytes()
    by_cli, by_serve = [r for r in journal_of(home) if r["status"] == "received"]
    assert same_record(by_cli) == same_record(by_serve) and by_serve["level"] == -1


def test_restore_file_refuses_markers_it_cannot_restore_unless_forced_and_writes_nothing(world, session, home):
    answer, dest = world.folder / "answer.csv", world.folder / "out.csv"
    answer.write_text("email\n[EMAIL_9]\n[EMAIL-1]\n")
    before = journal_of(home)
    reply = request(session, "restore-file", src=str(answer), dest=str(dest), scope="f1")
    assert reply == {"id": 1, "ok": False, "error": "not restored, check by hand", "anomalies": ["[EMAIL_9]", "[EMAIL-1]"]}
    assert not dest.exists() and hidden(world.folder) == [] and journal_of(home) == before  # nothing written, nothing recorded
    reply = request(session, "restore-file", src=str(answer), dest=str(dest), scope="f1", force=True)
    assert reply["ok"] is True and reply["anomalies"] == ["[EMAIL_9]", "[EMAIL-1]"]
    assert dest.read_text() == "email\n[EMAIL_9]\n[EMAIL-1]\n" and journal_of(home)[-1]["status"] == "received"


def test_force_does_not_replace_a_file_and_replace_does_not_lift_the_check_of_the_markers(world, session):
    answer, dest = world.folder / "answer.csv", world.folder / "out.csv"
    answer.write_text("email\n[EMAIL_9]\n")
    dest.write_bytes(NOTES)
    fields = {"src": str(answer), "dest": str(dest), "scope": "f1"}
    assert request(session, "restore-file", **fields, force=True)["error"] == EXISTS  # each flag for its own question
    reply = request(session, "restore-file", **fields, replace=True)
    assert reply["error"] == "not restored, check by hand" and dest.read_bytes() == NOTES
    assert request(session, "restore-file", **fields, replace=True, force=True)["ok"] is True
    assert dest.read_text() == "email\n[EMAIL_9]\n"


def test_restore_file_of_an_unknown_scope_is_refused_before_anything_is_made(world, session):
    dest = world.folder / "out.csv"
    reply = request(session, "restore-file", src=str(world.masked), dest=str(dest), scope="nope")
    assert reply == {"id": 1, "ok": False, "error": "unknown scope"} and not dest.exists()


def test_mask_file_refuses_level_4_and_nothing_is_made(boxed_env, tmp_path, session):
    src, dest = tmp_path / "in.csv", tmp_path / "out.csv"
    src.write_text(CLIENTS)
    assert request(session, "mask-file", src=str(src), dest=str(dest), level=4) == {"id": 1, "ok": False, "error": REFUSAL_LEVEL_4}
    boxed_env.mkdir(parents=True)
    (boxed_env / "boxed.toml").write_text("[boxed]\nlevel = 4\n")
    assert request(session, "mask-file", src=str(src), dest=str(dest)) == {"id": 1, "ok": False, "error": REFUSAL_LEVEL_4}
    assert sorted(path.name for path in boxed_env.iterdir()) == ["boxed.toml"] and not dest.exists()  # no vault, no journal, no key


def test_a_level_from_0_to_3_overrides_level_4_in_boxed_toml_for_mask_file(boxed_env, tmp_path, session):
    boxed_env.mkdir(parents=True)
    (boxed_env / "boxed.toml").write_text("[boxed]\nlevel = 4\n")
    src = tmp_path / "in.csv"
    src.write_text(CLIENTS)
    assert request(session, "mask-file", src=str(src), dest=str(tmp_path / "out.csv"), level=3)["level"] == 3
    assert journal_of(boxed_env)[-1]["level"] == 3


def test_mask_file_without_a_scope_names_one(world, session):
    reply = mask_file(session, world, world.folder / "out.csv")
    assert re.fullmatch(r"file-\d{8}T\d{6}", reply["scope"])


BAD_FILE_REQUESTS = [
    {},
    {"src": "/x/a.csv"},
    {"dest": "/x/b.csv"},
    {"src": "a.csv", "dest": "/x/b.csv"},  # not absolute
    {"src": "/x/a.csv", "dest": "b.csv"},
    {"src": "~/a.csv", "dest": "/x/b.csv"},
    {"src": "", "dest": "/x/b.csv"},
    {"src": 5, "dest": "/x/b.csv"},
    {"src": ["/x/a.csv"], "dest": "/x/b.csv"},
    {"src": "/x/a\x00.csv", "dest": "/x/b.csv"},
    {"src": "/x/" + "a" * 5000, "dest": "/x/b.csv"},
    {"src": "/x/a\ud800.csv", "dest": "/x/b.csv"},
    {"src": "/x/a.csv", "dest": "/x/b.csv", "replace": "yes"},
    {"src": "/x/a.csv", "dest": "/x/b.csv", "replace": 1},
    {"src": "/x/a.csv", "dest": "/x/b.csv", "force": True},  # only restore-file has force
    {"src": "/x/a.csv", "dest": "/x/b.csv", "level": 9},
    {"src": "/x/a.csv", "dest": "/x/b.csv", "scope": "a b"},
    {"src": "/x/a.csv", "dest": "/x/b.csv", "text": "x"},
]


@pytest.mark.parametrize("fields", BAD_FILE_REQUESTS, ids=[json.dumps(m)[:60] for m in BAD_FILE_REQUESTS])
def test_mask_file_refuses_what_is_not_a_request_before_anything_is_made(boxed_env, session, fields):
    assert request(session, "mask-file", **fields) == {"id": 1, "ok": False, "error": "bad request"}
    assert not boxed_env.exists()


BAD_RESTORE_FILE_REQUESTS = [
    {"src": "/x/a.csv", "dest": "/x/b.csv"},  # the scope is required
    {"src": "/x/a.csv", "dest": "/x/b.csv", "scope": None},
    {"src": "/x/a.csv", "dest": "/x/b.csv", "scope": "s", "level": 2},
    {"src": "/x/a.csv", "dest": "/x/b.csv", "scope": "s", "force": "yes"},
    {"src": "/x/a.csv", "dest": "/x/b.csv", "scope": "s", "replace": None, "force": 0},
    {"src": "a.csv", "dest": "/x/b.csv", "scope": "s"},
]


@pytest.mark.parametrize("fields", BAD_RESTORE_FILE_REQUESTS, ids=[json.dumps(m)[:60] for m in BAD_RESTORE_FILE_REQUESTS])
def test_restore_file_refuses_what_is_not_a_request_before_anything_is_made(boxed_env, session, fields):
    assert request(session, "restore-file", **fields) == {"id": 1, "ok": False, "error": "bad request"}
    assert not boxed_env.exists()


def test_the_source_must_be_a_plain_file_that_is_there_and_not_too_large(world, session, monkeypatch):
    dest = world.folder / "out.csv"
    reply = request(session, "mask-file", src=str(world.folder / "missing.csv"), dest=str(dest))
    assert reply == {"id": 1, "ok": False, "error": "the file was not found"}
    reply = request(session, "mask-file", src=str(world.folder / "missing" / "x.csv"), dest=str(dest))
    assert reply["error"] == "the file was not found"
    (world.folder / "folder.csv").mkdir()
    assert request(session, "mask-file", src=str(world.folder / "folder.csv"), dest=str(dest))["error"] == "the path is not a plain file"
    monkeypatch.setattr(serve_module, "MAX_FILE", 10)
    assert request(session, "mask-file", src=str(world.src), dest=str(dest))["error"] == "the file is larger than 16 MiB"
    assert request(session, "restore-file", src=str(world.masked), dest=str(dest), scope="f1")["error"] == "the file is larger than 16 MiB"
    assert not dest.exists()


def test_a_pipe_as_the_source_is_refused_and_not_waited_for(world, session):
    pipe = world.folder / "pipe.csv"
    os.mkfifo(pipe)
    reply = finishes(lambda: request(session, "mask-file", src=str(pipe), dest=str(world.folder / "out.csv")))
    assert reply["error"] == "the path is not a plain file"


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads a file whatever its mode")
def test_a_source_that_cannot_be_read_gets_a_fixed_text_without_the_path(world, session):
    locked = world.folder / "locked.csv"
    locked.write_text(CLIENTS)
    locked.chmod(0)
    try:
        reply = request(session, "mask-file", src=str(locked), dest=str(world.folder / "out.csv"))
    finally:
        locked.chmod(0o600)
    assert reply == {"id": 1, "ok": False, "error": "the file cannot be read or written: permission denied"}
    assert "locked" not in json.dumps(reply)


def test_a_file_type_boxed_does_not_know_is_refused_in_the_words_of_the_formats(world, session):
    odd = world.folder / "notes.xyz"
    odd.write_text("mail ivan.petrov@acme.com")
    reply = request(session, "mask-file", src=str(odd), dest=str(world.folder / "out.xyz"))
    assert reply == {"id": 1, "ok": False, "error": "unsupported file type; supported: .csv, .docx, .pdf, .xlsx"}
    pdf = world.folder / "doc.pdf"
    pdf.write_bytes(b"%PDF-1.4\n")
    reply = request(session, "mask-file", src=str(pdf), dest=str(world.folder / "out.csv"))
    assert reply["error"] == OUTPUT_NAME  # a pdf is masked to a .txt file: the name says so before anything is read
    assert request(session, "restore-file", src=str(pdf), dest=str(world.folder / "back.pdf"), scope="f1")["error"] == (
        "a pdf is restored from the .txt made from it"
    )


def test_a_file_that_cannot_be_processed_is_a_fixed_text_that_quotes_none_of_it(world, session):
    broken = world.folder / "broken.docx"
    broken.write_bytes(b"ivan.petrov@acme.com is not a zip file")
    dest = world.folder / "out.docx"
    reply = request(session, "mask-file", src=str(broken), dest=str(dest))
    assert reply == {"id": 1, "ok": False, "error": "cannot process this docx file"}
    assert not dest.exists() and hidden(world.folder) == []


def test_a_csv_that_is_not_utf8_is_refused_without_quoting_a_byte_of_it(world, session):
    bad = world.folder / "bad.csv"
    bad.write_bytes(b"name,email\nIvan,\xff\xfeivan.petrov@acme.com\n")
    reply = request(session, "mask-file", src=str(bad), dest=str(world.folder / "out.csv"))
    assert reply["ok"] is False and "ivan" not in json.dumps(reply) and "0xff" not in json.dumps(reply)


def test_mask_file_never_replaces_its_source_even_with_replace(world, session):
    before = world.src.read_bytes()
    for flags in ({}, {"replace": True}):
        reply = mask_file(session, world, world.src, **flags)
        assert reply == {"id": 1, "ok": False, "error": "the output would replace the source file"}
        assert world.src.read_bytes() == before


def test_restore_file_never_replaces_its_input_whatever_the_flags(world, session):
    before = world.masked.read_bytes()
    for flags in ({}, {"force": True}, {"replace": True}, {"force": True, "replace": True}):
        reply = restore_file(session, world, world.masked, **flags)
        assert reply == {"id": 1, "ok": False, "error": "the output is the input file: choose another output name"}
        assert world.masked.read_bytes() == before


def test_a_link_to_the_source_is_the_source(world, session):
    link = world.folder / "latest.csv"
    link.symlink_to(world.src)
    assert mask_file(session, world, link, replace=True)["error"] == "the output would replace the source file"


def test_the_journal_comes_before_the_originals_land_and_a_journal_that_fails_leaves_no_file(world, session, home, monkeypatch):
    dest = world.folder / "back.csv"
    seen = []
    real = Journal.append

    def spy(self, entry):
        seen.append((entry.status, dest.exists()))
        return real(self, entry)

    with monkeypatch.context() as spying:
        spying.setattr(Journal, "append", spy)
        assert restore_file(session, world, dest)["ok"] is True
    assert seen == [("received", False)]  # written while the originals were still in the part file
    dest.unlink()
    (home / "journal.jsonl").unlink()
    (home / "journal.jsonl").mkdir()  # the journal cannot be written
    reply = restore_file(session, world, dest)
    assert reply == {"id": 1, "ok": False, "error": "the journal file is not a regular file"}
    assert not dest.exists() and hidden(world.folder) == []


@pytest.mark.parametrize("replace", [False, True])
def test_mask_file_journals_the_copy_before_it_lands_and_a_journal_that_fails_leaves_none(world, session, home, monkeypatch, replace):
    import hashlib

    dest = world.folder / "out.csv"
    seen = []
    real = Journal.append

    def spy(self, entry):
        seen.append((entry.status, dest.exists(), entry.payload_sha256))
        return real(self, entry)

    with monkeypatch.context() as spying:
        spying.setattr(Journal, "append", spy)
        assert mask_file(session, world, dest, scope="f9")["ok"] is True
    assert seen == [("prepared", False, hashlib.sha256(dest.read_bytes()).hexdigest())]  # the hash of the copy that landed
    dest.unlink()
    if replace:
        dest.write_bytes(b"name,email\nan older copy\n")
    (home / "journal.jsonl").unlink()
    (home / "journal.jsonl").mkdir()  # the journal cannot be written
    reply = mask_file(session, world, dest, scope="f10", **({"replace": True} if replace else {}))
    assert reply == {"id": 1, "ok": False, "error": "the journal file is not a regular file"}
    assert (dest.read_bytes() == b"name,email\nan older copy\n") if replace else not dest.exists()
    assert hidden(world.folder) == []


def test_the_map_of_a_scope_is_saved_only_when_the_clean_copy_was_written(world, session, home):
    scopes = session.context().vault.scopes()
    (world.folder / "out.csv").write_bytes(NOTES)
    assert mask_file(session, world, world.folder / "out.csv", scope="f9")["error"] == EXISTS
    assert session.context().vault.scopes() == scopes  # no scope f9 for a file that was never made


def hidden(folder: Path) -> list[str]:
    return sorted(path.name for path in folder.iterdir() if path.name.startswith("."))


def finishes(function, seconds=10):
    """function's result, or a failed test when it does not return: opening a pipe waits for the other end."""
    done = []
    thread = threading.Thread(target=lambda: done.append(function()), daemon=True)
    thread.start()
    thread.join(seconds)
    assert not thread.is_alive(), "still waiting"
    return done[0]


# The safe writer, for every file a command writes at a name the person gave. The texts are fixed: none names the file.

IN_HOME = "the output cannot be inside the boxed data folder"
IS_LINK = "the output path is a link: name the file itself"
NO_FOLDER = "the folder of the output file does not exist"
NOT_PLAIN = "the output path is not a plain file"
EXISTS = "the output file exists already: name another file, or allow replacing it"
CHANGED = "the place of the output file changed while it was made"


@dataclass(frozen=True)
class Writer:
    name: str
    command: str
    fields: Callable  # (world, out, **flags) -> the fields of a request that writes `out`
    ext: str
    work: tuple[str, str]  # the module and function that do its work, to put something in the way while it works
    own: bool = False  # a file of its own kind can be told from its first bytes, so a new run replaces it without replace


def mask_fields(world, out, **flags):
    return {"src": str(world.src), "dest": str(out), "scope": "f2", **flags}


def restore_fields(world, out, **flags):
    return {"src": str(world.masked), "dest": str(out), "scope": "f1", **flags}


def result_fields(world, out, **flags):
    return {"plan": PLAN, "table": str(world.table), "scope": "p1", "out": str(out), **flags}


def chart_fields(world, out, **flags):
    return {"plan": PLAN, "table": str(world.table), "scope": "p1", "chart_out": str(out), **flags}


def export_fields(world, out, **flags):
    return {"out": str(out), **flags}


OUTPUTS = [
    Writer("mask-file", "mask-file", mask_fields, ".csv", ("boxed.formats", "mask_file")),
    Writer("restore-file", "restore-file", restore_fields, ".csv", ("boxed.formats", "restore_file")),
    Writer("plan result", "plan-run", result_fields, ".csv", ("boxed.opplan", "run_plan")),
    Writer("plan chart", "plan-run", chart_fields, ".json", ("boxed.opplan", "run_plan"), own=True),
    Writer("journal export", "journal-export", export_fields, ".json", ("boxed.dashboard", "export_for_security"), own=True),
]


def writers(func):
    return pytest.mark.parametrize("writer", OUTPUTS, ids=lambda writer: writer.name)(func)


def write(session, writer, world, out, **flags):
    return request(session, writer.command, **writer.fields(world, out, **flags))


def snapshot(folder: Path) -> dict[str, bytes]:
    return {str(path.relative_to(folder)): path.read_bytes() for path in sorted(folder.rglob("*")) if path.is_file()}


@writers
def test_nothing_is_written_in_the_boxed_home(writer, world, home, session):
    before = snapshot(home)
    for name in ("vault.db", "journal.jsonl", "insecure-keys/device-signing-key.key", "new" + writer.ext, "reports/new" + writer.ext):
        reply = write(session, writer, world, home / name)
        assert reply == {"id": 1, "ok": False, "error": IN_HOME}, name
    assert snapshot(home) == before  # not one byte of it, and no new file


@writers
def test_a_link_is_refused_whatever_it_points_to(writer, world, home, tmp_path, session):
    victim, link = tmp_path / "victim.txt", tmp_path / ("link" + writer.ext)
    victim.write_bytes(b"precious\n")
    victim.chmod(0o644)
    link.symlink_to(victim)
    assert write(session, writer, world, link) == {"id": 1, "ok": False, "error": IS_LINK}
    assert victim.read_bytes() == b"precious\n" and stat.S_IMODE(victim.stat().st_mode) == 0o644 and link.is_symlink()
    link.unlink()
    link.symlink_to(tmp_path / ("new" + writer.ext))  # a link to nothing
    assert write(session, writer, world, link)["error"] == IS_LINK and not (tmp_path / ("new" + writer.ext)).exists()
    link.unlink()
    link.symlink_to(home / "journal.jsonl")  # a link to what boxed keeps is that, whatever else it is
    before = snapshot(home)
    assert write(session, writer, world, link)["error"] == IN_HOME and snapshot(home) == before


@writers
def test_a_folder_or_a_pipe_is_not_a_plain_file(writer, world, tmp_path, session):
    folder = tmp_path / ("folder" + writer.ext)
    folder.mkdir()
    assert write(session, writer, world, folder)["error"] == NOT_PLAIN and list(folder.iterdir()) == []
    pipe = tmp_path / ("pipe" + writer.ext)
    os.mkfifo(pipe)
    reader = os.open(pipe, os.O_RDONLY | os.O_NONBLOCK)  # with a reader there a write would not block: the test can fail instead of hanging
    try:
        assert finishes(lambda: write(session, writer, world, pipe))["error"] == NOT_PLAIN
        assert os.read(reader, 100) == b""  # nothing went into it
    finally:
        os.close(reader)


@writers
def test_the_folder_of_the_file_must_be_there_and_nothing_is_recorded_before_that(writer, world, home, tmp_path, session):
    journal = (home / "journal.jsonl").read_bytes()
    assert write(session, writer, world, tmp_path / "missing" / ("out" + writer.ext))["error"] == NO_FOLDER
    assert not (tmp_path / "missing").exists() and (home / "journal.jsonl").read_bytes() == journal


@writers
def test_a_file_that_is_there_is_replaced_only_when_the_request_says_replace(writer, world, tmp_path, session):
    out = tmp_path / ("out" + writer.ext)
    out.write_bytes(NOTES)
    assert write(session, writer, world, out) == {"id": 1, "ok": False, "error": EXISTS}
    assert out.read_bytes() == NOTES
    assert write(session, writer, world, out, replace=True)["ok"] is True and out.read_bytes() != NOTES


@writers
def test_a_file_is_private_replaced_whole_and_leaves_nothing_behind(writer, world, tmp_path, session):
    out, alias = tmp_path / ("out" + writer.ext), tmp_path / ("old" + writer.ext)
    assert write(session, writer, world, out)["ok"] is True
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    os.link(out, alias)  # a hard link keeps the old file: the old file was replaced, not written into
    before = hidden(tmp_path)
    assert write(session, writer, world, out, replace=True)["ok"] is True
    assert out.stat().st_ino != alias.stat().st_ino and alias.stat().st_nlink == 1
    assert stat.S_IMODE(out.stat().st_mode) == 0o600 and hidden(tmp_path) == before  # no part file, no folder for one


@writers
def test_links_planted_where_part_files_used_to_go_are_not_followed(writer, world, tmp_path, session):
    out, victim = tmp_path / ("out" + writer.ext), tmp_path / "victim.txt"
    victim.write_bytes(b"precious\n")
    for name in (f"out{writer.ext}.part", f".out.boxed-part{writer.ext}", f".out{writer.ext}.boxed-part"):
        (tmp_path / name).symlink_to(victim)
    assert write(session, writer, world, out)["ok"] is True and out.stat().st_size > 0
    assert victim.read_bytes() == b"precious\n"


@writers
def test_a_file_that_appears_while_the_work_goes_on_is_not_replaced(writer, world, tmp_path, session, monkeypatch):
    out = tmp_path / ("out" + writer.ext)
    module = importlib.import_module(writer.work[0])
    real = getattr(module, writer.work[1])

    def meanwhile(*args, **kwargs):
        out.write_bytes(NOTES)
        return real(*args, **kwargs)

    monkeypatch.setattr(module, writer.work[1], meanwhile)
    assert write(session, writer, world, out) == {"id": 1, "ok": False, "error": EXISTS}
    assert out.read_bytes() == NOTES and hidden(tmp_path) == []


@writers
def test_a_place_that_turns_into_a_link_while_the_work_goes_on_is_refused(writer, world, tmp_path, session, monkeypatch):
    out, victim = tmp_path / ("out" + writer.ext), tmp_path / "victim.txt"
    victim.write_bytes(b"precious\n")
    module = importlib.import_module(writer.work[0])
    real = getattr(module, writer.work[1])

    def meanwhile(*args, **kwargs):
        out.symlink_to(victim)
        return real(*args, **kwargs)

    monkeypatch.setattr(module, writer.work[1], meanwhile)
    assert write(session, writer, world, out)["error"] == IS_LINK
    assert victim.read_bytes() == b"precious\n" and out.is_symlink()


@writers
def test_a_refusal_names_no_file_and_quotes_no_input(writer, world, home, tmp_path, session):
    secret = tmp_path / "ivan.petrov@acme.com exists already"
    secret.write_bytes(NOTES)
    replies_ = [
        write(session, writer, world, secret),
        write(session, writer, world, tmp_path / "ivan.petrov@acme.com" / ("out" + writer.ext)),
        write(session, writer, world, home / "ivan.petrov@acme.com"),
    ]
    assert [r["error"] for r in replies_] == [EXISTS, NO_FOLDER, IN_HOME]
    assert "ivan" not in json.dumps(replies_) and "acme" not in json.dumps(replies_)


# ---- what the program reads and where it writes: only files of the kind the command is for, never the boxed home ----
# The window has no file system of its own: every path in a request is a path the sidecar will read or write for it. So a table is
# a .csv or .tsv file, a file below the boxed home is nobody's input, and an output is named as what it holds - which keeps
# replace from turning into "overwrite any file the person owns".

TABLE_NAME = "a table must be a .csv or .tsv file"
SOURCE_IN_HOME = "the file is inside the boxed data folder"
OUTPUT_NAME = "the output file name must end the way its content does: .csv, .tsv, .xlsx, .docx, .txt or .json"
CREDENTIALS = "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
SELECT_KEYS = '{"version": 1, "steps": [{"op": "select", "columns": ["aws_access_key_id"]}]}'


@pytest.mark.parametrize("name", ["credentials", ".env", "id_rsa", "notes.txt", "table.json", "sales.xlsx", "sales.csv.bak", "sales.csvx", "sales.csv."])
def test_only_a_csv_or_tsv_file_is_read_as_a_table(name, world, session):
    """A select over a credentials-like file used to return every row of it."""
    path = world.folder / name
    path.write_text(CREDENTIALS)
    for command, fields in (("plan-prompt", {"task": "x"}), ("plan-run", {"plan": SELECT_KEYS, "scope": "p1"})):
        reply = request(session, command, table=str(path), **fields)
        assert reply == {"id": 1, "ok": False, "error": TABLE_NAME}, (command, name)
        assert "AKIA" not in json.dumps(reply) and "wJalr" not in json.dumps(reply)


def test_a_table_may_be_a_csv_in_any_case_or_a_tsv(world, session):
    upper, tab = world.folder / "SALES.CSV", world.folder / "sales.tsv"
    upper.write_text(SALES)
    tab.write_text(SALES.replace(";", "\t"))
    for table in (upper, tab):
        assert request(session, "plan-prompt", task="top clients", table=str(table), scope="t9")["ok"] is True
    reply = request(session, "plan-run", plan=PLAN, table=str(tab), scope="t9")
    assert reply["ok"] is True and reply["delimiter"] == "\t" and reply["csv"].startswith("client\ttotal\n")


def test_a_file_in_the_boxed_home_is_never_read(world, home, session, tmp_path):
    reports = home / "reports"
    reports.mkdir()
    (reports / "t.csv").write_text(SALES)
    (reports / "c.csv").write_text(CLIENTS)
    (home / "x.csv").write_text(SALES)
    (tmp_path / "latest.csv").symlink_to(reports / "t.csv")  # a link to what boxed keeps is that, whatever else it is
    (tmp_path / "latest-c.csv").symlink_to(reports / "c.csv")
    tables = [reports / "t.csv", home / "x.csv", tmp_path / "latest.csv", reports / ".." / "x.csv"]
    sources = [reports / "c.csv", tmp_path / "latest-c.csv", reports / ".." / "reports" / "c.csv"]
    alias = home.parent / home.name.upper()
    if alias.exists():  # a file system that ignores case calls ~/.BOXED and ~/.boxed one folder
        tables.append(alias / "x.csv")
        sources.append(alias / "reports" / "c.csv")
    for table in tables:
        assert request(session, "plan-prompt", task="x", table=str(table))["error"] == SOURCE_IN_HOME, table
        assert request(session, "plan-run", plan=PLAN, table=str(table), scope="p1")["error"] == SOURCE_IN_HOME, table
    for source in sources:
        assert request(session, "mask-file", src=str(source), dest=str(world.folder / "o.csv"))["error"] == SOURCE_IN_HOME, source
        assert request(session, "restore-file", src=str(source), dest=str(world.folder / "o.csv"), scope="f1")["error"] == SOURCE_IN_HOME, source
    assert not (world.folder / "o.csv").exists() and hidden(world.folder) == []


@writers
@pytest.mark.parametrize("name", ["zshrc", "run.sh", "agent.plist", "script.py", "notes.md", "x."])
def test_a_name_that_is_not_the_name_of_what_the_file_holds_is_refused_even_with_replace(writer, name, world, tmp_path, session):
    """replace is for a file that is the same kind as the one written, not for any plain file the person owns."""
    out = tmp_path / name
    out.write_bytes(NOTES)
    assert write(session, writer, world, out, replace=True) == {"id": 1, "ok": False, "error": OUTPUT_NAME}
    assert out.read_bytes() == NOTES and hidden(tmp_path) == []
    out.unlink()
    assert write(session, writer, world, out) == {"id": 1, "ok": False, "error": OUTPUT_NAME}
    assert not out.exists()


@writers
def test_a_table_is_not_written_as_json_nor_a_chart_or_an_export_as_csv(writer, world, tmp_path, session):
    other = ".json" if writer.ext == ".csv" else ".csv"
    assert write(session, writer, world, tmp_path / ("out" + other)) == {"id": 1, "ok": False, "error": OUTPUT_NAME}
    assert write(session, writer, world, tmp_path / ("OUT" + writer.ext.upper()))["ok"] is True  # case does not matter


def test_a_result_table_may_be_a_tsv(world, session):
    out = world.folder / "result.tsv"
    assert request(session, "plan-run", plan=PLAN, table=str(world.table), scope="p1", out=str(out))["ok"] is True
    assert out.read_text().startswith("client;total\n")  # the delimiter of the table is kept, whatever the name says


def make_office_files(folder):
    """A docx and an xlsx with an e-mail address in them, and a pdf with a text layer."""
    docx = pytest.importorskip("docx")
    openpyxl = pytest.importorskip("openpyxl")
    document = docx.Document()
    document.add_paragraph("Write to ivan.petrov@acme.com")
    document.save(folder / "a.docx")
    book = openpyxl.Workbook()
    book.active.append(["ivan.petrov@acme.com"])
    book.save(folder / "a.xlsx")
    text = "BT /F1 12 Tf 20 700 Td (Write to ivan.petrov@acme.com) Tj ET"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n%s\nendstream" % (len(text), text.encode()),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out, offsets = bytearray(b"%PDF-1.4\n"), []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (number, body)
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % offset for offset in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    (folder / "a.pdf").write_bytes(bytes(out))


def test_a_masked_or_restored_copy_keeps_the_suffix_of_the_original_and_a_pdf_becomes_txt(world, session):
    make_office_files(world.folder)
    for name, good, bad in (("a.docx", "m.docx", "wrong.csv"), ("a.xlsx", "m.xlsx", "wrong.docx"), ("a.pdf", "m.txt", "wrong.pdf")):
        src = world.folder / name
        assert request(session, "mask-file", src=str(src), dest=str(world.folder / bad), scope="k1")["error"] == OUTPUT_NAME, name
        reply = request(session, "mask-file", src=str(src), dest=str(world.folder / good), scope="k1")
        assert reply["ok"] is True and "ivan" not in json.dumps(reply), name
        back = "r" + good[1:]
        wrong = "r.csv" if good != "m.csv" else "r.docx"
        assert request(session, "restore-file", src=str(world.folder / good), dest=str(world.folder / wrong), scope="k1")["error"] == OUTPUT_NAME
        assert request(session, "restore-file", src=str(world.folder / good), dest=str(world.folder / back), scope="k1")["ok"] is True, name


# ---- the work a file may ask of one request: counted first, refused in one fixed sentence when the shell would give up on it ----

TOO_MUCH = "the file is too large to be masked or restored here in the time allowed: split it into smaller files"
Work = serve_module.Work


def table_csv(folder: Path, name: str, cells: int, columns: int = 10) -> Path:
    path = folder / name
    path.write_text("".join(",".join(f"c{r}x{c}" for c in range(columns)) + "\n" for r in range(cells // columns)))
    return path


def zip_of(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return path


def pdf_of_pages(path: Path, pages: int) -> Path:
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [%s] /Count %d >>" % (b" ".join(b"%d 0 R" % (3 + i) for i in range(pages)), pages)]
    objects += [b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>"] * pages
    out, offsets = bytearray(b"%PDF-1.4\n"), []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (number, body)
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % offset for offset in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    path.write_bytes(bytes(out))
    return path


# Seconds on a Mac that was busy with other work, on the worst content for the masker (every text a new e-mail address, so every text
# adds a marker): the numbers behind the constants of serve.py, one case on each side of the line.
ESTIMATES = [
    # (what the file holds, markers in the scope, restoring, language models, allowed)
    (Work(".csv", texts=40_000), 0, False, [], True),  # mask-file 35 s
    (Work(".csv", texts=60_000), 0, False, [], False),  # mask-file 61 s
    (Work(".csv", texts=40_000), 40_000, True, [], True),  # restore-file 32 s
    (Work(".csv", texts=60_000), 60_000, True, [], False),  # restore-file 48 s
    (Work(".csv", texts=1_000), 300_000, True, [], True),  # a scope with a long past costs every text: 300,000 markers, 1,000 cells
    (Work(".csv", texts=10_000), 300_000, True, [], False),
    (Work(".csv", texts=30_000), 100_000, False, [], False),  # and so does a mask in such a scope
    (Work(".xlsx", texts=30_000), 0, False, [], True),  # 40,000 cells took 36 s
    (Work(".xlsx", texts=50_000), 0, False, [], False),
    (Work(".docx", texts=8_000), 0, False, [], True),  # 8,000 paragraphs: 12 s
    (Work(".docx", texts=30_000), 0, False, [], False),
    (Work(".docx", texts=2_000, cell_rows=1_000_000), 0, False, [], True),  # one table of 500 rows of 4 cells: 17 s
    (Work(".docx", texts=4_000, cell_rows=4_000_000), 0, False, [], False),  # 1,000 rows of 4 cells: 96 s
    (Work(".pdf", pages=158), 0, False, [], True),  # the manual of bash: 2.2 s
    (Work(".pdf", pages=900), 0, False, [], True),
    (Work(".pdf", pages=1_200), 0, False, [], False),
    (Work(".txt"), 5_000_000, True, [], True),  # the masked text of a pdf is one text: the size of the file is its limit
    (Work(".csv", texts=300), 0, False, ["en"], True),  # the English model: 115 ms a text
    (Work(".csv", texts=500), 0, False, ["en"], False),
    (Work(".csv", texts=40_000), 0, False, ["ru"], False),  # the Russian one: 0.2 ms a text, 8 s more for 40,000
    (Work(".csv", texts=30_000), 0, False, ["ru"], True),
]


@pytest.mark.parametrize(
    ("work", "markers", "restoring", "ner", "allowed"),
    ESTIMATES,
    ids=[f"{w.suffix} {w.texts}t {w.pages}p {w.cell_rows}cr {m}m {'restore' if r else 'mask'} {'+'.join(n) or 'rules'}" for w, m, r, n, _ in ESTIMATES],
)
def test_the_estimate_of_the_work_follows_the_measurements(work, markers, restoring, ner, allowed):
    if allowed:
        serve_module._refuse_work(work, ner, markers, restoring=restoring)
    else:
        with pytest.raises(serve_module.Refusal) as refused:
            serve_module._refuse_work(work, ner, markers, restoring=restoring)
        assert str(refused.value) == TOO_MUCH


def test_a_csv_is_counted_by_the_cells_that_hold_text(tmp_path):
    path = tmp_path / "a.csv"
    path.write_text('a,b\n,c\n"x, y",\n\n')
    assert Work(".csv", texts=4) == serve_module._work(path)  # a, b, c and "x, y"; empty cells and empty lines cost nothing


def test_an_xlsx_is_counted_by_the_cells_that_hold_a_value(tmp_path):
    openpyxl = pytest.importorskip("openpyxl")
    from openpyxl.styles import Font

    book = openpyxl.Workbook()
    sheet = book.active
    sheet.append(["a", 1, None])
    sheet.append([None, "b", "c"])
    sheet["C1"].font = Font(bold=True)  # a cell with a style and no value is in the file and costs nothing
    book.save(tmp_path / "a.xlsx")
    assert serve_module._work(tmp_path / "a.xlsx") == Work(".xlsx", texts=4)


def test_a_docx_is_counted_by_its_paragraphs_and_by_the_cells_of_its_tables_times_their_rows(tmp_path):
    docx = pytest.importorskip("docx")
    document = docx.Document()
    document.add_paragraph("one")
    document.add_paragraph("two")
    document.add_table(rows=3, cols=2)  # six cells, a paragraph in each
    inner = document.add_table(rows=1, cols=1)
    inner.cell(0, 0).add_table(rows=2, cols=2)  # a table in a cell is a table of its own
    document.save(tmp_path / "a.docx")
    work = serve_module._work(tmp_path / "a.docx")
    assert work.texts == 2 + 6 + 1 + 4 + 1 and work.cell_rows == 3 * 6 + 2 * 4 + 1 * 1  # (the outer cell holds its own paragraph too)


def test_a_pdf_is_counted_by_its_pages(tmp_path):
    pytest.importorskip("pypdf")
    assert serve_module._work(pdf_of_pages(tmp_path / "a.pdf", 7)) == Work(".pdf", pages=7)


def test_a_file_that_cannot_be_counted_is_left_to_the_converter_to_name(tmp_path):
    (tmp_path / "bad.xlsx").write_bytes(b"not a zip")
    (tmp_path / "bad.csv").write_bytes(b"\xff\xfe\x00")
    (tmp_path / "bad.pdf").write_bytes(b"%PDF-1.4 nothing")
    for name in ("bad.xlsx", "bad.csv", "bad.pdf"):
        assert serve_module._work(tmp_path / name).texts == 0  # no error: the converter says what is wrong, in its own words


@pytest.fixture
def made_nothing(world, session, home):
    """What a refused request leaves: no output, no part folder, no scope, no record."""
    before = journal_of(home)

    def check(dest: Path, scope: str) -> None:
        assert not dest.exists() and hidden(dest.parent) == []
        assert request(session, "restore", text="x", scope=scope) == {"id": 1, "ok": False, "error": "unknown scope"}
        assert journal_of(home) == before

    return check


def test_a_csv_with_more_cells_than_the_time_allows_is_refused_before_anything_is_made(world, session, made_nothing):
    big, dest = table_csv(world.folder, "big.csv", 60_000), world.folder / "out.csv"
    assert request(session, "mask-file", src=str(big), dest=str(dest), scope="big1") == {"id": 1, "ok": False, "error": TOO_MUCH}
    made_nothing(dest, "big1")


def test_an_xlsx_docx_and_pdf_that_ask_for_too_much_are_refused_before_anything_is_made(world, session, made_nothing):
    pytest.importorskip("pypdf")
    sheet = b'<worksheet><sheetData><row>' + b"<c><v>1</v></c>" * 50_000 + b"</row></sheetData></worksheet>"
    table = b'<w:document xmlns:w="w"><w:body><w:tbl>' + (b"<w:tr>" + b"<w:tc><w:p/></w:tc>" * 4 + b"</w:tr>") * 1_000 + b"</w:tbl></w:body></w:document>"
    big = {
        "big.xlsx": zip_of(world.folder / "big.xlsx", {"xl/worksheets/sheet1.xml": sheet}),
        "big.docx": zip_of(world.folder / "big.docx", {"word/document.xml": table}),
        "big.pdf": pdf_of_pages(world.folder / "big.pdf", 1_200),
        "bomb.xlsx": zip_of(world.folder / "bomb.xlsx", {"xl/worksheets/sheet1.xml": b"0" * (70 * 1024 * 1024)}),  # a few kilobytes that unpack to 70 MiB
    }
    for name, path in big.items():
        dest = world.folder / ("out.txt" if name.endswith(".pdf") else f"out{path.suffix}")
        assert path.stat().st_size < 16 * 1024 * 1024
        assert request(session, "mask-file", src=str(path), dest=str(dest), scope="big2") == {"id": 1, "ok": False, "error": TOO_MUCH}, name
        made_nothing(dest, "big2")


def test_with_the_english_model_a_table_is_refused_before_the_model_is_loaded(world, session, boxed_env, monkeypatch, made_nothing):
    (boxed_env / "boxed.toml").write_text('[boxed]\nner = ["en"]\n')
    monkeypatch.setattr(serve_module, "_detect_config", lambda config: pytest.fail("the model was loaded to refuse a file"))
    big, dest = table_csv(world.folder, "big.csv", 1_000), world.folder / "out.csv"
    assert request(session, "mask-file", src=str(big), dest=str(dest), scope="big3") == {"id": 1, "ok": False, "error": TOO_MUCH}
    made_nothing(dest, "big3")


def test_a_restore_in_a_scope_with_a_long_past_is_refused_when_the_file_is_large(world, session):
    from boxed.mask import MarkerMap

    markers = MarkerMap()
    for i in range(100_000):
        markers.marker_for("EMAIL", f"user{i}@company.com")
    session.context().vault.save_map("long", markers)
    answer, dest = table_csv(world.folder, "answer.csv", 30_000), world.folder / "back.csv"  # 30,000 cells go over 100,000 markers each
    assert request(session, "restore-file", src=str(answer), dest=str(dest), scope="long") == {"id": 1, "ok": False, "error": TOO_MUCH}
    assert not dest.exists() and hidden(world.folder) == []
    small = table_csv(world.folder, "small.csv", 500)  # the same scope, a file that fits: restored
    assert request(session, "restore-file", src=str(small), dest=str(world.folder / "ok.csv"), scope="long")["ok"] is True


def test_a_mask_in_a_scope_with_a_long_past_is_refused_when_the_file_is_large_and_the_scope_stays_as_it_was(world, session):
    from boxed.mask import MarkerMap

    markers = MarkerMap()
    for i in range(100_000):
        markers.marker_for("EMAIL", f"user{i}@company.com")
    vault = session.context().vault
    vault.save_map("long", markers)
    src, dest = table_csv(world.folder, "in.csv", 20_000), world.folder / "out.csv"  # 20,000 cells, each looking at 100,000 markers twice
    assert request(session, "mask-file", src=str(src), dest=str(dest), scope="long") == {"id": 1, "ok": False, "error": TOO_MUCH}
    assert not dest.exists() and hidden(world.folder) == []
    assert len(vault.load_map("long").items()) == 100_000


def test_a_csv_with_hundreds_of_thousands_of_cells_is_refused_as_it_is_counted(tmp_path):
    with pytest.raises(serve_module.Refusal) as refused:
        serve_module._work(table_csv(tmp_path, "huge.csv", 600_000))
    assert str(refused.value) == TOO_MUCH


# ---- policy-check: what the policy allows for a text and a recipient, decided before anything is masked ----

PROFILES = ["no-rules", "no-confidential", "approved-only", "ban"]
RECIPIENTS = [
    "openai:personal-private:US",
    "deepseek:personal-training:CN",
    "acme:corporate:EU",
    "openai:api-zero-retention:US",
    "ollama:local:local",
]
POLICY_TEXTS = {
    "clean": "Q3 plan",
    "email": "mail ivan@acme.com",
    "key": "key AKIAIOSFODNN7EXAMPLE",
    "amount": "Total due: $1,200.50",
    "client": "Offer for Acme Corp",
    "cyrillic": "Позвоните Ивану Петрову: +7 (912) 345-67-89",
}


def write_profile(home, profile):
    home.mkdir(parents=True, exist_ok=True)
    (home / "boxed.toml").write_text(f'[boxed]\n[boxed.dictionary]\n"Acme Corp" = "CLIENT"\n[boxed.policy]\nprofile = "{profile}"\n')


def cli_policy_lines(reply: dict) -> str:
    """What boxed policy check prints for the decision the shell gets."""
    level = f" (level {reply['min_level']} or higher)" if reply["verdict"] == "masked" else ""
    lines = [f"verdict: {reply['verdict']}{level}", "categories: " + (", ".join(reply["categories"]) or "none found")]
    lines += [f"reason: {reason}" for reason in reply["reasons"]] + [f"warning: {warning}" for warning in reply["warnings"]]
    return "\n".join(lines) + "\n"


@pytest.mark.parametrize("categories", [[], ["finance"], ["hr", "health"], ["strategy", "finance", "strategy"]])
@pytest.mark.parametrize("recipient", RECIPIENTS)
@pytest.mark.parametrize("text", POLICY_TEXTS.values(), ids=POLICY_TEXTS.keys())
@pytest.mark.parametrize("profile", PROFILES)
def test_policy_check_decides_what_boxed_policy_check_decides(boxed_env, session, capsys, monkeypatch, profile, text, recipient, categories):
    write_profile(boxed_env, profile)
    monkeypatch.chdir(boxed_env)
    extra = [flag for name in categories for flag in ("--category", name)]
    code, out, err = run_cli(capsys, monkeypatch, ["policy", "check", *extra, "--recipient", recipient, "-"], stdin=text)
    reply = request(session, "policy-check", text=text, recipient=recipient, categories=categories)
    assert reply["ok"] is True and err == ""
    assert cli_policy_lines(reply) == out
    assert code == (4 if reply["verdict"] in ("deny", "local-only") else 0)


def test_policy_check_names_the_verdict_the_level_the_categories_and_why(boxed_env, session):
    write_profile(boxed_env, "no-confidential")
    reply = request(session, "policy-check", text="mail ivan@acme.com, pay $1,200.50", recipient="openai:personal-training:US")
    assert reply == {
        "id": 1,
        "ok": True,
        "verdict": "masked",
        "min_level": 3,
        "categories": ["finance", "personal"],
        "reasons": ["personal for personal-training: masked at level 1", "finance for personal-training: masked at level 3"],
        "warnings": ["personal data leaves the EEA: this needs a legal basis, masking does not replace it", "this account may train on chats"],
    }
    write_profile(boxed_env, "ban")
    reply = request(session, "policy-check", text="hello", recipient="openai:personal-private:US")
    assert (reply["verdict"], reply["min_level"], reply["categories"]) == ("deny", None, [])


def test_policy_check_opens_neither_the_vault_nor_the_journal_nor_the_key_store(boxed_env, session):
    write_profile(boxed_env, "approved-only")
    assert request(session, "policy-check", text="mail ivan@acme.com", recipient="openai:personal-private:US")["verdict"] == "deny"
    assert sorted(path.name for path in boxed_env.iterdir()) == ["boxed.toml"]


def test_policy_check_reads_boxed_toml_of_the_boxed_home_again_for_each_request(boxed_env, session):
    ask = {"text": "mail ivan@acme.com", "recipient": "openai:personal-private:US"}
    write_profile(boxed_env, "no-rules")
    assert request(session, "policy-check", **ask)["verdict"] == "masked"
    write_profile(boxed_env, "ban")
    assert request(session, "policy-check", **ask)["verdict"] == "deny"
    (boxed_env / "boxed.toml").write_text("[boxed\n")
    assert request(session, "policy-check", **ask) == {"id": 1, "ok": False, "error": "boxed.toml cannot be read"}


BAD_POLICY_CHECKS = [
    {},
    {"text": "x"},
    {"recipient": "openai:personal-private:US"},
    {"text": 5, "recipient": "openai:personal-private:US"},
    {"text": "lone \ud800", "recipient": "openai:personal-private:US"},
    {"text": "x", "recipient": 5},
    {"text": "x", "recipient": "openai:personal-private"},
    {"text": "x", "recipient": "openai:personal-private:US:extra"},
    {"text": "x", "recipient": "openai:nobody:US"},
    {"text": "x", "recipient": "openai:Personal-Private:US"},
    {"text": "x", "recipient": ":personal-private:US"},
    {"text": "x", "recipient": "openai:personal-private:"},
    {"text": "x", "recipient": "open ai:personal-private:US"},
    {"text": "x", "recipient": "openai:personal-private:US\n"},
    {"text": "x", "recipient": "openai:personal-private:" + "U" * 65},
    {"text": "x", "recipient": "openai:personal-private:US", "categories": "finance"},
    {"text": "x", "recipient": "openai:personal-private:US", "categories": ["personal"]},  # a detector raises it
    {"text": "x", "recipient": "openai:personal-private:US", "categories": ["Finance"]},
    {"text": "x", "recipient": "openai:personal-private:US", "categories": [["finance"]]},
    {"text": "x", "recipient": "openai:personal-private:US", "categories": [None]},
    {"text": "x", "recipient": "openai:personal-private:US", "level": 2},
    {"text": "x", "recipient": "openai:personal-private:US", "scope": "s"},
]


@pytest.mark.parametrize("fields", BAD_POLICY_CHECKS, ids=[json.dumps(m)[:70] for m in BAD_POLICY_CHECKS])
def test_policy_check_refuses_what_is_not_a_request_before_anything_is_made(boxed_env, session, fields):
    assert request(session, "policy-check", **fields) == {"id": 1, "ok": False, "error": "bad request"}
    assert not boxed_env.exists()


def test_policy_check_quotes_nothing_it_was_given(boxed_env, session):
    write_profile(boxed_env, "approved-only")
    reply = request(session, "policy-check", text=TEXT, recipient="ivan-petrov:personal-private:AKIAIOSFODNN7EXAMPLE")
    assert reply["ok"] is True
    for value in [*VALUES, "ivan-petrov", "AKIAIOSFODNN7EXAMPLE"]:
        assert value not in json.dumps(reply)


@pytest.mark.parametrize("writer", [w for w in OUTPUTS if w.own], ids=lambda writer: writer.name)
def test_an_earlier_file_of_its_own_kind_is_replaced_without_replace(writer, world, tmp_path, session):
    out = tmp_path / ("out" + writer.ext)
    assert write(session, writer, world, out)["ok"] is True
    assert write(session, writer, world, out)["ok"] is True


# ---- plan-prompt and plan-run: level 4, the task and the schema go out, the plan comes back and runs here ----


def both_configs(tmp_path, home, text):
    """The same boxed.toml where the command line looks (the folder it runs in) and where serve looks (the boxed home)."""
    home.mkdir(parents=True, exist_ok=True)
    for folder in (tmp_path, home):
        (folder / "boxed.toml").write_text(text)


DICTIONARY = '[boxed]\n[boxed.dictionary]\n"Acme Corp" = "CLIENT"\n'
SALES_WITH_CLIENT = "client;Acme Corp margin\nRomashka;1 234,50\nLutik;99,5\n\n"


@pytest.mark.parametrize("decimal", ["auto", ".", ","])
def test_plan_prompt_gives_what_boxed_plan_prompt_gives_and_journals_the_same(world, home, session, capsys, tmp_path, decimal):
    both_configs(tmp_path, home, DICTIONARY)
    table = tmp_path / "margins.csv"
    table.write_text(SALES_WITH_CLIENT)
    task = "top clients of Acme Corp by margin, mail ivan@acme.com"
    code, out, err = run_cli(capsys, None, ["plan", "prompt", "--task", task, "--scope", "c1", "--decimal", decimal, str(table)])
    reply = request(session, "plan-prompt", task=task, table=str(table), scope="s1", decimal=decimal)
    assert code == 0 and reply["ok"] is True
    assert reply["prompt"] + "\n" == out and "[CLIENT_1]" in reply["prompt"] and "Acme Corp" not in reply["prompt"]
    assert err == f"scope: c1; decimal: {reply['decimal']}\n"
    assert reply["decimal"] == ("," if decimal in ("auto", ",") else ".")
    by_cli, by_serve = [r for r in journal_of(home) if r["scope"] in ("c1", "s1")]
    assert same_record(by_cli) == same_record(by_serve)
    assert by_serve["level"] == 4 and by_serve["coverage"] == "level 4: task and schema only"
    assert by_serve["payload_sha256"] == hashlib.sha256(reply["prompt"].encode()).hexdigest()
    assert reply["markers_by_kind"] == by_serve["markers_by_kind"] == {"CLIENT": 2, "EMAIL": 1}  # in the task and in a column name


def test_plan_prompt_without_a_scope_names_one_and_keeps_it_for_the_plan(world, session):
    reply = request(session, "plan-prompt", task="top clients", table=str(world.table))
    assert re.fullmatch(r"plan-\d{8}T\d{6}", reply["scope"]) and reply["scope"] in session.context().vault.scopes()


def test_plan_prompt_needs_header_ok_for_a_header_that_looks_like_data(world, session):
    table = world.folder / "t.csv"
    table.write_text("ivan,1500\nanna,200\n")
    reply = request(session, "plan-prompt", task="sum", table=str(table))
    assert reply == {"id": 1, "ok": False, "error": "the header looks like a data row: check that the table has a header, then confirm it"}
    assert request(session, "plan-prompt", task="sum", table=str(table), header_ok=True)["ok"] is True


def test_plan_prompt_masks_at_the_level_of_boxed_toml_whatever_it_is(world, home, session):
    home.mkdir(parents=True, exist_ok=True)
    (home / "boxed.toml").write_text("[boxed]\nlevel = 4\n")  # level 4 is what a plan is: nothing to refuse
    assert request(session, "plan-prompt", task="mail ivan@acme.com", table=str(world.table), scope="s1")["ok"] is True


def test_plan_refuses_a_table_over_the_cell_limit_before_it_normalises_or_writes_anything(boxed_env, tmp_path, session, monkeypatch):
    monkeypatch.setattr("boxed.opplan.MAX_CELLS", 8)
    table = tmp_path / "t.csv"
    table.write_text("a,b,c\n1,2,3\n4,5,6\n7,8,9\n")  # 9 cells of data
    for fields in ({}, {"decimal": "."}):
        reply = request(session, "plan-prompt", task="sum", table=str(table), **fields)
        assert reply == {"id": 1, "ok": False, "error": "table: more than 8 cells"}
    reply = request(session, "plan-run", plan=PLAN, table=str(table), scope="nope")
    assert reply["error"] == "table: more than 8 cells"  # the table comes before the scope
    assert not boxed_env.exists()  # not the vault, not the journal


def test_plan_prompt_and_plan_run_refuse_a_table_that_is_not_utf8_text_or_is_empty(boxed_env, tmp_path, session):
    expected = {"id": 1, "ok": False, "error": "the table is not UTF-8 text, or it is empty"}
    for content in (b"", b"\n\n", b"a,b\n1,\xff\xfe\n", b"a,b\n1,\x00\n", "a,b\n1,2\n".encode("utf-16")):
        table = tmp_path / "t.csv"
        table.write_bytes(content)
        assert request(session, "plan-prompt", task="sum", table=str(table)) == expected
        assert request(session, "plan-run", plan=PLAN, table=str(table), scope="p1") == expected
    assert not boxed_env.exists()


def test_plan_prompt_reads_a_table_that_is_there_and_not_too_large(boxed_env, tmp_path, session, monkeypatch):
    assert request(session, "plan-prompt", task="sum", table=str(tmp_path / "nope.csv"))["error"] == "the file was not found"
    (tmp_path / "folder.csv").mkdir()
    assert request(session, "plan-prompt", task="sum", table=str(tmp_path / "folder.csv"))["error"] == "the path is not a plain file"
    (tmp_path / "t.csv").write_text("a\n1\n")
    monkeypatch.setattr(serve_module, "MAX_FILE", 2)
    assert request(session, "plan-prompt", task="sum", table=str(tmp_path / "t.csv"))["error"] == "the file is larger than 16 MiB"
    assert not boxed_env.exists()


def test_plan_prompt_and_run_normalise_the_columns_the_way_the_command_line_does(world, session, monkeypatch):
    from boxed import opplan

    asked, real = [], opplan.normalize_rows
    monkeypatch.setattr(opplan, "normalize_rows", lambda rows, decimal=".", columns=None: asked.append(columns) or real(rows, decimal, columns))
    request(session, "plan-prompt", task="top clients", table=str(world.table), scope="p9")
    assert asked == [None]  # the model is told the type of every column
    assert request(session, "plan-run", plan=PLAN, table=str(world.table), scope="p9")["ok"] is True
    assert asked == [None, {0, 2}]  # client and revenue; region and day are dropped by the group
    limit = '{"version": 1, "steps": [{"op": "limit", "n": 1}]}'
    assert request(session, "plan-run", plan=limit, table=str(world.table), scope="p9")["ok"] is True
    assert asked == [None, {0, 2}, None]  # nothing is dropped: every column is normalised
    assert request(session, "plan-run", plan="I cannot do that", table=str(world.table), scope="p9")["error"] == "plan: not valid JSON"
    assert asked == [None, {0, 2}, None, None]


BAD_PLAN_PROMPTS = [
    {},
    {"task": "x"},
    {"table": "/x/t.csv"},
    {"task": 5, "table": "/x/t.csv"},
    {"task": "lone \ud800", "table": "/x/t.csv"},
    {"task": "x", "table": "t.csv"},
    {"task": "x", "table": "/x/t.csv", "decimal": "x"},
    {"task": "x", "table": "/x/t.csv", "decimal": 1},
    {"task": "x", "table": "/x/t.csv", "header_ok": "yes"},
    {"task": "x", "table": "/x/t.csv", "scope": "a b"},
    {"task": "x", "table": "/x/t.csv", "level": 2},
    {"task": "x", "table": "/x/t.csv", "out": "/x/o.csv"},
]


@pytest.mark.parametrize("fields", BAD_PLAN_PROMPTS, ids=[json.dumps(m)[:60] for m in BAD_PLAN_PROMPTS])
def test_plan_prompt_refuses_what_is_not_a_request_before_anything_is_made(boxed_env, session, fields):
    assert request(session, "plan-prompt", **fields) == {"id": 1, "ok": False, "error": "bad request"}
    assert not boxed_env.exists()


BAD_PLAN_RUNS = [
    {},
    {"plan": PLAN, "table": "/x/t.csv"},  # the scope is required
    {"plan": PLAN, "scope": "p1"},
    {"table": "/x/t.csv", "scope": "p1"},
    {"plan": 5, "table": "/x/t.csv", "scope": "p1"},
    {"plan": "lone \ud800", "table": "/x/t.csv", "scope": "p1"},
    {"plan": PLAN, "table": "/x/t.csv", "scope": "p1", "decimal": "x"},
    {"plan": PLAN, "table": "/x/t.csv", "scope": "p1", "out": "t.csv"},
    {"plan": PLAN, "table": "/x/t.csv", "scope": "p1", "chart_out": 5},
    {"plan": PLAN, "table": "/x/t.csv", "scope": "p1", "replace": "yes"},
    {"plan": PLAN, "table": "/x/t.csv", "scope": "p1", "force": True},
    {"plan": PLAN, "table": "/x/t.csv", "scope": "p1", "chart": "/x/c.json"},
]


@pytest.mark.parametrize("fields", BAD_PLAN_RUNS, ids=[json.dumps(m)[:60] for m in BAD_PLAN_RUNS])
def test_plan_run_refuses_what_is_not_a_request_before_anything_is_made(boxed_env, session, fields):
    assert request(session, "plan-run", **fields) == {"id": 1, "ok": False, "error": "bad request"}
    assert not boxed_env.exists()


def test_plan_run_restores_names_runs_the_plan_on_the_real_rows_and_returns_the_table_and_the_chart(world, session):
    reply = request(session, "plan-run", plan=PLAN, table=str(world.table), scope="p1")
    assert reply == {
        "id": 1,
        "ok": True,
        "csv": "client;total\nRomashka;1244.5\nLutik;99.5\n",
        "delimiter": ";",
        "rows": 2,
        "chart": {"kind": "bar", "x": "client", "y": "total", "points": [["Romashka", 1244.5], ["Lutik", 99.5]]},
    }


def test_plan_run_gives_what_boxed_plan_run_gives_and_journals_the_same(world, home, session, capsys, tmp_path):
    both_configs(tmp_path, home, DICTIONARY)
    table = tmp_path / "margins.csv"
    table.write_text(SALES_WITH_CLIENT)
    for scope in ("c1", "s1"):
        task = "top clients of Acme Corp"
        if scope == "c1":
            assert run_cli(capsys, None, ["plan", "prompt", "--task", task, "--scope", scope, str(table)])[0] == 0
        else:
            assert request(session, "plan-prompt", task=task, table=str(table), scope=scope)["ok"] is True
    answer = '```json\n{"version": 1, "steps": [{"op": "sort", "by": ["[CLIENT_1] margin"], "desc": true}, {"op": "limit", "n": 1}]}\n```'
    (tmp_path / "answer.json").write_text(answer)
    code, out, err = run_cli(capsys, None, ["plan", "run", "--scope", "c1", str(tmp_path / "answer.json"), str(table)])
    reply = request(session, "plan-run", plan=answer, table=str(table), scope="s1")
    assert code == 0 and reply["ok"] is True and err == ""
    assert reply["csv"] == out == "client;Acme Corp margin\nRomashka;1234.5\n"
    by_cli, by_serve = [r for r in journal_of(home) if r["scope"] in ("c1", "s1") and r["status"] == "received"]
    assert same_record(by_cli) == same_record(by_serve)
    assert by_serve["coverage"] == "level 4 plan run, 1 rows" and by_serve["payload_sha256"] == hashlib.sha256(answer.encode()).hexdigest()


def test_plan_run_writes_the_files_the_command_line_writes(world, home, session, capsys, tmp_path):
    (tmp_path / "by-cli").mkdir()
    (tmp_path / "by-serve").mkdir()
    argv = ["plan", "run", "--scope", "p1", "--out", str(tmp_path / "by-cli" / "t.csv"), "--chart", str(tmp_path / "by-cli" / "c.json")]
    code, out, _ = run_cli(capsys, None, [*argv, str(world.plan), str(world.table)])
    reply = request(
        session, "plan-run", plan=PLAN, table=str(world.table), scope="p1",
        out=str(tmp_path / "by-serve" / "t.csv"), chart_out=str(tmp_path / "by-serve" / "c.json"),
    )
    assert code == 0 and out == "" and reply["ok"] is True
    assert (tmp_path / "by-serve" / "t.csv").read_bytes() == (tmp_path / "by-cli" / "t.csv").read_bytes()
    assert (tmp_path / "by-serve" / "c.json").read_bytes() == (tmp_path / "by-cli" / "c.json").read_bytes()
    assert reply["csv"] is None and reply["rows"] == 2 and reply["chart"]["kind"] == "bar"  # the table went to the file


def test_plan_run_refuses_placeholders_it_cannot_restore_and_runs_nothing(world, home, session):
    before = journal_of(home)
    plan = '{"version": 1, "steps": [{"op": "filter", "column": "client", "cmp": "==", "value": "[EMAIL_9]"}]}'
    out = world.folder / "t.csv"
    reply = request(session, "plan-run", plan=plan, table=str(world.table), scope="p1", out=str(out))
    assert reply == {"id": 1, "ok": False, "error": "plan not run, check these placeholders", "anomalies": ["[EMAIL_9]"]}
    assert not out.exists() and journal_of(home) == before


def test_plan_run_of_an_unknown_scope_is_refused(world, session):
    assert request(session, "plan-run", plan=PLAN, table=str(world.table), scope="nope") == {"id": 1, "ok": False, "error": "unknown scope"}


@pytest.mark.parametrize(
    ("plan", "error"),
    [
        ("I cannot do that", "plan: not valid JSON"),
        ('{"version": 2, "steps": []}', "plan: version must be 1"),
        ('{"version": 1, "steps": [{"op": "limit", "n": 0}]}', "step 1: n must be a whole number from 1 to 10000"),
        ('{"version": 1, "steps": [{"op": "sort", "by": ["ivan.petrov@acme.com"], "desc": false}]}', "step 1: unknown column"),
        ("x" * 100_001, "plan: the answer is too long"),
    ],
    ids=["not json", "version", "limit", "unknown column", "too long"],
)
def test_a_plan_that_cannot_run_is_refused_in_the_words_of_the_executor_without_quoting_the_plan(world, session, plan, error):
    reply = request(session, "plan-run", plan=plan, table=str(world.table), scope="p1")
    assert reply == {"id": 1, "ok": False, "error": error}


def test_the_journal_comes_before_any_data_leaves_a_plan_run(world, home, session, monkeypatch):
    out, chart = world.folder / "t.csv", world.folder / "c.json"
    seen = []
    real = Journal.append

    def spy(self, entry):
        seen.append((entry.status, out.exists(), chart.exists()))
        return real(self, entry)

    with monkeypatch.context() as spying:
        spying.setattr(Journal, "append", spy)
        assert request(session, "plan-run", plan=PLAN, table=str(world.table), scope="p1", out=str(out), chart_out=str(chart))["ok"] is True
    assert seen == [("received", False, False)]
    out.unlink()
    chart.unlink()
    (home / "journal.jsonl").unlink()
    (home / "journal.jsonl").mkdir()  # the journal cannot be written
    reply = request(session, "plan-run", plan=PLAN, table=str(world.table), scope="p1", out=str(out), chart_out=str(chart))
    assert reply == {"id": 1, "ok": False, "error": "the journal file is not a regular file"}
    assert not out.exists() and not chart.exists() and hidden(world.folder) == []


def test_a_plan_run_reply_that_cannot_be_sent_is_not_journaled_and_writes_nothing(world, home, session, monkeypatch):
    monkeypatch.setattr(serve_module, "MAX_REPLY", 250)
    before, chart = journal_of(home), world.folder / "c.json"
    assert request(session, "plan-run", plan=PLAN, table=str(world.table), scope="p1", chart_out=str(chart))["error"] == "reply too large"
    assert journal_of(home) == before and not chart.exists()


def test_plan_errors_name_a_step_and_never_a_value(world, session):
    table = world.folder / "secret.csv"
    table.write_text("client;ivan.petrov@acme.com\nRomashka;1\n")
    reply = request(session, "plan-run", plan='{"version": 1, "steps": [{"op": "limit", "n": 0}]}', table=str(table), scope="p1")
    assert reply["ok"] is False and "ivan" not in json.dumps(reply)


# ---- ask: policy, then masking, then the journal, then the request, then the journal and the restore ----

KEY = "sk-test-0123456789abcdef"
ASK_TEXT = "Write to ivan@acme.com about the invoice"
ASK_MASKED = "Write to [EMAIL_1] about the invoice"


@pytest.fixture
def start_api():
    """A local stand-in for a provider's API: it records what arrives and answers with what the test sets."""
    started = []

    def start(status=200, body=b"{}", delay=0.0):
        api = types.SimpleNamespace(requests=[], status=status, body=body)

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                lowered = {name.lower(): value for name, value in self.headers.items()}
                api.requests.append(types.SimpleNamespace(path=self.path, headers=lowered, body=raw))
                time.sleep(delay)  # a provider that takes its time
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


def ask(session, text=ASK_TEXT, **fields):
    return request(session, "ask", text=text, provider="openai", model="gpt-test", **fields)


def test_ask_returns_the_restored_answer_and_sends_only_the_masked_text(session, openai_api, boxed_env):
    reply = ask(session, scope="deal-7")
    assert reply == {
        "id": 1,
        "ok": True,
        "text": "Dear ivan@acme.com, noted.",
        "scope": "deal-7",
        "level": 2,
        "verdict": "masked",
        "warnings": ["personal data leaves the EEA: this needs a legal basis, masking does not replace it"],
        "unknown": [],
        "suspicious": [],
        "model": "gpt-test-2026",
        "usage": {"input": 12, "output": 5},
        "complete": True,
    }
    [sent_request] = openai_api.requests
    assert sent_request.path == "/responses" and sent_request.headers["authorization"] == f"Bearer {KEY}"
    assert json.loads(sent_request.body)["input"] == ASK_MASKED and b"ivan@acme.com" not in sent_request.body
    sent, received = journal_of(boxed_env)
    assert (sent["channel"], sent["status"], sent["model"], sent["scope"]) == ("api", "sent", "gpt-test", "deal-7")
    assert (received["status"], received["usage"]) == ("received", {"input": 12, "output": 5})
    assert KEY not in json.dumps(reply) + (boxed_env / "journal.jsonl").read_text()  # a key is never handed back or journaled
    assert "ivan@acme.com" not in (boxed_env / "journal.jsonl").read_text()


def test_ask_gives_what_boxed_ask_gives_and_journals_the_same(session, openai_api, capsys, monkeypatch, boxed_env):
    openai_api.body = answer("Dear [EMAIL_1], not [EMAIL_9], and [EMAIL-1] is odd.", status="incomplete", incomplete_details={"reason": "max_output_tokens"})
    argv = ["ask", "--provider", "openai", "--model", "gpt-test", "--account", "corporate", "--level", "3", "--scope", "c1", "-"]
    code, out, err = run_cli(capsys, monkeypatch, argv, stdin=ASK_TEXT)
    reply = ask(session, account="corporate", level=3, scope="s1")
    assert code == 3 and reply["ok"] is True
    assert reply["text"] == out  # the answer is kept, anomalies and all: it was paid for
    assert (reply["unknown"], reply["suspicious"], reply["complete"]) == (["[EMAIL_9]"], ["[EMAIL-1]"], False)
    lines = err.splitlines()
    assert lines[0] == "scope: c1" and "not restored, check by hand: [EMAIL_9], [EMAIL-1]" in lines
    assert [line for line in lines if line.startswith("warning:")] == [f"warning: {w}" for w in reply["warnings"]] + [
        "warning: the answer was cut off: the provider stopped it before the end"
    ]
    cli_sent, cli_received, serve_sent, serve_received = journal_of(boxed_env)
    assert same_record(cli_sent) == same_record(serve_sent) and same_record(cli_received) == same_record(serve_received)
    assert (serve_sent["account_type"], serve_sent["level"]) == ("corporate", 3)


@pytest.mark.parametrize("profile", ["ban", "approved-only", "no-confidential"])
def test_ask_blocked_by_the_policy_sends_nothing_and_says_why_as_boxed_ask_does(boxed_env, session, openai_api, capsys, monkeypatch, profile):
    write_profile(boxed_env, profile)
    monkeypatch.chdir(boxed_env)
    argv = ["ask", "--provider", "openai", "--model", "gpt-test", "--category", "hr", "--scope", "c1", "-"]
    code, out, err = run_cli(capsys, monkeypatch, argv, stdin=ASK_TEXT)
    reply = ask(session, categories=["hr"], scope="s1")
    assert code == 4 and out == "" and reply["ok"] is False
    assert reply["error"] == f"blocked by policy: {reply['verdict']}" and reply["verdict"] in ("deny", "local-only")
    cli_lines = err.splitlines()
    assert cli_lines[0] == f"boxed: {reply['error']}"
    assert cli_lines[1:] == [f"reason: {r}" for r in reply["reasons"]] + [f"warning: {w}" for w in reply["warnings"]]
    assert openai_api.requests == []
    cli_blocked, serve_blocked = journal_of(boxed_env)
    assert (serve_blocked["status"], serve_blocked["payload_sha256"]) == ("blocked", hashlib.sha256(b"").hexdigest())
    assert same_record(cli_blocked) == same_record(serve_blocked)
    assert "ivan@acme.com" not in json.dumps(reply)


def test_ask_that_needs_level_4_from_the_policy_points_to_the_plan(boxed_env, session, openai_api):
    boxed_env.mkdir(parents=True)
    (boxed_env / "boxed.toml").write_text('[boxed]\n[boxed.policy.rules]\n"personal:personal-private" = "masked:4"\n')
    reply = ask(session)
    assert reply["ok"] is False and reply["verdict"] == "masked"
    assert reply["error"] == "blocked by policy: masked: the policy asks for level 4, which sends the task and the table schema only: use boxed plan"
    assert reply["reasons"] == ["personal for personal-private: masked at level 4"] and openai_api.requests == []
    assert (journal_of(boxed_env)[0]["status"], journal_of(boxed_env)[0]["level"]) == ("blocked", 2)  # never 4: nothing was masked at 4


@pytest.mark.parametrize("how", ["request", "boxed.toml"])
def test_ask_refuses_level_4_in_the_words_of_the_command_line_and_sends_nothing(boxed_env, session, openai_api, how):
    if how == "boxed.toml":
        boxed_env.mkdir(parents=True)
        (boxed_env / "boxed.toml").write_text("[boxed]\nlevel = 4\n")
    reply = ask(session, **({"level": 4} if how == "request" else {}))
    assert reply == {"id": 1, "ok": False, "error": REFUSAL_LEVEL_4}
    assert openai_api.requests == [] and journal_of(boxed_env) == []


def test_ask_at_level_3_goes_out_and_is_recorded_as_3(session, openai_api, boxed_env):
    assert ask(session, level=3)["level"] == 3 and journal_of(boxed_env)[0]["level"] == 3


def test_ask_masks_amounts_and_dates_with_the_level_the_policy_asks_for(session, openai_api, boxed_env):
    """No profile is set: finance still goes to a personal account at level 3 or higher, and an amount is finance."""
    openai_api.body = answer("Noted: [MONEY_1] due on [DATE_1].")
    reply = ask(session, text="Total due: $1,200.50 on 21.10.2026")
    assert reply["text"] == "Noted: $1,200.50 due on 21.10.2026." and reply["level"] == 3
    sent = json.loads(openai_api.requests[0].body)["input"]
    assert sent == "Total due: [MONEY_1] on [DATE_1]" and "1,200" not in sent


def test_the_categories_of_the_request_count_for_the_policy(boxed_env, session, openai_api):
    write_profile(boxed_env, "approved-only")
    openai_api.body = answer("Noted.")
    assert ask(session, text="Q3 plan")["ok"] is True  # nothing in it raises a category
    reply = ask(session, text="Q3 plan", categories=["finance"])
    assert reply["ok"] is False and reply["verdict"] == "deny" and len(openai_api.requests) == 1


def test_ask_names_the_account(session, openai_api, boxed_env):
    assert ask(session, account="corporate")["ok"] is True and journal_of(boxed_env)[0]["account_type"] == "corporate"


def test_a_channel_error_is_the_fixed_text_the_channel_makes_and_the_journal_says_so(session, openai_api, boxed_env):
    openai_api.status = 401
    openai_api.body = json.dumps({"error": {"message": f"bad key {KEY} for {ASK_MASKED}", "code": "invalid_api_key"}}).encode()
    reply = ask(session)
    assert reply == {"id": 1, "ok": False, "error": "openai: HTTP 401 (invalid_api_key)"}
    assert [r["status"] for r in journal_of(boxed_env)] == ["sent", "error"]
    assert KEY not in json.dumps(reply) and ASK_MASKED not in json.dumps(reply)


def test_ask_without_a_key_sends_nothing_and_makes_nothing(boxed_env, session, start_api, monkeypatch):
    api = start_api(body=answer())
    monkeypatch.setitem(PROVIDERS, "openai", replace(PROVIDERS["openai"], base_url=api.url))
    assert ask(session) == {"id": 1, "ok": False, "error": "no API key for this provider"}
    assert api.requests == [] and not boxed_env.exists()


def test_ask_takes_the_key_from_the_keychain(session, openai_api, monkeypatch, memory_keyring):
    monkeypatch.delenv("OPENAI_API_KEY")
    memory_keyring.set_password("boxed.si", "api-key:openai", "sk-from-keychain")
    assert ask(session)["ok"] is True and openai_api.requests[0].headers["authorization"] == "Bearer sk-from-keychain"


def test_a_stored_key_that_could_not_be_a_key_is_refused_in_the_words_of_the_channel(session, openai_api, monkeypatch, boxed_env):
    monkeypatch.setenv("OPENAI_API_KEY", "sk with spaces")
    assert ask(session) == {"id": 1, "ok": False, "error": "the API key must be printable ASCII without spaces"}
    assert openai_api.requests == [] and journal_of(boxed_env) == []


def test_when_the_journal_cannot_be_written_nothing_is_sent(boxed_env, session, openai_api):
    boxed_env.mkdir(parents=True)
    (boxed_env / "journal.jsonl").mkdir()
    reply = ask(session)
    assert reply == {"id": 1, "ok": False, "error": "the journal file is not a regular file"}
    assert openai_api.requests == [] and KEY not in json.dumps(reply)


HOSTILE = "ok \x1b]52;c;aGk=\x07 \x1b[2J \x9b31m done\r\nsecond\tline\x7f end"


def test_the_answer_comes_back_exactly_as_it_is_whatever_characters_it_holds(session, openai_api):
    """The shell shows the text in its own window and never lets it near a terminal: nothing is escaped on the way."""
    openai_api.body = answer(HOSTILE)
    assert ask(session)["text"] == HOSTILE


def test_ask_sends_through_a_relay_named_in_the_environment_and_says_so_on_stderr_only(session, start_api, monkeypatch, boxed_env, capsys):
    relay = start_api(body=answer())
    monkeypatch.setenv("OPENAI_API_KEY", KEY)
    monkeypatch.setenv("BOXED_OPENAI_BASE_URL", relay.url + "/openai/v1")  # http is fine to this computer
    code, out = run_serve(session, {"id": 1, "cmd": "ask", "text": ASK_TEXT, "provider": "openai", "model": "gpt-test"})
    assert code == 0 and out[0]["ok"] is True
    [relayed] = relay.requests
    assert relayed.path == "/openai/v1/responses" and b"ivan@acme.com" not in relayed.body
    assert [record["note"] for record in journal_of(boxed_env)][0] == "relay"
    captured = capsys.readouterr()
    [notice] = [line for line in captured.err.splitlines() if "relay" in line]
    assert "BOXED_OPENAI_BASE_URL" in notice and KEY not in captured.err and "ivan@acme.com" not in captured.err


def test_a_relay_address_a_key_must_not_go_to_is_refused_in_the_words_of_the_channel(session, start_api, monkeypatch, boxed_env):
    api = start_api(body=answer())
    monkeypatch.setenv("OPENAI_API_KEY", KEY)
    monkeypatch.setenv("BOXED_OPENAI_BASE_URL", "http://relay.example.com/v1")
    reply = ask(session)
    assert reply["ok"] is False and reply["error"].startswith("BOXED_OPENAI_BASE_URL must be an https address")
    assert "relay.example.com" not in json.dumps(reply) and api.requests == [] and journal_of(boxed_env) == []


def test_openrouter_zero_retention_and_the_reported_cost_run_through_to_the_journal(session, start_api, monkeypatch, boxed_env):
    usage = {"prompt_tokens": 8, "completion_tokens": 3, "cost": 0.000042}
    api = start_api(body=json.dumps({"model": "vendor/m", "choices": [{"message": {"content": "Dear [EMAIL_1]"}}], "usage": usage}).encode())
    monkeypatch.setenv("OPENROUTER_API_KEY", KEY)
    monkeypatch.setenv("BOXED_OPENROUTER_BASE_URL", api.url)
    reply = request(session, "ask", text=ASK_TEXT, provider="openrouter", model="vendor/m", account="api-zero-retention")
    assert reply["ok"] is True and reply["text"] == "Dear ivan@acme.com"
    assert reply["usage"] == {"input": 8, "output": 3, "cost_micro_usd": 42} == journal_of(boxed_env)[-1]["usage"]
    assert json.loads(api.requests[0].body)["provider"] == {"data_collection": "deny", "zdr": True}


BAD_ASKS = [
    {},
    {"text": ASK_TEXT, "provider": "openai"},
    {"text": ASK_TEXT, "model": "gpt-test"},
    {"provider": "openai", "model": "gpt-test"},
    {"text": 5, "provider": "openai", "model": "gpt-test"},
    {"text": "lone \ud800", "provider": "openai", "model": "gpt-test"},
    {"text": ASK_TEXT, "provider": "nope", "model": "gpt-test"},
    {"text": ASK_TEXT, "provider": "OpenAI", "model": "gpt-test"},
    {"text": ASK_TEXT, "provider": ["openai"], "model": "gpt-test"},
    {"text": ASK_TEXT, "provider": "openai", "model": 5},
    {"text": ASK_TEXT, "provider": "openai", "model": "gpt 4"},
    {"text": ASK_TEXT, "provider": "openai", "model": ""},
    {"text": ASK_TEXT, "provider": "openai", "model": "m" * 129},
    {"text": ASK_TEXT, "provider": "openai", "model": "gpt-test", "account": "local"},
    {"text": ASK_TEXT, "provider": "openai", "model": "gpt-test", "account": "nobody"},
    {"text": ASK_TEXT, "provider": "openai", "model": "gpt-test", "account": ["corporate"]},
    {"text": ASK_TEXT, "provider": "openai", "model": "gpt-test", "level": 9},
    {"text": ASK_TEXT, "provider": "openai", "model": "gpt-test", "level": "2"},
    {"text": ASK_TEXT, "provider": "openai", "model": "gpt-test", "scope": "a b"},
    {"text": ASK_TEXT, "provider": "openai", "model": "gpt-test", "categories": ["secrets"]},
    {"text": ASK_TEXT, "provider": "openai", "model": "gpt-test", "categories": "hr"},
    {"text": ASK_TEXT, "provider": "openai", "model": "gpt-test", "key": KEY},
    {"text": ASK_TEXT, "provider": "openai", "model": "gpt-test", "base_url": "https://example.com"},
]


@pytest.mark.parametrize("fields", BAD_ASKS, ids=[json.dumps(m)[:70] for m in BAD_ASKS])
def test_ask_refuses_what_is_not_a_request_before_anything_is_made_or_sent(boxed_env, session, openai_api, fields):
    assert request(session, "ask", **fields) == {"id": 1, "ok": False, "error": "bad request"}
    assert openai_api.requests == [] and not boxed_env.exists()


def test_an_ask_reply_that_cannot_be_sent_says_so_after_the_answer_was_journaled(session, openai_api, boxed_env, monkeypatch):
    monkeypatch.setattr(serve_module, "MAX_REPLY", 300)
    assert ask(session) == {"id": 1, "ok": False, "error": "reply too large"}
    assert [r["status"] for r in journal_of(boxed_env)] == ["sent", "received"]  # it was received: the journal says what happened


# ---- key-status, key-set and key-remove: the API key of a provider, kept in the OS keychain ----

SLOT = ("boxed.si", "api-key:openai")


class BrokenKeyring(KeyringBackend):
    """A keychain that refuses to store and, like some real backends, quotes the password in its error."""

    priority = 1

    def get_password(self, service, username):
        return None

    def set_password(self, service, username, password):
        raise RuntimeError(f"cannot store {password}")

    def delete_password(self, service, username):
        raise RuntimeError("cannot delete")


def test_key_status_names_the_place_and_nothing_else(session, memory_keyring, monkeypatch, capsys):
    for expected, prepare in (
        (None, lambda: None),
        ("environment", lambda: monkeypatch.setenv("OPENAI_API_KEY", KEY)),
        ("keychain", lambda: memory_keyring.set_password(*SLOT, "sk-from-keychain")),  # the one ask would use
    ):
        prepare()
        reply = request(session, "key-status", provider="openai")
        assert reply == {"id": 1, "ok": True, "source": expected}
        code, out, _ = run_cli(capsys, monkeypatch, ["key", "status", "openai"])
        assert out == (f"set ({expected})\n" if expected else "not set\n")  # the command line says the same
        assert KEY not in json.dumps(reply) and "sk-from-keychain" not in json.dumps(reply)
    assert request(session, "key-status", provider="anthropic")["source"] is None  # a key belongs to its provider


def test_key_set_stores_the_key_in_the_keychain_as_boxed_key_set_does_and_never_hands_it_back(session, memory_keyring, monkeypatch, capsys, boxed_env):
    code, _, _ = run_cli(capsys, monkeypatch, ["key", "set", "openai"], stdin=f"  {KEY}\n")
    by_cli = dict(memory_keyring.store)
    memory_keyring.store.clear()
    reply = request(session, "key-set", provider="openai", key=f"  {KEY}\n")  # padding is dropped
    assert code == 0 and reply == {"id": 1, "ok": True} and memory_keyring.store == by_cli == {SLOT: KEY}
    assert KEY not in json.dumps(reply)
    assert not boxed_env.exists()  # a key is not a journal entry, and no data folder is made for it


@pytest.mark.parametrize("given", ["", "\n", "sk bad", "sk-ключ", "k" * 5000], ids=["empty", "blank", "space", "non-ascii", "long"])
def test_key_set_refuses_what_could_not_be_sent_as_a_key_without_quoting_it(session, memory_keyring, monkeypatch, capsys, given):
    code, _, err = run_cli(capsys, monkeypatch, ["key", "set", "openai"], stdin=given + "\n")
    reply = request(session, "key-set", provider="openai", key=given)
    assert reply == {"id": 1, "ok": False, "error": "the API key must be printable ASCII without spaces"}
    assert memory_keyring.store == {} and "printable ASCII without spaces" in err
    if given.strip():
        assert given.strip() not in json.dumps(reply, ensure_ascii=False)


def test_a_key_with_a_line_break_inside_is_no_key(session, memory_keyring):
    """The command line takes the first line of what a pipe gives it; the shell gives one field, and it is the key."""
    reply = request(session, "key-set", provider="openai", key="sk-a\nsk-b")
    assert reply["error"] == "the API key must be printable ASCII without spaces" and memory_keyring.store == {}


def test_a_keychain_that_refuses_gives_a_fixed_error_without_the_key(session, boxed_env):
    keyring.set_keyring(BrokenKeyring())  # the autouse fixture puts the original back afterwards
    reply = request(session, "key-set", provider="openai", key="sk-secret-value")
    assert reply == {"id": 1, "ok": False, "error": "openai: cannot store the key in the keychain"}
    assert "sk-secret-value" not in json.dumps(reply)
    reply = request(session, "key-remove", provider="openai")
    assert reply == {"id": 1, "ok": True, "removed": False, "environment": False}  # nothing was there to remove


def test_key_remove_deletes_the_keychain_entry_and_says_what_it_cannot_touch(session, memory_keyring, monkeypatch, capsys):
    memory_keyring.set_password(*SLOT, "sk-from-keychain")
    monkeypatch.setenv("OPENAI_API_KEY", KEY)
    reply = request(session, "key-remove", provider="openai")
    assert reply == {"id": 1, "ok": True, "removed": True, "environment": True}  # the variable is the person's: named, never touched
    assert memory_keyring.store == {} and request(session, "key-status", provider="openai")["source"] == "environment"
    assert KEY not in json.dumps(reply)
    code, out, _ = run_cli(capsys, monkeypatch, ["key", "remove", "openai"])
    assert code == 0 and out.startswith("no key for openai in the keychain") and "OPENAI_API_KEY is still set" in out


def test_key_remove_with_nothing_to_remove_is_not_an_error(session, memory_keyring):
    assert request(session, "key-remove", provider="openai") == {"id": 1, "ok": True, "removed": False, "environment": False}


BAD_KEY_REQUESTS = [
    ("key-status", {}),
    ("key-status", {"provider": "nope"}),
    ("key-status", {"provider": None}),
    ("key-status", {"provider": "OpenAI"}),
    ("key-status", {"provider": "openai", "key": KEY}),
    ("key-set", {"provider": "openai"}),
    ("key-set", {"key": KEY}),
    ("key-set", {"provider": "openai", "key": 5}),
    ("key-set", {"provider": "openai", "key": None}),
    ("key-set", {"provider": "openai", "key": "sk-\ud800"}),
    ("key-set", {"provider": "nope", "key": KEY}),
    ("key-set", {"provider": "openai", "key": KEY, "scope": "s"}),
    ("key-remove", {}),
    ("key-remove", {"provider": "nope"}),
    ("key-remove", {"provider": "openai", "force": True}),
]


@pytest.mark.parametrize(("command", "fields"), BAD_KEY_REQUESTS, ids=[f"{c} {json.dumps(f)[:50]}" for c, f in BAD_KEY_REQUESTS])
def test_the_key_commands_refuse_what_is_not_a_request_and_store_nothing(boxed_env, session, memory_keyring, command, fields):
    assert request(session, command, **fields) == {"id": 1, "ok": False, "error": "bad request"}
    assert memory_keyring.store == {} and not boxed_env.exists()


def test_a_failure_while_a_key_is_stored_quotes_nothing_and_logs_only_the_class(boxed_env, session, memory_keyring, monkeypatch):
    def boom(provider, key):
        raise RuntimeError(f"cannot store {key}")

    boxed_env.mkdir(parents=True)
    monkeypatch.setattr("boxed.channels.set_api_key", boom)
    assert request(session, "key-set", provider="openai", key=KEY) == {"id": 1, "ok": False, "error": "internal error"}
    log = (boxed_env / "host-errors.log").read_text()
    assert "internal error: RuntimeError" in log and KEY not in log


def test_the_session_and_the_modules_do_not_hold_a_key_after_the_request(session, memory_keyring):
    stdin = io.BytesIO(frames({"id": 1, "cmd": "key-set", "provider": "openai", "key": KEY}, {"id": 2, "cmd": "key-status", "provider": "openai"}))
    assert serve(stdin, io.BytesIO(), session) == 0
    stdin = None
    gc.collect()
    modules = [vars(module) for name, module in list(sys.modules.items()) if name.startswith("boxed") and module is not None]
    for place, root in (("the session", session), ("the modules", modules)):
        held = [s for s in held_strings(root) if (KEY in s if isinstance(s, str) else KEY.encode() in s)]
        assert not held, f"the key is still held in {place}"


# ---- checks, check-set and check-remove: what the person knows about training on chats, per account ----

CHECK_NOTE = "Training off does not mean nothing is stored: providers still keep chats for a while."
FAIL_SAFE = "A check that is missing, unknown or shows training on is treated as personal-training, the stricter recipient."
SETTINGS_URLS = {
    "chatgpt": "https://chatgpt.com/#settings/DataControls",
    "claude": "https://claude.ai/settings/data-privacy-controls",
    "gemini": "https://myactivity.google.com/product/gemini",
    "deepseek": None,
    "zai": None,
}


@pytest.fixture
def now(monkeypatch):
    """boxed.cli and boxed.serve see 2026-10-21 12:00:05 UTC, whatever the clock says."""

    class Fixed(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 10, 21, 12, 0, 5, tzinfo=UTC)

    monkeypatch.setattr("boxed.cli.datetime", Fixed)
    monkeypatch.setattr("boxed.serve.datetime", Fixed)


def keep(home, provider, account, training, memory, checked_at):
    home.mkdir(parents=True, exist_ok=True)
    save_check(home, Check(provider, account, training, memory, "asked", checked_at))


def damage(home, content=b"{not json"):
    home.mkdir(parents=True, exist_ok=True)
    path = home / "checks.json"
    path.write_bytes(content)
    path.chmod(0o600)
    return path


def cli_check_lines(reply: dict) -> str:
    """What boxed check list prints for the checks the shell gets."""
    lines = []
    for row in reply["checks"]:
        lines.append(
            f"{row['provider']}  {row['account']}  training {row['training']}  memory {row['memory']}  checked {row['checked_at']}"
            f" ({row['source']})  recipient {row['recipient']}" + ("  due" if row["due"] else "")
        )
        if row["due"] and row["settings_url"]:
            lines.append(f"  check again: {row['settings_url']}")
    if not lines:
        lines.append("no checks recorded yet: boxed check set --provider P --account A --training on|off|unknown --memory on|off|unknown")
    return "\n".join(lines) + f"\n\n{reply['note']}\n{reply['fail_safe']}\n"


def test_checks_without_a_file_lists_the_providers_and_makes_nothing(boxed_env, session, now):
    assert request(session, "checks") == {
        "id": 1,
        "ok": True,
        "checks": [],
        "providers": ["chatgpt", "claude", "gemini", "deepseek", "zai"],
        "settings": SETTINGS_URLS,
        "note": CHECK_NOTE,
        "fail_safe": FAIL_SAFE,
    }
    assert not boxed_env.exists()


def test_checks_lists_what_boxed_check_list_lists_with_what_is_due_and_where_to_look(boxed_env, session, now, capsys):
    keep(boxed_env, "chatgpt", "me@acme.com", "off", "off", "2026-10-21")
    keep(boxed_env, "claude", "work", "off", "off", "2026-09-20")  # 31 days ago
    keep(boxed_env, "gemini", "me", "unknown", "off", "2026-10-21")  # unknown is always due
    keep(boxed_env, "deepseek", "old", "on", "off", "2026-09-21")  # 30 days ago: not due, but training is on
    reply = request(session, "checks")
    assert [(r["provider"], r["due"], r["recipient"]) for r in reply["checks"]] == [
        ("chatgpt", False, "personal-private"),
        ("claude", True, "personal-private"),
        ("gemini", True, "personal-training"),
        ("deepseek", False, "personal-training"),
    ]
    assert reply["checks"][1] == {
        "provider": "claude", "account": "work", "training": "off", "memory": "off", "source": "asked", "checked_at": "2026-09-20",
        "due": True, "settings_url": "https://claude.ai/settings/data-privacy-controls", "recipient": "personal-private",
    }
    code, out, _ = run_cli(capsys, None, ["check", "list"])
    assert code == 5 and out == cli_check_lines(reply)  # exit 5: something is due


def test_checks_marks_overdue_ones_without_comparing_every_pair(boxed_env, session, now, monkeypatch):
    today = "2026-10-21"
    many = [Check("chatgpt", f"a{i}", "off", "unknown" if i % 2 else "off", "asked", today) for i in range(2000)]
    monkeypatch.setattr(serve_module, "load_checks", lambda home: many)
    compared = []
    equal = Check.__eq__
    monkeypatch.setattr(Check, "__eq__", lambda self, other: compared.append(1) or equal(self, other))
    reply = request(session, "checks")
    assert [row["due"] for row in reply["checks"]] == [i % 2 == 1 for i in range(2000)]
    assert len(compared) < len(many)  # looking each record up in the list of due ones takes 2000 x 1000 comparisons


def test_check_set_saves_the_answer_as_asked_today_as_boxed_check_set_does(boxed_env, session, now, capsys):
    code, out, _ = run_cli(capsys, None, ["check", "set", "--provider", "chatgpt", "--account", "me@acme.com", "--training", "off", "--memory", "on"])
    by_cli = load_checks(boxed_env)
    (boxed_env / "checks.json").unlink()
    assert request(session, "check-set", provider="chatgpt", account="me@acme.com", training="off", memory="on") == {"id": 1, "ok": True}
    assert code == 0 and load_checks(boxed_env) == by_cli == [Check("chatgpt", "me@acme.com", "off", "on", "asked", "2026-10-21")]
    assert stat.S_IMODE((boxed_env / "checks.json").stat().st_mode) == 0o600  # the day comes from the clock, not from the caller


def test_check_set_replaces_the_same_account_and_keeps_the_others(boxed_env, session, now):
    def set_(**fields):
        return request(session, "check-set", **({"provider": "chatgpt", "account": "me@acme.com", "training": "off", "memory": "on"} | fields))

    set_(training="on")
    set_(provider="claude", account="work", memory="off")
    set_(training="off")
    assert [(c.provider, c.account, c.training) for c in load_checks(boxed_env)] == [("claude", "work", "off"), ("chatgpt", "me@acme.com", "off")]


BAD_CHECK_SETS = [
    {"provider": "chatgpt", "account": "me", "training": "off"},
    {"provider": "chatgpt", "account": "me", "memory": "off"},
    {"provider": "chatgpt", "training": "off", "memory": "off"},
    {"account": "me", "training": "off", "memory": "off"},
    {"provider": "bing", "account": "me", "training": "off", "memory": "off"},
    {"provider": "Claude", "account": "me", "training": "off", "memory": "off"},
    {"provider": ["claude"], "account": "me", "training": "off", "memory": "off"},
    {"provider": "claude", "account": "my account", "training": "off", "memory": "off"},
    {"provider": "claude", "account": "", "training": "off", "memory": "off"},
    {"provider": "claude", "account": ".x", "training": "off", "memory": "off"},
    {"provider": "claude", "account": "x/y", "training": "off", "memory": "off"},
    {"provider": "claude", "account": "a" * 65, "training": "off", "memory": "off"},
    {"provider": "claude", "account": "me\n", "training": "off", "memory": "off"},
    {"provider": "claude", "account": 5, "training": "off", "memory": "off"},
    {"provider": "claude", "account": "me", "training": "maybe", "memory": "off"},
    {"provider": "claude", "account": "me", "training": "OFF", "memory": "off"},
    {"provider": "claude", "account": "me", "training": True, "memory": "off"},
    {"provider": "claude", "account": "me", "training": "off", "memory": 0},
    {"provider": "claude", "account": "me", "training": "off", "memory": "off", "source": "page"},  # the program decides how and when
    {"provider": "claude", "account": "me", "training": "off", "memory": "off", "checked_at": "2020-01-01"},
]


@pytest.mark.parametrize("fields", BAD_CHECK_SETS, ids=[json.dumps(m)[:70] for m in BAD_CHECK_SETS])
def test_check_set_refuses_what_is_not_a_request_before_anything_is_written(boxed_env, session, now, fields):
    assert request(session, "check-set", **fields) == {"id": 1, "ok": False, "error": "bad request"}
    assert not boxed_env.exists()


def test_check_remove_deletes_one_check_as_boxed_check_remove_does(boxed_env, session, now, capsys):
    keep(boxed_env, "chatgpt", "me@acme.com", "off", "off", "2026-10-21")
    keep(boxed_env, "claude", "work", "off", "off", "2026-10-21")
    keep(boxed_env, "gemini", "me", "off", "off", "2026-10-21")
    assert run_cli(capsys, None, ["check", "remove", "--provider", "gemini", "--account", "me"])[0] == 0
    assert request(session, "check-remove", provider="chatgpt", account="me@acme.com") == {"id": 1, "ok": True}
    assert [(c.provider, c.account) for c in load_checks(boxed_env)] == [("claude", "work")]
    assert stat.S_IMODE((boxed_env / "checks.json").stat().st_mode) == 0o600
    assert request(session, "check-remove", provider="claude", account="work")["ok"] is True
    assert load_checks(boxed_env) == [] and request(session, "checks")["ok"] is True  # an empty file is still a good file


def test_check_remove_of_a_check_that_is_not_there_changes_nothing(boxed_env, session, now, capsys):
    keep(boxed_env, "chatgpt", "me@acme.com", "off", "off", "2026-10-21")
    before = (boxed_env / "checks.json").read_bytes()
    code, out, err = run_cli(capsys, None, ["check", "remove", "--provider", "claude", "--account", "work"])
    assert code == 1 and err.strip() == "boxed: no check for claude work"
    assert request(session, "check-remove", provider="claude", account="work") == {"id": 1, "ok": False, "error": "no check for this account"}
    assert request(session, "check-remove", provider="chatgpt", account="me")["ok"] is False  # the account must match exactly
    assert (boxed_env / "checks.json").read_bytes() == before


@pytest.mark.parametrize("fields", [{}, {"provider": "chatgpt"}, {"account": "me"}, {"provider": "bing", "account": "me"},
                                    {"provider": "chatgpt", "account": "my account"}, {"provider": "chatgpt", "account": 5},
                                    {"provider": "chatgpt", "account": "me", "training": "off"}])
def test_check_remove_refuses_what_is_not_a_request(boxed_env, session, now, fields):
    assert request(session, "check-remove", **fields) == {"id": 1, "ok": False, "error": "bad request"}
    assert not boxed_env.exists()


def test_a_file_that_is_not_believed_is_an_error_and_never_reads_as_training_off(boxed_env, session, now, capsys):
    path = damage(boxed_env, b'{"version": 1, "checks": [{"provider": "chatgpt", "account": "me", "training": "off"}]}')
    expected = {"id": 1, "ok": False, "error": "training checks need to be confirmed again"}  # unsigned: from before files were signed
    assert request(session, "checks") == expected
    code, _, err = run_cli(capsys, None, ["check", "list"])
    assert code == 2 and f"boxed: error: {expected['error']}, so every account counts as personal-training" in err
    before = path.read_bytes()
    assert request(session, "check-set", provider="chatgpt", account="me", training="off", memory="off") == expected
    assert request(session, "check-remove", provider="chatgpt", account="me") == expected
    assert path.read_bytes() == before  # nothing is repaired behind the person's back


def test_a_garbage_file_reads_as_damaged(boxed_env, session, now):
    damage(boxed_env, b"\x00garbage")
    assert request(session, "checks") == {"id": 1, "ok": False, "error": "checks.json is damaged"}


ASIDE = "checks.json.damaged-20261021T120005Z"  # the clock of the `now` fixture, to the second
CHECKS_READABLE = "checks.json is readable: nothing to reset"
ASIDE_EXISTS = "an earlier damaged checks.json has this second's name: wait a second and try again"


def test_check_reset_moves_a_damaged_file_aside_and_keeps_it(boxed_env, session, now):
    path = damage(boxed_env, b"\x00garbage")
    assert request(session, "check-reset") == {"id": 1, "ok": True, "moved": True, "kept_as": ASIDE}
    assert not path.exists() and (boxed_env / ASIDE).read_bytes() == b"\x00garbage"  # moved, not deleted
    assert request(session, "checks")["ok"] is True  # the person can start again
    assert request(session, "check-set", provider="chatgpt", account="me", training="off", memory="off")["ok"] is True
    assert [c.provider for c in load_checks(boxed_env)] == ["chatgpt"]


def test_check_reset_moves_aside_a_file_that_was_not_signed_by_this_device(boxed_env, session, now):
    unsigned = b'{"version": 1, "checks": [{"provider": "chatgpt", "account": "me", "training": "off"}]}'
    damage(boxed_env, unsigned)
    assert request(session, "checks")["error"] == "training checks need to be confirmed again"
    assert request(session, "check-reset")["moved"] is True and (boxed_env / ASIDE).read_bytes() == unsigned


def test_check_reset_does_what_boxed_check_reset_does(boxed_env, session, now, capsys):
    damage(boxed_env, b"\x00garbage")
    code, out, err = run_cli(capsys, None, ["check", "reset"])
    assert code == 0 and err == "" and f"damaged checks.json moved to {boxed_env / ASIDE}" in out
    assert (boxed_env / ASIDE).read_bytes() == b"\x00garbage"
    (boxed_env / ASIDE).unlink()
    damage(boxed_env, b"\x00garbage")
    assert request(session, "check-reset") == {"id": 1, "ok": True, "moved": True, "kept_as": ASIDE}
    assert (boxed_env / ASIDE).read_bytes() == b"\x00garbage"


def test_check_reset_moves_aside_whatever_stands_in_the_place_of_the_file(boxed_env, session, now, tmp_path):
    boxed_env.mkdir(parents=True)
    (boxed_env / "checks.json").mkdir()
    assert request(session, "check-reset")["moved"] is True
    assert (boxed_env / ASIDE).is_dir() and not (boxed_env / "checks.json").exists()
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"precious\n")
    (boxed_env / ASIDE).rmdir()
    (boxed_env / "checks.json").symlink_to(victim)  # a link: the link goes aside, never the file it points to
    assert request(session, "check-reset")["moved"] is True
    assert (boxed_env / ASIDE).is_symlink() and victim.read_bytes() == b"precious\n"


def test_check_reset_does_not_overwrite_an_earlier_file_moved_aside(boxed_env, session, now):
    boxed_env.mkdir(parents=True)
    (boxed_env / ASIDE).write_bytes(b"the first one")
    path = damage(boxed_env, b"the second one")
    assert request(session, "check-reset") == {"id": 1, "ok": False, "error": ASIDE_EXISTS}
    assert (boxed_env / ASIDE).read_bytes() == b"the first one" and path.read_bytes() == b"the second one"


def test_check_reset_leaves_a_good_file_alone(boxed_env, session, now):
    keep(boxed_env, "chatgpt", "me@acme.com", "off", "off", "2026-10-21")
    before = (boxed_env / "checks.json").read_bytes()
    assert request(session, "check-reset") == {"id": 1, "ok": False, "error": CHECKS_READABLE}
    assert (boxed_env / "checks.json").read_bytes() == before and not list(boxed_env.glob("checks.json.damaged-*"))


def test_check_reset_without_a_file_says_so_and_makes_nothing(boxed_env, session, now):
    assert request(session, "check-reset") == {"id": 1, "ok": True, "moved": False, "kept_as": None}
    assert not boxed_env.exists()


def test_check_reset_takes_no_fields(boxed_env, session, now):
    damage(boxed_env, b"\x00garbage")
    assert request(session, "check-reset", force=True) == {"id": 1, "ok": False, "error": "bad request"}
    assert (boxed_env / "checks.json").exists()


@pytest.mark.parametrize(
    ("command", "fields", "function"),
    [
        ("checks", {}, "load_checks"),
        ("check-set", {"provider": "claude", "account": "me", "training": "off", "memory": "off"}, "save_check"),
    ],
)
def test_a_failure_in_a_checks_command_quotes_nothing(boxed_env, session, now, monkeypatch, command, fields, function):
    def boom(*args, **kwargs):
        raise RuntimeError(TEXT)

    boxed_env.mkdir(parents=True)
    monkeypatch.setattr(serve_module, function, boom)
    reply = request(session, command, **fields)
    assert reply == {"id": 1, "ok": False, "error": "internal error"}
    assert not (boxed_env / "checks.json").exists() and TEXT not in (boxed_env / "host-errors.log").read_text()


# ---- journal-verify and journal-export: the chain, and the signed export for the security team ----


@pytest.fixture
def used(session):
    """A journal with a few records of different kinds."""
    request(session, "mask", text=TEXT, scope="a1")
    request(session, "restore", text=MASKED, scope="a1")
    request(session, "mask", text="pay $1,200.50 to ivan@acme.com", scope="a2", level=3)
    return session.context()


def test_journal_verify_says_ok_for_a_whole_journal_and_for_none(boxed_env, session, used, capsys):
    assert request(session, "journal-verify") == {"id": 1, "ok": True, "chain_ok": True, "count": 3, "first_bad": None, "reason": "ok"}
    code, out, _ = run_cli(capsys, None, ["journal", "verify"])
    assert code == 0 and out == "ok: 3 records verified; ok\n"
    (boxed_env / "journal.jsonl").unlink()
    assert request(session, "journal-verify") == {"id": 1, "ok": True, "chain_ok": True, "count": 0, "first_bad": None, "reason": "ok"}


def test_journal_verify_says_broken_for_an_edited_record_as_boxed_journal_verify_does(boxed_env, session, used, capsys):
    path = boxed_env / "journal.jsonl"
    record = json.loads(path.read_text().splitlines()[1])
    record["level"] = 0
    lines = path.read_text().splitlines()
    lines[1] = json.dumps(record)
    path.write_text("\n".join(lines) + "\n")
    reply = request(session, "journal-verify")
    assert reply == {"id": 1, "ok": True, "chain_ok": False, "count": 1, "first_bad": 2, "reason": "record 2: hash does not match content"}
    code, out, _ = run_cli(capsys, None, ["journal", "verify"])
    assert code == 1 and out == "BROKEN: 1 records verified; record 2: hash does not match content\n"


def test_journal_verify_counts_damaged_lines(boxed_env, session, used):
    with (boxed_env / "journal.jsonl").open("a") as f:
        f.write('{"seq": 4, "torn\n')
    reply = request(session, "journal-verify")
    assert (reply["chain_ok"], reply["count"], reply["first_bad"]) == (False, 3, 4)
    assert reply["reason"] == "line 4 is not a journal record (1 damaged); the 3 whole records verify"


def test_journal_verify_of_a_journal_that_is_not_a_file_is_a_fixed_error(boxed_env, session, used):
    (boxed_env / "journal.jsonl").unlink()
    (boxed_env / "journal.jsonl").mkdir()
    assert request(session, "journal-verify") == {"id": 1, "ok": False, "error": "the journal file is not a regular file"}


def test_journal_export_writes_the_file_the_command_line_writes_and_says_how_many_records(boxed_env, session, used, capsys, tmp_path):
    (tmp_path / "by-cli").mkdir()
    (tmp_path / "by-serve").mkdir()
    code, out, _ = run_cli(capsys, None, ["journal", "export", "--out", str(tmp_path / "by-cli" / "e.json")])
    reply = request(session, "journal-export", out=str(tmp_path / "by-serve" / "e.json"))
    key = reply["public_key"]
    assert code == 0 and reply == {"id": 1, "ok": True, "records": 3, "public_key": key}
    assert out == f"3 records exported to {tmp_path / 'by-cli' / 'e.json'}; device key {key}\n"
    assert (tmp_path / "by-serve" / "e.json").read_bytes() == (tmp_path / "by-cli" / "e.json").read_bytes()
    assert stat.S_IMODE((tmp_path / "by-serve" / "e.json").stat().st_mode) == 0o600
    code, out, _ = run_cli(capsys, None, ["journal", "check-export", str(tmp_path / "by-serve" / "e.json")])
    assert code == 0 and out.startswith("ok: 3 records verified")  # the security team's side needs no key store


def test_journal_export_takes_the_days_the_command_line_takes(boxed_env, session, capsys, tmp_path, monkeypatch):
    class Day(datetime):
        day = 14

        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 10, cls.day, 12, tzinfo=UTC)

    monkeypatch.setattr("boxed.journal.datetime", Day)
    for day in (14, 15, 20, 21):
        Day.day = day
        request(session, "mask", text="mail a@x.io", scope=f"day-{day}")
    (tmp_path / "by-cli").mkdir()
    code, out, _ = run_cli(capsys, None, ["journal", "export", "--since", "2026-10-15", "--until", "2026-10-20", "--out", str(tmp_path / "by-cli" / "e.json")])
    reply = request(session, "journal-export", out=str(tmp_path / "e.json"), since="2026-10-15", until="2026-10-20")
    assert code == 0 and reply["records"] == 2
    assert (tmp_path / "e.json").read_bytes() == (tmp_path / "by-cli" / "e.json").read_bytes()
    assert [e["scope"] for e in json.loads((tmp_path / "e.json").read_text())["entries"]] == ["day-15", "day-20"]


BAD_JOURNAL_REQUESTS = [
    ("journal-verify", {"scope": "s"}),
    ("journal-verify", {"last": 5}),
    ("journal-export", {}),
    ("journal-export", {"out": "e.json"}),
    ("journal-export", {"out": 5}),
    ("journal-export", {"out": "/x/e.json", "since": "yesterday"}),
    ("journal-export", {"out": "/x/e.json", "since": "2026-13-01"}),
    ("journal-export", {"out": "/x/e.json", "since": "2026-1-1"}),
    ("journal-export", {"out": "/x/e.json", "until": 20261020}),
    ("journal-export", {"out": "/x/e.json", "until": "2026-10-20\n"}),
    ("journal-export", {"out": "/x/e.json", "replace": "yes"}),
    ("journal-export", {"out": "/x/e.json", "format": "csv"}),
]


@pytest.mark.parametrize(("command", "fields"), BAD_JOURNAL_REQUESTS, ids=[f"{c} {json.dumps(f)[:50]}" for c, f in BAD_JOURNAL_REQUESTS])
def test_the_journal_commands_refuse_what_is_not_a_request_before_anything_is_made(boxed_env, session, command, fields):
    assert request(session, command, **fields) == {"id": 1, "ok": False, "error": "bad request"}
    assert not boxed_env.exists()


# ---- dashboard: the data the dashboard page shows, as JSON; every number is compared with the page boxed dashboard writes ----


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


def record(channel, provider, account, level, kinds, status, scope, **more):
    return JournalEntry(channel, provider, account, level, kinds, status, "ab" * 32, "full", scope, {"boxed": "0.1.0"}, **more)


HISTORY = [  # (day, record)
    (14, record("manual", "unknown", "unknown", 2, {"EMAIL": 2}, "prepared", "d14")),
    (15, record("api", "openai", "personal-private", 2, {"EMAIL": 1}, "sent", "d15", model="gpt-test")),
    (15, record("api", "openai", "personal-private", -1, {}, "received", "d15", model="gpt-test", usage={"input": 12, "output": 5})),
    (20, record("api", "openrouter", "personal-training", 3, {"MONEY": 1, "DATE": 1}, "sent", "d20", model="vendor/m")),
    (20, record("api", "openrouter", "personal-training", -1, {}, "received", "d20", model="vendor/m", usage={"input": 8, "output": 3, "cost_micro_usd": 42})),
    (21, record("api", "anthropic", "corporate", 2, {"PERSON": 1}, "blocked", "d21")),
    (21, record("manual", "unknown", "unknown", 1, {"PHONE": 1}, "prepared", "d21")),
    (21, record("api", "openai", "personal-private", 2, {}, "error", "d21", model="gpt-test")),
]
SEEN_BY_THE_BROWSER = [  # (day, site, text, coverage)
    (19, "chatgpt", "mail ivan@acme.com and key AKIAIOSFODNN7EXAMPLE", "checked"),
    (20, "claude", "mail a@x.io", "checked"),
    (20, "deepseek", "", "not checked"),
    (21, "chatgpt", "nothing here", "checked"),
]


@pytest.fixture
def busy(boxed_env, session, journal_clock, now):
    """A boxed home that has been used for a week: a journal of every kind of record, what the browser saw, three checks."""
    ctx = session.context()
    for day, entry in HISTORY:
        journal_clock(day)
        ctx.journal.append(entry)
    observed = observed_journal(boxed_env, ctx.keys)
    for day, site, text, coverage in SEEN_BY_THE_BROWSER:
        journal_clock(day)
        observe(text, site, coverage, observed, None)
    journal_clock(20)
    for site, kinds in (("claude", {"EMAIL": 0}), ("gemini", {"JWT": "many"})):  # records only a hand could write: a zero, a count nobody can read
        observed.append(JournalEntry("observed", site, "unknown", 0, kinds, "sent", "cd" * 32, "checked", "", {"boxed": "0.1.0"}))
    keep(boxed_env, "chatgpt", "me@acme.com", "off", "off", "2026-10-21")
    keep(boxed_env, "claude", "work", "off", "off", "2026-08-01")
    keep(boxed_env, "gemini", "me", "unknown", "on", "2026-10-21")
    journal_clock(21)
    return boxed_env


def page_cards(page):
    return {label: int(n) for label, n in re.findall(r"<div class=card><span class=muted>([^<]*)</span><b>([0-9]+)</b></div>", page)}


def page_boxes(page):
    """Title -> [(name, count)] of every breakdown box of the page, in the order of its rows."""
    found = {}
    for title, table in re.findall(r"<div class=box><h2>([^<]*)</h2><table>(.*?)</table>", page, re.S):
        found[html.unescape(title)] = [
            (html.unescape(name), int(n)) for name, n in re.findall(r"<tr><td>([^<]*)</td><td class=n>([0-9]+)</td><td class=bar>", table)
        ]
    return found


def page_days(page):
    box = re.search(r"<h2>By day \(UTC\)</h2>(.*?)</div>", page, re.S).group(1)
    return [(day, int(cells.rsplit("<td class=n>", 1)[1].split("<")[0])) for day, cells in re.findall(r"<tr><td>([0-9-]+|unknown)</td>(.*?)</tr>", box)]


def page_section_text(page, name):
    found = re.search(rf"<section id={name}>(.*?)</section>", page, re.S)
    assert found, f"the page has no section {name}"
    return " ".join(html.unescape(re.sub(r"<[^>]*>", " ", found.group(1))).split())


def shown(items):
    """Counts as the page shows them: -1 is a restore, which has no level."""
    return [("n/a" if name == -1 else str(name), n) for name, n in items]


def dashboard_pair(session, capsys, tmp_path, **flags):
    """The reply of serve and the page and the table of boxed dashboard for the same days."""
    argv = ["dashboard", "--html", str(tmp_path / "page.html"), "--csv", str(tmp_path / "table.csv")]
    for name, value in flags.items():
        argv += [f"--{name}", value]
    code, _, err = run_cli(capsys, None, argv)
    assert code == 0
    return request(session, "dashboard", **flags), (tmp_path / "page.html").read_text(encoding="utf-8"), csv_of(tmp_path / "table.csv")[1], err


def csv_of(path):
    table = list(csv.reader(io.StringIO(path.read_bytes().decode("utf-8-sig"), newline="")))
    return table[0], [dict(zip(table[0], row, strict=True)) for row in table[1:]]


@pytest.mark.parametrize("flags", [{}, {"period": "day"}, {"period": "week"}, {"period": "month"}, {"since": "2026-10-15", "until": "2026-10-20"}, {"since": "2026-10-20"}, {"until": "2026-10-15"}],
                         ids=["all", "day", "week", "month", "since-until", "since", "until"])
def test_dashboard_shows_the_numbers_of_the_page_boxed_dashboard_writes(busy, session, capsys, tmp_path, flags):
    reply, page, table, _ = dashboard_pair(session, capsys, tmp_path, **flags)
    assert reply["ok"] is True
    summary = reply["summary"]
    cards = page_cards(page)
    assert (cards["Records"], cards["Sent"], cards["Blocked"], cards["Markers"]) == (
        summary["records"], summary["sent"], summary["blocked"], summary["markers"],
    )
    boxes = page_boxes(page)
    for title, key in (
        ("Markers by kind", "markers_by_kind"), ("By channel", "by_channel"), ("By provider", "by_provider"),
        ("By account type", "by_account_type"), ("By model", "by_model"), ("By status", "by_status"),
    ):
        assert boxes[title] == [(name, n) for name, n in summary[key]], title
    assert boxes["By level"] == shown(summary["by_level"])
    tokens = [("input", summary["tokens_in"]), ("output", summary["tokens_out"])] if summary["tokens_in"] or summary["tokens_out"] else []
    assert boxes["Tokens, as reported by the provider"] == tokens
    spend = re.search(r"<h2>Spend reported by the provider</h2><table><tr><td>([^<]*)</td><td class=muted>(\d+) records? reported a cost", page)
    assert (spend is not None) == (summary["spend_records"] > 0)
    if spend:
        assert (spend.group(1), int(spend.group(2))) == (dashboard._usd(summary["spend_micro_usd"]), summary["spend_records"])
    assert page_days(page) == [(day, sum(counts.values())) for day, counts in summary["by_day"]]
    if "period" not in flags:
        assert reply["period"] == {"since": flags.get("since"), "until": flags.get("until")}
    in_period = [r["seq"] for r in table]
    assert [row["seq"] for row in reversed(reply["rows"])] == [int(seq) for seq in in_period]  # newest first, the table in journal order
    assert re.findall(r"<tr><td class=nw>([0-9]+)</td><td class=nw>", page) == [str(row["seq"]) for row in reply["rows"]]
    assert reply["chain"] == {"ok": True, "count": len(HISTORY), "first_bad": None, "reason": "ok"} and "Chain OK" in page
    assert reply["damaged"] == 0


def test_dashboard_names_the_days_of_a_period_as_the_page_does(busy, session, capsys, tmp_path):
    for period, first in (("day", "2026-10-21"), ("week", "2026-10-15"), ("month", "2026-09-22")):
        reply, page, _, _ = dashboard_pair(session, capsys, tmp_path, period=period)
        assert reply["period"] == {"since": first, "until": "2026-10-21"} and f"Period: {first} to 2026-10-21." in " ".join(page.split())
    reply, page, _, _ = dashboard_pair(session, capsys, tmp_path)
    assert reply["period"] == {"since": None, "until": None} and "Period: all records." in page


def test_dashboard_has_the_sends_the_browser_saw_without_boxed(busy, session, capsys, tmp_path):
    reply, page, _, _ = dashboard_pair(session, capsys, tmp_path, since="2026-10-19", until="2026-10-20")
    seen = reply["observed"]
    cards = page_cards(page)
    assert (cards["Sends"], cards["Sends with findings"]) == (seen["sends"], seen["with_findings"]) == (5, 2)  # a zero is no finding
    boxes = page_boxes(page)
    assert (boxes["Kinds"], boxes["Sites"], boxes["Coverage"]) == (
        [tuple(i) for i in seen["kinds"]], [tuple(i) for i in seen["sites"]], [tuple(i) for i in seen["coverage"]],
    )
    assert seen["kinds"] == [["EMAIL", 2], ["SECRET", 1]] and seen["coverage"] == [["checked", 4], ["not checked", 1]]
    assert seen["sites"] == [["claude", 2], ["chatgpt", 1], ["deepseek", 1], ["gemini", 1]]
    text = page_section_text(page, "observed")
    assert seen["gaps"] == 2 and "2 sends could not be checked" in text  # one not checked, one with a count nobody can read
    assert seen["revoke"] == ["SECRET", "JWT"]  # a key kind whose count cannot be read still counts as sent, because it may have been
    assert "Revoke and replace the keys and tokens that were sent (SECRET, JWT)" in text
    assert seen["chain"] == {"ok": True, "count": 6, "first_bad": None, "reason": "ok"} and "Observation chain OK" in text
    assert seen["damaged"] == 0


def test_dashboard_without_a_send_seen_does_not_claim_nothing_was_sent(boxed_env, session, capsys, tmp_path, now):
    session.context()
    reply, page, _, _ = dashboard_pair(session, capsys, tmp_path)
    seen = reply["observed"]
    assert (seen["sends"], seen["with_findings"], seen["gaps"], seen["revoke"], seen["kinds"]) == (0, 0, 0, [], [])
    assert "No sends were observed in this period. This is not proof that nothing was sent" in page_section_text(page, "observed")
    assert reply["summary"]["records"] == 0 and reply["rows"] == [] and reply["chain"]["ok"] is True


def test_dashboard_says_when_the_observation_log_or_the_journal_is_damaged_or_broken(busy, session, capsys, tmp_path):
    with (busy / "observed.jsonl").open("a") as f:
        f.write('{"seq": 5, "torn\n')
    with (busy / "journal.jsonl").open("a") as f:
        f.write('{"seq": 9, "torn\n')
    reply, page, _, err = dashboard_pair(session, capsys, tmp_path)
    assert reply["damaged"] == 1 and reply["observed"]["damaged"] == 1
    assert (reply["chain"]["ok"], reply["observed"]["chain"]["ok"]) == (False, False)
    assert "Chain BROKEN" in page and "Observation chain BROKEN" in page and "1 damaged line skipped" in err
    assert dashboard._cut(reply["chain"]["reason"]) in page  # the page cuts every text taken from a record at 64 characters
    assert reply["summary"]["records"] == len(HISTORY)  # the whole records are counted


def test_dashboard_has_the_checks_the_page_has_and_says_when_they_cannot_be_read(busy, session, capsys, tmp_path):
    reply, page, _, _ = dashboard_pair(session, capsys, tmp_path)
    assert [(c["provider"], c["account"], c["due"]) for c in reply["checks"]] == [("chatgpt", "me@acme.com", False), ("claude", "work", True), ("gemini", "me", True)]
    text = page_section_text(page, "checks")
    rows = " ".join(
        f"{c['provider']} {c['account']} {c['training']} {c['memory']} {c['source']} {c['checked_at']} {c['settings_url'] or '-'}" + (" due" if c["due"] else "")
        for c in reply["checks"]
    )
    assert rows in text
    assert reply["checks"][1]["settings_url"] == "https://claude.ai/settings/data-privacy-controls"
    damage(busy, b"\x00garbage")
    reply, page, _, _ = dashboard_pair(session, capsys, tmp_path)
    assert reply["ok"] is True and reply["checks"] is None  # None is not "none recorded"
    assert "could not be read" in page_section_text(page, "checks")


@pytest.mark.parametrize("profile", PROFILES)
def test_dashboard_has_the_policy_matrix_of_the_page(busy, session, capsys, tmp_path, monkeypatch, profile):
    write_profile(busy, profile)
    monkeypatch.chdir(busy)
    reply, page, _, _ = dashboard_pair(session, capsys, tmp_path)
    policy = reply["policy"]
    assert policy["categories"] == list(CATEGORIES) and policy["recipients"] == list(RECIPIENT_KINDS)
    text = page_section_text(page, "policy")
    for category in policy["categories"]:
        assert f"{category} " + " ".join(policy["rules"][category][kind] for kind in policy["recipients"]) in text
    assert {row["local"] for row in policy["rules"].values()} == {"allow"}


def test_dashboard_is_the_data_of_the_page_and_nothing_more(busy, session):
    """Kinds, counts and names: no value of a text, no hash, no signature, no scope of a conversation."""
    reply = request(session, "dashboard")
    blob = json.dumps(reply)
    for hidden_thing in ("ivan", "AKIA", "ab" * 32, '"sig"', '"hash"', '"prev_hash"', "d14", "d21", "payload"):
        assert hidden_thing not in blob, hidden_thing


def test_dashboard_reads_boxed_toml_for_the_policy_only(busy, session):
    (busy / "boxed.toml").write_text("[boxed\n")
    assert request(session, "dashboard") == {"id": 1, "ok": False, "error": "boxed.toml cannot be read"}
    (busy / "boxed.toml").write_text('[boxed.policy]\nprofile = "ban"\n')
    assert request(session, "dashboard")["policy"]["rules"]["secrets"]["corporate"] == "deny"


def test_dashboard_with_a_journal_that_is_not_a_file_is_a_fixed_error(busy, session):
    (busy / "journal.jsonl").unlink()
    (busy / "journal.jsonl").mkdir()
    assert request(session, "dashboard") == {"id": 1, "ok": False, "error": "the journal file is not a regular file"}


def test_dashboard_lists_at_most_the_newest_500_rows(boxed_env, session, journal_clock, now):
    ctx = session.context()
    for _ in range(503):
        ctx.journal.append(record("manual", "unknown", "unknown", 2, {}, "prepared", "s"))
    reply = request(session, "dashboard")
    assert reply["summary"]["records"] == 503 and len(reply["rows"]) == 500
    assert [row["seq"] for row in reply["rows"]][:2] == [503, 502] and reply["rows"][-1]["seq"] == 4


BAD_DASHBOARDS = [
    {"period": "year"},
    {"period": "Week"},
    {"period": 7},
    {"period": ["week"]},
    {"period": "week", "since": "2026-10-01"},
    {"period": "week", "until": "2026-10-01"},
    {"since": "yesterday"},
    {"since": "2026-13-01"},
    {"until": "2026-10-20T12:00"},
    {"until": 20261020},
    {"html": "/x/d.html"},
    {"out": "/x/d.html"},
]


@pytest.mark.parametrize("fields", BAD_DASHBOARDS, ids=[json.dumps(m) for m in BAD_DASHBOARDS])
def test_dashboard_refuses_what_is_not_a_request_before_anything_is_made(boxed_env, session, fields):
    assert request(session, "dashboard", **fields) == {"id": 1, "ok": False, "error": "bad request"}
    assert not boxed_env.exists()


# ---- the journal comes before anything leaves: the reply, a request to a provider ----


def journaling_requests(world):
    """One request of every command that writes a record in the journal."""
    return {
        "mask": {"id": 1, "cmd": "mask", "text": TEXT, "scope": "j1"},
        "restore": {"id": 1, "cmd": "restore", "text": MASKED, "scope": "f1"},
        "mask-file": {"id": 1, "cmd": "mask-file", "src": str(world.src), "dest": str(world.folder / "j.csv"), "scope": "j2"},
        "restore-file": {"id": 1, "cmd": "restore-file", "src": str(world.masked), "dest": str(world.folder / "jr.csv"), "scope": "f1"},
        "plan-prompt": {"id": 1, "cmd": "plan-prompt", "task": "top clients", "table": str(world.table), "scope": "j3"},
        "plan-run": {"id": 1, "cmd": "plan-run", "plan": PLAN, "table": str(world.table), "scope": "p1"},
        "ask": {"id": 1, "cmd": "ask", "text": ASK_TEXT, "provider": "openai", "model": "gpt-test", "scope": "j4"},
    }


@pytest.mark.parametrize("command", ["mask", "restore", "mask-file", "restore-file", "plan-prompt", "plan-run", "ask"])
def test_every_command_that_is_journaled_writes_its_record_before_the_reply_leaves(command, world, session, openai_api, monkeypatch):
    events = []
    real = Journal.append

    def spy(self, entry):
        events.append("journal")
        return real(self, entry)

    class Recording(io.BytesIO):
        def write(self, data):
            events.append("reply")
            return super().write(data)

    with monkeypatch.context() as spying:
        spying.setattr(Journal, "append", spy)
        stdin, stdout = io.BytesIO(frames(journaling_requests(world)[command])), Recording()
        assert serve(stdin, stdout, session) == 0
    assert replies(stdout.getvalue())[0]["ok"] is True
    assert events[-1] == "reply" and events.count("reply") == 1 and "journal" in events[:-1], events
    assert set(events[:-1]) == {"journal"}


def test_ask_writes_the_sent_record_before_the_request_reaches_the_provider_and_the_received_one_before_the_reply(session, start_api, monkeypatch, boxed_env):
    events = []
    api = start_api(body=answer())
    real_append = Journal.append

    def spy(self, entry):
        events.append(f"journal {entry.status}")
        return real_append(self, entry)

    class Recording(io.BytesIO):
        def write(self, data):
            events.append("reply")
            return super().write(data)

    class Watching(list):
        def append(self, item):
            events.append("request")
            super().append(item)

    api.requests = Watching()
    monkeypatch.setitem(PROVIDERS, "openai", replace(PROVIDERS["openai"], base_url=api.url))
    monkeypatch.setenv("OPENAI_API_KEY", KEY)
    with monkeypatch.context() as spying:
        spying.setattr(Journal, "append", spy)
        stdin = io.BytesIO(frames({"id": 1, "cmd": "ask", "text": ASK_TEXT, "provider": "openai", "model": "gpt-test"}))
        assert serve(stdin, Recording(), session) == 0
    assert events == ["journal sent", "request", "journal received", "reply"]


# ---- the models: loaded from the local cache and never from the hub; a model that is not there is said in fixed words ----

NER_RU_EXTRA = "the Russian name detector needs the ner-ru extra, which is not installed"
NER_EN_EXTRA = "the English name detector needs the ner-en extra, which is not installed"
NER_EN_MODEL = "the model of the ner-en extra is not in the local cache, and the program does not go online to fetch it"


@pytest.fixture
def broken_detector(monkeypatch, boxed_env):
    """fail(name, error): the detector of "ru" (Natasha) or "en" (GLiNER) raises `error` when it is built, as it does when the extra
    or the model is not there. boxed.toml asks for that detector."""
    from boxed import config

    def fail(name, error):
        def build(*args, **kwargs):
            raise error

        monkeypatch.setattr(ner, "NatashaDetector" if name == "ru" else "GlinerDetector", build)
        config._ner_detectors.cache_clear()
        boxed_env.mkdir(parents=True, exist_ok=True)
        (boxed_env / "boxed.toml").write_text(f'[boxed]\nner = ["{name}"]\n')

    yield fail
    config._ner_detectors.cache_clear()


def test_the_program_never_goes_to_the_hub_for_a_model_whatever_the_person_set(run_main, monkeypatch):
    for name in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE"):
        monkeypatch.setenv(name, "0")  # even a variable of the person's own: a window must never wait for a download
    run_main({"id": 1, "cmd": "ping"})
    assert os.environ["HF_HUB_OFFLINE"] == "1" and os.environ["TRANSFORMERS_OFFLINE"] == "1"


READING = ["mask", "mask-file", "policy-check", "plan-prompt", "ask"]


@pytest.mark.parametrize("command", READING)
@pytest.mark.parametrize(
    ("name", "error", "said"),
    [
        ("ru", ModuleNotFoundError("No module named 'natasha'", name="natasha"), NER_RU_EXTRA),
        ("en", ModuleNotFoundError("No module named 'gliner'", name="gliner"), NER_EN_EXTRA),
        ("en", ModuleNotFoundError("No module named 'torch'", name="torch"), NER_EN_EXTRA),
        ("en", OSError("We couldn't connect to 'https://huggingface.co' to load this file ivan.petrov@acme.com"), NER_EN_MODEL),
        ("en", FileNotFoundError("Cannot find an appropriate cached snapshot folder for the specified revision"), NER_EN_MODEL),
    ],
    ids=["natasha missing", "gliner missing", "torch missing", "model not cached", "snapshot not found"],
)
def test_a_detector_that_cannot_be_built_is_a_fixed_error_that_names_the_extra_and_nothing_is_made(
    command, name, error, said, broken_detector, world, home, session, openai_api
):
    broken_detector(name, error)
    before = sorted(path.name for path in home.iterdir())
    reply = handle(reading_requests(world)[command], session)
    assert reply == {"id": 1, "ok": False, "error": said}
    assert openai_api.requests == [] and not (world.folder / "n.csv").exists() and hidden(world.folder) == []
    assert sorted(path.name for path in home.iterdir()) == before  # no scope, no record, no log line: it is not a fault of the program
    assert "ivan" not in json.dumps(reply)


@pytest.mark.parametrize("name", ["ru", "en"])
def test_a_detector_that_fails_for_any_other_reason_is_still_an_internal_error(name, broken_detector, session, boxed_env):
    broken_detector(name, RuntimeError("could not load ivan.petrov@acme.com"))
    assert request(session, "mask", text=TEXT, scope="s") == {"id": 1, "ok": False, "error": "internal error"}
    assert "RuntimeError" in (boxed_env / "host-errors.log").read_text() and "ivan" not in (boxed_env / "host-errors.log").read_text()


def test_the_real_program_asks_the_hub_for_nothing_and_says_what_is_missing(live, boxed_env, tmp_path):
    """GLiNER with an empty cache of models: with the hub reachable it would start a download. A proxy that counts what reaches it
    stands where the hub would be; nothing may."""
    pytest.importorskip("gliner")
    reached = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.2)
    done = threading.Event()

    def count():
        while not done.is_set():
            try:
                connection = listener.accept()[0]
            except OSError:
                continue
            reached.append(1)
            with contextlib.suppress(OSError):  # a proxy that cuts the connection, fast, so that a program that does call fails at once
                connection.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            connection.close()

    threading.Thread(target=count, daemon=True).start()
    try:
        boxed_env.mkdir(parents=True)
        (boxed_env / "boxed.toml").write_text('[boxed]\nner = ["en"]\n')
        proxy = f"http://127.0.0.1:{listener.getsockname()[1]}"
        env = {
            "HF_HOME": str(tmp_path / "empty-cache"), "HF_HUB_OFFLINE": "0", "TRANSFORMERS_OFFLINE": "0",
            "HTTPS_PROXY": proxy, "HTTP_PROXY": proxy, "https_proxy": proxy, "http_proxy": proxy, "NO_PROXY": "", "no_proxy": "",
        }
        sidecar = live(START, env)
        assert sidecar.ask({"id": 1, "cmd": "mask", "text": TEXT, "scope": "s"}) == {"id": 1, "ok": False, "error": NER_EN_MODEL}
        assert sidecar.close() == 0
    finally:
        done.set()
        listener.close()
    assert reached == []


# ---- whatever a request holds, an error says none of it ----

SENTINEL = "QQ-sentinel-QQ"
FIELD_NAMES = sorted({field for fields, _ in serve_module._COMMANDS.values() for field in fields} | {"extra"})


def junk(folder: Path):
    """A value that a request could hold in any field: of every type, with the sentinel here and there, names of places in the
    folder of the test, and words the commands know."""
    return st.one_of(
        st.none(),
        st.booleans(),
        st.integers(-5, 12),
        st.floats(allow_nan=False),
        st.text(max_size=30),
        st.just(SENTINEL),
        st.builds(lambda tail: SENTINEL + tail, st.text(max_size=5)),
        st.sampled_from(
            ["openai", "chatgpt", "off", "on", "week", "2026-10-01", "openai:personal-private:US", "finance", "[EMAIL_1]", ".", ",", "auto", "s1", "p1"]
        ),
        st.builds(lambda name: str(folder / name), st.text(alphabet="abcdef._-", max_size=8)),
        st.just(str(folder / SENTINEL)),
        st.lists(st.text(max_size=8) | st.just(SENTINEL), max_size=3),
    )


def good_requests(world, folder: Path) -> dict[str, dict]:
    """One request that works for every command: the fuzz starts from these, so that it gets past the checks of the shape."""
    provider = {"provider": "openai"}
    account = {"provider": "claude", "account": "me"}
    return {
        "ping": {},
        "mask": {"text": TEXT, "scope": "z1", "level": 2},
        "restore": {"text": MASKED, "scope": "f1"},
        "mask-file": {"src": str(world.src), "dest": str(folder / "z.csv"), "scope": "z2", "level": 2, "replace": True},
        "restore-file": {"src": str(world.masked), "dest": str(folder / "zr.csv"), "scope": "f1", "force": False, "replace": True},
        "policy-check": {"text": TEXT, "recipient": "openai:personal-private:US", "categories": ["finance"]},
        "plan-prompt": {"task": "top clients", "table": str(world.table), "scope": "z3", "decimal": "auto", "header_ok": False},
        "plan-run": {"plan": PLAN, "table": str(world.table), "scope": "p1", "out": str(folder / "zo.csv"), "chart_out": str(folder / "zc.json"), "replace": True},
        "ask": {"text": ASK_TEXT, "provider": "openai", "model": "gpt-test", "account": "corporate", "scope": "z4", "level": 2, "categories": ["hr"]},
        "key-status": provider,
        "key-set": {**provider, "key": KEY},
        "key-remove": provider,
        "checks": {},
        "check-set": {**account, "training": "off", "memory": "on"},
        "check-remove": account,
        "check-reset": {},
        "journal-verify": {},
        "journal-export": {"out": str(folder / "ze.json"), "since": "2026-10-01", "until": "2026-10-31", "replace": True},
        "dashboard": {"period": "week"},
    }


@settings(max_examples=600, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(data=st.data())
def test_no_request_makes_an_error_that_quotes_it_or_a_crash(data, world, session):
    folder = world.folder / "fuzz"
    folder.mkdir(exist_ok=True)
    good = good_requests(world, folder)
    assert set(good) == set(serve_module._COMMANDS)  # a new command gets a request here
    command = data.draw(st.sampled_from(sorted(good)))
    fields = dict(good[command])
    for name in data.draw(st.sets(st.sampled_from(sorted(fields)), max_size=2)) if fields else ():
        del fields[name]
    fields.update(data.draw(st.dictionaries(st.sampled_from(FIELD_NAMES), junk(folder), max_size=3)))
    request_id = data.draw(st.one_of(st.integers(0, 2**64), st.text(max_size=5), st.none()))
    reply = handle({"id": request_id, "cmd": command, **fields}, session)
    assert set(reply) >= {"id", "ok"} and type(reply["ok"]) is bool
    if not reply["ok"]:
        assert reply["error"] != "internal error", (command, fields)  # a malformed request is refused, it does not break a command
        assert SENTINEL not in json.dumps(reply, ensure_ascii=False), (command, fields)
        assert len(reply["error"]) < 200 and reply["error"].isprintable()
    json.dumps(reply)  # whatever the reply holds, it can be sent


# ---- nothing of a text outlasts its request: the tokenizer cache of the language model, and what the process holds ----


def reading_requests(world):
    """One request of every command that reads a text with the detectors."""
    return {
        "mask": {"id": 1, "cmd": "mask", "text": TEXT, "scope": "n1"},
        "mask-file": {"id": 1, "cmd": "mask-file", "src": str(world.src), "dest": str(world.folder / "n.csv"), "scope": "n2"},
        "policy-check": {"id": 1, "cmd": "policy-check", "text": TEXT, "recipient": "openai:personal-private:US"},
        "plan-prompt": {"id": 1, "cmd": "plan-prompt", "task": "top clients, mail ivan@acme.com", "table": str(world.table), "scope": "n3"},
        "ask": {"id": 1, "cmd": "ask", "text": ASK_TEXT, "provider": "openai", "model": "gpt-test", "scope": "n4"},
    }


@pytest.mark.parametrize("command", ["mask", "mask-file", "policy-check", "plan-prompt", "ask"])
def test_every_command_that_reads_a_text_empties_the_tokenizer_cache_and_the_process_stays_up(command, world, home, session, openai_api, gliner_stand_in):
    emptied = gliner_stand_in(can_empty=True)
    (home / "boxed.toml").write_text('[boxed]\nner = ["en"]\n')
    code, out = run_serve(session, reading_requests(world)[command], {"id": 9, "cmd": "ping"})
    assert code == 0 and [reply["ok"] for reply in out] == [True, True]
    assert len(emptied) >= 1  # once for every text that was read


@pytest.mark.parametrize("command", ["mask", "mask-file", "policy-check", "plan-prompt", "ask"])
def test_every_command_that_reads_a_text_ends_the_process_when_the_cache_cannot_be_emptied(command, world, home, session, openai_api, gliner_stand_in):
    gliner_stand_in(can_empty=False)
    (home / "boxed.toml").write_text('[boxed]\nner = ["en"]\n')
    stdin, stdout = io.BytesIO(frames(reading_requests(world)[command], {"id": 9, "cmd": "ping"})), io.BytesIO()
    assert serve(stdin, stdout, session) == 0
    [answer_] = replies(stdout.getvalue())
    assert answer_["ok"] is True and stdin.read() != b""  # the ping was not read: the shell starts the program again for it


def test_the_session_and_the_modules_hold_no_text_after_a_request_of_every_command(world, home, session, openai_api):
    marked = f"{UNIQUE}-"
    (world.folder / "unique.csv").write_text(f"name,email\n{marked}file,ivan.petrov@acme.com\n")
    (world.folder / "answer.csv").write_text(f"name,email\n{marked}answer,[EMAIL_1]\n")
    (world.folder / "t.csv").write_text(f"client;value\n{marked}client;1\n")
    plan = '{"version": 1, "steps": [{"op": "filter", "column": "client", "cmp": "contains", "value": "' + marked + 'plan"}]}'
    openai_api.body = answer(f"Dear [EMAIL_1], {marked}answer")
    stdin = io.BytesIO(
        frames(
            {"id": 1, "cmd": "mask", "text": f"{TEXT} {marked}text", "scope": "u1"},
            {"id": 2, "cmd": "restore", "text": f"mail [EMAIL_1] {marked}restore", "scope": "u1"},
            {"id": 3, "cmd": "mask-file", "src": str(world.folder / "unique.csv"), "dest": str(world.folder / "unique.masked.csv"), "scope": "u2"},
            {"id": 4, "cmd": "restore-file", "src": str(world.folder / "answer.csv"), "dest": str(world.folder / "answer.restored.csv"), "scope": "u2"},
            {"id": 5, "cmd": "policy-check", "text": f"{TEXT} {marked}policy", "recipient": "openai:personal-private:US"},
            {"id": 6, "cmd": "plan-prompt", "task": f"{marked}task", "table": str(world.folder / "t.csv"), "scope": "u3"},
            {"id": 7, "cmd": "plan-run", "plan": plan, "table": str(world.folder / "t.csv"), "scope": "u3"},
            {"id": 8, "cmd": "ask", "text": f"{ASK_TEXT} {marked}ask", "provider": "openai", "model": "gpt-test", "scope": "u4"},
            {"id": 9, "cmd": "key-set", "provider": "openai", "key": KEY},
        )
    )
    stdout = io.BytesIO()
    assert serve(stdin, stdout, session) == 0
    assert [reply["ok"] for reply in replies(stdout.getvalue())] == [True] * 9
    stdin = stdout = None
    gc.collect()
    modules = [vars(module) for name, module in list(sys.modules.items()) if name.startswith("boxed") and module is not None]
    for needle in [UNIQUE, "ivan.petrov", KEY]:
        for place, root in (("the session", session), ("the modules", modules)):
            held = [s for s in held_strings(root) if (needle in s if isinstance(s, str) else needle.encode() in s)]
            assert not held, f"{needle!r} is still held in {place}"


def test_stderr_of_the_real_process_never_carries_a_request(live, tmp_path):
    sidecar = live()
    marked = f"{UNIQUE}-stderr"
    assert sidecar.ask({"id": 1, "cmd": "mask", "text": f"{TEXT} {marked}", "scope": "e1"})["ok"] is True
    assert sidecar.ask({"id": 2, "cmd": "restore", "text": f"[EMAIL_1] {marked}", "scope": "e1"})["ok"] is True
    assert sidecar.ask({"id": 3, "cmd": "restore", "text": f"[EMAIL_1] {marked}", "scope": "nope"})["error"] == "unknown scope"
    assert sidecar.ask({"id": 4, "cmd": "mask", "text": f"{TEXT} {marked}", "scope": "bad scope"})["error"] == "bad request"
    assert sidecar.close() == 0
    assert (tmp_path / "live0.err").read_bytes() == b""


def test_sigterm_while_a_provider_is_slow_ends_the_process_at_once_and_the_journal_says_what_happened(live, start_api, monkeypatch, tmp_path):
    api = start_api(body=answer(), delay=30)  # a provider that does not answer in time
    monkeypatch.setenv("OPENAI_API_KEY", KEY)
    monkeypatch.setenv("BOXED_OPENAI_BASE_URL", api.url)  # the real program talks to this server through the relay setting
    sidecar = live()
    sidecar.send({"id": 1, "cmd": "ask", "text": ASK_TEXT, "provider": "openai", "model": "gpt-test", "scope": "term"})
    deadline = time.monotonic() + 60
    while not api.requests and time.monotonic() < deadline:
        time.sleep(0.02)
    assert api.requests, "the request never reached the provider"
    sidecar.process.send_signal(signal.SIGTERM)  # the app quits while the answer is on its way
    assert sidecar.process.wait(timeout=10) == 0  # not after the 30 seconds of the provider
    assert sidecar.read() is None  # no answer: nobody is left to read it
    assert (tmp_path / "live0.err").read_text().startswith("boxed: sending through the relay at ")  # the notice of the relay, and no traceback
    assert "Traceback" not in (tmp_path / "live0.err").read_text()
    records = [json.loads(line) for line in (tmp_path / "boxed-home" / "journal.jsonl").read_text().splitlines()]
    assert [r["status"] for r in records] == ["sent"]  # the send is recorded, and no answer came: nothing is half written


SLOW_FILE = """
import sys, time
from boxed import serve
def slow(*args, **kwargs):
    time.sleep(120)  # a converter that takes its time, inside the part folder
serve.formats.mask_file = slow
sys.exit(serve.main())
"""


def test_sigterm_in_the_middle_of_a_file_ends_the_process_at_once_and_leaves_no_part_folder(live, tmp_path):
    folder = tmp_path / "work"
    folder.mkdir()
    src, dest = folder / "in.csv", folder / "out.csv"
    src.write_text(CLIENTS)
    sidecar = live(SLOW_FILE)
    sidecar.send({"id": 1, "cmd": "mask-file", "src": str(src), "dest": str(dest), "scope": "term"})
    deadline = time.monotonic() + 60
    while not hidden(folder) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert hidden(folder), "the program never began on the file"
    sidecar.process.send_signal(signal.SIGTERM)
    assert sidecar.process.wait(timeout=10) == 0
    assert sidecar.read() is None
    assert hidden(folder) == [] and not dest.exists()  # the part folder went with the request
    assert (tmp_path / "live0.err").read_bytes() == b""


# ---- part folders: written down while they exist, so that the start after a kill can remove what the kill left ----


def dead_pid() -> int:
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait()
    return child.pid


def leave_part(boxed_env, folder: Path, *, pid: int, age: float = 0, name: str = ".boxed-part-abc123") -> tuple[Path, Path]:
    """A part folder with half a file in it, and the record that a process with this number writes while it makes the folder."""
    part = folder / name
    part.mkdir(parents=True)
    (part / "out.csv").write_text("half of a file")
    registry = boxed_env / serve_module.PARTS
    registry.mkdir(parents=True, exist_ok=True)
    record = registry / f"{pid}.test"
    record.write_text(str(part))
    if age:
        os.utime(record, (time.time() - age, time.time() - age))
    return part, record


def test_the_part_folder_of_a_process_that_is_gone_is_removed_at_start(boxed_env, tmp_path):
    part, record = leave_part(boxed_env, tmp_path / "work", pid=dead_pid())
    serve_module.clear_stale_parts()
    assert not part.exists() and not record.exists()


def test_the_part_folder_of_a_process_that_is_still_there_is_left_alone(boxed_env, tmp_path):
    part, record = leave_part(boxed_env, tmp_path / "work", pid=os.getppid())
    serve_module.clear_stale_parts()
    assert (part / "out.csv").read_text() == "half of a file" and record.exists()


def test_a_record_that_is_over_an_hour_old_is_stale_whoever_wrote_it(boxed_env, tmp_path):
    """Windows cannot be asked whether a process is there, and a number can be taken by another process since."""
    part, record = leave_part(boxed_env, tmp_path / "work", pid=os.getppid(), age=3601)
    serve_module.clear_stale_parts()
    assert not part.exists() and not record.exists()


def test_a_process_does_not_remove_what_it_is_making_itself(boxed_env, tmp_path):
    part, record = leave_part(boxed_env, tmp_path / "work", pid=os.getpid(), age=3601)
    serve_module.clear_stale_parts()
    assert part.exists() and record.exists()


def test_only_a_part_folder_is_ever_removed(boxed_env, tmp_path):
    """A record names a path; whatever the path is, it is removed only if it is a folder made by outputs.staging."""
    pid = dead_pid()
    work = tmp_path / "work"
    precious = work / "precious"
    precious.mkdir(parents=True)
    (precious / "keep.txt").write_text("mine")
    target = work / "target"
    target.mkdir()
    (target / "keep.txt").write_text("mine")
    (work / ".boxed-part-file").write_text("a plain file")
    (work / ".boxed-part-link").symlink_to(target, target_is_directory=True)
    registry = boxed_env / serve_module.PARTS
    registry.mkdir(parents=True)
    named = {"other-name": precious, "a-file": work / ".boxed-part-file", "a-link": work / ".boxed-part-link", "the-home": boxed_env}
    for label, path in named.items():
        (registry / f"{pid}.{label}").write_text(str(path))
    (registry / f"{pid}.relative").write_text(".boxed-part-x")  # not absolute
    (registry / f"{pid}.empty").write_text("")
    (registry / "junk").write_text(str(precious))  # no number in front
    serve_module.clear_stale_parts()
    assert (precious / "keep.txt").read_text() == "mine" and (target / "keep.txt").read_text() == "mine"
    assert (work / ".boxed-part-file").read_text() == "a plain file" and (work / ".boxed-part-link").is_symlink()
    assert boxed_env.is_dir() and list(registry.iterdir()) == []  # the records of this are junk, and gone


def test_a_record_of_a_folder_that_is_gone_is_just_removed(boxed_env, tmp_path):
    part, record = leave_part(boxed_env, tmp_path / "work", pid=dead_pid())
    shutil.rmtree(part)
    serve_module.clear_stale_parts()
    assert not record.exists()


def test_nothing_to_clear_without_a_registry(boxed_env):
    serve_module.clear_stale_parts()  # no folder, no home: no error


def test_a_part_folder_is_written_down_while_it_exists_and_not_after(world, session, boxed_env, monkeypatch):
    seen = []
    real = serve_module.formats.mask_file

    def looking(src, part, markers, **kwargs):
        registry = boxed_env / serve_module.PARTS
        seen.append({record.name.split(".")[0]: record.read_text() for record in registry.iterdir()})
        seen.append(str(part.parent))
        return real(src, part, markers, **kwargs)

    monkeypatch.setattr(serve_module.formats, "mask_file", looking)
    assert mask_file(session, world, world.folder / "out.csv")["ok"] is True
    records, folder = seen
    assert records == {str(os.getpid()): folder} and Path(folder).name.startswith(".boxed-part-")
    registry = boxed_env / serve_module.PARTS
    assert not registry.exists() or list(registry.iterdir()) == []  # the folder is gone, and so is the note of it


def test_every_output_of_the_program_is_written_down_while_its_part_folder_exists(world, home, session, monkeypatch):
    noted = []
    real = serve_module._note

    def spy(folder):
        noted.append(folder.name)
        return real(folder)

    monkeypatch.setattr(serve_module, "_note", spy)
    assert mask_file(session, world, world.folder / "out.csv")["ok"] is True
    assert restore_file(session, world, world.folder / "back.csv")["ok"] is True
    plan = request(session, "plan-run", plan=PLAN, table=str(world.table), scope="p1", out=str(world.folder / "r.csv"), chart_out=str(world.folder / "c.json"))
    assert plan["ok"] is True
    assert request(session, "journal-export", out=str(world.folder / "j.json"))["ok"] is True
    assert len(noted) == 5 and all(name.startswith(".boxed-part-") for name in noted)


def test_a_process_killed_in_the_middle_of_a_file_leaves_a_part_folder_that_the_next_start_removes(live, tmp_path):
    folder = tmp_path / "work"
    folder.mkdir()
    src, dest = folder / "in.csv", folder / "out.csv"
    src.write_text(CLIENTS)
    first = live(SLOW_FILE)
    first.send({"id": 1, "cmd": "mask-file", "src": str(src), "dest": str(dest), "scope": "kill"})
    deadline = time.monotonic() + 60
    while not hidden(folder) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert hidden(folder), "the program never began on the file"
    first.process.kill()  # the shell gave up after 120 s: no handler runs
    first.process.wait()
    assert hidden(folder), "a kill leaves the part folder behind"
    second = live()
    assert second.ask({"id": 1, "cmd": "ping"})["ok"] is True  # the start has cleared the folder before it served
    assert hidden(folder) == []
    assert second.close() == 0


# ---- the vault lock: a wait that has an end, so that a busy or hung process does not stop the next one for ever ----

BUSY = "boxed is busy with another request: try again in a moment"


@pytest.fixture(params=["posix", "windows, fake msvcrt"])
def timed_lock_branch(request, monkeypatch):
    if request.param == "posix":
        if sys.platform == "win32":
            pytest.skip("needs fcntl")
        monkeypatch.setattr(boxed_platform, "IS_WINDOWS", False)
    else:
        request.getfixturevalue("fake_msvcrt")
    return request.param


def test_a_lock_that_another_holds_is_given_up_after_the_time_it_was_asked_to_wait(timed_lock_branch, tmp_path):
    path = tmp_path / "x.lock"
    first, second = os.open(path, os.O_RDWR | os.O_CREAT, 0o600), os.open(path, os.O_RDWR)
    try:
        boxed_platform.lock_exclusive(first)
        started = time.monotonic()
        with pytest.raises(boxed_platform.LockTimeout) as gave_up:
            boxed_platform.lock_exclusive(second, timeout=0.3)
        assert 0.3 <= time.monotonic() - started < 5
        assert isinstance(gave_up.value, TimeoutError)  # an OSError: code that catches OSError for a lock still does
        boxed_platform.unlock(first)
        boxed_platform.lock_exclusive(second, timeout=0.3)  # free now: taken at once
        boxed_platform.unlock(second)
    finally:
        os.close(first)
        os.close(second)


def test_a_lock_without_a_time_to_wait_waits_as_it_did(timed_lock_branch, tmp_path):
    path = tmp_path / "x.lock"
    first, second = os.open(path, os.O_RDWR | os.O_CREAT, 0o600), os.open(path, os.O_RDWR)
    got = threading.Event()

    def take():
        boxed_platform.lock_exclusive(second)
        got.set()

    try:
        boxed_platform.lock_exclusive(first)
        threading.Thread(target=take, daemon=True).start()
        assert not got.wait(0.5)  # no end to this wait
        boxed_platform.unlock(first)
        assert got.wait(5)
        boxed_platform.unlock(second)
    finally:
        os.close(first)
        os.close(second)


def test_file_lock_with_a_time_gives_up_and_a_free_lock_is_taken(tmp_path):
    from boxed.locks import file_lock

    with file_lock(tmp_path / "data.json"):
        with pytest.raises(boxed_platform.LockTimeout):
            with file_lock(tmp_path / "data.json", timeout=0.2):
                pytest.fail("the lock was taken while another held it")
    with file_lock(tmp_path / "data.json", timeout=0.2):  # let go: taken
        pass


def test_the_vault_of_a_session_waits_for_its_lock_a_limited_time(boxed_env):
    assert serve_module.VAULT_WAIT < 120  # the shell gives up on a request after 120 s: the answer must come first
    assert Session().context().vault.lock_timeout == serve_module.VAULT_WAIT


BUSY_REQUESTS = {
    "mask": {"text": "mail ivan@acme.com", "scope": "busy1"},
    "mask-file": {"src": "<src>", "dest": "<dest>", "scope": "busy2"},
    "plan-prompt": {"task": "top clients", "table": "<table>", "scope": "busy3"},
    "ask": {"text": "write to ivan@acme.com", "provider": "openai", "model": "gpt-test", "scope": "busy4"},
}


@pytest.mark.parametrize("cmd", list(BUSY_REQUESTS))
def test_a_vault_that_another_process_holds_is_a_busy_error_and_not_a_wait_for_ever(cmd, world, session, home, monkeypatch):
    from boxed.locks import file_lock

    monkeypatch.setenv("OPENAI_API_KEY", KEY)
    fields = {key: str(world.src) if value == "<src>" else str(world.folder / "out.csv") if value == "<dest>" else str(world.table) if value == "<table>" else value for key, value in BUSY_REQUESTS[cmd].items()}
    vault = session.context().vault
    vault.lock_timeout = 0.3  # the real wait is serve_module.VAULT_WAIT
    before = journal_of(home)
    with file_lock(vault.path):  # a process that is busy, or hangs, inside a transaction
        started = time.monotonic()
        assert request(session, cmd, **fields) == {"id": 1, "ok": False, "error": BUSY}
        assert time.monotonic() - started < 10
    assert journal_of(home) == before and not (world.folder / "out.csv").exists() and hidden(world.folder) == []
    if cmd != "ask":  # (an ask that goes through would reach for a provider)
        assert request(session, cmd, **fields)["ok"] is True  # let go: the same request is no longer busy


def test_only_the_wait_for_a_lock_is_busy_any_other_timeout_is_not(session, monkeypatch):
    def slow(message, session):
        raise TimeoutError("a provider did not answer")

    monkeypatch.setitem(serve_module._COMMANDS, "ping", (frozenset(), slow))
    reply = request(session, "ping")
    assert reply == {"id": 1, "ok": False, "error": "the file cannot be read or written"} and BUSY not in json.dumps(reply)




# ---- which name detectors run: those of boxed.toml, and those this process was switched on to run (BOXED_SERVE_NER) ----


def only_installed(monkeypatch, *libraries: str) -> None:
    """Only these libraries of the extras are found: natasha is ner-ru, gliner is ner-en."""
    real = importlib.util.find_spec

    def find_spec(name, *args, **kwargs):
        if name in ("natasha", "gliner"):
            return object() if name in libraries else None
        return real(name, *args, **kwargs)

    monkeypatch.setattr(importlib.util, "find_spec", find_spec)


def test_ping_tells_the_name_detectors_that_run_and_the_extras_that_are_installed(session, monkeypatch):
    only_installed(monkeypatch, "natasha")
    assert request(session, "ping") == {"id": 1, "ok": True, "version": __version__, "ner": [], "ner_installed": ["ru"]}
    only_installed(monkeypatch, "natasha", "gliner")
    assert request(session, "ping")["ner_installed"] == ["ru", "en"]
    only_installed(monkeypatch, "gliner")
    assert request(session, "ping")["ner_installed"] == ["en"]
    only_installed(monkeypatch)
    assert request(session, "ping")["ner_installed"] == []


def test_ping_tells_the_detectors_of_boxed_toml(boxed_env, session):
    boxed_env.mkdir(parents=True)
    (boxed_env / "boxed.toml").write_text('[boxed]\nner = ["en", "ru"]\n')
    assert request(session, "ping")["ner"] == ["en", "ru"]


def test_a_ping_still_answers_when_boxed_toml_cannot_be_read(boxed_env):
    boxed_env.mkdir(parents=True)
    (boxed_env / "boxed.toml").write_text("[boxed\n")
    reply = request(Session(ner=("ru",)), "ping")
    assert is_ping(reply, 1, ner=["ru"])  # what the process was switched on to run


@pytest.mark.parametrize(
    ("value", "names"),
    [(None, ()), ("", ()), ("ru", ("ru",)), ("ru,en", ("ru", "en")), ("en,ru", ("ru", "en")), (" RU , en ", ("ru", "en")), ("ru,ru", ("ru",)), ("ru,xx,,fr", ("ru",)), ("xx", ())],
)
def test_the_switch_of_the_process_is_read_from_the_environment(value, names):
    assert serve_module._ner_from_env({} if value is None else {"BOXED_SERVE_NER": value}) == names


@pytest.mark.parametrize(
    ("toml", "switch", "runs"),
    [
        ("", ("ru",), ["ru"]),
        ('ner = ["en"]', ("ru",), ["en", "ru"]),  # added to those of boxed.toml, after them
        ('ner = ["ru"]', ("ru",), ["ru"]),  # and once
        ('ner = ["en", "ru"]', (), ["en", "ru"]),  # nothing switched on: boxed.toml as it is, in its order
        ("", (), []),
    ],
)
def test_the_switch_adds_to_the_detectors_of_boxed_toml_and_reaches_the_masker(boxed_env, monkeypatch, toml, switch, runs):
    seen = []
    monkeypatch.setattr(serve_module, "to_detect_config", lambda config: seen.append(list(config.ner)) or DetectConfig())
    boxed_env.mkdir(parents=True)
    (boxed_env / "boxed.toml").write_text(f"[boxed]\n{toml}\n")
    session = Session(ner=switch)
    assert request(session, "mask", text="hello", scope="sw1")["ok"] is True
    assert request(session, "policy-check", text="hello", recipient="openai:personal-private:US")["ok"] is True
    assert seen == [runs, runs]
    assert request(session, "ping")["ner"] == runs


def test_the_switch_is_never_written_to_boxed_toml(boxed_env, monkeypatch):
    monkeypatch.setattr(serve_module, "to_detect_config", lambda config: DetectConfig())
    session = Session(ner=("ru", "en"))
    assert request(session, "mask", text="hello", scope="sw2")["ok"] is True
    assert not (boxed_env / "boxed.toml").exists()
    (boxed_env / "boxed.toml").write_bytes(b'[boxed]\nner = ["en"]\n')
    assert request(session, "mask", text="hello", scope="sw3")["ok"] is True
    assert (boxed_env / "boxed.toml").read_bytes() == b'[boxed]\nner = ["en"]\n'


def test_main_reads_the_switch_from_the_environment(run_main, monkeypatch):
    monkeypatch.setenv("BOXED_SERVE_NER", "ru")
    code, out, _ = run_main({"id": 1, "cmd": "ping"})
    assert code == 0 and is_ping(out[0], 1, ner=["ru"])


def test_a_real_program_switched_on_to_find_russian_names_hides_them(live):
    pytest.importorskip("natasha")
    sidecar = live(env={"BOXED_SERVE_NER": "ru"})
    assert is_ping(sidecar.ask({"id": 1, "cmd": "ping"}), 1, ner=["ru"])
    reply = sidecar.ask({"id": 2, "cmd": "mask", "text": "Позвоните Ивану Петрову завтра", "level": 2, "scope": "ru1"})
    assert reply["ok"] is True and "Ивану" not in reply["text"] and "[PERSON_1]" in reply["text"]
    assert sidecar.close() == 0


@pytest.mark.parametrize("replace", [False, True])
def test_mask_file_leaves_no_clean_copy_when_the_map_cannot_be_saved(world, session, monkeypatch, replace):
    from boxed.vault import Vault

    dest = world.folder / "out.csv"
    if replace:
        dest.write_bytes(b"name,email\nan older copy\n")
        before = dest.read_bytes()

    def fails(self, scope, markers):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Vault, "save_map", fails)
    reply = mask_file(session, world, dest, scope="f9", **({"replace": True} if replace else {}))
    assert reply["ok"] is False
    assert (dest.read_bytes() == before) if replace else not dest.exists()
    assert not list(world.folder.glob(".boxed-part-*"))
