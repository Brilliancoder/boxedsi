import json
import os
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import boxed
from boxed.journal import GENESIS, Journal, JournalEntry
from boxed.keys import InsecureFileKeyStore
from boxed.locks import file_lock

SRC = str(Path(boxed.__file__).resolve().parent.parent)


def entry(level=2, status="sent"):
    return JournalEntry(
        channel="mcp",
        provider="anthropic",
        account_type="subscription",
        level=level,
        markers_by_kind={"EMAIL": 2},
        status=status,
        payload_sha256="ab" * 32,
        coverage="full",
        scope="ws-1",
        versions={"boxed": "0.1.0"},
    )


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal.jsonl", InsecureFileKeyStore(tmp_path / "keys"))


def rewrite(path, fn):
    lines = path.read_text().splitlines()
    path.write_text("\n".join(fn(lines)) + "\n")


def test_append_verify_ok(journal):
    for _ in range(3):
        journal.append(entry())
    report = journal.verify()
    assert (report.ok, report.count, report.first_bad) == (True, 3, None)
    assert [e["seq"] for e in journal.entries()] == [1, 2, 3]
    assert journal.entries()[1]["prev_hash"] == journal.entries()[0]["hash"]


def test_tamper_field(journal):
    for _ in range(3):
        journal.append(entry())

    def tamper(lines):
        rec = json.loads(lines[1])
        rec["level"] = 0
        lines[1] = json.dumps(rec)
        return lines

    rewrite(journal.path, tamper)
    report = journal.verify()
    assert (report.ok, report.first_bad) == (False, 2)


def test_deleted_line(journal):
    for _ in range(3):
        journal.append(entry())
    rewrite(journal.path, lambda lines: [lines[0], lines[2]])
    report = journal.verify()
    assert (report.ok, report.first_bad) == (False, 3)


def test_other_key_fails(journal, tmp_path):
    journal.append(entry())
    other = Journal(journal.path, InsecureFileKeyStore(tmp_path / "other-keys"))
    report = other.verify()
    assert (report.ok, report.first_bad) == (False, 1)


def test_bad_status_rejected():
    with pytest.raises(ValueError):
        entry(status="uploaded")


def test_empty_journal_verifies(journal):
    assert journal.verify().ok and journal.verify().count == 0


def test_append_after_a_torn_line_keeps_the_damage_visible(journal):
    journal.append(entry())
    journal.append(entry())
    with journal.path.open("a") as f:
        f.write('{"seq": 3, "torn')
    rec = journal.append(entry())
    assert rec["seq"] == 3 and rec["prev_hash"] == journal.entries()[1]["hash"]
    assert [r["seq"] for r in journal.entries()] == [1, 2, 3] and journal.read()[1] == 1
    report = journal.verify()
    assert not report.ok and report.first_bad == 3


def test_append_does_not_read_the_whole_journal(journal, monkeypatch):
    journal.append(entry())
    monkeypatch.setattr(Journal, "entries", lambda self: pytest.fail("append must not read the whole journal"))
    monkeypatch.setattr(Journal, "read", lambda self: pytest.fail("append must not read the whole journal"), raising=False)
    assert journal.append(entry())["seq"] == 2


@pytest.mark.parametrize("damage", [b'{"seq": 3, "note": "\xd0', b"123", b"null", b"[]"])
def test_damaged_lines_never_crash_read_or_verify(journal, damage):
    journal.append(entry())
    with journal.path.open("ab") as f:
        f.write(damage + b"\n")
    journal.append(entry())
    records, damaged = journal.read()
    assert [r["seq"] for r in records] == [1, 2] and damaged == 1
    report = journal.verify()
    assert not report.ok and report.first_bad == 2 and report.count == 2


def test_records_with_unicode_line_separators_verify(journal):
    e = entry()
    e.note = "a\u2028b\u0085c"
    journal.append(e)
    records, damaged = journal.read()
    assert len(records) == 1 and damaged == 0 and journal.verify().ok


@pytest.mark.parametrize("pad", [0, 3796, 5000, 9000])
def test_tail_reader_across_block_boundaries(journal, pad):
    e = entry()
    e.note = "x" * pad
    journal.append(e)
    journal.append(entry())
    assert journal.append(entry())["seq"] == 3 and journal.verify().ok


def test_append_to_an_empty_or_fully_damaged_journal(journal):
    journal.path.write_text("")
    assert journal.append(entry())["seq"] == 1
    journal.path.write_text("junk\nmore junk")
    rec = journal.append(entry())
    assert rec["seq"] == 1 and rec["prev_hash"] == GENESIS


def test_append_after_a_huge_unterminated_tail_is_fast(journal):
    journal.append(entry())
    with journal.path.open("a") as f:
        f.write("x" * 20_000_000)
    start = time.monotonic()
    assert journal.append(entry())["seq"] == 2
    assert time.monotonic() - start < 2


def test_public_key_hex_matches_the_signer(journal, tmp_path):
    rec = journal.append(entry())
    key = journal.public_key_hex()
    assert len(key) == 64 and key == key.lower()
    public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key))
    public.verify(bytes.fromhex(rec["sig"]), bytes.fromhex(rec["hash"]))
    same_device = Journal(journal.path, InsecureFileKeyStore(tmp_path / "keys"))
    other_device = Journal(tmp_path / "other.jsonl", InsecureFileKeyStore(tmp_path / "other-keys"))
    assert same_device.public_key_hex() == key != other_device.public_key_hex()
    stranger = Ed25519PublicKey.from_public_bytes(bytes.fromhex(other_device.public_key_hex()))
    with pytest.raises(InvalidSignature):
        stranger.verify(bytes.fromhex(rec["sig"]), bytes.fromhex(rec["hash"]))


def test_verify_survives_hostile_records(journal):
    journal.append(entry())
    journal.append(entry())

    def edit(field, value):
        def change(lines):
            rec = json.loads(lines[1])
            rec[field] = value
            return [lines[0], json.dumps(rec)]

        return change

    rewrite(journal.path, edit("sig", 123))
    assert not journal.verify().ok
    rewrite(journal.path, edit("note", "\ud800"))
    assert not journal.verify().ok


def test_model_and_usage_appear_only_when_set(journal):
    plain = journal.append(entry())
    assert "model" not in plain and "usage" not in plain
    sent = entry(status="received")
    sent.model, sent.usage = "gpt-test", {"input": 12, "output": 30}
    rec = journal.append(sent)
    assert rec["model"] == "gpt-test" and rec["usage"] == {"input": 12, "output": 30}
    assert journal.verify().ok


# A file opened as text without an encoding takes the one of the locale: cp1252 on Windows, ASCII under the C locale. The
# child below runs under the second, with the premise printed, so that the test cannot pass for lack of a non-UTF-8 default.
WRITER = """
import json, locale, sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from boxed.journal import Journal, JournalEntry
from boxed.keys import InsecureFileKeyStore

print(locale.getencoding())
text = json.load(sys.stdin)
root = Path(sys.argv[2])
journal = Journal(root / "journal.jsonl", InsecureFileKeyStore(root / "keys"))
journal.append(JournalEntry("cli", "anthropic", "subscription", 2, {"EMAIL": 1}, "sent", "ab" * 32, "full", text, note=text))
"""


def test_non_ascii_text_is_written_as_utf_8_whatever_the_locale(tmp_path):
    text = "Привет, мир: café"
    env = {**os.environ, "LC_ALL": "C", "PYTHONCOERCECLOCALE": "0", "PYTHONUTF8": "0"}
    run = subprocess.run(
        [sys.executable, "-c", WRITER, SRC, str(tmp_path)], input=json.dumps(text).encode(), env=env, capture_output=True, timeout=60
    )
    assert run.returncode == 0, run.stderr.decode()
    assert "utf" not in run.stdout.decode().lower()  # the premise: this child's default encoding is not UTF-8
    journal = Journal(tmp_path / "journal.jsonl", InsecureFileKeyStore(tmp_path / "keys"))
    (record,) = journal.entries()
    assert (record["scope"], record["note"]) == (text, text)
    assert journal.read()[1] == 0 and journal.verify().ok
    assert text.encode() in journal.path.read_bytes()  # the bytes on disk are UTF-8, not an escape and not another encoding


GOOD_HASH = "ab" * 32  # what the hash of a record looks like: 64 lowercase hex digits


def line_with(seq="2", digest=f'"{GOOD_HASH}"'):
    """A record line with these two fields only, each given as JSON text: they are all the reader looks at."""
    return f'{{"seq": {seq}, "hash": {digest}}}'.encode()


HOSTILE_LINES = {
    "a record nested 200k levels deep": b'{"seq": 2, "hash": "' + GOOD_HASH.encode() + b'", "a": ' + b"[" * 200_000 + b"]" * 200_000 + b"}",
    "200k opening brackets": b"[" * 200_000,
    "seq is text": line_with(seq='"2"'),
    "seq is a list": line_with(seq="[]"),
    "seq is a decimal": line_with(seq="2.5"),
    "seq is true": line_with(seq="true"),
    "seq is zero": line_with(seq="0"),
    "seq is negative": line_with(seq="-1"),
    "seq is 2**53": line_with(seq=str(2**53)),
    "seq has 4300 digits": line_with(seq="9" * 4300),  # one digit more and the JSON parser refuses it itself
    "hash is a lone surrogate": line_with(digest=r'"\ud800"'),
    "hash is one character": line_with(digest='"x"'),
    "hash is 63 digits": line_with(digest=f'"{GOOD_HASH[:-1]}"'),
    "hash is 65 digits": line_with(digest=f'"{GOOD_HASH}a"'),
    "hash is upper case": line_with(digest=f'"{GOOD_HASH.upper()}"'),
    "hash is not hex": line_with(digest='"' + "xyz" * 21 + 'x"'),
    "hash ends with a line break": line_with(digest=f'"{GOOD_HASH}' + r'\n"'),  # what a pattern closed with $ lets through
    "hash is a number": line_with(digest="12"),
    "hash is a list": line_with(digest="[]"),
    "hash is null": line_with(digest="null"),
}


@pytest.mark.parametrize("line", HOSTILE_LINES.values(), ids=HOSTILE_LINES.keys())
def test_a_hostile_line_is_a_damaged_line_and_the_chain_goes_on(journal, line):
    first = journal.append(entry())
    with journal.path.open("ab") as f:
        f.write(line + b"\n")
    second = journal.append(entry())  # the newest whole record is the one before the line; the line itself breaks nothing
    assert second["seq"] == 2 and second["prev_hash"] == first["hash"]
    records, damaged = journal.read()
    assert [r["seq"] for r in records] == [1, 2] and damaged == 1
    report = journal.verify()
    assert not report.ok and report.first_bad == 2 and report.count == 2


def test_seq_may_be_any_positive_whole_number_below_2_to_the_53(journal):
    with journal.path.open("ab") as f:
        f.write(line_with(seq="1") + b"\n" + line_with(seq=str(2**53 - 1)) + b"\n")
    records, damaged = journal.read()
    assert [r["seq"] for r in records] == [1, 2**53 - 1] and damaged == 0


OPERATIONS = {
    "append": lambda journal: journal.append(entry()),
    "read": lambda journal: journal.read(),
    "entries": lambda journal: journal.entries(),
    "verify": lambda journal: journal.verify(),
}


def outcome(operation, journal, release=lambda: None):
    """What `operation(journal)` returns or raises, run on a thread: a pipe that makes it wait fails the test instead of hanging it.
    `release` frees a thread that waits."""
    result = []

    def run():
        try:
            result.append(operation(journal))
        except BaseException as error:
            result.append(error)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout=3)
    if thread.is_alive():
        release()
        thread.join(timeout=3)
        pytest.fail("the journal waits on a pipe")
    return result[0]


def refused_without_a_path(result, journal):
    """The answer for a journal that is no plain file: an OSError of a fixed text, with no errno, no file name and no path in it."""
    assert isinstance(result, OSError), result
    assert result.errno is None and result.filename is None
    assert str(journal.path) not in str(result) and journal.path.name not in str(result)


@pytest.mark.parametrize("operation", OPERATIONS.values(), ids=OPERATIONS.keys())
@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no pipe in the file system (os.mkfifo)")
def test_a_pipe_at_the_journal_path_is_an_error_not_a_hang(journal, operation):
    os.mkfifo(journal.path)  # opening it to read waits for a writer, and to write for a reader

    def release():  # a process that holds both ends lets a waiting open through
        os.close(os.open(journal.path, os.O_RDWR | os.O_NONBLOCK))

    refused_without_a_path(outcome(operation, journal, release), journal)


@pytest.mark.parametrize(
    "kind", [pytest.param("pipe", marks=pytest.mark.skipif(sys.platform == "win32", reason="Windows has no pipe in the file system (os.mkfifo)")), "folder"]
)
def test_a_refused_append_does_not_keep_the_lock(journal, kind):
    def release():  # a process that holds both ends lets a waiting open through; a folder does not make anything wait
        if kind == "pipe":
            os.close(os.open(journal.path, os.O_RDWR | os.O_NONBLOCK))

    if kind == "pipe":
        os.mkfifo(journal.path)
    else:
        journal.path.mkdir()
    refused_without_a_path(outcome(OPERATIONS["append"], journal, release), journal)

    def take_the_lock(journal):
        with file_lock(journal.path):
            return "taken"

    assert outcome(take_the_lock, journal) == "taken"  # another writer is not left waiting for it


@pytest.mark.parametrize("operation", OPERATIONS.values(), ids=OPERATIONS.keys())
@pytest.mark.parametrize("target", ["a journal that verifies", "nothing"])
def test_a_symlink_at_the_journal_path_is_never_followed(journal, tmp_path, operation, target):
    elsewhere = tmp_path / "elsewhere.jsonl"
    if target == "nothing":
        before = None
    else:
        other = Journal(elsewhere, InsecureFileKeyStore(tmp_path / "keys"))  # the same device key: through the link it all verifies
        other.append(entry())
        other.append(entry())
        before = elsewhere.read_bytes()
    journal.path.symlink_to(elsewhere)
    refused_without_a_path(outcome(operation, journal), journal)
    assert journal.path.is_symlink()
    if before is None:
        assert not elsewhere.exists()  # not even created
    else:
        assert elsewhere.read_bytes() == before


@pytest.mark.parametrize("operation", OPERATIONS.values(), ids=OPERATIONS.keys())
def test_a_folder_at_the_journal_path_is_refused_in_the_same_words(journal, operation):
    journal.path.mkdir()
    refused_without_a_path(outcome(operation, journal), journal)


@pytest.mark.skipif(sys.platform == "win32", reason="a pipe in the file system and /dev/fd: neither is on Windows")
def test_a_refusal_leaves_no_descriptor_open(journal):
    os.mkfifo(journal.path)  # opened and then refused, again and again: a long-lived host would run out of descriptors

    def open_descriptors():
        return len(os.listdir("/dev/fd"))

    before = open_descriptors()
    for _ in range(25):
        for operation in OPERATIONS.values():
            refused_without_a_path(outcome(operation, journal), journal)
    assert open_descriptors() == before


@pytest.mark.parametrize("swapped_for", ["a symlink", "a pipe"])
def test_append_looks_again_when_it_writes(journal, tmp_path, monkeypatch, swapped_for):
    if swapped_for == "a pipe" and not hasattr(os, "mkfifo"):
        pytest.skip("Windows has no pipe in the file system (os.mkfifo)")
    journal.append(entry())
    elsewhere = tmp_path / "elsewhere.jsonl"
    elsewhere.write_text("keep\n")
    read_the_tail = Journal._tail

    def swapped_after_reading(self):  # the journal is replaced between the read of its tail and the write
        found = read_the_tail(self)
        self.path.unlink()
        if swapped_for == "a symlink":
            self.path.symlink_to(elsewhere)
        else:
            os.mkfifo(self.path)
        return found

    monkeypatch.setattr(Journal, "_tail", swapped_after_reading)
    release = lambda: os.close(os.open(journal.path, os.O_RDWR | os.O_NONBLOCK))
    refused_without_a_path(outcome(OPERATIONS["append"], journal, release), journal)
    assert elsewhere.read_text() == "keep\n"


@pytest.mark.skipif(sys.platform == "win32", reason="binds a Unix socket at a file name")
def test_a_socket_at_the_journal_path_is_refused_in_the_same_words(journal, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # the name of a socket is limited to about 100 characters: bind it by a relative one
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(journal.path.name)
        for operation in OPERATIONS.values():
            refused_without_a_path(outcome(operation, journal), journal)


@pytest.mark.skipif(sys.platform == "win32", reason="a file mode means nothing on Windows: the folder decides who may read a file")
def test_a_new_journal_file_is_private_from_its_first_byte(journal, monkeypatch):
    # Created with mode 600, not made private afterwards: a chmod after the first write leaves the file open to others until it runs.
    monkeypatch.setattr(os, "chmod", lambda *args, **kwargs: None)  # so nothing can repair the mode later
    old = os.umask(0)  # a file created with the default mode would now be open to everyone
    try:
        journal.append(entry())
    finally:
        os.umask(old)
    assert stat.S_IMODE(journal.path.stat().st_mode) == 0o600


# ---- Windows: the same refusal for what Windows has instead of a symbolic link ----


@pytest.mark.parametrize("operation", OPERATIONS.values(), ids=OPERATIONS.keys())
def test_windows_a_reparse_point_at_the_journal_path_is_refused_in_the_same_words(fake_msvcrt, journal, see_as, operation):
    journal.append(entry())  # a journal that is there, and a plain file by its mode
    see_as(journal.path, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)  # but for Windows a junction, a mount point or a placeholder
    refused_without_a_path(outcome(operation, journal), journal)


def test_the_lines_end_in_line_feeds_where_a_text_file_gets_carriage_returns(journal, crlf_text_files):
    """Windows writes \\r\\n for each \\n to a file opened as text: the journal of one computer must be the journal of another."""
    journal.append(entry())
    journal.append(entry())
    assert b"\r" not in journal.path.read_bytes() and journal.path.read_bytes().count(b"\n") == 2
    assert journal.verify().ok
