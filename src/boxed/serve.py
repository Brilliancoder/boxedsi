"""boxed serve: the core as one long-running process for the desktop program. The shell starts it once, writes a request, reads
the reply, and so on until it closes stdin. One request at a time, answered in order.

Every command runs the code of its command line twin (boxed mask, boxed restore, ...) in the same order: the policy first, the
journal before anything leaves, files through the safe writer (outputs.Target), the same refusals of level 4. tests/test_serve.py
compares the two on the same inputs. What differs is the shape: structured fields instead of printed lines, a text in a field
instead of stdin, the settings (boxed.toml) read from the boxed home for each request and not from the folder it runs in.

Framing, both ways: a 4-byte little-endian length, then that many bytes of UTF-8 JSON (one object). stdout carries frames and
nothing else (a stray print goes to stderr); stderr never carries the text of a request.
Request: {"id": ..., "cmd": ..., <the fields of the command>}. A field the command does not know is refused ("bad request").
Reply:   {"id": ..., "ok": true, <fields>} or {"id": ..., "ok": false, "error": <a fixed sentence>, <extra fields>}. The id is an
         integer from 0 to 2**64 - 1, or a string of up to 64 letters, digits and . _ - ; it is echoed as it came. A request
         without a usable id is answered with "id": null. An error sentence never quotes the request: it comes from a closed
         set fixed in the modules that raise it, and anything unexpected is "internal error" (the class of the exception, and
         nothing else, goes to host-errors.log in the boxed home).
Caps:    a request frame is at most 1 MiB and is refused from its header, unread; a reply is at most 16 MiB. A file goes by its
         absolute path and is at most 16 MiB. A reply that does not fit is "reply too large", before anything was saved or
         journaled for it (for ask: after, because the answer was paid for and is in the journal).
Ending:  EOF on stdin ends the process with 0. SIGTERM does too, at once, whatever the process is doing: the request in hand is
         not finished and not answered (a file's part folder goes, a vault that was not saved stays as it was; the journal has
         what was recorded before). A bad, truncated or oversize frame gets one error frame with "id": null and ends the process
         with 1. The process also ends with 0 right after an answer when the tokenizer of the language model cannot forget the
         words it read (ner.words_kept): the shell starts it again for the next request. It ends too, at once and without an
         answer, when its parent has ended (on macOS and Linux the parent changes to launchd or init): checked after each answer
         and once a second by a thread, so that neither a pipe that another process still holds nor a request that hangs keeps
         it, and a busy process does not keep the vault from the next app. Windows keeps the number of the parent: only EOF there.

Commands (fields -> fields of the reply; "?" is optional; paths are absolute):
 ping                                                          -> version, ner (name detectors that run), ner_installed (extras there)
 mask          text, scope?, level?                            -> text, scope, level, markers_by_kind
 restore       text, scope                                     -> text, unknown, suspicious, restored
 mask-file     src, dest, scope?, level?, replace?             -> report, scope, level
 restore-file  src, dest, scope, force?, replace?              -> report, scope, anomalies
 policy-check  text, recipient ("provider:kind:jurisdiction"), categories? -> verdict, min_level, categories, reasons, warnings
 plan-prompt   task, table, scope?, decimal?, header_ok?       -> prompt, scope, decimal, markers_by_kind
 plan-run      plan, table, scope, decimal?, out?, chart_out?, replace? -> csv (null when out is given), delimiter, rows, chart
 ask           text, provider, model, account?, scope?, level?, categories? -> text, scope, level, verdict, warnings, unknown,
                                                                 suspicious, model, usage, complete
 key-status    provider                                        -> source ("keychain", "environment" or null)
 key-set       provider, key                                   -> (nothing)
 key-remove    provider                                        -> removed, environment
 checks                                                        -> checks, providers, settings, note, fail_safe
 check-set     provider, account, training, memory             -> (nothing)
 check-remove  provider, account                               -> (nothing)
 check-reset                                                   -> moved, kept_as (a damaged checks.json is kept under a new name)
 dashboard     period? ("day", "week", "month") or since?, until? (YYYY-MM-DD) -> period, chain, damaged, summary, rows,
                                                                 observed, checks, policy
 journal-verify                                                -> chain_ok, count, first_bad, reason
 journal-export out, since?, until?, replace?                  -> records, public_key
A restored text always comes with the placeholders that were not restored (unknown, suspicious): the window shows them next to
the text. restore-file and plan-run refuse instead (error with "anomalies"): nothing is written or run on a placeholder that
does not fit, unless restore-file is told force. A level is 0 to 3; 4 is a plan, and is refused in the words of boxed ask.
An ask that the policy stops is an error with verdict, reasons and warnings; nothing was sent.
The shell sends the next request after the reply to the last one: a process that ends itself after an answer has read no more.
The window has no file system of its own, so a path in a request is a path this program reads or writes for it: a table is a .csv
or .tsv file, no file below the boxed home is read, and an output is named as what it holds (a masked copy keeps the suffix of the
original, a PDF becomes .txt; a plan result is .csv or .tsv; a chart and an export are .json), so that replace can only replace a
file of that kind. Every output goes through outputs.Target.
The language models load from the local cache and never from the hub (HF_HUB_OFFLINE and TRANSFORMERS_OFFLINE are set at the start);
one that is not there is an error that names the extra: ner-ru or ner-en.
BOXED_SERVE_NER (ru, en or both) switches name detectors on for this process besides those of boxed.toml; it is never written to a
file, and ping says what runs and what is installed.
mask-file and restore-file count the work first - cells, paragraphs, pages, and the markers the scope has - and refuse in one fixed
sentence what would not be done in WORK_BUDGET seconds, because the shell gives up on a request after 120.
The vault is waited for VAULT_WAIT seconds at most: a request that finds it held by another process (the command line, the browser's
host, a program of an earlier app that hangs) is the error "boxed is busy with another request: try again in a moment".
A file is made in a part folder next to where it goes (outputs.staging), and a note of the folder is kept in serve-parts of the boxed
home for as long as it exists: the start of the program removes the folders that a killed process left (clear_stale_parts).
"""

import csv
import importlib.util
import io
import json
import os
import re
import secrets
import shutil
import signal
import stat
import sys
import threading
import time
import zipfile
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import asdict, dataclass, replace
from datetime import UTC, date, datetime
from pathlib import Path
from typing import BinaryIO

from . import __version__, channels, checks, cli, dashboard, formats, opplan
from .channels import ChannelError, PolicyBlocked
from .checks import ACCOUNT_RE, NOTE, SETTINGS, STATES, Check, CheckError, account_kind, due, load_checks, save_check
from .config import CONFIG_NAME, NER_NAMES, ProjectConfig, read_config, to_detect_config
from .dashboard import CHECKS_FAIL_SAFE
from .detect import KINDS_BY_LEVEL, DetectConfig, detect, ner
from .formats import FormatError, documents, tabular
from .journal import JournalEntry, JournalError, VerifyReport
from .locks import file_lock
from .mask import dictionary_kinds, mask_text, restore
from .native_host import SCOPE_RE, _encode, _log_failure, _Refused, _scope, _text, read_message, write_message
from .observe import observed_journal
from .opplan import PlanError
from .outputs import Target, inside
from .paths import boxed_home, boxed_home_path
from .platform import IS_WINDOWS, LockTimeout
from .policy import CATEGORIES, RECIPIENT_KINDS, Policy, PolicyError, Recipient, categories_for, decide
from .vault import VaultError

MAX_REQUEST = 1024 * 1024  # bytes of JSON in a request frame: a text goes in the frame, a file by its path
MAX_REPLY = 16 * 1024 * 1024
MAX_FILE = 16 * 1024 * 1024  # bytes of a file named by its path
ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
REPLY_ROOM = 128  # bytes that handle adds to a reply: the id and "ok"
PARENT_POLL = 1.0  # seconds between two looks at the parent, from the thread that watches it
VAULT_WAIT = 20  # seconds a request waits for the vault when another process has it; the shell gives up after 120
PARTS = "serve-parts"  # in the boxed home: a note of each part folder a process is making, see clear_stale_parts
PARTS_STALE = 3600  # seconds after which a note is stale whoever wrote it
PART_PREFIX = ".boxed-part-"  # how outputs.staging names its folders
BAD_REQUEST = "bad request"
INTERNAL = "internal error"
MAX_PATH = 4096  # characters of a path in a request
DAY_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
CONFIG = "boxed.toml cannot be read"
BUSY = "boxed is busy with another request: try again in a moment"
STORE = "the boxed data folder or the key store cannot be opened"
UNKNOWN_SCOPE = "unknown scope"
VAULT = "cannot decrypt the scope: wrong key or tampered data"
NOT_RESTORED = "not restored, check by hand"
FILE_MISSING = "the file was not found"
FILE_DENIED = "the file cannot be read or written: permission denied"
FILE_OTHER = "the file cannot be read or written"
NOT_A_FILE = "the path is not a plain file"
TOO_LARGE = "the file is larger than 16 MiB"
# What Target says in its own words, which name the file, as texts that do not (see _output_refusal)
IN_HOME = "the output cannot be inside the boxed data folder"
IS_LINK = "the output path is a link: name the file itself"
NO_FOLDER = "the folder of the output file does not exist"
NOT_PLAIN = "the output path is not a plain file"
EXISTS = "the output file exists already: name another file, or allow replacing it"
CHANGED = "the place of the output file changed while it was made"
OUTPUT_OTHER = "the output file cannot be written there"
OUTPUT_IS_SOURCE = "the output would replace the source file"
OUTPUT_IS_INPUT = "the output is the input file: choose another output name"
TABLE_SUFFIXES = (".csv", ".tsv")  # what boxed plan reads: CSV and delimited text
TABLE_NAME = "a table must be a .csv or .tsv file"
SOURCE_IN_HOME = "the file is inside the boxed data folder"
OUTPUT_NAME = "the output file name must end the way its content does: .csv, .tsv, .xlsx, .docx, .txt or .json"
TABLE_UNREADABLE = "the table is not UTF-8 text, or it is empty"
PLAN_NOT_RUN = "plan not run, check these placeholders"
NO_KEY = "no API key for this provider"
NO_CHECK = "no check for this account"
NER_SWITCH = "BOXED_SERVE_NER"  # in the environment: ru, en or both, the name detectors this process runs besides those of boxed.toml
NER_LIBRARIES = {"ru": "natasha", "en": "gliner"}  # what each of the extras installs that is looked for
NER_RU_EXTRA = "the Russian name detector needs the ner-ru extra, which is not installed"
NER_EN_EXTRA = "the English name detector needs the ner-en extra, which is not installed"
NER_EN_MODEL = "the model of the ner-en extra is not in the local cache, and the program does not go online to fetch it"
RUSSIAN_MODULES = frozenset({"natasha", "navec", "slovnet", "razdel", "yargy", "ipymarkup", "pymorphy2", "pymorphy3"})  # what ner-ru installs
CHECKS_READABLE = "checks.json is readable: nothing to reset"
ASIDE_EXISTS = "an earlier damaged checks.json has this second's name: wait a second and try again"
ACCOUNTS = tuple(kind for kind in RECIPIENT_KINDS if kind != "local")  # the kinds of account a remote API call can belong to
# The refusals of channels.ask for an argument it would not send, which are fixed there: the level of a plan, a stored key that
# could not be a key, a relay address a key must not go to. Any other ValueError from it is not one of them.
ASK_REFUSALS = {channels._PLAN_REFUSAL, channels._KEY_REFUSAL}
RELAY_REFUSAL = re.compile(r"BOXED_[A-Z]+_BASE_URL must be an https address \(or http on this computer\) without a login, query or fragment")


class Refusal(_Refused):
    """An error the shell may show. Its text is fixed in this module (or in the module that raised it, for the families
    named in handle), never built from a request. `extra` is data that goes with the error, such as the placeholders that
    were not restored."""

    def __init__(self, text: str, **extra) -> None:
        super().__init__(text)
        self.extra = extra


class Session:
    """What stays between requests: the boxed home and the objects built on its key store. Never a text."""

    def __init__(self, ner: tuple[str, ...] = ()) -> None:
        self.ner = ner  # name detectors this process was switched on to run (see NER_SWITCH); boxed.toml is never written
        self._context: cli.Context | None = None

    def context(self) -> cli.Context:
        """The data folder, the key store, the vault and the journal, opened by the first request that needs them: a request
        that is refused, a ping and a check of the policy open nothing. A failure is not remembered; the next request tries
        again, so a keychain the person unlocks a moment later works."""
        if self._context is None:
            try:
                self._context = cli.Context()
            except Exception as e:  # a locked keychain, a folder that cannot be made: the text may name a path
                _log_failure(boxed_home_path(), "cannot open the key store", e)
                raise Refusal(STORE) from None
            self._context.vault.lock_timeout = VAULT_WAIT  # a process that hangs in a transaction must not stop the next one for ever
        return self._context

    def config(self) -> ProjectConfig:
        """boxed.toml of the boxed home, read again for each request that needs it: the shell has no project folder, a file in
        a parent of the folder the program happens to run in must not change what is masked, and a dictionary entry added a
        moment ago applies to the next request. One that cannot be read stops the request: nothing is masked with an old copy."""
        home = boxed_home_path()
        try:
            config = read_config(home / CONFIG_NAME)
        except Exception as e:  # the text of a parse error can quote the file
            _log_failure(home, "cannot read boxed.toml", e)
            raise Refusal(CONFIG) from None
        return replace(config, ner=self._switched(config.ner))

    def _switched(self, names: list[str]) -> list[str]:
        """The detectors of boxed.toml, in its order, and then those this process was switched on to run that it does not name."""
        return [*names, *(name for name in self.ner if name not in names)]

    def running(self) -> list[str]:
        """The name detectors that run, for a ping, which does not depend on the settings: a boxed.toml that cannot be read is said
        by the commands that need it, and here it counts for nothing."""
        try:
            names = read_config(boxed_home_path() / CONFIG_NAME).ner
        except Exception:
            names = []
        return self._switched(names)


def read_request(stream: BinaryIO) -> dict | None:
    return read_message(stream, MAX_REQUEST, "<")


def write_reply(stream: BinaryIO, reply: dict) -> None:
    write_message(stream, reply, MAX_REPLY, "<")


def _request_id(message: dict) -> int | str | None:
    request_id = message.get("id")
    if type(request_id) is int and 0 <= request_id < 2**64:  # not True, not 1.0
        return request_id
    if type(request_id) is str and ID_RE.fullmatch(request_id):
        return request_id
    return None


def _fit(reply: dict) -> dict:
    """The reply, once it is known to fit in a frame: nothing is saved or journaled for one that cannot be sent."""
    try:
        _encode(reply, MAX_REPLY - REPLY_ROOM)
    except ValueError as e:
        raise Refusal(str(e)) from None
    return reply


def _default_scope(prefix: str) -> str:
    return prefix + "-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S")


def _level(message: dict) -> int | None:
    level = message.get("level")
    if level is None:
        return None
    if type(level) is not int or level not in KINDS_BY_LEVEL:  # not True, not 1.0
        raise Refusal(BAD_REQUEST)
    return level


def _refuse_plan_level(level: int) -> None:
    try:
        cli._refuse_plan_level(level)
    except ValueError as e:  # the words ask uses, fixed in channels.py
        raise Refusal(str(e)) from None


def _journal(ctx: cli.Context, *, scope: str, status: str, level: int, counts: dict[str, int], payload: str, note: str = "") -> None:
    """The record boxed mask and boxed restore write."""
    ctx.journal.append(
        JournalEntry(
            channel="manual",
            provider="unknown",
            account_type="unknown",
            level=level,
            markers_by_kind=counts,
            status=status,
            payload_sha256=cli._sha256(payload),
            coverage="full",
            scope=scope,
            versions={"boxed": __version__},
            note=note,
        )
    )


def _flag(message: dict, name: str) -> bool:
    value = message.get(name)
    if value is None:
        return False
    if type(value) is not bool:
        raise Refusal(BAD_REQUEST)
    return value


def _path(message: dict, name: str) -> str:
    """A path the shell names: absolute, because the program does not know where it was started from."""
    value = message.get(name)
    if not isinstance(value, str) or not 0 < len(value) <= MAX_PATH or "\x00" in value or not Path(value).is_absolute():
        raise Refusal(BAD_REQUEST)
    try:
        os.fsencode(value)
    except UnicodeEncodeError:  # a lone surrogate: no file system has such a name
        raise Refusal(BAD_REQUEST) from None
    return value


def _os_refusal(error: OSError) -> str:
    """The text for a file that cannot be read or written: the Python message quotes the path."""
    if isinstance(error, FileNotFoundError | NotADirectoryError):
        return FILE_MISSING
    if isinstance(error, PermissionError):
        return FILE_DENIED
    return FILE_OTHER


def _source(name: str, suffixes: tuple[str, ...] | None = None) -> Path:
    """A file the person named to read. The window has no file system of its own, so a path in a request is a path this program
    reads for it: the kind of file the command is for (`suffixes`; None when the formats refuse the type in their own words),
    never one below the boxed home (the journal, the vault, the keys), a plain file (a pipe would be waited for), and no larger
    than MAX_FILE."""
    path = Path(name)
    if suffixes is not None and path.suffix.lower() not in suffixes:
        raise Refusal(TABLE_NAME)
    if inside(path.resolve(), boxed_home_path().resolve()) is not None:  # also through a link, and in another spelling of its name
        raise Refusal(SOURCE_IN_HOME)
    try:
        info = path.stat()
    except OSError as e:
        raise Refusal(_os_refusal(e)) from None
    if not stat.S_ISREG(info.st_mode):
        raise Refusal(NOT_A_FILE)
    if info.st_size > MAX_FILE:
        raise Refusal(TOO_LARGE)
    return path


def _masked_suffixes(source: Path) -> tuple[str, ...] | None:
    """How a masked copy of `source` is named: as the original (a PDF becomes .txt). None for a type the formats refuse."""
    suffix = source.suffix.lower()
    if suffix == ".pdf":
        return (".txt",)
    return (suffix,) if suffix in formats.SUPPORTED else None


def _restored_suffixes(source: Path) -> tuple[str, ...] | None:
    suffix = source.suffix.lower()
    return (suffix,) if suffix in formats.RESTORABLE else None


# ---- how much a file may ask of one request ----
# The shell gives up on a request after 120 s. A file is counted before any work is done, and one that would take more than
# WORK_BUDGET seconds is refused. The seconds are those of a Mac that was busy with other work (load average 16 on 10 cores), measured on
# the worst content for the masker - every text a new e-mail address, so that every text adds a marker - and rounded up:
#   mask-file of a csv     10,000 cells 1.9 s   20,000 10 s    40,000 35 s    60,000 61 s     (xlsx: 40,000 cells 36 s)
#   restore-file of a csv  10,000 cells 1.9 s   20,000 13 s    40,000 32 s    60,000 48 s
#   mask-file of a docx    8,000 paragraphs 12 s; one table of 500 rows of 4 cells 17 s, of 1,000 rows 96 s
#   mask-file of a pdf     158 pages 2.2 s (14 ms a page); one text of 12 MB: 7.5 s
#   a text read by the language models: Russian 0.17 ms, English 115 ms (and 13 s to load it)
# Most of it is the masker: MarkerMap.kinds() (mask.py) walks every marker of the scope for each text it masks (twice) or restores
# (once), so the time grows with the square of the markers. Kept as a set that marker_for grows, it is linear: 60,000 cells take 2.2 s
# to mask and 0.5 s to restore. With that change SECONDS_A_VISIT goes to 0 and the files that fit grow twentyfold.
WORK_BUDGET = 50
SECONDS_A_TEXT = {".csv": 1e-4, ".xlsx": 2.5e-4, ".docx": 1.5e-3}  # reading, masking and writing one text of this format
SECONDS_A_PAGE = 0.05  # a page of a PDF, with the Russian model: 14-16 ms for a page of text, three times that for the rest
SECONDS_A_CELL_ROW = 2.3e-5  # python-docx reads all the cells of a table again for each of its rows: a table costs cells x rows
SECONDS_A_VISIT = 2.5e-8  # one marker looked at by MarkerMap.kinds()
SECONDS_A_NAME = {"ru": 2e-4, "en": 0.12}  # a text read by the language model of this extra
UNPACKED_MAX = 64 * 1024 * 1024  # bytes of an xlsx or a docx once unpacked: a zip that unpacks to more is not opened
TOO_MUCH = "the file is too large to be masked or restored here in the time allowed: split it into smaller files"
CELL_WITH_VALUE = re.compile(rb"<(?:\w+:)?(?:v|is)[\s>/]")  # in a sheet: the value of a cell, or an inline string
DOCX_BLOCK = re.compile(rb"<(?:\w+:)?(?P<open>p|tbl|tr|tc)(?=[\s>/])|</(?:\w+:)?(?P<close>tbl)\s*>")


@dataclass
class Work:
    """What a file asks of the masker, counted from the file before a converter reads any of it."""

    suffix: str
    texts: int = 0  # texts that go through the masker one by one: cells, paragraphs
    pages: int = 0  # pages of a PDF
    cell_rows: int = 0  # for each table of a docx: its cells times its rows


def _seconds(work: Work, ner: list[str], markers: int, *, restoring: bool) -> float:
    """The time the work takes, in the seconds of the measurements above. `markers`: those the scope has already."""
    seconds = work.texts * SECONDS_A_TEXT.get(work.suffix, 0) + work.pages * SECONDS_A_PAGE + work.cell_rows * SECONDS_A_CELL_ROW
    if restoring:  # every text looks at the markers once
        return seconds + work.texts * markers * SECONDS_A_VISIT
    seconds += work.texts * (2 * markers + work.texts) * SECONDS_A_VISIT  # twice, and in the worst case every text adds one
    return seconds + work.texts * sum(SECONDS_A_NAME[name] for name in ner)


def _refuse_work(work: Work, ner: list[str], markers: int, *, restoring: bool) -> None:
    if _seconds(work, ner, markers, restoring=restoring) > WORK_BUDGET:
        raise Refusal(TOO_MUCH)


def _csv_texts(source: Path, limit: int) -> int:
    """The cells of a csv that hold text, as the converter reads them (same delimiter, same quoting)."""
    body = source.read_bytes().decode("utf-8").removeprefix(tabular.BOM)
    count = 0
    for row in csv.reader(io.StringIO(body, newline=""), delimiter=tabular._delimiter(body)):
        count += sum(1 for cell in row if cell)
        if count > limit:
            raise Refusal(TOO_MUCH)
    return count


def _docx_blocks(xml: bytes, work: Work) -> None:
    """Paragraphs, and for each table its cells times its rows (a table in a cell is a table of its own)."""
    tables: list[list[int]] = []  # rows and cells of the tables that are open
    for found in DOCX_BLOCK.finditer(xml):
        if found.lastgroup == "close":
            if tables:
                rows, cells = tables.pop()
                work.cell_rows += rows * cells
            continue
        name = found.group("open")
        if name == b"p":
            work.texts += 1
        elif name == b"tbl":
            tables.append([0, 0])
        elif tables:
            tables[-1][name == b"tc"] += 1  # a row, or a cell


def _office_work(source: Path, work: Work, limit: int) -> None:
    with zipfile.ZipFile(source) as archive:
        members = archive.infolist()
        if sum(member.file_size for member in members) > UNPACKED_MAX:  # said by the directory of the zip: nothing is unpacked yet
            raise Refusal(TOO_MUCH)
        for member in members:
            if work.suffix == ".xlsx" and member.filename.startswith(tabular.SHEET_PREFIX):
                work.texts += sum(1 for _ in CELL_WITH_VALUE.finditer(archive.read(member)))
            elif work.suffix == ".docx" and documents.CONTENT_PARTS.fullmatch(member.filename):
                _docx_blocks(archive.read(member), work)
            if work.texts > limit:
                raise Refusal(TOO_MUCH)


def _pdf_pages(source: Path) -> int:
    pypdf = formats.need("pypdf")
    with documents._silent("pypdf"):
        reader = pypdf.PdfReader(str(source))
        if reader.is_encrypted and not reader.decrypt(""):
            return 0  # the converter says that it is password protected
        return len(reader.pages)


def _work(source: Path) -> Work:
    """Count what a converter will do with the file. A file that cannot be counted counts for nothing: the converter names what is
    wrong with it in its own words."""
    suffix = source.suffix.lower()
    work = Work(suffix)
    limit = int(WORK_BUDGET / SECONDS_A_TEXT.get(suffix, 1))  # more texts than this are too much whatever the scope holds
    try:
        if suffix == ".csv":
            work.texts = _csv_texts(source, limit)
        elif suffix in (".xlsx", ".docx"):
            _office_work(source, work, limit)
        elif suffix == ".pdf":
            work.pages = _pdf_pages(source)
    except Refusal:
        raise
    except Exception:
        return Work(suffix)
    return work


def _output_refusal(error: ValueError) -> str:
    """Target says why a place is refused in words that name the file. The same reasons without the name, found by the fixed
    words around the name and never by the name; anything not known is the general one."""
    text = str(error)
    if "is not written in the boxed home" in text:
        return IN_HOME
    if text.endswith(" is a link: name the file itself"):
        return IS_LINK
    if text.startswith("the folder of ") and text.endswith(" does not exist"):
        return NO_FOLDER
    if text.endswith(" is not a plain file"):
        return NOT_PLAIN
    if text.endswith(("or delete it first", "or add --replace to replace it")):
        return EXISTS
    if text.endswith(": the place of the file changed while it was made"):
        return CHANGED
    return OUTPUT_OTHER


def _note(folder: Path) -> Path | None:
    """Write down that this process is making `folder`: a file named for the process, in the registry of the boxed home, that holds
    the path. Best effort - a registry that cannot be written costs the clearing of this one folder, not the request."""
    try:
        registry = boxed_home() / PARTS
        registry.mkdir(mode=0o700, exist_ok=True)
        record = registry / f"{os.getpid()}.{secrets.token_hex(4)}"
        record.write_bytes(os.fsencode(folder))
        return record
    except Exception as e:
        _log_failure(boxed_home_path(), "cannot note a part folder", e)
        return None


def _forget(record: Path) -> None:
    try:
        record.unlink(missing_ok=True)
        record.parent.rmdir()  # the registry goes with its last note, so that a home that was used holds nothing more
    except OSError:  # other notes in it, or already gone
        pass


@contextmanager
def _noted(stage: AbstractContextManager[Path]) -> Iterator[Path]:
    """A part folder (see outputs.staging) with a note of it for as long as it exists: the note goes after the folder."""
    record = None
    try:
        with stage as part:
            record = _note(part.parent)
            yield part
    finally:
        if record is not None:
            _forget(record)


class _Target(Target):
    """The safe writer of outputs.py with one addition: every part folder it makes is noted while it exists. Everything that makes a
    file goes through stage(), `write` included."""

    def stage(self) -> AbstractContextManager[Path]:
        return _noted(super().stage())


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)  # never on Windows, where it ends the process
    except ProcessLookupError:
        return False
    except PermissionError:  # a process of another user
        return True
    return True


def _clear(record: Path) -> None:
    """Remove the folder a note names, if it is a folder made by outputs.staging - by its name, its kind and its owner, never by
    what the note says it is - and then the note."""
    folder = Path(os.fsdecode(record.read_bytes()))
    try:
        info = os.lstat(folder)
    except OSError:  # already gone
        info = None
    if (
        info is not None
        and folder.is_absolute()
        and folder.name.startswith(PART_PREFIX)
        and stat.S_ISDIR(info.st_mode)  # not a link to one, not a file
        and (IS_WINDOWS or info.st_uid == os.getuid())
    ):
        shutil.rmtree(folder, ignore_errors=True)
    record.unlink(missing_ok=True)


def clear_stale_parts() -> None:
    """At start: remove the part folders that a process of this program left when it was killed in the middle of a file. outputs.staging
    removes its folder however a block ends, but not when nothing runs - SIGKILL, which is what the shell does after 120 s, a power cut.
    What is left holds half of a masked file, or half of a restored one, which is the original text. A note is stale when the process
    that wrote it is gone (not asked on Windows) or when it is over an hour old, as a number can be taken by another process since.
    Best effort: the program starts whatever this meets."""
    try:
        records = sorted((boxed_home_path() / PARTS).iterdir())
    except OSError:  # no registry, no home
        return
    for record in records:
        pid, _, _ = record.name.partition(".")
        try:
            if not pid.isdigit():  # not a note of ours: nothing it says is acted on
                record.unlink(missing_ok=True)
            elif int(pid) != os.getpid() and (time.time() - record.stat().st_mtime > PARTS_STALE or not (IS_WINDOWS or _alive(int(pid)))):
                _clear(record)
        except Exception as e:
            _log_failure(boxed_home_path(), "cannot clear a part folder", e)


def _target(name: str, *, suffixes: tuple[str, ...] | None, **rules) -> Target:
    """The place for a file, looked at before anything is created: Target says whether the place may hold it, and the name must
    end the way the content does (`suffixes`; None only where the formats refuse the type before they write a byte). So replace
    replaces a file of the kind that is written and not any plain file the person owns (a shell profile, a launch agent)."""
    try:
        target = _Target(name, **rules)
    except ValueError as e:
        raise Refusal(_output_refusal(e)) from None
    if suffixes is not None and Path(name).suffix.lower() not in suffixes:
        raise Refusal(OUTPUT_NAME)
    return target


def _publish(target: Target, part: Path) -> None:
    try:
        target.publish(part)
    except ValueError as e:
        raise Refusal(_output_refusal(e)) from None


def _write(target: Target, data: bytes) -> None:
    try:
        target.write(data)
    except ValueError as e:
        raise Refusal(_output_refusal(e)) from None


def _string(message: dict, name: str) -> str:
    """A text field other than "text": a string that can travel back as UTF-8 (a lone surrogate cannot)."""
    value = message.get(name)
    if not isinstance(value, str):
        raise Refusal(BAD_REQUEST)
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise Refusal(BAD_REQUEST) from None
    return value


def _optional_path(message: dict, name: str) -> str | None:
    return None if message.get(name) is None else _path(message, name)


def _decimal(message: dict) -> str:
    value = message.get("decimal")
    if value is None:
        return "auto"
    if value not in ("auto", ".", ","):
        raise Refusal(BAD_REQUEST)
    return value


def _table(name: str, choice: str) -> tuple[list[str], list[list[str]], str, str]:
    """The table of a path as boxed plan reads it: header, rows, delimiter and the decimal separator. A table over the cell
    limit is refused here, before anything is made."""
    source = _source(name, TABLE_SUFFIXES)
    try:
        header, rows, delimiter = cli._read_table(str(source))
    except (ValueError, csv.Error):  # their texts are fixed or quote the file: one sentence for both
        raise Refusal(TABLE_UNREADABLE) from None
    return header, rows, delimiter, opplan.guess_decimal(rows) if choice == "auto" else choice


def _detect_config(config: ProjectConfig) -> DetectConfig:
    """to_detect_config, which builds the language models the settings ask for: the first call loads them, and takes seconds.
    A model that is not there is said in fixed words that name the extra: the extra is not installed, or its model is not in the
    local cache - the program never goes online for one (main sets HF_HUB_OFFLINE). Any other failure stays what it is."""
    try:
        return to_detect_config(config)
    except ImportError as e:
        russian = (e.name or "").split(".")[0] in RUSSIAN_MODULES or "en" not in config.ner
        raise Refusal(NER_RU_EXTRA if russian else NER_EN_EXTRA) from None
    except OSError:  # huggingface_hub's LocalEntryNotFoundError, and the other ways a model that is not cached fails offline
        if "en" in config.ner:
            raise Refusal(NER_EN_MODEL) from None
        raise


def _ner_from_env(environ) -> tuple[str, ...]:
    """The name detectors the environment switches on: ru, en or both, in any case, with spaces; anything else is not one."""
    asked = {part.strip().lower() for part in environ.get(NER_SWITCH, "").split(",")}
    return tuple(name for name in NER_NAMES if name in asked)


def _installed_ner() -> list[str]:
    """The extras whose library is there to be loaded, found and not imported: the model of GLiNER takes seconds and a gigabyte."""
    return [name for name, library in NER_LIBRARIES.items() if importlib.util.find_spec(library) is not None]


def _ping(message: dict, session: Session) -> dict:
    """The version, the name detectors that run (boxed.toml and the switch of this process) and those that could, so that the window
    does not promise names that the build cannot find."""
    return {"version": __version__, "ner": session.running(), "ner_installed": _installed_ner()}


def _mask(message: dict, session: Session) -> dict:
    text = _text(message)
    scope = _scope(message, _default_scope("manual"))
    level = _level(message)
    config = session.config()
    level = config.level if level is None else level
    _refuse_plan_level(level)
    detect_config = _detect_config(config)  # before the vault is touched: a model that is not there makes nothing
    ctx = session.context()
    with ctx.vault.transaction(scope) as markers:
        masked, counts = mask_text(text, markers, level=level, config=detect_config)
        reply = _fit({"text": masked, "scope": scope, "level": level, "markers_by_kind": counts})  # a refusal skips the save
    _journal(ctx, scope=scope, status="prepared", level=level, counts=counts, payload=masked)
    return reply


def _restore(message: dict, session: Session) -> dict:
    text = _text(message)
    scope = _scope(message)
    ctx = session.context()
    if scope not in ctx.vault.scopes():
        raise Refusal(UNKNOWN_SCOPE)
    result = restore(text, ctx.vault.load_map(scope), dictionary_kinds(session.config()))
    reply = _fit({"text": result.text, "unknown": result.unknown, "suspicious": result.suspicious, "restored": result.restored})
    note = f"restored={result.restored} unknown={len(result.unknown)} suspicious={len(result.suspicious)}"
    _journal(ctx, scope=scope, status="received", level=-1, counts={}, payload=text, note=note)
    return reply


def _recipient(message: dict) -> Recipient:
    """provider:kind:jurisdiction, as boxed policy check takes it. Each part is a short name, and the kind is one of the five."""
    value = message.get("recipient")
    parts = value.split(":") if isinstance(value, str) else []
    if len(parts) != 3 or not all(SCOPE_RE.fullmatch(part) for part in parts) or parts[1] not in RECIPIENT_KINDS:
        raise Refusal(BAD_REQUEST)
    return Recipient(*parts)


def _categories(message: dict) -> set[str]:
    """The categories the person says the text belongs to: the ones no detector raises, as boxed ask --category takes them."""
    named = message.get("categories")
    if named is None:
        return set()
    if not isinstance(named, list) or not all(isinstance(name, str) and name in cli.NAMED_CATEGORIES for name in named):
        raise Refusal(BAD_REQUEST)
    return set(named)


def _policy_check(message: dict, session: Session) -> dict:
    text = _text(message)
    recipient = _recipient(message)
    named = _categories(message)
    config = session.config()
    found = detect(text, level=max(KINDS_BY_LEVEL), config=_detect_config(config))
    categories = categories_for({d.kind for d in found}, dictionary_kinds(config)) | named
    decision = decide(categories, recipient, Policy.from_config(config.policy))
    return {
        "verdict": decision.verdict,
        "min_level": decision.min_level,
        "categories": sorted(categories),
        "reasons": decision.reasons,
        "warnings": decision.warnings,
    }


def _mask_file(message: dict, session: Session) -> dict:
    src, dest = _path(message, "src"), _path(message, "dest")
    scope = _scope(message, _default_scope("file"))
    level = _level(message)
    replace = _flag(message, "replace")
    config = session.config()
    level = config.level if level is None else level
    _refuse_plan_level(level)
    source = _source(src)
    if Path(dest).exists() and os.path.samefile(source, dest):  # also a link to it, or another spelling on a file system that ignores case
        raise Refusal(OUTPUT_IS_SOURCE)
    target = _target(dest, kind="masked file", suffixes=_masked_suffixes(source), replace=replace)  # before anything is created
    work = _work(source)
    _refuse_work(work, config.ner, 0, restoring=False)  # before the models are loaded and the vault is opened
    detect_config = _detect_config(config)
    ctx = session.context()
    with target.stage() as part:  # the map is saved only when the clean copy was written; the copy lands after the map and the journal
        with ctx.vault.transaction(scope) as markers:
            _refuse_work(work, config.ner, len(markers.items()), restoring=False)  # what the scope holds already costs every text
            report = formats.mask_file(source, part, markers, level=level, config=detect_config)
        cli._journal_file(ctx, scope, "prepared", level, report, part.read_bytes())  # the hash of the copy made here
        _publish(target, part)
    return {"report": asdict(report), "scope": scope, "level": level}


def _restore_file(message: dict, session: Session) -> dict:
    src, dest = _path(message, "src"), _path(message, "dest")
    scope = _scope(message)
    force, replace = _flag(message, "force"), _flag(message, "replace")
    config = session.config()
    ctx = session.context()
    if scope not in ctx.vault.scopes():
        raise Refusal(UNKNOWN_SCOPE)
    source = _source(src)
    if Path(dest).exists() and os.path.samefile(source, dest):
        raise Refusal(OUTPUT_IS_INPUT)
    target = _target(dest, kind="restored file", suffixes=_restored_suffixes(source), replace=replace)
    markers = ctx.vault.load_map(scope)
    _refuse_work(_work(source), config.ner, len(markers.items()), restoring=True)
    with target.stage() as part:  # nothing reaches dest unless the restore is exact or forced
        report, anomalies = formats.restore_file(source, part, markers, kinds=dictionary_kinds(config))
        if anomalies and not force:
            raise Refusal(NOT_RESTORED, anomalies=anomalies)
        cli._journal_file(ctx, scope, "received", -1, report, part.read_bytes())  # before the originals land
        _publish(target, part)
    return {"report": asdict(report), "scope": scope, "anomalies": anomalies}


def _plan_prompt(message: dict, session: Session) -> dict:
    task = _string(message, "task")
    table = _path(message, "table")
    scope = _scope(message, _default_scope("plan"))
    choice = _decimal(message)
    header_ok = _flag(message, "header_ok")
    config = session.config()
    header, rows, _, decimal = _table(table, choice)
    rows = opplan.normalize_rows(rows, decimal)  # the model is told the type of every column
    detect_config = _detect_config(config)
    ctx = session.context()
    counts, names = Counter(), []
    with ctx.vault.transaction(scope) as markers:  # the task and the column names go out masked too
        masked_task, found = mask_text(task, markers, level=config.level, config=detect_config)
        counts.update(found)
        for name in header:
            masked, found = mask_text(name, markers, level=config.level, config=detect_config)
            names.append(masked)
            counts.update(found)
    prompt = opplan.plan_prompt(masked_task, opplan.infer_schema(names, rows), header_confirmed=header_ok)
    reply = _fit({"prompt": prompt, "scope": scope, "decimal": decimal, "markers_by_kind": dict(counts)})
    cli._journal_plan(ctx, scope, "prepared", dict(counts), prompt, "level 4: task and schema only")
    return reply


def _plan_run(message: dict, session: Session) -> dict:
    plan = _string(message, "plan")
    table = _path(message, "table")
    scope = _scope(message)
    choice = _decimal(message)
    out, chart_out = _optional_path(message, "out"), _optional_path(message, "chart_out")
    replace = _flag(message, "replace")
    config = session.config()
    result_file = _target(out, kind="result table", suffixes=TABLE_SUFFIXES, replace=replace) if out else None
    chart_file = _target(chart_out, kind="chart file", suffixes=(".json",), own=cli._is_chart, replace=replace) if chart_out else None
    header, rows, delimiter, decimal = _table(table, choice)
    ctx = session.context()
    if scope not in ctx.vault.scopes():
        raise Refusal(UNKNOWN_SCOPE)
    restored = restore(plan, cli._json_safe(ctx.vault.load_map(scope)), dictionary_kinds(config))
    if anomalies := restored.unknown + restored.suspicious:
        raise Refusal(PLAN_NOT_RUN, anomalies=anomalies)
    rows = opplan.normalize_rows(rows, decimal, columns=opplan.plan_columns(restored.text, header))  # only the columns the plan reads
    result = opplan.run_plan(opplan.parse_plan(restored.text, opplan.infer_schema(header, rows)), header, rows)
    table_text = io.StringIO()
    writer = csv.writer(table_text, delimiter=delimiter, lineterminator="\n")
    writer.writerow(result.header)
    writer.writerows(result.rows)
    reply = _fit({"csv": None if result_file else table_text.getvalue(), "delimiter": delimiter, "rows": len(result.rows), "chart": result.chart})
    cli._journal_plan(ctx, scope, "received", {}, plan, f"level 4 plan run, {len(result.rows)} rows")  # before any data goes out
    if result.chart and chart_file:
        _write(chart_file, json.dumps(result.chart, ensure_ascii=False).encode("utf-8"))
    if result_file:
        _write(result_file, table_text.getvalue().encode("utf-8"))
    return reply


def _provider(message: dict) -> str:
    value = message.get("provider")
    if not isinstance(value, str) or value not in channels.PROVIDERS:
        raise Refusal(BAD_REQUEST)
    return value


def _account(message: dict) -> str | None:
    value = message.get("account")
    if value is not None and (not isinstance(value, str) or value not in ACCOUNTS):
        raise Refusal(BAD_REQUEST)
    return value


def _ask(message: dict, session: Session) -> dict:
    """Mask a prompt, send it through the person's API key and return the restored answer: channels.ask, as boxed ask runs it."""
    text = _text(message)
    provider = _provider(message)
    model = _string(message, "model")
    if not channels._MODEL_RE.fullmatch(model):
        raise Refusal(BAD_REQUEST)
    account = _account(message)
    scope = _scope(message, _default_scope("ask"))
    level = _level(message)
    categories = sorted(_categories(message))
    key = channels.api_key(provider)
    if key is None:
        raise Refusal(NO_KEY)
    config = session.config()
    _detect_config(config)  # builds the models now (channels.ask finds them built), so that one that is not there is said in words
    ctx = session.context()
    try:
        result = channels.ask(
            text, provider=provider, model=model, key=key, scope=scope, vault=ctx.vault, journal=ctx.journal,
            config=config, account=account, level=level, categories=categories, transport=cli._send,
        )
    except PolicyBlocked as blocked:
        decision = blocked.decision
        raise Refusal(str(blocked), verdict=decision.verdict, reasons=decision.reasons, warnings=decision.warnings) from None
    except ValueError as e:
        if str(e) in ASK_REFUSALS or RELAY_REFUSAL.fullmatch(str(e)):
            raise Refusal(str(e)) from None
        raise
    return _fit(
        {
            "text": result.text,
            "scope": scope,
            "level": result.level,
            "verdict": result.verdict,
            "warnings": result.warnings,
            "unknown": result.unknown,
            "suspicious": result.suspicious,
            "model": result.model,
            "usage": result.usage,
            "complete": result.complete,
        }
    )


def _key_status(message: dict, session: Session) -> dict:
    """Where ask would find the key: "keychain", "environment" or None. Never the key."""
    return {"source": channels.key_source(_provider(message))}


def _key_set(message: dict, session: Session) -> dict:
    provider = _provider(message)
    key = _string(message, "key")
    try:
        channels.set_api_key(provider, key)
    except ValueError as e:
        if str(e) == channels._KEY_REFUSAL:  # fixed in channels.py; it quotes none of the key
            raise Refusal(str(e)) from None
        raise
    return {}


def _key_remove(message: dict, session: Session) -> dict:
    """Remove the keychain entry. The environment variable is the person's own: said, never read out, never touched."""
    provider = _provider(message)
    stored = channels.key_source(provider) == "keychain"
    channels.delete_api_key(provider)
    return {"removed": stored, "environment": channels.key_source(provider) == "environment"}


def _day(message: dict, name: str) -> date | None:
    """A day as YYYY-MM-DD (UTC), the form boxed journal export takes."""
    value = message.get(name)
    if value is None:
        return None
    if not isinstance(value, str) or not DAY_RE.fullmatch(value):
        raise Refusal(BAD_REQUEST)
    try:
        return cli._date(value)
    except ValueError:  # 2026-13-01: the message of strptime quotes it
        raise Refusal(BAD_REQUEST) from None


def _verdict(report: VerifyReport) -> dict:
    return {"ok": report.ok, "count": report.count, "first_bad": report.first_bad, "reason": report.reason}


def _journal_verify(message: dict, session: Session) -> dict:
    verdict = _verdict(session.context().journal.verify())
    return {"chain_ok": verdict["ok"], "count": verdict["count"], "first_bad": verdict["first_bad"], "reason": verdict["reason"]}


def _pairs(counts: Counter) -> list[list]:
    """Names and counts, the most first: a list, because a JSON object has no order and a level is a number."""
    return [[name, n] for name, n in dashboard._ranked(counts)]


def _summary_data(s: dashboard.Summary) -> dict:
    return {
        "records": s.records,
        "sent": s.by_status["sent"],
        "blocked": s.by_status["blocked"],
        "markers": sum(s.markers_by_kind.values()),
        "markers_by_kind": _pairs(s.markers_by_kind),
        "by_channel": _pairs(s.by_channel),
        "by_provider": _pairs(s.by_provider),
        "by_account_type": _pairs(s.by_account_type),
        "by_model": _pairs(s.by_model),
        "by_level": [[level, n] for level, n in dashboard._by_level(s.by_level)],  # -1 is a restore, which has no level
        "by_status": _pairs(s.by_status),
        "tokens_in": s.tokens_in,
        "tokens_out": s.tokens_out,
        "spend_micro_usd": s.spend_micro_usd,
        "spend_records": s.spend_records,
        "by_day": [[day, dict(counts)] for day, counts in s.by_day.items()],
    }


def _observed_data(records: list[dict], since: date | None, until: date | None, verdict: VerifyReport, damaged: int) -> dict:
    """What the section "Sent without boxed" of the page counts, by the rules of dashboard._observed. A send is clean only when
    it is marked "checked" and every count in it can be read, and a key kind whose count cannot be read still counts as sent."""
    sends = with_findings = gaps = 0
    kinds: Counter = Counter()
    sites: Counter = Counter()
    coverage: Counter = Counter()
    doubtful: set[str] = set()
    for rec in records:
        if not dashboard._in_period(rec, since, until):
            continue
        sends += 1
        found = dashboard._kinds(rec)
        unreadable, no_counts = dashboard._doubt(rec)
        if any(found.values()):
            with_findings += 1
        if rec.get("coverage") != "checked" or no_counts or unreadable:
            gaps += 1
        doubtful |= unreadable
        kinds.update(found)
        sites[dashboard._text(rec, "provider")] += 1
        coverage[dashboard._text(rec, "coverage")] += 1
    return {
        "chain": _verdict(verdict),
        "damaged": damaged,
        "sends": sends,
        "with_findings": with_findings,
        "gaps": gaps,
        "kinds": _pairs(kinds),
        "sites": _pairs(sites),
        "coverage": _pairs(coverage),
        "revoke": [kind for kind in dashboard.KEY_KINDS if kinds[kind] > 0 or kind in doubtful],  # sent without boxed: masking later cannot undo it
    }


def _policy_data(policy: Policy) -> dict:
    rules = {}
    for category in CATEGORIES:
        row = {}
        for kind in RECIPIENT_KINDS:
            try:
                row[kind] = str(policy.rule(category, kind))
            except PolicyError:
                row[kind] = None  # decide() refuses a pair without a rule
        rules[category] = row
    return {"categories": list(CATEGORIES), "recipients": list(RECIPIENT_KINDS), "rules": rules}


def _dashboard(message: dict, session: Session) -> dict:
    """The data the page of boxed dashboard shows: counts, kinds and names, never a value, a hash or a scope."""
    period = message.get("period")
    if period is not None and (not isinstance(period, str) or period not in dashboard.PERIOD_DAYS):
        raise Refusal(BAD_REQUEST)
    since, until = _day(message, "since"), _day(message, "until")
    if period is not None and (since or until):  # the period names the days itself
        raise Refusal(BAD_REQUEST)
    today = datetime.now(UTC).date()
    if period is not None:
        since, until = dashboard.period_bounds(period, today)
    ctx = session.context()
    records, damaged = ctx.journal.read()
    observed = observed_journal(ctx.home, ctx.keys)  # the browser's log: a chain of its own, never mixed into the journal
    seen, seen_damaged = observed.read()
    return _fit(
        {
            "period": {"since": since and since.isoformat(), "until": until and until.isoformat()},
            "chain": _verdict(ctx.journal.verify()),
            "damaged": damaged,
            "summary": _summary_data(dashboard.summarize(records, since, until)),
            "rows": dashboard.journal_rows(records, since, until),
            "observed": _observed_data(seen, since, until, observed.verify(), seen_damaged),
            "checks": cli._check_rows(ctx.home, today),  # None: the saved checks could not be read, which is not "none recorded"
            "policy": _policy_data(Policy.from_config(session.config().policy)),
        }
    )


def _journal_export(message: dict, session: Session) -> dict:
    """The records of a period as stored, with the device key to check them with: for the security team, who need no key store."""
    out = _path(message, "out")
    since, until = _day(message, "since"), _day(message, "until")
    replace = _flag(message, "replace")
    target = _target(out, kind="journal export", suffixes=(".json",), own=cli._is_export, replace=replace)
    export = dashboard.export_for_security(session.context().journal, since, until)
    _write(target, (json.dumps(export, ensure_ascii=False, indent=1) + "\n").encode("utf-8"))
    return {"records": len(export["entries"]), "public_key": export["public_key"]}


def _account_name(message: dict) -> tuple[str, str]:
    """The provider and the account a check is about: a provider the checks know and a short name, never text."""
    provider, account = message.get("provider"), message.get("account")
    if not isinstance(provider, str) or provider not in SETTINGS or not isinstance(account, str) or not ACCOUNT_RE.fullmatch(account):
        raise Refusal(BAD_REQUEST)
    return provider, account


def _checks(message: dict, session: Session) -> dict:
    """The saved checks as boxed check list shows them. A file that cannot be believed is an error, never an empty list: no
    account then reads as training off."""
    saved = load_checks(boxed_home_path())
    overdue = {(c.provider, c.account) for c in due(saved, datetime.now(UTC).date())}  # one per account: a set, not a scan
    rows = [asdict(c) | {"due": (c.provider, c.account) in overdue, "settings_url": SETTINGS[c.provider], "recipient": account_kind(c)} for c in saved]
    return {"checks": rows, "providers": list(SETTINGS), "settings": dict(SETTINGS), "note": NOTE, "fail_safe": CHECKS_FAIL_SAFE}


def _check_set(message: dict, session: Session) -> dict:
    """The person's answer about one account. The program sets the source and the date: a request cannot back-date a check."""
    provider, account = _account_name(message)
    training, memory = message.get("training"), message.get("memory")
    if not all(isinstance(state, str) and state in STATES for state in (training, memory)):
        raise Refusal(BAD_REQUEST)
    save_check(boxed_home(), Check(provider, account, training, memory, "asked", datetime.now(UTC).date().isoformat()))
    return {}


def _check_remove(message: dict, session: Session) -> dict:
    provider, account = _account_name(message)
    home = boxed_home()
    path = home / checks.FILE_NAME
    with file_lock(path):  # the browser's host may save a check at the same moment
        saved = checks._load(home)  # load_checks takes this lock too, and a second descriptor of it would wait for the first
        kept = [c for c in saved if (c.provider, c.account) != (provider, account)]
        if len(kept) == len(saved):
            raise Refusal(NO_CHECK)
        checks._write(path, json.dumps({"version": checks.VERSION, "checks": [asdict(c) for c in kept]}, indent=2) + "\n")  # the one safe way
    return {}


def _check_reset(message: dict, session: Session) -> dict:
    """Move a checks.json that cannot be believed aside, kept under a new name, so that the person can record the settings again:
    boxed check reset. A file that can be read is left alone."""
    path = boxed_home_path() / checks.FILE_NAME
    if not os.path.lexists(path):
        return {"moved": False, "kept_as": None}
    aside = path.with_name(f"{checks.FILE_NAME}.damaged-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}")
    with file_lock(path):
        try:
            checks._load(path.parent)
        except CheckError:
            pass
        else:
            raise Refusal(CHECKS_READABLE)
        if os.path.lexists(aside):
            raise Refusal(ASIDE_EXISTS)
        os.rename(path, aside)  # a file, a folder or a link: whatever stands there is kept, under its new name
    return {"moved": True, "kept_as": aside.name}


_COMMANDS: dict[str, tuple[frozenset[str], Callable[[dict, Session], dict]]] = {
    "ping": (frozenset(), _ping),
    "mask": (frozenset({"text", "scope", "level"}), _mask),
    "restore": (frozenset({"text", "scope"}), _restore),
    "mask-file": (frozenset({"src", "dest", "scope", "level", "replace"}), _mask_file),
    "restore-file": (frozenset({"src", "dest", "scope", "force", "replace"}), _restore_file),
    "policy-check": (frozenset({"text", "recipient", "categories"}), _policy_check),
    "plan-prompt": (frozenset({"task", "table", "scope", "decimal", "header_ok"}), _plan_prompt),
    "plan-run": (frozenset({"plan", "table", "scope", "decimal", "out", "chart_out", "replace"}), _plan_run),
    "ask": (frozenset({"text", "provider", "model", "account", "scope", "level", "categories"}), _ask),
    "key-status": (frozenset({"provider"}), _key_status),
    "key-set": (frozenset({"provider", "key"}), _key_set),
    "key-remove": (frozenset({"provider"}), _key_remove),
    "checks": (frozenset(), _checks),
    "check-set": (frozenset({"provider", "account", "training", "memory"}), _check_set),
    "check-remove": (frozenset({"provider", "account"}), _check_remove),
    "check-reset": (frozenset(), _check_reset),
    "journal-verify": (frozenset(), _journal_verify),
    "journal-export": (frozenset({"out", "since", "until", "replace"}), _journal_export),
    "dashboard": (frozenset({"period", "since", "until"}), _dashboard),
}

# Errors that come from other modules, each with a text that module fixes and never builds from what it was given.
_FIXED = (JournalError, FormatError, PlanError, ChannelError, CheckError)


def handle(message: dict, session: Session) -> dict:
    """{"id", "ok": True, ...} or {"id", "ok": False, "error": <fixed text>}; an error never quotes the request."""
    request_id = _request_id(message)
    try:
        cmd = message.get("cmd")
        if request_id is None or not isinstance(cmd, str) or cmd not in _COMMANDS:
            raise Refusal(BAD_REQUEST)
        fields, run = _COMMANDS[cmd]
        if not set(message) <= fields | {"id", "cmd"}:
            raise Refusal(BAD_REQUEST)
        return {"id": request_id, "ok": True, **run(message, session)}
    except _Refused as e:  # also the ones native_host's helpers raise
        return {"id": request_id, "ok": False, "error": str(e), **getattr(e, "extra", {})}
    except _FIXED as e:
        return {"id": request_id, "ok": False, "error": str(e)}
    except VaultError:  # its message names the scope
        return {"id": request_id, "ok": False, "error": VAULT}
    except LockTimeout:  # the vault of another process, which has not let it go in VAULT_WAIT seconds; no other timeout is this
        return {"id": request_id, "ok": False, "error": BUSY}
    except OSError as e:  # the message of one quotes a path
        text = _os_refusal(e)
        if text == FILE_OTHER:
            _log_failure(boxed_home_path(), "file error", e)
        return {"id": request_id, "ok": False, "error": text}
    except Exception as e:  # fail closed: the text of an exception may quote the request
        _log_failure(boxed_home_path(), "internal error", e)
        return {"id": request_id, "ok": False, "error": INTERNAL}


def _terminate(signum, frame) -> None:
    """SIGTERM: the process ends where it stands, whether it waits for a request or is in the middle of one, and the request is
    not answered. Everything a request holds is undone by the blocks it runs in: the part folder of a file goes, a vault that was
    not saved stays as it was, the journal has what was recorded before."""
    raise SystemExit(0)


def _answer_one(stdin: BinaryIO, stdout: BinaryIO, respond: Callable[[dict], dict]) -> int | None:
    """Read one frame and answer it. None: go on. A number: the exit code, once the input has ended or cannot be trusted.

    A function of its own so that the request and its answer end with its frame: the loop that calls it holds nothing of them
    while it waits for the next frame, which may be a minute away."""
    try:
        message = read_request(stdin)
    except ValueError as e:  # after a bad frame the stream cannot be trusted any more
        write_reply(stdout, {"id": None, "ok": False, "error": str(e)})
        return 1
    if message is None:
        return 0
    reply = respond(message)
    try:
        write_reply(stdout, reply)
    except ValueError as e:  # a reply that cannot be sent: say so, keep serving
        write_reply(stdout, {"id": reply.get("id"), "ok": False, "error": str(e)})
    except TypeError as e:  # a value that is no JSON: a bug in a command costs its request and not the process
        _log_failure(boxed_home_path(), "internal error", e)
        write_reply(stdout, {"id": reply.get("id"), "ok": False, "error": INTERNAL})
    return None


def _loop(stdin: BinaryIO, stdout: BinaryIO, respond: Callable[[dict], dict], again: Callable[[], bool] = lambda: True) -> int:
    """Answer frames until the input ends or `again()` says no, which it is asked after each answer: the input is then left
    unread."""
    while (code := _answer_one(stdin, stdout, respond)) is None:
        if not again():
            return 0
    return code


def _parent_gone(parent: int) -> bool:
    """Has the process that started this one ended? Its children are adopted by another (launchd, init), so the number of the
    parent changes. Windows keeps the number it started with: there only EOF on stdin ends a process, and this says no."""
    return not IS_WINDOWS and os.getppid() != parent


def _watch_parent(parent: int, done: threading.Event) -> None:
    """A thread that ends the process, at once and without a word, when its parent has ended: an app that was killed leaves no EOF
    on a pipe that another process still holds, a request that hangs is not reading it, and a busy process keeps the vault from
    the next app. `done` stops the watch."""
    if IS_WINDOWS:
        return

    def watch() -> None:
        while not done.wait(PARENT_POLL):
            if _parent_gone(parent):
                os._exit(0)  # nothing is flushed, unwound or written: no one is left to read it

    threading.Thread(target=watch, name="parent-watch", daemon=True).start()


def serve(stdin: BinaryIO, stdout: BinaryIO, session: Session, parent: int | None = None) -> int:
    """Answer frames until EOF. Every request is answered as a new process would answer it.

    Nothing of a text is meant to outlast its answer. If the tokenizer of GLiNER keeps the words it has read and the library
    gives no way to empty it (ner.words_kept), the only way to forget them is to end: the loop does, after the answer to the
    request that read them, with 0. The shell starts the program again for what comes next. It ends the same way when `parent`,
    the process that started it, has ended."""

    def again() -> bool:
        return not ner.words_kept() and not (parent is not None and _parent_gone(parent))

    return _loop(stdin, stdout, lambda message: handle(message, session), again)


def _claim_stdout() -> BinaryIO:
    """The stream the frames go to. Descriptor 1 is the pipe of the shell, and whatever writes to it - os.write(1, ...), a library
    in C, a child process a request starts - would land between two frames, which the shell takes for a bad frame and restarts the
    program. So the frames get a private copy of the descriptor (a child does not inherit it), and descriptor 1 itself is pointed
    at stderr, where the rest of the noise can do no harm. A stdout without a descriptor (a test's) is used as it is."""
    try:
        fd = sys.stdout.fileno()
    except (AttributeError, OSError, ValueError):  # io.UnsupportedOperation is both of the last two
        return sys.stdout.buffer
    sys.stdout.flush()
    frames = os.dup(fd)
    try:
        err, opened = sys.stderr.fileno(), False
    except (AttributeError, OSError, ValueError):  # no stderr (a program without a console): the noise goes nowhere
        err, opened = os.open(os.devnull, os.O_WRONLY), True
    os.dup2(err, fd)
    if opened:
        os.close(err)
    return os.fdopen(frames, "wb")


def main() -> int:
    # The language models load from the local cache and never from the hub: behind a proxy that cuts the connection every request
    # would fail, and a window must not wait for a download. Set before anything imports a library that reads them.
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    stdout = _claim_stdout()
    stdin = sys.stdin.buffer
    sys.stdout = sys.stderr  # and a print of Python's goes there too
    signal.signal(signal.SIGTERM, _terminate)
    parent, watching = os.getppid(), threading.Event()
    _watch_parent(parent, watching)
    try:
        clear_stale_parts()
        return serve(stdin, stdout, Session(_ner_from_env(os.environ)), parent)
    except SystemExit as e:  # SIGTERM
        return e.code if type(e.code) is int else 0
    except OSError:  # the shell is gone: nobody is left to tell
        return 1
    finally:
        watching.set()
