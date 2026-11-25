"""Claude Code hooks for masked workspaces. Outside a workspace every hook is a no-op."""

import functools
import hashlib
import json
import os
import re
import shlex
import stat
import unicodedata
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from . import __version__
from .config import to_detect_config
from .detect import detect
from .journal import Journal, JournalEntry
from .keys import default_keystore
from .workspace import MARKER_FILE, RESERVED, SENSITIVE_HOME_PARTS, Workspace, load_workspace, load_workspace_config

SESSION_NOTE = (
    "This is a boxed.si masked workspace. Values like [EMAIL_1] or [SECRET_2] are placeholders for real data "
    "that stays on the user's computer. Keep every placeholder exactly as it is, never invent new ones, "
    "and work only with files inside this folder. File names can hold placeholders too: quote such paths in "
    "shell commands, for example cat 'exports/[EMAIL_1].csv'."
)
PATH_FIELDS = {
    "Read": ("file_path",),
    "Write": ("file_path",),
    "Edit": ("file_path",),
    "MultiEdit": ("file_path",),
    "NotebookEdit": ("notebook_path",),
    "Grep": ("path",),
    "Glob": ("pattern", "path"),
}
WRITE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")
GLOB_CHARS = "*?[{"
# What a wildcard stands for is read from the files, as the shell does before the program runs: at most GLOB_LIMIT folders or links on the
# way of one pattern, GLOB_DEPTH parts with a wildcard in it and GLOB_SCAN entries of folders for a whole command. More is not read: blocked.
GLOB_LIMIT = 1000
GLOB_DEPTH = 8
GLOB_SCAN = 100_000
PATH_LIMIT = 4096  # the longest path a system call takes (macOS 1024, Linux 4096)
# a part of a path that stands for names: * ? [, a brace the guard could not expand ({1..3}), zsh's leading ^ (every name but)
WILDCARD_PART = re.compile(r"[*?\[]|\{[^{}]+\}|^\^")
# zsh: <-> and <1-9> stand for the names that are numbers; the guard turns < and > into spaces, so they are made a wildcard first
ZSH_RANGE = re.compile(r"<\d*-\d*>")
# the classes of a bracket expression as parts of a regex set; any character past ASCII counts as a member (a letter of another script)
NON_ASCII = "\u0080-\U0010ffff"
POSIX_CLASSES = {
    "alpha": "a-zA-Z" + NON_ASCII, "digit": "0-9", "alnum": "0-9a-zA-Z" + NON_ASCII, "upper": "A-Z" + NON_ASCII, "lower": "a-z" + NON_ASCII,
    "space": " \t\n\r\f\v" + NON_ASCII, "blank": " \t" + NON_ASCII, "punct": "!-/:-@\\[-`{-~" + NON_ASCII, "print": " -~" + NON_ASCII, "graph": "!-~" + NON_ASCII,
    "cntrl": "\x00-\x1f\x7f" + NON_ASCII, "xdigit": "0-9a-fA-F", "word": "0-9a-zA-Z_" + NON_ASCII,
}
# in a set that takes names out ([!..]) a class must be the smaller one: the names left are then the more
ASCII_CLASSES = {name: members.replace(NON_ASCII, "") for name, members in POSIX_CLASSES.items()}
CLASS_NAME = re.compile(r"\[:([^\]:]*):\]")
DENIED = "boxed: {tool} blocked: it points outside the masked workspace. Work only with files inside this folder."
BOXED_DENIED = "boxed: {tool} blocked: boxed commands do not run inside the masked workspace. Run them in your own terminal."
FILE_DENIED = (
    "boxed: {tool} blocked: git config and hooks, .pth files, sitecustomize.py, usercustomize.py and the files boxed keeps in this "
    "folder run commands or switch the guard off. Edit them in your own editor."
)
# what a hook says when it fails inside a copy; the model may see it, so it carries no path, no value and no error text
HOOK_FAILED = "boxed: the hook failed and blocked this step; details are in the boxed hook error log"
CONTENT_DENIED = (
    "boxed: {tool} blocked: this text would run boxed (an import, a module run or a boxed command). boxed commands do not run "
    "inside the masked workspace. Run them in your own terminal."
)
# An edit is judged on the file it leaves, so the file is read: the biggest one that is, and what is said of a bigger one.
EDIT_LIMIT = 16 * 1024 * 1024
FILE_TOO_BIG = "boxed: {tool} blocked: the file is too large to check for commands that run boxed. Edit it in your own editor."
# boxed code itself: the native host, an import of boxed in inline code, anywhere in an import list (import os, boxed)
BOXED_MODULE = re.compile(
    r"boxed-native-host\b|boxed\.native_host\b|\bimport\s+(?:[\w.]+(?:\s+as\s+\w+)?\s*,[\s\\]*)*boxed\b|\bfrom\s+boxed[\w.]*\s+import\b"
)
# a quoted module name in Python code is a dynamic import: __import__('boxed'), importlib.import_module("boxed.cli")
QUOTED_MODULE = re.compile(r"""['"]boxed(?=[.'"])""")
# something that runs Python code, anywhere in the command: python3.13, /usr/bin/python3, ipython, pypy3; uv (uv run - reads a script)
PYTHON = re.compile(r"(?<![\w-])(?:[ib]?python|pypy|uvx?(?![\w-]))", re.IGNORECASE)
# a module run through any launcher: python -m boxed, python3 -Im boxed.cli, python -mboxed, uv run --module boxed
MODULE_FLAG = re.compile(r"(?:-[A-Za-z]*m|--module)\s*boxed\b")
# a module flag alone in its word: the module is the next word, or one the words do not show (>/dev/null boxed, "$(echo boxed)")
LONE_FLAG = re.compile(r"(?<!\S)(?:-[A-Za-z]*m|--module)(?!\S)")
# pytest and these git commands take a message or a marker after -m, not a module: -m boxed, -am boxed (the next word), -mfix
# (the same word). Git runs an alias with the words after it, so after any other name -m could still be a module flag.
GIT_COMMANDS = frozenset({"commit", "tag", "merge", "stash", "notes", "revert", "cherry-pick", "rebase", "log", "show", "branch",
                          "checkout", "switch", "diff"})
MESSAGE_FLAG = re.compile(r"-[A-Za-z]*m(.*)", re.DOTALL)
# That -m is set aside only on one plain line. A comment, an expansion or substitution ($), a here-doc or redirect from a file
# (<), a separator (; & |), a group (( )) and a line break can start or hide a second command, and a shlex parse does not
# model them (bash drops what follows #, a here-doc body is data, $'..' has its own quotes): such a line is judged as before,
# every module flag in it is a hit.
UNPLAIN = re.compile(r"[#$`;&|()<\n\r\x00]")
# quotes and backslashes (and a line continuation with them) that a nested shell removes when it reads the string
NESTED_QUOTING = re.compile(r"""\\\n|['"\\]""")
# absolute or ~ paths inside quoted code; a name must follow the slash, so `4 / 2` is not a path
RAW_PATH = re.compile(r"(?<![\w.])(?:~/?|/)[\w.\-]+(?:/[\w.\-]+)*")
# shell punctuation glues paths to commands: "ls ~;", "$(ls ~)", "x|head"
SHELL_PUNCT = re.compile(r"[;&|()<>`]")
# a run of backslashes before a line break: bash pairs them up from the left, so with an odd number the last one joins the lines
CONTINUATION = re.compile(r"(?<!\\)(\\+)\n")
# ~+ is the folder the shell is in, ~- the one it left, ~2 one on the stack: Python does not expand them and a cd changes them
TILDE_STACK = re.compile(r"~[+\-0-9]")
SHELL_TOOLS = ("Bash", "Monitor")
# A lone "/" is a division sign, not the root, in a whole line of expr over numbers and in a $(( .. )) word made only of numbers and
# signs. That word stands between blanks: glued to other text, even a closing quote, its value could finish a protected name
# ("site"$(( 6 / 3 )) is site2). It is replaced by its value, which can be the name of a link (ls $(( 6 / 3 )) is ls 2). The rest of the
# line must be plain words (no $, backslash, backtick, group, separator, redirect, glob or brace): the guard cannot see through those,
# and a line that was blocked by the division sign alone must not pass because of it.
EXPR_LINE = re.compile(r"expr[ \t]+[0-9]+(?:[ \t]+(?:[-+/%]|\\\*)[ \t]+[0-9]+)*")
ARITHMETIC = re.compile(r"\$\(\(([ \t0-9+*/%-]*)\)\)")
ARITHMETIC_WORD = re.compile(rf"(?<![^ \t]){ARITHMETIC.pattern}(?![^ \t])")
PLAIN_LINE = re.compile(r"""[\w@%+,.:/~=\- \t'"]*""")
# cd <plain path> && <line>: two simple commands and nothing else on the line. The path is plain words and no option (it does not start
# with -), so there is no quote, expansion, glob or second command in it. The line is judged as it would be alone, and its relative
# paths are read from the folder the cd goes to, when that folder is inside the mirror. It has no glob or brace character (bash would
# match names the guard never looks at: pe* is the link peek), no $ but $HOME and no backslash: such a line is judged as before.
CD_THEN = re.compile(r"cd[ \t]+([\w./][\w./-]*)[ \t]*&&[ \t]*((?:[^*?\[{$\\\r\n]|\$HOME(?!\w)|\$\{HOME\})+)")
BLANKS = " \t\n"  # what bash skips around a command; a carriage return or a form feed is part of the command's name
# echo, printf and pwd only print their words: a whole line of them over plain words, quoted text and $HOME reads nothing, so a path
# that merely holds protected data (~, /, the folder above the project) may be printed. A path inside a protected folder may not.
PRINT_LINE = re.compile(
    r"""(?:echo|printf|pwd)(?:[ \t]+(?:[\w@%+,.:/~-]|\$HOME(?!\w)|\$\{HOME\}|'[^'\n\r\x00]*'"""
    r"""|"(?:[^"\\$`\n\r\x00]|\\[A-Za-z0-9]|\$HOME(?!\w)|\$\{HOME\})*")+)*"""
)
# Text written into a file is judged by what the file is, and only where boxed would really run once something runs the file: an import
# of the package at the start of a statement, a dynamic import or a spawn that names boxed in a literal, the native host, boxed with one
# of its subcommands (or an argument filled in later) at the start of a command or of a string handed on, and a module run through a
# Python launcher at the start of a command. The bare word, a name that contains it, prose around a command name and another
# language's own `boxed` are not hits, and neither is anything in a file that is only read (prose, markup, data tables). Names built at
# run time are not seen (README, known limits).
CONTENT_NATIVE = re.compile(r"boxed-native-host\b|boxed\.native_host\b")
PY_IMPORT = re.compile(
    r"(?:^|;)[ \t]*(?:(?:else|try|finally)[ \t]*:[ \t]*|(?:if|elif|while|for|with|except)\b[^\n#]*?:[ \t]*(?=import|from))?"
    r"(?:import[ \t]+(?:[\w.]+(?:[ \t]+as[ \t]+\w+)?[ \t]*,[ \t\\\n]*)*boxed\b(?![ \t]+from\b)|from[ \t]+boxed(?:[ \t]*\.[ \t]*\w+)*[ \t]+import\b)",
    re.MULTILINE,
)
CONTENT_DYNAMIC = re.compile(
    r"""\b(?:__import__|import_module|run_module|find_spec|load_module)\s*\(\s*[rRbBuUfF]{0,2}['"]boxed(?=[.'"])"""
    r"""|\bexec\s*\(\s*[rRbBuUfF]{0,2}['"]\s*(?:import|from)[ \t]+boxed\b"""
)
CONTENT_FLAGS = re.compile(r"(?:[ \t]+-\S+)*+")
BOXED_WORD = re.compile(r"boxed(?:\.cli)?(?![\w-])")
PATH_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.~$-/")
# what may stand right before the name: a line start (after a prompt or a make prefix), a separator or group, the first word of a string
# in a call or a value, a wrapper command, a key whose value is a command, a Dockerfile instruction. An = starts a string only after a
# blank (cmd = "boxed run"), not in an attribute (class="boxed check"); cmd="boxed run" is a key.
LINE_START = re.compile(r"[ \t]*(?:\$[ \t]+)?[@+\-]*")
SHELL_START = (
    r"""[;&|({!)][ \t]*|\$\([ \t]*|`[ \t]*"""
    r"""|\b(?:sudo|doas|exec|env|nohup|time|xargs|command|builtin|nice|ionice|setsid|stdbuf|timeout|watch|parallel|then|else|do)[ \t]+"""
    r"""(?:(?:-\S+|\w+=\S*|\d+[smhd]?)[ \t]+)*|\b(?:RUN|CMD|ENTRYPOINT)[ \t]+"""
)
STRING_START = (
    r"""(?:[(\[,:{]|(?<=[ \t])=)[ \t]*[rRbBuUfF]{0,2}['"`][ \t]*"""
    r"""|(?:\beval|\btrap|(?<!\S)-[A-Za-z]*c)[ \t]+['"]?[ \t]*"""
    r"""|\b(?:run|entry|command|cmd|args|script|exec|shell)[ \t]*[:=][ \t]*['"]?[ \t]*"""
)
COMMAND_START = re.compile(rf"(?:{SHELL_START}|{STRING_START})$")  # in a shell script, a Makefile, a Dockerfile, a CI file
CODE_START = re.compile(rf"(?:{STRING_START})$")  # in code: the first word of a string
QUOTES = frozenset("'\"`")
# What a file is, from its name and its first line: only its kind says what in it is run. Unknown means a script.
PROSE_SUFFIXES = frozenset(
    ".md .markdown .mdx .txt .text .rst .adoc .asciidoc .org .tex .html .htm .xhtml .xml .svg .css .scss .sass .less .csv .tsv .log .rtf .srt .vtt .ics .vcf".split()
)
PROSE_NAMES = frozenset("readme license licence notice authors changelog copying contributing todo history news credits thanks".split())
PYTHON_SUFFIXES = frozenset(".py .pyw .pyi .pyx".split())
CODE_SUFFIXES = frozenset(
    ".js .mjs .cjs .jsx .ts .tsx .vue .svelte .astro .rb .go .rs .java .kt .kts .scala .groovy .php .pl .pm .lua .swift .c .h .cc .cpp .hpp .cs .m .mm .dart "
    ".ex .exs .erl .hs .ml .r .jl".split()
)


class WorkspaceError(Exception):
    pass


@dataclass
class HookResult:
    exit_code: int
    stdout: str = ""
    stderr: str = ""


def find_marker(cwd: Path) -> Path | None:
    for directory in [cwd, *cwd.parents]:
        if (directory / MARKER_FILE).is_file():
            return directory
    return None


def inside_workspaces(path: Path, home: Path) -> bool:
    workspaces = (home / "workspaces").resolve()
    return path != workspaces and path.is_relative_to(workspaces)


def find_workspace(cwd: Path, home: Path) -> Workspace | None:
    cwd = cwd.resolve()
    root = find_marker(cwd)
    if root is None:
        if inside_workspaces(cwd, home):
            raise WorkspaceError("this boxed mirror has lost its marker file")
        return None
    ws_id = json.loads((root / MARKER_FILE).read_text())["id"]
    ws = load_workspace(ws_id, home)
    if ws.mirror.resolve() != root.resolve():
        raise WorkspaceError("workspace marker does not match its mirror")
    return ws


def _payload_cwd(payload: dict) -> Path:
    return Path(payload.get("cwd") or os.getcwd())


def _resolve(value: str, cwd: Path) -> Path:
    p = Path(os.path.expanduser(value))
    return (p if p.is_absolute() else cwd / p).resolve()


def _fold(text: str) -> str:
    """A path as a case blind file system that ignores the form of an accent sees it."""
    return unicodedata.normalize("NFC", text).casefold()


def _folded(path: Path) -> PurePosixPath:
    return PurePosixPath(_fold(str(path)))


def _lexical(value: str, cwd: Path) -> Path:
    """The path as written, with .. folded but links not followed: a link named .git is a .git."""
    return Path(os.path.normpath(os.path.join(cwd, os.path.expanduser(value))))


@functools.lru_cache(maxsize=1)
def _boxed_names() -> str:
    """Every boxed subcommand as a regex alternation, read from the CLI parser: a command added later is covered too."""
    import argparse

    from .cli import build_parser

    action = next(a for a in build_parser()._actions if isinstance(a, argparse._SubParsersAction))
    return "|".join(re.escape(name) for name in sorted(action.choices, key=len, reverse=True))


class _Reveal:
    """boxed with one of its subcommands, flags allowed in between: `boxed -v restore`, `/usr/bin/boxed run`, `x;boxed mask`.
    The name starts a command after a space or one of ; & | ( ` ' " or after a path; any path ends in a slash and starts after a space, so
    one slash before the name says the same as a prefix of any length, without a scan of the prefix from every quote. Flags that lead to
    no subcommand are read once: a name inside them (boxed -x/boxed -x/boxed ...) would only reach the same end."""

    def __init__(self, names: str) -> None:
        self.start = re.compile(r"(?:^|[\s;&|(`'\"/])boxed(?:\.cli)?")
        self.tail = re.compile(rf"(?:\s+-\S+)*+(\s+(?:{names})(?![\w-]))?")

    def search(self, text: str) -> bool:
        skip = 0
        for found in self.start.finditer(text):
            if found.start() < skip:
                continue
            tail = self.tail.match(text, found.end())
            if tail[1]:
                return True
            skip = tail.end()
        return False


@functools.lru_cache(maxsize=1)
def boxed_reveal() -> _Reveal:
    """Every boxed subcommand, read from the CLI parser: a command added later is blocked inside a mirror too."""
    return _Reveal(_boxed_names())


@functools.lru_cache(maxsize=1)
def _content_spawn() -> re.Pattern:
    """["boxed", "restore"] and "boxed", ["restore"]: a program and its subcommand as separate literals."""
    names = _boxed_names()
    return re.compile(
        rf"""\[\s*['"](?:[^'"\s]*/)?boxed(?:\.cli)?['"]\s*,\s*(?:['"]-[^'"]*['"]\s*,\s*)*['"](?:{names})['"]"""
        rf"""|['"](?:[^'"\s]*/)?boxed['"]\s*,\s*\[\s*['"](?:{names})['"]"""
    )


@functools.lru_cache(maxsize=1)
def _content_subcommand() -> re.Pattern:
    """A subcommand, or an argument filled in when the script runs (exec boxed "$@" runs what the caller gives it), after the flags."""
    return re.compile(rf"""[ \t]+(?:(?:{_boxed_names()})(?![\w-])|["']?\$[@*#?!$\-\w{{(])""")


def _shell_words(command: str) -> tuple[str, list[str]]:
    """The command with $HOME spelled out, and its words with shell punctuation, quotes and escapes removed.
    Words are split before $HOME is spelled out, so a home with spaces or quotes stays inside one word."""
    home_dir = os.path.expanduser("~")

    def spell(text: str) -> str:
        return text.replace("${HOME}", home_dir).replace("$HOME", home_dir)

    flat = SHELL_PUNCT.sub(" ", command)
    try:
        words = shlex.split(flat)
    except ValueError:
        words = flat.split()
    return spell(command), [spell(w) for w in words]


def _nested_words(words: list[str], depth: int = 3) -> list[str]:
    """The words, and the words inside any word that holds a blank: a string handed to another shell (sh -c 'ls li*') is read again by it."""
    found = list(words)
    for word in words if depth else ():
        if any(char.isspace() for char in word):
            found += _nested_words(_shell_words(word)[1], depth - 1)
    return found


def _join_lines(command: str) -> str:
    """bash deletes a backslash and the line break after it before it reads any word; an escaped backslash (\\\\) before the break
    is no continuation: the next line is a command of its own."""
    return CONTINUATION.sub(lambda run: run[1][:-1] if len(run[1]) % 2 else run[0], command)


def _expr_line(command: str) -> bool:
    return EXPR_LINE.fullmatch(command.strip(BLANKS)) is not None


def _arithmetic_value(expression: str) -> int | None:
    """The value of whole numbers joined by + - * / % (the usual precedence, left to right), or None for anything the shell could read
    otherwise: a sign in front of a number, two signs in a row, a number that starts with 0 (octal in bash, decimal in zsh), a division by
    zero, a number that does not fit in 62 bits. Division and remainder only ever meet numbers that are not negative, so they agree with C."""
    parts = re.findall(r"\d+|[-+*/%]", expression)
    numbers, signs = parts[0::2], parts[1::2]
    if len(parts) % 2 == 0 or not all(p.isdigit() for p in numbers) or any(p.isdigit() for p in signs):
        return None
    if any(len(p) > 18 or (len(p) > 1 and p[0] == "0") for p in numbers):
        return None
    total, term, sign = 0, int(numbers[0]), 1
    for op, number in zip(signs, map(int, numbers[1:])):
        if op in "+-":
            total, term, sign = total + sign * term, number, 1 if op == "+" else -1
        elif op == "*":
            term *= number
        elif number == 0:
            return None
        else:
            term = term // number if op == "/" else term % number
        if term >= 1 << 62:
            return None
    total += sign * term
    return total if abs(total) < 1 << 62 else None


def _arithmetic_words(command: str) -> str:
    """The command with each arithmetic word replaced by its value, when the rest of the line is plain words and every word can be computed.
    On a line that is not plain the text stays (the division signs in it keep it blocked) and the values of the arithmetic in it, glued
    to other text or not, are added at the end: they are names, and a link may be called so."""
    values = []

    def value(word: re.Match) -> str:
        values.append(_arithmetic_value(word[1]))
        return str(values[-1])

    numbers = ARITHMETIC_WORD.sub(value, command)
    if None not in values and PLAIN_LINE.fullmatch(numbers):
        return numbers
    computed = [v for v in map(_arithmetic_value, (m[1] for m in ARITHMETIC.finditer(command))) if v is not None]
    return "\n".join([command, *map(str, computed)])


def _prints_only(command: str) -> bool:
    return PRINT_LINE.fullmatch(command.strip(BLANKS)) is not None


def _after_cd(command: str) -> tuple[str, str] | None:
    """The path and the line of `cd <plain path> && <line>`."""
    moved = CD_THEN.fullmatch(command.strip(BLANKS))
    return (moved[1], moved[2]) if moved else None


def _cd_is_exact(path: str) -> bool:
    """A path the shell reaches from where it is: `.`, `./x` or `/x`. CDPATH is not searched for these (bash and zsh), and with no `..`
    in them the shell has nothing to fold before it follows a link. `src` could be $CDPATH/src."""
    return (path == "." or path.startswith(("./", "/"))) and ".." not in path.split("/")


def _takes_messages(words: list[str]) -> bool:
    """pytest, or git with a built-in command after its -C, -c and pager options."""
    if words[:1] == ["pytest"]:
        return True
    if words[:1] != ["git"]:
        return False
    i = 1
    while i < len(words) and words[i] in ("-C", "-c", "-p", "-P", "--paginate", "--no-pager"):
        i += 2 if words[i] in ("-C", "-c") else 1
    return i < len(words) and words[i] in GIT_COMMANDS


def _only_messages(command: str) -> bool:
    """One plain line of pytest or a git built-in, whose every module flag is the -m of a message or a marker. After those
    -m options are set aside no module flag may be left, even one whose module the words do not show. A line that is not
    plain, quoting that does not parse and a hit the parsed words do not explain all keep the call blocked."""
    command = command.strip(BLANKS)  # what bash skips: a form feed in front is part of the command's name
    if UNPLAIN.search(command):
        return False
    try:
        words = shlex.split(command)
    except ValueError:
        return False
    if not _takes_messages(words) or not MODULE_FLAG.search(" ".join(words)):
        return False
    kept, i = [], 0
    while i < len(words):
        flag = MESSAGE_FLAG.fullmatch(words[i])
        if flag:
            i += 1 if flag[1] else 2  # the flag with its message, or the flag alone when the message is attached
        else:
            kept.append(words[i])
            i += 1
    left = " ".join(kept)
    return not (MODULE_FLAG.search(left) or LONE_FLAG.search(left))


def _runs_module(command: str, texts: list[str]) -> bool:
    """python -m boxed through any launcher: a module flag followed by boxed, unless it is only the -m of a git or pytest message."""
    return any(MODULE_FLAG.search(text) for text in texts) and not _only_messages(command)


def _runs_boxed(command: str, words: list[str]) -> bool:
    """The boxed patterns only where "boxed" occurs. The joined words drop
    quotes and escapes ("boxed" restore, bo''xed restore). The command without any quote or backslash does the same for a
    string that a second shell reads later (sh -c 'bo""xed re\\store', git -c core.pager=...), where they are still in the
    words."""
    texts = [text for text in (command, " ".join(words), NESTED_QUOTING.sub("", command)) if "boxed" in text]
    return any(
        boxed_reveal().search(text) or BOXED_MODULE.search(text) or (PYTHON.search(text) and QUOTED_MODULE.search(text))
        for text in texts
    ) or _runs_module(command, texts)


def _starts_a_command(line: str, end: int, kind: str) -> bool:
    """Whether a command, or a string handed on as one, may start at `end` of the line. A script is read by a shell: a line start, a
    separator, a wrapper, a string. Code only hands a string on, and a quote before on the line says the separators and wrappers after it
    are in one (os.system("cd x && boxed run")): the sentence "a time boxed plan" is no command there."""
    before = line[max(0, end - 600) :end]
    i = len(before)
    while i and before[i - 1] in PATH_CHARS and len(before) - i < 200:
        i -= 1
    if before[i:].endswith("/"):  # a path in front of the name: /usr/local/bin/boxed, ./boxed, ~/bin/boxed
        before = before[:i]
    tail = before[-160:]
    if kind in ("python", "code"):
        return CODE_START.search(tail) is not None or (not QUOTES.isdisjoint(before) and COMMAND_START.search(tail) is not None)
    return (end <= 300 and LINE_START.fullmatch(before) is not None) or COMMAND_START.search(tail) is not None


def _line_runs_boxed(line: str, kind: str = "script") -> bool:
    kinds = ("script", "python") if kind == "both" else (kind,)

    def starts(end: int) -> bool:
        return any(_starts_a_command(line, end, k) for k in kinds)

    # inline code or a module run: python3 -c 'import boxed', python3 -m boxed, uv run -m boxed
    launched = next((m.end() for m in PYTHON.finditer(line) if starts(m.start())), None)
    if launched is not None and (QUOTED_MODULE.search(line, launched) or BOXED_MODULE.search(line, launched)
                                 or (MODULE_FLAG.search(line, launched) and not _only_messages(line))):
        return True
    # boxed with a subcommand: a name inside the flags of one already read (boxed -x/boxed ...) ends where that one did
    covered, found = 0, False
    for m in BOXED_WORD.finditer(line):
        if not (m.end() < covered and line[m.end() : m.end() + 1] in (" ", "\t")):  # else the flags of the name before it end where its flags end
            covered = CONTENT_FLAGS.match(line, m.end()).end()
            found = _content_subcommand().match(line, covered) is not None
        if found and starts(m.start()):
            return True
    return False


def _is_comment(line: str, kind: str) -> bool:
    """A comment is never run: a line of # (shell, Python, Make, YAML, Dockerfile) and, in code, of //."""
    stripped = line.lstrip(" \t")
    return stripped.startswith("#") or (kind == "code" and stripped.startswith("//"))


def _notebook_cells(text: str) -> list[str] | None:
    """The source of each code cell in the JSON of a notebook, or None when the text is no notebook."""
    try:
        data = json.loads(text)
    except ValueError:
        return None
    cells = data.get("cells") if isinstance(data, dict) else None
    if not isinstance(cells, list):
        return None
    sources = []
    for cell in cells:
        if isinstance(cell, dict) and cell.get("cell_type") == "code":
            source = cell.get("source")
            sources.append("".join(source) if isinstance(source, list) and all(isinstance(s, str) for s in source) else source if isinstance(source, str) else "")
    return sources


def _content_kind(path: object, text: str) -> str:
    """What a file is, from its first line and its name: "prose" (only read, never run), "python", "code" (another language), "notebook" or
    "script" (a shell script, a Makefile, a Dockerfile, a config file, and whatever else is not known)."""
    first = text[:300].split("\n", 1)[0]
    if first.startswith("#!"):
        return "python" if "python" in first else "script"
    name = PurePosixPath(str(path or "").lower()).name
    suffix = PurePosixPath(name).suffix
    if suffix == ".ipynb":
        return "notebook"
    if suffix in PYTHON_SUFFIXES:
        return "python"
    if suffix in CODE_SUFFIXES:
        return "code"
    return "prose" if suffix in PROSE_SUFFIXES or (not suffix and name in PROSE_NAMES) else "script"


def _writes_boxed(text: str, kind: str = "script") -> bool:
    """Whether text that is going into a file of this kind would run boxed once something runs the file."""
    if kind == "prose":
        return False
    if kind == "notebook":
        cells = _notebook_cells(text)
        return _writes_boxed(text, "both") if cells is None else any(_writes_boxed(cell, "both") for cell in cells)
    flat = NESTED_QUOTING.sub("", text)  # what a shell reads of bo''xed or a name split by a line continuation
    if "boxed" not in flat:
        return False
    if CONTENT_NATIVE.search(text) or CONTENT_DYNAMIC.search(text) or _content_spawn().search(text):
        return True
    if kind != "code" and PY_IMPORT.search(text):
        return True
    return any(_line_runs_boxed(line, kind) for t in {text, flat} for line in t.split("\n") if "boxed" in line and not _is_comment(line, kind))


class _TooBig(Exception):
    pass


def _file_text(path: Path) -> str | None:
    """What a file holds now, read as text; None when there is no regular file to read (a pipe would never end)."""
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            return None
        with open(path, "rb") as f:
            data = f.read(EDIT_LIMIT + 1)
    except OSError:
        return None
    if len(data) > EDIT_LIMIT:
        raise _TooBig
    return data.decode("utf-8", errors="replace")


def _written_texts(tool: str, tool_input: dict, current: str | None = None) -> list[str]:
    """What a write tool puts into the file: its new text, and for an edit the file it leaves too (edits complete what the file has: a file
    that says `boxed x`, an edit that turns x into restore). A text the edit takes out is never judged."""
    if tool == "Write":
        values = [tool_input.get("content")]
    elif tool in ("Edit", "MultiEdit"):
        edits = [tool_input] if tool == "Edit" else tool_input.get("edits")
        edits = [e for e in edits if isinstance(e, dict)] if isinstance(edits, list) else []
        values = [e.get("new_string") for e in edits]
        for e in edits if current is not None else ():  # one after the other, as the tool does
            old, new = e.get("old_string"), e.get("new_string")
            if isinstance(old, str) and isinstance(new, str):
                current = (current or new) if old == "" else current.replace(old, new, -1 if e.get("replace_all") else 1)
        values.append(current)
    elif tool_input.get("cell_type") == "markdown":  # NotebookEdit: a markdown cell is read, not run
        values = []
    else:
        values = [tool_input.get("new_source")]
    return [v for v in values if isinstance(v, str)]


def _expand_braces(text: str, limit: int = 64) -> list[str] | None:
    """Shell-style {a,b} expansion, innermost first; None when a pattern grows past `limit` variants."""
    done, todo = [], [text]
    while todo:
        s = todo.pop()
        m = re.search(r"\{([^{}]*,[^{}]*)\}", s)
        if m is None:
            done.append(s)
        else:
            todo += [s[: m.start()] + alt + s[m.end() :] for alt in m.group(1).split(",")]
        if len(done) + len(todo) > limit:
            return None
    return done


def _static_dir(pattern: str) -> str:
    """Where a glob pattern starts: everything before the name that holds the first wildcard."""
    cut = min((pattern.index(c) for c in GLOB_CHARS if c in pattern), default=None)
    if cut is None:
        return pattern or "."
    head = pattern[:cut]
    return head[: head.rfind("/") + 1] or "."


def _has_wildcard(text: str) -> bool:
    return any(WILDCARD_PART.search(part) for part in text.split("/"))


def _bracket_end(part: str, i: int) -> int | None:
    """The index of the ] that closes the bracket expression whose first character after the [ is at i, or None. A ] right at the start is
    one of the characters, and so is a ] inside [:class:]."""
    j = i + 1 if part[i : i + 1] in ("!", "^") else i
    j += part[j : j + 1] == "]"
    while j < len(part):
        if part.startswith("[:", j) and part.find(":]", j + 2) != -1:
            j = part.find(":]", j + 2) + 2
        elif part[j] == "]":
            return j
        else:
            j += 1
    return None


def _bracket(body: str):
    """One character of a bracket expression: a regex for it, or None for any character. A range is any character: where [a-z] stops
    depends on the collation of the locale (é, B, even ^ in [%-+]), which the guard cannot ask. So is a class it does not know."""
    negate = body[:1] in ("!", "^")
    body, out, i = (body[1:] if negate else body), [], 0
    classes = ASCII_CLASSES if negate else POSIX_CLASSES
    while i < len(body):
        end = body.find(":]", i + 2)
        if body.startswith("[:", i) and end != -1:
            if body[i + 2 : end] not in classes:
                return None
            out.append(classes[body[i + 2 : end]])
            i = end + 2
        elif body[i + 1 : i + 2] == "-" and i + 2 < len(body):
            return None
        else:
            out.append("\\" + body[i] if body[i] in "\\]^[-" else body[i])
            i += 1
    try:
        return re.compile(("[^" if negate else "[") + "".join(out) + "]", re.DOTALL)
    except re.error:
        return None


class _Wildcard:
    """A part of a path with wildcards. It matches every name the shells match with it (bash and zsh: * ? [..] [!..] [^..] [[:class:]], a
    brace left over, zsh's ^), and a name too many is harmless: the guard only blocks more. A shell in the C locale counts the bytes of a
    name as its characters (? stands for one of the two bytes of é), so a name is matched as characters and as bytes. It walks the pattern
    once with one star to go back to, so no name can make it slow."""

    def __init__(self, part: str, by_bytes: bool = False) -> None:
        # long, zsh's all-but, an equivalence class or collating symbol, [!] (any one name in zsh), a class the shell may read as something else
        # (an unknown name, or a [: that is not [:name:]: [n[:]] is a bracket with an empty class in it)
        self.everything = (len(part) > 512 or part.startswith("^") or any(mark in part for mark in ("[=", "[.", "[!]", "[^]"))
                           or part.count("[:") != len(CLASS_NAME.findall(part)) or any(name not in POSIX_CLASSES for name in CLASS_NAME.findall(part)))
        self.tokens, i = [], 0
        while not self.everything and i < len(part):
            c, i = part[i], i + 1
            if c == "*":
                if not self.tokens or self.tokens[-1] != ("*",):
                    self.tokens.append(("*",))
            elif c == "[" and (end := _bracket_end(part, i)) is not None:
                one = _bracket(part[i:end])
                self.tokens.append(("?",) if one is None else ("[", one))
                i = end + 1
            elif c == "{" and (end := part.find("}", i)) != -1:
                self.tokens.append(("*",))
                i = end + 1
            else:
                self.tokens.append(("?",) if c == "?" else ("=", c))
        self.bytes = None if by_bytes or part.isascii() else _Wildcard(part.encode("utf-8", "surrogateescape").decode("latin-1"), True)

    @staticmethod
    def one(token: tuple, char: str) -> bool:
        return token[0] == "?" or (token[0] == "=" and token[1] == char) or (token[0] == "[" and token[1].fullmatch(char) is not None)

    def walk(self, name: str) -> bool:
        t = n = mark = 0
        star = -1
        while n < len(name):
            if t < len(self.tokens) and self.tokens[t] == ("*",):
                star, mark, t = t, n, t + 1
            elif t < len(self.tokens) and self.one(self.tokens[t], name[n]):
                t, n = t + 1, n + 1
            elif star != -1:
                t, mark = star + 1, mark + 1
                n = mark
            else:
                return False
        while t < len(self.tokens) and self.tokens[t] == ("*",):
            t += 1
        return t == len(self.tokens)

    def fullmatch(self, name: str) -> bool:
        if self.everything or self.walk(name):
            return True
        if name.isascii():
            return False
        return (self.bytes or self).walk(name.encode("utf-8", "surrogateescape").decode("latin-1"))


@functools.lru_cache(maxsize=512)
def _wildcard(part: str) -> _Wildcard:
    return _Wildcard(part)


class _Scan:
    """What the wildcards of one command make the guard read: each folder once, and GLOB_SCAN entries looked at in all, however many
    patterns look at them: a command is not given the time to look at a big folder with thousands of patterns."""

    def __init__(self) -> None:
        self.left = GLOB_SCAN
        self.folders: dict[str, list[tuple[str, bool, bool]]] = {}

    def entries(self, folder: str) -> list[tuple[str, bool, bool]] | None:
        """(name, is a link, is a folder that is not a link) for each entry, or None when the command has made the guard look at too much."""
        if folder not in self.folders:
            try:
                with os.scandir(folder) as found:
                    self.folders[folder] = [(e.name, e.is_symlink(), e.is_dir(follow_symlinks=False)) for e in found]
            except OSError:
                self.folders[folder] = []
        self.left -= len(self.folders[folder]) + 1
        return self.folders[folder] if self.left >= 0 else None


class _Guard:
    def __init__(self, ws: Workspace, home: Path) -> None:
        config = load_workspace_config(ws.id, home)
        h = home.resolve()
        self.mirror = ws.mirror.resolve()
        self.roots = [ws.original.resolve(), *(h / part for part in SENSITIVE_HOME_PARTS)]
        self.roots += [_resolve(p, config.source.parent if config.source else ws.original) for p in config.protected_paths]
        self.workspaces = h / "workspaces"
        # A mac file system ignores case and the form of an accent: ~/PROJECT/.env opens ~/project/.env. Paths are compared folded.
        self.folded_mirror, self.folded_workspaces = _folded(self.mirror), _folded(self.workspaces)
        self.folded_roots = [_folded(r) for r in self.roots]
        self.controls = {_fold(str(self.mirror / name)) for name in RESERVED}  # the marker and the settings that carry the guard

    def runs_by_itself(self, *paths: Path) -> bool:
        """A file that git, python or the guard reads and runs without being asked: anything in a .git folder (config, hooks), *.pth,
        sitecustomize.py, usercustomize.py, and the files boxed keeps in the mirror."""
        for path in paths:
            parts = _folded(path).parts
            if ".git" in parts or parts[-1].endswith(".pth") or parts[-1] in ("sitecustomize.py", "usercustomize.py"):
                return True
            if _fold(str(path)) in self.controls:
                return True
        return False

    def blocked(self, path: Path, holders: bool = True) -> bool:
        """Whether the path is protected data or, with `holders`, a folder that holds some (the folder above the project, ~, /)."""
        path = _folded(path)
        if path == self.folded_mirror or path.is_relative_to(self.folded_mirror):
            return False
        if path.is_relative_to(self.folded_workspaces) and (holders or path != self.folded_workspaces):  # another workspace's mirror
            return True
        if holders and any(r.is_relative_to(path) for r in [*self.folded_roots, self.folded_workspaces]):  # a folder that holds protected data
            return True
        return any(path == r or path.is_relative_to(r) for r in self.folded_roots)

    @staticmethod
    def ways(value: str, cwd: Path) -> list[Path]:
        """Where a path leads. The system follows its links first and then goes up; a cd (and Python's os.path) folds the .. first: past
        a link the two end in different places, and the guard cannot know which one the command meets."""
        ways = [_resolve(value, cwd)]
        if ".." in value.split("/"):
            ways.append(_lexical(value, cwd))
        return ways

    def pattern_blocked(self, pattern: str, cwd: Path, holders: bool = True) -> bool:
        """What lies before the first wildcard character, and the word as written too: a { that closes nothing, or a quoted *, is a
        name, and ./a{/../../vault.db goes through a folder called a{ to the vault."""
        variants = _expand_braces(pattern)
        if variants is None:
            return True
        for v in variants:
            static = _static_dir(v)
            literal = static != v and len(v) <= PATH_LIMIT  # a path no system call takes names nothing
            if any(self.blocked(way, holders) for way in [*self.ways(static, cwd), *(self.ways(v, cwd) if literal else ())]):
                return True
        return False

    def inside(self, path: Path) -> bool:
        path = _folded(path)
        return path == self.folded_mirror or path.is_relative_to(self.folded_mirror)

    def climbs_out(self, path: str, cwd: Path) -> bool:
        """A relative path with .. in it that ends outside the mirror. It is read from where the command starts, but a cd moves that
        start, and a link target is read from the folder of the link: only a path that stays in the mirror is safe from every start,
        and nothing in the mirror has a reason to climb out of it."""
        if path.startswith(("/", "~")) or ".." not in path.split("/"):
            return False
        return not all(self.inside(way) for way in self.ways(path, cwd))

    def concrete_blocked(self, path: str, cwd: Path, holders: bool) -> bool:
        """A path without wildcards, read every way it can be read."""
        return (holders and self.climbs_out(path, cwd)) or any(self.blocked(way, holders) for way in self.ways(path, cwd))

    def links_below(self, folder: str, cwd: Path, holders: bool, scan: _Scan) -> bool:
        """zsh's **/ goes through every folder below (not the hidden ones, not through links): whether a link in there leads to protected data."""
        todo = [os.path.join(cwd, folder)]
        while todo:
            here = todo.pop()
            entries = scan.entries(here)
            if entries is None:
                return True
            for name, link, plain in entries:
                if link and self.concrete_blocked(os.path.join(here, name), cwd, holders):
                    return True
                if plain and not name.startswith("."):
                    todo.append(os.path.join(here, name))
        return False

    def glob_blocked(self, pattern: str, cwd: Path, holders: bool, scan: _Scan) -> bool:
        """Whether a pattern with wildcards stands for protected data. The shell turns it into names before the program runs, so the names
        are read from the files as they are now: the pattern itself, as a name (a link may be called [PERSON_1]), and every path it
        stands for. Only a link, or a folder to go on in, can lead anywhere new: a plain name at the end is under a folder that was checked."""
        if sum(1 for part in pattern.split("/") if WILDCARD_PART.search(part)) > GLOB_DEPTH:
            return True
        if len(pattern) > PATH_LIMIT:  # no path is that long: there is nothing it could stand for
            return False
        if self.concrete_blocked(pattern, cwd, holders):
            return True
        pattern = os.path.expanduser(pattern)
        parts = [part for part in pattern.split("/") if part]
        frontier = ["/" if pattern.startswith("/") else ""]
        for k, part in enumerate(parts):
            last = k == len(parts) - 1
            if not WILDCARD_PART.search(part):
                frontier = [os.path.join(prefix, part) for prefix in frontier]
                continue
            if part in ("**", "***") and not last:  # zero folders or any number: what is below was looked at, the rest goes on from here
                if ".." in parts[k + 1 :] or any(self.links_below(prefix, cwd, holders, scan) for prefix in frontier):
                    return True
                continue
            matcher, grown = _wildcard(part), []
            dots = ((".", False, True), ("..", False, True)) if part.startswith(".") else ()  # bash before 5.2 lets .* match . and ..
            for prefix in frontier:
                entries = scan.entries(os.path.join(cwd, prefix))
                if entries is None:
                    return True
                if last and prefix and self.concrete_blocked(prefix, cwd, holders):
                    return True
                for name, link, plain in [*dots, *entries]:
                    if not matcher.fullmatch(name):
                        continue
                    path = os.path.join(prefix, name)
                    if last:
                        if (link or name in (".", "..")) and self.concrete_blocked(path, cwd, holders):
                            return True
                    elif part.startswith(".") or not name.startswith("."):
                        if plain or (link and os.path.isdir(os.path.join(cwd, path))):
                            grown.append(path)
            if len(grown) > GLOB_LIMIT:
                return True
            frontier = grown
        if parts and WILDCARD_PART.search(parts[-1]):
            return False  # the last part was read above
        return any(self.concrete_blocked(prefix, cwd, holders) for prefix in frontier if prefix)

    def after_cd(self, command: str, cwd: Path) -> tuple[str, list[Path], bool] | None:
        """For `cd <plain path> && <line>` that can end inside the mirror: the line, the folders inside it the cd can end in and whether
        it can end nowhere else. Only then is the line two simple commands to judge alone; any other cd is judged as before, its line
        read from those folders as well."""
        moved = _after_cd(command)
        if moved is None:
            return None
        ways = set(self.ways(moved[0], cwd)) | {_lexical(moved[0], cwd)}
        folders = [way for way in ways if self.inside(way)]
        return (moved[1], folders, _cd_is_exact(moved[0]) and len(folders) == len(ways)) if folders else None

    def bash_blocked(self, command: str, cwd: Path) -> bool:
        command = _join_lines(command)
        if _expr_line(command):
            return False
        holders = not _prints_only(command)  # a line that only prints may name a folder that holds protected data
        command, tokens = _shell_words(_arithmetic_words(ZSH_RANGE.sub("*", command)))
        folded = _fold(command)
        if any(str(r) in folded for r in self.folded_roots):
            return True
        scan = _Scan()
        # A word with blanks is a string for another shell (sh -c 'ls li*'): its wildcards are read like the others, the rest of its text
        # is quoted code and goes to RAW_PATH below (print(4 / 2) is no path).
        for token, whole in [(t, True) for t in tokens] + [(t, False) for t in _nested_words(tokens)[len(tokens) :]]:
            # a = or : cuts a word into paths (PATH=a:b), and a bracket or a brace may hold one ([p:]eek, {link,[x=x]}): the word is read uncut too. A class
            # ([[:alpha:]]) is a pattern for sure and is not cut.
            parts = [(part, whole) for part in ([token] if "[:" in token else re.split(r"[=:]", token))]
            for part, full in [*parts, (token, whole)] if len(parts) > 1 and _has_wildcard(token) else parts:
                variants = _expand_braces(part)
                if variants is None:
                    return True
                for v in variants:
                    if full:
                        if TILDE_STACK.match(v):  # the folder the shell is in or left: after a cd the guard does not know which
                            return True
                        if "/" in v or v.startswith(("~", "..")):
                            static = _static_dir(v)
                            if (holders and (self.climbs_out(static, cwd) or (static != v and len(v) <= PATH_LIMIT and self.climbs_out(v, cwd)))) or self.pattern_blocked(v, cwd, holders):
                                return True
                        elif os.path.islink(cwd / v) and self.blocked(_resolve(v, cwd), holders):  # a link in the mirror, named without a slash
                            return True
                    if _has_wildcard(v) and self.glob_blocked(v, cwd, holders, scan):
                        return True
        return any(self.blocked(_resolve(m.group(0), cwd), holders) for m in RAW_PATH.finditer(command))


def hook_pre_tool_use(payload: dict, home: Path) -> HookResult:
    cwd = _payload_cwd(payload)
    ws = find_workspace(cwd, home)
    tool = payload.get("tool_name")
    if ws is None or (tool not in PATH_FIELDS and tool not in SHELL_TOOLS):
        return HookResult(0)
    guard = _Guard(ws, home)
    tool_input = payload.get("tool_input") or {}
    if tool in SHELL_TOOLS:
        command = str(tool_input.get("command") or "")
        moved = guard.after_cd(command, cwd)  # the line after a cd, and the folders inside the mirror it can run in
        if _runs_boxed(*_shell_words(moved[0] if moved and moved[2] else command)):  # only an exact cd leaves two simple commands
            return HookResult(2, "", BOXED_DENIED.format(tool=tool))
        hit = guard.bash_blocked(command, cwd) or (moved is not None and any(guard.bash_blocked(moved[0], folder) for folder in moved[1]))
    else:
        hit = False
        for field in PATH_FIELDS[tool]:
            value = tool_input.get(field)
            if isinstance(value, str) and value:
                hit = hit or (guard.pattern_blocked(value, cwd) if field == "pattern" else guard.blocked(_resolve(value, cwd)))
        if not hit and tool in WRITE_TOOLS:
            path = tool_input.get(PATH_FIELDS[tool][0])
            if isinstance(path, str) and path and guard.runs_by_itself(_resolve(path, cwd), _lexical(path, cwd)):
                return HookResult(2, "", FILE_DENIED.format(tool=tool))
            current = None
            if tool in ("Edit", "MultiEdit") and isinstance(path, str) and path:
                try:
                    current = _file_text(_resolve(path, cwd))
                except _TooBig:
                    return HookResult(2, "", FILE_TOO_BIG.format(tool=tool))
            if any(_writes_boxed(text, _content_kind(path, text)) for text in _written_texts(tool, tool_input, current)):
                return HookResult(2, "", CONTENT_DENIED.format(tool=tool))
    return HookResult(2, "", DENIED.format(tool=tool)) if hit else HookResult(0)


def hook_user_prompt_submit(payload: dict, home: Path) -> HookResult:
    ws = find_workspace(_payload_cwd(payload), home)
    if ws is None:
        return HookResult(0)
    prompt = str(payload.get("prompt") or "")
    found = detect(prompt, level=ws.level, config=to_detect_config(load_workspace_config(ws.id, home)))
    if not found:
        return HookResult(0)
    counts = Counter(d.kind for d in found)
    Journal(home / "journal.jsonl", default_keystore()).append(
        JournalEntry(
            channel="claude-code",
            provider="anthropic",
            account_type="unknown",
            level=ws.level,
            markers_by_kind=dict(counts),
            status="blocked",
            payload_sha256=hashlib.sha256(prompt.encode()).hexdigest(),
            coverage="prompt",
            scope=ws.scope,
            versions={"boxed": __version__},
            note="UserPromptSubmit",
        )
    )
    found_text = ", ".join(f"{kind} {n}" for kind, n in counts.most_common())
    return HookResult(
        2,
        "",
        f"boxed: prompt blocked, it contains {found_text}. Mask it first, for example: "
        f"pbpaste | boxed mask --scope {ws.scope} | pbcopy, then paste again.",
    )


def hook_session_start(payload: dict, home: Path) -> HookResult:
    if find_workspace(_payload_cwd(payload), home) is None:
        return HookResult(0)
    out = {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": SESSION_NOTE}}
    return HookResult(0, json.dumps(out))


def hook_skills_check(payload: dict, home: Path) -> HookResult:
    """The SessionStart hook of the boxed plugin (skills/session.py), loaded only when it runs: the guard hooks stay as quick as they
    were. Its own event name, not session-start, which every mirror already runs from its settings: the plugin's would run twice."""
    from .skills.session import hook_skills_check as check

    return check(payload, home)


HOOKS = {
    "pre-tool-use": hook_pre_tool_use,
    "user-prompt-submit": hook_user_prompt_submit,
    "session-start": hook_session_start,
    "skills-check": hook_skills_check,
}
