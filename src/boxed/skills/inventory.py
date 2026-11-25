"""What is installed: every place where the agents on this computer load extensions, and what each place holds.

The inventory is plain reading. It never runs, imports, sources or evaluates anything it finds, and it never follows a link inside what
it scans (a link is recorded with its target text). The only links it follows are the ones the person made at the top of an agent's own
folders (a skill folder that points at another skills root), and those are counted once.

Shapes of `Item.entry`, which the rules read: an MCP server is its own mapping; a hook is its handler mapping plus `event` and, when
there is one, `matcher`; a setting is the settings file cut down to that key (`{"env": {"ANTHROPIC_BASE_URL": ...}}`, `{"notify": [...]}`).
An entry may hold secrets and is never printed; the digest hashes it as canonical JSON.

What a plugin declares: an MCP server or a hook that comes from a plugin's own config files (`.mcp.json`, `hooks/hooks.json`, the
manifest) has a name that starts with `PLUGIN_PREFIX` ("plugin:"), as in `plugin:<plugin>:<server>` and `plugin:<plugin id>:<Event>:<sha8>`.
Nothing else gets that prefix from this module, so `item.kind in ("mcp", "hook") and item.name.startswith(PLUGIN_PREFIX)` is the one test
for "comes from a plugin", and the scanner passes scope "plugin" to `rules.check_entry` for it. A person can name their own server or
event that way too; that only makes the rules stricter. Hooks from a skill, an agent or a command file are named `skill:<n>:`,
`agent:<n>:`, `command:<n>:` before `<Event>:<sha8>`; their scope is the scope of the file."""

import errno
import hashlib
import json
import os
import re
import shlex
import stat
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from boxed import platform
from boxed.skills._shared import escaped

KINDS = ("skill", "plugin", "mcp", "hook", "agent", "command", "output-style", "prompt", "setting")
AGENTS = ("claude", "claude-desktop", "codex", "agents", "cursor", "gemini", "openclaw")  # "agents" = the cross-agent ~/.agents

PLUGIN_PREFIX = "plugin:"  # the marker of what a plugin declares, see the docstring
MAX_FILES = 10_000  # per item: a cap is reported as a problem and leaves the item unchecked, never a silent cut
MAX_SEEN = 50_000  # entries looked at while a target folder is searched for what it holds
MAX_LISTED = 200_000  # entries past the cap of an item whose size and times stand in for them in its digest
MAX_SCRIPTS = 20  # local script files kept for one command; past it the item is unchecked
MAX_NESTING = 30


@dataclass(frozen=True)
class Roots:
    home: Path  # every agent path is derived from it at call time
    projects: tuple[Path, ...] = ()  # extra project folders (the CLI passes the current folder)
    registered_projects: bool = True  # also read projects from ~/.claude.json and ~/.codex/config.toml


@dataclass(frozen=True)
class Item:
    id: str  # "<agent>:<kind>:<scope>:<name>", stable across runs and unique
    agent: str
    kind: str
    scope: str  # "user" | "project" | "local" | "target"
    name: str
    root: Path  # the folder or file that holds it; for config entries the config file
    files: tuple[Path, ...]  # regular files that belong to it (absolute, sorted); for hooks and MCP also the local scripts their command names
    links: tuple[tuple[str, str], ...]  # links met inside it: (path relative to root, link target text); never followed
    entry: Mapping | None  # config entries only: the parsed entry (may hold secrets; never printed)
    config_path: Path | None
    config_key: tuple[str, ...]  # where the entry sits inside config_path
    location: str  # human locator, home shown as "~"
    project: Path | None  # project root for project and local scope; for a user plugin, the current project whose settings switch it on
    origin: str  # "skills-lock:<source>" | "marketplace:<name>" | "claude.ai" | "unknown"
    enabled: bool | None  # plugins and MCP servers with an on/off switch, and what a plugin declares (on and off with it); None otherwise
    # what of it was not read: (place relative to root, "." for the item itself; "too many files" | "too many scripts" | "unreadable";
    # a hash of the path, size and times of what was left out, which stands in for its content in the digest)
    unchecked: tuple[tuple[str, str, str], ...] = ()


@dataclass(frozen=True)
class Problem:
    location: str  # human locator
    reason: str  # fixed words: "not valid JSON", "not valid TOML", "not valid frontmatter", "unreadable", "link to a missing target", "too many files"


@dataclass(frozen=True)
class Inventory:
    items: tuple[Item, ...]  # sorted by id
    problems: tuple[Problem, ...]


# ---- small helpers ----

# Settings that point traffic somewhere else or change how a program starts, found by name inside an `env` block.
WATCHED_ENV = re.compile(
    r"(?i)(_BASE_URL$|_API_BASE$|_API_URL$|_ENDPOINT$|_PROXY$|^PROXY$|_CA_BUNDLE$|_EXTRA_CA_CERTS$|^SSL_CERT_FILE$|TLS_REJECT_UNAUTHORIZED"
    r"|_REGISTRY$|_INDEX_URL$|^UV_(DEFAULT_|EXTRA_)?INDEX(_URL)?$|^NODE_OPTIONS$|^LD_PRELOAD$|^DYLD_INSERT_LIBRARIES$|^BASH_ENV$|^PYTHONSTARTUP$)"
)
CLAUDE_TOP_SETTINGS = (
    "statusLine", "apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper",
    "skipDangerousModePermissionPrompt", "enableAllProjectMcpServers",
)
CODEX_TOP_SETTINGS = ("notify", "approval_policy", "sandbox_mode")
WIDE_ALLOW = ("*", "Bash", "Bash(*)", "Bash(*:*)", "Bash(:*)")


def _holds_secret(rule: str) -> bool:
    """A permission rule keeps the whole command that was allowed once, a key in a header or an option with it."""
    from boxed.detect import detect

    return bool(detect(rule[:4096], level=0, ner=[]))
INTERPRETER = re.compile(
    r"^(env|sh|bash|zsh|dash|fish|python[\d.]*|node|deno|bun|ruby|perl|php|npx|uv|uvx|pipx|pnpm|npm|yarn|java|pwsh|powershell|cmd)(\.exe)?$", re.I
)
SCRIPT_SUFFIXES = {".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".php", ".ps1", ".lua", ".bat", ".cmd"}


def _sha(text: str, n: int) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:n]


def _safe_source(text: str) -> str:
    """An address as an origin may carry it: no user or token before the host, no query, no fragment."""
    text = re.sub(r"(?<=://)[^/\s]*@", "", text)
    return escaped(re.split(r"[?#]", text, maxsplit=1)[0])[:200]


def _hooks_shape_ok(hooks) -> bool:
    """True when a `hooks` value is what the agents read: events, each a list of groups, each group a mapping that holds a list of
    handler mappings or is a handler itself."""
    if hooks is None:
        return True
    if not isinstance(hooks, dict):
        return False
    for groups in hooks.values():
        if groups is None:
            continue
        if not isinstance(groups, list):
            return False
        for group in groups:
            if not isinstance(group, dict):
                return False
            handlers = group.get("hooks")
            if handlers is not None and not (isinstance(handlers, list) and all(isinstance(h, dict) for h in handlers)):
                return False
    return True


def _tag(project: Path) -> str:
    """`<folder name>@<first 6 hex of the sha256 of the absolute path>`: two projects of one folder name stay apart."""
    path = os.path.abspath(project)
    return f"{escaped(os.path.basename(path) or 'root').replace(':', '_')}@{_sha(path, 6)}"


def _scope_part(scope: str, project: Path | None) -> str:
    if scope in ("project", "local") and project is not None:
        return f"{scope}={_tag(project)}"
    return scope


def _inside(path: str, base: str) -> bool:
    return path == base or path.startswith(base.rstrip(os.sep) + os.sep)


def _is_link(path) -> bool:
    return os.path.islink(path)


def _hop(raw: str, roots: list[str]) -> str | None:
    """The first link on the way down to a path from the deepest of `roots` (folders that are scanned) that holds it, the last part
    left out (a link there is recorded as the file itself): what lies behind such a link is outside what is scanned and is never read.
    The way is taken as written, so `linked/..` still passes the link. None when no root holds the path or no link is met."""
    path = os.path.normpath(raw)
    holding = [r for r in roots if path != r and _inside(path, r)]
    if not holding:
        return None
    top = max(holding, key=len)
    parts = Path(raw).parts
    for n in range(1, len(parts)):
        step = os.path.normpath(os.path.join(*parts[:n]))
        if step != top and _inside(step, top) and (os.path.islink(step) or os.path.isjunction(step)):
            return step
    return None


def _behind(path: str, roots: list[str]) -> tuple[str, str, str] | Path | None:
    """What a command reaches through a link (on the way, or the name itself). When every link on the way stays inside what is
    scanned, the script behind them: its real path, read like a script named directly. When a link leads out, or the name cannot be
    resolved, what the item misses: that script is never read, so the item is unchecked there (a link that leads out is also a finding
    of its own where the item can judge it), and the size and times of the script stand in for it, so an edit still changes the
    digest. None when no root holds the path or when what is behind it is no script."""
    holding = [r for r in roots if path != r and _inside(path, r)]
    if not holding:
        return None
    top = max(holding, key=len)
    try:
        real = os.path.realpath(path)
    except ValueError:  # a name no file can have: what it runs is not known
        return path, "unreadable", hashlib.sha256(path.encode("utf-8", "surrogatepass")).hexdigest()
    try:
        mode = os.lstat(real).st_mode
    except OSError:
        return None
    script = Path(path).suffix in SCRIPT_SUFFIXES or Path(real).suffix in SCRIPT_SUFFIXES
    if not stat.S_ISREG(mode) or not (script or (mode & 0o111 and not platform.IS_WINDOWS)):
        return None
    if _inside(real, os.path.realpath(top)):
        return Path(real)
    return path, "behind a link", hashlib.sha256(_stand_in(path, real)).hexdigest()


def _settle(items: list[Item]) -> list[Item]:
    """A script behind a link that another item reads whole (a plugin, a skill, the rest of a target, a command that names it
    directly) is checked there: it is no longer unchecked in the item whose command passes the link."""
    if not any(u[1] == "behind a link" for i in items for u in i.unchecked):
        return items
    read = {os.path.realpath(f) for i in items for f in i.files}
    out = []
    for item in items:
        kept = tuple(u for u in item.unchecked if u[1] != "behind a link" or os.path.realpath(u[0]) not in read)
        out.append(item if kept == item.unchecked else replace(item, unchecked=kept))
    return out


def _stand_in(rel: str, path) -> bytes:
    """What stands in for an entry that is not read, in a digest: its place, kind, size and times (never its content). A change made
    through a write, a rename or a new link changes the change time, which no program can set back."""
    try:
        st = os.lstat(path)
    except OSError:
        return b"?" + _frame(rel.encode("utf-8", "surrogatepass"))
    times = f"{stat.S_IFMT(st.st_mode)}:{st.st_size}:{st.st_mtime_ns}:{st.st_ctime_ns}"
    return b"S" + _frame(rel.encode("utf-8", "surrogatepass")) + _frame(times.encode())


def _nested(path: tuple[str, ...], value) -> dict:
    """The value at a key path, cut out as the settings file would hold it."""
    for key in reversed(path):
        value = {key: value}
    return value


# Names that look like secrets: such a file is never a file of an item, whatever its suffix or mode.
SECRET_NAME = re.compile(
    r"(?i)^(\.env(\..*)?|\.npmrc|\.pypirc|\.netrc|\.git-credentials|.*\.(pem|key|p12|kdbx)|id_rsa.*|id_ecdsa.*|id_ed25519.*|credentials.*"
    r"|auth\.json)$"
)


_WRAPPERS = frozenset({"exec", "command", "builtin", "nohup", "sudo", "doas", "env", "time", "timeout", "nice", "xargs", "if", "then",
                       "elif", "else", "while", "until", "do", "!"})
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")


def _words(command, depth: int = 0) -> list[tuple[str, bool]]:
    """Every word of a command line, and of the strings nested in it (`sh -c "..."`), with whether it names what runs: the first word,
    one after ; && || | & or (, one after a wrapper (exec, sudo, env, timeout and the like, past their options and numbers) or an
    assignment, and the first word after an interpreter that is not an option (the script it runs). Nothing is run or expanded. What
    is a file of the item is decided on the file itself; only a folder behind a link on the way asks where the word stands."""
    if isinstance(command, list):
        tokens = [w for w in command if isinstance(w, str)]
    elif isinstance(command, str):
        try:
            lexer = shlex.shlex(command, posix=not platform.IS_WINDOWS, punctuation_chars=True)
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError:
            tokens = command.split()
    else:
        return []
    out: list[tuple[str, bool]] = []
    lead, script = True, False  # the next word names what runs; the next word that is no option is the script of an interpreter
    for token in tokens[:200]:
        word = token.strip("\"'")
        if not word:
            continue
        if all(c in "();<>|&" for c in word):
            lead, script = not any(c in "<>" for c in word), False  # a redirect names a file; the others start a command
            continue
        if depth < 2 and len(word) < 4000 and (" " in word or "\n" in word):
            out.extend(_words(word, depth + 1))
            lead = script = False
            continue
        out.append((word, lead or (script and not word.startswith("-"))))
        name = os.path.basename(word)
        if lead and (name in _WRAPPERS or _ASSIGNMENT.match(word) or word.startswith("-") or word.isdigit()):
            continue  # what runs comes after it
        script = (lead and INTERPRETER.match(name) is not None) or (script and word.startswith("-"))
        lead = False
    return out


# ---- the front matter of a skill, an agent or a command: just enough YAML to read its hooks ----


def _split_frontmatter(text: str) -> tuple[str | None, bool]:
    """(the block between the first two `---` lines, whether the file is well formed). No front matter at all is well formed."""
    lines = text.lstrip("﻿").split("\n")
    if lines[0].rstrip() != "---":
        return None, True
    for i in range(1, len(lines)):
        if lines[i].rstrip() in ("---", "..."):
            return "\n".join(lines[1:i]), True
    return None, False


def _strip_comment(text: str) -> str:
    quote = ""
    for i, c in enumerate(text):
        if quote:
            if c == quote:
                quote = ""
        elif c in "\"'" and (i == 0 or text[i - 1] in " \t[{,:-"):
            quote = c
        elif c == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i]
    return text


def _split_key(text: str) -> tuple[str, str] | None:
    """`key: rest` of a mapping line, else None."""
    if text[:1] in "\"'":
        end = text.find(text[0], 1)
        while end != -1 and text[end - 1] == "\\" and text[0] == '"':
            end = text.find(text[0], end + 1)
        if end == -1:
            return None
        key, tail = text[1:end], text[end + 1:].lstrip()
        if tail[:1] != ":" or (len(tail) > 1 and tail[1] not in " \t"):
            return None
        return key, tail[1:].strip()
    if text[:1] in "[{":
        return None
    match = re.search(r":(?=\s|$)", text)
    if match is None or match.start() == 0:
        return None
    return text[: match.start()].strip(), text[match.end():].strip()


def _scalar(text: str):
    t = text.strip()
    if t[:1] == '"':
        try:
            return json.loads(t)
        except ValueError:
            return t.strip('"')
    if t[:1] == "'" and len(t) >= 2 and t.endswith("'"):
        return t[1:-1].replace("''", "'")
    if t[:1] in "[{":
        try:
            return json.loads(t)
        except ValueError:
            if t[0] == "[" and t[-1] == "]":
                return [_scalar(part) for part in t[1:-1].split(",") if part.strip()]
            return t
    if t in ("true", "True"):
        return True
    if t in ("false", "False"):
        return False
    if t in ("null", "~", ""):
        return None
    if re.fullmatch(r"-?\d+", t):
        return int(t)
    return t


class _Yaml:
    """A reader for the block YAML a front matter uses: mappings, sequences, plain and quoted scalars, `|` and `>` blocks."""

    BLOCK = re.compile(r"(?:^|:\s+|^-\s+)[|>][+-]?\d?$")

    def __init__(self, block: str) -> None:
        raw = block.split("\n")
        self.rows: list[tuple[int, str, str | None]] = []
        i = 0
        while i < len(raw):
            line = raw[i].rstrip("\r")
            i += 1
            body = _strip_comment(line).rstrip()
            if not body.strip() or body.strip() in ("---", "..."):
                continue
            lead = body[: len(body) - len(body.lstrip())]
            if "\t" in lead:
                raise ValueError("tab")
            indent, text = len(lead), body.strip()
            scalar = None
            if self.BLOCK.search(text):
                chunk: list[str] = []
                while i < len(raw) and (not raw[i].strip() or len(raw[i]) - len(raw[i].lstrip()) > indent):
                    chunk.append(raw[i].rstrip("\r"))
                    i += 1
                pad = min((len(c) - len(c.lstrip()) for c in chunk if c.strip()), default=0)
                lines = [c[pad:] for c in chunk]
                scalar = (" " if text.rstrip("+-0123456789").endswith(">") else "\n").join(lines).strip("\n")
            self.rows.append((indent, text, scalar))

    def parse(self):
        if not self.rows:
            return None
        value, end = self._node(0, self.rows[0][0], 0)
        if end != len(self.rows):
            raise ValueError("left over")
        return value

    def _node(self, i: int, indent: int, depth: int):
        if depth > MAX_NESTING or self.rows[i][0] != indent:
            raise ValueError("indent")
        text = self.rows[i][1]
        return self._seq(i, indent, depth) if text == "-" or text.startswith("- ") else self._map(i, indent, depth)

    def _seq(self, i: int, indent: int, depth: int):
        out = []
        while i < len(self.rows) and self.rows[i][0] == indent and (self.rows[i][1] == "-" or self.rows[i][1].startswith("- ")):
            _, text, block = self.rows[i]
            rest = text[1:].lstrip(" ")
            offset = len(text) - len(rest)
            if not rest:
                if i + 1 < len(self.rows) and self.rows[i + 1][0] > indent:
                    value, i = self._node(i + 1, self.rows[i + 1][0], depth + 1)
                else:
                    value, i = None, i + 1
            elif block is not None and self.BLOCK.fullmatch(rest):
                value, i = block, i + 1
            elif _split_key(rest) is not None:
                self.rows[i] = (indent + offset, rest, block)  # the mapping starts on the dash line
                value, i = self._map(i, indent + offset, depth + 1)
            else:
                value, i = _scalar(rest), i + 1
            out.append(value)
        return out, i

    def _map(self, i: int, indent: int, depth: int):
        out: dict = {}
        while i < len(self.rows) and self.rows[i][0] == indent and not (self.rows[i][1] == "-" or self.rows[i][1].startswith("- ")):
            _, text, block = self.rows[i]
            pair = _split_key(text)
            if pair is None:
                raise ValueError("not a mapping line")
            key, rest = pair
            if block is not None and self.BLOCK.fullmatch(rest):
                value, i = block, i + 1
            elif rest == "":
                nxt = self.rows[i + 1] if i + 1 < len(self.rows) else None
                if nxt is not None and nxt[0] > indent:
                    value, i = self._node(i + 1, nxt[0], depth + 1)
                elif nxt is not None and nxt[0] == indent and nxt[1].startswith("- "):
                    value, i = self._seq(i + 1, indent, depth + 1)
                else:
                    value, i = None, i + 1
            else:
                value, i = _scalar(rest), i + 1
            out[key] = value
        return out, i


# ---- the walk ----


class _Disc:
    """One discovery run: collects items and problems."""

    def __init__(self, home: Path | None, target: tuple[Path, str] | None = None) -> None:
        self.home = home
        self.target = target
        self.items: list[Item] = []
        self.problems: list[Problem] = []
        self._said: set[Problem] = set()  # what self.problems holds, for a look-up that stays cheap with thousands of them
        self._skills: list[tuple] = []
        self.account_layout: set[Path] = set()  # roots of the skills in synced/<account>/ and of their frontmatter hooks, see _unique
        self._lock: dict | None = None
        self._lock_read = False

    # -- locators and problems

    def loc(self, path) -> str:
        text = os.path.abspath(os.fspath(path))
        if self.target is not None:
            root = os.path.abspath(self.target[0])
            if text == root:
                return escaped(self.target[1])
            if _inside(text, root):
                return escaped(f"{self.target[1]}/{text[len(root) + 1:]}".replace(os.sep, "/"))
        elif self.home is not None:
            home = os.path.abspath(self.home)
            if text == home:
                return "~"
            if _inside(text, home):
                return escaped("~/" + text[len(home) + 1:].replace(os.sep, "/"))
        return escaped(text.replace(os.sep, "/"))

    def problem(self, where, reason: str) -> None:
        found = Problem(self.loc(where), reason)
        if found not in self._said:
            self._said.add(found)
            self.problems.append(found)

    # -- reading

    def read(self, path, *, follow: bool) -> bytes | None:
        """The whole file, or None: when it is not there nothing is said, when it cannot be read that is a problem."""
        shown = os.fspath(path)
        target = os.path.realpath(shown) if follow else shown
        try:
            fd = platform.open_nofollow(target, os.O_RDONLY)
        except (FileNotFoundError, NotADirectoryError):
            return None
        except OSError as e:
            if e.errno != errno.ELOOP:  # a link is listed among the links of its item, not read through
                self.problem(path, "unreadable")
            return None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                self.problem(path, "unreadable")
                return None
            with os.fdopen(fd, "rb", closefd=False) as handle:
                return handle.read()
        except OSError:
            self.problem(path, "unreadable")
            return None
        finally:
            os.close(fd)

    def json_file(self, path, *, follow: bool = True) -> dict | None:
        raw = self.read(path, follow=follow)
        if raw is None:
            return None
        try:
            data = json.loads(raw.decode("utf-8-sig"))
        except (ValueError, RecursionError):
            self.problem(path, "not valid JSON")
            return None
        if not isinstance(data, dict):
            self.problem(path, "not valid JSON")
            return None
        return data

    def toml_file(self, path, *, follow: bool = True) -> dict | None:
        raw = self.read(path, follow=follow)
        if raw is None:
            return None
        try:
            return tomllib.loads(raw.decode("utf-8"))
        except (ValueError, RecursionError):  # TOMLDecodeError and UnicodeDecodeError are both ValueErrors
            self.problem(path, "not valid TOML")
            return None

    def listdir(self, folder) -> list[str] | None:
        try:
            return sorted(os.listdir(folder))
        except (FileNotFoundError, NotADirectoryError):
            return None
        except OSError:
            self.problem(folder, "unreadable")
            return None

    def walk(self, root, skip: frozenset[str] = frozenset(), prune: frozenset[str] = frozenset()
             ) -> tuple[list[Path], list[tuple[str, str]], tuple[tuple[str, str, str], ...]]:
        """Regular files and links under a folder, links never followed, and what of it was not read (see `Item.unchecked`). A folder
        that cannot be read, a link to nowhere and too many files are problems, and the rest is still walked. A link counts toward
        MAX_FILES like a file, and the listing never follows one, not even to ask whether it leads to a folder (os.walk would): a
        hundred thousand links to nowhere cost a listing, not minutes. Past the cap nothing more is read or followed, but every further
        entry is listed and its place, size and times are hashed (`_stand_in`), so the digest of a cut item still changes when
        anything in it does; past MAX_LISTED more the hash takes a value that never repeats. Folders are walked depth first in name
        order, as os.walk walks them; a folder in `skip` (absolute paths) or named in `prune` is left out."""
        base = os.fspath(root)
        files: list[Path] = []
        links: list[tuple[str, str]] = []
        unchecked: list[tuple[str, str, str]] = []
        rest = None  # past the cap: the hash of what stands in for the entries that are not read
        listed = 0
        folders = [base]

        def place(path: str) -> str:
            return "." if path == base else path[len(base) + 1:].replace(os.sep, "/")

        def left_out(entry) -> bool:
            if entry.path in skip:
                return True
            try:
                return entry.name in prune and entry.is_dir(follow_symlinks=False)  # a link of that name is still a link
            except OSError:
                return False

        while folders:
            where = folders.pop()
            try:
                with os.scandir(where) as listing:
                    entries = sorted(listing, key=lambda e: e.name)
            except OSError:
                self.problem(where, "unreadable")
                if rest is None:
                    unchecked.append((place(where), "unreadable", hashlib.sha256(_stand_in(place(where), where)).hexdigest()))
                else:
                    rest.update(b"?" + _frame(place(where).encode("utf-8", "surrogatepass")))
                continue
            inner = []
            for entry in entries:
                if left_out(entry):
                    continue
                if rest is not None:
                    listed += 1
                    if listed > MAX_LISTED:
                        rest.update(os.urandom(16))
                        folders.clear()
                        inner.clear()
                        break
                    rest.update(_stand_in(place(entry.path), entry.path))
                    try:
                        if entry.is_dir(follow_symlinks=False) and not entry.is_junction():
                            inner.append(entry.path)
                    except OSError:
                        pass  # it is hashed as it is
                    continue
                try:
                    link = entry.is_symlink() or entry.is_junction()  # a Windows junction is a link to a folder too
                    if not link and entry.is_dir(follow_symlinks=False):
                        inner.append(entry.path)
                        continue
                    if not link and not entry.is_file(follow_symlinks=False):
                        continue  # a pipe or a socket: nothing to read
                except OSError:
                    self.problem(entry.path, "unreadable")
                    unchecked.append((place(entry.path), "unreadable", ""))
                    continue
                if len(files) + len(links) >= MAX_FILES:
                    self.problem(base, "too many files")
                    rest = hashlib.sha256()
                    listed = 1
                    rest.update(_stand_in(place(entry.path), entry.path))
                    continue
                if link:
                    self._link(base, entry.path, links)
                else:
                    files.append(Path(entry.path))
            folders.extend(reversed(inner))
        if rest is not None:
            unchecked.append((".", "too many files", rest.hexdigest()))
        return sorted(files), sorted(links), tuple(unchecked)

    def _link(self, base: str, full: str, links: list[tuple[str, str]]) -> None:
        try:
            target = os.readlink(full)
        except OSError:
            target = ""
        links.append((os.path.relpath(full, base).replace(os.sep, "/"), target))
        if not os.path.exists(full):
            self.problem(full, "link to a missing target")

    # -- items

    def add(self, *, agent: str, kind: str, scope: str, project: Path | None, name: str, root, files=(), links=(), entry=None,
            config_path=None, config_key=(), origin: str = "unknown", enabled: bool | None = None, shown=None, unchecked=()) -> None:
        name = escaped(name)
        project = Path(os.path.abspath(project)) if project is not None else None
        key = tuple(str(k) for k in config_key)
        if shown is None and config_path is not None and key:
            location = escaped(f"{self.loc(config_path)} {'.'.join(key)}")
        else:
            location = self.loc(shown if shown is not None else root)
        self.items.append(Item(
            id=f"{agent}:{kind}:{_scope_part(scope, project)}:{name}", agent=agent, kind=kind, scope=scope, name=name, root=Path(root),
            files=tuple(sorted(Path(f) for f in files)), links=tuple(sorted(links)), entry=entry,
            config_path=Path(config_path) if config_path is not None else None, config_key=key, location=location, project=project,
            origin=origin, enabled=enabled, unchecked=tuple(unchecked),
        ))

    def command_files(self, command, *, base=None, project=None, plugin_root=None
                      ) -> tuple[list[Path], list[tuple[str, str]], tuple[tuple[str, str, str], ...]]:
        """Local files that a command line may run: an existing regular file with a script suffix, or with the execute bit set under the
        home, the project or the plugin. A name that looks like a secret is never one. Nothing is run or expanded beyond a few fixed
        variables; a word that still needs the shell is skipped. A link is recorded as a link, and so is a link on the way to the file
        inside what is scanned (the project, the plugin, the target, the folder of the item): the file behind it is never one, and a
        script behind a link that stays inside leaves the item unchecked there (`_behind`; `_settle` drops that when another item
        reads the script). Past MAX_SCRIPTS nothing more is kept, and the item is unchecked: the place, size and times of the rest
        stand in for them."""
        known = (("CLAUDE_PROJECT_DIR", project), ("CLAUDE_PLUGIN_ROOT", plugin_root), ("HOME", self.home))
        bases = [os.path.abspath(b) for b in (self.home, project, plugin_root, base) if b is not None]
        home = os.path.abspath(self.home) if self.home is not None else None
        # what is scanned, never passed through a link; the home is the person's own, with the links they made in it
        roots = [r for r in (os.path.abspath(b) for b in (project, plugin_root, base) if b is not None) if r != home]
        files: list[Path] = []
        links: list[tuple[str, str]] = []
        seen: set[str] = set()
        unchecked: list[tuple[str, str, str]] = []
        rest = None  # past MAX_SCRIPTS: the hash of what stands in for the files that are not kept
        for word, runs in _words(command):
            if word.startswith("-") and "=" in word:
                word = word.split("=", 1)[1]
            for var, value in known:
                if value is not None:
                    word = word.replace("${" + var + "}", os.fspath(value)).replace("$" + var, os.fspath(value))
            if self.home is not None and (word == "~" or word.startswith("~/")):
                word = os.fspath(self.home) + word[1:]
            if not word or word.startswith("-") or any(c in word for c in "$`*?\n\0"):
                continue
            if INTERPRETER.match(os.path.basename(word)):
                continue
            if os.path.isabs(word):
                raw = word
            elif base is not None and ("/" in word or Path(word).suffix in SCRIPT_SUFFIXES):
                raw = os.path.join(base, word)
            else:
                continue
            path = os.path.normpath(raw)
            if path in seen or SECRET_NAME.match(os.path.basename(path)):
                continue
            try:
                hop = _hop(raw, roots)
                if hop is not None and not (runs or Path(path).suffix in SCRIPT_SUFFIXES) and os.path.isdir(path):
                    continue  # a folder behind a link that the command only names (`--root ./shared/docs`) is data, no program
                found = hop if hop is not None else path
                mode = os.lstat(found).st_mode
            except (OSError, ValueError):
                continue
            if hop is None:
                script = Path(path).suffix in SCRIPT_SUFFIXES
                runnable = script or (bool(mode & 0o111) and not platform.IS_WINDOWS and any(_inside(path, b) for b in bases))
                if not runnable or not (stat.S_ISLNK(mode) or stat.S_ISREG(mode)):
                    continue
            seen.add(path)
            linked = stat.S_ISLNK(mode) or hop is not None
            behind = _behind(path, roots) if linked else None
            if isinstance(behind, tuple):
                unchecked.append(behind)
            elif behind is not None and behind not in files:
                if len(files) + len(links) >= MAX_SCRIPTS:
                    if rest is None:
                        rest = hashlib.sha256()
                    rest.update(_stand_in(os.fspath(behind), os.fspath(behind)))
                else:
                    files.append(behind)  # every link on the way stays inside: read like a script named directly
            if found in seen and found != path:
                continue  # a link already recorded for another word
            seen.add(found)
            if len(files) + len(links) >= MAX_SCRIPTS:
                if rest is None:
                    rest = hashlib.sha256()
                rest.update(_stand_in(found, found))
            elif linked:
                try:
                    links.append((found, os.readlink(found)))
                except OSError:
                    pass
            else:
                files.append(Path(path))
        if rest is not None:
            unchecked.append((".", "too many scripts", rest.hexdigest()))
        return files, links, tuple(unchecked)

    # -- entries of config files

    def hooks(self, hooks, *, agent, scope, project, cfg, key=("hooks",), prefix="", base=None, plugin_root=None, origin="unknown",
              enabled=None) -> None:
        if not isinstance(hooks, dict):
            return
        for event, groups in hooks.items():
            if not isinstance(event, str) or not isinstance(groups, list):
                continue
            for i, group in enumerate(groups):
                if not isinstance(group, dict):
                    continue
                handlers = group.get("hooks")
                if isinstance(handlers, list):
                    for j, handler in enumerate(handlers):
                        self._hook(handler, group.get("matcher"), (*key, event, str(i), "hooks", str(j)), event, agent, scope, project, cfg,
                                   prefix, base, plugin_root, origin, enabled)
                elif "command" in group or "type" in group:
                    self._hook(group, None, (*key, event, str(i)), event, agent, scope, project, cfg, prefix, base, plugin_root, origin, enabled)

    def _hook(self, handler, matcher, key, event, agent, scope, project, cfg, prefix, base, plugin_root, origin, enabled=None) -> None:
        if not isinstance(handler, dict):
            return
        command = handler.get("command")
        text = command if isinstance(command, str) else json.dumps(handler, sort_keys=True, default=str)
        entry = dict(handler)
        entry["event"] = event
        if isinstance(matcher, str) and matcher:
            entry["matcher"] = matcher
        if base is None and scope in ("project", "local"):
            base = project
        files, links, unchecked = self.command_files(command, base=base or plugin_root, project=project or self._target_root(),
                                                     plugin_root=plugin_root)
        self.add(agent=agent, kind="hook", scope=scope, project=project, name=f"{prefix}{event}:{_sha(text, 8)}", root=cfg, files=files,
                 links=links, entry=entry, config_path=cfg, config_key=key, origin=origin, enabled=enabled, unchecked=unchecked)

    def _target_root(self) -> Path | None:
        return self.target[0] if self.target is not None else None

    def mcp(self, servers, *, agent, scope, project, cfg, key=("mcpServers",), prefix="", base=None, plugin_root=None, origin="unknown",
            enabled=None) -> None:
        if not isinstance(servers, dict):
            return
        for name, entry in servers.items():
            if not isinstance(name, str) or not isinstance(entry, dict):
                continue
            command, args = entry.get("command"), entry.get("args")
            words = ([command] if isinstance(command, str) else []) + [a for a in args if isinstance(a, str)] if isinstance(args, list) else [command]
            place = base if base is not None else (project if scope in ("project", "local") else plugin_root)
            files, links, unchecked = self.command_files(words, base=place, project=project or self._target_root(), plugin_root=plugin_root)
            self.add(agent=agent, kind="mcp", scope=scope, project=project, name=f"{prefix}{name}", root=cfg, files=files, links=links,
                     entry=entry, config_path=cfg, config_key=(*key, name), origin=origin,
                     enabled=enabled(name, entry) if enabled is not None else None, unchecked=unchecked)

    def setting(self, path: tuple[str, ...], value, *, agent, scope, project, cfg, command=None, base=None) -> None:
        base = base if base is not None else (project if scope in ("project", "local") else None)
        files, links, unchecked = self.command_files(command, base=base, project=project or self._target_root())
        self.add(agent=agent, kind="setting", scope=scope, project=project, name=".".join(path), root=cfg, files=files, links=links,
                 entry=_nested(path, value), config_path=cfg, config_key=path, unchecked=unchecked)

    def claude_settings(self, path, *, scope, project, base=None, follow=True) -> dict | None:
        """Hooks and the settings that run a command or send traffic elsewhere, from a Claude Code settings file."""
        data = self.json_file(path, follow=follow)
        if data is None:
            return None
        self.hooks(data.get("hooks"), agent="claude", scope=scope, project=project, cfg=path, base=base)
        kw = {"agent": "claude", "scope": scope, "project": project, "cfg": path, "base": base}
        for key in CLAUDE_TOP_SETTINGS:
            if key in data:
                value = data[key]
                command = value.get("command") if isinstance(value, dict) else value
                self.setting((key,), value, command=command if isinstance(command, str) else None, **kw)
        permissions = data.get("permissions")
        if isinstance(permissions, dict):
            if "defaultMode" in permissions:
                self.setting(("permissions", "defaultMode"), permissions["defaultMode"], **kw)
            allow = permissions.get("allow")
            if isinstance(allow, list) and any(isinstance(a, str) and (a.strip() in WIDE_ALLOW or _holds_secret(a)) for a in allow):
                self.setting(("permissions", "allow"), allow, **kw)
        env = data.get("env")
        if isinstance(env, dict):
            for name, value in env.items():
                if isinstance(name, str) and WATCHED_ENV.search(name):
                    self.setting(("env", name), value, **kw)
        return data

    def codex_config(self, path, *, scope, project, base=None, follow=True) -> dict | None:
        data = self.toml_file(path, follow=follow)
        if data is None:
            return None

        def enabled(_name, entry):
            return entry["enabled"] if isinstance(entry.get("enabled"), bool) else True

        self.mcp(data.get("mcp_servers"), agent="codex", scope=scope, project=project, cfg=path, key=("mcp_servers",), base=base,
                 enabled=enabled)
        kw = {"agent": "codex", "scope": scope, "project": project, "cfg": path, "base": base}
        for key in CODEX_TOP_SETTINGS:
            if key in data:
                self.setting((key,), data[key], command=data[key] if key == "notify" else None, **kw)
        for key, value in data.items():
            if key.endswith("_base_url") and isinstance(value, str):
                self.setting((key,), value, **kw)
        providers = data.get("model_providers")
        if isinstance(providers, dict):
            for name, value in providers.items():
                self.setting(("model_providers", str(name)), value, **kw)
        policy = data.get("shell_environment_policy")
        env = policy.get("set") if isinstance(policy, dict) else None
        if isinstance(env, dict):
            for name, value in env.items():
                if WATCHED_ENV.search(str(name)):
                    self.setting(("shell_environment_policy", "set", str(name)), value, **kw)
        return data

    def hooks_json(self, path, *, agent, scope, project, base=None, follow=True) -> dict | None:
        data = self.json_file(path, follow=follow)
        if data is not None:
            self.hooks(data.get("hooks"), agent=agent, scope=scope, project=project, cfg=path, base=base)
        return data

    def mcp_json(self, path, *, agent, scope, project, base=None, enabled=None, follow=True) -> dict | None:
        data = self.json_file(path, follow=follow)
        if data is not None:
            self.mcp(data.get("mcpServers"), agent=agent, scope=scope, project=project, cfg=path, base=base, enabled=enabled)
        return data

    # -- skills, plugins and single-file kinds

    def user_lock(self) -> dict:
        """Skill name -> source, from the lock file the cross-agent installer keeps."""
        if not self._lock_read:
            self._lock_read = True
            self._lock = self.lock_file(self.home / ".agents" / ".skill-lock.json") if self.home is not None else {}
        return self._lock or {}

    def lock_file(self, path) -> dict:
        data = self.json_file(path)
        skills = data.get("skills") if data else None
        out = {}
        if isinstance(skills, dict):
            for name, entry in skills.items():
                if isinstance(entry, dict) and isinstance(entry.get("source"), str):
                    out[name] = _safe_source(entry["source"])
        return out

    def skill_root(self, agent: str, folder, *, scope, project, prefix="", origin="unknown", lock=None) -> None:
        """Queue the skill folders of one skills root; `flush_skills` builds them once every root is known, so a folder that two roots
        reach is built once and the real one is preferred to a link to it."""
        names = self.listdir(folder)
        if names is None:
            return
        for name in names:
            path = Path(folder) / name
            if not os.path.isdir(path):
                if _is_link(path) and not os.path.exists(path):
                    self.problem(path, "link to a missing target")
                continue
            if os.path.lexists(path / "SKILL.md"):
                self._skills.append((agent, path, f"{prefix}{name}", scope, project, origin, lock, _is_link(path)))
                continue
            for sub in self.listdir(path) or []:  # a folder of skills (synced/, .system/)
                inner = path / sub
                if not os.path.isdir(inner):
                    continue
                shown = "claude.ai" if name == "synced" and origin == "unknown" else origin
                linked = _is_link(path) or _is_link(inner)
                if os.path.lexists(inner / "SKILL.md"):
                    self._skills.append((agent, inner, f"{prefix}{name}/{sub}", scope, project, shown, lock, linked))
                elif name == "synced":  # skills from claude.ai, one folder per account: synced/<account>/<skill>, named synced/<skill>
                    for deep in self.listdir(inner) or []:
                        found = inner / deep
                        if os.path.isdir(found) and os.path.lexists(found / "SKILL.md"):
                            self._skills.append((agent, found, f"{prefix}{name}/{deep}", scope, project, shown, lock, linked or _is_link(found)))
                            self.account_layout.update((found, found / "SKILL.md"))

    def flush_skills(self) -> None:
        seen: set[str] = set()
        for agent, path, name, scope, project, origin, lock, _ in sorted(self._skills, key=lambda c: c[7]):
            real = os.path.realpath(path)
            if real in seen:
                continue
            seen.add(real)
            files, links, unchecked = self.walk(path)
            self.add(agent=agent, kind="skill", scope=scope, project=project, name=name, root=path, files=files, links=links,
                     origin=self._origin(real, os.path.basename(path), origin, lock), unchecked=unchecked)
            self.frontmatter_hooks(path / "SKILL.md", agent=agent, scope=scope, project=project, prefix=f"skill:{name}:", base=path)
        self._skills = []

    def _origin(self, real: str, folder: str, default: str, project_lock: dict | None) -> str:
        if self.home is not None:
            store = os.path.realpath(self.home / ".agents" / "skills")
            if _inside(real, store) and real != store:
                source = self.user_lock().get(real[len(store) + 1:].split(os.sep)[0])
                if source:
                    return f"skills-lock:{source}"
        if project_lock and folder in project_lock:
            return f"skills-lock:{project_lock[folder]}"
        return default

    def frontmatter_hooks(self, md, *, agent, scope, project, prefix, base) -> None:
        raw = self.read(md, follow=False)
        if raw is None:
            return
        block, well_formed = _split_frontmatter(raw.decode("utf-8", "replace"))
        if not well_formed:
            self.problem(md, "not valid frontmatter")
            return
        if block is None or not re.search(r"""(?m)(?:^|[\s{,?])["']?hooks["']?\s*(?::|$)""", block):
            return
        try:
            data = _Yaml(block).parse()
        except (ValueError, RecursionError, IndexError):
            data = None
        keyless = not re.search(r"""hooks["']?\s*:""", block) and not re.search(r"(?:^|[\s\[{,])[&*][^\s\[\]{},]", block)
        if isinstance(data, dict) and keyless:
            # read whole, the word never stands before a colon and no anchor or alias can make it a key, so it is in a value
            # (`description: Tips for writing React hooks`); `!!str hooks:`, `&a hooks:` and `*a :` are said below
            return
        # the agent reads these hooks, and a YAML reader may find them in a form this one does not (flow style, an explicit key, a
        # merge key): where no hooks mapping was parsed it is said, never skipped
        if not isinstance(data, dict) or not isinstance(data.get("hooks"), dict) or not _hooks_shape_ok(data["hooks"]):
            self.problem(md, "not valid frontmatter")
            return
        self.hooks(data["hooks"], agent=agent, scope=scope, project=project, cfg=md, prefix=prefix, base=base)

    def file_kind(self, agent: str, kind: str, folder, *, scope, project, suffixes=(".md",), hooks=True) -> None:
        """One item per file of a folder: commands, agents, output styles, prompts."""
        if self.listdir(folder) is None:
            return
        folder = Path(folder)
        files, links, _ = self.walk(folder)  # what could not be read here is a problem of the inventory: no one item holds it
        for path in files:
            if path.suffix in suffixes:
                self._file_item(agent, kind, folder, path, path, (), scope, project, hooks)
        for rel, target in links:
            link = folder / rel
            if link.suffix not in suffixes or os.path.isdir(link):
                continue
            real = os.path.realpath(link)
            # a file the person linked at the top of the folder is followed, once; nothing in a target is
            if "/" not in rel and self.target is None and os.path.isfile(real):
                self._file_item(agent, kind, folder, link, Path(real), (), scope, project, hooks)
            else:
                self._file_item(agent, kind, folder, link, None, ((rel, target),), scope, project, hooks)

    def _file_item(self, agent, kind, folder, path, real, links, scope, project, hooks) -> None:
        name = path.relative_to(folder).with_suffix("").as_posix()
        self.add(agent=agent, kind=kind, scope=scope, project=project, name=name, root=path, files=(real,) if real else (), links=links)
        if hooks and kind in ("agent", "command") and real is not None:
            self.frontmatter_hooks(real, agent=agent, scope=scope, project=project, prefix=f"{kind}:{name}:", base=None)

    def plugin(self, agent: str, name: str, root, *, scope, project, origin, enabled, cfg, key, entry=None, plugin_name=None,
               switched_in=None) -> None:
        """A plugin as installed: the folder as one item, and the MCP servers and hooks its own config files declare. Those are on
        and off with the plugin, so they carry its `enabled`. `switched_in`: the current project whose own settings switch a user
        plugin on; it is the plugin item's `project` (its scope stays "user"), where a quarantine switches it off."""
        root = Path(root)
        files, links, unchecked = self.walk(root)
        self.add(agent=agent, kind="plugin", scope=scope, project=switched_in if switched_in is not None else project, name=name, root=root,
                 files=files, links=links, entry=entry, config_path=cfg, config_key=key, origin=origin, enabled=enabled, shown=root,
                 unchecked=unchecked)
        short = escaped(plugin_name or name.split("@")[0])

        def own(path) -> dict | None:
            """A config file of the plugin, never read through a link inside it: such a link is one of the plugin's links."""
            return None if _hop(os.fspath(path), [os.path.abspath(root)]) is not None else self.json_file(path, follow=False)

        manifest = None
        for sub in (".claude-plugin", ".codex-plugin"):
            manifest = manifest or own(root / sub / "plugin.json")
        kw = {"agent": agent, "scope": scope, "project": project, "plugin_root": root, "origin": origin}

        def switch(_name, _entry):
            return enabled

        mcp = self.json_file(root / ".mcp.json", follow=False)
        if mcp is not None:
            servers = mcp.get("mcpServers")
            if not isinstance(servers, dict):  # the short form: the file is the table of servers
                servers = {k: v for k, v in mcp.items() if isinstance(v, dict) and ("command" in v or "url" in v or "type" in v)}
            key_ = ("mcpServers",) if "mcpServers" in mcp else ()
            self.mcp(servers, cfg=root / ".mcp.json", key=key_, prefix=f"{PLUGIN_PREFIX}{short}:", base=root, enabled=switch, **kw)
        if manifest is not None and isinstance(manifest.get("mcpServers"), dict):
            cfg = root / (".claude-plugin" if (root / ".claude-plugin").is_dir() else ".codex-plugin") / "plugin.json"
            self.mcp(manifest["mcpServers"], cfg=cfg, prefix=f"{PLUGIN_PREFIX}{short}:", base=root, enabled=switch, **kw)
        hooks = own(root / "hooks" / "hooks.json")
        if hooks is not None:
            self.hooks(hooks.get("hooks"), cfg=root / "hooks" / "hooks.json", prefix=f"{PLUGIN_PREFIX}{name}:", base=root, enabled=enabled, **kw)
        if manifest is not None and isinstance(manifest.get("hooks"), dict):
            cfg = root / (".claude-plugin" if (root / ".claude-plugin").is_dir() else ".codex-plugin") / "plugin.json"
            self.hooks(manifest["hooks"], cfg=cfg, prefix=f"{PLUGIN_PREFIX}{name}:", base=root, enabled=enabled, **kw)


# ---- discovery of what is installed ----


def _worktree_copy(path: Path) -> bool:
    parts = path.parts
    return any(a == ".claude" and b == "worktrees" for a, b in zip(parts, parts[1:]))


def _registered(data: dict | None, key: str) -> list[str]:
    table = data.get(key) if data else None
    return [k for k in table if isinstance(k, str) and os.path.isabs(k) and "\0" not in k] if isinstance(table, dict) else []


def _project_list(roots: Roots, claude: dict | None, codex: dict | None) -> list[Path]:
    found: list[Path] = []
    seen: set[str] = set()

    def add(path, registered: bool) -> None:
        path = Path(os.path.abspath(path))
        real = os.path.realpath(path)
        if real in seen or (registered and _worktree_copy(path)):
            return
        try:
            if not path.is_dir():
                return
        except (OSError, ValueError):
            return
        seen.add(real)
        found.append(path)

    for path in roots.projects:
        add(path, False)
    if roots.registered_projects:
        for key in sorted(_registered(claude, "projects")):
            add(key, True)
        for key in sorted(_registered(codex, "projects")):
            add(key, True)
    return found


def discover(roots: Roots) -> Inventory:
    home = roots.home
    d = _Disc(home)
    claude_json = d.json_file(home / ".claude.json")
    codex_toml = d.toml_file(home / ".codex" / "config.toml")
    projects = _project_list(roots, claude_json, codex_toml)

    claude_dir = home / ".claude"
    settings = d.claude_settings(claude_dir / "settings.json", scope="user", project=None) or {}
    enabled_plugins = settings.get("enabledPlugins") if isinstance(settings.get("enabledPlugins"), dict) else {}
    d.skill_root("claude", claude_dir / "skills", scope="user", project=None)
    d.skill_root("claude", claude_dir / "plugins" / "synced", scope="user", project=None, prefix="plugins-synced/", origin="claude.ai")
    for kind, folder in (("agent", "agents"), ("command", "commands"), ("output-style", "output-styles")):
        d.file_kind("claude", kind, claude_dir / folder, scope="user", project=None)
    _claude_plugins(d, home, enabled_plugins, _project_list(roots, None, None))  # the named folders, not the registered ones
    if claude_json is not None:
        d.mcp(claude_json.get("mcpServers"), agent="claude", scope="user", project=None, cfg=home / ".claude.json",
              origin="unknown")

    for where in ("Library/Application Support/Claude", "AppData/Roaming/Claude", ".config/Claude"):
        d.mcp_json(home / where / "claude_desktop_config.json", agent="claude-desktop", scope="user", project=None)

    codex_dir = home / ".codex"
    if codex_toml is not None:
        d.codex_config(codex_dir / "config.toml", scope="user", project=None)
        _codex_plugins(d, home, codex_toml)
    d.hooks_json(codex_dir / "hooks.json", agent="codex", scope="user", project=None)
    d.skill_root("codex", codex_dir / "skills", scope="user", project=None)
    d.file_kind("codex", "prompt", codex_dir / "prompts", scope="user", project=None)
    d.file_kind("codex", "agent", codex_dir / "agents", scope="user", project=None, suffixes=(".md", ".toml"), hooks=False)

    d.skill_root("agents", home / ".agents" / "skills", scope="user", project=None)
    d.mcp_json(home / ".cursor" / "mcp.json", agent="cursor", scope="user", project=None)
    d.skill_root("cursor", home / ".cursor" / "skills", scope="user", project=None)
    d.mcp_json(home / ".gemini" / "settings.json", agent="gemini", scope="user", project=None)
    d.skill_root("gemini", home / ".gemini" / "skills", scope="user", project=None)
    d.skill_root("openclaw", home / ".openclaw" / "skills", scope="user", project=None)
    d.skill_root("openclaw", home / ".clawdbot" / "skills", scope="user", project=None, prefix="clawdbot/")
    d.skill_root("openclaw", home / ".openclaw" / "workspace" / "skills", scope="user", project=None, prefix="workspace/")

    local = {}
    if claude_json is not None:
        for key in _registered(claude_json, "projects"):
            local.setdefault(os.path.realpath(key), (key, claude_json["projects"][key]))
    home_real = os.path.realpath(home)
    for project in projects:
        _project(d, project, local.get(os.path.realpath(project)), os.path.realpath(project) == home_real)

    d.flush_skills()
    return Inventory(_unique(_settle(d.items), frozenset(d.account_layout)), tuple(d.problems))


def _unique(items: list[Item], last: frozenset[Path] = frozenset()) -> tuple[Item, ...]:
    """Sorted by id; two items that would share an id keep it apart with a counter, in a fixed order. An item whose root is in `last`
    comes after the others of its id: a skill in synced/<account>/ never takes the id of one in synced/<skill> found before it."""
    out: list[Item] = []
    count: dict[str, int] = {}
    for item in sorted(items, key=lambda i: (i.id, i.root in last, str(i.root), i.config_key)):
        count[item.id] = count.get(item.id, 0) + 1
        out.append(item if count[item.id] == 1 else replace(item, id=f"{item.id}~{count[item.id]}"))
    return tuple(sorted(out, key=lambda i: i.id))


def _project_switches(d: _Disc, folder: Path, home: Path) -> dict[str, bool]:
    """Plugin id -> on or off, as a project's own settings switch plugins: settings.local.json over settings.json. In the home folder
    settings.json is the person's own file, so only settings.local.json speaks for the folder there."""
    own = os.path.realpath(folder) == os.path.realpath(home)
    switches: dict[str, bool] = {}
    for name in ("settings.local.json",) if own else ("settings.json", "settings.local.json"):
        data = d.json_file(folder / ".claude" / name)
        flags = data.get("enabledPlugins") if data else None
        if isinstance(flags, dict):
            switches.update((pid, on) for pid, on in flags.items() if isinstance(on, bool))
    return switches


def _claude_plugins(d: _Disc, home: Path, enabled_user: dict, current: list[Path]) -> None:
    """The installed Claude Code plugins. A user plugin is on or off where the person works: the settings of the current projects
    (`current`, the folders the caller named) switch it there and win over the person's own, as in Claude Code. Several current
    projects: on when one of them has it on."""
    path = home / ".claude" / "plugins" / "installed_plugins.json"
    data = d.json_file(path)
    plugins = data.get("plugins") if data else None
    if not isinstance(plugins, dict):
        return
    here = [(folder, _project_switches(d, folder, home)) for folder in current]
    for pid in sorted(plugins):
        entries = plugins[pid]
        for entry in [entries] if isinstance(entries, dict) else entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict) or not isinstance(pid, str) or not isinstance(entry.get("installPath"), str):
                continue
            root = home / ".claude" / "plugins" / entry["installPath"]
            scope, project = "user", None
            if entry.get("scope") in ("project", "local") and isinstance(entry.get("projectPath"), str):
                project = Path(entry["projectPath"])
                if not project.is_absolute() or not project.is_dir():
                    continue
                scope = entry["scope"]
            if not root.is_dir():
                continue
            enabled = enabled_user.get(pid)
            switched_in = None
            if project is not None:
                for name in ("settings.json", "settings.local.json"):
                    local = d.json_file(project / ".claude" / name)
                    flags = local.get("enabledPlugins") if local else None
                    if isinstance(flags, dict) and pid in flags:
                        enabled = flags[pid]
            elif here:
                user = enabled if isinstance(enabled, bool) else None
                states = []
                for folder, switches in here:
                    word = switches.get(pid)
                    if word is True and switched_in is None:
                        switched_in = folder
                    states.append(user if word is None else word)
                enabled = True if True in states else None if None in states else False
            market = pid.partition("@")[2]
            d.plugin("claude", pid, root, scope=scope, project=project, origin=f"marketplace:{escaped(market)}" if market else "unknown",
                     enabled=enabled if isinstance(enabled, bool) else None, cfg=path, key=("plugins", pid), switched_in=switched_in)


def _version_key(name: str):
    return [int(n) for n in re.findall(r"\d+", name)], name


def _codex_plugins(d: _Disc, home: Path, config: dict) -> None:
    plugins = config.get("plugins")
    if not isinstance(plugins, dict):
        return
    cfg = home / ".codex" / "config.toml"
    for pid in sorted(plugins):
        entry = plugins[pid]
        if not isinstance(entry, dict):
            continue
        name, _, market = str(pid).partition("@")
        folder = home / ".codex" / "plugins" / "cache" / market / name
        versions = [v for v in (d.listdir(folder) or []) if (folder / v).is_dir()]
        root = folder / max(versions, key=_version_key) if versions else None
        enabled = entry["enabled"] if isinstance(entry.get("enabled"), bool) else True
        origin = f"marketplace:{escaped(market)}" if market else "unknown"
        if root is not None:
            d.plugin("codex", str(pid), root, scope="user", project=None, origin=origin, enabled=enabled, cfg=cfg,
                     key=("plugins", str(pid)), entry=entry)
        else:
            d.add(agent="codex", kind="plugin", scope="user", project=None, name=str(pid), root=cfg, entry=entry, config_path=cfg,
                  config_key=("plugins", str(pid)), origin=origin, enabled=enabled)


def _project(d: _Disc, project: Path, local: tuple | None, is_home: bool) -> None:
    """The extensions of one project. The home folder counts as a project only for what it alone holds: its `.claude`, `.codex` and
    `.agents` are the user's own, found already; its settings files still switch the servers of ~/.mcp.json, as in any project."""
    claude_dir = project / ".claude"
    shared = local[1] if local and isinstance(local[1], dict) else {}
    disabled: set = set(shared.get("disabledMcpjsonServers") or []) if isinstance(shared.get("disabledMcpjsonServers"), list) else set()
    enabled: set = set(shared.get("enabledMcpjsonServers") or []) if isinstance(shared.get("enabledMcpjsonServers"), list) else set()
    enable_all = False
    for scope, name in (("project", "settings.json"), ("local", "settings.local.json")):
        # in the home folder these files hold the person's own items, listed already or not at all: only their switches count here,
        # among them what a quarantine of a server of ~/.mcp.json writes into ~/.claude/settings.local.json
        data = d.json_file(claude_dir / name) if is_home else d.claude_settings(claude_dir / name, scope=scope, project=project)
        if data:
            for key, bucket in (("disabledMcpjsonServers", disabled), ("enabledMcpjsonServers", enabled)):
                if isinstance(data.get(key), list):
                    bucket.update(n for n in data[key] if isinstance(n, str))
            enable_all = enable_all or data.get("enableAllProjectMcpServers") is True

    def switch(name, _entry):
        return False if name in disabled else True if name in enabled or enable_all else None

    d.mcp_json(project / ".mcp.json", agent="claude", scope="project", project=project, base=project, enabled=switch)
    if local and isinstance(shared.get("mcpServers"), dict):
        d.mcp(shared["mcpServers"], agent="claude", scope="local", project=project, cfg=d.home / ".claude.json",
              key=("projects", local[0], "mcpServers"))
    if is_home:
        return
    lock = d.lock_file(project / "skills-lock.json") if os.path.lexists(project / "skills-lock.json") else None
    d.skill_root("claude", claude_dir / "skills", scope="project", project=project, lock=lock)
    for kind, folder in (("agent", "agents"), ("command", "commands"), ("output-style", "output-styles")):
        d.file_kind("claude", kind, claude_dir / folder, scope="project", project=project)
    d.codex_config(project / ".codex" / "config.toml", scope="project", project=project, base=project)
    d.hooks_json(project / ".codex" / "hooks.json", agent="codex", scope="project", project=project, base=project)
    d.skill_root("agents", project / ".agents" / "skills", scope="project", project=project, lock=lock)
    d.mcp_json(project / ".cursor" / "mcp.json", agent="cursor", scope="project", project=project, base=project)
    d.skill_root("cursor", project / ".cursor" / "skills", scope="project", project=project, lock=lock)
    d.mcp_json(project / ".gemini" / "settings.json", agent="gemini", scope="project", project=project, base=project)
    d.skill_root("gemini", project / ".gemini" / "skills", scope="project", project=project, lock=lock)
    d.skill_root("openclaw", project / ".openclaw" / "skills", scope="project", project=project, lock=lock)


# ---- a folder before it is installed ----

CONFIG_NAMES = {".mcp.json", "settings.json", "settings.local.json", "hooks.json", "config.toml", "claude_desktop_config.json", "mcp.json"}
# every name of a file the inventory reads as an agent's settings, lower case: the configs above, the home's .claude.json, the lists of
# installed plugins and skills; and plugin.json in a manifest folder
AGENT_CONFIG_NAMES = frozenset({*CONFIG_NAMES, ".claude.json", "installed_plugins.json", ".skill-lock.json", "skills-lock.json"})
MANIFEST_FOLDERS = frozenset({".claude-plugin", ".codex-plugin"})


def is_agent_config(path: Path) -> bool:
    """A file an agent reads as its settings: one the inventory reads entries from (with their env, headers and allowed commands), or a
    plugin manifest, which may declare MCP servers with their env. Names are compared without case: a file system that ignores case
    (a Mac, Windows) hands `.MCP.json` to the agent as `.mcp.json`. Such a file never leaves (ai.py), and no value of it shows in the
    evidence of a finding (scan.py)."""
    name = path.name.casefold()
    return name in AGENT_CONFIG_NAMES or (name == "plugin.json" and path.parent.name.casefold() in MANIFEST_FOLDERS)


PRUNE = {".git", "node_modules"}
VCS_FOLDERS = frozenset({".git"})  # git's own folder: no agent loads it, and git keeps no path inside it (.hg and .svn it keeps like any folder)
# folders whose files are items of their own, as the agents keep them in a project or a home: (parent, folder) -> (agent, kind, suffixes,
# whether front matter hooks are read)
FILE_FOLDERS = {
    (".claude", "agents"): ("claude", "agent", (".md",), True),
    (".claude", "commands"): ("claude", "command", (".md",), True),
    (".claude", "output-styles"): ("claude", "output-style", (".md",), True),
    (".codex", "prompts"): ("codex", "prompt", (".md",), True),
    (".codex", "agents"): ("codex", "agent", (".md", ".toml"), False),
}


def discover_target(folder: Path, label: str) -> Inventory:
    """Every SKILL.md folder, plugin root, config file and file of a folder of commands, agents, output styles or prompts inside a
    folder, and one more item named label for the files that none of them holds (the whole folder when nothing is found): a harmless
    skill hides nothing beside it. Nothing of the folder is run, and no link in it is followed."""
    root = Path(os.path.abspath(folder))
    d = _Disc(None, (root, label))
    if os.path.isfile(root) and not _is_link(root):
        data = _target_config(d, root, root.parent)
        if _target_kind(root.parent, root.name) is None or (data is not None and _left_over(d, root, data)):
            d.add(agent="agents", kind="skill", scope="target", project=None, name=label, root=root, files=(root,))
        return Inventory(_unique(_settle(d.items)), tuple(d.problems))
    skills, plugins, configs, folders = _target_search(d, root)
    plugins = _outermost(plugins)
    skills = [s for s in _outermost(skills) if not any(_inside(os.fspath(s), os.fspath(p)) for p, _ in plugins)]
    holders = [p for p, _ in plugins] + skills
    for plugin, agent in plugins:
        name = label if plugin == root else plugin.relative_to(root).as_posix()
        manifest = d.json_file(plugin / (".codex-plugin" if agent == "codex" else ".claude-plugin") / "plugin.json", follow=False) or {}
        short = manifest.get("name") if isinstance(manifest.get("name"), str) else (root.name if plugin == root else plugin.name)
        d.plugin(agent, name, plugin, scope="target", project=None, origin="unknown", enabled=None, cfg=plugin, key=(), plugin_name=short)
    for skill in skills:
        files, links, unchecked = d.walk(skill)
        name = label if skill == root else skill.relative_to(root).as_posix()
        d.add(agent="agents", kind="skill", scope="target", project=None, name=name, root=skill, files=files, links=links, unchecked=unchecked)
        d.frontmatter_hooks(skill / "SKILL.md", agent="agents", scope="target", project=None, prefix=f"skill:{name}:", base=skill)
    read = set()  # configs whose every part became an item, or that could not be parsed (a problem): the rest leaves them out
    for config in configs:
        if not any(_inside(os.fspath(config), os.fspath(h)) for h in holders):
            data = _target_config(d, config, config.parent.parent if config.parent.name in (".claude", ".codex", ".cursor", ".gemini") else config.parent)
            if data is None or not _left_over(d, config, data):
                read.add(os.fspath(config))
    for where, (agent, kind, suffixes, hooks) in _outermost(folders):
        if not any(_inside(os.fspath(where), os.fspath(h)) for h in holders):
            d.file_kind(agent, kind, where, scope="target", project=None, suffixes=suffixes, hooks=hooks)
    _rest(d, root, label, holders, read)
    return Inventory(_unique(_settle(d.items)), tuple(d.problems))


def _rest(d: _Disc, root: Path, label: str, holders: list[Path], read: set[str]) -> None:
    """The files and links of a target that no item holds, and the configs with something left over that became no item, as one
    more item named by the label. With no other item it is the whole folder. A folder .git is no part of it: git's objects would
    only read as opaque data, and no repository can hold a file there."""
    if root in holders:
        return  # a skill or a plugin at the top holds it all
    single = ("agent", "command", "output-style", "prompt")  # a file of its own; a config entry's root is its config, see `read`
    held = read | {os.fspath(p) for item in d.items for p in (*item.files, *((item.root,) if item.kind in single else ()))}
    # what another item holds is left out before the cap counts: the cap is on what only this item reads
    files, links, unchecked = d.walk(root, skip=frozenset(held | {os.fspath(h) for h in holders}), prune=VCS_FOLDERS)
    if files or links or unchecked or not d.items:
        d.add(agent="agents", kind="skill", scope="target", project=None, name=label, root=root, files=files, links=links, unchecked=unchecked)


def _outermost(found: list) -> list:
    """Of nested folders only the outer one: its files already hold the inner."""
    keyed = sorted(found, key=lambda f: len((f[0] if isinstance(f, tuple) else f).parts))
    out: list = []
    for item in keyed:
        path = item[0] if isinstance(item, tuple) else item
        if not any(_inside(os.fspath(path), os.fspath(o[0] if isinstance(o, tuple) else o)) for o in out):
            out.append(item)
    return sorted(out, key=lambda f: str(f[0] if isinstance(f, tuple) else f))


def _target_search(d: _Disc, root: Path) -> tuple[list[Path], list[tuple[Path, str]], list[Path], list[tuple[Path, tuple]]]:
    skills: list[Path] = []
    plugins: list[tuple[Path, str]] = []
    configs: list[Path] = []
    folders: list[tuple[Path, tuple]] = []  # folders of FILE_FOLDERS, with what they hold
    seen = 0

    def onerror(error: OSError) -> None:
        d.problem(error.filename or root, "unreadable")

    for where, dirnames, filenames in os.walk(os.fspath(root), followlinks=False, onerror=onerror):
        dirnames[:] = sorted(n for n in dirnames if n not in PRUNE and not _is_link(os.path.join(where, n)))
        seen += len(dirnames) + len(filenames)
        if seen > MAX_SEEN:
            d.problem(root, "too many files")
            break
        here = Path(where)
        if (here.parent.name, here.name) in FILE_FOLDERS:
            folders.append((here, FILE_FOLDERS[here.parent.name, here.name]))
        if "SKILL.md" in filenames:
            skills.append(here)
        for sub, agent in ((".claude-plugin", "claude"), (".codex-plugin", "codex")):
            marker = here / sub / "plugin.json"
            if sub in dirnames and os.path.isfile(marker) and not _is_link(marker):
                plugins.append((here, agent))
                break
        for name in filenames:
            if name in CONFIG_NAMES and not _is_link(here / name) and _target_kind(here, name) is not None:
                configs.append(here / name)
    return skills, plugins, sorted(configs), folders


def _target_kind(folder: Path, name: str) -> str | None:
    """Which agent reads a config file of that name in that folder, or None when no agent does."""
    parent = folder.name
    if name == ".mcp.json":
        return "claude"
    if name in ("settings.json", "settings.local.json"):
        return {".claude": "claude", ".gemini": "gemini"}.get(parent) if name == "settings.json" or parent == ".claude" else None
    if name == "hooks.json":
        return "codex" if parent == ".codex" else "claude" if parent == "hooks" else None
    if name == "config.toml":
        return "codex" if parent == ".codex" else None
    if name == "claude_desktop_config.json":
        return "claude-desktop"
    if name == "mcp.json":
        return "cursor" if parent == ".cursor" else None
    return None


def _target_config(d: _Disc, config: Path, base: Path) -> dict | None:
    """Items of one config file inside a target, and the file as parsed: None when no agent reads a file of that name there, or when
    it cannot be parsed (a problem)."""
    agent = _target_kind(config.parent, config.name)
    if agent is None:
        return None
    kw = {"scope": "target", "project": None, "base": base, "follow": False}
    if config.name == ".mcp.json":
        return d.mcp_json(config, agent="claude", **kw)
    if config.name in ("settings.json", "settings.local.json") and agent == "claude":
        return d.claude_settings(config, scope="target", project=None, base=base, follow=False)
    if config.name == "settings.json":
        return d.mcp_json(config, agent=agent, **kw)
    if config.name == "hooks.json":
        return d.hooks_json(config, agent=agent, **kw)
    if config.name == "config.toml":
        return d.codex_config(config, scope="target", project=None, base=base, follow=False)
    return d.mcp_json(config, agent=agent, **kw)


def _left_over(d: _Disc, config: Path, data) -> bool:
    """Does a parsed config hold anything besides the entries that became its items (Codex `developer_instructions`, a `$schema`, a
    permission list)? Such content is checked as text, with the rest of the target; parsing a config is not checking all of it."""
    taken = {i.config_key for i in d.items if i.config_path == config}

    def more(value, path: tuple[str, ...]) -> bool:
        if path in taken:
            return False
        if isinstance(value, dict):
            kept = {k for k, v in value.items() if more(v, (*path, str(k)))}
            # a hook group whose every handler became an item is taken whole, its matcher with it
            return bool(kept) and not ("hooks" in value and "hooks" not in kept and kept <= {"matcher"})
        if isinstance(value, list):
            return any(more(v, (*path, str(n))) for n, v in enumerate(value))
        return True

    try:
        return more(data, ())
    except RecursionError:
        return True


# ---- digests and lookup ----


def _frame(data: bytes) -> bytes:
    return len(data).to_bytes(8, "big") + data


def _file_digest(path: Path) -> bytes:
    """SHA-256 of one file, streamed; a file that cannot be opened as a plain file hashes as a fixed marker."""
    try:
        fd = platform.open_nofollow(path, os.O_RDONLY)
    except OSError:
        return hashlib.sha256(b"unreadable").digest()
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return hashlib.sha256(b"unreadable").digest()
        digest = hashlib.sha256()
        while chunk := os.read(fd, 1 << 20):
            digest.update(chunk)
        return digest.digest()
    except OSError:
        return hashlib.sha256(b"unreadable").digest()
    finally:
        os.close(fd)


def item_digest(item: Item) -> str:
    """SHA-256 hex over the files as (relative path, content), the links as (path, target), the entry as canonical JSON and what was not
    read (`Item.unchecked`, whose hash stands in for it). A plain hash: it needs no key, so the session hook can compute it without the
    keychain."""
    root = os.fspath(item.root)
    rows = []
    for path in item.files:
        text = os.fspath(path)
        rel = text[len(root) + 1:].replace(os.sep, "/") if text.startswith(root + os.sep) else "." if text == root else text
        rows.append((rel, path))
    outer = hashlib.sha256()
    for rel, path in sorted(rows, key=lambda r: r[0]):
        outer.update(b"F" + _frame(rel.encode("utf-8", "surrogatepass")) + _file_digest(path))
    for where, target in sorted(item.links):
        outer.update(b"L" + _frame(where.encode("utf-8", "surrogatepass")) + _frame(target.encode("utf-8", "surrogatepass")))
    if item.entry is not None:
        canonical = json.dumps(item.entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
        outer.update(b"E" + _frame(canonical.encode("utf-8", "surrogatepass")))
    for unread in sorted(item.unchecked):
        outer.update(b"U" + b"".join(_frame(part.encode("utf-8", "surrogatepass")) for part in unread))
    return outer.hexdigest()


def find_items(inventory: Inventory, query: str) -> list[Item]:
    """The item with exactly that id, else every item whose id ends with `:<query>` or whose name is the query."""
    for item in inventory.items:
        if item.id == query:
            return [item]
    return [i for i in inventory.items if i.id.endswith(":" + query) or i.name == query]
