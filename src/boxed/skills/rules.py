"""The static rules of boxed skills: what in a file, a config entry or a link looks like a technique of malicious agent extensions.

The catalog covers 22 technique classes (T1-T22 in _rules_catalog.py). Every regex and threshold lives here and nowhere else. The checks never run,
import or follow anything they read: a file is opened without following links, read whole (no truncation, so padding cannot push
a payload out of sight), and only matched against patterns. Base64 runs and Unicode tag text are decoded and checked again, so
encoding hides nothing; what cannot be read (programs, archives, bytecode, a link out of the item) is a finding, never a pass. An
image, a font or a sound is read for the commands in its readable lines, since a script can stand between its binary parts.
Combinations weigh more than signs alone: a secret path plus a network call in one file, download + chmod + run, decode + run.

Every pattern is bounded (no unbounded wildcard after a fixed start), so no input makes a rule backtrack for long; a pattern runs
only when one of its trigger words occurs in the text, which keeps thousands of ordinary files fast."""

import base64
import bisect
import itertools
import ipaddress
import json
import math
import os
import re
import stat
import unicodedata
import zipfile
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from boxed import platform
from boxed.skills._rules_catalog import RULES, Rule  # both are part of this module's interface

SEVERITIES = ("info", "low", "medium", "high", "critical")
CAPABILITIES = ("runs-commands", "network", "reads-secrets", "writes-agent-files", "installs-packages",
                "binary-content", "event-hooks", "auto-approves", "obfuscation")
RULES_VERSION = "11"  # bump whenever a rule changes: the record compares it to know a finding may differ now
# The finding of something that was not checked in full: the inventory's caps (scan.py) and a rule's own caps (_Result.cut) alike.
INCOMPLETE = ("incomplete", "high", "Was not checked in full", "Part of it was not read, and what was left out can hold anything.",
              "Check the rest by hand, or remove what the item does not need and scan again.")
CUT_EVIDENCE = "a check stopped at its limit before the end of the text: the rest was not checked by every rule"


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    title: str
    why: str
    advice: str
    file: str
    line: int
    evidence: str
    source: str = "rules"


@dataclass(frozen=True)
class FileReport:
    findings: tuple[Finding, ...]
    capabilities: frozenset[str]


_BY_ID = {r.id: r for r in RULES}
_RANK = {s: i for i, s in enumerate(SEVERITIES)}

EVIDENCE_MAX = 160
# characters of one file that its evidence is masked against (the detectors read them whole once: linear, about half a second a
# megabyte); a text past what is left shows this instead of an excerpt, so no excerpt is ever shown unmasked
MASK_MAX = 1_000_000
LEFT_OUT = "excerpt left out: the file is too large to mask safely"
PER_RULE_MAX = 20  # findings of one rule in one file: the rest repeats what is shown
MATCHES_MAX = 200  # findings a pattern may yield per text, so a file full of one trick costs no more than a few; past it only a worse one
SCAN_MAX = 20_000  # matches a pattern may examine per text: decoys its judge drops cannot hide a real one behind them; past it, `incomplete`
DECODE_DEPTH = 3
DECODE_MAX = 2_000  # base64 runs decoded per text; past it, `incomplete`
BLANK_RUN = 1_000
LONG_LINE = 10_000
LARGE_SKILL = 256 * 1024
EXEC_WINDOW = 8  # lines between a decode and the call that runs it
HEAD = 64 * 1024
WINDOW = 1_200  # longer than any match of a pattern can reach from its trigger word
WINDOWED_FROM = 64 * 1024

# What a capability is shown for: the rules that prove it, and the signals below.
_RULE_CAPS = {
    "runs-commands": {"pipe-to-shell", "pipe-to-interpreter", "download-execute", "decode-exec", "reverse-shell", "ai-cli-unsafe",
                      "event-hook", "command-setting", "command-network"},
    "network": {"pipe-to-shell", "pipe-to-interpreter", "exfil-endpoint", "chat-webhook", "tunnel-host", "upload-file", "dns-exfil",
                "reverse-shell", "secret-exfiltration", "command-network", "remote-mcp-host", "download-execute"},
    "reads-secrets": {"secret-store", "credential-file", "env-dump", "many-secret-stores", "secret-exfiltration"},
    "writes-agent-files": {"agent-file-write"},
    "installs-packages": {"dependency-hijack", "unpinned-package", "mcp-lookalike", "vulnerable-package", "install-script"},
    "binary-content": {"binary-file", "bytecode", "archive", "encrypted-archive", "opaque-file"},
    "event-hooks": {"event-hook", "command-network", "auto-approve", "suppress-output"},
    "auto-approves": {"auto-approve", "bypass-permissions", "skip-permission-prompt", "auto-enable-mcp", "allow-all-bash", "ai-cli-unsafe"},
    "obfuscation": {"decode-exec", "obfuscated-code", "encoded-text", "unicode-tags", "zero-width", "bidi-control", "variation-selector"},
}
_SIGNAL_CAPS = {"network": "network", "exfil": "network", "download": "network", "run": "runs-commands", "exec": "runs-commands",
                "install": "installs-packages", "agent-write": "writes-agent-files"}

# Hosts. A domain matches itself and its subdomains.
_PASTE = ("glot.io", "pastebin.com", "rentry.co", "rentry.org", "hastebin.com", "paste.ee", "gist.githubusercontent.com", "dpaste.org",
          "dpaste.com", "termbin.com", "ix.io", "0x0.st", "transfer.sh", "paste.rs", "pastes.dev", "ghostbin.com", "privatebin.net",
          "controlc.com", "justpaste.it")
_COLLECT = ("webhook.site", "requestbin.com", "requestbin.net", "pipedream.net", "beeceptor.com", "hookbin.com", "interact.sh", "oast.fun",
            "oast.live", "oast.me", "oast.pro", "oast.site", "oast.online", "burpcollaborator.net", "oastify.com", "canarytokens.com",
            "requestcatcher.com", "webhook.cool", "ptsv3.com")
_TUNNEL = ("ngrok.io", "ngrok-free.app", "ngrok.app", "ngrok-free.dev", "ngrok.dev", "trycloudflare.com", "loca.lt", "serveo.net",
           "localhost.run", "lhr.life", "bore.pub", "localtunnel.me")
_WORKERS = ("workers.dev",)
_INSTALLERS = ("brew.sh", "sh.rustup.rs", "static.rust-lang.org", "astral.sh", "deb.nodesource.com", "rpm.nodesource.com", "get.docker.com",
               "bun.sh", "deno.land", "install.python-poetry.org", "get.pnpm.io", "install.determinate.systems", "nixos.org", "claude.ai",
               "ollama.com", "get.sdkman.io", "starship.rs", "pyenv.run", "fnm.vercel.app", "get.volta.sh")
_INSTALLER_PATHS = ("raw.githubusercontent.com/homebrew/", "raw.githubusercontent.com/nvm-sh/nvm/")
_API_HOSTS = ("api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com", "aiplatform.googleapis.com")
_REGISTRIES = ("registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "pypi.python.org", "files.pythonhosted.org", "download.pytorch.org")

_URL_HOST = re.compile(r"(?i)\b(?:https?|wss?|ftp)://(?:[^\s/@'\"<>]{0,200}@)?(\[[0-9a-f:.]{2,45}\]|[a-z0-9.-]{1,253})")
_BARE_IP = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_SKIP_NETS = tuple(ipaddress.ip_network(n) for n in ("127.0.0.0/8", "0.0.0.0/8", "169.254.0.0/16"))
_PRIVATE_NETS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"))


def _in(host: str, domains: tuple[str, ...]) -> bool:
    host = host.lower().strip(".")
    return any(host == d or host.endswith("." + d) for d in domains)


def _ip_class(text: str) -> str | None:
    """"skip" (this computer, link-local), "private" (a home or office network), "public", or None when it is no IPv4 address."""
    try:
        ip = ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return None
    if ip.version != 4:
        return "skip" if ip.is_loopback or ip.is_link_local else "public"
    if any(ip in n for n in _SKIP_NETS):
        return "skip"
    return "private" if any(ip in n for n in _PRIVATE_NETS) else "public"


def _local_host(host: str) -> bool:
    return host in ("localhost", "host.docker.internal") or host.endswith(".localhost") or _ip_class(host) in ("skip", "private")


def _risky_host(host: str) -> bool:
    return _in(host, _PASTE + _COLLECT + _TUNNEL + _WORKERS) or _ip_class(host) == "public"


def _installer(host: str, url: str) -> bool:
    """A well-known installer: its host, or for raw GitHub the installer's own repository at the start of the address itself
    (never a mention elsewhere on the line)."""
    if _in(host, _INSTALLERS):
        return True
    low = url.lower().split("://", 1)[-1]
    return host == "raw.githubusercontent.com" and ".." not in low and low.startswith(_INSTALLER_PATHS)


def _hosts(text: str) -> list[str]:
    return [h.lower().strip(".") for h in _URL_HOST.findall(text)]


_URL = re.compile(r"(?i)\b(?:https?|wss?|ftp)://(?:[^\s/@'\"<>]{0,200}@)?(\[[0-9a-f:.]{2,45}\]|[a-z0-9.-]{1,253})[^\s'\"<>)]{0,2000}")
_BARE_ADDRESS = re.compile(r"(?<![\w/@:.-])[\w-]{1,63}(?:\.[\w-]{1,63}){1,6}(?::\d{1,5})?/\S{0,500}")


def _urls(text: str) -> list[tuple[str, str]]:
    """(host, whole address) of every address in `text`."""
    return [(m.group(1).lower().strip("."), m.group()) for m in _URL.finditer(text)]


def _fetch_severity(segment: str) -> str | None:
    """The weight of what a download command fetches: critical from a bare public IP or a paste, collection or tunnel host; low
    when every address it names is a well-known installer (brew, rustup, uv); None (the rule's own) otherwise, also when an
    address is written without a scheme and cannot be judged."""
    urls = _urls(segment)
    if any(_ip_class(ip) == "public" for ip in _BARE_IP.findall(segment)) or any(_risky_host(h) for h, _ in urls):
        return "critical"
    bare = _BARE_ADDRESS.search(_URL.sub(" ", segment))
    if urls and not bare and all(_installer(h, u) for h, u in urls):
        return "low"
    return None


# Patterns


@dataclass(frozen=True)
class _Pattern:
    rule: str
    regex: re.Pattern
    triggers: tuple[str, ...]
    severity: str | None
    signal: str | None
    judge: Callable | None
    kinds: frozenset[str] | None
    names: frozenset[str] | None
    needs: tuple[str, ...]


def _P(rule: str, regex: str, triggers: tuple[str, ...] = (), *, severity: str | None = None, signal: str | None = None,
       judge: Callable | None = None, kinds: tuple[str, ...] | None = None, names: tuple[str, ...] | None = None,
       needs: tuple[str, ...] = ()) -> _Pattern:
    """A pattern of `rule`. It runs only when one of the lowercase `triggers` occurs in the lowered text (none: always), and one
    of `needs` too when given; in a long text it runs around the triggers only."""
    return _Pattern(rule, re.compile(regex), tuple(t.lower() for t in triggers), severity, signal, judge,
                    frozenset(kinds) if kinds else None, frozenset(names) if names else None, tuple(t.lower() for t in needs))


_FETCH_WORDS = r"\b(?:curl|wget|fetch|iwr|irm|invoke-webrequest|invoke-restmethod)\b"
_FETCH_NAMES = ("curl", "wget", "fetch", "iwr", "irm", "invoke-webrequest", "invoke-restmethod")
FETCH_BACK = 400  # how far before a pipe into a shell its download command may start


def _pipe_judge(t: "_Text", m: re.Match) -> str | None:
    """A pipe from a download command into a shell or an interpreter (see _from_fetch), weighed by what the command fetches: the
    text from the command to the pipe."""
    return _fetch_severity(t.text[m.start():m.start(1)])


def _subshell_judge(t: "_Text", m: re.Match) -> str | None:
    """bash <(curl ...), bash -c "$(curl ...)": weighed by the addresses inside the parentheses."""
    close = t.text.find(")", m.end(), m.end() + 2_000)
    _, line_end = t.span_of(m.start())
    return _fetch_severity(t.text[m.start():close if close != -1 else min(line_end, m.end() + 2_000)])


def _after_curl_judge(t: "_Text", m: re.Match) -> tuple[str | None, int] | str:
    """An upload option counts only in a curl command before it on the same line; anchored on the option for the same reason."""
    line_start, _ = t.span_of(m.start())
    curl = None
    for c in re.finditer(r"\bcurl\b", t.text[max(line_start, m.start() - FETCH_BACK):m.start()]):
        curl = c
    if curl is None:
        return "drop"
    return None, max(line_start, m.start() - FETCH_BACK) + curl.start()


def _after_7z_judge(t: "_Text", m: re.Match) -> tuple[None, int] | str:
    """7z x ... -pPASSWORD: the option counts only after 7z x or 7z e in the same line."""
    line_start, _ = t.span_of(m.start())
    lo = max(line_start, m.start() - FETCH_BACK)
    found = None
    for f in re.finditer(r"\b7za?\s+[xe]\b", t.text[lo:m.start()]):
        found = f
    return "drop" if found is None else (None, lo + found.start())


def _words_before_judge(words: str, back: int) -> Callable:
    """For a pattern anchored on its last words (cheap however often the first word repeats): it counts only when `words` come
    before it in the same line, within `back` characters; the hit is reported where they start."""
    regex = re.compile(words)

    def judge(t: "_Text", m: re.Match) -> tuple[None, int] | str:
        line_start, _ = t.span_of(m.start())
        lo = max(line_start, m.start() - back)
        found = regex.search(t.text, lo, m.start())
        return "drop" if found is None else (None, found.start())
    return judge


def _words_near_judge(words: str, reach: int) -> Callable:
    """For a pattern anchored on one word: it counts only when `words` stand within `reach` characters either side in the line."""
    regex = re.compile(words)

    def judge(t: "_Text", m: re.Match) -> str | None:
        start, end = t.span_of(m.start())
        return None if regex.search(t.text, max(start, m.start() - reach), min(end, m.end() + reach)) else "drop"
    return judge


def _line_fetch_judge(t: "_Text", m: re.Match) -> str | None:
    _, line_end = t.span_of(m.start())
    return _fetch_severity(t.text[m.start():min(line_end, m.end() + 2_000)])


def _ip_judge(t: "_Text", m: re.Match) -> str | None:
    kind = _ip_class(m.group(1))
    return "drop" if kind in ("skip", None) else ("low" if kind == "private" else None)


def _value_judge(allowed: tuple[str, ...]) -> Callable:
    """The severity of a setting whose last group is an address: none when it is an allowed host, low for this computer or a
    private network, medium when it is not written out (a variable), the rule's own otherwise."""
    def judge(t: "_Text", m: re.Match) -> str | None:
        value = m.group(m.lastindex or 0)
        hosts = _hosts(value)
        if not hosts:
            bare = re.match(r"[\w.-]+", value)
            hosts = [bare.group().lower()] if bare and "." in bare.group() else []
        if not hosts:
            return "medium"
        if all(_in(h, allowed) for h in hosts):
            return "drop"
        return "low" if all(_local_host(h) for h in hosts) else None
    return judge


def _mutable_judge(t: "_Text", m: re.Match) -> str | None:
    return "drop" if any(p in m.group().lower() for p in _INSTALLER_PATHS) else None


def _manifest_judge(t: "_Text", m: re.Match) -> str | None:
    return "high" if _MANIFEST.search(t.text) else "low"


_MANIFEST = re.compile(r"(?i)\b(?:requirements[\w.-]{0,40}\.txt|pyproject\.toml|package\.json|setup\.py|Pipfile|setup\.cfg)\b")

# A program however it is named: sudo, exec or command in front, any absolute path (/opt/homebrew/bin/), env with its options, a
# quote or a backslash before the name.
_LEAD = r"(?:(?:sudo|doas|exec|command|builtin|nohup)\s+(?:-\S+\s+){0,3}){0,3}"
_DIR = r"(?:/[\w.+-]{1,64}){0,6}/"
_NAMED = _LEAD + r"[\"']?\\?(?:" + _DIR + r")?(?:env\s+(?:-\S+\s+){0,3}[\"']?(?:" + _DIR + r")?)?"
_SH = _NAMED + r"(?:ba|z|da|k|fi)?sh"
_INTERPRETER = _NAMED + r"(?:python[0-9.]{0,4}|node|perl|ruby|php|osascript|deno|bun)"
_PIPE = r"\|&?\s*(?=[\"'a-z/\\])"  # a pipe, also |& (stderr too), before a name; in patterns that ignore case


def _from_fetch(tail: str) -> str:
    """A download command, then within FETCH_BACK characters of the same line, never past another download command, a pipe into
    `tail`; group 1 is empty, where the pipe starts. Anchored on the download command, so a pipe without one before it (a decoy)
    is not even a match, and a text full of the word curl stays linear: each scan stops at the next command."""
    return (r"(?i)" + _FETCH_WORDS + r"(?:(?!" + _FETCH_WORDS + r")[^\n]){0," + str(FETCH_BACK) + r"}?()" + _PIPE
            + r"(?:" + tail + r")\b")


def _domains(domains: tuple[str, ...]) -> str:
    return r"(?i)(?<![\w.-])(?:[a-z0-9-]{1,63}\.){0,6}(?:" + "|".join(re.escape(d) for d in domains) + r")(?![\w-])"


_AGENT_TARGET = (r"(?:(?:CLAUDE|AGENTS|MEMORY|SOUL)\.md|\.claude[/\\](?:settings(?:\.local)?\.json|skills|hooks|agents|commands|plugins)"
                 r"|\.codex[/\\](?:config\.toml|skills|prompts|hooks\.json|rules)|\.cursor[/\\](?:mcp\.json|rules)|\.agents[/\\]skills"
                 r"|\.gemini[/\\]settings\.json)")
_AGENT_TRIGGERS = ("claude.md", "agents.md", "memory.md", "soul.md", ".claude", ".codex", ".cursor", ".agents", ".gemini")

_SECRET_PATTERNS = (
    ("ssh", r"\.ssh[/\\](?:id_[a-z0-9_]{1,40}|[\w.-]{1,80}\.pem|identity)\b|(?:~|\$HOME|\$\{HOME\})[/\\]\.ssh[/\\]?(?=[\"'\s)]|$)", (".ssh",)),
    ("wallet", r"nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|egjidjbpglichdcondbcbdnbeeppgdph|hnfanknocfeofbddgcijnmhnfnkdnaad"
               r"|fhbohimaelbohpjbbldcngcnapndodjp|ibnejdfjmmkpcnlpebklmnkoeoihofec"
               r"|(?i:\bexodus[/\\](?:exodus\.wallet|wallets?)\b|\belectrum[/\\]wallets\b|(?-i:\bLedger Live\b)|\bwallet\.dat\b"
               r"|\.ethereum[/\\]keystore|solana[/\\]id\.json|\batomic[/\\]local storage)",
     ("nkbihf", "bfnaelm", "egjidj", "hnfankn", "fhbohim", "ibnejdf", "exodus", "electrum", "ledger", "wallet.dat", "keystore",
      "solana", "atomic/", "atomic\\")),
    ("browser", r"\b(?:Login Data|key4\.db|logins\.json|cookies\.sqlite)\b", ("login", "key4.db", "cookies.sqlite")),
    ("browser", r"(?i)\b(?:google[/\\]chrome|chromium|bravesoftware|microsoft[/\\]edge|firefox[/\\]profiles|opera software|vivaldi)\b"
                r"[^\n]{0,120}?\b(?:cookies|local state|web data)\b",
     ("google/chrome", "google\\chrome", "chromium", "bravesoftware", "microsoft/edge", "microsoft\\edge", "firefox/profiles",
      "firefox\\profiles", "opera", "vivaldi")),
    ("agent", r"\.clawdbot[/\\]\.env|\.openclaw[/\\](?:\.env|credentials|auth)|\.claude[/\\]\.credentials\.json|\.codex[/\\]auth\.json"
              r"|\.cursor[/\\]mcp\.json|claude_desktop_config\.json",
     (".clawdbot", ".openclaw", ".credentials.json", "auth.json", ".cursor", "claude_desktop_config")),
    ("keychain", r"\bsecurity\s+(?:find-(?:generic|internet)-password|dump-keychain)\b|\blogin\.keychain(?:-db)?\b", ("security", "keychain")),
    ("telegram", r"(?i)\btelegram(?: desktop)?[/\\]tdata\b", ("tdata",)),
    ("gpg", r"\.gnupg[/\\](?:private-keys|secring)", (".gnupg",)),
)

_PATTERNS: tuple[_Pattern, ...] = (
    # T1
    # anchored on the download command, the hit is where it starts (see _from_fetch); searched around the pipes
    _P("pipe-to-shell", _from_fetch(_SH + r"|iex|invoke-expression|source"), ("|",), needs=_FETCH_NAMES, judge=_pipe_judge, signal="run"),
    _P("pipe-to-shell", r"(?i)(?:\b(?:ba|z|da|k)?sh\s+(?:-\w+\s+){0,3}|\bsource\s+|(?<![\w.])\.\s+)<\(\s*(?:curl|wget)\b", ("<(",),
       judge=_subshell_judge, signal="run"),
    _P("pipe-to-shell", r"(?i)\b(?:(?:ba|z|da|k)?sh\s+-c|eval)\s+[\"']?\$\(\s*(?:curl|wget)\b", ("$(",), judge=_subshell_judge, signal="run"),
    _P("pipe-to-shell", r"(?i)\b(?:iex|invoke-expression)\b\s*\(?\s*\(?\s*(?:iwr|irm|invoke-webrequest|invoke-restmethod|curl|wget"
                        r"|new-object\s+(?:system\.)?net\.webclient)\b", ("iex", "invoke-expression"), judge=_line_fetch_judge, signal="run"),
    _P("pipe-to-shell", r"(?i)\.download(?:string|data)\s*\([^\n)]{0,300}\)\s*\|\s*(?:iex|invoke-expression)\b", ("downloadstring", "downloaddata"),
       judge=_line_fetch_judge, signal="run"),
    _P("pipe-to-interpreter", _from_fetch(_INTERPRETER), ("|",), needs=_FETCH_NAMES, judge=_pipe_judge, signal="run"),
    _P("paste-host", _domains(_PASTE), tuple(_PASTE), signal="network"),
    _P("raw-ip-url", r"(?i)\b(?:https?|wss?|ftp)://(?:[^\s/@'\"<>]{0,200}@)?(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])", ("://",), judge=_ip_judge,
       signal="network"),
    _P("known-ioc", r"(?i)\b91\.92\.242\.30\b|\bcom\.finder\.helper\b|\b(?:zaycv|aslaep123|pepe276|moonshine-100rze|infected123)\b",
       ("91.92.242.30", "com.finder.helper", "zaycv", "aslaep123", "pepe276", "moonshine-100rze", "infected123")),
    # T2
    _P("archive-password", r"\bunzip\s+(?:-[a-zA-Z]{1,8}\s+){0,4}-P\s*\S", ("unzip",)),
    _P("archive-password", r"\s-p\S", ("7z",), judge=_after_7z_judge),
    _P("archive-password", r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*\S[^\n]{0,80}?\b(?:zip|archive|extract|7z|rar)\b"
                           r"|\b(?:zip|archive|7z|rar)\b[^\n]{0,80}?\b(?:password|passwd|pwd)\s*[:=]\s*\S", ("password", "passwd", "pwd")),
    _P("archive-password", r"\.(?:setpassword|extractall|extract|open)\([^\n]{0,120}?\bpwd\s*=", ("pwd",)),
    # T3
    # anchored on the last words, the judge looks back for the first ones (cheap however often the first word repeats)
    _P("decode-exec", r"(?i)" + _PIPE + _SH + r"\b", ("base64",), judge=_words_before_judge(r"(?i)\bbase64\s+(?:-d|-D|--decode)\b", 200)),
    _P("decode-exec", r"(?i)\beval\s*[\"']?\$\(\s*(?:echo|printf)\b", ("eval",)),
    _P("decode-exec", r"(?i)base64", ("eval",), judge=_words_before_judge(r"(?i)\beval\s*[\"']?\$\([^\n)]{0,200}\Z", 200)),
    _P("decode-exec", r"\b(?:exec|eval)\s*\(\s*(?:compile\s*\(\s*)?(?:base64\.\w{0,10}b64decode|zlib\.decompress|bytes\.fromhex|codecs\.decode"
                      r"|marshal\.loads|__import__\(\s*[\"'](?:base64|zlib|codecs|marshal)[\"']\))", ("exec", "eval")),
    _P("decode-exec", r"\b(?:eval|Function)\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(|\beval\s*\(\s*Buffer\.from\(", ("eval", "function")),
    _P("decode-exec", r"(?i)frombase64string", ("frombase64string",), judge=_words_near_judge(r"(?i)\b(?:iex|invoke-expression)\b", 200)),
    _P("obfuscated-code", r"String\.fromCharCode\(\s*(?:\d{1,7}\s*,\s*){20,}", ("fromcharcode",)),
    _P("obfuscated-code", r"(?:\\x[0-9a-fA-F]{2}){40,}|(?:\\u00[0-9a-fA-F]{2}){20,}", ("\\x", "\\u00")),
    _P("obfuscated-code", r"(?:\bchr\(\d{1,7}\)\s*\+\s*){10,}", ("chr(",)),
    # T4
    *(_P("secret-store", regex, triggers, signal="secret:" + category) for category, regex, triggers in _SECRET_PATTERNS),
    _P("credential-file", r"\.aws[/\\]credentials\b|\.config[/\\]gcloud[/\\](?:credentials|application_default_credentials|legacy_credentials"
                          r"|access_tokens)|\.azure[/\\](?:accessTokens|msal_token_cache)|\.kube[/\\]config\b|\.docker[/\\]config\.json"
                          r"|(?<![\w.])\.npmrc\b|\.pypirc\b|(?<![\w.])\.netrc\b|\.git-credentials\b|\.config[/\\]gh[/\\]hosts\.yml",
       (".aws", "gcloud", ".azure", ".kube", ".docker", ".npmrc", ".pypirc", ".netrc", ".git-credentials", "hosts.yml"), signal="credential"),
    _P("env-dump", r"\bprintenv\b(?!\s+[\w$])", ("printenv",), signal="secret:env"),
    _P("env-dump", r"(?m)(?:^|[;&|(`]|\$\()[ \t]{0,8}env[ \t]{1,8}(?:>|\|(?!\|))", ("env",), signal="secret:env"),
    _P("env-dump", r"\bjson\.dumps\(\s*(?:dict\(\s*)?os\.environ\b(?!\s*[\[.])|\bdict\(\s*os\.environ\s*\)"
                   r"|\bJSON\.stringify\(\s*process\.env\s*[,)]|(?i:\bGet-ChildItem\s+env:)",
       ("os.environ", "process.env", "get-childitem"), signal="secret:env"),
    # T5
    _P("exfil-endpoint", _domains(_COLLECT), tuple(_COLLECT), signal="exfil"),
    _P("chat-webhook", r"(?i)discord(?:app)?\.com/api/webhooks/\d{5,30}/[\w-]{20,}|api\.telegram\.org/bot\d{6,12}:[\w-]{30,}", ("discord", "telegram"),
       severity="critical", signal="exfil"),
    _P("chat-webhook", r"(?i)discord(?:app)?\.com/api/webhooks\b|api\.telegram\.org/bot", ("discord", "telegram"), signal="network"),
    _P("tunnel-host", _domains(_TUNNEL), tuple(_TUNNEL), signal="network"),
    _P("tunnel-host", _domains(_WORKERS), _WORKERS, severity="medium", signal="network"),
    _P("upload-file", r"\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form)\s*[\"']?[\w.\[\]-]{0,40}=?@|\s(?:-T|--upload-file)\s+\S",
       ("-d", "--data", "-f", "--form", "-t", "--upload-file"), judge=_after_curl_judge, signal="network"),
    _P("dns-exfil", r"\b(?:nslookup|dig|host)\s+[^\n]{0,100}?\$\(", ("nslookup", "dig", "host")),
    _P("hidden-bcc", r"(?i)\bbcc\b[\"']?\s*[:=]\s*\[?\s*[\"'][^\"'\s@]{1,64}@[^\"'\s]{1,255}[\"']", ("bcc",)),
    # T6
    _P("reverse-shell", r"/dev/(?:tcp|udp)/[^/\s]{1,255}/\d{1,5}|\bmkfifo\s+/tmp/|\bsocat\b[^\n]{0,200}?\bexec:|\bpty\.spawn\s*\("
                        r"|\bos\.dup2\s*\(\s*\w{1,40}\.fileno\(\)", ("/dev/tcp", "/dev/udp", "mkfifo", "socat", "pty.spawn", "dup2"),
       signal="network"),
    _P("reverse-shell", r"\bn(?:c|cat)\b[^\n]{0,100}?\s-[a-z]{0,6}[ec]\s", ("nc",), signal="network"),
    # T7
    _P("persistence", r"Library/LaunchDaemons/", ("launchdaemons",), severity="critical"),
    _P("persistence", r"Library/LaunchAgents/|\blaunchctl\s+(?:load|bootstrap|submit|enable)\b|(?m:\bcrontab\s+-(?=[\s;)|&]|$))"
                      r"|\|\s*crontab\b|\bsystemctl\s+--user\s+enable\b"
                      r"|\bgit\s+config\s+--global\s+core\.hooksPath\b",
       ("launchagents", "launchctl", "crontab", "systemctl", "hookspath")),
    _P("persistence", r"(?i)\blogin\s+item\b", ("login",), judge=_words_before_judge(r"(?i)\bosascript\b", 200)),
    _P("persistence", r">>\s*[\"']?(?:~|\$HOME|\$\{HOME\})?/?\.(?:zshrc|bashrc|bash_profile|zprofile|profile|zshenv|zlogin)\b",
       (">>",), severity="medium"),
    _P("agent-file-write", r"(?<=[\w\"')\]}])\s*>>?\s*[\"']?[~$\w./{}\\-]{0,200}?" + _AGENT_TARGET, _AGENT_TRIGGERS, signal="agent-write"),
    # the agent file is the destination: the last word of the command
    _P("agent-file-write", r"\b(?:tee(?:\s+-a)?|sed\s+-i(?:\s*['\"]{2})?|cp|mv|ln\s+-s\w{0,3})\s[^\n|;&]{0,200}?" + _AGENT_TARGET
                           + r"[\"']?(?=\s*(?:$|[;&|)`]|>\s*/dev/null|2>))", _AGENT_TRIGGERS, signal="agent-write"),
    _P("agent-file-write", _AGENT_TARGET + r"[^\n]{0,200}?(?:[\"'],\s*[\"'][wa]\+?b?[\"']|\)\.write_text\(|\bwriteFileSync\b|\bappendFileSync\b)"
       r"|\b(?:writeFileSync|writeFile|appendFile|appendFileSync|write_text|Set-Content|Add-Content|Out-File)\b[^\n]{0,200}?" + _AGENT_TARGET,
       _AGENT_TRIGGERS, signal="agent-write"),
    _P("agent-file-write", r"(?i)\b(?:append|add|write|insert|save)\b[^\n]{0,60}?\b(?:to|into)\s+(?:your\s+|the\s+)?(?:~/)?(?:MEMORY|SOUL)\.md\b",
       ("memory.md", "soul.md"), severity="medium"),
    # T8
    _P("defence-evasion", r"\bxattr\b[^\n]{0,60}?\s-[a-zA-Z]{0,4}[dc]|\bsudo\s+-S\b|\bsecurity\s+unlock-keychain\b|LSQuarantine\s+-bool\s+(?:NO|false)",
       ("xattr", "sudo", "unlock-keychain", "lsquarantine")),
    _P("defence-evasion", r"\bspctl\s+--(?:master|global)-disable\b|\bcsrutil\s+disable\b", ("spctl", "csrutil"), severity="critical"),
    _P("password-prompt", r"(?i)\bhidden\s+answer\b", ("hidden",), judge=_words_before_judge(r"(?i)\bosascript\b[^\n]{0,300}?display\s+dialog", 600)),
    _P("password-prompt", r"\bdscl\s+\.\s+-authonly\b", ("dscl",)),
    # T9
    _P("prompt-injection", r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|earlier|preceding)\s+"
                           r"(?:instructions|prompts?|rules|directions)", ("ignore", "disregard", "forget")),
    # Hiding things from the person is common in honest instructions too ("do not show the user the raw JSON"): low alone,
    # raised when the file does something else that matters (see _combine).
    _P("prompt-injection", r"(?i)\b(?:do\s+not|don't|never)\s+(?:tell|mention|inform|reveal|show|disclose)\b[^.\n]{0,40}?\b(?:user|human)"
                           r"|\bwithout\s+(?:asking|telling|informing)\b[^.\n]{0,40}?\b(?:user|human)",
       ("not", "don't", "never", "without"), severity="low", signal="concealment"),
    _P("prompt-injection", r"(?i)\b(?:enable|enter|activate|switch\s+to)\s+(?:developer|god|dan|jailbreak)\s+mode\b"
                           r"|\byou\s+are\s+(?:now\s+)?in\s+(?:developer|god|dan|jailbreak)\s+mode\b", ("mode",)),
    _P("prompt-injection", r"(?i)\b(?:before|prior\s+to)\s+(?:using|calling)\s+(?:this|any)\s+tool\b[^.\n]{0,60}?\b(?:read|cat|send|pass)\b",
       ("tool",)),
    _P("prompt-injection", r"(?i)<\s*/?\s*(?:important|system|admin|secret)\s*>|\bpass\s+(?:its|the)\s+contents?\s+as\b",
       ("important", "system", "admin", "secret", "pass"), severity="medium"),
    _P("reviewer-address", r"(?i)\b(?:security|malware|virus|ai|llm|automated|static[- ]analysis)\s+(?:reviewers?|scanners?|auditors?)\b"
                           r"|\b(?:note|message|attention)\s+(?:to|for)\s+(?:the\s+|any\s+|all\s+)?(?:\w{1,20}\s+)?"
                           r"(?:reviewers?|scanners?|auditors?|analy[sz]ers?|moderators?)\b",
       ("reviewer", "scanner", "auditor", "analyzer", "analyser", "moderator")),
    _P("reviewer-address", r"(?i)\bthis\s+(?:skill|plugin|extension|server|tool|file|code|package|script|repo(?:sitory)?)\s+is\s+"
                           r"(?:safe|benign|harmless|trusted|legitimate|verified|clean|not\s+malicious)\b"
                           r"|\b(?:mark|classify|rate)\s+(?:this|it)\s+as\s+(?:safe|clean|benign)\b",
       ("safe", "benign", "harmless", "trusted", "legitimate", "verified", "clean", "malicious")),
    _P("reviewer-address", r"(?i)\bignore\s+(?:all\s+|any\s+|the\s+|these\s+|those\s+|such\s+)?(?:security\s+|scanner\s+|static[- ]analysis\s+)?"
                           r"(?:warnings?|alerts?|findings?)\b"
                           r"|\b(?:these|those|all|any|security|scanner)\s+(?:warnings?|findings?|alerts?|detections?)\s+(?:are|is)\s+"
                           r"(?:test\s+artifacts|false\s+positives?|expected|safe\s+to\s+ignore)\b",
       ("warning", "alert", "finding", "detection")),
    _P("reviewer-address", r"(?i)\b(?:report|flag)\s+(?:nothing|no\s+(?:issues|findings|problems|warnings))\b",
       ("nothing", "issues", "findings", "problems", "warnings")),
    # T10
    _P("tool-shadowing", r"(?i)\b(?:when|while|before|after)\s+(?:using|calling|invoking)\s+(?:any|all|other|another)\s+tools?\b"
                         r"|\binstead\s+of\s+(?:using|calling)\s+(?:the\s+)?[\w-]{1,60}\s+tool\b|\b(?:for|with)\s+(?:all|any|every)\s+other\s+tools?\b",
       ("tool",)),
    # T22
    _P("context-exfiltration", r"(?is)\b(?:(?:conversation|chat)\s+history|full\s+context|debug(?:ging)?\s+context|entire\s+conversation)\b"
                               r".{0,100}?(?:https?://|\bcurl\b|\bwebhook\b)|(?:https?://|\bcurl\b).{0,100}?\b(?:(?:conversation|chat)\s+history"
                               r"|full\s+context|debug(?:ging)?\s+context|entire\s+conversation)\b",
       ("history", "context", "entire")),
    # T13
    _P("preload-injection", r"\b(?:LD_PRELOAD|DYLD_INSERT_LIBRARIES)\b", ("ld_preload", "dyld_insert")),
    _P("external-instructions", r"(?i)\b(?:read|load|open|follow|extract|use)\b[^\n]{0,80}?\b(?:instructions?|steps|setup|rules|prompt)\b[^\n]{0,80}?"
                                r"\b[\w-]{1,100}\.(?:docx|zip|pdf|xlsx|pptx|7z|rar|odt)\b"
                                r"|\b(?:read|load|open|follow|extract)\b[^\n]{0,40}?\b[\w-]{1,100}\.(?:docx|zip|pdf|7z|rar)\b[^\n]{0,60}?\binstructions?\b",
       (".docx", ".zip", ".pdf", ".xlsx", ".pptx", ".7z", ".rar", ".odt")),
    # T14
    _P("remote-instructions", r"(?i)\b(?:fetch|download|load|read|get|pull)\s+(?:the\s+)?(?:latest\s+|updated\s+|current\s+|new\s+)?"
                              r"(?:instructions|rules|prompts?|commands|system\s+prompt|skill)\s+from\s+https?://", ("from",)),
    _P("mutable-download", r"(?i)raw\.githubusercontent\.com/[\w.-]{1,100}/[\w.-]{1,100}/(?:main|master|HEAD|latest|develop)/",
       ("raw.githubusercontent.com",), judge=_mutable_judge),
    # T15
    _P("endpoint-override", r"\b(ANTHROPIC_BASE_URL|ANTHROPIC_API_URL|ANTHROPIC_BEDROCK_BASE_URL|ANTHROPIC_VERTEX_BASE_URL|OPENAI_BASE_URL"
                            r"|OPENAI_API_BASE|AZURE_OPENAI_ENDPOINT|GOOGLE_GEMINI_BASE_URL|GEMINI_API_BASE|GEMINI_BASE_URL)\b[\"']?\s*[:=]\s*[\"']?"
                            r"([^\s\"']{0,300})", ("base_url", "api_url", "api_base", "_endpoint"), judge=_value_judge(_API_HOSTS)),
    _P("proxy-override", r"\b(?:HTTPS?_PROXY|ALL_PROXY|https?_proxy|all_proxy)\b[\"']?\s*[:=]\s*[\"']?([^\s\"']{0,300})", ("_proxy",),
       judge=_value_judge(())),
    _P("tls-override", r"\bNODE_TLS_REJECT_UNAUTHORIZED\b[\"']?\s*[:=]\s*[\"']?0\b|\bGIT_SSL_NO_VERIFY\b[\"']?\s*[:=]\s*[\"']?(?:1|true)\b"
                       r"|\bPYTHONHTTPSVERIFY\b[\"']?\s*[:=]\s*[\"']?0\b", ("tls_reject", "ssl_no_verify", "httpsverify")),
    _P("tls-override", r"\b(?:NODE_EXTRA_CA_CERTS|REQUESTS_CA_BUNDLE|SSL_CERT_FILE|CURL_CA_BUNDLE)\b[\"']?\s*[:=]",
       ("ca_certs", "ca_bundle", "ssl_cert_file"), severity="medium"),
    _P("registry-override", r"(?i)\b(?:npm|pnpm|yarn|bun)\s+config\s+set\s+(?:registry|npmRegistryServer|@[\w-]{1,60}:registry)\s+[\"']?(\S{1,300})",
       ("config",), judge=_value_judge(_REGISTRIES)),
    _P("registry-override", r"(?i)\b(?:npm_config_registry|PIP_INDEX_URL|PIP_EXTRA_INDEX_URL|UV_INDEX_URL|UV_DEFAULT_INDEX|UV_EXTRA_INDEX_URL|UV_INDEX"
                            r"|YARN_REGISTRY|YARN_NPM_REGISTRY_SERVER|BUN_CONFIG_REGISTRY)\b[\"']?\s*[:=]\s*[\"']?([^\s\"']{0,300})",
       ("npm_config_registry", "pip_index_url", "pip_extra_index_url", "uv_index", "uv_default_index", "uv_extra_index_url", "yarn_registry",
        "yarn_npm_registry_server", "bun_config_registry"), judge=_value_judge(_REGISTRIES)),
    _P("registry-override", r"--(?:extra-)?index-url[ =][\"']?(\S{1,300})", ("index-url",), judge=_value_judge(_REGISTRIES)),
    _P("registry-override", r"--registry[ =][\"']?(\S{1,300})", ("--registry",), judge=_value_judge(_REGISTRIES)),
    _P("registry-override", r"(?m:^[ \t]{0,8}registry[ \t]*=[ \t]*(\S{1,300}))", ("registry",), judge=_value_judge(_REGISTRIES)),
    _P("git-redirect", r"(?i)\burl\.[^\s=]{1,200}?\.insteadOf\b", ("insteadof",)),
    # T16
    _P("auto-approve", r"[\"']?permissionDecision\\?[\"']?\s*[:=]\s*\\?[\"']allow\\?[\"']|[\"']decision\\?[\"']\s*:\s*\\?[\"']approve\\?[\"']",
       ("permissiondecision", "decision")),
    _P("suppress-output", r"[\"']?suppressOutput\\?[\"']?\s*[:=]\s*(?:true|True)\b", ("suppressoutput",)),
    _P("bypass-permissions", r"[\"']defaultMode[\"']\s*:\s*[\"']bypassPermissions[\"']|--permission-mode[ =]bypassPermissions"
                             r"|\bsandbox_mode\s*=\s*[\"']danger-full-access[\"']", ("bypasspermissions", "danger-full-access")),
    _P("skip-permission-prompt", r"[\"']skipDangerousModePermissionPrompt[\"']\s*:\s*true", ("skipdangerous",)),
    _P("auto-enable-mcp", r"[\"']enableAllProjectMcpServers[\"']\s*:\s*true", ("enableallproject",)),
    _P("allow-all-bash", r"[\"']Bash\((?:\*|\*:\*|:\*)\)[\"']", ("bash(",)),
    # T17
    _P("install-script", r"[\"'](?:pre|post)?install[\"']\s*:", ("install",), names=("package.json",)),
    # T19
    _P("ai-cli-unsafe", r"--dangerously-skip-permissions|--allow-dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox"
                        r"|--trust-all-tools|\bgemini\b[^\n]{0,200}?\s--yolo\b|\bcodex\b[^\n]{0,200}?\s(?:--full-auto|--yolo)\b",
       ("--dangerously", "--trust-all-tools", "--yolo", "--full-auto"), signal="ai-cli"),
    # T20
    _P("dependency-hijack", r"(?i)\b(?:pip3?|uv\s+pip|pipx|python3?\s+-m\s+pip)\s+install\b[^\n]{0,200}?\bgit\+(?:https?|ssh)://", ("git+",),
       judge=_manifest_judge),
    _P("dependency-hijack", r"(?i)\b(?:npm|pnpm|yarn|bun)\s+(?:install|i|add)\b[^\n]{0,200}?\bhttps?://", ("npm", "pnpm", "yarn", "bun"),
       judge=_manifest_judge),
    _P("dependency-hijack", r"(?i)\b(?:pip3?|uv\s+pip)\s+install\b[^\n]{0,200}?\bhttps?://\S{1,300}\.(?:whl|tar\.gz|zip)\b",
       (".whl", ".tar.gz", ".zip"), judge=_manifest_judge),
    # T21
    _P("destructive-command", r"\brm\s+-(?:rf|fr|Rf|rF|r\s+-f|f\s+-r)\s+(?:--no-preserve-root\s+)?[\"']?(?:~|\$HOME|\$\{HOME\}|/)/?\*?[\"']?"
                              r"(?=\s|$|;|&|\|)", ("-rf", "-fr", "-r")),
    _P("destructive-command", r"\bchmod\s+-R\s+0?[67][67][67]\s+[\"']?(?:~|\$HOME|/)/?[\"']?(?=\s|$)", ("chmod",)),
    _P("destructive-command", r"(?:>>?|\btee\b(?:\s+-a)?|\bsed\s+-i\b)[^\n]{0,40}?/etc/(?:hosts|sudoers)\b|\bvisudo\b", ("/etc/", "visudo")),
    _P("destructive-command", r"\bpfctl\s+-d\b|\bufw\s+disable\b|\bnetsh\s+advfirewall\s+set\b[^\n]{0,80}?\boff\b|Set-MpPreference\s+-Disable"
                              r"|\bsetenforce\s+0\b", ("pfctl", "ufw", "netsh", "set-mppreference", "setenforce")),
    _P("destructive-command", r"\bsystemctl\s+(?:edit|disable|mask)\b", ("systemctl",), severity="medium"),
)

# Signals: not findings, but what a file does, for capabilities and for the combinations.
_SIGNALS: tuple[tuple[str, re.Pattern, tuple[str, ...]], ...] = tuple((name, re.compile(regex), triggers) for name, regex, triggers in (
    ("network", r"(?i)\b(?:curl|wget|ncat|socat|scp|sftp|rsync|telnet|aria2c)\s",
     ("curl", "wget", "ncat", "socat", "scp", "sftp", "rsync", "telnet", "aria2c")),
    ("network", r"\b(?:requests|httpx|aiohttp|urllib3?)\.(?:get|post|put|patch|delete|request|Session|AsyncClient|Client|ClientSession|urlopen"
                r"|PoolManager)\b|\burlopen\(|\burlretrieve\(|\bhttp\.client\b|\bsocket\.(?:socket|create_connection)\(|\bsmtplib\b",
     ("requests.", "httpx.", "aiohttp.", "urllib", "urlopen(", "urlretrieve(", "http.client", "socket.", "smtplib")),
    ("network", r"\bfetch\(|\baxios\b|\bXMLHttpRequest\b|\bhttps?\.(?:request|get)\(|\bnet\.connect\(|\bnew\s+WebSocket\(|\bnodemailer\b",
     ("fetch(", "axios", "xmlhttprequest", "http.request(", "https.request(", "http.get(", "https.get(", "net.connect(", "websocket(",
      "nodemailer")),
    ("network", r"(?i)\bInvoke-(?:WebRequest|RestMethod)\b|\bNet\.WebClient\b", ("invoke-webrequest", "invoke-restmethod", "net.webclient")),
    ("network", r"(?i)\b(?:send|upload|post|submit|forward|transmit|exfiltrate)\b[^\n]{0,80}?https?://", ("http",)),
    ("run", r"\bsubprocess\.|\bos\.(?:system|popen|exec[lv]p?e?|spawn\w{0,3})\(|\bchild_process\b|\bexecSync\(|\bspawnSync\(|\bexecFile(?:Sync)?\("
            r"|\bRuntime\.getRuntime\(\)\.exec|\bProcessBuilder\(|\bStart-Process\b|\bpty\.spawn|\bBun\.spawn|\bDeno\.Command",
     ("subprocess.", "os.system", "os.popen", "os.exec", "os.spawn", "child_process", "execsync(", "spawnsync(", "execfile", "getruntime",
      "processbuilder(", "start-process", "pty.spawn", "bun.spawn", "deno.command")),
    ("run", r"\b(?:ba|z)?sh\s+-c\b", ("sh",)),
    ("install", r"(?i)\b(?:pip3?|uv\s+pip|pipx|npm|pnpm|yarn|brew|cargo|conda|mamba|poetry|composer|winget|choco|scoop|apt-get)\s+(?:install|add|i)\b",
     ("pip", "npm", "pnpm", "yarn", "brew", "cargo", "conda", "mamba", "poetry", "composer", "winget", "choco", "scoop", "apt-get")),
    ("install", r"(?i)\b(?:bun|gem|go|apt|dnf|yum|apk|uv)\s+(?:install|add)\b|\b(?:npx|bunx|uvx|pnpm\s+dlx|pipx\s+run)\s",
     ("install", "add", "npx", "bunx", "uvx", "dlx", "pipx")),
    ("decode", r"\bbase64\s+(?:-d|-D|--decode)\b|\bb64decode\(|\batob\(|Buffer\.from\([^\n)]{0,200}[\"']base64[\"']|\bbytes\.fromhex\(|\bzlib\.decompress\("
               r"|\bcodecs\.decode\(|FromBase64String|\bxxd\s+-r\b|\bmarshal\.loads\(|\bgzip\.decompress\(|\bopenssl\s+(?:enc\s+)?(?:-\w{1,10}\s+){0,4}-d\b",
     ("base64", "b64decode", "atob(", "fromhex", "decompress", "codecs.decode", "xxd", "marshal", "openssl")),
    ("shell-fence", r"(?m)^[ \t]{0,3}(?:```|~~~)[ \t]*(?:bash|sh|shell|zsh|console|terminal|powershell|ps1|cmd)\b|!`[^`\n]{1,200}`", ("```", "~~~", "!`")),
))

_FETCH_TRIGGERS = ("requests.", "httpx.", "session.", "client.", "urlopen", "fetch(", "http.get", "https.get", "http.request", "https.request",
                   "axios", "downloadstring", "invoke-webrequest", "invoke-restmethod", "iwr", "irm", "got(", ".get(", ".post(", ".request(")
_DOWNLOAD_TRIGGERS = ("curl", "wget", "iwr", "invoke-webrequest", "urlretrieve", "chmod")
# Triggers never hold white space: they are looked up in the set of a text's words joined by spaces.
_TRIGGERS = (frozenset(t for p in _PATTERNS for t in p.triggers + p.needs) | frozenset(t for _, _, ts in _SIGNALS for t in ts)
             | frozenset(_FETCH_TRIGGERS) | frozenset(_DOWNLOAD_TRIGGERS))
assert not any(any(c.isspace() for c in t) for t in _TRIGGERS) and all(t.isascii() for t in _TRIGGERS)
_NON_ASCII = re.compile(r"[^\x00-\x7f]+")
LONG_WORDS = 1_000_000  # distinct words longer than this together are checked for triggers letter by letter first
_EXEC = re.compile(r"(?<![\w.])(?:exec|eval)\s*\(|\bnew\s+Function\s*\(|(?<![\w.])Function\s*\(|\bos\.system\s*\(|" + _PIPE + _SH + r"\b"
                   r"|\b(?:ba|z)?sh\s+-c\b|\bInvoke-Expression\b|\biex\b|\bpickle\.loads\(|\bvm\.runIn\w{0,20}Context\(|\beval\s+[\"']?\$")
_CHMOD = re.compile(r"\bchmod\s+(?:-[a-zA-Z]{1,4}\s+){0,3}(?:[ugoa]{0,4}\+[rwX]{0,2}x[rwX]{0,2}|0?[1357][0-7]{2})\s+[\"']?([^\s\"';&|]{1,300})"
                    r"|\bos\.chmod\(\s*[\"']?([^,\"'\n]{1,200})[\"']?\s*,\s*0o?[1357][0-7]{2}")
# Where a download command puts what it fetches. Anchored on curl and scanned to the end of its line, never past another curl
# (as _from_fetch), so options and redirections of other commands are not even matches: the file after -o, or after > or >>
# (standard output; not 2> and not >&), or the name of the address with -O.
_TO_FILE = r"(?<![2>])>{1,2}[ \t]*[\"']?([^\s\"';&|)<>]{1,300})"
_DL_CURL = re.compile(r"\b(?i:curl)\b(?:(?!\b(?i:curl)\b)[^\n]){0," + str(FETCH_BACK) + r"}?(?:\s(?:-[a-zA-Z]{0,6}o|--output)(?:\s+|=)"
                      r"[\"']?([^\s\"';&|)]{1,300})|" + _TO_FILE + r"|(\s(?:-[a-zA-Z]{0,6}O|--remote-name)\b))")
_DL_WGET = re.compile(r"\bwget\b")
_COMMAND_END = re.compile(r"[\n;&|]|\b(?i:curl|wget)\b")  # where a download command ends: what it fetches is judged up to there
_DL_WGET_OUT = re.compile(r"\s(?:-[a-zA-Z]{0,6}O|--output-document)(?:\s*|=)[\"']?([^\s\"';&|)]{1,300})|" + _TO_FILE)
_DL_PS_OUT = re.compile(r"(?i)\s-OutFile\s+[\"']?([^\s\"';&|)]{1,300})")
_DL_RETRIEVE = re.compile(r"\burlretrieve\(\s*[^,\n]{1,500},\s*[fr]?[\"']([^\"'\n]{1,300})")
_DECODE_OUT = re.compile(r"(?i)\bbase64\s+(?:-d|-D|--decode)\b[^\n;&|]{0,200}?(?:>\s*|\s-o\s+|\s--output[ =])[\"']?([^\s\"';&|)]{1,300})")
# a command position: a line start, after ; & | ( ` $( && || then do, or as the first word of a quoted command (sh -c "...")
_COMMAND_AT = r"(?:^|[;&|(`]|\bthen\b|\bdo\b|\bexec\b|(?<=-c)\s*[\"'])[ \t]*"
# Every place a file is run, with its name (group 1, 2 or 3): by a shell or an interpreter, or by its own name at a command
# position. Lookaheads, so runs inside runs count too: sh -c "sh x" runs "sh x" and x.
_RUN_ARG = r"(?:\"(?:\./)?([^\"\n]{1,300})\"|'(?:\./)?([^'\n]{1,300})'|[\"']?(?:\./)?([^\s\"';&|()<>`]{1,300}))"
_RUN_BY_SHELL = re.compile(r"(?m)(?=" + _COMMAND_AT + _NAMED + r"(?:(?:ba|z|da|k)?sh|source|\.|python[0-9.]{0,4}|node|perl|ruby|osascript"
                           r"|pwsh|powershell)(?:\s+-\S+){0,3}\s+" + _RUN_ARG + ")")
_RUN_BY_NAME = re.compile(r"(?m)(?=" + _COMMAND_AT + _RUN_ARG + ")")
_SPAWN = re.compile(r"\bsubprocess\.|\bos\.(?:system|exec\w{0,3})\(|\bspawn\(")
RUN_AFTER = 20_000  # how far after a download or a chmod its file may be run
AHEAD = 64 * 1024  # how far past a window a search for the next match runs, so the next windows are answered without one
NEAR = 4_000  # characters either side of a decode or a fetch where the code that runs it is looked for
# Code fetched from the network and run in the same few lines: exec(requests.get(u).text), https.get + child_process.exec, and
# exec or eval wrapped straight around a get, post or request of any name (an alias: import requests as r; exec(r.get(u).text)).
_FETCH_CODE = re.compile(r"\b(?:requests|httpx|session|client)\.get\s*\(|\burlopen\s*\(|\bfetch\s*\(|\bhttps?\.(?:get|request)\s*\(|\baxios(?:\.get)?\s*\("
                         r"|\.DownloadString\s*\(|(?i:\bInvoke-(?:WebRequest|RestMethod)\b|\b(?:iwr|irm)\b)|\bgot\s*\("
                         r"|(?<![\w.])(?:exec|eval)\s*\(\s*(?:await\s+)?\w{1,40}\.(?:get|post|request)\s*\(")
_RUN_CODE = re.compile(r"(?<![\w.])(?:exec|eval)\s*\(|\bnew\s+Function\s*\(|(?<![\w.])Function\s*\(|\bvm\.runIn\w{0,20}Context\s*\("
                       r"|\.then\s*\(\s*(?:(?:window|globalThis|self)\.)?eval\s*\)"
                       r"|child_process[\"']\s*\)\s*\.\s*exec(?:Sync)?\s*\(|\b(?:cp|child_process|childProcess)\.exec(?:Sync)?\s*\("
                       r"|(?<![\w.])execSync\s*\(|(?i:\bInvoke-Expression\b|(?<![\w-])iex\b)|\bos\.system\s*\("
                       r"|\bsubprocess\.\w{1,20}\([^\n]{0,200}?shell\s*=\s*True")
_B64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{40,}={0,2}")
_B64_PAD = re.compile("=+")
_B64_URL_SAFE = str.maketrans("-_", "+/")
# Consecutive lines of base64 only, as the base64 command wraps them (76 characters): joined before decoding.
_B64_LINES = re.compile(r"(?m)(?:^[ \t]{0,8}[A-Za-z0-9+/]{16,}={0,2}[ \t]{0,8}\r?\n){2,}(?:^[ \t]{0,8}[A-Za-z0-9+/]{4,}={0,2}[ \t]{0,8}$)?")
_NL = re.compile("\n")
_BLANKS = re.compile(r"\n(?:[ \t\r\f\v]*\n)+")
_FENCE = re.compile(r"(?m)^[ \t]{0,3}(?:`{3,}|~{3,})")
_TAG_TEXT = {c: (c - 0xE0000 if 0xE0020 <= c <= 0xE007E else None) for c in range(0xE0000, 0xE0080)}  # tags to the text they hide
_TAGS = re.compile("[\U000e0000-\U000e007f]+")
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
_ZERO_WIDTH = re.compile("[\u00ad\u034f\u180e\u200b-\u200f\u2060-\u2064\ufeff]")
_SELECTORS = re.compile("[\ufe00-\ufe0f\U000e0100-\U000e01ef]+")
_LANGUAGE_RULES = {"prompt-injection": "low", "reviewer-address": "medium", "tool-shadowing": "low", "context-exfiltration": "low"}
# The rules about what runs, fetches, decodes, takes keys or digs into the system: the only ones that look into the readable
# lines of an image, a font or a sound, where a script can hide (see _check_media)
_COMMAND_RULES = frozenset(("pipe-to-shell", "pipe-to-interpreter", "download-execute", "known-ioc", "archive-password", "decode-exec",
                            "secret-store", "credential-file", "env-dump", "many-secret-stores", "secret-exfiltration", "upload-file",
                            "dns-exfil", "reverse-shell", "persistence", "agent-file-write", "defence-evasion", "password-prompt",
                            "preload-injection", "ai-cli-unsafe", "dependency-hijack", "destructive-command"))
assert _COMMAND_RULES <= _BY_ID.keys()
_PROSE_SUFFIXES = frozenset(".md .markdown .mdx .txt .text .rst .adoc .asciidoc .org .html .htm".split())
_PROSE_NAMES = frozenset("readme license licence notice authors changelog copying contributing todo".split())
_SHELL_SUFFIXES = frozenset(".sh .bash .zsh .fish .ksh .command".split())
_PYTHON_SUFFIXES = frozenset(".py .pyw .pyi .pyx".split())
_CODE_SUFFIXES = frozenset(".js .mjs .cjs .jsx .ts .tsx .rb .go .rs .java .kt .php .pl .pm .lua .swift .c .h .cc .cpp .cs .ps1 .psm1 .bat .cmd .vbs "
                           ".applescript .scpt".split())
_CONFIG_SUFFIXES = frozenset(".toml .yaml .yml .ini .cfg .conf .env .plist .xml".split())
_SHEBANG = re.compile(r"#!\s{0,4}\S{0,100}?(?:/|env\s+(?:-S\s+)?)(?:(?:ba|z|da|k|fi)?sh|python[0-9.]{0,4}|node|perl|ruby|osascript)\b")


def _up(severity: str) -> str:
    return SEVERITIES[min(_RANK[severity] + 1, len(SEVERITIES) - 1)]


def _escape(text: str, limit: int) -> str:
    """`text` with every character that is not printable written as \\xNN, \\uNNNN or \\UNNNNNNNN, cut to `limit` characters."""
    out, size = [], 0
    for c in text:
        if c.isprintable():
            piece = c
        else:
            o = ord(c)
            piece = f"\\x{o:02x}" if o < 0x100 else (f"\\u{o:04x}" if o < 0x10000 else f"\\U{o:08x}")
        if size + len(piece) > limit:
            break
        out.append(piece)
        size += len(piece)
    return "".join(out)


# What the normalised view drops: invisible characters (zero width, soft hyphen, joiners, bidi controls, variation selectors, tags)
# and line continuations (a backslash at the end of a line), so `ig<ZWSP>nore` reads as ignore and `curl ... \<newline> | bash` as
# one command. Look-alike letters from other alphabets and fullwidth forms are mapped to plain Latin.
_DROP = re.compile("(?:[\u00ad\u034f\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\ufe00-\ufe0f"
                   "\U000e0000-\U000e007f\U000e0100-\U000e01ef]|\\\\\r?\n)+")
_MIXED = re.compile("[A-Za-z][\u0370-\u03ff\u0400-\u04ff\uff01-\uff5e]|[\u0370-\u03ff\u0400-\u04ff\uff01-\uff5e][A-Za-z]")
_LOOK_ALIKES = str.maketrans({
    **dict(zip("\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0456\u0458\u0455\u0501\u04cf\u043a\u0410\u0412\u0415\u041a\u041c\u041d\u041e\u0420"
               "\u0421\u0422\u0425\u0423\u0406\u0408\u0405", "aeopcyxijsdlkABEKMHOPCTXYIJS")),
    **dict(zip("\u03bf\u03b1\u03b9\u03ba\u03bd\u03c1\u03c5\u03c7\u039f\u0391\u0392\u0395\u0396\u0397\u0399\u039a\u039c\u039d\u03a1\u03a4\u03a5\u03a7",
               "oaikvpuxOABEZHIKMNPTYX")),
    **{chr(c): chr(c - 0xFEE0) for c in range(0xFF01, 0xFF5F)},
})


class _Normal:
    """A text with invisible characters and line continuations dropped and look-alike letters mapped, and the way back to the lines
    of the text it came from."""

    def __init__(self, text: str):
        pieces, self.cuts, self.dropped = [], [], []
        last = total = size = 0
        for m in _DROP.finditer(text):
            pieces.append(text[last:m.start()])
            size += m.start() - last
            total += m.end() - m.start()
            self.cuts.append(size)
            self.dropped.append(total)
            last = m.end()
        pieces.append(text[last:])
        self.text = "".join(pieces).translate(_LOOK_ALIKES)
        self.source_nl = [m.start() for m in _NL.finditer(text)]

    def line_of(self, pos: int) -> int:
        i = bisect.bisect_right(self.cuts, pos)
        source = pos + (self.dropped[i - 1] if i else 0)
        return bisect.bisect_left(self.source_nl, source) + 1

    def source(self, pos: int) -> int:
        """The offset in the text it came from of the character at `pos`."""
        i = bisect.bisect_right(self.cuts, pos)
        return pos + (self.dropped[i - 1] if i else 0)


def _normal(text: str) -> "_Normal | None":
    """The normalised view of a text, or None when nothing in it would change."""
    if text.isascii():
        return _Normal(text) if "\\\n" in text or "\\\r\n" in text else None
    return _Normal(text) if _DROP.search(text) or _MIXED.search(text) else None


class _Result:
    """Findings, capabilities and signals of one file or entry, shared by every text decoded from it."""

    def __init__(self, file: str):
        self.file = file
        self.findings: list[Finding] = []
        self.caps: set[str] = set()
        # first line and evidence of each signal; the evidence is made only for a finding, since masking it reads the whole text
        self.signals: dict[str, tuple[int, Callable[[], str]]] = {}
        self.marked: dict[str, set[int]] = {}  # lines of an injection or of hiding something, to raise those findings only
        self.was_cut = False
        self.mask_left = MASK_MAX  # characters its texts may still be masked against (see _Text.evidence)

    def cut(self, line: int) -> None:
        """A check stopped at one of its caps before the end of the data: the file was not checked in full, so it is never ok. One
        finding per file, at the first place."""
        if not self.was_cut:
            self.was_cut = True
            self.findings.append(Finding(*INCOMPLETE, self.file, line, CUT_EVIDENCE))

    def _hit(self, rule: str, severity: str | None, line: int, evidence: str) -> None:
        r = _BY_ID[rule]
        self.findings.append(Finding(rule, severity or r.severity, r.title, r.why, r.advice, self.file, line, evidence))

    def _raise(self, rule: str, severity: str, lines: set[int] | None = None) -> None:
        self.findings = [Finding(**{**f.__dict__, "severity": severity})
                         if f.rule == rule and _RANK[f.severity] < _RANK[severity] and (lines is None or f.line in lines) else f
                         for f in self.findings]

    def signal(self, name: str, t: "_Text", start: int, end: int) -> None:
        if name not in self.signals:
            self.signals[name] = (t.line_of(start), lambda: t.evidence(start, end))

    def has(self, prefix: str) -> bool:
        return any(name == prefix or name.startswith(prefix + ":") for name in self.signals)

    def report(self) -> FileReport:
        best: dict[tuple[str, int], Finding] = {}
        for f in self.findings:
            key = (f.rule, f.line)
            if key not in best or _RANK[f.severity] > _RANK[best[key].severity]:
                best[key] = f
        per_rule: dict[str, int] = {}
        kept = []
        for f in sorted(best.values(), key=lambda f: (-_RANK[f.severity], f.line, f.rule)):
            per_rule[f.rule] = per_rule.get(f.rule, 0) + 1
            if per_rule[f.rule] <= PER_RULE_MAX:
                kept.append(f)
        caps = set(self.caps)
        for f in kept:
            caps.update(cap for cap, ids in _RULE_CAPS.items() if f.rule in ids)
        for name in self.signals:
            if name.startswith(("secret", "credential")):
                caps.add("reads-secrets")
            elif name in _SIGNAL_CAPS:
                caps.add(_SIGNAL_CAPS[name])
        return FileReport(tuple(sorted(kept, key=lambda f: (f.line, f.rule, -_RANK[f.severity]))), frozenset(caps))


def sensitive_spans(text: str) -> list[tuple[int, int, str]]:
    """Every secret and personal datum of the whole text as (start, end, kind), sorted; IP addresses stay, as in scan.redact. Found
    once over the whole text, so a value is known with its name, however far apart they are and however long the value is."""
    from boxed.detect import DetectConfig, detect

    return sorted((d.start, d.end, d.kind) for d in detect(text, level=1, config=DetectConfig(ner=[]), ner=[]) if d.kind != "IP")


def masked_excerpt(text: str, spans: list[tuple[int, int, str]], ls: int, le: int) -> str:
    """text[ls:le] with every span of `spans` (sensitive_spans of the whole text) that touches it as [KIND]."""
    out, pos = [], ls
    for s, e, kind in spans:
        if e <= pos or s >= le:
            continue
        out += [text[pos:max(s, pos)], f"[{kind}]"]
        pos = min(e, le)
    out.append(text[pos:le])
    return "".join(out)


def masking_spans(res: "_Result", text: str) -> list[tuple[int, int, str]] | None:
    """sensitive_spans of the whole text and of its normalised view taken back to the text, so a value cut by an invisible character
    or named with look-alike letters is masked too; None when the text does not fit in what its file may still be masked against
    (MASK_MAX characters in all), and the evidence is then LEFT_OUT."""
    if len(text) > res.mask_left:
        return None  # before the normalised view is made: a text past the budget costs nothing more
    normal = _normal(text)
    cost = len(text) + (len(normal.text) if normal is not None else 0)
    if cost > res.mask_left:
        return None
    res.mask_left -= cost
    spans = sensitive_spans(text)
    if normal is not None:
        spans += [(normal.source(s), normal.source(e - 1) + 1, kind) for s, e, kind in sensitive_spans(normal.text) if e > s]
    merged: list[tuple[int, int, str]] = []
    for s, e, kind in sorted(spans):
        if merged and s < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e), merged[-1][2])
        else:
            merged.append((s, e, kind))
    return merged


class _Text:
    """One text under check: the file itself, or text decoded from it. Decoded text reports the line of what it was decoded from
    and labels its evidence, so a reader sees it was hidden."""

    def __init__(self, res: _Result, text: str, kind: str, rel: str, *, label: str = "", line: int = 0, depth: int = 0,
                 shown: str | None = None, origin: "_Normal | None" = None):
        self.res, self.text, self.kind, self.rel = res, text, kind, rel
        self.label, self.base, self.depth = label, line, depth
        self.shown = text if shown is None else shown  # what evidence is cut from: the text, or the same length with values starred
        self.origin = origin  # a normalised view reports the lines of the text it was made from
        self.nl = [m.start() for m in _NL.finditer(text)]
        self.fences: list[int] = []  # offsets of fence lines; a position after an odd number of them is inside a fenced block
        self.comments: list[tuple[int, int]] = []
        self.decodes: list[int] = []  # where decodes are, for the decode-then-run window
        self.chmods: dict[str, list[int]] | None = None  # found once, when asked (see _chmods)
        self.spans: list[tuple[int, int, str]] | None = None  # the sensitive spans of `shown` (see evidence); found once, when asked
        self.too_large = False  # `shown` did not fit in what the file may still be masked against: no excerpt

    def line_of(self, pos: int) -> int:
        if self.origin is not None:
            return self.origin.line_of(pos)
        return self.base or bisect.bisect_left(self.nl, pos) + 1

    def span_of(self, pos: int) -> tuple[int, int]:
        i = bisect.bisect_left(self.nl, pos)
        return (self.nl[i - 1] + 1 if i else 0), (self.nl[i] if i < len(self.nl) else len(self.text))

    def evidence(self, start: int, end: int) -> str:
        """The line holding text[start:end], or the part of it around the match when the line is long, escaped and cut to 160. Secrets
        and personal data are replaced by [KIND] before the cut, found once in the whole text and not in the excerpt: a cut that parts
        a value from its name, a value longer than any window, or a value that spans lines would leave a piece no detector knows.
        Past MASK_MAX characters of the file the evidence is LEFT_OUT: no excerpt is shown that was not masked by the whole text."""
        if self.spans is None and not self.too_large:
            self.spans = masking_spans(self.res, self.shown)
            self.too_large = self.spans is None
        if self.spans is None:
            return self.label + LEFT_OUT
        ls, le = self.span_of(start)
        budget = EVIDENCE_MAX - len(self.label)
        if le - ls > budget:
            ls = max(ls, start - 40)
            le = min(le, ls + budget)
        return self.label + _escape(masked_excerpt(self.shown, self.spans, ls, le).strip(), budget)

    def _hit(self, rule: str, severity: str | None, start: int, end: int) -> None:
        severity = severity or _BY_ID[rule].severity
        if self.depth and rule != "encoded-text" and severity in ("medium", "high"):
            severity = _up(severity)  # what was hidden by encoding weighs one level more
        self.res._hit(rule, severity, self.line_of(start), self.evidence(start, end))

    def cut(self, pos: int) -> None:
        self.res.cut(self.line_of(pos))

    def fenced(self, pos: int) -> bool:
        if not self.fences:
            return False
        return bisect.bisect_right(self.fences, pos) % 2 == 1 and not any(s <= pos < e for s, e in self.comments)


def _kind(rel: str, text: str) -> str:
    p = PurePosixPath(rel.replace("\\", "/"))
    suffix, name = p.suffix.lower(), p.name.lower()
    first = text[:200].split("\n", 1)[0]
    if suffix in _PROSE_SUFFIXES or (not suffix and name in _PROSE_NAMES):
        return "prose"
    if suffix in _SHELL_SUFFIXES:
        return "shell"
    if suffix in _PYTHON_SUFFIXES:
        return "python"
    if suffix in (".json", ".jsonc"):
        return "json"
    if suffix in _CODE_SUFFIXES:
        return "code"
    if suffix in _CONFIG_SUFFIXES:
        return "config"
    shebang = _SHEBANG.match(first)
    if shebang:
        return "python" if "python" in shebang.group() else ("shell" if re.search(r"(?:ba|z|da|k|fi)?sh\b", shebang.group()) else "code")
    return "other"


class _Places:
    """Where a pattern has to run. A short text is searched whole. In a long one a pattern runs only in windows around its
    trigger words (every pattern is bounded, so no match reaches further than WINDOW from its trigger), unless the triggers are
    so frequent that the windows would cover much of the text anyway."""

    def __init__(self, text: str):
        self.text = text
        self.low = text.lower()
        self.windowed = len(text) >= WINDOWED_FROM and len(self.low) == len(text)  # lowering may change the length: then search whole
        words = " ".join(set(self.low.split())) if len(text) > 4096 else self.low  # a long text repeats its words: look in each once
        if len(words) > LONG_WORDS:  # huge words (a blob, padding): triggers are ASCII, and one with a letter the text lacks is absent
            words = words if words.isascii() else _NON_ASCII.sub("", words)
            letters = set(words)
            self.present = {w for w in _TRIGGERS if letters.issuperset(w) and w in words}
        else:
            self.present = {w for w in _TRIGGERS if w in words}
        self.counts: dict[str, int] = {}

    def matches(self, regex: re.Pattern, triggers: tuple[str, ...]) -> Iterator[re.Match]:
        spans = self._spans(triggers) if self.windowed and triggers else None
        if spans is None:
            yield from regex.finditer(self.text)
            return
        for start, end in spans:
            yield from regex.finditer(self.text, start, end)

    def _spans(self, triggers: tuple[str, ...]) -> list[tuple[int, int]] | None:
        low, size = self.low, len(self.low)
        present = [t for t in triggers if t in self.present]
        total = 0
        for t in present:
            if t not in self.counts:
                self.counts[t] = low.count(t)
            total += self.counts[t]
        if total * 2 * WINDOW > size // 2:
            return None
        spans = []
        for t in present:
            i = low.find(t)
            while i != -1:
                start = low.rfind("\n", max(0, i - LONG_LINE), i)
                end = low.find("\n", i, i + LONG_LINE)
                # the whole line and some context when the line is short, so padding inside a line cannot push a match out of
                # the window; a longer line is reported as long-line and searched WINDOW around the trigger
                start = max(0, start - WINDOW) if start != -1 or i < LONG_LINE else i - WINDOW
                if end != -1:
                    end = min(size, end + WINDOW)
                else:
                    end = size if i + LONG_LINE >= size else min(size, i + len(t) + WINDOW)
                after = low.find("\n", end, end + WINDOW)
                end = after if after != -1 else end  # end on a line end, where $ really matches
                spans.append((max(0, start), end))
                i = low.find(t, i + 1)
        spans.sort()
        merged: list[tuple[int, int]] = []
        for start, end in spans:
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        return merged


def _scan(t: _Text, rules: frozenset[str] | None = None) -> None:
    """Every pattern, signal, decoder and character check over one text; with `rules`, the patterns of those rules and the
    checks of what is run only, no character, encoding or structure check."""
    text, res = t.text, t.res
    places = _Places(text)
    low, present = places.low, places.present
    name = PurePosixPath(t.rel.replace("\\", "/")).name.lower()
    if t.kind == "prose" and not t.depth:
        t.fences = [m.start() for m in _FENCE.finditer(text)]
        t.comments = list(_comments(text))
    for p in _PATTERNS:
        if ((rules is not None and p.rule not in rules) or (p.kinds and t.kind not in p.kinds) or (p.names and name not in p.names)
                or (p.triggers and present.isdisjoint(p.triggers)) or (p.needs and present.isdisjoint(p.needs))):
            continue
        hits, worst = 0, -1
        for count, m in enumerate(places.matches(p.regex, p.triggers)):
            if count >= SCAN_MAX:  # the check itself stops here, not only what is shown of it
                t.cut(m.start())
                break
            judged = p.judge(t, m) if p.judge else None
            if judged == "drop":
                continue
            severity, at = judged if isinstance(judged, tuple) else (judged, m.start())
            severity = severity or p.severity
            signal = p.signal
            if p.rule in _LANGUAGE_RULES and t.fenced(m.start()):
                severity, signal = _LANGUAGE_RULES[p.rule], None  # a quoted example in prose, as security docs have
            elif p.rule == "prompt-injection" and (severity or "high") == "high":
                if t.kind == "prose" and m.start() and text[m.start() - 1] in "\"'`\u201c\u2018\u00ab":
                    severity, signal = "medium", None  # quoted inline, as a guide that warns about it does; still not clean
                else:
                    signal = "injection"
            rank = _RANK[severity or _BY_ID[p.rule].severity]
            if hits >= MATCHES_MAX and rank <= worst:
                continue  # enough of these are shown; the rest is still judged, so a worse one later is not missed
            hits, worst = hits + 1, max(worst, rank)
            t._hit(p.rule, severity, at, m.end())
            if signal in ("injection", "concealment"):
                res.marked.setdefault(signal, set()).add(t.line_of(at))
            if signal:
                res.signal(signal, t, at, m.end())
    for sig, regex, triggers in _SIGNALS:
        if triggers and present.isdisjoint(triggers):
            continue
        for count, m in enumerate(places.matches(regex, triggers)):
            if count >= (SCAN_MAX if sig == "decode" else MATCHES_MAX):  # every decode is a candidate for decode-then-run
                if sig == "decode":
                    t.cut(m.start())  # the decodes past it are not weighed against what runs them
                break  # any other signal: all those met were shell fences outside prose, which say nothing
            sig_name = ("run" if t.kind == "prose" else None) if sig == "shell-fence" else sig
            if not sig_name:
                continue
            res.signal(sig_name, t, m.start(), m.end())
            if sig_name == "decode":
                t.decodes.append(m.start())
            else:
                break  # only whether it happens matters, and where first
    if t.kind == "shell":
        res.caps.add("runs-commands")
    _decode_exec(t, places)
    _download_execute(t, places)
    _fetch_exec(t, places)
    # the normalised view repeats the patterns only, characters, encodings and structure were checked on the text itself; the
    # readable lines of binary content get no such check
    if t.origin is not None or rules is not None:
        return
    if t.depth < DECODE_DEPTH:
        _base64(t)
    if not text.isascii():
        _unicode(t)
    if "\x1b" in text:
        for count, m in enumerate(re.finditer("\x1b", text)):
            if count >= MATCHES_MAX:
                break
            t._hit("ansi-escape", "medium" if t.kind in ("shell", "python", "code") else None, m.start(), m.end())


def _scan_all(t: _Text, masker: Callable[[str], str] | None = None, rules: frozenset[str] | None = None) -> None:
    """The text, then its normalised view when it has invisible characters, look-alike letters or line continuations: one hidden
    character inside a keyword must not hide it. A finding from the view is labelled and reported on the line of the text;
    `masker` stars values in the view's evidence as it does in the text's; `rules` limits both scans (see _scan)."""
    _scan(t, rules)
    normal = _normal(t.text)
    if normal is not None:
        view = _Text(t.res, normal.text, t.kind, t.rel, label=t.label + "[normalised] ", origin=normal,
                     shown=masker(normal.text) if masker else None)
        _scan(view, rules)


def _comments(text: str) -> Iterator[tuple[int, int]]:
    """HTML comments, found with plain searches (linear on any input): text hidden in them is never a quoted example."""
    pos = text.find("<!--")
    while pos != -1:
        end = text.find("-->", pos + 4)
        if end == -1:
            yield pos, len(text)
            return
        yield pos, end + 3
        pos = text.find("<!--", end + 3)


def _line_span(t: _Text, line: int) -> tuple[int, int]:
    nl = t.nl
    return (nl[line - 2] + 1 if line > 1 else 0), (nl[line - 1] if line - 1 < len(nl) else len(t.text))


def _run_index(t: _Text, regex: re.Pattern, starts: list[int]) -> dict[str, list[int]]:
    """Each file `regex` (_RUN_BY_SHELL or _RUN_BY_NAME) finds run within RUN_AFTER after one of `starts` (in order) -> where, in
    order. Each part of the text is searched once however many windows overlap it, and nothing outside them, so checking
    thousands of downloads costs a lookup each."""
    text = t.text
    spans: list[tuple[int, int]] = []
    for s in starts:
        if spans and s <= spans[-1][1]:
            spans[-1] = (spans[-1][0], min(len(text), max(spans[-1][1], s + RUN_AFTER)))
        else:
            spans.append((s, min(len(text), s + RUN_AFTER)))
    found: dict[str, list[int]] = {}
    for lo, hi in spans:
        for m in regex.finditer(text, lo, min(len(text), hi + WINDOW)):  # a run that starts in the window may end after it
            if m.start() >= hi:
                break
            found.setdefault(m.group(1) or m.group(2) or m.group(3), []).append(m.start())
    return found


def _ran(found: dict[str, list[int]], start: int, target: str) -> bool:
    """Whether the file `target` is run within RUN_AFTER after `start`, by a run index (see _run_index); "-" is standard output."""
    plain = _plain(target)
    at = found.get(plain, []) if plain != "-" else []
    i = bisect.bisect_left(at, start)
    return i < len(at) and at[i] < start + RUN_AFTER


class _After:
    """Whether a pattern matches in windows that move down a text (start and end never decrease): each part of the text is searched
    once however many windows overlap it, and never more than AHEAD past the window asked about."""

    def __init__(self, regex: re.Pattern, text: str):
        self.regex, self.text = regex, text
        self.searched = 0  # no match starts from where the last search began up to here
        self.at = -1  # the match the last search found first, -1 when none

    def within(self, start: int, end: int) -> bool:
        """Whether a match starts in [start, end)."""
        if start <= self.at:
            return self.at < end
        lo = max(start, self.searched)
        if lo < end:
            upto = min(len(self.text), max(end, lo + AHEAD))
            m = self.regex.search(self.text, lo, min(len(self.text), upto + WINDOW))  # a match that starts before upto ends in time
            if m is not None and m.start() < upto:
                self.at = self.searched = m.start()
                return m.start() < end
            self.searched = upto
        self.at = -1
        return False


def _near(t: _Text, pos: int) -> tuple[int, int]:
    """EXEC_WINDOW lines around `pos`, and never more than NEAR characters either side, so one huge line costs no more than a
    short one."""
    line = bisect.bisect_left(t.nl, pos) + 1
    start = _line_span(t, max(1, line - EXEC_WINDOW))[0]
    end = _line_span(t, min(len(t.nl) + 1, line + EXEC_WINDOW))[1]
    return max(start, pos - NEAR), min(end, pos + NEAR)


def _line_near(t: _Text, pos: int) -> tuple[int, int]:
    start, end = t.span_of(pos)
    return max(start, pos - NEAR), min(end, pos + NEAR)


def _by_line(t: _Text, positions: list[int]) -> list[int]:
    """The first of `positions` in each line, in order."""
    seen: dict[int, int] = {}
    for pos in positions:
        seen.setdefault(bisect.bisect_left(t.nl, pos), pos)
    return sorted(seen.values())


def _decode_exec(t: _Text, places: "_Places") -> None:
    """A decode within EXEC_WINDOW lines of a call that runs code, or a decoded file that is then run (by a shell or an interpreter,
    or by its own name once made executable): decode and execute."""
    runs = _After(_EXEC, t.text)
    outs: list[tuple[int, int, str]] = []  # (the decode, where the file it writes is named, that file)
    for pos in _by_line(t, t.decodes):
        start, end = _near(t, pos)
        if runs.within(start, end):
            t._hit("decode-exec", None, pos, pos + 1)
            return
        out = _DECODE_OUT.search(t.text, *_line_near(t, pos))
        if out:
            outs.append((pos, out.end(), _plain(out.group(1))))
    shell = _run_index(t, _RUN_BY_SHELL, [end for _, end, _ in outs])
    made: list[tuple[int, int, str]] = []  # (the first chmod of the decoded file after it, the decode, that file)
    for pos, end, name in outs:
        if _ran(shell, end, name):
            t._hit("decode-exec", None, pos, pos + 1)
            return
        ends = _chmods(t, places).get(name, [])
        i = bisect.bisect_right(ends, end)
        if i < len(ends) and ends[i] - end < RUN_AFTER:
            made.append((ends[i], pos, name))
    made.sort()
    by_name = _run_index(t, _RUN_BY_NAME, [chmod for chmod, _, _ in made])
    for chmod, pos, name in made:
        if _ran(by_name, chmod, name):
            t._hit("decode-exec", None, pos, pos + 1)
            return


def _plain(name: str) -> str:
    """A file name as a command writes it, without quotes and a leading ./"""
    name = name.strip("\"'")
    return name[2:] if name.startswith("./") else name


def _chmods(t: _Text, places: "_Places") -> dict[str, list[int]]:
    """Each file made executable (chmod +x or 755, os.chmod) -> where each such chmod ends, in order; at most SCAN_MAX chmods,
    found once per text."""
    if t.chmods is None:
        t.chmods = {}
        if "chmod" in places.present:
            for count, m in enumerate(places.matches(_CHMOD, ("chmod",))):
                if count >= SCAN_MAX:
                    t.cut(m.start())
                    break
                t.chmods.setdefault(_plain(m.group(1) or m.group(2) or ""), []).append(m.end())
    return t.chmods


def _command_before(t: _Text, pos: int, word: str) -> int | None:
    """Where `word` (a command name) last starts before `pos` in the same line, within FETCH_BACK."""
    line_start, _ = t.span_of(pos)
    lo = max(line_start, pos - FETCH_BACK)
    found = None
    for m in re.finditer(r"(?i)\b" + word + r"\b", t.text[lo:pos]):
        found = lo + m.start()
    return found


def _downloads(t: _Text, places: "_Places") -> Iterator[tuple[int, str]]:
    """(where the command starts, the file it writes) of every download to a file whose addresses are not all well-known
    installers or registries. curl is the anchor of its own pattern; for PowerShell the command is looked for before -OutFile.
    What a command fetches is judged on the command itself, up to the next command."""
    text = t.text
    installers: dict[str, bool] = {}  # a command written many times is judged once

    def judged(at: int, target: str, end: int) -> Iterator[tuple[int, str]]:
        segment = text[at:end]
        if segment not in installers:
            urls = _urls(segment)
            installers[segment] = bool(urls and all(_installer(h, u) or _in(h, _REGISTRIES) for h, u in urls)
                                       and not _BARE_ADDRESS.search(_URL.sub(" ", segment)))
        if not installers[segment]:
            yield at, target

    def url_name(at: int, end: int) -> str:
        urls = _urls(text[at:end])
        return urls[0][1].split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1] if urls else ""

    examined = 0
    for regex, triggers in ((_DL_CURL, ("curl",)), (_DL_WGET, ("wget",)), (_DL_PS_OUT, ("iwr", "invoke-webrequest")),
                            (_DL_RETRIEVE, ("urlretrieve",))):
        if places.present.isdisjoint(triggers):
            continue
        for m in places.matches(regex, triggers):
            examined += 1
            if examined > SCAN_MAX:
                t.cut(m.start())
                return
            at = m.start() if regex is not _DL_PS_OUT else _command_before(t, m.start(), "(?:iwr|invoke-webrequest)")
            if at is None:
                continue
            line_end = _line_near(t, m.start())[1]
            stop = _COMMAND_END.search(text, max(at + 4, m.end() if regex is _DL_CURL else at), line_end)
            end = stop.start() if stop else line_end
            if regex is _DL_WGET:  # the file after -O or >, else the name of the address ("-" is standard output)
                outs = (o.group(1) or o.group(2) for o in _DL_WGET_OUT.finditer(text, m.end(), end))
                yield from judged(at, next((o for o in outs if o != "-"), None) or url_name(at, end), end)
            elif regex is _DL_CURL:
                yield from judged(at, m.group(1) or m.group(2) or url_name(at, end), end)
            else:
                yield from judged(at, m.group(1), end)


def _download_execute(t: _Text, places: "_Places") -> None:
    """A download to a file that is then run: by a shell or an interpreter (curl -o x && sh x), or after chmod +x by its own name.
    This is how fake prerequisites install stealers. Downloads from well-known installer hosts (rustup, brew) do not count. Every
    download (to SCAN_MAX) and every chmod is checked, so decoys before the real one hide nothing; the hit is the download that
    is run, or for a chmod the latest download of that file (else any) before it."""
    downloads = sorted(_downloads(t, places))
    if not downloads:
        return
    chmods = sorted((end, name) for name, ends in _chmods(t, places).items() for end in ends if end > downloads[0][0])
    shell = _run_index(t, _RUN_BY_SHELL, sorted([at for at, _ in downloads] + [end for end, _ in chmods]))
    hit = next((at for at, target in downloads if _ran(shell, at, target)), None)
    if hit is None and chmods:
        by_name = _run_index(t, _RUN_BY_NAME, [end for end, _ in chmods])
        spawn = _After(_SPAWN, t.text)
        for end, name in chmods:
            if _ran(shell, end, name) or _ran(by_name, end, name) or spawn.within(end, end + RUN_AFTER):
                before = [at for at, _ in downloads if at < end]
                hit = next((at for at, target in reversed(downloads) if at < end and _plain(target) == name), before[-1])
                break
    if hit is not None:
        t._hit("download-execute", None, hit, hit + 1)
        t.res.signal("network", t, hit, hit + 1)


def _fetch_exec(t: _Text, places: "_Places") -> None:
    """Code fetched from the network and run within EXEC_WINDOW lines: exec(requests.get(url).text), https.get + child_process.exec,
    iex (iwr url). Every fetching line (to SCAN_MAX) is checked; the hit is the fetch nearest before the code that runs, weighed
    by the addresses on its line."""
    if places.present.isdisjoint(_FETCH_TRIGGERS):
        return
    found = [m.start() for m in itertools.islice(places.matches(_FETCH_CODE, _FETCH_TRIGGERS), SCAN_MAX + 1)]
    if len(found) > SCAN_MAX:
        t.cut(found.pop())
    fetches = _by_line(t, found)
    runs = _After(_RUN_CODE, t.text)
    for pos in fetches:
        start, end = _near(t, pos)
        if runs.within(start, end):
            pos = max(pos, fetches[max(0, bisect.bisect_right(fetches, runs.at) - 1)])
            ls, le = _line_near(t, pos)
            t._hit("pipe-to-interpreter", _fetch_severity(t.text[ls:le]), pos, pos + 1)
            t.res.signal("run", t, pos, pos + 1)
            return


_MAGIC_BINARY = ((b"\x7fELF", "ELF program"), (b"\xfe\xed\xfa\xce", "Mach-O program"), (b"\xfe\xed\xfa\xcf", "Mach-O program"),
                 (b"\xce\xfa\xed\xfe", "Mach-O program"), (b"\xcf\xfa\xed\xfe", "Mach-O program"), (b"\xca\xfe\xba\xbe", "Mach-O universal program"),
                 (b"\xbe\xba\xfe\xca", "Mach-O universal program"), (b"\x00asm", "WebAssembly module"))
_MAGIC_ARCHIVE = ((b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"), (b"PK\x07\x08", "zip"), (b"\x1f\x8b", "gzip"), (b"7z\xbc\xaf\x27\x1c", "7z"),
                  (b"Rar!\x1a\x07", "rar"), (b"\xfd7zXZ\x00", "xz"), (b"BZh", "bzip2"), (b"\x28\xb5\x2f\xfd", "zstd"), (b"MSCF", "cab"))
_MAGIC_MEDIA = (b"\x89PNG", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"wOFF", b"wOF2", b"OTTO", b"\x00\x01\x00\x00\x00", b"ID3", b"fLaC",
                b"OggS", b"\x00\x00\x01\x00")


def _after_media_signature(head: bytes) -> bytes | None:
    """The bytes after an image, font or sound signature at the start of `head` (all of it for RIFF and ftyp, whose fixed bytes
    are text), None without one."""
    for magic in _MAGIC_MEDIA:
        if head.startswith(magic):
            return head[len(magic):]
    if (head[:4] == b"RIFF" and head[8:12] in (b"WEBP", b"WAVE", b"AVI ")) or head[4:8] == b"ftyp":
        return head
    return None


def _magic(head: bytes, name: str) -> tuple[str, str] | None:
    """(rule, label) for content that is not text by its first bytes, None for text."""
    for magic, label in _MAGIC_BINARY:
        if head.startswith(magic):
            return "binary-file", label
    if head.startswith(b"MZ") and len(head) >= 64:
        offset = int.from_bytes(head[60:64], "little")
        if head[offset:offset + 4] == b"PE\0\0" or name.endswith((".exe", ".dll", ".sys", ".scr")):
            return "binary-file", "Windows program"
    for magic, label in _MAGIC_ARCHIVE:
        if head.startswith(magic):
            return "archive", label
    if head[257:262] == b"ustar":
        return "archive", "tar"
    if name.endswith((".pyc", ".pyo")):
        return "bytecode", "compiled Python"
    # Media only when binary: every real image, font and sound has NUL bytes right after its signature (header fields), while a
    # script may start like one (GIF89a=1 is a valid shell line) and is text
    after = _after_media_signature(head)
    if after is not None and b"\x00" in after:
        return "", "media"
    if head.startswith(b"%PDF"):
        return "opaque-file", "PDF document"
    if name.endswith((".exe", ".dll", ".so", ".dylib", ".node", ".sys")):
        return "binary-file", "program by its name"
    return None


def _unreadable(rel: str, why: str) -> FileReport:
    res = _Result(rel)
    res._hit("unreadable", None, 0, why)
    return res.report()


READABLE_MIN = 6  # printable characters in a row that make a line of binary content readable, as `strings` takes a fragment
_READABLE = re.compile(rb"[\t\x20-\x7e]{%d,}" % READABLE_MIN)
_UNPRINTABLE = bytes(c for c in range(256) if c not in (9, 10) and not 0x20 <= c <= 0x7e)


def _readable_text(data: bytes) -> str:
    """The readable lines of binary content as a shell meets them. NUL bytes are dropped (bash and dash skip them). A line with a
    fragment of READABLE_MIN printable characters or more is kept whole with its other bytes dropped, so its short pieces stay
    glued to their neighbours (curl -s URL -A<byte>|sh reads curl -s URL -A|sh); a line without one stays empty. A backslash
    before a line break continues the line, as in a shell. Line breaks are kept up to the last readable line, so a line of this
    text is the line of the file. Linear in the size of `data`."""
    data = data.replace(b"\x00", b"")
    pieces: list[str] = []
    last = 0  # where the last readable line ends
    for m in _READABLE.finditer(data):
        if m.start() < last:
            continue  # in a line already taken
        start = data.rfind(b"\n", last, m.start())
        while start > last and data[start - 1] == 0x5C:  # a continued line starts further back
            start = data.rfind(b"\n", last, start)
        end = data.find(b"\n", m.end())
        while end > 0 and data[end - 1] == 0x5C:
            end = data.find(b"\n", end + 1)
        start, end = start + 1, len(data) if end == -1 else end
        pieces.append("\n" * data.count(b"\n", last, start))
        pieces.append(data[start:end].translate(None, _UNPRINTABLE).decode("ascii"))
        last = end
    return "".join(pieces)


def _check_media(data: bytes, rel: str, executable: bool) -> FileReport:
    """An image, a font or a sound. Nothing in it runs, unless a script stands between its binary parts: a shell drops NUL bytes
    and goes past lines it cannot run, so GIF89a=1, then a command, then binary data runs the command. Its readable lines are
    checked by the rules about running, fetching, decoding and taking keys only, and a file marked executable is a low sign
    besides (real images often carry the bit). Capabilities come from findings only, not from stray words in binary data."""
    res = _Result(rel)
    if executable:
        res._hit("opaque-file", "low", 0, "media file marked executable")
    text = _readable_text(data)
    if text:
        _scan_all(_Text(res, text, "other", rel, label="[text in media] "), rules=_COMMAND_RULES)
        _combine(res)
        res.signals.clear()
    return res.report()


def check_file(path: Path, rel: str) -> FileReport:
    """The findings and capabilities of one file of an item. The file is opened without following a link and must be a regular
    file; text is read whole, programs, archives, bytecode and other opaque data are findings by their first bytes. An image, a
    font or a sound (binary after its signature) is read whole too, for the commands in its readable lines."""
    try:
        fd = platform.open_nofollow(path, os.O_RDONLY)
    except OSError:
        return _unreadable(rel, "cannot be opened (missing, a link, or no access)")
    try:
        mode = os.fstat(fd).st_mode
    except OSError:
        mode = 0
    if not stat.S_ISREG(mode):
        os.close(fd)
        return _unreadable(rel, "not a regular file")
    with os.fdopen(fd, "rb") as f:
        try:
            head = f.read(HEAD)
            name = PurePosixPath(rel.replace("\\", "/")).name.lower()
            kind = _magic(head, name)
            if kind is not None and kind[0]:
                return _opaque(f, path, rel, head, name, *kind)
            data = head + f.read()
        except OSError:
            return _unreadable(rel, "read failed")
    if kind is not None:  # an image, a font or a sound
        return _check_media(data, rel, bool(mode & 0o111))
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return check_text(data.decode("utf-16", errors="replace"), rel)
    if b"\x00" in head and _after_media_signature(head) is None:  # NUL bytes only inside a font or icon signature: text after it
        res = _Result(rel)
        res._hit("opaque-file", None, 0, "binary data")
        return res.report()
    return check_text(data.decode("utf-8", errors="replace"), rel)


def _opaque(f, path: Path, rel: str, head: bytes, name: str, rule: str, label: str) -> FileReport:
    res = _Result(rel)
    if rule == "bytecode":
        stem = name.split(".", 1)[0]
        source = path.parent.parent / f"{stem}.py" if path.parent.name == "__pycache__" else path.with_suffix(".py")
        try:
            os.lstat(source)
            res._hit("bytecode", None, 0, label)
        except OSError:
            res._hit("bytecode", "critical", 0, "compiled Python without its source")
        return res.report()
    if label == "zip":
        encrypted, office = _zip_facts(f, head, name)
        if encrypted:
            res._hit("encrypted-archive", None, 0, "encrypted zip")
        res._hit("archive", None, 0, "Office document (zip)" if office else "zip archive")
        return res.report()
    res._hit(rule, None, 0, f"{label} archive" if rule == "archive" else label)
    return res.report()


def _zip_facts(f, head: bytes, name: str) -> tuple[bool, bool]:
    """(encrypted, Office document) from the central directory; nothing is extracted. A zip the module cannot parse falls back to
    the flag of its first local header."""
    office = name.endswith((".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".odt", ".ods", ".odp"))
    try:
        f.seek(0)
        with zipfile.ZipFile(f) as z:
            infos = z.infolist()
        encrypted = any(i.flag_bits & 1 for i in infos)
        office = office or any(i.filename in ("[Content_Types].xml", "mimetype") for i in infos)
    except Exception:  # a hostile archive may break the parser in any way; the header flag still answers
        encrypted = head.startswith(b"PK\x03\x04") and len(head) > 6 and bool(head[6] & 1)
    return encrypted, office


def check_text(text: str, rel: str) -> FileReport:
    """The findings and capabilities of a text; its kind comes from `rel` and its first line."""
    res = _Result(rel)
    kind = _kind(rel, text)
    t = _Text(res, text, kind, rel)
    _scan_all(t)
    _structure(t)
    if kind == "json":
        _json_config(res, text, rel)
    _combine(res)
    return res.report()


def _structure(t: _Text) -> None:
    """Padding, long lines, a huge SKILL.md, the frontmatter, hooks in JSON: checks of the file as a whole."""
    text = t.text
    for m in _BLANKS.finditer(text):
        if m.group().count("\n") - 1 >= BLANK_RUN:
            after = m.end()
            if after < len(text):
                t._hit("padding", None, after, after + 1)
            else:
                t.res._hit("padding", None, t.line_of(m.start()), "blank lines at the end")
    starts = [0] + [n + 1 for n in t.nl]
    ends = t.nl + [len(text)]
    for count, (s, e) in enumerate(((s, e) for s, e in zip(starts, ends) if e - s > LONG_LINE)):
        if count >= PER_RULE_MAX:
            break
        t._hit("long-line", "medium" if t.kind in ("prose", "other", "config") else "low", s, s + 1)
    name = PurePosixPath(t.rel.replace("\\", "/")).name
    if name == "SKILL.md" and len(text) > LARGE_SKILL // 4 and len(text.encode("utf-8", "replace")) > LARGE_SKILL:
        t.res._hit("large-instructions", None, 0, "")
    if t.kind == "prose" and text.lstrip("\ufeff").startswith("---"):
        _frontmatter(t)
    if t.kind == "json" and '"hooks"' in text:
        t.res.caps.add("event-hooks")


_KNOWN_NAMES = ("clawhub", "openclaw", "claude-code", "skill-creator", "mcp-builder", "frontend-design", "webapp-testing", "brand-guidelines",
                "canvas-design", "algorithmic-art", "internal-comms", "theme-factory", "doc-coauthoring", "polymarket", "superpowers", "context7",
                "playwright")
_IOC_NAMES = ("clawhud", "clawhub1", "polymarket-traiding-bot", "bybit-agent", "moltbook-lm8")
_MISSPELLED = re.compile(r"traiding|reciever|offical|offcial|anthropc|antropic|claud-code|openal\b")
_SUFFIX = re.compile(r"-(?=[a-z0-9]{0,2}\d)(?=[0-9]{0,2}[a-z])[a-z0-9]{3}$")


def _frontmatter(t: _Text) -> None:
    text = t.text
    start = text.find("---")
    end = text.find("\n---", start + 3)
    if end == -1:
        return
    fm = text[start:end]
    m = re.search(r"(?m)^name:[ \t]*[\"']?([^\"'\n]{1,200})", fm)
    if m:
        name = m.group(1).strip()
        pos = start + m.start(1)
        low = name.lower()
        latin = any("a" <= c.lower() <= "z" for c in name)
        other = any(c.isalpha() and unicodedata.name(c, "").startswith(("CYRILLIC", "GREEK", "ARMENIAN")) for c in name)
        if latin and other:
            t._hit("mixed-script", None, pos, pos + len(name))
        if low in _IOC_NAMES:
            t._hit("known-ioc", None, pos, pos + len(name))
        elif (any(0 < _distance(low, k) <= 2 for k in _KNOWN_NAMES if len(k) >= 6) or _MISSPELLED.search(low) or _SUFFIX.search(low)):
            t._hit("name-impersonation", None, pos, pos + len(name))
        elif re.search(r"\b(?:official|anthropic|openai)\b", low):
            t._hit("name-impersonation", "low", pos, pos + len(name))
    tools = re.search(r"(?m)^allowed-tools:[ \t]*(.{0,500})((?:\n[ \t]+-[^\n]{0,200}){0,50})", fm)
    if tools:
        words = re.split(r"[,\s\[\]\"'-]+", tools.group(1) + " " + tools.group(2))
        if any(w in ("Bash", "Bash(*)", "Bash(*:*)") for w in words):
            pos = start + tools.start()
            t._hit("unrestricted-bash", None, pos, pos + 1)


def _distance(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2 or len(a) > 64:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_CONTROL_BYTES = bytes(c for c in range(32) if c not in (9, 10, 13)) + b"\x7f"


def _printable_text(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < 16:
        return None
    if len(data) - len(data.translate(None, _CONTROL_BYTES)) > 0.1 * len(text):
        return None  # control bytes are characters that are not printable: counted fast, the same answer as below
    good = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    return text if good >= 0.9 * len(text) and any(c.isalpha() for c in text) else None


def _base64(t: _Text) -> None:
    """Every base64 run of 40 characters or more is decoded, and so is a block of base64 lines joined (the base64 command wraps
    at 76 characters, which would cut a payload between the pieces). Text that comes out is checked again (to DECODE_DEPTH
    levels), a program that comes out is a finding. Images, keys and hashes decode to bytes that are not text and are left alone."""
    blocks: list[tuple[int, int]] = []
    count = 0
    for m in _B64_LINES.finditer(t.text):
        joined = re.sub(r"\s+", "", m.group())
        pieces = _b64_pieces(joined)
        count += max(len(pieces), 1)  # each piece of a block cut by padding is a run of its own
        if count > DECODE_MAX:
            t.cut(m.start())
            break
        if len(joined) >= 40 and _decode_blob(t, pieces, m.start(), m.end()):
            blocks.append((m.start(), m.end()))
    starts = [b[0] for b in blocks]
    count = 0
    for m in _B64.finditer(t.text):
        i = bisect.bisect_right(starts, m.start()) - 1
        if i >= 0 and m.start() < blocks[i][1]:
            continue  # already decoded with the lines around it
        count += 1
        if count > DECODE_MAX:
            t.cut(m.start())
            break
        _decode_blob(t, _b64_pieces(m.group()), m.start(), m.end())


def _b64_pieces(blob: str) -> list[bytes]:
    """The bytes of each piece of a base64 blob cut at its padding (pieces encoded apart and joined, as lines of a block are),
    decoded by a rule of our own and not by what `b64decode` does with dirty input, which changed between patch releases of
    Python 3.13: a padding in the middle gave the first piece on one and an error on another, so one file got two verdicts.
    '-' and '_' read as '+' and '/' (in any mix), a piece of 4n+1 characters loses its last one, and the last 2 or 3 characters
    of a piece give the 1 or 2 bytes they hold whatever their spare bits: no padding ever reaches the standard library."""
    out = []
    for piece in _B64_PAD.split(blob):
        if len(piece) % 4 == 1:
            piece = piece[:-1]
        if piece:
            data = base64.b64decode(piece.translate(_B64_URL_SAFE) + "A" * (-len(piece) % 4), validate=True)
            out.append(data[:len(piece) * 3 // 4])
    return out


def _decode_blob(t: _Text, pieces: list[bytes], start: int, end: int) -> bool:
    """Judges the pieces of one base64 blob of `t` (see _b64_pieces); True when they gave text or a program. The pieces joined
    are judged (a payload may be cut between them), and with more than one piece each piece alone too: bytes that are not text in
    front cannot hide the text of the others, and the end of one piece glued to the next cannot hide a word."""
    found = [_decode_bytes(t, b"".join(pieces), start, end)] if pieces else []
    if len(pieces) > 1:
        found += [_decode_bytes(t, p, start, end) for p in pieces]
    return any(found)


def _decode_bytes(t: _Text, data: bytes, start: int, end: int) -> str | None:
    """"text" when `data` is text (checked again one level down), "binary" when it is a program or an archive (a finding)."""
    kind = _magic(data[:HEAD], "")
    if kind and kind[0] in ("binary-file", "archive"):
        t._hit(kind[0], None, start, end)
        return "binary"
    decoded = _printable_text(data)
    if decoded is None:
        return None
    level = t.depth + 1
    label = "[decoded base64" + (f" x{level}" if level > 1 else "") + "] "
    child = _Text(t.res, decoded, "decoded", t.rel, label=label, line=t.line_of(start), depth=level)
    t.res._hit("encoded-text", None, child.base, child.evidence(0, min(len(decoded), 1)))
    _scan(child)
    return "text"


def _emoji_like(c: str) -> bool:
    return ord(c) >= 0x2000 and unicodedata.category(c) in ("So", "Sk", "Mn", "Me")


def _unicode(t: _Text) -> None:
    text, res = t.text, t.res
    count = 0  # of the runs that count: a cap met by what is skipped as harmless would cut a file of flags or emoji for nothing
    for m in _TAGS.finditer(text):
        run = m.group()
        if m.start() and text[m.start() - 1] == "\U0001f3f4" and run.endswith("\U000e007f") and len(run) <= 8:
            continue  # a subdivision flag, as the flag of England
        count += 1
        if count > MATCHES_MAX:
            t.cut(m.start())  # the hidden text past it is not decoded and checked
            break
        hidden = run.translate(_TAG_TEXT)
        line = t.line_of(m.start())
        label = t.label + "[decoded tags] "
        child = _Text(res, hidden, "decoded", t.rel, label=label, line=line, depth=t.depth + 1)
        first = len(hidden) - len(hidden.lstrip())  # the evidence shows the first line with words, masked as any other text
        res._hit("unicode-tags", "critical" if len(run) >= 10 else "high", line, child.evidence(first, first + 1))
        if hidden.strip() and t.depth < DECODE_DEPTH:
            _scan(child)
    seen: set[int] = set()
    for count, m in enumerate(_BIDI.finditer(text)):
        if count >= MATCHES_MAX:
            break  # only what is shown stops: every further one would be the same finding
        line = t.line_of(m.start())
        if line not in seen:
            seen.add(line)
            t._hit("bidi-control", None, m.start(), m.end())
    per_line: dict[int, list[int]] = {}
    count = 0
    for m in _ZERO_WIDTH.finditer(text):
        i, c = m.start(), m.group()
        before, after = (text[i - 1] if i else ""), (text[i + 1] if i + 1 < len(text) else "")
        if c == "\ufeff" and i == 0:
            continue  # a byte order mark
        if c == "\u200d" and before and after and (_emoji_like(before) or ord(before) >= 0x1F000) and (_emoji_like(after) or ord(after) >= 0x1F000):
            continue  # an emoji sequence
        if c in "\u200c\u200d\u200e\u200f" and ((before and ord(before) >= 0x0590 and before.isalpha()) or (after and ord(after) >= 0x0590 and after.isalpha())):
            continue  # joiners and marks inside right-to-left or Indic text
        count += 1
        if count > 10 * MATCHES_MAX:
            t.cut(i)  # a line past it could weigh more than one character alone
            break
        per_line.setdefault(t.line_of(i), []).append(i)
    for line, positions in per_line.items():
        t._hit("zero-width", "low" if len(positions) == 1 else None, positions[0], positions[0] + 1)
    count = 0
    for m in _SELECTORS.finditer(text):
        i = m.start()
        before = text[i - 1] if i else ""
        if len(m.group()) == 1 and before and (ord(before) >= 0x80 or before in "#*0123456789"):
            continue  # an emoji or a standardized variation sequence
        count += 1
        if count > MATCHES_MAX:
            t.cut(i)  # a longer run past it weighs more
            break
        t._hit("variation-selector", "high" if len(m.group()) >= 10 else None, i, m.end())


def _combine(res: _Result) -> None:
    """Combinations: what weighs more together than apart, across the file and everything decoded from it."""
    secrets = {name.split(":", 1)[1] for name in res.signals if name.startswith("secret:")}
    network = res.has("network") or res.has("exfil")
    if secrets - {"env"} and network:
        line, evidence = res.signals[next(n for n in res.signals if n.startswith("secret:") and n != "secret:env")]
        res._hit("secret-exfiltration", None, line, evidence())
    elif (res.has("credential") or "env" in secrets) and network:
        line, evidence = res.signals.get("credential") or res.signals["secret:env"]
        res._hit("secret-exfiltration", "high", line, evidence())
    if len(secrets - {"env"}) >= 3:
        line, evidence = res.signals[next(n for n in res.signals if n.startswith("secret:") and n != "secret:env")]
        res._hit("many-secret-stores", None, line, evidence())
    if "injection" in res.signals and secrets - {"env"}:
        res._raise("prompt-injection", "critical", res.marked.get("injection", set()))
    if "concealment" in res.signals:
        if secrets - {"env"} or res.has("exfil"):
            res._raise("prompt-injection", "critical", res.marked["concealment"])
        elif any(f.rule not in ("prompt-injection", "name-impersonation") and _RANK[f.severity] >= _RANK["medium"] for f in res.findings):
            res._raise("prompt-injection", "high", res.marked["concealment"])
    if "ai-cli" in res.signals and (secrets or res.has("credential") or res.has("exfil")):
        res._raise("ai-cli-unsafe", "critical")
    if any(f.rule != "name-impersonation" and _RANK[f.severity] >= _RANK["medium"] for f in res.findings):
        res._raise("name-impersonation", "high")


# Config entries


_ENDPOINT_KEYS = frozenset(("ANTHROPIC_BASE_URL", "ANTHROPIC_API_URL", "ANTHROPIC_BEDROCK_BASE_URL", "ANTHROPIC_VERTEX_BASE_URL", "OPENAI_BASE_URL",
                            "OPENAI_API_BASE", "AZURE_OPENAI_ENDPOINT", "GOOGLE_GEMINI_BASE_URL", "GEMINI_API_BASE", "GEMINI_BASE_URL", "BASE_URL",
                            "CHATGPT_BASE_URL"))
_PROXY_KEYS = frozenset(("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"))
_TLS_OFF = {"NODE_TLS_REJECT_UNAUTHORIZED": "0", "GIT_SSL_NO_VERIFY": "1", "PYTHONHTTPSVERIFY": "0"}
_CA_KEYS = frozenset(("NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE"))
_REGISTRY_KEYS = frozenset(("NPM_CONFIG_REGISTRY", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_EXTRA_INDEX_URL",
                            "UV_INDEX", "YARN_REGISTRY", "YARN_NPM_REGISTRY_SERVER", "BUN_CONFIG_REGISTRY"))
# The kinds of names a settings env block holds, as the inventory watches them (inventory.WATCHED_ENV): a name of any program
# fits. Only in the env of the agent's own settings; in the env of an MCP server they configure that server's own service.
_ENDPOINT_NAME = re.compile(r"_(?:BASE_URL|API_BASE|API_URL|ENDPOINT)$")
_PROXY_NAME = re.compile(r"(?:^|_)PROXY$")
_CA_NAME = re.compile(r"_CA_BUNDLE$|_EXTRA_CA_CERTS$|^SSL_CERT_FILE$")
_REGISTRY_NAME = re.compile(r"_REGISTRY$|_INDEX_URL$|^UV_(?:DEFAULT_|EXTRA_)?INDEX(?:_URL)?$")
_PRELOAD_KEYS = frozenset(("LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "BASH_ENV", "PYTHONSTARTUP"))  # code every program or shell loads
_NODE_PRELOAD = re.compile(r"(?:^|\s)(?:-r|--require|--import|--(?:experimental-)?loader)(?:[\s=]|$)")  # in NODE_OPTIONS
_COMMAND_KEYS = frozenset(("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper", "notify"))
_SECRET_KEY = re.compile(r"(?i)token|secret|passw|api[_-]?key|apikey|auth|credential|private[_-]?key|access[_-]?key|bearer|cookie|session")
# Values a command line carries: a header after -H (also bundled, -sH, and with no space, -H'X: v'), what follows ? in an address,
# userinfo, user:password after -u or -U (also bundled, -fsSLu) or --user or --proxy-user, a cookie after -b or --cookie, a
# password option (mysql -pSECRET, --password SECRET), sshpass -p SECRET.
_HEADER = r"(?<![\w-])(?:-[a-zA-Z]{0,6}H|-h|(?i:--header))(?:\s*|=)"
_HEADER_QUOTED = re.compile(_HEADER + r"([\"'])[^:\"'\n]{1,100}:([^\"'\n]*)\1")
_HEADER_BARE = re.compile(_HEADER + r"[^:\"'\s]{1,100}:(\S*)")
_USER_OPTION = re.compile(r"(?<![\w-])(?:-[a-zA-Z]{0,6}[uU]|--user|--proxy-user)(?:\s+|=)?[\"']?([^\s:\"']*:[^\s\"']*)")
_COOKIE_OPTION = re.compile(r"(?<![\w-])(?:-[a-zA-Z]{0,6}b|--cookie)(?:\s+|=)?(?=[\"']?[^\s\"'=]{0,200}=)(\"[^\"\n]*\"|'[^'\n]*'|[^\s\"']+)")
_PASSWORD_OPTION = re.compile(r"(?<![\w-])(?:-p(?=\S)|--pass(?:word|wd)?(?:\s+|=))[\"']?([^\s\"']+)")
_SSHPASS = re.compile(r"\bsshpass\s+(?:-[a-zA-Z]{1,4}\s+){0,3}?-p\s*[\"']?([^\s\"']+)")
_QUERY = re.compile(r"(?i)\b[a-z][a-z0-9+.-]{1,20}://[^\s?#\"'<>]{1,2000}\?([^\s#\"'<>]*)")
_USERINFO = re.compile(r"(?i)\b[a-z][a-z0-9+.-]{1,20}://([^\s/@\"'<>]{1,500})@")
_TOKEN = re.compile(r"[A-Za-z0-9+/=_.~-]{16,}")


def _entropic(value: str) -> bool:
    """A value that looks random, whatever its name: upper and lower case and digits with high entropy, a long hex string, or a
    long base64-like string. Words, paths and versions are not."""
    if len(value) < 16 or any(c.isspace() for c in value) or value.startswith(("/", "~", ".", "$")) or "://" in value:
        return False
    counts: dict[str, int] = {}
    for c in value:
        counts[c] = counts.get(c, 0) + 1
    entropy = -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())
    classes = any(c.isupper() for c in value) + any(c.islower() for c in value) + any(c.isdigit() for c in value)
    hexadecimal = all(c in "0123456789abcdefABCDEF" for c in value)
    return (classes == 3 and entropy >= 3.5) or (hexadecimal and len(value) >= 32) or (len(value) >= 32 and entropy >= 4.2)


_SECRET_VALUE = re.compile(r"(?i)(?:api[_-]?key|token|secret|password|passwd|authorization|bearer|auth)[\"']?\s*[:=]?\s*[\"']?(?:bearer\s+)?([^\s\"']{6,})")
_CAMEL_WORDS = re.compile(r"(?:[A-Z][a-z]{2,24}){2,12}(?:V?\d{1,4}(?:[A-Z][a-z]{2,24}){0,12})+")
_SECRET_PARENTS = frozenset(("env", "headers", "http_headers", "env_vars", "environment"))
_OFFICIAL_SERVERS = ("github", "gitlab", "figma", "postgres", "filesystem", "slack", "google-maps", "brave-search", "puppeteer", "fetch", "memory",
                     "sqlite", "git", "everything", "sequential-thinking", "time", "redis", "sentry", "gdrive", "aws-kb-retrieval", "everart")
_DOCKER_VALUE_FLAGS = frozenset(("-v", "--volume", "-e", "--env", "--name", "-p", "--publish", "--network", "--mount", "-w", "--workdir", "--entrypoint",
                                 "-u", "--user", "--env-file", "--platform", "-l", "--label", "--add-host", "--cpus", "-m", "--memory"))


ENTRY_DEPTH = 20  # levels of a config entry that are walked
ENTRY_WIDTH = 10_000  # keys or members of one mapping or list that are walked


def _leaves(value, path: tuple[str, ...] = (), depth: int = 0, cut: list | None = None) -> Iterator[tuple[tuple[str, ...], object]]:
    """Every (path, scalar) of an entry; what lies past ENTRY_DEPTH or ENTRY_WIDTH is not walked, and `cut` then gets one True: a
    scalar right past the depth is left out as much as a mapping is."""
    if depth > ENTRY_DEPTH:
        if cut is not None:
            cut.append(True)
        return
    if isinstance(value, Mapping):
        items = list(value.items())
        if len(items) > ENTRY_WIDTH and cut is not None:
            cut.append(True)
        for k, v in items[:ENTRY_WIDTH]:
            yield from _leaves(v, path + (str(k),), depth + 1, cut)
    elif isinstance(value, (list, tuple)):
        if len(value) > ENTRY_WIDTH and cut is not None:
            cut.append(True)
        for i, v in enumerate(value[:ENTRY_WIDTH]):
            yield from _leaves(v, path + (str(i),), depth + 1, cut)
    else:
        yield path, value


def _key_name(path: tuple[str, ...]) -> str:
    for part in reversed(path):
        if not part.isdigit() and part.lower() not in ("value", "values"):
            return part
    return ""


class _Entry:
    """The findings of one config entry. Evidence names keys and hosts, never values: whatever came from the entry's env, headers
    or secret-looking fields is replaced before a finding is made."""

    def __init__(self, entry: Mapping, *, agent: str, kind: str, scope: str, locator: str):
        self.entry, self.agent, self.kind = entry, agent, kind
        self.res = _Result(locator)
        norm = locator.replace("\\", "/")
        self.trusted = scope == "user" and "/plugins/" not in norm and kind != "plugin"
        hint = locator.rsplit(" ", 1)[-1] if " " in locator else ""
        self.prefix = tuple(p for p in hint.split(".") if p) if hint and "/" not in hint else ()
        cut: list = []
        self.leaves = list(_leaves(entry, self.prefix, cut=cut))
        if cut:
            self.res.cut(0)  # an entry too deep or too wide was not read whole
        self.values = sorted({str(v) for p, v in self.leaves if isinstance(v, str) and len(v) >= 4 and (
            any(part.lower() in _SECRET_PARENTS for part in p) or _SECRET_KEY.search(_key_name(p)) or "url" in _key_name(p).lower()
            or _entropic(v))}, key=len, reverse=True)

    def by_scope(self, user: str, other: str) -> str:
        return user if self.trusted else other

    def _hit(self, rule: str, severity: str | None, evidence: str) -> None:
        """The evidence is masked by the spans of all of it, as the evidence of a file is (see masking_spans)."""
        spans = masking_spans(self.res, evidence)
        shown = LEFT_OUT if spans is None else masked_excerpt(evidence, spans, 0, len(evidence))
        self.res._hit(rule, severity, 0, _escape(shown, EVIDENCE_MAX))

    def mask(self, text: str) -> str:
        """`text` with every value starred, at the same length: the entry's env, header and secret-looking values wherever they
        occur, header values after -H, what follows ? in an address, userinfo, user:password options, cookies, password options,
        sshpass -p, labelled secrets, random-looking tokens and what the level-0 detector finds."""
        spans: list[tuple[int, int]] = []
        for v in self.values:
            i = text.find(v)
            while i != -1:
                spans.append((i, i + len(v)))
                i = text.find(v, i + 1)
        for regex, group in ((_HEADER_QUOTED, 2), (_HEADER_BARE, 1), (_QUERY, 1), (_USERINFO, 1), (_USER_OPTION, 1), (_COOKIE_OPTION, 1),
                             (_PASSWORD_OPTION, 1), (_SSHPASS, 1), (_SECRET_VALUE, 1)):
            spans.extend(m.span(group) for m in regex.finditer(text))
        spans.extend(m.span() for m in _TOKEN.finditer(text) if _entropic(m.group()))
        try:
            from boxed.detect import detect
            spans.extend((d.start, d.end) for d in detect(text, level=0, ner=[]))
        except Exception:  # the detector is an extra layer here; the rules above already ran
            pass
        chars = list(text)
        for start, end in spans:
            chars[start:end] = "*" * (end - start)
        return "".join(chars)

    def command(self, command: str, *, prose: bool = False) -> _Result:
        """Checks the command text with the file rules; the findings come over with masked evidence and the entry as file."""
        sub = _Result(self.res.file)
        t = _Text(sub, command, "prose" if prose else "shell", "command", shown=self.mask(command))
        _scan_all(t, self.mask)
        _combine(sub)
        for f in sub.findings:
            self.res.findings.append(Finding(**{**f.__dict__, "line": 0, "evidence": _escape(self.mask(f.evidence), EVIDENCE_MAX)}))
        self.res.caps |= sub.caps
        for name, (line, evidence) in sub.signals.items():
            self.res.signals.setdefault(name, (0, lambda evidence=evidence: self.mask(evidence())))
        if not prose:
            self.res.caps.add("runs-commands")
        return sub

    def keys(self) -> None:
        """Settings by key: base URL, endpoint, proxy, TLS, registry and code-loading overrides weigh by scope; permission switches;
        secrets written in. In the env block of a setting (Claude settings env, Codex shell_environment_policy.set) a name counts
        by its kind (any *_BASE_URL, *_ENDPOINT, *_PROXY ...), as the inventory watches it; so does a top-level *_base_url key."""
        for path, value in self.leaves:
            name = _key_name(path)
            upper = name.upper()
            if upper == "BASE_URL" and "model_providers" not in path:
                upper = ""  # a generic name: only a Codex model provider's base_url is the AI endpoint
            where = ".".join(p for i, p in enumerate(path) if not i or p != path[i - 1]) or name
            text = str(value) if value is not None else ""
            inner = path[len(self.prefix):]  # the path inside the entry
            env = self.kind == "setting" and len(inner) >= 2 and (inner[-2] == "env" or inner[-3:-1] == ("shell_environment_policy", "set"))
            top = self.kind == "setting" and len(inner) == 1
            tls_off = _TLS_OFF.get(upper) or ("0" if env and "TLS_REJECT_UNAUTHORIZED" in upper else None)
            if ((upper in _ENDPOINT_KEYS or (env and _ENDPOINT_NAME.search(upper)) or (top and upper.endswith("_BASE_URL")))
                    and isinstance(value, str) and value):
                hosts = _hosts(value)
                if not (hosts and all(_in(h, _API_HOSTS) for h in hosts)):
                    self._hit("endpoint-override", self.by_scope("medium", "critical"), where + self._host_note(hosts))
            elif (upper in _PROXY_KEYS or (env and _PROXY_NAME.search(upper))) and text:
                # NO_PROXY names hosts that skip the proxy: a sign, not a route
                severity = "low" if upper == "NO_PROXY" else self.by_scope("medium", "critical")
                self._hit("proxy-override", severity, where + self._host_note(_hosts(text)))
            elif tls_off and text.strip().lower() in (tls_off, "true" if tls_off == "1" else tls_off):
                self._hit("tls-override", self.by_scope("medium", "critical"), where)
            elif (upper in _CA_KEYS or (env and _CA_NAME.search(upper))) and text:
                self._hit("tls-override", self.by_scope("low", "high"), where)
            elif (upper in _REGISTRY_KEYS or (env and _REGISTRY_NAME.search(upper))) and text:
                hosts = _hosts(text)
                if not (hosts and all(_in(h, _REGISTRIES) for h in hosts)):
                    self._hit("registry-override", self.by_scope("medium", "critical"), where + self._host_note(hosts))
            elif (upper in _PRELOAD_KEYS and text) or (upper == "NODE_OPTIONS" and _NODE_PRELOAD.search(text)):
                self._hit("preload-injection", self.by_scope("medium", "critical"), where)
            if value == "bypassPermissions" or (name == "sandbox_mode" and value == "danger-full-access"):
                self._hit("bypass-permissions", self.by_scope("high", "critical"), where)
            elif name == "skipDangerousModePermissionPrompt" and value is True:
                self._hit("skip-permission-prompt", self.by_scope("medium", "high"), where)
            elif name == "enableAllProjectMcpServers" and value is True:
                self._hit("auto-enable-mcp", self.by_scope("medium", "high"), where)
            elif "allow" in path and value in ("Bash", "Bash(*)", "Bash(*:*)", "Bash(:*)"):
                self._hit("allow-all-bash", self.by_scope("medium", "high"), where)
            elif name == "suppressOutput" and value is True:
                self._hit("suppress-output", None, where)
            if (isinstance(value, str) and value and not value.startswith("$") and upper not in _ENDPOINT_KEYS | _PROXY_KEYS | _REGISTRY_KEYS
                    and any(part.lower() in _SECRET_PARENTS for part in path) and (_SECRET_KEY.search(name) or self._looks_secret(value))):
                self._hit("inline-secret", None, where)
            elif self.kind == "setting" and isinstance(value, str) and inner[:2] == ("permissions", "allow") and self._looks_secret(value):
                self._hit("inline-secret", None, where)  # a permission rule keeps the whole command that was allowed, its key too

    @staticmethod
    def _host_note(hosts: list[str]) -> str:
        return f" ({hosts[0]})" if hosts else ""

    @staticmethod
    def _looks_secret(value: str) -> bool:
        if _CAMEL_WORDS.fullmatch(value):  # FeatureFlagV2Enabled, StagingEnvironment1: words and a number, not random
            return False
        if _entropic(value):
            return True
        try:
            from boxed.detect import detect
            return bool(detect(value, level=0, ner=[]))
        except Exception:
            return False

    def network(self, sub: _Result) -> bool:
        return sub.has("network") or sub.has("exfil") or "download" in sub.signals

    def hook(self) -> None:
        self.res.caps.add("event-hooks")
        for path, value in self.leaves:
            if not isinstance(value, str):
                continue
            name = _key_name(path)
            if name == "command":
                sub = self.command(value)
                if self.network(sub):
                    self._hit("command-network", self.by_scope("medium", "critical"), self.mask(value))
                else:
                    self._hit("event-hook", self.by_scope("info", "low"), self.mask(value))
            elif name == "prompt":
                self.command(value, prose=True)

    def setting(self) -> None:
        """Settings that run a command (statusLine, apiKeyHelper, Codex notify as an argument list)."""
        commands: dict[tuple[str, ...], list[str]] = {}
        for path, value in self.leaves:
            name = _key_name(path)
            if "hooks" in path[:1] or not (name == "command" or name in _COMMAND_KEYS) or not isinstance(value, str) or not value:
                continue
            group = path[:-1] if path[-1].isdigit() else path
            commands.setdefault(group, []).append(value)
        for parts in commands.values():
            command = " ".join(parts)
            if command:
                sub = self.command(command)
                if self.network(sub):
                    self._hit("command-network", self.by_scope("medium", "critical"), self.mask(command))
                else:
                    self._hit("command-setting", self.by_scope("info", "low"), self.mask(command))

    def mcp(self) -> None:
        entry = self.entry
        url = next((entry.get(k) for k in ("url", "serverUrl", "httpUrl") if isinstance(entry.get(k), str)), None)
        if url:
            self.res.caps.add("network")
            hosts = _hosts(url)
            if hosts:
                host = hosts[0]
                shown = url.split("://", 1)[0] + "://" + host
                if _in(host, _COLLECT):
                    self._hit("exfil-endpoint", None, shown)
                elif _risky_host(host):
                    self._hit("remote-mcp-host", None, shown)
        command = entry.get("command")
        args = entry.get("args") if isinstance(entry.get("args"), list) else []
        argv = ([command] if isinstance(command, str) else list(command) if isinstance(command, list) else []) + args
        argv = [str(a) for a in argv]
        if not argv:
            return
        base = argv[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
        if base in ("sh", "bash", "zsh", "dash", "ksh") and "-c" in argv[1:]:
            i = argv.index("-c", 1)
            script = argv[i + 1] if i + 1 < len(argv) else ""
            sub = self.command(script)
            t1 = {"pipe-to-shell", "pipe-to-interpreter", "paste-host", "raw-ip-url", "download-execute", "decode-exec"}
            for rule in t1 & {f.rule for f in sub.findings}:
                self.res._raise(rule, "critical")
        else:
            self.command(" ".join(argv))
        self._runner(base, argv[1:])

    def _runner(self, base: str, args: list[str]) -> None:
        package = None
        if base in ("npx", "bunx") or (base == "pnpm" and args[:1] == ["dlx"]):
            rest = args[1:] if base == "pnpm" else args
            package = next((a for a in rest if not a.startswith("-")), None)
            npm = True
        elif base in ("uvx", "pipx"):
            rest = args[1:] if base == "pipx" and args[:1] == ["run"] else args
            frm = next((rest[i + 1] for i, a in enumerate(rest[:-1]) if a == "--from"), None)
            package = frm or next((a for a in rest if not a.startswith("-")), None)
            npm = False
        elif base in ("docker", "podman") and "run" in args:
            self._docker(args[args.index("run") + 1:])
            return
        if not package:
            return
        self.res.caps.add("installs-packages")
        name, version = self._split(package, npm)
        if not re.match(r"\d", version or ""):
            # named from the package with its address masked: a user:password before @ would otherwise be the name
            self._hit("unpinned-package", None, base + " " + self._split(self.mask(package), npm)[0])
        if npm:
            scope, _, bare = name.rpartition("/")
            official = {f"mcp-server-{s}" for s in _OFFICIAL_SERVERS} | {f"server-{s}" for s in _OFFICIAL_SERVERS}
            if (not scope and bare in official) or (scope and scope != "@modelcontextprotocol" and 0 < _distance(scope, "@modelcontextprotocol") <= 2):
                self._hit("mcp-lookalike", None, name)
        if name == "mcp-remote" and version and re.match(r"\d", version):
            numbers = tuple(int(x) for x in re.findall(r"\d+", version)[:3])
            if numbers < (0, 1, 16):
                self._hit("vulnerable-package", None, f"{name}@{version}")

    @staticmethod
    def _split(package: str, npm: bool) -> tuple[str, str]:
        if not npm and "==" in package:
            name, _, version = package.partition("==")
            return name, version
        at = package.find("@", 1)
        return (package[:at], package[at + 1:]) if at > 0 else (package, "")

    def _docker(self, args: list[str]) -> None:
        image, i = None, 0
        while i < len(args):
            a = args[i]
            if a in _DOCKER_VALUE_FLAGS:
                if a in ("-v", "--volume", "--mount") and i + 1 < len(args):
                    source = args[i + 1].split(":", 1)[0].replace("source=", "").replace("src=", "")
                    if source.rstrip("/") in ("", "~", "$HOME", "${HOME}", "/Users", "/home", "/root") or source in ("/", "~/"):
                        self._hit("broad-mount", None, f"{a} {source}:")
                i += 2
                continue
            if not a.startswith("-"):
                image = a
                break
            i += 1
        if image:
            last = image.rsplit("/", 1)[-1]
            if "@sha256:" not in image and (":" not in last or last.endswith(":latest")):
                self._hit("unpinned-package", None, "docker " + image)


def check_entry(entry: Mapping, *, agent: str, kind: str, scope: str, locator: str) -> FileReport:
    """The findings of an MCP server, hook, setting or other config entry. Weight follows the scope: what the person set in their
    own user settings is milder than the same thing in project, local or plugin scope (a plugin's own config counts as plugin
    scope wherever it sits). Values never reach a finding: evidence names keys, hosts and commands with secrets replaced."""
    e = _Entry(entry if isinstance(entry, Mapping) else {}, agent=agent, kind=kind, scope=scope, locator=locator)
    if kind == "mcp":
        e.mcp()
    elif kind == "hook":
        e.hook()
    else:
        e.setting()
    e.keys()
    _combine(e.res)
    return e.res.report()


def _json_config(res: _Result, text: str, rel: str) -> None:
    """Hooks, MCP servers and settings inside a JSON file of an item are checked as entries of plugin scope."""
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        return
    if not isinstance(doc, dict):
        return
    entries: list[tuple[Mapping, str, str]] = []
    hooks = doc.get("hooks")
    if isinstance(hooks, Mapping):
        for event, groups in hooks.items():
            for i, group in enumerate(groups if isinstance(groups, list) else []):
                for j, hook in enumerate(group.get("hooks", []) if isinstance(group, Mapping) else []):
                    if isinstance(hook, Mapping):
                        entries.append((hook, "hook", f"{rel} hooks.{event}.{i}.hooks.{j}"))
    servers = doc.get("mcpServers")
    if isinstance(servers, Mapping):
        for name, server in servers.items():
            if isinstance(server, Mapping):
                entries.append((server, "mcp", f"{rel} mcpServers.{name}"))
    rest = {k: v for k, v in doc.items() if k not in ("hooks", "mcpServers")}
    if rest and ("settings" in rel.lower() or any(k in rest for k in ("env", "permissions", "statusLine", "apiKeyHelper"))):
        entries.append((rest, "setting", rel))
    for entry, kind, locator in entries:
        report = check_entry(entry, agent="claude", kind=kind, scope="plugin", locator=locator)
        anchor = _anchor(text, entry)
        for f in report.findings:
            res.findings.append(Finding(**{**f.__dict__, "file": rel, "line": anchor}))
        res.caps |= report.capabilities


def _anchor(text: str, entry: Mapping) -> int:
    """The line of an entry in its JSON text: where its command or first string value is written."""
    for key in ("command", "url"):
        value = entry.get(key)
        if isinstance(value, str) and value:
            pos = text.find(json.dumps(value)[1:-1])
            if pos != -1:
                return text.count("\n", 0, pos) + 1
    return 0


def check_link(rel: str, target: str, *, leaves_item: bool) -> FileReport:
    """A link met inside an item (never followed). One that stays inside is fine; one that leaves is a finding, critical when it
    points at a secret store, the home folder or the root."""
    res = _Result(rel)
    if not leaves_item:
        return res.report()
    parts = [p for p in target.replace("\\", "/").split("/") if p]
    sensitive = {".ssh", ".aws", ".gnupg", ".kube", ".docker", "Keychains", ".codex", ".claude", ".config", ".azure", ".clawdbot", ".openclaw",
                 ".cursor", ".gemini", ".boxed", ".password-store", ".netrc", ".npmrc", ".pypirc", ".git-credentials", ".electrum", "tdata",
                 ".claude.json", "Cookies", "Login Data"}
    home_like = target in ("/", "~", "$HOME") or (len(parts) == 2 and parts[0] in ("Users", "home")) or parts == ["root"]
    severity = "critical" if home_like or sensitive & set(parts) else None
    res._hit("link-outside", severity, 0, _escape(f"{rel} -> {target}", EVIDENCE_MAX))
    return res.report()
