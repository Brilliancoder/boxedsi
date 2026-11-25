import hashlib
import hmac
import io
import json
import os
import shutil
import stat
import sys
from collections import Counter
from datetime import date
from pathlib import Path

import pytest

from boxed.audit.report import render_html, render_terminal, run_audit
from boxed.audit.sources import SentItem, iter_claude_code, iter_codex
from boxed.cli import main
from support import mode_is

FIXTURES = Path(__file__).parent / "fixtures"
SENSITIVE = [
    "ivan.petrov@acme.com",
    "anna@acme.com",
    "bob@acme.com",
    "hunter22",
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
    "sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV",
    "345-67-89",
    "203.0.113.7",
]


@pytest.fixture
def roots(tmp_path):
    claude = tmp_path / "claude"
    (claude / "-work-proj").mkdir(parents=True)
    shutil.copy(FIXTURES / "claude_session.jsonl", claude / "-work-proj" / "s1.jsonl")
    codex = tmp_path / "codex" / "2026" / "10" / "04"
    codex.mkdir(parents=True)
    shutil.copy(FIXTURES / "codex_rollout.jsonl", codex / "rollout-c1.jsonl")
    return claude, tmp_path / "codex"


def summary(roots, **kw):
    stats = Counter()
    claude, codex = roots
    items = [*iter_claude_code(claude, stats), *iter_codex(codex, stats)]
    return run_audit(items, stats=stats, **kw)


def test_summary_counts(roots):
    s = summary(roots)
    assert s.items == 8 and s.malformed == 1  # the developer message of Codex counts: it goes to the model
    assert s.by_kind == Counter({"EMAIL": 4, "SECRET": 4, "PHONE": 1, "IP": 1})
    assert s.by_role == Counter({"tool_result": 5, "user_prompt": 3, "attachment": 1, "instructions": 1})
    assert s.by_source["codex"]["SECRET"] == 2
    assert s.by_project["/work/proj"]["EMAIL"] == 2
    assert s.by_day["2026-10-04"]["IP"] == 1
    assert len(s.secrets) == 4 and all(len(h.hmac_prefix) == 12 for h in s.secrets)


def test_secret_hits_have_no_values(roots):
    s = summary(roots)
    for rendered in (render_terminal(s), render_html(s)):
        for value in SENSITIVE:
            assert value not in rendered


def test_html_is_self_contained(roots):
    html = render_html(summary(roots))
    assert html.startswith("<!doctype html>")
    assert "http://" not in html and "https://" not in html and "<script" not in html.lower()
    assert "rotate" in html.lower()


def test_since_filter(roots):
    s = summary(roots, since=date(2026, 10, 3))
    assert s.items == 6
    assert s.by_kind["EMAIL"] == 2
    assert s.projects == {"/work/proj", "/work/other"}  # a project of the period before still has its settings read


def test_a_project_is_named_whatever_the_period():
    old = SentItem("claude-code", "anthropic", "/work/old", "s1", None, "user_prompt", "hello", "f:1")
    assert run_audit([old], since=date(2030, 1, 1)).projects == {"/work/old"}


def test_audit_cli(roots, tmp_path, capsys):
    claude, codex = roots
    out_html = tmp_path / "reports" / "audit.html"
    code = main(["audit", "--claude-dir", str(claude), "--codex-dir", str(codex), "--html", str(out_html)])
    out, _ = capsys.readouterr()
    assert code == 0 and "SECRET" in out
    assert out_html.exists()
    for value in SENSITIVE:
        assert value not in out and value not in out_html.read_text()


def test_secret_prefix_is_keyed():
    value = "AKIAIOSFODNN7EXAMPLE"
    item = SentItem("claude-code", "anthropic", "/p", "s1", None, "user_prompt", f"key {value}", "f:1")
    key = b"k" * 32
    hit = run_audit([item], key=key).secrets[0]
    assert hit.hmac_prefix == hmac.new(key, value.encode(), hashlib.sha256).hexdigest()[:12]
    assert hit.hmac_prefix != hashlib.sha256(value.encode()).hexdigest()[:12]
    assert run_audit([item]).secrets[0].hmac_prefix != run_audit([item]).secrets[0].hmac_prefix


def test_audit_without_a_keychain_uses_a_run_key(roots, tmp_path, capsys, monkeypatch):
    claude, codex = roots

    def broken():
        raise RuntimeError("no keychain")

    monkeypatch.setattr("boxed.cli.default_keystore", broken)
    assert main(["audit", "--claude-dir", str(claude), "--codex-dir", str(codex)]) == 0
    assert "random for this run" in capsys.readouterr().err


def test_audit_report_inside_boxed_home_is_private(roots, boxed_env, tmp_path, monkeypatch):
    from boxed.keys import InsecureFileKeyStore

    claude, codex = roots
    monkeypatch.setattr("boxed.cli.default_keystore", lambda: InsecureFileKeyStore(tmp_path / "keys"))  # like the keychain: no BOXED_HOME
    out_html = boxed_env / "reports" / "audit.html"
    assert main(["audit", "--claude-dir", str(claude), "--codex-dir", str(codex), "--html", str(out_html)]) == 0
    assert mode_is(boxed_env, 0o700)


# ---- audit --html writes by the dashboard's rules: where it may write, what it may replace, how ----


def audit_html(roots, target):
    claude, codex = roots
    return main(["audit", "--claude-dir", str(claude), "--codex-dir", str(codex), "--html", str(target)])


@pytest.fixture
def data(boxed_env, monkeypatch, capsys):
    """A boxed home with a journal, a vault and a key, and their bytes before any report."""
    monkeypatch.setattr("sys.stdin", io.StringIO("mail ivan@acme.com"))
    assert main(["mask", "--scope", "d1", "-"]) == 0
    capsys.readouterr()
    names = ["journal.jsonl", "vault.db", "insecure-keys/device-signing-key.key"]
    return {name: (boxed_env / name).read_bytes() for name in names}


def kept(boxed_env, data):
    return {name: (boxed_env / name).read_bytes() for name in data}


def test_audit_html_never_writes_over_what_boxed_keeps_in_its_home(roots, capsys, boxed_env, data):
    for name in data:
        assert audit_html(roots, boxed_env / name) == 2, name
        assert "boxed home" in capsys.readouterr().err, name
    for how in ("reports/../journal.jsonl", "other/audit.html", "audit.html"):  # a path that goes round, a new folder, a new name
        assert audit_html(roots, boxed_env / how) == 2, how
        assert "boxed home" in capsys.readouterr().err, how
    assert kept(boxed_env, data) == data  # not one byte of them changed
    assert not (boxed_env / "other").exists() and not (boxed_env / "audit.html").exists()


def test_audit_html_never_writes_through_a_link_to_what_boxed_keeps(roots, tmp_path, capsys, boxed_env, data):
    (tmp_path / "friendly.html").symlink_to(boxed_env / "journal.jsonl")
    (boxed_env / "reports").symlink_to(boxed_env)  # reports/ that leads back into the home is not the reports folder
    for target in (tmp_path / "friendly.html", boxed_env / "reports" / "vault.db"):
        assert audit_html(roots, target) == 2, target
        assert "boxed home" in capsys.readouterr().err, target
    assert kept(boxed_env, data) == data
    assert (tmp_path / "friendly.html").is_symlink()


def test_audit_html_may_write_under_reports_in_the_home_where_the_docs_put_it(roots, boxed_env, data):
    target = boxed_env / "reports" / "audit.html"
    assert audit_html(roots, target) == 0 and b"<title>boxed audit</title>" in target.read_bytes()
    assert kept(boxed_env, data) == data


@pytest.mark.parametrize("name", ["notes.txt", "empty"])
def test_audit_html_does_not_replace_a_file_that_is_not_a_boxed_report(roots, tmp_path, capsys, name):
    precious = tmp_path / name
    precious.write_bytes(b"" if name == "empty" else b"my notes, not a report\n")
    before = precious.read_bytes()
    assert audit_html(roots, precious) == 2
    err = capsys.readouterr().err
    assert "the output file exists and boxed did not write it: name another file, or delete it first" in err and name not in err
    assert precious.read_bytes() == before


def test_audit_html_and_the_dashboard_each_replace_only_their_own_reports(roots, tmp_path, capsys, boxed_env, data):
    page, audit_page = tmp_path / "dashboard.html", tmp_path / "audit.html"
    assert main(["dashboard", "--html", str(page)]) == 0 and audit_html(roots, audit_page) == 0
    capsys.readouterr()
    before = page.read_bytes(), audit_page.read_bytes()
    assert audit_html(roots, page) == 2 and "the output file exists and boxed did not write it" in capsys.readouterr().err
    assert main(["dashboard", "--html", str(audit_page)]) == 2 and "the output file exists and boxed did not write it" in capsys.readouterr().err
    assert (page.read_bytes(), audit_page.read_bytes()) == before


def test_audit_html_does_not_write_into_a_folder_or_a_pipe(roots, tmp_path, capsys):
    (tmp_path / "folder").mkdir()
    assert audit_html(roots, tmp_path / "folder") == 2 and "plain file" in capsys.readouterr().err
    if not hasattr(os, "mkfifo"):  # Windows has no pipe in the file system
        return
    pipe = tmp_path / "pipe.html"
    os.mkfifo(pipe)
    reader = os.open(pipe, os.O_RDONLY | os.O_NONBLOCK)  # with a reader there, a write would not block: the test can fail instead of hanging
    try:
        assert audit_html(roots, pipe) == 2 and "plain file" in capsys.readouterr().err
        assert os.read(reader, 100) == b""  # nothing went into it
    finally:
        os.close(reader)


def test_audit_html_replaces_a_report_of_its_own_through_a_part_file(roots, tmp_path):
    """A hard link keeps the old report's bytes: the old file was replaced whole, not written into."""
    target, alias = tmp_path / "audit.html", tmp_path / "old-audit.html"
    assert audit_html(roots, target) == 0
    os.link(target, alias)
    old = target.read_bytes()
    with (roots[0] / "-work-proj" / "s1.jsonl").open("a") as f:
        f.write("not json\n")  # one more malformed line, so that the next report differs
    assert audit_html(roots, target) == 0
    assert alias.read_bytes() == old and target.read_bytes() != old
    assert mode_is(target, 0o600)
    assert sorted(path.name for path in tmp_path.iterdir() if path.name.startswith(".")) == []  # no part file is left


def test_audit_html_does_not_follow_a_link_planted_where_the_part_file_goes(roots, tmp_path, boxed_env, data):
    (tmp_path / ".audit.html.boxed-part").symlink_to(boxed_env / "journal.jsonl")
    assert audit_html(roots, tmp_path / "audit.html") == 0
    assert kept(boxed_env, data) == data
    assert b"<title>boxed audit</title>" in (tmp_path / "audit.html").read_bytes()


def test_audit_html_keeps_the_old_report_when_the_new_one_cannot_be_written(roots, tmp_path, monkeypatch):
    target = tmp_path / "audit.html"
    assert audit_html(roots, target) == 0
    before = target.read_bytes()

    def disk_full(fd):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fsync", disk_full)
    assert audit_html(roots, target) == 2 and target.read_bytes() == before
    assert sorted(path.name for path in tmp_path.iterdir() if path.name not in ("claude", "codex", "boxed-home")) == ["audit.html"]


def test_audit_html_path_is_checked_before_anything_is_scanned(roots, boxed_env, data, capsys, monkeypatch):
    def scanned(*args):
        raise AssertionError("the transcripts were read before the report path was checked")

    monkeypatch.setattr("boxed.audit.sources.iter_claude_code", scanned)
    assert audit_html(roots, boxed_env / "journal.jsonl") == 2
    assert "boxed home" in capsys.readouterr().err


# ---- how sure a secret is: a key of a known format, or a possible one ----


def item(text, locator="f:1", source="claude-code", project="/p"):
    return SentItem(source, "anthropic", project, "s1", None, "user_prompt", text, locator)


def test_known_key_formats_come_from_the_rules():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabc123\n-----END RSA PRIVATE KEY-----"
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.c2lnbmF0dXJlZGVtbw"
    known = {"AKIAIOSFODNN7EXAMPLE", pem, jwt, "ghp_1234567890abcdefghijklmnopqrstuvwxyz"}
    known.add(f"Authorization: Bearer {jwt}x")  # a JWT is one after Bearer too, where the rule of headers takes it
    possible = {"DB_PASSWORD=hunter22x", "token: Xk9#mQ2vLp", "Zq8vXk2mPw9rTb4nLs7dHc3fGj6yUa5eQ1"}
    s = run_audit([item(f"see {t} here") for t in sorted(known | possible)])
    assert sorted(h.known for h in s.secrets) == [False] * 3 + [True] * 5


def test_the_summary_line_splits_known_formats_from_possible_ones(roots):
    s = summary(roots)
    out = render_terminal(s)
    assert "secrets: 4 unique (3 known key formats, 1 possible), 4 occurrences" in out
    known, possible = out.index("known key formats (3)"), out.index("possible (1)")
    assert known < out.index("pattern or checksum match") < out.index("rotate the credential") < possible < out.index("Review these")
    assert "saved local record of a session" in out and "No match in the session records" not in out
    html = render_html(s)
    assert html.index("Known key formats") < html.index("rotate the credential") < html.index("Possible") < html.index("Review these")
    assert "3 known key formats, 1 possible" in html


def test_rotate_advice_only_for_known_formats():
    out = render_terminal(run_audit([item("DB_PASSWORD=hunter22x")]))
    assert "possible (1)" in out and "Review these" in out
    assert "rotate" not in out and "known key formats (" not in out
    out = render_terminal(run_audit([item("key AKIAIOSFODNN7EXAMPLE")]))
    assert "rotate the credential" in out and "Review these" not in out


def test_each_secret_is_listed_under_the_file_it_was_first_seen_in():
    items = [
        item("key AKIAIOSFODNN7EXAMPLE", "/t/a.jsonl:16"),
        item("token ghp_1234567890abcdefghijklmnopqrstuvwxyz", "/t/a.jsonl:3"),
        item("key AKIAIOSFODNN7EXAMPLE", "/t/b.jsonl:2"),
        item("DB_PASSWORD=hunter22x", "/t/b.jsonl:9"),
    ]
    s = run_audit(items, key=b"k" * 32)
    lines = render_terminal(s).splitlines()
    at = lines.index("/t/a.jsonl")
    aws, gh = (hmac.new(b"k" * 32, v.encode(), hashlib.sha256).hexdigest()[:12] for v in ("AKIAIOSFODNN7EXAMPLE", "ghp_1234567890abcdefghijklmnopqrstuvwxyz"))
    assert lines[at + 1].split() == [":16", "SECRET", f"#{aws}", "x2"]
    assert lines[at + 2].split() == [":3", "SECRET", f"#{gh}", "x1"]
    assert lines.index("/t/b.jsonl") > lines.index("possible (1)")  # b.jsonl only for the possible one


def test_the_home_folder_is_shown_as_a_tilde(tmp_path, monkeypatch):
    home = tmp_path / "home" / "jdoe"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    s = run_audit([item("key AKIAIOSFODNN7EXAMPLE", f"{home}/.claude/projects/x/s.jsonl:3", project=f"{home}/work/shop")])
    for rendered in (render_terminal(s), render_html(s)):
        assert str(home) not in rendered and "jdoe" not in rendered
        assert "~/.claude/projects/x/s.jsonl" in rendered and "~/work/shop" in rendered


# ---- Claude Code settings files ----


@pytest.fixture
def settings_home(roots, tmp_path):
    """A user folder named like ~/.claude (its projects next to the settings) and a project of the transcripts with settings."""
    claude, codex = roots
    user = tmp_path / "u" / ".claude"
    (user / "projects").mkdir(parents=True)
    shutil.copytree(claude, user / "projects", dirs_exist_ok=True)
    project = tmp_path / "work" / "shop"
    (project / ".claude").mkdir(parents=True)
    line = {"type": "user", "message": {"role": "user", "content": "hello"}, "cwd": str(project), "sessionId": "s2",
            "timestamp": "2026-10-05T10:00:00.000Z"}
    (user / "projects" / "-work-shop").mkdir()
    (user / "projects" / "-work-shop" / "s2.jsonl").write_text(json.dumps(line) + "\n")
    return user, project, codex


def audit_settings(settings_home, *extra):
    user, _, codex = settings_home
    return main(["audit", "--claude-dir", str(user / "projects"), "--codex-dir", str(codex), *extra])


def test_audit_reads_the_settings_of_the_user_and_of_the_projects(settings_home, capsys):
    user, project, _ = settings_home
    (user / "settings.json").write_text('{"env": {"OPENAI_API_KEY": "sk-zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONM"}}')
    local = project / ".claude" / "settings.local.json"
    local.write_text('{\n "permissions": {"allow": [\n  "Bash(curl -H \\"Authorization: Bearer Zq8vXk2mPw9rTb4nLs7dHc3fGj6y\\" x)"\n ]}\n}\n')
    before = local.read_bytes(), local.stat().st_mtime_ns
    assert audit_settings(settings_home) == 0
    out = capsys.readouterr().out
    assert "claude-settings: SECRET 2" in out
    lines = out.splitlines()
    assert lines[lines.index(str(local)) + 1].split()[:2] == [":3", "SECRET"]
    assert lines[lines.index(str(user / "settings.json")) + 1].split()[:2] == [":1", "SECRET"]
    assert "can reach git with the project" in out
    assert "Zq8vXk2mPw9rTb4nLs7dHc3fGj6y" not in out and "sk-zyxwvuts" not in out
    assert (local.read_bytes(), local.stat().st_mtime_ns) == before  # read only


def test_a_secret_in_the_user_settings_alone_gives_no_hint_about_git(settings_home, capsys):
    user, _, _ = settings_home
    (user / "settings.local.json").write_text('{"env": {"GITHUB_TOKEN": "ghp_1234567890abcdefghijklmnopqrstuvwxyz"}}')
    assert audit_settings(settings_home, "--since", "2030-01-01") == 0  # settings are read whatever the period
    out = capsys.readouterr().out
    assert "claude-settings: SECRET 1" in out and "git" not in out


def test_the_settings_findings_are_in_the_html_report(settings_home, tmp_path):
    _, project, _ = settings_home
    (project / ".claude" / "settings.json").write_text('{"env": {"DB_PASSWORD": "hunter22x"}}')
    target = tmp_path / "audit.html"
    assert audit_settings(settings_home, "--html", str(target)) == 0
    page = target.read_text()
    assert "claude-settings" in page and "can reach git with the project" in page and "hunter22x" not in page


def test_the_report_of_a_synthetic_home_fits_100_columns(tmp_path, monkeypatch, capsys):
    import importlib.util

    script = Path(__file__).parents[2] / "scripts" / "demo" / "make_home.py"
    if not script.is_file():
        pytest.skip("the demo generator is not in the source archive")
    spec = importlib.util.spec_from_file_location("make_home", script)
    make_home = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(make_home)
    home = tmp_path / "home"
    make_home.write_home(home)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    assert main(["audit", "--claude-dir", str(home / ".claude" / "projects"), "--codex-dir", str(home / ".codex" / "sessions")]) == 0
    out = capsys.readouterr().out
    assert "known key formats (" in out and str(home) not in out
    assert "  ~/work/acme-api: " in out and "not checked" not in out and "not on a local disk" not in out
    assert main(["audit", "--claude-dir", str(home / ".claude" / "projects"), "--html", str(home / "audit.html")]) == 0
    assert capsys.readouterr().out.endswith("report: ~/audit.html\n")
    assert max(len(line) for line in out.splitlines()) <= 100, out


# ---- a report to share: no user name, no value, no control character; what was not checked shows ----

from html import unescape  # noqa: E402

from boxed.audit.paths import show_locator, show_path  # noqa: E402


def encoded(path):
    return "".join(c if c.isascii() and c.isalnum() else "-" for c in str(path))


def test_paths_show_no_user_name_and_no_value_but_keep_what_finds_the_file(tmp_path, monkeypatch):
    home = tmp_path / "home" / "jdoe"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    shop, mail, keyed = f"{home}/work/shop", "/work/ivan.petrov@acme.com", "/srv/AKIAIOSFODNN7EXAMPLE/app"
    projects = home / ".claude" / "projects"
    items = [
        item("key AKIAIOSFODNN7EXAMPLE", f"{projects}/{encoded(shop)}/0b9e-s1.jsonl:3", project=shop),
        item("token ghp_1234567890abcdefghijklmnopqrstuvwxyz", f"{projects}/{encoded(mail)}/0b9e-s2.jsonl:7", project=mail),
        item("DB_PASSWORD=hunter22y", f"{projects}/{encoded(keyed)}/0b9e-s3.jsonl:9", project=keyed),
        item("DB_PASSWORD=hunter22x", f"{projects}/{encoded(home / 'old')}/0b9e-s4.jsonl:2", project=encoded(home / "old")),
    ]
    s = run_audit(items)
    for rendered in (render_terminal(s), unescape(render_html(s))):
        for leak in ("jdoe", str(tmp_path), "ivan", "petrov", "acme-com", "AKIAIOSFODNN7EXAMPLE"):
            assert leak not in rendered, leak
        for shown in ("~/.claude/projects/~-work-shop/0b9e-s1.jsonl", "~/work/shop", "/work/<EMAIL>", "-work-<EMAIL>/0b9e-s2.jsonl",
                      "/srv/<SECRET>/app", "-srv-<SECRET>-app/0b9e-s3.jsonl", "~/.claude/projects/~-old/0b9e-s4.jsonl"):
            assert shown in rendered, shown
    assert show_locator(f"{projects}/{encoded(shop)}/0b9e-s1.jsonl:3", shop) == ("~/.claude/projects/~-work-shop/0b9e-s1.jsonl", "3")


def test_control_characters_from_a_transcript_are_escaped(tmp_path):
    evil = "/work/app\x1b[2K\rclean\n:1  nothing here‮"
    s = run_audit([item("key AKIAIOSFODNN7EXAMPLE", "/t/s\x1b]0;x\x07.jsonl:4", project=evil)])
    out = render_terminal(s)
    assert not any(c in out for c in "\x1b\r\x07‮") and "\\x1b[2K\\x0dclean\\x0a" in out and "\\u202e" in out
    assert "/t/s\\x1b]0;x\\x07.jsonl" in out.splitlines()
    assert show_path("/a\tb") == "/a\\x09b"
    page = render_html(s)
    assert "\x1b" not in page and "\\x1b" in page


def test_one_value_is_one_secret_whatever_kind_the_rules_gave_it():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.c2lnbmF0dXJlZGVtbw"
    s = run_audit([item(f"see {jwt} here", "/t/a.jsonl:1"), item(f"Authorization: Bearer {jwt}", "/t/a.jsonl:2")], key=b"k" * 32)
    assert sorted(h.kind for h in s.secrets) == ["JWT", "SECRET"]  # the rule of Bearer headers takes it as a secret
    out = render_terminal(s)
    assert "secrets: 1 unique (1 known key formats, 0 possible), 2 occurrences" in out
    lines = out.splitlines()
    assert lines[lines.index("/t/a.jsonl") + 1].split() == [":1", "JWT", f"#{s.secrets[0].hmac_prefix}", "x2"]


def settings_item(text, project="/p"):
    return SentItem("claude-settings", "", project, "settings.json", None, "user_settings", text, f"{project}/.claude/settings.json:1")


def test_a_key_found_only_in_a_settings_file_is_not_called_sent():
    s = run_audit([settings_item("OPENAI_API_KEY: sk-zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONM")])
    for rendered in (render_terminal(s), render_html(s)):
        assert "Remove these from the settings file. No match in the session records checked for this report." in rendered
        assert "rotate" not in rendered and "record of a session" not in rendered
        assert "boxed does not check that a value is real or still valid" in rendered
    both = [item("key AKIAIOSFODNN7EXAMPLE"), settings_item("AWS: AKIAIOSFODNN7EXAMPLE")]
    out = render_terminal(run_audit(both))
    assert "In a saved local record of a session: if real, rotate the credential or call the card issuer." in out
    assert "Remove these" not in out and "known key formats (1)" in out


def test_what_was_there_and_not_checked_is_in_both_reports(settings_home, tmp_path, capsys):
    user, project, _ = settings_home
    (user / "settings.json").write_text("{ not json")
    (project / ".claude" / "settings.local.json").write_text('{"env": {"PAD": "' + "x" * (4 * 1024 * 1024) + '"}}')
    line = {"type": "user", "message": {"content": "hi"}, "cwd": "//fileserver.example.test/team/app", "sessionId": "s3"}
    (user / "projects" / "-team-app").mkdir()
    (user / "projects" / "-team-app" / "s3.jsonl").write_text(json.dumps(line) + "\n")
    target = tmp_path / "audit.html"
    assert audit_settings(settings_home, "--html", str(target)) == 3  # an incomplete report: the exit code of an anomaly
    out = capsys.readouterr().out
    assert "not checked (the report is incomplete):\n  settings files: 1 too big, 1 not JSON\n" in out
    assert "  project folders: 1 not on a local disk\n" in out
    page = target.read_text()
    assert "not checked (the report is incomplete)" in page and "settings files: 1 too big, 1 not JSON" in page
    assert "project folders: 1 not on a local disk" in page


def test_nothing_left_unread_adds_no_line(roots):
    assert "not checked" not in render_terminal(summary(roots))


def test_a_complete_audit_that_finds_nothing_says_so_and_exits_0(tmp_path, capsys):
    (tmp_path / "claude" / "-work-quiet").mkdir(parents=True)
    line = {"type": "user", "message": {"content": "plain words"}, "cwd": str(tmp_path / "work" / "quiet")}
    (tmp_path / "claude" / "-work-quiet" / "s.jsonl").write_text(json.dumps(line) + "\n")
    page = tmp_path / "audit.html"
    assert main(["audit", "--claude-dir", str(tmp_path / "claude"), "--codex-dir", str(tmp_path / "none"), "--html", str(page)]) == 0
    out = capsys.readouterr().out
    assert "found: nothing\n" in out and "not checked" not in out and "nothing found in what was read" not in out
    assert "nothing found in what was read" not in page.read_text()


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="a closed folder needs POSIX permissions and no root")
def test_an_audit_that_could_not_read_everything_exits_3_and_says_nothing_was_found_only_in_what_was_read(tmp_path, capsys):
    closed = tmp_path / "claude" / "-work-closed"
    closed.mkdir(parents=True)
    (closed / "s.jsonl").write_text("{}\n")
    closed.chmod(0)
    page = tmp_path / "audit.html"
    try:
        code = main(["audit", "--claude-dir", str(tmp_path / "claude"), "--codex-dir", str(tmp_path / "none"), "--html", str(page)])
    finally:
        closed.chmod(0o700)
    out = capsys.readouterr().out
    assert code == 3
    assert "not checked (the report is incomplete):" in out
    assert "nothing found in what was read\n" in out and "found: nothing" not in out
    text = page.read_text()
    assert "not checked (the report is incomplete)" in text and "nothing found in what was read" in text


def test_nothing_read_at_all_is_incomplete_too():
    stats = Counter({"folders_disk_unknown": 1})
    s = run_audit([], stats=stats)
    assert s.incomplete
    assert "nothing found in what was read" in render_terminal(s) and "nothing found in what was read" in render_html(s)
    assert not run_audit([]).incomplete


def test_the_settings_of_a_project_are_read_whatever_the_period(settings_home, capsys):
    _, project, _ = settings_home
    (project / ".claude" / "settings.json").write_text('{"env": {"GITHUB_TOKEN": "ghp_1234567890abcdefghijklmnopqrstuvwxyz"}}')
    assert audit_settings(settings_home, "--since", "2030-01-01") == 0
    out = capsys.readouterr().out
    assert "0 items checked" in out and "claude-settings: SECRET 1" in out and "can reach git with the project" in out


def test_a_project_named_only_by_answers_has_its_settings_read(tmp_path, capsys):
    project = tmp_path / "work" / "quiet"
    (project / ".claude").mkdir(parents=True)
    (project / ".claude" / "settings.json").write_text('{"env": {"DB_PASSWORD": "hunter22x"}}')
    folder = tmp_path / "claude" / "-work-quiet"
    folder.mkdir(parents=True)
    line = {"type": "assistant", "message": {"content": [{"type": "text", "text": "done"}]}, "cwd": str(project)}
    (folder / "s.jsonl").write_text(json.dumps(line) + "\n")
    assert main(["audit", "--claude-dir", str(tmp_path / "claude"), "--codex-dir", str(tmp_path / "none")]) == 0
    assert "claude-settings: SECRET 1" in capsys.readouterr().out


def test_without_a_keychain_one_value_gets_one_hash_in_both_passes(settings_home, capsys, monkeypatch):
    user, project, _ = settings_home
    (project / ".claude" / "settings.json").write_text('{"env": {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"}}')

    def broken():
        raise RuntimeError("no keychain")

    monkeypatch.setattr("boxed.cli.default_keystore", broken)
    assert audit_settings(settings_home) == 0
    out, err = capsys.readouterr()
    assert "no keychain: prefixes are random for this run" in err
    # the AWS key of the transcript and of the settings file is one secret with two occurrences, not two secrets
    assert "secrets: 4 unique (3 known key formats, 1 possible), 5 occurrences" in out


def test_a_damaged_audit_key_is_told_apart_from_a_missing_keychain(roots, tmp_path, capsys, monkeypatch):
    from boxed.keys import InsecureFileKeyStore

    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "audit-mac-key.key").write_text("c2hvcnQ=")  # 5 bytes, no key of 32
    monkeypatch.setattr("boxed.cli.default_keystore", lambda: InsecureFileKeyStore(keys))
    claude, codex = roots
    assert main(["audit", "--claude-dir", str(claude), "--codex-dir", str(codex)]) == 0
    err = capsys.readouterr().err
    assert "the audit key in the keychain cannot be used: prefixes are random for this run" in err and "no keychain" not in err


def test_the_role_of_what_was_found_is_in_the_report(roots):
    s = summary(roots)
    assert "by role: tool_result 5, user_prompt 3, attachment 1, instructions 1" in render_terminal(s)
    assert "<h2>By role</h2>" in render_html(s) and "<td>instructions</td>" in render_html(s)
