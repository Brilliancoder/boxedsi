import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from boxed import workspace as workspace_module
from boxed.config import ProjectConfig
from boxed.journal import Journal
from boxed.keys import InsecureFileKeyStore
from boxed.vault import Vault
from boxed.workspace import (
    MARKER_FILE,
    create_workspace,
    drop_workspace,
    SyncReport,
    list_workspaces,
    load_workspace,
    sync_back,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="boxed workspace is not supported on Windows yet")
NOT_ROOT = pytest.mark.skipif(getattr(os, "geteuid", lambda: 1)() == 0, reason="root is not stopped by file rights")

SECRETS = [b"hunter22", b"AKIAIOSFODNN7EXAMPLE", b"ivan.petrov@acme.com", b"anna@acme.com", b"203.0.113.7"]


@pytest.fixture
def env(tmp_path):
    repo = tmp_path / "client-acme-repo"
    (repo / "logs").mkdir(parents=True)
    (repo / "src").mkdir()
    (repo / "bin").mkdir()
    (repo / "legacy").mkdir()
    (repo / ".env").write_text("DB_PASSWORD=hunter22\nAPI_KEY=AKIAIOSFODNN7EXAMPLE\n")
    (repo / "logs" / "app.log").write_text("login ivan.petrov@acme.com from 203.0.113.7\nlogin anna@acme.com\n")
    (repo / "src" / "app.py").write_text("def send():\n    return 'ivan.petrov@acme.com'\n")
    (repo / "bin" / "blob.bin").write_bytes(b"\x00\x01\x02binary")
    (repo / "legacy" / "cp1251.txt").write_bytes("Привет, ivan@acme.com".encode("cp1251"))
    (repo / "crlf.txt").write_bytes(b"line one ivan.petrov@acme.com\r\nline two\r\n")
    (repo / "big.txt").write_bytes(b"a" * (5 * 1024 * 1024 + 1))
    os.symlink(repo / "src" / "app.py", repo / "link.txt")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    keys = InsecureFileKeyStore(tmp_path / "keys")
    home = tmp_path / "home"
    home.mkdir()
    vault = Vault(home / "vault.db", keys)
    journal = Journal(home / "journal.jsonl", keys)
    report = create_workspace(repo, level=2, config=ProjectConfig(), vault=vault, journal=journal, home=home)
    return repo, home, vault, journal, report


def sync(env, **kw):
    _, home, vault, journal, report = env
    return sync_back(report.workspace.id, vault=vault, journal=journal, home=home, **kw)


def mirror_bytes(mirror: Path) -> bytes:
    return b"".join(p.read_bytes() for p in mirror.rglob("*") if p.is_file() and not p.is_symlink())


def test_mirror_has_no_originals(env):
    repo, _, _, _, report = env
    ws = report.workspace
    data = mirror_bytes(ws.mirror)
    assert all(s not in data for s in SECRETS)
    assert ws.mirror.name == f"ws-{ws.id}" and repo.name not in str(ws.mirror)
    assert (ws.mirror / MARKER_FILE).exists()
    assert report.copied == 4 and report.markers_by_kind["EMAIL"] >= 3


def test_skipped_report(env):
    _, _, _, _, report = env
    skipped = dict(report.skipped)
    assert skipped == {
        "bin/blob.bin": "binary",
        "legacy/cp1251.txt": "non-utf8",
        "link.txt": "symlink",
        "big.txt": "too-large",
    }
    for rel in skipped:
        assert not (report.workspace.mirror / rel).exists()


def test_sync_writes_change_with_restore(env):
    repo, _, _, _, report = env
    m = report.workspace.mirror / "src" / "app.py"
    m.write_text(m.read_text().replace("def send():", "def send_mail():"))
    r = sync(env)
    assert r.written == ["src/app.py"] and r.conflicts == [] and r.refused == []
    assert (repo / "src" / "app.py").read_text() == "def send_mail():\n    return 'ivan.petrov@acme.com'\n"


def test_sync_conflict(env):
    repo, _, _, _, report = env
    (repo / "src" / "app.py").write_text("def send():\n    return 'ivan.petrov@acme.com'\n# local change\n")
    m = report.workspace.mirror / "src" / "app.py"
    m.write_text(m.read_text() + "# agent change\n")
    r = sync(env)
    assert r.conflicts == ["src/app.py"] and r.written == []
    assert (repo / "src" / "app.py").read_text().endswith("# local change\n")


def test_sync_refuses_unknown_marker(env):
    repo, _, _, _, report = env
    m = report.workspace.mirror / "logs" / "app.log"
    m.write_text(m.read_text() + "contact [EMAIL_9]\n")
    r = sync(env)
    assert [rel for rel, _ in r.refused] == ["logs/app.log"]
    assert r.refused[0][1].unknown == ["[EMAIL_9]"]
    assert "[EMAIL_9]" not in (repo / "logs" / "app.log").read_text()
    r = sync(env, force=True)
    assert r.written == ["logs/app.log"]
    restored = (repo / "logs" / "app.log").read_text()
    assert "[EMAIL_9]" in restored and "ivan.petrov@acme.com" in restored


def test_sync_new_file_created(env):
    repo, _, vault, _, report = env
    ws = report.workspace
    (ws.mirror / "notes").mkdir()
    (ws.mirror / "notes" / "new.md").write_text("ping [EMAIL_1]")
    r = sync(env)
    assert r.created == ["notes/new.md"]
    assert (repo / "notes" / "new.md").read_text() == "ping " + vault.load_map(ws.scope).original_for("[EMAIL_1]")


def test_sync_delete_requires_flag(env):
    repo, _, _, _, report = env
    (report.workspace.mirror / "logs" / "app.log").unlink()
    assert sync(env).deleted == []
    assert (repo / "logs" / "app.log").exists()
    assert sync(env, delete=True).deleted == ["logs/app.log"]
    assert not (repo / "logs" / "app.log").exists()


def test_crlf_preserved(env):
    repo, _, _, _, report = env
    m = report.workspace.mirror / "crlf.txt"
    m.write_bytes(m.read_bytes().replace(b"line two", b"line 2"))
    sync(env)
    assert (repo / "crlf.txt").read_bytes() == b"line one ivan.petrov@acme.com\r\nline 2\r\n"


def test_dry_run_writes_nothing(env):
    repo, _, _, _, report = env
    before = (repo / "src" / "app.py").read_bytes()
    m = report.workspace.mirror / "src" / "app.py"
    m.write_text(m.read_text() + "# agent change\n")
    assert sync(env, dry_run=True).written == ["src/app.py"]
    assert (repo / "src" / "app.py").read_bytes() == before
    assert sync(env).written == ["src/app.py"]


def test_sync_refuses_symlink_in_mirror(env, tmp_path):
    repo, _, _, _, report = env
    outside = tmp_path / "outside.txt"
    outside.write_text("not for the repo")
    os.symlink(outside, report.workspace.mirror / "evil.txt")
    r = sync(env)
    assert "evil.txt" in [rel for rel, _ in r.refused]
    assert not (repo / "evil.txt").exists()


def test_list_and_load(env):
    _, home, _, _, report = env
    ws = report.workspace
    assert [w.id for w in list_workspaces(home)] == [ws.id]
    assert load_workspace(ws.id, home) == ws


def test_drop_removes_mirror_state_and_scope(env):
    _, home, vault, _, report = env
    ws = report.workspace
    drop_workspace(ws.id, vault=vault, home=home)
    assert not ws.mirror.exists()
    assert list_workspaces(home) == []
    assert ws.scope not in vault.scopes()


def test_workspace_cli(tmp_path, capsys):
    import re

    from boxed.cli import main

    repo = tmp_path / "plain-dir"
    repo.mkdir()
    (repo / "a.txt").write_text("mail ivan.petrov@acme.com\n")
    assert main(["workspace", "create", str(repo)]) == 0
    out = capsys.readouterr().out
    ws_id = re.search(r"workspace (\w+) created", out).group(1)
    mirror = Path(re.search(r"mirror: (.+)", out).group(1))
    assert "ivan.petrov@acme.com" not in (mirror / "a.txt").read_text()
    (mirror / "a.txt").write_text((mirror / "a.txt").read_text() + "more\n")
    assert main(["workspace", "sync", ws_id]) == 0
    assert (repo / "a.txt").read_text() == "mail ivan.petrov@acme.com\nmore\n"
    assert main(["workspace", "list"]) == 0 and ws_id in capsys.readouterr().out
    assert main(["workspace", "drop", ws_id]) == 0
    assert not mirror.exists()


def test_sync_skips_tool_dirs_and_ignored_paths(env):
    repo, _, _, _, report = env
    m = report.workspace.mirror
    (repo / ".gitignore").write_text("build/\n")
    for rel, data in {
        ".git/hooks/pre-commit": b"#!/bin/sh\necho hi\n",
        "__pycache__/m.cpython-313.pyc": b"\x00\x01pyc",
        ".venv/lib/x.py": b"x = 1\n",
        "node_modules/p/index.js": b"module.exports = 1\n",
        "build/out.txt": b"generated\n",
    }.items():
        (m / rel).parent.mkdir(parents=True, exist_ok=True)
        (m / rel).write_bytes(data)
    r = sync(env)
    assert r.written == [] and r.created == [] and r.refused == []
    assert not (repo / ".git" / "hooks" / "pre-commit").exists()
    assert not (repo / "build").exists() and not (repo / ".venv").exists()


def test_state_hashes_of_originals_are_keyed(env):
    import hashlib
    import json as _json

    repo, home, _, _, report = env
    state = (home / "state" / f"{report.workspace.id}.json").read_text()
    plain = hashlib.sha256((repo / ".env").read_bytes()).hexdigest()
    assert plain not in state
    assert _json.loads(state)["files"][".env"]["orig_sha"]


# git without the developer's own config: no signing, no hooks, no LFS filter
GIT_ENV = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.com",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.com",
}


def make_project(tmp_path, files, *, git=True, track=False):
    """git=False: a plain folder. track=True: every file, ignored or not, is committed in the git repo."""
    repo = tmp_path / "proj"
    for rel, text in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    if git:
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
    if track:
        subprocess.run(["git", "-C", str(repo), "add", "-f", "-A"], check=True, env=GIT_ENV)
        subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "files"], check=True, env=GIT_ENV, capture_output=True)
    return repo


def make_ws(tmp_path, files, *, git=True, track=False):
    repo = make_project(tmp_path, files, git=git, track=track)
    keys = InsecureFileKeyStore(tmp_path / "keys")
    home = tmp_path / "home"
    home.mkdir()
    vault, journal = Vault(home / "vault.db", keys), Journal(home / "journal.jsonl", keys)
    return repo, home, vault, journal, create_workspace(repo, level=2, config=ProjectConfig(), vault=vault, journal=journal, home=home)


def test_file_names_are_masked_in_the_mirror(tmp_path):
    _, home, _, _, report = make_ws(tmp_path, {"exports/ivan.petrov@acme.com.csv": "id\n1\n", "logs/203.0.113.7.log": "ok\n"})
    mirror = report.workspace.mirror
    assert (mirror / "exports" / "[EMAIL_1].csv").is_file() and (mirror / "logs" / "[IP_1].log").is_file()
    assert "ivan.petrov" not in (home / "state" / f"{report.workspace.id}.json").read_text()


def test_sync_restores_masked_file_names(tmp_path):
    repo, home, vault, journal, report = make_ws(tmp_path, {"exports/ivan.petrov@acme.com.csv": "id\n1\n"})
    mirror = report.workspace.mirror
    (mirror / "exports" / "[EMAIL_1].csv").write_text("id\n1\n2\n")
    (mirror / "exports" / "[EMAIL_1]-summary.txt").write_text("total 2\n")
    r = sync_back(report.workspace.id, vault=vault, journal=journal, home=home)
    assert r.written == ["exports/ivan.petrov@acme.com.csv"] and r.created == ["exports/ivan.petrov@acme.com-summary.txt"]
    assert (repo / "exports" / "ivan.petrov@acme.com.csv").read_text() == "id\n1\n2\n"


def test_sync_refuses_a_name_with_an_unknown_marker(tmp_path):
    repo, home, vault, journal, report = make_ws(tmp_path, {"a.txt": "x\n"})
    (report.workspace.mirror / "[EMAIL_9].txt").write_text("y\n")
    r = sync_back(report.workspace.id, vault=vault, journal=journal, home=home)
    assert [rel for rel, _ in r.refused] == ["[EMAIL_9].txt"] and not (repo / "[EMAIL_9].txt").exists()


def test_state_with_plain_names_still_syncs(env):  # workspaces made before name masking
    repo, *_, report = env
    (report.workspace.mirror / "src" / "app.py").write_text("print('ok')\n")
    assert sync(env).written == ["src/app.py"] and (repo / "src" / "app.py").read_text() == "print('ok')\n"


def test_sync_refuses_broken_marker(env):
    repo, *_, report = env
    p = report.workspace.mirror / "src" / "app.py"
    p.write_text(p.read_text().replace("[EMAIL_1]", "[EMAIL_1"))
    assert [rel for rel, _ in sync(env).refused] == ["src/app.py"]
    assert "ivan.petrov@acme.com" in (repo / "src" / "app.py").read_text()


def test_sync_only_limits_force_to_named_files(env):
    repo, *_, report = env
    mirror = report.workspace.mirror
    (mirror / "src" / "app.py").write_text("x = '[EMAIL_9]'\n")
    (mirror / "logs" / "app.log").write_text("login [email_1]\n")
    r = sync(env, force=True, only={"src/app.py"})
    assert r.written == ["src/app.py"] and r.refused == []
    assert "[email_1]" not in (repo / "logs" / "app.log").read_text()
    assert [rel for rel, _ in sync(env).refused] == ["logs/app.log"]


def test_diff_preview_shows_the_restored_change(env):
    repo, *_, report = env
    p = report.workspace.mirror / "src" / "app.py"
    p.write_text(p.read_text().replace("'\n", "'  # checked\n"))
    r = sync(env, dry_run=True, diff=True)
    assert "+    return 'ivan.petrov@acme.com'  # checked" in r.diffs["src/app.py"]
    assert "# checked" not in (repo / "src" / "app.py").read_text()


def test_sync_reports_files_deleted_in_the_mirror(env):
    *_, report = env
    (report.workspace.mirror / "src" / "app.py").unlink()
    r = sync(env)
    assert r.missing == ["src/app.py"] and r.deleted == []


def test_sync_cli_hints_force_only_for_marker_problems(tmp_path, capsys):
    import re

    from boxed.cli import main

    repo = tmp_path / "plain-dir"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("x = 'ivan.petrov@acme.com'\n")
    assert main(["workspace", "create", str(repo)]) == 0
    out = capsys.readouterr().out
    ws_id = re.search(r"workspace (\w+) created", out).group(1)
    mirror = Path(re.search(r"mirror: (.+)", out).group(1))
    os.symlink(mirror / "src" / "app.py", mirror / "peek.txt")
    (mirror / "src" / "app.py").write_text("x = '[EMAIL_9]'\n")
    assert main(["workspace", "sync", ws_id]) == 3
    err = capsys.readouterr().err.splitlines()
    assert any("peek.txt" in line and "--force" not in line for line in err)
    assert any("src/app.py" in line and "--force" in line for line in err)


def test_diff_of_a_crlf_file_shows_only_the_changed_line(env):
    *_, report = env
    p = report.workspace.mirror / "crlf.txt"
    p.write_bytes(p.read_bytes().replace(b"line two", b"line 2"))
    d = sync(env, dry_run=True, diff=True).diffs["crlf.txt"]
    assert "-line two\n+line 2\n" in d and "-line one" not in d


def test_diff_without_trailing_newline_keeps_lines_apart(tmp_path):
    repo, home, vault, journal, report = make_ws(tmp_path, {"a.txt": "x", "b.txt": "y"})
    for name in ("a.txt", "b.txt"):
        (report.workspace.mirror / name).write_text((report.workspace.mirror / name).read_text() + " edited")
    r = sync_back(report.workspace.id, vault=vault, journal=journal, home=home, dry_run=True, diff=True)
    assert "-x\n+x edited\n" in r.diffs["a.txt"] and all(d.endswith("\n") for d in r.diffs.values())


def test_ini_sections_sync_back_without_force(tmp_path):
    repo, home, vault, journal, report = make_ws(tmp_path, {"app.ini": "[SERVER_1]\nhost = db.example.com\n"})
    p = report.workspace.mirror / "app.ini"
    assert p.read_text().startswith("[SERVER_1]\n")
    p.write_text(p.read_text() + "port = 5432\n")
    assert sync_back(report.workspace.id, vault=vault, journal=journal, home=home).written == ["app.ini"]


def test_sync_refuses_when_the_vault_lost_the_scope(tmp_path):
    repo, home, vault, journal, report = make_ws(tmp_path, {"a.txt": "mail ivan.petrov@acme.com\n"})
    vault.delete_scope(report.workspace.scope)
    (report.workspace.mirror / "a.txt").write_text("x\n")
    with pytest.raises(ValueError, match="no markers"):
        sync_back(report.workspace.id, vault=vault, journal=journal, home=home)
    assert (repo / "a.txt").read_text() == "mail ivan.petrov@acme.com\n"


def test_only_normalises_paths_and_reports_typos(env):
    *_, report = env
    p = report.workspace.mirror / "src" / "app.py"
    p.write_text(p.read_text() + "# more\n")
    r = sync(env, only={"./src/app.py", "nope.txt"})
    assert r.written == ["src/app.py"] and r.unmatched == ["nope.txt"]


# files that git tracks inside the folders a mirror never looks into
TOOL_FOLDER_FILES = {
    "node_modules/pkg/index.js": "module.exports = 1\n",
    "packages/app/node_modules/dep/index.js": "module.exports = 2\n",
    ".venv/lib/site.py": "x = 1\n",
    "src/__pycache__/app.txt": "cached\n",
}


def mirror_files(mirror: Path) -> set[str]:
    """Every file in the mirror as the file system lists it, without boxed's own two."""
    found = {p.relative_to(mirror).as_posix() for p in mirror.rglob("*") if p.is_file() or p.is_symlink()}
    return found - {MARKER_FILE, ".claude/settings.local.json"}


def recorded_files(home: Path, report) -> set[str]:
    return set(json.loads((home / "state" / f"{report.workspace.id}.json").read_text())["files"])


def test_git_project_leaves_out_tracked_files_in_tool_folders(tmp_path):
    files = {"src/app.py": "print('hi')\n", "README.md": "readme\n", **TOOL_FOLDER_FILES}
    _, home, _, _, report = make_ws(tmp_path, files, track=True)
    assert mirror_files(report.workspace.mirror) == {"src/app.py", "README.md"}
    assert recorded_files(home, report) == {"src/app.py", "README.md"}
    assert report.copied == 2 and report.skipped == []


def test_git_and_plain_folders_copy_the_same_files(tmp_path):
    files = {
        "src/app.py": "print('hi')\n",
        "docs/node_modules": "a file that shares the name of a tool folder\n",  # only folders are left out
        "lib/__pycache__": "so does this one\n",
        "vendor/.git/hooks/pre-commit": "#!/bin/sh\n",
        **TOOL_FOLDER_FILES,
    }
    for name in ("g", "p"):
        (tmp_path / name).mkdir()
    in_git = make_ws(tmp_path / "g", files, track=True)[4].workspace.mirror
    in_plain = make_ws(tmp_path / "p", files, git=False)[4].workspace.mirror
    assert mirror_files(in_plain) == {"src/app.py", "docs/node_modules", "lib/__pycache__"}
    assert mirror_files(in_git) == mirror_files(in_plain)


def test_a_fresh_copy_of_a_git_project_reports_no_file_as_deleted(tmp_path):
    _, home, vault, journal, report = make_ws(tmp_path, {"src/app.py": "x = 1\n", **TOOL_FOLDER_FILES}, track=True)
    for delete in (False, True):
        r = sync_back(report.workspace.id, vault=vault, journal=journal, home=home, dry_run=True, delete=delete)
        assert r.missing == [] and r.deleted == [] and r.conflicts == []


def test_sync_delete_keeps_tracked_files_in_tool_folders(tmp_path):
    files = {"src/app.py": "x = 1\n", **TOOL_FOLDER_FILES}
    repo, home, vault, journal, report = make_ws(tmp_path, files, track=True)
    r = sync_back(report.workspace.id, vault=vault, journal=journal, home=home, delete=True)
    assert r.deleted == [] and r.missing == [] and r.conflicts == []
    assert {rel: (repo / rel).read_text() for rel in files} == files


def old_version_records(ws, rels):
    """The state an earlier boxed made for a git project: tracked files under tool folders, copied into the mirror and recorded."""
    repo, home, vault, _, report = ws
    path = home / "state" / f"{report.workspace.id}.json"
    state = json.loads(path.read_text())
    for rel in rels:
        data = (repo / rel).read_bytes()
        (report.workspace.mirror / rel).parent.mkdir(parents=True, exist_ok=True)
        (report.workspace.mirror / rel).write_bytes(data)
        state["files"][rel] = {"orig_sha": vault.mac(data), "masked_sha": hashlib.sha256(data).hexdigest()}
    path.write_text(json.dumps(state))


@pytest.mark.parametrize("the_agent_removed_them", [False, True])
def test_records_under_tool_folders_from_an_earlier_version_are_never_deleted(tmp_path, the_agent_removed_them):
    files = {"src/app.py": "x = 1\n", **TOOL_FOLDER_FILES}
    ws = make_ws(tmp_path, files, track=True)
    repo, home, _, _, report = ws
    old_version_records(ws, TOOL_FOLDER_FILES)
    if the_agent_removed_them:
        for top in ("node_modules", ".venv", "packages", "src/__pycache__"):
            shutil.rmtree(report.workspace.mirror / top)
    r = sync(ws, delete=True)
    assert r.deleted == [] and r.missing == [] and r.conflicts == []
    assert {rel: (repo / rel).read_text() for rel in files} == files
    assert recorded_files(home, report) == {"src/app.py"}  # a sync without dry_run drops the records


def test_sync_refuses_when_the_mirror_folder_is_gone(tmp_path):
    files = {"src/app.py": "x = 1\n", "README.md": "hi\n"}
    ws = make_ws(tmp_path, files, track=True)
    repo, _, _, _, report = ws
    shutil.rmtree(report.workspace.mirror)
    with pytest.raises(ValueError, match="mirror folder"):
        sync(ws, delete=True)
    assert {rel: (repo / rel).read_text() for rel in files} == files


def refused_mirror(ws, files):
    """sync refuses, with or without --delete, and every file of the project is still there."""
    repo = ws[0]
    for delete in (False, True):
        with pytest.raises(ValueError, match="not the folder boxed made"):
            sync(ws, delete=delete)
    assert {rel: (repo / rel).read_text() for rel in files} == files


def test_sync_refuses_a_mirror_that_is_a_link_to_an_empty_folder(tmp_path):
    files = {"src/app.py": "x = 1\n", "README.md": "hi\n"}
    ws = make_ws(tmp_path, files, track=True)
    shutil.rmtree(ws[4].workspace.mirror)
    (tmp_path / "empty").mkdir()
    os.symlink(tmp_path / "empty", ws[4].workspace.mirror)
    refused_mirror(ws, files)


def test_sync_refuses_a_mirror_deleted_and_made_again_empty(tmp_path):
    files = {"src/app.py": "x = 1\n", "README.md": "hi\n"}
    ws = make_ws(tmp_path, files, track=True)
    shutil.rmtree(ws[4].workspace.mirror)
    ws[4].workspace.mirror.mkdir()
    refused_mirror(ws, files)


@pytest.mark.parametrize("marker", [None, "garbage", "[]", "{}", '{"id": 5}', '{"id": "ffffffff"}'])
def test_sync_refuses_a_mirror_whose_marker_is_missing_damaged_or_another_workspaces(tmp_path, marker):
    files = {"src/app.py": "x = 1\n", "README.md": "hi\n"}
    ws = make_ws(tmp_path, files, track=True)
    marker_file = ws[4].workspace.mirror / MARKER_FILE
    if marker is None:
        marker_file.unlink()
    else:
        marker_file.write_text(marker)
    (ws[4].workspace.mirror / "src" / "app.py").unlink()
    refused_mirror(ws, files)


def test_sync_delete_does_not_follow_a_link_out_of_the_project(tmp_path):
    ws = make_ws(tmp_path, {"src/app.py": "x = 1\n"}, track=True)
    repo, _, _, _, report = ws
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "app.py").write_text("x = 1\n")  # the same text the mirror held
    (repo / "src" / "app.py").unlink()
    (repo / "src").rmdir()
    os.symlink(outside, repo / "src")
    (report.workspace.mirror / "src" / "app.py").unlink()
    r = sync(ws, delete=True)
    assert r.deleted == [] and [rel for rel, _ in r.refused] == ["src/app.py"]
    assert (outside / "app.py").read_text() == "x = 1\n"


def test_sync_delete_does_not_follow_a_link_inside_the_project(tmp_path):
    ws = make_ws(tmp_path, {"src/app.py": "x = 1\n", "lib/app.py": "x = 1\n"}, track=True)
    repo, _, _, _, report = ws
    shutil.rmtree(repo / "src")
    os.symlink(repo / "lib", repo / "src")  # src/app.py now names lib/app.py, which the agent did not delete
    (report.workspace.mirror / "src" / "app.py").unlink()
    r = sync(ws, delete=True)
    assert r.deleted == [] and r.conflicts == ["src/app.py"]
    assert (repo / "lib" / "app.py").read_text() == "x = 1\n"


def test_sync_delete_keeps_originals_when_a_mirror_folder_became_a_link(tmp_path):
    files = {"src/app.py": "x = 1\n", "keep.py": "k\n"}
    ws = make_ws(tmp_path, files, track=True)
    repo, _, _, _, report = ws
    shutil.rmtree(report.workspace.mirror / "src")
    os.symlink(tmp_path / "nowhere", report.workspace.mirror / "src")  # where src/app.py went is unknown
    r = sync(ws, delete=True)
    assert r.deleted == [] and r.missing == [] and [rel for rel, _ in r.refused] == ["src"]
    assert {rel: (repo / rel).read_text() for rel in files} == files


def test_sync_delete_keeps_originals_when_a_mirror_folder_cannot_be_read(tmp_path):
    files = {"src/app.py": "x = 1\n", "keep.py": "k\n"}
    ws = make_ws(tmp_path, files, track=True)
    repo, _, _, _, report = ws
    locked = report.workspace.mirror / "src"
    locked.chmod(0o000)  # boxed cannot look in: "permission denied" does not say that a file is gone
    try:
        r = sync(ws, delete=True)
    finally:
        locked.chmod(0o755)
    assert r.deleted == [] and r.missing == []
    assert {rel: (repo / rel).read_text() for rel in files} == files


@NOT_ROOT
def test_mirror_folders_boxed_cannot_read_are_reported(tmp_path):
    files = {"src/app.py": "x = 1\n", "d/e/f.txt": "f\n", "keep.py": "k\n"}
    ws = make_ws(tmp_path, files, track=True)
    repo, _, _, _, report = ws
    mirror = report.workspace.mirror
    (mirror / "node_modules" / "p").mkdir(parents=True)  # a tool folder is never looked at, so it is never reported
    (mirror / "node_modules").chmod(0o000)
    (mirror / "src").chmod(0o000)
    (mirror / "d" / "e").chmod(0o000)
    (mirror / "keep.py").write_text("k edited\n")
    try:
        r = dry_then_real(ws, delete=True)
    finally:
        for locked in ("node_modules", "src", "d/e"):
            (mirror / locked).chmod(0o755)
    assert r.unreadable == ["d/e", "src"] and r.written == ["keep.py"] and r.deleted == [] and r.missing == []
    assert {rel: (repo / rel).read_text() for rel in files if rel != "keep.py"} == {k: v for k, v in files.items() if k != "keep.py"}


@NOT_ROOT
def test_only_limits_the_report_of_unreadable_folders_to_its_paths(tmp_path):
    ws = make_ws(tmp_path, {"src/app.py": "x = 1\n", "d/e/f.txt": "f\n", "keep.py": "k\n"}, track=True)
    mirror = ws[4].workspace.mirror
    (mirror / "src").chmod(0o000)
    (mirror / "d" / "e").chmod(0o000)
    try:
        assert sync(ws, only={"keep.py"}).unreadable == []  # the folders are none of its business
        assert sync(ws, only={"src/app.py"}).unreadable == ["src"]  # the path it names lies in one
        assert sync(ws, only={"d/e/f.txt", "keep.py"}).unreadable == ["d/e"]
        assert sync(ws).unreadable == ["d/e", "src"]
    finally:
        (mirror / "src").chmod(0o755)
        (mirror / "d" / "e").chmod(0o755)


def test_a_mirror_without_unreadable_folders_reports_none(env):
    assert sync(env).unreadable == []


@NOT_ROOT
def test_cli_sync_reports_unreadable_mirror_folders_and_exits_with_the_conflict_code(tmp_path, capsys):
    import re

    from boxed.cli import main

    repo = make_project(tmp_path, {"src/app.py": "x = 1\n", "keep.py": "k\n"}, track=True)
    assert main(["workspace", "create", str(repo)]) == 0
    out = capsys.readouterr().out
    ws_id = re.search(r"workspace (\w+) created", out).group(1)
    mirror = Path(re.search(r"mirror: (.+)", out).group(1))
    (mirror / "src").chmod(0o000)
    try:
        assert main(["workspace", "sync", ws_id, "--delete"]) == 3
    finally:
        (mirror / "src").chmod(0o755)
    seen = capsys.readouterr()
    assert seen.out == "" and seen.err == "unreadable src: boxed cannot look into this folder of the mirror, so nothing in it was synced\n"
    assert (repo / "src" / "app.py").exists()


def test_sync_refuses_a_mirror_whose_own_folder_cannot_be_read(tmp_path):
    files = {"src/app.py": "x = 1\n", "keep.py": "k\n"}
    ws = make_ws(tmp_path, files, track=True)
    mirror = ws[4].workspace.mirror
    mirror.chmod(0o000)  # the marker cannot be read, so boxed cannot tell that this is the mirror
    try:
        refused_mirror(ws, files)
    finally:
        mirror.chmod(0o755)


def test_sync_delete_never_touches_a_file_added_to_the_project_after_the_copy(tmp_path):
    ws = make_ws(tmp_path, {"src/app.py": "x = 1\n"}, track=True)
    repo, _, _, _, report = ws
    later = {"later.txt": "added later\n", "src/later.py": "y = 2\n", "node_modules/late.js": "z\n"}
    for rel, text in later.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    r = sync(ws, delete=True)
    assert r.deleted == [] and r.missing == [] and r.conflicts == []
    (report.workspace.mirror / "later.txt").write_text("the agent made the same name\n")
    assert sync(ws, delete=True).conflicts == ["later.txt"]  # a name that is taken is a conflict, not a record
    (report.workspace.mirror / "later.txt").unlink()
    r = sync(ws, delete=True)
    assert r.deleted == [] and r.missing == [] and r.conflicts == []
    assert {rel: (repo / rel).read_text() for rel in later} == later


def test_sync_delete_never_touches_originals_that_create_did_not_copy(env):
    repo, *_, report = env
    mirror = report.workspace.mirror
    not_copied = ("bin/blob.bin", "legacy/cp1251.txt", "big.txt", "link.txt")  # binary, non-utf8, too large, a link
    before = {rel: (repo / rel).read_bytes() for rel in not_copied}
    for rel in not_copied:  # the agent makes files under the same names, and later removes them
        (mirror / rel).parent.mkdir(parents=True, exist_ok=True)
        (mirror / rel).write_text("the agent's own text\n")
    r = sync(env, delete=True)
    assert sorted(r.conflicts) == sorted(not_copied) and r.deleted == [] and r.created == []
    for rel in not_copied:
        (mirror / rel).unlink()
    r = sync(env, delete=True)
    assert r.deleted == [] and r.missing == [] and r.conflicts == []
    assert {rel: (repo / rel).read_bytes() for rel in not_copied} == before and (repo / "link.txt").is_symlink()


def test_sync_does_not_write_through_a_link_inside_the_project(tmp_path):
    ws = make_ws(tmp_path, {"src/app.py": "x = 1\n", "lib/app.py": "x = 1\n"}, track=True)
    repo, _, _, _, report = ws
    shutil.rmtree(repo / "src")
    os.symlink(repo / "lib", repo / "src")  # src/app.py now names lib/app.py
    (report.workspace.mirror / "src" / "app.py").write_text("x = 2\n")
    (report.workspace.mirror / "src" / "new.txt").write_text("n\n")
    r = dry_then_real(ws)
    assert sorted(r.conflicts) == ["src/app.py", "src/new.txt"] and r.written == [] and r.created == []
    assert (repo / "lib" / "app.py").read_text() == "x = 1\n" and not (repo / "lib" / "new.txt").exists()


def test_sync_does_not_write_through_a_link_out_of_the_project(tmp_path):
    ws = make_ws(tmp_path, {"src/app.py": "x = 1\n"}, track=True)
    repo, _, _, _, report = ws
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "app.py").write_text("x = 1\n")
    shutil.rmtree(repo / "src")
    os.symlink(outside, repo / "src")
    (report.workspace.mirror / "src" / "app.py").write_text("x = 2\n")
    r = dry_then_real(ws)
    assert [rel for rel, _ in r.refused] == ["src/app.py"] and r.written == []
    assert (outside / "app.py").read_text() == "x = 1\n"


def test_sync_delete_follows_renames_made_in_the_mirror(tmp_path):
    files = {"src/app.py": "x = 1\n", "exports/ivan.petrov@acme.com.csv": "id\n1\n", "keep.py": "k\n", **TOOL_FOLDER_FILES}
    ws = make_ws(tmp_path, files, track=True)
    repo, _, _, _, report = ws
    mirror = report.workspace.mirror
    (mirror / "src" / "app.py").rename(mirror / "src" / "main.py")
    (mirror / "exports" / "[EMAIL_1].csv").rename(mirror / "exports" / "[EMAIL_1]-old.csv")
    r = sync(ws, delete=True)
    assert sorted(r.deleted) == ["exports/ivan.petrov@acme.com.csv", "src/app.py"]
    assert sorted(r.created) == ["exports/ivan.petrov@acme.com-old.csv", "src/main.py"]
    assert not (repo / "src" / "app.py").exists() and not (repo / "exports" / "ivan.petrov@acme.com.csv").exists()
    assert (repo / "src" / "main.py").read_text() == "x = 1\n"
    assert (repo / "exports" / "ivan.petrov@acme.com-old.csv").read_text() == "id\n1\n"
    assert all((repo / rel).exists() for rel in ("keep.py", *TOOL_FOLDER_FILES))


def test_cli_sync_delete_in_a_git_project_deletes_only_what_the_agent_deleted(tmp_path, capsys):
    import re

    from boxed.cli import main

    files = {"src/app.py": "x = 1\n", "src/util.py": "u = 1\n", **TOOL_FOLDER_FILES}
    repo = make_project(tmp_path, files, track=True)
    assert main(["workspace", "create", str(repo)]) == 0
    out = capsys.readouterr().out
    ws_id = re.search(r"workspace (\w+) created", out).group(1)
    mirror = Path(re.search(r"mirror: (.+)", out).group(1))
    (mirror / "src" / "app.py").unlink()
    assert main(["workspace", "sync", ws_id, "--delete"]) == 0
    seen = capsys.readouterr()
    assert seen.out.splitlines() == ["delete src/app.py"] and seen.err == ""
    assert not (repo / "src" / "app.py").exists()
    assert all((repo / rel).read_text() == files[rel] for rel in files if rel != "src/app.py")


def test_sync_delete_follows_a_folder_renamed_in_the_mirror(tmp_path):
    ws = make_ws(tmp_path, {"pkg/a.py": "a = 1\n", "pkg/b.py": "b = 2\n", "keep.py": "k\n", **TOOL_FOLDER_FILES}, track=True)
    repo, _, _, _, report = ws
    (report.workspace.mirror / "pkg").rename(report.workspace.mirror / "lib")
    r = sync(ws, delete=True)
    assert sorted(r.deleted) == ["pkg/a.py", "pkg/b.py"] and sorted(r.created) == ["lib/a.py", "lib/b.py"]
    assert (repo / "lib" / "b.py").read_text() == "b = 2\n" and not (repo / "pkg" / "a.py").exists()
    assert all((repo / rel).exists() for rel in ("keep.py", *TOOL_FOLDER_FILES))


def test_sync_delete_after_the_project_renamed_a_file(tmp_path):
    ws = make_ws(tmp_path, {"a.txt": "a\n", "b.txt": "b\n"}, track=True)
    repo, _, _, _, report = ws
    (repo / "a.txt").rename(repo / "c.txt")  # the person renames it in the project
    (report.workspace.mirror / "a.txt").unlink()  # the agent deletes the old name
    r = sync(ws, delete=True)
    assert r.deleted == [] and r.conflicts == ["a.txt"]
    assert (repo / "c.txt").read_text() == "a\n" and (repo / "b.txt").read_text() == "b\n"


def test_sync_delete_keeps_an_original_whose_mirror_name_changed_only_in_case(tmp_path):
    ws = make_ws(tmp_path, {"readme.txt": "hello\n", "other.txt": "o\n"}, track=True)
    repo, _, _, _, report = ws
    mirror = report.workspace.mirror
    if not (mirror / "README.txt").exists():
        pytest.skip("this file system tells README.txt from readme.txt")
    (mirror / "readme.txt").rename(mirror / "README.txt")  # one file with two spellings: the name is not gone
    r = sync(ws, delete=True)
    assert r.deleted == [] and r.conflicts
    assert (repo / "readme.txt").read_text() == "hello\n"


def test_the_record_of_mirrored_files_follows_every_sync(tmp_path):
    ws = make_ws(tmp_path, {"src/app.py": "x = 1\n", "old.txt": "o\n", **TOOL_FOLDER_FILES}, track=True)
    _, home, _, _, report = ws
    mirror = report.workspace.mirror
    assert recorded_files(home, report) == {"src/app.py", "old.txt"}
    (mirror / "notes.md").write_text("n\n")
    (mirror / "node_modules" / "x.js").parent.mkdir(parents=True)
    (mirror / "node_modules" / "x.js").write_text("a tool folder is never recorded\n")
    sync(ws, dry_run=True)
    assert recorded_files(home, report) == {"src/app.py", "old.txt"}
    sync(ws)
    assert recorded_files(home, report) == {"src/app.py", "old.txt", "notes.md"}
    (mirror / "old.txt").unlink()
    assert sync(ws).missing == ["old.txt"] and "old.txt" in recorded_files(home, report)  # kept: a later --delete can act
    assert sync(ws, delete=True).deleted == ["old.txt"]
    assert recorded_files(home, report) == {"src/app.py", "notes.md"}


def test_workspace_create_without_a_path_is_a_usage_error(boxed_env, capsys):
    from boxed.cli import main

    assert main(["workspace", "create"]) == 2
    err = capsys.readouterr().err
    assert err.startswith("boxed: error: create needs the project folder") and "NoneType" not in err
    assert not boxed_env.exists()  # no data folder, vault or key was made


def test_workspace_create_with_an_empty_path_is_a_usage_error(boxed_env, capsys):
    from boxed.cli import main

    assert main(["workspace", "create", ""]) == 2  # "" would otherwise be the current folder
    assert capsys.readouterr().err.startswith("boxed: error: create needs the project folder")
    assert not boxed_env.exists()


def test_workspace_create_refuses_a_path_that_is_not_a_folder(tmp_path, boxed_env, capsys):
    from boxed.cli import main

    note = tmp_path / "notes.txt"
    note.write_text("x\n")
    for path, text in ((tmp_path / "nope", "the project folder does not exist"), (note, "the project path is not a folder")):
        assert main(["workspace", "create", str(path)]) == 2
        assert capsys.readouterr().err == f"boxed: error: {text}\n"  # the path is not quoted
        assert not boxed_env.exists()


def test_workspace_create_accepts_a_relative_folder(tmp_path, monkeypatch, capsys):
    from boxed.cli import main

    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / "a.txt").write_text("hello\n")
    monkeypatch.chdir(tmp_path / "proj")
    assert main(["workspace", "create", "."]) == 0
    assert "1 files masked" in capsys.readouterr().out


@pytest.mark.parametrize("action", ["sync", "drop"])
def test_workspace_sync_and_drop_without_an_id_are_usage_errors(action, boxed_env, capsys):
    from boxed.cli import main

    assert main(["workspace", action]) == 2
    err = capsys.readouterr().err
    assert err.startswith(f"boxed: error: {action} needs the workspace id") and "None" not in err


def meet_in_the_mirror(monkeypatch, names):
    """Give the originals in names the mirror name of another file: what a.txt and A.txt do on a case-sensitive project volume when
    the mirror lies on a volume that reads the two names as one."""
    real = workspace_module.mask_path

    def meet(rel, markers, level=2, config=None):
        mirror_name, counts = real(rel, markers, level=level, config=config)
        return names.get(rel, mirror_name), counts

    monkeypatch.setattr(workspace_module, "mask_path", meet)


def test_create_skips_a_file_whose_name_in_the_mirror_is_taken(tmp_path, monkeypatch):
    meet_in_the_mirror(monkeypatch, {"y.txt": "x.txt"})
    ws = make_ws(tmp_path, {"x.txt": "one\n", "y.txt": "two\n", "z.txt": "z\n"})
    repo, home, _, _, report = ws
    assert report.copied == 2 and report.skipped == [("y.txt", "name-taken")]
    assert (report.workspace.mirror / "x.txt").read_text() == "one\n"  # the first file keeps the name
    assert recorded_files(home, report) == {"x.txt", "z.txt"}
    (report.workspace.mirror / "x.txt").unlink()
    r = sync(ws, delete=True)
    assert r.deleted == ["x.txt"] and (repo / "y.txt").read_text() == "two\n"  # the file that was never mirrored stays


def test_create_skips_a_file_whose_folder_in_the_mirror_is_a_file(tmp_path, monkeypatch):
    meet_in_the_mirror(monkeypatch, {"b/c": "a/c"})
    ws = make_ws(tmp_path, {"a": "file\n", "b/c": "inner\n"})
    _, home, _, _, report = ws
    assert report.copied == 1 and report.skipped == [("b/c", "name-taken")]
    assert recorded_files(home, report) == {"a"}


def test_create_workspace_refuses_a_missing_path_and_a_file(tmp_path):
    keys = InsecureFileKeyStore(tmp_path / "keys")
    home = tmp_path / "home"
    home.mkdir()
    vault, journal = Vault(home / "vault.db", keys), Journal(home / "journal.jsonl", keys)
    note = tmp_path / "notes.txt"
    note.write_text("x\n")
    for path, text in ((tmp_path / "nope", "the project folder does not exist"), (note, "the project path is not a folder")):
        with pytest.raises(ValueError, match=text):
            create_workspace(path, level=2, config=ProjectConfig(), vault=vault, journal=journal, home=home)
    assert not (home / "workspaces").exists() and list_workspaces(home) == []


def dry_then_real(ws, **kw):
    """A dry run says what the real run does: the same report, down to the diffs."""
    dry = sync(ws, dry_run=True, diff=True, **kw)
    real = sync(ws, diff=True, **kw)
    assert dry == real
    return real


def test_a_mirror_file_turned_into_a_folder_is_a_conflict_not_a_crash(tmp_path):
    ws = make_ws(tmp_path, {"a.txt": "a\n", "keep.py": "k\n", "z.txt": "z\n"}, track=True)
    repo, _, _, _, report = ws
    mirror = report.workspace.mirror
    (mirror / "a.txt").write_text("a edited\n")  # sorts before the folder, so the old run had written it when it died
    (mirror / "keep.py").unlink()
    (mirror / "keep.py").mkdir()
    (mirror / "keep.py" / "inner.txt").write_text("inner\n")
    (mirror / "z.txt").write_text("z edited\n")  # sorts after it
    r = dry_then_real(ws)
    assert r.conflicts == ["keep.py/inner.txt"] and r.created == [] and r.written == ["a.txt", "z.txt"]
    assert (repo / "keep.py").read_text() == "k\n" and not (repo / "keep.py" / "inner.txt").exists()
    assert (repo / "a.txt").read_text() == "a edited\n" and (repo / "z.txt").read_text() == "z edited\n"
    again = sync(ws, force=True)  # what the first run wrote is no conflict now, with --force or without
    assert again.written == [] and again.created == [] and again.conflicts == ["keep.py/inner.txt"]


@NOT_ROOT
def test_a_file_that_cannot_be_written_is_reported_and_sync_goes_on(tmp_path):
    ws = make_ws(tmp_path, {"a.txt": "a\n", "ro.txt": "r\n", "z.txt": "z\n"}, track=True)
    repo, _, _, _, report = ws
    for name in ("a.txt", "ro.txt", "z.txt"):
        (report.workspace.mirror / name).write_text(f"{name} edited\n")
    (repo / "ro.txt").chmod(0o444)
    try:
        r = sync(ws)
    finally:
        (repo / "ro.txt").chmod(0o644)
    assert r.failed == [("ro.txt", "Permission denied")] and r.written == ["a.txt", "z.txt"]
    assert (repo / "ro.txt").read_text() == "r\n" and (repo / "z.txt").read_text() == "z.txt edited\n"
    r = sync(ws)  # the rights are back: the file that failed is the one left, and no one else is said to have changed it
    assert r.written == ["ro.txt"] and r.conflicts == [] and r.failed == []


@NOT_ROOT
def test_a_mirror_file_boxed_cannot_read_is_reported_and_sync_goes_on(tmp_path):
    ws = make_ws(tmp_path, {"a.txt": "a\n", "locked.txt": "l\n", "z.txt": "z\n"}, track=True)
    repo, _, _, _, report = ws
    mirror = report.workspace.mirror
    (mirror / "a.txt").write_text("a edited\n")
    (mirror / "z.txt").write_text("z edited\n")
    (mirror / "locked.txt").chmod(0o000)
    try:
        r = sync(ws, delete=True)
    finally:
        (mirror / "locked.txt").chmod(0o644)
    assert r.failed == [("locked.txt", "Permission denied")] and r.written == ["a.txt", "z.txt"] and r.deleted == []
    assert (repo / "locked.txt").read_text() == "l\n"


def test_an_interrupted_sync_still_saves_the_state_and_the_journal(tmp_path, monkeypatch):
    ws = make_ws(tmp_path, {"a.txt": "a\n", "z.txt": "z\n"}, track=True)
    repo, home, vault, journal, report = ws
    for name in ("a.txt", "z.txt"):
        (report.workspace.mirror / name).write_text(f"{name} edited\n")
    records = len(journal.read()[0])
    real_mac, calls = Vault.mac, []

    def flaky(self, data):
        calls.append(1)
        if len(calls) == 3:  # a.txt: the original is looked at (1) and the new record is made (2); then z.txt is looked at
            raise RuntimeError("something nobody foresaw")
        return real_mac(self, data)

    monkeypatch.setattr(Vault, "mac", flaky)
    with pytest.raises(RuntimeError):
        sync(ws)
    monkeypatch.setattr(Vault, "mac", real_mac)
    assert (repo / "a.txt").read_text() == "a.txt edited\n" and (repo / "z.txt").read_text() == "z\n"
    saved = json.loads((home / "state" / f"{report.workspace.id}.json").read_text())["files"]
    assert saved["a.txt"]["orig_sha"] == vault.mac(b"a.txt edited\n")  # what was written is on the record
    assert len(journal.read()[0]) == records + 1
    r = sync(ws)
    assert r.written == ["z.txt"] and r.conflicts == [] and r.failed == []


@NOT_ROOT
def test_cli_sync_prints_failed_files_and_exits_with_the_conflict_code(tmp_path, capsys):
    import re

    from boxed.cli import main

    repo = make_project(tmp_path, {"a.txt": "a\n", "ro.txt": "r\n"}, track=True)
    assert main(["workspace", "create", str(repo)]) == 0
    out = capsys.readouterr().out
    ws_id = re.search(r"workspace (\w+) created", out).group(1)
    mirror = Path(re.search(r"mirror: (.+)", out).group(1))
    for name in ("a.txt", "ro.txt"):
        (mirror / name).write_text(f"{name} edited\n")
    (repo / "ro.txt").chmod(0o444)
    try:
        assert main(["workspace", "sync", ws_id]) == 3
    finally:
        (repo / "ro.txt").chmod(0o644)
    seen = capsys.readouterr()
    assert seen.out.splitlines() == ["write a.txt"] and seen.err.splitlines() == ["failed ro.txt: Permission denied"]


@NOT_ROOT
def test_a_dry_run_sees_a_read_only_folder_like_the_real_run(tmp_path):
    files = {"locked/x.txt": "x\n", "locked/w.txt": "w\n", "free/y.txt": "y\n", "ro.txt": "r\n"}
    ws = make_ws(tmp_path, files, track=True)
    repo, _, _, _, report = ws
    mirror = report.workspace.mirror
    (mirror / "locked" / "x.txt").unlink()  # a deletion in a folder that takes no change of names
    (mirror / "locked" / "new.txt").write_text("n\n")  # a new file in it
    (mirror / "locked" / "w.txt").write_text("w edited\n")  # an edit of a file that may be written: fine in that folder
    (mirror / "free" / "y.txt").unlink()
    (mirror / "ro.txt").write_text("r edited\n")
    (repo / "locked").chmod(0o555)
    (repo / "ro.txt").chmod(0o444)
    try:
        r = dry_then_real(ws, delete=True)
    finally:
        (repo / "locked").chmod(0o755)
        (repo / "ro.txt").chmod(0o644)
    assert sorted(r.failed) == [(p, "Permission denied") for p in ("locked/new.txt", "locked/x.txt", "ro.txt")]
    assert r.deleted == ["free/y.txt"] and r.written == ["locked/w.txt"] and r.created == []
    assert (repo / "locked" / "x.txt").exists() and not (repo / "free" / "y.txt").exists()


def scenario_file_deleted(repo, mirror):
    (mirror / "a.txt").unlink()


def scenario_file_renamed(repo, mirror):
    (mirror / "a.txt").rename(mirror / "a2.txt")


def scenario_folder_deleted(repo, mirror):
    shutil.rmtree(mirror / "d")


def scenario_folder_renamed(repo, mirror):
    (mirror / "d").rename(mirror / "d2")


def scenario_folder_turned_into_a_file(repo, mirror):
    shutil.rmtree(mirror / "d")
    (mirror / "d").write_text("now a file\n")


def scenario_file_turned_into_a_folder(repo, mirror):
    (mirror / "a.txt").unlink()
    (mirror / "a.txt").mkdir()
    (mirror / "a.txt" / "inner.txt").write_text("inner\n")


def scenario_mirror_folder_turned_into_a_link(repo, mirror):
    shutil.rmtree(mirror / "d")
    os.symlink(mirror.parent / "nowhere", mirror / "d")


def scenario_project_folder_turned_into_a_link(repo, mirror):
    (mirror / "d" / "b.txt").unlink()
    shutil.rmtree(repo / "d")
    os.symlink(repo / "keep-dir", repo / "d")


def scenario_original_changed_since(repo, mirror):
    (mirror / "a.txt").unlink()
    (repo / "a.txt").write_text("changed in the project\n")


def scenario_original_already_gone(repo, mirror):
    (mirror / "a.txt").unlink()
    (repo / "a.txt").unlink()


def scenario_edits_and_deletions_together(repo, mirror):
    (mirror / "a.txt").write_text("a edited\n")
    (mirror / "d" / "b.txt").unlink()
    (mirror / "new.txt").write_text("new\n")
    shutil.rmtree(mirror / "d" / "e")


DELETION_SCENARIOS = [
    scenario_file_deleted,
    scenario_file_renamed,
    scenario_folder_deleted,
    scenario_folder_renamed,
    scenario_folder_turned_into_a_file,
    scenario_file_turned_into_a_folder,
    scenario_mirror_folder_turned_into_a_link,
    scenario_project_folder_turned_into_a_link,
    scenario_original_changed_since,
    scenario_original_already_gone,
    scenario_edits_and_deletions_together,
]


@pytest.mark.parametrize("scenario", DELETION_SCENARIOS, ids=lambda f: f.__name__.removeprefix("scenario_"))
def test_a_dry_run_equals_the_real_run_on_deletions(tmp_path, scenario):
    ws = make_ws(tmp_path, {"a.txt": "a\n", "d/b.txt": "b\n", "d/e/c.txt": "c\n", "keep.txt": "k\n"}, track=True)
    repo, _, _, _, report = ws
    (repo / "keep-dir").mkdir()
    scenario(repo, report.workspace.mirror)
    for delete in (False, True):  # the same report whether the deletions are asked for or only listed
        assert dry_then_real(ws, delete=delete) != SyncReport()


def test_a_mirror_folder_turned_into_a_file_counts_as_deleted(tmp_path):
    ws = make_ws(tmp_path, {"src/app.py": "x = 1\n", "src/util.py": "u = 1\n", "keep.py": "k\n"}, track=True)
    repo, _, _, _, report = ws
    mirror = report.workspace.mirror
    shutil.rmtree(mirror / "src")
    (mirror / "src").write_text("now a file\n")
    plain = dry_then_real(ws)
    assert plain.conflicts == ["src"] and plain.missing == ["src/app.py", "src/util.py"] and plain.deleted == []
    r = dry_then_real(ws, delete=True)
    assert r.deleted == ["src/app.py", "src/util.py"] and r.conflicts == ["src"]  # the name src is taken in the project
    assert not (repo / "src" / "app.py").exists() and (repo / "src").is_dir() and (repo / "keep.py").exists()


def test_dry_run_of_drop_and_create_is_refused_and_changes_nothing(tmp_path, boxed_env, capsys):
    import re

    from boxed.cli import main
    from boxed.keys import default_keystore

    repo = tmp_path / "plain-dir"
    repo.mkdir()
    (repo / "a.txt").write_text("mail ivan.petrov@acme.com\n")
    assert main(["workspace", "create", str(repo)]) == 0
    out = capsys.readouterr().out
    ws_id = re.search(r"workspace (\w+) created", out).group(1)
    mirror = Path(re.search(r"mirror: (.+)", out).group(1))
    (mirror / "a.txt").write_text((mirror / "a.txt").read_text() + "not synced yet\n")
    scopes = Vault(boxed_env / "vault.db", default_keystore()).scopes()
    assert main(["workspace", "drop", ws_id, "--dry-run"]) == 2
    assert capsys.readouterr().err == "boxed: error: --dry-run works with sync only\n"
    assert (mirror / "a.txt").read_text().endswith("not synced yet\n")
    assert [ws.id for ws in list_workspaces(boxed_env)] == [ws_id]
    assert Vault(boxed_env / "vault.db", default_keystore()).scopes() == scopes
    other = tmp_path / "other-dir"
    other.mkdir()
    assert main(["workspace", "create", str(other), "--dry-run"]) == 2
    assert [ws.id for ws in list_workspaces(boxed_env)] == [ws_id]
    assert main(["workspace", "sync", ws_id, "--dry-run"]) == 0
    assert capsys.readouterr().out == "would write a.txt\n" and (repo / "a.txt").read_text() == "mail ivan.petrov@acme.com\n"
