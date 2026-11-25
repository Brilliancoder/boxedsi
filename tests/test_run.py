import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from boxed.config import ProjectConfig
from boxed.journal import Journal
from boxed.keys import default_keystore
from boxed.run import agent_env, build_agent_command, run_agent, sandbox_profile
from boxed.vault import Vault
from boxed.workspace import create_workspace

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="boxed run needs the macOS sandbox and is not supported on Windows yet")


@pytest.fixture
def ws_env(tmp_path, boxed_env):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".env").write_text("DB_PASSWORD=hunter22\n")
    (repo / "app.py").write_text("print('hi')\n")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    home = boxed_env
    home.mkdir(parents=True, exist_ok=True)
    keys = default_keystore()
    ws = create_workspace(
        repo, level=2, config=ProjectConfig(), vault=Vault(home / "vault.db", keys), journal=Journal(home / "journal.jsonl", keys), home=home
    ).workspace
    return repo.resolve(), home, ws


def test_sandbox_profile_escapes_paths(tmp_path):
    base = tmp_path.resolve()  # /tmp is a symlink on macOS; profiles always name real paths
    profile = sandbox_profile(base / 'm "x"', base / "o\\p", base / "h")
    assert f'(subpath "{base}/o\\\\p")' in profile
    assert f'"{base}/m \\"x\\""' in profile


def test_sandbox_profile_denies_original_and_vault(ws_env):
    repo, home, ws = ws_env
    profile = sandbox_profile(ws.mirror, repo, home)
    assert profile.startswith("(version 1)\n(allow default)")
    assert f'(subpath "{repo}")' in profile
    assert f'(subpath "{home.resolve() / "insecure-keys"}")' in profile
    # the MCP server runs inside the sandbox and must open the encrypted vault
    assert "vault.db" not in profile.split("(deny file-write* (subpath")[0]


@pytest.mark.skipif(sys.platform != "darwin" or not shutil.which("sandbox-exec"), reason="macOS sandbox-exec only")
def test_sandbox_blocks_original_at_os_level(ws_env):
    repo, home, ws = ws_env
    profile = home / "test.sb"
    profile.write_text(sandbox_profile(ws.mirror, repo, home))
    blocked = subprocess.run(["sandbox-exec", "-f", str(profile), "cat", str(repo / ".env")], capture_output=True, text=True)
    assert blocked.returncode != 0 and "hunter22" not in blocked.stdout
    allowed = subprocess.run(["sandbox-exec", "-f", str(profile), "cat", str(ws.mirror / ".env")], capture_output=True, text=True)
    assert allowed.returncode == 0 and "[SECRET_1]" in allowed.stdout
    write_out = subprocess.run(["sandbox-exec", "-f", str(profile), "touch", str(repo / "planted")], capture_output=True)
    assert write_out.returncode != 0 and not (repo / "planted").exists()


def test_build_agent_command(ws_env, tmp_path):
    _, home, ws = ws_env
    sb = tmp_path / "p.sb"
    claude = build_agent_command("claude", ["-p", "hi"], sb, agent_path="/bin/claude")
    assert claude[:4] == ["sandbox-exec", "-f", str(sb), "/bin/claude"]
    assert json.loads(claude[claude.index("--settings") + 1]) == {"sandbox": {"enabled": False}}
    assert claude[-2:] == ["-p", "hi"]
    codex = build_agent_command("codex", ["exec", "x"], sb, agent_path="/bin/codex")
    assert "--dangerously-bypass-approvals-and-sandbox" in codex and codex[-2:] == ["exec", "x"]


def test_run_requires_workspace_cwd(tmp_path, boxed_env):
    with pytest.raises(ValueError, match="workspace"):
        run_agent("claude", [], cwd=tmp_path, home=boxed_env)


@pytest.mark.skipif(sys.platform != "darwin" or not shutil.which("sandbox-exec"), reason="macOS sandbox-exec only")
def test_sandbox_keeps_agent_config_and_mirror_controls_read_only(ws_env, tmp_path, monkeypatch):
    repo, home, ws = ws_env
    fake_home = (tmp_path / "user").resolve()
    (fake_home / ".claude" / "projects").mkdir(parents=True)
    (fake_home / ".codex" / "sessions").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(fake_home))
    profile = home / "test2.sb"
    profile.write_text(sandbox_profile(ws.mirror, repo, home))

    def touch(path):
        return subprocess.run(["sandbox-exec", "-f", str(profile), "touch", str(path)], capture_output=True).returncode

    assert touch(fake_home / ".claude" / "projects" / "session.jsonl") == 0
    assert touch(fake_home / ".codex" / "sessions" / "rollout.jsonl") == 0
    assert touch(ws.mirror / "src.txt") == 0
    assert touch(fake_home / ".claude" / "settings.json") != 0
    assert touch(fake_home / ".codex" / "config.toml") != 0
    assert touch(ws.mirror / ".boxed-workspace") != 0
    assert touch(ws.mirror / ".claude" / "settings.local.json") != 0


# ---- the environment of the agent: what looks like a credential stays out, unless the agent signs in with it or you name it ----

ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/Users/someone",
    "LANG": "en_US.UTF-8",
    "PWD": "/Users/someone/work",
    "HTTPS_PROXY": "http://proxyuser:proxypass@proxy.example:3128",
    "GITHUB_TOKEN": "made-up-value",
    "DB_PASSWORD": "summer2024",
    "AWS_SECRET_ACCESS_KEY": "made-up-value",
    "SSH_AUTH_SOCK": "/private/tmp/agent.sock",
    "DATABASE_URL": "postgres://app:Xk9mQ2vLp@db.example:5432/app",
    "SOME_SETTING": "ghp_" + "a1B2c3D4e5F6g7H8i9J0" * 2,
    "ANTHROPIC_API_KEY": "made-up-value",
    "OPENAI_API_KEY": "made-up-value",
    "EDITOR": "vim",
}
ALWAYS_OUT = ["AWS_SECRET_ACCESS_KEY", "DATABASE_URL", "DB_PASSWORD", "GITHUB_TOKEN", "SOME_SETTING", "SSH_AUTH_SOCK"]


@pytest.mark.parametrize("agent,own,other", [("claude", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"), ("codex", "OPENAI_API_KEY", "ANTHROPIC_API_KEY")])
def test_the_agent_gets_no_credential_but_its_own_sign_in(agent, own, other):
    env, removed = agent_env(agent, ENV)
    assert removed == sorted([*ALWAYS_OUT, other])  # by name, or by a value the detectors take for a secret (a URL with a password, a GitHub token)
    assert env == {name: value for name, value in ENV.items() if name not in removed}
    assert own in env and "PATH" in env and "HOME" in env and "LANG" in env and "PWD" in env and "HTTPS_PROXY" in env


def test_keep_env_passes_a_named_variable():
    env, removed = agent_env("claude", ENV, keep=["GITHUB_TOKEN", "SSH_AUTH_SOCK"])
    assert env["GITHUB_TOKEN"] == ENV["GITHUB_TOKEN"] and env["SSH_AUTH_SOCK"] == ENV["SSH_AUTH_SOCK"]
    assert "GITHUB_TOKEN" not in removed and "DB_PASSWORD" in removed


@pytest.mark.parametrize("keep_args", [["--keep-env", "GITHUB_TOKEN", "claude"], ["claude", "--keep-env", "GITHUB_TOKEN"], ["claude", "--keep-env=GITHUB_TOKEN"]])
def test_boxed_run_starts_the_agent_with_the_filtered_environment_and_names_what_it_kept_out(ws_env, monkeypatch, capsys, keep_args):
    from boxed.cli import main

    _, _, ws = ws_env
    for name, value in ENV.items():
        monkeypatch.setenv(name, value)
    started = {}

    def call(cmd, cwd, env):
        started.update(cmd=cmd, cwd=cwd, env=env)
        return 0

    monkeypatch.setattr("boxed.run.shutil.which", lambda name: "/opt/fake/" + name)
    monkeypatch.setattr("boxed.run.subprocess.call", call)
    monkeypatch.chdir(ws.mirror)
    assert main(["run", *keep_args, "--", "-p", "hi"]) == 0
    env = started["env"]
    assert started["cmd"][-2:] == ["-p", "hi"] and "--keep-env" not in started["cmd"]
    assert env["GITHUB_TOKEN"] == ENV["GITHUB_TOKEN"] and env["ANTHROPIC_API_KEY"] == ENV["ANTHROPIC_API_KEY"]
    assert not {"DB_PASSWORD", "AWS_SECRET_ACCESS_KEY", "DATABASE_URL", "OPENAI_API_KEY", "SSH_AUTH_SOCK"} & set(env)
    assert env["PATH"] == ENV["PATH"] and "XDG_CACHE_HOME" in env and env["BOXED_HOME"] == os.environ["BOXED_HOME"]
    err = capsys.readouterr().err
    line = [row for row in err.splitlines() if "environment" in row]
    assert len(line) == 1 and line[0].startswith("boxed: kept out of the agent's environment: ")
    for name in ("DB_PASSWORD", "AWS_SECRET_ACCESS_KEY", "DATABASE_URL", "OPENAI_API_KEY"):
        assert name in line[0]
    assert not any(value in err for value in ("summer2024", "made-up-value", "Xk9mQ2vLp", "proxypass"))


# names written as one word (PGPASSWORD) or with a short credential part (MYSQL_PWD), with plain made-up passwords that the value
# detectors do not take for a secret: the name alone keeps them out
JOINED = {
    "PGPASSWORD": "Summer2024",
    "MYSQL_PWD": "Summer2024",
    "MYSQL_PASSWORD": "Summer2024",
    "DOCKER_AUTH_CONFIG": '{"auths": {}}',
    "NPM_TOKEN": "Summer2024",
    "AWS_SECRET_ACCESS_KEY": "Summer2024",
    "GH_TOKEN": "Summer2024",
    "SSHPASS": "Summer2024",
    "REDISCLI_AUTH": "Summer2024",
    "BW_SESSION": "Summer2024",
    "SENTRY_DSN": "Summer2024",
    "TWINE_PASSWORD": "Summer2024",
    "DBPASSWD": "Summer2024",
    "APPSECRET": "Summer2024",
    "VAULTTOKEN": "Summer2024",
}
# names that only look like one: they stay
NOT_CREDENTIALS = {
    "GIT_AUTHOR_NAME": "Someone",
    "TOKENIZERS_PARALLELISM": "false",
    "XDG_SESSION_TYPE": "tty",
    "KEYBOARD_LAYOUT": "us",
    "COMPASS_MODE": "on",
    "PGPASSFILE": "/Users/someone/.pgpass",  # where the password file is, not a password
}


def test_a_credential_name_written_as_one_word_is_kept_out_of_the_agent(ws_env, monkeypatch, capsys):
    from boxed.cli import main

    _, _, ws = ws_env
    for name in os.environ:
        if name not in ("BOXED_HOME", "BOXED_KEYSTORE", "HOME", "PATH"):
            monkeypatch.delenv(name, raising=False)
    for name, value in {**JOINED, **NOT_CREDENTIALS}.items():
        monkeypatch.setenv(name, value)
    started = {}
    monkeypatch.setattr("boxed.run.shutil.which", lambda name: "/opt/fake/" + name)
    monkeypatch.setattr("boxed.run.subprocess.call", lambda cmd, cwd, env: started.update(env=env) or 0)
    monkeypatch.chdir(ws.mirror)
    assert main(["run", "claude"]) == 0
    env = started["env"]
    assert not set(JOINED) & set(env)
    assert all(env[name] == value for name, value in NOT_CREDENTIALS.items())
    assert "Summer2024" not in capsys.readouterr().err
