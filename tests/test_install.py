import io
import json
import os
import shlex
import stat
import subprocess
import sys
import tomllib
from pathlib import Path, PureWindowsPath

import pytest

from boxed import __version__
from boxed.cli import main
from boxed.install import install_claude, install_codex, install_native_host, remove_native_host

REPO = Path(__file__).resolve().parents[1]
EXTENSION_ID = "abcdefghijklmnopabcdefghijklmnop"
NOT_HERE = "boxed install native-host works on macos and windows only"


@pytest.fixture(autouse=True)
def as_on_macos(macos):
    """The tests of this file pin the folders of macOS (or, with the windows fixture, the registry): on Linux too."""


def test_native_host_is_refused_where_it_is_not_supported(tmp_path, monkeypatch, capsys):
    """Linux: the browsers look in other folders, not tried with a real browser yet. Nothing is written in the macOS ones instead."""
    from boxed import platform

    monkeypatch.setattr(platform, "IS_MACOS", False)
    monkeypatch.setattr(platform, "IS_WINDOWS", False)
    monkeypatch.setenv("HOME", str(tmp_path / "user"))
    for call in (lambda: install_native_host(EXTENSION_ID, home=tmp_path / "user"),
                 lambda: install_native_host(EXTENSION_ID, dry_run=True, home=tmp_path / "user"),
                 lambda: remove_native_host(home=tmp_path / "user")):
        with pytest.raises(ValueError) as e:
            call()
        assert str(e.value) == NOT_HERE
    for argv in (["install", "native-host"], ["install", "native-host", "--extension-id", EXTENSION_ID], ["install", "native-host", "--remove"]):
        assert main(argv) == 2
        assert capsys.readouterr().err == f"boxed: error: {NOT_HERE}\n"
    assert not (tmp_path / "user").exists()


def test_plugin_json_valid():
    plugin = json.loads((REPO / "plugin" / ".claude-plugin" / "plugin.json").read_text())
    assert plugin["name"] == "boxed" and plugin["version"] == __version__
    mcp = json.loads((REPO / "plugin" / ".mcp.json").read_text())
    assert mcp["mcpServers"]["boxed"]["args"] == ["mcp"]
    market = json.loads((REPO / ".claude-plugin" / "marketplace.json").read_text())
    assert market["name"] == "boxed"
    assert market["plugins"][0]["name"] == "boxed" and market["plugins"][0]["source"] == "./plugin"
    skill = (REPO / "plugin" / "skills" / "boxed" / "SKILL.md").read_text()
    assert skill.startswith("---\nname: boxed\ndescription: ")


def test_the_plugin_has_one_hook_the_skills_check_at_session_start():
    """The guard hooks live in each mirror's settings (a plugin copy would fire twice); the plugin adds only its own event."""
    hooks = json.loads((REPO / "plugin" / "hooks" / "hooks.json").read_text())["hooks"]
    assert list(hooks) == ["SessionStart"]
    (group,) = hooks["SessionStart"]
    assert group["matcher"] == "startup|clear"
    (handler,) = group["hooks"]
    assert handler["type"] == "command" and "onFailure" not in handler
    assert handler["command"] == '"${CLAUDE_PLUGIN_ROOT}/hooks/run-boxed" hook skills-check'
    assert sorted(os.listdir(REPO / "plugin" / "hooks")) == ["hooks.json", "run-boxed"]


@pytest.mark.skipif(sys.platform == "win32", reason="the launcher is a sh script; boxed hook is not supported on Windows yet")
def test_the_launcher_runs_boxed_from_path_or_local_bin_and_is_silent_without_it(tmp_path):
    launcher = REPO / "plugin" / "hooks" / "run-boxed"
    assert os.access(launcher, os.X_OK)
    home, on_path, empty = tmp_path / "home", tmp_path / "on-path", tmp_path / "empty"
    for folder in (home / ".local" / "bin", on_path, empty):
        folder.mkdir(parents=True)
    for folder, word in ((on_path, "path"), (home / ".local" / "bin", "local")):
        stub = folder / "boxed"
        stub.write_text(f'#!/bin/sh\nread line\necho "{word} $* $line"\n')
        stub.chmod(0o755)

    def launch(path):
        env = {"HOME": str(home), "PATH": path}
        return subprocess.run(["/bin/sh", str(launcher), "hook", "skills-check"], input="{}\n", capture_output=True, text=True, env=env)

    found = launch(f"{on_path}:/usr/bin:/bin")
    assert (found.returncode, found.stdout, found.stderr) == (0, "path hook skills-check {}\n", "")
    found = launch(str(empty))  # SessionStart can run with a PATH that holds nothing useful
    assert (found.returncode, found.stdout, found.stderr) == (0, "local hook skills-check {}\n", "")
    (home / ".local" / "bin" / "boxed").unlink()
    found = launch(str(empty))
    assert (found.returncode, found.stdout, found.stderr) == (0, "", "")


def test_install_codex_idempotent_with_backup(tmp_path):
    cfg = tmp_path / "config.toml"
    original = 'model = "gpt-6-astra"\n\n[profiles.fast]\nmodel = "gpt-6-luna"\n'
    cfg.write_text(original)
    assert install_codex(cfg) is True
    assert (tmp_path / "config.toml.bak").read_text() == original
    data = tomllib.loads(cfg.read_text())
    assert data["model"] == "gpt-6-astra" and data["profiles"]["fast"]["model"] == "gpt-6-luna"
    assert data["mcp_servers"]["boxed"]["args"][-1] == "mcp"
    after = cfg.read_text()
    assert install_codex(cfg) is False
    assert cfg.read_text() == after


def test_install_codex_creates_missing_config(tmp_path):
    cfg = tmp_path / "codex" / "config.toml"
    assert install_codex(cfg) is True
    assert "boxed" in tomllib.loads(cfg.read_text())["mcp_servers"]
    assert not (tmp_path / "codex" / "config.toml.bak").exists()


def test_install_codex_dry_run_writes_nothing(tmp_path):
    cfg = tmp_path / "codex" / "config.toml"
    assert install_codex(cfg, dry_run=True) is True  # it would add the block
    assert not cfg.parent.exists()  # not the folder, not the file
    cfg.parent.mkdir()
    original = 'model = "gpt-6-astra"\n'
    cfg.write_text(original)
    assert install_codex(cfg, dry_run=True) is True
    assert cfg.read_text() == original
    assert [p.name for p in cfg.parent.iterdir()] == ["config.toml"]  # no .bak either
    assert install_codex(cfg) is True
    after = cfg.read_text()
    assert install_codex(cfg, dry_run=True) is False  # already there
    assert cfg.read_text() == after


def test_install_codex_dry_run_still_refuses_a_config_that_codex_cannot_parse(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[mcp_servers\n")
    with pytest.raises(tomllib.TOMLDecodeError):
        install_codex(cfg, dry_run=True)
    assert cfg.read_text() == "[mcp_servers\n" and [p.name for p in tmp_path.iterdir()] == ["config.toml"]


CODEX_CHILD = """
import sys
from pathlib import Path
from boxed.install import install_codex
print(install_codex(Path(sys.argv[1])))
"""


def test_install_codex_reads_and_writes_utf8_whatever_the_code_page_of_the_system_is(tmp_path):
    """A Codex config is UTF-8 (TOML says so). Where the code page is not (cp1251 on a Russian Windows, ASCII with LC_ALL=C), the
    letter "И" is not read as itself, or cannot be read at all. The code page is chosen as a program starts: so a program is started.
    "И" is D0 98 and "Ё" is D0 81 in UTF-8; cp1251 has nothing at 98 and cp1252 nothing at 81."""
    config = tmp_path / "config.toml"
    original = '# Иван, Ёлка\nmodel = "gpt-6-astra"\n'
    config.write_bytes(original.encode("utf-8"))
    environment = {**os.environ, "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0", "LC_ALL": "C"}
    done = subprocess.run([sys.executable, "-c", CODEX_CHILD, str(config)], env=environment, capture_output=True, timeout=120)
    assert done.returncode == 0 and done.stdout.strip() == b"True", done.stderr
    assert (tmp_path / "config.toml.bak").read_bytes() == original.encode("utf-8")
    written = config.read_text(encoding="utf-8")
    assert written.startswith(original) and "[mcp_servers.boxed]" in written


@pytest.mark.parametrize("dry_run", [False, True], ids=["install", "dry run"])
@pytest.mark.parametrize("target", ["claude", "codex"])
def test_windows_install_claude_and_codex_are_refused_before_anything_runs_or_is_written(windows, tmp_path, monkeypatch, capsys, target, dry_run):
    """The plugin commands are split with POSIX quoting and the Codex config is looked for through HOME: neither is made for Windows yet."""
    ran = []
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: ran.append(args))
    assert main(["install", target] + (["--dry-run"] if dry_run else [])) == 2
    out, err = capsys.readouterr()
    assert out == "" and err == f"boxed: error: boxed install {target} is not supported on Windows yet\n"
    assert ran == [] and list(tmp_path.iterdir()) == []  # tmp_path is the profile of the test: no .codex folder, no config


@pytest.mark.skipif(sys.platform == "win32", reason="the Claude Code plugin is not supported on Windows yet")
def test_install_claude_dry_run():
    cmds = install_claude(REPO, dry_run=True)
    assert cmds == [f"claude plugin marketplace add {REPO}", "claude plugin install boxed@boxed"]


def test_wheel_contains_plugin(tmp_path):
    import subprocess
    import zipfile

    subprocess.run(["uv", "build", "--wheel", "-o", str(tmp_path), "-q"], cwd=REPO, check=True)
    wheel = zipfile.ZipFile(next(tmp_path.glob("*.whl")))
    names = wheel.namelist()
    assert "boxed/_claude_plugin/.claude-plugin/marketplace.json" in names
    assert "boxed/_claude_plugin/plugin/.claude-plugin/plugin.json" in names
    assert "boxed/_claude_plugin/plugin/skills/boxed/SKILL.md" in names
    assert "boxed/_claude_plugin/plugin/hooks/hooks.json" in names
    launcher = wheel.getinfo("boxed/_claude_plugin/plugin/hooks/run-boxed")
    assert (launcher.external_attr >> 16) & 0o111 == 0o111  # installed executable, as Claude Code runs it directly


@pytest.mark.skipif(sys.platform == "win32", reason="pins the macOS folders, launcher and modes of the native host")
def test_install_native_host_manifests(tmp_path):
    home = tmp_path / "user"
    paths = install_native_host(EXTENSION_ID, home=home)
    assert paths == [
        home / "Library/Application Support/Google/Chrome/NativeMessagingHosts/si.boxed.host.json",
        home / "Library/Application Support/Microsoft Edge/NativeMessagingHosts/si.boxed.host.json",
    ]
    launcher = home / ".boxed/bin/boxed-native-host"
    for path in paths:
        manifest = json.loads(path.read_text())
        assert manifest.pop("description")
        assert manifest == {
            "name": "si.boxed.host",
            "path": str(launcher),
            "type": "stdio",
            "allowed_origins": [f"chrome-extension://{EXTENSION_ID}/"],
        }
    assert [stat.S_IMODE(p.stat().st_mode) for p in (launcher, launcher.parent, launcher.parent.parent)] == [0o700] * 3
    text = launcher.read_text()
    assert text.startswith("#!/bin/sh\n")
    assert f'exec {shlex.quote(sys.executable)} -P -m boxed.native_host "$@"\n' in text


@pytest.mark.skipif(sys.platform == "win32", reason="pins the macOS folders, launcher and modes of the native host")
def test_launcher_keeps_a_custom_boxed_home(tmp_path, monkeypatch, boxed_env):
    launcher = tmp_path / "user/.boxed/bin/boxed-native-host"
    install_native_host(EXTENSION_ID, browsers=("chrome",), home=tmp_path / "user")
    assert f"export BOXED_HOME={shlex.quote(str(boxed_env))}\n" in launcher.read_text()
    monkeypatch.delenv("BOXED_HOME")
    install_native_host(EXTENSION_ID, browsers=("chrome",), home=tmp_path / "user")
    assert "BOXED_HOME" not in launcher.read_text()


@pytest.mark.skipif(sys.platform == "win32", reason="pins the macOS folders, launcher and modes of the native host")
def test_install_native_host_dry_run_writes_nothing(tmp_path):
    home = tmp_path / "user"
    paths = install_native_host(EXTENSION_ID, dry_run=True, home=home)
    assert len(paths) == 2 and not home.exists()


@pytest.mark.parametrize(
    "bad",
    ["", "a" * 31, "a" * 33, "A" * 32, "q" * 32, "1" * 32, "a" * 32 + "\n", "a" * 31 + "/", f"chrome-extension://{EXTENSION_ID}/"],
)
def test_install_native_host_refuses_a_bad_extension_id(tmp_path, bad):
    with pytest.raises(ValueError, match="extension id"):
        install_native_host(bad, home=tmp_path / "user")
    assert not (tmp_path / "user").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="pins the macOS folders, launcher and modes of the native host")
def test_install_native_host_one_browser_and_unknown_browser(tmp_path):
    home = tmp_path / "user"
    (path,) = install_native_host(EXTENSION_ID, browsers=("edge",), home=home)
    assert "Microsoft Edge" in str(path) and not (home / "Library/Application Support/Google").exists()
    with pytest.raises(ValueError, match="browser"):
        install_native_host(EXTENSION_ID, browsers=("firefox",), home=tmp_path / "other")
    assert not (tmp_path / "other").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="pins the macOS folders, launcher and modes of the native host")
def test_install_native_host_again_replaces_the_id(tmp_path):
    home = tmp_path / "user"
    install_native_host(EXTENSION_ID, home=home)
    paths = install_native_host("p" * 32, home=home)
    assert all(json.loads(p.read_text())["allowed_origins"] == ["chrome-extension://" + "p" * 32 + "/"] for p in paths)


@pytest.mark.skipif(sys.platform == "win32", reason="pins the macOS folders, launcher and modes of the native host")
def test_launcher_write_does_not_follow_a_symlink(tmp_path):
    from boxed.install import install_native_host

    home = tmp_path / "home"
    (home / ".boxed" / "bin").mkdir(parents=True)
    victim = tmp_path / "victim.txt"
    victim.write_text("keep")
    victim.chmod(0o644)
    (home / ".boxed" / "bin" / "boxed-native-host").symlink_to(victim)
    install_native_host("a" * 32, home=home)
    launcher = home / ".boxed" / "bin" / "boxed-native-host"
    assert victim.read_text() == "keep" and victim.stat().st_mode & 0o777 == 0o644
    assert not launcher.is_symlink() and launcher.stat().st_mode & 0o777 == 0o700


def test_wheel_contains_the_extension(tmp_path):
    import subprocess
    import zipfile

    subprocess.run(["uv", "build", "--wheel", "-o", str(tmp_path), "-q"], cwd=REPO, check=True)
    names = zipfile.ZipFile(next(tmp_path.glob("*.whl"))).namelist()
    parts = [p.relative_to(REPO / "extension").parts for p in (REPO / "extension").rglob("*") if p.is_file()]
    shipped = {"boxed/_extension/" + "/".join(rel) for rel in parts
               if "test" not in rel and not any(part.startswith(".") for part in rel)}  # .DS_Store and other hidden files are not the extension's
    assert {"boxed/_extension/manifest.json", "boxed/_extension/icons/icon-128.png"} <= shipped
    assert shipped and shipped <= set(names), sorted(shipped - set(names))  # every file the extension loads, lib/ and icons/ included
    assert not any(n.startswith("boxed/_extension/test/") for n in names)


def test_sdist_holds_the_sources_only_and_builds_the_wheel(tmp_path):
    """The source archive is listed, not the whole folder: no desktop build, CI, demo or images. A wheel builds from it alone."""
    import subprocess
    import tarfile
    import zipfile

    subprocess.run(["uv", "build", "--sdist", "-o", str(tmp_path / "sdist"), "-q"], cwd=REPO, check=True)
    (archive,) = (tmp_path / "sdist").glob("*.tar.gz")
    assert archive.stat().st_size < 5_000_000
    with tarfile.open(archive) as tar:
        names = {name.split("/", 1)[1] for name in tar.getnames() if "/" in name}
    assert {"src/boxed/cli.py", "tests/conftest.py", "docs/guide/cli.md", "plugin/hooks/hooks.json", ".claude-plugin/marketplace.json",
            "extension/manifest.json", "extension/lib/protocol.js", "extension/icons/icon-128.png", "LICENSE", "NOTICE", "README.md",
            "pyproject.toml"} <= names
    for part in ("desktop/", ".github/", "scripts/demo/", "docs/assets/", "extension/test/", ".venv/"):
        assert not any(name.startswith(part) for name in names), part
    subprocess.run(["uv", "build", "--wheel", str(archive), "-o", str(tmp_path / "wheel"), "-q"], cwd=tmp_path, check=True)
    wheel = zipfile.ZipFile(next((tmp_path / "wheel").glob("*.whl"))).namelist()
    assert {"boxed/cli.py", "boxed/_extension/manifest.json", "boxed/_claude_plugin/plugin/hooks/hooks.json"} <= set(wheel)


def test_wheel_declares_the_apache_license(tmp_path):
    import subprocess
    import zipfile

    subprocess.run(["uv", "build", "--wheel", "-o", str(tmp_path), "-q"], cwd=REPO, check=True)
    wheel = zipfile.ZipFile(next(tmp_path.glob("*.whl")))
    names = wheel.namelist()
    metadata = wheel.read(next(n for n in names if n.endswith(".dist-info/METADATA"))).decode()
    assert "License-Expression: Apache-2.0" in metadata
    assert any(n.endswith(".dist-info/licenses/LICENSE") for n in names)
    assert any(n.endswith(".dist-info/licenses/NOTICE") for n in names)


# ---- Windows: one manifest, one launcher, and the registry of the user (HKCU) tells Chrome and Edge where they are ----

CHROME_KEY = r"Software\Google\Chrome\NativeMessagingHosts\si.boxed.host"
EDGE_KEY = r"Software\Microsoft\Edge\NativeMessagingHosts\si.boxed.host"
PLAIN_LAUNCHER = '@echo off\r\nchcp 65001 >nul\r\n"{python}" -P -m boxed.native_host %*\r\n'


def host_folder(home):
    return home / "AppData" / "Local" / "boxed" / "native-host"


def test_windows_install_writes_the_manifest_and_points_both_browsers_at_it(fake_winreg, tmp_path):
    home = tmp_path / "user"
    paths = install_native_host(EXTENSION_ID, home=home)
    manifest = host_folder(home) / "si.boxed.host.json"
    assert paths == [manifest, PureWindowsPath("HKCU\\" + CHROME_KEY), PureWindowsPath("HKCU\\" + EDGE_KEY)]
    assert fake_winreg.values == {CHROME_KEY: str(manifest), EDGE_KEY: str(manifest)}  # HKCU only: the fake knows no other root
    data = json.loads(manifest.read_text())
    assert data.pop("description")
    assert data == {
        "name": "si.boxed.host",
        "path": str(host_folder(home) / "boxed-native-host.cmd"),
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{EXTENSION_ID}/"],
    }


def test_windows_the_launcher_runs_this_python_and_ends_its_lines_as_cmd_wants(fake_winreg, tmp_path, monkeypatch):
    monkeypatch.delenv("BOXED_HOME")
    install_native_host(EXTENSION_ID, home=tmp_path / "user")
    launcher = host_folder(tmp_path / "user") / "boxed-native-host.cmd"
    assert launcher.read_bytes() == PLAIN_LAUNCHER.format(python=sys.executable).encode()  # CRLF whatever the system, no byte order mark


def test_windows_the_launcher_keeps_a_custom_boxed_home_and_doubles_the_percent_signs(fake_winreg, tmp_path, monkeypatch):
    monkeypatch.setenv("BOXED_HOME", str(tmp_path / "100%real" / "Иван"))  # a % starts a variable in a .cmd file; a name can have letters of any alphabet
    install_native_host(EXTENSION_ID, browsers=("chrome",), home=tmp_path / "user")
    text = (host_folder(tmp_path / "user") / "boxed-native-host.cmd").read_bytes()
    assert b'\r\nset "BOXED_HOME=' in text and b"100%%real" in text and b"100%real" not in text
    assert text.index(b"chcp 65001") < text.index("Иван".encode())  # the code page is switched before the first letter that needs it
    assert text.endswith(f'"{sys.executable}" -P -m boxed.native_host %*\r\n'.encode())


def test_windows_the_launcher_of_a_frozen_sidecar_calls_the_sidecar(fake_winreg, tmp_path, monkeypatch):
    monkeypatch.delenv("BOXED_HOME")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", r"C:\Program Files\Boxed\boxed.exe")
    install_native_host(EXTENSION_ID, home=tmp_path / "user")
    text = (host_folder(tmp_path / "user") / "boxed-native-host.cmd").read_bytes()
    assert text == b'@echo off\r\nchcp 65001 >nul\r\n"C:\\Program Files\\Boxed\\boxed.exe" native-host\r\n'  # no -m: a frozen program has none


def test_windows_one_browser_sets_one_key(fake_winreg, tmp_path):
    manifest, key = install_native_host(EXTENSION_ID, browsers=("edge",), home=tmp_path / "user")
    assert str(key) == "HKCU\\" + EDGE_KEY
    assert fake_winreg.values == {EDGE_KEY: str(manifest)}


def test_windows_dry_run_names_both_keys_and_writes_nothing(fake_winreg, tmp_path):
    _, *keys = install_native_host(EXTENSION_ID, dry_run=True, home=tmp_path / "user")
    assert [str(key) for key in keys] == ["HKCU\\" + CHROME_KEY, "HKCU\\" + EDGE_KEY]
    assert fake_winreg.values == {} and not (tmp_path / "user").exists()


@pytest.mark.parametrize(("extension_id", "browsers"), [("a" * 31, ("chrome",)), (EXTENSION_ID, ("firefox",))], ids=["id", "browser"])
def test_windows_a_bad_id_or_browser_is_refused_before_anything_is_written(fake_winreg, tmp_path, extension_id, browsers):
    with pytest.raises(ValueError):
        install_native_host(extension_id, browsers=browsers, home=tmp_path / "user")
    assert fake_winreg.values == {} and not (tmp_path / "user").exists()


def test_windows_a_link_at_the_manifest_or_the_launcher_is_replaced_never_followed(fake_winreg, tmp_path):
    home, victim = tmp_path / "user", tmp_path / "victim.txt"
    victim.write_text("keep")
    host_folder(home).mkdir(parents=True)
    for name in ("si.boxed.host.json", "boxed-native-host.cmd"):
        (host_folder(home) / name).symlink_to(victim)
    install_native_host(EXTENSION_ID, home=home)
    assert victim.read_text() == "keep"
    assert not any((host_folder(home) / name).is_symlink() for name in ("si.boxed.host.json", "boxed-native-host.cmd"))


def test_windows_remove_deletes_both_keys_and_the_folder_and_nothing_else(fake_winreg, tmp_path):
    home = tmp_path / "user"
    install_native_host(EXTENSION_ID, home=home)
    other = r"Software\Google\Chrome\NativeMessagingHosts\com.other.host"
    fake_winreg.values[other] = r"C:\other.json"  # another host of the same browser
    removed = remove_native_host(home=home)
    assert [str(path) for path in removed] == ["HKCU\\" + CHROME_KEY, "HKCU\\" + EDGE_KEY, str(host_folder(home))]
    assert fake_winreg.values == {other: r"C:\other.json"}
    assert not (home / "AppData" / "Local" / "boxed").exists()  # nothing of boxed is left, not even the empty folder above


def test_windows_remove_keeps_a_folder_that_holds_something_else(fake_winreg, tmp_path):
    home = tmp_path / "user"
    install_native_host(EXTENSION_ID, home=home)
    (host_folder(home) / "notes.txt").write_text("mine")
    (host_folder(home) / "draft.part").write_text("mine too")  # a part file that is not one of ours
    removed = remove_native_host(home=home)
    assert host_folder(home) not in removed and (host_folder(home) / "notes.txt").read_text() == "mine"
    assert sorted(path.name for path in host_folder(home).iterdir()) == ["draft.part", "notes.txt"]  # the manifest and the launcher are gone


def test_windows_remove_clears_the_part_files_an_interrupted_install_left(fake_winreg, tmp_path):
    home = tmp_path / "user"
    install_native_host(EXTENSION_ID, home=home)
    (host_folder(home) / "si.boxed.host.json.part").write_text("half")
    assert host_folder(home) in remove_native_host(home=home) and not host_folder(home).exists()


def test_windows_remove_does_not_reach_through_a_link_at_the_folder(fake_winreg, tmp_path):
    home, elsewhere = tmp_path / "user", tmp_path / "elsewhere"
    elsewhere.mkdir()
    for name in ("si.boxed.host.json", "boxed-native-host.cmd"):
        (elsewhere / name).write_text("not boxed's")
    host_folder(home).parent.mkdir(parents=True)
    host_folder(home).symlink_to(elsewhere, target_is_directory=True)
    fake_winreg.values[CHROME_KEY] = "C:\\somewhere.json"
    removed = remove_native_host(home=home)
    assert [str(path) for path in removed] == ["HKCU\\" + CHROME_KEY]  # the key goes; the folder is a link and is left as it is
    assert sorted(path.read_text() for path in elsewhere.iterdir()) == ["not boxed's"] * 2 and host_folder(home).is_symlink()


def test_windows_a_link_planted_at_the_part_name_is_never_written_through(fake_winreg, tmp_path, monkeypatch):
    home, victim = tmp_path / "user", tmp_path / "victim.txt"
    victim.write_text("keep")
    lstat, planted = os.lstat, []

    def lstat_then_plant_a_link(name, *args, **kwargs):  # the old part file was removed; a link takes its name right after the look
        try:
            found = lstat(name, *args, **kwargs)
        except OSError as error:
            found = error
        if os.fspath(name).endswith(".part") and not planted:
            planted.append(name)
            os.symlink(victim, name)
        if isinstance(found, OSError):
            raise found
        return found

    monkeypatch.setattr(os, "lstat", lstat_then_plant_a_link)
    with pytest.raises(OSError):
        install_native_host(EXTENSION_ID, home=home)
    assert planted and victim.read_text() == "keep" and fake_winreg.values == {}  # and nothing was registered for a launcher that is not there


def test_windows_remove_when_nothing_is_installed_removes_nothing_and_says_so(fake_winreg, tmp_path):
    assert remove_native_host(home=tmp_path / "user") == []


def test_windows_remove_dry_run_names_what_it_would_remove_and_removes_nothing(fake_winreg, tmp_path):
    home = tmp_path / "user"
    install_native_host(EXTENSION_ID, home=home)
    would = remove_native_host(dry_run=True, home=home)
    assert len(would) == 3 and len(fake_winreg.values) == 2 and (host_folder(home) / "si.boxed.host.json").is_file()
    assert fake_winreg.deleted == []


def test_windows_remove_takes_away_the_keys_above_that_install_made_and_stops_before_software(fake_winreg, tmp_path):
    """SetValue makes every key on the way, and DeleteKey takes away the last one only: the keys above stayed, empty."""
    home = tmp_path / "user"
    install_native_host(EXTENSION_ID, home=home)
    assert r"Software\Google\Chrome\NativeMessagingHosts" in fake_winreg.paths() and r"Software\Microsoft\Edge" in fake_winreg.paths()
    remove_native_host(home=home)
    assert fake_winreg.paths() == {"Software"} and "Software" not in fake_winreg.deleted  # the key of the user's own software is not boxed's


def test_windows_remove_keeps_the_keys_above_that_hold_something_else(fake_winreg, tmp_path):
    home = tmp_path / "user"
    install_native_host(EXTENSION_ID, home=home)
    other = r"Software\Google\Chrome\NativeMessagingHosts\com.other.host"
    fake_winreg.values[other] = r"C:\other.json"  # another host of the same browser: its keys above stay
    fake_winreg.keys[r"Software\Microsoft\Edge"] = 1  # and a value of Edge's own: it stays, with the key above it
    remove_native_host(home=home)
    assert fake_winreg.paths() == {
        "Software", r"Software\Google", r"Software\Google\Chrome", r"Software\Google\Chrome\NativeMessagingHosts", other,
        r"Software\Microsoft", r"Software\Microsoft\Edge",
    }  # Edge's NativeMessagingHosts was boxed's alone, and went
    assert fake_winreg.deleted == [CHROME_KEY, EDGE_KEY, r"Software\Microsoft\Edge\NativeMessagingHosts"]  # a key that holds something is not even tried


def test_windows_the_command_line_installs_and_removes(fake_winreg, tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    assert main(["install", "native-host", "--extension-id", EXTENSION_ID, "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert f"would write: HKCU\\{CHROME_KEY}\n" in out and f"would write: HKCU\\{EDGE_KEY}\n" in out and "load unpacked" in out
    assert fake_winreg.values == {} and not (tmp_path / "Local").exists()
    assert main(["install", "native-host", "--extension-id", EXTENSION_ID]) == 0
    capsys.readouterr()
    assert len(fake_winreg.values) == 2
    assert main(["install", "native-host", "--remove"]) == 0  # no extension id is needed to take it away
    out = capsys.readouterr().out
    assert f"removed: HKCU\\{CHROME_KEY}\n" in out and fake_winreg.values == {}
    assert main(["install", "native-host", "--remove"]) == 0
    assert "not installed" in capsys.readouterr().out


def test_remove_is_for_the_native_host_only(capsys):
    assert main(["install", "claude", "--remove"]) == 2
    assert "--remove" in capsys.readouterr().err


windows_only = pytest.mark.skipif(sys.platform != "win32", reason="needs a real Windows")


def test_a_test_gets_a_fake_registry_and_never_the_one_of_the_user_unless_it_asks():
    import winreg

    assert type(winreg).__name__ == "FakeWinreg"  # install_native_host in any test, on any system, writes to a dict


@windows_only
@pytest.mark.real_registry
def test_a_test_that_asks_for_the_real_registry_gets_it():
    import winreg

    assert hasattr(winreg, "HKEY_LOCAL_MACHINE")


@windows_only
def test_the_tests_of_the_real_registry_are_skipped_unless_the_variable_is_set():
    """They write the registry of whoever runs the suite. A run of just those tests, without the variable, must skip them all."""
    environment = {name: value for name, value in os.environ.items() if name != "BOXED_TEST_REAL_REGISTRY"}
    done = subprocess.run(
        [sys.executable, "-m", "pytest", "-o", "addopts=", "-q", "-p", "no:cacheprovider", "-m", "real_registry", str(Path(__file__))],
        env=environment, capture_output=True, timeout=300,
    )
    assert done.returncode == 0 and b"skipped" in done.stdout and b"passed" not in done.stdout and b"failed" not in done.stdout, done.stdout


@windows_only
@pytest.mark.real_registry
def test_windows_the_real_registry_gets_both_keys_and_loses_them_again(tmp_path):
    """Run only with BOXED_TEST_REAL_REGISTRY=1. The registry of the user is the same afterwards: the keys boxed made are gone, those
    that held something else are still there (a key that was empty before may go with them: an empty key means nothing)."""
    import winreg

    def there(path):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
                return winreg.QueryInfoKey(key)[:2]  # (subkeys, values)
        except FileNotFoundError:
            return None

    for key in (CHROME_KEY, EDGE_KEY):
        try:
            winreg.QueryValue(winreg.HKEY_CURRENT_USER, key)
        except FileNotFoundError:
            continue
        pytest.skip("this user has the host registered already: it is not touched")
    above = [  # the keys on the way to the two, below Software: SetValue makes the ones that are not there
        "\\".join(key.split("\\")[:depth]) for key in (CHROME_KEY, EDGE_KEY) for depth in range(2, len(key.split("\\")))
    ]
    absent = [path for path in above if there(path) is None]
    holding = [path for path in above if any(there(path) or ())]
    home = tmp_path / "user"
    try:
        manifest, *keys = install_native_host(EXTENSION_ID, home=home)
        assert manifest.is_file() and len(keys) == 2
        for key in (CHROME_KEY, EDGE_KEY):
            assert winreg.QueryValue(winreg.HKEY_CURRENT_USER, key) == str(manifest)  # the default value, which is what the browsers read
        assert remove_native_host(home=home) == [*keys, host_folder(home)]
        for key in (CHROME_KEY, EDGE_KEY):
            with pytest.raises(FileNotFoundError):
                winreg.QueryValue(winreg.HKEY_CURRENT_USER, key)
        assert not host_folder(home).exists()
        assert [path for path in absent if there(path) is not None] == []  # what boxed made above the keys is gone
        assert [path for path in holding if there(path) is None] == []  # and what held something else is not
    finally:
        for key in (CHROME_KEY, EDGE_KEY, *reversed(absent)):  # whatever a failed test left, the deepest first
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key)
            except OSError:
                pass


@windows_only
def test_windows_the_launcher_starts_the_host_in_a_home_with_cyrillic_letters_and_a_percent_sign(tmp_path, monkeypatch):
    import subprocess

    from boxed.install import LAUNCHER_CMD, _cmd_launcher_text, _write_new
    from boxed.native_host import read_message, write_message

    boxed_home = tmp_path / "Иван 100%" / "данные"
    monkeypatch.setenv("BOXED_HOME", str(boxed_home))
    launcher = tmp_path / "папка" / LAUNCHER_CMD  # the folder of the launcher has the letters too
    launcher.parent.mkdir()
    _write_new(launcher, _cmd_launcher_text(), 0o700, newline="\r\n")
    asked = io.BytesIO()
    write_message(asked, {"cmd": "mask", "text": "mail ivan@acme.com", "scope": "s"})
    environment = {name: value for name, value in os.environ.items() if name != "BOXED_HOME"}  # the launcher alone must carry it over
    done = subprocess.run(
        ["cmd", "/c", str(launcher), f"chrome-extension://{EXTENSION_ID}/", "--parent-window=0"],  # what Chrome adds to the command line
        input=asked.getvalue(), capture_output=True, env=environment, timeout=120,
    )
    reply = read_message(io.BytesIO(done.stdout))
    assert done.returncode == 0 and reply is not None and reply["text"] == "mail [EMAIL_1]", done.stderr
    assert (boxed_home / "journal.jsonl").is_file()  # written where the launcher said, not in the home of the user


# ---- macOS: the same --remove takes the manifests and the launcher away, and leaves the data ----


@pytest.mark.skipif(sys.platform == "win32", reason="pins the macOS folders, launcher and modes of the native host")
def test_remove_deletes_the_manifests_and_the_launcher_and_keeps_the_data(tmp_path):
    home = tmp_path / "user"
    paths = install_native_host(EXTENSION_ID, home=home)
    (home / ".boxed" / "vault.db").write_text("data")  # the data folder is not ours to delete
    removed = remove_native_host(home=home)
    assert sorted(removed) == sorted([*paths, home / ".boxed" / "bin" / "boxed-native-host"])
    assert not any(path.exists() for path in removed) and not (home / ".boxed" / "bin").exists()
    assert (home / ".boxed" / "vault.db").read_text() == "data"
    assert remove_native_host(home=home) == []


@pytest.mark.skipif(sys.platform == "win32", reason="pins the macOS folders, launcher and modes of the native host")
def test_remove_dry_run_removes_nothing(tmp_path):
    home = tmp_path / "user"
    paths = install_native_host(EXTENSION_ID, home=home)
    assert len(remove_native_host(dry_run=True, home=home)) == 3 and all(path.exists() for path in paths)
