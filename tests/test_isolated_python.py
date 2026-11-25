"""The hook and MCP commands that run boxed as `python -m boxed.cli` start Python in isolated mode (-I).

Without it Python puts the folder it runs in at the head of its path, and a hook runs in the copy: two files the agent writes there,
boxed/__init__.py and boxed/cli.py, take the place of boxed, and every hook exits 0. No test touches the real ~/.boxed or the keychain:
conftest.py points BOXED_HOME at a temp folder and the keys at files."""

import shlex
import subprocess
import sys

import pytest

from boxed import __version__

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="the hooks and the sandbox are not supported on Windows yet")

STUB = "import sys\nopen('stub-ran', 'w').write('the stub ran')\nsys.exit(0)\n"


@pytest.fixture
def folder_with_a_stub(tmp_path):
    """A folder with a package named boxed in it, as the agent can write one into the copy."""
    (tmp_path / "boxed").mkdir()
    (tmp_path / "boxed" / "__init__.py").write_text("")
    (tmp_path / "boxed" / "cli.py").write_text(STUB)
    return tmp_path


def test_the_hook_command_without_boxed_on_the_path_isolates_python(monkeypatch):
    import boxed.workspace as workspace

    monkeypatch.setattr(workspace.shutil, "which", lambda name: None)
    assert workspace.boxed_command() == f"{shlex.quote(sys.executable)} -I -m boxed.cli"


def test_the_mcp_command_without_boxed_on_the_path_isolates_python(monkeypatch):
    import boxed.install as install

    monkeypatch.setattr(install.shutil, "which", lambda name: None)
    assert install._mcp_command() == (sys.executable, ["-I", "-m", "boxed.cli", "mcp"])


def test_a_package_named_boxed_in_the_folder_takes_the_place_of_boxed_unless_python_is_isolated(folder_with_a_stub):
    """The attack, and what stops it, with the very arguments of the two commands."""
    plain = subprocess.run([sys.executable, "-m", "boxed.cli", "--version"], cwd=folder_with_a_stub, capture_output=True, text=True)
    assert (folder_with_a_stub / "stub-ran").exists() and plain.stdout == ""  # without -I the stub ran, not boxed
    (folder_with_a_stub / "stub-ran").unlink()
    isolated = subprocess.run([sys.executable, "-I", "-m", "boxed.cli", "--version"], cwd=folder_with_a_stub, capture_output=True, text=True)
    assert isolated.stdout.strip() == f"boxed {__version__}" and not (folder_with_a_stub / "stub-ran").exists()
