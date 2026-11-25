"""The hook that tells PyInstaller what a static scan of boxed cannot see, so that a frozen build needs no hand-written hidden imports.
Whether a frozen build then works is shown by building one (on Windows and on macOS); these tests pin what the hook says and that
PyInstaller finds it."""

import ast
import importlib
import runpy
import subprocess
import sys
import tomllib
import types
import zipfile
from pathlib import Path

import boxed

ROOT = Path(__file__).resolve().parents[1]
SRC = Path(boxed.__file__).resolve().parent


def hook_dirs() -> list[Path]:
    """The folders the entry point `pyinstaller40` of pyproject.toml hands to PyInstaller."""
    entry = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["entry-points"]["pyinstaller40"]["hook-dirs"]
    module, function = entry.split(":")
    return [Path(folder) for folder in getattr(importlib.import_module(module), function)()]


def run_hook(monkeypatch) -> dict:
    """hook-boxed.py as PyInstaller runs it, with the two helpers it takes from PyInstaller replaced by ones that say what they found."""
    hooks = types.ModuleType("PyInstaller.utils.hooks")
    hooks.collect_submodules = lambda package: [f"{package}.found_by_collect_submodules"]
    hooks.copy_metadata = lambda dist: [(f"/fake/{dist}.dist-info", f"{dist}.dist-info")]
    for name, module in (("PyInstaller", types.ModuleType("PyInstaller")), ("PyInstaller.utils", types.ModuleType("PyInstaller.utils")), ("PyInstaller.utils.hooks", hooks)):
        monkeypatch.setitem(sys.modules, name, module)
    (folder,) = hook_dirs()
    return runpy.run_path(str(folder / "hook-boxed.py"))


def modules_loaded_by_name() -> set[str]:
    """The names boxed.formats.need() is given in the source: modules it imports with importlib, which no scan of the imports meets."""
    names = set()
    for path in (SRC / "formats").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "need" and node.args and isinstance(node.args[0], ast.Constant):
                names.add(node.args[0].value)
    return names


def test_the_entry_point_names_one_folder_and_the_hook_is_in_it():
    (folder,) = hook_dirs()
    assert (folder / "hook-boxed.py").is_file()


def test_the_hook_declares_every_module_the_formats_loader_imports_by_name(monkeypatch):
    names = modules_loaded_by_name()
    assert {"docx", "openpyxl", "pypdf"} <= names  # so that a scan that finds nothing cannot pass
    assert names <= set(run_hook(monkeypatch)["hiddenimports"])


def test_the_hook_declares_the_keyring_backends_and_ships_the_metadata_that_finds_them(monkeypatch):
    hook = run_hook(monkeypatch)
    assert "keyring.backends.found_by_collect_submodules" in hook["hiddenimports"]
    assert ("/fake/keyring.dist-info", "keyring.dist-info") in hook["datas"]  # keyring picks its backend through entry points


def test_the_wheel_carries_the_hook_and_registers_it_with_pyinstaller(tmp_path):
    subprocess.run(["uv", "build", "--wheel", "-o", str(tmp_path), "-q"], cwd=ROOT, check=True)
    wheel = zipfile.ZipFile(next(tmp_path.glob("*.whl")))
    names = wheel.namelist()
    assert "boxed/_pyinstaller/hook-boxed.py" in names and "boxed/_pyinstaller/__init__.py" in names
    entry_points = wheel.read(next(n for n in names if n.endswith(".dist-info/entry_points.txt"))).decode()
    assert "[pyinstaller40]\nhook-dirs = boxed._pyinstaller:get_hook_dirs" in entry_points
