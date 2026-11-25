"""PyInstaller finds the hook of boxed through the pyinstaller40 entry point of pyproject.toml."""

from pathlib import Path


def get_hook_dirs() -> list[str]:
    return [str(Path(__file__).resolve().parent)]
