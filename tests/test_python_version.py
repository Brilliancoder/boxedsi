"""A fresh checkout must pick Python 3.13: with no pin, uv takes the newest Python on the machine, and torch (needed by the ner-en
extra) has no wheel for 3.15."""

import tomllib
from pathlib import Path

from packaging.specifiers import SpecifierSet

ROOT = Path(__file__).resolve().parents[1]


def test_python_version_file_pins_3_13_and_pyproject_allows_it():
    assert (ROOT / ".python-version").read_text() == "3.13\n"
    requires = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["requires-python"]
    assert SpecifierSet(requires).contains("3.13")


def test_readme_development_section_says_why_the_version_is_pinned():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = readme.split("## Development", 1)[1].split("\n## ", 1)[0]
    assert ".python-version" in section and "3.13" in section and "torch" in section
