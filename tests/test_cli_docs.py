"""docs/guide/cli.md is generated from the command parser. It must equal what scripts/gen_cli_docs.py writes now, so a command,
a flag or a help text that changes in the parser fails here until the page is generated again."""

import argparse
import importlib.util
from pathlib import Path

from boxed.cli import build_parser

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "docs" / "guide" / "cli.md"


def generator():
    """The script by its path: scripts/ is a folder of tools, not a package."""
    spec = importlib.util.spec_from_file_location("gen_cli_docs", ROOT / "scripts" / "gen_cli_docs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def commands(parser, path=()):
    """Every command and subcommand as a tuple of names, in parser order, found without the generator."""
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                yield (*path, name), sub
                yield from commands(sub, (*path, name))


def sections(text):
    """Heading text -> the lines under it, for the headings of level 2 and 3."""
    found, name = {}, None
    for line in text.splitlines():
        if line.startswith(("## ", "### ")):
            name = line.split(" ", 1)[1]
            found[name] = []
        elif name is not None:
            found[name].append(line)
    return {name: "\n".join(lines) for name, lines in found.items()}


def test_cli_page_is_current():
    assert PAGE.read_text(encoding="utf-8") == generator().render(), (
        "docs/guide/cli.md is out of date: run `uv run python scripts/gen_cli_docs.py` and commit the result"
    )


def test_every_command_has_a_section_in_parser_order():
    expected = ["boxed", *("boxed " + " ".join(path) for path, _ in commands(build_parser()))]
    assert list(sections(PAGE.read_text(encoding="utf-8"))) == expected


def test_every_flag_and_argument_is_in_the_section_of_its_command():
    found = sections(PAGE.read_text(encoding="utf-8"))
    for path, sub in commands(build_parser()):
        body = found["boxed " + " ".join(path)]
        for action in sub._actions:
            if isinstance(action, (argparse._HelpAction, argparse._SubParsersAction)):
                continue
            name = action.option_strings[0] if action.option_strings else action.dest
            assert f"`{name}" in body, f"{name} is missing from the section of boxed {' '.join(path)}"


def test_page_does_not_depend_on_the_terminal_width(monkeypatch):
    monkeypatch.setenv("COLUMNS", "40")
    narrow = generator().render()
    monkeypatch.setenv("COLUMNS", "300")
    assert generator().render() == narrow
