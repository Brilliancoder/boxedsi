"""Writes docs/guide/cli.md from boxed.cli.build_parser(): every command and subcommand in parser order, with its usage line,
its arguments and its options. Run it after a command changes:

    uv run python scripts/gen_cli_docs.py

tests/test_cli_docs.py fails while the page differs from what this script writes."""

import argparse
import functools
from pathlib import Path

from boxed.cli import build_parser

PAGE = Path(__file__).resolve().parents[1] / "docs" / "guide" / "cli.md"
WIDTH = 80  # usage lines wrap here, whatever the terminal says: the page must not depend on who generates it

INTRO = """\
# Command reference

This page lists every `boxed` command with its usage line, its arguments and its options. It is generated from the command \
parser by `scripts/gen_cli_docs.py`, so do not edit it by hand: run `uv run python scripts/gen_cli_docs.py` after a command \
changes. A test fails while the page is out of date.

- Every command also takes `-h` and `--help`.
- A default of `-` means standard input.
- Where an option has no description, the parser has none. [README.md](README.md) maps each command to the page that explains it.
- Exit codes are in [troubleshooting.md](troubleshooting.md).
"""


def sentence(text: str) -> str:
    """A parser summary as a sentence: capital letter, full stop."""
    text = text.strip()
    text = text[:1].upper() + text[1:]
    return text if text.endswith((".", "!", "?")) else text + "."


def walk(parser: argparse.ArgumentParser, path: tuple[str, ...] = (), summary: str | None = None):
    """(names, parser, summary) for the parser itself and then for each subcommand, depth first, in the order they were added."""
    parser.formatter_class = functools.partial(argparse.HelpFormatter, width=WIDTH)
    yield path, parser, summary or parser.description
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            summaries = {choice.dest: choice.help for choice in action._choices_actions}
            for name, sub in action.choices.items():
                yield from walk(sub, (*path, name), summaries.get(name))


def code(text: object) -> str:
    return f"`{text}`"


def value_name(action: argparse.Action) -> str:
    if isinstance(action.metavar, str):
        return action.metavar
    return action.dest.upper() if action.option_strings else action.dest


def signature(action: argparse.Action) -> str:
    """How the entry names the argument: `--level LEVEL` for an option that takes a value, `--force` for a flag, `file`."""
    if not action.option_strings:
        return value_name(action)
    name = action.option_strings[0]
    return name if action.nargs == 0 else f"{name} {value_name(action)}"


def facts(action: argparse.Action) -> list[str]:
    found = []
    if action.option_strings:
        if action.required:
            found.append("required")
    elif action.nargs == argparse.REMAINDER:
        found.append("optional; the rest of the command line")
    elif action.nargs == "?":
        found.append("optional")
    if action.nargs != 0 and action.type is int and not action.choices:
        found.append("whole number")
    if isinstance(action, argparse._AppendAction) and "repeatable" not in (action.help or ""):
        found.append("repeatable")
    if action.choices:
        found.append("one of " + ", ".join(code(choice) for choice in action.choices))
    if action.nargs != 0 and action.default is not None:
        found.append(f"default {code(action.default)}")
    return found


def entry(action: argparse.Action) -> str:
    line = f"- {code(signature(action))}"
    if found := facts(action):
        line += f" ({'; '.join(found)})"
    return line + (f" - {action.help}" if action.help else "")


def section(path: tuple[str, ...], parser: argparse.ArgumentParser, summary: str | None) -> str:
    name = " ".join(("boxed", *path))
    lines = [f"{'###' if len(path) > 1 else '##'} {name}", ""]
    if summary:
        lines += [sentence(summary), ""]
    lines += ["```text", parser.format_usage().strip(), "```", ""]
    shown = [a for a in parser._actions if not isinstance(a, (argparse._HelpAction, argparse._SubParsersAction))]
    for label, group in (
        ("Arguments:", [a for a in shown if not a.option_strings]),
        ("Options:", [a for a in shown if a.option_strings]),
    ):
        if group:
            lines += [label, "", *map(entry, group), ""]
    return "\n".join(lines)


def render() -> str:
    commands = list(walk(build_parser()))
    index = ["| Command | What it does |", "|---|---|"]
    for path, _, summary in commands[1:]:
        name = " ".join(("boxed", *path))
        what = sentence(summary).replace("|", "\\|") if summary else ""
        index.append(f"| [{code(name)}](#{name.replace(' ', '-')}) | {what} |")
    parts = [INTRO, "\n".join(index) + "\n"]
    parts += [section(path, parser, summary) for path, parser, summary in commands]
    return "\n".join(parts).rstrip("\n") + "\n"


def main() -> None:
    PAGE.parent.mkdir(parents=True, exist_ok=True)
    PAGE.write_text(render(), encoding="utf-8", newline="\n")
    print(f"wrote {PAGE}")


if __name__ == "__main__":
    main()
