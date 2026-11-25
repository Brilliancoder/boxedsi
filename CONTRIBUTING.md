# Contributing to boxed.si

Thanks for helping. boxed.si is alpha software with a small team, so a short, focused change with a test is the easiest thing to review.

Contributions are accepted under the [Apache License 2.0](LICENSE), the same as the project. There is no CLA.

By taking part you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). To report a security problem, use [SECURITY.md](SECURITY.md), not a public issue.

## Never paste real secrets or personal data

Not in an issue, a pull request, a test, a fixture, a log or a screenshot. Use invented values of the same shape: `user@example.com`, `203.0.113.7`, a random key you made up. If you have already pasted a real value, treat it as leaked: revoke it, then edit the text.

## Set up

You need [uv](https://docs.astral.sh/uv/) and Python 3.13 (`.python-version` pins it; uv fetches it). The project is tested on Python 3.13 only.

```bash
git clone https://github.com/boxedsi/boxedsi && cd boxedsi
uv sync --frozen --extra ner-ru --extra formats
uv run boxed --help
```

- `--extra formats` is needed: `tests/formats/` fails at collection without it.
- `--extra ner-ru` adds the small Russian name model.
- `--extra ner-en` pulls torch and a model of about 1 GB. Skip it unless you work on English names; its tests are skipped without it.
- If your shell has a foreign `VIRTUAL_ENV`, uv warns: `unset VIRTUAL_ENV`.

## Run the tests

Python (the full run takes a few minutes):

```bash
uv run --no-sync pytest -p no:cacheprovider -o addopts="" -q                                    # everything
uv run --no-sync pytest -p no:cacheprovider -o addopts="" -q tests/detect/test_patterns.py     # one file
```

Browser extension (plain JavaScript, Node 22 or newer, no install step):

```bash
cd extension && node --test
```

Desktop shell, JavaScript part (Node only):

```bash
cd desktop && node --test
```

Desktop shell, Rust part (macOS). The Rust tests need the Rust toolchain only; building the application bundle also needs the Tauri CLI, see [desktop/README.md](desktop/README.md):

```bash
cd desktop/src-tauri && cargo test --locked
```

Notes:

- Timing tests (`tests/detect/test_numbers.py`, `tests/detect/test_linear.py`, some in `tests/skills/`) can fail on a loaded machine. Set `BOXED_TEST_TIME_FACTOR=3` and rerun them alone.
- Tests never touch your real `~/.boxed`, keychain or agent folders: `tests/conftest.py` gives each test its own home and fails a test that reaches a real place. If your code reads a new place in the home folder, add it to `REAL_PLACES` in `tests/conftest.py` and `PLACES` in `tests/test_isolation.py`.
- Providers are never called for real: tests reach `boxed ask` and `skills scan --ai` through a fake transport (`transport=`).
- `docs/guide/cli.md` is generated. After any change to the parser or help text run `uv run python scripts/gen_cli_docs.py` (`tests/test_cli_docs.py` fails otherwise).
- To try the real CLI by hand without touching your data, start a throwaway home with the block in [docs/guide/install.md](docs/guide/install.md#try-it-without-touching-your-own-data): a new `HOME`, `BOXED_HOME` inside it, `BOXED_KEYSTORE=insecure-file` and `cd` into it. A new `BOXED_HOME` alone is not enough: `audit` and `skills` still read your real agent folders, and `install codex` changes them. The `insecure-file` keystore keeps keys in plain files, so use it only for throwaway runs.

## How detection works

`src/boxed/detect/` finds sensitive spans in text; `src/boxed/mask.py` replaces them with markers like `[EMAIL_1]`.

- `patterns.py`: the `RULES` tuple. Each `Rule` has a name (`rule:email`), a kind (`EMAIL`), a regex and optional helpers: a `validator` (checksums, in `validators.py` or next to the rule), `skip_if`, `needs`, `shield`, `check`, `stage`. A rule with a later `stage` only fills gaps and never takes a match from an earlier one.
- `numbers.py`: amounts, percentages, dates and plain numbers (level 3).
- `ner.py`: optional name models (`ner-ru`, `ner-en`) for people and organizations.
- `detect/__init__.py`: `KINDS_BY_LEVEL` says which kinds each level (0-3) masks, and overlapping matches are resolved by `PRIORITY`.
- `bench/` measures recall and false positives on synthetic documents: `uv run python -m bench.metrics --seed 7 --docs 500` (see `bench/README.md`).

To add or fix a detector:

1. Write the failing test first, in `tests/detect/` (start from `test_patterns.py`: a positive case, and a negative case for the look-alike it must not catch).
2. Add or change the `Rule` in `patterns.py` (or a validator, or `numbers.py`).
3. A new kind also goes into `KINDS_BY_LEVEL` and, if it can collide with others, `PRIORITY`.
4. Run `tests/detect/`, then the full suite. A change that makes ordinary text, code or logs mask more than before needs a negative test.
5. Test values must be invented. Checksummed numbers (cards, IBAN, INN, SNILS) must be generated, not taken from a real person or account.

The rules of `boxed skills` (static checks of agent extensions) live in `src/boxed/skills/rules.py` and `_rules_catalog.py`. Changing a rule there means bumping `RULES_VERSION`. Tests are in `tests/skills/`. Samples in tests must be inert strings with invented hosts. Scanned content is hostile: code must never execute, import or follow it.

Other rules of the code base:

- A file in the boxed home is written through a part file under `locks.file_lock`. A new file there that an agent must not see goes into `workspace.SENSITIVE_HOME_PARTS`.
- Platform differences live in `src/boxed/platform.py`; feature code asks `platform.IS_WINDOWS` at call time.
- Error messages are fixed lower-case text and never quote a value, key or path.
- Architecture and conventions: [docs/architecture.md](docs/architecture.md). Words: [CONTEXT.md](CONTEXT.md). Decisions: [docs/adr/](docs/adr/).

## A good pull request

- Does one thing and says why in the description.
- Has a test for every change of behavior: a bug fix has a test that failed before; a feature has tests for what it does and what it refuses.
- Keeps the full test run green (Python, and the extension or desktop tests if you touched them: `node --test`, and `cargo test --locked` in `desktop/src-tauri` for Rust changes).
- Updates the docs in `docs/guide/` when a command, option or default changes, and adds a line to the top section of `CHANGELOG.md` for a change users can see.
- Does not reformat or refactor code it has no reason to touch.
- Uses invented data everywhere. No real keys, addresses, names, plugins, MCP servers or machine paths.
- Is written in English, with plain hyphens (` - `) instead of em or en dashes and straight quotes.

Open an issue first for a large change (a new channel, a new dependency, a change to the vault or journal format). Small fixes can go straight to a pull request.

## Reporting a false positive or a miss

Use the "Detector report" issue form. Give the kind, the level, the command and a made-up example of the same shape: the same length, separators and surrounding words, with the characters replaced. Do not paste the real value, even partly. If you cannot make a safe example, describe the shape in words.

A security problem (masking that can be bypassed, a value that leaks into a journal or output) is not a detector report: see [SECURITY.md](SECURITY.md).

## Good first issues

Issues labelled `good first issue` are small, self-contained and have a clear test to write: a missed token format, a false positive with an obvious negative test, a doc fix, a better error message. Comment on one before you start so two people do not do the same work.
