## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] Every change of behavior has a test (a bug fix has a test that failed before).
- [ ] The tests pass: `uv run --no-sync pytest -p no:cacheprovider -o addopts="" -q`, and `node --test` inside `extension/` or `desktop/` if I touched them. For Rust changes, `cargo test --locked` from `desktop/src-tauri` on macOS.
- [ ] No real secrets, personal data, plugin or machine names anywhere (code, tests, docs, logs). Only invented values.
- [ ] Docs updated if a command, option or default changed (`docs/guide/`; `uv run python scripts/gen_cli_docs.py` after a parser change). `CHANGELOG.md` updated for a visible change.
- [ ] Rules of `boxed skills` changed: `RULES_VERSION` bumped.
- [ ] I agree that my contribution is licensed under Apache-2.0.
