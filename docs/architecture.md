# Architecture

Pointers for a change to the code. What the commands do for a user is in `docs/guide/`; why a decision was made is in `docs/adr/`; the words are in `CONTEXT.md`.

## Two products, one core

`src/boxed/` is one Python package (src layout, `boxed = boxed.cli:main`). Every front end calls it; none re-implements it:

- CLI: `cli.py` (`build_parser`, one `cmd_*` per command, exit codes `EXIT_*` at the top).
- Claude Code plugin: `plugin/` (a skill and `hooks/`), shipped inside the wheel; hooks call `boxed hook <event>`.
- Codex: `mcp_server.py` (masked read and search; no restore tool for the model).
- Browser side panel: `extension/` (plain JS) talks to `native_host.py` over native messaging.
- Desktop app: `desktop/` (Tauri) starts `boxed serve` (`serve.py`) as a sidecar and speaks framed JSON on stdio.

## Masking flow

```
text or file -> detect.detect(level) -> policy.decide (category + recipient) -> mask.mask_text -> MarkerMap in vault.Vault
            -> channels.ask / agent / chat  -> answer with markers -> mask.restore (locally) -> journal.Journal entry
```

- `detect/`: rule-based candidates (`patterns.py`, `validators.py`, `numbers.py`) and optional NER (`ner.py`, extras `ner-ru`, `ner-en`). `Detection` has a kind and a span; levels 0-3 widen the kinds (`KINDS_BY_LEVEL`).
- `mask.py`: replaces spans with `[KIND_n]`; `MarkerMap` is per scope, so the same value gets the same marker inside a scope. `restore` reports ambiguous or altered markers instead of guessing.
- `vault.py`: encrypted marker maps, one per scope, in the boxed home. Keys come from `keys.py` (OS keychain; `BOXED_KEYSTORE=insecure-file` for tests and throwaway homes).
- `journal.py`: append-only, hash-chained, signed. Kinds, counts and hashes only, never values.
- `workspace.py` + `hooks.py` + `run.py`: a masked copy of a project for an agent, restore-on-sync of its edits, hooks that are no-ops outside a workspace, `boxed run` under the macOS sandbox. `workspace.SENSITIVE_HOME_PARTS` lists what of the boxed home an agent in a copy must never see.
- `formats/`: CSV, XLSX, DOCX, PDF clean copies (extra `formats`). `opplan.py`: level 4, the model returns a plan and boxed runs it locally.
- `audit/`: counts what past agent transcripts saved locally (possible exposure to the provider). `dashboard.py`, `checks.py`, `observe.py`: reports, "training on chats" notes, browser send observation.

## Boxed home

`paths.boxed_home()` (`BOXED_HOME`, else `~/.boxed`) holds vault, journal, `checks.json`, `observed.jsonl`, and `skills/` (`record.json`, `quarantine/`). Writes go through a private part file, fsync and `platform.replace_file` under `locks.file_lock`. Files at names the person gives go through `outputs.Target`. POSIX/Windows differences live only in `platform.py`: ask `platform.IS_WINDOWS` at call time, never `os.O_NOFOLLOW`, `fcntl` or `sys.platform` in feature code.

## Extension check: `src/boxed/skills/`

`boxed skills scan | list | quarantine | restore` and the SessionStart hook. Reads what agents load, judges it with static rules, remembers the result, and moves an item out of reach only when asked.

```
inventory.discover(Roots)  ->  scan.scan_inventory(inventory, record)  ->  report.render_*  (terminal, HTML, JSON)
(or discover_target(folder) <- fetch.target_folder: folder, zip, https git, owner/repo)
        |                          rules.check_file/check_text/check_entry/check_link -> Finding -> verdict
        |                          ai.review (only with --ai, after masking, only adds findings)
        v
record.py: <home>/skills/record.json   quarantine.py: <home>/skills/quarantine/<qid>/   session.py: hook
```

Modules:

- `inventory.py`: every path where agents (claude, claude-desktop, codex, agents, cursor, gemini, openclaw) load extensions, config parsing, `Item` identity (`<agent>:<kind>:<scope>:<name>`, stable across runs), `item_digest`, `find_items`. Scope is user, project, local or target. Hooks are named by a hash of their command, so reordering does not rename them.
- `rules.py` + `_rules_catalog.py`: the rule catalog (`RULES`, `RULES_VERSION` - bump on any rule change, the record compares it), decoding (base64, Unicode tags), binaries and archives by magic bytes, capabilities. Rules are `.py` code, never data files (PyInstaller collects none). Severity depends on scope: an endpoint override is critical in project, local or plugin scope, medium in user scope.
- `scan.py`: verdict = dangerous (any critical), suspicious (any high or medium), else ok. `scan.redact` runs on all evidence before it reaches a terminal, report, record or prompt.
- `record.py`: strict, unsigned `record.json` (digests, verdicts, finding locations, quarantine entries, AI cache; no evidence). Change it only through `update_record` (read, change, write under one lock).
- `quarantine.py`: one method per kind of item (move, edit a plugin switch, cut a JSON or TOML entry, `claude mcp remove`); every method has an exact undo and refuses when the file cannot be edited safely.
- `session.py`: `hook_skills_check` (registered as `hooks.HOOKS["skills-check"]`, run by `plugin/hooks/hooks.json` through `plugin/hooks/run-boxed`). Silent when nothing is new or dangerous, when boxed is missing, or when the record cannot be read.
- `fetch.py`: the only network use besides `ai.py`. `ai.py`: sends only files that already have a rule finding, in batches, through `channels.ask` at level 1.
- `command.py`: the whole command line, `register(sub)` called from `cli.build_parser`. Exit codes: 0 clean, 3 dangerous or suspicious, or something not checked in full (an item cut at a cap or with a part that cannot be read, a problem of the inventory such as a config that cannot be read; `scan.incomplete`), 2 bad input or damaged record, 1 `--ai` failed (hides 3 - known bug).
- `_shared.py`: `escaped`, `no_repeated_keys`.

## Conventions

- English everywhere. No em or en dashes (use " - " or ":"), straight quotes only.
- Error text: lower-case, no final period, a colon then the remedy, never quotes a value, key or path. Commands raise `errors.UserError("fixed text")`; only its message is shown (`tests/test_error_texts.py`), and `cli.main` adds `boxed: error: `.
- Dependencies: stdlib plus `cryptography`, `keyring`, `mcp`. No YAML library (frontmatter is parsed by hand).
- Scanned content is hostile: never execute, import, source or eval it; never follow links (`os.walk(followlinks=False)`, `platform.open_nofollow` + `os.fstat` + `stat.S_ISREG`); read text files whole; cap file counts and archive sizes and report a cap as a finding.
- Untrusted text printed to a terminal goes through `cli._shown`. HTML escapes every dynamic value, no scripts, no external resources.
- Values from agent configs (env, headers, tokens in commands) are never printed, logged, journaled or stored in the record.
- Machine-specific facts (names of real plugins, MCP servers, projects, paths) never go into the repo; tests and docs use invented names.
- Tests never touch the real home: `tests/conftest.py` gives each test its own `BOXED_HOME`, and fails a test that reaches a real place (`REAL_PLACES`). Tests of agent folders build a fake home under `tmp_path` or pass `Roots`. A new place the code reads goes into `REAL_PLACES` there and `PLACES` in `tests/test_isolation.py`.
- `docs/guide/cli.md` is generated from the parser: after any parser or help-text change run `uv run python scripts/gen_cli_docs.py` (`tests/test_cli_docs.py` fails otherwise).
