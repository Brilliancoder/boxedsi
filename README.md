# boxedsi

**See what your agents already saw.**

Find the secrets Claude Code and Codex already saw, and mask new ones before they reach the model. Runs locally.

[![CI](https://github.com/boxedsi/boxedsi/actions/workflows/ci.yml/badge.svg)](https://github.com/boxedsi/boxedsi/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)
![Status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)

![demo](https://raw.githubusercontent.com/boxedsi/boxedsi/main/docs/assets/demo.gif)

## Try it in 60 seconds

You need [uv](https://docs.astral.sh/uv/) and git. uv fetches a suitable Python if you do not have one.

```bash
uvx --from git+https://github.com/boxedsi/boxedsi boxed audit
```

- Reads the Claude Code and Codex transcripts on your computer (`~/.claude/projects`, `~/.codex/sessions`): your prompts, tool results, attachments and the developer instructions of Codex, the text of your sessions with the model. It also reads the Claude Code settings files (`settings.json`, `settings.local.json`), where keys end up inside permission rules, of your user and of the projects on a local disk. It sends nothing anywhere and leaves transcripts and settings unchanged. It finds values in saved local records and does not check that a request reached the provider. It does not read Codex settings.
- What it writes: the `--html` report if you ask for one, and on its first run one key in the system keychain (service `boxed.si`, name `audit-mac-key`) so that the hashes match between runs. Making that key also creates the boxed data folder (`~/.boxed`, mode 0700 on macOS and Linux) with an empty `keychain.lock`. On macOS `security delete-generic-password -s boxed.si -a audit-mac-key` removes the key; the rest: [uninstall](docs/guide/install.md#uninstall).
- Prints what it finds by kind, tool, role and project, and what it could not check. Each secret appears as its kind and a keyed hash, never the value. Paths shorten your current home folder to `~`, but folder and file names stay and can name users, projects or clients: review the report before sharing it.
- `--html report.html` also writes a one-file report; `--since 2026-11-01` limits the period. Details: [docs/guide/dashboard-and-journal.md](docs/guide/dashboard-and-journal.md#what-already-went-out-boxed-audit).

## What the report looks like

A run on macOS on a made-up home folder (`scripts/demo/make_home.py`, plus one `~/.claude/settings.local.json` with an allowed `curl` command): invented transcripts, invented keys, invented projects in `~/work`.

```text
$ boxed audit --html ~/.boxed/reports/audit.html
boxed audit: 99 items checked, 1 Claude Code settings file, 0 malformed lines skipped
found: SECRET 26, EMAIL 6, CARD 1, PHONE 1, PRIVATE_KEY 1, IP 1
  claude-code: SECRET 15, EMAIL 4, CARD 1, PHONE 1, PRIVATE_KEY 1, IP 1
  claude-settings: SECRET 1
  codex: SECRET 10, EMAIL 2
by role: tool_result 24, user_prompt 6, attachment 5
top projects:
  ~/work/acme-api: SECRET 15, EMAIL 4, CARD 1
  ~/work/infra: SECRET 6, PRIVATE_KEY 1, IP 1, EMAIL 1
  ~/work/billing-worker: SECRET 2, PHONE 1
  ~/work/mobile-app: SECRET 2, EMAIL 1
  ~: SECRET 1
secrets: 14 unique (11 known key formats, 3 possible), 28 occurrences

known key formats (11)
A pattern or checksum match: boxed does not check that a value is real or still valid.
In a saved local record of a session: if real, rotate the credential or call the card issuer.
~/.claude/projects/~-work-acme-api/88b6d373-a33a-4bff-9ee1-186026989e42.jsonl
  :16  SECRET #b8d3706c11c0 x4
  :16  SECRET #e5041edc97ba x4
  :24  CARD #8e48d5cd8aa2 x1
~/.claude/projects/~-work-billing-worker/378af8d5-6df6-487d-95fd-1d798248157e.jsonl
  :19  SECRET #152982a35a77 x1
  :33  SECRET #ecdbf6576db1 x2
~/.claude/projects/~-work-infra/c6c5cffd-cc39-4c7d-9ffd-91ed5714b47c.jsonl
  :22  PRIVATE_KEY #e36256109492 x1
~/.codex/sessions/2026/11/11/rollout-2026-11-11T16-17-00-3d8d0f9d-fbfd-42f1-8c8d-494bc05f05ae.jsonl
  :15  SECRET #e5b1c67884cc x1
  :24  SECRET #b4dd77a6d47b x1
~/.codex/sessions/2026/11/13/rollout-2026-11-13T11-58-00-d688806d-1c12-4fb0-a6f4-80faa4abcc1c.jsonl
  :29  SECRET #ab3917996c1a x1
  :29  SECRET #490f20da4a68 x1
~/.codex/sessions/2026/11/15/rollout-2026-11-15T09-20-00-7e1da053-5cb0-47a2-aaf9-0c894107711d.jsonl
  :9  SECRET #e4877ab6400e x1

possible (3)
Review these: they look like secrets, but no rule of a known key format matched them.
~/.claude/projects/~-work-acme-api/88b6d373-a33a-4bff-9ee1-186026989e42.jsonl
  :16  SECRET #9a0924c02572 x5
  :16  SECRET #183bb8bee74e x4
~/.claude/settings.local.json
  :5  SECRET #91f194e56572 x1
report: ~/.boxed/reports/audit.html
```

The file and line tell you where to look. A value under "known key formats" matches a credential pattern or a card checksum; boxed does not check that it is real or valid. Found in a saved session record, it may have reached the provider: if it is real, rotate the credential or contact the card issuer. Found only in a settings file, it is on disk, which proves no send: remove it from the file and check where it was used. A "possible" one is a guess from a name or the look of a value (`DB_PASSWORD=...`, a random-looking token): check it, then rotate it if it is real. `claude-settings` are the Claude Code settings files of your user and of the projects in the transcripts, where an allowed command keeps the key it was run with. What audit could not check (a file too big or without access, a project folder on a network share) is listed under "not checked"; a run without that line read everything it found. The report names project folders and transcript files, so read it before you share it.

## What it is not

- **Alpha.** Version 0.1, no external security audit yet. Read the [threat model](docs/security/threat-model.md).
- **A clean result is not a guarantee.** Detectors are rules: they miss unusual formats and flag some harmless strings. `audit` finds no people names (that needs a name model). It sees only the records still on disk: Claude Code deletes transcripts older than 30 days by default (`cleanupPeriodDays`), so a clean report does not mean nothing went out before.
- **It only works with what goes through boxed.** Text you paste into a chat page yourself, and what agents read before you set boxed up, has already gone.

## What else is in the box

Install it to keep it:

```bash
uv tool install --python 3.13 git+https://github.com/boxedsi/boxedsi   # puts `boxed` on PATH
uv tool update-shell   # only if `boxed` is not found afterwards; then open a new terminal
```

- **Mask and restore (CLI).** `boxed mask --scope t prompt.txt` replaces secrets and personal data with placeholders such as `[EMAIL_1]`; `boxed restore --scope t answer.txt` puts the originals back on your computer. [Quickstart](docs/guide/quickstart.md), [levels](docs/guide/concepts.md).
- **Claude Code plugin.** With `boxed` installed, run in Claude Code `/plugin marketplace add boxedsi/boxedsi`, then `/plugin install boxed@boxed`. It adds the MCP server, a skill and a session-start note about new or changed agent extensions. [Install](docs/guide/install.md#claude-code-and-codex).
- **Masked workspace.** `boxed workspace create ~/work/project` makes a masked copy for Claude Code or Codex; `boxed workspace sync <id>` writes the agent's edits back with the real values. [Claude Code and Codex](docs/guide/claude-code-and-codex.md).
- **MCP server.** `boxed mcp` gives an agent `read_masked` and `search_masked` over the folders you list; `boxed install codex` adds it to Codex. [MCP tools](docs/guide/claude-code-and-codex.md#files-outside-the-project-the-mcp-tools).
- **`boxed skills scan`.** Reads the skills, plugins, MCP servers, hooks and settings of Claude Code, Codex, Cursor, Gemini CLI, Claude Desktop and OpenClaw, or a repository before you install it, and flags each item `dangerous`, `suspicious` or `ok`. It never runs them. [Skills](docs/guide/skills.md).
- **Sandbox: `boxed run claude`.** Starts the agent inside a masked copy made by `boxed workspace create`, under the macOS sandbox, which denies the original project at the OS level, and keeps variables that look like credentials out of its environment (`--keep-env NAME` passes one). macOS only. [Sandbox](docs/guide/claude-code-and-codex.md#boxed-run-and-the-sandbox).
- **`boxed ask`.** Sends a masked prompt with your own key to OpenAI, Anthropic, DeepSeek or OpenRouter and restores the answer locally. [API](docs/guide/api.md).

Experimental, less tested and may change:

- Browser side panel for Chrome and Edge: mask, insert and restore on five AI chats. [Browser extension](docs/guide/browser-extension.md).
- Desktop app: a window for mask and restore, built from source, macOS 14 or later on Apple silicon only. [Desktop](docs/guide/desktop.md).
- Files and tables: clean copies of CSV, XLSX and DOCX, the text of a PDF as `.txt`, and table questions answered without your rows. [Files](docs/guide/files.md), [tables](docs/guide/tables.md).

## Platforms

| Platform | What was checked | What does not work yet |
|---|---|---|
| macOS | Developed and used here; full test suite | Desktop app: macOS 14 or later on Apple silicon only |
| Windows 11 | Core commands and the browser host. CI runs the whole test suite: about 100 tests of `serve` and `skills` do not pass yet, so the Windows job, core tests included, does not fail CI; the core tests become required once those are fixed. CI runs `skills scan` | `boxed run`, workspace, hooks, MCP server, Claude Code plugin. `skills` not tried on a Windows desktop. [Details](docs/guide/windows.md) |
| Linux | Full test suite in a container as a regular user | `boxed run` (no sandbox), browser host (`install native-host` refuses). Not tried on a desktop. Without a Secret Service keyring, `audit` (temporary key), a scan of a folder, `skills list`, `policy check` and `journal check-export` run, and a scan of what is installed is not saved; the commands that keep keys (`mask`, `ask`, journal, dashboard, workspace) stop and say a keychain is needed |

## How it compares

| Tool | What it reads | What it does with a finding |
|---|---|---|
| [gitleaks](https://github.com/gitleaks/gitleaks) | Git history, folders and files, stdin | Reports it; can redact it in its own output |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | Git, GitHub, GitLab, S3, Docker images, the file system and more | Reports it; checks many kinds of keys against the live service |
| [snyk agent-scan](https://github.com/snyk/agent-scan) | Installed agents, their MCP servers and skills | Reports it; analysis goes through the Agent Scan API, with secrets redacted first |
| [cisco skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) | Agent skills | Reports it; static and behavioral analyzers, optional LLM and cloud analyzers |
| [agent-sweep](https://github.com/Ishannaik/agent-sweep) | Local history of many coding agents, Claude Code and Codex among them | Reports it; can redact the history files in place, with backups |
| boxedsi | Claude Code and Codex transcripts; agent extensions of six agents; text, files and projects you hand it | Reports counts and keyed hashes and changes no transcript; masks new text before it reaches a model and restores the answer locally |

Use them together: a repository scanner in CI, a history cleaner for old transcripts, boxedsi for what the agent reads next.

## Documentation

- [User guide](docs/guide/README.md): install, quickstart, every command and channel, troubleshooting. [Every command](docs/guide/cli.md).
- [What leaves your computer](docs/guide/privacy.md), and [how to remove boxed](docs/guide/install.md#uninstall).
- [Security documents](docs/security/README.md): threat model, data flows, journal records.
- [Roadmap](ROADMAP.md): what does not work yet.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Never paste real secrets or personal data into an issue: use invented values. Report security problems privately, as [SECURITY.md](SECURITY.md) says. Changes are in [CHANGELOG.md](CHANGELOG.md).

## Development

```bash
uv sync --frozen --extra ner-ru --extra formats
uv run --no-sync pytest -p no:cacheprovider -o addopts="" -q
```

boxed is tested on Python 3.13 only, and `.python-version` pins it: torch, which the `ner-en` extra needs, may have no wheel for the newest Python yet.

Part of [Boxed](https://boxed.si).

## License

Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). The license does not cover the boxed.si name or logo.
