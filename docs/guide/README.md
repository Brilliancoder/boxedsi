# boxed.si user guide

boxed prepares work data for an AI you are allowed to use, and gives you the result back in a usable form. It finds secrets and personal data in code, logs, text and files, and replaces them on your computer with typed placeholders such as `[EMAIL_1]`. What the detectors find is replaced before the text goes to the AI, and boxed puts the originals back into the answer on your computer; what the detectors miss goes out as it is. Masking, restoring, workspaces and requests to a provider write records to a signed journal: counts, hashes and metadata such as the scope name, never the values, so give scopes neutral names. `boxed audit` and a scan of a folder leave the journal as it is. There are no boxed servers in the data path.

## Who it is for

- Developers who let Claude Code or Codex work on code and logs that hold customer data and keys.
- Office staff who use a web chat (ChatGPT, Claude, Gemini, DeepSeek, Z.ai) for letters, documents and tables.
- Anyone who calls an AI with their own API key.
- Anyone who installs skills, plugins or MCP servers for AI agents from other people's repositories. `boxed skills` checks them for malicious behaviour.
- Security and compliance teams that want to see what leaves the company. They have their own folder: [docs/security](../security/README.md).

## Read this first

- Masking hides direct identifiers, not context. A model can still guess who or what a text is about from the details that remain.
- boxed finds people and companies only with a name model or your dictionary. Rules find the rest, and they miss things.
- boxed masks only what goes through it. It does not stop text you type or paste into a chat page yourself. Observation mode reports such sends to you; it stops nothing.
- The journal proves what was recorded, not that nothing was sent around boxed.
- Hooks are best effort. The macOS sandbox of `boxed run` is the hard guard for AI agents. On Windows the core commands (mask, restore, files, plans, policy, ask, keys, checks, journal, dashboard, audit) and the browser extension's host run on Windows 11; not yet: the Claude Code and Codex plugin (`workspace`, hooks, `mcp`, `install claude|codex`) and `boxed run` (see [windows.md](windows.md)).
- boxed is alpha software and has had no external security audit. The threat model is in [docs/security](../security/threat-model.md).

The full list is at the end of [concepts.md](concepts.md).

## The pages

| Page | What it covers |
|---|---|
| [install.md](install.md) | Install from GitHub or a copy, what works on macOS, Linux and Windows, the extras for files and name models, the browser extension, the Claude Code plugin and Codex, uninstall, where data lives |
| [windows.md](windows.md) | Windows 11: what works and what does not yet, Credential Manager, the data folder in your profile, the registry keys of the browser host, PowerShell and UTF-8, running the tests |
| [quickstart.md](quickstart.md) | Ten minutes: mask and restore a prompt, a masked workspace for Claude Code, a clean copy of a table, one `boxed ask` |
| [concepts.md](concepts.md) | Levels 0 to 4, placeholders and scopes, the vault, the journal and its signatures, policy categories, observation, training checks, the limits |
| [claude-code-and-codex.md](claude-code-and-codex.md) | The workspace mirror and sync, hooks and what they block, MCP tools, `boxed run`, the sandbox and the agent's environment |
| [skills.md](skills.md) | `boxed skills`: check the skills, plugins, MCP servers and hooks of your agents before and after you install them, read the verdicts, quarantine and restore, the warning at the start of a Claude Code session, the optional `--ai` look |
| [browser-extension.md](browser-extension.md) | Experimental. The side panel, levels, insert and copy, observation mode, training checks, permissions |
| [desktop.md](desktop.md) | Experimental. The desktop app: a window for mask and restore over the same core |
| [files.md](files.md) | `mask-file` and `restore-file`, formats, what is left out, `--force` and `--replace` |
| [tables.md](tables.md) | Level 4: `plan prompt` and `plan run`, the plan grammar, budgets, number formats |
| [api.md](api.md) | `boxed key`, `boxed ask`, providers, accounts, relays, cost, exit codes |
| [policy.md](policy.md) | Profiles, `boxed policy check`, rules in `boxed.toml`, the EEA warning |
| [configuration.md](configuration.md) | Every `boxed.toml` key and every environment variable |
| [dashboard-and-journal.md](dashboard-and-journal.md) | `boxed dashboard`, the CSV, `journal verify`, `show`, `export`, `check-export`, the device key, `boxed audit` |
| [privacy.md](privacy.md) | What leaves the computer, what is stored where and for how long, what boxed never collects |
| [troubleshooting.md](troubleshooting.md) | Exit codes, error texts and what to do, how to report a problem without sending data |
| [cli.md](cli.md) | Every command with its usage line, arguments and options. Generated from the program |

## Commands and the page that explains them

| Command | Page |
|---|---|
| `mask`, `restore` | [quickstart.md](quickstart.md), [concepts.md](concepts.md) |
| `mask-file`, `restore-file` | [files.md](files.md) |
| `plan prompt`, `plan run` | [tables.md](tables.md) |
| `ask`, `key` | [api.md](api.md) |
| `policy check` | [policy.md](policy.md) |
| `workspace`, `run`, `hook`, `mcp` | [claude-code-and-codex.md](claude-code-and-codex.md) |
| `skills` (`scan`, `list`, `quarantine`, `restore`) | [skills.md](skills.md) |
| `install` | [install.md](install.md), [browser-extension.md](browser-extension.md) |
| `check` | [concepts.md](concepts.md), [browser-extension.md](browser-extension.md) |
| `journal`, `dashboard`, `audit` | [dashboard-and-journal.md](dashboard-and-journal.md) |

## How to read the examples

Examples show commands as `boxed ...`. The outputs are real: each example ran once in a throwaway home (`HOME` and `BOXED_HOME` set to new folders, `BOXED_KEYSTORE=insecure-file`), on made-up data. The examples that call an AI provider ran against a test server on the same computer. Timestamps, hashes and keys differ on your computer. A `...` marks shortened text, such as the front of a long path.

To try boxed without touching your real data, start a throwaway home the same way, with the block in "Try it without touching your own data" in [install.md](install.md#try-it-without-touching-your-own-data). A new `HOME` matters: `audit` and `skills scan` read your real `~/.claude` and `~/.codex` otherwise, and `install codex` and `skills quarantine` change them. It does not hide the system keychain, where API keys live: the same section says how to check which key boxed will use.

## Where to look

- Start with [install.md](install.md), then [quickstart.md](quickstart.md). On Windows, read [windows.md](windows.md) too.
- To choose a level, read [concepts.md](concepts.md).
- When a command fails, see [troubleshooting.md](troubleshooting.md).
- For a security review, give your security team [docs/security](../security/README.md) and [dashboard-and-journal.md](dashboard-and-journal.md).
