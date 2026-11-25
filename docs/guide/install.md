# Install

This page covers the install, the optional parts (file formats, name models, the browser extension, the Claude Code plugin, Codex), where boxed keeps its data, and how to remove it. boxed prints full paths; this guide shortens your home folder to `~`.

## What works where

- **macOS:** the main development platform; every feature works here. The experimental desktop app needs macOS 14 or later on Apple silicon.
- **Linux:** the full test suite passes in a Linux container as a regular user; boxed has not been tried on a Linux desktop yet. The commands use POSIX calls only, with two exceptions that work on macOS only: `boxed run` (it needs `sandbox-exec`) and the browser extension, whose host `boxed install native-host` refuses to register (`boxed install native-host works on macos and windows only`). boxed keeps its keys in the system keyring, so a Secret Service such as GNOME Keyring or KWallet must be running. Without one, the commands that need a key (`mask`, `ask`, the journal, the dashboard, the workspace) stop with:

  ```text
  boxed: error: the system keychain cannot be used, and boxed keeps its keys there: on linux, run a secret service such as gnome keyring or kwallet in your session
  ```

  `boxed audit` still runs without a keyring: it says `boxed: no keychain: prefixes are random for this run`, so the hashes in its report differ from run to run. A scan of a folder (`boxed skills scan <folder>`), `boxed skills list`, `boxed policy check` and `boxed journal check-export` work as usual. A scan of what is installed (`boxed skills scan`) shows its verdicts, warns that the check was not saved and exits with code 1.

- **Windows 11:** the core commands and the browser extension's host work. Install the same way with Python 3.13; `boxed install native-host` registers the host for Chrome and Edge under your user's registry (`--remove` undoes it). Not yet: the Claude Code and Codex plugin (`workspace`, hooks, `mcp`, `install claude|codex`) and `boxed run`, which stop with "not supported on Windows yet". `BOXED_HOME` must sit inside your user profile, and Credential Manager works only in your own desktop session. `boxed skills` reads the same folders in your profile and is written for Windows; CI runs `boxed skills scan` on Windows, but nobody has tried it on a Windows desktop yet, and about 100 tests of `serve` and `skills` do not pass on Windows yet. Details: [windows.md](windows.md).

## Install boxed

You need [uv](https://docs.astral.sh/uv/) (on macOS: `brew install uv`) and git. boxed is not on PyPI yet, so install it from GitHub:

```text
$ uv tool install --python 3.13 git+https://github.com/boxedsi/boxedsi
Resolved 34 packages in 764ms
...
Installed 1 executable: boxed
$ boxed --version
boxed 0.1.0
```

To try one command without installing anything, `uvx` runs boxed from a temporary environment: `uvx --from git+https://github.com/boxedsi/boxedsi boxed audit`.

From a copy of the repository, give its folder (the one that holds `pyproject.toml`) instead of the address: `uv tool install --python 3.13 /path/to/boxedsi`, or `uv tool install --python 3.13 .` inside that folder.

Use `--python 3.13`. The project pins 3.13, and without the flag uv takes the newest Python it finds. The `ner-en` extra needs torch, and torch may not support the newest Python.

If the shell says `boxed: command not found`, uv installed it into a folder that is not on your `PATH`. Run `uv tool update-shell` and open a new terminal.

boxed keeps its own keys in the OS keychain (service `boxed.si`) and creates each one the first time a command needs it. macOS may ask you to allow access. While it creates a key it holds `~/.boxed/keychain.lock`; when the home folder is missing or read-only (and `BOXED_HOME` points elsewhere), the lock goes to a folder of your user in the system's temporary folder (`boxed-<user number>`, mode 0700), which boxed uses only when it is a folder of yours closed to others. Masking and restoring need a usable keychain, and so do the journal, the dashboard, the workspace and `boxed ask`. Without one, `audit` uses a temporary key for the run; a scan of a folder, `policy check` and `journal check-export` work as usual; a scan of what is installed shows its findings but cannot save them.

## Extras

The base install handles text, CSV and the API commands. Three extras add more. Each one is a name in square brackets after `boxedsi`:

| Extra | Adds | You need it for |
|---|---|---|
| `formats` | `openpyxl`, `python-docx`, `pypdf` | `boxed mask-file` on XLSX, DOCX and PDF files (CSV works without it) |
| `ner-ru` | Natasha | finding Russian names and companies |
| `ner-en` | GLiNER (needs torch) | finding names and companies in English, Russian and German; about 1 GB to download on first use and about 2.5 GB of memory |

Put the extras in the install command. The address (or the path of your copy) comes after `@`:

```text
$ uv tool install --python 3.13 "boxedsi[formats,ner-ru] @ git+https://github.com/boxedsi/boxedsi"
```

To add an extra later, run the install again with `--reinstall`:

```text
$ uv tool install --python 3.13 --reinstall "boxedsi[formats,ner-ru] @ git+https://github.com/boxedsi/boxedsi"
```

An extra only installs the code. A name model runs when `boxed.toml` asks for it with `ner = ["ru"]` or `ner = ["en"]` (see [configuration.md](configuration.md)). Without the extra, that setting stops boxed with an error that names the missing package:

```text
boxed: error: no module named natasha: install the extra that brings it (see install.md)
```

An XLSX, DOCX or PDF file without the `formats` extra gives:

```text
boxed: error: this file type needs the formats extra: reinstall boxed with it, as docs/guide/install.md shows
```

Add `formats` to the extras and run the install again with `--reinstall`, as above.

Without a name model, boxed finds only what patterns and your dictionary can find: e-mail addresses, phone numbers, keys, IP addresses and the like. A person's name in plain text stays visible. See [concepts.md](concepts.md).

## The browser extension

The extension ships inside the boxed package. You load it into Chrome or Edge by hand, then register the native host that connects it to boxed. This works on macOS and on Windows 11 (see [windows.md](windows.md) for the registry keys). On Linux `boxed install native-host` stops with `works on macos and windows only` and writes nothing: the browsers there look in other folders, which boxed does not write yet.

```text
$ boxed install native-host
boxed: error: native-host needs --extension-id: load ~/.local/share/uv/tools/boxedsi/lib/python3.13/site-packages/boxed/_extension unpacked in the browser, then copy its id
```

The error is expected. It names the folder to load. Open `chrome://extensions` (or `edge://extensions`), turn on Developer mode, press Load unpacked and pick that folder. In the macOS file dialog, press Cmd+Shift+G and paste the path, because the folder is hidden. Copy the extension id the browser shows, then register the host:

```text
$ boxed install native-host --extension-id <id>
wrote: ~/Library/Application Support/Google/Chrome/NativeMessagingHosts/si.boxed.host.json
wrote: ~/Library/Application Support/Microsoft Edge/NativeMessagingHosts/si.boxed.host.json
extension folder to load unpacked: ~/.local/share/uv/tools/boxedsi/lib/python3.13/site-packages/boxed/_extension
```

`--dry-run` prints the same lines with `would write:` and writes nothing. The id is 32 letters from a to p. Chrome derives the id of an unpacked extension from its folder path, so a new path (for example after you reinstall with another Python version) means a new id: load the folder again and run the command again.

The full walk-through is in [browser-extension.md](browser-extension.md).

## Claude Code and Codex

```text
$ boxed install claude --dry-run
would run: claude plugin marketplace add ~/.local/share/uv/tools/boxedsi/lib/python3.13/site-packages/boxed/_claude_plugin
would run: claude plugin install boxed@boxed
```

Without `--dry-run`, boxed runs those two commands, so the `claude` command must be on your `PATH`. The same plugin can be added from GitHub inside Claude Code: `/plugin marketplace add boxedsi/boxedsi`, then `/plugin install boxed@boxed`. Either way `boxed` itself must be installed first: the plugin calls it. The plugin adds the `boxed` skill and an MCP server (`boxed mcp`) with two tools, `read_masked` and `search_masked`. It adds one hook, at the start of a Claude Code session (`boxed hook skills-check`): one line when skills, plugins or MCP servers of your agents are new or changed since `boxed skills scan`, or when one it found dangerous is still installed. It finds `boxed` on your `PATH` or in `~/.local/bin` and says nothing without it (see [skills.md](skills.md)). The hooks that guard a masked workspace come with each workspace. Claude Code 2.1.295 or later is required for the masked workspace.

```text
$ boxed install codex
added boxed MCP server to ~/.codex/config.toml
```

This appends a `[mcp_servers.boxed]` block to `~/.codex/config.toml` and keeps the old file as `config.toml.bak`. Run it again and boxed says `boxed is already in ~/.codex/config.toml`. With `--dry-run` boxed says `would add boxed MCP server to ~/.codex/config.toml` (or `boxed is already in ...`) and writes nothing: no folder, no `config.toml.bak`, no change to `config.toml`. Codex gets the MCP server only. Hooks are a Claude Code feature.

What both do in a project is in [claude-code-and-codex.md](claude-code-and-codex.md).

## Where boxed keeps data

Everything lives in one folder, `~/.boxed`, or the folder named by `BOXED_HOME`. boxed sets that folder's mode to 0700 whenever it uses it, so point `BOXED_HOME` only at a folder that is meant for boxed.

| Path in the boxed folder | What it holds |
|---|---|
| `vault.db` | The placeholder maps (placeholder and original), encrypted with AES-256-GCM |
| `journal.jsonl` | The signed journal: kinds, counts and hashes, never values |
| `observed.jsonl` | The observation log, only if you turned observation on in the browser |
| `checks.json` | Your notes about training on chats, signed with the device key |
| `workspaces/ws-<id>/` | Masked copies of projects for AI agents |
| `state/` | One file per workspace (`<id>.json`) and, after `boxed run`, its sandbox profile (`<id>.sb`) |
| `bin/boxed-native-host` | The launcher the browser starts. `boxed install native-host` writes it |
| `reports/` | Reports you write with `boxed audit --html` or `boxed dashboard` if you name this folder |
| `skills/record.json` | What `boxed skills scan` found last: for each item its id, place, SHA-256 digest and verdict, and the rule, severity, file and line of each finding. Also the answers of `--ai` and the list of quarantined items. No evidence text, no value from a config |
| `skills/quarantine/<id>/` | What `boxed skills quarantine` took out: the moved item (`payload`), or the cut config entry in `entry.json` (mode 600; it can hold the values of `env` and headers) and the file as it was before the edit in `original` |
| `boxed.toml` | Optional. The browser extension reads only this file (see [configuration.md](configuration.md)) |
| `hook-errors.log` | One line for each failed hook: the time, the hook and the error class. The error's message is not kept: it can name a file or quote a value |
| `host-errors.log` | One line for each failed start or request of the browser host: the error class, never text |
| `*.lock` | Empty lock files |

Outside the boxed folder:

- **OS keychain**, service `boxed.si`. The names are `vault-key`, `state-mac-key`, `device-signing-key`, `observe-hmac`, `audit-mac-key` and one `api-key:<provider>` for each key you store with `boxed key set`.
- **Browser registration:** `si.boxed.host.json` in the Chrome and Edge folders shown above. If `BOXED_HOME` points elsewhere, the launcher still goes into `~/.boxed/bin`, outside your boxed folder, and exports `BOXED_HOME` for the browser.
- **Codex:** the block in `~/.codex/config.toml` and its `.bak`.
- **Claude Code:** the plugin and the marketplace entry, which Claude Code manages.
- **Config files of your agents:** only when you run `boxed skills quarantine` or `restore`. boxed then edits the file the item lives in (for example `~/.claude/settings.json` or `~/.codex/config.toml`), or runs `claude mcp remove` to take a Claude Code MCP server out of `~/.claude.json`. See [skills.md](skills.md).

What leaves the computer, and when, is in [privacy.md](privacy.md).

## Try it without touching your own data

To run the examples in this guide on made-up data, give boxed a throwaway home in one terminal and run everything there. The other pages of this guide, the contributing guide and the bug report form point here.

```bash
clone="$PWD"   # (clone) run this in your copy of the repository, before HOME changes
export HOME="$(mktemp -d)"
export BOXED_HOME="$HOME/.boxed" BOXED_KEYSTORE=insecure-file
cd "$HOME"
python3 "$clone/scripts/demo/make_home.py" "$HOME"   # (clone) made-up transcripts, a .env and a skill
```

The two lines marked `(clone)` need a copy of the repository and only add made-up data; without a copy, leave them out.

- `HOME`: `boxed audit` and `boxed skills scan` read the agent folders in your home (`~/.claude`, `~/.codex` and the others), and `boxed install codex` and `boxed skills quarantine` change them. A new `HOME` keeps all four away from your real ones. A new `BOXED_HOME` alone does not.
- `BOXED_HOME`: boxed's own data folder (vault, journal, workspaces).
- `BOXED_KEYSTORE=insecure-file`: boxed's own keys go to plain files inside `BOXED_HOME` instead of the system keychain. Use it only with made-up data, never with real data.
- `cd "$HOME"`: the examples create their files in the current folder, and `boxed skills scan` also looks at the project you stand in.
- `make_home.py` writes made-up Claude Code and Codex transcripts for projects in `~/work`, a `~/samples/app/.env` and a harmless skill in `~/samples/release-notes`, so `boxed audit` and `boxed skills scan` have something to find.

A new `HOME` does not hide the system keychain. API keys live there: `boxed key set` ignores `BOXED_KEYSTORE`, and a throwaway home cannot use it reliably (`openai: cannot store the key in the keychain`). Put a test key in the provider's variable for that terminal instead, without typing it on the command line: run `read -rs OPENAI_API_KEY && export OPENAI_API_KEY`, paste the key and press Enter. A key you stored earlier with `boxed key set` comes before the variable, throwaway home or not, so run `boxed key status openai` and go on only if it says `set (environment)` (see [api.md](api.md)).

## Update

Run the install command again with `--reinstall` (and the extras you use). After an update:

- Reload the extension on `chrome://extensions`, so the browser picks up the new files.
- Run `boxed install native-host --extension-id <id>` again if the Python environment moved, because the launcher names the Python that was in use.
- Create the masked workspace again if `boxed` moved. The workspace's hooks hold the path of `boxed` from the day you created it.

## Uninstall

1. Sync the edits you want to keep. Run `boxed workspace list`, then `boxed workspace sync <id>` for each workspace. Nothing else writes into your original projects (apart from a `boxed skills quarantine` you ran yourself). When the original project holds the edits you want, run `boxed workspace drop <id>`: it deletes the mirror and the cache `boxed run` keeps for it in the temporary folder, which deleting the boxed folder in step 7 does not.
   Put back what you quarantined and want to keep: `boxed skills list` shows it, `boxed skills restore <id>` returns it. The quarantine folder goes away with the boxed folder in step 7.
2. Export the journal if the security team needs it: `boxed journal export --out journal.json` (see [dashboard-and-journal.md](dashboard-and-journal.md)).
3. Remove the browser parts: delete the extension on `chrome://extensions`, then run `boxed install native-host --remove` (add `--dry-run` first to see the list). It deletes the two `si.boxed.host.json` files and `~/.boxed/bin/boxed-native-host`, or on Windows the registry keys and the host folder.
4. Remove the Claude Code plugin: `claude plugin uninstall boxed@boxed`, then `claude plugin marketplace remove boxed`.
5. Remove the `[mcp_servers.boxed]` block from `~/.codex/config.toml`. `boxed install codex` also left `~/.codex/config.toml.bak`, a copy of the file as it was before: delete it only if it is that copy and you no longer need it.
6. Remove the program: `uv tool uninstall boxedsi`.
7. Delete the boxed folder. Without `vault.db`, text that boxed masked can never be restored.
8. Delete boxed's keychain items. On macOS, open Keychain Access, search for `boxed.si` and delete the items. On Linux, use your keyring tool, and on Windows Credential Manager: the items have the same service and names.
