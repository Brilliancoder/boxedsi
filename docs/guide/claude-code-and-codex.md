# Claude Code and Codex

An AI coding agent reads whole files, logs and configs. boxed gives it a masked copy of your project to work in. This page covers the copy (the workspace), the hooks that guard it, the MCP tools for files outside the project, the macOS sandbox, and the limits. boxed prints full paths; this guide shortens your home folder to `~`.

## The idea

A masked workspace is a copy of your project in which secrets and personal data are placeholders such as `[EMAIL_1]` and `[SECRET_2]`. The agent works in the copy and never in the real project. When it is done, you run `boxed workspace sync` in your own terminal. boxed puts the agent's edits into the real project and swaps the originals back in.

```text
your project  --create-->  masked copy  <--->  Claude Code or Codex
     ^                         |
     +-------- sync <---------+   (originals restored, you run it)
```

boxed has no server. The agent still talks to its own provider, and what it reads in the copy goes there as placeholders. The placeholder map stays on your computer in the encrypted vault (`vault.db`) and never goes into the copy.

## Before you start: what already went out

`boxed audit` finds potential secrets and personal data in the saved session records of Claude Code (`~/.claude/projects`) and Codex (`~/.codex/sessions`), and in the settings files of Claude Code (not those of Codex). A finding in a session record shows a possible exposure to the provider: audit reads what was saved on your computer and cannot check that a request reached the provider. A finding only in a settings file shows that the value is stored on disk. The report shows kinds and counts, never values.

```text
$ boxed audit
boxed audit: 99 items checked, 0 malformed lines skipped
found: SECRET 25, EMAIL 6, CARD 1, PHONE 1, PRIVATE_KEY 1, IP 1
  claude-code: SECRET 15, EMAIL 4, CARD 1, PHONE 1, PRIVATE_KEY 1, IP 1
  codex: SECRET 10, EMAIL 2
by role: tool_result 24, user_prompt 6, attachment 5
top projects:
  ~/work/acme-api: SECRET 15, EMAIL 4, CARD 1
  ~/work/infra: SECRET 6, PRIVATE_KEY 1, IP 1, EMAIL 1
  ...
secrets: 13 unique (11 known key formats, 2 possible), 27 occurrences

known key formats (11)
A pattern or checksum match: boxed does not check that a value is real or still valid.
In a saved local record of a session: if real, rotate the credential or call the card issuer.
~/.claude/projects/~-work-acme-api/88b6d373-a33a-4bff-9ee1-186026989e42.jsonl
  :16  SECRET #85b77ae0b721 x4
  ...
```

The output comes from the made-up home of `scripts/demo/make_home.py`. A known format is a match of a pattern or a card checksum: confirm whether the value is real, then rotate an exposed credential or contact the card issuer. One found only in a settings file is on disk; no match for it turned up in the session records this report checked. The `#...` tag is a keyed hash that groups equal secrets. Options: `--since YYYY-MM-DD`, `--html FILE` for a report page, `--level` (default 2), `--claude-dir` and `--codex-dir`. The whole report is explained in [dashboard-and-journal.md](dashboard-and-journal.md#what-already-went-out-boxed-audit).

## Create a masked workspace

```text
$ boxed workspace create ~/work/project
workspace 34a67d02 created: 3 files masked, 0 skipped, level 2
mirror: ~/.boxed/workspaces/ws-34a67d02
```

The id (`34a67d02`) names the workspace in later commands. The copy, called the mirror, lives in `~/.boxed/workspaces/ws-<id>`. boxed only reads your project. `create` needs the path of a folder that exists. Without a path, or with a path that does not exist or is a file, it stops with an error and writes nothing.

**Which files are copied.**

- If the folder you name is the root of a git repository (it holds `.git`): the files git lists, which are tracked files and untracked files that `.gitignore` does not exclude. boxed does not copy ignored files such as `.env` or `node_modules`. It also leaves out files that git tracks in folders named `.git`, `node_modules`, `.venv` and `__pycache__`, as it does in any other folder.
- In any other folder, including a subfolder of a repository: every file except those in folders named `.git`, `node_modules`, `.venv` and `__pycache__`. boxed does not use git here, so it copies (and masks) a `.env` that `.gitignore` excludes.
- Text files only, up to 5 MiB. boxed lists each file it does not copy, with a reason: `symlink`, `too-large`, `binary` (a NUL byte in the first 8 KiB), `non-utf8`, `reserved` (the names `.boxed-workspace` and `.claude/settings.local.json`, which boxed uses itself), `missing` or `name-taken` (the mirror already holds a file under that name: `a.txt` and `A.txt` of a project on a case-sensitive volume, when the mirror lies on a volume that reads them as one). A link to a folder is not followed and is not listed.

```text
workspace 925123a1 created: 2 files masked, 4 skipped, level 2
mirror: ~/.boxed/workspaces/ws-925123a1
  skipped dump.sql (too-large)
  skipped legacy.txt (non-utf8)
  skipped link.txt (symlink)
  skipped logo.png (binary)
```

**What is masked.** The text of every copied file, and the names of files and folders. The file `exports/anna.petrova@example.com.csv` becomes `exports/[EMAIL_2].csv` in the copy. `sync` turns the name back, also for new files the agent creates. File modes are kept.

**The level.** `--level N` sets it. Otherwise it is `level` in the `boxed.toml` that boxed finds from the project folder upward, and otherwise 2. Levels 0 to 3 work. Level 4 is the plan route for tables (see [tables.md](tables.md)), and `workspace create` refuses it. What each level hides is in [concepts.md](concepts.md).

**What boxed adds to the copy.** Two files. `.boxed-workspace` is a marker with the id, which the hooks use to know they are in a copy and `sync` uses to know that the folder is the copy boxed made. `.claude/settings.local.json` holds the rules for Claude Code (see "Hooks and rules").

**What the copy is not.** It has no `.git` folder, so commit in the original project after you sync. It is made once. If the project changes afterwards (a `git pull`, an edit in your editor), the copy does not follow. Drop it and create a new one when the project moves on.

boxed writes one journal record (`workspace`, `prepared`) with the number of placeholders per kind. It holds no values.

## Work in the copy

**Claude Code** (version 2.1.295 or later). Start it in the root of the copy. The rules and hooks come from the `.claude/settings.local.json` there, so they do not apply anywhere else.

```text
$ cd ~/.boxed/workspaces/ws-34a67d02
$ claude
```

**Codex.** Register boxed's MCP server once with `boxed install codex` (see [install.md](install.md)). Then start Codex under the sandbox:

```text
$ cd ~/.boxed/workspaces/ws-34a67d02
$ boxed run codex
```

Codex gets none of boxed's hooks, neither the guard hooks of a copy nor the warning of the plugin. On macOS, the sandbox of `boxed run` is its only guard, so use it. The MCP tools start inside that sandbox but fail there (see "`boxed run` and the sandbox"). Without the sandbox, the copy keeps the original out of Codex's view, but nothing stops Codex from opening the original by its path.

The agent sees placeholders in files, in file names and in tool output. It should keep them exactly as they are and not invent new ones. In a Claude Code session the `SessionStart` hook tells it so. The secrets in the files of the copy are placeholders: `API_KEY = "[SECRET_1]"` is not a key, so code in the copy cannot use the keys and passwords that were in your project's files, and tests that need a real password, host or address do not pass there. That is all the copy itself does. The network is open, and code in the copy can still use any credential it finds elsewhere: in the environment (`boxed run` keeps most of those out, see below), in files outside the project such as `~/.aws` or `~/.netrc`, or in the agent's own sign-in.

Run `boxed` commands in your own terminal. In a Claude Code session the hooks block them, so the agent cannot restore or probe values.

## Hooks and rules

`boxed workspace create` writes `.claude/settings.local.json` into the copy. It holds:

- `permissions.deny` rules that stop Claude Code from reading or editing your original project and boxed's own data.
- The setting `blockReadsOutsideWorkingDirectories`, which asks Claude Code to block reads outside the copy.
- Claude Code's sandbox, switched on for Bash and told not to read the original or boxed's data.
- Three hooks that run `boxed hook <event>`. The two that guard carry `onFailure: "block"`: if a hook cannot run, Claude Code blocks the step. That is why Claude Code 2.1.295 or later is required.

These three hooks come from this file and exist only inside copies; the plugin from `boxed install claude` does not carry them. The plugin has one hook of its own, `boxed hook skills-check`. It runs at the start of a session and after `/clear`, in any folder, and only tells you when the extensions of your agents are new or changed since `boxed skills scan`, or were found dangerous and are still installed. It never blocks anything (see [skills.md](skills.md)). The command of the three hooks holds the path of `boxed` from the day you created the copy. If you move `boxed`, create the copy again. When `boxed` was not on the `PATH` that day, the command is `python -I -m boxed.cli`, with the Python that ran `workspace create`: `-I` keeps a package named `boxed` that the agent writes into the copy from taking the place of boxed (the hooks run in the copy, and Python would look there first). The command of `boxed install codex` is made the same way.

| Hook | When | What boxed does |
|---|---|---|
| `SessionStart` | A session starts in the copy | Adds a short note: values like `[EMAIL_1]` are placeholders, keep them, work inside this folder, quote paths that hold placeholders. |
| `UserPromptSubmit` | You send a prompt | Looks for secrets and personal data in your text, at the level of the copy. If it finds any, the prompt is blocked. |
| `PreToolUse` | Before `Read`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `Grep`, `Glob`, `Bash` and `Monitor` | Blocks calls that reach protected places, run boxed or write files that run code. |

**A blocked prompt.** Claude Code does not send it. boxed says what it found and how to mask it with the scope of the copy, so the new placeholders match the ones in the files:

```text
boxed: prompt blocked, it contains EMAIL 1. Mask it first, for example: pbpaste | boxed mask --scope ws-34a67d02 | pbcopy, then paste again.
```

The journal record (`claude-code`, `blocked`) holds the kinds and counts, not the text. A prompt that holds only placeholders passes. At level 0 only secrets and card numbers block a prompt.

**What `PreToolUse` blocks.**

- Calls aimed at protected places: your original project; the folders that hold it (its parent, your home folder, `/`); boxed's data (vault, journal, state, reports, observation log, checks, logs, key files, the record and quarantine of `boxed skills`); other masked copies; and every folder you list in `protected_paths` in `boxed.toml`. The hook resolves `..`, links, quotes, escapes, braces and wildcards. It lists the files a wildcard stands for and checks every match.
- Every `boxed` command in Bash, in the spellings the hook can recognise (`boxed`, a path to it, `python -m boxed.cli`).
- Writes with `Write`, `Edit`, `MultiEdit` and `NotebookEdit` into `.git`, `*.pth`, `sitecustomize.py`, `usercustomize.py` and boxed's own files in the copy (the marker and the settings). Also writes of text that would run boxed: an import, a module run, or a `boxed` command at the start of a command in a script.

A few plain lines are allowed although they name a folder that holds protected data (the parent of your project, your home folder, `/`), because they read nothing from it: `echo`, `printf`, `pwd`, and `expr` and `$(( ))` arithmetic over numbers. A path inside the protected data itself stays blocked in every case.

The agent sees a short message. For example:

```text
boxed: Read blocked: it points outside the masked workspace. Work only with files inside this folder.
boxed: Bash blocked: boxed commands do not run inside the masked workspace. Run them in your own terminal.
boxed: Write blocked: this text would run boxed (an import, a module run or a boxed command). boxed commands do not run inside the masked workspace. Run them in your own terminal.
```

**When a hook fails.** Inside a copy, a failure while the hook checks a call blocks the step with exit code 2 and the line `boxed: the hook failed and blocked this step; details are in the boxed hook error log`. That covers input the hook cannot read and a boxed folder it cannot open. A hook that cannot tell whether it is in a copy counts as inside one. The log is `hook-errors.log` in the boxed folder (mode 600, and the rules keep the agent from reading it). Under `boxed run` the sandbox does not let a hook write that log, so the line on screen is all you get there. Outside a copy a hook never blocks and prints nothing, so a Claude Code session in another folder is not touched.

**Hooks are best effort.** They read the text of a command. They cannot know what a running program does. Names and paths built at run time, a bare `~` or `/` inside a nested shell string (`bash -c 'ls ~'`), a `cd` that is not followed by `&&` on the same line, and arithmetic the hook cannot compute can still reach outside. The marker and the settings in the copy are protected from the file tools only. A Bash command such as `rm .claude/settings.local.json` or `mv .claude .claude-old` passes the hook, and the next session in that copy would then run without the rules and hooks. Under `boxed run` the sandbox refuses both. A differential test against real bash and zsh (about 400,000 generated commands, see the [threat model](../security/threat-model.md)) found no harmful allowance. That is evidence, not proof. Tools that are not in the matcher, such as web fetches, are not looked at. The hard guard is the macOS sandbox of `boxed run`, and the hooks work inside it (see below).

## Review and sync back

Run `sync` yourself, in your own terminal. Start with a dry run and a diff. The diff shows real values, so it stays in your terminal.

```text
$ boxed workspace sync 34a67d02 --dry-run --diff
would write app.py
would create NOTES.md
--- a/NOTES.md
+++ b/NOTES.md
@@ -0,0 +1,3 @@
+# Notes
+
+The export failed for anna.petrova@example.com because DB_HOST (db1.acme.internal) timed out.
--- a/app.py
...
```

Then run it without `--dry-run`:

```text
$ boxed workspace sync 34a67d02
write app.py
create NOTES.md
```

`sync` looks only at files that changed in the copy since the copy was made or last synced. For each one it restores the placeholders and writes the file into the project. A second `sync` right after writes nothing again. It repeats only the lines that still need your attention (`conflict`, `refused`, `kept`, see below).

`sync` skips some files without a message:

- Files in folders named `.git`, `node_modules`, `.venv` and `__pycache__`, in every project. `create` leaves them out as well, so they are not in the copy, and edits there never come back. `--delete` never deletes their originals.
- New files that the project's `.gitignore` excludes (for example `build/output.txt`), when the project folder is the root of a git repository.

Lines on standard output say what changed. Dry runs say `would write`, `would create` and `would delete`.

- `write <path>`: boxed changed an existing file.
- `create <path>`: boxed wrote a new file.
- `delete <path>`: boxed deleted an original. Only with `--delete`.

Lines on standard error say what needs your attention.

- `conflict <path>: the original changed since the mirror was made`. boxed never overwrites a file that changed in your project after the copy was made. A new file whose name is already taken is a conflict too. So is a file whose path in your project goes through a link, or through a file where a folder must be (the agent turned a file of the copy into a folder: the original file stays, and the files in the new folder are conflicts).
- `refused <path>: [EMAIL-1], EMAIL_2 (use --force after checking)`. The file holds a placeholder that is not in the map, or one that looks changed (here a hyphen in place of the underscore, and round brackets in place of square ones).
- `failed <path>: Permission denied`. The file system refused the change in your project (a read-only file or folder), or boxed cannot read the file in the copy. That file is untouched, and `sync` goes on with the others. A dry run says the same.
- `unreadable <folder>: boxed cannot look into this folder of the mirror, so nothing in it was synced`. The agent may have changed the rights of the folder. Fix them and run `sync` again. `--delete` does not delete the originals of files in such a folder.
- `not in the mirror: <path>`. A path you gave to `--only` is not in the copy.
- `kept <path>: deleted in the mirror, add --delete to delete the original`. The agent deleted the file. boxed keeps the original unless you ask.

Exit code 0 means nothing needed your attention (a `kept` line alone is still 0). Exit code 3 means at least one conflict, refusal, failed file, unreadable folder or unknown `--only` path. Exit code 2 is an error, for example an unknown id, a mirror that is not the folder boxed made (see `--delete`), or a journal that another process holds for more than 30 seconds or that cannot take a record. A run that is not a dry run takes the lock of the journal and checks it before it writes any file of your project, so these errors leave your project as it was.

Options:

- `--dry-run`: change nothing and print what would happen. The report is the one a real run gives, `failed` lines included, as far as the rights of the files show.
- `--diff`: print a unified diff of every change, with real values.
- `--only PATH`: look at this path of the copy only. Repeat it for more.
- `--force`: accept files with unknown or odd placeholders. Check first: the placeholder stays in your file as it is. With `--only`, it applies to those files alone. It cannot override a link, a file that is not UTF-8 or a path outside the project.
- `--delete`: delete the originals of files the agent deleted. boxed deletes an original only if all of this holds: the copy held the file (made by `create`, or by an earlier `sync`), the file system finds nothing at its path in the mirror, and the original is still as it was after the last sync. A folder that became a link, in the mirror or in your project, and a mirror folder that boxed cannot read, stop the deletion. A folder that the agent replaced by a file counts as deleted, with the files in it: `--delete` deletes their originals (the new file is a conflict, because the folder is in your project). A file you added to your project after the copy was made is never deleted. `sync` stops with an error, with or without `--delete`, if the mirror folder is missing, is a link, cannot be read, or has no `.boxed-workspace` that names the workspace (a folder made again empty has none).

**To resolve a conflict**, restore the agent's version by hand and merge it yourself. The scope of a workspace is `ws-<id>`:

```text
$ boxed restore --scope ws-34a67d02 ~/.boxed/workspaces/ws-34a67d02/app.py
```

`sync` writes one more journal record (`workspace`, `received`) with the numbers of files written, created and deleted.

## List and drop

```text
$ boxed workspace list
34a67d02  level 2  2026-10-24T10:18:03.715276+00:00  ~/work/project -> ~/.boxed/workspaces/ws-34a67d02
$ boxed workspace drop 34a67d02
workspace 34a67d02 dropped
```

`drop` deletes the copy, its state file, its placeholder map from the vault and the cache folder that `boxed run` made for it in your temporary folder. Edits you did not sync are lost, and nothing masked under that scope can be restored afterwards. boxed does not touch your project.

## Files outside the project: the MCP tools

The agent cannot read your original project. A log folder outside it needs another way in. `boxed mcp` is a stdio MCP server with two tools. `boxed install claude` and `boxed install codex` register it (see [install.md](install.md)).

| Tool | Arguments | Result |
|---|---|---|
| `read_masked` | `path` | The text of one file, with placeholders. |
| `search_masked` | `pattern`, `root`, `max_results` (default 200) | Lines `path:line: text` from the masked text of the files under `root`. |

Both tools reach only the folders you list as `mcp_roots` in `boxed.toml`. A relative root counts from the folder of that file. boxed looks for the file from the folder where the server starts, going up. Inside a copy it uses the settings your project had when you made the copy. The tools read text files only: UTF-8, up to 5 MiB, no binaries. `search_masked` skips links.

Give the tools absolute paths. A relative path counts from the folder where the server runs, and inside a copy that is the copy. It then falls outside every root and gives `path is not inside an allowed root (set mcp_roots in boxed.toml)`. This is what the tools return for a made-up log folder, `/var/log/myapp`, listed as an `mcp_roots` entry. `search_masked` shows file names relative to the root:

```text
read_masked("/var/log/myapp/orders.log")
2026-10-21 09:14:02 INFO  order 8812 created for [EMAIL_1]
2026-10-21 09:14:03 ERROR payment failed token=[SECRET_1]
2026-10-21 09:14:05 INFO  order 8813 created for [EMAIL_2]
2026-10-21 09:14:09 ERROR payment failed for [EMAIL_2] from [IP_1]

search_masked("failed", "/var/log/myapp")
orders.log:2: 2026-10-21 09:14:03 ERROR payment failed token=[SECRET_1]
orders.log:4: 2026-10-21 09:14:09 ERROR payment failed for [EMAIL_2] from [IP_1]
```

boxed matches the pattern against masked lines. A search for `anna\.petrova` finds nothing, so the agent cannot use search to test guesses about hidden values. File names in results are masked. A masked name that you pass back to `read_masked` is restored on your computer first. There is no restore tool.

When the server runs inside a copy, it uses the placeholder map of that copy, so `[EMAIL_1]` means the same address in files and in logs. Outside a copy the scope is `mcp-YYYYMMDD` (the UTC date). Each call writes a journal record (`mcp`, `sent`) with the tool name and the counts.

Two things keep this honest:

- Also list the folder in `protected_paths`. The hook does not treat `mcp_roots` as protected. Without that line, a `cat` of the log folder passes the hook and the agent reads the raw log. With it, the hook blocks the call.
- Keep the agent from writing into those folders.

## `boxed run` and the sandbox

On macOS, `boxed run` starts the agent under `sandbox-exec` with a profile that boxed writes to `~/.boxed/state/<id>.sb`. Run it from inside the copy.

```text
$ cd ~/.boxed/workspaces/ws-34a67d02
$ boxed run claude -- --model sonnet
```

Arguments after `--` go to the agent. The exit code is the exit code of the agent.

**The environment of the agent.** Variables that look like credentials are kept out of it, and one line before the start names them (names only, never values):

```text
boxed: kept out of the agent's environment: AWS_SECRET_ACCESS_KEY, DATABASE_URL, GITHUB_TOKEN, SSH_AUTH_SOCK (--keep-env NAME passes one)
```

- **Kept out:** a variable whose name has a word of credentials in it (`KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `PASSWD`, `PWD`, `AUTH`, `CREDENTIALS`, `COOKIE`, `BEARER` and the like, also inside a longer or fused name such as `GITHUB_TOKEN`, `PGPASSWORD`, `MYSQL_PWD`, `NPM_TOKEN` or `dbPassword`), `SSHPASS`, `BW_SESSION` and any `*_DSN` (a DSN holds the key of its client), and a variable whose value boxed's detectors read as a secret, a private key or a JWT (`DATABASE_URL=postgres://app:password@host/db`, a GitHub token under any name). `SSH_AUTH_SOCK` is kept out too: it lets a program use your SSH keys. So git over ssh inside `boxed run` (a `git fetch` from a `git@...` remote, an ssh dependency of a package install) needs `--keep-env SSH_AUTH_SOCK`; then the agent and what it starts can use your loaded keys too.
- **Passed anyway:** the variables the agent signs in with, so that it can start: `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` and `CLAUDE_CODE_OAUTH_TOKEN` for Claude Code, `OPENAI_API_KEY` and `CODEX_API_KEY` for Codex. `PWD`, `OLDPWD` and the proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, in either case) pass even when a proxy address holds a password: the agent needs them to reach its provider.
- **Everything else passes as it is:** `PATH`, `HOME`, the locale, `TERM`, the settings of your tools.
- **`--keep-env NAME`** passes one more variable (repeatable), before or right after the agent's name: `boxed run claude --keep-env NPM_TOKEN -- --model sonnet`.

The agent's own sign-in key is in its environment, so the agent and every process it starts in the copy (a test, a script, a package install) can read it. So can they read a variable you pass with `--keep-env`. A credential in a file outside the protected places (`~/.aws/credentials`, `~/.netrc`, `~/.npmrc`) is not in the environment and stays readable: list such folders in `protected_paths` for the hooks, and know that the sandbox does not hide them.

What the profile does:

- **Denies** reading and writing of your original project and of boxed's data: the observation log, the checks, the reports, the key files, the logs, `bin/` and `skills/` (the record and quarantine of `boxed skills`).
- **Denies writing** everywhere except the copy, `journal.jsonl` and its lock file, the temporary folders, `/dev`, `~/.claude`, `~/.codex` and `~/Library/Caches`. That leaves out `~/.local`, where uv keeps the code of boxed, `~/.claude.json`, which holds your Claude Code MCP servers, and `~/.cache`, whose uv wheels your next `uv run` unpacks and whose scripts your shell may source: code written there would run outside the sandbox. `boxed run` gives the agent a cache folder of its own in your temporary folder instead (`XDG_CACHE_HOME` and `UV_CACHE_DIR`, one for each copy), so `uv run` works. Claude Code cannot save its choices in `~/.claude.json` under `boxed run`, so it asks again at each start whether you trust the copy.
- **Denies writing** to the files and folders that change what agents do later. In `~/.claude`: `settings.json`, `settings.local.json`, `CLAUDE.md` and the folders `agents`, `commands`, `skills`, `hooks`, `plugins`, `rules`, `output-styles`, `workflows` and `local`. In `~/.codex`: `config.toml`, `AGENTS.md`, `AGENTS.override.md`, `hooks.json` and the folders `rules`, `prompts`, `skills`, `plugins` and `agents`. In the copy: the whole `.claude` folder (the `.claude` files of your project too), `.mcp.json` and `.boxed-workspace`. The copy, `~/.claude` and `~/.codex` cannot be renamed or removed, or the agent could move them away, change what is in them and move them back.
- **Refuses the ways out that macOS offers**, where the system starts something, or types, for a caller outside the sandbox: `open` and every other launch of an app (an app of five lines that the agent wrote, started with `open -g -j`, ran outside the sandbox, wrote a denied path and copied the original `.env` to a folder the agent can read), Apple Events (`osascript` to Terminal or System Events), `defaults write` (the preferences of a Terminal profile can run a command), typing into the terminal of your shell (`TIOCSTI`: your shell runs the characters when the agent ends), keystrokes posted through the window server, login items and background tasks, your Shortcuts, the request for your password that runs a command as root (`osascript` with administrator privileges), and the sockets of Docker, containerd and Podman. `launchctl`, `crontab` and `at` are refused by macOS itself. So `docker`, `open`, `osascript`, `defaults write`, `screencapture` and `shortcuts` fail inside `boxed run`.
- **Allows** the rest, the network included. The agent needs its provider.

A test with a stand-in script for the agent, run under `boxed run claude`, gave these results. Reading and writing in the copy worked. Reading a file of the original project failed at the operating system, not in a hook:

```text
cat: ~/work/project/config.env: Operation not permitted
```

Writes to `~/.local`, `~/.claude.json`, `~/.codex/AGENTS.md`, the copy's `.claude` folder and the copy's `.mcp.json` failed with the same error. So did renaming `.claude`, and moving the copy, `~/.claude` or `~/.codex` away. Reading `vault.db` worked (see the limits).

**The hooks work inside `boxed run`. The MCP tools do not.** The agent starts both as child processes, so they start inside the sandbox. A hook reads the state file of the copy and the files it checks, and a prompt it blocks is appended to `journal.jsonl`, which the profile allows. The same test ran the hooks the way Claude Code runs them. `PreToolUse` blocked a `Read` of the original project (exit code 2) and let a `Read` in the copy through, `SessionStart` added its note, and `UserPromptSubmit` blocked a prompt that held an email address. A hook that fails blocks the step, as anywhere in a copy. `boxed mcp` starts and lists `read_masked` and `search_masked`, but a call to either answers `Error executing tool read_masked: not available inside boxed run yet` (or the same for `search_masked`), before it touches anything, and the server logs no crash. A call has to save the placeholders it hands out in `vault.db`, and the sandbox keeps `vault.db` and its lock file read-only: an agent that could write them could destroy the map that restores your files. Use the MCP tools in a session without `boxed run`. A broker outside the sandbox is the planned fix.

**The profile still leaves some writes open.** `~/.claude` and `~/.codex` keep the sessions, history and caches of the agents, so only the files and folders named above are read-only there. A script that one of your settings points to, inside `~/.claude`, is writable. So is `~/Library/Caches`, and the agent can read your clipboard (`pbpaste`). In the copy, `AGENTS.md`, `CLAUDE.md` and a `.codex` folder are ordinary files. Tools that install into `~/.local` (`uv tool install`, `pip install --user`) fail inside the sandbox. The journal and its lock file are writable, because the hooks write a blocked prompt there. A process of the sandbox that outlives the agent can hold a lock file of boxed through a descriptor that cannot write, or take `journal.jsonl.lock` away and put a folder in its place. boxed waits 30 seconds for a lock and then stops with `boxed: error: another process holds a lock of boxed for too long; try again, or stop that process`; a hook that waits that long blocks the step. A lock path that is not a plain file is refused. Remove the folder, or stop the process, and run the command again. The profile does not look at the sockets of other programs of yours, such as an IDE or a terminal multiplexer: a program that runs commands for whoever connects to its socket is a way out too.

`boxed run claude` adds `--settings '{"sandbox": {"enabled": false}}'`, because the sandbox of boxed replaces the one of Claude Code (macOS cannot nest sandboxes). `boxed run codex` adds `--dangerously-bypass-approvals-and-sandbox` for the same reason, and prints `boxed: Codex runs with its own sandbox off; the macOS sandbox from boxed is the outer guard`.

Two errors you may meet:

```text
boxed: error: run this inside a boxed workspace (boxed workspace create <project>)
boxed: error: claude not found on PATH
```

## Known limits

- **Masking does not stop inference from context.** Placeholders hide direct identifiers. A model can still guess who or what a text is about from the details that remain. Names and companies are found only with a name model or your dictionary (see [install.md](install.md)).
- **Hooks are best effort.** See "Hooks are best effort" above. `boxed run` adds a sandbox, which guards the original project and most of boxed's own data at the operating system level. The hooks work inside it, so `boxed run claude` has both. Codex has the sandbox only.
- **The sandbox is macOS only.** `boxed run` needs `sandbox-exec`. On Linux boxed has no sandbox of its own. The copy still asks Claude Code to use its own Bash sandbox, as far as Claude Code supports it on your system. On Windows `boxed run` is not supported yet.
- **Hooks are for Claude Code.** Codex gets the copy and, on macOS, the sandbox of `boxed run`. It gets none of the hooks and no prompt check. Its MCP tools work only when you start Codex without `boxed run`.
- **The sandbox does not hide or protect everything.** The hooks need `~/.boxed/state/`, so the agent can read it. It holds the path of the original project, hashes of your files and a copy of your `boxed.toml` settings, dictionary terms included. The `boxed.toml` in the boxed folder, which the browser panel uses, is not on the protected list either, so its dictionary terms are readable too. `vault.db` is readable. It is encrypted and its key is in the keychain. An agent that can run code as you could try to read that key. macOS may ask you before it hands the key out; do not rely on that. `journal.jsonl` is writable. The rest of your files stay readable. List sensitive folders such as `~/.ssh` in `protected_paths`, and remember that only the hooks enforce that list. A broker outside the sandbox is the planned fix: it would keep the state and the vault where the agent cannot read them, and the hooks and the MCP tools would ask it.
- **The agent can read `.claude/settings.local.json` in the copy.** It names the original project folder (not its content). Use neutral folder names if the name itself is sensitive.
- **Only what goes through boxed is protected.** Text you type or paste into a chat yourself is not checked. In a Claude Code session in a copy, also under `boxed run`, the prompt hook catches the data it can detect, and nothing catches the rest. A session in another folder, and Codex, are not covered by it.
- **The journal proves what boxed recorded.** It does not prove that nothing was sent around boxed.
- **Not everything is copied.** Binaries, big files, links and files that are not UTF-8 are left out, so the agent cannot see them.
