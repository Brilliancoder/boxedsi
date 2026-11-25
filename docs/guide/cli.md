# Command reference

This page lists every `boxed` command with its usage line, its arguments and its options. It is generated from the command parser by `scripts/gen_cli_docs.py`, so do not edit it by hand: run `uv run python scripts/gen_cli_docs.py` after a command changes. A test fails while the page is out of date.

- Every command also takes `-h` and `--help`.
- A default of `-` means standard input.
- Where an option has no description, the parser has none. [README.md](README.md) maps each command to the page that explains it.
- Exit codes are in [troubleshooting.md](troubleshooting.md).

| Command | What it does |
|---|---|
| [`boxed mask`](#boxed-mask) | Mask a file or stdin, print the masked text. |
| [`boxed restore`](#boxed-restore) | Put the originals back into a model answer. |
| [`boxed ask`](#boxed-ask) | Send a masked prompt through your API key and print the restored answer. |
| [`boxed key`](#boxed-key) | Store, remove or check the API key of a provider (kept in the OS keychain). |
| [`boxed check`](#boxed-check) | What you know about training on chats, per account: list, set, remove, reset. |
| [`boxed check list`](#boxed-check-list) | Show the checks; exit code 5 when one is due. |
| [`boxed check set`](#boxed-check-set) | Write down what the data controls of an account say. |
| [`boxed check remove`](#boxed-check-remove) | Delete the check of one account. |
| [`boxed check reset`](#boxed-check-reset) | Move a damaged checks.json aside (it is kept, not deleted). |
| [`boxed journal`](#boxed-journal) | Verify, show or export the signed journal; print the device key. |
| [`boxed mask-file`](#boxed-mask-file) | Write a masked clean copy of a CSV, XLSX, DOCX or PDF (PDF to .txt). |
| [`boxed restore-file`](#boxed-restore-file) | Put the originals back into a masked file a model returned. |
| [`boxed dashboard`](#boxed-dashboard) | Write a self-contained HTML overview of the journal, and a CSV of its records. |
| [`boxed audit`](#boxed-audit) | Count secrets and personal data in the local session records and settings files of Claude Code and Codex. |
| [`boxed workspace`](#boxed-workspace) | Masked project mirror for AI agents: create, sync back, list, drop. |
| [`boxed policy`](#boxed-policy) | Check what the company policy allows for a text and a recipient. |
| [`boxed plan`](#boxed-plan) | Level 4: send only the task and the table schema, run the returned plan locally. |
| [`boxed plan prompt`](#boxed-plan-prompt) | Print the prompt: masked task, column names and types, made-up rows. |
| [`boxed plan run`](#boxed-plan-run) | Run the model's plan locally on the real table. |
| [`boxed hook`](#boxed-hook) | Claude Code hook entry point, reads the hook JSON from stdin. |
| [`boxed mcp`](#boxed-mcp) | Run the stdio MCP server with masked read and search. |
| [`boxed serve`](#boxed-serve) | Run the core for the desktop program: framed JSON on stdin and stdout, until stdin closes. |
| [`boxed install`](#boxed-install) | Add boxed to Claude Code (plugin), Codex (MCP server) or the browser (native host). |
| [`boxed native-host`](#boxed-native-host) | The browser starts this: serve the side panel on stdin and stdout. |
| [`boxed run`](#boxed-run) | Start Claude Code or Codex in the current workspace under the macOS sandbox. |
| [`boxed skills`](#boxed-skills) | Check the skills, plugins, MCP servers and hooks of your AI agents for malicious behaviour. |
| [`boxed skills scan`](#boxed-skills-scan) | Check what is installed, or a folder, file, zip or git address before you install it. |
| [`boxed skills list`](#boxed-skills-list) | Show what is installed with its last verdict, and what is in quarantine. |
| [`boxed skills quarantine`](#boxed-skills-quarantine) | Take an installed item out of use so the agent no longer loads it; restore puts it back. |
| [`boxed skills restore`](#boxed-skills-restore) | Put a quarantined item back exactly as it was. |

## boxed

Mask secrets and personal data before they reach AI models.

```text
usage: boxed [-h] [--version]
             {mask,restore,ask,key,check,journal,mask-file,restore-file,dashboard,audit,workspace,policy,plan,hook,mcp,serve,install,native-host,run,skills} ...
```

Options:

- `--version` - show program's version number and exit

## boxed mask

Mask a file or stdin, print the masked text.

```text
usage: boxed mask [-h] [--level {0,1,2,3,4}] [--scope SCOPE] [file]
```

Arguments:

- `file` (optional; default `-`)

Options:

- `--level LEVEL` (one of `0`, `1`, `2`, `3`, `4`)
- `--scope SCOPE`

## boxed restore

Put the originals back into a model answer.

```text
usage: boxed restore [-h] --scope SCOPE [--force] [file]
```

Arguments:

- `file` (optional; default `-`)

Options:

- `--scope SCOPE` (required)
- `--force` - print the text even if some markers look wrong

## boxed ask

Send a masked prompt through your API key and print the restored answer.

```text
usage: boxed ask [-h] --provider {openai,anthropic,deepseek,openrouter}
                 --model MODEL
                 [--account {personal-training,personal-private,corporate,api-zero-retention}]
                 [--scope SCOPE] [--level {0,1,2,3,4}]
                 [--category {finance,strategy,hr,health}]
                 [file]
```

Arguments:

- `file` (optional; default `-`)

Options:

- `--provider PROVIDER` (required; one of `openai`, `anthropic`, `deepseek`, `openrouter`)
- `--model MODEL` (required)
- `--account ACCOUNT` (one of `personal-training`, `personal-private`, `corporate`, `api-zero-retention`) - the kind of account the key belongs to
- `--scope SCOPE`
- `--level LEVEL` (one of `0`, `1`, `2`, `3`, `4`)
- `--category CATEGORY` (one of `finance`, `strategy`, `hr`, `health`) - the text holds this kind of data (repeatable)

## boxed key

Store, remove or check the API key of a provider (kept in the OS keychain).

```text
usage: boxed key [-h] {set,remove,status} {openai,anthropic,deepseek,openrouter}
```

Arguments:

- `action` (one of `set`, `remove`, `status`)
- `provider` (one of `openai`, `anthropic`, `deepseek`, `openrouter`)

## boxed check

What you know about training on chats, per account: list, set, remove, reset.

```text
usage: boxed check [-h] {list,set,remove,reset} ...
```

### boxed check list

Show the checks; exit code 5 when one is due.

```text
usage: boxed check list [-h]
```

### boxed check set

Write down what the data controls of an account say.

```text
usage: boxed check set [-h] --provider {chatgpt,claude,gemini,deepseek,zai}
                       --account ACCOUNT --training {on,off,unknown}
                       --memory {on,off,unknown}
```

Options:

- `--provider PROVIDER` (required; one of `chatgpt`, `claude`, `gemini`, `deepseek`, `zai`)
- `--account ACCOUNT` (required)
- `--training TRAINING` (required; one of `on`, `off`, `unknown`) - is training on your chats on, off or unknown
- `--memory MEMORY` (required; one of `on`, `off`, `unknown`) - is the chat's memory on, off or unknown

### boxed check remove

Delete the check of one account.

```text
usage: boxed check remove [-h] --provider {chatgpt,claude,gemini,deepseek,zai}
                          --account ACCOUNT
```

Options:

- `--provider PROVIDER` (required; one of `chatgpt`, `claude`, `gemini`, `deepseek`, `zai`)
- `--account ACCOUNT` (required)

### boxed check reset

Move a damaged checks.json aside (it is kept, not deleted).

```text
usage: boxed check reset [-h]
```

## boxed journal

Verify, show or export the signed journal; print the device key.

```text
usage: boxed journal [-h] [--last LAST] [--out OUT] [--since SINCE]
                     [--until UNTIL] [--replace]
                     {verify,show,export,key,check-export} [file]
```

Arguments:

- `action` (one of `verify`, `show`, `export`, `key`, `check-export`)
- `file` (optional) - check-export: the export file to check

Options:

- `--last LAST` (whole number; default `20`)
- `--out OUT` - export: where to write the export
- `--since SINCE` - export: first day, YYYY-MM-DD (UTC)
- `--until UNTIL` - export: last day, YYYY-MM-DD (UTC)
- `--replace` - export: replace a file that is not an earlier export

## boxed mask-file

Write a masked clean copy of a CSV, XLSX, DOCX or PDF (PDF to .txt).

```text
usage: boxed mask-file [-h] [--level {0,1,2,3,4}] [--scope SCOPE] [--replace]
                       [--delimiter {comma,semicolon,tab,pipe}]
                       src dest
```

Arguments:

- `src`
- `dest`

Options:

- `--level LEVEL` (one of `0`, `1`, `2`, `3`, `4`)
- `--scope SCOPE`
- `--replace` - replace a file that is already there
- `--delimiter DELIMITER` (one of `comma`, `semicolon`, `tab`, `pipe`) - the delimiter of a CSV file, when boxed cannot tell it for sure

## boxed restore-file

Put the originals back into a masked file a model returned.

```text
usage: boxed restore-file [-h] --scope SCOPE [--force] [--replace]
                          [--delimiter {comma,semicolon,tab,pipe}]
                          src dest
```

Arguments:

- `src`
- `dest`

Options:

- `--scope SCOPE` (required)
- `--force` - write the file even with unknown or suspicious markers
- `--replace` - replace a file that is already there
- `--delimiter DELIMITER` (one of `comma`, `semicolon`, `tab`, `pipe`) - the delimiter of a CSV file, when boxed cannot tell it for sure

## boxed dashboard

Write a self-contained HTML overview of the journal, and a CSV of its records.

```text
usage: boxed dashboard [-h] [--html HTML] [--csv CSV]
                       [--period {day,week,month}] [--since SINCE]
                       [--until UNTIL]
```

Options:

- `--html HTML` - the overview page
- `--csv CSV` - the records of the period, for a spreadsheet
- `--period PERIOD` (one of `day`, `week`, `month`) - the last day, 7 days or 30 days up to today (UTC)
- `--since SINCE` - first day, YYYY-MM-DD (UTC)
- `--until UNTIL` - last day, YYYY-MM-DD (UTC)

## boxed audit

Count secrets and personal data in the local session records and settings files of Claude Code and Codex.

```text
usage: boxed audit [-h] [--since SINCE] [--claude-dir CLAUDE_DIR]
                   [--codex-dir CODEX_DIR] [--html HTML] [--level {0,1,2,3,4}]
```

Options:

- `--since SINCE` - YYYY-MM-DD
- `--claude-dir CLAUDE_DIR` (default `~/.claude/projects`)
- `--codex-dir CODEX_DIR` (default `~/.codex/sessions`)
- `--html HTML` - also write a self-contained HTML report here
- `--level LEVEL` (one of `0`, `1`, `2`, `3`, `4`; default `2`)

## boxed workspace

Masked project mirror for AI agents: create, sync back, list, drop.

```text
usage: boxed workspace [-h] [--level {0,1,2,3,4}] [--force] [--only PATH]
                       [--diff] [--delete] [--dry-run]
                       {create,sync,list,drop} [target]
```

Arguments:

- `action` (one of `create`, `sync`, `list`, `drop`)
- `target` (optional) - project path for create, workspace id for sync and drop

Options:

- `--level LEVEL` (one of `0`, `1`, `2`, `3`, `4`)
- `--force` - sync files even with unknown or suspicious markers; with --only, just those files
- `--only PATH` - sync only this mirror path (repeatable)
- `--diff` - print a unified diff of every change sync makes or would make
- `--delete` - delete originals of files deleted in the mirror
- `--dry-run` - sync only: print what would change, change nothing

## boxed policy

Check what the company policy allows for a text and a recipient.

```text
usage: boxed policy [-h] --recipient RECIPIENT
                    [--category {finance,strategy,hr,health}]
                    {check} [file]
```

Arguments:

- `action` (one of `check`)
- `file` (optional; default `-`)

Options:

- `--recipient RECIPIENT` (required) - provider:kind:jurisdiction, for example openai:personal-private:US
- `--category CATEGORY` (one of `finance`, `strategy`, `hr`, `health`) - the text holds this kind of data (repeatable)

## boxed plan

Level 4: send only the task and the table schema, run the returned plan locally.

```text
usage: boxed plan [-h] {prompt,run} ...
```

### boxed plan prompt

Print the prompt: masked task, column names and types, made-up rows.

```text
usage: boxed plan prompt [-h] --task TASK [--scope SCOPE] [--decimal {auto,.,,}]
                         [--header-ok]
                         table
```

Arguments:

- `table`

Options:

- `--task TASK` (required)
- `--scope SCOPE`
- `--decimal DECIMAL` (one of `auto`, `.`, `,`; default `auto`)
- `--header-ok` - the first row is a header even though it looks like data

### boxed plan run

Run the model's plan locally on the real table.

```text
usage: boxed plan run [-h] --scope SCOPE [--decimal {auto,.,,}] [--out OUT]
                      [--replace] [--chart CHART]
                      plan table
```

Arguments:

- `plan`
- `table`

Options:

- `--scope SCOPE` (required)
- `--decimal DECIMAL` (one of `auto`, `.`, `,`; default `auto`)
- `--out OUT` - write the result table here instead of stdout
- `--replace` - replace a --out file that is already there, or a --chart file that is not a chart
- `--chart CHART` - write the chart spec (JSON) here

## boxed hook

Claude Code hook entry point, reads the hook JSON from stdin.

```text
usage: boxed hook [-h]
                  {pre-tool-use,user-prompt-submit,session-start,skills-check}
```

Arguments:

- `event` (one of `pre-tool-use`, `user-prompt-submit`, `session-start`, `skills-check`)

## boxed mcp

Run the stdio MCP server with masked read and search.

```text
usage: boxed mcp [-h]
```

## boxed serve

Run the core for the desktop program: framed JSON on stdin and stdout, until stdin closes.

```text
usage: boxed serve [-h]
```

## boxed install

Add boxed to Claude Code (plugin), Codex (MCP server) or the browser (native host).

```text
usage: boxed install [-h] [--extension-id EXTENSION_ID] [--remove] [--dry-run]
                     {claude,codex,native-host}
```

Arguments:

- `target` (one of `claude`, `codex`, `native-host`)

Options:

- `--extension-id EXTENSION_ID` - native-host: the id Chrome or Edge shows for the unpacked extension
- `--remove` - native-host: take the registration and its files away
- `--dry-run`

## boxed native-host

The browser starts this: serve the side panel on stdin and stdout.

```text
usage: boxed native-host [-h]
```

## boxed run

Start Claude Code or Codex in the current workspace under the macOS sandbox.

```text
usage: boxed run [-h] [--keep-env NAME] {claude,codex} ...
```

Arguments:

- `agent` (one of `claude`, `codex`)
- `args` (optional; the rest of the command line) - arguments for the agent, after --

Options:

- `--keep-env NAME` - pass this variable to the agent although it looks like a credential (repeatable); credentials are kept out by default

## boxed skills

Check the skills, plugins, MCP servers and hooks of your AI agents for malicious behaviour.

```text
usage: boxed skills [-h] {scan,list,quarantine,restore} ...
```

### boxed skills scan

Check what is installed, or a folder, file, zip or git address before you install it.

```text
usage: boxed skills scan [-h] [--html HTML] [--json JSON] [--replace] [--ai]
                         [--provider {openai,anthropic,deepseek,openrouter}]
                         [--model MODEL]
                         [--account {personal-training,personal-private,corporate,api-zero-retention}]
                         [target]
```

Arguments:

- `target` (optional) - a folder, a file, a .zip, an https git address or owner/repo (GitHub) to check before installing; leave out to check what is installed

Options:

- `--html HTML` - also write a self-contained HTML report here
- `--json JSON` - also write a JSON report (boxed-skills-report/1) here
- `--replace` - replace a report file that is already there and is not an earlier report
- `--ai` - also let a model look at the files with findings (masked, through your API key); it can only add findings
- `--provider PROVIDER` (one of `openai`, `anthropic`, `deepseek`, `openrouter`) - --ai: the provider whose key is used
- `--model MODEL` - --ai: the model to ask
- `--account ACCOUNT` (one of `personal-training`, `personal-private`, `corporate`, `api-zero-retention`) - --ai: the kind of account the key belongs to

### boxed skills list

Show what is installed with its last verdict, and what is in quarantine.

```text
usage: boxed skills list [-h]
```

### boxed skills quarantine

Take an installed item out of use so the agent no longer loads it; restore puts it back.

```text
usage: boxed skills quarantine [-h] id
```

Arguments:

- `id` - the id or the name of an item, as boxed skills list shows it

### boxed skills restore

Put a quarantined item back exactly as it was.

```text
usage: boxed skills restore [-h] id
```

Arguments:

- `id` - the quarantine id, the item id or the name of the item
