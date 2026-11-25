# Dashboard and journal

The journal is the signed record of what boxed did. The dashboard is a report built from it. This page covers the commands to read, check, report and export the journal, and `boxed audit`, which counts what earlier agent sessions saved in local session records (possible exposure to the provider). For what a record holds, see [journal-records.md](../security/journal-records.md); for the ideas behind it, [concepts.md](concepts.md).

The examples that call a provider ran against a test server on the same computer, not against a real provider. Timestamps, hashes and keys differ on your computer.

## Read the journal

`boxed journal show` prints the last records, oldest first, one JSON object per line. `--last N` sets how many (the default is 20).

```bash
boxed journal show --last 1
```

```text
{"channel": "api", "provider": "openai", "account_type": "personal-private", "level": 3, "markers_by_kind": {}, "status": "error", "payload_sha256": "ad4bea15...", "coverage": "full", "scope": "deal-7", "versions": {"boxed": "0.1.0"}, "note": "openai: HTTP 401 (invalid_api_key)", "model": "gpt-5", "seq": 6, "ts": "2026-10-24T10:24:38.911014+00:00", "prev_hash": "b3998138...", "hash": "b4b9100b...", "sig": "b37a59a5..."}
```

This record says: the API call for the scope `deal-7` failed with HTTP 401. The record before it (`status: sent`) has the same `payload_sha256`: the hash of the masked prompt that boxed sent. A call to `boxed ask` leaves `sent` and then `received`; a failed call leaves `sent` and then `error`; a call the policy stopped leaves one `blocked` record. Masking by hand leaves `prepared`, and a restore leaves `received` with level `-1`. `boxed skills scan`, `quarantine` and `restore` leave a `prepared` record in the channel `skills`, with counts and a hash and no name.

boxed skips a line it cannot read (a write torn by a crash) and says so on stderr: `1 damaged line skipped, run boxed journal verify`.

## Check the journal

```bash
boxed journal verify
```

```text
ok: 6 records verified; ok
```

`verify` recomputes every hash, checks every signature with the device key, and follows the chain from the first record. The exit code is 0 when everything holds and 1 when it does not. A problem names the first record that fails:

| Output | What happened |
|---|---|
| `BROKEN: 4 records verified; record 5: hash does not match content` | A field of record 5 was changed after it was written |
| `BROKEN: 4 records verified; record 6: chain break` | A record was removed, added or moved: record 6 does not follow the one before it |
| `BROKEN: 0 records verified; record 1: bad signature` | The record was not signed with this device's key. The key was replaced or lost, or the record was forged |
| `BROKEN: 47 records verified; line 48 is not a journal record (1 damaged); the 47 whole records verify` | A line is damaged, for example a write torn by a crash. The chain of whole records around it still holds |

What `verify` cannot see: records removed from the end, and records written by someone who can use your keychain entry. Compare the record count with an earlier export when this matters. The journal proves what was recorded; it does not prove that nothing was sent around boxed.

## The device key

boxed signs `journal.jsonl` with an Ed25519 key that it creates on first use and keeps in the OS keychain (`device-signing-key`). `boxed journal key` prints the public half as 64 hexadecimal characters:

```bash
boxed journal key
```

```text
8a7380cb61a8b596445d980ad6bf1b4dc007af0c70ddb4ceed6884c50eb37f32
```

Give this key to the security team once and keep it on record outside the computer. An export carries the key too, but a key that travels with the data proves nothing by itself: the reader must compare it with the copy on record.

## The dashboard

```bash
boxed dashboard --html journal.html --csv journal.csv --period week
```

```text
dashboard: journal.html
csv: journal.csv
```

`--html FILE` writes the overview page and `--csv FILE` writes the records. Give one or both. The period:

- `--period day`, `week` or `month` covers the last 1, 7 or 30 days up to today, today included, in UTC.
- `--since YYYY-MM-DD` and `--until YYYY-MM-DD` set the first and the last day, both included, in UTC. Either can stand alone.
- Without a period, every record counts. `--period` together with `--since` or `--until` is an error.

### The page

The page is one file. It has no scripts, loads nothing from outside, never links anywhere and follows the light or dark setting of the browser. It shows counts, kinds and names, never values. Its sections, in order:

1. The period and the verdict on the whole journal (`Chain OK: 6 records verified (the whole journal, not only this period)` or `Chain BROKEN`, with the reason). If the chain is broken, the page says so: the numbers then come from a journal that failed verification.
2. Overview: cards for records, sent, blocked and markers, then counts by kind, channel, provider, account type, model, tokens, level and status, and a table by day. Tokens are the numbers the provider reported. A box "Spend reported by the provider" appears when some record reports a cost (OpenRouter does); it adds only those records, so it is not your whole spend.
3. Journal: the newest 500 records of the period, newest first (left out when the period has no record).
4. Sent without boxed: what the browser panel saw you send to a chat while observation mode was on, from `observed.jsonl`, with the verdict on its own chain. It lists kinds and counts. If a key or token was in a message it says to revoke and replace it. It shows how many sends it could not read, so the counts may be too low.
5. Training on chats: your checks, with the date of each and a `due` mark.
6. Policy: the matrix of categories and recipients of the `boxed.toml` in the folder where you run the command.

The first lines of the page, condensed to text:

```text
boxed.si journal
Period: 2026-10-18 to 2026-10-24. Counts, kinds and names only, never the values.
Chain OK: 6 records verified (the whole journal, not only this period).
Overview
Records 6   Sent 2   Blocked 0   Markers 13
Markers by kind: EMAIL 5, HOST 3, SECRET 3, MONEY 2
By channel: api 4, manual 2
By status: prepared 2, sent 2, error 1, received 1
...
```

### The CSV

The CSV has one row per record of the period, in journal order. It is UTF-8 with a byte order mark, so Excel reads it correctly, and rows end with CRLF. A cell that would start a formula (`=`, `+`, `-`, `@`, a tab or a carriage return) gets a leading quote. boxed cuts every text to 64 characters. The CSV leaves out the chain fields (`prev_hash`, `hash`, `sig`), because a spreadsheet cannot verify them. The level of a restore is `n/a`.

```text
seq,ts,channel,provider,model,account_type,level,markers_by_kind,tokens_in,tokens_out,cost_micro_usd,status,coverage,scope,versions,payload_sha256,note
2,2026-10-24T10:24:38.667386+00:00,api,openai,gpt-5,personal-private,3,EMAIL:1 HOST:1 MONEY:1 SECRET:1,,,,sent,full,deal-7,boxed:0.1.0,ad4bea15...,relay
3,2026-10-24T10:24:38.677212+00:00,api,openai,gpt-5,personal-private,n/a,,41,17,,received,full,deal-7,boxed:0.1.0,1c436974...,restored=4 unknown=0 suspicious=0
```

(Two rows of six, hashes shortened.) `cost_micro_usd` is the cost a provider reported, in millionths of a US dollar.

### Where the files may go

The dashboard writes a new file, or replaces a report of its own. It checks the first bytes of an existing file and refuses anything that is not a boxed report:

```text
boxed: error: the output file exists and boxed did not write it: name another file, or delete it first
```

It also refuses the same file for `--html` and `--csv`, a link, and any place in the boxed home except below `reports/` (the journal and the vault live there):

```text
boxed: error: a report is not written in the boxed home, where the journal, the vault and the keys are, except under reports/
```

boxed creates a folder that does not exist. It writes through a part file and sets mode 600.

## Export the journal for the security team

An export is the journal, signed record by record, in one file that someone else can check.

```bash
boxed journal export --out journal-oct.json --since 2026-10-01
```

```text
6 records exported to journal-oct.json; device key 8a7380cb61a8b596445d980ad6bf1b4dc007af0c70ddb4ceed6884c50eb37f32
```

`--since` and `--until` take UTC days, both included. The export runs from the first to the last record of that period, so a clock that stepped back does not leave a hole. It holds the records exactly as stored, including the scope names, the payload hashes and the notes. It also holds the device public key and a `verify` field with the verdict of your computer at the time. That field is an unsigned claim: the check below never reads it.

boxed replaces an export of its own without asking. It stops at any other existing file; `--replace` replaces that file anyway. It refuses to write into the boxed home.

The security team checks the file without any boxed keys:

```bash
boxed journal check-export journal-oct.json
```

```text
ok: 6 records verified; ok
```

`check-export` recomputes each hash, verifies each signature against the public key in the file, and follows the chain from the first record's own `prev_hash`, so a slice of the journal verifies. Only a first record numbered 1 must start from the zero hash. A changed field breaks it:

```text
BROKEN: 1 records verified; record 2: hash does not match content
```

The exit code is 0 for `ok` and 1 for `BROKEN`. A file that is not a boxed export is `BROKEN: 0 records verified; not a boxed journal export`, and a missing or unreadable file is an error with exit code 2.

Limits of a check:

- The check cannot notice records cut off at either end of a slice.
- The key in the file proves nothing by itself. Compare it with the one you hold on record (`boxed journal key`).
- Observation records are not in the export. They stay on the employee's computer unless the employee hands them over.

A routine that works: the employee runs `boxed journal key` once and sends the key to the security team. At each period the employee runs `boxed journal export --out journal.json` and sends the file. The reviewer compares the `public_key` field in `journal.json` with the device key received separately, then runs `boxed journal check-export journal.json`. The employee keeps the exports, so the security team can compare the record count of a later export with an earlier one. The rest of the package for the security team (data flows, threat model, DPIA template, policy clause) is in [docs/security](../security/README.md).

## What already went out: boxed audit

`boxed audit` finds potential secrets and personal data in saved Claude Code and Codex session records. It reads the transcripts on your computer (`~/.claude/projects` and `~/.codex/sessions`), including prompts and tool results, with the rules of level 2. A transcript finding indicates possible exposure to the provider: audit reads what was saved locally and does not check that a request reached the provider. It also reads the Claude Code settings files, where keys end up by accident (see below); it does not read the settings of Codex. A finding only in Claude Code settings shows that the value is stored on disk.

```bash
boxed audit --since 2026-11-13 --html audit.html
```

```text
boxed audit: 23 items checked, 1 Claude Code settings file, 0 malformed lines skipped
found: SECRET 9, EMAIL 1
  claude-settings: SECRET 1
  codex: SECRET 8, EMAIL 1
by role: tool_result 8, user_prompt 1
top projects:
  ~/work/acme-api: SECRET 6, EMAIL 1
  ~/work/infra: SECRET 2
  ~: SECRET 1
secrets: 9 unique (6 known key formats, 3 possible), 9 occurrences

known key formats (6)
A pattern or checksum match: boxed does not check that a value is real or still valid.
In a saved local record of a session: if real, rotate the credential or call the card issuer.
~/.codex/sessions/2026/11/13/rollout-2026-11-13T11-58-00-d688806d-1c12-4fb0-a6f4-80faa4abcc1c.jsonl
  :29  SECRET #ab3917996c1a x1
  :29  SECRET #490f20da4a68 x1
  :41  SECRET #b8d3706c11c0 x1
  :41  SECRET #e5041edc97ba x1
~/.codex/sessions/2026/11/15/rollout-2026-11-15T09-20-00-7e1da053-5cb0-47a2-aaf9-0c894107711d.jsonl
  :9   SECRET #e4877ab6400e x1
  :16  SECRET #ecdbf6576db1 x1

possible (3)
Review these: they look like secrets, but no rule of a known key format matched them.
~/.codex/sessions/2026/11/13/rollout-2026-11-13T11-58-00-d688806d-1c12-4fb0-a6f4-80faa4abcc1c.jsonl
  :41  SECRET #9a0924c02572 x1
  :41  SECRET #183bb8bee74e x1
~/.claude/settings.local.json
  :5  SECRET #91f194e56572 x1
report: audit.html
```

This is the command above on the made-up home folder of `scripts/demo/make_home.py` (plus a `~/.claude/settings.local.json` with an allowed `curl` command), on macOS. Its projects are folders in `~/work` on a local disk, so audit read everything it found and printed no "not checked" lines. A project on a network share or an automount folder (on macOS `/home` is one) would show there as `project folders: N not on a local disk`. When something was not checked, audit exits with code 3, and a report with no finding says `nothing found in what was read` instead of `found: nothing`: what was not read may hold secrets. The options:

- `--since YYYY-MM-DD` counts only items from that day on. boxed then leaves out items without a time. The settings files are read whatever the period: they hold what is on disk now. A project is named by any of its sessions, of any day, so its settings files are read even when its sessions are older than the period.
- `--level N` sets the level of the rules; the default is 2.
- `--claude-dir` and `--codex-dir` name other transcript folders (defaults `~/.claude/projects` and `~/.codex/sessions`).
- `--html FILE` also writes a self-contained report. The file rules are those of the dashboard.

### How sure a secret is

Secrets fall into two groups, known key formats first:

- **known key formats**: the value matches a credential pattern or a card checksum: the prefix of a provider (AWS, GitHub, Anthropic, OpenAI, Slack, Google, Stripe, Telegram bots), a private key block, a JWT, a card number with a valid checksum. boxed does not check validity with an issuer: a test value or a made-up key of the right shape lands here too (the demo's do). Confirm whether the value is real, then act by where it was found:
  - in a session record (a transcript): the saved text of a session may have reached the provider, so rotate an exposed credential, or contact the card issuer for a card number;
  - only in a settings file: it is on disk, which proves no send, and no match turned up in the session records this report checked (with `--since`, older sessions were not checked). Remove it from the file, then check where it was used (the history of the repository, other files, the logs of the provider).
- **possible**: a guess from what stands around the value or from its look: a value after a name such as `password=` or `DB_PASSWORD:`, a header after `Bearer`, the user and password in an address, a random-looking token. Review each one; some are test values or placeholders.

One value is one secret, whatever rule found it: a JWT that the rule of `Bearer` headers took is listed once, as `JWT`, with the occurrences of both. The terminal lists each secret under the file it was first seen in, with its line, kind, hash and number of occurrences, so a line fits a terminal of 100 columns. The HTML report has one table per group with the source and project too. `by role` counts the findings in transcripts by what the text was: `user_prompt`, `tool_result`, `attachment` or `instructions` (see below).

### What audit reads in a transcript

- Claude Code (`*.jsonl` under `--claude-dir`): records of type `user` (a prompt, its text parts, tool results) and of type `attachment` (their rendered content). Not read: `assistant` records (the model's own answers, tool calls and thinking), `system` and `summary` records, images. What Claude Code sends without writing it to the transcript, its system prompt for one, is not checked either.
- Codex (`*.jsonl` under `--codex-dir`): `response_item` records with a message of the user (`user_prompt`) or of the developer (`instructions`: what Codex adds to the context in that role, such as the sandbox permissions and project instructions), and the output of tool calls (`function_call_output`, `custom_tool_call_output`, as `tool_result`). Not read: messages of the assistant, reasoning, the calls themselves, `event_msg` and `compacted` records.
- Every record that names a folder (`cwd` in Claude Code, `session_meta` and `turn_context` in Codex) names a project, whatever its type and day. In Codex the folder of the latest `session_meta` or `turn_context` is the project of the records after it. A Claude Code record without a `cwd` takes the name of its transcript folder, shown cleaned like any path (see below).

A line that is no JSON object, or whose fields have the wrong type at any depth (a `message` that is no object, a `cwd` or a `text` part that is no text), counts as malformed and is skipped; the next line is read.

audit opens a transcript only when it is a plain file on a local disk, checked the way project folders are (see below): a named pipe, a link that leads to a network share and a folder on a network or automount file system are not read. A folder that cannot be listed, and a transcript that cannot be opened or is not known to be local, are counted under "not checked".

### Claude Code settings files

When you allow a command once "for this project", Claude Code writes the whole command into the `permissions.allow` list of a settings file, a key in a `curl -H "Authorization: Bearer ..."` header included. `audit` reads, and never changes, these files:

- `~/.claude/settings.json` and `~/.claude/settings.local.json` (the folder above `--claude-dir` when that one is named `projects`, as the default is);
- `.claude/settings.json` and `.claude/settings.local.json` of every project folder the transcripts name (the folder each Claude Code or Codex session ran in).

A missing file is skipped without a word. A file that is there, or that cannot be told missing because a folder on the way is closed, is a gap, and the report lists it under "not checked (the report is incomplete)" in the terminal and in the HTML report, by why: too big (over 4 MB), not JSON (or no JSON object), no access (or no plain file), not on a local disk, disk type not known. The settings of the user and of the projects are opened by the same rules as transcripts.

A project folder comes from a transcript, so audit treats it as untrusted. It looks only at a folder on a local disk: not at a UNC or device path (`\\server\share`, `\\?\`, `//server/share`), not at a network drive on Windows, not at a folder on a network or automount file system (NFS, SMB, AFP, WebDAV, sshfs, autofs and the like, from the system's own list of mounts), and not past a link that leads to one. Each part of the path is looked at only once the part before it is known to be local, so audit never makes the system connect to another computer. On macOS a mount point matches whatever the case and Unicode form of the path, as the disk compares names. Such a project counts under "not checked" as `project folders: N not on a local disk`. What cannot be told is not taken as local: when the list of mounts cannot be read or parsed, or (on Linux) a file system is of a type audit does not know as local, the folders, transcripts and settings files on it count as `disk type not known` and are not read. The report then adds `disk type not known: nothing on it was read; report the type at github.com/boxedsi/boxedsi/issues`; on Linux `findmnt -no FSTYPE -T ~` shows the type of the home folder. Known as local: ext2/3/4, xfs, btrfs, zfs, f2fs, bcachefs, jfs, reiserfs, nilfs2, tmpfs, ramfs, overlay, squashfs, erofs, vfat, exfat, ntfs, ntfs3, hfsplus, apfs, ecryptfs, gocryptfs, encfs, virtiofs and the system's own (proc, sysfs and the like). `fuseblk`, `fuse` without a subtype and the Windows drives of WSL stay not known.

Every string value in a file goes through the same rules (the value of a key is read with the key in front, so `"DB_PASSWORD": "..."` counts, whatever spaces and line breaks stand between them). The findings appear as the source `claude-settings`, with the file and line. A settings file of a project can go into git with the project: when a secret is found in one, the report says so, and you should check the history of the repository. `boxed skills scan` flags the same permission rules as `inline-secret`.

### What the report holds

The report holds counts, hashes and places, never the values. A secret appears as its kind and the first 12 characters of a keyed hash (`#36684f5fb306`), so the same key groups into one line, and nobody can test a guess against the report. The key for that hash is in your keychain (`audit-mac-key`), so the hashes differ between computers. Without a keychain, or with a stored key that cannot be used, audit says which on stderr and takes one random key for the run: the hashes still group within the report (a key in a transcript and in a settings file is one secret), but they differ from the hashes of another run.

Paths are shown the same way in the terminal and in the HTML report, so that a screenshot can be shared:

- your home folder is `~` (on Windows whatever the slashes and the case of the path: `c:/users/jdoe` too);
- the transcript folder of a Claude Code project is named after the whole project path (`-Users-jdoe-work-shop`); the report shows it after the shown project path, so it starts with `~-` and carries no user name: `~/.claude/projects/~-work-shop/0b9e....jsonl`;
- a part of a path in which the rules of level 1 find a secret or personal data (an email address, a key, a phone number) is shown as its kind: a project in `/work/ivan.petrov@acme.example` appears as `/work/<EMAIL>`, its transcript folder as `-work-<EMAIL>`. Host names are left as they are: many project folders are named after a site;
- control characters (escape sequences, line breaks, tabs, marks that turn the direction of text) in a project or file name are written as escapes (`\x1b`), so a crafted name cannot change what the terminal shows;
- the name of a transcript folder that stands for a project (a record without `cwd`) goes through the same rules after the `~-`, with `-` also read as `_`, since Claude Code turns `_` into `-` there.

What finds the file stays: the project name, the session id in the file name and the line. When a part is shown as its kind, find the file by its session id: `find ~/.claude/projects -name '0b9e*.jsonl'`. The report still names project folders and transcript files, which can reveal client names: read it before you share it. There is no JSON output yet.

`audit` uses the rules only. It ignores `boxed.toml`: it uses no name model, no dictionary and no `internal_domains`, so it finds no people, companies or client terms. It writes nothing to the journal. It sees only the transcripts of those two tools and the settings files above; text you typed into a chat in the browser is not there (observation mode in the panel covers that, from the day you switch it on). A key found in a session record was in the text of a session with a model: rotate it.

## Exit codes

| Command | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| `journal show`, `journal key` | done | | error | |
| `journal verify` | `ok` | `BROKEN` | error | |
| `journal export` | exported | | error: no `--out`, a file in the way, a place in the boxed home | |
| `journal check-export` | `ok` | `BROKEN` | the file is missing or not JSON, or no file was given | |
| `dashboard` | written | | error: no `--html` or `--csv`, the same file twice, a bad date, a file in the way | |
| `audit` | done, everything found was checked | | error | done, but something was not checked (the report lists it under "not checked") |

The messages and what to do about them are in [troubleshooting.md](troubleshooting.md).
