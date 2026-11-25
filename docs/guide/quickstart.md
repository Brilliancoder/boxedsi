# Quickstart

Ten minutes. You mask a prompt, let Claude Code work in a masked copy of a project, make a clean copy of a table and send one prompt through your own API key.

You need boxed installed ([install.md](install.md)). To try everything on made-up data first, start a throwaway home in the terminal you use for this page with the block in "Try it without touching your own data" in [install.md](install.md#try-it-without-touching-your-own-data). This page makes its own files, so the lines marked `(clone)` there are not needed. A new `HOME` keeps boxed away from your real agent folders, and `insecure-file` keeps boxed's keys in plain files: only for made-up data.

All data below is made up, and each step gives the commands that create its files. Ids and times come from a test run and differ on your computer. boxed prints full paths; this guide shortens your home folder to `~`.

## 1. Mask and restore a prompt

Create `prompt.txt`:

```bash
cat > prompt.txt <<'EOF'
Draft a reply to anna.petrova@example.com about invoice 4471.
Our staging host db1.acme.internal (10.20.30.40) was down on Tuesday.
The log shows the key sk-example-0123456789abcdefghij.
EOF
```

Mask it. A scope is a name for one set of placeholders: the same scope gives the same value the same placeholder.

```text
$ boxed mask --scope my-task prompt.txt
Draft a reply to [EMAIL_1] about invoice 4471.
Our staging host [HOST_1] ([IP_1]) was down on Tuesday.
The log shows the key [SECRET_1].
scope: my-task
```

The masked text goes to standard output and `scope:` to standard error, so `pbpaste | boxed mask --scope my-task | pbcopy` masks what you copied and leaves it on the clipboard. Paste it into any AI chat and press send yourself.

The invoice number stays visible: level 2, the default, does not mask plain numbers. Level 3 does (see [concepts.md](concepts.md)). A person's name would stay visible too, because finding names needs a name model (see [install.md](install.md)).

Save the model's answer as `answer.txt`. To follow along without a chat, use this one:

```bash
cat > answer.txt <<'EOF'
Subject: Invoice 4471

Dear [EMAIL_1],

The delay came from [HOST_1], which was down on Tuesday. We have rotated [SECRET_1] and will resend the invoice today.

Best regards
EOF
```

Put the originals back:

```text
$ boxed restore --scope my-task answer.txt
Subject: Invoice 4471

Dear anna.petrova@example.com,

The delay came from db1.acme.internal, which was down on Tuesday. We have rotated sk-example-0123456789abcdefghij and will resend the invoice today.

Best regards
```

Restore never guesses. If the answer holds a placeholder that is not in the scope, such as `[EMAIL_9]`, boxed prints `not restored, check by hand: [EMAIL_9]`, prints no text and exits with code 3. Add `--force` after you have looked.

## 2. A masked workspace for Claude Code

The project folder holds a config file with a password, a log with customer e-mail addresses and some code. Create it:

```bash
mkdir -p ~/work/project
cat > ~/work/project/config.env <<'EOF'
DB_HOST=db1.acme.internal
DB_PASSWORD=Plum-Harbor-7x2q-Lantern
API_KEY=sk-example-9f8e7d6c5b4a3210zyxwvuts
EOF
cat > ~/work/project/app.log <<'EOF'
2026-10-20 09:14 invoice 4471 sent to anna.petrova@example.com
2026-10-20 09:15 invoice 4472 sent to j.miller@example.org
2026-10-21 11:02 payment reminder bounced for li.wei@example.net
EOF
cat > ~/work/project/app.py <<'EOF'
"""Invoices of the staging service."""

import csv


def load(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def total(rows):
    return sum(float(r["amount"]) for r in rows)
EOF
```

Create the masked copy:

```text
$ boxed workspace create ~/work/project
workspace 34a67d02 created: 3 files masked, 0 skipped, level 2
mirror: ~/.boxed/workspaces/ws-34a67d02
```

The copy holds placeholders where the original holds data:

```text
$ cat ~/.boxed/workspaces/ws-34a67d02/config.env
DB_HOST=[HOST_1]
DB_PASSWORD=[SECRET_1]
API_KEY=[SECRET_2]
```

Open Claude Code in the copy, not in the project (Claude Code 2.1.295 or later):

```text
$ cd ~/.boxed/workspaces/ws-34a67d02
$ claude
```

Claude Code reads and edits the copy. The copy carries rules and hooks that block access to your original project and to boxed's data. Hooks are best effort. On macOS, `boxed run claude` starts Claude Code under a sandbox that blocks the original folder at the operating system level. The hooks keep working inside that sandbox; the MCP tools `read_masked` and `search_masked` do not work there yet (see [claude-code-and-codex.md](claude-code-and-codex.md#boxed-run-and-the-sandbox)).

No Claude Code at hand, or in a throwaway home, where Claude Code is not signed in? Make the edit it would make in `app.py` of the copy yourself (use your own id):

```bash
cd ~/.boxed/workspaces/ws-34a67d02
python3 - <<'EOF'
from pathlib import Path
p = Path("app.py")
p.write_text(p.read_text().replace("open(path)", 'open(path, newline="")').replace('r["amount"])', 'r["amount"] or 0)'))
EOF
cd ~
```

When Claude Code has edited the copy, review the changes from your own terminal. boxed puts the original values back before it shows them:

```text
$ boxed workspace sync 34a67d02 --dry-run --diff
would write app.py
--- a/app.py
+++ b/app.py
@@ -4,9 +4,9 @@
 
 
 def load(path):
-    with open(path) as f:
+    with open(path, newline="") as f:
         return list(csv.DictReader(f))
 
 
 def total(rows):
-    return sum(float(r["amount"]) for r in rows)
+    return sum(float(r["amount"] or 0) for r in rows)
```

Then write the changes into the real project:

```text
$ boxed workspace sync 34a67d02
write app.py
```

Do not ask the agent to run `boxed` commands. In a plain Claude Code session, the hooks block them on purpose. More in [claude-code-and-codex.md](claude-code-and-codex.md).

## 3. A clean copy of a table

Create a small client list as CSV:

```bash
cat > clients.csv <<'EOF'
client,email,phone,deal
Anna Petrova,anna.petrova@example.com,+44 20 7946 0958,12500
John Miller,j.miller@example.org,+1 415 555 0142,8300
Li Wei,li.wei@example.net,+49 30 901820,4100
EOF
```

```text
$ boxed mask-file --scope deal-7 clients.csv clients.masked.csv
csv: clients.csv -> clients.masked.csv
checked: 4 rows, 4 columns
markers: EMAIL 3, PHONE 3
complete: yes
scope: deal-7
```

The clean copy holds `[EMAIL_1]` and `[PHONE_1]` where the original holds the address and the number. The names stay: finding them needs a name model (step 1). boxed does not send or patch `clients.csv`. It builds a new file from what it checked. `complete: yes` means nothing that could hold data was left out. When it says `complete: no`, the line `left out:` names what was dropped, and you should look before you send. When the model returns a file, `boxed restore-file --scope deal-7 answer.csv answer.restored.csv` puts the originals back. XLSX and DOCX work the same way with the `formats` extra; CSV needs no extra. A PDF is not rebuilt: boxed masks its text layer into a `.txt` file, and you restore that text file. Images and scanned pages in it are not part of that text: handle them separately. Details in [files.md](files.md).

## 4. One request through your API key

Store your key once. It goes to the OS keychain and is never printed:

```text
$ boxed key set openai
API key for openai (input hidden):
key for openai stored in the keychain
```

In a throwaway home, skip `boxed key set`: it always uses the system keychain, whatever `BOXED_KEYSTORE` says, and may refuse there with `openai: cannot store the key in the keychain`. Put the key in the provider's variable for this terminal instead. `read -rs` keeps it off the screen and out of your shell history: paste the key and press Enter.

```text
$ read -rs OPENAI_API_KEY && export OPENAI_API_KEY
$ boxed key status openai
set (environment)
```

A new `HOME` does not hide the system keychain, and a key stored there earlier with `boxed key set` comes before the variable. Go on only if `boxed key status openai` says `set (environment)`; `set (keychain)` means the next step would use that stored key and its account.

Then send the prompt from step 1. This step contacts the provider and uses your key and your quota:

```text
$ boxed ask --provider openai --model gpt-5 prompt.txt
scope: ask-20261024T101818
warning: personal data leaves the EEA: this needs a legal basis, masking does not replace it
Subject: Invoice 4471

Dear anna.petrova@example.com,

Thank you for your message. The delay came from db1.acme.internal, which was down on Tuesday. The invoice will be resent today.

Best regards
```

The reply above comes from a small local server that stands in for the provider, so no real model was called. A real model answers differently. Because the test server is reached through `BOXED_OPENAI_BASE_URL`, boxed also printed `boxed: sending through the relay at 127.0.0.1:18701 (BOXED_OPENAI_BASE_URL)`. With the real provider you do not see that line.

boxed checked the policy, masked the prompt, wrote a journal record and only then sent the masked text. The provider received `[EMAIL_1]`, `[HOST_1]`, `[IP_1]` and `[SECRET_1]`, never the originals. The answer was restored on your computer. The warning is not an error: the provider is in the US, and the prompt held an e-mail address. See [api.md](api.md).

## 5. Check the journal

Masking, restoring, creating and syncing the workspace, the table and the request each left records. The journal is a signed hash chain, and `verify` checks it:

```text
$ boxed journal verify
ok: 7 records verified; ok
```

## What boxed does not do

- It hides direct identifiers. A model can still guess who or what a text is about from the details that remain.
- It masks only what goes through it. Text you type or paste into a chat page yourself is not checked.
- The journal proves what boxed recorded. It does not prove that nothing was sent around boxed.

## Next

- [concepts.md](concepts.md): levels, placeholders, scopes, the vault and the journal.
- [claude-code-and-codex.md](claude-code-and-codex.md): the masked workspace, hooks, MCP tools and the sandbox.
- [browser-extension.md](browser-extension.md): the same masking in a browser side panel.
- [files.md](files.md), [api.md](api.md) and [tables.md](tables.md): files, API keys and tables.
- [skills.md](skills.md): check the skills, plugins and MCP servers of your agents for malicious behaviour.
- [policy.md](policy.md) and [configuration.md](configuration.md): company rules and `boxed.toml`.
- [troubleshooting.md](troubleshooting.md): exit codes and error texts.
- [cli.md](cli.md): every command with its arguments and flags.
