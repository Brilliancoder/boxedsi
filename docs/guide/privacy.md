# Privacy

What leaves your computer, when and to whom. What boxed stores, where and for how long. What it never collects. The security team has the same facts as diagrams in [data-flows.md](../security/data-flows.md).

## What leaves the computer

There are no boxed servers in the data path. Nothing goes to boxed.si. The text that leaves your computer is the masked text you send through a channel, to the AI service you chose.

| Channel | What leaves | Where it goes | When |
|---|---|---|---|
| `boxed ask` | The masked prompt, the model name and your API key (as a request header), with a `User-Agent` of `boxed/<version>` and the headers the API needs | The provider you named, or the relay in `BOXED_<PROVIDER>_BASE_URL` | After the policy allows it and the `sent` record is written. One request per prompt, no streaming |
| Browser side panel | Masked text, put into the open AI tab by Insert, or copied by Copy | The AI site, when you press its send button. Insert never presses it | You decide, per message |
| Masked workspace | Whatever the agent reads in the mirror: masked files and the output of its tools | The provider the agent uses (for example Anthropic for Claude Code, OpenAI for Codex), under that tool's terms | While the agent works. boxed does not control the agent's network use |
| MCP tools (`read_masked`, `search_masked`) | Masked text, in the tool's answer | The agent, and so the agent's provider | When the agent calls the tool |
| `boxed skills scan --ai` | The masked text of the files that have findings of the rules (secrets, personal data and IP addresses replaced; host names and URLs stay readable), at most 100 KiB per request, the model name and your API key (as a request header). Never a file name, a path or a config entry, and never a config file of an agent (settings, MCP, hooks and Codex config files, `.claude.json`, the lists of installed plugins and skills, plugin manifests; names in any letter case): their `env`, headers and allowed commands stay on this computer, and the report counts such files as not sent | The provider you named, or the relay in `BOXED_<PROVIDER>_BASE_URL` | Only with `--ai`, after the policy allows it and the `sent` record is written. boxed prints first how many files go where |
| `boxed skills scan` of a git address or `owner/repo` | A clone request for the address you named. It carries none of your files | The git host in the address (GitHub for `owner/repo`) | Only when you scan such a target. The host sees what any web request shows |
| Text you type or paste into a chat page yourself | Everything you type | The AI site | Always, whatever boxed does. boxed cannot stop it |
| A report or an export | Counts, kinds, names and hashes | Wherever you send the file | Only when you share it |

Apart from the clone of an address you scan, the only other network traffic comes from a library, not from boxed: the first time you use the English name model (`ner = ["en"]`), GLiNER downloads the model files from the Hugging Face model hub, about 1 GB. The download carries no text. The Russian model is part of the Python package and needs no download. Installing boxed and its extras downloads packages from your package index; that is the installer, not boxed.

A provider also sees what any web request shows: your IP address and the time. A relay that you name receives the masked prompt and your key. An address on this computer is never sent through a proxy; a remote address follows `HTTPS_PROXY`.

What the provider keeps is its own business:

- OpenAI: boxed sends `store: false`, so OpenAI does not store the response for later retrieval. OpenAI may still keep abuse-monitoring logs for up to 30 days.
- OpenRouter: every request asks for providers that neither keep nor train on the data (`data_collection: deny`), and with `--account api-zero-retention` also for endpoints with zero data retention (`zdr: true`). These fields come from OpenRouter's public documentation. boxed has not tried them on a live call.
- Anthropic and DeepSeek: boxed sends no retention setting.
- Zero retention at OpenAI or Anthropic is an agreement on your account. boxed cannot request it per call.
- Training off in a chat does not mean that the provider stores nothing. Providers keep chats for a while.

## What boxed stores

Everything lives in the boxed home: `~/.boxed`, or the folder in `BOXED_HOME`. boxed creates the folder with mode 0700 and writes its own files there with mode 600; the table notes the exceptions. "Who can read what" below explains how boxed keeps an agent in a masked workspace away from these files.

| Item | Where | What it holds | Protection | How long |
|---|---|---|---|---|
| Placeholder maps | `vault.db` | Each replaced value with its placeholder, per scope | AES-256-GCM; the key is in the OS keychain. Scope names and change times are in clear text | Until you drop the workspace (`boxed workspace drop`) or delete the file. No expiry |
| Journal | `journal.jsonl` | One record per step: kinds, counts, hashes, scope names, notes. Never values | Hash chain and Ed25519 signatures | Until you delete it. boxed never rotates or trims it |
| Observation log | `observed.jsonl` | Site, time, kinds, counts, a keyed hash. Never the text | A chain of its own, signed with the same device key | Until you delete it |
| Training checks | `checks.json` | What you recorded per chat account | Signed with the device key | Until you remove the check. A damaged file is moved aside as `checks.json.damaged-<time>` and kept |
| Masked workspaces | `workspaces/ws-<id>/` | A masked copy of your project, and the files that guard it | The folder `workspaces/` has mode 0700; the copies keep the permissions of the originals | Until `boxed workspace drop` |
| Workspace state | `state/<id>.json`, `state/<id>.sb` | The path of the original, the level, the settings of `boxed.toml` at that time (your dictionary too), hashes of the files, the sandbox profile | Mode 600 | Until `boxed workspace drop` |
| Reports | `reports/` | Dashboard and audit pages you write there | Mode 600 | Until you delete them |
| Extension check record | `skills/record.json` | For each agent extension `boxed skills scan` checked: its id (agent, kind, scope and name, with the folder name of a project), its place, a SHA-256 digest of its content, the verdict, when and with which rules, and the rule, severity, file and line of each finding. The answers of `--ai` by file hash, provider and model: of each finding only the rule, severity, file and line, never the evidence or the model's reason. The entries of quarantined items. Never the evidence text, never a value from a config | Mode 600 inside a folder of mode 0700, read strictly, not signed. Closed to an agent in a masked workspace | Until you delete it. Every scan of what is installed rewrites it |
| Quarantine | `skills/quarantine/<id>/` | What `boxed skills quarantine` took out: the moved item (`payload`), or the entry cut out of a config in `entry.json` and the file as it was before the edit in `original`. They can hold values: the `env` and headers of an MCP server, the command of a hook | Folder 0700, `entry.json` and `original` mode 600 (a moved item keeps its own modes). Closed to an agent in a masked workspace | Until you restore the item or delete the folder. boxed never empties it |
| Native host launcher | `~/.boxed/bin/boxed-native-host` (always in `~/.boxed`) | A small script that starts the program for the browser | Mode 0700 | Until you delete it |
| Hook error log | `hook-errors.log` | One line per hook failure: the time, the hook and the error class, never the error's message | Mode 600 | It only grows |
| Host error log | `host-errors.log` | One line per browser-program failure: the time and the error class, never a message | Mode 600, at most 64 KiB, then it starts again | Last 64 KiB |
| Lock files | `*.lock` | Nothing | | |
| Plain key files | `insecure-keys/` | The keys, only with `BOXED_KEYSTORE=insecure-file` | Mode 600 | Until you delete the folder |

Outside the boxed home:

- The OS keychain holds the keys, under the service name `boxed.si`: `vault-key`, `device-signing-key`, `state-mac-key`, `audit-mac-key`, `observe-hmac`, and `api-key:<provider>` for each key you stored with `boxed key set`.
- `boxed install native-host` writes a manifest for Chrome and one for Edge (in `~/Library/Application Support/...`, macOS).
- `boxed install codex` adds a block to `~/.codex/config.toml` and keeps a `.bak` copy. `boxed install claude` registers the plugin through the `claude` command.
- `boxed skills quarantine` and `restore` edit the config file of the item (for example `~/.claude/settings.json`, `~/.codex/config.toml`, or the `.claude/settings.local.json` of a project) and, to take a Claude Code MCP server out of `~/.claude.json`, run `claude mcp remove` with the name of the server and nothing else. A restore writes that file itself, so no value of a config is ever put on a command line. They also move skill folders into the boxed home and back. They run only when you type them.
- The browser keeps the Observe switch (in the browser's local storage), the last 20 observation results (session storage, gone when the browser closes), and the name of the last scope you typed in the panel.

A report of `boxed skills scan` (`--html`, `--json`) is never written in the boxed home: you name a place outside it, and the file gets mode 600. It names your extensions and projects and holds evidence with secrets and personal data replaced, so read it before you share it. The placeholder map of an `--ai` request stays in `vault.db`, under the scope `skills-<time>`, like that of any other request.

boxed deletes nothing on its own, apart from the part files it makes while it writes and the host error log that starts again at 64 KiB. Retention rules for the journal and the vault are yours to set; the [policy clause](../security/policy-clause.md) has a place for them. To remove a workspace with its mirror, its state and its map, run `boxed workspace drop`. To remove everything, delete the boxed home and the keychain entries.

The browser program (the native host) keeps no text after it answers, by design. Python does not wipe memory it has freed, though: pieces of recent texts can stay in the program's memory until it ends, which is 60 seconds after your last click or when you close the panel. See [browser-extension.md](browser-extension.md).

## What boxed never collects

- No telemetry, analytics, crash reports, usage statistics, update checks or accounts. boxed does not contact boxed.si or any other server of ours.
- No content in logs. The journal and the observation log hold kinds, counts and hashes. An error names the provider, the HTTP status and a word from a fixed list, and never quotes your text, your key or the provider's message.
- boxed does not read your chats. The extension reads neither your chat history nor the answers on the page. The one exception is observation mode: it reads only the message you send, and only after you switch it on.
- boxed does not read the provider's settings page. The training checks hold what you typed.
- boxed scans nothing beyond what you give it. `boxed audit` reads the transcript folders of Claude Code and Codex; you can name other folders. `boxed skills scan` reads the folders where your agents load extensions (the list is in [skills.md](skills.md)) and the target you name, only when you run it. It runs none of it, and without `--ai` it sends none of it anywhere.

## Who can read what

- You, and any program that runs as your user, can read the files of the boxed home within their permissions. An agent with code execution, running as your user, could try to reach the keychain; macOS asks you before it hands out the vault key.
- An AI agent in a masked workspace is meant to see the mirror only. The Claude Code hooks block its reads of the original project and of the boxed data. They are best effort. Under `boxed run` the macOS sandbox denies the original project and the boxed files the agent has no use for. The encrypted vault, the journal and the state folder stay readable under the sandbox, because the MCP server and the hooks need them. The mirror holds `.claude/settings.local.json`, which names the original project path (not its content): use neutral folder names if the name itself is sensitive.
- The security team sees only what you hand over: a journal export, a dashboard, an audit report. An export holds scope names and payload hashes. A dashboard or audit report names folders and counts, never values.
- The AI service sees the masked text, and from masked text a model can sometimes still guess who or what it is about. See [concepts.md](concepts.md).
