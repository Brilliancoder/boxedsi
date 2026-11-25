# Check the extensions of your agents

`boxed skills` checks the skills, plugins, MCP servers, hooks and settings that AI agents load on your computer for malicious behaviour. People install these from other people's repositories with one command, and some of them steal keys, download and run programs, or send your requests through someone else's server. boxed reads what is installed, or what you are about to install, and says for each item `dangerous`, `suspicious` or `ok`, with the reason, the file and the line, and what to do. boxed prints full paths; this guide shortens your home folder to `~`.

boxed only reads these files and judges them with rules. It never runs, imports or sources anything it checks, and it never follows a link inside it. A config file of an agent that is itself a link (a `~/.claude/settings.json` kept in a dotfiles folder, a project's `.claude/settings.json`) is read where it points, because the agent reads it there too. Without `--ai` it uses no network. The one exception is the `git clone` of an address you name. The files of your agents change only when you run `boxed skills quarantine` or `restore`.

- `ok` means the rules found nothing, not that an item is safe (see "What it cannot do").
- A report holds secrets and personal data replaced by `[KIND]`, but the names and places in it are real. Read it before you share it.
- The examples ran in a throwaway home with made-up extensions (`HOME` and `BOXED_HOME` set to new folders, `BOXED_KEYSTORE=insecure-file`). The ids, times and hashes on your computer differ. The `ai:` lines below are given as the program writes them: no provider was called for this guide.

## The commands

| Command | What it does |
|---|---|
| `boxed skills scan` | Checks everything installed, saves the result as the record of the last check and adds a journal entry |
| `boxed skills scan TARGET` | Checks a folder, a file, a `.zip`, an https git address or `owner/repo` before you install it. Leaves the record of the last check and the journal as they were. `--html` and `--json` save the reports you name. `--ai` keeps the masked values of its requests in the vault and adds the journal entries of each provider request |
| `boxed skills list` | Shows what is installed with its last verdict, and what is in quarantine |
| `boxed skills quarantine ID` | Takes an installed item out of use, so its agent no longer loads it. Only when you run it |
| `boxed skills restore ID` | Puts a quarantined item back as it was |

The options of `scan` are described where they matter: `--html`, `--json` and `--replace` under "Scan what is installed", `--ai`, `--provider`, `--model` and `--account` under "Ask a model".

## What is checked

An item is one thing an agent loads. The kinds are `skill`, `plugin` (the installed version), `mcp` (an MCP server), `hook`, `agent` (a subagent), `command` (a slash command), `output-style`, `prompt` (a Codex prompt) and `setting`. A setting is only one that runs a command, sends traffic elsewhere or loads code into other programs: `statusLine`, `apiKeyHelper`, `env` entries that point to an API base URL or endpoint (names ending in `_BASE_URL`, `_API_URL`, `_API_BASE` or `_ENDPOINT`), a proxy, a certificate bundle or a package registry, or that load code into every program (`NODE_OPTIONS`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, `PYTHONSTARTUP`), settings that switch off permission prompts, a wide `allow` such as `Bash(*)`, and for Codex `notify`, `[model_providers.*]`, `approval_policy` and `sandbox_mode`.

An agent that is not on the computer is skipped without a word.

| Agent | At user level | In a project |
|---|---|---|
| Claude Code | `~/.claude/skills` (with the skills synced from claude.ai in `~/.claude/skills/synced/<account>/<skill>`), `agents`, `commands`, `output-styles`; `settings.json` (hooks and the settings above); the installed versions of plugins; MCP servers in `~/.claude.json` | `.claude/skills`, `agents`, `commands`, `output-styles`; `.claude/settings.json` and `settings.local.json`; `.mcp.json` |
| Codex | `~/.codex/config.toml` (MCP servers, plugins and the settings above), `hooks.json`, `skills`, `prompts`, `agents`, installed plugins | `.codex/config.toml` and `hooks.json` |
| Any agent that reads `~/.agents` | `~/.agents/skills` | `.agents/skills` |
| Claude Desktop, Cursor, Gemini CLI | MCP servers in their config files; the `skills` folders of Cursor and Gemini | `.cursor` and `.gemini`: MCP servers and `skills` |
| OpenClaw | `~/.openclaw/skills`, `~/.clawdbot/skills`, `~/.openclaw/workspace/skills` | `.openclaw/skills` |

The projects are the current folder and those your agents have registered (`projects` in `~/.claude.json`, `[projects]` in `~/.codex/config.toml`). A copy under `.claude/worktrees/` of a registered project is not counted twice, and a skill folder that two roots reach is one item. A skill synced from claude.ai is named `synced/<skill>` without the account, for example `claude:skill:user:synced/pdf-tools`; when two of your accounts have a skill of the same name, the id of one of them ends in `~2`. Skills and commands inside a plugin belong to the plugin item. The MCP servers and hooks that a plugin declares in its own files are listed as items of their own, with a name that starts with `plugin:`, and are judged as strictly as the settings of a project; they are on or off with the plugin.

How a file is judged:

- It is read whole, whatever its size: padding with blank lines cannot push a payload out of sight. Base64 text of 40 characters or more and invisible Unicode tag characters are decoded and checked again. Base64 is decoded by boxed's own rule, the same on every Python version: lines of base64 are joined, padding in the middle cuts them into pieces that are decoded one by one, the pieces are checked together and each alone, and `-` and `_` read as `+` and `/`.
- Rules cover 22 classes of known techniques: a fake prerequisite that pipes a download into a shell, a password-protected archive, obfuscated execution, theft of keys and wallets, channels that carry data out, reverse shells, persistence, macOS defence evasion and fake password dialogs, orders hidden for the model, tool shadowing, invisible characters, padding, opaque files, instructions loaded from the internet, a changed API address, registry or proxy, hooks that approve or run code, risky MCP launch settings, look-alike names, AI command lines run without approvals, hijacked dependencies, destructive commands and the sending out of your conversation.
- Combinations weigh more than signs. Secret paths and a network call in one file are `critical`. So are a download made executable and run, and decoded text that is run.
- The usual spellings of an attack are caught, and harmless look-alikes in front of the real line do not hide it: a shell or an interpreter named by its path, after `exec` or `command`, in quotes or after `|&`; a download sent with `>` to a file that is then run or made executable; `exec(requests.get(url).text)`, also when `requests` is imported under another name; `.then(eval)`; a decoded file that is made executable and run. Thousands of harmless downloads or pipes before the real one change nothing, and a finding for a download that is run points at that download.
- What cannot be read is a finding, never a pass: a program (Mach-O, ELF, PE), compiled Python, an archive or an Office file, an encrypted zip, a link that leads out of the item, an unreadable file.
- An item that was not checked in full is never `ok`. One that holds more than 10,000 files and links together (only the first 10,000 are read), has a folder inside it that cannot be read, or whose command names more than 20 local scripts gets a `high` finding `incomplete` ("Was not checked in full"), so it is at least `suspicious`. So does a file or a config entry where a rule stopped at one of its own limits before the end: more than 20,000 matches of one pattern, download, `chmod` or fetch to weigh, more than 2,000 base64 runs to decode, more than 200 runs of hidden tag characters or of variation selectors, more than 2,000 invisible characters, or a config entry more than 20 levels deep or with more than 10,000 keys or members in one place (evidence: `a check stopped at its limit before the end of the text: the rest was not checked by every rule`). A limit on how many findings are shown is no such stop: past 200 findings of one pattern the rest is still judged, and only a worse one is added. What was left out still counts toward the item's content by its place, size and times, so a change there marks the item `[changed]` like any other.
- A link on the way to a script is not passed: when a hook, an MCP server or a setting names `./linked/run.sh` and `linked` is a link inside the project, the plugin, the skill or the target, the link is recorded and judged like any other. When every link on the way stays inside (`linked` pointing at `scripts`, or `run.sh` itself a link to `scripts/run.sh`, as npm and pnpm make in `node_modules`), the real script is read as if the command named it. When one leads out, the script is never read: the item is `incomplete`, and a link that leads out is a `link-outside` finding too. A folder behind a link that a command only names (`--root ./shared/docs`) is no program and no concern of its own. The config files of a plugin behind a link are not read.
- A config entry (an MCP server, a hook, a setting) is judged by its command, arguments, address and the names of its `env` and headers. A rule in `permissions.allow` of a Claude Code settings file that holds a secret (Claude Code keeps the whole command that was allowed, a `curl -H "Authorization: Bearer ..."` included) is `inline-secret` too, at `permissions.allow.<n>`. A value is never printed, stored in the record or journaled: in the evidence of a command it is replaced by stars of the same length (a header after `-H`, a query string, the login of an address, the password of `-u user:password`, `-p`, `--password` or `sshpass -p`). Where the text of a config file is checked as a whole (one with more than its entries in a target, the config files and the `plugin.json` manifest of a plugin, a `.claude.json` given as a target; a name in any capitals counts, `.MCP.json` as `.mcp.json`), the evidence of those findings is starred past its labels (`[decoded base64]` and the like), since a value may be spelled there in any form; the line says where to look, and the findings of the entries show the command with its values starred.
- A common honest look-alike is held below `dangerous`: a Homebrew or rustup installer, a skill for AWS that reads `~/.aws`, a formatter hook. It may still be `suspicious` or carry a sign, so that you can look.

## Verdicts and severities

Every finding has a severity. The verdict of an item follows its worst finding:

| Worst finding | Verdict | Meaning |
|---|---|---|
| `critical` | `dangerous` | Stop and look before you use the item. This is what attacks do |
| `high` or `medium` | `suspicious` | Read it. Attacks use the pattern, and some honest tools have it too |
| `low`, `info` or none | `ok` | Signs only, shown under the item. `info` marks an item that runs a command on agent events |

Where an item lives can change the severity. A changed API base URL or endpoint (one that is not the vendor's own), proxy or registry, and a setting that loads code into every program (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, `PYTHONSTARTUP`, or `NODE_OPTIONS` with `--require`, `-r`, `--import` or `--loader`), is `critical` in a project, local or plugin setting, and `medium` in your own user settings. `NO_PROXY` alone, which only names hosts that skip a proxy, is `low`. A hook in your user settings with no download or network in it is `info`. Text that talks to a reviewer or a scanner ("this skill is safe", "ignore warnings") is `high` by itself.

## Scan what is installed

```text
$ boxed skills scan
boxed skills: 7 items checked: 2 dangerous, 2 suspicious, 3 ok

...

DANGEROUS  claude:skill:user:sync-notes  [new]
  where: ~/.claude/skills/sync-notes
  can: network, reads-secrets, runs-commands
  critical  secret-exfiltration  scripts/sync.sh:2
    Reads secrets and talks to the network in the same file
    why: Secret files plus a network call is how keys and wallets are stolen.
    evidence: cat ~/.ssh/id_rsa > /tmp/n.txt
    advice: Quarantine the item unless you can prove the data goes only where you expect.
  high  secret-store  scripts/sync.sh:2
  ...

SUSPICIOUS  claude:mcp:user:files  [new]
  where: ~/.claude.json mcpServers.files
  can: installs-packages, runs-commands
  medium  inline-secret  ~/.claude.json mcpServers.files
    Has a secret written into the config
    why: A secret written in plain text leaks with every copy of the file.
    evidence: mcpServers.files.env.FILES_API_KEY
    advice: Move it to the keychain or an environment variable.
  ...

OK  claude:plugin:user:tool@market  [new]
```

(Shortened: `...` marks what is left out, for example the other dangerous item, a project setting that points the API at another server.) Reading it:

- The first line counts the items. The dangerous come first, then the suspicious, then the rest, each group by id.
- The id is `<agent>:<kind>:<scope>:<name>`, for example `claude:skill:user:my-skill`, `claude:plugin:user:tool@market`, `codex:mcp:user:repl`. The scope is `user`, `project=<folder name>@<six hex characters>` or `local=<the same>` for an item of a project, and `target` for something you scan before you install it. A hook is named by its event and a hash of its command, so reordering hooks does not rename them.
- `[new]` means the item is not in the record of the last check. `[changed]` means its content differs from the record: a file, a link or a config entry changed. Without a mark, nothing changed.
- `where:` is the place, with your home folder as `~`. `can:` lists what the item is able to do, for the dangerous and suspicious ones. It is there so that an honest but alarming skill can be understood, not only feared.
- A finding line has the severity, the rule id and `file:line` (or the key inside a config file). Then come what it is, why it is dangerous, the evidence (at most 160 characters, with secrets and personal data replaced by `[KIND]`; hosts and IP addresses stay, they are the evidence) and what to do. Values are found once in the whole text before any excerpt is cut, so a cut never shows a piece of a key whose name it left out, however long the value, and a value that spans lines (a private key block, a name on the line before) is hidden on each of its lines. The same holds for text hidden in Unicode tags (the evidence shows its first line after `[decoded tags]`), for a value cut by an invisible character or named with look-alike letters, and for the evidence of a config entry, a package address with a login included. Past the first 1,000,000 characters of a file that are read this way (a file larger than that, or a decoded or normalised text beyond it), the evidence is `excerpt left out: the file is too large to mask safely`; the finding and its line stay.
- `could not read: <place> (<reason>)` lines close the report. The reasons are `not valid JSON`, `not valid TOML`, `not valid frontmatter`, `unreadable`, `link to a missing target` and `too many files` (an item may hold 10,000 files and links together). The rest is checked anyway. Every reason but `link to a missing target` means that something was not checked, so the scan does not exit 0 (see the exit codes below); when the place is inside an item, that item has an `incomplete` finding as well.

What `can:` says:

| Word | The item can |
|---|---|
| `runs-commands` | start programs or shell commands |
| `network` | reach the network |
| `reads-secrets` | read places that hold keys, tokens or wallets |
| `writes-agent-files` | write the instructions, memory or settings of an agent |
| `installs-packages` | install or run packages |
| `binary-content` | carry programs, archives or other content that cannot be read |
| `event-hooks` | run a command when the agent does something |
| `auto-approves` | skip or switch off confirmations |
| `obfuscation` | hide text or code by encoding |

A scan of what is installed writes one journal entry (its coverage is `full`, or `partial` when an item has an `incomplete` finding or a `could not read` line keeps something from being checked, with the counts `incomplete=` and `unread=` in its note) and then saves the record of the last check in `skills/record.json` in the boxed home (the digest, the verdict and the rule, severity, file and line of each finding; never the evidence). The record is saved only after the journal took the entry, so the warning at the start of a session never trusts a check the journal does not hold. Details are in [privacy.md](privacy.md).

Options:

- `--html FILE` also writes a self-contained page: everything is escaped, and it has no script, no link and no resource from outside.
- `--json FILE` also writes the same result as JSON, format `boxed-skills-report/1`: `format`, `target`, `summary`, `items` (each with its `findings`, `capabilities`, `change` and `digest`) and `problems`. It is plain ASCII.
- `--replace` replaces a report file that is already there and is not a report of boxed. Without it boxed replaces only an earlier skills report of its own and stops at any other file.
- boxed checks the names before it starts to scan. A report is never written in the boxed home and never through a link, and `--html` and `--json` cannot name the same file. The files have mode 600, and boxed prints `html: FILE` or `json: FILE` for each.

Exit codes: 0 when every item is `ok`, nothing was left unchecked and the check was saved. 3 when something is `dangerous` or `suspicious`, or when something could not be checked (a `could not read` line with any reason but `link to a missing target`); the report is printed in full, also when the check could not be saved. 2 for an error. 1 when `--ai` was asked and the AI check failed (this wins over 3, and the report of the rules is printed anyway), and also when every item is `ok` but the check could not be saved. The report is printed, and the files of `--html` and `--json` are written, before the save is tried, so a failed save takes no verdict away. boxed adds one line on stderr: `boxed: warning: the check was not saved, so the next session will not know about it: run boxed skills scan again` when the record could not be written. Look at the free space and at the rights on the `skills` folder of the boxed home, then scan again. When the journal could not take the entry (no keychain, or the journal cannot be written), the record is left as it was and the line is `boxed: warning: the check was not saved: the journal could not take it (no keychain, or the journal cannot be written), so the record was left as it was: run boxed skills scan again`; the exit codes are the same. A scan of a target keeps no record, so it has nothing to save.

## Check before you install

```text
$ boxed skills scan ~/downloads/cool-skill --json report.json --html report.html
boxed skills: cool-skill: 1 item checked: 1 dangerous, 0 suspicious, 0 ok

DANGEROUS  agents:skill:target:cool-skill
  where: cool-skill
  can: obfuscation, runs-commands
  critical  decode-exec  setup.sh:2
    Decodes hidden content and runs it
    why: Encoding hides what will run; decoding straight into a shell or eval is how obfuscated payloads start.
    evidence: echo "ZWNobyBoZWxsbw==" | base64 -d | sh
    advice: Do not run it; decode the content by hand to see what it does.
  low  prompt-injection  SKILL.md:8
  ...
html: report.html
json: report.json
```

The target is one of:

- a folder or a file on your computer;
- a `.zip` or `.skill` file;
- an https git address, including a GitHub address with a branch and a folder, `https://github.com/owner/repo/tree/<ref>/<path>` (the ref is one name);
- `owner/repo` or `owner/repo/path` for GitHub. This short form counts only when no folder of that name exists, and any owner works, also one whose name starts like a scheme (`httpkit/demo`): only text with `://` in it, or one that starts with `git@`, is read as an address. boxed then says which address it took, on stderr: `boxed: no folder of that name here, taking https://github.com/owner/repo`.

boxed finds every skill folder, plugin and config file inside the target, and every file in a folder of commands, subagents, output styles or prompts (`.claude/commands`, `.claude/agents`, `.claude/output-styles`, `.codex/prompts`, `.codex/agents`), each an item of its own, as in a project: `claude:command:target:deploy`. The files that none of them holds, also those beside a harmless skill, are checked as one more item named by the target, `agents:skill:target:<target>`; a folder with none of them is that one item. A config file whose every part became an item is not in it, but one with anything more (Codex `developer_instructions`, a `$schema`, a list of permissions) is, and its text is checked whole, so a finding of its entries may show twice. A folder `.git` is no part of it: no agent loads it, git's objects would only read as data that cannot be checked, and git cannot keep a file there. `.hg` and `.svn` are checked like any folder, since a git repository or a zip can carry them. A target scan saves no record and writes no journal entry of its own (only `--ai` adds the entries of its provider requests), and its items carry no `[new]` mark. Nothing in the target is ever run, and no link in it is followed, not even one at the top of `.claude/commands`.

How a target is fetched:

- A git address is cloned over https only, to depth 1, without submodules, LFS, git hooks or templates, with no git configuration of yours or of the system, no credentials and no prompts, and with a time limit of 120 seconds. The clone goes into a private temporary folder (mode 0700) that is removed afterwards, also when the scan fails. `git` must be installed. An address with a login, a query or a fragment is refused, and so is an ssh address such as `git@host:owner/repo`: clone it yourself and scan the folder.
- A zip is unpacked into the same kind of folder. A name that leaves the folder, is used twice, or would mean something else on Windows (a drive, a colon, a trailing dot or space, a device name such as `CON`, `nul.txt` or `con .txt`, as Windows itself judges it) stops the scan before anything is written, and the unpacking stops at 10,000 files or 256 MiB. A link in the archive is never made, but it is not dropped: boxed says on stderr how many it left out (`boxed: 2 links in the archive were not unpacked, and will be reported`) and judges each one as it judges a link in a folder. A link that stays inside its item is no finding. One that leads out of it is a `link-outside` finding: `critical` when it points at a place that holds keys, credentials or the settings of an agent (`.ssh`, `.aws`, `.claude` and the like), your home folder or the root, `high` otherwise. A link belongs to the item whose folder holds it, also when the archive spells that folder with other capitals or another Unicode form than the item has. An encrypted zip is not unpacked: it is checked as a file and is a `critical` finding.

## List, quarantine and restore

`boxed skills list` shows each installed item with the verdict of the last check, `unchecked` for an item that is not in the record yet, and `[new]` or `[changed]` as in the report. Lines `could not read: ...` name what could not be read. Then comes `quarantined: N`, with one line for each item in quarantine: the quarantine id, the item id, the method and the time. A quarantine whose record could not be saved (a full disk, for one) is found by its folder in the boxed home and listed too, with `not in the record: boxed skills restore <id> puts it back`. `list` changes nothing.

Quarantine takes an item out of use in a way that can be undone. It happens only when you run it: `scan` and the warning at the start of a session never do it.

```text
$ boxed skills quarantine sync-notes
quarantined claude:skill:user:sync-notes: moved to the quarantine folder of boxed
quarantine id 5d089d71: boxed skills restore 5d089d71 puts it back
$ boxed skills list
installed: 7
dangerous  claude:setting:project=shop@bcb867:env.ANTHROPIC_BASE_URL
suspicious claude:mcp:user:files
suspicious claude:skill:user:pdf-tools
unchecked  claude:skill:user:new-helper  [new]
ok         claude:hook:user:PostToolUse:f68b51ec
ok         claude:plugin:user:tool@market
ok         claude:skill:user:my-skill
quarantined: 1
5d089d71  claude:skill:user:sync-notes  move  2026-11-04T00:53:52.300424+00:00
$ boxed skills restore 5d089d71
restored claude:skill:user:sync-notes: moved back to its place
```

(A skill named `new-helper` was added after the last scan, so `list` shows it as `unchecked`.)

`ID` of `quarantine` is the full item id from `list`, or just the name (`sync-notes`, `files`, `tool@market`). If the name fits no item or several, boxed refuses and, for several, lists up to 20 ids to choose from. `ID` of `restore` is the quarantine id, the item id or the name.

| Item | Quarantine | Restore |
|---|---|---|
| Skill, subagent, slash command, output style, Codex prompt (of any agent) | Moves the folder or file to `skills/quarantine/<id>/payload` in the boxed home. The same disk only: a move never copies | Moves it back. Refuses when something stands in its place |
| Claude Code plugin | Sets `enabledPlugins["name@market"]` to `false` in `~/.claude/settings.json` (a project plugin: in the project's `.claude/settings.local.json`). The MCP servers and hooks it declares go off with it | Puts the earlier value back, or removes the key boxed made |
| Codex plugin, Codex MCP server | Writes `enabled = false` in its table of `~/.codex/config.toml`, as a text edit that `tomllib` must read back | Puts the earlier line back, or removes the one boxed made |
| Claude Code MCP server of user or local scope (`~/.claude.json`) | Runs `claude mcp remove` with the name of the server and nothing else, after saving the entry | Writes the saved entry back into `~/.claude.json` at its key, by itself: it does not need `claude`, and no value of the entry is ever put on a command line |
| MCP server in a project's `.mcp.json` | Names it in `disabledMcpjsonServers` of the project's `.claude/settings.local.json` | Takes the name out again |
| A hook or a setting in a JSON file; an MCP server of Claude Desktop, Cursor or Gemini | Cuts the entry out of its JSON file and saves it | Puts it back at the same key and place |
| Codex `notify` or a `[model_providers.x]` table | Cuts it out of `config.toml` as text and saves it | Puts it back where TOML reads the file as before |

A restore of a file nobody has touched since writes the bytes from before the edit back, so the file is the same byte for byte (a Claude Code MCP server always goes back at its key in `~/.claude.json`). A file that has changed since gets the entry back by its meaning, checked by parsing it. A hook goes back only into the group it was cut from, one of the same event with the same matcher.

A user plugin can be switched on again by the settings of the current project, which win over yours. The first quarantine switches it off in `~/.claude/settings.json` and then prints `the settings of this project still switch it on here: run the same command again to switch it off in this project too`. The second one writes `false` into the project's `.claude/settings.local.json`. Each has a quarantine id of its own.

What stays in the quarantine folder `skills/quarantine/<id>/` (mode 0700): `entry.json` (mode 600) with the entry that was cut out, which can hold `env` and header values and the command of a hook; `original` (mode 600) with the bytes of the edited file before the edit, a full copy of it, so it also holds the values of every other entry in that file (the `env` and headers of other MCP servers, allowed commands); or `payload`, the moved item. `restore` removes the folder. Delete the boxed folder and they are gone, so restore first (see [install.md](install.md)). Quarantine and restore each write a journal entry with the kind only.

boxed refuses, and changes nothing, when:

- a config file does not parse, changed between reading and writing, is a link, has a second name on disk (a hard link: a replacement would part the two names for good) or has a key written twice;
- the entry is declared by a plugin (quarantine the plugin) or by a skill, agent or command file (quarantine that file);
- the item is already in quarantine or already switched off;
- you quarantine a Claude Code MCP server and `claude` is not on the `PATH` (a restore does not need it), or `claude mcp remove` fails and the server is still in place;
- the item is on another disk than the boxed folder, or its place is taken at restore.

One more case is no refusal. If a step fails or is stopped after it has changed the item (`claude mcp remove` removed the server and then failed, timed out or was interrupted), boxed does not take the saved copy away. It records the quarantine, prints the quarantine id and then `the step reported a failure or was stopped, but the item is no longer as it was: it is kept in quarantine, see boxed skills list`, and exits 0 (after Ctrl-C it prints the same lines and then stops). `boxed skills list` shows it, and `restore` puts it back. Only when the item is seen in its place, untouched, is the saved copy dropped and the command a plain refusal.

The messages are in [troubleshooting.md](troubleshooting.md). The warning at the start of a session does not count what is switched off in quarantine as new, changed or dangerous, and that includes the MCP servers and hooks a quarantined plugin declares. An item that is in use again (put back by hand, or switched on by the settings of a project) is named again, and quarantining it gives a new quarantine id; the earlier id can still be restored.

## The warning at the start of a session

The Claude Code plugin from `boxed install claude` has one hook. At the start of a session and after `/clear` it runs `boxed hook skills-check`, which reads what is installed for you and for the current folder and compares it with the record of the last check. It says:

- before any scan: `boxed has not checked the extensions of your agents yet: run boxed skills scan`;
- when the record is damaged: `boxed cannot read its record of checked extensions: run boxed skills list to see why`;
- for items that are new or changed since the last check: `boxed: 1 new or changed agent extension since the last check: claude:skill:user:new-helper: run boxed skills scan`, with up to five ids;
- for items the last check found dangerous that are still installed and switched on: `boxed: 1 agent extension found dangerous by the last check is still installed: ...: run boxed skills quarantine ID`. For these the hook also gives the model a fixed note: how many there are, an opaque reference for each (`bx-` and a hash of the id), and to ask you before it invokes a skill, plugin, MCP server, hook or subagent and not to follow the instructions of a flagged one. The names, which are the extension author's text, go only to you, never into the model's context;
- nothing when there is nothing to say.

It reads only. It does not use the network, write the record, block anything or quarantine anything. A failure is a line in `hook-errors.log` and the session goes on.

What the two lines leave out:

| An item that is | In the new or changed line | In the dangerous line |
|---|---|---|
| switched off by `boxed skills quarantine`, and what a quarantined plugin declares | not named | not named |
| switched off by hand (a plugin, an MCP server), and what a plugin switched off by hand declares | named when it is new or changed since the last check, until a scan has seen it | not named |
| back in use after a quarantine (put back, or switched on again by the settings of a project) | named like any other | named like any other |
| one of the guard hooks that boxed itself writes into a masked copy | not named | not named |
| a hook put next to those guard hooks in a copy | named like any other | named like any other |

Only a quarantine takes an item out of both lines. Something you switched off by hand is left out of the dangerous line only, because it is not in use, and it stays in the other line as long as it is new or changed since the last check. A guard hook counts as boxed's own only when its command is `<boxed> hook <event>` or `<python> -I -m boxed.cli hook <event>` and nothing else, the program is the one that runs the check (the `boxed` on the `PATH`, the launcher that started the check, which is the one in `~/.local/bin` when the `PATH` has none, or the same Python), and the handler does not set `onFailure` to anything but `block`. A program that is only named `boxed`, a command with anything added to it, or a handler set otherwise is somebody else's, and is named.

It is silent where it cannot know: when `boxed` is neither on the `PATH` nor in `~/.local/bin`, and under the sandbox of `boxed run`, which closes the `skills` folder of the boxed home. In a masked workspace it checks the copy like any project: what is configured in the copy is what the agent loads there. The items of a copy carry the name of the copy's folder in their ids, so they are new until a scan has been run from that folder, except the guard hooks that boxed itself writes there, which are never named. It is for Claude Code, not for Codex, and not for Windows.

## Ask a model: --ai

```bash
boxed skills scan --ai --provider openai --model gpt-5 --account corporate
```

Rules are the judge. `--ai` adds a second pair of eyes for what rules read poorly, such as instructions in plain language.

- `--ai` needs `--provider` and `--model`, and they need `--ai`. `--provider` is one of the providers of `boxed ask`, `--model` the model to ask. `--account` is the kind of account your key belongs to, as in `boxed ask` (`personal-training`, `personal-private`, `corporate` or `api-zero-retention`); without it the provider's usual kind counts. The key is the one from `boxed key set` or the provider's environment variable. Without a key boxed stops with `no API key for openai: run boxed key set openai`, unless there is nothing to send.
- What goes out: the text of the files of an item that have at least one finding of the rules, in requests of at most 100 KiB. Never a config entry or the config file of an agent (`settings.json`, `settings.local.json`, `.mcp.json`, `mcp.json`, `hooks.json`, `config.toml`, `claude_desktop_config.json`, `.claude.json`, `installed_plugins.json`, the lists of installed skills, a plugin's `plugin.json`; in any capitals), whose `env`, headers and allowed commands stay on your computer even when the file has findings (`ai: skipped 2 files: agent configs, whose values never leave`). Never a file over 100 KiB, a file that is not UTF-8 text, a file name or a path: the model sees `file-1`, `file-2`, and the ids and severities of the rule findings as hints.
- It is masked first, at level 1 and with your `boxed.toml`: secrets, e-mail addresses, phone numbers, IP addresses and other personal data become placeholders. Host names and URLs stay readable, or the model would have nothing to judge. Before it sends, boxed prints on stderr how many files and about how many tokens go where: `ai: sending 2 files (about 900 tokens) in 1 request to openai, model gpt-5; secrets and personal data are masked first`.
- It goes through the same channel as `boxed ask`, so the policy of the `boxed.toml` found from the current folder upward decides first, a `sent` record is written before the request and a `received` record after it, with the scope `skills-<UTC time>`. A policy that says `deny` or `local-only` for that provider sends nothing, and one that asks for a higher level masks more (host names and URLs too).
- The model must answer in a strict JSON shape. A finding counts only when its quote is in the file word for word; boxed finds the line itself. At most 10 findings a file are kept, and their text is redacted. They appear with the rule `ai-review` and the title "A model flagged this passage".
- The model can only add. Nothing in its answer removes or lowers a finding of the rules, and a verdict never goes down. A file that imitates the markers around the text sent to the model is a `high` finding of its own (`delimiter-collision`), and so is text addressed to a reviewer (`reviewer-address`, found by the rules with or without `--ai`).
- A file with the same SHA-256 that the same provider and model have judged is not sent again. The answers are kept in the record, for scans of what is installed: of each finding only the rule, the severity, the file and the line, never its evidence or the model's reason. A finding from the record shows the line of the file again, with every value that the whole file holds hidden as in the first report (a name on the line before, a private key block), with the reason "a model judged this passage unsafe". A target is looked at too: a zip or a clone is reviewed while it is still unpacked.
- What the masking hid stays hidden. boxed reads the answer with the placeholders the model saw, and puts a hidden value back only to find a quote in the file. In the text it keeps, the value is hidden again in every shape the answer can give it (other spaces, a soft hyphen, JSON escapes). When the map of the hidden values cannot be read, the answer is ignored and boxed prints `ai: the answer could not be checked against the masked values: it was ignored`; that counts as a failed check (exit code 1).
- An answer that does not follow the format is ignored, and the result of the rules stands. A policy block or a failed request is "the AI check did not run": boxed prints `ai: ...` lines on stderr and the report of the rules, and exits with code 1.

Without `--ai` nothing leaves your computer. What `--ai` sends is also in [privacy.md](privacy.md) and in [data-flows.md](../security/data-flows.md).

## What it cannot do

- **Rules read patterns, not meaning.** A skill that asks the model in everyday words to send your notes somewhere, or to ignore what you say, can pass when no known phrase or technique shows. `--ai` is a second look, not a guarantee.
- **MCP servers are not started.** boxed checks the config and the local files its command names. Starting a server only to list its tools would run unchecked code. What a server tells the model while it runs is not checked.
- **A new technique passes.** The rules follow known attacks.
- **A scan is a moment.** An item can change later. The warning at the start of a session notices changes in Claude Code, for the user level and the current folder, after you have scanned once. After an update of a plugin, scan again.
- **Not covered:** the Cursor `hooks.json` and Gemini CLI extensions; Continue, Cline, VS Code and browser extensions; npm and pip packages in general. boxed does not look anything up by reputation (VirusTotal and the like): it works on your computer.
- **Nothing blocks an install.** The warning at the start of a session informs; it does not stop a session, and nothing stops you from installing an unchecked skill. The results are in the terminal, the HTML page and the JSON file: the desktop app and the browser panel have no screen for them yet.
- **The record is not signed.** It is read strictly and kept private, and an agent in a masked workspace cannot reach it, but a program running as you can rewrite it. That hides a warning, nothing more (see [threat-model.md](../security/threat-model.md)).
- **Quarantine is not clean-up.** It stops an item from loading. If a dangerous item has already run, rotate the keys it could read and check the computer.
- **Windows:** the commands are written to use the same folders in your profile. CI runs `boxed skills scan` on Windows, but nobody has tried the commands on a Windows desktop, about 100 tests of `serve` and `skills` do not pass on Windows yet, and the warning at the start of a session is not available there.

## Exit codes

| Command | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| `scan` | every item `ok`, nothing left unchecked and, for what is installed, the check was saved | `--ai` was asked and failed (the report of the rules is printed); or every item is `ok` but the check could not be saved | error: wrong arguments, a target that cannot be fetched, a damaged record | something is `dangerous` or `suspicious`, or could not be checked, also when the check could not be saved |
| `list` | done | | error | |
| `quarantine`, `restore` | done; also when a step failed after it had changed the item and the quarantine was kept | | a refusal: nothing was changed | |
| `hook skills-check` | always: it only informs | | | |

The messages and what to do about them are in [troubleshooting.md](troubleshooting.md).
