# Configuration

boxed reads settings from a file named `boxed.toml` and from environment variables. This page lists every key and every variable.

## boxed.toml

### Where boxed looks for it

boxed looks in the current folder, then in each parent folder, and uses the first `boxed.toml` it finds. If there is none, it uses the defaults below.

| Where you run boxed | Which file |
|---|---|
| `mask`, `restore`, `ask`, `policy`, `plan`, `mask-file`, `restore-file`, `dashboard`, `mcp` outside a workspace | The first one found from the current folder upward |
| `workspace create` | The first one found from the project folder upward. boxed stores a copy with the workspace. The hooks, `workspace sync` and the MCP server of that mirror use the copy, so a later edit of `boxed.toml` does not change a mirror that exists |
| The browser side panel | Only `boxed.toml` in the boxed home (`~/.boxed`, or `$BOXED_HOME`). The browser gives the program no project folder. The file is read again before every request |
| `audit`, `journal`, `key`, `check`, `install`, `run` | None |

The file is UTF-8 text. boxed reads only the `[boxed]` table, and its two sub-tables `[boxed.dictionary]` and `[boxed.policy]`. It ignores other tables and keys outside `[boxed]` without a message: a line `level = 3` at the top of the file does nothing.

An unknown key inside `[boxed]` is an error, because a typo must not switch protection off:

```text
boxed: error: boxed.toml: [boxed] has a key boxed does not know; the known ones are level, internal_domains, dictionary, allow, protected_paths, mcp_roots, ner, policy
```

The message does not name the key you wrote, nor the folder of the file: a key of the dictionary can be a client's name, and a path can be private.

### The keys

| Key | Type | Default | What it does |
|---|---|---|---|
| `level` | integer 0 to 4 | `2` | The masking level when a command gets no `--level`. See [concepts.md](concepts.md) |
| `internal_domains` | list of strings | `[]` | Domains whose hosts count as internal |
| `dictionary` | table of term = kind | empty | Your own terms to replace |
| `allow` | list of strings | `[]` | Texts that are never replaced |
| `protected_paths` | list of strings | `[]` | Folders that the hooks of a masked workspace guard like the original project |
| `mcp_roots` | list of strings | `[]` | Folders that the MCP tools `read_masked` and `search_masked` may read |
| `ner` | list of `"ru"`, `"en"` | `[]` | Name models for people and companies |
| `policy` | table | `{}` (profile `no-rules`) | The company policy. See [policy.md](policy.md) |

#### level

```toml
[boxed]
level = 3
```

Levels 0 to 3 mask text. The file accepts level 4, but `mask`, `mask-file`, `ask`, `workspace create` and `mcp` refuse it and point to `boxed plan`: `level 4 sends the task and the table schema only: use boxed plan, or ask at a level from 0 to 3`. `--level N` on a command overrides the key. For `boxed ask` the policy can raise the level and never lower it. The browser panel offers levels 0 to 2 and caps the key at 2.

#### internal_domains

```toml
[boxed]
internal_domains = ["corp.example.com"]
```

A host counts as internal when its name ends in `.internal`, `.local`, `.lan`, `.corp` or `.intranet`, or when it is one of these domains or lies under one (`build.corp.example.com` and `corp.example.com`, not `example.com`). From level 2, internal hosts become `[HOST_N]` and URLs that point to them become `[URL_N]`. Public hosts and URLs stay visible.

#### dictionary

```toml
[boxed.dictionary]
"Acme Corp" = "CLIENT"
"Project Falcon" = "CODENAME"
```

Each entry is a term and the kind of its placeholder. boxed finds the term as a whole word, ignoring case, from level 2 up, and writes `[CLIENT_1]`, `[CODENAME_1]` and so on. Spelling still counts for the number: `Acme Corp` and `ACME corp` get two placeholders.

- A kind is a string. A number, `true`, a list or a date (`"Acme Corp" = 5`) stops the command at once with `[boxed.dictionary] every kind must be a string, such as CLIENT`. The message names neither the term nor the value.
- A kind starts with a letter and holds letters, digits and `_`. boxed upper-cases it. A kind with a space or a leading digit stops the command with `bad dictionary kind 'CLIENT NAME'` as soon as the term occurs in a text.
- A kind cannot be a built-in one such as `EMAIL`, `DATE` or `NUMBER`: `[boxed.dictionary] a term cannot use a built-in kind name`.
- For the policy, every dictionary term puts the category `clients` on a text.
- Levels 0 and 1 do not use the dictionary.

#### allow

```toml
[boxed]
allow = ["support@example.com"]
```

Use `allow` for values that look sensitive but are not, such as a public support address. When a rule, a name model, a number detector or the dictionary finds a text that equals an entry exactly (case counts), boxed leaves it alone. An entry does not unmask part of a longer match.

#### protected_paths

```toml
[boxed]
protected_paths = ["~/.ssh", "../secrets"]
```

The Claude Code hooks of a masked workspace block tools and shell commands that point at the original project, at boxed's own files (the vault, the journal and the like) or at a folder in this list. A relative path counts from the folder that holds `boxed.toml`. boxed expands `~`. Only the hooks use this list. The macOS sandbox of `boxed run` does not know it, and hooks are best effort without the sandbox.

#### mcp_roots

```toml
[boxed]
mcp_roots = ["/var/log/myapp", "logs"]
```

The folders the MCP tools may read, masked. A relative path counts from the folder that holds `boxed.toml`; boxed expands `~`. With an empty list the tools refuse every path: `path is not inside an allowed root (set mcp_roots in boxed.toml)`. The agent must not be able to write to these folders.

#### ner

```toml
[boxed]
ner = ["ru", "en"]
```

`"ru"` runs Natasha, and needs the extra `ner-ru`. `"en"` runs GLiNER (`urchade/gliner_multi_pii-v1`, Apache-2.0), and needs the extra `ner-en`; it downloads the model the first time you use it (about 1 GB) and uses about 2.5 GB of memory. It finds names and companies in English, and in Russian and German too. Both models only produce `PERSON` and `ORG`. If the extra is missing, the command stops with `boxed: error: No module named 'natasha'` (or `'gliner'`). Install the extra, or remove `ner`.

#### policy

```toml
[boxed.policy]
profile = "no-confidential"

[boxed.policy.rules]
"finance:personal-private" = "deny"
```

`profile` is one of `no-rules` (the default), `no-confidential`, `approved-only` and `ban`. `rules` maps `"category:recipient"` to `allow`, `masked:N`, `local-only` or `deny`, and may only be stricter than the profile. Everything about it is in [policy.md](policy.md).

### A complete file

```toml
[boxed]
level = 2
internal_domains = ["corp.example.com"]
allow = ["support@example.com"]
protected_paths = ["~/.ssh"]
mcp_roots = ["/var/log/myapp"]
ner = ["ru"]

[boxed.dictionary]
"Acme Corp" = "CLIENT"

[boxed.policy]
profile = "no-confidential"

[boxed.policy.rules]
"finance:personal-private" = "deny"
```

With this file in the current folder and the extra `ner-ru` installed, `note.txt` holds:

```text
Иван Петров (ivan@example.org) от Acme Corp просит доступ к build.corp.example.com.
Write to support@example.com. The budget is 1 200 EUR.
```

```bash
boxed mask --scope cfgdemo note.txt
```

```text
scope: cfgdemo
[PERSON_1] ([EMAIL_1]) от [CLIENT_1] просит доступ к [HOST_1].
Write to support@example.com. The budget is 1 200 EUR.
```

The name model found the person, the dictionary the client, `internal_domains` the host and `allow` kept the support address. The amount stays visible at level 2. The policy says what happens when this text goes to a personal account:

```bash
boxed policy check --recipient openai:personal-private:US note.txt
```

```text
verdict: deny
categories: clients, code, finance, personal
reason: personal for personal-private: masked at level 1
reason: clients for personal-private: masked at level 2
reason: finance for personal-private: denied
warning: personal data leaves the EEA: this needs a legal basis, masking does not replace it
```

### Errors in the file

Every command that reads `boxed.toml` checks it first and stops with exit code 2. The message starts with `boxed.toml:`, never with the folder of the file, and quotes nothing you wrote: not a value, not a key.

| You wrote | boxed says |
|---|---|
| A key that does not exist: `colour = 1` | `boxed.toml: [boxed] has a key boxed does not know; the known ones are level, internal_domains, dictionary, allow, protected_paths, mcp_roots, ner, policy` |
| A file that is not UTF-8 | `boxed.toml: not UTF-8 text` |
| A value of the wrong type: `level = "2"`, `level = true` | `boxed.toml: [boxed].level must be int` (the same for `list` and `dict`) |
| A list with an item that is not a string: `internal_domains = [1]` | `boxed.toml: [boxed].internal_domains must be a list of strings` (the same for `allow`, `protected_paths`, `mcp_roots` and `ner`) |
| `level = 5` | `boxed.toml: [boxed].level must be 0-4` |
| `ner = ["fr"]` | `boxed.toml: [boxed].ner takes ru, en` |
| `"Acme" = 5` in the dictionary | `boxed.toml: [boxed.dictionary] every kind must be a string, such as CLIENT` |
| `"Acme" = "EMAIL"` in the dictionary | `boxed.toml: [boxed.dictionary] a term cannot use a built-in kind name (EMAIL, DATE, NUMBER and the like)` |
| `"Acme" = "CLIENT NAME"` in the dictionary | `boxed.toml: [boxed.dictionary] a kind has letters, digits and _ only, and starts with a letter` (when a command masks at level 2 or higher) |
| A wrong policy | The messages in [policy.md](policy.md) |
| TOML that does not parse | `boxed.toml: not valid TOML (at line 1, column 5)`: the line and the column, without the words of the parser, which can quote a key |

boxed checks the type of every item as well: a list holds strings only, and every dictionary kind is a string. The two messages for that name the list or the dictionary and nothing of what you wrote: not the item, not the term. Put every item in quotes, such as `"corp.example.com"`.

## Environment variables

| Variable | Default | What it does |
|---|---|---|
| `BOXED_HOME` | `~/.boxed` | The folder for everything boxed keeps. boxed creates it with mode 0700 |
| `BOXED_KEYSTORE` | `keyring` | Where boxed's own keys live (vault, journal, checks, audit): `keyring` or `insecure-file` |
| `BOXED_OPENAI_BASE_URL`, `BOXED_ANTHROPIC_BASE_URL`, `BOXED_DEEPSEEK_BASE_URL`, `BOXED_OPENROUTER_BASE_URL` | not set | A relay address that replaces the provider's address for `boxed ask` |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`, `OPENROUTER_API_KEY` | not set | The API key of a provider, used when the keychain has none |

### `BOXED_HOME`

boxed keeps the vault, the journal, the checks, the workspaces and the reports in this folder. A relative path works, but it then means a different folder in every working directory: use an absolute path. boxed expands `~`. An empty value counts as not set.

`boxed install native-host` writes the current value of `BOXED_HOME` into the launcher that the browser starts, because the browser does not pass your environment on. Run the command again after you change it.

A throwaway home is the safest way to try boxed: use the block in [Try it without touching your own data](install.md#try-it-without-touching-your-own-data). A new `BOXED_HOME` by itself still reads your real agent folders (`~/.claude`, `~/.codex`), so the block sets a new `HOME` too. API keys stay in the system keychain either way.

### `BOXED_KEYSTORE`

`keyring` (the default) keeps the keys in the OS keychain: the macOS Keychain, or the Secret Service on Linux. The keys are `vault-key`, `device-signing-key`, `state-mac-key`, `audit-mac-key` and `observe-hmac`, all under the service name `boxed.si`.

`insecure-file` keeps the same keys as plain files in `$BOXED_HOME/insecure-keys/`. Use it for a throwaway home or a test, never for real data: anyone who can read the folder can read the vault. Any other value is an error:

```text
boxed: error: unknown BOXED_KEYSTORE: it takes keyring or insecure-file
```

`BOXED_KEYSTORE` does not touch API keys. They always use the keychain, or the provider's variable.

On a computer with no keychain service, every command that needs one of these keys stops with `boxed: error: the system keychain cannot be used, and boxed keeps its keys there: on linux, run a secret service such as gnome keyring or kwallet in your session`. Run a Secret Service for the machine. `boxed audit` and `boxed skills scan` still run: audit hashes with a key of the run, and the scan shows its verdicts but is not saved.

### `BOXED_<PROVIDER>_BASE_URL`

For `boxed ask`, the provider's own address is the default. Set the variable to send the request to a relay that you run or trust instead:

| Provider | Variable | Default address |
|---|---|---|
| `openai` | `BOXED_OPENAI_BASE_URL` | `https://api.openai.com/v1` |
| `anthropic` | `BOXED_ANTHROPIC_BASE_URL` | `https://api.anthropic.com/v1` |
| `deepseek` | `BOXED_DEEPSEEK_BASE_URL` | `https://api.deepseek.com` |
| `openrouter` | `BOXED_OPENROUTER_BASE_URL` | `https://openrouter.ai/api/v1` |

boxed adds the path of the call to your address (`/responses`, `/messages` or `/chat/completions`), so give the address up to the same point as the default.

The address must be `https`, or `http` to this computer (`localhost` or a loopback IP). It may hold no login, no query and no fragment, not even an empty `?` or `#`, and only visible ASCII. Anything else stops the command before boxed records anything:

```text
boxed: error: BOXED_OPENAI_BASE_URL must be an https address (or http on this computer) without a login, query or fragment
```

The message never quotes the address. The masked prompt and your API key go to the relay. boxed says so on stderr when it sends, and the journal marks the send with the note `relay`:

```text
boxed: sending through the relay at 127.0.0.1:18765 (BOXED_OPENAI_BASE_URL)
```

An address on this computer is never sent through a proxy. A remote address follows the proxy settings of the environment (`HTTPS_PROXY`, `NO_PROXY`), as does the default provider address. boxed cannot protect a key from a relay you point it at.

### Provider keys

`boxed key set PROVIDER` stores a key in the keychain under the service `boxed.si` and the user `api-key:PROVIDER`. When the keychain has none, boxed reads the variable of the provider. The keychain wins when both exist. `boxed key status PROVIDER` says which one is in use: `set (keychain)`, `set (environment)` or `not set`. `boxed key remove` removes only the keychain entry and names a variable that is still set:

```text
note: OPENAI_API_KEY is still set in the environment
```

A key is visible ASCII without spaces, at most 1024 characters. boxed refuses anything else with `the API key must be printable ASCII without spaces`.
