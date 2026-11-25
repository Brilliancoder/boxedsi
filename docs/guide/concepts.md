# Concepts

The ideas behind the commands: levels, placeholders and scopes, the vault, the journal, policy, observation and training checks. The last section lists what boxed does not do.

## Levels

A level says how much boxed replaces. Each level replaces what the lower levels replace, and more. The default is level 2. Set it in `boxed.toml` (`level`) or for one command with `--level N`.

| Level | Replaced with a placeholder | Still visible | Use it for |
|---|---|---|---|
| 0 | API keys, tokens, passwords, private keys, JWTs, card numbers, and tokens that look random | Everything else | Public data |
| 1 | Level 0, plus e-mail addresses, phone numbers, IP addresses, IBANs, Russian INN and SNILS numbers, passport numbers, US social security numbers, and people (with a name model) | Companies, hosts, amounts, dates | Text where personal data is the only problem |
| 2 (default) | Level 1, plus internal hosts and URLs, EU VAT numbers, Bitcoin and Ethereum addresses, companies (with a name model) and the terms of your dictionary | Public hosts and URLs, amounts, percentages, dates, numbers | Letters, documents, code, logs |
| 3 | Level 2, plus every amount, percentage, date and number of two or more digits | The wording, single digits, versions such as `1.2.3` | Finance, sales, HR, strategy |
| 4 | Not a masking level. The AI gets the task and the table schema, and returns a plan that boxed runs on your computer (`boxed plan`) | The task, column names and types | Tables and reports |

Level 3 never replaces less than level 2. boxed shifts and scales nothing: an amount becomes `[MONEY_1]`, not a different amount. Commands that mask text (`mask`, `mask-file`, `ask`, `workspace create`, `mcp`) refuse level 4 and point to `boxed plan`.

Here is one text at each level. The file `sample.txt` holds a name, an e-mail address, a phone number, an internal host, an IP address, an AWS example key, an amount, a date, a percentage, a public URL, a card number and a company. In the output, the `scope:` line goes to stderr and the masked text to stdout.

```text
Ticket 4711. Anna Meier (anna.meier@example.com, +1 202 555 0143) says db1.corp.internal
at 10.1.2.3 rejects the key AKIAIOSFODNN7EXAMPLE. The invoice of 1 200 EUR is due on
2026-10-21 with a 15% discount. Docs: https://www.example.com/help. Card 4111 1111 1111 1111.
Customer: Acme Corp.
```

```bash
boxed mask --level 0 --scope lvl0 sample.txt
```

```text
scope: lvl0
Ticket 4711. Anna Meier (anna.meier@example.com, +1 202 555 0143) says db1.corp.internal
at 10.1.2.3 rejects the key [SECRET_1]. The invoice of 1 200 EUR is due on
2026-10-21 with a 15% discount. Docs: https://www.example.com/help. Card [CARD_1].
Customer: Acme Corp.
```

Level 1 (`--level 1`):

```text
Ticket 4711. Anna Meier ([EMAIL_1], [PHONE_1]) says db1.corp.internal
at [IP_1] rejects the key [SECRET_1]. The invoice of 1 200 EUR is due on
2026-10-21 with a 15% discount. Docs: https://www.example.com/help. Card [CARD_1].
Customer: Acme Corp.
```

Level 2 (the default):

```text
Ticket 4711. Anna Meier ([EMAIL_1], [PHONE_1]) says [HOST_1]
at [IP_1] rejects the key [SECRET_1]. The invoice of 1 200 EUR is due on
2026-10-21 with a 15% discount. Docs: https://www.example.com/help. Card [CARD_1].
Customer: Acme Corp.
```

Level 3 (`--level 3`):

```text
Ticket [NUMBER_1]. Anna Meier ([EMAIL_1], [PHONE_1]) says [HOST_1]
at [IP_1] rejects the key [SECRET_1]. The invoice of [MONEY_1] is due on
[DATE_1] with a [PERCENT_1] discount. Docs: https://www.example.com/help. Card [CARD_1].
Customer: Acme Corp.
```

Three things in this output are easy to miss:

- `Anna Meier` and `Acme Corp` stay visible at every level. People and companies need a name model or your dictionary (below). Without them boxed finds only what its rules and your dictionary describe.
- `https://www.example.com/help` stays visible at level 2. The level replaces internal hosts and URLs: names that end in `.internal`, `.local`, `.lan`, `.corp` or `.intranet`, and names under a domain you list in `internal_domains`. boxed leaves a public address alone.
- boxed finds a phone number when it starts with `+` or looks like `8 (495) 123-45-67`. A number written as `030 1234567` stays visible at levels 0 to 2.

### What each placeholder stands for

| Placeholder | What it replaces | From level |
|---|---|---|
| `[SECRET_N]` | Keys and tokens of common services (AWS, GitHub, OpenAI, Anthropic, Slack, Google, Stripe, Telegram bots, bearer tokens), values after names such as `password`, `secret`, `token`, `api key` and their Russian forms, login and password pairs, passwords inside URLs, passwords in table cells, and any other token that looks random (see below) | 0 |
| `[PRIVATE_KEY_N]` | PEM private key blocks | 0 |
| `[JWT_N]` | JSON web tokens | 0 |
| `[CARD_N]` | Card numbers with a valid checksum and the prefix of a real card network | 0 |
| `[EMAIL_N]`, `[PHONE_N]`, `[IP_N]` | E-mail addresses, phone numbers, IPv4 and IPv6 addresses (not loopback or unspecified ones) | 1 |
| `[IBAN_N]`, `[INN_N]`, `[SNILS_N]` | IBANs, Russian tax numbers (after the word `ИНН`, `INN` or `TIN`) and insurance numbers, all with valid check digits | 1 |
| `[PASSPORT_N]` | Passport numbers, only after a word such as `паспорт`, `загранпаспорт`, `серия` or `passport`: a Russian series and number (`4510 123456`, `75 1234567`), or 6 to 9 letters and digits after `passport` | 1 |
| `[SSN_N]` | US social security numbers: `123-45-6789` (not right after a word such as `part` or `order`), or nine digits after `SSN` or `social security number`. The area, group and serial parts must be ones the SSA assigns | 1 |
| `[PERSON_N]` | People, found by a name model | 1 |
| `[HOST_N]`, `[URL_N]` | Internal host names and URLs to them | 2 |
| `[VAT_ID_N]` | EU VAT numbers with their country code. Numbers of Austria, Belgium, Germany, Spain, France, Italy, the Netherlands and Poland are found anywhere when the check digit is right; numbers of any EU country are found after a word such as `VAT`, `TVA`, `USt` or `BTW` | 2 |
| `[CRYPTO_ADDR_N]` | Bitcoin addresses of the main net (starting with `1`, `3` or `bc1`) with a valid checksum, and Ethereum addresses (`0x` and 40 hex digits; when the letters are of both cases the capitals must follow the EIP-55 checksum) | 2 |
| `[ORG_N]` | Companies, found by a name model | 2 |
| `[KIND_N]` for your own kinds | Terms from `[boxed.dictionary]`, for example `[CLIENT_1]` | 2 |
| `[MONEY_N]`, `[PERCENT_N]`, `[DATE_N]`, `[NUMBER_N]` | Amounts, percentages, dates, other numbers of two or more digits | 3 |

A token that looks random is a `[SECRET_N]` too. boxed takes a run of letters, digits, `+`, `-` and `_` that holds a lower-case letter, a capital and a digit, has fewer than half of its characters in words of four letters or more, and is no UUID, no hex hash and no alphabet. What else it needs depends on the words before it on the same line:

- After a word such as `key`, `token`, `secret`, `password`, `credentials` or `ключ`, 20 characters and an entropy of 3.6 bits per character are enough.
- On its own, it must have 32 to 128 characters, 4.2 bits, and not begin like a file in base64 (`eyJ`, `H4sI`, ...). The IDs of services (`evt_...`, KSUID, ULID) have 26 to 28 characters, and a longer run is data.
- If the nearest of these words is one of public things (`wallet`, `address`, `public key`, `verification`), it is never a secret. The private key of a wallet is one.
- A slash right before or after it makes it a part of a path, so the IDs in the URLs of documents, files and deploys are left alone. The path of a webhook is the exception, as it ends in its secret: `.../services/T000/B000/<secret>`, `.../api/webhooks/<id>/<secret>`, `.../hooks/<secret>`. A dot or a colon ends a run.

Digests with their algorithm (`sha256=...`, `sha512-...`), data URI payloads, public PEM blocks and SSH public keys are left alone. The rule only fills gaps: it never changes what the rules above found.

It cannot tell a key from other random data of the same shape. A key that stands on its own and has fewer than 32 characters is not found unless a word such as `token` stands before it, nor is one made of letters only, of lower-case letters and digits only, or one that a slash cuts into pieces. Opaque IDs after a word such as `key` and base64 data after a word of credentials are replaced; put an ID that must stay readable in `allow` ([configuration.md](configuration.md#allow)).

The rules are patterns plus checksums. They miss things. The [benchmark](../../bench/README.md) runs on synthetic documents and says so itself; read the placeholders in the masked text before you send it.

### Name models

`ner = ["ru"]` in `boxed.toml` turns on Natasha, a Russian name model (extra `ner-ru`). `ner = ["en"]` turns on GLiNER, which finds names and companies in English and also in Russian and German (extra `ner-en`; the model, about 1 GB, downloads the first time you use it). You can list both. The settings are in [configuration.md](configuration.md).

With this `boxed.toml`:

```toml
[boxed]
ner = ["ru"]
```

and this `ru.txt`:

```text
Иван Петров из ООО Ромашка просит перенести встречу на вторник.
```

run:

```bash
boxed mask --scope ru1 ru.txt
```

```text
scope: ru1
[PERSON_1] из [ORG_1] просит перенести встречу на вторник.
```

If `boxed.toml` asks for a name model whose extra you have not installed, every masking command stops with `boxed: error: no module named natasha: install the extra that brings it (see install.md)` (or `gliner`). Install the extra or remove `ner`.

## Placeholders and scopes

A placeholder is a kind in capitals and a number in square brackets: `[EMAIL_1]`. Inside one scope the same original text always gets the same placeholder, and a new original gets the next number of its kind.

A scope is a named map from placeholders to originals. You name it with `--scope`. Without `--scope` boxed makes a name from the command and the time, for example `manual-20261024T101009`, and prints it on stderr as `scope: ...`. Restore needs the same scope that masked the text.

The file `dup.txt` holds:

```text
Reply to anna@example.com or bob@example.com, again anna@example.com. Old note: [EMAIL_7].
```

```bash
boxed mask --scope dup dup.txt
```

```text
scope: dup
Reply to [EMAIL_1] or [EMAIL_2], again [EMAIL_1]. Old note: [LITERAL_1].
```

A second text masked in the scope `dup` continues the numbering and reuses the numbers of values it has seen:

```bash
printf 'And carol@example.com, plus bob@example.com.\n' | boxed mask --scope dup
```

```text
scope: dup
And [EMAIL_3], plus [EMAIL_2].
```

Use one scope for texts that belong together, so that the same person stays `[PERSON_1]` across prompts. Use a new scope for unrelated work. boxed writes the scope name in clear text to the journal and to the vault, so choose a neutral one such as `deal-7`, not a client name.

The old note `[EMAIL_7]` in `dup.txt` looks like a placeholder boxed could issue. boxed masks such text as `[LITERAL_1]`, so that restore returns it unchanged and never mistakes it for a placeholder it issued. A bracketed token of a kind boxed does not use (`[GPIO_12]`) stays as it is.

The spelling counts. `Acme Corp` and `ACME corp` are different originals and get different placeholders, even if one dictionary term matches both.

### Restore

`boxed restore` puts the originals back into an answer from the AI. It replaces placeholders that are in the scope and changes nothing else. It does not fix the words around a placeholder, and it never guesses.

```bash
boxed mask --level 1 --scope demo sample.txt > masked.txt
boxed restore --scope demo masked.txt
```

```text
Ticket 4711. Anna Meier (anna.meier@example.com, +1 202 555 0143) says db1.corp.internal
at 10.1.2.3 rejects the key AKIAIOSFODNN7EXAMPLE. The invoice of 1 200 EUR is due on
2026-10-21 with a 15% discount. Docs: https://www.example.com/help. Card 4111 1111 1111 1111.
Customer: Acme Corp.
```

Restore reports two kinds of problem and leaves the text as it is:

- unknown: a well-formed placeholder of a kind boxed uses that the scope does not hold, such as `[EMAIL_9]`. The AI invented it, or it came from another scope.
- suspicious: a placeholder the AI damaged, such as `[EMAIL 1]` or `[email_1]`.

The file `answer.txt` holds `Write to [EMAIL_1], then [EMAIL_9] and [EMAIL 1] and [email_1].`

```bash
boxed restore --scope demo answer.txt
```

```text
not restored, check by hand: [EMAIL_9], [EMAIL 1], [email_1]
```

The exit code is 3 and stdout stays empty. Check the answer by hand, or add `--force` to print it anyway. The message still goes to stderr, and the exit code is 0 with `--force`.

## The vault

The vault is the file `vault.db` in the boxed home (`~/.boxed`, or `$BOXED_HOME`). It holds one encrypted map per scope. boxed encrypts each map with AES-256-GCM, and the key (`vault-key`, service `boxed.si`) lives in the OS keychain, not in the file. boxed does not encrypt the scope names or the time of the last change.

boxed does not copy your files. The vault holds only the values that boxed replaced, each with its placeholder, which is what restore needs.

boxed does not expire maps. A map stays until you drop the workspace it belongs to (`boxed workspace drop`) or delete `vault.db`. Without the vault, or without the keychain entry, boxed can no longer restore earlier answers:

```text
boxed: error: a marker map of the vault cannot be decrypted: wrong key or tampered data
boxed: error: unknown scope: boxed journal show lists the scopes in use (the scope field)
```

The first line appears when the keychain entry is gone, the second when the file is gone. See [privacy.md](privacy.md) for everything boxed stores.

## The journal

boxed adds one line to `journal.jsonl` in the boxed home each time it takes one of these steps: it masks or restores text, prepares a file or a plan, creates or syncs a workspace, serves an MCP tool, answers the browser panel, calls an API, blocks a prompt, or checks, quarantines or restores an agent extension. A line records what boxed did, through which channel, at which level, how many placeholders of each kind, and a hash of exactly what it sent or received. It never holds the text, the values or the placeholder map. [journal-records.md](../security/journal-records.md) lists the fields.

```json
{"channel": "manual", "provider": "unknown", "account_type": "unknown", "level": 0,
 "markers_by_kind": {"SECRET": 1, "CARD": 1}, "status": "prepared",
 "payload_sha256": "ec3513f9...", "coverage": "full", "scope": "lvl0",
 "versions": {"boxed": "0.1.0"}, "note": "", "seq": 1,
 "ts": "2026-10-24T10:07:34.653669+00:00", "prev_hash": "00000000...",
 "hash": "f7b0f5d3...", "sig": "f8ea1f59..."}
```

(The real record is one line. This copy is wrapped and shortened.)

Two fields make the journal checkable:

- `hash` is the SHA-256 of the record without `hash` and `sig`, and the record holds the hash of the one before it in `prev_hash`. Changing, removing or reordering a record breaks the chain after it.
- `sig` is an Ed25519 signature of `hash`, made with a device key that boxed creates on first use and keeps in the OS keychain (`device-signing-key`). `boxed journal key` prints the matching public key.

`boxed journal verify` checks every hash, every signature and the chain. See [dashboard-and-journal.md](dashboard-and-journal.md) for the commands and for exports.

What the journal proves: this device's key wrote these records in this order, and nobody edited or removed a record before the last one. What it does not prove:

- That you sent nothing around boxed. Text you type into a chat page yourself is not in the journal.
- That nobody cut records off the end. A journal that lost its last records still verifies. Compare the record count with an earlier export.
- That the writer was honest. A program that can use your keychain entry can write valid records.

## Policy: categories and recipients

A company policy answers one question before boxed masks or sends anything: may this kind of data go to this kind of recipient, and at which level? The question is a pair.

- Categories: `secrets`, `personal`, `clients`, `finance`, `code`, `strategy`, `hr`, `health`. Detectors raise the first five. You name `strategy`, `hr` and `health`, and `finance` when the text holds no amount, with `--category`.
- Recipients: the kind of account that receives the text. `personal-training` is a personal account that may train on chats, `personal-private` a personal account with training off, `corporate` a company plan, `api-zero-retention` an API account with zero data retention, and `local` a model on your computer.
- Answers: `allow`, `masked:N` (mask at level N or higher), `local-only` or `deny`.

The profiles, the matrix, the rules you may add and the commands are in [policy.md](policy.md).

## Observation

Observation mode is off until you switch it on in the browser side panel. While it is on, the extension reads the message you send to ChatGPT, Claude, Gemini, DeepSeek or Z.ai, and the program on your computer counts what is in it: kinds and numbers, for example `EMAIL 2`. It never blocks, delays or changes a send.

It is a report to you, not protection. The text has already gone. If a key or token was in a message, revoke and replace it: masking later cannot take a send back.

The program keeps the site, the time, the kinds and counts, and a keyed hash of the text in `observed.jsonl`, a signed chain of its own that is not part of the journal export. It never keeps the text. It does not check WebSocket messages or attachments, and it lists a send it could not read as `not checked`. "Nothing found" is a best-effort answer. The details are in [browser-extension.md](browser-extension.md).

`boxed audit` is the same idea for the past: it counts what earlier Claude Code and Codex sessions saved in local session records (possible exposure to the provider). See [dashboard-and-journal.md](dashboard-and-journal.md).

## Training checks

A training check is what you tell boxed about one chat account: whether training on your chats is `on`, `off` or `unknown`, and the same for memory. boxed does not read the provider's settings page. You read the page, then record what you saw.

```bash
boxed check set --provider chatgpt --account me@acme.example --training off --memory off
boxed check list
```

```text
saved: chatgpt me@acme.example training off memory off
chatgpt  me@acme.example  training off  memory off  checked 2026-10-24 (asked)  recipient personal-private
...
```

- A check is due after more than 30 days, or while a field is `unknown`. `boxed check list` exits with code 5 while a check is due.
- Only `off` counts as `personal-private`. `on`, `unknown`, a missing check and a damaged file all count as `personal-training`, the stricter recipient.
- Nothing picks the kind up by itself. `boxed ask` and `boxed policy check` use the kind you give them (`--account`, `--recipient`), so copy it from the list.
- boxed signs `checks.json` with the device key. A file edited by hand, written by another computer or by an older boxed version reads as "training checks need to be confirmed again" until `boxed check reset`. The signature shows that boxed on this computer wrote the file. It cannot tell a current file from an older signed copy that someone put back: it gives integrity, not freshness.
- Training off does not mean the provider stores nothing. Providers still keep chats for a while.

## What boxed does not do

- Masking does not stop inference from context. Placeholders hide direct identifiers. A model can still guess who or what a text is about from the details that remain. boxed minimises data, it does not anonymise it. In GDPR terms this is pseudonymisation: while the map exists on your computer, the data stays personal data for your employer.
- Detectors miss things. boxed finds people and companies only with a name model or your dictionary. If a detector or a parser fails, boxed sends nothing.
- Observation is not protection. It reports what the browser sent without boxed, after the fact.
- The journal proves what was recorded, not that nothing was sent around boxed. boxed is not a data loss prevention tool: it does not watch you, and it does not stop text you type or paste straight into an AI website.
- Signed checks give integrity, not freshness.
- `boxed skills` judges the skills, plugins, MCP servers and hooks of your agents with rules for known attacks. `ok` does not mean safe: plain-language instructions and a new technique can pass, and MCP servers are never started to see what they do (see [skills.md](skills.md)).
- Hooks are best effort. In a masked workspace the Claude Code hooks block reads of the original project and of boxed data, but without the sandbox they can be got around. Under `boxed run` the macOS sandbox is the hard guard. Linux and Windows have none yet.
- On Windows the core commands (mask, restore, files, plans, policy, ask, keys, checks, journal, dashboard, audit) and the browser extension's host run on Windows 11; not yet: the Claude Code and Codex plugin (`workspace`, hooks, `mcp`, `install claude|codex`) and `boxed run`. See [windows.md](windows.md).
- A relay you name in `BOXED_<PROVIDER>_BASE_URL` receives the masked prompt and your API key. boxed cannot protect a key from a relay you point it at.
- boxed does not make a send lawful. Masking does not replace a legal basis for moving personal data outside the EEA. The [security team package](../security/README.md) has the data-flow description, the threat model and a DPIA template for that discussion.
