# Policy

A policy decides what may go to which kind of recipient, before boxed masks or sends anything. You choose a profile in `boxed.toml`, and you may add stricter rules. `boxed policy check` shows the verdict for a text, and `boxed ask` obeys it.

## Where the policy applies

- `boxed ask` decides first. A verdict of `deny` or `local-only` stops the send: boxed masks and sends nothing, and the journal gets a `blocked` record. A verdict of `masked` raises the level to at least what the policy needs.
- `boxed skills scan --ai` asks the policy in the same way before it hands any file to a model (see [skills.md](skills.md)). A verdict of `deny` or `local-only` for that provider sends nothing, the AI check does not run and the command exits with code 1; the report of the rules is printed as usual.
- `boxed policy check` prints the verdict and changes nothing.
- The dashboard shows the policy matrix next to the journal.
- Nothing else asks the policy: not `mask`, `mask-file`, the masked workspace, the MCP tools, `boxed plan` or the browser panel. In those channels you choose the level. Use `boxed policy check` to see what your profile asks for.

The profile is a line in a file on your computer. boxed applies it to your own commands. It does not protect the policy from you: you can edit the file. A rule can only be stricter than the profile, but you choose the profile. There is no central administration in this version.

## Categories, recipients and verdicts

The policy answers for a pair: a data category and a recipient kind.

Detectors put a category on a text when they find one of its kinds:

| Category | Found when the text holds |
|---|---|
| `secrets` | `SECRET`, `PRIVATE_KEY`, `JWT`, `CARD` |
| `personal` | `EMAIL`, `PHONE`, `PERSON`, `INN`, `SNILS`, `IBAN`, `PASSPORT`, `SSN` |
| `clients` | `ORG`, `VAT_ID`, and any term of your dictionary, whatever kind you gave it |
| `finance` | `MONEY`, an amount with a currency, and `CRYPTO_ADDR`, a Bitcoin or Ethereum address |
| `code` | `HOST`, `URL`, `IP` |
| `strategy`, `hr`, `health` | Nothing: no detector exists. You name them with `--category` |

`PERCENT`, `DATE` and `NUMBER` put no category on a text. Finance data without an amount has no detector either, so name it with `--category finance`. `--category` takes `finance`, `strategy`, `hr` or `health`, and you can repeat it. `PERSON` and `ORG` appear only with a name model; see [concepts.md](concepts.md).

The recipient kind says what happens to the text on the other side:

| Recipient kind | Meaning |
|---|---|
| `personal-training` | A personal account that may train on chats |
| `personal-private` | A personal account with training off |
| `corporate` | A company plan |
| `api-zero-retention` | An API account with zero data retention |
| `local` | A model on your computer |

Each pair has one rule. The answers:

| Rule | Meaning |
|---|---|
| `allow` | Send as it is |
| `masked:N` | Send only after masking at level N or higher (N is 0 to 4) |
| `local-only` | Do not send to a remote recipient |
| `deny` | Do not send |

When a text holds several categories, the strictest rule wins. From loosest to strictest: `allow`, `masked:0` up to `masked:4`, `local-only`, `deny`.

## Profiles

Set the profile in `boxed.toml`:

```toml
[boxed.policy]
profile = "no-confidential"
```

Without a `[boxed.policy]` table the profile is `no-rules`. The `local` column is `allow` in every profile.

| Profile | Meaning |
|---|---|
| `no-rules` | The employer has set nothing. Personal accounts get masked data; company and API accounts get everything except unmasked secrets |
| `no-confidential` | AI is allowed, but not with confidential data. Secrets, personal data, clients, finance and strategy are masked for every account; HR and health data stay local on personal accounts; code is open except on accounts that train on chats |
| `approved-only` | Only approved tools. Personal accounts get nothing, except code masked at level 2; company and API accounts get masked data |
| `ban` | Nothing goes to any remote recipient, even a text with nothing sensitive in it |

The rules of each profile:

### no-rules

| Category | personal-training | personal-private | corporate | api-zero-retention |
|---|---|---|---|---|
| secrets | `masked:0` | `masked:0` | `masked:0` | `masked:0` |
| personal | `masked:1` | `masked:1` | `allow` | `allow` |
| clients | `masked:2` | `masked:2` | `allow` | `allow` |
| finance | `masked:3` | `masked:3` | `allow` | `allow` |
| code | `allow` | `allow` | `allow` | `allow` |
| strategy | `masked:3` | `masked:3` | `allow` | `allow` |
| hr | `masked:3` | `masked:3` | `allow` | `allow` |
| health | `masked:3` | `masked:3` | `allow` | `allow` |

### no-confidential

| Category | personal-training | personal-private | corporate | api-zero-retention |
|---|---|---|---|---|
| secrets | `masked:0` | `masked:0` | `masked:0` | `masked:0` |
| personal | `masked:1` | `masked:1` | `masked:1` | `masked:1` |
| clients | `masked:2` | `masked:2` | `masked:2` | `masked:2` |
| finance | `masked:3` | `masked:3` | `masked:3` | `masked:3` |
| code | `masked:2` | `allow` | `allow` | `allow` |
| strategy | `masked:3` | `masked:3` | `masked:3` | `masked:3` |
| hr | `local-only` | `local-only` | `masked:3` | `masked:3` |
| health | `local-only` | `local-only` | `masked:3` | `masked:3` |

### approved-only

| Category | personal-training | personal-private | corporate | api-zero-retention |
|---|---|---|---|---|
| secrets | `deny` | `deny` | `masked:0` | `masked:0` |
| personal | `deny` | `deny` | `masked:1` | `masked:1` |
| clients | `deny` | `deny` | `masked:2` | `masked:2` |
| finance | `deny` | `deny` | `masked:3` | `masked:3` |
| code | `masked:2` | `masked:2` | `allow` | `allow` |
| strategy | `deny` | `deny` | `masked:3` | `masked:3` |
| hr | `deny` | `deny` | `masked:3` | `masked:3` |
| health | `deny` | `deny` | `masked:3` | `masked:3` |

### ban

Every category is `deny` for `personal-training`, `personal-private`, `corporate` and `api-zero-retention`. Under `ban` boxed denies a text with nothing sensitive in it as well:

```text
verdict: deny
categories: none found
reason: all categories for corporate: denied
```

## Check a text

```bash
boxed policy check --recipient provider:kind:jurisdiction [--category NAME] [file]
```

`--recipient` is the provider, the recipient kind and the jurisdiction, separated by colons. The provider is a label for you. The kind must be one of the five above. The jurisdiction is a country code such as `US`, `FR` or `CN`; it decides the warnings. The text comes from the file, or from standard input when you give none.

The file `sample.txt` is the text from [concepts.md](concepts.md): it holds an e-mail address, a phone number, an internal host, an IP address, an AWS example key, an amount and a card number. With no `boxed.toml`, the profile is `no-rules`:

```bash
boxed policy check --recipient openai:personal-private:US sample.txt
```

```text
verdict: masked (level 3 or higher)
categories: code, finance, personal, secrets
reason: secrets for personal-private: masked at level 0
reason: personal for personal-private: masked at level 1
reason: finance for personal-private: masked at level 3
warning: personal data leaves the EEA: this needs a legal basis, masking does not replace it
```

The same text for a company plan asks for much less:

```bash
boxed policy check --recipient openai:corporate:US sample.txt
```

```text
verdict: masked (level 0 or higher)
categories: code, finance, personal, secrets
reason: secrets for corporate: masked at level 0
warning: personal data leaves the EEA: this needs a legal basis, masking does not replace it
```

For a local model the answer is `allow`:

```bash
boxed policy check --recipient local:local:local sample.txt
```

```text
verdict: allow
categories: code, finance, personal, secrets
```

The exit code is 0 for `allow` and `masked`, and 4 for `deny` and `local-only`: the text must not go to that recipient. A wrong `--recipient` is an error with exit code 2.

Text that no detector can recognise needs a name. This sentence holds finance and HR matter, but no pattern, so the check finds nothing until you add the categories (the profile here is `no-confidential`):

```bash
boxed policy check --recipient openai:personal-private:US words.txt
```

```text
verdict: allow
categories: none found
```

```bash
boxed policy check --recipient openai:personal-private:US --category finance --category hr words.txt
```

```text
verdict: local-only
categories: finance, hr
reason: finance for personal-private: masked at level 3
reason: hr for personal-private: local only
warning: personal data leaves the EEA: this needs a legal basis, masking does not replace it
```

(The file `words.txt` holds `Our margin fell last quarter.`)

## Add rules

A rule names a category and a recipient kind, and gives the answer. Put the rules in `[boxed.policy.rules]`. The key needs quotes because of the colon.

```toml
[boxed.policy]
profile = "no-confidential"

[boxed.policy.rules]
"finance:corporate" = "masked:3"
"code:personal-private" = "deny"
```

A rule can only make a pair stricter than the profile. A looser rule is an error, and so is a typo, in every command that reads `boxed.toml`:

```text
boxed: error: [boxed.policy.rules] secrets:corporate: allow is looser than masked:0, a policy can only be tightened
boxed: error: unknown profile, expected one of no-rules, no-confidential, approved-only, ban
boxed: error: [boxed.policy.rules] a key is not <category>:<recipient> with category in secrets, personal, clients, finance, code, strategy, hr, health and recipient in personal-training, personal-private, corporate, api-zero-retention, local
boxed: error: [boxed.policy.rules] a bad rule, expected allow, masked:0-4, local-only or deny
boxed: error: [boxed.policy.rules] masked needs a level 0-4
boxed: error: [boxed.policy] has a key boxed does not know; the known ones are profile, rules
```

(The first one comes from the profile `approved-only` with the rule `"secrets:corporate" = "allow"`: a key and rules that boxed knows are named. A key or a rule it does not know is not quoted, nor is the path of the file: find the line in `[boxed.policy.rules]` yourself.) The other `boxed.toml` errors are in [troubleshooting.md](troubleshooting.md).

With the rules from the example above, `sample.txt` gets a different answer for a personal account:

```bash
boxed policy check --recipient openai:personal-private:US sample.txt
```

```text
verdict: deny
categories: code, finance, personal, secrets
reason: secrets for personal-private: masked at level 0
reason: personal for personal-private: masked at level 1
reason: finance for personal-private: masked at level 3
reason: code for personal-private: denied
warning: personal data leaves the EEA: this needs a legal basis, masking does not replace it
```

The exit code is 4.

## What boxed ask does with the verdict

`boxed ask` looks at the text with the widest detector, whatever level you ask for, then asks the policy. The recipient is the provider and the account kind. With `--account` you name the kind of account the key belongs to. Without it, OpenAI and Anthropic count as `personal-private`, and DeepSeek and OpenRouter as `personal-training`, the stricter kind, because they may log or train on API traffic. The jurisdiction comes from the provider: `US` for OpenAI, Anthropic and OpenRouter, `CN` for DeepSeek.

- `deny` or `local-only`: boxed masks and sends nothing. The message and the reasons go to stderr, the journal gets a `blocked` record, and the exit code is 4.

  ```bash
  boxed ask --provider openai --model gpt-5 sample.txt
  ```

  ```text
  boxed: blocked by policy: deny
  reason: secrets for personal-private: masked at level 0
  reason: personal for personal-private: masked at level 1
  reason: finance for personal-private: masked at level 3
  reason: code for personal-private: denied
  warning: personal data leaves the EEA: this needs a legal basis, masking does not replace it
  ```

- `masked:N`: boxed masks at the higher of your level and N. `--level` can raise the level, never lower it. A text that holds an amount, sent from a personal account under `no-rules`, goes out at level 3 even with `--level 0`: the `sent` record in the journal says `"level": 3`.
- `allow`: boxed masks at your level.
- A rule of `masked:4` blocks `ask`, because level 4 is the task and the table schema only. The message points to `boxed plan` and the exit code is 4. `boxed policy check` still prints `masked (level 4 or higher)` with exit code 0.

  ```text
  boxed: blocked by policy: masked: the policy asks for level 4, which sends the task and the table schema only: use boxed plan
  reason: personal for personal-private: masked at level 1
  reason: finance for personal-private: masked at level 4
  warning: personal data leaves the EEA: this needs a legal basis, masking does not replace it
  ```

Warnings appear as `warning: ...` lines, on stdout for `boxed policy check` and on stderr for `boxed ask`. They come in this order:

| Warning | When |
|---|---|
| `personal data leaves the EEA: this needs a legal basis, masking does not replace it` | The categories hold `personal`, `hr` or `health`, and the jurisdiction is not in the EEA. The EEA list is the EU states plus Iceland, Liechtenstein and Norway (the codes `EU` and `EEA` count too). A `local` recipient with the jurisdiction `local` never triggers it |
| `this account may train on chats` | The recipient kind is `personal-training` |
| `data is stored in China` | The jurisdiction is `CN` |

The EEA warning is a reminder. Masking hides direct identifiers, and it does not replace a legal basis for moving personal data out of the EEA.

## Limits

- The categories come from detectors. A detector that misses a value also misses its category. `strategy`, `hr` and `health` exist only when you name them.
- The account kind is your word. `boxed check list` shows the kind each chat account counts as, but nothing passes it to `boxed ask` or `boxed policy check` by itself: you copy it into `--account` or `--recipient`.
- The policy covers `boxed ask` and the `--ai` look of `boxed skills scan`. In the masked workspace, with the manual commands and in the browser panel, the policy does not stop anything.
- The matrix is a default, not legal advice. Your employer's rules may differ; the clause for them is in [policy-clause.md](../security/policy-clause.md).
