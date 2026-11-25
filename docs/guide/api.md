# API keys and `boxed ask`

If you have an API key from OpenAI, Anthropic, DeepSeek or OpenRouter, `boxed ask` sends one masked prompt through it and prints the restored answer. boxed checks the policy first, masks the prompt, writes a journal record and only then sends. The answer is restored on your computer.

What leaves your computer: the masked prompt and your key, to the provider, or to the relay address you set (see "Relays"). Nothing goes to boxed.

## Store a key

```text
$ boxed key set openai
API key for openai (input hidden):
key for openai stored in the keychain
$ boxed key status openai
set (keychain)
$ boxed key remove openai
key for openai removed from the keychain
```

- `boxed key set` reads the key at a hidden prompt on a terminal. From a pipe or a file it reads the first line of standard input. It never prints the key. A key must be 1 to 1024 visible ASCII characters without spaces, else boxed stops with `the API key must be printable ASCII without spaces`.
- The key goes to the OS keychain, service `boxed.si`, user `api-key:<provider>`. This holds even if you set `BOXED_KEYSTORE` for boxed's own keys.
- Without a keychain entry, boxed reads the provider's environment variable: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY` or `OPENROUTER_API_KEY`. The keychain wins when both exist. A keychain that cannot be read counts as empty.
- `boxed key status` prints `set (keychain)`, `set (environment)` or `not set`. It never prints the key.
- `boxed key remove` removes the keychain entry only. If the environment variable is set, boxed says so and leaves it: `note: OPENAI_API_KEY is still set in the environment`. With nothing to remove it says `no key for openai in the keychain` and exits with code 0.

## Send a prompt

```text
$ boxed ask --provider openai --model gpt-5 --scope invoice-4471 prompt.txt
boxed: sending through the relay at 127.0.0.1:18701 (BOXED_OPENAI_BASE_URL)
scope: invoice-4471
warning: personal data leaves the EEA: this needs a legal basis, masking does not replace it
Subject: Invoice 4471

Dear anna.petrova@example.com,

Thank you for your message. The delay came from db1.acme.internal, which was down on Tuesday. The invoice will be resent today.

Best regards
```

This run went to a small local server that stands in for the provider, so no real model was called. A real model answers differently. The first line appears because the test server counts as a relay (see "Relays"). A call to the provider itself prints no such line.

The prompt comes from a file. `-` or no file name reads standard input, so `pbpaste | boxed ask --provider openai --model gpt-5` works. The input must be UTF-8.

**What goes where.** Standard output gets the restored answer and nothing else, so `> answer.txt` saves only the answer. Standard error gets the relay notice, `scope:`, warnings and problems.

**What happens, in this order.** Each step comes before the next:

1. The policy decides. If it says deny or local-only, boxed stops: nothing is masked or sent.
2. boxed masks the prompt.
3. boxed writes a `sent` record to the journal. If it cannot, nothing is sent.
4. boxed makes one request. There is no streaming and no conversation history: one prompt, one answer.
5. boxed restores the answer and writes a `received` record.

**Options.**

| Option | Meaning |
|---|---|
| `--provider` | `openai`, `anthropic`, `deepseek` or `openrouter`. Required. |
| `--model` | The model name, passed on as you write it. boxed does not check that it exists. It must start with a letter, a digit or `~`, and may hold letters, digits and `. _ : / @ + ~ -`, up to 128 characters, else boxed stops with `bad model name`. Required. |
| `--account` | The kind of account the key belongs to. See "Accounts". |
| `--category` | A kind of data the text holds. See "Policy". Repeatable. |
| `--level` | The masking level you ask for, instead of `level` in `boxed.toml`. The policy can raise it, never lower it. See "Policy". |
| `--scope` | A name for the set of placeholders. The default is `ask-<UTC date and time>`. The same scope gives the same value the same placeholder in several prompts. |

An answer gets back only the placeholders of its own prompt, even if the scope holds more from earlier prompts. Text from the network cannot ask boxed to restore anything else.

On a terminal, control characters in the answer other than the line feed and the tab are shown escaped, for example `\x1b`. An answer cannot then move the cursor, change the window title or write to the clipboard. Into a pipe or a file the answer goes exactly as it came.

## Providers

| Provider | API | Address | Default account | Jurisdiction | Environment variable |
|---|---|---|---|---|---|
| `openai` | Responses, sent with `store: false` | `https://api.openai.com/v1` | `personal-private` | US | `OPENAI_API_KEY` |
| `anthropic` | Messages, `max_tokens` 4096 | `https://api.anthropic.com/v1` | `personal-private` | US | `ANTHROPIC_API_KEY` |
| `deepseek` | Chat completions | `https://api.deepseek.com` | `personal-training` | CN | `DEEPSEEK_API_KEY` |
| `openrouter` | Chat completions | `https://openrouter.ai/api/v1` | `personal-training` | US | `OPENROUTER_API_KEY` |

- With `store: false` OpenAI does not store the response for later retrieval. OpenAI may still keep abuse-monitoring logs for up to 30 days.
- The Anthropic request asks for at most 4096 tokens. A longer answer is cut off, and boxed says so (see "Exit codes").
- One request has one deadline of 120 seconds for connecting, waiting and reading. boxed refuses an answer over 10 MiB.
- boxed never follows a redirect, so the key stays with the address you set.

## Accounts

`--account` names the kind of account the key belongs to:

| Account | Meaning |
|---|---|
| `personal-training` | A personal account that may train on your data. |
| `personal-private` | A personal account with training off. |
| `corporate` | A company plan. |
| `api-zero-retention` | An API account with an agreement that nothing is kept. |

Without `--account`, OpenAI and Anthropic count as `personal-private`. DeepSeek and OpenRouter count as `personal-training`, the stricter kind, because they may log or train on API traffic.

`--account` is what you tell boxed. boxed does not check it, and it does not read your provider settings. The kind decides which policy rule applies (see [policy.md](policy.md)). Do not claim `api-zero-retention` or `corporate` unless your account has that agreement. For OpenAI and Anthropic, zero retention is an agreement on your account, and boxed cannot ask for it in a request.

The training checks (`boxed check list`, see [browser-extension.md](browser-extension.md)) show the kind that each chat account counts as, but nothing in `ask` picks it up. Copy it into `--account` yourself.

## Policy, categories and levels

The policy decides before anything is masked. The company profile and the rules in `boxed.toml` combine a data category with the account kind into a verdict: allow, masked at level N or higher, local only, or deny. Profiles and rules are in [policy.md](policy.md). When the verdict is `deny` or `local-only`, `ask` stops with exit code 4:

```text
$ boxed ask --provider openai --model gpt-5 --category hr prompt.txt
boxed: blocked by policy: local-only
reason: secrets for personal-private: masked at level 0
reason: personal for personal-private: masked at level 1
reason: hr for personal-private: local only
warning: personal data leaves the EEA: this needs a legal basis, masking does not replace it
```

This run used a `boxed.toml` with this policy:

```toml
[boxed.policy]
profile = "no-confidential"
```

boxed writes a `blocked` record and sends nothing. The same text on a company plan passes, masked at level 3:

```text
$ boxed ask --provider openai --model gpt-5 --account corporate --category hr prompt.txt
boxed: sending through the relay at 127.0.0.1:18701 (BOXED_OPENAI_BASE_URL)
scope: ask-20261024T103003
warning: personal data leaves the EEA: this needs a legal basis, masking does not replace it
Subject: Invoice 4471
...
```

**`--category`.** The detectors find secrets, personal data, clients and code, and an amount counts as finance. Strategy, HR and health have no detector, and finance data without an amount has none either. When your text holds them, name them: `--category finance`, `--category strategy`, `--category hr` or `--category health`. Repeat the option for more than one. `boxed policy check` takes the same option.

**`--level N`.** `--level` sets the level you ask for, instead of the `level` in `boxed.toml` (2 if unset). The policy can raise it to its own minimum, and nothing lowers it below that minimum. So `--level 0` can mask less than your usual level, and never less than the policy needs. Levels 0 to 3 work. Level 4 sends the task and the table schema only, which `boxed plan` builds (see [tables.md](tables.md)). `ask` refuses it, also from `level = 4` in `boxed.toml`:

```text
$ boxed ask --provider openai --model gpt-5 --level 4 prompt.txt
boxed: error: level 4 sends the task and the table schema only: use boxed plan, or ask at a level from 0 to 3
```

A policy rule that needs level 4 blocks `ask` with exit code 4. Use `boxed plan` for such data.

## OpenRouter and zero retention

Every OpenRouter request asks for providers that neither keep nor train on the data (`data_collection: deny`). With `--account api-zero-retention` it also asks for endpoints with zero data retention only (`zdr: true`). The request also asks OpenRouter to report usage:

```text
"provider": {"data_collection": "deny", "zdr": true}, "usage": {"include": true}
```

OpenRouter reports what each call cost. boxed keeps it in the journal in millionths of a US dollar, next to the token counts:

```text
"usage": {"input": 63, "output": 45, "cost_micro_usd": 412}
```

`boxed dashboard` shows the sum as "Spend reported by the provider". Calls that report no cost are not in that sum, so it is not your whole spend. The request fields come from OpenRouter's public documentation and have not been tried on a live call.

## Relays

`BOXED_OPENAI_BASE_URL`, `BOXED_ANTHROPIC_BASE_URL`, `BOXED_DEEPSEEK_BASE_URL` and `BOXED_OPENROUTER_BASE_URL` send the request to your address instead of the provider's. Use one for a gateway or proxy that you run or trust.

- The address must be `https`, or `http` to this computer. It must have no login, query or fragment, not even an empty `?` or `#`, and only visible ASCII. Otherwise boxed stops before it records anything:

  ```text
  boxed: error: BOXED_OPENAI_BASE_URL must be an https address (or http on this computer) without a login, query or fragment
  ```

- The masked prompt and your key go to the relay. boxed cannot protect a key from a relay you point it at.
- boxed says so on standard error when it sends: `boxed: sending through the relay at <host> (BOXED_<PROVIDER>_BASE_URL)`. The journal marks the `sent` record with the note `relay`.
- An address on this computer is never handed to a proxy. A remote one follows `HTTPS_PROXY`.

## Exit codes

| Code | Meaning | Example |
|---|---|---|
| 0 | Done. | |
| 1 | The call failed. | `boxed: openai: HTTP 401 (invalid_api_key)` |
| 2 | An error before the call: no key, a bad argument, an unreadable file. | `boxed: no API key for openai: run boxed key set openai` |
| 3 | The answer holds placeholders boxed could not restore. | `not restored, check by hand: [EMAIL_9]` |
| 4 | The policy blocks the send. | `boxed: blocked by policy: local-only` |

With exit code 3 boxed prints the answer anyway, with the unknown placeholders in it. You paid for it, and the text may still be useful. Check by hand before you use it.

```text
$ boxed ask --provider openai --model gpt-5 prompt.txt
...
not restored, check by hand: [EMAIL_9]
Subject: Invoice 4471

Dear anna.petrova@example.com,
...
Cc: [EMAIL_9]
```

When the provider stops an answer early, boxed prints the cut-off answer with a warning and exits with code 0: `warning: the answer was cut off: the provider stopped it before the end`.

**Error texts.** An error names the provider, the HTTP status and one word from a fixed list. It never quotes the provider's message, because that can echo your prompt or your key. The words are `authentication_error`, `invalid_api_key`, `invalid_request_error`, `permission_error`, `not_found_error`, `model_not_found`, `rate_limit_error`, `rate_limit_exceeded`, `insufficient_quota`, `billing_error`, `context_length_exceeded`, `request_too_large`, `api_error`, `server_error`, `overloaded_error`, `service_unavailable` and `timeout_error`. Other failures use short fixed texts:

| Text | Meaning |
|---|---|
| `openai: network error` | The connection failed. |
| `openai: timed out` | No answer within 120 seconds. |
| `openai: answer too large` | The answer is over 10 MiB. |
| `openai: the model refused to answer` | The provider reports a refusal. |
| `openai: the answer was filtered` | The provider's content filter stopped the answer. |
| `openai: the provider reported an error (rate_limit_error)` | An error object came with HTTP 200. |
| `openai: malformed answer` | The answer is not the shape the API promises. |
| `openai: the answer cannot be restored` | The answer broke the restore step. |

An error after the `sent` record writes an `error` record with the same fixed text.

## What the journal records

Each `ask` leaves records in `journal.jsonl` (channel `api`). They hold kinds, counts, hashes and names, never the prompt, the answer or the key.

- `blocked`: the policy said deny or local-only, or it asked for level 4 (the note then says `policy masked at level 4: use boxed plan`). Nothing was masked or sent. The hash is that of an empty text, and the counts are what the detectors found.
- `sent`: written before the request goes out. It has the hash of the masked prompt, the model you asked for, the level, the placeholder counts and the account kind. A relay adds the note `relay`.
- `received`: the hash of the raw answer, the model and token counts the provider reported, the OpenRouter cost, and a note such as `restored=2 unknown=0 suspicious=0`.
- `error`: the call failed. It has the fixed error text.

`boxed journal show --last 3` prints the newest records. The full list of fields is in [../security/journal-records.md](../security/journal-records.md). Reading, verifying and exporting the journal is in [dashboard-and-journal.md](dashboard-and-journal.md).

## Limits

- **Masking does not stop inference from context.** The provider can still guess who or what the text is about from what remains. Names and companies are found only with a name model (see [install.md](install.md)).
- **The provider keeps what it receives, under its terms.** Training off does not mean nothing is stored.
- **The key goes to whoever receives the request.** That is the provider, or the relay you name.
- **boxed does not verify your account.** `--account` is a claim. The policy trusts it.
- **One prompt per call.** No streaming, no history, no system prompt, no tools, no files. For a file, see [files.md](files.md).
- **The journal proves what boxed recorded.** It does not prove that nothing was sent around boxed.
