# Journal records

Every processing step and send that goes through boxed adds one line to `~/.boxed/journal.jsonl`. A record holds what was done, through which channel, at which level and with how many placeholders of each kind. It never holds the text, the values or the placeholder map.

| Field | Meaning |
|---|---|
| `seq`, `ts` | Record number and UTC time |
| `channel` | `manual`, `workspace`, `mcp`, `claude-code`, `extension`, `api` (boxed sent the text itself with an API key), `skills` (a check of agent extensions, below), `observed` (only in `observed.jsonl`, below) |
| `provider`, `account_type` | Where the content went, as far as boxed knows |
| `level` | Masking level, `-1` for a restore |
| `markers_by_kind` | Counts of placeholders, for example `{"EMAIL": 3, "SECRET": 1}` |
| `status` | `prepared`, `sent`, `received`, `blocked`, `error` |
| `payload_sha256` | SHA-256 of exactly what was sent or received, to match against provider logs |
| `coverage` | What was checked, for example `12 files masked, 2 skipped` |
| `scope` | Which placeholder map was used |
| `versions` | boxed version |
| `note` | Fixed words only: for example `restored=1 unknown=0 suspicious=0`, `policy deny`, `relay` (the request went to the address in `BOXED_<PROVIDER>_BASE_URL`), or an error such as `openai: HTTP 401 (invalid_api_key)` |
| `model`, `usage` | Only when boxed sent the text itself: the model that answered and the token counts the provider reported (`input`, `output`); for OpenRouter also `cost_micro_usd`, the cost it reported in millionths of a US dollar |
| `prev_hash`, `hash`, `sig` | Hash chain and the Ed25519 signature of `hash` |

A synthetic example:

```json
{"channel": "mcp", "provider": "client", "account_type": "unknown", "level": 2, "markers_by_kind": {"EMAIL": 1, "SECRET": 1}, "status": "sent", "payload_sha256": "9f2c...", "coverage": "file", "scope": "ws-1a2b3c4d", "versions": {"boxed": "0.1.0"}, "note": "read_masked", "seq": 42, "ts": "2026-10-20T09:15:02+00:00", "prev_hash": "77e1...", "hash": "c0a9...", "sig": "5b1e..."}
```

## API records

A prompt given to `boxed ask` leaves these records:

- `blocked`: the policy said deny or local-only. Nothing was masked or sent; `payload_sha256` is the hash of an empty text.
- `sent`: written before the request goes out, with the hash of the masked prompt, the requested `model`, the level and the placeholder counts. If it cannot be written, no request is made.
- `received`: level `-1`, the hash of the raw answer, the `model` and `usage` the provider reported, and the note `restored=N unknown=N suspicious=N`. Or `error`: the hash and level of the `sent` record and a fixed error text, never a part of what the provider replied.

## Extension check records

`boxed skills scan` of what is installed (not of a folder or an address given as a target), `boxed skills quarantine` and `boxed skills restore` each add one record in the channel `skills`. The fields are fixed: `provider` and `account_type` `local`, `level` `-1`, no markers, `status` `prepared`, `scope` `skills`. `coverage` is `full` when every item was read whole and nothing was left out, else `partial`, and the note of a scan then ends with ` incomplete=N unread=M` (items cut, places not read). `payload_sha256` is the SHA-256 of the item id, or of the sorted ids for a scan. `note` holds fixed words: `scan items=7 dangerous=2 suspicious=2`, or `quarantine` or `restore` with the kind of the item (`quarantine skill`, `restore hook`). A record holds no extension name, no path and no value from a config. The record of the last check, `skills/record.json`, is a separate file and not part of the journal; a scan writes it only after its journal record was written, so a scan the journal did not take leaves the earlier record as it was.

`boxed skills scan --ai` also leaves the `api` records of `boxed ask` for each request (`sent` and `received`, or `blocked`), with the scope `skills-<UTC time>`.

## Observation log

`~/.boxed/observed.jsonl` holds what the browser sent to ChatGPT, Claude, Gemini, DeepSeek or Z.ai without boxed, while the employee had observation switched on. It has the shape of a journal record with `channel` `observed`, the site as `provider`, `status` `sent`, `markers_by_kind` with what the detectors found, and `coverage` `checked` or `not checked` (the text could not be read, so the counts may be too low). It is a chain of its own, signed with the same device key, and it is never mixed into `journal.jsonl`. `boxed journal export` carries `journal.jsonl` only, so observation records never reach the security team unless the employee hands them over. `payload_sha256` holds an HMAC-SHA256 with a key in the OS keychain, not a bare hash: a short text, such as a prompt that is one phone number, cannot be guessed from it, and it cannot be matched against provider logs.

## Checking it

- `boxed journal verify` recomputes every hash, checks every signature and the chain, and names the first problem: an edited field, a record removed, added or moved before the last one, a damaged line or a wrong key. A line torn by a crash shows up as damaged while the chain of whole records around it still verifies; a record edited, or removed from the middle, breaks the chain.
- What `verify` cannot see: records cut off the end. The chain that is left is whole, so a journal that lost its last records, or every record, still verifies. To catch that, keep the record count or the hash of the last record from an earlier export and compare; a newer journal must hold that record, with the same hash, at the same `seq`.
- An export for the security team carries the records and the device public key, so the chain and signatures can be verified without any boxed keys.

What the journal proves: these records were written by this device's key in this order. What it does not prove: that nothing was sent around boxed.
