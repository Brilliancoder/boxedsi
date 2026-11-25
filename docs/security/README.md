# boxed.si for security teams

boxed.si runs on an employee's computer. Before work data goes to an AI service the company allows, boxed finds secrets and personal data in it, replaces them with typed placeholders such as `[EMAIL_1]` or `[SECRET_2]`, and keeps the originals on the device. The answer comes back with placeholders, and boxed puts the originals back locally.

## What leaves the computer

- Only the masked text or file the employee sends through boxed, to the AI service the employee or the company chose.
- With an API key (`boxed ask`): the masked prompt and the key, to the provider, or to the relay address the employee sets in `BOXED_<PROVIDER>_BASE_URL` (https, or http to the same computer).
- With `boxed skills scan --ai` only: the masked text of agent extension files that have findings of the rules, to the provider the employee names, through the steps of `boxed ask`. The extension check uses no other network, apart from the `git clone` of an address the employee gives as a target.
- Nothing goes to boxed.si: there are no boxed servers in the data path and no telemetry of content.

## What stays on the computer

| Item | Where | Protection |
|---|---|---|
| Originals | The project or file where they already were | Not copied anywhere |
| Placeholder map (placeholder - original) | `~/.boxed/vault.db` | AES-256-GCM, key in the OS keychain |
| Journal of processing and sends | `~/.boxed/journal.jsonl` | Hash chain, every record signed with an Ed25519 device key; no values, only kinds, counts and hashes |
| Observation log: what the browser sent without boxed | `~/.boxed/observed.jsonl` | A chain of its own, signed with the same device key; kinds, counts and a keyed hash, never the text; not part of the journal export |
| Training checks: what the employee recorded about each chat account | `~/.boxed/checks.json` | Mode 600, written through a part file; signed with the device Ed25519 key (integrity, not freshness: an older signed copy can be put back) |
| Native host errors: exception class names only, never text | `~/.boxed/host-errors.log` | Mode 600, capped at 64 KiB, refused when it is a link or has other hard links |
| API keys | OS keychain (service `boxed.si`, user `api-key:<provider>`), or the provider's environment variable | Never printed, logged or journaled |
| Masked working copies for AI agents | `~/.boxed/workspaces/` | Folder mode 0700; guarded by agent hooks and, on macOS, an OS sandbox |
| Record of the last check of agent extensions: ids, places, digests, verdicts, rule ids with file and line | `~/.boxed/skills/record.json` | Mode 600, read strictly, not signed; closed to agents in masked workspaces. No evidence text, no config values |
| Quarantine: agent extensions the employee took out of use | `~/.boxed/skills/quarantine/<id>/` | Folder mode 0700, files mode 600; can hold the `env` and header values of a config entry, and `original`, a full copy of each config file boxed edited as it was before (with the values of its other entries), until restore |

## What boxed does and what it does not

boxed is alpha software without an external security audit. What follows is how it is built and what its tests check, not a guarantee.

- In the controlled route (the masked workspace, `boxed mask`, `boxed ask`, the MCP tools, the browser side panel) boxed sends only text it has masked, unless the employee chooses level 0, and a detector or parsing error blocks the send instead of letting the text through. Masking covers what the detectors find: a value they miss leaves as it is (see the [threat model](threat-model.md)). `boxed ask` also asks the policy first: a verdict of deny or local-only sends nothing.
- Placeholders hide direct identifiers, not context. A model can sometimes still tell who or what a text is about from the remaining details. boxed is data minimisation, not anonymisation.
- Under GDPR this is pseudonymisation: while the map exists on the employee's device, the data stays personal data for the employer.
- boxed is not a DLP: it does not watch employees and does not stop text typed or pasted straight into an AI website outside boxed. Its observation mode reports only to the employee.
- Agent hooks are best effort. The hard guard for AI coding agents is the macOS sandbox (`boxed run`); Linux has no sandbox yet. On Windows 11 the core commands and the browser extension's host run; the sandbox, workspaces, the Claude Code hooks and the MCP server do not yet (see [windows.md](../guide/windows.md)).

## What you can check yourself

- The core is open source: detectors, placeholders, vault, journal, the agent plugin and the extension.
- `boxed journal verify` checks the hash chain and the signatures; a signed export with the device public key lets you verify records without any boxed keys. Records cut off the end still verify: compare the record count or the last hash with an earlier export.
- `boxed audit` shows what earlier Claude Code and Codex sessions saved in local session records (possible exposure to the provider), by kind and count, without the values.
- `boxed skills scan` reads the skills, plugins, MCP servers and hooks of the agents on the computer (or a folder or address before install), rates each `dangerous`, `suspicious` or `ok` with the reason, file and line, and can write a self-contained HTML or JSON report. It uses static rules and no network unless `--ai` is added. What it cannot do is in [the guide](../guide/skills.md); a verdict of `ok` is not a guarantee.
- `boxed dashboard` shows, apart from the journal, what the browser sent without boxed (by kind and count, when the employee turned observation on) and the training checks with the date of each; both are the employee's own report.

## In this folder

- [Data flows](data-flows.md)
- [Threat model](threat-model.md)
- [DPIA template](dpia-template.md)
- [Journal records](journal-records.md)
- [Policy clause](policy-clause.md)
