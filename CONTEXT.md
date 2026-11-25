# boxed.si

Masks secrets and personal data before text reaches an AI model and restores the answer locally.
It also scans what AI agents load - skills, plugins, MCP servers, hooks - for malicious behaviour.

## Language

**Item**:
One thing an agent can load or run, judged on its own: a skill, plugin, MCP server, hook, subagent, slash command, output style, prompt, or a setting that runs a command or redirects traffic. Together these are the agents' extensions; the skills command covers them all.
_Avoid_: skill, element

**Agent**:
A program that works with an AI model on the person's behalf and loads items, such as Claude Code or Codex. A subagent definition is an item, not an agent in this sense.
_Avoid_: tool, client, assistant

**Scope**:
Where an item lives: user (the person's own), project (in a project folder), local (the person's private setting for one project) or target (only named for a scan). Masking has its own scopes, named groups of markers - a different thing.
_Avoid_: level, layer

**Target**:
What the person names to be scanned before installing it: a folder, file, zip, git address or owner/repo. Scanning a target never changes the record.
_Avoid_: source, candidate, input

**Finding**:
One problem reported about an item: the rule that fired (or that a model flagged it), how severe, where, a short excerpt as evidence with secrets masked, and what to do. A masking detection is a different thing.
_Avoid_: alert, issue, hit

**Verdict**:
The overall call on one item: dangerous if any finding is critical, suspicious if any is high or medium, otherwise ok. Low and info findings are shown but do not move it.
_Avoid_: score, risk level, status

**Capability**:
What an item is able to do - run commands, use the network, read places that hold secrets - listed so a powerful but legitimate item can be understood, not only feared. It says what is possible, not that something is wrong.
_Avoid_: permission, privilege

**Record**:
Boxed's memory of the last scan: per item a digest, a verdict and where findings were, plus what is in quarantine. It holds no values and no excerpts. Not the journal.
_Avoid_: baseline, scan history, state file

**Quarantine**:
Taking one item out of an agent's reach, only when the person asks, in a way that restore undoes. Restoring an item is unrelated to restoring hidden values in a model's answer.
_Avoid_: disable, remove, block

**Marker**:
The stand-in written in place of a hidden value, such as `[EMAIL_1]`. Boxed remembers locally which value stands behind it, so an answer can be restored.
_Avoid_: placeholder, token

**Level**:
How much boxed hides before text leaves: 0 secrets and keys, 1 adds personal data, 2 adds web addresses, hosts and organizations, 3 adds amounts, dates and numbers. Level 4 is for plans and never used for masking.
_Avoid_: severity, strictness

**Workspace**:
A copy of a project folder that boxed creates and syncs, in which an agent sees markers instead of secrets and personal data. Not the confinement that `boxed run` provides.
_Avoid_: mirror, masked copy, sandbox

**Boxed home**:
The private folder where boxed keeps its own state: journal, record, quarantined items and the map from markers back to hidden values. Not the person's home folder.
_Avoid_: data folder, config directory

**Journal**:
A signed, hash-chained history of what boxed did: masking, sends to models, scans, quarantine. It holds kinds, counts, hashes and fixed words, never text, values or paths. Not the record.
_Avoid_: log, audit log
