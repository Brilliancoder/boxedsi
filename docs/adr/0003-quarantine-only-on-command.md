# Quarantine happens only on the person's command and can be undone

## Context

Showing findings alone was judged not enough, but findings are heuristics: the rules are meant not to call plausible legitimate look-alikes dangerous (an installer script, a skill that reads the credentials of its own cloud, a formatter hook), and they can still be wrong.

## Decision

- Boxed takes an item out of an agent's reach only when the person runs `boxed skills quarantine` for it, and brings it back only on `boxed skills restore`. No scan, no model result and no notice at the start of a session quarantines anything by itself.
- Each kind of item is taken out in its own reversible way, and restore returns the item to the state it had before.
- Whatever is cut out of a config is kept, with its values, only in a file with mode 0600 in the boxed home. Values never reach the journal, the record or any output.
- When a safe edit is not possible - the file does not parse, or it changed during the edit - the command refuses with the reason and a manual step. A second quarantine, or a restore onto an occupied place, is refused without loss.
- Warnings only inform. Boxed does not block the install of unchecked items.

## Why

A wrong verdict must cost the person one command, never their data or their working setup. Rejected:

- Quarantine automatically, at scan time or at session start. The product owner ruled it out when the work was scoped, and the reason holds: a wrong verdict would silently switch off something the person depends on, in another tool's files, while they are busy with something else.
- Block the install of unchecked items. Report, quarantine and warning were chosen instead. The check at the start of a session has no network and only knows that an item is new or changed, not that it is bad; blocking on that would stop work for every harmless newcomer.
- Removal that cannot be undone. Simpler, and no copy of config values would sit on disk, but it turns every wrong verdict into data loss.
- One mechanism for every kind, such as always moving files. Many items are entries inside a shared config, not folders, so there is nothing to move; each kind needs its own undo.

## Consequences

- A dangerous item stays active until the person acts. The warning repeats; nothing else happens.
- Every new kind of item or agent adds another undo to write, test and keep correct, and a bug in one is a bug in someone's agent configuration.
- Some cases end in a refusal and a manual step, for example an item declared inside a plugin ("quarantine the plugin instead").
- If another program changes the same config file between quarantine and restore, restore puts the entry back by parsing, not by rewriting the old bytes: the file ends up equivalent, not byte-identical.
- While an item is quarantined, a second copy of its config values sits on disk in the boxed home, so keeping that folder out of reach of agents in a workspace matters.
