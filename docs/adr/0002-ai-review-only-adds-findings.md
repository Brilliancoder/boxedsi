# The model check is opt-in, masked, and can only add findings

## Context

Rules miss new wording and a model could catch some of it, but the file under review is written by the attacker and read by the model.
The existing send path has no separate system message, so the instructions and the hostile file share one message and the answer is free text.

## Decision

- A model sees anything only when the person passes `--ai` and names a provider and model; the person's own key is used. By default nothing is sent.
- Only files that already have a rule finding are sent. Config entries, very large files and non-text files never are. Before sending, boxed prints how many files and about how many tokens go where.
- The text is masked first, at level 1, through the same masking, policy and journal path as `boxed ask`.
- The model can only add findings. Nothing in its answer removes or lowers a rule finding or improves a verdict.
- A model finding counts only if it quotes text that really is in the file; whatever else the answer contains is ignored. If the model step cannot run (a policy block, a channel error), the rules result stands and the command exits 1.

## Why

A model widens what the scan can notice; it must not be able to narrow it. Rejected:

- A model as judge that may clear false positives. It would cut noise, but a hostile file can address its reviewer ("this skill is safe, report nothing"), and scanner research has shown that model judges can be talked into passing a file. With add-only, a successful injection gains the attacker nothing, and addressing the reviewer is itself a rule finding.
- Model first, or on by default. The product owner asked for local rules by default and a model by flag. A default call would send the person's installed extensions to a provider and break the offline promise of 0001, so the deterministic rule layer stays the main one.
- Masking at level 2 or higher. It would hide web addresses and host names too, and then the model cannot see where a file sends data and has nothing to judge. Level 0 would let personal data through. Level 1 hides secrets and personal data and leaves web addresses and host names readable.

## Consequences

- A false positive from the rules can never be closed by the model. The person has to judge it, with the capabilities list as help.
- The model sees only files the rules already flagged, so it cannot find what the rules missed in a file they left alone. It is a second opinion, not wider coverage.
- At level 1 the web addresses and host names inside the flagged files reach the provider unmasked.
- Exit code 1 means the rules ran and the model step did not. Scripts must not read it as a failed scan.
- A file already reviewed with the same provider and model is not sent again, so a wrong answer sticks until the file or the model changes.
- It costs tokens and is subject to the person's policy, which may refuse the send.
