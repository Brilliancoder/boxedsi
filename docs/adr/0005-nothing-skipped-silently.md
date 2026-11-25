# What the scan cannot check is reported, not passed over

## Context

Known attacks hide the payload where scanners stop looking: after a very long run of blank lines, inside base64, in invisible Unicode tag characters, in binaries and archives.

## Decision

- Every file is read whole, whatever its size. Large input is streamed, never truncated.
- Long base64 runs and hidden Unicode tag text are decoded and checked again.
- What cannot be inspected is reported, never dropped: binaries and compiled files (recognised by their signature, not their name), archives and Office documents, links that leave the item, unreadable files, and any limit the scan runs into. An encrypted archive is critical.

## Why

Each shortcut below is a bypass the attacker can build in on purpose. Rejected:

- Cut files at a size limit. Fast, but the attacker pads with blank lines until the payload sits past the cut; a test sample puts it after 100,000 blank lines.
- Skip binaries, archives and anything that does not parse. A silent skip is a free hiding place: ship the payload as a compiled file or a zip.
- Stop quietly at a file-count or size limit. The same hole, opened by making the tree big enough, so a limit is itself reported.

## Consequences

- Legitimate items that bundle binaries, compiled files or archives always show findings for them, and the person has to read their capabilities to judge them.
- Reading everything is paid for in time: a tree of 3,000 files must scan in 15 seconds, so every new rule has to stay cheap. For very large texts the rules look around trigger words instead of at every byte, and an extremely long line is reported on its own. "Read whole" is a promise about the input, not about every rule seeing every byte.
- An item over a limit is reported as such instead of being half-scanned in silence, so a huge but harmless tree gets flagged.
- An unreadable file stays reported until the person fixes its permission or removes it; the scan cannot resolve it.
