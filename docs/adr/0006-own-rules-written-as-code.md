# The rules are written by this project, as code

## Context

Other open scanners publish rule sets for malicious agent extensions, but this repository is Apache-2.0 with a core meant to be open.
The desktop app ships a sidecar frozen with PyInstaller, and the build collects no data files.

## Decision

- The rule catalog is written from scratch by this project. Ideas from other scanners and from published research are used freely; their rule files are not copied or adapted.
- Rules live in Python modules, never in JSON, TOML or other data files.
- A rules version is bumped whenever any rule changes, and the record keeps the version that produced each verdict.

## Why

Rejected:

- Copy or vendor the rule files of other scanners. It gives a head start on patterns, but each file carries its own license, and shipping them in an open core means license review and a NOTICE entry for every one. The head start is not worth that: what to look for is public knowledge, and the real work is writing each rule against this project's attack classes and testing it against a legitimate look-alike.
- Keep rules in data files so they can be edited or updated without touching code. The frozen sidecar's build collects no data files, so such a catalog would be silently missing from the app.

## Consequences

- Rules change only with a release; there is no live rule feed.
- Outside contributors cannot hand in someone else's ruleset; coverage grows as fast as rules are written and tested.
- Reviewing a rule means reading code, patterns and thresholds included, rather than a table.
- A stored verdict is only as current as the rules version that produced it.
