# Security policy

## Status

boxed.si is **alpha** software (0.1.x). It has **not had an external security audit**. It is a privacy tool, not a guarantee: detectors miss things, and masking hides direct identifiers, not context. Read the [threat model](docs/security/threat-model.md) before you rely on it for anything that matters.

## Reporting a vulnerability

Please report privately, not in a public issue or discussion.

1. Preferred: GitHub private vulnerability reporting. Open the repository on GitHub, go to the **Security** tab and choose **Report a vulnerability**.
2. Fallback: write to `hello@boxed.si` with "boxed security" in the subject.

Include the version (`boxed --version`), the operating system, the command or channel, the steps to reproduce and what you expected. Use invented data in the reproduction. Do not send real secrets or personal data, and do not attach your `~/.boxed` folder.

## What to expect

boxed.si is maintained by a very small team. We answer on a best-effort basis, usually within a week, and will tell you if a fix will take longer. There is no bug bounty and no guaranteed fix time. We credit reporters in the changelog unless you prefer not to be named. Please give us a reasonable time to fix a problem before you publish it.

Only the latest release and the `main` branch get fixes while the project is in alpha.

## What counts as a vulnerability

- Masking bypass: sensitive data of a kind and level boxed documents as masked reaches a model, a file, a clipboard or an API request unmasked, in a way that is not just a detector that misses an unusual format (see below).
- Leak of real values: an original value, key or placeholder map appears in the journal, a report, the dashboard, an error message, a log or any output where the docs say it never does.
- Restore abuse: a model answer, a file or a placeholder can make boxed restore values it should not (for example the placeholders of another prompt or scope).
- Sandbox escape: a way for an agent under `boxed run` or in a masked workspace to read the original project, the boxed home or the keychain, to run a process outside the sandbox, or to change what runs later (agent settings, hooks), beyond what the docs list as not yet denied.
- Bypass of the extension check: `boxed skills scan` is made to rate a dangerous item `ok` by a technique the docs say it covers, or reading a hostile folder, zip or repository harms the computer.
- Journal or vault integrity: forged or silently changed journal records that `boxed journal verify` accepts, or a weakness in how the vault or signing keys are stored.
- Browser extension: it reads, changes or blocks pages or requests beyond its documented permissions, or restored text reaches a web page.

## What does not count

- A detector missing a secret or a personal value, or masking something it should not. That is a quality bug: use the "Detector report" issue form, with invented examples. If the miss shows a systematic hole in a documented guarantee, report it privately.
- Anything the docs list as a known limit: text you type into a chat yourself, context that identifies a person, hooks being best effort without the sandbox, observation mode only reporting, a relay you name receiving your masked prompt and key, memory of a running process, a program already running as you with full rights.
- Findings that need an attacker who already has control of your account or computer, or of your OS keychain.
- Reports from automated scanners without a working scenario, and denial of service by feeding a huge file to your own machine.
- Problems in a third-party AI provider, browser or operating system.

Not sure? Report it privately anyway.
