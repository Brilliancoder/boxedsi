# The record of checks is an unsigned file of plain digests

## Context

The check at the start of an agent session must say what is new or changed since the last scan, within seconds and without network.
Boxed's other signed state, such as its checks file, depends on a device key held in the system keychain.

## Decision

- What the last scan found is kept in one file in the boxed home (mode 0600), read strictly: a damaged file is an error and is never replaced by an empty record.
- The file is not signed. An item's digest is a plain SHA-256 of its content (files by relative path and bytes, config entries as canonical JSON), not a keyed hash, so no key or keychain is needed to read or write it.
- It stores digests, verdicts, times, rule ids with locations and the bookkeeping for quarantine - no values and no excerpts from the scanned material.
- Agents working in a workspace can neither read nor change it.

## Why

The record only has to answer "is this the same as last time?". Rejected:

- Sign it like the checks file. A signature needs the device key, so every session start would depend on the keychain, which can prompt or fail at the moment the person starts to work. It also buys little: code running as the same user can switch the check off outright, and agents in a workspace cannot reach the file at all.
- Key the digests, as the audit report does for its secret prefixes. Same keychain dependency, and these digests protect no secret because the record holds no values.
- The cost of this choice is small and accepted: a forged record can hide one warning.

## Consequences

- The record is a convenience, not evidence. Anything that runs as the person can edit it and boxed cannot tell, so do not build a "verified clean" claim on top of it.
- A digest is an unkeyed hash that anyone with the same content can recompute. The JSON report carries digests too; for a config entry that embeds a weak secret, a digest in a forwarded report is a way to test guesses. Treat digests as not secret.
- A damaged record stops the next scan of installed items with an error instead of starting over silently, so the person has to deal with the file.
- Because the file is read strictly, any format change needs a version bump and a reader for old files.
