# The scan only reads, and stays offline unless asked

## Context

Skills, plugins and MCP servers come from other people's repositories, so every file and config entry the scan opens is hostile input.
Boxed works locally by design, and the scan has to be safe to run on exactly the material it distrusts.

## Decision

- The scan reads files and config entries and never runs them. Nothing from the scanned material is executed, imported, sourced or evaluated, and links inside an item are recorded but not followed.
- It judges what is on disk. It does not start an MCP server to ask which tools it offers.
- Without `--ai` the scan opens no network connection. The one exception is fetching a git address the person typed, to scan it before installing: https only, shallow, no submodules or large-file content, the person's git configuration ignored, with a timeout, into a private temporary folder that is deleted afterwards.
- `--ai` is the other door; see 0002.

## Why

Reading gives what is scanned the least power over the scanner (very large input can still slow it down), and it is the only mode that works offline. Rejected:

- Start each MCP server and read its live tool list. It would show what a server claims to do, but starting a server is running unchecked code, which is exactly what the scan exists to catch. The config and the files on disk are checked instead.
- Look items up by hash or name in a public reputation service. Cheap, and it would flag known-bad items, but it tells a third party what the person has installed, and boxed is local by design. It stays a possible later option, only with explicit consent.
- Follow links so the scan covers whatever an agent would reach through them. A link in hostile content can point anywhere on the machine, so following it lets the item decide what the scanner reads. A link that leaves its item is reported instead.

## Consequences

- Behaviour that exists only at run time is invisible: a server whose tools or code come from elsewhere is judged by its config and local files alone.
- There is no reputation signal, so a freshly published malicious item that looks plain on disk is caught only by the rules and the optional model check.
- "No network without --ai" is a tested promise: a test refuses every socket, and a scan of installed items and a scan of a folder must still pass. A feature that needs the network breaks that promise and has to be weighed against this record first.
- The git fetch is the one place where the scan touches remote content, so its hardening is part of the contract, not a detail.
