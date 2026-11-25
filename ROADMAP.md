# Roadmap

boxed is alpha. This page lists what does not work yet and where the project may grow. It has no dates and makes no promises: the order depends on what people report and on who helps. To push an item, comment on its issue or open one.

## Not supported yet

- **PyPI.** boxed installs from GitHub (`uv tool install git+https://github.com/boxedsi/boxedsi`). A release of the `boxedsi` package on PyPI would make it `uvx --from boxedsi boxed audit`.
- **Linux sandbox.** `boxed run` uses the macOS `sandbox-exec`; on Linux the guard hooks are the only barrier. An equivalent with bubblewrap or Landlock is open for a design proposal.
- **Linux browser host.** `boxed install native-host` refuses on Linux: Chrome, Chromium and Edge there look in their own folders (snap and flatpak builds in others again), which boxed does not write until they are tried with a real browser.
- **Linux on a desktop.** The test suite passes in a container; nobody has used boxed on a Linux desktop yet.
- **Windows: agents.** The Claude Code plugin, the masked workspace and its hooks, `boxed mcp` and `boxed install claude|codex` are refused on Windows. The session-start warning about agent extensions needs a launcher that works without `sh`.
- **Windows: `boxed skills` and `serve`.** CI runs the whole test suite and `boxed skills scan` on Windows; the core passes, about a hundred tests of `serve` and `skills` do not yet. Until those known failures are fixed, the whole Windows job in CI is optional; after that, the core tests on Windows become required. Nobody has run `boxed skills` on a Windows desktop computer.
- **Gaps of the macOS sandbox.** The threat model lists what `boxed run` does not deny yet: the clipboard, sockets of IDEs, tmux and the ssh-agent, and writes to `~/Library/Caches`. A broker outside the sandbox would keep the workspace state and the vault out of the agent's reach.
- **Python 3.14.** boxed is tested on Python 3.13 only, so the package asks for 3.13 (`>=3.13,<3.14`) and `uv` picks that version even where a newer one is installed. 3.14 needs a CI run of the whole suite and wheels of every extra (torch for `ner-en`) first.
- **Desktop app.** One proof screen, unsigned builds, Apple silicon only; no Intel Mac build, no updater, no English name model.

## Where it may grow

- **More detectors.** Prefix rules for GitLab, DigitalOcean and Shopify tokens, Russian phone numbers written as `8 912 ...`, Russian OGRN and OGRNIP numbers.
- **The benchmark.** Synthetic documents in the formats it does not cover yet.

Security problems do not belong here: report them as [SECURITY.md](SECURITY.md) says.
