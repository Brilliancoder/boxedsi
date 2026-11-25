# boxed.si desktop (experimental)

A small desktop window for boxed: paste a text, mask it, send the masked text to any AI chat yourself, paste the answer back and
restore it. The window is a Tauri 2 app; the masking itself is done by the Python core, which the app runs as a sidecar process
(`boxed serve`).

**Status: experimental.** There are no released builds, nothing is signed, and only macOS on Apple silicon has been built and run.
If you want to use boxed today, use the command line (`boxed mask`, `boxed restore`): see [docs/guide/quickstart.md](../docs/guide/quickstart.md).
The user-facing page for this app is [docs/guide/desktop.md](../docs/guide/desktop.md).

## What works and what does not

Works (macOS 14 or later, Apple silicon):

- One screen: a text box, a scope, a level from 0 to 3, Mask, Restore, and Try again when the engine is down.
- The shell starts the core at launch, restarts it after a crash, gives up a request after 120 s and stops restarting after three
  failures in a minute.
- The Russian name model (`ner-ru`) is bundled; the level texts say what the engine reports it can find.
- Masks go into the same boxed home and vault as the command line (`~/.boxed` or `BOXED_HOME`), so a scope made in the window can
  be restored with `boxed restore --scope <name>` and the other way round.

Not there yet:

- Any screen besides the one above: files (`mask-file`), `ask`, keys, the journal, settings, the extension check. The visual design
  is a plain placeholder.
- English names: the `ner-en` extra (GLiNER and torch, about 1 GB plus a model) is not bundled, so English names are not reliably found.
- Signing and notarization: builds are ad-hoc signed, `spctl` rejects them, and a downloaded copy is blocked by Gatekeeper as
  coming from an unidentified developer.
- Updates: the updater plugin is registered but never called, and its key and address are placeholders (see "Configuration").
- macOS on Intel: the shell builds and its tests pass for `x86_64-apple-darwin`, but the sidecar does not, because the locked
  `cryptography` 50.0.2 has no macOS x86_64 wheel.
- Windows: there is an installer config (NSIS, per user) and the sidecar starts without a console window, but the app has never
  been built or run on Windows. Ending a leftover sidecar is not implemented there.
- Linux: not supported. `build-sidecar.py` builds for macOS and Windows only, and there is no Linux bundle config.

## Requirements

- Rust (stable; tested with 1.99) and the Tauri CLI: `cargo install tauri-cli --version "^2" --locked`.
- Node 20.19 or later in the 20.x series, or Node 22.12 or later (Vite asks for `^20.19.0 || >=22.12.0`), and npm (tested with Node 26).
- [uv](https://docs.astral.sh/uv/) and a checkout of this repository: the sidecar is frozen from its `src/boxed` and `uv.lock`.
- macOS 14 or later on Apple silicon, with the Xcode command line tools.

The Rust tests need neither the sidecar nor the built web page, so a Rust toolchain alone is enough to run them.

## Build and run

All commands run from `desktop/` unless said otherwise.

```
npm ci                                   # web dependencies
npm test                                 # JavaScript tests (node --test, run from desktop/)
python3 scripts/build-sidecar.py         # freeze `boxed serve` into src-tauri/binaries/; about 1 min, then runs sidecar_check.py
```

`build-sidecar.py` freezes the repository it lives in; `--source DIR` freezes another checkout. It prints the oldest macOS the
result runs on (14.0 today).

Run a debug build locally:

```
cargo tauri build --debug --no-bundle --config src-tauri/tauri.sidecar.conf.json
ln -s ../../binaries/_internal src-tauri/target/debug/_internal     # once: the sidecar's libraries
./src-tauri/target/debug/boxed-desktop
```

`cargo tauri dev` is not set up: it serves the page from a local dev server, and the app refuses to show any page but its own
(see "Design notes"). Rebuild with the first command after a change.

Build the app and the disk image:

```
CI=true cargo tauri build --config src-tauri/tauri.sidecar.conf.json   # CI=true: no Finder scripting for the disk image
python3 scripts/smoke-bundle.py                                       # optional, see below
```

The result is `src-tauri/target/release/bundle/macos/Boxed.app` and a `.dmg` next to it. Without
`--config src-tauri/tauri.sidecar.conf.json` the app has no sidecar and says it cannot reach its masking engine.

## Tests

```
npm test                                          # 16 tests of the screen logic (src/flow.js)
cd src-tauri && cargo test --locked               # 71 tests: 20 unit, 6 config, 45 manager
python3 scripts/sidecar_check.py PATH_TO_SIDECAR  # a frozen sidecar end to end
python3 scripts/smoke-bundle.py [--no-ui]         # the built app, macOS only
```

A cold `cargo test` builds the Tauri dependencies first: about 3 minutes on an Apple silicon laptop, plus downloads.

- `tests/config.rs` pins the security settings: the one permission, the CSP, the updater rules, the dependency list. Weakening one
  of them has to change a test.
- `tests/manager.rs` runs the sidecar manager against a fake sidecar, which is the test program itself. It uses its own harness
  (`harness = false`), so a filter matches test names by substring only.
- `sidecar_check.py` talks to a frozen sidecar the way the shell does, with made-up data, a throwaway boxed home, the file key store
  and an empty `PATH`: ping, mask (a Russian name too), restore, scopes, refusals, xlsx, docx, pdf, end of input.
- `smoke-bundle.py` checks the built app: the sidecar inside it, start in its own process group, the pid file, Quit, a killed app,
  and a busy leftover sidecar ended by the next start. It reads the window through the Accessibility API (`--no-ui` skips that) and
  never types or clicks. Running the app leaves WebKit folders named `si.boxed.desktop` in `~/Library/Caches` and `~/Library/WebKit`.

## How it works

```
page (src/)  --invoke("sidecar_request")-->  shell (src-tauri/src/)  --frames on stdin/stdout-->  boxed serve
flow.js, main.js   ping, mask, restore,      commands.rs  manager.rs  processes.rs  framing.rs  navigation.rs
                   restart
```

- `src/flow.js` is the screen logic with no DOM and no Tauri (tested by `test/flow.test.mjs`); `src/main.js` wires it to the page.
- The page has one command, `sidecar_request`, and may send `ping`, `mask`, `restore` and the shell's own `restart`
  (`commands::ALLOWED`); everything else is refused before it reaches the core.
- `framing.rs`: a 4-byte little-endian length, then UTF-8 JSON. Requests are limited to 1 MiB, replies to 16 MiB. The core's side
  of the protocol is `src/boxed/serve.py`.
- `manager.rs`: one supervisor thread owns the state; each sidecar gets a reader, a writer and an error-stream thread. Replies are
  matched to requests by id. No ports are opened: everything goes over the sidecar's stdin and stdout.
- `processes.rs`: the sidecar leads its own process group, and a pid file per app (`sidecar-<app pid>.pid` in the app's data
  folder) lets the next start find a sidecar whose app was killed.
- `navigation.rs`: the window may only show the app's own pages.
- The shell sets `BOXED_SERVE_NER=ru` for its sidecar only; `boxed.toml` is not written.

### Configuration files

| File | What it holds |
|---|---|
| `src-tauri/tauri.conf.json` | Shared: name `Boxed`, identifier `si.boxed.desktop`, version, window, CSP, icons, updater settings |
| `src-tauri/tauri.macos.conf.json` | macOS: `app` and `dmg` targets, minimum macOS 14.0 |
| `src-tauri/tauri.windows.conf.json` | Windows: NSIS installer, installed per user |
| `src-tauri/tauri.sidecar.conf.json` | The sidecar (`externalBin`) and, on macOS, its libraries in `Contents/Frameworks`. Passed with `--config` |
| `src-tauri/capabilities/default.json` | The main window may call `sidecar_request` and nothing else |

The updater block holds placeholders, not keys: `pubkey` is the text `REPLACE-WITH-...`, the endpoint is on `.invalid`. A real
release needs a key pair from `cargo tauri signer generate`; the public key goes into `pubkey`, the private key never goes into the
repository.

## Design notes

Why the app is built the way it is, and what each choice costs.

- **The shell owns the sidecar, not the shell plugin.** Tauri's shell plugin cannot close stdin, splits output into lines (frames
  are binary) and would give the page a right to spawn processes. Instead the app has one command of its own. Cost: none worth
  noting; adding the plugin later would keep the manager.
- **Least privilege for the page.** It may ask for `ping`, `mask`, `restore` and `restart` only. A new screen adds its verbs to
  `commands::ALLOWED` on purpose.
- **The sidecar lives in a separate config file.** `tauri-build` wants the sidecar file to exist at compile time, and `cargo test`
  has to work on a clean checkout. Cost: a build without `--config src-tauri/tauri.sidecar.conf.json` has no sidecar.
- **`build.rs` writes a stub page when the front end is not built**, because `generate_context!` reads `dist/` at compile time.
  Cost: a plain `cargo build --release` embeds the stub; `cargo tauri build` builds the page first.
- **Folder build, uv's Python, hashed dependencies.** A one-file PyInstaller build unpacks hundreds of files on every start (about
  3 s); a folder build starts in 0.1 s. uv's standalone Python has an old deployment target, so the program runs on older macOS
  than the build machine. Cost: macOS 14 on Apple silicon, set by numpy, which the Russian name model needs.
- **The Russian name model is switched on per process** (`BOXED_SERVE_NER=ru`), because `boxed.toml` is shared with the command
  line and the browser host, which may lack the extra. Cost: about 60 MB more and English names stay unreliable.
- **The level texts come from the engine's `ping`** (`ner` and `ner_installed`), and nothing it does not report is promised. A core
  that does not report `ner` gets texts saying it is not known whether names are found.
- **Masks of a session share a visible scope**, so a placeholder means one thing across them; scope names (not text) are kept in
  local storage, twenty at most, so an older answer can be restored after a restart. Cost: scope names outlive the window.
- **Leftover sidecars.** A busy sidecar does not notice that its input closed, and it holds the vault lock. So the sidecar leads its
  own process group, which is ended on a timeout and at exit, and a pid file lets the next start end a sidecar whose app is gone
  (same command line, parent is pid 1). `ps` is called by its full path, since an app's `PATH` may be empty. Cost: macOS and Linux
  only; a sidecar of an app that is still running is never touched.
- **Errors stay in memory.** The error stream is read, and its last 20 lines (200 characters each), the exit code and the restart
  count are kept for support and shown nowhere, because a traceback can quote the user's text. The window gets the numbers only.
  Cost: no log on disk, so a crash can be understood only while the app runs.
- **Three failures in a minute stop the restarts** until Try again; a timeout counts as a failure. Cost: a machine that is slow for
  a while needs one click.
- **A timeout replaces the sidecar at once**, and requests fail immediately while a restart waits, instead of queueing behind a
  spinner. Restarts after failures wait 0, 0.5, 1, 2, 4, 8, 16, 30 s; one good answer resets that. Exit code 0 right after an answer
  is the core's own decision and not a failure: the request it never read is sent again, once. Cost: a request that needs more than
  120 s is lost.
- **The smoke test never types or clicks**, so it cannot send keystrokes to another app. Cost: Mask and Restore are not driven in the
  window; the manager and flow tests cover them.
- **The updater is registered and never called**, and `createUpdaterArtifacts` is off, so builds need no signing key. Updates, when
  they come, must be signed, over HTTPS, with no downgrades (`requireSignedVersion`), and the tests check that.
- **Navigation is limited to the app's own pages** by a small plugin, because the CSP does not stop a page from being replaced.
  Cost: a dev server needs an exception, which is why `cargo tauri dev` is not set up.
- **The manager tests use their own harness** (`harness = false`) because the fake sidecar is the test executable, and the standard
  harness would print into the frame stream.

Security settings in short: one permission (`allow-sidecar-request`), no fs, shell, http, updater or core permission; CSP
`default-src 'self'; connect-src ipc: http://ipc.localhost; object-src 'none'; base-uri 'none'; form-action 'none'` with no inline
script or style; `freezePrototype`; no global Tauri object. The page shows text through `.value` and `.textContent` only.

## How to help

- Build and run it on Windows, and report what breaks.
- Design and build the missing screens (files, `ask`, keys, journal); add each verb to `commands::ALLOWED` with a test.
- Signing, notarization and the update check.
- An Intel macOS sidecar once the `cryptography` pin allows it.

Read [CONTRIBUTING.md](../CONTRIBUTING.md) first; security issues go through [SECURITY.md](../SECURITY.md). License: Apache-2.0.
