# Desktop app (experimental)

The desktop app is a small window for masking and restoring text without a terminal: paste a text, press Mask, send the masked
text to any AI chat yourself, paste the answer back and press Restore. It runs the same boxed core as the command line, on your
computer.

## Status

Experimental. There are no ready-made builds to download: if you want to try it, you build it yourself. Builds are not signed.
It has been built and run only on macOS 14 or later on Apple silicon. Intel Macs, Windows and Linux are not supported yet.

For everyday use, use the command line: [quickstart.md](quickstart.md) shows `boxed mask` and `boxed restore` in a few minutes,
and [files.md](files.md) covers spreadsheets and documents.

## What it can do

- Mask a text at level 0 to 3 and restore an answer. The levels are the same as on the command line: see [concepts.md](concepts.md).
- Keep masks of one task in one scope, so a placeholder means the same thing across them. The window shows the scope and remembers
  the names of recent scopes (names only, never text), so you can restore an answer that comes later.
- Find Russian names of people and companies with the bundled Russian name model. English names are not reliably found: the
  English model is not included.

It uses the same boxed home (`~/.boxed`, or `BOXED_HOME`) and the same vault key in your system keychain as the command line. A
scope made in the window can be restored with `boxed restore --scope <name>`, and the other way round. macOS may ask once whether
the app may use the keychain item.

## What it cannot do yet

- Files, `boxed ask`, provider keys, the journal and dashboard, settings, and the extension check have no screen. Use the command
  line for them.
- No automatic updates.
- The look is a plain first version.

## Build and run it yourself

You need a Mac with Apple silicon and macOS 14 or later, the Xcode command line tools, Rust with the Tauri CLI
(`cargo install tauri-cli --version "^2" --locked`), Node 20.19 or later in the 20.x series or Node 22.12 or later, [uv](https://docs.astral.sh/uv/) and a copy of this
repository. Then, in the repository:

```
cd desktop
npm ci
python3 scripts/build-sidecar.py
CI=true cargo tauri build --config src-tauri/tauri.sidecar.conf.json
open src-tauri/target/release/bundle/macos
```

`build-sidecar.py` packs the boxed core with its own Python, so the app does not need Python on your computer. The first Rust
build takes a few minutes. Drag `Boxed.app` to Applications or open it from that folder.

The build is not signed. A copy you built yourself usually opens as is; a copy that reached another Mac through a download or a
messenger is blocked as coming from an unidentified developer. Allow it in System Settings, Privacy & Security, Open Anyway.

Details for developers, tests and how the app is put together: [desktop/README.md](../../desktop/README.md).

## Limits

- Masking hides direct identifiers, not context; the limits in [concepts.md](concepts.md) apply here too.
- Nothing is sent anywhere by the app: you copy the masked text and send it yourself.
- If the masking engine crashes three times in a minute, the window stops restarting it and shows Try again.
- A request that takes longer than 120 seconds is given up.
