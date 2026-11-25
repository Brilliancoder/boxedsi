# boxed.si browser extension (experimental)

A side panel for Chrome and Edge (Manifest V3, plain JavaScript, no build step, no remote code). You paste text into the panel, the `boxed` program on your computer masks it, and you send the masked text to an AI chat yourself. You paste the answer back and the originals come back in the panel only. An optional Observe mode counts what you sent to five chats without masking.

**Status: experimental alpha.** It has had no external security audit, it is not in any extension store, and it has been used mostly on macOS. It is a convenience around the `boxed` CLI, not a guarantee that nothing personal reaches a chat. The user guide, with what it does and does not do, every permission and the known limits, is [docs/guide/browser-extension.md](../docs/guide/browser-extension.md).

## Try it

You need `boxed` installed first (see the main [README](../README.md)): the extension does no masking itself.

1. Open `chrome://extensions` (or `edge://extensions`) and turn on **Developer mode**.
2. Press **Load unpacked** and pick this `extension/` folder of your clone. (With boxed installed as a package, `boxed install native-host` without an id prints the folder of the copy that ships inside it.)
3. Copy the extension id the browser shows (32 letters from a to p).
4. Register the native host: `boxed install native-host --extension-id <id>`. Add `--dry-run` first to see what it would write. On macOS it writes `si.boxed.host.json` for Chrome and Edge and the launcher `~/.boxed/bin/boxed-native-host`.
5. Click the toolbar button. The panel says `Connected to boxed.si 0.1.0` when it works.

Chrome derives the id of an unpacked extension from its folder path: load it from another folder and you register the host again. To undo: remove the extension on `chrome://extensions`, then `boxed install native-host --remove`.

## Tests

```bash
cd extension && node --test      # Node 22 or later; the libraries, the inserter, the worker, the panel, the manifest
uv run --no-sync pytest -p no:cacheprovider -o addopts="" -q tests/test_native_host.py tests/test_install.py   # the host and the packaging
```

The Node tests run the real files against a stub `chrome` object; nothing starts a browser. `tests/test_native_host.py` also checks that the extension code has no `fetch`, XHR, WebSocket, `eval` or inline script and names no web address other than the five chats (and the project page in the manifest).

## How the code is laid out

- `manifest.json` - permissions and the five hosts; the tests pin both.
- `sidepanel.html`, `sidepanel.js` - the panel: Prepare (mask, copy, insert), Restore, Observe and the training checks.
- `background.js` - the service worker: opens the panel and, when Observe is on, watches the send request of each chat (never blocking it).
- `lib/protocol.js` - requests and replies of the native host, the site list, the page inserter. Shared by the panel, the worker and the tests.
- `lib/observe.js` - which request is a send for each chat, and how to read the prompt from its body.
- `icons/` - the toolbar and extension icons (`icon.svg` is the source).
- The host on the other end: `src/boxed/native_host.py` (protocol), `src/boxed/install.py` (registration).

## Helping

Most useful right now: re-checking the five send shapes in `lib/observe.js` (`SENDS`, `EXTRACTORS`) against the live sites, since sites change them without notice; trying the panel on Windows and on Edge; and reports of text that should have been masked. Read [CONTRIBUTING.md](../CONTRIBUTING.md) first; report security problems privately as [SECURITY.md](../SECURITY.md) says, not in a public issue. Licensed under Apache-2.0.
