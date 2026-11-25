# Demo assets

Everything here runs on a made-up home folder: `make_home.py DIR` writes invented Claude Code and Codex transcripts, a `.env` and a harmless skill into `DIR`, from a fixed seed. CI uses it for the smoke job.

- GIF (`docs/assets/demo.gif`): from the repository root, with `boxed` in `.venv/bin` (`uv sync`) or another folder named in `BOXED_DEMO_BIN`, run `vhs scripts/demo/demo.tape` (`brew install vhs`). The tape sets `HOME`, `BOXED_HOME` and `BOXED_KEYSTORE=insecure-file` to a new `mktemp -d` folder, so boxed never reads your agents or keychain.
- Check the frames before you commit: `ffmpeg -i docs/assets/demo.gif -vf fps=1 /tmp/frames/%02d.png`. No real path, user name or value may appear.
- Social preview (`docs/assets/social-preview.png`, 1280x640): `node scripts/demo/render-preview.mjs` renders `social-preview.html` with the system Chrome through `playwright-core` (set `PLAYWRIGHT_CORE` to its folder if it is not installed next to the repo, and `CHROME` to the browser if it is not in the usual place). Upload it in the repository settings under Social preview.
- Never run boxed for a demo with your real `HOME`.
