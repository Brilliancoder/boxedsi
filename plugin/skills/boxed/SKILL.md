---
name: boxed
description: Use inside a boxed.si masked workspace (a folder with a .boxed-workspace file), or when the user asks to read logs or files with secrets and personal data masked. Explains placeholders like [EMAIL_1] and the read_masked and search_masked tools.
---

# Working with boxed.si

- In a masked workspace, values like `[EMAIL_1]`, `[SECRET_2]` or `[HOST_3]` are placeholders for real data that stays on the user's computer. Keep every placeholder exactly as it is, never invent new ones and never try to recover the originals.
- Work only inside the masked workspace. Never open the original project, even when a read of it is not stopped: on macOS `boxed run` enforces that restriction at the OS level, but in a plain Claude Code session the hooks are best effort, and Codex has no such hooks.
- To look at files outside the workspace, for example server logs, use the `read_masked` and `search_masked` MCP tools. They only reach folders the user listed in `mcp_roots` in `boxed.toml`.
- When the task is done, tell the user to run `boxed workspace sync <id>`: it moves your edits back into the real project and puts the original values in place.
