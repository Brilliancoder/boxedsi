# Windows

The core of boxed and the browser extension's host run on Windows 11 with Python 3.13, under the same rules as on macOS. The Claude Code and Codex parts and the sandbox do not, yet. This page lists what works, where boxed keeps its keys and data there, and what to watch for in a Windows terminal.

## Install

Install [uv](https://docs.astral.sh/uv/), then the same command as on macOS (see [install.md](install.md)):

```text
uv tool install --python 3.13 git+https://github.com/boxedsi/boxedsi
boxed --version
```

From a copy of the repository, `pip install <folder of boxed>` works too.

## What works

| | Commands |
|---|---|
| Works | `mask`, `restore`, `mask-file`, `restore-file`, `ask`, `key`, `check`, `journal`, `dashboard`, `audit`, `plan`, `policy`, and the browser side panel in Chrome and Edge |
| Not supported yet | `boxed run` (it needs the macOS sandbox), `boxed workspace` and the Claude Code hooks, `boxed mcp`, `boxed install claude` and `boxed install codex`. Each says `boxed <command> is not supported on Windows yet` and exits with code 2 before it touches the data folder or a key. The Claude Code plugin is not available on Windows |
| Not tried on a desktop yet | `boxed skills` reads the same folders in your profile and is written to work there. CI runs `boxed skills scan` on Windows, but nobody has run it on a Windows desktop computer, and about a hundred tests of `skills` and `serve` do not pass on Windows yet (see "Running the tests"). The warning at the start of a Claude Code session needs the plugin's hook, which Windows does not have |

## Keys

Keys live in Windows Credential Manager (service `boxed.si`). It belongs to the signed-in session of the person: from a terminal you opened it works; from an SSH or service session Windows may have no logon session to give the keys out (error 1312), and boxed stops with that error.

## Data folder

Data lives in `%USERPROFILE%\.boxed`, or in `%BOXED_HOME%`, which must be a folder in your profile. boxed refuses any other, such as one on `C:\`, where other users of the computer may be able to change files. Windows keeps a profile to its user, SYSTEM and the administrators, and a file mode means nothing there, so boxed neither sets nor checks one.

A symbolic link, a junction or any other reparse point at the journal, `checks.json`, a lock file or an output file is refused and never followed, as a link is on macOS.

## Browser extension

`boxed install native-host --extension-id <id>` writes the manifest and a launcher to `%LOCALAPPDATA%\boxed\native-host` and sets the default value of `HKCU\Software\Google\Chrome\NativeMessagingHosts\si.boxed.host`, and of the Edge key, to the manifest. It writes the registry of your user only and needs no administrator rights. `--dry-run` names both keys; `boxed install native-host --remove` deletes the keys and the folder. The rest is in [browser-extension.md](browser-extension.md).

## Text, pipes and code pages

boxed writes UTF-8 with line feeds, whatever the code page of the console is. Windows PowerShell 5.1 sends a pipe to a program as ASCII (any other letter becomes `?`) and writes a `>` file as UTF-16. So give boxed the file (`boxed mask notes.txt`) and redirect from `cmd.exe`, or use PowerShell 7, which sends UTF-8.

## Running the tests

CI runs the whole test suite on Windows. The core passes; about a hundred tests of the newer parts, `serve` and `skills`, do not pass yet, so that job reports them without failing the run. `pytest` runs on Windows, with its temp folder in your profile (the default; boxed refuses a home elsewhere). The tests of links need Developer Mode or an elevated terminal. `BOXED_TEST_TIME_FACTOR=3` loosens the timing budgets for a slow machine. The two tests that write the real registry run only with `BOXED_TEST_REAL_REGISTRY=1`. The rest of the setup is in [CONTRIBUTING.md](../../CONTRIBUTING.md).
