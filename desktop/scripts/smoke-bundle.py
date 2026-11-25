#!/usr/bin/env python3
"""Smoke test of the built macOS app with no Python anywhere on its PATH. Standard library only; macOS only.

    python3 desktop/scripts/smoke-bundle.py [--app path/to/Boxed.app] [--no-ui]

What it proves, in order:
  1. The sidecar inside the app (Contents/MacOS/boxed, libraries in Contents/Frameworks) passes sidecar_check.py: ping with the
     Russian name model on, mask (a Russian name too), restore, refusals, xlsx, docx, pdf, end of input.
  2. The app starts the sidecar at launch, in a process group of its own, and writes its pid file; the sidecar's libraries all come
     from the app, none from a Python of the machine.
  3. The window reports the engine ready and words the levels from what the engine says it detects (read only, through the
     Accessibility API; --no-ui skips it).
  4. Quit (an Apple Event to this very bundle) ends the app with exit code 0, ends the sidecar and removes the pid file.
  5. An app killed with signal 9 leaves no idle sidecar behind: its input closes with it.
  6. A sidecar that is busy and so does not see the end of its input (here: it waits for the lock of the vault, which this script
     holds) outlives a killed app, and the next start of the app finds it by the pid file and ends it.

It never types and never clicks: no keystroke, no Accessibility action on the window, nothing that could reach another app.
The environment of the app: PATH is an empty folder, HOME and the boxed home are throwaway, the key store is a file (the real
keychain is never touched). Running the app leaves two small WebKit folders of its own in ~/Library (Caches and WebKit, named
si.boxed.desktop).
"""

from __future__ import annotations

import argparse
import fcntl
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sidecar_check  # noqa: E402

DESKTOP = Path(__file__).resolve().parent.parent
DEFAULT_APP = DESKTOP / "src-tauri" / "target" / "release" / "bundle" / "macos" / "Boxed.app"
PROCESS = "boxed-desktop"  # the name System Events knows the app by
IDENTIFIER = "si.boxed.desktop"


class UiError(Exception):
    pass


def osa(script: str) -> str:
    done = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=60)
    if done.returncode != 0:
        raise UiError(done.stderr.strip())
    return done.stdout.rstrip("\n")


def window_texts() -> list[str]:
    """Every static text of the window of the app: a read, no action."""
    out = osa(
        f"""
tell application "System Events"
  tell process "{PROCESS}"
    set els to entire contents of window 1
    set res to ""
    repeat with e in els
      try
        if role of e is "AXStaticText" then set res to res & (value of e as text) & linefeed
      end try
    end repeat
    return res
  end tell
end tell"""
    )
    return out.split("\n")


def wait_for(what: str, condition, seconds: float = 30.0):
    """The first true value of condition(). The window may not exist yet, so an error of the Accessibility API is tried again,
    except one that says the permission is missing."""
    until = time.monotonic() + seconds
    problem = ""
    while True:
        try:
            result = condition()
        except UiError as error:
            if "assistive" in str(error) or "-25211" in str(error):
                raise
            result, problem = None, str(error)
        if result:
            return result
        if time.monotonic() > until:
            raise AssertionError(f"timed out waiting for {what} {problem}".strip())
        time.sleep(0.3)


def children(pid: int) -> list[int]:
    out = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True, text=True).stdout.split()
    return [int(p) for p in out]


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def launch(app: Path, env: dict) -> subprocess.Popen:
    binary = app / "Contents" / "MacOS" / PROCESS
    return subprocess.Popen([str(binary)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)


def sidecar_of(process: subprocess.Popen) -> int:
    return wait_for("the app to start its sidecar", lambda: (children(process.pid) or [None])[0])


def libraries_of(pid: int) -> list[str]:
    lines = subprocess.run(["lsof", "-p", str(pid), "-Fn"], capture_output=True, text=True).stdout.splitlines()
    return sorted({line[1:] for line in lines if line.startswith("n/") and any(mark in line for mark in (".dylib", ".so", "Python", "python"))})


def pid_file(env: dict, app_pid: int) -> Path:
    """Where the app keeps the pid of its sidecar: its data folder, which sits under HOME for a program that is not sandboxed."""
    return Path(env["HOME"]) / "Library" / "Application Support" / IDENTIFIER / f"sidecar-{app_pid}.pid"


def quit_app(app: Path, process: subprocess.Popen) -> int | None:
    """Quit, as a person would with the menu: an Apple Event to this very bundle (by its path, so that no other copy of the
    app can be meant). None when the system does not let this script send it."""
    try:
        osa(f'tell application "{app}" to quit')
    except UiError:
        return None
    return process.wait(timeout=30)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--app", type=Path, default=DEFAULT_APP)
    parser.add_argument("--no-ui", action="store_true", help="do not read the window (no Accessibility permission needed)")
    args = parser.parse_args()
    app = args.app.resolve()
    sidecar = app / "Contents" / "MacOS" / "boxed"
    for needed in (app / "Contents" / "MacOS" / PROCESS, sidecar, app / "Contents" / "Frameworks"):
        if not needed.exists():
            sys.exit(f"{needed} is missing: build the app with the sidecar first (see desktop/README.md)")

    with tempfile.TemporaryDirectory(prefix="boxed-smoke-") as folder:
        env = sidecar_check.clean_env(Path(folder))
        env.pop("BOXED_SERVE_NER")  # the app sets it itself for its sidecar; a smoke test that set it would hide a shell that did not
        assert shutil.which("python3", path=env["PATH"]) is None and shutil.which("python", path=env["PATH"]) is None
        megabytes = sum(p.stat().st_size for p in app.rglob("*") if p.is_file() and not p.is_symlink()) / 1e6
        print(f"{app}: {megabytes:.1f} MB\nPATH={env['PATH']} (an empty folder: no Python)")

        print("\n1. the sidecar inside the app")
        for line in sidecar_check.check(sidecar):
            print("ok -", line)

        print("\n2. the app starts its sidecar at launch")
        process = launch(app, env)
        try:
            pid = sidecar_of(process)
            command = subprocess.run(["ps", "-o", "command=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
            assert command == f"{sidecar} serve", command
            group = subprocess.run(["ps", "-o", "pgid=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
            assert group == str(pid), f"the sidecar does not lead a process group of its own (group {group})"
            file = pid_file(env, process.pid)
            wait_for("the pid file", file.exists)
            assert file.read_text().strip() == str(pid), file.read_text()
            print(f"ok - the app (pid {process.pid}) started `boxed serve` (pid {pid}) in a process group of its own; {file.name} names it")

            print("\n3. the window (read only)")
            if args.no_ui:
                print("skipped (--no-ui)")
            else:
                try:
                    wait_for("the engine to report ready", lambda: any("Masking engine ready" in t for t in window_texts()))
                    texts = window_texts()
                except UiError as error:
                    sys.exit(f"the window could not be read: {error}\nIf this is a missing permission, grant Accessibility to this terminal, or use --no-ui")
                ready = next(t for t in texts if "Masking engine ready" in t)
                assert ready.endswith("Names: Russian model."), ready
                assert any("Russian company names are found by the same small model; English ones are not reliably found." in t for t in texts), texts
                print(f"ok - {ready!r}: a ping went through the page, the shell and the sidecar, and the levels are worded from its answer")

            libraries = libraries_of(pid)
            system = ("/usr/lib/", "/System/", "/Library/Apple/", "/private/var/db/")
            outside = [p for p in libraries if not p.startswith(str(app)) and not p.startswith(system)]
            assert not outside, f"the sidecar uses files from outside the app: {outside}"
            frameworks = str(app / "Contents" / "Frameworks")
            assert any(p.startswith(frameworks) and "libpython" in p for p in libraries), libraries
            print(f"ok - the sidecar's {len(libraries)} libraries come from Contents/Frameworks or the system, none from a Python of the machine")

            print("\n4. Quit")
            code = quit_app(app, process)
            if code is None:
                print("skipped: this script may not send the app an Apple Event here")
            else:
                assert code == 0, f"the app exited with {code}"
                wait_for("the sidecar to leave after Quit", lambda: not alive(pid), 15)
                assert not file.exists(), "the pid file is still there after a clean end"
                print("ok - the app exited with code 0, the sidecar left with it, and the pid file is gone")
        finally:
            if process.poll() is None:
                process.kill()

        print("\n5. an app that is killed leaves no idle sidecar behind")
        process = launch(app, env)
        try:
            pid = sidecar_of(process)
            os.kill(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
            wait_for("the sidecar to leave after the app was killed", lambda: not alive(pid), 15)
            print("ok - signal 9 on the app: the sidecar's input closed with it and it left by itself")
        finally:
            if process.poll() is None:
                process.kill()

        print("\n6. a busy sidecar that its killed app left behind is ended by the next start")
        home = Path(env["BOXED_HOME"])
        home.mkdir(mode=0o700, exist_ok=True)
        lock = os.open(home / "vault.db.lock", os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)  # the vault is held: a mask now waits for it, and reads nothing else meanwhile
        fifo = Path(folder) / "stdin.fifo"
        os.mkfifo(fifo)
        started = subprocess.run(["/bin/sh", "-c", f'"{sidecar}" serve > /dev/null 2>&1 < "{fifo}" & echo $!'], env=env, capture_output=True, text=True, timeout=30)
        leftover = int(started.stdout.strip())  # a sidecar whose app is gone: its parent is the shell, which has ended
        asking = os.open(fifo, os.O_WRONLY)  # its input stays open, as if the app were alive: no end of input will come
        second = None
        try:
            os.write(asking, sidecar_check.encode({"id": 1, "cmd": "mask", "text": "waiting for the vault", "level": 0}))
            wait_for("the shell to be gone", lambda: subprocess.run(["ps", "-o", "ppid=", "-p", str(leftover)], capture_output=True, text=True).stdout.strip() == "1", 10)
            data = Path(env["HOME"]) / "Library" / "Application Support" / IDENTIFIER
            data.mkdir(parents=True, exist_ok=True)
            (data / "sidecar-1.pid").write_text(f"{leftover}\n")  # what a killed app leaves in its data folder
            time.sleep(1)
            assert alive(leftover), "the busy sidecar is gone before the app was started: the check has nothing to show"
            second = launch(app, env)
            replacement = sidecar_of(second)
            assert replacement != leftover
            wait_for("the leftover sidecar to be ended", lambda: not alive(leftover), 15)
            assert not (data / "sidecar-1.pid").exists(), "its pid file is still there"
            print(f"ok - the next start ended the busy sidecar (pid {leftover}) that a killed app left behind, and started its own (pid {replacement})")
            if not args.no_ui:
                wait_for("the new sidecar to answer", lambda: any("Masking engine ready" in t for t in window_texts()))
                print("ok - and the new sidecar answers: the window reports the engine ready")
        finally:
            if second is not None and second.poll() is None:
                second.kill()
            os.close(asking)
            os.close(lock)
            if alive(leftover):
                os.kill(leftover, signal.SIGKILL)
    print("\nsmoke test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
