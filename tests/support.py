"""Small helpers that several test files share."""

import stat
import sys
from pathlib import Path


def mode_is(path: Path, mode: int) -> bool:
    """Is the mode of the file `mode`? Always yes on Windows, where a mode is only the read-only mark (a file reads 0o666) and the folder
    of the file decides who may read it: a test that is about something else does not stop there."""
    return sys.platform == "win32" or stat.S_IMODE(path.stat().st_mode) == mode
