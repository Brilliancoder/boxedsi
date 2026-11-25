"""Where boxed keeps its local data."""

import os
import stat
from pathlib import Path

from .platform import refuse_home_outside_profile


def boxed_home_path() -> Path:
    """Where the data lives, without creating it."""
    return Path(os.environ.get("BOXED_HOME") or Path.home() / ".boxed").expanduser()


def boxed_home() -> Path:
    home = boxed_home_path()
    refuse_home_outside_profile(home)  # Windows: before the folder is made
    home.mkdir(parents=True, exist_ok=True)
    if stat.S_IMODE(home.stat().st_mode) != 0o700:  # a chmod is a write: the boxed run sandbox refuses it, even to set what is set
        os.chmod(home, 0o700)
    return home
