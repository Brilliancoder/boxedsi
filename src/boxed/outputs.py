"""Where boxed may write a file the person named, and how it writes it: one place for a report, a journal export, a masked or
restored file and the result of a plan. A file is made as a part file that nobody else can reach and renamed into place, so the
file that was there is replaced as a whole and never written into."""

import os
import shutil
import stat
import tempfile
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path

from .errors import UserError
from .paths import boxed_home, boxed_home_path
from .platform import open_nofollow

HEAD = 4096  # the first bytes of a file that is already there, to tell whether boxed wrote it
# Why a place is refused. Fixed words: serve._output_refusal finds them by their ends.
IN_HOME = "the output is not written in the boxed home, where the journal, the vault and the keys are"
IN_HOME_REPORT = "a report is not written in the boxed home, where the journal, the vault and the keys are, except under reports/"
IS_LINK = "the output path is a link: name the file itself"
NO_FOLDER = "the folder of the output file does not exist"
NOT_PLAIN = "the output path is not a plain file"
CHANGED = "the output file: the place of the file changed while it was made"
# by (nothing in the file shows its kind, the command has no --replace)
EXISTS = {
    (True, True): "the output file exists already: name another file, or delete it first",
    (True, False): "the output file exists already: name another file, delete it first, or add --replace to replace it",
    (False, True): "the output file exists and boxed did not write it: name another file, or delete it first",
    (False, False): "the output file exists and boxed did not write it: name another file, delete it first, or add --replace to replace it",
}


def inside(path: Path, folder: Path) -> Path | None:
    """The part of `path` below `folder`, or None when it is not below it. Found by what the folders are and not by how they
    are spelled: a file system that ignores case calls ~/.BOXED and ~/.boxed one folder. A folder that does not exist has no
    identity to compare, so its spelling is all there is."""
    for above in (path, *path.parents):
        try:
            if os.path.samefile(above, folder):
                return path.relative_to(above)
        except OSError:
            continue  # one of the two is not there
    return path.relative_to(folder) if path.is_relative_to(folder) else None


@contextmanager
def staging(dest: Path) -> Iterator[Path]:
    """A part file for `dest`, with the name of dest, in a folder made for it next to dest. The folder has mode 700 and a name
    nobody can know, so no one can plant a link or a file in it, and it is on the file system of dest, so the rename into place
    is one step. The part file is there already, empty, mode 600, made without following a link: whatever writes to it by name
    writes nowhere else. The folder and what is left in it go when the block ends, however it ends."""
    folder = Path(tempfile.mkdtemp(prefix=".boxed-part-", dir=dest.parent))
    try:
        part = folder / dest.name
        os.close(open_nofollow(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        yield part
    finally:
        shutil.rmtree(folder, ignore_errors=True)


class Target:
    """A file the person asked for, and the rules it is held to.

    Not inside the boxed home, where the journal, the vault and the keys are (a report may go below its reports/ folder, and
    only there); not a link, whatever it points to; a plain file if there is one already, and then replaced only when boxed can
    tell from its first bytes that it wrote one of this kind (`own`) or the person said --replace. The place is looked at again
    just before the file lands, because a file may have appeared while the work went on.

    kind: what the file is called in a refusal. own: tells a file of this kind from its first bytes, or None when nothing in the
    file shows it. replace: None when the command has no --replace, else whether it was given. reports: a report of the boxed
    home, which may make its folders."""

    def __init__(
        self, name: str, *, kind: str, own: Callable[[bytes], bool] | None = None, replace: bool | None = None, reports: bool = False
    ) -> None:
        self.name, self.kind, self.own, self.replace, self.reports = name, kind, own, replace, reports
        self.path = self.check()

    def check(self) -> Path:
        """The resolved path of the file, or a UserError that says why this is not the place for it, in fixed words: the name of
        the file is the person's, and may say what is in it."""
        given = Path(self.name).expanduser()
        out = given.resolve()  # through links first, so that a link to the journal is the journal
        below = inside(out, boxed_home_path().resolve())
        if below is not None and not (self.reports and below.parts[:1] == ("reports",) and len(below.parts) > 1):
            raise UserError(IN_HOME_REPORT if self.reports else IN_HOME)
        if given.is_symlink():
            raise UserError(IS_LINK)
        if not self.reports and not out.parent.is_dir():
            raise UserError(NO_FOLDER)
        try:
            info = os.lstat(out)
        except FileNotFoundError:
            return out  # a new file
        if not stat.S_ISREG(info.st_mode):
            raise UserError(NOT_PLAIN)
        if self.replace or (self.own is not None and self._wrote(out)):
            return out
        raise UserError(EXISTS[(self.own is None, self.replace is None)])

    def _wrote(self, path: Path) -> bool:
        """Do the first bytes of this plain file show that boxed wrote a file of this kind? It is opened without following a link
        and without waiting, and looked at on the descriptor: what stands there may have changed since it was last looked at."""
        try:
            fd = open_nofollow(path, os.O_RDONLY)
        except OSError:
            return False
        try:
            return stat.S_ISREG(os.fstat(fd).st_mode) and self.own(os.read(fd, HEAD))
        except OSError:
            return False
        finally:
            os.close(fd)

    def stage(self) -> AbstractContextManager[Path]:
        """A part file to build the file in (see staging); publish moves it into place."""
        return staging(self.path)

    def publish(self, part: Path) -> None:
        """Moves the finished part file into place, after looking once more at what stands there now."""
        path = self.check()
        if path != self.path:
            raise UserError(CHANGED)
        os.replace(part, path)

    def write(self, data: bytes) -> None:
        """The whole file, written to a part file, flushed to the disk and renamed into place."""
        if self.reports:
            if inside(self.path, boxed_home_path().resolve()) is not None:
                boxed_home()  # creates the data folder with mode 0700 before any report folder inside it
            self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.stage() as part:
            with os.fdopen(open_nofollow(part, os.O_WRONLY), "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            self.publish(part)
