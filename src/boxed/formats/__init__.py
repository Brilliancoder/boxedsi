"""Masked clean copies of CSV, XLSX, DOCX and PDF files, and restore of what comes back.

The source file is never sent or patched: a new file is built from the parts that were checked, and the report names
what was left out. Errors and reports hold kinds, counts and masked names only, never file content.
"""

import datetime
import importlib
import json
import os
import re
import zipfile
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..detect import DetectConfig, detect
from ..detect.numbers import KINDS as NUMBER_KINDS
from ..errors import UserError
from ..mask import MARKER_RE, MarkerMap, mask_path, mask_text, restore
from ..outputs import staging
from . import display

SUPPORTED = frozenset({".csv", ".xlsx", ".docx", ".pdf"})
RESTORABLE = frozenset({".csv", ".xlsx", ".docx", ".txt"})  # a masked PDF is a .txt file
UNSUPPORTED = {allowed: "unsupported file type; supported: " + ", ".join(sorted(allowed)) for allowed in (SUPPORTED, RESTORABLE)}
CANNOT_PROCESS = {suffix: f"cannot process this {suffix[1:]} file" for suffix in SUPPORTED | RESTORABLE}  # a suffix _require let in
COMPANY = re.compile(rb"<(?:\w+:)?(?:Company|Manager)>\s*[^<\s]")  # text in the extended properties (docProps/app.xml)
CUSTOM = re.compile(rb"<(?:\w+:)?property[\s/>]")  # a property in the custom ones (docProps/custom.xml), not the empty list
PEEK = 1024 * 1024  # a properties part is small; a hostile one is not read whole
THUMBNAIL = "docProps/thumbnail"  # the picture of the first page or sheet that Office saves with a file (.jpeg, .png, ...)
# the link list of docProps/app.xml: found with plain searches, because a pattern for the whole element restarts at every opening tag
LINK_LIST_START = re.compile(rb"<(?:\w+:)?HLinks[\s>]")
LINK_LIST_END = re.compile(rb"</(?:\w+:)?HLinks\s*>")
# a string in a variant of the list; the attributes stop at the next "<", so a tag without its ">" costs no rescan of the rest
LINK_TEXT = re.compile(rb"<(?:\w+:)?lpw?str(?:\s[^<>]*)?>([^<]+)<")
# What an address looks like, against the name of a bookmark (a word in any script, with its marks, digits, "_" or "="): it starts
# with a scheme (https:, mailto:), has a mark of a path, a query or a mail address, or is a name with dots (www.acme.com, report.docx).
ADDRESS_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]+:")
ADDRESS_MARK = re.compile(r"[/\\@?#]")
ADDRESS_NAME = re.compile(r"[\w-]+(?:\.[\w-]+)+")
FORMATS_EXTRA = "this file type needs the formats extra: reinstall boxed with it, as docs/guide/install.md shows"


class FormatError(UserError):
    """The file cannot be read or written safely. The message never holds file content."""


@dataclass
class FileReport:
    source: str  # file name only, masked
    output: str  # file name only
    format: str  # "csv" | "xlsx" | "docx" | "pdf"
    checked: list[str]
    dropped: list[str]
    markers_by_kind: dict[str, int]  # markers placed (mask) or put back (restore)
    complete: bool  # False when content that could hold data was not checked or was dropped; a note (properties, thumbnail) does not count


@dataclass
class Parts:
    """What a format converter did, as the report shows it."""

    checked: list[str]
    dropped: list[str]
    complete: bool


# A marker stands for a text, the one the person saw, and a number or date cell must come back as the number or date it was. So a
# mask run also hands the scope an index of its cells: for each sheet of the copy and each address, the marker that stands there
# and the exact text of the value. It sits among the foreign tokens, which the scope saves with its markers and which nothing
# ever replaces by an original, so no text can make restore read it. It starts with CELLS.
CELLS = '{"xlsx":'


class RunMarkers:
    """The markers of a run, as mask_text and restore use them. Both ask the map for its kinds on every text, and the map finds them
    by going through all its markers: with a marker for every number of a big sheet, each cell would take longer than the one
    before. This one knows its kinds and keeps them up to date; the markers themselves stay in the map."""

    def __init__(self, markers: MarkerMap) -> None:
        self.markers, self._kinds = markers, markers.kinds()

    def kinds(self) -> set[str]:
        return set(self._kinds)

    def marker_for(self, kind: str, original: str) -> str:
        marker = self.markers.marker_for(kind, original)
        self._kinds.add(MARKER_RE.fullmatch(marker).group(1))  # an original that was seen before keeps the marker of its first kind
        return marker

    def reserve(self, token: str) -> bool:
        return self.markers.reserve(token)

    def original_for(self, marker: str) -> str | None:
        return self.markers.original_for(marker)

    def keep(self, token: str) -> None:
        """Save a text with the scope that restore never reads. The map has one place for that: the foreign tokens, which it saves
        and loads as they are and never replaces by an original."""
        self.markers._foreign.add(token)

    def kept(self) -> list[str]:
        return [token for token in self.markers._foreign if token.startswith(CELLS)]


class Pipe:
    """The one place where text is masked or restored: a converter sends every text that lands in the output through it."""

    def __init__(
        self,
        markers: MarkerMap,
        *,
        restoring: bool = False,
        level: int = 2,
        config: DetectConfig | None = None,
        kinds: frozenset[str] = frozenset(),
        delimiter: str | None = None,
    ) -> None:
        self.markers, self.restoring, self.level, self.config, self.kinds = markers, restoring, level, config, kinds
        self.delimiter = delimiter  # of a csv file, when the person names it; None: read from the file (tabular._delimiter)
        self._run = RunMarkers(markers)
        self.counts: Counter[str] = Counter()
        self.anomalies: list[str] = []  # unknown and half-broken markers met while restoring
        self._kind_of = {marker: kind for marker, kind, _ in markers.items()} if restoring else {}
        self._reads: dict[tuple[str, str], tuple[str, str] | None] = {}  # (exact text, number format) -> (kind, text seen), see number
        self._recorded: dict[str, dict[str, list[str]]] = {}  # sheet -> address -> [marker, exact text] of the cells masked here
        self._cells = _index(self._run.kept()) if restoring else {}

    def text(self, value: str) -> str:
        if not value:
            return value
        if not self.restoring:
            masked, found = mask_text(value, self._run, self.level, self.config)
            self.counts.update(found)
            return masked
        result = restore(value, self._run, self.kinds)
        self.counts.update(kind for m in MARKER_RE.finditer(value) if (kind := self._kind_of.get(m.group(0))))
        self.anomalies += result.unknown + result.suspicious
        return result.text

    def secret(self, value, where: tuple[str, str] | None = None):
        """A value under a column header that names a secret ("password", "API key"), masked whole as one SECRET whatever it looks
        like: the header says what it is, and a password such as "summer2024" looks like nothing. A number keeps its exact text, and
        a cell of a sheet (where: the sheet of the copy and the address) is recorded as a number cell is, so restore gives the number
        back. The value itself as `text` would mask it: in a restore run, for an empty value or a boolean, and for a value that is a
        placeholder already."""
        text = value if isinstance(value, str) else display.exact(value)
        if self.restoring or not text or not text.strip() or MARKER_RE.fullmatch(text.strip()):
            return self.text(value) if isinstance(value, str) else value
        marker = self._run.marker_for("SECRET", text)
        self.counts[MARKER_RE.fullmatch(marker).group(1)] += 1
        if where is not None and not isinstance(value, str):
            sheet, address = where
            self._recorded.setdefault(sheet, {})[address] = [marker, text]
        return marker

    def label(self, value: str) -> str:
        """A name for the report: masked in a mask run, as found in a restore run. Not counted."""
        return value if self.restoring else mask_text(value, self._run, self.level, self.config)[0]

    def number(self, value, number_format: str, where: tuple[str, str]) -> str | None:
        """The placeholder for a number or date cell of a spreadsheet, or None when the cell stays as it is (not a number or a
        date, or nothing in it to mask: a lone digit is structure, as in text). where: the sheet of the copy and the address.

        The detectors read the text Excel shows under the number format, which gives the kind (an amount, a percentage, a date),
        and the exact text of the value, which catches what the format hides. The marker stands for the text that was shown, as a
        marker of a text does: cells that show the same text share it, and restoring it in prose gives that text. The exact text
        of the cell is recorded for keep_cells. Name models never read a number."""
        text = display.exact(value)
        if text is None:
            return None
        key = (text, number_format)
        if key not in self._reads:
            self._reads[key] = self._read(value, text, number_format)
        read = self._reads[key]
        if read is None:
            return None
        kind, seen = read
        marker = self._run.marker_for(kind, seen)
        self.counts[MARKER_RE.fullmatch(marker).group(1)] += 1  # the kind of the marker, which a text seen before keeps
        sheet, address = where
        self._recorded.setdefault(sheet, {})[address] = [marker, text]
        return marker

    def keep_cells(self) -> None:
        """Hand the scope the cells that this run masked as numbers or dates, see CELLS."""
        if self._recorded:
            self._run.keep(json.dumps({"xlsx": self._recorded}, sort_keys=True, separators=(",", ":")))

    def typed(self, sheet: str, address: str, text: str):
        """The number, date, time or duration for a cell of a restore run whose text is exactly the marker that stood in this cell
        of this sheet in the masked copy (a whole number past 2**53: its digits, as text); None for any other cell, which is restored
        as text (see `text`). Two copies of one scope that put different values there are not guessed between."""
        exacts = self._cells.get((sheet, address), {}).get(text)
        if not exacts or len(exacts) != 1 or text not in self._kind_of:
            return None
        exact = next(iter(exacts))
        value = display.parse(exact)
        if value is None:
            return None
        self.counts[self._kind_of[text]] += 1
        # past 2**53 a whole number is no double, and the library writes 16 digits and a power of ten: it comes back as its digits
        return exact if isinstance(value, int) and abs(value) > display.EXACT_INT else value

    def _read(self, value, text: str, number_format: str) -> tuple[str, str] | None:
        """(kind, the text that was seen) for a cell, or None when neither reading has anything to mask. A kind that is no number
        kind (a card, a phone number, a term of the dictionary) wins in whichever reading it is found: a float is shown with 15
        digits, and a card of 16 is no card there."""
        shown = display.shown(value, number_format)
        in_shown = detect(shown, self.level, self.config, ner=[])
        in_text = detect(text, self.level, self.config, ner=[])
        seen = shown.strip() or text  # a format that shows nothing leaves the exact text to stand for the cell
        strict = [d for d in in_shown + in_text if d.kind not in NUMBER_KINDS]
        if strict:
            return _longest(strict), seen
        if not in_shown and not in_text:
            return None
        if isinstance(value, datetime.date):  # also a datetime: a date cell is a date, whatever part of it the format shows
            return "DATE", seen
        return _longest(in_shown or in_text), seen


def _longest(found) -> str:
    """The kind of the longest finding, of the first of equals."""
    return max(found, key=lambda d: (d.end - d.start, -d.start)).kind


def _index(tokens: list[str]) -> dict[tuple[str, str], dict[str, set[str]]]:
    """(sheet, address) -> marker -> the exact texts that the copies of a scope put there, from the tokens that keep_cells saved."""
    index: dict[tuple[str, str], dict[str, set[str]]] = {}
    for token in tokens:
        try:
            for sheet, cells in json.loads(token)["xlsx"].items():
                for address, (marker, exact) in cells.items():
                    index.setdefault((sheet, address), {}).setdefault(marker, set()).add(exact)
        except (ValueError, KeyError, TypeError, AttributeError):
            continue  # a token that is not whole: its cells come back as text
    return index


def plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def need(module: str):
    """Import a module of the formats extra, or say how to get it. Not from PyPI: the package is not published there."""
    try:
        return importlib.import_module(module)
    except ImportError:
        raise FormatError(FORMATS_EXTRA) from None


def has_extra_properties(archive: zipfile.ZipFile) -> bool:
    """Office properties beyond the core ones that hold the text of a person: custom properties, a company or a manager.
    Neither python-docx nor openpyxl carries them over."""
    names = archive.namelist()
    for name, pattern in (("docProps/custom.xml", CUSTOM), ("docProps/app.xml", COMPANY)):
        if name in names:
            with archive.open(name) as part:
                if pattern.search(part.read(PEEK)):
                    return True
    return False


def looks_like_address(text: str) -> bool:
    return bool(ADDRESS_SCHEME.match(text) or ADDRESS_MARK.search(text) or ADDRESS_NAME.fullmatch(text))


def lists_link_addresses(archive: zipfile.ZipFile) -> bool:
    """Does the extended properties part (docProps/app.xml) list the address of a link? Word keeps such a list apart from
    the text of the document. The name of a bookmark (the links of a table of contents) is no address, as in the document
    itself, whatever script it is written in."""
    if "docProps/app.xml" not in archive.namelist():
        return False
    with archive.open("docProps/app.xml") as part:
        xml = part.read(PEEK)
    start = LINK_LIST_START.search(xml)
    if start is None:
        return False
    end = LINK_LIST_END.search(xml, start.end())
    texts = LINK_TEXT.finditer(xml, start.end(), end.start() if end else len(xml))
    return any(looks_like_address(text.group(1).decode("utf-8", "replace").strip()) for text in texts)


def thumbnail_lost(src: Path, copy: Path) -> bool:
    """Does the source hold a thumbnail that the copy does not? The copy starts from the library's template, and the one of
    python-docx carries a picture of its own, so a file made by a script has the same one and loses nothing."""
    with zipfile.ZipFile(src) as old, zipfile.ZipFile(copy) as new:
        kept = set(new.namelist())
        return any(
            name not in kept or old.getinfo(name).file_size != new.getinfo(name).file_size or old.read(name) != new.read(name)
            for name in old.namelist()
            if name.startswith(THUMBNAIL)
        )


def has(names: list[str], *prefixes: str) -> bool:
    """Does the package hold a part whose name starts with one of the prefixes?"""
    return any(name.startswith(prefixes) for name in names)


def _converter(suffix: str) -> Callable[[Path, Path, Pipe], Parts]:
    from . import documents, tabular

    return {
        ".csv": tabular.convert_csv,
        ".xlsx": tabular.convert_xlsx,
        ".docx": documents.convert_docx,
        ".pdf": documents.convert_pdf,
        ".txt": documents.convert_text,
    }[suffix]


def _require(suffix: str, allowed: frozenset[str]) -> None:
    if suffix not in allowed:
        raise FormatError(UNSUPPORTED[allowed])


def _convert(src: Path, dest: Path, pipe: Pipe) -> Parts:
    """Build dest as a part file that nobody else can reach (see staging) and move it into place: a failure leaves no half-written
    file, and a link planted where the part file used to go takes nothing."""
    src.stat()  # a missing source is a plain FileNotFoundError
    if dest.exists() and os.path.samefile(src, dest):  # also a link, or another spelling on a case-blind file system
        raise FormatError("the output would replace the source file")
    try:
        with staging(dest) as part:
            parts = _converter(src.suffix.lower())(src, part, pipe)
            os.replace(part, dest)
    except BaseException as error:
        if isinstance(error, Exception) and not isinstance(error, (FormatError, OSError)):
            # library messages can quote file content
            raise FormatError(CANNOT_PROCESS[src.suffix.lower()]) from None
        raise
    return parts


def mask_file(
    src: Path, dest: Path, markers: MarkerMap, *, level: int = 2, config: DetectConfig | None = None, delimiter: str | None = None
) -> FileReport:
    """Write a masked clean copy of src to dest (a PDF becomes a .txt file) and report what was checked and what was
    left out. markers gains the new markers even when this raises: save the map only after it returns. delimiter: of a csv file,
    when the person names it."""
    src, dest = Path(src), Path(dest)
    suffix = src.suffix.lower()
    _require(suffix, SUPPORTED)
    if suffix == ".pdf" and dest.suffix.lower() != ".txt":
        raise FormatError("a pdf is masked to a .txt file")
    pipe = Pipe(markers, level=level, config=config, delimiter=delimiter)
    parts = _convert(src, dest, pipe)
    source, output = (mask_path(p.name, markers, level, config)[0] for p in (src, dest))
    return FileReport(source, output, suffix[1:], parts.checked, parts.dropped, dict(pipe.counts), parts.complete)


def restore_file(
    src: Path, dest: Path, markers: MarkerMap, *, kinds: frozenset[str] = frozenset(), delimiter: str | None = None
) -> tuple[FileReport, list[str]]:
    """Put the originals back into a masked file. The second value lists the unknown and half-broken markers met;
    [] means the restore was exact."""
    src, dest = Path(src), Path(dest)
    suffix = src.suffix.lower()
    if suffix == ".pdf":
        raise FormatError("a pdf is restored from the .txt made from it")
    _require(suffix, RESTORABLE)
    pipe = Pipe(markers, restoring=True, kinds=kinds, delimiter=delimiter)
    parts = _convert(src, dest, pipe)
    kind = "pdf" if suffix == ".txt" else suffix[1:]
    report = FileReport(src.name, dest.name, kind, parts.checked, parts.dropped, dict(pipe.counts), parts.complete)
    return report, list(dict.fromkeys(pipe.anomalies))
