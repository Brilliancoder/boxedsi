"""CSV and XLSX clean copies."""

import csv
import io
import re
import zipfile
from pathlib import Path

from ..detect.patterns import names_a_secret
from . import FormatError, Parts, Pipe, has, has_extra_properties, need, plural, thumbnail_lost

BOM = "\N{BYTE ORDER MARK}"
LINE_END = re.compile(r"(?:\r\n|\n|\r)\Z")
FORMULA = re.compile(rb"<(?:\w+:)?f[\s/>]")  # a formula element in sheet xml
SHEET_PREFIX = "xl/worksheets/sheet"
BAD_TITLE_CHARS = re.compile(r"[\\*?:/]")
CORE_TEXT = ("creator", "lastModifiedBy", "title", "subject", "keywords", "description", "category")  # the Summary tab
PRINT_SLOTS = ("oddHeader", "oddFooter", "evenHeader", "evenFooter", "firstHeader", "firstFooter")
# the codes of a print header: a font ("..."), a color, a size, a field or toggle (&P, &A, &B, ...) and "&&"
PRINT_CODE = re.compile(r'&(?:"[^"]*"|K(?:[0-9A-Fa-f]{6}|[0-9]{2}[+-][0-9]{3})|[0-9]+|[A-Za-z&])')
# the words that label the codes in the defaults of Excel and LibreOffice ("Page &P of &N"), in a few languages
FIXED_WORDS = frozenset(
    "page pages p pp of sheet tab file date time "  # English
    "seite von blatt datei datum zeit "  # German
    "sur feuille fichier heure "  # French (page, date)
    "pagina página de hoja archivo fecha hora "  # Spanish
    "di foglio data ora "  # Italian (pagina, file)
    "страница стр из лист файл дата время".split()  # Russian
)
PAREN_MARKER = re.compile(r"\((\s*[A-Za-z][A-Za-z0-9_]*?[_\- ]\d+\s*)\)")  # the forms of a marker that the restore reports


DELIMITERS = (",", ";", "\t", "|")
AMBIGUOUS_DELIMITER = (
    "the delimiter of this csv file cannot be told for sure: name it (boxed mask-file --delimiter comma, semicolon, tab or pipe)"
)


def _records(body: str, delimiter: str) -> list[list[str]]:
    """The rows that hold anything, as this delimiter cuts them."""
    return [row for row in csv.reader(io.StringIO(body, newline=""), delimiter=delimiter) if any(cell.strip() for cell in row)]


def _fits(rows: list[list[str]], delimiter: str) -> bool:
    """Do the data rows fit the header that this delimiter makes? A row may be shorter (an empty last field left out), not wider
    unless what is past the header is empty, and a row of one cell under a header of several must not hold another delimiter:
    that row was cut with another one."""
    width, others = len(rows[0]), [d for d in DELIMITERS if d != delimiter]
    for row in rows[1:]:
        if len(row) > width and any(cell.strip() for cell in row[width:]):
            return False
        if width >= 2 and len(row) == 1 and any(d in row[0] for d in others):
            return False
    return True


def _delimiter(body: str, named: str | None = None) -> str:
    """The delimiter named, or the one that the header and every data row agree on. The header must make two cells or more with
    it and the rows must fit (_fits); when no delimiter does, the file is one column, cut by none that fits. Two that fit, or none,
    is a refusal: a wrong guess makes the header one cell, and the values under a secret header are then copied as they are."""
    if named is not None:
        return named
    wide, narrow = [], []
    for delimiter in DELIMITERS:
        rows = _records(body, delimiter)
        if not rows:
            return ","
        (wide if len(rows[0]) >= 2 else narrow).append((delimiter, _fits(rows, delimiter)))
    fitting = [d for d, ok in (wide or narrow) if ok]
    if len(fitting) == 1 or (fitting and not wide):
        return fitting[0]
    raise FormatError(AMBIGUOUS_DELIMITER)


def _line_end(body: str, delimiter: str) -> str:
    """How the first record ends (a quoted cell may hold line breaks of its own); CRLF when it does not end."""
    stream = io.StringIO(body, newline="")
    next(csv.reader(stream, delimiter=delimiter), None)
    found = LINE_END.search(body[: stream.tell()])
    return found.group() if found else "\r\n"


def convert_csv(src: Path, out: Path, pipe: Pipe) -> Parts:
    """Every cell goes through the pipe; the delimiter, line ending, final newline and BOM of the input are kept.
    Quoting is minimal, so a file that quotes more than it must comes back with the same cells but fewer quotes."""
    try:
        text = src.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        raise FormatError("not UTF-8") from None
    if "\x00" in text:  # UTF-16 or UTF-32 without a BOM: ASCII text in them decodes as UTF-8 with NUL between the letters
        raise FormatError("not UTF-8 (NUL characters found; UTF-16 and UTF-32 are not supported)")
    bom = text.startswith(BOM)
    body = text.removeprefix(BOM)
    delimiter = _delimiter(body, pipe.delimiter)
    line_end = _line_end(body, delimiter)
    dialect = {"delimiter": delimiter, "lineterminator": line_end}
    read = list(csv.reader(io.StringIO(body, newline=""), **dialect))
    header = next((i for i, row in enumerate(read) if any(cell.strip() for cell in row)), len(read))
    secret = _secret_columns(read[header] if header < len(read) else []) if not pipe.restoring else set()
    rows = [
        [pipe.secret(cell) if i > header and k in secret else pipe.text(cell) for k, cell in enumerate(row)]
        for i, row in enumerate(read)
    ]
    buffer = io.StringIO(newline="")
    csv.writer(buffer, **dialect).writerows(rows)
    data = buffer.getvalue()
    if rows and not body.endswith(("\r", "\n")):
        data = data.removesuffix(line_end)
    out.write_bytes(((BOM if bom else "") + data).encode("utf-8"))
    columns = max(map(len, rows), default=0)
    return Parts([f"{plural(len(rows), 'row')}, {plural(columns, 'column')}"], [], True)


def _secret_columns(header) -> set[int]:
    """The columns whose header names a secret: every value under it is masked whole (Pipe.secret), not only one that looks like a
    secret. The header is the first row that holds anything."""
    return {k for k, cell in enumerate(header) if isinstance(cell, str) and names_a_secret(cell)}


def _secret_headers(openpyxl, sheet, rows: set[int], columns: set[int]) -> dict[int, list[tuple[int, int | None]]]:
    """column -> (header row, last row or None) of every header cell that names a secret. The headers are the first row that holds
    a value, the first row that holds a visible value (a hidden row above the header must not hide it) and the header row of each
    table the sheet declares (Insert > Table), which counts down to the end of its table."""
    found: dict[int, list[tuple[int, int | None]]] = {}
    first = next((cell.row for cell in _cells(sheet) if cell.value is not None), None)
    shown = next(
        (cell.row for cell in _cells(sheet) if cell.value is not None and cell.row not in rows and cell.column not in columns), None
    )
    spans = [(row, None, None, None) for row in {first, shown} if row is not None]
    for table in sheet.tables.values():
        if table.headerRowCount != 0:  # None is the default: one header row
            min_col, min_row, max_col, max_row = openpyxl.utils.cell.range_boundaries(table.ref)
            spans.append((min_row, max_row, min_col, max_col))
    for row, last, low, high in spans:
        for (at_row, column), cell in sheet._cells.items():
            if at_row == row and (low is None or low <= column <= high):
                if isinstance(cell.value, str) and names_a_secret(cell.value):
                    found.setdefault(column, []).append((row, last))
    return found


def _under(headers: dict[int, list[tuple[int, int | None]]], row: int, column: int) -> bool:
    """Is the cell below a header that names a secret, inside the span of that header?"""
    return any(header < row and (last is None or row <= last) for header, last in headers.get(column, ()))


def _digits(value) -> str | None:
    """The digits of a whole number, as a text cell would hold them: the detectors read digits (a card number is often stored
    as a number), not numbers. None for text, booleans, fractions and everything else."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value)
    return str(int(value)) if isinstance(value, float) and value.is_integer() else None


def _hidden_columns(sheet) -> set[int]:
    """The numbers of the hidden columns. One column element may cover a range; only the used part of the sheet matters."""
    hidden: set[int] = set()
    for dimension in sheet.column_dimensions.values():
        if dimension.hidden:
            dimension.reindex()  # min and max, taken from the column letter when the file leaves them out
            hidden.update(range(dimension.min, min(dimension.max, sheet.max_column) + 1))
    return hidden


def _formula_cells(openpyxl, src: Path) -> dict[str, set[tuple[int, int]]]:
    """The (row, column) of every formula cell, by sheet title. A second look at the file, because the workbook that holds
    the cached results has no formulas in it."""
    book = openpyxl.load_workbook(src)
    return {
        sheet.title: {(cell.row, cell.column) for cell in _cells(sheet) if cell.data_type == "f"}
        for sheet in book.worksheets
    }


def _results(sheet, formulas: set[tuple[int, int]], rows: set[int], columns: set[int]) -> tuple[int, int]:
    """How many of the formula cells that the copy keeps have a cached result, and how many have none. Excel stores a result
    that is the empty text as t="str" without a value, and the sheet keeps that type."""
    kept = empty = 0
    for row, column in formulas:
        if row in rows or column in columns:
            continue
        cell = sheet.cell(row=row, column=column)
        if cell.value is None and cell.data_type != "str":
            empty += 1
        else:
            kept += 1
    return kept, empty


def _cells(sheet):
    """The cells that are in the file, row by row. iter_rows would also make up every empty cell of the bounding box,
    and one styled cell far away turns that into millions."""
    return (sheet._cells[at] for at in sorted(sheet._cells))


def _start(text: str, limit: int) -> str:
    """The longest start of text that fits in limit UTF-16 code units, which is how Excel counts the length of a sheet
    title: a character outside the Basic Multilingual Plane (an emoji) counts twice and is never cut in two."""
    used = 0
    for at, char in enumerate(text):
        used += 2 if ord(char) > 0xFFFF else 1
        if used > limit:
            return text[:at]
    return text


def _fit_title(wanted: str, taken: list[str]) -> str:
    """A sheet title Excel accepts: without the characters it forbids, 31 UTF-16 code units at most and not one of those
    taken (case does not matter). A title that is taken gives up its last characters for a number; openpyxl would add
    the number and go past 31, which Excel refuses."""
    base = BAD_TITLE_CHARS.sub("_", wanted)
    used = {title.lower() for title in taken}
    title, number = _start(base, 31), 1
    while title.lower() in used:
        number += 1
        suffix = f"_{number}"
        title = _start(base, 31 - len(suffix)) + suffix
    return title


def _printed(sheet) -> bool:
    """Is there text of the document in a print header or footer of the sheet? They belong to the page setup and show in
    no cell. The codes (&A, &P, ...) and the fixed words around them ("Page &P of &N") are not text of the document:
    LibreOffice puts the sheet name and the page number on every sheet. Any other word is."""
    items = (getattr(sheet, slot) for slot in PRINT_SLOTS)
    texts = (part.text or "" for item in items for part in (item.left, item.center, item.right))
    words = (word for text in texts for word in re.findall(r"\w+", PRINT_CODE.sub(" ", text)))
    return any(word.lower() not in FIXED_WORDS for word in words)


def _own_properties(book, clean) -> bool:
    """Does the workbook hold text in its core properties (author, title, ...) that the new one does not? The new one
    starts from the library's defaults, so the library's own name in a file made by a script does not count."""
    return any(
        (value := getattr(book.properties, name) or "").strip() and value != getattr(clean.properties, name)
        for name in CORE_TEXT
    )


def _bracketed(title: str) -> str:
    """Excel allows no brackets in a sheet name, so a marker sits there as (KIND_1). Every paren form of a marker, in any
    case and with "_", "-" or a space, is read as the bracket form. A name a model changed is then reported like a cell,
    and a sheet that was named like a marker to begin with is masked as the plain text it is."""
    return PAREN_MARKER.sub(r"[\1]", title)


def convert_xlsx(src: Path, out: Path, pipe: Pipe) -> Parts:
    """A new workbook from the values of the visible sheets, without their hidden rows and columns: strings go through
    the pipe, and so do numbers (a number it changes becomes text). From level 3 on that is every number, date and time,
    read as Excel shows it (see display). Below that only whole numbers do; decimals, dates and times stay as they are.
    Booleans always stay. Markers sit in sheet names as (KIND_1), because Excel does not allow brackets there. What the
    copy does not hold (link targets, print headers and footers, comments, properties, ...) is named."""
    openpyxl = need("openpyxl")
    with zipfile.ZipFile(src) as archive:
        names = archive.namelist()
        formulas = any(FORMULA.search(archive.read(n)) for n in names if n.startswith(SHEET_PREFIX))
        extra = has_extra_properties(archive)
    book = openpyxl.load_workbook(src, data_only=True)  # the cached result of a formula, not the formula
    formula_cells = _formula_cells(openpyxl, src) if formulas else {}
    clean = openpyxl.Workbook()
    clean.remove(clean.active)
    numbers = pipe.level >= 3 and not pipe.restoring  # from level 3 on every number and date cell is read, not only the whole numbers
    checked, dropped, visible = [], [], []
    hidden_rows = hidden_columns = False  # did a hidden row or column hold a value that the copy leaves out?
    linked = printed = False  # did a cell hold the address of a link, did a sheet have a print header or footer?
    cached = uncalculated = 0  # formula cells with and without a cached result
    for sheet in book.worksheets:
        name = _bracketed(sheet.title)
        label = pipe.label(name)
        if sheet.sheet_state != "visible":
            dropped.append(f"{'very hidden' if sheet.sheet_state == 'veryHidden' else 'hidden'} sheet {label}")
            continue
        visible.append(sheet)
        checked.append(f"sheet {label}")
        printed = printed or _printed(sheet)
        wanted = pipe.text(name).replace("[", "(").replace("]", ")")
        copy = clean.create_sheet(_fit_title(wanted, clean.sheetnames))
        if copy.title != wanted:
            reason = "invalid characters, over 31 characters or a duplicate"
            dropped.append(f"sheet name {label} changed to fit Excel ({reason})")
        rows = {number for number, dimension in sheet.row_dimensions.items() if dimension.hidden}
        columns = _hidden_columns(sheet)
        headers = {} if pipe.restoring else _secret_headers(openpyxl, sheet, rows, columns)
        for cell in _cells(sheet):
            if cell.value is None:
                continue
            in_row, in_column = cell.row in rows, cell.column in columns
            if in_row or in_column:  # not shown, not copied; the cells that stay keep their address
                hidden_rows, hidden_columns = hidden_rows or in_row, hidden_columns or in_column
                continue
            linked = linked or bool(cell.hyperlink and cell.hyperlink.target)
            target = copy.cell(row=cell.row, column=cell.column)
            value = cell.value
            if _under(headers, cell.row, cell.column) and not isinstance(value, bool):
                value = pipe.secret(value, (copy.title, cell.coordinate))  # a number keeps its type through the restore
            elif isinstance(value, str):
                # restoring: the marker of a number or date cell, alone in the same cell of the same sheet, is a number or a date again
                typed = pipe.typed(sheet.title, cell.coordinate, value) if pipe.restoring else None
                value = pipe.text(value) if typed is None else typed
            elif numbers:  # a number or date that the masker changes becomes text
                value = pipe.number(value, cell.number_format, (copy.title, cell.coordinate)) or value
            elif (digits := _digits(value)) is not None and (masked := pipe.text(digits)) != digits:
                value = masked  # a whole number the masker changes becomes the masked text
            target.value = value
            if target.data_type == "f":  # a text that starts with "=" must not become a formula
                target.data_type = "s"
        kept, empty = _results(sheet, formula_cells.get(sheet.title, set()), rows, columns)
        cached, uncalculated = cached + kept, uncalculated + empty
    pipe.keep_cells()
    if hidden_rows:
        dropped.append("hidden rows")
    if hidden_columns:
        dropped.append("hidden columns")
    if has(names, "xl/comments", "xl/threadedComments"):
        dropped.append("comments")
    if has(names, "xl/media/", "xl/charts/", "xl/chartsheets/", "xl/embeddings/", "xl/drawings/drawing"):
        dropped.append("images and charts")
    if book.defined_names or any(sheet.defined_names for sheet in visible):
        dropped.append("defined names")
    if any(sheet.data_validations.dataValidation for sheet in visible):
        dropped.append("data validation")
    if has(names, "xl/externalLinks/"):
        dropped.append("external links")
    if has(names, "xl/pivotCache/", "xl/pivotTables/"):  # a pivot cache keeps a copy of its source data
        dropped.append("pivot tables")
    if linked:  # the text of a link stays in its cell
        dropped.append("hyperlink targets")
    if printed:
        dropped.append("print headers and footers")
    complete = not dropped and not uncalculated
    if cached:
        dropped.append("formulas (cached values kept)")  # what the sheet shows was checked, so the copy stays complete
    if uncalculated:  # empty cells where a formula stood: a workbook a script wrote has no results, and nothing was checked
        dropped.append(f"formulas without cached values (left empty): {uncalculated}")
    if extra or _own_properties(book, clean):  # a note: every file from Office has an author, and none of it reaches the copy
        dropped.append("document properties")
    clean.save(out)
    if thumbnail_lost(src, out):  # a note too: a picture of the first sheet, whose cells were checked
        dropped.append("document thumbnail")
    return Parts(checked, dropped, complete)
