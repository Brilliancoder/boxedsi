"""DOCX and PDF clean copies, and the restore of a masked PDF text."""

import logging
import re
import zipfile
from contextlib import contextmanager
from pathlib import Path

from . import FormatError, Parts, Pipe, has, has_extra_properties, lists_link_addresses, need, plural, thumbnail_lost

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
M = "{http://schemas.openxmlformats.org/officeDocument/2006/math}"
R = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
NAMED = frozenset(W + tag for tag in ("drawing", "pict", "object", "ins", "moveTo", "sdt"))  # the report names these already
CONTENT_PARTS = re.compile(r"word/(?:document|header\d*|footer\d*)\.xml")
HEADER_FOOTER = ("header", "footer", "first_page_header", "first_page_footer", "even_page_header", "even_page_footer")
CORE_TEXT = ("author", "last_modified_by", "title", "subject", "keywords", "comments", "category")  # the Summary tab
# an address after the word, quoted (a UNC path starts with backslashes) or not; a switch such as \l is none
LINK_FIELD = re.compile(r'HYPERLINK\s+(?:"[^"]|[^\s"\\])', re.IGNORECASE)


def _grid(table) -> list[list]:
    """The cells of a table row by row. The place a merged cell covers is None, so every text is read once."""
    seen, rows = set(), []
    for row in table.rows:
        cells = []
        for cell in row.cells:
            cells.append(None if cell._tc in seen else cell)
            seen.add(cell._tc)
        rows.append(cells)
    return rows


def _text(paragraph, hidden: list[str]) -> str:
    """The text of a paragraph as a reader sees it. The text of hidden runs (w:vanish) is left out and added to hidden."""
    shown = []
    for part in paragraph.iter_inner_content():
        for run in getattr(part, "runs", (part,)):  # a hyperlink holds runs of its own
            (hidden if run.font.hidden else shown).append(run.text)
    return "".join(shown)


def _texts(container, hidden: list[str]) -> list[str]:
    """The paragraph texts of a body, cell, header or footer; a nested table is read cell by cell."""
    texts = []
    for block in container.iter_inner_content():
        if hasattr(block, "rows"):
            texts += [text for row in _grid(block) for cell in row if cell is not None for text in _texts(cell, hidden)]
        else:
            texts.append(_text(block, hidden))
    return texts


def _add_table(clean, table, pipe: Pipe, hidden: list[str]) -> None:
    grid = _grid(table)
    width = max(map(len, grid), default=0)
    if not width:
        return
    copy = clean.add_table(rows=len(grid), cols=width, style="Table Grid")
    for r, row in enumerate(grid):
        for c, cell in enumerate(row):
            if cell is not None:
                copy.cell(r, c).text = pipe.text("\n".join(_texts(cell, hidden)))


def _copy_headers(source, clean, pipe: Pipe, hidden: list[str]) -> tuple[bool, bool]:
    """The headers and footers of the first section, every variant it defines. The first value is True when there were
    any, the second when one holds text that no paragraph we read accounts for (a field)."""
    if not source.sections:
        return False, False
    first, copy = source.sections[0], clean.sections[0]
    copy.different_first_page_header_footer = first.different_first_page_header_footer
    clean.settings.odd_and_even_pages_header_footer = source.settings.odd_and_even_pages_header_footer
    found = unread = False
    for name in HEADER_FOOTER:
        old = getattr(first, name)
        if old.is_linked_to_previous:  # no definition of its own
            continue
        found, new = True, getattr(copy, name)
        new.is_linked_to_previous = False
        start = len(hidden)
        read = _texts(old, hidden)
        unread = unread or _unaccounted(old._element, read + hidden[start:])
        texts = [pipe.text(text) for text in read] or [""]
        new.paragraphs[0].text = texts[0]
        for text in texts[1:]:
            new.add_paragraph(text)
    return found, unread


def _present(roots, *tags: str) -> bool:
    return any(next(root.iter(*(W + tag for tag in tags)), None) is not None for root in roots)


def _letters(text: str | None) -> int:
    return len("".join((text or "").split()))


def _present_letters(root) -> int:
    """The letters in the texts under root, except those inside something the report names already. python-docx reads
    a w:noBreakHyphen as "-", so it counts as one letter here too."""
    return sum(
        1 if t.tag == W + "noBreakHyphen" else _letters(t.text)
        for t in root.iter(W + "t", M + "t", W + "noBreakHyphen")
        if not NAMED.intersection(a.tag for a in t.iterancestors())
    )


def _unaccounted(root, read: list[str]) -> bool:
    """Is there more text under root than the paragraphs we read hold (fields, smart tags, equations)? The text of
    hidden runs is part of what was read: it was read and left out, and the report names it."""
    return _present_letters(root) > sum(map(_letters, read))


def _unread_text(source) -> bool:
    """Is there text in the body that no paragraph we read accounts for?"""
    hidden: list[str] = []
    read = _texts(source, hidden)
    return _unaccounted(source.element, read + hidden)


def _field_codes(root) -> list[str]:
    """The instruction of every field in a part. A simple field holds it in an attribute; a complex one spreads it over
    the w:instrText runs between its begin and its separate mark, cut wherever the editing happened."""
    codes: list[str] = []
    open_fields: list[list[str] | None] = []  # the pieces of each open field; None once its shown text has begun
    for element in root.iter(W + "fldSimple", W + "fldChar", W + "instrText"):
        if element.tag == W + "fldSimple":
            codes.append(element.get(W + "instr", ""))
        elif element.tag == W + "instrText":
            if open_fields and open_fields[-1] is not None:
                open_fields[-1].append(element.text or "")
            else:  # outside a field, or among its shown text: read it on its own
                codes.append(element.text or "")
        else:
            mark = element.get(W + "fldCharType")
            if mark == "begin":
                open_fields.append([])
            elif mark == "separate" and open_fields and open_fields[-1] is not None:
                codes.append("".join(open_fields[-1]))
                open_fields[-1] = None
            elif mark == "end" and open_fields:
                pieces = open_fields.pop()
                if pieces is not None:  # a field without shown text
                    codes.append("".join(pieces))
    codes += ["".join(pieces) for pieces in open_fields if pieces is not None]  # a field that was never closed
    return codes


def _linked(roots) -> bool:
    """Does a part hold the address of a link, in a hyperlink element or a HYPERLINK field? The copy keeps the text of
    a link, never its target. A link to a bookmark of the same document holds no address."""
    for root in roots:
        if any(link.get(R + "id") for link in root.iter(W + "hyperlink")):
            return True
        if any(LINK_FIELD.search(code) for code in _field_codes(root)):
            return True
    return False


def _own_properties(source, clean) -> bool:
    """Does the source hold text in its core properties (author, title, ...) that the new document does not? The new
    document starts from the library's template, so the library's own text in a file made by a script does not count."""
    return any(
        (value := getattr(source.core_properties, name)).strip() and value != getattr(clean.core_properties, name)
        for name in CORE_TEXT
    )


def _has_notes(archive: zipfile.ZipFile, parse, kind: str) -> bool:
    """Real footnotes or endnotes: Word writes the part even when it holds only the separators."""
    part = f"word/{kind}s.xml"
    if part not in archive.namelist():
        return False
    return any(note.get(W + "type") in (None, "normal") for note in parse(archive.read(part)).iter(W + kind))


def convert_docx(src: Path, out: Path, pipe: Pipe) -> Parts:
    """A new document from the body paragraphs (with their style names), the tables and the first section's headers and
    footers; every text goes through the pipe, and hidden text is left out. What python-docx does not read and the copy
    does not hold (link targets, text in fields, document properties, ...) is named."""
    docx = need("docx")
    source = docx.Document(str(src))
    clean = docx.Document()
    styles = {style.name for style in clean.styles}
    hidden: list[str] = []  # the text of hidden runs, which the copy leaves out
    for block in source.iter_inner_content():
        if hasattr(block, "rows"):
            _add_table(clean, block, pipe, hidden)
        else:
            style = block.style.name
            clean.add_paragraph(pipe.text(_text(block, hidden)), style=style if style in styles else None)
    headers, header_fields = _copy_headers(source, clean, pipe, hidden)
    checked = ["body"] + (["tables"] if source.tables else []) + (["headers and footers"] if headers else [])

    parse = docx.oxml.parse_xml  # refuses to resolve entities
    with zipfile.ZipFile(src) as archive:
        names = archive.namelist()
        roots = [parse(archive.read(name)) for name in names if CONTENT_PARTS.fullmatch(name)]
        footnotes, endnotes = (_has_notes(archive, parse, kind) for kind in ("footnote", "endnote"))
        extra = has_extra_properties(archive)
        listed = lists_link_addresses(archive)
    later = any(
        _present_letters(getattr(section, name)._element)  # any text, a field's included
        for section in source.sections[1:]
        for name in HEADER_FOOTER
        if not getattr(section, name).is_linked_to_previous
    )
    pictures = _present(roots, "drawing", "pict", "object") or has(names, "word/media/", "word/embeddings/")
    found = {
        "comments": has(names, "word/comments"),
        "tracked changes": _present(roots, "ins", "del", "moveFrom", "moveTo"),
        "hidden text": any(text.strip() for text in hidden),
        "images and embedded objects": pictures,
        "footnotes": footnotes,
        "endnotes": endnotes,
        "content controls": _present(roots, "sdt"),
        "headers and footers of later sections": later,
        "other text (fields, smart tags, equations)": _unread_text(source),
        "other text in headers and footers (fields, smart tags, equations)": header_fields,
        "hyperlink targets": _linked(roots) or listed,
    }
    dropped = [what for what, there in found.items() if there]
    complete = not dropped
    clean.save(str(out))
    # notes, like the formatting: every file from Office has an author, and none of it reaches the copy; a thumbnail is a
    # picture of the first page, whose text was checked
    notes = ["document properties"] if extra or _own_properties(source, clean) else []
    if thumbnail_lost(src, out):
        notes.append("document thumbnail")
    return Parts(checked, dropped + notes + ["character formatting"], complete)


@contextmanager
def _silent(name: str):
    """pypdf warns through logging, and some warnings quote the first bytes of a file it cannot read."""
    logger = logging.getLogger(name)
    level = logger.level
    logger.setLevel(logging.CRITICAL + 1)
    try:
        yield
    finally:
        logger.setLevel(level)


def convert_pdf(src: Path, out: Path, pipe: Pipe) -> Parts:
    """The text layer of every page, masked, as a .txt file. Images, annotations, attachments and document properties are
    never read, so a PDF is never complete: without OCR what a picture shows stays unchecked."""
    pypdf = need("pypdf")
    with _silent("pypdf"):
        reader = pypdf.PdfReader(str(src))
        if reader.is_encrypted and not reader.decrypt(""):  # only an owner password can be opened without asking
            raise FormatError("the pdf is password protected")
        pages = [page.extract_text() for page in reader.pages]
    out.write_bytes(pipe.text("\n\n".join(pages)).encode("utf-8", "replace"))
    dropped = ["images", "annotations", "attachments", "document properties"]
    return Parts([f"text layer of {plural(len(pages), 'page')}"], dropped, False)


def convert_text(src: Path, out: Path, pipe: Pipe) -> Parts:
    """The masked text of a PDF, restored."""
    try:
        text = src.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        raise FormatError("not UTF-8") from None
    out.write_bytes(pipe.text(text).encode("utf-8"))
    return Parts(["text"], [], True)
