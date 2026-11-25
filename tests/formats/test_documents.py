import base64
import io
import logging
import re
import time
import unicodedata
import zipfile
from pathlib import Path

import docx
import openpyxl
import pypdf
import pytest
from docx.opc.constants import RELATIONSHIP_TYPE
from docx.opc.packuri import PackURI
from docx.opc.part import Part
from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls

from boxed.detect import DetectConfig
from boxed.formats import SUPPORTED, FormatError, mask_file, restore_file
from boxed.mask import MarkerMap, dictionary_kinds

from . import EMPTY_CUSTOM_PROPERTIES, assert_clean, rewrite_zip

PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")


def test_restore_reports_unknown_markers(tmp_path):
    src, masked, back = tmp_path / "in.csv", tmp_path / "masked.csv", tmp_path / "back.csv"
    src.write_bytes(b"mail,note\r\nivan@acme.com,hello\r\n")
    markers = MarkerMap()
    mask_file(src, masked, markers)
    masked.write_bytes(masked.read_bytes().replace(b"hello", b"[EMAIL_9] and [email_1]"))

    _, anomalies = restore_file(masked, back, markers)

    assert anomalies == ["[EMAIL_9]", "[email_1]"]  # unknown first, then half-broken
    assert back.read_bytes() == b"mail,note\r\nivan@acme.com,[EMAIL_9] and [email_1]\r\n"


@pytest.mark.parametrize("name", ["notes.txt", "sheet.xls", "letter.doc", "deck.pptx", "README"])
def test_unsupported_suffix_rejected(tmp_path, name):
    src, dest = tmp_path / name, tmp_path / "out.bin"
    src.write_text("ivan@acme.com")

    with pytest.raises(FormatError, match="unsupported file type"):
        mask_file(src, dest, MarkerMap())

    assert not dest.exists()
    assert SUPPORTED == frozenset({".csv", ".xlsx", ".docx", ".pdf"})


def csv_source(path):
    path.write_bytes(b"a,b\r\nivan@acme.com,x\r\n")


def xlsx_source(path):
    book = openpyxl.Workbook()
    book.active.append(["ivan@acme.com"])
    book.save(path)


def fail_writing_a_file(monkeypatch):
    real = Path.write_bytes

    def half_then_fail(self, data):
        real(self, data[: len(data) // 2])
        raise OSError("disk full")

    monkeypatch.setattr(Path, "write_bytes", half_then_fail)


def docx_source(path):
    document = docx.Document()
    document.add_paragraph("ivan@acme.com")
    document.save(str(path))


def pdf_source(path):
    path.write_bytes(pdf_bytes(["mail ivan@acme.com"]))


def fail_after_saving(monkeypatch, cls):
    """The library writes the whole file, then the disk 'fills up' and the file is cut."""
    real = cls.save

    def cut_then_fail(self, target):
        real(self, target)
        Path(target).write_bytes(Path(target).read_bytes()[:100])
        raise OSError("disk full")

    monkeypatch.setattr(cls, "save", cut_then_fail)


@pytest.mark.parametrize(
    "suffix, out_suffix, make_source, break_writer",
    [
        ("csv", "csv", csv_source, fail_writing_a_file),
        ("xlsx", "xlsx", xlsx_source, lambda monkeypatch: fail_after_saving(monkeypatch, openpyxl.Workbook)),
        ("docx", "docx", docx_source, lambda monkeypatch: fail_after_saving(monkeypatch, docx.document.Document)),
        ("pdf", "txt", pdf_source, fail_writing_a_file),
    ],
)
def test_failed_write_leaves_no_partial_file(tmp_path, monkeypatch, suffix, out_suffix, make_source, break_writer):
    src, dest = tmp_path / f"in.{suffix}", tmp_path / f"out.{out_suffix}"
    make_source(src)
    dest.write_text("old copy")
    break_writer(monkeypatch)

    with pytest.raises(OSError, match="disk full"):
        mask_file(src, dest, MarkerMap())

    assert dest.read_text() == "old copy" and not (tmp_path / f"out.{out_suffix}.part").exists()


def test_output_cannot_replace_the_source(tmp_path):
    src = tmp_path / "in.csv"
    src.write_bytes(b"ivan@acme.com\r\n")

    with pytest.raises(FormatError, match="source file"):
        mask_file(src, src, MarkerMap())
    with pytest.raises(FormatError, match="source file"):
        restore_file(src, tmp_path / "." / "in.csv", MarkerMap())

    assert src.read_bytes() == b"ivan@acme.com\r\n"


def test_output_cannot_replace_the_source_under_another_spelling(tmp_path):
    src = tmp_path / "clients.csv"
    src.write_bytes(b"ivan@acme.com\r\n")
    other_case = tmp_path / "CLIENTS.CSV"
    if not other_case.exists():
        pytest.skip("this file system tells upper and lower case apart")

    with pytest.raises(FormatError, match="source file"):
        mask_file(src, other_case, MarkerMap())

    assert src.read_bytes() == b"ivan@acme.com\r\n"


@pytest.mark.parametrize("suffix", ["xlsx", "docx", "pdf"])
def test_unreadable_file_is_refused_without_echoing_it(tmp_path, suffix):
    src, dest = tmp_path / f"broken.{suffix}", tmp_path / ("broken.txt" if suffix == "pdf" else f"out.{suffix}")
    src.write_bytes(b"SECRETLEAK ivan@acme.com is not an office file")

    with pytest.raises(FormatError) as raised:
        mask_file(src, dest, MarkerMap())

    assert "SECRET" not in str(raised.value) and "acme" not in str(raised.value)
    assert not dest.exists() and not dest.with_name(dest.name + ".part").exists()


def test_report_names_are_masked(tmp_path):
    src = tmp_path / "ivan@acme.com.csv"
    src.write_text("a,b\r\n1,2\r\n")

    report = mask_file(src, tmp_path / "out.csv", MarkerMap())

    assert (report.source, report.output) == ("[EMAIL_1].csv", "out.csv")


def build_contract(path):
    document = docx.Document()
    document.core_properties.author = "ivan.author@acme.com"
    heading = document.add_paragraph("Contract with ivan@acme.com", style="Heading 1")
    document.add_paragraph("Terms\tand\nconditions")
    table = document.add_table(rows=2, cols=2)
    for (row, column), text in {(0, 0): "name", (0, 1): "phone", (1, 0): "Olga", (1, 1): "+7 999 123-45-67"}.items():
        table.cell(row, column).text = text
    document.sections[0].header.paragraphs[0].text = "Acme Corp - confidential"
    # parts that must never reach the clean copy
    document.add_comment(heading.runs, text="check with anna@secret.org", author="Ivan", initials="I")
    document.add_paragraph().add_run().add_picture(io.BytesIO(PNG + b"IMGSECRET"))
    revised = document.add_paragraph("kept ")
    revised._p.append(
        parse_xml(f'<w:del {nsdecls("w")} w:id="1" w:author="a"><w:r><w:delText>DELETED_SECRET</w:delText></w:r></w:del>')
    )
    document.save(str(path))


def table_cells(document):
    return [[cell.text for cell in row.cells] for row in document.tables[0].rows]


def test_docx_rebuilt_from_checked_parts(tmp_path):
    src, dest = tmp_path / "contract.docx", tmp_path / "contract.masked.docx"
    build_contract(src)
    config = DetectConfig(dictionary={"Acme Corp": "CLIENT"})

    report = mask_file(src, dest, MarkerMap(), config=config)

    values = ("ivan@acme.com", "+7 999 123-45-67", "Acme Corp", "anna@secret.org", "IMGSECRET", "DELETED_SECRET")
    assert_clean(dest, *values, "ivan.author@acme.com")
    clean = docx.Document(str(dest))
    assert [(p.text, p.style.name) for p in clean.paragraphs[:2]] == [
        ("Contract with [EMAIL_1]", "Heading 1"),
        ("Terms\tand\nconditions", "Normal"),
    ]
    (table,) = clean.tables
    assert (len(table.rows), len(table.columns)) == (2, 2)
    assert table_cells(clean) == [["name", "phone"], ["Olga", "[PHONE_1]"]]
    assert [p.text for p in clean.sections[0].header.paragraphs] == ["[CLIENT_1] - confidential"]
    assert report.format == "docx" and report.checked == ["body", "tables", "headers and footers"]
    assert report.dropped == [
        "comments",
        "tracked changes",
        "images and embedded objects",
        "document properties",  # the author
        "character formatting",
    ]
    assert report.markers_by_kind == {"EMAIL": 1, "PHONE": 1, "CLIENT": 1}  # the comment and the author were never looked at
    assert report.complete is False


def test_docx_restore_round_trip(tmp_path):
    src, masked, back = tmp_path / "in.docx", tmp_path / "masked.docx", tmp_path / "back.docx"
    build_contract(src)
    config = DetectConfig(dictionary={"Acme Corp": "CLIENT"})
    markers = MarkerMap()
    mask_file(src, masked, markers, config=config)

    restored, anomalies = restore_file(masked, back, markers, kinds=dictionary_kinds(config))

    assert anomalies == []
    before, after = docx.Document(str(src)), docx.Document(str(back))
    assert [(p.text, p.style.name) for p in after.paragraphs] == [(p.text, p.style.name) for p in before.paragraphs]
    assert table_cells(after) == table_cells(before)
    assert [p.text for p in after.sections[0].header.paragraphs] == ["Acme Corp - confidential"]
    assert restored.format == "docx" and restored.markers_by_kind == {"EMAIL": 1, "PHONE": 1, "CLIENT": 1}
    assert restored.dropped == ["character formatting"] and restored.complete is True  # a clean copy loses nothing more


def add_footnotes(document, text):
    xml = (
        f'<w:footnotes {nsdecls("w")}><w:footnote w:type="separator" w:id="-1"><w:p><w:r><w:separator/></w:r></w:p></w:footnote>'
        f'<w:footnote w:id="1"><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:footnote></w:footnotes>'
    )
    content_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml"
    part = Part(PackURI("/word/footnotes.xml"), content_type, xml.encode(), document.part.package)
    document.part.relate_to(part, RELATIONSHIP_TYPE.FOOTNOTES)


def test_docx_other_text_that_is_not_copied_is_named(tmp_path):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    document = docx.Document()
    document.add_paragraph("plain body")
    inserted = document.add_paragraph("before ")
    inserted._p.append(parse_xml(f'<w:ins {nsdecls("w")} w:id="2" w:author="a"><w:r><w:t>INSERTED_SECRET</w:t></w:r></w:ins>'))
    control = parse_xml(
        f"<w:sdt {nsdecls('w')}><w:sdtPr/><w:sdtContent><w:p><w:r><w:t>CONTROL_SECRET</w:t></w:r></w:p></w:sdtContent></w:sdt>"
    )
    document.element.body.sectPr.addprevious(control)
    add_footnotes(document, "FOOTNOTE_SECRET")
    later = document.add_section()
    later.header.is_linked_to_previous = False
    later.header.paragraphs[0].text = "LATER_HEADER_SECRET"
    document.save(str(src))

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "INSERTED_SECRET", "CONTROL_SECRET", "FOOTNOTE_SECRET", "LATER_HEADER_SECRET")
    assert report.checked == ["body"]
    assert report.dropped == [
        "tracked changes",
        "footnotes",
        "content controls",
        "headers and footers of later sections",
        "character formatting",
    ]
    assert report.complete is False


def test_docx_hidden_text_is_not_copied_and_is_named(tmp_path):
    src, dest, back = tmp_path / "in.docx", tmp_path / "out.docx", tmp_path / "back.docx"
    document = docx.Document()
    mixed = document.add_paragraph("shown")
    mixed.add_run("HIDDEN_BODY_SECRET ivan@acme.com").font.hidden = True
    mixed.add_run(" and shown again")
    document.add_paragraph().add_run("switched off, still visible").font.hidden = False
    link = document.part.relate_to("https://example.com", RELATIONSHIP_TYPE.HYPERLINK, is_external=True)
    shown_run = "<w:r><w:t>the portal</w:t></w:r>"
    hidden_run = "<w:r><w:rPr><w:vanish/></w:rPr><w:t>HIDDEN_LINK_SECRET</w:t></w:r>"
    namespaces = f'{nsdecls("w")} xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
    document.add_paragraph("see ")._p.append(
        parse_xml(f'<w:hyperlink {namespaces} r:id="{link}">{shown_run}{hidden_run}</w:hyperlink>')
    )
    cell = document.add_table(rows=1, cols=1).cell(0, 0).paragraphs[0]
    cell.add_run("cell")
    cell.add_run("HIDDEN_CELL_SECRET").font.hidden = True
    header = document.sections[0].header.paragraphs[0]
    header.add_run("header")
    header.add_run("HIDDEN_HEADER_SECRET").font.hidden = True
    document.save(str(src))
    markers = MarkerMap()

    report = mask_file(src, dest, markers)

    secrets = ("HIDDEN_BODY_SECRET", "HIDDEN_LINK_SECRET", "HIDDEN_CELL_SECRET", "HIDDEN_HEADER_SECRET", "ivan@acme.com")
    assert_clean(dest, *secrets)
    clean = docx.Document(str(dest))
    texts = [p.text for p in clean.paragraphs[:3]]
    assert texts == ["shown and shown again", "switched off, still visible", "see the portal"]
    assert table_cells(clean) == [["cell"]] and clean.sections[0].header.paragraphs[0].text == "header"
    assert report.checked == ["body", "tables", "headers and footers"]
    # not "other text": it was read, then left out; the link in the body has an address of its own
    assert report.dropped == ["hidden text", "hyperlink targets", "character formatting"]
    assert report.markers_by_kind == {} and report.complete is False  # the hidden address was never looked at

    restored, anomalies = restore_file(dest, back, markers)

    assert anomalies == [] and restored.dropped == ["character formatting"] and restored.complete is True


def test_docx_hidden_text_does_not_account_for_text_that_was_not_read(tmp_path):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    document = docx.Document()
    paragraph = document.add_paragraph("before ")
    paragraph.add_run("HIDDENRUN").font.hidden = True
    wrapper = '<w:fldSimple {ns} w:instr=" REF x "><w:r><w:t>WRAPPED_SECRET</w:t></w:r></w:fldSimple>'
    paragraph._p.append(parse_xml(wrapper.format(ns=nsdecls("w"))))
    document.save(str(src))

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "HIDDENRUN", "WRAPPED_SECRET")
    assert report.dropped == ["hidden text", "other text (fields, smart tags, equations)", "character formatting"]


def test_docx_hidden_spaces_alone_are_not_reported(tmp_path):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    document = docx.Document()
    paragraph = document.add_paragraph("one")
    paragraph.add_run(" \t").font.hidden = True
    paragraph.add_run(" two")
    document.save(str(src))

    report = mask_file(src, dest, MarkerMap())

    assert [p.text for p in docx.Document(str(dest)).paragraphs] == ["one two"]
    assert report.dropped == ["character formatting"] and report.complete is True


@pytest.mark.parametrize(
    "wrapper",
    [
        '<w:fldSimple {ns} w:instr=" REF target "><w:r><w:t>WRAPPED_SECRET</w:t></w:r></w:fldSimple>',
        '<w:smartTag {ns} w:uri="urn:x" w:element="name"><w:r><w:t>WRAPPED_SECRET</w:t></w:r></w:smartTag>',
        "<m:oMath {ns}><m:r><m:t>WRAPPED_SECRET</m:t></m:r></m:oMath>",
    ],
    ids=["field", "smart tag", "equation"],
)
def test_docx_text_python_docx_cannot_read_is_named(tmp_path, wrapper):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    document = docx.Document()
    document.add_paragraph("before ")._p.append(parse_xml(wrapper.format(ns=nsdecls("w", "m"))))
    document.save(str(src))

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "WRAPPED_SECRET")
    assert report.dropped == ["other text (fields, smart tags, equations)", "character formatting"]
    assert report.complete is False


def test_docx_no_break_hyphens_do_not_hide_text_that_was_not_read(tmp_path):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    document = docx.Document()
    paragraph = document.add_paragraph()
    # python-docx reads each w:noBreakHyphen as "-": "a-b-c-d" is seven letters to the reader but only four w:t letters
    hyphens = "<w:r {ns}><w:t>a</w:t><w:noBreakHyphen/><w:t>b</w:t><w:noBreakHyphen/><w:t>c</w:t><w:noBreakHyphen/><w:t>d</w:t></w:r>"
    paragraph._p.append(parse_xml(hyphens.format(ns=nsdecls("w"))))
    # three letters in a field that nobody reads: together with the hyphens they add up to what was read
    field = '<w:fldSimple {ns} w:instr=" REF x "><w:r><w:t>QXZ</w:t></w:r></w:fldSimple>'
    paragraph._p.append(parse_xml(field.format(ns=nsdecls("w"))))
    document.save(str(src))
    assert docx.Document(str(src)).paragraphs[0].text == "a-b-c-d"

    report = mask_file(src, dest, MarkerMap())

    assert docx.Document(str(dest)).paragraphs[0].text == "a-b-c-d"
    assert report.dropped == ["other text (fields, smart tags, equations)", "character formatting"]
    assert report.complete is False


def test_docx_no_break_hyphens_alone_leave_the_copy_complete(tmp_path):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    document = docx.Document()
    hyphens = "<w:r {ns}><w:t>a</w:t><w:noBreakHyphen/><w:t>b</w:t><w:noBreakHyphen/><w:t>c</w:t></w:r>"
    document.add_paragraph()._p.append(parse_xml(hyphens.format(ns=nsdecls("w"))))
    document.save(str(src))

    report = mask_file(src, dest, MarkerMap())

    assert docx.Document(str(dest)).paragraphs[0].text == "a-b-c"
    assert report.dropped == ["character formatting"] and report.complete is True


FIELD = '<w:fldSimple {ns} w:instr=" DOCPROPERTY Company "><w:r><w:t>FIELD_SECRET</w:t></w:r></w:fldSimple>'


def add_field(paragraph):
    paragraph._p.append(parse_xml(FIELD.format(ns=nsdecls("w"))))


@pytest.mark.parametrize(
    "name, with_text",
    [("header", False), ("footer", False), ("first_page_header", False), ("even_page_footer", False), ("header", True)],
    ids=["header", "footer", "first page header", "even page footer", "text and a field"],
)
def test_docx_text_in_a_field_in_a_header_or_footer_is_named(tmp_path, name, with_text):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    document = docx.Document()
    document.add_paragraph("body")
    section = document.sections[0]
    section.different_first_page_header_footer = True
    document.settings.odd_and_even_pages_header_footer = True
    part = getattr(section, name)
    part.is_linked_to_previous = False
    if with_text:
        part.paragraphs[0].add_run("Acme report ")
    add_field(part.paragraphs[0])
    document.save(str(src))

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "FIELD_SECRET")
    assert report.checked == ["body", "headers and footers"]
    assert report.dropped == ["other text in headers and footers (fields, smart tags, equations)", "character formatting"]
    assert report.complete is False


def test_docx_text_in_a_field_in_the_header_of_a_later_section_is_named(tmp_path):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    document = docx.Document()
    document.add_paragraph("body")
    later = document.add_section()
    later.header.is_linked_to_previous = False
    add_field(later.header.paragraphs[0])
    document.save(str(src))

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "FIELD_SECRET")
    assert report.checked == ["body"]
    assert report.dropped == ["headers and footers of later sections", "character formatting"]
    assert report.complete is False


LINK_NS = f'{nsdecls("w")} xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
LINK_URL = "https://crm.acme.com/clients?token=LINK_SECRET"


def link_element(part):
    address = part.relate_to(LINK_URL, RELATIONSHIP_TYPE.HYPERLINK, is_external=True)
    return parse_xml(f'<w:hyperlink {LINK_NS} r:id="{address}"><w:r><w:t>the portal</w:t></w:r></w:hyperlink>')


def link_field(*codes):
    """A complex field: begin, the instruction, separate, the shown text, end (each a run of its own, as Word writes it).
    Word cuts an instruction into several runs where the editing happened: each code is a run."""
    runs = ['<w:r {ns}><w:fldChar w:fldCharType="begin"/></w:r>']
    runs += [f'<w:r {{ns}}><w:instrText xml:space="preserve">{code}</w:instrText></w:r>' for code in codes]
    runs += [
        '<w:r {ns}><w:fldChar w:fldCharType="separate"/></w:r>',
        "<w:r {ns}><w:t>the portal</w:t></w:r>",
        '<w:r {ns}><w:fldChar w:fldCharType="end"/></w:r>',
    ]
    return [parse_xml(run.format(ns=nsdecls("w"))) for run in runs]


def docx_with_link(path, where):
    document = docx.Document()
    document.add_paragraph("see ")
    paragraph = document.paragraphs[0]
    if where == "body":
        paragraph._p.append(link_element(document.part))
    elif where == "header":
        header = document.sections[0].header
        header.is_linked_to_previous = False
        header.paragraphs[0]._p.append(link_element(header.part))
    elif where == "field":
        for run in link_field(f' HYPERLINK "{LINK_URL}" '):
            paragraph._p.append(run)
    else:  # a simple field keeps its shown text inside the field element, where nobody reads it
        simple = f'<w:fldSimple {{ns}} w:instr=\' HYPERLINK "{LINK_URL}" \'><w:r><w:t>the portal</w:t></w:r></w:fldSimple>'
        paragraph._p.append(parse_xml(simple.format(ns=nsdecls("w"))))
    document.save(str(path))


@pytest.mark.parametrize("where", ["body", "header", "field", "simple field"])
def test_docx_hyperlink_targets_are_named(tmp_path, where):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    docx_with_link(src, where)

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "LINK_SECRET", "crm.acme.com")
    named = ["other text (fields, smart tags, equations)"] if where == "simple field" else []
    assert report.dropped == [*named, "hyperlink targets", "character formatting"]
    assert report.complete is False
    if where != "simple field":  # the text of the link is copied
        texts = [p.text for p in docx.Document(str(dest)).paragraphs]
        header = [p.text for p in docx.Document(str(dest)).sections[0].header.paragraphs]
        assert "the portal" in "".join(texts + header)


@pytest.mark.parametrize(
    "codes",
    [
        [' HYPERLINK "', 'https://crm.acme.com/clients?token=LINK_SECRET" '],
        [" HYPERLINK ", '"https://crm.acme.com/clients?token=LINK_SECRET" '],
        [" HYPER", 'LINK "https://crm.acme.com/clients?token=LINK_SECRET" '],
        [' HYPERLINK "\\\\fileserver\\clients\\LINK_SECRET.docx" '],  # a UNC path, every backslash doubled in a field
    ],
    ids=["cut after the quote", "cut after the word", "cut inside the word", "UNC path"],
)
def test_docx_a_hyperlink_field_is_named_however_its_instruction_is_cut_or_written(tmp_path, codes):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    document = docx.Document()
    paragraph = document.add_paragraph("see ")
    for run in link_field(*codes):
        paragraph._p.append(run)
    document.save(str(src))

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "LINK_SECRET", "crm.acme.com", "fileserver")
    assert [p.text for p in docx.Document(str(dest)).paragraphs] == ["see the portal"]
    assert report.dropped == ["hyperlink targets", "character formatting"] and report.complete is False


def test_docx_a_cut_instruction_that_points_inside_the_document_holds_no_address(tmp_path):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    document = docx.Document()
    paragraph = document.add_paragraph("see ")
    for run in link_field(" HYPER", 'LINK \\l "_Toc2" '):
        paragraph._p.append(run)
    document.save(str(src))

    report = mask_file(src, dest, MarkerMap())

    assert report.dropped == ["character formatting"] and report.complete is True


def test_docx_link_to_a_bookmark_holds_no_address(tmp_path):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    document = docx.Document()
    paragraph = document.add_paragraph("contents ")
    paragraph._p.append(parse_xml(f'<w:hyperlink {nsdecls("w")} w:anchor="_Toc1"><w:r><w:t>Chapter 1</w:t></w:r></w:hyperlink>'))
    for run in link_field(' HYPERLINK \\l "_Toc2" '):
        paragraph._p.append(run)
    document.save(str(src))

    report = mask_file(src, dest, MarkerMap())

    assert [p.text for p in docx.Document(str(dest)).paragraphs] == ["contents Chapter 1the portal"]
    assert report.dropped == ["character formatting"] and report.complete is True


@pytest.mark.parametrize("name", ["author", "last_modified_by", "title", "subject", "keywords", "comments", "category"])
def test_docx_document_properties_are_named(tmp_path, name):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    document = docx.Document()
    document.add_paragraph("body")
    setattr(document.core_properties, name, "PROPERTY_SECRET")
    document.save(str(src))

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "PROPERTY_SECRET")
    # a note, like the character formatting: an author is in every file from Office and never reaches the copy
    assert report.dropped == ["document properties", "character formatting"]
    assert report.complete is True


@pytest.mark.parametrize("tag", ["Company", "Manager"])
def test_docx_company_and_manager_are_document_properties_too(tmp_path, tag):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    docx.Document().save(str(src))
    named = f"<{tag}>PROPERTY_SECRET</{tag}>".encode()
    rewrite_zip(src, {"docProps/app.xml": lambda xml: xml.replace(f"<{tag}/>".encode(), named)})
    assert named in zipfile.ZipFile(src).read("docProps/app.xml")

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "PROPERTY_SECRET")
    assert report.dropped == ["document properties", "character formatting"] and report.complete is True


def test_docx_custom_properties_are_document_properties_too(tmp_path):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    docx.Document().save(str(src))
    custom = b'<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"><property name="Client" pid="2"><lpwstr>PROPERTY_SECRET</lpwstr></property></Properties>'
    rewrite_zip(src, {"docProps/custom.xml": lambda _: custom})

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "PROPERTY_SECRET")
    assert report.dropped == ["document properties", "character formatting"] and report.complete is True


@pytest.mark.parametrize(
    "empty",
    [EMPTY_CUSTOM_PROPERTIES, EMPTY_CUSTOM_PROPERTIES.replace(b"></Properties>", b"/>")],
    ids=["open and close", "self-closing"],
)
def test_docx_an_empty_custom_properties_part_is_not_named(tmp_path, empty):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    docx.Document().save(str(src))
    rewrite_zip(src, {"docProps/custom.xml": lambda _: empty})  # LibreOffice writes this one into every document

    report = mask_file(src, dest, MarkerMap())

    assert report.dropped == ["character formatting"] and report.complete is True


def test_docx_properties_that_hold_nothing_are_not_named(tmp_path):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    document = docx.Document()
    document.core_properties.comments = ""  # the library's own text, cleared; author and the rest are its defaults
    document.core_properties.title = "  "
    document.save(str(src))

    report = mask_file(src, dest, MarkerMap())

    assert report.dropped == ["character formatting"] and report.complete is True


def link_list(*links):
    """The HLinks element that Word writes into docProps/app.xml: six variants for each link, its address and bookmark last."""
    variants = ""
    for address, bookmark in links:
        variants += "<vt:variant><vt:i4>2031705</vt:i4></vt:variant>" + "<vt:variant><vt:i4>0</vt:i4></vt:variant>" * 2
        variants += f"<vt:variant><vt:i4>5</vt:i4></vt:variant><vt:variant><vt:lpwstr>{address}</vt:lpwstr></vt:variant>"
        variants += f"<vt:variant><vt:lpwstr>{bookmark}</vt:lpwstr></vt:variant>"
    return f'<HLinks><vt:vector size="{6 * len(links)}" baseType="variant">{variants}</vt:vector></HLinks>'.encode()


def put_link_list(path, *links):
    rewrite_zip(path, {"docProps/app.xml": lambda xml: xml.replace(b"</Properties>", link_list(*links) + b"</Properties>")})


def test_docx_link_list_in_the_extended_properties_is_named(tmp_path):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    docx.Document().save(str(src))
    put_link_list(src, (LINK_URL, ""), ("mailto:link.secret@acme.com", ""))
    assert LINK_URL.encode() in zipfile.ZipFile(src).read("docProps/app.xml")

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "LINK_SECRET", "crm.acme.com", "link.secret@acme.com")
    assert report.dropped == ["hyperlink targets", "character formatting"] and report.complete is False


@pytest.mark.parametrize(
    "links",
    [
        [],
        [("", "")],
        [("", "_Toc123456789")],
        [("", "_Toc1"), ("", "Chapter_2"), ("", "Глава_3")],
        [("  ", "\n    _Toc1\n  ")],
    ],
    ids=["no links", "empty link", "table of contents", "bookmarks in any script", "padded by a pretty printer"],
)
def test_docx_link_list_with_only_bookmarks_holds_no_address(tmp_path, links):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    docx.Document().save(str(src))
    put_link_list(src, *links)

    report = mask_file(src, dest, MarkerMap())

    assert report.dropped == ["character formatting"] and report.complete is True


@pytest.mark.parametrize(
    "bookmark",
    [
        pytest.param("अध्याय१", id="hindi, with a virama and a vowel sign"),
        pytest.param("บทที่_1", id="thai, with a vowel and a tone mark"),
        pytest.param(unicodedata.normalize("NFD", "Chương_1"), id="vietnamese in NFD, letters and marks apart"),
        pytest.param("_heading=h.30j0zll", id="google docs heading, with = and a dot"),
        pytest.param("_Toc123456789", id="word"),
    ],
)
def test_docx_link_list_bookmarks_with_marks_or_signs_hold_no_address(tmp_path, bookmark):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    docx.Document().save(str(src))
    put_link_list(src, ("", bookmark))
    assert bookmark.encode() in zipfile.ZipFile(src).read("docProps/app.xml")

    report = mask_file(src, dest, MarkerMap())

    assert report.dropped == ["character formatting"] and report.complete is True


@pytest.mark.parametrize(
    "address",
    [
        pytest.param(LINK_URL, id="url"),
        pytest.param("HTTPS://CRM.ACME.COM/LINK_SECRET", id="scheme in capitals"),
        pytest.param("mailto:link.secret@acme.com", id="mailto"),
        pytest.param("tel:+15551234567", id="tel"),
        pytest.param("link.secret@acme.com", id="e-mail address without a scheme"),
        pytest.param(r"\\fileserver\clients\LINK_SECRET.docx", id="UNC path"),
        pytest.param(r"C:\Users\ivan\LINK_SECRET.xlsx", id="drive path"),
        pytest.param(r"..\clients\LINK_SECRET.xlsx", id="relative path"),
        pytest.param("clients/LINK_SECRET.xlsx", id="relative path with a slash"),
        pytest.param("www.acme.com", id="host name"),
        pytest.param("crm.acme.com:8080", id="host name and port"),
        pytest.param("LINK_SECRET.docx", id="file name"),
    ],
)
def test_docx_link_list_names_every_kind_of_address(tmp_path, address):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    docx.Document().save(str(src))
    put_link_list(src, ("", "_Toc1"), (address, ""))

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, address)
    assert report.dropped == ["hyperlink targets", "character formatting"] and report.complete is False


def test_docx_link_list_with_a_table_of_contents_and_one_address_is_named(tmp_path):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    docx.Document().save(str(src))
    put_link_list(src, ("", "_Toc1"), ("", "_Toc2"), (LINK_URL, ""), ("", "_Toc3"))

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "LINK_SECRET")
    assert report.dropped == ["hyperlink targets", "character formatting"] and report.complete is False


def test_docx_link_in_the_body_and_in_the_link_list_is_named_once(tmp_path):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    docx_with_link(src, "body")
    put_link_list(src, (LINK_URL, ""))

    report = mask_file(src, dest, MarkerMap())

    assert report.dropped == ["hyperlink targets", "character formatting"]


def test_docx_extended_properties_without_a_link_list_name_no_link(tmp_path):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    docx.Document().save(str(src))  # its app.xml has HyperlinkBase and HyperlinksChanged, which are no list
    assert b"HyperlinksChanged" in zipfile.ZipFile(src).read("docProps/app.xml")

    report = mask_file(src, dest, MarkerMap())

    assert report.dropped == ["character formatting"] and report.complete is True


@pytest.mark.parametrize(
    "hostile",
    [
        pytest.param(b"<HLinks>" * 30_000, id="opening tags"),
        pytest.param(b"<HLinks><vt:lpwstr>" * 12_000, id="opening string tags"),
        pytest.param(b"<HLinks>" + b"<vt:lpwstr>a</vt:lpwstr>" * 10_000, id="many strings"),
        pytest.param(b"<HLinks>" + b"<vt:lpstr " * 20_000, id="string tags with a space and no end"),
        pytest.param(b"<HLinks>" + b'<vt:lpwstr a="b" ' * 12_000, id="string tags with attributes and no end"),
        pytest.param(b"<HLinks><vt:lpwstr>" + b"a." * 300_000 + b"=</vt:lpwstr>", id="one long dotted name"),
        pytest.param(b"<HLinks><vt:lpwstr>" + b"a" * 900_000 + b"</vt:lpwstr>", id="one long word"),
        pytest.param(b"<HLinks>" + (b"<vt:lpwstr>" + b"a-" * 300 + b"=</vt:lpwstr>") * 1_500, id="many long names"),
    ],
)
def test_docx_a_hostile_extended_properties_part_is_read_in_linear_time(tmp_path, hostile):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    docx.Document().save(str(src))
    rewrite_zip(src, {"docProps/app.xml": lambda _: hostile})
    started = time.perf_counter()

    mask_file(src, dest, MarkerMap())

    assert time.perf_counter() - started < 2.0  # a pattern that restarts at every opening tag needs minutes here


THUMBNAIL = b"JPEGDATA THUMB_SECRET"


def test_docx_thumbnail_is_named(tmp_path):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    docx.Document().save(str(src))
    rewrite_zip(src, {"docProps/thumbnail.jpeg": lambda _: THUMBNAIL})

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "THUMB_SECRET")
    # a note, like the properties: it is a picture of the first page, whose text was checked, and it never reaches the copy
    assert report.dropped == ["document thumbnail", "character formatting"] and report.complete is True


@pytest.mark.parametrize("name", ["docProps/thumbnail.png", "docProps/thumbnail.wmf", "docProps/thumbnail1.jpeg"])
def test_docx_thumbnail_under_another_name_is_named(tmp_path, name):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    docx.Document().save(str(src))
    rewrite_zip(src, {name: lambda _: THUMBNAIL})

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "THUMB_SECRET")
    assert report.dropped == ["document thumbnail", "character formatting"]


def test_docx_made_by_a_script_has_the_librarys_own_thumbnail_which_is_not_named(tmp_path):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    docx.Document().save(str(src))
    assert "docProps/thumbnail.jpeg" in zipfile.ZipFile(src).namelist()  # python-docx's template carries a picture of its own

    report = mask_file(src, dest, MarkerMap())

    assert report.dropped == ["character formatting"] and report.complete is True


def test_docx_restore_does_not_name_the_librarys_thumbnail(tmp_path):
    src, masked, back = tmp_path / "in.docx", tmp_path / "masked.docx", tmp_path / "back.docx"
    document = docx.Document()
    document.add_paragraph("mail ivan@acme.com")
    document.save(str(src))
    markers = MarkerMap()
    mask_file(src, masked, markers)

    report, anomalies = restore_file(masked, back, markers)

    assert anomalies == [] and report.dropped == ["character formatting"] and report.complete is True


def test_docx_notes_and_findings_come_in_a_fixed_order(tmp_path):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    document = docx.Document()
    document.core_properties.author = "PROPERTY_SECRET"
    document.add_comment(document.add_paragraph("see").runs, text="check this", author="Ivan", initials="I")
    document.save(str(src))
    put_link_list(src, (LINK_URL, ""))
    rewrite_zip(src, {"docProps/thumbnail.jpeg": lambda _: THUMBNAIL})

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "PROPERTY_SECRET", "LINK_SECRET", "THUMB_SECRET")
    names = ["comments", "hyperlink targets", "document properties", "document thumbnail", "character formatting"]
    assert report.dropped == names and report.complete is False


def test_docx_merged_and_nested_tables_keep_every_text_once(tmp_path):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    document = docx.Document()
    table = document.add_table(rows=3, cols=3)
    table.cell(0, 0).merge(table.cell(0, 1)).text = "ivan@acme.com"
    table.cell(1, 2).merge(table.cell(2, 2)).text = "tall"
    table.cell(2, 0).text = "plain"
    table.cell(1, 0).add_table(rows=1, cols=1).cell(0, 0).text = "nested olga@acme.com"
    document.save(str(src))

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "ivan@acme.com", "olga@acme.com")
    cells = [[cell.text for cell in row.cells] for row in docx.Document(str(dest)).tables[0].rows]
    assert [len(row) for row in cells] == [3, 3, 3]
    flat = [text for row in cells for text in row]
    assert flat.count("[EMAIL_1]") == 1 and flat.count("tall") == 1 and flat.count("plain") == 1
    assert any("nested [EMAIL_2]" in text for text in flat)
    assert report.checked == ["body", "tables"] and report.dropped == ["character formatting"] and report.complete is True


def test_docx_every_header_and_footer_variant_of_the_first_section(tmp_path):
    src, masked, back = tmp_path / "in.docx", tmp_path / "masked.docx", tmp_path / "back.docx"
    document = docx.Document()
    document.add_paragraph("body")
    section = document.sections[0]
    section.different_first_page_header_footer = True
    document.settings.odd_and_even_pages_header_footer = True
    texts = {
        "header": "default ivan@acme.com",
        "first_page_header": "first olga@acme.com",
        "even_page_header": "even anna@acme.com",
        "footer": "footer petr@acme.com",
    }
    for name, text in texts.items():
        getattr(section, name).paragraphs[0].text = text
    document.save(str(src))
    markers = MarkerMap()

    report = mask_file(src, masked, markers)

    assert_clean(masked, "ivan@acme.com", "olga@acme.com", "anna@acme.com", "petr@acme.com")
    clean = docx.Document(str(masked))
    assert clean.sections[0].different_first_page_header_footer and clean.settings.odd_and_even_pages_header_footer
    masked_texts = [getattr(clean.sections[0], name).paragraphs[0].text for name in texts]
    assert all(re.fullmatch(rf"{text.split()[0]} \[EMAIL_\d\]", masked) for text, masked in zip(texts.values(), masked_texts))
    assert len(set(masked_texts)) == 4 and report.checked == ["body", "headers and footers"]

    restore_file(masked, back, markers)

    restored = docx.Document(str(back)).sections[0]
    assert [getattr(restored, name).paragraphs[0].text for name in texts] == list(texts.values())


def test_docx_without_section_properties(tmp_path):
    src, dest = tmp_path / "in.docx", tmp_path / "out.docx"
    document = docx.Document()
    document.add_paragraph("mail ivan@acme.com")
    document.element.body.sectPr.getparent().remove(document.element.body.sectPr)  # valid, if unusual
    document.save(str(src))

    report = mask_file(src, dest, MarkerMap())

    assert [p.text for p in docx.Document(str(dest)).paragraphs] == ["mail [EMAIL_1]"]
    assert report.checked == ["body"] and report.complete is True


def pdf_stream(data, entries=""):
    return f"<< {entries} /Length {len(data)} >>\nstream\n{data}\nendstream"


def pdf_bytes(pages, extras=False, info=""):
    """A hand-written PDF with one line of text per page. With extras page 1 also holds an image, a note annotation and
    an attached file, each with a secret of its own. info is the body of the document information dictionary."""
    first, extra = 4, 4 + 2 * len(pages)  # objects: 1 catalog, 2 page tree, 3 font, a page and its text per page, extras
    kids = " ".join(f"{first + 2 * i} 0 R" for i in range(len(pages)))
    attached = f" /Names << /EmbeddedFiles << /Names [(note.txt) {extra + 2} 0 R] >> >>" if extras else ""
    objects = [
        f"<< /Type /Catalog /Pages 2 0 R{attached} >>",
        f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    for i, text in enumerate(pages):
        more = extras and i == 0
        image = f" /XObject << /Im1 {extra} 0 R >>" if more else ""
        note = f" /Annots [{extra + 1} 0 R]" if more else ""
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {first + 2 * i + 1} 0 R"
            f" /Resources << /Font << /F1 3 0 R >>{image} >>{note} >>"
        )
        objects.append(pdf_stream(f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET"))
    if extras:
        picture = "/Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceGray /BitsPerComponent 8"
        objects += [
            pdf_stream("IMAGESECRET", picture),
            "<< /Type /Annot /Subtype /Text /Rect [10 10 30 30] /Contents (note for anna@secret.org) >>",
            f"<< /Type /Filespec /F (note.txt) /EF << /F {extra + 3} 0 R >> >>",
            pdf_stream("attached hidden@acme.com", "/Type /EmbeddedFile"),
        ]
    described = f" /Info {len(objects) + 1} 0 R" if info else ""
    if info:
        objects.append(f"<< {info} >>")
    body = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(body))
        body += f"{number} 0 obj\n{obj}\nendobj\n".encode()
    xref = len(body)
    body += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    body += "".join(f"{offset:010d} 00000 n \n" for offset in offsets).encode()
    body += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R{described} >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(body)


def test_pdf_text_layer_masked_to_txt(tmp_path):
    src, dest = tmp_path / "letter.pdf", tmp_path / "letter.txt"
    src.write_bytes(pdf_bytes(["mail ivan@acme.com", "second page"]))

    report = mask_file(src, dest, MarkerMap())

    text = dest.read_text()
    assert "[EMAIL_1]" in text and "ivan@acme.com" not in text and text.index("[EMAIL_1]") < text.index("second page")
    assert report.format == "pdf" and report.checked == ["text layer of 2 pages"]
    assert report.dropped == ["images", "annotations", "attachments", "document properties"]
    assert report.markers_by_kind == {"EMAIL": 1}
    assert report.complete is False

    with pytest.raises(FormatError, match="txt"):
        mask_file(src, tmp_path / "copy.pdf", MarkerMap())
    assert not (tmp_path / "copy.pdf").exists()


def test_pdf_document_properties_are_not_copied(tmp_path):
    src, dest = tmp_path / "in.pdf", tmp_path / "out.txt"
    src.write_bytes(pdf_bytes(["mail ivan@acme.com"], info="/Author (author@acme.com) /Title (PROPERTY_SECRET)"))
    assert pypdf.PdfReader(str(src)).metadata.title == "PROPERTY_SECRET"

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "PROPERTY_SECRET", "author@acme.com")
    assert "document properties" in report.dropped and report.markers_by_kind == {"EMAIL": 1}


def test_pdf_images_annotations_and_attachments_are_not_read(tmp_path):
    src, dest = tmp_path / "in.pdf", tmp_path / "out.txt"
    src.write_bytes(pdf_bytes(["mail ivan@acme.com"], extras=True))
    assert all(secret.encode() in src.read_bytes() for secret in ("IMAGESECRET", "anna@secret.org", "hidden@acme.com"))

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "ivan@acme.com", "IMAGESECRET", "anna@secret.org", "hidden@acme.com")
    assert report.markers_by_kind == {"EMAIL": 1}


def test_pdf_without_a_text_layer_gives_an_empty_txt(tmp_path):
    src, dest = tmp_path / "scan.pdf", tmp_path / "scan.txt"
    src.write_bytes(pdf_bytes([""]))

    report = mask_file(src, dest, MarkerMap())

    assert dest.read_bytes() == b"" and report.checked == ["text layer of 1 page"] and report.complete is False


def encrypted_pdf(path, user_password):
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes(["mail ivan@acme.com"])))
    writer = pypdf.PdfWriter(clone_from=reader)
    writer.encrypt(user_password, owner_password="owner", algorithm="AES-256")
    with open(path, "wb") as handle:
        writer.write(handle)


def test_pdf_with_an_owner_password_only_is_read_and_a_user_password_refused(tmp_path):
    open_pdf, locked_pdf = tmp_path / "open.pdf", tmp_path / "locked.pdf"
    encrypted_pdf(open_pdf, "")
    encrypted_pdf(locked_pdf, "secret-password")

    mask_file(open_pdf, tmp_path / "open.txt", MarkerMap())
    with pytest.raises(FormatError, match="password"):
        mask_file(locked_pdf, tmp_path / "locked.txt", MarkerMap())

    assert "[EMAIL_1]" in (tmp_path / "open.txt").read_text() and not (tmp_path / "locked.txt").exists()


def test_pdf_errors_and_logs_hold_no_file_content(tmp_path, caplog):
    src = tmp_path / "bad.pdf"
    src.write_bytes(b"SECRETLEAK this is not a pdf")
    caplog.set_level(logging.DEBUG)

    with pytest.raises(FormatError) as raised:
        mask_file(src, tmp_path / "bad.txt", MarkerMap())

    assert "SECRE" not in str(raised.value) + caplog.text  # pypdf logs the first bytes of a file it cannot read
    assert not (tmp_path / "bad.txt").exists()


def test_pdf_text_restore_round_trip(tmp_path):
    src, masked, back = tmp_path / "in.pdf", tmp_path / "masked.txt", tmp_path / "back.txt"
    src.write_bytes(pdf_bytes(["mail ivan@acme.com", "second page"]))
    markers = MarkerMap()
    mask_file(src, masked, markers)
    masked.write_text(masked.read_text() + "\nanswer for [EMAIL_1] and [EMAIL_9]")

    restored, anomalies = restore_file(masked, back, markers)

    restored_text = back.read_text()
    assert restored_text.startswith("mail ivan@acme.com") and "answer for ivan@acme.com and [EMAIL_9]" in restored_text
    assert anomalies == ["[EMAIL_9]"]
    assert restored.format == "pdf" and restored.markers_by_kind == {"EMAIL": 2} and restored.complete is True
    with pytest.raises(FormatError, match="txt"):
        restore_file(src, tmp_path / "again.txt", markers)  # a pdf itself cannot be restored


def test_text_restore_refuses_non_utf8(tmp_path):
    src, back = tmp_path / "answer.txt", tmp_path / "back.txt"
    src.write_bytes("Ответ".encode("cp1251"))

    with pytest.raises(FormatError, match="^not UTF-8$"):
        restore_file(src, back, MarkerMap())

    assert not back.exists() and not (tmp_path / "back.txt.part").exists()


def test_docx_restore_reports_unknown_markers(tmp_path):
    src, masked, edited, back = (tmp_path / name for name in ("in.docx", "masked.docx", "edited.docx", "back.docx"))
    document = docx.Document()
    document.add_paragraph("mail ivan@acme.com")
    document.sections[0].header.paragraphs[0].text = "header"
    document.save(str(src))
    markers = MarkerMap()
    mask_file(src, masked, markers)
    document = docx.Document(str(masked))
    document.paragraphs[0].text = document.paragraphs[0].text + " and [EMAIL_9]"
    document.sections[0].header.paragraphs[0].text = "header [email_1]"
    document.save(str(edited))

    _, anomalies = restore_file(edited, back, markers)

    assert anomalies == ["[EMAIL_9]", "[email_1]"]
    restored = docx.Document(str(back))
    assert restored.paragraphs[0].text == "mail ivan@acme.com and [EMAIL_9]"
    assert restored.sections[0].header.paragraphs[0].text == "header [email_1]"
