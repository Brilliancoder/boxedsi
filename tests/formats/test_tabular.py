import datetime
import re
import zipfile

import openpyxl
import pytest
from openpyxl.cell.cell import Cell
from openpyxl.chart import BarChart, Reference
from openpyxl.comments import Comment
from openpyxl.packaging.custom import StringProperty
from openpyxl.styles import Font
from openpyxl.workbook.defined_name import DefinedName
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.worksheet.hyperlink import Hyperlink

from boxed.detect import DetectConfig
from boxed.formats import FileReport, FormatError, mask_file, restore_file
from boxed.mask import MarkerMap, dictionary_kinds

from . import EMPTY_CUSTOM_PROPERTIES, assert_clean, rewrite_zip

# canonical form (minimal quoting, one line ending): masking and restoring gives the same bytes back
CLIENTS_CSV = (
    "\N{BYTE ORDER MARK}name;email;key\r\n"
    "Ivan;ivan@acme.com;AKIAIOSFODNN7EXAMPLE\r\n"
    '"Olga; the second\nline";olga@acme.com;ok\r\n'
)


def test_csv_cells_masked_and_restored_exactly(tmp_path):
    src, dest, back = tmp_path / "clients.csv", tmp_path / "clients.masked.csv", tmp_path / "back.csv"
    src.write_bytes(CLIENTS_CSV.encode())
    markers = MarkerMap()

    report = mask_file(src, dest, markers)

    assert_clean(dest, "ivan@acme.com", "olga@acme.com", "AKIAIOSFODNN7EXAMPLE")
    masked = dest.read_bytes()
    assert masked.startswith(b"\xef\xbb\xbf") and b";" in masked and b"[EMAIL_1]" in masked
    assert report == FileReport(
        source="clients.csv",
        output="clients.masked.csv",
        format="csv",
        checked=["3 rows, 3 columns"],
        dropped=[],
        markers_by_kind={"EMAIL": 2, "SECRET": 1},
        complete=True,
    )

    restored, anomalies = restore_file(dest, back, markers)
    assert back.read_bytes() == src.read_bytes() and anomalies == []
    assert restored.format == "csv" and restored.markers_by_kind == {"EMAIL": 2, "SECRET": 1}


def test_csv_non_utf8_refused(tmp_path):
    src, dest = tmp_path / "old.csv", tmp_path / "out.csv"
    src.write_bytes("Имя;Почта\r\nИван;ivan@acme.com\r\n".encode("cp1251"))

    with pytest.raises(FormatError, match="^not UTF-8$"):
        mask_file(src, dest, MarkerMap())

    assert not dest.exists() and not (tmp_path / "out.csv.part").exists()


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"])
def test_csv_utf16_and_utf32_without_bom_refused(tmp_path, encoding):
    # ASCII text in these encodings is valid UTF-8 (every other byte is NUL), so nothing in it would be masked
    src, dest, back = tmp_path / "wide.csv", tmp_path / "out.csv", tmp_path / "back.csv"
    src.write_bytes("name,email\r\nIvan,ivan@acme.com\r\n".encode(encoding))

    with pytest.raises(FormatError, match="^not UTF-8") as raised:
        mask_file(src, dest, MarkerMap())
    with pytest.raises(FormatError, match="^not UTF-8"):
        restore_file(src, back, MarkerMap())

    assert "ivan" not in str(raised.value)
    assert not dest.exists() and not (tmp_path / "out.csv.part").exists() and not back.exists()


def test_csv_with_a_nul_character_refused(tmp_path):
    src, dest = tmp_path / "nul.csv", tmp_path / "out.csv"
    src.write_bytes(b"a,b\nivan@acme.com\x00,x\n")

    with pytest.raises(FormatError, match="^not UTF-8"):
        mask_file(src, dest, MarkerMap())

    assert not dest.exists()


@pytest.mark.parametrize(
    "text",
    [
        'a,b\nivan@acme.com,"say ""hi"", ok"\nx,y',  # LF, doubled quotes, no final newline
        "a\tb\r\nivan@acme.com\tx\r\n\r\nlast\ty\r\n",  # tab, an empty line
        'a|b\nivan@acme.com|"two\nlines"\n',  # pipe, a quoted line break
        "ivan@acme.com\n",  # one column: nothing to sniff
        "",
    ],
)
def test_csv_round_trip_keeps_dialect_and_bytes(tmp_path, text):
    src, dest, back = tmp_path / "in.csv", tmp_path / "masked.csv", tmp_path / "back.csv"
    src.write_bytes(text.encode())
    markers = MarkerMap()

    mask_file(src, dest, markers)
    _, anomalies = restore_file(dest, back, markers)

    assert_clean(dest, "ivan@acme.com")
    assert back.read_bytes() == src.read_bytes() and anomalies == []


def test_csv_error_holds_no_file_content(tmp_path):
    src = tmp_path / "big.csv"
    src.write_text("a,b\n" + "SECRETVALUE" * 20000 + ",x\n")  # a cell over the csv field limit

    with pytest.raises(FormatError) as raised:
        mask_file(src, tmp_path / "out.csv", MarkerMap())

    assert "SECRETVALUE" not in str(raised.value) and raised.value.__suppress_context__
    assert not (tmp_path / "out.csv").exists()


def plant_cached_value(path, ref, kind, value):
    """openpyxl never writes the result of a formula, Excel always does."""
    pattern = rf'<c r="{ref}"><f>(.*?)</f><v></v>'.encode()
    replacement = rf'<c r="{ref}" t="{kind}"><f>\1</f><v>{value}</v>'.encode()
    rewrite_zip(path, {"xl/worksheets/sheet1.xml": lambda xml: re.sub(pattern, replacement, xml)})


def values_of(sheet):
    return [[cell.value for cell in row] for row in sheet.iter_rows()]


def build_clients(path):
    book = openpyxl.Workbook()
    sheet = book.active
    sheet.title = "Clients"
    sheet.append(["email", "revenue", "paid", "since", "note"])
    sheet.append(["ivan@acme.com", 1200, True, datetime.datetime(2026, 10, 1, 9, 30), "key AKIAIOSFODNN7EXAMPLE"])
    sheet.append(["olga@acme.com", 99.5, False, datetime.datetime(2026, 10, 2), "ok"])
    sheet["A2"].comment = Comment("call anna@secret.org", "ivan")
    old = book.create_sheet("Old")
    old["A1"] = "Project Orion budget"  # no detector catches this: it must not be copied at all
    old["A2"] = "hidden@acme.com"
    old.sheet_state = "hidden"
    vault = book.create_sheet("Vault")
    vault["A1"] = "very hidden secret"
    vault.sheet_state = "veryHidden"
    book.properties.creator, book.properties.lastModifiedBy = "author@acme.com", "editor@acme.com"
    book.save(path)


def test_xlsx_hidden_sheets_and_comments_dropped(tmp_path):
    src, dest = tmp_path / "clients.xlsx", tmp_path / "clients.masked.xlsx"
    build_clients(src)

    report = mask_file(src, dest, MarkerMap())

    values = ("ivan@acme.com", "olga@acme.com", "AKIAIOSFODNN7EXAMPLE", "anna@secret.org", "Orion", "hidden@acme.com")
    assert_clean(dest, *values, "very hidden", "author@acme.com", "editor@acme.com")  # nor do the document properties carry over
    book = openpyxl.load_workbook(dest)
    assert book.sheetnames == ["Clients"]
    rows = values_of(book["Clients"])
    assert rows[1] == ["[EMAIL_1]", 1200, True, datetime.datetime(2026, 10, 1, 9, 30), "key [SECRET_1]"]
    assert rows[2][:2] == ["[EMAIL_2]", 99.5] and type(rows[1][1]) is int and type(rows[2][1]) is float
    assert report.format == "xlsx" and report.checked == ["sheet Clients"]
    assert report.dropped == ["hidden sheet Old", "very hidden sheet Vault", "comments", "document properties"]
    assert report.markers_by_kind == {"EMAIL": 2, "SECRET": 1}  # nothing from the hidden parts was even looked at
    assert report.complete is False


def test_xlsx_hidden_rows_and_columns_are_not_copied(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    book = openpyxl.Workbook()
    sheet = book.active
    sheet.title = "Data"
    sheet.append(["id", "HIDDEN_COLUMN_SECRET", "email", "HIDDEN_GROUP_SECRET", "g", "note"])
    sheet.append([1, "b", "ivan@acme.com", "d", "e", "shown"])
    sheet.append([2, "b", "olga@acme.com", "d", "e", "HIDDEN_ROW_SECRET"])
    sheet.append([3, "b", "anna@acme.com", "d", "e", "kept"])
    sheet.row_dimensions[3].hidden = True
    sheet.column_dimensions["B"].hidden = True
    sheet.column_dimensions.group("D", "E", hidden=True)  # one <col> element for two columns
    book.save(src)

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "HIDDEN_COLUMN_SECRET", "HIDDEN_GROUP_SECRET", "HIDDEN_ROW_SECRET", "olga@acme.com")
    copy = openpyxl.load_workbook(dest)["Data"]
    assert values_of(copy) == [  # the visible cells keep their addresses
        ["id", None, "email", None, None, "note"],
        [1, None, "[EMAIL_1]", None, None, "shown"],
        [None, None, None, None, None, None],
        [3, None, "[EMAIL_2]", None, None, "kept"],
    ]
    assert report.checked == ["sheet Data"] and report.dropped == ["hidden rows", "hidden columns"]
    assert report.markers_by_kind == {"EMAIL": 2} and report.complete is False


def test_xlsx_hidden_but_empty_rows_and_columns_are_not_reported(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    book = openpyxl.Workbook()
    book.active["A1"] = "ivan@acme.com"
    book.active.row_dimensions[5].hidden = True
    book.active.column_dimensions["C"].hidden = True
    book.save(src)

    report = mask_file(src, dest, MarkerMap())

    assert openpyxl.load_workbook(dest).active["A1"].value == "[EMAIL_1]"
    assert report.dropped == [] and report.complete is True


def test_xlsx_whole_numbers_go_through_the_masker(tmp_path):
    src, dest, back = tmp_path / "cards.xlsx", tmp_path / "cards.masked.xlsx", tmp_path / "back.xlsx"
    book = openpyxl.Workbook()
    book.active.title = "Cards"
    book.active.append(["card", "as float", "as text", "amount", "count", "paid"])
    book.active.append([4111111111111111, 4111111111111111.0, "4111 1111 1111 1111", 99.5, 42, True])
    book.save(src)
    markers = MarkerMap()

    report = mask_file(src, dest, markers)

    assert_clean(dest, "4111111111111111")
    row = values_of(openpyxl.load_workbook(dest)["Cards"])[1]
    assert row == ["[CARD_1]", "[CARD_1]", "[CARD_2]", 99.5, 42, True]  # the same digits, the same marker
    assert type(row[3]) is float and type(row[4]) is int and row[5] is True  # numbers the masker leaves alone stay numbers
    assert report.markers_by_kind == {"CARD": 3} and report.complete is True

    restore_file(dest, back, markers)

    # the marker does not know whether the cell was a number or a text, so it comes back as the digits in a text cell
    assert values_of(openpyxl.load_workbook(back)["Cards"])[1] == [
        "4111111111111111",
        "4111111111111111",
        "4111 1111 1111 1111",
        99.5,
        42,
        True,
    ]


def test_xlsx_formula_keeps_cached_value_note(tmp_path):
    src, dest = tmp_path / "calc.xlsx", tmp_path / "calc.masked.xlsx"
    book = openpyxl.Workbook()
    sheet = book.active
    sheet.title = "Calc"
    sheet["A1"], sheet["B1"] = "ivan@acme.com", 5
    sheet["C1"], sheet["D1"] = '="mail "&A1', "=B1*2"
    book.save(src)
    plant_cached_value(src, "C1", "str", "mail ivan@acme.com")
    plant_cached_value(src, "D1", "n", "10")

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "ivan@acme.com")
    sheet = openpyxl.load_workbook(dest)["Calc"]
    assert [sheet[ref].value for ref in ("C1", "D1")] == ["mail [EMAIL_1]", 10]
    assert b"<f>" not in zipfile.ZipFile(dest).read("xl/worksheets/sheet1.xml")
    assert report.dropped == ["formulas (cached values kept)"]
    assert report.complete is True  # what the sheet shows was checked; only the expression text is dropped


def test_xlsx_formulas_without_cached_values_are_counted(tmp_path):
    src, dest = tmp_path / "calc.xlsx", tmp_path / "calc.masked.xlsx"
    book = openpyxl.Workbook()
    sheet = book.active
    sheet.title = "Calc"
    sheet["A1"], sheet["B1"] = "ivan@acme.com", 5
    sheet["C1"], sheet["D1"], sheet["E1"] = '="mail "&A1', "=B1*2", "=B1+1"
    book.save(src)
    plant_cached_value(src, "D1", "n", "10")  # C1 and E1 were never calculated

    report = mask_file(src, dest, MarkerMap())

    sheet = openpyxl.load_workbook(dest)["Calc"]
    assert [sheet[ref].value for ref in ("A1", "C1", "D1", "E1")] == ["[EMAIL_1]", None, 10, None]
    assert report.dropped == ["formulas (cached values kept)", "formulas without cached values (left empty): 2"]
    assert report.complete is False  # two cells that held a formula are empty, and nobody saw what they should show


def test_xlsx_restore_reports_formulas_that_were_never_calculated(tmp_path):
    src, back = tmp_path / "reply.xlsx", tmp_path / "back.xlsx"
    book = openpyxl.Workbook()
    sheet = book.active
    sheet.title = "Report"
    sheet.append(["client", "revenue", "cost", "margin", "note"])
    sheet.append(["[CLIENT_1]", 100, 80, "=B2-C2", '=CONCATENATE("mail ", "[EMAIL_1]")'])
    sheet.append(["[CLIENT_2]", 200, 150, "=B3-C3", "=SUM(B2:B3)"])
    book.save(src)  # as a script of the model writes it: openpyxl stores no results
    markers = MarkerMap()
    for kind, original in (("CLIENT", "Acme Corp"), ("CLIENT", "Globex"), ("EMAIL", "ivan@acme.com")):
        markers.marker_for(kind, original)

    report, anomalies = restore_file(src, back, markers)

    rows = values_of(openpyxl.load_workbook(back)["Report"])
    assert rows[1:] == [["Acme Corp", 100, 80, None, None], ["Globex", 200, 150, None, None]]
    assert report.dropped == ["formulas without cached values (left empty): 4"]
    assert report.complete is False and anomalies == []


def test_xlsx_a_formula_that_gives_an_empty_text_has_a_cached_value(tmp_path):
    src, dest = tmp_path / "calc.xlsx", tmp_path / "calc.masked.xlsx"
    book = openpyxl.Workbook()
    book.active["A1"], book.active["B1"] = 5, '=IF(A1>9,"x","")'
    book.save(src)
    plant_cached_value(src, "B1", "str", "")  # how Excel stores a result that is the empty text

    report = mask_file(src, dest, MarkerMap())

    assert report.dropped == ["formulas (cached values kept)"] and report.complete is True


def test_xlsx_restore_round_trip(tmp_path):
    src, masked, back = tmp_path / "in.xlsx", tmp_path / "masked.xlsx", tmp_path / "back.xlsx"
    config = DetectConfig(dictionary={"Acme Corp": "CLIENT"})
    book = openpyxl.Workbook()
    book.active.title = "Clients"
    book.active.append(["ivan@acme.com", "Acme Corp pays", 12.5, datetime.datetime(2026, 1, 2)])
    book.active.append(["=1+1", "AKIAIOSFODNN7EXAMPLE", False, None])
    book.active["A2"].data_type = "s"  # a text that only looks like a formula
    book.create_sheet("Acme Corp")["B2"] = "olga@acme.com"
    book.save(src)
    markers = MarkerMap()

    report = mask_file(src, masked, markers, config=config)

    assert_clean(masked, "ivan@acme.com", "Acme Corp", "AKIAIOSFODNN7EXAMPLE", "olga@acme.com")
    assert openpyxl.load_workbook(masked).sheetnames == ["Clients", "(CLIENT_1)"]  # no brackets in sheet names
    assert report.checked == ["sheet Clients", "sheet [CLIENT_1]"] and report.dropped == [] and report.complete is True

    restored, anomalies = restore_file(masked, back, markers, kinds=dictionary_kinds(config))

    assert anomalies == []
    before, after = openpyxl.load_workbook(src), openpyxl.load_workbook(back)
    assert after.sheetnames == before.sheetnames == ["Clients", "Acme Corp"]
    for name in before.sheetnames:
        assert values_of(after[name]) == values_of(before[name])
    assert after["Clients"]["A2"].value == "=1+1" and after["Clients"]["A2"].data_type == "s"
    assert restored.format == "xlsx" and restored.markers_by_kind == {"EMAIL": 2, "CLIENT": 2, "SECRET": 1}


def test_xlsx_sheet_names_masked_in_title_and_report(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    config = DetectConfig(dictionary={"Acme Corp": "CLIENT"})
    book = openpyxl.Workbook()
    book.active.title = "a@b.co c@d.io e@f.org g@h.net"  # 29 characters, 39 once masked
    book.create_sheet("Acme Corp").sheet_state = "hidden"
    book.save(src)

    report = mask_file(src, dest, MarkerMap(), config=config)

    assert openpyxl.load_workbook(dest).sheetnames == ["(EMAIL_1) (EMAIL_2) (EMAIL_3) ("]  # 31 characters at most
    assert_clean(dest, "a@b.co", "g@h.net", "Acme Corp")
    assert report.checked == ["sheet [EMAIL_1] [EMAIL_2] [EMAIL_3] [EMAIL_4]"]
    cut = "changed to fit Excel (invalid characters, over 31 characters or a duplicate)"
    assert report.dropped == [f"sheet name [EMAIL_1] [EMAIL_2] [EMAIL_3] [EMAIL_4] {cut}", "hidden sheet [CLIENT_1]"]
    assert report.complete is False  # the cut is not silent


def test_xlsx_hyperlink_targets_are_named(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    book = openpyxl.Workbook()
    sheet = book.active
    sheet.title = "Data"
    sheet["A1"] = "the portal"
    sheet["A1"].hyperlink = "https://crm.acme.com/clients?token=LINK_SECRET"
    sheet["A2"] = "mail"
    sheet["A2"].hyperlink = "mailto:link.secret@acme.com"
    book.save(src)

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "LINK_SECRET", "crm.acme.com", "link.secret@acme.com")
    copy = openpyxl.load_workbook(dest)["Data"]
    assert [copy["A1"].value, copy["A2"].value] == ["the portal", "mail"] and copy["A1"].hyperlink is None
    assert report.dropped == ["hyperlink targets"] and report.complete is False


def test_xlsx_a_link_inside_the_workbook_holds_no_address(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    book = openpyxl.Workbook()
    sheet = book.active
    sheet.title = "Data"
    sheet["A1"] = "back to the top"
    sheet["A1"].hyperlink = Hyperlink(ref="A1", location="Data!A5")
    book.save(src)

    report = mask_file(src, dest, MarkerMap())

    assert report.dropped == [] and report.complete is True


def test_xlsx_a_link_on_a_hidden_sheet_is_not_named_twice(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    book = openpyxl.Workbook()
    book.active.title = "Data"
    hidden = book.create_sheet("Old")
    hidden["A1"] = "the portal"
    hidden["A1"].hyperlink = "https://crm.acme.com/clients?token=LINK_SECRET"
    hidden.sheet_state = "hidden"
    book.save(src)

    report = mask_file(src, dest, MarkerMap())

    assert report.dropped == ["hidden sheet Old"]


@pytest.mark.parametrize("name", ["creator", "lastModifiedBy", "title", "subject", "keywords", "description", "category"])
def test_xlsx_document_properties_are_named(tmp_path, name):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    book = openpyxl.Workbook()
    book.active["A1"] = "text"
    setattr(book.properties, name, "PROPERTY_SECRET")
    book.save(src)

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "PROPERTY_SECRET")
    # a note, like the character formatting of a document: an author is in every file from Office and never reaches the copy
    assert report.dropped == ["document properties"] and report.complete is True


def test_xlsx_custom_properties_are_document_properties_too(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    book = openpyxl.Workbook()
    book.custom_doc_props.append(StringProperty(name="Client", value="PROPERTY_SECRET"))
    book.save(src)
    assert "docProps/custom.xml" in zipfile.ZipFile(src).namelist()

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "PROPERTY_SECRET")
    assert report.dropped == ["document properties"] and report.complete is True


@pytest.mark.parametrize("tag", ["Company", "Manager"])
def test_xlsx_company_and_manager_are_document_properties_too(tmp_path, tag):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    openpyxl.Workbook().save(src)
    named = f"<{tag}>PROPERTY_SECRET</{tag}>".encode()
    rewrite_zip(src, {"docProps/app.xml": lambda xml: xml.replace(b"</Properties>", named + b"</Properties>")})

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "PROPERTY_SECRET")
    assert report.dropped == ["document properties"] and report.complete is True


@pytest.mark.parametrize(
    "empty",
    [EMPTY_CUSTOM_PROPERTIES, EMPTY_CUSTOM_PROPERTIES.replace(b"></Properties>", b"/>")],
    ids=["open and close", "self-closing"],
)
def test_xlsx_an_empty_custom_properties_part_is_not_named(tmp_path, empty):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    openpyxl.Workbook().save(src)
    rewrite_zip(src, {"docProps/custom.xml": lambda _: empty})

    report = mask_file(src, dest, MarkerMap())

    assert report.dropped == [] and report.complete is True


def test_xlsx_without_extended_properties_has_no_extra_properties(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    openpyxl.Workbook().save(src)
    rewrite_zip(src, {"docProps/app.xml": None})  # the part is optional
    assert "docProps/app.xml" not in zipfile.ZipFile(src).namelist()

    report = mask_file(src, dest, MarkerMap())

    assert report.dropped == [] and report.complete is True


THUMBNAIL = b"JPEGDATA THUMB_SECRET"


def test_xlsx_thumbnail_is_named(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    openpyxl.Workbook().save(src)
    rewrite_zip(src, {"docProps/thumbnail.jpeg": lambda _: THUMBNAIL})

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "THUMB_SECRET")
    # a note, like the properties: a picture of the first sheet, which never reaches the copy
    assert report.dropped == ["document thumbnail"] and report.complete is True


def test_xlsx_thumbnail_comes_after_the_properties(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    book = openpyxl.Workbook()
    book.properties.creator = "PROPERTY_SECRET"
    book.save(src)
    rewrite_zip(src, {"docProps/thumbnail.jpeg": lambda _: THUMBNAIL})

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "PROPERTY_SECRET", "THUMB_SECRET")
    assert report.dropped == ["document properties", "document thumbnail"] and report.complete is True


@pytest.mark.parametrize(
    "slot, side",
    [
        ("oddHeader", "left"),
        ("oddFooter", "center"),
        ("evenHeader", "right"),
        ("evenFooter", "left"),
        ("firstHeader", "center"),
        ("firstFooter", "right"),
    ],
)
def test_xlsx_print_headers_and_footers_are_named(tmp_path, slot, side):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    book = openpyxl.Workbook()
    book.active.title = "Data"
    book.active["A1"] = "text"
    getattr(getattr(book.active, slot), side).text = "PRINT_SECRET"
    book.save(src)

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "PRINT_SECRET")
    assert report.dropped == ["print headers and footers"] and report.complete is False


@pytest.mark.parametrize(
    "words",
    [
        "&A",
        "&P",
        "&N",
        "&D",
        "&T",
        "&F",
        "&Z",
        "&G",
        "&&",
        "&P / &N",
        "&D &T",
        "Page &P",
        "Page &P of &N",
        "Sheet &A",
        "File: &F",
        "Date: &D",
        "Seite &P von &N",
        "Страница &P из &N",
        '&"Times New Roman,Regular"&12Page &P',
        "&KFF0000&B&UPage &P",
    ],
)
def test_xlsx_print_headers_and_footers_of_only_codes_and_fixed_words_are_not_named(tmp_path, words):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    book = openpyxl.Workbook()
    book.active.title = "Data"
    book.active["A1"] = "text"
    book.active.oddHeader.center.text = words
    book.active.oddFooter.right.text = words
    book.save(src)

    report = mask_file(src, dest, MarkerMap())

    assert report.dropped == [] and report.complete is True  # nothing of the document is in them


# verbatim from a workbook that LibreOffice exported: the sheet name on top, "Page 1" below, on every sheet
LIBREOFFICE_HEADER_FOOTER = (
    b'<headerFooter differentFirst="false" differentOddEven="false">'
    b"<oddHeader>&amp;C&amp;&quot;Times New Roman&quot;&amp;12&amp;A</oddHeader>"
    b"<oddFooter>&amp;C&amp;&quot;Times New Roman&quot;&amp;12Page &amp;P</oddFooter></headerFooter>"
)


def test_xlsx_the_default_header_and_footer_of_libreoffice_leave_the_copy_complete(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    book = openpyxl.Workbook()
    book.active["A1"] = "text"
    book.active.oddHeader.center.text = "placeholder"  # makes openpyxl write the element that is replaced next
    book.save(src)
    rewrite_zip(src, {"xl/worksheets/sheet1.xml": lambda xml: re.sub(rb"<headerFooter>.*?</headerFooter>", LIBREOFFICE_HEADER_FOOTER, xml)})
    assert LIBREOFFICE_HEADER_FOOTER in zipfile.ZipFile(src).read("xl/worksheets/sheet1.xml")

    report = mask_file(src, dest, MarkerMap())

    assert report.dropped == [] and report.complete is True


@pytest.mark.parametrize(
    "words",
    [
        "Confidential",
        "Acme Corp",
        "Acme Corp - Page &P",  # the codes and the fixed words around them do not make the rest harmless
        "Prepared by Ivan Petrov &D",
        "Q&A 2026",
        "AT&T",
        "Invoice 12345",
        "Page 1 of 3",  # a number typed in is text of the document, a code is not
        "&P Конфиденциально",
    ],
)
def test_xlsx_print_headers_and_footers_with_any_other_word_are_named(tmp_path, words):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    book = openpyxl.Workbook()
    book.active["A1"] = "text"
    book.active.oddFooter.left.text = words
    book.save(src)

    report = mask_file(src, dest, MarkerMap())

    assert report.dropped == ["print headers and footers"] and report.complete is False


def test_xlsx_print_headers_of_a_hidden_sheet_are_not_named_twice(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    book = openpyxl.Workbook()
    book.active.title = "Data"
    hidden = book.create_sheet("Old")
    hidden.oddHeader.left.text = "PRINT_SECRET"
    hidden.sheet_state = "hidden"
    book.save(src)

    report = mask_file(src, dest, MarkerMap())

    assert report.dropped == ["hidden sheet Old"]


def test_xlsx_sheet_names_cut_to_the_same_31_characters_stay_distinct(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    book = openpyxl.Workbook()
    book.active.title = "a@b.co c@d.io e@f.org g@h.net"  # 29 characters, 39 once masked: the cut keeps 31
    book.create_sheet("a@b.co c@d.io e@f.org g@h.org")  # the same first 31 characters
    book.create_sheet("a@b.co c@d.io e@f.org g@h.com")
    book.save(src)

    report = mask_file(src, dest, MarkerMap())

    titles = openpyxl.load_workbook(dest).sheetnames
    assert titles[0] == "(EMAIL_1) (EMAIL_2) (EMAIL_3) ("
    assert len(titles) == 3 and len({title.lower() for title in titles}) == 3
    assert all(len(title) <= 31 for title in titles)  # Excel refuses a longer one; openpyxl only warns
    assert len([line for line in report.dropped if line.startswith("sheet name ")]) == 3
    assert report.complete is False


EMOJI = chr(0x1F600)  # one character, two UTF-16 code units


def units(title):
    """How Excel counts the length of a sheet name: in UTF-16 code units."""
    return len(title.encode("utf-16-le")) // 2


def test_xlsx_sheet_names_are_cut_to_31_utf16_code_units(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    book = openpyxl.Workbook()
    book.active.title = EMOJI * 20  # 20 characters, 40 code units
    book.create_sheet("a" * 30 + EMOJI)  # 31 characters, 32 units: the emoji does not fit, and it is not cut in two
    book.create_sheet("b" * 29 + EMOJI)  # 30 characters, 31 units: fits
    book.save(src)

    report = mask_file(src, dest, MarkerMap())

    titles = openpyxl.load_workbook(dest).sheetnames
    assert titles == [EMOJI * 15, "a" * 30, "b" * 29 + EMOJI]
    assert all(units(title) <= 31 for title in titles)
    assert len([line for line in report.dropped if line.startswith("sheet name ")]) == 2  # the one that fits is not named
    assert report.complete is False


def test_xlsx_sheet_names_with_emoji_cut_to_the_same_start_stay_distinct(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    book = openpyxl.Workbook()
    book.active.title = EMOJI * 16  # 32 units
    book.create_sheet(EMOJI * 17)
    book.create_sheet(EMOJI * 18)
    book.save(src)

    mask_file(src, dest, MarkerMap())

    titles = openpyxl.load_workbook(dest).sheetnames
    assert titles[0] == EMOJI * 15
    assert len(titles) == 3 and len({title.lower() for title in titles}) == 3
    assert all(units(title) <= 31 for title in titles)  # the number takes its place in the 31 units, too


def test_xlsx_restored_sheet_names_cut_to_the_same_31_characters_stay_distinct(tmp_path):
    src, back = tmp_path / "reply.xlsx", tmp_path / "back.xlsx"
    book = openpyxl.Workbook()
    book.active.title = "(ORG_1)"
    book.create_sheet("(ORG_2)")
    book.save(src)
    markers = MarkerMap()
    markers.marker_for("ORG", "Global Logistics Partners International Ltd")
    markers.marker_for("ORG", "Global Logistics Partners International Inc")

    report, anomalies = restore_file(src, back, markers)

    titles = openpyxl.load_workbook(back).sheetnames
    assert titles[0] == "Global Logistics Partners Inter"
    assert len(set(titles)) == 2 and all(len(title) <= 31 for title in titles)
    assert len([line for line in report.dropped if line.startswith("sheet name ")]) == 2 and anomalies == []


@pytest.mark.parametrize("with_formula", [False, True], ids=["values", "formula"])
def test_xlsx_a_far_styled_cell_does_not_make_reading_build_the_bounding_box(tmp_path, monkeypatch, with_formula):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    book = openpyxl.Workbook()
    sheet = book.active
    sheet["A1"] = "ivan@acme.com"
    if with_formula:  # the formulas are read in a second pass of their own
        sheet["B1"] = "=1+1"
    sheet["AZ2000"].font = Font(bold=True)  # empty and styled: the box A1:AZ2000 holds 104000 cells
    book.save(src)
    built = []
    real = Cell.__init__

    def counting(self, *args, **kwargs):
        built.append(1)
        real(self, *args, **kwargs)

    monkeypatch.setattr(Cell, "__init__", counting)

    mask_file(src, dest, MarkerMap())

    assert len(built) < 100
    monkeypatch.undo()
    assert openpyxl.load_workbook(dest).active["A1"].value == "[EMAIL_1]"


def test_xlsx_sheet_named_like_a_marker_is_not_taken_for_one(tmp_path):
    src, masked, back = tmp_path / "in.xlsx", tmp_path / "masked.xlsx", tmp_path / "back.xlsx"
    book = openpyxl.Workbook()
    book.active.title = "Data"
    book.active["A1"] = "ivan@acme.com"
    book.create_sheet("(EMAIL_1)")["A1"] = "a sheet of its own"
    book.create_sheet("(email_2)")["A1"] = "so is this one"
    book.save(src)
    markers = MarkerMap()

    mask_file(src, masked, markers)

    # text, like [EMAIL_1] in a cell
    assert openpyxl.load_workbook(masked).sheetnames == ["Data", "(LITERAL_1)", "(LITERAL_2)"]
    report, anomalies = restore_file(masked, back, markers)

    assert openpyxl.load_workbook(back).sheetnames == ["Data", "(EMAIL_1)", "(email_2)"]  # not the address of marker 1
    assert anomalies == [] and report.markers_by_kind == {"EMAIL": 1, "LITERAL": 2}


def test_xlsx_restore_reports_every_paren_form_of_a_marker_in_a_sheet_name(tmp_path):
    src, back = tmp_path / "edited.xlsx", tmp_path / "back.xlsx"
    book = openpyxl.Workbook()
    book.active.title = "(email_1)"
    for title in ("(EMAIL 1)", "(EMAIL-1)", "Summary (EMAIL_01)", "( EMAIL_1 )"):
        book.create_sheet(title)
    book.save(src)
    markers = MarkerMap()
    markers.marker_for("EMAIL", "ivan@acme.com")

    _, anomalies = restore_file(src, back, markers)

    assert anomalies == ["[email_1]", "[EMAIL 1]", "[EMAIL-1]", "[EMAIL_01]", "[ EMAIL_1 ]"]  # as they would be in a cell
    names = ["(email_1)", "(EMAIL 1)", "(EMAIL-1)", "Summary (EMAIL_01)", "( EMAIL_1 )"]
    assert openpyxl.load_workbook(back).sheetnames == names


def test_xlsx_restore_reports_a_sheet_name_that_had_to_change(tmp_path):
    src, back = tmp_path / "edited.xlsx", tmp_path / "back.xlsx"
    book = openpyxl.Workbook()
    book.active.title = "(URL_1)"
    book.create_sheet("(ORG_1)")
    book.create_sheet("(EMAIL_1)")
    book.save(src)
    markers = MarkerMap()
    markers.marker_for("URL", "https://crm.acme.internal/clients?id=5")  # characters a sheet name cannot hold
    markers.marker_for("ORG", "Global Logistics Partners International")  # 38 characters
    markers.marker_for("EMAIL", "ivan@acme.com")

    report, anomalies = restore_file(src, back, markers)

    names = ["https___crm.acme.internal_clien", "Global Logistics Partners Inter", "ivan@acme.com"]
    assert openpyxl.load_workbook(back).sheetnames == names
    change = "changed to fit Excel (invalid characters, over 31 characters or a duplicate)"
    assert report.dropped == [f"sheet name [URL_1] {change}", f"sheet name [ORG_1] {change}"]
    assert report.checked == ["sheet [URL_1]", "sheet [ORG_1]", "sheet [EMAIL_1]"]
    assert report.complete is False and anomalies == []


def test_xlsx_other_parts_are_dropped_and_named(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    book = openpyxl.Workbook()
    sheet = book.active
    sheet.title = "Data"
    sheet.append(["item", "margin"])
    sheet.append(["a", 3])
    sheet.append(["b", 4])
    chart = BarChart()
    chart.title = "Orion margin"
    chart.add_data(Reference(sheet, min_col=2, min_row=1, max_row=3), titles_from_data=True)
    sheet.add_chart(chart, "E2")
    book.defined_names["Rate"] = DefinedName("Rate", attr_text="Data!$B$2")
    validation = DataValidation(type="list", formula1='"Acme,Globex"')
    sheet.add_data_validation(validation)
    validation.add("A2")
    book.save(src)
    rewrite_zip(
        src,
        {
            "xl/externalLinks/externalLink1.xml": lambda _: b"<externalLink/>",
            "xl/pivotCache/pivotCacheRecords1.xml": lambda _: b"<pivotCacheRecords>CACHE_SECRET</pivotCacheRecords>",
        },
    )

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "Orion", "Acme,Globex", "Data!$B$2", "externalLink", "CACHE_SECRET")
    assert report.dropped == ["images and charts", "defined names", "data validation", "external links", "pivot tables"]
    assert report.complete is False


def test_xlsx_restore_reports_unknown_markers_in_cells_and_names(tmp_path):
    src, masked, edited, back = (tmp_path / name for name in ("in.xlsx", "masked.xlsx", "edited.xlsx", "back.xlsx"))
    book = openpyxl.Workbook()
    book.active.append(["ivan@acme.com", "note"])
    book.save(src)
    markers = MarkerMap()
    mask_file(src, masked, markers)
    book = openpyxl.load_workbook(masked)
    book.active["B1"] = "see [EMAIL_9]"
    book.active.title = "(EMAIL_8)"
    book.save(edited)

    _, anomalies = restore_file(edited, back, markers)

    assert anomalies == ["[EMAIL_8]", "[EMAIL_9]"]  # the sheet name comes first
    restored = openpyxl.load_workbook(back)
    assert restored.sheetnames == ["(EMAIL_8)"] and restored.active["B1"].value == "see [EMAIL_9]"
    assert restored.active["A1"].value == "ivan@acme.com"


# A column whose header names a secret holds secrets, whatever they look like: "summer2024" alone is a word and a number, under
# "password" it is a password. Every value under such a header is masked whole; the header and the other columns are read as usual.
@pytest.mark.parametrize("delimiter", [",", "\t", ";"])
def test_csv_values_under_a_secret_header_are_masked_whatever_they_look_like(tmp_path, delimiter):
    src, dest, back = tmp_path / "logins.csv", tmp_path / "logins.masked.csv", tmp_path / "back.csv"
    rows = [["login", "Password", "API key", "note"], ["admin", "summer2024", "letmein", "plain"], ["anna", "", "qwerty", "x"]]
    src.write_text("".join(delimiter.join(row) + "\r\n" for row in rows))
    markers = MarkerMap()

    report = mask_file(src, dest, markers)

    assert_clean(dest, "summer2024", "letmein", "qwerty")
    masked = dest.read_text().splitlines()
    assert masked[0] == delimiter.join(rows[0])  # the header is a label
    assert masked[1] == delimiter.join(["admin", "[SECRET_1]", "[SECRET_2]", "plain"])
    assert masked[2] == delimiter.join(["anna", "", "[SECRET_3]", "x"])  # an empty cell stays empty
    assert report.markers_by_kind == {"SECRET": 3} and report.complete is True
    restore_file(dest, back, markers)
    assert back.read_bytes() == src.read_bytes()


def test_csv_a_secret_header_after_blank_lines_still_counts_and_the_same_word_in_data_is_no_header(tmp_path):
    src, dest = tmp_path / "a.csv", tmp_path / "m.csv"
    src.write_text("\r\ntoken,user\r\nabcd1234,password\r\n")
    mask_file(src, dest, MarkerMap())
    assert dest.read_bytes() == b"\r\ntoken,user\r\n[SECRET_1],password\r\n"


# The delimiter is read from the header and the data rows together. A semicolon file whose rows are of different widths (an empty
# last field that some rows leave out) defeats csv.Sniffer; a guessed comma made the header one cell and copied the passwords.
RAGGED_SEMICOLON = "login;password;note\r\nadmin;Summer2024;\r\nanna;Winter2025\r\nbob;Autumn2023;x\r\n"


def test_csv_a_semicolon_file_with_rows_of_different_widths_masks_the_secret_column(tmp_path):
    src, dest, back = tmp_path / "logins.csv", tmp_path / "logins.masked.csv", tmp_path / "back.csv"
    src.write_text(RAGGED_SEMICOLON, newline="")
    markers = MarkerMap()

    report = mask_file(src, dest, markers)

    assert_clean(dest, "Summer2024", "Winter2025", "Autumn2023")
    assert dest.read_bytes() == b"login;password;note\r\nadmin;[SECRET_1];\r\nanna;[SECRET_2]\r\nbob;[SECRET_3];x\r\n"
    assert report.complete is True and report.markers_by_kind == {"SECRET": 3}
    _, anomalies = restore_file(dest, back, markers)
    assert back.read_bytes() == src.read_bytes() and anomalies == []


@pytest.mark.parametrize(
    "text,named",
    [
        ("id,user;token\r\n1,admin;Summer2024\r\n", ";"),  # a header of two cells with ";" and with ",", and so is every row
        ("user,password\r\nadmin;Summer2024\r\n", ","),  # a comma header over rows that a semicolon splits
        ("user;password\r\nadmin;Summer2024;extra;more\r\n", ";"),  # rows wider than the header
    ],
)
def test_csv_whose_delimiter_cannot_be_told_is_refused_and_a_named_one_is_used(tmp_path, text, named):
    from boxed.formats.tabular import AMBIGUOUS_DELIMITER

    src, dest = tmp_path / "logins.csv", tmp_path / "logins.masked.csv"
    src.write_text(text, newline="")

    with pytest.raises(FormatError) as raised:
        mask_file(src, dest, MarkerMap())

    assert str(raised.value) == AMBIGUOUS_DELIMITER and "Summer2024" not in str(raised.value)
    assert not dest.exists() and [p.name for p in tmp_path.iterdir()] == ["logins.csv"]
    report = mask_file(src, dest, MarkerMap(), delimiter=named)  # the person's word decides, whatever the rows look like
    assert report.complete is True and dest.exists()


def test_csv_one_column_keeps_a_cell_with_a_delimiter_in_it_whole(tmp_path):
    src, dest = tmp_path / "pw.csv", tmp_path / "m.csv"
    src.write_text("password\nfoo;Summer2024\nbar,Winter2025\n", newline="")
    mask_file(src, dest, MarkerMap())
    assert dest.read_bytes() == b"password\n[SECRET_1]\n[SECRET_2]\n"


def test_mask_file_on_the_command_line_names_the_delimiter(tmp_path, capsys, monkeypatch):
    from boxed.cli import main
    from boxed.formats.tabular import AMBIGUOUS_DELIMITER

    monkeypatch.chdir(tmp_path)
    (tmp_path / "logins.csv").write_text("id,user;token\r\n1,admin;Summer2024\r\n", newline="")
    assert main(["mask-file", "logins.csv", "out.csv"]) == 2
    assert capsys.readouterr().err == f"boxed: error: {AMBIGUOUS_DELIMITER}\n" and not (tmp_path / "out.csv").exists()
    assert main(["mask-file", "--delimiter", "semicolon", "logins.csv", "out.csv"]) == 0
    assert (tmp_path / "out.csv").read_bytes() == b"id,user;token\r\n1,admin;[SECRET_1]\r\n"


def test_without_the_formats_extra_the_error_points_to_the_install_guide_and_not_to_pypi(tmp_path, monkeypatch):
    import importlib

    import boxed.formats

    real = importlib.import_module
    monkeypatch.setattr(importlib, "import_module", lambda name, *a: (_ for _ in ()).throw(ImportError(name)) if name == "openpyxl" else real(name, *a))
    book = openpyxl.Workbook()
    book.save(tmp_path / "a.xlsx")
    with pytest.raises(FormatError) as raised:
        mask_file(tmp_path / "a.xlsx", tmp_path / "b.xlsx", MarkerMap())
    assert str(raised.value) == boxed.formats.FORMATS_EXTRA
    assert "docs/guide/install.md" in str(raised.value) and "pip" not in str(raised.value) and "boxedsi[" not in str(raised.value)


# The header of a sheet is the first row of visible cells, and the header row of every table the sheet declares: a hidden row
# above the header, or a title above a table, made the password column an ordinary one.
def test_xlsx_a_hidden_row_before_the_visible_header_does_not_hide_the_secret_column(tmp_path):
    src, dest = tmp_path / "logins.xlsx", tmp_path / "logins.masked.xlsx"
    book = openpyxl.Workbook()
    sheet = book.active
    sheet.append(["internal note"])
    sheet.append(["login", "password"])
    sheet.append(["admin", "Summer2024"])
    sheet.row_dimensions[1].hidden = True
    book.save(src)

    report = mask_file(src, dest, MarkerMap())

    assert_clean(dest, "Summer2024", "internal note")
    copy = openpyxl.load_workbook(dest).active
    assert (copy["A2"].value, copy["B2"].value, copy["A3"].value, copy["B3"].value) == ("login", "password", "admin", "[SECRET_1]")
    assert report.dropped == ["hidden rows"] and report.complete is False


def test_xlsx_the_header_of_a_declared_table_names_its_secret_columns(tmp_path):
    from openpyxl.worksheet.table import Table

    src, dest = tmp_path / "logins.xlsx", tmp_path / "logins.masked.xlsx"
    book = openpyxl.Workbook()
    sheet = book.active
    sheet["A1"] = "Accounts of the team"
    sheet["B4"], sheet["C4"] = "user", "Password"
    sheet["B5"], sheet["C5"] = "admin", "Summer2024"
    sheet["B6"], sheet["C6"] = "anna", "Winter2025"
    sheet["C8"] = "Autumn2023"  # below the table: an ordinary cell
    sheet.add_table(Table(displayName="Accounts", ref="B4:C6"))
    book.save(src)

    mask_file(src, dest, MarkerMap())

    copy = openpyxl.load_workbook(dest).active
    assert (copy["C4"].value, copy["C5"].value, copy["C6"].value) == ("Password", "[SECRET_1]", "[SECRET_2]")
    assert copy["C8"].value == "Autumn2023" and copy["A1"].value == "Accounts of the team"


def test_xlsx_values_under_a_secret_header_are_masked_and_a_number_comes_back_a_number(tmp_path):
    src, dest, back = tmp_path / "logins.xlsx", tmp_path / "logins.masked.xlsx", tmp_path / "back.xlsx"
    book = openpyxl.Workbook()
    book.active.title = "Logins"
    book.active.append(["login", "Пароль", "DB_TOKEN", "flag"])
    book.active.append(["admin", "summer2024", 123456, True])
    book.active.append(["anna", "letmein", None, False])
    book.save(src)
    markers = MarkerMap()

    report = mask_file(src, dest, markers)

    assert_clean(dest, "summer2024", "letmein", "123456")
    rows = values_of(openpyxl.load_workbook(dest)["Logins"])
    assert rows[0] == ["login", "Пароль", "DB_TOKEN", "flag"]
    assert rows[1] == ["admin", "[SECRET_1]", "[SECRET_2]", True] and rows[2][:2] == ["anna", "[SECRET_3]"]
    assert report.markers_by_kind == {"SECRET": 3} and report.complete is True
    restore_file(dest, back, markers)
    restored = values_of(openpyxl.load_workbook(back)["Logins"])
    assert restored[1] == ["admin", "summer2024", 123456, True] and type(restored[1][2]) is int and restored[2][:2] == ["anna", "letmein"]
