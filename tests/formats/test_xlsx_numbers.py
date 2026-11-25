"""XLSX numbers and dates at level 3: every number and date cell is read as the text Excel shows, and masked from it."""

import datetime
import json
import re
import tempfile
import time
import zipfile
from pathlib import Path

import openpyxl
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from boxed.detect import DetectConfig
from boxed.formats import FormatError, mask_file, restore_file
from boxed.mask import MarkerMap, dictionary_kinds, mask_text, restore

from . import assert_clean, rewrite_zip

STAMP = datetime.datetime(2026, 10, 21, 14, 30, 5)


def workbook(path, cells, title="Data"):
    """One sheet; cells maps a reference to a value or to (value, number format)."""
    book = openpyxl.Workbook()
    sheet = book.active
    sheet.title = title
    for ref, item in cells.items():
        value, fmt = item if isinstance(item, tuple) else (item, None)
        sheet[ref] = value
        if fmt:
            sheet[ref].number_format = fmt
    book.save(path)


def values_of(sheet):
    return [[cell.value for cell in row] for row in sheet.iter_rows()]


def sheet_xml(path):
    return zipfile.ZipFile(path).read("xl/worksheets/sheet1.xml")


def plant_cached_value(path, ref, kind, value):
    """openpyxl never writes the result of a formula, Excel always does."""
    pattern = rf'<c r="{ref}"([^>]*)><f>(.*?)</f><v></v>'.encode()
    replacement = rf'<c r="{ref}"\1 t="{kind}"><f>\2</f><v>{value}</v>'.encode()
    rewrite_zip(path, {"xl/worksheets/sheet1.xml": lambda xml: re.sub(pattern, replacement, xml)})


@pytest.mark.parametrize(
    "value, fmt, kind",
    [
        (1234.5678, None, "NUMBER"),
        (1200, None, "NUMBER"),
        (1200.0, None, "NUMBER"),
        (-5.25, None, "NUMBER"),
        (1e-7, None, "NUMBER"),
        (12345678901234, None, "NUMBER"),
        (1234.5, '#,##0.00 "EUR"', "MONEY"),
        (1200, '#,##0 "EUR"', "MONEY"),
        (1234.5, "$#,##0.00", "MONEY"),
        (1234.5, '#,##0.00\\ "₽"', "MONEY"),
        (5, "$0", "MONEY"),  # a lone digit is no number, but with a currency sign it is an amount
        (5, '0 "EUR"', "MONEY"),
        (0.15, "0%", "PERCENT"),
        (0.153, "0.0%", "PERCENT"),
        (0.05, "0%", "PERCENT"),  # shows "5%"
        (1234.5678, "0", "NUMBER"),  # shows "1235"
        (5.123, "0", "NUMBER"),  # shows a lone "5": the cell still holds 5.123
        (0.5, "0", "NUMBER"),
        (STAMP, "dd.mm.yyyy", "DATE"),
        (STAMP, "yyyy-mm-dd hh:mm:ss", "DATE"),
        (STAMP, "d mmmm yyyy", "DATE"),
        (STAMP, "mmmm yyyy", "DATE"),
        (STAMP, "mmm", "DATE"),  # shows "Oct": the day and the year are still in the cell
        (STAMP, "yy", "DATE"),  # shows "26", which alone reads as a number
        (STAMP, "dddd", "DATE"),
        (datetime.datetime(2026, 10, 21), "yyyy-mm-dd", "DATE"),
        (datetime.time(14, 30), "hh:mm", "NUMBER"),
        (datetime.time(9, 5, 3), "h:mm:ss AM/PM", "NUMBER"),
        (datetime.timedelta(hours=26, minutes=3, seconds=4), "[h]:mm:ss", "NUMBER"),
    ],
)
def test_level_3_masks_a_number_or_date_cell_with_the_kind_its_format_shows(tmp_path, value, fmt, kind):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    workbook(src, {"A1": (value, fmt)})

    report = mask_file(src, dest, MarkerMap(), level=3)

    cell = openpyxl.load_workbook(dest)["Data"]["A1"]
    assert cell.value == f"[{kind}_1]" and cell.data_type == "s"
    assert report.markers_by_kind == {kind: 1}
    assert report.checked == ["sheet Data"] and report.dropped == [] and report.complete is True


def test_level_3_leaves_no_number_or_date_value_in_the_copy(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    workbook(
        src,
        {
            "A1": 1234.5678,
            "A2": (STAMP, "dd.mm.yyyy"),
            "A3": (0.15, "0%"),
            "A4": (datetime.time(14, 30), "hh:mm"),
            "A5": (-5.25, "#,##0.00;(#,##0.00)"),
            "A6": 1e-7,
            "A7": 12345678901234,
            "A8": (datetime.timedelta(hours=26, minutes=3, seconds=4), "[h]:mm:ss"),
            "A9": "plain text",
        },
    )

    report = mask_file(src, dest, MarkerMap(), level=3)

    sheet = openpyxl.load_workbook(dest)["Data"]
    assert [cell.value for cell in sheet["A"]] == [
        "[NUMBER_1]",
        "[DATE_1]",
        "[PERCENT_1]",
        "[NUMBER_2]",
        "[NUMBER_3]",
        "[NUMBER_4]",
        "[NUMBER_5]",
        "[NUMBER_6]",
        "plain text",
    ]
    assert_clean(dest, "1234.5678", "46316", "0.15", "5.25", "12345678901234", "0.6041")  # a serial day or fraction is a leak too
    cells = re.findall(rb"<c [^>]*>", sheet_xml(dest))
    assert len(cells) == 9 and all(re.search(rb't="(?:s|inlineStr)"', cell) for cell in cells)  # all text: no number or date cell is left
    assert report.markers_by_kind == {"NUMBER": 6, "DATE": 1, "PERCENT": 1}


@pytest.mark.parametrize("level", [0, 1, 2])
def test_levels_0_to_2_keep_decimals_dates_and_times_as_they_are(tmp_path, level):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    cells = {
        "A1": 1234.5678,
        "A2": 99.5,
        "A3": (STAMP, "dd.mm.yyyy"),
        "A4": (0.15, "0%"),
        "A5": (datetime.time(14, 30), "hh:mm"),
        "A6": (datetime.timedelta(hours=26), "[h]:mm:ss"),
        "A7": 42,
        "A8": True,
        "A9": (1234.5, '#,##0.00 "EUR"'),
    }
    workbook(src, cells)

    report = mask_file(src, dest, MarkerMap(), level=level)

    before, after = openpyxl.load_workbook(src)["Data"], openpyxl.load_workbook(dest)["Data"]
    assert values_of(after) == values_of(before)
    assert [type(c.value) for c in after["A"]] == [type(c.value) for c in before["A"]]
    assert report.markers_by_kind == {} and report.dropped == [] and report.complete is True


def test_a_card_number_stored_as_a_number_is_still_a_card_at_level_3(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    workbook(src, {"A1": 4111111111111111, "A2": 42, "A3": 7, "A4": 7.0})

    report = mask_file(src, dest, MarkerMap(), level=3)

    assert [c.value for c in openpyxl.load_workbook(dest)["Data"]["A"]] == ["[CARD_1]", "[NUMBER_1]", 7, 7]
    assert report.markers_by_kind == {"CARD": 1, "NUMBER": 1}


def test_a_card_is_a_card_in_either_reading_of_its_cell(tmp_path):
    # Excel keeps a number of more than 15 digits as a float, and shown with 15 digits it is 4111111111111110, which is no card
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    workbook(src, {"A1": 4111111111111111, "A2": 1234.5, "A3": (4111111111111111, "$#,##0"), "A4": (79991234567, "+0 (000) 000-00-00")})
    rewrite_zip(src, {"xl/worksheets/sheet1.xml": lambda xml: xml.replace(b"<v>4111111111111111</v>", b"<v>4.111111111111111E+15</v>", 1)})
    assert type(openpyxl.load_workbook(src)["Data"]["A1"].value) is float

    report = mask_file(src, dest, MarkerMap(), level=3)

    # the dollars of the third cell are a number in the shown text and a card in the stored one: the card is the stricter kind
    assert [c.value for c in openpyxl.load_workbook(dest)["Data"]["A"]] == ["[CARD_1]", "[NUMBER_1]", "[CARD_2]", "[PHONE_1]"]
    assert report.markers_by_kind == {"CARD": 2, "NUMBER": 1, "PHONE": 1}


def test_a_term_of_the_dictionary_in_the_shown_text_of_a_cell_wins_over_its_number(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    workbook(src, {"A1": (12.5, '0.00 "Acme"'), "A2": 12.5})  # shows "12.50 Acme": the number is longer, the term is stricter

    mask_file(src, dest, MarkerMap(), level=3, config=DetectConfig(dictionary={"Acme": "CLIENT"}))

    assert [c.value for c in openpyxl.load_workbook(dest)["Data"]["A"]] == ["[CLIENT_1]", "[NUMBER_1]"]


def test_equal_values_get_equal_markers_in_every_cell_sheet_and_kind_of_cell(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    book = openpyxl.Workbook()
    book.active.title = "One"
    book.active.append([99.5, "99.5", 99.5, 12345, "12345", 12345.0])
    book.create_sheet("Two").append([99.5, 12345, 100.25])
    book.save(src)

    report = mask_file(src, dest, MarkerMap(), level=3)

    copy = openpyxl.load_workbook(dest)
    assert values_of(copy["One"]) == [["[NUMBER_1]", "[NUMBER_1]", "[NUMBER_1]", "[NUMBER_2]", "[NUMBER_2]", "[NUMBER_2]"]]
    assert values_of(copy["Two"]) == [["[NUMBER_1]", "[NUMBER_2]", "[NUMBER_3]"]]
    assert report.markers_by_kind == {"NUMBER": 9}


def test_a_lone_digit_is_structure_as_in_text(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    workbook(src, {"A1": 7, "A2": 7.0, "A3": 0, "A4": -3, "A5": 0.0, "A6": (9, "0")})

    report = mask_file(src, dest, MarkerMap(), level=3)

    assert values_of(openpyxl.load_workbook(dest)["Data"]) == [[7], [7], [0], [-3], [0], [9]]
    assert report.markers_by_kind == {}


def test_booleans_text_and_empty_cells_are_not_numbers(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    workbook(src, {"A1": True, "A2": False, "A3": "a note", "A5": "2026"})

    report = mask_file(src, dest, MarkerMap(), level=3)

    # the text "2026" is a text cell: it is masked as the text it is, by the same detectors
    assert values_of(openpyxl.load_workbook(dest)["Data"]) == [[True], [False], ["a note"], [None], ["[NUMBER_1]"]]
    assert report.markers_by_kind == {"NUMBER": 1}


@pytest.mark.parametrize("days", [3_000_000, -700_000])
def test_a_duration_that_no_date_holds_is_masked_at_level_3_and_does_not_stop_the_copy(tmp_path, days):
    # Excel shows 3000000 days as 72000000:00:00; Python holds no date that far, and level 2 never reads the cell
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    workbook(src, {"A1": (datetime.timedelta(days=days), "[h]:mm:ss"), "A2": "a note"})
    assert openpyxl.load_workbook(src)["Data"]["A1"].value == datetime.timedelta(days=days)
    mask_file(src, dest, MarkerMap(), level=2)
    assert openpyxl.load_workbook(dest)["Data"]["A1"].value == datetime.timedelta(days=days)

    report = mask_file(src, dest, MarkerMap(), level=3)

    assert values_of(openpyxl.load_workbook(dest)["Data"]) == [["[NUMBER_1]"], ["a note"]]
    assert report.markers_by_kind == {"NUMBER": 1} and report.complete is True


def test_the_cached_result_of_a_formula_is_masked_like_any_other_number(tmp_path):
    src, dest = tmp_path / "calc.xlsx", tmp_path / "calc.masked.xlsx"
    book = openpyxl.Workbook()
    sheet = book.active
    sheet.title = "Calc"
    sheet["A1"], sheet["B1"], sheet["B2"], sheet["B3"] = 10.5, "=A1*2", "=DATE(2026,10,21)", "=A1/10"
    sheet["B2"].number_format = "yyyy-mm-dd"
    book.save(src)
    plant_cached_value(src, "B1", "n", "21")
    plant_cached_value(src, "B2", "n", "46316")
    plant_cached_value(src, "B3", "n", "1.05")

    report = mask_file(src, dest, MarkerMap(), level=3)

    assert values_of(openpyxl.load_workbook(dest)["Calc"]) == [["[NUMBER_1]", "[NUMBER_2]"], [None, "[DATE_1]"], [None, "[NUMBER_3]"]]
    assert_clean(dest, "10.5", "46316", "1.05")
    assert report.dropped == ["formulas (cached values kept)"] and report.complete is True


def test_a_merged_range_holds_its_value_in_the_first_cell(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    book = openpyxl.Workbook()
    sheet = book.active
    sheet.title = "Data"
    sheet["A1"] = 4321.5
    sheet.merge_cells("A1:C1")
    sheet["A2"] = STAMP
    sheet.merge_cells("A2:B3")
    book.save(src)

    mask_file(src, dest, MarkerMap(), level=3)

    copy = openpyxl.load_workbook(dest)["Data"]
    assert [copy[ref].value for ref in ("A1", "B1", "C1", "A2", "B2", "A3")] == ["[NUMBER_1]", None, None, "[DATE_1]", None, None]
    assert_clean(dest, "4321.5")


def test_level_4_masks_the_cells_like_level_3(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    workbook(src, {"A1": (1234.5, '#,##0.00 "EUR"'), "A2": (STAMP, "dd.mm.yyyy")})

    mask_file(src, dest, MarkerMap(), level=4)

    assert [c.value for c in openpyxl.load_workbook(dest)["Data"]["A"]] == ["[MONEY_1]", "[DATE_1]"]


def test_what_the_person_allowed_stays_and_the_dictionary_applies_to_numbers(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    workbook(src, {"A1": 2026, "A2": 4711, "A3": 1999, "A4": 12.5})
    config = DetectConfig(allow={"2026"}, dictionary={"4711": "CASE"})

    report = mask_file(src, dest, MarkerMap(), level=3, config=config)

    assert [c.value for c in openpyxl.load_workbook(dest)["Data"]["A"]] == [2026, "[CASE_1]", "[NUMBER_1]", "[NUMBER_2]"]
    assert report.markers_by_kind == {"CASE": 1, "NUMBER": 2}


def test_numbers_never_go_to_the_name_models(tmp_path):
    class Exploding:
        def find(self, text):
            if re.search(r"\d", text):  # the sheet title "Data" is text and may go to the name models
                raise AssertionError("a name model read a number")
            return []

    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    workbook(src, {"A1": 1234.5, "A2": (STAMP, "dd.mm.yyyy")})

    mask_file(src, dest, MarkerMap(), level=3, config=DetectConfig(ner=[Exploding()]))

    assert [c.value for c in openpyxl.load_workbook(dest)["Data"]["A"]] == ["[NUMBER_1]", "[DATE_1]"]


def test_an_error_while_reading_a_number_names_no_value(tmp_path, monkeypatch):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    workbook(src, {"A1": 1234.5678})

    def broken(value):
        raise ValueError(f"cannot read {value!r}")

    monkeypatch.setattr("boxed.formats.display.exact", broken)

    with pytest.raises(FormatError, match="^cannot process this xlsx file$") as raised:
        mask_file(src, dest, MarkerMap(), level=3)

    assert "1234.5678" not in str(raised.value) and raised.value.__suppress_context__
    assert not dest.exists()


def test_the_report_holds_counts_and_names_never_values(tmp_path):
    src, dest = tmp_path / "in.xlsx", tmp_path / "out.xlsx"
    workbook(src, {"A1": 1234.5678, "A2": (STAMP, "dd.mm.yyyy")})

    report = mask_file(src, dest, MarkerMap(), level=3)

    assert report.markers_by_kind == {"NUMBER": 1, "DATE": 1}
    assert not re.search(r"\d{2,}", repr(report))  # counts of one digit are all the digits there are


def test_a_big_sheet_of_numbers_is_masked_in_linear_time(tmp_path):
    src, dest = tmp_path / "big.xlsx", tmp_path / "big.masked.xlsx"
    book = openpyxl.Workbook()
    sheet = book.active
    for row in range(4000):
        sheet.append([row + 0.25, row * 7 + 1000, STAMP + datetime.timedelta(minutes=row), "note"])
    book.save(src)

    started = time.perf_counter()
    report = mask_file(src, dest, MarkerMap(), level=3)
    elapsed = time.perf_counter() - started

    assert report.markers_by_kind == {"NUMBER": 8000, "DATE": 4000}
    assert elapsed < 20, f"12000 number cells took {elapsed:.1f} s"


# --- restore: the original value comes back with its type -----------------------------------------------------------------


def typed_values(book):
    """The values of the cells that still hold a number, a date, a time or a duration."""
    typed = (int, float, datetime.date, datetime.time, datetime.timedelta)
    return [c.value for sheet in book for row in sheet.iter_rows() for c in row if isinstance(c.value, typed) and not isinstance(c.value, bool)]


def every_cell_type(path):
    """Every kind of cell in two sheets, a merged range, a formula with a cached result and a second sheet with a title that is masked."""
    book = openpyxl.Workbook()
    sheet = book.active
    sheet.title = "Types"
    rows = [
        ("text", "a note for Ivan"),
        ("whole", 1200),
        ("decimal", (1234.5678, None)),
        ("negative", (-5.25, "#,##0.00;(#,##0.00)")),
        ("percent", (0.15, "0%")),
        ("money", (1234.5, '#,##0.00 "EUR"')),
        ("date", (STAMP, "dd.mm.yyyy")),
        ("midnight", (datetime.datetime(2026, 10, 22), "yyyy-mm-dd")),
        ("datetime", (STAMP + datetime.timedelta(days=1, microseconds=500000), "yyyy-mm-dd hh:mm:ss.000")),
        ("time", (datetime.time(14, 30, 5), "hh:mm:ss")),
        ("elapsed", (datetime.timedelta(hours=26, minutes=3, seconds=4), "[h]:mm:ss")),
        ("lone digit", 7),
        ("zero", 0),
        ("bool", True),
        ("text number", "00123"),
        ("text decimal", "12.50"),
        ("text date", "2026-11-03"),
        ("text amount", "3 400 000 руб."),
        ("error", "#DIV/0!"),
        ("empty", None),
        ("tiny", 1.5e-7),
        ("huge", 12345678901234567890.0),
    ]
    for row, (name, item) in enumerate(rows, start=1):
        value, fmt = item if isinstance(item, tuple) else (item, None)
        sheet.cell(row=row, column=1, value=name)
        sheet.cell(row=row, column=2, value=value)
        if fmt:
            sheet.cell(row=row, column=2).number_format = fmt
    sheet["D1"] = 4321.5
    sheet.merge_cells("D1:F2")
    sheet["H1"], sheet["H2"], sheet["H3"] = 10.25, "=H1*2", "=DATE(2026,10,21)"
    sheet["H3"].number_format = "yyyy-mm-dd"
    other = book.create_sheet("Other")
    other.append([1234.5678, 99.5, STAMP, "text", 4321.5])
    other.append([None, 1234.5678, datetime.date(2026, 12, 31)])
    book.save(path)
    plant_cached_value(path, "H2", "n", "20.5")
    plant_cached_value(path, "H3", "n", "46316")


def test_restore_gives_a_workbook_with_every_cell_type_back(tmp_path):
    src, masked, back = tmp_path / "in.xlsx", tmp_path / "masked.xlsx", tmp_path / "back.xlsx"
    every_cell_type(src)
    markers = MarkerMap()

    report = mask_file(src, masked, markers, level=3)

    assert typed_values(openpyxl.load_workbook(masked)) == [7, 0]  # the lone digits are all that is left
    assert_clean(masked, "1234.5678", "1234.5", "4321.5", "10.25", "46316", "12345678901234567", "0.15")
    assert report.dropped == ["formulas (cached values kept)"] and report.complete is True

    restored, anomalies = restore_file(masked, back, MarkerMap.from_json(markers.to_json()))  # as the vault hands the map back

    assert anomalies == [] and restored.dropped == [] and restored.complete is True
    before, after = openpyxl.load_workbook(src, data_only=True), openpyxl.load_workbook(back)
    assert after.sheetnames == before.sheetnames
    for name in before.sheetnames:
        assert values_of(after[name]) == values_of(before[name])
        assert [[type(c.value) for c in row] for row in after[name].iter_rows()] == [[type(c.value) for c in row] for row in before[name].iter_rows()]
    assert report.markers_by_kind == restored.markers_by_kind
    assert after["Types"]["B7"].is_date and after["Types"]["B10"].is_date and after["Types"]["B11"].is_date  # a date shows as a date


def model_file(masked, path, edit):
    """What a model sends back: the masked workbook, changed."""
    book = openpyxl.load_workbook(masked)
    edit(book)
    book.save(path)


def test_a_placeholder_comes_back_typed_only_in_the_cell_it_stood_in(tmp_path):
    src, masked, answer, back = (tmp_path / name for name in ("in.xlsx", "masked.xlsx", "answer.xlsx", "back.xlsx"))
    workbook(src, {"A1": 1234.5, "A2": (STAMP, "dd.mm.yyyy"), "A3": 98.75})
    markers = MarkerMap()
    mask_file(src, masked, markers, level=3)

    def edit(book):
        sheet = book["Data"]
        sheet["B1"], sheet["B2"], sheet["B3"] = "Total: [NUMBER_1]", " [NUMBER_1]", "[NUMBER_1] and [NUMBER_2]"
        sheet["B4"], sheet["C1"] = "[DATE_1]", "[NUMBER_2]"  # a copy of a cell and a cell the model made itself

    model_file(masked, answer, edit)

    report, anomalies = restore_file(answer, back, markers)

    after = openpyxl.load_workbook(back)["Data"]
    assert anomalies == []
    assert [after[ref].value for ref in ("A1", "A2", "A3")] == [1234.5, STAMP, 98.75]  # where the masked copy had them: numbers, a date
    assert [after[ref].value for ref in ("B4", "C1")] == ["21.10.2026", "98.75"]  # elsewhere: the text the person saw
    assert [after[ref].value for ref in ("B1", "B2", "B3")] == ["Total: 1234.5", " 1234.5", "1234.5 and 98.75"]
    assert report.markers_by_kind == {"NUMBER": 7, "DATE": 2}


def test_a_text_cell_that_looks_like_a_number_or_a_date_stays_text(tmp_path):
    src, masked, back = tmp_path / "in.xlsx", tmp_path / "masked.xlsx", tmp_path / "back.xlsx"
    workbook(src, {"A1": "1200", "A2": "00123", "A3": "2026-10-21", "A4": "12.50", "A5": 99.5, "A6": "21.10.2026", "A7": "1 200 EUR"})
    markers = MarkerMap()
    mask_file(src, masked, markers, level=3)
    assert all(isinstance(c.value, str) and c.value.startswith("[") for c in openpyxl.load_workbook(masked)["Data"]["A"])

    restore_file(masked, back, markers)

    assert values_of(openpyxl.load_workbook(back)["Data"]) == [["1200"], ["00123"], ["2026-10-21"], ["12.50"], [99.5], ["21.10.2026"], ["1 200 EUR"]]


def test_a_text_cell_beside_a_number_cell_with_the_same_digits_stays_text(tmp_path):
    # the two cells share a marker, because they show the same text; only the cell that held a number gets a number back
    src, masked, back = tmp_path / "in.xlsx", tmp_path / "masked.xlsx", tmp_path / "back.xlsx"
    workbook(src, {"A1": "79161234567", "A2": 79161234567, "A3": "1200", "A4": 1200, "B3": 1200, "B4": "1200"})
    markers = MarkerMap()
    mask_file(src, masked, markers, level=3)
    copy = openpyxl.load_workbook(masked)["Data"]
    assert copy["A1"].value == copy["A2"].value and copy["A3"].value == copy["A4"].value == copy["B3"].value == copy["B4"].value

    restore_file(masked, back, markers)

    assert values_of(openpyxl.load_workbook(back)["Data"]) == [["79161234567", None], [79161234567, None], ["1200", 1200], [1200, "1200"]]


def test_a_marker_that_no_number_cell_made_comes_back_as_text(tmp_path):
    answer, back = tmp_path / "answer.xlsx", tmp_path / "back.xlsx"
    markers = MarkerMap()
    mask_text("paid 1200 on 2026-10-21", markers, 3)  # [NUMBER_1] and [DATE_1] of a text, as every scope made before
    workbook(answer, {"A1": "[NUMBER_1]", "A2": "[DATE_1]"})

    report, anomalies = restore_file(answer, back, markers)

    assert values_of(openpyxl.load_workbook(back)["Data"]) == [["1200"], ["2026-10-21"]]
    assert anomalies == [] and report.markers_by_kind == {"NUMBER": 1, "DATE": 1}


def test_a_placeholder_the_scope_does_not_know_is_reported_and_left(tmp_path):
    src, masked, answer, back = (tmp_path / name for name in ("in.xlsx", "masked.xlsx", "answer.xlsx", "back.xlsx"))
    workbook(src, {"A1": 1234.5})
    markers = MarkerMap()
    mask_file(src, masked, markers, level=3)
    model_file(masked, answer, lambda book: book["Data"].__setitem__("B1", "[NUMBER_99]"))

    _, anomalies = restore_file(answer, back, markers)

    assert anomalies == ["[NUMBER_99]"]
    assert values_of(openpyxl.load_workbook(back)["Data"]) == [[1234.5, "[NUMBER_99]"]]


def test_the_scope_keeps_the_text_the_person_saw_and_the_copy_keeps_none_of_it(tmp_path):
    src, masked = tmp_path / "in.xlsx", tmp_path / "masked.xlsx"
    workbook(src, {"A1": (1234.5, '#,##0.00 "Project Orion"'), "A2": (0.15, "0%")})
    markers = MarkerMap()

    mask_file(src, masked, markers, level=3)

    assert [original for _, _, original in markers.items()] == ["1,234.50 Project Orion", "15%"]  # in the vault, which stays on the computer
    assert_clean(masked, "Orion", "1,234.50", "15%")  # not in the file that goes to the model: its cells are placeholders


def test_what_the_scope_keeps_for_the_cells_is_never_read_as_a_marker(tmp_path):
    src, masked, answer, back = (tmp_path / name for name in ("in.xlsx", "masked.xlsx", "answer.xlsx", "back.xlsx"))
    workbook(src, {"A1": 1234.5, "A2": (STAMP, "dd.mm.yyyy")})
    markers = MarkerMap()
    mask_file(src, masked, markers, level=3)
    kept = MarkerMap.from_json(markers.to_json())  # as the vault hands the map back

    assert {kind for _, kind, _ in kept.items()} == {"NUMBER", "DATE"}  # every entry stands for a text the person saw
    for odd in ("[XLSX_VALUE_1]", "[XLSX_VALUE_01]", "[XLSX_CELLS_1]", "[xlsx_value_1]"):
        result = restore(f"see {odd}", kept)
        assert result.text == f"see {odd}" and result.unknown == [] and result.suspicious == []  # plain text: no original, no NUL
        model_file(masked, answer, lambda book: book["Data"].__setitem__("B1", odd))
        report, anomalies = restore_file(answer, back, kept)
        assert openpyxl.load_workbook(back)["Data"]["B1"].value == odd and anomalies == []
        back.unlink()


def test_a_big_sheet_asks_the_map_for_its_kinds_once_not_for_every_cell(tmp_path, monkeypatch):
    # mask_text and restore ask for the kinds on every text, and the map finds them by going through all its markers: with one marker
    # for every number of a sheet, each text would take longer than the one before
    src, masked, back = tmp_path / "in.xlsx", tmp_path / "masked.xlsx", tmp_path / "back.xlsx"
    book = openpyxl.Workbook()
    for row in range(300):
        book.active.append([f"client{row}@acme.com", row + 0.25, STAMP + datetime.timedelta(minutes=row)])
    book.save(src)
    asked, real = [], MarkerMap.kinds
    monkeypatch.setattr(MarkerMap, "kinds", lambda self: asked.append(1) or real(self))
    markers = MarkerMap()

    mask_file(src, masked, markers, level=3)
    masked_asks, asked[:] = len(asked), []
    restore_file(masked, back, markers)

    assert masked_asks < 30 and len(asked) < 30  # 900 cells
    monkeypatch.undo()
    assert values_of(openpyxl.load_workbook(back).active) == values_of(openpyxl.load_workbook(src).active)


def test_the_markers_of_a_run_know_the_kinds_of_the_map_also_when_a_text_keeps_the_marker_of_another_kind():
    from boxed.formats import RunMarkers

    markers = MarkerMap()
    markers.marker_for("CASE", "4711")
    run = RunMarkers(markers)

    assert run.kinds() == {"CASE"}
    assert run.marker_for("NUMBER", "4711") == "[CASE_1]" and run.kinds() == {"CASE"}  # the first marker of a text is kept
    assert run.marker_for("NUMBER", "12345") == "[NUMBER_1]" and run.kinds() == {"CASE", "NUMBER"} == markers.kinds()
    assert run.original_for("[NUMBER_1]") == "12345" and run.reserve("[GPIO_12]") and markers.reserve("[GPIO_12]")


NUMBER_FORMATS = ["General", "0", "0.00", "#,##0.00", "0%", '#,##0.00 "EUR"', "$#,##0", "0.00E+00", "000000", "@", "0.0,", "#,##0;(#,##0)"]
DATE_FORMATS = ["yyyy-mm-dd", "dd.mm.yyyy", "d mmmm yyyy", "mmm", "yy", "yyyy-mm-dd hh:mm:ss", "mm/dd/yyyy", "dddd", "h:mm AM/PM"]
TIME_FORMATS = ["hh:mm", "h:mm:ss AM/PM", "hh:mm:ss.000"]
any_cell = st.one_of(
    st.tuples(st.integers(-(10**12), 10**12), st.sampled_from(NUMBER_FORMATS)),
    st.tuples(st.floats(allow_nan=False, allow_infinity=False, min_value=-1e15, max_value=1e15), st.sampled_from(NUMBER_FORMATS)),
    st.tuples(st.datetimes(min_value=datetime.datetime(1900, 3, 1), max_value=datetime.datetime(2200, 1, 1)), st.sampled_from(DATE_FORMATS)),
    st.tuples(st.times(), st.sampled_from(TIME_FORMATS)),
    st.tuples(st.timedeltas(min_value=datetime.timedelta(0), max_value=datetime.timedelta(days=5000)), st.just("[h]:mm:ss")),
)


@settings(max_examples=80, deadline=None)
@given(st.lists(any_cell, min_size=1, max_size=10))
def test_any_numbers_and_dates_are_masked_and_come_back_equal(items):
    with tempfile.TemporaryDirectory() as folder:
        src, masked, back = (Path(folder) / name for name in ("in.xlsx", "masked.xlsx", "back.xlsx"))
        workbook(src, {f"A{row}": item for row, item in enumerate(items, start=1)})
        markers = MarkerMap()

        mask_file(src, masked, markers, level=3)
        report, anomalies = restore_file(masked, back, MarkerMap.from_json(markers.to_json()))

        before, copy, after = (openpyxl.load_workbook(path)["Data"] for path in (src, masked, back))
        for was, now in zip(before["A"], copy["A"]):
            if isinstance(now.value, str):
                assert re.fullmatch(r"\[[A-Z_]+_\d+\]", now.value)
            else:  # only a lone digit stays, as in text
                assert now.value == was.value and not isinstance(was.value, datetime.date | datetime.time | datetime.timedelta)
                assert len(str(abs(was.value))) == 1
        assert anomalies == [] and report.complete is True
        assert values_of(after) == values_of(before)
        assert [[type(c.value) for c in row] for row in after.iter_rows()] == [[type(c.value) for c in row] for row in before.iter_rows()]


def test_mask_file_and_restore_file_on_the_command_line_keep_the_types(tmp_path, capsys, monkeypatch):
    # through the vault: the scope is saved encrypted and read back, with the entries that say which markers stood for a number
    from boxed.cli import main

    monkeypatch.chdir(tmp_path)
    src, masked, back = tmp_path / "sales.xlsx", tmp_path / "sales.masked.xlsx", tmp_path / "sales.restored.xlsx"
    workbook(src, {"A1": "Acme", "B1": (1234.5, '#,##0.00 "EUR"'), "C1": (STAMP, "dd.mm.yyyy"), "D1": (0.15, "0%"), "E1": 42})

    code = main(["mask-file", "--level", "3", "--scope", "n1", str(src), str(masked)])
    out, err = capsys.readouterr()

    assert code == 0 and "markers: DATE 1, MONEY 1, NUMBER 1, PERCENT 1" in out and "complete: yes" in out and "XLSX_VALUE" not in out + err
    assert values_of(openpyxl.load_workbook(masked)["Data"]) == [["Acme", "[MONEY_1]", "[DATE_1]", "[PERCENT_1]", "[NUMBER_1]"]]

    code = main(["restore-file", "--scope", "n1", str(masked), str(back)])
    out, err = capsys.readouterr()

    assert code == 0 and "markers: DATE 1, MONEY 1, NUMBER 1, PERCENT 1" in out and "XLSX_VALUE" not in out + err
    assert values_of(openpyxl.load_workbook(back)["Data"]) == values_of(openpyxl.load_workbook(src)["Data"])


def test_cells_that_show_the_same_text_share_a_marker_and_each_gets_its_own_value_back(tmp_path):
    src, masked, back = tmp_path / "in.xlsx", tmp_path / "masked.xlsx", tmp_path / "back.xlsx"
    workbook(src, {"A1": (0.4217, "0.0%"), "A2": (0.4219, "0.0%"), "A3": (0.4217, "0.00%"), "A4": 0.4217})  # "42.2%", "42.2%", "42.17%", "0.4217"
    markers = MarkerMap()

    report = mask_file(src, masked, markers, level=3)

    assert values_of(openpyxl.load_workbook(masked)["Data"]) == [["[PERCENT_1]"], ["[PERCENT_1]"], ["[PERCENT_2]"], ["[NUMBER_1]"]]
    assert report.markers_by_kind == {"PERCENT": 3, "NUMBER": 1}
    restored, _ = restore_file(masked, back, markers)
    assert restored.markers_by_kind == report.markers_by_kind
    assert values_of(openpyxl.load_workbook(back)["Data"]) == [[0.4217], [0.4219], [0.4217], [0.4217]]  # the hidden digits come back too


def test_a_placeholder_in_prose_comes_back_as_the_text_the_person_saw(tmp_path):
    src, masked, answer, back = (tmp_path / name for name in ("in.xlsx", "masked.xlsx", "answer.xlsx", "back.xlsx"))
    workbook(src, {"A1": (0.4217, "0.0%"), "A2": (1234567.891, '#,##0.00 "EUR"'), "A3": (STAMP, "dd.mm.yyyy"), "A4": 1234.5678})
    markers = MarkerMap()
    mask_file(src, masked, markers, level=3)
    prose = "Growth was [PERCENT_1], we paid [MONEY_1] on [DATE_1], the total is [NUMBER_1]."
    saw = "Growth was 42.2%, we paid 1,234,567.89 EUR on 21.10.2026, the total is 1234.5678."

    assert restore(prose, MarkerMap.from_json(markers.to_json())).text == saw  # boxed restore, the browser, the API
    model_file(masked, answer, lambda book: book["Data"].__setitem__("B1", prose))
    restore_file(answer, back, markers)
    assert openpyxl.load_workbook(back)["Data"]["B1"].value == saw


def test_a_workbook_in_the_1904_date_system_comes_back_with_the_same_dates(tmp_path):
    from openpyxl.utils.datetime import CALENDAR_MAC_1904

    src, masked, back = tmp_path / "in.xlsx", tmp_path / "masked.xlsx", tmp_path / "back.xlsx"
    book = openpyxl.Workbook()
    book.epoch = CALENDAR_MAC_1904
    book.active["A1"], book.active["A1"].number_format = STAMP, "dd.mm.yyyy"
    book.save(src)
    assert openpyxl.load_workbook(src).active["A1"].value == STAMP
    markers = MarkerMap()
    mask_file(src, masked, markers, level=3)

    restore_file(masked, back, markers)

    assert openpyxl.load_workbook(back).active["A1"].value == STAMP


def test_two_copies_of_a_scope_that_put_different_values_in_one_cell_are_not_guessed_between(tmp_path):
    first, second, masked_first, masked_second, back = (tmp_path / name for name in ("a.xlsx", "b.xlsx", "ma.xlsx", "mb.xlsx", "back.xlsx"))
    workbook(first, {"A1": (0.4217, "0.0%"), "B1": 1234.5})
    workbook(second, {"A1": (0.4219, "0.0%"), "B1": 1234.5})  # the same text "42.2%" in the same cell, another value
    markers = MarkerMap()
    mask_file(first, masked_first, markers, level=3)
    mask_file(second, masked_second, markers, level=3)

    restore_file(masked_first, back, markers)

    # the percentage may be either value; the number is the same in both copies
    assert values_of(openpyxl.load_workbook(back)["Data"]) == [["42.2%", 1234.5]]


def test_a_cell_the_format_shows_nothing_of_stands_for_its_exact_text_and_a_padded_one_for_the_text_without_the_padding(tmp_path):
    src, masked = tmp_path / "in.xlsx", tmp_path / "masked.xlsx"
    workbook(src, {"A1": (1234.5678, ";;;"), "A2": (1234.5, '_($* #,##0.00_)'), "A3": (-3, "0;(0);0")})
    markers = MarkerMap()

    mask_file(src, masked, markers, level=3)

    assert [original for _, _, original in markers.items()] == ["1234.5678", "$1,234.50"]  # the third cell is a lone digit: it stays
    assert values_of(openpyxl.load_workbook(masked)["Data"]) == [["[NUMBER_1]"], ["[MONEY_1]"], [-3]]


def test_a_damaged_index_of_cells_costs_the_types_and_nothing_else(tmp_path):
    answer, back = tmp_path / "answer.xlsx", tmp_path / "back.xlsx"
    stood = ['{"xlsx":{"Data":{"A1":["[NUMBER_1]"]}}', '{"xlsx":[1]}', '{"xlsx":{"Data":{"A2":["[NUMBER_9]","12"]}}}']  # whole, then not: a short list, a list, a marker the map lacks
    markers = MarkerMap.from_json(json.dumps({"version": 1, "items": [["[NUMBER_1]", "NUMBER", "1234.5"]], "foreign": stood}))
    workbook(answer, {"A1": "[NUMBER_1]", "A2": "[NUMBER_9]"})

    report, anomalies = restore_file(answer, back, markers)

    assert values_of(openpyxl.load_workbook(back)["Data"]) == [["1234.5"], ["[NUMBER_9]"]]  # text, and the unknown marker reported as ever
    assert anomalies == ["[NUMBER_9]"] and report.markers_by_kind == {"NUMBER": 1}


@pytest.mark.parametrize("title", ["Acme Corp", "ivan@acme.com", "a@b.co c@d.io e@f.org g@h.net"])  # masked, masked, masked and cut to 31
def test_a_number_in_a_sheet_whose_name_is_masked_or_cut_comes_back_typed(tmp_path, title):
    src, masked, back = tmp_path / "in.xlsx", tmp_path / "masked.xlsx", tmp_path / "back.xlsx"
    config = DetectConfig(dictionary={"Acme Corp": "CLIENT"})
    workbook(src, {"A1": 1234.5, "B1": (STAMP, "dd.mm.yyyy")}, title=title)
    markers = MarkerMap()
    mask_file(src, masked, markers, level=3, config=config)
    assert openpyxl.load_workbook(masked).sheetnames[0] != title  # the copy carries a masked or a cut name

    restore_file(masked, back, markers, kinds=dictionary_kinds(config))

    restored = openpyxl.load_workbook(back)
    assert values_of(restored.worksheets[0]) == [[1234.5, STAMP]]


def plant_digits(path, ref, digits):
    """openpyxl writes a number with 16 significant digits; Excel and other writers keep every digit of a whole number."""
    pattern = rf'(<c r="{ref}"[^>]*><v>)[^<]*(</v>)'.encode()
    rewrite_zip(path, {"xl/worksheets/sheet1.xml": lambda xml: re.sub(pattern, rb"\g<1>" + digits.encode() + rb"\g<2>", xml)})


def test_a_whole_number_that_a_double_cannot_hold_comes_back_as_its_digits(tmp_path):
    # past 2**53 the library would write 1.234567890123457e+16 for 12345678901234567; the copy of the digits keeps them
    src, masked, back = tmp_path / "in.xlsx", tmp_path / "masked.xlsx", tmp_path / "back.xlsx"
    digits = ["123456789012345", "9007199254740992", "9007199254740993", "12345678901234567", "-12345678901234567", "40702810900000012345"]
    workbook(src, {f"A{row}": row for row in range(1, len(digits) + 1)})
    for row, number in enumerate(digits, start=1):
        plant_digits(src, f"A{row}", number)
    assert [c.value for c in openpyxl.load_workbook(src)["Data"]["A"]] == [int(number) for number in digits]  # read exactly
    markers = MarkerMap()
    mask_file(src, masked, markers, level=3)
    assert all(isinstance(c.value, str) for c in openpyxl.load_workbook(masked)["Data"]["A"])

    restore_file(masked, back, markers)

    # up to 2**53 a number, as before; beyond it the text of the digits, which is what a masked whole number always came back as
    assert [c.value for c in openpyxl.load_workbook(back)["Data"]["A"]] == [123456789012345, 9007199254740992, *digits[2:]]
