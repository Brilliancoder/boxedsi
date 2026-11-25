"""How a spreadsheet shows a number or a date (shown), and the exact text of a value and the way back (exact, parse)."""

import datetime
from decimal import Decimal

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from boxed.formats.display import exact, parse, shown

STAMP = datetime.datetime(2026, 10, 21, 14, 30, 5)  # a Wednesday


@pytest.mark.parametrize(
    "value, fmt, text",
    [
        (1234.5678, "General", "1234.5678"),
        (1200, "General", "1200"),
        (0.1 + 0.2, "General", "0.3"),  # 15 significant digits, as Excel keeps them
        (1e-7, "General", "0.0000001"),
        (123456789012, "General", "123456789012"),
        (1200, "@", "1200"),
        (1234.5678, "0", "1235"),
        (1234.5678, "0.00", "1234.57"),
        (2.5, "0", "3"),  # halves round away from zero, as in Excel
        (-2.5, "0", "-3"),
        (1234.5678, "#,##0.00", "1,234.57"),
        (1234.5678, "#,##0", "1,235"),
        (1234567.891, "#,##0.00", "1,234,567.89"),
        (5, "00000", "00005"),
        (1234, "00000", "01234"),
        (5, "#,##0", "5"),
        (12, "0,000", "0,012"),
        (0.5, "#.##", ".5"),
        (0.5, ".00", ".50"),
        (3.14159, "0.0#", "3.14"),
        (3.1, "0.0#", "3.1"),
        (3.0, "0.0#", "3.0"),
        (1.5, "?.??", "1.5 "),
        (79991234567, "+0 (000) 000-00-00", "+7 (999) 123-45-67"),
        (123456789, "000-00-0000", "123-45-6789"),
        (0.5, "0%", "50%"),
        (0.15, "0.00%", "15.00%"),
        (1.234, "0.0%", "123.4%"),
        (1234.5, '#,##0.00 "EUR"', "1,234.50 EUR"),
        (1234.5, '"$"#,##0.00', "$1,234.50"),
        (1234.5, "$#,##0.00", "$1,234.50"),
        (1234.5, "[$€-407] #,##0.00", "€ 1,234.50"),
        (1234.5, "[$$-409]#,##0.00", "$1,234.50"),
        (1234.5, '#,##0.00\\ "₽"', "1,234.50 ₽"),
        (7, '0 "kg"', "7 kg"),
        (7, '0\\ "kg"', "7 kg"),
        (12.5, '"Total: "0.00', "Total: 12.50"),
        (1234.5, "[Blue]#,##0.00", "1,234.50"),
        (1234.5, "0.0,", "1.2"),  # a comma after the digits divides by 1000
        (1234567, "0.0,,", "1.2"),
        (1234567, "#,##0,", "1,235"),
        (0.000012345, "0.00E+00", "1.23E-05"),
        (12345.678, "0.00E+00", "1.23E+04"),
        (12345.678, "##0.0E+0", "12.3E+3"),
        (-0.5, "0.00E+00", "-5.00E-01"),
        (9.996, "0.00E+00", "1.00E+01"),  # the mantissa rounds up to 10 and takes the exponent along
        (99999, "0.0E+0", "1.0E+5"),
        (0, "0.00E+00", "0.00E+00"),
        (0.000012345, "0.00E-00", "1.23E-05"),
        (12345.678, "0.00E-00", "1.23E04"),
    ],
)
def test_numbers_are_shown_as_their_format_says(value, fmt, text):
    assert shown(value, fmt) == text


@pytest.mark.parametrize(
    "value, fmt, text",
    [
        (-1234.5, "#,##0.00", "-1,234.50"),
        (-1234.5, "#,##0.00;[Red]-#,##0.00", "-1,234.50"),
        (-1234.5, "#,##0.00;(#,##0.00)", "(1,234.50)"),  # a second section for negatives shows no minus of its own
        (1234.5, "#,##0.00;(#,##0.00)", "1,234.50"),
        (0, "#,##0.00;(#,##0.00)", "0.00"),  # zero belongs to the first section when there are two
        (0, '#,##0.00;(#,##0.00);"-"', "-"),  # and to the third when there are three
        (-5, "0;(0)", "(5)"),
        (-5, "0", "-5"),
        (5, '[>10]"big";[<=10]"small"', "small"),
        (50, '[>10]"big";[<=10]"small"', "big"),
        (-3, "_($* #,##0.00_);_($* (#,##0.00);_($* \"-\"??_);_(@_)", " $(3.00)"),
        (1234.5, "_($* #,##0.00_);_($* (#,##0.00);_($* \"-\"??_);_(@_)", " $1,234.50 "),
    ],
)
def test_sections_choose_by_the_sign_and_the_conditions(value, fmt, text):
    assert shown(value, fmt) == text


@pytest.mark.parametrize(
    "value, fmt, text",
    [
        (5, '[=5]"five";0', "five"),
        (6, '[<>5]"other";0', "other"),
        (5, '[<>5]"other";0', "5"),
        (6, '[>=6]"six or more";0', "six or more"),
        (1234.5, 'General" units"', "1234.5 units"),
        (-5.5, "General", "-5.5"),
        (1.5, "# ?/?", "1.5"),  # a fraction format is shown as General
        (0.75, "# ??/??", "0.75"),
        (1234.5, "[Red]0.0;[Blue]-0.0", "1234.5"),
        (7, '[$USD] 0', "USD 7"),
        (7, "0.0;;", "7.0"),
        (-7, "0.0;;", ""),  # a section without a format shows nothing
    ],
)
def test_conditions_fractions_and_other_odd_formats(value, fmt, text):
    assert shown(value, fmt) == text


def test_the_system_date_and_time_codes_are_the_long_forms():
    assert shown(STAMP, "[$-F800]") == "Wednesday, October 21, 2026"
    assert shown(STAMP, "[$-F400]") == "2:30:05 PM"


def test_a_number_under_a_date_format_is_a_day_count():
    serial = (STAMP - datetime.datetime(1899, 12, 30)).total_seconds() / 86400
    assert shown(serial, "yyyy-mm-dd hh:mm:ss") == "2026-10-21 14:30:05"


@pytest.mark.parametrize(
    "fmt, text",
    [
        ("yyyy-mm-dd", "2026-10-21"),
        ("dd.mm.yyyy", "21.10.2026"),
        ("d/m/yy", "21/10/26"),
        ("mm/dd/yyyy", "10/21/2026"),
        ("DD.MM.YYYY", "21.10.2026"),
        ("d mmm yyyy", "21 Oct 2026"),
        ("d mmmm yyyy", "21 October 2026"),
        ("mmmm yyyy", "October 2026"),
        ("mmm", "Oct"),
        ("mmmmm", "O"),
        ("dddd", "Wednesday"),
        ("ddd, d mmm", "Wed, 21 Oct"),
        ("dddd, mmmm d, yyyy", "Wednesday, October 21, 2026"),
        ("yyyy", "2026"),
        ("yy", "26"),
        ("m", "10"),
        ("d", "21"),
        ('dd "of" mmmm', "21 of October"),
        ("yyyy-mm-dd hh:mm:ss", "2026-10-21 14:30:05"),
        ("yyyy-mm-dd h:mm", "2026-10-21 14:30"),
        ("yyyy-mm-dd h:mm AM/PM", "2026-10-21 2:30 PM"),
        ("h:mm:ss AM/PM", "2:30:05 PM"),
        ("mm:ss", "30:05"),  # "mm" right before the seconds is minutes
        ("hh:mm", "14:30"),  # and right after the hours
        ("mm-yy", "10-26"),  # but otherwise a month
        ("[$-409]d mmmm yyyy", "21 October 2026"),
        ("[Red]yyyy-mm-dd", "2026-10-21"),
        ("m/d/yy h:mm", "10/21/26 14:30"),
    ],
)
def test_dates_are_shown_as_their_format_says(fmt, text):
    assert shown(STAMP, fmt) == text


@pytest.mark.parametrize(
    "stamp, fmt, text",
    [
        (datetime.datetime(2026, 10, 21, 4, 5, 6), "h:mm A/P", "4:05 A"),
        (datetime.datetime(2026, 10, 21, 4, 5, 6), "h:mm am/pm", "4:05 am"),
        (datetime.datetime(2026, 10, 21, 0, 5, 6), "h:mm AM/PM", "12:05 AM"),
        (datetime.datetime(2026, 10, 21, 12, 5, 6), "h:mm AM/PM", "12:05 PM"),
        (datetime.datetime(2026, 10, 21, 14, 30, 5, 123000), "hh:mm:ss.000", "14:30:05.123"),
        (datetime.datetime(2026, 10, 21, 14, 30, 5, 123000), "hh:mm:ss.0", "14:30:05.1"),
        (datetime.datetime(2026, 1, 5), "d/m/yyyy", "5/1/2026"),
    ],
)
def test_clock_details(stamp, fmt, text):
    assert shown(stamp, fmt) == text


@pytest.mark.parametrize(
    "value, fmt, text",
    [
        (datetime.time(14, 30), "hh:mm", "14:30"),
        (datetime.time(9, 5, 3), "h:mm:ss", "9:05:03"),
        (datetime.time(9, 5, 3), "hh:mm:ss", "09:05:03"),
        (datetime.time(14, 30), "h:mm AM/PM", "2:30 PM"),
        (datetime.timedelta(hours=26, minutes=3, seconds=4), "[h]:mm:ss", "26:03:04"),
        (datetime.timedelta(hours=26, minutes=3, seconds=4), "[h]:mm", "26:03"),
        (datetime.timedelta(hours=26, minutes=3, seconds=4), "[m]", "1563"),
        (datetime.timedelta(hours=26, minutes=3, seconds=4), "[s]", "93784"),
        (datetime.timedelta(hours=5, minutes=3), "[hh]:mm:ss", "05:03:00"),
    ],
)
def test_times_and_durations(value, fmt, text):
    assert shown(value, fmt) == text


@pytest.mark.parametrize(
    "value, text",
    [
        (datetime.date(2026, 10, 21), "2026-10-21"),
        (STAMP, "2026-10-21 14:30:05"),
        (datetime.time(14, 30), "14:30:00"),
        (datetime.timedelta(hours=26, minutes=3, seconds=4), "26:03:04"),
    ],
)
def test_a_date_under_a_format_that_is_no_date_format_is_shown_in_the_default_form(value, text):
    assert shown(value, "General") == text


@pytest.mark.parametrize("days", [2_958_466, 3_000_000, 999_999_999, -693_594, -700_000, -999_999_999])
@pytest.mark.parametrize("fmt", ["[h]:mm:ss", "General", "yyyy-mm-dd", "hh:mm", ""])
def test_a_duration_beyond_the_dates_python_holds_is_shown_by_its_exact_text(days, fmt):
    # a day count Excel can show as hours, but that no date holds: the format cannot render it, so the exact text stands in
    value = datetime.timedelta(days=days)
    assert shown(value, fmt) == exact(value)


@pytest.mark.parametrize("days, hours", [(2_958_465, "71003160"), (-693_593, "16646232")])
def test_the_last_durations_that_are_still_dates_are_rendered_by_their_format(days, hours):
    assert shown(datetime.timedelta(days=days), "[h]:mm:ss") == f"{hours}:00:00"


@pytest.mark.parametrize("fmt", ["", "0.00;", '"unclosed', "\\", "[", "[$", "0.00E", "#,##0.00_", "*", "0/0", "# ?/?", "[>5", "0.00.00", ",,,", "E+", "%%", "@@"])
def test_a_format_that_cannot_be_read_is_shown_without_raising(fmt):
    assert isinstance(shown(1234.5, fmt), str)


@pytest.mark.parametrize("fmt, text", [("", "1234.5"), ("0.00;", "1234.50"), (";;;", "")])
def test_an_empty_format_is_general_and_hidden_sections_show_nothing(fmt, text):
    assert shown(1234.5, fmt) == text


def test_a_format_longer_than_excel_allows_is_shown_as_general():
    assert shown(1234.5, "0" * 300) == "1234.5"


def test_a_huge_number_is_shown_without_raising():
    assert shown(10**400, "0.00") == "1" + "0" * 400 + ".00"
    assert shown(1e300, "0.00") == "1" + "0" * 300 + ".00"
    assert shown(1e300, "#,##0").startswith("1,000,000,000,000")


@pytest.mark.parametrize(
    "value, text",
    [
        (1200, "1200"),
        (-5, "-5"),
        (0, "0"),
        (1234.5678, "1234.5678"),
        (1200.0, "1200"),  # a whole float is its digits, as a whole number is
        (-3.0, "-3"),
        (0.1 + 0.2, "0.30000000000000004"),  # the shortest text that gives the same float back
        (1e-7, "0.0000001"),  # never an exponent: the detectors read digits
        (1e22, "10000000000000000000000.0"),  # ".0" keeps a huge whole float a float
        (123456789012345678, "123456789012345678"),  # a whole number of any size stays exact
        (Decimal("12.50"), "12.5"),  # a Decimal is read as the number it stands for
        (Decimal("1E+3"), "1000"),
        (datetime.date(2026, 10, 21), "2026-10-21"),
        (datetime.datetime(2026, 10, 21), "2026-10-21"),  # a date is a date at midnight
        (STAMP, "2026-10-21 14:30:05"),
        (datetime.datetime(2026, 10, 21, 14, 30, 5, 123000), "2026-10-21 14:30:05.123000"),
        (datetime.time(14, 30), "14:30:00"),
        (datetime.time(14, 30, 5, 500000), "14:30:05.500000"),
        (datetime.timedelta(hours=26, minutes=3, seconds=4), "26h 03m 04s"),
        (datetime.timedelta(hours=-26, minutes=-3, seconds=-4), "-26h 03m 04s"),
        (datetime.timedelta(hours=5), "5h 00m 00s"),
        (datetime.timedelta(seconds=1, milliseconds=500), "0h 00m 01.500000s"),
    ],
)
def test_exact_is_the_lossless_text_of_a_value(value, text):
    assert exact(value) == text


@pytest.mark.parametrize(
    "value", [True, False, "text", "12", None, float("nan"), float("inf"), -float("inf"), Decimal("NaN"), Decimal("Infinity"), b"1", [1], {}]
)
def test_exact_is_none_for_everything_that_is_no_number_or_date(value):
    assert exact(value) is None


@pytest.mark.parametrize(
    "text, value",
    [
        ("1200", 1200),
        ("-5", -5),
        ("1234.5678", 1234.5678),
        ("0.0000001", 1e-7),
        ("10000000000000000000000.0", 1e22),
        ("2026-10-21", datetime.date(2026, 10, 21)),
        ("2026-10-21 14:30:05", STAMP),
        ("2026-10-21 14:30:05.123000", datetime.datetime(2026, 10, 21, 14, 30, 5, 123000)),
        ("14:30:00", datetime.time(14, 30)),
        ("14:30:05.500000", datetime.time(14, 30, 5, 500000)),
        ("26h 03m 04s", datetime.timedelta(hours=26, minutes=3, seconds=4)),
        ("-26h 03m 04s", datetime.timedelta(hours=-26, minutes=-3, seconds=-4)),
        ("0h 00m 01.500000s", datetime.timedelta(seconds=1, milliseconds=500)),
    ],
)
def test_parse_gives_the_value_back(text, value):
    got = parse(text)
    assert got == value and type(got) is type(value)


@pytest.mark.parametrize(
    "text",
    ["", "00123", "-0", "1,200", "1 200", "12.50", ".5", "1e5", "1E-5", "+5", "٣", "2026-13-01", "2026-02-30", "25:00:00", "1200 ", " 1200", "26h 3m 4s", "26h 60m 00s", "26h 00m 60s", "text", "[NUMBER_1]", "2026-10-21T14:30:05", "1" * 5000],
)
def test_parse_refuses_every_text_that_exact_never_writes(text):
    assert parse(text) is None


numbers = st.one_of(
    st.integers(min_value=-(10**30), max_value=10**30),
    st.floats(allow_nan=False, allow_infinity=False),
)
dates = st.one_of(
    st.dates(min_value=datetime.date(1900, 3, 1)),
    st.datetimes(min_value=datetime.datetime(1900, 3, 1)),
    st.times(),
    st.timedeltas(min_value=datetime.timedelta(days=-100000), max_value=datetime.timedelta(days=100000)),
)


@settings(max_examples=300, deadline=None)
@given(numbers)
def test_a_number_comes_back_equal_from_its_exact_text(value):
    text = exact(value)
    assert parse(text) == value
    assert text == text.strip() and text.isascii()


@settings(max_examples=300, deadline=None)
@given(dates)
def test_a_date_or_time_comes_back_equal_from_its_exact_text(value):
    got = parse(exact(value))
    if isinstance(value, datetime.datetime) and value.time() == datetime.time():
        value = value.date()
    assert got == value and type(got) is type(value)
