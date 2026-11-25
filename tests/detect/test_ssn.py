"""SSN: a US social security number, nine digits as 3-2-4. The Social Security Administration never assigns an area number of
000, 666 or 900-999, a group number of 00 or a serial number of 0000 (POMS RM 10201.035, secure.ssa.gov/poms.nsf/lnx/0110201035).
With dashes the shape stands alone; without them a word of social security numbers must stand before it. All numbers are made up."""

import pytest

from boxed.detect import KINDS_BY_LEVEL, detect


def found(text, level=1):
    return [(d.kind, d.text) for d in detect(text, level=level)]


@pytest.mark.parametrize(
    "ssn",
    ["512-34-7890", "234-56-7890", "001-01-0001", "899-99-9999", "665-12-3456", "667-12-3456", "123-45-6789", "100-10-1000"],
)
def test_a_valid_number_with_dashes(ssn):
    assert found(f"The number is {ssn}.") == [("SSN", ssn)]
    assert found(ssn) == [("SSN", ssn)]


@pytest.mark.parametrize(
    "text,ssn",
    [
        ("SSN 512347890", "512347890"),
        ("SSN: 512 34 7890", "512 34 7890"),
        ("ssn=512347890", "512347890"),
        ("SS# 512 34 7890", "512 34 7890"),
        ("Social Security Number 512-34-7890", "512-34-7890"),
        ("Social security number: 512347890", "512347890"),
        ("social-security no. 512347890", "512347890"),
        ("Your Social Security number (SSN) is 512 34 7890", "512 34 7890"),
        ("SSN (required): 512347890", "512347890"),
    ],
)
def test_a_valid_number_after_a_word_of_social_security_numbers(text, ssn):
    assert found(text) == [("SSN", ssn)]


@pytest.mark.parametrize(
    "text",
    [
        "512347890",  # nine digits with no word
        "512 34 7890",  # spaces with no word
        "800-555-1212",  # a phone number: 3-3-4
        "2026-10-24",
        "1234-56-7890",
        "12-345-6789",
        "512-34-78901",
        "5123-34-7890",
        "a512-34-7890",
        "512-34-7890-1",
        "1-512-34-7890",
        "512-34-7890.5",
        "512-34-789",
        "SSN",
        "SSN: n/a",
        "SSN: 51234789",  # eight digits
        "SSN: 5123478901",  # ten digits
        "SSN abc512347890",  # glued to letters
        "social security administration office reference 512347890",  # more than 20 characters between
        "My SSN\n512347890",  # a line break
    ],
)
def test_no_ssn(text):
    assert found(text) == []


@pytest.mark.parametrize(
    "ssn",
    [
        "000-12-3456",  # area 000
        "666-12-3456",  # area 666
        "900-12-3456",  # 9xx: a taxpayer number, not a social security number
        "987-65-4321",
        "999-99-9999",
        "123-00-4567",  # group 00
        "123-45-0000",  # serial 0000
    ],
)
def test_an_invalid_area_group_or_serial_is_no_ssn(ssn):
    assert found(ssn) == []
    assert found(f"SSN: {ssn}") == []
    assert found(f"SSN: {ssn.replace('-', '')}") == []


@pytest.mark.parametrize(
    "text",
    [
        "Part number 512-34-7890 is back in stock",
        "Order #512-34-7890 shipped",
        "SKU: 512-34-7890",
        "item 512-34-7890",
        "Model No. 512-34-7890",
        "Ref. 512-34-7890",
        "Invoice 512-34-7890",
        "tracking number 512-34-7890",
        "Артикул 512-34-7890 есть на складе",
        "Заказ № 512-34-7890",
    ],
)
def test_a_part_or_order_number_is_no_ssn(text):
    assert found(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "Part-time employee 512-34-7890",  # "part" begins a word of something else
        "Part time employee 512-34-7890",
        "Order placed by employee 512-34-7890",
        "Invoice for John Smith: 512-34-7890",
        "Model employee of the year 512-34-7890",
        "Item sold to Jane Doe, 512-34-7890",
        "Заказчик Иван Петров 512-34-7890",
    ],
)
def test_a_word_of_orders_far_from_the_number_does_not_hide_it(text):
    assert found(text) == [("SSN", "512-34-7890")]


def test_a_word_of_social_security_numbers_wins_over_a_word_of_orders():
    assert found("SSN for order 512-34-7890") == [("SSN", "512-34-7890")]
    assert found("Order SSN: 512-34-7890") == [("SSN", "512-34-7890")]


def test_a_snils_is_no_ssn():
    assert found("112-233-445 95") == [("SNILS", "112-233-445 95")]


def test_the_span_is_the_number_only():
    text = "Employee SSN: 512-34-7890, hired in 2026"
    (d,) = detect(text, level=1)
    assert text[d.start : d.end] == "512-34-7890"


def test_level_1_and_up_only():
    assert "SSN" in KINDS_BY_LEVEL[1] and "SSN" not in KINDS_BY_LEVEL[0]
    assert found("SSN 512-34-7890", level=0) == []
    for level in (1, 2, 3, 4):
        assert found("SSN 512-34-7890", level=level)[0] == ("SSN", "512-34-7890")


def test_a_phone_number_keeps_its_kind():
    # the older rule keeps the digits; the new one fills gaps only
    assert found("+1 512-34-7890") == [("PHONE", "+1 512-34-7890")]


def test_a_number_with_a_word_and_dashes_is_found_once():
    assert found("SSN 512-34-7890 and SSN 234-56-7890") == [("SSN", "512-34-7890"), ("SSN", "234-56-7890")]
