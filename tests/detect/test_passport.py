"""PASSPORT: a passport number needs a word of passports before it (level 1, category personal).

All numbers below are made up. The formats are: a Russian internal passport has a series of 4 digits (two of the region, two
of the year of the blank) and a number of 6 digits; a Russian foreign passport 2 and 7 digits; other countries have no common
shape, so a number of 6 to 9 letters and digits with five digits at least counts after the word "passport" and nothing else."""

import pytest

from boxed.detect import KINDS_BY_LEVEL, detect


def found(text, level=1):
    return [(d.kind, d.text) for d in detect(text, level=level)]


@pytest.mark.parametrize(
    "text,number",
    [
        ("Паспорт: 4510 123456", "4510 123456"),
        ("паспорт 45 10 123456", "45 10 123456"),
        ("Паспорт 4510123456", "4510123456"),
        ("паспорт РФ 4510-123456", "4510-123456"),
        ("паспорт РФ 4510/123456", "4510/123456"),
        ("Паспорт серии 4510 № 123456, выдан", "4510 № 123456"),
        ("паспорт гражданина РФ серия 45 10 номер 123456", "45 10 номер 123456"),
        ("Паспортные данные: серия 4510, номер 123456", "4510, номер 123456"),
        ("Серия и номер паспорта: 45 10 123456", "45 10 123456"),
        ("паспорт\xa04510\xa0123456", "4510\xa0123456"),
        ("Паспорт:\n4510 123456", "4510 123456"),
        ("ПАСПОРТ 4510 123456", "4510 123456"),
        ("Passport: 4510 123456", "4510 123456"),
        ("Russian passport series 4510 No. 123456", "4510 No. 123456"),
        ("серия 4510 № 123456", "4510 № 123456"),  # no word of passports: a series and a number named as such
        ("Серия: 45 10, Номер: 123456", "45 10, Номер: 123456"),
        ("Паспорт гражданина Российской Федерации (серия и номер): 4510 123456", "4510 123456"),
    ],
)
def test_russian_internal_passport(text, number):
    assert found(text) == [("PASSPORT", number)]


@pytest.mark.parametrize(
    "text,number",
    [
        ("Загранпаспорт: 75 1234567", "75 1234567"),
        ("загранпаспорт 751234567", "751234567"),
        ("заграничный паспорт № 75 1234567", "75 1234567"),
        ("Паспорт (загран) 71-7654321", "71-7654321"),
        ("foreign passport 75 1234567", "75 1234567"),
    ],
)
def test_russian_foreign_passport(text, number):
    assert found(text) == [("PASSPORT", number)]


@pytest.mark.parametrize(
    "text,number",
    [
        ("Passport number: 123456789", "123456789"),
        ("passport no. A12345678", "A12345678"),
        ("Passport # C01X00T47", "C01X00T47"),
        ("Passport No 12AB34567", "12AB34567"),
        ("Reisepass Nr. C01X00T47", "C01X00T47"),
        ("Passeport n° 12AB34567", "12AB34567"),
        ("pasaporte ABC123456", "ABC123456"),
        ("Passaporto YA1234567", "YA1234567"),
        ("passport: 123456", "123456"),
        ("Passport ID AB123456", "AB123456"),
    ],
)
def test_other_countries_after_the_word_passport(text, number):
    assert found(text) == [("PASSPORT", number)]


@pytest.mark.parametrize(
    "text",
    [
        "4510 123456",  # no context
        "Заказ 4510 123456 принят",
        "75 1234567",
        "Order A12345678",
        "Паспорт",
        "Паспорт: нет",
        "паспорт 4510",  # a series alone
        "паспорт 12345678",  # eight digits are no passport
        "паспорт 4510 12345",  # a number of five digits
        "паспорт 4510 1234567",  # seven digits after a series of four
        "Паспорт качества № 12345",
        "паспорт сделки 12345678/1234/1234/1/1",
        "паспорт ТС 77 УА 123456",  # a vehicle passport: letters in the series
        "Получил паспорт. 4510 123456",  # the sentence has ended
        "Паспорт\n\n4510 123456",  # more than one line break
        "паспорт 0000 000000",  # a placeholder
        "паспорт 0000 No. 000000",
        "Passport No. A00000000",
        "passport 1111111111",
        "my passport expires in 2027",
        "passport control took 25 minutes",
        "passport photo 600x600",
        "Passport photo 20210101",  # a word between the word of passports and the number
        "Паспорт " + "а" * 61 + " 4510 123456",  # more than 60 characters between
        "passport number 12345",
        "серия 4510",  # a series without a number
        "серия фильмов 4510 123456",  # a word that is no label stands between
        "passport 12AB",
        "passport abcdefgh1",  # lower case: a passport number is upper case
        "passport A1B2C3D4E5F6G7",  # longer than 9
    ],
)
def test_no_passport(text):
    assert found(text) == []


def test_the_span_is_the_number_only():
    text = "Паспорт гражданина РФ: 4510 123456, выдан ОВД района"
    (d,) = detect(text, level=1)
    assert text[d.start : d.end] == "4510 123456"


def test_level_1_and_up_only():
    assert KINDS_BY_LEVEL[1] - KINDS_BY_LEVEL[0] >= {"PASSPORT"}
    assert "PASSPORT" not in KINDS_BY_LEVEL[0]
    assert found("Паспорт: 4510 123456", level=0) == []
    for level in (1, 2, 3, 4):
        assert found("Паспорт: 4510 123456", level=level)[0] == ("PASSPORT", "4510 123456")


def test_several_in_a_text():
    text = "Паспорт: 4510 123456. Загранпаспорт: 75 1234567. Passport no. A12345678."
    assert found(text) == [("PASSPORT", "4510 123456"), ("PASSPORT", "75 1234567"), ("PASSPORT", "A12345678")]


def test_the_inn_after_a_word_of_passports_stays_an_inn():
    # the same ten digits: the older rule keeps them, the passport rule only fills gaps
    assert found("паспорт ИНН 7707083893") == [("INN", "7707083893")]
