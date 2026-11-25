"""VAT_ID: an EU VAT number, with its country prefix (level 2, category clients).

Eight countries have a public checksum, so their numbers are found anywhere: AT, BE, DE, IT, NL, PL from the construction rules
the member states published (Austrian Federal Ministry of Finance, "Konstruktionsregeln der Umsatzsteuer-Identifikationsnummern",
Nov 2020, with the sample numbers used below), FR from the key formula (Wikipedia, "VAT identification number") and ES from the
letters of the NIF (Wikipedia es, "Número de identificación fiscal"). The other EU countries are found only after a word of VAT
numbers, as their format alone is no proof. Every other number here is made up by the generators below, which are written from
the same texts, apart from the production code."""

import random

import pytest

from boxed.detect import KINDS_BY_LEVEL, detect


def found(text, level=2):
    return [(d.kind, d.text) for d in detect(text, level=level)]


# --- generators of valid numbers, from the published rules

DNI = "TRWAGMYFPDXBNJZSQVHLCKE"


def at(rng):
    d = [rng.randrange(10) for _ in range(7)]
    s = lambda c: c // 5 + c * 2 % 10  # noqa: E731
    r = s(d[1]) + s(d[3]) + s(d[5])
    return "ATU" + "".join(map(str, d)) + str((10 - (r + d[0] + d[2] + d[4] + d[6] + 4) % 10) % 10)


def be(rng):
    first = rng.choice("01") + "".join(rng.choice("0123456789") for _ in range(7))
    return f"BE{first}{97 - int(first) % 97:02d}"


def de(rng):
    first = str(rng.randrange(1, 10)) + "".join(str(rng.randrange(10)) for _ in range(7))
    p = 10
    for ch in first:
        s = int(ch) + p
        m = s % 10 or 10
        p = 2 * m % 11
    r = 11 - p
    return "DE" + first + str(0 if r == 10 else r)


def fr(rng):
    siren = "".join(str(rng.randrange(10)) for _ in range(9))
    return f"FR{(12 + 3 * (int(siren) % 97)) % 97:02d}{siren}"


def it(rng):
    first = "".join(str(rng.randrange(10)) for _ in range(7)) + f"{rng.randrange(1, 101):03d}"
    s1 = sum(int(first[i]) for i in range(0, 10, 2))
    s2 = sum(int(first[i]) // 5 + int(first[i]) * 2 % 10 for i in range(1, 10, 2))
    return "IT" + first + str((10 - (s1 + s2) % 10) % 10)


def nl(rng):
    while True:
        first = "".join(str(rng.randrange(10)) for _ in range(8))
        a = sum(int(c) * w for c, w in zip(first, range(9, 1, -1))) % 11
        if a != 10:
            return f"NL{first}{a}B{rng.randrange(1, 100):02d}"


def pl(rng):
    while True:
        first = "".join(str(rng.randrange(10)) for _ in range(9))
        r = sum(int(c) * w for c, w in zip(first, (6, 5, 7, 2, 3, 4, 5, 6, 7))) % 11
        if r != 10:
            return f"PL{first}{r}"


def es_dni(rng):
    n = rng.randrange(10**8)
    return f"ES{n:08d}{DNI[n % 23]}"


def es_nie(rng):
    x = rng.randrange(3)
    n = rng.randrange(10**7)
    return f"ES{'XYZ'[x]}{n:07d}{DNI[int(str(x) + f'{n:07d}') % 23]}"


def es_cif(rng):
    letter = rng.choice("ABEHCDFGJUV")  # the control of A, B, E, H is a digit, of the others a digit or a letter
    d = [rng.randrange(10) for _ in range(7)]
    a = d[1] + d[3] + d[5]
    b = sum(c * 2 // 10 + c * 2 % 10 for c in (d[0], d[2], d[4], d[6]))
    control = (10 - (a + b) % 10) % 10
    last = str(control) if letter in "ABEH" else rng.choice([str(control), "JABCDEFGHI"[control]])
    return f"ES{letter}{''.join(map(str, d))}{last}"


GENERATORS = {"AT": at, "BE": be, "DE": de, "FR": fr, "IT": it, "NL": nl, "PL": pl, "ES-DNI": es_dni, "ES-NIE": es_nie, "ES-CIF": es_cif}

# the sample numbers of the published rules (and the worked example of the French key)
SAMPLES = [
    "ATU10223006",
    "BE0776091951",
    "DE111111125",
    "IT00000010215",
    "NL010000446B01",  # modulo 11
    "NL123456782B01",  # modulo 11 (the Dutch tax authority's example, in the AFAS help)
    "NL123456789B13",  # modulo 97
    "PL5260001246",
    "FR83404833048",
    "ES00000000T",
    "ESX0000000T",
    "ESN1234567D",  # the control of N, P, Q, R, S and W is a letter
    "ESR1234567D",
    "ESW1234567D",
]


@pytest.mark.parametrize("vat", SAMPLES)
def test_a_sample_of_the_published_rules(vat):
    assert found(f"Invoice to {vat} today") == [("VAT_ID", vat)]
    assert found(vat) == [("VAT_ID", vat)]


@pytest.mark.parametrize("country", sorted(GENERATORS))
def test_generated_numbers_with_a_valid_checksum(country):
    rng = random.Random(country)
    for _ in range(60):
        vat = GENERATORS[country](rng)
        assert found(f"VAT {vat}.") == [("VAT_ID", vat)], vat


@pytest.mark.parametrize("country", ["AT", "BE", "DE", "FR", "IT", "PL"])
def test_no_single_wrong_digit_passes_the_checksum(country):
    """These checks catch every single mistyped digit, so none of the mutations may be found."""
    rng = random.Random(country + "mutate")
    for _ in range(25):
        vat = GENERATORS[country](rng)
        for i in range(2 + (1 if country == "AT" else 0), len(vat)):
            for digit in "0123456789":
                if digit != vat[i]:
                    assert found(vat[:i] + digit + vat[i + 1 :]) == [], (vat, i, digit)


@pytest.mark.parametrize(
    "vat",
    [
        "DE111111126",
        "ATU10223007",
        "BE0776091952",
        "IT00000010216",
        "IT00000001503",  # a valid check digit, but the office code 150 is none (1-100, 120, 121, 888, 999)
        "NL010000447B01",
        "NL010000446B00",  # the index 00
        "PL5260001247",
        "PL5260001240",
        "FR84404833048",
        "ES00000000R",
        "ES12345678A",
        "ESX0000000A",
        "ESA12345670",  # the control digit of A1234567 is 4
        "ESP12345674",  # P wants a letter ("ESP1234567D" is right)
        "ESN12345674",  # so do N, R and W
        "ESR12345674",
        "ESW12345674",
        "ESA1234567D",  # A wants a digit
        "BE2776091993",  # a right check, but the first digit is 0 or 1
        "DE011111129",  # a right check, but the first digit is not 0
    ],
)
def test_a_number_with_a_wrong_checksum_or_range_is_no_vat_id(vat):
    assert found(vat) == []


@pytest.mark.parametrize(
    "text",
    [
        "DE11111112",  # one digit short
        "DE1111111250",
        "de111111125",  # lower case
        "XX111111125",
        "xDE111111125",
        "DE111111125x",
        "ATU1022300",
        "NL010000446B1",
        "NL010000446X01",
        "PL526000124",
        "FR8340483304",
        "DE 1 2",
        "DE89 3704 0044 0532 0130 00",  # an IBAN, not a VAT number (it is an IBAN)
    ],
)
def test_no_vat_id_in_a_malformed_number(text):
    assert "VAT_ID" not in [kind for kind, _ in found(text)]


@pytest.mark.parametrize(
    "text,vat",
    [
        ("DE 111 111 125", "DE 111 111 125"),
        ("DE-111111125", "DE-111111125"),
        ("DE111.111.125", "DE111.111.125"),
        ("FR 83 404 833 048", "FR 83 404 833 048"),
        ("FR83 404833048", "FR83 404833048"),
        ("ATU 10223006", "ATU 10223006"),
        ("AT U10223006", "AT U10223006"),
        ("BE 0776.091.951", "BE 0776.091.951"),
        ("BE0776 091 951", "BE0776 091 951"),
        ("BE 776091951", "BE 776091951"),  # nine digits: the old form without the leading 0
        ("IT 00000010215", "IT 00000010215"),
        ("NL 010000446 B01", "NL 010000446 B01"),
        ("NL010.000.446.B01", "NL010.000.446.B01"),
        ("PL 526-000-12-46", "PL 526-000-12-46"),
        ("PL526 000 1246", "PL526 000 1246"),
        ("ES A12345674", "ES A12345674"),
        ("ES-00000000T", "ES-00000000T"),
    ],
)
def test_a_number_as_it_is_written(text, vat):
    assert found(f"VAT: {text}, thanks") == [("VAT_ID", vat)]


# --- the other EU countries: format only, and a word of VAT numbers before the number

OTHERS = [
    "BG123456789",
    "BG1234567890",
    "CY12345678L",
    "CZ12345678",
    "CZ1234567890",
    "DK12345678",
    "EE123456789",
    "EL123456789",
    "FI12345678",
    "HR12345678901",
    "HU12345678",
    "IE1234567T",
    "IE1234567TA",
    "IE1A34567T",
    "LT123456789",
    "LT123456789012",
    "LU12345678",
    "LV12345678901",
    "MT12345678",
    "PT123456789",
    "RO123456",
    "RO1234567890",
    "SE123456789001",
    "SI12345678",
    "SK1234567890",
]


@pytest.mark.parametrize("vat", OTHERS)
def test_other_countries_after_a_word_of_vat_numbers(vat):
    assert found(f"VAT number: {vat}") == [("VAT_ID", vat)]
    assert found(f"Supplier VAT ID {vat}, Berlin") == [("VAT_ID", vat)]


@pytest.mark.parametrize("vat", OTHERS)
def test_other_countries_without_the_word_are_left_alone(vat):
    assert found(f"Order {vat} shipped") == []


@pytest.mark.parametrize(
    "text",
    [
        "VAT: DE123456789",  # a wrong checksum, but the word and the format are there
        "USt-IdNr.: DE123456789",
        "MwSt-Nr. DE123456789",
        "Umsatzsteuer-ID DE123456789",
        "TVA intracommunautaire : FR12345678901",
        "n° TVA FR12345678901",
        "partita IVA IT12345678901",
        "BTW-nummer NL123456789B01",
        "IVA ES12345678A",
        "Tax ID: PL1234567890",
        "VATIN DE123456789",
        "ндс DE123456789",
        "VAT ID: DE123456789",
    ],
)
def test_after_the_word_the_format_is_enough(text):
    kinds = [kind for kind, _ in found(text)]
    assert kinds == ["VAT_ID"], text


@pytest.mark.parametrize(
    "text",
    [
        "VAT: DK1234567",  # seven digits
        "VAT: DK123456789",  # nine
        "VAT: XX12345678",
        "VAT: dk12345678",
        "VAT\nDK12345678",  # a line break between
        "VAT 21%: DK12345678",  # a number between the word and the number
        "CVAT DK12345678",  # a word that only ends like one
        "VATDK12345678",
        "Our vat is high: more than twenty characters stand between this word and DK12345678",
    ],
)
def test_nothing_in_these(text):
    assert found(text) == []


def test_a_full_stop_between_the_word_and_the_number_is_no_break():
    assert found("VAT. Order DK12345678") == [("VAT_ID", "DK12345678")]


def test_the_span_is_the_number_with_its_country_code():
    text = "Seller: Acme GmbH, USt-IdNr. DE 111 111 125, Berlin"
    (d,) = detect(text, level=2)
    assert text[d.start : d.end] == "DE 111 111 125"


def test_level_2_only():
    assert "VAT_ID" in KINDS_BY_LEVEL[2] and "VAT_ID" not in KINDS_BY_LEVEL[1]
    assert found("VAT DE111111125", level=1) == []
    for level in (2, 3, 4):
        assert found("VAT DE111111125", level=level)[0] == ("VAT_ID", "DE111111125")


def test_an_iban_keeps_its_kind():
    assert found("IBAN DE89 3704 0044 0532 0130 00") == [("IBAN", "DE89 3704 0044 0532 0130 00")]


def test_several_numbers_in_a_text():
    text = "From DE111111125 to ATU10223006, then PL5260001246 and FR83404833048."
    assert [t for _, t in found(text)] == ["DE111111125", "ATU10223006", "PL5260001246", "FR83404833048"]
