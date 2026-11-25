from boxed.detect.validators import iban_ok, inn_ok, luhn_ok, snils_ok


def test_luhn():
    assert luhn_ok("4111111111111111")
    assert not luhn_ok("4111111111111112")


def test_iban():
    assert iban_ok("DE89370400440532013000")
    assert iban_ok("DE89 3704 0044 0532 0130 00")
    assert not iban_ok("DE89370400440532013001")


def test_inn():
    assert inn_ok("7707083893")
    assert inn_ok("500100732259")
    assert not inn_ok("7707083894")
    assert not inn_ok("500100732258")
    assert not inn_ok("12345")


def test_snils():
    assert snils_ok("112-233-445 95")
    assert snils_ok("11223344595")
    assert not snils_ok("112-233-445 96")
