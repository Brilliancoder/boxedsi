"""Checksum validators for structured identifiers."""

import re

_NON_DIGIT = re.compile(r"\D")
_NON_ALNUM = re.compile(r"[^0-9A-Za-z]")
_IBAN = re.compile(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}")

_INN10 = (2, 4, 10, 3, 5, 9, 4, 6, 8)
_INN11 = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
_INN12 = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)


def luhn_ok(digits: str) -> bool:
    ds = _NON_DIGIT.sub("", digits)
    if not ds:
        return False
    total = 0
    for i, ch in enumerate(reversed(ds)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def iban_ok(s: str) -> bool:
    v = _NON_ALNUM.sub("", s).upper()
    if not _IBAN.fullmatch(v):
        return False
    rearranged = v[4:] + v[:4]
    return int("".join(str(int(c, 36)) for c in rearranged)) % 97 == 1


def _inn_check(digits: str, weights: tuple[int, ...]) -> int:
    return sum(int(d) * w for d, w in zip(digits, weights)) % 11 % 10


def inn_ok(s: str) -> bool:
    if not (s.isascii() and s.isdigit()):
        return False
    if len(s) == 10:
        return _inn_check(s, _INN10) == int(s[9])
    if len(s) == 12:
        return _inn_check(s, _INN11) == int(s[10]) and _inn_check(s, _INN12) == int(s[11])
    return False


def snils_ok(s: str) -> bool:
    ds = _NON_DIGIT.sub("", s)
    if len(ds) != 11:
        return False
    total = sum(int(d) * (9 - i) for i, d in enumerate(ds[:9]))
    if total < 100:
        expected = total
    elif total in (100, 101):
        expected = 0
    else:
        expected = total % 101
        if expected == 100:
            expected = 0
    return expected == int(ds[9:])
