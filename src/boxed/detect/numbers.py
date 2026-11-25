"""Level 3 candidates: amounts, percentages, dates and numbers (all become placeholders, none is shifted).

Typed findings (secrets, e-mails, names, ...) come first and are never touched. Then one left-to-right pass finds the
amounts, percentages and dates, and a second one the plain numbers in what is left: every character belongs to at most
one token, so a long chain of digits is scanned once and no rule restarts inside it. Level 3 therefore never masks less
than level 2. Each branch opens with a cheap look-ahead, so the long word lists below are tried only where they can match.
"""

import re
from collections.abc import Iterable
from operator import attrgetter

from .patterns import Candidate

KINDS = frozenset({"MONEY", "PERCENT", "DATE", "NUMBER"})

_NBSP, _THIN, _NARROW = r"\N{NO-BREAK SPACE}", r"\N{THIN SPACE}", r"\N{NARROW NO-BREAK SPACE}"
_SPACE = rf"[ {_NBSP}{_THIN}{_NARROW}]"  # never a newline or a tab
_THOUSANDS = rf"[ {_NBSP}{_THIN}{_NARROW},.'\N{{RIGHT SINGLE QUOTATION MARK}}]"
_SIGN = r"[+\-\N{MINUS SIGN}]"
_DASH = r"[-\N{EN DASH}\N{EM DASH}]"
_LETTER = r"[^\W\d_]"
# 1 200, 1,200, 1.200, 1'200 (groups of three after one to three digits) or plain digits, then a decimal part. A dot
# that goes on with digits ("1.2.3", "10.0.0.1") makes it no number of ours: those chains are skipped as a whole.
# When what follows does not fit, the number gives back its last group: "1 234 567abcdefgh" keeps "1 234". Not atomic,
# on purpose: with all or nothing, every group of a long chain would start a new scan of the rest of it.
_NUM = rf"(?:(?:\d{{1,3}}(?:{_THOUSANDS}\d{{3}})+(?!\d)|\d+)(?:[.,]\d+)?(?!\.\d))"

# --- money -----------------------------------------------------------------------------------------------------------

_CUR_SIGN = r"[$€£¥₽₴₸₾₼₺₹₩₪₫฿₦₱₡₭₮]"
_CUR_SIGN_PREFIXED = r"(?:US|CA|AU|NZ|HK|MX|[CASR])\$"  # US$ 1.2 million, C$5
_CODES_BIG = "USDT|USDC|USD|EUR|GBP|RUB"
_CODES_OTHER = (
    "CHF|JPY|CNY|RMB|KZT|UAH|BYN|AZN|AMD|GEL|TRY|AED|INR|PLN|CZK|SEK|NOK|DKK|CAD|AUD|NZD"
    "|HKD|SGD|KRW|BRL|MXN|ZAR|ILS|THB|UZS|KGS|MDL|RSD|BGN|HUF|BTC|ETH"
)
_CUR_CODE = rf"(?:{_CODES_BIG}|{_CODES_OTHER}|RON)(?![A-Za-z])"
# A number is bare when none of its own digits follow: no decimal part, no group, no more digits.
_BARE = rf"(?!\d)(?![.,'\N{{RIGHT SINGLE QUOTATION MARK}}]\d)(?!{_SPACE}\d{{3}})"
# In front of a number a code makes money, except in front of a bare year of the last decades ("CAD 2024") and, for RON,
# of an octane number ("RON 95"). The big codes keep every number: "USD 2024" may be an amount, so may "CHF 2000".
_CUR_CODE_BEFORE = (
    rf"(?:(?:{_CODES_BIG})(?![A-Za-z])"
    rf"|(?:{_CODES_OTHER})(?![A-Za-z])(?!{_SPACE}?20[1-3]\d{_BARE})"
    rf"|RON(?![A-Za-z])(?!{_SPACE}?(?:8[5-9]|9\d|10[0-2]){_BARE}))"
)
_CUR_WORD = (
    r"(?i:"
    r"руб(?:л(?:ей|ям|ях|ями|ь|я|ю|ем|е)|\.)?|р\.|коп(?:ейк(?:ам|ах|а|и|е|у|ой)|еек|\.)?"
    r"|долл(?:ар(?:ов|ам|ах|ами|а|ы|е|у|ом)?|\.)?|евро|цент(?:ов|ам|ах|ами|а|ы|е|у|ом)?|у\.[ ]?е\."
    r"|гривн(?:ам|ах|ами|а|ы|е|у|ой|ей)|грн\.?|тенге|юан(?:ей|ям|ях|ями|ь|я|е|ю|ем)|[ий]ен[аыеу]?|франк(?:ов|ам|ах|а|и)?"
    r"|злот(?:ых|ого|ым|ый)|дирхам(?:ов|а)?|манат(?:ов|а)?|лари"
    r"|dollars?|euros?|cents?|rubles?|roubles?|yuan|yen|francs?|dirhams?|rupees?|bucks|usd|eur|rub"
    r")(?!\w)"
)
_SCALE_ABBR = r"(?i:тыс|млн|млрд|трлн|mln|bln|mn|bn)(?:\.|(?!\w))"
_SCALE_FULL = (
    r"(?i:тысяч(?:ами|ей|ам|ах|а|и|е|у)?|(?:миллион|миллиард|триллион)(?:ами|ов|ам|ах|а|у|ом|е)?"
    r"|thousand|million|billion|trillion)(?!\w)"
)
_SCALE_WORD = rf"{_SPACE}?(?={_LETTER})(?:{_SCALE_ABBR}|{_SCALE_FULL})"
_SCALE = rf"(?:{_SCALE_WORD}|[kKкКmMbB](?!\w))"  # a single letter only when it sticks to the number

# a number with its scale, and for a range the other bound with its own: 5-7 млн, 100k-200k, 1.2M-1.5M, 10-15
_AMOUNT_NUM = rf"{_NUM}{_SCALE}?(?:{_SPACE}?{_DASH}{_SPACE}?{_NUM}{_SCALE}?)?"
# what some write between the number and the currency: 1 200 000 (один миллион двести тысяч) рублей
_PAREN = r"\([^()\n\x00]{1,100}\)"

_CUR_BEFORE = rf"(?:{_CUR_SIGN_PREFIXED}|{_CUR_SIGN}|{_CUR_CODE_BEFORE})"
_CUR_AFTER = rf"(?=[^\W\d_]|{_CUR_SIGN})(?:{_CUR_SIGN}|{_CUR_CODE}|{_CUR_WORD})"
_MONEY_BEFORE = rf"{_SIGN}?{_CUR_BEFORE}{_SPACE}?{_SIGN}?{_AMOUNT_NUM}(?:{_SPACE}?{_CUR_AFTER})?"

# --- percent ---------------------------------------------------------------------------------------------------------

_PERCENT_WORD = r"(?i:процент(?:ов|ам|ах|ами|а|ы|е|у|ом)?|percent|per cent|percentage points?|п\.[ ]?п\.)(?!\w)"
_PERCENT_MARK = rf"(?:[%\N{{FULLWIDTH PERCENT SIGN}}]|(?={_LETTER}){_PERCENT_WORD})"

# --- dates -----------------------------------------------------------------------------------------------------------

_YEAR = r"[12]\d{3}(?!\d)"
_DAY = r"(?:0?[1-9]|[12]\d|3[01])(?!\d)"
_DAY2 = r"(?:0[1-9]|[12]\d|3[01])(?!\d)"
_MONTH_NO = r"(?:0?[1-9]|1[0-2])(?!\d)"
_MONTH_NO2 = r"(?:0[1-9]|1[0-2])(?!\d)"
_RU_MONTH = (
    r"(?i:январ(?:ь|я|е|ю|[её]м)|феврал(?:ь|я|е|ю|[её]м)|март(?:ом|а|е|у)?|апрел(?:ь|я|е|ю|ем)|ма(?:й|я|е|ю|ем)"
    r"|июн(?:ь|я|е|ю|ем)|июл(?:ь|я|е|ю|ем)|август(?:ом|а|е|у)?|сентябр(?:ь|я|е|ю|[её]м)|октябр(?:ь|я|е|ю|[её]м)"
    r"|ноябр(?:ь|я|е|ю|[её]м)|декабр(?:ь|я|е|ю|[её]м))(?!\w)"
)
_RU_MONTH_ABBR = r"(?i:янв|февр?|мар|апр|июн|июл|авг|сент?|окт|нояб?|дек)(?:\.|(?!\w))"
# in any case; only the word "may" needs a capital
_EN_MONTH = r"(?i:January|February|March|April|(?-i:May|MAY)|June|July|August|September|October|November|December)(?!\w)"
_EN_MONTH_ABBR = r"(?i:Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sept?|Oct|Nov|Dec)(?:\.|(?!\w))"
_MONTH_NAME = rf"(?={_LETTER})(?:{_RU_MONTH}|{_RU_MONTH_ABBR}|{_EN_MONTH}|{_EN_MONTH_ABBR})"
_ORDINAL = r"(?:st|nd|rd|th)?"
_TIME = r"(?:[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:Z|[+\-]\d{2}(?::?\d{2})?)?)?"

_DATE = (
    # 2026-10-21, 2026/10/21, 2026.10.21, with a time after it: 2026-10-21T14:30:00+03:00
    rf"{_YEAR}(?P<iso_sep>[-/.]){_MONTH_NO2}(?P=iso_sep){_DAY2}{_TIME}(?!\d)"
    # 21.10.2026, 10.21.2026, 1.9.2026; with two year digits both other parts need two digits and come day first:
    # 21.10.26 (but "3.10.12" is a version)
    rf"|(?:(?:{_DAY}\.{_MONTH_NO}|{_MONTH_NO}\.{_DAY})\.{_YEAR}|{_DAY2}\.{_MONTH_NO2}\.\d{{2}}(?!\d))(?!\.\d)"
    # 21/10/2026 and 10/21/2026 (either order), 21-10-2026
    rf"|(?:{_DAY}/{_MONTH_NO}|{_MONTH_NO}/{_DAY})/(?:{_YEAR}|\d{{2}}(?!\d))(?!/\d)"
    rf"|{_DAY}-{_MONTH_NO}-{_YEAR}"
    # 21 октября 2026, 21 окт. 2026, 21st of October, 2026, 21 October, 21-23 октября
    rf"|{_DAY}(?:{_SPACE}?{_DASH}{_SPACE}?{_DAY})?{_ORDINAL}{_SPACE}(?:of{_SPACE})?{_MONTH_NAME}(?:,?{_SPACE}{_YEAR})?"
    # October 21, 2026; Oct. 21; октябрь 2026
    rf"|{_MONTH_NAME}{_SPACE}(?:{_DAY}{_ORDINAL}(?:,?{_SPACE}{_YEAR})?|{_YEAR})"
    # 21-Oct-2026, 21-Oct, Oct-2026
    rf"|{_DAY}-{_MONTH_NAME}(?:-{_YEAR})?|{_MONTH_NAME}-{_YEAR}"
    # Q3 2026, Q3-2026, Q32026, Q3'26, 2026 Q3, 2026Q3, H1 2026, FY2026, FY26 (a period needs its year)
    rf"|(?:Q[1-4]|H[12])(?:(?:{_SPACE}|-)?{_YEAR}|['\N{{RIGHT SINGLE QUOTATION MARK}}]\d{{2}}(?!\d))"
    rf"|{_YEAR}(?:{_SPACE}|-)?(?:Q[1-4]|H[12])(?!\w)|FY(?:{_SPACE}|-)?(?:{_YEAR}|\d{{2}}(?!\d))"
    # 3 кв. 2026, III квартал 2026
    rf"|(?:[1-4](?:-(?i:й|м|го|е|я))?|I{{1,3}}|IV){_SPACE}(?:кв\.|(?i:квартал(?:ом|а|е|у)?)(?!\w)){_SPACE}{_YEAR}"
    # 20261021T143000Z, 20261021T1430
    rf"|[12]\d{{3}}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3])[0-5]\d(?:[0-5]\d)?"
    r"(?:Z|[+\-]\d{2}(?::?\d{2})?)?(?!\d)"
)
# a date starts with 1-4 digits and a dot, slash, hyphen or dash, or an (ordinal,) space and a letter, or 4 digits and
# Q or H, or 8 digits and T; or with a capital letter or a Cyrillic one (months, Q, FY, Roman numerals), or the start of an
# English month in lower case
_DATE_AHEAD = (
    rf"(?=\d{{1,4}}(?:[/.]|{_SPACE}?{_DASH}|{_ORDINAL}{_SPACE}{_LETTER})|\d{{4}}[QH]|\d{{8}}T|[A-ZА-Яа-яЁё]"
    r"|(?i:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec))"
)

# --- plain numbers ---------------------------------------------------------------------------------------------------

# Two digits or more (a lone digit is structure, not data), or any number with a scale word ("5 млн"). A short run of
# letters may follow ("100kg", "2026г."); a longer one or a digit after the letters makes it an identifier ("24x7").
_NUMBER_END = rf"(?P<number_scale>{_SCALE})?(?:(?!\w)|(?={_LETTER}{{1,4}}(?!\w)))"
_CHAIN = r"\d+(?:\.\d+){2,}"  # 1.2.3, 10.0.0.1: versions and addresses, not numbers
# 9:05 AM, 14:30:15: one number, not three
_CLOCK = rf"(?:[01]?\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:[.,]\d+)?)?(?:{_SPACE}?[AaPp]\.?[Mm]\.?)?(?![\w:])"

# --- the passes ------------------------------------------------------------------------------------------------------

# A token starts at a word boundary and not after "digit." (the rest of a version or a decimal). A hyphen is no boundary
# of its own: the year of "report-2026-10-21" and the 19 of "COVID-19" are figures like any other.
_START = r"(?<!\w)(?<!\d\.)"
# A run of digits the first pass steps over: groups of three, or plain digits. No decimal part: "120000,2021-03-01" has a
# date behind the comma, and a run read once is not scanned again from each of its groups.
_RUN = rf"(?:\d{{1,3}}(?:{_THOUSANDS}\d{{3}})+(?!\d)|\d+)"

# Two passes, as the order of kinds says: typed findings, then amounts, percentages and dates, then plain numbers. A pass
# reads a text in which what came before is blanked out, so nothing is ever cut in two or swallowed by a longer token.
_AMOUNTS = re.compile(
    rf"{_START}(?:"
    rf"{_DATE_AHEAD}(?P<date>{_DATE})"
    rf"|(?=[+\-\N{{MINUS SIGN}}A-Z]|{_CUR_SIGN})(?P<money_before>{_MONEY_BEFORE})"
    rf"|{_SIGN}?{_AMOUNT_NUM}(?:(?P<money_after>(?:{_SPACE}?{_PAREN})?{_SPACE}?{_CUR_AFTER})"
    rf"|(?P<percent>{_SPACE}?{_PERCENT_MARK}))"
    rf"|(?P<run>{_RUN})"
    r")"
)
_NUMBERS = re.compile(
    rf"{_START}(?:(?P<time>{_CLOCK})|{_SIGN}?{_NUM}(?P<number>{_NUMBER_END})|(?P<chain>{_CHAIN}))"
)

_DETECTORS = {
    "date": ("DATE", "rule:date"),
    "money_before": ("MONEY", "rule:money"),
    "money_after": ("MONEY", "rule:money"),
    "percent": ("PERCENT", "rule:percent"),
    "time": ("NUMBER", "rule:number"),
    "number": ("NUMBER", "rule:number"),
}
_HOLE = "\0"  # blanks a taken span: no token reads it, none runs across it


def _blank(text: str, spans: list[tuple[int, int]]) -> str:
    parts, pos = [], 0
    for start, end in sorted(spans):
        start = max(start, pos)
        if end > start:
            parts.append(text[pos:start])
            parts.append(_HOLE * (end - start))
            pos = end
    parts.append(text[pos:])
    return "".join(parts)


def _tokens(pattern: re.Pattern[str], blanked: str, text: str) -> list[Candidate]:
    out = []
    for m in pattern.finditer(blanked):
        name = m.lastgroup
        if name in ("run", "chain"):
            continue
        start, end = m.span()
        if name == "number" and end - start < 3 and (end - start == 1 or not blanked[start].isdecimal()):
            continue  # a lone digit, with or without a sign (a scale word would make the token longer)
        kind, detector = _DETECTORS[name]
        out.append(Candidate(start, end, kind, text[start:end], detector))
    return out


def number_candidates(text: str, taken: Iterable[Candidate] = ()) -> list[Candidate]:
    """Amounts, percentages and dates, then numbers of two or more digits, in text order and without overlaps.

    taken: findings of other kinds (anything with start and end). They win: no candidate touches them."""
    blanked = _blank(text, [(c.start, c.end) for c in taken])
    amounts = _tokens(_AMOUNTS, blanked, text)
    numbers = _tokens(_NUMBERS, _blank(blanked, [(c.start, c.end) for c in amounts]), text)
    return sorted(amounts + numbers, key=attrgetter("start"))
