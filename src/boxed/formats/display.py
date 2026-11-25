"""How a spreadsheet shows a number or a date, and the exact text of a cell value.

The detectors read text, so a number or date cell is turned into text twice. `shown` is the text Excel puts on the screen under
the number format of the cell: it tells an amount ("1,234.50 EUR") from a percentage ("15%") and a date ("21.10.2026"), and it is
the text that a marker stands for. `exact` is the lossless text of the stored value: it also holds what a format hides (the cents
under "0", the day under "mmm"), `parse` turns it back into the value, and the scope keeps it for each cell, for restore. Neither
text is ever written to a masked copy.
"""

import datetime
import math
import operator
import re
from dataclasses import dataclass
from decimal import MAX_EMAX, MIN_EMIN, ROUND_HALF_UP, Context, Decimal
from functools import lru_cache

MIDNIGHT = datetime.time()
SERIAL_ZERO = datetime.datetime(1899, 12, 30)  # day 0 of the date system of Excel (it counts 1900 as a leap year, this day does not)
WHOLE_FLOAT = 1e15  # from here on a whole float keeps a ".0" in its text, so that it stays a float
EXACT_INT = 2**53  # the largest whole number that a double holds exactly: past it a number cell the library writes is not the number
MAX_FORMAT = 255  # the longest number format Excel allows; a longer one is not read
CONTEXT = Context(prec=5000, rounding=ROUND_HALF_UP, Emax=MAX_EMAX, Emin=MIN_EMIN)  # digits of any number, halves away from zero

MONTHS = "January February March April May June July August September October November December".split()
DAYS = "Monday Tuesday Wednesday Thursday Friday Saturday Sunday".split()


# --- the exact text of a value ---------------------------------------------------------------------------------------

_INT = re.compile(r"(?:0|-?[1-9][0-9]*)")
_FLOAT = re.compile(r"-?(?:0|[1-9][0-9]*)\.(?:[0-9]*[1-9]|0)")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_DATETIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{6})?")
_TIME = re.compile(r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{6})?")
_ELAPSED = re.compile(r"(-?)(0|[1-9][0-9]*)h ([0-9]{2})m ([0-9]{2})(\.[0-9]{6})?s")


def exact(value) -> str | None:
    """The lossless text of a number, date, time or duration: the digits and the shortest text that gives the same float back,
    never an exponent (the detectors read digits). None for everything else, a boolean and a number without digits included."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _float_text(value) if math.isfinite(value) else None
    if isinstance(value, Decimal):
        return _decimal_text(value) if value.is_finite() else None
    if isinstance(value, datetime.datetime):
        return value.date().isoformat() if value.time() == MIDNIGHT else value.isoformat(" ")
    if isinstance(value, (datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, datetime.timedelta):
        return _elapsed_text(value)
    return None


def _float_text(value: float) -> str:
    shortest = Decimal(repr(value))
    if value.is_integer():  # a whole float is its digits, as a whole number is
        digits = str(int(shortest))
        return digits + ".0" if abs(value) >= WHOLE_FLOAT else digits
    return format(shortest, "f")


def _decimal_text(value: Decimal) -> str:
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return "0" if text == "-0" else text


def _elapsed_text(value: datetime.timedelta) -> str:
    total = abs(value)
    hours, rest = divmod(total.days * 86400 + total.seconds, 3600)
    minutes, seconds = divmod(rest, 60)
    fraction = f".{total.microseconds:06d}" if total.microseconds else ""
    return f"{'-' if value < datetime.timedelta() else ''}{hours}h {minutes:02d}m {seconds:02d}{fraction}s"


def parse(text: str):
    """The value that `exact` wrote as text; None for any other text (also one that looks like a number or a date but is not
    written the way exact writes it, such as "00123" or "1,200")."""
    try:
        if _INT.fullmatch(text):
            return int(text)
        if _FLOAT.fullmatch(text):
            return float(text)
        if _DATE.fullmatch(text):
            return datetime.date.fromisoformat(text)
        if _DATETIME.fullmatch(text):
            return datetime.datetime.fromisoformat(text)
        if _TIME.fullmatch(text):
            return datetime.time.fromisoformat(text)
        if found := _ELAPSED.fullmatch(text):
            sign, hours, minutes, seconds, fraction = found.groups()
            if int(minutes) > 59 or int(seconds) > 59:
                return None
            elapsed = datetime.timedelta(
                hours=int(hours), minutes=int(minutes), seconds=int(seconds), microseconds=int(fraction[1:]) if fraction else 0
            )
            return -elapsed if sign else elapsed
    except (ValueError, OverflowError):  # a date that does not exist, a number with more digits than int() takes
        return None
    return None


# --- what Excel shows ------------------------------------------------------------------------------------------------

_CONDITION = re.compile(r"(<=|>=|<>|<|>|=)\s*(-?[0-9]*\.?[0-9]+(?:[eE][+-]?[0-9]+)?)")
_ELAPSED_CODE = re.compile(r"(h+|m+|s+)", re.IGNORECASE)
_AM_PM = re.compile(r"am/pm|a/p", re.IGNORECASE)
_DATE_RUN = re.compile(r"[ymdhs]+", re.IGNORECASE)
_OPERATORS = {"<": operator.lt, "<=": operator.le, ">": operator.gt, ">=": operator.ge, "=": operator.eq, "<>": operator.ne}
_LONG_DATE, _LONG_TIME = "dddd, mmmm d, yyyy", "h:mm:ss AM/PM"  # what the system date and time codes of Excel stand for
_DEFAULT_FORMATS = {
    datetime.datetime: "yyyy-mm-dd hh:mm:ss",
    datetime.date: "yyyy-mm-dd",
    datetime.time: "hh:mm:ss",
    datetime.timedelta: "[h]:mm:ss",
}

Token = tuple[str, str]  # (kind, text); kinds: lit digit point comma percent slash exp date ampm elapsed general text


@dataclass(frozen=True)
class Section:
    tokens: tuple[Token, ...]
    condition: tuple[str, Decimal] | None
    is_date: bool


def _split(fmt: str) -> list[str]:
    """The sections of a format: cut at the semicolons that are not quoted, escaped or inside brackets."""
    parts, start, i = [], 0, 0
    while i < len(fmt):
        c = fmt[i]
        if c == '"':
            i = fmt.find('"', i + 1)
            i = len(fmt) if i < 0 else i
        elif c in "\\_*":
            i += 1
        elif c == "[":
            i = fmt.find("]", i + 1)
            i = len(fmt) if i < 0 else i
        elif c == ";":
            parts.append(fmt[start:i])
            start = i + 1
        i += 1
    parts.append(fmt[start:])
    return parts


def _bracket(body: str) -> tuple[str, str | tuple[str, Decimal]] | None:
    """A token for the text in [...]: a condition, a currency sign, an elapsed time; None for a color and anything unknown."""
    if found := _CONDITION.fullmatch(body):
        return "condition", (found.group(1), Decimal(found.group(2)))
    if _ELAPSED_CODE.fullmatch(body):
        return "elapsed", body.lower()
    if body.startswith("$"):
        symbol, _, locale = body[1:].rpartition("-") if "-" in body[1:] else (body[1:], "", "")
        if locale.upper() in ("F800", "SYSDATE"):
            return "system", _LONG_DATE
        if locale.upper() in ("F400", "SYSTIME"):
            return "system", _LONG_TIME
        return ("lit", symbol) if symbol else None
    return None


def _tokens(section: str) -> tuple[list[Token], tuple[str, Decimal] | None]:
    out: list[Token] = []
    condition = None
    i = 0
    while i < len(section):
        c = section[i]
        if c == '"':
            end = section.find('"', i + 1)
            end = len(section) if end < 0 else end
            out.append(("lit", section[i + 1 : end]))
            i = end + 1
        elif c == "\\":
            out.append(("lit", section[i + 1 : i + 2]))
            i += 2
        elif c == "_":  # as wide as the next character: a space
            out.append(("lit", " "))
            i += 2
        elif c == "*":  # repeats the next character to fill the cell: it only pads
            i += 2
        elif c == "[":
            end = section.find("]", i + 1)
            if end < 0:
                out.append(("lit", c))
                i += 1
                continue
            bracket = _bracket(section[i + 1 : end])
            if bracket and bracket[0] == "condition":
                condition = condition or bracket[1]
            elif bracket and bracket[0] == "system":
                out.extend(_tokens(bracket[1])[0])
            elif bracket:
                out.append(bracket)
            i = end + 1
        elif c in "0#?":
            out.append(("digit", c))
            i += 1
        elif c in ".,%/@":
            out.append(({".": "point", ",": "comma", "%": "percent", "/": "slash", "@": "text"}[c], c))
            i += 1
        elif c in "Ee" and section[i + 1 : i + 2] in ("+", "-"):
            out.append(("exp", section[i : i + 2]))
            i += 2
        elif found := _AM_PM.match(section, i):
            out.append(("ampm", found.group()))
            i = found.end()
        elif found := _DATE_RUN.match(section, i):
            out.append(("date", found.group().lower()))
            i = found.end()
        elif section[i : i + 7].lower() == "general":
            out.append(("general", ""))
            i += 7
        else:  # a character that Excel shows as it is: $ - + ( ) : space ...
            out.append(("lit", c))
            i += 1
    return out, condition


@lru_cache(maxsize=512)
def _sections(fmt: str) -> tuple[Section, ...]:
    sections = []
    for part in _split(fmt)[:4]:
        tokens, condition = _tokens(part)
        is_date = any(kind in ("date", "ampm", "elapsed") for kind, _ in tokens)
        sections.append(Section(tuple(tokens), condition, is_date))
    return tuple(sections)


def _choose(sections: tuple[Section, ...], number: Decimal) -> tuple[Section, bool]:
    """The section for a number and whether it shows a minus sign. The fourth section is for text. Without conditions the first
    is for positive numbers (and zero when it is the only one besides the second) and the second for negative ones, which
    then show no minus of their own; a section without a condition that comes last takes what is left."""
    usable = sections[:3]
    explicit = any(section.condition for section in usable)
    for k, section in enumerate(usable):
        if section.condition:
            fits = _OPERATORS[section.condition[0]](number, section.condition[1])
        elif k == len(usable) - 1:
            fits = True
        elif k == 0:
            fits = number > 0 if len(usable) > 2 else number >= 0
        else:
            fits = number < 0
        if fits:
            return section, number < 0 and (k == 0 or explicit)
    return usable[-1], number < 0


def _decimal(value) -> Decimal:
    return Decimal(repr(value)) if isinstance(value, float) else Decimal(value)


def _general(value) -> str:
    """What Excel shows without a format: up to 15 significant digits, never an exponent."""
    if isinstance(value, float):
        return format(Decimal(f"{value:.15g}"), "f") if math.isfinite(value) else ""
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, int):
        return str(value)
    return _shown_date(value, _DEFAULT_FORMATS[_family(value)])


def _family(value) -> type:
    for family in (datetime.datetime, datetime.date, datetime.time, datetime.timedelta):
        if isinstance(value, family):
            return family
    raise TypeError("not a number or a date")


def shown(value, number_format: str) -> str:
    """The text Excel shows for a number, date, time or duration under a number format. A format that cannot be read is shown as
    General: the exact text of the value is checked as well, so a poor reading only costs the kind of the placeholder."""
    try:
        if not number_format or number_format.lower() == "general" or len(number_format) > MAX_FORMAT:
            return _general(value)
        if isinstance(value, (datetime.date, datetime.time, datetime.timedelta)):
            return _shown_date(value, number_format)
        return _shown_number(value, number_format)
    except (ArithmeticError, ValueError, IndexError, KeyError, TypeError):  # an odd format must never stop a copy
        return _fallback(value)


def _fallback(value) -> str:
    """What stands for a value that its format cannot render: General, and where not even that can (a duration of more days than
    Python has dates, 3000000 under [h]:mm:ss), the exact text. Never an error: one cell that cannot be read would stop the copy."""
    try:
        return _general(value)
    except (ArithmeticError, ValueError, TypeError):
        return exact(value) or ""


# --- numbers ---------------------------------------------------------------------------------------------------------


def _shown_number(value, number_format: str) -> str:
    sections = _sections(number_format)
    number = _decimal(value)
    section, minus = _choose(sections, number)
    if section.is_date:  # a number under a date format is a day count
        return _render_date(section, SERIAL_ZERO + datetime.timedelta(days=float(number)), None)
    text = _render_number(section.tokens, abs(number))
    return ("-" if minus else "") + text if text is not None else _general(value)


def _render_number(tokens: tuple[Token, ...], number: Decimal) -> str | None:
    """The digits of a non-negative number in the places of a numeric section. None for a fraction format ("# ?/?"): that is
    shown as General."""
    kinds = [kind for kind, _ in tokens]
    zone, level = [], 0  # 0: before the point, 1: after it, 2: after the exponent
    for kind in kinds:
        level = 1 if kind == "point" and level == 0 else 2 if kind == "exp" and level < 2 else level
        zone.append(level)
    places = [i for i, kind in enumerate(kinds) if kind == "digit"]
    whole_places = [i for i in places if zone[i] == 0]
    fraction_places = [i for i in places if zone[i] == 1]
    if any(kind == "slash" and places and places[0] < i < places[-1] for i, kind in enumerate(kinds)):
        return None
    grouping, scaling, hidden = False, 0, set()  # hidden: the commas that are not shown
    for i, kind in enumerate(kinds):
        if kind == "comma" and zone[i] == 0 and any(j > i for j in whole_places):
            grouping = True  # between digit places: a thousands separator
            hidden.add(i)
        elif kind == "comma" and zone[i] < 2 and any(j < i for j in places):
            scaling += 1  # after the last digit place: divides by 1000
            hidden.add(i)
    number = number.scaleb(2 * kinds.count("percent") - 3 * scaling, CONTEXT)
    step = Decimal(1).scaleb(-len(fraction_places))
    exponent = 0
    if "exp" in kinds:
        size = max(len(whole_places), 1)  # a format with ### in front of the point gives exponents in steps of 3
        exponent = (number.adjusted() // size) * size if number else 0
        mantissa = number.scaleb(-exponent, CONTEXT).quantize(step, context=CONTEXT)
        if mantissa >= Decimal(10) ** size:  # 9.996 rounds up to 10.00
            exponent += size
            mantissa = number.scaleb(-exponent, CONTEXT).quantize(step, context=CONTEXT)
    else:
        mantissa = number.quantize(step, context=CONTEXT)
    whole, _, fraction = format(mantissa, "f").partition(".")
    digits = whole.lstrip("0")
    # The places take the digits from the right, and a digit place that has none shows "0", " " or nothing; more digits than
    # places stay in front of the leftmost place (or of the point).
    units = []
    for k in range(max(len(digits), len(whole_places))):
        if k < len(digits):
            unit, real = digits[-1 - k], True
        else:
            fill = tokens[whole_places[-1 - k]][1]
            unit, real = {"0": "0", "?": " ", "#": ""}[fill], fill == "0"
        units.append(unit + "," if grouping and k and k % 3 == 0 and real else unit)
    shown_whole = {at: units[len(whole_places) - 1 - n] for n, at in enumerate(whole_places)}
    lead = "".join(reversed(units[len(whole_places) :]))
    if whole_places:
        shown_whole[whole_places[0]] = lead + shown_whole[whole_places[0]]
        lead = ""
    # The fraction places take the digits from the left; trailing zeros of "#" and "?" places are not shown.
    shown_fraction, trailing = {}, True
    for n in reversed(range(len(fraction_places))):
        fill = tokens[fraction_places[n]][1]
        if trailing and fill != "0" and fraction[n] == "0":
            shown_fraction[fraction_places[n]] = "" if fill == "#" else " "
        else:
            trailing = False
            shown_fraction[fraction_places[n]] = fraction[n]
    out, pointed = [], False
    for i, (kind, text) in enumerate(tokens):
        if kind == "digit":
            out.append(shown_whole.get(i) if zone[i] == 0 else shown_fraction.get(i, ""))
        elif kind == "point" and not pointed and zone[i] == 1:
            pointed = True
            out.append(lead + text)
        elif kind == "comma":
            out.append("" if i in hidden else text)
        elif kind == "exp":
            sign = "-" if exponent < 0 else "+" if text[1] == "+" else ""
            zeros = sum(1 for j in places if zone[j] == 2 and tokens[j][1] == "0")
            out.append(text[0] + sign + str(abs(exponent)).zfill(zeros))
        elif kind in ("general", "text"):
            out.append(_general(number))
        else:
            out.append(text)
    return "".join(out)


# --- dates -----------------------------------------------------------------------------------------------------------


def _shown_date(value, number_format: str) -> str:
    section = _sections(number_format)[0]
    if not section.is_date:
        section = _sections(_DEFAULT_FORMATS[_family(value)])[0]
    return _render_date(section, value, value if isinstance(value, datetime.timedelta) else None)


def _as_datetime(value) -> datetime.datetime:
    if isinstance(value, datetime.datetime):
        return value
    if isinstance(value, datetime.date):
        return datetime.datetime.combine(value, MIDNIGHT)
    if isinstance(value, datetime.time):
        return datetime.datetime.combine(SERIAL_ZERO.date(), value)
    return SERIAL_ZERO + value


def _render_date(section: Section, value, duration: datetime.timedelta | None) -> str:
    moment = _as_datetime(value)
    elapsed = duration.total_seconds() if duration is not None else (moment - SERIAL_ZERO).total_seconds()
    tokens = section.tokens
    clock = [i for i, (kind, text) in enumerate(tokens) if kind in ("date", "elapsed")]
    twelve = any(kind == "ampm" for kind, _ in tokens)
    out, skip = [], 0
    for i, (kind, text) in enumerate(tokens):
        if skip:
            skip -= 1
            continue
        if kind == "date":
            out.append(_date_part(text, moment, _is_minutes(tokens, clock, i), twelve))
        elif kind == "elapsed":
            unit = {"h": 3600, "m": 60, "s": 1}[text[0]]
            out.append(str(int(abs(elapsed) // unit)).zfill(len(text)))
        elif kind == "ampm":
            marker = "pm" if moment.hour >= 12 else "am"
            marker = marker if text[1].lower() == "m" else marker[0]  # "A/P" gives a letter
            out.append(marker.upper() if text[0].isupper() else marker.lower())
        elif kind == "point" and _after_seconds(tokens, i):
            places = 0
            while i + 1 + places < len(tokens) and tokens[i + 1 + places][0] == "digit":
                places += 1
            if places:
                out.append("." + f"{moment.microsecond:06d}"[:places].ljust(places, "0"))
                skip = places
            else:
                out.append(text)
        else:
            out.append(text)
    return "".join(out)


def _is_minutes(tokens: tuple[Token, ...], clock: list[int], index: int) -> bool:
    """An m right after the hours or right before the seconds is minutes; any other m is a month."""
    if tokens[index][1][0] != "m":
        return False
    at = clock.index(index)
    before = tokens[clock[at - 1]][1][0] if at else ""
    after = tokens[clock[at + 1]][1][0] if at + 1 < len(clock) else ""
    return before == "h" or after == "s"


def _after_seconds(tokens: tuple[Token, ...], index: int) -> bool:
    for kind, text in reversed(tokens[:index]):
        if kind in ("date", "elapsed"):
            return text[0] == "s"
    return False


def _date_part(code: str, moment: datetime.datetime, minutes: bool, twelve: bool) -> str:
    n = len(code)
    match code[0]:
        case "y":
            return f"{moment.year % 100:02d}" if n <= 2 else f"{moment.year:04d}"
        case "m" if minutes:
            return str(moment.minute) if n == 1 else f"{moment.minute:02d}"
        case "m":
            name = MONTHS[moment.month - 1]
            return {1: str(moment.month), 2: f"{moment.month:02d}", 3: name[:3], 5: name[0]}.get(n, name)
        case "d":
            name = DAYS[moment.weekday()]
            return {1: str(moment.day), 2: f"{moment.day:02d}", 3: name[:3]}.get(n, name)
        case "h":
            hour = moment.hour % 12 or 12 if twelve else moment.hour
            return str(hour) if n == 1 else f"{hour:02d}"
        case _:
            return str(moment.second) if n == 1 else f"{moment.second:02d}"
