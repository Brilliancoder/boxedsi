"""Find secrets and personal data in text."""

import bisect
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from itertools import accumulate
from operator import attrgetter

from ..errors import UserError
from .numbers import KINDS as NUMBER_KINDS
from .numbers import number_candidates

# the kind is the person's, and names a client: not quoted
BAD_DICTIONARY_KIND = "boxed.toml: [boxed.dictionary] a kind has letters, digits and _ only, and starts with a letter"
from .patterns import LABEL_WORD, Candidate, dictionary_candidates, host_url_candidates, rule_candidates

_LEVEL_0 = frozenset({"SECRET", "PRIVATE_KEY", "JWT", "CARD"})
_LEVEL_1 = _LEVEL_0 | {"EMAIL", "PHONE", "IP", "IBAN", "INN", "SNILS", "PERSON", "PASSPORT", "SSN"}
_LEVEL_2 = _LEVEL_1 | {"HOST", "URL", "ORG", "VAT_ID", "CRYPTO_ADDR"}
_LEVEL_3 = _LEVEL_2 | NUMBER_KINDS  # all amounts, percentages, dates and numbers; level 4 detects the same

KINDS_BY_LEVEL: dict[int, frozenset[str]] = {0: _LEVEL_0, 1: _LEVEL_1, 2: _LEVEL_2, 3: _LEVEL_3, 4: _LEVEL_3}
DICTIONARY_MIN_LEVEL = 2
# The number kinds come last. They are searched after everything else (see detect) and never compete in _resolve; the
# order stays for a dictionary term of such a kind, which loses a tie with any other.
PRIORITY = {
    "SECRET": 0,
    "PRIVATE_KEY": 1,
    "JWT": 2,
    "EMAIL": 3,
    "URL": 4,
    "HOST": 5,
    "IP": 6,
    "MONEY": 101,
    "PERCENT": 102,
    "DATE": 103,
    "NUMBER": 104,
}
KIND_RE = re.compile(r"[A-Z][A-Z0-9_]*")


@dataclass(frozen=True)
class Detection:
    start: int
    end: int
    kind: str
    text: str
    detector: str


@dataclass
class DetectConfig:
    internal_domains: list[str] = field(default_factory=list)
    dictionary: dict[str, str] = field(default_factory=dict)
    allow: set[str] = field(default_factory=set)
    ner: list = field(default_factory=list)  # NER detector objects, see boxed.detect.ner


def _span_finder(spans: list[tuple[int, int]]) -> Callable[[int], bool]:
    """A test of whether a position lies in any of the spans (start <= position < end), whether they overlap or not.

    The spans are sorted once; a question is then a bisect over the starts and a look at the furthest end among the spans
    that start at or before the position, so n questions about m spans cost (n + m) log m, not n * m."""
    ordered = sorted(spans)
    starts = [start for start, _ in ordered]
    reach = list(accumulate((end for _, end in ordered), max))  # the furthest end of the spans up to each one

    def holds(position: int) -> bool:
        i = bisect.bisect_right(starts, position)  # the spans that start at or before it
        return i > 0 and reach[i - 1] > position

    return holds


def _resolve(cands: list[Candidate]) -> list[Candidate]:
    """Longest first, then by kind priority; a candidate that overlaps a kept one is dropped. Spans end at or after their start.

    A kept span is never shorter than the candidate, so it can overlap only by covering the candidate's first or last cell.
    The cells are the gaps between the sorted coordinates, in a byte array: two lookups per candidate, and since kept spans
    never overlap, each cell is filled once. An empty candidate (they come last) overlaps only a span that holds its point
    strictly inside: the cell after the point is covered by a span that does not start there (`begins`), so that span began
    earlier and covers the cell before too."""
    ordered = sorted(cands, key=lambda c: (-(c.end - c.start), PRIORITY.get(c.kind, 100), c.start))
    cell = {x: i for i, x in enumerate(sorted({x for c in ordered for x in (c.start, c.end)}))}
    covered, begins = bytearray(len(cell)), bytearray(len(cell))
    kept: list[Candidate] = []
    for c in ordered:
        a, b = cell[c.start], cell[c.end]
        if a == b:
            if covered[a] and not begins[a]:
                continue
        elif covered[a] or covered[b - 1]:
            continue
        else:
            covered[a:b] = b"\x01" * (b - a)
            begins[a] = 1
        kept.append(c)
    # Two kept spans share a start only when one or both are empty, and empty ones are processed last. Reversing first puts the
    # latest empty span first at a shared start, the order an insert at the left of equal starts gave.
    kept.reverse()
    kept.sort(key=attrgetter("start"))
    return kept


_LETTERS = re.compile(r"[^\W\d_]+")


def _is_name(part: str) -> bool:
    """A word of two letters at least, and not only labels of numbers: a model that takes "IBAN DE89 3704 ..." for an
    organization leaves "IBAN" once the rule has the number."""
    words = _LETTERS.findall(part)
    return any(len(word) > 1 for word in words) and not all(LABEL_WORD.fullmatch(word) for word in words)


def _outside(c: Candidate, text: str, kept: list[Candidate], starts: list[int], ends: list[int]) -> list[Candidate]:
    """The parts of a span of a name model that no finding covers, each without the blanks at its edges and only when it is a name
    (_is_name). The model takes a VAT number or a tax number for a part of the company ("ООО Ромашка DE811569869"); the rule keeps
    the number, and what is left is still a name. `kept` are sorted by their starts and do not overlap, so are their ends."""
    first = bisect.bisect_right(ends, c.start)  # the first finding that ends after the span starts
    last = bisect.bisect_left(starts, c.end)  # the findings from here on start at or after its end
    inside = [k for k in kept[first:last] if k.end > k.start]
    if not inside:
        return [c]
    cuts, at = [], c.start
    for k in inside:
        cuts.append((at, k.start))
        at = max(at, k.end)
    cuts.append((at, c.end))
    parts = []
    for a, b in cuts:
        piece = text[a:b] if a < b else ""
        body = piece.strip()
        if _is_name(body):
            lead = a + len(piece) - len(piece.lstrip())
            parts.append(Candidate(lead, lead + len(body), c.kind, body, c.detector))
    return parts


def detect(text: str, level: int = 2, config: DetectConfig | None = None, ner: list | None = None) -> list[Detection]:
    """Rules first; NER spans (boxed.detect.ner) only fill gaps: one overlapping a rule match is cut around it. From level 3 on
    the amounts, percentages, dates and numbers come last, in what the rest left free: level 3 is level 2 and more."""
    if level not in KINDS_BY_LEVEL:
        raise ValueError(f"unknown level {level}")
    config = config or DetectConfig()
    kinds = KINDS_BY_LEVEL[level]
    hosts, authority_spans = host_url_candidates(text, config.internal_domains)
    in_credentials = _span_finder(authority_spans)
    terms = []
    if level >= DICTIONARY_MIN_LEVEL:
        for c in dictionary_candidates(text, config.dictionary):
            if not KIND_RE.fullmatch(c.kind):
                raise UserError(BAD_DICTIONARY_KIND)
            terms.append(c)
    from_config = [c for c in [*(h for h in hosts if h.kind in kinds), *terms] if c.text not in config.allow]
    cands = [
        c
        for c in rule_candidates(text, from_config) + hosts
        if c.kind in kinds and not (c.kind == "EMAIL" and in_credentials(c.start))
    ] + terms
    kept = _resolve([c for c in cands if c.text not in config.allow])
    ner = config.ner if ner is None else ner
    if ner:
        extra = [
            Candidate(d.start, d.end, d.kind, d.text, d.detector)
            for detector in ner
            for d in detector.find(text)
            if d.kind in kinds and d.text not in config.allow
        ]
        starts, ends = [k.start for k in kept], [k.end for k in kept]  # kept: sorted by start, no overlaps
        free = [part for c in extra for part in _outside(c, text, kept, starts, ends) if part.text not in config.allow]
        kept = _resolve(kept + free)
    if kinds & NUMBER_KINDS:  # last: amounts, percentages, dates and numbers only where nothing else was found
        numbers = [c for c in number_candidates(text, kept) if c.kind in kinds and c.text not in config.allow]
        kept = sorted(kept + numbers, key=attrgetter("start"))
    return [Detection(c.start, c.end, c.kind, c.text, c.detector) for c in kept]
