"""Optional named-entity detectors for people and organizations (extras ner-ru and ner-en)."""

import bisect
import re
import weakref
from typing import Protocol

from . import Detection
from .numbers import _MONTH_NAME, number_candidates

DEFAULT_GLINER_MODEL = "urchade/gliner_multi_pii-v1"

# A transcript or chat tells its speakers apart by a role word and a number or one letter ("Speaker 1", "Спикер 2",
# "Participant A"): that is a label, not a person. Nominative only, so a surname built on a role word is never cut.
_ROLES_EN = (
    "speaker|participant|interviewer|interviewee|respondent|moderator|host|guest|client|customer|user|agent|caller|operator|person"
    "|patient|doctor|nurse|employee|candidate|student|teacher|witness|applicant|member|attendee|presenter|reporter|buyer|seller|visitor"
)
_ROLES_RU = (
    "спикер|участник|участница|респондент|респондентка|модератор|ведущий|ведущая|гость|клиент|клиентка|заказчик|пользователь"
    "|оператор|собеседник|собеседница|абонент|менеджер|сотрудник|сотрудница|докладчик|интервьюер|говорящий"
    "|пациент|пациентка|врач|кандидат|студент|студентка|преподаватель|свидетель|заявитель|посетитель|покупатель|продавец|работник"
    "|ученик|ученица"
)
_ROLE_LABEL = re.compile(rf"(?i)(?:{_ROLES_EN}|{_ROLES_RU})(?:[\s_#№\-]*\d{{1,3}}|[\s_#№\-]+[^\W\d_])")
_CYRILLIC = re.compile(r"[\u0400-\u04ff]")


def _is_role_label(d: Detection) -> bool:
    return d.kind == "PERSON" and _ROLE_LABEL.fullmatch(d.text.strip().rstrip(":")) is not None


_CELL_EDGE = re.compile(r"[|\t]")


def _by_cells(found: list[Detection]) -> list[Detection]:
    """A name never holds a pipe or a tab. A model that takes "bob | hunter22x", two cells of a table, for one person gives a rule
    that finds the password in the second cell a span to drop whole, and the login of the first goes unmasked. Cut at the cells,
    each part is its own span."""
    out = []
    for d in found:
        if not _CELL_EDGE.search(d.text):
            out.append(d)
            continue
        at = d.start
        for part in _CELL_EDGE.split(d.text):
            body = part.strip()
            if body:
                start = at + len(part) - len(part.lstrip())
                out.append(Detection(start, start + len(body), d.kind, body, d.detector))
            at += len(part) + 1
    return out


_MONTH = re.compile(_MONTH_NAME)
_DAY_AND_YEAR = re.compile(r"\W*\d{1,2}(?!\d)(?:st|nd|rd|th)?,?\s+[12]\d{3}(?!\d)")  # what follows the month in "March 5, 2026"


def _without_months_in_dates(found: list[Detection], text: str) -> list[Detection]:
    """A month name that the model took for a person, in a date that no first name followed by a number can be, is a month: left
    as a person it would cut the date in two. Such a date has a day before the month ("5 March 2026", "5 марта") or is month,
    day and year ("March 5, 2026"). "Марта 5 раз" and "Jan 2 days" read as "March 5" and "Jan 2" to the number rules, and
    "март 2026" as a month and a year, but there the person stays: April, May, June, August, Jan and Марта are names. The dates
    come from one pass over the text, made only when there is a month to ask about."""
    months = [d for d in found if d.kind == "PERSON" and _MONTH.fullmatch(d.text.strip())]
    if not months:
        return found
    dates = [(c.start, c.end) for c in number_candidates(text) if c.kind == "DATE"]  # in text order, without overlaps
    starts = [start for start, _ in dates]

    def in_a_date(d: Detection) -> bool:
        start, end = d.start + len(d.text) - len(d.text.lstrip()), d.end - (len(d.text) - len(d.text.rstrip()))
        i = bisect.bisect_right(starts, start)  # the last date that starts at or before the month
        if not (i > 0 and end <= dates[i - 1][1]):
            return False
        return dates[i - 1][0] < start or _DAY_AND_YEAR.fullmatch(text, end, dates[i - 1][1]) is not None

    gone = {id(d) for d in months if in_a_date(d)}
    return [d for d in found if id(d) not in gone]


class NerDetector(Protocol):
    def find(self, text: str) -> list[Detection]: ...


class NatashaDetector:
    """Russian NER (Natasha/Slovnet): PER -> PERSON, ORG -> ORG. `tagger` can be injected for tests.

    With `cyrillic_only` a person without a Cyrillic letter is dropped, to be left to GLiNER: set it only when GLiNER also runs,
    otherwise no one would find a Latin name."""

    KINDS = {"PER": "PERSON", "ORG": "ORG"}

    def __init__(self, tagger: object | None = None, *, cyrillic_only: bool = False) -> None:
        from natasha import Doc, NewsEmbedding, NewsNERTagger, Segmenter

        self._doc = Doc
        self._segmenter = Segmenter()
        self._tagger = NewsNERTagger(NewsEmbedding()) if tagger is None else tagger
        self._cyrillic_only = cyrillic_only

    def find(self, text: str) -> list[Detection]:
        doc = self._doc(text)
        doc.segment(self._segmenter)
        doc.tag_ner(self._tagger)
        found = [
            Detection(s.start, s.stop, self.KINDS[s.type], text[s.start : s.stop], "ner:natasha")
            for s in doc.spans
            if s.type in self.KINDS
        ]
        latin_ok = not self._cyrillic_only
        kept = [d for d in _by_cells(found) if not _is_role_label(d) and (latin_ok or d.kind != "PERSON" or _CYRILLIC.search(d.text))]
        return _without_months_in_dates(kept, text)


_loaded = weakref.WeakSet()  # the GLiNER detectors that are alive


def words_kept() -> bool:
    """Has a GLiNER detector that is alive left the words of a text in the cache of its tokenizer, because the library gave it no
    way to empty it? A program that stays up and can end instead (the native host) does so after the answer."""
    return any(detector.kept_words for detector in _loaded)


# The GLiNER model reads at most 384 of its tokens (words and punctuation marks) and silently drops the rest, so a name after
# the first few hundred words of a long text would never be found. Texts are read in windows of WINDOW_WORDS words that
# overlap by OVERLAP_WORDS, so a name cut by one window's edge lies whole in the next.
WINDOW_WORDS = 200
OVERLAP_WORDS = 40
_WORD = re.compile(r"\S+")


def _windows(text: str):
    """(offset, window) pairs that cover the text; a text of at most WINDOW_WORDS words is one window, the text itself."""
    words = [m.span() for m in _WORD.finditer(text)]
    if len(words) <= WINDOW_WORDS:
        yield 0, text
        return
    i = 0
    while True:
        j = min(i + WINDOW_WORDS, len(words))
        start, end = words[i][0], words[j - 1][1]
        yield start, text[start:end]
        if j == len(words):
            return
        i = j - OVERLAP_WORDS


class GlinerDetector:
    """GLiNER PII model: person -> PERSON, organization -> ORG. `model` can be injected for tests.

    The tokenizer of the model caches every distinct word it splits - a name, a whole API key - in native memory that Python
    cannot reach, for as long as the tokenizer lives. find() empties that cache after every text, so a program that stays up
    (the native host for the length of a panel, the MCP server for a session) keeps none of them."""

    LABELS = {"person": "PERSON", "organization": "ORG"}

    def __init__(self, model_id: str = DEFAULT_GLINER_MODEL, threshold: float = 0.5, model: object | None = None) -> None:
        if model is None:
            from gliner import GLiNER

            model = GLiNER.from_pretrained(model_id)
        self._model = model
        self._threshold = threshold
        self.kept_words = False  # set when the cache could not be emptied: see words_kept
        _loaded.add(self)

    def _empty_cache(self) -> None:
        """The call is a private one of the tokenizers library (there is no public one): if the library no longer has it, or it
        fails, the words stay where they are and the detector says so."""
        try:
            self._model.data_processor.transformer_tokenizer.backend_tokenizer.model._clear_cache()
        except Exception:
            self.kept_words = True

    def find(self, text: str) -> list[Detection]:
        raw: list[Detection] = []
        try:
            for offset, window in _windows(text):
                for e in self._model.predict_entities(window, list(self.LABELS), threshold=self._threshold):
                    if e["label"] in self.LABELS:
                        start, end, kind = offset + e["start"], offset + e["end"], self.LABELS[e["label"]]
                        raw.append(Detection(start, end, kind, text[start:end], "ner:gliner"))
        finally:
            self._empty_cache()  # also when reading the text failed half way: the words of the part that was read are in the cache
        # windows overlap, so the same piece can come twice: merge after the cut at cells, where the pieces are final
        pieces = list({(d.start, d.end, d.kind): d for d in _by_cells(raw)}.values())
        return _without_months_in_dates([d for d in pieces if not _is_role_label(d)], text)
