from types import SimpleNamespace

import pytest

from boxed.detect import DetectConfig, Detection, detect
from boxed.detect.ner import GlinerDetector


class FixedNer:
    """NER stub returning given spans, to test how detect() merges NER with rules."""

    def __init__(self, spans):
        self.spans = spans

    def find(self, text):
        return [Detection(s, e, kind, text[s:e], "ner:stub") for s, e, kind in self.spans]


def found(text, level=2, ner=None):
    return [(d.kind, d.text) for d in detect(text, level=level, ner=ner)]


def test_ner_respects_level():
    ner = [FixedNer([(0, 11, "PERSON")])]
    assert found("Ivan Petrov signed", level=1, ner=ner) == [("PERSON", "Ivan Petrov")]
    assert found("Ivan Petrov signed", level=0, ner=ner) == []


def test_rules_win_over_ner_on_overlap():
    text = "write ivan.petrov@acme.com now"
    ner = [FixedNer([(6, 26, "PERSON")])]  # the characters of the email: they belong to the rule
    assert found(text, ner=ner) == [("EMAIL", "ivan.petrov@acme.com")]
    assert found(text, ner=[FixedNer([(8, 20, "PERSON")])]) == [("EMAIL", "ivan.petrov@acme.com")]  # inside it


@pytest.mark.parametrize(
    "text, span, kind, kept",
    [
        # the model takes the VAT number for a part of the company: the rule keeps the number, the name stays a name
        ("ООО Ромашка DE811569869", "ООО Ромашка DE811569869", "ORG", [("ORG", "ООО Ромашка"), ("VAT_ID", "DE811569869")]),
        ("Supplier Acme GmbH DE811569869 sent", "Acme GmbH DE811569869", "ORG", [("ORG", "Acme GmbH"), ("VAT_ID", "DE811569869")]),
        # a rule match in the middle or at the start: both sides stay
        ("see Ivan ivan@acme.com Petrov", "Ivan ivan@acme.com Petrov", "PERSON", [("PERSON", "Ivan"), ("EMAIL", "ivan@acme.com"), ("PERSON", "Petrov")]),
        ("see ivan@acme.com Ivan Petrov", "ivan@acme.com Ivan Petrov", "PERSON", [("EMAIL", "ivan@acme.com"), ("PERSON", "Ivan Petrov")]),
        # two rule matches in one span
        (
            "Ivan 4111 1111 1111 1111 Petrov ivan@acme.com",
            "Ivan 4111 1111 1111 1111 Petrov ivan@acme.com",
            "PERSON",
            [("PERSON", "Ivan"), ("CARD", "4111 1111 1111 1111"), ("PERSON", "Petrov"), ("EMAIL", "ivan@acme.com")],
        ),
        # what is left holds no word: a bracket, a single letter, digits
        ("a (ivan@acme.com) b", "(ivan@acme.com)", "PERSON", [("EMAIL", "ivan@acme.com")]),
        ("a J ivan@acme.com b", "J ivan@acme.com", "PERSON", [("EMAIL", "ivan@acme.com")]),
        ("a 12 ivan@acme.com b", "12 ivan@acme.com", "PERSON", [("EMAIL", "ivan@acme.com")]),
        # what is left is the label of the number, no name: GLiNER takes "IBAN DE89 ..." for an organization (31 times in 740
        # documents of company, IBAN, VAT lines)
        ("Acme GmbH, IBAN DE89 3704 0044 0532 0130 00", "IBAN DE89 3704 0044 0532 0130 00", "ORG", [("IBAN", "DE89 3704 0044 0532 0130 00")]),
        ("Контрагент ИНН 7707083893", "ИНН 7707083893", "ORG", [("INN", "7707083893")]),
        ("Employee SSN 512-34-7890", "SSN 512-34-7890", "PERSON", [("SSN", "512-34-7890")]),
        ("Customer passport 4510 123456", "passport 4510 123456", "PERSON", [("PASSPORT", "4510 123456")]),
        ("Seller VAT ID DE811569869", "VAT ID DE811569869", "ORG", [("VAT_ID", "DE811569869")]),
        # a label beside a name stays in the part of the name
        (
            "ООО Ромашка IBAN DE89 3704 0044 0532 0130 00",
            "ООО Ромашка IBAN DE89 3704 0044 0532 0130 00",
            "ORG",
            [("ORG", "ООО Ромашка IBAN"), ("IBAN", "DE89 3704 0044 0532 0130 00")],
        ),
    ],
)
def test_a_name_model_span_is_cut_around_a_rule_match_and_what_is_left_stays_a_name(text, span, kind, kept):
    assert found(text, level=2, ner=[FixedNer(spans_of(text, (span, kind)))]) == kept


def test_the_part_of_a_name_model_span_that_is_allowed_stays_in_clear():
    text = "ООО Ромашка DE811569869"
    ner = [FixedNer([(0, len(text), "ORG")])]
    assert [(d.kind, d.text) for d in detect(text, 2, DetectConfig(allow={"ООО Ромашка"}), ner=ner)] == [("VAT_ID", "DE811569869")]
    assert [(d.kind, d.text) for d in detect(text, 2, DetectConfig(allow={text}), ner=ner)] == [("VAT_ID", "DE811569869")]


def test_the_part_of_a_name_model_span_is_found_at_its_own_place_in_the_text():
    text = "x ООО Ромашка  DE811569869 y"
    ner = [FixedNer([(2, len(text) - 2, "ORG")])]
    assert [(d.start, d.end, d.kind) for d in detect(text, 2, ner=ner)] == [(2, 13, "ORG"), (15, 26, "VAT_ID")]


def test_natasha_keeps_the_company_next_to_a_vat_number():
    pytest.importorskip("natasha")
    from boxed.detect.ner import NatashaDetector

    ner = [NatashaDetector()]
    for text in ("ООО Ромашка DE811569869", "Поставщик ООО Ромашка DE811569869 выставил счёт.", "Поставщик ООО Ромашка (VAT: DE811569869) выставил счёт."):
        masked = {(d.kind, d.text) for d in detect(text, level=2, ner=ner)}
        assert ("VAT_ID", "DE811569869") in masked, text
        assert any(kind == "ORG" and "Ромашка" in value for kind, value in masked), text


class FakeGliner:
    def predict_entities(self, text, labels, threshold):
        assert set(labels) == {"person", "organization"}
        return [
            {"start": 0, "end": 11, "text": "Ivan Petrov", "label": "person", "score": 0.95},
            {"start": 21, "end": 30, "text": "Acme Corp", "label": "organization", "score": 0.9},
            {"start": 34, "end": 40, "text": "London", "label": "location", "score": 0.9},
        ]


def test_gliner_mapping_with_fake_model():
    text = "Ivan Petrov works at Acme Corp in London"
    det = GlinerDetector(model=FakeGliner())
    assert [(d.kind, d.text) for d in det.find(text)] == [("PERSON", "Ivan Petrov"), ("ORG", "Acme Corp")]


def test_natasha_person_ru():
    pytest.importorskip("natasha")
    from boxed.detect.ner import NatashaDetector

    assert ("PERSON", "Иван Петров") in found("Иван Петров подписал акт", level=1, ner=[NatashaDetector()])


def test_natasha_org_ru():
    pytest.importorskip("natasha")
    from boxed.detect.ner import NatashaDetector

    assert ("ORG", "Сбербанк") in found("Сделку одобрил Сбербанк вчера", ner=[NatashaDetector()])


def test_gliner_person_en():
    pytest.importorskip("gliner")
    assert ("PERSON", "Ivan Petrov") in found("Ivan Petrov signed the contract", level=1, ner=[GlinerDetector()])


def test_gliner_finds_a_name_after_many_words():
    pytest.importorskip("gliner")
    filler = " ".join(["The quarterly report covers revenue, costs and plans for the next period."] * 60)
    text = filler + " Please call John Smith tomorrow."  # the model alone reads only its first 384 tokens
    assert ("PERSON", "John Smith") in found(text, level=1, ner=[GlinerDetector()])


def test_config_ner_ru_masks_names():
    pytest.importorskip("natasha")
    from boxed.config import ProjectConfig, to_detect_config
    from boxed.mask import MarkerMap, mask_text

    masked, _ = mask_text("Иван Петров подписал акт", MarkerMap(), level=1, config=to_detect_config(ProjectConfig(ner=["ru"])))
    assert masked == "[PERSON_1] подписал акт"


def test_config_ner_unknown_name_rejected(tmp_path):
    from boxed.config import load_config

    (tmp_path / "boxed.toml").write_text('[boxed]\nner = ["xx"]\n')
    with pytest.raises(ValueError, match="ner"):
        load_config(tmp_path)


# role labels and Cyrillic-only Natasha spans


def spans_of(text, *items):
    """(start, end, label) for each (substring, label) in order of appearance."""
    return [(text.index(s), text.index(s) + len(s), label) for s, label in items]


class StubGliner:
    """GLiNER stub returning given spans, so no model is downloaded. The spans are offsets in the whole text; for a text
    longer than one window, pass it as `text` and each call answers with the spans that lie inside the window it is given."""

    def __init__(self, spans, text=None):
        from boxed.detect.ner import _windows

        self.spans = spans
        self.offsets = [offset for offset, _ in _windows(text)] if text is not None else [0]
        self.calls = 0

    def predict_entities(self, text, labels, threshold):
        offset = self.offsets[min(self.calls, len(self.offsets) - 1)]
        self.calls += 1
        return [
            {"start": s - offset, "end": e - offset, "text": text[s - offset : e - offset], "label": label, "score": 0.9}
            for s, e, label in self.spans
            if offset <= s and e - offset <= len(text)
        ]


class StubTagger:
    """Natasha tagger stub (text -> markup with spans), so no model is loaded."""

    def __init__(self, spans):
        self.spans = spans

    def __call__(self, text):
        return SimpleNamespace(spans=self.spans)


ROLE_LABELS = [
    "Speaker 1",
    "Спикер 2",
    "Participant A",
    "Клиент 3",
    "SPEAKER_00",
    "Speaker #1",
    "Спикер №2",
    "Участница 3",
    "Speaker 1:",
    "Patient 1",
    "Пациент 2",
    "Пациентка 3",
    "Doctor A",
    "Врач 1",
    "Employee 4",
    "Студент А",
    "Witness 2",
    "Свидетель 1",
]


@pytest.mark.parametrize("label", ROLE_LABELS)
def test_gliner_drops_a_person_span_that_is_a_role_label(label):
    text = f"{label} says hello"
    det = GlinerDetector(model=StubGliner(spans_of(text, (label, "person"))))
    assert det.find(text) == []


def test_gliner_keeps_names_next_to_role_labels():
    text = "Speaker 1: Ivan Petrov asked Client Ivan and Agent Smith"
    spans = spans_of(text, ("Speaker 1", "person"), ("Ivan Petrov", "person"), ("Client Ivan", "person"), ("Agent Smith", "person"))
    det = GlinerDetector(model=StubGliner(spans))
    assert [d.text for d in det.find(text)] == ["Ivan Petrov", "Client Ivan", "Agent Smith"]


def test_role_labels_stay_visible_and_names_are_masked():
    text = "Speaker 1: write to Ivan Petrov"
    ner = [GlinerDetector(model=StubGliner(spans_of(text, ("Speaker 1", "person"), ("Ivan Petrov", "person"))))]
    assert found(text, level=1, ner=ner) == [("PERSON", "Ivan Petrov")]


@pytest.mark.parametrize("label", ROLE_LABELS)
def test_natasha_drops_a_person_span_that_is_a_role_label(label):
    pytest.importorskip("natasha")
    from boxed.detect.ner import NatashaDetector

    text = f"{label} сказал привет"
    det = NatashaDetector(tagger=StubTagger(spans_of(text, (label, "PER"))))
    assert det.find(text) == []


def test_natasha_keeps_person_spans_with_a_cyrillic_letter_only():
    pytest.importorskip("natasha")
    from boxed.detect.ner import NatashaDetector

    text = "John Smith и Иван Петров подписали, а Иван Smith и Петров K нет"
    spans = spans_of(text, ("John Smith", "PER"), ("Иван Петров", "PER"), ("Иван Smith", "PER"), ("Петров K", "PER"))
    det = NatashaDetector(tagger=StubTagger(spans), cyrillic_only=True)
    assert [(d.kind, d.text) for d in det.find(text)] == [("PERSON", "Иван Петров"), ("PERSON", "Иван Smith"), ("PERSON", "Петров K")]


def test_natasha_keeps_latin_persons_unless_asked_not_to():
    pytest.importorskip("natasha")
    from boxed.detect.ner import NatashaDetector

    text = "John Smith signed the contract"
    det = NatashaDetector(tagger=StubTagger(spans_of(text, ("John Smith", "PER"))))
    assert [(d.kind, d.text) for d in det.find(text)] == [("PERSON", "John Smith")]


@pytest.fixture
def built_detectors(monkeypatch):
    """boxed.toml ner = [...] with stand-ins for both detectors; each remembers the arguments it was built with."""
    from boxed import config
    from boxed.detect import ner

    built = []

    class FakeNatasha:
        def __init__(self, **kwargs):
            built.append(("ru", kwargs))

    class FakeGliner:
        def __init__(self, **kwargs):
            built.append(("en", kwargs))

    monkeypatch.setattr(ner, "NatashaDetector", FakeNatasha)
    monkeypatch.setattr(ner, "GlinerDetector", FakeGliner)
    config._ner_detectors.cache_clear()
    yield built
    config._ner_detectors.cache_clear()


@pytest.mark.parametrize(
    "names,expected",
    [
        (["ru"], [("ru", {"cyrillic_only": False})]),
        (["ru", "en"], [("ru", {"cyrillic_only": True}), ("en", {})]),
        (["en", "ru"], [("en", {}), ("ru", {"cyrillic_only": True})]),
    ],
)
def test_config_drops_latin_natasha_persons_only_when_the_english_model_also_runs(built_detectors, names, expected):
    from boxed.config import ProjectConfig, to_detect_config

    to_detect_config(ProjectConfig(ner=names))
    assert built_detectors == expected


def test_natasha_keeps_organizations_in_latin_script():
    pytest.importorskip("natasha")
    from boxed.detect.ner import NatashaDetector

    text = "Сделку одобрил Google и ООО Ромашка"
    det = NatashaDetector(tagger=StubTagger(spans_of(text, ("Google", "ORG"), ("ООО Ромашка", "ORG"))))
    assert [(d.kind, d.text) for d in det.find(text)] == [("ORG", "Google"), ("ORG", "ООО Ромашка")]


@pytest.mark.parametrize("level", [2, 3, 4])
@pytest.mark.parametrize("text,name", [("Сделку одобрил Тинькофф Банк 24 вчера", "Тинькофф Банк 24"), ("Call Банк 24 now", "Банк 24")])
def test_a_ner_organization_with_a_number_in_it_stays_whole(text, name, level):
    # the number kinds are searched last, in what rules and NER left free, so they never cut or beat a NER span
    ner = [FixedNer(spans_of(text, (name, "ORG")))]
    assert found(text, level=level, ner=ner) == [("ORG", name)]


# months that a name model takes for people

# (text, the month as it stands in it, the date the number rules read around it). Only a date that no first name followed by a
# number can be: a day before the month ("5 March", "5 марта"), or month, day and year ("March 5, 2026").
MONTH_DATES = [
    ("Due 5 March 2026", "March", "5 March 2026"),
    ("Due 5 MARCH 2026", "MARCH", "5 MARCH 2026"),
    ("Due 5 march 2026", "march", "5 march 2026"),
    ("Due March 5, 2026", "March", "March 5, 2026"),
    ("Due March 5 2026", "March", "March 5 2026"),
    ("Due March 5th, 2026", "March", "March 5th, 2026"),
    ("Due Oct. 21, 2026", "Oct.", "Oct. 21, 2026"),
    ("Due 5th of March", "March", "5th of March"),
    ("Due 5 Mar 2026", "Mar", "5 Mar 2026"),
    ("Due 5-Mar-2026", "Mar", "5-Mar-2026"),
    ("Due 5 Sept. 2026", "Sept.", "5 Sept. 2026"),
    ("Due 5 May 2026", "May", "5 May 2026"),
    ("Срок 5 марта 2026 года", "марта", "5 марта 2026"),
    ("Срок 5 МАРТА 2026", "МАРТА", "5 МАРТА 2026"),
    ("Срок 5 мая 2026", "мая", "5 мая 2026"),
    ("Срок 21-23 октября 2026", "октября", "21-23 октября 2026"),
    ("Срок 5 авг. 2026", "авг.", "5 авг. 2026"),
]


@pytest.mark.parametrize("text,month,date", MONTH_DATES)
def test_gliner_drops_a_person_span_that_is_a_month_in_a_date(text, month, date):
    det = GlinerDetector(model=StubGliner(spans_of(text, (month, "person"))))
    assert det.find(text) == []


@pytest.mark.parametrize("text,month,date", MONTH_DATES)
def test_natasha_drops_a_person_span_that_is_a_month_in_a_date(text, month, date):
    pytest.importorskip("natasha")
    from boxed.detect.ner import NatashaDetector

    det = NatashaDetector(tagger=StubTagger(spans_of(text, (month, "PER"))))
    assert det.find(text) == []


@pytest.mark.parametrize("text,month,date", MONTH_DATES)
def test_a_month_taken_for_a_person_leaves_the_date_whole(text, month, date):
    ner = [GlinerDetector(model=StubGliner(spans_of(text, (month, "person"))))]
    assert found(text, level=3, ner=ner) == [("DATE", date)]
    assert found(text, level=2, ner=ner) == []  # a date is found from level 3 on, and the month is nobody's name


def test_a_month_is_found_in_its_date_far_from_the_start_of_a_long_line():
    text = "x " * 5_000 + "Due 5 March 2026" + " y" * 5_000
    det = GlinerDetector(model=StubGliner(spans_of(text, ("March", "person")), text))
    assert det.find(text) == []


@pytest.mark.parametrize(
    "text,name",
    [
        ("April said hello", "April"),
        ("Dear June, thanks", "June"),
        ("Call May tomorrow", "May"),
        ("Thanks, August.", "August"),
        ("Jan will call you", "Jan"),
        ("Due in March", "March"),  # no day, no year: nothing makes it a date, so the model's word stands
        ("Звонил Июнь", "Июнь"),
        ("Спасибо, Май.", "Май"),
        ("Dear march, thanks", "march"),
    ],
)
def test_a_month_name_with_no_date_around_it_keeps_its_person(text, name):
    # April, May, June, August, Jan and the like are names: only a date makes them months
    gliner = GlinerDetector(model=StubGliner(spans_of(text, (name, "person"))))
    assert [(d.kind, d.text) for d in gliner.find(text)] == [("PERSON", name)]


def test_a_person_whose_name_holds_a_month_is_kept_next_to_a_date():
    text = "June Carter signed on 5 March 2026 and August Petrov agreed"
    spans = spans_of(text, ("June Carter", "person"), ("March", "person"), ("August Petrov", "person"))
    det = GlinerDetector(model=StubGliner(spans))
    assert [d.text for d in det.find(text)] == ["June Carter", "August Petrov"]


# A first name before a number reads as "Month N" to the number rules, but it is a person: real GLiNER takes "Марта" in
# "Позвонила Марта 5 раз" and "Jan" in "Meeting with Jan 2 days ago" for people. Neither a month with a day only, nor with a
# year only, nor with any other number is a date no name can be.
NAMES_BEFORE_NUMBERS = [
    ("Позвонила Марта 5 раз и ушла.", "Марта"),
    ("Звонила Мая 3 раза.", "Мая"),
    ("Мая 12 лет, живёт в Москве.", "Мая"),
    ("Спросите у Августа 12 вопросов.", "Августа"),
    ("Meeting with Jan 2 days ago.", "Jan"),
    ("Hi May 3 people are coming, May will host.", "May"),
    ("Call August 20 minutes before.", "August"),
    ("Ask Mar 5 times, said Mar.", "Mar"),
    ("April 5 is the deadline, please ask April.", "April"),
    ("June 25 years old, lives in London.", "June"),
    ("Report for June 2026 is ready.", "June"),
    ("Срок март 2026", "март"),  # month and year only
    ("Dec 2026 numbers", "Dec"),
]


@pytest.mark.parametrize("text,name", NAMES_BEFORE_NUMBERS)
def test_gliner_keeps_a_first_name_before_a_number(text, name):
    det = GlinerDetector(model=StubGliner(spans_of(text, (name, "person"))))
    assert [(d.kind, d.text) for d in det.find(text)] == [("PERSON", name)]


@pytest.mark.parametrize("text,name", NAMES_BEFORE_NUMBERS)
def test_natasha_keeps_a_first_name_before_a_number(text, name):
    pytest.importorskip("natasha")
    from boxed.detect.ner import NatashaDetector

    det = NatashaDetector(tagger=StubTagger(spans_of(text, (name, "PER"))))
    assert [(d.kind, d.text) for d in det.find(text)] == [("PERSON", name)]


@pytest.mark.parametrize("text,name", NAMES_BEFORE_NUMBERS)
@pytest.mark.parametrize("level", [1, 2])
def test_a_first_name_before_a_number_is_still_masked(text, name, level):
    ner = [GlinerDetector(model=StubGliner(spans_of(text, (name, "person"))))]
    assert ("PERSON", name) in found(text, level=level, ner=ner)


# A name never holds a pipe or a tab. Real GLiNER takes "bob | hunter22x", two cells of a table, for one person; a rule that finds the
# password in the second cell then drops the whole span, and the login of the first goes unmasked. Cut at the cells, each is its own.


def test_gliner_cuts_a_span_that_crosses_the_cells_of_a_table():
    text = "| VPN | admin | hunter22x |"
    det = GlinerDetector(model=StubGliner(spans_of(text, ("admin | hunter22x", "person"))))
    assert [(d.kind, d.text, d.start, d.end) for d in det.find(text)] == [("PERSON", "admin", 8, 13), ("PERSON", "hunter22x", 16, 25)]


def test_natasha_cuts_a_span_that_crosses_the_cells_of_a_tsv_row():
    pytest.importorskip("natasha")
    from boxed.detect.ner import NatashaDetector

    text = "Логин\tПароль\nИван\tXk9#mQ2v"
    det = NatashaDetector(tagger=StubTagger(spans_of(text, ("Иван\tXk9#mQ2v", "PER"))))
    assert [(d.kind, d.text) for d in det.find(text)] == [("PERSON", "Иван"), ("PERSON", "Xk9#mQ2v")]


def test_a_span_with_a_pipe_in_blanks_only_is_dropped_and_one_without_stays_whole():
    text = "| Ivan Petrov | |"
    spans = spans_of(text, ("Ivan Petrov | ", "person"))
    assert [d.text for d in GlinerDetector(model=StubGliner(spans)).find(text)] == ["Ivan Petrov"]
    plain = "Ivan Petrov signed"
    assert [d.text for d in GlinerDetector(model=StubGliner(spans_of(plain, ("Ivan Petrov", "person")))).find(plain)] == ["Ivan Petrov"]


@pytest.mark.parametrize(
    "table",
    ["| Логин | Пароль |\n|---|---|\n| bob | hunter22x |", "Логин\tПароль\nbob\thunter22x"],
)
def test_the_login_next_to_a_password_keeps_its_mask_when_the_model_took_both_for_one_person(table):
    cut = "bob | hunter22x" if "|" in table else "bob\thunter22x"
    ner = [GlinerDetector(model=StubGliner(spans_of(table, (cut, "person"))))]
    assert found(table, level=2, ner=ner) == [("PERSON", "bob"), ("SECRET", "hunter22x")]


class TruncatingGliner:
    """Like the real model: it reads only the first `limit` words of a text and finds "John Smith" there."""

    def __init__(self, limit=384):
        self.limit = limit
        self.calls = []

    def predict_entities(self, text, labels, threshold):
        self.calls.append(text)
        import re

        spans = [m.end() for m in re.finditer(r"\S+", text)][: self.limit]
        end_of_seen = spans[-1] if spans else 0
        out, start = [], text.find("John Smith")
        while start != -1:
            if start + 10 <= end_of_seen:
                out.append({"start": start, "end": start + 10, "text": "John Smith", "label": "person", "score": 0.9})
            start = text.find("John Smith", start + 1)
        return out


FILLER = " ".join(["The quarterly report covers revenue, costs and plans for the next period."] * 60)  # about 720 words


@pytest.mark.parametrize("where", ["end", "middle", "start"])
def test_gliner_reads_a_long_text_in_windows(where):
    text = {"end": FILLER + " Please call John Smith tomorrow.",
            "middle": FILLER[: len(FILLER) // 2] + " John Smith " + FILLER[len(FILLER) // 2 :],
            "start": "Please call John Smith tomorrow. " + FILLER}[where]
    model = TruncatingGliner()
    hits = [d for d in GlinerDetector(model=model).find(text) if d.kind == "PERSON"]
    assert [(d.text, text[d.start : d.end]) for d in hits] == [("John Smith", "John Smith")]  # once, with true offsets
    assert all(len(chunk.split()) <= 384 for chunk in model.calls)


def test_gliner_short_text_is_one_call():
    model = TruncatingGliner()
    GlinerDetector(model=model).find("Please call John Smith tomorrow.")
    assert model.calls == ["Please call John Smith tomorrow."]
