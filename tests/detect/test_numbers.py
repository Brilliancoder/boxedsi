"""Level 3 kinds: amounts, percentages, dates and numbers (all become placeholders, none is shifted)."""

import os
import re
import string
import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from boxed.detect import KINDS_BY_LEVEL, PRIORITY, DetectConfig, Detection, detect
from boxed.detect.numbers import KINDS, number_candidates
from boxed.detect.patterns import Candidate
from boxed.mask import BOXED_KINDS, MarkerMap, mask_text, restore


def found(text):
    return [(c.kind, c.text) for c in number_candidates(text)]


def kinds(text):
    return [c.kind for c in number_candidates(text)]


def visible(text):
    """The text with every candidate cut out: what a model would still see."""
    out, pos = [], 0
    for c in number_candidates(text):
        out.append(text[pos : c.start])
        pos = c.end
    out.append(text[pos:])
    return "".join(out)


# MONEY


@pytest.mark.parametrize(
    "money",
    ["$1,200.50", "1 200 руб.", "EUR 300", "300 €", "5 млн рублей", "$1.2M", "₽ 15 000", "12 тыс. руб."],
)
def test_money_examples_are_found_with_their_exact_span(money):
    assert found(money) == [("MONEY", money)]
    assert found(f"paid {money} yesterday") == [("MONEY", money)]


@pytest.mark.parametrize(
    "money",
    [
        "£45",
        "¥1000",
        "100 USD",
        "USD100",
        "15 000 ₽",
        "₸500",
        "2 500 грн",
        "10 евро",
        "50 dollars",
        "3 $",
        "99 cents",
        "50 коп.",
        "100р.",
        "5000руб",
        "1 234,56 ₽",
        "€1.234,56",
        "10 usd",
        "2 000 у.е.",
        "3 млн USD",
        "2.5 млрд ₽",
        "1,5 миллиона долларов",
        "$5k",
        "5k USD",
        "€3B",
        "$2 bn",
        "$100 USD",
        "-$5",
        "-300 €",
        "+$20",
    ],
)
def test_more_money_shapes(money):
    assert found(f"({money})") == [("MONEY", money)]


@pytest.mark.parametrize("space", ["\u00a0", "\u2009", "\u202f"])
def test_money_with_no_break_and_thin_spaces(space):
    amount = f"1{space}200{space}руб."
    assert found(f"cost {amount} net") == [("MONEY", amount)]


def test_money_stops_before_the_end_of_the_sentence():
    assert found("It costs $1,200.") == [("MONEY", "$1,200")]
    assert found("Итого 300 €, без НДС") == [("MONEY", "300 €")]


def test_rubles_and_kopecks_are_two_amounts():
    assert found("5 руб. 30 коп.") == [("MONEY", "5 руб."), ("MONEY", "30 коп.")]


@pytest.mark.parametrize(
    "text",
    [
        "10 kg",
        "5 m long",
        "in 2026",
        "EUR is the euro code",
        "EURO 300",
        "AMD Ryzen 5",
        "a $ sign",
        "5 рублевых",
        "100 копать",
        "$1.2.3",
        "1.2.3 руб.",
        "v2 USD",
        "abc300€",
        "300 тыс",
    ],
)
def test_not_money(text):
    assert "MONEY" not in kinds(text)


# PERCENT


@pytest.mark.parametrize(
    "percent",
    [
        "15%",
        "15 %",
        "12,5%",
        "0.5%",
        "1 200,5 %",
        "+3%",
        "-3,5%",
        "7\uff05",
        "5 процентов",
        "1 процент",
        "2 процента",
        "20 percent",
        "15 per cent",
        "3 п.п.",
        "1,5 п. п.",
        "2 percentage points",
    ],
)
def test_percent_shapes(percent):
    assert found(f"up {percent} on") == [("PERCENT", percent)]


def test_percent_stops_before_the_end_of_the_sentence():
    assert found("Growth was 15%.") == [("PERCENT", "15%")]
    assert found("from 10 to 15%, then") == [("NUMBER", "10"), ("PERCENT", "15%")]
    assert found("10-15%") == [("PERCENT", "10-15%")]


@pytest.mark.parametrize("text", ["15 percentile", "5 процентный", "% of 5", "abc15%"])
def test_not_percent(text):
    assert "PERCENT" not in kinds(text)


# DATE


@pytest.mark.parametrize(
    "date",
    [
        "2026-10-21",
        "2026-10-21T14:30:00Z",
        "2026-10-21T14:30",
        "2026-10-21 14:30",
        "2026-10-21 14:30:00",
        "2026-10-21T14:30:00+03:00",
        "2026-10-21T14:30:00-0500",
        "2026-10-21T14:30:00.123456Z",
        "2026/10/21",
        "2026.10.21",
        "21.10.2026",
        "01.09.2026",
        "1.9.2026",
        "10.21.2026",
        "21.10.26",
        "21/10/2026",
        "10/21/2026",
        "1/5/26",
        "21-10-2026",
    ],
)
def test_numeric_dates(date):
    assert found(f"due {date} sharp") == [("DATE", date)]


@pytest.mark.parametrize(
    "date",
    [
        "21 октября 2026",
        "21 окт. 2026",
        "21 октября",
        "1 января 2027",
        "8 марта",
        "9 мая 2026",
        "5 июля 2026",
        "31 декабря 2026",
        "5 февр. 2026",
        "10 сент. 2026",
        "октябрь 2026",
        "октябре 2026",
        "Март 2026",
        "October 21, 2026",
        "October 21 2026",
        "October 21st, 2026",
        "Oct. 21",
        "Oct 21, 2026",
        "21 Oct 2026",
        "21st October 2026",
        "21st of October, 2026",
        "21 October",
        "October 2026",
        "Sept 2026",
        "May 5",
        "5 May 2026",
    ],
)
def test_dates_with_a_month_name(date):
    assert found(f"on {date} we") == [("DATE", date)]


@pytest.mark.parametrize(
    "date",
    ["Q3 2026", "Q3-2026", "Q3'26", "2026 Q3", "3 кв. 2026", "III кв. 2026", "3 квартал 2026", "4-м квартале 2026", "II квартал 2026"],
)
def test_quarters(date):
    assert found(f"in {date} we") == [("DATE", date)]


def test_a_date_stops_at_the_year():
    assert found("с 21 октября 2026 года по 5 ноября.") == [("DATE", "21 октября 2026"), ("DATE", "5 ноября")]
    assert found("signed 21.10.2026.") == [("DATE", "21.10.2026")]


@pytest.mark.parametrize(
    "text",
    [
        "13.13.2026",
        "32.10.2026",
        "2026-13-01",
        "2026-10-32",
        "2026-00-10",
        "13/13/2026",
        "1.2.3",
        "3.10.12",
        "10.0.0.1",
        "10.10.10.10",
        "21.10.2026.12",
        "Q3",
        "Q3 results",
        "30 кв. м",
        "кв. 2026",
        "Octopus 21",
        "Decimal 2026",
        "we may 5 times",
        "в мае",
        "21 октябрят",
        "v21.10.2026",
    ],
)
def test_not_a_date(text):
    assert "DATE" not in kinds(text)


# NUMBER


@pytest.mark.parametrize(
    "number",
    [
        "1500",
        "42",
        "00",
        "2026",
        "1 500",
        "1\u00a0500",
        "1\u2009500",
        "1\u202f500",
        "1,500",
        "1.500",
        "1'500",
        "1\u2019500",
        "12 345 678",
        "1,234,567",
        "1.234.567",
        "3.14",
        "0,5",
        "12.50",
        "1 500,25",
        "1,500.75",
        "1.500,75",
        "-42",
        "+15",
        "\u221215",
        "-1 500",
        "-3.14",
        "5 млн",
        "3 тыс.",
        "1,5 млрд",
        "2.5 million",
        "10 billion",
        "7 thousand",
    ],
)
def test_number_shapes(number):
    assert found(f"about {number} in total") == [("NUMBER", number)]


@pytest.mark.parametrize(
    "text,number",
    [
        ("order #123", "123"),
        ("\u21164521", "4521"),
        ("(1500)", "1500"),
        ("[42]", "42"),
        ("id=12345&x", "12345"),
        ("x=-15", "-15"),
        ("in 2026.", "2026"),
        ("costs 1,200.", "1,200"),
        ("5-15", "15"),
        ("100kg", "100"),
        ("2026г.", "2026"),
        ("50шт", "50"),
        ("10GB", "10"),
        ("15kg", "15"),
        ("21st", "21"),
        ("10x", "10"),
    ],
)
def test_the_number_alone_is_the_span(text, number):
    assert found(text) == [("NUMBER", number)]


@pytest.mark.parametrize(
    "text",
    [
        "v2",
        "x86_64",
        "abc123",
        "2fa",
        "1.2.3",
        "10.4.1",
        "3.11.2",
        "1.2.3.4",
        "10.0.0.1",
        "v1.2.3",
        "GPT-4o",
        "utf8 sha256 mp3 h264 k8s ec2 i18n",
        "24x7",
        "0x1F4",
        "abc_123",
        "a1b2",
        "12ab34",
        "7",
        "3 clients",
        "-7",
        "+7",
        "1, 2, 3",
        "1-2",
        "[EMAIL_1] [NUMBER_12] [LITERAL_3]",
    ],
)
def test_not_a_number(text):
    assert found(text) == []


def test_other_kinds_leave_no_number_behind():
    for text in ["$1,200.50", "15%", "21.10.2026", "5 млн рублей", "Q3 2026"]:
        assert len(found(text)) == 1, text


def test_a_group_glued_to_a_word_is_left_out_but_the_groups_before_it_are_masked():
    assert found("1 234 567abcdefgh and 12 345abcdefgh") == [("NUMBER", "1 234"), ("NUMBER", "12")]


@pytest.mark.parametrize(
    "text",
    ["5,10,15,20", "Ivan,1200,15,2026-10-21", "495-123-45-67", "10-20", "2026-13-01", "1 000 2 000 3 000", "100 200 300 400"],
)
def test_lists_and_ids_keep_no_digit_visible(text):
    assert not re.search(r"\d{2}", visible(text)), visible(text)


# the kinds and the levels


def at(text, level=3, config=None, ner=None):
    return [(d.kind, d.text) for d in detect(text, level=level, config=config, ner=ner)]


def test_the_number_kinds_belong_to_level_3_and_4_only():
    assert KINDS == {"MONEY", "PERCENT", "DATE", "NUMBER"}
    assert KINDS_BY_LEVEL[3] == KINDS_BY_LEVEL[4] == KINDS_BY_LEVEL[2] | KINDS
    assert not KINDS & KINDS_BY_LEVEL[2]
    assert KINDS <= BOXED_KINDS  # a marker-like [NUMBER_1] in a source file is a literal, as [EMAIL_1] is


def test_the_number_kinds_lose_a_tie_with_every_other_kind():
    assert [PRIORITY[kind] for kind in ("MONEY", "PERCENT", "DATE", "NUMBER")] == [101, 102, 103, 104]
    assert max(v for k, v in PRIORITY.items() if k not in KINDS) < 101


ALL_KINDS_TEXT = "Paid $1,200.50 (15%) on 21.10.2026, order 4521, contact ivan@acme.com, key AKIAIOSFODNN7EXAMPLE"


def test_level_3_finds_the_amounts_percentages_dates_and_numbers():
    assert at(ALL_KINDS_TEXT) == [
        ("MONEY", "$1,200.50"),
        ("PERCENT", "15%"),
        ("DATE", "21.10.2026"),
        ("NUMBER", "4521"),
        ("EMAIL", "ivan@acme.com"),
        ("SECRET", "AKIAIOSFODNN7EXAMPLE"),
    ]


def test_level_4_detects_like_level_3():
    assert at(ALL_KINDS_TEXT, level=4) == at(ALL_KINDS_TEXT, level=3)


@pytest.mark.parametrize("level", [0, 1, 2])
def test_levels_0_to_2_never_return_the_number_kinds(level):
    got = {kind for kind, _ in at(ALL_KINDS_TEXT, level=level)}
    assert got <= KINDS_BY_LEVEL[level] and not got & KINDS


def test_level_2_leaves_the_figures_visible():
    assert at("Paid $1,200.50 (15%) on 21.10.2026, order 4521", level=2) == []


# the other kinds keep what is theirs


@pytest.mark.parametrize(
    "kind,value",
    [
        ("PHONE", "+7 (912) 345-67-89"),
        ("PHONE", "+44 20 7946 0958"),
        ("PHONE", "8 (912) 345-67-89"),
        ("CARD", "4111 1111 1111 1111"),
        ("CARD", "4111-1111-1111-1111"),
        ("IBAN", "DE89 3704 0044 0532 0130 00"),
        ("IP", "203.0.113.7"),
        ("IP", "192.168.100.200"),
        ("IP", "100.100.100.100"),
        ("SNILS", "112-233-445 95"),
        ("EMAIL", "ivan2026@acme.com"),
        ("EMAIL", "12345@mail.ru"),
        ("DATE", "21.10.2026"),
        ("DATE", "2026-10-21T14:30:00Z"),
        ("DATE", "21 октября 2026"),
        ("MONEY", "1 200 руб."),
    ],
)
def test_a_structured_value_is_never_split_into_numbers(kind, value):
    assert at(f"call {value} now") == [(kind, value)]


@pytest.mark.parametrize(
    "text,expected",
    [
        ("ИНН 7707083893", [("INN", "7707083893")]),
        ("СНИЛС 11223344595", [("SNILS", "11223344595")]),
        ("password=1234567890", [("SECRET", "1234567890")]),
        ("pin: 5, password: 12345678.", [("SECRET", "12345678.")]),
    ],
)
def test_an_identifier_with_context_keeps_its_kind(text, expected):
    assert at(text) == expected


def test_a_dictionary_term_wins_over_a_number_of_the_same_span():
    cfg = DetectConfig(dictionary={"2026": "CLIENT"})
    assert at("in 2026 we had 1500", config=cfg) == [("CLIENT", "2026"), ("NUMBER", "1500")]


def test_the_allow_list_keeps_a_number_visible():
    cfg = DetectConfig(allow={"2026"})
    assert at("in 2026 we had 1500", config=cfg) == [("NUMBER", "1500")]


# masking and restoring


MIXED = (
    "Q3 2026 revenue was $1.2M (+15% YoY), or 95 млн руб. Договор №4521 от 21 октября 2026 на сумму EUR 300 000, "
    "оплата до 2026-11-15."
)


def test_a_mixed_finance_paragraph_is_masked_and_restored_exactly():
    markers = MarkerMap()
    masked, counts = mask_text(MIXED, markers, level=3)
    assert masked == (
        "[DATE_1] revenue was [MONEY_1] ([PERCENT_1] YoY), or [MONEY_2] Договор №[NUMBER_1] от [DATE_2] на сумму "
        "[MONEY_3], оплата до [DATE_3]."
    )
    assert counts == {"DATE": 3, "MONEY": 3, "PERCENT": 1, "NUMBER": 1}
    assert restore(masked, markers).text == MIXED


def test_a_paragraph_with_every_kind_round_trips():
    text = (
        f"{MIXED} Contact ivan.petrov@acme.com or +7 (912) 345-67-89, card 4111 1111 1111 1111, host 203.0.113.7. "
        "Headcount 1 500, margin 12,5 процентов, 3 п.п. above plan; see v2 notes, 3.10.12 and order #123."
    )
    markers = MarkerMap()
    masked, _ = mask_text(text, markers, level=3)
    assert not re.search(r"\d{2}", masked.replace("3.10.12", "")), masked
    assert restore(masked, markers).text == text


def test_a_marker_like_string_of_a_number_kind_in_the_source_round_trips():
    markers = MarkerMap()
    text = "see [NUMBER_1], [DATE_7] and 1500"
    masked, _ = mask_text(text, markers, level=3)
    assert masked == "see [LITERAL_1], [LITERAL_2] and [NUMBER_1]"
    assert restore(masked, markers).text == text


def test_the_digits_of_a_marker_are_never_a_number():
    masked, _ = mask_text(MIXED, MarkerMap(), level=3)
    assert number_candidates(masked) == []


CHUNKS = st.one_of(
    st.text(alphabet=string.digits + " .,'-+/:%$", max_size=8),
    st.sampled_from(
        ["руб.", "млн", "тыс.", "€", "₽", "EUR", "USD", "k", "M", "Oct", "октября", "Q3", "кв.", "п.п.", "%", "T", "Z", "x", "v"]
    ),
    st.sampled_from(
        ["\n", " ", "\N{NO-BREAK SPACE}", "\N{THIN SPACE}", "[NUMBER_1]", "[DATE_2]", "ivan@acme.com", "+7 (912) 345-67-89"]
    ),
    st.sampled_from(  # findings of the other kinds, and a name of the dictionary: numbers run into all of them
        ["4111 1111 1111 1111", "12345@mail.ru", "8 (912) 345-67-89", "203.0.113.7", "AKIAIOSFODNN7EXAMPLE", "password=", "Acme Corp", "4521"]
    ),
)


@settings(max_examples=400, deadline=None)
@given(st.lists(CHUNKS, max_size=14).map("".join))
def test_candidates_are_well_formed_and_level_3_round_trips(text):
    candidates = number_candidates(text)
    assert all(text[c.start : c.end] == c.text and c.kind in KINDS and c.detector.startswith("rule:") for c in candidates)
    assert all(a.end <= b.start for a, b in zip(candidates, candidates[1:]))
    markers = MarkerMap()
    masked, _ = mask_text(text, markers, level=3)
    assert restore(masked, markers).text == text


# typed findings come first: a number never takes a name, a phone, a card or an e-mail away, nor an edge of one


class FixedNer:
    """NER stub: the given (start, end, kind) spans, wherever they are."""

    def __init__(self, spans):
        self.spans = spans

    def find(self, text):
        return [Detection(s, e, kind, text[s:e], "ner:stub") for s, e, kind in self.spans]


def test_a_ner_name_with_a_number_is_masked_whole_at_level_3():
    text = "Тинькофф Банк 24 одобрил сделку"
    ner = [FixedNer([(0, 16, "ORG")])]
    assert at(text, level=2, ner=ner) == [("ORG", "Тинькофф Банк 24")]
    assert at(text, level=3, ner=ner) == [("ORG", "Тинькофф Банк 24")]


@pytest.mark.parametrize(
    "text,org",
    [
        ("Сделку одобрил Тинькофф Банк 24 вчера", "Тинькофф Банк 24"),
        ("В компании Яндекс 360 работает Иван Петров", "Яндекс 360"),
    ],
)
def test_natasha_names_with_a_number_are_masked_whole_at_level_3(text, org):
    pytest.importorskip("natasha")
    from boxed.detect.ner import NatashaDetector

    ner = [NatashaDetector()]
    level2 = at(text, level=2, ner=ner)
    assert ("ORG", org) in level2
    assert set(level2) <= set(at(text, level=3, ner=ner))


@pytest.mark.parametrize(
    "text,config,expected",
    [
        ("Иванов Иван 8 (912) 345-67-89 120 000 руб.", None, [("PHONE", "8 (912) 345-67-89"), ("MONEY", "120 000 руб.")]),
        ("Ivan,500000,12345678@qq.com", None, [("NUMBER", "500000"), ("EMAIL", "12345678@qq.com")]),
        ("Ivan,95000,4111 1111 1111 1111", None, [("NUMBER", "95000"), ("CARD", "4111 1111 1111 1111")]),
        ("total 1 234 567,12345@mail.ru", None, [("NUMBER", "1 234 567"), ("EMAIL", "12345@mail.ru")]),
        ("4111111111111111.0", None, [("CARD", "4111111111111111")]),
        ("ref 4521.0", DetectConfig(dictionary={"4521": "CLIENT"}), [("CLIENT", "4521")]),
        ("Ivan,120000,2021-03-01", None, [("NUMBER", "120000"), ("DATE", "2021-03-01")]),
    ],
)
def test_a_typed_finding_keeps_its_span_and_the_numbers_beside_it_are_masked(text, config, expected):
    assert at(text, config=config) == expected


def test_a_card_with_a_decimal_tail_still_makes_the_text_secret():
    from boxed.policy import categories_for

    assert categories_for({d.kind for d in detect("pay 4111111111111111.0 now", level=3)}) == {"secrets"}


def test_number_candidates_leave_the_spans_taken_by_other_kinds_alone():
    text = "ref 4521.0 and 120 000 руб."
    taken = [Candidate(4, 8, "CLIENT", "4521", "dict")]
    assert [(c.kind, c.text) for c in number_candidates(text, taken)] == [("MONEY", "120 000 руб.")]
    assert [(c.kind, c.text) for c in number_candidates(text)] == [("NUMBER", "4521.0"), ("MONEY", "120 000 руб.")]


SPANS = st.lists(st.tuples(st.integers(0, 60), st.integers(0, 60)), max_size=4)


@settings(max_examples=300, deadline=None)
@given(st.lists(CHUNKS, max_size=14).map("".join), SPANS)
def test_number_candidates_never_touch_a_taken_span(text, spans):
    spans = sorted({(min(a, b, len(text)), min(max(a, b), len(text))) for a, b in spans if a != b})
    taken, last = [], 0
    for start, end in spans:  # disjoint and in order, as the findings of detect() are
        if start >= last:
            taken.append(Candidate(start, end, "SECRET", text[start:end], "test"))
            last = end
    found = number_candidates(text, taken)
    assert all(text[c.start : c.end] == c.text for c in found)
    assert all(a.end <= b.start for a, b in zip(found, found[1:]))
    assert not any(c.start < t.end and t.start < c.end for c in found for t in taken)


CONFIGS = [None, DetectConfig(internal_domains=["corp.acme.io"], dictionary={"Acme Corp": "CLIENT", "2026": "YEAR", "4521": "CLIENT"})]


@settings(max_examples=500, deadline=None)
@given(st.lists(CHUNKS, max_size=14).map("".join), st.data())
def test_level_3_never_masks_less_than_level_2(text, data):
    names = data.draw(st.lists(st.tuples(st.integers(0, len(text)), st.integers(0, len(text)), st.sampled_from(["PERSON", "ORG"])), max_size=3))
    ner = [FixedNer([(min(a, b), max(a, b), kind) for a, b, kind in names if a != b])]
    config = data.draw(st.sampled_from(CONFIGS))
    level2 = detect(text, level=2, config=config, ner=ner)
    level3 = detect(text, level=3, config=config, ner=ner)
    assert {(d.start, d.end, d.kind) for d in level2} <= {(d.start, d.end, d.kind) for d in level3}  # same spans, same kinds
    masked3 = {i for d in level3 for i in range(d.start, d.end)}
    assert all(i in masked3 for d in level2 for i in range(d.start, d.end))  # every character masked at level 2
    assert [d for d in level3 if d.kind not in KINDS] == level2  # level 3 is level 2 and the number kinds, nothing else
    assert all(a.end <= b.start for a, b in zip(level3, level3[1:]))


# hyphens and ranges: a year or an upper bound behind a hyphen is as much a figure as the rest


@pytest.mark.parametrize(
    "text,expected",
    [
        ("report-2026-10-21.pdf", [("DATE", "2026-10-21")]),
        ("INV-2026-0457", [("NUMBER", "2026"), ("NUMBER", "0457")]),
        ("21-Oct-2026", [("DATE", "21-Oct-2026")]),
        ("due 21-Oct", [("DATE", "21-Oct")]),
        ("Oct-2026", [("DATE", "Oct-2026")]),
        ("COVID-19", [("NUMBER", "19")]),
        ("ISO-9001", [("NUMBER", "9001")]),
        ("post-123", [("NUMBER", "123")]),
        ("ВАЗ-2107", [("NUMBER", "2107")]),
        ("Ivan-500", [("NUMBER", "500")]),
    ],
)
def test_a_number_behind_a_hyphen_is_masked(text, expected):
    assert found(text) == expected


@pytest.mark.parametrize(
    "text,expected",
    [
        ("$1.2M-1.5M", [("MONEY", "$1.2M-1.5M")]),
        ("$100-200", [("MONEY", "$100-200")]),
        ("$100 - $200", [("MONEY", "$100"), ("MONEY", "$200")]),
        ("5-7 млн руб.", [("MONEY", "5-7 млн руб.")]),
        ("5\N{EN DASH}7 млн руб.", [("MONEY", "5\N{EN DASH}7 млн руб.")]),
        ("100-200 USD", [("MONEY", "100-200 USD")]),
        ("1.5-2 million dollars", [("MONEY", "1.5-2 million dollars")]),
        ("100k-200k USD", [("MONEY", "100k-200k USD")]),
        ("10-15%", [("PERCENT", "10-15%")]),
        ("5 - 7 %", [("PERCENT", "5 - 7 %")]),
        ("1-5 июня 2026", [("DATE", "1-5 июня 2026")]),
        ("21\N{EN DASH}23 октября", [("DATE", "21\N{EN DASH}23 октября")]),
    ],
)
def test_a_range_is_one_token(text, expected):
    assert found(text) == expected


def test_both_bounds_of_a_plain_range_are_masked():
    assert not re.search(r"\d", visible("100k-200k and 20-30 people"))
# scale letters and compact dates: a lone digit with a scale is a big quantity, FY2026 and 2026Q3 are dates


@pytest.mark.parametrize(
    "text,expected",
    [
        ("5k", [("NUMBER", "5k")]),
        ("7M followers", [("NUMBER", "7M")]),
        ("15K users", [("NUMBER", "15K")]),
        ("2.5bn", [("NUMBER", "2.5bn")]),
        ("5к", [("NUMBER", "5к")]),
        ("1.5M-2M", [("NUMBER", "1.5M"), ("NUMBER", "2M")]),
        ("100k-200k", [("NUMBER", "100k"), ("NUMBER", "200k")]),
        ("+5k", [("NUMBER", "+5k")]),
    ],
)
def test_a_scale_letter_sticks_to_its_number(text, expected):
    assert found(text) == expected


@pytest.mark.parametrize("text", ["5kg", "5mm", "3D", "4G", "k8s", "M5", "5 k", "2 M"])
def test_a_letter_that_is_no_scale_leaves_a_lone_digit_alone(text):
    assert found(text) == []


@pytest.mark.parametrize(
    "date",
    [
        "FY2026",
        "FY26",
        "FY 2026",
        "FY-2026",
        "2026Q3",
        "2026-Q3",
        "Q32026",
        "H1 2026",
        "H2-2026",
        "2026H1",
        "20261021T143000Z",
        "20261021T1430",
        "20261021T143000+0300",
    ],
)
def test_compact_dates_and_fiscal_periods(date):
    assert found(f"in {date} we") == [("DATE", date)]


@pytest.mark.parametrize("text", ["FY", "FYI 2026", "2026Qx", "H3 2026", "20261321T143000Z", "20261021Tabc"])
def test_not_a_compact_date(text):
    assert "DATE" not in kinds(text)
# amounts the first version read as plain numbers, and words that look like amounts, times and dates


@pytest.mark.parametrize(
    "text",
    [
        "1 200 000 (один миллион двести тысяч) рублей",
        "5 (five) dollars",
        "100 (сто) руб.",
        "US$ 1.2 million",
        "US$1.2M",
        "C$5",
        "A$ 100",
        "CA$20",
        "S$ 1,000",
        "R$ 1.000,00",
        "NZ$5k",
        "HK$ 300",
        "$1.2 million",
        "1.2 billion dollars",
        "5 thousand euros",
    ],
)
def test_more_amounts(text):
    assert found(f"sum {text} paid") == [("MONEY", text)]


@pytest.mark.parametrize(
    "text,expected",
    [
        ("RON 95", [("NUMBER", "95")]),
        ("RON 98 fuel", [("NUMBER", "98")]),
        ("CAD 2024", [("NUMBER", "2024")]),
        ("AUD 2025", [("NUMBER", "2025")]),
        ("NZD 2010-2012", [("NUMBER", "2010"), ("NUMBER", "2012")]),
        ("CHF 2000", [("MONEY", "CHF 2000")]),  # years of the last decades only: 2000 francs are an amount
        ("JPY 1999", [("MONEY", "JPY 1999")]),
        ("USD 2024", [("MONEY", "USD 2024")]),  # the big codes keep every number: USD 2024 may be an amount
        ("EUR 2000", [("MONEY", "EUR 2000")]),
        ("CAD 2,024", [("MONEY", "CAD 2,024")]),
        ("CAD 2024.50", [("MONEY", "CAD 2024.50")]),
        ("CAD 1 500", [("MONEY", "CAD 1 500")]),
        ("CAD 3000", [("MONEY", "CAD 3000")]),
        ("RON 95.50", [("MONEY", "RON 95.50")]),
        ("RON 150", [("MONEY", "RON 150")]),
        ("95 RON", [("MONEY", "95 RON")]),
        ("2024 CAD", [("MONEY", "2024 CAD")]),
    ],
)
def test_a_code_in_front_of_a_year_or_an_octane_number_is_not_money(text, expected):
    assert found(text) == expected


@pytest.mark.parametrize(
    "time",
    ["9:05 AM", "9:05pm", "10:20 p.m.", "14:30", "14:30:15", "09:05:30.250", "23:59"],
)
def test_a_time_of_day_is_one_number(time):
    assert found(f"at {time} sharp") == [("NUMBER", time)]


def test_a_time_does_not_take_a_word_that_only_starts_like_am():
    assert found("at 9:05 America") == [("NUMBER", "9:05")]


@pytest.mark.parametrize(
    "date",
    ["OCTOBER 21", "october 21", "Oct 21", "OCT. 21, 2026", "21 OCTOBER 2026", "21 october 2026", "MAY 5", "december 2026", "SEPT 2026"],
)
def test_english_months_in_any_case(date):
    assert found(f"on {date} we") == [("DATE", date)]


@pytest.mark.parametrize("text", ["we may 5 times", "may be 21", "the may 2026 issue"])
def test_the_word_may_needs_a_capital(text):
    assert "DATE" not in kinds(text)
# no rule is quadratic: 200 KB of digits, dots, spaces and currency signs, in the shapes that make a regex rescan


BIG = 200_000
# name: (the unit that is repeated up to 200 KB, the fewest detections level 3 must find: a fast "nothing" cannot pass)
SHAPES = {
    "a dotted chain": ("1.", 0),
    "lone digits": ("1 ", 0),
    "one number of 50k groups": ("123 ", 1),
    "one number of 200k digits": ("9", 1),
    "currency signs": ("$ ", 0),
    "tiny amounts": ("$1 ", 60_000),
    "tiny numbers": ("12 ", 60_000),
    "decimals": ("1.5 ", 45_000),
    "grouped decimals": ("1 000.50 ", 20_000),
    "version chains": ("1.2.3 ", 0),
    "dates": ("21.10.2026 ", 15_000),
    "amounts after numbers": ("1 ₽ 2 $ 3 € ", 45_000),
    "mixed lengths": ("1.5 $ 20 ₽ 3.4.5 100 of it ", 12_000),
    "signs and separators": ("-1+1-", 0),
    "ranges and hyphens": ("1-5-", 0),
    "parentheses": ("5 (a b c d) ", 0),
    "unclosed parentheses": ("5 (", 0),
    "times": ("9:05 AM ", 20_000),
    "prefixed dollars": ("US$5 ", 35_000),
    "compact dates": ("FY2026 20261021T143000Z ", 14_000),
    "typed findings among numbers": ("ivan@acme.com 12; 4111 1111 1111 1111; ", 13_000),
}


def repeated(unit):
    return (unit * (BIG // len(unit) + 1))[:BIG]


TIME_FACTOR = float(os.environ.get("BOXED_TEST_TIME_FACTOR", "1"))  # the budgets fit a fast machine; a slower one sets this (3 for a 2020 i5)


def finishes_in_time(fn, text, limit=0.5):
    """The result of fn(text); three tries, so that another process taking the cpu does not fail the test."""
    limit *= TIME_FACTOR
    for _ in range(3):
        start = time.perf_counter()
        result = fn(text)
        if time.perf_counter() - start < limit:
            return result
    pytest.fail(f"slower than {limit} s")


@pytest.mark.parametrize("name", SHAPES)
def test_number_rules_are_linear(name):
    finishes_in_time(number_candidates, repeated(SHAPES[name][0]))


@pytest.mark.parametrize("name", SHAPES)
def test_level_3_takes_under_half_a_second_for_200_kb(name):
    unit, minimum = SHAPES[name]
    assert len(finishes_in_time(lambda text: detect(text, level=3), repeated(unit))) >= minimum


def test_long_runs_of_blanks_around_a_number_are_cheap():
    text = "5" + " " * (BIG // 3) + "x" + " " * (BIG // 3) + "$" + " " * (BIG // 3) + "5"
    assert finishes_in_time(lambda t: detect(t, level=3), text) == []


def test_a_number_that_ends_in_a_word_is_linear():
    # the last group is glued to a word, the rest of the chain is still one number
    chain = "123 " * (BIG // 4) + "123abcdefgh"
    assert len(finishes_in_time(number_candidates, chain)) == 1
    assert finishes_in_time(number_candidates, "9" * BIG + "abcdefgh") == []
