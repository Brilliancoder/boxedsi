"""The rules of the later stages fill the gaps of the stage 0 rules: a match of a later stage that overlaps a match of an earlier
stage is dropped, so a new rule can never take a finding from an old one (no existing finding is lost)."""

import re

from hypothesis import given, settings
from hypothesis import strategies as st

from boxed.detect import KINDS_BY_LEVEL, DetectConfig, detect
from boxed.detect import patterns
from boxed.detect.patterns import Rule, _Spans, rule_candidates


def test_spans_answer_whether_a_span_overlaps_any_of_them():
    taken = _Spans([(10, 20), (30, 31), (5, 8)])
    assert [taken.overlaps(a, b) for a, b in [(0, 5), (0, 6), (7, 10), (8, 10), (19, 21), (20, 30), (20, 31), (30, 40), (31, 40), (0, 100)]] == [
        False,
        True,
        True,
        False,
        True,
        False,
        True,
        True,
        False,
        True,
    ]


def test_spans_of_nothing_overlap_nothing():
    assert not _Spans([]).overlaps(0, 10)


def test_a_match_of_a_later_stage_is_dropped_where_it_overlaps_an_earlier_one(monkeypatch):
    old = Rule("rule:old", "SECRET", re.compile(r"bcd"))
    longer = Rule("rule:longer", "PASSPORT", re.compile(r"abcdefg"), stage=1)  # longer than the old match, and around it
    apart = Rule("rule:apart", "PASSPORT", re.compile(r"xyz"), stage=1)
    monkeypatch.setattr(patterns, "RULES", (old, longer, apart))
    assert [(c.start, c.end, c.detector) for c in rule_candidates("abcdefg xyz")] == [(1, 4, "rule:old"), (8, 11, "rule:apart")]


def test_rules_of_one_stage_do_not_drop_each_other(monkeypatch):
    first = Rule("rule:first", "SSN", re.compile(r"abcd"), stage=1)
    second = Rule("rule:second", "PASSPORT", re.compile(r"cdef"), stage=1)
    monkeypatch.setattr(patterns, "RULES", (first, second))
    assert [c.detector for c in rule_candidates("abcdef")] == ["rule:first", "rule:second"]


def test_a_stage_after_the_next_sees_both_earlier_ones(monkeypatch):
    zero = Rule("rule:zero", "SECRET", re.compile(r"aaa"))
    one = Rule("rule:one", "SSN", re.compile(r"ccc"), stage=1)
    two = Rule("rule:two", "SECRET", re.compile(r"[ac]{2,}"), stage=2)
    monkeypatch.setattr(patterns, "RULES", (zero, one, two))
    assert [c.detector for c in rule_candidates("aaa ccc cc aa")] == ["rule:zero", "rule:one", "rule:two", "rule:two"]


def test_the_cells_of_a_table_belong_to_the_first_stage(monkeypatch):
    late = Rule("rule:late", "SECRET", re.compile(r"Xk9#mQ2v"), stage=1)
    monkeypatch.setattr(patterns, "RULES", (late,))
    # the cell rule finds the password under its name; the later rule must not take the same span again
    assert [c.detector for c in rule_candidates("| Пароль | Xk9#mQ2v |")] == ["rule:key-cell"]


# --- what the config finds is kept too: a dictionary term, a host or a URL that a new match would cut stays whole


def found(text, level=2, config=None):
    return [(d.kind, d.text) for d in detect(text, level, config)]


def test_a_new_match_never_cuts_a_dictionary_term():
    config = DetectConfig(dictionary={"Acme Project": "CLIENT"})
    assert found("Acme Project-6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk", 2, config) == [("CLIENT", "Acme Project")]
    assert found("x Acme Project+6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk end", 2, config) == [("CLIENT", "Acme Project")]
    assert found("Acme Project 6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk", 2, config) == [("CLIENT", "Acme Project"), ("SECRET", "6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk")]


def test_the_dictionary_shields_from_level_2_on_and_not_what_the_user_allows():
    config = DetectConfig(dictionary={"Acme Project": "CLIENT"})
    assert found("Acme Project-6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk", 1, config) == [("SECRET", "Project-6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk")]  # not read at level 1
    allowed = DetectConfig(dictionary={"Acme Project": "CLIENT"}, allow={"Acme Project"})
    assert found("Acme Project-6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk", 2, allowed) == [("SECRET", "Project-6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk")]


def test_a_passport_number_never_cuts_a_dictionary_term():
    config = DetectConfig(dictionary={"Acme 4510": "CLIENT"})
    assert found("Паспорт Acme 4510 123456", 2, config) == [("CLIENT", "Acme 4510")]


def test_a_later_match_that_overlaps_a_given_span_is_dropped_and_an_older_one_is_not(monkeypatch):
    first = Rule("rule:first", "SECRET", re.compile(r"abc"))
    later = Rule("rule:later", "PASSPORT", re.compile(r"efg|xyz"), stage=1)
    monkeypatch.setattr(patterns, "RULES", (first, later))
    text = "abc efg xyz"
    assert [c.text for c in rule_candidates(text)] == ["abc", "efg", "xyz"]
    given = [patterns.Candidate(5, 6, "CLIENT", "f", "dict"), patterns.Candidate(1, 2, "CLIENT", "b", "dict")]
    assert [c.text for c in rule_candidates(text, given)] == ["abc", "xyz"]


# --- the property: whatever the new rules find, every finding of the older ones is still covered, at every level


def old_rule_candidates(text):
    out = [c for rule in patterns.RULES if rule.stage == 0 for c in patterns._matches(rule, text)]
    return out + patterns.cell_candidates(text)


def covered(spans, start, end):
    """Whether the spans together cover every character of [start, end)."""
    pos = start
    for s, e in sorted(spans):
        if s <= pos < e:
            pos = e
        if pos >= end:
            return True
    return pos >= end


def detect_without_new_rules(text, level, config):
    """What detect() finds with the stage 0 rules alone: the same pipeline over the rules of stage 0 only."""
    from boxed.detect import DICTIONARY_MIN_LEVEL, _resolve

    kinds = KINDS_BY_LEVEL[level]
    hosts, authority = patterns.host_url_candidates(text, config.internal_domains)
    cands = [c for c in old_rule_candidates(text) + hosts if c.kind in kinds and not (c.kind == "EMAIL" and any(s <= c.start < e for s, e in authority))]
    if level >= DICTIONARY_MIN_LEVEL:
        cands += patterns.dictionary_candidates(text, config.dictionary)
    return _resolve([c for c in cands if c.text not in config.allow])


FRAGMENTS = [
    "Паспорт: 4510 123456",
    "паспорт 75 1234567",
    "Passport no. A12345678",
    "SSN 512-34-7890",
    "512-34-7890",
    "+1 512-34-7890",
    "VAT: DE111111125",
    "DE111111125",
    "VAT DK12345678",
    "ATU10223006",
    "NL010000446B01",
    "FR83404833048",
    "ES A12345674",
    "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs",
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0x52908400098527886E0F7030069857D2E4169EE7",
    "ИНН 7707083893",
    "СНИЛС 112-233-445 95",
    "AKIAIOSFODNN7EXAMPLE",
    "ivan.petrov@acme.com",
    "+7 912 345-67-89",
    "+7 4510 123456",
    "4111 1111 1111 1111",
    "DE89 3704 0044 0532 0130 00",
    "10.0.0.1",
    "db1.acme.local",
    "http://u:p@h.io/",
    "https://wiki.acme.local/x",
    "password=hunter22hunter",
    "| Пароль | Xk9#mQ2v |",
    "6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk",
    "6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk+https://a.acme.local",
    "key=",
    "Acme Project",
    "Acme Project-",
    "Acme Project+",
    "Acme 4510",
    "Acme",
    "-",
    "+",
    ".",
    ":",
    "/",
    "@",
    "=",
    "№",
    " ",
    " ",
    "\n",
    ", ",
    "4510",
    "123456",
    "x",
]
texts = st.lists(st.sampled_from(FRAGMENTS), max_size=12).map("".join)
CONFIG = DetectConfig(
    internal_domains=["acme.local"],
    dictionary={"Xk9mQ2vL": "CLIENT", "hunter22hunter": "CODENAME", "4510": "CLIENT", "Acme Project": "CLIENT", "Acme 4510": "CLIENT"},
)


@settings(max_examples=1500, deadline=None)
@given(texts, st.sampled_from(sorted(KINDS_BY_LEVEL)), st.sampled_from([DetectConfig(), CONFIG]))
def test_no_finding_of_the_older_rules_is_lost(text, level, config):
    now = [(d.start, d.end) for d in detect(text, level, config)]
    for d in detect_without_new_rules(text, level, config):
        assert covered(now, d.start, d.end), (text, level, d)
