"""detect() against a copy of the version it replaced (dc4dcca): the same findings for any text. The copy has since learned two
things: the findings of the config (hosts, URLs, dictionary terms) are passed to rule_candidates, as detect() does, and a span of
a name model that overlaps a finding is cut around it, the parts that are names staying (found here character by character).

That version dropped an e-mail inside the credentials of a URL by asking every authority span about every e-mail, which is
quadratic in the number of URLs times the number of e-mails. The copy below keeps that one line as it was."""

import re
from operator import attrgetter

from hypothesis import given, settings
from hypothesis import strategies as st

from boxed.detect import (
    DICTIONARY_MIN_LEVEL,
    KIND_RE,
    KINDS_BY_LEVEL,
    NUMBER_KINDS,
    DetectConfig,
    Detection,
    _resolve,
    _span_finder,
    detect,
)
from boxed.detect.numbers import number_candidates
from boxed.detect.patterns import LABEL_WORD, Candidate, dictionary_candidates, host_url_candidates, rule_candidates


def reference_detect(text, level, config):
    kinds = KINDS_BY_LEVEL[level]
    hosts, authority_spans = host_url_candidates(text, config.internal_domains)
    terms = []
    if level >= DICTIONARY_MIN_LEVEL:
        for c in dictionary_candidates(text, config.dictionary):
            if not KIND_RE.fullmatch(c.kind):
                raise ValueError(f"bad dictionary kind {c.kind!r}")
            terms.append(c)
    from_config = [c for c in [*(h for h in hosts if h.kind in kinds), *terms] if c.text not in config.allow]
    cands = [
        c
        for c in rule_candidates(text, from_config) + hosts
        if c.kind in kinds and not (c.kind == "EMAIL" and any(s <= c.start < e for s, e in authority_spans))
    ] + terms
    kept = _resolve([c for c in cands if c.text not in config.allow])
    if config.ner:
        extra = [
            Candidate(d.start, d.end, d.kind, d.text, d.detector)
            for detector in config.ner
            for d in detector.find(text)
            if d.kind in kinds and d.text not in config.allow
        ]
        covered = [False] * len(text)
        for k in kept:
            covered[k.start : k.end] = [True] * (k.end - k.start)
        free = []
        for c in extra:
            i = c.start
            while i < c.end:
                if covered[i]:
                    i += 1
                    continue
                j = i
                while j < c.end and not covered[j]:
                    j += 1
                if (i, j) == (c.start, c.end):
                    free.append(c)  # nothing of it is covered
                else:
                    piece = text[i:j]
                    body = piece.strip()
                    start = i + len(piece) - len(piece.lstrip())
                    words = re.findall(r"[^\W\d_]+", body)
                    is_name = any(len(w) > 1 for w in words) and not all(LABEL_WORD.fullmatch(w) for w in words)
                    if is_name and body not in config.allow:
                        free.append(Candidate(start, start + len(body), c.kind, body, c.detector))
                i = j
        kept = _resolve(kept + free)
    if kinds & NUMBER_KINDS:
        numbers = [c for c in number_candidates(text, kept) if c.kind in kinds and c.text not in config.allow]
        kept = sorted(kept + numbers, key=attrgetter("start"))
    return [Detection(c.start, c.end, c.kind, c.text, c.detector) for c in kept]


class WordNer:
    """Finds every occurrence of two words, so that NER spans meet the e-mails and URLs of a text."""

    WORDS = {"Acme": "ORG", "Ivan Petrov": "PERSON"}

    def find(self, text):
        found = []
        for word, kind in self.WORDS.items():
            at = text.find(word)
            while at != -1:
                found.append(Detection(at, at + len(word), kind, word, "ner:stub"))
                at = text.find(word, at + 1)
        return found


# Pieces that meet at their edges: an e-mail inside the credentials of a URL, one just before or after its authority, one in its
# path, a URL without a password, hosts, numbers and words for the dictionary and the NER stub.
FRAGMENTS = [
    "http://u:p@h.io/",
    "https://user:pass@db.acme.local:5432/x",
    "ftp://a:b@c.d",
    "http://user.name@host.io/path",
    "postgres://admin:s3cret@db1.acme.local/app",
    "http://h.io/x",
    "https://example.com/a@b.io",
    "http://a:b@c.io@y.io",
    "p@h.io",
    "ivan.petrov@acme.com",
    "a@x.io",
    "@y.io",
    "pass@host.example",
    "db1.acme.local",
    "10.0.0.1",
    "+7 912 345-67-89",
    "2026-10-21",
    "$5",
    "password=hunter22hunter",
    "Acme",
    "Ivan Petrov",
    "Beta Ltd",
    " ",
    " ",
    "\n",
    ", ",
    "(",
    ")",
    "<",
    ">",
    "/",
    ":",
    "@",
    "x",
]
texts = st.lists(st.sampled_from(FRAGMENTS), max_size=14).map("".join)
CONFIG = DetectConfig(internal_domains=["acme.local"], dictionary={"Beta Ltd": "CLIENT"}, allow={"a@x.io"}, ner=[WordNer()])


@settings(max_examples=900, deadline=None)
@given(texts, st.sampled_from(sorted(KINDS_BY_LEVEL)), st.sampled_from([DetectConfig(), CONFIG]))
def test_detect_matches_the_reference(text, level, config):
    assert detect(text, level, config) == reference_detect(text, level, config)


def test_an_email_in_the_credentials_of_a_url_is_still_dropped_and_one_beside_it_is_not():
    text = "see http://u:p@h.io/ and mail p@h.io or a@b.io; also http://h.io/x@y.io"
    assert [(d.kind, d.text) for d in detect(text, 1)] == [("SECRET", "u:p"), ("EMAIL", "p@h.io"), ("EMAIL", "a@b.io"), ("EMAIL", "x@y.io")]


span_lists = st.lists(st.tuples(st.integers(-5, 40), st.integers(-5, 40)), max_size=30)  # overlapping, empty and reversed ones too


@settings(max_examples=1000, deadline=None)
@given(span_lists, st.lists(st.integers(-6, 45), max_size=30))
def test_the_span_finder_answers_as_asking_every_span_does(spans, positions):
    holds = _span_finder(spans)
    for position in positions:
        assert holds(position) == any(start <= position < end for start, end in spans), (spans, position)
