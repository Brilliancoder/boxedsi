"""The resolver against a copy of the implementation it replaced (9f6cd1f): the same answer for every list of spans, at any size."""

import bisect
import random
import time

from hypothesis import given, settings
from hypothesis import strategies as st

from boxed.detect import PRIORITY, _resolve, detect
from boxed.detect.patterns import Candidate

KINDS = (*PRIORITY, "ORG", "CLIENT")  # known priorities, and kinds that get the default one


def reference_resolve(cands):
    """boxed.detect._resolve before it stopped using list.insert: longest first, then kind priority, then start."""
    ordered = sorted(cands, key=lambda c: (-(c.end - c.start), PRIORITY.get(c.kind, 100), c.start))
    starts, ends, kept = [], [], []
    for c in ordered:
        i = bisect.bisect_left(starts, c.end)
        if i and ends[i - 1] > c.start:
            continue
        starts.insert(i, c.start)
        ends.insert(i, c.end)
        kept.insert(i, c)
    return kept


def candidates(spans):
    """A unique text per candidate, so equal spans stay distinguishable and the order of ties is compared too."""
    return [Candidate(start, start + length, kind, f"c{i}", "test") for i, (start, length, kind) in enumerate(spans)]


dense = st.lists(st.tuples(st.integers(0, 40), st.integers(0, 10), st.sampled_from(KINDS)), max_size=60)


@st.composite
def sparse(draw):
    anchors = draw(st.lists(st.integers(0, 10**12), min_size=1, max_size=4))
    return draw(st.lists(st.tuples(st.builds(lambda a, d: a + d, st.sampled_from(anchors), st.integers(0, 30)), st.integers(0, 12),
                                   st.sampled_from(KINDS)), max_size=60))


@settings(max_examples=1000, deadline=None)
@given(dense)
def test_resolve_matches_the_reference_on_dense_spans(spans):
    cands = candidates(spans)
    assert _resolve(cands) == reference_resolve(cands)


@settings(max_examples=300, deadline=None)
@given(sparse())
def test_resolve_matches_the_reference_on_spans_far_apart(spans):
    cands = candidates(spans)
    assert _resolve(cands) == reference_resolve(cands)


# few places and short lengths, so empty spans keep landing on the edges of kept spans
tiny = st.lists(st.tuples(st.integers(0, 6), st.sampled_from((0, 0, 1, 2, 3, 5)), st.sampled_from(KINDS)), max_size=12)


@settings(max_examples=1500, deadline=None)
@given(tiny)
def test_resolve_matches_the_reference_on_spans_that_touch(spans):
    cands = candidates(spans)
    assert _resolve(cands) == reference_resolve(cands)


EMPTY_SPAN_CASES = {  # (start, end) spans in; the (start, end) spans kept, in order
    "empty between two touching spans": ([(0, 5), (5, 9), (5, 5)], [(0, 5), (5, 5), (5, 9)]),
    "empty at the end of a span, a free cell after": ([(0, 5), (8, 9), (5, 5)], [(0, 5), (5, 5), (8, 9)]),
    "empty inside a span": ([(0, 10), (5, 5)], [(0, 10)]),
    "empty at the start of a span": ([(5, 10), (5, 5)], [(5, 5), (5, 10)]),
    "empty at the first coordinate": ([(0, 5), (0, 0)], [(0, 0), (0, 5)]),
    "empty at the end of the last span": ([(0, 5), (5, 5)], [(0, 5), (5, 5)]),
    "empty before everything": ([(0, 0), (3, 6)], [(0, 0), (3, 6)]),
    "empty inside the second of two touching spans": ([(0, 5), (5, 9), (7, 7)], [(0, 5), (5, 9)]),
    "empty inside, and another at the end": ([(0, 5), (3, 3), (5, 5)], [(0, 5), (5, 5)]),
    "empty at a touching point, spans of three and three": ([(0, 3), (3, 6), (3, 3)], [(0, 3), (3, 3), (3, 6)]),
}


def test_resolve_places_an_empty_span_against_the_edges_of_kept_spans():
    for name, (spans, expected) in EMPTY_SPAN_CASES.items():
        cands = [Candidate(start, end, "EMAIL", f"c{i}", "test") for i, (start, end) in enumerate(spans)]
        kept = _resolve(cands)
        assert [(c.start, c.end) for c in kept] == expected, name
        assert kept == reference_resolve(cands), name


def test_resolve_matches_the_reference_on_a_large_random_input():
    rnd = random.Random(7)
    cands = candidates([(rnd.randint(0, 3000), rnd.randint(0, 40), rnd.choice(KINDS)) for _ in range(5000)])
    kept = _resolve(cands)
    assert kept == reference_resolve(cands) and 0 < len(kept) < len(cands)


def test_resolve_keeps_the_order_of_identical_empty_spans():
    cands = [Candidate(5, 5, kind, f"c{i}", "test") for i, kind in enumerate(("EMAIL", "IP", "EMAIL"))]
    # processed as c0, c2, c1 (kind priority, then input order); each later one lands before the earlier ones
    assert _resolve(cands) == reference_resolve(cands) == [cands[1], cands[2], cands[0]]


def test_resolve_survives_a_span_that_ends_before_it_starts():
    """Not a span (no detector gives one), so there is no answer to match; it must not crash or invent candidates."""
    cands = [Candidate(10, 5, "EMAIL", "x", "test"), Candidate(0, 20, "SECRET", "y", "test"), Candidate(3, 3, "IP", "z", "test")]
    assert all(c in cands for c in _resolve(cands))


def disjoint_spans(count):
    rnd = random.Random(1)
    cands, pos = [], 0
    for _ in range(count):
        width = rnd.randint(6, 30)
        cands.append(Candidate(pos, pos + width, rnd.choice(("EMAIL", "IP", "SECRET", "HOST")), "x", "test"))
        pos += width + rnd.randint(1, 5)
    rnd.shuffle(cands)  # the widths differ, so kept spans arrive in the middle of the result, not at its end
    return cands


def test_resolve_200k_findings_under_two_seconds():
    cands = disjoint_spans(200_000)
    start = time.monotonic()
    kept = _resolve(cands)
    assert time.monotonic() - start < 2
    assert len(kept) == 200_000 and all(a.end <= b.start for a, b in zip(kept, kept[1:]))


def test_resolve_200k_overlapping_findings_under_two_seconds():
    rnd = random.Random(2)
    cands = []
    for _ in range(200_000):
        start = rnd.randint(0, 1_600_000)
        cands.append(Candidate(start, start + rnd.randint(1, 40), rnd.choice(("EMAIL", "IP", "SECRET", "HOST", "URL")), "x", "test"))
    start = time.monotonic()
    kept = _resolve(cands)
    assert time.monotonic() - start < 2
    assert all(a.end <= b.start for a, b in zip(kept, kept[1:]))


def test_resolve_one_long_span_over_200k_short_ones_under_two_seconds():
    cands = [Candidate(0, 2_000_000, "SECRET", "x", "test")]
    cands += [Candidate(10 * i, 10 * i + 8, "EMAIL", "x", "test") for i in range(200_000)]
    start = time.monotonic()
    kept = _resolve(cands)
    assert time.monotonic() - start < 2
    assert kept == cands[:1]


def test_detect_200k_emails_under_five_seconds():
    text = "".join(f"u{i}@acme.io " for i in range(200_000))
    start = time.monotonic()
    assert len(detect(text, level=1)) == 200_000
    assert time.monotonic() - start < 5
