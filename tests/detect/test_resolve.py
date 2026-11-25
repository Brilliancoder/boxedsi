import time

from hypothesis import given, settings
from hypothesis import strategies as st

from boxed.detect import PRIORITY, _resolve, detect
from boxed.detect.patterns import Candidate


def naive(cands):
    ordered = sorted(cands, key=lambda c: (-(c.end - c.start), PRIORITY.get(c.kind, 100), c.start))
    kept = []
    for c in ordered:
        if not any(c.start < k.end and k.start < c.end for k in kept):
            kept.append(c)
    return sorted(kept, key=lambda c: c.start)


@settings(max_examples=300, deadline=None)
@given(st.lists(st.tuples(st.integers(0, 60), st.integers(1, 12), st.sampled_from(["EMAIL", "SECRET", "IP", "HOST"])), max_size=40))
def test_resolve_matches_the_naive_rule(spans):
    cands = [Candidate(s, s + n, kind, "x" * n, "test") for s, n, kind in spans]
    assert _resolve(cands) == naive(cands)


def test_many_short_findings_resolve_fast():
    text = "".join(f"u{i}@acme.io " for i in range(25_000))
    start = time.monotonic()
    assert len(detect(text, level=1)) == 25_000
    assert time.monotonic() - start < 5
