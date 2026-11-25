"""Per-document metrics: a document counts as failed if any critical value is not fully covered by a detection."""

import argparse
import json
import math
import os
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from time import perf_counter

from boxed.detect import detect
from boxed.mask import MarkerMap, mask, restore

from .generate import BenchDoc, generate

CATEGORIES = {
    "secrets": frozenset({"SECRET", "PRIVATE_KEY", "JWT"}),
    "identifiers": frozenset({"EMAIL", "PHONE", "CARD", "IBAN"}),
    "people": frozenset({"PERSON"}),
    "organizations": frozenset({"ORG"}),
}
CRITICAL = CATEGORIES["secrets"] | CATEGORIES["identifiers"]  # people and organizations are reported apart, and only with NER
NAME_KINDS = CATEGORIES["people"] | CATEGORIES["organizations"]
CATEGORY_OF = {kind: category for category, kinds in CATEGORIES.items() for kind in kinds}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval (95% by default) for k documents out of n; (0, 1) when there are no documents."""
    if not 0 <= k <= n:
        raise ValueError(f"k must be between 0 and n, got {k} of {n}")
    if n == 0:
        return 0.0, 1.0
    p, denominator = k / n, 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denominator
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return (0.0 if k == 0 else max(0.0, centre - half)), (1.0 if k == n else min(1.0, centre + half))


@dataclass
class LangReport:
    docs: int
    docs_with_critical_miss: int
    critical_miss_rate: float
    critical_miss_interval: tuple[float, float]  # Wilson, 95%
    values_by_category: dict[str, int]  # labelled values; people and organizations are there only with NER
    misses_by_category: dict[str, int]  # values no detection fully covers; only secrets and identifiers are critical
    false_positives: int  # detections that overlap no label
    false_positives_per_doc: float
    restore_errors: int  # documents that do not come back as they were after mask and restore
    restore_errors_per_doc: float
    ambiguous_places: int  # suspicious markers found when restoring
    ambiguous_per_doc: float
    time_ms_median: float  # detect and mask, one document
    time_ms_p95: float


@dataclass
class BenchReport:
    docs: int
    docs_with_critical_miss: int
    level: int
    ner: bool  # people and organizations are measured only when true
    by_lang: dict[str, LangReport]
    recall_by_kind: dict[str, float]
    false_positives_by_kind: dict[str, int]


@dataclass
class _Tally:
    docs: int = 0
    critical_miss_docs: int = 0
    values: Counter = field(default_factory=Counter)
    misses: Counter = field(default_factory=Counter)
    false_positives: int = 0
    restore_errors: int = 0
    ambiguous: int = 0
    ms: list[float] = field(default_factory=list)

    def report(self, categories: list[str]) -> LangReport:
        low, high = wilson(self.critical_miss_docs, self.docs)
        ms = sorted(self.ms)
        return LangReport(
            docs=self.docs,
            docs_with_critical_miss=self.critical_miss_docs,
            critical_miss_rate=round(self.critical_miss_docs / self.docs, 4),
            critical_miss_interval=(round(low, 4), round(high, 4)),
            values_by_category={c: self.values[c] for c in categories},
            misses_by_category={c: self.misses[c] for c in categories},
            false_positives=self.false_positives,
            false_positives_per_doc=round(self.false_positives / self.docs, 4),
            restore_errors=self.restore_errors,
            restore_errors_per_doc=round(self.restore_errors / self.docs, 4),
            ambiguous_places=self.ambiguous,
            ambiguous_per_doc=round(self.ambiguous / self.docs, 4),
            time_ms_median=round(statistics.median(ms), 2),
            time_ms_p95=round(ms[-(-len(ms) * 95 // 100) - 1], 2),  # nearest rank, in integers
        )


def evaluate(docs: list[BenchDoc], level: int = 2, ner: list | None = None, masker=mask) -> BenchReport:
    """A value counts as found when one detection, of any kind, covers all of it. masker(text, detections, markers)
    returns the masked text; the real one by default. People and organizations are skipped without NER: no detector runs for them."""
    names_measured = bool(ner)
    categories = [c for c in CATEGORIES if names_measured or c not in ("people", "organizations")]
    hits, totals, false_pos = Counter(), Counter(), Counter()
    tallies: dict[str, _Tally] = defaultdict(_Tally)
    for doc in docs:
        tally = tallies[doc.lang]
        started = perf_counter()
        found = detect(doc.text, level=level, ner=ner)
        markers = MarkerMap()
        masked = masker(doc.text, found, markers)
        tally.ms.append((perf_counter() - started) * 1000)
        restored = restore(masked, markers)
        tally.restore_errors += restored.text != doc.text
        tally.ambiguous += len(restored.suspicious)
        missed = False
        for start, end, kind in doc.labels:
            if kind in NAME_KINDS and not names_measured:
                continue
            covered = any(d.start <= start and end <= d.end for d in found)
            totals[kind] += 1
            hits[kind] += covered
            if category := CATEGORY_OF.get(kind):
                tally.values[category] += 1
                tally.misses[category] += not covered
            missed |= not covered and kind in CRITICAL
        for d in found:
            if not any(d.start < end and start < d.end for start, end, _ in doc.labels):
                false_pos[d.kind] += 1
                tally.false_positives += 1
        tally.docs += 1
        tally.critical_miss_docs += missed
    return BenchReport(
        docs=len(docs),
        docs_with_critical_miss=sum(t.critical_miss_docs for t in tallies.values()),
        level=level,
        ner=names_measured,
        by_lang={lang: tallies[lang].report(categories) for lang in sorted(tallies)},
        recall_by_kind={kind: round(hits[kind] / n, 4) for kind, n in sorted(totals.items())},
        false_positives_by_kind=dict(sorted(false_pos.items())),
    )


def _load_ner() -> list:
    """The detectors a boxed.toml with ner = ["ru", "en"] loads: extras ner-ru and ner-en, models from the local cache."""
    from boxed.config import ProjectConfig, to_detect_config

    return to_detect_config(ProjectConfig(ner=["ru", "en"])).ner


def _write_private(path: Path, text: str) -> None:
    """A part file moved into place with os.replace, mode 600: a crash never leaves half a report."""
    part = path.with_name(path.name + ".part")
    part.unlink(missing_ok=True)
    fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(part, path)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run boxed-bench on synthetic documents")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--docs", type=int, default=500)
    parser.add_argument("--level", type=int, default=2)
    parser.add_argument("--ner", action="store_true", help="also measure people and organizations (extras ner-ru and ner-en)")
    parser.add_argument("--json", metavar="PATH", help="write the report to this file instead of printing it")
    args = parser.parse_args(argv)
    ner = None
    if args.ner:
        try:
            ner = _load_ner()
        except Exception as error:  # a model that does not load must not turn into rules-only numbers under an NER label
            print(f"bench: NER did not load ({type(error).__name__}); is it installed (extras ner-ru, ner-en) and cached?", file=sys.stderr)
            print("bench: nothing was measured", file=sys.stderr)
            raise SystemExit(2) from None
    report = evaluate(generate(args.seed, args.docs), level=args.level, ner=ner)
    text = json.dumps({"seed": args.seed, **asdict(report)}, indent=2, ensure_ascii=False)
    if args.json:
        _write_private(Path(args.json), text + "\n")
    else:
        print(text)


if __name__ == "__main__":
    main()
