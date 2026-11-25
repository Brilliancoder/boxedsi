"""Replace detections with typed markers and restore them exactly."""

import json
import os
import re
import sys
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field

from .detect import KINDS_BY_LEVEL, DetectConfig, Detection, detect

MARKER_RE = re.compile(r"\[([A-Z][A-Z0-9_]*)_(\d+)\]")
LITERAL = "LITERAL"
MAX_FOREIGN = 10_000  # marker-like tokens of other kinds that a scope remembers, see MarkerMap.reserve
MAX_TOKEN = 100  # the longest a remembered token is: a kind name of 80 characters, an underscore, a number of 15 digits
# kinds boxed itself uses; marker-like tokens of other kinds ([GPIO_12], an INI [SERVER_1]) are plain text
BOXED_KINDS = frozenset().union(*KINDS_BY_LEVEL.values()) | {LITERAL}
_LOOSE_BRACKETED = re.compile(r"(?i)\[([a-z][a-z0-9_]*)_(\d+)\]")
# half-broken markers: one bracket, "-" or " " for "_", spaces inside; without brackets only upper case counts
_NEAR = re.compile(
    r"(?<![A-Za-z0-9_])(?:\[\s*(?P<k1>[A-Za-z][A-Za-z0-9_]*?)[_\- ](?P<n1>\d+)\s*\]?"
    r"|(?P<k2>[A-Za-z][A-Za-z0-9_]*?)[_\- ](?P<n2>\d+)\s*\]"
    r"|(?P<k3>[A-Z][A-Z0-9_]*?)[_\-](?P<n3>\d+))(?![A-Za-z0-9_])"
)


class MarkerMap:
    """Markers of one scope: the same original string always gets the same marker."""

    def __init__(self) -> None:
        self._by_original: dict[str, str] = {}
        self._by_marker: dict[str, tuple[str, str]] = {}
        self._counters: Counter[str] = Counter()
        self._foreign: set[str] = set()  # marker-like tokens of the scope's texts that are none of ours, see reserve

    def reserve(self, token: str) -> bool:
        """A marker-like token of a text that boxed did not make ("[CLIENT_1]" while CLIENT is nobody's kind) is never issued
        in this scope, so a kind that joins the dictionary later cannot make a restore turn that token into an original.

        A scope remembers at most MAX_FOREIGN tokens, the oldest: the map is stored whole, and a text can hold any number of them.
        Past the cap, and for a token longer than MAX_TOKEN characters (no marker is), nothing is remembered and False is
        returned: a kind that joins the dictionary later may then issue that number, as it could before tokens were remembered."""
        if token in self._foreign:
            return True
        if len(self._foreign) >= MAX_FOREIGN or len(token) > MAX_TOKEN:
            return False
        self._foreign.add(token)
        return True

    def marker_for(self, kind: str, original: str) -> str:
        existing = self._by_original.get(original)
        if existing:
            return existing
        number = self._counters[kind] + 1
        while f"[{kind}_{number}]" in self._foreign:
            number += 1
        self._counters[kind] = number
        marker = f"[{kind}_{number}]"
        self._by_original[original] = marker
        self._by_marker[marker] = (kind, original)
        return marker

    def original_for(self, marker: str) -> str | None:
        entry = self._by_marker.get(marker)
        return entry[1] if entry else None

    def kinds(self) -> set[str]:
        """Every kind with an issued marker: the counters hold exactly those, so this does not walk the markers (it runs
        once per text, and a large table has hundreds of thousands)."""
        return {kind for kind, count in self._counters.items() if count > 0}

    def items(self) -> list[tuple[str, str, str]]:
        return [(marker, kind, original) for marker, (kind, original) in self._by_marker.items()]

    def to_json(self) -> str:
        data = {"version": 1, "items": self.items()}
        if self._foreign:  # a map without any is stored as it always was
            data["foreign"] = sorted(self._foreign)
        return json.dumps(data, ensure_ascii=False)

    @classmethod
    def from_json(cls, s: str) -> "MarkerMap":
        m = cls()
        data = json.loads(s)
        for marker, kind, original in data["items"]:
            m._by_original[original] = marker
            m._by_marker[marker] = (kind, original)
            number = int(MARKER_RE.fullmatch(marker).group(2))
            m._counters[kind] = max(m._counters[kind], number)
        m._foreign = set(data.get("foreign", ()))
        return m


def _spans(text: str, detections: list[Detection], literal_kinds: frozenset[str]) -> list[tuple[int, int, str]]:
    """Detections plus pre-existing markers of literal_kinds; overlapping spans merge, a detection's kind wins."""
    raw = [(d.start, d.end, d.kind) for d in detections]
    # any case and leading zeros too: [email_7] in an original must round-trip, not come back "suspicious"
    raw += [(m.start(), m.end(), LITERAL) for m in _LOOSE_BRACKETED.finditer(text) if m.group(1).upper() in literal_kinds]
    raw.sort(key=lambda s: (s[0], -s[1]))
    merged: list[list] = []
    for start, end, kind in raw:
        if merged and start < merged[-1][1]:
            last = merged[-1]
            last[1] = max(last[1], end)
            if last[2] == LITERAL:
                last[2] = kind
        else:
            merged.append([start, end, kind])
    return [(s, e, k) for s, e, k in merged]


def dictionary_kinds(config) -> frozenset[str]:
    """Kinds of a project dictionary (DetectConfig or ProjectConfig), upper-cased the way the detector names them."""
    return frozenset(kind.upper() for kind in config.dictionary.values()) if config else frozenset()


_MAX_DIGITS = 4000


def _is_a_number(digits: str) -> bool:
    """Whether int() takes the digits of a marker number. A text can hold more of them than the interpreter converts (4,300 by
    default) and a marker never does: such a token is plain text, left alone and not reported."""
    limit = sys.get_int_max_str_digits()  # 0: no limit
    return len(digits) <= (min(limit, _MAX_DIGITS) if limit else _MAX_DIGITS)


def _foreign_tokens(text: str, literal_kinds: frozenset[str]) -> Iterator[str]:
    """The markers as restore would read them ("[CLIENT_1]", no leading zero) whose kind is none of literal_kinds, one at a time.
    The digits are not converted to a number: a text can hold more of them than int() will take."""
    for m in MARKER_RE.finditer(text):
        if m.group(1) not in literal_kinds and (m.group(2)[0] != "0" or m.group(2) == "0") and m.end() - m.start() <= MAX_TOKEN:
            yield m.group(0)


def mask(text: str, detections: list[Detection], markers: MarkerMap, kinds: frozenset[str] = frozenset()) -> str:
    """kinds: extra kinds (from the project dictionary) whose marker-like strings must round-trip as LITERAL.

    A marker-like string of any other kind stays as it is, and the scope remembers it: should its kind join the dictionary
    later, no original gets that marker, so the string cannot be restored to one. A scope remembers at most MAX_FOREIGN."""
    literal_kinds = BOXED_KINDS | markers.kinds() | kinds
    for token in _foreign_tokens(text, literal_kinds):
        if not markers.reserve(token):  # the scope is full: nothing more of this text can be remembered
            break
    out, pos = [], 0
    for start, end, kind in _spans(text, detections, literal_kinds):
        out.append(text[pos:start])
        out.append(markers.marker_for(kind, text[start:end]))
        pos = end
    out.append(text[pos:])
    return "".join(out)


def mask_text(
    text: str, markers: MarkerMap, level: int = 2, config: DetectConfig | None = None
) -> tuple[str, dict[str, int]]:
    detections = detect(text, level=level, config=config)
    kinds = dictionary_kinds(config)
    counts = Counter(kind for _, _, kind in _spans(text, detections, BOXED_KINDS | markers.kinds() | kinds))
    return mask(text, detections, markers, kinds), dict(counts)


def _mask_name(name: str, markers: MarkerMap, level: int, config: DetectConfig | None) -> tuple[str, dict[str, int]]:
    """Rules only: NER takes README for a company. "_" and "-" glue words in names, so they are also read as spaces."""
    found = []
    for variant in {name, name.replace("_", " "), name.replace("_", " ").replace("-", " ")}:  # same length, same offsets
        found += detect(variant, level=level, config=config, ner=[])
    kinds = dictionary_kinds(config)
    counts = Counter(kind for _, _, kind in _spans(name, found, BOXED_KINDS | markers.kinds() | kinds))
    return mask(name, found, markers, kinds), dict(counts)


def mask_path(rel: str, markers: MarkerMap, level: int = 2, config: DetectConfig | None = None) -> tuple[str, dict[str, int]]:
    """Mask every name of a relative path; the extension stays visible when the part before it holds the finding."""
    names, counts = [], Counter()
    for name in rel.split("/"):
        stem, suffix = os.path.splitext(name)
        plain_suffix = suffix and not _LOOSE_BRACKETED.search(suffix)  # a marker-like suffix must be masked with the name
        masked, found = _mask_name(stem, markers, level, config) if plain_suffix else (name, {})
        if found:
            masked += suffix
        else:
            masked, found = _mask_name(name, markers, level, config)
        names.append(masked)
        counts.update(found)
    return "/".join(names), dict(counts)


@dataclass
class RestoreResult:
    text: str
    restored: int
    unknown: list[str] = field(default_factory=list)
    suspicious: list[str] = field(default_factory=list)


def restore(text: str, markers: MarkerMap, kinds: frozenset[str] = frozenset()) -> RestoreResult:
    """kinds: dictionary kinds, so a missing [CLIENT_1] is reported even when the map holds no CLIENT yet."""
    unknown: list[str] = []
    restored = 0

    def replace(m: re.Match[str]) -> str:
        nonlocal restored
        original = markers.original_for(m.group(0))
        if original is not None and m.group(0) == f"[{m.group(1)}_{int(m.group(2))}]":
            restored += 1
            return original
        return m.group(0)

    out = MARKER_RE.sub(replace, text)

    known = markers.kinds()
    anomalies: list[tuple[int, str]] = []
    for m in _LOOSE_BRACKETED.finditer(text):
        if not _is_a_number(m.group(2)):
            continue
        kind, canonical = m.group(1).upper(), f"[{m.group(1).upper()}_{int(m.group(2))}]"
        if m.group(0) == canonical:
            if markers.original_for(canonical) is None and (kind in BOXED_KINDS or kind in known or kind in kinds):
                unknown.append(m.group(0))
        elif kind in known:
            anomalies.append((m.start(), m.group(0)))
    blanked = _LOOSE_BRACKETED.sub(lambda m: " " * len(m.group(0)), text)  # whole bracketed forms are handled above
    for m in _NEAR.finditer(blanked):
        if (m.group("k1") or m.group("k2") or m.group("k3")).upper() in known:
            anomalies.append((m.start(), m.group(0)))
    suspicious = [s for _, s in sorted(anomalies)]
    return RestoreResult(text=out, restored=restored, unknown=unknown, suspicious=suspicious)
