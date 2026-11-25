"""Observation mode: what went to a chat site without boxed. The journal keeps kinds, counts and a hash, never the text."""

import hashlib
import hmac
from collections import Counter
from pathlib import Path

from . import __version__
from .detect import DetectConfig, detect
from .journal import Journal, JournalEntry
from .keys import KeyStore

SITES = ("chatgpt", "claude", "gemini", "deepseek", "zai")
COVERAGE = ("checked", "not checked")
# Observation counts what level 2 finds: secrets, personal data, names and hosts. Level 3 adds amounts, dates, percentages and
# numbers, which nearly every text has and which leak nothing by themselves: counted, they would bury the real findings.
COUNT_LEVEL = 2
HASH_KEY = "observe-hmac"  # the key store name of the key that hashes observed texts


class ObservedJournal(Journal):
    """observed.jsonl: the main journal's signed chain, and the key that hashes the texts it counts."""

    def __init__(self, path: Path, keys: KeyStore) -> None:
        super().__init__(path, keys)
        self._hash_key = keys.get_or_create(HASH_KEY, 32)

    def payload_hash(self, payload: bytes) -> str:
        """HMAC-SHA256, not a bare hash: a short text (a prompt that is one phone number) is found from a bare hash by
        trying every candidate. The key stays in the key store, so only this device can match a hash to a text."""
        return hmac.new(self._hash_key, payload, hashlib.sha256).hexdigest()


def observed_journal(home: Path, keys: KeyStore) -> ObservedJournal:
    """observed.jsonl beside the main journal: the same device key signs it, and the two are never mixed."""
    return ObservedJournal(home / "observed.jsonl", keys)


def observe(text: str, site: str, coverage: str, journal: ObservedJournal, config: DetectConfig | None) -> dict[str, int]:
    """Count the findings in a send boxed did not make and journal them. `not checked` is a send whose text could not be read."""
    if site not in SITES or coverage not in COVERAGE or (coverage == "not checked" and text):
        raise ValueError("bad observation")  # a fixed text: the arguments come from a web page
    try:
        payload = text.encode()
    except UnicodeEncodeError:  # a lone surrogate (a cut emoji): no tool can read this text, so it was not checked
        text, payload, coverage = "", b"", "not checked"
    found = dict(Counter(d.kind for d in detect(text, COUNT_LEVEL, config)))
    journal.append(
        JournalEntry(
            channel="observed",
            provider=site,
            account_type="unknown",
            level=0,
            markers_by_kind=found,
            status="sent",
            payload_sha256=journal.payload_hash(payload),  # the field keeps its name; here it holds the keyed hash
            coverage=coverage,
            scope="",
            versions={"boxed": __version__},
        )
    )
    return found
