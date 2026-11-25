"""What the tokenizer of GLiNER keeps of the texts it has read.

The tokenizers library caches every distinct word it splits - a name, a whole API key - in native memory, for as long as the
tokenizer lives. A program that stays up for as long as a panel is used (the native host) must not keep them, so the detector
empties that cache after every text. The call is a private one of the library: when it is not there, the detector says so
(words_kept), and a program that can end does.
"""

import gc
import json
import subprocess
import sys
import weakref
from pathlib import Path
from types import SimpleNamespace

import pytest

from boxed.detect import ner
from boxed.detect.ner import GlinerDetector, words_kept

PROBE = Path(__file__).with_name("word_cache_probe.py")
SPAN = {"start": 0, "end": 11, "label": "person", "text": "Ivan Petrov", "score": 0.9}


@pytest.fixture(autouse=True)
def alone(monkeypatch):
    """A detector that another test left alive must not decide what words_kept() says here."""
    monkeypatch.setattr(ner, "_loaded", weakref.WeakSet())


class Cache:
    """The model of a tokenizer as far as the detector reaches it: it holds the words it has split until it is emptied."""

    def __init__(self):
        self.words = set()
        self.emptied = 0

    def _clear_cache(self):
        self.emptied += 1
        self.words.clear()


def gliner(cache, fail=None):
    """A GLiNER whose tokenizer is `cache`: reading a text puts its words there, as the real one does."""

    def predict_entities(text, labels, threshold):
        cache.words.update(text.split())
        if fail:
            raise fail
        return [SPAN]

    tokenizer = SimpleNamespace(backend_tokenizer=SimpleNamespace(model=cache))
    return SimpleNamespace(data_processor=SimpleNamespace(transformer_tokenizer=tokenizer), predict_entities=predict_entities)


def test_the_cache_of_words_is_empty_after_every_text():
    cache = Cache()
    detector = GlinerDetector(model=gliner(cache))
    assert [(d.kind, d.text) for d in detector.find("Ivan Petrov has key sk_live_AB12CD34")] == [("PERSON", "Ivan Petrov")]
    assert cache.words == set() and cache.emptied == 1
    detector.find("A second text, with other words")
    assert cache.words == set() and cache.emptied == 2
    assert not words_kept()


def test_the_cache_is_emptied_when_reading_the_text_fails():
    cache = Cache()
    detector = GlinerDetector(model=gliner(cache, fail=RuntimeError("out of memory")))
    with pytest.raises(RuntimeError, match="out of memory"):
        detector.find("Ivan Petrov has key sk_live_AB12CD34")
    assert cache.words == set() and cache.emptied == 1
    assert not words_kept()


class NoWay:
    """A tokenizer model that has no way to empty its cache: the library changed."""

    def __init__(self):
        self.words = set()


class Refuses(Cache):
    def _clear_cache(self):
        raise RuntimeError("the cache is locked")


NO_TOKENIZER = SimpleNamespace(predict_entities=lambda text, labels, threshold: [SPAN])


@pytest.mark.parametrize(
    "model",
    [
        pytest.param(NO_TOKENIZER, id="no tokenizer to reach"),
        pytest.param(gliner(NoWay()), id="no call to empty the cache"),
        pytest.param(gliner(Refuses()), id="the call fails"),
    ],
)
def test_a_cache_that_cannot_be_emptied_is_reported_and_the_text_is_still_read(model):
    detector = GlinerDetector(model=model)
    assert not words_kept()  # nothing has been read yet
    assert [(d.kind, d.text) for d in detector.find("Ivan Petrov signed")] == [("PERSON", "Ivan Petrov")]
    assert words_kept()
    del detector
    gc.collect()
    assert not words_kept()  # it is about the detectors that are alive


@pytest.mark.skipif(sys.platform != "darwin", reason="reads the memory of its own process with the Mach VM calls of macOS")
def test_a_real_tokenizer_holds_no_word_once_the_detector_has_read_it():
    pytest.importorskip("tokenizers")

    def marker_runs(mode):
        done = subprocess.run([sys.executable, "-P", str(PROBE), mode], capture_output=True, text=True, timeout=120)
        assert done.returncode == 0, done.stderr
        return json.loads(done.stdout)["marker_runs"]

    assert marker_runs("control") >= 60  # the probe script does see a cache that is kept: 40 texts of two words
    assert marker_runs("shipped") <= 4  # leftovers of freed memory are not the cache; a cache that is kept holds all 80
