"""Run by test_ner_words.py in a process of its own, not collected as a test: does a real tokenizer keep the words it has split?

The tokenizers library caches every distinct word it splits, in native memory that Python cannot look into. This process looks at
its own memory instead (macOS, through the Mach VM calls), for a marker that every word starts with, after 40 texts of two words
have gone through a tiny but real Unigram tokenizer:

  control  - the words go through the tokenizer on their own: the cache keeps them, so the marker is found 80 times
  shipped  - they go through GlinerDetector.find: the marker is found only if the detector leaves its words in the cache

It prints {"mode": ..., "marker_runs": n}. The marker is built here and never written down, and the pattern that looks for it is
one escaped byte after the other, so that neither stands in memory as the bytes the scan looks for.
"""

import ctypes
import gc
import json
import os
import random
import re
import string
import sys
import types

from tokenizers import Tokenizer, models

from boxed.detect.ner import GlinerDetector

_lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
_task = ctypes.c_uint.in_dll(_lib, "mach_task_self_").value
_region = _lib.mach_vm_region
_region.argtypes = [
    ctypes.c_uint, ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64), ctypes.c_int,
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32),
]
_region.restype = ctypes.c_int
_read = _lib.mach_vm_read_overwrite
_read.argtypes = [ctypes.c_uint, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64)]
_read.restype = ctypes.c_int

CHUNK = 4 << 20
OVERLAP = 64  # a marker is shorter than this, so a run that crosses two chunks is seen in the second
_buffer = ctypes.create_string_buffer(CHUNK)
_buffer_at = ctypes.addressof(_buffer)
_view = memoryview(_buffer).cast("B")


def _regions():
    """(start, size) of every region of memory that is readable, writable and not shared."""
    at = ctypes.c_uint64(0)
    while True:
        size = ctypes.c_uint64(0)
        info = (ctypes.c_uint8 * 64)()
        count = ctypes.c_uint32(9)
        obj = ctypes.c_uint32(0)
        if _region(_task, ctypes.byref(at), ctypes.byref(size), 9, ctypes.addressof(info), ctypes.byref(count), ctypes.byref(obj)) != 0:
            return
        protection = int.from_bytes(bytes(info[0:4]), "little")
        shared = int.from_bytes(bytes(info[12:16]), "little")
        if protection & 1 and protection & 2 and not shared and size.value < (4 << 30):
            yield at.value, size.value
        at.value += size.value


def _without_buffer(start, size):
    """The scan buffer holds a copy of whatever it has read last: it is not looked at."""
    low, high, end = _buffer_at, _buffer_at + CHUNK, start + size
    if end <= low or start >= high:
        return [(start, size)]
    return ([(start, low - start)] if start < low else []) + ([(high, end - high)] if end > high else [])


def runs_of(pattern):
    found = 0
    for region, region_size in _regions():
        for start, size in _without_buffer(region, region_size):
            at = 0
            while at < size:
                take = min(CHUNK, size - at)
                got = ctypes.c_uint64(0)
                if _read(_task, start + at, take, _buffer_at, ctypes.byref(got)) == 0 and got.value:
                    found += sum(1 for _ in pattern.finditer(_view[: got.value]))
                if at + take >= size:
                    break
                at += take - OVERLAP
    return found


def churn():
    """Allocates and frees objects of many sizes, so that memory freed earlier is reused and written over."""
    held = []
    for size in (16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 1024, 4096, 16384, 65536):
        for _ in range(max(50, 2_000_000 // (size * 4))):
            held.append(bytearray(os.urandom(min(size, 64)) * (size // 64 + 1)))
        held.clear()


LETTERS = "".join(map(chr, range(0x430, 0x450)))  # Cyrillic: Python holds such a text as two-byte characters, the tokenizer as UTF-8
MARKER = "".join(map(chr, (0x416, 0x437, 0x42F, 0x44A, 0x429, 0x44D, 0x416, 0x437)))
PATTERN = re.compile(b"(?:)".join(re.escape(bytes([byte])) for letter in MARKER for byte in letter.encode()))

tokenizer = Tokenizer(models.Unigram([("<unk>", 0.0)] + [(c, -2.0) for c in LETTERS + LETTERS.upper() + string.ascii_letters], unk_id=0))


class Model:
    """What GlinerDetector reaches into, with a real tokenizer behind it; reading a text sends its words through the tokenizer."""

    data_processor = types.SimpleNamespace(
        transformer_tokenizer=types.SimpleNamespace(backend_tokenizer=types.SimpleNamespace(model=tokenizer.model))
    )

    def predict_entities(self, text, labels, threshold):
        tokenizer.encode(text.split(), is_pretokenized=True)
        return []


def texts(seed, n=40):
    rnd = random.Random(seed)
    return [f"{MARKER}{''.join(rnd.choice(LETTERS) for _ in range(9))} {MARKER}{''.join(rnd.choice(LETTERS) for _ in range(7))}" for _ in range(n)]


mode = sys.argv[1]
if mode == "control":
    for text in texts(1):
        Model().predict_entities(text, [], 0.5)
elif mode == "shipped":
    detector = GlinerDetector(model=Model())
    for text in texts(2):
        detector.find(text)
else:
    raise SystemExit(f"unknown mode {mode!r}")
gc.collect()
churn()
gc.collect()
print(json.dumps({"mode": mode, "marker_runs": runs_of(PATTERN)}))
