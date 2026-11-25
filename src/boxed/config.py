"""Project settings from boxed.toml, section [boxed]."""

import re
import tomllib
from dataclasses import dataclass, field, fields
from functools import lru_cache
from pathlib import Path

from .detect import DetectConfig
from .errors import UserError, number, one_of
from .mask import BOXED_KINDS
from .policy import Policy

CONFIG_NAME = "boxed.toml"


@dataclass
class ProjectConfig:
    level: int = 2
    internal_domains: list[str] = field(default_factory=list)
    dictionary: dict[str, str] = field(default_factory=dict)
    allow: list[str] = field(default_factory=list)
    protected_paths: list[str] = field(default_factory=list)
    mcp_roots: list[str] = field(default_factory=list)
    ner: list[str] = field(default_factory=list)  # "ru" (Natasha), "en" (GLiNER)
    policy: dict = field(default_factory=dict)  # [boxed.policy]: profile and rules, see boxed.policy.Policy.from_config
    source: Path | None = None


_TYPES = {
    "level": int,
    "internal_domains": list,
    "dictionary": dict,
    "allow": list,
    "protected_paths": list,
    "mcp_roots": list,
    "ner": list,
    "policy": dict,
}
NER_NAMES = ("ru", "en")
NOT_UTF8 = CONFIG_NAME + ": not UTF-8 text"
UNKNOWN_KEYS = CONFIG_NAME + ": [boxed] has a key boxed does not know; the known ones are " + ", ".join(_TYPES)
TYPE_ERRORS = {key: f"{CONFIG_NAME}: [boxed].{key} must be {kind.__name__}" for key, kind in _TYPES.items()}
LIST_ERRORS = {key: f"{CONFIG_NAME}: [boxed].{key} must be a list of strings" for key in _TYPES}
TOML_AT = re.compile(r"\(at line (\d+), column (\d+)\)\Z")  # the place tomllib names; the words before it may quote a key


def load_config(start: Path) -> ProjectConfig:
    for directory in [start, *start.parents]:
        path = directory / CONFIG_NAME
        if path.is_file():
            return _parse(path)
    return ProjectConfig()


def read_config(path: Path) -> ProjectConfig:
    """Exactly this boxed.toml, without looking in parent folders; defaults when it does not exist."""
    return _parse(path) if path.is_file() else ProjectConfig()


def _parse(path: Path) -> ProjectConfig:
    """The settings of one boxed.toml. An error names the file by its name and the setting by its key in the closed set of
    _TYPES, never the folder, a value or a key of the person (a term of the dictionary is a client's name); a TOML error keeps
    the place in the file and nothing of its words (tomllib quotes keys)."""
    try:
        text = path.read_bytes().decode("utf-8")  # TOML is UTF-8; the locale's encoding would read a Cyrillic term as other letters
    except UnicodeDecodeError:
        raise UserError(NOT_UTF8) from None  # Python's own message would name a byte of the file
    try:
        section = tomllib.loads(text).get("boxed", {})
    except tomllib.TOMLDecodeError as e:
        at = TOML_AT.search(str(e))
        if at is None:
            raise UserError(CONFIG_NAME + ": not valid TOML") from None
        line, column = int(at.group(1)), int(at.group(2))
        raise UserError(CONFIG_NAME + f": not valid TOML (at line {number(line)}, column {number(column)})") from None
    known = {f.name for f in fields(ProjectConfig)} - {"source"}
    if set(section) - known:
        raise UserError(UNKNOWN_KEYS)
    for key, value in section.items():
        if not isinstance(value, _TYPES[key]) or isinstance(value, bool):
            raise UserError(TYPE_ERRORS[key])
        if _TYPES[key] is list and not all(isinstance(item, str) for item in value):  # which item and what it was stay unsaid
            raise UserError(LIST_ERRORS[key])
        if key == "dictionary" and not all(isinstance(kind, str) for kind in value.values()):  # neither a term (a client's name) nor a value is quoted
            raise UserError(CONFIG_NAME + ": [boxed.dictionary] every kind must be a string, such as CLIENT")
    config = ProjectConfig(**section, source=path)
    if config.level not in range(5):
        raise UserError(CONFIG_NAME + ": [boxed].level must be 0-4")
    if any(n not in NER_NAMES for n in config.ner):
        raise UserError(CONFIG_NAME + f": [boxed].ner takes {one_of(NER_NAMES)}")
    # The detector upper-cases a dictionary kind, so a term of kind "date" would be counted and masked as a DATE. The message
    # names neither the term (it is a client's name) nor the kind.
    if any(kind.upper() in BOXED_KINDS for kind in config.dictionary.values()):
        raise UserError(CONFIG_NAME + ": [boxed.dictionary] a term cannot use a built-in kind name (EMAIL, DATE, NUMBER and the like)")
    Policy.from_config(config.policy)  # a PolicyError is a UserError: its words name [boxed.policy]
    return config


@lru_cache(maxsize=4)
def _ner_detectors(names: tuple[str, ...]) -> tuple:
    from .detect.ner import GlinerDetector, NatashaDetector

    # Natasha leaves Latin names to GLiNER only when GLiNER is there to find them
    factories = {"ru": lambda: NatashaDetector(cyrillic_only="en" in names), "en": GlinerDetector}
    return tuple(factories[n]() for n in names)


def to_detect_config(c: ProjectConfig) -> DetectConfig:
    return DetectConfig(
        internal_domains=list(c.internal_domains),
        dictionary=dict(c.dictionary),
        allow=set(c.allow),
        ner=list(_ner_detectors(tuple(c.ner))) if c.ner else [],
    )
