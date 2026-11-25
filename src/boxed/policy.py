"""Category plus recipient policy: what may go to which recipient, decided before masking."""

import re
from collections.abc import Iterable
from dataclasses import dataclass

from .detect import KINDS_BY_LEVEL
from .errors import UserError, one_of
from .mask import LITERAL

CATEGORIES = ("secrets", "personal", "clients", "finance", "code", "strategy", "hr", "health")
RECIPIENT_KINDS = ("personal-training", "personal-private", "corporate", "api-zero-retention", "local")
PROFILES = ("no-rules", "no-confidential", "approved-only", "ban")
DEFAULT_PROFILE = "no-rules"  # what an employer who has set nothing means
VERDICTS = ("allow", "masked", "local-only", "deny")  # in this order of strictness; "masked" with a higher level is stricter
# the EU member states, IS, LI, NO and the region codes
EEA = frozenset("AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE IS LI NO EU EEA".split())
PERSONAL_DATA = frozenset({"personal", "hr", "health"})  # categories that hold personal data in the legal sense
# the keys and rules a policy can hold, by name: an error names one of these only after it was found here
KEY_NAMES = {(category, kind): f"{category}:{kind}" for category in CATEGORIES for kind in RECIPIENT_KINDS}
RULE_NAMES = {name: name for name in ("allow", "local-only", "deny", *(f"masked:{level}" for level in KINDS_BY_LEVEL))}


class PolicyError(UserError):
    """A policy that cannot be used, in fixed words: never a key, a rule or a category the person wrote."""


@dataclass(frozen=True)
class Rule:
    verdict: str
    min_level: int | None = None  # only for "masked"

    def __post_init__(self) -> None:
        if self.verdict not in VERDICTS:
            raise PolicyError(f"unknown verdict, expected one of {one_of(VERDICTS)}")  # never the value: errors quote none
        if self.verdict == "masked":
            if type(self.min_level) is not int or self.min_level not in KINDS_BY_LEVEL:  # True and 2.0 equal levels
                raise PolicyError(f"[boxed.policy.rules] masked needs a level {min(KINDS_BY_LEVEL)}-{max(KINDS_BY_LEVEL)}")
        elif self.min_level is not None:
            raise PolicyError("only masked takes a level")

    def __str__(self) -> str:
        return f"masked:{self.min_level}" if self.verdict == "masked" else self.verdict


def _strictness(rule: Rule) -> tuple[int, int]:
    return VERDICTS.index(rule.verdict), rule.min_level or 0


_MASKED = re.compile(r"masked:([0-9])")  # not \d: it takes the digits of every script


def _parse_rule(text: str) -> Rule:
    if text in ("allow", "local-only", "deny"):
        return Rule(text)
    match = _MASKED.fullmatch(text) if isinstance(text, str) else None  # a TOML value can be any type
    if not match:
        raise PolicyError("[boxed.policy.rules] a bad rule, expected allow, masked:0-4, local-only or deny")
    return Rule("masked", int(match.group(1)))


def _parse_key(key: str) -> tuple[str, str]:
    category, _, kind = key.partition(":")
    if category not in CATEGORIES or kind not in RECIPIENT_KINDS:
        raise PolicyError(
            f"[boxed.policy.rules] a key is not <category>:<recipient> with category in {one_of(CATEGORIES)} "
            f"and recipient in {one_of(RECIPIENT_KINDS)}"
        )
    return category, kind


# The profile matrices: one row per category, one column per recipient kind except "local",
# which allows everything in every profile. Secrets are masked at level 0 or stricter for every other recipient, and
# finance at level 3 or stricter: the amounts it is found by stay visible below that (the table of levels in docs/guide/concepts.md). Strategy has the rule of
# finance in every profile, since docs/security/policy-clause.md asks the same of both: level 3 or higher. HR is masked at
# level 3 too, where the table of levels lists it with finance, sales and strategy, and health has the rule of hr in every profile:
# special-category data does not sit below HR.
_COLUMNS = tuple(kind for kind in RECIPIENT_KINDS if kind != "local")  # personal-training, personal-private, corporate, api
_MATRICES = {
    "no-rules": {
        "secrets": ("masked:0", "masked:0", "masked:0", "masked:0"),
        "personal": ("masked:1", "masked:1", "allow", "allow"),
        "clients": ("masked:2", "masked:2", "allow", "allow"),
        "finance": ("masked:3", "masked:3", "allow", "allow"),
        "code": ("allow", "allow", "allow", "allow"),
        "strategy": ("masked:3", "masked:3", "allow", "allow"),
        "hr": ("masked:3", "masked:3", "allow", "allow"),
        "health": ("masked:3", "masked:3", "allow", "allow"),
    },
    "no-confidential": {
        "secrets": ("masked:0", "masked:0", "masked:0", "masked:0"),
        "personal": ("masked:1", "masked:1", "masked:1", "masked:1"),
        "clients": ("masked:2", "masked:2", "masked:2", "masked:2"),
        "finance": ("masked:3", "masked:3", "masked:3", "masked:3"),
        "code": ("masked:2", "allow", "allow", "allow"),
        "strategy": ("masked:3", "masked:3", "masked:3", "masked:3"),
        "hr": ("local-only", "local-only", "masked:3", "masked:3"),
        "health": ("local-only", "local-only", "masked:3", "masked:3"),
    },
    "approved-only": {
        "secrets": ("deny", "deny", "masked:0", "masked:0"),
        "personal": ("deny", "deny", "masked:1", "masked:1"),
        "clients": ("deny", "deny", "masked:2", "masked:2"),
        "finance": ("deny", "deny", "masked:3", "masked:3"),
        "code": ("masked:2", "masked:2", "allow", "allow"),
        "strategy": ("deny", "deny", "masked:3", "masked:3"),
        "hr": ("deny", "deny", "masked:3", "masked:3"),
        "health": ("deny", "deny", "masked:3", "masked:3"),
    },
    "ban": {category: ("deny",) * len(_COLUMNS) for category in CATEGORIES},
}


class Policy:
    """One rule for every pair of category and recipient kind; users may only tighten it."""

    def __init__(self, rules: dict[tuple[str, str], Rule]) -> None:
        self._rules = dict(rules)

    @classmethod
    def from_profile(cls, name: str) -> "Policy":
        if name not in PROFILES:
            raise PolicyError(f"unknown profile, expected one of {one_of(PROFILES)}")
        rules = {(category, "local"): Rule("allow") for category in CATEGORIES}
        for category, row in _MATRICES[name].items():
            for kind, text in zip(_COLUMNS, row, strict=True):
                rules[(category, kind)] = _parse_rule(text)
        return cls(rules)

    @classmethod
    def from_config(cls, table: dict) -> "Policy":
        """The [boxed.policy] table: {"profile": "...", "rules": {"finance:personal-private": "deny" | "masked:3" | ...}}."""
        if set(table) - {"profile", "rules"}:
            raise PolicyError("[boxed.policy] has a key boxed does not know; the known ones are profile, rules")
        rules = table.get("rules", {})
        if not isinstance(rules, dict):
            raise PolicyError("[boxed.policy].rules must be a table")
        overrides = {_parse_key(key): _parse_rule(text) for key, text in rules.items()}  # the errors name no key: it is the person's
        return cls.from_profile(table.get("profile", DEFAULT_PROFILE)).tighten(overrides)

    def rule(self, category: str, recipient_kind: str) -> Rule:
        try:
            return self._rules[(category, recipient_kind)]
        except KeyError:
            raise PolicyError("no rule for this category and recipient kind") from None

    def tighten(self, overrides: dict[tuple[str, str], Rule]) -> "Policy":
        rules = dict(self._rules)
        for (category, kind), rule in overrides.items():
            current = self.rule(category, kind)
            if _strictness(rule) < _strictness(current):
                raise PolicyError(  # the key and the rules are known ones here: named from the closed tables
                    f"[boxed.policy.rules] {KEY_NAMES[(category, kind)]}: {RULE_NAMES[str(rule)]} is looser than "
                    f"{RULE_NAMES[str(current)]}, a policy can only be tightened"
                )
            rules[(category, kind)] = rule
        return Policy(rules)


# Detector kinds by category. strategy, hr and health have no detector: the caller adds them. finance has the amounts that
# level 3 finds and the cryptocurrency addresses of level 2; the percentages, dates and numbers of level 3 are no category of
# their own.
_CATEGORY_KINDS = {
    "secrets": ("SECRET", "PRIVATE_KEY", "JWT", "CARD"),
    "personal": ("EMAIL", "PHONE", "PERSON", "INN", "SNILS", "IBAN", "PASSPORT", "SSN"),
    "clients": ("ORG", "VAT_ID"),
    "finance": ("MONEY", "CRYPTO_ADDR"),
    "code": ("HOST", "URL", "IP"),
}
NEUTRAL_KINDS = frozenset({"PERCENT", "DATE", "NUMBER"})  # detected, but they put no category on a text
_KIND_CATEGORY = {kind: category for category, kinds in _CATEGORY_KINDS.items() for kind in kinds}


def categories_for(kinds: Iterable[str], dictionary_kinds: Iterable[str] = ()) -> set[str]:
    """Categories of detected kinds; dictionary_kinds are the kinds of the project dictionary (clients)."""
    dictionary = set(dictionary_kinds)
    found: set[str] = set()
    for kind in kinds:
        if kind in dictionary:
            found.add("clients")
        if kind in _KIND_CATEGORY:
            found.add(_KIND_CATEGORY[kind])
        elif kind not in dictionary and kind != LITERAL and kind not in NEUTRAL_KINDS:
            raise PolicyError("a kind of data has no category of the policy")  # fail closed: an unmapped kind must not pass as allowed
    return found


@dataclass(frozen=True)
class Recipient:
    provider: str  # "openai", "anthropic", "google", "deepseek", "zai", "openrouter", "local", ...
    kind: str  # one of RECIPIENT_KINDS
    jurisdiction: str  # "US", "EU", "CN", "SG", "local", ...

    def __post_init__(self) -> None:
        if self.kind not in RECIPIENT_KINDS:
            raise PolicyError(f"unknown recipient kind, expected one of {one_of(RECIPIENT_KINDS)}")


@dataclass
class Decision:
    verdict: str
    min_level: int | None  # only with "masked"
    reasons: list[str]  # "finance for personal-private: masked at level 3"
    warnings: list[str]


_PHRASES = {"masked": "masked at level {level}", "local-only": "local only", "deny": "denied"}


def _warnings(categories: set[str], recipient: Recipient) -> list[str]:
    region = recipient.jurisdiction.upper()  # "cn" and "us" typed by hand must not slip past the checks
    on_this_computer = recipient.kind == "local" and region == "LOCAL"  # the word as the jurisdiction of another kind means nothing
    warnings = []
    if PERSONAL_DATA.intersection(categories) and region not in EEA and not on_this_computer:
        warnings.append("personal data leaves the EEA: this needs a legal basis, masking does not replace it")
    if recipient.kind == "personal-training":
        warnings.append("this account may train on chats")
    if region == "CN":
        warnings.append("data is stored in China")
    return warnings


def decide(categories: set[str], recipient: Recipient, policy: Policy) -> Decision:
    categories = set(categories)  # a one-shot iterable must not be drained before the rules see it
    unknown = categories - set(CATEGORIES)
    if unknown:
        raise PolicyError(f"unknown category, expected one of {one_of(CATEGORIES)}")
    rules = {category: policy.rule(category, recipient.kind) for category in CATEGORIES if category in categories}
    if not rules and all(policy.rule(category, recipient.kind).verdict == "deny" for category in CATEGORIES):
        rules = {"all categories": Rule("deny")}  # nothing sensitive found, but a full ban stays a ban
    strictest = max(rules.values(), key=_strictness, default=Rule("allow"))
    reasons = [
        f"{what} for {recipient.kind}: {_PHRASES[rule.verdict].format(level=rule.min_level)}"
        for what, rule in rules.items()
        if rule.verdict != "allow"
    ]
    return Decision(strictest.verdict, strictest.min_level, reasons, _warnings(categories, recipient))
