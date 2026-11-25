import io
import re
from pathlib import Path

import pytest

from boxed.cli import main
from boxed.config import ProjectConfig, load_config
from boxed.detect import KINDS_BY_LEVEL
from boxed.policy import (
    CATEGORIES,
    EEA,
    NEUTRAL_KINDS,
    PERSONAL_DATA,
    PROFILES,
    RECIPIENT_KINDS,
    Decision,
    Policy,
    PolicyError,
    Recipient,
    Rule,
    categories_for,
    decide,
)

PT, PP, CO, API, LO = RECIPIENT_KINDS
DETECTOR_KINDS = set().union(*KINDS_BY_LEVEL.values()) - NEUTRAL_KINDS  # percentages, dates and numbers have no category
LEAVES = "personal data leaves the EEA: this needs a legal basis, masking does not replace it"
TRAINS = "this account may train on chats"
CHINA = "data is stored in China"


def all_rules(policy):
    return {(c, k): policy.rule(c, k) for c in CATEGORIES for k in RECIPIENT_KINDS}


def test_rule_str_uses_the_config_notation():
    rules = [Rule("allow"), Rule("masked", 3), Rule("local-only"), Rule("deny")]
    assert [str(r) for r in rules] == ["allow", "masked:3", "local-only", "deny"]


@pytest.mark.parametrize(
    "args",
    [
        ("nope",),
        ("masked",),
        ("masked", 5),
        ("masked", -1),
        ("allow", 1),
        ("deny", 0),
        ("local-only", 2),
        ("masked", True),  # == 1 and hashes like it, but it is not a level
        ("masked", False),
        ("masked", 2.0),
        ("masked", 0.0),
        ("masked", "2"),
    ],
)
def test_rule_refuses_a_bad_verdict_or_level(args):
    with pytest.raises(PolicyError):
        Rule(*args)


@pytest.mark.parametrize(
    "profile,category,kind,expected",
    [
        ("no-rules", "personal", PT, "masked:1"),
        ("no-rules", "personal", PP, "masked:1"),
        ("no-rules", "personal", CO, "allow"),
        ("no-rules", "personal", API, "allow"),
        ("no-rules", "clients", PP, "masked:2"),
        ("no-rules", "finance", CO, "allow"),
        ("no-rules", "strategy", PT, "masked:3"),  # strategy follows finance, as the policy clause says of both
        ("no-rules", "strategy", PP, "masked:3"),
        ("no-rules", "strategy", CO, "allow"),
        ("no-rules", "hr", PT, "masked:3"),  # hr is a level 3 matter (the table of levels)
        ("no-rules", "health", PT, "masked:3"),  # health follows hr: special-category data does not sit below HR
        ("no-rules", "health", PP, "masked:3"),
        ("no-rules", "health", API, "allow"),
        ("no-rules", "code", PT, "allow"),
        ("no-rules", "secrets", CO, "masked:0"),
        ("no-confidential", "personal", API, "masked:1"),
        ("no-confidential", "clients", CO, "masked:2"),
        ("no-rules", "finance", PT, "masked:3"),  # the figures are masked from level 3 on (the table of levels)
        ("no-rules", "finance", PP, "masked:3"),
        ("no-confidential", "finance", PT, "masked:3"),
        ("no-confidential", "finance", CO, "masked:3"),
        ("no-confidential", "finance", API, "masked:3"),
        ("no-confidential", "strategy", PP, "masked:3"),
        ("no-confidential", "strategy", CO, "masked:3"),
        ("no-confidential", "strategy", API, "masked:3"),
        ("no-confidential", "hr", PP, "local-only"),
        ("no-confidential", "hr", CO, "masked:3"),
        ("no-confidential", "health", PT, "local-only"),
        ("no-confidential", "health", CO, "masked:3"),
        ("no-confidential", "health", API, "masked:3"),
        ("no-confidential", "code", PT, "masked:2"),
        ("no-confidential", "code", PP, "allow"),
        ("no-confidential", "code", API, "allow"),
        ("no-confidential", "secrets", API, "masked:0"),
        ("approved-only", "personal", PT, "deny"),
        ("approved-only", "secrets", PP, "deny"),
        ("approved-only", "hr", PP, "deny"),
        ("approved-only", "finance", PP, "deny"),
        ("approved-only", "code", PT, "masked:2"),
        ("approved-only", "code", PP, "masked:2"),
        ("approved-only", "personal", CO, "masked:1"),
        ("approved-only", "finance", CO, "masked:3"),
        ("approved-only", "finance", API, "masked:3"),
        ("approved-only", "strategy", PT, "deny"),
        ("approved-only", "strategy", CO, "masked:3"),
        ("approved-only", "strategy", API, "masked:3"),
        ("approved-only", "hr", API, "masked:3"),
        ("approved-only", "code", CO, "allow"),
        ("ban", "secrets", CO, "deny"),
        ("ban", "code", API, "deny"),
        ("ban", "personal", PP, "deny"),
        ("ban", "hr", PT, "deny"),
        ("no-rules", "hr", LO, "allow"),
        ("no-confidential", "secrets", LO, "allow"),
        ("approved-only", "health", CO, "masked:3"),
        ("approved-only", "health", API, "masked:3"),
        ("approved-only", "health", LO, "allow"),
        ("ban", "finance", LO, "allow"),
    ],
)
def test_profiles_table(profile, category, kind, expected):
    assert str(Policy.from_profile(profile).rule(category, kind)) == expected


@pytest.mark.parametrize("profile", PROFILES)
def test_every_profile_covers_every_cell_and_local_allows_everything(profile):
    policy = Policy.from_profile(profile)
    all_rules(policy)  # raises on a missing cell
    assert {policy.rule(c, LO) for c in CATEGORIES} == {Rule("allow")}


@pytest.mark.parametrize("profile", PROFILES)
def test_secrets_are_never_allowed_raw_outside_local(profile):
    policy = Policy.from_profile(profile)  # "allow" is the only verdict looser than masked:0
    assert all(policy.rule("secrets", kind).verdict != "allow" for kind in (PT, PP, CO, API))


CLAUSE = Path(__file__).resolve().parents[1] / "docs" / "security" / "policy-clause.md"


def clause_says(pattern, what):
    """The first group of `pattern` in the clause, read from the clause itself. When the clause no longer says `what`, the test
    fails and names it: the test changes with the clause."""
    found = re.search(pattern, CLAUSE.read_text(encoding="utf-8"))
    assert found, f"the policy clause no longer says {what}"
    return found.group(1)


def clause_profile():
    return clause_says(r"company profile \[([a-z-]+)\]", "which profile it is written for")


def sent_at_least_at(rule, level):
    return rule.verdict in ("local-only", "deny") or (rule.verdict == "masked" and rule.min_level >= level)


def test_the_profile_of_the_policy_clause_keeps_finance_and_strategy_to_the_level_the_clause_asks():
    profile = clause_profile()
    level = int(clause_says(r"Financial results, deal terms and strategy are sent only at level (\d) or higher", "what level finance and strategy need"))
    policy = Policy.from_profile(profile)
    for category in ("finance", "strategy"):
        for kind in (PT, PP, CO, API):
            rule = policy.rule(category, kind)
            assert sent_at_least_at(rule, level), f"{category} for {kind} is {rule} in {profile}, the clause says level {level} or higher"


def test_the_profile_of_the_policy_clause_masks_personal_data_and_keeps_hr_and_health_off_personal_accounts():
    profile = clause_profile()
    level = int(clause_says(r"Personal data of customers and staff is sent only masked, at level (\d) or higher", "what level personal data needs"))
    clause_says(r"(HR and health data only to \[company plan or local model\] and never to personal accounts)", "that HR and health data never go to personal accounts")
    policy = Policy.from_profile(profile)
    for category in sorted(PERSONAL_DATA):  # personal data of customers and staff: personal, hr and health
        for kind in (PT, PP, CO, API):
            rule = policy.rule(category, kind)
            assert sent_at_least_at(rule, level), f"{category} for {kind} is {rule} in {profile}, the clause says masked at level {level} or higher"
    for category in ("hr", "health"):
        for kind in (PT, PP):  # a personal account, whether it trains on chats or not: never masked, never raw, only a local model
            verdict = policy.rule(category, kind).verdict
            assert verdict in ("local-only", "deny"), f"{category} for {kind} is {verdict} in {profile}, the clause says never to personal accounts"


CONCEPTS = Path(__file__).resolve().parents[1] / "docs" / "guide" / "concepts.md"


def guide_levels_naming(word):
    """The levels of the table in the "Levels" section of docs/guide/concepts.md whose "Use it for" column names `word`, read
    from the guide itself: when the table moves HR to another level, the test below fails and names it."""
    section = re.search(r"^## Levels\b.*?(?=^## )", CONCEPTS.read_text(encoding="utf-8"), re.S | re.M)
    assert section, "docs/guide/concepts.md has no Levels section any more"
    rows = re.findall(r"^\|\s*(\d)\b[^|]*\|[^|]*\|[^|]*\|([^|]*)\|\s*$", section.group(), re.M)
    assert len(rows) == 5, "the table of levels in docs/guide/concepts.md does not have its five levels any more"
    return [int(level) for level, when in rows if word in when]


def test_the_hr_rows_are_masked_at_the_level_the_guide_gives_hr():
    (level,) = guide_levels_naming("HR")  # exactly one row of the table names it
    cells = {(profile, kind): Policy.from_profile(profile).rule("hr", kind) for profile in PROFILES for kind in (PT, PP, CO, API)}
    masked = {cell: rule for cell, rule in cells.items() if rule.verdict == "masked"}
    assert len(masked) == 6  # no-rules: the two personal accounts; no-confidential and approved-only: the company plan and the API
    assert {rule.min_level for rule in masked.values()} == {level}, {cell: str(rule) for cell, rule in masked.items()}


@pytest.mark.parametrize("profile", PROFILES)
def test_strategy_follows_finance_in_every_profile(profile):
    policy = Policy.from_profile(profile)  # the clause names both in one breath: they share a rule, for every recipient but local
    for kind in (PT, PP, CO, API):
        assert policy.rule("strategy", kind) == policy.rule("finance", kind), (profile, kind)


@pytest.mark.parametrize("profile", PROFILES)
def test_health_follows_hr_in_every_profile(profile):
    policy = Policy.from_profile(profile)  # special-category data does not sit below HR, and the clause names the two together
    for kind in RECIPIENT_KINDS:
        assert policy.rule("health", kind) == policy.rule("hr", kind), (profile, kind)


@pytest.mark.parametrize("looser,stricter", list(zip(PROFILES, PROFILES[1:])))
def test_each_profile_is_a_tightening_of_the_previous_one(looser, stricter):
    loose, strict = Policy.from_profile(looser), Policy.from_profile(stricter)
    loose.tighten(all_rules(strict))
    with pytest.raises(PolicyError):
        strict.tighten(all_rules(loose))


def test_unknown_profile_refused():
    with pytest.raises(PolicyError, match="unknown profile"):
        Policy.from_profile("strict")


def test_rule_refuses_an_unknown_cell():
    policy = Policy.from_profile("ban")
    for category, kind in [("gossip", CO), ("finance", "moon"), ("", ""), ("finance", "")]:
        with pytest.raises(PolicyError):
            policy.rule(category, kind)


def test_tighten_keeps_the_stricter_rule():
    base = Policy.from_profile("no-confidential")
    tight = base.tighten(
        {
            ("finance", CO): Rule("deny"),
            ("finance", PP): Rule("masked", 4),
            ("finance", PT): Rule("masked", 3),  # the same rule
            ("code", CO): Rule("masked", 0),
            ("hr", PP): Rule("deny"),
        }
    )
    cells = [("finance", CO), ("finance", PP), ("finance", PT), ("code", CO), ("hr", PP)]
    assert [str(tight.rule(*cell)) for cell in cells] == ["deny", "masked:4", "masked:3", "masked:0", "deny"]
    assert str(tight.rule("clients", CO)) == "masked:2"  # untouched cells stay
    assert str(base.rule("finance", CO)) == "masked:3"  # the original policy is not changed


def test_tighten_can_also_restrict_local():
    assert Policy.from_profile("ban").tighten({("hr", LO): Rule("deny")}).rule("hr", LO) == Rule("deny")


@pytest.mark.parametrize(
    "cell,rule",
    [
        (("finance", PP), Rule("masked", 2)),  # the profile says masked:3
        (("finance", PP), Rule("allow")),
        (("hr", PP), Rule("masked", 4)),  # the profile says local-only
        (("hr", PP), Rule("allow")),
        (("secrets", CO), Rule("allow")),
    ],
)
def test_tighten_rejects_a_looser_rule(cell, rule):
    base = Policy.from_profile("no-confidential")
    with pytest.raises(PolicyError, match="looser"):
        base.tighten({cell: rule})


def test_tighten_refuses_the_whole_batch_and_an_unknown_cell():
    base = Policy.from_profile("no-confidential")
    with pytest.raises(PolicyError, match="looser"):
        base.tighten({("finance", CO): Rule("deny"), ("finance", PP): Rule("allow")})
    with pytest.raises(PolicyError):
        base.tighten({("gossip", CO): Rule("deny")})
    assert str(base.rule("finance", CO)) == "masked:3"


def test_categories_for_kinds():
    assert categories_for(["SECRET", "PRIVATE_KEY", "JWT", "CARD"]) == {"secrets"}
    assert categories_for(["EMAIL", "PHONE", "PERSON", "INN", "SNILS", "IBAN", "PASSPORT", "SSN"]) == {"personal"}
    assert categories_for(["ORG", "VAT_ID"]) == {"clients"}
    assert categories_for(["MONEY", "CRYPTO_ADDR"]) == {"finance"}
    assert categories_for(["HOST", "URL", "IP"]) == {"code"}
    assert categories_for(["SECRET", "EMAIL", "IP", "ORG"]) == {"secrets", "personal", "code", "clients"}
    assert categories_for([]) == set()
    assert categories_for(iter(["EMAIL", "EMAIL"])) == {"personal"}


def test_categories_for_dictionary_kinds():
    assert categories_for(["CLIENT", "EMAIL"], {"CLIENT", "CODENAME"}) == {"clients", "personal"}
    assert categories_for(["CODENAME"], ["CLIENT", "CODENAME"]) == {"clients"}
    assert categories_for(["EMAIL"], {"EMAIL"}) == {"personal", "clients"}  # a dictionary term of a built-in kind counts twice
    assert categories_for(["LITERAL"]) == set()  # a marker-like string in the source is not data


def test_categories_for_refuses_a_kind_nobody_mapped():
    with pytest.raises(PolicyError, match="has no category"):
        categories_for(["CLIENT"])  # the dictionary kinds were forgotten: fail closed, do not allow
    with pytest.raises(PolicyError, match="has no category") as raised:
        categories_for(["EMAIL", "LICENSE_PLATE"], {"CLIENT"})
    assert "LICENSE_PLATE" not in str(raised.value)  # a kind of the dictionary is the person's word


def test_every_detector_kind_has_exactly_one_category():
    for kind in DETECTOR_KINDS:
        assert len(categories_for([kind])) == 1, kind


def test_the_guide_names_the_kinds_of_every_category():
    """docs/guide/policy.md has a row for each category with the kinds that put it on a text; a kind that is missing there is a
    detector the page does not mention."""
    page = (Path(__file__).resolve().parents[1] / "docs" / "guide" / "policy.md").read_text(encoding="utf-8")
    rows = {m.group(1): m.group(2) for m in re.finditer(r"^\| `(\w+)` \| (.+) \|$", page, re.M)}
    for kind in sorted(DETECTOR_KINDS):
        (category,) = categories_for([kind])
        assert f"`{kind}`" in rows[category], (category, kind)


def test_masked_levels_mask_the_kinds_of_their_category():
    for profile in PROFILES:
        policy = Policy.from_profile(profile)
        for kind in DETECTOR_KINDS:
            (category,) = categories_for([kind])
            for recipient in (PT, PP, CO, API):
                rule = policy.rule(category, recipient)
                if rule.verdict == "masked":
                    assert kind in KINDS_BY_LEVEL[rule.min_level], (profile, category, recipient, kind)


def test_eea_members():
    eu = "AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE".split()
    assert len(eu) == 27
    assert EEA == set(eu) | {"IS", "LI", "NO", "EU", "EEA"}
    assert not {"US", "GB", "CH", "CN", "SG", "UA", "local"} & EEA


def test_recipient_refuses_an_unknown_kind():
    with pytest.raises(PolicyError, match="unknown recipient kind") as caught:
        Recipient("openai", "enterprise", "US")
    assert "enterprise" not in str(caught.value)  # an error never quotes the value it was given


def rcp(kind, jurisdiction="EU"):
    return Recipient("acme-ai", kind, jurisdiction)


def test_decide_takes_the_strictest_and_highest_level():
    policy = Policy.from_profile("no-confidential")
    d = decide({"secrets", "personal", "finance"}, rcp(PP), policy)
    assert d == Decision(
        "masked",
        3,
        [
            "secrets for personal-private: masked at level 0",
            "personal for personal-private: masked at level 1",
            "finance for personal-private: masked at level 3",
        ],
        [],
    )
    d = decide({"secrets", "personal", "finance"}, rcp(CO), policy)  # the same data, a corporate account: finance asks 3 there too
    assert (d.verdict, d.min_level) == ("masked", 3)
    d = decide({"secrets", "personal", "clients"}, rcp(CO), policy)
    assert (d.verdict, d.min_level) == ("masked", 2)
    d = decide({"finance", "hr"}, rcp(PP), policy)  # a stricter verdict beats any level
    assert (d.verdict, d.min_level) == ("local-only", None)
    assert d.reasons == ["finance for personal-private: masked at level 3", "hr for personal-private: local only"]
    d = decide({"secrets", "hr", "finance"}, rcp(PP), Policy.from_profile("approved-only"))
    assert (d.verdict, d.min_level) == ("deny", None)
    assert d.reasons == [f"{c} for personal-private: denied" for c in ("secrets", "finance", "hr")]


def test_decide_level_0_is_a_level():
    d = decide({"secrets"}, rcp(CO), Policy.from_profile("no-confidential"))
    assert (d.verdict, d.min_level) == ("masked", 0)


def test_decide_lists_only_the_rules_that_restrict():
    d = decide({"code", "finance"}, rcp(PP), Policy.from_profile("no-confidential"))
    assert d.reasons == ["finance for personal-private: masked at level 3"]
    d = decide({"code"}, rcp(PP), Policy.from_profile("no-confidential"))
    assert d == Decision("allow", None, [], [])


def test_decide_local_takes_everything():
    for profile in PROFILES:
        d = decide(set(CATEGORIES), rcp(LO, "local"), Policy.from_profile(profile))
        assert d == Decision("allow", None, [], [])


def test_decide_without_categories_allows_unless_the_recipient_is_banned():
    assert decide(set(), rcp(PP), Policy.from_profile("no-confidential")) == Decision("allow", None, [], [])
    assert decide(set(), rcp(PP), Policy.from_profile("approved-only")).verdict == "allow"  # code is still allowed there
    assert decide(set(), rcp(LO, "local"), Policy.from_profile("ban")).verdict == "allow"
    d = decide(set(), rcp(CO), Policy.from_profile("ban"))
    assert (d.verdict, d.min_level, d.reasons) == ("deny", None, ["all categories for corporate: denied"])
    tight = Policy.from_profile("no-rules").tighten({(c, CO): Rule("deny") for c in CATEGORIES})
    assert decide(set(), rcp(CO), tight).verdict == "deny"
    assert decide(set(), rcp(API), tight).verdict == "allow"


def test_decide_refuses_an_unknown_category():
    with pytest.raises(PolicyError, match="unknown category") as raised:
        decide({"finance", "gossip"}, rcp(CO), Policy.from_profile("no-rules"))
    assert "gossip" not in str(raised.value)


def test_warning_outside_the_eea():
    policy = Policy.from_profile("no-rules")
    assert LEAVES in decide({"personal"}, rcp(CO, "US"), policy).warnings
    assert LEAVES in decide({"personal"}, rcp(PP, "CN"), policy).warnings
    assert LEAVES in decide({"hr"}, rcp(CO, "US"), policy).warnings  # hr and health are personal data too
    assert LEAVES in decide({"health", "code"}, rcp(API, "SG"), policy).warnings
    for jurisdiction in ("EU", "EEA", "DE", "NO", "IS"):
        assert LEAVES not in decide({"personal"}, rcp(CO, jurisdiction), policy).warnings, jurisdiction
    assert LEAVES not in decide({"finance", "clients", "secrets", "code"}, rcp(CO, "US"), policy).warnings
    assert LEAVES not in decide(set(), rcp(CO, "US"), policy).warnings
    # hand-typed codes in lower case
    assert LEAVES in decide({"personal"}, rcp(CO, "us"), policy).warnings
    assert LEAVES not in decide({"personal"}, rcp(CO, "de"), policy).warnings
    assert LEAVES not in decide({"personal"}, rcp(LO, "Local"), policy).warnings


def test_the_eea_warning_is_silent_only_for_the_local_kind():
    policy = Policy.from_profile("no-rules")
    for kind in (PT, PP, CO, API):  # the word "local" in the jurisdiction says nothing about where the data goes
        for jurisdiction in ("local", "Local", "LOCAL"):
            assert LEAVES in decide({"personal"}, rcp(kind, jurisdiction), policy).warnings, (kind, jurisdiction)
    for jurisdiction in ("local", "Local", "EU"):
        assert LEAVES not in decide({"personal", "hr", "health"}, rcp(LO, jurisdiction), policy).warnings
    # a local recipient in a place that is neither "local" nor in the EEA is a contradiction: the warning stays
    assert LEAVES in decide({"personal"}, rcp(LO, "US"), policy).warnings


def test_warning_comes_with_every_verdict():
    for profile in PROFILES:
        d = decide({"personal"}, rcp(PP, "US"), Policy.from_profile(profile))
        assert LEAVES in d.warnings, profile
    assert decide({"personal"}, rcp(PP, "US"), Policy.from_profile("ban")).verdict == "deny"


def test_training_and_china_warnings():
    policy = Policy.from_profile("no-rules")
    assert decide({"code"}, rcp(PT, "US"), policy).warnings == [TRAINS]
    assert decide({"code"}, rcp(CO, "CN"), policy).warnings == [CHINA]
    assert decide({"code"}, rcp(PT, "CN"), policy).warnings == [TRAINS, CHINA]
    assert decide({"personal"}, rcp(PT, "CN"), policy).warnings == [LEAVES, TRAINS, CHINA]
    assert decide({"code"}, rcp(CO, "US"), policy).warnings == []
    assert decide({"code"}, rcp(PP, "US"), policy).warnings == []
    assert decide({"code"}, rcp(CO, "cn"), policy).warnings == [CHINA]
    assert decide(set(), rcp(PT, "CN"), policy).warnings == [TRAINS, CHINA]  # about the recipient, not about the data


def test_from_config_without_a_profile_starts_from_no_rules():
    default = all_rules(Policy.from_profile("no-rules"))
    assert all_rules(Policy.from_config({})) == default
    assert all_rules(Policy.from_config({"rules": {}})) == default
    tight = Policy.from_config({"rules": {"finance:corporate": "deny"}})
    assert str(tight.rule("finance", CO)) == "deny" and str(tight.rule("finance", PP)) == "masked:3"


def test_from_config_profile_and_rules():
    policy = Policy.from_config(
        {
            "profile": "no-confidential",
            "rules": {
                "finance:corporate": "deny",
                "hr:personal-private": "deny",
                "code:corporate": "masked:3",
                "finance:personal-private": "masked:3",  # the same as the profile
                "secrets:local": "masked:0",
                "clients:api-zero-retention": "local-only",
            },
        }
    )
    got = {cell: str(policy.rule(*cell)) for cell in [("finance", CO), ("hr", PP), ("code", CO), ("finance", PP)]}
    assert got == {("finance", CO): "deny", ("hr", PP): "deny", ("code", CO): "masked:3", ("finance", PP): "masked:3"}
    assert str(policy.rule("secrets", LO)) == "masked:0" and str(policy.rule("clients", API)) == "local-only"
    assert str(policy.rule("strategy", CO)) == "masked:3"  # the profile everywhere else


@pytest.mark.parametrize(
    "table,needle",
    [
        ({"profle": "ban"}, "has a key boxed does not know"),
        ({"profile": "ban", "rule": {}}, "rule"),
        ({"profile": "strict"}, "unknown profile"),  # the value itself is never quoted
        ({"profile": 3}, "unknown profile"),
        ({"rules": "deny"}, "rules"),
        ({"rules": {"finance": "deny"}}, r"^\[boxed.policy.rules\] a key is not <category>:<recipient>"),  # the key is not quoted
        ({"rules": {":corporate": "deny"}}, r"^\[boxed.policy.rules\] a key is not <category>:<recipient>"),
        ({"rules": {"gossip:corporate": "deny"}}, r"^\[boxed.policy.rules\] a key is not <category>:<recipient>"),
        ({"rules": {"finance:moon": "deny"}}, r"^\[boxed.policy.rules\] a key is not <category>:<recipient>"),
        ({"rules": {"finance:corporate:x": "deny"}}, r"^\[boxed.policy.rules\] a key is not <category>:<recipient>"),
        ({"rules": {"finance:corporate": "forbid"}}, r"^\[boxed.policy.rules\] a bad rule"),
        ({"rules": {"finance:corporate": "Deny"}}, r"^\[boxed.policy.rules\] a bad rule"),
        ({"rules": {"finance:corporate": "masked"}}, "masked"),
        ({"rules": {"finance:corporate": "masked:9"}}, "level"),
        ({"rules": {"finance:corporate": "masked:12"}}, "bad rule"),
        ({"rules": {"finance:corporate": "masked:03"}}, "bad rule"),
        ({"rules": {"finance:corporate": "masked:\u0663"}}, "bad rule"),  # an Arabic-Indic digit three
        ({"rules": {"finance:corporate": "masked:\uff13"}}, "bad rule"),  # a fullwidth digit three
        ({"rules": {"finance:corporate": "masked:3\n"}}, "bad rule"),
        ({"rules": {"finance:corporate": True}}, "a bad rule"),
        ({"rules": {"finance:corporate": ["deny"]}}, "a bad rule"),
        ({"profile": "no-confidential", "rules": {"hr:personal-private": "allow"}}, "looser"),
        ({"profile": "ban", "rules": {"code:corporate": "masked:4"}}, "looser"),
    ],
)
def test_from_config_refuses_a_bad_table(table, needle):
    with pytest.raises(PolicyError, match=needle):
        Policy.from_config(table)


def test_config_policy_table(tmp_path):
    (tmp_path / "boxed.toml").write_text(
        '[boxed]\n[boxed.policy]\nprofile = "no-confidential"\n[boxed.policy.rules]\n"finance:corporate" = "deny"\n'
    )
    config = load_config(tmp_path)
    assert config.policy == {"profile": "no-confidential", "rules": {"finance:corporate": "deny"}}
    policy = Policy.from_config(config.policy)
    assert str(policy.rule("finance", CO)) == "deny"
    assert str(policy.rule("finance", PP)) == "masked:3"  # from the profile


def test_config_without_a_policy_table(tmp_path):
    assert load_config(tmp_path).policy == {}
    (tmp_path / "boxed.toml").write_text("[boxed]\nlevel = 1\n")
    assert load_config(tmp_path).policy == {}
    assert ProjectConfig().policy == {}


@pytest.mark.parametrize(
    "body,needle",
    [
        ('policy = "ban"\n', "policy must be dict"),
        ('[boxed.policy]\nprofle = "ban"\n', "has a key boxed does not know"),
        ('[boxed.policy]\nprofile = "strict"\n', "unknown profile"),
        ('[boxed.policy.rules]\n"finance:moon" = "deny"\n', "a key is not <category>:<recipient>"),
        ('[boxed.policy.rules]\n"finance:corporate" = "forbid"\n', "bad rule"),
        ('[boxed.policy]\nprofile = "approved-only"\n[boxed.policy.rules]\n"hr:corporate" = "allow"\n', "looser"),
    ],
)
def test_config_policy_table_errors(tmp_path, body, needle):
    path = tmp_path / "boxed.toml"
    path.write_text("[boxed]\n" + body)
    with pytest.raises(ValueError, match=needle) as excinfo:
        load_config(tmp_path)
    message = str(excinfo.value)
    assert str(tmp_path) not in message and not any(word in message for word in ("profle", "strict", "moon", "forbid"))


# the cells where a profile masks hr, and health with it, at level 3: a company can ask for more there, never for less
LEVEL_3_CELLS = [("no-rules", PT), ("no-rules", PP), ("no-confidential", CO), ("no-confidential", API), ("approved-only", CO), ("approved-only", API)]


def toml_with_rule(tmp_path, profile, cell, rule):
    path = tmp_path / "boxed.toml"
    path.write_text(f'[boxed]\n[boxed.policy]\nprofile = "{profile}"\n[boxed.policy.rules]\n"{cell}" = "{rule}"\n')
    return path


@pytest.mark.parametrize("category", ["hr", "health"])
@pytest.mark.parametrize("profile,kind", LEVEL_3_CELLS)
def test_boxed_toml_cannot_loosen_a_level_3_cell_to_level_2(tmp_path, category, profile, kind):
    path = toml_with_rule(tmp_path, profile, f"{category}:{kind}", "masked:2")
    with pytest.raises(ValueError, match=f"{category}:{kind}: masked:2 is looser than masked:3") as excinfo:
        load_config(tmp_path)
    assert str(path) not in str(excinfo.value)  # a known key and known rules are named, the path is not


@pytest.mark.parametrize("category", ["hr", "health"])
@pytest.mark.parametrize("profile,kind", LEVEL_3_CELLS)
@pytest.mark.parametrize("rule", ["masked:3", "masked:4"])
def test_boxed_toml_may_keep_or_raise_a_level_3_cell(tmp_path, category, profile, kind, rule):
    toml_with_rule(tmp_path, profile, f"{category}:{kind}", rule)
    assert str(Policy.from_config(load_config(tmp_path).policy).rule(category, kind)) == rule


def run_cli(capsys, monkeypatch, tmp_path, toml, text="mail a@x.io"):
    (tmp_path / "boxed.toml").write_text(toml)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO(text))
    code = main(["mask", "-"])
    out, err = capsys.readouterr()
    return code, out, err


def test_cli_accepts_a_policy_table(tmp_path, capsys, monkeypatch):
    code, out, _ = run_cli(capsys, monkeypatch, tmp_path, '[boxed]\n[boxed.policy]\nprofile = "ban"\n')
    assert code == 0 and out == "mail [EMAIL_1]"


def test_cli_refuses_an_unknown_policy_key(tmp_path, capsys, monkeypatch):
    code, out, err = run_cli(capsys, monkeypatch, tmp_path, '[boxed]\n[boxed.policy]\nprofle = "ban"\n')
    assert code == 2 and out == "" and "profle" not in err and "the known ones are profile, rules" in err


def test_cli_refuses_an_hr_rule_looser_than_its_profile(tmp_path, capsys, monkeypatch):
    toml = '[boxed]\n[boxed.policy]\nprofile = "no-confidential"\n[boxed.policy.rules]\n"hr:corporate" = "masked:2"\n'
    code, out, err = run_cli(capsys, monkeypatch, tmp_path, toml)
    assert code == 2 and out == "" and "hr:corporate: masked:2 is looser than masked:3" in err


def test_decide_accepts_a_one_shot_iterable():
    recipient = Recipient("openai", "personal-training", "US")
    decision = decide(map(str, ["secrets"]), recipient, Policy.from_profile("approved-only"))
    assert decision.verdict != "allow" and decision.reasons
