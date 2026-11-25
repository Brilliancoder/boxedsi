"""The kinds that only level 3 detects, seen by the policy: amounts are finance, the other number kinds have no category."""

import io

import pytest

from boxed.cli import main
from boxed.detect import KINDS_BY_LEVEL, detect
from boxed.mask import MarkerMap, mask_text
from boxed.policy import NEUTRAL_KINDS, Policy, PolicyError, Recipient, categories_for, decide

PERSONAL = Recipient("openai", "personal-private", "US")
TRAINING = Recipient("openai", "personal-training", "US")


def categories_of(text):
    return categories_for({d.kind for d in detect(text, level=3)})


def test_money_counts_as_finance():
    assert categories_for(["MONEY"]) == {"finance"}


def test_percent_date_and_number_carry_no_category():
    assert NEUTRAL_KINDS == {"PERCENT", "DATE", "NUMBER"}
    for kind in NEUTRAL_KINDS:
        assert categories_for([kind]) == set(), kind
    assert categories_for(["NUMBER", "DATE", "PERCENT", "EMAIL"]) == {"personal"}
    assert categories_for(["MONEY", "NUMBER", "ORG"]) == {"finance", "clients"}


def test_every_kind_of_level_3_is_finance_or_neutral():
    new_kinds = KINDS_BY_LEVEL[3] - KINDS_BY_LEVEL[2]
    assert new_kinds == {"MONEY"} | NEUTRAL_KINDS
    for kind in new_kinds:
        assert categories_for([kind]) == ({"finance"} if kind == "MONEY" else set()), kind


def test_a_kind_nobody_mapped_is_still_refused_next_to_neutral_ones():
    with pytest.raises(PolicyError, match="has no category"):
        categories_for(["NUMBER", "FOO"])


def test_a_dictionary_term_of_a_neutral_kind_counts_as_clients():
    assert categories_for(["NUMBER"], {"NUMBER"}) == {"clients"}


def test_a_text_with_an_amount_is_finance():
    assert categories_of("Pay $1,200 by 21.10.2026, 15% off, order 4521") == {"finance"}
    assert categories_of("Выручка 95 млн руб.") == {"finance"}


def test_a_text_with_only_a_date_a_percentage_and_a_number_has_no_category():
    assert categories_of("Due 21.10.2026, 15% of 1500, order 4521") == set()


def test_the_approved_only_finance_rule_now_applies_to_a_text_with_an_amount():
    policy = Policy.from_profile("approved-only")
    assert decide(categories_of("Pay $1,200 by 21.10.2026"), PERSONAL, policy).verdict == "deny"
    assert decide(categories_of("Due 21.10.2026 for 1500, 15%"), PERSONAL, policy).verdict == "allow"


def test_a_strict_profile_asks_for_the_level_that_masks_the_amount():
    text = "Pay $1,200 by 21.10.2026"
    decision = decide(categories_of(text), TRAINING, Policy.from_profile("no-confidential"))
    assert (decision.verdict, decision.min_level) == ("masked", 3)
    masked, _ = mask_text(text, MarkerMap(), level=decision.min_level)
    assert masked == "Pay [MONEY_1] by [DATE_1]"


def run_policy_check(capsys, monkeypatch, tmp_path, text):
    (tmp_path / "boxed.toml").write_text('[boxed]\n[boxed.policy]\nprofile = "approved-only"\n')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO(text))
    code = main(["policy", "check", "--recipient", "openai:personal-private:US", "-"])
    out, err = capsys.readouterr()
    return code, out, err


def test_policy_check_denies_a_text_with_an_amount_under_approved_only(tmp_path, capsys, monkeypatch):
    code, out, err = run_policy_check(capsys, monkeypatch, tmp_path, "Pay $1,200 by 21.10.2026")
    assert code == 4 and "deny" in out and "categories: finance" in out
    assert "1,200" not in out + err


def test_policy_check_lets_dates_and_numbers_through(tmp_path, capsys, monkeypatch):
    code, out, _ = run_policy_check(capsys, monkeypatch, tmp_path, "Due 21.10.2026 for 1500, 15%")
    assert code == 0 and "verdict: allow" in out and "none found" in out


def test_policy_check_still_denies_a_card_followed_by_a_decimal_tail(tmp_path, capsys, monkeypatch):
    code, out, err = run_policy_check(capsys, monkeypatch, tmp_path, "pay 4111111111111111.0 now")
    assert code == 4 and "deny" in out and "categories: secrets" in out
    assert "4111" not in out + err
