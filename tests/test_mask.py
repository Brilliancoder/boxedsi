import json
import string

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from boxed.detect import DetectConfig, Detection
from boxed.mask import MARKER_RE, MAX_FOREIGN, MarkerMap, RestoreResult, mask_path, mask_text, restore


ROWS = st.one_of(
    st.sampled_from(
        [
            "| Пароль | Xk9#mQ2v |",
            "|Пароль|`Xk9#mQ2v`|",
            "| **Пароль:** | pa$$,word1 | почта |",
            "Пароль\tXk9#mQ2v",
            "Токен бота\t123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ\r",
            "Пароль для входа в систему: Xk9#mQ2v",
            "Пароль от учётной записи администратора - Xk9#mQ2v",
            "Пароль для входа в систему: 'мой длинный пароль'",
            "| Пароль | строка |",
            "| 5 March 2026 | ivan@acme.com |",
            "\n",
            "\r\n",
            "|",
            "\t",
            " ",
        ]
    ),
    st.text(alphabet=string.printable, max_size=6),
)


@settings(max_examples=300, deadline=None)
@given(st.lists(ROWS, max_size=12).map("".join), st.sampled_from([0, 1, 2, 3]))
def test_roundtrip_property_with_table_rows_and_long_names(text, level):
    m = MarkerMap()
    masked, _ = mask_text(text, m, level=level)
    assert restore(masked, MarkerMap.from_json(m.to_json())).text == text


def test_numbering_stable():
    m = MarkerMap()
    assert m.marker_for("EMAIL", "a@x.io") == "[EMAIL_1]"
    assert m.marker_for("EMAIL", "b@x.io") == "[EMAIL_2]"
    assert m.marker_for("EMAIL", "a@x.io") == "[EMAIL_1]"
    assert m.original_for("[EMAIL_2]") == "b@x.io"
    assert m.original_for("[EMAIL_3]") is None


def test_mask_text_counts():
    m = MarkerMap()
    masked, counts = mask_text("a@x.io b@x.io a@x.io", m)
    assert masked == "[EMAIL_1] [EMAIL_2] [EMAIL_1]"
    assert counts == {"EMAIL": 3}


def test_roundtrip_literal():
    m = MarkerMap()
    text = "see [EMAIL_1] and bob@x.io"
    masked, _ = mask_text(text, m)
    assert "bob@x.io" not in masked
    r = restore(masked, m)
    assert r == RestoreResult(text=text, restored=2, unknown=[], suspicious=[])


def test_literal_overlapping_detection_is_masked():
    m = MarkerMap()
    text = "ref [CARD_4111111111111111] end"
    masked, _ = mask_text(text, m)
    assert "4111" not in masked
    assert restore(masked, m).text == text


def test_crlf_and_no_trailing_newline_roundtrip():
    m = MarkerMap()
    text = "line1 a@x.io\r\nline2 AKIAIOSFODNN7EXAMPLE\r\nlast"
    masked, _ = mask_text(text, m)
    assert "\r\n" in masked and not masked.endswith("\n")
    assert restore(masked, m).text == text


CHUNKS = st.one_of(
    st.text(alphabet=string.printable, max_size=12),
    st.sampled_from(
        [
            "ivan.petrov@acme.com",
            "AKIAIOSFODNN7EXAMPLE",
            "password=hunter22",
            "[EMAIL_1]",
            "[SECRET_3]",
            "EMAIL_1",
            "\r\n",
            "\n",
            " ",
            "[",
            "]",
            "_1]",
        ]
    ),
)


@settings(max_examples=300, deadline=None)
@given(st.lists(CHUNKS, max_size=12).map("".join))
def test_roundtrip_property(text):
    m = MarkerMap()
    masked, _ = mask_text(text, m)
    assert restore(masked, m).text == text


def test_unknown_marker():
    m = MarkerMap()
    m.marker_for("EMAIL", "bob@x.io")
    r = restore("reply to [EMAIL_9] or [EMAIL_1]", m)
    assert r.text == "reply to [EMAIL_9] or bob@x.io"
    assert r.unknown == ["[EMAIL_9]"]
    assert r.restored == 1


def test_suspicious():
    m = MarkerMap()
    m.marker_for("EMAIL", "bob@x.io")
    text = "a [email_1] b [EMAIL_01] c EMAIL_1 d"
    r = restore(text, m)
    assert r.text == text
    assert r.suspicious == ["[email_1]", "[EMAIL_01]", "EMAIL_1"]
    assert r.unknown == [] and r.restored == 0


def test_map_json_roundtrip():
    m = MarkerMap()
    m.marker_for("EMAIL", "a@x.io")
    m.marker_for("EMAIL", "b@x.io")
    m.marker_for("SECRET", "AKIAIOSFODNN7EXAMPLE")
    m2 = MarkerMap.from_json(m.to_json())
    assert m2.items() == m.items()
    assert m2.marker_for("EMAIL", "c@x.io") == "[EMAIL_3]"


def test_marker_regex():
    assert MARKER_RE.fullmatch("[PRIVATE_KEY_12]").groups() == ("PRIVATE_KEY", "12")
    assert MARKER_RE.fullmatch("[email_1]") is None


def test_mask_path_keeps_extensions_and_restores():
    m = MarkerMap()
    masked, counts = mask_path("exports/ivan.petrov@acme.com.csv", m)
    assert masked == "exports/[EMAIL_1].csv" and counts == {"EMAIL": 1}
    assert mask_path("logs/203.0.113.7.log", m)[0] == "logs/[IP_1].log"
    assert mask_path("mail/ivan.petrov@acme.com", m)[0] == "mail/[EMAIL_1]"
    assert mask_path("src/app.py", m)[0] == "src/app.py"
    assert restore("exports/[EMAIL_1].csv", m).text == "exports/ivan.petrov@acme.com.csv"


def known_email_map():
    m = MarkerMap()
    m.marker_for("EMAIL", "ivan@acme.com")
    return m


def test_broken_marker_forms_are_suspicious():
    for broken in ("[EMAIL_1", "EMAIL_1]", "[EMAIL-1]", "[EMAIL 1]", "[ EMAIL_1 ]"):
        r = restore(f"see {broken} now", known_email_map())
        assert r.suspicious == [broken] and r.text == f"see {broken} now", broken


def test_glued_markers_and_code_identifiers_are_not_suspicious():
    r = restore("id[EMAIL_1]x and email_1 = 3 and STEP_1", known_email_map())
    assert r.suspicious == [] and r.text == "idivan@acme.comx and email_1 = 3 and STEP_1"


def test_mask_path_finds_values_glued_with_underscores_and_hyphens():
    m = MarkerMap()
    assert mask_path("ivan.petrov@acme.com_2026.csv", m)[0] == "[EMAIL_1]_2026.csv"
    assert mask_path("invoice_ivan.petrov@acme.com_final.pdf", m)[0] == "invoice_[EMAIL_1]_final.pdf"
    assert mask_path("ivan.petrov@acme.com-2026.csv", m)[0] == "[EMAIL_1]-2026.csv"
    assert mask_path("passport_+79991234567.pdf", m)[0] == "passport_[PHONE_1].pdf"
    assert mask_path("prod_AKIAIOSFODNN7EXAMPLE.txt", m)[0] == "prod_[SECRET_1].txt"
    assert mask_path("2026_10_20_backup.tar.gz", m)[0] == "2026_10_20_backup.tar.gz"
    assert restore("invoice_[EMAIL_1]_final.pdf", m).text == "invoice_ivan.petrov@acme.com_final.pdf"


class TagEverything:
    def find(self, text):
        return [Detection(0, len(text), "ORG", text, "ner:fake")]


def test_mask_path_leaves_names_to_rules_not_ner():
    m, config = MarkerMap(), DetectConfig(ner=[TagEverything()])
    assert mask_text("Acme", m, config=config)[0] == "[ORG_1]"
    assert mask_path("src/Footer.tsx", m, config=config)[0] == "src/Footer.tsx"
    assert mask_path("README.md", m, config=config)[0] == "README.md"


def test_foreign_marker_like_tokens_stay_as_they_are():
    m = MarkerMap()
    masked, _ = mask_text("[GPIO_12] pin, [SERVER_1] section, mail ivan@acme.com", m)
    assert masked == "[GPIO_12] pin, [SERVER_1] section, mail [EMAIL_1]"
    r = restore(masked.replace("pin", "pins"), m)
    assert r.text == "[GPIO_12] pins, [SERVER_1] section, mail ivan@acme.com" and r.unknown == [] and r.suspicious == []


def test_marker_like_tokens_of_boxed_kinds_still_round_trip():
    m, config = MarkerMap(), DetectConfig(dictionary={"Acme Corp": "CLIENT"})
    text = "[EMAIL_7] and [CLIENT_1] for Acme Corp"
    masked, _ = mask_text(text, m, config=config)
    assert "[EMAIL_7]" not in masked and masked.count("[LITERAL_") == 2
    assert restore(masked, m).text == text


def test_lowercase_dictionary_kinds_still_protect_literals():
    m, config = MarkerMap(), DetectConfig(dictionary={"Acme Corp": "client"})
    text = "[CLIENT_1] literal, then Acme Corp"
    masked, _ = mask_text(text, m, config=config)
    assert "[CLIENT_1] literal" not in masked and restore(masked, m).text == text


def test_restore_reports_unknown_markers_of_dictionary_kinds():
    assert restore("[CLIENT_1] only", MarkerMap(), kinds=frozenset({"CLIENT"})).unknown == ["[CLIENT_1]"]


def test_odd_case_literals_of_boxed_kinds_round_trip():
    m = MarkerMap()
    text = "see [email_7] and [EMAIL_07] here"
    masked, _ = mask_text(text, m)
    assert "[email_7]" not in masked and "[EMAIL_07]" not in masked
    r = restore(masked, m)
    assert r.text == text and r.suspicious == [] and r.unknown == []


def test_marker_like_extension_round_trips():
    m = MarkerMap()
    masked, _ = mask_path("ivan.petrov@acme.com.[EMAIL_1]", m)
    assert restore(masked, m).text == "ivan.petrov@acme.com.[EMAIL_1]"


# a foreign token whose kind joins the dictionary later

ACME = DetectConfig(dictionary={"Acme Corp": "CLIENT"})
CLIENT = frozenset({"CLIENT"})


def test_a_foreign_token_never_restores_to_a_dictionary_original_that_joined_later():
    m = MarkerMap()
    first = "template: [CLIENT_1] and [CLIENT_2], mail ivan@acme.com"
    masked_first, _ = mask_text(first, m)  # CLIENT is nobody's kind yet: the tokens stay as they are
    assert masked_first == "template: [CLIENT_1] and [CLIENT_2], mail [EMAIL_1]"
    masked_second, _ = mask_text("Deal with Acme Corp", m, config=ACME)
    assert masked_second == "Deal with [CLIENT_3]"  # the two numbers of the first text are taken
    for kinds in (frozenset(), CLIENT):
        assert restore(masked_first, m, kinds).text == first
        assert restore(masked_second, m, kinds).text == "Deal with Acme Corp"


def test_a_foreign_token_is_skipped_only_where_it_stands():
    m = MarkerMap()
    mask_text("[CLIENT_2] and [CLIENT_4]", m)
    four = DetectConfig(dictionary={"Acme Corp": "CLIENT", "Beta Ltd": "CLIENT", "Gamma Inc": "CLIENT", "Delta AG": "CLIENT"})
    masked, _ = mask_text("Acme Corp, Beta Ltd, Gamma Inc, Delta AG", m, config=four)
    assert masked == "[CLIENT_1], [CLIENT_3], [CLIENT_5], [CLIENT_6]"


def test_a_foreign_token_in_a_file_name_is_remembered_too():
    m = MarkerMap()
    assert mask_path("docs/[CLIENT_1].txt", m)[0] == "docs/[CLIENT_1].txt"
    assert mask_text("Acme Corp", m, config=ACME)[0] == "[CLIENT_2]"


def test_a_token_of_a_kind_that_is_already_known_is_not_foreign():
    m = MarkerMap()
    config = DetectConfig(dictionary={"Acme Corp": "CLIENT"})
    assert mask_text("Acme Corp", m, config=config)[0] == "[CLIENT_1]"
    masked, _ = mask_text("[CLIENT_1] is literal text", m, config=config)  # a literal of a known kind is wrapped, as before
    assert masked.startswith("[LITERAL_1]") and restore(masked, m).text == "[CLIENT_1] is literal text"
    assert mask_text("Acme Corp again", m, config=config)[0] == "[CLIENT_1] again"


@pytest.mark.parametrize("token", ["[client_1]", "[CLIENT_01]", "[CLIENT-1]", "CLIENT_1", "[CLIENT_]", "[CLIENT_1", "[1_1]"])
def test_a_token_that_restore_would_never_replace_is_not_remembered(token):
    m = MarkerMap()
    mask_text(f"see {token}", m)
    assert mask_text("Acme Corp", m, config=ACME)[0] == "[CLIENT_1]"


def test_the_remembered_tokens_travel_with_the_map():
    m = MarkerMap()
    mask_text("[CLIENT_1] [GPIO_12]", m)
    assert json.loads(m.to_json())["foreign"] == ["[CLIENT_1]", "[GPIO_12]"]
    again = MarkerMap.from_json(m.to_json())
    assert again.items() == m.items() == []  # they are no markers: nothing in the map restores to anything
    assert mask_text("Acme Corp", again, config=ACME)[0] == "[CLIENT_2]"


def test_a_map_without_foreign_tokens_is_stored_as_before():
    m = MarkerMap()
    mask_text("mail ivan@acme.com", m)
    assert set(json.loads(m.to_json())) == {"version", "items"}
    assert MarkerMap.from_json('{"version": 1, "items": [["[EMAIL_1]", "EMAIL", "a@x.io"]]}').marker_for("EMAIL", "b@x.io") == "[EMAIL_2]"


def test_a_marker_like_token_with_a_huge_number_does_not_break_masking():
    m = MarkerMap()
    token = "[CLIENT_" + "9" * 5_000 + "]"  # more digits than int() will convert
    assert mask_text(f"see {token}", m)[0] == f"see {token}"
    assert mask_text("Acme Corp", m, config=ACME)[0] == "[CLIENT_1]"


def test_a_scope_remembers_at_most_ten_thousand_tokens_and_keeps_the_oldest():
    m = MarkerMap()
    mask_text(" ".join(f"[K_{i}]" for i in range(1, 20_001)), m)
    remembered = json.loads(m.to_json())["foreign"]
    assert len(remembered) == MAX_FOREIGN == 10_000
    assert "[K_1]" in remembered and "[K_10000]" in remembered and "[K_10001]" not in remembered
    # a kind that joins the dictionary skips the remembered numbers; past the cap the guarantee ends and the numbers are free
    assert mask_text("Acme Corp", m, config=DetectConfig(dictionary={"Acme Corp": "K"}))[0] == "[K_10001]"


def test_the_oldest_tokens_are_kept_across_texts_and_a_remembered_one_is_not_a_new_one():
    m = MarkerMap()
    mask_text(" ".join(f"[K_{i}]" for i in range(1, MAX_FOREIGN + 1)), m)
    assert m.reserve("[K_5]") is True  # remembered already
    assert m.reserve("[K_99999]") is False  # the scope is full
    mask_text("[K_99999] [K_5]", m)
    assert len(json.loads(m.to_json())["foreign"]) == MAX_FOREIGN


def test_a_token_no_marker_could_be_is_not_remembered():
    m = MarkerMap()
    mask_text("[K_" + "9" * 200 + "] [" + "K" * 500 + "_1]", m)
    assert "foreign" not in json.loads(m.to_json())


def test_masking_a_text_of_a_million_tokens_stores_a_small_map():
    m = MarkerMap()
    masked, _ = mask_text(" ".join(f"[K{i % 5000}_{i}]" for i in range(1, 200_001)), m)
    assert masked.count("[K") == 200_000  # all of them stay as they are
    assert len(m.to_json()) < 200_000  # ten thousand tokens of at most 15 characters, not two hundred thousand


@pytest.mark.parametrize("kind", ["EMAIL", "CLIENT", "email", "client"])
@pytest.mark.parametrize("digits", [4_301, 5_000, 100_000])
def test_a_marker_number_with_more_digits_than_int_takes_is_plain_text(kind, digits):
    m = MarkerMap()
    masked, _ = mask_text("mail ivan@acme.com", m)
    token = f"[{kind}_" + "9" * digits + "]"
    r = restore(f"{masked} see {token}", m, frozenset({"CLIENT"}))
    assert r.text == f"mail ivan@acme.com see {token}"
    assert r.restored == 1 and r.unknown == [] and r.suspicious == []


def test_a_marker_number_of_four_thousand_digits_is_still_reported_as_unknown():
    m = MarkerMap()
    r = restore("[EMAIL_" + "9" * 4_000 + "]", m)  # the longest number that is read as a number
    assert r.unknown == ["[EMAIL_" + "9" * 4_000 + "]"]


BEFORE = ["[CLIENT_1]", "[CLIENT_2]", "[CLIENT_3]", "[PROJECT_1]", "[EMAIL_1]", "Acme Corp", "Beta Ltd", "ivan@acme.com", "x ", "\n"]
AFTER = ["[CLIENT_1]", "[CLIENT_2]", "[PROJECT_1]", "[LITERAL_1]", "Acme Corp", "Beta Ltd", "Gamma Inc", "ivan@acme.com", "x ", "\n"]


@settings(max_examples=300, deadline=None)
@given(st.lists(st.sampled_from(BEFORE), max_size=10).map("".join), st.lists(st.sampled_from(AFTER), max_size=10).map("".join))
def test_texts_masked_before_and_after_a_dictionary_joined_all_round_trip(before, after):
    m = MarkerMap()
    masked_before, _ = mask_text(before, m)  # no dictionary
    config = DetectConfig(dictionary={"Acme Corp": "CLIENT", "Beta Ltd": "CLIENT", "Gamma Inc": "PROJECT"})
    masked_after, _ = mask_text(after, m, config=config)
    again = MarkerMap.from_json(m.to_json())  # as the vault stores it
    for markers in (m, again):
        assert restore(masked_before, markers, CLIENT | {"PROJECT"}).text == before
        assert restore(masked_after, markers, CLIENT | {"PROJECT"}).text == after


def test_marker_map_kinds_is_cheap_and_exact():
    import time

    from boxed.mask import MarkerMap

    m = MarkerMap()
    for i in range(200_000):
        m.marker_for(("EMAIL", "PHONE", "CLIENT")[i % 3], f"value-{i}")
    assert m.kinds() == {kind for _, kind, _ in m.items()} == {"EMAIL", "PHONE", "CLIENT"}
    assert MarkerMap.from_json(m.to_json()).kinds() == m.kinds()
    start = time.process_time()
    for _ in range(2_000):
        m.kinds()
    assert time.process_time() - start < 0.5  # once per text: quadratic on large tables when it walks every marker
