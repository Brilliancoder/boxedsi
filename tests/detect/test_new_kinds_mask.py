"""The newer kinds (PASSPORT, SSN, VAT_ID, CRYPTO_ADDR) go through mask and restore as the others do: typed placeholders, the
original back to the letter, and a placeholder-like text of a new kind in an original is a literal."""

from pathlib import Path

import pytest

from boxed.config import read_config
from boxed.detect import DetectConfig
from boxed.mask import BOXED_KINDS, MarkerMap, mask_text, restore

TEXT = """Passport: 4510 123456 and Загранпаспорт 75 1234567.
SSN 512-34-7890, VAT DE111111125, wallet bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 and 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed.
Code: 6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk, again 6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk.
"""


def test_a_text_with_every_new_kind_comes_back_as_it_was():
    markers = MarkerMap()
    masked, counts = mask_text(TEXT, markers, 2, DetectConfig())
    assert counts == {"PASSPORT": 2, "SSN": 1, "VAT_ID": 1, "CRYPTO_ADDR": 2, "SECRET": 2}  # places, not placeholders: the code is twice there
    assert "[PASSPORT_1]" in masked and "[PASSPORT_2]" in masked and "[SSN_1]" in masked and "[VAT_ID_1]" in masked
    assert "[CRYPTO_ADDR_1]" in masked and "[CRYPTO_ADDR_2]" in masked and masked.count("[SECRET_1]") == 2
    for original in ("4510 123456", "512-34-7890", "DE111111125", "6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"):
        assert original not in masked
    result = restore(masked, markers)
    assert result.text == TEXT and not result.unknown and not result.suspicious


@pytest.mark.parametrize("level,left", [(0, "4510 123456"), (1, "DE111111125")])
def test_a_lower_level_leaves_what_belongs_to_a_higher_one(level, left):
    masked, _ = mask_text(TEXT, MarkerMap(), level, DetectConfig())
    assert left in masked


@pytest.mark.parametrize("kind", ["PASSPORT", "SSN", "VAT_ID", "CRYPTO_ADDR"])
def test_a_marker_like_text_of_a_new_kind_in_an_original_is_a_literal(kind):
    assert kind in BOXED_KINDS
    markers = MarkerMap()
    masked, counts = mask_text(f"old note [{kind}_7]", markers, 2, DetectConfig())
    assert masked == "old note [LITERAL_1]" and counts == {"LITERAL": 1}
    assert restore(masked, markers).text == f"old note [{kind}_7]"


def test_the_guide_tells_what_to_do_with_a_dictionary_kind_that_is_now_a_built_in_one():
    page = (Path(__file__).resolve().parents[2] / "docs" / "guide" / "troubleshooting.md").read_text(encoding="utf-8")
    (row,) = [line for line in page.splitlines() if "a term cannot use a built-in kind name" in line]
    for kind in ("PASSPORT", "SSN", "VAT_ID", "CRYPTO_ADDR"):
        assert kind in row, kind
    assert "boxed.toml" in row


@pytest.mark.parametrize("kind", ["passport", "SSN", "Vat_Id", "crypto_addr"])
def test_a_dictionary_cannot_use_the_name_of_a_new_kind(tmp_path, kind):
    path = tmp_path / "boxed.toml"
    path.write_text(f'[boxed.dictionary]\n"Acme" = "{kind}"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="built-in kind"):
        read_config(path)
