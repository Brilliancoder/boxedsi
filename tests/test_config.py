"""boxed.toml: a project dictionary names its own kinds (CLIENT, PROJECT), never one that boxed itself uses."""

import pytest

from boxed.config import load_config, read_config
from boxed.mask import BOXED_KINDS


def write(tmp_path, body):
    path = tmp_path / "boxed.toml"
    path.write_text("[boxed]\n[boxed.dictionary]\n" + body, encoding="utf-8")  # the terms have Cyrillic letters: UTF-8, not the code page
    return path


@pytest.mark.parametrize("kind", sorted(BOXED_KINDS))
def test_a_dictionary_may_not_use_a_built_in_kind_name(tmp_path, kind):
    path = write(tmp_path, f'"Acme Corp" = "{kind}"\n')
    with pytest.raises(ValueError, match="built-in kind name") as excinfo:
        load_config(tmp_path)
    message = str(excinfo.value)
    assert message.startswith("boxed.toml: " f"[boxed.dictionary]")
    assert "Acme" not in message  # a term is a client's name: no message quotes it


@pytest.mark.parametrize("kind", ["date", "Date", "email", "Money", "number", "literal", "pErSoN"])
def test_the_case_of_a_kind_does_not_hide_a_built_in_name(tmp_path, kind):
    # the detector names a dictionary kind in upper case, so these are EMAIL, DATE, ... for it
    write(tmp_path, f'"Acme Corp" = "{kind}"\n')
    with pytest.raises(ValueError, match="built-in kind name"):
        load_config(tmp_path)


def test_one_built_in_kind_among_good_ones_is_enough_to_refuse(tmp_path):
    write(tmp_path, '"Acme Corp" = "CLIENT"\n"Q3 plan" = "PROJECT"\n"1 Jan" = "DATE"\n')
    with pytest.raises(ValueError, match="built-in kind name"):
        load_config(tmp_path)


def test_the_message_is_the_same_whichever_term_and_kind_caused_it(tmp_path):
    messages = set()
    for term, kind in [("Acme Corp", "DATE"), ("Иван Петров", "email"), ("secret-project-x", "NUMBER")]:
        path = write(tmp_path, f'"{term}" = "{kind}"\n')
        with pytest.raises(ValueError) as excinfo:
            load_config(tmp_path)
        messages.add(str(excinfo.value).replace(str(path), "<path>"))
    assert len(messages) == 1


def test_read_config_refuses_it_too(tmp_path):
    # the native host reads the boxed home's boxed.toml through read_config
    path = write(tmp_path, '"Acme Corp" = "IP"\n')
    with pytest.raises(ValueError, match="built-in kind name"):
        read_config(path)


@pytest.mark.parametrize("kind", ["CLIENT", "client", "PROJECT", "YEAR", "DEAL_2026", "DATE_OF_BIRTH", "EMAILS", "PERSONA"])
def test_a_kind_of_its_own_is_accepted(tmp_path, kind):
    write(tmp_path, f'"Acme Corp" = "{kind}"\n')
    assert load_config(tmp_path).dictionary == {"Acme Corp": kind}


def test_no_dictionary_and_an_empty_one_are_accepted(tmp_path):
    (tmp_path / "boxed.toml").write_text("[boxed]\nlevel = 2\n")
    assert load_config(tmp_path).dictionary == {}
    write(tmp_path, "")
    assert load_config(tmp_path).dictionary == {}


# ---- a list holds strings, and the message does not say which item or what it was ----

LISTS = ["internal_domains", "allow", "protected_paths", "mcp_roots", "ner"]
NOT_STRINGS = {
    "a number": "[1]",
    "a number after a string": '["corp.example.com", 2]',
    "a float": "[1.5]",
    "a boolean": "[true]",
    "a list": '[["nested"]]',
    "a table": '[{ a = "b" }]',
    "a date": "[1979-05-27]",
    "a date and time": "[1979-05-27T07:32:00]",
}


@pytest.mark.parametrize("key", LISTS)
@pytest.mark.parametrize("items", NOT_STRINGS.values(), ids=NOT_STRINGS.keys())
def test_a_list_of_boxed_toml_holds_strings_only(tmp_path, key, items):
    path = tmp_path / "boxed.toml"
    path.write_text(f"[boxed]\n{key} = {items}\n")
    for read in (lambda: load_config(tmp_path), lambda: read_config(path)):  # the native host reads the file through read_config
        with pytest.raises(ValueError) as excinfo:
            read()
        assert str(excinfo.value) == "boxed.toml: " f"[boxed].{key} must be a list of strings"  # the same for every item that is wrong


@pytest.mark.parametrize("key", [k for k in LISTS if k != "ner"])
def test_a_list_of_strings_is_accepted(tmp_path, key):
    (tmp_path / "boxed.toml").write_text(f'[boxed]\n{key} = ["corp.example.com", "~/notes"]\n')
    assert getattr(load_config(tmp_path), key) == ["corp.example.com", "~/notes"]


def test_an_empty_list_and_the_name_models_are_accepted(tmp_path):
    (tmp_path / "boxed.toml").write_text('[boxed]\ninternal_domains = []\nner = ["ru", "en"]\n')
    config = load_config(tmp_path)
    assert config.internal_domains == [] and config.ner == ["ru", "en"]


def test_a_value_that_is_not_a_list_keeps_its_own_message(tmp_path):
    path = tmp_path / "boxed.toml"
    path.write_text('[boxed]\nallow = "ivan@acme.com"\n')
    with pytest.raises(ValueError) as excinfo:
        load_config(tmp_path)
    assert str(excinfo.value) == "boxed.toml: " f"[boxed].allow must be list"


# ---- a dictionary kind is a string, and the message names neither the term nor the kind ----

NOT_KINDS = {
    "a number": "5",
    "a float": "1.5",
    "a boolean": "true",
    "a list": '["CLIENT"]',
    "a table": '{ kind = "CLIENT" }',
    "a date": "1979-05-27",
    "a date and time": "1979-05-27T07:32:00",
}
KIND_REFUSAL = "[boxed.dictionary] every kind must be a string, such as CLIENT"


@pytest.mark.parametrize("kind", NOT_KINDS.values(), ids=NOT_KINDS.keys())
def test_a_dictionary_kind_must_be_a_string(tmp_path, kind):
    path = write(tmp_path, f'"Acme Corp" = {kind}\n')
    for read in (lambda: load_config(tmp_path), lambda: read_config(path)):  # the native host reads the file through read_config
        with pytest.raises(ValueError) as excinfo:
            read()
        assert str(excinfo.value) == "boxed.toml: " f"{KIND_REFUSAL}"


def test_one_kind_that_is_not_a_string_among_good_ones_is_enough_to_refuse(tmp_path):
    path = write(tmp_path, '"Acme Corp" = "CLIENT"\n"Q3 plan" = 7\n"Beta" = "PROJECT"\n')
    with pytest.raises(ValueError) as excinfo:
        load_config(tmp_path)
    assert str(excinfo.value) == "boxed.toml: " f"{KIND_REFUSAL}"


def test_the_kind_message_is_the_same_whichever_term_and_value_caused_it(tmp_path):
    messages = set()
    for term, value in [("Acme Corp", "12345"), ("Иван Петров", "true"), ("secret-project-x", '["PROJECT"]')]:
        path = write(tmp_path, f'"{term}" = {value}\n')
        with pytest.raises(ValueError) as excinfo:
            load_config(tmp_path)
        message = str(excinfo.value).replace(str(path), "<path>")
        assert term not in message and value not in message  # a term is a client's name; the value is what the person wrote
        messages.add(message)
    assert len(messages) == 1


def test_a_kind_that_is_not_a_string_is_refused_before_the_built_in_names_are_looked_at(tmp_path):
    path = write(tmp_path, '"Acme Corp" = "DATE"\n"Q3 plan" = 7\n')
    with pytest.raises(ValueError) as excinfo:
        load_config(tmp_path)
    assert str(excinfo.value) == "boxed.toml: " f"{KIND_REFUSAL}"
