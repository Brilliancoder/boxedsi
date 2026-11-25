"""The text edits of config.toml under generated files: a cut Codex setting comes back so that tomllib reads the file exactly as before,
whether the file was left alone (byte for byte) or got another key meanwhile. Fake HOME, invented names, through cli.main."""

import json
import shutil
import tomllib

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from boxed.cli import main

NAMES = st.from_regex(r"[a-z][a-z0-9_-]{0,8}", fullmatch=True)
TEXT = st.text(st.characters(codec="utf-8", exclude_categories=("Cs", "Cc")), max_size=20)


def quoted(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)  # without control characters a JSON string is a TOML basic string


@st.composite
def configs(draw):
    """(config text, the setting to quarantine as (agent kind name))."""
    provider = draw(NAMES)
    lines = [f"model = {quoted(draw(TEXT))}"]
    if draw(st.booleans()):
        lines.append("notify = [" + ", ".join(quoted(w) for w in draw(st.lists(TEXT, min_size=1, max_size=4))) + "]")
    lines += ["", f"[model_providers.{provider}]", f"name = {quoted(draw(TEXT))}", f"base_url = {quoted('https://' + draw(NAMES) + '.example.net')}"]
    for name in draw(st.lists(NAMES, max_size=3, unique=True)):
        if name != "model_providers":
            lines += ["", f"[{name}]", f"value = {draw(st.integers(-5, 5))}"]
    text = "\n".join(lines) + ("\n" if draw(st.booleans()) else "")
    keys = ["model_providers." + provider] + (["notify"] if "notify = [" in text else [])
    return text, draw(st.sampled_from(keys))


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(case=configs(), edit=st.booleans())
def test_a_cut_codex_setting_reads_back_exactly_as_before(case, edit, tmp_path, monkeypatch, capsys):
    text, name = case
    home = tmp_path / "home"
    shutil.rmtree(home, ignore_errors=True)
    (home / ".codex").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)
    config = home / ".codex" / "config.toml"
    config.write_text(text, encoding="utf-8")
    before = tomllib.loads(text)

    assert main(["skills", "quarantine", f"codex:setting:user:{name}"]) == 0, capsys.readouterr()
    out = capsys.readouterr().out
    cut = tomllib.loads(config.read_text(encoding="utf-8"))
    assert name.split(".")[-1] not in (cut.get("model_providers", {}) if "." in name else cut)
    if edit:
        config.write_text("added_later = 1\n" + config.read_text(encoding="utf-8"), encoding="utf-8")
    qid = out.split("quarantine id ", 1)[1].split(":", 1)[0]
    assert main(["skills", "restore", qid]) == 0, capsys.readouterr()
    capsys.readouterr()
    if edit:
        assert tomllib.loads(config.read_text(encoding="utf-8")) == {"added_later": 1, **before}
    else:
        assert config.read_text(encoding="utf-8") == text


@pytest.mark.parametrize("text", ['model_providers = { relay = { name = "R" } }\n', 'model_providers.relay.name = "R"\nmodel_providers.relay.url = "u"\n'])
def test_a_setting_written_in_a_form_the_text_edit_cannot_cut_is_refused(text, tmp_path, monkeypatch, capsys):
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)
    (home / ".codex" / "config.toml").write_text(text)
    code = main(["skills", "quarantine", "codex:setting:user:model_providers.relay"])
    _, err = capsys.readouterr()
    assert code == 2 and "the config file of this item cannot be edited safely here" in err
    assert (home / ".codex" / "config.toml").read_text() == text
