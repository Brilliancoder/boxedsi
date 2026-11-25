import io
import json

import pytest

import boxed.cli
from boxed.cli import main

TEXT = "write to ivan.petrov@acme.com, key AKIAIOSFODNN7EXAMPLE\r\nbye"


def run(capsys, argv, stdin=None, monkeypatch=None):
    if stdin is not None:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    code = main(argv)
    out, err = capsys.readouterr()
    return code, out, err


def test_mask_restore_roundtrip_cli(tmp_path, capsys):
    src = tmp_path / "in.txt"
    src.write_bytes(TEXT.encode())
    code, masked, err = run(capsys, ["mask", "--scope", "t1", str(src)])
    assert code == 0 and "t1" in err
    assert "ivan.petrov@acme.com" not in masked and "AKIA" not in masked
    back = tmp_path / "masked.txt"
    back.write_bytes(masked.encode())
    code, restored, _ = run(capsys, ["restore", "--scope", "t1", str(back)])
    assert code == 0
    assert restored == TEXT


def test_restore_unknown_exit_3(tmp_path, capsys, monkeypatch):
    src = tmp_path / "in.txt"
    src.write_text(TEXT)
    run(capsys, ["mask", "--scope", "t1", str(src)])
    code, out, err = run(capsys, ["restore", "--scope", "t1", "-"], stdin="see [EMAIL_9]", monkeypatch=monkeypatch)
    assert code == 3 and out == "" and "[EMAIL_9]" in err
    code, out, err = run(capsys, ["restore", "--scope", "t1", "--force", "-"], stdin="see [EMAIL_9]", monkeypatch=monkeypatch)
    assert code == 0 and out == "see [EMAIL_9]" and "[EMAIL_9]" in err


def test_restore_unknown_scope_fails(capsys, monkeypatch):
    code, out, _ = run(capsys, ["restore", "--scope", "nope", "-"], stdin="x", monkeypatch=monkeypatch)
    assert code == 2 and out == ""


def test_mask_writes_journal(tmp_path, capsys, boxed_env):
    src = tmp_path / "in.txt"
    src.write_text("mail ivan.petrov@acme.com")
    run(capsys, ["mask", "--scope", "t1", str(src)])
    journal = (boxed_env / "journal.jsonl").read_text()
    assert "ivan.petrov@acme.com" not in journal
    rec = json.loads(journal.splitlines()[0])
    assert (rec["channel"], rec["status"], rec["markers_by_kind"], rec["scope"]) == ("manual", "prepared", {"EMAIL": 1}, "t1")


def test_journal_verify_cli(tmp_path, capsys, boxed_env):
    src = tmp_path / "in.txt"
    src.write_text("mail ivan.petrov@acme.com")
    run(capsys, ["mask", str(src)])
    code, out, _ = run(capsys, ["journal", "verify"])
    assert code == 0 and "ok" in out
    path = boxed_env / "journal.jsonl"
    rec = json.loads(path.read_text())
    rec["level"] = 0
    path.write_text(json.dumps(rec) + "\n")
    code, _, _ = run(capsys, ["journal", "verify"])
    assert code == 1


def test_config_dictionary_applied(tmp_path, capsys, monkeypatch):
    (tmp_path / "boxed.toml").write_text('[boxed]\nlevel = 2\n[boxed.dictionary]\n"Acme Corp" = "CLIENT"\n')
    monkeypatch.chdir(tmp_path)
    code, out, _ = run(capsys, ["mask", "-"], stdin="Deal with Acme Corp", monkeypatch=monkeypatch)
    assert code == 0 and out == "Deal with [CLIENT_1]"


def test_config_unknown_key_fails(tmp_path, capsys, monkeypatch):
    (tmp_path / "boxed.toml").write_text("[boxed]\nlevl = 1\n")
    monkeypatch.chdir(tmp_path)
    code, out, err = run(capsys, ["mask", "-"], stdin="mail a@x.io", monkeypatch=monkeypatch)
    assert code == 2 and out == "" and "levl" not in err  # a key of the person is not quoted; the known ones are named
    assert err == "boxed: error: boxed.toml: [boxed] has a key boxed does not know; the known ones are " + ", ".join(boxed.config._TYPES) + "\n"


def test_mask_fails_closed(capsys, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("detector crashed")

    monkeypatch.setattr(boxed.cli, "mask_text", boom)
    code, out, err = run(capsys, ["mask", "-"], stdin="mail a@x.io", monkeypatch=monkeypatch)
    assert code == 2 and out == "" and err == "boxed: error: RuntimeError: an unexpected error; its message is not shown, it may quote a path or a value\n"



def test_the_error_line_quotes_no_path_and_no_value_that_python_or_a_library_put_in_a_message(tmp_path, capsys, monkeypatch):
    missing = tmp_path / "client-acme" / "notes.txt"
    code, out, err = run(capsys, ["mask", str(missing)])
    assert (code, out, err) == (2, "", "boxed: error: no such file or directory\n")
    monkeypatch.setattr(boxed.cli, "_read_input", int)  # a built-in called by boxed: its ValueError quotes what it was given
    code, out, err = run(capsys, ["mask", "hunter22-x"])
    assert code == 2 and out == "" and "hunter22" not in err and err.startswith("boxed: error: ValueError: an unexpected error")


@pytest.mark.parametrize(
    "argv",
    [
        ["audit", "--since", "2026-13-01"],
        ["dashboard", "--csv", "r.csv", "--since", "2026-13-45"],
        ["dashboard", "--csv", "r.csv", "--until", "2026/10/01"],
        ["journal", "export", "--out", "e.json", "--since", "2026-02-30"],
        ["journal", "export", "--out", "e.json", "--until", "tomorrow"],
    ],
)
def test_a_wrong_date_is_refused_while_the_arguments_are_read_in_fixed_words(argv, tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as stop:
        main(argv)
    out, err = capsys.readouterr()
    flag, value = argv[-2], argv[-1]
    assert stop.value.code == 2 and out == "" and value not in err
    assert err.endswith(f"error: argument {flag}: a date is written YYYY-MM-DD, for example 2026-12-31\n")
    assert not list(tmp_path.iterdir())  # nothing was written


def test_a_missing_extra_is_named_by_its_module(capsys, monkeypatch):
    def needs_natasha(*args, **kwargs):
        raise ModuleNotFoundError("No module named 'natasha'", name="natasha")

    monkeypatch.setattr(boxed.cli, "mask_text", needs_natasha)
    code, out, err = run(capsys, ["mask", "-"], stdin="x", monkeypatch=monkeypatch)
    assert (code, out, err) == (2, "", "boxed: error: no module named natasha: install the extra that brings it (see install.md)\n")


def test_an_error_boxed_raises_itself_keeps_its_fixed_words(capsys):
    code, out, err = run(capsys, ["workspace", "drop", "abc", "--dry-run"])
    assert (code, out, err) == (2, "", "boxed: error: --dry-run works with sync only\n")


def test_only_a_user_error_shows_its_message_whoever_raised_the_other():
    from boxed.errors import UserError

    assert boxed.cli._error_text(UserError("fixed words")) == "fixed words"
    assert boxed.cli._error_text(ValueError("hunter22-x")) == f"ValueError: {boxed.cli.UNEXPECTED}"
    try:  # a plain ValueError raised by a raise statement in boxed is no longer trusted for its words
        boxed.cli._date("hunter22-x")
    except ValueError as e:
        assert boxed.cli._error_text(e) == "a date is written YYYY-MM-DD, for example 2026-12-31"  # a UserError
    try:
        raise ValueError("a value hunter22-x in a message of boxed")
    except ValueError as e:
        assert "hunter22" not in boxed.cli._error_text(e)


@pytest.mark.parametrize(
    "toml,value",
    [
        ('[boxed]\nner = ["ru", "hunter22-x"]\n', "hunter22-x"),  # the value that is wrong
        ("[boxed]\nhunter22_key = 1\n", "hunter22_key"),  # a key that is not known
        ('[boxed]\nlevel = "hunter22-x"\n', "hunter22-x"),
        ('[boxed.dictionary]\n"hunter22 corp" = "CLIENT"\n"hunter22 corp" = "CLIENT"\n', "hunter22"),  # tomllib quotes the key
        ('[boxed.policy.rules]\n"finance:hunter22" = "deny"\n', "hunter22"),
        ('[boxed.policy.rules]\n"finance:personal-private" = "hunter22"\n', "hunter22"),
        ('[boxed.policy.rules]\n"secrets:personal-private" = "allow"\n', None),  # looser than the profile: known names only
    ],
)
def test_a_wrong_boxed_toml_names_neither_its_path_nor_the_value_on_the_real_command_line(tmp_path, toml, value):
    import os
    import subprocess
    import sys

    folder = tmp_path / "client-acme-folder"
    folder.mkdir()
    (folder / "boxed.toml").write_text(toml, encoding="utf-8")
    env = {**os.environ, "HOME": str(tmp_path), "BOXED_HOME": str(tmp_path / "boxed-home"), "BOXED_KEYSTORE": "insecure-file"}
    done = subprocess.run(
        [sys.executable, "-m", "boxed.cli", "mask", "-"], input="mail a@x.io", cwd=folder, env=env, capture_output=True, text=True, timeout=120
    )
    assert done.returncode == 2 and done.stdout == ""
    assert done.stderr.startswith("boxed: error: ") and done.stderr.count("\n") == 1
    assert (value is None or value not in done.stderr) and "client-acme" not in done.stderr and str(tmp_path) not in done.stderr
    assert "boxed.toml" in done.stderr or "[boxed." in done.stderr  # it still says which file or section is wrong


@pytest.mark.parametrize(
    "argv,flag,reason",
    [
        (["mask", "--level", "hunter22"], "--level", "not a whole number"),
        (["mask", "--level", "7777"], "--level", "not one of 0, 1, 2, 3, 4"),
        (["ask", "--provider", "hunter22", "--model", "m"], "--provider", "not one of "),
        (["key", "status", "hunter22"], "provider", "not one of "),
        (["hunter22"], "command", "not one of "),
        (["mask", "--hunter22"], None, "unrecognized arguments: boxed COMMAND --help lists the known ones"),
        (["mask", "-", "hunter22"], None, "unrecognized arguments: "),
        (["mask", "--sc", "x", "--sc"], None, ""),
    ],
)
def test_a_wrong_argument_is_named_with_a_fixed_reason_and_its_value_is_not_repeated(capsys, argv, flag, reason):
    with pytest.raises(SystemExit) as stop:
        main(argv)
    out, err = capsys.readouterr()
    line = err.splitlines()[-1]
    assert stop.value.code == 2 and out == "" and "hunter22" not in err and "error: " in line
    if flag is not None:
        assert f"error: argument {flag}: {reason}" in line
    else:
        assert reason in line


def test_a_missing_argument_is_still_named(capsys):
    with pytest.raises(SystemExit):
        main(["restore", "-"])
    assert capsys.readouterr().err.splitlines()[-1] == "boxed restore: error: the following arguments are required: --scope"


def test_a_vault_that_cannot_be_decrypted_is_named_without_the_scope(capsys, monkeypatch):
    from boxed.vault import Vault, VaultError

    def damaged(self, scope):
        raise VaultError(f"cannot decrypt scope {scope!r}: wrong key or tampered data")

    monkeypatch.setattr(Vault, "load_map", damaged)
    monkeypatch.setattr(Vault, "scopes", lambda self: ["client-acme-scope"])
    code, out, err = run(capsys, ["restore", "--scope", "client-acme-scope", "-"], stdin="x", monkeypatch=monkeypatch)
    assert (code, out) == (2, "") and "client-acme" not in err and err.startswith("boxed: error: a marker map of the vault")


def test_journal_show_skips_damaged_lines(boxed_env, capsys, monkeypatch):
    code, _, _ = run(capsys, ["mask", "-"], stdin="mail ivan@acme.com\n", monkeypatch=monkeypatch)
    assert code == 0
    with (boxed_env / "journal.jsonl").open("a") as f:
        f.write("not json\n")
    code, out, err = run(capsys, ["journal", "show"])
    assert code == 0 and '"seq": 1' in out and "1 damaged line" in err
