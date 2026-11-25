import csv
import io
import sys
import types

import pytest

from boxed.cli import main


def run(capsys, argv, stdin=None, monkeypatch=None):
    if stdin is not None:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    code = main(argv)
    out, err = capsys.readouterr()
    return code, out, err


def test_policy_check_denies_personal_data_for_a_personal_account(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "boxed.toml").write_text('[boxed]\n[boxed.policy]\nprofile = "approved-only"\n')
    argv = ["policy", "check", "--recipient", "openai:personal-private:US", "-"]
    code, out, err = run(capsys, argv, stdin="mail ivan@acme.com", monkeypatch=monkeypatch)
    assert code == 4 and "deny" in out and "EEA" in out
    assert "ivan@acme.com" not in out + err


def test_policy_check_allows_clean_text_and_warns_about_training(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    argv = ["policy", "check", "--recipient", "openai:personal-training:US", "-"]
    code, out, _ = run(capsys, argv, stdin="hello world", monkeypatch=monkeypatch)
    assert code == 0 and "allow" in out and "train" in out


def write_sales(tmp_path):
    (tmp_path / "boxed.toml").write_text('[boxed]\n[boxed.dictionary]\n"Acme Corp" = "CLIENT"\n')
    table = tmp_path / "sales.csv"
    table.write_text("client;Acme Corp margin\nRomashka;1 234,50\nLutik;99,5\n\n")
    return table


def test_plan_prompt_masks_the_task_and_column_names(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    table = write_sales(tmp_path)
    argv = ["plan", "prompt", "--task", "top clients of Acme Corp by margin", "--scope", "p1", str(table)]
    code, out, err = run(capsys, argv)
    assert code == 0 and "[CLIENT_1]" in out and "p1" in err
    assert "Acme Corp" not in out and "Romashka" not in out and "1 234" not in out


def test_plan_run_restores_names_and_runs_on_real_rows(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    table = write_sales(tmp_path)
    run(capsys, ["plan", "prompt", "--task", "top clients of Acme Corp", "--scope", "p1", str(table)])
    plan = tmp_path / "plan.json"
    plan.write_text('```json\n{"version": 1, "steps": [{"op": "sort", "by": ["[CLIENT_1] margin"], "desc": true}, '
                    '{"op": "limit", "n": 1}]}\n```')
    code, out, _ = run(capsys, ["plan", "run", "--scope", "p1", str(plan), str(table)])
    assert code == 0 and out.splitlines() == ["client;Acme Corp margin", "Romashka;1234.5"]


def test_plan_run_refuses_unknown_markers(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    table = write_sales(tmp_path)
    run(capsys, ["plan", "prompt", "--task", "top clients", "--scope", "p1", str(table)])
    plan = tmp_path / "plan.json"
    plan.write_text('{"version": 1, "steps": [{"op": "filter", "column": "client", "cmp": "==", "value": "[CLIENT_9]"}]}')
    code, out, err = run(capsys, ["plan", "run", "--scope", "p1", str(plan), str(table)])
    assert code == 3 and out == "" and "[CLIENT_9]" in err


def test_plan_prompt_needs_header_ok_for_a_data_like_header(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    table = tmp_path / "t.csv"
    table.write_text("ivan,1500\nanna,200\n")
    code, out, err = run(capsys, ["plan", "prompt", "--task", "sum", str(table)])
    assert code == 2 and out == "" and "header" in err
    code, out, _ = run(capsys, ["plan", "prompt", "--task", "sum", "--header-ok", str(table)])
    assert code == 0


def test_plan_refuses_a_table_over_the_cell_limit_before_it_normalises_or_writes_anything(tmp_path, capsys, monkeypatch, boxed_env):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("boxed.opplan.MAX_CELLS", 8)
    table = tmp_path / "t.csv"
    table.write_text("a,b,c\n1,2,3\n4,5,6\n7,8,9\n")  # 9 cells of data
    plan = tmp_path / "plan.json"
    plan.write_text('{"version": 1, "steps": [{"op": "limit", "n": 1}]}')
    for argv in (
        ["plan", "prompt", "--task", "sum", str(table)],
        ["plan", "prompt", "--task", "sum", "--decimal", ".", str(table)],
        ["plan", "run", "--scope", "nope", str(plan), str(table)],  # the table comes before the scope
    ):
        code, out, err = run(capsys, argv)
        assert code == 2 and out == "" and "cells" in err and "unknown scope" not in err
    assert not boxed_env.exists()  # not the vault, not the journal


SALES = "client;region;revenue;day\nRomashka;EU;1 234,50;21.10.2026\nLutik;US;99,5;22.10.2026\nRomashka;EU;10,00;23.10.2026\n"


def test_plan_run_normalises_only_the_columns_the_plan_reads(tmp_path, capsys, monkeypatch):
    from boxed import opplan

    monkeypatch.chdir(tmp_path)
    table = tmp_path / "sales.csv"
    table.write_text(SALES)
    asked, real = [], opplan.normalize_rows
    monkeypatch.setattr(opplan, "normalize_rows", lambda rows, decimal=".", columns=None: asked.append(columns) or real(rows, decimal, columns))
    run(capsys, ["plan", "prompt", "--task", "top clients", "--scope", "p1", str(table)])
    assert asked == [None]  # the model is told the type of every column
    plan = tmp_path / "plan.json"
    plan.write_text('{"version": 1, "steps": [{"op": "group", "by": ["client"], "aggregates": {"total": ["sum", "revenue"]}}, '
                    '{"op": "sort", "by": ["total"], "desc": true}]}')
    code, out, _ = run(capsys, ["plan", "run", "--scope", "p1", str(plan), str(table)])
    assert code == 0 and out.splitlines() == ["client;total", "Romashka;1244.5", "Lutik;99.5"]
    assert asked == [None, {0, 2}]  # client and revenue; region and day are dropped by the group


def test_plan_run_normalises_every_column_when_the_plan_drops_none(tmp_path, capsys, monkeypatch):
    from boxed import opplan

    monkeypatch.chdir(tmp_path)
    table = tmp_path / "sales.csv"
    table.write_text(SALES)
    run(capsys, ["plan", "prompt", "--task", "top clients", "--scope", "p1", str(table)])
    asked, real = [], opplan.normalize_rows
    monkeypatch.setattr(opplan, "normalize_rows", lambda rows, decimal=".", columns=None: asked.append(columns) or real(rows, decimal, columns))
    plan = tmp_path / "plan.json"
    plan.write_text('{"version": 1, "steps": [{"op": "limit", "n": 2}]}')
    code, out, _ = run(capsys, ["plan", "run", "--scope", "p1", str(plan), str(table)])
    assert code == 0 and out.splitlines() == ["client;region;revenue;day", "Romashka;EU;1234.5;2026-10-21", "Lutik;US;99.5;2026-10-22"]
    plan.write_text("I cannot do that")  # not a plan: all columns are normalised, parse_plan says what is wrong
    code, out, err = run(capsys, ["plan", "run", "--scope", "p1", str(plan), str(table)])
    assert code == 2 and out == "" and "not valid JSON" in err
    assert asked == [None, None]


def test_mask_file_and_restore_file(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "clients.csv"
    src.write_text("name,email\nIvan,ivan.petrov@acme.com\n")
    code, out, err = run(capsys, ["mask-file", "--scope", "f1", str(src), str(tmp_path / "masked.csv")])
    assert code == 0 and "complete: yes" in out and "f1" in err
    assert "ivan.petrov" not in (tmp_path / "masked.csv").read_text()
    code, _, _ = run(capsys, ["restore-file", "--scope", "f1", str(tmp_path / "masked.csv"), str(tmp_path / "back.csv")])
    assert code == 0 and (tmp_path / "back.csv").read_text() == src.read_text()


def test_restore_file_refuses_unknown_markers_unless_forced(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "a.csv"
    src.write_text("email\nivan@acme.com\n")
    run(capsys, ["mask-file", "--scope", "f2", str(src), str(tmp_path / "m.csv")])
    (tmp_path / "answer.csv").write_text("email\n[EMAIL_9]\n")
    argv = ["restore-file", "--scope", "f2", str(tmp_path / "answer.csv"), str(tmp_path / "out.csv")]
    code, _, err = run(capsys, argv)
    assert code == 3 and "[EMAIL_9]" in err and not (tmp_path / "out.csv").exists()
    assert not list(tmp_path.glob(".out*"))
    code, _, _ = run(capsys, argv[:1] + ["--force"] + argv[1:])
    assert code == 0 and (tmp_path / "out.csv").exists()


def test_install_native_host_cli(tmp_path, capsys, monkeypatch, macos):
    monkeypatch.setenv("HOME", str(tmp_path))
    code, out, _ = run(capsys, ["install", "native-host", "--extension-id", "a" * 32, "--dry-run"])
    assert code == 0 and "NativeMessagingHosts" in out and "load unpacked" in out
    assert not (tmp_path / "Library").exists()
    code, _, err = run(capsys, ["install", "native-host"])
    assert code == 2 and "extension-id" in err and "unpacked" in err


@pytest.mark.skipif(sys.platform == "win32", reason="boxed install codex is not supported on Windows yet")
def test_install_codex_cli_dry_run_writes_nothing(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))  # ~/.codex/config.toml is looked for here, never in the home of the person who runs the tests
    config = tmp_path / ".codex" / "config.toml"
    code, out, _ = run(capsys, ["install", "codex", "--dry-run"])
    assert code == 0 and out == f"would add boxed MCP server to {config}\n"
    assert list(tmp_path.iterdir()) == []  # not even the folder
    code, out, _ = run(capsys, ["install", "codex"])
    assert code == 0 and out == f"added boxed MCP server to {config}\n" and config.is_file()
    written = config.read_text()
    code, out, _ = run(capsys, ["install", "codex", "--dry-run"])
    assert code == 0 and out == f"boxed is already in {config}\n"
    assert config.read_text() == written and sorted(p.name for p in config.parent.iterdir()) == ["config.toml"]


def test_dashboard_html(tmp_path, capsys, monkeypatch):
    run(capsys, ["mask", "--scope", "d1", "-"], stdin="mail ivan@acme.com", monkeypatch=monkeypatch)
    out_html = tmp_path / "dash.html"
    code, _, _ = run(capsys, ["dashboard", "--html", str(out_html), "--since", "2000-01-01"])
    html = out_html.read_text()
    assert code == 0 and "<html" in html.lower() and "ivan@acme.com" not in html


def test_journal_key_export_and_offline_check(tmp_path, capsys, monkeypatch):
    run(capsys, ["mask", "--scope", "e1", "-"], stdin="mail ivan@acme.com", monkeypatch=monkeypatch)
    code, key, _ = run(capsys, ["journal", "key"])
    assert code == 0 and len(key.strip()) == 64
    out_json = tmp_path / "export.json"
    code, _, _ = run(capsys, ["journal", "export", "--out", str(out_json)])
    assert code == 0 and key.strip() in out_json.read_text() and "ivan@acme.com" not in out_json.read_text()
    code, out, _ = run(capsys, ["journal", "check-export", str(out_json)])
    assert code == 0 and out.startswith("ok")
    out_json.write_text(out_json.read_text().replace('"level": 2', '"level": 0'))
    code, out, _ = run(capsys, ["journal", "check-export", str(out_json)])
    assert code == 1 and out.startswith("BROKEN")


def test_outputs_wait_for_the_journal(tmp_path, capsys, monkeypatch, boxed_env):
    monkeypatch.chdir(tmp_path)
    table = write_sales(tmp_path)
    run(capsys, ["plan", "prompt", "--task", "top", "--scope", "p1", str(table)])
    plan = tmp_path / "plan.json"
    plan.write_text('{"version": 1, "steps": [{"op": "limit", "n": 1}]}')
    src = tmp_path / "a.csv"
    src.write_text("email\nivan@acme.com\n")
    run(capsys, ["mask-file", "--scope", "f3", str(src), str(tmp_path / "m.csv")])
    journal = boxed_env / "journal.jsonl"
    journal.unlink()
    journal.mkdir()  # the journal cannot be written
    code, out, _ = run(capsys, ["plan", "run", "--scope", "p1", str(plan), str(table)])
    assert code == 2 and out == ""
    code, out, _ = run(capsys, ["restore-file", "--scope", "f3", str(tmp_path / "m.csv"), str(tmp_path / "back.csv")])
    assert code == 2 and not (tmp_path / "back.csv").exists() and not list(tmp_path.glob(".back*"))


def test_restore_file_refuses_its_own_input_as_output(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "a.csv"
    src.write_text("email\nivan@acme.com\n")
    run(capsys, ["mask-file", "--scope", "f4", str(src), str(tmp_path / "m.csv")])
    before = (tmp_path / "m.csv").read_text()
    code, _, _ = run(capsys, ["restore-file", "--scope", "f4", str(tmp_path / "m.csv"), str(tmp_path / "m.csv")])
    assert code == 2 and (tmp_path / "m.csv").read_text() == before


def sniffer_that_remembers(monkeypatch):
    """csv.Sniffer replaced by one that answers ";" for any text and keeps the texts it was asked about."""
    seen = []

    class Sniffer:
        def sniff(self, sample, delimiters=None):
            seen.append(sample)
            return types.SimpleNamespace(delimiter=";")

    monkeypatch.setattr(csv, "Sniffer", Sniffer)
    return seen


def test_windows_the_sniffer_reads_a_table_with_line_feeds_only(windows, tmp_path, monkeypatch):
    from boxed.cli import _read_table

    seen = sniffer_that_remembers(monkeypatch)
    (tmp_path / "t.csv").write_bytes(b"a;b\r\n1;2\r\n\r\n")
    assert _read_table(str(tmp_path / "t.csv"))[:2] == (["a", "b"], [["1", "2"]])  # the table itself is read as it is
    assert seen == ["a;b\n1;2\n\n"]


def test_posix_the_sniffer_reads_a_table_as_it_is(tmp_path, monkeypatch):
    """macOS and Linux: the text goes to the sniffer as it came, whatever its line ends are. Nothing is changed for them."""
    from boxed import platform
    from boxed.cli import _read_table

    monkeypatch.setattr(platform, "IS_WINDOWS", False)
    seen = sniffer_that_remembers(monkeypatch)
    (tmp_path / "t.csv").write_bytes(b"a;b\r\n1;2\r\n\r\n")
    _read_table(str(tmp_path / "t.csv"))
    assert seen == ["a;b\r\n1;2\r\n\r\n"]


def test_a_table_with_crlf_lines_and_a_blank_line_at_the_end_keeps_its_delimiter(windows, tmp_path):
    """What Excel writes on Windows. Python up to 3.13.14 could not tell the delimiter of such a text, and the comma it fell back to cut
    "1 234,50" in two: the error said a row had too many cells."""
    from boxed.cli import _read_table

    (tmp_path / "t.csv").write_bytes(b"client;Acme Corp margin\r\nRomashka;1 234,50\r\nLutik;99,5\r\n\r\n")
    header, rows, delimiter = _read_table(str(tmp_path / "t.csv"))
    assert (delimiter, header, rows) == (";", ["client", "Acme Corp margin"], [["Romashka", "1 234,50"], ["Lutik", "99,5"]])


@pytest.mark.parametrize("replace", [False, True])
def test_mask_file_leaves_no_clean_copy_when_the_map_cannot_be_saved(tmp_path, capsys, monkeypatch, replace):
    from boxed.vault import Vault

    folder = tmp_path / "files"
    folder.mkdir()
    monkeypatch.chdir(folder)
    src, dest = folder / "clients.csv", folder / "masked.csv"
    src.write_text("name,email\nIvan,ivan.petrov@acme.com\n")
    if replace:
        dest.write_text("an older copy\n")

    def fails(self, scope, markers):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Vault, "save_map", fails)
    argv = ["mask-file", "--scope", "f9", *(["--replace"] if replace else []), str(src), str(dest)]
    code, out, _ = run(capsys, argv)
    assert code == 2 and out == ""
    assert (dest.read_text() == "an older copy\n") if replace else not dest.exists()
    assert sorted(p.name for p in folder.iterdir()) == sorted(["clients.csv", *(["masked.csv"] if replace else [])])


@pytest.mark.parametrize("replace", [False, True])
def test_mask_file_journals_the_copy_it_made_before_it_lands_and_a_journal_that_fails_leaves_none(tmp_path, capsys, monkeypatch, boxed_env, replace):
    import hashlib

    from boxed.journal import Journal

    folder = tmp_path / "files"
    folder.mkdir()
    src, dest = folder / "clients.csv", folder / "masked.csv"
    src.write_text("name,email\nIvan,ivan.petrov@acme.com\n")
    seen = []
    real = Journal.append

    def spy(self, entry):
        seen.append((entry.status, dest.exists(), entry.payload_sha256))
        return real(self, entry)

    with monkeypatch.context() as spying:
        spying.setattr(Journal, "append", spy)
        assert run(capsys, ["mask-file", "--scope", "f9", str(src), str(dest)])[0] == 0
    assert seen == [("prepared", False, hashlib.sha256(dest.read_bytes()).hexdigest())]  # the hash of the copy that landed
    dest.unlink()
    if replace:
        dest.write_text("an older copy\n")
    (boxed_env / "journal.jsonl").unlink()
    (boxed_env / "journal.jsonl").mkdir()  # the journal cannot be written
    argv = ["mask-file", "--scope", "f10", *(["--replace"] if replace else []), str(src), str(dest)]
    code, out, err = run(capsys, argv)
    assert code == 2 and out == "" and "journal" in err
    assert (dest.read_text() == "an older copy\n") if replace else not dest.exists()
    assert sorted(p.name for p in folder.iterdir()) == sorted(["clients.csv", *(["masked.csv"] if replace else [])])
