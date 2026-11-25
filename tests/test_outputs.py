"""Every file a command writes at a name the person gave goes through one safe writer (src/boxed/outputs.py).
No test touches the real ~/.boxed or the keychain: conftest.py points BOXED_HOME at a temp folder and the keys at files."""

import importlib
import io
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from boxed.cli import main
from support import mode_is


def run(capsys, argv, stdin=None, monkeypatch=None):
    if stdin is not None:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    code = main(argv)
    out, err = capsys.readouterr()
    return code, out, err


@pytest.fixture
def home(boxed_env, capsys, monkeypatch):
    """A boxed home with a journal, a vault and a key: what a person who has used boxed has."""
    monkeypatch.setattr("sys.stdin", io.StringIO("mail ivan@acme.com"))
    assert main(["mask", "--scope", "d1", "-"]) == 0
    capsys.readouterr()
    return boxed_env


# ---- the reports: where in the boxed home they may go ----


def dashboard_html(out):
    return ["dashboard", "--html", str(out)]


def dashboard_csv(out):
    return ["dashboard", "--csv", str(out)]


def audit_html(out):
    return ["audit", "--claude-dir", "/no/such/claude", "--codex-dir", "/no/such/codex", "--html", str(out)]


REPORTS = [dashboard_html, dashboard_csv, audit_html]


@pytest.mark.parametrize("report", REPORTS)
def test_a_report_is_not_written_as_the_reports_folder_itself(report, home, capsys):
    code, _, err = run(capsys, report(home / "reports"))
    assert code == 2 and "boxed home" in err
    assert not (home / "reports").exists()  # not even as a file, which would keep the folder from ever being made


@pytest.mark.parametrize("report", REPORTS)
def test_a_differently_spelled_boxed_home_is_still_the_boxed_home(report, home, capsys):
    """On a file system that ignores case ~/.BOXED is ~/.boxed: a new checks.json full of HTML was written there."""
    alias = home.parent / home.name.upper()
    if not alias.exists():
        pytest.skip("this file system tells upper and lower case apart")
    for name in ("checks.json", "observed.jsonl", "new.html"):
        code, _, err = run(capsys, report(alias / name))
        assert code == 2 and "boxed home" in err, name
        assert not (home / name).exists()
    assert run(capsys, report(alias / "reports" / "r.out"))[0] == 0  # under reports/ it is allowed, whichever way it is spelled
    assert (home / "reports" / "r.out").exists()


def test_inside_goes_by_what_the_folders_are_not_by_their_spelling(tmp_path):
    from boxed.outputs import inside

    real = tmp_path / "real"
    (real / "a").mkdir(parents=True)
    link = tmp_path / "link"
    link.symlink_to(real)
    assert inside(real / "a" / "b.txt", link) == Path("a/b.txt")  # a link to the folder is the folder
    assert inside(real, real) == Path(".")
    assert inside(real / "not" / "yet" / "x", real) == Path("not/yet/x")  # below it, in folders that are not there yet
    assert inside(tmp_path / "other" / "x", real) is None
    gone = tmp_path / "gone"  # a folder that is not there has its spelling and nothing else
    assert inside(gone / "x", gone) == Path("x") and inside(tmp_path / "x", gone) is None


# ---- the place is looked at again just before the file lands ----

BUILT_BY = {dashboard_html: "boxed.dashboard.render_html", dashboard_csv: "boxed.dashboard.to_csv", audit_html: "boxed.audit.report.run_audit"}


@pytest.mark.parametrize("report", REPORTS)
def test_a_file_that_appears_while_a_report_is_made_is_not_replaced(report, home, tmp_path, capsys, monkeypatch):
    """The audit reads gigabytes of transcripts first: what stands at the name by the end is what counts."""
    target = tmp_path / "report.out"
    module_name, function = BUILT_BY[report].rsplit(".", 1)
    module = importlib.import_module(module_name)
    real = getattr(module, function)

    def meanwhile(*args, **kwargs):
        target.write_bytes(b"my notes, not a report\n")
        return real(*args, **kwargs)

    monkeypatch.setattr(module, function, meanwhile)
    code, _, err = run(capsys, report(target))
    assert code == 2 and "the output file exists and boxed did not write it" in err
    assert target.read_bytes() == b"my notes, not a report\n"


# ---- a link at the name is refused, whatever it points to ----


@pytest.mark.parametrize("report", REPORTS)
def test_a_report_is_not_written_through_a_link(report, home, tmp_path, capsys):
    victim = tmp_path / "victim.out"
    assert run(capsys, report(victim))[0] == 0  # an earlier report of the right kind: only the link is wrong with it
    before = victim.read_bytes()
    link = tmp_path / "latest.out"
    link.symlink_to(victim)
    code, _, err = run(capsys, report(link))
    assert code == 2 and "the output path is a link" in err and "latest.out" not in err
    assert link.is_symlink() and victim.read_bytes() == before


@pytest.mark.parametrize("report", REPORTS)
def test_a_report_is_not_created_through_a_dangling_link(report, home, tmp_path, capsys):
    link = tmp_path / "latest.out"
    link.symlink_to(tmp_path / "new.out")
    code, _, err = run(capsys, report(link))
    assert code == 2 and "the output path is a link" in err
    assert not (tmp_path / "new.out").exists()


# ---- every other file a command writes at a name it was given ----

SALES = "client;region;revenue;day\nRomashka;EU;1 234,50;21.10.2026\nLutik;US;99,5;22.10.2026\nRomashka;EU;10,00;23.10.2026\n"
PLAN = (
    '{"version": 1, "steps": [{"op": "group", "by": ["client"], "aggregates": {"total": ["sum", "revenue"]}}, '
    '{"op": "chart", "kind": "bar", "x": "client", "y": "total"}]}'
)
CLIENTS = "name,email\nIvan,ivan@acme.com\n"
NOTES = b"my notes, not boxed output\n"


@dataclass(frozen=True)
class Writer:
    name: str
    ext: str  # an extension that suits what it writes
    argv: Callable  # (world, out, *flags) -> the command line that writes `out`
    work: tuple[str, str]  # the module and function that do its work, to put something in the way while it works
    own: bool = False  # a file of its own kind can be told from its first bytes, so a new run replaces it without --replace


def export_argv(world, out, *flags):
    return ["journal", "export", "--out", str(out), *flags]


def result_argv(world, out, *flags):
    return ["plan", "run", "--scope", "p1", *flags, "--out", str(out), str(world.plan), str(world.table)]


def chart_argv(world, out, *flags):
    return ["plan", "run", "--scope", "p1", *flags, "--chart", str(out), str(world.plan), str(world.table)]


def mask_argv(world, out, *flags):
    return ["mask-file", "--scope", "f2", *flags, str(world.src), str(out)]


def restore_argv(world, out, *flags):
    return ["restore-file", "--scope", "f1", *flags, str(world.masked), str(out)]


def skills_html_argv(world, out, *flags):
    return ["skills", "scan", str(world.table), "--html", str(out), *flags]


def skills_json_argv(world, out, *flags):
    return ["skills", "scan", str(world.table), "--json", str(out), *flags]


EXPORT = Writer("journal export", ".json", export_argv, ("boxed.dashboard", "export_for_security"), own=True)
RESULT = Writer("plan result", ".csv", result_argv, ("boxed.opplan", "run_plan"))
CHART = Writer("plan chart", ".json", chart_argv, ("boxed.opplan", "run_plan"), own=True)
MASKED = Writer("mask-file", ".csv", mask_argv, ("boxed.formats", "mask_file"))
RESTORED = Writer("restore-file", ".csv", restore_argv, ("boxed.formats", "restore_file"))
SKILLS_HTML = Writer("skills html", ".html", skills_html_argv, ("boxed.skills.scan", "scan_inventory"), own=True)
SKILLS_JSON = Writer("skills json", ".json", skills_json_argv, ("boxed.skills.scan", "scan_inventory"), own=True)
OUTPUTS = [EXPORT, RESULT, CHART, MASKED, RESTORED, SKILLS_HTML, SKILLS_JSON]


@pytest.fixture
def world(tmp_path, home, capsys, monkeypatch):
    """A table with a plan and its scope (p1), a file to mask, and a masked file with its scope (f1)."""
    monkeypatch.chdir(tmp_path)
    table, plan, src, masked = (tmp_path / name for name in ("sales.csv", "plan.json", "clients.csv", "masked.csv"))
    table.write_text(SALES)
    plan.write_text(PLAN)
    src.write_text(CLIENTS)
    assert main(["plan", "prompt", "--task", "top clients", "--scope", "p1", str(table)]) == 0
    assert main(["mask-file", "--scope", "f1", str(src), str(masked)]) == 0
    capsys.readouterr()
    return SimpleNamespace(table=table, plan=plan, src=src, masked=masked)


def snapshot(folder: Path) -> dict[str, bytes]:
    return {str(path.relative_to(folder)): path.read_bytes() for path in sorted(folder.rglob("*")) if path.is_file()}


def hidden(folder: Path) -> list[str]:
    return sorted(path.name for path in folder.iterdir() if path.name.startswith("."))


def writers(func):
    return pytest.mark.parametrize("writer", OUTPUTS, ids=lambda writer: writer.name)(func)


@writers
def test_nothing_is_written_in_the_boxed_home(writer, world, home, capsys):
    before = snapshot(home)
    for name in ("vault.db", "journal.jsonl", "insecure-keys/device-signing-key.key", "new" + writer.ext, "reports/new" + writer.ext):
        code, _, err = run(capsys, writer.argv(world, home / name))
        assert code == 2 and "boxed home" in err, name
    assert snapshot(home) == before  # not one byte of it, and no new file


@writers
def test_a_link_is_refused_whatever_it_points_to(writer, world, home, tmp_path, capsys):
    victim, link = tmp_path / "victim.txt", tmp_path / ("link" + writer.ext)
    victim.write_bytes(b"precious\n")
    victim.chmod(0o644)
    link.symlink_to(victim)
    code, _, err = run(capsys, writer.argv(world, link))
    assert code == 2 and "the output path is a link" in err
    assert victim.read_bytes() == b"precious\n" and mode_is(victim, 0o644) and link.is_symlink()
    link.unlink()
    link.symlink_to(tmp_path / ("new" + writer.ext))  # a link to nothing
    code, _, err = run(capsys, writer.argv(world, link))
    assert code == 2 and "the output path is a link" in err and not (tmp_path / ("new" + writer.ext)).exists()
    link.unlink()
    link.symlink_to(home / "journal.jsonl")  # a link to what boxed keeps is that, whatever else it is
    before = snapshot(home)
    code, _, err = run(capsys, writer.argv(world, link))
    assert code == 2 and "boxed home" in err and snapshot(home) == before


@writers
def test_a_folder_or_a_pipe_is_not_a_plain_file(writer, world, tmp_path, capsys):
    folder = tmp_path / ("folder" + writer.ext)
    folder.mkdir()
    code, _, err = run(capsys, writer.argv(world, folder))
    assert code == 2 and "plain file" in err and list(folder.iterdir()) == []
    if not hasattr(os, "mkfifo"):  # Windows has no pipe in the file system
        return
    pipe = tmp_path / ("pipe" + writer.ext)
    os.mkfifo(pipe)
    reader = os.open(pipe, os.O_RDONLY | os.O_NONBLOCK)  # with a reader there, a write would not block: the test can fail instead of hanging
    try:
        code, _, err = run(capsys, writer.argv(world, pipe))
        assert code == 2 and "plain file" in err
        assert os.read(reader, 100) == b""  # nothing went into it
    finally:
        os.close(reader)


@writers
def test_the_folder_of_the_file_must_be_there(writer, world, home, tmp_path, capsys):
    journal = (home / "journal.jsonl").read_bytes()
    code, _, err = run(capsys, writer.argv(world, tmp_path / "missing" / ("out" + writer.ext)))
    assert code == 2 and "the folder of the output file does not exist" in err and not (tmp_path / "missing").exists()
    assert (home / "journal.jsonl").read_bytes() == journal  # refused before anything was recorded


@writers
def test_a_file_boxed_cannot_tell_is_its_own_is_replaced_only_with_replace(writer, world, tmp_path, capsys):
    out = tmp_path / ("out" + writer.ext)
    out.write_bytes(NOTES)
    code, _, err = run(capsys, writer.argv(world, out))
    assert code == 2 and "the output file exists" in err and "--replace" in err and "--force" not in err and out.name not in err
    assert ("boxed did not write it" in err) == writer.own  # a kind boxed can recognise says so
    assert out.read_bytes() == NOTES
    code, _, err = run(capsys, writer.argv(world, out, "--replace"))
    assert code == 0 and out.read_bytes() != NOTES


@pytest.mark.parametrize("writer", [w for w in OUTPUTS if w.own], ids=lambda writer: writer.name)
def test_an_earlier_file_of_its_own_kind_is_replaced_without_replace(writer, world, tmp_path, capsys):
    out = tmp_path / ("out" + writer.ext)
    assert run(capsys, writer.argv(world, out))[0] == 0
    assert run(capsys, writer.argv(world, out))[0] == 0


@writers
def test_a_file_is_private_replaced_whole_and_leaves_nothing_behind(writer, world, tmp_path, capsys):
    out, alias = tmp_path / ("out" + writer.ext), tmp_path / ("old" + writer.ext)
    flags = () if writer.own else ("--replace",)
    assert run(capsys, writer.argv(world, out))[0] == 0
    assert mode_is(out, 0o600)
    os.link(out, alias)  # a hard link keeps the old file: the old file was replaced, not written into
    before = hidden(tmp_path)
    assert run(capsys, writer.argv(world, out, *flags))[0] == 0
    assert out.stat().st_ino != alias.stat().st_ino and alias.stat().st_nlink == 1
    assert mode_is(out, 0o600)
    assert hidden(tmp_path) == before  # no part file, no folder for one


@writers
def test_links_planted_where_part_files_used_to_go_are_not_followed(writer, world, tmp_path, capsys):
    out, victim = tmp_path / ("out" + writer.ext), tmp_path / "victim.txt"
    victim.write_bytes(b"precious\n")
    for name in (f"out{writer.ext}.part", f".out.boxed-part{writer.ext}", f".out{writer.ext}.boxed-part", f".out.boxed-part{writer.ext}.part"):
        (tmp_path / name).symlink_to(victim)
    assert run(capsys, writer.argv(world, out))[0] == 0 and out.stat().st_size > 0
    assert victim.read_bytes() == b"precious\n"


@writers
def test_a_file_that_appears_while_the_work_goes_on_is_not_replaced(writer, world, tmp_path, capsys, monkeypatch):
    out = tmp_path / ("out" + writer.ext)
    module = importlib.import_module(writer.work[0])
    real = getattr(module, writer.work[1])

    def meanwhile(*args, **kwargs):
        out.write_bytes(NOTES)
        return real(*args, **kwargs)

    monkeypatch.setattr(module, writer.work[1], meanwhile)
    code, _, err = run(capsys, writer.argv(world, out))
    assert code == 2 and "the output file exists" in err and out.read_bytes() == NOTES


@pytest.mark.parametrize("function", ["mask_file", "restore_file"])
def test_the_formats_do_not_write_through_a_link_at_the_old_part_name(function, tmp_path):
    """The library on its own, whatever command calls it: dest.part was made by name, so a link there took the output."""
    from boxed import formats
    from boxed.mask import MarkerMap

    src, dest, victim = tmp_path / "in.csv", tmp_path / "out.csv", tmp_path / "victim.txt"
    src.write_text(CLIENTS)
    victim.write_bytes(b"precious\n")
    (tmp_path / "out.csv.part").symlink_to(victim)
    getattr(formats, function)(src, dest, MarkerMap())
    assert victim.read_bytes() == b"precious\n"
    assert dest.read_text() == CLIENTS or "[EMAIL_1]" in dest.read_text()
    assert mode_is(dest, 0o600) and hidden(tmp_path) == []


def test_mask_file_never_replaces_its_source_even_with_replace(world, capsys):
    before = world.src.read_bytes()
    for flags in ((), ("--replace",)):
        code, out, err = run(capsys, mask_argv(world, world.src, *flags))
        assert code == 2 and out == "" and "source file" in err
        assert world.src.read_bytes() == before


def test_restore_file_never_replaces_its_input_whatever_the_flags(world, capsys):
    before = world.masked.read_bytes()
    for flags in ((), ("--force",), ("--replace",), ("--force", "--replace")):
        code, out, err = run(capsys, restore_argv(world, world.masked, *flags))
        assert code == 2 and out == "" and "the output is the input file" in err
        assert world.masked.read_bytes() == before


def test_force_does_not_replace_a_file(world, tmp_path, capsys):
    """--force is for the placeholders of the answer only."""
    out = tmp_path / "out.csv"
    out.write_bytes(NOTES)
    code, _, err = run(capsys, restore_argv(world, out, "--force"))
    assert code == 2 and "the output file exists" in err and "--replace" in err and "--force" not in err
    assert out.read_bytes() == NOTES


def test_replace_does_not_lift_the_check_of_the_placeholders(world, tmp_path, capsys):
    answer, out = tmp_path / "answer.csv", tmp_path / "out.csv"
    answer.write_text("email\n[EMAIL_9]\n")
    out.write_bytes(NOTES)
    code, _, err = run(capsys, ["restore-file", "--scope", "f1", "--replace", str(answer), str(out)])
    assert code == 3 and "[EMAIL_9]" in err and out.read_bytes() == NOTES and hidden(tmp_path) == []
    code, _, _ = run(capsys, ["restore-file", "--scope", "f1", "--replace", "--force", str(answer), str(out)])
    assert code == 0 and out.read_text() == "email\n[EMAIL_9]\n"  # each flag for its own question


@pytest.mark.parametrize("argv", [["mask-file"], ["restore-file"], ["plan", "run"], ["journal"], ["skills", "scan"]], ids=lambda argv: " ".join(argv))
def test_every_command_that_writes_a_file_has_replace_and_only_restore_file_has_force(argv, capsys):
    with pytest.raises(SystemExit):
        main([*argv, "--help"])
    text = capsys.readouterr().out
    assert "--replace" in text and ("--force" in text) == (argv == ["restore-file"])


def test_a_restore_that_is_refused_for_its_markers_leaves_nothing_behind(world, tmp_path, capsys):
    answer, out = tmp_path / "answer.csv", tmp_path / "out.csv"
    answer.write_text("email\n[EMAIL_9]\n")
    code, _, err = run(capsys, ["restore-file", "--scope", "f1", str(answer), str(out)])
    assert code == 3 and "[EMAIL_9]" in err and not out.exists() and hidden(tmp_path) == []


def test_the_chart_waits_for_the_journal_like_the_table(world, home, tmp_path, capsys):
    journal = home / "journal.jsonl"
    journal.unlink()
    journal.mkdir()  # the journal cannot be written
    chart = tmp_path / "chart.json"
    code, _, _ = run(capsys, chart_argv(world, chart))
    assert code == 2 and not chart.exists() and hidden(tmp_path) == []


# ---- Windows: the same writer where os has no O_NOFOLLOW, and a reparse point is not a file of boxed ----


def test_windows_a_report_is_written_and_replaced_where_os_has_no_o_nofollow(home, windows_os, tmp_path, capsys):
    out = tmp_path / "report.html"
    code, _, err = run(capsys, dashboard_html(out))
    assert code == 0 and out.stat().st_size > 0, err
    code, _, err = run(capsys, dashboard_html(out))  # the earlier report is recognised by its first bytes, read without following a link
    assert code == 0, err


def test_windows_a_reparse_point_at_the_name_is_not_a_report_of_boxed_to_replace(home, fake_msvcrt, see_as, tmp_path, capsys):
    target = tmp_path / "report.html"
    assert run(capsys, dashboard_html(target))[0] == 0
    before = target.read_bytes()
    see_as(target, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)  # a plain file by its mode: a placeholder of a cloud folder, say
    code, _, err = run(capsys, dashboard_html(target))
    assert code == 2 and "the output file exists and boxed did not write it" in err
    assert target.read_bytes() == before
