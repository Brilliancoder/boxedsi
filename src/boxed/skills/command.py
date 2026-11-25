"""The whole `boxed skills` command line, written once: scan, list, quarantine, restore.

`scan` with no target checks what is installed, saves the record and journals one entry; with a target (a folder, a file, a .zip, an https
git address, owner/repo) it checks it before it is installed and touches neither the record nor the journal. `--ai` hands the files
that have findings to a model through the person's key (ai.py), which journals each request, a target's too. `quarantine` and `restore` call quarantine.py;
both modules are imported only inside the branch that needs them. Everything else works offline."""

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from boxed import cli
from boxed.cli import EXIT_ANOMALY, EXIT_FAIL, EXIT_OK
from boxed.errors import UserError
from boxed.journal import JournalEntry
from boxed.outputs import Target
from boxed.skills._shared import escaped

RECORD_FAILED = "boxed: warning: the check was not saved, so the next session will not know about it: run boxed skills scan again"
JOURNAL_FAILED = ("boxed: warning: the check was not saved: the journal could not take it (no keychain, or the journal cannot be "
                  "written), so the record was left as it was: run boxed skills scan again")


def register(sub) -> None:
    """Adds `boxed skills` with its four subcommands to the top-level parser."""
    from boxed.channels import PROVIDERS
    from boxed.policy import RECIPIENT_KINDS

    p = sub.add_parser("skills", help="check the skills, plugins, MCP servers and hooks of your AI agents for malicious behaviour")
    actions = p.add_subparsers(dest="action", required=True)

    ps = actions.add_parser("scan", help="check what is installed, or a folder, file, zip or git address before you install it")
    ps.add_argument("target", nargs="?", help="a folder, a file, a .zip, an https git address or owner/repo (GitHub) to check before installing; leave out to check what is installed")
    ps.add_argument("--html", help="also write a self-contained HTML report here")
    ps.add_argument("--json", help="also write a JSON report (boxed-skills-report/1) here")
    ps.add_argument("--replace", action="store_true", help="replace a report file that is already there and is not an earlier report")
    ps.add_argument("--ai", action="store_true", help="also let a model look at the files with findings (masked, through your API key); it can only add findings")
    ps.add_argument("--provider", choices=list(PROVIDERS), help="--ai: the provider whose key is used")
    ps.add_argument("--model", help="--ai: the model to ask")
    ps.add_argument("--account", choices=[kind for kind in RECIPIENT_KINDS if kind != "local"], help="--ai: the kind of account the key belongs to")
    ps.set_defaults(func=cmd_skills)

    pl = actions.add_parser("list", help="show what is installed with its last verdict, and what is in quarantine")
    pl.set_defaults(func=cmd_skills)

    pq = actions.add_parser("quarantine", help="take an installed item out of use so the agent no longer loads it; restore puts it back")
    pq.add_argument("id", help="the id or the name of an item, as boxed skills list shows it")
    pq.set_defaults(func=cmd_skills)

    pr = actions.add_parser("restore", help="put a quarantined item back exactly as it was")
    pr.add_argument("id", help="the quarantine id, the item id or the name of the item")
    pr.set_defaults(func=cmd_skills)


def cmd_skills(args: argparse.Namespace) -> int:
    return {"scan": _scan, "list": _list, "quarantine": _quarantine, "restore": _restore}[args.action](args)


def _roots():
    from boxed.skills.inventory import Roots

    return Roots(home=Path.home(), projects=(Path.cwd(),))


def _write(text: str) -> None:
    sys.stdout.write(cli._shown(text, sys.stdout))


# ---- scan ----


def _scan(args: argparse.Namespace) -> int:
    from boxed.skills import fetch, scan
    from boxed.skills.inventory import discover, discover_target
    from boxed.skills.record import RecordItem, load_record, update_record
    from boxed.skills.report import is_skills_report, render_html, render_json, render_terminal
    from boxed.skills.rules import RULES_VERSION

    if args.ai and not (args.provider and args.model):
        raise UserError("--ai needs --provider and --model")
    if not args.ai and (args.provider or args.model or args.account):
        raise UserError("--provider, --model and --account go with --ai: add --ai")
    if args.target == "":
        raise UserError("the target is empty: name a folder, a file, a .zip or an https git address, or leave it out to check what is installed")
    if args.ai:
        from boxed.skills import ai  # imported before the work so a missing module stops the command at once
    reports = []  # before any work, so a bad name fails first
    for label, name, render in (("html", args.html, render_html), ("json", args.json, render_json)):
        if name:
            reports.append((label, name, render, Target(name, kind="skills report", own=is_skills_report, replace=args.replace)))
    if len(reports) == 2 and reports[0][3].path == reports[1][3].path:
        raise UserError("--html and --json name the same file: give each its own")

    ctx = cli.Context() if args.ai else None  # the AI look needs the keys; the check alone only reads, keychain or none
    installed = args.target is None
    home = ctx.home if ctx else cli.boxed_home() if installed else None
    record = load_record(home) if installed else None
    failed = False
    cache: dict[str, list[dict]] = {}

    def review(found):
        """The AI look, when asked for. It reads the files from disk, so for a zip or a clone it runs while the temp folder still stands."""
        nonlocal failed, cache
        if not args.ai:
            return found
        outcome = ai.review(found, provider=args.provider, model=args.model, account=args.account, ctx=ctx,
                            cache=record.ai if record is not None else {}, transport=cli._send)
        failed, cache = outcome.failed, outcome.cache
        for line in outcome.lines:
            print(cli._shown(line, sys.stderr), file=sys.stderr)
        return scan.sort_results(outcome.results)

    if installed:
        inventory = discover(_roots())
        results = review(scan.scan_inventory(inventory, record))
        label = None
    else:
        with fetch.target_folder(args.target, work=Path(tempfile.gettempdir())) as fetched:
            folder, label = fetched
            inventory = scan.with_links(discover_target(folder, label), folder, fetched.links)
            results = review(scan.scan_inventory(inventory, None))

    _write(render_terminal(results, inventory.problems, target=label))
    for kind, name, render, out in reports:
        out.write(render(results, inventory.problems, target=label).encode("utf-8"))
        print(f"{kind}: {name}")
    saved = True
    if installed:  # after the output: whatever goes wrong here must not take the verdicts away
        when = datetime.now(UTC).isoformat()

        def remember(rec) -> None:
            rec.items = {
                r.item.id: RecordItem(r.digest, r.verdict, when, RULES_VERSION, tuple((f.rule, f.severity, f.file, f.line) for f in r.findings))
                for r in results
            }
            rec.ai.update(cache)

        try:  # the signed journal first: a record the journal does not back would quiet the next session for a check nobody can prove
            ctx = ctx or cli.Context()  # the journal is signed: without a keychain the check is not saved, the record neither
            _journal_scan(ctx, results, unread=sum(scan.incomplete([p]) for p in inventory.problems))
        except Exception:
            saved = False
            print(JOURNAL_FAILED, file=sys.stderr)
        else:
            try:
                update_record(home, remember)
            except Exception:
                saved = False
                print(RECORD_FAILED, file=sys.stderr)
    if any(r.verdict != "ok" for r in results) or scan.incomplete(inventory.problems):  # what could not be checked is never clean
        return EXIT_FAIL if failed else EXIT_ANOMALY
    return EXIT_FAIL if failed or not saved else EXIT_OK


def _journal_scan(ctx, results, *, unread: int = 0) -> None:
    """One entry: counts and a hash of the ids, never a name or a path. The coverage is `full` only when every item was read whole
    and the inventory left nothing out (`unread`: its problems that kept something from being checked); else `partial`, and the
    note says how many items were cut and how many places were not read."""
    from boxed.skills.rules import INCOMPLETE

    ids = "\n".join(sorted(r.item.id for r in results))
    dangerous = sum(r.verdict == "dangerous" for r in results)
    suspicious = sum(r.verdict == "suspicious" for r in results)
    cut = sum(any(f.rule == INCOMPLETE[0] for f in r.findings) for r in results)
    note = f"scan items={len(results)} dangerous={dangerous} suspicious={suspicious}"
    if cut or unread:
        note += f" incomplete={cut} unread={unread}"
    ctx.journal.append(
        JournalEntry(
            channel="skills", provider="local", account_type="local", level=-1, markers_by_kind={}, status="prepared",
            payload_sha256=hashlib.sha256(ids.encode("utf-8", "backslashreplace")).hexdigest(),
            coverage="partial" if cut or unread else "full", scope="skills", note=note,
        )
    )


# ---- list ----


def _list(args: argparse.Namespace) -> int:
    from boxed.paths import boxed_home_path
    from boxed.skills.inventory import discover, item_digest
    from boxed.skills.record import changes, load_record

    record = load_record(boxed_home_path())
    inventory = discover(_roots())
    digests = {item.id: item_digest(item) for item in inventory.items}
    new, changed = changes(record, digests)
    marks = {**{i: "  [new]" for i in new}, **{i: "  [changed]" for i in changed}}
    order = {"dangerous": 0, "suspicious": 1, "unchecked": 2, "ok": 3}
    rows = sorted(((record.items[i.id].verdict if i.id in record.items else "unchecked", i.id) for i in inventory.items), key=lambda r: (order[r[0]], r[1]))
    lines = [f"installed: {len(rows)}"]
    lines += [f"{verdict:<11}{escaped(item_id)}{marks.get(item_id, '')}" for verdict, item_id in rows]
    for p in inventory.problems:
        lines.append(f"could not read: {escaped(p.location)} ({escaped(p.reason)})")
    loose = _unrecorded(boxed_home_path(), record)
    lines.append(f"quarantined: {len(record.quarantined) + len(loose)}")
    for qid, q in sorted(record.quarantined.items()):
        lines.append(f"{escaped(qid)}  {escaped(q['item'])}  {escaped(q['method'])}  {escaped(q['at'])}")
    for qid, q in loose:
        lines.append(f"{qid}  {escaped(q.get('item', '?'))}  {escaped(q.get('method', '?'))}  {escaped(q.get('at', '?'))}"
                     f"  not in the record: boxed skills restore {qid} puts it back")
    _write("\n".join(lines) + "\n")
    return EXIT_OK


ENTRY_MAX = 64 * 1024 * 1024  # of an entry.json read for its item, method and time


def _unrecorded(home: Path, record) -> list[tuple[str, dict]]:
    """Quarantines the record lacks, because neither the record nor the undo could be written (a full disk): a folder
    `skills/quarantine/<qid>` that keeps its entry.json, which restore finds by the id. Of the entry only the item, the method and the
    time are taken, as text; the value it saved (env, headers, a hook's command) is never read out. Reads only, follows no link."""
    from boxed import platform
    from boxed.skills.quarantine import ENTRY_FILE, QUARANTINE
    from boxed.skills.record import FOLDER

    base = home / FOLDER / QUARANTINE
    try:
        with os.scandir(base) as listing:
            folders = sorted(e.name for e in listing if re.fullmatch(r"[0-9a-f]{8}", e.name) and e.is_dir(follow_symlinks=False))
    except OSError:
        return []
    out = []
    for qid in folders:
        if qid in record.quarantined:
            continue
        try:
            fd = platform.open_nofollow(base / qid / ENTRY_FILE, os.O_RDONLY)
        except OSError:
            continue  # no entry.json: nothing a restore could act on
        with os.fdopen(fd, "rb") as f:
            raw = f.read(ENTRY_MAX + 1) if stat.S_ISREG(os.fstat(f.fileno()).st_mode) else None
        if raw is None:
            continue
        try:
            saved = json.loads(raw.decode("utf-8")) if len(raw) <= ENTRY_MAX else None
        except (ValueError, RecursionError):
            saved = None
        entry = saved.get("entry") if isinstance(saved, dict) and saved.get("qid") == qid else None
        shown = {k: v for k, v in entry.items() if k in ("item", "method", "at") and isinstance(v, str)} if isinstance(entry, dict) else {}
        out.append((qid, shown))
    return out


# ---- quarantine and restore ----


def _quarantine(args: argparse.Namespace) -> int:
    from boxed.skills.inventory import discover, find_items

    matches = find_items(discover(_roots()), args.id)
    if not matches:
        raise UserError("no installed item matches: run boxed skills list to see the ids")
    if len(matches) > 1:
        raise UserError("several items match: give the full id that boxed skills list shows")
    from boxed.skills.quarantine import quarantine_item

    ctx = cli.Context()
    _write("".join(line + "\n" for line in quarantine_item(matches[0], home=ctx.home, journal=ctx.journal)))
    return EXIT_OK


def _restore(args: argparse.Namespace) -> int:
    from boxed.skills.quarantine import restore_item

    ctx = cli.Context()
    _write("".join(line + "\n" for line in restore_item(args.id, home=ctx.home, journal=ctx.journal)))
    return EXIT_OK
