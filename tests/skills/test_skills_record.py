"""The record of what boxed skills checked: one strict, private, unsigned file in the boxed home. Names here are invented."""

import json
import os
import stat

import pytest

from boxed.skills.record import Record, RecordError, RecordItem, changes, load_record, save_record

DIGEST = "a" * 64
OTHER = "b" * 64
WHEN = "2026-11-03T10:00:00+00:00"


def item(digest=DIGEST, verdict="ok", findings=()):
    return RecordItem(digest, verdict, WHEN, "1", findings)


def path_of(home):
    return home / "skills" / "record.json"


def test_a_missing_record_is_an_empty_one(boxed_env):
    assert load_record(boxed_env) == Record(items={}, quarantined={}, ai={})
    assert not (boxed_env / "skills").exists()  # looking makes nothing


def test_a_saved_record_loads_back_equal_and_is_private(boxed_env):
    boxed_env.mkdir()
    record = Record(
        items={"claude:skill:user:demo": item(verdict="suspicious", findings=(("pipe-to-shell", "high", "SKILL.md", 3),))},
        quarantined={"q1": {"item": "claude:skill:user:old", "agent": "claude", "kind": "skill", "name": "old", "method": "move",
                            "original": "~/.claude/skills/old", "at": WHEN, "data": {"n": 1, "ok": True, "l": ["a"]}}},
        ai={f"{DIGEST}:openai:m1": [{"rule": "ai-review", "severity": "high", "file": "SKILL.md", "line": 2}]},
    )
    save_record(boxed_env, record)
    assert load_record(boxed_env) == record
    assert stat.S_IMODE(path_of(boxed_env).stat().st_mode) == 0o600
    assert stat.S_IMODE((boxed_env / "skills").stat().st_mode) == 0o700


def test_the_file_holds_the_version_and_no_evidence_or_values(boxed_env):
    boxed_env.mkdir()
    save_record(boxed_env, Record(items={"x": item(findings=(("rule-a", "low", "f.md", 1),))}))
    data = json.loads(path_of(boxed_env).read_text())
    assert data["version"] == 1 and set(data) == {"version", "items", "quarantined", "ai"}
    assert data["items"]["x"] == {"digest": DIGEST, "verdict": "ok", "checked_at": WHEN, "rules_version": "1", "findings": [["rule-a", "low", "f.md", 1]]}


def test_an_older_ai_cache_with_evidence_is_read_and_saved_without_any_text(boxed_env):
    row = {"rule": "ai-review", "severity": "high", "title": "t", "why": "the reason a model gave", "advice": "a", "file": "SKILL.md",
           "line": 2, "evidence": "a passage of the file", "source": "ai"}
    write_raw(boxed_env, doc(ai={f"{DIGEST}:openai:m1": [row]}))
    save_record(boxed_env, load_record(boxed_env))
    text = path_of(boxed_env).read_text()
    assert json.loads(text)["ai"] == {f"{DIGEST}:openai:m1": [{"rule": "ai-review", "severity": "high", "file": "SKILL.md", "line": 2}]}
    assert "passage" not in text and "reason" not in text


def write_raw(home, text):
    path_of(home).parent.mkdir(parents=True, exist_ok=True)
    path_of(home).write_text(text)
    path_of(home).chmod(0o600)


def doc(item_fields=None, **over):
    base = {"digest": DIGEST, "verdict": "ok", "checked_at": WHEN, "rules_version": "1", "findings": []}
    base.update(item_fields or {})
    data = {"version": 1, "items": {"a": base}, "quarantined": {}, "ai": {}}
    data.update(over)
    return json.dumps(data)


BAD = [
    "not json",
    "[]",
    doc(version=2),
    json.dumps({"version": 1, "items": {}, "quarantined": {}}),  # a key missing
    doc(extra=1),
    doc({"digest": "short"}),
    doc({"verdict": "fine"}),
    doc({"checked_at": "yesterday"}),
    doc({"findings": [["r", "huge", "f", 1]]}),
    doc({"evidence": "key"}),
    doc(quarantined={"q": {"item": "i"}}),
    doc(ai={"k": "not a list"}),
    '{"version": 1, "items": {"a": null, "a": null}, "quarantined": {}, "ai": {}}',  # a key twice
]


@pytest.mark.parametrize("text", BAD)
def test_a_damaged_record_is_an_error_with_a_remedy_that_quotes_nothing(boxed_env, text):
    boxed_env.mkdir()
    write_raw(boxed_env, text)
    with pytest.raises(RecordError) as caught:
        load_record(boxed_env)
    message = str(caught.value)
    assert message.startswith("record.json is damaged: ") and "boxed skills scan" in message
    assert "short" not in message and "huge" not in message and "yesterday" not in message


def test_a_record_that_others_could_change_or_a_link_is_not_believed(boxed_env, tmp_path):
    boxed_env.mkdir()
    save_record(boxed_env, Record())
    path_of(boxed_env).chmod(0o666)
    with pytest.raises(RecordError):
        load_record(boxed_env)
    path_of(boxed_env).chmod(0o600)
    real = tmp_path / "elsewhere.json"
    real.write_bytes(path_of(boxed_env).read_bytes())
    path_of(boxed_env).unlink()
    os.symlink(real, path_of(boxed_env))
    with pytest.raises(RecordError):
        load_record(boxed_env)


def test_a_record_over_the_size_cap_is_damaged(boxed_env, monkeypatch):
    boxed_env.mkdir()
    save_record(boxed_env, Record(items={"x": item()}))
    monkeypatch.setattr("boxed.skills.record.MAX_BYTES", 50)
    with pytest.raises(RecordError):
        load_record(boxed_env)


def test_changes_lists_new_and_changed_ids_and_leaves_the_same_alone():
    record = Record(items={"a": item(), "b": item(OTHER), "gone": item()})
    assert changes(record, {"a": DIGEST, "b": DIGEST, "c": DIGEST}) == (["c"], ["b"])


def test_a_save_replaces_the_file_whole_and_leaves_no_part_file(boxed_env):
    boxed_env.mkdir()
    save_record(boxed_env, Record(items={"x": item()}))
    before = path_of(boxed_env).stat().st_ino
    save_record(boxed_env, Record(items={"y": item(OTHER)}))
    assert path_of(boxed_env).stat().st_ino != before
    assert list(load_record(boxed_env).items) == ["y"]
    assert not any(p.name.endswith(".part") for p in (boxed_env / "skills").iterdir())


def test_a_name_of_any_length_is_saved_under_its_hash_and_found_by_its_id(boxed_env):
    boxed_env.mkdir()
    name = "claude:mcp:user:" + "x\udc80" * 600_000  # over a million characters, with a byte that is not UTF-8
    save_record(boxed_env, Record(items={name: item(findings=(("r", "low", "f" * 6000, 1),)), "short": item(OTHER)}))
    assert path_of(boxed_env).stat().st_size < 10_000  # the name itself is not in the file
    loaded = load_record(boxed_env)
    assert name in loaded.items and loaded.items[name].digest == DIGEST and loaded.items.get(name) is not None
    assert len(loaded.items[name].findings[0][2]) == 512 and loaded.items["short"].digest == OTHER
    assert changes(loaded, {name: DIGEST, "short": OTHER}) == ([], [])
    assert changes(loaded, {name: OTHER}) == ([], [name])
    loaded.items = {name: item(OTHER)}  # a plain dict assigned later keeps the same lookups
    assert name in loaded.items


def test_a_record_over_the_size_cap_keeps_verdicts_and_drops_findings(boxed_env, monkeypatch):
    boxed_env.mkdir()
    findings = tuple(("rule", "low", "f.md", n) for n in range(50))
    record = Record(items={f"id{n}": item(findings=findings) for n in range(20)})
    full = len(json.dumps({"x": [list(f) for f in findings] * 20}))
    monkeypatch.setattr("boxed.skills.record.MAX_BYTES", full)
    save_record(boxed_env, record)
    loaded = load_record(boxed_env)
    assert sorted(loaded.items) == sorted(record.items) and all(i.findings == () and i.verdict == "ok" for i in loaded.items.values())
