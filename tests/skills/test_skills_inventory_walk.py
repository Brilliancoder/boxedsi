"""Stable ids, which projects are looked at, links that are never followed, and garbage that must not stop the walk."""

import os
import sys
import time

import pytest

from boxed.skills import inventory
from boxed.skills.inventory import Problem
from test_skills_inventory import by_id, find, home, hook_doc, jput, put, skill, tag  # noqa: F401  (home is a fixture)


def test_two_passes_give_the_same_ids(home, tmp_path):
    project = tmp_path / "site"
    skill(home / ".claude/skills/a")
    jput(project / ".mcp.json", {"mcpServers": {"m": {"command": "x"}}})
    jput(home / ".claude/settings.json", hook_doc("echo a"))
    first, second = find(home, projects=[project]), find(home, projects=[project])
    assert [i.id for i in first.items] == [i.id for i in second.items]
    assert [i.id for i in first.items] == sorted(i.id for i in first.items)
    assert len({i.id for i in first.items}) == len(first.items) >= 3


def test_reordering_hooks_does_not_rename_them(home):
    one = {"type": "command", "command": "echo one"}
    two = {"type": "command", "command": "echo two"}
    path = home / ".claude/settings.json"
    jput(path, {"hooks": {"Stop": [{"hooks": [one]}, {"hooks": [two]}]}})
    before = {i.id for i in find(home).items}
    jput(path, {"hooks": {"Stop": [{"hooks": [two]}, {"hooks": [one]}]}})
    assert {i.id for i in find(home).items} == before and len(before) == 2


def test_two_projects_with_the_same_folder_name_get_different_ids(home, tmp_path):
    first, second = tmp_path / "a" / "site", tmp_path / "b" / "site"
    for project in (first, second):
        skill(project / ".claude/skills/page")
    ids = {i.id for i in find(home, projects=[first, second]).items}
    assert ids == {f"claude:skill:project={tag(first)}:page", f"claude:skill:project={tag(second)}:page"}


def test_projects_come_from_the_claude_and_codex_registries(home, tmp_path):
    claude_project, codex_project, unknown = tmp_path / "p1", tmp_path / "p2", tmp_path / "p3"
    for project in (claude_project, codex_project, unknown):
        skill(project / ".claude/skills/page")
    jput(home / ".claude.json", {"projects": {str(claude_project): {}}})
    put(home / ".codex/config.toml", f'[projects."{codex_project}"]\ntrust_level = "trusted"\n')
    ids = {i.id for i in find(home, registered=True).items}
    assert ids == {f"claude:skill:project={tag(claude_project)}:page", f"claude:skill:project={tag(codex_project)}:page"}
    assert find(home, registered=False).items == ()
    assert {i.id for i in find(home, projects=[unknown], registered=False).items} == {f"claude:skill:project={tag(unknown)}:page"}


def test_a_copy_under_claude_worktrees_is_not_counted_twice(home, tmp_path):
    project = tmp_path / "site"
    copy = project / ".claude" / "worktrees" / "feature"
    skill(project / ".claude/skills/page")
    skill(copy / ".claude/skills/page")
    jput(home / ".claude.json", {"projects": {str(project): {}, str(copy): {}}})
    assert [i.id for i in find(home, registered=True).items] == [f"claude:skill:project={tag(project)}:page"]


def test_a_project_folder_that_is_gone_is_skipped_without_a_word(home, tmp_path):
    skill(home / ".claude/skills/here")  # the walk goes on past the missing projects
    jput(home / ".claude.json", {"projects": {str(tmp_path / "gone"): {"mcpServers": {"m": {"command": "x"}}}}})
    inventory_ = find(home, projects=[tmp_path / "also-gone"], registered=True)
    assert [i.id for i in inventory_.items] == ["claude:skill:user:here"] and inventory_.problems == ()


def test_a_skill_folder_that_links_to_another_skills_root_counts_once(home):
    real = skill(home / ".agents/skills/shared")
    (home / ".claude/skills").mkdir(parents=True)
    (home / ".claude/skills/shared").symlink_to(real)
    found = [i for i in find(home).items if i.kind == "skill"]
    assert [i.id for i in found] == ["agents:skill:user:shared"]  # the real folder owns it, not the link to it
    assert found[0].files == (real / "SKILL.md",)


def test_a_link_inside_an_item_is_recorded_and_never_followed(home, tmp_path):
    outside = put(tmp_path / "elsewhere/secret.txt", "do not read\n")
    folder = skill(home / ".claude/skills/linky")
    (folder / "ref").symlink_to(outside)
    (folder / "dir").symlink_to(outside.parent)
    item = by_id(find(home))["claude:skill:user:linky"]
    assert item.files == (folder / "SKILL.md",)
    assert item.links == (("dir", str(outside.parent)), ("ref", str(outside)))


def test_broken_json_toml_and_frontmatter_are_problems_and_the_walk_goes_on(home):
    skill(home / ".claude/skills/fine")
    put(home / ".claude/settings.json", "{not json")
    put(home / ".codex/config.toml", "this = = broken")
    put(home / ".claude/skills/torn/SKILL.md", "---\nname: torn\nno closing line\n")
    reasons = {(p.location, p.reason) for p in find(home).problems}
    assert ("~/.claude/settings.json", "not valid JSON") in reasons
    assert ("~/.codex/config.toml", "not valid TOML") in reasons
    assert ("~/.claude/skills/torn/SKILL.md", "not valid frontmatter") in reasons
    assert "claude:skill:user:fine" in by_id(find(home))


@pytest.mark.parametrize("key", ["!!str hooks", "&anchor hooks"])
def test_a_hooks_key_this_reader_does_not_model_is_a_problem(home, key):
    # a YAML reader takes a tagged or anchored key for `hooks`; this one does not, so it is said, never passed
    hook = "  PreToolUse:\n    - matcher: Bash\n      command: echo hi\n"
    put(home / ".claude/skills/odd/SKILL.md", f"---\nname: odd\ndescription: x\n{key}:\n{hook}---\nbody\n")
    assert Problem("~/.claude/skills/odd/SKILL.md", "not valid frontmatter") in find(home).problems


def test_a_hooks_key_reached_through_an_alias_is_a_problem(home):
    # `*h :` is the key `hooks` to a YAML reader that knows aliases; this one does not, so it is said, never passed
    put(home / ".claude/skills/odd/SKILL.md", "---\nname: odd\ndescription: &h hooks\n*h :\n  Stop:\n    - command: echo hi\n---\nbody\n")
    assert Problem("~/.claude/skills/odd/SKILL.md", "not valid frontmatter") in find(home).problems


def test_a_deep_value_beside_the_word_hooks_does_not_stop_the_walk(home):
    deep = "[" * 500 + "]" * 500
    put(home / ".claude/skills/deep/SKILL.md", f"---\nname: deep\ndescription: React hooks\nmeta: {deep}\n---\nbody\n")
    skill(home / ".claude/skills/fine")
    assert "claude:skill:user:fine" in by_id(find(home))


def test_a_broken_claude_json_does_not_hide_the_other_agents(home):
    put(home / ".claude.json", "[1, 2")
    jput(home / ".cursor/mcp.json", {"mcpServers": {"db": {"command": "x"}}})
    inventory_ = find(home)
    assert Problem("~/.claude.json", "not valid JSON") in inventory_.problems
    assert "cursor:mcp:user:db" in by_id(inventory_)


@pytest.mark.skipif(sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0), reason="needs a user who can be refused")
def test_a_folder_that_cannot_be_read_is_a_problem(home):
    skill(home / ".claude/skills/ok")
    locked = skill(home / ".claude/skills/locked")
    put(locked / "inner/file.txt")
    (locked / "inner").chmod(0)
    try:
        inventory_ = find(home)
    finally:
        (locked / "inner").chmod(0o700)
    assert Problem("~/.claude/skills/locked/inner", "unreadable") in inventory_.problems
    assert "claude:skill:user:ok" in by_id(inventory_)


def test_a_link_to_nowhere_is_a_problem(home):
    folder = skill(home / ".claude/skills/dangling")
    (folder / "gone").symlink_to(home / "nothing-here")
    inventory_ = find(home)
    assert Problem("~/.claude/skills/dangling/gone", "link to a missing target") in inventory_.problems
    assert ("gone", str(home / "nothing-here")) in by_id(inventory_)["claude:skill:user:dangling"].links


def test_an_item_with_too_many_files_is_cut_and_reported(home, monkeypatch):
    monkeypatch.setattr(inventory, "MAX_FILES", 5)
    folder = skill(home / ".claude/skills/big")
    for n in range(9):
        put(folder / f"f{n}.txt")
    inventory_ = find(home)
    assert Problem("~/.claude/skills/big", "too many files") in inventory_.problems
    assert len(by_id(inventory_)["claude:skill:user:big"].files) == 5


def test_no_value_of_env_or_headers_reaches_a_locator_a_name_or_a_problem(home, tmp_path):
    secrets = ("sk-live-AAAA1111", "hdr-secret-BBBB2222", "env-secret-CCCC3333", "url-secret-DDDD4444")
    project = tmp_path / "site"
    jput(project / ".mcp.json", {"mcpServers": {
        "api": {"type": "http", "url": "https://mcp.example.test/?k=" + secrets[3], "headers": {"Authorization": "Bearer " + secrets[1]}},
        "cli": {"command": "node", "args": ["--token", secrets[0]], "env": {"TOKEN": secrets[2]}}}})
    jput(project / ".claude/settings.json", {"env": {"ANTHROPIC_BASE_URL": "https://r.example.test/" + secrets[0]},
                                             **hook_doc("curl -H 'x: " + secrets[1] + "' https://h.example.test")})
    put(project / ".claude/settings.local.json", "{ broken " + secrets[2])
    inventory_ = find(home, projects=[project])
    assert len(inventory_.items) >= 4 and inventory_.problems
    shown = [i.location + "|" + i.name + "|" + i.id for i in inventory_.items] + [p.location + "|" + p.reason for p in inventory_.problems]
    for text in shown:
        assert not any(secret in text for secret in secrets), text


def test_three_thousand_files_are_found_in_five_seconds(home):
    for n in range(100):
        folder = skill(home / ".claude/skills" / f"s{n}")
        for k in range(29):
            put(folder / "refs" / f"r{k}.md")
    started = time.monotonic()
    inventory_ = find(home)
    assert time.monotonic() - started < 5
    assert len(inventory_.items) == 100 and sum(len(i.files) for i in inventory_.items) == 3000
