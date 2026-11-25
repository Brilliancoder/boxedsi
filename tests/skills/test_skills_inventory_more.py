"""Front matter, links at the top of a folder, plugins of one project, and repeats."""

from boxed.skills.inventory import Problem
from test_skills_inventory import by_id, find, home, jput, put, skill, tag  # noqa: F401  (home is a fixture)
from test_skills_inventory import hook_doc


def test_front_matter_hooks_in_block_style_with_comments_and_windows_line_ends(home):
    text = (
        "---\r\nname: x\r\n# a comment\r\nhooks:\r\n  PostToolUse:\r\n    - matcher: Edit|Write   # trailing note\r\n"
        "      hooks:\r\n        - type: command\r\n          command: |\r\n            echo one\r\n            echo two\r\n---\r\nbody\r\n"
    )
    (home / ".claude/commands").mkdir(parents=True)
    (home / ".claude/commands/fmt.md").write_bytes(text.encode())
    (item,) = [i for i in find(home).items if i.kind == "hook"]
    assert item.entry["command"] == "echo one\necho two"
    assert item.entry["matcher"] == "Edit|Write" and item.entry["event"] == "PostToolUse"


def test_front_matter_with_a_tab_in_its_hooks_is_a_problem_and_the_file_is_still_an_item(home):
    put(home / ".claude/agents/odd.md", "---\nname: odd\nhooks:\n\tStop: []\n---\nbody\n")
    inventory_ = find(home)
    assert Problem("~/.claude/agents/odd.md", "not valid frontmatter") in inventory_.problems
    assert "claude:agent:user:odd" in by_id(inventory_)


def test_a_command_file_linked_at_the_top_of_the_folder_is_followed_once_and_a_deeper_link_is_not(home, tmp_path):
    real = put(tmp_path / "dotfiles/deploy.md", "deploy\n")
    deep = put(tmp_path / "dotfiles/deep.md", "deep\n")
    folder = home / ".claude/commands"
    folder.mkdir(parents=True)
    (folder / "deploy.md").symlink_to(real)
    (folder / "team").mkdir()
    (folder / "team/deep.md").symlink_to(deep)
    items = by_id(find(home))
    top = items["claude:command:user:deploy"]
    assert top.root == folder / "deploy.md" and top.files == (real,) and top.links == ()
    nested = items["claude:command:user:team/deep"]
    assert nested.files == () and nested.links == (("team/deep.md", str(deep)),)


def test_a_plugin_installed_for_one_project_belongs_to_that_project(home, tmp_path):
    project = tmp_path / "site"
    root = home / ".claude/plugins/cache/market/tool/1.0.0"
    skill(root / "skills/inner")
    jput(home / ".claude/plugins/installed_plugins.json", {"version": 2, "plugins": {"tool@market": [
        {"scope": "local", "installPath": str(root), "projectPath": str(project)},
        {"scope": "project", "installPath": str(root), "projectPath": str(tmp_path / "gone")}]}})
    jput(project / ".claude/settings.json", {"enabledPlugins": {"tool@market": False}})
    items = by_id(find(home))
    assert list(items) == [f"claude:plugin:local={tag(project)}:tool@market"]
    assert items[f"claude:plugin:local={tag(project)}:tool@market"].enabled is False


def test_a_project_lock_file_gives_the_origin_of_a_project_skill(home, tmp_path):
    project = tmp_path / "site"
    skill(project / ".agents/skills/locked")
    jput(project / "skills-lock.json", {"version": 1, "skills": {"locked": {"source": "acme/team-skills"}}})
    (item,) = find(home, projects=[project]).items
    assert item.origin == "skills-lock:acme/team-skills"


def test_a_script_that_is_a_link_is_recorded_as_a_link_and_not_as_a_file(home, tmp_path):
    real = put(tmp_path / "elsewhere/real.sh", "exit 0\n")
    link = home / ".claude/hooks/linked.sh"
    link.parent.mkdir(parents=True)
    link.symlink_to(real)
    jput(home / ".claude/settings.json", hook_doc(str(link)))
    (item,) = [i for i in find(home).items if i.kind == "hook"]
    assert item.files == () and item.links == ((str(link), str(real)),)


def test_the_home_folder_as_a_registered_project_does_not_count_the_user_files_twice(home):
    skill(home / ".claude/skills/mine")
    put(home / ".claude/commands/c.md")
    jput(home / ".mcp.json", {"mcpServers": {"here": {"command": "x"}}})
    jput(home / ".claude.json", {"projects": {str(home): {"mcpServers": {"scratch": {"command": "y"}}}}})
    ids = [i.id for i in find(home, registered=True).items]
    assert sorted(ids) == sorted([
        "claude:skill:user:mine", "claude:command:user:c",
        f"claude:mcp:project={tag(home)}:here", f"claude:mcp:local={tag(home)}:scratch"])


def test_the_same_command_twice_in_one_file_keeps_two_ids(home):
    same = {"type": "command", "command": "echo twice"}
    jput(home / ".claude/settings.json", {"hooks": {"Stop": [{"matcher": "a", "hooks": [same]}, {"matcher": "b", "hooks": [same]}]}})
    ids = sorted(i.id for i in find(home).items)
    assert len(ids) == 2 and len(set(ids)) == 2 and ids[0] in ids[1]


def test_a_target_that_is_one_config_file_gives_its_entries(tmp_path):
    from boxed.skills.inventory import discover_target

    config = jput(tmp_path / ".mcp.json", {"mcpServers": {"srv": {"command": "node"}}})
    assert [i.id for i in discover_target(config, "cfg").items] == ["claude:mcp:target:srv"]


def test_a_target_with_a_codex_config_gives_its_servers_and_notify(tmp_path):
    from boxed.skills.inventory import discover_target

    script = put(tmp_path / "pkg/hook.py", "print(1)\n")
    put(tmp_path / "pkg/.codex/config.toml", f'notify = ["python3", "{script}"]\n[mcp_servers.repl]\ncommand = "node"\n')
    items = by_id(discover_target(tmp_path / "pkg", "pkg"))
    assert set(items) == {"codex:mcp:target:repl", "codex:setting:target:notify"}
    assert items["codex:setting:target:notify"].files == (script,)
    assert items["codex:mcp:target:repl"].location == "pkg/.codex/config.toml mcp_servers.repl"


def test_a_folder_in_the_skills_root_with_no_skill_inside_is_not_an_item(home):
    put(home / ".claude/skills/notes/readme.txt", "not a skill\n")
    put(home / ".claude/skills/loose-file.md", "not a skill\n")
    assert find(home).items == ()
