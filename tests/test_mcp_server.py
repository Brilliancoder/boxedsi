import asyncio
import inspect
import json
import os
import subprocess
import sys

import pytest

from boxed.config import ProjectConfig
from boxed.journal import Journal
from boxed.keys import default_keystore
from boxed.mcp_server import ServerContext, build_server, read_masked, search_masked
from boxed.vault import Vault
from boxed.workspace import create_workspace

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="boxed mcp is not supported on Windows yet")


@pytest.fixture
def setup(tmp_path, boxed_env):
    logs = tmp_path / "logs"
    (logs / "old").mkdir(parents=True)
    (logs / "app.log").write_text("login ivan.petrov@acme.com ok\nlogout\nDB_PASSWORD=hunter22\n")
    (logs / "old" / "web.log").write_text("login anna@acme.com from 203.0.113.7\n")
    (logs / "blob.bin").write_bytes(b"\x00\x01binary")
    outside = tmp_path / "outside.txt"
    outside.write_text("secret plans")
    os.symlink(outside, logs / "escape.txt")
    home = boxed_env
    home.mkdir(parents=True, exist_ok=True)
    keys = default_keystore()
    ctx = ServerContext(
        home=home,
        config=ProjectConfig(mcp_roots=[str(logs)]),
        vault=Vault(home / "vault.db", keys),
        journal=Journal(home / "journal.jsonl", keys),
        scope="mcp-test",
    )
    return ctx, logs, outside


def test_read_inside_root_masked(setup):
    ctx, logs, _ = setup
    out = read_masked(str(logs / "app.log"), ctx=ctx)
    assert out == "login [EMAIL_1] ok\nlogout\nDB_PASSWORD=[SECRET_1]\n"


def test_read_outside_root_rejected(setup):
    ctx, _, outside = setup
    with pytest.raises(ValueError, match="allowed root"):
        read_masked(str(outside), ctx=ctx)


def test_symlink_escape_rejected(setup):
    ctx, logs, _ = setup
    with pytest.raises(ValueError, match="allowed root"):
        read_masked(str(logs / "escape.txt"), ctx=ctx)


def test_binary_rejected(setup):
    ctx, logs, _ = setup
    with pytest.raises(ValueError, match="binary"):
        read_masked(str(logs / "blob.bin"), ctx=ctx)


def test_no_roots_means_no_reads(setup):
    ctx, logs, _ = setup
    ctx.config = ProjectConfig()
    with pytest.raises(ValueError, match="allowed root"):
        read_masked(str(logs / "app.log"), ctx=ctx)


def test_search_masked_lines(setup):
    ctx, logs, _ = setup
    out = search_masked("login", str(logs), ctx=ctx)
    assert out.splitlines() == ["app.log:1: login [EMAIL_1] ok", "old/web.log:1: login [EMAIL_2] from [IP_1]"]


def test_search_cannot_probe_secrets(setup):
    ctx, logs, _ = setup
    assert search_masked("hunter", str(logs), ctx=ctx) == "no matches"
    assert search_masked(r"ivan\.petrov", str(logs), ctx=ctx) == "no matches"


def test_journal_written(setup):
    ctx, logs, _ = setup
    read_masked(str(logs / "app.log"), ctx=ctx)
    last = ctx.journal.entries()[-1]
    assert (last["channel"], last["status"], last["scope"]) == ("mcp", "sent", "mcp-test")
    assert last["markers_by_kind"] == {"EMAIL": 1, "SECRET": 1}


def test_markers_shared_with_workspace_scope(setup, tmp_path):
    ctx, logs, _ = setup
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "notes.txt").write_text("owner anna@acme.com\n")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    ws = create_workspace(repo, level=2, config=ProjectConfig(), vault=ctx.vault, journal=ctx.journal, home=ctx.home).workspace
    mirror_marker = (ws.mirror / "notes.txt").read_text().split()[1]
    ctx.scope = ws.scope
    assert mirror_marker in read_masked(str(logs / "old" / "web.log"), ctx=ctx)


def test_build_server_tools(setup):
    ctx, _, _ = setup
    tools = build_server(ctx).list_tools()
    if inspect.isawaitable(tools):
        tools = asyncio.run(tools)
    assert sorted(t.name for t in tools) == ["read_masked", "search_masked"]
    assert all("restore" not in json.dumps(t.model_dump()).lower() for t in tools)


def test_stdio_server_lists_tools(boxed_env):
    """Regression pin: `boxed mcp` speaks MCP over stdio to the SDK client."""
    import sys

    import mcp.client.stdio as cs
    from mcp import ClientSession

    async def main():
        params = cs.StdioServerParameters(command=sys.executable, args=["-m", "boxed.cli", "mcp"], env=dict(os.environ))
        async with cs.stdio_client(params) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                return sorted(t.name for t in (await s.list_tools()).tools)

    assert asyncio.run(asyncio.wait_for(main(), 45)) == ["read_masked", "search_masked"]


def test_search_masks_file_names_and_read_accepts_them(setup):
    ctx, logs, _ = setup
    (logs / "ivan.petrov@acme.com.log").write_text("error 1\n")
    out = search_masked("error", str(logs), ctx=ctx)
    assert "[EMAIL_1].log:1: error 1" in out and "ivan.petrov" not in out
    assert read_masked(str(logs / "[EMAIL_1].log"), ctx=ctx) == "error 1\n"
    with pytest.raises(ValueError):
        read_masked(str(logs / "[EMAIL_9].log"), ctx=ctx)


def test_journal_counts_only_real_markers(setup):
    ctx, logs, _ = setup
    (logs / "pins.txt").write_text("[GPIO_12] [SERVER_1] mail ivan.petrov@acme.com\n")
    read_masked(str(logs / "pins.txt"), ctx=ctx)
    assert ctx.journal.entries()[-1]["markers_by_kind"] == {"EMAIL": 1}
