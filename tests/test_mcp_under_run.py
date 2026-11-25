"""Under `boxed run` a call of an MCP tool ends in one fixed sentence, not in a crash.

A call must save the placeholders it hands out in vault.db, and the profile of boxed run keeps the vault read-only. The call used to
end in a PermissionError that the server logged as a crash: about 50 KB of traceback on stderr, and "Error executing tool" for the
agent. Now the tool says that it is not available inside boxed run yet, before it touches the vault. No test touches the real
~/.boxed or the keychain: conftest.py points BOXED_HOME at a temp folder and the keys at files."""

import asyncio
import sys

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from boxed import mcp_server, platform
from boxed.config import ProjectConfig
from boxed.journal import Journal
from boxed.keys import default_keystore
from boxed.mcp_server import ServerContext, build_server
from boxed.vault import Vault

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="boxed mcp is not supported on Windows yet")
SENTENCE = "Error executing tool {tool}: not available inside boxed run yet"


@pytest.fixture
def served(tmp_path, boxed_env):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "app.log").write_text("login ivan.petrov@acme.com ok\n")
    boxed_env.mkdir(parents=True, exist_ok=True)
    keys = default_keystore()
    ctx = ServerContext(
        home=boxed_env,
        config=ProjectConfig(mcp_roots=[str(logs)]),
        vault=Vault(boxed_env / "vault.db", keys),
        journal=Journal(boxed_env / "journal.jsonl", keys),
        scope="mcp-test",
    )
    return build_server(ctx), ctx, logs


CALLS = {"read_masked": lambda logs: {"path": str(logs / "app.log")}, "search_masked": lambda logs: {"pattern": "login", "root": str(logs)}}


@pytest.mark.parametrize("tool", CALLS)
def test_a_call_inside_the_sandbox_is_refused_in_one_sentence(tool, served, monkeypatch):
    server, _, logs = served
    monkeypatch.setattr(mcp_server, "sandboxed", lambda: True)
    with pytest.raises(ToolError) as caught:
        asyncio.run(server.call_tool(tool, CALLS[tool](logs)))
    assert type(caught.value) is ToolError  # a refusal the server does not log as a crash
    assert str(caught.value) == SENTENCE.format(tool=tool)


def test_a_call_inside_the_sandbox_does_not_touch_the_vault_or_the_journal(served, monkeypatch):
    server, ctx, logs = served
    monkeypatch.setattr(mcp_server, "sandboxed", lambda: True)

    def touched(*args, **kwargs):
        raise AssertionError("the vault was used")

    monkeypatch.setattr(ctx.vault, "transaction", touched)
    before = ctx.journal.entries()
    with pytest.raises(ToolError):
        asyncio.run(server.call_tool("read_masked", {"path": str(logs / "app.log")}))
    assert ctx.journal.entries() == before


def test_a_call_outside_the_sandbox_works_as_before(served, monkeypatch):
    server, _, logs = served
    monkeypatch.setattr(mcp_server, "sandboxed", lambda: False)
    result = asyncio.run(server.call_tool("read_masked", {"path": str(logs / "app.log")}))
    assert result.is_error is False and "ivan.petrov" not in str(result.content) and "[EMAIL_1]" in str(result.content)


def test_nothing_is_a_sandbox_off_macos(monkeypatch):
    monkeypatch.setattr(platform.sys, "platform", "linux")
    assert platform.sandboxed() is False
