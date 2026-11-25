"""Write a synthetic home folder for demos and smoke tests of `boxed audit` and `boxed skills scan`.

Usage: python scripts/demo/make_home.py DIR
       python scripts/demo/make_home.py --values

`--values` writes nothing and prints every made-up value, one line each (a private key one line per line of it), for a check
that a report shows none of them. DIR becomes a made-up home: project folders in DIR/work, Claude Code transcripts in DIR/.claude/projects, Codex sessions in
DIR/.codex/sessions, plus DIR/samples/app/.env (for `boxed mask`) and DIR/samples/release-notes (a harmless skill for
`boxed skills scan`). The transcripts name the projects by their absolute path, as the agents do, so a report shows them as
~/work/<name>. Every value is invented and generated from a fixed seed, so two runs for the same DIR write the same bytes. The keys carry FAKE or DEMO
and break the provider's own format where the detector allows it (AWS ids with digits outside base32, GitHub tokens with
no valid checksum, Anthropic keys with a made-up version), so no provider would take them. No dependencies.
"""

import base64
import json
import os
import random
import re
import string
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 20261125
ALNUM = string.ascii_letters + string.digits


def fake_values(rng: random.Random) -> dict[str, str]:
    def pick(n: int, alphabet: str = ALNUM) -> str:
        return "".join(rng.choice(alphabet) for _ in range(n))

    def b64(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")

    key_body = "\n".join(base64.b64encode(rng.randbytes(48)).decode() for _ in range(4))
    return {
        "aws": "AKIAFAKE" + pick(8, "0189") + "DEMO",
        "github": "ghp_FAKE" + pick(32),
        "anthropic": "sk-ant-demo00-" + pick(40),
        "openai": "sk-demo-" + pick(40),
        "stripe": "sk_test_DEMO" + pick(20),
        "slack": "xoxb-000000000000-000000000000-FAKE" + pick(20),
        "google": "AIzaFAKE" + pick(31),
        "telegram": "100000000:FAKE" + pick(31),
        "db_password": "demo-" + pick(14, string.ascii_lowercase + string.digits),
        "db_url": "postgres://app:demo-" + pick(10, string.ascii_lowercase) + "@db.acme.example:5432/app",
        "jwt": b64({"alg": "none", "typ": "JWT"}) + "." + b64({"sub": "demo-user", "demo": True}) + "." + pick(32),
        "private_key": f"-----BEGIN OPENSSH PRIVATE KEY-----\n{key_body}\n-----END OPENSSH PRIVATE KEY-----",
        "email_1": "jane.doe@example.com",
        "email_2": "ops-lead@example.org",
        "phone": "+1 202 555 0143",
        "ip": "203.0.113.42",
        "card": "4242 4242 4242 4242",
    }


FILLER = [
    "run the unit tests and tell me which ones fail",
    "rename the helper to something clearer",
    "why does the build take so long on the second run",
    "add a short docstring to the parser module",
    "the linter complains about unused imports, fix them",
    "explain what this function returns when the list is empty",
    "make the retry loop stop after three attempts",
    "write a changelog entry for the last change",
]
TOOL_FILLER = [
    "tests passed: 41, failed: 0",
    "src/parser.py\nsrc/retry.py\nREADME.md",
    "nothing to commit, working tree clean",
    "def parse(lines):\n    return [line.strip() for line in lines if line]",
    "build finished without warnings",
]


def env_file(v: dict[str, str]) -> str:
    return (
        "APP_ENV=staging\n"
        f"DATABASE_URL={v['db_url']}\n"
        f"DB_PASSWORD={v['db_password']}\n"
        f"AWS_ACCESS_KEY_ID={v['aws']}\n"
        f"STRIPE_SECRET_KEY={v['stripe']}\n"
        f"SUPPORT_EMAIL={v['email_1']}\n"
    )


def sessions(v: dict[str, str]) -> list[tuple[str, str, list[tuple[str, str]]]]:
    """(agent, project, [(role, text)]): project is a folder name under DIR/work; role is prompt, tool or attachment. Secrets
    repeat across sessions on purpose."""
    env = env_file(v)
    return [
        ("claude", "acme-api", [("prompt", "the app fails to start, look at the config"), ("tool", env),
                                ("prompt", "now run the migrations"), ("tool", f"connected as app to {v['db_url']}")]),
        ("claude", "acme-api", [("prompt", "why is the payment test red"), ("attachment", env),
                                ("prompt", f"the customer is {v['email_1']}, card {v['card']}, retry the charge")]),
        ("claude", "billing-worker", [("prompt", "the worker cannot reach slack"),
                                      ("tool", f"SLACK_BOT_TOKEN={v['slack']}\nALERT_PHONE={v['phone']}"),
                                      ("prompt", f"use this one instead: {v['github']}")]),
        ("claude", "infra", [("prompt", "set up the deploy key on the build box"), ("tool", v["private_key"]),
                             ("tool", f"ssh: connect to host {v['ip']} port 22: timed out"), ("tool", env)]),
        ("codex", "mobile-app", [("prompt", f"wire the maps sdk, the key is {v['google']}"),
                                 ("tool", f"Authorization: Bearer {v['jwt']}"),
                                 ("prompt", f"send crash reports to {v['email_2']}")]),
        ("codex", "acme-api", [("prompt", "check why the assistant endpoint returns 401"),
                               ("tool", f"ANTHROPIC_API_KEY={v['anthropic']}\nOPENAI_API_KEY={v['openai']}"),
                               ("tool", env)]),
        ("codex", "infra", [("prompt", f"the bot token is {v['telegram']}, register the webhook"),
                            ("tool", f"export GITHUB_TOKEN={v['github']}")]),
    ]


def claude_lines(rng: random.Random, project: str, sid: str, start: datetime, turns: list[tuple[str, str]]) -> list[dict]:
    out, t = [], start
    base = {"cwd": project, "sessionId": sid, "version": "2.1.0", "gitBranch": "main"}
    for i, (role, text) in enumerate(_with_filler(rng, turns)):
        t += timedelta(seconds=rng.randint(5, 90))
        ts = t.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        if role == "prompt":
            rec = {"type": "user", "message": {"role": "user", "content": text}}
        elif role == "tool":
            tool_id = f"toolu_demo{i:04d}"
            out.append({**base, "type": "assistant", "timestamp": ts,
                        "message": {"role": "assistant", "content": [{"type": "tool_use", "id": tool_id, "name": "Bash",
                                                                      "input": {"command": "cat output.txt"}}]}})
            rec = {"type": "user", "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": tool_id, "content": text}]}}
        else:
            rec = {"type": "attachment", "attachment": {"type": "file", "filename": ".env"},
                   "rendered": [{"content": [{"type": "text", "text": text}]}]}
        out.append({**base, **rec, "timestamp": ts})
        out.append({**base, "type": "assistant", "timestamp": ts,
                    "message": {"role": "assistant", "content": [{"type": "text", "text": "Done, see the notes above."}]}})
    return out


def codex_lines(rng: random.Random, project: str, sid: str, start: datetime, turns: list[tuple[str, str]]) -> list[dict]:
    ts = start.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    out = [{"type": "session_meta", "timestamp": ts, "payload": {"id": sid, "cwd": project, "timestamp": ts,
                                                                 "originator": "codex_cli_rs", "cli_version": "0.80.0"}}]
    t = start
    for i, (role, text) in enumerate(_with_filler(rng, turns)):
        t += timedelta(seconds=rng.randint(5, 90))
        ts = t.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        if role == "prompt":
            payload = {"type": "message", "role": "user", "content": [{"type": "input_text", "text": text}]}
        else:
            call = f"call_demo{i:04d}"
            out.append({"type": "response_item", "timestamp": ts, "payload": {
                "type": "function_call", "name": "shell", "call_id": call, "arguments": "{\"command\":[\"cat\",\"output.txt\"]}"}})
            payload = {"type": "function_call_output", "call_id": call, "output": text}
        out.append({"type": "response_item", "timestamp": ts, "payload": payload})
        out.append({"type": "response_item", "timestamp": ts, "payload": {
            "type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Done."}]}})
    return out


def _with_filler(rng: random.Random, turns: list[tuple[str, str]]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for turn in turns:
        for _ in range(rng.randint(2, 5)):
            out.append(("prompt", rng.choice(FILLER)) if rng.random() < 0.5 else ("tool", rng.choice(TOOL_FILLER)))
        out.append(turn)
    return out


SKILL = """---
name: release-notes
description: Drafts release notes from the merged pull requests of the current branch.
---

# Release notes

1. List the commits since the last tag with `git log --oneline`.
2. Group them into Added, Changed and Fixed.
3. Write the draft to RELEASE_NOTES.md and show it to the user. Do not publish anything.
"""


def write_home(root: Path) -> None:
    root = Path(os.path.abspath(root))  # not resolved: the projects must start with the home as HOME spells it
    rng = random.Random(SEED)
    values = fake_values(rng)
    start = datetime(2026, 11, 3, 9, 0, tzinfo=timezone.utc)
    for n, (agent, name, turns) in enumerate(sessions(values)):
        project_dir = root / "work" / name
        project_dir.mkdir(parents=True, exist_ok=True)
        (project_dir / "README.md").write_bytes(f"# {name}\n\nA made-up project of the boxed demo.\n".encode())
        project = str(project_dir)
        sid = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        begin = start + timedelta(days=2 * n, minutes=rng.randint(0, 600))
        if agent == "claude":
            # Claude Code names the folder after the whole project path: every character but an ASCII letter or digit is '-'
            folder = root / ".claude" / "projects" / re.sub(r"[^A-Za-z0-9]", "-", project)
            lines = claude_lines(rng, project, sid, begin, turns)
            path = folder / f"{sid}.jsonl"
        else:
            folder = root / ".codex" / "sessions" / begin.strftime("%Y/%m/%d")
            lines = codex_lines(rng, project, sid, begin, turns)
            path = folder / f"rollout-{begin.strftime('%Y-%m-%dT%H-%M-%S')}-{sid}.jsonl"
        folder.mkdir(parents=True, exist_ok=True)
        path.write_bytes("".join(json.dumps(line, ensure_ascii=False) + "\n" for line in lines).encode())
    app = root / "samples" / "app"
    app.mkdir(parents=True, exist_ok=True)
    (app / ".env").write_bytes(env_file(values).encode())
    skill = root / "samples" / "release-notes"
    skill.mkdir(parents=True, exist_ok=True)
    (skill / "SKILL.md").write_bytes(SKILL.encode())


def value_lines() -> list[str]:
    """The made-up values write_home uses (the same seed, the same first draws), one line each, no empty line."""
    return [line for v in fake_values(random.Random(SEED)).values() for line in v.splitlines() if line.strip()]


if __name__ == "__main__":
    if sys.argv[1:] == ["--values"]:
        sys.stdout.buffer.write("".join(line + "\n" for line in value_lines()).encode())  # "\n" on Windows too: grep -f reads it
    elif len(sys.argv) == 2 and not sys.argv[1].startswith("-"):
        write_home(Path(sys.argv[1]))
    else:
        sys.exit("usage: make_home.py DIR | --values")
