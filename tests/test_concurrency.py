import base64
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from boxed.config import ProjectConfig
from boxed.journal import Journal, JournalEntry
from boxed.keys import default_keystore
from boxed.mcp_server import ServerContext, read_masked
from boxed.vault import Vault


def test_parallel_read_masked_gives_distinct_markers(tmp_path, boxed_env):
    logs = tmp_path / "logs"
    logs.mkdir()
    n = 16
    for i in range(n):
        (logs / f"f{i}.log").write_text(f"user{i}@acme.com logged in\n")
    boxed_env.mkdir(parents=True, exist_ok=True)
    keys = default_keystore()
    ctx = ServerContext(boxed_env, ProjectConfig(mcp_roots=[str(logs)]), Vault(boxed_env / "vault.db", keys), Journal(boxed_env / "journal.jsonl", keys), "mcp-race")
    barrier = threading.Barrier(n)

    def work(i):
        barrier.wait()
        return i, read_masked(str(logs / f"f{i}.log"), ctx=ctx).split()[0]

    with ThreadPoolExecutor(n) as pool:
        results = list(pool.map(work, range(n)))
    markers = ctx.vault.load_map("mcp-race")
    assert len({m for _, m in results}) == n
    for i, marker in results:
        assert markers.original_for(marker) == f"user{i}@acme.com"
    assert ctx.journal.verify().ok and ctx.journal.verify().count == n


def test_parallel_journal_appends_verify(tmp_path):
    from boxed.keys import InsecureFileKeyStore

    journal = Journal(tmp_path / "j.jsonl", InsecureFileKeyStore(tmp_path / "k"))
    entry = JournalEntry("mcp", "x", "x", 2, {}, "sent", "00" * 32, "file", "s")
    barrier = threading.Barrier(8)

    def work(_):
        barrier.wait()
        for _ in range(10):
            journal.append(entry)

    with ThreadPoolExecutor(8) as pool:
        list(pool.map(work, range(8)))
    report = journal.verify()
    assert report.ok and report.count == 80


# Two processes that need the same key for the first time at once. Making a key is slowed down in both, so that without the lock
# each would find no key, make one of its own, and the one written last would win: the other's vault map would not open again.
FIRST_KEY = r"""
import json, os, sys, time
from pathlib import Path

real_urandom = os.urandom
os.urandom = lambda n: (time.sleep(0.5), real_urandom(n))[1]
go = Path(sys.argv[2])
while not go.exists():
    time.sleep(0.01)
if sys.argv[1] == "keyring":
    import keyring
    from keyring.backend import KeyringBackend

    class FileKeyring(KeyringBackend):  # a keychain of its own in a file: the real one is never asked
        priority = 1
        store = Path(sys.argv[3])

        def _all(self):
            return json.loads(self.store.read_text()) if self.store.exists() else {}

        def get_password(self, service, username):
            return self._all().get(f"{service}/{username}")

        def set_password(self, service, username, password):
            self.store.write_text(json.dumps(self._all() | {f"{service}/{username}": password}))

        def delete_password(self, service, username):
            raise NotImplementedError

    keyring.set_keyring(FileKeyring())
    from boxed.keys import KeyringKeyStore as Store

    keys = Store()
else:
    from boxed.keys import default_keystore

    keys = default_keystore()
print(keys.get_or_create("vault-key", 32).hex())
"""


@pytest.mark.parametrize("store,homes", [("insecure-file", 1), ("keyring", 1), ("keyring", 2)])
def test_two_processes_that_make_the_first_key_at_once_get_the_same_key(tmp_path, store, homes):
    """With the keychain, also when the two have different data folders: the keychain is one for the user, and so is its lock."""
    home = tmp_path / "boxed-home"
    go = tmp_path / "go"
    args = [sys.executable, "-c", FIRST_KEY, store, str(go), str(tmp_path / "keychain.json")]
    envs = [
        {**os.environ, "HOME": str(tmp_path), "BOXED_HOME": str(home if homes == 1 else tmp_path / f"boxed-home-{n}"), "BOXED_KEYSTORE": store}
        for n in range(2)
    ]
    workers = [subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for env in envs]
    time.sleep(0.5)  # both are waiting for the start
    go.touch()
    results = [worker.communicate(timeout=60) for worker in workers]
    assert all(worker.returncode == 0 for worker in workers), [err for _, err in results]
    first, second = (out.strip() for out, _ in results)
    assert first and first == second
    if store == "insecure-file":
        assert bytes.fromhex(first) == base64.b64decode((home / "insecure-keys" / "vault-key.key").read_text())
        assert not list((home / "insecure-keys").glob("*.part"))
