import errno
import sqlite3
import stat
import sys

import keyring
import pytest
from keyring.backend import KeyringBackend

from boxed.detect import DetectConfig
from boxed.keys import InsecureFileKeyStore, KeyringKeyStore
from boxed.mask import MarkerMap, mask_text, restore
from boxed.paths import boxed_home
from boxed.vault import Vault, VaultError


@pytest.fixture
def keys(tmp_path):
    return InsecureFileKeyStore(tmp_path / "keys")


def sample_map():
    m = MarkerMap()
    m.marker_for("EMAIL", "ivan.petrov@acme.com")
    m.marker_for("SECRET", "AKIAIOSFODNN7EXAMPLE")
    return m


def test_save_load(tmp_path, keys):
    v = Vault(tmp_path / "vault.db", keys)
    v.save_map("ws-1", sample_map())
    assert Vault(tmp_path / "vault.db", keys).load_map("ws-1").items() == sample_map().items()
    assert v.load_map("missing").items() == []


def test_wrong_key_raises_vault_error(tmp_path, keys):
    Vault(tmp_path / "vault.db", keys).save_map("ws-1", sample_map())
    other = Vault(tmp_path / "vault.db", InsecureFileKeyStore(tmp_path / "other-keys"))
    with pytest.raises(VaultError):
        other.load_map("ws-1")


def test_no_plaintext_on_disk(tmp_path, keys):
    Vault(tmp_path / "vault.db", keys).save_map("ws-1", sample_map())
    data = (tmp_path / "vault.db").read_bytes()
    assert b"ivan.petrov@acme.com" not in data
    assert b"AKIAIOSFODNN7EXAMPLE" not in data


def test_scope_swap_detected(tmp_path, keys):
    v = Vault(tmp_path / "vault.db", keys)
    v.save_map("a", sample_map())
    v.save_map("b", MarkerMap())
    with sqlite3.connect(tmp_path / "vault.db") as db:
        nonce, ct = db.execute("SELECT nonce, ciphertext FROM maps WHERE scope = 'a'").fetchone()
        db.execute("UPDATE maps SET nonce = ?, ciphertext = ? WHERE scope = 'b'", (nonce, ct))
    with pytest.raises(VaultError):
        v.load_map("b")


def test_delete_scope(tmp_path, keys):
    v = Vault(tmp_path / "vault.db", keys)
    v.save_map("a", sample_map())
    v.save_map("b", sample_map())
    v.delete_scope("a")
    assert v.scopes() == ["b"]
    assert v.load_map("a").items() == []


def test_a_foreign_token_of_a_scope_is_remembered_by_the_vault(tmp_path, keys):
    acme = DetectConfig(dictionary={"Acme Corp": "CLIENT"})
    with Vault(tmp_path / "vault.db", keys).transaction("task") as markers:
        first, _ = mask_text("template [CLIENT_1] for ivan@acme.com", markers)  # CLIENT is nobody's kind yet
    with Vault(tmp_path / "vault.db", keys).transaction("task") as markers:  # the dictionary has grown since, in a new process
        second, _ = mask_text("Deal with Acme Corp", markers, config=acme)
    assert second == "Deal with [CLIENT_2]"
    restored = Vault(tmp_path / "vault.db", keys).load_map("task")
    assert restore(first, restored, frozenset({"CLIENT"})).text == "template [CLIENT_1] for ivan@acme.com"
    assert restore(second, restored).text == "Deal with Acme Corp"
    with Vault(tmp_path / "vault.db", keys).transaction("other") as markers:  # another scope has its own
        assert mask_text("Deal with Acme Corp", markers, config=acme)[0] == "Deal with [CLIENT_1]"
    assert b"CLIENT_1" not in (tmp_path / "vault.db").read_bytes()  # stored encrypted like the rest of the map


@pytest.mark.skipif(sys.platform == "win32", reason="a file mode means nothing on Windows: the folder decides who may read a file")
def test_vault_file_permissions_0600(tmp_path, keys):
    Vault(tmp_path / "vault.db", keys)
    assert stat.S_IMODE((tmp_path / "vault.db").stat().st_mode) == 0o600


@pytest.mark.skipif(sys.platform == "win32", reason="a file mode means nothing on Windows: the folder decides who may read a file")
def test_home_permissions_0700(tmp_path, monkeypatch):
    monkeypatch.setenv("BOXED_HOME", str(tmp_path / "home"))
    home = boxed_home()
    assert home == tmp_path / "home"
    assert stat.S_IMODE(home.stat().st_mode) == 0o700


class MemoryKeyring(KeyringBackend):
    priority = 1

    def __init__(self):
        super().__init__()
        self.store = {}

    def get_password(self, service, username):
        return self.store.get((service, username))

    def set_password(self, service, username, password):
        self.store[(service, username)] = password

    def delete_password(self, service, username):
        self.store.pop((service, username), None)


def test_keyring_keystore_roundtrip(tmp_path, monkeypatch):
    for name in ("HOME", "USERPROFILE"):  # a first key is made under the lock of the user, in ~/.boxed
        monkeypatch.setenv(name, str(tmp_path))
    previous = keyring.get_keyring()
    backend = MemoryKeyring()
    keyring.set_keyring(backend)
    try:
        ks = KeyringKeyStore()
        first = ks.get_or_create("vault-key", 32)
        assert len(first) == 32
        assert ks.get_or_create("vault-key", 32) == first
        assert ("boxed.si", "vault-key") in backend.store
    finally:
        keyring.set_keyring(previous)


VAULT_CALLS = {
    "open": lambda vault, keys: Vault(vault.path, keys),
    "load_map": lambda vault, keys: vault.load_map("ws-1"),
    "save_map": lambda vault, keys: vault.save_map("ws-2", sample_map()),
    "scopes": lambda vault, keys: vault.scopes(),
    "delete_scope": lambda vault, keys: vault.delete_scope("ws-1"),
}


@pytest.mark.parametrize("name", ["vault.db", "vault.db-journal", "vault.db-wal", "vault.db-shm"])
@pytest.mark.parametrize("call", VAULT_CALLS.values(), ids=VAULT_CALLS.keys())
def test_windows_a_reparse_point_at_vault_db_or_a_file_sqlite_makes_beside_it_is_refused_and_never_opened(fake_msvcrt, tmp_path, keys, see_as, call, name):
    """sqlite follows a link on any system, and macOS leaves it so; Windows says no to every link, junction and placeholder, at the
    database and at the journal, the write-ahead log and the shared memory that sqlite opens by name beside it (a link at
    vault.db-journal took the journal of a write: a file elsewhere grew by it)."""
    vault = Vault(tmp_path / "vault.db", keys)
    vault.save_map("ws-1", sample_map())
    (tmp_path / name).touch()  # vault.db is there; the others only while sqlite works: here one is, as a plain file by its mode
    see_as(tmp_path / name, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)  # and a junction or a placeholder for Windows
    with pytest.raises(OSError) as caught:
        call(vault, keys)
    assert caught.value.errno == errno.ELOOP
