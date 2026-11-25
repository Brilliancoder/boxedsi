"""Encrypted store of marker maps, one per scope."""

import hashlib
import hmac
import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .keys import KeyStore
from .locks import file_lock
from .mask import MarkerMap
from .platform import refuse_reparse_point

SQLITE_FILES = ("", "-journal", "-wal", "-shm")  # the database, and the files sqlite opens by name beside it
_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS maps ("
    "scope TEXT PRIMARY KEY, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, updated_at TEXT NOT NULL)"
)


class VaultError(Exception):
    pass


class Vault:
    def __init__(self, path: Path, keys: KeyStore) -> None:
        self.path = path
        self.lock_timeout: float | None = None  # seconds a transaction waits for the lock of another; None: the usual wait (LOCK_TIMEOUT)
        self._aead = AESGCM(keys.get_or_create("vault-key", 32))
        self._mac_key = keys.get_or_create("state-mac-key", 32)
        self._execute(_SCHEMA)
        if stat.S_IMODE(path.stat().st_mode) != 0o600:  # not on every open: the boxed run sandbox refuses a chmod, even to set what is set
            os.chmod(path, 0o600)

    def mac(self, data: bytes) -> str:
        """Keyed hash for state files: a plain SHA-256 of a short secret can be brute-forced."""
        return hmac.new(self._mac_key, data, hashlib.sha256).hexdigest()

    @contextmanager
    def transaction(self, scope: str) -> Iterator[MarkerMap]:
        """Load, change and save a scope's markers under an exclusive lock, so parallel callers never reuse a marker."""
        with file_lock(self.path, self.lock_timeout):
            markers = self.load_map(scope)
            yield markers
            self.save_map(scope, markers)

    def _execute(self, sql: str, params: tuple = ()) -> list[tuple]:
        for beside in SQLITE_FILES:  # sqlite would follow a link at any of them, and write the journal of a transaction through it
            refuse_reparse_point(self.path.with_name(self.path.name + beside))
        with closing(sqlite3.connect(self.path)) as db, db:
            return db.execute(sql, params).fetchall()

    def load_map(self, scope: str) -> MarkerMap:
        rows = self._execute("SELECT nonce, ciphertext FROM maps WHERE scope = ?", (scope,))
        if not rows:
            return MarkerMap()
        nonce, ciphertext = rows[0]
        try:
            plain = self._aead.decrypt(nonce, ciphertext, scope.encode())
        except InvalidTag as e:
            raise VaultError(f"cannot decrypt scope {scope!r}: wrong key or tampered data") from e
        return MarkerMap.from_json(plain.decode())

    def save_map(self, scope: str, markers: MarkerMap) -> None:
        nonce = os.urandom(12)
        ciphertext = self._aead.encrypt(nonce, markers.to_json().encode(), scope.encode())
        self._execute(
            "INSERT OR REPLACE INTO maps (scope, nonce, ciphertext, updated_at) VALUES (?, ?, ?, ?)",
            (scope, nonce, ciphertext, datetime.now(UTC).isoformat()),
        )

    def delete_scope(self, scope: str) -> None:
        self._execute("DELETE FROM maps WHERE scope = ?", (scope,))

    def scopes(self) -> list[str]:
        return [row[0] for row in self._execute("SELECT scope FROM maps ORDER BY scope")]
