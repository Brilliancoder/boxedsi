"""A keyring backend that keeps its passwords in one JSON file. For the sandbox tests only.

The boxed run sandbox hides boxed's file key store (insecure-keys) from the agent on purpose, and a test must never open the real
keychain, so the keys of those tests live in this file, in a folder the sandbox may read. A test selects it with
PYTHON_KEYRING_BACKEND=file_keyring.FileKeyring and BOXED_TEST_KEYRING_FILE, and checks that the keyring library did pick it before
anything is stored."""

import json
import os

from keyring.backend import KeyringBackend


class FileKeyring(KeyringBackend):
    priority = 1

    def _load(self) -> dict:
        try:
            with open(os.environ["BOXED_TEST_KEYRING_FILE"], encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _save(self, data: dict) -> None:
        fd = os.open(os.environ["BOXED_TEST_KEYRING_FILE"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)

    def get_password(self, service, username):
        return self._load().get(f"{service}/{username}")

    def set_password(self, service, username, password):
        data = self._load()
        data[f"{service}/{username}"] = password
        self._save(data)

    def delete_password(self, service, username):
        data = self._load()
        data.pop(f"{service}/{username}", None)
        self._save(data)
