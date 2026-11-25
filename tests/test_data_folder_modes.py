"""The data folder and the vault file change their mode only when it is wrong. A sandbox that allows no writes there
refuses os.chmod even for a mode that is right already, and that stopped every hook and the MCP server under boxed run. No test
touches the real ~/.boxed or the keychain: conftest.py points BOXED_HOME at a temp folder and the keys at files."""

import os
import stat
import sys

import pytest

from boxed.keys import default_keystore
from boxed.paths import boxed_home
from boxed.vault import Vault

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="a file mode means nothing on Windows: the folder decides who may read a file")


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def refuse_chmod(monkeypatch):
    """os.chmod as the boxed run sandbox answers it: not permitted, whatever the mode is."""

    def refuse(path, *args, **kwargs):
        raise PermissionError(1, "Operation not permitted", str(path))

    monkeypatch.setattr(os, "chmod", refuse)


def test_a_new_data_folder_is_private(boxed_env):
    assert boxed_home() == boxed_env
    assert mode(boxed_env) == 0o700


def test_a_data_folder_with_another_mode_is_made_private(boxed_env):
    boxed_env.mkdir()
    boxed_env.chmod(0o755)
    boxed_home()
    assert mode(boxed_env) == 0o700


def test_a_private_data_folder_is_not_changed_again(boxed_env, monkeypatch):
    boxed_home()
    refuse_chmod(monkeypatch)
    assert boxed_home() == boxed_env


def test_a_mode_that_is_wrong_and_cannot_be_set_is_an_error(boxed_env, monkeypatch):
    boxed_env.mkdir()
    boxed_env.chmod(0o755)
    refuse_chmod(monkeypatch)
    with pytest.raises(PermissionError):
        boxed_home()
    assert mode(boxed_env) == 0o755  # nothing pretends that it was fixed


def test_a_vault_file_with_another_mode_is_made_private(boxed_env):
    keys = default_keystore()
    path = boxed_home() / "vault.db"
    Vault(path, keys)
    path.chmod(0o644)
    Vault(path, keys)
    assert mode(path) == 0o600


def test_a_private_vault_file_is_opened_without_changing_its_mode(boxed_env, monkeypatch):
    keys = default_keystore()
    path = boxed_home() / "vault.db"
    Vault(path, keys)
    refuse_chmod(monkeypatch)
    Vault(path, keys)
