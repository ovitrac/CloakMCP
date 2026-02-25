"""Tests for Tier 1 key wrapping (scrypt passphrase-wrapped keys)."""
from __future__ import annotations
import os
import tempfile

import pytest
from cryptography.fernet import Fernet, InvalidToken

from cloakmcp.storage import (
    _derive_wrapping_key,
    _detect_key_format,
    _gen_keyfile,
    _load_key,
    _wrap_key,
    _unwrap_key,
    _verify_permissions,
    _KEY_HEADER,
    _SCRYPT_N,
    _SCRYPT_R,
    _SCRYPT_P,
    wrap_keyfile,
    unwrap_keyfile,
    Vault,
    encrypt_backup,
    decrypt_backup,
)


class TestDeriveWrappingKey:
    def test_deterministic(self):
        salt = b"x" * 32
        k1 = _derive_wrapping_key("mypass", salt)
        k2 = _derive_wrapping_key("mypass", salt)
        assert k1 == k2

    def test_different_passphrase_different_key(self):
        salt = b"x" * 32
        k1 = _derive_wrapping_key("pass1", salt)
        k2 = _derive_wrapping_key("pass2", salt)
        assert k1 != k2

    def test_different_salt_different_key(self):
        k1 = _derive_wrapping_key("mypass", b"a" * 32)
        k2 = _derive_wrapping_key("mypass", b"b" * 32)
        assert k1 != k2

    def test_result_is_valid_fernet_key(self):
        salt = b"z" * 32
        key = _derive_wrapping_key("test", salt)
        # Must not raise
        Fernet(key)


class TestDetectKeyFormat:
    def test_raw_key(self):
        key = Fernet.generate_key()
        assert _detect_key_format(key) == "raw"

    def test_wrapped_key(self):
        data = _KEY_HEADER + b"abcdef\nciphertext\n"
        assert _detect_key_format(data) == "wrapped"

    def test_empty_data(self):
        assert _detect_key_format(b"") == "raw"


class TestWrapUnwrap:
    def test_roundtrip(self):
        raw_key = Fernet.generate_key()
        wrapped = _wrap_key(raw_key, "passphrase123")
        unwrapped = _unwrap_key(wrapped, "passphrase123")
        assert unwrapped == raw_key

    def test_wrong_passphrase_raises(self):
        raw_key = Fernet.generate_key()
        wrapped = _wrap_key(raw_key, "correct")
        with pytest.raises(InvalidToken):
            _unwrap_key(wrapped, "wrong")

    def test_wrapped_format_has_header(self):
        raw_key = Fernet.generate_key()
        wrapped = _wrap_key(raw_key, "pass")
        assert wrapped.startswith(_KEY_HEADER)

    def test_malformed_wrapped_raises(self):
        with pytest.raises(ValueError, match="missing CLOAKKEY1"):
            _unwrap_key(b"garbage", "pass")


class TestGenKeyfile:
    def test_tier0_no_passphrase(self, tmp_path):
        path = str(tmp_path / "test.key")
        key = _gen_keyfile(path, passphrase=None)
        # Raw key file: just base64 bytes
        with open(path, "rb") as f:
            data = f.read()
        assert _detect_key_format(data) == "raw"
        assert key == data  # raw key is the file content
        Fernet(key)  # must be valid

    def test_tier1_with_passphrase(self, tmp_path):
        path = str(tmp_path / "test.key")
        key = _gen_keyfile(path, passphrase="secret")
        with open(path, "rb") as f:
            data = f.read()
        assert _detect_key_format(data) == "wrapped"
        # Unwrap must give back the same raw key
        unwrapped = _unwrap_key(data, "secret")
        assert unwrapped == key


class TestLoadKey:
    def test_load_raw_key(self, tmp_path):
        path = str(tmp_path / "test.key")
        original = _gen_keyfile(path, passphrase=None)
        loaded = _load_key(path)
        assert loaded == original

    def test_load_wrapped_key_with_passphrase(self, tmp_path, monkeypatch):
        path = str(tmp_path / "test.key")
        original = _gen_keyfile(path, passphrase="mypass")
        monkeypatch.setenv("CLOAK_PASSPHRASE", "mypass")
        loaded = _load_key(path)
        assert loaded == original

    def test_load_wrapped_key_wrong_passphrase(self, tmp_path, monkeypatch):
        path = str(tmp_path / "test.key")
        _gen_keyfile(path, passphrase="correct")
        monkeypatch.setenv("CLOAK_PASSPHRASE", "wrong")
        with pytest.raises(InvalidToken):
            _load_key(path)

    def test_load_wrapped_key_no_passphrase_raises(self, tmp_path, monkeypatch):
        path = str(tmp_path / "test.key")
        _gen_keyfile(path, passphrase="secret")
        monkeypatch.delenv("CLOAK_PASSPHRASE", raising=False)
        with pytest.raises(RuntimeError, match="passphrase-wrapped"):
            _load_key(path)


class TestWrapUnwrapKeyfile:
    def test_wrap_then_unwrap(self, tmp_path, monkeypatch):
        # Create a raw key file (no passphrase during generation)
        monkeypatch.delenv("CLOAK_PASSPHRASE", raising=False)
        key_dir = tmp_path / "keys"
        key_dir.mkdir()
        monkeypatch.setattr("cloakmcp.storage.KEYS_DIR", str(key_dir))
        monkeypatch.setattr("cloakmcp.storage.DEFAULT_HOME", str(tmp_path))
        monkeypatch.setattr("cloakmcp.storage.VAULTS_DIR", str(tmp_path / "vaults"))
        monkeypatch.setattr("cloakmcp.storage.BACKUPS_DIR", str(tmp_path / "backups"))

        project_dir = str(tmp_path / "project")
        os.makedirs(project_dir)

        # Create a vault to generate the raw key file
        vault = Vault(project_dir)
        original_key = vault._vault_key

        # Now wrap with passphrase
        path = wrap_keyfile(project_dir, passphrase="wrap-pass")
        with open(path, "rb") as f:
            data = f.read()
        assert _detect_key_format(data) == "wrapped"

        # Unwrap
        unwrap_keyfile(project_dir, passphrase="wrap-pass")
        with open(path, "rb") as f:
            data = f.read()
        assert _detect_key_format(data) == "raw"
        assert data.strip() == original_key

    def test_wrap_already_wrapped_raises(self, tmp_path, monkeypatch):
        # Create raw key first (no passphrase)
        monkeypatch.delenv("CLOAK_PASSPHRASE", raising=False)
        key_dir = tmp_path / "keys"
        key_dir.mkdir()
        monkeypatch.setattr("cloakmcp.storage.KEYS_DIR", str(key_dir))
        monkeypatch.setattr("cloakmcp.storage.DEFAULT_HOME", str(tmp_path))
        monkeypatch.setattr("cloakmcp.storage.VAULTS_DIR", str(tmp_path / "vaults"))
        monkeypatch.setattr("cloakmcp.storage.BACKUPS_DIR", str(tmp_path / "backups"))

        project_dir = str(tmp_path / "project")
        os.makedirs(project_dir)
        Vault(project_dir)

        # First wrap succeeds
        wrap_keyfile(project_dir, passphrase="pass")
        # Second wrap fails
        with pytest.raises(RuntimeError, match="already wrapped"):
            wrap_keyfile(project_dir, passphrase="pass")

    def test_unwrap_already_raw_raises(self, tmp_path, monkeypatch):
        monkeypatch.delenv("CLOAK_PASSPHRASE", raising=False)
        key_dir = tmp_path / "keys"
        key_dir.mkdir()
        monkeypatch.setattr("cloakmcp.storage.KEYS_DIR", str(key_dir))
        monkeypatch.setattr("cloakmcp.storage.DEFAULT_HOME", str(tmp_path))
        monkeypatch.setattr("cloakmcp.storage.VAULTS_DIR", str(tmp_path / "vaults"))
        monkeypatch.setattr("cloakmcp.storage.BACKUPS_DIR", str(tmp_path / "backups"))

        project_dir = str(tmp_path / "project")
        os.makedirs(project_dir)
        Vault(project_dir)

        with pytest.raises(RuntimeError, match="already raw"):
            unwrap_keyfile(project_dir, passphrase="pass")


class TestVaultWithWrappedKey:
    def test_vault_operations(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CLOAK_PASSPHRASE", "vault-pass")
        key_dir = tmp_path / "keys"
        key_dir.mkdir()
        vaults_dir = tmp_path / "vaults"
        vaults_dir.mkdir()
        monkeypatch.setattr("cloakmcp.storage.KEYS_DIR", str(key_dir))
        monkeypatch.setattr("cloakmcp.storage.DEFAULT_HOME", str(tmp_path))
        monkeypatch.setattr("cloakmcp.storage.VAULTS_DIR", str(vaults_dir))
        monkeypatch.setattr("cloakmcp.storage.BACKUPS_DIR", str(tmp_path / "backups"))

        project_dir = str(tmp_path / "project")
        os.makedirs(project_dir)

        # Create vault with raw key first
        monkeypatch.delenv("CLOAK_PASSPHRASE", raising=False)
        vault1 = Vault(project_dir)
        tag = vault1.tag_for("my-secret-123", "TAG")
        assert vault1.secret_for(tag) == "my-secret-123"

        # Wrap the key
        monkeypatch.setenv("CLOAK_PASSPHRASE", "vault-pass")
        wrap_keyfile(project_dir, passphrase="vault-pass")

        # Re-open vault with wrapped key — must still work
        vault2 = Vault(project_dir)
        assert vault2.secret_for(tag) == "my-secret-123"


class TestBackupWithWrappedKey:
    def test_encrypt_decrypt_with_wrapped_key(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CLOAK_PASSPHRASE", "backup-pass")
        key_dir = tmp_path / "keys"
        key_dir.mkdir()
        monkeypatch.setattr("cloakmcp.storage.KEYS_DIR", str(key_dir))
        monkeypatch.setattr("cloakmcp.storage.DEFAULT_HOME", str(tmp_path))
        monkeypatch.setattr("cloakmcp.storage.VAULTS_DIR", str(tmp_path / "vaults"))
        monkeypatch.setattr("cloakmcp.storage.BACKUPS_DIR", str(tmp_path / "backups"))

        project_dir = str(tmp_path / "project")
        os.makedirs(project_dir)

        # Create key as wrapped
        from cloakmcp.storage import _gen_keyfile, _project_slug, _key_path
        slug = _project_slug(project_dir)
        kp = _key_path(slug)
        _gen_keyfile(kp, passphrase="backup-pass")

        # Encrypt and decrypt
        plaintext = b"secret backup data here"
        encrypted = encrypt_backup(plaintext, project_dir)
        decrypted = decrypt_backup(encrypted, project_dir)
        assert decrypted == plaintext


class TestVerifyPermissions:
    def test_corrects_wrong_permissions(self, tmp_path):
        path = tmp_path / "test.key"
        path.write_bytes(b"test")
        os.chmod(str(path), 0o644)
        corrected = _verify_permissions(str(path), 0o600)
        assert corrected is True
        actual = os.stat(str(path)).st_mode & 0o777
        assert actual == 0o600

    def test_no_correction_needed(self, tmp_path):
        path = tmp_path / "test.key"
        path.write_bytes(b"test")
        os.chmod(str(path), 0o600)
        corrected = _verify_permissions(str(path), 0o600)
        assert corrected is False


class TestScryptParams:
    def test_params_values(self):
        assert _SCRYPT_N == 2**17
        assert _SCRYPT_R == 8
        assert _SCRYPT_P == 1
