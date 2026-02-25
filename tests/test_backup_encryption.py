"""Tests for encrypted backup at rest (G6 Phase 2).

Covers: HKDF key derivation, create/restore round-trip, permission
hardening, backward compat with legacy directories, and security
(path traversal, wrong key, corrupt data).
"""
from __future__ import annotations
import os
import stat
import tarfile
import io
import tempfile
import shutil

import pytest
from cryptography.fernet import Fernet, InvalidToken

from cloakmcp.storage import (
    _derive_backup_key,
    _backup_fernet,
    encrypt_backup,
    decrypt_backup,
    backup_path_for,
    _project_slug,
    _gen_keyfile,
    _load_key,
    _key_path,
    _ensure_dirs,
    BACKUPS_DIR,
    KEYS_DIR,
)
from cloakmcp.dirpack import (
    create_backup,
    restore_from_backup,
    cleanup_backup,
    list_backups,
)


# ── Fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def project(tmp_path):
    """Create a minimal project directory with a secret-bearing file."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "config.py").write_text(
        'DATABASE_URL = "postgresql://admin:s3cret@localhost/db"\n'
        'API_KEY = "sk-proj-abc123def456ghi789jkl012"\n'
    )
    (tmp_path / "README.md").write_text("# Test project\n")
    # No .mcpignore → all files are in scope
    return tmp_path


@pytest.fixture
def project_with_ignore(project):
    """Project with .mcpignore excluding README."""
    (project / ".mcpignore").write_text("README.md\n")
    return project


# ── HKDF derivation ─────────────────────────────────────────────


class TestHKDF:
    def test_deterministic(self, tmp_path):
        """Same key + slug always produces the same derived key."""
        key = Fernet.generate_key()
        slug = "abcdef1234567890"
        k1 = _derive_backup_key(key, slug)
        k2 = _derive_backup_key(key, slug)
        assert k1 == k2

    def test_differs_from_vault_key(self, tmp_path):
        """HKDF-derived backup key is NOT the raw project key."""
        key = Fernet.generate_key()
        slug = "abcdef1234567890"
        derived = _derive_backup_key(key, slug)
        assert derived != key

    def test_different_slugs_different_keys(self):
        """Different project slugs produce different backup keys."""
        key = Fernet.generate_key()
        k1 = _derive_backup_key(key, "slug_project_a__")
        k2 = _derive_backup_key(key, "slug_project_b__")
        assert k1 != k2

    def test_derived_key_is_valid_fernet_key(self):
        """Derived key can be used to construct a Fernet instance."""
        key = Fernet.generate_key()
        derived = _derive_backup_key(key, "testslug12345678")
        f = Fernet(derived)
        # Round-trip
        ct = f.encrypt(b"hello")
        assert f.decrypt(ct) == b"hello"


# ── Encrypt / decrypt primitives ─────────────────────────────────


class TestEncryptDecrypt:
    def test_round_trip(self, project):
        """encrypt_backup → decrypt_backup returns original bytes."""
        data = b"secret payload inside tar"
        enc = encrypt_backup(data, str(project))
        dec = decrypt_backup(enc, str(project))
        assert dec == data

    def test_encrypted_is_not_plaintext(self, project):
        """Encrypted output does not contain the original bytes."""
        data = b"postgresql://admin:s3cret@localhost/db"
        enc = encrypt_backup(data, str(project))
        assert data not in enc

    def test_wrong_project_fails(self, tmp_path):
        """Backup encrypted for project A cannot be decrypted for project B."""
        proj_a = tmp_path / "project_a"
        proj_b = tmp_path / "project_b"
        proj_a.mkdir()
        proj_b.mkdir()
        data = b"secret"
        enc = encrypt_backup(data, str(proj_a))
        with pytest.raises(InvalidToken):
            decrypt_backup(enc, str(proj_b))

    def test_corrupt_data_raises(self, project):
        """Truncated/corrupted ciphertext raises InvalidToken."""
        data = b"payload"
        enc = encrypt_backup(data, str(project))
        with pytest.raises(InvalidToken):
            decrypt_backup(enc[:len(enc) // 2], str(project))


# ── backup_path_for ──────────────────────────────────────────────


class TestBackupPathFor:
    def test_format(self, tmp_path):
        path = backup_path_for(str(tmp_path), "20260225_143000")
        assert path.endswith(".enc")
        assert "20260225_143000" in path
        slug = _project_slug(str(tmp_path))
        assert slug in path


# ── create_backup (encrypted) ───────────────────────────────────


class TestCreateBackup:
    def test_produces_enc_file(self, project):
        """create_backup returns a .enc file path, not a directory."""
        bp = create_backup(str(project), external=True)
        assert bp.endswith(".enc")
        assert os.path.isfile(bp)
        assert not os.path.isdir(bp)

    def test_enc_file_not_readable_as_text(self, project):
        """The .enc file is binary — reading as text yields no secrets."""
        bp = create_backup(str(project), external=True)
        raw = open(bp, "rb").read()
        # The original secret should not appear in the encrypted blob
        assert b"s3cret" not in raw
        assert b"sk-proj" not in raw

    def test_file_permissions(self, project):
        """Encrypted backup file should be 0o600."""
        bp = create_backup(str(project), external=True)
        mode = stat.S_IMODE(os.stat(bp).st_mode)
        assert mode == 0o600

    def test_legacy_plaintext_still_works(self, project):
        """external=False creates a legacy directory backup."""
        bp = create_backup(str(project), external=False)
        assert os.path.isdir(bp)
        # Should contain actual file content (plaintext)
        config = os.path.join(bp, "src", "config.py")
        assert os.path.isfile(config)
        assert "s3cret" in open(config).read()

    def test_respects_mcpignore(self, project_with_ignore):
        """Files excluded by .mcpignore should not be in the backup."""
        bp = create_backup(str(project_with_ignore), external=True)
        # Decrypt and inspect tar contents
        raw = open(bp, "rb").read()
        dec = decrypt_backup(raw, str(project_with_ignore))
        buf = io.BytesIO(dec)
        with tarfile.open(fileobj=buf, mode="r:gz") as tar:
            names = [m.name for m in tar.getmembers()]
        assert "README.md" not in names
        assert "src/config.py" in names


# ── restore_from_backup ─────────────────────────────────────────


class TestRestoreFromBackup:
    def test_round_trip(self, project):
        """Create encrypted backup → delete files → restore → verify."""
        original = (project / "src" / "config.py").read_text()
        bp = create_backup(str(project), external=True)

        # Destroy the original
        (project / "src" / "config.py").write_text("CORRUPTED")

        # Restore
        restored, skipped = restore_from_backup(bp, str(project))
        assert restored >= 1
        assert skipped == 0

        # Verify content
        assert (project / "src" / "config.py").read_text() == original

    def test_dry_run(self, project):
        """Dry run counts files without writing."""
        bp = create_backup(str(project), external=True)
        (project / "src" / "config.py").write_text("CORRUPTED")

        restored, skipped = restore_from_backup(bp, str(project), dry_run=True)
        assert restored >= 1
        # File should still be corrupted (dry run)
        assert (project / "src" / "config.py").read_text() == "CORRUPTED"

    def test_legacy_directory_restore(self, project):
        """Legacy plaintext directory backup still restores correctly."""
        original = (project / "src" / "config.py").read_text()
        bp = create_backup(str(project), external=False)

        (project / "src" / "config.py").write_text("CORRUPTED")

        restored, skipped = restore_from_backup(bp, str(project))
        assert restored >= 1
        assert (project / "src" / "config.py").read_text() == original

    def test_missing_backup_returns_zero(self, project):
        """Non-existent backup path returns (0, 0)."""
        restored, skipped = restore_from_backup("/nonexistent", str(project))
        assert (restored, skipped) == (0, 0)

    def test_path_traversal_blocked(self, project):
        """Tar members with .. in name are skipped."""
        # Manually craft a malicious tar
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo(name="../../../etc/evil.txt")
            info.size = 4
            tar.addfile(info, io.BytesIO(b"evil"))
            info2 = tarfile.TarInfo(name="safe.txt")
            info2.size = 4
            tar.addfile(info2, io.BytesIO(b"good"))

        enc = encrypt_backup(buf.getvalue(), str(project))
        enc_path = str(project / "test.enc")
        with open(enc_path, "wb") as f:
            f.write(enc)

        restored, skipped = restore_from_backup(enc_path, str(project))
        assert skipped == 1  # ../../../etc/evil.txt blocked
        assert restored == 1  # safe.txt restored
        assert not os.path.exists("/etc/evil.txt")


# ── cleanup_backup ───────────────────────────────────────────────


class TestCleanupBackup:
    def test_removes_enc_file(self, project):
        bp = create_backup(str(project), external=True)
        assert os.path.isfile(bp)
        cleanup_backup(bp)
        assert not os.path.exists(bp)

    def test_removes_legacy_dir(self, project):
        bp = create_backup(str(project), external=False)
        assert os.path.isdir(bp)
        cleanup_backup(bp)
        assert not os.path.exists(bp)

    def test_missing_path_no_error(self):
        """Cleaning up a non-existent path is a no-op."""
        cleanup_backup("/nonexistent/path.enc")
        cleanup_backup("/nonexistent/dir/")


# ── list_backups ─────────────────────────────────────────────────


class TestListBackups:
    def test_empty(self, tmp_path):
        assert list_backups(str(tmp_path)) == []

    def test_encrypted_backup_listed(self, project):
        bp = create_backup(str(project), external=True)
        backups = list_backups(str(project))
        assert len(backups) >= 1
        assert backups[0]["format"] == "encrypted"
        assert backups[0]["path"] == bp
        assert backups[0]["size"] > 0

    def test_mixed_formats(self, project):
        """Both encrypted and legacy backups appear in listing."""
        bp_legacy = create_backup(str(project), external=False)
        # Manually place the legacy dir where list_backups looks
        # (list_backups looks in ~/.cloakmcp/backups/<slug>/)
        slug = _project_slug(str(project))
        slug_dir = os.path.join(BACKUPS_DIR, slug)
        os.makedirs(slug_dir, exist_ok=True)
        legacy_dest = os.path.join(slug_dir, "20200101_000000")
        if os.path.isdir(bp_legacy):
            shutil.copytree(bp_legacy, legacy_dest)

        bp_enc = create_backup(str(project), external=True)

        backups = list_backups(str(project))
        formats = {b["format"] for b in backups}
        assert "encrypted" in formats
        assert "legacy_plaintext" in formats

        # Cleanup
        shutil.rmtree(legacy_dest, ignore_errors=True)


# ── Permission hardening ─────────────────────────────────────────


class TestPermissions:
    def test_ensure_dirs_sets_0700(self, monkeypatch, tmp_path):
        """_ensure_dirs sets 0o700 on all managed directories."""
        home = tmp_path / ".cloakmcp"
        monkeypatch.setattr("cloakmcp.storage.DEFAULT_HOME", str(home))
        monkeypatch.setattr("cloakmcp.storage.VAULTS_DIR", str(home / "vaults"))
        monkeypatch.setattr("cloakmcp.storage.KEYS_DIR", str(home / "keys"))
        monkeypatch.setattr("cloakmcp.storage.BACKUPS_DIR", str(home / "backups"))

        _ensure_dirs()

        for d in [home, home / "vaults", home / "keys", home / "backups"]:
            mode = stat.S_IMODE(os.stat(d).st_mode)
            assert mode == 0o700, f"{d} has mode {oct(mode)}"
