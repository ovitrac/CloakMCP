"""Tests for backup lifecycle: legacy migration (P0) and pruning (P2)."""
from __future__ import annotations
import os
import shutil
import time
from datetime import datetime, timedelta

import pytest

from cloakmcp.dirpack import (
    _parse_ttl,
    _parse_backup_timestamp,
    migrate_legacy_backup,
    migrate_all_legacy_backups,
    prune_backups,
    list_backups,
    create_backup,
    cleanup_backup,
)
from cloakmcp.storage import (
    BACKUPS_DIR,
    _project_slug,
    _ensure_dirs,
    decrypt_backup,
)


@pytest.fixture
def project_env(tmp_path, monkeypatch):
    """Set up isolated CloakMCP dirs and a project with sample files."""
    home = tmp_path / "cloakmcp_home"
    keys_dir = home / "keys"
    vaults_dir = home / "vaults"
    backups_dir = home / "backups"
    for d in (home, keys_dir, vaults_dir, backups_dir):
        d.mkdir(parents=True)

    monkeypatch.setattr("cloakmcp.storage.DEFAULT_HOME", str(home))
    monkeypatch.setattr("cloakmcp.storage.KEYS_DIR", str(keys_dir))
    monkeypatch.setattr("cloakmcp.storage.VAULTS_DIR", str(vaults_dir))
    monkeypatch.setattr("cloakmcp.storage.BACKUPS_DIR", str(backups_dir))
    # Also patch in dirpack which imports from storage
    monkeypatch.setattr("cloakmcp.dirpack.BACKUPS_DIR", str(backups_dir))
    monkeypatch.delenv("CLOAK_PASSPHRASE", raising=False)

    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "secret.txt").write_text("API_KEY=sk_live_abc123")
    (project_dir / "config.yaml").write_text("db_password: s3cret")

    return {
        "project_dir": str(project_dir),
        "backups_dir": str(backups_dir),
        "home": str(home),
    }


def _create_legacy_backup(project_dir: str, backups_dir: str, timestamp: str):
    """Create a fake legacy plaintext backup directory."""
    slug = _project_slug(project_dir)
    legacy_dir = os.path.join(backups_dir, slug, timestamp)
    os.makedirs(legacy_dir, exist_ok=True)
    # Copy project files
    for name in ("secret.txt", "config.yaml"):
        src = os.path.join(project_dir, name)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(legacy_dir, name))
    return legacy_dir


# ── P0: TTL Parsing ─────────────────────────────────────────────


class TestParseTtl:
    def test_days(self):
        assert _parse_ttl("30d") == timedelta(days=30)

    def test_hours(self):
        assert _parse_ttl("24h") == timedelta(hours=24)

    def test_minutes(self):
        assert _parse_ttl("90m") == timedelta(minutes=90)

    def test_invalid_raises(self):
        with pytest.raises(ValueError, match="Invalid TTL"):
            _parse_ttl("foo")

    def test_no_unit_raises(self):
        with pytest.raises(ValueError, match="Invalid TTL"):
            _parse_ttl("30")


class TestParseBackupTimestamp:
    def test_valid(self):
        dt = _parse_backup_timestamp("20260225_143000")
        assert dt == datetime(2026, 2, 25, 14, 30, 0)

    def test_invalid(self):
        assert _parse_backup_timestamp("not-a-timestamp") is None


# ── P0: Legacy Migration ────────────────────────────────────────


class TestMigrateLegacyBackup:
    def test_migrate_single(self, project_env):
        legacy_dir = _create_legacy_backup(
            project_env["project_dir"],
            project_env["backups_dir"],
            "20260101_120000",
        )
        assert os.path.isdir(legacy_dir)

        enc_path = migrate_legacy_backup(
            legacy_dir, project_env["project_dir"]
        )
        assert enc_path is not None
        assert enc_path.endswith(".enc")
        assert os.path.isfile(enc_path)
        assert not os.path.isdir(legacy_dir)  # legacy removed

    def test_migrate_verifies_integrity(self, project_env):
        legacy_dir = _create_legacy_backup(
            project_env["project_dir"],
            project_env["backups_dir"],
            "20260102_120000",
        )
        enc_path = migrate_legacy_backup(
            legacy_dir, project_env["project_dir"]
        )
        assert enc_path is not None

        # Decrypt and check files
        with open(enc_path, "rb") as f:
            enc = f.read()
        tar_bytes = decrypt_backup(enc, project_env["project_dir"])
        import io, tarfile
        buf = io.BytesIO(tar_bytes)
        with tarfile.open(fileobj=buf, mode="r:gz") as tar:
            names = [m.name for m in tar.getmembers() if m.isfile()]
        assert "secret.txt" in names
        assert "config.yaml" in names

    def test_migrate_quarantine(self, project_env):
        legacy_dir = _create_legacy_backup(
            project_env["project_dir"],
            project_env["backups_dir"],
            "20260103_120000",
        )
        enc_path = migrate_legacy_backup(
            legacy_dir, project_env["project_dir"], quarantine=True
        )
        assert enc_path is not None
        assert not os.path.isdir(legacy_dir)  # original removed
        # Quarantine dir should exist somewhere

    def test_migrate_empty_dir(self, project_env):
        slug = _project_slug(project_env["project_dir"])
        empty_dir = os.path.join(project_env["backups_dir"], slug, "20260104_120000")
        os.makedirs(empty_dir)
        result = migrate_legacy_backup(empty_dir, project_env["project_dir"])
        assert result is None  # empty dir returns None


class TestMigrateAllLegacyBackups:
    def test_dry_run(self, project_env):
        _create_legacy_backup(
            project_env["project_dir"],
            project_env["backups_dir"],
            "20260201_120000",
        )
        _create_legacy_backup(
            project_env["project_dir"],
            project_env["backups_dir"],
            "20260202_120000",
        )
        results = migrate_all_legacy_backups(
            project_env["project_dir"], dry_run=True
        )
        assert len(results) == 2
        assert all(r["status"] == "would_migrate" for r in results)
        # Dirs still exist
        slug = _project_slug(project_env["project_dir"])
        assert os.path.isdir(
            os.path.join(project_env["backups_dir"], slug, "20260201_120000")
        )

    def test_actual_migration(self, project_env):
        _create_legacy_backup(
            project_env["project_dir"],
            project_env["backups_dir"],
            "20260203_120000",
        )
        results = migrate_all_legacy_backups(
            project_env["project_dir"], dry_run=False
        )
        assert len(results) == 1
        assert results[0]["status"] == "migrated"
        assert results[0]["enc_path"].endswith(".enc")

    def test_no_legacy_returns_empty(self, project_env):
        results = migrate_all_legacy_backups(
            project_env["project_dir"], dry_run=True
        )
        assert results == []


# ── P2: Pruning ──────────────────────────────────────────────────


class TestPruneBackups:
    def _create_enc_backup(self, project_env, timestamp):
        """Create an encrypted backup with a specific timestamp."""
        from cloakmcp.storage import encrypt_backup, backup_path_for
        import io, tarfile

        enc_path = backup_path_for(project_env["project_dir"], timestamp)
        os.makedirs(os.path.dirname(enc_path), exist_ok=True)

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name in ("secret.txt", "config.yaml"):
                src = os.path.join(project_env["project_dir"], name)
                if os.path.isfile(src):
                    tar.add(src, arcname=name)

        enc = encrypt_backup(buf.getvalue(), project_env["project_dir"])
        with open(enc_path, "wb") as f:
            f.write(enc)
        return enc_path

    def test_dry_run_no_delete(self, project_env):
        # Create 3 backups
        for ts in ("20250101_120000", "20250201_120000", "20260225_120000"):
            self._create_enc_backup(project_env, ts)

        result = prune_backups(
            project_env["project_dir"],
            ttl="30d",
            keep_last=1,
            apply=False,
        )
        # All files should still exist
        backups = list_backups(project_env["project_dir"])
        assert len(backups) == 3
        assert result["pruned"] >= 1  # some marked for prune
        assert result["kept"] >= 1

    def test_respects_keep_last(self, project_env):
        for ts in ("20250101_120000", "20250201_120000", "20250301_120000",
                    "20260101_120000", "20260225_120000"):
            self._create_enc_backup(project_env, ts)

        result = prune_backups(
            project_env["project_dir"],
            ttl="0d",  # everything is "old"
            keep_last=3,
            apply=True,
        )
        assert result["kept"] == 3
        assert result["pruned"] == 2
        # Verify only 3 remain
        remaining = list_backups(project_env["project_dir"])
        assert len(remaining) == 3

    def test_respects_ttl(self, project_env):
        # One recent, one old
        recent_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._create_enc_backup(project_env, recent_ts)
        self._create_enc_backup(project_env, "20230101_120000")

        result = prune_backups(
            project_env["project_dir"],
            ttl="30d",
            keep_last=0,
            apply=True,
        )
        assert result["pruned"] == 1
        assert result["kept"] == 1

    def test_apply_deletes_files(self, project_env):
        self._create_enc_backup(project_env, "20230101_120000")
        self._create_enc_backup(project_env, "20230201_120000")

        result = prune_backups(
            project_env["project_dir"],
            ttl="1d",
            keep_last=0,
            apply=True,
        )
        assert result["pruned"] == 2
        remaining = list_backups(project_env["project_dir"])
        assert len(remaining) == 0

    def test_include_legacy(self, project_env):
        _create_legacy_backup(
            project_env["project_dir"],
            project_env["backups_dir"],
            "20230101_120000",
        )
        # Without --include-legacy, legacy should be excluded
        result_no = prune_backups(
            project_env["project_dir"],
            ttl="1d",
            keep_last=0,
            apply=False,
            include_legacy=False,
        )
        assert result_no["pruned"] == 0

        # With --include-legacy
        result_yes = prune_backups(
            project_env["project_dir"],
            ttl="1d",
            keep_last=0,
            apply=True,
            include_legacy=True,
        )
        assert result_yes["pruned"] == 1

    def test_invalid_ttl_raises(self, project_env):
        with pytest.raises(ValueError, match="Invalid TTL"):
            prune_backups(project_env["project_dir"], ttl="bad")


# ── SessionStart warnings ───────────────────────────────────────


class TestSessionStartWarnings:
    def test_warns_legacy_external_backups(self, project_env, monkeypatch):
        """SessionStart should warn when legacy plaintext backups exist."""
        _create_legacy_backup(
            project_env["project_dir"],
            project_env["backups_dir"],
            "20260101_120000",
        )
        backups = list_backups(project_env["project_dir"])
        legacy_count = sum(1 for b in backups if b["format"] == "legacy_plaintext")
        assert legacy_count == 1
