from __future__ import annotations
import base64
import json
import os
import hashlib
import hmac
from typing import Dict, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

DEFAULT_HOME = os.path.join(os.path.expanduser("~"), ".cloakmcp")
VAULTS_DIR = os.path.join(DEFAULT_HOME, "vaults")
KEYS_DIR = os.path.join(DEFAULT_HOME, "keys")
BACKUPS_DIR = os.path.join(DEFAULT_HOME, "backups")

def _ensure_dirs() -> None:
    for d in (DEFAULT_HOME, VAULTS_DIR, KEYS_DIR, BACKUPS_DIR):
        os.makedirs(d, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except PermissionError:
            pass

def _project_slug(project_root: str) -> str:
    p = os.path.abspath(project_root)
    return hashlib.sha256(p.encode("utf-8")).hexdigest()[:16]

def _key_path(slug: str) -> str:
    return os.path.join(KEYS_DIR, f"{slug}.key")

def _vault_path(slug: str) -> str:
    return os.path.join(VAULTS_DIR, f"{slug}.vault")

def _gen_keyfile(path: str) -> bytes:
    key = Fernet.generate_key()
    with open(path, "wb") as f:
        f.write(key)
    try:
        os.chmod(path, 0o600)
    except PermissionError:
        pass
    return key

def _load_key(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read().strip()


# ── Backup encryption (HKDF-derived key) ────────────────────────


def _derive_backup_key(project_key: bytes, slug: str) -> bytes:
    """Derive a Fernet-compatible backup key via HKDF-SHA256.

    Key separation: the vault uses the raw project Fernet key; backups use
    an HKDF-derived subkey.  Compromising one does not expose the other.

    Args:
        project_key: Raw key file content (base64-encoded 32 bytes).
        slug: Project slug (SHA-256 of absolute path, first 16 hex chars).

    Returns:
        URL-safe base64-encoded 32-byte key suitable for ``Fernet()``.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"cloakmcp-backup",
        info=slug.encode("utf-8"),
    )
    raw = hkdf.derive(project_key)
    return base64.urlsafe_b64encode(raw)


def _backup_fernet(project_root: str) -> Fernet:
    """Return a Fernet instance keyed for backup encryption."""
    _ensure_dirs()
    slug = _project_slug(project_root)
    key_path = _key_path(slug)
    if not os.path.exists(key_path):
        _gen_keyfile(key_path)
    project_key = _load_key(key_path)
    backup_key = _derive_backup_key(project_key, slug)
    return Fernet(backup_key)


def encrypt_backup(tar_bytes: bytes, project_root: str) -> bytes:
    """Encrypt a tar.gz byte stream using the HKDF-derived backup key."""
    return _backup_fernet(project_root).encrypt(tar_bytes)


def decrypt_backup(enc_bytes: bytes, project_root: str) -> bytes:
    """Decrypt a ``.enc`` backup file using the HKDF-derived backup key."""
    return _backup_fernet(project_root).decrypt(enc_bytes)


def backup_path_for(project_root: str, timestamp: str) -> str:
    """Return the canonical path for an encrypted backup file.

    Format: ``~/.cloakmcp/backups/<slug>/<timestamp>.enc``
    """
    slug = _project_slug(project_root)
    return os.path.join(BACKUPS_DIR, slug, f"{timestamp}.enc")


class Vault:
    """Encrypted mapping of tag -> secret for a project. Lives outside repo."""
    def __init__(self, project_root: str) -> None:
        _ensure_dirs()
        self.slug = _project_slug(project_root)
        self.key_path = _key_path(self.slug)
        self.vault_path = _vault_path(self.slug)
        if not os.path.exists(self.key_path):
            _gen_keyfile(self.key_path)
        self._vault_key = _load_key(self.key_path)
        self.fernet = Fernet(self._vault_key)
        self._data: Dict[str, str] = {}
        if os.path.exists(self.vault_path):
            self._data = self._read()

    def _read(self) -> Dict[str, str]:
        with open(self.vault_path, "rb") as f:
            enc = f.read()
        if not enc:
            return {}
        raw = self.fernet.decrypt(enc)
        return json.loads(raw.decode("utf-8"))

    def _write(self) -> None:
        raw = json.dumps(self._data, ensure_ascii=False).encode("utf-8")
        enc = self.fernet.encrypt(raw)
        with open(self.vault_path, "wb") as f:
            f.write(enc)
        try:
            os.chmod(self.vault_path, 0o600)
        except PermissionError:
            pass

    def tag_for(self, secret: str, prefix: str) -> str:
        """Generate HMAC-based deterministic tag for a secret.

        Uses HMAC-SHA256 with the vault key to ensure tags cannot be
        brute-forced without access to the vault environment.

        Args:
            secret: The secret value to tag
            prefix: Tag prefix (e.g., "TAG", "SEC")

        Returns:
            Deterministic tag like "TAG-2f1a8e3c9b12"
        """
        # HMAC-SHA256 with vault key (prevents brute-force attacks)
        h = hmac.new(
            self._vault_key,
            secret.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()[:12]
        tag = f"{prefix}-{h}"
        if tag not in self._data:
            self._data[tag] = secret
            self._write()
        return tag

    def secret_for(self, tag: str) -> Optional[str]:
        return self._data.get(tag)

    def export_to_json(self, output_path: str) -> None:
        """Export vault contents to an encrypted JSON file."""
        raw = json.dumps(self._data, ensure_ascii=False, indent=2).encode("utf-8")
        enc = self.fernet.encrypt(raw)
        with open(output_path, "wb") as f:
            f.write(enc)
        try:
            os.chmod(output_path, 0o600)
        except PermissionError:
            pass

    def import_from_json(self, input_path: str) -> None:
        """Import vault contents from an encrypted JSON file."""
        with open(input_path, "rb") as f:
            enc = f.read()
        raw = self.fernet.decrypt(enc)
        self._data = json.loads(raw.decode("utf-8"))
        self._write()

    def get_stats(self) -> Dict[str, int]:
        """Get vault statistics."""
        return {
            "total_secrets": len(self._data),
            "unique_tags": len(set(self._data.keys())),
        }
