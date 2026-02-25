from __future__ import annotations
import base64
import json
import os
import hashlib
import hmac
import sys
from typing import Dict, Optional
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes

DEFAULT_HOME = os.path.join(os.path.expanduser("~"), ".cloakmcp")
VAULTS_DIR = os.path.join(DEFAULT_HOME, "vaults")
KEYS_DIR = os.path.join(DEFAULT_HOME, "keys")
BACKUPS_DIR = os.path.join(DEFAULT_HOME, "backups")

# Tier 1 key wrapping constants
_KEY_HEADER = b"CLOAKKEY1\n"
_SCRYPT_N = 2**17  # ~128 MiB memory, ~0.5s
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_SALT_LEN = 32


def _ensure_dirs() -> None:
    for d in (DEFAULT_HOME, VAULTS_DIR, KEYS_DIR, BACKUPS_DIR):
        os.makedirs(d, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except PermissionError:
            pass


def _verify_permissions(path: str, expected: int) -> bool:
    """Check file permissions, fix if wrong, return True if correction was needed."""
    try:
        stat = os.stat(path)
        actual = stat.st_mode & 0o777
        if actual != expected:
            os.chmod(path, expected)
            print(
                f"[CloakMCP] WARNING: Permissions on {path} were {oct(actual)}, "
                f"corrected to {oct(expected)}.",
                file=sys.stderr,
            )
            return True
    except (OSError, PermissionError):
        pass
    return False


def _project_slug(project_root: str) -> str:
    p = os.path.abspath(project_root)
    return hashlib.sha256(p.encode("utf-8")).hexdigest()[:16]

def _key_path(slug: str) -> str:
    return os.path.join(KEYS_DIR, f"{slug}.key")

def _vault_path(slug: str) -> str:
    return os.path.join(VAULTS_DIR, f"{slug}.vault")


# ── Tier 1: Passphrase-wrapped keys (scrypt) ─────────────────────


def _get_passphrase() -> Optional[str]:
    """Read passphrase from CLOAK_PASSPHRASE env var. Returns None if unset."""
    val = os.environ.get("CLOAK_PASSPHRASE")
    if val and val.strip():
        return val.strip()
    return None


def _derive_wrapping_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible wrapping key from a passphrase via scrypt."""
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
    )
    raw = kdf.derive(passphrase.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


def _detect_key_format(data: bytes) -> str:
    """Detect key file format. Returns 'wrapped' or 'raw'."""
    if data.startswith(_KEY_HEADER):
        return "wrapped"
    return "raw"


def _wrap_key(raw_key: bytes, passphrase: str) -> bytes:
    """Wrap a raw Fernet key with a passphrase-derived key.

    Returns bytes in the wrapped format:
        CLOAKKEY1\\n
        <hex-encoded 32-byte salt>\\n
        <Fernet-encrypted raw key>\\n
    """
    salt = os.urandom(_SCRYPT_SALT_LEN)
    wrapping_key = _derive_wrapping_key(passphrase, salt)
    encrypted = Fernet(wrapping_key).encrypt(raw_key)
    return _KEY_HEADER + salt.hex().encode() + b"\n" + encrypted + b"\n"


def _unwrap_key(data: bytes, passphrase: str) -> bytes:
    """Unwrap a passphrase-wrapped key file.

    Args:
        data: Full content of the wrapped key file (starts with CLOAKKEY1).
        passphrase: The passphrase used to wrap.

    Returns:
        The raw Fernet key bytes.

    Raises:
        InvalidToken: Wrong passphrase or corrupt key file.
        ValueError: Malformed key file.
    """
    if not data.startswith(_KEY_HEADER):
        raise ValueError("Not a wrapped key file (missing CLOAKKEY1 header)")
    rest = data[len(_KEY_HEADER):]
    lines = rest.split(b"\n", 1)
    if len(lines) < 2:
        raise ValueError("Malformed wrapped key file: missing salt or ciphertext")
    salt_hex = lines[0].strip()
    encrypted = lines[1].strip()
    try:
        salt = bytes.fromhex(salt_hex.decode("ascii"))
    except (ValueError, UnicodeDecodeError) as e:
        raise ValueError(f"Malformed wrapped key file: invalid salt: {e}")
    wrapping_key = _derive_wrapping_key(passphrase, salt)
    return Fernet(wrapping_key).decrypt(encrypted)


def _gen_keyfile(path: str, passphrase: Optional[str] = None) -> bytes:
    """Generate a new Fernet key and write to disk.

    If passphrase is provided, the key is wrapped (Tier 1).
    Otherwise, raw base64 is written (Tier 0).

    Returns the raw (unwrapped) key.
    """
    key = Fernet.generate_key()
    if passphrase is None:
        passphrase = _get_passphrase()
    if passphrase:
        data = _wrap_key(key, passphrase)
    else:
        data = key
    with open(path, "wb") as f:
        f.write(data)
    try:
        os.chmod(path, 0o600)
    except PermissionError:
        pass
    return key


def _load_key(path: str) -> bytes:
    """Load a key file, auto-detecting format (raw or wrapped).

    For wrapped keys, requires CLOAK_PASSPHRASE env var.

    Returns the raw Fernet key bytes.

    Raises:
        RuntimeError: Wrapped key but no passphrase available.
        InvalidToken: Wrong passphrase.
    """
    _verify_permissions(path, 0o600)
    with open(path, "rb") as f:
        data = f.read()
    fmt = _detect_key_format(data)
    if fmt == "raw":
        return data.strip()
    # Wrapped key — need passphrase
    passphrase = _get_passphrase()
    if not passphrase:
        raise RuntimeError(
            f"Key file {path} is passphrase-wrapped (CLOAKKEY1 format). "
            "Set CLOAK_PASSPHRASE environment variable to unlock."
        )
    return _unwrap_key(data, passphrase)


def wrap_keyfile(project_root: str, passphrase: Optional[str] = None) -> str:
    """Wrap an existing raw key file with a passphrase (Tier 0 -> Tier 1).

    Args:
        project_root: Project root directory.
        passphrase: Passphrase to use. If None, reads CLOAK_PASSPHRASE.

    Returns:
        Path to the wrapped key file.

    Raises:
        RuntimeError: No passphrase, or key already wrapped.
        FileNotFoundError: No key file for this project.
    """
    _ensure_dirs()
    slug = _project_slug(project_root)
    path = _key_path(slug)
    if not os.path.exists(path):
        raise FileNotFoundError(f"No key file for project: {path}")

    with open(path, "rb") as f:
        data = f.read()

    if _detect_key_format(data) == "wrapped":
        raise RuntimeError(f"Key file is already wrapped: {path}")

    if passphrase is None:
        passphrase = _get_passphrase()
    if not passphrase:
        raise RuntimeError(
            "No passphrase provided. Set CLOAK_PASSPHRASE environment variable."
        )

    raw_key = data.strip()
    wrapped = _wrap_key(raw_key, passphrase)

    # Verify before writing: unwrap must produce the same raw key
    verify = _unwrap_key(wrapped, passphrase)
    if verify != raw_key:
        raise RuntimeError("Wrap verification failed: unwrapped key does not match")

    with open(path, "wb") as f:
        f.write(wrapped)
    try:
        os.chmod(path, 0o600)
    except PermissionError:
        pass
    return path


def unwrap_keyfile(project_root: str, passphrase: Optional[str] = None) -> str:
    """Unwrap a passphrase-wrapped key file back to raw (Tier 1 -> Tier 0).

    Args:
        project_root: Project root directory.
        passphrase: Passphrase to use. If None, reads CLOAK_PASSPHRASE.

    Returns:
        Path to the unwrapped key file.

    Raises:
        RuntimeError: No passphrase, or key not wrapped.
        InvalidToken: Wrong passphrase.
    """
    _ensure_dirs()
    slug = _project_slug(project_root)
    path = _key_path(slug)
    if not os.path.exists(path):
        raise FileNotFoundError(f"No key file for project: {path}")

    with open(path, "rb") as f:
        data = f.read()

    if _detect_key_format(data) == "raw":
        raise RuntimeError(f"Key file is already raw (unwrapped): {path}")

    if passphrase is None:
        passphrase = _get_passphrase()
    if not passphrase:
        raise RuntimeError(
            "No passphrase provided. Set CLOAK_PASSPHRASE environment variable."
        )

    raw_key = _unwrap_key(data, passphrase)

    with open(path, "wb") as f:
        f.write(raw_key)
    try:
        os.chmod(path, 0o600)
    except PermissionError:
        pass
    return path


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
