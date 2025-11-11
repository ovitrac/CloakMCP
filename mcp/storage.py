from __future__ import annotations
import json
import os
import hashlib
from typing import Dict, Optional
from cryptography.fernet import Fernet

DEFAULT_HOME = os.path.join(os.path.expanduser("~"), ".cloakmcp")
VAULTS_DIR = os.path.join(DEFAULT_HOME, "vaults")
KEYS_DIR = os.path.join(DEFAULT_HOME, "keys")

def _ensure_dirs() -> None:
    os.makedirs(VAULTS_DIR, exist_ok=True)
    os.makedirs(KEYS_DIR, exist_ok=True)

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

class Vault:
    """Encrypted mapping of tag -> secret for a project. Lives outside repo."""
    def __init__(self, project_root: str) -> None:
        _ensure_dirs()
        self.slug = _project_slug(project_root)
        self.key_path = _key_path(self.slug)
        self.vault_path = _vault_path(self.slug)
        if not os.path.exists(self.key_path):
            _gen_keyfile(self.key_path)
        self.fernet = Fernet(_load_key(self.key_path))
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
        h = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12]
        tag = f"{prefix}-{h}"
        if tag not in self._data:
            self._data[tag] = secret
            self._write()
        return tag

    def secret_for(self, tag: str) -> Optional[str]:
        return self._data.get(tag)
