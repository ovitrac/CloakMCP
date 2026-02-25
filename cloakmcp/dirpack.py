from __future__ import annotations
import fnmatch
import hashlib
import io
import os
import re
import shutil
import tarfile
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from .policy import Policy
from .storage import (
    Vault, BACKUPS_DIR, _project_slug,
    encrypt_backup, decrypt_backup, backup_path_for,
)
from .filepack import TAG_RE, pack_text, unpack_text

IGNORE_FILE = ".mcpignore"
BACKUP_DIR = ".cloak-backups"

def load_ignores(root: str) -> List[str]:
    path = os.path.join(root, IGNORE_FILE)
    globs: List[str] = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if ln and not ln.startswith("#"):
                    globs.append(ln)
    # Always ignore backup directory
    if BACKUP_DIR not in globs:
        globs.append(f"{BACKUP_DIR}/")
    return globs

def iter_files(
    root: str,
    globs: List[str],
    on_ignored: Optional[Callable[[str], None]] = None,
) -> Iterable[str]:
    """Yield absolute paths of files under *root* that are not ignored.

    Args:
        root: Directory to walk.
        globs: Ignore patterns loaded from .mcpignore.
        on_ignored: Optional callback invoked with the absolute path of every
                    file skipped by an ignore rule (not called for pruned dirs).
    """
    for dirpath, dirnames, filenames in os.walk(root):
        rp = os.path.relpath(dirpath, root)
        skip_dir = any(g.endswith("/") and fnmatch.fnmatch(rp + "/", g) for g in globs)
        if skip_dir:
            dirnames[:] = []
            continue
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if any(fnmatch.fnmatch(rel, g) for g in globs if not g.endswith("/")):
                if on_ignored is not None:
                    on_ignored(full)
                continue
            yield full

def create_backup(root: str, external: bool = True) -> str:
    """Create an encrypted, timestamped backup of project files.

    Files are collected into a gzip-compressed tar archive, then encrypted
    using an HKDF-derived backup key (separate from the vault key).

    Args:
        root: Project root directory
        external: If True (default), store encrypted backup outside the
                  project tree as ``~/.cloakmcp/backups/<slug>/<ts>.enc``.
                  If False, use legacy in-tree ``.cloak-backups/<ts>/``
                  (plaintext directory — deprecated, for testing only).

    Returns:
        Path to the created ``.enc`` file (or backup directory if legacy).
    """
    import sys
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if not external:
        # Legacy plaintext directory backup (deprecated)
        bp = os.path.join(root, BACKUP_DIR, timestamp)
        os.makedirs(bp, exist_ok=True)
        ignores = load_ignores(root)
        n = 0
        for path in iter_files(root, ignores):
            rel = os.path.relpath(path, root)
            dst = os.path.join(bp, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            try:
                shutil.copy2(path, dst)
                n += 1
            except (OSError, IOError, PermissionError) as e:
                print(f"Warning: Failed to backup {rel}: {e}", file=sys.stderr)
        print(f"Backup created: {bp} ({n} files, plaintext)", file=sys.stderr)
        return bp

    # ── Encrypted backup (.enc) ──────────────────────────────────
    enc_path = backup_path_for(root, timestamp)
    os.makedirs(os.path.dirname(enc_path), exist_ok=True)
    try:
        os.chmod(os.path.dirname(enc_path), 0o700)
    except PermissionError:
        pass

    ignores = load_ignores(root)
    files_backed_up = 0

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path in iter_files(root, ignores):
            rel = os.path.relpath(path, root)
            try:
                tar.add(path, arcname=rel)
                files_backed_up += 1
            except (OSError, IOError, PermissionError) as e:
                print(f"Warning: Failed to backup {rel}: {e}", file=sys.stderr)

    enc = encrypt_backup(buf.getvalue(), root)

    # Atomic write with restrictive permissions
    tmp = enc_path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(enc)
    try:
        os.chmod(tmp, 0o600)
    except PermissionError:
        pass
    os.replace(tmp, enc_path)

    print(
        f"Backup created: {enc_path} ({files_backed_up} files, encrypted)",
        file=sys.stderr,
    )
    return enc_path


def cleanup_backup(backup_path: str) -> None:
    """Remove a backup (encrypted file or legacy directory) after session end."""
    if os.path.isfile(backup_path):
        try:
            os.remove(backup_path)
        except FileNotFoundError:
            pass
    elif os.path.isdir(backup_path):
        shutil.rmtree(backup_path, ignore_errors=True)


def restore_from_backup(
    backup_path: str, project_dir: str, dry_run: bool = False
) -> Tuple[int, int]:
    """Restore files from a backup into the project directory.

    Auto-detects format: encrypted ``.enc`` file (new) or plaintext
    directory (legacy).  DESTRUCTIVE when ``dry_run=False``.

    Args:
        backup_path: Path to the ``.enc`` file or legacy backup directory
        project_dir: Project root directory to restore into
        dry_run: If True, count files only without writing

    Returns:
        (restored_count, skipped_count)
    """
    if os.path.isdir(backup_path):
        return _restore_from_backup_dir(backup_path, project_dir, dry_run)

    if not os.path.isfile(backup_path):
        return (0, 0)

    # ── Encrypted backup ─────────────────────────────────────────
    with open(backup_path, "rb") as f:
        enc = f.read()

    tar_bytes = decrypt_backup(enc, project_dir)
    buf = io.BytesIO(tar_bytes)

    restored = 0
    skipped = 0
    with tarfile.open(fileobj=buf, mode="r:gz") as tar:
        for member in tar.getmembers():
            # Security: reject absolute paths and path traversal
            if member.name.startswith("/") or ".." in member.name:
                skipped += 1
                continue
            if not member.isfile():
                continue
            if dry_run:
                restored += 1
                continue
            target = os.path.join(project_dir, member.name)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with tar.extractfile(member) as src:
                if src is not None:
                    with open(target, "wb") as dst:
                        shutil.copyfileobj(src, dst)
            restored += 1

    return (restored, skipped)


def _restore_from_backup_dir(
    backup_path: str, project_dir: str, dry_run: bool = False
) -> Tuple[int, int]:
    """Legacy restore: copy files from a plaintext backup directory."""
    restored = 0
    skipped = 0

    for dirpath, _dirnames, filenames in os.walk(backup_path):
        for name in filenames:
            src = os.path.join(dirpath, name)
            rel_path = os.path.relpath(src, backup_path)
            target = os.path.join(project_dir, rel_path)

            if dry_run:
                restored += 1
                continue

            try:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                shutil.copy2(src, target)
                restored += 1
            except OSError:
                skipped += 1

    return (restored, skipped)


def list_backups(project_root: str) -> List[Dict[str, Any]]:
    """List available backups for a project (both encrypted and legacy).

    Returns:
        List of dicts with keys: timestamp, path, format, size.
        Sorted newest-first.
    """
    slug = _project_slug(project_root)
    backup_dir = os.path.join(BACKUPS_DIR, slug)
    backups: List[Dict[str, Any]] = []

    if not os.path.isdir(backup_dir):
        return backups

    for entry in sorted(os.listdir(backup_dir), reverse=True):
        full = os.path.join(backup_dir, entry)
        if entry.endswith(".enc") and os.path.isfile(full):
            ts = entry[:-4]  # strip .enc
            backups.append({
                "timestamp": ts,
                "path": full,
                "format": "encrypted",
                "size": os.path.getsize(full),
            })
        elif os.path.isdir(full):
            backups.append({
                "timestamp": entry,
                "path": full,
                "format": "legacy_plaintext",
                "size": _dir_size(full),
            })

    return backups


def _dir_size(path: str) -> int:
    """Total size of all files in a directory tree."""
    total = 0
    for dirpath, _dirnames, filenames in os.walk(path):
        for name in filenames:
            try:
                total += os.path.getsize(os.path.join(dirpath, name))
            except OSError:
                pass
    return total


def _parse_ttl(ttl_str: str) -> timedelta:
    """Parse a duration string like '7d', '30d', '24h', '90m'.

    Raises ValueError on invalid format.
    """
    match = re.match(r'^(\d+)([dhm])$', ttl_str)
    if not match:
        raise ValueError(f"Invalid TTL format: {ttl_str} (use e.g. 30d, 24h, 90m)")
    value, unit = int(match.group(1)), match.group(2)
    if unit == 'd':
        return timedelta(days=value)
    if unit == 'h':
        return timedelta(hours=value)
    return timedelta(minutes=value)


def _parse_backup_timestamp(ts_str: str) -> Optional[datetime]:
    """Parse a backup timestamp string (YYYYMMDD_HHMMSS) to datetime."""
    try:
        return datetime.strptime(ts_str, "%Y%m%d_%H%M%S")
    except ValueError:
        return None


def migrate_legacy_backup(
    legacy_dir: str, project_root: str, quarantine: bool = False
) -> Optional[str]:
    """Encrypt a single legacy plaintext backup directory into a .enc file.

    Args:
        legacy_dir: Path to legacy backup directory (e.g. ~/.cloakmcp/backups/<slug>/<ts>/)
        project_root: Project root directory (for key derivation).
        quarantine: If True, move to quarantine instead of deleting after migration.

    Returns:
        Path to the new .enc file on success, None on failure.
    """
    if not os.path.isdir(legacy_dir):
        return None

    timestamp = os.path.basename(legacy_dir)
    enc_path = backup_path_for(project_root, timestamp)

    # Build tar.gz in memory from legacy directory
    buf = io.BytesIO()
    file_hashes: Dict[str, str] = {}
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for dirpath, _dirnames, filenames in os.walk(legacy_dir):
            for name in filenames:
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, legacy_dir)
                tar.add(full, arcname=rel)
                # Record SHA-256 for verification
                h = hashlib.sha256()
                with open(full, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        h.update(chunk)
                file_hashes[rel] = h.hexdigest()

    if not file_hashes:
        # Empty directory — just remove it
        shutil.rmtree(legacy_dir, ignore_errors=True)
        return None

    # Encrypt
    enc = encrypt_backup(buf.getvalue(), project_root)

    # Atomic write
    tmp = enc_path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(enc)
    try:
        os.chmod(tmp, 0o600)
    except PermissionError:
        pass
    os.replace(tmp, enc_path)

    # Verify: decrypt and compare file hashes
    with open(enc_path, "rb") as f:
        verify_enc = f.read()
    verify_tar = decrypt_backup(verify_enc, project_root)
    verify_buf = io.BytesIO(verify_tar)
    with tarfile.open(fileobj=verify_buf, mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            extracted = tar.extractfile(member)
            if extracted is None:
                continue
            h = hashlib.sha256(extracted.read()).hexdigest()
            if file_hashes.get(member.name) != h:
                # Verification failed — remove .enc, keep legacy
                try:
                    os.remove(enc_path)
                except OSError:
                    pass
                return None

    # Verification passed — remove or quarantine legacy directory
    if quarantine:
        quarantine_dir = os.path.join(
            os.path.dirname(os.path.dirname(legacy_dir)),
            "..", "quarantine",
            os.path.basename(os.path.dirname(legacy_dir)),
            timestamp,
        )
        quarantine_dir = os.path.normpath(quarantine_dir)
        os.makedirs(os.path.dirname(quarantine_dir), exist_ok=True)
        shutil.move(legacy_dir, quarantine_dir)
    else:
        shutil.rmtree(legacy_dir, ignore_errors=True)

    return enc_path


def migrate_all_legacy_backups(
    project_root: str,
    dry_run: bool = True,
    quarantine: bool = False,
) -> List[Dict[str, Any]]:
    """Migrate all legacy plaintext backups for a project.

    Args:
        project_root: Project root directory.
        dry_run: If True, only list what would be migrated.
        quarantine: Move legacy dirs to quarantine instead of deleting.

    Returns:
        List of result dicts with keys: timestamp, status, enc_path, size.
    """
    backups = list_backups(project_root)
    legacy = [b for b in backups if b["format"] == "legacy_plaintext"]
    results: List[Dict[str, Any]] = []

    for b in legacy:
        entry: Dict[str, Any] = {
            "timestamp": b["timestamp"],
            "size": b["size"],
        }
        if dry_run:
            entry["status"] = "would_migrate"
            results.append(entry)
            continue

        enc_path = migrate_legacy_backup(
            b["path"], project_root, quarantine=quarantine
        )
        if enc_path:
            entry["status"] = "migrated"
            entry["enc_path"] = enc_path
        else:
            entry["status"] = "failed"
        results.append(entry)

    return results


def prune_backups(
    project_root: str,
    ttl: str = "30d",
    keep_last: int = 10,
    apply: bool = False,
    include_legacy: bool = False,
) -> Dict[str, Any]:
    """Prune old backups based on TTL and keep-last policy.

    Args:
        project_root: Project root directory.
        ttl: Time-to-live string (e.g. '30d', '24h').
        keep_last: Always keep the N most recent backups.
        apply: If True, actually delete. If False, dry-run.
        include_legacy: If True, also prune legacy plaintext backups.

    Returns:
        Dict with keys: pruned, kept, freed_bytes, details.
    """
    ttl_delta = _parse_ttl(ttl)
    now = datetime.now()
    backups = list_backups(project_root)

    if not include_legacy:
        backups = [b for b in backups if b["format"] != "legacy_plaintext"]

    # Backups are already sorted newest-first by list_backups()
    pruned = 0
    kept = 0
    freed_bytes = 0
    details: List[Dict[str, Any]] = []

    for i, b in enumerate(backups):
        ts = _parse_backup_timestamp(b["timestamp"])
        action = "keep"

        if i < keep_last:
            action = "keep"
        elif ts and (now - ts) > ttl_delta:
            action = "prune"
        else:
            action = "keep"

        if action == "prune":
            if apply:
                cleanup_backup(b["path"])
                freed_bytes += b.get("size", 0)
            pruned += 1
        else:
            kept += 1

        details.append({
            "timestamp": b["timestamp"],
            "format": b["format"],
            "size": b.get("size", 0),
            "action": action if not apply else ("deleted" if action == "prune" else "kept"),
        })

    return {
        "pruned": pruned,
        "kept": kept,
        "freed_bytes": freed_bytes,
        "details": details,
    }


def warn_legacy_backups(root: str) -> Optional[str]:
    """Return warning string if legacy .cloak-backups/ exists in project tree."""
    legacy_path = os.path.join(root, BACKUP_DIR)
    if os.path.isdir(legacy_path):
        return (
            "[CloakMCP] WARNING: Legacy backup directory found at "
            f"{legacy_path}. This exposes pre-redaction secrets to LLM tools. "
            "Remove it: rm -rf .cloak-backups/"
        )
    return None

def pack_dir(
    root: str,
    policy: Policy,
    prefix: str = "TAG",
    in_place: bool = True,
    dry_run: bool = False,
    backup: bool = True
) -> None:
    """Pack a directory: replace secrets by tags.

    Args:
        root: Directory to process
        policy: Policy to apply
        prefix: Tag prefix (e.g., TAG, SEC, KEY)
        in_place: Modify files in place (always True for now)
        dry_run: Preview changes without modifying files
        backup: Create backup before modifications (recommended)
    """
    import sys
    vault = Vault(root)
    ignores = load_ignores(root)
    error_count = 0
    ignored_count = 0
    processed_count = 0
    scanned_count = 0
    files_to_modify: List[Tuple[str, int]] = []  # (path, match_count)

    def _count_ignored(path: str) -> None:
        nonlocal ignored_count
        ignored_count += 1

    # First pass: scan all files for secrets
    for path in iter_files(root, ignores, on_ignored=_count_ignored):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except (OSError, IOError, PermissionError) as e:
            print(f"Warning: Skipping file (read error): {path} - {e}", file=sys.stderr)
            error_count += 1
            continue
        except UnicodeDecodeError as e:
            print(f"Warning: Skipping file (encoding error): {path} - {e}", file=sys.stderr)
            error_count += 1
            continue

        scanned_count += 1
        _, count = pack_text(text, policy, vault, prefix=prefix)
        if count > 0:
            files_to_modify.append((path, count))

    if not files_to_modify:
        print(
            f"No secrets found to replace "
            f"(scanned {scanned_count}, ignored {ignored_count}).",
            file=sys.stderr,
        )
        return

    # Dry-run mode: show preview and exit
    if dry_run:
        print(f"[DRY RUN] Would modify {len(files_to_modify)} files:", file=sys.stderr)
        for path, count in files_to_modify[:20]:  # Show first 20
            rel_path = os.path.relpath(path, root)
            print(f"  {rel_path}: {count} secrets -> tags", file=sys.stderr)
        if len(files_to_modify) > 20:
            print(f"  ... and {len(files_to_modify) - 20} more files", file=sys.stderr)
        print(f"\nRun without --dry-run to apply changes.", file=sys.stderr)
        return

    # Create backup before modifications
    if backup:
        create_backup(root)

    # Second pass: modify files (re-read to get fresh content)
    for path, _ in files_to_modify:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except (OSError, IOError, PermissionError) as e:
            print(f"Warning: Skipping file (read error): {path} - {e}", file=sys.stderr)
            error_count += 1
            continue

        packed, count = pack_text(text, policy, vault, prefix=prefix)
        if count > 0 and packed != text:
            try:
                tmp = path + ".cloak.tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    f.write(packed)
                os.replace(tmp, path)
                processed_count += 1
            except (OSError, IOError, PermissionError) as e:
                print(f"Warning: Failed to write file: {path} - {e}", file=sys.stderr)
                error_count += 1
                if os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except:
                        pass

    parts = [f"{processed_count} files modified"]
    if ignored_count:
        parts.append(f"{ignored_count} ignored")
    if error_count:
        parts.append(f"{error_count} errors")
    print(f"Pack complete: {', '.join(parts)}.", file=sys.stderr)

def unpack_dir(root: str, dry_run: bool = False, backup: bool = True) -> None:
    """Unpack a directory: restore tags from vault.

    Args:
        root: Directory to process
        dry_run: Preview changes without modifying files
        backup: Create backup before modifications (recommended)
    """
    import sys
    vault = Vault(root)
    ignores = load_ignores(root)
    error_count = 0
    ignored_count = 0
    processed_count = 0
    files_to_modify: List[Tuple[str, int]] = []  # (path, tag_count)

    def _count_ignored(path: str) -> None:
        nonlocal ignored_count
        ignored_count += 1

    # First pass: scan all files for resolvable tags
    for path in iter_files(root, ignores, on_ignored=_count_ignored):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except (OSError, IOError, PermissionError) as e:
            print(f"Warning: Skipping file (read error): {path} - {e}", file=sys.stderr)
            error_count += 1
            continue
        except UnicodeDecodeError as e:
            print(f"Warning: Skipping file (encoding error): {path} - {e}", file=sys.stderr)
            error_count += 1
            continue

        # Count resolvable tags
        tag_count = 0
        for m in TAG_RE.finditer(text):
            tag = m.group(1)
            if vault.secret_for(tag) is not None:
                tag_count += 1

        if tag_count > 0:
            files_to_modify.append((path, tag_count))

    if not files_to_modify:
        print("No tags found to restore.", file=sys.stderr)
        return

    # Dry-run mode: show preview and exit
    if dry_run:
        print(f"[DRY RUN] Would modify {len(files_to_modify)} files:", file=sys.stderr)
        for path, count in files_to_modify[:20]:  # Show first 20
            rel_path = os.path.relpath(path, root)
            print(f"  {rel_path}: {count} tags -> secrets", file=sys.stderr)
        if len(files_to_modify) > 20:
            print(f"  ... and {len(files_to_modify) - 20} more files", file=sys.stderr)
        print(f"\nRun without --dry-run to apply changes.", file=sys.stderr)
        return

    # Create backup before modifications
    if backup:
        create_backup(root)

    # Second pass: modify files
    for path, _ in files_to_modify:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except (OSError, IOError, PermissionError) as e:
            print(f"Warning: Skipping file (read error): {path} - {e}", file=sys.stderr)
            error_count += 1
            continue

        unpacked, count = unpack_text(text, vault)

        if count > 0 and unpacked != text:
            try:
                tmp = path + ".cloak.tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    f.write(unpacked)
                os.replace(tmp, path)
                processed_count += 1
            except (OSError, IOError, PermissionError) as e:
                print(f"Warning: Failed to write file: {path} - {e}", file=sys.stderr)
                error_count += 1
                if os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except:
                        pass

    parts = [f"{processed_count} files modified"]
    if ignored_count:
        parts.append(f"{ignored_count} ignored")
    if error_count:
        parts.append(f"{error_count} errors")
    print(f"Unpack complete: {', '.join(parts)}.", file=sys.stderr)


# ── R4: Post-unpack verification ──────────────────────────────────


def verify_unpack(root: str) -> Dict[str, Any]:
    """Scan directory for remaining tags after unpack.

    Rescans all walkable files for TAG_RE matches and classifies them
    as resolvable (still in vault — shouldn't remain) or unresolvable
    (orphaned tags from another project/session).

    Args:
        root: Directory root to scan

    Returns:
        {
            "tags_found": int,
            "tags_resolved": int,
            "tags_unresolvable": int,
            "unresolvable_files": [(rel_path, count), ...],
        }
    """
    vault = Vault(root)
    ignores = load_ignores(root)

    tags_found = 0
    tags_resolved = 0
    tags_unresolvable = 0
    unresolvable_files: List[Tuple[str, int]] = []

    for path in iter_files(root, ignores):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except (OSError, IOError, PermissionError):
            continue

        file_unresolvable = 0
        for m in TAG_RE.finditer(text):
            tag = m.group(1)
            tags_found += 1
            if vault.secret_for(tag) is not None:
                tags_resolved += 1
            else:
                tags_unresolvable += 1
                file_unresolvable += 1

        if file_unresolvable > 0:
            rel = os.path.relpath(path, root)
            unresolvable_files.append((rel, file_unresolvable))

    return {
        "tags_found": tags_found,
        "tags_resolved": tags_resolved,
        "tags_unresolvable": tags_unresolvable,
        "unresolvable_files": unresolvable_files,
    }


# ── R5: Session manifest ─────────────────────────────────────────


def _file_sha256(path: str) -> str:
    """Compute SHA-256 hex digest for a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(root: str, ignores: List[str]) -> Dict[str, Any]:
    """Build a file manifest (sha256 hash + size) for all walkable files.

    Called after pack_dir to snapshot the project state at session start.

    Args:
        root: Project root directory
        ignores: Glob patterns to skip

    Returns:
        {
            "ts": ISO timestamp,
            "files": { rel_path: {"sha256": ..., "size": ...}, ... },
            "total_files": int,
        }
    """
    files: Dict[str, Dict[str, Any]] = {}

    for path in iter_files(root, ignores):
        try:
            rel = os.path.relpath(path, root)
            sha = _file_sha256(path)
            size = os.path.getsize(path)
            files[rel] = {"sha256": sha, "size": size}
        except (OSError, IOError, PermissionError):
            continue

    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "files": files,
        "total_files": len(files),
    }


def compute_delta(
    manifest: Dict[str, Any], root: str, ignores: List[str]
) -> Dict[str, Any]:
    """Compare current file state against a pack-time manifest.

    Identifies files that were created, deleted, or changed during the session.

    Args:
        manifest: The manifest dict from build_manifest()
        root: Project root directory
        ignores: Glob patterns to skip

    Returns:
        {
            "new_files": [rel_path, ...],
            "deleted_files": [rel_path, ...],
            "changed_files": [rel_path, ...],
            "unchanged_count": int,
        }
    """
    old_files = manifest.get("files", {})

    # Build current file set
    current_files: Dict[str, str] = {}
    for path in iter_files(root, ignores):
        try:
            rel = os.path.relpath(path, root)
            current_files[rel] = _file_sha256(path)
        except (OSError, IOError, PermissionError):
            continue

    old_set = set(old_files.keys())
    cur_set = set(current_files.keys())

    new_files = sorted(cur_set - old_set)
    deleted_files = sorted(old_set - cur_set)
    changed_files = sorted(
        f for f in (old_set & cur_set)
        if current_files[f] != old_files[f]["sha256"]
    )
    unchanged_count = len(old_set & cur_set) - len(changed_files)

    return {
        "new_files": new_files,
        "deleted_files": deleted_files,
        "changed_files": changed_files,
        "unchanged_count": unchanged_count,
    }


# ── R6: Incremental re-pack ─────────────────────────────────────


def repack_dir(
    root: str,
    policy: Policy,
    prefix: str = "TAG",
    manifest: Optional[Dict[str, Any]] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Incremental re-pack: only process new or changed files.

    Compares current file SHA-256 against packed-content hashes in the
    session manifest. Files matching the manifest are skipped (already
    packed, no changes since last pack).

    Args:
        root: Project root directory
        policy: Detection policy
        prefix: Tag prefix (e.g., TAG, SEC, KEY)
        manifest: Session manifest from build_manifest(). If None, repacks all.
        dry_run: Preview only (no file modifications)

    Returns:
        {"repacked_files": int, "skipped_files": int, "new_secrets": int}
    """
    import sys
    vault = Vault(root)
    ignores = load_ignores(root)
    manifest_files = manifest.get("files", {}) if manifest else {}

    repacked = 0
    skipped = 0
    new_secrets = 0

    for path in iter_files(root, ignores):
        rel = os.path.relpath(path, root)

        # Check manifest: skip if file hash matches (already packed, unchanged)
        if manifest_files:
            try:
                current_hash = _file_sha256(path)
                entry = manifest_files.get(rel)
                if entry and entry.get("sha256") == current_hash:
                    skipped += 1
                    continue
            except (OSError, IOError, PermissionError):
                pass

        # File is new or changed — re-pack
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except (OSError, IOError, PermissionError) as e:
            print(f"Warning: Skipping file (read error): {path} - {e}", file=sys.stderr)
            continue

        packed, count = pack_text(text, policy, vault, prefix=prefix)
        if count > 0 and packed != text:
            if not dry_run:
                tmp = path + ".cloak.tmp"
                try:
                    with open(tmp, "w", encoding="utf-8") as f:
                        f.write(packed)
                    os.replace(tmp, path)
                    repacked += 1
                    new_secrets += count
                except (OSError, IOError, PermissionError) as e:
                    print(f"Warning: Failed to write: {path} - {e}", file=sys.stderr)
                    if os.path.exists(tmp):
                        try:
                            os.remove(tmp)
                        except OSError:
                            pass
            else:
                repacked += 1
                new_secrets += count
        else:
            skipped += 1

    if not dry_run and repacked > 0:
        print(f"Repack: {repacked} files repacked, {new_secrets} new secrets", file=sys.stderr)
    elif dry_run and repacked > 0:
        print(f"[DRY RUN] Would repack {repacked} files ({new_secrets} secrets)", file=sys.stderr)

    return {"repacked_files": repacked, "skipped_files": skipped, "new_secrets": new_secrets}


def repack_file(
    path: str,
    root: str,
    policy: Policy,
    vault: Vault,
    prefix: str = "TAG",
) -> int:
    """Re-pack a single file in-place (standalone, no manifest dependency).

    Validates that the path is inside the project root and not ignored.
    Uses the idempotency guard in pack_text() to avoid double-tagging.

    Args:
        path: Absolute path to the file
        root: Project root directory
        policy: Detection policy
        vault: Vault for tag storage
        prefix: Tag prefix

    Returns:
        Count of new secrets packed (0 if file unchanged or skipped)
    """
    # Validate path is inside project root
    abs_path = os.path.abspath(path)
    abs_root = os.path.abspath(root)
    if not abs_path.startswith(abs_root + os.sep) and abs_path != abs_root:
        return 0

    # Check if file is ignored
    rel = os.path.relpath(abs_path, abs_root)
    ignores = load_ignores(abs_root)
    for g in ignores:
        if g.endswith("/"):
            # Directory pattern — check if rel path starts with it
            dir_part = os.path.dirname(rel) + "/"
            if fnmatch.fnmatch(dir_part, g):
                return 0
        elif fnmatch.fnmatch(rel, g):
            return 0

    if not os.path.isfile(abs_path):
        return 0

    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except (OSError, IOError, PermissionError):
        return 0

    packed, count = pack_text(text, policy, vault, prefix=prefix)
    if count > 0 and packed != text:
        tmp = abs_path + ".cloak.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(packed)
            os.replace(tmp, abs_path)
        except (OSError, IOError, PermissionError):
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
            return 0

    return count
