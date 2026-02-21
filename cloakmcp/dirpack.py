from __future__ import annotations
import fnmatch
import hashlib
import os
import shutil
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Tuple

from .policy import Policy
from .storage import Vault
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

def iter_files(root: str, globs: List[str]) -> Iterable[str]:
    for dirpath, dirnames, filenames in os.walk(root):
        rp = os.path.relpath(dirpath, root)
        skip_dir = any(g.endswith("/") and fnmatch.fnmatch(rp + "/", g) for g in globs)
        if skip_dir:
            dirnames[:] = []
            continue
        for name in filenames:
            rel = os.path.relpath(os.path.join(dirpath, name), root)
            if any(fnmatch.fnmatch(rel, g) for g in globs if not g.endswith("/")):
                continue
            yield os.path.join(root, rel)

def create_backup(root: str) -> str:
    """Create a timestamped backup of files in the directory."""
    import sys
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(root, BACKUP_DIR, timestamp)
    os.makedirs(backup_path, exist_ok=True)

    ignores = load_ignores(root)
    files_backed_up = 0

    for path in iter_files(root, ignores):
        rel_path = os.path.relpath(path, root)
        backup_file = os.path.join(backup_path, rel_path)
        os.makedirs(os.path.dirname(backup_file), exist_ok=True)
        try:
            shutil.copy2(path, backup_file)
            files_backed_up += 1
        except (OSError, IOError, PermissionError) as e:
            print(f"Warning: Failed to backup {rel_path}: {e}", file=sys.stderr)

    print(f"Backup created: {backup_path} ({files_backed_up} files)", file=sys.stderr)
    return backup_path

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
    skipped_count = 0
    processed_count = 0
    files_to_modify: List[Tuple[str, int]] = []  # (path, match_count)

    # First pass: scan all files for secrets
    for path in iter_files(root, ignores):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except (OSError, IOError, PermissionError) as e:
            print(f"Warning: Skipping file (read error): {path} - {e}", file=sys.stderr)
            skipped_count += 1
            continue
        except UnicodeDecodeError as e:
            print(f"Warning: Skipping file (encoding error): {path} - {e}", file=sys.stderr)
            skipped_count += 1
            continue

        _, count = pack_text(text, policy, vault, prefix=prefix)
        if count > 0:
            files_to_modify.append((path, count))

    if not files_to_modify:
        print("No secrets found to replace.", file=sys.stderr)
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
            skipped_count += 1
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
                skipped_count += 1
                if os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except:
                        pass

    if processed_count > 0 or skipped_count > 0:
        print(f"Pack complete: {processed_count} files modified, {skipped_count} files skipped", file=sys.stderr)

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
    skipped_count = 0
    processed_count = 0
    files_to_modify: List[Tuple[str, int]] = []  # (path, tag_count)

    # First pass: scan all files for resolvable tags
    for path in iter_files(root, ignores):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except (OSError, IOError, PermissionError) as e:
            print(f"Warning: Skipping file (read error): {path} - {e}", file=sys.stderr)
            skipped_count += 1
            continue
        except UnicodeDecodeError as e:
            print(f"Warning: Skipping file (encoding error): {path} - {e}", file=sys.stderr)
            skipped_count += 1
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
            skipped_count += 1
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
                skipped_count += 1
                if os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except:
                        pass

    if processed_count > 0 or skipped_count > 0:
        print(f"Unpack complete: {processed_count} files modified, {skipped_count} files skipped", file=sys.stderr)


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
