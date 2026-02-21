from __future__ import annotations
import os
import re
from typing import Tuple

from .normalizer import normalize
from .policy import Policy
from .scanner import scan
from .storage import Vault

# Single source of truth for tag regex
TAG_RE = re.compile(r"\b([A-Z]{2,8}-[0-9a-f]{12})\b")


def _dedup_overlapping(matches: list) -> list:
    """Remove overlapping matches, keeping the longest span at each position."""
    if not matches:
        return []
    # Sort by start, then by span length descending (prefer longer matches)
    sorted_m = sorted(matches, key=lambda m: (m.start, -(m.end - m.start)))
    kept = [sorted_m[0]]
    for m in sorted_m[1:]:
        if m.start >= kept[-1].end:
            # No overlap — keep it
            kept.append(m)
        # Otherwise skip (fully or partially overlapping with a longer match)
    return kept


def pack_text(
    text: str,
    policy: Policy,
    vault: Vault,
    prefix: str = "TAG",
) -> Tuple[str, int]:
    """Replace secrets in text with deterministic vault tags.

    Args:
        text: Input text (will be normalized)
        policy: Policy defining what counts as a secret
        vault: Vault for tag storage
        prefix: Tag prefix (e.g., TAG, SEC, KEY)

    Returns:
        (packed_text, replacement_count)
    """
    norm = normalize(text)
    matches = scan(norm, policy)
    if not matches:
        return norm, 0

    # Idempotency guard: exclude matches overlapping existing tags.
    # This prevents re-packing already-packed content (double-tagging).
    existing_tags = [(m.start(), m.end()) for m in TAG_RE.finditer(norm)]
    if existing_tags:
        matches = [
            m for m in matches
            if not any(m.start < te and m.end > ts for ts, te in existing_tags)
        ]
        if not matches:
            return norm, 0

    # Deduplicate overlapping matches to prevent corruption
    matches = _dedup_overlapping(matches)

    out = list(norm)
    count = 0
    for m in reversed(matches):
        tag = vault.tag_for(m.value, prefix=prefix)
        out[m.start : m.end] = list(tag)
        count += 1

    return "".join(out), count


def unpack_text(text: str, vault: Vault) -> Tuple[str, int]:
    """Restore vault tags in text back to original secrets.

    Args:
        text: Text containing TAG-xxxxxxxxxxxx placeholders
        vault: Vault with tag-to-secret mapping

    Returns:
        (unpacked_text, restoration_count)
    """
    count = 0

    def repl(m: re.Match) -> str:
        nonlocal count
        tag = m.group(1)
        secret = vault.secret_for(tag)
        if secret is not None:
            count += 1
            return secret
        return m.group(0)

    result = TAG_RE.sub(repl, text)
    return result, count


def pack_file(
    path: str,
    policy: Policy,
    vault: Vault,
    prefix: str = "TAG",
    dry_run: bool = False,
) -> int:
    """Pack a single file: replace secrets with vault tags.

    Args:
        path: File path
        policy: Policy defining what counts as a secret
        vault: Vault for tag storage
        prefix: Tag prefix
        dry_run: If True, return count without modifying file

    Returns:
        Number of replacements made (or that would be made in dry_run)
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    packed, count = pack_text(text, policy, vault, prefix=prefix)

    if count > 0 and not dry_run and packed != text:
        tmp = path + ".cloak.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(packed)
            os.replace(tmp, path)
        except (OSError, IOError, PermissionError):
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
            raise

    return count


def unpack_file(
    path: str,
    vault: Vault,
    dry_run: bool = False,
) -> int:
    """Unpack a single file: restore vault tags to secrets.

    Args:
        path: File path
        vault: Vault with tag-to-secret mapping
        dry_run: If True, return count without modifying file

    Returns:
        Number of restorations made (or that would be made in dry_run)
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    unpacked, count = unpack_text(text, vault)

    if count > 0 and not dry_run and unpacked != text:
        tmp = path + ".cloak.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(unpacked)
            os.replace(tmp, path)
        except (OSError, IOError, PermissionError):
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
            raise

    return count
