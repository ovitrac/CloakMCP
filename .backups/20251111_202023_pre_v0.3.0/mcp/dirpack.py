from __future__ import annotations
import fnmatch
import os
import re
from typing import Iterable, List

from .policy import Policy
from .scanner import scan
from .normalizer import normalize
from .storage import Vault

IGNORE_FILE = ".mcpignore"
TAG_RE = re.compile(r"\b([A-Z]{2,8}-[0-9a-f]{12})\b")

def load_ignores(root: str) -> List[str]:
    path = os.path.join(root, IGNORE_FILE)
    globs: List[str] = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if ln and not ln.startswith("#"):
                    globs.append(ln)
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

def pack_dir(root: str, policy: Policy, prefix: str = "TAG", in_place: bool = True) -> None:
    import sys
    vault = Vault(root)
    ignores = load_ignores(root)
    skipped_count = 0
    processed_count = 0

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

        norm = normalize(text)
        matches = scan(norm, policy)
        if not matches:
            continue

        out = list(norm)
        for m in reversed(matches):
            tag = vault.tag_for(m.value, prefix=prefix)
            out[m.start:m.end] = list(tag)
        new_text = "".join(out)

        if new_text != text:
            try:
                tmp = path + ".mcp.tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    f.write(new_text)
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

def unpack_dir(root: str) -> None:
    import sys
    vault = Vault(root)
    ignores = load_ignores(root)
    skipped_count = 0
    processed_count = 0

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

        changed = False
        def repl(m):
            nonlocal changed
            tag = m.group(1)
            secret = vault.secret_for(tag)
            if secret is not None:
                changed = True
                return secret
            return tag
        new_text = TAG_RE.sub(repl, text)

        if changed:
            try:
                tmp = path + ".mcp.tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    f.write(new_text)
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
