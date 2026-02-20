"""Tests for mcp.filepack — file-level pack/unpack API."""
from __future__ import annotations
import os
import tempfile
import pytest

from cloakmcp.filepack import TAG_RE, pack_text, unpack_text, pack_file, unpack_file
from cloakmcp.policy import Policy
from cloakmcp.storage import Vault


POLICY_PATH = "examples/mcp_policy.yaml"

SAMPLE_TEXT = (
    "Email: alice@example.org\n"
    "Key: AKIAABCDEFGHIJKLMNOP\n"
    "Safe line with no secrets.\n"
)


@pytest.fixture
def vault(tmp_path):
    """Create a temporary vault."""
    return Vault(str(tmp_path))


@pytest.fixture
def policy():
    return Policy.load(POLICY_PATH)


# ── TAG_RE ──────────────────────────────────────────────────────

class TestTagRegex:
    def test_matches_standard_tag(self):
        assert TAG_RE.search("TAG-2f1a8e3c9b12")

    def test_matches_short_prefix(self):
        assert TAG_RE.search("SE-2f1a8e3c9b12")

    def test_matches_long_prefix(self):
        assert TAG_RE.search("SECRETKV-2f1a8e3c9b12")

    def test_no_match_too_short_hex(self):
        assert TAG_RE.search("TAG-2f1a8e") is None

    def test_no_match_lowercase_prefix(self):
        assert TAG_RE.search("tag-2f1a8e3c9b12") is None

    def test_extracts_full_tag(self):
        m = TAG_RE.search("before TAG-aabbccddee11 after")
        assert m and m.group(1) == "TAG-aabbccddee11"


# ── pack_text / unpack_text ─────────────────────────────────────

class TestPackText:
    def test_basic_pack(self, policy, vault):
        packed, count = pack_text(SAMPLE_TEXT, policy, vault)
        assert count > 0
        assert "alice@example.org" not in packed
        assert TAG_RE.search(packed)

    def test_no_secrets(self, policy, vault):
        packed, count = pack_text("nothing secret here\n", policy, vault)
        assert count == 0

    def test_custom_prefix(self, policy, vault):
        packed, count = pack_text(SAMPLE_TEXT, policy, vault, prefix="SEC")
        assert count > 0
        assert "SEC-" in packed
        assert "TAG-" not in packed

    def test_deterministic(self, policy, vault):
        packed1, _ = pack_text(SAMPLE_TEXT, policy, vault)
        packed2, _ = pack_text(SAMPLE_TEXT, policy, vault)
        assert packed1 == packed2


class TestUnpackText:
    def test_basic_unpack(self, policy, vault):
        packed, _ = pack_text(SAMPLE_TEXT, policy, vault)
        unpacked, count = unpack_text(packed, vault)
        assert count > 0
        assert "alice@example.org" in unpacked

    def test_unknown_tags_preserved(self, vault):
        text = "TAG-000000000000 is unknown"
        unpacked, count = unpack_text(text, vault)
        assert count == 0
        assert "TAG-000000000000" in unpacked

    def test_no_tags(self, vault):
        text = "no tags here"
        unpacked, count = unpack_text(text, vault)
        assert count == 0
        assert unpacked == text


class TestRoundtrip:
    def test_pack_unpack_roundtrip(self, policy, vault):
        """Pack then unpack should restore original text."""
        original = "Email: bob@example.com\nSafe text stays.\n"
        packed, pack_count = pack_text(original, policy, vault)
        assert pack_count > 0
        unpacked, unpack_count = unpack_text(packed, vault)
        assert unpack_count > 0
        assert "bob@example.com" in unpacked

    def test_idempotent_double_pack(self, policy, vault):
        """Packing already-packed text should not double-pack."""
        packed1, c1 = pack_text(SAMPLE_TEXT, policy, vault)
        packed2, c2 = pack_text(packed1, policy, vault)
        # Tags don't match secret patterns, so second pack should find nothing new
        # (the tags themselves may or may not be detected depending on policy)
        assert packed1 == packed2 or c2 == 0


# ── pack_file / unpack_file ─────────────────────────────────────

class TestPackFile:
    def test_pack_file_modifies(self, policy, vault, tmp_path):
        f = tmp_path / "secret.txt"
        f.write_text("Email: test@example.org\n")
        count = pack_file(str(f), policy, vault)
        assert count > 0
        content = f.read_text()
        assert "test@example.org" not in content
        assert TAG_RE.search(content)

    def test_pack_file_dry_run(self, policy, vault, tmp_path):
        f = tmp_path / "secret.txt"
        f.write_text("Email: test@example.org\n")
        count = pack_file(str(f), policy, vault, dry_run=True)
        assert count > 0
        # File should not be modified
        assert "test@example.org" in f.read_text()


class TestUnpackFile:
    def test_unpack_file_restores(self, policy, vault, tmp_path):
        f = tmp_path / "secret.txt"
        original = "Email: test@example.org\n"
        f.write_text(original)
        pack_file(str(f), policy, vault)
        count = unpack_file(str(f), vault)
        assert count > 0
        assert "test@example.org" in f.read_text()

    def test_unpack_file_dry_run(self, policy, vault, tmp_path):
        f = tmp_path / "secret.txt"
        f.write_text("Email: test@example.org\n")
        pack_file(str(f), policy, vault)
        packed_content = f.read_text()
        count = unpack_file(str(f), vault, dry_run=True)
        assert count > 0
        # File should not be modified
        assert f.read_text() == packed_content
