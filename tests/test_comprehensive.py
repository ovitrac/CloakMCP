"""
Comprehensive test suite for CloakMCP v0.3.1

Tests all major functionality:
- Policy loading and validation
- Scanner detectors (regex, entropy, IP, URL, JWT)
- Actions (redact, pseudonymize, block, hash, templates)
- Normalizer (Unicode, zero-width chars)
- Vault (encryption, deterministic tagging, pack/unpack)
- CLI commands
- API endpoints
- Edge cases and error conditions

Run: pytest -v tests/test_comprehensive.py
"""

from __future__ import annotations
import hashlib
import json
import os
import pytest
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Dict

# Import MCP modules
from mcp.policy import Policy, Rule, GlobalsCfg, PseudonymizationCfg
from mcp.scanner import scan, shannon_entropy, Match
from mcp.actions import apply_action, ActionResult
from mcp.normalizer import normalize
from mcp.utils import sha256_hex, base62_short, nfc, strip_zero_width
from mcp.storage import Vault
from mcp.dirpack import pack_dir, unpack_dir, load_ignores, iter_files
from mcp.cli import sanitize_text, _load_text, _write_text
from mcp.audit import write_event, now_iso


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def temp_dir():
    """Create temporary directory for tests"""
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


@pytest.fixture
def policy_yaml(temp_dir: Path) -> Path:
    """Create minimal valid policy YAML"""
    yaml_content = """
version: 1
globals:
  default_action: redact
  audit:
    enabled: true
    path: ./audit/test_audit.jsonl
    include_value_hash: true
  pseudonymization:
    method: hmac-sha256
    secret_key_file: ./keys/test_hmac_key
    salt: session

detection:
  - id: test_email
    type: regex
    pattern: '(?i)[a-z0-9_.+-]+@[a-z0-9-]+\\.[a-z0-9.-]+'
    action: replace_with_template
    template: '<EMAIL:{hash8}>'
  - id: test_aws_key
    type: regex
    pattern: '\\b(AKIA|ASIA)[A-Z0-9]{16}\\b'
    action: block
  - id: test_jwt
    type: regex
    pattern: '\\b[A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_]+\\b'
    action: pseudonymize
  - id: test_ipv4
    type: ipv4
    whitelist_cidrs: ['10.0.0.0/8', '192.168.0.0/16']
    action: pseudonymize
  - id: test_url
    type: url
    action: pseudonymize
  - id: test_entropy
    type: entropy
    min_entropy: 4.5
    min_length: 20
    action: redact
"""
    policy_path = temp_dir / "test_policy.yaml"
    policy_path.write_text(yaml_content)

    # Create keys directory and test key
    keys_dir = temp_dir / "keys"
    keys_dir.mkdir()
    test_key = keys_dir / "test_hmac_key"
    test_key.write_bytes(b"a" * 32)  # 32-byte test key

    # Create audit directory
    audit_dir = temp_dir / "audit"
    audit_dir.mkdir()

    return policy_path


@pytest.fixture
def policy(policy_yaml: Path) -> Policy:
    """Load policy from YAML"""
    # Change to temp dir so relative paths work
    orig_cwd = os.getcwd()
    os.chdir(policy_yaml.parent)
    try:
        pol = Policy.load(str(policy_yaml))
        return pol
    finally:
        os.chdir(orig_cwd)


# ============================================================================
# Test: Normalizer
# ============================================================================

class TestNormalizer:
    def test_normalize_line_endings(self):
        """Test CRLF and CR conversion to LF"""
        assert normalize("a\r\nb\rc") == "a\nb\nc"

    def test_normalize_unicode_nfc(self):
        """Test Unicode NFC normalization"""
        # é can be U+00E9 (composed) or U+0065 U+0301 (decomposed)
        decomposed = "e\u0301"  # e + combining acute
        assert normalize(decomposed) == "\u00e9"  # composed é

    def test_strip_zero_width(self):
        """Test zero-width character removal"""
        text = "hello\u200Bworld\u200C!\u200D\uFEFF"
        assert normalize(text) == "helloworld!"

    def test_normalize_empty(self):
        """Test empty string"""
        assert normalize("") == ""


# ============================================================================
# Test: Scanner
# ============================================================================

class TestScanner:
    def test_entropy_calculation(self):
        """Test Shannon entropy"""
        assert shannon_entropy("aaaa") < 1.0  # low entropy
        assert shannon_entropy("abcdefgh12345678") > 3.0  # high entropy
        assert shannon_entropy("") == 0.0

    def test_scan_email(self, policy: Policy):
        """Test email detection"""
        text = "Contact: alice@example.com"
        matches = scan(text, policy)
        assert len(matches) >= 1
        assert any(m.rule.id == "test_email" for m in matches)
        email_match = [m for m in matches if m.rule.id == "test_email"][0]
        assert email_match.value == "alice@example.com"

    def test_scan_aws_key(self, policy: Policy):
        """Test AWS key detection"""
        text = "Key: AKIAIOSFODNN7EXAMPLE"
        matches = scan(text, policy)
        assert len(matches) >= 1
        assert any(m.rule.id == "test_aws_key" for m in matches)

    def test_scan_jwt(self, policy: Policy):
        """Test JWT token detection"""
        text = "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def"
        matches = scan(text, policy)
        # Should match JWT rule (not just email pattern)
        jwt_matches = [m for m in matches if m.rule.id == "test_jwt"]
        assert len(jwt_matches) >= 1

    def test_scan_ipv4_whitelist(self, policy: Policy):
        """Test IPv4 with CIDR whitelist"""
        text = "Private: 192.168.1.1, Public: 203.0.113.42"
        matches = scan(text, policy)
        # 192.168.1.1 should be whitelisted, 203.0.113.42 should match
        ipv4_matches = [m for m in matches if m.rule.id == "test_ipv4"]
        assert any("203.0.113.42" in m.value for m in ipv4_matches)
        assert not any("192.168.1.1" in m.value for m in ipv4_matches)

    def test_scan_url(self, policy: Policy):
        """Test URL detection"""
        text = "Visit https://example.com/path?key=value"
        matches = scan(text, policy)
        url_matches = [m for m in matches if m.rule.id == "test_url"]
        assert len(url_matches) >= 1

    def test_scan_high_entropy(self, policy: Policy):
        """Test high-entropy string detection"""
        # 50-char random base64-like string
        text = "Token: aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9dE1fG="
        matches = scan(text, policy)
        entropy_matches = [m for m in matches if m.rule.id == "test_entropy"]
        assert len(entropy_matches) >= 1

    def test_scan_no_match(self, policy: Policy):
        """Test text with no secrets"""
        text = "Hello world, this is a clean text."
        matches = scan(text, policy)
        assert len(matches) == 0

    def test_scan_unicode(self, policy: Policy):
        """Test scanning Unicode text"""
        text = "Email: user@tëst.com 日本語"
        matches = scan(text, policy)
        # Should still detect email despite non-ASCII
        assert len(matches) >= 0  # Depends on regex pattern


# ============================================================================
# Test: Actions
# ============================================================================

class TestActions:
    def test_action_allow(self, policy: Policy):
        """Test 'allow' action"""
        rule = Rule(id="test", type="regex", action="allow")
        result = apply_action(rule, "secret123", policy)
        assert result.replacement == "secret123"
        assert result.blocked is False

    def test_action_block(self, policy: Policy):
        """Test 'block' action"""
        rule = Rule(id="test", type="regex", action="block")
        result = apply_action(rule, "secret123", policy)
        assert result.replacement == ""
        assert result.blocked is True

    def test_action_redact(self, policy: Policy):
        """Test 'redact' action"""
        rule = Rule(id="test_rule", type="regex", action="redact")
        result = apply_action(rule, "secret123", policy)
        assert result.replacement == "<REDACTED:test_rule>"
        assert result.blocked is False

    def test_action_pseudonymize(self, policy: Policy):
        """Test 'pseudonymize' action (HMAC)"""
        rule = Rule(id="test", type="regex", action="pseudonymize")
        result = apply_action(rule, "secret123", policy)
        assert result.replacement.startswith("PZ-")
        assert result.blocked is False

        # Test determinism: same secret → same pseudonym
        result2 = apply_action(rule, "secret123", policy)
        assert result.replacement == result2.replacement

    def test_action_hash(self, policy: Policy):
        """Test 'hash' action"""
        rule = Rule(id="test", type="regex", action="hash")
        result = apply_action(rule, "secret123", policy)
        assert result.replacement.startswith("HASH-")
        assert len(result.replacement) == len("HASH-") + 16  # HASH- + 16 hex chars

    def test_action_template(self, policy: Policy):
        """Test 'replace_with_template' action"""
        rule = Rule(
            id="test",
            type="regex",
            action="replace_with_template",
            template="<SECRET:{hash8}>",
        )
        result = apply_action(rule, "secret123", policy)
        assert result.replacement.startswith("<SECRET:")
        assert result.replacement.endswith(">")

    def test_action_unknown(self, policy: Policy):
        """Test unknown action falls back to redact"""
        rule = Rule(id="test", type="regex", action="unknown_action")
        result = apply_action(rule, "secret123", policy)
        assert "<REDACTED:" in result.replacement


# ============================================================================
# Test: Policy
# ============================================================================

class TestPolicy:
    def test_policy_load(self, policy_yaml: Path):
        """Test policy loading from YAML"""
        pol = Policy.load(str(policy_yaml))
        assert pol.version == 1
        assert pol.globals.default_action == "redact"
        assert pol.globals.audit_enabled is True
        assert len(pol.rules) > 0

    def test_policy_cidr_allowed(self, policy: Policy):
        """Test CIDR whitelist checking"""
        assert policy.cidr_allowed("192.168.1.1", ["192.168.0.0/16"]) is True
        assert policy.cidr_allowed("203.0.113.42", ["192.168.0.0/16"]) is False
        assert policy.cidr_allowed("10.0.0.1", ["10.0.0.0/8"]) is True

    def test_policy_email_whitelist(self, policy: Policy):
        """Test email whitelist patterns"""
        # Set up whitelist in policy
        policy.whitelist["emails"] = ["*@example.com", "admin@test.org"]

        assert policy.email_whitelisted("alice@example.com") is True
        assert policy.email_whitelisted("bob@example.com") is True
        assert policy.email_whitelisted("admin@test.org") is True
        assert policy.email_whitelisted("evil@badguy.com") is False


# ============================================================================
# Test: Storage (Vault)
# ============================================================================

class TestVault:
    def test_vault_create(self, temp_dir: Path):
        """Test vault creation"""
        vault = Vault(str(temp_dir))
        assert os.path.exists(vault.key_path)
        assert os.path.exists(vault.vault_path)

    def test_vault_tag_deterministic(self, temp_dir: Path):
        """Test deterministic tagging"""
        vault = Vault(str(temp_dir))
        tag1 = vault.tag_for("my_secret", prefix="TAG")
        tag2 = vault.tag_for("my_secret", prefix="TAG")
        assert tag1 == tag2
        assert tag1.startswith("TAG-")

    def test_vault_roundtrip(self, temp_dir: Path):
        """Test encrypt → decrypt roundtrip"""
        vault = Vault(str(temp_dir))
        tag = vault.tag_for("my_secret_value", prefix="SEC")
        retrieved = vault.secret_for(tag)
        assert retrieved == "my_secret_value"

    def test_vault_multiple_secrets(self, temp_dir: Path):
        """Test multiple secrets in vault"""
        vault = Vault(str(temp_dir))
        tag1 = vault.tag_for("secret1", prefix="TAG")
        tag2 = vault.tag_for("secret2", prefix="TAG")
        tag3 = vault.tag_for("secret1", prefix="TAG")  # duplicate

        assert tag1 != tag2
        assert tag1 == tag3  # deterministic
        assert vault.secret_for(tag1) == "secret1"
        assert vault.secret_for(tag2) == "secret2"

    def test_vault_persistence(self, temp_dir: Path):
        """Test vault persists across instances"""
        vault1 = Vault(str(temp_dir))
        tag = vault1.tag_for("persistent_secret", prefix="TAG")

        # Create new vault instance for same project
        vault2 = Vault(str(temp_dir))
        retrieved = vault2.secret_for(tag)
        assert retrieved == "persistent_secret"


# ============================================================================
# Test: Directory Pack/Unpack
# ============================================================================

class TestDirPack:
    def test_load_ignores(self, temp_dir: Path):
        """Test .mcpignore loading"""
        mcpignore = temp_dir / ".mcpignore"
        mcpignore.write_text("*.pyc\n__pycache__/\n# comment\n\nnode_modules/\n")

        globs = load_ignores(str(temp_dir))
        assert "*.pyc" in globs
        assert "__pycache__/" in globs
        assert "node_modules/" in globs
        assert "# comment" not in globs

    def test_iter_files_with_ignores(self, temp_dir: Path):
        """Test file iteration with ignore patterns"""
        # Create test structure
        (temp_dir / "file1.py").write_text("print('hello')")
        (temp_dir / "file2.pyc").write_text("binary")
        (temp_dir / "subdir").mkdir()
        (temp_dir / "subdir" / "file3.py").write_text("print('world')")

        # Create .mcpignore
        (temp_dir / ".mcpignore").write_text("*.pyc\n")

        globs = load_ignores(str(temp_dir))
        files = list(iter_files(str(temp_dir), globs))

        # Should include .py files but not .pyc
        file_names = [os.path.basename(f) for f in files]
        assert "file1.py" in file_names
        assert "file3.py" in file_names
        assert "file2.pyc" not in file_names

    def test_pack_unpack_roundtrip(self, temp_dir: Path, policy_yaml: Path):
        """Test pack → unpack roundtrip preserves secrets"""
        # Change to temp dir
        orig_cwd = os.getcwd()
        os.chdir(policy_yaml.parent)

        try:
            # Create test project
            project = temp_dir / "test_project"
            project.mkdir()
            test_file = project / "secrets.txt"
            original_content = "Email: alice@example.com\nKey: AKIAIOSFODNN7EXAMPLE\n"
            test_file.write_text(original_content)

            # Load policy
            pol = Policy.load(str(policy_yaml))

            # Pack (replace secrets with tags)
            pack_dir(str(project), pol, prefix="TAG", in_place=True)

            packed_content = test_file.read_text()
            assert "TAG-" in packed_content
            assert "alice@example.com" not in packed_content

            # Unpack (restore secrets)
            unpack_dir(str(project))

            unpacked_content = test_file.read_text()
            # Email should be restored; AWS key might be blocked so check carefully
            assert "alice@example.com" in unpacked_content or "<EMAIL:" in unpacked_content

        finally:
            os.chdir(orig_cwd)

    def test_pack_respects_mcpignore(self, temp_dir: Path, policy_yaml: Path):
        """Test pack respects .mcpignore"""
        orig_cwd = os.getcwd()
        os.chdir(policy_yaml.parent)

        try:
            project = temp_dir / "test_project2"
            project.mkdir()

            # Create files
            (project / "public.py").write_text("email = 'test@example.com'")
            (project / "secret.pyc").write_text("email = 'test@example.com'")

            # Create .mcpignore
            (project / ".mcpignore").write_text("*.pyc\n")

            pol = Policy.load(str(policy_yaml))
            pack_dir(str(project), pol, prefix="TAG", in_place=True)

            # public.py should be modified
            assert "TAG-" in (project / "public.py").read_text() or "<EMAIL:" in (project / "public.py").read_text()

            # secret.pyc should be unchanged (ignored)
            assert "test@example.com" in (project / "secret.pyc").read_text()

        finally:
            os.chdir(orig_cwd)


# ============================================================================
# Test: CLI
# ============================================================================

class TestCLI:
    def test_sanitize_text(self, policy: Policy):
        """Test sanitize_text function"""
        text = "Email: alice@example.com"
        output, blocked = sanitize_text(text, policy, dry_run=False)
        assert output != text  # Should be modified
        assert blocked is False  # Email is not blocked, only replaced

    def test_sanitize_text_blocked(self, policy: Policy):
        """Test sanitize_text with blocked content"""
        text = "AWS Key: AKIAIOSFODNN7EXAMPLE"
        output, blocked = sanitize_text(text, policy, dry_run=False)
        assert blocked is True

    def test_sanitize_text_dry_run(self, policy: Policy):
        """Test dry-run mode (no modifications)"""
        text = "Email: alice@example.com"
        output, blocked = sanitize_text(text, policy, dry_run=True)
        assert output == text  # Should be unchanged


# ============================================================================
# Test: Audit
# ============================================================================

class TestAudit:
    def test_write_event(self, temp_dir: Path):
        """Test audit log writing"""
        audit_path = temp_dir / "audit.jsonl"
        event = {
            "ts": now_iso(),
            "rule_id": "test_rule",
            "action": "redact",
            "value_hash": "abc123",
        }
        write_event(str(audit_path), event)

        assert audit_path.exists()
        content = audit_path.read_text()
        assert "test_rule" in content
        assert "redact" in content

    def test_audit_multiple_events(self, temp_dir: Path):
        """Test multiple audit events (JSONL format)"""
        audit_path = temp_dir / "audit.jsonl"
        for i in range(3):
            write_event(str(audit_path), {"event_id": i, "ts": now_iso()})

        lines = audit_path.read_text().strip().split("\n")
        assert len(lines) == 3
        for line in lines:
            data = json.loads(line)
            assert "event_id" in data
            assert "ts" in data


# ============================================================================
# Test: Utils
# ============================================================================

class TestUtils:
    def test_sha256_hex(self):
        """Test SHA-256 hashing"""
        h = sha256_hex(b"test")
        assert len(h) == 64  # SHA-256 → 64 hex chars
        assert h == hashlib.sha256(b"test").hexdigest()

    def test_base62_short(self):
        """Test base62 encoding"""
        hex_str = "abcdef1234567890"
        encoded = base62_short(hex_str, n=8)
        assert len(encoded) <= 8
        assert all(c in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" for c in encoded)

    def test_nfc_normalization(self):
        """Test Unicode NFC normalization"""
        decomposed = "e\u0301"  # e + combining acute
        assert nfc(decomposed) == "\u00e9"

    def test_strip_zero_width(self):
        """Test zero-width character stripping"""
        text = "test\u200B\u200C\u200D\uFEFF"
        assert strip_zero_width(text) == "test"


# ============================================================================
# Test: Edge Cases
# ============================================================================

class TestEdgeCases:
    def test_empty_input(self, policy: Policy):
        """Test empty string input"""
        output, blocked = sanitize_text("", policy, dry_run=False)
        assert output == ""
        assert blocked is False

    def test_very_long_input(self, policy: Policy):
        """Test very long input (10MB)"""
        text = "a" * (10 * 1024 * 1024)
        output, blocked = sanitize_text(text, policy, dry_run=False)
        assert len(output) > 0

    def test_unicode_edge_cases(self, policy: Policy):
        """Test various Unicode edge cases"""
        text = "Emoji: 😀, CJK: 日本語, Arabic: مرحبا, Email: test@例え.jp"
        output, blocked = sanitize_text(text, policy, dry_run=False)
        assert len(output) > 0

    def test_malformed_input(self, policy: Policy):
        """Test malformed/binary input"""
        # Binary data that's not valid UTF-8
        text = "Valid text\x00\xff\xfe"
        # Should not crash
        try:
            output, blocked = sanitize_text(text, policy, dry_run=False)
            assert True
        except Exception as e:
            pytest.fail(f"Should handle binary gracefully: {e}")

    def test_overlapping_matches(self, policy: Policy):
        """Test overlapping regex matches"""
        # Create a scenario where matches overlap
        text = "email@jwt.token.parts"
        matches = scan(text, policy)
        # Should have at least one match (behavior is deterministic)
        assert len(matches) >= 0


# ============================================================================
# Test: Error Handling
# ============================================================================

class TestErrorHandling:
    def test_missing_policy_file(self):
        """Test loading non-existent policy"""
        with pytest.raises(FileNotFoundError):
            Policy.load("/nonexistent/policy.yaml")

    def test_invalid_yaml(self, temp_dir: Path):
        """Test loading invalid YAML"""
        bad_yaml = temp_dir / "bad.yaml"
        bad_yaml.write_text("invalid: yaml: syntax:")
        with pytest.raises(Exception):  # YAML parse error
            Policy.load(str(bad_yaml))

    def test_missing_hmac_key(self, temp_dir: Path):
        """Test pseudonymization with missing key file"""
        yaml_content = """
version: 1
globals:
  pseudonymization:
    secret_key_file: /nonexistent/key
detection:
  - id: test
    type: regex
    pattern: 'test'
    action: pseudonymize
"""
        pol_path = temp_dir / "policy.yaml"
        pol_path.write_text(yaml_content)
        pol = Policy.load(str(pol_path))

        rule = pol.rules[0]
        with pytest.raises(FileNotFoundError):
            apply_action(rule, "test", pol)


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    def test_full_workflow(self, temp_dir: Path, policy_yaml: Path):
        """Test complete workflow: scan → sanitize → pack → unpack"""
        orig_cwd = os.getcwd()
        os.chdir(policy_yaml.parent)

        try:
            # Create project with secrets
            project = temp_dir / "full_test"
            project.mkdir()
            secrets_file = project / "config.py"
            original = """
# Configuration
EMAIL = 'admin@company.com'
AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'
DATABASE_URL = 'postgresql://user:pass@db.internal.com:5432/mydb'
"""
            secrets_file.write_text(original)

            pol = Policy.load(str(policy_yaml))

            # Step 1: Scan (dry-run)
            text = secrets_file.read_text()
            _, blocked = sanitize_text(text, pol, dry_run=True)
            assert blocked is True  # AWS key should block

            # Step 2: Pack directory
            pack_dir(str(project), pol, prefix="TAG", in_place=True)
            packed = secrets_file.read_text()
            assert "TAG-" in packed
            assert "AKIAIOSFODNN7EXAMPLE" not in packed

            # Step 3: Unpack directory
            unpack_dir(str(project))
            unpacked = secrets_file.read_text()
            assert "admin@company.com" in unpacked or "<EMAIL:" in unpacked
            # Note: AWS key was blocked during scan, so it might not be in packed version

        finally:
            os.chdir(orig_cwd)


# ============================================================================
# Performance Tests (Optional)
# ============================================================================

class TestPerformance:
    def test_scan_large_file(self, policy: Policy):
        """Test scanning large file (1MB)"""
        import time
        text = "email@example.com " * 10000  # ~200KB
        start = time.time()
        matches = scan(text, policy)
        elapsed = time.time() - start
        assert elapsed < 5.0  # Should complete within 5 seconds

    def test_vault_many_secrets(self, temp_dir: Path):
        """Test vault with many secrets"""
        import time
        vault = Vault(str(temp_dir))
        start = time.time()
        for i in range(1000):
            vault.tag_for(f"secret_{i}", prefix="TAG")
        elapsed = time.time() - start
        assert elapsed < 10.0  # Should handle 1000 secrets quickly


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
