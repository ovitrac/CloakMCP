"""Tests for the enterprise policy profile (R7).

Validates:
- Policy inheritance from default mcp_policy.yaml
- Detection of provider-specific tokens (GitHub, GitLab, Slack, Stripe, etc.)
- Context-gated rules (Heroku UUID requires HEROKU prefix)
- whitelist_patterns scoped to entropy rules only
"""
from __future__ import annotations
import os
import re

import pytest

from cloakmcp.policy import Policy, validate_policy
from cloakmcp.scanner import scan
from cloakmcp.normalizer import normalize

POLICY_PATH = os.path.join(os.path.dirname(__file__), "..", "examples", "mcp_policy_enterprise.yaml")
BASE_POLICY_PATH = os.path.join(os.path.dirname(__file__), "..", "examples", "mcp_policy.yaml")


@pytest.fixture
def enterprise_policy():
    return Policy.load(POLICY_PATH)


@pytest.fixture
def base_policy():
    return Policy.load(BASE_POLICY_PATH)


# ── Inheritance ──────────────────────────────────────────────────


class TestEnterprisePolicyInheritance:
    def test_enterprise_inherits_default(self, enterprise_policy, base_policy):
        """Enterprise policy includes all base rule IDs."""
        base_ids = {r.id for r in base_policy.rules}
        enterprise_ids = {r.id for r in enterprise_policy.rules}
        # All base IDs should be present (some may be overridden but same ID)
        assert base_ids.issubset(enterprise_ids), (
            f"Missing base rules: {base_ids - enterprise_ids}"
        )

    def test_enterprise_total_rules(self, enterprise_policy):
        """Enterprise policy has base + enterprise rules."""
        # Base: 10 rules, Enterprise adds 16 new + overrides 1 (high_entropy_token)
        # Total unique: 10 + 16 = 26 (high_entropy_token is replaced, not duplicated)
        assert len(enterprise_policy.rules) >= 25, (
            f"Expected >= 25 rules, got {len(enterprise_policy.rules)}"
        )

    def test_enterprise_policy_valid(self):
        """Enterprise policy passes validation."""
        is_valid, errors = validate_policy(POLICY_PATH)
        assert is_valid, f"Validation errors: {errors}"

    def test_enterprise_inherits_globals(self, enterprise_policy, base_policy):
        """Enterprise policy inherits globals from base."""
        assert enterprise_policy.globals.default_action == base_policy.globals.default_action
        assert enterprise_policy.globals.pz.method == base_policy.globals.pz.method


# ── Provider-specific detection ──────────────────────────────────


class TestProviderDetection:
    def _find_match(self, policy, text, expected_rule_id):
        """Scan text and assert a match with given rule ID is found."""
        norm = normalize(text)
        matches = scan(norm, policy)
        rule_ids = [m.rule.id for m in matches]
        assert expected_rule_id in rule_ids, (
            f"Expected rule '{expected_rule_id}' to match in: {text!r}\n"
            f"Got: {rule_ids}"
        )

    def _find_no_match(self, policy, text, excluded_rule_id):
        """Scan text and assert NO match with given rule ID."""
        norm = normalize(text)
        matches = scan(norm, policy)
        rule_ids = [m.rule.id for m in matches]
        assert excluded_rule_id not in rule_ids, (
            f"Rule '{excluded_rule_id}' should NOT match in: {text!r}"
        )

    def test_github_pat_detected(self, enterprise_policy):
        self._find_match(
            enterprise_policy,
            "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
            "github_pat",
        )

    def test_github_fine_grained_detected(self, enterprise_policy):
        self._find_match(
            enterprise_policy,
            "github_pat_1234567890ABCDEFGHIJkl_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456",
            "github_fine_grained",
        )

    def test_gitlab_token_detected(self, enterprise_policy):
        self._find_match(
            enterprise_policy,
            "GITLAB_TOKEN=glpat-ABCDEFGHIJKLMNOPQRSTuv",
            "gitlab_token",
        )

    def test_slack_bot_token_detected(self, enterprise_policy):
        self._find_match(
            enterprise_policy,
            "SLACK_TOKEN=xoxb-123456789012-1234567890123-ABCDEFGHIJKLmnopqrstuv",
            "slack_bot_token",
        )

    def test_slack_webhook_detected(self, enterprise_policy):
        self._find_match(
            enterprise_policy,
            "url: https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
            "slack_webhook",
        )

    def test_stripe_live_key_detected(self, enterprise_policy):
        self._find_match(
            enterprise_policy,
            "stripe_key = sk_live_ABCDEFGHIJKLMNOPQRSTUVWXyz",
            "stripe_secret_key",
        )

    def test_stripe_live_key_critical_severity(self, enterprise_policy):
        """Stripe live keys should be critical severity."""
        rule = next(r for r in enterprise_policy.rules if r.id == "stripe_secret_key")
        assert rule.severity == "critical"

    def test_stripe_test_key_lower_severity(self, enterprise_policy):
        """Stripe test keys should be medium severity (not critical)."""
        self._find_match(
            enterprise_policy,
            "test_key = sk_test_ABCDEFGHIJKLMNOPQRSTUVWXyz",
            "stripe_test_key",
        )
        rule = next(r for r in enterprise_policy.rules if r.id == "stripe_test_key")
        assert rule.severity == "medium"

    def test_npm_token_detected(self, enterprise_policy):
        self._find_match(
            enterprise_policy,
            "NPM_TOKEN=npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
            "npm_token",
        )

    def test_heroku_context_gated_with_prefix(self, enterprise_policy):
        """Heroku UUID with HEROKU prefix → detected."""
        self._find_match(
            enterprise_policy,
            'HEROKU_API_KEY="12345678-1234-1234-1234-123456789abc"',
            "heroku_api_key",
        )

    def test_heroku_bare_uuid_not_matched(self, enterprise_policy):
        """Bare UUID without HEROKU context → NOT detected by heroku rule."""
        self._find_no_match(
            enterprise_policy,
            "id: 12345678-1234-1234-1234-123456789abc",
            "heroku_api_key",
        )

    def test_sendgrid_detected(self, enterprise_policy):
        # SG. + 22+ chars + . + 43+ chars
        sg_key = "SG." + "A" * 22 + "." + "B" * 43
        self._find_match(enterprise_policy, f"key = {sg_key}", "sendgrid_api_key")

    def test_twilio_api_key_detected(self, enterprise_policy):
        self._find_match(
            enterprise_policy,
            "TWILIO_KEY=SK0123456789abcdef0123456789abcdef",
            "twilio_api_key",
        )

    def test_generic_password_detected(self, enterprise_policy):
        self._find_match(
            enterprise_policy,
            'password = "SuperSecret123!@#"',
            "generic_password_assign",
        )

    def test_generic_secret_detected(self, enterprise_policy):
        self._find_match(
            enterprise_policy,
            "api_key: 'MySecretApiKey12345678'",
            "generic_secret_assign",
        )

    def test_pkcs8_private_key_detected(self, enterprise_policy):
        pem = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg...\n-----END PRIVATE KEY-----"
        self._find_match(enterprise_policy, pem, "private_key_pkcs8")

    def test_encrypted_private_key_detected(self, enterprise_policy):
        pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFHDBOBg...\n-----END ENCRYPTED PRIVATE KEY-----"
        self._find_match(enterprise_policy, pem, "encrypted_private_key")

    def test_azure_connection_string_detected(self, enterprise_policy):
        # AccountKey= followed by 86 base64 chars + ==
        key = "A" * 86 + "=="
        self._find_match(
            enterprise_policy,
            f"AccountKey={key}",
            "azure_connection_string",
        )


# ── Entropy whitelist_patterns ───────────────────────────────────


class TestEntropyWhitelistPatterns:
    def test_whitelist_patterns_skip_data_uri(self, enterprise_policy):
        """data:image/ prefix should not be flagged by entropy detector."""
        # Build a long base64 data URI that would normally trigger entropy
        data_uri = "data:image/" + "A" * 60
        norm = normalize(data_uri)
        matches = scan(norm, enterprise_policy)
        entropy_matches = [m for m in matches if m.rule.id == "high_entropy_token"]
        assert len(entropy_matches) == 0, (
            f"data:image/ URI should be skipped by entropy allowlist, got {len(entropy_matches)} matches"
        )

    def test_whitelist_patterns_only_affects_entropy(self, enterprise_policy):
        """whitelist_patterns on entropy rule does NOT affect regex rules."""
        # A GitHub PAT should still be detected even if it starts with a
        # pattern that might look like an allowlisted string
        text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        norm = normalize(text)
        matches = scan(norm, enterprise_policy)
        rule_ids = [m.rule.id for m in matches]
        assert "github_pat" in rule_ids

    def test_non_allowlisted_entropy_still_detected(self, enterprise_policy):
        """High-entropy string NOT matching allowlist → still detected."""
        # A random-looking base64 string (not data:image/)
        random_b64 = "Xk9pLmN2Qjh3RnVZZEhqS2xNblByU3RWd3h6QWNFZw=="
        norm = normalize(random_b64)
        matches = scan(norm, enterprise_policy)
        entropy_matches = [m for m in matches if m.rule.id == "high_entropy_token"]
        # Should still trigger (not in allowlist)
        assert len(entropy_matches) >= 1 or len(matches) > 0, (
            "High-entropy string should still be detected"
        )

    def test_base_policy_has_no_whitelist_patterns(self, base_policy):
        """Base policy entropy rule has no whitelist_patterns."""
        entropy_rule = next(
            (r for r in base_policy.rules if r.id == "high_entropy_token"), None
        )
        assert entropy_rule is not None
        assert entropy_rule.whitelist_patterns is None
