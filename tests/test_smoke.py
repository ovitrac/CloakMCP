from cloakmcp.policy import Policy
from cloakmcp.cli import sanitize_text

EXAMPLE = """Token: AKIAABCDEFGHIJKLMNOP
Email: alice@example.org and bob@internal.company
JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
IPv4: 203.0.113.42 and 10.1.2.3
"""

def test_sanitize():
    pol = Policy.load("examples/mcp_policy.yaml")
    out, blocked = sanitize_text(EXAMPLE, pol, dry_run=False)
    assert blocked is True    # AWS key → block
    assert "<EMAIL:" in out   # email template applies
