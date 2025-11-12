# Threat Model — CloakMCP

**Version**: 0.3.1-alpha
**Date**: 2025-11-12
**Maintainer**: Olivier Vitrac (Adservio Innovation Lab)

---

## Purpose

This document defines the security assumptions, threats in scope, threats out of scope, and trust boundaries for CloakMCP. It is intended for security reviewers, adopters, and contributors to understand what CloakMCP protects against and what it does not.

---

## Summary

CloakMCP is a **local-first anonymization layer** that protects secrets before they are shared with Large Language Models (LLMs) or external parties. It operates under the assumption that:

- **The local machine is trusted** (filesystem security, OS integrity).
- **The vault environment (`~/.cloakmcp/`) is secure** (proper permissions, encrypted at rest by OS if required).
- **Users follow operational best practices** (key management, backup procedures).

CloakMCP **does not** protect against:
- Compromised developer machines.
- Adversaries with physical or root access to the local system.
- Brute-force attacks by parties who already have access to vault keys.

---

## Trust Boundaries

### Trusted Zone
- **Local developer machine** (laptop, workstation).
- **Vault directory** (`~/.cloakmcp/keys/` and `~/.cloakmcp/vaults/`).
- **User's filesystem** (project directories).
- **Encryption keys** (stored locally in `~/.cloakmcp/keys/`).

### Untrusted Zone
- **LLM providers** (Claude, Codex, Gemini, etc.) — honest-but-curious.
- **Public repositories** (GitHub, GitLab, Bitbucket) if packed code is accidentally pushed.
- **CI/CD systems** if packed code is shared.
- **Collaborators** who receive packed repositories without vault access.

### Trust Boundary Line
The boundary is crossed when:
- A user runs `cloak pack` and the packed repository is **sent to an LLM**.
- Packed files are **committed to a public repository**.
- Packed files are **shared with unauthorized parties**.

**After crossing the boundary:**
- Secrets are replaced by deterministic HMAC-based tags (e.g., `TAG-2f1a8e3c9b12`).
- Tags **cannot be reversed** without access to the vault and encryption key.
- LLMs and external parties see only opaque identifiers.

---

## Threats In Scope

### 1. Accidental Secret Disclosure to LLMs
**Threat**: Developer accidentally shares unredacted code/config with an LLM, leaking API keys, credentials, PII.

**Mitigation**:
- CloakMCP **detects** secrets via configurable policy (regex, entropy, JWT, AWS keys, emails, IPs, URLs).
- CloakMCP **replaces** secrets with deterministic tags before sharing.
- Tags are HMAC-SHA256 with vault key (not reversible without vault).

**Residual Risk**: LOW
*Detection depends on policy completeness. Users must maintain up-to-date detection rules for new secret formats.*

---

### 2. Secret Leakage via Public Repositories
**Threat**: Developer accidentally commits unredacted secrets to GitHub/GitLab.

**Mitigation**:
- Use `cloak pack` before committing to replace secrets by tags.
- Add pre-commit hook invoking `cloak scan` to block commits with unredacted secrets.

**Residual Risk**: MEDIUM
*Users must remember to pack before committing. CloakMCP does not enforce this automatically.*

---

### 3. Honest-But-Curious LLM Provider
**Threat**: LLM provider logs all inputs and attempts to extract secrets from context.

**Mitigation**:
- Tags are HMAC-based (keyed with vault key).
- Without vault access, provider sees only `TAG-xxxxxx` strings.
- Provider cannot reverse tags or correlate tags across sessions without vault key.

**Residual Risk**: LOW
*Assumes HMAC-SHA256 is computationally infeasible to brute-force. True for high-entropy secrets (AWS keys, JWTs). Lower entropy secrets (emails, IPs) still benefit from deterministic pseudonymization.*

---

### 4. Insider Threat (Unauthorized Collaborator)
**Threat**: Team member receives packed repository and attempts to reconstruct secrets.

**Mitigation**:
- Vault and keys are stored in `~/.cloakmcp/`, **not** in the project directory.
- Only users with explicit vault access can unpack.
- Vault is encrypted with Fernet (AES-128-CBC + HMAC).

**Residual Risk**: LOW
*Assumes vault/key files are not shared via insecure channels (email, Slack, public storage).*

---

### 5. Side-Channel Information Leakage
**Threat**: Attacker infers secret structure from tag patterns or code logic.

**Mitigation**:
- Tags are deterministic but reveal no information about secret content (HMAC output is cryptographically random).
- Code logic remains visible (e.g., `if API_KEY == TAG-xxxxx`), revealing intent but not value.

**Residual Risk**: MEDIUM
*CloakMCP protects **content confidentiality**, not **intent semantics**. Adversary may infer "this is an API key" but cannot learn the key itself.*

---

### 6. Vault Corruption or Loss
**Threat**: Vault file corrupted, deleted, or lost; secrets unrecoverable.

**Mitigation**:
- CloakMCP provides `cloak vault-export` to create encrypted backups.
- Users should backup `~/.cloakmcp/` regularly.
- Auto-backup feature (v0.3.1+) creates `.cloak-backups/` before pack/unpack.

**Residual Risk**: MEDIUM
*Users must follow backup procedures. CloakMCP does not enforce automated cloud backup.*

---

## Threats Out of Scope

### 1. Compromised Developer Machine
**Threat**: Attacker gains root/admin access to developer's machine.

**Out of Scope**: CloakMCP assumes the local machine is trusted. If an attacker has root access:
- They can read `~/.cloakmcp/keys/` and decrypt vaults.
- They can intercept keystrokes, read memory, or install keyloggers.
- **No local-first tool can protect against this.**

**Recommendation**: Use full-disk encryption (BitLocker, FileVault, LUKS), strong OS passwords, and secure boot.

---

### 2. Brute-Force Attacks with Vault Access
**Threat**: Attacker obtains both vault file and encryption key, attempts to brute-force HMAC tags.

**Out of Scope**: If attacker has both vault and key:
- They can decrypt the vault and read all secrets directly.
- Brute-forcing tags is unnecessary.

**Recommendation**: Protect `~/.cloakmcp/` with OS-level encryption and filesystem permissions (0600).

---

### 3. Network-Based Attacks on Server Mode
**Threat**: Attacker exploits CloakMCP server (`uvicorn cloak.server:app --host 0.0.0.0`) over the network.

**Out of Scope**: CloakMCP server is designed for **localhost-only** use (`127.0.0.1`). Exposing it to LAN or internet:
- Transmits secrets over the network (defeats local-first model).
- Introduces network attack surface (DoS, token brute-force, RCE).

**Recommendation**: **DO NOT expose server to untrusted networks.** If required:
- Use TLS with valid certificates.
- Use strong authentication (rotate API tokens frequently).
- Use VPN or SSH tunneling.
- Apply strict firewall rules.

**See `SERVER.md` for comprehensive warnings.**

---

### 4. Quantum Computing Attacks
**Threat**: Future quantum computers break AES-128 or SHA-256.

**Out of Scope**: CloakMCP uses Fernet (AES-128-CBC + HMAC-SHA256):
- AES-128 provides 64-bit quantum security (Grover's algorithm).
- SHA-256 provides 128-bit quantum security (still secure).

**Recommendation**: If quantum threat becomes imminent, CloakMCP can migrate to AES-256 (trivial vault re-encryption).

---

### 5. Detection Evasion by Adversary
**Threat**: Attacker crafts secret formats that bypass CloakMCP detection rules.

**Out of Scope**: CloakMCP detects secrets via regex, entropy, and heuristics. Adversary with knowledge of detection rules can:
- Obfuscate secrets (base64 encode, split across lines).
- Use non-standard formats.

**Recommendation**:
- Regularly update detection rules (`examples/mcp_policy.yaml`).
- Use entropy detectors to catch obfuscated secrets.
- Add custom rules for organization-specific secret formats.

---

### 6. Physical Security
**Threat**: Attacker steals developer's laptop and extracts secrets from disk.

**Out of Scope**: CloakMCP stores secrets in plaintext (encrypted vault, but keys are on disk).

**Recommendation**: Use full-disk encryption and strong OS passwords.

---

## Attack Scenarios

### Scenario 1: Honest Developer, Curious LLM
**Setup**: Developer uses CloakMCP correctly: packs repository, sends to Claude, unpacks locally.

**Attack**: Claude (or provider) logs all inputs and attempts to reconstruct secrets.

**Outcome**:
- ✅ **PROTECTED**: Claude sees only `TAG-xxxxxx` strings.
- ✅ Tags are HMAC-based (cannot reverse without vault key).
- ✅ Developer unpacks locally; secrets never leave machine.

**Result**: **Attack fails.**

---

### Scenario 2: Accidental Public Commit
**Setup**: Developer forgets to pack, commits secrets to GitHub.

**Attack**: GitHub secret scanning detects AWS keys, notifies AWS, keys revoked.

**Outcome**:
- ❌ **NOT PROTECTED**: Secrets leaked to public repository.
- CloakMCP does not prevent this (user error).

**Recommendation**: Add pre-commit hook:
```bash
#!/bin/bash
cloak scan --policy examples/mcp_policy.yaml --input - < /dev/stdin
if [ $? -ne 0 ]; then
  echo "ERROR: Secrets detected in commit. Run 'cloak pack' first."
  exit 1
fi
```

**Result**: **Attack succeeds (user error).**

---

### Scenario 3: Malicious Collaborator
**Setup**: Team member receives packed repository, no vault access.

**Attack**: Attempts to reverse tags by:
1. Brute-forcing HMAC (infeasible without vault key).
2. Correlating tags across multiple packed repositories (deterministic, but still HMAC-protected).
3. Social engineering vault key from teammate.

**Outcome**:
- ✅ **PROTECTED** (attacks 1 & 2): HMAC prevents reversal.
- ❌ **NOT PROTECTED** (attack 3): Social engineering vault key succeeds.

**Recommendation**: Treat vault keys as sensitive as secrets themselves. Use secure key distribution (encrypted channels, password managers).

**Result**: **Attack fails (unless social engineering succeeds).**

---

### Scenario 4: Compromised Developer Machine
**Setup**: Attacker gains root access via malware (keylogger, RAT).

**Attack**: Reads `~/.cloakmcp/keys/` and `~/.cloakmcp/vaults/`, decrypts all secrets.

**Outcome**:
- ❌ **NOT PROTECTED**: Local machine compromise defeats all local-first tools.

**Recommendation**: Use OS-level security (antivirus, firewall, full-disk encryption, regular updates).

**Result**: **Attack succeeds (out of scope).**

---

### Scenario 5: Network Exposure (Server Mode)
**Setup**: Developer runs `uvicorn cloak.server:app --host 0.0.0.0 --port 8765` on public IP.

**Attack**: Remote attacker:
1. Brute-forces API token (default: 32-byte hex = 2^128 entropy, infeasible).
2. Exploits uvicorn/FastAPI vulnerability (e.g., DoS, RCE).
3. Intercepts unencrypted traffic (no TLS).

**Outcome**:
- ⚠️ **PARTIALLY PROTECTED**: API token brute-force infeasible.
- ❌ **NOT PROTECTED**: Network attacks (DoS, traffic interception).

**Recommendation**: **DO NOT expose server publicly.** If required, use TLS + VPN + firewall.

**Result**: **Attack may succeed (network exposure defeats local-first model).**

---

## Cryptographic Guarantees

### Vault Encryption
- **Algorithm**: Fernet (AES-128-CBC + HMAC-SHA256)
- **Key Derivation**: Random 32-byte key (256-bit entropy)
- **Authentication**: HMAC-SHA256 prevents tampering
- **Security Level**: 128-bit symmetric security (NIST approved through 2030+)

**Guarantees**:
- ✅ Vault contents confidential (AES-128).
- ✅ Vault integrity protected (HMAC-SHA256).
- ✅ No tampering possible without key.

**Assumptions**:
- Vault key stored securely (filesystem permissions 0600).
- No key leakage via logs, environment variables, or insecure channels.

---

### Tag Generation
- **Algorithm**: HMAC-SHA256 (keyed with vault encryption key)
- **Output**: Truncated to 12 hex characters (48-bit space)
- **Collision Probability**: ~1 in 16 million per vault

**Guarantees**:
- ✅ Tags deterministic (same secret → same tag).
- ✅ Tags cryptographically random (HMAC output indistinguishable from random).
- ✅ Tags non-reversible without vault key.

**Assumptions**:
- Vault key not leaked.
- HMAC-SHA256 remains secure (no practical pre-image attacks).

---

## Operational Assumptions

### Users Will:
1. **Pack before sharing**: Run `cloak pack` before sending code to LLMs or committing to repos.
2. **Secure vault**: Keep `~/.cloakmcp/` with strict permissions (0600 for keys, 0700 for directories).
3. **Backup vault**: Regularly export vaults (`cloak vault-export`) and store backups securely.
4. **Rotate keys**: Periodically re-key vaults (future: `cloak vault rekey`).
5. **Update policies**: Maintain up-to-date detection rules for new secret formats.

### Users Will Not:
1. **Share vault keys**: Never commit keys to repos, share via email/Slack, or log to files.
2. **Expose server**: Never run `cloak.server` with `--host 0.0.0.0` on public networks.
3. **Ignore warnings**: Heed dry-run previews and backup recommendations.

---

## Known Limitations

### 1. Policy Completeness
**Limitation**: Detection depends on regex/entropy rules. New secret formats may not be detected.

**Mitigation**: Regularly update `examples/mcp_policy.yaml`. Contribute new detectors to project.

---

### 2. False Positives/Negatives
**Limitation**: Regex detectors may match non-secrets (e.g., JWTs in test data). Entropy detectors may miss structured low-entropy secrets.

**Mitigation**: Use `cloak scan --dry-run` to preview detections. Tune policy thresholds. Use whitelists for known false positives.

---

### 3. Intent Semantics
**Limitation**: CloakMCP hides **values**, not **logic**. Code like `if API_KEY == TAG-xxxxx` reveals intent (this is an API key check) but not the key itself.

**Mitigation**: Accept this trade-off. Semantic obfuscation (renaming variables, removing comments) is out of scope.

---

### 4. Vault Portability
**Limitation**: Vaults are per-project (based on absolute path hash). Moving project directory breaks vault linkage.

**Mitigation**: Use `cloak vault-export` before moving. After moving, use `cloak vault-import` to restore.

---

### 5. Backup Overhead
**Limitation**: Auto-backup (v0.3.1+) creates `.cloak-backups/` directory, consuming disk space.

**Mitigation**: Periodically clean old backups. Use `--no-backup` flag for CI/automation (not recommended for interactive use).

---

## Compliance Notes

### GDPR / PII
CloakMCP can redact PII (emails, IP addresses, names) using policy rules. However:
- CloakMCP does not classify data automatically (user must configure detection rules).
- CloakMCP does not log PII to audit logs (only SHA-256 hashes).

**Recommendation**: Add organization-specific PII patterns to policy.

---

### SOC 2 / ISO 27001
CloakMCP supports security controls:
- **Access Control**: Vault keys separate from project data.
- **Audit Logging**: All detections logged to `audit/audit.jsonl`.
- **Encryption at Rest**: Vault encrypted with Fernet (AES-128).

**Recommendation**: Document CloakMCP usage in security policies. Implement key rotation procedures.

---

### NIST / FIPS
CloakMCP uses NIST-approved algorithms:
- AES-128-CBC (FIPS 197)
- HMAC-SHA256 (FIPS 198-1)

**Limitation**: Fernet implementation (`cryptography.io`) not FIPS-validated.

**Recommendation**: For FIPS compliance, replace Fernet with FIPS-validated library (e.g., OpenSSL FIPS module).

---

## Future Enhancements

### Planned (v0.4.0)
1. **Key Rotation**: `cloak vault rekey` command for re-encrypting vaults with new keys.
2. **Group Policies**: Inherit detection rules from organization-wide baselines.
3. **Detection Catalog**: Published list of all built-in detectors with accuracy metrics.

### Under Consideration (v0.5.0+)
1. **AES-256 Option**: Upgrade vault encryption to AES-256-GCM for quantum resistance.
2. **OS Keyring Integration**: Store vault keys in OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service).
3. **Hardware Token Support**: Encrypt vault keys with YubiKey or TPM.
4. **Cloud KMS Integration**: Optional vault encryption with AWS KMS, Azure Key Vault, or GCP KMS (reduces local-first guarantee).

---

## References

- **Fernet Specification**: https://github.com/fernet/spec/blob/master/Spec.md
- **NIST Cryptographic Standards**: https://csrc.nist.gov/publications
- **OWASP Secrets Management**: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- **CloakMCP GitHub**: https://github.com/ovitrac/CloakMCP
- **CloakMCP Documentation**: See `README.md`, `SERVER.md`, `QUICKREF.md`

---

## Contact

For security issues, please email: `olivier.vitrac@adservio.com` (PGP key available on request).

For general questions, open a GitHub issue: https://github.com/ovitrac/CloakMCP/issues

---

**Last Updated**: 2025-11-12
**Version**: 0.3.1-alpha
**Author**: Olivier Vitrac (Adservio Innovation Lab)
