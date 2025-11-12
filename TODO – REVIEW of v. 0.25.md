# TODO – `REVIEW of v. 0.25`

## 1. Positioning & differentiation

**What works**

- Clear niche: *local-first, reversible sanitization for LLM workflows*, not just generic “secret scan like everyone else”. That’s a real gap between:
  - scanners (ggshield, trivy, gitleaks, detect-secrets) that detect but don’t round-trip, [GitHub+2Aqua Security+2](https://github.com/GitGuardian/ggshield?utm_source=chatgpt.com)
  - secret managers / SOPS-style tooling focused on infra/KMS, not LLM workflows. [GitHub+1](https://github.com/getsops/sops?utm_source=chatgpt.com)
- The story “code with tags to LLM → restore from local vault” is crisp and visually well-supported in the README. README

**Issues**

1. **Name collision / ambiguity**:
   - `CloakMCP` with CLI `cloak`:
     - “MCP” is heavily overloaded (Anthropic’s Model Context Protocol, etc.), and `cloak` as a binary is likely to conflict.
   - This hurts discoverability and adoption; looks like “yet another MCP-related thing” instead of a standalone primitive.
2. **Competitive landscape underplayed**:
   - README hints inspiration from ggshield/SOPS etc., but doesn’t explicitly articulate:
     - *When should a team use CloakMCP instead of ggshield + SOPS + in-house scripts?*
   - As written, it can be misread as “a nicer secret scanner” rather than “a deterministic redaction/proxy layer purpose-built for LLMs”.

**Concrete suggestions**

- Consider renaming the binary (e.g. `cloak`, `cloakmcp`, `cloak-llm`) and making the LLM-centric reversible workflow the first 3 lines of the README.
- Add a short “Compared to existing tools” table making the differentiator explicit (reversible tags + local vault + LLM workflow).

------

## 2. Security model & cryptography

Overall model is **sound in spirit** (local vault + tag indirection), but some details in the README are either underspecified or oversold.

### 2.1 Vault & keys

From docs: Fernet-based AES-128 vault in `~/.cloakmcp/vaults/` with keys in `~/.cloakmcp/keys/`.

**Strengths**

- Separation of concerns: tags in repo, vault+keys out-of-repo → good.
- Per-project slug + per-project key is sane.
- Permissions and local-only design are clearly documented.

**Concerns**

1. **AES-128 vs expectations**:
   - Fernet’s AES-128 is fine in practice, but not for a security product.
   - Security people will ask “Why not 256?”; the project should either:
     - justify Fernet (“battle-tested, authenticated encryption, 128 is enough”), or
     - offer an AES-256 / configurable backend.
   - Right now it reads accidental rather than deliberate.
2. **Key management story is minimal**:
   - Flat files only; no OS keyring, no KMS, no hardware-backed storage.
   - For a “production-ready beta”, larger orgs will want:
     - non-interactive bootstrap,
     - rotation procedure,
     - migration path between machines.
   - Some of this exists (vault export/import), but it’s scattered; the README doesn’t clearly state the operational playbook.

**Recommendation**

- Tighten the “Vault Security Model” with explicit statements:
  - AEAD scheme,
  - key rotation procedure,
  - recommended backup + restore workflow.
- Either own Fernet/AES-128 as a conscious design or allow pluggable crypto.

------

## 3. Tags, determinism & brute-force resistance

This is the **most critical weak spot in the current messaging**.

The project describes:

- Deterministic tags.
- Example format: `TAG-2f1a8e3c9b12`.
- Statement: tags are truncated SHA-256 with 12 hex chars → “2^48 attempts minimum (computationally infeasible)”. README

Problems:

1. **2^48 is not “computationally infeasible” anymore**:
   - For generic secrets maybe borderline, but:
     - Many secrets (API keys, emails, internal hosts) are highly structured or low entropy.
     - An attacker can massively shrink the search space.
   - If tags are **un-keyed** hashes of the secret, this is absolutely brute-forceable for AWS keys, emails, many API tokens.
2. **Mismatch between pseudonymization and tags**:
   - Elsewhere the project mentions HMAC-based pseudonymization (`PZ-xxxxx`) with a secret key in `keys/mcp_hmac_key`. Good.
   - But for vault mapping / `TAG-...` the project implies pure truncated hashes.
   - If tags are un-keyed, they leak:
     - equality (intended),
     - and allow offline guessing if an attacker suspects a value.
   - That’s a very different guarantee than what some of the text suggests.
3. **Docs blur threat model**:
   - The project correctly says: “Tags are one-way — cannot reverse without vault”.
   - That’s not strictly true if tags are un-keyed hashes and the candidate space is small; an attacker *can* reverse by guessing without the vault.
   - For secrets like `admin@company.com`, trivial.

**Recommendations (high priority)**

- The project should decide **one** of these and document precisely:
  1. **Keyed tags (recommended)**:
     - Use HMAC(secret_key, secret) truncated → `TAG-...`.
     - Store the HMAC key next to vault key.
     - Then “cannot reverse without vault environment” is accurate.
  2. **Unkeyed, but honest**:
     - Keep SHA-256 truncated tags, but the project should reverse and:
       - Explicitly state: “protects against accidental disclosure, *not* a defense against a determined attacker with guesses”.
       - Remove “computationally infeasible” wording.
- The project makes the policy: *all deterministic identifiers used in shared code are HMAC-based, using non-public keys*.
- Document collision risk from 12 hex chars and whether the project handle collisions.

Right now, this is the **main place** where marketing slightly overpromises relative to the likely implementation.

------

## 4. Threat model clarity

The project largely targets:

- untrusted LLM provider,
- trusted local machine,
- accidental repo leaks. SERVER

This is okay, but:

1. Some parts of the README read as if CloakMCP is robust against strong adversaries; others read as “safety rails for developers”.
2. The current model **assumes no compromise** of `~/.cloakmcp/`. That’s common, but it should be written as an assumption, not a guarantee.
3. Remote / LAN server mode:
   - The project *doe*s show `--host 0.0.0.0` and Docker recipes.
   - That contradicts the early, strong “localhost only” story, and deserves a harsher disclaimer:
     - “If exposed beyond localhost, the project is now transmitting secrets over the network; use TLS and treat it as a high-value target.”

**Recommendations**

- Add a one-page, explicit threat model:
  - In scope:
    - Accidental sharing with LLMs / GitHub.
    - Honest-but-curious LLM providers.
  - Out of scope:
    - Compromised dev boxes.
    - Users who `uvicorn --host 0.0.0.0` on the open internet with no TLS.
    - Brute force on low-entropy secrets given tags (until the project fixes tags).
- In server docs, move “0.0.0.0” behind **big red warning**.

------

## 5. Architecture & implementation choices

Based on README/SERVER docs only.

**Strengths**

- Clear modular breakdown: scanner, policy engine, actions, vault, API server.
- `pack/unpack` concept for whole directories is powerful and differentiating.
- `.mcpignore` pattern consistent with `.gitignore` mental model.
- Audit log design (hashes, rule IDs, etc.) is good.

**Potential issues / questions**

1. **“Modify in place” semantics for `pack`/`unpack`**:
   - High risk UX: a mistaken `cloak pack` on wrong path can mass-edit files.
   - The project warns, but:
     - no default dry-run,
     - no built-in git workspace safety check,
     - no snapshot/backup mechanism.
   - For a tool whose failure mode is “silently mangled secrets”, this is dangerous.
2. **CLI ergonomics & naming consistency**
   - Binary `cloak` vs project `CloakMCP` vs Model Context Protocol.
   - Mixing:
     - `cloak scan/sanitize/pack/unpack`
     - vault-export/import/stats
   - It’s functional, but crowded; consider hierarchical commands (`cloak vault export`, etc.) for clarity.
3. **Server + CLI code paths**
   - Docs suggest a lot of features: rate limiting, token auth, HMAC caching, etc.
   - For credibility, ensure:
     - server endpoints and CLI share the same policy + action engine,
     - no drift between behavior in docs and actual code.

------

## 6. Detection engine realism

The project presents a solid baseline: AWS, GCP, JWTs, SSH/X.509, URLs, IPs, entropy, custom regex. README

However:

- Competing tools (ggshield, trivy, gitleaks) market hundreds of detectors + verification heuristics. [GitHub+2Aqua Security+2](https://github.com/GitGuardian/ggshield?utm_source=chatgpt.com)
- The project does not state:
  - how many detectors it actually ships,
  - how it manages false positives / negatives,
  - performance characteristics at scale (monorepos, vendor dirs).

**Recommendations**

- Add an explicit “Detection scope & limitations” section:
  - list exactly what’s supported and what isn’t;
  - show some benchmarks on typical repos.
- Consider aligning some detector names/semantics with popular tools to ease migration of policies.

------

## 7. Documentation, claims & polish

**Good**

- README is unusually complete: diagrams, workflows, IDE integration, CI hooks, server docs, etc.
- Strong narrative coherence across docs.

**Critical notes**

1. **“Production-Ready Beta” sounds risky**
   - Combined with:
     - not-yet-on-PyPI,
     - evolving crypto/tag story,
     - “Future” install path.
   - This risks undermining trust; security-conscious users are allergic to “beta” + “production-ready” in the same line.
2. **Some sections overclaim slightly**
   - The 2^48 “computationally infeasible” line (already discussed).
   - “LLM cannot access secrets” without the caveat about guessability / side channels.
   - “Never network exposed” in one paragraph vs Docker/0.0.0.0 examples later.
3. **Length vs entry barrier**
   - README is long; excellent for depth, but first-time users may bounce.
   - The projectc does have Quick Start, but it’s buried.

**Recommendations**

- Tone down guarantees; use precise language.
- Add a very small “2-minute getting started” at top:
  - install,
  - create policy from example,
  - sanitize one file,
  - show before/after.
- Move some of the heavy detail into `/docs`.