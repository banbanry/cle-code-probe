# Contributing to CLE Code Probe

Thank you for your interest in contributing to CLE Code Probe. This project is the engineering instantiation of the PEF (Anchored Determinism) Meta-Architecture.

## Types of Contributions

### 1. Architecture Challenges (Most Valuable)

The most valuable contribution is an **architecture challenge** — a rigorous critique of the PEF anchoring mechanism, the onion pipeline design, or the anti-fraud protocol. If you can demonstrate that:

- The π-anchor mechanism is forgeable
- The onion pipeline has a bypass
- The V1-V6 anti-fraud protocol can be defeated
- The Byzantine canary injection has a false acceptance path

Please open an issue with the `architecture-challenge` label. Include:
- The specific claim you are challenging
- A counterexample or proof
- The expected vs actual behavior

### 2. Bug Reports

If you find a bug in the deterministic probe, the π-anchor scheduling, or the evidence fusion:

- Include the source code that triggers the bug
- Include the command you ran
- Include the full output
- Expected vs actual behavior

### 3. New Operators / Signatures

If you want to add a new detection operator or signature:

- The operator must be deterministic (no AI judgment)
- The operator must have a clear causal chain: P[condition] → E[mechanism] → F[consequence]
- Include test cases (positive and negative)
- Add the operator to the appropriate module (pef_operators.py, python_operators.py, or a new language module)

### 4. New Language Support

If you want to add support for a new language (Java, Rust, Go, etc.):

- Create a new operator module (e.g., `java_operators.py`)
- Add auto-detection in `cle_deploy.py`
- Add language-specific signatures to `signature_library_data.py`
- Include test cases

## Development Setup

```bash
# Clone
git clone https://github.com/banbanry/cle-code-probe.git
cd cle-code-probe

# No external dependencies (stdlib only)
# Run verification
python resources/cle_deploy.py verify

# Run Byzantine tests
python resources/cle_deploy.py byzantine

# Run full regression (49 tests)
python resources/cle_deploy.py audit resources/cle_deploy.py
```

## Code Standards

1. **Determinism first** — All detection logic must be reproducible. No randomness, no AI judgment in Layer 1.
2. **π-anchor integrity** — The `SecurePiDigitProvider` must never be bypassed. All scheduling must go through the π-anchor.
3. **Audit chain** — All findings must be appended to the SHA-256 audit chain. No findings may be emitted without a chain hash.
4. **Causal chain** — Every finding must include `causal_chain`: P[condition] → E[mechanism] → F[consequence].
5. **Severity levels** — P0 (crash/data loss/security), P1 (latent risk), P2 (code quality), P3 (style).
6. **Source watermark** — Every new file must include the source watermark header.

## Testing

Before submitting a PR:

1. Run `python resources/cle_deploy.py verify` — all 17 modules must load
2. Run `python resources/cle_deploy.py byzantine` — all 11 scenarios must PASS
3. Run `python resources/cle_deploy.py audit <your_test_file>` — no crashes
4. If you added an operator, include both positive (detects) and negative (no false positive) test cases

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-operator`)
3. Make your changes
4. Run all tests
5. Commit with a clear message
6. Open a PR with:
   - What you changed
   - Why you changed it
   - Test results
   - Any limitations

## Architecture Principles (Do Not Violate)

1. **The anchor produces the potential difference** — No π-anchor = no scheduling = no audit.
2. **Layer 1 is deterministic, Layer 2 is verified, Layer 3 is unforgeable** — Do not mix responsibilities.
3. **AI claims are never trusted** — Every AI finding must pass V1-V6 anti-fraud verification.
4. **The audit chain is append-only** — No deletion, no modification, only append.
5. **Graceful degradation, not crash** — π cache exhaustion → GAMMA, not exception. Empty input → GAMMA, not crash.

## Questions?

Open an issue with the `question` label. Architecture questions are especially welcome.

---

*CLE Code Probe © 2026 banbanry. Anchored Determinism Code Audit.*
