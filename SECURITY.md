# Security Policy

## Supported Versions

| Version | Supported          | Notes                                |
| ------- | ------------------ | ------------------------------------ |
| 0.21.2  | :white_check_mark: | Current release (post-quantum ready) |
| ≤ 0.21.1| :x:                | Pre-PQ, do not use                   |

## Reporting a Vulnerability

Soqucoin Core is a post-quantum cryptocurrency with native Dilithium (ML-DSA-44) signatures and PAT batch attestation. LatticeFold+ batch verification is deprecated and its deployment does not activate on any network. Security is therefore non-negotiable.

To report a security vulnerability, please send a PGP-encrypted email to:

**Casey Wilson**  
E-mail: dev@soqu.org  
PGP Key Fingerprint: Available on request at dev@soqu.org

Alternatively, encrypted DMs are accepted via X/Twitter @saborealabs (preferred for speed).

We follow responsible disclosure:  
- You will receive an acknowledgement within 12 hours.  
- A fix will be developed on a private branch and shipped within 72 hours for critical consensus issues.  
- Public disclosure occurs only after the fix is live on mainnet or a credible timeline is agreed.

Bounties: Critical consensus bugs (remote chain split, inflation, verifiable preimage) are eligible for ≥ 5000 SOQ bounty at mainnet launch, paid from block 100 001 reward.

## Cryptographic Security Model

### Post-Quantum Signatures: Dilithium (ML-DSA-44)

Soqucoin uses NIST FIPS 204 Dilithium (ML-DSA-44) as its **sole signature scheme**. Legacy ECDSA is permanently disabled at consensus level (`dilithiumOnlyHeight = 0` on all networks). Key properties:

| Property | Implementation | Status |
|----------|---------------|--------|
| Algorithm | ML-DSA-44 (Dilithium2) | NIST-standardized |
| Security level | 128-bit classical and quantum | NIST Level 2 |
| Reference implementation | CRYSTALS-Dilithium reference code | Unmodified |
| Nonce derivation | Deterministic (K ‖ μ) | Prevents nonce reuse |

### Constant-Time Execution Policy

The following operations are implemented with constant-time guarantees to prevent timing side-channel attacks:

| Operation | File | Method |
|-----------|------|--------|
| Dilithium signing | `crypto/dilithium/sign.c` | NIST reference implementation (no data-dependent branches on secret data) |
| HMAC tag comparison | `wallet/pqwallet/pqcrypto.cpp` | XOR-accumulate comparison (`diff |= a ^ b`), prevents timing side-channel |
| Secret key operations | `wallet/pqwallet/pqwallet.cpp` | SecureBytes class with `memory_cleanse()` |

**Non-constant-time by design**: `make_hint()` in `crypto/dilithium/rounding.c` uses data-dependent branches, but operates only on public hint bits (not secret key material), matching NIST FIPS 204 reference exactly.

### Memory Security

Sensitive cryptographic material (private keys, derived keys, seed phrases) is protected by the `SecureBytes` class:

- **Memory locking**: `mlock()` prevents swapping to disk (with failure logging)
- **Explicit zeroing**: `memory_cleanse()` / `explicit_bzero()` prevents compiler optimization of zeroing
- **RAII lifecycle**: Keys are wiped on destruction via `SecureBytes::Wipe()`
- **No logging**: Contents are never logged, printed, or passed to non-security functions

### Known Limitations

The following items are acknowledged and documented for transparency:

| Item | Risk | Status |
|------|------|--------|
| `SecureBytes::Wipe()` vs compiler optimization | Low | Uses `memory_cleanse()` (volatile barrier) |
| `mlock()` is OS-dependent | Low | Failure now logged; Linux/macOS only |
| No binary code signing | Medium | Planned for pre-mainnet |
| No RPC rate limiting | Low | Planned for post-mainnet |
| Formal verification of constant-time | Low | Relies on NIST reference implementation review |

For detailed threat analysis, see `doc/wallet/WALLET_THREAT_MODEL.md`.  
For cryptographic specifications, see `doc/wallet/WALLET_CRYPTOGRAPHIC_SPEC.md`.

Thank you for helping keep the first quantum-resistant PoW chain unbreakable.

- Casey Wilson, Soqucoin Founder   
February 2026