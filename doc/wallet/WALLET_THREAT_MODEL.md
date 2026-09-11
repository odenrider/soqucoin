# Soqucoin Wallet Threat Model

> **Version**: 1.1 | **Date**: February 6, 2026
> **Classification**: Public — Open Source Transparency
> **Methodology**: STRIDE + OWASP + Custom PQ Extensions
> **Review Status**: Pre-Audit Final — Halborn Review Feb 10, 2026

---

## 1. Executive Summary

This document defines the threat model for the Soqucoin post-quantum wallet (`libsoqucoin-wallet`). It identifies assets, adversaries, attack surfaces, and mitigations using industry-standard STRIDE methodology, extended for post-quantum cryptographic threats.

### Scope

| Component | In Scope | Notes |
|-----------|----------|-------|
| Key generation (`PQKeyPair`) | ✅ | Dilithium ML-DSA-44 |
| Key storage (`SecureBytes`) | ✅ | Memory protection |
| Wallet file encryption (`pqcrypto.cpp`) | ✅ | AES-256-CBC + HMAC |
| Address encoding (`PQAddress`) | ✅ | Bech32m |
| Transaction signing | ✅ | Dilithium signatures |
| RPC interface | ✅ | `rpc_pqwallet.cpp` |
| GUI wallet | ❌ | Future scope |
| Hardware wallet integration | ❌ | Future scope |

---

## 2. Assets Under Protection

### 2.1 Critical Assets (Loss = Total Fund Loss)

| Asset | Location | Confidentiality | Integrity | Availability |
|-------|----------|-----------------|-----------|--------------|
| **Private Keys** | Memory, wallet.dat | 🔴 CRITICAL | 🔴 CRITICAL | 🟠 HIGH |
| **Seed Phrase** | User-managed | 🔴 CRITICAL | 🔴 CRITICAL | 🔴 CRITICAL |
| **Blinding Factors** | Memory (Stage 3+) | 🔴 CRITICAL | 🔴 CRITICAL | 🔴 CRITICAL |

### 2.2 High-Value Assets (Compromise = Privacy/Usability Loss)

| Asset | Location | Confidentiality | Integrity | Availability |
|-------|----------|-----------------|-----------|--------------|
| **Public Keys** | wallet.dat, chain | 🟡 LOW | 🟠 HIGH | 🟠 HIGH |
| **Addresses** | wallet.dat, chain | 🟡 LOW | 🟠 HIGH | 🟠 HIGH |
| **Transaction History** | wallet.dat | 🟠 HIGH | 🟠 HIGH | 🟡 MEDIUM |
| **Wallet Metadata** | wallet.dat | 🟠 HIGH | 🟡 MEDIUM | 🟡 MEDIUM |

### 2.3 Operational Assets

| Asset | Location | Impact if Compromised |
|-------|----------|----------------------|
| Wallet passphrase | User memory | Full fund loss |
| Encryption key (derived) | Memory only | Session compromise |
| RPC credentials | soqucoin.conf | Remote wallet control |

---

## 3. Adversary Model

### 3.1 Adversary Classes

| Class | Capability | Resources | Motivation | Example |
|-------|------------|-----------|------------|---------|
| **A1: Script Kiddie** | Public exploits, malware | Low | Opportunistic theft | Commodity malware |
| **A2: Targeted Attacker** | Custom malware, social engineering | Medium | Targeted theft | Exchange attacker |
| **A3: Sophisticated Attacker** | 0-days, advanced persistence | High | High-value targets | APT group |
| **A4: Nation-State (Classical)** | Full spectrum, legal compulsion | Very High | Surveillance, seizure | Law enforcement |
| **A5: Nation-State (Quantum)** | Cryptographically-relevant QC | Extreme | Long-term decryption | Future adversary |

### 3.2 Quantum Adversary Timeline (NIST Guidance)

| Timeframe | CRQC Availability | Soqucoin Mitigation |
|-----------|-------------------|---------------------|
| 2026-2030 | Unlikely | Dilithium provides future-proofing |
| 2030-2035 | Possible | Dilithium (ML-DSA-44) provides ~128-bit PQ security; LatticeFold+ is deprecated and not part of the security argument |
| 2035+ | Probable | Migration path to stronger parameters if needed |

**Design Decision**: Soqucoin uses NIST Level 2 (Dilithium2/ML-DSA-44) which provides 128-bit security against both classical and quantum adversaries per NIST SP 800-208.

---

## 4. Attack Surface Analysis

### 4.1 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────┐
│                         USER DOMAIN                                  │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐  │
│  │  Seed Phrase    │    │  Passphrase     │    │  User Intent    │  │
│  │  (paper/metal)  │    │  (memory)       │    │  (UI actions)   │  │
│  └────────┬────────┘    └────────┬────────┘    └────────┬────────┘  │
│           │                      │                      │            │
└───────────┼──────────────────────┼──────────────────────┼────────────┘
            │                      │                      │
            ▼                      ▼                      ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    WALLET APPLICATION DOMAIN                         │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    MEMORY (Trusted)                          │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │    │
│  │  │ SecureBytes  │  │ Private Keys │  │ Derived Keys │       │    │
│  │  │ (mlock'd)    │  │ (Dilithium)  │  │ (HKDF)       │       │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘       │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              │                                       │
│  ┌───────────────────────────┼───────────────────────────────────┐  │
│  │                     STORAGE (Encrypted)                        │  │
│  │  ┌──────────────────────────────────────────────────────┐     │  │
│  │  │            wallet.dat (AES-256-CBC + HMAC)            │     │  │
│  │  └──────────────────────────────────────────────────────┘     │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                              │                                       │
└──────────────────────────────┼───────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    NETWORK DOMAIN (Untrusted)                        │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐  │
│  │  P2P Network    │    │  RPC Clients    │    │  Blockchain     │  │
│  │  (peers)        │    │  (local only)   │    │  (public)       │  │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.2 Entry Points

| Entry Point | Trust Level | Attack Vectors |
|-------------|-------------|----------------|
| **Seed Import** | User-controlled | Malicious seed, clipboard hijack |
| **Passphrase Entry** | User-controlled | Keylogger, shoulder surfing |
| **RPC Interface** | Local only (default) | Credential theft, MITM if exposed |
| **Wallet File Load** | File system | Malicious wallet file, path traversal |
| **Transaction Signing** | Application | Malicious TX construction |
| **Address Display** | Application | Address substitution attack |


### 4.3 Key Derivation Lifecycle

The wallet encryption follows Encrypt-then-MAC with cascading KDF:

```
  User Passphrase + Random Salt
         │
         ▼
  ┌────────────────────────────────┐
  │  KDF Cascade:                  │
  │  1. Argon2id (t=3, m=64MB)    │
  │  2. scrypt   (N=32768)        │
  │  3. PBKDF2   (600K iter)      │
  └──────────┬─────────────────────┘
             ▼
       AES-256 Key (32 bytes)
         │
    ┌────┴────┐
    ▼         ▼
  Encrypt   HMAC-SHA256(key, ciphertext ‖ IV)
  AES-CBC     │
  + PKCS7     ▼
            16-byte tag (truncated)

  Stored: [salt ‖ IV ‖ ciphertext ‖ tag]
```

**Decrypt order**: Derive key → recompute HMAC → constant-time tag compare → **only then** AES-CBC decrypt → PKCS7 unpad → `memory_cleanse()` key.

**Security properties**:
- **KDF cascade**: Prefers memory-hard Argon2id; falls back if OpenSSL lacks support
- **Encrypt-then-MAC**: Ciphertext authenticated before decryption (prevents padding oracles)
- **HMAC (RFC 2104)**: `CHMAC_SHA256` with inner/outer key schedule, resistant to length-extension
- **Constant-time verification**: XOR-accumulate tag comparison prevents timing side-channels

---

## 5. STRIDE Threat Analysis

### 5.1 Spoofing Identity

| Threat | Target | Attack | Mitigation | Status |
|--------|--------|--------|------------|--------|
| **S1** | Address verification | Attacker substitutes displayed address | Address checksum validation | ✅ Bech32m |
| **S2** | RPC authentication | Attacker impersonates authorized client | Cookie-based auth, localhost-only | ✅ Implemented |
| **S3** | Transaction origin | Attacker forges transaction signature | Dilithium signature verification | ✅ Implemented |

### 5.2 Tampering

| Threat | Target | Attack | Mitigation | Status |
|--------|--------|--------|------------|--------|
| **T1** | Wallet file | Modify encrypted wallet data | HMAC-SHA256 integrity check (Encrypt-then-MAC) | ✅ Implemented |
| **T2** | Transaction | Modify TX before signing | Sign full TX, verify before broadcast | ✅ Implemented |
| **T3** | Memory | Modify keys in memory | SecureBytes + process isolation | ⚠️ OS-dependent |
| **T4** | Binary | Trojanized wallet binary | Code signing (planned) | ⬜ TODO |
| **T5** | Padding oracle | Decrypt ciphertext via padding errors | Encrypt-then-MAC: tag verified before decryption | ✅ Implemented |

### 5.3 Repudiation

| Threat | Target | Attack | Mitigation | Status |
|--------|--------|--------|------------|--------|
| **R1** | Transaction | Deny having made transaction | Blockchain immutability + Dilithium | ✅ By design |
| **R2** | Key ownership | Deny owning address | Signature proves ownership | ✅ By design |

### 5.4 Information Disclosure

| Threat | Target | Attack | Mitigation | Status |
|--------|--------|--------|------------|--------|
| **I1** | Private keys | Memory dump, core dump | SecureBytes::Wipe(), disable core dumps | ⚠️ Partial |
| **I2** | Wallet passphrase | Keylogger, clipboard | Secure input (GUI), no clipboard | ⬜ GUI TODO |
| **I3** | Transaction graph | Blockchain analysis | Future: Stealth addresses | ⬜ Stage 3 |
| **I4** | Wallet file | Unauthorized file access | AES-256-CBC + HMAC-SHA256 encryption | ✅ Implemented |
| **I5** | Seed phrase | Physical observation | User responsibility | 📋 Documented |
| **I6** | Side channels | Timing attacks on signing | Constant-time Dilithium ref impl | ✅ Verified (NIST ref impl; `make_hint()` branches are on public data only) |
| **I7** | MAC tag | Timing leak on tag comparison | Constant-time XOR-accumulate comparison | ✅ Implemented |

### 5.5 Denial of Service

| Threat | Target | Attack | Mitigation | Status |
|--------|--------|--------|------------|--------|
| **D1** | Wallet availability | Ransomware encrypts wallet | Backup documentation | 📋 Documented |
| **D2** | Memory exhaustion | Large malicious inputs | Input validation, limits | ✅ Implemented |
| **D3** | RPC flooding | Excessive RPC requests | Rate limiting | ⬜ TODO |

### 5.6 Elevation of Privilege

| Threat | Target | Attack | Mitigation | Status |
|--------|--------|--------|------------|--------|
| **E1** | Wallet process | Buffer overflow → code execution | Memory-safe practices, ASLR | ⚠️ C++ risk |
| **E2** | Passphrase bypass | Exploit to skip decryption | Fail-closed design | ✅ Implemented |
| **E3** | RPC privileges | Escalate to admin commands | Capability-based RPC auth | ⬜ TODO |

---

## 6. Post-Quantum Specific Threats

### 6.1 Harvest Now, Decrypt Later (HNDL)

| Threat | Description | Soqucoin Mitigation |
|--------|-------------|---------------------|
| **PQ1** | Adversary captures encrypted wallet file, decrypts with future QC | AES-256 remains PQ-secure (Grover's provides 128-bit) |
| **PQ2** | Adversary captures signatures, derives private key with QC | Dilithium is PQ-secure by NIST FIPS 204 |
| **PQ3** | Adversary captures ECDH key exchange, derives shared secret | Not applicable - no legacy ECDH in wallet |

### 6.2 Shor's Algorithm Resistance

| Classical Primitive | Vulnerable | Soqucoin Replacement |
|---------------------|------------|---------------------|
| ECDSA signatures | ✅ Vulnerable | Dilithium ML-DSA-44 |
| secp256k1 key agreement | ✅ Vulnerable | Not used |
| RSA encryption | ✅ Vulnerable | Not used |
| SHA-256 | ❌ Secure (Grover's halves bits) | Used as-is |
| AES-256 | ❌ Secure (Grover's halves bits) | Used as-is |

### 6.3 Lattice-Specific Attacks

| Attack | Description | Mitigation |
|--------|-------------|------------|
| **LWE Key Recovery** | Solve underlying lattice problem | Parameters chosen for 128-bit security |
| **Signature Forgery** | Forge Dilithium signature | NIST-vetted parameters, reference impl |
| **Nonce Reuse** | Reuse nonce in signing leaks key | Deterministic nonce derivation |
| **Fault Injection** | Induce faults during signing | Signature verification after sign |

---

## 7. Security Assumptions

### 7.1 Cryptographic Assumptions

| Assumption | Confidence | Basis |
|------------|------------|-------|
| Dilithium is secure at Level 2 | High | NIST FIPS 204 standardization |
| AES-256 provides 128-bit PQ security | High | Grover's algorithm analysis |
| HMAC-SHA256 is collision-resistant | High | No practical attacks known |
| PBKDF2/Argon2 provides key stretching | High | Industry standard |
| Host CSPRNG provides quality entropy | Medium | OS-dependent |

### 7.2 Implementation Assumptions

| Assumption | Status | Verification |
|------------|--------|--------------|
| Dilithium reference impl is constant-time | ✅ Verified | NIST FIPS 204 reference code; `make_hint()` branches operate on public data only |
| SecureBytes::Wipe() actually clears memory | ⚠️ Assumed | Compiler may optimize out |
| mlock() prevents swap exposure | ⚠️ OS-dependent | Linux/macOS only |
| Process memory is isolated | ⚠️ Assumed | Depends on OS security |

### 7.3 Operational Assumptions

| Assumption | Owner | Mitigation if False |
|------------|-------|---------------------|
| User keeps seed phrase secure | User | Cannot mitigate |
| User chooses strong passphrase | User | Entropy estimation (TODO) |
| Host system is not compromised | User | Cannot fully mitigate |
| Wallet binary is authentic | User | Code signing (TODO) |

---

## 8. Security Controls Summary

### 8.1 Implemented Controls

| Control | Implementation | Covers Threats |
|---------|----------------|----------------|
| **Dilithium Signatures** | `PQKeyPair::Sign()` | S3, R1, R2, PQ2 |
| **Bech32m Addresses** | `PQAddress::Encode()` | S1 |
| **Wallet Encryption** | `WalletCrypto::Encrypt()` | I4, PQ1 |
| **HMAC-SHA256 Integrity** | `CHMAC_SHA256` (RFC 2104) | T1, T5 |
| **Constant-Time Tag Comparison** | XOR-accumulate in `Decrypt()` | I7 |
| **SecureBytes** | `SecureBytes::Wipe()` via `memory_cleanse()` | I1 |
| **Localhost RPC** | Default configuration | S2 |
| **Input Validation** | Throughout codebase | D2, E1 |
| **Encrypt-then-MAC** | Tag verified before decryption | T5 |

### 8.2 Controls Requiring Verification

| Control | Concern | Verification Method |
|---------|---------|---------------------|
| Constant-time signing | Timing side channels | NIST ref impl verified; `make_hint()` on public data |
| Constant-time tag comparison | Compiler optimization | XOR-accumulate pattern (`diff |= a ^ b`) |
| Memory wiping | Compiler optimization | `memory_cleanse()` uses `volatile`; assembly inspection recommended |
| Entropy quality | Weak randomness | `GetStrongRandBytes()` → OS CSPRNG; NIST SP 800-90B testing |

### 8.3 Controls Not Yet Implemented

| Control | Priority | Target |
|---------|----------|--------|
| Binary code signing | 🟠 High | Pre-mainnet |
| RPC rate limiting | 🟡 Medium | Post-mainnet |
| Passphrase entropy check | 🟡 Medium | GUI wallet |
| Core dump prevention | 🟡 Medium | Production config |
| Stealth addresses | 🟡 Medium | Stage 3 |

---

## 9. Risk Register

| Risk ID | Threat | Likelihood | Impact | Risk Level | Mitigation Status |
|---------|--------|------------|--------|------------|-------------------|
| R-001 | Private key theft via memory dump | Medium | Critical | 🔴 HIGH | ⚠️ SecureBytes partial |
| R-002 | Side-channel key extraction | Low | Critical | 🟡 LOW | ✅ Verified (NIST ref impl) |
| R-003 | Wallet file brute force | Low | Critical | 🟡 LOW | ✅ Argon2id + AES-256 |
| R-004 | Address substitution | Medium | High | 🟠 MEDIUM | ✅ Bech32m checksum |
| R-005 | RPC credential theft | Low | High | 🟡 LOW | ✅ Localhost default |
| R-006 | Quantum key recovery | Very Low (2026) | Critical | 🟡 LOW | ✅ Dilithium |
| R-007 | Seed phrase compromise | Medium | Critical | 🔴 HIGH | 📋 User responsibility |
| R-008 | Blinding factor loss (GAP-010) | High | High | 🔴 HIGH | ⬜ Fix in progress |
| R-009 | Padding oracle attack | Very Low | High | 🟡 LOW | ✅ Encrypt-then-MAC |
| R-010 | MAC tag timing leak | Low | Medium | 🟡 LOW | ✅ XOR-accumulate |

---

## 10. Recommendations for Auditors

### 10.1 Priority Focus Areas

1. **Dilithium Implementation** - Verify reference impl integration is correct
2. **Key Generation Entropy** - Verify CSPRNG usage throughout
3. **SecureBytes Effectiveness** - Verify memory wiping at assembly level
4. **Wallet File Crypto** - Verify AES-CBC + HMAC construction
5. **Nonce Handling** - Verify no nonce reuse in Dilithium signing

### 10.2 Suggested Test Scenarios

| Test | Description | Expected Result |
|------|-------------|-----------------|
| **TC-001** | Generate key with low entropy | Should fail or warn |
| **TC-002** | Sign with same nonce twice | Should be impossible (deterministic) |
| **TC-003** | Decrypt with wrong passphrase | Should fail cleanly |
| **TC-004** | Load corrupted wallet file | Should detect via HMAC |
| **TC-005** | Verify signature with wrong pubkey | Should return false |
| **TC-006** | Address decode with bit flip | Should fail checksum |

### 10.3 Out of Scope for This Audit

- GUI wallet security
- Hardware wallet integration
- L2 Lightning channel security
- Stablecoin asset handling

---

## 11. References

1. NIST FIPS 204 - Module-Lattice-Based Digital Signature Standard (ML-DSA)
2. NIST SP 800-208 - Recommendation for Stateful Hash-Based Signature Schemes
3. OWASP Threat Modeling Cheat Sheet
4. Bitcoin Core Security Model
5. Monero Wallet Security Documentation
6. Trail of Bits Blockchain Security Guidelines

---

## 12. Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-23 | Casey Wilson | Initial threat model |
| 1.1 | 2026-02-06 | Pre-audit hardening | HMAC-SHA256 upgrade (RFC 2104), constant-time tag comparison, Encrypt-then-MAC analysis, risk register corrections, KDF cascade documentation |

---

*Soqucoin Wallet Threat Model v1.1*
*Prepared for Halborn Security Audit — February 2026*
