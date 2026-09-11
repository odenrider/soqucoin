# Soqucoin Lattice-BP++ Privacy Architecture

> Status (2026-09-11): historical document. Lattice-BP++ is superseded by SoquObscura, a lattice-based confidential-asset system in research whose deployment is not scheduled on any network and which is subject to the second external audit phase before any activation. LatticeFold+ batch verification (`OP_CHECKFOLDPROOF`, witness v3) is deprecated and its deployment does not activate on any network; the ALWAYS_ACTIVE references below are historical.

> **Version**: 2.0 | **Status**: Implementation Complete, Audit Pending
> **Author**: Soqucoin Foundation R&D
> **Updated**: April 27, 2026
> **Classification**: Strategic Research Document — Patent Pending
> **Registry**: SOQ-P003, SOQ-AUD2-006
> **Cross-references**: DL-PRIVACY-INTEGRATION-ARCHITECTURE.md, DL-LATTICE-RANGE-PROOF.md

---

## Executive Summary

This document describes the **Lattice-BP++ privacy architecture** — a fully post-quantum private
transaction system built on native lattice cryptography. It integrates with Soqucoin's existing
stack (Dilithium, PAT, LatticeFold+) using a **native dual-format transaction model** where every
UTXO carries a visibility mode (`TRANSPARENT` or `CONFIDENTIAL`).

**Key Design Principles:**
1. **Opt-In Privacy** — Default transparency, user-optional confidentiality via `nVisibility` field
2. **Full Post-Quantum Security** — Pure lattice math (Module-LWE/SIS), zero ECC dependency
3. **Native Dual-Format** — One UTXO set, one validation path, no extension blocks
4. **Compliance-Ready** — View keys, audit keys, selective disclosure for regulators
5. **Measured Performance** — Prove: 0.55ms, Verify: 22µs, Proof: ~12KB

> [!IMPORTANT]
> **Architecture Decision (April 2026)**: Extension blocks (MWEB model) were evaluated and rejected.
> Soqucoin is pre-mainnet with zero live UTXOs — no backward compatibility constraints. Native
> dual-format provides larger anonymity sets, eliminates peg-in/peg-out linkability, and requires
> ~40% less code than extension blocks. See §2 for full comparison.
>
> **Activation**: flag-day by height (v1.5.0 model). Dormant (`NOT_SCHEDULED`) on mainnet;
> the activation height is set in a released binary after the Halborn Phase 2 audit clears.
> Active from height 0 on stagenet/testnet/regtest. Witness version v4 (`OP_4`).

---

## Part I: Cryptographic Foundation

### 1.1 Problem Statement

Soqucoin requires privacy primitives that match its post-quantum signature layer:

| Component | Implementation | Status |
|-----------|---------------|--------|
| Signatures | Dilithium ML-DSA-44 (FIPS 204) | ✅ Quantum-safe, audited |
| Commitments | Ring-LWE Pedersen (C=vA+rS) | ✅ Implemented (`commitment.cpp`, 582 LOC) |
| Range Proofs | LNP22 polynomial product | ✅ Implemented (`range_proof.cpp`, 407 LOC) |
| Ring Signatures | LSAG/MLSAG (Module-SIS) | ✅ Implemented (`ring_signature.cpp`, 440 LOC) |
| Stealth Addresses | Dilithium + HKDF one-time keys | ✅ Implemented (`stealth_address.h`, 166 LOC) |
| Batch Verification | LatticeFold+ accumulation | ✅ Active from genesis (witness v3) |

**Total implementation**: 2,269 LOC across 5 source files + 674 LOC tests (16/16 passing).

### 1.2 Cryptographic Parameters

All parameters align with Dilithium ML-DSA-44 for NTT table reuse:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Ring dimension N | 256 | Matches Dilithium, NTT-compatible |
| Modulus q | 8,380,417 | Same as Dilithium (q ≡ 1 mod 2N) |
| Module rank K | 4 | NIST Level 1 (128-bit classical) |
| Gaussian σ | 2.0 | Standard for Ring-LWE |
| Rejection bound β | 256 | 4σ√(NK), prevents norm leakage |
| Range bits | 64 | Full CAmount range [0, 2^64) |

> **Source**: `src/crypto/latticebp/commitment.h` — compile-time validated via `static_assert`.

### 1.3 Threat Model

| Adversary | Capability | Mitigation |
|-----------|------------|------------|
| Classical Attacker | Statistical/computational analysis | Ring signatures (n=11 decoys), stealth addresses |
| Quantum Attacker | Shor's algorithm (EC discrete log) | Pure lattice commitments (Module-LWE/SIS) |
| Regulatory Auditor | Legal subpoena authority | View keys, audit keys, selective disclosure |
| Network Observer | IP/timing correlation | Constant-time verification, future Dandelion++ |

### 1.4 Cryptographic Building Blocks

#### Lattice-Based Pedersen Commitments (`commitment.h/cpp`)

```
Classical Pedersen: C = vG + rH  (EC points — Shor-vulnerable)
Lattice Pedersen:   C = vA + rS  (Ring-LWE elements — quantum-safe)
```

- Homomorphic: `C(v1) + C(v2) = C(v1+v2)` — enables balance proofs
- Commitment size: ~3KB (vs 32 bytes EC)
- Opening size: ~4KB
- Public params generated deterministically from consensus seed

#### Range Proofs (`range_proof.h/cpp`)

LNP22-inspired polynomial product construction (patent pending):

1. **Binary decomposition**: `v = Σ b_i · 2^i` where `b_i ∈ {0,1}`
2. **Bit commitments**: `C_i = b_i · A + r_i · S` (Ring-LWE)
3. **Binary proof**: `b_i · (b_i - 1) = 0` via polynomial product
4. **Fiat-Shamir challenge**: `α ← H(domain ‖ sighash ‖ pubkey_hash ‖ C_bits)`
5. **Aggregation**: `Σ α^i · b_i · (b_i - 1) = 0` with overwhelming probability
6. **Reconstruction**: `Σ 2^i · C_i = C` (value-commitment link)

**Measured performance** (Stagenet VPS, 4-core, 16GB):

| Operation | Time | Size |
|-----------|------|------|
| Prove | 0.55 ms | — |
| Verify | 0.022 ms (22 µs) | — |
| Proof size | — | ~12 KB |
| Full private TX (ring sig n=11) | 67.7 ms | ~26 KB |

#### Ring Signatures (`ring_signature.h/cpp`)

LSAG (Linkable Spontaneous Anonymous Group) adapted for lattice:

- **Default ring size**: 11 decoys (matches Monero)
- **Key images**: Lattice analogue of `I = x · H(P)` — unique per UTXO, double-spend prevention
- **MLSAG**: Multi-layered variant for transactions with multiple inputs
- **Decoy selection**: Gamma-distributed, age-weighted from confidential UTXO subset

#### Stealth Addresses (`stealth_address.h`)

Monero-style one-time addresses adapted for Dilithium key infrastructure:

| Key Type | Can View | Can Spend | Use Case |
|----------|----------|-----------|----------|
| **Spend Key** | Own TXs | ✅ Yes | User wallet |
| **View Key** | Incoming TXs | ❌ No | Accountant/auditor |
| **Audit Key** | All TXs + Amounts | ❌ No | Regulatory compliance |

Key derivation uses HKDF with domain separation:
```cpp
view_key  = HKDF("soqucoin.privacy.view.v1", master_seed)
spend_key = HKDF("soqucoin.privacy.spend.v1", master_seed)
audit_key = HKDF("soqucoin.privacy.audit.v1", tx_seed)
```

---

## Part II: Native Dual-Format Privacy Model

### 2.1 Architecture Decision: Why Not Extension Blocks

| Dimension | Extension Block (MWEB) | **Native Dual-Format** |
|-----------|----------------------|----------------------|
| **UTXO sets** | 2 (main + extension) | **1 (unified)** |
| **Anonymity set** | Extension block users only | **All confidential UTXOs** |
| **Peg linkability** | Visible on-chain (entry/exit) | **No peg boundary** |
| **Wallet UX** | Explicit shield/unshield | **Toggle: "Send Private?"** |
| **Estimated LOC** | ~1,500–2,100 | **~900–1,300 (~40% less)** |
| **Audit surface** | Two validation paths | **One validation path** |
| **Backward compat needed?** | Yes (Litecoin had 10yr of UTXOs) | **No (pre-mainnet)** |

> **Prior art**: Zcash Orchard (native shielded pools, 2022) proved this architecture viable.
> Litecoin MWEB solved a backward compatibility problem Soqucoin doesn't have.

### 2.2 Transaction Format

Every UTXO carries format flags:

```
CTxOut {
    uint8_t nVisibility;  // 0x00 = TRANSPARENT, 0x01 = CONFIDENTIAL
    uint8_t nAssetType;   // 0x00 = SOQ, 0x01 = USDSOQ, 0x02+ = future

    // TRANSPARENT mode (standard):
    CAmount nValue;                    // visible
    CScript scriptPubKey;              // Dilithium P2PKH/P2SH

    // CONFIDENTIAL mode (nVisibility == 0x01):
    LatticeCommitment commitment;      // hides amount (Ring-LWE)
    LatticeBPRangeProof range_proof;   // proves amount ∈ [0, 2^64)
    LatticeRingSig ring_sig;           // sender privacy (n=11 decoys)
    LatticeKeyImage key_image;         // double-spend prevention
    StealthAddress stealth_addr;       // receiver privacy (one-time)
    ViewKeyData view_key_data;         // optional: encrypted memo
}
```

### 2.3 Mixed-Mode Transactions

Transactions freely mix transparent and confidential inputs/outputs:

```
✅ Transparent → Transparent     (standard transfer, institutional)
✅ Transparent → Confidential    (shield — opt into privacy)
✅ Confidential → Transparent    (unshield — reveal for compliance)
✅ Confidential → Confidential   (fully private transfer)
✅ Mixed inputs/outputs           (partial shielding)
```

### 2.4 Balance Verification

```
Per transaction, per asset type:
  sum(transparent_inputs) + sum(confidential_input_commitments)
  ==
  sum(transparent_outputs) + sum(confidential_output_commitments) + fee

Rules:
  - Balance holds INDEPENDENTLY per nAssetType (no cross-asset mixing)
  - Transparent amounts validated by MoneyRange()
  - Confidential amounts validated by Lattice-BP++ range proofs
  - Key images checked against spent-key-image set (O(1) hash lookup)
  - Fees are always transparent, always in native SOQ (nAssetType == 0x00)
```

### 2.5 Block-Level LatticeFold Accumulation

```
Per block:
  1. Validate each TX individually (balance + range proofs)
  2. Collect all range proofs from confidential outputs
  3. Fold via LatticeFold+ into single accumulated proof
  4. Store accumulated proof in block header extension
  5. Verifiers check: individual TX validity + accumulated proof

Performance (stagenet benchmarks, April 2026):
  - Range proof verify: 0.022 ms each
  - LatticeFold accumulation (25 proofs): ~68 ms total
  - Block overhead (25 confidential TXs): ~1.7s / 60s = 2.8%
```

### 2.6 USDSOQ Integration

```
OP_USDSOQ_MINT  → creates TRANSPARENT output, nAssetType=0x01 (enforced)
                → holder can shield in subsequent TX

OP_USDSOQ_BURN  → requires TRANSPARENT input, nAssetType=0x01
                → holder must unshield before burning

OP_USDSOQ_FREEZE → works on both visibility modes, requires nAssetType=0x01
```

**Rationale**: Mint/burn are always transparent for supply invariant auditability.
The `nAssetType` tag carries through all downstream transactions including shielding.

---

## Part III: Integration with Soqucoin Stack

### 3.1 Witness Version Routing

```
v0/v1: Dilithium signature verification (inline)     [ALWAYS_ACTIVE]
v2:    PAT: OP_CHECKPATAGG via EvalScript()           [ALWAYS_ACTIVE]
v3:    LatticeFold: OP_CHECKFOLDPROOF via EvalScript() [ALWAYS_ACTIVE]
v4:    Lattice-BP++: OP_LATTICEBP_RANGEPROOF (0xfa)   [NEVER_ACTIVE]
v5:    USDSOQ: OP_USDSOQ_* via EvalScript()           [NEVER_ACTIVE]
v6-v16: Future (anyone-can-spend until activated)
```

### 3.2 Code Locations (Implemented)

| Component | File | LOC | Status |
|-----------|------|-----|--------|
| Lattice commitments | `src/crypto/latticebp/commitment.h/cpp` | 746 | ✅ Complete |
| Range proofs | `src/crypto/latticebp/range_proof.h/cpp` | 570 | ✅ Complete |
| Ring signatures + MLSAG | `src/crypto/latticebp/ring_signature.h/cpp` | 628 | ✅ Complete |
| Stealth addresses + View keys | `src/crypto/latticebp/stealth_address.h` | 166 | ✅ Complete |
| Test suite | `src/crypto/latticebp/test_latticebp.cpp` | 674 | ✅ 16/16 pass |
| Consensus opcode | `src/script/interpreter.cpp` (v4 handler) | — | ✅ Wired |
| Deployment (flag-day) | `src/chainparams.cpp` (DEPLOYMENT_LATTICEBP) | — | ✅ Dormant on mainnet; active height 0 on test networks |

### 3.3 LatticeFold+ Synergy

LatticeFold+ (witness v3, `ALWAYS_ACTIVE`) provides batch verification:

```cpp
// Batch verify 512 Dilithium signatures
LatticeFoldProof batch_proof = CreateFoldProof(private_txs);
bool valid = VerifyFoldProof(batch_proof); // ~0.75ms for 512 sigs

// Ring sigs over 11 decoys: LatticeFold folds into single proof
```

### 3.4 SOQ Lightning (L2) Compatibility

The `nAssetType` field enables multi-asset Lightning channels:

| L2 Feature | Privacy Requirement | Solution |
|------------|---------------------|----------|
| Channel open | Hidden capacity (future) | Lattice commitment (v2 channels) |
| HTLC | Hidden amount (future) | Range proof |
| Channel close | Selective reveal | View key |
| Asset routing | USDSOQ on Lightning | `nAssetType=0x01` preserved |

**Precedent**: Taproot Assets / Taro v0.7 made multi-asset Lightning production-ready on Bitcoin.

### 3.5 Solana Bridge Compatibility

```
SOQ (Private) → Unshield (reveals amount) → Bridge → pSOQ (Solana)
pSOQ → Burn → Bridge → SOQ (Transparent) → Shield (optional)
```

Bridge requires visibility at crossing. Users must unshield before bridging.

---

## Part IV: Security Analysis

### 4.1 Cryptographic Assumptions

| Assumption | Hardness Problem | Standard |
|------------|------------------|----------|
| Ring-LWE | Lattice shortest vector | NIST PQ Standard |
| Module-SIS | Short integer solution | NIST PQ Standard |
| Dilithium | ML-DSA security | FIPS 204 |

**No classical ECC dependency** — entire privacy stack is post-quantum.

### 4.2 Preemptive Audit Hardening

Every finding from the Halborn LatticeFold audit (SOQ-A001 through A006) has a
preemptive defense in Lattice-BP++:

| Halborn Finding | Our Defense |
|----------------|-------------|
| SOQ-A001 (reducible polynomial) | `static_assert` validates N=256, Q=8380417 at compile time |
| SOQ-A002 (wrong intrinsic) | Pure C implementation — NO platform-specific intrinsics |
| SOQ-A003 (missing reduction) | Every multiply followed by `barrett_reduce()` + debug assertions |
| SOQ-A004 (wrong exponent) | No Montgomery form — standard modular arithmetic |
| SOQ-A005 (no external binding) | Fiat-Shamir includes sighash + pubkey_hash (UTXO binding) |
| SOQ-A006 (const_cast UB) | Zero `const_cast` in entire module |

Additional hardening from PAT audit (SOQ-H001 through H030):

| Pattern | Defense |
|---------|---------|
| Bounds checking | `MAX_RANGE_BITS=64`, `MAX_PROOF_SIZE=16384`, all sizes validated |
| Memory cleanse | `memory_cleanse()` on all secret material (randomness, keys, bits) |
| Integer overflow | All size arithmetic uses `size_t` with overflow checks |
| Constant-time | No early returns based on secret data; XOR-accumulate comparison |
| Domain separation | `CSHA256("soqucoin-latticebp-rangeproof-v1" ‖ context ‖ data)` |

### 4.3 Attack Surface

| Attack | Mitigation | Residual Risk |
|--------|------------|---------------|
| Forge proof for negative value | Binary decomposition forces b∈{0,1}; b·(b-1)=0 | Low |
| Value overflow (>2^64) | 64 bits max + `MoneyRange()` pre-check | Low |
| Proof reuse across TXs | Fiat-Shamir transcript includes sighash + pubkey_hash | Low |
| Norm inflation | Rejection sampling with β=256; verify ‖z‖ ≤ β | Low |
| Ring analysis | 11 decoys, gamma-distributed age-weighted selection | Medium |
| Key image linkability | Unique per UTXO, O(1) hash-table check | Low |
| Timing side-channel | Constant-time implementation, no data-dependent branches | Low |

---

## Part V: Competitive Analysis

| Project | Privacy Tech | Quantum Safe | Compliance | Architecture |
|---------|-------------|-------------|------------|--------------|
| **Monero** | RingCT (EC) | ❌ | ❌ Delistings | Mandatory privacy |
| **Zcash** | Groth16 zk-SNARK | ❌ | 🟡 Optional | Native shielded pools |
| **Litecoin** | MWEB (EC) | ❌ | ✅ Optional | Extension blocks |
| **Secret** | TEE-based | ❌ | 🟡 | Hardware enclave |
| **Soqucoin** | **Lattice-BP++** | **✅ Full** | **✅ Optional** | **Native dual-format** |

**Differentiators**:
- First privacy blockchain with NIST-grade post-quantum security (no ECC)
- Compliance-first design (view keys, audit keys, opt-in, transparent by default)
- Native L1 recursive SNARK accumulation (LatticeFold+)
- Multi-asset privacy (SOQ + USDSOQ via `nAssetType`)

---

## Part VI: Audit Checklist

### Cryptography Review (Halborn — July 2026 Target)

- [ ] Ring-LWE commitment binding (`commitment.cpp` — 582 LOC)
- [ ] LNP22 range proof soundness (`range_proof.cpp` — 407 LOC)
- [ ] LSAG/MLSAG ring signature unforgeability (`ring_signature.cpp` — 440 LOC)
- [ ] Key image uniqueness and unlinkability
- [ ] Stealth address key derivation (HKDF domain separation)
- [ ] Fiat-Shamir transcript completeness (sighash + pubkey_hash binding)
- [ ] Norm bound verification (β=256)
- [ ] Side-channel resistance (constant-time ops)
- [ ] NTT multiplication correctness (vs schoolbook reference)

### Consensus Integration Review

- [ ] Witness v4 handler in `VerifyScript()` → `EvalScript()` dispatch
- [ ] `SCRIPT_VERIFY_LATTICEBP` flag gating
- [ ] `DEPLOYMENT_LATTICEBP` correctly dormant on mainnet (flag-day `NOT_SCHEDULED`)
- [ ] Mixed-mode balance verification (transparent + confidential)
- [ ] Per-asset-type balance isolation (`nAssetType`)
- [ ] Key-image spent set management and reorg handling
- [ ] LatticeFold accumulation of per-block range proofs
- [ ] Block weight calculation with SegWit-style confidential data discount

### Compliance Review

- [ ] View key disclosure mechanism
- [ ] Audit key completeness verification
- [ ] FATF Travel Rule compatibility
- [ ] Default transparency enforced when `NEVER_ACTIVE`
- [ ] `OP_USDSOQ_MINT` enforces `nVisibility=0x00`

### Performance Targets

| Operation | Target | Measured |
|-----------|--------|----------|
| Range proof generation | <10ms | **0.55ms** ✅ |
| Range proof verification | <5ms | **0.022ms** ✅ |
| Ring signature (n=11) | <100ms | **67.7ms** ✅ |
| Proof size | <16KB | **~12KB** ✅ |
| Batch verify (25 proofs via LatticeFold) | <100ms | **~68ms** ✅ |

---

## Appendix A: Academic References

| Topic | Paper | Authors | Year |
|-------|-------|---------|------|
| Lattice Range Proofs | LNP22: Lattice-Based ZK Range Proofs | Lyubashevsky, Nguyen, Plançon | CRYPTO 2022 |
| Lattice Commitments | LaZer: A Lattice Library for ZKP | IBM Research | CCS 2024 |
| Proof Accumulation | LatticeFold+: Faster Lattice Folding | Boneh, Chen | ePrint 2025/247 |
| Ring Signatures | Lattice-Based Ring Signatures | Lyubashevsky | 2021 |
| Binary Commitments | LACT+: Logarithmic Lattice Range Proofs | Alupotha, Boyen, McKague | 2023 |
| Poly Commitments | Greyhound: Fast Poly Commitments | IBM Research | CRYPTO 2024 |

## Appendix B: Glossary

| Term | Definition |
|------|------------|
| **nVisibility** | Per-UTXO flag: 0x00=transparent, 0x01=confidential |
| **nAssetType** | Per-UTXO asset tag: 0x00=SOQ, 0x01=USDSOQ |
| **Ring-LWE Commitment** | Quantum-safe alternative to EC Pedersen: C=vA+rS |
| **Key Image** | Unique identifier per spent output — prevents double-spend |
| **View Key** | Read-only key for transaction inspection |
| **Stealth Address** | One-time address generated per transaction |
| **LatticeFold Accumulation** | Folding N range proofs into 1 near-constant-size proof |
| **MLSAG** | Multi-Layered Linkable Spontaneous Anonymous Group signature |

---

*Soqucoin Lattice-BP++ Privacy Architecture v2.0*
*Updated April 27, 2026 — Reflects native dual-format design, actual implementation benchmarks, and the flag-day height activation model (updated 2026-07-06)*
*Patent Pending — Soqucoin Labs Inc.*
*Soqucoin Core Development Team*
