# PAT (Practical Aggregation Technique) Architecture

> Status (2026-09-11): LatticeFold+ batch verification (`OP_CHECKFOLDPROOF`, witness v3) is deprecated and its deployment does not activate on any network; the Stage 2 and block 100,000 references below are historical. Its successor for confidential assets and succinct proofs is SoquObscura, in research and not scheduled on any network. PAT is unchanged and ships.

> **Version**: 1.0
> **Last Updated**: January 20, 2026
> **Audience**: Security auditors, developers, researchers

---

## Overview

PAT (Practical Aggregation Technique) is Soqucoin's approach to managing the size overhead of Dilithium signatures (2,420 bytes each) without compromising security.

**Problem**: Post-quantum signatures are ~34x larger than ECDSA, creating bandwidth and storage challenges.

**Solution**: PAT provides an aggregated commitment that enables:
1. Block header compactness (100 bytes vs full signatures)
2. Light client verification without downloading all signatures
3. Archival nodes to prune signatures after verification

---

## Architecture

```
Block Validation Flow
┌─────────────────────────────────────────────────────────────┐
│                       Block Header                          │
│  ├─ hashPrevBlock (32B)                                     │
│  ├─ hashMerkleRoot (32B)      ← Standard TX hash tree       │
│  ├─ PAT Commitment (100B)     ← Aggregated signature proof  │
│  ├─ nTime, nBits, nNonce                                    │
│  └─ AuxPoW proof (if merged mining)                         │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   Transaction Data                          │
│  ├─ TX₁: [inputs, outputs, Dilithium sig (2420B)]          │
│  ├─ TX₂: [inputs, outputs, Dilithium sig (2420B)]          │
│  └─ ...                                                     │
└─────────────────────────────────────────────────────────────┘
```

---

## PAT Commitment Structure

The 100-byte PAT commitment consists of:

| Field | Size | Description |
|-------|------|-------------|
| `pubkey_xor` | 32 bytes | XOR of all signer public keys (collision resistance) |
| `message_root` | 32 bytes | Merkle root of all signed messages (sighashes) |
| `commitment_hash` | 32 bytes | Hash binding pubkeys, messages, and signatures |
| `sig_count` | 4 bytes | Number of signatures aggregated |

---

## Validation Flow

### Full Node Validation

```cpp
// 1. Verify Merkle root (standard Bitcoin-style)
if (block.hashMerkleRoot != ComputeMerkleRoot(block.vtx))
    return REJECT("bad-txnmrklroot");

// 2. Verify each Dilithium signature individually
for (const auto& tx : block.vtx) {
    for (const auto& input : tx.vin) {
        if (!VerifyDilithiumSignature(input.sig, input.pubkey, tx.sighash))
            return REJECT("bad-dilithium-sig");
    }
}

// 3. Compute PAT commitment from verified signatures
PATCommitment computed = ComputePATCommitment(block.vtx);

// 4. Verify PAT commitment matches header
if (computed != block.patCommitment)
    return REJECT("bad-pat-commitment");
```

### Light Client / SPV Validation

Light clients can verify PAT commitment without full signatures:

```cpp
// Light client receives:
// - Block headers (including PAT commitment)
// - Merkle proofs for specific transactions

// Trust model:
// - If multiple full nodes agree on PAT commitment, signatures are valid
// - Light client trusts that full nodes verified all signatures
```

---

## Key Implementation Files

| File | Purpose |
|------|---------|
| `src/pat/keys.h` | `CDilithiumKey` class for key management |
| `src/rpc/pat.cpp` | RPC commands: `generatedilithiumkey`, `signdilithiummessage` |
| `src/test/pat_tests.cpp` | PAT unit tests |
| `src/test/fuzz/pat_aggregate.cpp` | Fuzz testing for aggregation |
| `src/bench/bench_pat.cpp` | Performance benchmarks |
| `src/consensus/consensus.h` | `PAT_VERIFY_COST = 20` (verification cost units) |

---

## Relationship to LatticeFold+

PAT and LatticeFold+ serve different purposes:

| Aspect | PAT (Genesis) | LatticeFold+ (Stage 2) |
|--------|---------------|------------------------|
| **Activates at** | Block 0 | Block 100,000 |
| **Verifies signatures?** | No (commitment only) | Yes (recursive SNARK) |
| **Purpose** | Header compactness, pruning | Batch verification speedup |
| **Node must verify each sig?** | Yes | No (proof covers batch) |
| **Verification time (256 sigs)** | ~45ms (individual verify) | ~0.75ms (batch proof) |

**Key Insight**: PAT enables signature pruning; LatticeFold+ enables faster verification. They are complementary, not alternatives.

---

## Security Properties

### What PAT Guarantees

1. **Integrity**: PAT commitment binds to exact set of signatures
2. **Non-malleability**: Cannot produce valid commitment for different signatures
3. **Collision resistance**: XOR of pubkeys prevents key substitution attacks

### What PAT Does NOT Guarantee

1. **Signature validity**: Full nodes must still verify each signature
2. **Privacy**: All pubkeys and messages are visible
3. **Size reduction**: Individual signatures still transmitted (optimization via LatticeFold+)

---

## Verification Cost

From `src/consensus/consensus.h`:

```cpp
/** PAT (Practical Aggregation Technique) signature aggregation (~4ms) */
static const int64_t PAT_VERIFY_COST = 20;
```

PAT verification consumes 20 units of the block's 80,000-unit verification budget.

---

## Test Vectors

See `src/test/pat_tests.cpp` for comprehensive test coverage:

- PAT commitment computation
- Cross-implementation compatibility
- Edge cases (empty block, single TX, max TX)
- Consensus rejection on mismatch

---

## References

- **CONSENSUS_COST_SPEC.md**: Full verification cost accounting
- **LatticeFold+ (ePrint 2025/247)**: Recursive batch verification
- **Dilithium (NIST FIPS 204)**: Underlying signature scheme

---

*This document is part of the Halborn audit preparation package.*
