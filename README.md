<p align="center">
  <img src="doc/soqucoin-label-logo.png" alt="Soqucoin" width="280"/>
</p>

<h1 align="center">Soqucoin™ Core</h1>

<p align="center">
  <strong>A post-quantum Layer 1 with native ML-DSA-44 signatures. Running on stagenet, mainnet genesis in progress.</strong>
</p>

<p align="center">
  <a href="https://github.com/soqucoin/soqucoin/actions/workflows/ci.yml"><img src="https://github.com/soqucoin/soqucoin/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/soqucoin/soqucoin/releases/latest"><img src="https://img.shields.io/github/v/release/soqucoin/soqucoin?include_prereleases&label=release" alt="Release"></a>
  <a href="https://github.com/soqucoin/soqucoin/blob/main/COPYING"><img src="https://img.shields.io/badge/license-MIT-blue" alt="License"></a>
  <a href="https://soqu.org"><img src="https://img.shields.io/badge/website-soqu.org-purple" alt="Website"></a>
</p>

<p align="center">
  <a href="#about">About</a> •
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#documentation">Documentation</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a>
</p>

---

## About

Soqucoin is a Scrypt-based proof-of-work cryptocurrency that removes ECDSA from the transaction authorization path and uses **NIST-standardized ML-DSA-44 (Dilithium)** signatures. It uses **PAT** (Practical Attestation Technique) for batch signature attestation. **SoquObscura**, the post-quantum confidential transaction system built on the LNP22/LaZer proof system with LaBRADOR block-level aggregation, is designed and partly in-tree but is **not activated on any network**. See the status note in the Architecture section before citing any of its figures.

> **Why does this matter?** Quantum computers will eventually break ECDSA. Soqucoin makes all user transaction signatures quantum-resistant without requiring a soft-fork migration from an ECDSA-based design.

### Current Status

| Milestone | Status | Date |
|-----------|--------|------|
| Consensus code merged | ✅ Complete | Nov 20, 2025 |
| ASIC validation (L7) | ✅ Complete | Nov 24, 2025 |
| Testnet3 launch | ✅ Complete | Dec 2025 |
| Stability testing (1200+ blocks) | ✅ Complete | Jan 2, 2026 |
| Halborn security audit (30 findings) | ✅ Complete | Feb–Mar 2026 |
| Lattice-BP++ consensus wired | ✅ Complete | Apr 2026 |
| SoquObscura CT (LNP22/LaBRADOR) | 🔄 In Progress | Jul 2026 |
| Mainnet genesis | 🔄 In Progress | 2026 |

---

## Features

### Post-Quantum Cryptography

| Component | Implementation | Security Level |
|-----------|---------------|----------------|
| **Signatures** | ML-DSA-44 (Dilithium) | NIST Level 2 (128-bit quantum) |
| **Address Hashing** | SHA-256 | 128-bit collision |
| **Batch Verification** | PAT (Merkle-aggregated) | Constant-size proofs |
| **Proof-of-Work** | Scrypt (N=1024, r=1, p=1) | Grover-resistant |

### Confidential Transactions: SoquObscura (SOQ-P010)

> **STATUS: NOT ACTIVE ON ANY NETWORK.** `DEPLOYMENT_SOQUOBSCURA` is
> `NOT_SCHEDULED` on mainnet, testnet, regtest and stagenet, and its BIP9 entry
> is configured to never activate. The table below describes the **design**, not
> behaviour you can observe on a running node. The reference sizes and timings
> are measured against the research implementation, not against consensus code.
> Confidential outputs do not currently hide amounts.

| Component | Implementation | Security Level |
|-----------|---------------|----------------|
| **Commitments** | ABDLOP (R = Z_{12289}[X]/(X^64+1)) | NIST Category 2 (quantum-safe) |
| **Range Proofs** | LNP22 exact-binary extraction | NIST Category 2 (quantum-safe) |
| **Balance Proofs** | Corrector-chain with shift-shadow boundary pin | NIST Category 2 (quantum-safe) |
| **Verifiable Encryption** | Dual-target Module-LPR (issuer + recipient) | NIST Category 2 (quantum-safe) |
| **Block Aggregation** | LaBRADOR pack proofs (single q = 2^38 − 107) | Constant-size per block |
| **Ref Tx Size** | ~146 KB (2 range + 1 balance + 4 VE) | — |
| **Ref Verify Time** | 316 ms (single-thread, Xeon 8358, AVX-512) | — |

> **Note:** SoquObscura supersedes the earlier Lattice-BP++ system (SOQ-P002). It uses ABDLOP commitments with LNP22/LaZer proofs and LaBRADOR block-level aggregation. The exactness architecture confines approximate proof slack (ψ) to non-consensus-critical margins via compile-time static asserts. Patent pending (SOQ-P010).

### Performance Benchmarks

```
┌─────────────────────────────────┬────────────────┬─────────────┐
│ Operation                       │ Time           │ Size        │
├─────────────────────────────────┼────────────────┼─────────────┤
│ Dilithium Sign (M4)             │ 0.177 ms       │ 2,420 bytes │
│ Dilithium Verify (M4)           │ 0.041 ms       │ —           │
│ PAT root over 1000 sigs (M4)    │ 0.67 ms        │ 72 bytes    │
│ SoquObscura Range Prove (Xeon)  │ 61.8 ms        │ 17,991 B    │
│ SoquObscura Range Verify (Xeon) │ 26.8 ms        │ —           │
│ SoquObscura Balance Verify      │ 34.9 ms        │ 20,233 B    │
│ SoquObscura VE Verify           │ 56.9 ms        │ 22,426 B    │
│ Full Ref Tx Verify (Xeon 8358)  │ 316 ms         │ ~146 KB     │
└─────────────────────────────────┴────────────────┴─────────────┘
```

### ASIC Compatibility

Validated on **Antminer L7** (9.5 GH/s):
- Standard Stratum V1 protocol
- Zero firmware modifications
- Zero rejected shares across the validation run
- 640+ blocks continuous operation, zero crashes

### PAT (Practical Attestation Technique)

**Status**: ✅ Fully Implemented (v1.0) — November 2025

Soqucoin implements PAT to commit a batch of Dilithium signatures to a Merkle root. This gives a constant-size on-chain commitment for batch validation; the signatures themselves remain in witness data.

#### Implementation Details

| Component | Status | File |
|-----------|--------|------|
| Proof Generation | ✅ Complete | `src/crypto/pat/logarithmic.cpp` |
| Proof Verification | ✅ Complete | `CreateLogarithmicProof()` |
| Simple Mode Verification | ✅ Production | `VerifyLogarithmicProof()` |
| Full Mode Verification | ✅ Infrastructure Ready | Full witness validation |
| Consensus Opcode | ✅ Active | `OP_CHECKPATAGG` (0xfd) |
| Unit Tests | ✅ 17/17 Passing | `test/pat_tests.cpp` |
| Integration Tests | ✅ Complete | `test/pat_script_tests.cpp` |

#### Verification Guarantees

- ✅ **Merkle Root Binding**: Prevents proof forgery and signature omission
- ✅ **Hash Aggregation (SHA3-256)**: Prevents rogue-key substitution attacks  
- ✅ **Message Commitment**: Prevents message tampering or reordering
- ✅ **Non-Malleability**: Canonical ordering ensures unique proofs

#### Performance Metrics

| Metric | Value | Notes |
|--------|-------|-------|
| Proof Size | 100 bytes | Constant, regardless of batch size |
| Verification (Simple) | < 4 µs | O(1) constant time |
| Verification (Full) | ~800 µs @ n=1024 | O(log n) tree traversal |
| Commitment ratio | ~25,600× @ n=1024 | 100-byte commitment vs the raw signature bytes it commits; signatures remain in witness |
| Activation | Block 0 | Active since genesis |

#### Consensus Mode

```
Stack: <sigs...> <pks...> <msgs...> <count> 
       <proof> <agg_pk> <msg_root> OP_CHECKPATAGG
Use Case: Transaction validation, block verification
Trust Model: Full cryptographic verification with witness data
```

#### Documentation

- **Wire Format**: [doc/pat-specification.md](doc/pat-specification.md)
- **API Reference**: [src/crypto/pat/logarithmic.h](src/crypto/pat/logarithmic.h)
- **Test Vectors**: [test/pat_tests.cpp](test/pat_tests.cpp)

---

## Quick Start

### Prerequisites

- C++14 compiler (GCC 7+ or Clang 8+)
- Boost 1.60.0+
- OpenSSL 1.1+
- libevent 2.1+

### Build from Source

```bash
git clone https://github.com/soqucoin/soqucoin.git
cd soqucoin
./autogen.sh
./configure
make -j$(nproc)
make install  # optional
```

### Run a Node

```bash
# Stagenet (current active network)
./src/soqucoind -stagenet -daemon -server -rpcuser=soqucoin -rpcpassword=YOUR_PASSWORD

# Mainnet (after genesis)
./src/soqucoind -daemon -server -rpcuser=soqucoin -rpcpassword=YOUR_PASSWORD

# Regtest (local development)
./src/soqucoind -regtest -daemon
```

### ⛏️ Solo Mining

The **SOQ Solo Miner** is a lightweight stratum proxy included in `contrib/solo-miner/`. Mine blocks directly to your wallet, zero pool fees.

```bash
# 1. Configure with your node RPC and wallet address
cd contrib/solo-miner
cp config.example.json config.json && nano config.json

# 2. Run it
./soq-solo-miner config.json

# 3. Point your ASIC/GPU at stratum+tcp://localhost:3333
```

📖 [Full Solo Mining Guide](contrib/solo-miner/README.md)

### Network Ports

| Network | P2P | RPC |
|---------|-----|-----|
| Mainnet | 33388 | 33389 |
| Testnet | 44556 | 44555 |
| Stagenet | 28333 | 28332 |
| Regtest | 18444 | 18332 |


---

## Documentation

| Document | Description |
|----------|-------------|
| [INSTALL.md](INSTALL.md) | Build instructions for all platforms |
| [doc/stagenet-mining-guide.md](doc/stagenet-mining-guide.md) | Stagenet mining & node setup |
| [contrib/solo-miner/README.md](contrib/solo-miner/README.md) | Solo mining stratum proxy |
| [doc/pat-specification.md](doc/pat-specification.md) | PAT wire format specification |
| [Whitepaper](https://soqu.org/whitepaper/soqucoin_whitepaper.pdf) | Technical specification |

---

## Architecture

### Consensus Opcodes

| Opcode | Hex | Witness | Purpose |
|--------|-----|---------|----------|
| `OP_CHECKPATAGG` | 0xfd | v2 | PAT Merkle commitment verification |
| `OP_SOQUOBSCURA_RANGEPROOF` | 0xfa | v4 | SoquObscura range proof verification (deployment `NOT_SCHEDULED`) |

### Prover Implementation Status

| Component | Location | Status |
|-----------|----------|--------|
| **PAT Prover** | `src/crypto/pat/logarithmic.cpp` | ✅ In-tree |
| **PAT Verifier** | `src/crypto/pat/logarithmic.cpp` | ✅ In-tree |
| **SoquObscura disclosure + issuer registry** | `src/consensus/soquobscura/` | ◻ Scaffolding — headers only, deliberately not in the build |
| **SoquObscura Verifier** | _(planned; no path yet)_ | ◻ Not started — see note |
| **SoquObscura Prover** | _(planned; no path yet)_ | ◻ Not started |
| **LaBRADOR Aggregator** | _(planned; no path yet)_ | ◻ Not started |
| **PQ Wallet Library** | `src/wallet/pqwallet/` | ✅ In-tree |

Note: Lattice-BP++ (SOQ-P002) is superseded by SoquObscura (SOQ-P010). LatticeFold+ batch verification (`OP_CHECKFOLDPROOF`, witness v3) is deprecated. The opcode remains in the tree behind a deployment that does not activate on any network. It was reviewed in the April 2026 external extension audit. Its successor for confidential assets and succinct proofs is SoquObscura, a lattice-based confidential-asset system in research, whose deployment is not scheduled on any network and which is subject to the second external audit phase before any activation.

> ⛔ **Status note, so this table is not read as a claim of what exists.** Rows marked
> ◻ have **no code in this tree**. Earlier revisions of this table cited concrete paths
> (`src/crypto/soquobscura/`, `src/crypto/labrador/`) that have never existed; they are
> now marked as planned. Confidential outputs are **not active on any network** —
> `DEPLOYMENT_SOQUOBSCURA` is `NOT_SCHEDULED` on mainnet, testnet, regtest and stagenet
> — because the currently-shipped range verifier accepts an all-zero witness. See
> `src/test/soquobscura_degenerate_witness_tests.cpp`, whose three failing tests are
> committed red on purpose as the regression gate (zero witness, wire-reachable zero
> witness, and scaled witness; the scaled case staying red confirms the break is
> homogeneity-wide, so no "reject all zeros" patch can legitimately turn this battery
> green). Attribution for the LNP22/LaZer and
> LaBRADOR upstreams this work builds on is in [`ATTRIBUTION.md`](ATTRIBUTION.md).

### Branch Structure

| Branch | Purpose |
|--------|---------|
| `main` | Active development (default, protected) |
| `release/v1.0.x` | Stable release branch (hotfixes only) |
| `feature/*` | Feature branches (PR into main) |

---

## Contributing

### Pre-Launch Policy

Soqucoin Core is in **pre-genesis final validation**. The consensus stack has completed external security audit and is undergoing final pre-mainnet testing. The audit reports are published by Halborn: [blockchain node audit](https://www.halborn.com/audits/soqucoin/soqucoin-blockchain-node-a4f1f7), [architecture assessment](https://www.halborn.com/audits/soqucoin/blockchain-architecture-assessment---added-days-907771), and a [case study](https://www.halborn.com/case-studies/post/case-study-halborn-secures-soqucoin-the-first-native-post-quantum-scrypt-pow-blockchain).

**How to contribute now:**

1. **Report bugs** — Open a [GitHub Issue](https://github.com/soqucoin/soqucoin/issues)
2. **Discuss features** — Join [GitHub Discussions](https://github.com/soqucoin/soqucoin/discussions)
3. **Share test data** — Regtest blocks, fuzz corpora, ASIC screenshots

> Pull requests will be enabled immediately after genesis. Contributors who help stress-test the chain will be credited in the launch paper.

### Code Style

This project follows [Bitcoin Core contribution guidelines](CONTRIBUTING.md):
- C++14 standard (C++17 is optional, via `--enable-cxx17`)
- 4-space indentation
- No trailing whitespace
- Signed commits required

---

## Tokenomics

| Parameter | Value |
|-----------|-------|
| **Ticker** | SOQ |
| **Algorithm** | Scrypt |
| **Block Time** | 1 minute |
| **Initial Block Reward** | 100,000 SOQ |
| **Halving Interval** | 250,000 blocks (~174 days) |
| **Terminal Emission** | 2,500 SOQ perpetual (after block 1,000,000) |
| **Supply Model** | Inflationary with declining rate |
| **Premine** | 0 SOQ |

**Fair Launch** — No premine, no ICO, no founder allocation, no treasury. 100% proof-of-work distribution.

---

## Security

For security vulnerabilities, please see [SECURITY.md](.github/SECURITY.md).

**Do not** open public issues for security-related bugs.

---

## License

Soqucoin Core is released under the terms of the MIT license. See [COPYING](COPYING) for details.

---

<p align="center">
  <sub>Built with 🔐 by the Soqucoin Core developers</sub>
</p>
