# Stage 5: L2SOQ — Quantum-Safe Payment Channel Network

> Status (2026-09-11): LatticeFold+ batch verification (`OP_CHECKFOLDPROOF`, witness v3) is deprecated and its deployment does not activate on any network; the Stage 2 and ALWAYS_ACTIVE references to it below are historical and batch settlement is not a shipped feature. Its successor for succinct proofs is SoquObscura, in research and not scheduled on any network.

> **Version**: 0.5 (ELTOO Architecture)
> **Status**: PROTOTYPE — Single-Hop ELTOO Channels Functional on Stagenet
> **Classification**: PUBLIC - Research Specification  
> **Target**: Multi-Hop Q3 2026, L2 Security Audit Q3–Q4 2026, Mainnet Post-Audit
> **Prepared For**: Public Review, VC Due Diligence, Future Audit Scope
> **Last Updated**: May 20, 2026

---

> [!CAUTION]
> **Research Preview Document**
> This specification describes a **research initiative**, not a committed deliverable. Post-quantum
> payment channels are an **unsolved problem** in the broader cryptographic research community.
> Timelines are aspirational targets contingent on solving open cryptographic challenges.
> No production timeline is guaranteed.

---

## Executive Summary

Stage 5 is a **research initiative** exploring quantum-safe Layer 2 payment channels built on 
Soqucoin's L1 settlement layer. Inspired by Bitcoin's Lightning Network, we're investigating:

- **Sub-second payments** (design target: <500ms)
- **High throughput** (theoretical target: 10,000+ TPS)
- **Quantum-resistant channels** (Dilithium commitment signatures)
- **Privacy by default** (channel state is off-chain)

### Research vs Engineering Distinction

| Category | Description |
|----------|-------------|
| **What we have** | Production L1 with Dilithium, functional single-hop ELTOO channels on Stagenet, QR-based state exchange, CTV + CSV covenant opcodes active |
| **What we're researching** | Multi-hop routing, adaptor signature alternatives for lattice-based schemes |
| **What's unsolved** | PQ adaptor signatures, channel state aggregation across multi-hop paths |
| **Our approach** | ELTOO state supersession (no watchtowers, no penalty txs), adapt BOLT specs where possible |

---

## Motivation

### L1 Limitations

| Metric | L1 (All Stages) | Requirement for Payments |
|--------|-----------------|--------------------------|
| TPS | ~40-70 | 10,000+ |
| Confirmation | 60 seconds | <1 second |
| Fees | ~0.01 SOQ | <0.0001 SOQ |
| Privacy | Opt-in (on-chain visible) | Default private |

### Why L2 is Necessary

1. **Block size/time constraints**: L1 TPS is fundamentally limited by 4MB blocks and 60-second target
2. **Payment UX**: Users expect instant confirmations for retail transactions
3. **Micropayments**: On-chain fees prohibit sub-cent transactions
4. **Scalability ceiling**: Mainnet adoption will exceed L1 capacity

### Why Now (After Stage 4)

| Prerequisite | Stage | Rationale |
|--------------|-------|-----------|
| Dilithium signatures | Genesis | L2 channels must use PQ signatures |
| LatticeFold+ verification | Stage 2 | Efficient batch settlement of channel closes |
| Full PQ privacy | Stage 3 | End-to-end quantum-safe privacy |
| Liquidity bridge | Stage 4 | Cross-chain liquidity for channel funding |

---

## Open Research Challenges

> [!WARNING]
> **Unsolved Problems**
> The following challenges do not have known solutions in the post-quantum cryptography literature.
> Our research timeline is contingent on making progress on these problems.

### 1. Post-Quantum Adaptor Signatures

**Problem**: Bitcoin Lightning uses Schnorr adaptor signatures for atomic multi-hop payments (PTLCs).
Dilithium does not natively support adaptor signatures.

**Status**: Active research  
**Approaches under investigation**:
- Hash-based HTLC alternatives (proven but less efficient)
- Exploring lattice-based adaptor constructions from academic literature
- Hybrid approaches using hash-time-locked commitments

**References**:
- Erwig et al., "Two-Party Adaptor Signatures From Identification Schemes" (2021)
- Tairi et al., "Post-Quantum Adaptor Signature" (2023, preprint)

### 2. Channel State Size

**Problem**: Dilithium signatures are 2,420 bytes (vs 64 bytes for Schnorr). Each channel state
update requires signatures from both parties, accumulating storage and bandwidth costs.

**Status**: Exploring solutions  
**Potential mitigations**:
- Signature aggregation (research needed)
- State compression via LatticeFold+ proofs
- Periodic state consolidation

**Impact**: May limit practical channel update frequency compared to Bitcoin LN.

### 3. Route Finding

**Problem**: Large keys and signatures affect channel capacity variance and gossip protocol
bandwidth. Network topology may differ significantly from Bitcoin Lightning.

**Status**: Under analysis  
**Open questions**:
- Optimal channel capacity sizes with PQ overhead
- Gossip protocol modifications for larger announcements
- Pathfinding algorithm adaptations

---

## Technical Architecture

### Design Principles

1. **Quantum-safe from genesis**: All channel operations use Dilithium signatures
2. **ELTOO state supersession**: Latest state always wins; no penalty transactions, no watchtowers
3. **Covenant-enabled**: CTV (0xb3) + CSV (0xb2) opcodes active from L1 genesis
4. **L1 settlement efficiency**: LatticeFold+ for batch channel settlements
5. **Privacy preservation**: Channel state never touches L1 during normal operation

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        L2SOQ Network                            │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │  Node A  │◄──►│  Node B  │◄──►│  Node C  │◄──►│  Node D  │  │
│  └────┬─────┘    └──────────┘    └──────────┘    └────┬─────┘  │
│       │              Payment Channels                  │        │
│       │                                                │        │
└───────┼────────────────────────────────────────────────┼────────┘
        │                                                │
        ▼                                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Soqucoin L1 (Settlement)                      │
│  ┌────────────────┐              ┌────────────────────────────┐ │
│  │ Channel Open   │              │ LatticeFold+ Batch Close   │ │
│  │ (Dilithium 2x) │              │ (512 channels per proof)   │ │
│  └────────────────┘              └────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Channel Lifecycle

#### 1. Channel Open (On-Chain)
```
Alice → L1 Transaction:
  - Output: 2-of-2 Dilithium multisig P2WSH (witness v6)
  - CTV covenant hash locks spend template
  - Value: X SOQ locked (min 100 SOQ)
  - Channel ID: SHA-256("L2SOQ-CHAN-V1" || sort(pkA, pkB) || capacity)
```

#### 2. Off-Chain Payments (Instant)
```
Alice → Bob (off-chain):
  - State Update: New balance distribution
  - Signed: ML-DSA-44 (both parties)
  - State #N supersedes all prior states (ELTOO)
  - No revocation needed

Payment latency: <500ms (measured on Stagenet)
Fees: 0 SOQ (off-chain)
```

#### 3. Channel Close (On-Chain)
```
Cooperative Close:
  - Latest state → L1
  - LatticeFold+ batch verification (if multiple channels)

Force Close (ELTOO):
  - Broadcast latest state + CSV timelock (144 blocks, ~2.4 hours)
  - Counterparty can publish newer state during timelock
  - No watchtower needed — any party can publish latest state
```

### Quantum-Safe Adaptations

| Lightning (Bitcoin) | L2SOQ | Rationale |
|---------------------|-------|-----------|
| ECDSA signatures | Dilithium ML-DSA-44 | Quantum resistance |
| SHA-256 HTLCs | SHA-256 HTLCs | SHA-256 is PQ-safe |
| Penalty-based revocation | **ELTOO state supersession** | No watchtowers, simpler security model |
| 71-byte signatures | 2,420-byte signatures | Larger but acceptable for L2 |
| Requires watchtowers | **No watchtowers** | ELTOO eliminates third-party monitors |

> [!NOTE]
> ELTOO's state supersession model means the latest state always wins. This eliminates:
> - Revocation keys and the complexity of penalty transactions
> - Watchtower infrastructure and its associated bandwidth/storage costs
> - The risk of accidental old-state broadcasts resulting in fund loss
>
> This is enabled by CTV (`OP_CHECKTEMPLATEVERIFY`, 0xb3) for covenant hash commitment
> and CSV (`OP_CHECKSEQUENCEVERIFY`, 0xb2) for relative timelocks on dispute windows.

---

## Performance Targets

### Comparison: Bitcoin Lightning vs L2SOQ

| Metric | Bitcoin Lightning (2025) | L2SOQ (Measured/Projected) |
|--------|--------------------------|----------------------------|
| Payment latency | <500ms | **<500ms** (measured on Stagenet) |
| Success rate | 99.7% | **>99%** (target) |
| Per-channel TPS | ~1,000 | **410–2,300** (measured) |
| Network TPS at scale | 1M+ | **500,000+** (projected, linear scaling) |
| Quantum safe | ❌ | **✅** |
| L1 settlement | ~10 min | **60 sec** |
| Watchtowers required | ✅ Yes | **❌ No** (ELTOO) |
| Crypto overhead / update | ~0.05 ms | **0.436 ms** (Dilithium sign+verify × 2) |

### Why L2SOQ is Competitive

| Advantage | Explanation |
|-----------|-------------|
| **1-minute L1 blocks** | Faster channel opens/closes than Bitcoin (10 min) |
| **ELTOO model** | No watchtowers, no penalty transactions, simpler security |
| **Dogecoin-like tokenomics** | Lower fees, more suitable for micropayments |
| **LatticeFold+ settlements** | 512 channel closes in <1ms verification |
| **Quantum-safe channels** | End-to-end post-quantum from channel open through close |
| **CTV + CSV covenants** | Non-interactive settlement, relative timelocks for disputes |

---

## Research Roadmap

### Phase 1: Foundation (Q2 2026) ✅ COMPLETE

| Deliverable | Owner | Status |
|-------------|-------|--------|
| L2-compatible wallet architecture | Core Team | ✅ Complete |
| HKDF key derivation for channels | Core Team | ✅ Complete |
| QR-based peer exchange protocol (l2soq:// URI scheme) | Wallet Team | ✅ Complete |
| Channel state machine (open/send/receive/close) | Wallet Team | ✅ Complete |
| 2-of-2 Dilithium multisig scripts | Wallet Team | ✅ Complete |
| CSV/CTV covenant construction | Wallet Team | ✅ Complete |
| Commitment TX builder (BIP143-compatible) | Wallet Team | ✅ Complete |
| Initial BOLT specification review | Research | 🔄 In Progress |
| Security model research | Security Lead | 🔄 In Progress |

### Phase 2: Specification (Q2 2026)

| Deliverable | Owner | Timeline |
|-------------|-------|----------|
| BOLT specification review complete | Research | 8 weeks |
| Dilithium channel prototype (regtest) | Crypto Lead | 10 weeks |
| L2SOQ Protocol specification draft docs | Core Team | 6 weeks |
| Routing algorithm analysis | Research | 6 weeks |

### Phase 3: Multi-Hop Design (Q3 2026)

| Deliverable | Owner | Status |
|-------------|-------|--------|
| Multi-hop payment routing design | Research | ⬜ Not started |
| Hash-based forwarding alternatives for Dilithium | Research | ⬜ Not started |
| Basic routing implementation | Dev Team | ⬜ Not started |
| Initial security review | External | ⬜ Not started |

### Phase 4: L2 Security Audit (Q3–Q4 2026)

| Deliverable | Owner | Timeline |
|-------------|-------|----------|
| External audit of channel protocol | External (Halborn) | 8 weeks |
| Force-close path verification | External | Included |
| Covenant script audit (CTV + CSV) | External | Included |
| Performance optimization | Dev Team | 6 weeks |
| Bug bounty program launch | Community | Ongoing |

### Phase 5: L2 Mainnet Deploy (Post-Audit)

| Deliverable | Owner | Timeline |
|-------------|-------|----------|
| L2SOQ activation via flag-day height (post-audit) | Core Team | 2 weeks |
| Liquidity bootstrapping | Community | Ongoing |
| Multi-hop channel support | Dev Team | Ongoing |

---

## Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Quantum adversary | Dilithium signatures throughout |
| Channel breach (stale state) | ELTOO state supersession — latest state always wins, CSV timelock dispute window |
| Routing attacks | Onion routing (Sphinx adaptation) |
| Liquidity attacks | Channel capacity limits (min 100 SOQ) |
| Eclipse attacks | L1 peer diversity requirements |

### Audit Scope (Preliminary)

1. Dilithium 2-of-2 multisig implementation (witness v6)
2. CTV covenant hash commitment correctness
3. CSV relative timelock enforcement on force-close
4. ELTOO state supersession logic
5. HTLC hash-lock security
6. HKDF key derivation paths (funding, state, HTLC)

---

## Resource Requirements

### Team (Estimated)

| Role | FTE | Duration |
|------|-----|----------|
| Protocol Engineer | 2.0 | 12 months |
| Cryptography Researcher | 0.5 | 12 months |
| Security Engineer | 1.0 | 6 months |
| Wallet Developer | 1.0 | 6 months |
| DevOps/Infrastructure | 0.5 | 12 months |

**Total**: ~5 FTE-years

### External Costs (Estimated)

| Item | Cost (USD) |
|------|------------|
| Security Audit (L2 specific) | $100,000 - $200,000 |
| Infrastructure (Testnet) | $5,000/month |
| Bug Bounty Program | $50,000 initial |

---

## Dependencies

### Hard Prerequisites

- [x] Genesis: Dilithium signatures
- [x] Genesis: LatticeFold+ verification (ALWAYS_ACTIVE)
- [x] Genesis: CTV + CSV covenant opcodes (ALWAYS_ACTIVE)
- [ ] Stage 3: Full PQ privacy primitives (Lattice-BP++, height-gated on mainnet; active on stagenet)
- [x] Stage 4: Solana bridge operational (SoquShield)

### Soft Prerequisites

- [ ] Mainnet stability (6+ months)
- [ ] Exchange integrations complete
- [ ] Wallet ecosystem mature
- [ ] Community liquidity available

---

## Success Metrics

| Metric | Target (Y1) | Target (Y2) |
|--------|-------------|-------------|
| Active channels | 1,000 | 10,000 |
| Network capacity | 1M SOQ | 10M SOQ |
| Payment success rate | >99% | >99.5% |
| Average payment latency | <1 sec | <500ms |
| Monthly transaction volume | 100K | 1M |

---

## Appendix A: Lightning Network Performance Data (2025)

*Source: Industry research, January 2025*

| Metric | Value | Source |
|--------|-------|--------|
| Monthly transactions | 8M+ | CoinLaw.io |
| Q1 2025 transactions | 100M | Medium/Industry |
| Payment success rate | 99.7% | RhinoBitcoin |
| Network capacity | 5,358 BTC (~$509M) | SimpleSwap |
| Active nodes | ~16,000 | CoinLaw.io |
| Active channels | ~52,700 | Industry data |
| Payment latency | <500ms typical | Lightning.network |

**Key insight**: Lightning Network processed 100M transactions in Q1 2025 alone, with 99.7% success rate.
This demonstrates that payment channel networks at scale are production-ready technology.

---

## Appendix B: Competitive Analysis

| Network | L1 | Quantum Safe | TPS | Status |
|---------|-----|--------------|-----|--------|
| Bitcoin Lightning | Bitcoin | ❌ | 1M+ | Production |
| Litecoin Lightning | Litecoin | ❌ | Similar | Limited adoption |
| Solana | N/A (L1) | ❌ | 65K | Production |
| **L2SOQ** | **Soqucoin** | **✅** | **500K+** | **Prototype (Stagenet, May 2026)** |

**Unique value proposition**: L2SOQ is the first quantum-safe payment channel network
using ELTOO state supersession with Dilithium signatures and covenant opcodes.

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | 2026-01-08 | Core Team | Initial draft |
| 0.3 | 2026-01-10 | Core Team | Added open research challenges, VC-ready framing, public release |
| 0.4 | 2026-05-20 | Wallet Team | Prototype complete: single-hop channels, QR exchange, L1 settlement |
| 0.5 | 2026-05-20 | Core Team | ELTOO architecture, CTV/CSV covenants, witness v6, measured perf data, updated roadmap |

---

> [!NOTE]
> **Public Document**
> This specification is publicly available to encourage community feedback and research collaboration.
