# Soqucoin-Solana Gateway Architecture

> ⚠️ **Status (28 August 2026): a design in active development. No service is operating yet.**
> The gateway described below remains the planned automated path between pSOQ and native
> SOQ, and it stays open source. It is not live: no conversion, redemption, or exchange
> service between pSOQ and SOQ operates or is offered today, and it will not operate
> before third-party audit and review. Nothing in this document is a promise of
> redemption, of backing, or of a timeline; the specific dates and backing tables below
> predate the current review and will be revised.

> **Version**: 1.0 | **Status**: Shipped to Devnet/Stagenet
> **Last Updated**: June 15, 2026
> **Network**: Soqucoin ↔ Solana

---

> [!NOTE]
> **Gateway Design Choice**: The team pivoted from third-party oracle providers to a custom post-quantum relayer committee to ensure native signature compatibility and eliminate third-party oracle risks.

---

## 1. Overview

The Soqucoin-Solana Gateway enables bidirectional transfer of value between the Soqucoin mainnet and the Solana blockchain through a wrapped token mechanism.

| Component | Description |
|-----------|-------------|
| **SOQ** | Native Soqucoin token (L1, Dilithium signatures) |
| **pSOQ** | Wrapped SOQ on Solana (SPL token inside XMSS vault) |
| **Gateway** | Smart contract system managing lock/mint/burn/release |

---

## 2. Token Mechanics

### SOQ → pSOQ (Lock & Mint)

```
1. User sends SOQ to Dilithium L1 Vault custody address on Soqucoin
2. Dilithium relayer committee observes and confirms deposit (3-of-5 threshold)
3. pSOQ is minted on Solana directly into user's XMSS Revolving Door vault
```

### pSOQ → SOQ (Burn & Release)

```
1. User burns pSOQ on Solana via the gateway program
2. Dilithium relayer committee observes and confirms the burn
3. SOQ is released via Quantum Express to the user's Dilithium address in under 30 seconds
```

---

## 3. Security Model

### Relayer Set

| Parameter | **Gateway Committee** | Justification |
|-----------|------------------------|---------------|
| **Relayer count** | **5** | Balanced committee for signature efficiency |
| **Threshold** | **3-of-5 (60%)** | Fault tolerant, ensures rapid attestation |
| **Geographic distribution** | **Minimum 3 continents** | Jurisdiction diversity, latency distribution |
| **Technical requirements** | HSM, 99.9% uptime, 24/7 on-call | Professional operations standard |

### Relayer Selection Criteria

| Slot | Type | Region | Selection Criteria |
|------|------|--------|-------------------|
| 1 | Foundation-operated | North America | Fiduciary responsibility |
| 2 | Mining pool partner | Europe | Hashrate stake alignment |
| 3 | Exchange partner | Asia | Liquidity stake alignment |
| 4 | Security firm | Variable | Audit relationship (e.g., Halborn) |
| 5 | Infrastructure provider | Variable | Professional operations |

### Collateralization

| Model | Description | Status |
|-------|-------------|--------|
| **1:1 Custody** | SOQ locked = pSOQ minted | ✅ Confirmed |
| **Proof of Reserves** | Real-time on-chain dashboard | ✅ Active |

---

## 4. Smart Contract Architecture

### Solana Program (pSOQ)

| Component | Technology | Notes |
|-----------|------------|-------|
| **Token Standard** | SPL Token | Native Solana token standard |
| **Mint Authority** | Multisig PDA | Controlled by Dilithium relayer committee |
| **Custody Program** | XMSS Revolving Door | Offline-signer WOTS+ key hashes |

### Soqucoin Gateway Address

| Component | Technology | Notes |
|-----------|------------|-------|
| **Custody Address** | Dilithium L1 Vault | 3-of-5 signature threshold |
| **Monitoring** | Relayer committee nodes | Watch for deposits/releases |

---

## 5. Risk Considerations

### Known Risks

| Risk | Mitigation |
|------|------------|
| **Relayer collusion** | Threshold signature, geographic distribution |
| **Smart contract bugs** | Audit before launch, timelocked upgrades |
| **Solana outages** | Queue deposits, process on recovery |
| **Soqucoin reorgs** | Wait for 288+ confirmations. That is the chain's own finality horizon (`nMaxReorgDepth`), and coinbase maturity now equals it (`chainparams.cpp`, `nCoinbaseMaturity = 288`). The horizon is enforced when a header is first accepted and is not re-checked, so treat 288 as the practical bound, not an absolute one: bead `finality-horizon-header-only-8p5y`, `doc/PAT_WITNESS_PRUNING.md` §6 |
| **Key compromise** | Hardware security modules, rotation procedures |

### Out of Scope (v1)

- Atomic swaps (requires protocol-level support)
- Trustless bridge (requires light client verification)
- Cross-chain smart contracts

---

## 6. Deployment Timeline

| Phase | Target | Description |
|-------|--------|-------------|
| **Design** | Q2 2026 | Architecture finalization ✅ |
| **Development** | Q2 2026 | Custom Dilithium relayer and XMSS Vault ✅ |
| **Audit** | Q2-Q3 2026 | Halborn Phase 2 audit (in progress) |
| **Testnet** | Q2-Q3 2026 | Integration testing on devnet and stagenet |
| **Mainnet** | **Q3 2026** | Production gateway activation |

---

## 7. pSOQ Token Information

| Parameter | Value |
|-----------|-------|
| **Name** | Pegged Soqucoin |
| **Symbol** | pSOQ |
| **Decimals** | 8 (matches SOQ) |
| **Network** | Solana Mainnet |
| **Total Supply** | 1,000,000,000 (1 billion) |
| **Mint Address** | `6NX2MWBuJM2Fn63K4hUgMPivLXHV8pwsU1yTdmjKpump` |

---

## 8. pSOQ Backing Economics

### The Core Economics

pSOQ was launched on Pump.fun before Soqucoin mainnet was active. This creates a timing mismatch:

| Asset | Supply | Current Backing |
|-------|--------|-----------------|
| **pSOQ (Solana)** | 1 billion | ❌ Not backed (pre-gateway) |
| **SOQ (at block 100k)** | ~5 billion | N/A (native L1 token) |

**"1:1" refers to the exchange rate, not supply parity:**
- 1 SOQ locked in vault = 1 pSOQ redeemable
- Gateway operates at 1:1 unit rate
- Total pSOQ backing depends on SOQ locked in vault

### pSOQ Distribution

| Holder | Amount | Percentage | Status |
|--------|--------|------------|--------|
| **LP (Foundation)** | ~120M pSOQ | 12% | Locked until Q3 2026 |
| **Team Wallets** | ~60M pSOQ | 6% | Liquid |
| **Foundation Total** | **~180M pSOQ** | **18%** | See subordination below |
| **Public Float** | ~820M pSOQ | 82% | Trading on Solana DEXs |

### Backing Model: Foundation Commitment + Open Market Redemption

#### Phase 1: Gateway Launch (Q3 2026)

```
Foundation commits: Lock 180M mined SOQ
Vault balance: 180M SOQ
pSOQ circulation: 1B
Foundation pSOQ (subordinated): 180M
Public pSOQ (senior): 820M

Effective public backing: 180M / 820M = 22%
```

#### Phase 2: Open Redemption (Ongoing)

```
Independent market participants lock additional SOQ to redeem pSOQ
Vault fills progressively as redemptions occur

Month 1: ~380M SOQ in vault (46% public backing)
Month 3: ~580M SOQ in vault (70% public backing)
Month 6+: Approaching full backing
```

### Foundation Subordination Structure

> [!NOTE]
> The foundation's 180M pSOQ is subordinated to public holdings.
> This means the team's pSOQ is redeemable only after public pSOQ is 100% backed.

| Priority | Holder | Redemption Rights |
|----------|--------|-------------------|
| **Senior (1st)** | Public (820M pSOQ) | Can redeem immediately from vault |
| **Junior (2nd)** | Foundation (180M pSOQ) | Can only redeem after vault ≥ 1B SOQ |

**Subordination Terms:**
1. Foundation locks 180M mined SOQ at gateway launch.
2. Foundation pSOQ redeems LAST, after all public pSOQ is 100% backed.
3. Foundation cannot front-run public redemptions.
4. Subordination is enforced by smart contract logic.

### Illustrative Convergence Scenarios

| Timeframe Post-Gateway | Est. Vault Balance | Public Backing | Illustrative pSOQ/SOQ |
|-----------------------|-------------------|----------------|-------------------|
| Gateway launch | 180M SOQ | 22% | 0.20 - 0.40 |
| Month 1 | ~380M SOQ | 46% | 0.40 - 0.60 |
| Month 3 | ~580M SOQ | 70% | 0.65 - 0.85 |
| Month 6+ | ~800M+ SOQ | 97%+ | 0.90 - 1.00 |

*Illustrative only — not a projection or promise. Actual convergence depends on SOQ liquidity and independent market participation.*

### Why This Model Works

| Stakeholder | Benefit |
|-------------|---------|
| **Public pSOQ holders** | 22% day-1 backing (vs 0% pure market model) |
| **Foundation** | Demonstrates alignment ("we eat last") |
| **Community** | Founders cannot dump before the gateway is stable |
| **Regulators** | Clear subordination = transparent risk hierarchy |

### Required Disclosures

**Pre-Gateway (Now):**
> pSOQ is a speculation vehicle representing aspirational access to Soqucoin. 
> It is NOT currently backed. Gateway activation is planned for Q3 2026.

**At Gateway Launch:**
> pSOQ Gateway Economics:
> - Total pSOQ: 1 billion
> - Foundation holdings: 180M (18%), subordinated
> - Public float: 820M (82%), senior
> - Current vault balance: [LIVE DASHBOARD]
>
> Foundation pSOQ cannot be redeemed until public pSOQ is 100% backed.

---

## 9. pSOQ Launch Models (Community Analysis)

### The Core Challenge

At mainnet genesis, there is 0 SOQ in circulation until miners produce blocks. This creates a chicken-and-egg problem for pSOQ:

| Challenge | Impact |
|-----------|--------|
| No SOQ to lock | Cannot mint backed pSOQ |
| No pSOQ liquidity | No Solana DeFi integration |
| Miners need incentive | Early adoption requires rewards |

### Model A: Pre-Mine Pool (Treasury-Backed)

```
Foundation pre-mines pSOQ supply → available at Solana launch
SOQ backing comes from early mining treasury
```

| Aspect | Assessment |
|--------|------------|
| **Liquidity** | ✅ Immediate (pSOQ available day 1) |
| **Complexity** | ✅ Simple, with no oracle dependency |
| **Trust** | ❌ Centralized, requiring users to trust foundation backing |
| **Alignment** | ❌ Conflicts with "0% premine" philosophy |

> [!WARNING]
> **Expert Assessment**: This model contradicts Soqucoin's fair-launch principles.
> While operationally simple, it introduces counter-party risk and undermines
> the project's core value proposition. **Not recommended.**

### Model B: Mining-Backed (Pure Lock/Mint)

```
pSOQ exists ONLY when SOQ is locked in bridge contract
No pSOQ until mainnet miners produce SOQ
```

| Aspect | Assessment |
|--------|------------|
| **Liquidity** | ❌ Delayed (must wait for mining circulation) |
| **Trust** | ✅ Fully trustless with 1:1 provable backing |
| **Alignment** | ✅ Perfect, with no premine or treasury |
| **DeFi Timeline** | ❌ Weeks/months delay for Solana integration |

> [!TIP]
> **Expert Assessment**: This is the most philosophically pure model and aligns
> with Soqucoin's values. The liquidity delay is acceptable if properly communicated.
> **Recommended for long-term.**

### Model C: Hybrid (Forward-Commit Mining)

```
Phase 1: Foundation provides temporary liquidity guarantee
Phase 2: Mining-backed pSOQ replaces temporary supply
Phase 3: Foundation guarantee expires, fully decentralized
```

| Aspect | Assessment |
|--------|------------|
| **Liquidity** | ✅ Early access with transition plan |
| **Trust** | 🟡 Temporary centralization, planned sunset |
| **Alignment** | 🟡 Compromise, remaining transparent about tradeoffs |
| **Complexity** | ❌ Higher, as it requires migration mechanics |

> [!IMPORTANT]
> **Expert Assessment**: This model balances pragmatism with principles IF:
> - Foundation liquidity is time-bounded (e.g., 90 days)
> - Transition to mining-backed is automatic and verifiable
> - Community is fully informed of the hybrid phase
>
> **Acceptable if properly executed.**

### Recommended Approach

Based on expert analysis, the recommended path is:

| Phase | Timeline | Model | Notes |
|-------|----------|-------|-------|
| **Genesis** | Q2 2026 | No pSOQ | Focus on SOQ mining, network stability |
| **Early Gateway** | Q2 2026 | Model B | Mining-backed only, limited liquidity |
| **Mature Gateway** | Q3+ 2026 | Model B | Full liquidity from mining circulation |

**Key Principle**: Wait for natural mining circulation rather than compromising
on the "0% premine" commitment. Early Solana integration is not worth
sacrificing long-term credibility.

---

## 10. Gateway Decisions

### Decision 1: Relayer Provider (Custom Dilithium Committee)

| Option | Recommendation |
|--------|----------------|
| **Custom Relayer Committee** | ✅ **Selected** |
| Wormhole Guardians | v2 consideration |
| LayerZero | Alternative if terms unfavorable |

**Justification:**
- Custom 3-of-5 committee using Dilithium signatures provides native post-quantum security
- Eliminates third-party oracle fees and protocol risks
- Prevents cross-chain validation bypass vectors seen in third-party implementations

---

### Decision 2: Activation Threshold (5B SOQ Mined)

| Threshold | Blocks | Timeline | Status |
|-----------|--------|----------|--------|
| 1B SOQ | ~20,000 | ~14 days | ❌ Too early |
| **5B SOQ** | ~100,000 | **~69 days** | ✅ **Selected** |
| 10B SOQ | ~200,000 | ~139 days | ❌ Unnecessary delay |

**Justification:**
- Sufficient on-chain liquidity for redemption-driven price convergence
- Aligns with Stage 2 (LatticeFold+) activation, signaling maturity
- Exchange listings likely by this point
- Conservative threshold, prioritizing stability over speed

---

### Decision 3: Fee Structure (0.1% Gateway Fee)

| Component | Decision |
|-----------|-------------------|
| **Gateway fee** | 0.1% of transfer value |
| **Minimum fee** | 100 SOQ (prevents dust attacks) |
| **Maximum fee** | 10,000 SOQ cap |
| **Distribution** | 80% validators, 20% treasury |
| **Payment** | Monthly settlement in SOQ |

**Justification:**
- Industry standard fee structure helps fund committee operations
- Sustainable for professional validator operations
- Lower fee discourages validators; higher fee discourages users

---

### Decision 4: Emergency Procedures (Tiered Response)

| Level | Trigger | Action | Authority |
|-------|---------|--------|-----------|
| **1: Anomaly** | Unusual volume | Monitoring alert | Ops team |
| **2: Concern** | Failed attestation | Rate limiting | 2 validators |
| **3: Incident** | Exploit suspected | Gateway pause | 3 validators |
| **4: Critical** | Active exploit | Full freeze | 4 validators |

**Automatic Circuit Breakers:**
- Hourly volume >200% of 7-day average → Rate limit to 50%
- Single transaction >5% of vault → Manual review required
- 3+ consecutive attestation failures → Pause new mints
- Proof of Reserves mismatch → Full freeze

---

### Decision 5: Governance (Progressive Decentralization)

| Phase | Timeline | Model |
|-------|----------|-------|
| **Phase 1** | Months 0-6 | Foundation multisig (3-of-5) |
| **Phase 2** | Months 6-12 | Validator committee (5-of-7) |
| **Phase 3** | Months 12-18 | Committee + token holder veto |
| **Phase 4** | Months 18-24 | Full token governance |

**Upgrade Timelocks:**
| Type | Timelock |
|------|----------|
| Parameter adjustment | 24 hours |
| Bug fix | 48 hours |
| Feature addition | 7 days |
| Critical change | 14+ days |

---

### Decision 6: Sunset Planning (24-Month Support Window)

| Phase | Timeline | Status |
|-------|----------|--------|
| **Full support** | Months 0-18 | Normal operations, LP incentives |
| **Notice period** | Month 18 | Announce 6-month sunset |
| **Reduced support** | Months 18-24 | No new incentives, full function |
| **Sunset** | Month 24+ | Gateway open, no guaranteed support |

**Post-Sunset:**
- pSOQ remains redeemable indefinitely (vault stays)
- Minimum 3 validators maintain operations
- Monthly community updates in final 6 months

---

## 11. Remaining Open Questions

1. **Initial validator candidates**: Identify entities meeting committee criteria
2. **Gateway audit timeline**: Coordinate with Halborn for Phase 2 completion
3. **Regulatory review**: Confirm gateway structure with legal counsel

---

## 12. Related Documents

- [Consensus Cost Specification](CONSENSUS_COST_SPEC.md): Mainnet protocol parameters
- [Mining Guide](mining-guide.md): SOQ acquisition
- [Node Operator Guide](node-operator-guide.md): Running Soqucoin infrastructure
- [BRIDGE_ARCHITECTURE.md](BRIDGE_ARCHITECTURE.md): Detailed technical architecture

---

*Last Updated: June 15, 2026*
*Gateway decisions pending board approval post-mainnet*
*Soqucoin Core Development Team*
