# pSOQ ↔ SOQ Gateway Architecture

> ⚠️ **Status (28 August 2026): a design in active development. No service is operating yet.**
> The gateway described below remains the planned automated path between pSOQ and native
> SOQ, and it stays open source. It is not live: no conversion, redemption, or exchange
> service between pSOQ and SOQ operates or is offered today, and it will not operate
> before third-party audit and review. Nothing in this document is a promise of
> redemption, of backing, or of a timeline; the specific dates and backing tables below
> predate the current review and will be revised.

> **Status:** Design record. Demonstrated on devnet and stagenet in 2026; not deployed.  
> **Last Updated:** June 15, 2026  
> **Audit Requirement:** Halborn Phase 2 Audit in progress  

---

## Overview

This document records the gateway design, as of June 2026, for moving between pSOQ (Solana SPL token) and native SOQ. It was published to document the technical design and trust model of the SOQ-TEC cross-chain gateway. The design was not deployed.

**Bottom line up front:** The design used a standard lock-and-mint / burn-and-release pattern. It was built for cryptographic longevity in a post-quantum environment, utilizing Dilithium attestations and XMSS-Lite revolving vault custody.

---

## Architecture

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SOQ → pSOQ (Deposit)                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   User sends SOQ ──► Dilithium L1 Vault ──► Relayer committee attestation   │
│                                                            │                │
│                                                            ▼                │
│                                              pSOQ minted to XMSS Vault      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                           pSOQ → SOQ (Redemption)                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   User burns pSOQ on Solana ──► Relayers detect burn ──► Quantum Express    │
│                                                            │                │
│                                                            ▼                │
│                                                   SOQ released from L1 Vault│
└─────────────────────────────────────────────────────────────────────────────┘
```

### Components

#### 1. Dilithium L1 Vault (Soqucoin L1)

- **Location:** Native Soqucoin script
- **Security:** Dilithium ML-DSA-44 multi-signature (3-of-5 threshold)
- **Function:** Holds locked SOQ backing all circulating pSOQ
- **Audit scope:** Script correctness, signature verification, replay protection

The vault is the critical L1 component. It is secured by the same post-quantum signatures that protect all Soqucoin transactions.

#### 2. pSOQ Token Contract & XMSS Vault (Solana)

- **Standard:** SPL Token & Anchor program
- **Mint Authority:** Gateway program (controlled by relayer consensus)
- **Solana Fees:** Ed25519 (required by Solana for gas fees, but keys never touch the network for bridge signatures)
- **Custody:** XMSS Revolving Door (WOTS+ key hashes)

This component resides on Solana. The trade-off is explicit: pSOQ holders use Solana's runtime for liquidity while securing their assets inside an offline-signer XMSS vault.

#### 3. Dilithium Relayer Network (3-of-5 Committee)

- **Function:** Observes lock/burn events, attests to state changes
- **Mechanism:**
  - 3-of-5 Dilithium attestation relayer committee
  - Independent validator nodes running on-chain verification
  - Quantum Express optimistic release for rapid redemptions (under 30 seconds)

**Honest assessment:** The relayer committee is the trust anchor of the gateway. A compromised relayer set could:
- Mint unbacked pSOQ (inflation attack)
- Fail to release locked SOQ (liveness failure)
- Censor specific redemption requests

The design mitigated this through multi-signature threshold requirements and monitoring.

---

## Security Model

### What IS Protected

| Component | Protection Level |
|-----------|-----------------|
| Locked SOQ in vault | Dilithium ML-DSA-44 (NIST Level 2 PQ) |
| L1 Vault script logic | Consensus-enforced on Soqucoin L1 |
| Solana Asset Custody | XMSS Revolving Door (WOTS+ key hashes) |

### What is NOT Protected

| Component | Vulnerability |
|-----------|--------------|
| Solana gas fee signatures | Ed25519 (vulnerable to Shor's algorithm) |
| Relayer uptime | Dependent on relayer committee stability |

**For miners considering pSOQ:** If your threat model includes quantum adversaries on the Solana network, pSOQ is not the right vehicle. The design treated it as a liquidity path and never as a long-term store of value. Mine native SOQ post-mainnet for actual PQ protection.

---

## Economic Considerations

### Peg Maintenance

The design relied on a 1:1 redemption rate to hold the two prices together:
- If pSOQ traded below SOQ, holders could redeem pSOQ for SOQ at 1:1, reducing pSOQ supply until prices converged.
- If pSOQ traded above SOQ, holders could lock SOQ for pSOQ at 1:1, increasing pSOQ supply until prices converged.

This assumed:
1. An operating gateway
2. Liquidity on both sides
3. Transaction costs below the spread

### Backing Model

The design called for full 1:1 backing, with reserve pools funded from Foundation mining rewards after the Phase 2 audit and senior redemption priority for the public float. No reserve pool was funded and the design was not deployed.

---

## Implementation Timeline

| Phase | Target | Deliverable |
|-------|--------|-------------|
| Design | Q2 2026 ✅ | This document, threat model |
| Development | Q2 2026 ✅ | Custom Dilithium relayer, XMSS Vault |
| Audit | Q2-Q3 2026 | Halborn Phase 2 audit (in progress) |
| Testnet | Q2-Q3 2026 | Integration testing on devnet and stagenet |
| Mainnet | Planned for Q3 2026 at the time of writing | Not carried out; the design was not deployed |

> [!NOTE]
> **Gateway Design Choice**: The team pivoted from third-party oracle providers to a custom post-quantum relayer committee to ensure native signature compatibility and eliminate third-party oracle risks.

---

## Risk Disclosure

### The Gateway Was Not Activated

The design made activation contingent on audit completion. The reasons recorded at the time that it might not activate:

1. **Audit findings:** Critical vulnerabilities that cannot be remediated
2. **Regulatory uncertainty:** Legal advice indicating the gateway creates unacceptable risk
3. **Technical blockers:** L1 script limitations or Solana runtime issues

The design was not deployed. pSOQ is a token on Solana. The path from pSOQ to SOQ is in legal review and details will be published when it is complete.

### Relayer Compromise Scenarios

| Scenario | Impact | Mitigation |
|----------|--------|------------|
| Relayer set colludes | Unbacked pSOQ minted | Threshold signatures, time-locked withdrawals |
| Relayer keys compromised | Same as above | Key rotation, hardware security modules |
| Relayer set goes offline | Gateway halts, no new mints or redeems | Fallback relayer set, emergency governance |

The design addressed these threats, but no system is invulnerable. A gateway adds trust assumptions that native SOQ does not have.

---

## For Miners: Practical Guidance

The recommendation recorded in June 2026 for anyone evaluating participation in Soqucoin:

1. **pSOQ is for pre-mainnet exposure only.** It is a speculation vehicle, not the ultimate store of value.
2. **Mining native SOQ post-mainnet gives you actual PQ protection.** That is the core thesis.
3. **Do not over-allocate to pSOQ based on gateway assumptions.** The design was not deployed.
4. **Audit results are published when they are available.**

---

## Questions?

- **GitHub Issues:** [soqucoin/soqucoin/issues](https://github.com/soqucoin/soqucoin/issues)
- **Discord:** [discord.gg/kc6GMmbZvX](https://discord.gg/kc6GMmbZvX)
- **Technical Contact:** pm@soqu.org

---

*Last updated: June 15, 2026*  
*Document maintainer: Soqucoin Core Team*
