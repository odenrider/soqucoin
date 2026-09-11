# Soqucoin v0.22 Design Note

> Status (2026-09-11): historical draft. LatticeFold+ batch verification (`OP_CHECKFOLDPROOF`, witness v3) is deprecated and its deployment does not activate on any network; its successor for confidential assets and succinct proofs is SoquObscura, in research and not scheduled on any network. The activation plan below was not carried out.

## Full Confidential Amounts and LatticeFold+ Activation

Status: **Draft**  
Target Version: **v0.22**  
Scope: **Consensus, wallet/RPC, validation, tests**  

This document sketches the intended design for Soqucoin v0.22, where:

- Confidential transactions move from “range-correctness proofs attached to visible amounts” (v1) to **full confidential-amount semantics**.
- LatticeFold+ moves from “prototype verifier reserved for future activation” to an **actively enforced consensus feature** on mainnet.

The design below is compatible with the existing v1.0 code and whitepaper and is meant to guide future implementation work. It is not a binding specification.

---

## 1. Goals

1. **Confidential Amounts**
   - Replace on-chain explicit amounts for selected outputs with Pedersen commitments.
   - Enforce value conservation using commitments and Bulletproofs++ range proofs.
   - Preserve Dilithium-only authorization (no ECDSA in spend paths).

2. **LatticeFold+ Mainnet Activation**
   - Require a valid LatticeFold+ batch proof for blocks that include PAT-aggregated batches.
   - Preserve soft-fork safety (old blocks remain valid; new blocks add extra checks).

3. **Operational Safety**
   - Minimize miner overhead (prove off-chain, verify on-chain).
   - Maintain Scrypt PoW unchanged.
   - Provide clear deployment knobs (activation heights or versionbits).

---

## 2. Confidential Amount Semantics

### 2.1 Current v1 Behavior (Summary)

- Wallet (`rpcwallet.cpp::SendMoney`):
  - For `fConfidential=true`, constructs:
    - Pedersen commitment `C = vG + rH` (33 bytes).
    - Bulletproofs++ range proof `π` (~675 bytes).
    - Output script: `OP_RETURN <C> <π>`.
  - Still sets `recipient.nAmount = nValue` (amount is visible on-chain).

- Consensus (`script/interpreter.cpp::VerifyScript`):
  - For `OP_RETURN` outputs with sufficient size, parses `<C> <π>` and calls `zk::VerifyRangeProof(π, C)`.
  - Does **not** use `C` in value conservation; only `nValue` participates in `CheckTxInputs`.

### 2.2 v0.22 Target Behavior

#### 2.2.1 Output Types

We introduce three conceptual output types:

1. **Transparent Dilithium Output (TDO)**  
   - Script: standard P2WPK(Dilithium) or equivalent.  
   - Value: `vout.nValue > 0`.  
   - No commitments.

2. **Confidential Output (CTO)**  
   - Script: `OP_RETURN <C> <π>` (or a dedicated CT script type).  
   - Value: `vout.nValue == 0`.  
   - Commitment `C` and proof `π` carry the monetary value.

3. **Mixed/Legacy Outputs**  
   - Only allowed before activation height; after activation, consensus may forbid creation of new non-TDO/CTO forms.

#### 2.2.2 Consensus Rules

Let `H_CT` be the activation height for full confidential amounts.

For blocks at height `h >= H_CT`:

1. **Output Validation**
   - For each CTO:
     - Require `nValue == 0`.
     - Require script of the form `OP_RETURN <commitment> <proof>`.
     - Call `zk::VerifyRangeProof(π, C)` and fail the script if invalid.

2. **Input/Output Value Conservation**
   - For each transaction:
     - Partition inputs and outputs into **transparent** and **confidential**.
     - Transparent value conservation:
       \[
       \sum v_{\text{TDO,in}} \geq \sum v_{\text{TDO,out}} + \text{fee}
       \]
     - Confidential value conservation:
       \[
       \sum C_{\text{CTO,in}} - \sum C_{\text{CTO,out}} = \text{fee}_{\text{CT}} \cdot G
       \]
       where `fee_CT` is any difference intentionally paid as fee via CT outputs.
   - In early v0.22, it is acceptable to **forbid CT-derived fees** and require `fee_CT = 0`, i.e. commitment sums must match exactly.

3. **No Mixed Semantics**
   - After `H_CT`, new outputs that:
     - Have `nValue > 0` **and** an `OP_RETURN` CT payload:
       - Should be rejected as non-standard or invalid.

Implementation sketch:

- Extend `CTransaction` with helper methods:
  - `GetTransparentValueIn/Out()`
  - `GetCommitmentSumIn/Out()` (using `zk::GenerateCommitment` inverses or stored commitments).
- Modify `CheckTxInputs` (and/or a CT-specific helper) to enforce the above equations when a CT deployment flag is active.

### 2.3 Wallet / RPC Behavior

In v0.22, for CT outputs:

- `SendMoney` (or a dedicated `sendtoconfidential` RPC):
  - Sets `recipient.nAmount = 0`.
  - Stores `C`, `π`, `blinding`, and `nonce` in wallet metadata for recovery.
- Balance reporting:
  - Introduce `getbalance` modes:
    - `transparent` – sum of TDOs (current behavior).
    - `confidential` – sum of CTOs (via rewinding).
    - `total` – combined view.

Backwards compatibility:

- Before `H_CT`, retain current v1 behavior (visible amounts + attached proofs).
- After `H_CT`, soft-fork to disallow new v1-style “visible amount + CT proof” outputs.

---

## 3. LatticeFold+ Mainnet Activation

### 3.1 Current Behavior (v1 Summary)

- Verifier:
  - Implemented in `src/crypto/latticefold/verifier.cpp`.
- Script:
  - `OP_CHECKFOLDPROOF` parses a proof blob and calls `EvalCheckFoldProof`, which in turn calls the verifier.
- Activation:
  - Controlled by `Consensus::Params::nLatticeFoldActivationHeight`.
  - Mainnet: `INT_MAX` (effectively disabled).
  - Testnet/regtest: `0` (enabled from genesis).

### 3.2 v0.22 Target Behavior

1. **Deployment Flag**
   - Introduce a script verification flag `SCRIPT_VERIFY_LATTICEFOLD`.
   - In `ConnectBlock` / `CheckInputs`, set this flag when `height >= consensus.nLatticeFoldActivationHeight`.
   - In `EvalScript`, gate the `OP_CHECKFOLDPROOF` case on this flag rather than directly reading the chain height.

2. **Activation Parameters**
   - Mainnet:
     - Set `nLatticeFoldActivationHeight` to a specific height `H_LF` agreed at launch (or use versionbits/BIP9-style signaling if desired).
   - Testnet/regtest:
     - Keep `H_LF = 0` or a low value for continuous testing.

3. **Consensus Rule**
   - When `SCRIPT_VERIFY_LATTICEFOLD` is active:
     - Any script that executes `OP_CHECKFOLDPROOF` MUST supply a structurally valid proof that passes `LatticeFoldVerifier::VerifyDilithiumBatch`.
   - Before activation:
     - Executing `OP_CHECKFOLDPROOF` should either:
       - Fail with a dedicated “disabled opcode” error, or
       - Be treated as a no-op that causes the script to fail policy (recommended: treat as disabled to avoid ambiguity).

### 3.3 Interaction with PAT

For blocks that advertise a PAT-aggregated batch:

- Enforce that:
  - PAT proof (LogarithmicProof) commits to the same batch as the LatticeFold+ proof.
  - This linkage is already described in the whitepaper; implementation can:
    - Embed the PAT root in the LatticeFold+ `BatchInstance`.
    - Require the script to provide both proofs, or require the block header/coinbase to carry the LatticeFold+ proof that binds to the PAT root.

---

## 4. Deployment Strategy

### 4.1 Phased Rollout

> **Mainnet Staged Activation Schedule** (from CONSENSUS_COST_SPEC.md):
> - **Stage 1 (BP++ Opt-In)**: Height 50,000 (~35 days post-launch)
> - **Stage 2 (LatticeFold+ Active)**: Height 100,000 (~70 days post-launch)
> - **Stage 3 (Lattice-BP Hybrid)**: Height 200,000+ (future upgrade)

1. **v1.x (current)**
   - Dilithium-only signatures enforced.
   - PAT and LatticeFold+ wired and tested on regtest/testnet.
   - Bulletproofs++ attached to outputs; amounts visible.

2. **v0.22 (target)**
   - Activate:
     - Full confidential-amount semantics at `H_CT = 50,000` (Stage 1).
     - LatticeFold+ verification at `H_LF = 100,000` (Stage 2).
   - Retain backwards compatibility with historical blocks.

3. **Post-v0.22**
   - Introduce distributed LatticeFold+ provers (removing trust in centralized pools).
   - Lattice-BP Hybrid range proofs at Stage 3 (Height 200,000+).
   - Incrementally migrate more validation logic off-chain while keeping on-chain checks succinct.

### 4.2 Testing Requirements

- Unit tests:
  - CT value-conservation invariants.
  - Edge cases: zero-value commitments, overflow, negative values (must be rejected).
- Functional tests:
  - Pre-activation: v1-style outputs remain valid.
  - Post-activation:
    - v1-style “visible+CT” outputs rejected for new transactions.
    - Pure CT transactions accepted and validated.
    - LatticeFold+ proofs enforced when present.
- Fuzz tests:
  - Extend existing LatticeFold+ and Dilithium fuzz targets to cover CT and `OP_CHECKFOLDPROOF` with activation flags set/unset.

---

## 5. Summary

This design note captures the intended evolution from the current v1 semantics (Dilithium-only authorization, classical BP++ privacy, prototype LatticeFold+ verifier) to a v0.22 release with:

- **Full confidential-amount support** using Pedersen commitments and Bulletproofs++.
- **Mainnet-enforced LatticeFold+ verification** for batched Dilithium signatures.

All changes are designed to be:

- **Soft-fork compatible**: older blocks remain valid.
- **Operationally safe**: prover logic remains off-chain, verifiers are succinct and already benchmarked.
- **Auditable**: implementations live in well-scoped modules (`zk/`, `crypto/pat/`, `crypto/latticefold/`, `script/interpreter.cpp`, `validation.cpp`).

Future work (beyond v0.22) includes replacing BP++ with a lattice-based range proof system and deploying distributed LatticeFold+ provers to remove reliance on trusted pools.


