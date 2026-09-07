# DL — Witness-version fork class and the additive asset-rule posture

Status: ratified 2026-09-07. Applies to the mainnet genesis binary and every later release.

## 1. The rule

A release is a soft fork iff every block it accepts, the genesis binary also accepts. A release
may therefore **add** a rejection, and may never accept anything the genesis binary rejects.
Two corollaries decide everything below:

1. A consensus rule in the genesis binary that **rejects** a shape is a promise every later
   release must keep. A rule that **exempts, skips or widens** on a shape is one every later
   release must keep exempting.
2. So the genesis binary carries **no consensus behaviour keyed on a dormant feature's shape**
   unless that behaviour is one every later release will keep verbatim.

"Dormant in the binary" is necessary for a later flag-day activation to be a soft fork. It is not
sufficient. The *shape* of the dormant feature's rules decides the fork class, and a rule that
switches from reject to accept at activation is a hard fork however it is gated.

## 2. What was in the genesis candidate and what changed (2026-09)

| rule | where | class before | disposition |
|---|---|---|---|
| SOQ-I009 creation reservation: a block may not create an output of a dormant witness version | `validation.cpp` ConnectBlock | rejection relaxed at activation → **hard fork per version** | retired for every version except v2 |
| SOQ-ARCH-001: confidential (v4/v10) outputs rejected while SoquObscura dormant | ConnectBlock | same | retired |
| `bad-*-authority-not-active`: authority-shaped tx rejected while the asset deployment is dormant | `CheckInputs` | same (the activation release accepts the shape) | replaced by fall-through to ordinary per-input script verification |
| Undo mirrors for asset supply, authority outpoint, freeze registry and key images | `DisconnectBlock` | state corruption, not fork class: reversed ops ConnectBlock never applied | gated on the deployment exactly as ConnectBlock is |
| Asset/attestation opcodes inside a v6 script: `BAD_OPCODE` while the asset flag is clear, executed once set | `interpreter.cpp` v6 path | rejection relaxed at asset activation → hard fork for every asset activation after P2WSH-Dilithium | made unconditionally invalid inside v6 (opcodes are dispatched by witness version, never by script) |
| Coinbase asset bans (`bad-cb-usdsoq-asset`, `bad-cb-btcsoq-asset`) and dual-marker ban | `CheckTransaction` | rejections every release keeps | **kept**, coinbase USDSOQ ban extended to v10 |
| Per-asset `nValue` conservation and per-asset fee filter | `CheckTxInputs`, ConnectBlock | rejections/accounting every release keeps | kept; satisfied trivially forever under §4 |
| Ex-nihilo mint exemption from conservation; authority script skip | `CheckTxInputs`, `CheckInputs` | gated on deployment active and authority initialised; never fire on mainnet in the genesis binary | kept dormant; **the activation release must delete both** (§4) |

Net posture of the genesis binary on mainnet: witness v3–v16 are creatable, anyone-can-spend at
consensus, worth their `nValue` in SOQ, non-standard until their deployment activates, with no
asset accounting of any kind. v2 (PAT) is permanently unconstructable because its spend path
binds neither the witness program nor the sighash.

## 3. Per-version fork class after the change

| ver | owner | activation class | note |
|---|---|---|---|
| v0/v1 | Dilithium | active | base forms |
| v2 | PAT | n/a | not an output type; permanently unfundable |
| v3 | LatticeFold (retired) | soft, if ever revived with a sound verifier | creatable, anyone-can-spend |
| v4 | SoquObscura pool (confidential SOQ) | **soft**, provided the activation release follows §4 (shielded-pool value model) | |
| v5 / v7 | USDSOQ authority / holding | **soft**, provided the activation release follows §4 | |
| v6 | P2WSH-Dilithium | **soft** | spend binds `SHA256(witnessScript)` to the program and the sighash inside the script; the covenant opcodes (CTV, CSFS, CDKH, V6_CONTROLFLOW) are NOP-when-clear inside v6 scripts and can activate with it or after it |
| v8 / v9 | BTCSOQ holding / authority | **soft**, provided the activation release follows §4 | |
| v10 | confidential USDSOQ | **soft**, provided the activation release follows §4 | the USDSOQ-gated backstop `bad-txns-usdsoq-confidential-not-active` stays: it is a tightening |
| v11–v16 | unallocated | soft for any future version whose rules are additive | allocation-time review applies §1 |

Out of scope here and tracked separately: `DEPLOYMENT_APO` gates SIGHASH_ANYPREVOUT at consensus
on the v1/v7/v8 path, so its activation is a rejection relaxed = hard fork; the additive fix is
to reject those hashtypes on v1/v7/v8 permanently and reach APO only inside v6 scripts.

## 4. The additive asset-rule design the activation releases must follow

The genesis binary makes activation *possible* as a soft fork. The activation release makes it
*actual* only if every rule it adds is a rejection. Concretely:

1. **Asset amounts live outside `nValue`.** Every v7/v8/v10 output carries `nValue = 0`. The
   asset amount is committed in a per-transaction ledger output (`OP_RETURN`, tag, version,
   `(vout, amount)` pairs) that old nodes ignore and new nodes parse. An asset output without a
   ledger entry has amount 0. Pre-activation asset-shaped outputs have amount 0 by definition.
2. **SOQ conservation stays asset-blind.** `in ≥ out` and `fee = in − out` over every output.
   The genesis binary's per-asset conservation and fee-filter rules only ever see zeros for
   asset outputs and are therefore satisfied trivially forever; they are not relaxed, and they
   need not be.
3. **Asset conservation is an added rule** over ledger amounts, with an outpoint-keyed asset
   index in the coins database (no wire-format change). Mint and burn are additional checks that
   permit a ledger imbalance iff the authority check passes; they are never exemptions from (2).
4. **Authority verification is additive.** The authority transaction's fee input is an ordinary
   v1 spend with an ordinary signature; the M-of-N ML-DSA-44 signatures ride in the witness of
   the v5/v9 marker input it spends (the authority UTXO chain). The genesis binary sees that
   marker spend as anyone-can-spend; the activation release requires the M-of-N. **The
   whole-transaction script-verification skip and the conservation exemption in the genesis
   binary must be deleted by the activation release**; inheriting either would accept
   transactions the genesis binary rejects.
5. **Every asset rule is gated on its deployment and only ever rejects.** Freeze is a rejection
   of spends of listed outpoints. Coinbase and dual-marker bans are rejections. Nothing keyed on
   a shape may exempt, skip, widen, or change how SOQ value is counted.
6. **SoquObscura uses the shielded-pool model.** Shielding pays visible SOQ into pool outputs,
   unshielding spends them back to visible SOQ, and only transfers inside the pool hide amounts
   and links. SOQ conservation holds publicly at every pool boundary. Per-output hidden amounts
   on the base layer cannot be a soft fork on any UTXO chain.
7. **UTXO_COST**, when scheduled, exempts zero-value asset outputs as it already exempts the
   authority markers. It is dormant in the genesis binary, so any version of it is a tightening.

## 5. Why the retired rules existed, and what bounds the hazard now

SOQ-I009 (2026-08-24) closed two hazards: fund-and-sweep of a dormant shape, and asset markers
buying consensus exemptions while the verifier was dormant. The second is closed at its source:
every exemption is gated on the deployment being active *and* the authority initialised, so the
shape alone buys nothing, and the activation release deletes the exemptions outright. The first
is bounded, not closed, exactly as it is on Bitcoin: dormant-version outputs are non-standard
(`policy.cpp`, mask from `AcceptToMemoryPoolWorker`), no wallet or RPC path constructs a
non-v1 address (`utiladdress.cpp`), and a stock miner builds blocks from its mempool. Reaching
the anyone-can-spend window takes raw construction plus a miner running modified policy, and
the only funds at risk are the constructor's own.

Tests: `witness_version_reservation_tests` (creation posture, the steal, relay refusal,
activation-tightens, the value premise on both paths, reorg over dormant shapes),
`v6_asset_opcode_ban_tests`, `authority_skip_gate_tests`, `usdsoq_v10_reject_path_tests`.
