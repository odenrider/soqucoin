# DL — Witness-version fork class and the additive asset-rule posture

Status: ratified 2026-09-07. Applies to the mainnet genesis binary and every later release.

## 1. The rule

A release is a soft fork iff every block it accepts, the genesis binary also accepts. A release
may therefore **add** a rejection, and may never accept anything the genesis binary rejects.
Two corollaries decide everything below:

1. A consensus rule in the genesis binary that **rejects** a shape is a promise every later
   release must keep. An **exemption, skip or widening** that is dormant in the genesis binary
   and switches ON at activation is a loosening, i.e. a hard fork; an exemption the genesis
   binary applies may be dropped later, since dropping it only tightens.
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
| Coinbase asset bans (`bad-cb-usdsoq-asset`, `bad-cb-btcsoq-asset`) and dual-marker ban | `CheckTransaction` | rejections every release keeps | **kept**, coinbase USDSOQ ban extended to v10 and to the v5 authority marker (2026-09-08), matching the v9 ban; §4.4 authority transactions are ordinary transactions that spend a marker, never coinbases, so this is a rejection every activation release keeps |
| `HasDilithiumSignatures` (`bad-txns-requires-dilithium`): the LAST witness item of every non-coinbase input must begin `0x00`, with a whole-tx exemption when an `OP_5` output plus an authority-shaped witness is present | `CheckTransaction` via `primitives/transaction.cpp` | the check is a rejection every release keeps; the exemption is applied by the genesis binary (dropping it later only tightens) | **kept**; constrains every future witness layout (§4.8) |
| PAT attested set: v7/v8 two-item spends joined the set only when their deployment was active | `consensus/pat_attestation.cpp`, `ConnectBlock` commitment check | commitment became a function of activation state → genesis and upgraded nodes reject each other's commitments = **hard fork** | set fixed at v0/v1/v7/v8 for every height |
| Mempool marker-spend mirrors (`bad-*-marker-spend`) | `AcceptToMemoryPoolWorker` | policy, not fork class, but DoS(100) on a consensus-valid spend of a dormant marker | gated on the deployment like their ConnectBlock twins |
| Per-asset `nValue` conservation and per-asset fee filter | `CheckTxInputs`, ConnectBlock | rejections/accounting every release keeps | kept; satisfied trivially forever under §4 |
| Ex-nihilo mint exemption from conservation; authority script skip | `CheckTxInputs`, `CheckInputs` | gated on deployment active and authority initialised; never fire on mainnet in the genesis binary | kept dormant; **the activation release must delete both** (§4) |

Net posture of the genesis binary on mainnet: witness v3–v16 are creatable, anyone-can-spend at
consensus and non-standard until their deployment activates. Every `nValue` is plaintext SOQ.
The asset holding shapes v7/v8/v10 can only be created with `nValue == 0` (the unconditional
per-asset conservation rule and the coinbase bans); every other shape carries whatever SOQ it is
paid. v2 (PAT) is permanently unconstructable because its spend path binds neither the witness
program nor the sighash.

## 3. Per-version fork class after the change

| ver | owner | activation class | note |
|---|---|---|---|
| v0/v1 | Dilithium | active | base forms |
| v2 | PAT | n/a | not an output type; permanently unfundable |
| v3 | LatticeFold (retired) | soft, if ever revived with a sound verifier | creatable, anyone-can-spend |
| v4 | SoquObscura pool (confidential SOQ) | **soft**, provided the activation release follows §4 (shielded-pool value model) | |
| v5 / v7 | USDSOQ authority / holding | **soft**, provided the activation release follows §4 | |
| v6 | P2WSH-Dilithium | **soft**, provided the activation release follows §3a | spend binds `SHA256(witnessScript)` to the program and the sighash inside the script. ⛔ The covenant opcodes are NOT interchangeable here: only CTV is arity-neutral with its flag clear (`interpreter.cpp:628`, validates and leaves its hash on the stack when set, NOP when clear) and may therefore activate after v6. CSFS (`:689`, pops 3 pushes 1 when set, NOP when clear), CDKH (`:786`, pops 3 when set, NOP7 when clear) and V6_CONTROLFLOW (`:857`, its opcodes are silently ignored when clear) each change the stack depth between states, so a script that fails the clean-stack check while they are dormant passes once they activate. A later activation of any of the three is a LOOSENING, by the same mechanism as APO in §3a, and they activate in the SAME flag-day as v6 |
| v8 / v9 | BTCSOQ holding / authority | **soft**, provided the activation release follows §4 | |
| v10 | confidential USDSOQ | **soft**, provided the activation release follows §4 | the USDSOQ-gated backstop `bad-txns-usdsoq-confidential-not-active` stays: it is a tightening |
| v11–v16 | unallocated | soft for any future version whose rules are additive | allocation-time review applies §1 |

### 3a. APO / eLTOO, and the activation-sequencing rule (bead mpu9, ruled 2026-09-08)

D1 found that `DEPLOYMENT_APO` gated SIGHASH_ANYPREVOUT at consensus on the v1/v7/v8 single-key
path, so activating it would relax a rejection = hard fork. Option (a) was ruled and is
implemented:

* **The single-key path (v0/v1, and the v7/v8 holding shapes) rejects APO hashtypes
  UNCONDITIONALLY** (`interpreter.cpp`, `IsAPOSigHashType` at the VerifyScript call site). v1 is
  active from genesis, so the genesis binary rejects those spends and every later release must
  keep rejecting them. `DEPLOYMENT_APO` can no longer open this path, so the trap cannot be
  sprung by scheduling a height.
* **APO reaches the chain only inside witness v6**, through `OP_CHECKDILITHIUMKEYHASH`, whose
  handler keeps the `SCRIPT_VERIFY_APO` gate. That is safe because OP_CDKH is NOP-when-clear:
  while its flag is clear the opcode succeeds without inspecting any signature, so the genesis
  binary rejects nothing there and activation only ADDS a requirement.
* eLTOO is unaffected. Its channel outputs are already v6 (`src/stagenet-eltoo.cpp` `MakeV6Spk`,
  `OP_6 <SHA256(witnessScript)>`) and its ANYPREVOUT signatures are verified inside the v6
  witnessScript.

⛔ **SEQUENCING IS PART OF THE FORK CLASS — this is a rule on the activation coordination, not
on the code.** `DEPLOYMENT_APO` MUST activate in the SAME flag-day as
`DEPLOYMENT_P2WSH_DILITHIUM` and `DEPLOYMENT_DILITHIUM_KEYHASH`. Measured against the genesis
binary a combined activation is a soft fork, because a dormant v6 output is anyone-can-spend and
the genesis binary accepts any v6 script. Activating APO LATER is a loosening measured against
the intermediate release: between the two heights a v6 script spending with an APO signature is
rejected, and after the second height it is accepted, which splits every node running the
v6-without-APO release. The whole covenant / eLTOO / atomic-swap stack (v6, CTV, CSFS, CDKH,
V6_CONTROLFLOW, APO) therefore activates as ONE flag-day, which is what D1 §4 assumed.

Pinned by `apo_hashtype_gate_tests`: the single-key path rejects APO *with the deployment
active*, with an ordinary-hashtype spend as the positive control.

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
   unshielding spends them back to visible SOQ, and only the notes inside the pool (commitments
   that are not UTXOs) hide amounts and links. Every UTXO's `nValue`, including every pool
   output's, stays plaintext, so no conservation rule changes. SOQ conservation holds publicly
   at every pool boundary. Per-output hidden amounts in `nValue` on the base layer cannot be a
   soft fork on any UTXO chain.
7. **UTXO_COST**, when scheduled, exempts zero-value asset outputs as it already exempts the
   authority markers. It is dormant in the genesis binary, so any version of it is a tightening.
8. **Witness layout constraint from `HasDilithiumSignatures`.** The genesis binary rejects any
   non-coinbase transaction whose input witness does not END with a `0x00`-prefixed item, unless
   the `OP_5`-marker exemption applies (which the activation release deletes with the script
   skip). Every future layout must satisfy it: the authority M-of-N witness on a v5/v9 marker
   input must end with a `0x00`-prefixed item (for example a `0x00`-prefixed authority set), and
   a pool-spend witness for SoquObscura must end with a `0x00`-prefixed item rather than a bare
   commitment.

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

Residual, tracked separately: the USDSOQ bootstrap in `ConnectBlock` selects its authority
input by SHAPE — any `OP_5 <32>` prevout, while the tracked outpoint is null — and does not
require the program to equal `ComputeAuthorityKeyHash`. BTCSOQ does not have this shape: its
bootstrap pins the authority input to index 0 and signs against the tx's own new v9 marker
output. Neither is exploitable without the authority keyset, since a bootstrap still verifies
M-of-N ML-DSA-44 against the configured keys, and the coinbase bans remove the free miner-only
path to planting a marker; an ordinary transaction can still create one by paying its own SOQ
into it. Pinning the USDSOQ fallback is a tightening, so it is safe to add in the release that
schedules USDSOQ, alongside the keyset.

Tests: `witness_version_reservation_tests` (creation posture, the steal, relay refusal,
activation-tightens, the value premise on both paths, reorg over dormant shapes, the coinbase
marker bans for v5 and v9), `v6_asset_opcode_ban_tests`, `authority_skip_gate_tests`,
`usdsoq_v10_reject_path_tests`.
