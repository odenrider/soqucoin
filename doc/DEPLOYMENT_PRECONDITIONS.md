# Per-deployment activation preconditions

**Status:** working document. Bead `x7hb` asked for exactly this and said why:

> the freeze needs to ship alongside a written per-deployment precondition list —
> what must be true before THIS deployment may be activated — rather than the
> current situation where that constraint is restated in five separate beads and
> depends on whoever is holding the pen remembering it.

**What this is.** One row per consensus deployment: its state in the genesis
binary, what it gates, and the conditions that must ALL be true before anyone
sets an activation height for it. It is the checklist a reviewer, an auditor or a
future maintainer reads instead of reconstructing the answer from beads.

**What this is not.** It is not a schedule. No deployment here has a date, and
the absence of one is deliberate.

---

## The rules that apply to every deployment

These come from bead `9iu` (the flag-day runbook) and from the fund-loss path
closed by commit `b4b8fddab`. They are preconditions in their own right: a
feature that satisfies its own row and violates one of these is **not** ready.

1. **Activation is by scheduled HEIGHT, not BIP9 signalling.** Soqucoin is
   merge-mined and AuxPoW occupies the version high bits, so there is no
   signalling constituency. Activation is `DeploymentActiveAtHeight` in
   `ConnectBlock`, mirrored in the mempool.

2. **Every consensus node must run a binary that knows the height BEFORE that
   block arrives.** That means all `soqucoind` instances — broadcast, services,
   relayers — and every merge-mining pool node. A node on an older binary does
   not enforce the new rule and forks off at the activation block. Set the height
   far enough ahead to guarantee 100% fleet coverage plus buffer.

3. **One feature at a time, and only after its audit scope clears.** Never
   batch-activate. `NOT_SCHEDULED` stays until the relevant Halborn Phase 2 scope
   signs off on that specific feature.

   ⛔ **ONE EXCEPTION, AND IT IS MANDATORY, NOT PERMISSIVE: the witness-v6
   covenant stack.** `DEPLOYMENT_P2WSH_DILITHIUM`, `DEPLOYMENT_DILITHIUM_KEYHASH`,
   `DEPLOYMENT_CSFS`, `DEPLOYMENT_V6_CONTROLFLOW` and `DEPLOYMENT_APO` MUST
   activate at the SAME height, in one flag-day. Splitting them is not a
   conservative choice here, it is a hard fork: each of those opcodes changes the
   stack depth between its clear and set states, so a v6 script that fails the
   clean-stack check while one of them is dormant PASSES once it activates. That
   is a loosening measured against the intermediate release, and it splits every
   node running it. Measured against the genesis binary the combined activation
   is a soft fork, because a dormant v6 output is anyone-can-spend.
   `DEPLOYMENT_CTV` is the one member of the stack that is
   genuinely arity-neutral and could follow later; it is included in the
   flag-day anyway so that the rule has no edge case to remember. Audit scope
   must therefore clear for the WHOLE stack before any of it is scheduled.
   Rationale and the per-opcode arity trace:
   `doc/specifications/WITNESS_VERSION_FORK_CLASS.md` §3a and the v6 row of §2.
   Pinned by `witness_version_allocation_tests::v6_covenant_stack_activates_together`.

4. **Relay policy must move in lockstep with consensus, never ahead of it.** A
   gated witness version is anyone-can-spend until its deployment activates. If
   relay policy also calls it standard, the pair is not a safe failure, it is a
   fund-loss path: the output relays, confirms, and then anybody may spend it.
   That shipped for v5–v9 and was closed by replacing the carve-out list with an
   activation mask that defaults to zero. **Precondition: the standardness mask
   for this version derives from the same deployment state `ConnectBlock`
   enforces.** Do not hand-add a version to a carve-out list.

5. **Post-activation verification is part of the activation, not follow-up.**
   After the height passes: confirm every node agrees on tip, and confirm the
   feature actually engages — for example that a newly created output of that
   type is no longer anyone-can-spend.

   ⛔ **The first test written for any new output or script type is: create one,
   fund it, mine it, and TRY TO STEAL IT.** Unit-testing a verifier proves what
   it computes, never what it *authorizes*. This is not a style preference — it
   is the control that failed. `DL-PAT-REMEDIATION.md` prescribed exactly this
   test for witness v2 and it was never written, which is the direct reason a
   fund-loss defect (bead `pat-v2-anyone-can-spend-ae6u`) survived a full L1
   audit: every PAT test asserted the proof arithmetic, and none asserted that a
   stranger could not spend the output. A verifier-only test suite is green in
   precisely the case that loses the money. The test belongs in
   `witness_version_reservation_tests.cpp`, must drive a real block through
   `ConnectBlock`, and must be shown to fail against the pre-fix rule.

6. **A rollback posture must be written down BEFORE the height is set.** A
   soft-fork cannot be cleanly un-activated without coordination.

7. **⛔ Adding a verifier where one did not exist is a RELAXATION.** Several rows
   below ship a dispatch that fails closed. Replacing that reject with real
   verification makes previously invalid spends valid, so it is only safe inside
   a coordinated flag-day upgrade — which is why the scaffolding must be present
   in the genesis binary (Gate 0 ruling, bead `r0vn`). Never satisfy a row by
   deleting the dispatch.

---

## Active from genesis

These are live on mainnet at block 0. Their preconditions are **launch**
preconditions, not activation preconditions.

### `DEPLOYMENT_CSV`, `DEPLOYMENT_SEGWIT` — `ALWAYS_ACTIVE`
Historical Bitcoin deployments. Nothing outstanding.

⚠️ **SegWit being active from genesis is load-bearing for everything else.** If
it were not, every witness-dispatched feature (USDSOQ v5/v7, SoquObscura v4/v10,
P2WSH-Dilithium, v6) would never execute even once height-activated. Confirm the
launch binary carries the `g7c` fix (`7117c22f9`).

### `DEPLOYMENT_CHECKPATAGG` (bit 3) — `ALWAYS_ACTIVE`
PAT, the Practical **Attestation** Technique: Dilithium batch attestation via
`OP_CHECKPATAGG`.

⛔ **This deployment no longer means "witness v2 outputs are allowed."** Ruled
2026-08-31: PAT's attestation is block metadata — a commitment in the coinbase,
validated in `ConnectBlock` — and not an output type. **Witness v2 is
permanently unfundable at consensus, unconditionally and not gated on this
deployment** (the v2 creation rule in `ConnectBlock`). Read the flag as "the
PAT commitment rules are in force", never as a witness-version gate.

The reason is recorded because it is counter-intuitive: the v2 spend path binds
neither the witness program nor the sighash, and PAT by design verifies no
signature — only the internal consistency of witness-supplied 32-byte tuples. So
any v2 output that ever confirmed would be spendable by anybody. That is not a
binding bug to fix: PAT stores 32-byte commitments, and a commitment cannot
verify a signature, which is information-theoretic. Unfundability is therefore
the control, and it must not be re-openable by flipping a deployment. Pinned by
`pat_v2_unfundable_tests.cpp` and `witness_version_reservation_tests.cpp`.

**This is the only Soqucoin-specific consensus cryptography live at launch, so it
carries the launch risk the others defer.**

- ✅ Covered by Halborn Phase 1 (the L1/PQ engagement, 30 findings, all
  remediated). Scope included the PAT batch-verification primitive.
- ✅ Its verdicts are now inside the consensus digest, with valid proofs at
  n=1..4 executed through the opcode and a tampered proof required to reject
  (bead `71z6`). Before 2026-08-27 the digest reached no PAT cryptography at all.
- ☐ **Cross-build evidence.** Run `contrib/f4-digest-sweep.sh` and record that
  every optimisation level produces one digest. This is the F4 check, and it was
  not meaningful for the script path until the coverage fix landed.
- ☐ **Naming fix owed before the audit.** `consensus.h:36` mislabels PAT as
  *Aggregation* where the technique is *Attestation* (bead `uv58`). ⚠️ PAT
  verifies no signatures **by design** — two separate false P1 escalations have
  been filed against it by readers who did not check the design intent first.
  Read the patent and the headers before reporting anything here as a defect.

---

## Withdrawn — not to be activated

### `DEPLOYMENT_LATTICEFOLD` (bit 28) — `nStartTime=0 / nTimeout=0`
Terminal `THRESHOLD_FAILED`. `OP_CHECKFOLDPROOF` and witness v3.

Withdrawn from launch consensus because the verifier reads its statement fields
from the untrusted proof blob and every algebraic check is homogeneous in the
witness, so an all-zero witness carrying a recomputed Fiat-Shamir seed verifies.
A proof with no valid Dilithium signature therefore passes.

**Preconditions to ever reactivate — all three, not any:**
1. A real prover exists. There has never been one.
2. The statement is anchored to a commitment fixed **outside** the proof.
3. Re-audit. Halborn finding 7.3 was remediated and signed off SOLVED, and the
   zero-witness class **survived that remediation** (bead `quwp`) because the fix
   was scoped to external binding. A sign-off on one class is not a sign-off on
   the defect.

⛔ While inactive, witness v3 must stay relay-nonstandard via the BIP141 s4
future-witness rejection. Do **not** add `OP_3` to the v5–v9 carve-outs.

Guard: `latticefold_tests.cpp::mainnet_latticefold_deployment_never_active`.

---

## Dormant with machinery — activation candidates

All of these are `nStartTime=0 / nTimeout=0` and `nActivationHeight =
NOT_SCHEDULED` on **all four networks**.

### `DEPLOYMENT_SOQUOBSCURA` (bit 5)
Confidential transactions. Gates witness v4 (confidential SOQ) and, compounded
with `DEPLOYMENT_USDSOQ`, witness v10 (confidential USDSOQ).

Both dispatches currently **fail closed** when active, because no confidential
verifier ships. v10 has done so since FC4; v4 joined it in
`consensus: stop routing the v4 range proof to an unsound verifier`.

**Preconditions:**
1. ☐ **A verifier that binds the amount.** The in-tree `LatticeRangeProofV2` does
   not: Check 4 compares a prover-supplied value against a homogeneous relation,
   so `(0,0,0)` with an honest seed passes. Seeding the generators from
   `consensus.latticeBPSeed` is **necessary but not sufficient** (bead `uv34`,
   SOQ-I011). The replacement is the extracted LaZer subset.
2. ☐ **All 18 degenerate-witness vectors reject.** Three mutation classes across
   six honest bases; two of the three are **non-zero**, so a reject-if-all-zeros
   patch cannot satisfy them. ⛔ The deliberate failures in
   `soquobscura_degenerate_witness_tests.cpp` must never be patched at the symptom.
3. ☐ **Halborn Phase 2 clearance** for the confidential layer. Per bead `uv58` the
   audit cannot start until the layer is code-complete and wired: "Halborn gets
   the FINISHED layer."
4. ☐ **If the flag-2 pack aggregate is in scope: the portable LaBRADOR port**
   (bead `bx46`). `validation.cpp:4987` puts `VerifyBlockAggregate` on the
   `ConnectBlock` path and the archive requires AVX-512 by ratified decision D1.
   6 of 8 fleet nodes have none, and a node without it rejects the block — no DoS
   score, correctly, but it still stalls. **A hardware feature must not become a
   de facto consensus requirement.**
5. ☐ **Amount privacy must be true before it is claimed.** A v4/v10 output still
   carries its amount in cleartext `nValue` (bead `sh2u`). Public copy has been
   corrected to say "research direction, not yet available"; do not re-claim
   amount privacy on activation unless this is actually fixed.

Guard: `witness_version_allocation_tests::soquobscura_must_stay_dormant_on_every_network`.

### `DEPLOYMENT_USDSOQ` (bit 6)
Stablecoin authority opcodes, witness v5 (authority) and v7 (holdings).

**Preconditions:**
1. ☐ Halborn Phase 2 clearance for the USDSOQ layer.
2. ☐ Per-asset value conservation enforced in `ConnectBlock` **and** mirrored in
   the mempool. Policy-equals-consensus on both the input and output side; the
   output side was the `b4b8fddab` fix.
3. ☐ The authority registry and rotation path reviewed as part of that scope.
4. ⛔ Activating USDSOQ alone does **not** enable confidential USDSOQ. Witness v10
   is compound-gated on USDSOQ **and** SOQUOBSCURA, and fails closed when both are
   active. Activating both without satisfying the SoquObscura row above turns a
   fail-closed reject into a live confidential path with no verifier.
5. ☑ **Not an attestation change** (amended 2026-09-07). The PAT attested set
   is fixed at v0/v1/v7/v8 for every height (`doc/PAT_BLOCK_ATTESTATION.md` §2,
   Decision 1 as amended), so this activation does not change any node's
   recomputed block attestation. The earlier "joins at this height" rule was
   removed with the additive-asset genesis door because an activation-dependent
   attested set is a hard fork.

### `DEPLOYMENT_BTCSOQ` (bit 14)
Bitcoin-backed consensus asset, witness v8 (holding) and v9 (authority).

**Preconditions:**
1. ☐ The v8/v9 history sweep gate (bead `uen6.2`) run against the target network.
2. ☐ Reorg and release hardening cluster closed (bead `1g6`) — notably that
   `attemptRelease` re-verifies the deposit before paying.
3. ☐ Bridge-side validator signatures actually verified. `mint_from_deposit`
   currently counts set membership and never checks the signature bytes, and the
   field is 64-byte Ed25519-shaped, which cannot carry ML-DSA-44 (bead `23q1`).
   ⛔ This violates the standing rule: ML-DSA-44 only in the bridge signing path.
4. ☐ Halborn Phase 2 clearance for the BTCSOQ layer.
5. ☑ **Not an attestation change** (amended 2026-09-07). Same as the USDSOQ
   row: the attested set is fixed at v0/v1/v7/v8, so v8 is attested at every
   height and this activation leaves every node's recomputed attestation
   unchanged.

### `DEPLOYMENT_CTV` (bit 7), `DEPLOYMENT_APO` (bit 8), `DEPLOYMENT_CSFS` (bit 9)
BIP 119 `OP_CHECKTEMPLATEVERIFY`, BIP 118 `SIGHASH_ANYPREVOUT`, BIP 348
`OP_CHECKSIGFROMSTACK`. Covenants, eltoo Lightning, oracle and bridge attestation.

**Preconditions:**
1. ☐ Halborn Phase 2 covenant scope cleared. Groundwork exists in
   `DL-COVENANT-ADVERSARIAL-AUDIT.md` and `DL-COVENANT-POST-AUDIT-HARDENING.md`.
2. ☐ APO specifically: the hashtype gate must be pinned
   (`apo_hashtype_gate_tests.cpp`), since ANYPREVOUT changes what a signature
   commits to.
3. ☐ These three are commonly activated together for eLTOO. Under the v6
   covenant-stack exception to rule 3 they are not three separate scheduling
   decisions: CSFS and APO activate in the same flag-day as
   `DEPLOYMENT_P2WSH_DILITHIUM`, `DEPLOYMENT_DILITHIUM_KEYHASH` and
   `DEPLOYMENT_V6_CONTROLFLOW`, because a later activation of any of them is a
   loosening. They remain three separate AUDIT decisions, and the flag-day
   cannot be scheduled until all of them clear.

### `DEPLOYMENT_P2WSH_DILITHIUM` (bit 10)
Witness v6: P2WSH with Dilithium. Covenant script execution and L2SOQ Lightning.

**Preconditions:**
1. ☐ **An audit that is not currently scheduled.** This is called out explicitly
   in `b4b8fddab` as an additional block beyond the deployment being inactive.
2. ☐ ⛔ The witness-version allocation must be re-derived from `interpreter.cpp`
   before any adjacent version is allocated. A v6 collision with P2WSH-Dilithium
   was green in CI once already and forced a reallocation to v10. Never derive
   the free list from a document.
3. ☐ **The audit scope must include every opcode reachable from `EvalScript`,
   not only the covenant set.** A v6 witnessScript executes with the live flag
   set, and `SCRIPT_VERIFY_PAT` is always on, so a witnessScript consisting of
   `OP_CHECKPATAGG` verifies attacker-supplied self-consistent tuples and
   succeeds: an anyone-can-spend contract. The funder chooses the script, so
   this is self-inflicted in the same class as funding `OP_TRUE`, and it steals
   from nobody. It is recorded here because the v6 activation review must
   treat "which opcodes can a witnessScript reach, and what does each one
   actually bind" as in scope; the PAT anyone-can-spend defect (bead
   `pat-v2-anyone-can-spend-ae6u`) came from precisely this question going
   unasked at a different dispatch site. Note that v6 witness data is also
   outside the PAT block attestation (`doc/PAT_BLOCK_ATTESTATION.md` §2), so
   these scripts stay unpruned regardless.

### `DEPLOYMENT_V6_CONTROLFLOW` (bit 13)
`IF`/`CLTV`/`CSV`/`DROP`/`SHA256`/`EQUAL` inside v6 `EvalScript`, for the eLTOO
ratchet and HTLCs.

**Preconditions:**
1. ☐ Cannot precede `DEPLOYMENT_P2WSH_DILITHIUM`: it extends v6 script execution,
   so activating it first has no meaning.
2. ☐ Halborn Phase 2 clearance for the restored control-flow surface.

### `DEPLOYMENT_DILITHIUM_KEYHASH` (bit 12)
`OP_CHECKDILITHIUMKEYHASH`: key-committed Dilithium verification, eLTOO 2-of-2.

**Preconditions:**
1. ☐ Halborn Phase 2 clearance.
2. ☐ Committed-keyhash tests green (`dilithium_keyhash_committed_tests.cpp`).

### `DEPLOYMENT_UTXO_COST` (bit 11)
SOQ-ARCH-003, consensus-enforced minimum UTXO value.

**Preconditions:**
1. ☐ Confirm it remains a **tightening**. A tightening can be added later as a
   soft fork, which is why bead `x7hb` places it outside the freeze scope.
2. ☐ The 0-value v4 dust and utxo-cost exemption (seam-audit F8/R1) must be
   settled first, or activating this rejects outputs the confidential design
   depends on.

---

## Maintaining this document

- A new deployment is not complete until it has a row here.
- A precondition is discharged by **evidence**, not by assertion. Link the commit,
  the test, or the audit finding.
- When a row's conditions are all met, that is the input to the activation
  decision. It is not the decision.
