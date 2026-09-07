# PAT block attestation — consensus specification

**Status:** SPECIFICATION, ratified. Phase 3 of the PAT completion epic
(`pat-completion-epic-xlab`). Both open decisions were ruled on 2026-09-01;
§10 records the rulings. Implementation may begin against this document.

**Purpose.** This document defines the rules a node follows to compute, commit,
and verify the per-block PAT attestation. The attestation is recomputed
independently by every node and compared byte-for-byte against the miner's
commitment, so any ambiguity in this definition is a consensus-divergence risk.
The standard this document is written to: an independent implementer must be
able to produce identical bytes from this document alone.

---

## 1. Definition

One PAT proof per block, computed over the Dilithium signatures carried by that
block's attested spends (§2). The proof is committed in the coinbase and
validated in `ConnectBlock`. The attestation is block metadata. It is not an
output type: witness v2 is permanently unfundable (the v2 creation rule in
`ConnectBlock`), so no value can be paid into the attestation machinery.

The attestation enables witness pruning: nodes may discard attested raw witness
data past the finality horizon while retaining the attestation (phase 5 of the
epic). The attestation does not assert that the attested signatures are valid.
Signature validity is established by per-input script verification. The
attestation attests to what the block contained; it does not authorize
anything.

---

## 2. The attested set — DECISION 1

This is the most divergence-prone definition in the document, for two reasons:
several witness versions reach the same Dilithium verification code by
different routes, and the set of active versions changes as deployments
activate. The rule must therefore be defined explicitly for every witness
version, including the versions that can never contribute. An implementation
that derives the set from "whatever the code collects" will agree with the
specification today and diverge from it at a future activation height.

### Disposition of all seventeen witness versions

| Version | Carries a Dilithium signature per input? | Attested? | Basis |
|---|---|---|---|
| v0, v1 | Yes. Witness is exactly `[sig, pubkey]`; verified by the single-key path (`interpreter.cpp:1906`) | **Yes** | Active from genesis; the base spend forms |
| v2 (PAT) | No spend can exist. Permanently unfundable (PR #63) | No | Nothing to attest; no v2 output can ever be created |
| v3 (LatticeFold) | No spend can exist. Retired; never activates on any network; unfundable under the reservation rule | No | Same basis as v2 |
| v4 (confidential SOQ) | No. Witness carries `[range_proof, pubkey_hash, commitment]`; there is no per-input Dilithium signature over a sighash | No | Wrong payload shape; also unfundable while `SOQUOBSCURA` is dormant, and fails closed if activated (no verifier ships) |
| v5 (USDSOQ authority marker) | Not per-input. Authority transactions carry M-of-N ML-DSA signatures verified whole-transaction in `ConnectBlock`; they skip `VerifyScript` entirely | No — see the authority-signature note below | Not a per-input tuple; a different verification model |
| v6 (P2WSH-Dilithium) | Sometimes. A witnessScript may perform zero, one, or many signature checks (`OP_CHECKSIGFROMSTACK`, `OP_CHECKDILITHIUMSIG` variants) at positions the block structure does not expose | No — see the v6 note below | No 1:1 spend-to-tuple mapping exists without re-executing scripts |
| v7 (USDSOQ holding) | Yes, once `USDSOQ` activates. Falls through to the same single-key path as v1; witness is exactly `[sig, pubkey]` | **Yes, always** (Decision 1 as amended 2026-09-07) | Identical verification to v1; a dormant two-item spend is attested as bytes |
| v8 (BTCSOQ holding) | Yes, once `BTCSOQ` activates. Same fall-through | **Yes, always** (Decision 1 as amended 2026-09-07) | Same basis as v7 |
| v9 (BTCSOQ authority marker) | Not per-input. Same whole-transaction M-of-N model as v5 | No — see the authority-signature note below | Same basis as v5 |
| v10 (confidential USDSOQ) | No. Same payload shape as v4; compound gate; fails closed if activated | No | Same basis as v4 |
| v11–v16 | Unallocated; creatable and anyone-can-spend while unallocated (additive-asset genesis door) | No | No defined tuple |

### The rule, as ruled (Decision 1, 2026-09-01)

A spend is attested if and only if it is a witness spend whose witness stack is
exactly two items and whose verification is the single-key Dilithium path:
v0, v1, v7 and v8, **at every height and independent of deployment state**.

Amended 2026-09-07 (additive-asset genesis door). Decision 1 originally had v7
join at the `USDSOQ` activation height and v8 at the `BTCSOQ` height. That made
the block commitment a function of activation state: from the activation height
on, a genesis-binary node and an upgraded node recompute different attestations
over the same block and reject each other's commitments in both directions — a
hard fork by construction, which the additive-asset design forbids. A fixed set
cannot do that. A dormant v7/v8 spend is an anyone-can-spend two-item spend; its
tuple is attested as bytes, exactly like every other tuple, and commits to
nothing about validity.

### The authority-signature note (v5, v9)

Authority transactions do carry real Dilithium signatures (M-of-N ML-DSA,
verified whole-transaction in `ConnectBlock`). Excluding them means those
signatures are not attested and their witness data is not prunable in phase 5.
This exclusion is a deliberate scope decision, recorded with its costs:

- Authority events (mint, burn, freeze, rotate) are administrative and rare, so
  the storage cost of retaining their witnesses is negligible.
- Their verification model is whole-transaction over a custom digest, so they do
  not fit the per-input `(sig, pk, sighash)` tuple shape without a second,
  parallel tuple definition. A second tuple shape doubles the divergence
  surface of §3 for negligible benefit.

If the design contract "every Dilithium signature in a block is committed" is
read to include authority signatures, it overstates what is attested. The
accurate statement of the ruled scope is: every single-key Dilithium spend
signature is committed; authority M-of-N signatures and v6 witnessScript checks
are not. The public documentation must state the contract in that form
(tracked under `pat-public-claims-correction-pq03`).

### The v6 note

v6 (P2WSH-Dilithium, dormant, pending audit) executes an arbitrary
witnessScript. Signature checks inside it are data-dependent: their number and
their inputs are known only by executing the script. Including v6 would require
the attestation to re-execute scripts during commitment computation, which is a
substantially larger consensus surface and the place where an ordering
ambiguity would be hardest to detect. v6 witness data is therefore not
attested and not prunable. If v6 volume becomes material (L2SOQ channel
transactions are the expected source), extending the attestation to v6 is
future work with its own specification, not an amendment to this one.

---

## 3. The tuple — DECISION 2

PAT batches triples of 32-byte commitments; `VerifyLogarithmicProof`
structurally requires 32-byte fields. A Dilithium signature is 2,420 bytes and
a public key 1,312, so each field enters the batch by hash.

For each attested spend, in the order fixed by §4:

| Field | Value |
|---|---|
| `sig` | `SHA3-256(witness.stack[0])`: the signature exactly as it appears in the witness |
| `pk`  | `SHA3-256(canonical public key)`: see below |
| `msg` | the sighash already computed for that input's verification |

`SHA3-256` is PAT's own hash (`PatHash` in `logarithmic.cpp`), used here for
consistency with the proof's internal hashing.

### The public-key encoding duality

Consensus accepts two encodings of the same key: the bare 1,312-byte form and a
`0x00`-prefixed 1,313-byte form (FIPS 204 Table 3). `VerifyScript` strips the
prefix before hashing to compare against the witness program
(`interpreter.cpp:1921`). Tracked as bead
`dilithium-pubkey-encoding-duality-flpa`.

**Ruled (Decision 2, 2026-09-01):** `pk` commits to the stripped canonical
form, the same bytes that are SHA-256'd to produce the witness program.

The precise consequence of each option, stated carefully because the difference
is easy to overstate:

- Neither option is a consensus-divergence risk. The attestation is computed
  from block bytes, and all nodes see identical block bytes, so both options
  are deterministic per block.
- Committing raw witness bytes means the same logical spend attests differently
  depending on which encoding the relaying path delivered, and witness
  malleability allows a third party to choose that encoding for an unconfirmed
  transaction. The attestation remains internally consistent, but downstream
  consumers (auditors recomputing attestations from canonical key material,
  future L2SOQ references into attestation entries) cannot reproduce it without
  knowing which encoding was mined.
- Committing the stripped form makes the attestation independent of the
  duality at the cost of one normalisation step, which mirrors what
  `VerifyScript` already does. If bead `flpa` is later resolved by rejecting
  one encoding outright, the stripped-form rule remains correct with no
  amendment.

### The sighash

`msg` is the sighash for that input, byte-identical to the value `CheckSig`
verified against. Stated in implementable terms: `SignatureHash(scriptCode,
tx, nIn, nHashType, amount, SIGVERSION_WITNESS_V0, txdata)`, where `scriptCode`
is the prevout `scriptPubKey`, `nHashType` is the trailing byte of the witness
signature (exactly as `TransactionSignatureChecker::CheckSig` extracts it), and
`amount` is the prevout value.

The collector MUST obtain this value through the same `SignatureHash` function
and the same argument derivation that `CheckSig` uses, either by capturing the
value at verification time or by invoking the identical code path with
identical arguments. What is prohibited is an independent reimplementation of
the derivation: two implementations of the same value is the drift hazard that
`CreateLogarithmicProof` and `VerifyLogarithmicProof` carried until PR #65.

A witness signature can be empty in a malformed block. The collector uses
`nHashType = 0` for an empty signature so the computation stays total; such a
block fails script verification regardless, so the value never reaches a
connected chain, but a collector that could fail differently on different
nodes would itself be a divergence surface.

APO sighash types (`DEPLOYMENT_APO`, dormant) change what a sighash covers.
Because `msg` is defined as whatever the input actually verified against, the
attestation inherits an APO activation automatically; the APO activation review
must confirm this (§8, item 5).

---

## 4. Canonical order

Implemented and merged (PR #65). Entries are sorted by the total key
`(PatHash(msg), PatHash(pk), PatHash(sig))` with the entry's original position
as a final tie-break, via `CanonicalOrder` in `crypto/pat/logarithmic.cpp`.
Both `CreateLogarithmicProof` and `VerifyLogarithmicProof` derive the order
from that one function.

"Original position" for the attestation is defined as transaction index within
the block, then input index within the transaction, ascending, coinbase first.
This is stated explicitly because it feeds a tie-break: an implementation that
collected tuples in a different order would agree on every batch except one
containing fully identical tuples, which is the least-testable place to
disagree.

Pinned by `pat_canonical_ordering_tests.cpp`, including known-answer vectors. A
vector mismatch on a new platform is the divergence, caught in a test.

---

## 5. Empty and oversized batches

- `CreateLogarithmicProof` returns false for `n = 0` (`logarithmic.cpp:184`).
  A block with no attested spends has no attestation. Specified: such a block
  MUST NOT carry a PAT commitment, and a commitment present on such a block is
  invalid. A coinbase-only block is the common case, so this rule is exercised
  by every empty block on the chain.
- `n > 2^20` is rejected by the same guard. No block can approach this bound
  under current size limits; the rule is stated so that the failure mode is a
  defined rejection rather than silent absence.

---

## 6. Commitment placement and encoding

An `OP_RETURN` output in the coinbase, following the established in-tree shape
(the SegWit witness commitment, and the LatticeFold accumulator at
`block_accumulator.h:90`):

```
OP_RETURN OP_PUSHBYTES_34 0x50 0x41 <32-byte attestation hash>
```

36 bytes total; magic `PA` (`0x50 0x41`). This does not collide with
LatticeFold's `LF` (`0x4C 0x46`), and the 36-byte length is distinct from
SegWit's 38-byte `aa21a9ed` form.

**The 32-byte attestation hash is defined as:**

```
attestation_hash = SHA3-256(0x02 || proof)
```

where `proof` is the complete 100-byte PAT proof (`merkle_root || pk_agg ||
msg_root || count`) produced by `CreateLogarithmicProof` over the block's
canonical batch. The `0x02` prefix is a domain separator, continuing the scheme
already used inside the proof (`0x00` for leaf hashes, `0x01` for internal
nodes, `logarithmic.cpp`), so an attestation hash can never be confused with a
tree node. Committing the hash of the whole proof rather than `merkle_root`
alone binds `pk_agg`, `msg_root`, and `count` in the commitment as well.

**Exactly one.** A block carrying more than one output that parses as a PAT
commitment is invalid. This differs deliberately from the LatticeFold
validator, which accepts the first matching output and stops
(`validation.cpp:5401`); that behaviour depends on coinbase output order and
permits a decoy ahead of the intended commitment. The same observation applies
to LatticeFold itself and is recorded for a separate review; LatticeFold is
withdrawn, so it is not urgent.

A 2-byte magic is a weak tag: any 36-byte `OP_RETURN` beginning with the same
four bytes parses as a commitment. The coinbase is miner-controlled, so a
malformed or decoy commitment causes the miner's own block to fail validation
and confers no advantage on anyone else. This reasoning step is recorded so it
does not have to be rediscovered.

---

## 7. Validation and activation

Ratified fail-safe shape: optional-but-verified at genesis, mandatory at a
scheduled height.

At genesis:

1. A miner MAY emit the commitment.
2. A node that observes one MUST verify it: recompute the attestation over the
   block per §2–§5 and compare. A mismatch rejects the block.
3. A block without a commitment is valid.

From the scheduled height, a block with attested spends and no commitment is
invalid.

Rationale: a mandatory-from-genesis rule converts any commitment-computation
bug into a chain halt. Optional-but-verified provides full PAT function from
block 1 without that risk, using `DeploymentActiveAtHeight` exactly as
`doc/DEPLOYMENT_PRECONDITIONS.md` rule 1 prescribes.

Note that this differs from LatticeFold's shape, which is mandatory whenever
the block has confidential outputs (`bad-blk-missing-latticefold-commitment`,
`validation.cpp:5416`). That is the chain-halt posture the ratified plan
rejected; it must not be copied here.

Reject reasons, named so tests can pin them by string:

| Condition | Reject reason |
|---|---|
| Commitment present, recomputation differs | `bad-blk-pat-commitment` |
| More than one PAT commitment in the coinbase | `bad-blk-pat-commitment-duplicate` |
| Commitment present on a block with no attested spends | `bad-blk-pat-commitment-empty` |
| Attested spends present, no commitment, past the mandatory height | `bad-blk-missing-pat-commitment` |

---

## 8. Determinism hazards

The complete risk surface, collected for review as a single list:

1. **Tie-breaking in the canonical ordering.** Closed by PR #65 and pinned by
   known-answer vectors. This was a measured defect, not a hypothetical.
2. **The attested set changing under deployment activation** (§2). Removed
   (Decision 1 as amended 2026-09-07): the set is fixed at v0/v1/v7/v8 for
   every height, so no activation changes the commitment and there is no
   attestation-change review item. The earlier "managed" posture was itself
   the hard-fork class the additive-asset genesis door exists to remove.
3. **Public-key encoding duality** (§3). Ruled (Decision 2): `pk` commits to
   the canonical stripped form, so both accepted encodings of a key attest
   identically. Coupled to bead `flpa`: if the duality is later closed by
   rejecting one encoding, the rule stands unamended, but the coupling note in
   §3 must be revisited.
4. **Sighash provenance.** `msg` must come from the verification that happened,
   never from a second derivation.
5. **APO sighash types.** Dormant. Activation changes what a sighash covers;
   the attestation inherits the change automatically, and the APO activation
   review must confirm it.
6. **Collection order feeding the positional tie-break** (§4).
7. **Digest blindness to ordering.** The consensus digest currently absorbs PAT
   proof bytes only for distinct-message batches, so it cannot detect an
   ordering regression. See §9.

---

## 9. Digest and cross-build evidence

The attestation is consensus cryptography and must be inside the consensus
digest, swept across optimisation levels and platforms by
`contrib/f4-digest-sweep.sh`.

Two items enter the same deliberate re-pin, and they are distinct:

1. The block attestation computation itself.
2. A duplicate-message PAT batch added to `AbsorbOpcodeVerdicts`. The digest
   already absorbs PAT proof bytes, but only for batches built by
   `BuildValidPatScript`, whose messages are all distinct (`0x70+i`). Its
   material never reaches the ordering's tie path, which is why the digest did
   not move when the canonical ordering was corrected in PR #65. Without this
   addition the F4 sweep does not cover canonical ordering. Bead
   `pat-canonical-ordering-not-total-97dz` remains open until it lands.

One re-pin, one sweep. The working rule this epic has now confirmed three
times: when adding a check or a tripwire, identify the input that would make it
fail. A check with no such input is documentation presenting itself as
coverage.

---

## 10. Decisions — RULED 2026-09-01

1. **The attested set (§2): the set is fixed.** Attestation covers every
   two-item single-key Dilithium spend of v0/v1/v7/v8 at every height
   (amended 2026-09-07: v7/v8 originally joined at their activation heights,
   which made the commitment activation-dependent, i.e. a hard fork). Basis
   for the original ruling, still the basis for including v7/v8 at all: the
   extension honours the "every single-key Dilithium signature is committed"
   contract and keeps v7/v8 witnesses prunable, and the added process cost is
   one review item on an activation checklist that `DEPLOYMENT_PRECONDITIONS.md`
   rule 2 already imposes. Authority signatures (v5/v9) and v6 witnessScript
   checks remain out of scope, per §2, with their costs recorded there.
2. **The public-key commitment (§3): the canonical stripped form.** Basis for
   the ruling: both encodings of a key attest identically, third parties cannot
   choose which encoding of an unconfirmed transaction's key is attested, and
   the rule needs no amendment if bead `flpa` later rejects one encoding.

The magic bytes (§6) are specified as `PA`; there was no tradeoff to rule on,
only a collision to avoid.

---

Related: `DL-PAT-COMPLETION-PLAN-2026-08-31.md` (soqucoin-ops),
`doc/DEPLOYMENT_PRECONDITIONS.md`, `crypto/pat/logarithmic.h`, beads
`pat-completion-epic-xlab`, `pat-canonical-ordering-not-total-97dz`,
`dilithium-pubkey-encoding-duality-flpa`, `pat-public-claims-correction-pq03`.
