// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// PAT block attestation (SOQ-P001, phase 3 of the PAT completion epic).
//
// Specification: doc/PAT_BLOCK_ATTESTATION.md. Every rule this module
// implements is defined there; this header cites sections rather than
// restating them. The attestation is recomputed independently by every node
// and compared byte-for-byte against the miner's coinbase commitment, so
// every function here must be a total, deterministic function of its inputs.
//
// This module is deliberately free of chain state. Callers (the miner's
// commitment producer and ConnectBlock's validator) supply the prevout lookup
// and the activation facts; the module never consults globals. That keeps the
// computation testable in isolation and keeps both callers on one code path,
// which is the property that prevents producer/validator drift.

#ifndef BITCOIN_CONSENSUS_PAT_ATTESTATION_H
#define BITCOIN_CONSENSUS_PAT_ATTESTATION_H

#include "primitives/block.h"
#include "script/script.h"
#include "uint256.h"

#include <functional>
#include <vector>

namespace patattest {

//! Parameters of the attested-set rule. Since the additive-asset genesis door
//! (2026-09) the set is FIXED — v0/v1/v7/v8 two-item spends, independent of
//! any deployment — because a set that changes at an activation height makes
//! the block commitment disagree between a genesis node and an upgraded one
//! (a hard fork). The two flags are retained so the collector's interface and
//! the spec's disposition-table tests keep their shape; IsAttestedVersion no
//! longer consults them.
struct AttestedSetParams {
    bool fUsdsoqActive = false;   // no longer consulted
    bool fBtcsoqActive = false;   // no longer consulted
};

//! Witness version of the one canonical Soqucoin shape, OP_N <32 bytes>
//! (34-byte scriptPubKey). Returns 0-16, or -1 for anything else. Matches the
//! shape predicate used by ConnectBlock's reservation rule and VerifyScript's
//! dispatch; those three must never diverge.
int WitnessVersionOf(const CScript& scriptPubKey);

//! The attested-set rule of spec §2: v0/v1/v7/v8 always (the two-item
//! single-key shapes). Every other version is never attested, each for the
//! reason recorded in the spec's disposition table.
bool IsAttestedVersion(int version, const AttestedSetParams& params);

//! One block's batch, as the three parallel vectors CreateLogarithmicProof
//! takes. Entries are the 32-byte commitments of spec §3, in block order
//! (transaction index, then input index — the "original position" that feeds
//! the canonical ordering's final tie-break, spec §4).
struct PatBatch {
    std::vector<std::vector<unsigned char>> sigs;
    std::vector<std::vector<unsigned char>> pks;
    std::vector<std::vector<unsigned char>> msgs;

    bool empty() const { return sigs.empty(); }
    size_t size() const { return sigs.size(); }
};

//! Append one transaction's attested tuples to a batch, in input order
//! (spec §2-§4). This is the collection primitive: ConnectBlock calls it per
//! transaction inside its main loop, where the UTXO view still holds that
//! transaction's prevouts, and CollectBatch below composes it over a whole
//! block. Both consumers therefore run the identical tuple construction.
//!
//! `prevoutLookup` must return the output being spent and return false when
//! it cannot; an input whose prevout cannot be resolved contributes nothing,
//! which is safe because such a block is invalid long before the attestation
//! is compared. A coinbase transaction contributes nothing by definition.
//!
//! Total over transaction bytes: never fails. A witness signature can be
//! empty in a malformed block; the collector uses nHashType = 0 for it so the
//! computation stays total (the block is rejected by script verification
//! regardless).
void AppendTuples(PatBatch& batch, const CTransaction& tx,
                  const std::function<bool(const COutPoint&, CTxOut&)>& prevoutLookup,
                  const AttestedSetParams& params);

//! Collect the attested tuples of a whole block: AppendTuples over every
//! non-coinbase transaction, in block order. Used by the commitment producer
//! and by tests; ConnectBlock collects incrementally with AppendTuples
//! instead, because its view resolves each transaction's prevouts only while
//! that transaction is being connected.
PatBatch CollectBatch(const CBlock& block,
                      const std::function<bool(const COutPoint&, CTxOut&)>& prevoutLookup,
                      const AttestedSetParams& params);

//! attestation_hash = SHA3-256(0x02 || proof), spec §6. The 0x02 prefix
//! continues the domain-separation scheme inside the proof (0x00 leaves,
//! 0x01 internal nodes), so an attestation hash can never collide with a
//! tree node.
uint256 AttestationHash(const std::vector<unsigned char>& proof);

//! Compute the block attestation over a collected batch. Returns false for an
//! empty batch: a block with no attested spends has no attestation, and MUST
//! NOT carry a commitment (spec §5).
bool ComputeBlockAttestation(const PatBatch& batch, uint256& hashOut);

//! The 36-byte coinbase commitment script of spec §6:
//! OP_RETURN OP_PUSHBYTES_34 0x50 0x41 <32-byte attestation hash>.
CScript BuildCommitmentScript(const uint256& attestationHash);

//! Parse one output script against the spec §6 shape. Strict: exactly 36
//! bytes, exact opcodes, exact magic.
bool ParseCommitmentScript(const CScript& script, uint256& hashOut);

//! Scan a coinbase transaction for PAT commitments. Returns how many outputs
//! parse as one and sets hashOut to the first. The exactly-one rule
//! (bad-blk-pat-commitment-duplicate, spec §6) is enforced by the caller from
//! the returned count; this deliberately does not stop at the first match,
//! which is the LatticeFold validator behaviour the spec rejects.
int FindCommitments(const CTransaction& coinbase, uint256& hashOut);

} // namespace patattest

#endif // BITCOIN_CONSENSUS_PAT_ATTESTATION_H
