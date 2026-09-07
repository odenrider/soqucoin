// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// PAT block attestation. Specification: doc/PAT_BLOCK_ATTESTATION.md.

#include "consensus/pat_attestation.h"

#include "crypto/pat/logarithmic.h"
#include "crypto/sha3.h"
#include "script/interpreter.h"

namespace patattest {

namespace {

//! SHA3-256 of a byte range. The same hash the PAT proof uses internally
//! (PatHash in logarithmic.cpp), reproduced here because that helper is
//! file-static. The two must stay the same function: spec §3 commits tuple
//! fields with the proof's own hash.
uint256 Sha3(const unsigned char* data, size_t len)
{
    SHA3_256 hasher;
    hasher.Write(data, len);
    uint256 out;
    hasher.Finalize(out.begin());
    return out;
}

std::vector<unsigned char> Sha3Vec(const std::vector<unsigned char>& data)
{
    const uint256 h = Sha3(data.data(), data.size());
    return std::vector<unsigned char>(h.begin(), h.end());
}

} // namespace

int WitnessVersionOf(const CScript& scriptPubKey)
{
    if (scriptPubKey.size() != 34 || scriptPubKey[1] != 32) return -1;
    if (scriptPubKey[0] == OP_0) return 0;
    if (scriptPubKey[0] >= OP_1 && scriptPubKey[0] <= OP_16) {
        return scriptPubKey[0] - (OP_1 - 1);
    }
    return -1;
}

bool IsAttestedVersion(int version, const AttestedSetParams& params)
{
    switch (version) {
    case 0: case 1: return true;                  // base forms, active from genesis
    // v7/v8 are attested UNCONDITIONALLY (additive-asset genesis door,
    // 2026-09). They used to join at their deployment's activation height,
    // which made the block commitment a function of activation state: a
    // genesis node and an upgraded node would recompute different
    // attestations over the same block from the activation height onward and
    // reject each other's commitments — a hard fork by construction. A set
    // that never changes cannot do that. Dormant v7/v8 spends are anyone-
    // can-spend two-item spends; attesting their (unverified) tuples commits
    // to bytes, not to validity, exactly as for every other tuple.
    case 7: case 8: return true;                  // USDSOQ / BTCSOQ holding, fixed
    default: return false;                        // spec §2 disposition table
    }
}

void AppendTuples(PatBatch& batch, const CTransaction& tx,
                  const std::function<bool(const COutPoint&, CTxOut&)>& prevoutLookup,
                  const AttestedSetParams& params)
{
    if (tx.IsCoinBase()) return; // spends nothing

    const PrecomputedTransactionData txdata(tx);

    // Input order within the transaction is part of the "original position"
    // of spec §4 (transaction index, then input index). CreateLogarithmicProof
    // applies the canonical ordering internally, using insertion order as the
    // positional tie-break, so insertion order here IS the consensus
    // definition. Do not reorder.
    for (size_t in = 0; in < tx.vin.size(); ++in) {
        CTxOut prevout;
        if (!prevoutLookup(tx.vin[in].prevout, prevout)) continue;

        const int version = WitnessVersionOf(prevout.scriptPubKey);
        if (version < 0 || !IsAttestedVersion(version, params)) continue;

        // Spec §2: attested iff the witness stack is exactly two items
        // (the single-key Dilithium shape, [sig, pubkey]).
        const CScriptWitness& wit = tx.vin[in].scriptWitness;
        if (wit.stack.size() != 2) continue;

        const std::vector<unsigned char>& sig = wit.stack[0];
        const std::vector<unsigned char>& pubkey = wit.stack[1];

        // Spec §3: pk commits to the canonical stripped form — the same
        // normalisation TransactionSignatureChecker::CheckSig and
        // VerifyScript perform (Decision 2).
        const unsigned char* pkData = pubkey.data();
        size_t pkSize = pubkey.size();
        if (pkSize == 1313 && pubkey[0] == 0x00) {
            pkData += 1;
            pkSize -= 1;
        }

        // Spec §3: msg is the sighash CheckSig verified against, obtained
        // through the same SignatureHash function with the same argument
        // derivation: nHashType from the trailing signature byte,
        // scriptCode from the prevout, amount from the prevout value.
        // An empty signature cannot verify, so the block is invalid
        // regardless; nHashType = 0 keeps this function total.
        const int nHashType = sig.empty() ? 0 : sig.back();
        const uint256 sighash = SignatureHash(prevout.scriptPubKey, tx, in,
                                              nHashType, prevout.nValue,
                                              SIGVERSION_WITNESS_V0, &txdata);

        const uint256 pkHash = Sha3(pkData, pkSize);
        batch.sigs.push_back(Sha3Vec(sig));
        batch.pks.push_back(std::vector<unsigned char>(pkHash.begin(), pkHash.end()));
        batch.msgs.push_back(std::vector<unsigned char>(sighash.begin(), sighash.end()));
    }
}

PatBatch CollectBatch(const CBlock& block,
                      const std::function<bool(const COutPoint&, CTxOut&)>& prevoutLookup,
                      const AttestedSetParams& params)
{
    PatBatch batch;
    for (size_t txIdx = 1; txIdx < block.vtx.size(); ++txIdx) {
        AppendTuples(batch, *block.vtx[txIdx], prevoutLookup, params);
    }
    return batch;
}

uint256 AttestationHash(const std::vector<unsigned char>& proof)
{
    SHA3_256 hasher;
    const unsigned char domain = 0x02; // spec §6: 0x00 leaf, 0x01 node, 0x02 attestation
    hasher.Write(&domain, 1);
    hasher.Write(proof.data(), proof.size());
    uint256 out;
    hasher.Finalize(out.begin());
    return out;
}

bool ComputeBlockAttestation(const PatBatch& batch, uint256& hashOut)
{
    if (batch.empty()) return false; // spec §5: no attested spends, no attestation

    std::vector<unsigned char> proof;
    if (!pat::CreateLogarithmicProof(batch.sigs, batch.pks, batch.msgs, proof)) {
        return false; // n > 2^20, unreachable under block limits but defined (spec §5)
    }

    hashOut = AttestationHash(proof);
    return true;
}

CScript BuildCommitmentScript(const uint256& attestationHash)
{
    CScript script;
    script.resize(36);
    script[0] = OP_RETURN;
    script[1] = 0x22; // OP_PUSHBYTES_34
    script[2] = 0x50; // 'P'
    script[3] = 0x41; // 'A'
    memcpy(&script[4], attestationHash.begin(), 32);
    return script;
}

bool ParseCommitmentScript(const CScript& script, uint256& hashOut)
{
    if (script.size() != 36) return false;
    if (script[0] != OP_RETURN) return false;
    if (script[1] != 0x22) return false;
    if (script[2] != 0x50 || script[3] != 0x41) return false;
    memcpy(hashOut.begin(), &script[4], 32);
    return true;
}

int FindCommitments(const CTransaction& coinbase, uint256& hashOut)
{
    int found = 0;
    for (const CTxOut& out : coinbase.vout) {
        uint256 h;
        if (ParseCommitmentScript(out.scriptPubKey, h)) {
            if (found == 0) hashOut = h;
            ++found;
            // Deliberately no break: the count is what lets the caller
            // enforce exactly-one (spec §6). Stopping at the first match is
            // the LatticeFold validator behaviour the spec rejects.
        }
    }
    return found;
}

} // namespace patattest
