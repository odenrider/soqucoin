// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// pat_attestation_tests.cpp — the PAT block attestation module against its
// specification, doc/PAT_BLOCK_ATTESTATION.md. Section references below are to
// that document. Each case names the input that would make it fail; a check
// with no such input is documentation, not coverage.

#include "consensus/pat_attestation.h"
#include "crypto/pat/logarithmic.h"
#include "crypto/sha3.h"
#include "script/interpreter.h"
#include "test/dilithium_chain_setup.h"

#include <boost/test/unit_test.hpp>

typedef std::vector<unsigned char> valtype;

namespace {

//! SHA3-256, matching the tuple-commitment hash of spec §3.
valtype Sha3Of(const unsigned char* data, size_t len)
{
    SHA3_256 h;
    h.Write(data, len);
    uint256 out;
    h.Finalize(out.begin());
    return valtype(out.begin(), out.end());
}

valtype Sha3Of(const valtype& v) { return Sha3Of(v.data(), v.size()); }

} // namespace

struct PatAttestationSetup : public DilithiumChainSetup {
    //! A block containing one transaction that spends `cb`'s output 0 to
    //! `destSpk`, signed for real. The block is synthetic (never connected):
    //! the collector is a pure function of block bytes plus the prevout
    //! lookup, so nothing here needs a chain.
    CBlock BlockSpending(const CTransaction& cb, const CScript& prevoutSpkOverride,
                         CTxOut& prevoutOut)
    {
        // The prevout the lookup will report. Overriding its scriptPubKey lets
        // a test present the same signed spend as a different witness version.
        prevoutOut = cb.vout[0];
        if (!prevoutSpkOverride.empty()) prevoutOut.scriptPubKey = prevoutSpkOverride;

        CMutableTransaction tx;
        tx.nVersion = 2;
        CTxIn in;
        in.prevout = COutPoint(cb.GetHash(), 0);
        in.nSequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.push_back(in);
        CTxOut out;
        out.nValue = prevoutOut.nValue - 10000;
        out.scriptPubKey = Spk(OP_1);
        tx.vout.push_back(out);
        SignInput(tx, 0, prevoutOut.scriptPubKey, prevoutOut.nValue);

        CBlock block;
        block.vtx.push_back(MakeTransactionRef(CTransaction(coinbaseTxns[0]))); // stand-in coinbase
        block.vtx.push_back(MakeTransactionRef(CTransaction(tx)));
        return block;
    }

    //! Lookup that resolves every input of the (single) spend to `prevout`.
    static std::function<bool(const COutPoint&, CTxOut&)> LookupReturning(const CTxOut& prevout)
    {
        return [prevout](const COutPoint&, CTxOut& out) { out = prevout; return true; };
    }
};

BOOST_FIXTURE_TEST_SUITE(pat_attestation_tests, PatAttestationSetup)

// --- §6: commitment script encoding -----------------------------------------

// Fails if the builder or parser drifts from the 36-byte OP_RETURN + PA shape.
BOOST_AUTO_TEST_CASE(commitment_script_round_trip)
{
    uint256 h;
    GetRandBytes(h.begin(), 32);

    const CScript script = patattest::BuildCommitmentScript(h);
    BOOST_CHECK_EQUAL(script.size(), 36u);

    uint256 parsed;
    BOOST_REQUIRE(patattest::ParseCommitmentScript(script, parsed));
    BOOST_CHECK(parsed == h);
}

// Fails if the parser loosens: every near-miss shape must be refused, because
// anything that parses as a commitment is consensus-compared against the
// recomputation.
BOOST_AUTO_TEST_CASE(commitment_parser_rejects_near_misses)
{
    uint256 h, ignored;
    GetRandBytes(h.begin(), 32);
    const CScript good = patattest::BuildCommitmentScript(h);

    // Wrong magic: the LatticeFold commitment ('LF') must not parse as PAT.
    CScript lf = good;
    lf[2] = 0x4C; lf[3] = 0x46;
    BOOST_CHECK(!patattest::ParseCommitmentScript(lf, ignored));

    // Truncated by one byte.
    CScript shortScript(good.begin(), good.end() - 1);
    BOOST_CHECK(!patattest::ParseCommitmentScript(shortScript, ignored));

    // One byte appended (the SegWit commitment is 38 bytes; length must bind).
    CScript longScript = good;
    longScript.push_back(0x00);
    BOOST_CHECK(!patattest::ParseCommitmentScript(longScript, ignored));

    // Not an OP_RETURN.
    CScript notOpReturn = good;
    notOpReturn[0] = OP_NOP;
    BOOST_CHECK(!patattest::ParseCommitmentScript(notOpReturn, ignored));
}

// Fails if FindCommitments regresses to first-match-and-stop — the LatticeFold
// validator behaviour the spec rejects (§6), under which a miner could place a
// decoy ahead of the real commitment and have the decoy be the one compared.
BOOST_AUTO_TEST_CASE(find_commitments_counts_every_match)
{
    uint256 h1, h2;
    GetRandBytes(h1.begin(), 32);
    GetRandBytes(h2.begin(), 32);

    CMutableTransaction cb;
    cb.vout.resize(3);
    cb.vout[0].scriptPubKey = Spk(OP_1);                            // ordinary payout
    cb.vout[1].scriptPubKey = patattest::BuildCommitmentScript(h1); // the "decoy"
    cb.vout[2].scriptPubKey = patattest::BuildCommitmentScript(h2); // the second

    uint256 first;
    BOOST_CHECK_EQUAL(patattest::FindCommitments(CTransaction(cb), first), 2);
    BOOST_CHECK(first == h1);

    cb.vout.resize(2); // exactly one commitment
    BOOST_CHECK_EQUAL(patattest::FindCommitments(CTransaction(cb), first), 1);

    cb.vout.resize(1); // none
    BOOST_CHECK_EQUAL(patattest::FindCommitments(CTransaction(cb), first), 0);
}

// --- §2: the attested set ----------------------------------------------------

// Fails if the version rule drifts from the spec's disposition table in either
// direction: a version wrongly attested changes every affected block's
// commitment; a version wrongly excluded changes it the other way. The set is
// FIXED and must not depend on deployment state: a set that changed at an
// activation height would make the genesis binary and the activation release
// recompute different commitments over the same block (a hard fork).
BOOST_AUTO_TEST_CASE(attested_set_matches_the_disposition_table)
{
    patattest::AttestedSetParams off;                 // flags clear
    patattest::AttestedSetParams on;                  // flags set (must be ignored)
    on.fUsdsoqActive = true;
    on.fBtcsoqActive = true;

    for (int v = -1; v <= 17; ++v) {
        const bool attested = (v == 0 || v == 1 || v == 7 || v == 8);
        BOOST_CHECK_MESSAGE(patattest::IsAttestedVersion(v, off) == attested,
            "attested set must be exactly {v0, v1, v7, v8}; disagreed at v" << v);

        BOOST_CHECK_MESSAGE(patattest::IsAttestedVersion(v, on) == patattest::IsAttestedVersion(v, off),
            "the attested set must not depend on deployment flags; disagreed at v" << v);
    }
}

// --- §2-§4: collection -------------------------------------------------------

// Fails if the collector's tuple construction drifts from §3 in any argument:
// the expected values are recomputed here from first principles (explicit
// SignatureHash arguments, explicit SHA3 of the witness items), so a wrong
// amount, scriptCode, input index, or hash-type byte shows up as a mismatch.
BOOST_AUTO_TEST_CASE(collector_builds_the_specified_tuple_for_a_v1_spend)
{
    CTxOut prevout;
    const CBlock block = BlockSpending(coinbaseTxns[0], CScript(), prevout);
    const CTransaction& spend = *block.vtx[1];

    patattest::PatBatch batch =
        patattest::CollectBatch(block, LookupReturning(prevout), patattest::AttestedSetParams());

    BOOST_REQUIRE_EQUAL(batch.size(), 1u);

    const valtype& sig = spend.vin[0].scriptWitness.stack[0];
    BOOST_CHECK(batch.sigs[0] == Sha3Of(sig));

    // pk commits to the STRIPPED canonical form (Decision 2): the witness
    // carries the 1313-byte prefixed key, the tuple must hash the 1312 bytes.
    BOOST_CHECK(batch.pks[0] == Sha3Of(coinbasePkBytes));

    const PrecomputedTransactionData txdata(spend);
    const uint256 expectedSighash =
        SignatureHash(prevout.scriptPubKey, spend, 0, sig.back(), prevout.nValue,
                      SIGVERSION_WITNESS_V0, &txdata);
    BOOST_CHECK(batch.msgs[0] == valtype(expectedSighash.begin(), expectedSighash.end()));
}

// The Decision 2 pin, end to end. Fails if the collector commits raw witness
// bytes: the same key under its two accepted encodings would then produce two
// different attestations for otherwise identical spends.
BOOST_AUTO_TEST_CASE(both_pubkey_encodings_attest_identically)
{
    CTxOut prevout;
    CBlock prefixed = BlockSpending(coinbaseTxns[1], CScript(), prevout);

    // The same block with the witness key re-encoded to the bare 1312-byte
    // form. Consensus treats the two as the same key; so must the attestation.
    CBlock bare = prefixed;
    CMutableTransaction tx(*bare.vtx[1]);
    tx.vin[0].scriptWitness.stack[1] = coinbasePkBytes;
    bare.vtx[1] = MakeTransactionRef(CTransaction(tx));

    const patattest::AttestedSetParams params;
    uint256 a, b;
    BOOST_REQUIRE(patattest::ComputeBlockAttestation(
        patattest::CollectBatch(prefixed, LookupReturning(prevout), params), a));
    BOOST_REQUIRE(patattest::ComputeBlockAttestation(
        patattest::CollectBatch(bare, LookupReturning(prevout), params), b));

    BOOST_CHECK_MESSAGE(a == b,
        "the two accepted encodings of the same key produced different "
        "attestations. The collector is committing raw witness bytes instead "
        "of the canonical stripped form (spec section 3, Decision 2).");
}

// A v7 two-item spend is attested in EVERY deployment state. Fails if the
// collector starts consulting the flags again: a genesis node (flags clear)
// and an activation-release node (flags set) would then build different
// batches over the same block and reject each other's commitments.
BOOST_AUTO_TEST_CASE(v7_is_attested_regardless_of_activation_state)
{
    CTxOut prevout;
    const CBlock block = BlockSpending(coinbaseTxns[2], Spk(OP_7), prevout);

    patattest::AttestedSetParams genesis;
    BOOST_CHECK_EQUAL(
        patattest::CollectBatch(block, LookupReturning(prevout), genesis).size(), 1u);

    patattest::AttestedSetParams activated;
    activated.fUsdsoqActive = true;
    BOOST_CHECK_EQUAL(
        patattest::CollectBatch(block, LookupReturning(prevout), activated).size(), 1u);
}

// Fails if the collector widens past the two-item single-key shape. A v6-style
// multi-item witness has no defined tuple (spec §2), and a v1 spend with a
// third witness item is not the single-key shape even though the version is
// attested.
BOOST_AUTO_TEST_CASE(collector_requires_the_exact_single_key_shape)
{
    CTxOut prevout;
    CBlock block = BlockSpending(coinbaseTxns[3], CScript(), prevout);

    CMutableTransaction tx(*block.vtx[1]);
    tx.vin[0].scriptWitness.stack.push_back(valtype(1, 0x01)); // third item
    block.vtx[1] = MakeTransactionRef(CTransaction(tx));

    BOOST_CHECK_EQUAL(
        patattest::CollectBatch(block, LookupReturning(prevout),
                                patattest::AttestedSetParams()).size(), 0u);
}

// Fails if an excluded version leaks into the batch. The spend is signed and
// two-item, so only the version rule excludes it — the discriminating input.
BOOST_AUTO_TEST_CASE(excluded_versions_never_contribute)
{
    const opcodetype excluded[] = {OP_3, OP_4, OP_5, OP_6, OP_9, OP_10, OP_16};
    patattest::AttestedSetParams everythingOn;
    everythingOn.fUsdsoqActive = true;
    everythingOn.fBtcsoqActive = true;

    int idx = 4;
    for (opcodetype v : excluded) {
        CTxOut prevout;
        const CBlock block = BlockSpending(coinbaseTxns[idx++], Spk(v), prevout);
        BOOST_CHECK_MESSAGE(
            patattest::CollectBatch(block, LookupReturning(prevout), everythingOn).empty(),
            "witness version opcode " << (int)v << " contributed to the batch; "
            "the spec section 2 disposition table excludes it");
    }
}

// --- §5: empty batch ---------------------------------------------------------

// Fails if an empty block acquires an attestation. Every coinbase-only block
// on the chain exercises this rule.
BOOST_AUTO_TEST_CASE(empty_batch_has_no_attestation)
{
    uint256 h;
    BOOST_CHECK(!patattest::ComputeBlockAttestation(patattest::PatBatch(), h));
}

// --- §6: the attestation hash ------------------------------------------------

// Fails if the 0x02 domain prefix is dropped or changed: the hash would then
// collide with the proof's own leaf/node hash space or plain SHA3.
BOOST_AUTO_TEST_CASE(attestation_hash_is_domain_separated)
{
    valtype proof(100, 0xAB);
    const uint256 attested = patattest::AttestationHash(proof);

    SHA3_256 plain;
    plain.Write(proof.data(), proof.size());
    uint256 plainHash;
    plain.Finalize(plainHash.begin());
    BOOST_CHECK(attested != plainHash);

    for (unsigned char domain : {(unsigned char)0x00, (unsigned char)0x01}) {
        SHA3_256 other;
        other.Write(&domain, 1);
        other.Write(proof.data(), proof.size());
        uint256 otherHash;
        other.Finalize(otherHash.begin());
        BOOST_CHECK(attested != otherHash);
    }
}

// Known-answer pin for the batch-to-hash pipeline (CreateLogarithmicProof over
// a fixed batch, then the domain-separated hash). Fails on any cross-build or
// cross-platform divergence in that pipeline — the same role the canonical
// ordering vectors play one layer down. Do not re-pin to a new platform's
// output; a mismatch here is the divergence, caught in a test.
BOOST_AUTO_TEST_CASE(attestation_matches_pinned_vector)
{
    patattest::PatBatch batch;
    for (unsigned char i = 0; i < 3; ++i) {
        batch.sigs.push_back(valtype(32, (unsigned char)(0x10 + i)));
        batch.pks.push_back(valtype(32, (unsigned char)(0x40 + i)));
        batch.msgs.push_back(valtype(32, (unsigned char)(0x70 + i)));
    }

    uint256 h;
    BOOST_REQUIRE(patattest::ComputeBlockAttestation(batch, h));
    BOOST_CHECK_EQUAL(h.GetHex(),
        "dcbd3730c01846a58a2d00b476ff9c056dc8a4224650232a805349d0fc4d86c0");
}

BOOST_AUTO_TEST_SUITE_END()
