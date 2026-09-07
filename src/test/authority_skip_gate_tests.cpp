// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// authority_skip_gate_tests.cpp — proof harness for the CheckInputs authority
// script-verification skip.
//
// validation.cpp CheckInputs() skips per-input script verification for the
// ENTIRE transaction when the tx "looks like" a USDSOQ authority tx:
//
//     an OP_5 <32> output  +  some input whose witness has
//     stack.size() >= 6, stack[2] == {0x55}, and a 2420-byte item at [4..n-2]
//
// Both halves of that predicate are attacker-chosen data. The compensating
// M-of-N ML-DSA verification lives in ConnectBlock behind TWO guards the skip
// does not share:
//     if (flags & SCRIPT_VERIFY_USDSOQ)          // DEPLOYMENT_USDSOQ active
//         ... if (isAuthorityTx && g_usdsoq_authority.IsInitialized())
//
// Regtest has DEPLOYMENT_USDSOQ active at height 0 but defines NO
// usdsoqAuthorityKeys, so IsInitialized() is false — the same posture mainnet
// has (mainnet defines no authority keys either, and additionally ships the
// deployment NOT_SCHEDULED). So regtest reproduces the mainnet gap exactly.
//
// FIXED by SOQ-I009 (see validation.cpp): the skip is now granted only when
// the deployment is active AND the authority is initialised — the same two
// guards as the verifier that replaces it. With the deployment DORMANT an
// authority-shaped tx is an ordinary tx and every input runs ordinary script
// verification (the additive-asset genesis door, 2026-09, replaced the
// earlier outright rejection of that shape: a rejection the activation
// release would have to relax is a hard fork). Every case below asserts the
// SAFE outcome, so the file is a regression guard, not a repro.
//
// The cases below are byte-identical except for ONE opcode in one output:
// OP_1 (control) vs OP_5 (attack). Both carry the same deliberately invalid
// witness. If the control is rejected and the attack connects, the skip is
// unauthenticated and the difference is that single opcode.
//
// Fixture shape borrowed from usdsoq_v7_conservation_harness_tests.cpp.

#include "chainparams.h"
#include "consensus/btcsoq.h"
#include "consensus/validation.h"
#include "key.h"
#include "miner.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "coins.h"
#include "txdb.h"
#include "uint256.h"
#include "validation.h"
#include "crypto/sha256.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>
#include <algorithm>

namespace {

static const int COINBASE_MATURITY_SOQ = 60 * 4;  // 240, regtest

static CScript MakeVerSpk(int opN, const std::vector<unsigned char>& rawPubkey)
{
    uint256 pkHash;
    CSHA256().Write(rawPubkey.data(), rawPubkey.size()).Finalize(pkHash.begin());
    CScript spk;
    spk << CScript::EncodeOP_N(opN) << std::vector<unsigned char>(pkHash.begin(), pkHash.end());
    return spk;
}

static std::vector<unsigned char> Prefixed(const std::vector<unsigned char>& rawPubkey)
{
    std::vector<unsigned char> out;
    out.reserve(rawPubkey.size() + 1);
    out.push_back(0x00);
    out.insert(out.end(), rawPubkey.begin(), rawPubkey.end());
    return out;
}

} // namespace

struct AuthoritySkipChainSetup : public TestingSetup {
    CKey victimKey;                              // owns the coins that get stolen
    CScript victimSpk;
    std::vector<unsigned char> victimPkBytes;

    CKey attackerKey;                            // never signs anything
    CScript attackerSpk;
    std::vector<unsigned char> attackerPkBytes;

    std::vector<CTransaction> coinbaseTxns;

    AuthoritySkipChainSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
        // These cases assert the NO-AUTHORITY default-deny, so the precondition
        // has to be established rather than assumed. The authority globals are
        // process-wide and another suite may have installed one.
        {
            LOCK(cs_main);
            g_usdsoq_authority.Reset();
            g_btcsoq_authority.Reset();
        }

        victimKey.MakeNewKey(true);
        CPubKey vpk = victimKey.GetPubKey();
        BOOST_REQUIRE(vpk.IsValid());
        victimPkBytes.assign(vpk.begin(), vpk.end());
        victimSpk = MakeVerSpk(1, victimPkBytes);

        attackerKey.MakeNewKey(true);
        CPubKey apk = attackerKey.GetPubKey();
        BOOST_REQUIRE(apk.IsValid());
        attackerPkBytes.assign(apk.begin(), apk.end());
        attackerSpk = MakeVerSpk(1, attackerPkBytes);

        for (int i = 0; i < COINBASE_MATURITY_SOQ; i++) {
            std::vector<CMutableTransaction> noTxns;
            CBlock b = CreateAndProcessBlock(noTxns, victimSpk);
            BOOST_REQUIRE(b.vtx.size() > 0);
            coinbaseTxns.push_back(*b.vtx[0]);
        }
    }

    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns, const CScript& spk)
    {
        const CChainParams& cp = Params();
        std::unique_ptr<CBlockTemplate> tmpl = BlockAssembler(cp).CreateNewBlock(spk, true);
        BOOST_REQUIRE(tmpl != nullptr);
        CBlock& block = tmpl->block;
        block.vtx.resize(1);
        {
            CMutableTransaction coinbaseMut(*block.vtx[0]);
            coinbaseMut.vout.erase(
                std::remove_if(coinbaseMut.vout.begin(), coinbaseMut.vout.end(),
                    [](const CTxOut& o) {
                        return o.scriptPubKey.size() >= 38 &&
                               o.scriptPubKey[0] == OP_RETURN && o.scriptPubKey[1] == 0x24 &&
                               o.scriptPubKey[2] == 0xaa && o.scriptPubKey[3] == 0x21 &&
                               o.scriptPubKey[4] == 0xa9 && o.scriptPubKey[5] == 0xed;
                    }),
                coinbaseMut.vout.end());
            coinbaseMut.vin[0].scriptWitness.stack.clear();
            block.vtx[0] = MakeTransactionRef(std::move(coinbaseMut));
        }
        for (const CMutableTransaction& tx : txns)
            block.vtx.push_back(MakeTransactionRef(tx));
        GenerateCoinbaseCommitment(block, chainActive.Tip(), cp.GetConsensus(0));
        unsigned int extraNonce = 0;
        IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);
        while (!CheckProofOfWork(block.GetPoWHash(), block.nBits, cp.GetConsensus(0)))
            ++block.nNonce;
        std::shared_ptr<const CBlock> shared = std::make_shared<const CBlock>(block);
        bool fNewBlock = false;
        ProcessNewBlock(cp, shared, true, &fNewBlock);
        return block;
    }

    // r0vn: a rejection has to be observed by NAME, not inferred from a tip that
    // did not move. Every case in this file originally asserted only "the tip is
    // unchanged", which passes just as happily for the WRONG rejection — the
    // exact weakness this file exists to expose elsewhere. Returns the reject
    // string, or "" if the block validated.
    //
    // Caveat that matters here: a failure inside VerifyScript surfaces as
    // `state.DoS(100, false)` with an EMPTY reject string (ConnectBlock's
    // control.Wait() path), so "" is ambiguous for script-layer rules. The
    // rejections asserted below all come from CheckInputs' own named
    // default-denies, which do carry a string.
    std::string RejectReasonFor(const std::vector<CMutableTransaction>& txns)
    {
        CBlock B = BuildSolvedBlock(txns, victimSpk);
        CValidationState st;
        LOCK(cs_main);
        if (TestBlockValidity(st, Params(), B, chainActive.Tip(), true, true)) return std::string();
        return st.GetRejectReason();
    }

    // Build and solve a block without submitting it.
    CBlock BuildSolvedBlock(const std::vector<CMutableTransaction>& txns, const CScript& spk)
    {
        const CChainParams& cp = Params();
        std::unique_ptr<CBlockTemplate> tmpl = BlockAssembler(cp).CreateNewBlock(spk, true);
        BOOST_REQUIRE(tmpl != nullptr);
        CBlock& block = tmpl->block;
        block.vtx.resize(1);
        {
            CMutableTransaction coinbaseMut(*block.vtx[0]);
            coinbaseMut.vout.erase(
                std::remove_if(coinbaseMut.vout.begin(), coinbaseMut.vout.end(),
                    [](const CTxOut& o) {
                        return o.scriptPubKey.size() >= 38 &&
                               o.scriptPubKey[0] == OP_RETURN && o.scriptPubKey[1] == 0x24 &&
                               o.scriptPubKey[2] == 0xaa && o.scriptPubKey[3] == 0x21 &&
                               o.scriptPubKey[4] == 0xa9 && o.scriptPubKey[5] == 0xed;
                    }),
                coinbaseMut.vout.end());
            coinbaseMut.vin[0].scriptWitness.stack.clear();
            block.vtx[0] = MakeTransactionRef(std::move(coinbaseMut));
        }
        for (const CMutableTransaction& tx : txns)
            block.vtx.push_back(MakeTransactionRef(tx));
        GenerateCoinbaseCommitment(block, chainActive.Tip(), cp.GetConsensus(0));
        unsigned int extraNonce = 0;
        IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);
        while (!CheckProofOfWork(block.GetPoWHash(), block.nBits, cp.GetConsensus(0)))
            ++block.nNonce;
        return block;
    }

    // Steal victim coinbase `cb` to attackerSpk. `markerOpN` picks the opcode of
    // the marker output: 5 == the USDSOQ authority marker (attack), 1 == an
    // ordinary Dilithium output (control). Everything else is identical, and the
    // witness is deliberately garbage in BOTH cases — the victim never signs.
    CMutableTransaction BuildForgedAuthoritySteal(const CTransaction& cb, int markerOpN,
                                                  uint8_t tagByte = 0x55)
    {
        const CAmount inVal = cb.vout[0].nValue;
        CMutableTransaction tx;
        tx.nVersion = 2;

        CTxIn in;
        in.prevout = COutPoint(cb.GetHash(), 0);
        in.nSequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.push_back(in);

        CTxOut marker;
        marker.nValue = 10000;
        marker.scriptPubKey = MakeVerSpk(markerOpN, attackerPkBytes);
        tx.vout.push_back(marker);

        CTxOut loot;
        loot.nValue = inVal - 20000;             // 10000 fee
        loot.scriptPubKey = attackerSpk;
        tx.vout.push_back(loot);

        // Authority-shaped witness, entirely fabricated. No call to any Sign().
        std::vector<unsigned char> junkSig(2421, 0xAB);   // [0] "payout sig"+hashtype
        std::vector<unsigned char> tag(1, tagByte);       // [2] auth_tag
        std::vector<unsigned char> payload(8, 0xCD);      // [3] auth_payload
        std::vector<unsigned char> junkAuthSig(2420, 0xEF); // [4] "authority sig" — size is the whole test
        std::vector<unsigned char> authSet(4, 0x00);      // [5] authority_set
        // Leading 0x00 keeps CTransaction::HasDilithiumSignatures()'s fallback
        // happy (it only tests pk_blob[0] == 0x00), which matters for the
        // BTCSOQ variant: that one's tag byte is not 0x55, so it does not take
        // the authority exemption inside HasDilithiumSignatures.

        tx.vin[0].scriptWitness.stack.clear();
        tx.vin[0].scriptWitness.stack.push_back(junkSig);
        tx.vin[0].scriptWitness.stack.push_back(Prefixed(attackerPkBytes)); // attacker's key, not victim's
        tx.vin[0].scriptWitness.stack.push_back(tag);
        tx.vin[0].scriptWitness.stack.push_back(payload);
        tx.vin[0].scriptWitness.stack.push_back(junkAuthSig);
        tx.vin[0].scriptWitness.stack.push_back(authSet);
        BOOST_REQUIRE_EQUAL(tx.vin[0].scriptWitness.stack.size(), 6u);

        return tx;
    }
};

BOOST_FIXTURE_TEST_SUITE(authority_skip_gate_tests, AuthoritySkipChainSetup)

// CONTROL: identical tx, marker output is OP_1. No skip, so the garbage witness
// must fail Dilithium verification and the block must NOT connect.
BOOST_AUTO_TEST_CASE(control_no_marker_forged_witness_is_rejected)
{
    const int heightBefore = chainActive.Height();
    std::vector<CMutableTransaction> txns{ BuildForgedAuthoritySteal(coinbaseTxns[0], 1) };
    CBlock b = CreateAndProcessBlock(txns, victimSpk);

    // Deliberately NOT string-pinned: this rejection comes from VerifyScript
    // (NULLFAIL on the garbage witness), and ConnectBlock reports script-check
    // failure as state.DoS(100, false) with an EMPTY reject string. There is no
    // name to assert. Every OTHER case in this file names its string.
    BOOST_CHECK_MESSAGE(chainActive.Tip()->GetBlockHash() != b.GetHash(),
        "CONTROL FAILED: a block spending someone else's coin with a garbage "
        "witness connected even WITHOUT the OP_5 marker — the harness is not "
        "verifying scripts at all, so the attack case below proves nothing.");
    BOOST_CHECK_EQUAL(chainActive.Height(), heightBefore);
}

// ATTACK: the only change is OP_1 -> OP_5 on the marker output. Regtest runs
// DEPLOYMENT_USDSOQ active but configures no usdsoqAuthorityKeys, so the
// default-deny (bad-usdsoq-authority-unavailable) is what must catch this.
BOOST_AUTO_TEST_CASE(op5_marker_does_not_skip_script_verification)
{
    const std::string why = RejectReasonFor({ BuildForgedAuthoritySteal(coinbaseTxns[1], 5) });
    BOOST_TEST_MESSAGE("reject: '" << why << "'");
    BOOST_CHECK_EQUAL(why, "bad-usdsoq-authority-unavailable");
}

// Same forgery under MAINNET posture: DEPLOYMENT_USDSOQ withdrawn, exactly as
// CMainParams ships it. No skip is granted while the deployment is dormant, so
// the forged 6-item witness on someone else's coin is verified like any other
// input and fails in VerifyScript — the same path as the control, and like the
// control it has no reject string to pin. (Until 2026-09 this was an outright
// "bad-usdsoq-authority-not-active" rejection; that rejection would have been
// relaxed by the activation release, which is a hard fork, so it became a
// fall-through to ordinary verification.)
BOOST_AUTO_TEST_CASE(op5_marker_does_not_skip_scripts_when_usdsoq_not_scheduled)
{
    UpdateRegtestActivationHeight(Consensus::DEPLOYMENT_USDSOQ,
                                  Consensus::BIP9Deployment::NOT_SCHEDULED);
    SelectParams(CBaseChainParams::REGTEST);

    const int heightBefore = chainActive.Height();
    std::vector<CMutableTransaction> txns{ BuildForgedAuthoritySteal(coinbaseTxns[1], 5) };
    CBlock b = CreateAndProcessBlock(txns, victimSpk);

    UpdateRegtestActivationHeight(Consensus::DEPLOYMENT_USDSOQ, 0);  // restore
    SelectParams(CBaseChainParams::REGTEST);

    BOOST_CHECK_MESSAGE(chainActive.Tip()->GetBlockHash() != b.GetHash(),
        "STEAL CONNECTED: with DEPLOYMENT_USDSOQ dormant, an OP_5 marker plus an "
        "authority-shaped witness skipped script verification and spent someone "
        "else's coin. The skip must never be granted without the verifier.");
    BOOST_CHECK_EQUAL(chainActive.Height(), heightBefore);
}

// The BTCSOQ twin, with BTCSOQ ACTIVE (stock regtest). Unlike USDSOQ, the
// BTCSOQ ConnectBlock block carries a default-deny for an uninitialised
// authority ("bad-btcsoq-authority-unavailable", validation.cpp:4245), so the
// forgery is caught here. This case documents that asymmetry — USDSOQ has no
// equivalent default-deny.
BOOST_AUTO_TEST_CASE(op9_marker_caught_when_btcsoq_deployment_active)
{
    const std::string why = RejectReasonFor({
        BuildForgedAuthoritySteal(coinbaseTxns[2], 9, BTCSOQ_OP_MINT) });
    BOOST_TEST_MESSAGE("reject: '" << why << "'");
    BOOST_CHECK_EQUAL(why, "bad-btcsoq-authority-unavailable");
}

// The BTCSOQ twin under MAINNET posture: DEPLOYMENT_BTCSOQ withdrawn, exactly
// as CMainParams ships it. SCRIPT_VERIFY_BTCSOQ is never set, so no skip is
// granted and the forged witness fails ordinary script verification, exactly
// as in the USDSOQ case above.
BOOST_AUTO_TEST_CASE(op9_marker_does_not_skip_scripts_when_btcsoq_not_scheduled)
{
    UpdateRegtestActivationHeight(Consensus::DEPLOYMENT_BTCSOQ,
                                  Consensus::BIP9Deployment::NOT_SCHEDULED);
    SelectParams(CBaseChainParams::REGTEST);

    const int heightBefore = chainActive.Height();
    std::vector<CMutableTransaction> txns{
        BuildForgedAuthoritySteal(coinbaseTxns[2], 9, BTCSOQ_OP_MINT) };
    CBlock b = CreateAndProcessBlock(txns, victimSpk);

    UpdateRegtestActivationHeight(Consensus::DEPLOYMENT_BTCSOQ, 0);  // restore
    SelectParams(CBaseChainParams::REGTEST);

    BOOST_CHECK_MESSAGE(chainActive.Tip()->GetBlockHash() != b.GetHash(),
        "STEAL CONNECTED: with DEPLOYMENT_BTCSOQ dormant, a v9 marker plus an "
        "authority-shaped witness skipped script verification and spent someone "
        "else's coin. The skip must never be granted without the verifier.");
    BOOST_CHECK_EQUAL(chainActive.Height(), heightBefore);
}

// Positive control: SOQ-I009 must not break ordinary spending. A correctly
// signed, non-authority spend still connects.
BOOST_AUTO_TEST_CASE(honest_signed_spend_still_connects)
{
    const CTransaction& cb = coinbaseTxns[3];
    const CAmount inVal = cb.vout[0].nValue;

    CMutableTransaction tx;
    tx.nVersion = 2;
    CTxIn in;
    in.prevout = COutPoint(cb.GetHash(), 0);
    in.nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vin.push_back(in);
    CTxOut out;
    out.nValue = inVal - 10000;
    out.scriptPubKey = attackerSpk;
    tx.vout.push_back(out);

    CTransaction ctxForSign(tx);
    uint256 sighash = SignatureHash(victimSpk, ctxForSign, 0, SIGHASH_ALL,
                                    inVal, SIGVERSION_WITNESS_V0, nullptr);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(victimKey.Sign(sighash, sig));
    sig.push_back((unsigned char)SIGHASH_ALL);
    tx.vin[0].scriptWitness.stack.clear();
    tx.vin[0].scriptWitness.stack.push_back(sig);
    tx.vin[0].scriptWitness.stack.push_back(Prefixed(victimPkBytes));

    std::vector<CMutableTransaction> txns{ tx };
    CBlock b = CreateAndProcessBlock(txns, victimSpk);
    BOOST_CHECK_MESSAGE(chainActive.Tip()->GetBlockHash() == b.GetHash(),
        "SOQ-I009 broke ordinary signed spending");
}

BOOST_AUTO_TEST_SUITE_END()
