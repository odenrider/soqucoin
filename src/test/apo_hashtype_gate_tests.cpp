// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// apo_hashtype_gate_tests.cpp — SOQ-I010. DEPLOYMENT_APO must actually gate
// SIGHASH_ANYPREVOUT (0x41) and SIGHASH_ANYPREVOUTANYSCRIPT (0x42).
//
// SignatureHash() has computed BIP 118 sighashes unconditionally since June
// 2026, and TransactionSignatureChecker::CheckSig() never receives `flags`, so
// the deployment gated nothing at consensus. The comment left at CheckSig
// argued this was safe because "the policy layer is the correct and sufficient
// gate" and "STANDARD_SCRIPT_VERIFY_FLAGS now includes SCRIPT_VERIFY_APO".
// The second claim is false: policy.h deliberately OMITS APO from
// STANDARD_SCRIPT_VERIFY_FLAGS (SOQ-COV-012), and the ATMP block mirrors the
// deployment instead. So the stated gate did not exist in the place claimed,
// and APO semantics were live on mainnet from genesis with the deployment off.
//
// Nobody could steal with it — only the key holder can produce an APO signature
// — but an APO signature is replayable across any UTXO paying the same
// scriptPubKey, and address reuse is ordinary. More to the point, activating
// APO would have been a no-op, so the Halborn Phase 2 sighash review would have
// been gating a feature that was already enforced.

#include "consensus/params.h"
#include "test/dilithium_chain_setup.h"

#include <boost/test/unit_test.hpp>

namespace {

struct ScopedApoWithdrawal {
    ScopedApoWithdrawal()
    {
        UpdateRegtestActivationHeight(Consensus::DEPLOYMENT_APO,
                                      Consensus::BIP9Deployment::NOT_SCHEDULED);
        SelectParams(CBaseChainParams::REGTEST);
    }
    ~ScopedApoWithdrawal()
    {
        UpdateRegtestActivationHeight(Consensus::DEPLOYMENT_APO, 0);
        SelectParams(CBaseChainParams::REGTEST);
    }
};

} // namespace

struct ApoGateSetup : public DilithiumChainSetup {
    // A v1 Dilithium spend signed with an arbitrary sighash type. Everything
    // except the hash type is a perfectly ordinary, valid transaction.
    CMutableTransaction SpendWithHashType(const CTransaction& cb, int nHashType)
    {
        const CAmount inVal = cb.vout[0].nValue;
        CMutableTransaction tx;
        tx.nVersion = 2;
        CTxIn in;
        in.prevout = COutPoint(cb.GetHash(), 0);
        in.nSequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.push_back(in);
        CTxOut out;
        out.nValue = inVal - 10000;
        out.scriptPubKey = coinbaseSpk;
        tx.vout.push_back(out);

        CTransaction ctxForSign(tx);
        uint256 sighash = SignatureHash(coinbaseSpk, ctxForSign, 0, nHashType,
                                        inVal, SIGVERSION_WITNESS_V0, nullptr);
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(coinbaseKey.Sign(sighash, sig));
        sig.push_back((unsigned char)nHashType);
        tx.vin[0].scriptWitness.stack.clear();
        tx.vin[0].scriptWitness.stack.push_back(sig);
        tx.vin[0].scriptWitness.stack.push_back(PrefixedPubkey(coinbasePkBytes));
        return tx;
    }
};

BOOST_FIXTURE_TEST_SUITE(apo_hashtype_gate_tests, ApoGateSetup)

// THE TRAP THIS PINS (bead mpu9, ruled 2026-09-08). Until 2026-09-08 this case
// asserted the OPPOSITE — that an APO-signed v1 spend CONNECTS while
// DEPLOYMENT_APO is active. That behaviour is what made activating APO a HARD
// FORK: v1 is active from genesis, so the genesis binary rejects this spend,
// and a release that accepts it accepts a block the genesis binary rejects.
// Flag-day scheduling does not change that; only direction does.
//
// The rejection on the single-key path is now UNCONDITIONAL. APO reaches the
// chain only inside witness v6, through OP_CHECKDILITHIUMKEYHASH, which is
// NOP-when-clear and therefore soft-fork activatable (covenant_tests,
// dilithium_keyhash_committed_tests, keyhash_broadcast_tests,
// lightning_script_tests cover that path; eLTOO channel outputs are v6, see
// src/stagenet-eltoo.cpp MakeV6Spk).
//
// Regtest activates APO at height 0, so this runs with the deployment ACTIVE.
// That is the point: the flag must not be able to open this path.
BOOST_AUTO_TEST_CASE(apo_rejected_on_single_key_path_even_when_deployment_active)
{
    const int h = chainActive.Height() + 1;
    BOOST_REQUIRE_MESSAGE(Consensus::DeploymentActiveAtHeight(
        h, Params().GetConsensus(h), Consensus::DEPLOYMENT_APO),
        "regtest must have DEPLOYMENT_APO active, or this proves nothing");

    CMutableTransaction apo = SpendWithHashType(coinbaseTxns[0], SIGHASH_ANYPREVOUT);
    BOOST_CHECK_MESSAGE(!BlockIsValid({apo}),
        "SIGHASH_ANYPREVOUT was honoured on the v1 single-key path with "
        "DEPLOYMENT_APO ACTIVE — the flag can still open a path the genesis "
        "binary rejects, which is a hard fork (bead mpu9)");

    CMutableTransaction apoas = SpendWithHashType(coinbaseTxns[4], SIGHASH_ANYPREVOUTANYSCRIPT);
    BOOST_CHECK_MESSAGE(!BlockIsValid({apoas}),
        "SIGHASH_ANYPREVOUTANYSCRIPT was honoured on the v1 single-key path "
        "with DEPLOYMENT_APO ACTIVE");
}

// Positive control for the case above: with APO ACTIVE, the same harness and
// the same key produce a spend that CONNECTS when the hashtype is ordinary. So
// the rejections above are about the hashtype, not about a broken fixture.
BOOST_AUTO_TEST_CASE(single_key_path_still_spends_with_an_ordinary_hashtype)
{
    CMutableTransaction tx = SpendWithHashType(coinbaseTxns[5], SIGHASH_ALL);
    BOOST_CHECK_MESSAGE(BlockIsValid({tx}),
        "ordinary SIGHASH_ALL spending broke — the APO rejection is too wide");
}

// The gate. Same transaction, deployment withdrawn (mainnet's posture).
BOOST_AUTO_TEST_CASE(anyprevout_rejected_while_deployment_withdrawn)
{
    ScopedApoWithdrawal off;
    const int h = chainActive.Height() + 1;
    BOOST_REQUIRE(!Consensus::DeploymentActiveAtHeight(
        h, Params().GetConsensus(h), Consensus::DEPLOYMENT_APO));
    CMutableTransaction tx = SpendWithHashType(coinbaseTxns[1], SIGHASH_ANYPREVOUT);
    BOOST_CHECK_MESSAGE(!BlockIsValid({tx}),
        "SIGHASH_ANYPREVOUT was honoured with DEPLOYMENT_APO withdrawn — the "
        "deployment flag does not gate the feature it names");
}

BOOST_AUTO_TEST_CASE(anyprevoutanyscript_rejected_while_deployment_withdrawn)
{
    ScopedApoWithdrawal off;
    CMutableTransaction tx = SpendWithHashType(coinbaseTxns[2], SIGHASH_ANYPREVOUTANYSCRIPT);
    BOOST_CHECK_MESSAGE(!BlockIsValid({tx}),
        "SIGHASH_ANYPREVOUTANYSCRIPT was honoured with DEPLOYMENT_APO withdrawn");
}

// The gate must be narrow: ordinary SIGHASH_ALL spending is unaffected by APO
// dormancy. This is the regression guard on the fix itself.
BOOST_AUTO_TEST_CASE(sighash_all_unaffected_by_apo_dormancy)
{
    ScopedApoWithdrawal off;
    CMutableTransaction tx = SpendWithHashType(coinbaseTxns[3], SIGHASH_ALL);
    BOOST_CHECK_MESSAGE(BlockIsValid({tx}),
        "withdrawing APO must not affect ordinary SIGHASH_ALL spending");
}

// Policy must agree with consensus, or an APO tx relays and can never be mined
// (accept-then-reject, the daf9fd85 template-stalling failure). APO is omitted
// from STANDARD_SCRIPT_VERIFY_FLAGS and OR-ed in by the ATMP block from the
// same DeploymentActiveAtHeight call ConnectBlock uses, so the two agree at
// off/off and on/on. Pinned because the stale CheckSig comment asserted the
// opposite arrangement.
BOOST_AUTO_TEST_CASE(apo_is_not_in_standard_flags)
{
    BOOST_CHECK_MESSAGE((STANDARD_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_APO) == 0,
        "SCRIPT_VERIFY_APO has entered STANDARD_SCRIPT_VERIFY_FLAGS. Consensus gates it "
        "on DEPLOYMENT_APO, so an unconditional policy flag makes the mempool accept "
        "APO transactions that mainnet consensus rejects — accept-then-reject. If APO "
        "activation is intended, change chainparams, not this flag set");
}

BOOST_AUTO_TEST_SUITE_END()
