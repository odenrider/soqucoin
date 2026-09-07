// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// witness_version_reservation_tests.cpp — the witness-version CREATION posture
// at consensus, after the additive-asset genesis door (2026-09).
//
// The posture is BIP141's: an output of any witness version except v2 may be
// created in a block. A dormant version is anyone-can-spend at the script
// layer and non-standard at the relay layer, and its activation only ADDS the
// requirement that the spend verify — which is what makes every activation a
// SOFT fork. Until 2026-09 this file pinned the opposite (SOQ-I009: every
// dormant version consensus-reserved), which closed a fund-and-sweep hazard
// at the price of making every activation a hard fork. The hazard is bounded
// instead by the relay layer (policy.cpp gates v2-v16 on the live activation
// mask; witness_standardness_tests) and by the fact that no wallet path can
// construct a non-v1 address (utiladdress.cpp DecodeDestination).
//
// What this file pins, in order:
//   1. only v2 is reserved; every other version is creatable while dormant;
//   2. the STEAL: a dormant-version output is swept with a garbage witness and
//      the sweep CONNECTS. Expected. It is the price of soft-forkability, and
//      it is why (3) and (4) are the only defences;
//   3. the same output is non-standard, so it never relays;
//   4. ACTIVATION TIGHTENS: the identical garbage sweep is rejected once the
//      version's deployment is active. That is the soft-fork property as a test;
//   5. the premise of the additive asset design: no asset-shaped output (v7,
//      v8, v10) can hold SOQ value before its deployment activates — the
//      per-asset conservation rule catches the non-coinbase path and
//      CheckTransaction's coinbase bans catch the coinbase path. This is what
//      lets the activation release mandate nValue == 0 on asset outputs without
//      relaxing any rule the genesis binary carries;
//   6. a reorg over a block that CONTAINS dormant asset shapes must not touch
//      asset state (supply, authority outpoint, freeze registry), because
//      ConnectBlock never applied any: the undo mirrors are gated on the
//      deployment exactly as the apply side is.
//
// Regtest runs USDSOQ, BTCSOQ and P2WSH-Dilithium active from height 0, so
// each case withdraws the deployment it needs dormant rather than relying on
// the network default; SoquObscura and LatticeFold are dormant everywhere.

#include "consensus/btcsoq.h"
#include "consensus/merkle.h"
#include "consensus/params.h"
#include "consensus/usdsoq.h"
#include "consensus/privacy.h"
#include "policy/policy.h"
#include "test/dilithium_chain_setup.h"
#include "test/testutil.h"   // ScopedRegtestActivation
#include "txdb.h"

#include <boost/test/unit_test.hpp>

namespace {

//! Withdraw a deployment for the duration of a scope (the inverse of
//! ScopedRegtestActivation, which only turns things ON).
struct ScopedRegtestWithdrawal {
    Consensus::DeploymentPos pos;
    int restore;
    ScopedRegtestWithdrawal(Consensus::DeploymentPos p, int restoreHeight)
        : pos(p), restore(restoreHeight)
    {
        UpdateRegtestActivationHeight(pos, Consensus::BIP9Deployment::NOT_SCHEDULED);
        SelectParams(CBaseChainParams::REGTEST);
    }
    ~ScopedRegtestWithdrawal()
    {
        UpdateRegtestActivationHeight(pos, restore);
        SelectParams(CBaseChainParams::REGTEST);
    }
};

//! A 0x00-prefixed blob: satisfies CheckTransaction's pubkey-prefix shape test
//! (bad-txns-requires-dilithium) and nothing else. The point of the steal.
std::vector<unsigned char> GarbageWitnessItem()
{
    std::vector<unsigned char> v(33, 0x5a);
    v[0] = 0x00;
    return v;
}

} // namespace

struct WitnessReservationSetup : public DilithiumChainSetup {
    // A minimal correctly-signed spend of `cb` paying everything to `destSpk`.
    // The signature is valid, so any rejection is about the OUTPUT SHAPE alone.
    CMutableTransaction SpendTo(const CTransaction& cb, const CScript& destSpk)
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
        out.scriptPubKey = destSpk;
        tx.vout.push_back(out);
        SignInput(tx, 0, coinbaseSpk, inVal);
        return tx;
    }

    // Spend `funding`'s single output back to a v1 form with a witness that
    // proves nothing: one 0x00-prefixed blob. Connects iff the funded version
    // is anyone-can-spend right now.
    CMutableTransaction GarbageSweep(const CTransaction& funding)
    {
        CMutableTransaction tx;
        tx.nVersion = 2;
        CTxIn in;
        in.prevout = COutPoint(funding.GetHash(), 0);
        in.nSequence = CTxIn::SEQUENCE_FINAL;
        in.scriptWitness.stack.push_back(GarbageWitnessItem());
        tx.vin.push_back(in);
        CTxOut out;
        out.nValue = funding.vout[0].nValue - 10000;
        out.scriptPubKey = Spk(OP_1);
        tx.vout.push_back(out);
        return tx;
    }

    // Connect a block carrying `tx` and require that it became the tip.
    void Connect(const CMutableTransaction& tx)
    {
        const int before = chainActive.Height();
        CBlock b = CreateAndProcessBlock({tx}, coinbaseSpk);
        BOOST_REQUIRE_MESSAGE(chainActive.Height() == before + 1 &&
                              chainActive.Tip()->GetBlockHash() == b.GetHash(),
            "funding block did not connect");
    }

    // Reject reason for a block whose COINBASE pays to `spk` (empty if valid).
    // CreateNewBlock validates its own template and returns nullptr for a
    // coinbase CheckTransaction rejects, so the block is solved for the normal
    // coinbase first and the coinbase output is rewritten afterwards. Only the
    // coinbase txid changes (its witness hash is zero by convention, so the
    // witness commitment stays valid); the merkle root and PoW are redone.
    std::string CoinbaseRejectReason(const CScript& spk)
    {
        CBlock B = BuildSolvedBlock({}, coinbaseSpk);
        {
            CMutableTransaction cb(*B.vtx[0]);
            cb.vout[0].scriptPubKey = spk;
            B.vtx[0] = MakeTransactionRef(std::move(cb));
        }
        B.hashMerkleRoot = BlockMerkleRoot(B);
        const CChainParams& cp = Params();
        B.nNonce = 0;
        while (!CheckProofOfWork(B.GetPoWHash(), B.nBits, cp.GetConsensus(0)))
            ++B.nNonce;
        CValidationState st;
        bool ok;
        {
            LOCK(cs_main);
            ok = TestBlockValidity(st, Params(), B, chainActive.Tip(), true, true);
        }
        return ok ? std::string() : st.GetRejectReason();
    }
};

BOOST_FIXTURE_TEST_SUITE(witness_version_reservation_tests, WitnessReservationSetup)

// ---------------------------------------------------------------------------
// 1. Only v2 is reserved.
// ---------------------------------------------------------------------------

// ⛔ THE STEAL TEST for witness v2 (PAT). Bead pat-v2-anyone-can-spend-ae6u.
//
// DEPLOYMENT_CHECKPATAGG is ALWAYS_ACTIVE on every network, and the v2 spend
// path binds neither the witness program nor the sighash (the spend itself is
// driven in pat_v2_unfundable_tests.cpp, PIN 1), so a stranger could sweep any
// v2 output that confirmed. Unfundability is therefore the control, and it is
// UNCONDITIONAL rather than deployment-gated. This test asserts the deployment
// is active first: if the rejection ever starts depending on dormancy, the
// guarantee has silently weakened to the one that already failed.
BOOST_AUTO_TEST_CASE(v2_output_unfundable_even_though_checkpatagg_is_active)
{
    const int h = chainActive.Height() + 1;
    const auto& dep = Params().GetConsensus(h).vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG];
    BOOST_REQUIRE_MESSAGE(dep.nStartTime == Consensus::BIP9Deployment::ALWAYS_ACTIVE,
        "DEPLOYMENT_CHECKPATAGG is no longer ALWAYS_ACTIVE on regtest, so this test "
        "would now be proving dormancy rather than unconditional unfundability. Read "
        "bead pat-v2-anyone-can-spend-ae6u before changing it.");

    CMutableTransaction tx = SpendTo(coinbaseTxns[0], Spk(OP_2));
    BOOST_CHECK_EQUAL(RejectReasonFor({tx}), "bad-txns-witness-version-not-active");
}

// Every other version is creatable while its deployment is dormant. Each row
// withdraws the deployment regtest runs active (or asserts the version has no
// active deployment to withdraw), then connects a correctly-signed spend into
// that shape. A rejection here would mean a consensus rule keyed on the shape
// survived the door, and every such rule is a future hard fork.
BOOST_AUTO_TEST_CASE(every_version_but_v2_is_creatable_while_dormant)
{
    struct Row { opcodetype op; const char* name; int deployment; };
    // deployment == -1: no deployment to withdraw (dormant on regtest already,
    // or unallocated).
    const Row rows[] = {
        { OP_3,  "v3 LatticeFold (retired)",     -1 },
        { OP_4,  "v4 confidential SOQ",          -1 },
        { OP_5,  "v5 USDSOQ authority marker",   Consensus::DEPLOYMENT_USDSOQ },
        { OP_6,  "v6 P2WSH-Dilithium",           Consensus::DEPLOYMENT_P2WSH_DILITHIUM },
        { OP_9,  "v9 BTCSOQ authority marker",   Consensus::DEPLOYMENT_BTCSOQ },
        { OP_11, "v11 unallocated",              -1 },
        { OP_12, "v12 unallocated",              -1 },
        { OP_13, "v13 unallocated",              -1 },
        { OP_14, "v14 unallocated",              -1 },
        { OP_15, "v15 unallocated",              -1 },
        { OP_16, "v16 unallocated",              -1 },
    };
    int cbIdx = 1;
    for (const Row& r : rows) {
        std::unique_ptr<ScopedRegtestWithdrawal> off;
        if (r.deployment >= 0)
            off.reset(new ScopedRegtestWithdrawal((Consensus::DeploymentPos)r.deployment, 0));
        const int h = chainActive.Height() + 1;
        const Consensus::Params& cons = Params().GetConsensus(h);
        if (r.deployment >= 0) {
            BOOST_REQUIRE(!Consensus::DeploymentActiveAtHeight(h, cons, (Consensus::DeploymentPos)r.deployment));
        }
        CMutableTransaction tx = SpendTo(coinbaseTxns[cbIdx++], Spk(r.op));
        BOOST_CHECK_MESSAGE(RejectReasonFor({tx}).empty(),
            r.name << " output must be consensus-valid to create while dormant; a rejection "
            "keyed on this shape makes the version's activation a hard fork");
    }
    // Sanity: LatticeFold and SoquObscura really are dormant on regtest, so the
    // v3/v4 rows above tested dormancy and not an active deployment.
    const int h = chainActive.Height() + 1;
    const Consensus::Params& cons = Params().GetConsensus(h);
    BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(h, cons, Consensus::DEPLOYMENT_LATTICEFOLD));
    BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(h, cons, Consensus::DEPLOYMENT_SOQUOBSCURA));
}

// The base forms must stay unconditionally constructable — this rule must never
// be able to brick ordinary spending.
BOOST_AUTO_TEST_CASE(v1_base_form_always_constructable)
{
    CMutableTransaction tx = SpendTo(coinbaseTxns[13], Spk(OP_1));
    BOOST_CHECK_MESSAGE(RejectReasonFor({tx}).empty(),
        "v1 Dilithium outputs must never be gated");
}

// ---------------------------------------------------------------------------
// 2-4. The steal, the relay refusal, and activation as a tightening.
// ---------------------------------------------------------------------------

// For each dormant version: fund it for real, then sweep it with a witness
// that proves nothing.
//   (2) the sweep CONNECTS while dormant — expected, and the reason the next
//       two assertions are the only defences;
//   (3) the funding tx is NON-STANDARD with the live (empty) activation mask,
//       and standard with the version's bit set where Solver names the form;
//   (4) with the deployment active, the identical sweep is REJECTED. Nothing
//       that the active rules accept was rejected while dormant, and this
//       sweep is something they reject that was accepted: activation only
//       tightens. (Rejection is asserted as "block invalid" rather than by
//       reject string because it comes from script verification, which
//       ConnectBlock reports with an empty reason; any other active-state
//       rejection would also satisfy the tightening property.)
BOOST_AUTO_TEST_CASE(dormant_output_is_anyone_can_spend_nonstandard_and_activation_tightens)
{
    struct Row { opcodetype op; int version; const char* name; int deployment; bool solverNames; };
    const Row rows[] = {
        { OP_4,  4,  "v4 confidential SOQ",        Consensus::DEPLOYMENT_SOQUOBSCURA,      false },
        { OP_5,  5,  "v5 USDSOQ authority marker", Consensus::DEPLOYMENT_USDSOQ,           true  },
        { OP_6,  6,  "v6 P2WSH-Dilithium",         Consensus::DEPLOYMENT_P2WSH_DILITHIUM,  true  },
        { OP_9,  9,  "v9 BTCSOQ authority marker", Consensus::DEPLOYMENT_BTCSOQ,           true  },
        { OP_11, 11, "v11 unallocated",            -1,                                     false },
    };
    int cbIdx = 20;
    for (const Row& r : rows) {
        CMutableTransaction sweep;
        {
            // SoquObscura is dormant on regtest already; the others must be
            // withdrawn for the funding and the steal.
            std::unique_ptr<ScopedRegtestWithdrawal> off;
            if (r.deployment >= 0 && r.deployment != Consensus::DEPLOYMENT_SOQUOBSCURA)
                off.reset(new ScopedRegtestWithdrawal((Consensus::DeploymentPos)r.deployment, 0));

            CMutableTransaction fund = SpendTo(coinbaseTxns[cbIdx++], Spk(r.op));

            // (3) relay refuses the shape while dormant.
            std::string reason;
            BOOST_CHECK_MESSAGE(!IsStandardTx(CTransaction(fund), reason, true, 0) && reason == "scriptpubkey",
                r.name << " funding tx must be non-standard while dormant (got '" << reason << "')");
            if (r.solverNames) {
                BOOST_CHECK_MESSAGE(IsStandardTx(CTransaction(fund), reason, true, WitnessVersionBit(r.version)),
                    r.name << " funding tx must be standard once its version bit is active");
            }

            Connect(fund);
            sweep = GarbageSweep(CTransaction(fund));

            // (2) THE STEAL. Connects while dormant.
            BOOST_CHECK_MESSAGE(BlockIsValid({sweep}),
                r.name << ": a garbage-witness sweep must connect while the version is dormant. "
                "If this fails, some rule verifies a dormant version's spend, which means the "
                "version was never anyone-can-spend and its activation was never a soft fork.");
        }

        // (4) ACTIVATION TIGHTENS. Same UTXO, same sweep, deployment active.
        if (r.deployment >= 0) {
            std::unique_ptr<ScopedRegtestActivation> on;
            if (r.deployment == Consensus::DEPLOYMENT_SOQUOBSCURA)
                on.reset(new ScopedRegtestActivation(Consensus::DEPLOYMENT_SOQUOBSCURA, 0));
            const int h = chainActive.Height() + 1;
            BOOST_REQUIRE(Consensus::DeploymentActiveAtHeight(h, Params().GetConsensus(h),
                                                              (Consensus::DeploymentPos)r.deployment));
            BOOST_CHECK_MESSAGE(!BlockIsValid({sweep}),
                r.name << ": the garbage sweep must be REJECTED once the deployment is active. "
                "If it still connects, activating the deployment enforces nothing on this version.");
        }
    }
}

// ---------------------------------------------------------------------------
// 5. The premise of the additive asset design: asset shapes cannot hold value
//    before activation, on either path.
// ---------------------------------------------------------------------------

// Non-coinbase path: the per-asset conservation rule in Consensus::CheckTxInputs
// rejects SOQ paid into a v7/v8/v10 output (asset out > asset in = 0). These
// rules are unconditional and stay in the genesis binary; the activation
// release satisfies them trivially by mandating nValue == 0 on asset outputs.
BOOST_AUTO_TEST_CASE(asset_holdings_cannot_hold_value_before_activation)
{
    {
        ScopedRegtestWithdrawal off(Consensus::DEPLOYMENT_USDSOQ, 0);
        CMutableTransaction v7  = SpendTo(coinbaseTxns[30], Spk(OP_7));
        CMutableTransaction v10 = SpendTo(coinbaseTxns[31], Spk(OP_10));
        BOOST_CHECK_EQUAL(RejectReasonFor({v7}),  "bad-txns-usdsoq-not-conserved");
        BOOST_CHECK_EQUAL(RejectReasonFor({v10}), "bad-txns-usdsoq-not-conserved");
    }
    {
        ScopedRegtestWithdrawal off(Consensus::DEPLOYMENT_BTCSOQ, 0);
        CMutableTransaction v8 = SpendTo(coinbaseTxns[32], Spk(OP_8));
        BOOST_CHECK_EQUAL(RejectReasonFor({v8}), "bad-txns-btcsoq-not-conserved");
    }
}

// Coinbase path: CheckTransaction bans asset holdings and the BTCSOQ marker in
// a coinbase, unconditionally. A coinbase is the one transaction the
// conservation rule does not see, so without these bans a miner could create a
// valued asset-shaped output while the deployment is dormant. v10 is covered
// by the same ban as v7 (IsAnyUSDSOQ), which is the part this PR added.
BOOST_AUTO_TEST_CASE(coinbase_cannot_create_asset_shapes)
{
    ScopedRegtestWithdrawal offU(Consensus::DEPLOYMENT_USDSOQ, 0);
    ScopedRegtestWithdrawal offB(Consensus::DEPLOYMENT_BTCSOQ, 0);
    BOOST_CHECK_EQUAL(CoinbaseRejectReason(Spk(OP_7)),  "bad-cb-usdsoq-asset");
    BOOST_CHECK_EQUAL(CoinbaseRejectReason(Spk(OP_10)), "bad-cb-usdsoq-asset");
    BOOST_CHECK_EQUAL(CoinbaseRejectReason(Spk(OP_8)),  "bad-cb-btcsoq-asset");
    BOOST_CHECK_EQUAL(CoinbaseRejectReason(Spk(OP_9)),  "bad-cb-btcsoq-asset");
    // Control: the ban is about asset shapes, not about non-v1 coinbases.
    BOOST_CHECK_EQUAL(CoinbaseRejectReason(Spk(OP_1)), "");
}

// ---------------------------------------------------------------------------
// 5b. The activation release's authority-transaction SHAPE is valid in the
//     genesis binary while dormant.
// ---------------------------------------------------------------------------

// Under the additive design an authority transaction spends the previous
// marker output, carries the M-of-N signatures in THAT input's witness, and
// creates the next marker. The genesis binary must ACCEPT that shape while the
// deployment is dormant (marker input anyone-can-spend, ordinary verification
// for everything else), so that the activation release's M-of-N requirement is
// a pure tightening. Until 2026-09 CheckInputs rejected this exact shape while
// dormant ("bad-*-authority-not-active"), which would have made the asset
// activation a hard fork. The witness below is authority-SHAPED (6 items, tag
// at [2], a 2420-byte item) but proves nothing; the marker input is
// anyone-can-spend, so it connects. The same tx spending a v1 input with that
// witness is rejected by ordinary script verification (authority_skip_gate_tests).
BOOST_AUTO_TEST_CASE(dormant_authority_shape_spending_a_marker_input_connects)
{
    struct Row { opcodetype op; unsigned char tag; int deployment; const char* name; };
    const Row rows[] = {
        { OP_5, 0x55,           Consensus::DEPLOYMENT_USDSOQ, "USDSOQ" },
        { OP_9, BTCSOQ_OP_MINT, Consensus::DEPLOYMENT_BTCSOQ, "BTCSOQ" },
    };
    int cbIdx = 40;
    for (const Row& r : rows) {
        ScopedRegtestWithdrawal off((Consensus::DeploymentPos)r.deployment, 0);

        CMutableTransaction fund = SpendTo(coinbaseTxns[cbIdx++], Spk(r.op));
        Connect(fund);
        const CTransaction funded(fund);

        CMutableTransaction auth;
        auth.nVersion = 2;
        CTxIn in;
        in.prevout = COutPoint(funded.GetHash(), 0);
        in.nSequence = CTxIn::SEQUENCE_FINAL;
        // [0] payout_sig [1] payout_pk [2] tag [3] payload [4] auth_sig [5] authority_set
        in.scriptWitness.stack.push_back(std::vector<unsigned char>(2421, 0x01));
        in.scriptWitness.stack.push_back(std::vector<unsigned char>(1313, 0x00));
        in.scriptWitness.stack.push_back(std::vector<unsigned char>(1, r.tag));
        in.scriptWitness.stack.push_back(std::vector<unsigned char>(32, 0x02));
        in.scriptWitness.stack.push_back(std::vector<unsigned char>(2420, 0x03));
        // CheckTransaction requires the LAST witness item of every input to be
        // 0x00-prefixed (bad-txns-requires-dilithium) unless the tx carries the
        // OP_5 marker exemption. The USDSOQ row is exempt (OP_5 output plus an
        // authority-shaped witness); the BTCSOQ row is NOT, so its last item
        // must be 0x00-prefixed or the genesis binary rejects the shape. That
        // rule is one the genesis binary keeps forever, so the activation
        // release's authority_set item must be 0x00-prefixed
        // (WITNESS_VERSION_FORK_CLASS.md §4.8).
        std::vector<unsigned char> authoritySet(64, 0x04);
        authoritySet[0] = 0x00;
        in.scriptWitness.stack.push_back(authoritySet);
        auth.vin.push_back(in);
        CTxOut nextMarker;
        nextMarker.nValue = funded.vout[0].nValue - 10000;
        nextMarker.scriptPubKey = Spk(r.op);
        auth.vout.push_back(nextMarker);

        BOOST_CHECK_MESSAGE(RejectReasonFor({auth}).empty() && BlockIsValid({auth}),
            r.name << ": an authority-SHAPED spend of a dormant marker input must connect in the "
            "genesis binary. A rejection here is a rule the activation release must relax, "
            "i.e. a hard fork.");
    }
}

// ---------------------------------------------------------------------------
// 6. Reorg over dormant asset shapes leaves asset state untouched.
// ---------------------------------------------------------------------------

// THE ATTACK: while BTCSOQ is dormant, a block carries a raw transaction with
// a v9 marker output and a well-formed BTCSOQ FREEZE envelope (UNFREEZE of an
// arbitrary outpoint). ConnectBlock applies nothing (its BTCSOQ block is
// gated). Before the undo mirrors were gated the same way, disconnecting that
// block REVERSED the op it never applied: the registry gained a phantom
// freeze on the target, and the tracked authority outpoint was overwritten.
// A phantom freeze is a griefing write against a future asset holder.
BOOST_AUTO_TEST_CASE(reorg_over_dormant_asset_shapes_does_not_touch_asset_state)
{
    ScopedRegtestWithdrawal off(Consensus::DEPLOYMENT_BTCSOQ, 0);

    const COutPoint target(uint256S("0x00000000000000000000000000000000000000000000000000000000deadbeef"), 7);
    const COutPoint sentinel(uint256S("0x0000000000000000000000000000000000000000000000000000000000c0ffee"), 3);

    // [tag 0x63][freeze_op 0x01 = UNFREEZE][txid 32][vout 4] = 38-byte push.
    std::vector<unsigned char> envelope;
    envelope.push_back(BTCSOQ_OP_FREEZE);
    envelope.push_back(FREEZE_OP_UNFREEZE);
    envelope.insert(envelope.end(), target.hash.begin(), target.hash.end());
    for (int i = 0; i < 4; i++) envelope.push_back((target.n >> (8 * i)) & 0xff);
    BOOST_REQUIRE_EQUAL(envelope.size(), 38u);

    const CTransaction& cb = coinbaseTxns[35];
    const CAmount inVal = cb.vout[0].nValue;
    CMutableTransaction tx;
    tx.nVersion = 2;
    CTxIn in; in.prevout = COutPoint(cb.GetHash(), 0); in.nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vin.push_back(in);
    CTxOut marker; marker.nValue = inVal - 10000; marker.scriptPubKey = Spk(OP_9);
    tx.vout.push_back(marker);
    CTxOut op; op.nValue = 0; op.scriptPubKey = CScript() << OP_RETURN << envelope;
    tx.vout.push_back(op);
    SignInput(tx, 0, coinbaseSpk, inVal);

    {
        uint8_t tag; std::vector<uint8_t> payload;
        BOOST_REQUIRE_MESSAGE(ParseBTCSOQAuthorityOp(CTransaction(tx), tag, payload) && tag == BTCSOQ_OP_FREEZE,
            "the envelope must parse as a BTCSOQ freeze op, or the attack is not being exercised");
    }

    BOOST_REQUIRE(!pcoinsdbview->IsBTCSOQFrozen(target));
    {
        LOCK(cs_main);
        g_btcsoq_authority_outpoint = sentinel;
    }

    Connect(tx);
    const int tipHeight = chainActive.Height();

    {
        LOCK(cs_main);
        CValidationState st;
        BOOST_REQUIRE(InvalidateBlock(st, Params(), chainActive.Tip()));
    }
    BOOST_REQUIRE_EQUAL(chainActive.Height(), tipHeight - 1);

    BOOST_CHECK_MESSAGE(!pcoinsdbview->IsBTCSOQFrozen(target),
        "disconnecting a block that carried a dormant BTCSOQ envelope wrote a phantom freeze: "
        "the undo path reversed an op ConnectBlock never applied");
    BOOST_CHECK_MESSAGE(g_btcsoq_authority_outpoint == sentinel,
        "disconnecting a block that carried a dormant v9 marker overwrote the tracked "
        "authority outpoint: the undo path restored state ConnectBlock never advanced");

    LOCK(cs_main);
    g_btcsoq_authority_outpoint = COutPoint();   // do not leak into the next suite
}

// The USDSOQ twin. Regtest's USDSOQ freeze-reversal path is height-gated
// (nUSDSOQAuthorityEnforcementHeight = 7700) and the supply path needs a v7
// output with value, which conservation forbids; the authority-outpoint
// reversal has neither guard. Before the undo gate, disconnecting a block with
// a v5-marker-shaped tx that spends no marker input reverted the tracked
// outpoint to null ("bootstrap disconnected") while USDSOQ was dormant.
BOOST_AUTO_TEST_CASE(reorg_over_dormant_usdsoq_marker_does_not_touch_authority_outpoint)
{
    ScopedRegtestWithdrawal off(Consensus::DEPLOYMENT_USDSOQ, 0);
    const COutPoint sentinel(uint256S("0x0000000000000000000000000000000000000000000000000000000000c0ffee"), 5);

    CMutableTransaction tx = SpendTo(coinbaseTxns[36], Spk(OP_5));
    {
        LOCK(cs_main);
        g_usdsoq_authority_outpoint = sentinel;
    }
    Connect(tx);
    const int tipHeight = chainActive.Height();
    {
        LOCK(cs_main);
        CValidationState st;
        BOOST_REQUIRE(InvalidateBlock(st, Params(), chainActive.Tip()));
    }
    BOOST_REQUIRE_EQUAL(chainActive.Height(), tipHeight - 1);
    BOOST_CHECK_MESSAGE(g_usdsoq_authority_outpoint == sentinel,
        "disconnecting a block that carried a dormant v5 marker overwrote the tracked USDSOQ "
        "authority outpoint: the undo path restored state ConnectBlock never advanced");

    LOCK(cs_main);
    g_usdsoq_authority_outpoint = COutPoint();
}

// The SoquObscura twin. ConnectBlock writes key images only while the
// deployment is active; the undo path erases the key image derived from the
// last witness item of every spend of a confidential-shaped input. Before the
// gate, disconnecting a block that spent a dormant v4 output with a garbage
// witness erased whatever key image that garbage happened to hash to. Seed
// that hash first so the erasure is observable.
BOOST_AUTO_TEST_CASE(reorg_over_dormant_confidential_spend_does_not_touch_key_images)
{
    const int h = chainActive.Height() + 1;
    BOOST_REQUIRE(!Consensus::DeploymentActiveAtHeight(h, Params().GetConsensus(h),
                                                       Consensus::DEPLOYMENT_SOQUOBSCURA));

    CMutableTransaction fund = SpendTo(coinbaseTxns[37], Spk(OP_4));
    Connect(fund);
    CMutableTransaction sweep = GarbageSweep(CTransaction(fund));
    const LatticeKeyImageHash kiHash =
        LatticeKeyImageHash::FromSerializedKeyImage(sweep.vin[0].scriptWitness.stack.back());
    BOOST_REQUIRE(pcoinsdbview->WriteKeyImage(kiHash.hash, 1));
    BOOST_REQUIRE(pcoinsdbview->HaveKeyImage(kiHash.hash));

    Connect(sweep);
    const int tipHeight = chainActive.Height();
    {
        LOCK(cs_main);
        CValidationState st;
        BOOST_REQUIRE(InvalidateBlock(st, Params(), chainActive.Tip()));
    }
    BOOST_REQUIRE_EQUAL(chainActive.Height(), tipHeight - 1);
    BOOST_CHECK_MESSAGE(pcoinsdbview->HaveKeyImage(kiHash.hash),
        "disconnecting a block that spent a dormant v4 output erased a key image: the undo "
        "path reversed a write ConnectBlock never made");

    pcoinsdbview->EraseKeyImage(kiHash.hash);   // do not leak into the next suite
}

BOOST_AUTO_TEST_SUITE_END()
