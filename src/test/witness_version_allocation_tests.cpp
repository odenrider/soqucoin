// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// witness_version_allocation_tests.cpp — the witness-version allocation table,
// derived from script/interpreter.cpp and pinned across every layer that holds
// an opinion about it. Bead v7xm, fork-risk class F2.
//
// ⛔ DERIVE THE TABLE FROM interpreter.cpp, NEVER FROM A DESIGN DOCUMENT. That
// instruction is on the bead because it has already cost us once: confidential
// USDSOQ was allocated witness v6 while v6 was ALREADY P2WSH-Dilithium, and the
// two predicates were byte-for-byte identical. It was green in CI, because
// nothing compared the two layers. It moved to v10.
//
// FOUR LAYERS INDEPENDENTLY ENCODE THIS TABLE, and they can drift apart in
// silence because no single compilation unit sees more than one of them:
//
//   1. script/interpreter.cpp   VerifyScript's shape predicates and their flag
//                               gates. AUTHORITATIVE: this decides whether a
//                               coin can actually be spent.
//   2. script/standard.cpp      Solver's txnouttype. Decides whether an output
//                               has a name, which is a precondition for relay.
//   3. validation.cpp/policy.cpp  the activeWitnessVersions mask. Decides
//                               whether a NAMED version relays right now.
//   4. primitives/transaction.h asset/visibility predicates. Decides what a
//                               consensus rule in validation.cpp thinks the
//                               output IS.
//
// A version can be allocated in one and absent from another, and every such gap
// is a real behaviour with no test behind it. The tests below assert the whole
// grid rather than one row at a time, so any layer moving on its own fails here.
//
// Policy-side behaviour has its own suite (witness_standardness_tests.cpp). This
// one exists for the SCRIPT side and for the cross-layer agreement, which is
// where the v6 collision lived and where nothing was looking.

#include "policy/policy.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/standard.h"

#include "chainparams.h"
#include "consensus/params.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <string>
#include <utility>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(witness_version_allocation_tests, BasicTestingSetup)

namespace {

//! OP_<version> <32-byte push> — the canonical 34-byte Soqucoin witness program.
CScript Program(int version, size_t programLen = 32)
{
    CScript s;
    s << (version == 0 ? OP_0 : CScript::EncodeOP_N(version));
    s << std::vector<unsigned char>(programLen, 0x01);
    return s;
}

//! A transaction to spend into, so VerifyScript has a checker to work with.
CMutableTransaction SpendTx()
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    CTxIn in;
    in.prevout = COutPoint(uint256S("0x2222222222222222222222222222222222222222222222222222222222222222"), 0);
    in.nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vin.push_back(in);
    CTxOut o; o.nValue = 50 * COIN; o.scriptPubKey = CScript() << OP_TRUE;
    tx.vout.push_back(o);
    return tx;
}

//! Run VerifyScript against a witness program with the given flags and an
//! arbitrary (deliberately meaningless) witness. Returns the ScriptError.
ScriptError ScriptVerdict(const CScript& spk, unsigned int flags, size_t witnessItems = 2)
{
    CMutableTransaction spend = SpendTx();
    CTransaction ctx(spend);
    CScriptWitness w;
    for (size_t i = 0; i < witnessItems; ++i)
        w.stack.push_back(std::vector<unsigned char>(4, 0x00));
    ScriptError serr = SCRIPT_ERR_OK;
    TransactionSignatureChecker checker(&ctx, 0, 50 * COIN);
    VerifyScript(CScript(), spk, &w, flags, checker, &serr);
    return serr;
}

bool SolverNames(const CScript& spk, txnouttype& t)
{
    std::vector<std::vector<unsigned char> > sols;
    return Solver(spk, t, sols);
}

bool StandardWith(const CScript& spk, WitnessVersionMask mask)
{
    txnouttype t;
    return IsStandard(spk, t, /*witnessEnabled=*/true, mask);
}

//! One row of the table, transcribed from interpreter.cpp's predicates.
struct Row {
    int version;
    const char* predicate;      // the is_* variable in VerifyScript
    unsigned int gate;          // 0 = ungated
    bool anyoneCanSpendWhenOff; // soft-fork posture while the gate is clear
    bool solverNames;           // does Solver give the 34-byte form a name
};

//! ⛔ TRANSCRIBED FROM script/interpreter.cpp. If a predicate there changes, this
//! table must change with it and the assertions below will say so.
const Row TABLE[] = {
    //  v   predicate               gate                              acs-when-off  named
    {  0, "is_dilithium",           0,                                false,        true  },
    {  1, "is_dilithium",           0,                                false,        true  },
    {  2, "is_pat",                 SCRIPT_VERIFY_PAT,                true,         false },
    {  3, "is_latticefold",         SCRIPT_VERIFY_LATTICEFOLD,        true,         false },
    {  4, "is_latticebp_witness",   SCRIPT_VERIFY_SOQUOBSCURA,        true,         false },
    {  5, "is_usdsoq_witness",      SCRIPT_VERIFY_USDSOQ,             true,         true  },
    {  6, "is_p2wsh_dilithium",     SCRIPT_VERIFY_P2WSH_DILITHIUM,    true,         true  },
    {  7, "is_usdsoq_holding",      SCRIPT_VERIFY_USDSOQ,             true,         true  },
    {  8, "is_btcsoq_holding",      SCRIPT_VERIFY_BTCSOQ,             true,         true  },
    {  9, "is_btcsoq_authority",    SCRIPT_VERIFY_BTCSOQ,             true,         true  },
    // v10 is ALLOCATED (confidential USDSOQ) with a COMPOUND gate: both
    // deployments must be active (bead jzg0; interpreter.cpp is_confidential_usdsoq_witness).
    { 10, "is_confidential_usdsoq_witness",
          SCRIPT_VERIFY_USDSOQ | SCRIPT_VERIFY_SOQUOBSCURA,           true,         false },
    { 11, "is_future_witness",      0,                                true,         false },
    { 12, "is_future_witness",      0,                                true,         false },
    { 13, "is_future_witness",      0,                                true,         false },
    { 14, "is_future_witness",      0,                                true,         false },
    { 15, "is_future_witness",      0,                                true,         false },
    { 16, "is_future_witness",      0,                                true,         false },
};

} // namespace

// ---------------------------------------------------------------------------
// SCRIPT LAYER. Every gated version must be anyone-can-spend while its gate is
// clear. That is the soft-fork posture and it is deliberate; it is also exactly
// why relay policy must refuse them, which is the other half of the pair and is
// covered in witness_standardness_tests.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(gated_versions_are_anyone_can_spend_while_dormant)
{
    for (const Row& r : TABLE) {
        if (!r.anyoneCanSpendWhenOff) continue;
        const ScriptError serr = ScriptVerdict(Program(r.version), SCRIPT_VERIFY_WITNESS);
        BOOST_CHECK_MESSAGE(serr == SCRIPT_ERR_OK,
            "witness v" + std::to_string(r.version) + " (" + r.predicate + ") must be "
            "anyone-can-spend while its gate is clear, got ScriptError " + std::to_string((int)serr));
    }
}

// Turning a gate on must actually change that version's behaviour. If it does
// not, the branch is unreachable and the version is effectively still ungated —
// the defect class that produced don9 and n1vf on the validation side.
BOOST_AUTO_TEST_CASE(activating_a_gate_stops_the_version_being_anyone_can_spend)
{
    for (const Row& r : TABLE) {
        if (r.gate == 0) continue;
        const ScriptError serr = ScriptVerdict(Program(r.version), SCRIPT_VERIFY_WITNESS | r.gate);
        BOOST_CHECK_MESSAGE(serr != SCRIPT_ERR_OK,
            "witness v" + std::to_string(r.version) + " (" + r.predicate + ") still verified a "
            "meaningless witness with its gate SET. Its branch is unreachable, so the gate "
            "buys nothing and the version is anyone-can-spend in every state");
    }
}

// A gate must move only its own version. The v6 collision was two versions
// sharing one predicate; this is the generalised guard against that shape.
BOOST_AUTO_TEST_CASE(gates_do_not_leak_across_versions)
{
    for (const Row& gated : TABLE) {
        if (gated.gate == 0) continue;
        for (const Row& other : TABLE) {
            if (other.version == gated.version) continue;
            // Versions sharing any deployment flag by design (v5/v7 on USDSOQ,
            // v8/v9 on BTCSOQ, and v10 whose COMPOUND gate contains both the
            // USDSOQ and SOQUOBSCURA flags) are expected to move together.
            if ((other.gate & gated.gate) != 0) continue;
            if (!other.anyoneCanSpendWhenOff) continue;
            const ScriptError serr = ScriptVerdict(Program(other.version),
                                                   SCRIPT_VERIFY_WITNESS | gated.gate);
            BOOST_CHECK_MESSAGE(serr == SCRIPT_ERR_OK,
                "activating the gate for v" + std::to_string(gated.version) + " changed the "
                "verdict for v" + std::to_string(other.version) + ". Two versions are sharing a "
                "predicate, which is the v6 / P2WSH-Dilithium collision shape");
        }
    }
}

// v10's gate is COMPOUND: either flag alone must leave it dormant, and with
// both set it must fail CLOSED on the scaffolding error, because no
// confidential verifier ships before activation (SOQ-I011; Gate 0 ruling
// r0vn). The activation release replaces the reject with real verification,
// and this pin is the tripwire that makes that replacement deliberate.
BOOST_AUTO_TEST_CASE(v10_fails_closed_when_both_gates_are_active)
{
    BOOST_CHECK_EQUAL(ScriptVerdict(Program(10), SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_USDSOQ),
                      SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(ScriptVerdict(Program(10), SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_SOQUOBSCURA),
                      SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(ScriptVerdict(Program(10),
                          SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_USDSOQ | SCRIPT_VERIFY_SOQUOBSCURA),
                      SCRIPT_ERR_CONFIDENTIAL_USDSOQ_UNVERIFIED);
}

// Shapes outside the allocated forms must fail CLOSED at the script layer, not
// silently succeed. This is the property that makes an unallocated version safe
// to leave alone.
BOOST_AUTO_TEST_CASE(unallocated_shapes_fail_closed)
{
    // A 22-byte v1 program: right version, wrong program length.
    BOOST_CHECK_MESSAGE(
        ScriptVerdict(Program(1, 20), SCRIPT_VERIFY_WITNESS) == SCRIPT_ERR_DISALLOWED_CLASSICAL_CRYPTO,
        "a witness program of a length no allocated form uses must be rejected outright");

    // A bare push with no version opcode at all.
    CScript notWitness;
    notWitness << std::vector<unsigned char>(32, 0x01);
    BOOST_CHECK_MESSAGE(
        ScriptVerdict(notWitness, SCRIPT_VERIFY_WITNESS) == SCRIPT_ERR_DISALLOWED_CLASSICAL_CRYPTO,
        "a non-witness script must be rejected outright, not treated as a future version");
}

// ---------------------------------------------------------------------------
// CROSS-LAYER AGREEMENT. Each of these caught, or would have caught, a real
// divergence. They assert the CURRENT truth so that any layer moving alone is
// visible; where the current truth is itself a defect it is named as such and
// tracked on a bead, rather than being quietly encoded as correct.
// ---------------------------------------------------------------------------

// Solver's named set and the script layer's allocated set are NOT the same set,
// and the difference has consequences. v2, v3 and v4 are allocated in
// interpreter.cpp and unnamed by Solver, so they can never be relay-standard no
// matter what the activation mask says.
BOOST_AUTO_TEST_CASE(solver_named_set_matches_the_transcribed_table)
{
    for (const Row& r : TABLE) {
        txnouttype t;
        const bool named = SolverNames(Program(r.version), t);
        BOOST_CHECK_MESSAGE(named == r.solverNames,
            "Solver " + std::string(named ? "now names" : "no longer names") + " witness v" +
            std::to_string(r.version) + ", which the table does not expect. Naming a version is "
            "what makes it eligible for relay, so this is a policy change and needs to be a "
            "deliberate one");
    }
}

// ⚠️ THE MASK BITS FOR v2, v3 AND v4 ARE DEAD. validation.cpp computes them from
// DEPLOYMENT_CHECKPATAGG, DEPLOYMENT_LATTICEFOLD and DEPLOYMENT_SOQUOBSCURA, and
// IsStandard can never consult them, because Solver refuses those shapes first.
//
// The consequence is not cosmetic: when SoquObscura activates, a confidential v4
// output will be consensus-valid and still non-standard, so it cannot propagate
// through the mempool at all. The privacy layer would be switched on and unable
// to relay a single transaction. Same for PAT (v2) and LatticeFold (v3).
//
// Pinned here rather than fixed: teaching Solver a v4 form is a relay-policy
// change that belongs with the SoquObscura activation decision, not with a test
// sweep. Bead v7xm F2.
BOOST_AUTO_TEST_CASE(mask_bits_for_v2_v3_v4_cannot_affect_standardness)
{
    for (int v : {2, 3, 4}) {
        BOOST_CHECK_MESSAGE(!StandardWith(Program(v), WitnessVersionBit(v)),
            "witness v" + std::to_string(v) + " became standard once its own mask bit was set. "
            "If Solver has learned this form, the dead-mask-bit finding is resolved and this "
            "test should be updated rather than deleted");
    }
}

// The asset predicates in transaction.h must agree with the script layer about
// which opcode means what. This is the exact comparison nobody was making when
// confidential USDSOQ was given v6, a version P2WSH-Dilithium already owned.
BOOST_AUTO_TEST_CASE(asset_predicates_agree_with_the_script_layer)
{
    CTxOut out;
    out.nValue = 1 * COIN;

    struct Case { int version; bool usdsoq; bool btcsoq; bool confidential; bool nativeSOQ; };
    const Case cases[] = {
        //  v    IsUSDSOQ  IsBTCSOQ  IsConfidential  IsNativeSOQ
        {   1,   false,    false,    false,          true  },   // plain Dilithium
        {   4,   false,    false,    true,           true  },   // confidential SOQ, Tier B
        {   6,   false,    false,    false,          true  },   // P2WSH-Dilithium, NOT confidential USDSOQ
        {   7,   true,     false,    false,          false },   // transparent USDSOQ
        {   8,   false,    true,     false,          false },   // BTCSOQ holding
        {  10,   false,    false,    true,           false },   // confidential USDSOQ, Tier A
        {  11,   false,    false,    false,          true  },   // unallocated: must claim nothing
    };

    for (const Case& c : cases) {
        out.scriptPubKey = Program(c.version);
        BOOST_CHECK_MESSAGE(out.IsUSDSOQ() == c.usdsoq,
            "IsUSDSOQ() disagrees with the table for witness v" + std::to_string(c.version));
        BOOST_CHECK_MESSAGE(out.IsBTCSOQ() == c.btcsoq,
            "IsBTCSOQ() disagrees with the table for witness v" + std::to_string(c.version));
        BOOST_CHECK_MESSAGE(out.IsConfidential() == c.confidential,
            "IsConfidential() disagrees with the table for witness v" + std::to_string(c.version));
        BOOST_CHECK_MESSAGE(out.IsNativeSOQ() == c.nativeSOQ,
            "IsNativeSOQ() disagrees with the table for witness v" + std::to_string(c.version) +
            ". This predicate decides what the miner may claim as fees, so a wrong answer here "
            "is an inflation bug, not a classification nit");
    }

    // The collision itself, stated directly: v6 and v10 must never be the same
    // output. An earlier revision made IsV6ConfidentialUSDSOQ byte-for-byte
    // identical to is_p2wsh_dilithium, and CI was green.
    CTxOut v6; v6.scriptPubKey = Program(6);
    CTxOut v10; v10.scriptPubKey = Program(10);
    BOOST_CHECK_MESSAGE(!v6.IsV10ConfidentialUSDSOQ(),
        "a v6 P2WSH-Dilithium covenant output is being classified as confidential USDSOQ. "
        "That is the exact collision that was caught and moved to v10");
    BOOST_CHECK_MESSAGE(v10.IsV10ConfidentialUSDSOQ(), "v10 must be confidential USDSOQ");
    BOOST_CHECK(!v6.IsConfidential());
}

// The free range, derived rather than asserted from memory. Anything an
// allocation touches at ANY layer is taken; the remainder is what a future
// feature may use. Deriving it is the point: the v6 collision happened because
// someone consulted a document.
BOOST_AUTO_TEST_CASE(free_witness_versions_are_v11_through_v16)
{
    std::vector<int> free_;
    for (int v = 2; v <= 16; ++v) {
        CTxOut o; o.scriptPubKey = Program(v);
        txnouttype t;
        const bool claimedByScript  = ScriptVerdict(Program(v), SCRIPT_VERIFY_WITNESS) == SCRIPT_ERR_OK &&
                                      v <= 9;   // v10-v16 are anyone-can-spend by default, not claimed
        const bool claimedBySolver  = SolverNames(Program(v), t);
        const bool claimedByAsset   = o.IsUSDSOQ() || o.IsBTCSOQ() || o.IsConfidential() ||
                                      o.IsV10ConfidentialUSDSOQ() || o.IsV4ConfidentialSOQ();
        if (!claimedByScript && !claimedBySolver && !claimedByAsset) free_.push_back(v);
    }

    const std::vector<int> expected = {11, 12, 13, 14, 15, 16};
    BOOST_CHECK_MESSAGE(free_ == expected,
        "the free witness-version range has moved. v10 is TAKEN (confidential USDSOQ, Tier A) "
        "in every layer: transaction.h, the activation mask in validation.cpp, and since FC4 the "
        "interpreter's own is_confidential_usdsoq_witness dispatch (bead jzg0 closed the "
        "half-allocation). Derive this list from the code before allocating anything, never "
        "from a design document");
}

// ⚠️ WITNESS v0 IS RELAY-STANDARD AND NOT SPENDABLE AS ITS NAME IMPLIES.
// Solver names both v0 forms, so IsStandard accepts them with an empty mask (the
// v2-v16 gate does not cover v0). The script layer disagrees with both:
//
//   v0 <20>  P2WPKH-shaped. VerifyScript requires a 34-byte program for the
//            Dilithium path, so a 22-byte script matches nothing and is rejected
//            outright. The output relays, confirms, and can never be spent.
//   v0 <32>  P2WSH-shaped to Solver, but is_dilithium accepts OP_0 exactly like
//            OP_1, so the script layer treats the program as SHA256(pubkey) and
//            demands a Dilithium signature. A real script hash is not a pubkey
//            hash, so those funds are gone too.
//
// Exposure is narrow: utiladdress.cpp hardcodes witness version 1, so no address
// encodes to v0 and only a hand-built scriptPubKey gets there. It is not zero,
// because a generic Bitcoin library pointed at our HRP produces v0 P2WPKH by
// default, and that is precisely what an exchange integrating from scratch
// reaches for. Same family as the SDK builders that hardcoded the stagenet HRP.
//
// Pinned, not fixed. The fix is a policy change (refuse v0 the way v5-v9 are
// refused while dormant), which is cheap and consensus-neutral, but the wallet
// and script/standard.cpp still carry v0 plumbing and that wants its own look.
// Bead v7xm F2.
BOOST_AUTO_TEST_CASE(witness_v0_is_standard_but_unspendable)
{
    const CScript keyhashShape   = Program(0, 20);   // OP_0 <20>, 22 bytes
    const CScript scripthashShape = Program(0, 32);  // OP_0 <32>, 34 bytes

    BOOST_CHECK_MESSAGE(StandardWith(keyhashShape, 0),
        "if v0 <20> has become non-standard the divergence is fixed and this test should be "
        "updated rather than deleted");
    BOOST_CHECK_MESSAGE(StandardWith(scripthashShape, 0),
        "if v0 <32> has become non-standard the divergence is fixed");

    BOOST_CHECK_MESSAGE(
        ScriptVerdict(keyhashShape, SCRIPT_VERIFY_WITNESS) == SCRIPT_ERR_DISALLOWED_CLASSICAL_CRYPTO,
        "a relay-standard v0 <20> output must at least fail CLOSED at the script layer. "
        "Standard plus spendable-by-anyone would be the v5-v9 fund-loss shape again; "
        "standard plus spendable-by-nobody is a burn, which is what this asserts");

    // v0 <32> takes the Dilithium branch, so it fails on the signature rather
    // than on the shape. Different error, same practical outcome for a caller
    // who thought they were creating P2WSH.
    const ScriptError v0script = ScriptVerdict(scripthashShape, SCRIPT_VERIFY_WITNESS);
    BOOST_CHECK_MESSAGE(v0script != SCRIPT_ERR_OK,
        "v0 <32> must not be anyone-can-spend");
    BOOST_CHECK_MESSAGE(v0script != SCRIPT_ERR_DISALLOWED_CLASSICAL_CRYPTO,
        "v0 <32> is expected to reach the Dilithium branch (is_dilithium accepts OP_0 as well "
        "as OP_1), so it should fail on the witness rather than on the shape. If that changed, "
        "the v0/v1 aliasing in interpreter.cpp has moved");
}

// ---------------------------------------------------------------------------
// WITNESS v3 / LatticeFold+ IS RETIRED, ON EVERY NETWORK.
//
// Superseded by SoquObscura. The verifier reads its own statement fields out of
// the untrusted proof blob and every algebraic check is homogeneous in the
// witness, so an all-zero witness satisfies all of them: a proof carrying no
// valid signature verifies. Mainnet withdrew it; testnet, regtest and stagenet
// were left ALWAYS_ACTIVE and therefore validated under a rule mainnet refuses,
// which is the same state bead 2pru withdrew SoquObscura from and the same
// reasoning. Retired on all four as of 2026-08-20.
//
// "Retired" is enforced here rather than asserted in a comment, because the
// entire lesson of this sweep is that an intention nothing executes is
// indistinguishable from an intention nobody implemented.
//
// ⛔ v3 MUST NOT BE REALLOCATED. It is deliberately left in the anyone-can-spend
// soft-fork posture rather than turned into a hard script error, which keeps
// both future options open: burning it later is a tightening (a soft fork, still
// available), whereas un-burning it would be a hard fork. Reuse is nonetheless
// the wrong move — v11-v16 are free, so there is no scarcity pressure, and a
// number that meant "LatticeFold+ batch proof" for a year will stay wrong in
// somebody's explorer, SDK or document. That is the confusion class that produced
// the v6 collision. Allocate upward from v11.
// ---------------------------------------------------------------------------
// ⛔⛔ SOQ-I011 TRIPWIRE. SoquObscura must stay NOT_SCHEDULED on every network
// until the range-proof verifier is made sound. Setting an activation height
// here is the single action that converts a dormant unsoundness into live
// inflation, so it must fail loudly rather than quietly work.
//
// The verifier does not bind the committed amount, and the reason is NOT the
// no-op at Check 5:
//
//   * Check 4 compares a PROVER-SUPPLIED t_reconstruction against
//     z_response*A + z_randomness*S. Both sides are prover-controlled and the
//     relation is homogeneous, so (z, z_r, t) = (0, 0, 0) with an honest
//     Fiat-Shamir seed satisfies it. The SOQ-D001 comment claiming
//     Schwartz-Zippel binding is an assertion, not a proof. Filling in Check 5
//     as an upper bound would still accept z_randomness = 0.
//   * On the OPCODE path it is worse. interpreter.cpp default-constructs
//     `latticebp::RangeProofParams rp_params;` and RingElement's default ctor
//     zero-fills, so A and S are all-zero and Check 4 collapses to
//     t_reconstruction == 0 independent of the responses. Any blob with a
//     zero t and a matching seed verifies, and the seed is computable from
//     public data alone.
//   * Root cause: `consensus.latticeBPSeed` is set twelve times in
//     chainparams.cpp and read NOWHERE. LatticeCommitment::PublicParams::
//     generate() has no consensus caller at all. The generators the verifier
//     needs are never derived, so the opcode path was never going to bind.
//
// The three deliberate failures in soquobscura_degenerate_witness_tests.cpp
// are the live demonstration of this and must NOT be "fixed" by patching the
// symptom. Correct order of work: seed PublicParams from consensus.
// latticeBPSeed, make Check 4 bind against a verifier-derived value, then
// Check 5, then re-run the forgery battery, then consider a height.
BOOST_AUTO_TEST_CASE(soquobscura_must_stay_dormant_on_every_network)
{
    for (const std::string& net : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET,
                                   CBaseChainParams::REGTEST, CBaseChainParams::STAGENET}) {
        SelectParams(net);
        const Consensus::BIP9Deployment& d =
            Params().GetConsensus(0).vDeployments[Consensus::DEPLOYMENT_SOQUOBSCURA];

        BOOST_CHECK_MESSAGE(
            d.nActivationHeight == Consensus::BIP9Deployment::NOT_SCHEDULED,
            net + ": DEPLOYMENT_SOQUOBSCURA has left NOT_SCHEDULED. The Lattice-BP++ range "
            "proof does not bind the committed amount (see this test's comment and bead "
            "soquobscura-verifier-epic-roadmap-y58a). Activating it makes confidential "
            "outputs mintable from nothing. Do not schedule a height until the forgery "
            "battery in soquobscura_degenerate_witness_tests.cpp passes for the right "
            "reason");

        // NO_HEIGHT_ACTIVATION would fall back to the BIP9 state machine, which is
        // exactly how a "cleanup" could re-activate this by accident.
        BOOST_CHECK_MESSAGE(
            d.nActivationHeight != Consensus::BIP9Deployment::NO_HEIGHT_ACTIVATION,
            net + ": DEPLOYMENT_SOQUOBSCURA must not use NO_HEIGHT_ACTIVATION. That "
            "sentinel defers to VersionBitsState and would re-open the feature");
    }
    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_CASE(latticefold_is_retired_and_cannot_activate_on_any_network)
{
    for (const std::string& net : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET,
                                   CBaseChainParams::REGTEST, CBaseChainParams::STAGENET}) {
        SelectParams(net);
        const Consensus::BIP9Deployment& d =
            Params().GetConsensus(0).vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD];

        // nStartTime=0 / nTimeout=0 is the terminal THRESHOLD_FAILED idiom: the BIP9
        // state machine can never leave FAILED, so SCRIPT_VERIFY_LATTICEFOLD is never
        // set and both entry points stay unreachable — OP_CHECKFOLDPROOF returns
        // SCRIPT_ERR_BAD_OPCODE, and a witness-v3 program short-circuits to
        // anyone-can-spend before the verifier is ever called.
        BOOST_CHECK_MESSAGE(d.nStartTime == 0 && d.nTimeout == 0,
            net + ": DEPLOYMENT_LATTICEFOLD must stay at nStartTime=0/nTimeout=0. It is "
            "RETIRED and superseded by SoquObscura, and its verifier accepts an all-zero "
            "witness, so activating it on any network is a forgery path");

        // This deployment is queried through VersionBitsState, never through
        // DeploymentActiveAtHeight, so an activation height here would be silently
        // ignored — someone adding one would believe they had changed something.
        BOOST_CHECK_MESSAGE(
            d.nActivationHeight == Consensus::BIP9Deployment::NO_HEIGHT_ACTIVATION,
            net + ": DEPLOYMENT_LATTICEFOLD has an nActivationHeight, which nothing reads "
            "for this deployment. Either the query site moved to DeploymentActiveAtHeight "
            "or someone set a field expecting it to lock the feature down");
    }
    SelectParams(CBaseChainParams::MAIN);
}

// v3 stays anyone-can-spend while retired, which is the posture that keeps the
// version safe to leave alone: it is not relay-standard (Solver has no v3 form),
// so no output can be funded into it through normal relay. If v3 ever becomes a
// hard script error that is a deliberate burn and this test should record it.
BOOST_AUTO_TEST_CASE(retired_v3_is_still_soft_fork_safe_not_burned)
{
    BOOST_CHECK_MESSAGE(ScriptVerdict(Program(3), SCRIPT_VERIFY_WITNESS) == SCRIPT_ERR_OK,
        "witness v3 is expected to remain anyone-can-spend while retired. If it now errors, "
        "v3 has been BURNED: reuse would need a hard fork. That is a legitimate choice but "
        "it must be a deliberate one");
    BOOST_CHECK_MESSAGE(!StandardWith(Program(3), WitnessVersionBit(3)),
        "witness v3 must never be relay-standard, even with its mask bit forced on. That is "
        "the only thing standing between anyone-can-spend and a funded v3 output");
}

// ⛔ THE ATTACK THIS PINS: someone schedules the v6 covenant stack the way
// DEPLOYMENT_PRECONDITIONS.md rule 3 reads at a glance — one feature at a time
// — and ships DEPLOYMENT_P2WSH_DILITHIUM + DEPLOYMENT_DILITHIUM_KEYHASH at
// height H1 and DEPLOYMENT_APO at H2 > H1. Between H1 and H2 every node
// rejects a v6 spend carrying an ANYPREVOUT signature; at H2 the upgraded
// nodes accept it and every node still on the H1 release forks off. That is a
// HARD FORK produced by a one-line chainparams edit, and until this test
// existed nothing in the tree observed it.
//
// The mechanism is stack arity, not APO specifically. Inside a v6 script:
//
//   OP_CTV             (interpreter.cpp:628)  set: validates, leaves its hash
//                                             on the stack. clear: NOP.
//                                             ARITY-NEUTRAL — the only one.
//   OP_CSFS            (interpreter.cpp:689)  set: pops 3, pushes 1. clear: NOP.
//   OP_CDKH            (interpreter.cpp:786)  set: pops 3. clear: NOP7.
//   V6_CONTROLFLOW     (interpreter.cpp:857)  set: OP_DROP/OP_EQUAL/OP_SHA256/
//                                             OP_CLTV/OP_CSV execute. clear:
//                                             silently ignored, no terminal
//                                             BAD_OPCODE.
//
// So for the eLTOO shape <khB> OP_CDKH <khA> OP_CDKH OP_1 satisfied by
// [sigA, pkA, sigB, pkB]: with CDKH clear nothing is popped, seven items
// remain, and the clean-stack check at interpreter.cpp:1893 REJECTS. With CDKH
// set the stack reduces to [1] and it ACCEPTS. Rejected-then-accepted is a
// loosening however it is scheduled; flag-day activation does not change fork
// class, only direction does.
//
// Measured against the GENESIS binary the combined activation is still a soft
// fork, because a dormant v6 output is anyone-can-spend. So the whole stack in
// one flag-day is safe and any split of it is not.
//
// See doc/specifications/WITNESS_VERSION_FORK_CLASS.md §3a and the v6 row of
// §2, doc/DEPLOYMENT_PRECONDITIONS.md rule 3's exception, and bead mpu9.
BOOST_AUTO_TEST_CASE(v6_covenant_stack_activates_together)
{
    const std::pair<Consensus::DeploymentPos, const char*> kStack[] = {
        {Consensus::DEPLOYMENT_P2WSH_DILITHIUM, "DEPLOYMENT_P2WSH_DILITHIUM"},
        {Consensus::DEPLOYMENT_DILITHIUM_KEYHASH, "DEPLOYMENT_DILITHIUM_KEYHASH"},
        {Consensus::DEPLOYMENT_CSFS, "DEPLOYMENT_CSFS"},
        {Consensus::DEPLOYMENT_V6_CONTROLFLOW, "DEPLOYMENT_V6_CONTROLFLOW"},
        {Consensus::DEPLOYMENT_APO, "DEPLOYMENT_APO"},
        // CTV is arity-neutral and could in principle follow later. It is held
        // to the same height anyway so the rule has no edge case to remember.
        {Consensus::DEPLOYMENT_CTV, "DEPLOYMENT_CTV"},
    };

    for (const std::string& net : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET,
                                   CBaseChainParams::REGTEST, CBaseChainParams::STAGENET}) {
        SelectParams(net);
        const Consensus::Params& params = Params().GetConsensus(0);

        const int32_t anchor = params.vDeployments[kStack[0].first].nActivationHeight;
        for (const auto& d : kStack) {
            const int32_t h = params.vDeployments[d.first].nActivationHeight;
            BOOST_CHECK_MESSAGE(
                h == anchor,
                net + ": " + d.second + " is scheduled at height " + std::to_string(h) +
                " but " + kStack[0].second + " is at " + std::to_string(anchor) +
                ". The witness-v6 covenant stack MUST activate in ONE flag-day. "
                "Splitting it is a HARD FORK: these opcodes change stack arity "
                "between their clear and set states, so a v6 script that fails the "
                "clean-stack check while one of them is dormant PASSES once it "
                "activates, which splits every node on the intermediate release. "
                "See WITNESS_VERSION_FORK_CLASS.md 3a and bead mpu9. If you are "
                "scheduling the flag-day, move ALL of these to the same height");

            // NO_HEIGHT_ACTIVATION defers to the BIP9 state machine, whose
            // per-deployment timing is not a single flag-day by construction.
            BOOST_CHECK_MESSAGE(
                params.vDeployments[d.first].nActivationHeight !=
                    Consensus::BIP9Deployment::NO_HEIGHT_ACTIVATION,
                net + ": " + d.second + " must not use NO_HEIGHT_ACTIVATION. The v6 "
                "covenant stack activates by height, together; the BIP9 state machine "
                "would let its members cross the threshold independently");
        }
    }
    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_SUITE_END()
