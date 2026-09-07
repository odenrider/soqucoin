// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// v6_asset_opcode_ban_tests.cpp — asset and attestation opcodes may not appear
// inside a P2WSH-Dilithium (witness v6) script, in ANY flag state.
//
// Why this is a consensus rule and why it is unconditional. OP_USDSOQ_*,
// OP_SOQUOBSCURA_RANGEPROOF, OP_CHECKFOLDPROOF and OP_CHECKPATAGG are
// dispatched by WITNESS VERSION (v5, v4, v3, v2): VerifyScript builds a
// one-opcode script and evaluates it with the version's own witness layout.
// Inside EvalScript each of them answers SCRIPT_ERR_BAD_OPCODE while its
// deployment flag is clear and executes once the flag is set. Reachable from
// a v6 script, that is a rule that FAILS before the asset activation and
// SUCCEEDS after it — a loosening — so every asset activation that followed
// P2WSH-Dilithium would have been a hard fork. Rejecting the opcode's presence
// in a v6 script in every state is a rule the activation release keeps, so
// P2WSH-Dilithium and the assets can each activate as soft forks in any order.
//
// Pinned by exact ScriptError, with a positive control (an innocuous v6 script
// verifies) and a push-data control (the banned byte values inside a data push
// are data, not opcodes).

#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "crypto/sha256.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

namespace {

typedef std::vector<unsigned char> valtype;

CScript V6ProgramFor(const CScript& witnessScript)
{
    uint256 h;
    CSHA256().Write(witnessScript.data(), witnessScript.size()).Finalize(h.begin());
    CScript spk;
    spk << OP_6 << valtype(h.begin(), h.end());
    return spk;
}

//! Witness layout for v6: [satisfaction items...] [witnessScript] [0x00-prefixed pubkey].
ScriptError VerdictFor(const CScript& witnessScript, unsigned int flags)
{
    CScriptWitness w;
    w.stack.push_back(valtype(witnessScript.begin(), witnessScript.end()));
    w.stack.push_back(valtype(1313, 0x00));
    BaseSignatureChecker checker;
    ScriptError serr = SCRIPT_ERR_OK;
    VerifyScript(CScript(), V6ProgramFor(witnessScript), &w, flags, checker, &serr);
    return serr;
}

const unsigned int P2WSH = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2WSH_DILITHIUM;

//! Every flag state that could change an asset opcode's EvalScript behaviour.
const unsigned int FLAG_STATES[] = {
    P2WSH,
    P2WSH | SCRIPT_VERIFY_USDSOQ,
    P2WSH | SCRIPT_VERIFY_BTCSOQ,
    P2WSH | SCRIPT_VERIFY_SOQUOBSCURA,
    P2WSH | SCRIPT_VERIFY_USDSOQ | SCRIPT_VERIFY_SOQUOBSCURA,
    P2WSH | SCRIPT_VERIFY_PAT,
    P2WSH | SCRIPT_VERIFY_LATTICEFOLD,
    P2WSH | SCRIPT_VERIFY_USDSOQ | SCRIPT_VERIFY_BTCSOQ | SCRIPT_VERIFY_SOQUOBSCURA |
        SCRIPT_VERIFY_PAT | SCRIPT_VERIFY_LATTICEFOLD | SCRIPT_VERIFY_V6_CONTROLFLOW,
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(v6_asset_opcode_ban_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(control_innocuous_v6_script_verifies)
{
    // OP_TRUE leaves exactly one truthy item: the clean-stack rule is satisfied.
    for (unsigned int flags : FLAG_STATES) {
        BOOST_CHECK_MESSAGE(VerdictFor(CScript() << OP_TRUE, flags) == SCRIPT_ERR_OK,
            "the harness must be able to verify a v6 script at all (flags=" << flags << ")");
    }
}

BOOST_AUTO_TEST_CASE(asset_and_attestation_opcodes_are_invalid_in_v6_in_every_flag_state)
{
    const opcodetype banned[] = {
        OP_USDSOQ_MINT, OP_USDSOQ_BURN, OP_USDSOQ_FREEZE, OP_USDSOQ_ROTATE,
        OP_SOQUOBSCURA_RANGEPROOF, OP_CHECKFOLDPROOF, OP_CHECKPATAGG,
    };
    for (opcodetype op : banned) {
        for (unsigned int flags : FLAG_STATES) {
            // Alone, and buried after an innocuous prefix: the scan must cover
            // the whole script, not just its first opcode.
            BOOST_CHECK_MESSAGE(VerdictFor(CScript() << op, flags) == SCRIPT_ERR_BAD_OPCODE,
                "opcode " << GetOpName(op) << " must be BAD_OPCODE inside v6 (flags=" << flags << ")");
            BOOST_CHECK_MESSAGE(VerdictFor(CScript() << OP_TRUE << op, flags) == SCRIPT_ERR_BAD_OPCODE,
                "opcode " << GetOpName(op) << " after a prefix must be BAD_OPCODE inside v6 (flags=" << flags << ")");
        }
    }
}

// The verdict must not depend on the asset flags: if it did, the ban would be
// the very loosening it exists to prevent. Same script, all states, one answer.
BOOST_AUTO_TEST_CASE(verdict_is_identical_across_flag_states)
{
    const CScript s = CScript() << OP_USDSOQ_MINT;
    const ScriptError first = VerdictFor(s, FLAG_STATES[0]);
    for (unsigned int flags : FLAG_STATES) {
        BOOST_CHECK_EQUAL((int)VerdictFor(s, flags), (int)first);
    }
}

BOOST_AUTO_TEST_CASE(banned_byte_values_inside_a_push_are_data_not_opcodes)
{
    // A single push whose bytes are the banned opcode values. It leaves one
    // truthy item (non-zero bytes), so a clean-stack verify must SUCCEED: the
    // scan uses GetOp and never looks inside push data.
    valtype data;
    data.push_back((unsigned char)OP_USDSOQ_MINT);
    data.push_back((unsigned char)OP_SOQUOBSCURA_RANGEPROOF);
    data.push_back((unsigned char)OP_CHECKPATAGG);
    for (unsigned int flags : FLAG_STATES) {
        BOOST_CHECK_MESSAGE(VerdictFor(CScript() << data, flags) == SCRIPT_ERR_OK,
            "banned opcode values inside push data must not trip the ban (flags=" << flags << ")");
    }
}

BOOST_AUTO_TEST_SUITE_END()
