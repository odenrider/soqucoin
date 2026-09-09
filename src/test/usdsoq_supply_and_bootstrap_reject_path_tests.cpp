// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// usdsoq_supply_and_bootstrap_reject_path_tests.cpp — the two remaining USDSOQ
// reject strings from bead reject-string-coverage-gap-244e that do not wait on
// another bead:
//
//   bad-usdsoq-supply-overflow      the supply guard in ConnectBlock's mint path
//   bad-usdsoq-bootstrap-reentry     the H2 re-entry guard in ConnectBlock's
//                                    USDSOQ bootstrap branch
//
// Rules are named by symbol, not by file and line: a line number in a test
// comment is checked by nothing and drifts on the next edit to validation.cpp.
// The exact lines against this branch's base commit are in the PR body.
//
// Both are the USDSOQ twins of rules covered on the BTCSOQ side in
// btcsoq_lifecycle_harness_tests.cpp, and the reachability answer is the same:
// neither is attacker-reachable.
//
//   supply-overflow — CUSDSOQSupply::Mint fails only when total_minted leaves
//     MoneyRange. Reaching that needs mints summing to a large fraction of
//     MAX_MONEY, every one of them signed by the authority, so the guard is
//     against an authority or accounting error and not against an outsider.
//     Reached here by preloading the counter.
//
//   bootstrap-reentry — needs LevelDB to hold an authority outpoint while the
//     in-memory global is null. No block produces that state; a partial reindex
//     or a corrupted datadir does, which is exactly what the rule says ("Run
//     -reindex to repair"). Reached here by nulling the global and leaving the
//     database alone.
//
// So these are invariant guards against a damaged local state, not consensus
// surface an attacker can drive, and the correct shape is to inject the state
// and prove the guard still fires. Recorded so a later reader does not re-file
// them as missing attack tests. Each case carries a presence control, because a
// reject asserted against an empty database or an untouched counter would prove
// nothing.

#include "chainparams.h"
#include "consensus/usdsoq.h"
#include "consensus/validation.h"
#include "test/dilithium_chain_setup.h"
#include "txdb.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

namespace {

//! Above the UTXO-cost floor, same value the BTCSOQ harness uses.
static const CAmount V7_MINT = 1000000;

} // namespace

struct UsdsoqSupplyBootstrapSetup : public DilithiumChainSetup {
    UsdsoqTestAuthority auth;

    //! A BOOTSTRAP authority transaction: input 0 is a mature coinbase that
    //! carries the authority witness, and the transaction creates the v5 marker
    //! that starts the chain of custody. With `mintV7` it also mints a v7
    //! output ex nihilo, which is what puts a delta into the supply counter —
    //! the marker-only form leaves the counter untouched and cannot reach the
    //! overflow rule at all.
    CMutableTransaction BuildBootstrap(const CTransaction& feeCoinbase, CAmount mintV7)
    {
        const CAmount feeVal = feeCoinbase.vout[0].nValue;
        CMutableTransaction tx;
        tx.nVersion = 2;

        CTxIn in;
        in.prevout = COutPoint(feeCoinbase.GetHash(), 0);
        in.nSequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.push_back(in);

        CTxOut mark; mark.nValue = 100000; mark.scriptPubKey = auth.MarkerSpk();
        tx.vout.push_back(mark);
        if (mintV7 > 0) {
            CTxOut v7; v7.nValue = mintV7; v7.scriptPubKey = Spk(OP_7);
            tx.vout.push_back(v7);
        }
        CTxOut chg; chg.nValue = feeVal - 110000; chg.scriptPubKey = Spk(OP_1);
        tx.vout.push_back(chg);

        // No per-input signature: input 0 is the authority input, and
        // auth.Sign rebuilds its whole witness stack, so a v1 signature written
        // here would be discarded. The input is not script-verified either --
        // the v5 marker output plus the authority stack shape takes the
        // CheckInputs authority skip.
        auth.Sign(tx, 0, auth.MarkerSpk());
        return tx;
    }
};

BOOST_FIXTURE_TEST_SUITE(usdsoq_supply_and_bootstrap_reject_path_tests,
                         UsdsoqSupplyBootstrapSetup)

// PRESENCE CONTROL for both cases below. An authority bootstrap that mints v7
// must connect on an untouched counter, otherwise the two rejects could be
// coming from something wrong with the transaction rather than from the guard
// under test.
BOOST_AUTO_TEST_CASE(an_authority_bootstrap_that_mints_v7_is_accepted)
{
    CMutableTransaction boot = BuildBootstrap(coinbaseTxns[0], V7_MINT);

    BOOST_CHECK_EQUAL(RejectReasonFor({boot}), "");
}

BOOST_AUTO_TEST_CASE(usdsoq_supply_overflow_guard_fires_with_the_counter_at_the_ceiling)
{
    {
        LOCK(cs_main);
        BOOST_REQUIRE_EQUAL(g_usdsoq_supply.TotalMinted(), 0);
        BOOST_REQUIRE(g_usdsoq_supply.Mint(MAX_MONEY - 1));
        BOOST_REQUIRE_EQUAL(g_usdsoq_supply.TotalMinted(), MAX_MONEY - 1);
    }

    CMutableTransaction boot = BuildBootstrap(coinbaseTxns[0], V7_MINT);

    BOOST_CHECK_EQUAL(RejectReasonFor({boot}), "bad-usdsoq-supply-overflow");
}

BOOST_AUTO_TEST_CASE(usdsoq_bootstrap_reentry_is_rejected_while_the_database_holds_an_outpoint)
{
    CMutableTransaction boot = BuildBootstrap(coinbaseTxns[0], 0);
    CBlock b = CreateAndProcessBlock({boot}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == b.GetHash());

    {
        LOCK(cs_main);
        // Presence control: this proves the accepted bootstrap really did
        // persist an outpoint, so the reject below cannot come from an empty
        // database taking the same branch for a different reason.
        COutPoint persisted;
        BOOST_REQUIRE(pcoinsdbview->ReadUSDSOQAuthorityOutpoint(persisted));
        BOOST_REQUIRE(!persisted.IsNull());

        // The damaged state the H2 guard exists for.
        g_usdsoq_authority_outpoint.SetNull();
    }

    CMutableTransaction boot2 = BuildBootstrap(coinbaseTxns[1], 0);

    BOOST_CHECK_EQUAL(RejectReasonFor({boot2}), "bad-usdsoq-bootstrap-reentry");
}

BOOST_AUTO_TEST_SUITE_END()
