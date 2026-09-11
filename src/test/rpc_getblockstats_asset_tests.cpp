// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// rpc_getblockstats_asset_tests.cpp — getblockstats on blocks whose
// transactions carry asset-bearing outputs.
//
// getblockstats derives each transaction's fee from the block undo as
// in minus out. Consensus conserves USDSOQ and BTCSOQ per asset and lets an
// authority transaction mint or burn them ex nihilo, so a raw sum over every
// output is not a SOQ quantity: a mint gives a negative "fee", a burn a fee
// inflated by the burned amount. The fee has to be computed over native SOQ
// only, the way ConnectBlock computes the fee it credits to the coinbase.
//
// Each case connects a real block through ProcessNewBlock and calls the RPC
// through the dispatch table, so the undo data the handler reads is the data
// the daemon would read.

#include "consensus/usdsoq.h"
#include "rpc/server.h"
#include "test/dilithium_chain_setup.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>
#include <univalue.h>

namespace {

static const CAmount V7_MINT = 1000000;
static const CAmount MARKER_VALUE = 100000;
static const CAmount SOQ_FEE = 10000;

//! Call getblockstats through the dispatch table for the block at `hash`.
static UniValue GetBlockStats(const uint256& hash)
{
    JSONRPCRequest req;
    req.strMethod = "getblockstats";
    req.params = UniValue(UniValue::VARR);
    req.params.push_back(hash.GetHex());
    req.fHelp = false;
    const CRPCCommand* cmd = tableRPC["getblockstats"];
    BOOST_REQUIRE(cmd != nullptr);
    return (*cmd->actor)(req);
}

static void CheckFeeStats(const UniValue& stats, CAmount fee, int64_t txs, int64_t ins)
{
    BOOST_CHECK_EQUAL(find_value(stats, "txs").get_int64(), txs);
    BOOST_CHECK_EQUAL(find_value(stats, "ins").get_int64(), ins);
    BOOST_CHECK_EQUAL(find_value(stats, "totalfee").get_int64(), fee);
    BOOST_CHECK_EQUAL(find_value(stats, "minfee").get_int64(), fee);
    BOOST_CHECK_EQUAL(find_value(stats, "maxfee").get_int64(), fee);
    BOOST_CHECK_EQUAL(find_value(stats, "avgfee").get_int64(), fee);
    BOOST_CHECK_EQUAL(find_value(stats, "medianfee").get_int64(), fee);
}

} // namespace

struct GetblockstatsAssetSetup : public DilithiumChainSetup {
    UsdsoqTestAuthority auth;

    //! A bootstrap authority transaction that mints `mintV7` of v7 USDSOQ ex
    //! nihilo. Input 0 is a mature coinbase carrying the authority witness;
    //! the outputs are the v5 marker, the minted v7 and SOQ change. SOQ in
    //! minus SOQ out is SOQ_FEE; the raw in minus out is SOQ_FEE - mintV7.
    CMutableTransaction BuildMint(const CTransaction& feeCoinbase, CAmount mintV7)
    {
        const CAmount feeVal = feeCoinbase.vout[0].nValue;
        CMutableTransaction tx;
        tx.nVersion = 2;

        CTxIn in;
        in.prevout = COutPoint(feeCoinbase.GetHash(), 0);
        in.nSequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.push_back(in);

        tx.vout.push_back(CTxOut(MARKER_VALUE, auth.MarkerSpk()));            // vout 0: v5 marker
        tx.vout.push_back(CTxOut(mintV7, Spk(OP_7)));                         // vout 1: minted v7
        tx.vout.push_back(CTxOut(feeVal - MARKER_VALUE - SOQ_FEE, Spk(OP_1))); // vout 2: SOQ change

        auth.Sign(tx, 0, auth.MarkerSpk());
        return tx;
    }

    //! A chained authority transaction that burns the v7 output of `mint`:
    //! input 0 spends the tracked marker, input 1 the minted v7, input 2 a
    //! mature coinbase for the fee. No v7 output. SOQ in minus SOQ out is
    //! SOQ_FEE; the raw in minus out is SOQ_FEE + the burned amount.
    CMutableTransaction BuildBurn(const CTransaction& mint, CAmount v7Val,
                                  const CTransaction& feeCoinbase)
    {
        const CAmount feeVal = feeCoinbase.vout[0].nValue;
        CMutableTransaction tx;
        tx.nVersion = 2;

        CTxIn marker;
        marker.prevout = COutPoint(mint.GetHash(), 0);
        marker.nSequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.push_back(marker);
        CTxIn v7;
        v7.prevout = COutPoint(mint.GetHash(), 1);
        v7.nSequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.push_back(v7);
        CTxIn fee;
        fee.prevout = COutPoint(feeCoinbase.GetHash(), 0);
        fee.nSequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.push_back(fee);

        tx.vout.push_back(CTxOut(MARKER_VALUE, auth.MarkerSpk()));
        tx.vout.push_back(CTxOut(feeVal - SOQ_FEE, Spk(OP_1)));

        SignInput(tx, 1, Spk(OP_7), v7Val);
        SignInput(tx, 2, coinbaseSpk, feeVal);
        auth.Sign(tx, 0, auth.MarkerSpk());
        return tx;
    }

    //! A plain SOQ spend of a mature coinbase paying SOQ_FEE.
    CMutableTransaction BuildSoqSpend(const CTransaction& coinbase)
    {
        const CAmount inVal = coinbase.vout[0].nValue;
        CMutableTransaction tx;
        tx.nVersion = 2;
        CTxIn in;
        in.prevout = COutPoint(coinbase.GetHash(), 0);
        in.nSequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.push_back(in);
        tx.vout.push_back(CTxOut(inVal - SOQ_FEE, Spk(OP_1)));
        SignInput(tx, 0, coinbaseSpk, inVal);
        return tx;
    }

    //! Connect `txns` in one block and require that it became the tip.
    CBlock Connect(const std::vector<CMutableTransaction>& txns)
    {
        BOOST_REQUIRE_EQUAL(RejectReasonFor(txns), "");
        CBlock b = CreateAndProcessBlock(txns, coinbaseSpk);
        BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == b.GetHash());
        return b;
    }
};

BOOST_FIXTURE_TEST_SUITE(rpc_getblockstats_asset_tests, GetblockstatsAssetSetup)

// Control: a block with one ordinary SOQ spend reports that spend's fee.
BOOST_AUTO_TEST_CASE(plain_soq_block_reports_the_soq_fee)
{
    CBlock b = Connect({BuildSoqSpend(coinbaseTxns[0])});
    CheckFeeStats(GetBlockStats(b.GetHash()), SOQ_FEE, 2, 1);
}

// A USDSOQ mint has more value in its outputs than in its inputs when every
// output is summed. The fee is the SOQ the transaction gave up, not that
// difference. The unfixed handler aborted the process here.
BOOST_AUTO_TEST_CASE(mint_block_reports_the_soq_fee)
{
    CBlock b = Connect({BuildMint(coinbaseTxns[0], V7_MINT)});
    CheckFeeStats(GetBlockStats(b.GetHash()), SOQ_FEE, 2, 1);
}

// A USDSOQ burn has more value in its inputs than in its outputs when every
// output is summed. The burned USDSOQ is not a fee.
BOOST_AUTO_TEST_CASE(burn_block_reports_the_soq_fee)
{
    CMutableTransaction mint = BuildMint(coinbaseTxns[0], V7_MINT);
    Connect({mint});

    CBlock b = Connect({BuildBurn(CTransaction(mint), V7_MINT, coinbaseTxns[1])});
    CheckFeeStats(GetBlockStats(b.GetHash()), SOQ_FEE, 2, 3);
}

// A block that holds a mint and an ordinary spend reports one fee per
// transaction, both in SOQ.
BOOST_AUTO_TEST_CASE(mixed_block_reports_every_fee_in_soq)
{
    CBlock b = Connect({BuildMint(coinbaseTxns[0], V7_MINT), BuildSoqSpend(coinbaseTxns[1])});
    UniValue stats = GetBlockStats(b.GetHash());
    BOOST_CHECK_EQUAL(find_value(stats, "txs").get_int64(), 3);
    BOOST_CHECK_EQUAL(find_value(stats, "totalfee").get_int64(), 2 * SOQ_FEE);
    BOOST_CHECK_EQUAL(find_value(stats, "minfee").get_int64(), SOQ_FEE);
    BOOST_CHECK_EQUAL(find_value(stats, "maxfee").get_int64(), SOQ_FEE);
}

BOOST_AUTO_TEST_SUITE_END()
