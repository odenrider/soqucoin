// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// btcsoq_lifecycle_harness_tests.cpp — REAL consensus-path proof of the
// BTCSOQ money-path (Steps 2C/2D). Drives actual ConnectBlock / DisconnectBlock
// through the validation engine on a regtest chain, with real ML-DSA-44
// authority keypairs, exercising:
//   * bootstrap MINT bound to a Bitcoin deposit (v9 marker + signed OP_RETURN
//     op envelope + v8 output; supply counter moves; deposit recorded)
//   * a plain v8 TRANSFER (non-authority, conserves value, spent via the
//     audited v1 Dilithium path now that SCRIPT_VERIFY_BTCSOQ gates v8)
//   * an authority BURN (v8 input destroyed, release intent == burned sats,
//     supply decremented)
//   * reorg UNDO (supply reversal + minted-deposit erase so the same deposit
//     can re-mint on the new chain)
//   * double-mint REJECTION (the same btc_txid:vout cannot back two mints)
//
// Mirrors the freeze_registry_harness_tests fixture (Dilithium v1 coinbase so
// CreateNewBlock's dilithium-only coinbase rule is satisfied on regtest).

#include "chainparams.h"
#include "consensus/btcsoq.h"
#include "consensus/usdsoq.h"     // ComputeAuthorityKeyHash, DILITHIUM_* sizes
#include "consensus/validation.h"
#include "key.h"
#include "miner.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "txdb.h"
#include "uint256.h"
#include "validation.h"
#include "crypto/sha256.h"
#include "coins.h"
#include "test/test_bitcoin.h"
#include "test/testutil.h"   // ScopedRegtestActivation

extern "C" {
#include "crypto/dilithium/api.h"
}

#include <boost/test/unit_test.hpp>
#include <algorithm>

namespace {

static const int COINBASE_MATURITY_SOQ = 60 * 4;  // 240, regtest
static const CAmount MINT_SATS = 1000000;          // above the UTXO-cost floor

// Raw ML-DSA-44 keypair (matches CBTCSOQAuthority::VerifyAuthoritySignatures,
// which calls pqcrystals_dilithium2_ref_verify with an empty context).
struct AuthKey {
    std::vector<uint8_t> pk, sk;
    AuthKey() : pk(pqcrystals_dilithium2_PUBLICKEYBYTES),
                sk(pqcrystals_dilithium2_SECRETKEYBYTES) {
        BOOST_REQUIRE_EQUAL(pqcrystals_dilithium2_ref_keypair(pk.data(), sk.data()), 0);
    }
};

static std::vector<uint8_t> AuthSign(const uint256& msg, const std::vector<uint8_t>& sk)
{
    std::vector<uint8_t> sig(pqcrystals_dilithium2_BYTES);
    size_t siglen = 0;
    int ret = pqcrystals_dilithium2_ref_signature(
        sig.data(), &siglen, msg.begin(), 32, nullptr, 0, sk.data());
    BOOST_REQUIRE_EQUAL(ret, 0);
    sig.resize(siglen);
    BOOST_REQUIRE_EQUAL(sig.size(), (size_t)DILITHIUM_SIG_SIZE);
    return sig;
}

static CScript MakeV1Spk(const std::vector<unsigned char>& rawPubkey)
{
    uint256 h; CSHA256().Write(rawPubkey.data(), rawPubkey.size()).Finalize(h.begin());
    CScript s; s << OP_1 << std::vector<unsigned char>(h.begin(), h.end());
    return s;
}

static CScript MakeV8Spk(const std::vector<unsigned char>& rawPubkey)
{
    uint256 h; CSHA256().Write(rawPubkey.data(), rawPubkey.size()).Finalize(h.begin());
    CScript s; s << OP_8 << std::vector<unsigned char>(h.begin(), h.end());
    return s;
}

// Confidential v4 — the "exotic input" a BTCSOQ transfer must refuse.
static CScript MakeV4Spk()
{
    CScript s; s << OP_4 << std::vector<unsigned char>(32, 0x11);
    return s;
}

static std::vector<unsigned char> Prefixed(const std::vector<unsigned char>& rawPubkey)
{
    std::vector<unsigned char> out; out.reserve(rawPubkey.size() + 1);
    out.push_back(0x00);
    out.insert(out.end(), rawPubkey.begin(), rawPubkey.end());
    return out;
}

// OP_RETURN <[tag][payload]> — the signed BTCSOQ op envelope.
static CScript MakeOpEnvelope(uint8_t tag, const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> data; data.reserve(1 + payload.size());
    data.push_back(tag);
    data.insert(data.end(), payload.begin(), payload.end());
    CScript s; s << OP_RETURN << data;
    return s;
}

} // namespace

// ---------------------------------------------------------------------------
struct BTCSOQChainSetup : public TestingSetup {
    CKey coinbaseKey;
    CScript coinbaseSpk;
    std::vector<unsigned char> coinbasePk;
    std::vector<CTransaction> coinbaseTxns;

    AuthKey a0, a1, a2;
    std::vector<std::vector<uint8_t>> authKeys;
    CScript markerSpk;

    BTCSOQChainSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
        coinbaseKey.MakeNewKey(true);
        CPubKey pk = coinbaseKey.GetPubKey();
        BOOST_REQUIRE(pk.IsValid());
        coinbasePk.assign(pk.begin(), pk.end());
        BOOST_REQUIRE_EQUAL(coinbasePk.size(), 1312u);
        coinbaseSpk = MakeV1Spk(coinbasePk);

        // Authority keyset: 2-of-3. Initialize the global directly (the daemon
        // lazy-inits the same way from chainparams; this bypasses chainparams
        // so the proof is self-contained). Reset the cs_main-protected globals
        // because they persist across BOOST fixtures.
        authKeys = {a0.pk, a1.pk, a2.pk};
        {
            LOCK(cs_main);
            g_btcsoq_supply.Reset();
            g_btcsoq_authority_outpoint.SetNull();
            g_btcsoq_authority.Reset();   // never inherit a previous suite's authority
            BOOST_REQUIRE(g_btcsoq_authority.Initialize(authKeys, 2));
        }
        uint256 kh = ComputeAuthorityKeyHash(authKeys);
        markerSpk = CScript() << OP_9 << std::vector<unsigned char>(kh.begin(), kh.end());
        BOOST_REQUIRE_EQUAL(markerSpk.size(), 34u);

        for (int i = 0; i < COINBASE_MATURITY_SOQ; i++) {
            std::vector<CMutableTransaction> none;
            CBlock b = CreateAndProcessBlock(none, coinbaseSpk);
            coinbaseTxns.push_back(*b.vtx[0]);
        }
    }

    ~BTCSOQChainSetup() {
        LOCK(cs_main);
        g_btcsoq_supply.Reset();
        g_btcsoq_authority_outpoint.SetNull();
        // Without this the authority stayed installed for every later suite, so
        // authority_skip_gate_tests' no-keyset default-deny passed alone and
        // failed in the full run. Link order must not decide test outcomes.
        g_btcsoq_authority.Reset();
    }

    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns, const CScript& spk)
    {
        CBlock block = BuildSolvedBlock(txns, spk);
        std::shared_ptr<const CBlock> shared = std::make_shared<const CBlock>(block);
        bool fNewBlock = false;
        ProcessNewBlock(Params(), shared, true, &fNewBlock);
        return block;
    }

    // Solve a block WITHOUT connecting it, so a caller can run TestBlockValidity
    // and read the reject reason. ProcessNewBlock only returns a bool, so a test
    // built on CreateAndProcessBlock can assert that the tip did not move but not
    // WHY — and "the tip did not move" passes for the wrong reject exactly as
    // happily as for the right one. Bead r0vn requires the exact string.
    CBlock BuildSolvedBlock(const std::vector<CMutableTransaction>& txns, const CScript& spk)
    {
        const CChainParams& cp = Params();
        std::unique_ptr<CBlockTemplate> tmpl = BlockAssembler(cp).CreateNewBlock(spk, true);
        BOOST_REQUIRE(tmpl != nullptr);
        CBlock& block = tmpl->block;
        block.vtx.resize(1);
        {
            CMutableTransaction cb(*block.vtx[0]);
            cb.vout.erase(std::remove_if(cb.vout.begin(), cb.vout.end(),
                [](const CTxOut& o) {
                    return o.scriptPubKey.size() >= 38 && o.scriptPubKey[0] == OP_RETURN &&
                           o.scriptPubKey[1] == 0x24 && o.scriptPubKey[2] == 0xaa &&
                           o.scriptPubKey[3] == 0x21 && o.scriptPubKey[4] == 0xa9 &&
                           o.scriptPubKey[5] == 0xed;
                }), cb.vout.end());
            cb.vin[0].scriptWitness.stack.clear();
            block.vtx[0] = MakeTransactionRef(std::move(cb));
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

    // Drive a block through the full ConnectBlock path and return the reject
    // reason, or "" if it validated.
    std::string RejectReasonFor(const std::vector<CMutableTransaction>& txns)
    {
        CBlock B = BuildSolvedBlock(txns, coinbaseSpk);
        CValidationState st;
        bool ok;
        {
            LOCK(cs_main);
            ok = TestBlockValidity(st, Params(), B, chainActive.Tip(), true, true);
        }
        if (ok) return std::string();
        BOOST_TEST_MESSAGE("reject: " << st.GetRejectReason()
            << (st.GetDebugMessage().empty() ? "" : " | " + st.GetDebugMessage()));
        return st.GetRejectReason();
    }

    // Drop a mature, spendable coin of an arbitrary witness version straight into
    // the UTXO set. Modifies pcoinsTip directly: an intermediate CCoinsViewCache
    // would flush its unset hashBlock over the tip's and trip ConnectBlock's
    // assertion.
    COutPoint SeedCoin(const CScript& spk, CAmount value, uint8_t tag)
    {
        uint256 txid;
        txid.begin()[0] = tag;
        {
            LOCK(cs_main);
            CCoinsModifier c = pcoinsTip->ModifyCoins(txid);
            c->Clear();
            c->fCoinBase = false;
            c->nHeight   = 1;
            c->nVersion  = 2;
            c->vout.resize(1);
            c->vout[0].nValue       = value;
            c->vout[0].scriptPubKey = spk;
        }
        return COutPoint(txid, 0);
    }

    // Sign a v1 Dilithium input (coinbase / v8 holding) with a CKey.
    void SignV1(CMutableTransaction& tx, unsigned int idx, const CScript& spk,
                CAmount amount, const CKey& key, const std::vector<unsigned char>& rawPk)
    {
        CTransaction ctx(tx);
        uint256 h = SignatureHash(spk, ctx, idx, SIGHASH_ALL, amount, SIGVERSION_WITNESS_V0, nullptr);
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(key.Sign(h, sig));
        sig.push_back((unsigned char)SIGHASH_ALL);
        tx.vin[idx].scriptWitness.stack.clear();
        tx.vin[idx].scriptWitness.stack.push_back(sig);
        tx.vin[idx].scriptWitness.stack.push_back(Prefixed(rawPk));
    }

    // Attach the M-of-N authority witness to the authority input. The sighash is
    // computed over the marker script at that input, amount 0 (mirrors ConnectBlock).
    void SignAuthority(CMutableTransaction& tx, unsigned int authIdx, uint8_t tag)
    {
        CTransaction ctx(tx);
        uint256 h = SignatureHash(markerSpk, ctx, authIdx, SIGHASH_ALL, CAmount(0),
                                  SIGVERSION_WITNESS_V0, nullptr);
        std::vector<uint8_t> s0 = AuthSign(h, a0.sk);
        std::vector<uint8_t> s1 = AuthSign(h, a1.sk);
        BuildAuthorityWitnessStack(
            tx.vin[authIdx].scriptWitness.stack, tag, s0, s1);
    }

    // MINT MINT_SATS of v8 to `recipient`, bound to (btcTxid, btcVout).
    // Bootstrap (prevMarker == nullptr): the single input is a mature coinbase
    // that carries the authority witness. Chained (prevMarker != nullptr): the
    // authority input spends the tracked marker outpoint, and a coinbase funds
    // the fee — a structurally valid non-bootstrap authority mint.
    //! Re-sign a chained authority tx after editing its outputs. Editing ANY
    //! output invalidates the SIGHASH_ALL authority signature -- and it
    //! invalidates the fee input's signature too, since both are SIGHASH_ALL
    //! over the same outputs. Without both, an authority-sig rejection shadows
    //! the rule the edit was aiming at.
    void ReSignChainedAuthority(CMutableTransaction& tx, const CTransaction& fund,
                                uint8_t tag)
    {
        SignV1(tx, 1, coinbaseSpk, fund.vout[0].nValue, coinbaseKey, coinbasePk);
        SignAuthority(tx, 0, tag);
    }

    CMutableTransaction BuildMint(const CTransaction& fundCoinbase,
                                  const uint256& btcTxid, uint32_t btcVout,
                                  const std::vector<unsigned char>& recipientPk,
                                  const COutPoint* prevMarker = nullptr)
    {
        CMutableTransaction tx; tx.nVersion = 2;
        const CAmount fund = fundCoinbase.vout[0].nValue;

        if (prevMarker) {
            CTxIn mk; mk.prevout = *prevMarker; mk.nSequence = CTxIn::SEQUENCE_FINAL;
            tx.vin.push_back(mk);                                    // vin[0] = authority marker
            CTxIn fee; fee.prevout = COutPoint(fundCoinbase.GetHash(), 0);
            fee.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(fee);  // vin[1] = fee
        } else {
            CTxIn in; in.prevout = COutPoint(fundCoinbase.GetHash(), 0);
            in.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(in);    // vin[0] = coinbase (auth+fund)
        }

        CScript v8spk = MakeV8Spk(recipientPk);
        uint256 commit = ComputeBTCSOQRecipientCommitment(v8spk);
        std::vector<uint8_t> payload = BuildBTCSOQMintPayload(btcTxid, btcVout, MINT_SATS, commit);

        tx.vout.push_back(CTxOut(0, markerSpk));                                  // v9 marker
        tx.vout.push_back(CTxOut(MINT_SATS, v8spk));                             // v8 mint
        tx.vout.push_back(CTxOut(0, MakeOpEnvelope(BTCSOQ_OP_MINT, payload)));   // signed op
        tx.vout.push_back(CTxOut(fund - 10000, coinbaseSpk));                    // SOQ change

        if (prevMarker)
            SignV1(tx, 1, coinbaseSpk, fund, coinbaseKey, coinbasePk);  // fee witness (not verified; HasDilithium)
        SignAuthority(tx, 0, BTCSOQ_OP_MINT);
        return tx;
    }

    //! A FREEZE/UNFREEZE authority tx. Payload is the USDSOQ freeze layout
    //! [op:1][txid:32][vout:4 LE] carried inside the BTCSOQ op envelope.
    //! Creates no v8 output, so it cannot trip the unbound-mint rule.
    CMutableTransaction BuildFreeze(const CTransaction& fundCoinbase, uint8_t freezeOp,
                                    const COutPoint& target, const COutPoint* prevMarker)
    {
        CMutableTransaction tx; tx.nVersion = 2;
        const CAmount fund = fundCoinbase.vout[0].nValue;

        if (prevMarker) {
            CTxIn mk; mk.prevout = *prevMarker; mk.nSequence = CTxIn::SEQUENCE_FINAL;
            tx.vin.push_back(mk);
            CTxIn fee; fee.prevout = COutPoint(fundCoinbase.GetHash(), 0);
            fee.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(fee);
        } else {
            CTxIn in; in.prevout = COutPoint(fundCoinbase.GetHash(), 0);
            in.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(in);
        }

        std::vector<uint8_t> payload;
        payload.push_back(freezeOp);
        payload.insert(payload.end(), target.hash.begin(), target.hash.end());
        payload.push_back((uint8_t)(target.n & 0xff));
        payload.push_back((uint8_t)((target.n >> 8) & 0xff));
        payload.push_back((uint8_t)((target.n >> 16) & 0xff));
        payload.push_back((uint8_t)((target.n >> 24) & 0xff));

        tx.vout.push_back(CTxOut(0, markerSpk));
        tx.vout.push_back(CTxOut(0, MakeOpEnvelope(BTCSOQ_OP_FREEZE, payload)));
        tx.vout.push_back(CTxOut(fund - 10000, coinbaseSpk));

        if (prevMarker)
            SignV1(tx, 1, coinbaseSpk, fund, coinbaseKey, coinbasePk);
        SignAuthority(tx, 0, BTCSOQ_OP_FREEZE);
        return tx;
    }
};

BOOST_FIXTURE_TEST_SUITE(btcsoq_lifecycle_harness_tests, BTCSOQChainSetup)

// ---------------------------------------------------------------------------
// The full happy-path lifecycle in one chain: MINT -> TRANSFER -> BURN.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(mint_transfer_burn_lifecycle)
{
    uint256 depositTxid = uint256S("bccc00000000000000000000000000000000000000000000000000000000d001");

    // ---- MINT ----
    CMutableTransaction mint = BuildMint(coinbaseTxns[0], depositTxid, 0, coinbasePk);
    uint256 mintHash = CTransaction(mint).GetHash();
    CBlock bMint = CreateAndProcessBlock({mint}, coinbaseSpk);
    BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == bMint.GetHash(),
        "MINT block must connect");
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(g_btcsoq_supply.Outstanding(), MINT_SATS);
        BOOST_CHECK_EQUAL(g_btcsoq_supply.TotalMinted(), MINT_SATS);
        BOOST_CHECK(pcoinsdbview->IsBTCSOQMinted(COutPoint(depositTxid, 0)));
        // v8 UTXO exists and is a BTCSOQ holding.
        CCoins c; BOOST_REQUIRE(pcoinsTip->GetCoins(mintHash, c));
        BOOST_CHECK(c.vout[1].IsBTCSOQ());
        BOOST_CHECK_EQUAL(c.vout[1].nValue, MINT_SATS);
    }

    // ---- TRANSFER (non-authority, v8 in == v8 out) ----
    CKey newOwner; newOwner.MakeNewKey(true);
    std::vector<unsigned char> newOwnerPk(newOwner.GetPubKey().begin(), newOwner.GetPubKey().end());
    CMutableTransaction xfer; xfer.nVersion = 2;
    CTxIn v8in; v8in.prevout = COutPoint(mintHash, 1); v8in.nSequence = CTxIn::SEQUENCE_FINAL;
    xfer.vin.push_back(v8in);
    CTxIn feeIn; feeIn.prevout = COutPoint(coinbaseTxns[1].GetHash(), 0);
    feeIn.nSequence = CTxIn::SEQUENCE_FINAL; xfer.vin.push_back(feeIn);
    CScript newV8 = MakeV8Spk(newOwnerPk);
    xfer.vout.push_back(CTxOut(MINT_SATS, newV8));                                   // v8 out == v8 in
    xfer.vout.push_back(CTxOut(coinbaseTxns[1].vout[0].nValue - 10000, coinbaseSpk)); // SOQ change
    SignV1(xfer, 0, MakeV8Spk(coinbasePk), MINT_SATS, coinbaseKey, coinbasePk);       // v8 owner sig
    SignV1(xfer, 1, coinbaseSpk, coinbaseTxns[1].vout[0].nValue, coinbaseKey, coinbasePk); // fee sig
    uint256 xferHash = CTransaction(xfer).GetHash();
    CBlock bXfer = CreateAndProcessBlock({xfer}, coinbaseSpk);
    BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == bXfer.GetHash(),
        "TRANSFER block must connect");
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(g_btcsoq_supply.Outstanding(), MINT_SATS);  // transfers are supply-neutral
        CCoins c; BOOST_REQUIRE(pcoinsTip->GetCoins(xferHash, c));
        BOOST_CHECK(c.vout[0].IsBTCSOQ());
    }

    // ---- BURN (authority tx: spends prev marker + the v8, no v8 out, sats == v8 in) ----
    CMutableTransaction burn; burn.nVersion = 2;
    CTxIn mk; mk.prevout = COutPoint(mintHash, 0); mk.nSequence = CTxIn::SEQUENCE_FINAL; // prev marker
    burn.vin.push_back(mk);
    CTxIn burnV8; burnV8.prevout = COutPoint(xferHash, 0); burnV8.nSequence = CTxIn::SEQUENCE_FINAL;
    burn.vin.push_back(burnV8);
    CTxIn burnFee; burnFee.prevout = COutPoint(coinbaseTxns[2].GetHash(), 0);
    burnFee.nSequence = CTxIn::SEQUENCE_FINAL; burn.vin.push_back(burnFee);
    uint256 releaseHash = uint256S("re1ea5e00000000000000000000000000000000000000000000000000000c0de");
    std::vector<uint8_t> burnPayload = BuildBTCSOQBurnPayload(releaseHash, MINT_SATS);
    burn.vout.push_back(CTxOut(0, markerSpk));                                       // continue chain
    burn.vout.push_back(CTxOut(0, MakeOpEnvelope(BTCSOQ_OP_BURN, burnPayload)));      // signed op
    burn.vout.push_back(CTxOut(coinbaseTxns[2].vout[0].nValue - 10000, coinbaseSpk)); // SOQ change
    // Every input needs a Dilithium witness to pass CheckTransaction's
    // HasDilithiumSignatures (context-free, runs before the authority
    // script-skip in CheckInputs). The authority tx won't script-verify the
    // v8/fee inputs, but the witnesses must be structurally present.
    SignV1(burn, 1, MakeV8Spk(newOwnerPk), MINT_SATS, newOwner, newOwnerPk);          // v8 being burned
    SignV1(burn, 2, coinbaseSpk, coinbaseTxns[2].vout[0].nValue, coinbaseKey, coinbasePk); // fee
    SignAuthority(burn, 0, BTCSOQ_OP_BURN);  // authority witness on the marker-spending input
    CBlock bBurn = CreateAndProcessBlock({burn}, coinbaseSpk);
    BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == bBurn.GetHash(),
        "BURN block must connect");
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(g_btcsoq_supply.TotalBurned(), MINT_SATS);
        BOOST_CHECK_EQUAL(g_btcsoq_supply.Outstanding(), 0);
    }
}

// ---------------------------------------------------------------------------
// Reorg UNDO: disconnecting the mint block reverses the supply and ERASES the
// minted deposit, so the same Bitcoin deposit can back a mint on the new chain.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(reorg_undoes_mint_and_erases_deposit)
{
    uint256 depositTxid = uint256S("bccc00000000000000000000000000000000000000000000000000000000d002");
    CMutableTransaction mint = BuildMint(coinbaseTxns[0], depositTxid, 7, coinbasePk);
    CBlock bMint = CreateAndProcessBlock({mint}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == bMint.GetHash());
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(g_btcsoq_supply.Outstanding(), MINT_SATS);
        BOOST_CHECK(pcoinsdbview->IsBTCSOQMinted(COutPoint(depositTxid, 7)));
    }

    {
        LOCK(cs_main);
        CValidationState state;
        BlockMap::iterator it = mapBlockIndex.find(bMint.GetHash());
        BOOST_REQUIRE(it != mapBlockIndex.end());
        InvalidateBlock(state, Params(), it->second);
        ActivateBestChain(state, Params());
    }
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() != bMint.GetHash());
    {
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(g_btcsoq_supply.Outstanding() == 0,
            "reorg must UndoMint the supply");
        BOOST_CHECK_MESSAGE(!pcoinsdbview->IsBTCSOQMinted(COutPoint(depositTxid, 7)),
            "reorg must erase the minted deposit so it can re-mint");
    }
}

// ---------------------------------------------------------------------------
// Double-mint REJECTION: a second mint binding the same (btc_txid, vout) is
// consensus-invalid; the block carrying it must not connect.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(double_mint_rejected)
{
    uint256 depositTxid = uint256S("bccc00000000000000000000000000000000000000000000000000000000d003");
    CMutableTransaction mint1 = BuildMint(coinbaseTxns[0], depositTxid, 3, coinbasePk);
    uint256 mint1Hash = CTransaction(mint1).GetHash();
    CBlock b1 = CreateAndProcessBlock({mint1}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == b1.GetHash());
    uint256 tipAfterFirst = chainActive.Tip()->GetBlockHash();

    // Second mint: a structurally VALID chained authority mint (spends the
    // tracked marker mint1Hash:0, funded by another coinbase, correct sigs and
    // recipient commitment) that binds the SAME deposit. The ONLY reason to
    // reject it is the anti-replay check — so the reject proves anti-replay,
    // not the outpoint-chain rule.
    COutPoint prevMarker(mint1Hash, 0);
    CMutableTransaction mint2 = BuildMint(coinbaseTxns[1], depositTxid, 3, coinbasePk, &prevMarker);
    CBlock b2 = CreateAndProcessBlock({mint2}, coinbaseSpk);
    BOOST_CHECK_MESSAGE(chainActive.Tip()->GetBlockHash() == tipAfterFirst,
        "double-mint block must be rejected — tip unchanged");
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(g_btcsoq_supply.TotalMinted(), MINT_SATS);  // only the first mint counted
    }
}

// ===========================================================================
// REJECT-PATH COVERAGE (beads n1vf, r0vn).
//
// The three rejects below are REACHABLE — unlike the USDSOQ pair, nothing about
// them was dead — and until now none of these strings appeared anywhere under
// src/test/ or qa/. Reachable and unexercised is not a lesser state than dead:
// it is the state a dead rule is indistinguishable from, which is the whole
// point of the r0vn criterion. Each drives a failing input through ConnectBlock
// and asserts the exact string.
// ===========================================================================

// A non-authority tx cannot conjure BTCSOQ. v8 out > v8 in = 0, so the per-asset
// conservation rule must reject it. This is the BTCSOQ mirror of
// usdsoq_v7_conservation_harness_tests::v7_minted_from_soq_is_rejected, and the
// property is load-bearing: without it, any miner could emit a v8 output from
// ordinary SOQ and create Bitcoin-backed supply with no deposit behind it.
BOOST_AUTO_TEST_CASE(connectblock_rejects_btcsoq_minted_from_soq)
{
    const CTransaction& cb = coinbaseTxns[0];
    const CAmount fund = cb.vout[0].nValue;

    CMutableTransaction tx; tx.nVersion = 2;
    CTxIn in; in.prevout = COutPoint(cb.GetHash(), 0); in.nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vin.push_back(in);
    tx.vout.push_back(CTxOut(MINT_SATS, MakeV8Spk(coinbasePk)));         // v8 from nothing
    tx.vout.push_back(CTxOut(fund - MINT_SATS - 10000, coinbaseSpk));    // SOQ change
    SignV1(tx, 0, coinbaseSpk, fund, coinbaseKey, coinbasePk);

    BOOST_CHECK_EQUAL(RejectReasonFor({tx}), "bad-txns-btcsoq-not-conserved");
}

// Input-type isolation: a BTCSOQ transfer may spend v8 inputs (the asset) and
// transparent native-SOQ inputs (the fee), nothing else. Here the tx CONSERVES
// v8 exactly, so conservation cannot be what rejects it, and the only thing
// wrong is the v7 USDSOQ input mixed in. Keeping the two assets from meeting in
// one transfer is what stops cross-asset accounting from ever being needed.
BOOST_AUTO_TEST_CASE(connectblock_rejects_exotic_input_in_btcsoq_transfer)
{
    const CAmount v8Val = MINT_SATS;
    COutPoint v8op = SeedCoin(MakeV8Spk(coinbasePk), v8Val, 0xb8);
    // A CONFIDENTIAL v4 input is the exotic one to use here. A v7 USDSOQ input
    // would trip the USDSOQ conservation rule first (v7 in, no v7 out) and the
    // test would pin the wrong string — it did exactly that on the first run.
    // v4 is native SOQ by asset, so it is invisible to both conservation rules,
    // and the only thing it violates is the transparency half of the isolation
    // predicate.
    COutPoint v4op = SeedCoin(MakeV4Spk(), MINT_SATS, 0xb4);

    CMutableTransaction tx; tx.nVersion = 2;
    { CTxIn i0; i0.prevout = v8op; i0.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(i0); }
    { CTxIn i1; i1.prevout = v4op; i1.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(i1); }
    tx.vout.push_back(CTxOut(v8Val, MakeV8Spk(coinbasePk)));   // v8 in == v8 out
    SignV1(tx, 0, MakeV8Spk(coinbasePk), v8Val, coinbaseKey, coinbasePk);
    // The v4 input still needs a witness ending in an ML-DSA pubkey, or
    // CheckTransaction's bad-txns-requires-dilithium fires before we ever reach
    // the isolation rule. The v4 program itself is anyone-can-spend while
    // SoquObscura is dormant, so the signature is not what is being tested.
    SignV1(tx, 1, MakeV4Spk(), MINT_SATS, coinbaseKey, coinbasePk);

    BOOST_CHECK_EQUAL(RejectReasonFor({tx}), "bad-txns-btcsoq-input-mismatch");
}

// Authority operations must be fully transparent: the mint/burn boundary is
// where supply is auditable, and a hidden amount there breaks the invariant
// outright (GENIUS Act 4(a)(2)).
//
// SoquObscura is activated here so the confidential output is a real
// confidential output rather than a dormant anyone-can-spend shape. (Until
// 2026-09 SOQ-ARCH-001 rejected every confidential output block-wide while
// SoquObscura was dormant and would have shadowed this rule; it was retired
// with the additive-asset genesis door.)
BOOST_AUTO_TEST_CASE(connectblock_rejects_confidential_output_in_btcsoq_authority_tx)
{
    ScopedRegtestActivation on(Consensus::DEPLOYMENT_SOQUOBSCURA, 0);

    uint256 depositTxid = uint256S("bccc00000000000000000000000000000000000000000000000000000000dc04");
    CMutableTransaction mint = BuildMint(coinbaseTxns[1], depositTxid, 0, coinbasePk);

    // Add a confidential v4 output funded from the SOQ change, then re-sign:
    // the authority sighash covers the outputs, so an unsigned edit would be
    // caught as a bad signature and prove nothing about the transparency rule.
    CScript v4spk = CScript() << OP_4 << std::vector<unsigned char>(32, 0x11);
    BOOST_REQUIRE_EQUAL(v4spk.size(), 34u);
    CTxOut& change = mint.vout.back();
    BOOST_REQUIRE(change.nValue > MINT_SATS);
    change.nValue -= MINT_SATS;
    mint.vout.push_back(CTxOut(MINT_SATS, v4spk));
    SignAuthority(mint, 0, BTCSOQ_OP_MINT);

    BOOST_CHECK_EQUAL(RejectReasonFor({mint}), "bad-btcsoq-authority-must-be-transparent");
}

// Reachability control for the case above: the SAME mint without the
// confidential output must connect, so the rejection is the transparency rule
// and not an artefact of the edit.
BOOST_AUTO_TEST_CASE(transparent_btcsoq_authority_mint_is_accepted)
{
    ScopedRegtestActivation on(Consensus::DEPLOYMENT_SOQUOBSCURA, 0);

    uint256 depositTxid = uint256S("bccc00000000000000000000000000000000000000000000000000000000dc05");
    CMutableTransaction mint = BuildMint(coinbaseTxns[2], depositTxid, 0, coinbasePk);

    BOOST_CHECK_MESSAGE(RejectReasonFor({mint}).empty(),
        "the identical authority mint without a confidential output must connect");
}

// ---------------------------------------------------------------------------
// FREEZE RULES (bead btcsoq-freeze-pins). These three rejections were added to
// restore symmetry with USDSOQ after the first freeze pass fixed only one of
// the two sibling subsystems. Same five-case shape as usdsoq_freeze_rules_tests.
//
// bad-btcsoq-freeze-dead-target was FAIL-OPEN: a freeze naming something that is
// not a live v8 UTXO was skipped with a log line, so the issuer believed a coin
// was frozen when consensus had ignored the op. The two redundancy rules exist
// because DisconnectBlock inverts freeze ops blindly with no record of prior
// state, so a redundant FREEZE was a no-op inbound and an UNFREEZE outbound — a
// reorg silently lifted a freeze that predated the block.
// ---------------------------------------------------------------------------

//! Mint a v8 coin so there is something real to freeze. Returns the v8 outpoint
//! via `v8`, and the tracked authority marker via `marker`.
static const uint256 FREEZE_DEPOSIT = uint256S(
    "bccc00000000000000000000000000000000000000000000000000000000f001");

BOOST_AUTO_TEST_CASE(freezing_a_live_btcsoq_utxo_is_accepted)
{
    CMutableTransaction mint = BuildMint(coinbaseTxns[0], FREEZE_DEPOSIT, 0, coinbasePk);
    CBlock bm = CreateAndProcessBlock({mint}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == bm.GetHash());

    COutPoint marker(mint.GetHash(), 0), v8(mint.GetHash(), 1);
    CMutableTransaction fz = BuildFreeze(coinbaseTxns[1], FREEZE_OP_FREEZE, v8, &marker);
    BOOST_CHECK_MESSAGE(RejectReasonFor({fz}).empty(),
        "control: freezing a live v8 UTXO must connect");
}

BOOST_AUTO_TEST_CASE(freezing_a_dead_btcsoq_target_is_rejected_by_name)
{
    CMutableTransaction mint = BuildMint(coinbaseTxns[0], FREEZE_DEPOSIT, 0, coinbasePk);
    CBlock bm = CreateAndProcessBlock({mint}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == bm.GetHash());

    COutPoint marker(mint.GetHash(), 0);
    COutPoint ghost(uint256S("00000000000000000000000000000000000000000000000000000000deadbeef"), 0);
    CMutableTransaction fz = BuildFreeze(coinbaseTxns[1], FREEZE_OP_FREEZE, ghost, &marker);
    BOOST_CHECK_EQUAL(RejectReasonFor({fz}), "bad-btcsoq-freeze-dead-target");
}

BOOST_AUTO_TEST_CASE(refreezing_a_frozen_btcsoq_outpoint_is_rejected_by_name)
{
    CMutableTransaction mint = BuildMint(coinbaseTxns[0], FREEZE_DEPOSIT, 0, coinbasePk);
    CBlock bm = CreateAndProcessBlock({mint}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == bm.GetHash());

    COutPoint marker(mint.GetHash(), 0), v8(mint.GetHash(), 1);
    CMutableTransaction fz1 = BuildFreeze(coinbaseTxns[1], FREEZE_OP_FREEZE, v8, &marker);
    CBlock b1 = CreateAndProcessBlock({fz1}, coinbaseSpk);
    BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == b1.GetHash(),
        "the first freeze must connect before a redundant one means anything");

    COutPoint m2(fz1.GetHash(), 0);
    CMutableTransaction fz2 = BuildFreeze(coinbaseTxns[2], FREEZE_OP_FREEZE, v8, &m2);
    BOOST_CHECK_EQUAL(RejectReasonFor({fz2}), "bad-btcsoq-freeze-redundant");
}

BOOST_AUTO_TEST_CASE(unfreezing_a_non_frozen_btcsoq_outpoint_is_rejected_by_name)
{
    CMutableTransaction mint = BuildMint(coinbaseTxns[0], FREEZE_DEPOSIT, 0, coinbasePk);
    CBlock bm = CreateAndProcessBlock({mint}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == bm.GetHash());

    COutPoint marker(mint.GetHash(), 0), v8(mint.GetHash(), 1);
    CMutableTransaction uz = BuildFreeze(coinbaseTxns[1], FREEZE_OP_UNFREEZE, v8, &marker);
    BOOST_CHECK_EQUAL(RejectReasonFor({uz}), "bad-btcsoq-unfreeze-redundant");
}

// Not optional. Guards against the redundancy rules hardening into "an outpoint
// may only ever be frozen once", which would be a different bug wearing the
// same shape.
BOOST_AUTO_TEST_CASE(btcsoq_freeze_unfreeze_freeze_round_trip_is_accepted)
{
    CMutableTransaction mint = BuildMint(coinbaseTxns[0], FREEZE_DEPOSIT, 0, coinbasePk);
    CBlock bm = CreateAndProcessBlock({mint}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == bm.GetHash());

    COutPoint marker(mint.GetHash(), 0), v8(mint.GetHash(), 1);
    CMutableTransaction f1 = BuildFreeze(coinbaseTxns[1], FREEZE_OP_FREEZE, v8, &marker);
    CBlock b1 = CreateAndProcessBlock({f1}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == b1.GetHash());

    COutPoint m2(f1.GetHash(), 0);
    CMutableTransaction u1 = BuildFreeze(coinbaseTxns[2], FREEZE_OP_UNFREEZE, v8, &m2);
    CBlock b2 = CreateAndProcessBlock({u1}, coinbaseSpk);
    BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == b2.GetHash(),
        "unfreezing a frozen v8 outpoint must be accepted");

    COutPoint m3(u1.GetHash(), 0);
    CMutableTransaction f2 = BuildFreeze(coinbaseTxns[3], FREEZE_OP_FREEZE, v8, &m3);
    BOOST_CHECK_MESSAGE(RejectReasonFor({f2}).empty(),
        "re-freezing after an unfreeze is a real state transition and must be "
        "accepted — the rule is about redundancy, not about freezing once");
}

// ===========================================================================
// AUTHORITY-SIGNATURE REJECT PATHS (bead reject-string-coverage-gap-244e).
//
// bad-btcsoq-authority-sig appeared nowhere in the tree until now, along with
// bad-btcsoq-tag-mismatch, bad-btcsoq-missing-op, bad-btcsoq-unbound-mint and
// bad-btcsoq-unbound-burn. Every existing case in this file signs with the real
// authority; none measured what happens when the signature is wrong.
//
// ONE STRING, SEVEN EMIT SITES, so a test that asserts the string pins nothing
// about WHICH rule ran. In ConnectBlock the sites are, in the order a
// transaction meets them: the marker prevout being unavailable in both the view
// and the block undo; a null witness on the authority input; an empty signature
// set after extraction; and M-of-N verification failing. Three more sit in the
// mempool mirror in AcceptToMemoryPoolWorker. Sites are named by their error()
// text rather than by line number, because a line number in a test comment
// drifts silently on the next edit to validation.cpp; the exact lines against
// this branch's base commit are in the PR body. The four cases below cover all
// four ConnectBlock sites except the prevout-unavailable one, and each was
// attributed by reading the emitted error() text, not by trusting the string.
//
// The chained shape is used throughout because it is the one an attacker has
// access to: the tracked marker outpoint is public on-chain.
// ===========================================================================

//! An authority-SHAPED witness stack whose signature slots hold filler.
//! Its consumer is the CheckInputs authority skip, NOT
//! CTransaction::HasDilithiumSignatures: the skip tests shape alone -- a v9
//! marker output, six or more items, a one-byte op tag at index 2 inside
//! [BTCSOQ_OP_MINT, BTCSOQ_OP_FREEZE], and at least one item of exactly 2420
//! bytes. HasDilithiumSignatures' whole-transaction exemption keys on 0x55 at
//! index 2 and an OP_5 output, so it never applies to a v9 transaction and this
//! stack does not try to satisfy it.
//!
//! Carried on the FEE input by any case that empties the authority input's
//! witness. Without it that case relies on script checks being queued rather
//! than run inline, which makes the test pass for a reason unrelated to the
//! rule under test.
static std::vector<std::vector<unsigned char>> DecoyStack(uint8_t tag)
{
    std::vector<std::vector<unsigned char>> s;
    BuildAuthorityWitnessStack(s, tag,
        std::vector<uint8_t>(DILITHIUM_SIG_SIZE, 0xcc),
        std::vector<uint8_t>(DILITHIUM_SIG_SIZE, 0xdd));
    return s;
}

static const uint256 AUTHSIG_DEPOSIT_A = uint256S(
    "bccc00000000000000000000000000000000000000000000000000000000a001");
static const uint256 AUTHSIG_DEPOSIT_B = uint256S(
    "bccc00000000000000000000000000000000000000000000000000000000a002");

BOOST_AUTO_TEST_CASE(chained_btcsoq_mint_signed_by_outsiders_is_rejected)
{
    CMutableTransaction m1 = BuildMint(coinbaseTxns[0], AUTHSIG_DEPOSIT_A, 0, coinbasePk);
    const uint256 m1Hash = CTransaction(m1).GetHash();
    CBlock b1 = CreateAndProcessBlock({m1}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == b1.GetHash());
    COutPoint marker(m1Hash, 0);

    CMutableTransaction m2 =
        BuildMint(coinbaseTxns[1], AUTHSIG_DEPOSIT_B, 1, coinbasePk, &marker);

    // Re-sign the authority input with two keypairs outside the set. The layout
    // and the sighash are correct, so only set membership can reject it.
    AuthKey out0, out1;
    {
        CTransaction ctx(m2);
        uint256 h = SignatureHash(markerSpk, ctx, 0, SIGHASH_ALL, CAmount(0),
                                  SIGVERSION_WITNESS_V0, nullptr);
        BuildAuthorityWitnessStack(m2.vin[0].scriptWitness.stack, BTCSOQ_OP_MINT,
                                   AuthSign(h, out0.sk), AuthSign(h, out1.sk));
    }

    BOOST_CHECK_EQUAL(RejectReasonFor({m2}), "bad-btcsoq-authority-sig");
}

BOOST_AUTO_TEST_CASE(chained_btcsoq_mint_below_threshold_is_rejected)
{
    CMutableTransaction m1 = BuildMint(coinbaseTxns[0], AUTHSIG_DEPOSIT_A, 0, coinbasePk);
    const uint256 m1Hash = CTransaction(m1).GetHash();
    CBlock b1 = CreateAndProcessBlock({m1}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == b1.GetHash());
    COutPoint marker(m1Hash, 0);

    CMutableTransaction m2 =
        BuildMint(coinbaseTxns[1], AUTHSIG_DEPOSIT_B, 1, coinbasePk, &marker);

    // Replace the second signature with a one-byte item. The extractor selects
    // by exact DILITHIUM_SIG_SIZE, so the verifier sees one signature against a
    // threshold of two.
    m2.vin[0].scriptWitness.stack[5] = std::vector<unsigned char>{0x00};
    BOOST_REQUIRE_EQUAL(
        ExtractBTCSOQWitnessSignatures(m2.vin[0].scriptWitness.stack).size(), 1u);

    BOOST_CHECK_EQUAL(RejectReasonFor({m2}), "bad-btcsoq-authority-sig");
}

// THE NULL-WITNESS ARM, AND THE ONE BYTE THAT DECIDES WHETHER IT RUNS.
// ConnectBlock rejects a BTCSOQ authority transaction whose authority input
// carries no witness ("has no witness on authority input"). Whether that arm
// ever executes depends entirely on what CheckTransaction does with the same
// transaction first, and the answer measured on this tree is: it depends on the
// scriptSig, which is one attacker-chosen push.
//
// CTransaction::HasDilithiumSignatures runs before ConnectBlock (from
// CheckTransaction) and requires every input to present a blob whose first byte
// is 0x00. For an input with a witness it reads the witness stack's last item.
// For an input with NO witness it falls back to the scriptSig's LAST PUSH and
// applies the same one-byte test to that. Nothing requires the scriptSig to be
// empty, and per-input script verification -- which would demand an empty
// scriptSig for a native witness program -- is skipped for BTCSOQ authority
// transactions.
//
// So the two cases below are the same attack shape one push apart:
//
//   empty scriptSig       -> no blob at all -> bad-txns-requires-dilithium,
//                            and the authority block never runs
//   scriptSig <0x00...>   -> the fallback is satisfied -> the authority block
//                            runs and the null-witness arm rejects
//
// Both are kept, and both assert the string they actually produce. The first
// one alone would read as proof that the arm is unreachable, which is what a
// reading of it claimed before the second case was written.
BOOST_AUTO_TEST_CASE(chained_btcsoq_mint_with_no_witness_on_the_authority_input_dies_earlier)
{
    CMutableTransaction m1 = BuildMint(coinbaseTxns[0], AUTHSIG_DEPOSIT_A, 0, coinbasePk);
    const uint256 m1Hash = CTransaction(m1).GetHash();
    CBlock b1 = CreateAndProcessBlock({m1}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == b1.GetHash());
    COutPoint marker(m1Hash, 0);

    CMutableTransaction m2 =
        BuildMint(coinbaseTxns[1], AUTHSIG_DEPOSIT_B, 1, coinbasePk, &marker);
    m2.vin[0].scriptWitness.stack.clear();

    // No decoy on the fee input here: this transaction is rejected before
    // CheckInputs is reached, so a stack that only the CheckInputs skip reads
    // would be inert, and carrying it would suggest it was load-bearing.
    BOOST_REQUIRE_MESSAGE(m2.vin[0].scriptWitness.IsNull(),
        "the authority input must carry no witness");
    BOOST_REQUIRE_MESSAGE(m2.vin[0].scriptSig.empty(),
        "and no scriptSig, which is what makes the fallback find nothing");
    BOOST_CHECK_MESSAGE(!CTransaction(m2).HasDilithiumSignatures(),
        "with neither a witness nor a scriptSig push there is no blob to test");

    BOOST_CHECK_EQUAL(RejectReasonFor({m2}), "bad-txns-requires-dilithium");
}

// The same transaction plus one scriptSig push, which is all it takes to clear
// CheckTransaction and put the null-witness arm on the path. Measured emit
// site: "has no witness on authority input".
BOOST_AUTO_TEST_CASE(chained_btcsoq_mint_with_a_scriptsig_in_place_of_the_authority_witness_is_rejected)
{
    CMutableTransaction m1 = BuildMint(coinbaseTxns[0], AUTHSIG_DEPOSIT_A, 0, coinbasePk);
    const uint256 m1Hash = CTransaction(m1).GetHash();
    CBlock b1 = CreateAndProcessBlock({m1}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == b1.GetHash());
    COutPoint marker(m1Hash, 0);

    CMutableTransaction m2 =
        BuildMint(coinbaseTxns[1], AUTHSIG_DEPOSIT_B, 1, coinbasePk, &marker);
    m2.vin[0].scriptWitness.stack.clear();
    // Not a public key and not 1313 bytes. The per-input fallback tests the
    // first byte and the first byte only.
    m2.vin[0].scriptSig = CScript() << std::vector<unsigned char>{0x00, 0xab, 0xcd};
    // Load-bearing: without the skip, the empty witness plus a non-empty
    // scriptSig on a native witness program also fails script verification, and
    // the case would no longer isolate the authority rule.
    m2.vin[1].scriptWitness.stack = DecoyStack(BTCSOQ_OP_MINT);

    BOOST_CHECK_MESSAGE(CTransaction(m2).HasDilithiumSignatures(),
        "the scriptSig fallback must be satisfied, or this case degenerates "
        "into the bad-txns-requires-dilithium case above");

    BOOST_CHECK_EQUAL(RejectReasonFor({m2}), "bad-btcsoq-authority-sig");
}

// The third emit site: a witness that survives extraction with zero signatures.
// ExtractBTCSOQWitnessSignatures selects items of exactly DILITHIUM_SIG_SIZE
// from indices [4, size-1), so a six-item stack carrying the correct op tag and
// no 2420-byte item passes the tag check and arrives at the verifier empty.
// Measured emit site: "has no signatures in witness". Distinct from the
// below-threshold case, which keeps one real signature and reaches M-of-N
// verification -- both assert the same string, and only the error() text tells
// them apart.
BOOST_AUTO_TEST_CASE(chained_btcsoq_mint_with_no_extractable_signatures_is_rejected)
{
    CMutableTransaction m1 = BuildMint(coinbaseTxns[0], AUTHSIG_DEPOSIT_A, 0, coinbasePk);
    const uint256 m1Hash = CTransaction(m1).GetHash();
    CBlock b1 = CreateAndProcessBlock({m1}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == b1.GetHash());
    COutPoint marker(m1Hash, 0);

    CMutableTransaction m2 =
        BuildMint(coinbaseTxns[1], AUTHSIG_DEPOSIT_B, 1, coinbasePk, &marker);

    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(std::vector<unsigned char>{0x00});             // [0] payout_sig
    stack.push_back(std::vector<unsigned char>{0x00});             // [1] payout_pk
    stack.push_back(std::vector<unsigned char>{BTCSOQ_OP_MINT});   // [2] op tag
    stack.push_back(std::vector<unsigned char>{0x00});             // [3] payload
    stack.push_back(std::vector<unsigned char>{0x00});             // [4] not a sig
    stack.push_back(std::vector<unsigned char>{0x00});             // [5] authority_set
    m2.vin[0].scriptWitness.stack = stack;
    m2.vin[1].scriptWitness.stack = DecoyStack(BTCSOQ_OP_MINT);

    // The tag check must pass, or this case asserts bad-btcsoq-tag-mismatch and
    // never reaches the extractor.
    BOOST_REQUIRE_EQUAL(GetBTCSOQWitnessTag(m2.vin[0].scriptWitness.stack),
                        BTCSOQ_OP_MINT);
    BOOST_REQUIRE_EQUAL(
        ExtractBTCSOQWitnessSignatures(m2.vin[0].scriptWitness.stack).size(), 0u);

    BOOST_CHECK_EQUAL(RejectReasonFor({m2}), "bad-btcsoq-authority-sig");
}

// bad-txns-dual-authority-marker. Each marker grants its own asset's ex-nihilo
// exemption, so a transaction carrying both would need stacked exemptions
// reasoned about; it is invalid instead. Untested until now.
//
// Note the order, because the natural reading of this rule is backwards. It
// does NOT keep a v9 transaction away from the OP_5 exemption. The exemption
// is granted first: HasDilithiumSignatures is called from CheckTransaction,
// and the whole-transaction OP_5 carve-out is applied there, well before this
// rule is reached later in the same function. So a v9 authority transaction
// carrying a v5 marker output IS granted the OP_5 exemption, and is then
// rejected for a different reason entirely. Same outcome, different mechanism,
// and only the mechanism tells a reader what breaks if the rule is removed.
BOOST_AUTO_TEST_CASE(an_authority_tx_carrying_both_asset_markers_is_rejected)
{
    CMutableTransaction m1 = BuildMint(coinbaseTxns[0], AUTHSIG_DEPOSIT_A, 0, coinbasePk);
    const uint256 m1Hash = CTransaction(m1).GetHash();
    CBlock b1 = CreateAndProcessBlock({m1}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == b1.GetHash());
    COutPoint marker(m1Hash, 0);

    CMutableTransaction m2 =
        BuildMint(coinbaseTxns[1], AUTHSIG_DEPOSIT_B, 1, coinbasePk, &marker);

    // Splice a USDSOQ v5 marker in beside the BTCSOQ v9 one, funded from change.
    uint256 kh;
    CSHA256().Write(coinbasePk.data(), coinbasePk.size()).Finalize(kh.begin());
    CScript v5spk = CScript() << OP_5 << std::vector<unsigned char>(kh.begin(), kh.end());
    m2.vout.back().nValue -= 10000;
    m2.vout.push_back(CTxOut(10000, v5spk));
    SignV1(m2, 1, coinbaseSpk, coinbaseTxns[1].vout[0].nValue, coinbaseKey, coinbasePk);
    SignAuthority(m2, 0, BTCSOQ_OP_MINT);

    BOOST_CHECK_EQUAL(RejectReasonFor({m2}), "bad-txns-dual-authority-marker");
}

BOOST_AUTO_TEST_CASE(btcsoq_witness_tag_must_match_the_signed_op_tag)
{
    CMutableTransaction m1 = BuildMint(coinbaseTxns[0], AUTHSIG_DEPOSIT_A, 0, coinbasePk);
    const uint256 m1Hash = CTransaction(m1).GetHash();
    CBlock b1 = CreateAndProcessBlock({m1}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == b1.GetHash());
    COutPoint marker(m1Hash, 0);

    CMutableTransaction m2 =
        BuildMint(coinbaseTxns[1], AUTHSIG_DEPOSIT_B, 1, coinbasePk, &marker);

    // The signed OP_RETURN still says MINT. Only the unsigned witness tag moves,
    // which is the whole reason the equality check exists: the witness is not
    // sighash-covered and is malleable in flight.
    m2.vin[0].scriptWitness.stack[2] = std::vector<unsigned char>{BTCSOQ_OP_FREEZE};

    BOOST_CHECK_EQUAL(RejectReasonFor({m2}), "bad-btcsoq-tag-mismatch");
}

BOOST_AUTO_TEST_CASE(btcsoq_authority_tx_without_an_op_envelope_is_rejected)
{
    CMutableTransaction m1 = BuildMint(coinbaseTxns[0], AUTHSIG_DEPOSIT_A, 0, coinbasePk);
    const uint256 m1Hash = CTransaction(m1).GetHash();
    CBlock b1 = CreateAndProcessBlock({m1}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == b1.GetHash());
    COutPoint marker(m1Hash, 0);

    CMutableTransaction m2 =
        BuildMint(coinbaseTxns[1], AUTHSIG_DEPOSIT_B, 1, coinbasePk, &marker);

    // BuildMint lays out [0] marker, [1] v8 mint, [2] op envelope, [3] change.
    BOOST_REQUIRE_EQUAL(m2.vout.size(), 4u);
    m2.vout.erase(m2.vout.begin() + 2);
    // Re-sign: removing an output changes the SIGHASH_ALL sighash for the fee
    // input as well as the authority input, and an authority-sig rejection
    // would then shadow the missing-op rule.
    ReSignChainedAuthority(m2, coinbaseTxns[1], BTCSOQ_OP_MINT);

    BOOST_CHECK_EQUAL(RejectReasonFor({m2}), "bad-btcsoq-missing-op");
}

// Asset flows must match the signed op: v8 outputs may only be created under
// MINT. Here a FREEZE-tagged authority tx carries a v8 output.
BOOST_AUTO_TEST_CASE(btcsoq_v8_output_under_a_non_mint_op_is_rejected)
{
    CMutableTransaction m1 = BuildMint(coinbaseTxns[0], AUTHSIG_DEPOSIT_A, 0, coinbasePk);
    const uint256 m1Hash = CTransaction(m1).GetHash();
    CBlock b1 = CreateAndProcessBlock({m1}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == b1.GetHash());
    COutPoint marker(m1Hash, 0);
    COutPoint v8op(m1Hash, 1);

    CMutableTransaction fz = BuildFreeze(coinbaseTxns[1], FREEZE_OP_FREEZE, v8op, &marker);
    // Splice a v8 output into an otherwise valid FREEZE, funded out of the
    // change, then re-sign so the rejection is the op binding and not the sig.
    BOOST_REQUIRE_EQUAL(fz.vout.size(), 3u);
    fz.vout.back().nValue -= MINT_SATS;
    fz.vout.push_back(CTxOut(MINT_SATS, MakeV8Spk(coinbasePk)));
    SignV1(fz, 1, coinbaseSpk, coinbaseTxns[1].vout[0].nValue, coinbaseKey, coinbasePk);
    SignAuthority(fz, 0, BTCSOQ_OP_FREEZE);

    BOOST_CHECK_EQUAL(RejectReasonFor({fz}), "bad-btcsoq-unbound-mint");
}

BOOST_AUTO_TEST_SUITE_END()
