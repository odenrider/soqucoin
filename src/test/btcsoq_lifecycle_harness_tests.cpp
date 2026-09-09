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

static const uint256 OPBIND_DEPOSIT_A = uint256S(
    "bccc00000000000000000000000000000000000000000000000000000000b001");
static const uint256 OPBIND_DEPOSIT_B = uint256S(
    "bccc00000000000000000000000000000000000000000000000000000000b002");
static const uint256 OPBIND_RELEASE = uint256S(
    "b0de00000000000000000000000000000000000000000000000000000000b0de");

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

    //! Establish the authority chain with one accepted BOOTSTRAP mint of
    //! `deposit` at vout 0, and return the mint txid: the marker is at (txid, 0)
    //! and the minted v8 at (txid, 1). Every case below then starts from a
    //! CHAINED transaction, the shape every later authority transaction has.
    uint256 SeedAuthorityChain(const CTransaction& fund, const uint256& deposit)
    {
        CMutableTransaction m = BuildMint(fund, deposit, 0, coinbasePk);
        const uint256 h = CTransaction(m).GetHash();
        CBlock b = CreateAndProcessBlock({m}, coinbaseSpk);
        BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == b.GetHash());
        return h;
    }

    //! A BURN authority tx chained off the mint at `mintHash`: vin[0] is the
    //! tracked marker, vin[1] the SOQ fee, and vin[2] the minted v8 when
    //! `spendV8`. `burnSats` goes into the signed payload verbatim, so a caller
    //! can drive both the payload parse and the intent-mismatch rule.
    //! `v8Override` burns a v8 coin other than the mint's own output, which is
    //! how a caller reaches the supply-underflow guard: see the reachability
    //! note above that case.
    CMutableTransaction BuildBurn(const CTransaction& fundCoinbase, const uint256& mintHash,
                                  CAmount burnSats, bool spendV8,
                                  const COutPoint* v8Override = nullptr,
                                  CAmount v8Value = MINT_SATS)
    {
        CMutableTransaction tx; tx.nVersion = 2;
        const CAmount fund = fundCoinbase.vout[0].nValue;

        CTxIn mk; mk.prevout = COutPoint(mintHash, 0); mk.nSequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.push_back(mk);
        CTxIn fee; fee.prevout = COutPoint(fundCoinbase.GetHash(), 0);
        fee.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(fee);
        if (spendV8) {
            CTxIn v8;
            v8.prevout = v8Override ? *v8Override : COutPoint(mintHash, 1);
            v8.nSequence = CTxIn::SEQUENCE_FINAL;
            tx.vin.push_back(v8);
        }

        std::vector<uint8_t> payload = BuildBTCSOQBurnPayload(OPBIND_RELEASE, burnSats);
        tx.vout.push_back(CTxOut(0, markerSpk));
        tx.vout.push_back(CTxOut(0, MakeOpEnvelope(BTCSOQ_OP_BURN, payload)));
        tx.vout.push_back(CTxOut(fund - 10000, coinbaseSpk));

        SignV1(tx, 1, coinbaseSpk, fund, coinbaseKey, coinbasePk);
        if (spendV8)
            SignV1(tx, 2, MakeV8Spk(coinbasePk), v8Value, coinbaseKey, coinbasePk);
        SignAuthority(tx, 0, BTCSOQ_OP_BURN);
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
// AUTHORITY-SIGNATURE REJECT PATHS.
//
// bad-btcsoq-authority-sig, bad-btcsoq-tag-mismatch, bad-btcsoq-missing-op,
// bad-btcsoq-unbound-mint and bad-btcsoq-unbound-burn. The cases above this
// block all sign with the real authority; these drive a wrong or missing
// signature and assert the exact reject string.
//
// bad-btcsoq-authority-sig is emitted at several sites, so asserting the string
// alone does not say which rule ran. In ConnectBlock the sites are, in the
// order a transaction meets them: the marker prevout unavailable in both the
// view and the block undo; a null witness on the authority input; an empty
// signature set after extraction; and M-of-N verification failing. The mempool
// path mirrors them. Sites are named by their error() text rather than by line
// number, and each case below was attributed to its site by reading the text
// it produced. The prevout-unavailable site has no case here.
// ===========================================================================

//! An authority-shaped witness stack whose signature slots hold filler.
//! Carried on the FEE input by any case that empties the authority input's
//! witness, so that the case is rejected by the rule under test and not by
//! per-input script verification of the fee input.
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

// THE NULL-WITNESS ARM. ConnectBlock rejects a BTCSOQ authority transaction
// whose authority input carries no witness ("has no witness on authority
// input"). Which rule rejects such a transaction depends on what
// CheckTransaction does with it first.
//
// CTransaction::HasDilithiumSignatures runs from CheckTransaction and requires
// every input to present a blob whose first byte is 0x00. For an input with a
// witness it reads the witness stack's last item. For an input with no witness
// it applies the same test to the scriptSig's last push. So:
//
//   empty scriptSig       -> no blob at all -> bad-txns-requires-dilithium,
//                            and the authority block never runs
//   scriptSig <0x00...>   -> CheckTransaction passes -> the authority block
//                            runs and the null-witness arm rejects
//
// Both cases are kept, and each asserts the string it produces.
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

    // No decoy on the fee input here: this transaction is rejected in
    // CheckTransaction, before any per-input verification, so a decoy would
    // be inert.
    BOOST_REQUIRE_MESSAGE(m2.vin[0].scriptWitness.IsNull(),
        "the authority input must carry no witness");
    BOOST_REQUIRE_MESSAGE(m2.vin[0].scriptSig.empty(),
        "and no scriptSig, which is what makes the fallback find nothing");
    BOOST_CHECK_MESSAGE(!CTransaction(m2).HasDilithiumSignatures(),
        "with neither a witness nor a scriptSig push there is no blob to test");

    BOOST_CHECK_EQUAL(RejectReasonFor({m2}), "bad-txns-requires-dilithium");
}

// The same transaction with a 0x00-leading scriptSig push, so CheckTransaction
// passes and the null-witness arm is reached. Emit site: "has no witness on
// authority input".
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
    // Not a public key and not 1313 bytes; only the first byte is tested.
    m2.vin[0].scriptSig = CScript() << std::vector<unsigned char>{0x00, 0xab, 0xcd};
    // Keeps the fee input from failing script verification first, which would
    // stop the case isolating the authority rule.
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
// Emit site: "has no signatures in witness". Distinct from the below-threshold
// case, which keeps one real signature and reaches M-of-N verification.
//
// Removing the empty-signature guard does not fail this case:
// CBTCSOQAuthority::VerifyAuthoritySignatures rejects an empty set itself, one
// site later, with the same string. The case is kept because it pins that the
// input shape is rejected and that the verifier is not vacuous on an empty set.
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
// exemption, so a transaction carrying both is invalid rather than reasoned
// about. The rule is checked in CheckTransaction after HasDilithiumSignatures,
// so the rejection asserted here comes from this rule and not from a signature
// check.
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
    ReSignChainedAuthority(m2, coinbaseTxns[1], BTCSOQ_OP_MINT);

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
    ReSignChainedAuthority(fz, coinbaseTxns[1], BTCSOQ_OP_FREEZE);

    BOOST_CHECK_EQUAL(RejectReasonFor({fz}), "bad-btcsoq-unbound-mint");
}

// ===========================================================================
// MINT/BURN OP-BINDING REJECT PATHS. The rules that bind a mint to a Bitcoin
// deposit and a burn to a release intent.
//
// bad-btcsoq-mint-payload and bad-btcsoq-burn-payload are reached only through
// the amount field. ParseBTCSOQAuthorityOp requires the OP_RETURN push to be
// exactly 1 + BTCSOQOpPayloadLen(tag) bytes, so a length malformation is
// reported as bad-btcsoq-missing-op before the op-specific parse runs. The two
// payload cases below therefore drive the sats field rather than truncating
// the payload, which would assert the wrong rule.
// ===========================================================================


// ---- MINT binding ---------------------------------------------------------

// The envelope length check passes and the amount field does not: sats == 0.
BOOST_AUTO_TEST_CASE(btcsoq_mint_payload_with_a_non_positive_amount_is_rejected)
{
    const uint256 m1 = SeedAuthorityChain(coinbaseTxns[0], OPBIND_DEPOSIT_A);
    COutPoint marker(m1, 0);

    CMutableTransaction m2 =
        BuildMint(coinbaseTxns[1], OPBIND_DEPOSIT_B, 1, coinbasePk, &marker);

    std::vector<uint8_t> zeroSats = BuildBTCSOQMintPayload(
        OPBIND_DEPOSIT_B, 1, 0, ComputeBTCSOQRecipientCommitment(MakeV8Spk(coinbasePk)));
    BOOST_REQUIRE_EQUAL(zeroSats.size(), BTCSOQ_MINT_PAYLOAD_LEN);
    m2.vout[2] = CTxOut(0, MakeOpEnvelope(BTCSOQ_OP_MINT, zeroSats));
    ReSignChainedAuthority(m2, coinbaseTxns[1], BTCSOQ_OP_MINT);

    BOOST_CHECK_EQUAL(RejectReasonFor({m2}), "bad-btcsoq-mint-payload");
}

// One deposit backs exactly one v8 output. A second v8 output would let one
// attested deposit mint twice its sats in a single transaction.
BOOST_AUTO_TEST_CASE(btcsoq_mint_with_two_v8_outputs_is_rejected)
{
    const uint256 m1 = SeedAuthorityChain(coinbaseTxns[0], OPBIND_DEPOSIT_A);
    COutPoint marker(m1, 0);

    CMutableTransaction m2 =
        BuildMint(coinbaseTxns[1], OPBIND_DEPOSIT_B, 1, coinbasePk, &marker);
    m2.vout.back().nValue -= MINT_SATS;   // fund the extra output out of the SOQ change
    m2.vout.push_back(CTxOut(MINT_SATS, MakeV8Spk(coinbasePk)));
    ReSignChainedAuthority(m2, coinbaseTxns[1], BTCSOQ_OP_MINT);

    BOOST_CHECK_EQUAL(RejectReasonFor({m2}), "bad-btcsoq-mint-outputs");
}

// The minted amount must equal the attested deposit, to the base unit.
BOOST_AUTO_TEST_CASE(btcsoq_mint_output_value_must_equal_the_attested_deposit)
{
    const uint256 m1 = SeedAuthorityChain(coinbaseTxns[0], OPBIND_DEPOSIT_A);
    COutPoint marker(m1, 0);

    CMutableTransaction m2 =
        BuildMint(coinbaseTxns[1], OPBIND_DEPOSIT_B, 1, coinbasePk, &marker);
    m2.vout[1].nValue = MINT_SATS + 1;   // the payload still commits MINT_SATS
    ReSignChainedAuthority(m2, coinbaseTxns[1], BTCSOQ_OP_MINT);

    BOOST_CHECK_EQUAL(RejectReasonFor({m2}), "bad-btcsoq-mint-amount");
}

// The recipient commitment is what stops an authority signature from being
// replayed to a different recipient, so redirecting the v8 output must fail.
BOOST_AUTO_TEST_CASE(btcsoq_mint_recipient_must_match_the_signed_commitment)
{
    const uint256 m1 = SeedAuthorityChain(coinbaseTxns[0], OPBIND_DEPOSIT_A);
    COutPoint marker(m1, 0);

    CMutableTransaction m2 =
        BuildMint(coinbaseTxns[1], OPBIND_DEPOSIT_B, 1, coinbasePk, &marker);

    CKey thief; thief.MakeNewKey(true);
    std::vector<unsigned char> thiefPk(thief.GetPubKey().begin(), thief.GetPubKey().end());
    m2.vout[1].scriptPubKey = MakeV8Spk(thiefPk);   // value unchanged, so only the commitment can reject
    ReSignChainedAuthority(m2, coinbaseTxns[1], BTCSOQ_OP_MINT);

    BOOST_CHECK_EQUAL(RejectReasonFor({m2}), "bad-btcsoq-mint-recipient");
}

// Anti-replay, PERSISTED arm: the deposit is already in the minted set on disk.
// The existing double_mint_rejected case asserts only that the tip did not move,
// which passes for the wrong reject as readily as for the right one.
BOOST_AUTO_TEST_CASE(btcsoq_double_mint_is_rejected_by_name)
{
    const uint256 m1 = SeedAuthorityChain(coinbaseTxns[0], OPBIND_DEPOSIT_A);
    COutPoint marker(m1, 0);

    CMutableTransaction m2 =
        BuildMint(coinbaseTxns[1], OPBIND_DEPOSIT_A, 0, coinbasePk, &marker);

    BOOST_CHECK_EQUAL(RejectReasonFor({m2}), "bad-btcsoq-double-mint");
}

// Anti-replay, IN-BLOCK arm: neither mint is on disk yet, so only the
// per-block blockMintedDeposits set can catch the second one. A test that
// exercised the persisted arm alone would leave this one unmeasured.
BOOST_AUTO_TEST_CASE(two_mints_of_one_deposit_in_the_same_block_are_rejected)
{
    CMutableTransaction m1 = BuildMint(coinbaseTxns[0], OPBIND_DEPOSIT_A, 0, coinbasePk);
    COutPoint marker(CTransaction(m1).GetHash(), 0);
    CMutableTransaction m2 =
        BuildMint(coinbaseTxns[1], OPBIND_DEPOSIT_A, 0, coinbasePk, &marker);

    BOOST_CHECK_EQUAL(RejectReasonFor({m1, m2}), "bad-btcsoq-double-mint");
}

// ---- BURN binding ---------------------------------------------------------

// Same narrow window as the mint payload: correctly sized, sats == 0.
BOOST_AUTO_TEST_CASE(btcsoq_burn_payload_with_a_non_positive_amount_is_rejected)
{
    const uint256 m1 = SeedAuthorityChain(coinbaseTxns[0], OPBIND_DEPOSIT_A);
    CMutableTransaction bn = BuildBurn(coinbaseTxns[1], m1, /*burnSats=*/0,
                                       /*spendV8=*/true);
    BOOST_CHECK_EQUAL(RejectReasonFor({bn}), "bad-btcsoq-burn-payload");
}

// A BURN that destroys nothing. Without this rule the authority could record a
// release intent on Bitcoin against no burned supply at all.
BOOST_AUTO_TEST_CASE(btcsoq_burn_with_no_v8_inputs_is_rejected)
{
    const uint256 m1 = SeedAuthorityChain(coinbaseTxns[0], OPBIND_DEPOSIT_A);
    CMutableTransaction bn = BuildBurn(coinbaseTxns[1], m1, MINT_SATS,
                                       /*spendV8=*/false);
    BOOST_CHECK_EQUAL(RejectReasonFor({bn}), "bad-btcsoq-burn-empty");
}

// The signed release intent must equal the consensus burn, so the gateway can
// never be told to release more than was destroyed.
BOOST_AUTO_TEST_CASE(btcsoq_burn_intent_must_equal_the_v8_input_sum)
{
    const uint256 m1 = SeedAuthorityChain(coinbaseTxns[0], OPBIND_DEPOSIT_A);
    CMutableTransaction bn = BuildBurn(coinbaseTxns[1], m1, MINT_SATS - 1,
                                       /*spendV8=*/true);
    BOOST_CHECK_EQUAL(RejectReasonFor({bn}), "bad-btcsoq-burn-amount");
}

// Asset flows must match the signed op in the other direction too: v8 inputs
// may only be spent under BURN. Here a FREEZE-tagged authority tx spends one.
BOOST_AUTO_TEST_CASE(btcsoq_v8_inputs_under_a_non_burn_op_are_rejected)
{
    const uint256 m1 = SeedAuthorityChain(coinbaseTxns[0], OPBIND_DEPOSIT_A);
    COutPoint marker(m1, 0), v8(m1, 1);

    CMutableTransaction fz = BuildFreeze(coinbaseTxns[1], FREEZE_OP_FREEZE, v8, &marker);
    CTxIn in; in.prevout = v8; in.nSequence = CTxIn::SEQUENCE_FINAL;
    fz.vin.push_back(in);   // vin[2] = the minted v8, spent under FREEZE
    SignV1(fz, 2, MakeV8Spk(coinbasePk), MINT_SATS, coinbaseKey, coinbasePk);
    ReSignChainedAuthority(fz, coinbaseTxns[1], BTCSOQ_OP_FREEZE);

    BOOST_CHECK_EQUAL(RejectReasonFor({fz}), "bad-btcsoq-unbound-burn");
}

// ---- FREEZE binding -------------------------------------------------------

// The freeze op byte inside the envelope is not the envelope tag, and only
// FREEZE/UNFREEZE are defined. An unknown byte must not fall through to a
// default action on a live outpoint.
BOOST_AUTO_TEST_CASE(btcsoq_freeze_with_an_unknown_op_byte_is_rejected)
{
    const uint256 m1 = SeedAuthorityChain(coinbaseTxns[0], OPBIND_DEPOSIT_A);
    COutPoint marker(m1, 0), v8(m1, 1);

    CMutableTransaction fz = BuildFreeze(coinbaseTxns[1], 0x7f, v8, &marker);
    BOOST_CHECK_EQUAL(RejectReasonFor({fz}), "bad-btcsoq-freeze-payload");
}

// ---- The presence control for every case above --------------------------

// PRESENCE CONTROLS. Each of the twelve cases above mutates one field of a
// chained authority tx and asserts one exact reject string. If the unmutated
// shape were itself invalid, those cases could pass for the wrong reason and
// nothing in the suite would say so.
//
// The twelve do not share one baseline, so one control does not cover them.
// Six are built by BuildMint, three by BuildBurn and three by BuildFreeze, and
// each builder needs its own accepted case:
//
//   BuildMint     the_unmutated_chained_btcsoq_mint_is_accepted, below
//   BuildBurn     the_unmutated_chained_btcsoq_burn_is_accepted, below
//   BuildFreeze   freezing_a_live_btcsoq_utxo_is_accepted, already in this file
//
// Each asserts the EMPTY reject reason, so each fails if its baseline ever
// stops connecting.
BOOST_AUTO_TEST_CASE(the_unmutated_chained_btcsoq_mint_is_accepted)
{
    const uint256 m1 = SeedAuthorityChain(coinbaseTxns[0], OPBIND_DEPOSIT_A);
    COutPoint marker(m1, 0);

    CMutableTransaction m2 =
        BuildMint(coinbaseTxns[1], OPBIND_DEPOSIT_B, 1, coinbasePk, &marker);

    BOOST_CHECK_EQUAL(RejectReasonFor({m2}), "");
}

// The BuildBurn baseline: the burn amount equals the v8 input sum and the v8
// input is present, which are the two fields the three burn cases mutate.
BOOST_AUTO_TEST_CASE(the_unmutated_chained_btcsoq_burn_is_accepted)
{
    const uint256 m1 = SeedAuthorityChain(coinbaseTxns[0], OPBIND_DEPOSIT_A);

    CMutableTransaction bn = BuildBurn(coinbaseTxns[1], m1, MINT_SATS,
                                       /*spendV8=*/true);

    BOOST_CHECK_EQUAL(RejectReasonFor({bn}), "");
}

// ===========================================================================
// SUPPLY AND BOOTSTRAP INVARIANT GUARDS.
//
// Three of the four rules below fire only on an authority or accounting error
// or on a damaged local state, so their cases inject that state and prove the
// guard fires. The fourth, bad-btcsoq-authority-outpoint, needs no injected
// state.
//
//   bad-btcsoq-supply-overflow — CBTCSOQSupply::Mint fails when total_minted
//     plus the mint leaves MoneyRange. The counter is cumulative and persisted:
//     ConnectBlock copies the global, adds the block's mints, and commits the
//     copy on connect. Every mint that moves it carries M-of-N authority
//     signatures. Reached below by preloading the counter.
//
//   bad-btcsoq-supply-underflow — CBTCSOQSupply::Burn fails when total_burned
//     plus the burn exceeds total_minted. Every v8 UTXO on a real chain was
//     counted into total_minted when created, so a block's v8 inputs sum to at
//     most the outstanding supply. Reached below by injecting a v8 coin that no
//     mint produced.
//
//   bad-btcsoq-bootstrap-reentry — the database holds an authority outpoint
//     while the in-memory global is null, which a partial reindex or a
//     corrupted datadir produces. Reached below by nulling the global and
//     leaving the database alone.
// ===========================================================================

// A valid authority witness on a transaction that does not continue the chain
// of custody. This rule is the only one that rejects the transaction below;
// the signatures on it are genuine.
//
// Note for mutation testing: removing the rejection alone leaves
// nAuthorityInputIndex at -1, and the next statement indexes tx.vin with it.
// A valid counterfactual falls back to the bootstrap treatment instead.
BOOST_AUTO_TEST_CASE(a_second_authority_tx_that_ignores_the_tracked_outpoint_is_rejected)
{
    SeedAuthorityChain(coinbaseTxns[0], OPBIND_DEPOSIT_A);

    // Bootstrap-SHAPED: no marker input at all, submitted while the tracked
    // outpoint is set. The authority signature is genuine; the only thing wrong
    // with the transaction is that it ignores the tracked UTXO.
    CMutableTransaction m2 = BuildMint(coinbaseTxns[1], OPBIND_DEPOSIT_B, 1, coinbasePk);

    BOOST_CHECK_EQUAL(RejectReasonFor({m2}), "bad-btcsoq-authority-outpoint");
}

BOOST_AUTO_TEST_CASE(btcsoq_supply_overflow_guard_fires_with_the_counter_at_the_ceiling)
{
    const uint256 m1 = SeedAuthorityChain(coinbaseTxns[0], OPBIND_DEPOSIT_A);
    COutPoint marker(m1, 0);

    {
        LOCK(cs_main);
        const CAmount headroom = MAX_MONEY - g_btcsoq_supply.TotalMinted() - 1;
        BOOST_REQUIRE(g_btcsoq_supply.Mint(headroom));
        BOOST_REQUIRE_EQUAL(g_btcsoq_supply.TotalMinted(), MAX_MONEY - 1);
    }

    CMutableTransaction m2 =
        BuildMint(coinbaseTxns[1], OPBIND_DEPOSIT_B, 1, coinbasePk, &marker);

    BOOST_CHECK_EQUAL(RejectReasonFor({m2}), "bad-btcsoq-supply-overflow");
}

BOOST_AUTO_TEST_CASE(btcsoq_supply_underflow_guard_fires_on_a_v8_coin_no_mint_produced)
{
    const uint256 m1 = SeedAuthorityChain(coinbaseTxns[0], OPBIND_DEPOSIT_A);

    // Injected straight into the UTXO set, so nothing ever counted it into
    // total_minted. Burning it takes total_burned past total_minted.
    const CAmount phantom = MINT_SATS * 2;
    COutPoint ghost = SeedCoin(MakeV8Spk(coinbasePk), phantom, 0xb8);

    CMutableTransaction bn = BuildBurn(coinbaseTxns[1], m1, phantom, /*spendV8=*/true,
                                       &ghost, phantom);

    BOOST_CHECK_EQUAL(RejectReasonFor({bn}), "bad-btcsoq-supply-underflow");
}

BOOST_AUTO_TEST_CASE(btcsoq_bootstrap_reentry_is_rejected_while_the_database_holds_an_outpoint)
{
    SeedAuthorityChain(coinbaseTxns[0], OPBIND_DEPOSIT_A);

    {
        LOCK(cs_main);
        // Also the presence control for this case: it proves the accepted mint
        // really did persist an outpoint, so the reject below cannot come from
        // an empty database.
        COutPoint persisted;
        BOOST_REQUIRE(pcoinsdbview->ReadBTCSOQAuthorityOutpoint(persisted));
        BOOST_REQUIRE(!persisted.IsNull());
        g_btcsoq_authority_outpoint.SetNull();
    }

    CMutableTransaction m2 = BuildMint(coinbaseTxns[1], OPBIND_DEPOSIT_B, 1, coinbasePk);

    BOOST_CHECK_EQUAL(RejectReasonFor({m2}), "bad-btcsoq-bootstrap-reentry");
}

// ---- The frozen registry ---------------------------------------------------
//
// bad-txns-spend-frozen-btcsoq has two arms: the committed frozen set, and the
// block's own freeze/unfreeze ops overlaid on it. Each arm gets a case.

BOOST_AUTO_TEST_CASE(spending_a_frozen_btcsoq_utxo_is_rejected)
{
    const uint256 m1 = SeedAuthorityChain(coinbaseTxns[0], OPBIND_DEPOSIT_A);
    COutPoint marker(m1, 0), v8(m1, 1);

    CMutableTransaction fz = BuildFreeze(coinbaseTxns[1], FREEZE_OP_FREEZE, v8, &marker);
    CBlock bf = CreateAndProcessBlock({fz}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == bf.GetHash());
    {
        LOCK(cs_main);
        // Presence control: without this the reject below could come from an
        // empty registry and a different rule.
        BOOST_REQUIRE(pcoinsdbview->IsBTCSOQFrozen(v8));
    }

    // An ORDINARY transfer of the frozen coin — no authority, no marker, so the
    // frozen registry is the only thing that can reject it.
    const CAmount fund = coinbaseTxns[2].vout[0].nValue;
    CMutableTransaction xfer; xfer.nVersion = 2;
    CTxIn in; in.prevout = v8; in.nSequence = CTxIn::SEQUENCE_FINAL;
    xfer.vin.push_back(in);
    CTxIn fee; fee.prevout = COutPoint(coinbaseTxns[2].GetHash(), 0);
    fee.nSequence = CTxIn::SEQUENCE_FINAL; xfer.vin.push_back(fee);
    xfer.vout.push_back(CTxOut(MINT_SATS, MakeV8Spk(coinbasePk)));   // v8 in == v8 out
    xfer.vout.push_back(CTxOut(fund - 10000, coinbaseSpk));
    SignV1(xfer, 0, MakeV8Spk(coinbasePk), MINT_SATS, coinbaseKey, coinbasePk);
    SignV1(xfer, 1, coinbaseSpk, fund, coinbaseKey, coinbasePk);

    BOOST_CHECK_EQUAL(RejectReasonFor({xfer}), "bad-txns-spend-frozen-btcsoq");
}

// THE IN-BLOCK OVERLAY. Its two halves behave differently:
//
//   FREEZE + spend in ONE block  -> rejected as bad-btcsoq-freeze-dead-target.
//     ConnectBlock spends every input in a first pass, and the FREEZE target
//     liveness check reads the view in a later pass, by which time the spend
//     has been applied, so the target reads as dead. The frozen-spend arm is
//     not reached for this pair. The reverse transaction order cannot be built
//     here, because the burn spends the marker output the freeze creates.
//
//   UNFREEZE + spend in ONE block -> accepted. The UNFREEZE branch requires
//     only that the outpoint is frozen, so the in-block unfreeze lifts the
//     freeze for the spend in the same block.
//
// The first case pins the ordering so a change to the pass structure fails a
// test; the second is the positive control showing the overlay is consulted.
BOOST_AUTO_TEST_CASE(a_same_block_freeze_and_spend_dies_on_the_dead_target_instead)
{
    const uint256 m1 = SeedAuthorityChain(coinbaseTxns[0], OPBIND_DEPOSIT_A);
    COutPoint marker(m1, 0), v8(m1, 1);

    CMutableTransaction fz = BuildFreeze(coinbaseTxns[1], FREEZE_OP_FREEZE, v8, &marker);
    COutPoint marker2(CTransaction(fz).GetHash(), 0);

    // The burn continues the chain of custody from the FREEZE's marker.
    CMutableTransaction bn = BuildBurn(coinbaseTxns[2], m1, MINT_SATS, /*spendV8=*/true);
    bn.vin[0].prevout = marker2;
    SignV1(bn, 2, MakeV8Spk(coinbasePk), MINT_SATS, coinbaseKey, coinbasePk);  // v8, not in the helper
    ReSignChainedAuthority(bn, coinbaseTxns[2], BTCSOQ_OP_BURN);

    BOOST_CHECK_EQUAL(RejectReasonFor({fz, bn}), "bad-btcsoq-freeze-dead-target");
}

BOOST_AUTO_TEST_CASE(an_unfreeze_earlier_in_the_block_permits_the_spend)
{
    const uint256 m1 = SeedAuthorityChain(coinbaseTxns[0], OPBIND_DEPOSIT_A);
    COutPoint marker(m1, 0), v8(m1, 1);

    // Commit the freeze in its own block.
    CMutableTransaction fz = BuildFreeze(coinbaseTxns[1], FREEZE_OP_FREEZE, v8, &marker);
    const uint256 fzHash = CTransaction(fz).GetHash();
    CBlock bf = CreateAndProcessBlock({fz}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == bf.GetHash());
    {
        LOCK(cs_main);
        BOOST_REQUIRE(pcoinsdbview->IsBTCSOQFrozen(v8));
    }

    // Now UNFREEZE and spend in the SAME block.
    COutPoint marker3(fzHash, 0);
    CMutableTransaction uf =
        BuildFreeze(coinbaseTxns[2], FREEZE_OP_UNFREEZE, v8, &marker3);

    const CAmount fund = coinbaseTxns[3].vout[0].nValue;
    CMutableTransaction xfer; xfer.nVersion = 2;
    CTxIn in; in.prevout = v8; in.nSequence = CTxIn::SEQUENCE_FINAL;
    xfer.vin.push_back(in);
    CTxIn fee; fee.prevout = COutPoint(coinbaseTxns[3].GetHash(), 0);
    fee.nSequence = CTxIn::SEQUENCE_FINAL; xfer.vin.push_back(fee);
    xfer.vout.push_back(CTxOut(MINT_SATS, MakeV8Spk(coinbasePk)));
    xfer.vout.push_back(CTxOut(fund - 10000, coinbaseSpk));
    SignV1(xfer, 0, MakeV8Spk(coinbasePk), MINT_SATS, coinbaseKey, coinbasePk);
    SignV1(xfer, 1, coinbaseSpk, fund, coinbaseKey, coinbasePk);

    BOOST_CHECK_EQUAL(RejectReasonFor({uf, xfer}), "");
}

// ---- The marker chain ------------------------------------------------------
//
// bad-btcsoq-marker-spend rejects a non-authority transaction that spends the
// tracked marker outpoint. It is the mirror of bad-btcsoq-authority-outpoint,
// which rejects an authority transaction that does not spend it.
//
// The transaction below is an authority transaction in nothing but its input:
// isBTCSOQAuthorityTx is set solely by the presence of a v9 marker OUTPUT, and
// this one creates none, so it takes the non-authority path and reaches the
// rule. The USDSOQ twin is covered in usdsoq_marker_spend_tests.
BOOST_AUTO_TEST_CASE(an_ordinary_tx_must_not_spend_the_btcsoq_authority_marker)
{
    const uint256 m1 = SeedAuthorityChain(coinbaseTxns[0], OPBIND_DEPOSIT_A);
    COutPoint marker(m1, 0);

    const CAmount fund = coinbaseTxns[1].vout[0].nValue;
    CMutableTransaction steal; steal.nVersion = 2;
    CTxIn mk; mk.prevout = marker; mk.nSequence = CTxIn::SEQUENCE_FINAL;
    steal.vin.push_back(mk);
    CTxIn fee; fee.prevout = COutPoint(coinbaseTxns[1].GetHash(), 0);
    fee.nSequence = CTxIn::SEQUENCE_FINAL; steal.vin.push_back(fee);

    // No v9 output, so this is not an authority tx and no marker is recreated.
    steal.vout.push_back(CTxOut(fund - 10000, coinbaseSpk));

    SignV1(steal, 0, markerSpk, 0, coinbaseKey, coinbasePk);
    SignV1(steal, 1, coinbaseSpk, fund, coinbaseKey, coinbasePk);

    BOOST_REQUIRE_MESSAGE(CTransaction(steal).HasDilithiumSignatures(),
        "the tx must clear CheckTransaction, or the marker rule is never reached");

    BOOST_CHECK_EQUAL(RejectReasonFor({steal}), "bad-btcsoq-marker-spend");
}

BOOST_AUTO_TEST_SUITE_END()
