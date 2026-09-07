// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SOQ-INFRA-020: Genesis block and chainparams validation tests
// Pre-mainnet checklist items:
//   - Genesis PoW verification for all networks
//   - BIP34Height > 16 assertion (prevents OP_N encoding mismatch)
//   - Serialization consistency (genesis hash stability)

#include "chainparams.h"
#include "consensus/consensus.h"
#include "soqucoin.h"
#include "primitives/block.h"
#include "uint256.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <map>
#include <string>

BOOST_FIXTURE_TEST_SUITE(genesis_chainparams_tests, BasicTestingSetup)

// ============================================================================
// Genesis PoW Verification Tests
//
// These tests verify that the hardcoded genesis nonces produce valid
// proof-of-work hashes for each network. This catches the critical bug
// from Stagenet Issue #7: GetHash() vs GetPoWHash() confusion.
//
// If ANY of these tests fail after a serialization change, ALL genesis
// nonces must be re-mined before release.
// ============================================================================

BOOST_AUTO_TEST_CASE(regtest_genesis_pow_valid)
{
    SelectParams(CBaseChainParams::REGTEST);
    const CChainParams& params = Params();
    const CBlock& genesis = params.GenesisBlock();
    const Consensus::Params& consensus = params.GetConsensus(0);

    // Genesis hash matches hardcoded value
    BOOST_CHECK_EQUAL(genesis.GetHash().ToString(),
                      consensus.hashGenesisBlock.ToString());

    // PoW is valid (uses scrypt via GetPoWHash)
    BOOST_CHECK(CheckAuxPowProofOfWork(genesis, consensus));
}

BOOST_AUTO_TEST_CASE(stagenet_genesis_pow_valid)
{
    SelectParams(CBaseChainParams::STAGENET);
    const CChainParams& params = Params();
    const CBlock& genesis = params.GenesisBlock();
    const Consensus::Params& consensus = params.GetConsensus(0);

    // Genesis hash matches hardcoded value
    BOOST_CHECK_EQUAL(genesis.GetHash().ToString(),
                      consensus.hashGenesisBlock.ToString());

    // PoW is valid (uses scrypt via GetPoWHash — Issue #7 regression test)
    BOOST_CHECK(CheckAuxPowProofOfWork(genesis, consensus));
}

// Mainnet genesis became final at the 2026-09-02 ceremony (doc/GENESIS_CEREMONY.md),
// so its PoW test is enabled below. testnet3's nonce is still the inherited one and
// its test stays disabled until that network is ever re-mined.
//
// BOOST_AUTO_TEST_CASE(testnet3_genesis_pow_valid)

BOOST_AUTO_TEST_CASE(mainnet_genesis_pow_valid)
{
    SelectParams(CBaseChainParams::MAIN);
    const CChainParams& params = Params();
    const CBlock& genesis = params.GenesisBlock();
    const Consensus::Params& consensus = params.GetConsensus(0);

    // The ceremony pins, asserted here as well as in chainparams.cpp so a
    // regression is a test failure, not only a startup abort.
    BOOST_CHECK_EQUAL(genesis.GetHash().ToString(),
                      "0d828600816cbd7c23789660b53f90cb6ec7ff85540698e13845eb2d2f0486a8");
    BOOST_CHECK_EQUAL(genesis.hashMerkleRoot.ToString(),
                      "8c4364d66ab67d746ddf1c5e0a316da5af9bbf7dc27bdd02e06ea77aec88ed28");
    BOOST_CHECK_EQUAL(genesis.GetHash().ToString(),
                      consensus.hashGenesisBlock.ToString());

    // PoW is valid (uses scrypt via GetPoWHash)
    BOOST_CHECK(CheckAuxPowProofOfWork(genesis, consensus));
}

// ============================================================================
// Genesis Block Consistency Tests
//
// Verify that genesis block properties are sane and consistent.
// ============================================================================

BOOST_AUTO_TEST_CASE(regtest_genesis_merkle_root_consistent)
{
    SelectParams(CBaseChainParams::REGTEST);
    const CBlock& genesis = Params().GenesisBlock();

    // Genesis should have exactly 1 transaction (coinbase)
    BOOST_CHECK_EQUAL(genesis.vtx.size(), 1u);

    // Merkle root should match the single coinbase TX hash
    BOOST_CHECK_EQUAL(genesis.hashMerkleRoot.ToString(),
                      genesis.vtx[0]->GetHash().ToString());
}

BOOST_AUTO_TEST_CASE(stagenet_genesis_merkle_root_consistent)
{
    SelectParams(CBaseChainParams::STAGENET);
    const CBlock& genesis = Params().GenesisBlock();

    // Genesis should have exactly 1 transaction (coinbase)
    BOOST_CHECK_EQUAL(genesis.vtx.size(), 1u);

    // Merkle root should match the single coinbase TX hash
    BOOST_CHECK_EQUAL(genesis.hashMerkleRoot.ToString(),
                      genesis.vtx[0]->GetHash().ToString());
}

BOOST_AUTO_TEST_CASE(genesis_coinbase_outputs_have_correct_fields)
{
    // Phase 4: Verify genesis coinbase outputs are transparent native SOQ
    // via structural predicates (nVisibility/nAssetType bytes were removed).
    SelectParams(CBaseChainParams::STAGENET);
    const CBlock& genesis = Params().GenesisBlock();
    const CTransaction& coinbase = *genesis.vtx[0];

    BOOST_CHECK(coinbase.vout.size() >= 1);
    for (const auto& out : coinbase.vout) {
        // Genesis coinbase outputs must be transparent native SOQ
        BOOST_CHECK(out.IsNativeSOQ());
        BOOST_CHECK(!out.IsConfidential());
        BOOST_CHECK(!out.IsUSDSOQ());
    }
}

// ============================================================================
// BIP34Height Safety Tests
//
// BIP34 requires the block height to be serialized in the coinbase scriptSig.
// Heights <= 16 use OP_N opcodes (OP_1 through OP_16), but heights > 16 use
// CScriptNum push encoding. If BIP34Height is <= 16, there's an encoding
// ambiguity that can cause consensus splits.
//
// Reference: Stagenet Issues Log, derived from Issue #15
// ============================================================================

BOOST_AUTO_TEST_CASE(bip34_height_safety_regtest)
{
    SelectParams(CBaseChainParams::REGTEST);
    const Consensus::Params& consensus = Params().GetConsensus(0);

    // Regtest: BIP34 is set very high (100000000) to allow v1 blocks in tests
    // This is intentionally above 16, so the check passes trivially
    BOOST_CHECK_GT(consensus.BIP34Height, 16);
}

BOOST_AUTO_TEST_CASE(bip34_height_safety_stagenet)
{
    SelectParams(CBaseChainParams::STAGENET);
    const Consensus::Params& consensus = Params().GetConsensus(0);

    // Stagenet: Must be > 16 to avoid OP_N mismatch
    BOOST_CHECK_GT(consensus.BIP34Height, 16);
}

BOOST_AUTO_TEST_CASE(bip34_height_safety_mainnet)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensus = Params().GetConsensus(0);

    // Mainnet: Must be > 16 — this is the most critical assertion
    BOOST_CHECK_GT(consensus.BIP34Height, 16);
}

BOOST_AUTO_TEST_CASE(bip34_height_safety_testnet3)
{
    SelectParams(CBaseChainParams::TESTNET);
    const Consensus::Params& consensus = Params().GetConsensus(0);

    // Testnet3: Must be > 16
    BOOST_CHECK_GT(consensus.BIP34Height, 16);
}

BOOST_AUTO_TEST_CASE(launch_ibd_thresholds_are_zero_on_every_network)
{
    // nMinimumChainWork is an IBD heuristic, and IsInitialBlockDownload()
    // gates the work-serving RPCs (getblocktemplate exempts only
    // stagenet/regtest; AuxMiningCheck exempts nothing). An unreachable
    // value therefore latches every fresh node in IBD and no node can serve
    // mining work: the chain never leaves height 0. Mainnet shipped exactly
    // that (the upstream pin for upstream block 5,050,000) until the Phase A
    // pre-launch audit drove it on 2026-08-29. Both fields stay 0x00 until a
    // post-launch release re-pins them from a live Soqucoin mainnet node
    // (doc/release-process.md).
    const std::map<std::string, std::string> networks = {
        {CBaseChainParams::MAIN, "main"},
        {CBaseChainParams::TESTNET, "test"},
        {CBaseChainParams::REGTEST, "regtest"},
        {CBaseChainParams::STAGENET, "stagenet"},
    };
    for (const auto& net : networks) {
        SelectParams(net.first);
        const Consensus::Params& consensus = Params().GetConsensus(0);
        BOOST_CHECK_MESSAGE(consensus.nMinimumChainWork == uint256S("0x00"),
            net.second + ": nMinimumChainWork must be zero pre-launch, got " +
            consensus.nMinimumChainWork.ToString());
        BOOST_CHECK_MESSAGE(consensus.defaultAssumeValid == uint256S("0x00"),
            net.second + ": defaultAssumeValid must be zero pre-launch, got " +
            consensus.defaultAssumeValid.ToString());
    }
}

// Stagenet mirrors mainnet's effective coinbase maturity from height 100,000,
// HEIGHT-GATED so historical spends of pre-gate coinbases stay valid and the
// stagenet history replay is unaffected (ruled 2026-08-29, bead
// maturity-tier-doc-divergence-x48g). Maturity is read from the tier at the
// COINBASE's height, so the boundary below is about when a coinbase was MINED.
//
// ⛔ THE MIRROR IS ASSERTED AGAINST MAINNET'S ACTUAL VALUE, NOT AGAINST A SECOND
// LITERAL. The earlier version of this case pinned 240 independently on both
// networks. That reads as a coupling but is not one: it is two separate facts
// that happen to agree, and the failure it cannot catch is the one that matters —
// somebody changes mainnet, updates the mainnet literal because that is the line
// the compiler pointed at, and the "mirror" silently stops mirroring. Reading the
// mainnet value at runtime makes drift impossible to express.
BOOST_AUTO_TEST_CASE(stagenet_maturity_mirrors_mainnet_from_the_gate_height)
{
    // Mainnet's effective maturity from height 1 — the value being mirrored.
    SelectParams(CBaseChainParams::MAIN);
    const uint32_t mainnetMaturity = Params().GetConsensus(1).nCoinbaseMaturity;
    BOOST_CHECK_EQUAL(Params().GetConsensus(1000000).nCoinbaseMaturity, mainnetMaturity);

    // One literal pin, so a silent change to mainnet still fails loudly here and
    // not only in the consensus digest. 288 == the finality horizon
    // (bead mainnet-maturity-240-not-30-mp5o); see
    // maturity_covers_finality_horizon_mainnet for why they must be equal.
    BOOST_CHECK_EQUAL(mainnetMaturity, 288u);

    SelectParams(CBaseChainParams::STAGENET);
    // Below the gate: the base tier, untouched so replayed history stays valid.
    BOOST_CHECK_EQUAL(Params().GetConsensus(0).nCoinbaseMaturity, 30);
    BOOST_CHECK_EQUAL(Params().GetConsensus(1).nCoinbaseMaturity, 30);
    BOOST_CHECK_EQUAL(Params().GetConsensus(100).nCoinbaseMaturity, 30);
    BOOST_CHECK_EQUAL(Params().GetConsensus(99999).nCoinbaseMaturity, 30);
    // At and above the gate: whatever mainnet does, exactly.
    BOOST_CHECK_EQUAL(Params().GetConsensus(100000).nCoinbaseMaturity, mainnetMaturity);
    BOOST_CHECK_EQUAL(Params().GetConsensus(100001).nCoinbaseMaturity, mainnetMaturity);
    BOOST_CHECK_EQUAL(Params().GetConsensus(1000000).nCoinbaseMaturity, mainnetMaturity);

    SelectParams(CBaseChainParams::MAIN);
}

// Every height-gated tier carries the chain's genesis fields. The tiers are
// built by copying the previous tier and then overriding a few fields, and the
// genesis hash and the Lattice-BP++ seed are assigned per tier AFTER the copies,
// so a tier that is copied early and not listed there silently carries a zero
// hash and a zero seed. That happened to the stagenet maturity-mirror tier
// (bead stagenet-mirror-tier-zeroed-genesis-lfll): GetConsensus(h >= 100000)
// reported hashGenesisBlock == 0, CheckBlockIndex would abort on it under
// -checkblockindex, and the consensus digest certified the zeroed tier as
// correct. This case reads the base tier at runtime and compares every sampled
// tier against it on every network, and also refuses an all-zero base so two
// zeroed sides cannot agree their way past it.
BOOST_AUTO_TEST_CASE(every_tier_carries_the_genesis_fields_on_every_network)
{
    const std::string nets[] = {CBaseChainParams::MAIN, CBaseChainParams::TESTNET,
                                CBaseChainParams::STAGENET, CBaseChainParams::REGTEST};
    // Every tier boundary in chainparams.cpp plus a point far above the last one.
    const int heights[] = {0, 1, 9, 10, 11, 19, 20, 21, 99, 100, 101, 1000,
                           99999, 100000, 100001, 1000000};
    for (const std::string& net : nets) {
        SelectParams(net);
        const Consensus::Params& base = Params().GetConsensus(0);
        BOOST_CHECK_MESSAGE(!base.hashGenesisBlock.IsNull(), net + ": base tier genesis hash is zero");
        bool seedAllZero = true;
        for (unsigned char b : base.latticeBPSeed) seedAllZero = seedAllZero && (b == 0);
        BOOST_CHECK_MESSAGE(!seedAllZero, net + ": base tier latticeBPSeed is all zero");
        for (int h : heights) {
            const Consensus::Params& tier = Params().GetConsensus(h);
            BOOST_CHECK_MESSAGE(tier.hashGenesisBlock == base.hashGenesisBlock,
                net + ": tier at height " + std::to_string(h) + " carries genesis hash " +
                tier.hashGenesisBlock.ToString() + ", base tier has " + base.hashGenesisBlock.ToString());
            BOOST_CHECK_MESSAGE(tier.latticeBPSeed == base.latticeBPSeed,
                net + ": tier at height " + std::to_string(h) + " carries a different latticeBPSeed");
        }
    }
    SelectParams(CBaseChainParams::MAIN);
}

// ============================================================================
// BIP9 Deployment Sanity Tests
//
// Verify that critical deployments are configured correctly on each network.
// ============================================================================

BOOST_AUTO_TEST_CASE(stagenet_critical_deployments_active)
{
    SelectParams(CBaseChainParams::STAGENET);
    const Consensus::Params& consensus = Params().GetConsensus(0);

    // PAT (bit 3) — must be ALWAYS_ACTIVE
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nStartTime,
                      Consensus::BIP9Deployment::ALWAYS_ACTIVE);

    // LatticeFold+ (bit 28) — RETIRED 2026-08-20, must NOT be active. Superseded
    // by SoquObscura. Mainnet had already withdrawn it (its verifier accepts an
    // all-zero witness, exactly like the SoquObscura range verifier below), while
    // stagenet was left ALWAYS_ACTIVE — so the mainnet REHEARSAL network was
    // validating under a rule mainnet refuses. Withdrawn here for the same reason
    // SoquObscura was. Full assertions live in
    // test/witness_version_allocation_tests.cpp.
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nStartTime, 0);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nTimeout, 0);

    // SoquObscura (bit 5) — WITHDRAWN 2026-08-17, must NOT be active. Its range
    // verifier accepts an all-zero witness carrying a correct Fiat-Shamir seed.
    // Full dormancy assertions live in test/soquobscura_withdrawal_tests.cpp.
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_SOQUOBSCURA].nStartTime, 0);
    BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(
        0, consensus, Consensus::DEPLOYMENT_SOQUOBSCURA));

    // USDSOQ (bit 6) — ALWAYS_ACTIVE on stagenet (Apr 28, 2026 activation)
    // Enables mint/burn/freeze testing. Mainnet remains NOT_ACTIVE pending audit.
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nStartTime,
                      Consensus::BIP9Deployment::ALWAYS_ACTIVE);
}

BOOST_AUTO_TEST_CASE(regtest_critical_deployments_active)
{
    SelectParams(CBaseChainParams::REGTEST);
    const Consensus::Params& consensus = Params().GetConsensus(0);

    // PAT and USDSOQ stay ALWAYS_ACTIVE on regtest.
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nStartTime,
                      Consensus::BIP9Deployment::ALWAYS_ACTIVE);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nStartTime,
                      Consensus::BIP9Deployment::ALWAYS_ACTIVE);

    // LatticeFold+ — RETIRED 2026-08-20, must NOT be active. Regtest is included
    // deliberately, on the same reasoning that included it in the SoquObscura
    // withdrawal below: leaving it active keeps every functional test running
    // against a verifier known to accept forged proofs.
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nStartTime, 0);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nTimeout, 0);

    // SoquObscura — WITHDRAWN 2026-08-17, must NOT be active. Regtest is included
    // in the withdrawal deliberately: leaving it active would keep every
    // functional test running against a verifier known to accept forged proofs.
    // Full dormancy assertions live in test/soquobscura_withdrawal_tests.cpp.
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_SOQUOBSCURA].nStartTime, 0);
    BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(
        0, consensus, Consensus::DEPLOYMENT_SOQUOBSCURA));
}

// g7c regression guard: the BASE witness framework (SegWit + CSV) must be
// active from genesis on MAINNET. If these ever revert to the inherited
// Bitcoin/Dogecoin BIP9 windows (real timestamps / SegWit nTimeout=0), they
// resolve to THRESHOLD_FAILED on a post-2017 genesis chain and every witness
// program (v0-v7: all Dilithium/PAT/LatticeFold outputs) becomes
// anyone-can-spend. See DL-G7C-SEGWIT-CSV-GENESIS-ACTIVATION.md.
BOOST_AUTO_TEST_CASE(mainnet_witness_framework_active_from_genesis)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensus = Params().GetConsensus(0);

    // SegWit must be ALWAYS_ACTIVE (nStartTime == -1, nTimeout == NO_TIMEOUT)
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime,
                      Consensus::BIP9Deployment::ALWAYS_ACTIVE);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout,
                      Consensus::BIP9Deployment::NO_TIMEOUT);

    // CSV must be ALWAYS_ACTIVE (BIP68/112/113 — L2SOQ force-close depends on it)
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime,
                      Consensus::BIP9Deployment::ALWAYS_ACTIVE);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout,
                      Consensus::BIP9Deployment::NO_TIMEOUT);

    // Belt-and-suspenders: the SegWit nTimeout must never be 0 (the specific
    // "Disabled" value that also suppresses the coinbase witness commitment).
    BOOST_CHECK(consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout != 0);
}

// ============================================================================
// Subsidy Calculation Tests
//
// Verify the halving schedule matches documented tokenomics.
// ============================================================================

BOOST_AUTO_TEST_CASE(subsidy_halving_schedule)
{
    SelectParams(CBaseChainParams::STAGENET);
    const Consensus::Params& consensus = Params().GetConsensus(0);
    uint256 dummyHash;
    dummyHash.SetNull();

    // 47B Moderate emission (locked 2026-06-28, bead c61): 100K launch reward,
    // 4 halvings at nSubsidyHalvingInterval, then a perpetual 2,500 SOQ tail.
    // Block 0 (epoch 0): 100,000 SOQ
    BOOST_CHECK_EQUAL(GetSoqucoinBlockSubsidy(0, consensus, dummyHash), 100000 * COIN);
    // After first halving: 50,000 SOQ
    BOOST_CHECK_EQUAL(GetSoqucoinBlockSubsidy(consensus.nSubsidyHalvingInterval, consensus, dummyHash), 50000 * COIN);
    // After second halving: 25,000 SOQ
    BOOST_CHECK_EQUAL(GetSoqucoinBlockSubsidy(2 * consensus.nSubsidyHalvingInterval, consensus, dummyHash), 25000 * COIN);
    // After third halving (final head epoch): 12,500 SOQ
    BOOST_CHECK_EQUAL(GetSoqucoinBlockSubsidy(3 * consensus.nSubsidyHalvingInterval, consensus, dummyHash), 12500 * COIN);
    // Fourth halving onward: perpetual 2,500 SOQ tail
    BOOST_CHECK_EQUAL(GetSoqucoinBlockSubsidy(4 * consensus.nSubsidyHalvingInterval, consensus, dummyHash), 2500 * COIN);
    BOOST_CHECK_EQUAL(GetSoqucoinBlockSubsidy(6 * consensus.nSubsidyHalvingInterval, consensus, dummyHash), 2500 * COIN);
    // Way past the tail transition: still 2,500 SOQ (perpetual inflation)
    BOOST_CHECK_EQUAL(GetSoqucoinBlockSubsidy(100 * consensus.nSubsidyHalvingInterval, consensus, dummyHash), 2500 * COIN);
}

// ============================================================================
// p96 / Option D — flag-day (height-gated) soft-fork activation
// ============================================================================

// The height-gated deployments that moved off BIP9 signaling (bits 5-13).
static const Consensus::DeploymentPos P96_FLAGDAY_DEPLOYMENTS[] = {
    Consensus::DEPLOYMENT_SOQUOBSCURA,
    Consensus::DEPLOYMENT_USDSOQ,
    Consensus::DEPLOYMENT_CTV,
    Consensus::DEPLOYMENT_APO,
    Consensus::DEPLOYMENT_CSFS,
    Consensus::DEPLOYMENT_P2WSH_DILITHIUM,
    Consensus::DEPLOYMENT_UTXO_COST,
    Consensus::DEPLOYMENT_DILITHIUM_KEYHASH,
    Consensus::DEPLOYMENT_V6_CONTROLFLOW,
    // BTCSOQ is height-gated exactly like the rest (mainnet NOT_SCHEDULED,
    // test networks 0) and was simply missing from this list, so the mainnet
    // dormancy assertion below did not cover the Bitcoin-backed asset.
    Consensus::DEPLOYMENT_BTCSOQ,
};

BOOST_AUTO_TEST_CASE(p96_deployment_active_predicate)
{
    Consensus::Params p;  // vDeployments default-constructed (nActivationHeight = NO_HEIGHT_ACTIVATION)
    const Consensus::DeploymentPos pos = Consensus::DEPLOYMENT_USDSOQ;

    // NO_HEIGHT_ACTIVATION (not height-gated) → never active via this predicate,
    // even at absurd heights. Such deployments must be queried via BIP9 instead.
    p.vDeployments[pos].nActivationHeight = Consensus::BIP9Deployment::NO_HEIGHT_ACTIVATION;
    BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(0, p, pos));
    BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(1000000, p, pos));

    // NOT_SCHEDULED → dormant at every reachable height (ships-off on mainnet).
    p.vDeployments[pos].nActivationHeight = Consensus::BIP9Deployment::NOT_SCHEDULED;
    BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(0, p, pos));
    BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(1000000000, p, pos));

    // A concrete future height H: inactive below H, active at/above H (flag day).
    p.vDeployments[pos].nActivationHeight = 500000;
    BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(499999, p, pos));
    BOOST_CHECK(Consensus::DeploymentActiveAtHeight(500000, p, pos));   // first enforcing block
    BOOST_CHECK(Consensus::DeploymentActiveAtHeight(500001, p, pos));

    // Height 0 → active from genesis (the test-network configuration).
    p.vDeployments[pos].nActivationHeight = 0;
    BOOST_CHECK(Consensus::DeploymentActiveAtHeight(0, p, pos));
    BOOST_CHECK(Consensus::DeploymentActiveAtHeight(1, p, pos));
}

BOOST_AUTO_TEST_CASE(p96_mainnet_ships_dormant)
{
    // Every flag-day soft-fork must be dormant on mainnet at genesis and stay
    // dormant until a coordinated release sets a real height. Prevents an
    // accidental genesis-active PQ/covenant/economic rule on mainnet.
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensus = Params().GetConsensus(0);
    for (const auto pos : P96_FLAGDAY_DEPLOYMENTS) {
        BOOST_CHECK_EQUAL(consensus.vDeployments[pos].nActivationHeight,
                          Consensus::BIP9Deployment::NOT_SCHEDULED);
        BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(0, consensus, pos));
        BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(1000000, consensus, pos));
    }
}

BOOST_AUTO_TEST_CASE(p96_testnets_active_from_genesis)
{
    // Regtest and stagenet must keep the flag-day features active from genesis
    // (height 0), preserving the prior ALWAYS_ACTIVE test behavior — and the
    // live stagenet's historical blocks must validate identically.
    //
    // ⛔ ONE DELIBERATE EXCEPTION: DEPLOYMENT_SOQUOBSCURA was WITHDRAWN from all
    // networks on 2026-08-17 because its range verifier accepts an all-zero
    // witness carrying a correct Fiat-Shamir seed, so a confidential output
    // proves nothing about its amount. Keeping it active here would keep every
    // functional test running against a verifier known to accept forged proofs.
    // Its dormancy is asserted positively — and much more thoroughly — in
    // test/soquobscura_withdrawal_tests.cpp, so nothing is lost by skipping it.
    // ⚠️ Do NOT remove it from P96_FLAGDAY_DEPLOYMENTS: that array still guards
    // the mainnet NOT_SCHEDULED assertion above, which SoquObscura must satisfy.
    for (const std::string& net : {CBaseChainParams::REGTEST, CBaseChainParams::STAGENET}) {
        SelectParams(net);
        const Consensus::Params& consensus = Params().GetConsensus(0);
        for (const auto pos : P96_FLAGDAY_DEPLOYMENTS) {
            if (pos == Consensus::DEPLOYMENT_SOQUOBSCURA) continue;  // withdrawn, see above
            BOOST_CHECK_EQUAL(consensus.vDeployments[pos].nActivationHeight, 0);
            BOOST_CHECK(Consensus::DeploymentActiveAtHeight(0, consensus, pos));
        }
    }
    SelectParams(CBaseChainParams::MAIN);  // restore default for later tests
}

// ============================================================================
// F8 (bead v7xm): the activation posture must hold at EVERY height, not just 0.
//
// The two tests above read GetConsensus(0), which returns the BASE consensus
// struct. That is not the struct most blocks are validated against. Every
// network assembles a height-indexed tree of Consensus::Params
// (consensus / digishieldConsensus / auxpowConsensus) and GetConsensus(nHeight)
// returns whichever tier covers that height — on regtest the cutovers are 10 and
// 20, on stagenet 1 and 100. The constructors copy the base struct AFTER setting
// the deployment fields, so the tiers agree today; nothing enforces that they
// keep agreeing, and a per-tier divergence would mean a deployment that is
// dormant at genesis and live at height 20, or the reverse.
//
// This is not hypothetical. A regtest activation lever added on 2026-08-20
// initially wrote only the base struct and was silently inert for every block a
// chain fixture mines. The same shape sits in UpdateMaxReorgDepth, which writes
// consensus and digishieldConsensus but not auxpowConsensus (bead tofg).
// ============================================================================
BOOST_AUTO_TEST_CASE(f8_deployment_posture_is_uniform_across_consensus_tiers)
{
    // Heights chosen to straddle every tier cutover on every network.
    const int kProbeHeights[] = {0, 1, 2, 9, 10, 11, 19, 20, 21, 99, 100, 101, 1000, 1000000};

    for (const std::string& net : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET,
                                   CBaseChainParams::REGTEST, CBaseChainParams::STAGENET}) {
        SelectParams(net);
        for (int pos = 0; pos < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; pos++) {
            const auto d = static_cast<Consensus::DeploymentPos>(pos);
            const Consensus::BIP9Deployment& base = Params().GetConsensus(0).vDeployments[d];
            for (int h : kProbeHeights) {
                const Consensus::BIP9Deployment& tier = Params().GetConsensus(h).vDeployments[d];
                BOOST_CHECK_MESSAGE(tier.nActivationHeight == base.nActivationHeight,
                    net + ": deployment " + std::to_string(pos) + " has nActivationHeight " +
                    std::to_string(tier.nActivationHeight) + " at height " + std::to_string(h) +
                    " but " + std::to_string(base.nActivationHeight) + " in the base struct — "
                    "the consensus tiers have diverged");
                BOOST_CHECK_MESSAGE(tier.bit == base.bit,
                    net + ": deployment " + std::to_string(pos) + " changes version bit across tiers");
                BOOST_CHECK_MESSAGE(tier.nStartTime == base.nStartTime &&
                                    tier.nTimeout == base.nTimeout,
                    net + ": deployment " + std::to_string(pos) + " changes its BIP9 window across tiers");
            }
        }
    }
    SelectParams(CBaseChainParams::MAIN);
}

// A height-gated deployment ignores nStartTime/nTimeout entirely, so a
// deployment carrying BOTH an nActivationHeight and a real BIP9 window is a
// statement of intent the code will not honour. Reject the combination outright
// rather than trusting anyone to remember the rule. The inert values (0/0 for
// "never" and ALWAYS_ACTIVE/NO_TIMEOUT for the pre-flag-day form) are allowed
// because they are what the existing configs use to mean "the BIP9 fields are
// not the mechanism here".
BOOST_AUTO_TEST_CASE(f8_no_deployment_relies_on_a_bip9_window_it_cannot_use)
{
    for (const std::string& net : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET,
                                   CBaseChainParams::REGTEST, CBaseChainParams::STAGENET}) {
        SelectParams(net);
        const Consensus::Params& c = Params().GetConsensus(0);
        for (int pos = 0; pos < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; pos++) {
            const Consensus::BIP9Deployment& d = c.vDeployments[static_cast<Consensus::DeploymentPos>(pos)];
            if (d.nActivationHeight == Consensus::BIP9Deployment::NO_HEIGHT_ACTIVATION) continue;

            const bool inertWindow =
                (d.nStartTime == 0 && d.nTimeout == 0) ||
                (d.nStartTime == Consensus::BIP9Deployment::ALWAYS_ACTIVE &&
                 d.nTimeout == Consensus::BIP9Deployment::NO_TIMEOUT);
            BOOST_CHECK_MESSAGE(inertWindow,
                net + ": deployment " + std::to_string(pos) + " is height-gated (nActivationHeight=" +
                std::to_string(d.nActivationHeight) + ") yet carries a live BIP9 window. "
                "DeploymentActiveAtHeight never reads nStartTime/nTimeout, so that window is a no-op "
                "and whoever set it believed something false about how this deployment activates.");
        }
    }
    SelectParams(CBaseChainParams::MAIN);
}

// Two deployments sharing a version bit means signalling for one is signalling
// for the other. Harmless while both are inert; a chain split if either is ever
// scheduled. TESTDUMMY is excluded because it is a test fixture rather than a
// feature, and it currently collides with LATTICEFOLD on bit 28 (bead nv7q) —
// excluding it here keeps this test honest about FEATURE bits without encoding
// that known overlap as acceptable.
BOOST_AUTO_TEST_CASE(f8_feature_deployments_do_not_share_version_bits)
{
    for (const std::string& net : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET,
                                   CBaseChainParams::REGTEST, CBaseChainParams::STAGENET}) {
        SelectParams(net);
        const Consensus::Params& c = Params().GetConsensus(0);
        std::map<int, int> bitOwner;   // bit -> deployment index
        for (int pos = 0; pos < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; pos++) {
            if (pos == Consensus::DEPLOYMENT_TESTDUMMY) continue;
            const int bit = c.vDeployments[static_cast<Consensus::DeploymentPos>(pos)].bit;
            auto it = bitOwner.find(bit);
            BOOST_CHECK_MESSAGE(it == bitOwner.end(),
                net + ": deployments " + std::to_string(it == bitOwner.end() ? -1 : it->second) +
                " and " + std::to_string(pos) + " both claim version bit " + std::to_string(bit));
            bitOwner[bit] = pos;
        }
    }
    SelectParams(CBaseChainParams::MAIN);
}

// ============================================================================
// F8 (bead zz2f): BIP34/65/66 heights must be OURS, not Dogecoin's.
//
// Mainnet shipped Dogecoin's mainnet heights verbatim (1034383 / 3464751 /
// 1034383) and testnet shipped Dogecoin's testnet heights. On a chain that
// starts at height 0 those are not history, they are activation heights, and
// the BIP65 one meant SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY stayed off for about
// 6.6 years — OP_CLTV a NOP, so any timelock branch was unenforceable the
// moment a CLTV-carrying deployment activated.
//
// The tell was that stagenet, the mainnet REHEARSAL network, already used
// 0/0/100, so the rehearsal validated under stricter rules than the thing it
// rehearses. This test pins all four networks together for exactly that reason:
// the defect was divergence, so the assertion has to be about agreement.
// ============================================================================
BOOST_AUTO_TEST_CASE(f8_bip_activation_heights_are_soqucoin_not_dogecoin)
{
    // Dogecoin's values, named so a regression is unmistakable rather than
    // looking like an arbitrary number changed.
    const int kDogeMainBIP34 = 1034383, kDogeMainBIP65 = 3464751;
    const int kDogeTestBIP34 = 708658,  kDogeTestBIP65 = 1854705;

    for (const std::string& net : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET,
                                   CBaseChainParams::STAGENET}) {
        SelectParams(net);
        const Consensus::Params& c = Params().GetConsensus(0);

        BOOST_CHECK_MESSAGE(c.BIP65Height == 0,
            net + ": BIP65Height must be 0 so OP_CHECKLOCKTIMEVERIFY is enforced from "
            "genesis. A nonzero value makes CLTV a NOP until that height, and any "
            "HTLC or vault timeout branch created before then is unenforceable.");
        BOOST_CHECK_MESSAGE(c.BIP66Height == 0, net + ": BIP66Height must be 0");

        // > 16 so the coinbase height cannot fall in the range where OP_N and a
        // 1-byte data push are both defensible encodings; >= 1 so genesis, which
        // has no height push and does reach ContextualCheckBlock on -reindex,
        // stays outside the rule.
        BOOST_CHECK_MESSAGE(c.BIP34Height > 16,
            net + ": BIP34Height must exceed 16 (OP_N vs push-byte coinbase encoding)");

        BOOST_CHECK_MESSAGE(c.BIP34Height != kDogeMainBIP34 && c.BIP34Height != kDogeTestBIP34,
            net + ": BIP34Height is a Dogecoin height");
        BOOST_CHECK_MESSAGE(c.BIP65Height != kDogeMainBIP65 && c.BIP65Height != kDogeTestBIP65,
            net + ": BIP65Height is a Dogecoin height");

        // BIP34Hash is the hash of the block AT BIP34Height and cannot be known
        // before launch. Null keeps the BIP30 duplicate-txid scan enforced by
        // lookup forever, which is strictly more checking; a stale inherited hash
        // had the same effect while also being false.
        BOOST_CHECK_MESSAGE(c.BIP34Hash.IsNull(),
            net + ": BIP34Hash must be null until a real post-launch value is known");
    }

    // Mainnet and its rehearsal network must agree, since disagreement is what
    // made every stagenet soak result carry an assumption mainnet did not honour.
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& m = Params().GetConsensus(0);
    const int mainBIP34 = m.BIP34Height, mainBIP65 = m.BIP65Height, mainBIP66 = m.BIP66Height;
    SelectParams(CBaseChainParams::STAGENET);
    const Consensus::Params& sg = Params().GetConsensus(0);
    BOOST_CHECK_EQUAL(mainBIP34, sg.BIP34Height);
    BOOST_CHECK_EQUAL(mainBIP65, sg.BIP65Height);
    BOOST_CHECK_EQUAL(mainBIP66, sg.BIP66Height);

    SelectParams(CBaseChainParams::MAIN);
}

// ---------------------------------------------------------------------------
// Coinbase maturity vs the finality horizon (bead mainnet-maturity-240-not-30-mp5o).
//
// THE DEFECT THIS EXISTS TO CATCH, stated as the attack rather than as the rule:
// the horizon rejects a fork only once it is nMaxReorgDepth blocks DEEP, so every
// reorg shallower than that is consensus-legal and accepted. If a coinbase becomes
// spendable before that depth, an attacker who can rent enough hashpower to reorg
// (say) 260 blocks can un-mine a coinbase that has already matured AND been spent,
// invalidating every descendant transaction. Coinbase is the one output class where
// this cascades, and it is the class this chain's own pool creates continuously.
//
// This test exists because the two constants were set NINE YEARS APART by different
// projects — 240 arrived with upstream Dogecoin in 2017, the 288-block horizon was
// added here on 2026-06-23 — and nothing in the tree ever compared them. A green
// suite is not evidence; the comparison simply did not exist until this case did.
//
// Both values are consensus and both are absorbed by the consensus digest, so a
// change to either after genesis is a hard fork.
//
// ⚠ SCOPE OF THE PROPERTY, so the next reader does not overclaim it. The horizon
// is enforced in exactly one place, ContextualCheckBlockHeader, and only when a
// header is FIRST accepted — AcceptBlockHeader returns early for a header already
// in mapBlockIndex, so the check never re-runs. Headers accepted while a fork is
// still shallow, with the blocks withheld and released later, can therefore still
// drive a deep reorg. Satisfying this invariant closes the header-arrives-on-time
// case, which is the reachable one, and not every case. Tracked as bead
// finality-horizon-header-only-8p5y; see doc/PAT_WITNESS_PRUNING.md §6.
static void CheckMaturityCoversFinality(const char* net, int sampleHeight)
{
    const Consensus::Params& c = Params().GetConsensus(sampleHeight);

    // NO SILENT SKIP. This used to return early when nMaxReorgDepth <= 0,
    // nominally for regtest — but no caller passes regtest, so the only thing
    // that escape could ever do is let a zeroed mainnet horizon report SUCCESS
    // here: the invariant becomes unassertable and the case says nothing is
    // wrong. The tree was not defenceless — nMaxReorgDepth is an absorbed digest
    // input (consensus_digest_tests.cpp), so consensus_digest_is_pinned fails on
    // that mutation regardless — but a case that cannot fail is not a case, and
    // the digest tells you "something moved", not which invariant broke. Assert
    // the horizon EXISTS first, then assert it is covered.
    BOOST_REQUIRE_MESSAGE(c.nMaxReorgDepth > 0,
        net << ": nMaxReorgDepth is " << c.nMaxReorgDepth << ", so the finality "
               "horizon is DISABLED on a network that is required to have one. "
               "Disabling it does not satisfy this invariant, it deletes the "
               "reason the invariant exists. If a network without a horizon is "
               "genuinely being added, give it its own case rather than widening "
               "this helper.");

    BOOST_CHECK_MESSAGE(
        (int64_t)c.nCoinbaseMaturity >= (int64_t)c.nMaxReorgDepth,
        net << ": coinbase matures at " << c.nCoinbaseMaturity
            << " blocks but the chain still accepts reorgs up to "
            << (c.nMaxReorgDepth - 1) << " deep (nMaxReorgDepth "
            << c.nMaxReorgDepth << "). A matured, spent coinbase can therefore be "
               "un-mined. Raise nCoinbaseMaturity to at least nMaxReorgDepth, or "
               "lower the horizon — but note that lowering it also shrinks the "
               "witness-pruned serving window, which is advertised as "
               "NODE_NETWORK_LIMITED and promises peers the last 288 blocks.");
}

BOOST_AUTO_TEST_CASE(maturity_covers_finality_horizon_mainnet)
{
    SelectParams(CBaseChainParams::MAIN);
    // Height 0 is the genesis tier; the genesis coinbase is unspendable, so the
    // property is asserted from height 1 where real coinbases live.
    CheckMaturityCoversFinality("mainnet h=1", 1);
    CheckMaturityCoversFinality("mainnet h=1000000", 1000000);
}

BOOST_AUTO_TEST_CASE(maturity_covers_finality_horizon_stagenet)
{
    SelectParams(CBaseChainParams::STAGENET);
    // Above the mainnet-maturity mirror gate at 100000, stagenet must reproduce
    // the mainnet property or the soak is not rehearsing launch maturity.
    CheckMaturityCoversFinality("stagenet h=100000 (the gate)", 100000);
    CheckMaturityCoversFinality("stagenet h=1000000", 1000000);

    // ⚠ SCOPE: only the mirror tier is asserted, and a green result here does NOT
    // mean "stagenet is covered". BELOW the gate stagenet runs maturity 30 against
    // the same 288 horizon — a 258-block gap, five times wider than the 48-block
    // testnet gap that gets a named exception case below, and it is the tier the
    // chain is actually running on today. That is deliberate and deliberately not
    // fixed: stagenet is a disposable soak chain that is reset for mainnet, the
    // gated tier already carries the launch value from 100000, and editing the
    // pre-gate tier in place would retroactively invalidate replayed history for
    // no benefit. Asserted as an exception below so it cannot outlive its cause.
    SelectParams(CBaseChainParams::MAIN);
}

// ⛔ TESTNET IS A KNOWN, DELIBERATE EXCEPTION — DO NOT "FIX" IT BY EDITING
// chainparams IN PLACE. Testnet carries the same gap (maturity 240 against a 288
// horizon), but it has no height-gated maturity tier, so raising the value in place
// would retroactively invalidate every past spend of a coinbase at depth 240-287 and
// split or strand the chain. It needs a height-gated tier or a reset, tracked on
// bead mainnet-maturity-240-not-30-mp5o.
//
// This case asserts the EXCEPTION, so the day testnet is fixed this test fails and
// says so — the exception cannot outlive its cause silently.
BOOST_AUTO_TEST_CASE(maturity_below_finality_horizon_testnet_known_exception)
{
    SelectParams(CBaseChainParams::TESTNET);
    const Consensus::Params& c = Params().GetConsensus(1);
    BOOST_CHECK_MESSAGE(
        (int64_t)c.nCoinbaseMaturity < (int64_t)c.nMaxReorgDepth,
        "testnet coinbase maturity now covers the finality horizon. If that was "
        "done on purpose, delete this case and add testnet to "
        "maturity_covers_finality_horizon_* instead.");
    SelectParams(CBaseChainParams::MAIN);
}

// ⛔ STAGENET BELOW THE MIRROR GATE IS THE SECOND KNOWN EXCEPTION, and the wider
// one: maturity 30 against the 288 horizon. It is the tier the live soak chain is
// running on right now. Left alone on purpose — stagenet is reset for mainnet and
// the gated tier at 100000 already carries the launch value, so editing the
// pre-gate tier would retroactively invalidate replayed history to protect a
// throwaway chain. Asserted here so that "stagenet is fine" is never inferred from
// maturity_covers_finality_horizon_stagenet, which only samples the mirror tier.
BOOST_AUTO_TEST_CASE(maturity_below_finality_horizon_stagenet_pregate_known_exception)
{
    SelectParams(CBaseChainParams::STAGENET);
    const Consensus::Params& c = Params().GetConsensus(99999);
    BOOST_CHECK_MESSAGE(
        (int64_t)c.nCoinbaseMaturity < (int64_t)c.nMaxReorgDepth,
        "stagenet's pre-gate tier now covers the finality horizon. If that was "
        "done on purpose, delete this case; if it happened by accident, it "
        "retroactively invalidated replayed stagenet history.");
    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_SUITE_END()
