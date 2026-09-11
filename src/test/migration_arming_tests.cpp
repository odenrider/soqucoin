// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// migration_arming_tests.cpp — where the genesis-migration constants land
// (bead chainparams-migration-arming-tier-footgun-ldbr).
//
// ConnectBlock reads hashMigrationOutputs / nMigrationTotal / nMigrationHeight
// through chainparams.GetConsensus(pindex->nHeight), which resolves every
// height >= 1 to a tier struct that was COPIED from `consensus` before the
// migration comment block in CMainParams. A constant written to `consensus`
// alone after those copies never reaches the tier that validates the armed
// height, and the rule stays silently inert. migration_rule_tests proves the
// rule fires when the constants are in the right tier; this suite proves the
// constants are in every tier, on every network, armed or not.
//
// The invariant is written so it holds today (everything null/0/0) AND on the
// day a ceremony arms mainnet: every sampled tier agrees, and if armed, the
// tier at the armed height carries the constants and the compiled-in vector
// hashes and sums to them.

#include "chainparams.h"
#include "consensus/params.h"
#include "hash.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "uint256.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <set>

namespace {

// Heights that land on every tier boundary any network has: genesis, the
// regtest digishield (10) and auxpow (20) boundaries, the mainnet merged tier
// at 1, the stagenet maturity mirror at 100000, and the planning-order
// activation height from the design log (about 40000).
static const int kSampleHeights[] = {0, 1, 2, 9, 10, 11, 19, 20, 21, 100, 1000,
                                     40000, 99999, 100000, 100001, 1000000};

struct Armed {
    uint256 hash;
    CAmount total;
    int height;
    bool operator==(const Armed& o) const { return hash == o.hash && total == o.total && height == o.height; }
};

static Armed At(const CChainParams& params, int nHeight)
{
    const Consensus::Params& c = params.GetConsensus(nHeight);
    return Armed{c.hashMigrationOutputs, c.nMigrationTotal, c.nMigrationHeight};
}

static CScript V1Spk(unsigned char seed)
{
    return CScript() << OP_1 << std::vector<unsigned char>(32, seed);
}

static uint256 HashOutputs(const std::vector<CTxOut>& vOutputs)
{
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << vOutputs;
    return hasher.GetHash();
}

//! Arms regtest for one scope and ALWAYS disarms on exit (same discipline as
//! migration_rule_tests: a leaked arming would poison every later suite).
struct RegtestArming {
    RegtestArming(const uint256& h, CAmount t, int height, const std::vector<CTxOut>& v)
    {
        UpdateRegtestMigrationParams(h, t, height, v);
    }
    ~RegtestArming() { UpdateRegtestMigrationParams(uint256(), 0, 0, std::vector<CTxOut>()); }
};

//! The standing invariant, checked on one network: all sampled tiers agree,
//! and an armed set is self-consistent with the compiled-in vector.
static void CheckTiersAgree(const CChainParams& params, const std::string& name)
{
    const Armed base = At(params, 0);
    for (int h : kSampleHeights) {
        const Armed tier = At(params, h);
        BOOST_CHECK_MESSAGE(tier == base,
            name << ": migration constants differ between height 0 and height " << h
                 << " (a tier was missed when arming)");
    }
    if (base.height == 0) {
        BOOST_CHECK_MESSAGE(base.hash.IsNull() && base.total == 0,
            name << ": nMigrationHeight is 0 but the hash or total is set");
        BOOST_CHECK_MESSAGE(params.MigrationOutputs().empty(),
            name << ": inert constants but a committed vector is compiled in");
        return;
    }
    // Armed: the tier that validates H must carry it, and the vector must match.
    const Armed atH = At(params, base.height);
    BOOST_CHECK_MESSAGE(atH == base, name << ": GetConsensus(H) does not carry the armed constants");
    BOOST_CHECK_MESSAGE(!base.hash.IsNull(), name << ": armed height with a null hash");
    BOOST_CHECK_MESSAGE(!params.MigrationOutputs().empty(), name << ": armed without a committed vector");
    BOOST_CHECK_EQUAL(HashOutputs(params.MigrationOutputs()).ToString(), base.hash.ToString());
    CAmount sum = 0;
    for (const CTxOut& out : params.MigrationOutputs()) sum += out.nValue;
    BOOST_CHECK_EQUAL(sum, base.total);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(migration_arming_tests, BasicTestingSetup)

// Today's state, on every network: inert on every tier, no vector compiled in.
// This is also the test that fails the day someone arms mainnet by assigning
// to `consensus` alone.
BOOST_AUTO_TEST_CASE(every_network_every_tier_agrees)
{
    // Built here, not at static-init time: the chain-name constants live in
    // another translation unit and may not exist yet when this file's statics run.
    const std::string networks[] = {CBaseChainParams::MAIN, CBaseChainParams::TESTNET,
                                    CBaseChainParams::STAGENET, CBaseChainParams::REGTEST};
    for (const std::string& net : networks) {
        CheckTiersAgree(Params(net), net);
    }
}

// Presence control for the agreement check above: the sampled heights must
// reach a distinct tier struct for every tier GetConsensus can return, or the
// check would compare one struct with itself. The counts are the reachable
// tiers per network that ArmMigrationTiers documents; stagenet's fourth tier
// (the maturity mirror at 100000) is the one a fixed-arity helper missed.
BOOST_AUTO_TEST_CASE(sampled_heights_reach_every_reachable_tier)
{
    const struct { const char* net; size_t tiers; } expected[] = {
        {CBaseChainParams::MAIN.c_str(), 2},
        {CBaseChainParams::TESTNET.c_str(), 2},
        {CBaseChainParams::REGTEST.c_str(), 3},
        {CBaseChainParams::STAGENET.c_str(), 4},
    };
    for (const auto& e : expected) {
        const CChainParams& params = Params(e.net);
        std::set<const Consensus::Params*> seen;
        for (int h : kSampleHeights) seen.insert(&params.GetConsensus(h));
        BOOST_CHECK_MESSAGE(seen.size() == e.tiers,
            e.net << ": sampled heights reach " << seen.size() << " tier structs, expected " << e.tiers);
    }
    const CChainParams& stagenet = Params(CBaseChainParams::STAGENET);
    BOOST_CHECK(&stagenet.GetConsensus(99999) != &stagenet.GetConsensus(100000));
}

// The shared arming path puts the constants where ConnectBlock reads them,
// for heights on both sides of every regtest tier boundary.
BOOST_AUTO_TEST_CASE(armed_height_tier_carries_constants)
{
    std::vector<CTxOut> vOutputs;
    vOutputs.push_back(CTxOut(10 * COIN, V1Spk(0xA1)));
    vOutputs.push_back(CTxOut(20 * COIN, V1Spk(0xA2)));
    const uint256 hash = HashOutputs(vOutputs);
    const CChainParams& regtest = Params(CBaseChainParams::REGTEST);

    for (int H : {1, 5, 10, 19, 20, 21, 100, 40000}) {
        RegtestArming arming(hash, 30 * COIN, H, vOutputs);
        const Consensus::Params& c = regtest.GetConsensus(H);
        BOOST_CHECK_EQUAL(c.nMigrationHeight, H);
        BOOST_CHECK_EQUAL(c.hashMigrationOutputs.ToString(), hash.ToString());
        BOOST_CHECK_EQUAL(c.nMigrationTotal, 30 * COIN);
        // The rule must be visible from every tier, not only the one at H.
        CheckTiersAgree(regtest, "regtest armed at " + std::to_string(H));
    }
    // Disarmed again on scope exit: inert on every tier.
    CheckTiersAgree(regtest, "regtest after disarm");
    BOOST_CHECK(regtest.GetConsensus(40000).hashMigrationOutputs.IsNull());
}

BOOST_AUTO_TEST_SUITE_END()
