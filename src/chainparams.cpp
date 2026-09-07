// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2022-2024 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/hmac_sha256.h"

#include <assert.h>
#include <cstring>

#include <boost/assign/list_of.hpp>


#include "chainparamsseeds.h"

/**
 * SOQ-H3: Derive Lattice-BP++ consensus seed from genesis block hash.
 *
 * Uses HKDF-SHA256 (RFC 5869) with:
 *   IKM  = genesis_block_hash (32 bytes)
 *   salt = domain separator string
 *   info = lattice parameter binding string
 *
 * This gives "nothing up my sleeve" assurance:
 *   - Genesis hash is public and predates privacy implementation
 *   - Different chains (mainnet, stagenet, regtest) get different A matrices
 *   - Lattice parameters (N, Q, K) are bound into the derivation
 *   - Version suffix allows future migration without breaking existing proofs
 */
static std::array<uint8_t, 32> ComputeSoquObscuraSeed(
    const uint256& genesisHash,
    const char* domain,
    const char* info)
{
    // HKDF-Extract: PRK = HMAC-SHA256(salt=domain, IKM=genesis_hash)
    unsigned char prk[32];
    CHMAC_SHA256 extract(
        reinterpret_cast<const unsigned char*>(domain), strlen(domain));
    extract.Write(genesisHash.begin(), 32);
    extract.Finalize(prk);

    // HKDF-Expand: OKM = HMAC-SHA256(key=PRK, info || 0x01)
    // For 32-byte output, only one HMAC round is needed.
    std::array<uint8_t, 32> seed;
    CHMAC_SHA256 expand(prk, 32);
    expand.Write(
        reinterpret_cast<const unsigned char*>(info), strlen(info));
    unsigned char one = 0x01;
    expand.Write(&one, 1);
    expand.Finalize(seed.data());

    return seed;
}

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1386325540, nBits=0x1e0ffff0, nNonce=99943, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Nintondo";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Soqucoin Testnet3 Genesis Block - Dec 2025
 * First quantum-resistant Scrypt chain
 */
static CBlock CreateGenesisBlockTestnet3(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "First quantum-resistant Scrypt chain - Soqucoin Testnet3 Dec 2025";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Soqucoin Stagenet Genesis Block - Jan 2026
 * Mainnet rehearsal network with identical staged activation
 */
static CBlock CreateGenesisBlockStagenet(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Soqucoin Stagenet - Mainnet rehearsal network Jan 2026";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Soqucoin Mainnet Genesis Block - genesis ceremony 2026-09-02 (doc/GENESIS_CEREMONY.md)
 *
 * Headline: The Block, 2026-08-26, "First quantum-resistant Bitcoin transaction
 * successfully executed, StarkWare says" (attribution tail trimmed, verb
 * compressed to the event's own fact: the transaction was mined in BTC block
 * 964199, txid 305a24ffea912b9cf428f29ebf952321c96dab5bab284fc0d0801562f5abab07).
 * Anchor: BTC block 965186, hash
 * 00000000000000000000d3b0f4905a4d1dc5366526c311004e9468743df764d3 (first
 * significant 8 hex = d3b0f490), fetched at ceremony start from two independent
 * explorers. The anchor proves this genesis could not have been mined before
 * that Bitcoin block existed.
 *
 * Output script is a bare OP_RETURN: provably unspendable with no embedded
 * data, so nothing-up-my-sleeve. The genesis coinbase is excluded from the
 * UTXO set regardless; this choice is about what decoders display.
 */
static CBlock CreateGenesisBlockMainnet(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "The Block 26/Aug/2026 First quantum-resistant Bitcoin transaction mined BTC 965186 d3b0f490";
    const CScript genesisOutputScript = CScript() << OP_RETURN;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams
{
private:
    Consensus::Params digishieldConsensus;
    Consensus::Params auxpowConsensus;

public:
    CMainParams()
    {
        strNetworkID = "main";
        bech32HRP = "sq";

        // Blocks 0 - 144999 are conventional difficulty calculation
        // 47B Moderate emission (locked 2026-06-28, bead soqucoin-build-c61):
        // 250,000-block halving interval (~174d at 60s) × 4 halvings; 100K launch
        // reward + 2,500 tail live in GetSoqucoinBlockSubsidy (soqucoin.cpp).
        consensus.nSubsidyHalvingInterval = 250000;
        consensus.nInitialSubsidy = 100000; // 47B launch reward
        consensus.nMajorityEnforceBlockUpgrade = 1500;
        consensus.nMajorityRejectBlockOutdated = 1900;
        consensus.nMajorityWindow = 2000;
        // BIP34 is never enforced in Soqucoin v2 blocks, so we enforce from v3
        // ⛔ THESE WERE DOGECOIN'S MAINNET HEIGHTS, INHERITED VERBATIM (comments and
        // Dogecoin block hashes included). Soqucoin is NOT a fork: it has its own
        // genesis and starts at height 0, so those numbers were not history, they
        // were activation heights for rules that would not have activated for years.
        // SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY is gated on BIP65Height, so OP_CLTV
        // would have been a NOP until block 3,464,751 — roughly 6.6 years at
        // 1-minute blocks. Nothing exploits that at genesis, because the CLTV
        // vehicles (witness v6 P2WSH-Dilithium, V6_CONTROLFLOW) ship NOT_SCHEDULED;
        // it goes live the moment either activates, and an eLTOO/HTLC timeout
        // branch with no enforceable timelock is loss of funds. Stagenet, our own
        // mainnet rehearsal network, already used 0/0/100 — so every soak result
        // carried an assumption mainnet did not honour. See bead zz2f.
        //
        // BIP34Height = 100, not 0 or 1, for two independent reasons:
        //   1. It must be > 16. The rule compares against `CScript() << nHeight`,
        //      which emits the single opcode OP_N for 1..16 rather than the 1-byte
        //      data push a strict BIP34 writer produces, so heights in that range
        //      have two defensible encodings and only one is accepted. Above 16 the
        //      encoding is an unambiguous data push.
        //   2. Genesis must stay outside the rule. ContextualCheckBlock is reached
        //      by the genesis block during -reindex (see SOQ-REINDEX-001), and the
        //      genesis coinbase carries no height push.
        // Beyond those constraints the exact value buys nothing, so it matches
        // stagenet: divergence between mainnet and its rehearsal network is the
        // defect that produced this finding, and parity is worth more than a
        // smaller number.
        //
        // BIP34Hash stays null. It is the hash of the block AT BIP34Height, which
        // cannot be known before launch, and its only use is letting ConnectBlock
        // skip the BIP30 duplicate-txid scan. A null hash never matches, so BIP30
        // stays enforced by lookup forever — strictly more checking, at the cost of
        // one coins-cache probe per transaction. The stale Dogecoin hash had the
        // same effect while also being a lie.
        consensus.BIP34Height = 100;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 0;   // CHECKLOCKTIMEVERIFY enforced from genesis
        consensus.BIP66Height = 0;   // strict DER enforced from genesis
        consensus.powLimit = uint256S("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 20;
        consensus.nPowTargetTimespan = 4 * 60 * 60;                                                          // pre-digishield: 4 hours
        consensus.nPowTargetSpacing = 60;                                                                    // 1 minute
        consensus.fDigishieldDifficultyCalculation = false;
        consensus.nCoinbaseMaturity = 30;
        // Finality horizon (Analysis [A], 2026-06-22): refuse reorgs deeper than
        // this. 288 blocks ~= 4.8h at 1-min spacing, >>any natural reorg depth.
        // TEAM-TUNABLE policy value (smaller = faster finality + smaller
        // double-spend window; must stay well above the deepest natural reorg).
        // Propagates into digishieldConsensus via the copy below.
        consensus.nMaxReorgDepth = 288;
        consensus.fSimplifiedRewards = true; // Deterministic subsidy: 100,000 SOQ initial, 47B/250k-halving schedule (no random rewards); see GetSoqucoinBlockSubsidy
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowAllowDigishieldMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 9576; // 95% of 10,080
        consensus.nMinerConfirmationWindow = 10080;      // 60 * 24 * 7 = 10,080 blocks, or one week
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999;   // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113 (CSV) and SegWit (BIP141/143/147).
        // g7c: these are the BASE witness framework the entire Dilithium model rides on.
        // They must be active from genesis on mainnet. The inherited upstream
        // BIP9 windows below (real 2016/2017 timestamps, SegWit nTimeout=0) resolve to
        // THRESHOLD_FAILED on a 2026-genesis chain, which would leave every witness
        // program (v0-v7: all Dilithium/PAT/LatticeFold outputs) anyone-can-spend.
        // BIP9 signaling cannot activate them either (AuxPoW chain-id occupies the
        // version high bits — see DL-P96). So they are set ALWAYS_ACTIVE, matching the
        // live stagenet config. See DL-G7C-SEGWIT-CSV-GENESIS-ACTIVATION.md.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;


        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // SOQ-P002: LatticeFold+ (OP_CHECKFOLDPROOF) — WITHDRAWN from launch consensus.
        // This was ALWAYS_ACTIVE from genesis under the April 2026 "new chain, privacy from
        // block 0" decision. That decision is withdrawn: the verifier reads the statement
        // fields (t_coeffs, c) from the untrusted proof blob and every algebraic check is
        // homogeneous in the witness, so the all-zero witness satisfies all of them. The only
        // non-homogeneous check is the Fiat-Shamir seed, a public value the spender recomputes.
        // A proof carrying no valid Dilithium signature therefore verifies. Consensus gates
        // this opcode via BIP9 VersionBitsState (validation.cpp:1470/3131), NOT the vestigial
        // nLatticeFoldActivationHeight below, so ALWAYS_ACTIVE was a live mainnet forgery path
        // from genesis.
        //
        // nStartTime=0 / nTimeout=0 => THRESHOLD_FAILED (terminal, never ACTIVE), the same
        // never-active idiom used for LATTICEBP below. SCRIPT_VERIFY_LATTICEFOLD is then never
        // set on mainnet, which makes both entry points unreachable: OP_CHECKFOLDPROOF in a
        // script returns SCRIPT_ERR_BAD_OPCODE (interpreter.cpp:316) and the witness-v3 program
        // short-circuits before EvalCheckFoldProof (interpreter.cpp:1652).
        //
        // Witness v3 (OP_3) stays relay-nonstandard via the BIP141 s4 future-witness rejection
        // in policy.cpp — it is NOT one of the v5-v9 carve-outs — so a v3 output cannot be
        // funded through normal relay while it is anyone-can-spend. Do not add OP_3 to those
        // carve-outs while this deployment is inactive.
        //
        // The confidential-transaction purpose is served by the flag-2 aggregation (pack) path.
        // Reactivate on mainnet only with a real prover, a statement anchored to a commitment
        // fixed OUTSIDE the proof, and a re-audit. Regression guard:
        // latticefold_tests.cpp: mainnet_latticefold_deployment_never_active.
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nStartTime = 0;  // Not started
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nTimeout = 0;    // Never activates

        // SOQ-P003: Lattice-BP++ Range Proofs — NOT ACTIVE (future soft-fork)
        // Post-quantum confidential transaction amount hiding using Ring-LWE
        // commitments. Activation requires separate soft-fork after audit.
        consensus.vDeployments[Consensus::DEPLOYMENT_SOQUOBSCURA].bit = 5;
        consensus.vDeployments[Consensus::DEPLOYMENT_SOQUOBSCURA].nStartTime = 0;  // Not started
        consensus.vDeployments[Consensus::DEPLOYMENT_SOQUOBSCURA].nTimeout = 0;    // Never activates

        // SOQ-AUD2-002: USDSOQ Stablecoin — NOT ACTIVE (future BIP9 soft-fork)
        // Activation requires miner signaling after Halborn audit.
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nStartTime = 0;  // Not started
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nTimeout = 0;    // Never activates

        // DL-BTCSOQ-CONSENSUS-NATIVE: BTCSOQ — NOT ACTIVE on mainnet (dormant pending Phase 2 audit)
        consensus.vDeployments[Consensus::DEPLOYMENT_BTCSOQ].bit = 14;
        consensus.vDeployments[Consensus::DEPLOYMENT_BTCSOQ].nStartTime = 0;  // Not started
        consensus.vDeployments[Consensus::DEPLOYMENT_BTCSOQ].nTimeout = 0;    // Never activates

        // SOQ-COV-012 [DOC]: Covenant opcode BIP9 activation — MAINNET
        // ============================================================
        // CTV (BIP 119), APO (BIP 118), and CSFS (BIP 348) are NOT YET
        // activated on mainnet. Activation is gated on Halborn Phase 2
        // audit sign-off covering SOQ-COV-001 through SOQ-COV-012.
        //
        // Activation procedure:
        //   1. Halborn Phase 2 audit completes and signs off on covenant fixes
        //   2. nStartTime is set to the UNIX timestamp of a future signaling window
        //   3. nTimeout is set to nStartTime + 1 year (standard BIP9 window)
        //   4. STANDARD_SCRIPT_VERIFY_FLAGS in policy.h is updated to include the
        //      relevant SCRIPT_VERIFY_* flags so mempool enforces covenant policy
        //
        // Until activation:
        //   - CTV/APO/CSFS scripts evaluate as NOP (harmless; soft-fork safe)
        //   - Covenant transactions are NOT standard and will not relay
        //   - Regtest and stagenet have these flags ALWAYS_ACTIVE for testing
        //
        // Reference: DL-COVENANT-POST-AUDIT-HARDENING.md, SOQ-COV-012
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].bit = 7;
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].nStartTime = 0;  // NOT ACTIVE: pending Halborn Phase 2 audit
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].nTimeout = 0;    // Not yet scheduled

        consensus.vDeployments[Consensus::DEPLOYMENT_APO].bit = 8;
        consensus.vDeployments[Consensus::DEPLOYMENT_APO].nStartTime = 0;  // NOT ACTIVE: pending Halborn Phase 2 sighash audit
        consensus.vDeployments[Consensus::DEPLOYMENT_APO].nTimeout = 0;    // Not yet scheduled

        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].nStartTime = 0;  // NOT ACTIVE: pending Halborn Phase 2 CSFS audit
        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].nTimeout = 0;    // Not yet scheduled

        // SOQ-AUD2-009: P2WSH-Dilithium (witness v6) — NOT ACTIVE on mainnet
        // Enables covenant script execution (CTV vaults, CSFS oracles, L2SOQ Lightning).
        // BIP9 activation post-audit: set nStartTime to future timestamp, miners signal bit 10.
        // See DL-P2WSH-DILITHIUM.md for full design.
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].nStartTime = 0;  // NOT ACTIVE: pending Halborn Phase 2 audit
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].nTimeout = 0;    // Not yet scheduled

        // SOQ-ARCH-003: UTXO Cost — NOT ACTIVE on mainnet (pending Phase 2 audit)
        // Cardano-style utxoCostPerByte: min output value = UTXO_COST_PER_BYTE × output_size.
        // BIP9 activation post-Phase 2 audit: set nStartTime, miners signal bit 11.
        // See DL-SOQ-FEE-ARCHITECTURE-V3.md.
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].bit = 11;
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].nStartTime = 0;  // NOT ACTIVE: pending Halborn Phase 2 audit
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].nTimeout = 0;    // Not yet scheduled

        // OP_CHECKDILITHIUMKEYHASH — NOT ACTIVE on mainnet (pending Phase 2 audit)
        // Key-committed Dilithium signature verification for eLTOO 2-of-2 multisig.
        // Enables L2SOQ Lightning channels with Dilithium pubkeys > MAX_SCRIPT_ELEMENT_SIZE.
        // BIP9 activation post-audit: set nStartTime, miners signal bit 12.
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].bit = 12;
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].nStartTime = 0;  // NOT ACTIVE: pending Halborn Phase 2 audit
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].nTimeout = 0;    // Not yet scheduled

        // DL-V6-CONTROLFLOW-RESTORE: restore branch/timelock/hashlock opcodes in v6 EvalScript.
        // BIP9 activation post-audit: set nStartTime, miners signal bit 13.
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].bit = 13;
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].nStartTime = 0;  // NOT ACTIVE: pending Halborn Phase 2 audit
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].nTimeout = 0;    // Not yet scheduled

        // p96 / Option D — MAINNET flag-day activation heights.
        // These post-launch soft-forks activate by scheduled HEIGHT (not BIP9 miner
        // signaling: Soqucoin is merge-mined with no signaling constituency; see
        // DL-P96-BLOCK-VERSION-ACTIVATION.md). All ship NOT_SCHEDULED (dormant) — a
        // coordinated release sets a real height for each as its Halborn Phase 2
        // scope clears. The nStartTime/nTimeout above are retained but NOT consulted
        // for these deployments. (CHECKPATAGG stays always-active on BIP9; LATTICEFOLD is
        // BIP9-inactive above; CSV/SegWit stay on the historical BIP9 windows.)
        consensus.vDeployments[Consensus::DEPLOYMENT_SOQUOBSCURA].nActivationHeight        = Consensus::BIP9Deployment::NOT_SCHEDULED;
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nActivationHeight           = Consensus::BIP9Deployment::NOT_SCHEDULED;
        consensus.vDeployments[Consensus::DEPLOYMENT_BTCSOQ].nActivationHeight           = Consensus::BIP9Deployment::NOT_SCHEDULED;
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].nActivationHeight              = Consensus::BIP9Deployment::NOT_SCHEDULED;
        consensus.vDeployments[Consensus::DEPLOYMENT_APO].nActivationHeight              = Consensus::BIP9Deployment::NOT_SCHEDULED;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].nActivationHeight             = Consensus::BIP9Deployment::NOT_SCHEDULED;
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].nActivationHeight  = Consensus::BIP9Deployment::NOT_SCHEDULED;
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].nActivationHeight        = Consensus::BIP9Deployment::NOT_SCHEDULED;
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].nActivationHeight = Consensus::BIP9Deployment::NOT_SCHEDULED;
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].nActivationHeight   = Consensus::BIP9Deployment::NOT_SCHEDULED;


        // The best chain should have at least this much work. Zero for launch:
        // this field is an IBD heuristic, and IsInitialBlockDownload() gates the
        // work-serving RPCs (getblocktemplate exempts only stagenet/regtest;
        // AuxMiningCheck exempts nothing), so any unreachable value here means a
        // fresh mainnet can never serve mining work and never leaves height 0.
        // The inherited upstream pin (chainwork at upstream block 5,050,000) did
        // exactly that; found and driven 2026-08-29 (Phase A pre-launch audit,
        // lane A1). Re-pin to real accumulated work in post-launch releases as
        // part of the checkpoint-update routine (doc/release-process.md).
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");
        consensus.dilithiumOnlyHeight = 0;
        consensus.dilithiumOnlyHeight = 0;
        // VESTIGIAL: never read by consensus (BIP9 VersionBitsState is the only gate for
        // DEPLOYMENT_LATTICEFOLD). Retained only so the struct layout is unchanged. Do NOT
        // wire this up as an activation path — it would bypass the deactivation above.
        consensus.nLatticeFoldActivationHeight = 0;

        // AuxPoW parameters
        consensus.nAuxpowChainId = 0x5351;   // "SQ" = Soqucoin (unique chain ID)
        // lw7: reject AuxPoW blocks that don't carry our chain id (and, via the
        // parent-side check, parents that DO) — blocks cross-chain / self-merge-mining
        // PoW reuse. Safe on mainnet: the chain is fresh and the miner (SetBaseVersion)
        // stamps chain id 0x5351 on every block from genesis. The check is scoped to
        // AuxPoW blocks (soqucoin.cpp), so solo blocks are unaffected.
        consensus.fStrictChainId = true;
        consensus.fAllowLegacyBlocks = true; // Allow both legacy Scrypt AND AuxPoW blocks
        consensus.nAuxpowStartHeight = 0;    // AuxPoW from genesis — merge mining available from block 0
        consensus.nHeightEffective = 0;

        // CONSENSUS FIX (DL-MAINNET-DIFFICULTY-TRANSITION):
        // DigiShield per-block difficulty adjustment from block 1 (matching stagenet).
        // Soqucoin launches from its own genesis — upstream height 145000 is meaningless here.
        // DigiShield must activate early so the chain can handle AuxPoW hashrate
        // without being stuck on 240-block retarget intervals.
        //
        // Since AuxPoW is allowed from block 0 (nAuxpowStartHeight=0), and DigiShield
        // activates at block 1, we merge them into a single consensus tier at height 1.
        // Block 0 (genesis) uses base consensus; block 1+ uses DigiShield + AuxPoW.
        digishieldConsensus = consensus;
        digishieldConsensus.nHeightEffective = 1;
        digishieldConsensus.fSimplifiedRewards = true;
        digishieldConsensus.fDigishieldDifficultyCalculation = true;
        digishieldConsensus.nPowTargetTimespan = 60; // post-digishield: 1 minute
        // Coinbase maturity == the finality horizon (288). Ruled 2026-09-07,
        // bead mainnet-maturity-240-not-30-mp5o.
        //
        // INVARIANT: nCoinbaseMaturity >= nMaxReorgDepth. The horizon rejects a
        // fork only at depth >= nMaxReorgDepth (validation.cpp, "bad-fork-beyond-
        // finality"), so every reorg SHALLOWER than 288 is consensus-legal and
        // accepted. At the inherited value of 240 a coinbase became spendable 48
        // blocks INSIDE that probabilistic window, and coinbase is the one output
        // class whose reversal invalidates every descendant spend.
        //
        // ⚠ WHAT THIS BUYS, STATED HONESTLY. The horizon is enforced in exactly
        // one place — ContextualCheckBlockHeader — and only when a header is
        // FIRST accepted: AcceptBlockHeader returns early for a header already in
        // mapBlockIndex, so the check never re-runs. An attacker who gets headers
        // accepted while the fork is still shallow and then WITHHOLDS the blocks
        // can still force a deep reorg when they are finally released. This
        // invariant therefore closes the header-arrives-on-time case, which is
        // the reachable one, and not every case. Do NOT restate it as "finality
        // is absolute" — the residual is real, is tracked as bead
        // finality-horizon-header-only-8p5y, and is written up in
        // doc/PAT_WITNESS_PRUNING.md §6.
        //
        // The 240 came from upstream Dogecoin (it arrived with the height-aware
        // consensus work in 2017); the 288 horizon was added here on 2026-06-23.
        // The two constants constrain each other and were set nine years apart by
        // different projects, so nothing had ever compared them. Do not put this
        // back to 240 to match Dogecoin: this chain has a finality rule and
        // Dogecoin does not, which is exactly why the values must differ.
        //
        // Cost: ~48 min of additional wait at 60s spacing. Absorbed by the
        // consensus digest per tier, so this re-pins the digest deliberately.
        digishieldConsensus.nCoinbaseMaturity = 288;

        // AuxPoW + DigiShield from block 1 (merged tier).
        // Both standalone Scrypt blocks (solo miners) and AuxPoW blocks
        // (merge-mining pools) accepted. fAllowLegacyBlocks = true enables
        // Dual mining model. nAuxpowStartHeight=0 on base consensus
        // means AuxPoW blocks are valid from genesis, but the DigiShield
        // difficulty adjustment kicks in at block 1 via this tier.
        auxpowConsensus = digishieldConsensus;
        auxpowConsensus.nHeightEffective = 1; // Same tier as DigiShield — BST valid
        auxpowConsensus.fAllowLegacyBlocks = true;

        // Assemble the binary search tree of consensus parameters
        // Simple two-node tree: genesis (left) and block 1+ (right)
        pConsensusRoot = &consensus;
        consensus.pRight = &auxpowConsensus;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xf5;
        pchMessageStart[1] = 0xe1;
        pchMessageStart[2] = 0xd5;
        pchMessageStart[3] = 0xc1;
        nDefaultPort = 33388;
        nPruneAfterHeight = 100000;

        // Genesis ceremony 2026-09-02 (doc/GENESIS_CEREMONY.md): purpose-built
        // genesis replacing the inherited Dogecoin template. nTime is the
        // ceremony's UTC epoch; nonce mined in-tree (genesis_remine_tests,
        // 3,319,596 attempts) and independently recomputed via pure-Python
        // scrypt/sha256d (ceremony log of record).
        // Scrypt PoW: 00000e6981993c98a9a7c1e534a8368f6e67f5f2330ab50646c10c477774be3f
        genesis = CreateGenesisBlockMainnet(1788365451, 3319596, 0x1e0ffff0, 1, 88 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();
        digishieldConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        assert(consensus.hashGenesisBlock == uint256S("0x0d828600816cbd7c23789660b53f90cb6ec7ff85540698e13845eb2d2f0486a8"));
        assert(genesis.hashMerkleRoot == uint256S("0x8c4364d66ab67d746ddf1c5e0a316da5af9bbf7dc27bdd02e06ea77aec88ed28"));

        // Genesis-migration allocation constants (DL-GENESIS-MIGRATION-IMPLEMENTATION §A1).
        // Deliberately NOT set here: hashMigrationOutputs stays null, nMigrationTotal 0,
        // nMigrationHeight 0, so the rule is inert. If a migration window is ever run,
        // the ceremony sets all three beside these genesis pins (with vMigrationOutputs
        // compiled in and asserted against the hash) at a scheduled post-genesis height,
        // per doc/GENESIS_CEREMONY.md. Struct defaults propagate into digishieldConsensus
        // and auxpowConsensus via the copies above.

        // SOQ-H3: Lattice-BP++ consensus seed — derived from genesis hash
        consensus.latticeBPSeed = ComputeSoquObscuraSeed(
            consensus.hashGenesisBlock,
            "soqucoin-latticebp-params-v1",
            "N=256,Q=8380417,K=4,range=64");
        digishieldConsensus.latticeBPSeed = consensus.latticeBPSeed;
        auxpowConsensus.latticeBPSeed = consensus.latticeBPSeed;

        // Soqucoin mainnet DNS seeds — DNS-only (grey cloud) A records in Cloudflare
        // These resolve to SOQUPOOL geo-distributed mining mesh nodes
        vSeeds.push_back(CDNSSeedData("soqu.org", "seed1.soqu.org", true));
        vSeeds.push_back(CDNSSeedData("soqu.org", "seed2.soqu.org", true));
        vSeeds.push_back(CDNSSeedData("soqu.org", "seed3.soqu.org", true));

        base58Prefixes[PUBKEY_ADDRESS] = boost::assign::list_of(63)(22).convert_to_container<std::vector<unsigned char> >(); // C5 prefix for mainnet
        base58Prefixes[SCRIPT_ADDRESS] = boost::assign::list_of(9)(18).convert_to_container<std::vector<unsigned char> >();  // 95 prefix
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 158);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x02)(0xfa)(0xca)(0xfd).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x02)(0xfa)(0xc3)(0x98).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        // Mainnet checkpoints — genesis only (updated after genesis re-mine)
        // Additional checkpoints will be added as the chain matures
        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
                (0, consensus.hashGenesisBlock)
        };

        // Mainnet chain transaction data — fresh chain, no history yet
        // Updated periodically as chain grows (timestamp, total txns, txns/sec)
        chainTxData = ChainTxData{
            0,    // No checkpoint timestamp yet — updated after genesis
            0,    // No transactions yet
            0.0   // No estimated tx rate yet
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams
{
private:
    Consensus::Params digishieldConsensus;
    Consensus::Params auxpowConsensus;

public:
    CTestNetParams()
    {
        strNetworkID = "test";
        bech32HRP = "sq";

        // Blocks 0 - 144999 are pre-Digishield
        consensus.nHeightEffective = 0;
        consensus.nPowTargetTimespan = 4 * 60 * 60; // pre-digishield: 4 hours
        consensus.fDigishieldDifficultyCalculation = false;
        consensus.nCoinbaseMaturity = 30;
        consensus.nMaxReorgDepth = 288; // Finality horizon (Analysis [A]); see CMainParams. Propagates into digishieldConsensus.
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowAllowDigishieldMinDifficultyBlocks = false;
        consensus.nSubsidyHalvingInterval = 250000; // 47B schedule — mirror mainnet (bead c61)
        consensus.nInitialSubsidy = 100000; // 47B launch reward
        consensus.nMajorityEnforceBlockUpgrade = 501;
        consensus.nMajorityRejectBlockOutdated = 750;
        consensus.nMajorityWindow = 1000;
        // BIP34 is never enforced in Soqucoin v2 blocks, so we enforce from v3
        // The same Dogecoin inheritance mainnet carried, from Dogecoin TESTNET this
        // time. Mirrored to the mainnet values, consistent with the lw7 posture
        // elsewhere in this file: testnet3 is retired and exists to rehearse
        // mainnet, so it must not validate under looser rules than the network it
        // rehearses. See bead zz2f.
        consensus.BIP34Height = 100;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 20;
        consensus.nPowTargetTimespan = 4 * 60 * 60;                                                          // pre-digishield: 4 hours
        consensus.nPowTargetSpacing = 60;                                                                    // 1 minute
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 2880; // 2 days (note this is significantly lower than Bitcoin standard)
        consensus.nMinerConfirmationWindow = 10080;      // 60 * 24 * 7 = 10,080 blocks, or one week
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999;   // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        // CSV mirrors mainnet: ALWAYS_ACTIVE. The inherited 2016/2017 Dogecoin
        // BIP9 window would resolve THRESHOLD_FAILED on a 2026-genesis chain,
        // silently disabling BIP68/112/113 on testnet forever (F8 class; the
        // exact hazard the mainnet comment describes). Fixed for FC4.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;


        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // LatticeFold+ activation — ALWAYS_ACTIVE from genesis (April 2026 decision)
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].bit = 28;
        // SOQ-P002: LatticeFold+ is RETIRED on every network, not just mainnet.
        // It was ALWAYS_ACTIVE here while mainnet had already withdrawn it, so this
        // network validated under a rule mainnet refuses — and the rule in question
        // is a verifier that accepts an all-zero witness (see the CMainParams block
        // for the full reasoning). Withdrawing SoquObscura from the test networks was
        // done for exactly this reason in bead 2pru; LatticeFold+ has the same defect
        // and was missed. A rehearsal network running a verifier known to accept
        // forged proofs is not rehearsing anything.
        //
        // Verified safe against the LIVE stagenet chain before making this change:
        // across all 48,733 blocks there is not one witness-v3 output, and the only
        // two v6 covenant spends carry the witnessScript
        // <32> OP_NOP7 <32> OP_NOP7 OP_1, so OP_CHECKFOLDPROOF has never executed.
        // Clearing the flag therefore cannot alter the validity of any historical
        // block. (Note the direction matters: for a v3 PROGRAM clearing the flag is a
        // relaxation, but for OP_CHECKFOLDPROOF inside a script it is a tightening —
        // SCRIPT_ERR_BAD_OPCODE — which is why the covenant witnessScripts had to be
        // read rather than assumed.)
        //
        // nStartTime=0 / nTimeout=0 => THRESHOLD_FAILED, terminal. This deployment is
        // queried through VersionBitsState, NOT DeploymentActiveAtHeight, so an
        // nActivationHeight would be ignored here — do not add one thinking it locks
        // anything down. Superseded by SoquObscura; witness v3 is retired and must not
        // be reallocated. See test/witness_version_allocation_tests.cpp.
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nStartTime = 0;  // retired
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nTimeout = 0;    // never activates

        // SoquObscura confidential outputs — WITHDRAWN 2026-08-17 (S1/P2).
        // The consensus range verifier accepts an all-zero witness carrying a correct
        // Fiat-Shamir seed, so a confidential output proves nothing about its amount.
        // Dormant here until a corpus-gated verifier replaces it.
        // See doc/design/DL-SOQUOBSCURA-STATE-MACHINE.md P2.
        consensus.vDeployments[Consensus::DEPLOYMENT_SOQUOBSCURA].bit = 5;
        consensus.vDeployments[Consensus::DEPLOYMENT_SOQUOBSCURA].nStartTime = 0;  // Not started
        consensus.vDeployments[Consensus::DEPLOYMENT_SOQUOBSCURA].nTimeout = 0;    // Never activates

        // SOQ-AUD2-002: USDSOQ Stablecoin — ACTIVE on stagenet for integration testing
        // Mainnet remains NEVER_ACTIVE pending Halborn audit. See DL-USDSOQ-STABLECOIN.md.
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // DL-BTCSOQ-CONSENSUS-NATIVE: BTCSOQ — ACTIVE for integration testing; mainnet dormant.
        consensus.vDeployments[Consensus::DEPLOYMENT_BTCSOQ].bit = 14;
        consensus.vDeployments[Consensus::DEPLOYMENT_BTCSOQ].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_BTCSOQ].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_BTCSOQ].nActivationHeight = 0;

        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].bit = 7;
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_APO].bit = 8;
        consensus.vDeployments[Consensus::DEPLOYMENT_APO].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_APO].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // SOQ-AUD2-009: P2WSH-Dilithium (witness v6) — ALWAYS_ACTIVE on testnet/stagenet
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // SOQ-ARCH-003: UTXO Cost — ALWAYS_ACTIVE on testnet for integration testing
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].bit = 11;
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // OP_CHECKDILITHIUMKEYHASH — ALWAYS_ACTIVE on testnet for integration testing
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].bit = 12;
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // DL-V6-CONTROLFLOW-RESTORE — ALWAYS_ACTIVE on testnet for eLTOO/HTLC integration testing
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].bit = 13;
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // p96 / Option D: height-gated activation, height 0 = active from genesis
        // (equivalent to the ALWAYS_ACTIVE test behavior above). See CMainParams.
        //
        // ⛔ SOQUOBSCURA IS WITHDRAWN, AND THIS LINE IS THE ONE THAT MATTERS.
        // DeploymentActiveAtHeight() (consensus/params.h:206-210) reads ONLY
        // nActivationHeight; when it is set, nStartTime/nTimeout are NOT consulted.
        // Setting nStartTime=0/nTimeout=0 above and leaving this at 0 would be a NO-OP
        // — the deployment would stay active from genesis. NOT_SCHEDULED is what
        // actually withdraws it, and it must match CMainParams.
        // ⚠️ Do NOT "simplify" this to NO_HEIGHT_ACTIVATION: that sentinel falls back
        // to the BIP9 state machine, which would re-activate the feature.
        consensus.vDeployments[Consensus::DEPLOYMENT_SOQUOBSCURA].nActivationHeight        = Consensus::BIP9Deployment::NOT_SCHEDULED;
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nActivationHeight           = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].nActivationHeight              = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_APO].nActivationHeight              = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].nActivationHeight             = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].nActivationHeight  = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].nActivationHeight        = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].nActivationHeight = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].nActivationHeight   = 0;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");
        consensus.dilithiumOnlyHeight = 0;
        consensus.nLatticeFoldActivationHeight = 0; // Active immediately for testing

        // AuxPoW parameters
        consensus.nAuxpowChainId = 0x5351; // "SQ" = Soqucoin (unique chain ID)
        consensus.fStrictChainId = true;   // lw7 — testnet3 is retired; mirror mainnet
        consensus.nHeightEffective = 0;
        consensus.fAllowLegacyBlocks = true; // Allow both legacy Scrypt AND AuxPoW blocks
        consensus.nAuxpowStartHeight = 0;    // AuxPoW from genesis — mirror mainnet (bead lnq)

        // DigiShield + AuxPoW from block 1 — mirrors mainnet's merged tier.
        // (bead soqucoin-build-lnq: the previous 145000/157500/158100 tier
        // ladder was un-customized upstream testnet history, meaningless on
        // Soqucoin's own genesis. Testnet3 is retired in favor of stagenet,
        // so this has no live-network impact; aligned to the mainnet design
        // for a possible future re-mine.)
        digishieldConsensus = consensus;
        digishieldConsensus.nHeightEffective = 1;
        digishieldConsensus.nPowTargetTimespan = 60; // post-digishield: 1 minute
        digishieldConsensus.fDigishieldDifficultyCalculation = true;
        digishieldConsensus.fSimplifiedRewards = true;
        digishieldConsensus.nCoinbaseMaturity = 240;
        // Testnet keeps the min-difficulty testing allowances (terminal state
        // of the old 157500+ tiers).
        digishieldConsensus.fPowAllowDigishieldMinDifficultyBlocks = true;
        digishieldConsensus.fPowAllowMinDifficultyBlocks = true;

        // AuxPoW shares the block-1 tier (same as mainnet — BST valid)
        auxpowConsensus = digishieldConsensus;
        auxpowConsensus.nHeightEffective = 1;
        auxpowConsensus.fAllowLegacyBlocks = true;

        // Assemble the binary search tree of parameters
        // Simple two-node tree: genesis (left) and block 1+ (right)
        pConsensusRoot = &consensus;
        consensus.pRight = &auxpowConsensus;

        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xc1;
        pchMessageStart[2] = 0xb7;
        pchMessageStart[3] = 0xdc;
        nDefaultPort = 44556;
        nPruneAfterHeight = 1000;

        // Soqucoin Testnet3 Genesis Block - Dec 2025
        // Unique genesis isolates Soqucoin from upstream testnet
        // "First quantum-resistant Scrypt chain - Soqucoin Testnet3 Dec 2025"
        genesis = CreateGenesisBlockTestnet3(1766813480, 1014070, 0x1e0ffff0, 1, 88 * COIN);

        // TODO: Re-mine testnet3 genesis with new nonce after CTxOut format change
        // Testnet3 is being retired in favor of stagenet.
        consensus.hashGenesisBlock = genesis.GetHash();
        digishieldConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        // Genesis hash assertion deferred — testnet3 is being retired

        // SOQ-H3: Lattice-BP++ consensus seed
        consensus.latticeBPSeed = ComputeSoquObscuraSeed(
            consensus.hashGenesisBlock,
            "soqucoin-latticebp-params-v1",
            "N=256,Q=8380417,K=4,range=64");
        digishieldConsensus.latticeBPSeed = consensus.latticeBPSeed;
        auxpowConsensus.latticeBPSeed = consensus.latticeBPSeed;

        // Clear all upstream seeds - Soqucoin testnet is isolated
        vSeeds.clear();
        // Soqucoin DNS seed nodes - January 2026
        vSeeds.push_back(CDNSSeedData("soqu.org", "seed1.soqu.org")); // Testnet3 VPS
        vSeeds.push_back(CDNSSeedData("soqu.org", "seed2.soqu.org")); // Stagenet VPS
        vSeeds.push_back(CDNSSeedData("soqu.org", "seed3.soqu.org")); // Pinode (home node)

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 113); // 0x71
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196); // 0xc4
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 241);     // 0xf1
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xcf).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of(0, uint256S("0x000001cf9dfb272cb071d8490aa5a1108897de05bfa4b95f48097a2d4f0e7809"))};

        chainTxData = ChainTxData{
            0,
            0,
            0};
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams
{
private:
    Consensus::Params digishieldConsensus;
    Consensus::Params auxpowConsensus;

public:
    CRegTestParams()
    {
        strNetworkID = "regtest";
        bech32HRP = "sq";
        consensus.nSubsidyHalvingInterval = 150;
        // Regtest keeps the historical 500,000 launch reward as a test fixture: the
        // qa/rpc-tests functional suite hardcodes 500K-coinbase balances. Mainnet
        // economics (100K) are exercised by the C++ subsidy unit tests, not regtest.
        consensus.nInitialSubsidy = 500000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351;                                                                        // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251;                                                                        // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 1;
        consensus.nPowTargetTimespan = 4 * 60 * 60;                                                          // pre-digishield: 4 hours
        consensus.nPowTargetSpacing = 1;                                                                     // regtest: 1 second blocks
        consensus.fDigishieldDifficultyCalculation = false;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 540; // 75% for testchains
        consensus.nMinerConfirmationWindow = 720;       // Faster than normal for regtest (2,520 instead of 10,080)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;


        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // LatticeFold+ activation — ALWAYS_ACTIVE for regtest
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].bit = 28;
        // SOQ-P002: LatticeFold+ is RETIRED on every network, not just mainnet.
        // It was ALWAYS_ACTIVE here while mainnet had already withdrawn it, so this
        // network validated under a rule mainnet refuses — and the rule in question
        // is a verifier that accepts an all-zero witness (see the CMainParams block
        // for the full reasoning). Withdrawing SoquObscura from the test networks was
        // done for exactly this reason in bead 2pru; LatticeFold+ has the same defect
        // and was missed. A rehearsal network running a verifier known to accept
        // forged proofs is not rehearsing anything.
        //
        // Verified safe against the LIVE stagenet chain before making this change:
        // across all 48,733 blocks there is not one witness-v3 output, and the only
        // two v6 covenant spends carry the witnessScript
        // <32> OP_NOP7 <32> OP_NOP7 OP_1, so OP_CHECKFOLDPROOF has never executed.
        // Clearing the flag therefore cannot alter the validity of any historical
        // block. (Note the direction matters: for a v3 PROGRAM clearing the flag is a
        // relaxation, but for OP_CHECKFOLDPROOF inside a script it is a tightening —
        // SCRIPT_ERR_BAD_OPCODE — which is why the covenant witnessScripts had to be
        // read rather than assumed.)
        //
        // nStartTime=0 / nTimeout=0 => THRESHOLD_FAILED, terminal. This deployment is
        // queried through VersionBitsState, NOT DeploymentActiveAtHeight, so an
        // nActivationHeight would be ignored here — do not add one thinking it locks
        // anything down. Superseded by SoquObscura; witness v3 is retired and must not
        // be reallocated. See test/witness_version_allocation_tests.cpp.
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nStartTime = 0;  // retired
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nTimeout = 0;    // never activates

        // SoquObscura confidential outputs — WITHDRAWN 2026-08-17 (S1/P2).
        // ⚠️ Regtest is withdrawn DELIBERATELY, not by oversight. Leaving it active
        // keeps every functional test running against a verifier known to accept
        // forged proofs, which is how a broken verifier keeps looking fine.
        consensus.vDeployments[Consensus::DEPLOYMENT_SOQUOBSCURA].bit = 5;
        consensus.vDeployments[Consensus::DEPLOYMENT_SOQUOBSCURA].nStartTime = 0;  // Not started
        consensus.vDeployments[Consensus::DEPLOYMENT_SOQUOBSCURA].nTimeout = 0;    // Never activates

        // SOQ-AUD2-002: USDSOQ Stablecoin — ALWAYS_ACTIVE for regtest
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].bit = 7;
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_APO].bit = 8;
        consensus.vDeployments[Consensus::DEPLOYMENT_APO].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_APO].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // SOQ-AUD2-009: P2WSH-Dilithium (witness v6) — ALWAYS_ACTIVE for regtest
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // SOQ-ARCH-003: UTXO Cost — ALWAYS_ACTIVE for regtest
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].bit = 11;
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // OP_CHECKDILITHIUMKEYHASH — ALWAYS_ACTIVE for regtest
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].bit = 12;
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // DL-V6-CONTROLFLOW-RESTORE — ALWAYS_ACTIVE for regtest (eLTOO/HTLC unit + functional tests)
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].bit = 13;
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // DL-BTCSOQ-CONSENSUS-NATIVE: BTCSOQ — ALWAYS_ACTIVE for regtest (consensus-native asset tests)
        consensus.vDeployments[Consensus::DEPLOYMENT_BTCSOQ].bit = 14;
        consensus.vDeployments[Consensus::DEPLOYMENT_BTCSOQ].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_BTCSOQ].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_BTCSOQ].nActivationHeight = 0;

        // p96 / Option D: height-gated activation, height 0 = active from genesis
        // (equivalent to the ALWAYS_ACTIVE test behavior above). See CMainParams.
        //
        // ⛔ SOQUOBSCURA IS WITHDRAWN, AND THIS LINE IS THE ONE THAT MATTERS.
        // DeploymentActiveAtHeight() (consensus/params.h:206-210) reads ONLY
        // nActivationHeight; when it is set, nStartTime/nTimeout are NOT consulted.
        // Setting nStartTime=0/nTimeout=0 above and leaving this at 0 would be a NO-OP
        // — the deployment would stay active from genesis. NOT_SCHEDULED is what
        // actually withdraws it, and it must match CMainParams.
        // ⚠️ Do NOT "simplify" this to NO_HEIGHT_ACTIVATION: that sentinel falls back
        // to the BIP9 state machine, which would re-activate the feature.
        consensus.vDeployments[Consensus::DEPLOYMENT_SOQUOBSCURA].nActivationHeight        = Consensus::BIP9Deployment::NOT_SCHEDULED;
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nActivationHeight           = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].nActivationHeight              = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_APO].nActivationHeight              = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].nActivationHeight             = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].nActivationHeight  = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].nActivationHeight        = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].nActivationHeight = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].nActivationHeight   = 0;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        // AuxPow parameters
        consensus.nAuxpowChainId = 0x5351;   // "SQ" = Soqucoin (unique chain ID)
        consensus.fStrictChainId = true;     // lw7 — regtest is ephemeral; mirror mainnet
        consensus.fAllowLegacyBlocks = true; // Allow both legacy Scrypt AND AuxPoW blocks
        consensus.nAuxpowStartHeight = 20;   // Regtest: match auxpowConsensus.nHeightEffective

        // Soqucoin parameters
        consensus.fSimplifiedRewards = true;
        consensus.nCoinbaseMaturity = 60; // For easier testability in RPC tests
        consensus.nMaxReorgDepth = 0;      // Disabled on regtest; functional tests opt in via -maxreorgdepth (see UpdateMaxReorgDepth)

        digishieldConsensus = consensus;
        digishieldConsensus.nHeightEffective = 10;
        digishieldConsensus.nPowTargetTimespan = 1; // regtest: also retarget every second in digishield mode, for conformity
        digishieldConsensus.fDigishieldDifficultyCalculation = true;
        digishieldConsensus.dilithiumOnlyHeight = 0;

        auxpowConsensus = digishieldConsensus;
        auxpowConsensus.fAllowLegacyBlocks = false;
        auxpowConsensus.nHeightEffective = 20;
        auxpowConsensus.dilithiumOnlyHeight = 0;

        // Assemble the binary search tree of parameters
        digishieldConsensus.pLeft = &consensus;
        digishieldConsensus.pRight = &auxpowConsensus;
        pConsensusRoot = &digishieldConsensus;

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 88 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();
        digishieldConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        // Phase 4: regtest genesis hash changed — byte-less CTxOut serialization.
        // Old (byte-ful): 0x22ad706761265b8c05cbc33ff212c1ad7c049afc4e15fc8c04f7e6824da9630f
        assert(consensus.hashGenesisBlock == uint256S("0x3d2160a3b5dc4a9d62e7e66a295f70313ac808440ef7400d6c0772171ce973a5"));

        // SOQ-H3: Lattice-BP++ consensus seed
        consensus.latticeBPSeed = ComputeSoquObscuraSeed(
            consensus.hashGenesisBlock,
            "soqucoin-latticebp-params-v1",
            "N=256,Q=8380417,K=4,range=64");
        digishieldConsensus.latticeBPSeed = consensus.latticeBPSeed;
        auxpowConsensus.latticeBPSeed = consensus.latticeBPSeed;
        // Old merkle root (byte-ful): 0xef6d97da4c49ec2be1f68b1608b62e15645237767a8a5f6e16747ede9b114920
        assert(genesis.hashMerkleRoot == uint256S("0x5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of(0, uint256S("0x3d2160a3b5dc4a9d62e7e66a295f70313ac808440ef7400d6c0772171ce973a5"))};

        chainTxData = ChainTxData{
            0,
            0,
            0};

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 111); // 0x6f
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196); // 0xc4
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // 0xef
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        // ⚠️ ALL THREE, for the same reason as UpdateActivationHeight below:
        // regtest's height-indexed consensus tree means a mutation applied to
        // `consensus` alone is invisible to every block above height 19
        // (bead tofg).
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
        digishieldConsensus.vDeployments[d].nStartTime = nStartTime;
        digishieldConsensus.vDeployments[d].nTimeout = nTimeout;
        auxpowConsensus.vDeployments[d].nStartTime = nStartTime;
        auxpowConsensus.vDeployments[d].nTimeout = nTimeout;
    }

    void UpdateActivationHeight(Consensus::DeploymentPos d, int nActivationHeight)
    {
        // ⚠️ ALL THREE, not just `consensus`. Regtest assembles a height-indexed
        // tree (consensus < 10, digishieldConsensus < 20, auxpowConsensus >= 20)
        // and GetConsensus(nHeight) returns whichever covers that height. The
        // deployment fields are set BEFORE the copies in the constructor, so they
        // agree at startup — but a mutation applied to `consensus` alone is
        // invisible to every block above height 19, which is every block a chain
        // fixture actually mines. Setting one struct here would look like it
        // worked and change nothing.
        consensus.vDeployments[d].nActivationHeight = nActivationHeight;
        digishieldConsensus.vDeployments[d].nActivationHeight = nActivationHeight;
        auxpowConsensus.vDeployments[d].nActivationHeight = nActivationHeight;
    }

    void UpdateMaxReorgDepth(int nMaxReorgDepth)
    {
        // ⚠️ ALL THREE structs, for the same height-indexed-tree reason as the
        // setters below (bead tofg): GetConsensus resolves heights above the
        // regtest auxpow boundary to auxpowConsensus, so a caller reading the
        // horizon at the tip height saw 0 here until 2026-09-01 — found when
        // witness-prune eligibility became the first consumer to read
        // nMaxReorgDepth at a high height through this override.
        consensus.nMaxReorgDepth = nMaxReorgDepth;
        digishieldConsensus.nMaxReorgDepth = nMaxReorgDepth;
        auxpowConsensus.nMaxReorgDepth = nMaxReorgDepth;
    }

    void UpdateMigrationParams(const uint256& hashOutputs, CAmount nTotal, int nHeight,
                               const std::vector<CTxOut>& vOutputs)
    {
        // ⚠️ ALL THREE structs, for the same height-indexed-tree reason as
        // UpdateActivationHeight above (bead tofg): a migration height above 19
        // resolves to auxpowConsensus, not `consensus`.
        consensus.hashMigrationOutputs = hashOutputs;
        consensus.nMigrationTotal = nTotal;
        consensus.nMigrationHeight = nHeight;
        digishieldConsensus.hashMigrationOutputs = hashOutputs;
        digishieldConsensus.nMigrationTotal = nTotal;
        digishieldConsensus.nMigrationHeight = nHeight;
        auxpowConsensus.hashMigrationOutputs = hashOutputs;
        auxpowConsensus.nMigrationTotal = nTotal;
        auxpowConsensus.nMigrationHeight = nHeight;
        vMigrationOutputs = vOutputs;
    }

    void UpdatePatCommitmentMandatoryHeight(int nHeight)
    {
        // Same height-indexed-tree caveat as the setters above (bead tofg).
        consensus.nPatCommitmentMandatoryHeight = nHeight;
        digishieldConsensus.nPatCommitmentMandatoryHeight = nHeight;
        auxpowConsensus.nPatCommitmentMandatoryHeight = nHeight;
    }
};
static CRegTestParams regTestParams;

/**
 * Stagenet - Mainnet rehearsal network
 * Mirrors mainnet consensus exactly:
 * - Real difficulty adjustment (fPowAllowMinDifficultyBlocks = false)
 * - Dilithium, PAT, LatticeFold+ all ALWAYS_ACTIVE from genesis
 * - Lattice-BP++ NOT_ACTIVE (future soft-fork, same as mainnet)
 * - fRequireStandard = true (reject non-standard txs)
 */
class CStageNetParams : public CChainParams
{
private:
    Consensus::Params digishieldConsensus;
    Consensus::Params auxpowConsensus;
    Consensus::Params maturityMirrorConsensus;

public:
    CStageNetParams()
    {
        strNetworkID = "stagenet";
        bech32HRP = "ssq"; // stagenet soqucoin

        // 47B schedule — stagenet mirrors mainnet economics (bead c61). At 250K
        // blocks/halving the first halving is ~174d out, so stagenet exercises the
        // schedule via unit tests, not by waiting for a live halving.
        consensus.nSubsidyHalvingInterval = 250000;
        consensus.nInitialSubsidy = 100000; // 47B launch reward (stagenet mirrors mainnet)
        consensus.nMajorityEnforceBlockUpgrade = 1500;
        consensus.nMajorityRejectBlockOutdated = 1900;
        consensus.nMajorityWindow = 2000;
        consensus.BIP34Height = 100; // Must be > 16 to avoid OP_N vs push-byte encoding mismatch in coinbase
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 4 * 60 * 60; // 4 hours
        consensus.nPowTargetSpacing = 60;           // 1 minute
        consensus.fDigishieldDifficultyCalculation = true;
        consensus.fPowAllowMinDifficultyBlocks = false;  // SOQ-INFRA-005: MUST be false to emulate mainnet
        consensus.fPowAllowDigishieldMinDifficultyBlocks = false;  // SOQ-INFRA-005: real Digishield retarget
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512;
        consensus.nMinerConfirmationWindow = 2016;
        consensus.fSimplifiedRewards = true;
        consensus.nCoinbaseMaturity = 30;
        consensus.nMaxReorgDepth = 288; // Finality horizon (Analysis [A]); mainnet rehearsal — match CMainParams.

        // Dilithium only from genesis
        consensus.dilithiumOnlyHeight = 0;

        // LatticeFold+ ALWAYS_ACTIVE from genesis (matches mainnet April 2026 decision)
        consensus.nLatticeFoldActivationHeight = 0;

        // BIP9 deployments - all active from genesis (Dilithium)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;


        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // LatticeFold deployment - height based, not BIP9
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].bit = 28;
        // SOQ-P002: LatticeFold+ is RETIRED on every network, not just mainnet.
        // It was ALWAYS_ACTIVE here while mainnet had already withdrawn it, so this
        // network validated under a rule mainnet refuses — and the rule in question
        // is a verifier that accepts an all-zero witness (see the CMainParams block
        // for the full reasoning). Withdrawing SoquObscura from the test networks was
        // done for exactly this reason in bead 2pru; LatticeFold+ has the same defect
        // and was missed. A rehearsal network running a verifier known to accept
        // forged proofs is not rehearsing anything.
        //
        // Verified safe against the LIVE stagenet chain before making this change:
        // across all 48,733 blocks there is not one witness-v3 output, and the only
        // two v6 covenant spends carry the witnessScript
        // <32> OP_NOP7 <32> OP_NOP7 OP_1, so OP_CHECKFOLDPROOF has never executed.
        // Clearing the flag therefore cannot alter the validity of any historical
        // block. (Note the direction matters: for a v3 PROGRAM clearing the flag is a
        // relaxation, but for OP_CHECKFOLDPROOF inside a script it is a tightening —
        // SCRIPT_ERR_BAD_OPCODE — which is why the covenant witnessScripts had to be
        // read rather than assumed.)
        //
        // nStartTime=0 / nTimeout=0 => THRESHOLD_FAILED, terminal. This deployment is
        // queried through VersionBitsState, NOT DeploymentActiveAtHeight, so an
        // nActivationHeight would be ignored here — do not add one thinking it locks
        // anything down. Superseded by SoquObscura; witness v3 is retired and must not
        // be reallocated. See test/witness_version_allocation_tests.cpp.
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nStartTime = 0;  // retired
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nTimeout = 0;    // never activates

        // SoquObscura confidential outputs — WITHDRAWN 2026-08-17 (S1/P2).
        // The shipped range verifier accepts an all-zero witness carrying a correct
        // Fiat-Shamir seed (proven by execution; regression battery in
        // test/soquobscura_degenerate_witness_tests.cpp), so a confidential output
        // establishes nothing about its amount. Stagenet had it active from height 0.
        // A COMPLETE scan of the live stagenet chain -- all 44,891 blocks (0..44,890),
        // zero coverage gaps, zero read errors -- found 558 premature-witness outputs:
        // 318 v7, 234 v5, 6 v6. Those are the positive control, proving the filter
        // finds real witness outputs. It found ZERO v4 and ZERO v10, so this
        // withdrawal strands nothing spendable.
        // See DL-SOQUOBSCURA-STATE-MACHINE.md P2.
        consensus.vDeployments[Consensus::DEPLOYMENT_SOQUOBSCURA].bit = 5;
        consensus.vDeployments[Consensus::DEPLOYMENT_SOQUOBSCURA].nStartTime = 0;  // Not started
        consensus.vDeployments[Consensus::DEPLOYMENT_SOQUOBSCURA].nTimeout = 0;    // Never activates

        // SOQ-AUD2-002: USDSOQ Stablecoin — ALWAYS_ACTIVE on stagenet
        // Enables mint/burn/freeze testing. Mainnet remains NOT_ACTIVE pending audit.
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // SOQ-COV-012 [DOC]: Covenant opcode activation — STAGENET / REGTEST
        // ================================================================
        // CTV (BIP 119), APO (BIP 118), and CSFS (BIP 348) are ALWAYS_ACTIVE
        // on stagenet and regtest from genesis. This is intentional:
        //
        //   - Enables full integration testing of covenant scripts, vaults,
        //     eltoo payment channels, and oracle contracts before mainnet
        //   - Allows the covenant_tests.cpp test suite to run against live
        //     regtest nodes without miner activation signaling
        //   - Stagenet mirrors mainnet economics but activates all features
        //     from genesis so developers can test the full feature set
        //
        // The ALWAYS_ACTIVE status does NOT indicate these features are
        // production-ready for mainnet. Mainnet activation is gated on
        // Halborn Phase 2 audit sign-off. See chainparams.cpp mainnet section
        // and DL-COVENANT-POST-AUDIT-HARDENING.md, SOQ-COV-012.
        //
        // Security implication: Since stagenet is a test network, the risk of
        // pre-audit covenant bugs being exploited for real funds is zero.
        // Stagenet SOQ has no monetary value.
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].bit = 7;
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;  // STAGENET ONLY — see note above
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_APO].bit = 8;
        consensus.vDeployments[Consensus::DEPLOYMENT_APO].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;  // STAGENET ONLY — see note above
        consensus.vDeployments[Consensus::DEPLOYMENT_APO].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;  // STAGENET ONLY — see note above
        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // SOQ-AUD2-009: P2WSH-Dilithium (witness v6) — ALWAYS_ACTIVE on stagenet
        // Enables covenant script execution for live testing. See DL-P2WSH-DILITHIUM.md.
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;  // STAGENET ONLY
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // SOQ-ARCH-003: UTXO Cost — ALWAYS_ACTIVE on stagenet for integration testing
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].bit = 11;
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;  // STAGENET ONLY
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // OP_CHECKDILITHIUMKEYHASH — ALWAYS_ACTIVE on stagenet for eLTOO testing
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].bit = 12;
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;  // STAGENET ONLY
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // DL-V6-CONTROLFLOW-RESTORE — ALWAYS_ACTIVE on stagenet for the eLTOO/HTLC e2e (ratchet, settlement, HTLC)
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].bit = 13;
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;  // STAGENET ONLY
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // DL-BTCSOQ-CONSENSUS-NATIVE: BTCSOQ — ALWAYS_ACTIVE on stagenet (consensus-native asset integration)
        consensus.vDeployments[Consensus::DEPLOYMENT_BTCSOQ].bit = 14;
        consensus.vDeployments[Consensus::DEPLOYMENT_BTCSOQ].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;  // STAGENET ONLY
        consensus.vDeployments[Consensus::DEPLOYMENT_BTCSOQ].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_BTCSOQ].nActivationHeight = 0;

        // p96 / Option D: height-gated activation, height 0 = active from genesis
        // (equivalent to the ALWAYS_ACTIVE test behavior above — the live stagenet's
        // historical blocks validate identically). See CMainParams.
        //
        // ⛔ SOQUOBSCURA IS WITHDRAWN, AND THIS LINE IS THE ONE THAT MATTERS.
        // DeploymentActiveAtHeight() (consensus/params.h:206-210) reads ONLY
        // nActivationHeight; when it is set, nStartTime/nTimeout are NOT consulted.
        // Setting nStartTime=0/nTimeout=0 above and leaving this at 0 would be a NO-OP
        // — the deployment would stay active from genesis. NOT_SCHEDULED is what
        // actually withdraws it, and it must match CMainParams.
        // ⚠️ Do NOT "simplify" this to NO_HEIGHT_ACTIVATION: that sentinel falls back
        // to the BIP9 state machine, which would re-activate the feature.
        consensus.vDeployments[Consensus::DEPLOYMENT_SOQUOBSCURA].nActivationHeight        = Consensus::BIP9Deployment::NOT_SCHEDULED;
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nActivationHeight           = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].nActivationHeight              = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_APO].nActivationHeight              = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].nActivationHeight             = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].nActivationHeight  = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].nActivationHeight        = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].nActivationHeight = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].nActivationHeight   = 0;

        // USDSOQ Authority Keys - 2-of-3 ML-DSA-44 multisig (FIPS 204)
        // Keys control USDSOQ mint/burn/freeze. Generated 2026-05-27T04:46:27Z
        // Private key material stored in ADDRESS_REGISTRY.md and soq-signer authority keystore.
        consensus.usdsoqAuthorityKeys = {
            "3f13d3d3fc8cec4b821524576607a873028be87b354b4ceb876322ef06ff0f66c8d475f32689ba66dc665ebb53393a795933c122c06d3a639a1e82579561c5628b7bac1a7eed9723741b540a158e3aa561719aa85e6f1f27e738c7e288bbbdf5eae599d5c2cb008f3de2bcba1db7723b3e980229db5c06fcec74379172970fe0d08469ffa11027455b675f3c4faea59155fb8d809bef6c8bb4544a599c08324fd857056ac4dddc6b0f3f8fed9819f82895ba79693fdfe781b9a4678eaf51b55503fe0c9286efc3d7fb47505321bcbc197d98b7a1f8754b4b23813823c4bc181b721c9803012548a2f0ee20294217715873cc48a3bf72707d09d3509dd95561dc97c212d0ea1b8df0998420e2043e19db070db6780647d4eba9c1675fa1ad69bb75d223ed22937a11e22582f8bb8f2b10acdb986dcbf8100c704c7f9960560c01051c7f9614d557af356ded0fe9f0ff73c16708c527744860291a607a235bba0077685dfe758472c1801e0ef004eaca656bc85a7cbb0a1e260f6403e3f5b38479d9fb276ba8b5b333e85955171fa4f817da8ec66bd0d1ceeb4fca019ee54962c84bda7d114f8c7c106f8abb67877c79bd6c97d69f2dea69688170812512c349eb09eb9d0a7d60eaf0215b10f53d22cdd0f872b1dc3a5d675338f4b980bae5eebc13af372ab1b2ff8ebd1b865440acac92e30fcc98734a1678296c57d8af001dc053203dcd167e8847f1076b78a807e19abafe1a8724b3ddd81ad772af6a5704a61a1a3be1a2c7023d2b17f27b4db68200df67aa2141f229315bd82d16440dc03deb0e3f0d96b7fe5f25c5fc409fb2259d693d1829199cce3a860994bd5535afcaa91cd7f0000a71ff005498e80858e21404676312bf55cb7eae15a142aac354028810b248a3be2432ab1acc41fda00ff105897f0225f40772661040399f3e8288c07e89968fa5ee60d098ffaf9528f2950915ca0f10b6f774385125d8c3ab320d15dbb62313669129a69b6369d52201fb499f1a1fa63b9e76b51030f8516dd4cad69c9c4ea5efd6bea1148aa7773d1e183a0ade2bfd707a2e436b73874d8a60fd2548e358511cb10747c4a02ac469a2add5d835d8631a76e500f080d29e561eed50a3d32bd7032698363e991218e74037544f65726fcad1597813c2fdedcaf047f211526c3915f18fff72ca950889415d414a1230a7448a97e21d4eb42fca35c54dd24397bf8b16c1712697770f3035b40577ca77c1f65973f29a087e272164c94d73a3547496fe4c890e2a4a7517e45fe885b7b0d2c26077cca73fd91c97ee115053b6ce300a441a963334786b63b3018a7b1a5b0d1728b00e7986c09708161559875204dbd729dadc0168e4d90bc937f9b1a0d27bee04945cb428c958e7f8236a9de7aa726133865542e1aba77ddfbc459c7c5a5aeeabcf5ae93bcc81432929aa17bafa6c106957a9f3fce333b1d04f423e90a4da84b0e85fc139597be4f3002b41cd8fec2b67f711973d6f218d01bddb65bf52b067ede05c302fa2e1f7a9a8eeb94c3125dc0ec1d0bd39a5c7797886b3826631c839b600be2df50bcc8322ca960faa84012a71dd562a7f695e4f31027252b2c5db2ee6c36815c2092ec7d6fb7cd381b56c47a1766875a33900c37f2ba46929a9fad1b7f0dc77126c80bcde0ac9ca6fc51fbff775ae908c4460e543b15686fe092e6aa01914d9ece7520c0f4f3a44591ded5c9bb313b089cbfc9724eadb6a659a7c9ea971c2243cac6827117f5cec2ed4a9ba80fdf1e4c6ff6dac643e01fec65feb5b0642df2fc6a8eae1fe1ad4b75c17ddc0060b933c2a52299fcd6c2eec5470d31a0fb768179d3b4bd617d3",
            "88ab756b23c4b4ee00d664ce402f1bc64ac2dc5ce08f63673806729af5352fd51678529a3119d2d7c6eb1ed531cd5a977a7d7956c62ae35dd929f3c314ce31833a1a31001cd5ebd35d9f4a90ce7458d5599f1f4889202bef98fe00f33b54cbf990a146bdfb48c5f3d2ca66af7db3d12eb66c008b9443ca655a651b23776ac156a46450f0664a2315abad65e5d78f57722003953085c65ddadb176c9f15f5baa25c863717c1e3c2692e285a0daf4a1da7b32ef88aef4ad625e8332dec5dc3eb4f62f61f1ba893937e3a25125848caa4d97e33cb9ae7b9ad3c54b019d4e5aa8259da3cbbb654e79c72868c3e9f53ac2cf433092d719ceb9f55f95a3a19199af32968034ede41158d1b3c6263bbf6ebbfee3322b5582f3635fc3a92e89d33c48033c7f0af0fb4a2fb0bc3a0d1246dbf817103da01e1604ad74a7e2b49a02d8b882d24056a5873b74ec1a3d5936e835af29c64d2ddabd2d7af7ce9f74992e5ee17e1362e92df5517ce91467ee4da76e8b9a359e9f464d8276b2fdc8d99c4e3c669c97a6821de2c00990313430296622546dd8568f3c1345e5ba8fbf4c993786625712feec5d57d07ed09095addfb4dbdd7e4d57809d3b8915ce340300f22d5bf4e8961a2d8ff6c27cc0e8a3ab70603c65e040bcf3984add59a849e0c289df494341cc4d7ae4ccb7eb47c0dd3c5c17c16aa9df02cfce0dac541f807654e23efd3eb3a9f54355df0b0230f2460704b96c19936df83dc4e38dbbad86dadef9fd47737610a3be55b452e53762e3c082f313612f1f4750100a1695d7576e48e85a7fae514b9e470b05418330e930839027ccecd7ed4e03923aaf9ed33aa7811c90e3a42ba3c52b8ef810e1708684270d8923103f79560fba1bb0d61fc7bc9bb8ae3f84a4830d7e4ddac270a95a1891ec1bf0a3691ae5785e06c80298c3a4793ec42f5f102ada4ee29c883cf385cb44d052852a3f72253789ba3d28495ecce5ad907f58196321a497c29456c12957860b4c0639afce7b542af42611046a387199296a5ce9b29bde05f948dc44c0c25cba13d6598b7c23de7f617e2e9f6a71e2d99adf6c5aca4f679d3a18c861b5b7a51e0853491d2aa6ff3dc0dbd18f8ca81d48f33a611482216f8853653935ee8a25bcca5902a1d48538fad33c7b31988b8f4cf6fc4e4976136fd227e5e54e9794e9915599a1073957e5d7fabf4f42e752047ab4328b9b7c67ba21fd1dcb5226ca088547535835c126d7fceec8b3ada0fa25713d0abd0f34f9ffdc201de542a304c13087eb4f5424149389733a446b65b306ad65b686c367bfa60b698c0a425399370224e401f8beac293c1760e4d1a0af18951ca14ed0c1f1340fe803c87e6b263fb2f4f11a73cf565c8880d3718a2416c3b176c6bb18365a896cf3c684859a52db5800506dd7897f5a7867bdb6a3a81b8f90855c4963ff9cd72b0d2712586a39d019cb1024e32d9caa7581927d49e339b805b4d2cc3610a987a50f989c281b391008f520149e4710f2fb1faa34ec3e86961649b4d2b784bf1d6dd4a976d2382ddf8d066534404bfc463f49ca3d6709f7923119736e1712eef1c2571ef5ca1618aa30f72a3ab3de879e26414c6080d42331c8e0cf6e65db45ed04e58a125d74baea33b90be4b8e45b24d5593cd17cdf94e0070a613c9e54e0975b4318e604d2c7a33abc7d4750f501e8ba1b45028544fa028596072767327e515173ae3e0899d3605effbfff6663bfa7d83b0d8532dc4580ee68388e9335bce1fa91158c919f42d73ab8cd48d85a78785200ea6f7d811ead446c1271a755ca85adaea1a5ee35deb4780e671fc46e5c0709ca895041b95dde511b71cbcec",
            "0e6734d74cb357881de3eafdeb0055bb88dd1de103a08f2bc4af58bdb0f4444a9102e6b5fcbb2ca26d8e8b59f9fef2ac6df6a3419433fe2b581fb95df5b10b2c3c6ba0c7fd6325014a6e5bcc229f632d004ea0ae5296f63331c9a65c7721800a8045bedfa774a6e1c9512927ae093f7c005001a381c12479c709b954ad5c2eb099d10c18e41f2aa42ef15e004bf5a1cefc4e658c506c588d2c3edabade9259d7db1e774505ab011202f637e237395e2a904271a42a8c9b3f39fedcaf6abb6c040c24142cdb4c6dd07eb5f35cb6880d2df0a6bd0a288544ecc7e7f3a87556c4f0019876e3b96faca222ba78e0ec7c02c5ad27481ce8d9e0e29975bd022fd68ad24a40636f168880249d0b0952e173a0920b5a52717b29b19b9d9cc1a9910857de49b92d995b7e035fab7fad7f23c8c391577d3ec2dfe9bb36600d607fae6fd7a5eb72c41cf0bb116de1f643199018233427cbabbd539290bf869c53d77c78ecf43b0ee5baa9127efc26cc765d2501645d16655afe7e0808982a896d80d05bea06aaecbafa804a57b667fec53527564857e5637c349a9c87de1fe684a6900f656a0734619e6bec0a5721cd9f4cc4bcee986445c20da3e96ce11039d8ac6f17e4d346a787e4487bae0719912da2d720919956532639b5526ef957b6bd9c9e6ae8e448966102e97a67e7a833e397b1ad3730f1447f292496cd0ab81269aadf5b464c4a5f569235b9aa612e39d1f7e01f4404aec0f5e96f16f33c13eeefbd66672768846e791ac4333a88055e4110d4e1d3760e2c45b6460b955ad30d23e4b82d7f2743d33b4440b3fba289fc13d10a19c4c7630cca75abc1e344958f5a06bf169dc7797958240f311a298d839b9d1f42b0b99ba3296206e596afd669fd7cb078641df98a0e2a20b41c96716bdf522a15211d0b85e43aba90a05166787e855b3aa776f17644b71a7cb5526db80ac6c2e6a4ca0f1da8ab13dc6ed4daf3394a73bfb7a2ec648b4037b1036bd8734a0134a42f3bd76442fa14405477516272a7b2630f0e95afc99d568bc3cf640369b09acb456b06abaaa2d2553bbd5df700ef848d38777dcbf9b7b0ab781bf67c3bece1794cbd516f15165907f829910772c2a8effd31541a8995d66fa71289acfb1d24e9bd29ea4a457c9fac7e8583d5eb6d605667b95a3c868acabdd2ca9cbe1d6f91378737b8d36ef99ff5dbd7162e702315fdf1e42faa3c3e9bcb04a83adeb30628e85d2a0f021e57a21f53142bfe128c8beeb23a0d4e17fbdb7858e3de396eadf69be230cc4dfbc1a7931182657627cd48bb0496bd66bad5f1ce2b02462ea48073d53717f274a19d625919bf613582a2e4dab5ae5d12142264f267308c68ecb20243643af3876ef56fb583810a4b31ecf207c5099475afced5a7f81903965d1e29f5dbc1ec7445ae5bce53f052e4bb64649fe24958f742d13c62e83d6333b53224fdf270007aea6a37b708a5b27a6e115dd3c73266e7cebfbadfd6b4d88f0bea727c9a942021c6e515825fab5433f1a7c1a1b19d1b59dff1d596869956e20f2ccaa91f6dbf771d6a3692ded1404fae9e4738bd482372c3165c3096cb15795edb8d9d26cd97c65f7dcf14bfef4057aa2b2abc5dddfc676b799d10509d7df54577b20289c52da7bfc0f2952d517f7ba9503de5931b9a98d7f867ad841e128aaa3446b6a1c8a70a94a171556320ab0d7396ff8eb631610fc19d3e937bd86949ee2ccfda40c434a11a0e3ebd84ae4fadf0f0f9e2e52faa019c9da87b18d262fe47aba0198e63ba2cb336381b81dbe7a3d7310e14b92ea1c432b1625a69d89e40aff6863b367351d78af9dd02472528817a80b235f895"
        };
        consensus.usdsoqAuthorityThreshold = 2;  // 2-of-3 multisig

        // DL-BTCSOQ-CONSENSUS-NATIVE: BTCSOQ Authority Keys — 2-of-3 ML-DSA-44
        // multisig (FIPS 204). Control BTCSOQ mint/burn/freeze. Generated
        // 2026-07-20 for stagenet. Secret key material lives in the offline
        // registry + signer keystore, NEVER committed.
        consensus.btcsoqAuthorityKeys = {
            "e36d956c7f180fe68d49a0d0cb75fa499f70239092b79672b7319e4810183180e51837ace1708732682aae6d5e8154e4a60268fb926b23a8ffaf132b31590ada560f38071d810da09f91d9bcf53c5ec4be373514a56e46e3d4f4d52bd63e8392e7bb9cbe43b37bc3602fe02800a44111b3ea6dcfefcaa7f1e754052da56615bbe2df62d6b63059dc433af845895fdd8ed507da784eee5a745c3390f7d7ed758094c971c4d026b250cc4a84c41bd78df7748d727255fc68c6a98e07993a5083d2550576a1b975177c1c38c11e5c0143a28cdf4c62201f4df198af709e7e53faf3e024fe5591dcd34bc0b7fc09e5a12c015a20c3593b7a95505e2a0c59498d211c06c5d3711a46207f19aa205ad9fbc7af3bdc19d8e730de7321610c7e5aa7b666cc5d6c1e3c4ae107d4fe3041150e33eef1372cb6536097d649430b4bf70df3d9ea6f37eb21fc135e333fa1b96efdfad405e55149c17787375d7b9f6a212c23b7ac136e7a4b8e2e8866e0f32f46a6f00755a9628024457e717dce35574eea73e26ca51d70520f8e0c117eaf18a0aef367433982a596dc17df4f35d2560dad97caa0e95ad39931f7aad46789467a0878d3d9aa06dfa098107fe23dca1c90f8b46ad08536fc134aee937c2c32f5557f0072886197efe6d81f364b4a920b8d9328df96ecb6a85d6c578ca53ddd5b31d4832ee5ce0139120e06e00672883c493d3db4f28d53a816f6194e479427c0432389835357f30817d78d9862d1e74c433faad53ce42df19478f3e14d71e2088a4ad889768981d416988adb1d669cc8ffedafac9dc14b162c0592d0556162b0652512d983bba8ed0fe7cc360c3987522048f0f3f6a63d40e35e3ffb0441f3c50ad2a75a2c0322a26009ec75490d0d870ea802f355dadda6a4b49f7bf6a08389ab6734a4b1dce70a7671ae0a26d7c1b042294f11ae89d454042e381c2e0834d11edd8400061691d52cdbac9bc836b82fcaf15237e191304ad8cea824ec6bc063bab55c19f92160bd8427a4df162b350ceb14dcc16bac1bb3a8a43754700225c5d66c052b3b5b0c7f3396b22f4f27604dafa83c331a997ac98ee4cfb7eafc0a504fc8d340e2e1f9fd4c2f617704ceab7ae3e0cdc355c6d15f125685abe2a7d16e6eb5fa1f5603d93d528b5ba1fee811511d2086abf0d273e7818b7e92394e4213a682fe44c650efb84d72f856b0402e0f0a1e094f104a024f396ed1433a96c57291c555220e36005d1841f8e61bd47bed36586f825bba4297dffc6bfa81ac5304af81283b2f00e276cfdb041b76af7e37e0bd0e2dea40d0597de37d61a9dd25a6c54726311cf1f37d056a6510ca41e713afd6c484fd9e30a20802c50a7b0251ea2b33448e7e30eaf46d2b6523d8ee2cfc611463c00f8457adc7079cf3caee52067d2ee74cce0cc6b8176de8237cc235520566ce466d416cc6a7e53c5d2a9821032564768994a877c1c975ae3fef073d9944aeaf166664627043a65043ce5da62e0de66aa7da8f5ac1b5ad01bd9ddfc2a7c6e7db4900c0fb251c19d3c037b3d6c26868fd5ef0c3e096e9b167d1e9ea733eb4e86abac876072a81ed8eb372fee84703b5bac4857d9ea85eb655bdd531608de82ef39a8433c82f020e739b1a9c5596429a79c38b2ab3d782a6d42fb649ec3f8a650631cccc9240c4c816b04b18851840588445c4d0aa222de20adcebe58101a74bd8843122b577ef6c25bb04d68235937c1045077825cfa85938f5f4a5cfa8ab97ec0cf09457fda79b89077503a1f1c221b6245f39308e9e559d3156c9c69456758b627c45dd3d79c1f602c84c145120bd271023dc850218880fe62c7da43a6865d5c2",
            "202aba46d6b4b5049b56fc9b90ab185fa39be262f87d5370f1e5cec54a97987cf184871d976ddb178c13a08c7faa732db54de75d75653fa4c1e584fd1f0be719d236347f696c9a684944b46dc7a1a78f2aef71342ff87ca08388eac665d67ab3a091824d3cfe68d26ceea470817aa63075a60f6373635ae474d639c380f8c7ed9f13fe79f4b314995c3675dab0de377788ae699b3bbb34dcab8db415d1594338b1a126f60e32c5166b06d69e8a994cf7a75f2c4d5a58fdb815fb102e72d12fd5837f54d1a3e86b9c28d6192e0bf667275d54c2d64d80a8902c7c1df7b99902b043edae6b7c2c4ad258c7bce39f15ca140b908b0055efdb8cb604aa25163ce187c32b811c4b017397896aee06b9bcc00bf31deca068a6b066d43b5e85019fe24c1a166024d8bb286ef885d01f88e944e4e737f9b6b7173486ee2713f4388da570f112119b7b2e119a60f0ec77621582be6e6f2c03343c95def1db6617ba12f866286b29719614b5ffa54641b2fd730828ca5be8e0607c914feb31338db396eb3eeb364c8f5f624fa27b747f750afb34b90eba5f31c5eea5252640277f2115842db71665b9def71648c714b147046a8b29128edffab4d718436612d6d8537b3401b33b314070e4c9988f9c81d85858bd47a7d311446235361fcabffdaabf1fc0c24db45b621c1c68379806c676f5adc0f30e1f3aa555738e72c1b5de76e5a3d0fe7d648696fbf4b45e1f4cf3cde41e0db33df8836c726a51ec8fc02c6db33bffc839db667a8d9c74ec247f653297cfa88508693bce06a792a322501bb74f1be9ea25e6b7728c06a881ea8a28e22299ae457e166cf80aba1338ea2147bfd38073d243e93140bb2842fdf8f595432d3a70732113e6a4504617dcb1a3c356b07b1caac3cff2f41c8376dedfe3513e876abf0ec55a5e82915119942e86a6ae4f15a88446459280d38df3eaad0dbb6865988fe00bdfd2e52d6e5a3fe8192f3616329b53f4ceb8c2d8b7970d7ec24a8b80b78fa891b5ac2a500a15d482742476e3d75b442d04494836f549b5a919070ac29bbcbf81c4a8f23febfcaa9202db50316499a93e04601d10e06be3915ff7929a5aa0ca3f5e6fec09db85adb3ea4f57b49f376e18f2ede046c5cafafc6be4fbe6335ded6a6d8812f8b33b773324830a9e116ebdfa6d77244d28bce89e1cea0adb0f7e36e5a898d169ba0f6108da9e9e5a6bdebc44f1fe1718649e461d495b3194339637dca5548e302eb52dc1fb7bcf0b704ef85734a40efa77766fe1be7ec29e6e64dbe3ecca5632d91e3d690d46caf404565d56e88c63111fbd195c8579b1080bae636a75ea496b80c7721d39f55ca95984f9aa19d90ccbb75094b908a568c41b55c9cc85e8dfa68fd11b26dd9024730d4ee1d3c7eb9a5dbeb6a728c4bfc558876446b7b30369e3fc98e8707abb4605d6bf4894103047f640f18c6849dfb0b92753a925455edf77fe94cfc353297c11dce62a059a216e3177338bbf8d485da1341d2aa0a76fd5a1126f96d09c7142cb1bf95686664e96b62eec2c519b56d3f80d1cc787e9431c393a215a4071fe311baac7f29c5c5a20d4aa9aed949b6ca011b4bceb625dc6ec1a8051b7bb536de23fe0e37ca7b9f6eda766273da8ce5680cdf4f321cd807c63d1d47fb98cfe9e56131baee02b230c5ce183d56d84768a19980c7595e7724cbe84dcb9d66879ca3f7617202d933b116b7967df46dfb6dd2398ea8db36b9f67378bc0c750bb479a29fd1fdc891eb4bdc621c6b868a11829c09569bc675808de289fae716262a384af5f89b81b4d8c3bc7f66c15154250822b7a43ab7dec23bf7166706f54bdc4c312e8ab2621",
            "89cf406c43df765d67a16cfcfe287c0ad096aa904fe7dd86db807c921950f1dd812c3773a16b056fadfa85d5ae220a6213d8c0a1a199c1f8f7564bc4738b7d7e12daf93d5462493c5d7761e80f27ebed24102b8664657324eed3a3c89be1cf094671639a59e59d9ff92385b19c6a080661dc271862e6b3cf347fa59f99e4e3a85aa3e795258c32b3a14375c3152b46118baed22680d4fc122b9b03bb06a49f28a7767a172e2c7a6558316afc56703c3b63e0f5e163b0b5bd2381b22a1e5493e4790aa5bf944c3a6e6b8eac29639ae8b0caf4e5492b65180d96b9482a31ee5c35ff19292207c9271fce320e80e963d4ed432be87358f090aa91f909b95a37da63ad1f85f53601eed3a64d68cbdc9cb35098cd9b2d340e406d9d778f33d5e213961ccee1a0a8fa80890e5fc0a27d13987ab6dbd2def1637458e3f46b51a66cbff59c9323cccb1fcb8b45643bc9aeb49196928eff9e7062143e08701bc7f9e9a9140b3e2a2ab1c0f6280ab6804f1bddf98425fc97223acb7c63a06bf55dd5aa63825e69eef7897456295f415c8beb003df9638220e7517dbe45016cca5f78d76688ecb8f071e4038d7c01d36a6ee2ca3e7b33a0caa1cc1211d960f456d36b05c5cb6ab2235c3cfb5375a43afe36d5dbbad1cd3755cb88b0b9cfeeb84707217565498b4f14528ead6c17b38e21834616d3473a68df0c7bba23ac5e44526314b5a9ddf05d7ac03e87405fa0e02e43ba2c99fbd9f8a23785fb300661e47fb2f78e754583aec0f8dfff446913bcb8da2d15f6a2ffbc293857d8717b666d0537c8c521b6657e2e6d86e5828cba3db367b5422a0b55e283eb4f08181cbc322530a76ea4164ba7661cc62a6b7e946c30b1caa8b2bf95d3bc95ed18730f186da2b22ea2588a347ad0cde1c57d15253141544b540a7c92598d204188c68ae8e33e6da706c9ce6621d647ac7a037ec8d14f214b0f10bde6781b8de06bea92eb1762e5ec7cd8c96699e7137f0bb859a4af79c426f07e662a1d03b8c6ab2d6a6398cbae6865888d97201668c54d066b9cbe90d1e6a4daa2cd2099fee2641453b5c0a5ffdcc871d17a284c2d174127b7cd6fd8dd95c0f45660f53d7d91805d5b763fcad5911e9ce766ffcf7c4bbab098f61b5a72ef69459b25f7103d5f1a1750dd80078951b481ac90c65a53559168d99343243ebd1dbde4db2acfb535d5856750f2b9d3bb924db6c916c67bce9ac130c6ac97cf701c33aa6bf010bec6b39633e1e8c28a77900cf50a02eb7d4bf1e07fb11ad11f735a78f0bc4829ad0fa6fa73ce28971ecc40fa0b1a157ce822f8426d16285b3dc6b41957420509e291a5ca8b8cf99536850a7236f9fde5aba6a734df64d4c4c4be6b540bc5c2bc6cba62cdf960e4610f2958c975b9f8591761515f811c9a0b2a6b31a1a1bd56292f2cae1475da891037526369fbdfacb03a26be48d154b7770e2d09a24f0d98efcffe5daecf5ef8a53d0b4332a6f9200ab8e1801f650b656bf017081b21bea2cdd1bddb04b1d3948b5f0e5aeb0f421ad259edc3bf966348518a061ed4d3d4798a8cdc2b50ea4816a56b09f1195be8546349c752a41d86f25fa6e487ec52c642fba7f45ace6ebbef96937c42b254c2ecb43445b4e2d689a5b45db95c492fd0939af946a008d8bc6dcb958688da320f2256a36db9d879de5774374925aeeaee57c767dc3dbb479f1ddee063736d8a569d29e8ea5cafb03334fd4a7a3f12aff9819f1744ddbf02a05b295110fd34a0914ee108401b02735cfb4d22a95eab7401150dcba15da619b39432cfb21f23b8e3bc668981d3b5bded11dbf6431a9c1050c4da4780fe64db266ad1f3cb9f5cc8"
        };
        consensus.btcsoqAuthorityThreshold = 2;  // 2-of-3 multisig
        // BTCSOQ has no legacy chain: enforce M-of-N + freeze from genesis
        // (no pre-authority exemption window, unlike the USDSOQ 7700 boundary).
        // Safe because no historical stagenet block carries a v8/v9 output
        // (verified by the pre-deploy OP_8/OP_9 sweep).
        consensus.nBTCSOQAuthorityEnforcementHeight = 0;

        // SOQ-I005-STAGENET: Authority signature enforcement height.
        // RECALIBRATED 2026-07-04 (Casey-ratified) for the reset stagenet chain:
        // the old 37201 was calibrated for the pre-reset chain's CLI test mints
        // and, on the reset chain, ALSO silently no-opped freeze/unfreeze
        // registry application in ConnectBlock until ~block 37201.
        // Blocks 0–7699 hold the signer-built drill txs (mint 6501, send 7077,
        // burn 7595) and stay exempt, so historical validation is unchanged.
        // From 7700 onward: full M-of-N authority signature verification AND
        // freeze-registry application are enforced (mainnet-shape behavior).
        // See SECURITY_ISSUE_REGISTRY.md SOQ-I005-STAGENET.
        consensus.nUSDSOQAuthorityEnforcementHeight = 7700;

        // SOQ-I008: was a hardcoded `static const int = 54300` inside
        // ConnectBlock, so it applied to mainnet too. It is a STAGENET
        // calibration (BUG-16: the pre-54300 chain has authority txs that do
        // not spend the tracked outpoint). Keep the value here so stagenet
        // history still validates; every other network defaults to 0.
        consensus.nUSDSOQAuthorityInputEnforcementHeight = 54300;

        // SOQ-I007-STAGENET: UTXO cost minimum enforcement height.
        // Blocks 0–37200 may contain outputs below UTXO_COST_PER_BYTE minimum
        // (mined before DEPLOYMENT_UTXO_COST code existed on stagenet fleet).
        // See SECURITY_ISSUE_REGISTRY.md SOQ-I007-STAGENET.
        consensus.nUtxoCostEnforcementHeight = 37201;
        consensus.nMinimumChainWork = uint256S("0x00");
        consensus.defaultAssumeValid = uint256S("0x00");

        // AuxPoW parameters - same as mainnet
        consensus.nAuxpowChainId = 0x5351; // "SQ" = Soqucoin
        // lw7: DELIBERATELY still false on stagenet. The LIVE stagenet's historical
        // AuxPoW blocks were mined as version 0x00000104 — AuxPoW flag set but chain
        // id 0x0 (the pre-lw7 miner didn't stamp it). Flipping strict here would make
        // every one of those blocks invalid (IsAuxpow && GetChainId 0 != 0x5351) and
        // reject the entire live chain. Flip this to true ONLY at the next coordinated
        // stagenet RESET, once a fresh chain is mined with the chain-id-stamping miner
        // AND the pool's merged-mining commitment is verified to use chain id 0x5351.
        consensus.fStrictChainId = false;
        consensus.nHeightEffective = 0;
        consensus.fAllowLegacyBlocks = true;
        consensus.nAuxpowStartHeight = 100;  // Stagenet Vanguard Window: solo blocks 0-99, AuxPoW from 100

        // Digishield from block 1
        digishieldConsensus = consensus;
        digishieldConsensus.nHeightEffective = 1;
        digishieldConsensus.fDigishieldDifficultyCalculation = true;
        digishieldConsensus.nPowTargetTimespan = 60;

        // AuxPoW from block 100 — dual mining model
        // Both standalone Scrypt and AuxPoW blocks accepted (matches mainnet)
        auxpowConsensus = digishieldConsensus;
        auxpowConsensus.nHeightEffective = 100;
        auxpowConsensus.fAllowLegacyBlocks = true;

        // Mainnet-maturity mirror from block 100,000 (ruled 2026-08-29, bead
        // maturity-tier-doc-divergence-x48g): coinbases MINED at height >=
        // 100000 mature like mainnet's post-genesis tiers, so the soak
        // exercises launch maturity. Raised 240 -> 288 on 2026-09-07 alongside
        // the mainnet change (bead mainnet-maturity-240-not-30-mp5o); the mirror
        // is only useful while it actually mirrors. Safe to edit in place:
        // stagenet was at height 72,864 when this landed, so the gate at 100,000
        // had not opened and no coinbase has ever matured under this tier.
        //
        // HEIGHT-GATED, not retroactive: maturity is read from the tier at the
        // COINBASE's height (CheckTxInputs), so every historical spend of a
        // pre-gate coinbase stays valid and the stagenet history replay
        // (differential validation) is unaffected.
        //
        // ⚠ OPERATIONAL CONSTRAINT — A FLEET REDEPLOY IS REQUIRED, AND TAG v2.3.0
        // NO LONGER SATISFIES IT. v2.3.0 carries 240 in this tier, so as of this
        // change it is the OLD binary: it ACCEPTS a post-gate coinbase spent at
        // depth 240-287 and a node carrying this change rejects it. Every fleet
        // node must run a binary carrying 288 before stagenet reaches height
        // 100000 (~2026-09-25 at 1440 blocks/day from 72,864 on 09-07).
        //
        // ⚠ THE REACTION WINDOW IS ~288 BLOCKS (~4.8h), NOT THE HEADROOM TO THE
        // GATE. The split is soft-fork shaped — the new rule is a strict subset of
        // the old — so if the 240 binaries hold the hashpower majority it is the
        // UPGRADED nodes that get partitioned. Once the branches are
        // nMaxReorgDepth apart (the check is >=, so refusal begins AT 288) each
        // side refuses the other's NEW headers and they can no longer reconcile by
        // chainwork.
        //
        // THE RECOVERY PROCEDURE IS DELIBERATELY NOT HERE. It lives in the
        // internal fleet deploy runbook, under "Recovery if a node ends up on the
        // wrong side of the split", where operations reviews it and it can be
        // corrected without touching consensus source. Two earlier drafts of that
        // procedure were written in this comment and both were wrong, which is why
        // it moved. Do not restate it here; update the runbook.
        //
        // The consensus facts it rests on are in this tree and are the part worth
        // citing: the horizon runs at header acceptance only (see the mainnet
        // tier); a local reorg is not horizon-gated; witness-pruned blocks cannot
        // be disconnected; and doc/PAT_WITNESS_PRUNING.md §2 and §6 cover those.
        //
        // The consensus digest absorbs nCoinbaseMaturity per tier, so this
        // change re-pins the digest deliberately (see the pin history in
        // consensus_digest_tests.cpp).
        maturityMirrorConsensus = auxpowConsensus;
        maturityMirrorConsensus.nHeightEffective = 100000;
        maturityMirrorConsensus.nCoinbaseMaturity = 288;
        maturityMirrorConsensus.pLeft = NULL;
        maturityMirrorConsensus.pRight = NULL;

        pConsensusRoot = &digishieldConsensus;
        digishieldConsensus.pLeft = &consensus;
        digishieldConsensus.pRight = &auxpowConsensus;
        auxpowConsensus.pRight = &maturityMirrorConsensus;

        // Message start - unique for stagenet
        pchMessageStart[0] = 0x53; // 'S'
        pchMessageStart[1] = 0x54; // 'T'
        pchMessageStart[2] = 0x47; // 'G'
        pchMessageStart[3] = 0x4e; // 'N'
        nDefaultPort = 28333;
        nPruneAfterHeight = 1000;

        // Stagenet Genesis Block - April 2026 (v3 — Phase 4 byte-less CTxOut re-mine)
        // Unique genesis isolates Stagenet from all other networks
        // Timestamp: 1745769600 = 2026-04-27 12:00:00 UTC
        // Reward: 500,000 SOQ (stagenet test value; mainnet initial subsidy is 100,000 SOQ)
        // Nonce re-mined 2026-06-16 after Phase 4 CTxOut byte removal (DL-GENESIS-REMINE.md)
        // Scrypt PoW: 0000023c1d9d18db4abcb57b77efda4968cc3ee0e273870889d7381757c211cc
        genesis = CreateGenesisBlockStagenet(1745769600, 1215028, 0x1e0ffff0, 1, 500000 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();
        digishieldConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        assert(consensus.hashGenesisBlock == uint256S("0x97df3ae79eaf5623c0feecfa1079439f8acdfea06a0f2acb4ef63c6b9ad91bb0"));

        // SOQ-H3: Lattice-BP++ consensus seed
        consensus.latticeBPSeed = ComputeSoquObscuraSeed(
            consensus.hashGenesisBlock,
            "soqucoin-latticebp-params-v1",
            "N=256,Q=8380417,K=4,range=64");
        digishieldConsensus.latticeBPSeed = consensus.latticeBPSeed;
        auxpowConsensus.latticeBPSeed = consensus.latticeBPSeed;
        // Phase 4 byte-less merkle root (unchanged — same coinbase, new serialization)
        assert(genesis.hashMerkleRoot == uint256S("0x994391b757742376b24ebdd37b0fa9ebc11da47366ca8f9ac0a21094da350736"));

        vSeeds.clear();
        // Stagenet DNS seeds — resolved to our VPS IPs
        // IMPORTANT: These DNS records MUST be DNS-only (grey cloud) in Cloudflare,
        // NOT proxied (orange cloud), because P2P port 28333 is not HTTP.
        vSeeds.push_back(CDNSSeedData("soqu.org", "stagenet.soqu.org"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 125); // s prefix
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 100); // g prefix
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 253);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xcf).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_stagenet, pnSeed6_stagenet + ARRAYLEN(pnSeed6_stagenet));

        fMiningRequiresPeers = false;  // Allow solo mining during bootstrap
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;  // SOQ-INFRA-005: Match mainnet — reject non-standard txs
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of(0, consensus.hashGenesisBlock)};

        chainTxData = ChainTxData{
            0,
            0,
            0};
    }
};
static CStageNetParams stageNetParams;

static CChainParams* pCurrentParams = 0;

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

const Consensus::Params* Consensus::Params::GetConsensus(uint32_t nTargetHeight) const
{
    if (nTargetHeight < this->nHeightEffective && this->pLeft != NULL) {
        return this->pLeft->GetConsensus(nTargetHeight);
    } else if (nTargetHeight > this->nHeightEffective && this->pRight != NULL) {
        const Consensus::Params* pCandidate = this->pRight->GetConsensus(nTargetHeight);
        if (pCandidate->nHeightEffective <= nTargetHeight) {
            return pCandidate;
        }
    }

    // No better match below the target height
    return this;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
        return testNetParams;
    else if (chain == CBaseChainParams::STAGENET)
        return stageNetParams;
    else if (chain == CBaseChainParams::REGTEST)
        return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}

void UpdateRegtestActivationHeight(Consensus::DeploymentPos d, int nActivationHeight)
{
    regTestParams.UpdateActivationHeight(d, nActivationHeight);
}

void UpdateRegtestMaxReorgDepth(int nMaxReorgDepth)
{
    regTestParams.UpdateMaxReorgDepth(nMaxReorgDepth);
}

void UpdateRegtestMigrationParams(const uint256& hashOutputs, CAmount nTotal, int nHeight,
                                  const std::vector<CTxOut>& vOutputs)
{
    regTestParams.UpdateMigrationParams(hashOutputs, nTotal, nHeight, vOutputs);
}

void UpdateRegtestPatCommitmentMandatoryHeight(int nHeight)
{
    regTestParams.UpdatePatCommitmentMandatoryHeight(nHeight);
}
