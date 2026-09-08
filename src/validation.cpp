// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2022-2023 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "validation.h"

#include "arith_uint256.h"
#include "chainparams.h"
#include "checkpoints.h"
#include "checkqueue.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/usdsoq.h"
#include "consensus/btcsoq.h"
#include "consensus/privacy.h"
#include "consensus/block_accumulator.h"
#include "consensus/pat_attestation.h"
#include "consensus/validation.h"
#include "fs.h"
#include "hash.h"
#include "init.h"
#include "policy/fees.h"
#include "policy/policy.h"
#include "pow.h"
#include "primitives/block.h"
#include "primitives/pureheader.h"
#include "primitives/transaction.h"
#include "random.h"
#include "script/script.h"
#include "script/sigcache.h"
#include "script/standard.h"
#include "soqucoin-fees.h"
#include "soqucoin.h"
#include "timedata.h"
#include "tinyformat.h"
#include "txdb.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "undo.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "validationinterface.h"
#include "versionbits.h"
#include "warnings.h"

#include <atomic>
#include <sstream>
#include <string>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/bind/bind.hpp>
#include <boost/math/distributions/poisson.hpp>
#include <boost/thread.hpp>

#if defined(NDEBUG)
#error "Soqucoin cannot be compiled without assertions."
#endif

/**
 * Global state
 */

CCriticalSection cs_main;

BlockMap mapBlockIndex;
CChain chainActive;
CBlockIndex* pindexBestHeader = NULL;
CWaitableCriticalSection csBestBlock;
CConditionVariable cvBlockChange;
int nScriptCheckThreads = 0;
std::atomic_bool fImporting(false);
bool fReindex = false;
bool fTxIndex = false;
bool fHavePruned = false;
bool fPruneMode = false;
bool fWitnessPrune = false;
bool fIsBareMultisigStd = DEFAULT_PERMIT_BAREMULTISIG;
bool fRequireStandard = true;
bool fCheckBlockIndex = false;
bool fCheckpointsEnabled = DEFAULT_CHECKPOINTS_ENABLED;
size_t nCoinCacheUsage = 5000 * 300;
uint64_t nPruneTarget = 0;
int64_t nMaxTipAge = DEFAULT_MAX_TIP_AGE;
bool fEnableReplacement = DEFAULT_ENABLE_REPLACEMENT;

uint256 hashAssumeValid;

// mlumin 5/2021: Changing this variable to a fee rate, because that's what it is, not a fee. Confusion bad.
CFeeRate minRelayTxFeeRate = CFeeRate(DEFAULT_MIN_RELAY_TX_FEE);
CAmount maxTxFee = DEFAULT_TRANSACTION_MAXFEE;

CTxMemPool mempool(::minRelayTxFeeRate);

/**
 * Returns true if there are nRequired or more blocks of minVersion or above
 * in the last Consensus::Params::nMajorityWindow blocks, starting at pstart and going backwards.
 */
static bool IsSuperMajority(int minVersion, const CBlockIndex* pstart, unsigned nRequired, const Consensus::Params& consensusParams);
static void CheckBlockIndex(const Consensus::Params& consensusParams);
static int GetWitnessCommitmentIndex(const CBlock& block);

/** Constant stuff for coinbase transactions we create: */
CScript COINBASE_FLAGS;

const std::string strMessageMagic = "Soqucoin Signed Message:\n";

// Internal stuff
namespace
{

struct CBlockIndexWorkComparator {
    bool operator()(CBlockIndex* pa, CBlockIndex* pb) const
    {
        // First sort by most total work, ...
        if (pa->nChainWork > pb->nChainWork) return false;
        if (pa->nChainWork < pb->nChainWork) return true;

        // ... then by earliest time received, ...
        if (pa->nSequenceId < pb->nSequenceId) return false;
        if (pa->nSequenceId > pb->nSequenceId) return true;

        // Use pointer address as tie breaker (should only happen with blocks
        // loaded from disk, as those all have id 0).
        if (pa < pb) return false;
        if (pa > pb) return true;

        // Identical blocks.
        return false;
    }
};

CBlockIndex* pindexBestInvalid;

/**
 * The set of all CBlockIndex entries with BLOCK_VALID_TRANSACTIONS (for itself and all ancestors) and
 * as good as our current tip or better. Entries may be failed, though, and pruning nodes may be
 * missing the data for the block.
 */
std::set<CBlockIndex*, CBlockIndexWorkComparator> setBlockIndexCandidates;
/** All pairs A->B, where A (or one of its ancestors) misses transactions, but B has transactions.
 * Pruned nodes may have entries where B is missing data.
 */
std::multimap<CBlockIndex*, CBlockIndex*> mapBlocksUnlinked;

CCriticalSection cs_LastBlockFile;
std::vector<CBlockFileInfo> vinfoBlockFile;
int nLastBlockFile = 0;
/** Global flag to indicate we should check to see if there are
 *  block/undo files that should be deleted.  Set on startup
 *  or if we allocate more file space when we're in prune mode
 */
bool fCheckForPruning = false;

/**
 * Every received block is assigned a unique and increasing identifier, so we
 * know which one to give priority in case of a fork.
 */
CCriticalSection cs_nBlockSequenceId;
/** Blocks loaded from disk are assigned id 0, so start the counter at 1. */
int32_t nBlockSequenceId = 1;
/** Decreasing counter (used by subsequent preciousblock calls). */
int32_t nBlockReverseSequenceId = -1;
/** chainwork for the last block that preciousblock has been applied to. */
arith_uint256 nLastPreciousChainwork = 0;

/** In order to efficiently track invalidity of headers, we keep the set of
 * blocks which we tried to connect and found to be invalid here (ie which
 * were set to BLOCK_FAILED_VALID since the last restart). We can then
 * walk this set and check if a new header is a descendant of something in
 * this set, preventing us from having to walk mapBlockIndex when we try
 * to connect a bad block and fail.
 *
 * While this is more complicated than marking everything which descends
 * from an invalid block as invalid at the time we discover it to be
 * invalid, doing so would require walking all of mapBlockIndex to find all
 * descendants. Since this case should be very rare, keeping track of all
 * BLOCK_FAILED_VALID blocks in a set should be just fine and work just as
 * well.
 *
 * Because we already walk mapBlockIndex in height-order at startup, we go
 * ahead and mark descendants of invalid blocks as FAILED_CHILD at that time,
 * instead of putting things in this set.
 */
std::set<CBlockIndex*> gFailedBlocks;

/** Dirty block index entries. */
std::set<CBlockIndex*> setDirtyBlockIndex;

/** Dirty block file entries. */
std::set<int> setDirtyFileInfo;
} // namespace

/* MemPoolConflictRemovalTracker REMOVED
 *
 * This class used boost::signals2 NotifyEntryRemoved signal to track conflicted
 * transactions. It had the same race condition as the validation interface signals,
 * causing segfaults during high-frequency mining.
 *
 * See Bitcoin Core PR #17477 for the proper fix using TransactionRemovedFromMempool.
 */

CBlockIndex* FindForkInGlobalIndex(const CChain& chain, const CBlockLocator& locator)
{
    // Find the first block the caller has in the main chain
    BOOST_FOREACH (const uint256& hash, locator.vHave) {
        BlockMap::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end()) {
            CBlockIndex* pindex = (*mi).second;
            if (chain.Contains(pindex))
                return pindex;
            if (pindex->GetAncestor(chain.Height()) == chain.Tip()) {
                return chain.Tip();
            }
        }
    }
    return chain.Genesis();
}

CCoinsViewCache* pcoinsTip = NULL;
CBlockTreeDB* pblocktree = NULL;

// SOQ-AUD2-002 D4: Global USDSOQ authority key set.
// Initialized from Consensus::Params when DEPLOYMENT_USDSOQ becomes ACTIVE.
// Protected by cs_main.
CUSDSOQAuthority g_usdsoq_authority;

// SOQ-AUD2-002 D1: Global USDSOQ supply counter.
// Updated during ConnectBlock/DisconnectBlock, persisted to LevelDB.
// Protected by cs_main.
CUSDSOQSupply g_usdsoq_supply;

// SOQ-I005: Tracked USDSOQ authority UTXO outpoint.
// Points to the current authority UTXO that must be spent for mint/burn/freeze/rotate.
// Updated in ConnectBlock (advance to new outpoint) and DisconnectBlock (revert).
// Persisted to LevelDB. Protected by cs_main.
COutPoint g_usdsoq_authority_outpoint;

// DL-BTCSOQ-CONSENSUS-NATIVE: BTCSOQ consensus globals (mirror USDSOQ). Protected by cs_main.
// Initialized from Consensus::Params on DEPLOYMENT_BTCSOQ activation; updated in
// ConnectBlock/DisconnectBlock (Step 2C); persisted to LevelDB.
CBTCSOQAuthority g_btcsoq_authority;
CBTCSOQSupply    g_btcsoq_supply;
COutPoint        g_btcsoq_authority_outpoint;

// DL-BTCSOQ-CONSENSUS-NATIVE: the BTCSOQ authority marker is witness v9
// (OP_9 <32-byte authority keyhash>) — deliberately DISTINCT from the USDSOQ
// v5 marker. Each asset's enforcement routes on its own unforgeable,
// sighash-covered output marker; witness tags are never used for routing
// (witness data is not signed and is therefore malleable in flight).
static bool IsBTCSOQAuthorityMarker(const CScript& spk)
{
    return spk.size() == 34 && spk[0] == OP_9 && spk[1] == 32;
}

enum FlushStateMode {
    FLUSH_STATE_NONE,
    FLUSH_STATE_IF_NEEDED,
    FLUSH_STATE_PERIODIC,
    FLUSH_STATE_ALWAYS
};

// See definition for documentation
bool static FlushStateToDisk(CValidationState& state, FlushStateMode mode, int nManualPruneHeight = 0);
void FindFilesToPruneManual(std::set<int>& setFilesToPrune, int nManualPruneHeight);

bool IsFinalTx(const CTransaction& tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx.nLockTime == 0)
        return true;
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;
    for (const auto& txin : tx.vin) {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
            return false;
    }
    return true;
}

bool CheckFinalTx(const CTransaction& tx, int flags)
{
    AssertLockHeld(cs_main);

    // By convention a negative value for flags indicates that the
    // current network-enforced consensus rules should be used. In
    // a future soft-fork scenario that would mean checking which
    // rules would be enforced for the next block and setting the
    // appropriate flags. At the present time no soft-forks are
    // scheduled, so no flags are set.
    flags = std::max(flags, 0);

    // CheckFinalTx() uses chainActive.Height()+1 to evaluate
    // nLockTime because when IsFinalTx() is called within
    // CBlock::AcceptBlock(), the height of the block *being*
    // evaluated is what is used. Thus if we want to know if a
    // transaction can be part of the *next* block, we need to call
    // IsFinalTx() with one more than chainActive.Height().
    const int nBlockHeight = chainActive.Height() + 1;

    // BIP113 will require that time-locked transactions have nLockTime set to
    // less than the median time of the previous block they're contained in.
    // When the next block is created its previous block will be the current
    // chain tip, so we use that to calculate the median time passed to
    // IsFinalTx() if LOCKTIME_MEDIAN_TIME_PAST is set.
    const int64_t nBlockTime = (flags & LOCKTIME_MEDIAN_TIME_PAST) ? chainActive.Tip()->GetMedianTimePast() : GetAdjustedTime();

    return IsFinalTx(tx, nBlockHeight, nBlockTime);
}

/**
 * Calculates the block height and previous block's median time past at
 * which the transaction will be considered final in the context of BIP 68.
 * Also removes from the vector of input heights any entries which did not
 * correspond to sequence locked inputs as they do not affect the calculation.
 */
static std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction& tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    assert(prevHeights->size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    // tx.nVersion is signed integer so requires cast to unsigned otherwise
    // we would be doing a signed comparison and half the range of nVersion
    // wouldn't support BIP 68.
    bool fEnforceBIP68 = static_cast<uint32_t>(tx.nVersion) >= 2 && flags & LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if (!fEnforceBIP68) {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn& txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            (*prevHeights)[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = (*prevHeights)[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            int64_t nCoinTime = block.GetAncestor(std::max(nCoinHeight - 1, 0))->GetMedianTimePast();
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } else {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

static bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
        return false;

    return true;
}

bool SequenceLocks(const CTransaction& tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

bool TestLockPointValidity(const LockPoints* lp)
{
    AssertLockHeld(cs_main);
    assert(lp);
    // If there are relative lock times then the maxInputBlock will be set
    // If there are no relative lock times, the LockPoints don't depend on the chain
    if (lp->maxInputBlock) {
        // Check whether chainActive is an extension of the block at which the LockPoints
        // calculation was valid.  If not LockPoints are no longer valid
        if (!chainActive.Contains(lp->maxInputBlock)) {
            return false;
        }
    }

    // LockPoints still valid
    return true;
}

bool CheckSequenceLocks(const CTransaction& tx, int flags, LockPoints* lp, bool useExistingLockPoints)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(mempool.cs);

    CBlockIndex* tip = chainActive.Tip();
    CBlockIndex index;
    index.pprev = tip;
    // CheckSequenceLocks() uses chainActive.Height()+1 to evaluate
    // height based locks because when SequenceLocks() is called within
    // ConnectBlock(), the height of the block *being*
    // evaluated is what is used.
    // Thus if we want to know if a transaction can be part of the
    // *next* block, we need to use one more than chainActive.Height()
    index.nHeight = tip->nHeight + 1;

    std::pair<int, int64_t> lockPair;
    if (useExistingLockPoints) {
        assert(lp);
        lockPair.first = lp->height;
        lockPair.second = lp->time;
    } else {
        // pcoinsTip contains the UTXO set for chainActive.Tip()
        CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
        std::vector<int> prevheights;
        prevheights.resize(tx.vin.size());
        for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
            const CTxIn& txin = tx.vin[txinIndex];
            CCoins coins;
            if (!viewMemPool.GetCoins(txin.prevout.hash, coins)) {
                return error("%s: Missing input", __func__);
            }
            if (coins.nHeight == MEMPOOL_HEIGHT) {
                // Assume all mempool transaction confirm in the next block
                prevheights[txinIndex] = tip->nHeight + 1;
            } else {
                prevheights[txinIndex] = coins.nHeight;
            }
        }
        lockPair = CalculateSequenceLocks(tx, flags, &prevheights, index);
        if (lp) {
            lp->height = lockPair.first;
            lp->time = lockPair.second;
            // Also store the hash of the block with the highest height of
            // all the blocks which have sequence locked prevouts.
            // This hash needs to still be on the chain
            // for these LockPoint calculations to be valid
            // Note: It is impossible to correctly calculate a maxInputBlock
            // if any of the sequence locked inputs depend on unconfirmed txs,
            // except in the special case where the relative lock time/height
            // is 0, which is equivalent to no sequence lock. Since we assume
            // input height of tip+1 for mempool txs and test the resulting
            // lockPair from CalculateSequenceLocks against tip+1.  We know
            // EvaluateSequenceLocks will fail if there was a non-zero sequence
            // lock on a mempool input, so we can use the return value of
            // CheckSequenceLocks to indicate the LockPoints validity
            int maxInputHeight = 0;
            BOOST_FOREACH (int height, prevheights) {
                // Can ignore mempool inputs since we'll fail if they had non-zero locks
                if (height != tip->nHeight + 1) {
                    maxInputHeight = std::max(maxInputHeight, height);
                }
            }
            lp->maxInputBlock = tip->GetAncestor(maxInputHeight);
        }
    }
    return EvaluateSequenceLocks(index, lockPair);
}


unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;
    for (const auto& txin : tx.vin) {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    for (const auto& txout : tx.vout) {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CTxOut& prevout = inputs.GetOutputFor(tx.vin[i]);
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

int64_t GetTransactionSigOpCost(const CTransaction& tx, const CCoinsViewCache& inputs, int flags)
{
    int64_t nSigOps = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR;

    if (tx.IsCoinBase())
        return nSigOps;

    if (flags & SCRIPT_VERIFY_P2SH) {
        nSigOps += GetP2SHSigOpCount(tx, inputs) * WITNESS_SCALE_FACTOR;
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CTxOut& prevout = inputs.GetOutputFor(tx.vin[i]);
        nSigOps += CountWitnessSigOps(tx.vin[i].scriptSig, prevout.scriptPubKey, &tx.vin[i].scriptWitness, flags);
    }
    return nSigOps;
}


bool CheckTransaction(const CTransaction& tx, CValidationState& state, bool fCheckDuplicateInputs)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vout-empty");
    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) > MAX_BLOCK_BASE_SIZE)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-oversize");

    // Check for negative or overflow output values
    CAmount nValueOut = 0;
    for (const auto& txout : tx.vout) {
        if (txout.nValue < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
    }

    // Check for duplicate inputs - note that this check is slow so we skip it in CheckBlock
    if (fCheckDuplicateInputs) {
        std::set<COutPoint> vInOutPoints;
        for (const auto& txin : tx.vin) {
            if (!vInOutPoints.insert(txin.prevout).second)
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-duplicate");
        }
    }

    if (tx.IsCoinBase()) {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-length");
    } else {
        for (const auto& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.DoS(10, false, REJECT_INVALID, "bad-txns-prevout-null");
    }

    if (!tx.HasDilithiumSignatures()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-requires-dilithium");
    }

    // Phase 4: Validate asset classification via witness-version predicates.
    // No nVisibility/nAssetType bytes exist; classification is structural.
    {
        bool hasUSDSOQ = false;
        bool hasBTCSOQ = false;
        bool hasUSDSOQAuthority = false;
        bool hasBTCSOQAuthority = false;

        for (const auto& txout : tx.vout) {
            // IsAnyUSDSOQ(), not IsUSDSOQ(): the coinbase ban must cover the
            // confidential v10 form as well as v7. Since witness-version
            // creation is no longer consensus-reserved (see the SOQ-I009 note
            // in ConnectBlock), a coinbase is the ONE path that could create an
            // asset-shaped output carrying SOQ value without passing the
            // per-asset conservation rule in CheckTxInputs. That rule and the
            // per-asset fee filter are both satisfied trivially only while no
            // asset-shaped output ever holds value before its deployment
            // activates; this ban is what keeps that true.
            if (txout.IsAnyUSDSOQ()) hasUSDSOQ = true;
            if (txout.IsBTCSOQ()) hasBTCSOQ = true;
            const CScript& spk = txout.scriptPubKey;
            if (spk.size() == 34 && spk[0] == OP_5 && spk[1] == 32) hasUSDSOQAuthority = true;
            if (IsBTCSOQAuthorityMarker(spk)) hasBTCSOQAuthority = true;
        }

        // Coinbase outputs must be native SOQ — cannot mint USDSOQ via mining.
        // The v5 authority marker is forbidden in a coinbase for the same
        // reason the v9 marker is (see the BTCSOQ rule below): with witness-
        // version creation no longer consensus-reserved, a coinbase-born v5
        // UTXO costs the miner nothing and would sit in the UTXO set as a
        // candidate prevout for the bootstrap fallback in ConnectBlock, which
        // accepts ANY v5 prevout as the authority input while the tracked
        // outpoint is null. This is a partial control, not a complete one: an
        // ordinary transaction can still create a v5 output by paying its own
        // SOQ into it, and neither marker ban changes that. Both paths are
        // inert without the authority keyset — a bootstrap still verifies
        // M-of-N ML-DSA against the configured keys — so this closes the free,
        // miner-only path and restores symmetry with BTCSOQ, and the residual
        // is tracked separately (pin the bootstrap fallback to
        // ComputeAuthorityKeyHash).
        //
        // Unconditional on purpose: a rejection the genesis binary carries is
        // one every later release keeps, and this one is load-bearing for the
        // additive asset design (see above).
        if (tx.IsCoinBase() && (hasUSDSOQ || hasUSDSOQAuthority)) {
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-usdsoq-asset");
        }

        // DL-BTCSOQ-CONSENSUS-NATIVE: same rule for BTCSOQ (v8), and the v9
        // authority marker is also forbidden in a coinbase. NOT for the reason
        // the v5 ban above exists: BTCSOQ's bootstrap pins
        // nAuthorityInputIndex = 0 (see the BTCSOQ block in ConnectBlock) and
        // never scans inputs for a v9 prevout, so a coinbase-born v9 marker is
        // inert, unlike a v5 one. This ban is a tightening in its own right,
        // kept because a free miner-only asset-shaped UTXO has no legitimate
        // use. (Unlike USDSOQ, BTCSOQ has no legacy chain, so this is strict
        // from genesis on every network.)
        if (tx.IsCoinBase() && (hasBTCSOQ || hasBTCSOQAuthority)) {
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-btcsoq-asset");
        }

        // A transaction may carry at most ONE asset's authority marker. Each
        // marker grants that asset's ex-nihilo exemption and routes to that
        // asset's ConnectBlock enforcement; allowing both on one tx would
        // require reasoning about stacked exemptions, so it is simply invalid.
        if (hasUSDSOQAuthority && hasBTCSOQAuthority) {
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-dual-authority-marker");
        }
    }

    return true;
}

void LimitMempoolSize(CTxMemPool& pool, size_t limit, unsigned long age)
{
    int expired = pool.Expire(GetTime() - age);
    if (expired != 0)
        LogPrint("mempool", "Expired %i transactions from the memory pool\n", expired);

    std::vector<uint256> vNoSpendsRemaining;
    pool.TrimToSize(limit, &vNoSpendsRemaining);
    BOOST_FOREACH (const uint256& removed, vNoSpendsRemaining)
        pcoinsTip->Uncache(removed);
}

/** Convert CValidationState to a human-readable message for logging */
std::string FormatStateMessage(const CValidationState& state)
{
    return strprintf("%s%s (code %i)",
        state.GetRejectReason(),
        state.GetDebugMessage().empty() ? "" : ", " + state.GetDebugMessage(),
        state.GetRejectCode());
}

static bool IsCurrentForFeeEstimation()
{
    AssertLockHeld(cs_main);
    if (IsInitialBlockDownload())
        return false;
    if (chainActive.Tip()->GetBlockTime() < (GetTime() - MAX_FEE_ESTIMATION_TIP_AGE))
        return false;
    if (chainActive.Height() < pindexBestHeader->nHeight - 1)
        return false;
    return true;
}

bool AcceptToMemoryPoolWorker(CTxMemPool& pool, CValidationState& state, const CTransactionRef& ptx, bool fLimitFree, bool* pfMissingInputs, int64_t nAcceptTime, std::list<CTransactionRef>* plTxnReplaced, bool fOverrideMempoolLimit, const CAmount& nAbsurdFee, std::vector<uint256>& vHashTxnToUncache)
{
    const CTransaction& tx = *ptx;
    const uint256 hash = tx.GetHash();
    AssertLockHeld(cs_main);
    if (pfMissingInputs)
        *pfMissingInputs = false;

    if (!CheckTransaction(tx, state))
        return false; // state filled in by CheckTransaction

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "coinbase");

    // Reject transactions with witness before segregated witness activates (override with -prematurewitness)
    bool witnessEnabled = IsWitnessEnabled(chainActive.Tip(), Params().GetConsensus(chainActive.Height()));
    if (!GetBoolArg("-prematurewitness", false) && tx.HasWitness() && !witnessEnabled) {
        return state.DoS(0, false, REJECT_NONSTANDARD, "no-witness-yet", true);
    }

    // Which gated witness versions are actually spendable-by-rule right now.
    //
    // A gated witness version is anyone-can-spend until its deployment activates,
    // so relaying an output of that form before activation is a fund-loss path,
    // not a safe failure: it confirms, and then anybody may spend it. Policy must
    // therefore track consensus on the OUTPUT side, exactly as it already does on
    // the INPUT side (see the scriptVerifyFlags block below, added after live bug
    // daf9fd85). Anything not listed here stays non-standard, which is the
    // fail-safe direction.
    WitnessVersionMask activeWitnessVersions = 0;
    {
        const int nNextHeight = chainActive.Height() + 1;
        const Consensus::Params& cons = Params().GetConsensus(nNextHeight);
        auto heightActive = [&](Consensus::DeploymentPos pos) {
            return Consensus::DeploymentActiveAtHeight(nNextHeight, cons, pos);
        };
        auto bip9Active = [&](Consensus::DeploymentPos pos) {
            return VersionBitsState(chainActive.Tip(), cons, pos, versionbitscache) == THRESHOLD_ACTIVE;
        };
        // v0/v1 are the always-standard base forms and are handled by Solver.
        // v2 (PAT) is deliberately absent and must stay absent: it is
        // permanently unfundable at consensus (ConnectBlock's v2 creation rule),
        // because PAT's attestation is a coinbase commitment rather than an
        // output type. Setting the bit from DEPLOYMENT_CHECKPATAGG would state
        // the opposite of the consensus rule. It would also have no effect —
        // Solver never names the v2 form, so IsStandard returns false before it
        // reads this mask (witness_version_allocation_tests
        // mask_bits_for_v2_v3_v4_cannot_affect_standardness) — and a dead bit
        // that contradicts consensus is exactly the kind of disagreement this
        // mask exists to prevent. Bead pat-v2-anyone-can-spend-ae6u.
        if (bip9Active(Consensus::DEPLOYMENT_LATTICEFOLD))     activeWitnessVersions |= WitnessVersionBit(3);
        if (heightActive(Consensus::DEPLOYMENT_SOQUOBSCURA))   activeWitnessVersions |= WitnessVersionBit(4);
        // USDSOQ governs both the v5 authority marker and the v7 holding form.
        if (heightActive(Consensus::DEPLOYMENT_USDSOQ))        activeWitnessVersions |= WitnessVersionBit(5) | WitnessVersionBit(7);
        if (heightActive(Consensus::DEPLOYMENT_P2WSH_DILITHIUM)) activeWitnessVersions |= WitnessVersionBit(6);
        // BTCSOQ governs both the v8 holding form and the v9 authority marker.
        if (heightActive(Consensus::DEPLOYMENT_BTCSOQ))        activeWitnessVersions |= WitnessVersionBit(8) | WitnessVersionBit(9);
        // v10 is ALLOCATED (confidential USDSOQ, gated on SOQUOBSCURA + USDSOQ
        // together) but deliberately stays out of this mask: its Solver form and
        // verifier ship with the activation release, and nothing is standard
        // that Solver cannot name. v11-v16 are unallocated: never standard
        // until one is assigned a deployment.
    }

    // Rather not work on nonstandard transactions (unless -testnet/-regtest)
    std::string reason;
    if (fRequireStandard && !IsStandardTx(tx, reason, witnessEnabled, activeWitnessVersions))
        return state.DoS(0, false, REJECT_NONSTANDARD, reason);

    // Only accept nLockTime-using transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    if (!CheckFinalTx(tx, STANDARD_LOCKTIME_VERIFY_FLAGS))
        return state.DoS(0, false, REJECT_NONSTANDARD, "non-final");

    // is it already in the memory pool?
    if (pool.exists(hash))
        return state.Invalid(false, REJECT_ALREADY_KNOWN, "txn-already-in-mempool");

    // Check for conflicts with in-memory transactions
    std::set<uint256> setConflicts;
    {
        LOCK(pool.cs); // protect pool.mapNextTx
        BOOST_FOREACH (const CTxIn& txin, tx.vin) {
            auto itConflicting = pool.mapNextTx.find(txin.prevout);
            if (itConflicting != pool.mapNextTx.end()) {
                const CTransaction* ptxConflicting = itConflicting->second;
                if (!setConflicts.count(ptxConflicting->GetHash())) {
                    // Allow opt-out of transaction replacement by setting
                    // nSequence >= maxint-1 on all inputs.
                    //
                    // maxint-1 is picked to still allow use of nLockTime by
                    // non-replaceable transactions. All inputs rather than just one
                    // is for the sake of multi-party protocols, where we don't
                    // want a single party to be able to disable replacement.
                    //
                    // The opt-out ignores descendants as anyone relying on
                    // first-seen mempool behavior should be checking all
                    // unconfirmed ancestors anyway; doing otherwise is hopelessly
                    // insecure.
                    bool fReplacementOptOut = true;
                    if (fEnableReplacement) {
                        BOOST_FOREACH (const CTxIn& _txin, ptxConflicting->vin) {
                            if (_txin.nSequence < std::numeric_limits<unsigned int>::max() - 1) {
                                fReplacementOptOut = false;
                                break;
                            }
                        }
                    }
                    if (fReplacementOptOut)
                        return state.Invalid(false, REJECT_CONFLICT, "txn-mempool-conflict");

                    setConflicts.insert(ptxConflicting->GetHash());
                }
            }
        }
    }

    {
        CCoinsView dummy;
        CCoinsViewCache view(&dummy);

        CAmount nValueIn = 0;
        LockPoints lp;
        {
            LOCK(pool.cs);
            CCoinsViewMemPool viewMemPool(pcoinsTip, pool);
            view.SetBackend(viewMemPool);

            // do we already have it?
            bool fHadTxInCache = pcoinsTip->HaveCoinsInCache(hash);
            if (view.HaveCoins(hash)) {
                if (!fHadTxInCache)
                    vHashTxnToUncache.push_back(hash);
                return state.Invalid(false, REJECT_ALREADY_KNOWN, "txn-already-known");
            }

            // do all inputs exist?
            // Note that this does not check for the presence of actual outputs (see the next check for that),
            // and only helps with filling in pfMissingInputs (to determine missing vs spent).
            BOOST_FOREACH (const CTxIn txin, tx.vin) {
                if (!pcoinsTip->HaveCoinsInCache(txin.prevout.hash))
                    vHashTxnToUncache.push_back(txin.prevout.hash);
                if (!view.HaveCoins(txin.prevout.hash)) {
                    if (pfMissingInputs)
                        *pfMissingInputs = true;
                    return false; // fMissingInputs and !state.IsInvalid() is used to detect this condition, don't set state.Invalid()
                }
            }

            // are the actual inputs available?
            if (!view.HaveInputs(tx))
                return state.Invalid(false, REJECT_DUPLICATE, "bad-txns-inputs-spent");

            // Bring the best block into scope
            view.GetBestBlock();

            nValueIn = view.GetValueIn(tx);

            // we have all inputs cached now, so switch back to dummy, so we don't need to keep lock on mempool
            view.SetBackend(dummy);

            // Only accept BIP68 sequence locked transactions that can be mined in the next
            // block; we don't want our mempool filled up with transactions that can't
            // be mined yet.
            // Must keep pool.cs for this unless we change CheckSequenceLocks to take a
            // CoinsViewCache instead of create its own
            if (!CheckSequenceLocks(tx, STANDARD_LOCKTIME_VERIFY_FLAGS, &lp))
                return state.DoS(0, false, REJECT_NONSTANDARD, "non-BIP68-final");
        }

        // Check for non-standard pay-to-script-hash in inputs
        if (fRequireStandard && !AreInputsStandard(tx, view))
            return state.Invalid(false, REJECT_NONSTANDARD, "bad-txns-nonstandard-inputs");

        // Check for non-standard witness in P2WSH
        if (tx.HasWitness() && fRequireStandard && !IsWitnessStandard(tx, view))
            return state.DoS(0, false, REJECT_NONSTANDARD, "bad-witness-nonstandard", true);

        // SOQ-I005-MEMPOOL: Reject authority TXs that don't spend the tracked
        // authority outpoint. This prevents mempool-poison attacks where a TX
        // passes relay validation but fails ConnectBlock's authority outpoint
        // check, causing CreateNewBlock/TestBlockValidity to abort and halting
        // block production network-wide.
        //
        // This check mirrors ConnectBlock L2777-2787 but runs at mempool
        // acceptance time, preventing the poison TX from ever entering.
        {
            bool hasAuthorityOutput = false;
            for (const auto& txout : tx.vout) {
                if (txout.scriptPubKey.size() == 34 &&
                    txout.scriptPubKey[0] == OP_5 &&
                    txout.scriptPubKey[1] == 0x20) {
                    hasAuthorityOutput = true;
                    break;
                }
            }

            if (hasAuthorityOutput && !g_usdsoq_authority_outpoint.IsNull()) {
                // Non-bootstrap: TX must spend the tracked authority outpoint
                bool spendsAuthorityOutpoint = false;
                for (const auto& txin : tx.vin) {
                    if (txin.prevout == g_usdsoq_authority_outpoint) {
                        spendsAuthorityOutpoint = true;
                        break;
                    }
                }
                if (!spendsAuthorityOutpoint) {
                    return state.DoS(100, false, REJECT_INVALID,
                        "bad-usdsoq-authority-outpoint-mempool",
                        false,
                        strprintf("USDSOQ authority TX %s rejected from mempool: "
                            "does not spend tracked authority UTXO %s:%u",
                            hash.ToString(),
                            g_usdsoq_authority_outpoint.hash.ToString(),
                            g_usdsoq_authority_outpoint.n));
                }
            }
        }

        // =====================================================================
        // DL-BTCSOQ-CONSENSUS-NATIVE: BTCSOQ authority-tx mempool guards.
        // Mirrors the USDSOQ outpoint-chain check above, PLUS the checks that
        // ConnectBlock enforces but USDSOQ policy historically did not mirror
        // (the accept-then-reject template-poison class — an invalid authority
        // tx sitting in the mempool makes TestBlockValidity fail and the pool
        // mine empty blocks): op-envelope validity, double-mint anti-replay,
        // witness/op tag equality, and M-of-N ML-DSA signature verification.
        // Every rejection here has an identical ConnectBlock twin, so policy
        // remains a strict subset of consensus.
        // =====================================================================
        {
            bool isBTCSOQAuthorityTx = false;
            for (const auto& txout : tx.vout) {
                if (IsBTCSOQAuthorityMarker(txout.scriptPubKey)) {
                    isBTCSOQAuthorityTx = true;
                    break;
                }
            }

            // Deployment gate (2D review finding): pre-activation, ConnectBlock
            // treats v9 as anyone-can-spend, so these mirrors must be dormant
            // too — otherwise the mempool rejects (with a ban score) a tx that
            // consensus would accept. Evaluated at the next block's height,
            // matching the mempool script-flag computation below.
            const int nBTCSOQNextHeight = chainActive.Height() + 1;
            const bool fBTCSOQActive = Consensus::DeploymentActiveAtHeight(
                nBTCSOQNextHeight, Params().GetConsensus(nBTCSOQNextHeight),
                Consensus::DEPLOYMENT_BTCSOQ);

            if (isBTCSOQAuthorityTx && fBTCSOQActive) {
                // Default-deny: no configured authority ⇒ no valid authority tx.
                if (!g_btcsoq_authority.IsInitialized()) {
                    return state.DoS(100, false, REJECT_INVALID,
                        "bad-btcsoq-authority-unavailable", false,
                        "BTCSOQ authority TX rejected: authority key set not initialized");
                }

                // Non-bootstrap: must spend the tracked authority outpoint.
                if (!g_btcsoq_authority_outpoint.IsNull()) {
                    bool spendsBTCSOQAuthOutpoint = false;
                    for (const auto& txin : tx.vin) {
                        if (txin.prevout == g_btcsoq_authority_outpoint) {
                            spendsBTCSOQAuthOutpoint = true;
                            break;
                        }
                    }
                    if (!spendsBTCSOQAuthOutpoint) {
                        return state.DoS(100, false, REJECT_INVALID,
                            "bad-btcsoq-authority-outpoint-mempool", false,
                            strprintf("BTCSOQ authority TX %s rejected from mempool: "
                                "does not spend tracked authority UTXO %s:%u",
                                hash.ToString(),
                                g_btcsoq_authority_outpoint.hash.ToString(),
                                g_btcsoq_authority_outpoint.n));
                    }
                } else if (pcoinsdbview) {
                    // Bootstrap re-entry guard (H2 pattern): if LevelDB already
                    // has an outpoint while memory is null, this node's state is
                    // damaged — never let a bootstrap tx into the mempool.
                    COutPoint dbOutpoint;
                    if (pcoinsdbview->ReadBTCSOQAuthorityOutpoint(dbOutpoint) &&
                        !dbOutpoint.IsNull()) {
                        return state.DoS(100, false, REJECT_INVALID,
                            "bad-btcsoq-bootstrap-reentry", false,
                            "BTCSOQ bootstrap rejected: authority outpoint exists in DB");
                    }
                }

                // The signed op envelope must parse to exactly one op.
                uint8_t btcsoqTag = 0;
                std::vector<uint8_t> btcsoqPayload;
                if (!ParseBTCSOQAuthorityOp(tx, btcsoqTag, btcsoqPayload)) {
                    return state.DoS(100, false, REJECT_INVALID,
                        "bad-btcsoq-missing-op", false,
                        "BTCSOQ authority TX lacks a single well-formed op OP_RETURN");
                }

                // Op-binding mirrors of ConnectBlock (review finding: without
                // these, an internally-inconsistent-but-signed authority op
                // would sit in the mempool poisoning every block template).
                // v8 sums come from the live coins view (inputs unspent here).
                CAmount nAtmpV8Out = 0;
                int nAtmpV8OutputIndex = -1;
                unsigned int nAtmpV8OutputCount = 0;
                for (size_t o = 0; o < tx.vout.size(); ++o) {
                    if (tx.vout[o].IsConfidential()) {
                        return state.DoS(100, false, REJECT_INVALID,
                            "bad-btcsoq-authority-must-be-transparent", false,
                            "BTCSOQ authority TX carries a confidential output");
                    }
                    if (tx.vout[o].IsBTCSOQ()) {
                        nAtmpV8Out += tx.vout[o].nValue;
                        nAtmpV8OutputIndex = static_cast<int>(o);
                        ++nAtmpV8OutputCount;
                    }
                }
                CAmount nAtmpV8In = 0;
                for (const auto& txin : tx.vin) {
                    const CCoins* c = view.AccessCoins(txin.prevout.hash);
                    if (c && c->IsAvailable(txin.prevout.n) &&
                        c->vout[txin.prevout.n].IsBTCSOQ()) {
                        nAtmpV8In += c->vout[txin.prevout.n].nValue;
                    }
                }
                if (nAtmpV8Out > 0 && btcsoqTag != BTCSOQ_OP_MINT) {
                    return state.DoS(100, false, REJECT_INVALID,
                        "bad-btcsoq-unbound-mint", false,
                        "BTCSOQ authority TX creates v8 outputs under a non-MINT op");
                }
                if (nAtmpV8In > 0 && btcsoqTag != BTCSOQ_OP_BURN) {
                    return state.DoS(100, false, REJECT_INVALID,
                        "bad-btcsoq-unbound-burn", false,
                        "BTCSOQ authority TX spends v8 inputs under a non-BURN op");
                }

                if (btcsoqTag == BTCSOQ_OP_MINT) {
                    uint256 btcTxid, mintRecipient;
                    uint32_t btcVout = 0;
                    CAmount mintSats = 0;
                    if (!ParseBTCSOQMintPayload(btcsoqPayload, btcTxid, btcVout,
                                                mintSats, mintRecipient)) {
                        return state.DoS(100, false, REJECT_INVALID,
                            "bad-btcsoq-mint-payload", false,
                            "BTCSOQ MINT payload malformed");
                    }
                    if (nAtmpV8OutputCount != 1) {
                        return state.DoS(100, false, REJECT_INVALID,
                            "bad-btcsoq-mint-outputs", false,
                            "BTCSOQ MINT must create exactly one v8 output");
                    }
                    if (tx.vout[nAtmpV8OutputIndex].nValue != mintSats) {
                        return state.DoS(100, false, REJECT_INVALID,
                            "bad-btcsoq-mint-amount", false,
                            "BTCSOQ MINT output value != attested deposit sats");
                    }
                    if (ComputeBTCSOQRecipientCommitment(
                            tx.vout[nAtmpV8OutputIndex].scriptPubKey) != mintRecipient) {
                        return state.DoS(100, false, REJECT_INVALID,
                            "bad-btcsoq-mint-recipient", false,
                            "BTCSOQ MINT recipient script does not match signed commitment");
                    }
                    if (pcoinsdbview &&
                        pcoinsdbview->IsBTCSOQMinted(COutPoint(btcTxid, btcVout))) {
                        return state.DoS(100, false, REJECT_INVALID,
                            "bad-btcsoq-double-mint", false,
                            strprintf("Bitcoin deposit %s:%u already minted",
                                btcTxid.ToString(), btcVout));
                    }
                } else if (btcsoqTag == BTCSOQ_OP_BURN) {
                    uint256 releaseScriptHash;
                    CAmount burnSats = 0;
                    if (!ParseBTCSOQBurnPayload(btcsoqPayload, releaseScriptHash, burnSats)) {
                        return state.DoS(100, false, REJECT_INVALID,
                            "bad-btcsoq-burn-payload", false,
                            "BTCSOQ BURN payload malformed");
                    }
                    if (nAtmpV8In <= 0) {
                        return state.DoS(100, false, REJECT_INVALID,
                            "bad-btcsoq-burn-empty", false,
                            "BTCSOQ BURN spends no v8 inputs");
                    }
                    if (nAtmpV8In != burnSats) {
                        return state.DoS(100, false, REJECT_INVALID,
                            "bad-btcsoq-burn-amount", false,
                            "BTCSOQ BURN release intent != v8 input sum");
                    }
                }

                // M-of-N ML-DSA authority signature verification (mempool
                // mirror of the ConnectBlock check). The authority input is
                // the tracked-outpoint spender, or — bootstrap only — input 0
                // signed against this tx's own v9 marker output script.
                int nBTCSOQAuthInput = -1;
                CScript btcsoqScriptCode;
                if (!g_btcsoq_authority_outpoint.IsNull()) {
                    for (unsigned int k = 0; k < tx.vin.size(); ++k) {
                        if (tx.vin[k].prevout == g_btcsoq_authority_outpoint) {
                            nBTCSOQAuthInput = static_cast<int>(k);
                            const CCoins* ac = view.AccessCoins(tx.vin[k].prevout.hash);
                            if (ac && ac->IsAvailable(tx.vin[k].prevout.n)) {
                                btcsoqScriptCode = ac->vout[tx.vin[k].prevout.n].scriptPubKey;
                            } else {
                                uint256 keyHash = ComputeAuthorityKeyHash(
                                    g_btcsoq_authority.GetKeys());
                                btcsoqScriptCode.clear();
                                btcsoqScriptCode << OP_9;
                                btcsoqScriptCode << std::vector<unsigned char>(
                                    keyHash.begin(), keyHash.end());
                            }
                            break;
                        }
                    }
                } else {
                    nBTCSOQAuthInput = 0;
                    for (const auto& txout : tx.vout) {
                        if (IsBTCSOQAuthorityMarker(txout.scriptPubKey)) {
                            btcsoqScriptCode = txout.scriptPubKey;
                            break;
                        }
                    }
                }
                if (nBTCSOQAuthInput < 0 ||
                    static_cast<size_t>(nBTCSOQAuthInput) >= tx.vin.size() ||
                    tx.vin[nBTCSOQAuthInput].scriptWitness.IsNull()) {
                    return state.DoS(100, false, REJECT_INVALID,
                        "bad-btcsoq-authority-sig", false,
                        "BTCSOQ authority TX has no verifiable authority input witness");
                }
                const CScriptWitness& btcsoqWit = tx.vin[nBTCSOQAuthInput].scriptWitness;

                // The (unsigned) witness tag must agree with the signed
                // OP_RETURN tag — one source of truth for the op selector.
                if (GetBTCSOQWitnessTag(btcsoqWit.stack) != btcsoqTag) {
                    return state.DoS(100, false, REJECT_INVALID,
                        "bad-btcsoq-tag-mismatch", false,
                        "BTCSOQ witness tag does not match signed op tag");
                }

                std::vector<std::vector<uint8_t>> btcsoqSigs =
                    ExtractBTCSOQWitnessSignatures(btcsoqWit.stack);
                if (btcsoqSigs.empty()) {
                    return state.DoS(100, false, REJECT_INVALID,
                        "bad-btcsoq-authority-sig", false,
                        "BTCSOQ authority TX has no signatures in witness");
                }
                PrecomputedTransactionData btcsoqTxdata(tx);
                uint256 btcsoqSighash = SignatureHash(
                    btcsoqScriptCode, tx, nBTCSOQAuthInput, SIGHASH_ALL,
                    CAmount(0), SIGVERSION_WITNESS_V0, &btcsoqTxdata);
                std::vector<uint8_t> btcsoqSighashBytes(
                    btcsoqSighash.begin(), btcsoqSighash.end());
                if (!g_btcsoq_authority.VerifyAuthoritySignatures(
                        btcsoqSighashBytes, btcsoqSigs)) {
                    return state.DoS(100, false, REJECT_INVALID,
                        "bad-btcsoq-authority-sig", false,
                        "BTCSOQ authority signature verification failed (M-of-N not met)");
                }
            }
        }

        int64_t nSigOpsCost = GetTransactionSigOpCost(tx, view, STANDARD_SCRIPT_VERIFY_FLAGS);

        // SOQ-ARCH-002: Asset-aware fee computation.
        // SOQ-ARCH-003 FIX: Always compute fee using SOQ-only inputs and outputs.
        // This matches ConnectBlock's per-asset fee computation exactly.
        //
        // Previous bug: hasMixedAssets only checked outputs, missing the case
        // where USDSOQ inputs exist but outputs are all SOQ (e.g., burn TXs
        // with OP_RETURN outputs). This caused the mempool to store the full
        // input sum as fee, inflating the miner's coinbase claim and triggering
        // TestBlockValidity → bad-cb-amount.
        //
        // The SOQ-filtered path is always correct:
        //   - Pure SOQ TX: nSOQIn == nValueIn, nSOQOut == nValueOut → same result
        //   - Mixed TX: correctly excludes USDSOQ from fee
        //   - Burn TX: USDSOQ input excluded, fee = SOQ fee input only
        CAmount nFees = 0;
        {
            CAmount nSOQIn = 0;
            CAmount nSOQOut = 0;
            for (unsigned int i = 0; i < tx.vin.size(); i++) {
                const CCoins* coins = view.AccessCoins(tx.vin[i].prevout.hash);
                if (coins && coins->IsAvailable(tx.vin[i].prevout.n)) {
                    if (coins->vout[tx.vin[i].prevout.n].IsNativeSOQ()) {
                        nSOQIn += coins->vout[tx.vin[i].prevout.n].nValue;
                    }
                }
            }
            for (const auto& txout : tx.vout) {
                if (txout.IsNativeSOQ()) {
                    nSOQOut += txout.nValue;
                }
            }
            nFees = nSOQIn - nSOQOut;
        }
        // nModifiedFees includes any fee deltas from PrioritiseTransaction
        CAmount nModifiedFees = nFees;
        double nPriorityDummy = 0;
        pool.ApplyDeltas(hash, nPriorityDummy, nModifiedFees);

        CAmount inChainInputValue;
        double dPriority = view.GetPriority(tx, chainActive.Height(), inChainInputValue);

        // SOQ-USDSOQ-MEMPOOL-CRASH: Enforce USDSOQ per-asset conservation HERE, before
        // constructing the CTxMemPoolEntry below. The full conservation check lives in
        // Consensus::CheckTxInputs (via CheckInputs), but that does not run until ~200
        // lines later — and CTxMemPoolEntry's `assert(inChainInputValue <= nValueIn)`
        // fires first for a non-conserving USDSOQ spend (inChainInputValue sums raw coin
        // value incl. USDSOQ, while nValueIn = GetValueOut() + SOQ-only fee; the delta is
        // exactly USDSOQ_in − USDSOQ_out). A non-conserving USDSOQ tx from any peer would
        // therefore abort() the daemon — a remotely-triggerable crash. Reject it cleanly
        // here, mirroring the ConnectBlock rule, so mempool policy matches consensus.
        // Authority txs (OP_5 marker) mint ex nihilo and are exempt, exactly as in
        // CheckTxInputs; they give USDSOQ_out ≥ USDSOQ_in so the assert never trips.
        {
            bool isAuthorityTx = false;
            for (const auto& txout : tx.vout) {
                if (txout.scriptPubKey.size() == 34 &&
                    txout.scriptPubKey[0] == OP_5 && txout.scriptPubKey[1] == 32) {
                    isAuthorityTx = true;
                    break;
                }
            }
            if (!isAuthorityTx) {
                CAmount nUSDSOQIn = 0, nUSDSOQOut = 0;
                for (const auto& txin : tx.vin) {
                    const CCoins* c = view.AccessCoins(txin.prevout.hash);
                    if (c && c->IsAvailable(txin.prevout.n) &&
                        c->vout[txin.prevout.n].IsUSDSOQ()) {
                        nUSDSOQIn += c->vout[txin.prevout.n].nValue;
                    }
                }
                for (const auto& txout : tx.vout) {
                    if (txout.IsUSDSOQ()) nUSDSOQOut += txout.nValue;
                }
                if (nUSDSOQIn != nUSDSOQOut) {
                    return state.DoS(100, false, REJECT_INVALID,
                        "bad-txns-usdsoq-not-conserved", false,
                        strprintf("USDSOQ in (%s) != USDSOQ out (%s)",
                            FormatMoney(nUSDSOQIn), FormatMoney(nUSDSOQOut)));
                }
            }
        }

        // DL-BTCSOQ-CONSENSUS-NATIVE: the identical remotely-triggerable crash
        // class exists for BTCSOQ — a non-conserving v8 spend would trip
        // CTxMemPoolEntry's `assert(inChainInputValue <= nValueIn)` below and
        // abort() the daemon. Enforce v8 conservation HERE, before the entry
        // is constructed, exactly as the USDSOQ guard above. Authority txs
        // (v9 marker) mint/burn ex nihilo and are exempt, matching
        // Consensus::CheckTxInputs.
        {
            bool isBTCSOQAuthTx = false;
            for (const auto& txout : tx.vout) {
                if (IsBTCSOQAuthorityMarker(txout.scriptPubKey)) {
                    isBTCSOQAuthTx = true;
                    break;
                }
            }
            // The marker-chain guard mirrors a ConnectBlock rule that sits inside
            // `flags & SCRIPT_VERIFY_BTCSOQ`, so it is gated the same way. While
            // the deployment is dormant a v9 marker is plain anyone-can-spend SOQ
            // (additive-asset genesis door); rejecting its spend here with
            // DoS(100) would ban the relayer of a transaction consensus accepts.
            // The conservation mirror stays ungated, like the CheckTxInputs rule.
            const int nBTCSOQMirrorHeight = chainActive.Height() + 1;
            const bool fBTCSOQMirrorActive = Consensus::DeploymentActiveAtHeight(
                nBTCSOQMirrorHeight, Params().GetConsensus(nBTCSOQMirrorHeight),
                Consensus::DEPLOYMENT_BTCSOQ);
            if (!isBTCSOQAuthTx) {
                CAmount nBTCSOQIn = 0, nBTCSOQOut = 0;
                for (const auto& txin : tx.vin) {
                    const CCoins* c = view.AccessCoins(txin.prevout.hash);
                    if (!c || !c->IsAvailable(txin.prevout.n)) continue;
                    // Marker-chain guard (mempool mirror of the ConnectBlock
                    // bad-btcsoq-marker-spend rule): only an authority tx may
                    // spend a v9 marker UTXO — once the deployment is active.
                    if (fBTCSOQMirrorActive &&
                        IsBTCSOQAuthorityMarker(c->vout[txin.prevout.n].scriptPubKey)) {
                        return state.DoS(100, false, REJECT_INVALID,
                            "bad-btcsoq-marker-spend", false,
                            strprintf("non-authority tx spends BTCSOQ authority marker %s:%u",
                                txin.prevout.hash.ToString(), txin.prevout.n));
                    }
                    if (c->vout[txin.prevout.n].IsBTCSOQ()) {
                        nBTCSOQIn += c->vout[txin.prevout.n].nValue;
                    }
                }
                for (const auto& txout : tx.vout) {
                    if (txout.IsBTCSOQ()) nBTCSOQOut += txout.nValue;
                }
                if (nBTCSOQIn != nBTCSOQOut) {
                    return state.DoS(100, false, REJECT_INVALID,
                        "bad-txns-btcsoq-not-conserved", false,
                        strprintf("BTCSOQ in (%s) != BTCSOQ out (%s)",
                            FormatMoney(nBTCSOQIn), FormatMoney(nBTCSOQOut)));
                }
            }
        }

        // BUG-22: Frozen-UTXO guard must ALSO run at mempool acceptance.
        // ConnectBlock rejects any spend of a registry-frozen USDSOQ output
        // (bad-txns-spend-frozen-usdsoq), but without this mirror a frozen-coin
        // spend is script-valid, relays, and sits in the mempool poisoning
        // every block template (TestBlockValidity fails) — the same
        // mempool/consensus divergence class as BUG-21. Mirrors the
        // ConnectBlock input loop exactly: applies to ALL txs (authority txs
        // included — a freeze blocks even authority burns of that outpoint),
        // USDSOQ prevouts only, registry lookup via pcoinsdbview. The registry
        // is empty until the first post-enforcement freeze, so this adds
        // nothing until freezes exist (mainnet-inert until USDSOQ activation).
        // SOQ-I015: mempool mirror of the ConnectBlock bad-usdsoq-marker-spend
        // rule, so policy stays a strict subset of consensus. Without it a
        // marker-destroying tx would relay and sit in every block template until
        // it expired, which is the accept-then-reject template-stall shape.
        // An authority tx here is identified the same way ConnectBlock does it:
        // by carrying an OP_5 output of its own.
        {
            bool hasUsdsoqMarkerOut = false;
            for (const auto& o : tx.vout) {
                if (o.scriptPubKey.size() == 34 && o.scriptPubKey[0] == OP_5 &&
                    o.scriptPubKey[1] == 32) { hasUsdsoqMarkerOut = true; break; }
            }
            // Gated on the deployment exactly like its ConnectBlock twin (inside
            // `flags & SCRIPT_VERIFY_USDSOQ`): while USDSOQ is dormant a v5 marker
            // is plain anyone-can-spend SOQ and its spend must not earn the
            // relayer a DoS(100) for a consensus-valid transaction.
            const int nUSDSOQMirrorHeight = chainActive.Height() + 1;
            const bool fUSDSOQMirrorActive = Consensus::DeploymentActiveAtHeight(
                nUSDSOQMirrorHeight, Params().GetConsensus(nUSDSOQMirrorHeight),
                Consensus::DEPLOYMENT_USDSOQ);
            if (fUSDSOQMirrorActive && !hasUsdsoqMarkerOut) {
                for (const auto& txin : tx.vin) {
                    const CCoins* c = view.AccessCoins(txin.prevout.hash);
                    if (!c || !c->IsAvailable(txin.prevout.n)) continue;
                    const CScript& spk = c->vout[txin.prevout.n].scriptPubKey;
                    if (spk.size() == 34 && spk[0] == OP_5 && spk[1] == 32) {
                        return state.DoS(100, false, REJECT_INVALID,
                            "bad-usdsoq-marker-spend", false,
                            strprintf("non-authority tx spends USDSOQ authority marker %s:%u",
                                txin.prevout.hash.ToString(), txin.prevout.n));
                    }
                }
            }
        }

        for (const auto& txin : tx.vin) {
            const CCoins* c = view.AccessCoins(txin.prevout.hash);
            // IsAnyUSDSOQ(): must match the ConnectBlock freeze-spend guard,
            // which was widened to v7 AND v10 so a frozen confidential outpoint
            // is unspendable too. With IsUSDSOQ() (v7 only) here, a spend of a
            // frozen v10 outpoint relayed and then rejected in-block — the
            // accept-then-reject/template-poison class. Phase A audit, lane A3.
            if (c && c->IsAvailable(txin.prevout.n) &&
                c->vout[txin.prevout.n].IsAnyUSDSOQ() &&
                pcoinsdbview && pcoinsdbview->IsFrozenOutpoint(txin.prevout)) {
                return state.DoS(100, false, REJECT_INVALID,
                    "bad-txns-spend-frozen-usdsoq", false,
                    strprintf("input %s:%u is a frozen USDSOQ outpoint",
                        txin.prevout.hash.ToString(), txin.prevout.n));
            }
            // DL-BTCSOQ-CONSENSUS-NATIVE: mirror for the BTCSOQ frozen
            // registry (same BUG-22 template-poison class; applies to ALL
            // txs, v8 prevouts only, registry lookup via pcoinsdbview).
            if (c && c->IsAvailable(txin.prevout.n) &&
                c->vout[txin.prevout.n].IsBTCSOQ() &&
                pcoinsdbview && pcoinsdbview->IsBTCSOQFrozen(txin.prevout)) {
                return state.DoS(100, false, REJECT_INVALID,
                    "bad-txns-spend-frozen-btcsoq", false,
                    strprintf("input %s:%u is a frozen BTCSOQ outpoint",
                        txin.prevout.hash.ToString(), txin.prevout.n));
            }
        }

        // Keep track of transactions that spend a coinbase, which we re-scan
        // during reorgs to ensure COINBASE_MATURITY is still met.
        bool fSpendsCoinbase = false;
        BOOST_FOREACH (const CTxIn& txin, tx.vin) {
            const CCoins* coins = view.AccessCoins(txin.prevout.hash);
            if (coins->IsCoinBase()) {
                fSpendsCoinbase = true;
                break;
            }
        }

        CTxMemPoolEntry entry(ptx, nFees, nAcceptTime, dPriority, chainActive.Height(),
            inChainInputValue, fSpendsCoinbase, nSigOpsCost, lp);
        unsigned int nSize = entry.GetTxSize();

        // Check that the transaction doesn't have an excessive number of
        // sigops, making it impossible to mine. Since the coinbase transaction
        // itself can contain sigops MAX_STANDARD_TX_SIGOPS is less than
        // MAX_BLOCK_SIGOPS; we still consider this an invalid rather than
        // merely non-standard transaction.
        if (nSigOpsCost > MAX_STANDARD_TX_SIGOPS_COST)
            return state.DoS(0, false, REJECT_NONSTANDARD, "bad-txns-too-many-sigops", false,
                strprintf("%d", nSigOpsCost));

        CAmount mempoolRejectFee = pool.GetMinFee(GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000).GetFee(nSize);
        if (mempoolRejectFee > 0 && nModifiedFees < mempoolRejectFee) {
            return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "mempool min fee not met", false, strprintf("%d < %d", nFees, mempoolRejectFee));
        } else if (GetBoolArg("-relaypriority", DEFAULT_RELAYPRIORITY) && nModifiedFees < ::minRelayTxFeeRate.GetFee(nSize) && !AllowFree(entry.GetPriority(chainActive.Height() + 1))) {
            // Require that free transactions have sufficient priority to be mined in the next block.
            return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "insufficient priority");
        }

        // Continuously rate-limit free (really, very-low-fee) transactions
        // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
        // be annoying or make others' transactions take longer to confirm.
        if (fLimitFree && nModifiedFees < GetSoqucoinMinRelayFee(tx, nSize, !fLimitFree)) {
            static CCriticalSection csFreeLimiter;
            static double dFreeCount;
            static int64_t nLastTime;
            int64_t nNow = GetTime();

            LOCK(csFreeLimiter);

            // Use an exponentially decaying ~10-minute window:
            dFreeCount *= pow(1.0 - 1.0 / 600.0, (double)(nNow - nLastTime));
            nLastTime = nNow;
            // -limitfreerelay unit is thousand-bytes-per-minute
            // At default rate it would take over a month to fill 1GB
            if (dFreeCount + nSize >= GetArg("-limitfreerelay", DEFAULT_LIMITFREERELAY) * 10 * 1000)
                return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "rate limited free transaction");
            LogPrint("mempool", "Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount + nSize);
            dFreeCount += nSize;
        }

        if (nAbsurdFee && nFees > nAbsurdFee)
            return state.Invalid(false,
                REJECT_HIGHFEE, "absurdly-high-fee",
                strprintf("%d > %d", nFees, nAbsurdFee));

        // Calculate in-mempool ancestors, up to a limit.
        CTxMemPool::setEntries setAncestors;
        size_t nLimitAncestors = GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
        size_t nLimitAncestorSize = GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT) * 1000;
        size_t nLimitDescendants = GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT);
        size_t nLimitDescendantSize = GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT) * 1000;
        std::string errString;
        if (!pool.CalculateMemPoolAncestors(entry, setAncestors, nLimitAncestors, nLimitAncestorSize, nLimitDescendants, nLimitDescendantSize, errString)) {
            return state.DoS(0, false, REJECT_NONSTANDARD, "too-long-mempool-chain", false, errString);
        }

        // A transaction that spends outputs that would be replaced by it is invalid. Now
        // that we have the set of all ancestors we can detect this
        // pathological case by making sure setConflicts and setAncestors don't
        // intersect.
        BOOST_FOREACH (CTxMemPool::txiter ancestorIt, setAncestors) {
            const uint256& hashAncestor = ancestorIt->GetTx().GetHash();
            if (setConflicts.count(hashAncestor)) {
                return state.DoS(10, false,
                    REJECT_INVALID, "bad-txns-spends-conflicting-tx", false,
                    strprintf("%s spends conflicting transaction %s",
                        hash.ToString(),
                        hashAncestor.ToString()));
            }
        }

        // Check if it's economically rational to mine this transaction rather
        // than the ones it replaces.
        CAmount nConflictingFees = 0;
        size_t nConflictingSize = 0;
        uint64_t nConflictingCount = 0;
        CTxMemPool::setEntries allConflicting;

        // If we don't hold the lock allConflicting might be incomplete; the
        // subsequent RemoveStaged() and addUnchecked() calls don't guarantee
        // mempool consistency for us.
        LOCK(pool.cs);
        const bool fReplacementTransaction = setConflicts.size();
        if (fReplacementTransaction) {
            CFeeRate newFeeRate(nModifiedFees, nSize);
            std::set<uint256> setConflictsParents;
            const int maxDescendantsToVisit = 100;
            CTxMemPool::setEntries setIterConflicting;
            BOOST_FOREACH (const uint256& hashConflicting, setConflicts) {
                CTxMemPool::txiter mi = pool.mapTx.find(hashConflicting);
                if (mi == pool.mapTx.end())
                    continue;

                // Save these to avoid repeated lookups
                setIterConflicting.insert(mi);

                // Don't allow the replacement to reduce the feerate of the
                // mempool.
                //
                // We usually don't want to accept replacements with lower
                // feerates than what they replaced as that would lower the
                // feerate of the next block. Requiring that the feerate always
                // be increased is also an easy-to-reason about way to prevent
                // DoS attacks via replacements.
                //
                // The mining code doesn't (currently) take children into
                // account (CPFP) so we only consider the feerates of
                // transactions being directly replaced, not their indirect
                // descendants. While that does mean high feerate children are
                // ignored when deciding whether or not to replace, we do
                // require the replacement to pay more overall fees too,
                // mitigating most cases.
                CFeeRate oldFeeRate(mi->GetModifiedFee(), mi->GetTxSize());
                if (newFeeRate <= oldFeeRate) {
                    return state.DoS(0, false,
                        REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                        strprintf("rejecting replacement %s; new feerate %s <= old feerate %s",
                            hash.ToString(),
                            newFeeRate.ToString(),
                            oldFeeRate.ToString()));
                }

                BOOST_FOREACH (const CTxIn& txin, mi->GetTx().vin) {
                    setConflictsParents.insert(txin.prevout.hash);
                }

                nConflictingCount += mi->GetCountWithDescendants();
            }
            // This potentially overestimates the number of actual descendants
            // but we just want to be conservative to avoid doing too much
            // work.
            if (nConflictingCount <= maxDescendantsToVisit) {
                // If not too many to replace, then calculate the set of
                // transactions that would have to be evicted
                BOOST_FOREACH (CTxMemPool::txiter it, setIterConflicting) {
                    pool.CalculateDescendants(it, allConflicting);
                }
                BOOST_FOREACH (CTxMemPool::txiter it, allConflicting) {
                    nConflictingFees += it->GetModifiedFee();
                    nConflictingSize += it->GetTxSize();
                }
            } else {
                return state.DoS(0, false,
                    REJECT_NONSTANDARD, "too many potential replacements", false,
                    strprintf("rejecting replacement %s; too many potential replacements (%d > %d)\n",
                        hash.ToString(),
                        nConflictingCount,
                        maxDescendantsToVisit));
            }

            for (unsigned int j = 0; j < tx.vin.size(); j++) {
                // We don't want to accept replacements that require low
                // feerate junk to be mined first. Ideally we'd keep track of
                // the ancestor feerates and make the decision based on that,
                // but for now requiring all new inputs to be confirmed works.
                if (!setConflictsParents.count(tx.vin[j].prevout.hash)) {
                    // Rather than check the UTXO set - potentially expensive -
                    // it's cheaper to just check if the new input refers to a
                    // tx that's in the mempool.
                    if (pool.mapTx.find(tx.vin[j].prevout.hash) != pool.mapTx.end())
                        return state.DoS(0, false,
                            REJECT_NONSTANDARD, "replacement-adds-unconfirmed", false,
                            strprintf("replacement %s adds unconfirmed input, idx %d",
                                hash.ToString(), j));
                }
            }

            // The replacement must pay greater fees than the transactions it
            // replaces - if we did the bandwidth used by those conflicting
            // transactions would not be paid for.
            if (nModifiedFees < nConflictingFees) {
                return state.DoS(0, false,
                    REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                    strprintf("rejecting replacement %s, less fees than conflicting txs; %s < %s",
                        hash.ToString(), FormatMoney(nModifiedFees), FormatMoney(nConflictingFees)));
            }

            // Finally in addition to paying more fees than the conflicts the
            // new transaction must pay for its own bandwidth.
            CAmount nDeltaFees = nModifiedFees - nConflictingFees;
            if (nDeltaFees < ::incrementalRelayFee.GetFee(nSize)) {
                return state.DoS(0, false,
                    REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                    strprintf("rejecting replacement %s, not enough additional fees to relay; %s < %s",
                        hash.ToString(),
                        FormatMoney(nDeltaFees),
                        FormatMoney(::incrementalRelayFee.GetFee(nSize))));
            }
        }

        unsigned int scriptVerifyFlags = STANDARD_SCRIPT_VERIFY_FLAGS;
        if (!Params().RequireStandard()) {
            scriptVerifyFlags = GetArg("-promiscuousmempoolflags", scriptVerifyFlags);
        }

        // Relay + enforce V6 covenant txs that the NEXT block will enforce. STANDARD omits the V6
        // covenant opcodes, so without this a B1/eLTOO (or CTV/CSFS/keyhash) tx is non-standard
        // (won't relay) AND its covenant opcodes are no-ops at the mempool — e.g. OP_CLTV in a v6
        // script wrongly passes a below-floor eLTOO spend that ConnectBlock rejects. OR-in the V6
        // covenant flags gated by their height-activation (p96/Option D), mirroring ConnectBlock:
        // they are height-0 on stagenet/regtest and NOT_SCHEDULED (never) on mainnet, so this adds
        // NOTHING on mainnet until activation — keeping mempool policy consistent with consensus.
        // Evaluated for the NEXT block (tip height + 1), which is what these txs would land in.
        {
            const int nNextHeight = chainActive.Height() + 1;
            const Consensus::Params& cons = Params().GetConsensus(nNextHeight);
            auto v6active = [&](Consensus::DeploymentPos pos) {
                return Consensus::DeploymentActiveAtHeight(nNextHeight, cons, pos);
            };
            if (v6active(Consensus::DEPLOYMENT_CTV))               scriptVerifyFlags |= SCRIPT_VERIFY_CTV;
            if (v6active(Consensus::DEPLOYMENT_APO))               scriptVerifyFlags |= SCRIPT_VERIFY_APO;
            if (v6active(Consensus::DEPLOYMENT_CSFS))              scriptVerifyFlags |= SCRIPT_VERIFY_CSFS;
            if (v6active(Consensus::DEPLOYMENT_P2WSH_DILITHIUM))   scriptVerifyFlags |= SCRIPT_VERIFY_P2WSH_DILITHIUM;
            if (v6active(Consensus::DEPLOYMENT_DILITHIUM_KEYHASH)) scriptVerifyFlags |= SCRIPT_VERIFY_DILITHIUM_KEYHASH;
            if (v6active(Consensus::DEPLOYMENT_V6_CONTROLFLOW))    scriptVerifyFlags |= SCRIPT_VERIFY_V6_CONTROLFLOW;

            // SOQ-P001 / SOQ-P002 / SOQ-ARCH-001 / SOQ-AUD2-002: mirror the PQ + asset
            // script flags that ConnectBlock enforces (interpreter.cpp gates the v7 USDSOQ,
            // PAT-aggregate, LatticeFold and Lattice-BP++ verification on these exact flags).
            // Without them the mempool verifies those inputs LENIENTLY — a v7 USDSOQ input is
            // effectively anyone-can-spend at accept time — so a tx that ConnectBlock will
            // REJECT is accepted and relayed, then sits in the mempool poisoning every block
            // template until it expires: the pool mines empty (coinbase-only) blocks. That is
            // exactly what a mis-signed v7 USDSOQ send (wrong scriptCode → NULLFAIL) did on
            // stagenet (live bug daf9fd85). This is the same policy≡consensus fix the V6
            // covenant flags above already apply. Match ConnectBlock's activation exactly:
            //   PAT / LATTICEFOLD  → BIP9 VersionBitsState at the tip (= the next block's pprev)
            //   LATTICEBP / USDSOQ → height-gated (p96/Option D) at the next block
            if (VersionBitsState(chainActive.Tip(), cons, Consensus::DEPLOYMENT_CHECKPATAGG, versionbitscache) == THRESHOLD_ACTIVE)
                scriptVerifyFlags |= SCRIPT_VERIFY_PAT;
            if (VersionBitsState(chainActive.Tip(), cons, Consensus::DEPLOYMENT_LATTICEFOLD, versionbitscache) == THRESHOLD_ACTIVE)
                scriptVerifyFlags |= SCRIPT_VERIFY_LATTICEFOLD;
            if (v6active(Consensus::DEPLOYMENT_SOQUOBSCURA))         scriptVerifyFlags |= SCRIPT_VERIFY_SOQUOBSCURA;
            if (v6active(Consensus::DEPLOYMENT_USDSOQ))            scriptVerifyFlags |= SCRIPT_VERIFY_USDSOQ;
            // DL-BTCSOQ-CONSENSUS-NATIVE: same height-gated (p96/Option D)
            // activation model as USDSOQ — mempool flags match ConnectBlock.
            if (v6active(Consensus::DEPLOYMENT_BTCSOQ))            scriptVerifyFlags |= SCRIPT_VERIFY_BTCSOQ;
        }

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        PrecomputedTransactionData txdata(tx);
        if (!CheckInputs(tx, state, view, true, scriptVerifyFlags, true, txdata)) {
            // SCRIPT_VERIFY_CLEANSTACK requires SCRIPT_VERIFY_WITNESS, so we
            // need to turn both off, and compare against just turning off CLEANSTACK
            // to see if the failure is specifically due to witness validation.
            CValidationState stateDummy; // Want reported failures to be from first CheckInputs
            if (!tx.HasWitness() && CheckInputs(tx, stateDummy, view, true, scriptVerifyFlags & ~(SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CLEANSTACK), true, txdata) &&
                !CheckInputs(tx, stateDummy, view, true, scriptVerifyFlags & ~SCRIPT_VERIFY_CLEANSTACK, true, txdata)) {
                // Only the witness is missing, so the transaction itself may be fine.
                state.SetCorruptionPossible();
            }
            return false; // state filled in by CheckInputs
        }

        // Check again against just the consensus-critical mandatory script
        // verification flags, in case of bugs in the standard flags that cause
        // transactions to pass as valid when they're actually invalid. For
        // instance the STRICTENC flag was incorrectly allowing certain
        // CHECKSIG NOT scripts to pass, even though they were invalid.
        //
        // There is a similar check in CreateNewBlock() to prevent creating
        // invalid blocks, however allowing such transactions into the mempool
        // can be exploited as a DoS attack.
        if (!CheckInputs(tx, state, view, true, MANDATORY_SCRIPT_VERIFY_FLAGS, true, txdata)) {
            return error("%s: BUG! PLEASE REPORT THIS! ConnectInputs failed against MANDATORY but not STANDARD flags %s, %s",
                __func__, hash.ToString(), FormatStateMessage(state));
        }

        // Remove conflicting transactions from the mempool
        BOOST_FOREACH (const CTxMemPool::txiter it, allConflicting) {
            LogPrint("mempool", "replacing tx %s with %s for %s BTC additional fees, %d delta bytes\n",
                it->GetTx().GetHash().ToString(),
                hash.ToString(),
                FormatMoney(nModifiedFees - nConflictingFees),
                (int)nSize - (int)nConflictingSize);
            if (plTxnReplaced)
                plTxnReplaced->push_back(it->GetSharedTx());
        }
        pool.RemoveStaged(allConflicting, false, MemPoolRemovalReason::REPLACED);

        // This transaction should only count for fee estimation if it isn't a
        // BIP 125 replacement transaction (may not be widely supported), the
        // node is not behind, and the transaction is not dependent on any other
        // transactions in the mempool.
        bool validForFeeEstimation = !fReplacementTransaction && IsCurrentForFeeEstimation() && pool.HasNoInputsOf(tx);

        // Store transaction in memory
        pool.addUnchecked(hash, entry, setAncestors, validForFeeEstimation);

        // trim mempool and check if tx was trimmed
        if (!fOverrideMempoolLimit) {
            LimitMempoolSize(pool, GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);
            if (!pool.exists(hash))
                return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "mempool full");
        }
    }

    GetMainSignals().SyncTransaction(tx, NULL, CMainSignals::SYNC_TRANSACTION_NOT_IN_BLOCK);

    return true;
}

bool AcceptToMemoryPoolWithTime(CTxMemPool& pool, CValidationState& state, const CTransactionRef& tx, bool fLimitFree, bool* pfMissingInputs, int64_t nAcceptTime, std::list<CTransactionRef>* plTxnReplaced, bool fOverrideMempoolLimit, const CAmount nAbsurdFee)
{
    std::vector<uint256> vHashTxToUncache;
    bool res = AcceptToMemoryPoolWorker(pool, state, tx, fLimitFree, pfMissingInputs, nAcceptTime, plTxnReplaced, fOverrideMempoolLimit, nAbsurdFee, vHashTxToUncache);
    if (!res) {
        BOOST_FOREACH (const uint256& hashTx, vHashTxToUncache)
            pcoinsTip->Uncache(hashTx);
    }
    // After we've (potentially) uncached entries, ensure our coins cache is still within its size limits
    CValidationState stateDummy;
    FlushStateToDisk(stateDummy, FLUSH_STATE_PERIODIC);
    return res;
}

bool AcceptToMemoryPool(CTxMemPool& pool, CValidationState& state, const CTransactionRef& tx, bool fLimitFree, bool* pfMissingInputs, std::list<CTransactionRef>* plTxnReplaced, bool fOverrideMempoolLimit, const CAmount nAbsurdFee)
{
    return AcceptToMemoryPoolWithTime(pool, state, tx, fLimitFree, pfMissingInputs, GetTime(), plTxnReplaced, fOverrideMempoolLimit, nAbsurdFee);
}

/** Return transaction in txOut, and if it was found inside a block, its hash is placed in hashBlock */
bool GetTransaction(const uint256& hash, CTransactionRef& txOut, const Consensus::Params& consensusParams, uint256& hashBlock, bool fAllowSlow)
{
    CBlockIndex* pindexSlow = NULL;

    LOCK(cs_main);

    CTransactionRef ptx = mempool.get(hash);
    if (ptx) {
        txOut = ptx;
        return true;
    }

    if (fTxIndex) {
        CDiskTxPos postx;
        if (pblocktree->ReadTxIndex(hash, postx)) {
            CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
            if (file.IsNull())
                return error("%s: OpenBlockFile failed", __func__);
            CBlockHeader header;
            try {
                file >> header;
                fseek(file.Get(), postx.nTxOffset, SEEK_CUR);
                file >> txOut;
            } catch (const std::exception& e) {
                return error("%s: Deserialize or I/O error - %s", __func__, e.what());
            }
            hashBlock = header.GetHash();
            if (txOut->GetHash() != hash)
                return error("%s: txid mismatch", __func__);
            return true;
        }
    }

    if (fAllowSlow) { // use coin database to locate block that contains transaction, and scan it
        int nHeight = -1;
        {
            const CCoinsViewCache& view = *pcoinsTip;
            const CCoins* coins = view.AccessCoins(hash);
            if (coins)
                nHeight = coins->nHeight;
        }
        if (nHeight > 0)
            pindexSlow = chainActive[nHeight];
    }

    if (pindexSlow) {
        CBlock block;
        if (ReadBlockFromDisk(block, pindexSlow, consensusParams)) {
            for (const auto& tx : block.vtx) {
                if (tx->GetHash() == hash) {
                    txOut = tx;
                    hashBlock = pindexSlow->GetBlockHash();
                    return true;
                }
            }
        }
    }

    return false;
}


//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

bool WriteBlockToDisk(const CBlock& block, CDiskBlockPos& pos, const CMessageHeader::MessageStartChars& messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenBlockFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("WriteBlockToDisk: OpenBlockFile failed");

    // Write index header
    unsigned int nSize = GetSerializeSize(fileout, block);
    fileout << FLATDATA(messageStart) << nSize;

    // Write block
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("WriteBlockToDisk: ftell failed");
    pos.nPos = (unsigned int)fileOutPos;
    fileout << block;

    return true;
}

/* Generic implementation of block reading that can handle
   both a block and its header.  */

template <typename T>
static bool ReadBlockOrHeader(T& block, const CDiskBlockPos& pos, const Consensus::Params& consensusParams, bool fCheckPOW)
{
    block.SetNull();

    // Open history file to read
    CAutoFile filein(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("ReadBlockFromDisk: OpenBlockFile failed for %s", pos.ToString());

    // Read block
    try {
        filein >> block;
    } catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s at %s", __func__, e.what(), pos.ToString());
    }

    // Check the header
    if (fCheckPOW && !CheckAuxPowProofOfWork(block, consensusParams))
        return error("ReadBlockFromDisk: Errors in block header at %s", pos.ToString());

    return true;
}

template <typename T>
static bool ReadBlockOrHeader(T& block, const CBlockIndex* pindex, const Consensus::Params& consensusParams, bool fCheckPOW)
{
    if (!ReadBlockOrHeader(block, pindex->GetBlockPos(), consensusParams, fCheckPOW))
        return false;
    if (block.GetHash() != pindex->GetBlockHash())
        return error("ReadBlockOrHeader(CBlock&, CBlockIndex*): GetHash() doesn't match index for %s at %s",
            pindex->ToString(), pindex->GetBlockPos().ToString());
    return true;
}

bool ReadBlockFromDisk(CBlock& block, const CDiskBlockPos& pos, const Consensus::Params& consensusParams, bool fCheckPOW)
{
    return ReadBlockOrHeader(block, pos, consensusParams, fCheckPOW);
}

bool ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex, const Consensus::Params& consensusParams, bool fCheckPOW)
{
    return ReadBlockOrHeader(block, pindex, consensusParams, fCheckPOW);
}

bool ReadBlockHeaderFromDisk(CBlockHeader& block, const CBlockIndex* pindex, const Consensus::Params& consensusParams, bool fCheckPOW)
{
    return ReadBlockOrHeader(block, pindex, consensusParams, fCheckPOW);
}

bool IsInitialBlockDownload()
{
    const CChainParams& chainParams = Params();

    // Once this function has returned false, it must remain false.
    static std::atomic<bool> latchToFalse{false};
    // Optimization: pre-test latch before taking the lock.
    if (latchToFalse.load(std::memory_order_relaxed))
        return false;

    LOCK(cs_main);
    if (latchToFalse.load(std::memory_order_relaxed))
        return false;
    if (fImporting || fReindex)
        return true;
    if (chainActive.Tip() == NULL)
        return true;
    if (chainActive.Tip()->nChainWork < UintToArith256(chainParams.GetConsensus(chainActive.Height()).nMinimumChainWork))
        return true;
    if (chainActive.Tip()->GetBlockTime() < (GetTime() - nMaxTipAge))
        return true;
    latchToFalse.store(true, std::memory_order_relaxed);
    return false;
}

CBlockIndex *pindexBestForkTip = NULL, *pindexBestForkBase = NULL;

static void AlertNotify(const std::string& strMessage)
{
    uiInterface.NotifyAlertChanged();
    std::string strCmd = GetArg("-alertnotify", "");
    if (strCmd.empty()) return;

    // Alert text should be plain ascii coming from a trusted source, but to
    // be safe we first strip anything not in safeChars, then add single quotes around
    // the whole string before passing it to the shell:
    std::string singleQuote("'");
    std::string safeStatus = SanitizeString(strMessage);
    safeStatus = singleQuote + safeStatus + singleQuote;
    boost::replace_all(strCmd, "%s", safeStatus);

    boost::thread t(runCommand, strCmd); // thread runs free
}

void CheckForkWarningConditions()
{
    AssertLockHeld(cs_main);
    // Before we get past initial download, we cannot reliably alert about forks
    // (we assume we don't get stuck on a fork before finishing our initial sync)
    if (IsInitialBlockDownload())
        return;

    // If our best fork is no longer within 360 blocks (+/- 6 hours if no one mines it)
    // of our head, drop it
    if (pindexBestForkTip && chainActive.Height() - pindexBestForkTip->nHeight >= 360)
        pindexBestForkTip = NULL;

    if (pindexBestForkTip || (pindexBestInvalid && pindexBestInvalid->nChainWork > chainActive.Tip()->nChainWork + (GetBlockProof(*chainActive.Tip()) * 30))) {
        if (!GetfLargeWorkForkFound() && pindexBestForkBase) {
            std::string warning = std::string("'Warning: Large-work fork detected, forking after block ") +
                                  pindexBestForkBase->phashBlock->ToString() + std::string("'");
            AlertNotify(warning);
        }
        if (pindexBestForkTip && pindexBestForkBase) {
            LogPrintf("%s: Warning: Large valid fork found\n  forking the chain at height %d (%s)\n  lasting to height %d (%s).\nChain state database corruption likely.\n", __func__,
                pindexBestForkBase->nHeight, pindexBestForkBase->phashBlock->ToString(),
                pindexBestForkTip->nHeight, pindexBestForkTip->phashBlock->ToString());
            SetfLargeWorkForkFound(true);
        } else {
            LogPrintf("%s: Warning: Found invalid chain at least ~6 blocks longer than our best chain.\nChain state database corruption likely.\n", __func__);
            SetfLargeWorkInvalidChainFound(true);
        }
    } else {
        SetfLargeWorkForkFound(false);
        SetfLargeWorkInvalidChainFound(false);
    }
}

void CheckForkWarningConditionsOnNewFork(CBlockIndex* pindexNewForkTip)
{
    AssertLockHeld(cs_main);
    // If we are on a fork that is sufficiently large, set a warning flag
    CBlockIndex* pfork = pindexNewForkTip;
    CBlockIndex* plonger = chainActive.Tip();
    while (pfork && pfork != plonger) {
        while (plonger && plonger->nHeight > pfork->nHeight)
            plonger = plonger->pprev;
        if (pfork == plonger)
            break;
        pfork = pfork->pprev;
    }

    // We define a condition where we should warn the user about as a fork of at least 7 blocks
    // with a tip within 72 blocks (+/- 12 hours if no one mines it) of ours
    // We use 7 blocks rather arbitrarily as it represents just under 10% of sustained network
    // hash rate operating on the fork.
    // or a chain that is entirely longer than ours and invalid (note that this should be detected by both)
    // We define it this way because it allows us to only store the highest fork tip (+ base) which meets
    // the 7-block condition and from this always have the most-likely-to-cause-warning fork
    if (pfork && (!pindexBestForkTip || (pindexBestForkTip && pindexNewForkTip->nHeight > pindexBestForkTip->nHeight)) &&
        pindexNewForkTip->nChainWork - pfork->nChainWork > (GetBlockProof(*pfork) * 7) &&
        chainActive.Height() - pindexNewForkTip->nHeight < 72) {
        pindexBestForkTip = pindexNewForkTip;
        pindexBestForkBase = pfork;
    }

    CheckForkWarningConditions();
}

void static InvalidChainFound(CBlockIndex* pindexNew)
{
    if (!pindexBestInvalid || pindexNew->nChainWork > pindexBestInvalid->nChainWork)
        pindexBestInvalid = pindexNew;

    LogPrintf("%s: invalid block=%s  height=%d  log2_work=%.8g  date=%s\n", __func__,
        pindexNew->GetBlockHash().ToString(), pindexNew->nHeight,
        log(pindexNew->nChainWork.getdouble()) / log(2.0), DateTimeStrFormat("%Y-%m-%d %H:%M:%S", pindexNew->GetBlockTime()));
    CBlockIndex* tip = chainActive.Tip();
    assert(tip);
    LogPrintf("%s:  current best=%s  height=%d  log2_work=%.8g  date=%s\n", __func__,
        tip->GetBlockHash().ToString(), chainActive.Height(), log(tip->nChainWork.getdouble()) / log(2.0),
        DateTimeStrFormat("%Y-%m-%d %H:%M:%S", tip->GetBlockTime()));
    CheckForkWarningConditions();
}

void static InvalidBlockFound(CBlockIndex* pindex, const CValidationState& state)
{
    if (!state.CorruptionPossible()) {
        pindex->nStatus |= BLOCK_FAILED_VALID;
        gFailedBlocks.insert(pindex);
        setDirtyBlockIndex.insert(pindex);
        setBlockIndexCandidates.erase(pindex);
        InvalidChainFound(pindex);
    }
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, CTxUndo& txundo, int nHeight)
{
    // mark inputs spent
    if (!tx.IsCoinBase()) {
        txundo.vprevout.reserve(tx.vin.size());
        BOOST_FOREACH (const CTxIn& txin, tx.vin) {
            CCoinsModifier coins = inputs.ModifyCoins(txin.prevout.hash);
            unsigned nPos = txin.prevout.n;

            if (nPos >= coins->vout.size() || coins->vout[nPos].IsNull())
                assert(false);
            // mark an outpoint spent, and construct undo information
            txundo.vprevout.push_back(CTxInUndo(coins->vout[nPos]));
            coins->Spend(nPos);
            if (coins->vout.size() == 0) {
                CTxInUndo& undo = txundo.vprevout.back();
                undo.nHeight = coins->nHeight;
                undo.fCoinBase = coins->fCoinBase;
                undo.nVersion = coins->nVersion;
            }
        }
    }
    // add outputs
    inputs.ModifyNewCoins(tx.GetHash(), tx.IsCoinBase())->FromTx(tx, nHeight);
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, int nHeight)
{
    CTxUndo txundo;
    UpdateCoins(tx, inputs, txundo, nHeight);
}

bool CScriptCheck::operator()()
{
    const CScript& scriptSig = ptxTo->vin[nIn].scriptSig;
    const CScriptWitness* witness = &ptxTo->vin[nIn].scriptWitness;
    if (!VerifyScript(scriptSig, scriptPubKey, witness, nFlags, CachingTransactionSignatureChecker(ptxTo, nIn, amount, cacheStore, *txdata), &error)) {
        return false;
    }
    return true;
}

int GetSpendHeight(const CCoinsViewCache& inputs)
{
    LOCK(cs_main);
    CBlockIndex* pindexPrev = mapBlockIndex.find(inputs.GetBestBlock())->second;
    return pindexPrev->nHeight + 1;
}

namespace Consensus
{
bool CheckTxInputs(const CChainParams& params, const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight)
{
    // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
    // for an attacker to attempt to split the network.
    if (!inputs.HaveInputs(tx))
        return state.Invalid(false, 0, "", "Inputs unavailable");

    CAmount nValueIn = 0;
    CAmount nFees = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const COutPoint& prevout = tx.vin[i].prevout;
        const CCoins* coins = inputs.AccessCoins(prevout.hash);
        assert(coins);

        // If prev is coinbase, check that it's matured
        if (coins->IsCoinBase()) {
            // Soqucoin: Switch maturity at depth based on consensus params
            int nCoinbaseMaturity = params.GetConsensus(coins->nHeight).nCoinbaseMaturity;
            if (nSpendHeight - coins->nHeight < nCoinbaseMaturity)
                return state.Invalid(false,
                    REJECT_INVALID, "bad-txns-premature-spend-of-coinbase",
                    strprintf("tried to spend coinbase at depth %d", nSpendHeight - coins->nHeight));
        }

        // Check for negative or overflow input values
        nValueIn += coins->vout[prevout.n].nValue;
        if (!MoneyRange(coins->vout[prevout.n].nValue) || !MoneyRange(nValueIn))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");
    }

    // SOQ-I009: an authority marker buys an exemption from value conservation,
    // and the operation it exempts is only ever VERIFIED (M-of-N ML-DSA + op
    // binding) inside ConnectBlock's `flags & SCRIPT_VERIFY_*` blocks. Granting
    // the exemption while the verifier is dormant is the asymmetry that made a
    // forged marker profitable, so the exemption is now gated on the same
    // deployment state the verifier is. Test nets run both deployments active
    // from height 0, so this changes nothing on any existing chain.
    const Consensus::Params& spendCons = params.GetConsensus(nSpendHeight);
    // "No verifier, no exemption." The authority globals are the same predicate
    // ConnectBlock's default-denies use (bad-*-authority-unavailable): they are
    // populated from chainparams at the first ConnectBlock that sets the
    // deployment flag, i.e. before any transaction in that block is checked, so
    // this is deterministic within the connect path. On mainnet, where no
    // authority keyset is configured at all, they are never initialised and no
    // marker can ever buy the ex-nihilo exemption.
    const bool fUSDSOQActiveHere = DeploymentActiveAtHeight(
        nSpendHeight, spendCons, Consensus::DEPLOYMENT_USDSOQ) &&
        g_usdsoq_authority.IsInitialized();
    const bool fBTCSOQActiveHere = DeploymentActiveAtHeight(
        nSpendHeight, spendCons, Consensus::DEPLOYMENT_BTCSOQ) &&
        g_btcsoq_authority.IsInitialized();

    // SOQ-AUD2-002: For authority transactions (witness v5 / OP_5 output),
    // the USDSOQ outputs are minted ex nihilo — they must NOT count in the
    // input-output value balance. Only SOQ outputs (fee change + marker) count.
    CAmount nValueOut = tx.GetValueOut();
    bool isAuthorityTx = false;
    for (const auto& txout : tx.vout) {
        if (fUSDSOQActiveHere &&
            txout.scriptPubKey.size() == 34 &&
            txout.scriptPubKey[0] == OP_5 &&
            txout.scriptPubKey[1] == 32) {
            isAuthorityTx = true;
            break;
        }
    }

    // DL-BTCSOQ-CONSENSUS-NATIVE: BTCSOQ authority txs (witness v9 marker) mint
    // v8 outputs ex nihilo exactly as USDSOQ authority txs mint v7, so the same
    // SOQ-only value-balance recompute applies. The exemptions are PER-ASSET:
    // a v9 marker does NOT exempt a tx from USDSOQ conservation below, and a v5
    // marker does NOT exempt BTCSOQ conservation — each exemption is granted
    // only by that asset's own unforgeable marker, whose operation is then
    // fully verified (M-of-N ML-DSA + op binding) in ConnectBlock. A tx cannot
    // carry both markers (bad-txns-dual-authority-marker in CheckTransaction).
    bool isBTCSOQAuthorityTx = false;
    for (const auto& txout : tx.vout) {
        if (fBTCSOQActiveHere && IsBTCSOQAuthorityMarker(txout.scriptPubKey)) {
            isBTCSOQAuthorityTx = true;
            break;
        }
    }

    if (isAuthorityTx || isBTCSOQAuthorityTx) {
        // Recompute output value counting only SOQ outputs
        nValueOut = 0;
        for (const auto& txout : tx.vout) {
            if (txout.IsNativeSOQ()) {
                nValueOut += txout.nValue;
            }
        }
        // SOQ-HOTFIX-001: Also recompute input value counting only SOQ inputs.
        // Without this, USDSOQ input values are counted as fee surplus,
        // inflating the miner's coinbase claim and causing:
        //   ERROR: ConnectBlock(): coinbase pays too much
        // This halted block production on all SOQUPOOL nodes for 5.5 hours
        // on June 7, 2026. See fleet_health_report_june7.md.
        nValueIn = 0;
        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            const COutPoint& prevout = tx.vin[i].prevout;
            const CCoins* coins = inputs.AccessCoins(prevout.hash);
            if (coins && coins->IsAvailable(prevout.n)) {
                if (coins->vout[prevout.n].IsNativeSOQ()) {
                    nValueIn += coins->vout[prevout.n].nValue;
                }
            }
        }
    }

    if (nValueIn < nValueOut)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-in-belowout", false,
            strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(nValueOut)));

    // Tally transaction fees
    // ⚠️ THE TWO REJECTS BELOW ARE UNREACHABLE BY CONSTRUCTION. Documented
    // rather than removed, and deliberately NOT given a synthetic trigger.
    //
    // bad-txns-fee-negative cannot fire: the `nValueIn < nValueOut` check
    // immediately above already returned bad-txns-in-belowout, so nTxFee is
    // non-negative here by definition. bad-txns-fee-outofrange cannot fire
    // either: every input passed MoneyRange as it was summed, and nValueOut is
    // MoneyRange-checked by CheckTransaction, so the difference is in range.
    //
    // Both are inherited Bitcoin Core belt-and-braces and both are correct as
    // defence against a future refactor that reorders those checks. Confirmed
    // dead by the Sweep C reachability pass, which found them the ONLY dead
    // rejects on the money path apart from the four key-image ones (bead p4wv).
    //
    // ⛔ Do not "fix coverage" by contriving an input that reaches them. The
    // only way to reach either is to first break the check above, at which
    // point the test would be pinning the broken state. An unreachable rule
    // that is LABELLED is safe; an unreachable rule mistaken for coverage is
    // how e2n, 0r2 and don9 stayed dead for months.
    CAmount nTxFee = nValueIn - nValueOut;
    if (nTxFee < 0)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-negative");
    nFees += nTxFee;
    if (!MoneyRange(nFees))
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-outofrange");

    // SOQ-ARCH-002: Per-asset conservation enforcement.
    // For non-authority transactions, USDSOQ must be strictly conserved:
    //   USDSOQ_in == USDSOQ_out  (no surplus, no deficit)
    // SOQ surplus (SOQ_in - SOQ_out) is the miner fee.
    // This prevents cross-asset conversion while allowing SOQ fee payment
    // alongside USDSOQ transfers.
    // On mainnet (USDSOQ NEVER_ACTIVE): no USDSOQ UTXOs exist, so
    // nUSDSOQIn == nUSDSOQOut == 0, and this check always passes.
    if (!isAuthorityTx) {
        // IsAnyUSDSOQ(), i.e. BOTH modes: transparent v7 and confidential v10.
        //
        // ⛔ WITH THE v7-ONLY PREDICATE, CONFIDENTIAL USDSOQ COULD BE CONJURED FROM
        // ORDINARY SOQ. A v10 output was invisible to this rule (nUSDSOQOut stayed 0,
        // so 0 == 0 conserved) AND invisible to the per-asset fee filters, which key
        // on IsNativeSOQ() and correctly exclude it. The two blind spots compose: the
        // tx minted USDSOQ from nothing and donated the same value to nFees for the
        // miner to claim. This is exactly the hole Phase 3 closed for v7 (see
        // usdsoq_v7_conservation_harness_tests::v7_minted_from_soq_is_rejected); it
        // was simply never extended when v10 was allocated.
        //
        // Like the v7 and v8 rules, this is STRUCTURAL and deliberately NOT
        // deployment-gated. The v10 SHAPE is creatable (additive-asset genesis
        // door) but its VALUE is reserved from genesis: no v10 input can exist,
        // so any tx creating a v10 output with nValue > 0 fails out > in = 0, and
        // only zero-value v10 outputs can exist before activation. The activation
        // release mandates nValue == 0 on asset outputs, so this rule stays
        // satisfied trivially and never has to be relaxed.
        //
        // ⚠️ REVISIT WHEN VALUE MOVES INTO THE COMMITMENT (bead sh2u). This sums
        // nValue, which is still a plaintext CAmount on a confidential output. The
        // day nValue becomes a commitment, a plaintext sum stops being meaningful
        // and this rule must be replaced by a commitment-balance check, not merely
        // widened again.
        CAmount nUSDSOQIn = 0;
        CAmount nUSDSOQOut = 0;
        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            const COutPoint& prevout = tx.vin[i].prevout;
            const CCoins* coins = inputs.AccessCoins(prevout.hash);
            assert(coins);
            if (coins->vout[prevout.n].IsAnyUSDSOQ()) {
                nUSDSOQIn += coins->vout[prevout.n].nValue;
            }
        }
        for (const auto& txout : tx.vout) {
            if (txout.IsAnyUSDSOQ()) {
                nUSDSOQOut += txout.nValue;
            }
        }
        if (nUSDSOQIn != nUSDSOQOut) {
            return state.DoS(100, false, REJECT_INVALID,
                "bad-txns-usdsoq-not-conserved", false,
                strprintf("USDSOQ in (%s) != USDSOQ out (%s)",
                    FormatMoney(nUSDSOQIn), FormatMoney(nUSDSOQOut)));
        }

        // Input-type isolation (Option B — beads 0r2/e2n). A transparent USDSOQ
        // transfer (any v7 output) may spend ONLY:
        //   * v7 USDSOQ inputs (the asset being moved), and
        //   * transparent native-SOQ (v1) inputs (to pay the SOQ fee).
        // Conservation (above) already guarantees USDSOQ cannot be forged or
        // converted; this additionally forbids exotic inputs (e.g. confidential
        // v4) being mixed into a transparent USDSOQ transfer, keeping such
        // transfers wholly transparent.
        //
        // WHY HERE (not ConnectBlock): CheckTxInputs runs with inputs still
        // available in BOTH validation paths — ConnectBlock's first pass
        // (via CheckInputs, before UpdateCoins spends them) AND mempool accept
        // (ATMP → CheckInputs). Enforcing from this single chokepoint makes the
        // rule LIVE in both, so mempool policy and consensus can never diverge.
        // The prior ConnectBlock-only rule lived in the SECOND pass, after
        // UpdateCoins had already spent every input, so its
        // `!coins->IsAvailable() → continue` guard made it DEAD CODE — it never
        // rejected anything, which is why a SOQ-fee transfer already connected
        // and why there was never an actual mempool-poison from it (bead 0r2).
        // Authority (mint/burn/freeze/rotate) txs are exempt (outer guard).
        if (nUSDSOQOut > 0) {
            for (unsigned int i = 0; i < tx.vin.size(); i++) {
                const COutPoint& prevout = tx.vin[i].prevout;
                const CTxOut& prevOut = inputs.AccessCoins(prevout.hash)->vout[prevout.n];
                // IsAnyUSDSOQ() must match the conservation predicate above. If this
                // stayed v7-only while conservation counted both modes, a legitimate
                // v10 transfer would conserve and then be rejected here for spending
                // its own asset.
                if (!prevOut.IsAnyUSDSOQ() &&
                    !(prevOut.IsNativeSOQ() && prevOut.IsTransparent())) {
                    return state.DoS(100, false, REJECT_INVALID,
                        "bad-txns-usdsoq-input-mismatch", false,
                        strprintf("USDSOQ transfer input %s:%u is neither a USDSOQ "
                            "input (v7 or v10) nor a transparent SOQ fee input",
                            prevout.hash.ToString(), prevout.n));
                }
            }
        }
    }

    // DL-BTCSOQ-CONSENSUS-NATIVE: per-asset conservation for BTCSOQ, mirroring
    // the USDSOQ rule above. For non-authority (no v9 marker) transactions:
    //   BTCSOQ_in == BTCSOQ_out  (no surplus, no deficit)
    // Enforced from this single chokepoint in BOTH the connect path
    // (ConnectBlock → CheckInputs) and mempool accept (ATMP → CheckInputs),
    // so policy and consensus can never diverge (Option B pattern).
    // DEPLOYMENT POSTURE: like the USDSOQ rule above, this is structural and
    // NOT deployment-gated. On mainnet (BTCSOQ NOT_SCHEDULED) no v8 UTXOs
    // carrying value exist, so any tx CREATING a v8 output with nValue > 0
    // fails this rule (out > in = 0) — i.e. the v8 VALUE is RESERVED from
    // genesis, exactly the USDSOQ v7 posture. Fleet upgrades are coordinated
    // flag-day releases, so there is no mixed-version mining window.
    if (!isBTCSOQAuthorityTx) {
        CAmount nBTCSOQIn = 0;
        CAmount nBTCSOQOut = 0;
        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            const COutPoint& prevout = tx.vin[i].prevout;
            const CCoins* coins = inputs.AccessCoins(prevout.hash);
            assert(coins);
            if (coins->vout[prevout.n].IsBTCSOQ()) {
                nBTCSOQIn += coins->vout[prevout.n].nValue;
            }
        }
        for (const auto& txout : tx.vout) {
            if (txout.IsBTCSOQ()) {
                nBTCSOQOut += txout.nValue;
            }
        }
        if (nBTCSOQIn != nBTCSOQOut) {
            return state.DoS(100, false, REJECT_INVALID,
                "bad-txns-btcsoq-not-conserved", false,
                strprintf("BTCSOQ in (%s) != BTCSOQ out (%s)",
                    FormatMoney(nBTCSOQIn), FormatMoney(nBTCSOQOut)));
        }

        // Input-type isolation, mirroring the USDSOQ Option B rule: a BTCSOQ
        // transfer (any v8 output) may spend ONLY v8 BTCSOQ inputs (the asset
        // being moved) and transparent native-SOQ inputs (the fee). This keeps
        // v7/v4 and other exotic input types out of BTCSOQ transfers entirely.
        if (nBTCSOQOut > 0) {
            for (unsigned int i = 0; i < tx.vin.size(); i++) {
                const COutPoint& prevout = tx.vin[i].prevout;
                const CTxOut& prevOut = inputs.AccessCoins(prevout.hash)->vout[prevout.n];
                if (!prevOut.IsBTCSOQ() &&
                    !(prevOut.IsNativeSOQ() && prevOut.IsTransparent())) {
                    return state.DoS(100, false, REJECT_INVALID,
                        "bad-txns-btcsoq-input-mismatch", false,
                        strprintf("BTCSOQ transfer input %s:%u is neither a v8 "
                            "BTCSOQ input nor a transparent SOQ fee input",
                            prevout.hash.ToString(), prevout.n));
                }
            }
        }
    }

    return true;
}
} // namespace Consensus

bool CheckInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, bool fScriptChecks, unsigned int flags, bool cacheStore, PrecomputedTransactionData& txdata, std::vector<CScriptCheck>* pvChecks)
{
    if (!tx.IsCoinBase()) {
        if (!Consensus::CheckTxInputs(Params(), tx, state, inputs, GetSpendHeight(inputs)))
            return false;

        if (pvChecks)
            pvChecks->reserve(tx.vin.size());

        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive signature checks.
        // Helps prevent CPU exhaustion attacks.

        // Skip script verification when connecting blocks under the
        // assumedvalid block. Assuming the assumedvalid block is valid this
        // is safe because block merkle hashes are still computed and checked,
        // Of course, if an assumed valid block is invalid due to false scriptSigs
        // this optimization would allow an invalid chain to be accepted.
        if (fScriptChecks) {
            // SOQ-I005: If this TX has ANY USDSOQ authority witness input,
            // skip standard script verification for the ENTIRE TX.
            // Authority TXs have their own M-of-N Dilithium consensus
            // verification in ConnectBlock (stronger than per-input checks).
            //
            // Authority witness layout (appended to fee input's standard witness):
            //   [0] payout_sig+hashtype  [1] payout_pk  [2] auth_tag (0x55)
            //   [3] auth_payload  [4..N-1] auth_sigs  [N] authority_set
            //
            // H1 FIX (June 3, 2026): Also require OP_5 output to prevent
            // non-authority TXs from forging witness layout to bypass scripts.
            bool isAuthorityTx = false;

            // First pass: check for OP_5 authority output (unforgeable)
            bool hasAuthorityOutput = false;
            for (const auto& txout : tx.vout) {
                if (txout.scriptPubKey.size() == 34 &&
                    txout.scriptPubKey[0] == OP_5 &&
                    txout.scriptPubKey[1] == 32) {
                    hasAuthorityOutput = true;
                    break;
                }
            }

            // Second pass: only check witness if OP_5 output exists
            if (hasAuthorityOutput) {
                for (unsigned int i = 0; i < tx.vin.size(); i++) {
                    const auto& wit = tx.vin[i].scriptWitness;
                    if (!wit.IsNull() && wit.stack.size() >= 6 &&
                        wit.stack[2].size() == 1 &&
                        wit.stack[2][0] == 0x55) {
                        for (size_t j = 4; j < wit.stack.size() - 1; ++j) {
                            if (wit.stack[j].size() == 2420) {
                                isAuthorityTx = true;
                                break;
                            }
                        }
                        if (isAuthorityTx) break;
                    }
                }
            }

            // DL-BTCSOQ-CONSENSUS-NATIVE: identical skip for BTCSOQ authority
            // txs. H1 pattern preserved: the unforgeable v9 marker OUTPUT is
            // required before the witness layout is even examined, so a
            // non-authority tx cannot forge the witness shape to bypass
            // standard script verification. The M-of-N ML-DSA consensus
            // verification for these txs runs in ConnectBlock's BTCSOQ block
            // (and is mirrored at mempool accept).
            bool isBTCSOQAuthorityTx = false;
            bool hasBTCSOQAuthorityOutput = false;
            for (const auto& txout : tx.vout) {
                if (IsBTCSOQAuthorityMarker(txout.scriptPubKey)) {
                    hasBTCSOQAuthorityOutput = true;
                    break;
                }
            }
            if (hasBTCSOQAuthorityOutput) {
                for (unsigned int i = 0; i < tx.vin.size(); i++) {
                    const auto& wit = tx.vin[i].scriptWitness;
                    if (!wit.IsNull() && wit.stack.size() >= 6 &&
                        wit.stack[2].size() == 1 &&
                        wit.stack[2][0] >= BTCSOQ_OP_MINT &&
                        wit.stack[2][0] <= BTCSOQ_OP_FREEZE) {
                        for (size_t j = 4; j < wit.stack.size() - 1; ++j) {
                            if (wit.stack[j].size() == 2420) {
                                isBTCSOQAuthorityTx = true;
                                break;
                            }
                        }
                        if (isBTCSOQAuthorityTx) break;
                    }
                }
            }

            // =============================================================
            // SOQ-I009: the skip must never outlive the thing that replaces
            // it. Both flags above are pure SHAPE tests over attacker-chosen
            // data (a marker output plus a witness layout), while the M-of-N
            // ML-DSA verification that justifies skipping per-input scripts
            // runs in ConnectBlock behind `flags & SCRIPT_VERIFY_USDSOQ` and
            // `g_usdsoq_authority.IsInitialized()`. With the deployment
            // dormant, or with no authority keyset configured, that verifier
            // never runs — and the skip did, so a forged authority-shaped tx
            // spent every one of its inputs with no signature check at all.
            // That is theft of arbitrary UTXOs, not merely a dormant-asset
            // mint. Proven in src/test/authority_skip_gate_tests.cpp.
            //
            // So: no verifier, no skip. While the deployment is dormant an
            // authority-SHAPED transaction is simply an ordinary transaction
            // and every input runs ordinary script verification — which is
            // exactly what a node that knows nothing about the asset would
            // do, so the shape gains nothing and loses nothing. This was
            // first written as an outright rejection (bad-*-authority-not-
            // active); that rejection was itself hard-fork shaped, because
            // the activation release ACCEPTS the very shape it rejected
            // (additive-asset genesis door, 2026-09). Falling through to
            // ordinary verification is strictly more permissive than
            // rejecting, so the activation release's M-of-N requirement is a
            // pure tightening on top of it. With the deployment ACTIVE but no
            // keyset configured, rejecting stays correct: that state never
            // exists on a chain the genesis binary validates (mainnet ships
            // NOT_SCHEDULED), and a release that schedules the height ships
            // the keyset with it.
            // =============================================================
            if (isAuthorityTx) {
                if (!(flags & SCRIPT_VERIFY_USDSOQ)) {
                    isAuthorityTx = false;   // dormant: verify every input like any other tx
                } else if (!g_usdsoq_authority.IsInitialized()) {
                    return state.DoS(100, false, REJECT_INVALID,
                        "bad-usdsoq-authority-unavailable", false,
                        "USDSOQ authority TX rejected: authority key set not initialized");
                }
            }
            if (isBTCSOQAuthorityTx) {
                if (!(flags & SCRIPT_VERIFY_BTCSOQ)) {
                    isBTCSOQAuthorityTx = false;   // dormant: verify every input like any other tx
                } else if (!g_btcsoq_authority.IsInitialized()) {
                    return state.DoS(100, false, REJECT_INVALID,
                        "bad-btcsoq-authority-unavailable", false,
                        "BTCSOQ authority TX rejected: authority key set not initialized");
                }
            }

            if (!isAuthorityTx && !isBTCSOQAuthorityTx) {
                for (unsigned int i = 0; i < tx.vin.size(); i++) {
                    const COutPoint& prevout = tx.vin[i].prevout;
                    const CCoins* coins = inputs.AccessCoins(prevout.hash);
                    assert(coins);

                    // Verify signature
                    CScriptCheck check(*coins, tx, i, flags, cacheStore, &txdata);
                    if (pvChecks) {
                        pvChecks->push_back(CScriptCheck());
                        check.swap(pvChecks->back());
                    } else if (!check()) {
                        if (flags & STANDARD_NOT_MANDATORY_VERIFY_FLAGS) {
                            // Check whether the failure was caused by a
                            // non-mandatory script verification check, such as
                            // non-standard DER encodings or non-null dummy
                            // arguments; if so, don't trigger DoS protection to
                            // avoid splitting the network between upgraded and
                            // non-upgraded nodes.
                            CScriptCheck check2(*coins, tx, i,
                                flags & ~STANDARD_NOT_MANDATORY_VERIFY_FLAGS, cacheStore, &txdata);
                            if (check2())
                                return state.Invalid(false, REJECT_NONSTANDARD, strprintf("non-mandatory-script-verify-flag (%s)", ScriptErrorString(check.GetScriptError())));
                        }
                        // Failures of other flags indicate a transaction that is
                        // invalid in new blocks, e.g. a invalid P2SH. We DoS ban
                        // such nodes as they are not following the protocol. That
                        // said during an upgrade careful thought should be taken
                        // as to the correct behavior - we may want to continue
                        // peering with non-upgraded nodes even after soft-fork
                        // super-majority signaling has occurred.
                        return state.DoS(100, false, REJECT_INVALID, strprintf("mandatory-script-verify-flag-failed (%s)", ScriptErrorString(check.GetScriptError())));
                    }
                }
            }
        }
    }

    return true;
}

bool UndoReadFromDisk(CBlockUndo& blockundo, const CDiskBlockPos& pos, const uint256& hashBlock)
{
    // Open history file to read
    CAutoFile filein(OpenUndoFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("%s: OpenUndoFile failed", __func__);

    // Read block
    uint256 hashChecksum;
    try {
        filein >> blockundo;
        filein >> hashChecksum;
    } catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }

    // Verify checksum
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << hashBlock;
    hasher << blockundo;
    if (hashChecksum != hasher.GetHash())
        return error("%s: Checksum mismatch", __func__);

    return true;
}

namespace
{

bool UndoWriteToDisk(const CBlockUndo& blockundo, CDiskBlockPos& pos, const uint256& hashBlock, const CMessageHeader::MessageStartChars& messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenUndoFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s: OpenUndoFile failed", __func__);

    // Write index header
    unsigned int nSize = GetSerializeSize(fileout, blockundo);
    fileout << FLATDATA(messageStart) << nSize;

    // Write undo data
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("%s: ftell failed", __func__);
    pos.nPos = (unsigned int)fileOutPos;
    fileout << blockundo;

    // calculate & write checksum
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << hashBlock;
    hasher << blockundo;
    fileout << hasher.GetHash();

    return true;
}

/** Abort with a message */
bool AbortNode(const std::string& strMessage, const std::string& userMessage = "")
{
    SetMiscWarning(strMessage);
    LogPrintf("*** %s\n", strMessage);
    uiInterface.ThreadSafeMessageBox(
        userMessage.empty() ? _("Error: A fatal internal error occurred, see debug.log for details") : userMessage,
        "", CClientUIInterface::MSG_ERROR);
    StartShutdown();
    return false;
}

bool AbortNode(CValidationState& state, const std::string& strMessage, const std::string& userMessage = "")
{
    AbortNode(strMessage, userMessage);
    return state.Error(strMessage);
}

} // namespace

/**
 * Apply the undo operation of a CTxInUndo to the given chain state.
 * @param undo The undo object.
 * @param view The coins view to which to apply the changes.
 * @param out The out point that corresponds to the tx input.
 * @return True on success.
 */
bool ApplyTxInUndo(const CTxInUndo& undo, CCoinsViewCache& view, const COutPoint& out)
{
    bool fClean = true;

    CCoinsModifier coins = view.ModifyCoins(out.hash);

    // SECURITY NOTE: Defensive null guard (SOQ-INFRA-005)
    // The CCoinsModifier wraps a boost::unordered_map iterator. Under high-frequency
    // block processing, map rehashes can invalidate iterators, causing operator->()
    // to return a dangling pointer. This guard prevents SEGFAULT by detecting invalid
    // state and aborting the undo operation cleanly instead of crashing.
    if (coins.operator->() == nullptr) {
        error("%s: coins modifier returned null for %s — possible UTXO cache corruption, skipping undo", __func__, out.hash.ToString());
        return false;
    }

    if (undo.nHeight != 0) {
        // undo data contains height: this is the last output of the prevout tx being spent
        if (!coins->IsPruned())
            fClean = fClean && error("%s: undo data overwriting existing transaction", __func__);
        coins->Clear();
        coins->fCoinBase = undo.fCoinBase;
        coins->nHeight = undo.nHeight;
        coins->nVersion = undo.nVersion;
    } else {
        if (coins->IsPruned())
            fClean = fClean && error("%s: undo data adding output to missing transaction", __func__);
    }
    if (coins->IsAvailable(out.n))
        fClean = fClean && error("%s: undo data overwriting existing output", __func__);
    if (coins->vout.size() < out.n + 1)
        coins->vout.resize(out.n + 1);
    coins->vout[out.n] = undo.txout;

    return fClean;
}


bool DisconnectBlock(const CBlock& block, CValidationState& state, const CBlockIndex* pindex, CCoinsViewCache& view, bool* pfClean)
{
    // PAT witness pruning (doc/PAT_WITNESS_PRUNING.md §6): eligibility requires
    // depth strictly beyond nMaxReorgDepth, and consensus refuses deeper
    // reorganizations, so a disconnect request for a witness-pruned block means
    // the finality rule itself has been violated. Halt loudly rather than
    // improvise on a chain state the pruning safety argument no longer covers.
    if (pindex->nStatus & BLOCK_WITNESS_PRUNED) {
        return AbortNode(state,
            "witness-pruned-block-disconnect: a block beyond the finality horizon "
            "was asked to disconnect; the node cannot validate a reorganization "
            "this deep and must not guess");
    }

    assert(pindex->GetBlockHash() == view.GetBestBlock());

    if (pfClean)
        *pfClean = false;

    bool fClean = true;

    // SOQ-I014: is this a REAL disconnect, or a verification scratch pass?
    //
    // VerifyDB runs at every startup (DEFAULT_CHECKLEVEL=3, DEFAULT_CHECKBLOCKS=6)
    // and calls us on the last N blocks against a SCRATCH CCoinsViewCache,
    // passing pfClean. Only nCheckLevel >= 4 reconnects, so at the default those
    // blocks are never re-applied. The coins changes go to the scratch view and
    // are thrown away — but the asset reversals below mutate process globals and
    // write straight to pcoinsdbview, neither of which is that scratch view. An
    // ordinary restart therefore rewound USDSOQ/BTCSOQ supply, the authority
    // outpoint, the freeze registry and the minted-deposit set by up to six
    // blocks, persistently, and never put them back.
    //
    // Every consequence was silent: supply drifting below the chain, the
    // authority tracker rewinding into the SOQ-I012 wedge, freezes inside the
    // window being ERASED (a compliance control lifted by restarting the node),
    // and BTCSOQ minted deposits being erased so double-mint protection lapsed.
    //
    // ⚠️ This was seen once and mis-diagnosed. init.cpp SOQ-HOTFIX-002 records
    // the June 15 2026 Broadcast VPS crash loop — 360 restarts in ~3 hours —
    // caused by UndoMint failing against a still-zeroed counter during exactly
    // this pass. The fix loaded the globals BEFORE VerifyDB so UndoMint would
    // succeed. It did. The crash stopped and the rewind did not: the only thing
    // making the corruption visible was removed. When a crash is "fixed" by
    // making the failing operation succeed, check whether it should have been
    // running at all.
    //
    // pfClean already separates the callers: DisconnectTip passes nullptr,
    // VerifyDB passes an address. A verification pass must touch nothing outside
    // its scratch view.
    const bool fRealDisconnect = (pfClean == nullptr);

    // Asset-state undo below mirrors ConnectBlock, whose asset blocks run only
    // when the deployment is active at this height (flags derived from
    // DeploymentActiveAtHeight). Mirror that gate here: while a deployment is
    // dormant, a block can still CONTAIN asset-shaped outputs (they are plain
    // anyone-can-spend SOQ since the additive-asset genesis door), and a reorg
    // over such a block must not reverse supply, restore an authority outpoint
    // or write a freeze-registry entry that ConnectBlock never applied.
    const Consensus::Params& disconnectParams = Params().GetConsensus(pindex->nHeight);
    const bool fUSDSOQActiveAtHeight = Consensus::DeploymentActiveAtHeight(
        pindex->nHeight, disconnectParams, Consensus::DEPLOYMENT_USDSOQ);
    const bool fBTCSOQActiveAtHeight = Consensus::DeploymentActiveAtHeight(
        pindex->nHeight, disconnectParams, Consensus::DEPLOYMENT_BTCSOQ);
    const bool fSoquObscuraActiveAtHeight = Consensus::DeploymentActiveAtHeight(
        pindex->nHeight, disconnectParams, Consensus::DEPLOYMENT_SOQUOBSCURA);


    CBlockUndo blockUndo;
    CDiskBlockPos pos = pindex->GetUndoPos();
    if (pos.IsNull())
        return error("DisconnectBlock(): no undo data available");
    if (!UndoReadFromDisk(blockUndo, pos, pindex->pprev->GetBlockHash()))
        return error("DisconnectBlock(): failure reading undo data");

    if (blockUndo.vtxundo.size() + 1 != block.vtx.size())
        return error("DisconnectBlock(): block and undo data inconsistent");

    // undo transactions in reverse order
    for (int i = block.vtx.size() - 1; i >= 0; i--) {
        const CTransaction& tx = *(block.vtx[i]);
        uint256 hash = tx.GetHash();

        // Check that all outputs are available and match the outputs in the block itself
        // exactly.
        {
            CCoinsModifier outs = view.ModifyCoins(hash);

            // SECURITY NOTE: Defensive null guard (SOQ-INFRA-005)
            if (outs.operator->() == nullptr) {
                error("DisconnectBlock(): coins modifier returned null for %s — possible UTXO cache corruption", hash.ToString());
                fClean = false;
                continue;  // Skip this tx, try to recover
            }

            outs->ClearUnspendable();

            CCoins outsBlock(tx, pindex->nHeight);
            // The CCoins serialization does not serialize negative numbers.
            // No network rules currently depend on the version here, so an inconsistency is harmless
            // but it must be corrected before txout nversion ever influences a network rule.
            if (outsBlock.nVersion < 0)
                outs->nVersion = outsBlock.nVersion;
            if (*outs != outsBlock)
                fClean = fClean && error("DisconnectBlock(): added transaction mismatch? database corrupted");

            // remove outputs
            outs->Clear();
        }

        // restore inputs
        if (i > 0) { // not coinbases
            const CTxUndo& txundo = blockUndo.vtxundo[i - 1];
            if (txundo.vprevout.size() != tx.vin.size())
                return error("DisconnectBlock(): transaction and undo data inconsistent");
            for (unsigned int j = tx.vin.size(); j-- > 0;) {
                const COutPoint& out = tx.vin[j].prevout;
                const CTxInUndo& undo = txundo.vprevout[j];
                if (!ApplyTxInUndo(undo, view, out))
                    fClean = false;
            }
        }
    }

    // =========================================================================
    // SOQ-AUD2-002: USDSOQ supply reversal on reorg
    //
    // C1/C2 FIX (June 3, 2026): The original code was circular — it read
    // LevelDB to "reload" the supply, but LevelDB had already been updated
    // by ConnectBlock. It also never counted reversed burns (inputs).
    //
    // Correct approach: Count the same deltas ConnectBlock counted, then
    // apply the INVERSE operations (UndoMint, UndoBurn) to the in-memory
    // supply counter. Persist the corrected counter to LevelDB.
    //
    // Reversed mint = USDSOQ output being removed → UndoMint(amount)
    // Reversed burn = USDSOQ input being restored → UndoBurn(amount)
    // =========================================================================
    if (fRealDisconnect && fUSDSOQActiveAtHeight) {
        CAmount nUSDSOQReversedMint = 0;
        CAmount nUSDSOQReversedBurn = 0;

        for (int i = block.vtx.size() - 1; i >= 0; i--) {
            const CTransaction& tx = *(block.vtx[i]);
            if (tx.IsCoinBase()) continue;

            // BUG-19: mirror ConnectBlock — only AUTHORITY txs (OP_5 marker) moved the
            // supply counter, so only they are reversed here. A transfer changed nothing,
            // so reversing its outputs/inputs would corrupt the supply on reorg (and
            // desync connect vs disconnect). Detect the authority marker as ConnectBlock does.
            bool isAuthorityTx = false;
            for (const auto& txout : tx.vout) {
                if (txout.scriptPubKey.size() == 34 &&
                    txout.scriptPubKey[0] == OP_5 && txout.scriptPubKey[1] == 32) {
                    isAuthorityTx = true;
                    break;
                }
            }
            if (!isAuthorityTx) continue;

            // Count USDSOQ outputs being removed (reverses mints)
            for (const auto& txout : tx.vout) {
                if (txout.IsUSDSOQ()) {
                    nUSDSOQReversedMint += txout.nValue;
                }
            }

            // Count USDSOQ inputs being restored (reverses burns)
            // After ApplyTxInUndo above, the coins being restored are back
            // in the view. We use blockUndo to get the original output data
            // for each input that was spent.
            if (i > 0) {
                const CTxUndo& txundo = blockUndo.vtxundo[i - 1];
                for (unsigned int j = 0; j < tx.vin.size(); j++) {
                    if (j < txundo.vprevout.size()) {
                        const CTxOut& restoredOut = txundo.vprevout[j].txout;
                        // Must match the CONNECT-side predicate at the supply
                        // accounting loop, which counts IsAnyUSDSOQ() (v7 AND
                        // v10). Both sides use IsAnyUSDSOQ() (the n1vf widening
                        // reached this mirror too; an earlier revision of this
                        // comment claimed otherwise and was stale). If either
                        // side ever changes, THE TWO PREDICATES MUST MOVE
                        // TOGETHER, or a v10 burn would inflate total_burned
                        // permanently on reorg.
                        if (restoredOut.IsAnyUSDSOQ()) {
                            nUSDSOQReversedBurn += restoredOut.nValue;
                        }
                    }
                }
            }
        }

        if (nUSDSOQReversedMint > 0 || nUSDSOQReversedBurn > 0) {
            LogPrintf("USDSOQ: reorg reversal at block %d: reversed_mint=%d reversed_burn=%d\n",
                pindex->nHeight, nUSDSOQReversedMint, nUSDSOQReversedBurn);

            // Apply inverse operations to supply counter
            if (nUSDSOQReversedMint > 0) {
                if (!g_usdsoq_supply.UndoMint(nUSDSOQReversedMint)) {
                    LogPrintf("ERROR: USDSOQ: UndoMint(%d) failed at block %d — supply invariant violation\n",
                        nUSDSOQReversedMint, pindex->nHeight);
                    fClean = false;
                }
            }
            if (nUSDSOQReversedBurn > 0) {
                if (!g_usdsoq_supply.UndoBurn(nUSDSOQReversedBurn)) {
                    LogPrintf("ERROR: USDSOQ: UndoBurn(%d) failed at block %d — supply invariant violation\n",
                        nUSDSOQReversedBurn, pindex->nHeight);
                    fClean = false;
                }
            }

            // Persist corrected supply to LevelDB
            if (pcoinsdbview) {
                if (!pcoinsdbview->WriteUSDSOQSupply(g_usdsoq_supply)) {
                    LogPrintf("ERROR: USDSOQ: Failed to persist supply after reorg at block %d\n",
                        pindex->nHeight);
                }
            }

            LogPrintf("USDSOQ: supply after reorg reversal: total_minted=%d total_burned=%d outstanding=%d\n",
                g_usdsoq_supply.TotalMinted(), g_usdsoq_supply.TotalBurned(),
                g_usdsoq_supply.Outstanding());
        }
    }

    // =========================================================================
    // SOQ-I005: Authority UTXO outpoint reversal on reorg
    // If the disconnected block contained a USDSOQ authority TX, the
    // g_usdsoq_authority_outpoint was advanced. We must revert it.
    // We find the authority TX in this block (OP_5 output), then look for
    // the input that spent the prior authority outpoint. That input's prevout
    // is the outpoint we need to restore.
    // =========================================================================
    if (fRealDisconnect && fUSDSOQActiveAtHeight) {
        for (const auto& ptx : block.vtx) {
            const CTransaction& tx = *ptx;
            if (tx.IsCoinBase()) continue;

            // Check if this TX has an authority output
            bool hasAuthorityOutput = false;
            for (const auto& txout : tx.vout) {
                if (txout.scriptPubKey.size() == 34 &&
                    txout.scriptPubKey[0] == OP_5 &&
                    txout.scriptPubKey[1] == 32) {
                    hasAuthorityOutput = true;
                    break;
                }
            }

            if (hasAuthorityOutput) {
                // This block advanced the authority outpoint.
                // Find the authority input (the input whose prevout was an OP_5 output).
                bool fRevertedToPrevout = false;
                for (unsigned int k = 0; k < tx.vin.size(); ++k) {
                    const CCoins* coins = view.AccessCoins(tx.vin[k].prevout.hash);
                    if (coins && coins->IsAvailable(tx.vin[k].prevout.n)) {
                        const CScript& prevSpk = coins->vout[tx.vin[k].prevout.n].scriptPubKey;
                        if (prevSpk.size() == 34 && prevSpk[0] == OP_5 && prevSpk[1] == 32) {
                            // Revert: the authority outpoint goes back to this input's prevout
                            g_usdsoq_authority_outpoint = tx.vin[k].prevout;

                            if (pcoinsdbview) {
                                pcoinsdbview->WriteUSDSOQAuthorityOutpoint(g_usdsoq_authority_outpoint);
                            }

                            LogPrintf("USDSOQ: reorg reversal — authority outpoint reverted to %s:%u\n",
                                g_usdsoq_authority_outpoint.hash.ToString(),
                                g_usdsoq_authority_outpoint.n);
                            fRevertedToPrevout = true;
                            break;
                        }
                    }
                }
                if (!fRevertedToPrevout) {
                    // SOQ-I012: no v5 marker input was restored, so this was the
                    // BOOTSTRAP authority tx and there is no prior outpoint to go
                    // back to. Disconnecting it must return the tracker to NULL so
                    // the next authority tx takes the bootstrap path again.
                    //
                    // Without this the tracker kept pointing at the disconnected
                    // block's marker — an outpoint that no longer exists on any
                    // chain. ConnectBlock then sees a NON-null tracked outpoint,
                    // finds no input spending it, and rejects the replacement
                    // block with bad-usdsoq-authority-outpoint. The node forks
                    // itself off the network, and because the tracker is written
                    // through to LevelDB a restart does not clear it: recovery is
                    // -reindex.
                    //
                    // Reachable the day USDSOQ activates on mainnet, because the
                    // first authority tx after activation IS a bootstrap and a
                    // one-block reorg is routine. Dormant until then: v5 outputs
                    // cannot be created pre-activation (SOQ-I009).
                    //
                    // ⚠️ This exact gap was found during the BTCSOQ 2D review,
                    // fixed for BTCSOQ, and recorded ONLY in a comment on the
                    // BTCSOQ reversal below saying "the USDSOQ reversal inherits
                    // this gap". A known defect written as prose instead of a bead
                    // or a test stays unfixed. See usdsoq_reorg_tests.
                    g_usdsoq_authority_outpoint = COutPoint();
                    if (pcoinsdbview) {
                        pcoinsdbview->WriteUSDSOQAuthorityOutpoint(g_usdsoq_authority_outpoint);
                    }
                    LogPrintf("USDSOQ: reorg reversal — bootstrap disconnected, "
                              "authority outpoint reverted to null\n");
                }
                break;  // first authority tx spends the pre-block outpoint
            }
        }
    }

    // =========================================================================
    // SOQ-ARCH-001 Phase 2: Key-Image Erasure on Reorg
    // When disconnecting a block, erase all key-images that were recorded
    // during ConnectBlock. This allows confidential outputs to be re-spent
    // on the new chain tip after a reorg.
    //
    // We re-extract key-images from the block's witness data using the same
    // logic as ConnectBlock (last witness stack element for confidential inputs).
    // =========================================================================
    if (fRealDisconnect && pcoinsdbview && fSoquObscuraActiveAtHeight) {
        unsigned int nErasedKeyImages = 0;
        for (const auto& ptx : block.vtx) {
            const CTransaction& tx = *ptx;
            if (tx.IsCoinBase()) continue;

            for (unsigned int j = 0; j < tx.vin.size(); j++) {
                // We need to check if the input was spending a confidential output.
                // Since DisconnectBlock has already restored inputs via ApplyTxInUndo,
                // we can access the restored coins to check nVisibility.
                const CCoins* coins = view.AccessCoins(tx.vin[j].prevout.hash);
                if (!coins || !coins->IsAvailable(tx.vin[j].prevout.n))
                    continue;

                const CTxOut& prevOut = coins->vout[tx.vin[j].prevout.n];
                if (!prevOut.IsConfidential())
                    continue;

                // Extract key-image from witness and erase from DB
                const CScriptWitness& wit = tx.vin[j].scriptWitness;
                if (!wit.IsNull() && !wit.stack.empty() && !wit.stack.back().empty()) {
                    LatticeKeyImageHash kiHash =
                        LatticeKeyImageHash::FromSerializedKeyImage(wit.stack.back());
                    pcoinsdbview->EraseKeyImage(kiHash.hash);
                    nErasedKeyImages++;
                }
            }
        }

        if (nErasedKeyImages > 0) {
            LogPrintf("PRIVACY: reorg at block %d erased %u key-images\n",
                pindex->nHeight, nErasedKeyImages);
        }
    }

    // =========================================================================
    // SOQ-FREEZE: Freeze-Registry Reversal on Reorg
    // When disconnecting a block, reverse all freeze/unfreeze ops that were
    // applied during ConnectBlock. This mirrors the key-image erasure pattern:
    // re-parse the tx's OP_RETURN, then invert the operation.
    //   ConnectBlock FREEZE  → DisconnectBlock ERASE  (undo the freeze)
    //   ConnectBlock UNFREEZE → DisconnectBlock WRITE  (re-freeze)
    //
    // R1 FIX: Mirror ConnectBlock apply's guards.
    // Only reverse freeze ops for txs that are authority txs (have OP_5 <32>
    // output) AND are at/after nUSDSOQAuthorityEnforcementHeight. Without
    // these guards, an attacker can craft a non-authority tx with a FREEZE
    // OP_RETURN, get it into a block that reorgs out, and the reverse would
    // erase a legitimate freeze (bypass) or write a phantom freeze (griefing).
    // Key-image reverse doesn't need this because key-images aren't
    // plaintext-forgeable; freeze ops are.
    // =========================================================================
    if (fRealDisconnect && pcoinsdbview && fUSDSOQActiveAtHeight) {
        const Consensus::Params& disconnectConsensus = Params().GetConsensus(pindex->nHeight);
        unsigned int nReversedFreezeOps = 0;
        for (const auto& ptx : block.vtx) {
            const CTransaction& tx = *ptx;
            if (tx.IsCoinBase()) continue;

            // R1 Guard 1: Height gate — mirror ConnectBlock apply.
            // Pre-enforcement blocks never had freeze ops applied.
            if (pindex->nHeight < disconnectConsensus.nUSDSOQAuthorityEnforcementHeight)
                continue;

            // R1 Guard 2: Authority gate — only authority txs can apply freeze ops.
            // An authority tx has at least one OP_5 <32-byte> output.
            bool isAuthorityTx = false;
            for (const auto& o : tx.vout) {
                if (o.scriptPubKey.size() == 34 &&
                    o.scriptPubKey[0] == OP_5 && o.scriptPubKey[1] == 32) {
                    isAuthorityTx = true;
                    break;
                }
            }
            if (!isAuthorityTx) continue;

            uint8_t freezeOp = 0;
            COutPoint freezeTarget;
            if (ParseUSDSOQFreezeOp(tx, freezeOp, freezeTarget)) {
                if (freezeOp == FREEZE_OP_FREEZE) {
                    // ConnectBlock added this to the frozen set → remove it
                    pcoinsdbview->EraseFrozenOutpoint(freezeTarget);
                } else if (freezeOp == FREEZE_OP_UNFREEZE) {
                    // ConnectBlock removed this from the frozen set → re-add it
                    pcoinsdbview->WriteFrozenOutpoint(freezeTarget);
                }
                nReversedFreezeOps++;
            }
        }

        if (nReversedFreezeOps > 0) {
            LogPrintf("USDSOQ: reorg at block %d reversed %u freeze-registry ops\n",
                pindex->nHeight, nReversedFreezeOps);
        }
    }

    // =========================================================================
    // DL-BTCSOQ-CONSENSUS-NATIVE: BTCSOQ reversal on reorg.
    // Symmetric inverse of ConnectBlock's BTCSOQ enforcement block, mirroring
    // the USDSOQ reversal sections above (C1/C2, BUG-19, R1 patterns):
    //   1. Supply: count the same deltas ConnectBlock counted (v8 outputs of
    //      v9-authority txs = mints, v8 inputs from undo = burns) and apply the
    //      INVERSE ops to the in-memory counter, then persist.
    //   2. Authority outpoint: revert to the prevout the block's first
    //      authority tx spent.
    //   3. Freeze registry: invert applied freeze/unfreeze ops (R1 guards).
    //   4. Minted-deposit set: ERASE the Bitcoin outpoints this block's MINTs
    //      recorded. CONSENSUS-CRITICAL: without this, the same mint tx could
    //      never reconnect on the new chain after a reorg (its deposit would
    //      still be marked minted), forking any node that replayed it.
    // =========================================================================
    if (fRealDisconnect && fBTCSOQActiveAtHeight) {
        CAmount nBTCSOQReversedMint = 0;
        CAmount nBTCSOQReversedBurn = 0;

        for (int i = block.vtx.size() - 1; i >= 0; i--) {
            const CTransaction& tx = *(block.vtx[i]);
            if (tx.IsCoinBase()) continue;

            // Only v9-authority txs moved the supply counter (BUG-19 mirror).
            bool isBTCSOQAuthorityTx = false;
            for (const auto& txout : tx.vout) {
                if (IsBTCSOQAuthorityMarker(txout.scriptPubKey)) {
                    isBTCSOQAuthorityTx = true;
                    break;
                }
            }
            if (!isBTCSOQAuthorityTx) continue;

            for (const auto& txout : tx.vout) {
                if (txout.IsBTCSOQ()) {
                    nBTCSOQReversedMint += txout.nValue;
                }
            }
            if (i > 0) {
                const CTxUndo& txundo = blockUndo.vtxundo[i - 1];
                for (unsigned int j = 0; j < tx.vin.size(); j++) {
                    if (j < txundo.vprevout.size()) {
                        const CTxOut& restoredOut = txundo.vprevout[j].txout;
                        if (restoredOut.IsBTCSOQ()) {
                            nBTCSOQReversedBurn += restoredOut.nValue;
                        }
                    }
                }
            }
        }

        if (nBTCSOQReversedMint > 0 || nBTCSOQReversedBurn > 0) {
            LogPrintf("BTCSOQ: reorg reversal at block %d: reversed_mint=%d reversed_burn=%d\n",
                pindex->nHeight, nBTCSOQReversedMint, nBTCSOQReversedBurn);

            if (nBTCSOQReversedMint > 0) {
                if (!g_btcsoq_supply.UndoMint(nBTCSOQReversedMint)) {
                    LogPrintf("ERROR: BTCSOQ: UndoMint(%d) failed at block %d — supply invariant violation\n",
                        nBTCSOQReversedMint, pindex->nHeight);
                    fClean = false;
                }
            }
            if (nBTCSOQReversedBurn > 0) {
                if (!g_btcsoq_supply.UndoBurn(nBTCSOQReversedBurn)) {
                    LogPrintf("ERROR: BTCSOQ: UndoBurn(%d) failed at block %d — supply invariant violation\n",
                        nBTCSOQReversedBurn, pindex->nHeight);
                    fClean = false;
                }
            }

            if (pcoinsdbview) {
                if (!pcoinsdbview->WriteBTCSOQSupply(g_btcsoq_supply)) {
                    LogPrintf("ERROR: BTCSOQ: Failed to persist supply after reorg at block %d\n",
                        pindex->nHeight);
                }
            }

            LogPrintf("BTCSOQ: supply after reorg reversal: total_minted=%d total_burned=%d outstanding=%d\n",
                g_btcsoq_supply.TotalMinted(), g_btcsoq_supply.TotalBurned(),
                g_btcsoq_supply.Outstanding());
        }
    }

    // BTCSOQ authority outpoint reversal: the block's FIRST v9-authority tx
    // spent the pre-block tracked outpoint (ConnectBlock enforces this), so
    // reverting to that input's prevout restores the pre-block chain state.
    // ApplyTxInUndo above has already restored the spent coins to the view.
    if (fRealDisconnect && fBTCSOQActiveAtHeight) {
        for (const auto& ptx : block.vtx) {
            const CTransaction& tx = *ptx;
            if (tx.IsCoinBase()) continue;

            bool hasBTCSOQAuthorityOutput = false;
            for (const auto& txout : tx.vout) {
                if (IsBTCSOQAuthorityMarker(txout.scriptPubKey)) {
                    hasBTCSOQAuthorityOutput = true;
                    break;
                }
            }

            if (hasBTCSOQAuthorityOutput) {
                bool fRevertedToPrevout = false;
                for (unsigned int k = 0; k < tx.vin.size(); ++k) {
                    const CCoins* coins = view.AccessCoins(tx.vin[k].prevout.hash);
                    if (coins && coins->IsAvailable(tx.vin[k].prevout.n)) {
                        const CScript& prevSpk = coins->vout[tx.vin[k].prevout.n].scriptPubKey;
                        if (IsBTCSOQAuthorityMarker(prevSpk)) {
                            g_btcsoq_authority_outpoint = tx.vin[k].prevout;
                            if (pcoinsdbview) {
                                pcoinsdbview->WriteBTCSOQAuthorityOutpoint(
                                    g_btcsoq_authority_outpoint);
                            }
                            LogPrintf("BTCSOQ: reorg reversal — authority outpoint reverted to %s:%u\n",
                                g_btcsoq_authority_outpoint.hash.ToString(),
                                g_btcsoq_authority_outpoint.n);
                            fRevertedToPrevout = true;
                            break;
                        }
                    }
                }
                if (!fRevertedToPrevout) {
                    // No v9 marker input restored ⇒ this was the BOOTSTRAP
                    // authority tx. Disconnecting it must return the chain to
                    // the pre-bootstrap state: a NULL outpoint, so the next
                    // authority tx takes the bootstrap path again. (Review
                    // finding. The USDSOQ reversal had the same gap; it was
                    // recorded here in prose and stayed unfixed until SOQ-I012.
                    // Both sides now null-restore.)
                    g_btcsoq_authority_outpoint = COutPoint();
                    if (pcoinsdbview) {
                        pcoinsdbview->WriteBTCSOQAuthorityOutpoint(
                            g_btcsoq_authority_outpoint);
                    }
                    LogPrintf("BTCSOQ: reorg reversal — bootstrap disconnected, "
                              "authority outpoint reverted to null\n");
                }
                break;  // first authority tx spends the pre-block outpoint
            }
        }
    }

    // BTCSOQ freeze-registry inversion + minted-deposit erasure. Both reverse
    // only what ConnectBlock actually applied, so both carry the R1 guards:
    // v9-authority txs only, at/after the enforcement height (pre-enforcement
    // blocks never had ops applied — a forged envelope in a non-authority tx
    // must not be able to erase a legitimate freeze or minted-deposit entry).
    if (fRealDisconnect && pcoinsdbview && fBTCSOQActiveAtHeight) {
        const Consensus::Params& btcsoqDisconnectConsensus =
            Params().GetConsensus(pindex->nHeight);
        unsigned int nBTCSOQReversedOps = 0;
        for (const auto& ptx : block.vtx) {
            const CTransaction& tx = *ptx;
            if (tx.IsCoinBase()) continue;

            if (pindex->nHeight < btcsoqDisconnectConsensus.nBTCSOQAuthorityEnforcementHeight)
                continue;

            bool isBTCSOQAuthorityTx = false;
            for (const auto& o : tx.vout) {
                if (IsBTCSOQAuthorityMarker(o.scriptPubKey)) {
                    isBTCSOQAuthorityTx = true;
                    break;
                }
            }
            if (!isBTCSOQAuthorityTx) continue;

            uint8_t btcsoqTag = 0;
            std::vector<uint8_t> btcsoqPayload;
            if (!ParseBTCSOQAuthorityOp(tx, btcsoqTag, btcsoqPayload)) continue;

            if (btcsoqTag == BTCSOQ_OP_MINT) {
                uint256 btcTxid, mintRecipient;
                uint32_t btcVout = 0;
                CAmount mintSats = 0;
                if (ParseBTCSOQMintPayload(btcsoqPayload, btcTxid, btcVout,
                                           mintSats, mintRecipient)) {
                    // The mint is being disconnected — the Bitcoin deposit is
                    // no longer consumed and MUST become mintable again.
                    pcoinsdbview->EraseBTCSOQMinted(COutPoint(btcTxid, btcVout));
                    nBTCSOQReversedOps++;
                }
            } else if (btcsoqTag == BTCSOQ_OP_FREEZE) {
                uint8_t freezeOp = btcsoqPayload[0];
                if (freezeOp != FREEZE_OP_FREEZE && freezeOp != FREEZE_OP_UNFREEZE)
                    continue;
                uint256 freezeTxid;
                memcpy(freezeTxid.begin(), &btcsoqPayload[1], 32);
                uint32_t freezeVout = (uint32_t)btcsoqPayload[33]
                                    | ((uint32_t)btcsoqPayload[34] << 8)
                                    | ((uint32_t)btcsoqPayload[35] << 16)
                                    | ((uint32_t)btcsoqPayload[36] << 24);
                COutPoint freezeTarget(freezeTxid, freezeVout);
                if (freezeOp == FREEZE_OP_FREEZE) {
                    pcoinsdbview->EraseBTCSOQFrozen(freezeTarget);   // undo the freeze
                } else {
                    pcoinsdbview->WriteBTCSOQFrozen(freezeTarget);   // re-freeze
                }
                nBTCSOQReversedOps++;
            }
        }

        if (nBTCSOQReversedOps > 0) {
            LogPrintf("BTCSOQ: reorg at block %d reversed %u registry ops\n",
                pindex->nHeight, nBTCSOQReversedOps);
        }
    }

    // move best block pointer to prevout block
    view.SetBestBlock(pindex->pprev->GetBlockHash());

    if (pfClean) {
        *pfClean = fClean;
        return true;
    }

    return fClean;
}

void static FlushBlockFile(bool fFinalize = false)
{
    LOCK(cs_LastBlockFile);

    CDiskBlockPos posOld(nLastBlockFile, 0);

    FILE* fileOld = OpenBlockFile(posOld);
    if (fileOld) {
        if (fFinalize)
            TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }

    fileOld = OpenUndoFile(posOld);
    if (fileOld) {
        if (fFinalize)
            TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nUndoSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }
}

bool FindUndoPos(CValidationState& state, int nFile, CDiskBlockPos& pos, unsigned int nAddSize);

static CCheckQueue<CScriptCheck> scriptcheckqueue(128);

void ThreadScriptCheck()
{
    RenameThread("soqucoin-scriptch");
    scriptcheckqueue.Thread();
}

// Protected by cs_main
VersionBitsCache versionbitscache;

int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(cs_main);
    int32_t nVersion = VERSIONBITS_TOP_BITS;

    for (int i = 0; i < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++) {
        ThresholdState state = VersionBitsState(pindexPrev, params, (Consensus::DeploymentPos)i, versionbitscache);
        if (state == THRESHOLD_LOCKED_IN || state == THRESHOLD_STARTED) {
            nVersion |= VersionBitsMask(params, (Consensus::DeploymentPos)i);
        }
    }

    return nVersion;
}

/**
 * Threshold condition checker that triggers when unknown versionbits are seen on the network.
 */
class WarningBitsConditionChecker : public AbstractThresholdConditionChecker
{
private:
    int bit;

public:
    WarningBitsConditionChecker(int bitIn) : bit(bitIn) {}

    int64_t BeginTime(const Consensus::Params& params) const { return 0; }
    int64_t EndTime(const Consensus::Params& params) const { return std::numeric_limits<int64_t>::max(); }
    int Period(const Consensus::Params& params) const { return params.nMinerConfirmationWindow; }
    int Threshold(const Consensus::Params& params) const { return params.nRuleChangeActivationThreshold; }

    bool Condition(const CBlockIndex* pindex, const Consensus::Params& params) const
    {
        return ((pindex->nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) &&
               ((pindex->nVersion >> bit) & 1) != 0 &&
               ((ComputeBlockVersion(pindex->pprev, params) >> bit) & 1) == 0;
    }
};

// Protected by cs_main
static ThresholdConditionCache warningcache[VERSIONBITS_NUM_BITS];

static int64_t nTimeCheck = 0;
static int64_t nTimeForks = 0;
static int64_t nTimeVerify = 0;
static int64_t nTimeConnect = 0;
static int64_t nTimeIndex = 0;
static int64_t nTimeCallbacks = 0;
static int64_t nTimeTotal = 0;

bool ConnectBlock(const CBlock& block, CValidationState& state, CBlockIndex* pindex, CCoinsViewCache& view, const CChainParams& chainparams, bool fJustCheck)
{
    AssertLockHeld(cs_main);

    const Consensus::Params& consensus = Params().GetConsensus(pindex->nHeight);
    int64_t nTimeStart = GetTimeMicros();

    // Check it again in case a previous version let a bad block in
    // NOTE: We don't currently (re-)invoke ContextualCheckBlock() or
    // ContextualCheckBlockHeader() here. This means that if we add a new
    // consensus rule that is enforced in one of those two functions, then we
    // may have let in a block that violates the rule prior to updating the
    // software, and we would NOT be enforcing the rule here. Fully solving
    // upgrade from one software version to the next after a consensus rule
    // change is potentially tricky and issue-specific (see RewindBlockIndex()
    // for one general approach that was used for BIP 141 deployment).
    // Also, currently the rule against blocks more than 2 hours in the future
    // is enforced in ContextualCheckBlockHeader(); we wouldn't want to
    // re-enforce that rule here (at least until we make it impossible for
    // GetAdjustedTime() to go backward).
    if (!CheckBlock(block, state, !fJustCheck, !fJustCheck)) {
        if (state.CorruptionPossible()) {
            LogPrintf("%s: Attempt to connect corrupted block %s.\n", __func__, block.GetHash().ToString());
            // We don't write down blocks to disk if they may have been
            // corrupted, so this should be impossible unless we're having hardware
            // problems.
            return AbortNode(state, "Corrupt block found indicating potential hardware failure; shutting down");
        }
        return error("%s: Consensus::CheckBlock: %s", __func__, FormatStateMessage(state));
    }

    // verify that the view's current state corresponds to the previous block
    uint256 hashPrevBlock = pindex->pprev == NULL ? uint256() : pindex->pprev->GetBlockHash();
    assert(hashPrevBlock == view.GetBestBlock());

    // Special case for the genesis block, skipping connection of its transactions
    // (its coinbase is unspendable)
    if (block.GetHash() == Params().GetConsensus(0).hashGenesisBlock) {
        if (!fJustCheck)
            view.SetBestBlock(pindex->GetBlockHash());
        return true;
    }

    bool fScriptChecks = true;
    if (!hashAssumeValid.IsNull()) {
        // We've been configured with the hash of a block which has been externally verified to have a valid history.
        // A suitable default value is included with the software and updated from time to time.  Because validity
        //  relative to a piece of software is an objective fact these defaults can be easily reviewed.
        // This setting doesn't force the selection of any particular chain but makes validating some faster by
        //  effectively caching the result of part of the verification.
        BlockMap::const_iterator it = mapBlockIndex.find(hashAssumeValid);
        if (it != mapBlockIndex.end()) {
            if (it->second->GetAncestor(pindex->nHeight) == pindex &&
                pindexBestHeader->GetAncestor(pindex->nHeight) == pindex &&
                pindexBestHeader->nChainWork >= UintToArith256(consensus.nMinimumChainWork)) {
                // This block is a member of the assumed verified chain and an ancestor of the best header.
                // The equivalent time check discourages hashpower from extorting the network via DOS attack
                //  into accepting an invalid block through telling users they must manually set assumevalid.
                //  Requiring a software change or burying the invalid block, regardless of the setting, makes
                //  it hard to hide the implication of the demand.  This also avoids having release candidates
                //  that are hardly doing any signature verification at all in testing without having to
                //  artificially set the default assumed verified block further back.
                // The test against nMinimumChainWork prevents the skipping when denied access to any chain at
                //  least as good as the expected chain.
                fScriptChecks = (GetBlockProofEquivalentTime(*pindexBestHeader, *pindex, *pindexBestHeader, consensus) <= 60 * 60 * 24 * 7 * 2);
            }
        }
    }

    int64_t nTime1 = GetTimeMicros();
    nTimeCheck += nTime1 - nTimeStart;
    LogPrint("bench", "    - Sanity checks: %.2fms [%.2fs]\n", 0.001 * (nTime1 - nTimeStart), nTimeCheck * 0.000001);

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
    // already refuses previously-known transaction ids entirely.
    // This rule was originally applied to all blocks with a timestamp after March 15, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
    // two in the chain that violate it. This prevents exploiting the issue against nodes during their
    // initial block download.
    // Soqucoin: BIP30 has been active since inception
    bool fEnforceBIP30 = true;

    // Once BIP34 activated it was not possible to create new duplicate coinbases and thus other than starting
    // with the 2 existing duplicate coinbase pairs, not possible to create overwriting txs.  But by the
    // time BIP34 activated, in each of the existing pairs the duplicate coinbase had overwritten the first
    // before the first had been spent.  Since those coinbases are sufficiently buried its no longer possible to create further
    // duplicate transactions descending from the known pairs either.
    // If we're on the known chain at height greater than where BIP34 activated, we can save the db accesses needed for the BIP30 check.
    CBlockIndex* pindexBIP34height = pindex->pprev->GetAncestor(chainparams.GetConsensus(0).BIP34Height);
    // Only continue to enforce if we're below BIP34 activation height or the block hash at that height doesn't correspond.
    fEnforceBIP30 = fEnforceBIP30 && (!pindexBIP34height || !(pindexBIP34height->GetBlockHash() == chainparams.GetConsensus(0).BIP34Hash));

    if (fEnforceBIP30) {
        for (const auto& tx : block.vtx) {
            const CCoins* coins = view.AccessCoins(tx->GetHash());
            if (coins && !coins->IsPruned())
                return state.DoS(100, error("ConnectBlock(): tried to overwrite transaction"),
                    REJECT_INVALID, "bad-txns-BIP30");
        }
    }

    // BIP16 didn't become active until Apr 1 2012
    // Soqucoin: BIP16 has been enabled since inception
    bool fStrictPayToScriptHash = true;

    unsigned int flags = fStrictPayToScriptHash ? SCRIPT_VERIFY_P2SH : SCRIPT_VERIFY_NONE;

    // Start enforcing the DERSIG (BIP66) rule
    if (pindex->nHeight >= chainparams.GetConsensus(0).BIP66Height) {
        flags |= SCRIPT_VERIFY_DERSIG;
    }

    // Start enforcing CHECKLOCKTIMEVERIFY, (BIP65) for block.nVersion=4 blocks
    if (pindex->nHeight >= chainparams.GetConsensus(0).BIP65Height) {
        flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    }

    // Start enforcing BIP68 (sequence locks) and BIP112 (CHECKSEQUENCEVERIFY) using versionbits logic.
    int nLockTimeFlags = 0;
    if (VersionBitsState(pindex->pprev, consensus, Consensus::DEPLOYMENT_CSV, versionbitscache) == THRESHOLD_ACTIVE) {
        flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
        nLockTimeFlags |= LOCKTIME_VERIFY_SEQUENCE;
    }

    // Start enforcing WITNESS rules using versionbits logic.
    if (IsWitnessEnabled(pindex->pprev, consensus)) {
        flags |= SCRIPT_VERIFY_WITNESS;
        flags |= SCRIPT_VERIFY_NULLDUMMY;
    }

    // SOQ-P001: Start enforcing PAT aggregation verification
    if (VersionBitsState(pindex->pprev, consensus, Consensus::DEPLOYMENT_CHECKPATAGG, versionbitscache) == THRESHOLD_ACTIVE) {
        flags |= SCRIPT_VERIFY_PAT;
    }

    // SOQ-P002: Start enforcing LatticeFold privacy proof verification
    if (VersionBitsState(pindex->pprev, consensus, Consensus::DEPLOYMENT_LATTICEFOLD, versionbitscache) == THRESHOLD_ACTIVE) {
        flags |= SCRIPT_VERIFY_LATTICEFOLD;
    }

    // SOQ-ARCH-001: Start enforcing Lattice-BP++ privacy proof verification
    // and confidential transaction output validation. When active, witness v4
    // outputs are no longer anyone-can-spend — range proofs are verified.
    // When NOT active, confidential outputs (nVisibility != 0x00) are rejected
    // in the per-TX output validation loop below.
    //
    // p96 / Option D: the post-launch soft-forks below activate by scheduled
    // HEIGHT (DeploymentActiveAtHeight), not BIP9 miner signaling — Soqucoin is
    // merge-mined with no signaling constituency. Test nets set the height to 0
    // (active from genesis); mainnet ships them NOT_SCHEDULED (dormant) until a
    // coordinated release sets a real height. CHECKPATAGG/LATTICEFOLD (always-
    // active) and CSV/SegWit (historical) remain on the BIP9 state machine above.
    if (Consensus::DeploymentActiveAtHeight(pindex->nHeight, consensus, Consensus::DEPLOYMENT_SOQUOBSCURA)) {
        flags |= SCRIPT_VERIFY_SOQUOBSCURA;
    }

    // SOQ-AUD2-002: Start enforcing USDSOQ stablecoin authority opcodes
    if (Consensus::DeploymentActiveAtHeight(pindex->nHeight, consensus, Consensus::DEPLOYMENT_USDSOQ)) {
        flags |= SCRIPT_VERIFY_USDSOQ;

        // SOQ-AUD2-002 D4: Lazy-initialize authority from Consensus::Params.
        // Only runs once — subsequent blocks skip if already initialized.
        if (!g_usdsoq_authority.IsInitialized() && !consensus.usdsoqAuthorityKeys.empty()) {
            std::vector<std::vector<uint8_t>> keys;
            for (const auto& hexKey : consensus.usdsoqAuthorityKeys) {
                std::vector<uint8_t> key = ParseHex(hexKey);
                if (key.size() == DILITHIUM_PUBKEY_SIZE) {
                    keys.push_back(key);
                } else {
                    LogPrintf("USDSOQ: WARNING: Skipping authority key with invalid size %u (expected %u)\n",
                              key.size(), DILITHIUM_PUBKEY_SIZE);
                }
            }
            if (g_usdsoq_authority.Initialize(keys, consensus.usdsoqAuthorityThreshold)) {
                LogPrintf("USDSOQ: Authority initialized: %u-of-%u Dilithium multisig\n",
                          consensus.usdsoqAuthorityThreshold, keys.size());
            } else {
                LogPrintf("USDSOQ: WARNING: Authority initialization failed (threshold=%u, keys=%u)\n",
                          consensus.usdsoqAuthorityThreshold, keys.size());
            }
        }
    }

    // DL-BTCSOQ-CONSENSUS-NATIVE: Start enforcing the BTCSOQ money-path.
    // Same height-gated activation model as USDSOQ (mainnet ships
    // NOT_SCHEDULED / dormant; test nets active from genesis).
    if (Consensus::DeploymentActiveAtHeight(pindex->nHeight, consensus, Consensus::DEPLOYMENT_BTCSOQ)) {
        flags |= SCRIPT_VERIFY_BTCSOQ;

        // Lazy-initialize the BTCSOQ issuer authority from Consensus::Params.
        if (!g_btcsoq_authority.IsInitialized() && !consensus.btcsoqAuthorityKeys.empty()) {
            std::vector<std::vector<uint8_t>> btcsoqKeys;
            for (const auto& hexKey : consensus.btcsoqAuthorityKeys) {
                std::vector<uint8_t> key = ParseHex(hexKey);
                if (key.size() == DILITHIUM_PUBKEY_SIZE) {
                    btcsoqKeys.push_back(key);
                } else {
                    LogPrintf("BTCSOQ: WARNING: Skipping authority key with invalid size %u (expected %u)\n",
                              key.size(), DILITHIUM_PUBKEY_SIZE);
                }
            }
            if (g_btcsoq_authority.Initialize(btcsoqKeys, consensus.btcsoqAuthorityThreshold)) {
                LogPrintf("BTCSOQ: Authority initialized: %u-of-%u Dilithium multisig\n",
                          consensus.btcsoqAuthorityThreshold, btcsoqKeys.size());
            } else {
                LogPrintf("BTCSOQ: WARNING: Authority initialization failed (threshold=%u, keys=%u)\n",
                          consensus.btcsoqAuthorityThreshold, btcsoqKeys.size());
            }
        }
    }

    // BIP 119: Start enforcing OP_CHECKTEMPLATEVERIFY (vault/covenant opcodes)
    if (Consensus::DeploymentActiveAtHeight(pindex->nHeight, consensus, Consensus::DEPLOYMENT_CTV)) {
        flags |= SCRIPT_VERIFY_CTV;
    }

    // BIP 118: Start enforcing SIGHASH_ANYPREVOUT (eltoo Lightning channels)
    // NOTE: This does NOT modify Dilithium signature verification. It adds
    // new sighash types (0x41, 0x42) that produce alternate sighash values.
    // The existing SIGHASH_ALL (0x01) path is completely untouched.
    if (Consensus::DeploymentActiveAtHeight(pindex->nHeight, consensus, Consensus::DEPLOYMENT_APO)) {
        flags |= SCRIPT_VERIFY_APO;
    }

    // BIP 348: Start enforcing OP_CHECKSIGFROMSTACK (oracle contracts, bridge attestation)
    // Strict ML-DSA-44 only. Message is SHA256'd before Dilithium verify.
    if (Consensus::DeploymentActiveAtHeight(pindex->nHeight, consensus, Consensus::DEPLOYMENT_CSFS)) {
        flags |= SCRIPT_VERIFY_CSFS;
    }

    // SOQ-AUD2-009: Start enforcing P2WSH-Dilithium (witness v6) — covenant script execution
    // When active, witness v6 programs execute arbitrary scripts via EvalScript,
    // enabling CTV vaults, CSFS oracles, OP_CAT covenants, and L2SOQ Lightning.
    // See DL-P2WSH-DILITHIUM.md for full design.
    if (Consensus::DeploymentActiveAtHeight(pindex->nHeight, consensus, Consensus::DEPLOYMENT_P2WSH_DILITHIUM)) {
        flags |= SCRIPT_VERIFY_P2WSH_DILITHIUM;
    }

    // OP_CHECKDILITHIUMKEYHASH: Key-committed Dilithium signature verification
    // When active, OP_NOP7 (0xb6) enforces SHA256(pubkey)==keyhash + Dilithium sig verify.
    // Enables eLTOO 2-of-2 multisig for L2SOQ Lightning with oversized Dilithium pubkeys.
    // See DL-OP-CHECKDILITHIUMKEYHASH.md for design.
    if (Consensus::DeploymentActiveAtHeight(pindex->nHeight, consensus, Consensus::DEPLOYMENT_DILITHIUM_KEYHASH)) {
        flags |= SCRIPT_VERIFY_DILITHIUM_KEYHASH;
    }

    // DL-V6-CONTROLFLOW-RESTORE: Start enforcing the restored branch/timelock/hashlock opcodes
    // (OP_IF/ELSE/ENDIF, OP_DROP, OP_CLTV, OP_CSV, OP_SHA256, OP_EQUAL[VERIFY]) in v6 EvalScript —
    // the eLTOO state ratchet, settlement CSV, and HTLC hashlock/timeout. PQ sigs stay on
    // CSFS/keyhash. When inactive these opcodes remain no-ops (unchanged behaviour).
    if (Consensus::DeploymentActiveAtHeight(pindex->nHeight, consensus, Consensus::DEPLOYMENT_V6_CONTROLFLOW)) {
        flags |= SCRIPT_VERIFY_V6_CONTROLFLOW;
    }

    // SATOSHI SCRIPT RESTORATION: Always-active on Soqucoin (genesis-active).
    // AND/OR/XOR/MUL/DIV/MOD/SUBSTR/LEFT/RIGHT re-enabled with BCH-style bounds.
    // No BIP9 gate needed — these are genesis-active like OP_CAT.
    // DoS vectors eliminated by existing CScriptNum + 520-byte element limits.
    flags |= SCRIPT_VERIFY_SCRIPT_RESTORE;

    // SOQ-ARCH-003: Check if consensus-enforced minimum UTXO value is active (BIP9).
    // When active, every output must hold >= UTXO_COST_PER_BYTE × serialized_output_size.
    // Prevents dust storm attacks that bloat the UTXO set (Cardano-style utxoCostPerByte).
    // Mainnet: NOT_SCHEDULED (dormant until Phase 2 audit). Stagenet/regtest: height 0.
    // See DL-SOQ-FEE-ARCHITECTURE-V3.md.
    bool fEnforceUtxoCost = Consensus::DeploymentActiveAtHeight(pindex->nHeight, consensus,
        Consensus::DEPLOYMENT_UTXO_COST);

    int64_t nTime2 = GetTimeMicros();
    nTimeForks += nTime2 - nTime1;
    LogPrint("bench", "    - Fork checks: %.2fms [%.2fs]\n", 0.001 * (nTime2 - nTime1), nTimeForks * 0.000001);

    CBlockUndo blockundo;

    CCheckQueueControl<CScriptCheck> control(fScriptChecks && nScriptCheckThreads ? &scriptcheckqueue : NULL);

    std::vector<int> prevheights;
    CAmount nFees = 0;
    int nInputs = 0;
    int64_t nSigOpsCost = 0;
    CDiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(block.vtx.size()));
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    vPos.reserve(block.vtx.size());
    blockundo.vtxundo.reserve(block.vtx.size() - 1);
    std::vector<PrecomputedTransactionData> txdata;
    txdata.reserve(block.vtx.size()); // Required so that pointers to individual PrecomputedTransactionData don't get invalidated

    // PAT block attestation (doc/PAT_BLOCK_ATTESTATION.md): tuples are
    // collected inside the loop below, per transaction, because the view
    // resolves each transaction's prevouts only until UpdateCoins spends them.
    // The attested set is fixed (v0/v1/v7/v8 two-item spends, independent of
    // any deployment flag) so that a later asset activation cannot change the
    // commitment the genesis binary recomputes; see IsAttestedVersion.
    // Enforcement happens after the loop, once the batch is complete.
    //
    // Gated on fScriptChecks, the assumevalid/checkpoint window where signature
    // verification itself is skipped. The attestation attests those same
    // signatures, so recomputing it there is the same class of redundant work
    // assumevalid exists to skip — and it is NOT cheap: a sighash per input
    // (which the base code does not compute at all in this window), SHA3 over
    // every 2,420-byte signature and 1,312-byte key, and an O(n log n) Merkle
    // build per block. Every historical commitment was verified by the nodes
    // that ran full checks, the same trust statement assumevalid already makes.
    //
    // ⛔ Collection and the enforcement block below are gated TOGETHER. Skipping
    // only collection would compare a present commitment against an empty batch
    // and reject valid historical blocks (bad-blk-pat-commitment-empty) during
    // fast sync.
    patattest::PatBatch patBatch;
    const patattest::AttestedSetParams patParams;   // fixed set; carries no per-height facts

    for (unsigned int i = 0; i < block.vtx.size(); i++) {
        const CTransaction& tx = *(block.vtx[i]);

        nInputs += tx.vin.size();

        if (!tx.IsCoinBase()) {
            if (!view.HaveInputs(tx))
                return state.DoS(100, error("ConnectBlock(): inputs missing/spent"),
                    REJECT_INVALID, "bad-txns-inputs-missingorspent");

            // Check that transaction is BIP68 final
            // BIP68 lock checks (as opposed to nLockTime checks) must
            // be in ConnectBlock because they require the UTXO set
            prevheights.resize(tx.vin.size());
            for (size_t j = 0; j < tx.vin.size(); j++) {
                prevheights[j] = view.AccessCoins(tx.vin[j].prevout.hash)->nHeight;
            }

            if (!SequenceLocks(tx, nLockTimeFlags, &prevheights, *pindex)) {
                return state.DoS(100, error("%s: contains a non-BIP68-final transaction", __func__),
                    REJECT_INVALID, "bad-txns-nonfinal");
            }
        }

        // GetTransactionSigOpCost counts 3 types of sigops:
        // * legacy (always)
        // * p2sh (when P2SH enabled in flags and excludes coinbase)
        // * witness (when witness enabled in flags and excludes coinbase)
        nSigOpsCost += GetTransactionSigOpCost(tx, view, flags);
        if (nSigOpsCost > MAX_BLOCK_SIGOPS_COST)
            return state.DoS(100, error("ConnectBlock(): too many sigops"),
                REJECT_INVALID, "bad-blk-sigops");

        txdata.emplace_back(tx);
        if (!tx.IsCoinBase()) {
            // SOQ-ARCH-001: Per-asset fee computation.
            // Only native SOQ (nAssetType == 0x00) contributes to miner-claimable fees.
            // USDSOQ surplus in a transaction is NOT claimable as fees — this prevents
            // cross-asset fee inflation where USDSOQ surplus inflates SOQ coinbase.
            CAmount nSOQIn = 0;
            CAmount nTotalIn = 0; // DIAG-FEE: unfiltered total for comparison
            for (unsigned int j = 0; j < tx.vin.size(); j++) {
                const CCoins* coins = view.AccessCoins(tx.vin[j].prevout.hash);
                if (coins && coins->IsAvailable(tx.vin[j].prevout.n)) {
                    const CTxOut& prevOut = coins->vout[tx.vin[j].prevout.n];
                    nTotalIn += prevOut.nValue;
                    if (prevOut.IsNativeSOQ()) {   // Phase 3: per-asset fee filter — v7 USDSOQ never counts as SOQ
                        nSOQIn += prevOut.nValue;
                    } else {
                        // DIAG-FEE: Log every non-SOQ input filtered from fee
                        LogPrint("diagfee", "DIAG-FEE: FILTERED INPUT tx=%s vin[%u] prevout=%s:%u "
                            "isUSDSOQ=%d isConfidential=%d value=%lld coinHeight=%d isCoinBase=%d\n",
                            tx.GetHash().ToString(), j,
                            tx.vin[j].prevout.hash.ToString(), tx.vin[j].prevout.n,
                            prevOut.IsUSDSOQ(),
                            prevOut.IsConfidential(),
                            prevOut.nValue, coins->nHeight, coins->fCoinBase);
                    }
                }
            }
            CAmount nSOQOut = 0;
            for (const auto& txout : tx.vout) {
                if (txout.IsNativeSOQ()) {
                    nSOQOut += txout.nValue;
                }
            }
            nFees += nSOQIn - nSOQOut;

            // DIAG-FEE: Summary if filtered fee differs from unfiltered
            if (nSOQIn != nTotalIn) {
                CAmount nTotalOut = tx.GetValueOut();
                LogPrint("diagfee", "DIAG-FEE: MISMATCH tx=%s inputs=%zu totalIn=%lld soqIn=%lld "
                    "excluded=%lld totalOut=%lld soqOut=%lld unfilteredFee=%lld filteredFee=%lld\n",
                    tx.GetHash().ToString(), tx.vin.size(),
                    nTotalIn, nSOQIn, nTotalIn - nSOQIn,
                    nTotalOut, nSOQOut,
                    nTotalIn - nTotalOut, nSOQIn - nSOQOut);
            }

            std::vector<CScriptCheck> vChecks;
            bool fCacheResults = fJustCheck; /* Don't cache results if we're actually connecting blocks (still consult the cache, though) */
            if (!CheckInputs(tx, state, view, fScriptChecks, flags, fCacheResults, txdata[i], nScriptCheckThreads ? &vChecks : NULL))
                return error("ConnectBlock(): CheckInputs on %s failed with %s",
                    tx.GetHash().ToString(), FormatStateMessage(state));
            control.Add(vChecks);

            // PAT attestation tuple collection (skipped with fScriptChecks —
            // see the gate rationale at the batch declaration above). The
            // prevouts consulted here are exactly the ones this transaction
            // spends (view.HaveInputs held above, UpdateCoins has not yet run
            // for this transaction), so in-block chained spends resolve the
            // same way the producer resolves them.
            if (fScriptChecks) {
                patattest::AppendTuples(patBatch, tx,
                    [&view](const COutPoint& out, CTxOut& txOut) -> bool {
                        const CCoins* coins = view.AccessCoins(out.hash);
                        if (coins == nullptr || !coins->IsAvailable(out.n)) return false;
                        txOut = coins->vout[out.n];
                        return true;
                    }, patParams);
            }
        }

        CTxUndo undoDummy;
        if (i > 0) {
            blockundo.vtxundo.push_back(CTxUndo());
        }
        UpdateCoins(tx, view, i == 0 ? undoDummy : blockundo.vtxundo.back(), pindex->nHeight);

        vPos.push_back(std::make_pair(tx.GetHash(), pos));
        pos.nTxOffset += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);
    }
    int64_t nTime3 = GetTimeMicros();
    nTimeConnect += nTime3 - nTime2;
    LogPrint("bench", "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) [%.2fs]\n", (unsigned)block.vtx.size(), 0.001 * (nTime3 - nTime2), 0.001 * (nTime3 - nTime2) / block.vtx.size(), nInputs <= 1 ? 0 : 0.001 * (nTime3 - nTime2) / (nInputs - 1), nTimeConnect * 0.000001);

    CAmount blockReward = nFees + GetSoqucoinBlockSubsidy(pindex->nHeight, chainparams.GetConsensus(pindex->nHeight), hashPrevBlock);

    // =========================================================================
    // Genesis-migration one-shot allocation (DL-GENESIS-MIGRATION-IMPLEMENTATION
    // §A2, bead gm-consensus-rule-bxws). Inert on every network until all three
    // constants are armed: with nMigrationHeight == 0 or a null hash this block
    // is byte-for-byte the pre-existing subsidy check. At exactly the armed
    // height, the coinbase must carry the committed allocation outputs as
    // vout[1..N] in committed order (trailing block-commitment outputs — the
    // segwit witness, LatticeFold, and PAT attestation commitments, which the
    // producer appends after them — are not part of the committed range): their standard serialization must hash to hashMigrationOutputs,
    // their values must sum to exactly nMigrationTotal, and the miner's own
    // output vout[0] stays bounded by subsidy + fees while the permitted total
    // becomes subsidy + fees + nMigrationTotal.
    // =========================================================================
    {
        const Consensus::Params& migrationConsensus = chainparams.GetConsensus(pindex->nHeight);
        if (migrationConsensus.nMigrationHeight != 0 &&
            pindex->nHeight == migrationConsensus.nMigrationHeight &&
            !migrationConsensus.hashMigrationOutputs.IsNull()) {
            const CTransaction& coinbase = *block.vtx[0];
            // The committed range excludes TRAILING block-commitment outputs.
            // Originally only the SegWit witness commitment; generalised
            // 2026-09-01 when the PAT attestation commitment (also appended by
            // GenerateCoinbaseCommitment, after the SegWit one) made "the
            // witness commitment is last" false for any migration block that
            // contains attested spends. Walk back over every recognised
            // block-commitment shape so the exclusion does not depend on the
            // order the producer appends them in. LatticeFold's commitment is
            // included for the same reason even though it cannot fire while
            // the deployment is withdrawn.
            const auto isBlockCommitmentOutput = [](const CTxOut& out) -> bool {
                const CScript& s = out.scriptPubKey;
                // SegWit witness commitment: >=38 bytes, OP_RETURN 0x24 aa21a9ed.
                if (s.size() >= 38 && s[0] == OP_RETURN && s[1] == 0x24 &&
                    s[2] == 0xaa && s[3] == 0x21 && s[4] == 0xa9 && s[5] == 0xed)
                    return true;
                uint256 ignored;
                if (patattest::ParseCommitmentScript(s, ignored)) return true;   // PAT ('PA')
                std::vector<uint8_t> raw(s.begin(), s.end());
                if (BlockProofAccumulator::ParseCoinbaseCommitment(raw, ignored))
                    return true;                                                 // LatticeFold ('LF')
                return false;
            };
            size_t committedEnd = coinbase.vout.size();
            while (committedEnd > 1 && isBlockCommitmentOutput(coinbase.vout[committedEnd - 1]))
                committedEnd--;
            if (committedEnd < 2)
                return state.DoS(100,
                    error("ConnectBlock(): migration block %d carries no committed outputs", pindex->nHeight),
                    REJECT_INVALID, "bad-cb-migration-missing");
            const std::vector<CTxOut> committed(coinbase.vout.begin() + 1, coinbase.vout.begin() + committedEnd);
            CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
            hasher << committed;
            if (hasher.GetHash() != migrationConsensus.hashMigrationOutputs)
                return state.DoS(100,
                    error("ConnectBlock(): migration block %d committed outputs do not match hashMigrationOutputs", pindex->nHeight),
                    REJECT_INVALID, "bad-cb-migration-outputs");
            CAmount committedSum = 0;
            for (const CTxOut& out : committed)
                committedSum += out.nValue; // per-output and total bounds already enforced by CheckTransaction
            if (committedSum != migrationConsensus.nMigrationTotal)
                return state.DoS(100,
                    error("ConnectBlock(): migration block %d committed sum %d != nMigrationTotal %d",
                        pindex->nHeight, committedSum, migrationConsensus.nMigrationTotal),
                    REJECT_INVALID, "bad-cb-migration-total");
            if (coinbase.vout[0].nValue > blockReward)
                return state.DoS(100,
                    error("ConnectBlock(): migration block %d miner output pays too much (actual=%d vs limit=%d)",
                        pindex->nHeight, coinbase.vout[0].nValue, blockReward),
                    REJECT_INVALID, "bad-cb-migration-miner-value");
            blockReward += migrationConsensus.nMigrationTotal;
        }
    }

    if (block.vtx[0]->GetValueOut() > blockReward)
        return state.DoS(100,
            error("ConnectBlock(): coinbase pays too much (actual=%d vs limit=%d)",
                block.vtx[0]->GetValueOut(), blockReward),
            REJECT_INVALID, "bad-cb-amount");

    // =========================================================================
    // Witness-version creation posture (additive-asset genesis door, 2026-09).
    //
    // A block may create an output of ANY witness version except v2. This is
    // BIP141's posture — a dormant version is anyone-can-spend at the script
    // layer (VerifyScript returns success while the deployment flag is clear)
    // and NON-STANDARD at the relay layer (policy.cpp gates v2-v16 on the live
    // activation mask computed in AcceptToMemoryPoolWorker) — and it is the
    // posture that makes every later activation a SOFT fork: activation only
    // ADDS a rule (the spend must now verify), and every block the new rule
    // accepts, the genesis binary also accepts.
    //
    // History. SOQ-I009 (2026-08-24) reserved every dormant version at
    // consensus (bad-txns-witness-version-not-active) and SOQ-ARCH-001
    // rejected confidential v4/v10 outputs while SoquObscura was dormant.
    // Both were correct for the hazards they closed at the time — fund-and-
    // sweep of a dormant shape, and asset markers buying consensus exemptions
    // with the verifier dormant — but both turned every activation into a
    // HARD fork: a block the genesis binary rejects would become valid. The
    // exemptions those markers bought are now gated on the deployment being
    // active AND its authority initialised (CheckTxInputs, CheckInputs), so
    // the shape alone buys nothing while dormant, and fund-and-sweep is
    // bounded to raw-constructed outputs that no wallet path can produce and
    // no stock miner will include. Ruled 2026-09-07; design record in
    // doc/specifications/WITNESS_VERSION_FORK_CLASS.md.
    //
    // ⛔ Invariants the additive design depends on, all enforced elsewhere and
    // pinned by witness_version_reservation_tests:
    //   * no asset-shaped output (v7/v8/v10) can hold SOQ value before its
    //     deployment activates — the per-asset conservation rule in
    //     CheckTxInputs rejects it from a non-coinbase tx, and CheckTransaction
    //     rejects it from a coinbase. That is what keeps the per-asset fee
    //     filter and conservation rules satisfied trivially, so the activation
    //     release can mandate nValue == 0 on asset outputs without relaxing any
    //     genesis rule;
    //   * nothing in ConnectBlock or DisconnectBlock touches asset state
    //     unless the deployment is active at this height.
    //
    // ⛔ v2 (PAT) is the one version that stays PERMANENTLY unfundable. PAT's
    // attestation is block metadata — a commitment in the coinbase, validated
    // in ConnectBlock — not a UTXO, and the v2 spend path in interpreter.cpp
    // binds NEITHER the witness program NOR the sighash: it delegates to
    // OP_CHECKPATAGG, which by design verifies no signature, only the internal
    // consistency of attacker-supplied 32-byte tuples. Any v2 output that ever
    // confirmed would be spendable by anybody, and DEPLOYMENT_CHECKPATAGG is
    // ALWAYS_ACTIVE, so unfundability is the control and it must not depend on
    // a deployment. Ruled 2026-08-31; bead pat-v2-anyone-can-spend-ae6u.
    // =========================================================================
    for (unsigned int i = 0; i < block.vtx.size(); i++) {
        const CTransaction& tx = *(block.vtx[i]);
        for (const auto& txout : tx.vout) {
            const CScript& spk = txout.scriptPubKey;
            // The one shape every Soqucoin witness version uses: OP_N <32>.
            if (spk.size() == 34 && spk[0] == OP_2 && spk[1] == 32) {
                return state.DoS(100,
                    error("ConnectBlock(): witness v2 output in block %d — PAT is not an output type",
                          pindex->nHeight),
                    REJECT_INVALID, "bad-txns-witness-version-not-active");
            }
        }
    }

    // =========================================================================
    // SOQ-AUD2-002 / SOQ-I005: USDSOQ Consensus Enforcement
    // When DEPLOYMENT_USDSOQ is active, enforce:
    //   1. M-of-N Dilithium authority signature verification (SOQ-I005)
    //   2. Authority UTXO chain tracking (Option D — P2WSH/Liquid pattern)
    //   3. Input-side asset isolation (USDSOQ inputs → USDSOQ outputs only)
    //   4. Frozen UTXO spend rejection (GENIUS Act §4(a)(2))
    //   5. Per-block supply delta tracking (mint/burn accounting)
    //
    // Authority verification: EvalScript only validates structural properties
    // (witness stack sizes, tag bytes). Cryptographic M-of-N Dilithium
    // verification is performed HERE in ConnectBlock, which has access to
    // the chain state (authority key set, tracked outpoint).
    // =========================================================================
    // SOQ-I013: pending containers live OUTSIDE the flag block so the commit
    // site after control.Wait() can see them, exactly as btcsoqPending* does.
    COutPoint usdsoqPendingOutpoint;
    bool usdsoqCommitOutpoint = false;
    CUSDSOQSupply usdsoqPendingSupply;
    bool usdsoqCommitSupply = false;
    std::vector<std::pair<uint8_t, COutPoint>> usdsoqPendingFreezeOps;

    if (flags & SCRIPT_VERIFY_USDSOQ) {
        // ────────────────────────────────────────────────────────────────────
        // SOQ-I013 COMMIT DISCIPLINE. This block VALIDATES and collects; it no
        // longer writes. Everything below lands in the usdsoqPending*
        // containers and is committed in one place after control.Wait() has
        // returned the script verdict and after the fJustCheck early-return.
        //
        // It used to write through immediately: the authority outpoint, the
        // freeze registry and the supply counters all hit globals and LevelDB
        // inside this loop, while the per-input script checks were still only
        // QUEUED. control.Wait() collects them ~1200 lines later. A block that
        // was valid right up until a signature failed therefore mutated USDSOQ
        // state permanently — ConnectTip abandons the child UTXO cache by
        // skipping view.Flush, but nothing abandons a LevelDB write or a
        // mutated global. The node's USDSOQ state then described a block on no
        // chain, which is the SOQ-I012 divergence reached from the other side,
        // with the same end state: the tracker points into a rejected block and
        // the next legitimate authority tx is refused.
        //
        // The !fJustCheck guards did not help; they protect dry runs, and this
        // was a real connect failing late.
        //
        // BTCSOQ has done it this way since review 2C (btcsoqPending*, commit
        // after Wait). This is that pattern, applied to the sibling that never
        // received it.
        // ────────────────────────────────────────────────────────────────────
        // In-block freeze overlay. FREEZE/UNFREEZE ops earlier in this block
        // must be visible to the frozen-spend guard for later txs in BOTH the
        // fJustCheck and real passes. Consulting only the committed DB made
        // TestBlockValidity accept a freeze-then-spend block that a real
        // connect rejected — BTCSOQ carries the same two sets for this reason.
        std::set<COutPoint> usdsoqBlockFrozenAdd;
        std::set<COutPoint> usdsoqBlockFrozenRemove;

        CAmount nUSDSOQMinted = 0;
        CAmount nUSDSOQBurned = 0;

        // SOQ-I005: Local authority outpoint tracker for this block.
        // Starts from the global value but tracks updates within this
        // ConnectBlock pass. This allows fJustCheck (TestBlockValidity)
        // to validate consecutive authority TXs in the same block
        // without mutating the global state.
        COutPoint localAuthOutpoint = g_usdsoq_authority_outpoint;

        for (unsigned int i = 0; i < block.vtx.size(); i++) {
            const CTransaction& tx = *(block.vtx[i]);
            if (tx.IsCoinBase()) continue;

            // (Input-type isolation that formerly read this per-tx "has USDSOQ
            // output" flag now lives in Consensus::CheckTxInputs (Option B),
            // enforced live in both the connect and mempool paths — bead 0r2/e2n.)

            // =============================================================
            // SOQ-I005: Authority TX detection and M-of-N Dilithium
            // signature verification.
            //
            // An "authority TX" has at least one OP_5 <32-byte hash> output
            // (witness v5 program). This indicates a MINT, BURN, FREEZE,
            // or ROTATE operation that requires M-of-N authorization.
            //
            // Verification flow:
            //   1. Detect authority output (OP_5 <32-byte>)
            //   2. Find the authority INPUT (spends the tracked outpoint)
            //   3. Extract witness stack signatures
            //   4. Compute BIP143 sighash over the authority input
            //   5. Verify M-of-N Dilithium signatures
            //   6. Update tracked outpoint to the new authority output
            // =============================================================
            bool isAuthorityTx = false;
            int nAuthorityOutputIndex = -1;
            for (size_t j = 0; j < tx.vout.size(); ++j) {
                const CScript& spk = tx.vout[j].scriptPubKey;
                if (spk.size() == 34 && spk[0] == OP_5 && spk[1] == 32) {
                    isAuthorityTx = true;
                    nAuthorityOutputIndex = static_cast<int>(j);
                    break;
                }
            }

            // SOQ-I009: default-deny, matching the BTCSOQ sibling below
            // ("bad-btcsoq-authority-unavailable"). Without this, an ORDINARY
            // correctly-signed transaction that merely carries an OP_5 marker
            // took the ex-nihilo mint exemption in Consensus::CheckTxInputs and
            // then found no verifier here, because the guard below is
            // `isAuthorityTx && IsInitialized()` and simply fell through when
            // the keyset was absent. That is unlimited USDSOQ minting the day
            // the deployment activates without keys configured — which is the
            // exact state CMainParams is in today. No authority ⇒ no authority
            // transaction.
            if (isAuthorityTx && !g_usdsoq_authority.IsInitialized()) {
                return state.DoS(100,
                    error("ConnectBlock(): USDSOQ authority tx %s at block %d but the "
                          "authority key set is not initialized",
                        tx.GetHash().ToString(), pindex->nHeight),
                    REJECT_INVALID, "bad-usdsoq-authority-unavailable");
            }

            if (isAuthorityTx && g_usdsoq_authority.IsInitialized()) {
                // SOQ-I005-STAGENET: Height-gated authority enforcement.
                // Before nUSDSOQAuthorityEnforcementHeight, authority TXs are
                // accepted without signature verification (pre-authority test mints).
                // After the height, full M-of-N Dilithium verification is required.
                //
                // MAINNET: nUSDSOQAuthorityEnforcementHeight=0, so this gate is
                // always open (signatures always required). No unsigned USDSOQ TX
                // can exist before BIP9 activates USDSOQ, making this safe.
                //
                // STAGENET: nUSDSOQAuthorityEnforcementHeight=7700 (recalibrated
                // 2026-07-04 for the reset chain), exempting the pre-enforcement
                // drill txs (mint 6501, send 7077, burn 7595).
                if (pindex->nHeight < consensus.nUSDSOQAuthorityEnforcementHeight) {
                    LogPrintf("USDSOQ: Pre-enforcement height %d < %d — "
                              "skipping authority sig verification for tx %s "
                              "(SOQ-I005-STAGENET exemption)\n",
                        pindex->nHeight,
                        consensus.nUSDSOQAuthorityEnforcementHeight,
                        tx.GetHash().ToString());

                    // SOQ-REINDEX-002: Track outpoint locally within the block only.
                    // Do NOT persist to g_usdsoq_authority_outpoint or LevelDB.
                    // The original chain was built with binaries that did not track
                    // outpoints during pre-enforcement, so the outpoint was null at
                    // the enforcement boundary (height 37201). Persisting here would
                    // create a phantom state causing the first post-enforcement TX
                    // to fail validation (it used the bootstrap path, not spend path).
                    if (nAuthorityOutputIndex >= 0) {
                        localAuthOutpoint = COutPoint(
                            tx.GetHash(), nAuthorityOutputIndex);
                        LogPrintf("USDSOQ: Pre-enforcement outpoint tracked (local only): %s:%u\n",
                            localAuthOutpoint.hash.ToString(),
                            localAuthOutpoint.n);
                    }
                } else {
                // SECURITY NOTE (SOQ-I005): This is the consensus-critical
                // authority verification. Without this block, any miner could
                // mint unlimited USDSOQ with structurally valid but
                // cryptographically unsigned transactions.

                // Step 1: Find the authority input — the input that spends
                // the tracked authority UTXO outpoint.
                int nAuthorityInputIndex = -1;
                CScript authorityScriptCode;

                // If the authority outpoint is null (not yet bootstrapped),
                // we must still verify authority sigs. In this case, look for
                // any input whose prevout scriptPubKey is OP_5 <32-byte>.
                for (unsigned int k = 0; k < tx.vin.size(); ++k) {
                    const CTxIn& txin = tx.vin[k];

                    // Check if this input spends the tracked authority UTXO
                    if (!localAuthOutpoint.IsNull() &&
                        txin.prevout == localAuthOutpoint) {
                        nAuthorityInputIndex = static_cast<int>(k);
                        // Try to get scriptPubKey from UTXO view first
                        const CCoins* authCoins = view.AccessCoins(txin.prevout.hash);
                        if (authCoins && authCoins->IsAvailable(txin.prevout.n)) {
                            authorityScriptCode = authCoins->vout[txin.prevout.n].scriptPubKey;
                        } else {
                            // UTXO already spent by UpdateCoins (which runs before
                            // this authority verification loop). Compute the script
                            // deterministically: OP_5 <SHA256(concat(all_pubkeys))>
                            uint256 authKeyHash = ComputeAuthorityKeyHash(
                                g_usdsoq_authority.GetKeys());
                            authorityScriptCode.clear();
                            authorityScriptCode << OP_5;
                            authorityScriptCode << std::vector<unsigned char>(
                                authKeyHash.begin(), authKeyHash.end());
                        }
                        break;
                    }

                    // Fallback for bootstrap: if no tracked outpoint yet,
                    // find the input whose prevout is a v5 program.
                    if (localAuthOutpoint.IsNull()) {
                        const CCoins* coins = view.AccessCoins(txin.prevout.hash);
                        if (coins && coins->IsAvailable(txin.prevout.n)) {
                            const CScript& prevSpk = coins->vout[txin.prevout.n].scriptPubKey;
                            if (prevSpk.size() == 34 && prevSpk[0] == OP_5 && prevSpk[1] == 32) {
                                nAuthorityInputIndex = static_cast<int>(k);
                                authorityScriptCode = prevSpk;
                                break;
                            }
                        }
                    }
                }

                if (nAuthorityInputIndex >= 0 && !tx.vin[nAuthorityInputIndex].scriptWitness.IsNull()) {
                    const CScriptWitness& authWitness = tx.vin[nAuthorityInputIndex].scriptWitness;

                    // Step 2: Extract signatures from the witness stack
                    std::vector<std::vector<uint8_t>> sigs = ExtractUSDSOQWitnessSignatures(authWitness.stack);

                    if (sigs.empty()) {
                        return state.DoS(100,
                            error("ConnectBlock(): USDSOQ authority tx %s has no signatures in witness",
                                tx.GetHash().ToString()),
                            REJECT_INVALID, "bad-usdsoq-authority-sig");
                    }

                    // Step 3: Compute BIP143 sighash for the authority input
                    // SECURITY: Uses SIGHASH_ALL to bind the signature to ALL
                    // inputs and outputs, preventing amount/destination tampering.
                    PrecomputedTransactionData txdata(tx);
                    uint256 sighash = SignatureHash(
                        authorityScriptCode, tx,
                        nAuthorityInputIndex, SIGHASH_ALL,
                        CAmount(0),  // Authority UTXOs are 0-value
                        SIGVERSION_WITNESS_V0, &txdata);

                    // Step 4: Verify M-of-N Dilithium authority signatures
                    std::vector<uint8_t> sighashBytes(sighash.begin(), sighash.end());
                    if (!g_usdsoq_authority.VerifyAuthoritySignatures(sighashBytes, sigs)) {
                        return state.DoS(100,
                            error("ConnectBlock(): USDSOQ authority signature verification "
                                  "FAILED for tx %s at block %d (M-of-N threshold not met)",
                                tx.GetHash().ToString(), pindex->nHeight),
                            REJECT_INVALID, "bad-usdsoq-authority-sig");
                    }

                    LogPrintf("USDSOQ: Authority signature verified for tx %s "
                              "(%u valid sigs, threshold=%u) at block %d\n",
                        tx.GetHash().ToString(), sigs.size(),
                        g_usdsoq_authority.GetThreshold(), pindex->nHeight);

                    // Step 5: Update tracked authority outpoint to the new
                    // authority output in this transaction (continues the chain).
                    // Guard with !fJustCheck to prevent TestBlockValidity from
                    // polluting the global during block template testing.
                    if (nAuthorityOutputIndex >= 0) {
                        COutPoint prevAuthOutpoint = localAuthOutpoint;
                        localAuthOutpoint = COutPoint(tx.GetHash(), nAuthorityOutputIndex);

                        // Persist to LevelDB (only when committing)
                        // SOQ-I013: collect, do not write. The !fJustCheck
                        // guard is gone deliberately — the pending value is
                        // harmless in a dry run and the commit site downstream
                        // is already behind `if (fJustCheck) return true`.
                        usdsoqPendingOutpoint = localAuthOutpoint;
                        usdsoqCommitOutpoint = true;

                        LogPrintf("USDSOQ: Authority outpoint updated: %s:%u → %s:%u\n",
                            prevAuthOutpoint.hash.ToString(), prevAuthOutpoint.n,
                            localAuthOutpoint.hash.ToString(),
                            localAuthOutpoint.n);
                    }
                } else if (nAuthorityInputIndex < 0) {
                    if (localAuthOutpoint.IsNull()) {
                        // BOOTSTRAP: No tracked outpoint yet (first authority TX).
                        //
                        // H2 FIX (June 3, 2026): Check LevelDB for a previously-set
                        // outpoint. If one exists but in-memory is null (corruption,
                        // partial -reindex), reject bootstrap to prevent re-entry.
                        if (pcoinsdbview) {
                            COutPoint dbOutpoint;
                            if (pcoinsdbview->ReadUSDSOQAuthorityOutpoint(dbOutpoint) &&
                                !dbOutpoint.IsNull()) {
                                return state.DoS(100,
                                    error("ConnectBlock(): USDSOQ bootstrap re-entry "
                                          "rejected — authority outpoint already exists "
                                          "in DB (%s:%u) but in-memory is null. "
                                          "Run -reindex to repair.",
                                        dbOutpoint.hash.ToString(), dbOutpoint.n),
                                    REJECT_INVALID, "bad-usdsoq-bootstrap-reentry");
                            }
                        }

                        // Use input 0 as the authority witness carrier.
                        // The sighash is computed against the authority output script
                        // since there's no prevout scriptPubKey to use.
                        nAuthorityInputIndex = 0;
                        authorityScriptCode = tx.vout[nAuthorityOutputIndex].scriptPubKey;

                        // Verify authority signatures for bootstrap
                        if (!tx.vin[0].scriptWitness.IsNull()) {
                            const CScriptWitness& bsWitness = tx.vin[0].scriptWitness;
                            std::vector<std::vector<uint8_t>> bsSigs =
                                ExtractUSDSOQWitnessSignatures(bsWitness.stack);

                            if (!bsSigs.empty()) {
                                PrecomputedTransactionData bsTxdata(tx);
                                uint256 bsSighash = SignatureHash(
                                    authorityScriptCode, tx, 0, SIGHASH_ALL,
                                    CAmount(0), SIGVERSION_WITNESS_V0, &bsTxdata);

                                std::vector<uint8_t> bsSighashBytes(bsSighash.begin(), bsSighash.end());
                                if (!g_usdsoq_authority.VerifyAuthoritySignatures(bsSighashBytes, bsSigs)) {
                                    return state.DoS(100,
                                        error("ConnectBlock(): USDSOQ bootstrap authority sig "
                                              "verification FAILED for tx %s",
                                            tx.GetHash().ToString()),
                                        REJECT_INVALID, "bad-usdsoq-authority-sig");
                                }

                                LogPrintf("USDSOQ: Bootstrap authority tx %s verified "
                                          "(%u sigs, threshold=%u)\n",
                                    tx.GetHash().ToString(), bsSigs.size(),
                                    g_usdsoq_authority.GetThreshold());

                                // Update local outpoint tracker (always)
                                if (nAuthorityOutputIndex >= 0) {
                                    localAuthOutpoint = COutPoint(
                                        tx.GetHash(), nAuthorityOutputIndex);
                                    // Persist to global + LevelDB only when committing
                                    if (!fJustCheck && pcoinsdbview) {
                                        usdsoqPendingOutpoint = localAuthOutpoint;   // SOQ-I013
                                        usdsoqCommitOutpoint = true;
                                    }
                                    LogPrintf("USDSOQ: Bootstrap authority outpoint set: %s:%u\n",
                                        localAuthOutpoint.hash.ToString(),
                                        localAuthOutpoint.n);
                                }
                            } else {
                                return state.DoS(100,
                                    error("ConnectBlock(): USDSOQ bootstrap tx %s has "
                                          "no authority signatures",
                                        tx.GetHash().ToString()),
                                    REJECT_INVALID, "bad-usdsoq-authority-sig");
                            }
                        } else {
                            return state.DoS(100,
                                error("ConnectBlock(): USDSOQ bootstrap tx %s has "
                                      "no witness on input 0",
                                    tx.GetHash().ToString()),
                                REJECT_INVALID, "bad-usdsoq-authority-sig");
                        }
                    } else {
                        // Authority TX detected but no authority input found.
                        // This means the TX has an OP_5 output but doesn't spend
                        // the tracked authority UTXO.
                        //
                        // HEIGHT GATE: Only enforce strict authority-input-spending
                        // for blocks AFTER the deployment height. Blocks before this
                        // height were mined under old rules where authority TXs could
                        // bootstrap without spending a previous authority UTXO.
                        // Without this gate, nodes replaying from genesis get stuck
                        // at the first post-bootstrap authority TX (BUG-16).
                        // SOQ-I008: this was a hardcoded `static const int =
                        // 54300`, a stagenet calibration applied to every
                        // network. It is now a chain parameter (stagenet 54300,
                        // everywhere else 0), so a fresh mainnet enforces the
                        // authority-UTXO chain from genesis instead of leaving
                        // it off for its first 54,300 blocks.
                        if (pindex->nHeight >= consensus.nUSDSOQAuthorityInputEnforcementHeight) {
                            return state.DoS(100,
                                error("ConnectBlock(): USDSOQ authority tx %s does not spend "
                                      "the tracked authority UTXO (expected %s:%u)",
                                    tx.GetHash().ToString(),
                                    localAuthOutpoint.hash.ToString(),
                                    localAuthOutpoint.n),
                                REJECT_INVALID, "bad-usdsoq-authority-outpoint");
                        }
                        // Pre-enforcement: update the authority outpoint from the
                        // OP_5 output to keep the chain tracking consistent.
                        if (nAuthorityOutputIndex >= 0) {
                            localAuthOutpoint = COutPoint(
                                tx.GetHash(), nAuthorityOutputIndex);
                            if (!fJustCheck && pcoinsdbview) {
                                usdsoqPendingOutpoint = localAuthOutpoint;   // SOQ-I013
                                usdsoqCommitOutpoint = true;
                            }
                            LogPrintf("USDSOQ: Pre-enforcement authority outpoint "
                                      "updated: %s:%u (height %d)\n",
                                localAuthOutpoint.hash.ToString(),
                                localAuthOutpoint.n, pindex->nHeight);
                        }
                    }
                    }
                } // end height gate else
            }

            // =============================================================
            // SOQ-FREEZE: Apply freeze/unfreeze op from authority TX.
            // After authority signature verification succeeds, parse the
            // OP_RETURN for a freeze-registry payload and update the
            // DB-backed frozen set.
            // Guard: only when committing (!fJustCheck), authority is
            // initialized, and we are past the enforcement height.
            // =============================================================
            // SOQ-I013: `!fJustCheck` REMOVED from this guard deliberately.
            // With it, freeze validation ran only on a real connect, so
            // TestBlockValidity could not see an in-block freeze while
            // ConnectBlock could — a template dry-run accepted a
            // freeze-then-spend block that the real connect then rejected, which
            // is the BUG-18 template-stalling shape. Validation must run in both
            // passes; only the WRITE is deferred, and its commit site is already
            // behind `if (fJustCheck) return true`.
            if (isAuthorityTx && pcoinsdbview &&
                g_usdsoq_authority.IsInitialized() &&
                pindex->nHeight >= consensus.nUSDSOQAuthorityEnforcementHeight) {
                uint8_t freezeOp = 0;
                COutPoint freezeTarget;
                if (ParseUSDSOQFreezeOp(tx, freezeOp, freezeTarget)) {
                    if (freezeOp == FREEZE_OP_FREEZE) {
                        // Q3: Defense-in-depth — require target to be a live
                        // USDSOQ UTXO. Skip + log if not (don't reject the
                        // block — the authority TX itself is valid).
                        // IsAnyUSDSOQ(), not IsUSDSOQ(): freeze targets an OUTPOINT, so it
                        // is the one compliance control that still works when the amount is
                        // hidden. With the v7-only predicate a v10 confidential USDSOQ
                        // outpoint could never be frozen — the op was silently skipped and
                        // logged as "not a live USDSOQ UTXO", so the issuer's GENIUS Act
                        // §4(a)(2) freeze authority did not reach Tier A at all.
                        // ⛔ WAS FAIL-OPEN. A FREEZE naming a target that is not
                        // a live USDSOQ UTXO used to be skipped with a log line,
                        // so the issuer believed a coin was frozen when consensus
                        // had ignored the op. BTCSOQ rejects the same condition.
                        // A compliance control that silently no-ops is worse than
                        // one that is absent, because it reports success.
                        const CCoins* targetCoins = view.AccessCoins(freezeTarget.hash);
                        if (!targetCoins || !targetCoins->IsAvailable(freezeTarget.n) ||
                            !targetCoins->vout[freezeTarget.n].IsAnyUSDSOQ()) {
                            return state.DoS(100,
                                error("ConnectBlock(): USDSOQ FREEZE target %s:%u is not a "
                                      "live USDSOQ UTXO at block %d",
                                    freezeTarget.hash.ToString(), freezeTarget.n,
                                    pindex->nHeight),
                                REJECT_INVALID, "bad-usdsoq-freeze-dead-target");
                        }
                        // ⛔ IDEMPOTENCY. The undo in DisconnectBlock inverts
                        // blindly: FREEZE becomes an erase, UNFREEZE becomes a
                        // write, with no record of the prior state. So a FREEZE
                        // of an ALREADY-frozen outpoint was a no-op on the way in
                        // and an UNFREEZE on the way out — a reorg silently
                        // lifted a freeze that predated the block. Requiring a
                        // real state transition makes every op exactly one
                        // change, which makes the blind inversion exactly right,
                        // and makes the op mean something on-chain instead of
                        // possibly nothing.
                        if (usdsoqBlockFrozenAdd.count(freezeTarget) ||
                            (usdsoqBlockFrozenRemove.count(freezeTarget) == 0 &&
                             pcoinsdbview && pcoinsdbview->IsFrozenOutpoint(freezeTarget))) {
                            return state.DoS(100,
                                error("ConnectBlock(): USDSOQ FREEZE of already-frozen "
                                      "outpoint %s:%u at block %d",
                                    freezeTarget.hash.ToString(), freezeTarget.n,
                                    pindex->nHeight),
                                REJECT_INVALID, "bad-usdsoq-freeze-redundant");
                        }
                        usdsoqBlockFrozenAdd.insert(freezeTarget);
                        usdsoqBlockFrozenRemove.erase(freezeTarget);
                        usdsoqPendingFreezeOps.emplace_back(FREEZE_OP_FREEZE, freezeTarget);
                    } else if (freezeOp == FREEZE_OP_UNFREEZE) {
                        if (usdsoqBlockFrozenRemove.count(freezeTarget) ||
                            (usdsoqBlockFrozenAdd.count(freezeTarget) == 0 &&
                             !(pcoinsdbview && pcoinsdbview->IsFrozenOutpoint(freezeTarget)))) {
                            return state.DoS(100,
                                error("ConnectBlock(): USDSOQ UNFREEZE of an outpoint that "
                                      "is not frozen %s:%u at block %d",
                                    freezeTarget.hash.ToString(), freezeTarget.n,
                                    pindex->nHeight),
                                REJECT_INVALID, "bad-usdsoq-unfreeze-redundant");
                        }
                        usdsoqBlockFrozenRemove.insert(freezeTarget);
                        usdsoqBlockFrozenAdd.erase(freezeTarget);
                        usdsoqPendingFreezeOps.emplace_back(FREEZE_OP_UNFREEZE, freezeTarget);
                    }
                }
            }

            // Frozen-UTXO guard (registry): reject any spend of a frozen USDSOQ
            // outpoint. Reads prevouts from the block UNDO data, NOT the coins
            // view, because by this second pass UpdateCoins (first pass) has
            // already spent every input — the same reason the burn loop below
            // reads undo. This runs in fJustCheck too, so TestBlockValidity
            // rejects a template carrying a frozen spend.
            //
            // e2n FIX: the previous freeze guard here iterated the coins VIEW and
            // bailed via `!coins->IsAvailable() → continue` on every (already
            // spent) input — it was DEAD CODE, so freeze was enforced ONLY at
            // mempool (BUG-22, the ATMP mirror). A miner assembling a block
            // off-mempool could therefore spend a frozen coin. Reading undo makes
            // consensus enforcement LIVE, matching the ATMP check. Applies to ALL
            // txs (a freeze blocks even an authority burn of that outpoint),
            // USDSOQ prevouts only. Input-type isolation formerly co-located here
            // now lives in Consensus::CheckTxInputs (Option B), enforced live in
            // both the connect and mempool paths from one chokepoint.
            if (i > 0 && (i - 1) < blockundo.vtxundo.size()) {
                const CTxUndo& txundoFreeze = blockundo.vtxundo[i - 1];
                for (unsigned int j = 0;
                     j < tx.vin.size() && j < txundoFreeze.vprevout.size(); j++) {
                    const CTxOut& prevOut = txundoFreeze.vprevout[j].txout;

                    // SOQ-I015: marker-chain guard. Only an authority tx may
                    // spend a v5 marker UTXO.
                    //
                    // BTCSOQ has had the equivalent rule at three layers since
                    // Step 2D (bad-btcsoq-marker-spend, plus an ATMP mirror and a
                    // script-layer default-deny). USDSOQ had it at none, and the
                    // v5 spend path never required authority: CheckInputs' skip
                    // needs an OP_5 OUTPUT, so a tx that only SPENDS the marker
                    // runs its scripts normally; VerifyScript then routes v5 to
                    // EvalScript's handler, which checks STRUCTURE ONLY (a
                    // one-byte tag, a non-empty payload, one correctly sized
                    // blob) and pushes true; and ConnectBlock's M-of-N check
                    // only ever ran for txs that CREATE an OP_5 output. Every
                    // witness element was fabricable from public data.
                    //
                    // The loss is not the marker's value. g_usdsoq_authority_
                    // outpoint advances only on authority txs, so it kept
                    // pointing at the spent marker and every later authority tx
                    // died at input resolution with
                    // bad-txns-inputs-missingorspent. USDSOQ mint, burn and
                    // freeze were dead from that block on, for one ordinary
                    // transaction, by anyone — and recovery was not an on-chain
                    // operation, because every on-chain authority operation
                    // needs the marker that was just destroyed.
                    if (prevOut.scriptPubKey.size() == 34 &&
                        prevOut.scriptPubKey[0] == OP_5 &&
                        prevOut.scriptPubKey[1] == 32 &&
                        !isAuthorityTx) {
                        return state.DoS(100,
                            error("ConnectBlock(): non-authority tx %s spends USDSOQ "
                                  "authority marker %s:%u",
                                tx.GetHash().ToString(),
                                tx.vin[j].prevout.hash.ToString(), tx.vin[j].prevout.n),
                            REJECT_INVALID, "bad-usdsoq-marker-spend");
                    }

                    // IsAnyUSDSOQ(): the SOQ-ARCH-004 block below states that freeze
                    // "works on a confidential output whose amount is hidden". With the
                    // v7-only predicate here that was not true — a frozen v10 outpoint
                    // was spendable. Widened so the claim and the code agree.
                    if (prevOut.IsAnyUSDSOQ() && pcoinsdbview &&
                        // SOQ-I013: consult the in-block overlay as well as the
                        // committed DB, so a freeze earlier in THIS block binds a
                        // later spend in the same block, in both passes.
                        ((usdsoqBlockFrozenAdd.count(tx.vin[j].prevout) > 0) ||
                         (usdsoqBlockFrozenRemove.count(tx.vin[j].prevout) == 0 &&
                          pcoinsdbview->IsFrozenOutpoint(tx.vin[j].prevout)))) {
                        return state.DoS(100,
                            error("ConnectBlock(): attempt to spend frozen USDSOQ UTXO %s:%u"
                                  " (registry)",
                                tx.vin[j].prevout.hash.ToString(), tx.vin[j].prevout.n),
                            REJECT_INVALID, "bad-txns-spend-frozen-usdsoq");
                    }
                }
            }

            // Track supply deltas for USDSOQ outputs in this block
            for (const auto& txout : tx.vout) {
                // IsAnyUSDSOQ() = transparent v7 OR confidential v10.
                //
                // ⛔ THIS PREDICATE WAS `IsUSDSOQ()` (v7 only) AND THAT MADE THE WHOLE
                // BLOCK BELOW DEAD CODE. Classification is structural: scriptPubKey[0] is
                // one opcode, so an output cannot be both v7 and v4, and every
                // `txout.IsConfidential()` test inside a v7-gated loop was unreachable.
                // Confidential USDSOQ was not representable at all until witness v10 was
                // allocated (v6 was tried first and collided with P2WSH-Dilithium). See doc/design/DL-SOQUOBSCURA-ASSET-TYPE-TRACE.md.
                if (txout.IsAnyUSDSOQ()) {
                    // =========================================================
                    // SOQ-ARCH-004: Confidential Compliant USDSOQ
                    //
                    // Design (founder-approved 2026-06-07):
                    //   - Authority TXs (mint/burn/freeze/rotate): MUST be transparent.
                    //     Supply auditability (GENIUS Act §4(a)(2)) requires visible
                    //     mint/burn amounts.
                    //   - User-to-user transfers: MAY be confidential (v10) once the
                    //     SoquObscura privacy layer is active. Range proofs prevent
                    //     inflation; transfers do not move supply.
                    //
                    // Asset and confidentiality both live in the witness version, so the
                    // two are decided by ONE byte and cannot disagree:
                    //     v7 = USDSOQ transparent      (IsUSDSOQ)
                    //     v10 = USDSOQ confidential    (IsV10ConfidentialUSDSOQ)
                    //     v4 = SOQ confidential        (Tier B, not this loop)
                    // Freeze state is NOT an output field; it lives in DB_USDSOQ_FROZEN,
                    // and freezing targets an outpoint, so it works on a confidential
                    // output whose amount is hidden.
                    //
                    // Adversarial notes:
                    //   - Inflation:    range proofs bound each committed amount
                    //   - Hidden mint:  authority transparency blocks stealth inflation
                    //   - Hidden burn:  authority transparency blocks stealth deflation
                    //   - Freeze evade: freeze targets the outpoint, not the value
                    // =========================================================
                    if (isAuthorityTx && txout.IsConfidential()) {
                        // Authority operations MUST be transparent for supply
                        // auditability. Mint/burn/freeze/rotate create the supply
                        // boundary; if these are hidden the supply invariant breaks.
                        return state.DoS(100,
                            error("ConnectBlock(): USDSOQ authority output %s:%u is confidential "
                                  "(v10) — authority TXs must be transparent "
                                  "(GENIUS Act §4(a)(2), SOQ-ARCH-004)",
                                tx.GetHash().ToString(), (&txout - &tx.vout[0])),
                            REJECT_INVALID, "bad-txns-usdsoq-authority-must-be-transparent");
                    }

                    if (!isAuthorityTx && txout.IsConfidential()) {
                        // User-to-user confidential USDSOQ transfer, allowed IF:
                        //   1. the SoquObscura privacy layer is active (BIP9)
                        //   2. range proofs are valid (checked in the section below)
                        //   3. commitment balance is preserved (sum_in == sum_out)
                        //
                        // This is the rule that fires for a pre-activation v10 output
                        // on a chain where USDSOQ is active (the test nets). Until
                        // 2026-09 it was SHADOWED by SOQ-ARCH-001, a generic all-assets
                        // rejection of confidential outputs that ran earlier in this
                        // ConnectBlock on the same flags; that rule was retired with
                        // the additive-asset genesis door (a dormant v4/v10 shape is
                        // plain anyone-can-spend SOQ, and rejecting its CREATION made
                        // SoquObscura activation a hard fork). This asset-specific
                        // backstop stays: it is gated on USDSOQ being active, so it is
                        // a tightening the activation release keeps, and it keeps the
                        // Tier A path fail-closed until the privacy layer is live.
                        // Pinned by usdsoq_v10_reject_path_tests::
                        // preactivation_v10_output_is_rejected_by_the_usdsoq_rule.
                        if (!(flags & SCRIPT_VERIFY_SOQUOBSCURA)) {
                            return state.DoS(100,
                                error("ConnectBlock(): USDSOQ confidential output %s:%u before "
                                      "SoquObscura activation — privacy layer required "
                                      "(SOQ-ARCH-004)",
                                    tx.GetHash().ToString(), (&txout - &tx.vout[0])),
                                REJECT_INVALID, "bad-txns-usdsoq-confidential-not-active");
                        }
                        // ⚠️ WI-3 ATTACHES HERE. This is the point at which a v10 output is
                        // accepted, and it is where the MANDATORY issuer disclosure must be
                        // required and verified: reject unless the output carries a valid
                        // issuer-targeted verifiable-encryption payload whose proof binds
                        // this output's commitment. Until that lands, a v10 output is
                        // accepted with NO auditor payload, which is Tier A without its
                        // compliance rule. Bead soqucoin-build-soquobscura-ve-wi3-8r6e.
                        // Do NOT activate the deployment for USDSOQ before it does.
                    }

                    // BUG-19: ONLY authority txs (mint/burn/freeze/rotate — OP_5 marker)
                    // change the USDSOQ supply. A plain user transfer re-emits existing
                    // USDSOQ in its outputs and MUST be supply-neutral. Counting every
                    // transparent USDSOQ output as "minted" inflated the supply by the
                    // transfer amount on every send (the input-burn loop below can't offset
                    // it — inputs are already spent in the view by the time it runs, so
                    // nUSDSOQBurned is always 0 here). That inflated supply then made block
                    // templates carrying a USDSOQ send fail validation → the pool mined empty
                    // blocks. Gate minting on isAuthorityTx so only real mints move the counter.
                    //
                    // v10 cannot reach this: a confidential authority output is rejected
                    // above, and IsTransparent() is false for v10 regardless. Supply
                    // tracking therefore stays anchored to the transparent mint/burn
                    // boundary, which is exactly what GENIUS Act §4(a)(2) auditability
                    // requires.
                    if (isAuthorityTx && txout.IsTransparent()) {
                        nUSDSOQMinted += txout.nValue;
                    }
                }
            }

            // Track USDSOQ inputs being spent (consumed supply) — AUTHORITY txs only.
            //
            // BUG-20: a burn is an authority tx that destroys USDSOQ; a plain transfer is
            // supply-neutral (its v7 output is NOT counted as minted, per BUG-19 above), so
            // its inputs must NOT be counted as burned either. Only authority txs move supply.
            //
            // The inputs are already spent in the coins view by now (UpdateCoins ran in the
            // first pass over the block), so the old `view.AccessCoins(...)->IsAvailable`
            // read here always hit the spent branch and nUSDSOQBurned was silently always 0 —
            // meaning burns could never decrement the supply. Read the original prevouts from
            // the block undo instead (the same source DisconnectBlock uses), so burns are
            // counted correctly AND connect/disconnect stay symmetric on reorg.
            if (isAuthorityTx && i > 0 && (i - 1) < blockundo.vtxundo.size()) {
                const CTxUndo& txundo = blockundo.vtxundo[i - 1];
                for (unsigned int j = 0; j < tx.vin.size() && j < txundo.vprevout.size(); j++) {
                    const CTxOut& prevOut = txundo.vprevout[j].txout;
                    // ⛔ n1vf: THIS PREDICATE WAS `IsUSDSOQ()` (v7 only), WHICH MADE THE
                    // REJECT BELOW STRUCTURALLY UNREACHABLE — the second instance of the
                    // SOQ-ARCH-004 dead-rule pattern, in the INPUT loop this time. v7 is
                    // one opcode and confidentiality is another, so `IsUSDSOQ() &&
                    // IsConfidential()` is the empty set and "bad-txns-usdsoq-conf-input"
                    // could never fire. Its own error text says the state "should not
                    // exist"; what did not exist was the rule. Widening to IsAnyUSDSOQ()
                    // makes it live: an authority tx that spends a CONFIDENTIAL USDSOQ
                    // input is now rejected, which is what supply auditability requires —
                    // nUSDSOQBurned is a plaintext sum, so a hidden burn amount would
                    // silently desynchronise the supply counter from the chain.
                    if (prevOut.IsAnyUSDSOQ()) {
                        // Authority operations must move supply across a TRANSPARENT
                        // boundary in both directions: mint is gated on IsTransparent()
                        // in the output loop above, burn is gated here.
                        if (prevOut.IsConfidential()) {
                            return state.DoS(100,
                                error("ConnectBlock(): spending confidential USDSOQ input %s:%u"
                                      " — should not exist",
                                    tx.vin[j].prevout.hash.ToString(), tx.vin[j].prevout.n),
                                REJECT_INVALID, "bad-txns-usdsoq-conf-input");
                        }
                        nUSDSOQBurned += prevOut.nValue;
                    }
                }
            }
        }

        // SOQ-AUD2-002 D1: Apply the USDSOQ supply delta to the global counter + LevelDB.
        //
        // BUG-18: ConnectBlock runs with fJustCheck=true for VALIDATION-ONLY dry-runs
        // (TestBlockValidity, called by CreateNewBlock on every getblocktemplate poll).
        // The old code mutated the GLOBAL g_usdsoq_supply here unconditionally and only
        // gated the LevelDB persist on !fJustCheck — so each template poll leaked the
        // in-memory counter with no rollback. After ~140 polls the supply inflated far
        // past reality, TestBlockValidity then failed, and the pool fell back to mining
        // empty (coinbase-only) blocks — blocking ALL USDSOQ tx confirmation.
        //
        // Fix: validate the delta on a COPY (so overflow/underflow is still detected
        // against the real current supply on every path), and COMMIT to the global +
        // LevelDB ONLY on a real connect (!fJustCheck). A discarded dry-run now leaves
        // the global untouched. DisconnectBlock reverses the committed delta on reorg.
        if (nUSDSOQMinted > 0 || nUSDSOQBurned > 0) {
            CUSDSOQSupply supplyAfter = g_usdsoq_supply; // value copy
            if (nUSDSOQMinted > 0 && !supplyAfter.Mint(nUSDSOQMinted)) {
                return state.DoS(100,
                    error("ConnectBlock(): USDSOQ supply overflow on mint of %d at block %d",
                        nUSDSOQMinted, pindex->nHeight),
                    REJECT_INVALID, "bad-usdsoq-supply-overflow");
            }
            if (nUSDSOQBurned > 0 && !supplyAfter.Burn(nUSDSOQBurned)) {
                return state.DoS(100,
                    error("ConnectBlock(): USDSOQ supply underflow on burn of %d at block %d",
                        nUSDSOQBurned, pindex->nHeight),
                    REJECT_INVALID, "bad-usdsoq-supply-underflow");
            }

            LogPrintf("USDSOQ: block %d supply delta: minted=%d burned=%d net=%d%s\n",
                pindex->nHeight, nUSDSOQMinted, nUSDSOQBurned,
                nUSDSOQMinted - nUSDSOQBurned, fJustCheck ? " (dry-run, not committed)" : "");

            if (!fJustCheck) {
                usdsoqPendingSupply = supplyAfter;   // SOQ-I013: commit after Wait
                usdsoqCommitSupply = true;
                LogPrintf("USDSOQ: supply state: total_minted=%d total_burned=%d outstanding=%d\n",
                    g_usdsoq_supply.TotalMinted(), g_usdsoq_supply.TotalBurned(),
                    g_usdsoq_supply.Outstanding());
            }
        }
    }

    // =========================================================================
    // DL-BTCSOQ-CONSENSUS-NATIVE: BTCSOQ Consensus Enforcement
    // Parallel sibling of the USDSOQ block above — the audited USDSOQ path is
    // untouched; BTCSOQ routes on its own unforgeable witness-v9 authority
    // marker (OP_9 <32>). When DEPLOYMENT_BTCSOQ is active, enforce:
    //   1. M-of-N ML-DSA-44 authority signature verification
    //   2. Authority UTXO chain tracking (Option D pattern; STRICT — no
    //      legacy input-enforcement window: BTCSOQ has no legacy chain)
    //   3. The signed OP_RETURN op envelope (tag + payload are sighash-covered;
    //      the witness tag must EQUAL the signed tag)
    //   4. MINT deposit binding: exactly one v8 output, value == payload sats,
    //      SHA256(recipient scriptPubKey) == payload commitment, and the
    //      (btc_txid, btc_vout) deposit never minted before (DB set + in-block
    //      set). A missed check here is a double mint = supply inflation.
    //   5. BURN binding: signed release intent sats == v8 input sum burned.
    //   6. Frozen v8 UTXO spend rejection (undo-based, live in fJustCheck)
    //   7. Per-block supply delta (copy-validate, commit iff !fJustCheck)
    // Asset-flow/op binding: v8 outputs REQUIRE the signed MINT tag and v8
    // inputs REQUIRE the signed BURN tag, so no authority op can move supply
    // outside its declared, signed operation.
    //
    // COMMIT DISCIPLINE (review finding, 2C): this block only VALIDATES and
    // collects side effects into the btcsoqPending* containers below. Nothing
    // is written to LevelDB or the globals here — the commit happens in one
    // place after EVERY ConnectBlock gate has passed (just after the
    // fJustCheck early-return). Direct mid-validation writes could otherwise
    // permanently strand a Bitcoin deposit in the minted set and inflate the
    // supply counter on a block that fails a LATER check (e.g. UTXO_COST) and
    // is never connected.
    // =========================================================================
    std::vector<COutPoint> btcsoqPendingMintedDeposits;
    std::vector<std::pair<uint8_t, COutPoint>> btcsoqPendingFreezeOps;
    bool btcsoqCommitSupply = false;
    CBTCSOQSupply btcsoqPendingSupply;
    bool btcsoqCommitOutpoint = false;
    COutPoint btcsoqPendingOutpoint;
    if (flags & SCRIPT_VERIFY_BTCSOQ) {
        CAmount nBTCSOQMinted = 0;
        CAmount nBTCSOQBurned = 0;

        // Local authority outpoint tracker (fJustCheck-safe, mirrors USDSOQ).
        COutPoint localBTCSOQAuthOutpoint = g_btcsoq_authority_outpoint;

        // In-block anti-replay: two MINTs binding the same Bitcoin deposit in
        // ONE block would each pass the (not-yet-written) DB check alone.
        std::set<COutPoint> blockMintedDeposits;

        // In-block freeze view: FREEZE/UNFREEZE ops earlier in this block must
        // be visible to the frozen-spend guard for later txs in BOTH the
        // fJustCheck and real passes (review finding: consulting only the
        // committed DB made TestBlockValidity accept a freeze-then-spend block
        // that a real connect rejected).
        std::set<COutPoint> blockFrozenAdd;
        std::set<COutPoint> blockFrozenRemove;

        for (unsigned int i = 0; i < block.vtx.size(); i++) {
            const CTransaction& tx = *(block.vtx[i]);
            if (tx.IsCoinBase()) continue;

            bool isBTCSOQAuthorityTx = false;
            int nBTCSOQAuthorityOutputIndex = -1;
            for (size_t j = 0; j < tx.vout.size(); ++j) {
                if (IsBTCSOQAuthorityMarker(tx.vout[j].scriptPubKey)) {
                    isBTCSOQAuthorityTx = true;
                    nBTCSOQAuthorityOutputIndex = static_cast<int>(j);
                    break;
                }
            }

            // Per-tx v8 sums. Outputs read from the tx; inputs read from the
            // block UNDO data — UpdateCoins (first pass) has already spent
            // every input in the coins view by this second pass (the BUG-20
            // lesson), and undo is the same source DisconnectBlock uses, so
            // connect and disconnect stay symmetric on reorg.
            CAmount nTxV8Out = 0;
            int nV8OutputIndex = -1;
            unsigned int nV8OutputCount = 0;
            for (size_t j = 0; j < tx.vout.size(); ++j) {
                if (tx.vout[j].IsBTCSOQ()) {
                    nTxV8Out += tx.vout[j].nValue;
                    nV8OutputIndex = static_cast<int>(j);
                    ++nV8OutputCount;
                }
            }
            CAmount nTxV8In = 0;
            if (i > 0 && (i - 1) < blockundo.vtxundo.size()) {
                const CTxUndo& txundoV8 = blockundo.vtxundo[i - 1];
                for (unsigned int j = 0;
                     j < tx.vin.size() && j < txundoV8.vprevout.size(); j++) {
                    const CTxOut& prevOut = txundoV8.vprevout[j].txout;
                    // Marker-chain guard: only a BTCSOQ authority tx may spend
                    // a v9 marker UTXO. Until Step 2D wires witness v9 into
                    // the interpreter, v9 programs are anyone-can-spend at the
                    // script layer — without this consensus check a miner
                    // could sever the authority outpoint chain.
                    if (IsBTCSOQAuthorityMarker(prevOut.scriptPubKey) &&
                        !isBTCSOQAuthorityTx) {
                        return state.DoS(100,
                            error("ConnectBlock(): non-authority tx %s spends BTCSOQ "
                                  "authority marker %s:%u",
                                tx.GetHash().ToString(),
                                tx.vin[j].prevout.hash.ToString(), tx.vin[j].prevout.n),
                            REJECT_INVALID, "bad-btcsoq-marker-spend");
                    }
                    if (!prevOut.IsBTCSOQ()) continue;
                    nTxV8In += prevOut.nValue;
                    // Frozen-registry guard: LIVE, undo-based (e2n pattern),
                    // applies to ALL txs (a freeze blocks even an authority
                    // burn of that outpoint), runs in fJustCheck too. The
                    // committed DB set is overlaid with this block's own
                    // freeze/unfreeze ops so both passes see the same state.
                    bool fFrozen = blockFrozenAdd.count(tx.vin[j].prevout) > 0 ||
                        (pcoinsdbview &&
                         pcoinsdbview->IsBTCSOQFrozen(tx.vin[j].prevout) &&
                         blockFrozenRemove.count(tx.vin[j].prevout) == 0);
                    if (fFrozen) {
                        return state.DoS(100,
                            error("ConnectBlock(): attempt to spend frozen BTCSOQ "
                                  "UTXO %s:%u (registry)",
                                tx.vin[j].prevout.hash.ToString(), tx.vin[j].prevout.n),
                            REJECT_INVALID, "bad-txns-spend-frozen-btcsoq");
                    }
                }
            }

            if (!isBTCSOQAuthorityTx) {
                // Non-authority tx: v8 conservation (in == out) was enforced in
                // Consensus::CheckTxInputs during the first pass. Nothing to do.
                continue;
            }

            // ------------------ BTCSOQ authority transaction ------------------

            // Default-deny: no configured authority ⇒ no valid authority tx.
            // (Deliberately STRICTER than USDSOQ, which skips verification when
            // uninitialized — BTCSOQ has no pre-authority history to tolerate.)
            if (!g_btcsoq_authority.IsInitialized()) {
                return state.DoS(100,
                    error("ConnectBlock(): BTCSOQ authority tx %s at block %d but the "
                          "authority key set is not initialized",
                        tx.GetHash().ToString(), pindex->nHeight),
                    REJECT_INVALID, "bad-btcsoq-authority-unavailable");
            }

            // Authority ops must be fully transparent (supply auditability —
            // the mint/burn boundary must never be hidden; GENIUS §4(a)(2)).
            for (const auto& txout : tx.vout) {
                if (txout.IsConfidential()) {
                    return state.DoS(100,
                        error("ConnectBlock(): BTCSOQ authority tx %s carries a "
                              "confidential (v4) output",
                            tx.GetHash().ToString()),
                        REJECT_INVALID, "bad-btcsoq-authority-must-be-transparent");
                }
            }

            if (pindex->nHeight < consensus.nBTCSOQAuthorityEnforcementHeight) {
                // Pre-enforcement window. Ships as 0 on EVERY network (BTCSOQ
                // has no legacy chain), so this branch is dead unless a future
                // stagenet drill sets it. SOQ-REINDEX-002 pattern: track the
                // outpoint locally only, never persist.
                LogPrintf("BTCSOQ: Pre-enforcement height %d < %d — skipping authority "
                          "verification for tx %s\n",
                    pindex->nHeight, consensus.nBTCSOQAuthorityEnforcementHeight,
                    tx.GetHash().ToString());
                if (nBTCSOQAuthorityOutputIndex >= 0) {
                    localBTCSOQAuthOutpoint = COutPoint(
                        tx.GetHash(), nBTCSOQAuthorityOutputIndex);
                }
            } else {
                // ---- Strict path (all networks, from genesis) ----

                // 1. The signed op envelope is MANDATORY. This is also where a
                //    ROTATE (0x62) or unknown tag fails: the parser recognizes
                //    only MINT/BURN/FREEZE until rotation semantics are wired.
                uint8_t btcsoqTag = 0;
                std::vector<uint8_t> btcsoqPayload;
                if (!ParseBTCSOQAuthorityOp(tx, btcsoqTag, btcsoqPayload)) {
                    return state.DoS(100,
                        error("ConnectBlock(): BTCSOQ authority tx %s lacks a single "
                              "well-formed op OP_RETURN",
                            tx.GetHash().ToString()),
                        REJECT_INVALID, "bad-btcsoq-missing-op");
                }

                // 2. Asset flows must match the signed op.
                if (nTxV8Out > 0 && btcsoqTag != BTCSOQ_OP_MINT) {
                    return state.DoS(100,
                        error("ConnectBlock(): BTCSOQ authority tx %s creates v8 outputs "
                              "under non-MINT op 0x%02x",
                            tx.GetHash().ToString(), btcsoqTag),
                        REJECT_INVALID, "bad-btcsoq-unbound-mint");
                }
                if (nTxV8In > 0 && btcsoqTag != BTCSOQ_OP_BURN) {
                    return state.DoS(100,
                        error("ConnectBlock(): BTCSOQ authority tx %s spends v8 inputs "
                              "under non-BURN op 0x%02x",
                            tx.GetHash().ToString(), btcsoqTag),
                        REJECT_INVALID, "bad-btcsoq-unbound-burn");
                }

                // 3. Find the authority input. STRICT: when an outpoint chain
                //    exists, the tx MUST spend it — there is no legacy
                //    "authority tx without authority input" window for BTCSOQ.
                int nAuthorityInputIndex = -1;
                CScript authorityScriptCode;
                if (!localBTCSOQAuthOutpoint.IsNull()) {
                    for (unsigned int k = 0; k < tx.vin.size(); ++k) {
                        if (tx.vin[k].prevout == localBTCSOQAuthOutpoint) {
                            nAuthorityInputIndex = static_cast<int>(k);
                            const CCoins* authCoins =
                                view.AccessCoins(tx.vin[k].prevout.hash);
                            if (authCoins && authCoins->IsAvailable(tx.vin[k].prevout.n)) {
                                authorityScriptCode =
                                    authCoins->vout[tx.vin[k].prevout.n].scriptPubKey;
                            } else if (i > 0 && (i - 1) < blockundo.vtxundo.size() &&
                                       k < blockundo.vtxundo[i - 1].vprevout.size()) {
                                // Already spent by UpdateCoins (first pass) —
                                // read the REAL prevout script from the block
                                // undo (review finding: recomputing
                                // OP_9 <keyhash> assumed the marker always
                                // carries the canonical keyhash; the undo
                                // prevout is the actual signed-against script
                                // and keeps consensus identical to the
                                // mempool mirror, which reads the live coin).
                                authorityScriptCode = blockundo.vtxundo[i - 1]
                                    .vprevout[k].txout.scriptPubKey;
                            } else {
                                return state.DoS(100,
                                    error("ConnectBlock(): BTCSOQ authority tx %s marker "
                                          "prevout unavailable in view and undo",
                                        tx.GetHash().ToString()),
                                    REJECT_INVALID, "bad-btcsoq-authority-sig");
                            }
                            break;
                        }
                    }
                    if (nAuthorityInputIndex < 0) {
                        return state.DoS(100,
                            error("ConnectBlock(): BTCSOQ authority tx %s does not spend "
                                  "the tracked authority UTXO (expected %s:%u)",
                                tx.GetHash().ToString(),
                                localBTCSOQAuthOutpoint.hash.ToString(),
                                localBTCSOQAuthOutpoint.n),
                            REJECT_INVALID, "bad-btcsoq-authority-outpoint");
                    }
                } else {
                    // BOOTSTRAP: first authority tx ever. H2 pattern: if
                    // LevelDB already has an outpoint while memory is null,
                    // this node's state is damaged — reject re-entry.
                    if (pcoinsdbview) {
                        COutPoint dbOutpoint;
                        if (pcoinsdbview->ReadBTCSOQAuthorityOutpoint(dbOutpoint) &&
                            !dbOutpoint.IsNull()) {
                            return state.DoS(100,
                                error("ConnectBlock(): BTCSOQ bootstrap re-entry rejected — "
                                      "authority outpoint already exists in DB (%s:%u) but "
                                      "in-memory is null. Run -reindex to repair.",
                                    dbOutpoint.hash.ToString(), dbOutpoint.n),
                                REJECT_INVALID, "bad-btcsoq-bootstrap-reentry");
                        }
                    }
                    // Input 0 carries the authority witness; the sighash is
                    // computed against the new v9 marker output script (no
                    // prior marker prevout exists).
                    nAuthorityInputIndex = 0;
                    authorityScriptCode =
                        tx.vout[nBTCSOQAuthorityOutputIndex].scriptPubKey;
                }

                // 4. Verify M-of-N ML-DSA-44 authority signatures over the
                //    BIP143 sighash (SIGHASH_ALL binds every input and output).
                if (tx.vin[nAuthorityInputIndex].scriptWitness.IsNull()) {
                    return state.DoS(100,
                        error("ConnectBlock(): BTCSOQ authority tx %s has no witness on "
                              "authority input %d",
                            tx.GetHash().ToString(), nAuthorityInputIndex),
                        REJECT_INVALID, "bad-btcsoq-authority-sig");
                }
                const CScriptWitness& authWitness =
                    tx.vin[nAuthorityInputIndex].scriptWitness;

                // The (unsigned) witness tag must agree with the signed
                // OP_RETURN tag — a single source of truth for the op selector.
                if (GetBTCSOQWitnessTag(authWitness.stack) != btcsoqTag) {
                    return state.DoS(100,
                        error("ConnectBlock(): BTCSOQ authority tx %s witness tag does "
                              "not match signed op tag 0x%02x",
                            tx.GetHash().ToString(), btcsoqTag),
                        REJECT_INVALID, "bad-btcsoq-tag-mismatch");
                }

                std::vector<std::vector<uint8_t>> sigs =
                    ExtractBTCSOQWitnessSignatures(authWitness.stack);
                if (sigs.empty()) {
                    return state.DoS(100,
                        error("ConnectBlock(): BTCSOQ authority tx %s has no signatures "
                              "in witness", tx.GetHash().ToString()),
                        REJECT_INVALID, "bad-btcsoq-authority-sig");
                }

                PrecomputedTransactionData btcsoqTxdata(tx);
                uint256 sighash = SignatureHash(
                    authorityScriptCode, tx,
                    nAuthorityInputIndex, SIGHASH_ALL,
                    CAmount(0),  // Authority marker UTXOs are 0-value
                    SIGVERSION_WITNESS_V0, &btcsoqTxdata);
                std::vector<uint8_t> sighashBytes(sighash.begin(), sighash.end());
                if (!g_btcsoq_authority.VerifyAuthoritySignatures(sighashBytes, sigs)) {
                    return state.DoS(100,
                        error("ConnectBlock(): BTCSOQ authority signature verification "
                              "FAILED for tx %s at block %d (M-of-N threshold not met)",
                            tx.GetHash().ToString(), pindex->nHeight),
                        REJECT_INVALID, "bad-btcsoq-authority-sig");
                }
                LogPrintf("BTCSOQ: Authority signature verified for tx %s "
                          "(%u sigs, threshold=%u, op=0x%02x) at block %d\n",
                    tx.GetHash().ToString(), sigs.size(),
                    g_btcsoq_authority.GetThreshold(), btcsoqTag, pindex->nHeight);

                // 5. Op-specific enforcement.
                if (btcsoqTag == BTCSOQ_OP_MINT) {
                    uint256 btcTxid, mintRecipient;
                    uint32_t btcVout = 0;
                    CAmount mintSats = 0;
                    if (!ParseBTCSOQMintPayload(btcsoqPayload, btcTxid, btcVout,
                                                mintSats, mintRecipient)) {
                        return state.DoS(100,
                            error("ConnectBlock(): BTCSOQ MINT tx %s has malformed payload",
                                tx.GetHash().ToString()),
                            REJECT_INVALID, "bad-btcsoq-mint-payload");
                    }
                    // Exactly ONE v8 output, worth exactly the attested sats,
                    // paying exactly the committed recipient script.
                    if (nV8OutputCount != 1) {
                        return state.DoS(100,
                            error("ConnectBlock(): BTCSOQ MINT tx %s has %u v8 outputs "
                                  "(exactly 1 required)",
                                tx.GetHash().ToString(), nV8OutputCount),
                            REJECT_INVALID, "bad-btcsoq-mint-outputs");
                    }
                    if (tx.vout[nV8OutputIndex].nValue != mintSats) {
                        return state.DoS(100,
                            error("ConnectBlock(): BTCSOQ MINT tx %s output value %d != "
                                  "attested deposit %d sats",
                                tx.GetHash().ToString(),
                                tx.vout[nV8OutputIndex].nValue, mintSats),
                            REJECT_INVALID, "bad-btcsoq-mint-amount");
                    }
                    if (ComputeBTCSOQRecipientCommitment(
                            tx.vout[nV8OutputIndex].scriptPubKey) != mintRecipient) {
                        return state.DoS(100,
                            error("ConnectBlock(): BTCSOQ MINT tx %s recipient script does "
                                  "not match the signed recipient commitment",
                                tx.GetHash().ToString()),
                            REJECT_INVALID, "bad-btcsoq-mint-recipient");
                    }
                    // Anti-replay: one Bitcoin deposit backs at most one mint,
                    // ever. Checked against the persisted set AND the in-block
                    // set; recorded only on a real connect.
                    COutPoint deposit(btcTxid, btcVout);
                    if (blockMintedDeposits.count(deposit) ||
                        (pcoinsdbview && pcoinsdbview->IsBTCSOQMinted(deposit))) {
                        return state.DoS(100,
                            error("ConnectBlock(): BTCSOQ MINT tx %s double-mints Bitcoin "
                                  "deposit %s:%u",
                                tx.GetHash().ToString(), btcTxid.ToString(), btcVout),
                            REJECT_INVALID, "bad-btcsoq-double-mint");
                    }
                    blockMintedDeposits.insert(deposit);
                    btcsoqPendingMintedDeposits.push_back(deposit);
                    LogPrintf("BTCSOQ: MINT verified — deposit %s:%u → %d base units "
                              "at block %d%s\n",
                        btcTxid.ToString(), btcVout, mintSats, pindex->nHeight,
                        fJustCheck ? " (dry-run)" : "");
                } else if (btcsoqTag == BTCSOQ_OP_BURN) {
                    uint256 releaseScriptHash;
                    CAmount burnSats = 0;
                    if (!ParseBTCSOQBurnPayload(btcsoqPayload, releaseScriptHash,
                                                burnSats)) {
                        return state.DoS(100,
                            error("ConnectBlock(): BTCSOQ BURN tx %s has malformed payload",
                                tx.GetHash().ToString()),
                            REJECT_INVALID, "bad-btcsoq-burn-payload");
                    }
                    if (nTxV8In <= 0) {
                        return state.DoS(100,
                            error("ConnectBlock(): BTCSOQ BURN tx %s burns no v8 inputs",
                                tx.GetHash().ToString()),
                            REJECT_INVALID, "bad-btcsoq-burn-empty");
                    }
                    // The signed release intent must equal the consensus burn.
                    if (nTxV8In != burnSats) {
                        return state.DoS(100,
                            error("ConnectBlock(): BTCSOQ BURN tx %s release intent %d != "
                                  "v8 input sum %d",
                                tx.GetHash().ToString(), burnSats, nTxV8In),
                            REJECT_INVALID, "bad-btcsoq-burn-amount");
                    }
                    LogPrintf("BTCSOQ: BURN verified — %d base units, release intent %s "
                              "at block %d%s\n",
                        burnSats, releaseScriptHash.ToString(), pindex->nHeight,
                        fJustCheck ? " (dry-run)" : "");
                } else if (btcsoqTag == BTCSOQ_OP_FREEZE) {
                    // Payload: [freeze_op:1][txid:32][vout:4 LE] — the USDSOQ
                    // freeze layout inside the BTCSOQ envelope.
                    uint8_t freezeOp = btcsoqPayload[0];
                    if (freezeOp != FREEZE_OP_FREEZE && freezeOp != FREEZE_OP_UNFREEZE) {
                        return state.DoS(100,
                            error("ConnectBlock(): BTCSOQ FREEZE tx %s has unknown "
                                  "freeze op 0x%02x",
                                tx.GetHash().ToString(), freezeOp),
                            REJECT_INVALID, "bad-btcsoq-freeze-payload");
                    }
                    uint256 freezeTxid;
                    memcpy(freezeTxid.begin(), &btcsoqPayload[1], 32);
                    uint32_t freezeVout = (uint32_t)btcsoqPayload[33]
                                        | ((uint32_t)btcsoqPayload[34] << 8)
                                        | ((uint32_t)btcsoqPayload[35] << 16)
                                        | ((uint32_t)btcsoqPayload[36] << 24);
                    COutPoint freezeTarget(freezeTxid, freezeVout);
                    // Decide the op's effect NOW, identically in both the
                    // fJustCheck and real passes; the DB apply is deferred to
                    // the single post-gate commit point.
                    if (freezeOp == FREEZE_OP_FREEZE) {
                        // ⛔ WAS FAIL-OPEN, and the USDSOQ side was fixed first,
                        // which briefly made this the asymmetric twin — the exact
                        // pattern SOQ-I012/I013/I015 all came from. A FREEZE
                        // naming a target that is not a live v8 UTXO used to be
                        // skipped with a log line, so the issuer believed a coin
                        // was frozen when consensus had ignored the op. A
                        // compliance control that silently no-ops is worse than
                        // one that is absent, because it reports success.
                        const CCoins* targetCoins = view.AccessCoins(freezeTarget.hash);
                        if (!targetCoins || !targetCoins->IsAvailable(freezeTarget.n) ||
                            !targetCoins->vout[freezeTarget.n].IsBTCSOQ()) {
                            return state.DoS(100,
                                error("ConnectBlock(): BTCSOQ FREEZE target %s:%u is not a "
                                      "live v8 UTXO at block %d",
                                    freezeTarget.hash.ToString(), freezeTarget.n,
                                    pindex->nHeight),
                                REJECT_INVALID, "bad-btcsoq-freeze-dead-target");
                        }
                        // ⛔ IDEMPOTENCY, same reasoning as the USDSOQ twin.
                        // DisconnectBlock inverts freeze ops blindly with no
                        // record of prior state, so a FREEZE of an ALREADY-frozen
                        // outpoint was a no-op inbound and an UNFREEZE outbound: a
                        // reorg silently lifted a freeze that predated the block.
                        // Requiring a real state transition makes every op exactly
                        // one change, which makes the blind inversion exactly
                        // right.
                        if (blockFrozenAdd.count(freezeTarget) ||
                            (blockFrozenRemove.count(freezeTarget) == 0 &&
                             pcoinsdbview && pcoinsdbview->IsBTCSOQFrozen(freezeTarget))) {
                            return state.DoS(100,
                                error("ConnectBlock(): BTCSOQ FREEZE of already-frozen "
                                      "outpoint %s:%u at block %d",
                                    freezeTarget.hash.ToString(), freezeTarget.n,
                                    pindex->nHeight),
                                REJECT_INVALID, "bad-btcsoq-freeze-redundant");
                        }
                        btcsoqPendingFreezeOps.emplace_back(FREEZE_OP_FREEZE, freezeTarget);
                        blockFrozenAdd.insert(freezeTarget);
                        blockFrozenRemove.erase(freezeTarget);
                        LogPrintf("BTCSOQ: FREEZE accepted — %s:%u at block %d%s\n",
                            freezeTarget.hash.ToString(), freezeTarget.n,
                            pindex->nHeight, fJustCheck ? " (dry-run)" : "");
                    } else {
                        if (blockFrozenRemove.count(freezeTarget) ||
                            (blockFrozenAdd.count(freezeTarget) == 0 &&
                             !(pcoinsdbview && pcoinsdbview->IsBTCSOQFrozen(freezeTarget)))) {
                            return state.DoS(100,
                                error("ConnectBlock(): BTCSOQ UNFREEZE of an outpoint that "
                                      "is not frozen %s:%u at block %d",
                                    freezeTarget.hash.ToString(), freezeTarget.n,
                                    pindex->nHeight),
                                REJECT_INVALID, "bad-btcsoq-unfreeze-redundant");
                        }
                        btcsoqPendingFreezeOps.emplace_back(FREEZE_OP_UNFREEZE, freezeTarget);
                        blockFrozenRemove.insert(freezeTarget);
                        blockFrozenAdd.erase(freezeTarget);
                        LogPrintf("BTCSOQ: UNFREEZE accepted — %s:%u at block %d%s\n",
                            freezeTarget.hash.ToString(), freezeTarget.n,
                            pindex->nHeight, fJustCheck ? " (dry-run)" : "");
                    }
                }

                // 6. Advance the authority outpoint chain (local always;
                //    global + LevelDB deferred to the post-gate commit point).
                if (nBTCSOQAuthorityOutputIndex >= 0) {
                    COutPoint prevAuthOutpoint = localBTCSOQAuthOutpoint;
                    localBTCSOQAuthOutpoint = COutPoint(
                        tx.GetHash(), nBTCSOQAuthorityOutputIndex);
                    btcsoqCommitOutpoint = true;
                    btcsoqPendingOutpoint = localBTCSOQAuthOutpoint;
                    LogPrintf("BTCSOQ: Authority outpoint updated: %s:%u → %s:%u%s\n",
                        prevAuthOutpoint.hash.ToString(), prevAuthOutpoint.n,
                        localBTCSOQAuthOutpoint.hash.ToString(),
                        localBTCSOQAuthOutpoint.n,
                        fJustCheck ? " (dry-run)" : "");
                }
            } // end strict path

            // 7. Supply accounting — authority txs only (BUG-19/BUG-20 class:
            //    plain transfers are supply-neutral and never counted).
            nBTCSOQMinted += nTxV8Out;
            nBTCSOQBurned += nTxV8In;
        }

        // Apply the delta on a COPY; commit only on a real connect (BUG-18:
        // fJustCheck dry-runs must never leak into the global counter).
        if (nBTCSOQMinted > 0 || nBTCSOQBurned > 0) {
            CBTCSOQSupply supplyAfter = g_btcsoq_supply; // value copy
            if (nBTCSOQMinted > 0 && !supplyAfter.Mint(nBTCSOQMinted)) {
                return state.DoS(100,
                    error("ConnectBlock(): BTCSOQ supply overflow on mint of %d at block %d",
                        nBTCSOQMinted, pindex->nHeight),
                    REJECT_INVALID, "bad-btcsoq-supply-overflow");
            }
            if (nBTCSOQBurned > 0 && !supplyAfter.Burn(nBTCSOQBurned)) {
                return state.DoS(100,
                    error("ConnectBlock(): BTCSOQ supply underflow on burn of %d at block %d",
                        nBTCSOQBurned, pindex->nHeight),
                    REJECT_INVALID, "bad-btcsoq-supply-underflow");
            }

            LogPrintf("BTCSOQ: block %d supply delta: minted=%d burned=%d net=%d%s\n",
                pindex->nHeight, nBTCSOQMinted, nBTCSOQBurned,
                nBTCSOQMinted - nBTCSOQBurned, fJustCheck ? " (dry-run, not committed)" : "");

            // Commit deferred to the post-gate commit point (BUG-18 discipline
            // plus the 2C review's atomicity finding).
            btcsoqCommitSupply = true;
            btcsoqPendingSupply = supplyAfter;
        }
    }

    // =========================================================================
    // SOQ-ARCH-003: Consensus-Enforced Minimum UTXO Value (BIP9-Gated)
    // When DEPLOYMENT_UTXO_COST is active, reject outputs whose value is below
    // UTXO_COST_PER_BYTE × serialized_output_size. This is the Cardano-style
    // utxoCostPerByte approach adapted for Soqucoin's post-quantum UTXO model.
    //
    // Exemptions:
    //   - Unspendable outputs (OP_RETURN data anchors) — not in UTXO set
    //   - USDSOQ authority marker outputs (0-value by design, witness v5)
    //
    // Placement: After USDSOQ enforcement, before key-image tracking.
    // Pattern: Same as LATTICEBP confidential output rejection (L2329-2342).
    //
    // Approved 2026-05-25. BIP9 bit 11.
    // See DL-SOQ-FEE-ARCHITECTURE-V3.md, Appendix A.
    // =========================================================================
    if (fEnforceUtxoCost) {
        // SOQ-I007-STAGENET: Height gate for UTXO cost enforcement.
        // Before nUtxoCostEnforcementHeight, skip minimum value check.
        // MAINNET: nUtxoCostEnforcementHeight=0 → always enforced from BIP9 activation.
        // STAGENET: nUtxoCostEnforcementHeight=37201 → blocks 0-37200 exempt.
        if (pindex->nHeight < consensus.nUtxoCostEnforcementHeight) {
            LogPrintf("UTXO_COST: Pre-enforcement height %d < %d — "
                      "skipping minimum value check (SOQ-I007-STAGENET)\n",
                pindex->nHeight, consensus.nUtxoCostEnforcementHeight);
        } else {
        for (unsigned int i = 0; i < block.vtx.size(); i++) {
            const CTransaction& tx = *(block.vtx[i]);
            for (size_t j = 0; j < tx.vout.size(); j++) {
                const CTxOut& txout = tx.vout[j];
                // Skip unspendable outputs (OP_RETURN data anchors)
                if (txout.scriptPubKey.IsUnspendable())
                    continue;
                // Skip USDSOQ authority marker outputs (0-value by design, OP_5 witness v5)
                if (txout.scriptPubKey.size() == 34 && txout.scriptPubKey[0] == 0x55)
                    continue;
                // Skip BTCSOQ authority marker outputs (0-value by design, OP_9 witness v9).
                // Requires the full marker shape (32-byte program) so non-marker
                // 34-byte scripts starting 0x59 stay subject to the floor.
                if (txout.scriptPubKey.size() == 34 && txout.scriptPubKey[0] == 0x59 &&
                    txout.scriptPubKey[1] == 32)
                    continue;
                // Calculate minimum value based on serialized output size
                size_t nOutputSize = ::GetSerializeSize(txout, SER_NETWORK, PROTOCOL_VERSION);
                CAmount nMinValue = UTXO_COST_PER_BYTE * static_cast<CAmount>(nOutputSize);
                if (txout.nValue < nMinValue) {
                    return state.DoS(100,
                        error("ConnectBlock(): output %u of tx %s in block %d has value %lld < "
                              "minimum %lld (%u bytes x %lld sat/byte)",
                              (unsigned)j, tx.GetHash().ToString().c_str(),
                              pindex->nHeight, txout.nValue, nMinValue,
                              (unsigned)nOutputSize, (long long)UTXO_COST_PER_BYTE),
                        REJECT_INVALID, "bad-txns-output-below-utxo-cost");
                }
            }
        }
        } // end UTXO cost height gate else
    }

    // =========================================================================
    // SOQ-ARCH-001 Phase 2: Key-Image Double-Spend Protection
    //
    // ⛔⛔ THIS BLOCK IS DEAD CODE AND ENFORCES NOTHING. It is residue of a
    // SUPERSEDED design. Do not read it as protection, and do not "fix" it
    // without reading the two paragraphs below. Bead p4wv.
    //
    // WHY IT CANNOT RUN. Inputs are resolved through
    // view.AccessCoins(...)->IsAvailable(), but this is the LAST pass over the
    // block and UpdateCoins spent every input during the FIRST pass, so the
    // guard skips all of them and the body never executes. Four reject strings
    // are therefore unreachable (bad-txns-conf-no-witness,
    // bad-txns-conf-empty-keyimage, bad-txns-conf-duplicate-keyimage,
    // bad-txns-conf-intrablock-duplicate-keyimage), vBlockKeyImages is always
    // empty, and WriteKeyImage below is never called, so the DB that the
    // cross-block check consults is never populated by the connect path. This
    // is the THIRD instance of one root cause: the freeze guard (bead e2n) and
    // the USDSOQ input-isolation rule (bead 0r2) were dead for exactly this
    // reason. The asymmetry is visible in this file: DisconnectBlock's mirror
    // loop works, and says why — ApplyTxInUndo has RESTORED the inputs there.
    // Proven by execution in test/soquobscura_keyimage_deadcode_tests.cpp.
    //
    // WHY THE FIX IS NOT "READ BLOCK UNDO". Key images exist only to make RING
    // SIGNATURES double-spend-safe, and the ratified design CUT ring signatures,
    // stealth addresses and decoys from launch
    // (DL-LATTICEBP-STATE-ANALYSIS-2026-07-18 Part II.6, "Key images leave
    // launch scope"; Phase 2, "remove LF+/ring/key-image opcodes from launch
    // rules"; DL-SOQUOBSCURA-NAMING-POLICY). Spends are outpoint-addressed
    // today, so the UTXO set already prevents double-spends and this layer adds
    // nothing. Reviving it as written would introduce THREE live defects:
    //   * the "key image" is just wit.stack.back(), which on every witness
    //     layout the node accepts today is the PUBKEY, not anything bound to the
    //     outpoint. Two honest spends by one owner collide, and the second is
    //     rejected as a double-spend of an output it never touched (pinned by
    //     the second case in that test file);
    //   * WriteKeyImage below has no !fJustCheck guard, so every
    //     getblocktemplate dry-run would persist key images and the next poll of
    //     the same template would reject it as a duplicate. BUG-18 verbatim;
    //     already filed as H2 in the state analysis;
    //   * no witness layout satisfies both script verification and key-image
    //     extraction (C5, same document).
    //
    // DECIDED 2026-08-20: leave it here, labelled, until Phase 2 of that plan
    // removes it after the crypto rebuild. Waiting is safe because the hazard is
    // that dead scaffolding gets MISTAKEN for enforcement, and that is closed by
    // this comment plus an executing test rather than by deletion. The code being
    // present costs nothing while the deployment is NOT_SCHEDULED everywhere.
    //
    // ⚠️ WHEN PHASE 2 DELETES THIS, DELETE THE DisconnectBlock MIRROR WITH IT.
    // That loop WORKS (ApplyTxInUndo restores the inputs before it runs), so it is
    // the half that looks correct in review and survives a careless deletion,
    // which would leave erase-without-write. Delete
    // test/soquobscura_keyimage_deadcode_tests.cpp in the same commit too: it
    // asserts this loop does not fire, and once the loop is gone that assertion
    // is vacuous — a green test proving nothing, which is the exact failure mode
    // this whole arc is about.
    //
    // Original intent, for whoever picks up Phase 2: witness v4 confidential
    // inputs were to carry the key image as the LAST stack element, after the
    // ring signature and range proof — [ring_sig][range_proof][key_image] —
    // hashed to a 32-byte LatticeKeyImageHash for LevelDB (consensus/privacy.h).
    // ConnectBlock writes; DisconnectBlock erases.
    // =========================================================================
    std::vector<LatticeKeyImageHash> vBlockKeyImages;  // Track for DisconnectBlock undo

    if (flags & SCRIPT_VERIFY_SOQUOBSCURA) {
        for (unsigned int i = 0; i < block.vtx.size(); i++) {
            const CTransaction& tx = *(block.vtx[i]);
            if (tx.IsCoinBase()) continue;

            for (unsigned int j = 0; j < tx.vin.size(); j++) {
                // Only process inputs that spend confidential outputs.
                // A confidential input's previous output has nVisibility == 0x01.
                const CCoins* coins = view.AccessCoins(tx.vin[j].prevout.hash);
                if (!coins || !coins->IsAvailable(tx.vin[j].prevout.n))
                    continue;

                const CTxOut& prevOut = coins->vout[tx.vin[j].prevout.n];
                if (!prevOut.IsConfidential())
                    continue;

                // Extract key-image from witness stack.
                // The key-image is the last element of the scriptWitness stack
                // for witness v4 (Lattice-BP++) inputs.
                const CScriptWitness& wit = tx.vin[j].scriptWitness;
                if (wit.IsNull() || wit.stack.empty()) {
                    return state.DoS(100,
                        error("ConnectBlock(): confidential input %s:%u has no witness data",
                            tx.vin[j].prevout.hash.ToString(), tx.vin[j].prevout.n),
                        REJECT_INVALID, "bad-txns-conf-no-witness");
                }

                // Last stack element = serialized key-image
                const std::vector<uint8_t>& keyImageBytes = wit.stack.back();
                if (keyImageBytes.empty()) {
                    return state.DoS(100,
                        error("ConnectBlock(): empty key-image in confidential input %s:%u",
                            tx.vin[j].prevout.hash.ToString(), tx.vin[j].prevout.n),
                        REJECT_INVALID, "bad-txns-conf-empty-keyimage");
                }

                // Hash the raw key-image to 32 bytes for storage
                LatticeKeyImageHash kiHash = LatticeKeyImageHash::FromSerializedKeyImage(keyImageBytes);

                // Check for double-spend: has this key-image been seen before?
                if (pcoinsdbview && pcoinsdbview->HaveKeyImage(kiHash.hash)) {
                    int32_t nPrevHeight = 0;
                    pcoinsdbview->ReadKeyImageHeight(kiHash.hash, nPrevHeight);
                    return state.DoS(100,
                        error("ConnectBlock(): duplicate key-image in tx %s input %u "
                              "(first seen at height %d, current block %d)",
                            tx.GetHash().ToString(), j, nPrevHeight, pindex->nHeight),
                        REJECT_INVALID, "bad-txns-conf-duplicate-keyimage");
                }

                // Check for intra-block duplicates (two TXs in the same block
                // spending the same confidential output)
                for (const auto& existing : vBlockKeyImages) {
                    if (existing == kiHash) {
                        return state.DoS(100,
                            error("ConnectBlock(): intra-block duplicate key-image in tx %s input %u",
                                tx.GetHash().ToString(), j),
                            REJECT_INVALID, "bad-txns-conf-intrablock-duplicate-keyimage");
                    }
                }

                vBlockKeyImages.push_back(kiHash);
            }
        }

        // Persist all new key-images from this block to the DB
        if (pcoinsdbview) {
            for (const auto& kiHash : vBlockKeyImages) {
                pcoinsdbview->WriteKeyImage(kiHash.hash, pindex->nHeight);
            }
        }

        if (!vBlockKeyImages.empty()) {
            LogPrintf("PRIVACY: block %d recorded %u new key-images\n",
                pindex->nHeight, vBlockKeyImages.size());
        }

        // =================================================================
        // SOQ-ARCH-001 Phase 2.3: LatticeFold Range Proof Accumulation
        // After key-image extraction, collect all range proofs from
        // confidential outputs and accumulate them via LatticeFold.
        // Then verify the miner's coinbase commitment matches.
        //
        // Range proofs are carried in the witness v4 stack as the
        // second-to-last element (before the key-image):
        //   [ring_sig_data...] [range_proof] [commitment] [key_image]
        //
        // Commitments are the confidential output's serialized
        // Pedersen commitment in the CTxOut witness extension.
        // =================================================================
        std::vector<std::vector<uint8_t>> vBlockRangeProofs;
        std::vector<std::vector<uint8_t>> vBlockCommitments;

        for (unsigned int i = 0; i < block.vtx.size(); i++) {
            const CTransaction& tx = *(block.vtx[i]);
            if (tx.IsCoinBase()) continue;

            for (unsigned int j = 0; j < tx.vout.size(); j++) {
                const CTxOut& txout = tx.vout[j];
                if (!txout.IsConfidential()) continue;

                // Read the proof and commitment straight off the input
                // witness stack (see the layout comment above). The previous
                // comment here claimed a scriptPubKey-hash commitment proxy;
                // that was residue from an earlier implementation and never
                // described these lines.
                //
                // NOTE the indexing assumption: output j is paired with input
                // j. That holds only for transactions built with a 1:1
                // output-to-input correspondence, and nothing in this loop
                // enforces it. Outputs beyond vin.size() get an empty witness
                // and are silently skipped.
                //
                // This loop sits inside `if (flags & SCRIPT_VERIFY_SOQUOBSCURA)`
                // (opened above the key-image extraction), so it runs only when
                // the deployment is active at this height. A v4/v10-shaped
                // output in a block while SoquObscura is dormant never reaches
                // it: such an output is plain anyone-can-spend SOQ.
                const CScriptWitness& wit = (j < tx.vin.size()) ?
                    tx.vin[j].scriptWitness : CScriptWitness();

                if (!wit.IsNull() && wit.stack.size() >= 3) {
                    // Stack layout: [..., range_proof, commitment, key_image]
                    const auto& proofData = wit.stack[wit.stack.size() - 3];
                    const auto& commitData = wit.stack[wit.stack.size() - 2];
                    vBlockRangeProofs.push_back(proofData);
                    vBlockCommitments.push_back(commitData);
                }
            }
        }

        // Accumulate range proofs if any exist in this block
        if (!vBlockRangeProofs.empty()) {
            BlockProofAccumulator blockAccum;
            if (!AccumulateBlockRangeProofs(vBlockRangeProofs, vBlockCommitments, blockAccum)) {
                return state.DoS(100,
                    error("ConnectBlock(): LatticeFold range proof accumulation failed at height %d",
                        pindex->nHeight),
                    REJECT_INVALID, "bad-blk-latticefold-accum");
            }

            // Verify the miner's coinbase commitment matches our accumulator
            // Scan coinbase outputs for the LatticeFold OP_RETURN commitment
            bool fFoundCommitment = false;
            const CTransaction& coinbase = *(block.vtx[0]);
            for (const auto& txout : coinbase.vout) {
                std::vector<uint8_t> scriptBytes(txout.scriptPubKey.begin(),
                    txout.scriptPubKey.end());
                uint256 coinbaseAccumHash;
                if (BlockProofAccumulator::ParseCoinbaseCommitment(scriptBytes, coinbaseAccumHash)) {
                    if (coinbaseAccumHash != blockAccum.hashAccumulator) {
                        return state.DoS(100,
                            error("ConnectBlock(): LatticeFold coinbase commitment mismatch "
                                  "at height %d (expected %s, got %s)",
                                pindex->nHeight,
                                blockAccum.hashAccumulator.ToString().substr(0, 16),
                                coinbaseAccumHash.ToString().substr(0, 16)),
                            REJECT_INVALID, "bad-blk-latticefold-commitment");
                    }
                    fFoundCommitment = true;
                    break;
                }
            }

            if (!fFoundCommitment) {
                return state.DoS(100,
                    error("ConnectBlock(): block %d has %u confidential outputs but "
                          "no LatticeFold coinbase commitment",
                        pindex->nHeight, vBlockRangeProofs.size()),
                    REJECT_INVALID, "bad-blk-missing-latticefold-commitment");
            }

            LogPrintf("PRIVACY: block %d verified LatticeFold accumulator (%u proofs, hash=%s)\n",
                pindex->nHeight, blockAccum.nProofCount,
                blockAccum.hashAccumulator.ToString().substr(0, 16));
        }
    }

    // =========================================================================
    // PAT block attestation enforcement (doc/PAT_BLOCK_ATTESTATION.md §7,
    // epic pat-completion-epic-xlab phase 3). Optional-but-verified: a miner
    // MAY emit the coinbase commitment; any commitment present MUST match the
    // attestation recomputed over the tuples collected in the loop above; from
    // nPatCommitmentMandatoryHeight onward, a block with attested spends and
    // no commitment is invalid. The four reject reasons are named in the spec
    // and pinned by string in pat_commitment_rule_tests.
    //
    // Unlike the LatticeFold check above, MORE THAN ONE commitment is invalid
    // rather than first-match-wins: a first-match scan makes validation depend
    // on coinbase output order and lets a miner place a decoy ahead of the
    // real commitment (spec §6).
    //
    // Skipped with fScriptChecks, TOGETHER with the collection above: inside
    // the assumevalid window the batch was never collected, so enforcing here
    // would compare any present commitment against an empty batch and reject
    // valid historical blocks. The trust statement is the one assumevalid
    // already makes — these commitments were verified by every node that ran
    // full checks when the blocks were new.
    // =========================================================================
    if (fScriptChecks) {
        uint256 committed;
        const int nCommitments = patattest::FindCommitments(*block.vtx[0], committed);
        uint256 computed;
        const bool fHaveAttestation = patattest::ComputeBlockAttestation(patBatch, computed);

        if (nCommitments > 1) {
            return state.DoS(100,
                error("ConnectBlock(): block %d carries %d PAT commitments, only one is permitted",
                      pindex->nHeight, nCommitments),
                REJECT_INVALID, "bad-blk-pat-commitment-duplicate");
        }
        if (nCommitments == 1) {
            if (!fHaveAttestation) {
                return state.DoS(100,
                    error("ConnectBlock(): block %d carries a PAT commitment but has no attested spends",
                          pindex->nHeight),
                    REJECT_INVALID, "bad-blk-pat-commitment-empty");
            }
            if (committed != computed) {
                return state.DoS(100,
                    error("ConnectBlock(): block %d PAT commitment mismatch (committed %s, computed %s)",
                          pindex->nHeight,
                          committed.ToString().substr(0, 16), computed.ToString().substr(0, 16)),
                    REJECT_INVALID, "bad-blk-pat-commitment");
            }
            LogPrintf("PAT: block %d attestation verified (%u tuples, hash=%s)\n",
                pindex->nHeight, (unsigned)patBatch.size(), computed.ToString().substr(0, 16));
        } else if (fHaveAttestation) {
            const int nMandatory =
                chainparams.GetConsensus(pindex->nHeight).nPatCommitmentMandatoryHeight;
            if (nMandatory != 0 && pindex->nHeight >= nMandatory) {
                return state.DoS(100,
                    error("ConnectBlock(): block %d has %u attested spends but no PAT commitment "
                          "(mandatory from height %d)",
                          pindex->nHeight, (unsigned)patBatch.size(), nMandatory),
                    REJECT_INVALID, "bad-blk-missing-pat-commitment");
            }
        }
    }

    if (!control.Wait())
        return state.DoS(100, false);
    int64_t nTime4 = GetTimeMicros();
    nTimeVerify += nTime4 - nTime2;
    LogPrint("bench", "    - Verify %u txins: %.2fms (%.3fms/txin) [%.2fs]\n", nInputs - 1, 0.001 * (nTime4 - nTime2), nInputs <= 1 ? 0 : 0.001 * (nTime4 - nTime2) / (nInputs - 1), nTimeVerify * 0.000001);

    if (fJustCheck)
        return true;

    // =========================================================================
    // DL-BTCSOQ-CONSENSUS-NATIVE: commit BTCSOQ side effects. This is the ONLY
    // place BTCSOQ chainstate (minted-deposit set, freeze registry, supply
    // counter, authority outpoint) is written. It sits after every validation
    // gate and after the fJustCheck early-return, so a block that fails any
    // check above leaves no BTCSOQ trace, and dry-runs never touch state.
    // =========================================================================
    if (pcoinsdbview) {
        for (const auto& deposit : btcsoqPendingMintedDeposits) {
            if (!pcoinsdbview->WriteBTCSOQMinted(deposit)) {
                LogPrintf("ERROR: BTCSOQ: Failed to persist minted deposit %s:%u at block %d\n",
                    deposit.hash.ToString(), deposit.n, pindex->nHeight);
            }
        }
        for (const auto& op : btcsoqPendingFreezeOps) {
            if (op.first == FREEZE_OP_FREEZE) {
                if (!pcoinsdbview->WriteBTCSOQFrozen(op.second)) {
                    LogPrintf("ERROR: BTCSOQ: Failed to write frozen outpoint %s:%u at block %d\n",
                        op.second.hash.ToString(), op.second.n, pindex->nHeight);
                }
            } else {
                if (!pcoinsdbview->EraseBTCSOQFrozen(op.second)) {
                    LogPrintf("ERROR: BTCSOQ: Failed to erase frozen outpoint %s:%u at block %d\n",
                        op.second.hash.ToString(), op.second.n, pindex->nHeight);
                }
            }
        }
    }
    if (btcsoqCommitOutpoint) {
        g_btcsoq_authority_outpoint = btcsoqPendingOutpoint;
        if (pcoinsdbview &&
            !pcoinsdbview->WriteBTCSOQAuthorityOutpoint(g_btcsoq_authority_outpoint)) {
            LogPrintf("ERROR: BTCSOQ: Failed to persist authority outpoint at block %d\n",
                pindex->nHeight);
        }
    }
    // ────────────────────────────────────────────────────────────────────────
    // SOQ-I013: the USDSOQ commit point. Everything the USDSOQ block collected
    // lands here, past control.Wait() and past the fJustCheck early-return, so
    // it can only run for a block that is fully valid and actually being
    // connected. Mirrors the BTCSOQ commit immediately below, which has worked
    // this way since review 2C.
    // ────────────────────────────────────────────────────────────────────────
    if (usdsoqCommitOutpoint) {
        g_usdsoq_authority_outpoint = usdsoqPendingOutpoint;
        if (pcoinsdbview &&
            !pcoinsdbview->WriteUSDSOQAuthorityOutpoint(g_usdsoq_authority_outpoint)) {
            LogPrintf("ERROR: USDSOQ: Failed to persist authority outpoint to LevelDB "
                      "at block %d\n", pindex->nHeight);
        }
        LogPrintf("USDSOQ: authority outpoint committed: %s:%u (block %d)\n",
            g_usdsoq_authority_outpoint.hash.ToString(),
            g_usdsoq_authority_outpoint.n, pindex->nHeight);
    }
    for (const auto& op : usdsoqPendingFreezeOps) {
        if (op.first == FREEZE_OP_FREEZE) {
            if (pcoinsdbview && !pcoinsdbview->WriteFrozenOutpoint(op.second)) {
                LogPrintf("ERROR: USDSOQ: Failed to write frozen outpoint %s:%u at block %d\n",
                    op.second.hash.ToString(), op.second.n, pindex->nHeight);
            } else {
                LogPrintf("USDSOQ: FREEZE committed — %s:%u at block %d\n",
                    op.second.hash.ToString(), op.second.n, pindex->nHeight);
            }
        } else {
            if (pcoinsdbview && !pcoinsdbview->EraseFrozenOutpoint(op.second)) {
                LogPrintf("ERROR: USDSOQ: Failed to erase frozen outpoint %s:%u at block %d\n",
                    op.second.hash.ToString(), op.second.n, pindex->nHeight);
            } else {
                LogPrintf("USDSOQ: UNFREEZE committed — %s:%u at block %d\n",
                    op.second.hash.ToString(), op.second.n, pindex->nHeight);
            }
        }
    }
    if (usdsoqCommitSupply) {
        g_usdsoq_supply = usdsoqPendingSupply;
        if (pcoinsdbview && !pcoinsdbview->WriteUSDSOQSupply(g_usdsoq_supply)) {
            LogPrintf("ERROR: USDSOQ: Failed to persist supply to LevelDB at block %d\n",
                pindex->nHeight);
        }
        LogPrintf("USDSOQ: supply state: total_minted=%d total_burned=%d outstanding=%d\n",
            g_usdsoq_supply.TotalMinted(), g_usdsoq_supply.TotalBurned(),
            g_usdsoq_supply.Outstanding());
    }

    if (btcsoqCommitSupply) {
        g_btcsoq_supply = btcsoqPendingSupply;
        if (pcoinsdbview && !pcoinsdbview->WriteBTCSOQSupply(g_btcsoq_supply)) {
            LogPrintf("ERROR: BTCSOQ: Failed to persist supply to LevelDB at block %d\n",
                pindex->nHeight);
        }
        LogPrintf("BTCSOQ: supply state: total_minted=%d total_burned=%d outstanding=%d\n",
            g_btcsoq_supply.TotalMinted(), g_btcsoq_supply.TotalBurned(),
            g_btcsoq_supply.Outstanding());
    }

    // Write undo information to disk
    if (pindex->GetUndoPos().IsNull() || !pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
        if (pindex->GetUndoPos().IsNull()) {
            CDiskBlockPos _pos;
            if (!FindUndoPos(state, pindex->nFile, _pos, ::GetSerializeSize(blockundo, SER_DISK, CLIENT_VERSION) + 40))
                return error("ConnectBlock(): FindUndoPos failed");
            if (!UndoWriteToDisk(blockundo, _pos, pindex->pprev->GetBlockHash(), chainparams.MessageStart()))
                return AbortNode(state, "Failed to write undo data");

            // update nUndoPos in block index
            pindex->nUndoPos = _pos.nPos;
            pindex->nStatus |= BLOCK_HAVE_UNDO;
        }

        pindex->RaiseValidity(BLOCK_VALID_SCRIPTS);
        setDirtyBlockIndex.insert(pindex);
    }

    if (fTxIndex)
        if (!pblocktree->WriteTxIndex(vPos))
            return AbortNode(state, "Failed to write transaction index");

    // add this block to the view's block chain
    view.SetBestBlock(pindex->GetBlockHash());

    int64_t nTime5 = GetTimeMicros();
    nTimeIndex += nTime5 - nTime4;
    LogPrint("bench", "    - Index writing: %.2fms [%.2fs]\n", 0.001 * (nTime5 - nTime4), nTimeIndex * 0.000001);

    // Watch for changes to the previous coinbase transaction.
    static uint256 hashPrevBestCoinBase;
    GetMainSignals().UpdatedTransaction(hashPrevBestCoinBase);
    hashPrevBestCoinBase = block.vtx[0]->GetHash();


    int64_t nTime6 = GetTimeMicros();
    nTimeCallbacks += nTime6 - nTime5;
    LogPrint("bench", "    - Callbacks: %.2fms [%.2fs]\n", 0.001 * (nTime6 - nTime5), nTimeCallbacks * 0.000001);

    return true;
}

/**
 * Update the on-disk chain state.
 * The caches and indexes are flushed depending on the mode we're called with
 * if they're too large, if it's been a while since the last write,
 * or always and in all cases if we're in prune mode and are deleting files.
 */
bool static FlushStateToDisk(CValidationState& state, FlushStateMode mode, int nManualPruneHeight)
{
    int64_t nMempoolUsage = mempool.DynamicMemoryUsage();
    const CChainParams& chainparams = Params();
    LOCK2(cs_main, cs_LastBlockFile);
    static int64_t nLastWrite = 0;
    static int64_t nLastFlush = 0;
    static int64_t nLastSetChain = 0;
    std::set<int> setFilesToPrune;
    bool fFlushForPrune = false;
    try {
        if (fPruneMode && (fCheckForPruning || nManualPruneHeight > 0) && !fReindex) {
            if (nManualPruneHeight > 0) {
                FindFilesToPruneManual(setFilesToPrune, nManualPruneHeight);
            } else {
                FindFilesToPrune(setFilesToPrune, chainparams.PruneAfterHeight());
                fCheckForPruning = false;
            }
            if (!setFilesToPrune.empty()) {
                fFlushForPrune = true;
                if (!fHavePruned) {
                    pblocktree->WriteFlag("prunedblockfiles", true);
                    fHavePruned = true;
                }
            }
        }
        int64_t nNow = GetTimeMicros();
        // Avoid writing/flushing immediately after startup.
        if (nLastWrite == 0) {
            nLastWrite = nNow;
        }
        if (nLastFlush == 0) {
            nLastFlush = nNow;
        }
        if (nLastSetChain == 0) {
            nLastSetChain = nNow;
        }
        int64_t nMempoolSizeMax = GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
        int64_t cacheSize = pcoinsTip->DynamicMemoryUsage() * DB_PEAK_USAGE_FACTOR;
        int64_t nTotalSpace = nCoinCacheUsage + std::max<int64_t>(nMempoolSizeMax - nMempoolUsage, 0);
        // The cache is large and we're within 10% and 200 MiB or 50% and 50MiB of the limit, but we have time now (not in the middle of a block processing).
        bool fCacheLarge = mode == FLUSH_STATE_PERIODIC && cacheSize > std::min(std::max(nTotalSpace / 2, nTotalSpace - MIN_BLOCK_COINSDB_USAGE * 1024 * 1024),
                                                                           std::max((9 * nTotalSpace) / 10, nTotalSpace - MAX_BLOCK_COINSDB_USAGE * 1024 * 1024));
        // The cache is over the limit, we have to write now.
        bool fCacheCritical = mode == FLUSH_STATE_IF_NEEDED && cacheSize > nTotalSpace;
        // It's been a while since we wrote the block index to disk. Do this frequently, so we don't need to redownload after a crash.
        bool fPeriodicWrite = mode == FLUSH_STATE_PERIODIC && nNow > nLastWrite + (int64_t)DATABASE_WRITE_INTERVAL * 1000000;
        // It's been very long since we flushed the cache. Do this infrequently, to optimize cache usage.
        bool fPeriodicFlush = mode == FLUSH_STATE_PERIODIC && nNow > nLastFlush + (int64_t)DATABASE_FLUSH_INTERVAL * 1000000;
        // Combine all conditions that result in a full cache flush.
        bool fDoFullFlush = (mode == FLUSH_STATE_ALWAYS) || fCacheLarge || fCacheCritical || fPeriodicFlush || fFlushForPrune;
        // Write blocks and block index to disk.
        if (fDoFullFlush || fPeriodicWrite) {
            // Depend on nMinDiskSpace to ensure we can write block index
            if (!CheckDiskSpace(0))
                return state.Error("out of disk space");
            // First make sure all block and undo data is flushed to disk.
            FlushBlockFile();
            // Then update all block file information (which may refer to block and undo files).
            {
                std::vector<std::pair<int, const CBlockFileInfo*> > vFiles;
                vFiles.reserve(setDirtyFileInfo.size());
                for (std::set<int>::iterator it = setDirtyFileInfo.begin(); it != setDirtyFileInfo.end();) {
                    vFiles.push_back(std::make_pair(*it, &vinfoBlockFile[*it]));
                    setDirtyFileInfo.erase(it++);
                }
                std::vector<const CBlockIndex*> vBlocks;
                vBlocks.reserve(setDirtyBlockIndex.size());
                for (std::set<CBlockIndex*>::iterator it = setDirtyBlockIndex.begin(); it != setDirtyBlockIndex.end();) {
                    vBlocks.push_back(*it);
                    setDirtyBlockIndex.erase(it++);
                }
                if (!pblocktree->WriteBatchSync(vFiles, nLastBlockFile, vBlocks)) {
                    return AbortNode(state, "Failed to write to block index database");
                }
            }
            // Finally remove any pruned files
            if (fFlushForPrune)
                UnlinkPrunedFiles(setFilesToPrune);
            nLastWrite = nNow;
        }
        // Flush best chain related state. This can only be done if the blocks / block index write was also done.
        if (fDoFullFlush) {
            // Typical CCoins structures on disk are around 128 bytes in size.
            // Pushing a new one to the database can cause it to be written
            // twice (once in the log, and once in the tables). This is already
            // an overestimation, as most will delete an existing entry or
            // overwrite one. Still, use a conservative safety factor of 2.
            if (!CheckDiskSpace(128 * 2 * 2 * pcoinsTip->GetCacheSize()))
                return state.Error("out of disk space");
            // Flush the chainstate (which may refer to block index entries).
            if (!pcoinsTip->Flush())
                return AbortNode(state, "Failed to write to coin database");
            nLastFlush = nNow;
        }
        if (fDoFullFlush || ((mode == FLUSH_STATE_ALWAYS || mode == FLUSH_STATE_PERIODIC) && nNow > nLastSetChain + (int64_t)DATABASE_WRITE_INTERVAL * 1000000)) {
            // Update best block in wallet (so we can detect restored wallets).
            GetMainSignals().SetBestChain(chainActive.GetLocator());
            nLastSetChain = nNow;
        }
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error while flushing: ") + e.what());
    }
    return true;
}

void FlushStateToDisk()
{
    CValidationState state;
    FlushStateToDisk(state, FLUSH_STATE_ALWAYS);
}

void PruneAndFlush()
{
    CValidationState state;
    fCheckForPruning = true;
    FlushStateToDisk(state, FLUSH_STATE_NONE);
}

// =============================================================================
// PAT witness pruning, route R1 (doc/PAT_WITNESS_PRUNING.md §3).
//
// Compaction rewrites an eligible block file with every transaction
// re-serialized under SERIALIZE_TRANSACTION_NO_WITNESS, into a FRESH file
// number. The original is never modified in place; the crash-safety property
// is that at every instant the block index points only at data that exists on
// disk, and the single destructive step (deleting the originals) runs after
// the index durably points away from them.
//
// nFile couples the block position AND the undo position (chain.h GetBlockPos
// / GetUndoPos share the field), so moving a block to a new file number must
// carry its undo data too. The rev file is HARDLINKED to the new number
// before the index moves: both names stay valid simultaneously, so neither
// side of the index flush has a window where undo reads fail. Found during
// implementation; recorded in the specification §3.
// =============================================================================

//! A file number the append pointer is about to rotate INTO must carry no
//! leftovers. A blk/rev pair at a number whose file info is empty is
//! unreferenced data: the partial target of an interrupted witness compaction
//! (doc/PAT_WITNESS_PRUNING.md §3), whose rev file may be a HARDLINK to a
//! source file's undo data, or a tail left by a crash between a rotation and
//! the next index flush. No index entry can reference such a number: entries
//! and non-empty file infos are written in the same batch, and the only batch
//! that writes infos alone (the reservation) writes empty ones. Appending undo
//! through a hardlinked rev would corrupt the source, so unlink; the source
//! keeps its own link. Second line of defence behind the durable reservation.
//! Runs on the block-accept path, so failures are logged, never thrown.
static void RemoveStrayFilesAtFreshNumber(int nFile)
{
    AssertLockHeld(cs_LastBlockFile);
    if (nFile < 0 || nFile >= (int)vinfoBlockFile.size()) return;
    const CBlockFileInfo& info = vinfoBlockFile[nFile];
    if (info.nBlocks != 0 || info.nSize != 0 || info.nUndoSize != 0) return;
    const CDiskBlockPos pos(nFile, 0);
    for (const char* prefix : {"blk", "rev"}) {
        const fs::path path = GetBlockPosFilename(pos, prefix);
        boost::system::error_code ec;
        if (!fs::exists(path, ec)) continue;
        LogPrintf("Removing stray %s file %d (unreferenced leftover) before rotating into it\n", prefix, nFile);
        fs::remove(path, ec);
        if (ec) {
            LogPrintf("ERROR: cannot remove stray %s file %d: %s\n", prefix, nFile, ec.message());
        }
    }
}

void SetLastBlockFileForTests(int nFile)
{
    LOCK(cs_main);
    LOCK(cs_LastBlockFile);
    FlushBlockFile(true);
    if ((int)vinfoBlockFile.size() <= nFile) {
        vinfoBlockFile.resize(nFile + 1);
    }
    nLastBlockFile = nFile;
    setDirtyFileInfo.insert(nLastBlockFile);
}

void RotateBlockFileForTests()
{
    LOCK(cs_main);
    LOCK(cs_LastBlockFile);
    FlushBlockFile(true);
    nLastBlockFile++;
    if ((int)vinfoBlockFile.size() <= nLastBlockFile) {
        vinfoBlockFile.resize(nLastBlockFile + 1);
    }
    RemoveStrayFilesAtFreshNumber(nLastBlockFile); // same hygiene as FindBlockPos
    setDirtyFileInfo.insert(nLastBlockFile);
}

bool WitnessFileEligibleForCompaction(int nFile)
{
    AssertLockHeld(cs_main);

    const int nTipHeight = chainActive.Height();
    if (nTipHeight < 0) return false;
    // The finality horizon is the property that makes witness pruning safe at
    // all (spec §6). Disabled horizon (regtest default) means nothing is ever
    // eligible; init refuses to enable the feature in that state, and this
    // guard keeps the invariant even for direct callers.
    const int nHorizon = Params().GetConsensus(nTipHeight).nMaxReorgDepth;
    if (nHorizon <= 0) return false;

    {
        LOCK(cs_LastBlockFile);
        if (nFile < 0 || nFile >= (int)vinfoBlockFile.size()) return false;
        if (nFile == nLastBlockFile) return false;   // never the append file
        if (vinfoBlockFile[nFile].nBlocks == 0) return false;
    }

    // Whole-file rule (spec §1/§3): EVERY block in the file must qualify.
    // A stale fork block, an unvalidated block, or one within the horizon
    // makes the whole file ineligible; it ages into eligibility naturally.
    for (const std::pair<const uint256, CBlockIndex*>& item : mapBlockIndex) {
        const CBlockIndex* pindex = item.second;
        if (pindex->nFile != nFile) continue;
        if (pindex->nStatus & BLOCK_WITNESS_PRUNED) return false; // a compaction product
        if (!(pindex->nStatus & BLOCK_HAVE_DATA)) return false;
        // Genesis never reaches BLOCK_VALID_SCRIPTS: ConnectBlock early-returns
        // for it before validity is raised (its coinbase is unspendable, there
        // is nothing to script-check). It is axiomatically final and carries no
        // witnesses, so it is exempt from the validity requirement — without
        // this, file 0 could never become whole-file eligible.
        if (pindex->nHeight > 0 && !pindex->IsValid(BLOCK_VALID_SCRIPTS)) return false;
        if (!chainActive.Contains(pindex)) return false;
        if (nTipHeight - pindex->nHeight <= nHorizon) return false; // strictly deeper required
    }
    return true;
}

//! Compact one eligible file into nTargetFile = (snapshot of nLastBlockFile)+1.
//! See the block comment above for the ordering argument.
static bool CompactOneWitnessFile(int nFile, std::string& strError, int nTestCrashPoint)
{
    const CChainParams& chainparams = Params();

    // ---- Snapshot under cs_main: the block list, and RESERVE the target file
    // number by advancing the append pointer past it. FindBlockPos only ever
    // allocates forward from nLastBlockFile, so a reserved number can never be
    // rotated into by concurrent block writes — the collision is impossible by
    // construction, not detected after the fact (found in review: a
    // commit-time check runs after the disk damage it would detect).
    //
    // The reservation is in-memory until the next index flush. If the process
    // crashes before the commit below, a restart may re-derive file numbers
    // over a leftover partial target: blk files are position-addressed, so
    // stray tail bytes behind a rotated-into file are inert, and the orphan
    // sweep removes any partial target whose file info is empty and which no
    // index entry references.
    std::vector<CBlockIndex*> vBlocks;
    int nTargetFile;
    uint64_t nSourceUndoSize;
    {
        LOCK(cs_main);
        if (!WitnessFileEligibleForCompaction(nFile)) return true; // raced; skip
        // The target must be a number NOTHING occupies. nLastBlockFile + 1 is
        // not enough: after a -reindex the append pointer can sit BEHIND a
        // populated file (the import writes at known positions, and the last
        // block it accepts may be a deferred child in an earlier file), and
        // upstream keeps such files as ordinary indexed files beyond the
        // pointer. Reserving one of them would null its info and delete it.
        // Take the highest number any index entry or file info uses (found in
        // review).
        int nHighestUsed = -1;
        for (const std::pair<const uint256, CBlockIndex*>& item : mapBlockIndex) {
            if (item.second->nFile == nFile) vBlocks.push_back(item.second);
            if (item.second->nStatus & BLOCK_HAVE_DATA) nHighestUsed = std::max(nHighestUsed, item.second->nFile);
        }
        std::sort(vBlocks.begin(), vBlocks.end(),
                  [](const CBlockIndex* a, const CBlockIndex* b) { return a->nDataPos < b->nDataPos; });
        {
            LOCK(cs_LastBlockFile);
            nSourceUndoSize = vinfoBlockFile[nFile].nUndoSize;
            nHighestUsed = std::max(nHighestUsed, nLastBlockFile);
            for (size_t i = 0; i < vinfoBlockFile.size(); ++i) {
                const CBlockFileInfo& info = vinfoBlockFile[i];
                if (info.nBlocks != 0 || info.nSize != 0 || info.nUndoSize != 0) {
                    nHighestUsed = std::max(nHighestUsed, (int)i);
                }
            }
            nTargetFile = nHighestUsed + 1;
            if ((int)vinfoBlockFile.size() <= nTargetFile + 1) {
                vinfoBlockFile.resize(nTargetFile + 2);
            }
            // Leaving the current append file: finalize it (fsync + truncate
            // of the pre-allocated tail) exactly as FindBlockPos does on a
            // rotation, so the index can never be synced ahead of block data
            // that is still in kernel buffers (found in review).
            FlushBlockFile(true);
            vinfoBlockFile[nTargetFile].SetNull();
            nLastBlockFile = nTargetFile + 1; // appends continue in a fresh file
            setDirtyFileInfo.insert(nTargetFile);
            setDirtyFileInfo.insert(nLastBlockFile);
            // Make the reservation DURABLE before any I/O (found in review).
            // The index is otherwise flushed hourly, so a reservation known
            // only in memory can be forgotten by a crash after the rev
            // hardlink below but before the commit flush. A restart would
            // then rotate appends into nTargetFile, and FindUndoPos would
            // write undo through the hardlink into the SOURCE file's undo
            // data. With the advanced append pointer and the two (empty)
            // file infos on disk, a restart sees the number as taken and the
            // orphan sweep reclaims the partial target instead.
            std::vector<std::pair<int, const CBlockFileInfo*> > vReserve;
            vReserve.push_back(std::make_pair(nTargetFile, &vinfoBlockFile[nTargetFile]));
            vReserve.push_back(std::make_pair(nLastBlockFile, &vinfoBlockFile[nLastBlockFile]));
            try {
                pblocktree->WriteBatchSync(vReserve, nLastBlockFile, std::vector<const CBlockIndex*>());
            } catch (const std::runtime_error& e) {
                // CDBWrapper reports failure by THROWING (dbwrapper_error), not
                // by returning false, and an exception escaping the scheduler
                // thread terminates the process. Skip the pass instead; the
                // in-memory reservation is harmless, and the next full flush
                // goes through AbortNode if the database is really broken.
                strError = strprintf("witnessprune: cannot persist the reservation of block file %d: %s",
                                     nTargetFile, e.what());
                return false;
            }
        }
    }

    // ---- I/O outside cs_main (spec §3 lock discipline). The source blocks
    // are final by eligibility, so reading their positions unlocked is safe.
    struct NewPos { CBlockIndex* pindex; unsigned int nDataPos; };
    std::vector<NewPos> vNewPos;
    uint64_t nTargetSize = 0;
    unsigned int nLowestHeight = std::numeric_limits<unsigned int>::max();
    unsigned int nHighestHeight = 0;
    uint64_t nEarliestTime = std::numeric_limits<uint64_t>::max();
    uint64_t nLatestTime = 0;
    {
        const CDiskBlockPos targetStart(nTargetFile, 0);
        // Remove any partial file from an interrupted pass, then write fresh.
        fs::remove(GetBlockPosFilename(targetStart, "blk"));
        CAutoFile fileout(OpenBlockFile(targetStart), SER_DISK,
                          CLIENT_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
        if (fileout.IsNull()) {
            strError = strprintf("witnessprune: cannot open target block file %d", nTargetFile);
            return false;
        }
        for (CBlockIndex* pindex : vBlocks) {
            CBlock block;
            if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus(pindex->nHeight))) {
                strError = strprintf("witnessprune: cannot read block %s from file %d",
                                     pindex->GetBlockHash().ToString(), nFile);
                return false;
            }
            CDataStream ssBlock(SER_DISK, CLIENT_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
            ssBlock << block;
            const unsigned int nSize = (unsigned int)ssBlock.size();
            fileout << FLATDATA(chainparams.MessageStart()) << nSize;
            const long filePos = ftell(fileout.Get());
            if (filePos < 0) {
                strError = "witnessprune: ftell failed on target file";
                return false;
            }
            fileout.write(&ssBlock[0], ssBlock.size());
            vNewPos.push_back({pindex, (unsigned int)filePos});
            nTargetSize = (uint64_t)filePos + nSize;
            nLowestHeight = std::min<unsigned int>(nLowestHeight, pindex->nHeight);
            nHighestHeight = std::max<unsigned int>(nHighestHeight, pindex->nHeight);
            nEarliestTime = std::min<uint64_t>(nEarliestTime, block.GetBlockTime());
            nLatestTime = std::max<uint64_t>(nLatestTime, block.GetBlockTime());
        }
        FileCommit(fileout.Get());
    }

    // Carry the undo data: hardlink rev(nFile) to rev(nTargetFile). Both names
    // are valid simultaneously, so undo reads work on either side of the index
    // flush. Fall back to a copy where the filesystem refuses links.
    const fs::path revSrc = GetBlockPosFilename(CDiskBlockPos(nFile, 0), "rev");
    const fs::path revDst = GetBlockPosFilename(CDiskBlockPos(nTargetFile, 0), "rev");
    if (fs::exists(revSrc)) {
        fs::remove(revDst); // a partial pass may have left one
        try {
            fs::create_hard_link(revSrc, revDst);
        } catch (const fs::filesystem_error&) {
            try {
                fs::copy_file(revSrc, revDst);
            } catch (const fs::filesystem_error& e) {
                strError = strprintf("witnessprune: cannot carry undo file %d -> %d: %s",
                                     nFile, nTargetFile, e.what());
                return false;
            }
        }
    }

    if (nTestCrashPoint == 1) return true; // §7.3b: crash before any commit

    // ---- Commit under the locks: fill the reserved target's file info, move
    // the index, retire the source file info. The append pointer was already
    // advanced at reservation time, so no rotation can have touched the target.
    {
        LOCK(cs_main);
        LOCK(cs_LastBlockFile);
        CBlockFileInfo& target = vinfoBlockFile[nTargetFile];
        target.SetNull();
        target.nBlocks = (unsigned int)vNewPos.size();
        target.nSize = nTargetSize;
        target.nUndoSize = nSourceUndoSize;
        target.nHeightFirst = nLowestHeight;
        target.nHeightLast = nHighestHeight;
        target.nTimeFirst = nEarliestTime;
        target.nTimeLast = nLatestTime;
        vinfoBlockFile[nFile].SetNull();
        setDirtyFileInfo.insert(nFile);
        setDirtyFileInfo.insert(nTargetFile);

        for (const NewPos& np : vNewPos) {
            np.pindex->nFile = nTargetFile;
            np.pindex->nDataPos = np.nDataPos;
            // nUndoPos is an offset within the rev file, and the rev file was
            // carried byte-identically, so the offset is unchanged.
            np.pindex->nStatus |= BLOCK_WITNESS_PRUNED;
            setDirtyBlockIndex.insert(np.pindex);
        }

        // The reindex-refusal marker (spec §2). Written before the index
        // flush below; if the flag write is lost to a crash here, a reindex
        // fails LOUDLY partway (stripped blocks cannot re-verify scripts)
        // rather than silently believing, so the failure direction is safe.
        pblocktree->WriteFlag("witnessprunedblocks", true);
    }

    // Durable index flush, then and only then the destructive step.
    FlushStateToDisk();

    if (nTestCrashPoint == 2) return true; // §7.3b: crash before deletion

    fs::remove(GetBlockPosFilename(CDiskBlockPos(nFile, 0), "blk"));
    fs::remove(revSrc);
    LogPrintf("witnessprune: compacted file %d -> %d (%u blocks, %u bytes written)\n",
              nFile, nTargetFile, (unsigned)vNewPos.size(), (unsigned)nTargetSize);
    return true;
}

bool CompactWitnessFiles(std::string& strError, int nTestCrashPoint)
{
    // Never compact while the block-file layout is in flux or the chain is
    // provisional (spec §3, §6; found in review). During -reindex the import
    // writes blocks at KNOWN positions and moves the append pointer backwards,
    // so the forward-only reservation argument below does not hold: a pass
    // could reserve, then delete, an original file the import has not reached
    // yet. A -loadblock import goes through the ordinary forward path, but the
    // chain is provisional while it runs, the same reason as initial block
    // download: the finality horizon is not enforced then (ContextualCheck-
    // BlockHeader skips it), so a minority-fork tip may legitimately be
    // reorganised past the horizon, and a block compacted here would have to
    // be disconnected, which is AbortNode on every restart. Skipping a pass
    // costs nothing: the scheduler retries in ten minutes.
    if (fReindex || fImporting || IsInitialBlockDownload()) return true;

    // Orphan sweep: a crash between the index flush and the deletion leaves
    // original files that no index entry references (spec §3, crash window 2).
    // Criterion: a retired file-info slot, not the append file, present on
    // disk, with zero index entries pointing at it.
    std::vector<int> vEligible;
    std::vector<int> vOrphans;
    {
        LOCK(cs_main);
        // The finality horizon is enforced when a HEADER is accepted, and not
        // while the node is in initial block download. A header chain with
        // more work than the tip that forks below the horizon can therefore
        // exist in the index (accepted during the initial sync), and the node
        // will reorganise onto it when the blocks arrive. Compacting a file
        // now could strip a block that reorganisation must disconnect, which
        // is AbortNode on every restart. Wait for it to resolve (found in
        // review; closes the residual the IsInitialBlockDownload gate leaves).
        if (pindexBestHeader != NULL && chainActive.Tip() != NULL &&
            pindexBestHeader->nChainWork > chainActive.Tip()->nChainWork) {
            const int nHorizon = Params().GetConsensus(chainActive.Height()).nMaxReorgDepth;
            const CBlockIndex* pfork = chainActive.FindFork(pindexBestHeader);
            if (pfork == NULL || (nHorizon > 0 && chainActive.Height() - pfork->nHeight > nHorizon)) return true;
        }
        int nFiles;
        int nAppend;
        {
            LOCK(cs_LastBlockFile);
            nFiles = (int)vinfoBlockFile.size();
            nAppend = nLastBlockFile;
        }
        std::set<int> setReferenced;
        for (const std::pair<const uint256, CBlockIndex*>& item : mapBlockIndex) {
            if (item.second->nStatus & BLOCK_HAVE_DATA) setReferenced.insert(item.second->nFile);
        }
        for (int f = 0; f < nFiles; ++f) {
            if (f == nAppend) continue;
            bool fEmptyInfo;
            {
                LOCK(cs_LastBlockFile);
                fEmptyInfo = (vinfoBlockFile[f].nBlocks == 0);
            }
            if (fEmptyInfo && setReferenced.count(f) == 0 &&
                fs::exists(GetBlockPosFilename(CDiskBlockPos(f, 0), "blk"))) {
                vOrphans.push_back(f);
            }
            if (WitnessFileEligibleForCompaction(f)) vEligible.push_back(f);
        }
    }
    for (int f : vOrphans) {
        LogPrintf("witnessprune: removing orphaned original file %d from an interrupted pass\n", f);
        fs::remove(GetBlockPosFilename(CDiskBlockPos(f, 0), "blk"));
        fs::remove(GetBlockPosFilename(CDiskBlockPos(f, 0), "rev"));
    }
    for (int f : vEligible) {
        if (!CompactOneWitnessFile(f, strError, nTestCrashPoint)) return false;
        if (nTestCrashPoint != 0) return true; // simulate at most one crash per pass
    }
    return true;
}

/** Update chainActive and related internal data structures. */
void static UpdateTip(CBlockIndex* pindexNew, const CChainParams& chainParams)
{
    chainActive.SetTip(pindexNew);

    // SOQ-INFRA-004: Defensive null guard — chainActive.Tip() should never be null
    // after SetTip(pindexNew), but guard against race conditions during concurrent
    // GBT mining / reorg scenarios.
    const CBlockIndex* pTip = chainActive.Tip();
    if (!pTip) {
        LogPrintf("%s: WARNING — chainActive.Tip() null after SetTip, skipping update\n", __func__);
        return;
    }

    // New best block
    mempool.AddTransactionsUpdated(1);

    cvBlockChange.notify_all();

    static bool fWarned = false;
    std::vector<std::string> warningMessages;
    if (!IsInitialBlockDownload()) {
        int nUpgraded = 0;
        const CBlockIndex* pindex = pTip;
        for (int bit = 0; bit < VERSIONBITS_NUM_BITS; bit++) {
            WarningBitsConditionChecker checker(bit);
            ThresholdState state = checker.GetStateFor(pindex, chainParams.GetConsensus(pindex->nHeight), warningcache[bit]);
            if (state == THRESHOLD_ACTIVE || state == THRESHOLD_LOCKED_IN) {
                if (state == THRESHOLD_ACTIVE) {
                    std::string strWarning = strprintf(_("Warning: unknown new rules activated (versionbit %i)"), bit);
                    SetMiscWarning(strWarning);
                    if (!fWarned) {
                        AlertNotify(strWarning);
                        fWarned = true;
                    }
                } else {
                    warningMessages.push_back(strprintf("unknown new rules are about to activate (versionbit %i)", bit));
                }
            }
        }
        // Check the version of the last 100 blocks to see if we need to upgrade:
        for (int i = 0; i < 100 && pindex != NULL; i++) {
            int32_t nExpectedVersion = ComputeBlockVersion(pindex->pprev, chainParams.GetConsensus(pindex->nHeight));
            if (pindex->GetBaseVersion() > VERSIONBITS_LAST_OLD_BLOCK_VERSION && (pindex->GetBaseVersion() & ~nExpectedVersion) != 0)
                ++nUpgraded;
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0)
            warningMessages.push_back(strprintf("%d of last 100 blocks have unexpected version", nUpgraded));
        if (nUpgraded > 100 / 2) {
            std::string strWarning = _("Warning: Unknown block versions being mined! It's possible unknown rules are in effect");
            // notify GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
            SetMiscWarning(strWarning);
            if (!fWarned) {
                AlertNotify(strWarning);
                fWarned = true;
            }
        }
    }
    LogPrintf("%s: new best=%s height=%d version=0x%08x log2_work=%.8g tx=%lu date='%s' progress=%f cache=%.1fMiB(%utx)", __func__,
        pTip->GetBlockHash().ToString(), chainActive.Height(), pTip->nVersion,
        log(pTip->nChainWork.getdouble()) / log(2.0), (unsigned long)pTip->nChainTx,
        DateTimeStrFormat("%Y-%m-%d %H:%M:%S", pTip->GetBlockTime()),
        GuessVerificationProgress(chainParams.TxData(), pindexNew), pcoinsTip->DynamicMemoryUsage() * (1.0 / (1 << 20)), pcoinsTip->GetCacheSize());
    if (!warningMessages.empty())
        LogPrintf(" warning='%s'", boost::algorithm::join(warningMessages, ", "));
    LogPrintf("\n");
}

/** Disconnect chainActive's tip. You probably want to call mempool.removeForReorg and manually re-limit mempool size after this, with cs_main held. */
bool static DisconnectTip(CValidationState& state, const CChainParams& chainparams, bool fBare = false)
{
    CBlockIndex* pindexDelete = chainActive.Tip();
    assert(pindexDelete);
    // Read block from disk.
    CBlock block;
    if (!ReadBlockFromDisk(block, pindexDelete, chainparams.GetConsensus(chainActive.Height())))
        return AbortNode(state, "Failed to read block");
    // Apply the block atomically to the chain state.
    int64_t nStart = GetTimeMicros();
    {
        CCoinsViewCache view(pcoinsTip);
        if (!DisconnectBlock(block, state, pindexDelete, view))
            return error("DisconnectTip(): DisconnectBlock %s failed", pindexDelete->GetBlockHash().ToString());
        bool flushed = view.Flush();
        assert(flushed);
    }
    LogPrint("bench", "- Disconnect block: %.2fms\n", (GetTimeMicros() - nStart) * 0.001);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED))
        return false;

    if (!fBare) {
        // Resurrect mempool transactions from the disconnected block.
        std::vector<uint256> vHashUpdate;
        for (const auto& it : block.vtx) {
            const CTransaction& tx = *it;
            // ignore validation errors in resurrected transactions
            CValidationState stateDummy;
            if (tx.IsCoinBase() || !AcceptToMemoryPool(mempool, stateDummy, it, false, NULL, NULL, true)) {
                mempool.removeRecursive(tx, MemPoolRemovalReason::REORG);
            } else if (mempool.exists(tx.GetHash())) {
                vHashUpdate.push_back(tx.GetHash());
            }
        }
        // AcceptToMemoryPool/addUnchecked all assume that new mempool entries have
        // no in-mempool children, which is generally not true when adding
        // previously-confirmed transactions back to the mempool.
        // UpdateTransactionsFromBlock finds descendants of any transactions in this
        // block that were added back and cleans up the mempool state.
        mempool.UpdateTransactionsFromBlock(vHashUpdate);
    }

    // Update chainActive and related variables.
    UpdateTip(pindexDelete->pprev, chainparams);
    // Let wallets know transactions went from 1-confirmed to
    // 0-confirmed or conflicted:
    for (const auto& tx : block.vtx) {
        GetMainSignals().SyncTransaction(*tx, pindexDelete->pprev, CMainSignals::SYNC_TRANSACTION_NOT_IN_BLOCK);
    }
    return true;
}

static int64_t nTimeReadFromDisk = 0;
static int64_t nTimeConnectTotal = 0;
static int64_t nTimeFlush = 0;
static int64_t nTimeChainState = 0;
static int64_t nTimePostConnect = 0;

/**
 * Used to track blocks whose transactions were applied to the UTXO state as a
 * part of a single ActivateBestChainStep call.
 */
struct ConnectTrace {
    std::vector<std::pair<CBlockIndex*, std::shared_ptr<const CBlock> > > blocksConnected;
};

/**
 * Connect a new block to chainActive. pblock is either NULL or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 *
 * The block is always added to connectTrace (either after loading from disk or by copying
 * pblock) - if that is not intended, care must be taken to remove the last entry in
 * blocksConnected in case of failure.
 */
bool static ConnectTip(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexNew, const std::shared_ptr<const CBlock>& pblock, ConnectTrace& connectTrace)
{
    assert(pindexNew->pprev == chainActive.Tip());
    // Read block from disk.
    int64_t nTime1 = GetTimeMicros();
    if (!pblock) {
        std::shared_ptr<CBlock> pblockNew = std::make_shared<CBlock>();
        connectTrace.blocksConnected.emplace_back(pindexNew, pblockNew);
        if (!ReadBlockFromDisk(*pblockNew, pindexNew, chainparams.GetConsensus(pindexNew->nHeight)))
            return AbortNode(state, "Failed to read block");
    } else {
        connectTrace.blocksConnected.emplace_back(pindexNew, pblock);
    }
    const CBlock& blockConnecting = *connectTrace.blocksConnected.back().second;
    // Apply the block atomically to the chain state.
    int64_t nTime2 = GetTimeMicros();
    nTimeReadFromDisk += nTime2 - nTime1;
    int64_t nTime3;
    LogPrint("bench", "  - Load block from disk: %.2fms [%.2fs]\n", (nTime2 - nTime1) * 0.001, nTimeReadFromDisk * 0.000001);
    {
        CCoinsViewCache view(pcoinsTip);
        bool rv = ConnectBlock(blockConnecting, state, pindexNew, view, chainparams);
        GetMainSignals().BlockChecked(blockConnecting, state);
        if (!rv) {
            if (state.IsInvalid())
                InvalidBlockFound(pindexNew, state);
            return error("ConnectTip(): ConnectBlock %s failed", pindexNew->GetBlockHash().ToString());
        }
        nTime3 = GetTimeMicros();
        nTimeConnectTotal += nTime3 - nTime2;
        LogPrint("bench", "  - Connect total: %.2fms [%.2fs]\n", (nTime3 - nTime2) * 0.001, nTimeConnectTotal * 0.000001);
        bool flushed = view.Flush();
        assert(flushed);
    }
    int64_t nTime4 = GetTimeMicros();
    nTimeFlush += nTime4 - nTime3;
    LogPrint("bench", "  - Flush: %.2fms [%.2fs]\n", (nTime4 - nTime3) * 0.001, nTimeFlush * 0.000001);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED))
        return false;
    int64_t nTime5 = GetTimeMicros();
    nTimeChainState += nTime5 - nTime4;
    LogPrint("bench", "  - Writing chainstate: %.2fms [%.2fs]\n", (nTime5 - nTime4) * 0.001, nTimeChainState * 0.000001);
    // Remove conflicting transactions from the mempool.;
    mempool.removeForBlock(blockConnecting.vtx, pindexNew->nHeight);
    // Update chainActive & related variables.
    UpdateTip(pindexNew, chainparams);

    int64_t nTime6 = GetTimeMicros();
    nTimePostConnect += nTime6 - nTime5;
    nTimeTotal += nTime6 - nTime1;
    LogPrint("bench", "  - Connect postprocess: %.2fms [%.2fs]\n", (nTime6 - nTime5) * 0.001, nTimePostConnect * 0.000001);
    LogPrint("bench", "- Connect block: %.2fms [%.2fs]\n", (nTime6 - nTime1) * 0.001, nTimeTotal * 0.000001);
    return true;
}

/**
 * Return the tip of the chain with the most work in it, that isn't
 * known to be invalid (it's however far from certain to be valid).
 */
static CBlockIndex* FindMostWorkChain()
{
    do {
        CBlockIndex* pindexNew = NULL;

        // Find the best candidate header.
        {
            std::set<CBlockIndex*, CBlockIndexWorkComparator>::reverse_iterator it = setBlockIndexCandidates.rbegin();
            if (it == setBlockIndexCandidates.rend())
                return NULL;
            pindexNew = *it;
        }

        // Check whether all blocks on the path between the currently active chain and the candidate are valid.
        // Just going until the active chain is an optimization, as we know all blocks in it are valid already.
        CBlockIndex* pindexTest = pindexNew;
        bool fInvalidAncestor = false;
        while (pindexTest && !chainActive.Contains(pindexTest)) {
            assert(pindexTest->nChainTx || pindexTest->nHeight == 0);

            // Pruned nodes may have entries in setBlockIndexCandidates for
            // which block files have been deleted.  Remove those as candidates
            // for the most work chain if we come across them; we can't switch
            // to a chain unless we have all the non-active-chain parent blocks.
            bool fFailedChain = pindexTest->nStatus & BLOCK_FAILED_MASK;
            bool fMissingData = !(pindexTest->nStatus & BLOCK_HAVE_DATA);
            if (fFailedChain || fMissingData) {
                // Candidate chain is not usable (either invalid or missing data)
                if (fFailedChain && (pindexBestInvalid == NULL || pindexNew->nChainWork > pindexBestInvalid->nChainWork))
                    pindexBestInvalid = pindexNew;
                CBlockIndex* pindexFailed = pindexNew;
                // Remove the entire chain from the set.
                while (pindexTest != pindexFailed) {
                    if (fFailedChain) {
                        pindexFailed->nStatus |= BLOCK_FAILED_CHILD;
                    } else if (fMissingData) {
                        // If we're missing data, then add back to mapBlocksUnlinked,
                        // so that if the block arrives in the future we can try adding
                        // to setBlockIndexCandidates again.
                        mapBlocksUnlinked.insert(std::make_pair(pindexFailed->pprev, pindexFailed));
                    }
                    setBlockIndexCandidates.erase(pindexFailed);
                    pindexFailed = pindexFailed->pprev;
                }
                setBlockIndexCandidates.erase(pindexTest);
                fInvalidAncestor = true;
                break;
            }
            pindexTest = pindexTest->pprev;
        }
        if (!fInvalidAncestor)
            return pindexNew;
    } while (true);
}

/** Delete all entries in setBlockIndexCandidates that are worse than the current tip. */
static void PruneBlockIndexCandidates()
{
    // Note that we can't delete the current block itself, as we may need to return to it later in case a
    // reorganization to a better block fails.
    std::set<CBlockIndex*, CBlockIndexWorkComparator>::iterator it = setBlockIndexCandidates.begin();
    while (it != setBlockIndexCandidates.end() && setBlockIndexCandidates.value_comp()(*it, chainActive.Tip())) {
        setBlockIndexCandidates.erase(it++);
    }
    // Either the current tip or a successor of it we're working towards is left in setBlockIndexCandidates.
    assert(!setBlockIndexCandidates.empty());
}

/**
 * Try to make some progress towards making pindexMostWork the active block.
 * pblock is either NULL or a pointer to a CBlock corresponding to pindexMostWork.
 */
static bool ActivateBestChainStep(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexMostWork, const std::shared_ptr<const CBlock>& pblock, bool& fInvalidFound, ConnectTrace& connectTrace)
{
    AssertLockHeld(cs_main);
    const CBlockIndex* pindexOldTip = chainActive.Tip();
    const CBlockIndex* pindexFork = chainActive.FindFork(pindexMostWork);

    // Disconnect active blocks which are no longer in the best chain.
    bool fBlocksDisconnected = false;
    while (chainActive.Tip() && chainActive.Tip() != pindexFork) {
        if (!DisconnectTip(state, chainparams))
            return false;
        fBlocksDisconnected = true;
    }

    // Build list of new blocks to connect.
    std::vector<CBlockIndex*> vpindexToConnect;
    bool fContinue = true;
    int nHeight = pindexFork ? pindexFork->nHeight : -1;
    while (fContinue && nHeight != pindexMostWork->nHeight) {
        // Don't iterate the entire list of potential improvements toward the best tip, as we likely only need
        // a few blocks along the way.
        int nTargetHeight = std::min(nHeight + 32, pindexMostWork->nHeight);
        vpindexToConnect.clear();
        vpindexToConnect.reserve(nTargetHeight - nHeight);
        CBlockIndex* pindexIter = pindexMostWork->GetAncestor(nTargetHeight);
        while (pindexIter && pindexIter->nHeight != nHeight) {
            vpindexToConnect.push_back(pindexIter);
            pindexIter = pindexIter->pprev;
        }
        nHeight = nTargetHeight;

        // Connect new blocks.
        BOOST_REVERSE_FOREACH (CBlockIndex* pindexConnect, vpindexToConnect) {
            if (!ConnectTip(state, chainparams, pindexConnect, pindexConnect == pindexMostWork ? pblock : std::shared_ptr<const CBlock>(), connectTrace)) {
                if (state.IsInvalid()) {
                    // The block violates a consensus rule.
                    if (!state.CorruptionPossible())
                        InvalidChainFound(vpindexToConnect.back());
                    state = CValidationState();
                    fInvalidFound = true;
                    fContinue = false;
                    // If we didn't actually connect the block, don't notify listeners about it
                    connectTrace.blocksConnected.pop_back();
                    break;
                } else {
                    // A system error occurred (disk space, database error, ...).
                    return false;
                }
            } else {
                PruneBlockIndexCandidates();
                if (!pindexOldTip || chainActive.Tip()->nChainWork > pindexOldTip->nChainWork) {
                    // We're in a better position than we were. Return temporarily to release the lock.
                    fContinue = false;
                    break;
                }
            }
        }
    }

    if (fBlocksDisconnected) {
        mempool.removeForReorg(pcoinsTip, chainActive.Height() + 1, STANDARD_LOCKTIME_VERIFY_FLAGS);
        LimitMempoolSize(mempool, GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);
    }
    mempool.check(pcoinsTip);

    // Callbacks/notifications for a new best chain.
    if (fInvalidFound)
        CheckForkWarningConditionsOnNewFork(vpindexToConnect.back());
    else
        CheckForkWarningConditions();

    return true;
}

static void NotifyHeaderTip()
{
    bool fNotify = false;
    bool fInitialBlockDownload = false;
    static CBlockIndex* pindexHeaderOld = NULL;
    CBlockIndex* pindexHeader = NULL;
    {
        LOCK(cs_main);
        pindexHeader = pindexBestHeader;

        if (pindexHeader != pindexHeaderOld) {
            fNotify = true;
            fInitialBlockDownload = IsInitialBlockDownload();
            pindexHeaderOld = pindexHeader;
        }
    }
    // Send block tip changed notifications without cs_main
    if (fNotify) {
        uiInterface.NotifyHeaderTip(fInitialBlockDownload, pindexHeader);
    }
}

/**
 * Make the best chain active, in multiple steps. The result is either failure
 * or an activated best chain. pblock is either NULL or a pointer to a block
 * that is already loaded (to avoid loading it again from disk).
 */
bool ActivateBestChain(CValidationState& state, const CChainParams& chainparams, std::shared_ptr<const CBlock> pblock)
{
    // Note that while we're often called here from ProcessNewBlock, this is
    // far from a guarantee. Things in the P2P/RPC will often end up calling
    // us in the middle of ProcessNewBlock - do not assume pblock is set
    // sanely for performance or correctness!

    CBlockIndex* pindexMostWork = NULL;
    CBlockIndex* pindexNewTip = NULL;
    do {
        const CBlockIndex* pindexFork;
        ConnectTrace connectTrace;
        bool fInitialDownload;
        {
            LOCK(cs_main);
            { // MemPoolConflictRemovalTracker removed - had race conditions
              // See Bitcoin Core PR #17477 for async TransactionRemovedFromMempool
                CBlockIndex* pindexOldTip = chainActive.Tip();
                if (pindexMostWork == NULL) {
                    pindexMostWork = FindMostWorkChain();
                }


                // Whether we have anything to do at all.
                if (pindexMostWork == NULL || pindexMostWork == chainActive.Tip())
                    return true;

                bool fInvalidFound = false;
                std::shared_ptr<const CBlock> nullBlockPtr;
                if (!ActivateBestChainStep(state, chainparams, pindexMostWork, pblock && pblock->GetHash() == pindexMostWork->GetBlockHash() ? pblock : nullBlockPtr, fInvalidFound, connectTrace))
                    return false;

                if (fInvalidFound) {
                    // Wipe cache, we may need another branch now.
                    pindexMostWork = NULL;
                }
                pindexNewTip = chainActive.Tip();
                pindexFork = chainActive.FindFork(pindexOldTip);
                fInitialDownload = IsInitialBlockDownload();

                // throw all transactions though the signal-interface

            } // MemPoolConflictRemovalTracker scope removed

            // Transactions in the connected block are notified
            for (const auto& pair : connectTrace.blocksConnected) {
                assert(pair.second);
                const CBlock& block = *(pair.second);
                for (unsigned int i = 0; i < block.vtx.size(); i++)
                    GetMainSignals().SyncTransaction(*block.vtx[i], pair.first, i);
            }
        }
        // When we reach this point, we switched to a new tip (stored in pindexNewTip).

        // Notifications/callbacks that can run without cs_main

        // Notify external listeners about the new tip.
        GetMainSignals().UpdatedBlockTip(pindexNewTip, pindexFork, fInitialDownload);

        // Always notify the UI if a new block tip was connected
        if (pindexFork != pindexNewTip) {
            uiInterface.NotifyBlockTip(fInitialDownload, pindexNewTip);
        }

        // Perform the shutdown detection to the end of the loop to prevent
        // pindexNewTip being nil
        boost::this_thread::interruption_point();
        if (ShutdownRequested()) {
            LogPrintf("ActivateBestChain: shutdown requested, breaking loop\n");
            break;
        }

    } while (pindexNewTip != pindexMostWork);
    if (pindexNewTip != NULL) {
        CheckBlockIndex(chainparams.GetConsensus(pindexNewTip->nHeight));
    } else {
        CheckBlockIndex(chainparams.GetConsensus(0));
    }

    // Write changes periodically to disk, after relay.
    if (!FlushStateToDisk(state, FLUSH_STATE_PERIODIC)) {
        return false;
    }

    return true;
}


bool PreciousBlock(CValidationState& state, const CChainParams& params, CBlockIndex* pindex)
{
    {
        LOCK(cs_main);
        if (pindex->nChainWork < chainActive.Tip()->nChainWork) {
            // Nothing to do, this block is not at the tip.
            return true;
        }
        if (chainActive.Tip()->nChainWork > nLastPreciousChainwork) {
            // The chain has been extended since the last call, reset the counter.
            nBlockReverseSequenceId = -1;
        }
        nLastPreciousChainwork = chainActive.Tip()->nChainWork;
        setBlockIndexCandidates.erase(pindex);
        pindex->nSequenceId = nBlockReverseSequenceId;
        if (nBlockReverseSequenceId > std::numeric_limits<int32_t>::min()) {
            // We can't keep reducing the counter if somebody really wants to
            // call preciousblock 2**31-1 times on the same set of tips...
            nBlockReverseSequenceId--;
        }
        if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) && pindex->nChainTx) {
            setBlockIndexCandidates.insert(pindex);
            PruneBlockIndexCandidates();
        }
    }

    return ActivateBestChain(state, params);
}

bool InvalidateBlock(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindex)
{
    AssertLockHeld(cs_main);

    // We first disconnect backwards and then mark the blocks as invalid.
    // This prevents a case where pruned nodes may fail to invalidateblock
    // and be left unable to start as they have no tip candidates (as there
    // are no blocks that meet the "have data and are not invalid per
    // nStatus" criteria for inclusion in setBlockIndexCandidates).

    bool findexWasInChain = false;
    CBlockIndex* invalidWalkTip = chainActive.Tip();

    while (chainActive.Contains(pindex)) {
        findexWasInChain = true;
        // ActivateBestChain considers blocks already in chainActive
        // unconditionally valid already, so force disconnect away from it.
        if (!DisconnectTip(state, chainparams)) {
            mempool.removeForReorg(pcoinsTip, chainActive.Height() + 1, STANDARD_LOCKTIME_VERIFY_FLAGS);
            return false;
        }
    }

    // Debug print the invalid parent's hash, later list the child hashes.
    LogPrintf("Invalid Block %s.", pindex->GetBlockHash().ToString());

    // Now mark the blocks we just disconnected as descendants invalid
    // Note: this may not be all descendants, e.g. the disconnected block
    // may be the root of competing block chains that have not settled into
    // one single block chain yet.
    while (findexWasInChain && invalidWalkTip != pindex) {
        LogPrintf("  Invalid Child Block %s.", invalidWalkTip->GetBlockHash().ToString());
        invalidWalkTip->nStatus |= BLOCK_FAILED_CHILD;
        setDirtyBlockIndex.insert(invalidWalkTip);
        setBlockIndexCandidates.erase(invalidWalkTip);
        invalidWalkTip = invalidWalkTip->pprev;
    }

    // Mark the block itself as invalid.
    pindex->nStatus |= BLOCK_FAILED_VALID;
    setDirtyBlockIndex.insert(pindex);
    setBlockIndexCandidates.erase(pindex);
    gFailedBlocks.insert(pindex);

    LimitMempoolSize(mempool, GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);

    // The resulting new best tip may not be in setBlockIndexCandidates anymore, so
    // add it again.
    BlockMap::iterator it = mapBlockIndex.begin();
    while (it != mapBlockIndex.end()) {
        if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->nChainTx && !setBlockIndexCandidates.value_comp()(it->second, chainActive.Tip())) {
            setBlockIndexCandidates.insert(it->second);
            gFailedBlocks.erase(it->second);
        }
        it++;
    }

    InvalidChainFound(pindex);
    mempool.removeForReorg(pcoinsTip, chainActive.Height() + 1, STANDARD_LOCKTIME_VERIFY_FLAGS);
    uiInterface.NotifyBlockTip(IsInitialBlockDownload(), pindex->pprev);
    return true;
}

bool ResetBlockFailureFlags(CBlockIndex* pindex)
{
    AssertLockHeld(cs_main);

    int nHeight = pindex->nHeight;

    // Remove the invalidity flag from this block and all its descendants.
    BlockMap::iterator it = mapBlockIndex.begin();
    while (it != mapBlockIndex.end()) {
        if (!it->second->IsValid() && it->second->GetAncestor(nHeight) == pindex) {
            it->second->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(it->second);
            if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->nChainTx && setBlockIndexCandidates.value_comp()(chainActive.Tip(), it->second)) {
                setBlockIndexCandidates.insert(it->second);
            }
            if (it->second == pindexBestInvalid) {
                // Reset invalid block marker if it was pointing to one of those.
                pindexBestInvalid = NULL;
            }
        }
        it++;
    }

    // Remove the invalidity flag from all ancestors too.
    while (pindex != NULL) {
        if (pindex->nStatus & BLOCK_FAILED_MASK) {
            pindex->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(pindex);
        }
        pindex = pindex->pprev;
    }
    return true;
}

CBlockIndex* AddToBlockIndex(const CBlockHeader& block)
{
    // Check for duplicate
    uint256 hash = block.GetHash();
    BlockMap::iterator it = mapBlockIndex.find(hash);
    if (it != mapBlockIndex.end())
        return it->second;

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(block);
    assert(pindexNew);
    // We assign the sequence id to blocks only when the full data is available,
    // to avoid miners withholding blocks but broadcasting headers, to get a
    // competitive advantage.
    pindexNew->nSequenceId = 0;
    BlockMap::iterator mi = mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);
    BlockMap::iterator miPrev = mapBlockIndex.find(block.hashPrevBlock);
    if (miPrev != mapBlockIndex.end()) {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
        pindexNew->BuildSkip();
    }
    pindexNew->nTimeMax = (pindexNew->pprev ? std::max(pindexNew->pprev->nTimeMax, pindexNew->nTime) : pindexNew->nTime);
    pindexNew->nChainWork = (pindexNew->pprev ? pindexNew->pprev->nChainWork : 0) + GetBlockProof(*pindexNew);
    pindexNew->RaiseValidity(BLOCK_VALID_TREE);
    if (pindexBestHeader == NULL || pindexBestHeader->nChainWork < pindexNew->nChainWork)
        pindexBestHeader = pindexNew;

    setDirtyBlockIndex.insert(pindexNew);

    return pindexNew;
}

/** Mark a block as having its data received and checked (up to BLOCK_VALID_TRANSACTIONS). */
bool ReceivedBlockTransactions(const CBlock& block, CValidationState& state, CBlockIndex* pindexNew, const CDiskBlockPos& pos)
{
    pindexNew->nTx = block.vtx.size();
    pindexNew->nChainTx = 0;
    pindexNew->nFile = pos.nFile;
    pindexNew->nDataPos = pos.nPos;
    pindexNew->nUndoPos = 0;
    pindexNew->nStatus |= BLOCK_HAVE_DATA;
    if (IsWitnessEnabled(pindexNew->pprev, Params().GetConsensus(pindexNew->nHeight))) {
        pindexNew->nStatus |= BLOCK_OPT_WITNESS;
    }
    pindexNew->RaiseValidity(BLOCK_VALID_TRANSACTIONS);
    setDirtyBlockIndex.insert(pindexNew);

    if (pindexNew->pprev == NULL || pindexNew->pprev->nChainTx) {
        // If pindexNew is the genesis block or all parents are BLOCK_VALID_TRANSACTIONS.
        std::deque<CBlockIndex*> queue;
        queue.push_back(pindexNew);

        // Recursively process any descendant blocks that now may be eligible to be connected.
        while (!queue.empty()) {
            CBlockIndex* pindex = queue.front();
            queue.pop_front();
            pindex->nChainTx = (pindex->pprev ? pindex->pprev->nChainTx : 0) + pindex->nTx;
            {
                LOCK(cs_nBlockSequenceId);
                pindex->nSequenceId = nBlockSequenceId++;
            }
            if (chainActive.Tip() == NULL || !setBlockIndexCandidates.value_comp()(pindex, chainActive.Tip())) {
                setBlockIndexCandidates.insert(pindex);
            }
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = mapBlocksUnlinked.equal_range(pindex);
            while (range.first != range.second) {
                std::multimap<CBlockIndex*, CBlockIndex*>::iterator it = range.first;
                queue.push_back(it->second);
                range.first++;
                mapBlocksUnlinked.erase(it);
            }
        }
    } else {
        if (pindexNew->pprev && pindexNew->pprev->IsValid(BLOCK_VALID_TREE)) {
            mapBlocksUnlinked.insert(std::make_pair(pindexNew->pprev, pindexNew));
        }
    }

    return true;
}

bool FindBlockPos(CValidationState& state, CDiskBlockPos& pos, unsigned int nAddSize, unsigned int nHeight, uint64_t nTime, bool fKnown = false)
{
    LOCK(cs_LastBlockFile);

    unsigned int nFile = fKnown ? pos.nFile : nLastBlockFile;
    if (vinfoBlockFile.size() <= nFile) {
        vinfoBlockFile.resize(nFile + 1);
    }

    if (!fKnown) {
        while (vinfoBlockFile[nFile].nSize + nAddSize >= MAX_BLOCKFILE_SIZE) {
            nFile++;
            if (vinfoBlockFile.size() <= nFile) {
                vinfoBlockFile.resize(nFile + 1);
            }
        }
        pos.nFile = nFile;
        pos.nPos = vinfoBlockFile[nFile].nSize;
    }

    if ((int)nFile != nLastBlockFile) {
        if (!fKnown) {
            LogPrintf("Leaving block file %i: %s\n", nLastBlockFile, vinfoBlockFile[nLastBlockFile].ToString());
            RemoveStrayFilesAtFreshNumber(nFile);
        }
        FlushBlockFile(!fKnown);
        nLastBlockFile = nFile;
    }

    vinfoBlockFile[nFile].AddBlock(nHeight, nTime);
    if (fKnown)
        vinfoBlockFile[nFile].nSize = std::max(pos.nPos + nAddSize, vinfoBlockFile[nFile].nSize);
    else
        vinfoBlockFile[nFile].nSize += nAddSize;

    if (!fKnown) {
        unsigned int nOldChunks = (pos.nPos + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        unsigned int nNewChunks = (vinfoBlockFile[nFile].nSize + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        if (nNewChunks > nOldChunks) {
            if (fPruneMode)
                fCheckForPruning = true;
            if (CheckDiskSpace(nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos)) {
                FILE* file = OpenBlockFile(pos);
                if (file) {
                    LogPrintf("Pre-allocating up to position 0x%x in blk%05u.dat\n", nNewChunks * BLOCKFILE_CHUNK_SIZE, pos.nFile);
                    AllocateFileRange(file, pos.nPos, nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos);
                    fclose(file);
                }
            } else
                return state.Error("out of disk space");
        }
    }

    setDirtyFileInfo.insert(nFile);
    return true;
}

bool FindUndoPos(CValidationState& state, int nFile, CDiskBlockPos& pos, unsigned int nAddSize)
{
    pos.nFile = nFile;

    LOCK(cs_LastBlockFile);

    unsigned int nNewSize;
    pos.nPos = vinfoBlockFile[nFile].nUndoSize;
    nNewSize = vinfoBlockFile[nFile].nUndoSize += nAddSize;
    setDirtyFileInfo.insert(nFile);

    unsigned int nOldChunks = (pos.nPos + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    unsigned int nNewChunks = (nNewSize + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    if (nNewChunks > nOldChunks) {
        if (fPruneMode)
            fCheckForPruning = true;
        if (CheckDiskSpace(nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos)) {
            FILE* file = OpenUndoFile(pos);
            if (file) {
                LogPrintf("Pre-allocating up to position 0x%x in rev%05u.dat\n", nNewChunks * UNDOFILE_CHUNK_SIZE, pos.nFile);
                AllocateFileRange(file, pos.nPos, nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos);
                fclose(file);
            }
        } else
            return state.Error("out of disk space");
    }

    return true;
}

bool CheckBlockHeader(const CBlockHeader& block, CValidationState& state, bool fCheckPOW)
{
    // Check proof of work matches claimed amount
    // We don't have block height as this is called without context (i.e. without
    // knowing the previous block), but that's okay, as the checks done are permissive
    // (i.e. doesn't check work limit or whether AuxPoW is enabled)
    if (fCheckPOW && !CheckAuxPowProofOfWork(block, Params().GetConsensus(0)))
        return state.DoS(50, false, REJECT_INVALID, "high-hash", false, "proof of work failed");

    return true;
}

bool CheckBlock(const CBlock& block, CValidationState& state, bool fCheckPOW, bool fCheckMerkleRoot)
{
    // These are checks that are independent of context.

    if (block.fChecked)
        return true;

    // Check that the header is valid (particularly PoW).  This is mostly
    // redundant with the call in AcceptBlockHeader.
    if (!CheckBlockHeader(block, state, fCheckPOW))
        return false;

    // Check the merkle root.
    if (fCheckMerkleRoot) {
        bool mutated;
        uint256 hashMerkleRoot2 = BlockMerkleRoot(block, &mutated);
        if (block.hashMerkleRoot != hashMerkleRoot2)
            return state.DoS(100, false, REJECT_INVALID, "bad-txnmrklroot", true, "hashMerkleRoot mismatch");

        // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
        // of transactions in a block without affecting the merkle root of a block,
        // while still invalidating it.
        if (mutated)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-duplicate", true, "duplicate transaction");
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.
    // Note that witness malleability is checked in ContextualCheckBlock, so no
    // checks that use witness data may be performed here.

    // Size limits
    if (block.vtx.empty() || block.vtx.size() > MAX_BLOCK_BASE_SIZE || ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) > MAX_BLOCK_BASE_SIZE)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-length", false, "size limits failed");

    // First transaction must be coinbase, the rest must not be
    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-missing", false, "first tx is not coinbase");
    for (unsigned int i = 1; i < block.vtx.size(); i++)
        if (block.vtx[i]->IsCoinBase())
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-multiple", false, "more than one coinbase");

    // Check transactions
    for (const auto& tx : block.vtx)
        if (!CheckTransaction(*tx, state, true))
            return state.Invalid(false, state.GetRejectCode(), state.GetRejectReason(),
                strprintf("Transaction check failed (tx hash %s) %s", tx->GetHash().ToString(), state.GetDebugMessage()));

    unsigned int nSigOps = 0;
    for (const auto& tx : block.vtx) {
        nSigOps += GetLegacySigOpCount(*tx);
    }
    if (nSigOps * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-sigops", false, "out-of-bounds SigOpCount");

    if (fCheckPOW && fCheckMerkleRoot)
        block.fChecked = true;

    return true;
}

bool IsWitnessEnabled(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    // Handle genesis block case where pindexPrev is NULL
    if (pindexPrev == nullptr) {
        // SegWit is ALWAYS_ACTIVE, so return true even at genesis
        return true;
    }
    LOCK(cs_main);
    return (VersionBitsState(pindexPrev, params, Consensus::DEPLOYMENT_SEGWIT, versionbitscache) == THRESHOLD_ACTIVE);
}

// Compute at which vout of the block's coinbase transaction the witness
// commitment occurs, or -1 if not found.
static int GetWitnessCommitmentIndex(const CBlock& block)
{
    int commitpos = -1;
    if (!block.vtx.empty()) {
        for (size_t o = 0; o < block.vtx[0]->vout.size(); o++) {
            if (block.vtx[0]->vout[o].scriptPubKey.size() >= 38 && block.vtx[0]->vout[o].scriptPubKey[0] == OP_RETURN && block.vtx[0]->vout[o].scriptPubKey[1] == 0x24 && block.vtx[0]->vout[o].scriptPubKey[2] == 0xaa && block.vtx[0]->vout[o].scriptPubKey[3] == 0x21 && block.vtx[0]->vout[o].scriptPubKey[4] == 0xa9 && block.vtx[0]->vout[o].scriptPubKey[5] == 0xed) {
                commitpos = o;
            }
        }
    }
    return commitpos;
}

void UpdateUncommittedBlockStructures(CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams)
{
    int commitpos = GetWitnessCommitmentIndex(block);
    static const std::vector<unsigned char> nonce(32, 0x00);
    if (commitpos != -1 && IsWitnessEnabled(pindexPrev, consensusParams) && !block.vtx[0]->HasWitness()) {
        CMutableTransaction tx(*block.vtx[0]);
        tx.vin[0].scriptWitness.stack.resize(1);
        tx.vin[0].scriptWitness.stack[0] = nonce;
        block.vtx[0] = MakeTransactionRef(std::move(tx));
    }
}

std::vector<unsigned char> GenerateCoinbaseCommitment(CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams)
{
    std::vector<unsigned char> commitment;
    int commitpos = GetWitnessCommitmentIndex(block);
    std::vector<unsigned char> ret(32, 0x00);
    if (consensusParams.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout != 0) {
        if (commitpos == -1) {
            uint256 witnessroot = BlockWitnessMerkleRoot(block, NULL);
            CHash256().Write(witnessroot.begin(), 32).Write(&ret[0], 32).Finalize(witnessroot.begin());
            CTxOut out;
            out.nValue = 0;
            out.scriptPubKey.resize(38);
            out.scriptPubKey[0] = OP_RETURN;
            out.scriptPubKey[1] = 0x24;
            out.scriptPubKey[2] = 0xaa;
            out.scriptPubKey[3] = 0x21;
            out.scriptPubKey[4] = 0xa9;
            out.scriptPubKey[5] = 0xed;
            memcpy(&out.scriptPubKey[6], witnessroot.begin(), 32);
            commitment = std::vector<unsigned char>(out.scriptPubKey.begin(), out.scriptPubKey.end());
            CMutableTransaction tx(*block.vtx[0]);
            tx.vout.push_back(out);
            // Add witness nonce to coinbase input
            tx.vin[0].scriptWitness.stack.resize(1);
            tx.vin[0].scriptWitness.stack[0] = ret;
            block.vtx[0] = MakeTransactionRef(std::move(tx));
        }
    }

    // =========================================================================
    // SOQ-ARCH-001 Phase 2.3: LatticeFold Range Proof Accumulation Commitment
    // If the block contains confidential outputs, compute the LatticeFold
    // accumulator and add its hash as an OP_RETURN output in the coinbase.
    // This follows the same pattern as the SegWit witness commitment above.
    // =========================================================================
    {
        std::vector<std::vector<uint8_t>> vBlockRangeProofs;
        std::vector<std::vector<uint8_t>> vBlockCommitments;

        for (unsigned int i = 1; i < block.vtx.size(); i++) {  // skip coinbase
            const CTransaction& tx = *(block.vtx[i]);
            for (unsigned int j = 0; j < tx.vout.size(); j++) {
                const CTxOut& txout = tx.vout[j];
                if (!txout.IsConfidential()) continue;

                const CScriptWitness& wit = (j < tx.vin.size()) ?
                    tx.vin[j].scriptWitness : CScriptWitness();

                if (!wit.IsNull() && wit.stack.size() >= 3) {
                    const auto& proofData = wit.stack[wit.stack.size() - 3];
                    const auto& commitData = wit.stack[wit.stack.size() - 2];
                    vBlockRangeProofs.push_back(proofData);
                    vBlockCommitments.push_back(commitData);
                }
            }
        }

        if (!vBlockRangeProofs.empty()) {
            BlockProofAccumulator blockAccum;
            if (AccumulateBlockRangeProofs(vBlockRangeProofs, vBlockCommitments, blockAccum)) {
                auto lfScript = blockAccum.GetCoinbaseCommitmentScript();

                CTxOut lfOut;
                lfOut.nValue = 0;
                lfOut.scriptPubKey = CScript(lfScript.begin(), lfScript.end());

                CMutableTransaction tx(*block.vtx[0]);
                tx.vout.push_back(lfOut);
                block.vtx[0] = MakeTransactionRef(std::move(tx));

                LogPrintf("PRIVACY: added LatticeFold coinbase commitment (%u proofs, hash=%s)\n",
                    blockAccum.nProofCount,
                    blockAccum.hashAccumulator.ToString().substr(0, 16));
            }
        }
    }

    // =========================================================================
    // PAT block attestation commitment (doc/PAT_BLOCK_ATTESTATION.md §6-§7,
    // epic pat-completion-epic-xlab phase 3). If the block contains attested
    // Dilithium spends, compute the batch attestation and add its hash as a
    // 36-byte OP_RETURN 'PA' output in the coinbase. Optional-but-verified:
    // emitting is the miner's side of the contract; ConnectBlock verifies any
    // commitment that is present and, past nPatCommitmentMandatoryHeight,
    // requires one. The tuple construction is patattest::AppendTuples — the
    // SAME function ConnectBlock recomputes with, which is what prevents
    // producer/validator drift.
    // =========================================================================
    if (pcoinsTip != nullptr && block.vtx.size() > 1) {
        // The attested set is fixed and height-independent (see
        // IsAttestedVersion), so the miner and ConnectBlock cannot disagree.
        const patattest::AttestedSetParams patParams;

        // Prevouts: outputs created earlier in this block first (in-block
        // chained spends), then the chain view. Same resolution order the
        // validator sees, because ConnectBlock's view gains each transaction's
        // outputs before the next transaction is connected.
        std::map<uint256, CTransactionRef> inBlock;
        for (const auto& txRef : block.vtx) inBlock[txRef->GetHash()] = txRef;
        const auto lookup = [&inBlock](const COutPoint& out, CTxOut& txOut) -> bool {
            const auto it = inBlock.find(out.hash);
            if (it != inBlock.end()) {
                if (out.n >= it->second->vout.size()) return false;
                txOut = it->second->vout[out.n];
                return true;
            }
            const CCoins* coins = pcoinsTip->AccessCoins(out.hash);
            if (coins == nullptr || !coins->IsAvailable(out.n)) return false;
            txOut = coins->vout[out.n];
            return true;
        };

        uint256 attestation;
        uint256 existing;
        if (patattest::FindCommitments(*block.vtx[0], existing) == 0 &&
            patattest::ComputeBlockAttestation(
                patattest::CollectBatch(block, lookup, patParams), attestation)) {
            CTxOut patOut;
            patOut.nValue = 0;
            patOut.scriptPubKey = patattest::BuildCommitmentScript(attestation);
            CMutableTransaction tx(*block.vtx[0]);
            tx.vout.push_back(patOut);
            block.vtx[0] = MakeTransactionRef(std::move(tx));
            LogPrintf("PAT: added block attestation commitment (hash=%s)\n",
                attestation.ToString().substr(0, 16));
        }
    }

    UpdateUncommittedBlockStructures(block, pindexPrev, consensusParams);
    return commitment;
}

bool ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, const CBlockIndex* pindexPrev, int64_t nAdjustedTime)
{
    const int nHeight = pindexPrev == NULL ? 0 : pindexPrev->nHeight + 1;
    const CChainParams& params = Params();
    const Consensus::Params& consensusParams = params.GetConsensus(nHeight);

    // Disallow legacy blocks after merge-mining start.
    if (!consensusParams.fAllowLegacyBlocks && block.IsLegacy())
        return state.DoS(100, error("%s : legacy block after auxpow start", __func__),
            REJECT_INVALID, "late-legacy-block");

    // AuxPoW height enforcement: reject AuxPoW blocks before the activation
    // height. On mainnet, nAuxpowStartHeight=0 (AuxPoW from genesis).
    // nAuxpowStartHeight: mainnet=0, stagenet=100, testnet=0, regtest=20.
    // Solo mining via getblocktemplate/submitblock is always available at all heights.
    if (block.IsAuxpow() && nHeight < consensusParams.nAuxpowStartHeight)
        return state.DoS(100, error("%s : auxpow block at height %d rejected, AuxPoW activates at height %d",
            __func__, nHeight, consensusParams.nAuxpowStartHeight),
            REJECT_INVALID, "early-auxpow-block");

    // Check proof of work
    if (block.nBits != GetNextWorkRequired(pindexPrev, &block, consensusParams))
        return state.DoS(100, false, REJECT_INVALID, "bad-diffbits", false, "incorrect proof of work");

    // Check against checkpoints
    if (fCheckpointsEnabled) {
        // Don't accept any forks from the main chain prior to last checkpoint.
        // GetLastCheckpoint finds the last checkpoint in MapCheckpoints that's in our
        // MapBlockIndex.
        CBlockIndex* pcheckpoint = Checkpoints::GetLastCheckpoint(params.Checkpoints());
        if (pcheckpoint && nHeight < pcheckpoint->nHeight)
            return state.DoS(100, error("%s: forked chain older than last checkpoint (height %d)", __func__, nHeight), REJECT_CHECKPOINT, "bad-fork-prior-to-checkpoint");
    }

    // Finality horizon (anti-deep-reorg). A small merge-mined chain cannot
    // out-hash a rental 51% attack (Analysis [A], 2026-06-22) — renting a
    // majority of SOQ's scrypt hashrate is ~free because the same hashrate
    // earns LTC+DOGE. So we refuse to reorganize more than nMaxReorgDepth blocks
    // deep: a block building on a branch that forks below the horizon can never
    // join the active chain, making sufficiently buried history final
    // regardless of attacker hashrate. Skipped during initial sync, when the
    // node must be free to select the most-work chain while bootstrapping.
    // No peer ban (DoS 0): near the horizon two honest nodes can briefly
    // disagree, and banning would partition them. 0 = disabled (e.g. regtest).
    if (consensusParams.nMaxReorgDepth > 0 && pindexPrev != NULL &&
        chainActive.Tip() != NULL && !IsInitialBlockDownload()) {
        const CBlockIndex* pforkPrev = chainActive.FindFork(pindexPrev);
        if (pforkPrev != NULL) {
            const int nReorgDepth = chainActive.Height() - pforkPrev->nHeight;
            if (nReorgDepth >= consensusParams.nMaxReorgDepth)
                return state.DoS(0, error("%s: block builds on a fork %d blocks deep, beyond the %d-block finality horizon",
                    __func__, nReorgDepth, consensusParams.nMaxReorgDepth),
                    REJECT_INVALID, "bad-fork-beyond-finality");
        }
    }

    // Check timestamp against prev
    if (block.GetBlockTime() <= pindexPrev->GetMedianTimePast())
        return state.Invalid(false, REJECT_INVALID, "time-too-old", "block's timestamp is too early");

    // Check timestamp
    if (block.GetBlockTime() > nAdjustedTime + 2 * 60 * 60)
        return state.Invalid(false, REJECT_INVALID, "time-too-new", "block timestamp too far in the future");

    // Reject outdated version blocks when 95% (75% on testnet) of the network has upgraded:
    // check for version 2, 3 and 4 upgrades
    // Soqucoin: Version 2 enforcement was never used
    if ((block.GetBaseVersion() < 3 && nHeight >= consensusParams.BIP66Height) ||
        (block.GetBaseVersion() < 4 && nHeight >= consensusParams.BIP65Height))
        return state.Invalid(false, REJECT_OBSOLETE, strprintf("bad-version(0x%08x)", block.GetBaseVersion()),
            strprintf("rejected nVersion=0x%08x block", block.GetBaseVersion()));

    return true;
}

bool ContextualCheckBlock(const CBlock& block, CValidationState& state, const CBlockIndex* pindexPrev)
{
    const int nHeight = pindexPrev == NULL ? 0 : pindexPrev->nHeight + 1;
    const CChainParams& chainParams = Params();
    const Consensus::Params& consensusParams = chainParams.GetConsensus(nHeight);

    // Start enforcing BIP113 (Median Time Past) using versionbits logic.
    // Soqucoin: We probably want to disable this
    int nLockTimeFlags = 0;
    if (VersionBitsState(pindexPrev, consensusParams, Consensus::DEPLOYMENT_CSV, versionbitscache) == THRESHOLD_ACTIVE) {
        nLockTimeFlags |= LOCKTIME_MEDIAN_TIME_PAST;
    }

    // SOQ-REINDEX-001: Guard against NULL pindexPrev when CSV is ALWAYS_ACTIVE.
    // During -reindex, the genesis block (pindexPrev=NULL) reaches this code with
    // LOCKTIME_MEDIAN_TIME_PAST set because VersionBitsState returns ACTIVE for
    // ALWAYS_ACTIVE deployments regardless of pindexPrev. Fallback to 0 is safe —
    // the genesis block has no parent, so median time past is undefined.
    int64_t nLockTimeCutoff = (nLockTimeFlags & LOCKTIME_MEDIAN_TIME_PAST)
        ? (pindexPrev ? pindexPrev->GetMedianTimePast() : 0)
        : block.GetBlockTime();

    // Check that all transactions are finalized
    for (const auto& tx : block.vtx) {
        if (!IsFinalTx(*tx, nHeight, nLockTimeCutoff)) {
            return state.DoS(10, false, REJECT_INVALID, "bad-txns-nonfinal", false, "non-final transaction");
        }
    }

    // Enforce rule that the coinbase starts with serialized block height
    if (nHeight >= consensusParams.BIP34Height) {
        CScript expect = CScript() << nHeight;
        if (block.vtx[0]->vin[0].scriptSig.size() < expect.size() ||
            !std::equal(expect.begin(), expect.end(), block.vtx[0]->vin[0].scriptSig.begin())) {
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-height", false, "block height mismatch in coinbase");
        }
    }

    // Enforce strict Dilithium coinbase output (OP_1 <32-byte hash>)
    // Reject any coinbase output that is not Dilithium bech32m v1 (or OP_RETURN for witness commitment)
    // SOQ-REINDEX-001: Exempt genesis block (nHeight == 0). The exemption is load-bearing
    // for testnet3 and stagenet, whose geneses carry the legacy P2PK output from
    // CreateGenesisBlock(); mainnet's ceremony genesis (2026-09-02) is a bare OP_RETURN
    // and would pass this check anyway. During normal sync, genesis bypasses this check
    // via InitBlockIndex(), but -reindex routes through AcceptBlock → ContextualCheckBlock.
    if (nHeight > 0 && chainParams.NetworkIDString() != CBaseChainParams::REGTEST) {
        for (const auto& txout : block.vtx[0]->vout) {
            const CScript& scriptPubKey = txout.scriptPubKey;
            // Dilithium P2WPKH-equivalent: OP_1 <32-byte hash>
            bool is_dilithium = (scriptPubKey.size() == 34 && scriptPubKey[0] == OP_1 && scriptPubKey[1] == 32);
            bool is_op_return = (scriptPubKey.size() > 0 && scriptPubKey[0] == OP_RETURN);
            if (!is_dilithium && !is_op_return) {
                return state.DoS(100, false, REJECT_INVALID, "bad-cb-output-type", false, "coinbase output must be Dilithium bech32m");
            }
        }
    }

    // Validation for witness commitments.
    // * We compute the witness hash (which is the hash including witnesses) of all the block's transactions, except the
    //   coinbase (where 0x0000....0000 is used instead).
    // * The coinbase scriptWitness is a stack of a single 32-byte vector, containing a witness nonce (unconstrained).
    // * We build a merkle tree with all those witness hashes as leaves (similar to the hashMerkleRoot in the block header).
    // * There must be at least one output whose scriptPubKey is a single 36-byte push, the first 4 bytes of which are
    //   {0xaa, 0x21, 0xa9, 0xed}, and the following 32 bytes are SHA256^2(witness root, witness nonce). In case there are
    //   multiple, the last one is used.
    bool fHaveWitness = false;
    if (VersionBitsState(pindexPrev, consensusParams, Consensus::DEPLOYMENT_SEGWIT, versionbitscache) == THRESHOLD_ACTIVE || GetBoolArg("-prematurewitness", false)) {
        int commitpos = GetWitnessCommitmentIndex(block);
        if (commitpos != -1) {
            bool malleated = false;
            uint256 hashWitness = BlockWitnessMerkleRoot(block, &malleated);
            // The malleation check is ignored; as the transaction tree itself
            // already does not permit it, it is impossible to trigger in the
            // witness tree.
            if (block.vtx[0]->vin[0].scriptWitness.stack.size() != 1 || block.vtx[0]->vin[0].scriptWitness.stack[0].size() != 32) {
                return state.DoS(100, false, REJECT_INVALID, "bad-witness-nonce-size", true, strprintf("%s : invalid witness nonce size", __func__));
            }
            CHash256().Write(hashWitness.begin(), 32).Write(&block.vtx[0]->vin[0].scriptWitness.stack[0][0], 32).Finalize(hashWitness.begin());
            if (memcmp(hashWitness.begin(), &block.vtx[0]->vout[commitpos].scriptPubKey[6], 32)) {
                return state.DoS(100, false, REJECT_INVALID, "bad-witness-merkle-match", true, strprintf("%s : witness merkle commitment mismatch", __func__));
            }
            fHaveWitness = true;
        }
    }

    // No witness data is allowed in blocks that don't commit to witness data, as this would otherwise leave room for spam
    if (!fHaveWitness) {
        for (size_t i = 0; i < block.vtx.size(); i++) {
            if (block.vtx[i]->HasWitness()) {
                return state.DoS(100, false, REJECT_INVALID, "unexpected-witness", true, strprintf("%s : unexpected witness data found", __func__));
            }
        }
    }

    // After the coinbase witness nonce and commitment are verified,
    // we can check if the block weight passes (before we've checked the
    // coinbase witness, it would be possible for the weight to be too
    // large by filling up the coinbase witness, which doesn't change
    // the block hash, so we couldn't mark the block as permanently
    // failed).
    if (GetBlockWeight(block) > MAX_BLOCK_WEIGHT) {
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-weight", false, strprintf("%s : weight limit failed", __func__));
    }

    return true;
}

static bool AcceptBlockHeader(const CBlockHeader& block, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex)
{
    AssertLockHeld(cs_main);
    // Check for duplicate
    uint256 hash = block.GetHash();
    BlockMap::iterator miSelf = mapBlockIndex.find(hash);
    CBlockIndex* pindex = NULL;
    if (hash != chainparams.GetConsensus(0).hashGenesisBlock) {
        if (miSelf != mapBlockIndex.end()) {
            // Block header is already known.
            pindex = miSelf->second;
            if (ppindex)
                *ppindex = pindex;
            if (pindex->nStatus & BLOCK_FAILED_MASK)
                return state.Invalid(error("%s: block %s is marked invalid", __func__, hash.ToString()), 0, "duplicate");
            return true;
        }

        if (!CheckBlockHeader(block, state))
            return error("%s: Consensus::CheckBlockHeader: %s, %s", __func__, hash.ToString(), FormatStateMessage(state));

        // Get prev block index
        CBlockIndex* pindexPrev = NULL;
        BlockMap::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
        if (mi == mapBlockIndex.end())
            return state.DoS(10, error("%s: prev block not found", __func__), 0, "bad-prevblk");
        pindexPrev = (*mi).second;
        if (pindexPrev->nStatus & BLOCK_FAILED_MASK)
            return state.DoS(100, error("%s: prev block invalid", __func__), REJECT_INVALID, "bad-prevblk");

        assert(pindexPrev);

        if (!ContextualCheckBlockHeader(block, state, pindexPrev, GetAdjustedTime()))
            return error("%s: Consensus::ContextualCheckBlockHeader: %s, %s", __func__, hash.ToString(), FormatStateMessage(state));

        if (!pindexPrev->IsValid(BLOCK_VALID_SCRIPTS)) {
            for (const CBlockIndex* failedit : gFailedBlocks) {
                if (pindexPrev->GetAncestor(failedit->nHeight) == failedit) {
                    assert(failedit->nStatus & BLOCK_FAILED_VALID);
                    CBlockIndex* invalidWalk = pindexPrev;
                    while (invalidWalk != failedit) {
                        invalidWalk->nStatus |= BLOCK_FAILED_CHILD;
                        setDirtyBlockIndex.insert(invalidWalk);
                        invalidWalk = invalidWalk->pprev;
                    }

                    LogPrintf("AcceptBlockHeader(): Invalid block %s, rejected child hash %s.", invalidWalk->GetBlockHash().ToString(), hash.ToString());
                    return state.DoS(100, error("%s: prev block invalid", __func__), REJECT_INVALID, "bad-prevblk");
                }
            }
        }
    }
    if (pindex == NULL)
        pindex = AddToBlockIndex(block);

    if (ppindex)
        *ppindex = pindex;

    CheckBlockIndex(chainparams.GetConsensus(pindex->nHeight));

    return true;
}

// Exposed wrapper for AcceptBlockHeader
bool ProcessNewBlockHeaders(const std::vector<CBlockHeader>& headers, CValidationState& state, const CChainParams& chainparams, const CBlockIndex** ppindex)
{
    {
        LOCK(cs_main);
        for (const CBlockHeader& header : headers) {
            CBlockIndex* pindex = NULL; // Use a temp pindex instead of ppindex to avoid a const_cast
            if (!AcceptBlockHeader(header, state, chainparams, &pindex)) {
                return false;
            }
            if (ppindex) {
                *ppindex = pindex;
            }
        }
    }
    NotifyHeaderTip();
    return true;
}

/** Store block on disk. If dbp is non-NULL, the file is known to already reside on disk */
static bool AcceptBlock(const std::shared_ptr<const CBlock>& pblock, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex, bool fRequested, const CDiskBlockPos* dbp, bool* fNewBlock)
{
    const CBlock& block = *pblock;

    if (fNewBlock) *fNewBlock = false;
    AssertLockHeld(cs_main);

    CBlockIndex* pindexDummy = NULL;
    CBlockIndex*& pindex = ppindex ? *ppindex : pindexDummy;

    if (!AcceptBlockHeader(block, state, chainparams, &pindex))
        return false;

    // Try to process all requested blocks that we don't have, but only
    // process an unrequested block if it's new and has enough work to
    // advance our tip, and isn't too many blocks ahead.
    bool fAlreadyHave = pindex->nStatus & BLOCK_HAVE_DATA;
    bool fHasMoreWork = (chainActive.Tip() ? pindex->nChainWork > chainActive.Tip()->nChainWork : true);
    // Blocks that are too out-of-order needlessly limit the effectiveness of
    // pruning, because pruning will not delete block files that contain any
    // blocks which are too close in height to the tip.  Apply this test
    // regardless of whether pruning is enabled; it should generally be safe to
    // not process unrequested blocks.
    bool fTooFarAhead = (pindex->nHeight > int(chainActive.Height() + MIN_BLOCKS_TO_KEEP));

    // TODO: Decouple this function from the block download logic by removing fRequested
    // This requires some new chain datastructure to efficiently look up if a
    // block is in a chain leading to a candidate for best tip, despite not
    // being such a candidate itself.

    // TODO: deal better with return value and error conditions for duplicate
    // and unrequested blocks.
    if (fAlreadyHave) return true;
    if (!fRequested) {                     // If we didn't ask for it:
        if (pindex->nTx != 0) return true; // This is a previously-processed block that was pruned
        if (!fHasMoreWork) return true;    // Don't process less-work chains
        if (fTooFarAhead) return true;     // Block height is too high
    }
    if (fNewBlock) *fNewBlock = true;

    if (!CheckBlock(block, state) ||
        !ContextualCheckBlock(block, state, pindex->pprev)) {
        if (state.IsInvalid() && !state.CorruptionPossible()) {
            pindex->nStatus |= BLOCK_FAILED_VALID;
            setDirtyBlockIndex.insert(pindex);
        }
        return error("%s: %s", __func__, FormatStateMessage(state));
    }

    // Header is valid/has work, merkle tree and segwit merkle tree are good...RELAY NOW
    // (but if it does not build on our best tip, let the SendMessages loop relay it)
    if (!IsInitialBlockDownload() && chainActive.Tip() == pindex->pprev)
        GetMainSignals().NewPoWValidBlock(pindex, pblock);

    int nHeight = pindex->nHeight;

    // Write block to history file
    try {
        unsigned int nBlockSize = ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION);
        CDiskBlockPos blockPos;
        if (dbp != NULL)
            blockPos = *dbp;
        if (!FindBlockPos(state, blockPos, nBlockSize + 8, nHeight, block.GetBlockTime(), dbp != NULL))
            return error("AcceptBlock(): FindBlockPos failed");
        if (dbp == NULL)
            if (!WriteBlockToDisk(block, blockPos, chainparams.MessageStart()))
                AbortNode(state, "Failed to write block");
        if (!ReceivedBlockTransactions(block, state, pindex, blockPos))
            return error("AcceptBlock(): ReceivedBlockTransactions failed");
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error: ") + e.what());
    }

    if (fCheckForPruning)
        FlushStateToDisk(state, FLUSH_STATE_NONE); // we just allocated more disk space for block files

    return true;
}

static bool IsSuperMajority(int minVersion, const CBlockIndex* pstart, unsigned nRequired, const Consensus::Params& consensusParams)
{
    unsigned int nFound = 0;
    for (int i = 0; i < consensusParams.nMajorityWindow && nFound < nRequired && pstart != NULL; i++) {
        if (pstart->GetBaseVersion() >= minVersion)
            ++nFound;
        pstart = pstart->pprev;
    }
    return (nFound >= nRequired);
}

bool ProcessNewBlock(const CChainParams& chainparams, const std::shared_ptr<const CBlock> pblock, bool fForceProcessing, bool* fNewBlock)
{
    {
        CBlockIndex* pindex = NULL;
        if (fNewBlock) *fNewBlock = false;
        CValidationState state;
        // Ensure that CheckBlock() passes before calling AcceptBlock, as
        // belt-and-suspenders.
        bool ret = CheckBlock(*pblock, state);

        LOCK(cs_main);

        if (ret) {
            // Store to disk
            ret = AcceptBlock(pblock, state, chainparams, &pindex, fForceProcessing, NULL, fNewBlock);
        }
        CheckBlockIndex(chainparams.GetConsensus(chainActive.Height()));
        if (!ret) {
            GetMainSignals().BlockChecked(*pblock, state);
            return error("%s: AcceptBlock FAILED", __func__);
        }
    }

    NotifyHeaderTip();

    CValidationState state; // Only used to report errors, not invalidity - ignore it
    if (!ActivateBestChain(state, chainparams, pblock))
        return error("%s: ActivateBestChain failed", __func__);

    return true;
}

bool TestBlockValidity(CValidationState& state, const CChainParams& chainparams, const CBlock& block, CBlockIndex* pindexPrev, bool fCheckPOW, bool fCheckMerkleRoot)
{
    AssertLockHeld(cs_main);
    assert(pindexPrev && pindexPrev == chainActive.Tip());
    CCoinsViewCache viewNew(pcoinsTip);
    CBlockIndex indexDummy(block);
    indexDummy.pprev = pindexPrev;
    indexDummy.nHeight = pindexPrev->nHeight + 1;

    // NOTE: CheckBlockHeader is called by CheckBlock
    if (!ContextualCheckBlockHeader(block, state, pindexPrev, GetAdjustedTime()))
        return error("%s: Consensus::ContextualCheckBlockHeader: %s", __func__, FormatStateMessage(state));
    if (!CheckBlock(block, state, fCheckPOW, fCheckMerkleRoot))
        return error("%s: Consensus::CheckBlock: %s", __func__, FormatStateMessage(state));
    if (!ContextualCheckBlock(block, state, pindexPrev))
        return error("%s: Consensus::ContextualCheckBlock: %s", __func__, FormatStateMessage(state));
    if (!ConnectBlock(block, state, &indexDummy, viewNew, chainparams, true))
        return false;
    assert(state.IsValid());

    return true;
}

/**
 * BLOCK PRUNING CODE
 */

/* Calculate the amount of disk space the block & undo files currently use */
uint64_t CalculateCurrentUsage()
{
    LOCK(cs_LastBlockFile);

    uint64_t retval = 0;
    BOOST_FOREACH (const CBlockFileInfo& file, vinfoBlockFile) {
        retval += file.nSize + file.nUndoSize;
    }
    return retval;
}

/* Prune a block file (modify associated database entries)*/
void PruneOneBlockFile(const int fileNumber)
{
    LOCK(cs_LastBlockFile);

    for (BlockMap::iterator it = mapBlockIndex.begin(); it != mapBlockIndex.end(); ++it) {
        CBlockIndex* pindex = it->second;
        if (pindex->nFile == fileNumber) {
            pindex->nStatus &= ~BLOCK_HAVE_DATA;
            pindex->nStatus &= ~BLOCK_HAVE_UNDO;
            pindex->nFile = 0;
            pindex->nDataPos = 0;
            pindex->nUndoPos = 0;
            setDirtyBlockIndex.insert(pindex);

            // Prune from mapBlocksUnlinked -- any block we prune would have
            // to be downloaded again in order to consider its chain, at which
            // point it would be considered as a candidate for
            // mapBlocksUnlinked or setBlockIndexCandidates.
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = mapBlocksUnlinked.equal_range(pindex->pprev);
            while (range.first != range.second) {
                std::multimap<CBlockIndex*, CBlockIndex*>::iterator _it = range.first;
                range.first++;
                if (_it->second == pindex) {
                    mapBlocksUnlinked.erase(_it);
                }
            }
        }
    }

    vinfoBlockFile[fileNumber].SetNull();
    setDirtyFileInfo.insert(fileNumber);
}


void UnlinkPrunedFiles(const std::set<int>& setFilesToPrune)
{
    for (std::set<int>::iterator it = setFilesToPrune.begin(); it != setFilesToPrune.end(); ++it) {
        CDiskBlockPos pos(*it, 0);
        fs::remove(GetBlockPosFilename(pos, "blk"));
        fs::remove(GetBlockPosFilename(pos, "rev"));
        LogPrintf("Prune: %s deleted blk/rev (%05u)\n", __func__, *it);
    }
}

/* Calculate the block/rev files to delete based on height specified by user with RPC command pruneblockchain */
void FindFilesToPruneManual(std::set<int>& setFilesToPrune, int nManualPruneHeight)
{
    assert(fPruneMode && nManualPruneHeight > 0);

    LOCK2(cs_main, cs_LastBlockFile);
    if (chainActive.Tip() == NULL)
        return;

    // last block to prune is the lesser of (user-specified height, MIN_BLOCKS_TO_KEEP from the tip)
    unsigned int nLastBlockWeCanPrune = std::min((unsigned)nManualPruneHeight, chainActive.Height() - MIN_BLOCKS_TO_KEEP);
    int count = 0;
    for (int fileNumber = 0; fileNumber < nLastBlockFile; fileNumber++) {
        if (vinfoBlockFile[fileNumber].nSize == 0 || vinfoBlockFile[fileNumber].nHeightLast > nLastBlockWeCanPrune)
            continue;
        PruneOneBlockFile(fileNumber);
        setFilesToPrune.insert(fileNumber);
        count++;
    }
    LogPrintf("Prune (Manual): prune_height=%d removed %d blk/rev pairs\n", nLastBlockWeCanPrune, count);
}

/* This function is called from the RPC code for pruneblockchain */
void PruneBlockFilesManual(int nManualPruneHeight)
{
    CValidationState state;
    FlushStateToDisk(state, FLUSH_STATE_NONE, nManualPruneHeight);
}

/* Calculate the block/rev files that should be deleted to remain under target*/
void FindFilesToPrune(std::set<int>& setFilesToPrune, uint64_t nPruneAfterHeight)
{
    LOCK2(cs_main, cs_LastBlockFile);
    if (chainActive.Tip() == NULL || nPruneTarget == 0) {
        return;
    }
    if ((uint64_t)chainActive.Height() <= nPruneAfterHeight) {
        return;
    }

    unsigned int nLastBlockWeCanPrune = chainActive.Height() - MIN_BLOCKS_TO_KEEP;
    uint64_t nCurrentUsage = CalculateCurrentUsage();
    // We don't check to prune until after we've allocated new space for files
    // So we should leave a buffer under our target to account for another allocation
    // before the next pruning.
    uint64_t nBuffer = BLOCKFILE_CHUNK_SIZE + UNDOFILE_CHUNK_SIZE;
    uint64_t nBytesToPrune;
    int count = 0;

    if (nCurrentUsage + nBuffer >= nPruneTarget) {
        for (int fileNumber = 0; fileNumber < nLastBlockFile; fileNumber++) {
            nBytesToPrune = vinfoBlockFile[fileNumber].nSize + vinfoBlockFile[fileNumber].nUndoSize;

            if (vinfoBlockFile[fileNumber].nSize == 0)
                continue;

            if (nCurrentUsage + nBuffer < nPruneTarget) // are we below our target?
                break;

            // don't prune files that could have a block within MIN_BLOCKS_TO_KEEP of the main chain's tip but keep scanning
            if (vinfoBlockFile[fileNumber].nHeightLast > nLastBlockWeCanPrune)
                continue;

            PruneOneBlockFile(fileNumber);
            // Queue up the files for removal
            setFilesToPrune.insert(fileNumber);
            nCurrentUsage -= nBytesToPrune;
            count++;
        }
    }

    LogPrint("prune", "Prune: target=%dMiB actual=%dMiB diff=%dMiB max_prune_height=%d removed %d blk/rev pairs\n",
        nPruneTarget / 1024 / 1024, nCurrentUsage / 1024 / 1024,
        ((int64_t)nPruneTarget - (int64_t)nCurrentUsage) / 1024 / 1024,
        nLastBlockWeCanPrune, count);
}

bool CheckDiskSpace(uint64_t nAdditionalBytes)
{
    uint64_t nFreeBytesAvailable = fs::space(GetDataDir()).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
        return AbortNode("Disk space is low!", _("Error: Disk space is low!"));

    return true;
}

FILE* OpenDiskFile(const CDiskBlockPos& pos, const char* prefix, bool fReadOnly)
{
    if (pos.IsNull())
        return NULL;
    fs::path path = GetBlockPosFilename(pos, prefix);
    fs::create_directories(path.parent_path());
    FILE* file = fsbridge::fopen(path, "rb+");
    if (!file && !fReadOnly)
        file = fsbridge::fopen(path, "wb+");
    if (!file) {
        LogPrintf("Unable to open file %s\n", path.string());
        return NULL;
    }
    if (pos.nPos) {
        if (fseek(file, pos.nPos, SEEK_SET)) {
            LogPrintf("Unable to seek to position %u of %s\n", pos.nPos, path.string());
            fclose(file);
            return NULL;
        }
    }
    return file;
}

FILE* OpenBlockFile(const CDiskBlockPos& pos, bool fReadOnly)
{
    return OpenDiskFile(pos, "blk", fReadOnly);
}

FILE* OpenUndoFile(const CDiskBlockPos& pos, bool fReadOnly)
{
    return OpenDiskFile(pos, "rev", fReadOnly);
}

fs::path GetBlockPosFilename(const CDiskBlockPos& pos, const char* prefix)
{
    return GetDataDir() / "blocks" / strprintf("%s%05u.dat", prefix, pos.nFile);
}

CBlockIndex* InsertBlockIndex(uint256 hash)
{
    if (hash.IsNull())
        return NULL;

    // Return existing
    BlockMap::iterator mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        return (*mi).second;

    // Create new
    CBlockIndex* pindexNew = new CBlockIndex();
    if (!pindexNew)
        throw std::runtime_error(std::string(__func__) + ": new CBlockIndex failed");
    mi = mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}

bool static LoadBlockIndexDB(const CChainParams& chainparams)
{
    if (!pblocktree->LoadBlockIndexGuts(InsertBlockIndex))
        return false;

    boost::this_thread::interruption_point();

    // Calculate nChainWork
    std::vector<std::pair<int, CBlockIndex*> > vSortedByHeight;
    vSortedByHeight.reserve(mapBlockIndex.size());
    BOOST_FOREACH (const PAIRTYPE(uint256, CBlockIndex*) & item, mapBlockIndex) {
        CBlockIndex* pindex = item.second;
        vSortedByHeight.push_back(std::make_pair(pindex->nHeight, pindex));
    }
    sort(vSortedByHeight.begin(), vSortedByHeight.end());
    BOOST_FOREACH (const PAIRTYPE(int, CBlockIndex*) & item, vSortedByHeight) {
        CBlockIndex* pindex = item.second;
        pindex->nChainWork = (pindex->pprev ? pindex->pprev->nChainWork : 0) + GetBlockProof(*pindex);
        pindex->nTimeMax = (pindex->pprev ? std::max(pindex->pprev->nTimeMax, pindex->nTime) : pindex->nTime);
        // We can link the chain of blocks for which we've received transactions at some point.
        // Pruned nodes may have deleted the block.
        if (pindex->nTx > 0) {
            if (pindex->pprev) {
                if (pindex->pprev->nChainTx) {
                    pindex->nChainTx = pindex->pprev->nChainTx + pindex->nTx;
                } else {
                    pindex->nChainTx = 0;
                    mapBlocksUnlinked.insert(std::make_pair(pindex->pprev, pindex));
                }
            } else {
                pindex->nChainTx = pindex->nTx;
            }
            if (!(pindex->nStatus & BLOCK_FAILED_MASK) && pindex->pprev && (pindex->pprev->nStatus & BLOCK_FAILED_MASK)) {
                LogPrintf("Invalid Block %s.", pindex->GetBlockHash().ToString());
                pindex->nStatus |= BLOCK_FAILED_CHILD;
                setDirtyBlockIndex.insert(pindex);
            }
        }
        if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) && (pindex->nChainTx || pindex->pprev == NULL))
            setBlockIndexCandidates.insert(pindex);
        if (pindex->nStatus & BLOCK_FAILED_MASK && (!pindexBestInvalid || pindex->nChainWork > pindexBestInvalid->nChainWork))
            pindexBestInvalid = pindex;
        if (pindex->pprev)
            pindex->BuildSkip();
        if (pindex->IsValid(BLOCK_VALID_TREE) && (pindexBestHeader == NULL || CBlockIndexWorkComparator()(pindexBestHeader, pindex)))
            pindexBestHeader = pindex;
    }

    // Load block file info
    pblocktree->ReadLastBlockFile(nLastBlockFile);
    vinfoBlockFile.resize(nLastBlockFile + 1);
    LogPrintf("%s: last block file = %i\n", __func__, nLastBlockFile);
    for (int nFile = 0; nFile <= nLastBlockFile; nFile++) {
        pblocktree->ReadBlockFileInfo(nFile, vinfoBlockFile[nFile]);
    }
    LogPrintf("%s: last block file info: %s\n", __func__, vinfoBlockFile[nLastBlockFile].ToString());
    for (int nFile = nLastBlockFile + 1; true; nFile++) {
        CBlockFileInfo info;
        if (pblocktree->ReadBlockFileInfo(nFile, info)) {
            vinfoBlockFile.push_back(info);
        } else {
            break;
        }
    }

    // Check presence of blk files
    LogPrintf("Checking all blk files are present...\n");
    std::set<int> setBlkDataFiles;
    BOOST_FOREACH (const PAIRTYPE(uint256, CBlockIndex*) & item, mapBlockIndex) {
        CBlockIndex* pindex = item.second;
        if (pindex->nStatus & BLOCK_HAVE_DATA) {
            setBlkDataFiles.insert(pindex->nFile);
        }
    }
    for (std::set<int>::iterator it = setBlkDataFiles.begin(); it != setBlkDataFiles.end(); it++) {
        CDiskBlockPos pos(*it, 0);
        if (CAutoFile(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION).IsNull()) {
            return false;
        }
    }

    // Check whether we have ever pruned block & undo files
    pblocktree->ReadFlag("prunedblockfiles", fHavePruned);
    if (fHavePruned)
        LogPrintf("LoadBlockIndexDB(): Block files have previously been pruned\n");

    // Check whether we need to continue reindexing
    bool fReindexing = false;
    pblocktree->ReadReindexing(fReindexing);
    fReindex |= fReindexing;

    // Check whether we have a transaction index
    pblocktree->ReadFlag("txindex", fTxIndex);
    LogPrintf("%s: transaction index %s\n", __func__, fTxIndex ? "enabled" : "disabled");

    // Load pointer to end of best chain
    BlockMap::iterator it = mapBlockIndex.find(pcoinsTip->GetBestBlock());
    if (it == mapBlockIndex.end())
        return true;
    chainActive.SetTip(it->second);

    PruneBlockIndexCandidates();

    LogPrintf("%s: hashBestChain=%s height=%d date=%s progress=%f\n", __func__,
        chainActive.Tip()->GetBlockHash().ToString(), chainActive.Height(),
        DateTimeStrFormat("%Y-%m-%d %H:%M:%S", chainActive.Tip()->GetBlockTime()),
        GuessVerificationProgress(chainparams.TxData(), chainActive.Tip()));

    return true;
}

CVerifyDB::CVerifyDB()
{
    uiInterface.ShowProgress(_("Verifying blocks..."), 0);
}

CVerifyDB::~CVerifyDB()
{
    uiInterface.ShowProgress("", 100);
}

bool CVerifyDB::VerifyDB(const CChainParams& chainparams, CCoinsView* coinsview, int nCheckLevel, int nCheckDepth)
{
    LOCK(cs_main);
    if (chainActive.Tip() == NULL || chainActive.Tip()->pprev == NULL)
        return true;

    // Verify blocks in the best chain
    if (nCheckDepth <= 0)
        nCheckDepth = 1000000000; // suffices until the year 19000
    if (nCheckDepth > chainActive.Height())
        nCheckDepth = chainActive.Height();
    nCheckLevel = std::max(0, std::min(4, nCheckLevel));
    LogPrintf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CCoinsViewCache coins(coinsview);
    CBlockIndex* pindexState = chainActive.Tip();
    CBlockIndex* pindexFailure = NULL;
    int nGoodTransactions = 0;
    CValidationState state;
    int reportDone = 0;
    LogPrintf("[0%%]...");
    for (CBlockIndex* pindex = chainActive.Tip(); pindex && pindex->pprev; pindex = pindex->pprev) {
        boost::this_thread::interruption_point();
        int percentageDone = std::max(1, std::min(99, (int)(((double)(chainActive.Height() - pindex->nHeight)) / (double)nCheckDepth * (nCheckLevel >= 4 ? 50 : 100))));
        if (reportDone < percentageDone / 10) {
            // report every 10% step
            LogPrintf("[%d%%]...", percentageDone);
            reportDone = percentageDone / 10;
        }
        uiInterface.ShowProgress(_("Verifying blocks..."), percentageDone);
        if (pindex->nHeight < chainActive.Height() - nCheckDepth)
            break;
        if (fPruneMode && !(pindex->nStatus & BLOCK_HAVE_DATA)) {
            // If pruning, only go back as far as we have data.
            LogPrintf("VerifyDB(): block verification stopping at height %d (pruning, no data)\n", pindex->nHeight);
            break;
        }
        CBlock block;
        // check level 0: read from disk
        if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus(pindex->nHeight)))
            return error("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
        // check level 1: verify block validity
        if (nCheckLevel >= 1 && !CheckBlock(block, state))
            return error("%s: *** found bad block at %d, hash=%s (%s)\n", __func__,
                pindex->nHeight, pindex->GetBlockHash().ToString(), FormatStateMessage(state));
        // check level 2: verify undo validity
        if (nCheckLevel >= 2 && pindex) {
            CBlockUndo undo;
            CDiskBlockPos pos = pindex->GetUndoPos();
            if (!pos.IsNull()) {
                if (!UndoReadFromDisk(undo, pos, pindex->pprev->GetBlockHash()))
                    return error("VerifyDB(): *** found bad undo data at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
            }
        }
        // check level 3: check for inconsistencies during memory-only disconnect of tip blocks
        if (nCheckLevel >= 3 && pindex == pindexState && (coins.DynamicMemoryUsage() + pcoinsTip->DynamicMemoryUsage()) <= nCoinCacheUsage) {
            bool fClean = true;
            if (!DisconnectBlock(block, state, pindex, coins, &fClean))
                return error("VerifyDB(): *** irrecoverable inconsistency in block data at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
            pindexState = pindex->pprev;
            if (!fClean) {
                nGoodTransactions = 0;
                pindexFailure = pindex;
            } else
                nGoodTransactions += block.vtx.size();
        }
        if (ShutdownRequested())
            return true;
    }
    if (pindexFailure)
        return error("VerifyDB(): *** coin database inconsistencies found (last %i blocks, %i good transactions before that)\n", chainActive.Height() - pindexFailure->nHeight + 1, nGoodTransactions);

    // check level 4: try reconnecting blocks
    if (nCheckLevel >= 4) {
        CBlockIndex* pindex = pindexState;
        while (pindex != chainActive.Tip()) {
            boost::this_thread::interruption_point();
            uiInterface.ShowProgress(_("Verifying blocks..."), std::max(1, std::min(99, 100 - (int)(((double)(chainActive.Height() - pindex->nHeight)) / (double)nCheckDepth * 50))));
            pindex = chainActive.Next(pindex);
            CBlock block;
            if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus(pindex->nHeight)))
                return error("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
            if (!ConnectBlock(block, state, pindex, coins, chainparams))
                return error("VerifyDB(): *** found unconnectable block at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
        }
    }

    LogPrintf("[DONE].\n");
    LogPrintf("No coin database inconsistencies in last %i blocks (%i transactions)\n", chainActive.Height() - pindexState->nHeight, nGoodTransactions);

    return true;
}

bool RewindBlockIndex(const CChainParams& params)
{
    LOCK(cs_main);

    int nHeight = 1;
    while (nHeight <= chainActive.Height()) {
        if (IsWitnessEnabled(chainActive[nHeight - 1], params.GetConsensus(nHeight - 1)) && !(chainActive[nHeight]->nStatus & BLOCK_OPT_WITNESS)) {
            break;
        }
        nHeight++;
    }

    // nHeight is now the height of the first insufficiently-validated block, or tipheight + 1
    CValidationState state;
    CBlockIndex* pindex = chainActive.Tip();
    while (chainActive.Height() >= nHeight) {
        if (fPruneMode && !(chainActive.Tip()->nStatus & BLOCK_HAVE_DATA)) {
            // If pruning, don't try rewinding past the HAVE_DATA point;
            // since older blocks can't be served anyway, there's
            // no need to walk further, and trying to DisconnectTip()
            // will fail (and require a needless reindex/redownload
            // of the blockchain).
            break;
        }
        if (!DisconnectTip(state, params, true)) {
            return error("RewindBlockIndex: unable to disconnect block at height %i", pindex->nHeight);
        }
        // Occasionally flush state to disk.
        if (!FlushStateToDisk(state, FLUSH_STATE_PERIODIC))
            return false;
    }

    // Reduce validity flag and have-data flags.
    // We do this after actual disconnecting, otherwise we'll end up writing the lack of data
    // to disk before writing the chainstate, resulting in a failure to continue if interrupted.
    for (BlockMap::iterator it = mapBlockIndex.begin(); it != mapBlockIndex.end(); it++) {
        CBlockIndex* pindexIter = it->second;

        // Note: If we encounter an insufficiently validated block that
        // is on chainActive, it must be because we are a pruning node, and
        // this block or some successor doesn't HAVE_DATA, so we were unable to
        // rewind all the way.  Blocks remaining on chainActive at this point
        // must not have their validity reduced.
        if (IsWitnessEnabled(pindexIter->pprev, params.GetConsensus(pindexIter->nHeight)) && !(pindexIter->nStatus & BLOCK_OPT_WITNESS) && !chainActive.Contains(pindexIter)) {
            // Reduce validity
            pindexIter->nStatus = std::min<unsigned int>(pindexIter->nStatus & BLOCK_VALID_MASK, BLOCK_VALID_TREE) | (pindexIter->nStatus & ~BLOCK_VALID_MASK);
            // Remove have-data flags.
            pindexIter->nStatus &= ~(BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
            // Remove storage location.
            pindexIter->nFile = 0;
            pindexIter->nDataPos = 0;
            pindexIter->nUndoPos = 0;
            // Remove various other things
            pindexIter->nTx = 0;
            pindexIter->nChainTx = 0;
            pindexIter->nSequenceId = 0;
            // Make sure it gets written.
            setDirtyBlockIndex.insert(pindexIter);
            // Update indexes
            setBlockIndexCandidates.erase(pindexIter);
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> ret = mapBlocksUnlinked.equal_range(pindexIter->pprev);
            while (ret.first != ret.second) {
                if (ret.first->second == pindexIter) {
                    mapBlocksUnlinked.erase(ret.first++);
                } else {
                    ++ret.first;
                }
            }
        } else if (pindexIter->IsValid(BLOCK_VALID_TRANSACTIONS) && pindexIter->nChainTx) {
            setBlockIndexCandidates.insert(pindexIter);
        }
    }

    PruneBlockIndexCandidates();

    CheckBlockIndex(params.GetConsensus(chainActive.Height()));

    if (!FlushStateToDisk(state, FLUSH_STATE_ALWAYS)) {
        return false;
    }

    return true;
}

// May NOT be used after any connections are up as much
// of the peer-processing logic assumes a consistent
// block index state
void UnloadBlockIndex()
{
    LOCK(cs_main);
    setBlockIndexCandidates.clear();
    chainActive.SetTip(NULL);
    pindexBestInvalid = NULL;
    pindexBestHeader = NULL;
    mempool.clear();
    mapBlocksUnlinked.clear();
    vinfoBlockFile.clear();
    nLastBlockFile = 0;
    nBlockSequenceId = 1;
    setDirtyBlockIndex.clear();
    gFailedBlocks.clear();
    setDirtyFileInfo.clear();
    versionbitscache.Clear();
    for (int b = 0; b < VERSIONBITS_NUM_BITS; b++) {
        warningcache[b].clear();
    }

    BOOST_FOREACH (BlockMap::value_type& entry, mapBlockIndex) {
        delete entry.second;
    }
    mapBlockIndex.clear();
    fHavePruned = false;
}

bool LoadBlockIndex(const CChainParams& chainparams)
{
    // Load block index from databases
    if (!fReindex && !LoadBlockIndexDB(chainparams))
        return false;
    return true;
}

bool InitBlockIndex(const CChainParams& chainparams)
{
    LOCK(cs_main);

    // Check whether we're already initialized
    if (chainActive.Genesis() != NULL)
        return true;

    // Use the provided setting for -txindex in the new database
    fTxIndex = GetBoolArg("-txindex", DEFAULT_TXINDEX);
    pblocktree->WriteFlag("txindex", fTxIndex);
    LogPrintf("Initializing databases...\n");

    // Only add the genesis block if not reindexing (in which case we reuse the one already on disk)
    if (!fReindex) {
        try {
            CBlock& block = const_cast<CBlock&>(chainparams.GenesisBlock());
            // Start new block file
            unsigned int nBlockSize = ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION);
            CDiskBlockPos blockPos;
            CValidationState state;
            if (!FindBlockPos(state, blockPos, nBlockSize + 8, 0, block.GetBlockTime()))
                return error("LoadBlockIndex(): FindBlockPos failed");
            if (!WriteBlockToDisk(block, blockPos, chainparams.MessageStart()))
                return error("LoadBlockIndex(): writing genesis block to disk failed");
            CBlockIndex* pindex = AddToBlockIndex(block);
            if (!ReceivedBlockTransactions(block, state, pindex, blockPos))
                return error("LoadBlockIndex(): genesis block not accepted");

            // Force genesis into candidate set to ensure ActivateBestChain finds it
            if (setBlockIndexCandidates.count(pindex) == 0) {
                LogPrintf("InitBlockIndex: Manually adding genesis to setBlockIndexCandidates\n");
                setBlockIndexCandidates.insert(pindex);
            }

            // Force a chainstate write so that when we VerifyDB in a moment, it doesn't check stale data
            return FlushStateToDisk(state, FLUSH_STATE_ALWAYS);
        } catch (const std::runtime_error& e) {
            return error("LoadBlockIndex(): failed to initialize block database: %s", e.what());
        }
    }

    return true;
}

bool LoadExternalBlockFile(const CChainParams& chainparams, FILE* fileIn, CDiskBlockPos* dbp)
{
    // Map of disk positions for blocks with unknown parent (only used for reindex)
    static std::multimap<uint256, CDiskBlockPos> mapBlocksUnknownParent;
    int64_t nStart = GetTimeMillis();

    int nLoaded = 0;
    try {
        // This takes over fileIn and calls fclose() on it in the CBufferedFile destructor
        CBufferedFile blkdat(fileIn, 2 * MAX_BLOCK_SERIALIZED_SIZE, MAX_BLOCK_SERIALIZED_SIZE + 8, SER_DISK, CLIENT_VERSION);
        uint64_t nRewind = blkdat.GetPos();
        while (!blkdat.eof()) {
            boost::this_thread::interruption_point();

            blkdat.SetPos(nRewind);
            nRewind++;         // start one byte further next time, in case of failure
            blkdat.SetLimit(); // remove former limit
            unsigned int nSize = 0;
            try {
                // locate a header
                unsigned char buf[CMessageHeader::MESSAGE_START_SIZE];
                blkdat.FindByte(chainparams.MessageStart()[0]);
                nRewind = blkdat.GetPos() + 1;
                blkdat >> FLATDATA(buf);
                if (memcmp(buf, chainparams.MessageStart(), CMessageHeader::MESSAGE_START_SIZE))
                    continue;
                // read size
                blkdat >> nSize;
                if (nSize < 80 || nSize > MAX_BLOCK_SERIALIZED_SIZE)
                    continue;
            } catch (const std::exception&) {
                // no valid block header found; don't complain
                break;
            }
            try {
                // read block
                uint64_t nBlockPos = blkdat.GetPos();
                if (dbp)
                    dbp->nPos = nBlockPos;
                blkdat.SetLimit(nBlockPos + nSize);
                blkdat.SetPos(nBlockPos);
                std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
                CBlock& block = *pblock;
                blkdat >> block;
                nRewind = blkdat.GetPos();

                // detect out of order blocks, and store them for later
                uint256 hash = block.GetHash();
                if (hash != chainparams.GetConsensus(0).hashGenesisBlock && mapBlockIndex.find(block.hashPrevBlock) == mapBlockIndex.end()) {
                    LogPrint("reindex", "%s: Out of order block %s, parent %s not known\n", __func__, hash.ToString(),
                        block.hashPrevBlock.ToString());
                    if (dbp)
                        mapBlocksUnknownParent.insert(std::make_pair(block.hashPrevBlock, *dbp));
                    continue;
                }

                // process in case the block isn't known yet
                if (mapBlockIndex.count(hash) == 0 || (mapBlockIndex[hash]->nStatus & BLOCK_HAVE_DATA) == 0) {
                    LOCK(cs_main);
                    CValidationState state;
                    if (AcceptBlock(pblock, state, chainparams, NULL, true, dbp, NULL))
                        nLoaded++;
                    if (state.IsError())
                        break;
                } else if (hash != chainparams.GetConsensus(0).hashGenesisBlock && mapBlockIndex[hash]->nHeight % 1000 == 0) {
                    LogPrint("reindex", "Block Import: already had block %s at height %d\n", hash.ToString(), mapBlockIndex[hash]->nHeight);
                }

                // Activate the genesis block so normal node progress can continue
                if (hash == chainparams.GetConsensus(0).hashGenesisBlock) {
                    CValidationState state;
                    if (!ActivateBestChain(state, chainparams)) {
                        break;
                    }
                }

                NotifyHeaderTip();

                // Recursively process earlier encountered successors of this block
                std::deque<uint256> queue;
                queue.push_back(hash);
                while (!queue.empty()) {
                    uint256 head = queue.front();
                    queue.pop_front();
                    std::pair<std::multimap<uint256, CDiskBlockPos>::iterator, std::multimap<uint256, CDiskBlockPos>::iterator> range = mapBlocksUnknownParent.equal_range(head);
                    while (range.first != range.second) {
                        std::multimap<uint256, CDiskBlockPos>::iterator it = range.first;
                        std::shared_ptr<CBlock> pblockrecursive = std::make_shared<CBlock>();
                        // TODO: Need a valid consensus height
                        if (ReadBlockFromDisk(*pblockrecursive, it->second, chainparams.GetConsensus(0))) {
                            LogPrint("reindex", "%s: Processing out of order child %s of %s\n", __func__, pblockrecursive->GetHash().ToString(),
                                head.ToString());
                            LOCK(cs_main);
                            CValidationState dummy;
                            if (AcceptBlock(pblockrecursive, dummy, chainparams, NULL, true, &it->second, NULL)) {
                                nLoaded++;
                                queue.push_back(pblockrecursive->GetHash());
                            }
                        }
                        range.first++;
                        mapBlocksUnknownParent.erase(it);
                        NotifyHeaderTip();
                    }
                }
            } catch (const std::exception& e) {
                LogPrintf("%s: Deserialize or I/O error - %s\n", __func__, e.what());
            }
        }
    } catch (const std::runtime_error& e) {
        AbortNode(std::string("System error: ") + e.what());
    }
    if (nLoaded > 0)
        LogPrintf("Loaded %i blocks from external file in %dms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}

void static CheckBlockIndex(const Consensus::Params& consensusParams)
{
    if (!fCheckBlockIndex) {
        return;
    }

    LOCK(cs_main);

    // During a reindex, we read the genesis block and call CheckBlockIndex before ActivateBestChain,
    // so we have the genesis block in mapBlockIndex but no active chain.  (A few of the tests when
    // iterating the block tree require that chainActive has been initialized.)
    if (chainActive.Height() < 0) {
        assert(mapBlockIndex.size() <= 1);
        return;
    }

    // Build forward-pointing map of the entire block tree.
    std::multimap<CBlockIndex*, CBlockIndex*> forward;
    for (BlockMap::iterator it = mapBlockIndex.begin(); it != mapBlockIndex.end(); it++) {
        forward.insert(std::make_pair(it->second->pprev, it->second));
    }

    assert(forward.size() == mapBlockIndex.size());

    std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> rangeGenesis = forward.equal_range(NULL);
    CBlockIndex* pindex = rangeGenesis.first->second;
    rangeGenesis.first++;
    assert(rangeGenesis.first == rangeGenesis.second); // There is only one index entry with parent NULL.

    // Iterate over the entire block tree, using depth-first search.
    // Along the way, remember whether there are blocks on the path from genesis
    // block being explored which are the first to have certain properties.
    size_t nNodes = 0;
    int nHeight = 0;
    CBlockIndex* pindexFirstInvalid = NULL;              // Oldest ancestor of pindex which is invalid.
    CBlockIndex* pindexFirstMissing = NULL;              // Oldest ancestor of pindex which does not have BLOCK_HAVE_DATA.
    CBlockIndex* pindexFirstNeverProcessed = NULL;       // Oldest ancestor of pindex for which nTx == 0.
    CBlockIndex* pindexFirstNotTreeValid = NULL;         // Oldest ancestor of pindex which does not have BLOCK_VALID_TREE (regardless of being valid or not).
    CBlockIndex* pindexFirstNotTransactionsValid = NULL; // Oldest ancestor of pindex which does not have BLOCK_VALID_TRANSACTIONS (regardless of being valid or not).
    CBlockIndex* pindexFirstNotChainValid = NULL;        // Oldest ancestor of pindex which does not have BLOCK_VALID_CHAIN (regardless of being valid or not).
    CBlockIndex* pindexFirstNotScriptsValid = NULL;      // Oldest ancestor of pindex which does not have BLOCK_VALID_SCRIPTS (regardless of being valid or not).
    while (pindex != NULL) {
        nNodes++;
        if (pindexFirstInvalid == NULL && pindex->nStatus & BLOCK_FAILED_VALID) pindexFirstInvalid = pindex;
        if (pindexFirstMissing == NULL && !(pindex->nStatus & BLOCK_HAVE_DATA)) pindexFirstMissing = pindex;
        if (pindexFirstNeverProcessed == NULL && pindex->nTx == 0) pindexFirstNeverProcessed = pindex;
        if (pindex->pprev != NULL && pindexFirstNotTreeValid == NULL && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TREE) pindexFirstNotTreeValid = pindex;
        if (pindex->pprev != NULL && pindexFirstNotTransactionsValid == NULL && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TRANSACTIONS) pindexFirstNotTransactionsValid = pindex;
        if (pindex->pprev != NULL && pindexFirstNotChainValid == NULL && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_CHAIN) pindexFirstNotChainValid = pindex;
        if (pindex->pprev != NULL && pindexFirstNotScriptsValid == NULL && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS) pindexFirstNotScriptsValid = pindex;

        // Begin: actual consistency checks.
        if (pindex->pprev == NULL) {
            // Genesis block checks.
            assert(pindex->GetBlockHash() == consensusParams.hashGenesisBlock); // Genesis block's hash must match.
            assert(pindex == chainActive.Genesis());                            // The current active chain's genesis block must be this block.
        }
        if (pindex->nChainTx == 0) assert(pindex->nSequenceId <= 0); // nSequenceId can't be set positive for blocks that aren't linked (negative is used for preciousblock)
        // VALID_TRANSACTIONS is equivalent to nTx > 0 for all nodes (whether or not pruning has occurred).
        // HAVE_DATA is only equivalent to nTx > 0 (or VALID_TRANSACTIONS) if no pruning has occurred.
        if (!fHavePruned) {
            // If we've never pruned, then HAVE_DATA should be equivalent to nTx > 0
            assert(!(pindex->nStatus & BLOCK_HAVE_DATA) == (pindex->nTx == 0));
            assert(pindexFirstMissing == pindexFirstNeverProcessed);
        } else {
            // If we have pruned, then we can only say that HAVE_DATA implies nTx > 0
            if (pindex->nStatus & BLOCK_HAVE_DATA) assert(pindex->nTx > 0);
        }
        if (pindex->nStatus & BLOCK_HAVE_UNDO) assert(pindex->nStatus & BLOCK_HAVE_DATA);
        assert(((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TRANSACTIONS) == (pindex->nTx > 0)); // This is pruning-independent.
        // All parents having had data (at some point) is equivalent to all parents being VALID_TRANSACTIONS, which is equivalent to nChainTx being set.
        assert((pindexFirstNeverProcessed != NULL) == (pindex->nChainTx == 0)); // nChainTx != 0 is used to signal that all parent blocks have been processed (but may have been pruned).
        assert((pindexFirstNotTransactionsValid != NULL) == (pindex->nChainTx == 0));
        assert(pindex->nHeight == nHeight);                                                                          // nHeight must be consistent.
        assert(pindex->pprev == NULL || pindex->nChainWork >= pindex->pprev->nChainWork);                            // For every block except the genesis block, the chainwork must be larger than the parent's.
        assert(nHeight < 2 || (pindex->pskip && (pindex->pskip->nHeight < nHeight)));                                // The pskip pointer must point back for all but the first 2 blocks.
        assert(pindexFirstNotTreeValid == NULL);                                                                     // All mapBlockIndex entries must at least be TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TREE) assert(pindexFirstNotTreeValid == NULL);       // TREE valid implies all parents are TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_CHAIN) assert(pindexFirstNotChainValid == NULL);     // CHAIN valid implies all parents are CHAIN valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_SCRIPTS) assert(pindexFirstNotScriptsValid == NULL); // SCRIPTS valid implies all parents are SCRIPTS valid
        if (pindexFirstInvalid == NULL) {
            // Checks for not-invalid blocks.
            assert((pindex->nStatus & BLOCK_FAILED_MASK) == 0); // The failed mask cannot be set for blocks without invalid parents.
        }
        if (!CBlockIndexWorkComparator()(pindex, chainActive.Tip()) && pindexFirstNeverProcessed == NULL) {
            if (pindexFirstInvalid == NULL) {
                // If this block sorts at least as good as the current tip and
                // is valid and we have all data for its parents, it must be in
                // setBlockIndexCandidates.  chainActive.Tip() must also be there
                // even if some data has been pruned.
                if (pindexFirstMissing == NULL || pindex == chainActive.Tip()) {
                    assert(setBlockIndexCandidates.count(pindex));
                }
                // If some parent is missing, then it could be that this block was in
                // setBlockIndexCandidates but had to be removed because of the missing data.
                // In this case it must be in mapBlocksUnlinked -- see test below.
            }
        } else { // If this block sorts worse than the current tip or some ancestor's block has never been seen, it cannot be in setBlockIndexCandidates.
            assert(setBlockIndexCandidates.count(pindex) == 0);
        }
        // Check whether this block is in mapBlocksUnlinked.
        std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> rangeUnlinked = mapBlocksUnlinked.equal_range(pindex->pprev);
        bool foundInUnlinked = false;
        while (rangeUnlinked.first != rangeUnlinked.second) {
            assert(rangeUnlinked.first->first == pindex->pprev);
            if (rangeUnlinked.first->second == pindex) {
                foundInUnlinked = true;
                break;
            }
            rangeUnlinked.first++;
        }
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed != NULL && pindexFirstInvalid == NULL) {
            // If this block has block data available, some parent was never received, and has no invalid parents, it must be in mapBlocksUnlinked.
            assert(foundInUnlinked);
        }
        if (!(pindex->nStatus & BLOCK_HAVE_DATA)) assert(!foundInUnlinked); // Can't be in mapBlocksUnlinked if we don't HAVE_DATA
        if (pindexFirstMissing == NULL) assert(!foundInUnlinked);           // We aren't missing data for any parent -- cannot be in mapBlocksUnlinked.
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed == NULL && pindexFirstMissing != NULL) {
            // We HAVE_DATA for this block, have received data for all parents at some point, but we're currently missing data for some parent.
            assert(fHavePruned); // We must have pruned.
            // This block may have entered mapBlocksUnlinked if:
            //  - it has a descendant that at some point had more work than the
            //    tip, and
            //  - we tried switching to that descendant but were missing
            //    data for some intermediate block between chainActive and the
            //    tip.
            // So if this block is itself better than chainActive.Tip() and it wasn't in
            // setBlockIndexCandidates, then it must be in mapBlocksUnlinked.
            if (!CBlockIndexWorkComparator()(pindex, chainActive.Tip()) && setBlockIndexCandidates.count(pindex) == 0) {
                if (pindexFirstInvalid == NULL) {
                    assert(foundInUnlinked);
                }
            }
        }
        // assert(pindex->GetBlockHash() == pindex->GetBlockHeader().GetHash()); // Perhaps too slow
        // End: actual consistency checks.

        // Try descending into the first subnode.
        std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = forward.equal_range(pindex);
        if (range.first != range.second) {
            // A subnode was found.
            pindex = range.first->second;
            nHeight++;
            continue;
        }
        // This is a leaf node.
        // Move upwards until we reach a node of which we have not yet visited the last child.
        while (pindex) {
            // We are going to either move to a parent or a sibling of pindex.
            // If pindex was the first with a certain property, unset the corresponding variable.
            if (pindex == pindexFirstInvalid) pindexFirstInvalid = NULL;
            if (pindex == pindexFirstMissing) pindexFirstMissing = NULL;
            if (pindex == pindexFirstNeverProcessed) pindexFirstNeverProcessed = NULL;
            if (pindex == pindexFirstNotTreeValid) pindexFirstNotTreeValid = NULL;
            if (pindex == pindexFirstNotTransactionsValid) pindexFirstNotTransactionsValid = NULL;
            if (pindex == pindexFirstNotChainValid) pindexFirstNotChainValid = NULL;
            if (pindex == pindexFirstNotScriptsValid) pindexFirstNotScriptsValid = NULL;
            // Find our parent.
            CBlockIndex* pindexPar = pindex->pprev;
            // Find which child we just visited.
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> rangePar = forward.equal_range(pindexPar);
            while (rangePar.first->second != pindex) {
                assert(rangePar.first != rangePar.second); // Our parent must have at least the node we're coming from as child.
                rangePar.first++;
            }
            // Proceed to the next one.
            rangePar.first++;
            if (rangePar.first != rangePar.second) {
                // Move to the sibling.
                pindex = rangePar.first->second;
                break;
            } else {
                // Move up further.
                pindex = pindexPar;
                nHeight--;
                continue;
            }
        }
    }

    // Check that we actually traversed the entire map.
    assert(nNodes == forward.size());
}

std::string CBlockFileInfo::ToString() const
{
    return strprintf("CBlockFileInfo(blocks=%u, size=%u, heights=%u...%u, time=%s...%s)", nBlocks, nSize, nHeightFirst, nHeightLast, DateTimeStrFormat("%Y-%m-%d", nTimeFirst), DateTimeStrFormat("%Y-%m-%d", nTimeLast));
}

CBlockFileInfo* GetBlockFileInfo(size_t n)
{
    LOCK(cs_LastBlockFile);

    return &vinfoBlockFile.at(n);
}

ThresholdState VersionBitsTipState(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    // Handle fresh chain (genesis only) - if ALWAYS_ACTIVE, return ACTIVE
    if (chainActive.Tip() == nullptr || chainActive.Tip()->pprev == nullptr) {
        if (params.vDeployments[pos].nStartTime == Consensus::BIP9Deployment::ALWAYS_ACTIVE) {
            return THRESHOLD_ACTIVE;
        }
        return THRESHOLD_DEFINED;
    }
    return VersionBitsState(chainActive.Tip(), params, pos, versionbitscache);
}

int VersionBitsTipStateSinceHeight(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    // Handle fresh chain (genesis only)
    if (chainActive.Tip() == nullptr || chainActive.Tip()->pprev == nullptr) {
        return 0;
    }
    return VersionBitsStateSinceHeight(chainActive.Tip(), params, pos, versionbitscache);
}

static const uint64_t MEMPOOL_DUMP_VERSION = 1;

bool LoadMempool(void)
{
    int64_t nExpiryTimeout = GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60;
    FILE* filestr = fsbridge::fopen(GetDataDir() / "mempool.dat", "rb");
    CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);
    if (file.IsNull()) {
        LogPrintf("Failed to open mempool file from disk. Continuing anyway.\n");
        return false;
    }

    int64_t count = 0;
    int64_t skipped = 0;
    int64_t failed = 0;
    int64_t nNow = GetTime();

    try {
        uint64_t version;
        file >> version;
        if (version != MEMPOOL_DUMP_VERSION) {
            return false;
        }
        uint64_t num;
        file >> num;
        double prioritydummy = 0;
        while (num--) {
            CTransactionRef tx;
            int64_t nTime;
            int64_t nFeeDelta;
            file >> tx;
            file >> nTime;
            file >> nFeeDelta;

            CAmount amountdelta = nFeeDelta;
            if (amountdelta) {
                mempool.PrioritiseTransaction(tx->GetHash(), tx->GetHash().ToString(), prioritydummy, amountdelta);
            }
            CValidationState state;
            if (nTime + nExpiryTimeout > nNow) {
                LOCK(cs_main);
                AcceptToMemoryPoolWithTime(mempool, state, tx, true, NULL, nTime);
                if (state.IsValid()) {
                    ++count;
                } else {
                    ++failed;
                }
            } else {
                ++skipped;
            }
            if (ShutdownRequested())
                return false;
        }
        std::map<uint256, CAmount> mapDeltas;
        file >> mapDeltas;

        for (const auto& i : mapDeltas) {
            mempool.PrioritiseTransaction(i.first, i.first.ToString(), prioritydummy, i.second);
        }
    } catch (const std::exception& e) {
        LogPrintf("Failed to deserialize mempool data on disk: %s. Continuing anyway.\n", e.what());
        return false;
    }

    LogPrintf("Imported mempool transactions from disk: %i successes, %i failed, %i expired\n", count, failed, skipped);
    return true;
}

void DumpMempool(void)
{
    int64_t start = GetTimeMicros();

    std::map<uint256, CAmount> mapDeltas;
    std::vector<TxMempoolInfo> vinfo;

    {
        LOCK(mempool.cs);
        for (const auto& i : mempool.mapDeltas) {
            mapDeltas[i.first] = i.second.second;
        }
        vinfo = mempool.infoAll();
    }

    int64_t mid = GetTimeMicros();

    try {
        FILE* filestr = fsbridge::fopen(GetDataDir() / "mempool.dat.new", "wb");
        if (!filestr) {
            return;
        }

        CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);

        uint64_t version = MEMPOOL_DUMP_VERSION;
        file << version;

        file << (uint64_t)vinfo.size();
        for (const auto& i : vinfo) {
            file << *(i.tx);
            file << (int64_t)i.nTime;
            file << (int64_t)i.nFeeDelta;
            mapDeltas.erase(i.tx->GetHash());
        }

        file << mapDeltas;
        FileCommit(file.Get());
        file.fclose();
        RenameOver(GetDataDir() / "mempool.dat.new", GetDataDir() / "mempool.dat");
        int64_t last = GetTimeMicros();
        LogPrintf("Dumped mempool: %gs to copy, %gs to dump\n", (mid - start) * 0.000001, (last - mid) * 0.000001);
    } catch (const std::exception& e) {
        LogPrintf("Failed to dump mempool: %s. Continuing anyway.\n", e.what());
    }
}

//! Guess how far we are in the verification process at the given block index
double GuessVerificationProgress(const ChainTxData& data, CBlockIndex* pindex)
{
    if (pindex == NULL)
        return 0.0;

    int64_t nNow = time(NULL);

    double fTxTotal;

    if (pindex->nChainTx <= data.nTxCount) {
        fTxTotal = data.nTxCount + (nNow - data.nTime) * data.dTxRate;
    } else {
        fTxTotal = pindex->nChainTx + (nNow - pindex->GetBlockTime()) * data.dTxRate;
    }

    return pindex->nChainTx / fTxTotal;
}

class CMainCleanup
{
public:
    CMainCleanup() {}
    ~CMainCleanup()
    {
        // block headers
        BlockMap::iterator it1 = mapBlockIndex.begin();
        for (; it1 != mapBlockIndex.end(); it1++)
            delete (*it1).second;
        mapBlockIndex.clear();
    }
} instance_of_cmaincleanup;
