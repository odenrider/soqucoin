// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2021-2022 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_POLICY_H
#define BITCOIN_POLICY_POLICY_H

#include "consensus/consensus.h"
#include "script/interpreter.h"
#include "script/standard.h"

#include <string>

class CCoinsViewCache;

/** Recommended transaction fee by Soqucoin Core developers
  *
  * All fee defaults used throughout the client derive their
  * value from this base default.
  */
static const CAmount RECOMMENDED_MIN_TX_FEE = COIN / 100;

/** Default for -blockmaxsize, which controls the maximum size of block the mining code will create **/
static const unsigned int DEFAULT_BLOCK_MAX_SIZE = 750000;
/** Default for -blockprioritysize, maximum space for zero/low-fee transactions **/
static const unsigned int DEFAULT_BLOCK_PRIORITY_SIZE = 27000;
/** Default for -blockmaxweight, which controls the range of block weights the mining code will create **/
static const unsigned int DEFAULT_BLOCK_MAX_WEIGHT = 3000000;
/** Default for -blockmintxfee, which sets the minimum feerate for a transaction in blocks created by mining code **/
static const unsigned int DEFAULT_BLOCK_MIN_TX_FEE = (unsigned int) RECOMMENDED_MIN_TX_FEE;
/** The maximum weight for transactions we're willing to relay/mine
 *  SOQ-ARCH-003: Bumped from 400K to 800K for Dilithium consolidation TXs.
 *  Each Dilithium input is ~3,896 WU — at 400K, only ~100 inputs fit.
 *  800K allows 205 inputs while capping any single TX at 20% of block space.
 *  Ratified 2026-05-25. See DL-SOQ-FEE-ARCHITECTURE-V3.md.
 */
static const unsigned int MAX_STANDARD_TX_WEIGHT = 800000;
/** Maximum number of signature check operations in an IsStandard() P2SH script */
static const unsigned int MAX_P2SH_SIGOPS = 15;
/** The maximum number of sigops we're willing to relay/mine in a single tx */
static const unsigned int MAX_STANDARD_TX_SIGOPS_COST = MAX_BLOCK_SIGOPS_COST/5;
/** Default for -maxmempool, maximum megabytes of mempool memory usage */
static const unsigned int DEFAULT_MAX_MEMPOOL_SIZE = 300;
/** Default for -incrementalrelayfee, which sets the minimum feerate increase
 *  for mempool limiting or BIP 125 replacement
 *
 *  Soqucoin:    Increment mempool limits and accept RBF in steps of 0.0001 DOGE
 *  Calculation: DEFAULT_MIN_RELAY_TX_FEE = RECOMMENDED_MIN_TX_FEE / 10
 *               DEFAULT_INCREMENTAL_RELAY_FEE = DEFAULT_MIN_RELAY_TX_FEE / 10
 *
 *  Rationale:   This implements a smaller granularity than the wallet
 *               implementation for fee increments by default, leaving room for
 *               alternative increment strategies, yet limiting the amount of
 *               ineffective RBF spam we expose the network to. This also makes
 *               an RBF fee bump 10x cheaper than a CPFP transaction, because
 *               RBF leaves no on-chain waste, whereas CPFP adds another
 *               transaction to the chain.
 */
static const CAmount DEFAULT_INCREMENTAL_RELAY_FEE = RECOMMENDED_MIN_TX_FEE / 100;
/** Default for -bytespersigop */
static const unsigned int DEFAULT_BYTES_PER_SIGOP = 20;
/** The maximum number of witness stack items in a standard P2WSH script */
static const unsigned int MAX_STANDARD_P2WSH_STACK_ITEMS = 100;
/** The maximum size of each witness stack item in a standard P2WSH script */
static const unsigned int MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80;
/** The maximum size of a standard witnessScript */
static const unsigned int MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600;
/**
 * Soqucoin: Default dust limit that is evaluated when considering whether a
 * transaction output is required to pay additional fee for relay and inclusion
 * in blocks. Overridden by -dustlimit
 */
static const CAmount DEFAULT_DUST_LIMIT = RECOMMENDED_MIN_TX_FEE;
/**
 * Soqucoin: Default hard dust limit that is evaluated when considering whether
 * a transaction is standard. Transactions under this limit will not be accepted
 * to the mempool and thus not relayed. Can be overridden by -harddustlimit
 *
 * Changing the hard dust limit changes which transactions are standard and
 * should be done with care and ideally rarely. It makes sense to only increase
 * this limit after prior releases were already not creating outputs below the
 * new threshold
 */
static const CAmount DEFAULT_HARD_DUST_LIMIT = DEFAULT_DUST_LIMIT / 10;

/**
 * Standard script verification flags that standard transactions will comply
 * with. However scripts violating these flags may still be present in valid
 * blocks and we must accept those blocks.
 *
 * SOQ-COV-012 [DOC]: Covenant opcode flags are intentionally OMITTED here.
 * =========================================================================
 * SCRIPT_VERIFY_CTV (BIP 119: OP_CHECKTEMPLATEVERIFY, bit 7)
 * SCRIPT_VERIFY_APO (BIP 118: SIGHASH_ANYPREVOUT, bit 8)
 * SCRIPT_VERIFY_CSFS (BIP 348: OP_CHECKSIGFROMSTACK, bit 9)
 *
 * ⛔ SCRIPT_VERIFY_SCRIPT_RESTORE WAS ON THIS LIST AND HAD TO COME OFF IT.
 * The three flags above ADD ENFORCEMENT: setting one makes the mempool reject
 * scripts it used to accept, and consensus keeps all three NOT_SCHEDULED on
 * mainnet, so omitting them here leaves policy and consensus agreeing at
 * off/off until activation brings them together. That is the reasoning below
 * and it is sound for them.
 *
 * SCRIPT_RESTORE is not that kind of flag. It ADDS CAPABILITY: with it OP_MUL
 * and friends execute, and WITHOUT it they are silent NO-OPS rather than
 * errors. Consensus sets it unconditionally from genesis (validation.cpp,
 * "Satoshi script restoration: always-active"), so there is no dormant state to
 * agree at. Omitting it produced a permanent split in which the same script has
 * two truth values:
 *
 *     0 7 OP_MUL      consensus -> ok[]      (0, FALSE)
 *                     mempool   -> ok[,07]   (operands left, top is TRUE)
 *
 * A transaction spending such an output was accepted and relayed by every node
 * and could never be mined: accept-then-reject, which is the template-stalling
 * failure live bug daf9fd85 produced. Grouping a capability flag with three
 * enforcement flags is what caused it. Bead mxph.
 *
 * These are NOT included in STANDARD_SCRIPT_VERIFY_FLAGS because:
 *
 * 1. Pre-mainnet policy gate: Covenant scripts are not yet standard mempool
 *    transactions. Adding these flags here would cause the mempool to enforce
 *    covenant rules on relay, which is premature before Phase 2 Halborn audit.
 *
 * 2. BIP9 activation: CTV/APO/CSFS activate via BIP9 soft fork:
 *    - Regtest/Stagenet: ALWAYS_ACTIVE from genesis (safe for testing)
 *    - Mainnet: nStartTime = 0 (NOT YET SCHEDULED; requires Halborn Phase 2
 *      audit sign-off on COV-001 through COV-012 remediations)
 *
 * 3. Consensus vs policy separation: The covenant flags ARE checked at the
 *    consensus layer (VerifyScript, ConnectBlock) via the flags passed from
 *    GetBlockScriptFlags(). Policy layer enforcement comes later, post-audit.
 *
 * When to add these flags:
 *    After Phase 2 Halborn audit clears CTV/APO/CSFS for mainnet activation,
 *    update chainparams.cpp nStartTime and add the flags here.
 *
 * Related flags that ARE included but inherited from Bitcoin Core:
 *    SCRIPT_VERIFY_DERSIG, SCRIPT_VERIFY_STRICTENC — these remain for
 *    historical policy compatibility. They do NOT gate Dilithium paths.
 *    See interpreter.cpp CheckSignatureEncoding() for the Dilithium encoding
 *    validator (SOQ-COV-011).
 */
static const unsigned int STANDARD_SCRIPT_VERIFY_FLAGS = MANDATORY_SCRIPT_VERIFY_FLAGS |
                                                         // Consensus sets this for every block
                                                         // unconditionally; relay must match or the
                                                         // restored opcodes mean two different
                                                         // things on the two paths (bead mxph).
                                                         SCRIPT_VERIFY_SCRIPT_RESTORE |
                                                         SCRIPT_VERIFY_DERSIG |
                                                         SCRIPT_VERIFY_STRICTENC |
                                                         SCRIPT_VERIFY_MINIMALDATA |
                                                         SCRIPT_VERIFY_NULLDUMMY |
                                                         SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
                                                         SCRIPT_VERIFY_CLEANSTACK |
                                                         SCRIPT_VERIFY_MINIMALIF |
                                                         SCRIPT_VERIFY_NULLFAIL |
                                                         SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
                                                         SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
                                                         SCRIPT_VERIFY_LOW_S |
                                                         SCRIPT_VERIFY_WITNESS |
                                                         SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM |
                                                         SCRIPT_VERIFY_WITNESS_PUBKEYTYPE;

/** For convenience, standard but not mandatory verify flags. */
static const unsigned int STANDARD_NOT_MANDATORY_VERIFY_FLAGS = STANDARD_SCRIPT_VERIFY_FLAGS & ~MANDATORY_SCRIPT_VERIFY_FLAGS;

/** Used as the flags parameter to sequence and nLocktime checks in non-consensus code. */
static const unsigned int STANDARD_LOCKTIME_VERIFY_FLAGS = LOCKTIME_VERIFY_SEQUENCE |
                                                           LOCKTIME_MEDIAN_TIME_PAST;

/**
 * Bitmask of witness versions whose CONSENSUS rules are active, bit N = version N.
 *
 * Policy must never admit an output whose consensus rule is dormant. A gated
 * witness version is anyone-can-spend until its deployment activates, so relaying
 * such an output is a fund-loss path rather than a safe failure: it confirms, and
 * then anybody may spend it.
 *
 * The default of 0 means "nothing gated is active", which is the fail-safe
 * direction — an unknown activation state rejects rather than relays. Callers that
 * know the chain state (the mempool acceptance path) pass the real mask.
 */
typedef uint32_t WitnessVersionMask;
static inline WitnessVersionMask WitnessVersionBit(int version) { return (uint32_t)1 << version; }

bool IsStandard(const CScript& scriptPubKey, txnouttype& whichType, const bool witnessEnabled = false,
                WitnessVersionMask activeWitnessVersions = 0);
    /**
     * Check for standard transaction types
     * @return True if all outputs (scriptPubKeys) use only standard transaction forms
     */
bool IsStandardTx(const CTransaction& tx, std::string& reason, const bool witnessEnabled = false,
                  WitnessVersionMask activeWitnessVersions = 0);
    /**
     * Check for standard transaction types
     * @param[in] mapInputs    Map of previous transactions that have outputs we're spending
     * @return True if all inputs (scriptSigs) use only standard transaction forms
     */
bool AreInputsStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs);
    /**
     * Check if the transaction is over standard P2WSH resources limit:
     * 3600bytes witnessScript size, 80bytes per witness stack element, 100 witness stack elements
     * These limits are adequate for multi-signature up to n-of-100 using OP_CHECKSIG, OP_ADD, and OP_EQUAL,
     */
bool IsWitnessStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs);

extern CFeeRate incrementalRelayFee;
extern CFeeRate dustRelayFee;
extern unsigned int nBytesPerSigOp;
extern CAmount nDustLimit;
extern CAmount nHardDustLimit;

/** Compute the virtual transaction size (weight reinterpreted as bytes). */
int64_t GetVirtualTransactionSize(int64_t nWeight, int64_t nSigOpCost);
int64_t GetVirtualTransactionSize(const CTransaction& tx, int64_t nSigOpCost = 0);

#endif // BITCOIN_POLICY_POLICY_H
