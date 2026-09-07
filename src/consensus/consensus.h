// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include <stdint.h>

/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 4000000;
/** The maximum allowed weight for a block, see BIP 141 (network rule) */
static const unsigned int MAX_BLOCK_WEIGHT = 4000000;
/** The maximum allowed size for a block excluding witness data, in bytes (network rule) */
static const unsigned int MAX_BLOCK_BASE_SIZE = 1000000;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const int64_t MAX_BLOCK_SIGOPS_COST = 80000;

/**
 * Proof Verification Costs (Soqucoin v1.0)
 *
 * These constants define the computational cost of verifying different proof types.
 * Similar to Bitcoin's sigops, they limit expensive operations per block.
 *
 * APPROVED: 2025-12-22 (Phase 1 Decision)
 */

/** Dilithium signature verification cost (baseline) */
static const int64_t DILITHIUM_VERIFY_COST = 1;

/** Bulletproofs++ range proof verification cost (~10ms) */
static const int64_t BPPP_VERIFY_COST = 50;

/** PAT (Practical Aggregation Technique) signature aggregation (~4ms) */
static const int64_t PAT_VERIFY_COST = 20;

/** LatticeFold+ recursive SNARK verification cost (~40ms) */
static const int64_t LATTICEFOLD_VERIFY_COST = 200;

/** Maximum verification units per block (mirrors MAX_BLOCK_SIGOPS_COST) */
static const int64_t MAX_BLOCK_VERIFY_COST = 80000;

/** Maximum LatticeFold+ proofs per block (v1 rate limit) */
static const int64_t MAX_LATTICEFOLD_PER_BLOCK = 10;

/** Maximum proof bytes per transaction */
static const unsigned int MAX_PROOF_BYTES_PER_TX = 65536; // 64 KB

/** Maximum proof bytes per block */
static const unsigned int MAX_PROOF_BYTES_PER_BLOCK = 262144; // 256 KB

/** SOQ-ARCH-003: Minimum UTXO value per serialized output byte.
 *  BIP9-gated via DEPLOYMENT_UTXO_COST (bit 11).
 *  Prevents UTXO set bloat from dust storm attacks (Cardano's utxoCostPerByte).
 *
 *  Formula: minOutputValue = UTXO_COST_PER_BYTE × serialized_output_size
 *
 *  Derivation: At fee_rate 1,000 sat/vB, a Dilithium input costs ~974,000 sat
 *  to spend. For a 50-byte output, requiring value >= spendCost/3:
 *    minValue = 974,000 / 3 ≈ 325,000 sat
 *    utxoCostPerByte = 325,000 / 50 = 6,500 sat/byte
 *
 *  Result: Standard 50-byte output → min 0.00325 SOQ (below policy 0.01 SOQ).
 *  Ratified 2026-05-25. See DL-SOQ-FEE-ARCHITECTURE-V3.md.
 */
static const int64_t UTXO_COST_PER_BYTE = 6500;

/** Flags for nSequence and nLockTime locks */
enum {
    /* Interpret sequence numbers as relative lock-time constraints. */
    LOCKTIME_VERIFY_SEQUENCE = (1 << 0),

    /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
    LOCKTIME_MEDIAN_TIME_PAST = (1 << 1),
};

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
