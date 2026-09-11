# Soqucoin Frequently Asked Questions

## How much SOQ can exist?

Soqucoin uses a **perpetual emission model** (similar to Dogecoin) to ensure long-term miner incentives for network security:

- **Initial block reward**: 100,000 SOQ
- **Halvings**: Every 250,000 blocks (~174 days)
- **Terminal emission**: 2,500 SOQ perpetual after block 1,000,000

This inflationary model ensures miners always have incentive to secure the post-quantum network.

## What is the emission schedule?

| Block Range | Block Reward | Timeline (~1 min blocks) |
|-------------|-------------|--------------------------|
| 1 – 250,000 | 100,000 SOQ | First ~174 days |
| 250,001 – 500,000 | 50,000 SOQ | ~174 days |
| 500,001 – 750,000 | 25,000 SOQ | ~174 days |
| 750,001 – 1,000,000 | 12,500 SOQ | ~174 days |
| **1,000,001+** | **2,500 SOQ (perpetual)** | **Forever** |

**Key characteristics:**
- **No hard cap** – perpetual emission after block 1,000,000
- **250,000 block halving interval** (~174 days at 1-min blocks)
- **~1.9 years** to reach terminal emission
- **Terminal emission**: 2,500 SOQ/block = ~1.31B SOQ/year

## Where is the emission schedule defined?

The emission schedule is defined in:

1. **Code** (authoritative source):
   - `src/soqucoin.cpp` – `GetSoqucoinBlockSubsidy()` function
   - `src/chainparams.cpp` – consensus parameters
   
2. **Documentation**:
   - This FAQ and the [Protocol page](https://soqu.org/protocol.html)

## What makes Soqucoin different?

Soqucoin is **post-quantum resistant from day one**. It uses:

- **Dilithium (ML-DSA-44)**: NIST FIPS 204 standardized signatures replacing ECDSA
- **Bulletproofs++**: Optional confidential transaction amounts
- **PAT**: Practical Aggregation Technique for efficient batch verification
- **LatticeFold+**: deprecated batch verification (`OP_CHECKFOLDPROOF`, witness v3); the deployment does not activate on any network. Its successor for confidential assets and succinct proofs is SoquObscura, in research and not scheduled on any network

## Mining Information ⛏

Soqucoin uses the **Scrypt** proof-of-work algorithm with:

- **Block time**: 1 minute (60 seconds)
- **Difficulty adjustment**: DigiShield (per-block retargeting)
- **Merged mining**: Compatible with Litecoin/Dogecoin (AuxPoW)
- **Chain ID**: 0x5351 ("SQ")

### Block Reward Schedule

| Block Range | Reward (SOQ) |
|-------------|-------------:|
| 1 – 250,000 | 100,000 |
| 250,001 – 500,000 | 50,000 |
| 500,001 – 750,000 | 25,000 |
| 750,001 – 1,000,000 | 12,500 |
| 1,000,001+ | 2,500 (perpetual) |

## Is there a mining pool?

**Current status (pre-mainnet):**

- **Engineering Testnet**: Stratum bridge available for testing with any Scrypt miner
- **Testnet**: Running Braiins pool software internally
- **Public pools**: No third-party pools yet (launching with mainnet)

**How to mine on Engineering Testnet:**

Visit https://soqu.org/testnet.html for current connection details and miner setup instructions.

**Mainnet plans:**
- Open-source pool software available at launch
- Community can run independent pools
- AuxPoW (merged mining with LTC/DOGE) supported from genesis

## Address Formats

Soqucoin uses **Bech32m** addresses with network-specific prefixes:

| Network | Prefix | Example |
|---------|--------|---------|
| Mainnet | `sq1` | `sq1qxyz...` |
| Testnet | `tsq1` | `tsq1qxyz...` |
| Stagenet | `ssq1` | `ssq1qxyz...` |

## Is Soqucoin quantum-safe?

Yes. Soqucoin replaces ECDSA (vulnerable to Shor's algorithm) with **Dilithium ML-DSA-44**, a NIST-standardized post-quantum signature scheme. All transaction signing uses Dilithium exclusively.

## More Information

- **Website**: https://soqu.org
- **Whitepaper**: https://soqu.org/whitepaper.html
- **GitHub**: https://github.com/soqucoin/soqucoin
- **Support**: dev@soqu.org

