# Soqucoin Mining Guide

> **Version**: 2.0 | **Updated**: 2026-01-02
> **Network**: Testnet3 (Mainnet Q2 2026)
> **Consensus**: Scrypt PoW + AuxPoW Merged Mining

---

## Overview

Soqucoin is a post-quantum resistant blockchain using Scrypt Proof-of-Work consensus. It supports two mining modes:

1. **Standalone Scrypt Mining**: Traditional ASIC mining with dedicated hardware
2. **AuxPoW Merged Mining**: Mine SOQ alongside Litecoin/Dogecoin at no extra cost

---

## 1. Hardware Requirements

### Supported Mining Hardware

Soqucoin uses **Scrypt Proof-of-Work** and is compatible with **all Scrypt mining hardware**. Any ASIC, FPGA, or device capable of mining Litecoin, Dogecoin, or other Scrypt coins can mine Soqucoin.

**Example Hardware** (not exhaustive):

| Device | Hashrate | Power | Notes |
|--------|----------|-------|-------|
| Antminer L7 9500M | 9.5 GH/s | 3425W | Enterprise |
| Antminer L7 8550M | 8.55 GH/s | 3080W | Enterprise |
| Antminer L3+ | 504 MH/s | 800W | Entry Level |
| Goldshell Mini-Doge | 185 MH/s | 233W | Home Mining |
| Elphapex DG Home 1 | 40 MH/s | 40W | Silent Home |
| *Any Scrypt ASIC* | *Varies* | *Varies* | ✅ Compatible |

> **Note**: CPU and GPU mining is technically possible but economically nonviable due to network hashrate from ASICs.

### Network Requirements

- Stable internet connection (100+ Mbps recommended)
- Static IP or dynamic DNS for pool connections
- Low latency to pool server (<100ms)

---

## 2. Standalone Scrypt Mining

### Step 1: Obtain a Soqucoin Address

All mining rewards are paid to **Dilithium addresses only**. Traditional ECDSA addresses are not supported.

```bash
# Generate a new Dilithium address
soqucoin-cli getnewaddress "mining_rewards"
# Example output: sq1q...
```

### Step 2: Configure Your ASIC

Configure your miner with the following settings:

| Setting | Value |
|---------|-------|
| **Pool URL** | *Pool URL will be announced at mainnet launch* |
| **Worker Name** | `sq1q..your_dilithium_address...` |
| **Password** | `x` (any string) |

> **Note**: The testnet pool is currently **private** during the security audit period. Public pool access will be announced after mainnet launch.

### Step 3: Verify Mining Status

Once connected to a pool, check your node's mining status:
```bash
soqucoin-cli getmininginfo
```

---

## 3. AuxPoW Merged Mining

### What is Merged Mining?

Merged mining allows you to mine Soqucoin simultaneously with another Scrypt chain (Litecoin, Dogecoin) without additional energy consumption. The parent chain's proof-of-work is used to validate Soqucoin blocks.

### Chain ID (Critical)

Soqucoin uses a unique Chain ID to prevent cross-chain replay attacks:

| Parameter | Value |
|-----------|-------|
| **Chain ID** | `0x5351` (decimal: 21329, "SQ") |
| **Version Bits** | Encoded in block header version |

> ⚠️ **Important**: Pool operators MUST verify they are mining with Chain ID `0x5351` to avoid invalid blocks. Dogecoin's Chain ID is `0x0062` - blocks mined with the wrong ID will be rejected.

### Pool Operator Setup

For pool operators running `merged-mining-pool` or similar software:

```go
// soqucoin.go configuration
var SoqucoinNetwork = &AuxChain{
    Name:           "soqucoin",
    Symbol:         "SQ",
    ChainID:        0x5351,     // Critical: Unique Soqucoin ID
    RPC: RPCConfig{
        Host:       "127.0.0.1",
        Port:       44555,
        User:       "soqurpc",
        Password:   "your_secure_password",
    },
    BlockReward:    100000,     // Initial block reward
    ConfirmBlocks:  240,        // Coinbase maturity — TESTNET (this block is
                                // testnet: Port 44555). Mainnet is 288.
}
```

### RPC Commands for Merged Mining

```bash
# Get work for merged mining
soqucoin-cli createauxblock "sq1qmyaddress"

# Submit solved AuxPoW block  
soqucoin-cli submitauxblock "blockhash" "auxpow_data"

# Alternative getauxblock interface
soqucoin-cli getauxblock
soqucoin-cli getauxblock "blockhash" "auxpow_data"
```

---

## 4. Block Rewards and Tokenomics

### Emission Schedule

| Block Range | Reward (SOQ) | Notes |
|-------------|--------------|-------|
| 1 - 250,000 | 100,000 | Initial phase |
| 250,001 - 500,000 | 50,000 | First halving |
| 500,001 - 750,000 | 25,000 | Second halving |
| 750,001 - 1,000,000 | 12,500 | Third halving |
| 1,000,001+ | 2,500 | Terminal perpetual |

### Block Time

- **Target**: 60 seconds
- **Difficulty Adjustment**: DigiShield (every block)
- **Coinbase Maturity**: network-dependent, and the two differ on purpose.
  - **Mainnet**: 288 blocks (~4.8 h), equal to the finality horizon `nMaxReorgDepth`, so a coinbase cannot mature inside the window the chain still accepts reorgs in.
  - **Testnet** (the network this guide is scoped to, see the header): 240 blocks. Testnet is a deliberate exception and is *not* equal to its 288 horizon; it has no height-gated maturity tier, so raising it in place would retroactively invalidate past spends.

---

## 5. Node Configuration for Miners

### Recommended `soqucoin.conf`

```ini
# Network
server=1
listen=1
testnet=1                    # Remove for mainnet

# RPC (restrict to localhost)
rpcuser=soqurpc
rpcpassword=secure_random_password_here
rpcallowip=127.0.0.1
rpcbind=127.0.0.1
rpcport=44555

# Mining support
rpcworkqueue=128             # Increase for high-frequency mining
rpcthreads=8                 # Match expected concurrent workers

# AuxPoW
fAllowLegacyBlocks=true      # Support both native and merged-mined blocks
```

### Performance Tuning

For high-frequency block submission (L7 miners at minimum difficulty):

```bash
soqucoind -rpcworkqueue=128 -rpcthreads=8 -dbcache=2048
```

---

## 6. Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "Address invalid" | ECDSA address used | Generate Dilithium address with `getnewaddress` |
| "Chain ID mismatch" | Wrong parent chain config | Verify Chain ID is 0x5351 |
| "Block rejected" | Stale share | Check network latency, update getblocktemplate frequency |
| "Connection refused" | RPC not running | Start soqucoind, check rpcbind settings |

### Diagnostic Commands

```bash
# Check node status
soqucoin-cli getblockchaininfo

# Check mining status
soqucoin-cli getmininginfo

# Verify peer connections
soqucoin-cli getpeerinfo | jq '.[].addr'

# Check mempool
soqucoin-cli getmempoolinfo
```

---

## 7. Security Best Practices

1. **Never expose RPC port 44555 to the public internet**
2. **Use strong, random RPC passwords**
3. **Enable firewall (UFW on Ubuntu)**:
   ```bash
   sudo ufw allow 44556/tcp   # P2P port (public OK)
   sudo ufw deny 44555/tcp    # RPC port (private only)
   ```
4. **Use SSH tunneling for remote mining**
5. **Regularly update to latest Soqucoin release**

---

## 8. Official Resources

- **Website**: https://soqu.org
- **Whitepaper**: https://soqu.org/whitepaper.html
- **Testnet Pool**: *Private during audit period*
- **Mainnet Pool**: *To be announced at launch*
- **GitHub**: https://github.com/soqucoin/soqucoin

---

*Last Updated: 2026-01-02*
*Prepared for Soqucoin Testnet3 / Mainnet Launch*
