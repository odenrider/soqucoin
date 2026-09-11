# Soqucoin Exchange Integration Guide

> **Version**: 1.0 | **Updated**: January 6, 2026
> **Audience**: Exchange operators, custodians, and trading platform developers
> **Support**: dev@soqu.org

---

## Overview

This guide provides comprehensive instructions for integrating Soqucoin (SOQ) into cryptocurrency exchanges. 

Soqucoin is **based on Dogecoin Core**. It uses Dogecoin's well-tested foundation while replacing the cryptographic engine with post-quantum primitives and adding high-performance feature engineering upgrades. Soqucoin begins with its own Genesis Block (Block 0) with **no shared transaction history** and **no airdrop to Dogecoin holders**. It is an entirely new and independent blockchain featuring Dilithium (ML-DSA-44) signatures and AuxPoW merged mining compatibility with Litecoin/Dogecoin.

### Key Properties

| Property | Value |
|----------|-------|
| **Consensus** | Proof-of-Work (Scrypt) |
| **Block Time** | 60 seconds |
| **Signature** | Dilithium ML-DSA-44 (NIST FIPS 204) |
| **Address Format** | Bech32m (`sq1...` mainnet, `tsq1...` testnet) |
| **Merged Mining** | Yes (Litecoin/Dogecoin compatible) |
| **Chain ID** | 0x5351 (21329) |
| **Ticker** | SOQ |
| **Decimals** | 8 |

---

## 1. Prerequisites

### 1.1 Hardware Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **CPU** | 4 cores | 8+ cores |
| **RAM** | 8 GB | 16+ GB |
| **Storage** | 100 GB SSD | 500 GB NVMe |
| **Network** | 50 Mbps | 100+ Mbps |

### 1.2 Operating System

- Ubuntu 22.04 LTS (recommended)
- Ubuntu 24.04 LTS (verified)
- Debian 11/12
- RHEL 8/9

> **Note**: macOS and Windows are supported for development but not recommended for production exchange deployments.

### 1.3 Build Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y \
  build-essential libtool autotools-dev automake \
  pkg-config bsdmainutils python3 libssl-dev \
  libevent-dev libboost-all-dev libzmq3-dev \
  libdb5.3-dev libdb5.3++-dev
```

---

## 2. Node Setup

### 2.1 Building from Source

```bash
# Clone repository
git clone https://github.com/soqucoin/soqucoin.git
cd soqucoin
git checkout soqucoin-genesis  # Mainnet branch

# Build
./autogen.sh
./configure --without-gui --with-incompatible-bdb
make -j$(nproc)
sudo make install
```

### 2.2 Configuration File

Create `~/.soqucoin/soqucoin.conf`:

```ini
# Basic Configuration
server=1
daemon=1
txindex=1

# RPC Configuration (IMPORTANT)
rpcuser=your_secure_rpc_username
rpcpassword=your_very_long_secure_password_at_least_32_chars
# Mainnet RPC port: 33389 | Testnet RPC port: 44555 | Stagenet RPC port: 28332
rpcport=33389
rpcbind=127.0.0.1
rpcallowip=127.0.0.1

# Network Configuration
listen=1
maxconnections=50

# Performance Tuning
dbcache=1000
par=4
rpcworkqueue=128
rpcthreads=8

# Security
disablewallet=0
walletnotify=/path/to/your/notify_script.sh %s
blocknotify=/path/to/your/block_script.sh %s
```

**Network Port Reference**:

| Network | P2P Port | RPC Port |
|---------|----------|----------|
| **Mainnet** | 33388 | 33389 |
| **Testnet3** | 44556 | 44555 |
| **Stagenet** | 28333 | 28332 |
| **Regtest** | 18444 | 18332 |

> **Security Warning**: Never expose RPC to the public internet. Use SSH tunnels or VPN for remote access.

### 2.3 Starting the Node

```bash
# Start daemon
soqucoind -daemon

# Check status
soqucoin-cli getblockchaininfo

# Monitor sync progress
soqucoin-cli getblockchaininfo | grep -E "(blocks|headers|verificationprogress)"
```

### 2.4 Sync Time Estimates

| Network | Blocks | Estimated Sync Time |
|---------|--------|---------------------|
| Mainnet | TBD (pre-launch) | TBD |
| Testnet3 | ~12,000 | < 1 hour |
| Stagenet | ~0 | Immediate |

---

## 3. Deposit Handling

### 3.1 Address Generation

Generate unique deposit addresses for each customer:

```bash
# Standard address generation (legacy)
soqucoin-cli getnewaddress "" "bech32"

# PQ wallet address generation
soqucoin-cli pqgetnewaddress
```

**Response**:
```json
{
  "address": "sq1qqmf3532trg036kjvamk9d2n4m9uafy...",
  "pubkey_hash": "b47468acb...",
  "network": "mainnet",
  "type": "P2PQ"
}
```

### 3.2 Address Validation

Always validate addresses before accepting deposits:

```bash
soqucoin-cli pqvalidateaddress "sq1qqmf3532trg036kjvamk9d2n4m9uafy..."
```

**Response**:
```json
{
  "isvalid": true,
  "network": "mainnet",
  "type": "P2PQ",
  "witness_version": 1
}
```

### 3.3 Monitoring Deposits

#### Option A: walletnotify (Recommended)

Configure `walletnotify` in `soqucoin.conf`:

```ini
walletnotify=/path/to/deposit_notify.sh %s
```

Example script (`deposit_notify.sh`):
```bash
#!/bin/bash
TXID="$1"
# Process deposit via your internal API
curl -X POST "https://your-internal-api/deposits" \
  -H "Content-Type: application/json" \
  -d "{\"txid\": \"$TXID\"}"
```

#### Option B: listtransactions Polling

```bash
soqucoin-cli listtransactions "*" 100 0 true | jq '.[] | select(.category == "receive")'
```

### 3.4 Confirmation Requirements

| Transaction Size | Recommended Confirmations |
|------------------|---------------------------|
| < 1,000 SOQ | 6 confirmations (~6 min) |
| 1,000 - 10,000 SOQ | 12 confirmations (~12 min) |
| 10,000 - 100,000 SOQ | 24 confirmations (~24 min) |
| Large value / final settlement | **288 confirmations (~4.8h — absolute finality)** |

> **Note**: Below 288 blocks, confirmations are **probabilistic** — more confirmations lower the reversal risk, but a large hashpower rental can still reorganize recent blocks. At **288 blocks (~4.8h)** finality becomes **absolute**: the network rejects any reorg deeper than 288 blocks (`nMaxReorgDepth`), so a buried transaction cannot be reversed by hashpower. **Do not credit large deposits on a handful of confirmations** — wait for the 288-block finality horizon for high-value settlement. See [Chain Finality](https://soqu.org/docs/protocol/finality/) for the full properties and tradeoffs.

---

## 4. Withdrawal Handling

### 4.1 Fee Estimation

```bash
# Estimate fee for standard transaction
soqucoin-cli estimatesmartfee 6

# Estimate verification cost (PQ-specific)
soqucoin-cli pqestimatefeerate 1 2
```

**Response**:
```json
{
  "verify_cost": 9,
  "breakdown": {
    "signature_cost": 1,
    "script_cost": 6,
    "hash_cost": 2
  },
  "recommendation": "Standard transaction, no aggregation needed"
}
```

### 4.2 Sending Transactions

```bash
# Simple send
soqucoin-cli sendtoaddress "sq1qrecipient..." 100.0

# With explicit fee rate
soqucoin-cli sendtoaddress "sq1qrecipient..." 100.0 "" "" false true null 6

# Raw transaction (advanced)
soqucoin-cli createrawtransaction '[{"txid":"...","vout":0}]' '{"sq1qrecipient...":100.0}'
```

### 4.3 Transaction Confirmation

```bash
# Check transaction status
soqucoin-cli gettransaction "txid..."

# Get raw transaction details
soqucoin-cli getrawtransaction "txid..." 1
```

### 4.4 Withdrawal Security

1. **Hot wallet limits**: Maintain only 5-10% of assets in hot wallet
2. **Cold wallet**: Store bulk assets in cold storage with multisig
3. **Rate limiting**: Implement withdrawal rate limits per user/IP
4. **2FA verification**: Require 2FA for all withdrawals
5. **Whitelisting**: Allow users to whitelist withdrawal addresses

---

## 5. AuxPoW/Merged Mining Considerations

### 5.1 Understanding AuxPoW Blocks

Soqucoin supports merged mining with Litecoin and Dogecoin. This means:
- Blocks may be submitted by Litecoin/Dogecoin miners
- AuxPoW headers contain parent chain proof
- Block structure differs from native PoW blocks

### 5.2 Block Validation

```bash
# Check if block is AuxPoW
soqucoin-cli getblock "blockhash" 2 | jq '.auxpow'
```

**AuxPoW block response includes**:
- `coinbasetx`: Parent chain coinbase
- `coinbranch`: Merkle branch for coinbase
- `blockchainbranch`: Merkle branch for aux chain
- `parentblock`: Parent chain block header

### 5.3 Chain ID Verification

Soqucoin's unique chain ID is `0x5351` (21329, representing "SQ"). This prevents cross-chain replay attacks with Dogecoin (`0x0062`).

```bash
# Verify chain ID in block
soqucoin-cli getblockchaininfo | jq '.chainid'
```

---

## 6. RPC Reference (Exchange-Relevant)

### 6.1 Balance & UTXO

| Command | Description |
|---------|-------------|
| `getbalance` | Total wallet balance |
| `listunspent` | List UTXOs |
| `listaddressgroupings` | Group addresses by wallet |

### 6.2 Transactions

| Command | Description |
|---------|-------------|
| `sendtoaddress <addr> <amt>` | Simple send |
| `sendmany <acct> <json>` | Batch withdrawals |
| `gettransaction <txid>` | Transaction details |
| `listtransactions` | Recent transactions |

### 6.3 Blockchain

| Command | Description |
|---------|-------------|
| `getblockchaininfo` | Sync status, chain info |
| `getblockcount` | Current block height |
| `getblock <hash> [verbosity]` | Block details |
| `getnetworkinfo` | Network/peer status |

### 6.4 PQ Wallet

| Command | Description |
|---------|-------------|
| `pqwalletinfo` | Wallet configuration |
| `pqgetnewaddress` | Generate PQ address |
| `pqvalidateaddress <addr>` | Validate address |
| `pqestimatefeerate [ins] [outs]` | Fee estimation |

---

## 7. Security Recommendations

### 7.1 Network Security

- [ ] Run node behind firewall
- [ ] Use SSH tunnels for RPC access
- [ ] Implement VPN for remote management
- [ ] Enable fail2ban for SSH

### 7.2 RPC Security

- [ ] Use strong 32+ character RPC password
- [ ] Bind RPC to localhost only
- [ ] Use SSL/TLS for RPC (nginx proxy)
- [ ] Implement RPC rate limiting

### 7.3 Wallet Security

- [ ] Enable wallet encryption: `soqucoin-cli encryptwallet "passphrase"`
- [ ] Regular wallet backups: `soqucoin-cli backupwallet "/path/to/backup"`
- [ ] Cold storage for bulk assets
- [ ] Hardware security modules (HSM) for production

### 7.4 Monitoring

- [ ] Alert on unusual withdrawal patterns
- [ ] Monitor node connectivity
- [ ] Track mempool size
- [ ] Watch for chain reorgs > 1 block

---

## 8. Troubleshooting

### 8.1 Common Issues

| Issue | Solution |
|-------|----------|
| Node not syncing | Check network connectivity, verify peers with `getpeerinfo` |
| RPC connection refused | Verify `rpcbind`, `rpcallowip`, and firewall rules |
| Transaction stuck | Check fee was adequate, verify UTXO not already spent |
| Address validation fails | Ensure correct network (mainnet vs testnet prefix) |

### 8.2 Log Analysis

```bash
# View recent logs
tail -f ~/.soqucoin/debug.log

# Search for errors
grep -i error ~/.soqucoin/debug.log | tail -20

# Check for network issues
grep -i "connection\|peer\|banned" ~/.soqucoin/debug.log
```

### 8.3 Node Recovery

```bash
# Rescan blockchain (after wallet restore)
soqucoind -rescan

# Reindex entire chain (if corruption suspected)
soqucoind -reindex

# Rebuild txindex
soqucoind -reindex-chainstate
```

---

## 9. Support & Resources

| Resource | Link |
|----------|------|
| **Protocol Spec** | https://soqu.org/protocol.html |
| **GitHub** | https://github.com/soqucoin/soqucoin |
| **Email Support** | dev@soqu.org |
| **Whitepaper** | https://soqu.org/whitepaper.html |

---

## Appendix A: Testnet Integration

For testing integration before mainnet:

```bash
# Testnet3 configuration
soqucoind -testnet -daemon

# Testnet RPC
soqucoin-cli -testnet getblockchaininfo

# Testnet address prefix
tsq1...
```

> **Note**: Contact dev@soqu.org for testnet node access during development.

---

## Appendix B: API Response Examples

### getblockchaininfo
```json
{
  "chain": "main",
  "blocks": 12108,
  "headers": 12108,
  "bestblockhash": "eb718060...",
  "difficulty": 170.06,
  "mediantime": 1736228400,
  "verificationprogress": 1.0,
  "chainwork": "...",
  "chainid": 21329
}
```

### pqgetnewaddress
```json
{
  "address": "sq1qqmf3532trg036kjvamk9d2n4m9uafyxyz...",
  "pubkey_hash": "b47468acb...",
  "network": "mainnet",
  "type": "P2PQ"
}
```

---

*Prepared for exchange partners*
*Soqucoin Development Team — January 2026*
