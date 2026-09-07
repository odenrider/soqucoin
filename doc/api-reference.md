# Soqucoin RPC API Reference

> **Version**: 2.0 | **Updated**: 2026-01-02
> **Network**: Testnet3 (Mainnet Q2 2026)
> **Default RPC Port**: 44555

---

## Overview

Soqucoin inherits the Bitcoin/Dogecoin JSON-RPC API with additional commands for:
- **AuxPoW Merged Mining**
- **Post-Quantum (Dilithium) Wallet Operations**

Authentication uses HTTP Basic Auth with the credentials from `soqucoin.conf`.

---

## 1. Connection

### RPC Configuration

```ini
# soqucoin.conf
rpcuser=soqurpc
rpcpassword=your_secure_password
rpcallowip=127.0.0.1
rpcport=44555
```

### Example Request (curl)

```bash
curl --user soqurpc:your_password --data-binary '{"jsonrpc":"1.0","id":"1","method":"getblockchaininfo","params":[]}' -H 'content-type: text/plain;' http://127.0.0.1:44555/
```

### Example Request (soqucoin-cli)

```bash
soqucoin-cli getblockchaininfo
```

---

## 2. Blockchain Commands

### `getblockchaininfo`

Returns general information about the blockchain.

**Response**:
```json
{
  "chain": "test",
  "blocks": 1212,
  "headers": 1212,
  "bestblockhash": "abc123...",
  "difficulty": 0.00097656,
  "mediantime": 1735848000,
  "verificationprogress": 1.0,
  "chainwork": "0000000000000..."
}
```

### `getblock <hash> [verbosity]`

Returns block data.

**Parameters**:
- `hash` (string): Block hash
- `verbosity` (int, optional): 0=hex, 1=JSON, 2=JSON with tx details

**Example**:
```bash
soqucoin-cli getblock "abc123..." 1
```

### `getblockhash <height>`

Returns the hash of block at given height.

**Example**:
```bash
soqucoin-cli getblockhash 100
```

### `getblockcount`

Returns the current block height.

---

## 3. AuxPoW / Merged Mining Commands

These commands are essential for merged mining pool operators.

### `createauxblock <address>`

Creates a new block template for merged mining.

**Parameters**:
- `address` (string): Dilithium address to receive coinbase reward

**Response**:
```json
{
  "hash": "abc123...",
  "chainid": 21329,
  "previousblockhash": "def456...",
  "coinbasevalue": 10000000000000,
  "bits": "1e0fffff",
  "height": 1213,
  "_target": "00000fffff..."
}
```

**Notes**:
- Chain ID `21329` = `0x5351` (hex) = "SQ"
- Pool software must embed this in parent chain coinbase

### `getauxblock [hash] [auxpow]`

Get work or submit solved block.

**Get Work** (no parameters):
```bash
soqucoin-cli getauxblock
```

**Submit Work** (with parameters):
```bash
soqucoin-cli getauxblock "blockhash" "auxpow_hex_data"
```

### `submitauxblock <hash> <auxpow>`

Submit a solved AuxPoW block.

**Parameters**:
- `hash` (string): Block hash from `createauxblock`
- `auxpow` (string): Serialized AuxPoW proof from parent chain

**Response**: `true` on success

---

## 4. Wallet Commands

### `getnewaddress [label]`

Generates a new Dilithium-based receiving address.

**Parameters**:
- `label` (string, optional): Account label

**Response**: `"sq1q..."`

> ⚠️ **Important**: Only Dilithium addresses (starting with `sq1`) are valid. ECDSA addresses are rejected.

### `getbalance [minconf]`

Returns wallet balance.

**Parameters**:
- `minconf` (int, optional): Minimum confirmations (default: 1)

### `sendtoaddress <address> <amount> [comment]`

Sends SOQ to an address.

**Parameters**:
- `address` (string): Destination Dilithium address
- `amount` (numeric): Amount in SOQ
- `comment` (string, optional): Transaction comment

**Example**:
```bash
soqucoin-cli sendtoaddress "sq1qmyaddress" 10.5 "Payment"
```

### `validateaddress <address>`

Validates an address and returns detailed information.

**Response**:
```json
{
  "isvalid": true,
  "address": "sq1q...",
  "scriptPubKey": "0014...",
  "isscript": false,
  "iswitness": true,
  "witness_version": 0,
  "witness_program": "..."
}
```

### `listunspent [minconf] [maxconf]`

Lists unspent transaction outputs (UTXOs).

---

## 5. Mining Commands

### `getmininginfo`

Returns mining-related information.

**Response**:
```json
{
  "blocks": 1212,
  "currentblockweight": 4000,
  "currentblocktx": 0,
  "difficulty": 0.00097656,
  "networkhashps": 1234567890,
  "pooledtx": 0,
  "chain": "test"
}
```

### `getblocktemplate [template_request]`

Returns data needed to construct a block.

**Parameters**:
- `template_request` (object, optional): Capabilities and mode

**Example**:
```bash
soqucoin-cli getblocktemplate '{"rules":["segwit"]}'
```

### `submitblock <hexdata>`

Submits a mined block to the network.

---

## 6. Network Commands

### `getnetworkinfo`

Returns network state information.

### `getpeerinfo`

Returns data about connected peers.

### `addnode <node> <command>`

Manages peer connections.

**Commands**: `add`, `remove`, `onetry`

---

## 7. Utility Commands

### `help [command]`

Lists all commands or gets help for specific command.

### `uptime`

Returns node uptime in seconds.

### `stop`

Gracefully stops the node.

---

## 8. Soqucoin-Specific Constants

| Parameter | Value | Notes |
|-----------|-------|-------|
| Chain ID | `0x5351` (21329) | Used in AuxPoW header |
| Block Time | 60 seconds | DigiShield adjustment |
| Coinbase Maturity | Mainnet 288 (from height 1; 30 at height 0); testnet 240; regtest 60 | Before reward spendable. On mainnet it equals the finality horizon `nMaxReorgDepth`; testnet is a deliberate exception |
| **Mainnet P2P** | 33388 | Public P2P connections |
| **Mainnet RPC** | 33389 | Local RPC only |
| **Testnet P2P** | 44556 | Testnet P2P connections |
| **Testnet RPC** | 44555 | Testnet RPC (local only) |
| Address Prefix | `sq1` | Bech32m Dilithium |

---

## 9. Error Codes

| Code | Message | Cause |
|------|---------|-------|
| -1 | General error | Miscellaneous failure |
| -5 | Invalid address | Non-Dilithium or malformed address |
| -6 | Insufficient funds | Wallet balance too low |
| -8 | Invalid parameter | Wrong argument type |
| -25 | Block not accepted | Invalid PoW or chain reorg |
| -28 | Loading | Node still initializing |

---

## 10. Example: Full Mining Workflow

```bash
# 1. Generate receiving address
ADDRESS=$(soqucoin-cli getnewaddress "mining")
echo "Mining to: $ADDRESS"

# 2. Get block template (for standalone mining)
soqucoin-cli getblocktemplate '{"rules":["segwit"]}'

# 3. OR: Get AuxPoW work (for merged mining)
soqucoin-cli createauxblock "$ADDRESS"

# 4. Submit solved block
soqucoin-cli submitblock "00000020..."

# 5. Verify block was accepted
soqucoin-cli getblockcount
```

---

*Last Updated: 2026-01-02*
*Soqucoin API Reference v2.0*
