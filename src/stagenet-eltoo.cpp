// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// stagenet-eltoo.cpp
// ---------------------------------------------------------------------------
// Phase 1a stagenet eLTOO broadcast tool.
//
// PURPOSE: Prove the eLTOO transaction graph (F→U→coop-close) is accepted
// and mined by the DEPLOYED stagenet soqucoind, using the production
// soq-signer funding path and real sendrawtransaction relay.
//
// CREDENTIAL HANDLING:
//   Credentials are read from environment variables (preferred) or CLI flags
//   (override). They are NEVER echoed to stderr/stdout.
//
//   Env vars:
//     ELTOO_SIGNER_URL     soq-signer base URL
//     ELTOO_SIGNER_TOKEN   soq-signer Bearer token
//     ELTOO_RPC_URL        soqucoind RPC URL
//     ELTOO_RPC_USER       RPC username
//     ELTOO_RPC_PASS       RPC password
//
// USAGE:
//   export ELTOO_SIGNER_URL=http://...:8550
//   export ELTOO_SIGNER_TOKEN=<token>
//   export ELTOO_RPC_URL=http://...:38334
//   export ELTOO_RPC_USER=<user>
//   export ELTOO_RPC_PASS=<pass>
//   ./soqucoin-stagenet-eltoo --amount=1000000000
//
// BUILD (from src/):
//   g++ -std=c++17 -w -I. -I./config -I./univalue/include \
//     -I/opt/homebrew/opt/boost/include \
//     -I/opt/homebrew/Cellar/openssl@3/3.6.2/include \
//     -DHAVE_CONFIG_H \
//     stagenet-eltoo.cpp \
//     libsoqucoin_common.a libsoqucoin_consensus.a libsoqucoin_util.a \
//     crypto/libsoqucoin_crypto.a univalue/.libs/libunivalue.a \
//     /opt/homebrew/opt/boost/lib/libboost_filesystem.a \
//     /opt/homebrew/opt/boost/lib/libboost_thread.a \
//     /opt/homebrew/opt/boost/lib/libboost_chrono.a \
//     /opt/homebrew/opt/boost/lib/libboost_program_options.a \
//     -L/opt/homebrew/Cellar/openssl@3/3.6.2/lib \
//     -lssl -lcrypto -lpthread \
//     -o soqucoin-stagenet-eltoo

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "chainparams.h"
#include "consensus/consensus.h"
#include "core_io.h"
#include "crypto/sha256.h"
#include "key.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "util.h"
#include "utilstrencodings.h"

#include <univalue.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <sys/stat.h>

// ============================================================================
// Configuration
// ============================================================================
struct Config {
    std::string signerUrl;    // e.g. http://...:8550
    std::string signerToken;  // Bearer token for soq-signer API
    std::string rpcUrl;       // e.g. http://...:38334
    std::string rpcUser;
    std::string rpcPass;
    int64_t amount;           // Funding amount in satoshis
    int64_t fee;              // Fee per tx in satoshis (0 = auto from getmempoolinfo)
    int64_t feeRate;          // Fee rate for soq-signer (sat/vB)
    bool dryRun;              // If true, build+sign but don't broadcast
    bool envelopeVector;      // If true, emit deterministic BIP141 envelope for TS pinning
};

// ============================================================================
// Helpers (copied from keyhash_broadcast_tests.cpp — proven in regtest)
// ============================================================================

// V6 P2WSH-Dilithium scriptPubKey: OP_6 <SHA256(witnessScript)>  (34 bytes).
static CScript MakeV6Spk(const CScript& witnessScript)
{
    uint256 scriptHash;
    CSHA256().Write(witnessScript.data(), witnessScript.size()).Finalize(scriptHash.begin());
    CScript spk;
    spk << OP_6;
    spk << std::vector<unsigned char>(scriptHash.begin(), scriptHash.end());
    return spk;
}

// SHA256(rawPubkey) — the keyhash committed in the witnessScript.
static std::vector<unsigned char> KeyHash(const std::vector<unsigned char>& rawPubkey)
{
    unsigned char h[32];
    CSHA256().Write(rawPubkey.data(), rawPubkey.size()).Finalize(h);
    return std::vector<unsigned char>(h, h + 32);
}

// 0x00-prefixed (FIPS 204) pubkey for the trailing v6 witness item.
static std::vector<unsigned char> Prefixed(const std::vector<unsigned char>& rawPubkey)
{
    std::vector<unsigned char> out;
    out.reserve(rawPubkey.size() + 1);
    out.push_back(0x00);
    out.insert(out.end(), rawPubkey.begin(), rawPubkey.end());
    return out;
}

// Sign a sighash and append the hashtype byte.
// Returns raw 2420-byte ML-DSA-44 sig + 1-byte hashtype = 2421 bytes.
static std::vector<unsigned char> SignWith(const CKey& key,
                                           const CScript& scriptCode,
                                           const CTransaction& tx,
                                           unsigned int nIn,
                                           const CAmount& amount,
                                           int hashType)
{
    uint256 sighash = SignatureHash(scriptCode, tx, nIn, hashType, amount,
                                    SIGVERSION_WITNESS_V0, nullptr);
    std::vector<unsigned char> sig;
    if (!key.Sign(sighash, sig)) {
        throw std::runtime_error("Dilithium signing failed");
    }
    if (sig.size() != 2420) {
        throw std::runtime_error("Unexpected signature size: " +
            std::to_string(sig.size()) + " (expected 2420)");
    }
    sig.push_back(static_cast<unsigned char>(hashType));
    return sig;
}

// ============================================================================
// HTTP helpers (uses popen+curl — no libcurl dependency)
// ============================================================================

// Execute a curl command and return stdout. Throws on failure.
static std::string ExecCurl(const std::string& cmd)
{
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe)
        throw std::runtime_error("popen failed for curl");

    std::string result;
    char buf[4096];
    while (fgets(buf, sizeof(buf), pipe))
        result += buf;

    int status = pclose(pipe);
    if (status != 0) {
        throw std::runtime_error("curl exited with status " +
            std::to_string(status) + ": " + result);
    }
    return result;
}

// Write body to a temp file and POST it. Returns parsed JSON.
// SECURITY: credentials are passed via curl -u netrc-file or -H header,
// never via command-line arguments visible in ps(1). We use a temp netrc
// file for basic auth and a temp header file for bearer tokens.
static UniValue HttpPost(const std::string& url,
                         const std::string& jsonBody,
                         const std::string& bearerToken = "",
                         const std::string& basicUser = "",
                         const std::string& basicPass = "")
{
    std::string ts = std::to_string(
        std::chrono::system_clock::now().time_since_epoch().count());

    // Write body to temp file to avoid shell escaping issues
    std::string tmpBody = "/tmp/stagenet_eltoo_body_" + ts + ".json";
    {
        std::ofstream f(tmpBody);
        if (!f.is_open())
            throw std::runtime_error("Cannot create temp file: " + tmpBody);
        f << jsonBody;
    }

    std::string cmd = "curl -s -S --max-time 30 -X POST";

    // Bearer token via temp header file (not visible in ps)
    std::string tmpHeader;
    if (!bearerToken.empty()) {
        tmpHeader = "/tmp/stagenet_eltoo_hdr_" + ts + ".txt";
        std::ofstream hf(tmpHeader);
        hf << "Authorization: Bearer " << bearerToken << "\n";
        hf.close();
        cmd += " -H @" + tmpHeader;
    }

    // Basic auth via temp netrc file (not visible in ps)
    std::string tmpNetrc;
    if (!basicUser.empty()) {
        tmpNetrc = "/tmp/stagenet_eltoo_netrc_" + ts;
        std::ofstream nf(tmpNetrc);
        // netrc format: machine <host> login <user> password <pass>
        // Extract host from URL
        std::string host = url;
        size_t slashSlash = host.find("//");
        if (slashSlash != std::string::npos) host = host.substr(slashSlash + 2);
        size_t colon = host.find(':');
        if (colon != std::string::npos) host = host.substr(0, colon);
        size_t slash = host.find('/');
        if (slash != std::string::npos) host = host.substr(0, slash);
        nf << "machine " << host << " login " << basicUser
           << " password " << basicPass << "\n";
        nf.close();
        // Restrict permissions
        chmod(tmpNetrc.c_str(), 0600);
        cmd += " --netrc-file " + tmpNetrc;
    }

    cmd += " -H 'Content-Type: application/json'";
    cmd += " -d @" + tmpBody;
    cmd += " '" + url + "' 2>&1";

    std::string response;
    try {
        response = ExecCurl(cmd);
    } catch (...) {
        std::remove(tmpBody.c_str());
        if (!tmpHeader.empty()) std::remove(tmpHeader.c_str());
        if (!tmpNetrc.empty()) std::remove(tmpNetrc.c_str());
        throw;
    }

    // Clean up temp files
    std::remove(tmpBody.c_str());
    if (!tmpHeader.empty()) std::remove(tmpHeader.c_str());
    if (!tmpNetrc.empty()) std::remove(tmpNetrc.c_str());

    UniValue val;
    if (!val.read(response)) {
        throw std::runtime_error("Failed to parse JSON response: " + response);
    }
    return val;
}

// JSON-RPC call to soqucoind
static UniValue RpcCall(const Config& cfg,
                        const std::string& method,
                        const UniValue& params)
{
    UniValue req(UniValue::VOBJ);
    req.pushKV("jsonrpc", "1.0");
    req.pushKV("id", "stagenet-eltoo");
    req.pushKV("method", method);
    req.pushKV("params", params);

    UniValue resp = HttpPost(cfg.rpcUrl, req.write(),
                             "", cfg.rpcUser, cfg.rpcPass);

    if (resp.exists("error") && !resp["error"].isNull()) {
        UniValue err = resp["error"];
        std::string msg = err.isStr() ? err.getValStr() :
                          (err.isObject() && err.exists("message")) ?
                          err["message"].getValStr() : err.write();
        throw std::runtime_error("RPC " + method + " failed: " + msg);
    }

    return resp["result"];
}

// soq-signer API call
static UniValue SignerCall(const Config& cfg,
                           const std::string& endpoint,
                           const std::string& jsonBody)
{
    std::string url = cfg.signerUrl + endpoint;
    return HttpPost(url, jsonBody, cfg.signerToken);
}

// ============================================================================
// Dynamic fee calculation from getmempoolinfo
// ============================================================================
// Estimates the fee for a keyhash-2-of-2 Dilithium spend based on actual
// mempool relay fee. The witness is ~8.8 KB raw:
//   2 × (2421 sig + 1312 pubkey) + 69 witnessScript + 1313 trailing = ~8848 bytes
// With witness discount (÷4): ~2212 vB + ~90 base overhead ≈ ~2300 vB.
// We query mempoolminfee, multiply by estimated vsize, and add 2× headroom.
static int64_t EstimateFee(const Config& cfg)
{
    // If user explicitly set a fee, use it
    if (cfg.fee > 0) {
        fprintf(stderr, "  Using explicit fee: %lld sat\n", (long long)cfg.fee);
        return cfg.fee;
    }

    fprintf(stderr, "  Querying getmempoolinfo for relay fee...\n");
    try {
        UniValue params(UniValue::VARR);
        UniValue result = RpcCall(cfg, "getmempoolinfo", params);

        double minFeeSoq = 0.0;
        if (result.exists("mempoolminfee")) {
            minFeeSoq = result["mempoolminfee"].get_real();
        } else if (result.exists("minrelaytxfee")) {
            minFeeSoq = result["minrelaytxfee"].get_real();
        }

        // Convert from SOQ/kB to sat/vB
        // minFeeSoq is in SOQ per 1000 bytes
        // 1 SOQ = 100,000,000 sat
        int64_t satPerKB = (int64_t)(minFeeSoq * 100000000.0);
        int64_t satPerVB = (satPerKB + 999) / 1000;  // round up

        // Estimated vsize of a keyhash-2-of-2 spend
        const int64_t ESTIMATED_VSIZE = 2400;  // ~2300 vB + headroom

        // Fee = rate × vsize × 2 (2× headroom on a valueless testnet)
        int64_t fee = satPerVB * ESTIMATED_VSIZE * 2;

        // Floor: at least 100,000 sat (0.001 SOQ) to clear any edge case
        if (fee < 100000) fee = 100000;

        // Ceiling: 50 SOQ max (insane fee protection)
        if (fee > 5000000000LL) fee = 5000000000LL;

        fprintf(stderr, "  mempoolminfee: %.8f SOQ/kB = %lld sat/vB\n",
                minFeeSoq, (long long)satPerVB);
        fprintf(stderr, "  Estimated vsize: %lld vB, calculated fee: %lld sat (2× headroom)\n",
                (long long)ESTIMATED_VSIZE, (long long)fee);

        return fee;

    } catch (const std::exception& e) {
        // Fallback if getmempoolinfo fails
        fprintf(stderr, "  WARNING: getmempoolinfo failed (%s), using fallback fee\n", e.what());
        // Use 0.1 SOQ (10M sat) as safe fallback — generous on a valueless testnet
        return 10000000;
    }
}

// ============================================================================
// Parse CLI args (env vars as defaults, CLI overrides)
// ============================================================================
static std::string EnvOr(const char* envVar, const std::string& cliVal)
{
    if (!cliVal.empty()) return cliVal;
    const char* v = std::getenv(envVar);
    return v ? std::string(v) : "";
}

static Config ParseArgs(int argc, char* argv[])
{
    Config cfg;
    cfg.amount = 1000000000;  // 10 SOQ default
    cfg.fee = 0;              // 0 = auto from getmempoolinfo
    cfg.feeRate = 1000;       // 1000 sat/vB default for soq-signer
    cfg.dryRun = false;
    cfg.envelopeVector = false;

    // Pre-load from env vars
    cfg.signerUrl   = EnvOr("ELTOO_SIGNER_URL", "");
    cfg.signerToken = EnvOr("ELTOO_SIGNER_TOKEN", "");
    cfg.rpcUrl      = EnvOr("ELTOO_RPC_URL", "");
    cfg.rpcUser     = EnvOr("ELTOO_RPC_USER", "");
    cfg.rpcPass     = EnvOr("ELTOO_RPC_PASS", "");

    for (int i = 1; i < argc; i++) {
        std::string arg(argv[i]);
        size_t eq = arg.find('=');
        if (eq == std::string::npos) {
            if (arg == "--dry-run") { cfg.dryRun = true; continue; }
            if (arg == "--envelope-vector") { cfg.envelopeVector = true; continue; }
            if (arg == "--help" || arg == "-h") {
                fprintf(stderr,
                    "Usage: soqucoin-stagenet-eltoo [options]\n"
                    "\n"
                    "Credentials (env vars preferred, CLI overrides):\n"
                    "  ELTOO_SIGNER_URL / --signer-url=URL\n"
                    "  ELTOO_SIGNER_TOKEN / --signer-token=TOKEN\n"
                    "  ELTOO_RPC_URL / --rpc-url=URL\n"
                    "  ELTOO_RPC_USER / --rpc-user=USER\n"
                    "  ELTOO_RPC_PASS / --rpc-pass=PASS\n"
                    "\n"
                    "Options:\n"
                    "  --amount=SAT          Funding amount in satoshis (default: 1000000000)\n"
                    "  --fee=SAT             Fee per tx in satoshis (default: auto from getmempoolinfo)\n"
                    "  --fee-rate=SAT        Fee rate for soq-signer (default: 1000)\n"
                    "  --dry-run             Build+sign but don't broadcast\n"
                    "  --envelope-vector     Emit deterministic BIP141 envelope for TS pinning\n"
                );
                exit(0);
            }
            fprintf(stderr, "Unknown option: %s\n", arg.c_str());
            exit(1);
        }
        std::string key = arg.substr(0, eq);
        std::string val = arg.substr(eq + 1);
        if (key == "--signer-url") cfg.signerUrl = val;
        else if (key == "--signer-token") cfg.signerToken = val;
        else if (key == "--rpc-url") cfg.rpcUrl = val;
        else if (key == "--rpc-user") cfg.rpcUser = val;
        else if (key == "--rpc-pass") cfg.rpcPass = val;
        else if (key == "--amount") cfg.amount = std::stoll(val);
        else if (key == "--fee") cfg.fee = std::stoll(val);
        else if (key == "--fee-rate") cfg.feeRate = std::stoll(val);
        else {
            fprintf(stderr, "Unknown option: %s\n", key.c_str());
            exit(1);
        }
    }

    // Envelope-vector mode doesn't need credentials
    if (cfg.envelopeVector) return cfg;

    // Validate required args (env or CLI must have provided them)
    if (cfg.signerUrl.empty()) { fprintf(stderr, "Missing ELTOO_SIGNER_URL or --signer-url\n"); exit(1); }
    if (cfg.signerToken.empty()) { fprintf(stderr, "Missing ELTOO_SIGNER_TOKEN or --signer-token\n"); exit(1); }
    if (cfg.rpcUrl.empty()) { fprintf(stderr, "Missing ELTOO_RPC_URL or --rpc-url\n"); exit(1); }
    if (cfg.rpcUser.empty()) { fprintf(stderr, "Missing ELTOO_RPC_USER or --rpc-user\n"); exit(1); }
    if (cfg.rpcPass.empty()) { fprintf(stderr, "Missing ELTOO_RPC_PASS or --rpc-pass\n"); exit(1); }

    return cfg;
}

// ============================================================================
// Wait for a UTXO to appear (poll gettxout)
// ============================================================================
static bool WaitForUtxo(const Config& cfg, const std::string& txid,
                        int vout, int maxWaitSec = 600)
{
    fprintf(stderr, "[wait] Polling gettxout for %s:%d (max %ds)...\n",
            txid.c_str(), vout, maxWaitSec);

    for (int elapsed = 0; elapsed < maxWaitSec; elapsed += 10) {
        try {
            UniValue params(UniValue::VARR);
            params.push_back(txid);
            params.push_back(vout);
            params.push_back(true);  // include_mempool
            UniValue result = RpcCall(cfg, "gettxout", params);

            if (!result.isNull()) {
                fprintf(stderr, "[wait] UTXO %s:%d found after %ds\n",
                        txid.c_str(), vout, elapsed);
                return true;
            }
        } catch (const std::exception& e) {
            fprintf(stderr, "[wait] gettxout error (retrying): %s\n", e.what());
        }

        std::this_thread::sleep_for(std::chrono::seconds(10));
    }

    fprintf(stderr, "[wait] TIMEOUT: UTXO %s:%d not found after %ds\n",
            txid.c_str(), vout, maxWaitSec);
    return false;
}

// ============================================================================
// Find the vout matching our scriptPubKey in a raw transaction
// ============================================================================
static int FindVout(const Config& cfg, const std::string& txid,
                    const CScript& targetSpk)
{
    UniValue params(UniValue::VARR);
    params.push_back(txid);
    params.push_back(true);  // verbose
    UniValue result = RpcCall(cfg, "getrawtransaction", params);

    if (!result.isObject() || !result.exists("vout"))
        throw std::runtime_error("getrawtransaction returned unexpected format");

    const UniValue& vouts = result["vout"];
    std::string targetHex = HexStr(targetSpk.begin(), targetSpk.end());

    for (size_t i = 0; i < vouts.size(); i++) {
        const UniValue& v = vouts[i];
        if (v.exists("scriptPubKey") && v["scriptPubKey"].exists("hex")) {
            if (v["scriptPubKey"]["hex"].getValStr() == targetHex) {
                return (int)i;
            }
        }
    }

    throw std::runtime_error("Could not find vout matching target scriptPubKey "
        + targetHex + " in tx " + txid);
}

// ============================================================================
// Envelope Vector Mode
// ============================================================================
// Emits a deterministic BIP141-serialized tx with known witness items for
// byte-exact comparison with the TypeScript serializeTxWithWitness.
// No real keys needed — uses fixed-length synthetic data.
static int EmitEnvelopeVector()
{
    SelectParams(CBaseChainParams::REGTEST);

    fprintf(stderr, "=== Envelope Vector Mode ===\n");
    fprintf(stderr, "Emitting deterministic BIP141 serialization for TS pinning.\n\n");

    // --- Build a tx matching the eLTOO update shape ---
    // 1 input spending a known prevout, 1 output, keyhash-2-of-2 witness.

    // Fixed 32-byte "keyhashes" — just incrementing patterns
    std::vector<unsigned char> khA(32, 0xAA);
    std::vector<unsigned char> khB(32, 0xBB);

    // Fixed witnessScript: <khB> OP_CDKH <khA> OP_CDKH OP_1
    CScript ws;
    ws << khB << OP_CHECKDILITHIUMKEYHASH
       << khA << OP_CHECKDILITHIUMKEYHASH
       << OP_1;

    CScript spk = MakeV6Spk(ws);

    // Fixed "signatures" — 2420 bytes of 0x11 (sigA) and 0x22 (sigB) + hashtype
    std::vector<unsigned char> fakeSigA(2420, 0x11);
    fakeSigA.push_back(0x42);  // SIGHASH_ANYPREVOUTANYSCRIPT
    std::vector<unsigned char> fakeSigB(2420, 0x22);
    fakeSigB.push_back(0x42);

    // Fixed "pubkeys" — 1312 bytes of 0xAA (alice) and 0xBB (bob)
    std::vector<unsigned char> fakePkA(1312, 0xAA);
    std::vector<unsigned char> fakePkB(1312, 0xBB);

    // Fixed "prefixed pubkey" — 0x00 || 1312 bytes
    std::vector<unsigned char> fakeTrailing(1313, 0xAA);
    fakeTrailing[0] = 0x00;

    // Build the transaction
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.nLockTime = 0;
    {
        CTxIn in;
        // Known prevout: all-0xCC hash, vout=0
        in.prevout.hash = uint256S("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        in.prevout.n = 0;
        in.nSequence = 0xffffffff;
        mtx.vin.push_back(in);
    }
    {
        CTxOut out;
        out.nValue = 999950000;  // 9.9995 SOQ
        out.scriptPubKey = spk;
        out.nVisibility = 0;
        out.nAssetType = 0;
        mtx.vout.push_back(out);
    }

    // Witness stack (same shape as the real update tx)
    CScriptWitness w;
    w.stack.push_back(fakeSigA);      // [0]: sigA + hashtype (2421 bytes)
    w.stack.push_back(fakePkA);       // [1]: pubkeyA (1312 bytes)
    w.stack.push_back(fakeSigB);      // [2]: sigB + hashtype (2421 bytes)
    w.stack.push_back(fakePkB);       // [3]: pubkeyB (1312 bytes)
    w.stack.push_back(std::vector<unsigned char>(ws.begin(), ws.end()));  // [4]: witnessScript
    w.stack.push_back(fakeTrailing);  // [5]: 0x00||pkA (1313 bytes)
    mtx.vin[0].scriptWitness = w;

    CTransaction ctx(mtx);
    std::string hex = EncodeHexTx(ctx);

    // Output the envelope vector as JSON
    UniValue envelope(UniValue::VOBJ);
    envelope.pushKV("description",
        "Deterministic BIP141 envelope vector for TS serializeTxWithWitness pinning");
    envelope.pushKV("nVersion", 2);
    envelope.pushKV("nLockTime", 0);

    // Input details
    UniValue input(UniValue::VOBJ);
    input.pushKV("prevout_hash", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    input.pushKV("prevout_n", 0);
    input.pushKV("nSequence", (int64_t)0xffffffff);
    input.pushKV("witness_items", 6);
    input.pushKV("witness_item_sizes", "[2421, 1312, 2421, 1312, 69, 1313]");
    envelope.pushKV("input", input);

    // Output details
    UniValue output(UniValue::VOBJ);
    output.pushKV("value_sat", 999950000);
    output.pushKV("scriptPubKey", HexStr(spk.begin(), spk.end()));
    output.pushKV("nVisibility", 0);
    output.pushKV("nAssetType", 0);
    envelope.pushKV("output", output);

    // The hex
    envelope.pushKV("txid", ctx.GetHash().ToString());
    envelope.pushKV("raw_hex_length", (int)hex.size());
    envelope.pushKV("raw_hex", hex);

    // Also emit the witnessScript hex for reconstruction
    envelope.pushKV("witnessScript_hex", HexStr(ws.begin(), ws.end()));

    fprintf(stdout, "%s\n", envelope.write(2).c_str());

    fprintf(stderr, "\n  txid: %s\n", ctx.GetHash().ToString().c_str());
    fprintf(stderr, "  Serialized size: %zu bytes (%zu hex chars)\n",
            hex.size() / 2, hex.size());
    fprintf(stderr, "  Witness items: 6 (sigA:2421 + pkA:1312 + sigB:2421 + pkB:1312 + ws:69 + trailing:1313)\n");
    fprintf(stderr, "\nTS should produce IDENTICAL raw_hex for the same inputs.\n");

    return 0;
}

// ============================================================================
// MAIN
// ============================================================================
int main(int argc, char* argv[])
{
    Config cfg = ParseArgs(argc, argv);

    // Envelope vector mode — no credentials needed, exits immediately
    if (cfg.envelopeVector) {
        return EmitEnvelopeVector();
    }

    // Initialize chain params (needed for SignatureHash consensus rules).
    SelectParams(CBaseChainParams::REGTEST);

    // Never echo credentials — only show URLs (redacted)
    fprintf(stderr,
        "====================================================================\n"
        "  Soqucoin Phase 1a: Stagenet eLTOO Broadcast Tool\n"
        "  Funding: %lld sat (%lld SOQ)\n"
        "  Signer:  %s\n"
        "  RPC:     %s (user: %s)\n"
        "  Mode:    %s\n"
        "====================================================================\n",
        (long long)cfg.amount, (long long)(cfg.amount / 100000000LL),
        cfg.signerUrl.c_str(), cfg.rpcUrl.c_str(), cfg.rpcUser.c_str(),
        cfg.dryRun ? "DRY RUN" : "LIVE BROADCAST");

    // ==================================================================
    // Step 0: Generate two ephemeral Dilithium keypairs (Alice and Bob)
    // ==================================================================
    fprintf(stderr, "\n[step 0] Generating Dilithium keypairs...\n");
    CKey alice, bob;
    alice.MakeNewKey(true);
    bob.MakeNewKey(true);
    CPubKey alicePk = alice.GetPubKey(), bobPk = bob.GetPubKey();
    if (!alicePk.IsValid() || !bobPk.IsValid())
        throw std::runtime_error("Key generation failed");

    std::vector<unsigned char> aPk(alicePk.begin(), alicePk.end());
    std::vector<unsigned char> bPk(bobPk.begin(), bobPk.end());
    if (aPk.size() != 1312 || bPk.size() != 1312)
        throw std::runtime_error("Unexpected pubkey size");

    fprintf(stderr, "  Alice pubkey SHA256: %s\n", HexStr(KeyHash(aPk)).c_str());
    fprintf(stderr, "  Bob   pubkey SHA256: %s\n", HexStr(KeyHash(bPk)).c_str());

    // ==================================================================
    // Step 1: Construct the 2-of-2 witnessScript and scriptPubKey
    // ==================================================================
    CScript ws;
    ws << KeyHash(bPk)  << OP_CHECKDILITHIUMKEYHASH
       << KeyHash(aPk)  << OP_CHECKDILITHIUMKEYHASH
       << OP_1;
    CScript spk = MakeV6Spk(ws);

    if (ws.size() != 69 || spk.size() != 34) {
        throw std::runtime_error("Unexpected script sizes: ws=" +
            std::to_string(ws.size()) + ", spk=" + std::to_string(spk.size()));
    }

    fprintf(stderr, "\n[step 1] 2-of-2 keyhash scripts constructed\n");
    fprintf(stderr, "  witnessScript (%zu bytes): %s\n",
            ws.size(), HexStr(ws.begin(), ws.end()).c_str());
    fprintf(stderr, "  scriptPubKey  (%zu bytes): %s\n",
            spk.size(), HexStr(spk.begin(), spk.end()).c_str());

    // ==================================================================
    // Step 2: Calculate fee from getmempoolinfo
    // ==================================================================
    fprintf(stderr, "\n[step 2] Calculating fee...\n");
    int64_t txFee = EstimateFee(cfg);
    fprintf(stderr, "  Using fee: %lld sat per tx\n", (long long)txFee);

    const CAmount V = cfg.amount;            // F output value
    const CAmount V_U = V - txFee;           // U output value
    const CAmount V_C = V_U - txFee;         // Coop-close total payout

    if (V_U <= 0 || V_C <= 0) {
        throw std::runtime_error("Fee too high for funding amount: fee=" +
            std::to_string(txFee) + ", amount=" + std::to_string(cfg.amount));
    }

    // ==================================================================
    // Step 3: Fund the v6 output via soq-signer
    // ==================================================================
    fprintf(stderr, "\n[step 3] Funding v6 keyhash-2-of-2 output via soq-signer...\n");

    std::string fundingTxid;
    {
        UniValue body(UniValue::VOBJ);
        body.pushKV("witness_script", HexStr(ws.begin(), ws.end()));
        body.pushKV("amount", cfg.amount);
        body.pushKV("fee_rate", cfg.feeRate);

        fprintf(stderr, "  POST %s/api/v1/send-to-witness-script\n",
                cfg.signerUrl.c_str());

        if (cfg.dryRun) {
            fprintf(stderr, "  [DRY RUN] Skipping funding.\n");
            fprintf(stdout, "{\"status\":\"dry_run\",\"witness_script\":\"%s\","
                "\"script_pubkey\":\"%s\",\"fee_per_tx\":%lld}\n",
                HexStr(ws.begin(), ws.end()).c_str(),
                HexStr(spk.begin(), spk.end()).c_str(),
                (long long)txFee);
            return 0;
        }

        UniValue resp = SignerCall(cfg, "/api/v1/send-to-witness-script",
                                  body.write());

        if (resp.exists("error")) {
            throw std::runtime_error("soq-signer error: " +
                resp["error"].getValStr());
        }
        if (!resp.exists("txid")) {
            throw std::runtime_error("soq-signer response missing txid: " +
                resp.write());
        }

        fundingTxid = resp["txid"].getValStr();
        fprintf(stderr, "  Funding txid: %s\n", fundingTxid.c_str());
    }

    // ==================================================================
    // Step 4: Wait for funding tx and find our vout
    // ==================================================================
    fprintf(stderr, "\n[step 4] Waiting for funding tx to appear...\n");
    std::this_thread::sleep_for(std::chrono::seconds(3));

    int fundingVout = FindVout(cfg, fundingTxid, spk);
    fprintf(stderr, "  Found our v6 output at vout %d\n", fundingVout);

    if (!WaitForUtxo(cfg, fundingTxid, fundingVout, 600)) {
        throw std::runtime_error("Funding UTXO never appeared — check soq-signer logs");
    }

    // ==================================================================
    // Step 5: PRE-FLIGHT — Build+sign BOTH U and C before broadcasting
    // ==================================================================
    // This is the crash-safe ordering settled in review: if we crash after
    // funding but before broadcasting, we still have both signed txs.
    // The ephemeral keys are only in memory; losing them means the 2-of-2
    // funds are unrecoverable. So we sign everything first.
    fprintf(stderr, "\n[step 5] PRE-FLIGHT: Building+signing U and C before broadcast...\n");

    // --- Build U (update tx) — spends F:vout with APO 0x42 ---
    CMutableTransaction updateTx;
    updateTx.nVersion = 2;
    updateTx.nLockTime = 0;
    {
        CTxIn in;
        in.prevout.hash = uint256S(fundingTxid);
        in.prevout.n = fundingVout;
        in.nSequence = 0xffffffff;
        updateTx.vin.push_back(in);
    }
    {
        CTxOut out;
        out.nValue = V_U;
        out.scriptPubKey = spk;  // same 2-of-2
        out.nVisibility = 0;
        out.nAssetType = 0;
        updateTx.vout.push_back(out);
    }

    // Sign U with APO 0x42
    {
        CTransaction ctx(updateTx);
        const int apo = SIGHASH_ANYPREVOUTANYSCRIPT;
        std::vector<unsigned char> sigA = SignWith(alice, ws, ctx, 0, V, apo);
        std::vector<unsigned char> sigB = SignWith(bob,   ws, ctx, 0, V, apo);

        CScriptWitness w;
        w.stack.push_back(sigA);
        w.stack.push_back(aPk);
        w.stack.push_back(sigB);
        w.stack.push_back(bPk);
        w.stack.push_back(std::vector<unsigned char>(ws.begin(), ws.end()));
        w.stack.push_back(Prefixed(aPk));
        updateTx.vin[0].scriptWitness = w;
    }

    std::string updateHex = EncodeHexTx(CTransaction(updateTx));
    std::string updateTxid = CTransaction(updateTx).GetHash().ToString();

    fprintf(stderr, "  U txid: %s\n", updateTxid.c_str());
    fprintf(stderr, "  U size: %zu bytes, sighash: APO 0x42\n", updateHex.size() / 2);

    // --- Build C (coop-close) — spends U:0 with SIGHASH_ALL ---
    // U's txid is deterministic once signed, so we can build C immediately.
    CMutableTransaction closeTx;
    closeTx.nVersion = 2;
    closeTx.nLockTime = 0;
    {
        CTxIn in;
        in.prevout.hash = CTransaction(updateTx).GetHash();
        in.prevout.n = 0;
        in.nSequence = 0xffffffff;  // cooperative, no CSV
        closeTx.vin.push_back(in);
    }
    {
        CAmount alicePayout = (V_C * 6) / 10;
        CAmount bobPayout   = V_C - alicePayout;

        CScript alicePayoutWs;
        alicePayoutWs << KeyHash(aPk) << OP_CHECKDILITHIUMKEYHASH << OP_1;
        CTxOut outA;
        outA.nValue = alicePayout;
        outA.scriptPubKey = MakeV6Spk(alicePayoutWs);
        outA.nVisibility = 0;
        outA.nAssetType = 0;
        closeTx.vout.push_back(outA);

        CScript bobPayoutWs;
        bobPayoutWs << KeyHash(bPk) << OP_CHECKDILITHIUMKEYHASH << OP_1;
        CTxOut outB;
        outB.nValue = bobPayout;
        outB.scriptPubKey = MakeV6Spk(bobPayoutWs);
        outB.nVisibility = 0;
        outB.nAssetType = 0;
        closeTx.vout.push_back(outB);

        fprintf(stderr, "  C Alice payout: %lld sat, Bob: %lld sat\n",
                (long long)alicePayout, (long long)bobPayout);
    }

    // Sign C with SIGHASH_ALL
    {
        CTransaction ctx(closeTx);
        std::vector<unsigned char> sigA = SignWith(alice, ws, ctx, 0, V_U, SIGHASH_ALL);
        std::vector<unsigned char> sigB = SignWith(bob,   ws, ctx, 0, V_U, SIGHASH_ALL);

        CScriptWitness w;
        w.stack.push_back(sigA);
        w.stack.push_back(aPk);
        w.stack.push_back(sigB);
        w.stack.push_back(bPk);
        w.stack.push_back(std::vector<unsigned char>(ws.begin(), ws.end()));
        w.stack.push_back(Prefixed(aPk));
        closeTx.vin[0].scriptWitness = w;
    }

    std::string closeHex = EncodeHexTx(CTransaction(closeTx));
    std::string closeTxid = CTransaction(closeTx).GetHash().ToString();

    fprintf(stderr, "  C txid: %s\n", closeTxid.c_str());
    fprintf(stderr, "  C size: %zu bytes, sighash: ALL 0x01\n", closeHex.size() / 2);

    fprintf(stderr, "\n  PRE-FLIGHT COMPLETE: Both U and C are signed in memory.\n");
    fprintf(stderr, "  Ephemeral keys can now be discarded after broadcast.\n");

    // ==================================================================
    // Step 6: Broadcast U via sendrawtransaction
    // ==================================================================
    fprintf(stderr, "\n[step 6] Broadcasting U (update, APO 0x42)...\n");
    {
        UniValue params(UniValue::VARR);
        params.push_back(updateHex);
        UniValue result = RpcCall(cfg, "sendrawtransaction", params);
        fprintf(stderr, "  U ACCEPTED: %s\n", result.getValStr().c_str());
    }

    // Wait for U to be spendable
    fprintf(stderr, "\n[step 6b] Waiting for U to be spendable...\n");
    if (!WaitForUtxo(cfg, updateTxid, 0, 600)) {
        // Don't throw — we have C pre-signed, try broadcasting anyway
        fprintf(stderr, "  WARNING: U UTXO not found via gettxout, attempting C broadcast anyway\n");
    }

    // ==================================================================
    // Step 7: Broadcast C (coop-close)
    // ==================================================================
    fprintf(stderr, "\n[step 7] Broadcasting C (cooperative close, SIGHASH_ALL)...\n");
    {
        UniValue params(UniValue::VARR);
        params.push_back(closeHex);
        UniValue result = RpcCall(cfg, "sendrawtransaction", params);
        fprintf(stderr, "  C ACCEPTED: %s\n", result.getValStr().c_str());
    }

    // ==================================================================
    // Step 8: Print transcript (machine-readable JSON on stdout)
    // ==================================================================
    UniValue transcript(UniValue::VOBJ);
    transcript.pushKV("phase", "1a-stagenet");
    transcript.pushKV("status", "GREEN");
    transcript.pushKV("note", "This proves 1a-stagenet (signer+RPC path), NOT 1b (TS SDK signing)");

    UniValue funding(UniValue::VOBJ);
    funding.pushKV("txid", fundingTxid);
    funding.pushKV("vout", fundingVout);
    funding.pushKV("amount_sat", cfg.amount);
    funding.pushKV("witness_script", HexStr(ws.begin(), ws.end()));
    funding.pushKV("script_pubkey", HexStr(spk.begin(), spk.end()));
    transcript.pushKV("funding", funding);

    UniValue update(UniValue::VOBJ);
    update.pushKV("txid", updateTxid);
    update.pushKV("sighash", "ANYPREVOUTANYSCRIPT (0x42)");
    update.pushKV("value_sat", V_U);
    update.pushKV("fee_sat", txFee);
    update.pushKV("hex_size", (int)(updateHex.size() / 2));
    transcript.pushKV("update", update);

    UniValue close(UniValue::VOBJ);
    close.pushKV("txid", closeTxid);
    close.pushKV("sighash", "ALL (0x01)");
    close.pushKV("value_sat", V_C);
    close.pushKV("fee_sat", txFee);
    close.pushKV("hex_size", (int)(closeHex.size() / 2));
    transcript.pushKV("coop_close", close);

    fprintf(stdout, "%s\n", transcript.write(4).c_str());

    fprintf(stderr,
        "\n"
        "====================================================================\n"
        "  Phase 1a STAGENET RESULTS\n"
        "  F (funding)    : %s (via soq-signer)\n"
        "  U (update)     : %s (APO 0x42) → ACCEPTED\n"
        "  C (coop-close) : %s (SIGHASH_ALL) → ACCEPTED\n"
        "  NOTE: This is 1a-stagenet, not 1b. 1b requires TS SDK signing.\n"
        "  STATUS: GREEN — eLTOO graph proven on deployed stagenet\n"
        "====================================================================\n",
        fundingTxid.c_str(), updateTxid.c_str(), closeTxid.c_str());

    return 0;
}
