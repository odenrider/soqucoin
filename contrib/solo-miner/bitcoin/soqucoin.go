package bitcoin

import (
        "strings"
)

// Soqucoin - Scrypt PoW chain with Dilithium signatures
type Soqucoin struct{}

func (Soqucoin) ChainName() string {
        return "soqucoin"
}

func (Soqucoin) CoinbaseDigest(coinbase string) (string, error) {
        return DoubleSha256(coinbase)
}

func (Soqucoin) HeaderDigest(header string) (string, error) {
        return ScryptDigest(header)
}

func (Soqucoin) ShareMultiplier() float64 {
        return 65536
}

func (Soqucoin) ValidMainnetAddress(address string) bool {
        // Soqucoin mainnet Dilithium addresses start with 'sq1' (bech32m)
        // Soqucoin stagenet Dilithium addresses use 'ssq1' prefix
        if strings.HasPrefix(address, "ssq1") && len(address) >= 42 {
                return true
        }
        if strings.HasPrefix(address, "sq1") && len(address) >= 42 {
                return true
        }
        // Also accept uppercase (ASICs sometimes uppercase addresses)
        upper := strings.ToUpper(address)
        if strings.HasPrefix(upper, "SSQ1") && len(address) >= 42 {
                return true
        }
        if strings.HasPrefix(upper, "SQ1") && len(address) >= 42 {
                return true
        }
        // Legacy mainnet addresses start with S (for transition period)
        if strings.HasPrefix(address, "S") && len(address) >= 34 && len(address) <= 36 {
                return true
        }
        return false
}

func (Soqucoin) ValidTestnetAddress(address string) bool {
        // Soqucoin testnet Dilithium addresses also use 'sq1' prefix (like mainnet)
        // The bech32m HRP is 'sq' for both networks in current implementation
        // Soqucoin stagenet Dilithium addresses use 'ssq1' prefix
        if strings.HasPrefix(address, "ssq1") && len(address) >= 42 {
                return true
        }
        if strings.HasPrefix(address, "sq1") && len(address) >= 42 {
                return true
        }
        // Also accept uppercase (ASICs sometimes uppercase addresses)
        upper := strings.ToUpper(address)
        if strings.HasPrefix(upper, "SSQ1") && len(address) >= 42 {
                return true
        }
        if strings.HasPrefix(upper, "SQ1") && len(address) >= 42 {
                return true
        }
        // Legacy testnet addresses start with n or 2 (for transition period)
        if (strings.HasPrefix(address, "n") || strings.HasPrefix(address, "2")) && len(address) >= 34 && len(address) <= 36 {
                return true
        }
        return false
}

func (Soqucoin) MinimumConfirmations() uint {
        // Mainnet coinbase maturity, raised 240 -> 288 on 2026-09-07 so that it
        // covers the finality horizon nMaxReorgDepth (bead
        // mainnet-maturity-240-not-30-mp5o). The prior value of 100 matched no
        // network on this chain: mainnet is 288 from height 1, testnet 240,
        // regtest 60, so 288 is conservative on the others rather than wrong.
        // No caller in this tool invokes it today; it is part of the Chain
        // interface (chain.go) and exists so the figure is not silently stale.
        return uint(288)
}
