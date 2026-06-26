package config

import (
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	// HSM
	HSMSlot  uint
	HSMPin   string
	KEKLabel string

	// Network
	SigningSubnet string
	TLSCert      string
	TLSKey       string
	ListenAddr   string

	// Chain
	ChainID      *big.Int
	PrivateNetID uint64
	RPCEndpoints []string

	// Per-chain registry (coin type defines derivation rules)
	Chains map[string]ChainConfig

	AuditLogPath string
}

type ChainConfig struct {
	ChainID   *big.Int
	DerivPath string // BIP44
	CoinType  uint32 // SLIP-0044
	RPCPort   int
	P2PPort   int
}

// DefaultChains returns the built-in BIP44 chain configurations.
// Returns a fresh map on each call so callers can safely mutate it.
func DefaultChains() map[string]ChainConfig {
	return map[string]ChainConfig{
		"eth": {
			ChainID:   big.NewInt(1),
			DerivPath: "m/44'/60'/0'/0/0",
			CoinType:  60,
			RPCPort:   8545,
			P2PPort:   30303,
		},
		"gnosis": {
			ChainID:   big.NewInt(100),
			DerivPath: "m/44'/60'/0'/0/0",
			CoinType:  60,
			RPCPort:   8545,
			P2PPort:   30303,
		},
		"zec": {
			ChainID:   big.NewInt(0),
			DerivPath: "m/44'/133'/0'/0/0",
			CoinType:  133,
			RPCPort:   8232,
			P2PPort:   8233,
		},
	}
}

func Load() (*Config, error) {
	slotStr := os.Getenv("HSM_SLOT")
	if slotStr == "" {
		return nil, fmt.Errorf("HSM_SLOT is required")
	}
	slot, err := strconv.ParseUint(slotStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("HSM_SLOT: %w", err)
	}

	pin := os.Getenv("HSM_PIN")
	if pin == "" {
		return nil, fmt.Errorf("HSM_PIN is required")
	}

	chainID, ok := new(big.Int).SetString(getEnvOrDefault("CHAIN_ID", "100"), 10)
	if !ok {
		return nil, fmt.Errorf("invalid CHAIN_ID")
	}

	privateNetID, err := strconv.ParseUint(getEnvOrDefault("PRIVATE_NET_ID", "8000"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("PRIVATE_NET_ID: %w", err)
	}

	cfg := &Config{
		HSMSlot:      uint(slot),
		HSMPin:       pin,
		KEKLabel:     getEnvOrDefault("KEK_LABEL", "acquire-kek-v1"),
		SigningSubnet: getEnvOrDefault("SIGNING_SUBNET", "172.22.0.0/24"),
		TLSCert:      os.Getenv("TLS_CERT"),
		TLSKey:       os.Getenv("TLS_KEY"),
		ListenAddr:   getEnvOrDefault("LISTEN_ADDR", "127.0.0.1:8443"),
		ChainID:      chainID,
		PrivateNetID: privateNetID,
		AuditLogPath: getEnvOrDefault("AUDIT_LOG", "/var/log/acquire/audit.jsonl"),
		Chains:       DefaultChains(),
	}

	if rpcURL := os.Getenv("RPC_URL"); rpcURL != "" {
		cfg.RPCEndpoints = strings.Split(rpcURL, ",")
	}

	return cfg, nil
}

func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
