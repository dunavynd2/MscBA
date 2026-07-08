package main

import (
	"context"
	"log"
	"math/big"
	"os"
	"os/signal"
	"syscall"

	"github.com/ethereum/go-ethereum/common"

	"acquire.io/infra/audit"
	"acquire.io/infra/bridge"
	"acquire.io/infra/config"
	"acquire.io/infra/signer"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	al, err := audit.New(cfg.AuditLogPath)
	if err != nil {
		log.Fatalf("audit logger: %v", err)
	}
	defer al.Close()

	hsm, err := signer.NewPKCS11HSM(cfg.HSMSlot, cfg.HSMPin)
	if err != nil {
		log.Fatalf("hsm init: %v", err)
	}
	defer hsm.Close()

	keys, err := config.LoadKeyHierarchy("/keys/key_hierarchy.json")
	if err != nil {
		log.Fatalf("key hierarchy: %v", err)
	}

	s := signer.New(hsm, keys, cfg)

	// Contract addresses — injected via env in production
	lockAddr := common.HexToAddress(mustEnv("BRIDGE_LOCK_ADDR"))
	releaseAddr := common.HexToAddress(mustEnv("BRIDGE_RELEASE_ADDR"))

	sourceChainID, ok := new(big.Int).SetString(mustEnv("SOURCE_CHAIN_ID"), 10)
	if !ok {
		log.Fatalf("SOURCE_CHAIN_ID: invalid integer")
	}
	destChainID, ok := new(big.Int).SetString(mustEnv("DEST_CHAIN_ID"), 10)
	if !ok {
		log.Fatalf("DEST_CHAIN_ID: invalid integer")
	}

	// Both RPCs must be WebSocket endpoints for log subscriptions
	relay, err := bridge.NewBridgeRelay(
		mustEnv("SOURCE_RPC_URL"),
		mustEnv("DEST_RPC_URL"),
		lockAddr,
		releaseAddr,
		s,
		al,
		mustEnv("DEST_CHAIN_NAME"),
		sourceChainID,
		destChainID,
	)
	if err != nil {
		log.Fatalf("bridge relay: %v", err)
	}
	defer relay.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- relay.Run(ctx) }()

	log.Printf("relay running: private(%d) → gnosis(100)", cfg.PrivateNetID)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-quit:
		log.Println("shutting down relay")
		cancel()
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			log.Fatalf("relay error: %v", err)
		}
	}
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required env var %s is not set", key)
	}
	return v
}
