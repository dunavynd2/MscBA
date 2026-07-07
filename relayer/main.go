package main

import (
    "context"
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/ethereum/go-ethereum/accounts/abi/bind"
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/ethclient"

    "acquire/bindings"
)

func main() {
    ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer cancel()

    rpcURL := os.Getenv("RPC_URL")
    if rpcURL == "" { rpcURL = "http://127.0.0.1:8545" }
    
    eth, err := ethclient.Dial(rpcURL)
    if err != nil { log.Fatalf("failed to connect to Geth: %v", err) }

    lockAddr := common.HexToAddress("0x80720fbb72812f0f33693016e343bd917d6a959e")
    lock, err := bindings.NewAcquireLock(lockAddr, eth)
    if err != nil { log.Fatalf("failed to bind AcquireLock: %v", err) }

    log.Printf("[relayer] Watching AcquireLock at %s", lockAddr.Hex())

    logs := make(chan *bindings.AcquireLockLocked)
    sub, err := lock.WatchLocked(&bind.WatchOpts{Context: ctx}, logs, nil, nil)
    if err != nil { log.Fatalf("failed to watch Locked events: %v", err) }
    defer sub.Unsubscribe()

    for {
        select {
        case event := <-logs:
            log.Printf("[relayer] EVENT Locked | from=%s dest=%s amount=%s nonce=%d",
                event.From.Hex(), event.Destination.Hex(), event.Amount.String(), event.Nonce)
        case err := <-sub.Err():
            log.Fatalf("subscription error: %v", err)
        case <-ctx.Done():
            return
        }
    }
}
