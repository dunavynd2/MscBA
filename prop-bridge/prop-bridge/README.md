# prop-bridge — Acquire LLC Infrastructure

Cross-chain bridge relayer connecting private Geth node (Network ID 8000) to Ethereum Mainnet.

## Structure

```
prop-bridge/
├── contracts/
│   ├── BridgePrivate.sol     # Deployed on private network 8000
│   └── BridgeMainnet.sol     # Deployed on Ethereum Mainnet
├── docker/
│   ├── Dockerfile            # Custom Geth build (multi-stage, alpine)
│   └── docker-compose.yml    # Private node config (network 8000)
├── relayer/
│   └── main.go               # Go relay engine (WS + RPC bridge)
└── README.md
```

## Quickstart

### 1. Generate Go ABI Bindings

```bash
solc --abi --bin contracts/BridgePrivate.sol -o build/
abigen --bin=build/BridgePrivate.bin \
       --abi=build/BridgePrivate.abi \
       --pkg=bridge \
       --out=relayer/bindings/private_bridge.go
```

### 2. Boot Private Geth Node (Network 8000)

```bash
docker compose -f docker/docker-compose.yml up --build -d
```

### 3. Run the Relayer

```bash
cd relayer
go mod init acquire-bridge
go mod tidy
go run main.go
```

## Notes

- Replace YOUR_API_KEY in relayer/main.go with your Alchemy key
- --dev flag enables instant-seal engine: zero gas, sub-second blocks
- Port 8545 = HTTP JSON-RPC, 8546 = WebSocket (used by relayer)
- authorizedRelayer in BridgeMainnet.sol must match your HSM signing address
