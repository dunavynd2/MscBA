# Geth Console — Bridge Setup & Interaction Guide

The private Geth node (Network ID 8000) exposes:
- **HTTP JSON-RPC** → `http://localhost:8545`
- **WebSocket** → `ws://localhost:8546`

---

## Step 1 — Boot the Private Node

```bash
docker compose -f docker/docker-compose.yml up --build -d
```

The `--dev` flag in `docker-compose.yml` automatically:
- Creates a pre-funded coinbase account (infinite ETH, no gas cost)
- Seals blocks instantly on each transaction (no miner needed)
- Sets Network ID 8000 via `--networkid=8000`

---

## Step 2 — Attach the Console

```bash
# From inside the running container
docker exec -it keen_goldstine geth attach http://localhost:8545
```

You'll land at the `>` JavaScript prompt.

---

## Step 3 — Create & Verify Accounts

The `--dev` coinbase is auto-created, but you can create additional named accounts:

```js
// See the auto-created dev account
eth.accounts
// → ["0xabc..."]

// Create a new account (set a password or leave empty for dev)
personal.newAccount("")
// → "0xNEW_ADDRESS"

// Confirm both accounts exist
eth.accounts
// → ["0xabc...", "0xNEW_ADDRESS"]

// Check dev account balance
web3.fromWei(eth.getBalance(eth.accounts[0]), 'ether')
// → very large number (dev mode pre-fund)

// Fund a secondary account from dev coinbase
eth.sendTransaction({
  from: eth.accounts[0],
  to: eth.accounts[1],
  value: web3.toWei(10, 'ether'),
  gas: 21000
});
```

> Unlock an account if you see `authentication needed`:
> ```js
> personal.unlockAccount(eth.accounts[0], "", 0)  // empty password, indefinite
> ```

---

## Step 4 — Confirm Network Partition (ID 8000)

```js
net.version        // → "8000"
net.peerCount      // → 0  (nodiscover = fully isolated)
eth.blockNumber    // → current block
```

A peer count of `0` is expected — `--nodiscover` keeps this network air-gapped from any public chain.

---

## Step 5 — Deploy BridgePrivate on Network 8000

ABI and bytecode come from compiling `contracts/BridgePrivate.sol`.

### Compile (run from project root, outside container)
```bash
solc --abi --bin contracts/BridgePrivate.sol -o build/
```
This writes `build/BridgePrivate.abi` and `build/BridgePrivate.bin`.

### Deploy via console

The ABI below matches `BridgePrivate.sol` exactly — no lookup needed:

```js
var privateABI = [
  {
    "inputs": [],
    "stateMutability": "nonpayable",
    "type": "constructor"
  },
  {
    "anonymous": false,
    "inputs": [
      { "indexed": true,  "name": "trader",            "type": "address" },
      { "indexed": true,  "name": "nonce",             "type": "uint256" },
      { "indexed": false, "name": "assetAmount",       "type": "uint256" },
      { "indexed": true,  "name": "destinationWallet", "type": "bytes32" }
    ],
    "name": "StrategySettled",
    "type": "event"
  },
  {
    "inputs": [],
    "name": "deskAdmin",
    "outputs": [{ "name": "", "type": "address" }],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "sequenceNonce",
    "outputs": [{ "name": "", "type": "uint256" }],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      { "name": "amount",            "type": "uint256" },
      { "name": "destinationWallet", "type": "bytes32" }
    ],
    "name": "lockAssets",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  }
];

// Paste the hex from build/BridgePrivate.bin here
var privateBytecode = "0x...";

var BridgePrivate = eth.contract(privateABI);
var privateDeployed = BridgePrivate.new({
  from: eth.accounts[0],
  data: privateBytecode,
  gas: 1000000
});

privateDeployed.address   // save this — needed for the relayer and console calls below
```

---

## Step 6 — Interact with BridgePrivate

```js
var bridgeAddr = "0xYOUR_DEPLOYED_ADDRESS";
var bridge = eth.contract(privateABI).at(bridgeAddr);

// Read state
bridge.deskAdmin()       // → deployer address (eth.accounts[0])
bridge.sequenceNonce()   // → 0 before any lockAssets call

// Lock assets (triggers StrategySettled event, which the relayer picks up)
// destinationWallet = bytes32 hex of the mainnet recipient address
var dest = "0x" + "MAINNET_WALLET_ADDRESS_WITHOUT_0x".padStart(64, '0');

bridge.lockAssets(
  web3.toWei(1, 'ether'),
  dest,
  { from: eth.accounts[0], gas: 200000 }
);

bridge.sequenceNonce()   // → 1 after the call

// Read past StrategySettled events
bridge.StrategySettled({}, { fromBlock: 0, toBlock: 'latest' }).get(
  function(err, logs) { console.log(JSON.stringify(logs, null, 2)); }
);
```

---

## Step 7 — Fund BridgeMainnet Before Any Release

The `BridgeMainnet` contract must hold ETH **before** any `releaseMainnetFunds` call or it will revert.
Send ETH directly to the contract address after deployment:

```bash
# From any funded Ethereum wallet / Hardhat script
eth.sendTransaction({
  from: "0xYOUR_FUNDED_WALLET",
  to:   "0xMAINNET_CONTRACT_ADDRESS",
  value: web3.toWei(10, 'ether')   # must cover all expected release amounts
});
```

Verify the balance:
```js
web3.fromWei(eth.getBalance("0xMAINNET_CONTRACT_ADDRESS"), 'ether')
```

> Every `releaseMainnetFunds` call transfers ETH from the contract to `target`. If the contract balance drops below the release amount, the `payable(target).transfer(amount)` will revert.

---

## Step 8 — BridgeMainnet Reference (Ethereum Mainnet)

`BridgeMainnet.sol` is deployed on Ethereum Mainnet and called by the relayer.
You interact with it through Alchemy, not the private node.

```bash
geth attach https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY
```

ABI derived from `contracts/BridgeMainnet.sol`:

```js
var mainnetABI = [
  {
    "inputs": [{ "name": "_authorizedRelayer", "type": "address" }],
    "stateMutability": "nonpayable",
    "type": "constructor"
  },
  {
    "anonymous": false,
    "inputs": [
      { "indexed": true,  "name": "target",      "type": "address" },
      { "indexed": false, "name": "assetAmount", "type": "uint256" }
    ],
    "name": "SettlementExecuted",
    "type": "event"
  },
  {
    "inputs": [],
    "name": "authorizedRelayer",
    "outputs": [{ "name": "", "type": "address" }],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [{ "name": "", "type": "uint256" }],
    "name": "processedNonces",
    "outputs": [{ "name": "", "type": "bool" }],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [
      { "name": "target",                  "type": "address" },
      { "name": "amount",                  "type": "uint256" },
      { "name": "nonce",                   "type": "uint256" },
      { "name": "cryptographicSignature",  "type": "bytes"   }
    ],
    "name": "releaseMainnetFunds",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  { "stateMutability": "payable", "type": "receive" }
];

var mainnetBridge = eth.contract(mainnetABI).at("0xMAINNET_CONTRACT_ADDRESS");

// Check the authorized relayer (must match HSM signing address used in relayer/main.go)
mainnetBridge.authorizedRelayer()

// Check if a nonce was already settled (replay protection)
mainnetBridge.processedNonces(1)   // → true if nonce 1 already cleared
```

---

## Relayer Startup Sequence

### Prerequisites
- SoftHSM2 token initialized with label `AcquireRootCA` (see `instruction.md` §2)
- secp256k1 key pair generated with label `AcquireRelayer`, id `02` (see `instruction.md` §3.1)
- `BridgePrivate` deployed on Network 8000 — note the address
- `BridgeMainnet` deployed on Ethereum Mainnet with the HSM-derived address as `authorizedRelayer` — note the address

### 1. Set constants in `relayer/main.go`

```go
mainnetRPC        = "https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY"
privateBridgeAddr = "0xYOUR_PRIVATE_BRIDGE_ADDRESS"
mainnetBridgeAddr = "0xYOUR_MAINNET_BRIDGE_ADDRESS"
```

### 2. Export environment variables

```bash
export HSM_USER_PIN="your-softhsm-user-pin"
export TX_PRIVATE_KEY="hex-private-key-of-funded-mainnet-account"
```

`TX_PRIVATE_KEY` pays gas for the `releaseMainnetFunds` transaction on Mainnet. The HSM key signs the *payload* — the private key never leaves the token.

### 3. Install dependencies and run

```bash
cd relayer
go mod tidy
go run main.go
```

**Expected startup output:**
```
HSM relayer address: 0xABC...123
Set this address as authorizedRelayer in BridgeMainnet.sol before deployment.
Prop-desk bridge active — listening for StrategySettled on Network 8000 ...
```

### 4. Trigger a settlement (from the Geth console)

```js
// Lock assets on Network 8000 — destinationWallet = bank's mainnet address, left-padded to bytes32
var bankAddr = "BANK_MAINNET_ADDRESS_WITHOUT_0x";
var dest = "0x" + bankAddr.padStart(64, '0');

bridge.lockAssets(
  web3.toWei(1, 'ether'),
  dest,
  { from: eth.accounts[0], gas: 200000 }
);
```

The relayer picks up the `StrategySettled` event, signs the payload with the HSM secp256k1 key, and submits `releaseMainnetFunds` to Mainnet. Watch the relayer log for:

```
StrategySettled → target=0xBANK... amount=1000000000000000000 nonce=1
Payload signed: <65-byte hex sig>
Settlement submitted: tx=0xTXHASH target=0xBANK... amount=1000000000000000000
```
