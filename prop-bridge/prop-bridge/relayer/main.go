package main

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/miekg/pkcs11"
)

const (
	localPrivateWS    = "ws://localhost:8546"
	mainnetRPC        = "https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY"
	privateBridgeAddr = "0xPRIVATE_BRIDGE_ADDRESS"
	mainnetBridgeAddr = "0xMAINNET_BRIDGE_ADDRESS"
	hsmModule         = "/usr/lib/softhsm/libsofthsm2.so"
	hsmTokenLabel     = "AcquireRootCA"
	hsmKeyLabel       = "AcquireRelayer"
)

// ABIs derived directly from BridgePrivate.sol and BridgeMainnet.sol.
const privateBridgeABIJSON = `[{
	"anonymous": false,
	"inputs": [
		{"indexed": true,  "name": "trader",            "type": "address"},
		{"indexed": true,  "name": "nonce",             "type": "uint256"},
		{"indexed": false, "name": "assetAmount",       "type": "uint256"},
		{"indexed": true,  "name": "destinationWallet", "type": "bytes32"}
	],
	"name": "StrategySettled",
	"type": "event"
}]`

const mainnetBridgeABIJSON = `[{
	"inputs": [
		{"name": "target",                 "type": "address"},
		{"name": "amount",                 "type": "uint256"},
		{"name": "nonce",                  "type": "uint256"},
		{"name": "cryptographicSignature", "type": "bytes"}
	],
	"name": "releaseMainnetFunds",
	"outputs": [],
	"stateMutability": "nonpayable",
	"type": "function"
}]`

// hsmSigner holds an open PKCS#11 session and the handles needed to sign.
type hsmSigner struct {
	p          *pkcs11.Ctx
	session    pkcs11.SessionHandle
	privHandle pkcs11.ObjectHandle
	address    common.Address
}

func newHSMSigner(pin string) (*hsmSigner, error) {
	p := pkcs11.New(hsmModule)
	if err := p.Initialize(); err != nil {
		return nil, fmt.Errorf("pkcs11 init: %w", err)
	}

	slots, err := p.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("get slots: %w", err)
	}

	var slot uint
	for _, s := range slots {
		info, err := p.GetTokenInfo(s)
		if err == nil && strings.TrimSpace(info.Label) == hsmTokenLabel {
			slot = s
			goto found
		}
	}
	return nil, fmt.Errorf("token '%s' not found in any slot", hsmTokenLabel)
found:

	session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("open session: %w", err)
	}
	if err := p.Login(session, pkcs11.CKU_USER, pin); err != nil {
		return nil, fmt.Errorf("hsm login: %w", err)
	}

	privHandle, err := findObject(p, session, pkcs11.CKO_PRIVATE_KEY, hsmKeyLabel)
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}
	pubHandle, err := findObject(p, session, pkcs11.CKO_PUBLIC_KEY, hsmKeyLabel)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}

	// CKA_EC_POINT is DER OCTET STRING wrapping the uncompressed secp256k1 point:
	// [04][41][04][x:32][y:32]  — skip the 3-byte DER+uncompressed header to get x||y.
	attrs, err := p.GetAttributeValue(session, pubHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil || len(attrs[0].Value) < 67 {
		return nil, fmt.Errorf("read EC point: %w", err)
	}
	xy := attrs[0].Value[3:] // skip 04 41 04 → 64 bytes: x || y
	addr := common.BytesToAddress(ethcrypto.Keccak256(xy)[12:])

	return &hsmSigner{p: p, session: session, privHandle: privHandle, address: addr}, nil
}

func findObject(p *pkcs11.Ctx, session pkcs11.SessionHandle, class uint, label string) (pkcs11.ObjectHandle, error) {
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	if err := p.FindObjectsInit(session, tmpl); err != nil {
		return 0, err
	}
	defer p.FindObjectsFinal(session)
	objs, _, err := p.FindObjects(session, 1)
	if err != nil || len(objs) == 0 {
		return 0, fmt.Errorf("object '%s' not found", label)
	}
	return objs[0], nil
}

// ethSign signs a 32-byte hash via CKM_ECDSA (raw), which returns [R(32)||S(32)].
// It brute-forces the 1-bit recovery ID V so the output is [R||S||V] as Ethereum expects.
func (h *hsmSigner) ethSign(hash []byte) ([]byte, error) {
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}
	if err := h.p.SignInit(h.session, mech, h.privHandle); err != nil {
		return nil, fmt.Errorf("sign init: %w", err)
	}
	rs, err := h.p.Sign(h.session, hash)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	if len(rs) != 64 {
		return nil, fmt.Errorf("unexpected sig length %d", len(rs))
	}
	for v := byte(0); v <= 1; v++ {
		candidate := append(append([]byte{}, rs...), v)
		recovered, err := ethcrypto.Ecrecover(hash, candidate)
		if err != nil {
			continue
		}
		if common.BytesToAddress(ethcrypto.Keccak256(recovered[1:])[12:]) == h.address {
			return candidate, nil
		}
	}
	return nil, fmt.Errorf("could not determine recovery ID")
}

func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func main() {
	ctx := context.Background()

	// --- HSM ---
	hsm, err := newHSMSigner(os.Getenv("HSM_USER_PIN"))
	if err != nil {
		log.Fatalf("HSM init: %v", err)
	}
	log.Printf("HSM relayer address: %s", hsm.address.Hex())
	log.Println("Set this address as authorizedRelayer in BridgeMainnet.sol before deployment.")

	// --- Transaction signing key (pays gas on mainnet) ---
	txKey, err := ethcrypto.HexToECDSA(os.Getenv("TX_PRIVATE_KEY"))
	if err != nil {
		log.Fatalf("TX_PRIVATE_KEY: %v", err)
	}

	// --- Clients ---
	privClient, err := ethclient.Dial(localPrivateWS)
	if err != nil {
		log.Fatalf("private WS: %v", err)
	}
	defer privClient.Close()

	mainnetClient, err := ethclient.Dial(mainnetRPC)
	if err != nil {
		log.Fatalf("mainnet RPC: %v", err)
	}
	defer mainnetClient.Close()

	// --- ABIs ---
	privateABI, err := abi.JSON(strings.NewReader(privateBridgeABIJSON))
	if err != nil {
		log.Fatalf("private ABI: %v", err)
	}
	mainnetABI, err := abi.JSON(strings.NewReader(mainnetBridgeABIJSON))
	if err != nil {
		log.Fatalf("mainnet ABI: %v", err)
	}

	// --- Subscribe to StrategySettled on Network 8000 ---
	query := ethereum.FilterQuery{
		Addresses: []common.Address{common.HexToAddress(privateBridgeAddr)},
		Topics:    [][]common.Hash{{privateABI.Events["StrategySettled"].ID}},
	}
	logsCh := make(chan types.Log)
	sub, err := privClient.SubscribeFilterLogs(ctx, query, logsCh)
	if err != nil {
		log.Fatalf("subscribe: %v", err)
	}
	log.Println("Prop-desk bridge active — listening for StrategySettled on Network 8000 ...")

	chainID, err := mainnetClient.ChainID(ctx)
	if err != nil {
		log.Fatalf("mainnet chainID: %v", err)
	}
	auth, err := bind.NewKeyedTransactorWithChainID(txKey, chainID)
	if err != nil {
		log.Fatalf("transactor: %v", err)
	}
	mainnetBridge := common.HexToAddress(mainnetBridgeAddr)

	for {
		select {
		case err := <-sub.Err():
			log.Fatalf("subscription: %v", err)

		case vLog := <-logsCh:
			// Indexed fields live in Topics (not Data).
			// Topics: [0]=event sig [1]=trader [2]=nonce [3]=destinationWallet
			nonce := new(big.Int).SetBytes(vLog.Topics[2].Bytes())
			// destinationWallet is the bank address left-padded to bytes32.
			target := common.BytesToAddress(vLog.Topics[3].Bytes()[12:])

			// Non-indexed: assetAmount is in Data.
			var eventData struct{ AssetAmount *big.Int }
			if err := privateABI.UnpackIntoInterface(&eventData, "StrategySettled", vLog.Data); err != nil {
				log.Printf("unpack event: %v", err)
				continue
			}
			amount := eventData.AssetAmount
			log.Printf("StrategySettled → target=%s amount=%s nonce=%s", target.Hex(), amount, nonce)

			// Build the payload hash that BridgeMainnet.sol verifies:
			// keccak256(abi.encodePacked(target, amount, nonce))
			packed := append(append(target.Bytes(), pad32(amount.Bytes())...), pad32(nonce.Bytes())...)
			msgHash := ethcrypto.Keccak256(packed)

			// Ethereum personal sign prefix (matches \x19Ethereum Signed Message:\n32 in BridgeMainnet)
			prefixed := ethcrypto.Keccak256(
				append([]byte("\x19Ethereum Signed Message:\n32"), msgHash...),
			)

			// Sign with HSM secp256k1 key — private key never leaves the token.
			sig, err := hsm.ethSign(prefixed)
			if err != nil {
				log.Printf("hsm sign: %v", err)
				continue
			}
			log.Printf("Payload signed: %x", sig)

			// Encode the call to releaseMainnetFunds(target, amount, nonce, sig).
			callData, err := mainnetABI.Pack("releaseMainnetFunds", target, amount, nonce, sig)
			if err != nil {
				log.Printf("abi pack: %v", err)
				continue
			}

			// Submit the settlement transaction to Ethereum Mainnet.
			pendingNonce, err := mainnetClient.PendingNonceAt(ctx, auth.From)
			if err != nil {
				log.Printf("pending nonce: %v", err)
				continue
			}
			gasPrice, err := mainnetClient.SuggestGasPrice(ctx)
			if err != nil {
				log.Printf("gas price: %v", err)
				continue
			}

			tx := types.NewTransaction(pendingNonce, mainnetBridge, big.NewInt(0), 200_000, gasPrice, callData)
			signed, err := auth.Signer(auth.From, tx)
			if err != nil {
				log.Printf("sign tx: %v", err)
				continue
			}
			if err := mainnetClient.SendTransaction(ctx, signed); err != nil {
				log.Printf("send tx: %v", err)
				continue
			}
			log.Printf("Settlement submitted: tx=%s target=%s amount=%s", signed.Hash().Hex(), target.Hex(), amount)
		}
	}
}
