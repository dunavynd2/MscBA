package bridge

import (
	"context"
	"fmt"
	"math/big"
	"sync"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"

	"acquire.io/infra/audit"
	"acquire.io/infra/signer"
)

// lockEventSig is the keccak256 of the Lock event signature from BridgeLock.sol.
// Lock(address indexed from, address indexed recipient, uint256 amount, uint64 nonce, uint256 destinationChainId)
var lockEventSig = crypto.Keccak256Hash([]byte("Lock(address,address,uint256,uint64,uint256)"))

// LockEvent is decoded from a BridgeLock.Lock log.
type LockEvent struct {
	TxHash             common.Hash
	From               common.Address
	Recipient          common.Address
	Amount             *big.Int
	LockNonce          uint64
	DestinationChainId uint64
}

// DestinationChain represents a target chain where tokens can be released.
type DestinationChain struct {
	ChainID      *big.Int
	ChainName    string
	RPC          string
	ReleaseAddr  common.Address
	Client       *ethclient.Client
}

// BridgeRelay subscribes to LockEvents on the source chain and submits
// BridgeRelease.release() calls on the appropriate destination chain.
type BridgeRelay struct {
	sourceClient *ethclient.Client
	
	// Map of destination chainID -> DestinationChain config
	destChains map[uint64]*DestinationChain
	
	sig   *signer.Signer
	audit *audit.Logger

	// BridgeLock.sol address on source chain
	lockAddr common.Address

	// Source chain ID
	sourceChainID uint64

	nonceMu       sync.Mutex
	pendingNonces map[string]uint64
}

func NewBridgeRelay(
	sourceRPC string,
	sourceChainID uint64,
	lockAddr common.Address,
	destChains map[uint64]*DestinationChain,
	s *signer.Signer,
	al *audit.Logger,
) (*BridgeRelay, error) {
	// Source chain RPC
	srcClient, err := ethclient.Dial(sourceRPC)
	if err != nil {
		return nil, fmt.Errorf("dial source rpc: %w", err)
	}

	// Connect to all destination chains
	for chainID, dest := range destChains {
		client, err := ethclient.Dial(dest.RPC)
		if err != nil {
			srcClient.Close()
			return nil, fmt.Errorf("dial destination rpc for chain %d: %w", chainID, err)
		}
		dest.Client = client
	}

	return &BridgeRelay{
		sourceClient:  srcClient,
		destChains:    destChains,
		sig:           s,
		audit:         al,
		lockAddr:      lockAddr,
		sourceChainID: sourceChainID,
		pendingNonces: make(map[string]uint64),
	}, nil
}

// Run subscribes to BridgeLock events and relays them until ctx is cancelled.
// sourceRPC must be a WebSocket endpoint (ws:// or wss://).
func (r *BridgeRelay) Run(ctx context.Context) error {
	query := ethereum.FilterQuery{
		Addresses: []common.Address{r.lockAddr},
		Topics:    [][]common.Hash{{lockEventSig}},
	}

	logs := make(chan ethtypes.Log, 32)
	sub, err := r.sourceClient.SubscribeFilterLogs(ctx, query, logs)
	if err != nil {
		return fmt.Errorf("subscribe lock events (ws endpoint required): %w", err)
	}
	defer sub.Unsubscribe()

	r.audit.Log(audit.Entry{Event: "relay_started"})

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-sub.Err():
			return fmt.Errorf("log subscription: %w", err)
		case vLog := <-logs:
			event, err := parseLockEvent(vLog, r.sourceChainID)
			if err != nil {
				r.audit.Log(audit.Entry{Event: "parse_lock_failed", Error: err.Error()})
				continue
			}
			if err := r.RelayLockEvent(ctx, event); err != nil {
				r.audit.Log(audit.Entry{
					Event:  "relay_failed",
					TxHash: event.TxHash.Hex(),
					Error:  err.Error(),
				})
			}
		}
	}
}

// RelayLockEvent verifies the lock is finalised on the source chain then
// broadcasts a release transaction on the appropriate destination chain.
func (r *BridgeRelay) RelayLockEvent(ctx context.Context, event *LockEvent) error {
	r.audit.Log(audit.Entry{
		Event:  "relay_lock_received",
		TxHash: event.TxHash.Hex(),
		From:   event.From.Hex(),
		To:     event.Recipient.Hex(),
		Value:  event.Amount.String(),
		Data:   fmt.Sprintf("destChainId=%d", event.DestinationChainId),
	})

	// Verify lock on source chain
	if err := r.verifyLock(ctx, event); err != nil {
		return fmt.Errorf("verify lock: %w", err)
	}

	// Get destination chain configuration
	destChain, ok := r.destChains[event.DestinationChainId]
	if !ok {
		return fmt.Errorf("destination chain %d not configured", event.DestinationChainId)
	}

	// Get next nonce for this destination chain
	nonce, err := r.nextNonce(ctx, destChain)
	if err != nil {
		return fmt.Errorf("get nonce for chain %d: %w", event.DestinationChainId, err)
	}

	// Encode release call with sourceChainId parameter
	data, err := encodeReleaseCall(
		event.Recipient,
		event.Amount,
		event.LockNonce,
		r.sourceChainID,
	)
	if err != nil {
		return fmt.Errorf("encode release call: %w", err)
	}

	tx := signer.BuildDynamicFeeTx(
		nonce,
		destChain.ReleaseAddr,
		big.NewInt(0),
		data,
		200_000, // Increased gas for 4-parameter release call
		big.NewInt(1e9), // 1 gwei tip
		big.NewInt(5e9), // 5 gwei max fee
		destChain.ChainID,
	)

	signed, err := r.sig.SignEthTx(tx, destChain.ChainName)
	if err != nil {
		return fmt.Errorf("sign release tx: %w", err)
	}

	if err := destChain.Client.SendTransaction(ctx, signed); err != nil {
		return fmt.Errorf("broadcast release tx to chain %d: %w", event.DestinationChainId, err)
	}

	r.audit.Log(audit.Entry{
		Event:  "relay_release_sent",
		Chain:  destChain.ChainName,
		TxHash: signed.Hash().Hex(),
		To:     event.Recipient.Hex(),
		Value:  event.Amount.String(),
		Data:   fmt.Sprintf("nonce=%d sourceChainId=%d", event.LockNonce, r.sourceChainID),
	})
	return nil
}

func (r *BridgeRelay) verifyLock(ctx context.Context, event *LockEvent) error {
	receipt, err := r.sourceClient.TransactionReceipt(ctx, event.TxHash)
	if err != nil {
		return fmt.Errorf("get receipt: %w", err)
	}
	if receipt.Status != ethtypes.ReceiptStatusSuccessful {
		return fmt.Errorf("lock tx reverted")
	}
	head, err := r.sourceClient.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("get head: %w", err)
	}
	const confirmations = 12
	if head < receipt.BlockNumber.Uint64()+confirmations {
		return fmt.Errorf("need %d confirmations, have %d",
			confirmations, head-receipt.BlockNumber.Uint64())
	}
	return nil
}

func (r *BridgeRelay) nextNonce(ctx context.Context, destChain *DestinationChain) (uint64, error) {
	r.nonceMu.Lock()
	defer r.nonceMu.Unlock()

	addr, err := r.sig.Address(destChain.ChainName)
	if err != nil {
		return 0, fmt.Errorf("derive signer address: %w", err)
	}

	onChain, err := destChain.Client.PendingNonceAt(ctx, addr)
	if err != nil {
		return 0, fmt.Errorf("pending nonce: %w", err)
	}

	// Never reuse a nonce: track locally submitted nonces against on-chain state
	chainKey := destChain.ChainName
	nonce := onChain
	if pending, ok := r.pendingNonces[chainKey]; ok && pending >= nonce {
		nonce = pending + 1
	}
	r.pendingNonces[chainKey] = nonce
	return nonce, nil
}

// parseLockEvent decodes a BridgeLock.Lock log.
// Solidity ABI encoding:
//   topic[0] = eventSig
//   topic[1] = from      (indexed address)
//   topic[2] = recipient (indexed address)
//   data[0:32]   = amount  (uint256)
//   data[32:64]  = nonce   (uint64 padded to 32 bytes)
//   data[64:96]  = destinationChainId (uint256)
func parseLockEvent(log ethtypes.Log, sourceChainID uint64) (*LockEvent, error) {
	if len(log.Topics) < 3 {
		return nil, fmt.Errorf("expected 3 topics, got %d", len(log.Topics))
	}
	if log.Topics[0] != lockEventSig {
		return nil, fmt.Errorf("unexpected event sig: %s", log.Topics[0].Hex())
	}
	if len(log.Data) < 96 {
		return nil, fmt.Errorf("log data too short: %d bytes (expected 96)", len(log.Data))
	}
	return &LockEvent{
		TxHash:             log.TxHash,
		From:               common.BytesToAddress(log.Topics[1].Bytes()),
		Recipient:          common.BytesToAddress(log.Topics[2].Bytes()),
		Amount:             new(big.Int).SetBytes(log.Data[:32]),
		LockNonce:          new(big.Int).SetBytes(log.Data[32:64]).Uint64(),
		DestinationChainId: new(big.Int).SetBytes(log.Data[64:96]).Uint64(),
	}, nil
}

// encodeReleaseCall hand-encodes release(address,uint256,uint64,uint256).
// Parameters: recipient (address), amount (uint256), lockNonce (uint64), sourceChainId (uint256)
func encodeReleaseCall(recipient common.Address, amount *big.Int, lockNonce uint64, sourceChainId uint64) ([]byte, error) {
	// keccak256("release(address,uint256,uint64,uint256)")[:4]
	sig := crypto.Keccak256([]byte("release(address,uint256,uint64,uint256)"))[:4]

	// ABI-encode: address (32 bytes), uint256 (32 bytes), uint64 (32 bytes), uint256 (32 bytes)
	enc := make([]byte, 4+32+32+32+32)
	copy(enc[0:4], sig)
	
	// recipient (address) - right-aligned in 32-byte slot
	copy(enc[16:36], recipient.Bytes())
	
	// amount (uint256)
	amount256 := make([]byte, 32)
	amount.FillBytes(amount256)
	copy(enc[36:68], amount256)
	
	// lockNonce (uint64 padded to 32 bytes)
	nonceBig := new(big.Int).SetUint64(lockNonce)
	nonce256 := make([]byte, 32)
	nonceBig.FillBytes(nonce256)
	copy(enc[68:100], nonce256)
	
	// sourceChainId (uint256)
	sourceBig := new(big.Int).SetUint64(sourceChainId)
	source256 := make([]byte, 32)
	sourceBig.FillBytes(source256)
	copy(enc[100:132], source256)
	
	return enc, nil
}

func (r *BridgeRelay) Close() {
	r.sourceClient.Close()
	for _, dest := range r.destChains {
		if dest.Client != nil {
			dest.Client.Close()
		}
	}
}
