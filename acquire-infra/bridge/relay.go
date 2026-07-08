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
	TxHash              common.Hash
	From                common.Address
	Recipient           common.Address
	Amount              *big.Int
	LockNonce           uint64
	DestinationChainId  *big.Int
}

// BridgeRelay subscribes to LockEvents on the source chain and submits
// BridgeRelease.release() calls on the destination chain.
type BridgeRelay struct {
	sourceClient *ethclient.Client
	destClient   *ethclient.Client
	sig          *signer.Signer
	audit        *audit.Logger

	// BridgeLock.sol address on source chain
	lockAddr common.Address
	// BridgeRelease.sol address on dest chain
	releaseAddr common.Address

	destChainID *big.Int
	destChain   string

	nonceMu       sync.Mutex
	pendingNonces map[string]uint64
}

func NewBridgeRelay(
	sourceRPC, destRPC string,
	lockAddr, releaseAddr common.Address,
	s *signer.Signer,
	al *audit.Logger,
	destChain string,
	destChainID *big.Int,
) (*BridgeRelay, error) {
	// Source chain requires a WebSocket RPC for log subscriptions
	srcClient, err := ethclient.Dial(sourceRPC)
	if err != nil {
		return nil, fmt.Errorf("dial source rpc: %w", err)
	}
	dstClient, err := ethclient.Dial(destRPC)
	if err != nil {
		srcClient.Close()
		return nil, fmt.Errorf("dial dest rpc: %w", err)
	}
	return &BridgeRelay{
		sourceClient:  srcClient,
		destClient:    dstClient,
		sig:           s,
		audit:         al,
		lockAddr:      lockAddr,
		releaseAddr:   releaseAddr,
		destChainID:   destChainID,
		destChain:     destChain,
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
			event, err := parseLockEvent(vLog)
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
// broadcasts a release transaction on the destination chain.
func (r *BridgeRelay) RelayLockEvent(ctx context.Context, event *LockEvent) error {
	r.audit.Log(audit.Entry{
		Event:  "relay_lock_received",
		Chain:  event.DestinationChainId.String(),
		TxHash: event.TxHash.Hex(),
		From:   event.From.Hex(),
		Value:  event.Amount.String(),
	})

	if event.DestinationChainId.Cmp(r.destChainID) != 0 {
		r.audit.Log(audit.Entry{
			Event: "relay_chain_mismatch",
			Chain: event.DestinationChainId.String(),
			Error: fmt.Sprintf("relay handles chain %s, got %s", r.destChainID, event.DestinationChainId),
		})
		return nil
	}

	if err := r.verifyLock(ctx, event); err != nil {
		return fmt.Errorf("verify lock: %w", err)
	}

	nonce, err := r.nextNonce(ctx)
	if err != nil {
		return fmt.Errorf("get nonce: %w", err)
	}

	// TODO: replace with abigen-generated BridgeRelease binding
	data, err := encodeReleaseCall(event.Recipient, event.Amount, event.LockNonce)
	if err != nil {
		return fmt.Errorf("encode release call: %w", err)
	}

	tx := signer.BuildDynamicFeeTx(
		nonce,
		r.releaseAddr,
		big.NewInt(0),
		data,
		120_000,
		big.NewInt(1e9), // 1 gwei tip
		big.NewInt(5e9), // 5 gwei max fee
		r.destChainID,
	)

	signed, err := r.sig.SignEthTx(tx, r.destChain)
	if err != nil {
		return fmt.Errorf("sign release tx: %w", err)
	}

	if err := r.destClient.SendTransaction(ctx, signed); err != nil {
		return fmt.Errorf("broadcast release tx: %w", err)
	}

	r.audit.Log(audit.Entry{
		Event:  "relay_release_sent",
		Chain:  r.destChain,
		TxHash: signed.Hash().Hex(),
		To:     event.Recipient.Hex(),
		Value:  event.Amount.String(),
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

func (r *BridgeRelay) nextNonce(ctx context.Context) (uint64, error) {
	r.nonceMu.Lock()
	defer r.nonceMu.Unlock()

	addr, err := r.sig.Address(r.destChain)
	if err != nil {
		return 0, fmt.Errorf("derive signer address: %w", err)
	}

	onChain, err := r.destClient.PendingNonceAt(ctx, addr)
	if err != nil {
		return 0, fmt.Errorf("pending nonce: %w", err)
	}

	// Never reuse a nonce: track locally submitted nonces against on-chain state
	nonce := onChain
	if pending, ok := r.pendingNonces[r.destChain]; ok && pending >= nonce {
		nonce = pending + 1
	}
	r.pendingNonces[r.destChain] = nonce
	return nonce, nil
}

// parseLockEvent decodes a BridgeLock.Lock log.
// Solidity ABI encoding:
//   topic[0] = eventSig
//   topic[1] = from               (indexed address)
//   topic[2] = recipient          (indexed address)
//   data[0:32]  = amount          (uint256)
//   data[32:64] = nonce           (uint64 padded to 32 bytes)
//   data[64:96] = destinationChainId (uint256)
func parseLockEvent(log ethtypes.Log) (*LockEvent, error) {
	if len(log.Topics) < 3 {
		return nil, fmt.Errorf("expected 3 topics, got %d", len(log.Topics))
	}
	if log.Topics[0] != lockEventSig {
		return nil, fmt.Errorf("unexpected event sig: %s", log.Topics[0].Hex())
	}
	if len(log.Data) < 96 {
		return nil, fmt.Errorf("log data too short: %d bytes", len(log.Data))
	}
	return &LockEvent{
		TxHash:             log.TxHash,
		From:               common.BytesToAddress(log.Topics[1].Bytes()),
		Recipient:          common.BytesToAddress(log.Topics[2].Bytes()),
		Amount:             new(big.Int).SetBytes(log.Data[:32]),
		LockNonce:          new(big.Int).SetBytes(log.Data[32:64]).Uint64(),
		DestinationChainId: new(big.Int).SetBytes(log.Data[64:96]),
	}, nil
}

// encodeReleaseCall hand-encodes release(address,uint256,uint64).
// Replace this with abigen output once BridgeRelease ABI is available.
func encodeReleaseCall(recipient common.Address, amount *big.Int, lockNonce uint64) ([]byte, error) {
	// keccak256("release(address,uint256,uint64)")[:4]
	sig := crypto.Keccak256([]byte("release(address,uint256,uint64)"))[:4]

	// ABI-encode: address (32 bytes, left-padded), uint256 (32 bytes), uint64 (32 bytes)
	enc := make([]byte, 4+32+32+32)
	copy(enc[0:4], sig)
	copy(enc[16:36], recipient.Bytes()) // right-align address in 32-byte slot
	amount256 := make([]byte, 32)
	amount.FillBytes(amount256)
	copy(enc[36:68], amount256)
	nonceBig := new(big.Int).SetUint64(lockNonce)
	nonce256 := make([]byte, 32)
	nonceBig.FillBytes(nonce256)
	copy(enc[68:100], nonce256)
	return enc, nil
}

func (r *BridgeRelay) Close() {
	r.sourceClient.Close()
	r.destClient.Close()
}
