package signer

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"acquire.io/infra/config"
)

// Signer wires HSM + KeyHierarchy to produce signed EIP-1559 transactions.
// Private key material is zeroed immediately after each signing operation.
type Signer struct {
	hsm  HSM
	keys *config.KeyHierarchy
	cfg  *config.Config
}

func New(hsm HSM, keys *config.KeyHierarchy, cfg *config.Config) *Signer {
	return &Signer{hsm: hsm, keys: keys, cfg: cfg}
}

// SignEthTx signs an EIP-1559 transaction for the named chain.
// Key material flows: HSM → DEK (in memory) → privkey (in memory) → signature.
// Both DEK and privkey are zeroed before returning.
func (s *Signer) SignEthTx(tx *types.Transaction, chain string) (*types.Transaction, error) {
	chainCfg, ok := s.cfg.Chains[chain]
	if !ok {
		return nil, fmt.Errorf("unknown chain: %q", chain)
	}

	// Layer 1: HSM unwraps DEK (KEK never leaves hardware)
	dek, err := s.hsm.UnwrapDEK(s.keys.KEKLabel, s.keys.WrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("unwrap dek: %w", err)
	}
	defer config.Wipe(dek)

	// Layer 2: DEK unwraps per-chain signing key
	privKeyBytes, err := s.keys.UnwrapSigningKey(dek, chain)
	if err != nil {
		return nil, fmt.Errorf("unwrap signing key [%s]: %w", chain, err)
	}
	defer config.Wipe(privKeyBytes)

	privKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ecdsa key: %w", err)
	}

	// EIP-1559 (London) signer scoped to chain ID
	ethSigner := types.NewLondonSigner(chainCfg.ChainID)
	signed, err := types.SignTx(tx, ethSigner, privKey)
	if err != nil {
		return nil, fmt.Errorf("sign tx: %w", err)
	}
	return signed, nil
}

// Address derives the Ethereum address for a chain's signing key without
// persisting the private key longer than the call stack.
func (s *Signer) Address(chain string) (common.Address, error) {
	dek, err := s.hsm.UnwrapDEK(s.keys.KEKLabel, s.keys.WrappedDEK)
	if err != nil {
		return common.Address{}, fmt.Errorf("unwrap dek: %w", err)
	}
	defer config.Wipe(dek)

	privKeyBytes, err := s.keys.UnwrapSigningKey(dek, chain)
	if err != nil {
		return common.Address{}, fmt.Errorf("unwrap signing key: %w", err)
	}
	defer config.Wipe(privKeyBytes)

	privKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(privKey.PublicKey), nil
}

// BuildDynamicFeeTx constructs an unsigned EIP-1559 transaction.
func BuildDynamicFeeTx(
	nonce uint64,
	to common.Address,
	value *big.Int,
	data []byte,
	gasLimit uint64,
	gasTipCap *big.Int,
	gasFeeCap *big.Int,
	chainID *big.Int,
) *types.Transaction {
	return types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		To:        &to,
		Value:     value,
		Data:      data,
		Gas:       gasLimit,
		GasTipCap: gasTipCap,
		GasFeeCap: gasFeeCap,
	})
}
