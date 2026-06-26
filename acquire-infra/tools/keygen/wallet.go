package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"acquire.io/infra/config"
)

// Wallet is the top-level entity stored as keys-dir/name.json.
// Nothing here is plaintext key material — WrappedDEK and per-account
// WrappedKey fields are all ciphertext.
type Wallet struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"created_at"`
	KEKLabel   string    `json:"kek_label"`
	WrappedDEK []byte    `json:"wrapped_dek"`  // AES-KW(KEK, DEK)
	Accounts   []Account `json:"accounts"`
}

// Account is one BIP44 key pair within a Wallet.
// Address is cached plaintext (public); WrappedKey is AES-GCM(DEK, privkey).
type Account struct {
	Index      uint32 `json:"index"`       // BIP44 account index
	Chain      string `json:"chain"`       // "eth", "gnosis", "zec"
	DerivPath  string `json:"deriv_path"`  // full BIP44 path
	Address    string `json:"address"`     // Ethereum-format hex address (0x...)
	WrappedKey []byte `json:"wrapped_key"` // AES-GCM(DEK, secp256k1 privkey)
}

func saveWallet(dir, name string, w *Wallet) error {
	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+".json"), data, 0600)
}

func loadWallet(dir, name string) (*Wallet, error) {
	data, err := os.ReadFile(filepath.Join(dir, name+".json"))
	if err != nil {
		return nil, err
	}
	var w Wallet
	return &w, json.Unmarshal(data, &w)
}

func listWalletNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, strings.TrimSuffix(e.Name(), ".json"))
		}
	}
	return names, nil
}

// generateDEK returns 32 cryptographically random bytes.
func generateDEK() ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	return dek, nil
}

// walletID returns a random 8-byte hex string for use as a wallet ID.
func walletID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// bip44Path builds m/44'/coinType'/accountIndex'/0/0.
func bip44Path(coinType, accountIndex uint32) string {
	return fmt.Sprintf("m/44'/%d'/%d'/0/0", coinType, accountIndex)
}

// deriveKey derives a secp256k1 private key from a BIP39 seed at the BIP44 path.
// Implements BIP-0032 child key derivation; supports hardened (') and normal segments.
func deriveKey(seed []byte, path string) ([]byte, error) {
	// Master key: HMAC-SHA512(Key="Bitcoin seed", Data=seed)
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed)
	I := mac.Sum(nil)

	key := make([]byte, 32)
	copy(key, I[:32])
	chainCode := make([]byte, 32)
	copy(chainCode, I[32:])

	n := crypto.S256().Params().N

	for _, seg := range strings.Split(strings.TrimPrefix(path, "m/"), "/") {
		hardened := strings.HasSuffix(seg, "'")
		idx, err := strconv.ParseUint(strings.TrimSuffix(seg, "'"), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid path segment %q: %w", seg, err)
		}
		index := uint32(idx)
		if hardened {
			index += 0x80000000
		}

		h := hmac.New(sha512.New, chainCode)
		if hardened {
			h.Write([]byte{0x00})
			h.Write(key)
		} else {
			priv, err := crypto.ToECDSA(key)
			if err != nil {
				return nil, fmt.Errorf("compress pubkey at %q: %w", seg, err)
			}
			h.Write(crypto.CompressPubkey(&priv.PublicKey))
		}
		var idxBuf [4]byte
		binary.BigEndian.PutUint32(idxBuf[:], index)
		h.Write(idxBuf[:])
		I := h.Sum(nil)

		IL := new(big.Int).SetBytes(I[:32])
		if IL.Cmp(n) >= 0 {
			return nil, fmt.Errorf("derived IL >= n at segment %q — try next index", seg)
		}
		child := new(big.Int).Mod(new(big.Int).Add(IL, new(big.Int).SetBytes(key)), n)
		if child.Sign() == 0 {
			return nil, fmt.Errorf("derived zero key at segment %q — try next index", seg)
		}

		key = make([]byte, 32)
		b := child.Bytes()
		copy(key[32-len(b):], b) // left-pad to 32 bytes
		chainCode = make([]byte, 32)
		copy(chainCode, I[32:])
	}

	out := make([]byte, 32)
	copy(out, key)
	return out, nil
}

// deriveAndWrapAccount derives the secp256k1 key at derivPath, computes the
// Ethereum address, wraps the key under dek, and returns a populated Account.
// privKey is zeroed before the function returns.
func deriveAndWrapAccount(seed, dek []byte, chainName, derivPath string, index uint32) (*Account, error) {
	privKey, err := deriveKey(seed, derivPath)
	if err != nil {
		return nil, fmt.Errorf("derive [%s] %s: %w", chainName, derivPath, err)
	}
	defer config.Wipe(privKey)

	ecKey, err := crypto.ToECDSA(privKey)
	if err != nil {
		return nil, fmt.Errorf("ecdsa parse [%s]: %w", chainName, err)
	}
	addr := crypto.PubkeyToAddress(ecKey.PublicKey)

	wrapped, err := config.AESGCMEncrypt(dek, privKey)
	if err != nil {
		return nil, fmt.Errorf("wrap key [%s]: %w", chainName, err)
	}

	return &Account{
		Index:      index,
		Chain:      chainName,
		DerivPath:  derivPath,
		Address:    addr.Hex(),
		WrappedKey: wrapped,
	}, nil
}
