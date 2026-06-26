package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
)

// KeyHierarchy holds only wrapped (ciphertext) key material.
// Plaintext never persists — DEK is unwrapped into memory during signing
// and zeroed immediately after; per-chain keys follow the same discipline.
type KeyHierarchy struct {
	KEKLabel    string            `json:"kek_label"`
	WrappedDEK  []byte            `json:"wrapped_dek"`  // AES-KW(KEK, DEK), KEK never leaves HSM
	WrappedKeys map[string][]byte `json:"wrapped_keys"` // chain → AES-GCM(DEK, privkey)
	// Chain keys stored:
	//   "eth"    → m/44'/60'/0'/0/0   secp256k1
	//   "gnosis" → m/44'/60'/0'/0/0   secp256k1 (same derivation, different chainID)
	//   "zec"    → m/44'/133'/0'/0/0  secp256k1
	//   "bls"    → m/12381/3600/0/0   BLS12-381 (validators)
}

// UnwrapSigningKey decrypts the per-chain private key using the DEK.
// Caller MUST call Wipe on the returned bytes immediately after use.
func (k *KeyHierarchy) UnwrapSigningKey(dek []byte, chain string) ([]byte, error) {
	wrapped, ok := k.WrappedKeys[chain]
	if !ok {
		return nil, fmt.Errorf("no key for chain %q", chain)
	}
	return aesGCMDecrypt(dek, wrapped)
}

// LoadKeyHierarchy reads and deserialises wrapped keys from path.
// The file is safe to store at rest — nothing here is plaintext.
func LoadKeyHierarchy(path string) (*KeyHierarchy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key hierarchy %s: %w", path, err)
	}
	var kh KeyHierarchy
	if err := json.Unmarshal(data, &kh); err != nil {
		return nil, fmt.Errorf("unmarshal key hierarchy: %w", err)
	}
	return &kh, nil
}

// AESGCMEncrypt encrypts plaintext under key (AES-256-GCM).
// Used by the keygen provisioning tool; not called at runtime.
func AESGCMEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func aesGCMDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	return gcm.Open(nil, nonce, ciphertext[gcm.NonceSize():], nil)
}

// UnwrapKey decrypts a single wrapped key using the DEK.
// Lower-level than UnwrapSigningKey — bypasses the chain-name map,
// useful when working with per-account WrappedKey fields directly.
func UnwrapKey(dek, wrappedKey []byte) ([]byte, error) {
	return aesGCMDecrypt(dek, wrappedKey)
}

// Wipe zeroes b and prevents the compiler from eliding the loop.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
