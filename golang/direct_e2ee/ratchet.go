package directe2ee

import (
	"crypto/ecdh"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const MaxSkip uint32 = 1000

// ChainStep contains derived message material for a single ratchet step.
type ChainStep struct {
	MessageKey   [32]byte
	Nonce        [12]byte
	NextChainKey [32]byte
}

// RootStep contains root and chain material derived from a DH ratchet step.
type RootStep struct {
	RootKey  [32]byte
	ChainKey [32]byte
}

// DeriveChainStep implements P5 kdf_ck(CK) -> (CK', MK, NONCE).
func DeriveChainStep(chainKey [32]byte) ChainStep {
	prk := hkdf.Extract(hashProvider, chainKey[:], make([]byte, 32))
	out, err := hkdfExpandOnly(prk, []byte("ANP Direct E2EE v1 KDF_CK"), 76)
	if err != nil {
		panic(err)
	}
	var nextChainKey [32]byte
	var messageKey [32]byte
	var nonce [12]byte
	copy(nextChainKey[:], out[0:32])
	copy(messageKey[:], out[32:64])
	copy(nonce[:], out[64:76])
	return ChainStep{MessageKey: messageKey, Nonce: nonce, NextChainKey: nextChainKey}
}

// DeriveRootStep implements P5 kdf_rk(RK, dh_out) -> (RK', CK).
func DeriveRootStep(rootKey [32]byte, dhOut []byte) (RootStep, error) {
	prk := hkdf.Extract(hashProvider, dhOut, rootKey[:])
	out, err := hkdfExpandOnly(prk, []byte("ANP Direct E2EE v1 KDF_RK"), 64)
	if err != nil {
		return RootStep{}, err
	}
	var nextRoot [32]byte
	var chain [32]byte
	copy(nextRoot[:], out[0:32])
	copy(chain[:], out[32:64])
	return RootStep{RootKey: nextRoot, ChainKey: chain}, nil
}

func deriveRootStepFromKeys(rootKey [32]byte, privateKey *ecdh.PrivateKey, publicKey *ecdh.PublicKey) (RootStep, error) {
	dhOut, err := privateKey.ECDH(publicKey)
	if err != nil {
		return RootStep{}, err
	}
	return DeriveRootStep(rootKey, dhOut)
}

// EncryptWithStep encrypts plaintext with the derived step.
func EncryptWithStep(step ChainStep, plaintext []byte, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(step.MessageKey[:])
	if err != nil {
		return nil, cryptoError("invalid ChaCha20-Poly1305 key")
	}
	return aead.Seal(nil, step.Nonce[:], plaintext, aad), nil
}

// DecryptWithStep decrypts ciphertext with the derived step.
func DecryptWithStep(step ChainStep, ciphertext []byte, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(step.MessageKey[:])
	if err != nil {
		return nil, cryptoError("invalid ChaCha20-Poly1305 key")
	}
	plaintext, err := aead.Open(nil, step.Nonce[:], ciphertext, aad)
	if err != nil {
		return nil, cryptoError("failed to decrypt ciphertext")
	}
	return plaintext, nil
}
