package directe2ee

import (
	"crypto/sha256"

	"golang.org/x/crypto/chacha20poly1305"
)

const MaxSkip uint32 = 1000

// ChainStep contains derived message material for a single ratchet step.
type ChainStep struct {
	MessageKey   [32]byte
	Nonce        [12]byte
	NextChainKey [32]byte
}

// DeriveChainStep derives message key, nonce, and next chain key.
func DeriveChainStep(chainKey [32]byte) ChainStep {
	nextChainKey := digestWithLabel(chainKey, []byte("ANP Direct E2EE v1 Next Chain Key"))
	messageKey := digestWithLabel(chainKey, []byte("ANP Direct E2EE v1 Message Key"))
	nonceMaterial := digestWithLabel(chainKey, []byte("ANP Direct E2EE v1 Message Nonce"))
	var nonce [12]byte
	copy(nonce[:], nonceMaterial[:12])
	return ChainStep{MessageKey: messageKey, Nonce: nonce, NextChainKey: nextChainKey}
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

func digestWithLabel(chainKey [32]byte, label []byte) [32]byte {
	hash := sha256.Sum256(append(append([]byte(nil), label...), chainKey[:]...))
	return hash
}
