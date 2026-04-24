package directe2ee

import (
	"crypto/ecdh"
	"io"

	anp "github.com/agent-network-protocol/anp/golang"
	"golang.org/x/crypto/hkdf"
)

// InitialMaterial contains the symmetric material derived from P5 X3DH-like.
type InitialMaterial struct {
	InitialSecret [32]byte
	RootKey       [32]byte
	ChainKey      [32]byte
	SessionID     string
}

// DeriveInitialMaterialForInitiator derives session material for the initiator.
func DeriveInitialMaterialForInitiator(senderStaticPrivate *ecdh.PrivateKey, senderEphemeralPrivate *ecdh.PrivateKey, recipientStaticPublic [32]byte, recipientSignedPrekeyPublic [32]byte) (InitialMaterial, error) {
	return DeriveInitialMaterialForInitiatorWithOPK(senderStaticPrivate, senderEphemeralPrivate, recipientStaticPublic, recipientSignedPrekeyPublic, nil)
}

// DeriveInitialMaterialForInitiatorWithOPK derives session material with optional OPK DH4.
func DeriveInitialMaterialForInitiatorWithOPK(senderStaticPrivate *ecdh.PrivateKey, senderEphemeralPrivate *ecdh.PrivateKey, recipientStaticPublic [32]byte, recipientSignedPrekeyPublic [32]byte, recipientOneTimePrekeyPublic *[32]byte) (InitialMaterial, error) {
	recipientStatic, err := ecdh.X25519().NewPublicKey(recipientStaticPublic[:])
	if err != nil {
		return InitialMaterial{}, err
	}
	recipientSignedPrekey, err := ecdh.X25519().NewPublicKey(recipientSignedPrekeyPublic[:])
	if err != nil {
		return InitialMaterial{}, err
	}
	dh1, err := senderStaticPrivate.ECDH(recipientSignedPrekey)
	if err != nil {
		return InitialMaterial{}, err
	}
	dh2, err := senderEphemeralPrivate.ECDH(recipientStatic)
	if err != nil {
		return InitialMaterial{}, err
	}
	dh3, err := senderEphemeralPrivate.ECDH(recipientSignedPrekey)
	if err != nil {
		return InitialMaterial{}, err
	}
	chunks := [][]byte{dh1, dh2, dh3}
	if recipientOneTimePrekeyPublic != nil {
		recipientOPK, err := ecdh.X25519().NewPublicKey(recipientOneTimePrekeyPublic[:])
		if err != nil {
			return InitialMaterial{}, err
		}
		dh4, err := senderEphemeralPrivate.ECDH(recipientOPK)
		if err != nil {
			return InitialMaterial{}, err
		}
		chunks = append(chunks, dh4)
	}
	return deriveInitialMaterial(chunks...)
}

// DeriveInitialMaterialForResponder derives session material for the responder.
func DeriveInitialMaterialForResponder(recipientStaticPrivate *ecdh.PrivateKey, recipientSignedPrekeyPrivate *ecdh.PrivateKey, senderStaticPublic [32]byte, senderEphemeralPublic [32]byte) (InitialMaterial, error) {
	return DeriveInitialMaterialForResponderWithOPK(recipientStaticPrivate, recipientSignedPrekeyPrivate, nil, senderStaticPublic, senderEphemeralPublic)
}

// DeriveInitialMaterialForResponderWithOPK derives session material with optional OPK DH4.
func DeriveInitialMaterialForResponderWithOPK(recipientStaticPrivate *ecdh.PrivateKey, recipientSignedPrekeyPrivate *ecdh.PrivateKey, recipientOneTimePrekeyPrivate *ecdh.PrivateKey, senderStaticPublic [32]byte, senderEphemeralPublic [32]byte) (InitialMaterial, error) {
	senderStatic, err := ecdh.X25519().NewPublicKey(senderStaticPublic[:])
	if err != nil {
		return InitialMaterial{}, err
	}
	senderEphemeral, err := ecdh.X25519().NewPublicKey(senderEphemeralPublic[:])
	if err != nil {
		return InitialMaterial{}, err
	}
	dh1, err := recipientSignedPrekeyPrivate.ECDH(senderStatic)
	if err != nil {
		return InitialMaterial{}, err
	}
	dh2, err := recipientStaticPrivate.ECDH(senderEphemeral)
	if err != nil {
		return InitialMaterial{}, err
	}
	dh3, err := recipientSignedPrekeyPrivate.ECDH(senderEphemeral)
	if err != nil {
		return InitialMaterial{}, err
	}
	chunks := [][]byte{dh1, dh2, dh3}
	if recipientOneTimePrekeyPrivate != nil {
		dh4, err := recipientOneTimePrekeyPrivate.ECDH(senderEphemeral)
		if err != nil {
			return InitialMaterial{}, err
		}
		chunks = append(chunks, dh4)
	}
	return deriveInitialMaterial(chunks...)
}

func deriveInitialMaterial(chunks ...[]byte) (InitialMaterial, error) {
	ikm := []byte{}
	for _, chunk := range chunks {
		ikm = append(ikm, chunk...)
	}
	prk := hkdf.Extract(hashProvider, ikm, make([]byte, 32))
	initialSecretBytes, err := hkdfExpandOnly(prk, []byte("ANP Direct E2EE v1 Initial Secret"), 32)
	if err != nil {
		return InitialMaterial{}, err
	}
	var initialSecret [32]byte
	copy(initialSecret[:], initialSecretBytes)
	rootKeyBytes, err := hkdfExpandOnly(initialSecret[:], []byte("ANP Direct E2EE v1 Root Key"), 32)
	if err != nil {
		return InitialMaterial{}, err
	}
	chainBytes, err := hkdfExpandOnly(initialSecret[:], []byte("ANP Direct E2EE v1 Chain Key"), 32)
	if err != nil {
		return InitialMaterial{}, err
	}
	sessionIDBytes, err := hkdfExpandOnly(initialSecret[:], []byte("ANP Direct E2EE v1 Session ID"), 16)
	if err != nil {
		return InitialMaterial{}, err
	}
	var rootKey [32]byte
	var chainKey [32]byte
	copy(rootKey[:], rootKeyBytes)
	copy(chainKey[:], chainBytes)
	return InitialMaterial{InitialSecret: initialSecret, RootKey: rootKey, ChainKey: chainKey, SessionID: anp.EncodeBase64URL(sessionIDBytes)}, nil
}

func hkdfExpandOnly(secret []byte, info []byte, length int) ([]byte, error) {
	reader := hkdf.Expand(hashProvider, secret, info)
	buffer := make([]byte, length)
	if _, err := io.ReadFull(reader, buffer); err != nil {
		return nil, cryptoError("hkdf fill failed")
	}
	return buffer, nil
}
