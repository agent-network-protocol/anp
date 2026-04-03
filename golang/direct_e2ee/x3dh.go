package directe2ee

import (
	"crypto/ecdh"
	"io"

	anp "github.com/agent-network-protocol/anp/golang"
	"golang.org/x/crypto/hkdf"
)

// InitialMaterial contains the symmetric material derived from X3DH.
type InitialMaterial struct {
	InitialSecret     [32]byte
	RootKey           [32]byte
	InitiatorChainKey [32]byte
	ResponderChainKey [32]byte
	SessionID         string
}

// DeriveInitialMaterialForInitiator derives session material for the initiator.
func DeriveInitialMaterialForInitiator(senderStaticPrivate *ecdh.PrivateKey, senderEphemeralPrivate *ecdh.PrivateKey, recipientStaticPublic [32]byte, recipientSignedPrekeyPublic [32]byte) (InitialMaterial, error) {
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
	return deriveInitialMaterial(dh1, dh2, dh3)
}

// DeriveInitialMaterialForResponder derives session material for the responder.
func DeriveInitialMaterialForResponder(recipientStaticPrivate *ecdh.PrivateKey, recipientSignedPrekeyPrivate *ecdh.PrivateKey, senderStaticPublic [32]byte, senderEphemeralPublic [32]byte) (InitialMaterial, error) {
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
	return deriveInitialMaterial(dh1, dh2, dh3)
}

// InitialSecretKeyAndNonce derives the init-message AEAD key and nonce.
func InitialSecretKeyAndNonce(initialSecret [32]byte) ([32]byte, [12]byte, error) {
	keyBytes, err := hkdfExpand(initialSecret[:], []byte("ANP Direct E2EE v1 Init AEAD Key"), 32)
	if err != nil {
		return [32]byte{}, [12]byte{}, err
	}
	nonceBytes, err := hkdfExpand(initialSecret[:], []byte("ANP Direct E2EE v1 Init AEAD Nonce"), 12)
	if err != nil {
		return [32]byte{}, [12]byte{}, err
	}
	var key [32]byte
	var nonce [12]byte
	copy(key[:], keyBytes)
	copy(nonce[:], nonceBytes)
	return key, nonce, nil
}

func deriveInitialMaterial(chunks ...[]byte) (InitialMaterial, error) {
	ikm := []byte{}
	for _, chunk := range chunks {
		ikm = append(ikm, chunk...)
	}
	initialSecretBytes, err := hkdfExpandFromIKM(ikm, []byte("ANP Direct E2EE v1 Initial Secret"), 32)
	if err != nil {
		return InitialMaterial{}, err
	}
	var initialSecret [32]byte
	copy(initialSecret[:], initialSecretBytes)
	rootKeyBytes, err := hkdfExpand(initialSecret[:], []byte("ANP Direct E2EE v1 Root Key"), 32)
	if err != nil {
		return InitialMaterial{}, err
	}
	initiatorChainBytes, err := hkdfExpand(initialSecret[:], []byte("ANP Direct E2EE v1 Initiator Chain Key"), 32)
	if err != nil {
		return InitialMaterial{}, err
	}
	responderChainBytes, err := hkdfExpand(initialSecret[:], []byte("ANP Direct E2EE v1 Responder Chain Key"), 32)
	if err != nil {
		return InitialMaterial{}, err
	}
	sessionIDBytes, err := hkdfExpand(initialSecret[:], []byte("ANP Direct E2EE v1 Session ID"), 16)
	if err != nil {
		return InitialMaterial{}, err
	}
	var rootKey [32]byte
	var initiatorChainKey [32]byte
	var responderChainKey [32]byte
	copy(rootKey[:], rootKeyBytes)
	copy(initiatorChainKey[:], initiatorChainBytes)
	copy(responderChainKey[:], responderChainBytes)
	return InitialMaterial{InitialSecret: initialSecret, RootKey: rootKey, InitiatorChainKey: initiatorChainKey, ResponderChainKey: responderChainKey, SessionID: anp.EncodeBase64URL(sessionIDBytes)}, nil
}

func hkdfExpandFromIKM(ikm []byte, info []byte, length int) ([]byte, error) {
	reader := hkdf.New(hashProvider, ikm, make([]byte, 32), info)
	buffer := make([]byte, length)
	if _, err := io.ReadFull(reader, buffer); err != nil {
		return nil, cryptoError("hkdf fill failed")
	}
	return buffer, nil
}

func hkdfExpand(secret []byte, info []byte, length int) ([]byte, error) {
	return hkdfExpandFromIKM(secret, info, length)
}
