package vm

import (
	"fmt"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/internal/base58util"
	"github.com/agent-network-protocol/anp/golang/internal/base64util"
)

// Error reports verification method parsing issues.
type Error struct {
	Message string
}

// Error implements error.
func (e *Error) Error() string {
	return e.Message
}

// VerificationMethod wraps parsed key material for signature helpers.
type VerificationMethod struct {
	ID         string
	MethodType string
	PublicKey  anp.PublicKeyMaterial
}

// VerifySignature verifies a base64url encoded signature.
func (v VerificationMethod) VerifySignature(content []byte, signature string) error {
	signatureBytes, err := base64util.DecodeURL(signature)
	if err != nil {
		return &Error{Message: "signature encoding error"}
	}
	if err := v.PublicKey.VerifyMessage(content, signatureBytes); err != nil {
		return &Error{Message: "signature encoding error"}
	}
	return nil
}

// EncodeSignature encodes signature bytes using base64url.
func (v VerificationMethod) EncodeSignature(signatureBytes []byte) (string, error) {
	if v.PublicKey.Type == anp.KeyTypeX25519 {
		return "", &Error{Message: fmt.Sprintf("unsupported verification method type: %s", v.MethodType)}
	}
	return base64util.EncodeURL(signatureBytes), nil
}

// CreateVerificationMethod parses a DID verification method.
func CreateVerificationMethod(method map[string]any) (VerificationMethod, error) {
	methodType, _ := method["type"].(string)
	if methodType == "" {
		return VerificationMethod{}, &Error{Message: "missing verification method type"}
	}
	publicKey, err := ExtractPublicKey(method)
	if err != nil {
		return VerificationMethod{}, err
	}
	id, _ := method["id"].(string)
	return VerificationMethod{ID: id, MethodType: methodType, PublicKey: publicKey}, nil
}

// ExtractPublicKey extracts public key material from a DID verification method.
func ExtractPublicKey(method map[string]any) (anp.PublicKeyMaterial, error) {
	methodType, _ := method["type"].(string)
	if methodType == "" {
		return anp.PublicKeyMaterial{}, &Error{Message: "missing verification method type"}
	}
	switch methodType {
	case "EcdsaSecp256k1VerificationKey2019":
		return extractECPublicKey(method, "secp256k1")
	case "EcdsaSecp256r1VerificationKey2019":
		return extractECPublicKey(method, "P-256")
	case "Ed25519VerificationKey2018", "Ed25519VerificationKey2020", "Multikey":
		return extractEd25519PublicKey(method)
	case "X25519KeyAgreementKey2019":
		return extractX25519PublicKey(method)
	case "JsonWebKey2020":
		jwk, ok := method["publicKeyJwk"].(map[string]any)
		if !ok {
			return anp.PublicKeyMaterial{}, &Error{Message: "missing key material"}
		}
		publicKey, err := anp.PublicKeyFromJWK(jwk)
		if err != nil {
			return anp.PublicKeyMaterial{}, &Error{Message: "invalid key material"}
		}
		return publicKey, nil
	default:
		return anp.PublicKeyMaterial{}, &Error{Message: fmt.Sprintf("unsupported verification method type: %s", methodType)}
	}
}

func extractECPublicKey(method map[string]any, expectedCurve string) (anp.PublicKeyMaterial, error) {
	if jwk, ok := method["publicKeyJwk"].(map[string]any); ok {
		publicKey, err := anp.PublicKeyFromJWK(jwk)
		if err != nil {
			return anp.PublicKeyMaterial{}, &Error{Message: "invalid key material"}
		}
		actualCurve := "P-256"
		if publicKey.Type == anp.KeyTypeSecp256k1 {
			actualCurve = "secp256k1"
		}
		if actualCurve != expectedCurve {
			return anp.PublicKeyMaterial{}, &Error{Message: "invalid key material"}
		}
		return publicKey, nil
	}
	if multibase, ok := method["publicKeyMultibase"].(string); ok && multibase != "" {
		decoded, err := base58util.Decode(stripMultibasePrefix(multibase))
		if err != nil {
			return anp.PublicKeyMaterial{}, &Error{Message: "invalid key material"}
		}
		keyType := anp.KeyTypeSecp256r1
		if expectedCurve == "secp256k1" {
			keyType = anp.KeyTypeSecp256k1
		}
		return anp.PublicKeyMaterial{Type: keyType, Bytes: decoded}, nil
	}
	return anp.PublicKeyMaterial{}, &Error{Message: "missing key material"}
}

func extractEd25519PublicKey(method map[string]any) (anp.PublicKeyMaterial, error) {
	if jwk, ok := method["publicKeyJwk"].(map[string]any); ok {
		publicKey, err := anp.PublicKeyFromJWK(jwk)
		if err != nil {
			return anp.PublicKeyMaterial{}, &Error{Message: "invalid key material"}
		}
		return publicKey, nil
	}
	if multibase, ok := method["publicKeyMultibase"].(string); ok && multibase != "" {
		decoded, err := base58util.Decode(stripMultibasePrefix(multibase))
		if err != nil {
			return anp.PublicKeyMaterial{}, &Error{Message: "invalid key material"}
		}
		if len(decoded) == 34 && decoded[0] == 0xed && decoded[1] == 0x01 {
			decoded = decoded[2:]
		}
		return anp.PublicKeyMaterial{Type: anp.KeyTypeEd25519, Bytes: decoded}, nil
	}
	if base58Value, ok := method["publicKeyBase58"].(string); ok && base58Value != "" {
		decoded, err := base58util.Decode(base58Value)
		if err != nil {
			return anp.PublicKeyMaterial{}, &Error{Message: "invalid key material"}
		}
		return anp.PublicKeyMaterial{Type: anp.KeyTypeEd25519, Bytes: decoded}, nil
	}
	return anp.PublicKeyMaterial{}, &Error{Message: "missing key material"}
}

func extractX25519PublicKey(method map[string]any) (anp.PublicKeyMaterial, error) {
	multibase, ok := method["publicKeyMultibase"].(string)
	if !ok || multibase == "" {
		return anp.PublicKeyMaterial{}, &Error{Message: "missing key material"}
	}
	decoded, err := base58util.Decode(stripMultibasePrefix(multibase))
	if err != nil {
		return anp.PublicKeyMaterial{}, &Error{Message: "invalid key material"}
	}
	if len(decoded) == 34 && decoded[0] == 0xec && decoded[1] == 0x01 {
		decoded = decoded[2:]
	}
	return anp.PublicKeyMaterial{Type: anp.KeyTypeX25519, Bytes: decoded}, nil
}

func stripMultibasePrefix(value string) string {
	if len(value) > 0 && value[0] == 'z' {
		return value[1:]
	}
	return value
}
