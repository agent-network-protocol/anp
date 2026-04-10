package directe2ee

import (
	"crypto/ecdh"
	"fmt"
	"strings"
	"time"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/authentication"
	"github.com/agent-network-protocol/anp/golang/proof"
)

// SignedPrekeyFromPrivateKey builds signed prekey metadata from an X25519 private key.
func SignedPrekeyFromPrivateKey(keyID string, privateKey *ecdh.PrivateKey, expiresAt string) SignedPrekey {
	return SignedPrekey{KeyID: keyID, PublicKeyB64U: anp.EncodeBase64URL(privateKey.PublicKey().Bytes()), ExpiresAt: expiresAt}
}

// BuildPrekeyBundle signs and builds a prekey bundle.
func BuildPrekeyBundle(bundleID string, ownerDID string, staticKeyAgreementID string, signedPrekey SignedPrekey, signingPrivateKey anp.PrivateKeyMaterial, verificationMethod string, created string) (PrekeyBundle, error) {
	unsigned := map[string]any{"bundle_id": bundleID, "owner_did": ownerDID, "suite": MTIDirectE2EESuite, "static_key_agreement_id": staticKeyAgreementID, "signed_prekey": map[string]any{"key_id": signedPrekey.KeyID, "public_key_b64u": signedPrekey.PublicKeyB64U, "expires_at": signedPrekey.ExpiresAt}}
	signed, err := proof.GenerateObjectProof(unsigned, signingPrivateKey, verificationMethod, ownerDID, created)
	if err != nil {
		return PrekeyBundle{}, err
	}
	proofValue, ok := signed["proof"].(map[string]any)
	if !ok {
		return PrekeyBundle{}, missingField("proof")
	}
	return PrekeyBundle{BundleID: bundleID, OwnerDID: ownerDID, Suite: MTIDirectE2EESuite, StaticKeyAgreementID: staticKeyAgreementID, SignedPrekey: signedPrekey, Proof: proofValue}, nil
}

// VerifyPrekeyBundle verifies a prekey bundle against the owner's DID document.
func VerifyPrekeyBundle(bundle PrekeyBundle, didDocument map[string]any) error {
	if bundle.Suite != MTIDirectE2EESuite {
		return unsupportedSuite(bundle.Suite)
	}
	if stringValue(didDocument["id"]) != bundle.OwnerDID {
		return invalidField("owner_did must match the issuer DID document")
	}
	if strings.HasPrefix(bundle.OwnerDID, "did:wba:") && !authentication.ValidateDIDDocumentBinding(didDocument, false) {
		return invalidField("owner DID document binding validation failed")
	}
	keyAgreement, ok := didDocument["keyAgreement"].([]any)
	if !ok {
		return missingField("keyAgreement")
	}
	found := false
	for _, entry := range keyAgreement {
		if identifier, ok := entry.(string); ok && identifier == bundle.StaticKeyAgreementID {
			found = true
			break
		}
	}
	if !found {
		return invalidField("static_key_agreement_id must appear in did_document.keyAgreement")
	}
	if _, err := proof.VerifyObjectProof(bundleToMap(bundle), bundle.OwnerDID, didDocument); err != nil {
		return invalidField("bundle proof verification failed")
	}
	return nil
}

// ExtractX25519PublicKey extracts an X25519 public key from a DID document.
func ExtractX25519PublicKey(didDocument map[string]any, keyID string) ([32]byte, error) {
	method := authentication.FindVerificationMethod(didDocument, keyID)
	if method == nil {
		return [32]byte{}, invalidField("verification method not found: " + keyID)
	}
	publicKey, err := authentication.ExtractPublicKey(method)
	if err != nil {
		return [32]byte{}, invalidField(fmt.Sprintf("invalid verification method: %v", err))
	}
	if publicKey.Type != anp.KeyTypeX25519 || len(publicKey.Bytes) != 32 {
		return [32]byte{}, invalidField("verification method is not X25519: " + keyID)
	}
	var result [32]byte
	copy(result[:], publicKey.Bytes)
	return result, nil
}

func bundleToMap(bundle PrekeyBundle) map[string]any {
	return map[string]any{
		"bundle_id":               bundle.BundleID,
		"owner_did":               bundle.OwnerDID,
		"suite":                   bundle.Suite,
		"static_key_agreement_id": bundle.StaticKeyAgreementID,
		"signed_prekey":           map[string]any{"key_id": bundle.SignedPrekey.KeyID, "public_key_b64u": bundle.SignedPrekey.PublicKeyB64U, "expires_at": bundle.SignedPrekey.ExpiresAt},
		"proof":                   bundle.Proof,
	}
}

func defaultSignedPrekeyExpiry() string {
	return time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339)
}
