package proof

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/internal/base58util"
	"github.com/agent-network-protocol/anp/golang/internal/cjson"
	"github.com/agent-network-protocol/anp/golang/internal/diddoc"
	"github.com/agent-network-protocol/anp/golang/internal/vm"
)

const (
	ObjectProofPurpose                  = "assertionMethod"
	ObjectProofSignatureMultibasePrefix = "z"
)

var ObjectProofRequiredFields = []string{
	"type",
	"cryptosuite",
	"verificationMethod",
	"proofPurpose",
	"created",
	"proofValue",
}

// ObjectProofVerificationResult captures successful Appendix-B proof verification output.
type ObjectProofVerificationResult struct {
	IssuerDID            string         `json:"issuer_did"`
	VerificationMethodID string         `json:"verification_method_id"`
	VerificationMethod   map[string]any `json:"verification_method"`
}

// GenerateObjectProof signs a strict Appendix-B object proof.
func GenerateObjectProof(document map[string]any, privateKey anp.PrivateKeyMaterial, verificationMethod string, issuerDID string, created string) (map[string]any, error) {
	if privateKey.Type != anp.KeyTypeEd25519 {
		return nil, &Error{Message: "Appendix-B object proof requires an Ed25519 private key"}
	}
	if err := ensureVerificationMethodMatchesIssuer(verificationMethod, issuerDID); err != nil {
		return nil, err
	}
	createdValue, err := normalizeRFC3339(created)
	if err != nil {
		return nil, err
	}
	proofObject := map[string]any{
		"type":               ProofTypeDataIntegrity,
		"cryptosuite":        CryptosuiteEddsaJCS2022,
		"verificationMethod": verificationMethod,
		"proofPurpose":       ObjectProofPurpose,
		"created":            createdValue,
	}
	unsigned := cloneMap(document)
	delete(unsigned, "proof")
	signingInput, err := computeSigningInput(unsigned, proofObject)
	if err != nil {
		return nil, err
	}
	signature, err := privateKey.SignMessage(signingInput)
	if err != nil {
		return nil, &Error{Message: "signing error"}
	}
	proofObject["proofValue"] = encodeObjectProofSignature(signature)
	signed := cloneMap(document)
	signed["proof"] = proofObject
	return signed, nil
}

// VerifyObjectProof verifies a strict Appendix-B object proof against the issuer DID document.
func VerifyObjectProof(document map[string]any, issuerDID string, issuerDocument map[string]any) (ObjectProofVerificationResult, error) {
	if stringValue(issuerDocument["id"]) != issuerDID {
		return ObjectProofVerificationResult{}, &Error{Message: "issuer DID document id does not match issuer DID"}
	}
	if strings.HasPrefix(issuerDID, "did:wba:") && !validateDidDocumentBindingForObjectProof(issuerDocument) {
		return ObjectProofVerificationResult{}, &Error{Message: "issuer DID document binding validation failed"}
	}
	proofValue, ok := document["proof"].(map[string]any)
	if !ok {
		return ObjectProofVerificationResult{}, &Error{Message: "missing proof object"}
	}
	for _, field := range ObjectProofRequiredFields {
		value, _ := proofValue[field].(string)
		if value == "" {
			return ObjectProofVerificationResult{}, &Error{Message: fmt.Sprintf("missing proof field: %s", field)}
		}
	}
	if stringValue(proofValue["type"]) != ProofTypeDataIntegrity {
		return ObjectProofVerificationResult{}, &Error{Message: "invalid proof field: type"}
	}
	if stringValue(proofValue["cryptosuite"]) != CryptosuiteEddsaJCS2022 {
		return ObjectProofVerificationResult{}, &Error{Message: "invalid proof field: cryptosuite"}
	}
	if stringValue(proofValue["proofPurpose"]) != ObjectProofPurpose {
		return ObjectProofVerificationResult{}, &Error{Message: "invalid proof field: proofPurpose"}
	}
	verificationMethodID := stringValue(proofValue["verificationMethod"])
	if err := ensureVerificationMethodMatchesIssuer(verificationMethodID, issuerDID); err != nil {
		return ObjectProofVerificationResult{}, err
	}
	if _, err := parseRFC3339String(stringValue(proofValue["created"])); err != nil {
		return ObjectProofVerificationResult{}, err
	}
	if !diddoc.IsAssertionMethodAuthorized(issuerDocument, verificationMethodID) {
		return ObjectProofVerificationResult{}, &Error{Message: "verification method is not authorized for assertionMethod"}
	}
	method := diddoc.FindVerificationMethod(issuerDocument, verificationMethodID)
	if method == nil {
		return ObjectProofVerificationResult{}, &Error{Message: "verification method not found in DID document"}
	}
	parsedMethod, err := vm.CreateVerificationMethod(method)
	if err != nil {
		return ObjectProofVerificationResult{}, &Error{Message: "invalid verification method"}
	}
	if parsedMethod.PublicKey.Type != anp.KeyTypeEd25519 {
		return ObjectProofVerificationResult{}, &Error{Message: "Appendix-B object proof requires an Ed25519 verification method"}
	}
	unsigned := cloneMap(document)
	delete(unsigned, "proof")
	proofOptions := cloneMap(proofValue)
	delete(proofOptions, "proofValue")
	signingInput, err := computeSigningInput(unsigned, proofOptions)
	if err != nil {
		return ObjectProofVerificationResult{}, err
	}
	signature, err := decodeObjectProofSignature(stringValue(proofValue["proofValue"]))
	if err != nil {
		return ObjectProofVerificationResult{}, err
	}
	if err := parsedMethod.PublicKey.VerifyMessage(signingInput, signature); err != nil {
		return ObjectProofVerificationResult{}, &Error{Message: "verification failed"}
	}
	return ObjectProofVerificationResult{IssuerDID: issuerDID, VerificationMethodID: verificationMethodID, VerificationMethod: cloneMap(method)}, nil
}

func ensureVerificationMethodMatchesIssuer(verificationMethod string, issuerDID string) error {
	did, err := didFromVerificationMethod(verificationMethod)
	if err != nil {
		return err
	}
	if did != issuerDID {
		return &Error{Message: "verification method DID does not match issuer DID"}
	}
	return nil
}

func didFromVerificationMethod(verificationMethod string) (string, error) {
	did, fragment, ok := strings.Cut(verificationMethod, "#")
	if !ok || did == "" || fragment == "" || !strings.HasPrefix(did, "did:") {
		return "", &Error{Message: "verification method must be a full DID URL"}
	}
	return did, nil
}

func normalizeRFC3339(value string) (string, error) {
	if value == "" {
		return time.Now().UTC().Format(time.RFC3339), nil
	}
	if _, err := parseRFC3339String(value); err != nil {
		return "", err
	}
	return value, nil
}

func parseRFC3339String(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, &Error{Message: fmt.Sprintf("invalid RFC3339 timestamp: %s", value)}
	}
	return parsed, nil
}

func encodeObjectProofSignature(signature []byte) string {
	return ObjectProofSignatureMultibasePrefix + base58util.Encode(signature)
}

func decodeObjectProofSignature(value string) ([]byte, error) {
	if !strings.HasPrefix(value, ObjectProofSignatureMultibasePrefix) {
		return nil, &Error{Message: "invalid proof value encoding"}
	}
	signature, err := base58util.Decode(strings.TrimPrefix(value, ObjectProofSignatureMultibasePrefix))
	if err != nil {
		return nil, &Error{Message: "invalid proof value encoding"}
	}
	if len(signature) != 64 {
		return nil, &Error{Message: "invalid proof value encoding"}
	}
	return signature, nil
}

func validateDidDocumentBindingForObjectProof(didDocument map[string]any) bool {
	did := stringValue(didDocument["id"])
	if did == "" {
		return false
	}
	lastSeparator := strings.LastIndex(did, ":")
	lastSegment := did
	if lastSeparator >= 0 {
		lastSegment = did[lastSeparator+1:]
	}
	if strings.HasPrefix(lastSegment, "e1_") {
		return validateE1BindingForObjectProof(didDocument, strings.TrimPrefix(lastSegment, "e1_"))
	}
	return true
}

func validateE1BindingForObjectProof(didDocument map[string]any, expectedFingerprint string) bool {
	proofValue, ok := didDocument["proof"].(map[string]any)
	if !ok {
		return false
	}
	if stringValue(proofValue["type"]) != ProofTypeDataIntegrity || stringValue(proofValue["cryptosuite"]) != CryptosuiteEddsaJCS2022 {
		return false
	}
	verificationMethodID := stringValue(proofValue["verificationMethod"])
	if !diddoc.IsAssertionMethodAuthorized(didDocument, verificationMethodID) {
		return false
	}
	method := diddoc.FindVerificationMethod(didDocument, verificationMethodID)
	if method == nil {
		return false
	}
	parsedMethod, err := vm.CreateVerificationMethod(method)
	if err != nil || parsedMethod.PublicKey.Type != anp.KeyTypeEd25519 {
		return false
	}
	fingerprint, err := computeMultikeyFingerprintForObjectProof(parsedMethod.PublicKey)
	if err != nil || fingerprint != expectedFingerprint {
		return false
	}
	return VerifyW3CProof(didDocument, parsedMethod.PublicKey, VerificationOptions{ExpectedPurpose: ObjectProofPurpose})
}

func computeMultikeyFingerprintForObjectProof(publicKey anp.PublicKeyMaterial) (string, error) {
	if publicKey.Type != anp.KeyTypeEd25519 {
		return "", &Error{Message: "invalid key material"}
	}
	jwk := map[string]any{
		"crv": "Ed25519",
		"kty": "OKP",
		"x":   anp.EncodeBase64URL(publicKey.Bytes),
	}
	canonical, err := cjson.Marshal(jwk)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(canonical)
	return anp.EncodeBase64URL(hash[:]), nil
}

func stringValue(value any) string {
	result, _ := value.(string)
	return result
}
