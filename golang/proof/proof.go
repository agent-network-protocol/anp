package proof

import (
	"crypto/sha256"
	"fmt"
	"time"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/internal/base64util"
	"github.com/agent-network-protocol/anp/golang/internal/cjson"
)

const (
	ProofTypeSecp256k1     = "EcdsaSecp256k1Signature2019"
	ProofTypeEd25519       = "Ed25519Signature2020"
	ProofTypeDataIntegrity = "DataIntegrityProof"

	CryptosuiteEddsaJCS2022        = "eddsa-jcs-2022"
	CryptosuiteDidWbaSecp256k12025 = "didwba-jcs-ecdsa-secp256k1-2025"
)

// Error reports proof generation or verification failures.
type Error struct {
	Message string
}

// Error implements error.
func (e *Error) Error() string {
	return e.Message
}

// GenerationOptions configures W3C proof generation.
type GenerationOptions struct {
	ProofPurpose string
	ProofType    string
	Cryptosuite  string
	Created      string
	Domain       string
	Challenge    string
}

// VerificationOptions configures W3C proof verification.
type VerificationOptions struct {
	ExpectedPurpose   string
	ExpectedDomain    string
	ExpectedChallenge string
}

// GenerateW3CProof signs a JSON object and injects its proof object.
func GenerateW3CProof(document map[string]any, privateKey anp.PrivateKeyMaterial, verificationMethod string, options GenerationOptions) (map[string]any, error) {
	proofType := options.ProofType
	if proofType == "" {
		proofType = inferProofType(privateKey.Type)
	}
	if err := validateProofCompatibility(privateKey.Type, proofType, options.Cryptosuite); err != nil {
		return nil, err
	}
	created := options.Created
	if created == "" {
		created = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	}
	proofPurpose := options.ProofPurpose
	if proofPurpose == "" {
		proofPurpose = "assertionMethod"
	}
	proofObject := map[string]any{
		"type":               proofType,
		"created":            created,
		"verificationMethod": verificationMethod,
		"proofPurpose":       proofPurpose,
	}
	if proofType == ProofTypeDataIntegrity {
		cryptosuite := options.Cryptosuite
		if cryptosuite == "" {
			cryptosuite = inferCryptosuite(privateKey.Type)
		}
		if err := validateCryptosuite(privateKey.Type, cryptosuite); err != nil {
			return nil, err
		}
		proofObject["cryptosuite"] = cryptosuite
	}
	if options.Domain != "" {
		proofObject["domain"] = options.Domain
	}
	if options.Challenge != "" {
		proofObject["challenge"] = options.Challenge
	}
	cloned := cloneMap(document)
	delete(cloned, "proof")
	signingInput, err := computeSigningInput(cloned, proofObject)
	if err != nil {
		return nil, err
	}
	signature, err := privateKey.SignMessage(signingInput)
	if err != nil {
		return nil, &Error{Message: "signing error"}
	}
	proofObject["proofValue"] = base64util.EncodeURL(signature)
	signed := cloneMap(document)
	signed["proof"] = proofObject
	return signed, nil
}

// VerifyW3CProof returns true when proof verification succeeds.
func VerifyW3CProof(document map[string]any, publicKey anp.PublicKeyMaterial, options VerificationOptions) bool {
	return VerifyW3CProofDetailed(document, publicKey, options) == nil
}

// VerifyW3CProofDetailed verifies a W3C proof and returns an error on failure.
func VerifyW3CProofDetailed(document map[string]any, publicKey anp.PublicKeyMaterial, options VerificationOptions) error {
	proofValue, ok := document["proof"].(map[string]any)
	if !ok {
		return &Error{Message: "missing proof object"}
	}
	proofType, err := requireStringField(proofValue, "type")
	if err != nil {
		return err
	}
	proofSignature, err := requireStringField(proofValue, "proofValue")
	if err != nil {
		return err
	}
	_, err = requireStringField(proofValue, "verificationMethod")
	if err != nil {
		return err
	}
	proofPurpose, err := requireStringField(proofValue, "proofPurpose")
	if err != nil {
		return err
	}
	_, err = requireStringField(proofValue, "created")
	if err != nil {
		return err
	}
	cryptosuite, _ := proofValue["cryptosuite"].(string)
	if err := validatePublicKeyCompatibility(publicKey.Type, proofType, cryptosuite); err != nil {
		return err
	}
	if options.ExpectedPurpose != "" && options.ExpectedPurpose != proofPurpose {
		return &Error{Message: "verification failed"}
	}
	if options.ExpectedDomain != "" {
		domain, _ := proofValue["domain"].(string)
		if domain != options.ExpectedDomain {
			return &Error{Message: "verification failed"}
		}
	}
	if options.ExpectedChallenge != "" {
		challenge, _ := proofValue["challenge"].(string)
		if challenge != options.ExpectedChallenge {
			return &Error{Message: "verification failed"}
		}
	}
	unsigned := cloneMap(document)
	delete(unsigned, "proof")
	proofOptions := cloneMap(proofValue)
	delete(proofOptions, "proofValue")
	signingInput, err := computeSigningInput(unsigned, proofOptions)
	if err != nil {
		return err
	}
	signatureBytes, err := base64util.DecodeURL(proofSignature)
	if err != nil {
		return &Error{Message: "invalid proof value encoding"}
	}
	if err := publicKey.VerifyMessage(signingInput, signatureBytes); err != nil {
		return &Error{Message: "verification failed"}
	}
	return nil
}

func computeSigningInput(document map[string]any, proofOptions map[string]any) ([]byte, error) {
	documentCanonical, err := cjson.Marshal(document)
	if err != nil {
		return nil, &Error{Message: fmt.Sprintf("canonicalization error: %v", err)}
	}
	proofCanonical, err := cjson.Marshal(proofOptions)
	if err != nil {
		return nil, &Error{Message: fmt.Sprintf("canonicalization error: %v", err)}
	}
	documentHash := sha256.Sum256(documentCanonical)
	proofHash := sha256.Sum256(proofCanonical)
	combined := make([]byte, 0, len(documentHash)+len(proofHash))
	combined = append(combined, proofHash[:]...)
	combined = append(combined, documentHash[:]...)
	return combined, nil
}

func inferProofType(keyType anp.KeyType) string {
	switch keyType {
	case anp.KeyTypeSecp256k1:
		return ProofTypeSecp256k1
	case anp.KeyTypeEd25519:
		return ProofTypeEd25519
	default:
		return ProofTypeDataIntegrity
	}
}

func inferCryptosuite(keyType anp.KeyType) string {
	switch keyType {
	case anp.KeyTypeEd25519:
		return CryptosuiteEddsaJCS2022
	case anp.KeyTypeSecp256k1:
		return CryptosuiteDidWbaSecp256k12025
	default:
		return ""
	}
}

func validateProofCompatibility(keyType anp.KeyType, proofType string, cryptosuite string) error {
	switch proofType {
	case ProofTypeSecp256k1:
		if keyType != anp.KeyTypeSecp256k1 {
			return &Error{Message: "key type mismatch for proof generation"}
		}
	case ProofTypeEd25519:
		if keyType != anp.KeyTypeEd25519 {
			return &Error{Message: "key type mismatch for proof generation"}
		}
	case ProofTypeDataIntegrity:
		if cryptosuite != "" {
			return validateCryptosuite(keyType, cryptosuite)
		}
	default:
		return &Error{Message: fmt.Sprintf("unsupported proof type: %s", proofType)}
	}
	return nil
}

func validatePublicKeyCompatibility(keyType anp.KeyType, proofType string, cryptosuite string) error {
	switch proofType {
	case ProofTypeSecp256k1:
		if keyType != anp.KeyTypeSecp256k1 {
			return &Error{Message: "invalid public key for proof verification"}
		}
	case ProofTypeEd25519:
		if keyType != anp.KeyTypeEd25519 {
			return &Error{Message: "invalid public key for proof verification"}
		}
	case ProofTypeDataIntegrity:
		if cryptosuite != "" {
			return validateCryptosuite(keyType, cryptosuite)
		}
	default:
		return &Error{Message: fmt.Sprintf("unsupported proof type: %s", proofType)}
	}
	return nil
}

func validateCryptosuite(keyType anp.KeyType, cryptosuite string) error {
	switch cryptosuite {
	case CryptosuiteEddsaJCS2022:
		if keyType != anp.KeyTypeEd25519 {
			return &Error{Message: fmt.Sprintf("unsupported cryptosuite: %s", cryptosuite)}
		}
	case CryptosuiteDidWbaSecp256k12025:
		if keyType != anp.KeyTypeSecp256k1 {
			return &Error{Message: fmt.Sprintf("unsupported cryptosuite: %s", cryptosuite)}
		}
	default:
		return &Error{Message: fmt.Sprintf("unsupported cryptosuite: %s", cryptosuite)}
	}
	return nil
}

func requireStringField(values map[string]any, key string) (string, error) {
	value, _ := values[key].(string)
	if value == "" {
		return "", &Error{Message: fmt.Sprintf("missing proof field: %s", key)}
	}
	return value, nil
}

func cloneMap(input map[string]any) map[string]any {
	result := make(map[string]any, len(input))
	for key, value := range input {
		switch typed := value.(type) {
		case map[string]any:
			result[key] = cloneMap(typed)
		case []any:
			result[key] = cloneSlice(typed)
		default:
			result[key] = typed
		}
	}
	return result
}

func cloneSlice(input []any) []any {
	result := make([]any, len(input))
	for index, value := range input {
		switch typed := value.(type) {
		case map[string]any:
			result[index] = cloneMap(typed)
		case []any:
			result[index] = cloneSlice(typed)
		default:
			result[index] = typed
		}
	}
	return result
}
