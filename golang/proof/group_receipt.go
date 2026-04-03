package proof

import anp "github.com/agent-network-protocol/anp/golang"

const GroupReceiptProofPurpose = "assertionMethod"

var GroupReceiptRequiredFields = []string{
	"receipt_type",
	"group_did",
	"group_state_version",
	"subject_method",
	"operation_id",
	"actor_did",
	"accepted_at",
	"payload_digest",
}

// GenerateGroupReceiptProof signs a group receipt object.
func GenerateGroupReceiptProof(receipt map[string]any, privateKey anp.PrivateKeyMaterial, verificationMethod string) (map[string]any, error) {
	if err := validateGroupReceipt(receipt); err != nil {
		return nil, err
	}
	cryptosuite := CryptosuiteDidWbaSecp256k12025
	if privateKey.Type == anp.KeyTypeEd25519 {
		cryptosuite = CryptosuiteEddsaJCS2022
	}
	return GenerateW3CProof(receipt, privateKey, verificationMethod, GenerationOptions{
		ProofPurpose: GroupReceiptProofPurpose,
		ProofType:    ProofTypeDataIntegrity,
		Cryptosuite:  cryptosuite,
	})
}

// VerifyGroupReceiptProof verifies a signed group receipt.
func VerifyGroupReceiptProof(receipt map[string]any, publicKey anp.PublicKeyMaterial) error {
	if err := validateGroupReceipt(receipt); err != nil {
		return err
	}
	return VerifyW3CProofDetailed(receipt, publicKey, VerificationOptions{ExpectedPurpose: GroupReceiptProofPurpose})
}

func validateGroupReceipt(receipt map[string]any) error {
	for _, field := range GroupReceiptRequiredFields {
		if _, ok := receipt[field]; !ok {
			return &Error{Message: "missing proof field: " + field}
		}
	}
	return nil
}
