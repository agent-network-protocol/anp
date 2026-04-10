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
	return GenerateObjectProof(receipt, privateKey, verificationMethod, stringValue(receipt["group_did"]), "")
}

// VerifyGroupReceiptProof verifies a signed group receipt.
func VerifyGroupReceiptProof(receipt map[string]any, issuerDocument map[string]any) error {
	if err := validateGroupReceipt(receipt); err != nil {
		return err
	}
	_, err := VerifyObjectProof(receipt, stringValue(receipt["group_did"]), issuerDocument)
	return err
}

func validateGroupReceipt(receipt map[string]any) error {
	for _, field := range GroupReceiptRequiredFields {
		if _, ok := receipt[field]; !ok {
			return &Error{Message: "missing proof field: " + field}
		}
	}
	return nil
}
