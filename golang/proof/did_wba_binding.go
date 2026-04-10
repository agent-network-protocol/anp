package proof

import (
	"time"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/internal/base64util"
	"github.com/agent-network-protocol/anp/golang/internal/diddoc"
)

var DidWbaBindingRequiredFields = []string{
	"agent_did",
	"verification_method",
	"leaf_signature_key_b64u",
	"issued_at",
	"expires_at",
}

// DidWbaBindingVerificationOptions configures business checks around did:wba bindings.
type DidWbaBindingVerificationOptions struct {
	Now                        string
	ExpectedLeafSignatureKey   string
	ExpectedCredentialIdentity string
}

// GenerateDidWbaBinding creates and signs a strict did:wba binding object.
func GenerateDidWbaBinding(agentDID string, verificationMethod string, leafSignatureKeyB64U string, privateKey anp.PrivateKeyMaterial, issuedAt string, expiresAt string, proofCreated string) (map[string]any, error) {
	binding := map[string]any{
		"agent_did":               agentDID,
		"verification_method":     verificationMethod,
		"leaf_signature_key_b64u": leafSignatureKeyB64U,
		"issued_at":               issuedAt,
		"expires_at":              expiresAt,
	}
	if err := validateDidWbaBindingFields(binding); err != nil {
		return nil, err
	}
	if proofCreated == "" {
		proofCreated = issuedAt
	}
	return GenerateObjectProof(binding, privateKey, verificationMethod, agentDID, proofCreated)
}

// VerifyDidWbaBinding verifies a strict did:wba binding object.
func VerifyDidWbaBinding(binding map[string]any, issuerDocument map[string]any, options DidWbaBindingVerificationOptions) error {
	if err := validateDidWbaBindingFields(binding); err != nil {
		return err
	}
	agentDID := stringValue(binding["agent_did"])
	verificationMethod := stringValue(binding["verification_method"])
	if did, err := didFromVerificationMethod(verificationMethod); err != nil || did != agentDID {
		return &Error{Message: "verification_method must belong to agent_did"}
	}
	if !diddoc.IsAssertionMethodAuthorized(issuerDocument, verificationMethod) {
		return &Error{Message: "verification_method is not authorized for assertionMethod"}
	}
	if diddoc.FindVerificationMethod(issuerDocument, verificationMethod) == nil {
		return &Error{Message: "verification_method not found in DID document"}
	}
	if options.ExpectedLeafSignatureKey != "" && options.ExpectedLeafSignatureKey != stringValue(binding["leaf_signature_key_b64u"]) {
		return &Error{Message: "leaf_signature_key_b64u does not match the expected MLS leaf key"}
	}
	if options.ExpectedCredentialIdentity != "" && options.ExpectedCredentialIdentity != agentDID {
		return &Error{Message: "credential.identity does not match agent_did"}
	}
	issuedAt, err := parseRFC3339String(stringValue(binding["issued_at"]))
	if err != nil {
		return err
	}
	expiresAt, err := parseRFC3339String(stringValue(binding["expires_at"]))
	if err != nil {
		return err
	}
	if issuedAt.After(expiresAt) {
		return &Error{Message: "issued_at must not be later than expires_at"}
	}
	now := time.Now().UTC()
	if options.Now != "" {
		now, err = parseRFC3339String(options.Now)
		if err != nil {
			return err
		}
	}
	if now.Before(issuedAt) || now.After(expiresAt) {
		return &Error{Message: "binding is outside the accepted validity window"}
	}
	_, err = VerifyObjectProof(binding, agentDID, issuerDocument)
	return err
}

func validateDidWbaBindingFields(binding map[string]any) error {
	for _, field := range DidWbaBindingRequiredFields {
		value, _ := binding[field].(string)
		if value == "" {
			return &Error{Message: "missing proof field: " + field}
		}
	}
	if _, err := base64util.DecodeURL(stringValue(binding["leaf_signature_key_b64u"])); err != nil {
		return &Error{Message: "leaf_signature_key_b64u is not valid base64url data"}
	}
	if _, err := parseRFC3339String(stringValue(binding["issued_at"])); err != nil {
		return err
	}
	if _, err := parseRFC3339String(stringValue(binding["expires_at"])); err != nil {
		return err
	}
	return nil
}
