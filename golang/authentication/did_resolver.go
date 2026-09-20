package authentication

import (
	"context"
	"fmt"
	"strings"

	"github.com/agent-network-protocol/anp/golang/proof"
)

// ValidateDIDDocumentMethod checks method rules after trusted resolution.
// It does not establish HTTPS provenance or grant any verification purpose.
func ValidateDIDDocumentMethod(document map[string]any, verifyProof bool) bool {
	did, ok := document["id"].(string)
	if !ok {
		return false
	}
	if strings.HasPrefix(did, "did:wba:") {
		return ValidateDIDDocumentBinding(document, verifyProof)
	}
	if strings.HasPrefix(did, "did:web:") {
		_, err := BuildDIDWebResolutionURL(did)
		return err == nil
	}
	return false
}

// ResolveDidDocument resolves a did:wba or did:web document.
func ResolveDidDocument(ctx context.Context, did string, verifyProof bool) (map[string]any, error) {
	return ResolveDidDocumentWithOptions(ctx, did, verifyProof, DidResolutionOptions{})
}

// ResolveDidDocumentWithOptions resolves a did:wba or did:web document with explicit options.
func ResolveDidDocumentWithOptions(ctx context.Context, did string, verifyProof bool, options DidResolutionOptions) (map[string]any, error) {
	if strings.HasPrefix(did, "did:wba:") {
		return ResolveDidWBADocumentWithOptions(ctx, did, verifyProof, options)
	}
	if !strings.HasPrefix(did, "did:web:") {
		return nil, fmt.Errorf("invalid DID format")
	}
	document, err := fetchDIDWebDocument(ctx, did, options)
	if err != nil {
		return nil, err
	}
	if identifier, _ := document["id"].(string); identifier != did {
		return nil, fmt.Errorf("invalid DID document")
	}
	if verifyProof {
		if rawProof, present := document["proof"]; present {
			proofValue, ok := rawProof.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("invalid DID document proof")
			}
			verificationMethodID, _ := proofValue["verificationMethod"].(string)
			verificationMethod := FindVerificationMethod(document, verificationMethodID)
			if verificationMethod == nil {
				return nil, fmt.Errorf("verification method not found")
			}
			publicKey, err := ExtractPublicKey(verificationMethod)
			if err != nil {
				return nil, err
			}
			if !proof.VerifyW3CProof(document, publicKey, proof.VerificationOptions{}) {
				return nil, fmt.Errorf("verification failed")
			}
		}
	}
	return document, nil
}
