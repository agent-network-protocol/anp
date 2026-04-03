package authentication

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/agent-network-protocol/anp/golang/proof"
)

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
	parts := strings.Split(did, ":")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid DID format")
	}
	domain, err := url.PathUnescape(parts[2])
	if err != nil {
		return nil, err
	}
	baseURL := options.BaseURLOverride
	if baseURL == "" {
		baseURL = "https://" + domain
	}
	resourceURL := strings.TrimRight(baseURL, "/") + "/.well-known/did.json"
	if len(parts) > 3 {
		pathSegments := make([]string, 0, len(parts)-3)
		for _, segment := range parts[3:] {
			decoded, decodeErr := url.PathUnescape(segment)
			if decodeErr != nil {
				return nil, decodeErr
			}
			pathSegments = append(pathSegments, decoded)
		}
		resourceURL = strings.TrimRight(baseURL, "/") + "/" + strings.Join(pathSegments, "/") + "/did.json"
	}
	document, err := fetchJSONDocument(ctx, resourceURL, options)
	if err != nil {
		return nil, err
	}
	if identifier, _ := document["id"].(string); identifier != did {
		return nil, fmt.Errorf("invalid DID document")
	}
	if verifyProof {
		proofValue, ok := document["proof"].(map[string]any)
		if ok {
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
