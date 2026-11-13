package authentication

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// FederatedHTTPSecurity supplies trusted receiver policy and atomic replay storage.
// A shared store is required for clustered hosts. Configure scope from the host,
// not from the incoming document or a peer-supplied original-request description.
type FederatedHTTPSecurity struct {
	Policy        HTTPSignaturePolicy
	Now           int64
	VerifierScope string
	ReplayStore   HTTPReplayStore
}

var federationHTTPReplayStore = NewMemoryHTTPReplayStore()

// VerifyFederatedHTTPRequest verifies a service-signed ANP request on behalf of a sender DID.
func VerifyFederatedHTTPRequest(ctx context.Context, senderDID string, requestMethod string, requestURL string, headers map[string]string, body []byte, options FederatedVerificationOptions) (FederatedVerificationResult, error) {
	scope, err := AuthenticationOrigin(requestURL)
	if err != nil {
		return FederatedVerificationResult{}, err
	}
	return VerifyFederatedHTTPRequestWithSecurity(ctx, senderDID, requestMethod, requestURL, headers, body, options, FederatedHTTPSecurity{Policy: DefaultHTTPSignaturePolicy(), Now: time.Now().Unix(), VerifierScope: scope, ReplayStore: federationHTTPReplayStore})
}

// VerifyFederatedHTTPRequestWithSecurity enforces signature/time/identity and shared replay.
func VerifyFederatedHTTPRequestWithSecurity(ctx context.Context, senderDID, requestMethod, requestURL string, headers map[string]string, body []byte, options FederatedVerificationOptions, security FederatedHTTPSecurity) (FederatedVerificationResult, error) {
	if security.Policy.CryptoOnly || security.ReplayStore == nil {
		return FederatedVerificationResult{}, fmt.Errorf("full federated authentication requires time and replay protection")
	}
	preflight, err := ExtractSignatureMetadata(headers)
	if err != nil {
		return FederatedVerificationResult{}, err
	}
	if _, err := security.Policy.Validate(preflight.Created, preflight.Expires, security.Now); err != nil {
		return FederatedVerificationResult{}, err
	}
	senderDocument := options.SenderDidDocument
	if senderDocument == nil {
		senderDocument, err = ResolveDidDocumentWithOptions(ctx, senderDID, options.VerifySenderDidProof, options.DidResolutionOptions)
		if err != nil {
			return FederatedVerificationResult{}, err
		}
	}
	if stringValue(senderDocument["id"]) != senderDID {
		return FederatedVerificationResult{}, fmt.Errorf("sender DID document ID mismatch")
	}
	service, err := selectANPMessageService(senderDocument, options.ServiceID, options.ServiceEndpoint)
	if err != nil {
		return FederatedVerificationResult{}, err
	}
	serviceDID := stringValue(service["serviceDid"])
	if serviceDID == "" {
		return FederatedVerificationResult{}, fmt.Errorf("selected ANPMessageService is missing serviceDid")
	}
	metadata, err := ExtractSignatureMetadata(headers)
	if err != nil {
		return FederatedVerificationResult{}, err
	}
	if strings.Split(metadata.KeyID, "#")[0] != serviceDID {
		return FederatedVerificationResult{}, fmt.Errorf("signature keyid DID does not match serviceDid")
	}
	serviceDocument := options.ServiceDidDocument
	if serviceDocument == nil {
		serviceDocument, err = ResolveDidDocumentWithOptions(ctx, serviceDID, options.VerifyServiceDidProof, options.DidResolutionOptions)
		if err != nil {
			return FederatedVerificationResult{}, err
		}
	}
	if stringValue(serviceDocument["id"]) != serviceDID {
		return FederatedVerificationResult{}, fmt.Errorf("serviceDid document ID mismatch")
	}
	if !IsAuthenticationAuthorized(serviceDocument, metadata.KeyID) {
		return FederatedVerificationResult{}, fmt.Errorf("verification method is not authorized for authentication")
	}
	verified, err := VerifyHTTPMessageSignatureWithPolicy(serviceDocument, requestMethod, requestURL, headers, body, security.Policy, security.Now)
	if err != nil {
		return FederatedVerificationResult{}, err
	}
	item, err := HTTPReplayContextForSignature(verified, requestMethod, requestURL, headers, security.VerifierScope, security.Policy)
	if err != nil {
		return FederatedVerificationResult{}, err
	}
	first, err := security.ReplayStore.ConsumeOnce(ctx, item)
	if err != nil {
		return FederatedVerificationResult{}, fmt.Errorf("HTTP replay protection unavailable")
	}
	if !first {
		return FederatedVerificationResult{}, fmt.Errorf("HTTP signature replay detected")
	}
	return FederatedVerificationResult{SenderDID: senderDID, ServiceDID: serviceDID, ServiceID: stringValue(service["id"]), SignatureMetadata: verified}, nil
}

func selectANPMessageService(didDocument map[string]any, serviceID string, serviceEndpoint string) (map[string]any, error) {
	services, ok := didDocument["service"].([]any)
	if !ok {
		return nil, fmt.Errorf("no ANPMessageService found in DID document")
	}
	candidates := []map[string]any{}
	for _, entry := range services {
		service, ok := entry.(map[string]any)
		if ok && stringValue(service["type"]) == ANPMessageServiceType {
			candidates = append(candidates, service)
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no ANPMessageService found in DID document")
	}
	if serviceID != "" {
		for _, candidate := range candidates {
			if stringValue(candidate["id"]) == serviceID {
				return candidate, nil
			}
		}
		return nil, fmt.Errorf("ANPMessageService not found for serviceId=%s", serviceID)
	}
	if serviceEndpoint != "" {
		for _, candidate := range candidates {
			if stringValue(candidate["serviceEndpoint"]) == serviceEndpoint {
				return candidate, nil
			}
		}
		return nil, fmt.Errorf("ANPMessageService not found for serviceEndpoint")
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	return nil, fmt.Errorf("multiple ANPMessageService entries found; serviceId or serviceEndpoint is required")
}
