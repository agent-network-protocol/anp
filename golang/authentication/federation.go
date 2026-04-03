package authentication

import (
	"context"
	"fmt"
	"strings"
)

// VerifyFederatedHTTPRequest verifies a service-signed ANP request on behalf of a sender DID.
func VerifyFederatedHTTPRequest(ctx context.Context, senderDID string, requestMethod string, requestURL string, headers map[string]string, body []byte, options FederatedVerificationOptions) (FederatedVerificationResult, error) {
	senderDocument := options.SenderDidDocument
	var err error
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
	verified, err := VerifyHTTPMessageSignature(serviceDocument, requestMethod, requestURL, headers, body)
	if err != nil {
		return FederatedVerificationResult{}, err
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
