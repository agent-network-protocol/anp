package wns

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/agent-network-protocol/anp/golang/authentication"
)

// VerifyHandleBinding verifies forward and reverse handle binding.
func VerifyHandleBinding(ctx context.Context, handle string) BindingVerificationResult {
	return VerifyHandleBindingWithOptions(ctx, handle, BindingVerificationOptions{})
}

// VerifyHandleBindingWithOptions verifies forward and reverse handle binding with options.
func VerifyHandleBindingWithOptions(ctx context.Context, handle string, options BindingVerificationOptions) BindingVerificationResult {
	bareHandle := strings.TrimPrefix(handle, "wba://")
	localPart, domain, err := ValidateHandle(bareHandle)
	if err != nil {
		return BindingVerificationResult{IsValid: false, Handle: bareHandle, ErrorMessage: err.Error()}
	}
	normalized := localPart + "." + domain
	resolution, err := ResolveHandleWithOptions(ctx, normalized, options.ResolutionOptions)
	if err != nil {
		return BindingVerificationResult{IsValid: false, Handle: normalized, ErrorMessage: "forward resolution failed: " + err.Error()}
	}
	if resolution.Status != HandleStatusActive {
		return BindingVerificationResult{IsValid: false, Handle: normalized, DID: resolution.DID, ErrorMessage: fmt.Sprintf("handle status is '%s', expected 'active'", resolution.Status)}
	}
	if !strings.HasPrefix(resolution.DID, "did:wba:") {
		return BindingVerificationResult{IsValid: false, Handle: normalized, DID: resolution.DID, ForwardVerified: true, ErrorMessage: "DID does not use did:wba method"}
	}
	parts := strings.Split(resolution.DID, ":")
	didDomain := ""
	if len(parts) > 2 {
		didDomain = parts[2]
	}
	if strings.ToLower(didDomain) != domain {
		return BindingVerificationResult{IsValid: false, Handle: normalized, DID: resolution.DID, ForwardVerified: true, ErrorMessage: fmt.Sprintf("domain mismatch: handle domain '%s' != DID domain '%s'", domain, didDomain)}
	}
	didDocument := options.DidDocument
	if didDocument == nil {
		didDocument, err = authentication.ResolveDidWBADocumentWithOptions(ctx, resolution.DID, false, options.DidResolutionOptions)
		if err != nil {
			return BindingVerificationResult{IsValid: false, Handle: normalized, DID: resolution.DID, ForwardVerified: true, ErrorMessage: "failed to resolve DID document: " + err.Error()}
		}
	}
	handleServices := ExtractHandleServiceFromDIDDocument(didDocument)
	reverseVerified := false
	for _, service := range handleServices {
		if matchesHandleServiceDomain(service.ServiceEndpoint, domain) {
			reverseVerified = true
			break
		}
	}
	if !reverseVerified {
		return BindingVerificationResult{IsValid: false, Handle: normalized, DID: resolution.DID, ForwardVerified: true, ErrorMessage: fmt.Sprintf("DID Document does not contain an %s entry whose HTTPS domain matches '%s'", ANPHandleServiceType, domain)}
	}
	return BindingVerificationResult{IsValid: true, Handle: normalized, DID: resolution.DID, ForwardVerified: true, ReverseVerified: true}
}

// BuildHandleServiceEntry builds the reverse binding service entry.
func BuildHandleServiceEntry(did string, localPart string, domain string) HandleServiceEntry {
	return HandleServiceEntry{ID: did + "#handle", Type: ANPHandleServiceType, ServiceEndpoint: BuildResolutionURL(localPart, domain)}
}

// ExtractHandleServiceFromDIDDocument extracts ANPHandleService entries from a DID document.
func ExtractHandleServiceFromDIDDocument(didDocument map[string]any) []HandleServiceEntry {
	services, ok := didDocument["service"].([]any)
	if !ok {
		return nil
	}
	result := []HandleServiceEntry{}
	for _, entry := range services {
		service, ok := entry.(map[string]any)
		if ok && fmt.Sprintf("%v", service["type"]) == ANPHandleServiceType {
			result = append(result, HandleServiceEntry{ID: fmt.Sprintf("%v", service["id"]), Type: fmt.Sprintf("%v", service["type"]), ServiceEndpoint: fmt.Sprintf("%v", service["serviceEndpoint"])})
		}
	}
	return result
}

func matchesHandleServiceDomain(serviceEndpoint string, expectedDomain string) bool {
	parsed, err := url.Parse(serviceEndpoint)
	if err != nil {
		return false
	}
	return strings.EqualFold(parsed.Scheme, "https") && strings.EqualFold(parsed.Hostname(), expectedDomain)
}
