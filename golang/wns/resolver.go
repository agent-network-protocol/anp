package wns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/agent-network-protocol/anp/golang/internal/httpsecurity"
	"io"
	"net/http"
	"strings"
)

// ResolveHandle resolves a handle over HTTPS.
func ResolveHandle(ctx context.Context, handle string) (HandleResolutionDocument, error) {
	return ResolveHandleWithOptions(ctx, handle, ResolveHandleOptions{})
}

// ResolveHandleWithOptions resolves a handle with explicit options.
func ResolveHandleWithOptions(ctx context.Context, handle string, options ResolveHandleOptions) (HandleResolutionDocument, error) {
	bareHandle := strings.TrimPrefix(handle, "wba://")
	localPart, domain, err := ValidateHandle(bareHandle)
	if err != nil {
		return HandleResolutionDocument{}, err
	}
	normalized := localPart + "." + domain
	resolutionURL := BuildResolutionURL(localPart, domain)
	if options.BaseURLOverride != "" {
		resolutionURL = strings.TrimRight(options.BaseURLOverride, "/") + "/.well-known/handle/" + localPart
	}
	trusted := options.BaseURLOverride != ""
	if err := httpsecurity.ValidateURL(resolutionURL, trusted); err != nil {
		return HandleResolutionDocument{}, err
	}
	client, err := httpsecurity.NewClient(options.TimeoutSeconds, options.VerifySSL == nil || *options.VerifySSL, trusted)
	if err != nil {
		return HandleResolutionDocument{}, err
	}
	defer client.CloseIdleConnections()
	return resolveHandleResponse(ctx, resolutionURL, normalized, client)
}

func resolveHandleResponse(ctx context.Context, resolutionURL, normalized string, client *http.Client) (HandleResolutionDocument, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, resolutionURL, nil)
	if err != nil {
		return HandleResolutionDocument{}, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return HandleResolutionDocument{}, fmt.Errorf("network error resolving handle '%s': %v", normalized, err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusMovedPermanently {
		return HandleResolutionDocument{}, fmt.Errorf("handle '%s' has been migrated", normalized)
	}
	if response.StatusCode == http.StatusNotFound {
		return HandleResolutionDocument{}, fmt.Errorf("handle '%s' does not exist", normalized)
	}
	if response.StatusCode == http.StatusGone {
		return HandleResolutionDocument{}, fmt.Errorf("handle '%s' has been permanently revoked", normalized)
	}
	if response.StatusCode != http.StatusOK {
		return HandleResolutionDocument{}, fmt.Errorf("unexpected status %d resolving '%s'", response.StatusCode, normalized)
	}
	data, err := httpsecurity.ReadBody(response, httpsecurity.MaxDocumentBytes)
	if err != nil {
		return HandleResolutionDocument{}, err
	}
	var document HandleResolutionDocument
	if err := authenticationDecodeJSON(bytes.NewReader(data), &document); err != nil {
		return HandleResolutionDocument{}, err
	}
	if document.BindingGeneration == "" {
		return HandleResolutionDocument{}, fmt.Errorf("binding_generation is required")
	}
	if strings.ToLower(document.Handle) != normalized {
		return HandleResolutionDocument{}, fmt.Errorf("handle mismatch: requested '%s', got '%s'", normalized, document.Handle)
	}
	dropInvalidProfileProjection(&document)
	return document, nil
}

// ResolveHandleFromURI resolves a wba:// URI.
func ResolveHandleFromURI(ctx context.Context, uri string) (HandleResolutionDocument, error) {
	parsed, err := ParseWBAURI(uri)
	if err != nil {
		return HandleResolutionDocument{}, err
	}
	return ResolveHandle(ctx, parsed.Handle)
}

func authenticationDecodeJSON(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing WNS response data")
	}
	return nil
}

func dropInvalidProfileProjection(document *HandleResolutionDocument) {
	if document.Profile == nil {
		return
	}
	if !isKnownSubjectType(document.Profile.SubjectType) {
		document.Profile.SubjectType = SubjectTypeUnknown
	}
	if document.Profile.SubjectDID != document.DID {
		document.Profile = nil
		return
	}
	if document.Profile.Handle != "" && document.Profile.Handle != document.Handle {
		document.Profile = nil
	}
}

func isKnownSubjectType(value SubjectType) bool {
	switch value {
	case SubjectTypePerson,
		SubjectTypeAgent,
		SubjectTypeGroup,
		SubjectTypeOrganization,
		SubjectTypeService,
		SubjectTypeApplication,
		SubjectTypeUnknown:
		return true
	default:
		return false
	}
}
