package wns

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
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
	client := newWNSHTTPClient(options)
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
		body, _ := io.ReadAll(response.Body)
		return HandleResolutionDocument{}, fmt.Errorf("unexpected status %d resolving '%s': %s", response.StatusCode, normalized, string(body))
	}
	var document HandleResolutionDocument
	if err := authenticationDecodeJSON(response.Body, &document); err != nil {
		return HandleResolutionDocument{}, err
	}
	if strings.ToLower(document.Handle) != normalized {
		return HandleResolutionDocument{}, fmt.Errorf("handle mismatch: requested '%s', got '%s'", normalized, document.Handle)
	}
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

func newWNSHTTPClient(options ResolveHandleOptions) *http.Client {
	timeout := 10 * time.Second
	if options.TimeoutSeconds > 0 {
		timeout = time.Duration(options.TimeoutSeconds * float64(time.Second))
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if options.VerifySSL != nil && !*options.VerifySSL {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

func authenticationDecodeJSON(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	decoder.UseNumber()
	return decoder.Decode(target)
}
