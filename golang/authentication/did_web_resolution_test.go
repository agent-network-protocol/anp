package authentication

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebResolutionSharedURLs(t *testing.T) {
	data, err := os.ReadFile("../../fixtures/did-method-lifecycle-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			DID string `json:"did"`
			URL string `json:"url"`
		} `json:"resolution_cases"`
		Invalid []string `json:"invalid_resolution_dids"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, c := range fixture.Cases {
		got, err := BuildDIDWebResolutionURL(c.DID)
		if err != nil || got != c.URL {
			t.Errorf("%s: got %s (%v), want %s", c.DID, got, err, c.URL)
		}
	}
	for _, did := range fixture.Invalid {
		if _, err := BuildDIDWebResolutionURL(did); err == nil {
			t.Errorf("accepted unsafe DID %s", did)
		}
	}
}

func TestWebResponseBoundary(t *testing.T) {
	const did = "did:web:example.com:users:alice"
	for _, mode := range []string{"valid", "wrong-id", "oversized", "redirect", "html", "malformed-proof", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count := requests.Add(1)
				if mode == "timeout" {
					time.Sleep(150 * time.Millisecond)
				}
				if count == 1 {
					switch mode {
					case "redirect":
						w.Header().Set("Location", "/redirected")
						w.WriteHeader(302)
						return
					case "oversized":
						_, _ = w.Write([]byte(strings.Repeat(" ", 1024*1024+1)))
						return
					case "wrong-id":
						_, _ = w.Write([]byte(`{"id":"did:web:other.example"}`))
						return
					case "html":
						_, _ = w.Write([]byte("<html>SPA</html>"))
						return
					case "malformed-proof":
						_ = json.NewEncoder(w).Encode(map[string]any{"id": did, "proof": false})
						return
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"id": did})
			}))
			defer server.Close()
			seconds := 10.0
			if mode == "timeout" {
				seconds = 0.05
			}
			document, err := ResolveDidDocumentWithOptions(context.Background(), did, true, DidResolutionOptions{BaseURLOverride: server.URL, TimeoutSeconds: seconds})
			if mode == "valid" {
				if err != nil || document["id"] != did {
					t.Fatalf("rootless Web resolution failed: %v", err)
				}
			} else if err == nil {
				t.Fatal("unsafe response accepted")
			}
			if requests.Load() != 1 {
				t.Fatal("resolver followed a redirect")
			}
		})
	}
}

func TestWebProductionRequiresTLS(t *testing.T) {
	verify := false
	if _, err := ResolveDidDocumentWithOptions(context.Background(), "did:web:example.com", false, DidResolutionOptions{VerifySSL: &verify}); err == nil {
		t.Fatal("production resolution disabled TLS verification")
	}
}

func TestWebPublicAddresses(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "192.168.0.1", "198.18.0.1", "224.0.0.1", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "2002:7f00:1::", "2001:db8::1", "3fff::1"} {
		if isPublicWebAddress(net.ParseIP(address)) {
			t.Errorf("accepted non-public address %s", address)
		}
	}
	for _, address := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if !isPublicWebAddress(net.ParseIP(address)) {
			t.Errorf("rejected public address %s", address)
		}
	}
}
