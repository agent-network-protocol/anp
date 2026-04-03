package wns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateHandleAndParseWBAURI(t *testing.T) {
	localPart, domain, err := ValidateHandle("Alice.Example.COM")
	if err != nil {
		t.Fatalf("ValidateHandle failed: %v", err)
	}
	if localPart != "alice" || domain != "example.com" {
		t.Fatalf("unexpected normalized handle: %s.%s", localPart, domain)
	}
	parsed, err := ParseWBAURI("wba://alice.example.com")
	if err != nil {
		t.Fatalf("ParseWBAURI failed: %v", err)
	}
	if parsed.Handle != "alice.example.com" {
		t.Fatalf("unexpected parsed handle: %s", parsed.Handle)
	}
}

func TestResolveHandleWithOverride(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/handle/alice" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(HandleResolutionDocument{Handle: "alice.example.com", DID: "did:wba:example.com:user:alice", Status: HandleStatusActive})
	}))
	defer server.Close()
	document, err := ResolveHandleWithOptions(context.Background(), "alice.example.com", ResolveHandleOptions{BaseURLOverride: server.URL, VerifySSL: boolPtr(false)})
	if err != nil {
		t.Fatalf("ResolveHandleWithOptions failed: %v", err)
	}
	if document.DID != "did:wba:example.com:user:alice" {
		t.Fatalf("unexpected did: %s", document.DID)
	}
}

func boolPtr(value bool) *bool { return &value }
