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
		ttl := 300
		_ = json.NewEncoder(w).Encode(HandleResolutionDocument{
			Handle:    "alice.example.com",
			DID:       "did:wba:example.com:user:alice",
			Status:    HandleStatusActive,
			VersionID: "42",
			TTL:       &ttl,
			Profile: &DIDSubjectProfile{
				Type:        "DIDSubjectProfile",
				SubjectDID:  "did:wba:example.com:user:alice",
				SubjectType: SubjectTypePerson,
				Handle:      "alice.example.com",
				DisplayName: "Alice",
				AvatarURI:   "https://example.com/avatars/alice.png",
				Proof:       map[string]any{"type": "DataIntegrityProof"},
			},
		})
	}))
	defer server.Close()
	document, err := ResolveHandleWithOptions(context.Background(), "alice.example.com", ResolveHandleOptions{BaseURLOverride: server.URL, VerifySSL: boolPtr(false)})
	if err != nil {
		t.Fatalf("ResolveHandleWithOptions failed: %v", err)
	}
	if document.DID != "did:wba:example.com:user:alice" {
		t.Fatalf("unexpected did: %s", document.DID)
	}
	if document.VersionID != "42" || document.TTL == nil || *document.TTL != 300 {
		t.Fatalf("unexpected cache metadata: version=%s ttl=%v", document.VersionID, document.TTL)
	}
	if document.Profile == nil || document.Profile.DisplayName != "Alice" || document.Profile.SubjectType != SubjectTypePerson {
		t.Fatalf("unexpected profile: %#v", document.Profile)
	}
	if document.Profile.Proof["type"] != "DataIntegrityProof" {
		t.Fatalf("unexpected profile proof: %#v", document.Profile.Proof)
	}
}

func TestResolveHandleIgnoresProfileSubjectDIDMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(HandleResolutionDocument{
			Handle: "alice.example.com",
			DID:    "did:wba:example.com:user:alice",
			Status: HandleStatusActive,
			Profile: &DIDSubjectProfile{
				SubjectDID:  "did:wba:example.com:user:bob",
				DisplayName: "Bob",
			},
		})
	}))
	defer server.Close()

	document, err := ResolveHandleWithOptions(context.Background(), "alice.example.com", ResolveHandleOptions{BaseURLOverride: server.URL, VerifySSL: boolPtr(false)})
	if err != nil {
		t.Fatalf("ResolveHandleWithOptions failed: %v", err)
	}
	if document.Profile != nil {
		t.Fatalf("expected profile to be ignored, got %#v", document.Profile)
	}
}

func TestResolveHandleIgnoresProfileHandleMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(HandleResolutionDocument{
			Handle: "alice.example.com",
			DID:    "did:wba:example.com:user:alice",
			Status: HandleStatusActive,
			Profile: &DIDSubjectProfile{
				SubjectDID:  "did:wba:example.com:user:alice",
				Handle:      "bob.example.com",
				DisplayName: "Bob",
			},
		})
	}))
	defer server.Close()

	document, err := ResolveHandleWithOptions(context.Background(), "alice.example.com", ResolveHandleOptions{BaseURLOverride: server.URL, VerifySSL: boolPtr(false)})
	if err != nil {
		t.Fatalf("ResolveHandleWithOptions failed: %v", err)
	}
	if document.Profile != nil {
		t.Fatalf("expected profile to be ignored, got %#v", document.Profile)
	}
}

func TestResolveHandleNormalizesUnknownProfileSubjectType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(HandleResolutionDocument{
			Handle: "alice.example.com",
			DID:    "did:wba:example.com:user:alice",
			Status: HandleStatusActive,
			Profile: &DIDSubjectProfile{
				SubjectDID:  "did:wba:example.com:user:alice",
				SubjectType: SubjectType("custom-private-type"),
				DisplayName: "Alice",
			},
		})
	}))
	defer server.Close()

	document, err := ResolveHandleWithOptions(context.Background(), "alice.example.com", ResolveHandleOptions{BaseURLOverride: server.URL, VerifySSL: boolPtr(false)})
	if err != nil {
		t.Fatalf("ResolveHandleWithOptions failed: %v", err)
	}
	if document.Profile == nil || document.Profile.SubjectType != SubjectTypeUnknown {
		t.Fatalf("expected unknown subject type, got %#v", document.Profile)
	}
}

func boolPtr(value bool) *bool { return &value }
