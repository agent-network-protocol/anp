package wns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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
			Handle:            "alice.example.com",
			DID:               "did:wba:example.com:user:alice",
			Status:            HandleStatusActive,
			BindingGeneration: "1",
			VersionID:         "42",
			TTL:               &ttl,
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
			Handle:            "alice.example.com",
			DID:               "did:wba:example.com:user:alice",
			Status:            HandleStatusActive,
			BindingGeneration: "1",
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
			Handle:            "alice.example.com",
			DID:               "did:wba:example.com:user:alice",
			Status:            HandleStatusActive,
			BindingGeneration: "1",
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
			Handle:            "alice.example.com",
			DID:               "did:wba:example.com:user:alice",
			Status:            HandleStatusActive,
			BindingGeneration: "1",
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

func TestSharedBindingGenerationVectors(t *testing.T) {
	data, err := os.ReadFile("../../testdata/wns/binding_generation_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Validation []struct {
			Name      string          `json:"name"`
			Value     json.RawMessage `json:"value"`
			Valid     bool            `json:"valid"`
			Canonical string          `json:"canonical"`
		} `json:"validation"`
		Transitions []struct {
			Name, Previous, Current string
			Accepted                bool
		} `json:"transitions"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, testCase := range vectors.Validation {
		t.Run(testCase.Name, func(t *testing.T) {
			var generation BindingGeneration
			err := json.Unmarshal(testCase.Value, &generation)
			if (err == nil) != testCase.Valid {
				t.Fatalf("valid=%v, error=%v", testCase.Valid, err)
			}
			if err == nil && string(generation) != testCase.Canonical {
				t.Fatalf("got %q, want %q", generation, testCase.Canonical)
			}
		})
	}
	for _, transition := range vectors.Transitions {
		current, _ := ParseBindingGeneration(transition.Current)
		previous, _ := ParseBindingGeneration(transition.Previous)
		if current.IsNewerThan(previous) != transition.Accepted {
			t.Errorf("transition %s: accepted mismatch", transition.Name)
		}
	}
}

func TestBindingGenerationPreservesTenThousandDigits(t *testing.T) {
	value := strings.Repeat("9", 10_000)
	generation, err := ParseBindingGeneration(value)
	if err != nil {
		t.Fatal(err)
	}
	if string(generation) != value {
		t.Fatal("binding generation was not preserved")
	}
	larger, err := ParseBindingGeneration("1" + strings.Repeat("0", 10_000))
	if err != nil {
		t.Fatal(err)
	}
	if !larger.IsNewerThan(generation) {
		t.Fatal("arbitrary-precision comparison rejected a larger generation")
	}
}

func TestResolveHandleRejectsMissingBindingGeneration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"handle":"alice.example.com","did":"did:wba:example.com:user:alice","status":"active"}`))
	}))
	defer server.Close()
	_, err := ResolveHandleWithOptions(context.Background(), "alice.example.com", ResolveHandleOptions{BaseURLOverride: server.URL})
	if err == nil {
		t.Fatal("expected missing binding_generation to fail")
	}
}

func TestVerifyHandleBindingReturnsGenerationOnlyOnSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(HandleResolutionDocument{
			Handle:            "alice.example.com",
			DID:               "did:wba:example.com:user:alice",
			Status:            HandleStatusActive,
			BindingGeneration: "8",
		})
	}))
	defer server.Close()
	didDocument := map[string]any{"service": []any{map[string]any{
		"id": "did:wba:example.com:user:alice#handle", "type": ANPHandleServiceType,
		"serviceEndpoint": "https://example.com/providers/wns",
	}}}

	result := VerifyHandleBindingWithOptions(context.Background(), "alice.example.com", BindingVerificationOptions{
		DidDocument:       didDocument,
		ResolutionOptions: ResolveHandleOptions{BaseURLOverride: server.URL},
	})
	if !result.IsValid || result.BindingGeneration == nil || *result.BindingGeneration != "8" {
		t.Fatalf("expected verified generation 8, got %#v", result)
	}

	didDocument["service"] = []any{}
	result = VerifyHandleBindingWithOptions(context.Background(), "alice.example.com", BindingVerificationOptions{
		DidDocument:       didDocument,
		ResolutionOptions: ResolveHandleOptions{BaseURLOverride: server.URL},
	})
	if result.IsValid || result.BindingGeneration != nil {
		t.Fatalf("invalid verification exposed generation: %#v", result)
	}
}
