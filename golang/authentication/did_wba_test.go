package authentication

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/proof"
)

func TestCreateDidWBADocumentProfiles(t *testing.T) {
	e1, err := CreateDidWBADocument("example.com", DidDocumentOptions{PathSegments: []string{"user", "alice"}})
	if err != nil {
		t.Fatalf("CreateDidWBADocument(e1) failed: %v", err)
	}
	if id := stringValue(e1.DidDocument["id"]); id == "" || !contains(id, ":e1_") {
		t.Fatalf("unexpected e1 did: %s", id)
	}
	k1, err := CreateDidWBADocument("example.com", DidDocumentOptions{PathSegments: []string{"user", "alice"}, DidProfile: DidProfileK1})
	if err != nil {
		t.Fatalf("CreateDidWBADocument(k1) failed: %v", err)
	}
	if id := stringValue(k1.DidDocument["id"]); id == "" || !contains(id, ":k1_") {
		t.Fatalf("unexpected k1 did: %s", id)
	}
	legacy, err := CreateDidWBADocument("example.com", DidDocumentOptions{PathSegments: []string{"user", "alice"}, DidProfile: DidProfilePlainLegacy})
	if err != nil {
		t.Fatalf("CreateDidWBADocument(legacy) failed: %v", err)
	}
	proofValue := legacy.DidDocument["proof"].(map[string]any)
	if stringValue(proofValue["type"]) != proof.ProofTypeSecp256k1 {
		t.Fatalf("unexpected legacy proof type: %v", proofValue["type"])
	}
}

func TestValidateDIDDocumentBindingRejectsE1WithoutAssertionMethodAuthorization(t *testing.T) {
	bundle, err := CreateDidWBADocument("example.com", DidDocumentOptions{PathSegments: []string{"user", "alice"}})
	if err != nil {
		t.Fatalf("CreateDidWBADocument failed: %v", err)
	}
	document := cloneMap(bundle.DidDocument)
	document["assertionMethod"] = []any{}
	if ValidateDIDDocumentBinding(document, false) {
		t.Fatalf("expected e1 binding validation to fail without assertionMethod authorization")
	}
}

func TestValidateDIDDocumentBindingRejectsE1WithTamperedThumbprint(t *testing.T) {
	bundle, err := CreateDidWBADocument("example.com", DidDocumentOptions{PathSegments: []string{"user", "alice"}})
	if err != nil {
		t.Fatalf("CreateDidWBADocument failed: %v", err)
	}
	document := cloneMap(bundle.DidDocument)
	document["id"] = stringValue(bundle.DidDocument["id"]) + "x"
	if ValidateDIDDocumentBinding(document, false) {
		t.Fatalf("expected e1 binding validation to fail when thumbprint is tampered")
	}
}

func TestLegacyAuthRoundTrip(t *testing.T) {
	bundle, err := CreateDidWBADocument("example.com", DidDocumentOptions{PathSegments: []string{"user", "alice"}, DidProfile: DidProfileK1})
	if err != nil {
		t.Fatalf("CreateDidWBADocument failed: %v", err)
	}
	privateKey, err := anp.PrivateKeyFromPEM(bundle.Keys[VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatalf("PrivateKeyFromPEM failed: %v", err)
	}
	header, err := GenerateAuthHeader(bundle.DidDocument, "api.example.com", privateKey, "1.1")
	if err != nil {
		t.Fatalf("GenerateAuthHeader failed: %v", err)
	}
	if err := VerifyAuthHeaderSignature(header, bundle.DidDocument, "api.example.com"); err != nil {
		t.Fatalf("VerifyAuthHeaderSignature failed: %v", err)
	}
}

func TestHTTPSignaturesTamperFails(t *testing.T) {
	bundle, err := CreateDidWBADocument("example.com", DidDocumentOptions{})
	if err != nil {
		t.Fatalf("CreateDidWBADocument failed: %v", err)
	}
	privateKey, err := anp.PrivateKeyFromPEM(bundle.Keys[VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatalf("PrivateKeyFromPEM failed: %v", err)
	}
	headers, err := GenerateHTTPSignatureHeaders(bundle.DidDocument, "https://api.example.com/orders", http.MethodPost, privateKey, map[string]string{}, []byte(`{"item":"book"}`), HttpSignatureOptions{})
	if err != nil {
		t.Fatalf("GenerateHTTPSignatureHeaders failed: %v", err)
	}
	if _, err := VerifyHTTPMessageSignature(bundle.DidDocument, http.MethodPost, "https://api.example.com/orders", headers, []byte(`{"item":"book"}`)); err != nil {
		t.Fatalf("VerifyHTTPMessageSignature failed: %v", err)
	}
	if _, err := VerifyHTTPMessageSignature(bundle.DidDocument, http.MethodPost, "https://api.example.com/orders", headers, []byte(`{"item":"music"}`)); err == nil {
		t.Fatalf("expected tampered body verification failure")
	}
}

func TestResolveDidDocumentWithOverride(t *testing.T) {
	bundle, err := CreateDidWBADocument("example.com", DidDocumentOptions{PathSegments: []string{"user", "alice"}})
	if err != nil {
		t.Fatalf("CreateDidWBADocument failed: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user/alice/e1_"+stringValue(bundle.DidDocument["id"])[len("did:wba:example.com:user:alice:e1_"):]+"/did.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(bundle.DidDocument)
	}))
	defer server.Close()
	if _, err := ResolveDidWBADocumentWithOptions(context.Background(), stringValue(bundle.DidDocument["id"]), true, DidResolutionOptions{BaseURLOverride: server.URL, VerifySSL: boolPtr(false)}); err != nil {
		t.Fatalf("ResolveDidWBADocumentWithOptions failed: %v", err)
	}
}

func contains(value string, needle string) bool {
	return strings.Contains(value, needle)
}

func boolPtr(value bool) *bool {
	return &value
}
