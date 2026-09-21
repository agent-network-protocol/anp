package authentication

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/proof"
)

func TestWebHTTPAuthBearerAndNegativeBoundaries(t *testing.T) {
	const did = "did:web:example.com:users:e1_web-path"
	keyID := did + "#request"
	private, err := anp.GeneratePrivateKeyMaterial(anp.KeyTypeEd25519)
	if err != nil {
		t.Fatal(err)
	}
	public, err := private.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := anp.PublicKeyToJWK(public)
	if err != nil {
		t.Fatal(err)
	}
	document := map[string]any{"id": did, "verificationMethod": []any{map[string]any{"id": keyID, "controller": did,
		"type": "JsonWebKey2020", "publicKeyJwk": jwk}}, "authentication": []any{keyID}, "assertionMethod": []any{keyID}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(document) }))
	defer server.Close()
	url, body := "https://api.example.com/orders", []byte(`{"item":"book"}`)
	headers, err := GenerateHTTPSignatureHeaders(document, url, "POST", private, nil, body, HttpSignatureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	verifier := NewDidWbaVerifier(DidWbaVerifierConfig{JWTAlgorithm: "HS256", JWTPrivateKey: "unit-test-secret-32-bytes-minimum", JWTPublicKey: "unit-test-secret-32-bytes-minimum", DidResolutionOptions: DidResolutionOptions{BaseURLOverride: server.URL}})
	for _, changed := range []struct {
		url  string
		body []byte
	}{{url + "/other", body}, {url, []byte(`{"item":"music"}`)}} {
		if _, err := verifier.VerifyRequestWithDidDocument("POST", changed.url, headers, changed.body, "", document); err == nil {
			t.Fatal("accepted tamper")
		}
	}
	first, err := verifier.VerifyRequest(context.Background(), "POST", url, headers, body, "")
	if err != nil || first.DID != did {
		t.Fatalf("Web authentication failed: %v", err)
	}
	if _, err := verifier.VerifyRequestWithDidDocument("POST", url, headers, body, "", document); err == nil {
		t.Fatal("accepted replay")
	}
	bearer, err := verifier.VerifyRequest(context.Background(), "POST", url, map[string]string{"Authorization": "Bearer " + first.AccessToken}, body, "")
	if err != nil || bearer.DID != did {
		t.Fatalf("Web bearer failed: %v", err)
	}
	assertionOnly := cloneMap(document)
	delete(assertionOnly, "authentication")
	groupObject, err := proof.GenerateObjectProof(map[string]any{"group_did": did, "epoch": 3}, private, keyID, did, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proof.VerifyObjectProof(groupObject, did, assertionOnly); err != nil {
		t.Fatalf("assertion-only Group proof failed: %v", err)
	}
	groupObject["epoch"] = 4
	if _, err := proof.VerifyObjectProof(groupObject, did, assertionOnly); err == nil {
		t.Fatal("accepted tampered Group object")
	}
	if _, err := verifier.VerifyRequestWithDidDocument("POST", url, headers, body, "", assertionOnly); err == nil {
		t.Fatal("assertion key granted authentication")
	}
}
