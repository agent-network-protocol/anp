package proof_test

import (
	"bytes"
	"strings"
	"testing"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/authentication"
	"github.com/agent-network-protocol/anp/golang/proof"
)

func TestCanonicalizeSignedRequestObjectOmitsWrapperFields(t *testing.T) {
	value, err := proof.BuildSignedRequestObject(
		"direct.send",
		map[string]any{
			"anp_version":      "1.0",
			"profile":          "anp.direct.base.v1",
			"security_profile": "transport-protected",
			"sender_did":       "did:wba:example.com:user:alice:e1_alice",
			"target": map[string]any{
				"kind": "agent",
				"did":  "did:wba:example.com:user:bob:e1_bob",
			},
			"operation_id": "op-1",
			"message_id":   "msg-1",
			"content_type": "text/plain",
		},
		map[string]any{"text": "hello"},
	)
	if err != nil {
		t.Fatalf("BuildSignedRequestObject failed: %v", err)
	}
	canonical, err := proof.CanonicalizeSignedRequestObject(value)
	if err != nil {
		t.Fatalf("CanonicalizeSignedRequestObject failed: %v", err)
	}
	for _, token := range [][]byte{[]byte(`"auth"`), []byte(`"client"`), []byte(`"jsonrpc"`), []byte(`"id"`)} {
		if bytes.Contains(canonical, token) {
			t.Fatalf("canonical request should not contain %s", token)
		}
	}
}

func TestBuildLogicalTargetURIUsesPercentEncodedDID(t *testing.T) {
	uri, err := proof.BuildLogicalTargetURI(proof.TargetKindService, "did:wba:example.com:services:message:e1_service")
	if err != nil {
		t.Fatalf("BuildLogicalTargetURI failed: %v", err)
	}
	expected := "anp://service/did%3Awba%3Aexample.com%3Aservices%3Amessage%3Ae1_service"
	if uri != expected {
		t.Fatalf("unexpected target URI: got %s want %s", uri, expected)
	}
}

func TestGenerateAndVerifyDirectRFC9421OriginProof(t *testing.T) {
	bundle, err := authentication.CreateDidWBADocument("example.com", authentication.DidDocumentOptions{PathSegments: []string{"user", "alice"}})
	if err != nil {
		t.Fatalf("CreateDidWBADocument failed: %v", err)
	}
	privateKey, err := anp.PrivateKeyFromPEM(bundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatalf("PrivateKeyFromPEM failed: %v", err)
	}
	did := stringValue(bundle.DidDocument["id"])
	meta := map[string]any{
		"anp_version":      "1.0",
		"profile":          "anp.direct.base.v1",
		"security_profile": "transport-protected",
		"sender_did":       did,
		"target": map[string]any{
			"kind": "agent",
			"did":  "did:wba:example.com:user:bob:e1_bob",
		},
		"operation_id": "op-1",
		"message_id":   "msg-1",
		"content_type": "text/plain",
	}
	body := map[string]any{"text": "hello"}
	originProof, err := proof.GenerateRFC9421OriginProof(
		"direct.send",
		meta,
		body,
		privateKey,
		did+"#key-1",
		proof.RFC9421OriginProofGenerationOptions{Created: int64Ptr(1712000000), Nonce: "nonce-1"},
	)
	if err != nil {
		t.Fatalf("GenerateRFC9421OriginProof failed: %v", err)
	}
	result, err := proof.VerifyRFC9421OriginProof(originProof, "direct.send", meta, body, proof.RFC9421OriginProofVerificationOptions{DidDocument: bundle.DidDocument, ExpectedSignerDID: did})
	if err != nil {
		t.Fatalf("VerifyRFC9421OriginProof failed: %v", err)
	}
	if result.ParsedSignatureInput.Label != proof.RFC9421OriginProofDefaultLabel {
		t.Fatalf("unexpected label: %s", result.ParsedSignatureInput.Label)
	}
	if !sameStrings(result.ParsedSignatureInput.Components, proof.RFC9421OriginProofDefaultComponents) {
		t.Fatalf("unexpected covered components: %#v", result.ParsedSignatureInput.Components)
	}
}

func TestGenerateAndVerifyGroupCreateRFC9421OriginProof(t *testing.T) {
	bundle, err := authentication.CreateDidWBADocument("example.com", authentication.DidDocumentOptions{PathSegments: []string{"user", "alice"}})
	if err != nil {
		t.Fatalf("CreateDidWBADocument failed: %v", err)
	}
	privateKey, err := anp.PrivateKeyFromPEM(bundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatalf("PrivateKeyFromPEM failed: %v", err)
	}
	did := stringValue(bundle.DidDocument["id"])
	meta := map[string]any{
		"anp_version":      "1.0",
		"profile":          "anp.group.base.v1",
		"security_profile": "transport-protected",
		"sender_did":       did,
		"target": map[string]any{
			"kind": "service",
			"did":  "did:wba:example.com:services:message:e1_service",
		},
		"operation_id": "op-group-create-1",
		"content_type": "application/json",
	}
	body := map[string]any{
		"group_profile": map[string]any{"display_name": "Demo"},
		"group_policy": map[string]any{
			"admission_mode": "open-join",
			"permissions": map[string]any{
				"send":           "member",
				"add":            "admin",
				"remove":         "admin",
				"update_profile": "admin",
				"update_policy":  "owner",
			},
		},
	}
	originProof, err := proof.GenerateRFC9421OriginProof(
		"group.create",
		meta,
		body,
		privateKey,
		did+"#key-1",
		proof.RFC9421OriginProofGenerationOptions{Created: int64Ptr(1712000100), Nonce: "nonce-group-create"},
	)
	if err != nil {
		t.Fatalf("GenerateRFC9421OriginProof failed: %v", err)
	}
	result, err := proof.VerifyRFC9421OriginProof(originProof, "group.create", meta, body, proof.RFC9421OriginProofVerificationOptions{DidDocument: bundle.DidDocument, ExpectedSignerDID: did})
	if err != nil {
		t.Fatalf("VerifyRFC9421OriginProof failed: %v", err)
	}
	if result.ParsedSignatureInput.Nonce != "nonce-group-create" {
		t.Fatalf("unexpected nonce: %s", result.ParsedSignatureInput.Nonce)
	}
}

func TestRejectsNonSig1RFC9421OriginProofLabel(t *testing.T) {
	bundle, err := authentication.CreateDidWBADocument("example.com", authentication.DidDocumentOptions{PathSegments: []string{"user", "alice"}})
	if err != nil {
		t.Fatalf("CreateDidWBADocument failed: %v", err)
	}
	privateKey, err := anp.PrivateKeyFromPEM(bundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatalf("PrivateKeyFromPEM failed: %v", err)
	}
	did := stringValue(bundle.DidDocument["id"])
	meta := map[string]any{
		"anp_version":      "1.0",
		"profile":          "anp.direct.base.v1",
		"security_profile": "transport-protected",
		"sender_did":       did,
		"target":           map[string]any{"kind": "agent", "did": "did:wba:example.com:user:bob:e1_bob"},
		"operation_id":     "op-2",
		"message_id":       "msg-2",
		"content_type":     "text/plain",
	}
	_, err = proof.GenerateRFC9421OriginProof("direct.send", meta, map[string]any{"text": "hello"}, privateKey, did+"#key-1", proof.RFC9421OriginProofGenerationOptions{Label: "sig2"})
	if err == nil || !strings.Contains(err.Error(), "signature label sig1") {
		t.Fatalf("expected sig1 label failure, got: %v", err)
	}
}

func TestRejectsRFC9421OriginProofWithExtraComponent(t *testing.T) {
	bundle, err := authentication.CreateDidWBADocument("example.com", authentication.DidDocumentOptions{PathSegments: []string{"user", "alice"}})
	if err != nil {
		t.Fatalf("CreateDidWBADocument failed: %v", err)
	}
	privateKey, err := anp.PrivateKeyFromPEM(bundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatalf("PrivateKeyFromPEM failed: %v", err)
	}
	did := stringValue(bundle.DidDocument["id"])
	meta := map[string]any{
		"anp_version":      "1.0",
		"profile":          "anp.direct.base.v1",
		"security_profile": "transport-protected",
		"sender_did":       did,
		"target":           map[string]any{"kind": "agent", "did": "did:wba:example.com:user:bob:e1_bob"},
		"operation_id":     "op-3",
		"message_id":       "msg-3",
		"content_type":     "text/plain",
	}
	body := map[string]any{"text": "hello"}
	originProof, err := proof.GenerateRFC9421OriginProof("direct.send", meta, body, privateKey, did+"#key-1", proof.RFC9421OriginProofGenerationOptions{Created: int64Ptr(1712000200), Nonce: "nonce-extra-component"})
	if err != nil {
		t.Fatalf("GenerateRFC9421OriginProof failed: %v", err)
	}
	originProof.SignatureInput = strings.Replace(
		originProof.SignatureInput,
		"(\"@method\" \"@target-uri\" \"content-digest\")",
		"(\"@method\" \"@target-uri\" \"content-digest\" \"@authority\")",
		1,
	)
	_, err = proof.VerifyRFC9421OriginProof(originProof, "direct.send", meta, body, proof.RFC9421OriginProofVerificationOptions{DidDocument: bundle.DidDocument, ExpectedSignerDID: did})
	if err == nil || !strings.Contains(err.Error(), "covered components") {
		t.Fatalf("expected covered-components failure, got: %v", err)
	}
}

func sameStrings(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
