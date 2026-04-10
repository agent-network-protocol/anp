package proof_test

import (
	"testing"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/authentication"
	proof "github.com/agent-network-protocol/anp/golang/proof"
)

func TestGenerateAndVerifySecp256k1Proof(t *testing.T) {
	privateKey, err := anp.GeneratePrivateKeyMaterial(anp.KeyTypeSecp256k1)
	if err != nil {
		t.Fatalf("GeneratePrivateKeyMaterial failed: %v", err)
	}
	publicKey, err := privateKey.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	document := map[string]any{"id": "did:wba:example.com:alice", "claim": "test-data"}
	signed, err := proof.GenerateW3CProof(document, privateKey, "did:wba:example.com:alice#key-1", proof.GenerationOptions{})
	if err != nil {
		t.Fatalf("GenerateW3CProof failed: %v", err)
	}
	if !proof.VerifyW3CProof(signed, publicKey, proof.VerificationOptions{}) {
		t.Fatalf("VerifyW3CProof returned false")
	}
}

func TestGenerateAndVerifyEd25519Proof(t *testing.T) {
	privateKey, err := anp.GeneratePrivateKeyMaterial(anp.KeyTypeEd25519)
	if err != nil {
		t.Fatalf("GeneratePrivateKeyMaterial failed: %v", err)
	}
	publicKey, err := privateKey.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	document := map[string]any{"id": "did:wba:example.com:bob", "type": "VerifiableCredential"}
	signed, err := proof.GenerateW3CProof(document, privateKey, "did:wba:example.com:bob#key-1", proof.GenerationOptions{ProofType: proof.ProofTypeDataIntegrity, Cryptosuite: proof.CryptosuiteEddsaJCS2022})
	if err != nil {
		t.Fatalf("GenerateW3CProof failed: %v", err)
	}
	if !proof.VerifyW3CProof(signed, publicKey, proof.VerificationOptions{}) {
		t.Fatalf("VerifyW3CProof returned false")
	}
}

func TestGroupReceiptProof(t *testing.T) {
	bundle, err := authentication.CreateDidWBADocument("groups.example", authentication.DidDocumentOptions{PathSegments: []string{"team", "dev"}})
	if err != nil {
		t.Fatalf("CreateDidWBADocument failed: %v", err)
	}
	groupDID := testStringValue(bundle.DidDocument["id"])
	privateKey, err := anp.PrivateKeyFromPEM(bundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatalf("PrivateKeyFromPEM failed: %v", err)
	}
	receipt := map[string]any{
		"receipt_type":        "anp.group_receipt.v1",
		"group_did":           groupDID,
		"group_state_version": "43",
		"group_event_seq":     "128",
		"subject_method":      "group.send",
		"operation_id":        "op-group-send-001",
		"message_id":          "msg-group-send-001",
		"actor_did":           "did:wba:a.example:agents:alice:e1_alice",
		"accepted_at":         "2026-03-29T15:10:01Z",
		"payload_digest":      "sha-256=:stub:",
	}
	signed, err := proof.GenerateGroupReceiptProof(receipt, privateKey, groupDID+"#"+authentication.VMKeyAuth)
	if err != nil {
		t.Fatalf("GenerateGroupReceiptProof failed: %v", err)
	}
	proofValue := signed["proof"].(map[string]any)
	if testStringValue(proofValue["cryptosuite"]) != proof.CryptosuiteEddsaJCS2022 {
		t.Fatalf("unexpected cryptosuite: %v", proofValue["cryptosuite"])
	}
	if testStringValue(proofValue["proofValue"]) == "" || testStringValue(proofValue["proofValue"])[0] != 'z' {
		t.Fatalf("expected multibase proofValue, got: %v", proofValue["proofValue"])
	}
	if err := proof.VerifyGroupReceiptProof(signed, bundle.DidDocument); err != nil {
		t.Fatalf("VerifyGroupReceiptProof failed: %v", err)
	}
}

func TestDidWbaBindingProof(t *testing.T) {
	bundle, err := authentication.CreateDidWBADocument("a.example", authentication.DidDocumentOptions{PathSegments: []string{"agents", "alice"}})
	if err != nil {
		t.Fatalf("CreateDidWBADocument failed: %v", err)
	}
	agentDID := testStringValue(bundle.DidDocument["id"])
	privateKey, err := anp.PrivateKeyFromPEM(bundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatalf("PrivateKeyFromPEM failed: %v", err)
	}
	binding, err := proof.GenerateDidWbaBinding(agentDID, agentDID+"#"+authentication.VMKeyAuth, "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY", privateKey, "2026-03-29T12:00:00Z", "2026-04-29T12:00:00Z", "2026-03-29T12:00:00Z")
	if err != nil {
		t.Fatalf("GenerateDidWbaBinding failed: %v", err)
	}
	proofValue := binding["proof"].(map[string]any)
	if testStringValue(proofValue["proofValue"]) == "" || testStringValue(proofValue["proofValue"])[0] != 'z' {
		t.Fatalf("expected multibase proofValue, got: %v", proofValue["proofValue"])
	}
	if err := proof.VerifyDidWbaBinding(binding, bundle.DidDocument, proof.DidWbaBindingVerificationOptions{Now: "2026-03-30T12:00:00Z", ExpectedCredentialIdentity: agentDID}); err != nil {
		t.Fatalf("VerifyDidWbaBinding failed: %v", err)
	}
}

func testStringValue(value any) string {
	result, _ := value.(string)
	return result
}
