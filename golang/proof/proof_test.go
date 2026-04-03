package proof

import (
	"testing"

	anp "github.com/agent-network-protocol/anp/golang"
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
	signed, err := GenerateW3CProof(document, privateKey, "did:wba:example.com:alice#key-1", GenerationOptions{})
	if err != nil {
		t.Fatalf("GenerateW3CProof failed: %v", err)
	}
	if !VerifyW3CProof(signed, publicKey, VerificationOptions{}) {
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
	signed, err := GenerateW3CProof(document, privateKey, "did:wba:example.com:bob#key-1", GenerationOptions{ProofType: ProofTypeDataIntegrity, Cryptosuite: CryptosuiteEddsaJCS2022})
	if err != nil {
		t.Fatalf("GenerateW3CProof failed: %v", err)
	}
	if !VerifyW3CProof(signed, publicKey, VerificationOptions{}) {
		t.Fatalf("VerifyW3CProof returned false")
	}
}

func TestGroupReceiptProof(t *testing.T) {
	privateKey, err := anp.GeneratePrivateKeyMaterial(anp.KeyTypeSecp256k1)
	if err != nil {
		t.Fatalf("GeneratePrivateKeyMaterial failed: %v", err)
	}
	publicKey, err := privateKey.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	receipt := map[string]any{
		"receipt_type":        "anp.group_receipt.v1",
		"group_did":           "did:wba:groups.example:team:dev:e1_group_dev",
		"group_state_version": "43",
		"subject_method":      "group.send",
		"operation_id":        "op-group-send-001",
		"actor_did":           "did:wba:a.example:agents:alice:e1_alice",
		"accepted_at":         "2026-03-29T15:10:01Z",
		"payload_digest":      "sha-256=:stub:",
	}
	signed, err := GenerateGroupReceiptProof(receipt, privateKey, "did:wba:groups.example:team:dev:e1_group_dev#key-1")
	if err != nil {
		t.Fatalf("GenerateGroupReceiptProof failed: %v", err)
	}
	if err := VerifyGroupReceiptProof(signed, publicKey); err != nil {
		t.Fatalf("VerifyGroupReceiptProof failed: %v", err)
	}
}
