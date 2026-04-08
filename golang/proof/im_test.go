package proof_test

import (
	"fmt"
	"strings"
	"testing"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/authentication"
	"github.com/agent-network-protocol/anp/golang/proof"
)

func TestGenerateAndVerifyE1IMProof(t *testing.T) {
	bundle, err := authentication.CreateDidWBADocument("example.com", authentication.DidDocumentOptions{PathSegments: []string{"user", "alice"}})
	if err != nil {
		t.Fatalf("CreateDidWBADocument failed: %v", err)
	}
	privateKey, err := anp.PrivateKeyFromPEM(bundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatalf("PrivateKeyFromPEM failed: %v", err)
	}
	did := stringValue(bundle.DidDocument["id"])
	payload := []byte(`{"text":"hello"}`)
	signatureInput, err := proof.BuildIMSignatureInput(did+"#key-1", proof.IMGenerationOptions{Nonce: "nonce-1", Created: int64Ptr(1712000000)})
	if err != nil {
		t.Fatalf("proof.BuildIMSignatureInput failed: %v", err)
	}
	signatureBase := buildBusinessSignatureBase("direct.send", "anp://agent/"+did, proof.BuildIMContentDigest(payload), signatureInput)
	proofValue, err := proof.GenerateIMProof(payload, signatureBase, privateKey, did+"#key-1", proof.IMGenerationOptions{Nonce: "nonce-1", Created: int64Ptr(1712000000)})
	if err != nil {
		t.Fatalf("proof.GenerateIMProof failed: %v", err)
	}
	result, err := proof.VerifyIMProofWithDocument(proofValue, payload, buildBusinessSignatureBase("direct.send", "anp://agent/"+did, proofValue.ContentDigest, proofValue.SignatureInput), bundle.DidDocument, did)
	if err != nil {
		t.Fatalf("proof.VerifyIMProofWithDocument failed: %v", err)
	}
	if result.ParsedSignatureInput.KeyID != did+"#key-1" {
		t.Fatalf("unexpected keyID: %s", result.ParsedSignatureInput.KeyID)
	}
}

func TestVerifyIMProofDefaultsToAuthenticationRelationship(t *testing.T) {
	bundle, err := authentication.CreateDidWBADocument("example.com", authentication.DidDocumentOptions{PathSegments: []string{"user", "assertion-only"}})
	if err != nil {
		t.Fatalf("CreateDidWBADocument failed: %v", err)
	}
	privateKey, err := anp.PrivateKeyFromPEM(bundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatalf("PrivateKeyFromPEM failed: %v", err)
	}
	did := stringValue(bundle.DidDocument["id"])
	payload := []byte(`{"text":"hello"}`)
	signatureInput, err := proof.BuildIMSignatureInput(did+"#key-1", proof.IMGenerationOptions{Nonce: "nonce-auth", Created: int64Ptr(1712000200)})
	if err != nil {
		t.Fatalf("proof.BuildIMSignatureInput failed: %v", err)
	}
	signatureBase := buildBusinessSignatureBase("direct.send", "anp://agent/"+did, proof.BuildIMContentDigest(payload), signatureInput)
	proofValue, err := proof.GenerateIMProof(payload, signatureBase, privateKey, did+"#key-1", proof.IMGenerationOptions{Nonce: "nonce-auth", Created: int64Ptr(1712000200)})
	if err != nil {
		t.Fatalf("proof.GenerateIMProof failed: %v", err)
	}
	didDocument := cloneTopLevelMap(bundle.DidDocument)
	didDocument["authentication"] = []any{}
	if _, err := proof.VerifyIMProofWithDocument(proofValue, payload, buildBusinessSignatureBase("direct.send", "anp://agent/"+did, proofValue.ContentDigest, proofValue.SignatureInput), didDocument, did); err == nil || !strings.Contains(err.Error(), "authorized for authentication") {
		t.Fatalf("expected authentication authorization failure, got: %v", err)
	}
	if _, err := proof.VerifyIMProofWithDocumentForRelationship(proofValue, payload, buildBusinessSignatureBase("direct.send", "anp://agent/"+did, proofValue.ContentDigest, proofValue.SignatureInput), didDocument, did, proof.IMProofRelationshipAssertionMethod); err != nil {
		t.Fatalf("proof.VerifyIMProofWithDocumentForRelationship failed: %v", err)
	}
}

func TestVerifyIMProofRequiresExactSignerDIDMatch(t *testing.T) {
	bundle, err := authentication.CreateDidWBADocument("example.com", authentication.DidDocumentOptions{PathSegments: []string{"user", "prefix-check"}})
	if err != nil {
		t.Fatalf("CreateDidWBADocument failed: %v", err)
	}
	privateKey, err := anp.PrivateKeyFromPEM(bundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatalf("PrivateKeyFromPEM failed: %v", err)
	}
	did := stringValue(bundle.DidDocument["id"])
	payload := []byte(`{"text":"hello"}`)
	signatureInput, err := proof.BuildIMSignatureInput(did+"#key-1", proof.IMGenerationOptions{Nonce: "nonce-prefix", Created: int64Ptr(1712000300)})
	if err != nil {
		t.Fatalf("proof.BuildIMSignatureInput failed: %v", err)
	}
	signatureBase := buildBusinessSignatureBase("direct.send", "anp://agent/"+did, proof.BuildIMContentDigest(payload), signatureInput)
	proofValue, err := proof.GenerateIMProof(payload, signatureBase, privateKey, did+"#key-1", proof.IMGenerationOptions{Nonce: "nonce-prefix", Created: int64Ptr(1712000300)})
	if err != nil {
		t.Fatalf("proof.GenerateIMProof failed: %v", err)
	}
	if _, err := proof.VerifyIMProofWithDocument(proofValue, payload, buildBusinessSignatureBase("direct.send", "anp://agent/"+did, proofValue.ContentDigest, proofValue.SignatureInput), bundle.DidDocument, "did:wba:example.com:user:prefix-check"); err == nil || !strings.Contains(err.Error(), "expected signer DID") {
		t.Fatalf("expected exact DID mismatch failure, got: %v", err)
	}
}

func buildBusinessSignatureBase(method string, targetURI string, contentDigest string, signatureInput string) []byte {
	parsed, err := proof.ParseIMSignatureInput(signatureInput)
	if err != nil {
		panic(err)
	}
	componentValues := map[string]string{
		"@method":        method,
		"@target-uri":    targetURI,
		"content-digest": contentDigest,
	}
	lines := make([]string, 0, len(parsed.Components)+1)
	for _, component := range parsed.Components {
		lines = append(lines, fmt.Sprintf("\"%s\": %s", component, componentValues[component]))
	}
	lines = append(lines, fmt.Sprintf("\"@signature-params\": %s", parsed.SignatureParams))
	return []byte(strings.Join(lines, "\n"))
}

func cloneTopLevelMap(value map[string]any) map[string]any {
	result := make(map[string]any, len(value))
	for key, entry := range value {
		result[key] = entry
	}
	return result
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func int64Ptr(value int64) *int64 {
	return &value
}
