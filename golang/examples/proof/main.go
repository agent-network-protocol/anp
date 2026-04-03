package main

import (
	"fmt"
	"log"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/proof"
)

func main() {
	privateKey, err := anp.GeneratePrivateKeyMaterial(anp.KeyTypeSecp256k1)
	if err != nil {
		log.Fatalf("GeneratePrivateKeyMaterial failed: %v", err)
	}
	publicKey, _ := privateKey.PublicKey()
	document := map[string]any{"id": "did:wba:example.com:agents:alice", "type": "AgentIdentityClaim", "name": "Agent Alice", "capabilities": []any{"search", "booking", "payment"}}
	signed, err := proof.GenerateW3CProof(document, privateKey, "did:wba:example.com:agents:alice#key-1", proof.GenerationOptions{})
	if err != nil {
		log.Fatalf("GenerateW3CProof failed: %v", err)
	}
	fmt.Println("secp256k1 verification:", proof.VerifyW3CProof(signed, publicKey, proof.VerificationOptions{}))
}
