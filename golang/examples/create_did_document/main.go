package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/agent-network-protocol/anp/golang/authentication"
)

func main() {
	profile := flag.String("profile", string(authentication.DidProfileE1), "DID profile: e1, k1, plain_legacy")
	hostname := flag.String("hostname", "demo.agent-network", "DID hostname")
	flag.Parse()
	bundle, err := authentication.CreateDidWBADocument(*hostname, authentication.DidDocumentOptions{DidProfile: authentication.DidProfile(*profile), PathSegments: []string{"agents", "demo"}, AgentDescriptionURL: "https://" + *hostname + "/agents/demo"})
	if err != nil {
		log.Fatalf("CreateDidWBADocument failed: %v", err)
	}
	outputDir := filepath.Join("examples", "generated", *profile)
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		log.Fatalf("MkdirAll failed: %v", err)
	}
	didPath := filepath.Join(outputDir, "did.json")
	data, _ := json.MarshalIndent(bundle.DidDocument, "", "  ")
	if err := os.WriteFile(didPath, data, 0o644); err != nil {
		log.Fatalf("WriteFile failed: %v", err)
	}
	fmt.Println("DID document saved to", didPath)
	for fragment, pair := range bundle.Keys {
		privatePath := filepath.Join(outputDir, fragment+"_private.pem")
		publicPath := filepath.Join(outputDir, fragment+"_public.pem")
		_ = os.WriteFile(privatePath, []byte(pair.PrivateKeyPEM), 0o600)
		_ = os.WriteFile(publicPath, []byte(pair.PublicKeyPEM), 0o644)
		fmt.Println("Registered verification method", fragment, "->", privatePath, publicPath)
	}
	fmt.Println("Generated DID identifier:", bundle.DidDocument["id"])
}
