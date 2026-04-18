package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/authentication"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		exitf("Usage: anp-interop <did-fixture|verify-key-fixture> [options]")
	}

	switch args[0] {
	case "did-fixture":
		runDIDFixture(args[1:])
	case "verify-key-fixture":
		runVerifyKeyFixture(args[1:])
	default:
		exitf("unsupported subcommand: %s", args[0])
	}
}

func runDIDFixture(args []string) {
	profile := authentication.DidProfile(readOption(args, "--profile", string(authentication.DidProfileE1)))
	hostname := readOption(args, "--hostname", "example.com")
	bundle, err := authentication.CreateDidWBADocument(hostname, authentication.DidDocumentOptions{
		PathSegments: []string{"user", "interop"},
		DidProfile:   profile,
	})
	if err != nil {
		exitf("CreateDidWBADocument failed: %v", err)
	}
	writeJSON(map[string]any{
		"profile":      profile,
		"did_document": bundle.DidDocument,
		"keys":         bundle.Keys,
	})
}

func runVerifyKeyFixture(args []string) {
	fixturePath := readOption(args, "--fixture", "")
	if fixturePath == "" {
		exitf("--fixture is required")
	}
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		exitf("read fixture failed: %v", err)
	}
	var fixture struct {
		Keys map[string]anp.GeneratedKeyPairPEM `json:"keys"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		exitf("decode fixture failed: %v", err)
	}
	for fragment, pair := range fixture.Keys {
		if !strings.HasPrefix(pair.PrivateKeyPEM, "-----BEGIN PRIVATE KEY-----") {
			exitf("%s private key must be PKCS#8 PEM", fragment)
		}
		if !strings.HasPrefix(pair.PublicKeyPEM, "-----BEGIN PUBLIC KEY-----") {
			exitf("%s public key must be SPKI PEM", fragment)
		}
		if strings.Contains(pair.PrivateKeyPEM, "ANP ") || strings.Contains(pair.PublicKeyPEM, "ANP ") {
			exitf("%s key pair must not use legacy ANP PEM labels", fragment)
		}
		privateKey, err := anp.PrivateKeyFromPEM(pair.PrivateKeyPEM)
		if err != nil {
			exitf("%s PrivateKeyFromPEM failed: %v", fragment, err)
		}
		publicKey, err := anp.PublicKeyFromPEM(pair.PublicKeyPEM)
		if err != nil {
			exitf("%s PublicKeyFromPEM failed: %v", fragment, err)
		}
		if publicKey.Type != anp.KeyTypeX25519 {
			signature, err := privateKey.SignMessage([]byte("cross-language standard pem"))
			if err != nil {
				exitf("%s SignMessage failed: %v", fragment, err)
			}
			if err := publicKey.VerifyMessage([]byte("cross-language standard pem"), signature); err != nil {
				exitf("%s VerifyMessage failed: %v", fragment, err)
			}
		}
	}
	writeJSON(map[string]any{"verified": true, "key_count": len(fixture.Keys)})
}

func readOption(args []string, name string, fallback string) string {
	for index := 0; index < len(args)-1; index++ {
		if args[index] == name {
			return args[index+1]
		}
	}
	return fallback
}

func writeJSON(value any) {
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		exitf("encode JSON failed: %v", err)
	}
}

func exitf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
