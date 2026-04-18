package anp

import (
	"encoding/pem"
	"strings"
	"testing"
)

func TestGeneratedKeyPairPEMUsesStandardLabels(t *testing.T) {
	for _, keyType := range []KeyType{KeyTypeEd25519, KeyTypeSecp256k1, KeyTypeSecp256r1, KeyTypeX25519} {
		t.Run(string(keyType), func(t *testing.T) {
			privateKey, publicKey, pair, err := GenerateKeyPairPEM(keyType)
			if err != nil {
				t.Fatalf("GenerateKeyPairPEM failed: %v", err)
			}
			if firstLine(pair.PrivateKeyPEM) != "-----BEGIN PRIVATE KEY-----" {
				t.Fatalf("private key must be PKCS#8 PEM, got %q", firstLine(pair.PrivateKeyPEM))
			}
			if firstLine(pair.PublicKeyPEM) != "-----BEGIN PUBLIC KEY-----" {
				t.Fatalf("public key must be SPKI PEM, got %q", firstLine(pair.PublicKeyPEM))
			}
			if strings.Contains(pair.PrivateKeyPEM, "ANP ") || strings.Contains(pair.PublicKeyPEM, "ANP ") {
				t.Fatalf("generated PEM must not contain legacy ANP labels")
			}
			parsedPrivate, err := PrivateKeyFromPEM(pair.PrivateKeyPEM)
			if err != nil {
				t.Fatalf("PrivateKeyFromPEM failed: %v", err)
			}
			parsedPublic, err := PublicKeyFromPEM(pair.PublicKeyPEM)
			if err != nil {
				t.Fatalf("PublicKeyFromPEM failed: %v", err)
			}
			if parsedPrivate.Type != privateKey.Type || parsedPublic.Type != publicKey.Type {
				t.Fatalf("parsed key types do not match generated key types")
			}
			if parsedPublic.Type != KeyTypeX25519 {
				signature, err := parsedPrivate.SignMessage([]byte("standard pem"))
				if err != nil {
					t.Fatalf("SignMessage failed: %v", err)
				}
				if err := parsedPublic.VerifyMessage([]byte("standard pem"), signature); err != nil {
					t.Fatalf("VerifyMessage failed: %v", err)
				}
			}
		})
	}
}

func TestLegacyANPPEMRejectedByRuntimeParsers(t *testing.T) {
	legacyPrivate := string(pem.EncodeToMemory(&pem.Block{
		Type:  "ANP ED25519 PRIVATE KEY",
		Bytes: make([]byte, 32),
	}))
	if _, err := PrivateKeyFromPEM(legacyPrivate); err == nil {
		t.Fatalf("PrivateKeyFromPEM must reject legacy ANP private labels")
	}

	legacyPublic := string(pem.EncodeToMemory(&pem.Block{
		Type:  "ANP ED25519 PUBLIC KEY",
		Bytes: make([]byte, 32),
	}))
	if _, err := PublicKeyFromPEM(legacyPublic); err == nil {
		t.Fatalf("PublicKeyFromPEM must reject legacy ANP public labels")
	}
}

func firstLine(value string) string {
	if index := strings.IndexByte(value, '\n'); index >= 0 {
		return value[:index]
	}
	return value
}
