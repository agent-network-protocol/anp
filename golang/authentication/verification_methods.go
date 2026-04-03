package authentication

import (
	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/internal/vm"
)

// CreateVerificationMethod parses a DID verification method entry.
func CreateVerificationMethod(method map[string]any) (VerificationMethod, error) {
	return vm.CreateVerificationMethod(method)
}

// ExtractPublicKey extracts public key material from a DID verification method entry.
func ExtractPublicKey(method map[string]any) (anp.PublicKeyMaterial, error) {
	return vm.ExtractPublicKey(method)
}
