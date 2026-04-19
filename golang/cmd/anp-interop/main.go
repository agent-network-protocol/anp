package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/authentication"
	proof "github.com/agent-network-protocol/anp/golang/proof"
	"github.com/agent-network-protocol/anp/golang/wns"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		exitf("Usage: anp-interop <did-fixture|verify-key-fixture|auth-fixture|verify-auth-fixture|proof-fixture|verify-proof-fixture|wns-fixture|verify-wns-fixture> [options]")
	}

	switch args[0] {
	case "did-fixture":
		runDIDFixture(args[1:])
	case "verify-key-fixture":
		runVerifyKeyFixture(args[1:])
	case "auth-fixture":
		runAuthFixture(args[1:])
	case "verify-auth-fixture":
		runVerifyAuthFixture(args[1:])
	case "proof-fixture":
		runProofFixture(args[1:])
	case "verify-proof-fixture":
		runVerifyProofFixture(args[1:])
	case "wns-fixture":
		runWNSFixture(args[1:])
	case "verify-wns-fixture":
		runVerifyWNSFixture(args[1:])
	default:
		exitf("unsupported subcommand: %s", args[0])
	}
}

func runDIDFixture(args []string) {
	bundle := createBundle(args)
	writeJSON(map[string]any{"profile": readOption(args, "--profile", string(authentication.DidProfileE1)), "did_document": bundle.DidDocument, "keys": bundle.Keys})
}

func runAuthFixture(args []string) {
	scheme := readOption(args, "--scheme", "legacy")
	method := readOption(args, "--method", "POST")
	requestURL := readOption(args, "--url", "https://api.example.com/orders")
	body := []byte(readOption(args, "--body", `{"item":"book"}`))
	serviceDomain := readOption(args, "--service-domain", "api.example.com")
	bundle := createBundle(args)
	privateKey := mustPrivate(bundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	fixture := map[string]any{"scheme": scheme, "profile": readOption(args, "--profile", string(authentication.DidProfileE1)), "did_document": bundle.DidDocument, "keys": bundle.Keys, "request_url": requestURL, "method": method, "body": string(body), "service_domain": serviceDomain}
	switch scheme {
	case "legacy":
		authorization, err := authentication.GenerateAuthHeader(bundle.DidDocument, serviceDomain, privateKey, "1.1")
		must(err)
		authJSON, err := authentication.GenerateAuthJSON(bundle.DidDocument, serviceDomain, privateKey, "1.1")
		must(err)
		fixture["authorization"] = authorization
		fixture["auth_json"] = authJSON
	case "http":
		headers, err := authentication.GenerateHTTPSignatureHeaders(bundle.DidDocument, requestURL, method, privateKey, map[string]string{"Content-Type": "application/json"}, body, authentication.HttpSignatureOptions{})
		must(err)
		fixture["headers"] = headers
	default:
		exitf("unsupported auth scheme: %s", scheme)
	}
	writeJSON(fixture)
}

func runVerifyAuthFixture(args []string) {
	fixture := readFixture(readOption(args, "--fixture", ""))
	didDocument := asMap(fixture["did_document"])
	scheme := stringValue(fixture["scheme"])
	if scheme == "" && fixture["headers"] != nil {
		scheme = "http"
	}
	if scheme == "" {
		scheme = "legacy"
	}
	switch scheme {
	case "legacy":
		must(authentication.VerifyAuthHeaderSignature(stringValue(fixture["authorization"]), didDocument, stringValue(fixture["service_domain"])))
		if authJSON := stringValue(fixture["auth_json"]); authJSON != "" {
			must(authentication.VerifyAuthJSONSignature(authJSON, didDocument, stringValue(fixture["service_domain"])))
		}
	case "http":
		_, err := authentication.VerifyHTTPMessageSignature(didDocument, stringValue(fixture["method"]), stringValue(fixture["request_url"]), toStringMap(asMap(fixture["headers"])), []byte(stringValue(fixture["body"])))
		must(err)
	default:
		exitf("unsupported auth scheme: %s", scheme)
	}
	writeJSON(map[string]any{"verified": true, "scheme": scheme})
}

func runProofFixture(args []string) {
	caseName := readOption(args, "--case", "w3c-ed25519")
	keyType := anp.KeyTypeEd25519
	if strings.Contains(caseName, "secp256k1") || readOption(args, "--profile", "") == "k1" {
		keyType = anp.KeyTypeSecp256k1
	}
	privateKey, publicKey, pair, err := anp.GenerateKeyPairPEM(keyType)
	must(err)
	document := map[string]any{"id": "urn:example:proof", "claim": "test-data"}
	verificationMethod := "did:wba:example.com:user:proof#key-1"
	signed, err := proof.GenerateW3CProof(document, privateKey, verificationMethod, proof.GenerationOptions{})
	must(err)
	writeJSON(map[string]any{"case": caseName, "document": document, "signed_document": signed, "verification_method": verificationMethod, "keys": map[string]any{"key-1": pair}, "public_key": publicKey})
}

func runVerifyProofFixture(args []string) {
	fixture := readFixture(readOption(args, "--fixture", ""))
	signed := asMap(fixture["signed_document"])
	keys := asMap(fixture["keys"])
	pair := asMap(keys["key-1"])
	publicKey := mustPublic(stringValue(pair["public_key_pem"]))
	if !proof.VerifyW3CProof(signed, publicKey, proof.VerificationOptions{}) {
		exitf("proof verification failed")
	}
	writeJSON(map[string]any{"verified": true, "case": stringValue(fixture["case"])})
}

func runWNSFixture(args []string) {
	handle := readOption(args, "--handle", "alice.example.com")
	localPart, domain, err := wns.ValidateHandle(handle)
	must(err)
	did := "did:wba:" + domain + ":user:" + localPart
	service := wns.BuildHandleServiceEntry(did, localPart, domain)
	didDocument := map[string]any{"id": did, "service": []any{map[string]any{"id": service.ID, "type": service.Type, "serviceEndpoint": service.ServiceEndpoint}}}
	writeJSON(map[string]any{"handle": localPart + "." + domain, "uri": wns.BuildWBAURI(localPart, domain), "local_part": localPart, "domain": domain, "resolution_url": wns.BuildResolutionURL(localPart, domain), "did": did, "did_document": didDocument})
}

func runVerifyWNSFixture(args []string) {
	fixture := readFixture(readOption(args, "--fixture", ""))
	localPart, domain, err := wns.ValidateHandle(stringValue(fixture["handle"]))
	must(err)
	if wns.BuildWBAURI(localPart, domain) != stringValue(fixture["uri"]) {
		exitf("WBA URI mismatch")
	}
	services := wns.ExtractHandleServiceFromDIDDocument(asMap(fixture["did_document"]))
	if len(services) == 0 {
		exitf("missing handle service")
	}
	writeJSON(map[string]any{"verified": true, "handle": localPart + "." + domain})
}

func runVerifyKeyFixture(args []string) {
	fixture := readFixture(readOption(args, "--fixture", ""))
	keys := asMap(fixture["keys"])
	for fragment, rawPair := range keys {
		pair := asMap(rawPair)
		privatePEM := stringValue(pair["private_key_pem"])
		publicPEM := stringValue(pair["public_key_pem"])
		if !strings.HasPrefix(privatePEM, "-----BEGIN PRIVATE KEY-----") {
			exitf("%s private key must be PKCS#8 PEM", fragment)
		}
		if !strings.HasPrefix(publicPEM, "-----BEGIN PUBLIC KEY-----") {
			exitf("%s public key must be SPKI PEM", fragment)
		}
		if strings.Contains(privatePEM, "ANP ") || strings.Contains(publicPEM, "ANP ") {
			exitf("%s key pair must not use legacy ANP PEM labels", fragment)
		}
		privateKey := mustPrivate(privatePEM)
		publicKey := mustPublic(publicPEM)
		if publicKey.Type != anp.KeyTypeX25519 {
			signature, err := privateKey.SignMessage([]byte("cross-language standard pem"))
			must(err)
			must(publicKey.VerifyMessage([]byte("cross-language standard pem"), signature))
		}
	}
	writeJSON(map[string]any{"verified": true, "key_count": len(keys)})
}

func createBundle(args []string) authentication.DidDocumentBundle {
	profile := authentication.DidProfile(readOption(args, "--profile", string(authentication.DidProfileE1)))
	hostname := readOption(args, "--hostname", "example.com")
	bundle, err := authentication.CreateDidWBADocument(hostname, authentication.DidDocumentOptions{PathSegments: []string{"user", "interop"}, DidProfile: profile})
	must(err)
	return bundle
}

func readFixture(path string) map[string]any {
	if path == "" {
		exitf("--fixture is required")
	}
	data, err := os.ReadFile(path)
	must(err)
	var fixture map[string]any
	must(json.Unmarshal(data, &fixture))
	return fixture
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

func asMap(value any) map[string]any {
	result, ok := value.(map[string]any)
	if !ok {
		exitf("expected object")
	}
	return result
}

func toStringMap(value map[string]any) map[string]string {
	result := map[string]string{}
	for key, entry := range value {
		result[key] = stringValue(entry)
	}
	return result
}

func stringValue(value any) string {
	result, _ := value.(string)
	return result
}

func mustPrivate(pem string) anp.PrivateKeyMaterial {
	key, err := anp.PrivateKeyFromPEM(pem)
	must(err)
	return key
}

func mustPublic(pem string) anp.PublicKeyMaterial {
	key, err := anp.PublicKeyFromPEM(pem)
	must(err)
	return key
}

func must(err error) {
	if err != nil {
		exitf("%v", err)
	}
}

func exitf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
