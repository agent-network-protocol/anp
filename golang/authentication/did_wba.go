package authentication

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/internal/base58util"
	"github.com/agent-network-protocol/anp/golang/internal/cjson"
	"github.com/agent-network-protocol/anp/golang/internal/diddoc"
	"github.com/agent-network-protocol/anp/golang/proof"
)

// FindVerificationMethod looks up a verification method by identifier.
func FindVerificationMethod(didDocument map[string]any, verificationMethodID string) map[string]any {
	return diddoc.FindVerificationMethod(didDocument, verificationMethodID)
}

// IsAuthenticationAuthorized reports whether a method is listed in authentication.
func IsAuthenticationAuthorized(didDocument map[string]any, verificationMethodID string) bool {
	return diddoc.IsAuthenticationAuthorized(didDocument, verificationMethodID)
}

// IsAssertionMethodAuthorized reports whether a method is listed in assertionMethod.
func IsAssertionMethodAuthorized(didDocument map[string]any, verificationMethodID string) bool {
	return diddoc.IsAssertionMethodAuthorized(didDocument, verificationMethodID)
}

// BuildANPMessageService builds a generic ANPMessageService record.
func BuildANPMessageService(didOrServiceRef string, serviceEndpoint string, options AnpMessageServiceOptions) map[string]any {
	fragment := options.Fragment
	if fragment == "" {
		fragment = "message"
	}
	serviceID := didOrServiceRef
	if !strings.HasPrefix(didOrServiceRef, "#") && !strings.HasPrefix(didOrServiceRef, "did:") {
		serviceID = didOrServiceRef + "#" + fragment
	} else if strings.HasPrefix(didOrServiceRef, "did:") {
		serviceID = didOrServiceRef + "#" + fragment
	}
	service := map[string]any{
		"id":              serviceID,
		"type":            ANPMessageServiceType,
		"serviceEndpoint": serviceEndpoint,
	}
	if options.ServiceDID != "" {
		service["serviceDid"] = options.ServiceDID
	}
	if len(options.Profiles) > 0 {
		service["profiles"] = stringSliceToAny(options.Profiles)
	}
	if len(options.SecurityProfiles) > 0 {
		service["securityProfiles"] = stringSliceToAny(options.SecurityProfiles)
	}
	if len(options.Accepts) > 0 {
		service["accepts"] = stringSliceToAny(options.Accepts)
	}
	if options.Priority != nil {
		service["priority"] = *options.Priority
	}
	if len(options.AuthSchemes) > 0 {
		service["authSchemes"] = stringSliceToAny(options.AuthSchemes)
	}
	return service
}

// BuildAgentMessageService builds a direct agent ANPMessageService record.
func BuildAgentMessageService(did string, serviceEndpoint string, options AnpMessageServiceOptions) map[string]any {
	if len(options.Profiles) == 0 {
		options.Profiles = []string{"anp.core.binding.v1", "anp.direct.base.v1", "anp.direct.e2ee.v1"}
	}
	if len(options.SecurityProfiles) == 0 {
		options.SecurityProfiles = []string{"transport-protected", "direct-e2ee"}
	}
	return BuildANPMessageService(did, serviceEndpoint, options)
}

// BuildGroupMessageService builds a group ANPMessageService record.
func BuildGroupMessageService(did string, serviceEndpoint string, options AnpMessageServiceOptions) map[string]any {
	if len(options.Profiles) == 0 {
		options.Profiles = []string{"anp.core.binding.v1", "anp.group.base.v1", "anp.group.e2ee.v1"}
	}
	if len(options.SecurityProfiles) == 0 {
		options.SecurityProfiles = []string{"transport-protected", "group-e2ee"}
	}
	return BuildANPMessageService(did, serviceEndpoint, options)
}

// CreateDidWBADocument creates a did:wba document and ANP PEM key bundle.
func CreateDidWBADocument(hostname string, options DidDocumentOptions) (DidDocumentBundle, error) {
	if strings.TrimSpace(hostname) == "" {
		return DidDocumentBundle{}, fmt.Errorf("hostname cannot be empty")
	}
	if net.ParseIP(hostname) != nil {
		return DidDocumentBundle{}, fmt.Errorf("hostname cannot be an IP address")
	}
	profile := options.DidProfile
	if profile == "" {
		profile = DidProfileE1
	}
	proofPurpose := options.ProofPurpose
	if proofPurpose == "" {
		proofPurpose = "assertionMethod"
	}
	enableE2EE := true
	if options.EnableE2EE != nil {
		enableE2EE = *options.EnableE2EE
	}
	contexts := []any{"https://www.w3.org/ns/did/v1"}
	verificationMethods := []any{}
	authenticationEntries := []any{}
	assertionMethodEntries := []any{}
	keyAgreementEntries := []any{}
	keys := map[string]anp.GeneratedKeyPairPEM{}
	pathSegments := append([]string(nil), options.PathSegments...)
	didBase := buildDidBase(hostname, options.Port)
	authKeyType := anp.KeyTypeEd25519
	if profile == DidProfileK1 || profile == DidProfilePlainLegacy {
		authKeyType = anp.KeyTypeSecp256k1
	}
	authPrivateKey, authPublicKey, authPair, err := anp.GenerateKeyPairPEM(authKeyType)
	if err != nil {
		return DidDocumentBundle{}, err
	}
	did := didBase
	switch profile {
	case DidProfileE1:
		if len(pathSegments) > 0 {
			fingerprint, err := ComputeMultikeyFingerprint(authPublicKey)
			if err != nil {
				return DidDocumentBundle{}, err
			}
			pathSegments = append(pathSegments, "e1_"+fingerprint)
		}
		did = joinDID(didBase, pathSegments)
	case DidProfileK1:
		if len(pathSegments) > 0 {
			fingerprint, err := ComputeJWKFingerprint(authPublicKey)
			if err != nil {
				return DidDocumentBundle{}, err
			}
			pathSegments = append(pathSegments, "k1_"+fingerprint)
		}
		did = joinDID(didBase, pathSegments)
	case DidProfilePlainLegacy:
		did = joinDID(didBase, pathSegments)
	default:
		return DidDocumentBundle{}, fmt.Errorf("unsupported profile")
	}
	authVM, contexts, err := buildAuthVerificationMethod(did, profile, authPublicKey, contexts)
	if err != nil {
		return DidDocumentBundle{}, err
	}
	verificationMethods = append(verificationMethods, authVM)
	authMethodID := did + "#" + VMKeyAuth
	authenticationEntries = append(authenticationEntries, authMethodID)
	if profile == DidProfileE1 || profile == DidProfileK1 {
		assertionMethodEntries = append(assertionMethodEntries, authMethodID)
	}
	keys[VMKeyAuth] = authPair
	if enableE2EE {
		contexts = append(contexts, "https://w3id.org/security/suites/x25519-2019/v1")
		signingPrivateKey, signingPublicKey, signingPair, err := anp.GenerateKeyPairPEM(anp.KeyTypeSecp256r1)
		if err != nil {
			return DidDocumentBundle{}, err
		}
		agreementPrivateKey, agreementPublicKey, agreementPair, err := anp.GenerateKeyPairPEM(anp.KeyTypeX25519)
		if err != nil {
			return DidDocumentBundle{}, err
		}
		signingJWK, err := anp.PublicKeyToJWK(signingPublicKey)
		if err != nil {
			return DidDocumentBundle{}, err
		}
		verificationMethods = append(verificationMethods,
			map[string]any{"id": did + "#" + VMKeyE2EESigning, "type": "EcdsaSecp256r1VerificationKey2019", "controller": did, "publicKeyJwk": signingJWK},
			map[string]any{"id": did + "#" + VMKeyE2EEAgreement, "type": "X25519KeyAgreementKey2019", "controller": did, "publicKeyMultibase": x25519PublicKeyToMultibase(agreementPublicKey.Bytes)},
		)
		keyAgreementEntries = append(keyAgreementEntries, did+"#"+VMKeyE2EEAgreement)
		keys[VMKeyE2EESigning] = signingPair
		keys[VMKeyE2EEAgreement] = agreementPair
		_ = signingPrivateKey
		_ = agreementPrivateKey
	}
	document := map[string]any{"@context": contexts, "id": did, "verificationMethod": verificationMethods, "authentication": authenticationEntries}
	if len(assertionMethodEntries) > 0 {
		document["assertionMethod"] = assertionMethodEntries
	}
	if len(keyAgreementEntries) > 0 {
		document["keyAgreement"] = keyAgreementEntries
	}
	services := buildServiceEntries(did, options.AgentDescriptionURL, options.Services)
	if len(services) > 0 {
		document["service"] = services
	}
	proofType := proof.ProofTypeDataIntegrity
	cryptosuite := ""
	if profile == DidProfilePlainLegacy {
		proofType = proof.ProofTypeSecp256k1
	} else if profile == DidProfileE1 {
		cryptosuite = proof.CryptosuiteEddsaJCS2022
	} else {
		cryptosuite = proof.CryptosuiteDidWbaSecp256k12025
	}
	verificationMethod := options.VerificationMethod
	if verificationMethod == "" {
		verificationMethod = authMethodID
	}
	signedDocument, err := proof.GenerateW3CProof(document, authPrivateKey, verificationMethod, proof.GenerationOptions{
		ProofPurpose: proofPurpose,
		ProofType:    proofType,
		Cryptosuite:  cryptosuite,
		Created:      options.Created,
		Domain:       options.Domain,
		Challenge:    options.Challenge,
	})
	if err != nil {
		return DidDocumentBundle{}, err
	}
	return DidDocumentBundle{DidDocument: signedDocument, Keys: keys}, nil
}

// Deprecated: Use CreateDidWBADocument with DidDocumentOptions{DidProfile: DidProfileK1} instead.
// CreateDidWBADocumentWithKeyBinding creates a k1 DID document and injects a path when absent.
func CreateDidWBADocumentWithKeyBinding(hostname string, options DidDocumentOptions) (DidDocumentBundle, error) {
	if len(options.PathSegments) == 0 {
		options.PathSegments = []string{"user"}
	}
	options.DidProfile = DidProfileK1
	return CreateDidWBADocument(hostname, options)
}

// ComputeJWKFingerprint computes the k1 fingerprint from a secp256k1 public key.
func ComputeJWKFingerprint(publicKey anp.PublicKeyMaterial) (string, error) {
	if publicKey.Type != anp.KeyTypeSecp256k1 {
		return "", fmt.Errorf("invalid DID document")
	}
	jwk, err := anp.PublicKeyToJWK(publicKey)
	if err != nil {
		return "", err
	}
	return jwkThumbprint(jwk)
}

// ComputeMultikeyFingerprint computes the e1 fingerprint from an Ed25519 public key.
func ComputeMultikeyFingerprint(publicKey anp.PublicKeyMaterial) (string, error) {
	if publicKey.Type != anp.KeyTypeEd25519 {
		return "", fmt.Errorf("invalid DID document")
	}
	jwk := map[string]any{"crv": "Ed25519", "kty": "OKP", "x": anp.EncodeBase64URL(publicKey.Bytes)}
	return jwkThumbprint(jwk)
}

// VerifyDIDKeyBinding verifies whether a verification method matches the key-binding suffix.
func VerifyDIDKeyBinding(did string, bindingMaterial map[string]any) bool {
	parts := strings.Split(did, ":")
	last := parts[len(parts)-1]
	if strings.HasPrefix(last, "k1_") {
		publicKey, err := ExtractPublicKey(bindingMaterial)
		if err != nil {
			return false
		}
		fingerprint, err := ComputeJWKFingerprint(publicKey)
		return err == nil && fingerprint == strings.TrimPrefix(last, "k1_")
	}
	if strings.HasPrefix(last, "e1_") {
		publicKey, err := ExtractPublicKey(bindingMaterial)
		if err != nil {
			return false
		}
		fingerprint, err := ComputeMultikeyFingerprint(publicKey)
		return err == nil && fingerprint == strings.TrimPrefix(last, "e1_")
	}
	return true
}

// ValidateDIDDocumentBinding validates did:wba key binding constraints.
func ValidateDIDDocumentBinding(didDocument map[string]any, verifyProof bool) bool {
	did, _ := didDocument["id"].(string)
	parts := strings.Split(did, ":")
	if len(parts) == 0 {
		return false
	}
	last := parts[len(parts)-1]
	if strings.HasPrefix(last, "e1_") {
		return validateE1Binding(didDocument, strings.TrimPrefix(last, "e1_"))
	}
	if strings.HasPrefix(last, "k1_") {
		if verifyProof {
			return validateK1Binding(didDocument, strings.TrimPrefix(last, "k1_"))
		}
		if methods, ok := didDocument["verificationMethod"].([]any); ok {
			for _, entry := range methods {
				method, ok := entry.(map[string]any)
				if !ok {
					continue
				}
				identifier, _ := method["id"].(string)
				if IsAuthenticationAuthorized(didDocument, identifier) && VerifyDIDKeyBinding(did, method) {
					return true
				}
			}
		}
		return false
	}
	return true
}

// ResolveDidWBADocument resolves a did:wba document over HTTPS.
func ResolveDidWBADocument(ctx context.Context, did string, verifyProof bool) (map[string]any, error) {
	return ResolveDidWBADocumentWithOptions(ctx, did, verifyProof, DidResolutionOptions{})
}

// ResolveDidWBADocumentWithOptions resolves a did:wba document with explicit options.
func ResolveDidWBADocumentWithOptions(ctx context.Context, did string, verifyProof bool, options DidResolutionOptions) (map[string]any, error) {
	if !strings.HasPrefix(did, "did:wba:") {
		return nil, fmt.Errorf("invalid DID format")
	}
	parts := strings.Split(did, ":")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid DID format")
	}
	domain, err := url.PathUnescape(parts[2])
	if err != nil {
		return nil, err
	}
	baseURL := options.BaseURLOverride
	if baseURL == "" {
		baseURL = "https://" + domain
	}
	resourceURL := strings.TrimRight(baseURL, "/") + "/.well-known/did.json"
	if len(parts) > 3 {
		resourceURL = strings.TrimRight(baseURL, "/") + "/" + strings.Join(parts[3:], "/") + "/did.json"
	}
	document, err := fetchJSONDocument(ctx, resourceURL, options)
	if err != nil {
		return nil, err
	}
	if identifier, _ := document["id"].(string); identifier != did {
		return nil, fmt.Errorf("invalid DID document")
	}
	if !ValidateDIDDocumentBinding(document, verifyProof) {
		return nil, fmt.Errorf("DID binding verification failed")
	}
	if verifyProof {
		proofValue, ok := document["proof"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid DID document")
		}
		verificationMethodID, _ := proofValue["verificationMethod"].(string)
		verificationMethod := FindVerificationMethod(document, verificationMethodID)
		if verificationMethod == nil {
			return nil, fmt.Errorf("verification method not found")
		}
		publicKey, err := ExtractPublicKey(verificationMethod)
		if err != nil {
			return nil, err
		}
		if !proof.VerifyW3CProof(document, publicKey, proof.VerificationOptions{}) {
			return nil, fmt.Errorf("verification failed")
		}
	}
	return document, nil
}

// GenerateAuthHeader generates a legacy DIDWba Authorization header.
func GenerateAuthHeader(didDocument map[string]any, serviceDomain string, privateKey anp.PrivateKeyMaterial, version string) (string, error) {
	payload, err := generateAuthPayload(didDocument, serviceDomain, privateKey, version, "", "")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("DIDWba v=\"%s\", did=\"%s\", nonce=\"%s\", timestamp=\"%s\", verification_method=\"%s\", signature=\"%s\"", payload.Version, payload.DID, payload.Nonce, payload.Timestamp, payload.VerificationMethod, payload.Signature), nil
}

// GenerateAuthJSON generates the JSON legacy DIDWba payload.
func GenerateAuthJSON(didDocument map[string]any, serviceDomain string, privateKey anp.PrivateKeyMaterial, version string) (string, error) {
	payload, err := generateAuthPayload(didDocument, serviceDomain, privateKey, version, "", "")
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(map[string]any{"v": payload.Version, "did": payload.DID, "nonce": payload.Nonce, "timestamp": payload.Timestamp, "verification_method": payload.VerificationMethod, "signature": payload.Signature})
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func generateAuthHeaderWithOverrides(didDocument map[string]any, serviceDomain string, privateKey anp.PrivateKeyMaterial, version string, nonce string, timestamp string) (string, error) {
	payload, err := generateAuthPayload(didDocument, serviceDomain, privateKey, version, nonce, timestamp)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("DIDWba v=\"%s\", did=\"%s\", nonce=\"%s\", timestamp=\"%s\", verification_method=\"%s\", signature=\"%s\"", payload.Version, payload.DID, payload.Nonce, payload.Timestamp, payload.VerificationMethod, payload.Signature), nil
}

// ExtractAuthHeaderParts parses a legacy DIDWba Authorization header.
func ExtractAuthHeaderParts(authHeader string) (ParsedAuthHeader, error) {
	if !strings.HasPrefix(strings.TrimSpace(authHeader), "DIDWba") {
		return ParsedAuthHeader{}, fmt.Errorf("authentication header must start with DIDWba")
	}
	values := map[string]string{}
	for _, field := range []string{"did", "nonce", "timestamp", "verification_method", "signature"} {
		pattern := regexp.MustCompile(`(?i)` + field + `="([^"]+)"`)
		matches := pattern.FindStringSubmatch(authHeader)
		if len(matches) != 2 {
			return ParsedAuthHeader{}, fmt.Errorf("missing field in authorization header: %s", field)
		}
		values[field] = matches[1]
	}
	version := "1.1"
	if matches := regexp.MustCompile(`(?i)v="([^"]+)"`).FindStringSubmatch(authHeader); len(matches) == 2 {
		version = matches[1]
	}
	return ParsedAuthHeader{DID: values["did"], Nonce: values["nonce"], Timestamp: values["timestamp"], VerificationMethod: values["verification_method"], Signature: values["signature"], Version: version}, nil
}

// VerifyAuthHeaderSignature verifies a legacy DIDWba Authorization header.
func VerifyAuthHeaderSignature(authHeader string, didDocument map[string]any, serviceDomain string) error {
	parsed, err := ExtractAuthHeaderParts(authHeader)
	if err != nil {
		return err
	}
	return verifyAuthPayload(parsed, didDocument, serviceDomain)
}

// VerifyAuthJSONSignature verifies a legacy DIDWba JSON payload.
func VerifyAuthJSONSignature(authJSON string, didDocument map[string]any, serviceDomain string) error {
	var payload map[string]any
	if err := decodeJSON(strings.NewReader(authJSON), &payload); err != nil {
		return err
	}
	parsed := ParsedAuthHeader{DID: stringValue(payload["did"]), Nonce: stringValue(payload["nonce"]), Timestamp: stringValue(payload["timestamp"]), VerificationMethod: stringValue(payload["verification_method"]), Signature: stringValue(payload["signature"]), Version: stringValue(payload["v"])}
	if parsed.Version == "" {
		parsed.Version = "1.1"
	}
	return verifyAuthPayload(parsed, didDocument, serviceDomain)
}

func generateAuthPayload(didDocument map[string]any, serviceDomain string, privateKey anp.PrivateKeyMaterial, version string, nonce string, timestamp string) (ParsedAuthHeader, error) {
	did := stringValue(didDocument["id"])
	if did == "" {
		return ParsedAuthHeader{}, fmt.Errorf("invalid DID document")
	}
	method, fragment, err := selectAuthenticationMethod(didDocument)
	if err != nil {
		return ParsedAuthHeader{}, err
	}
	if nonce == "" {
		nonce = anp.EncodeBase64URL(randomBytes(16))
	}
	if timestamp == "" {
		timestamp = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	}
	field := domainFieldForVersion(version)
	payload := map[string]any{"nonce": nonce, "timestamp": timestamp, field: serviceDomain, "did": did}
	canonical, err := cjson.Marshal(payload)
	if err != nil {
		return ParsedAuthHeader{}, err
	}
	contentHash := sha256.Sum256(canonical)
	signatureBytes, err := privateKey.SignMessage(contentHash[:])
	if err != nil {
		return ParsedAuthHeader{}, err
	}
	verifier, err := CreateVerificationMethod(method)
	if err != nil {
		return ParsedAuthHeader{}, err
	}
	signature, err := verifier.EncodeSignature(signatureBytes)
	if err != nil {
		return ParsedAuthHeader{}, err
	}
	if version == "" {
		version = "1.1"
	}
	return ParsedAuthHeader{DID: did, Nonce: nonce, Timestamp: timestamp, VerificationMethod: fragment, Signature: signature, Version: version}, nil
}

func verifyAuthPayload(parsed ParsedAuthHeader, didDocument map[string]any, serviceDomain string) error {
	identifier := strings.ToLower(stringValue(didDocument["id"]))
	if identifier == "" || identifier != strings.ToLower(parsed.DID) {
		return fmt.Errorf("verification failed")
	}
	field := domainFieldForVersion(parsed.Version)
	payload := map[string]any{"nonce": parsed.Nonce, "timestamp": parsed.Timestamp, field: serviceDomain, "did": parsed.DID}
	canonical, err := cjson.Marshal(payload)
	if err != nil {
		return err
	}
	contentHash := sha256.Sum256(canonical)
	verificationMethodID := parsed.DID + "#" + parsed.VerificationMethod
	method := FindVerificationMethod(didDocument, verificationMethodID)
	if method == nil {
		return fmt.Errorf("verification method not found")
	}
	verifier, err := CreateVerificationMethod(method)
	if err != nil {
		return err
	}
	if err := verifier.VerifySignature(contentHash[:], parsed.Signature); err != nil {
		return fmt.Errorf("verification failed")
	}
	return nil
}

func selectAuthenticationMethod(didDocument map[string]any) (map[string]any, string, error) {
	authentication, ok := didDocument["authentication"].([]any)
	if !ok || len(authentication) == 0 {
		return nil, "", fmt.Errorf("invalid DID document")
	}
	switch first := authentication[0].(type) {
	case string:
		method := FindVerificationMethod(didDocument, first)
		if method == nil {
			return nil, "", fmt.Errorf("verification method not found")
		}
		parts := strings.Split(first, "#")
		return method, parts[len(parts)-1], nil
	case map[string]any:
		identifier := stringValue(first["id"])
		if identifier == "" {
			return nil, "", fmt.Errorf("invalid DID document")
		}
		parts := strings.Split(identifier, "#")
		return first, parts[len(parts)-1], nil
	default:
		return nil, "", fmt.Errorf("invalid DID document")
	}
}

func buildAuthVerificationMethod(did string, profile DidProfile, publicKey anp.PublicKeyMaterial, contexts []any) (map[string]any, []any, error) {
	switch profile {
	case DidProfileE1:
		contexts = append(contexts, "https://w3id.org/security/data-integrity/v2", "https://w3id.org/security/multikey/v1")
		return map[string]any{"id": did + "#" + VMKeyAuth, "type": "Multikey", "controller": did, "publicKeyMultibase": ed25519PublicKeyToMultibase(publicKey.Bytes)}, contexts, nil
	case DidProfileK1, DidProfilePlainLegacy:
		contexts = append(contexts, "https://w3id.org/security/suites/jws-2020/v1", "https://w3id.org/security/suites/secp256k1-2019/v1")
		if profile == DidProfileK1 {
			contexts = append(contexts, "https://w3id.org/security/data-integrity/v2")
		}
		jwk, err := anp.PublicKeyToJWK(publicKey)
		if err != nil {
			return nil, nil, err
		}
		return map[string]any{"id": did + "#" + VMKeyAuth, "type": "EcdsaSecp256k1VerificationKey2019", "controller": did, "publicKeyJwk": jwk}, contexts, nil
	default:
		return nil, nil, fmt.Errorf("unsupported profile")
	}
}

func buildServiceEntries(did string, agentDescriptionURL string, services []map[string]any) []any {
	result := []any{}
	if agentDescriptionURL != "" {
		result = append(result, map[string]any{"id": did + "#ad", "type": "AgentDescription", "serviceEndpoint": agentDescriptionURL})
	}
	for _, service := range services {
		copyValue := cloneMap(service)
		if identifier, ok := copyValue["id"].(string); ok && strings.HasPrefix(identifier, "#") {
			copyValue["id"] = did + identifier
		}
		result = append(result, copyValue)
	}
	return result
}

func validateE1Binding(didDocument map[string]any, expectedFingerprint string) bool {
	proofValue, ok := didDocument["proof"].(map[string]any)
	if !ok {
		return false
	}
	if stringValue(proofValue["type"]) != proof.ProofTypeDataIntegrity || stringValue(proofValue["cryptosuite"]) != proof.CryptosuiteEddsaJCS2022 {
		return false
	}
	verificationMethodID := stringValue(proofValue["verificationMethod"])
	if !IsAssertionMethodAuthorized(didDocument, verificationMethodID) {
		return false
	}
	verificationMethod := FindVerificationMethod(didDocument, verificationMethodID)
	if verificationMethod == nil {
		return false
	}
	publicKey, err := ExtractPublicKey(verificationMethod)
	if err != nil {
		return false
	}
	fingerprint, err := ComputeMultikeyFingerprint(publicKey)
	if err != nil || fingerprint != expectedFingerprint {
		return false
	}
	return proof.VerifyW3CProof(didDocument, publicKey, proof.VerificationOptions{ExpectedPurpose: "assertionMethod"})
}

func validateK1Binding(didDocument map[string]any, expectedFingerprint string) bool {
	proofValue, ok := didDocument["proof"].(map[string]any)
	if !ok {
		return false
	}
	verificationMethodID := stringValue(proofValue["verificationMethod"])
	if !IsAssertionMethodAuthorized(didDocument, verificationMethodID) {
		return false
	}
	verificationMethod := FindVerificationMethod(didDocument, verificationMethodID)
	if verificationMethod == nil {
		return false
	}
	publicKey, err := ExtractPublicKey(verificationMethod)
	if err != nil {
		return false
	}
	fingerprint, err := ComputeJWKFingerprint(publicKey)
	if err != nil || fingerprint != expectedFingerprint {
		return false
	}
	return proof.VerifyW3CProof(didDocument, publicKey, proof.VerificationOptions{ExpectedPurpose: "assertionMethod"})
}

func buildDidBase(hostname string, port *int) string {
	if port != nil {
		return fmt.Sprintf("did:wba:%s%%3A%d", hostname, *port)
	}
	return "did:wba:" + hostname
}

func joinDID(base string, pathSegments []string) string {
	if len(pathSegments) == 0 {
		return base
	}
	return base + ":" + strings.Join(pathSegments, ":")
}

func jwkThumbprint(jwk map[string]any) (string, error) {
	canonical, err := cjson.Marshal(jwk)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(canonical)
	return anp.EncodeBase64URL(hash[:]), nil
}

func ed25519PublicKeyToMultibase(publicKey []byte) string {
	prefixed := append([]byte{0xed, 0x01}, append([]byte(nil), publicKey...)...)
	return "z" + base58util.Encode(prefixed)
}

func x25519PublicKeyToMultibase(publicKey []byte) string {
	prefixed := append([]byte{0xec, 0x01}, append([]byte(nil), publicKey...)...)
	return "z" + base58util.Encode(prefixed)
}

func domainFieldForVersion(version string) string {
	if version == "" {
		return "aud"
	}
	parsed, err := strconv.ParseFloat(version, 64)
	if err != nil {
		return "service"
	}
	if parsed >= 1.1 {
		return "aud"
	}
	return "service"
}

func fetchJSONDocument(ctx context.Context, resourceURL string, options DidResolutionOptions) (map[string]any, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	for key, value := range options.Headers {
		request.Header.Set(key, value)
	}
	client := newHTTPClient(options)
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("network failure")
	}
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var document map[string]any
	if err := decodeJSON(bytes.NewReader(data), &document); err != nil {
		return nil, err
	}
	return document, nil
}

func newHTTPClient(options DidResolutionOptions) *http.Client {
	timeout := 10 * time.Second
	if options.TimeoutSeconds > 0 {
		timeout = time.Duration(options.TimeoutSeconds * float64(time.Second))
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if options.VerifySSL != nil && !*options.VerifySSL {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

func decodeJSON(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	decoder.UseNumber()
	return decoder.Decode(target)
}

func cloneMap(input map[string]any) map[string]any {
	result := make(map[string]any, len(input))
	for key, value := range input {
		switch typed := value.(type) {
		case map[string]any:
			result[key] = cloneMap(typed)
		case []any:
			result[key] = cloneSlice(typed)
		default:
			result[key] = typed
		}
	}
	return result
}

func cloneSlice(input []any) []any {
	result := make([]any, len(input))
	for index, value := range input {
		switch typed := value.(type) {
		case map[string]any:
			result[index] = cloneMap(typed)
		case []any:
			result[index] = cloneSlice(typed)
		default:
			result[index] = typed
		}
	}
	return result
}

func parseAuthParams(value string) map[string]string {
	result := map[string]string{}
	for _, part := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';'
	}) {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		name, rawValue, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		result[strings.TrimSpace(name)] = strings.Trim(strings.TrimSpace(rawValue), "\"")
	}
	return result
}

func randomBytes(size int) []byte {
	buffer := make([]byte, size)
	_, _ = rand.Read(buffer)
	return buffer
}

func stringSliceToAny(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func extractDomain(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if host := parsed.Hostname(); host != "" {
		return host
	}
	return rawURL
}
