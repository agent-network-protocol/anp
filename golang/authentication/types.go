package authentication

import (
	"github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/internal/vm"
)

// DidProfile identifies the DID profile encoded in a did:wba identifier.
type DidProfile string

const (
	DidProfileE1          DidProfile = "e1"
	DidProfileK1          DidProfile = "k1"
	DidProfilePlainLegacy DidProfile = "plain_legacy"
)

// AuthMode identifies the client authentication mode.
type AuthMode string

const (
	AuthModeHTTPSignatures AuthMode = "http_signatures"
	AuthModeLegacyDidWba   AuthMode = "legacy_didwba"
	AuthModeAuto           AuthMode = "auto"
)

const (
	VMKeyAuth             = "key-1"
	VMKeyE2EESigning      = "key-2"
	VMKeyE2EEAgreement    = "key-3"
	ANPMessageServiceType = "ANPMessageService"
)

// DidDocumentOptions configures DID document generation.
type DidDocumentOptions struct {
	Port                *int
	PathSegments        []string
	AgentDescriptionURL string
	Services            []map[string]any
	ProofPurpose        string
	VerificationMethod  string
	Domain              string
	Challenge           string
	Created             string
	EnableE2EE          *bool
	DidProfile          DidProfile
}

// AnpMessageServiceOptions configures ANPMessageService records.
type AnpMessageServiceOptions struct {
	Fragment         string
	ServiceDID       string
	Profiles         []string
	SecurityProfiles []string
	Accepts          []string
	Priority         *int
	AuthSchemes      []string
}

// DidDocumentBundle stores a generated DID document and its PEM encoded keys.
type DidDocumentBundle struct {
	DidDocument map[string]any                     `json:"did_document"`
	Keys        map[string]anp.GeneratedKeyPairPEM `json:"keys"`
}

// ParsedAuthHeader is the parsed legacy DIDWba authorization header.
type ParsedAuthHeader struct {
	DID                string `json:"did"`
	Nonce              string `json:"nonce"`
	Timestamp          string `json:"timestamp"`
	VerificationMethod string `json:"verification_method"`
	Signature          string `json:"signature"`
	Version            string `json:"version"`
}

// DidResolutionOptions configures DID document resolution.
type DidResolutionOptions struct {
	TimeoutSeconds  float64
	VerifySSL       *bool
	BaseURLOverride string
	Headers         map[string]string
}

// HttpSignatureOptions configures HTTP message signature generation.
type HttpSignatureOptions struct {
	KeyID             string
	Nonce             string
	Created           *int64
	Expires           *int64
	CoveredComponents []string
}

// SignatureMetadata is extracted from Signature-Input and Signature headers.
type SignatureMetadata struct {
	Label      string   `json:"label"`
	Components []string `json:"components"`
	KeyID      string   `json:"keyid"`
	Nonce      string   `json:"nonce,omitempty"`
	Created    int64    `json:"created"`
	Expires    *int64   `json:"expires,omitempty"`
}

// FederatedVerificationOptions configures federated request verification.
type FederatedVerificationOptions struct {
	SenderDidDocument     map[string]any
	ServiceDidDocument    map[string]any
	ServiceID             string
	ServiceEndpoint       string
	VerifySenderDidProof  bool
	VerifyServiceDidProof bool
	DidResolutionOptions  DidResolutionOptions
}

// FederatedVerificationResult describes a verified federated ANP request.
type FederatedVerificationResult struct {
	SenderDID         string            `json:"sender_did"`
	ServiceDID        string            `json:"service_did"`
	ServiceID         string            `json:"service_id"`
	SignatureMetadata SignatureMetadata `json:"signature_metadata"`
}

// VerificationSuccess describes a verified inbound request.
type VerificationSuccess struct {
	DID             string            `json:"did"`
	AuthScheme      string            `json:"auth_scheme"`
	ResponseHeaders map[string]string `json:"response_headers"`
	AccessToken     string            `json:"access_token,omitempty"`
	TokenType       string            `json:"token_type,omitempty"`
}

// DidWbaVerifierConfig configures the request verifier.
type DidWbaVerifierConfig struct {
	JWTPrivateKey                 string
	JWTPublicKey                  string
	JWTAlgorithm                  string
	AccessTokenExpireMinutes      int
	NonceExpirationMinutes        int
	TimestampExpirationMinutes    int
	AllowedDomains                []string
	AllowHTTPSignatures           *bool
	AllowLegacyDidWba             *bool
	EmitAuthenticationInfoHeader  *bool
	EmitLegacyAuthorizationHeader *bool
	RequireNonceForHTTPSignatures *bool
	DidResolutionOptions          DidResolutionOptions
	ExternalNonceValidator        func(did string, nonce string) bool
}

// DidWbaVerifierError reports request verification failures.
type DidWbaVerifierError struct {
	Message    string
	StatusCode int
	Headers    map[string]string
}

// Error implements error.
func (e *DidWbaVerifierError) Error() string {
	return e.Message
}

// VerificationMethod re-exports parsed verification methods.
type VerificationMethod = vm.VerificationMethod

// VerificationMethodError re-exports verification method parsing errors.
type VerificationMethodError = vm.Error
