package proof

import (
	"fmt"
	"strings"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/internal/cjson"
)

const RFC9421OriginProofDefaultLabel = "sig1"

type TargetKind string

const (
	TargetKindAgent   TargetKind = "agent"
	TargetKindGroup   TargetKind = "group"
	TargetKindService TargetKind = "service"
)

var RFC9421OriginProofDefaultComponents = []string{"@method", "@target-uri", "content-digest"}

// SignedRequestObject is the shared business object defined by ANP P1 Appendix A.
type SignedRequestObject struct {
	Method string         `json:"method"`
	Meta   map[string]any `json:"meta"`
	Body   map[string]any `json:"body"`
}

// RFC9421OriginProof is the high-level origin proof payload defined by ANP P1 Appendix A.
type RFC9421OriginProof struct {
	ContentDigest  string `json:"contentDigest"`
	SignatureInput string `json:"signatureInput"`
	Signature      string `json:"signature"`
}

// RFC9421OriginProofGenerationOptions configures high-level origin proof generation.
type RFC9421OriginProofGenerationOptions struct {
	Created *int64
	Expires *int64
	Nonce   string
	Label   string
}

// RFC9421OriginProofVerificationOptions configures high-level origin proof verification.
type RFC9421OriginProofVerificationOptions struct {
	DidDocument        map[string]any
	VerificationMethod map[string]any
	ExpectedSignerDID  string
}

// BuildSignedRequestObject builds the shared signed request object.
func BuildSignedRequestObject(method string, meta map[string]any, body map[string]any) (SignedRequestObject, error) {
	if strings.TrimSpace(method) == "" {
		return SignedRequestObject{}, &Error{Message: "method is required"}
	}
	if meta == nil {
		return SignedRequestObject{}, &Error{Message: "meta must be an object"}
	}
	if body == nil {
		return SignedRequestObject{}, &Error{Message: "body must be an object"}
	}
	return SignedRequestObject{Method: method, Meta: cloneMap(meta), Body: cloneMap(body)}, nil
}

// CanonicalizeSignedRequestObject canonicalizes the shared signed request object with JCS semantics.
func CanonicalizeSignedRequestObject(value SignedRequestObject) ([]byte, error) {
	if strings.TrimSpace(value.Method) == "" {
		return nil, &Error{Message: "method is required"}
	}
	if value.Meta == nil {
		return nil, &Error{Message: "meta must be an object"}
	}
	if value.Body == nil {
		return nil, &Error{Message: "body must be an object"}
	}
	return cjson.Marshal(value)
}

// BuildLogicalTargetURI builds the ANP logical target URI for origin proof.
func BuildLogicalTargetURI(targetKind TargetKind, targetDID string) (string, error) {
	normalizedKind := strings.TrimSpace(string(targetKind))
	switch TargetKind(normalizedKind) {
	case TargetKindAgent, TargetKindGroup, TargetKindService:
	default:
		return "", &Error{Message: fmt.Sprintf("unsupported target kind: %s", targetKind)}
	}
	normalizedDID := strings.TrimSpace(targetDID)
	if normalizedDID == "" {
		return "", &Error{Message: "target did is required"}
	}
	return fmt.Sprintf("anp://%s/%s", normalizedKind, strictPercentEncode(normalizedDID)), nil
}

// BuildRFC9421OriginSignatureBase builds the RFC 9421 application-layer signature base.
func BuildRFC9421OriginSignatureBase(method string, logicalTargetURI string, contentDigest string, signatureInput string) ([]byte, error) {
	if strings.TrimSpace(method) == "" {
		return nil, &Error{Message: "method is required"}
	}
	if strings.TrimSpace(logicalTargetURI) == "" {
		return nil, &Error{Message: "logical_target_uri is required"}
	}
	if strings.TrimSpace(contentDigest) == "" {
		return nil, &Error{Message: "content_digest is required"}
	}
	parsed, err := ParseIMSignatureInput(signatureInput)
	if err != nil {
		return nil, err
	}
	if err := validateRFC9421OriginParsedSignatureInput(parsed); err != nil {
		return nil, err
	}
	componentValues := map[string]string{
		"@method":        method,
		"@target-uri":    logicalTargetURI,
		"content-digest": contentDigest,
	}
	lines := make([]string, 0, len(parsed.Components)+1)
	for _, component := range parsed.Components {
		lines = append(lines, fmt.Sprintf("\"%s\": %s", component, componentValues[component]))
	}
	lines = append(lines, fmt.Sprintf("\"@signature-params\": %s", parsed.SignatureParams))
	return []byte(strings.Join(lines, "\n")), nil
}

// GenerateRFC9421OriginProof builds and signs an origin proof from protocol fields.
func GenerateRFC9421OriginProof(method string, meta map[string]any, body map[string]any, privateKey anp.PrivateKeyMaterial, keyID string, options RFC9421OriginProofGenerationOptions) (RFC9421OriginProof, error) {
	if err := validateRFC9421OriginLabel(options.Label); err != nil {
		return RFC9421OriginProof{}, err
	}
	signedRequestObject, err := BuildSignedRequestObject(method, meta, body)
	if err != nil {
		return RFC9421OriginProof{}, err
	}
	canonicalRequest, err := CanonicalizeSignedRequestObject(signedRequestObject)
	if err != nil {
		return RFC9421OriginProof{}, err
	}
	logicalTargetURI, err := buildLogicalTargetURIFromMeta(signedRequestObject.Meta)
	if err != nil {
		return RFC9421OriginProof{}, err
	}
	signatureInput, err := BuildIMSignatureInput(keyID, IMGenerationOptions{
		Label:      normalizedRFC9421OriginLabel(options.Label),
		Components: append([]string(nil), RFC9421OriginProofDefaultComponents...),
		Created:    options.Created,
		Expires:    options.Expires,
		Nonce:      options.Nonce,
	})
	if err != nil {
		return RFC9421OriginProof{}, err
	}
	contentDigest := BuildIMContentDigest(canonicalRequest)
	signatureBase, err := BuildRFC9421OriginSignatureBase(method, logicalTargetURI, contentDigest, signatureInput)
	if err != nil {
		return RFC9421OriginProof{}, err
	}
	proofValue, err := GenerateIMProof(canonicalRequest, signatureBase, privateKey, keyID, IMGenerationOptions{
		Label:      normalizedRFC9421OriginLabel(options.Label),
		Components: append([]string(nil), RFC9421OriginProofDefaultComponents...),
		Created:    options.Created,
		Expires:    options.Expires,
		Nonce:      options.Nonce,
	})
	if err != nil {
		return RFC9421OriginProof{}, err
	}
	parsed, err := ParseIMSignatureInput(proofValue.SignatureInput)
	if err != nil {
		return RFC9421OriginProof{}, err
	}
	if err := validateRFC9421OriginParsedSignatureInput(parsed); err != nil {
		return RFC9421OriginProof{}, err
	}
	return RFC9421OriginProof(proofValue), nil
}

// VerifyRFC9421OriginProof verifies an origin proof against protocol fields.
func VerifyRFC9421OriginProof(originProof RFC9421OriginProof, method string, meta map[string]any, body map[string]any, options RFC9421OriginProofVerificationOptions) (IMVerificationResult, error) {
	signedRequestObject, err := BuildSignedRequestObject(method, meta, body)
	if err != nil {
		return IMVerificationResult{}, err
	}
	canonicalRequest, err := CanonicalizeSignedRequestObject(signedRequestObject)
	if err != nil {
		return IMVerificationResult{}, err
	}
	logicalTargetURI, err := buildLogicalTargetURIFromMeta(signedRequestObject.Meta)
	if err != nil {
		return IMVerificationResult{}, err
	}
	parsed, err := ParseIMSignatureInput(originProof.SignatureInput)
	if err != nil {
		return IMVerificationResult{}, err
	}
	if err := validateRFC9421OriginParsedSignatureInput(parsed); err != nil {
		return IMVerificationResult{}, err
	}
	signatureBase, err := BuildRFC9421OriginSignatureBase(method, logicalTargetURI, originProof.ContentDigest, originProof.SignatureInput)
	if err != nil {
		return IMVerificationResult{}, err
	}
	imProof := IMProof(originProof)
	if options.VerificationMethod != nil {
		return VerifyIMProofWithVerificationMethod(imProof, canonicalRequest, signatureBase, options.VerificationMethod, options.ExpectedSignerDID)
	}
	if options.DidDocument == nil {
		return IMVerificationResult{}, &Error{Message: "did_document or verification_method is required"}
	}
	return VerifyIMProofWithDocument(imProof, canonicalRequest, signatureBase, options.DidDocument, options.ExpectedSignerDID)
}

func buildLogicalTargetURIFromMeta(meta map[string]any) (string, error) {
	target, ok := meta["target"].(map[string]any)
	if !ok {
		return "", &Error{Message: "meta.target is required"}
	}
	targetKind, _ := target["kind"].(string)
	targetDID, _ := target["did"].(string)
	return BuildLogicalTargetURI(TargetKind(targetKind), targetDID)
}

func validateRFC9421OriginParsedSignatureInput(parsed ParsedIMSignatureInput) error {
	if err := validateRFC9421OriginLabel(parsed.Label); err != nil {
		return err
	}
	if !sameStringSlice(parsed.Components, RFC9421OriginProofDefaultComponents) {
		return &Error{Message: "RFC 9421 origin proof requires covered components (\"@method\" \"@target-uri\" \"content-digest\")"}
	}
	return nil
}

func validateRFC9421OriginLabel(label string) error {
	if normalizedRFC9421OriginLabel(label) != RFC9421OriginProofDefaultLabel {
		return &Error{Message: "RFC 9421 origin proof requires signature label sig1"}
	}
	return nil
}

func normalizedRFC9421OriginLabel(label string) string {
	if strings.TrimSpace(label) == "" {
		return RFC9421OriginProofDefaultLabel
	}
	return label
}

func sameStringSlice(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func strictPercentEncode(value string) string {
	var builder strings.Builder
	builder.Grow(len(value) * 3)
	for index := 0; index < len(value); index++ {
		ch := value[index]
		if (ch >= 'A' && ch <= 'Z') ||
			(ch >= 'a' && ch <= 'z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '.' || ch == '_' || ch == '~' {
			builder.WriteByte(ch)
			continue
		}
		builder.WriteString(fmt.Sprintf("%%%02X", ch))
	}
	return builder.String()
}
