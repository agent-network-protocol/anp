package proof

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"time"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/internal/base64util"
	"github.com/agent-network-protocol/anp/golang/internal/cjson"
	"github.com/agent-network-protocol/anp/golang/internal/diddoc"
	"github.com/agent-network-protocol/anp/golang/internal/vm"
)

var IMProofDefaultComponents = []string{"@method", "@target-uri", "content-digest"}

// IMProof stores an ANP IM business proof.
type IMProof struct {
	ContentDigest  string `json:"contentDigest"`
	SignatureInput string `json:"signatureInput"`
	Signature      string `json:"signature"`
}

// ParsedIMSignatureInput is the parsed signature-input structure.
type ParsedIMSignatureInput struct {
	Label           string   `json:"label"`
	Components      []string `json:"components"`
	SignatureParams string   `json:"signature_params"`
	KeyID           string   `json:"keyid"`
	Nonce           string   `json:"nonce,omitempty"`
	Created         *int64   `json:"created,omitempty"`
	Expires         *int64   `json:"expires,omitempty"`
}

// IMGenerationOptions configures IM proof generation.
type IMGenerationOptions struct {
	Label      string
	Components []string
	Created    *int64
	Expires    *int64
	Nonce      string
}

// IMVerificationResult contains the verified verification method.
type IMVerificationResult struct {
	ParsedSignatureInput ParsedIMSignatureInput `json:"parsed_signature_input"`
	VerificationMethod   map[string]any         `json:"verification_method"`
}

// BuildIMContentDigest builds a content-digest header value for IM payloads.
func BuildIMContentDigest(payload []byte) string {
	hash := sha256.Sum256(payload)
	return "sha-256=:" + base64util.EncodeStd(hash[:]) + ":"
}

// VerifyIMContentDigest verifies a content-digest value.
func VerifyIMContentDigest(payload []byte, contentDigest string) bool {
	return BuildIMContentDigest(payload) == strings.TrimSpace(contentDigest)
}

// BuildIMSignatureInput builds an IM signature-input value.
func BuildIMSignatureInput(keyID string, options IMGenerationOptions) (string, error) {
	label := options.Label
	if label == "" {
		label = "sig1"
	}
	components := options.Components
	if len(components) == 0 {
		components = append([]string(nil), IMProofDefaultComponents...)
	}
	if len(components) == 0 {
		return "", &Error{Message: "proof.signatureInput must include covered components"}
	}
	created := time.Now().Unix()
	if options.Created != nil {
		created = *options.Created
	}
	nonce := options.Nonce
	if nonce == "" {
		nonce = anp.EncodeBase64URL(randomNonce())
	}
	parts := []string{fmt.Sprintf("created=%d", created)}
	if options.Expires != nil {
		parts = append(parts, fmt.Sprintf("expires=%d", *options.Expires))
	}
	parts = append(parts, fmt.Sprintf("nonce=\"%s\"", nonce), fmt.Sprintf("keyid=\"%s\"", keyID))
	quoted := make([]string, 0, len(components))
	for _, component := range components {
		quoted = append(quoted, fmt.Sprintf("\"%s\"", component))
	}
	return fmt.Sprintf("%s=(%s);%s", label, strings.Join(quoted, " "), strings.Join(parts, ";")), nil
}

// ParseIMSignatureInput parses a signature-input string.
func ParseIMSignatureInput(signatureInput string) (ParsedIMSignatureInput, error) {
	separator := strings.IndexByte(signatureInput, '=')
	if separator < 0 {
		return ParsedIMSignatureInput{}, &Error{Message: "invalid proof.signatureInput format"}
	}
	label := strings.TrimSpace(signatureInput[:separator])
	remainder := strings.TrimSpace(signatureInput[separator+1:])
	openIndex := strings.IndexByte(remainder, '(')
	closeIndex := strings.IndexByte(remainder, ')')
	if openIndex < 0 || closeIndex <= openIndex {
		return ParsedIMSignatureInput{}, &Error{Message: "invalid proof.signatureInput format"}
	}
	componentTokens := strings.Fields(remainder[openIndex+1 : closeIndex])
	components := make([]string, 0, len(componentTokens))
	for _, token := range componentTokens {
		components = append(components, strings.Trim(token, "\""))
	}
	if len(components) == 0 {
		return ParsedIMSignatureInput{}, &Error{Message: "proof.signatureInput must include covered components"}
	}
	params := parseKVParams(strings.TrimPrefix(strings.TrimSpace(remainder[closeIndex+1:]), ";"))
	keyID := params["keyid"]
	if keyID == "" {
		return ParsedIMSignatureInput{}, &Error{Message: "proof.signatureInput must include keyid"}
	}
	result := ParsedIMSignatureInput{
		Label:           label,
		Components:      components,
		SignatureParams: remainder,
		KeyID:           keyID,
		Nonce:           params["nonce"],
	}
	if created := params["created"]; created != "" {
		if value, err := strconv.ParseInt(created, 10, 64); err == nil {
			result.Created = &value
		}
	}
	if expires := params["expires"]; expires != "" {
		if value, err := strconv.ParseInt(expires, 10, 64); err == nil {
			result.Expires = &value
		}
	}
	return result, nil
}

// EncodeIMSignature encodes signature bytes into structured signature syntax.
func EncodeIMSignature(signatureBytes []byte, label string) string {
	if label == "" {
		label = "sig1"
	}
	return fmt.Sprintf("%s=:%s:", label, base64util.EncodeStd(signatureBytes))
}

// DecodeIMSignature decodes a structured or bare signature value.
func DecodeIMSignature(signature string) (string, []byte, error) {
	trimmed := strings.TrimSpace(signature)
	if strings.Contains(trimmed, "=:") {
		parts := strings.SplitN(trimmed, "=:", 2)
		if len(parts) != 2 || !strings.HasSuffix(parts[1], ":") {
			return "", nil, &Error{Message: "invalid proof.signature encoding"}
		}
		decoded, err := base64util.DecodeStd(strings.TrimSuffix(parts[1], ":"))
		if err != nil {
			decoded, err = base64util.DecodeURL(strings.TrimSuffix(parts[1], ":"))
			if err != nil {
				return "", nil, &Error{Message: "invalid proof.signature encoding"}
			}
		}
		return parts[0], decoded, nil
	}
	bare := strings.Trim(trimmed, ":")
	decoded, err := base64util.DecodeStd(bare)
	if err != nil {
		decoded, err = base64util.DecodeURL(bare)
		if err != nil {
			return "", nil, &Error{Message: "invalid proof.signature encoding"}
		}
	}
	return "", decoded, nil
}

// GenerateIMProof signs a prepared signature base and payload digest.
func GenerateIMProof(payload []byte, signatureBase []byte, privateKey anp.PrivateKeyMaterial, keyID string, options IMGenerationOptions) (IMProof, error) {
	signatureInput, err := BuildIMSignatureInput(keyID, options)
	if err != nil {
		return IMProof{}, err
	}
	signatureBytes, err := privateKey.SignMessage(signatureBase)
	if err != nil {
		return IMProof{}, &Error{Message: "signing error"}
	}
	label := options.Label
	if label == "" {
		label = "sig1"
	}
	return IMProof{ContentDigest: BuildIMContentDigest(payload), SignatureInput: signatureInput, Signature: EncodeIMSignature(signatureBytes, label)}, nil
}

// VerifyIMProofWithDocument verifies an IM proof using a DID document.
func VerifyIMProofWithDocument(proof IMProof, payload []byte, signatureBase []byte, didDocument map[string]any, expectedSignerDID string) (IMVerificationResult, error) {
	parsed, err := ParseIMSignatureInput(proof.SignatureInput)
	if err != nil {
		return IMVerificationResult{}, err
	}
	if expectedSignerDID != "" && !strings.HasPrefix(parsed.KeyID, expectedSignerDID) {
		return IMVerificationResult{}, &Error{Message: "proof keyid must belong to expected signer DID"}
	}
	verificationMethod := diddoc.FindVerificationMethod(didDocument, parsed.KeyID)
	if verificationMethod == nil {
		return IMVerificationResult{}, &Error{Message: "verification method not found in DID document"}
	}
	return VerifyIMProofWithVerificationMethod(proof, payload, signatureBase, verificationMethod, expectedSignerDID)
}

// VerifyIMProofWithVerificationMethod verifies an IM proof with an explicit verification method.
func VerifyIMProofWithVerificationMethod(proof IMProof, payload []byte, signatureBase []byte, verificationMethod map[string]any, expectedSignerDID string) (IMVerificationResult, error) {
	if !VerifyIMContentDigest(payload, proof.ContentDigest) {
		return IMVerificationResult{}, &Error{Message: "proof contentDigest does not match request payload"}
	}
	parsed, err := ParseIMSignatureInput(proof.SignatureInput)
	if err != nil {
		return IMVerificationResult{}, err
	}
	if expectedSignerDID != "" && !strings.HasPrefix(parsed.KeyID, expectedSignerDID) {
		return IMVerificationResult{}, &Error{Message: "proof keyid must belong to expected signer DID"}
	}
	label, signatureBytes, err := DecodeIMSignature(proof.Signature)
	if err != nil {
		return IMVerificationResult{}, err
	}
	if label != "" && label != parsed.Label {
		return IMVerificationResult{}, &Error{Message: "invalid proof.signature encoding"}
	}
	parsedMethod, err := vm.CreateVerificationMethod(verificationMethod)
	if err != nil {
		return IMVerificationResult{}, &Error{Message: "verification method not found in DID document"}
	}
	if err := parsedMethod.PublicKey.VerifyMessage(signatureBase, signatureBytes); err != nil {
		return IMVerificationResult{}, &Error{Message: "signature verification failed"}
	}
	return IMVerificationResult{ParsedSignatureInput: parsed, VerificationMethod: cloneMap(verificationMethod)}, nil
}

func parseKVParams(value string) map[string]string {
	result := map[string]string{}
	for _, part := range strings.Split(value, ";") {
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

func randomNonce() []byte {
	seed, _ := cjson.Marshal(map[string]any{"time": time.Now().UnixNano()})
	hash := sha256.Sum256(seed)
	return hash[:16]
}
