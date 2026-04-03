package authentication

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/internal/base64util"
)

// BuildContentDigest builds a Content-Digest header value.
func BuildContentDigest(body []byte) string {
	hash := sha256.Sum256(body)
	return "sha-256=:" + base64util.EncodeStd(hash[:]) + ":"
}

// VerifyContentDigest verifies a Content-Digest header value.
func VerifyContentDigest(body []byte, contentDigest string) bool {
	return BuildContentDigest(body) == strings.TrimSpace(contentDigest)
}

// GenerateHTTPSignatureHeaders generates HTTP Message Signatures headers.
func GenerateHTTPSignatureHeaders(didDocument map[string]any, requestURL string, requestMethod string, privateKey anp.PrivateKeyMaterial, headers map[string]string, body []byte, options HttpSignatureOptions) (map[string]string, error) {
	keyID := options.KeyID
	if keyID == "" {
		selected, err := selectDefaultKeyID(didDocument)
		if err != nil {
			return nil, err
		}
		keyID = selected
	}
	covered := options.CoveredComponents
	if len(covered) == 0 {
		covered = []string{"@method", "@target-uri", "@authority"}
	}
	headersToSign := cloneHeaders(headers)
	if len(body) > 0 {
		if _, ok := headersToSign["Content-Digest"]; !ok {
			headersToSign["Content-Digest"] = BuildContentDigest(body)
		}
		if _, ok := headersToSign["Content-Length"]; !ok {
			headersToSign["Content-Length"] = strconv.Itoa(len(body))
		}
		if !containsFolded(covered, "content-digest") {
			covered = append(append([]string(nil), covered...), "content-digest")
		}
	}
	created := time.Now().Unix()
	if options.Created != nil {
		created = *options.Created
	}
	var expires *int64
	if options.Expires != nil {
		expires = options.Expires
	} else {
		defaultExpires := created + 300
		expires = &defaultExpires
	}
	nonce := options.Nonce
	if nonce == "" {
		nonce = anp.EncodeBase64URL(randomBytes(16))
	}
	signatureBase, err := buildSignatureBase(covered, requestMethod, requestURL, headersToSign, created, expires, nonce, keyID)
	if err != nil {
		return nil, err
	}
	signatureBytes, err := privateKey.SignMessage([]byte(signatureBase))
	if err != nil {
		return nil, err
	}
	result := map[string]string{
		"Signature-Input": fmt.Sprintf("sig1=%s", serializeSignatureParams(covered, created, expires, nonce, keyID)),
		"Signature":       fmt.Sprintf("sig1=:%s:", base64util.EncodeStd(signatureBytes)),
	}
	if value, ok := headersToSign["Content-Digest"]; ok {
		result["Content-Digest"] = value
	}
	return result, nil
}

// ExtractSignatureMetadata parses signature headers and returns their structured metadata.
func ExtractSignatureMetadata(headers map[string]string) (SignatureMetadata, error) {
	signatureInput, ok := getHeaderCaseInsensitive(headers, "Signature-Input")
	if !ok {
		return SignatureMetadata{}, fmt.Errorf("missing Signature-Input or Signature header")
	}
	signatureHeader, ok := getHeaderCaseInsensitive(headers, "Signature")
	if !ok {
		return SignatureMetadata{}, fmt.Errorf("missing Signature-Input or Signature header")
	}
	labelInput, components, params, err := parseSignatureInput(signatureInput)
	if err != nil {
		return SignatureMetadata{}, err
	}
	labelSignature, _, err := parseSignatureHeader(signatureHeader)
	if err != nil {
		return SignatureMetadata{}, err
	}
	if labelInput != labelSignature {
		return SignatureMetadata{}, fmt.Errorf("invalid signature input")
	}
	created, err := strconv.ParseInt(params["created"], 10, 64)
	if err != nil {
		return SignatureMetadata{}, fmt.Errorf("invalid signature input")
	}
	metadata := SignatureMetadata{Label: labelInput, Components: components, KeyID: params["keyid"], Nonce: params["nonce"], Created: created}
	if metadata.KeyID == "" {
		return SignatureMetadata{}, fmt.Errorf("invalid signature input")
	}
	if rawExpires := params["expires"]; rawExpires != "" {
		value, parseErr := strconv.ParseInt(rawExpires, 10, 64)
		if parseErr != nil {
			return SignatureMetadata{}, fmt.Errorf("invalid signature input")
		}
		metadata.Expires = &value
	}
	return metadata, nil
}

// VerifyHTTPMessageSignature verifies HTTP Message Signatures for a DID document.
func VerifyHTTPMessageSignature(didDocument map[string]any, requestMethod string, requestURL string, headers map[string]string, body []byte) (SignatureMetadata, error) {
	signatureInput, ok := getHeaderCaseInsensitive(headers, "Signature-Input")
	if !ok {
		return SignatureMetadata{}, fmt.Errorf("missing Signature-Input or Signature header")
	}
	signatureHeader, ok := getHeaderCaseInsensitive(headers, "Signature")
	if !ok {
		return SignatureMetadata{}, fmt.Errorf("missing Signature-Input or Signature header")
	}
	labelInput, components, params, err := parseSignatureInput(signatureInput)
	if err != nil {
		return SignatureMetadata{}, err
	}
	labelSignature, signatureBytes, err := parseSignatureHeader(signatureHeader)
	if err != nil {
		return SignatureMetadata{}, err
	}
	if labelInput != labelSignature {
		return SignatureMetadata{}, fmt.Errorf("invalid signature input")
	}
	keyID := params["keyid"]
	created, err := strconv.ParseInt(params["created"], 10, 64)
	if err != nil || keyID == "" {
		return SignatureMetadata{}, fmt.Errorf("invalid signature input")
	}
	if len(body) > 0 || containsFolded(components, "content-digest") {
		contentDigest, ok := getHeaderCaseInsensitive(headers, "Content-Digest")
		if !ok {
			return SignatureMetadata{}, fmt.Errorf("missing Content-Digest header")
		}
		if !VerifyContentDigest(body, contentDigest) {
			return SignatureMetadata{}, fmt.Errorf("content-digest verification failed")
		}
	}
	verificationMethod := FindVerificationMethod(didDocument, keyID)
	if verificationMethod == nil {
		return SignatureMetadata{}, fmt.Errorf("verification method not found")
	}
	publicKey, err := ExtractPublicKey(verificationMethod)
	if err != nil {
		return SignatureMetadata{}, fmt.Errorf("verification method not found")
	}
	var expires *int64
	if rawExpires := params["expires"]; rawExpires != "" {
		value, parseErr := strconv.ParseInt(rawExpires, 10, 64)
		if parseErr != nil {
			return SignatureMetadata{}, fmt.Errorf("invalid signature input")
		}
		expires = &value
	}
	signatureBase, err := buildSignatureBase(components, requestMethod, requestURL, headers, created, expires, params["nonce"], keyID)
	if err != nil {
		return SignatureMetadata{}, err
	}
	if err := publicKey.VerifyMessage([]byte(signatureBase), signatureBytes); err != nil {
		return SignatureMetadata{}, fmt.Errorf("signature verification failed")
	}
	return SignatureMetadata{Label: labelInput, Components: components, KeyID: keyID, Nonce: params["nonce"], Created: created, Expires: expires}, nil
}

func buildSignatureBase(components []string, method string, rawURL string, headers map[string]string, created int64, expires *int64, nonce string, keyID string) (string, error) {
	lines := make([]string, 0, len(components)+1)
	for _, component := range components {
		value, err := componentValue(component, method, rawURL, headers)
		if err != nil {
			return "", err
		}
		lines = append(lines, fmt.Sprintf("\"%s\": %s", component, value))
	}
	lines = append(lines, fmt.Sprintf("\"@signature-params\": %s", serializeSignatureParams(components, created, expires, nonce, keyID)))
	return strings.Join(lines, "\n"), nil
}

func componentValue(component string, method string, rawURL string, headers map[string]string) (string, error) {
	switch component {
	case "@method":
		return strings.ToUpper(method), nil
	case "@target-uri":
		return rawURL, nil
	case "@authority":
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return "", fmt.Errorf("invalid signature input")
		}
		host := parsed.Hostname()
		if port := parsed.Port(); port != "" {
			return host + ":" + port, nil
		}
		return host, nil
	default:
		value, ok := getHeaderCaseInsensitive(headers, component)
		if !ok {
			return "", fmt.Errorf("invalid signature input")
		}
		return value, nil
	}
}

func serializeSignatureParams(components []string, created int64, expires *int64, nonce string, keyID string) string {
	quoted := make([]string, 0, len(components))
	for _, component := range components {
		quoted = append(quoted, fmt.Sprintf("\"%s\"", component))
	}
	parts := []string{fmt.Sprintf("created=%d", created)}
	if expires != nil {
		parts = append(parts, fmt.Sprintf("expires=%d", *expires))
	}
	if nonce != "" {
		parts = append(parts, fmt.Sprintf("nonce=\"%s\"", nonce))
	}
	parts = append(parts, fmt.Sprintf("keyid=\"%s\"", keyID))
	return fmt.Sprintf("(%s);%s", strings.Join(quoted, " "), strings.Join(parts, ";"))
}

func parseSignatureInput(value string) (string, []string, map[string]string, error) {
	separator := strings.IndexByte(value, '=')
	if separator < 0 {
		return "", nil, nil, fmt.Errorf("invalid signature input")
	}
	label := value[:separator]
	remainder := value[separator+1:]
	openIndex := strings.IndexByte(remainder, '(')
	closeIndex := strings.IndexByte(remainder, ')')
	if openIndex < 0 || closeIndex <= openIndex {
		return "", nil, nil, fmt.Errorf("invalid signature input")
	}
	componentTokens := strings.Fields(remainder[openIndex+1 : closeIndex])
	components := make([]string, 0, len(componentTokens))
	for _, token := range componentTokens {
		components = append(components, strings.Trim(token, "\""))
	}
	if len(components) == 0 {
		return "", nil, nil, fmt.Errorf("invalid signature input")
	}
	params := parseAuthParams(strings.TrimPrefix(strings.TrimSpace(remainder[closeIndex+1:]), ";"))
	return label, components, params, nil
}

func parseSignatureHeader(value string) (string, []byte, error) {
	separator := strings.IndexByte(value, '=')
	if separator < 0 {
		return "", nil, fmt.Errorf("invalid signature header format")
	}
	label := value[:separator]
	raw := value[separator+1:]
	if !strings.HasPrefix(raw, ":") || !strings.HasSuffix(raw, ":") {
		return "", nil, fmt.Errorf("invalid signature header format")
	}
	decoded, err := base64util.DecodeStd(strings.Trim(raw, ":"))
	if err != nil {
		return "", nil, fmt.Errorf("invalid signature header format")
	}
	return label, decoded, nil
}

func selectDefaultKeyID(didDocument map[string]any) (string, error) {
	authentication, ok := didDocument["authentication"].([]any)
	if !ok || len(authentication) == 0 {
		return "", fmt.Errorf("verification method not found")
	}
	switch first := authentication[0].(type) {
	case string:
		return first, nil
	case map[string]any:
		value, _ := first["id"].(string)
		if value == "" {
			return "", fmt.Errorf("verification method not found")
		}
		return value, nil
	default:
		return "", fmt.Errorf("verification method not found")
	}
}

func getHeaderCaseInsensitive(headers map[string]string, name string) (string, bool) {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return "", false
}

func cloneHeaders(headers map[string]string) map[string]string {
	result := map[string]string{}
	for key, value := range headers {
		result[key] = value
	}
	return result
}

func containsFolded(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}
