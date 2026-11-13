package authentication

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"regexp"
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
	if !containsFolded(covered, "@method") || !containsFolded(covered, "@target-uri") {
		return nil, fmt.Errorf("missing required signed component")
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
		nonceBytes, err := randomBytes(16)
		if err != nil {
			return nil, err
		}
		nonce = anp.EncodeBase64URL(nonceBytes)
	}
	policy := DefaultHTTPSignaturePolicy()
	policy.CryptoOnly = true
	if _, err := policy.Validate(created, expires, created); err != nil {
		return nil, err
	}
	if len(nonce) > 1024 {
		return nil, fmt.Errorf("nonce exceeds size limit")
	}
	for _, c := range nonce {
		if c < 32 || c > 126 {
			return nil, fmt.Errorf("invalid nonce parameter")
		}
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
	return VerifyHTTPMessageSignatureWithPolicy(didDocument, requestMethod, requestURL, headers, body, DefaultHTTPSignaturePolicy(), time.Now().Unix())
}

// VerifyHTTPMessageSignatureWithPolicy checks signature, coverage and time without
// consuming replay state. Full authentication must additionally check trusted
// document provenance, authentication-key authorization and receiver scope.
func VerifyHTTPMessageSignatureWithPolicy(didDocument map[string]any, requestMethod string, requestURL string, headers map[string]string, body []byte, policy HTTPSignaturePolicy, now int64) (SignatureMetadata, error) {
	signatureInput, ok := getHeaderCaseInsensitive(headers, "Signature-Input")
	if !ok {
		return SignatureMetadata{}, fmt.Errorf("missing Signature-Input or Signature header")
	}
	signatureHeader, ok := getHeaderCaseInsensitive(headers, "Signature")
	if !ok {
		return SignatureMetadata{}, fmt.Errorf("missing Signature-Input or Signature header")
	}
	labelInput, components, params, serializedParams, err := parseSignedSignatureInput(signatureInput)
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
	if !containsFolded(components, "@method") || !containsFolded(components, "@target-uri") || len(body) > 0 && !containsFolded(components, "content-digest") {
		return SignatureMetadata{}, fmt.Errorf("missing required signed component")
	}
	if !strings.HasPrefix(keyID, "did:") || strings.Count(keyID, "#") != 1 || strings.HasSuffix(keyID, "#") || strings.SplitN(keyID, "#", 2)[0] != stringValue(didDocument["id"]) {
		return SignatureMetadata{}, fmt.Errorf("signature keyid DID mismatch")
	}
	if len(params["nonce"]) > 1024 {
		return SignatureMetadata{}, fmt.Errorf("invalid nonce parameter")
	}
	if _, exists := params["nonce"]; exists && params["nonce"] == "" {
		return SignatureMetadata{}, fmt.Errorf("invalid nonce parameter")
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
	if _, err := policy.Validate(created, expires, now); err != nil {
		return SignatureMetadata{}, err
	}
	signatureBase, err := buildSignatureBaseWithParams(components, requestMethod, requestURL, headers, serializedParams)
	if err != nil {
		return SignatureMetadata{}, err
	}
	candidates, err := authorityCandidates(requestURL)
	if err != nil {
		return SignatureMetadata{}, err
	}
	bases := []string{signatureBase}
	if containsFolded(components, "@authority") {
		for _, authority := range candidates {
			bases = append(bases, replaceAuthority(signatureBase, authority))
		}
	}
	verified := false
	for _, base := range bases {
		if publicKey.VerifyMessage([]byte(base), signatureBytes) == nil {
			verified = true
			break
		}
	}
	if !verified {
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

func replaceAuthority(base, authority string) string {
	lines := strings.Split(base, "\n")
	for index, line := range lines {
		if strings.HasPrefix(line, "\"@authority\": ") {
			lines[index] = "\"@authority\": " + authority
		}
	}
	return strings.Join(lines, "\n")
}
func authorityCandidates(rawURL string) ([]string, error) {
	origin, err := AuthenticationOrigin(rawURL)
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	suffix := ":443"
	if parsed.Scheme == "http" {
		suffix = ":80"
	}
	values := []string{}
	for _, authority := range []string{parsed.Host, strings.SplitN(origin, "://", 2)[1]} {
		for _, value := range []string{authority, strings.TrimSuffix(authority, suffix)} {
			values = append(values, value, strings.NewReplacer("[", "", "]", "").Replace(value))
		}
	}
	return values, nil
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
		parts = append(parts, "nonce="+strconv.Quote(nonce))
	}
	parts = append(parts, "keyid="+strconv.Quote(keyID))
	return fmt.Sprintf("(%s);%s", strings.Join(quoted, " "), strings.Join(parts, ";"))
}

var signatureComponentPattern = regexp.MustCompile("^\"[a-z0-9@!#$%&'*+.^_`|~-]+\"(?: +\"[a-z0-9@!#$%&'*+.^_`|~-]+\")*$")
var signatureParameterPattern = regexp.MustCompile("^;([a-z*][a-z0-9_.*-]*)(?:=(\"(?:[\\x20-\\x21\\x23-\\x5b\\x5d-\\x7e]|\\\\[\"\\\\])*\"|-?[0-9]{1,15}|\\?[01]|[A-Za-z*][A-Za-z0-9!#$%&'*+.^_`|~:/-]*))?")

func parseSignatureInput(value string) (string, []string, map[string]string, error) {
	label, components, params, _, err := parseSignedSignatureInput(value)
	return label, components, params, err
}

func parseSignedSignatureInput(value string) (string, []string, map[string]string, string, error) {
	invalid := fmt.Errorf("invalid or ambiguous signature input")
	if len(value) > 16384 {
		return "", nil, nil, "", invalid
	}
	label, remainder, ok := strings.Cut(strings.TrimSpace(value), "=")
	if !ok || label == "" || !strings.HasPrefix(remainder, "(") {
		return "", nil, nil, "", invalid
	}
	for _, c := range label {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return "", nil, nil, "", invalid
		}
	}
	end := strings.IndexByte(remainder, ')')
	if end <= 1 || !signatureComponentPattern.MatchString(remainder[1:end]) {
		return "", nil, nil, "", invalid
	}
	tokens := strings.Fields(remainder[1:end])
	if len(tokens) > 32 {
		return "", nil, nil, "", invalid
	}
	seen := map[string]bool{}
	components := make([]string, 0, len(tokens))
	for _, token := range tokens {
		component := strings.Trim(token, "\"")
		if seen[component] {
			return "", nil, nil, "", invalid
		}
		seen[component] = true
		components = append(components, component)
	}
	serialized := "(" + strings.Join(tokens, " ") + ")"
	rest := remainder[end+1:]
	params := map[string]string{}
	for rest != "" {
		match := signatureParameterPattern.FindStringSubmatch(rest)
		if match == nil || len(params) >= 32 {
			return "", nil, nil, "", invalid
		}
		name, raw := match[1], match[2]
		if _, exists := params[name]; exists {
			return "", nil, nil, "", invalid
		}
		if name == "created" || name == "expires" {
			if _, err := strconv.ParseInt(raw, 10, 64); err != nil {
				return "", nil, nil, "", invalid
			}
		}
		if name == "nonce" || name == "keyid" {
			if !strings.HasPrefix(raw, "\"") {
				return "", nil, nil, "", invalid
			}
		}
		decoded := raw
		if strings.HasPrefix(raw, "\"") {
			var err error
			decoded, err = strconv.Unquote(raw)
			if err != nil {
				return "", nil, nil, "", invalid
			}
		}
		params[name] = decoded
		serialized += ";" + name
		if raw != "" && raw != "?1" {
			serialized += "=" + raw
		}
		rest = rest[len(match[0]):]
	}
	return label, components, params, serialized, nil
}

func buildSignatureBaseWithParams(components []string, method, rawURL string, headers map[string]string, params string) (string, error) {
	lines := make([]string, 0, len(components)+1)
	for _, component := range components {
		value, err := componentValue(component, method, rawURL, headers)
		if err != nil {
			return "", err
		}
		lines = append(lines, fmt.Sprintf("\"%s\": %s", component, value))
	}
	lines = append(lines, "\"@signature-params\": "+params)
	return strings.Join(lines, "\n"), nil
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
	decoded, err := base64util.DecodeStd(raw[1 : len(raw)-1])
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
	found := false
	result := ""
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			if found || len(value) > 16384 || strings.ContainsAny(value, "\r\n\x00\x7f") {
				return "", false
			}
			found, result = true, value
		}
	}
	return result, found
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
