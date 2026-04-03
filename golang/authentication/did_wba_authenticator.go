package authentication

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	anp "github.com/agent-network-protocol/anp/golang"
)

// DIDWbaAuthHeader manages outgoing DIDWba and HTTP signature authentication headers.
type DIDWbaAuthHeader struct {
	didDocumentPath string
	privateKeyPath  string
	authMode        AuthMode
	didDocument     map[string]any
	tokens          map[string]string
}

// NewDIDWbaAuthHeader creates a new auth header helper.
func NewDIDWbaAuthHeader(didDocumentPath string, privateKeyPath string, authMode AuthMode) *DIDWbaAuthHeader {
	if authMode == "" {
		authMode = AuthModeHTTPSignatures
	}
	return &DIDWbaAuthHeader{didDocumentPath: filepath.Clean(didDocumentPath), privateKeyPath: filepath.Clean(privateKeyPath), authMode: authMode, tokens: map[string]string{}}
}

// GetAuthHeader returns the next outbound authentication headers.
func (h *DIDWbaAuthHeader) GetAuthHeader(serverURL string, forceNew bool, method string, headers map[string]string, body []byte) (map[string]string, error) {
	domain := extractDomain(serverURL)
	if !forceNew {
		if token, ok := h.tokens[domain]; ok {
			return map[string]string{"Authorization": "Bearer " + token}, nil
		}
	}
	didDocument, err := h.loadDidDocument()
	if err != nil {
		return nil, err
	}
	privateKey, err := h.loadPrivateKey()
	if err != nil {
		return nil, err
	}
	switch h.authMode {
	case AuthModeLegacyDidWba:
		authorization, err := GenerateAuthHeader(didDocument, domain, privateKey, "1.1")
		if err != nil {
			return nil, err
		}
		return map[string]string{"Authorization": authorization}, nil
	case AuthModeAuto, AuthModeHTTPSignatures:
		return GenerateHTTPSignatureHeaders(didDocument, serverURL, method, privateKey, headers, body, HttpSignatureOptions{})
	default:
		return nil, errUnsupportedAuthMode(h.authMode)
	}
}

// UpdateToken stores a bearer token discovered in response headers.
func (h *DIDWbaAuthHeader) UpdateToken(serverURL string, headers map[string]string) string {
	domain := extractDomain(serverURL)
	if value, ok := getHeaderCaseInsensitive(headers, "Authentication-Info"); ok {
		parsed := parseAuthenticationInfo(value)
		if token := parsed["access_token"]; token != "" {
			h.tokens[domain] = token
			return token
		}
	}
	if value, ok := getHeaderCaseInsensitive(headers, "Authorization"); ok && strings.HasPrefix(value, "Bearer ") {
		token := strings.TrimPrefix(value, "Bearer ")
		h.tokens[domain] = token
		return token
	}
	return ""
}

// ClearToken removes a cached bearer token for the given server.
func (h *DIDWbaAuthHeader) ClearToken(serverURL string) {
	delete(h.tokens, extractDomain(serverURL))
}

// ClearAllTokens clears all cached bearer tokens.
func (h *DIDWbaAuthHeader) ClearAllTokens() {
	h.tokens = map[string]string{}
}

// ShouldRetryAfter401 determines whether a 401 response should be retried with a new challenge response.
func (h *DIDWbaAuthHeader) ShouldRetryAfter401(responseHeaders map[string]string) bool {
	wwwAuthenticate, ok := getHeaderCaseInsensitive(responseHeaders, "WWW-Authenticate")
	if !ok {
		return false
	}
	challenge := parseWWWAuthenticate(wwwAuthenticate)
	if challenge["nonce"] != "" {
		return true
	}
	errorValue := challenge["error"]
	return errorValue != "invalid_did" && errorValue != "invalid_verification_method" && errorValue != "forbidden_did"
}

// GetChallengeAuthHeader returns challenge-specific authentication headers.
func (h *DIDWbaAuthHeader) GetChallengeAuthHeader(serverURL string, responseHeaders map[string]string, method string, headers map[string]string, body []byte) (map[string]string, error) {
	challenge := map[string]string{}
	if value, ok := getHeaderCaseInsensitive(responseHeaders, "WWW-Authenticate"); ok {
		challenge = parseWWWAuthenticate(value)
	}
	var covered []string
	if value, ok := getHeaderCaseInsensitive(responseHeaders, "Accept-Signature"); ok {
		covered = normalizeCoveredComponents(parseAcceptSignature(value), headers, body)
	}
	didDocument, err := h.loadDidDocument()
	if err != nil {
		return nil, err
	}
	privateKey, err := h.loadPrivateKey()
	if err != nil {
		return nil, err
	}
	switch h.authMode {
	case AuthModeLegacyDidWba:
		authorization, err := generateAuthHeaderWithOverrides(didDocument, extractDomain(serverURL), privateKey, "1.1", challenge["nonce"], "")
		if err != nil {
			return nil, err
		}
		return map[string]string{"Authorization": authorization}, nil
	case AuthModeAuto, AuthModeHTTPSignatures:
		return GenerateHTTPSignatureHeaders(didDocument, serverURL, method, privateKey, headers, body, HttpSignatureOptions{Nonce: challenge["nonce"], CoveredComponents: covered})
	default:
		return nil, errUnsupportedAuthMode(h.authMode)
	}
}

func (h *DIDWbaAuthHeader) loadDidDocument() (map[string]any, error) {
	if h.didDocument != nil {
		return h.didDocument, nil
	}
	data, err := os.ReadFile(h.didDocumentPath)
	if err != nil {
		return nil, err
	}
	var document map[string]any
	if err := decodeJSON(strings.NewReader(string(data)), &document); err != nil {
		return nil, err
	}
	h.didDocument = document
	return document, nil
}

func (h *DIDWbaAuthHeader) loadPrivateKey() (anp.PrivateKeyMaterial, error) {
	data, err := os.ReadFile(h.privateKeyPath)
	if err != nil {
		return anp.PrivateKeyMaterial{}, err
	}
	return anp.PrivateKeyFromPEM(string(data))
}

func parseAuthenticationInfo(value string) map[string]string {
	return parseDelimitedParams(value, ',')
}

func parseWWWAuthenticate(value string) map[string]string {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.TrimPrefix(strings.TrimPrefix(trimmed, "DIDWba "), "didwba ")
	return parseDelimitedParams(trimmed, ',')
}

func parseAcceptSignature(value string) []string {
	matches := acceptSignatureRegexp.FindAllStringSubmatch(value, -1)
	components := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) == 2 {
			components = append(components, match[1])
		}
	}
	return components
}

func normalizeCoveredComponents(components []string, headers map[string]string, body []byte) []string {
	if len(components) == 0 {
		return nil
	}
	normalizedHeaders := map[string]string{}
	for key, value := range headers {
		normalizedHeaders[strings.ToLower(key)] = value
	}
	bodyPresent := len(body) > 0
	result := make([]string, 0, len(components))
	for _, component := range components {
		lower := strings.ToLower(component)
		switch {
		case lower == "content-digest" && !bodyPresent:
			continue
		case lower == "content-length" && !bodyPresent && normalizedHeaders["content-length"] == "":
			continue
		case lower == "content-type" && normalizedHeaders["content-type"] == "":
			continue
		case !strings.HasPrefix(lower, "@") && lower != "content-length" && lower != "content-digest" && normalizedHeaders[lower] == "":
			continue
		default:
			result = append(result, component)
		}
	}
	return result
}

func parseDelimitedParams(value string, separator rune) map[string]string {
	result := map[string]string{}
	for _, part := range strings.Split(value, string(separator)) {
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

func errUnsupportedAuthMode(mode AuthMode) error {
	return fmt.Errorf("unsupported auth mode: %s", mode)
}

var acceptSignatureRegexp = regexp.MustCompile(`"([^"]+)"`)
