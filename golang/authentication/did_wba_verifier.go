package authentication

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"time"

	anp "github.com/agent-network-protocol/anp/golang"
)

// DidWbaVerifier verifies inbound ANP HTTP requests.
type DidWbaVerifier struct {
	config     DidWbaVerifierConfig
	usedNonces map[string]time.Time
	mu         sync.Mutex
}

// NewDidWbaVerifier creates a request verifier with defaults.
func NewDidWbaVerifier(config DidWbaVerifierConfig) *DidWbaVerifier {
	return &DidWbaVerifier{config: withVerifierDefaults(config), usedNonces: map[string]time.Time{}}
}

// VerifyRequest resolves the sender DID and verifies the request.
func (v *DidWbaVerifier) VerifyRequest(ctx context.Context, method string, requestURL string, headers map[string]string, body []byte, domain string) (VerificationSuccess, error) {
	requestDomain := domain
	if requestDomain == "" {
		requestDomain = extractDomain(requestURL)
	}
	if err := v.validateAllowedDomain(requestDomain); err != nil {
		return VerificationSuccess{}, err
	}
	if authorization, ok := getHeaderCaseInsensitive(headers, "Authorization"); ok && strings.HasPrefix(authorization, "Bearer ") {
		return v.handleBearerAuth(strings.TrimPrefix(authorization, "Bearer "))
	}
	if _, ok := getHeaderCaseInsensitive(headers, "Signature-Input"); ok {
		if !boolValue(v.config.AllowHTTPSignatures, true) {
			return VerificationSuccess{}, v.challengeError("HTTP Message Signatures authentication is disabled", 401, requestDomain, "invalid_request")
		}
		metadata, err := ExtractSignatureMetadata(headers)
		if err != nil {
			return VerificationSuccess{}, v.challengeError("Invalid signature metadata", 401, requestDomain, "invalid_request")
		}
		did := strings.Split(metadata.KeyID, "#")[0]
		document, err := ResolveDidWBADocumentWithOptions(ctx, did, false, v.config.DidResolutionOptions)
		if err != nil {
			return VerificationSuccess{}, v.challengeError("Failed to resolve DID document", 401, requestDomain, "invalid_did")
		}
		return v.VerifyRequestWithDidDocument(method, requestURL, headers, body, requestDomain, document)
	}
	if authorization, ok := getHeaderCaseInsensitive(headers, "Authorization"); ok {
		if !boolValue(v.config.AllowLegacyDidWba, true) {
			return VerificationSuccess{}, v.challengeError("Legacy DIDWba authentication is disabled", 401, requestDomain, "invalid_request")
		}
		parsed, err := ExtractAuthHeaderParts(authorization)
		if err != nil {
			return VerificationSuccess{}, v.challengeError("Invalid authorization header format", 401, requestDomain, "invalid_request")
		}
		document, err := ResolveDidWBADocumentWithOptions(ctx, parsed.DID, false, v.config.DidResolutionOptions)
		if err != nil {
			return VerificationSuccess{}, v.challengeError("Failed to resolve DID document", 401, requestDomain, "invalid_did")
		}
		return v.VerifyRequestWithDidDocument(method, requestURL, headers, body, requestDomain, document)
	}
	return VerificationSuccess{}, &DidWbaVerifierError{Message: "missing authentication headers", StatusCode: 401, Headers: map[string]string{}}
}

// VerifyRequestWithDidDocument verifies a request against an already resolved DID document.
func (v *DidWbaVerifier) VerifyRequestWithDidDocument(method string, requestURL string, headers map[string]string, body []byte, domain string, didDocument map[string]any) (VerificationSuccess, error) {
	requestDomain := domain
	if requestDomain == "" {
		requestDomain = extractDomain(requestURL)
	}
	if err := v.validateAllowedDomain(requestDomain); err != nil {
		return VerificationSuccess{}, err
	}
	if authorization, ok := getHeaderCaseInsensitive(headers, "Authorization"); ok && strings.HasPrefix(authorization, "Bearer ") {
		return v.handleBearerAuth(strings.TrimPrefix(authorization, "Bearer "))
	}
	if _, ok := getHeaderCaseInsensitive(headers, "Signature-Input"); ok {
		return v.handleHTTPSignatureAuth(method, requestURL, headers, body, requestDomain, didDocument)
	}
	if authorization, ok := getHeaderCaseInsensitive(headers, "Authorization"); ok {
		return v.handleLegacyAuth(authorization, requestDomain, didDocument)
	}
	return VerificationSuccess{}, &DidWbaVerifierError{Message: "missing authentication headers", StatusCode: 401, Headers: map[string]string{}}
}

func (v *DidWbaVerifier) handleHTTPSignatureAuth(method string, requestURL string, headers map[string]string, body []byte, domain string, didDocument map[string]any) (VerificationSuccess, error) {
	metadata, err := ExtractSignatureMetadata(headers)
	if err != nil {
		return VerificationSuccess{}, v.challengeError("Invalid signature metadata", 401, domain, "invalid_request")
	}
	did := strings.Split(metadata.KeyID, "#")[0]
	if !ValidateDIDDocumentBinding(didDocument, false) {
		return VerificationSuccess{}, &DidWbaVerifierError{Message: "DID binding verification failed", StatusCode: 401, Headers: map[string]string{}}
	}
	if !IsAuthenticationAuthorized(didDocument, metadata.KeyID) {
		return VerificationSuccess{}, &DidWbaVerifierError{Message: "Verification method is not authorized for authentication", StatusCode: 403, Headers: map[string]string{}}
	}
	verified, err := VerifyHTTPMessageSignature(didDocument, method, requestURL, headers, body)
	if err != nil {
		return VerificationSuccess{}, v.challengeError("Invalid signature", 401, domain, "invalid_signature")
	}
	if !v.verifyHTTPSignatureTimeWindow(verified.Created, verified.Expires) {
		return VerificationSuccess{}, v.challengeError("HTTP signature timestamp is expired or invalid", 401, domain, "invalid_timestamp")
	}
	if boolValue(v.config.RequireNonceForHTTPSignatures, true) && verified.Nonce == "" {
		return VerificationSuccess{}, v.challengeError("HTTP signature nonce is required", 401, domain, "invalid_nonce")
	}
	if verified.Nonce != "" && !v.isValidNonce(did, verified.Nonce) {
		return VerificationSuccess{}, v.challengeError("Nonce has already been used or expired", 401, domain, "invalid_nonce")
	}
	accessToken, err := v.createAccessToken(did)
	if err != nil {
		return VerificationSuccess{}, err
	}
	return v.buildSuccessResult(did, "http_signatures", accessToken), nil
}

func (v *DidWbaVerifier) handleLegacyAuth(authorization string, domain string, didDocument map[string]any) (VerificationSuccess, error) {
	parsed, err := ExtractAuthHeaderParts(authorization)
	if err != nil {
		return VerificationSuccess{}, v.challengeError("Invalid authorization header format", 401, domain, "invalid_request")
	}
	if !v.verifyLegacyTimestamp(parsed.Timestamp) {
		return VerificationSuccess{}, v.challengeError("Legacy DIDWba timestamp is expired or invalid", 401, domain, "invalid_timestamp")
	}
	if !v.isValidNonce(parsed.DID, parsed.Nonce) {
		return VerificationSuccess{}, v.challengeError("Legacy DIDWba nonce has already been used or expired", 401, domain, "invalid_nonce")
	}
	if !ValidateDIDDocumentBinding(didDocument, false) {
		return VerificationSuccess{}, &DidWbaVerifierError{Message: "DID binding verification failed", StatusCode: 401, Headers: map[string]string{}}
	}
	keyID := parsed.DID + "#" + parsed.VerificationMethod
	if !IsAuthenticationAuthorized(didDocument, keyID) {
		return VerificationSuccess{}, &DidWbaVerifierError{Message: "Verification method is not authorized for authentication", StatusCode: 403, Headers: map[string]string{}}
	}
	if err := VerifyAuthHeaderSignature(authorization, didDocument, domain); err != nil {
		return VerificationSuccess{}, v.challengeError("Legacy DIDWba signature verification failed", 401, domain, "invalid_signature")
	}
	accessToken, err := v.createAccessToken(parsed.DID)
	if err != nil {
		return VerificationSuccess{}, err
	}
	return v.buildSuccessResult(parsed.DID, "legacy_didwba", accessToken), nil
}

func (v *DidWbaVerifier) handleBearerAuth(token string) (VerificationSuccess, error) {
	claims, err := verifyJWT(token, v.config)
	if err != nil {
		return VerificationSuccess{}, &DidWbaVerifierError{Message: err.Error(), StatusCode: 401, Headers: map[string]string{}}
	}
	now := time.Now().Unix()
	if claims.IssuedAt > now+5 {
		return VerificationSuccess{}, &DidWbaVerifierError{Message: "token issued in the future", StatusCode: 401, Headers: map[string]string{}}
	}
	if claims.ExpiresAt <= now-5 {
		return VerificationSuccess{}, &DidWbaVerifierError{Message: "token has expired", StatusCode: 401, Headers: map[string]string{}}
	}
	return v.buildSuccessResult(claims.Subject, "bearer", ""), nil
}

func (v *DidWbaVerifier) buildSuccessResult(did string, authScheme string, accessToken string) VerificationSuccess {
	responseHeaders := map[string]string{}
	if accessToken != "" {
		expiresIn := v.config.AccessTokenExpireMinutes * 60
		if boolValue(v.config.EmitAuthenticationInfoHeader, true) {
			responseHeaders["Authentication-Info"] = fmt.Sprintf("access_token=\"%s\", token_type=\"Bearer\", expires_in=%d", accessToken, expiresIn)
		}
		if boolValue(v.config.EmitLegacyAuthorizationHeader, true) {
			responseHeaders["Authorization"] = "Bearer " + accessToken
		}
	}
	return VerificationSuccess{DID: did, AuthScheme: authScheme, ResponseHeaders: responseHeaders, AccessToken: accessToken, TokenType: "bearer"}
}

func (v *DidWbaVerifier) validateAllowedDomain(domain string) error {
	if len(v.config.AllowedDomains) == 0 {
		return nil
	}
	for _, candidate := range v.config.AllowedDomains {
		if candidate == domain {
			return nil
		}
	}
	return &DidWbaVerifierError{Message: "domain is not allowed", StatusCode: 403, Headers: map[string]string{}}
}

func (v *DidWbaVerifier) verifyLegacyTimestamp(timestamp string) bool {
	parsed, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return false
	}
	now := time.Now().UTC()
	if parsed.After(now.Add(time.Minute)) {
		return false
	}
	return now.Sub(parsed) <= time.Duration(v.config.TimestampExpirationMinutes)*time.Minute
}

func (v *DidWbaVerifier) verifyHTTPSignatureTimeWindow(created int64, expires *int64) bool {
	now := time.Now().Unix()
	if created > now+60 {
		return false
	}
	if now-created > int64(v.config.TimestampExpirationMinutes*60) {
		return false
	}
	if expires != nil && *expires < now {
		return false
	}
	return true
}

func (v *DidWbaVerifier) isValidNonce(did string, nonce string) bool {
	if v.config.ExternalNonceValidator != nil {
		return v.config.ExternalNonceValidator(did, nonce)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	now := time.Now().UTC()
	expiration := time.Duration(v.config.NonceExpirationMinutes) * time.Minute
	for key, issuedAt := range v.usedNonces {
		if now.Sub(issuedAt) > expiration {
			delete(v.usedNonces, key)
		}
	}
	cacheKey := did + ":" + nonce
	if _, exists := v.usedNonces[cacheKey]; exists {
		return false
	}
	v.usedNonces[cacheKey] = now
	return true
}

func (v *DidWbaVerifier) createAccessToken(did string) (string, error) {
	claims := jwtClaims{Subject: did, IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Duration(v.config.AccessTokenExpireMinutes) * time.Minute).Unix()}
	return signJWT(claims, v.config)
}

func (v *DidWbaVerifier) challengeError(message string, statusCode int, domain string, errorCode string) *DidWbaVerifierError {
	headers := map[string]string{"WWW-Authenticate": fmt.Sprintf("DIDWba realm=\"%s\", error=\"%s\", error_description=\"%s\"", domain, errorCode, message)}
	if boolValue(v.config.AllowHTTPSignatures, true) {
		headers["Accept-Signature"] = "sig1=(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\");created;expires;nonce;keyid"
	}
	return &DidWbaVerifierError{Message: message, StatusCode: statusCode, Headers: headers}
}

type jwtClaims struct {
	Subject   string `json:"sub"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

func withVerifierDefaults(config DidWbaVerifierConfig) DidWbaVerifierConfig {
	if config.JWTAlgorithm == "" {
		config.JWTAlgorithm = "RS256"
	}
	if config.AccessTokenExpireMinutes == 0 {
		config.AccessTokenExpireMinutes = 60
	}
	if config.NonceExpirationMinutes == 0 {
		config.NonceExpirationMinutes = 6
	}
	if config.TimestampExpirationMinutes == 0 {
		config.TimestampExpirationMinutes = 5
	}
	return config
}

func signJWT(claims jwtClaims, config DidWbaVerifierConfig) (string, error) {
	headerBytes, _ := json.Marshal(map[string]any{"alg": config.JWTAlgorithm, "typ": "JWT"})
	payloadBytes, _ := json.Marshal(claims)
	header := anp.EncodeBase64URL(headerBytes)
	payload := anp.EncodeBase64URL(payloadBytes)
	signingInput := header + "." + payload
	signature, err := jwtSign([]byte(signingInput), config.JWTAlgorithm, config.JWTPrivateKey)
	if err != nil {
		return "", &DidWbaVerifierError{Message: err.Error(), StatusCode: 500, Headers: map[string]string{}}
	}
	return signingInput + "." + anp.EncodeBase64URL(signature), nil
}

func verifyJWT(token string, config DidWbaVerifierConfig) (jwtClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return jwtClaims{}, fmt.Errorf("invalid token")
	}
	signingInput := parts[0] + "." + parts[1]
	signature, err := anp.DecodeBase64URL(parts[2])
	if err != nil {
		return jwtClaims{}, fmt.Errorf("invalid token")
	}
	secret := config.JWTPublicKey
	if secret == "" {
		secret = config.JWTPrivateKey
	}
	if err := jwtVerify([]byte(signingInput), signature, config.JWTAlgorithm, secret); err != nil {
		return jwtClaims{}, fmt.Errorf("invalid token")
	}
	payloadBytes, err := anp.DecodeBase64URL(parts[1])
	if err != nil {
		return jwtClaims{}, fmt.Errorf("invalid token")
	}
	var claims jwtClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return jwtClaims{}, fmt.Errorf("invalid token")
	}
	return claims, nil
}

func jwtSign(signingInput []byte, algorithm string, secret string) ([]byte, error) {
	hash, err := jwtHashForAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	switch algorithm {
	case "HS256", "HS384", "HS512":
		mac := hmac.New(hash.New, []byte(secret))
		mac.Write(signingInput)
		return mac.Sum(nil), nil
	case "RS256", "RS384", "RS512":
		privateKey, err := parseRSAPrivateKey(secret)
		if err != nil {
			return nil, fmt.Errorf("invalid JWT private key")
		}
		h := hash.New()
		h.Write(signingInput)
		digest := h.Sum(nil)
		return rsa.SignPKCS1v15(rand.Reader, privateKey, hash, digest)
	default:
		return nil, fmt.Errorf("unsupported JWT algorithm")
	}
}

func jwtVerify(signingInput []byte, signature []byte, algorithm string, secret string) error {
	hash, err := jwtHashForAlgorithm(algorithm)
	if err != nil {
		return err
	}
	switch algorithm {
	case "HS256", "HS384", "HS512":
		mac := hmac.New(hash.New, []byte(secret))
		mac.Write(signingInput)
		expected := mac.Sum(nil)
		if !hmac.Equal(expected, signature) {
			return fmt.Errorf("invalid token")
		}
		return nil
	case "RS256", "RS384", "RS512":
		publicKey, err := parseRSAPublicKey(secret)
		if err != nil {
			return fmt.Errorf("invalid JWT public key")
		}
		h := hash.New()
		h.Write(signingInput)
		digest := h.Sum(nil)
		return rsa.VerifyPKCS1v15(publicKey, hash, digest, signature)
	default:
		return fmt.Errorf("unsupported JWT algorithm")
	}
}

func jwtHashForAlgorithm(algorithm string) (crypto.Hash, error) {
	switch algorithm {
	case "HS256", "RS256":
		return crypto.SHA256, nil
	case "HS384", "RS384":
		return crypto.SHA384, nil
	case "HS512", "RS512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported JWT algorithm")
	}
}

func parseRSAPrivateKey(pemValue string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		return nil, fmt.Errorf("invalid RSA private key")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid RSA private key")
	}
	return rsaKey, nil
}

func parseRSAPublicKey(pemValue string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		return nil, fmt.Errorf("invalid RSA public key")
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PublicKey)
		if ok {
			return rsaKey, nil
		}
	}
	if key, err := x509.ParseCertificate(block.Bytes); err == nil {
		if rsaKey, ok := key.PublicKey.(*rsa.PublicKey); ok {
			return rsaKey, nil
		}
	}
	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("invalid RSA public key")
}

func boolValue(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}
