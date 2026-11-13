package authentication

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HTTPSignaturePolicy performs stateless validation. CryptoOnly is an explicit
// offline opt-out, never suitable for incoming authentication.
type HTTPSignaturePolicy struct {
	MaxAgeSeconds     int64
	FutureSkewSeconds int64
	CryptoOnly        bool
}

func DefaultHTTPSignaturePolicy() HTTPSignaturePolicy {
	return HTTPSignaturePolicy{MaxAgeSeconds: 300, FutureSkewSeconds: 60}
}

// Validate returns the final acceptable signature timestamp, without storage I/O.
func (p HTTPSignaturePolicy) Validate(created int64, expires *int64, now int64) (int64, error) {
	if now < 0 || now > 999999999999999 || p.MaxAgeSeconds <= 0 || p.MaxAgeSeconds > 86400 || p.FutureSkewSeconds < 0 || p.FutureSkewSeconds > 86400 || created < 0 || created > 999999999999999 {
		return 0, fmt.Errorf("invalid HTTP signature time policy or created parameter")
	}
	deadline := created + p.MaxAgeSeconds
	if expires != nil {
		if *expires < created || *expires > 999999999999999 {
			return 0, fmt.Errorf("invalid expires parameter")
		}
		if *expires < deadline {
			deadline = *expires
		}
	}
	if !p.CryptoOnly && (created > now && created-now > p.FutureSkewSeconds || now > deadline) {
		return 0, fmt.Errorf("HTTP signature timestamp is expired or invalid")
	}
	return deadline, nil
}

// AuthenticationOrigin isolates credentials by normalized scheme/host/effective port.
func AuthenticationOrigin(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || parsed.User != nil || strings.Contains(raw, "#") || parsed.Hostname() == "" || parsed.Scheme != "https" && parsed.Scheme != "http" || strings.ContainsAny(raw, "\r\n\t \\") {
		return "", fmt.Errorf("invalid authentication URL")
	}
	host := strings.ToLower(parsed.Hostname())
	if strings.Contains(host, "%") {
		return "", fmt.Errorf("invalid authentication host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if strings.Contains(host, ":") && ip.To4() != nil {
			return "", fmt.Errorf("mapped IPv6 authentication origins are not supported")
		}
		host = ip.String()
	} else if strings.Trim(host, "0123456789.") == "" {
		return "", fmt.Errorf("non-canonical numeric authentication host")
	}
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return "", fmt.Errorf("invalid authentication port")
	}
	return parsed.Scheme + "://" + net.JoinHostPort(host, strconv.FormatUint(number, 10)), nil
}

// HTTPReplayContext carries verified facts, never raw signatures or credentials.
type HTTPReplayContext struct {
	SignerDID     string
	VerifierScope string
	ReplayKey     string
	ValidUntil    int64
}

// HTTPReplayStore must atomically consume once, sharing state across replicas.
// Storage errors must fail authentication, never fall back to local state.
type HTTPReplayStore interface {
	ConsumeOnce(context.Context, HTTPReplayContext) (bool, error)
}

type MemoryHTTPReplayStore struct {
	mu       sync.Mutex
	seen     map[string]int64
	capacity int
	clock    func() time.Time
}

// NewMemoryHTTPReplayStore is process-local only, bounded and thread-safe.
func NewMemoryHTTPReplayStore() *MemoryHTTPReplayStore {
	return &MemoryHTTPReplayStore{seen: map[string]int64{}, capacity: 10000, clock: time.Now}
}

func (s *MemoryHTTPReplayStore) ConsumeOnce(ctx context.Context, item HTTPReplayContext) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock().Unix()
	for key, expires := range s.seen {
		if expires < now {
			delete(s.seen, key)
		}
	}
	if item.ValidUntil < now {
		return false, nil
	}
	if _, exists := s.seen[item.ReplayKey]; exists {
		return false, nil
	}
	if len(s.seen) >= s.capacity {
		return false, fmt.Errorf("HTTP replay store capacity exhausted")
	}
	s.seen[item.ReplayKey] = item.ValidUntil
	return true, nil
}

// HTTPReplayContextForSignature must only be called after successful signature,
// identity and trusted receiver validation. Scope is host-controlled.
func HTTPReplayContextForSignature(meta SignatureMetadata, method, requestURL string, headers map[string]string, scope string, policy HTTPSignaturePolicy) (HTTPReplayContext, error) {
	if scope == "" || strings.ContainsRune(scope, 0) {
		return HTTPReplayContext{}, fmt.Errorf("invalid verifier scope")
	}
	input, ok := getHeaderCaseInsensitive(headers, "Signature-Input")
	if !ok {
		return HTTPReplayContext{}, fmt.Errorf("missing signature input")
	}
	_, components, _, params, err := parseSignedSignatureInput(input)
	if err != nil {
		return HTTPReplayContext{}, err
	}
	base, err := buildSignatureBaseWithParams(components, method, requestURL, headers, params)
	if err != nil {
		return HTTPReplayContext{}, err
	}
	origin, err := AuthenticationOrigin(requestURL)
	if err != nil {
		return HTTPReplayContext{}, err
	}
	base = replaceAuthority(base, strings.SplitN(origin, "://", 2)[1])
	signer, _, found := strings.Cut(meta.KeyID, "#")
	if !found {
		return HTTPReplayContext{}, fmt.Errorf("invalid signature keyid")
	}
	material := "nonce:" + meta.Nonce
	if meta.Nonce == "" {
		material = fmt.Sprintf("base:%x", sha256.Sum256([]byte(base)))
	}
	key := strings.Join([]string{"anp.http-auth.replay.v1", scope, signer, material}, "\x00")
	deadline, err := policy.Validate(meta.Created, meta.Expires, meta.Created)
	if err != nil {
		return HTTPReplayContext{}, err
	}
	return HTTPReplayContext{SignerDID: signer, VerifierScope: scope, ReplayKey: fmt.Sprintf("%x", sha256.Sum256([]byte(key))), ValidUntil: deadline + policy.FutureSkewSeconds}, nil
}
