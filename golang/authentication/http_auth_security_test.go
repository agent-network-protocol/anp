package authentication

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/internal/httpsecurity"
)

type securityVectorCorpus struct {
	Now      int64          `json:"now"`
	Document map[string]any `json:"document"`
	Cases    []struct {
		ID       string            `json:"id"`
		Method   string            `json:"method"`
		URL      string            `json:"url"`
		Body     string            `json:"body"`
		Headers  map[string]string `json:"headers"`
		Accepted bool              `json:"accepted"`
	} `json:"cases"`
}

func securityCorpus(t *testing.T) securityVectorCorpus {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "authentication", "security_vectors_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result securityVectorCorpus
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestHTTPAuthSecuritySharedVectors(t *testing.T) {
	corpus := securityCorpus(t)
	for _, vector := range corpus.Cases {
		t.Run(vector.ID, func(t *testing.T) {
			_, err := VerifyHTTPMessageSignatureWithPolicy(corpus.Document, vector.Method, vector.URL, vector.Headers, []byte(vector.Body), DefaultHTTPSignaturePolicy(), corpus.Now)
			if (err == nil) != vector.Accepted {
				t.Fatalf("accepted=%v error=%v", vector.Accepted, err)
			}
		})
	}
}

func TestHTTPAuthSecurityRealTimeDefaultAndExplicitOffline(t *testing.T) {
	corpus := securityCorpus(t)
	vector := corpus.Cases[2]
	if _, err := VerifyHTTPMessageSignature(corpus.Document, vector.Method, vector.URL, vector.Headers, nil); err == nil {
		t.Fatal("expired signature accepted")
	}
	policy := DefaultHTTPSignaturePolicy()
	policy.CryptoOnly = true
	if _, err := VerifyHTTPMessageSignatureWithPolicy(corpus.Document, vector.Method, vector.URL, vector.Headers, nil, policy, corpus.Now); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPAuthSecurityAmbiguousInputsAndUnsignedExtensions(t *testing.T) {
	corpus := securityCorpus(t)
	vector := corpus.Cases[0]
	for _, mutation := range []string{"duplicate_header", "duplicate_created", "unsigned_extension"} {
		headers := cloneHeaders(vector.Headers)
		switch mutation {
		case "duplicate_header":
			headers["signature-input"] = headers["Signature-Input"]
		case "duplicate_created":
			headers["Signature-Input"] += ";created=1"
		case "unsigned_extension":
			headers["Signature-Input"] += ";tag=\"not-signed\""
		}
		if _, err := VerifyHTTPMessageSignatureWithPolicy(corpus.Document, vector.Method, vector.URL, headers, nil, DefaultHTTPSignaturePolicy(), corpus.Now); err == nil {
			t.Fatalf("accepted %s", mutation)
		}
	}
}

func TestReplayStoreAtomicRetentionAndCancellation(t *testing.T) {
	store := NewMemoryHTTPReplayStore()
	now := int64(1794556800)
	store.clock = func() time.Time { return time.Unix(now, 0) }
	store.capacity = 1
	item := HTTPReplayContext{SignerDID: "did:web:unit.example", VerifierScope: "receiver", ReplayKey: "unit", ValidUntil: now + 60}
	var accepted atomic.Int64
	var workers sync.WaitGroup
	for i := 0; i < 20; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			first, err := store.ConsumeOnce(context.Background(), item)
			if err != nil {
				t.Error(err)
			}
			if first {
				accepted.Add(1)
			}
		}()
	}
	workers.Wait()
	if accepted.Load() != 1 {
		t.Fatal("more than one consumer accepted")
	}
	now += 60
	if first, _ := store.ConsumeOnce(context.Background(), item); first {
		t.Fatal("replayed at deadline")
	}
	other := item
	other.ReplayKey, other.ValidUntil = "other", now+60
	if _, err := store.ConsumeOnce(context.Background(), other); err == nil {
		t.Fatal("live keys evicted")
	}
	now++
	if first, err := store.ConsumeOnce(context.Background(), other); !first || err != nil {
		t.Fatal(first, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.ConsumeOnce(ctx, other); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestHTTPAuthSecurityReplayContextAndOriginIsolation(t *testing.T) {
	corpus := securityCorpus(t)
	vector := corpus.Cases[1]
	policy := DefaultHTTPSignaturePolicy()
	meta, err := VerifyHTTPMessageSignatureWithPolicy(corpus.Document, vector.Method, vector.URL, vector.Headers, nil, policy, corpus.Now)
	if err != nil {
		t.Fatal(err)
	}
	item, err := HTTPReplayContextForSignature(meta, vector.Method, vector.URL, vector.Headers, "https://receiver.example:443", policy)
	if err != nil || len(item.ReplayKey) != 64 || item.ValidUntil != corpus.Now+360 {
		t.Fatal(item, err)
	}
	a, err := AuthenticationOrigin("https://EXAMPLE.com/a")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := AuthenticationOrigin("https://example.com:443/b")
	c, _ := AuthenticationOrigin("https://example.com:8443/b")
	if a != b || a == c {
		t.Fatal(a, b, c)
	}
	for _, value := range []string{"https://user@example.com/", "https://example.com:0/", "https://example.com/#x", "file://example.com/a"} {
		if _, err := AuthenticationOrigin(value); err == nil {
			t.Fatalf("accepted %s", value)
		}
	}
}

type unavailableHTTPReplayStore struct{}

func (unavailableHTTPReplayStore) ConsumeOnce(context.Context, HTTPReplayContext) (bool, error) {
	return false, fmt.Errorf("unit store unavailable")
}

func TestHTTPAuthSecurityTwoVerifiersShareAtomicStore(t *testing.T) {
	corpus := securityCorpus(t)
	vector := corpus.Cases[1]
	now := func() time.Time { return time.Unix(corpus.Now, 0) }
	store := NewMemoryHTTPReplayStore()
	store.clock = now
	no := false
	config := DidWbaVerifierConfig{JWTAlgorithm: "HS256", JWTPrivateKey: "public-unit-test-secret-not-production", RequireNonceForHTTPSignatures: &no}
	makeVerifier := func(store HTTPReplayStore) *DidWbaVerifier {
		return NewDidWbaVerifier(config).WithClock(now).WithReplayStore(store, "https://receiver.example:443")
	}
	first, second := makeVerifier(store), makeVerifier(store)
	bad := cloneHeaders(vector.Headers)
	bad["Signature"] = "sig1=:AA==:"
	if _, err := first.VerifyRequestWithDidDocument("GET", vector.URL, bad, nil, "", corpus.Document); err == nil {
		t.Fatal("accepted invalid signature")
	}
	var accepted atomic.Int64
	var workers sync.WaitGroup
	for _, verifier := range []*DidWbaVerifier{first, second} {
		workers.Add(1)
		go func(verifier *DidWbaVerifier) {
			defer workers.Done()
			result, err := verifier.VerifyRequestWithDidDocument("GET", vector.URL, vector.Headers, nil, "", corpus.Document)
			if err == nil {
				if result.DID != stringValue(corpus.Document["id"]) {
					t.Error("identity substituted")
				}
				accepted.Add(1)
			}
		}(verifier)
	}
	workers.Wait()
	if accepted.Load() != 1 {
		t.Fatal("expected exactly one successful consumer")
	}
	_, err := makeVerifier(unavailableHTTPReplayStore{}).VerifyRequestWithDidDocument("GET", vector.URL, vector.Headers, nil, "", corpus.Document)
	var unavailable *DidWbaVerifierError
	if !errors.As(err, &unavailable) || unavailable.StatusCode != 503 {
		t.Fatalf("expected unavailable, got %v", err)
	}
}

func TestHTTPAuthSecurityFederationRejectsReplayAndOfflinePolicy(t *testing.T) {
	corpus := securityCorpus(t)
	vector := corpus.Cases[0]
	store := NewMemoryHTTPReplayStore()
	store.clock = func() time.Time { return time.Unix(corpus.Now, 0) }
	senderID := "did:web:sender.example:agent"
	sender := map[string]any{"id": senderID, "service": []any{map[string]any{"id": "message", "type": ANPMessageServiceType, "serviceDid": corpus.Document["id"], "serviceEndpoint": "https://receiver.example/rpc"}}}
	options := FederatedVerificationOptions{SenderDidDocument: sender, ServiceDidDocument: corpus.Document}
	security := FederatedHTTPSecurity{Policy: DefaultHTTPSignaturePolicy(), Now: corpus.Now, VerifierScope: "receiver", ReplayStore: store}
	for _, expected := range []bool{true, false} {
		_, err := VerifyFederatedHTTPRequestWithSecurity(context.Background(), senderID, "GET", vector.URL, vector.Headers, nil, options, security)
		if (err == nil) != expected {
			t.Fatal("unexpected federation result", expected, err)
		}
	}
	security.Policy.CryptoOnly = true
	if _, err := VerifyFederatedHTTPRequestWithSecurity(context.Background(), senderID, "GET", vector.URL, vector.Headers, nil, options, security); err == nil {
		t.Fatal("offline policy used as authentication")
	}
}

type offlineAuthTransport func(*http.Request) (*http.Response, error)

func (f offlineAuthTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOutboundPolicyDocumentResponsesAreBoundedAndNeverRedirected(t *testing.T) {
	client, err := httpsecurity.NewClient(10, true, false)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	status, body := 200, `{"id":"did:wba:example.com"}`
	client.Transport = offlineAuthTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://127.0.0.1/"}}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: -1, Request: r}, nil
	})
	if _, err := fetchJSONResponse(context.Background(), "https://example.com/did.json", nil, client); err != nil {
		t.Fatal(err)
	}
	status = 302
	before := calls
	if _, err := fetchJSONResponse(context.Background(), "https://example.com/did.json", nil, client); err == nil || calls != before+1 {
		t.Fatal("followed redirect", err, calls)
	}
	status = 200
	body = strings.Repeat(" ", httpsecurity.MaxDocumentBytes+1)
	if _, err := fetchJSONResponse(context.Background(), "https://example.com/did.json", nil, client); err == nil {
		t.Fatal("oversized document accepted")
	}
	body = `{"id":"one"}{"id":"two"}`
	if _, err := fetchJSONResponse(context.Background(), "https://example.com/did.json", nil, client); err == nil {
		t.Fatal("trailing data accepted")
	}
	for _, did := range []string{"did:wba:example.com%2fother:user", "did:wba:user%40example.com:alice", "did:wba:example.com:..", "did:wba:example.com:%2fetc"} {
		if _, err := buildWBAResolutionURL(did); err == nil {
			t.Fatalf("ambiguous DID accepted %s", did)
		}
	}
	// Numeric private destinations fail before an HTTP client can connect.
	if _, err := ResolveDidWBADocumentWithOptions(context.Background(), "did:wba:127.0.0.1", false, DidResolutionOptions{}); err == nil {
		t.Fatal("private resource accepted")
	}
}

func TestHTTPAuthSecurityTokenOriginChallengeAndConcurrentCache(t *testing.T) {
	helper := NewDIDWbaAuthHeader("unit-no-document", "unit-no-private-key", AuthModeHTTPSignatures)
	headers := map[string]string{"Authentication-Info": `access_token="public-unit-marker", token_type="Bearer"`}
	if helper.UpdateToken("https://EXAMPLE.com:8443/", headers) == "" {
		t.Fatal("trusted token rejected")
	}
	own, err := helper.GetAuthHeader("https://example.com:8443/path", false, "GET", nil, nil)
	if err != nil || own["Authorization"] != "Bearer public-unit-marker" {
		t.Fatal(own, err)
	}
	for _, other := range []string{"https://example.com/", "http://example.com:8443/"} {
		if _, err := helper.GetAuthHeader(other, false, "GET", nil, nil); err == nil {
			t.Fatal("cross-origin cache hit")
		}
	}
	if helper.UpdateToken("http://example.com:8443/", headers) != "" {
		t.Fatal("HTTP token adopted")
	}
	if helper.UpdateToken("https://example.com/", map[string]string{"Authentication-Info": `access_token="marker", token_type="Basic"`}) != "" {
		t.Fatal("wrong token type")
	}
	covered := normalizeCoveredComponents([]string{"@method"}, nil, nil)
	if !containsFolded(covered, "@target-uri") {
		t.Fatal("challenge downgraded target binding")
	}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 20; j++ {
				helper.UpdateToken("https://example.com:8443/", headers)
				helper.ClearToken("https://other.example/")
			}
		}()
	}
	workers.Wait()
}

type entropyFailureReader struct{}

func (entropyFailureReader) Read([]byte) (int, error) { return 0, fmt.Errorf("unit entropy failure") }

func TestHTTPAuthSecurityEntropyFailureCannotGenerateNonce(t *testing.T) {
	previous := rand.Reader
	rand.Reader = entropyFailureReader{}
	defer func() { rand.Reader = previous }()
	if _, err := randomBytes(16); err == nil {
		t.Fatal("entropy failure ignored")
	}
	corpus := securityCorpus(t)
	if _, err := GenerateHTTPSignatureHeaders(corpus.Document, "https://example.com/rpc", "GET", anp.PrivateKeyMaterial{}, nil, nil, HttpSignatureOptions{}); err == nil || !strings.Contains(err.Error(), "nonce generation") {
		t.Fatal("HTTP signer did not reject unavailable nonce generation", err)
	}
	if _, err := GenerateAuthHeader(corpus.Document, "example.com", anp.PrivateKeyMaterial{}, "1.1"); err == nil || !strings.Contains(err.Error(), "nonce generation") {
		t.Fatal("Legacy signer did not reject unavailable nonce generation", err)
	}
}

func TestHTTPAuthSecurityFrozenLegacyAuthorityAndReplay(t *testing.T) {
	data, err := os.ReadFile("../../testdata/authentication/authority_compatibility_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Now      int64          `json:"now"`
		Document map[string]any `json:"document"`
		Cases    []struct {
			URL       string            `json:"url"`
			Headers   map[string]string `json:"headers"`
			ReplayKey string            `json:"replay_key"`
		} `json:"cases"`
	}
	if err = json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, v := range corpus.Cases {
		metadata, err := VerifyHTTPMessageSignatureWithPolicy(corpus.Document, "GET", v.URL, v.Headers, nil, DefaultHTTPSignaturePolicy(), corpus.Now)
		if err != nil {
			t.Fatal(err)
		}
		scope, _ := AuthenticationOrigin(v.URL)
		replay, err := HTTPReplayContextForSignature(metadata, "GET", v.URL, v.Headers, scope, DefaultHTTPSignaturePolicy())
		if err != nil || replay.ReplayKey != v.ReplayKey {
			t.Fatalf("inconsistent replay %v %s", err, replay.ReplayKey)
		}
		if _, err = VerifyHTTPMessageSignatureWithPolicy(corpus.Document, "GET", v.URL+"tampered", v.Headers, nil, DefaultHTTPSignaturePolicy(), corpus.Now); err == nil {
			t.Fatal("target tamper accepted")
		}
	}
}

func TestHTTPAuthSecurityHeaderBudgetAndLegacyAmbiguity(t *testing.T) {
	data, err := os.ReadFile("../../testdata/authentication/legacy_compatibility_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var legacy struct {
		Header string `json:"header"`
	}
	if err = json.Unmarshal(data, &legacy); err != nil {
		t.Fatal(err)
	}
	if parsed, err := ExtractAuthHeaderParts(legacy.Header); err != nil || parsed.Nonce != "public-legacy-fixture" {
		t.Fatal(err)
	}
	for _, tail := range []string{`, nonce="duplicate"`, `, DID="duplicate"`, `, v="1.0"`, " garbage"} {
		if _, err = ExtractAuthHeaderParts(legacy.Header + tail); err == nil {
			t.Fatal("ambiguous Legacy accepted")
		}
	}
	corpus := securityCorpus(t)
	v := corpus.Cases[0]
	for _, value := range []string{"sig1=:" + strings.Repeat("A", 20000) + ":", v.Headers["Signature"] + "\r\nInjected: value"} {
		headers := cloneHeaders(v.Headers)
		headers["Signature"] = value
		if _, err := VerifyHTTPMessageSignatureWithPolicy(corpus.Document, "GET", v.URL, headers, nil, DefaultHTTPSignaturePolicy(), corpus.Now); err == nil {
			t.Fatal("excessive/invalid header accepted")
		}
	}
}

func TestHTTPAuthSecurityCanonicalIPv6Origins(t *testing.T) {
	origin, err := AuthenticationOrigin("https://[2001:4860:0000:0000:0000:0000:0000:8888]/")
	if err != nil || origin != "https://[2001:4860::8888]:443" {
		t.Fatal(origin, err)
	}
	for _, value := range []string{"https://api.example:0/", "https://[::ffff:8.8.8.8]/"} {
		if _, err := AuthenticationOrigin(value); err == nil {
			t.Fatal("invalid origin accepted")
		}
	}
}
