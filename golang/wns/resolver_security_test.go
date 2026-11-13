package wns

import (
	"context"
	"github.com/agent-network-protocol/anp/golang/internal/httpsecurity"
	"io"
	"net/http"
	"strings"
	"testing"
)

type offlineWNSTransport func(*http.Request) (*http.Response, error)

func (f offlineWNSTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOutboundPolicyWNSResponseSemanticsWithoutNetwork(t *testing.T) {
	client, err := httpsecurity.NewClient(10, true, false)
	if err != nil {
		t.Fatal(err)
	}
	calls, status := 0, 200
	body := `{"handle":"alice.example.com","did":"did:wba:example.com:user:alice","status":"active","binding_generation":"1"}`
	client.Transport = offlineWNSTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://127.0.0.1/"}}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: -1, Request: r}, nil
	})
	if _, err := resolveHandleResponse(context.Background(), "https://example.com/.well-known/handle/alice", "alice.example.com", client); err != nil {
		t.Fatal(err)
	}
	for _, code := range []int{301, 404, 410} {
		status = code
		before := calls
		if _, err := resolveHandleResponse(context.Background(), "https://example.com/.well-known/handle/alice", "alice.example.com", client); err == nil || calls != before+1 {
			t.Fatal("status/redirect behavior changed", code, err, calls)
		}
	}
	status = 200
	body = strings.Repeat(" ", httpsecurity.MaxDocumentBytes+1)
	if _, err := resolveHandleResponse(context.Background(), "https://example.com/.well-known/handle/alice", "alice.example.com", client); err == nil {
		t.Fatal("unbounded WNS document")
	}
}
