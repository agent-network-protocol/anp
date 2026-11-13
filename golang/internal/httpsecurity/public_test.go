package httpsecurity

import (
	"context"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestOutboundPolicyURLTLSProxyRedirectAndLimits(t *testing.T) {
	for _, value := range []string{"http://example.com/", "https://localhost/", "https://127.0.0.1/", "https://169.254.169.254/", "https://[::1]/", "https://[::ffff:127.0.0.1]/", "https://user@example.com/", "https://example.com/#x"} {
		if err := ValidateURL(value, false); err == nil {
			t.Fatalf("accepted %s", value)
		}
	}
	if err := ValidateURL("http://127.0.0.1/fixture", true); err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient(10, false, false); err == nil {
		t.Fatal("disabled public TLS")
	}
	for _, timeout := range []float64{math.NaN(), math.Inf(1), -1} {
		if _, err := NewClient(timeout, true, false); err == nil {
			t.Fatal("invalid timeout accepted")
		}
	}
	client, err := NewClient(10, true, false)
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*budgetTransport).base.(*http.Transport)
	if transport.Proxy != nil || transport.TLSClientConfig.InsecureSkipVerify || transport.DialContext == nil {
		t.Fatal("public client policy missing")
	}
	if err := client.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatal("redirects allowed")
	}
	response := &http.Response{Body: io.NopCloser(strings.NewReader("12345")), ContentLength: -1}
	if _, err := ReadBody(response, 4); err == nil {
		t.Fatal("unbounded decoded body")
	}
}

func TestOutboundPolicyPinsCheckedDNSAndChecksEveryAnswer(t *testing.T) {
	answers := []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("127.0.0.1")}}
	lookups, dials := 0, 0
	lookup := func(context.Context, string) ([]net.IPAddr, error) { lookups++; return answers, nil }
	dial := func(_ context.Context, _ string, address string) (net.Conn, error) {
		dials++
		if address != "8.8.8.8:443" {
			t.Fatalf("dial not pinned to checked IP: %s", address)
		}
		first, second := net.Pipe()
		second.Close()
		return first, nil
	}
	if _, err := dialChecked(context.Background(), "tcp", "public.example:443", lookup, dial); err == nil || dials != 0 {
		t.Fatal("mixed DNS admitted")
	}
	answers = answers[:1]
	conn, err := dialChecked(context.Background(), "tcp", "public.example:443", lookup, dial)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if dials != 1 || lookups != 2 {
		t.Fatal("unexpected re-resolution", dials, lookups)
	}
	answers = []net.IPAddr{{IP: net.ParseIP("10.0.0.1")}}
	if _, err := dialChecked(context.Background(), "tcp", "public.example:443", lookup, dial); err == nil || dials != 1 {
		t.Fatal("rebound DNS admitted")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (callback roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return callback(request)
}
func TestOutboundPolicySharedBudgetRetainsThroughBodyAndRecovers(t *testing.T) {
	transport := &budgetTransport{base: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{Body: io.NopCloser(strings.NewReader("unit"))}, nil
	})}
	request, _ := http.NewRequest("GET", "https://public.example", nil)
	held := make([]*http.Response, 0, 32)
	defer func() {
		for _, response := range held {
			response.Body.Close()
		}
	}()
	for index := 0; index < 32; index++ {
		response, err := transport.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, response)
	}
	if _, err := transport.RoundTrip(request); err == nil {
		t.Fatal("unbounded outbound requests")
	}
	held[0].Body.Close()
	held[0].Body.Close()
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	response.Body.Close() // EOF/close must release exactly once.
	failed := &budgetTransport{base: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, io.ErrUnexpectedEOF })}
	if _, err = failed.RoundTrip(request); err == nil {
		t.Fatal("transport failure lost")
	}
	if len(outboundRequests) != 31 {
		t.Fatalf("permit leak or early release: %d", len(outboundRequests))
	}
	first, _ := NewClient(10, true, false)
	second, _ := NewClient(5, true, false)
	if first.Transport != second.Transport {
		t.Fatal("request-local connection pools")
	}
}
