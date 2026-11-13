// Package httpsecurity owns public ANP transport boundaries, shared by resolvers.
package httpsecurity

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const MaxDocumentBytes = 1024 * 1024

// IsPublicAddress excludes local, special-use, multicast and transition ranges.
func IsPublicAddress(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		a, b, c := v4[0], v4[1], v4[2]
		return !(a == 0 || a == 10 || a == 127 || a >= 224 || a == 100 && b >= 64 && b <= 127 || a == 169 && b == 254 || a == 172 && b >= 16 && b <= 31 || a == 192 && (b == 168 || b == 0 && (c == 0 || c == 2)) || a == 198 && (b == 18 || b == 19 || b == 51 && c == 100) || a == 203 && b == 0 && c == 113)
	}
	v6 := ip.To16()
	if v6 == nil {
		return false
	}
	first, second := uint16(v6[0])<<8|uint16(v6[1]), uint16(v6[2])<<8|uint16(v6[3])
	return first&0xe000 == 0x2000 && !(first == 0x2001 && (second < 0x200 || second == 0xdb8)) && first != 0x2002 && first&0xfff0 != 0x3ff0
}

// ValidateURL rejects ambiguous destinations before request/credential creation.
// trustedOverride is host configuration only, never peer-provided input.
func ValidateURL(raw string, trustedOverride bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || strings.Contains(raw, "#") || strings.ContainsAny(raw, "\\\r\n\t ") || parsed.Scheme != "https" && (!trustedOverride || parsed.Scheme != "http") {
		return fmt.Errorf("invalid public ANP URL")
	}
	host := strings.ToLower(parsed.Hostname())
	if strings.Contains(host, "%") {
		return fmt.Errorf("invalid ANP host")
	}
	if trustedOverride {
		return nil
	}
	if strings.TrimSuffix(host, ".") == "localhost" || strings.HasSuffix(strings.TrimSuffix(host, "."), ".localhost") {
		return fmt.Errorf("non-public ANP destination")
	}
	if ip := net.ParseIP(host); ip != nil && !IsPublicAddress(ip) {
		return fmt.Errorf("non-public ANP destination")
	}
	return nil
}

type lookupIPs func(context.Context, string) ([]net.IPAddr, error)
type dialIP func(context.Context, string, string) (net.Conn, error)

// Resolve once, check every answer, then dial only those exact IPs. Tests inject
// lookup/dial functions here; the production path never performs a second lookup.
func dialChecked(ctx context.Context, network, address string, lookup lookupIPs, dial dialIP) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("ANP DNS returned no addresses")
	}
	for _, ip := range ips {
		if !IsPublicAddress(ip.IP) || ip.Zone != "" {
			return nil, fmt.Errorf("ANP destination resolved to a non-public address")
		}
	}
	var last error
	for _, ip := range ips {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		conn, err := dial(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	return nil, last
}

func DialPublic(ctx context.Context, network, address string) (net.Conn, error) {
	return dialChecked(ctx, network, address, net.DefaultResolver.LookupIPAddr, (&net.Dialer{}).DialContext)
}

// NewClient disables ambient proxies/redirects. TLS/private-network overrides
// require an explicitly configured trusted endpoint, not an incoming flag.
func NewClient(seconds float64, verifySSL, trustedOverride bool) (*http.Client, error) {
	if seconds == 0 {
		seconds = 10
	}
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 || seconds > float64(math.MaxInt64)/float64(time.Second) {
		return nil, fmt.Errorf("invalid ANP timeout")
	}
	if !trustedOverride && !verifySSL {
		return nil, fmt.Errorf("public ANP requests require TLS verification")
	}
	transport := publicTransport
	if trustedOverride {
		transport = trustedTransport
		if !verifySSL {
			transport = insecureTrustedTransport
		}
	}
	return &http.Client{Transport: transport, Timeout: time.Duration(seconds * float64(time.Second)), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

// Shared transports reuse checked connection pools; every request holds one
// process-wide permit until body EOF/close. Overload never grows a waiting queue.
var outboundRequests = make(chan struct{}, 32)
var publicTransport = &budgetTransport{base: makeTransport(true, false)}
var trustedTransport = &budgetTransport{base: makeTransport(true, true)}
var insecureTrustedTransport = &budgetTransport{base: makeTransport(false, true)}

func makeTransport(verifySSL, trusted bool) *http.Transport {
	transport := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 10 * time.Second, IdleConnTimeout: 30 * time.Second, MaxResponseHeaderBytes: 65536, MaxIdleConns: 32, MaxConnsPerHost: 32, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	if trusted {
		transport.DialContext = (&net.Dialer{}).DialContext
		transport.TLSClientConfig.InsecureSkipVerify = !verifySSL
	} else {
		transport.DialContext = DialPublic
	}
	return transport
}

type budgetTransport struct{ base http.RoundTripper }

func (transport *budgetTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := request.Context().Err(); err != nil {
		return nil, err
	}
	select {
	case outboundRequests <- struct{}{}:
	default:
		return nil, fmt.Errorf("ANP outbound concurrency budget exhausted")
	}
	release := func() { <-outboundRequests }
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		release()
		return nil, err
	}
	if response.Body == nil || response.Body == http.NoBody {
		release()
	} else {
		response.Body = &budgetBody{ReadCloser: response.Body, release: release}
	}
	return response, nil
}
func (transport *budgetTransport) CloseIdleConnections() {
	if closer, ok := transport.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

type budgetBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (body *budgetBody) Read(data []byte) (int, error) {
	count, err := body.ReadCloser.Read(data)
	if err != nil {
		body.Close()
	}
	return count, err
}
func (body *budgetBody) Close() error {
	var err error
	body.once.Do(func() { err = body.ReadCloser.Close(); body.release() })
	return err
}

// ReadBody bounds decoded bytes as well as the untrusted Content-Length.
func ReadBody(response *http.Response, limit int64) ([]byte, error) {
	if limit <= 0 || limit >= math.MaxInt64 || response.ContentLength > limit {
		return nil, fmt.Errorf("ANP response exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("ANP response exceeds size limit")
	}
	return data, nil
}
