package authentication

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var webEncodedSegment = regexp.MustCompile(`^(?:[A-Za-z0-9._~-]|%[0-9A-Fa-f]{2})+$`)
var webHostLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
var webPort = regexp.MustCompile(`^[0-9]+$`)
var webHostLetter = regexp.MustCompile(`[A-Za-z]`)

func decodeWebSegment(raw string) (string, error) {
	if !webEncodedSegment.MatchString(raw) {
		return "", fmt.Errorf("invalid DID Web encoded component")
	}
	result, err := url.PathUnescape(raw)
	if err != nil || !utf8.ValidString(result) {
		return "", fmt.Errorf("invalid DID Web encoding")
	}
	return result, nil
}

// BuildDIDWebResolutionURL constructs an unambiguous HTTPS resource URL.
func BuildDIDWebResolutionURL(did string) (string, error) {
	parts := strings.Split(did, ":")
	if len(parts) < 3 || parts[0] != "did" || parts[1] != "web" {
		return "", fmt.Errorf("invalid DID Web")
	}
	authority, err := decodeWebSegment(parts[2])
	if err != nil {
		return "", err
	}
	hostPort := strings.Split(authority, ":")
	host := hostPort[0]
	labels := strings.Split(host, ".")
	if len(hostPort) > 2 || len(host) > 253 || len(labels) < 2 || !webHostLetter.MatchString(labels[len(labels)-1]) {
		return "", fmt.Errorf("DID Web requires a DNS hostname")
	}
	for _, label := range labels {
		if !webHostLabel.MatchString(label) {
			return "", fmt.Errorf("invalid DID Web hostname")
		}
	}
	authority = strings.ToLower(host)
	if len(hostPort) == 2 {
		port, err := strconv.ParseUint(hostPort[1], 10, 16)
		if err != nil || port == 0 || !webPort.MatchString(hostPort[1]) {
			return "", fmt.Errorf("invalid DID Web port")
		}
		authority += ":" + strconv.FormatUint(port, 10)
	}
	var segments []string
	for _, raw := range parts[3:] {
		segment, err := decodeWebSegment(raw)
		if err != nil {
			return "", err
		}
		if segment == "." || segment == ".." || strings.ContainsAny(segment, "/\\?#%") {
			return "", fmt.Errorf("unsafe DID Web path component")
		}
		for _, c := range segment {
			if c < 32 || c == 127 {
				return "", fmt.Errorf("unsafe DID Web path component")
			}
		}
		segments = append(segments, strings.ReplaceAll(url.QueryEscape(segment), "+", "%20"))
	}
	path := ".well-known/did.json"
	if len(segments) > 0 {
		path = strings.Join(segments, "/") + "/did.json"
	}
	return "https://" + authority + "/" + path, nil
}

func isPublicWebAddress(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		a, b, c := v4[0], v4[1], v4[2]
		return !(a == 0 || a == 10 || a == 127 || a >= 224 ||
			(a == 100 && b >= 64 && b <= 127) || (a == 169 && b == 254) ||
			(a == 172 && b >= 16 && b <= 31) || (a == 192 && (b == 168 || (b == 0 && (c == 0 || c == 2)))) ||
			(a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100))) || (a == 203 && b == 0 && c == 113))
	}
	v6 := ip.To16()
	if v6 == nil {
		return false
	}
	first, second := uint16(v6[0])<<8|uint16(v6[1]), uint16(v6[2])<<8|uint16(v6[3])
	return first&0xe000 == 0x2000 && !(first == 0x2001 && (second < 0x200 || second == 0xdb8)) &&
		first != 0x2002 && first&0xfff0 != 0x3ff0
}

// Dial using the checked DNS result so the connection cannot re-resolve it.
func dialPublicWeb(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("DID Web DNS returned no addresses")
	}
	for _, ip := range addresses {
		if !isPublicWebAddress(ip.IP) {
			return nil, fmt.Errorf("DID Web resolved to a non-public address")
		}
	}
	var lastErr error
	for _, ip := range addresses {
		connection, err := (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return connection, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func fetchDIDWebDocument(ctx context.Context, did string, options DidResolutionOptions) (map[string]any, error) {
	const maxBytes = 1024 * 1024
	resource, err := BuildDIDWebResolutionURL(did)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	if options.BaseURLOverride != "" {
		// The override is trusted host/test configuration, never peer document data.
		override, err := url.Parse(options.BaseURLOverride)
		if err != nil || (override.Scheme != "http" && override.Scheme != "https") || override.Hostname() == "" ||
			override.User != nil || override.RawQuery != "" || override.Fragment != "" {
			return nil, fmt.Errorf("invalid trusted resolution override")
		}
		parsed, _ := url.Parse(resource)
		resource = strings.TrimRight(options.BaseURLOverride, "/") + parsed.EscapedPath()
		if options.VerifySSL != nil && !*options.VerifySSL {
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
	} else {
		if options.VerifySSL != nil && !*options.VerifySSL {
			return nil, fmt.Errorf("DID Web requires TLS verification")
		}
		transport.DialContext = dialPublicWeb
	}
	seconds := options.TimeoutSeconds
	if seconds == 0 {
		seconds = 10
	}
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 || seconds > float64(math.MaxInt64)/float64(time.Second) {
		return nil, fmt.Errorf("invalid DID Web timeout")
	}
	client := &http.Client{Transport: transport, Timeout: time.Duration(seconds * float64(time.Second)),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, resource, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	for key, value := range options.Headers {
		request.Header.Set(key, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > maxBytes {
		return nil, fmt.Errorf("DID Web response rejected")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("DID document exceeds resolution size limit")
	}
	var document map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("trailing DID document data")
	}
	if document["id"] != did {
		return nil, fmt.Errorf("DID document ID mismatch")
	}
	return document, nil
}
