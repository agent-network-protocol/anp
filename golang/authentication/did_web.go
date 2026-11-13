package authentication

import (
	"context"
	"fmt"
	"github.com/agent-network-protocol/anp/golang/internal/httpsecurity"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
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

func isPublicWebAddress(ip net.IP) bool { return httpsecurity.IsPublicAddress(ip) }

func dialPublicWeb(ctx context.Context, network, address string) (net.Conn, error) {
	return httpsecurity.DialPublic(ctx, network, address)
}

func fetchDIDWebDocument(ctx context.Context, did string, options DidResolutionOptions) (map[string]any, error) {
	resource, err := BuildDIDWebResolutionURL(did)
	if err != nil {
		return nil, err
	}
	document, err := fetchJSONDocument(ctx, resource, options)
	if err != nil {
		return nil, err
	}
	if document["id"] != did {
		return nil, fmt.Errorf("DID document ID mismatch")
	}
	return document, nil
}
