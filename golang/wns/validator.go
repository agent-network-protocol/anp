package wns

import (
	"fmt"
	"regexp"
	"strings"
)

var domainLabelRegexp = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidateLocalPart validates the handle local-part.
func ValidateLocalPart(localPart string) bool {
	normalized := strings.ToLower(localPart)
	if normalized == "" || len(normalized) > 63 {
		return false
	}
	if strings.HasPrefix(normalized, "-") || strings.HasSuffix(normalized, "-") || strings.Contains(normalized, "--") {
		return false
	}
	for _, value := range normalized {
		if (value < 'a' || value > 'z') && (value < '0' || value > '9') && value != '-' {
			return false
		}
	}
	return true
}

// ValidateHandle validates a handle and returns its normalized local-part and domain.
func ValidateHandle(handle string) (string, string, error) {
	normalized := strings.ToLower(strings.TrimSpace(handle))
	if normalized == "" {
		return "", "", fmt.Errorf("handle must not be empty")
	}
	dotIndex := strings.IndexByte(normalized, '.')
	if dotIndex < 0 {
		return "", "", fmt.Errorf("handle must contain at least one dot: '%s'", handle)
	}
	localPart := normalized[:dotIndex]
	domain := normalized[dotIndex+1:]
	if localPart == "" {
		return "", "", fmt.Errorf("handle local-part is empty: '%s'", handle)
	}
	if domain == "" {
		return "", "", fmt.Errorf("handle domain is empty: '%s'", handle)
	}
	if !ValidateLocalPart(localPart) {
		return "", "", fmt.Errorf("invalid local-part '%s': must be 1-63 chars of a-z, 0-9, hyphen; must start/end with alnum; no consecutive hyphens", localPart)
	}
	if !isValidDomain(domain) {
		return "", "", fmt.Errorf("invalid domain '%s'", domain)
	}
	return localPart, domain, nil
}

// NormalizeHandle validates and normalizes a handle.
func NormalizeHandle(handle string) (string, error) {
	localPart, domain, err := ValidateHandle(handle)
	if err != nil {
		return "", err
	}
	return localPart + "." + domain, nil
}

// ParseWBAURI parses a wba:// URI.
func ParseWBAURI(uri string) (ParsedWBAURI, error) {
	if !strings.HasPrefix(uri, "wba://") {
		return ParsedWBAURI{}, fmt.Errorf("URI must start with 'wba://': '%s'", uri)
	}
	handle := strings.TrimPrefix(uri, "wba://")
	if handle == "" {
		return ParsedWBAURI{}, fmt.Errorf("URI contains no handle after 'wba://': '%s'", uri)
	}
	localPart, domain, err := ValidateHandle(handle)
	if err != nil {
		return ParsedWBAURI{}, fmt.Errorf("invalid handle in URI '%s': %v", uri, err)
	}
	return ParsedWBAURI{LocalPart: localPart, Domain: domain, Handle: localPart + "." + domain, OriginalURI: uri}, nil
}

// BuildResolutionURL builds the HTTPS resolution URL for a handle.
func BuildResolutionURL(localPart string, domain string) string {
	return "https://" + domain + "/.well-known/handle/" + localPart
}

// BuildWBAURI builds a wba:// URI.
func BuildWBAURI(localPart string, domain string) string {
	return "wba://" + localPart + "." + domain
}

func isValidDomain(domain string) bool {
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !domainLabelRegexp.MatchString(label) {
			return false
		}
	}
	return true
}
