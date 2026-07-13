package wns

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/agent-network-protocol/anp/golang/authentication"
)

const ANPHandleServiceType = "ANPHandleService"

// BindingGeneration is a canonical, arbitrary-precision positive integer.
type BindingGeneration string

// ParseBindingGeneration validates and canonicalizes a binding generation.
func ParseBindingGeneration(value string) (BindingGeneration, error) {
	if value == "" || value == "0" || value[0] == '0' {
		return "", fmt.Errorf("binding_generation must be a canonical positive decimal string")
	}
	for _, char := range []byte(value) {
		if char < '0' || char > '9' {
			return "", fmt.Errorf("binding_generation must be a canonical positive decimal string")
		}
	}
	return BindingGeneration(value), nil
}

// CompareBindingGenerations compares two validated arbitrary-precision values.
func CompareBindingGenerations(current, previous BindingGeneration) int {
	if len(current) < len(previous) {
		return -1
	}
	if len(current) > len(previous) {
		return 1
	}
	return bytes.Compare([]byte(current), []byte(previous))
}

// IsNewerThan reports whether generation is strictly newer than previous.
func (generation BindingGeneration) IsNewerThan(previous BindingGeneration) bool {
	return CompareBindingGenerations(generation, previous) > 0
}

func (generation *BindingGeneration) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("binding_generation must be a JSON string: %w", err)
	}
	parsed, err := ParseBindingGeneration(value)
	if err != nil {
		return err
	}
	*generation = parsed
	return nil
}

// HandleStatus identifies the state of a resolved handle.
type HandleStatus string

const (
	HandleStatusActive    HandleStatus = "active"
	HandleStatusSuspended HandleStatus = "suspended"
	HandleStatusRevoked   HandleStatus = "revoked"
)

// SubjectType identifies the recommended DID Subject Profile subject type.
type SubjectType string

const (
	SubjectTypePerson       SubjectType = "person"
	SubjectTypeAgent        SubjectType = "agent"
	SubjectTypeGroup        SubjectType = "group"
	SubjectTypeOrganization SubjectType = "organization"
	SubjectTypeService      SubjectType = "service"
	SubjectTypeApplication  SubjectType = "application"
	SubjectTypeUnknown      SubjectType = "unknown"
)

// DIDSubjectProfile is public presentational metadata for a DID subject.
type DIDSubjectProfile struct {
	Type            string         `json:"type,omitempty"`
	SubjectDID      string         `json:"subject_did"`
	SubjectType     SubjectType    `json:"subject_type,omitempty"`
	Handle          string         `json:"handle,omitempty"`
	DisplayName     string         `json:"display_name,omitempty"`
	Description     string         `json:"description,omitempty"`
	AvatarURI       string         `json:"avatar_uri,omitempty"`
	ProfileURI      string         `json:"profile_uri,omitempty"`
	Discoverability string         `json:"discoverability,omitempty"`
	Labels          map[string]any `json:"labels,omitempty"`
	Updated         string         `json:"updated,omitempty"`
	VersionID       string         `json:"versionId,omitempty"`
	TTL             *int           `json:"ttl,omitempty"`
	Proof           map[string]any `json:"proof,omitempty"`
}

// HandleResolutionDocument is the response body of a WNS handle record.
type HandleResolutionDocument struct {
	Handle            string             `json:"handle"`
	DID               string             `json:"did"`
	Status            HandleStatus       `json:"status"`
	BindingGeneration BindingGeneration  `json:"binding_generation"`
	Updated           string             `json:"updated,omitempty"`
	VersionID         string             `json:"versionId,omitempty"`
	TTL               *int               `json:"ttl,omitempty"`
	Profile           *DIDSubjectProfile `json:"profile,omitempty"`
}

// HandleServiceEntry is the DID service entry used for reverse handle binding.
type HandleServiceEntry struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// ParsedWBAURI is the parsed form of a wba:// handle URI.
type ParsedWBAURI struct {
	LocalPart   string `json:"local_part"`
	Domain      string `json:"domain"`
	Handle      string `json:"handle"`
	OriginalURI string `json:"original_uri"`
}

// ResolveHandleOptions configures handle resolution.
type ResolveHandleOptions struct {
	TimeoutSeconds  float64
	VerifySSL       *bool
	BaseURLOverride string
}

// BindingVerificationOptions configures handle binding verification.
type BindingVerificationOptions struct {
	DidDocument          map[string]any
	ResolutionOptions    ResolveHandleOptions
	DidResolutionOptions authentication.DidResolutionOptions
}

// BindingVerificationResult reports forward and reverse verification status.
type BindingVerificationResult struct {
	IsValid         bool   `json:"is_valid"`
	Handle          string `json:"handle"`
	DID             string `json:"did"`
	ForwardVerified bool   `json:"forward_verified"`
	ReverseVerified bool   `json:"reverse_verified"`
	ErrorMessage    string `json:"error_message,omitempty"`
}
