package wns

import "github.com/agent-network-protocol/anp/golang/authentication"

const ANPHandleServiceType = "ANPHandleService"

// HandleStatus identifies the state of a resolved handle.
type HandleStatus string

const (
	HandleStatusActive    HandleStatus = "active"
	HandleStatusSuspended HandleStatus = "suspended"
	HandleStatusRevoked   HandleStatus = "revoked"
)

// HandleResolutionDocument is the response body of a WNS handle record.
type HandleResolutionDocument struct {
	Handle  string       `json:"handle"`
	DID     string       `json:"did"`
	Status  HandleStatus `json:"status"`
	Updated string       `json:"updated,omitempty"`
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
