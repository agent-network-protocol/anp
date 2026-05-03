package groupe2ee

const (
	Profile                   = "anp.group.e2ee.v1"
	SecurityProfile           = "group-e2ee"
	TransportSecurityProfile  = "transport-protected"
	ContractArtifactMode      = "contract-test"
	MTISuite                  = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
	MethodLeaveRequest        = "group.e2ee.leave_request"
	MethodLeaveRequestProcess = "group.e2ee.leave_request.process"
)

type TargetRef struct {
	Kind string `json:"kind"`
	DID  string `json:"did"`
}

type GroupStateRef struct {
	GroupDID          string `json:"group_did"`
	GroupStateVersion string `json:"group_state_version"`
	PolicyHash        string `json:"policy_hash,omitempty"`
}

type EnvelopeMeta struct {
	ANPVersion      string     `json:"anp_version"`
	Profile         string     `json:"profile"`
	SecurityProfile string     `json:"security_profile"`
	SenderDID       string     `json:"sender_did,omitempty"`
	Target          *TargetRef `json:"target,omitempty"`
	OperationID     string     `json:"operation_id,omitempty"`
	MessageID       string     `json:"message_id,omitempty"`
	ContentType     string     `json:"content_type,omitempty"`
	CreatedAt       string     `json:"created_at,omitempty"`
}

type GroupKeyPackage struct {
	KeyPackageID      string         `json:"key_package_id"`
	OwnerDID          string         `json:"owner_did"`
	Suite             string         `json:"suite"`
	MLSKeyPackageB64U string         `json:"mls_key_package_b64u"`
	DIDWBABinding     map[string]any `json:"did_wba_binding"`
	ExpiresAt         string         `json:"expires_at,omitempty"`
	NonCryptographic  bool           `json:"non_cryptographic,omitempty"`
	ArtifactMode      string         `json:"artifact_mode,omitempty"`
}

type GroupCipherObject struct {
	CryptoGroupIDB64U  string        `json:"crypto_group_id_b64u"`
	Epoch              string        `json:"epoch"`
	PrivateMessageB64U string        `json:"private_message_b64u"`
	GroupStateRef      GroupStateRef `json:"group_state_ref"`
	EpochAuthenticator string        `json:"epoch_authenticator,omitempty"`
	NonCryptographic   bool          `json:"non_cryptographic,omitempty"`
	ArtifactMode       string        `json:"artifact_mode,omitempty"`
}

type GroupLeaveRequestObject struct {
	LeaveRequestID   string        `json:"leave_request_id"`
	GroupDID         string        `json:"group_did"`
	RequesterDID     string        `json:"requester_did"`
	GroupStateRef    GroupStateRef `json:"group_state_ref"`
	ReasonText       string        `json:"reason_text,omitempty"`
	RequestedAt      string        `json:"requested_at,omitempty"`
	NonCryptographic bool          `json:"non_cryptographic,omitempty"`
	ArtifactMode     string        `json:"artifact_mode,omitempty"`
}

type GroupLeaveRequestProcessObject struct {
	LeaveRequestID     string        `json:"leave_request_id"`
	GroupDID           string        `json:"group_did"`
	RequesterDID       string        `json:"requester_did"`
	ProcessorDID       string        `json:"processor_did"`
	GroupStateRef      GroupStateRef `json:"group_state_ref"`
	CryptoGroupIDB64U  string        `json:"crypto_group_id_b64u"`
	Epoch              string        `json:"epoch"`
	CommitB64U         string        `json:"commit_b64u"`
	EpochAuthenticator string        `json:"epoch_authenticator,omitempty"`
	ReasonText         string        `json:"reason_text,omitempty"`
	NonCryptographic   bool          `json:"non_cryptographic,omitempty"`
	ArtifactMode       string        `json:"artifact_mode,omitempty"`
}

type ApplicationPlaintext struct {
	ApplicationContentType string         `json:"application_content_type"`
	ThreadID               string         `json:"thread_id,omitempty"`
	ReplyToMessageID       string         `json:"reply_to_message_id,omitempty"`
	Annotations            map[string]any `json:"annotations,omitempty"`
	Text                   string         `json:"text,omitempty"`
	Payload                map[string]any `json:"payload,omitempty"`
	PayloadB64U            string         `json:"payload_b64u,omitempty"`
}

type Request struct {
	APIVersion          string         `json:"api_version"`
	RequestID           string         `json:"request_id"`
	AgentDID            string         `json:"agent_did,omitempty"`
	DeviceID            string         `json:"device_id,omitempty"`
	ContractTestEnabled bool           `json:"contract_test_enabled,omitempty"`
	Params              map[string]any `json:"params"`
}

type Response struct {
	OK         bool           `json:"ok"`
	APIVersion string         `json:"api_version"`
	RequestID  string         `json:"request_id"`
	Result     map[string]any `json:"result,omitempty"`
	Error      *ErrorObject   `json:"error,omitempty"`
}

type ErrorObject struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
