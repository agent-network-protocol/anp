package directe2ee

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

const (
	DirectE2EEProfileV2               = "anp.direct.e2ee.v2"
	DirectE2EESecurityProfile         = "direct-e2ee"
	TransportProtectedSecurityProfile = "transport-protected"
	ContentTypeDirectInitV2           = "application/anp-direct-init+json"
	ContentTypeDirectCipherV2         = "application/anp-direct-cipher+json"
	MTIDirectE2EESuiteV2              = "ANP-DIRECT-E2EE-X3DH-25519-CHACHA20POLY1305-SHA256-V1"
)

type V2SignedPrekey struct {
	KeyID         string `json:"key_id"`
	PublicKeyB64U string `json:"public_key_b64u"`
	ExpiresAt     string `json:"expires_at"`
}

func (value V2SignedPrekey) Validate() error {
	if value.KeyID == "" {
		return invalidV2("signed_prekey.key_id must be non-empty")
	}
	if err := validateX25519B64U(value.PublicKeyB64U, "signed_prekey.public_key_b64u"); err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339, value.ExpiresAt); err != nil {
		return invalidV2("signed_prekey.expires_at must be RFC3339")
	}
	return nil
}

type V2OneTimePrekey struct {
	KeyID         string `json:"key_id"`
	PublicKeyB64U string `json:"public_key_b64u"`
}

func (value V2OneTimePrekey) Validate() error {
	if value.KeyID == "" {
		return invalidV2("one_time_prekey.key_id must be non-empty")
	}
	return validateX25519B64U(value.PublicKeyB64U, "one_time_prekey.public_key_b64u")
}

type V2PrekeyBundle struct {
	BundleID             string         `json:"bundle_id"`
	OwnerDID             string         `json:"owner_did"`
	OwnerDeviceID        string         `json:"owner_device_id"`
	Suite                string         `json:"suite"`
	StaticKeyAgreementID string         `json:"static_key_agreement_id"`
	SignedPrekey         V2SignedPrekey `json:"signed_prekey"`
	Proof                map[string]any `json:"proof"`
}

func (value V2PrekeyBundle) ValidateStructure() error {
	if empty(value.BundleID, value.OwnerDID, value.OwnerDeviceID, value.StaticKeyAgreementID) {
		return invalidV2("bundle identifiers must be non-empty")
	}
	if value.Suite != MTIDirectE2EESuiteV2 {
		return invalidV2("unsupported suite")
	}
	if err := value.SignedPrekey.Validate(); err != nil {
		return err
	}
	for _, field := range []string{"type", "cryptosuite", "verificationMethod", "proofPurpose", "created", "proofValue"} {
		if stringValue(value.Proof[field]) == "" {
			return invalidV2("missing bundle proof field: " + field)
		}
	}
	if stringValue(value.Proof["type"]) != "DataIntegrityProof" || stringValue(value.Proof["cryptosuite"]) != "eddsa-jcs-2022" || stringValue(value.Proof["proofPurpose"]) != "assertionMethod" {
		return invalidV2("invalid Appendix-B Object Proof profile")
	}
	return nil
}

type V2Target struct {
	Kind string `json:"kind"`
	DID  string `json:"did"`
}

type V2KeyServiceMetadata struct {
	ANPVersion      string   `json:"anp_version,omitempty"`
	Profile         string   `json:"profile"`
	SecurityProfile string   `json:"security_profile"`
	SenderDID       string   `json:"sender_did"`
	SenderDeviceID  string   `json:"sender_device_id"`
	Target          V2Target `json:"target"`
	OperationID     string   `json:"operation_id"`
	CreatedAt       string   `json:"created_at,omitempty"`
}

func (value V2KeyServiceMetadata) Validate() error {
	if value.Profile != DirectE2EEProfileV2 || value.SecurityProfile != TransportProtectedSecurityProfile {
		return invalidV2("invalid key-service profile binding")
	}
	if value.Target.Kind != "service" {
		return invalidV2("key-service target.kind must be service")
	}
	if empty(value.SenderDID, value.SenderDeviceID, value.Target.DID, value.OperationID) {
		return invalidV2("key-service selectors must be non-empty")
	}
	if value.CreatedAt != "" {
		if _, err := time.Parse(time.RFC3339, value.CreatedAt); err != nil {
			return invalidV2("meta.created_at must be RFC3339")
		}
	}
	return nil
}

type V2DirectMetadata struct {
	ANPVersion        string   `json:"anp_version,omitempty"`
	Profile           string   `json:"profile"`
	SecurityProfile   string   `json:"security_profile"`
	SenderDID         string   `json:"sender_did"`
	SenderDeviceID    string   `json:"sender_device_id"`
	Target            V2Target `json:"target"`
	RecipientDeviceID string   `json:"recipient_device_id"`
	OperationID       string   `json:"operation_id"`
	MessageID         string   `json:"message_id"`
	ContentType       string   `json:"content_type"`
	CreatedAt         string   `json:"created_at,omitempty"`
}

func (value V2DirectMetadata) Validate() error {
	if value.Profile != DirectE2EEProfileV2 || value.SecurityProfile != DirectE2EESecurityProfile {
		return invalidV2("invalid direct.send profile binding")
	}
	if value.Target.Kind != "agent" {
		return invalidV2("direct.send target.kind must be agent")
	}
	if value.ContentType != ContentTypeDirectInitV2 && value.ContentType != ContentTypeDirectCipherV2 {
		return invalidV2("content_type is not a P5 v2 MTI wire object")
	}
	if empty(value.SenderDID, value.SenderDeviceID, value.Target.DID, value.RecipientDeviceID, value.OperationID, value.MessageID) {
		return invalidV2("direct.send selectors and IDs must be non-empty")
	}
	if value.OperationID != value.MessageID {
		return invalidV2("operation_id must equal message_id")
	}
	if value.CreatedAt != "" {
		if _, err := time.Parse(time.RFC3339, value.CreatedAt); err != nil {
			return invalidV2("meta.created_at must be RFC3339")
		}
	}
	return nil
}

type V2RatchetHeader struct {
	DHPubB64U string `json:"dh_pub_b64u"`
	PN        string `json:"pn"`
	N         string `json:"n"`
}

func (value V2RatchetHeader) Validate() error {
	if err := validateX25519B64U(value.DHPubB64U, "ratchet_header.dh_pub_b64u"); err != nil {
		return err
	}
	if empty(value.PN, value.N) || !decimal(value.PN) || !decimal(value.N) {
		return invalidV2("invalid ratchet header")
	}
	return nil
}

type V2DirectInitBody struct {
	SessionID                  string `json:"session_id"`
	Suite                      string `json:"suite"`
	SenderStaticKeyAgreementID string `json:"sender_static_key_agreement_id"`
	RecipientBundleID          string `json:"recipient_bundle_id"`
	RecipientSignedPrekeyID    string `json:"recipient_signed_prekey_id"`
	RecipientOneTimePrekeyID   string `json:"recipient_one_time_prekey_id,omitempty"`
	SenderEphemeralPubB64U     string `json:"sender_ephemeral_pub_b64u"`
	CiphertextB64U             string `json:"ciphertext_b64u"`
}

func (value V2DirectInitBody) Validate() error {
	if value.Suite != MTIDirectE2EESuiteV2 {
		return invalidV2("unsupported suite")
	}
	if err := validateFixedB64U(value.SessionID, "body.session_id", 16); err != nil {
		return err
	}
	if err := validateX25519B64U(value.SenderEphemeralPubB64U, "body.sender_ephemeral_pub_b64u"); err != nil {
		return err
	}
	if err := validateB64U(value.CiphertextB64U, "body.ciphertext_b64u"); err != nil {
		return err
	}
	if empty(value.SenderStaticKeyAgreementID, value.RecipientBundleID, value.RecipientSignedPrekeyID) {
		return invalidV2("init fields must be non-empty")
	}
	return nil
}

type V2DirectCipherBody struct {
	SessionID      string          `json:"session_id"`
	Suite          string          `json:"suite,omitempty"`
	RatchetHeader  V2RatchetHeader `json:"ratchet_header"`
	CiphertextB64U string          `json:"ciphertext_b64u"`
}

func (value V2DirectCipherBody) Validate() error {
	if err := validateFixedB64U(value.SessionID, "body.session_id", 16); err != nil {
		return err
	}
	if err := validateB64U(value.CiphertextB64U, "body.ciphertext_b64u"); err != nil {
		return err
	}
	if value.Suite != "" && value.Suite != MTIDirectE2EESuiteV2 {
		return invalidV2("cipher suite mismatch")
	}
	return value.RatchetHeader.Validate()
}

type V2ApplicationPlaintext struct {
	ApplicationContentType string          `json:"application_content_type"`
	LogicalMessageID       string          `json:"logical_message_id,omitempty"`
	ConversationID         string          `json:"conversation_id,omitempty"`
	ReplyToMessageID       string          `json:"reply_to_message_id,omitempty"`
	Annotations            *map[string]any `json:"annotations,omitempty"`
	Text                   *string         `json:"text,omitempty"`
	Payload                *map[string]any `json:"payload,omitempty"`
	PayloadB64U            *string         `json:"payload_b64u,omitempty"`
}

func (value *V2ApplicationPlaintext) UnmarshalJSON(encoded []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &raw); err != nil {
		return invalidV2("invalid ApplicationPlaintext")
	}
	for _, field := range []string{
		"logical_message_id", "conversation_id", "reply_to_message_id",
		"annotations", "text", "payload", "payload_b64u",
	} {
		if member, present := raw[field]; present && bytes.Equal(bytes.TrimSpace(member), []byte("null")) {
			return invalidV2(field + " must be omitted rather than null")
		}
	}
	for _, field := range []string{"logical_message_id", "conversation_id", "reply_to_message_id", "text", "payload_b64u"} {
		if member, present := raw[field]; present {
			var text string
			if err := json.Unmarshal(member, &text); err != nil || text == "" {
				return invalidV2(field + " must be a non-empty string")
			}
		}
	}
	type applicationPlaintextAlias V2ApplicationPlaintext
	var decoded applicationPlaintextAlias
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return invalidV2(err.Error())
	}
	*value = V2ApplicationPlaintext(decoded)
	return nil
}

func (value V2ApplicationPlaintext) Validate() error {
	if value.ApplicationContentType == "" {
		return invalidV2("application_content_type must be non-empty")
	}
	count := 0
	if value.Text != nil {
		count++
	}
	if value.Payload != nil {
		count++
	}
	if value.PayloadB64U != nil {
		count++
	}
	if count != 1 {
		return invalidV2("exactly one plaintext bearer must be present")
	}
	if value.Text != nil && *value.Text == "" || value.PayloadB64U != nil && *value.PayloadB64U == "" {
		return invalidV2("plaintext bearer must be non-empty")
	}
	if value.PayloadB64U != nil {
		if err := validateB64U(*value.PayloadB64U, "payload_b64u"); err != nil {
			return err
		}
	}
	if value.ApplicationContentType == "text/plain" && value.Text == nil {
		return invalidV2("text/plain requires the text bearer")
	}
	if (value.ApplicationContentType == "application/json" || value.ApplicationContentType == "application/anp-attachment-manifest+json") && value.Payload == nil {
		return invalidV2(value.ApplicationContentType + " requires the payload bearer")
	}
	return nil
}

func decodeV2(value any, target any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return invalidV2(err.Error())
	}
	return nil
}

func empty(values ...string) bool {
	for _, value := range values {
		if value == "" {
			return true
		}
	}
	return false
}

func decimal(value string) bool {
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return value != ""
}

func validateX25519B64U(value string, field string) error {
	if err := validateFixedB64U(value, field, 32); err != nil {
		return invalidV2(field + " must be unpadded base64url encoding a 32-byte X25519 public key")
	}
	return nil
}

func validateFixedB64U(value string, field string, expectedLength int) error {
	decoded, err := decodeV2B64U(value, field)
	if err != nil {
		return err
	}
	if len(decoded) != expectedLength {
		return invalidV2(field + " has the wrong decoded length")
	}
	return nil
}

func validateB64U(value string, field string) error {
	_, err := decodeV2B64U(value, field)
	return err
}

func decodeV2B64U(value string, field string) ([]byte, error) {
	if value == "" || strings.Contains(value, "=") {
		return nil, invalidV2(field + " must be unpadded base64url")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, invalidV2(field + " must be base64url")
	}
	return decoded, nil
}
