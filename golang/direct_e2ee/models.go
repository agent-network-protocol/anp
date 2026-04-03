package directe2ee

const MTIDirectE2EESuite = "ANP-DIRECT-E2EE-X3DH-25519-CHACHA20POLY1305-SHA256-V1"

// SignedPrekey describes a published signed prekey.
type SignedPrekey struct {
	KeyID         string `json:"key_id"`
	PublicKeyB64U string `json:"public_key_b64u"`
	ExpiresAt     string `json:"expires_at"`
}

// PrekeyBundle is the published prekey bundle.
type PrekeyBundle struct {
	BundleID             string         `json:"bundle_id"`
	OwnerDID             string         `json:"owner_did"`
	Suite                string         `json:"suite"`
	StaticKeyAgreementID string         `json:"static_key_agreement_id"`
	SignedPrekey         SignedPrekey   `json:"signed_prekey"`
	Proof                map[string]any `json:"proof"`
}

// DirectEnvelopeMetadata is the envelope metadata shared by all direct E2EE messages.
type DirectEnvelopeMetadata struct {
	SenderDID       string `json:"sender_did"`
	RecipientDID    string `json:"recipient_did"`
	MessageID       string `json:"message_id"`
	Profile         string `json:"profile"`
	SecurityProfile string `json:"security_profile"`
}

// RatchetHeader is the per-message ratchet header.
type RatchetHeader struct {
	DHPubB64U string `json:"dh_pub_b64u"`
	PN        string `json:"pn"`
	N         string `json:"n"`
}

// DirectInitBody is the init message body.
type DirectInitBody struct {
	SessionID                     string `json:"session_id"`
	Suite                         string `json:"suite"`
	SenderStaticKeyAgreementID    string `json:"sender_static_key_agreement_id"`
	RecipientBundleID             string `json:"recipient_bundle_id"`
	RecipientStaticKeyAgreementID string `json:"recipient_static_key_agreement_id"`
	RecipientSignedPrekeyID       string `json:"recipient_signed_prekey_id"`
	RecipientOneTimePrekeyID      string `json:"recipient_one_time_prekey_id,omitempty"`
	SenderEphemeralPubB64U        string `json:"sender_ephemeral_pub_b64u"`
	CiphertextB64U                string `json:"ciphertext_b64u"`
}

// DirectCipherBody is the follow-up encrypted message body.
type DirectCipherBody struct {
	SessionID      string        `json:"session_id"`
	Suite          string        `json:"suite"`
	RatchetHeader  RatchetHeader `json:"ratchet_header"`
	CiphertextB64U string        `json:"ciphertext_b64u"`
}

// ApplicationPlaintext is the decrypted application payload.
type ApplicationPlaintext struct {
	ApplicationContentType string         `json:"application_content_type"`
	ConversationID         string         `json:"conversation_id,omitempty"`
	ReplyToMessageID       string         `json:"reply_to_message_id,omitempty"`
	Annotations            map[string]any `json:"annotations,omitempty"`
	Text                   string         `json:"text,omitempty"`
	Payload                map[string]any `json:"payload,omitempty"`
}

// NewTextPlaintext builds a text application payload.
func NewTextPlaintext(contentType string, text string) ApplicationPlaintext {
	return ApplicationPlaintext{ApplicationContentType: contentType, Text: text}
}

// NewJSONPlaintext builds a JSON application payload.
func NewJSONPlaintext(contentType string, payload map[string]any) ApplicationPlaintext {
	return ApplicationPlaintext{ApplicationContentType: contentType, Payload: payload}
}

// SkippedMessageKey stores skipped ratchet keys.
type SkippedMessageKey struct {
	N              uint32 `json:"n"`
	MessageKeyB64U string `json:"message_key_b64u"`
	NonceB64U      string `json:"nonce_b64u"`
}

// DirectSessionState stores direct E2EE session state.
type DirectSessionState struct {
	SessionID                string              `json:"session_id"`
	Suite                    string              `json:"suite"`
	PeerDID                  string              `json:"peer_did"`
	LocalKeyAgreementID      string              `json:"local_key_agreement_id"`
	PeerKeyAgreementID       string              `json:"peer_key_agreement_id"`
	RootKeyB64U              string              `json:"root_key_b64u"`
	SendChainKeyB64U         string              `json:"send_chain_key_b64u"`
	RecvChainKeyB64U         string              `json:"recv_chain_key_b64u"`
	RatchetPublicKeyB64U     string              `json:"ratchet_public_key_b64u"`
	PeerRatchetPublicKeyB64U string              `json:"peer_ratchet_public_key_b64u,omitempty"`
	SendN                    uint32              `json:"send_n"`
	RecvN                    uint32              `json:"recv_n"`
	PreviousSendChainLength  uint32              `json:"previous_send_chain_length"`
	SkippedMessageKeys       []SkippedMessageKey `json:"skipped_message_keys,omitempty"`
	IsInitiator              bool                `json:"is_initiator"`
}

// PendingOutboundRecord stores outbound messages that await transport delivery.
type PendingOutboundRecord struct {
	OperationID     string         `json:"operation_id"`
	MessageID       string         `json:"message_id"`
	WireContentType string         `json:"wire_content_type"`
	BodyJSON        map[string]any `json:"body_json"`
}
