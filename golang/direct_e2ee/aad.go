package directe2ee

import "github.com/agent-network-protocol/anp/golang/internal/cjson"

const (
	ContentTypeDirectInit   = "application/anp-direct-init+json"
	ContentTypeDirectCipher = "application/anp-direct-cipher+json"
)

// BuildInitAAD builds canonical associated data for a P5 direct init message.
func BuildInitAAD(metadata DirectEnvelopeMetadata, body DirectInitBody) ([]byte, error) {
	payload := map[string]any{
		"content_type":                   ContentTypeDirectInit,
		"message_id":                     metadata.MessageID,
		"profile":                        metadata.Profile,
		"security_profile":               metadata.SecurityProfile,
		"sender_did":                     metadata.SenderDID,
		"recipient_did":                  metadata.RecipientDID,
		"suite":                          body.Suite,
		"recipient_bundle_id":            body.RecipientBundleID,
		"sender_static_key_agreement_id": body.SenderStaticKeyAgreementID,
		"recipient_signed_prekey_id":     body.RecipientSignedPrekeyID,
		"session_id":                     body.SessionID,
	}
	if body.RecipientOneTimePrekeyID != "" {
		payload["recipient_one_time_prekey_id"] = body.RecipientOneTimePrekeyID
	}
	return cjson.Marshal(payload)
}

// BuildMessageAAD builds canonical associated data for a P5 direct cipher message.
func BuildMessageAAD(metadata DirectEnvelopeMetadata, body DirectCipherBody) ([]byte, error) {
	payload := map[string]any{
		"content_type":     ContentTypeDirectCipher,
		"message_id":       metadata.MessageID,
		"profile":          metadata.Profile,
		"security_profile": metadata.SecurityProfile,
		"sender_did":       metadata.SenderDID,
		"recipient_did":    metadata.RecipientDID,
		"session_id":       body.SessionID,
		"ratchet_header": map[string]any{
			"dh_pub_b64u": body.RatchetHeader.DHPubB64U,
			"pn":          body.RatchetHeader.PN,
			"n":           body.RatchetHeader.N,
		},
	}
	return cjson.Marshal(payload)
}
