package directe2ee

import "github.com/agent-network-protocol/anp/golang/internal/cjson"

// BuildInitAAD builds canonical associated data for a direct init message.
func BuildInitAAD(metadata DirectEnvelopeMetadata, body DirectInitBody) ([]byte, error) {
	payload := map[string]any{
		"sender_did":                        metadata.SenderDID,
		"recipient_did":                     metadata.RecipientDID,
		"suite":                             body.Suite,
		"bundle_id":                         body.RecipientBundleID,
		"sender_static_key_agreement_id":    body.SenderStaticKeyAgreementID,
		"recipient_static_key_agreement_id": body.RecipientStaticKeyAgreementID,
		"recipient_signed_prekey_id":        body.RecipientSignedPrekeyID,
		"recipient_one_time_prekey_id":      emptyToNil(body.RecipientOneTimePrekeyID),
		"session_id":                        body.SessionID,
		"message_id":                        metadata.MessageID,
		"profile":                           metadata.Profile,
		"security_profile":                  metadata.SecurityProfile,
	}
	return cjson.Marshal(payload)
}

// BuildMessageAAD builds canonical associated data for a direct cipher message.
func BuildMessageAAD(metadata DirectEnvelopeMetadata, body DirectCipherBody, applicationContentType string) ([]byte, error) {
	payload := map[string]any{
		"sender_did":               metadata.SenderDID,
		"recipient_did":            metadata.RecipientDID,
		"session_id":               body.SessionID,
		"message_id":               metadata.MessageID,
		"profile":                  metadata.Profile,
		"security_profile":         metadata.SecurityProfile,
		"application_content_type": applicationContentType,
		"ratchet_header": map[string]any{
			"dh_pub_b64u": body.RatchetHeader.DHPubB64U,
			"pn":          body.RatchetHeader.PN,
			"n":           body.RatchetHeader.N,
		},
	}
	return cjson.Marshal(payload)
}

func emptyToNil(value string) any {
	if value == "" {
		return nil
	}
	return value
}
