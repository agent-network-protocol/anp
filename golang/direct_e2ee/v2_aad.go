package directe2ee

import "github.com/agent-network-protocol/anp/golang/internal/cjson"

func BuildInitAADV2(meta V2DirectMetadata, body V2DirectInitBody) ([]byte, error) {
	if err := meta.Validate(); err != nil {
		return nil, err
	}
	if err := body.Validate(); err != nil {
		return nil, err
	}
	if meta.ContentType != ContentTypeDirectInitV2 {
		return nil, invalidV2("init AAD content_type mismatch")
	}
	payload := map[string]any{
		"content_type": ContentTypeDirectInitV2, "message_id": meta.MessageID,
		"operation_id": meta.OperationID, "profile": meta.Profile,
		"security_profile": meta.SecurityProfile, "sender_did": meta.SenderDID,
		"sender_device_id": meta.SenderDeviceID, "recipient_did": meta.Target.DID,
		"recipient_device_id": meta.RecipientDeviceID, "suite": body.Suite,
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

func BuildMessageAADV2(meta V2DirectMetadata, body V2DirectCipherBody) ([]byte, error) {
	if err := meta.Validate(); err != nil {
		return nil, err
	}
	if err := body.Validate(); err != nil {
		return nil, err
	}
	if meta.ContentType != ContentTypeDirectCipherV2 {
		return nil, invalidV2("message AAD content_type mismatch")
	}
	return cjson.Marshal(map[string]any{
		"content_type": ContentTypeDirectCipherV2, "message_id": meta.MessageID,
		"operation_id": meta.OperationID, "profile": meta.Profile,
		"security_profile": meta.SecurityProfile, "sender_did": meta.SenderDID,
		"sender_device_id": meta.SenderDeviceID, "recipient_did": meta.Target.DID,
		"recipient_device_id": meta.RecipientDeviceID, "session_id": body.SessionID,
		"ratchet_header": body.RatchetHeader,
	})
}

func CanonicalApplicationPlaintextV2(value V2ApplicationPlaintext) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	return cjson.Marshal(value)
}
