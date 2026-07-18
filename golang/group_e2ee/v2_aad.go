package groupe2ee

import (
	"bytes"
	"encoding/json"

	"github.com/agent-network-protocol/anp/golang/internal/cjson"
)

func GroupSendAuthenticatedDataV2(meta V2GroupSendMetadata, body V2GroupCipherObject) ([]byte, error) {
	if err := meta.Validate(); err != nil {
		return nil, err
	}
	if err := body.Validate(); err != nil {
		return nil, err
	}
	if body.GroupStateRef.GroupDID != meta.Target.DID {
		return nil, invalidV2("body.group_state_ref.group_did must equal meta.target.did")
	}
	return cjson.Marshal(map[string]any{
		"content_type":         GroupCipherContentTypeV2,
		"group_did":            meta.Target.DID,
		"crypto_group_id_b64u": body.CryptoGroupIDB64U,
		"group_state_ref":      body.GroupStateRef,
		"security_profile":     SecurityProfileV2,
		"sender_did":           meta.SenderDID,
		"sender_device_id":     meta.SenderDeviceID,
		"message_id":           meta.MessageID,
		"operation_id":         meta.OperationID,
	})
}

func groupMembershipSubmissionBindingV2(method string, meta V2GroupControlMetadata, body any) ([]byte, error) {
	if method != MethodGroupAddV2 && method != MethodGroupRemoveV2 {
		return nil, invalidV2("subject_method must be group.e2ee.add or group.e2ee.remove")
	}
	if err := meta.Validate(); err != nil {
		return nil, err
	}
	var memberDID, memberDeviceID, cryptoGroupID, epoch string
	var stateRef V2GroupStateRef
	switch typed := body.(type) {
	case V2GroupAddBody:
		if method != MethodGroupAddV2 {
			return nil, invalidV2("add body requires group.e2ee.add")
		}
		if err := typed.Validate(); err != nil {
			return nil, err
		}
		memberDID, memberDeviceID, stateRef, cryptoGroupID, epoch = typed.MemberDID, typed.MemberDeviceID, typed.GroupStateRef, typed.CryptoGroupIDB64U, typed.Epoch
	case V2GroupRemoveBody:
		if method != MethodGroupRemoveV2 {
			return nil, invalidV2("remove body requires group.e2ee.remove")
		}
		if err := typed.Validate(); err != nil {
			return nil, err
		}
		memberDID, memberDeviceID, stateRef, cryptoGroupID, epoch = typed.MemberDID, typed.MemberDeviceID, typed.GroupStateRef, typed.CryptoGroupIDB64U, typed.Epoch
	default:
		return nil, invalidV2("unsupported membership body")
	}
	if stateRef.GroupDID != meta.Target.DID {
		return nil, invalidV2("group_state_ref.group_did must equal meta.target.did")
	}
	return cjson.Marshal(map[string]any{
		"group_did":            meta.Target.DID,
		"crypto_group_id_b64u": cryptoGroupID,
		"group_state_ref":      stateRef,
		"subject_method":       method,
		"member_did":           memberDID,
		"member_device_id":     memberDeviceID,
		"epoch":                epoch,
		"security_profile":     SecurityProfileV2,
		"sender_did":           meta.SenderDID,
		"sender_device_id":     meta.SenderDeviceID,
		"operation_id":         meta.OperationID,
	})
}

func GroupAddSubmissionBindingV2(meta V2GroupControlMetadata, body V2GroupAddBody) ([]byte, error) {
	return groupMembershipSubmissionBindingV2(MethodGroupAddV2, meta, body)
}

func GroupRemoveSubmissionBindingV2(meta V2GroupControlMetadata, body V2GroupRemoveBody) ([]byte, error) {
	return groupMembershipSubmissionBindingV2(MethodGroupRemoveV2, meta, body)
}

func CanonicalGroupApplicationPlaintextV2(value V2GroupApplicationPlaintext) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	return cjson.Marshal(value)
}

func ParseGroupApplicationPlaintextV2(value any) (V2GroupApplicationPlaintext, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return V2GroupApplicationPlaintext{}, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &members); err != nil {
		return V2GroupApplicationPlaintext{}, invalidV2("group application plaintext must be an object")
	}
	for _, field := range []string{"thread_id", "reply_to_message_id", "annotations", "text", "payload", "payload_b64u"} {
		if raw, present := members[field]; present && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return V2GroupApplicationPlaintext{}, invalidV2(field + " must be omitted rather than null")
		}
	}
	var plaintext V2GroupApplicationPlaintext
	if err := decodeStrictV2(encoded, &plaintext); err != nil {
		return V2GroupApplicationPlaintext{}, err
	}
	if err := plaintext.Validate(); err != nil {
		return V2GroupApplicationPlaintext{}, err
	}
	return plaintext, nil
}
