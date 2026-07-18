package groupe2ee

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

type v2Request struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type v2Params struct {
	Meta json.RawMessage `json:"meta"`
	Body json.RawMessage `json:"body"`
	Auth json.RawMessage `json:"auth,omitempty"`
}

type V2PublishKeyPackageResult struct {
	Published     bool   `json:"published"`
	OwnerDID      string `json:"owner_did"`
	OwnerDeviceID string `json:"owner_device_id"`
	KeyPackageID  string `json:"key_package_id"`
	PublishedAt   string `json:"published_at"`
}

func (value V2PublishKeyPackageResult) Validate() error {
	if !value.Published {
		return invalidV2("published must be true in a successful result")
	}
	if empty(value.OwnerDID, value.OwnerDeviceID, value.KeyPackageID) {
		return invalidV2("publish result identifiers must be non-empty")
	}
	if _, err := time.Parse(time.RFC3339, value.PublishedAt); err != nil {
		return invalidV2("published_at must be RFC3339")
	}
	return nil
}

type V2GetKeyPackageResult struct {
	TargetDID       string            `json:"target_did"`
	TargetDeviceID  string            `json:"target_device_id"`
	GroupKeyPackage V2GroupKeyPackage `json:"group_key_package"`
}

func (value V2GetKeyPackageResult) Validate() error {
	if empty(value.TargetDID, value.TargetDeviceID) {
		return invalidV2("get result target pair must be non-empty")
	}
	if err := value.GroupKeyPackage.ValidateStructure(); err != nil {
		return err
	}
	if value.TargetDID != value.GroupKeyPackage.OwnerDID || value.TargetDeviceID != value.GroupKeyPackage.OwnerDeviceID {
		return invalidV2("get result target pair must equal group_key_package owner pair")
	}
	return nil
}

type V2GroupCreateResult struct {
	Created           bool            `json:"created"`
	GroupDID          string          `json:"group_did"`
	GroupStateRef     V2GroupStateRef `json:"group_state_ref"`
	CryptoGroupIDB64U string          `json:"crypto_group_id_b64u"`
	Epoch             string          `json:"epoch"`
	AcceptedAt        string          `json:"accepted_at"`
}

func (value V2GroupCreateResult) Validate() error {
	if !value.Created {
		return invalidV2("created must be true in a successful result")
	}
	if empty(value.GroupDID) {
		return invalidV2("group_did must be non-empty")
	}
	if err := value.GroupStateRef.Validate(); err != nil {
		return err
	}
	if value.GroupStateRef.GroupDID != value.GroupDID {
		return invalidV2("result group_state_ref.group_did must equal group_did")
	}
	if _, err := decodeB64UV2("crypto_group_id_b64u", value.CryptoGroupIDB64U); err != nil {
		return err
	}
	if err := validateDecimalV2("epoch", value.Epoch); err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339, value.AcceptedAt); err != nil {
		return invalidV2("accepted_at must be RFC3339")
	}
	return nil
}

type V2GroupMembershipResult struct {
	Accepted          bool            `json:"accepted"`
	GroupDID          string          `json:"group_did"`
	MemberDID         string          `json:"member_did"`
	MemberDeviceID    string          `json:"member_device_id"`
	GroupStateRef     V2GroupStateRef `json:"group_state_ref"`
	CryptoGroupIDB64U string          `json:"crypto_group_id_b64u"`
	Epoch             string          `json:"epoch"`
	AcceptedAt        string          `json:"accepted_at"`
}

func (value V2GroupMembershipResult) Validate() error {
	if !value.Accepted {
		return invalidV2("accepted must be true in a successful result")
	}
	if empty(value.GroupDID, value.MemberDID, value.MemberDeviceID) {
		return invalidV2("membership result identifiers must be non-empty")
	}
	if err := value.GroupStateRef.Validate(); err != nil {
		return err
	}
	if value.GroupStateRef.GroupDID != value.GroupDID {
		return invalidV2("result group_state_ref.group_did must equal group_did")
	}
	if _, err := decodeB64UV2("crypto_group_id_b64u", value.CryptoGroupIDB64U); err != nil {
		return err
	}
	if err := validateDecimalV2("epoch", value.Epoch); err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339, value.AcceptedAt); err != nil {
		return invalidV2("accepted_at must be RFC3339")
	}
	return nil
}

type V2GroupSendResult struct {
	Accepted          bool   `json:"accepted"`
	GroupDID          string `json:"group_did"`
	MessageID         string `json:"message_id"`
	OperationID       string `json:"operation_id"`
	GroupEventSeq     string `json:"group_event_seq"`
	GroupStateVersion string `json:"group_state_version"`
	AcceptedAt        string `json:"accepted_at"`
	Epoch             string `json:"epoch"`
	GroupReceipt      any    `json:"group_receipt"`
}

func (value V2GroupSendResult) Validate() error {
	if !value.Accepted {
		return invalidV2("accepted must be true in a successful result")
	}
	if empty(value.GroupDID, value.MessageID, value.OperationID) {
		return invalidV2("send result identifiers must be non-empty")
	}
	if err := validateDecimalV2("group_event_seq", value.GroupEventSeq); err != nil {
		return err
	}
	if empty(value.GroupStateVersion) {
		return invalidV2("group_state_version must be non-empty")
	}
	if err := validateDecimalV2("epoch", value.Epoch); err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339, value.AcceptedAt); err != nil {
		return invalidV2("accepted_at must be RFC3339")
	}
	if !isJSONObjectV2(value.GroupReceipt) {
		return invalidV2("group_receipt must be a JSON object")
	}
	return nil
}

func PublishKeyPackageRequestV2(meta V2ServiceMetadata, body V2PublishKeyPackageBody) (map[string]any, error) {
	if err := validatePublishV2(meta, body); err != nil {
		return nil, err
	}
	return requestMapV2(MethodPublishKeyPackageV2, meta, body, nil)
}

func ParsePublishKeyPackageRequestV2(value any) (V2ServiceMetadata, V2PublishKeyPackageBody, error) {
	request, params, err := parseRequestV2(value, MethodPublishKeyPackageV2, false)
	_ = request
	if err != nil {
		return V2ServiceMetadata{}, V2PublishKeyPackageBody{}, err
	}
	var meta V2ServiceMetadata
	var body V2PublishKeyPackageBody
	if err := decodeStrictV2(params.Meta, &meta); err != nil {
		return meta, body, err
	}
	if err := decodeStrictV2(params.Body, &body); err != nil {
		return meta, body, err
	}
	if err := validatePublishV2(meta, body); err != nil {
		return meta, body, err
	}
	return meta, body, nil
}

func GetKeyPackageRequestV2(meta V2ServiceMetadata, body V2GetKeyPackageBody) (map[string]any, error) {
	if err := validateGetV2(meta, body); err != nil {
		return nil, err
	}
	return requestMapV2(MethodGetKeyPackageV2, meta, body, nil)
}

func ParseGetKeyPackageRequestV2(value any) (V2ServiceMetadata, V2GetKeyPackageBody, error) {
	_, params, err := parseRequestV2(value, MethodGetKeyPackageV2, false)
	if err != nil {
		return V2ServiceMetadata{}, V2GetKeyPackageBody{}, err
	}
	var meta V2ServiceMetadata
	var body V2GetKeyPackageBody
	if err := decodeStrictV2(params.Meta, &meta); err != nil {
		return meta, body, err
	}
	if err := decodeStrictV2(params.Body, &body); err != nil {
		return meta, body, err
	}
	if err := validateGetV2(meta, body); err != nil {
		return meta, body, err
	}
	return meta, body, nil
}

func GroupCreateRequestV2(meta V2ServiceMetadata, body V2GroupCreateBody, auth V2OriginAuth) (map[string]any, error) {
	if err := validateCreateV2(meta, body, auth); err != nil {
		return nil, err
	}
	return requestMapV2(MethodGroupCreateV2, meta, body, &auth)
}

func ParseGroupCreateRequestV2(value any) (V2ServiceMetadata, V2GroupCreateBody, V2OriginAuth, error) {
	_, params, err := parseRequestV2(value, MethodGroupCreateV2, true)
	if err != nil {
		return V2ServiceMetadata{}, V2GroupCreateBody{}, V2OriginAuth{}, err
	}
	var meta V2ServiceMetadata
	var body V2GroupCreateBody
	var auth V2OriginAuth
	if err := decodeStrictV2(params.Meta, &meta); err != nil {
		return meta, body, auth, err
	}
	if err := decodeStrictV2(params.Body, &body); err != nil {
		return meta, body, auth, err
	}
	if err := decodeStrictV2(params.Auth, &auth); err != nil {
		return meta, body, auth, err
	}
	if err := validateCreateV2(meta, body, auth); err != nil {
		return meta, body, auth, err
	}
	return meta, body, auth, nil
}

func GroupAddRequestV2(meta V2GroupControlMetadata, body V2GroupAddBody, auth V2OriginAuth) (map[string]any, error) {
	if err := validateAddV2(meta, body, auth); err != nil {
		return nil, err
	}
	return requestMapV2(MethodGroupAddV2, meta, body, &auth)
}

func ParseGroupAddRequestV2(value any) (V2GroupControlMetadata, V2GroupAddBody, V2OriginAuth, error) {
	_, params, err := parseRequestV2(value, MethodGroupAddV2, true)
	if err != nil {
		return V2GroupControlMetadata{}, V2GroupAddBody{}, V2OriginAuth{}, err
	}
	var meta V2GroupControlMetadata
	var body V2GroupAddBody
	var auth V2OriginAuth
	if err := decodeStrictV2(params.Meta, &meta); err != nil {
		return meta, body, auth, err
	}
	if err := decodeStrictV2(params.Body, &body); err != nil {
		return meta, body, auth, err
	}
	if err := decodeStrictV2(params.Auth, &auth); err != nil {
		return meta, body, auth, err
	}
	if err := validateAddV2(meta, body, auth); err != nil {
		return meta, body, auth, err
	}
	return meta, body, auth, nil
}

func GroupRemoveRequestV2(meta V2GroupControlMetadata, body V2GroupRemoveBody, auth V2OriginAuth) (map[string]any, error) {
	if err := validateRemoveV2(meta, body, auth); err != nil {
		return nil, err
	}
	return requestMapV2(MethodGroupRemoveV2, meta, body, &auth)
}

func ParseGroupRemoveRequestV2(value any) (V2GroupControlMetadata, V2GroupRemoveBody, V2OriginAuth, error) {
	_, params, err := parseRequestV2(value, MethodGroupRemoveV2, true)
	if err != nil {
		return V2GroupControlMetadata{}, V2GroupRemoveBody{}, V2OriginAuth{}, err
	}
	var meta V2GroupControlMetadata
	var body V2GroupRemoveBody
	var auth V2OriginAuth
	if err := decodeStrictV2(params.Meta, &meta); err != nil {
		return meta, body, auth, err
	}
	if err := decodeStrictV2(params.Body, &body); err != nil {
		return meta, body, auth, err
	}
	if err := decodeStrictV2(params.Auth, &auth); err != nil {
		return meta, body, auth, err
	}
	if err := validateRemoveV2(meta, body, auth); err != nil {
		return meta, body, auth, err
	}
	return meta, body, auth, nil
}

func GroupSendRequestV2(meta V2GroupSendMetadata, body V2GroupCipherObject, auth V2OriginAuth) (map[string]any, error) {
	if err := validateSendV2(meta, body, auth); err != nil {
		return nil, err
	}
	return requestMapV2(MethodGroupSendV2, meta, body, &auth)
}

func ParseGroupSendRequestV2(value any) (V2GroupSendMetadata, V2GroupCipherObject, V2OriginAuth, error) {
	_, params, err := parseRequestV2(value, MethodGroupSendV2, true)
	if err != nil {
		return V2GroupSendMetadata{}, V2GroupCipherObject{}, V2OriginAuth{}, err
	}
	var meta V2GroupSendMetadata
	var body V2GroupCipherObject
	var auth V2OriginAuth
	if err := decodeStrictV2(params.Meta, &meta); err != nil {
		return meta, body, auth, err
	}
	if err := decodeStrictV2(params.Body, &body); err != nil {
		return meta, body, auth, err
	}
	if err := decodeStrictV2(params.Auth, &auth); err != nil {
		return meta, body, auth, err
	}
	if err := validateSendV2(meta, body, auth); err != nil {
		return meta, body, auth, err
	}
	return meta, body, auth, nil
}

func GroupNoticeNotificationV2(meta V2GroupNoticeMetadata, body V2E2EENotice) (map[string]any, error) {
	if err := validateNoticeV2(meta, body); err != nil {
		return nil, err
	}
	return requestMapV2(MethodGroupNoticeV2, meta, body, nil)
}

func ParseGroupNoticeNotificationV2(value any) (V2GroupNoticeMetadata, V2E2EENotice, error) {
	_, params, err := parseRequestV2(value, MethodGroupNoticeV2, false)
	if err != nil {
		return V2GroupNoticeMetadata{}, V2E2EENotice{}, err
	}
	var meta V2GroupNoticeMetadata
	var body V2E2EENotice
	if err := decodeStrictV2(params.Meta, &meta); err != nil {
		return meta, body, err
	}
	if err := decodeStrictV2(params.Body, &body); err != nil {
		return meta, body, err
	}
	if err := validateNoticeV2(meta, body); err != nil {
		return meta, body, err
	}
	return meta, body, nil
}

func GroupIncomingNotificationV2(meta V2GroupIncomingMetadata, body V2GroupIncomingBody, auth V2OriginAuth) (map[string]any, error) {
	if err := validateIncomingV2(meta, body, auth); err != nil {
		return nil, err
	}
	return requestMapV2(MethodGroupIncomingV2, meta, body, &auth)
}

func ParseGroupIncomingNotificationV2(value any) (V2GroupIncomingMetadata, V2GroupIncomingBody, V2OriginAuth, error) {
	_, params, err := parseRequestV2(value, MethodGroupIncomingV2, true)
	if err != nil {
		return V2GroupIncomingMetadata{}, V2GroupIncomingBody{}, V2OriginAuth{}, err
	}
	var meta V2GroupIncomingMetadata
	var body V2GroupIncomingBody
	var auth V2OriginAuth
	if err := decodeStrictV2(params.Meta, &meta); err != nil {
		return meta, body, auth, err
	}
	if err := decodeStrictV2(params.Body, &body); err != nil {
		return meta, body, auth, err
	}
	if err := decodeStrictV2(params.Auth, &auth); err != nil {
		return meta, body, auth, err
	}
	if err := validateIncomingV2(meta, body, auth); err != nil {
		return meta, body, auth, err
	}
	return meta, body, auth, nil
}

func ParsePublishKeyPackageResultV2(value any) (V2PublishKeyPackageResult, error) {
	var result V2PublishKeyPackageResult
	if err := decodeValueV2(value, &result); err != nil {
		return result, err
	}
	return result, result.Validate()
}

func ParseGetKeyPackageResultV2(value any) (V2GetKeyPackageResult, error) {
	var result V2GetKeyPackageResult
	if err := decodeValueV2(value, &result); err != nil {
		return result, err
	}
	return result, result.Validate()
}

func ParseGroupCreateResultV2(value any) (V2GroupCreateResult, error) {
	var result V2GroupCreateResult
	if err := decodeValueV2(value, &result); err != nil {
		return result, err
	}
	return result, result.Validate()
}

func ParseGroupMembershipResultV2(value any) (V2GroupMembershipResult, error) {
	var result V2GroupMembershipResult
	if err := decodeValueV2(value, &result); err != nil {
		return result, err
	}
	return result, result.Validate()
}

func ParseGroupSendResultV2(value any) (V2GroupSendResult, error) {
	var result V2GroupSendResult
	if err := decodeValueV2(value, &result); err != nil {
		return result, err
	}
	return result, result.Validate()
}

func validatePublishV2(meta V2ServiceMetadata, body V2PublishKeyPackageBody) error {
	if err := meta.Validate(TransportSecurityProfileV2); err != nil {
		return err
	}
	if err := body.GroupKeyPackage.ValidateStructure(); err != nil {
		return err
	}
	if body.GroupKeyPackage.OwnerDID != meta.SenderDID || body.GroupKeyPackage.OwnerDeviceID != meta.SenderDeviceID {
		return invalidV2("published KeyPackage owner pair must equal sending device pair")
	}
	return nil
}

func validateGetV2(meta V2ServiceMetadata, body V2GetKeyPackageBody) error {
	if err := meta.Validate(TransportSecurityProfileV2); err != nil {
		return err
	}
	return body.Validate()
}

func validateCreateV2(meta V2ServiceMetadata, body V2GroupCreateBody, auth V2OriginAuth) error {
	if err := meta.Validate(SecurityProfileV2); err != nil {
		return err
	}
	if err := body.Validate(); err != nil {
		return err
	}
	if err := auth.Validate(); err != nil {
		return err
	}
	if body.CreatorKeyPackage.OwnerDID != meta.SenderDID || body.CreatorKeyPackage.OwnerDeviceID != meta.SenderDeviceID {
		return invalidV2("creator KeyPackage owner pair must equal sending owner device pair")
	}
	return nil
}

func validateAddV2(meta V2GroupControlMetadata, body V2GroupAddBody, auth V2OriginAuth) error {
	if err := meta.Validate(); err != nil {
		return err
	}
	if err := body.Validate(); err != nil {
		return err
	}
	if err := auth.Validate(); err != nil {
		return err
	}
	return validateGroupTargetV2(meta.Target, body.GroupStateRef)
}

func validateRemoveV2(meta V2GroupControlMetadata, body V2GroupRemoveBody, auth V2OriginAuth) error {
	if err := meta.Validate(); err != nil {
		return err
	}
	if err := body.Validate(); err != nil {
		return err
	}
	if err := auth.Validate(); err != nil {
		return err
	}
	return validateGroupTargetV2(meta.Target, body.GroupStateRef)
}

func validateSendV2(meta V2GroupSendMetadata, body V2GroupCipherObject, auth V2OriginAuth) error {
	if err := meta.Validate(); err != nil {
		return err
	}
	if err := body.Validate(); err != nil {
		return err
	}
	if err := auth.Validate(); err != nil {
		return err
	}
	return validateGroupTargetV2(meta.Target, body.GroupStateRef)
}

func validateNoticeV2(meta V2GroupNoticeMetadata, body V2E2EENotice) error {
	if err := meta.Validate(); err != nil {
		return err
	}
	if err := body.Validate(); err != nil {
		return err
	}
	if body.NoticeType == "welcome-delivery" && (meta.Target.DID != body.SubjectDID || meta.RecipientDeviceID != body.SubjectDeviceID) {
		return invalidV2("welcome-delivery target must equal the added subject device pair")
	}
	return nil
}

func validateIncomingV2(meta V2GroupIncomingMetadata, body V2GroupIncomingBody, auth V2OriginAuth) error {
	if err := meta.Validate(); err != nil {
		return err
	}
	if err := body.Validate(); err != nil {
		return err
	}
	return auth.Validate()
}

func validateGroupTargetV2(target V2Target, stateRef V2GroupStateRef) error {
	if target.DID != stateRef.GroupDID {
		return invalidV2("meta.target.did must equal group_state_ref.group_did")
	}
	return nil
}

func parseRequestV2(value any, expectedMethod string, requireAuth bool) (v2Request, v2Params, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return v2Request{}, v2Params{}, err
	}
	if err := rejectKnownNullsV2(encoded); err != nil {
		return v2Request{}, v2Params{}, err
	}
	var request v2Request
	if err := decodeStrictV2(encoded, &request); err != nil {
		return request, v2Params{}, err
	}
	if request.Method != expectedMethod {
		return request, v2Params{}, invalidV2("method must equal " + expectedMethod)
	}
	var params v2Params
	if err := decodeStrictV2(request.Params, &params); err != nil {
		return request, params, err
	}
	if requireAuth && len(params.Auth) == 0 {
		return request, params, invalidV2("params.auth is required")
	}
	if !requireAuth && len(params.Auth) != 0 {
		return request, params, invalidV2("params.auth is not allowed for this method")
	}
	return request, params, nil
}

func requestMapV2(method string, meta, body any, auth *V2OriginAuth) (map[string]any, error) {
	params := map[string]any{"meta": meta, "body": body}
	if auth != nil {
		params["auth"] = auth
	}
	encoded, err := json.Marshal(map[string]any{"method": method, "params": params})
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(encoded, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func decodeValueV2(value any, target any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := rejectKnownNullsV2(encoded); err != nil {
		return err
	}
	return decodeStrictV2(encoded, target)
}

func decodeStrictV2(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return invalidV2(err.Error())
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return invalidV2("multiple JSON values are not allowed")
	}
	return nil
}

func rejectKnownNullsV2(encoded []byte) error {
	var value any
	if err := json.Unmarshal(encoded, &value); err != nil {
		return invalidV2(err.Error())
	}
	optional := map[string]struct{}{
		"anp_version": {}, "created_at": {}, "policy_hash": {}, "roster_hash": {}, "expires_at": {},
		"preferred_suite": {}, "require_fresh": {}, "epoch_authenticator": {},
		"commit_b64u": {}, "welcome_b64u": {}, "ratchet_tree_b64u": {},
		"group_receipt": {}, "notice_id": {},
	}
	var walk func(any) error
	walk = func(current any) error {
		switch typed := current.(type) {
		case map[string]any:
			for field, child := range typed {
				if child == nil {
					if _, known := optional[field]; known {
						return invalidV2(fmt.Sprintf("%s must be omitted rather than null", field))
					}
					continue
				}
				if err := walk(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range typed {
				if err := walk(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(value)
}
