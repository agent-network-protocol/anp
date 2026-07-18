package directe2ee

import (
	"bytes"
	"encoding/json"
	"time"
)

type v2Request struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type v2KeyParams struct {
	Meta V2KeyServiceMetadata `json:"meta"`
	Body json.RawMessage      `json:"body"`
}

type v2DirectParams struct {
	Meta V2DirectMetadata `json:"meta"`
	Body json.RawMessage  `json:"body"`
}

type V2PublishPrekeyBundleBody struct {
	PrekeyBundle   V2PrekeyBundle    `json:"prekey_bundle"`
	OneTimePrekeys []V2OneTimePrekey `json:"one_time_prekeys,omitempty"`
}

type V2GetPrekeyBundleBody struct {
	TargetDID      string `json:"target_did"`
	TargetDeviceID string `json:"target_device_id"`
	PreferredSuite string `json:"preferred_suite,omitempty"`
	RequireOPK     *bool  `json:"require_opk,omitempty"`
}

type V2PublishPrekeyBundleResult struct {
	Published         bool    `json:"published"`
	OwnerDID          string  `json:"owner_did"`
	OwnerDeviceID     string  `json:"owner_device_id"`
	BundleID          string  `json:"bundle_id"`
	PublishedAt       string  `json:"published_at"`
	PublishedOPKCount *uint64 `json:"published_opk_count,omitempty"`
}

func (value V2PublishPrekeyBundleResult) Validate() error {
	if !value.Published {
		return invalidV2("published must be true in a successful result")
	}
	if empty(value.OwnerDID, value.OwnerDeviceID, value.BundleID) {
		return invalidV2("publish result identifiers must be non-empty")
	}
	if _, err := time.Parse(time.RFC3339, value.PublishedAt); err != nil {
		return invalidV2("published_at must be RFC3339")
	}
	return nil
}

type V2GetPrekeyBundleResult struct {
	TargetDID      string           `json:"target_did"`
	TargetDeviceID string           `json:"target_device_id"`
	PrekeyBundle   V2PrekeyBundle   `json:"prekey_bundle"`
	OneTimePrekey  *V2OneTimePrekey `json:"one_time_prekey,omitempty"`
}

func (value V2GetPrekeyBundleResult) Validate() error {
	if empty(value.TargetDID, value.TargetDeviceID) {
		return invalidV2("get result target must be non-empty")
	}
	if err := value.PrekeyBundle.ValidateStructure(); err != nil {
		return err
	}
	if value.TargetDID != value.PrekeyBundle.OwnerDID || value.TargetDeviceID != value.PrekeyBundle.OwnerDeviceID {
		return invalidV2("get result target must equal the returned bundle owner")
	}
	if value.OneTimePrekey != nil {
		if err := value.OneTimePrekey.Validate(); err != nil {
			return err
		}
	}
	return nil
}

type V2DirectSendResult struct {
	Accepted          bool   `json:"accepted"`
	MessageID         string `json:"message_id"`
	OperationID       string `json:"operation_id"`
	TargetDID         string `json:"target_did"`
	RecipientDeviceID string `json:"recipient_device_id"`
	AcceptedAt        string `json:"accepted_at"`
}

func (value V2DirectSendResult) Validate() error {
	if !value.Accepted {
		return invalidV2("accepted must be true in a successful result")
	}
	if empty(value.MessageID, value.OperationID, value.TargetDID, value.RecipientDeviceID) {
		return invalidV2("direct.send result identifiers must be non-empty")
	}
	if value.OperationID != value.MessageID {
		return invalidV2("result.operation_id must equal result.message_id")
	}
	if _, err := time.Parse(time.RFC3339, value.AcceptedAt); err != nil {
		return invalidV2("accepted_at must be RFC3339")
	}
	return nil
}

func ParsePublishPrekeyBundleResultV2(value any) (V2PublishPrekeyBundleResult, error) {
	var result V2PublishPrekeyBundleResult
	if err := decodeV2(value, &result); err != nil {
		return V2PublishPrekeyBundleResult{}, err
	}
	if err := result.Validate(); err != nil {
		return V2PublishPrekeyBundleResult{}, err
	}
	return result, nil
}

func ParseGetPrekeyBundleResultV2(value any) (V2GetPrekeyBundleResult, error) {
	var result V2GetPrekeyBundleResult
	if err := decodeV2(value, &result); err != nil {
		return V2GetPrekeyBundleResult{}, err
	}
	if err := result.Validate(); err != nil {
		return V2GetPrekeyBundleResult{}, err
	}
	return result, nil
}

func ParseDirectSendResultV2(value any) (V2DirectSendResult, error) {
	var result V2DirectSendResult
	if err := decodeV2(value, &result); err != nil {
		return V2DirectSendResult{}, err
	}
	if err := result.Validate(); err != nil {
		return V2DirectSendResult{}, err
	}
	return result, nil
}

func PublishPrekeyBundleRequestV2(meta V2KeyServiceMetadata, body V2PublishPrekeyBundleBody) (map[string]any, error) {
	if err := meta.Validate(); err != nil {
		return nil, err
	}
	if err := body.PrekeyBundle.ValidateStructure(); err != nil {
		return nil, err
	}
	for _, opk := range body.OneTimePrekeys {
		if err := opk.Validate(); err != nil {
			return nil, err
		}
	}
	if body.PrekeyBundle.OwnerDID != meta.SenderDID || body.PrekeyBundle.OwnerDeviceID != meta.SenderDeviceID {
		return nil, invalidV2("published bundle owner must equal sending device")
	}
	return requestMap("direct.e2ee.publish_prekey_bundle", meta, body)
}

func ParsePublishPrekeyBundleRequestV2(value any) (V2KeyServiceMetadata, V2PublishPrekeyBundleBody, error) {
	request, params, err := parseKeyRequest(value)
	if err != nil {
		return V2KeyServiceMetadata{}, V2PublishPrekeyBundleBody{}, err
	}
	if request.Method != "direct.e2ee.publish_prekey_bundle" {
		return V2KeyServiceMetadata{}, V2PublishPrekeyBundleBody{}, invalidV2("wrong publish method")
	}
	var rawBody map[string]json.RawMessage
	if err := json.Unmarshal(params.Body, &rawBody); err != nil {
		return V2KeyServiceMetadata{}, V2PublishPrekeyBundleBody{}, invalidV2("invalid publish body")
	}
	if encoded, present := rawBody["one_time_prekeys"]; present {
		var opks []json.RawMessage
		if err := json.Unmarshal(encoded, &opks); err != nil || len(opks) == 0 {
			return V2KeyServiceMetadata{}, V2PublishPrekeyBundleBody{}, invalidV2("one_time_prekeys must be omitted or non-empty")
		}
	}
	var body V2PublishPrekeyBundleBody
	if err := decodeRaw(params.Body, &body); err != nil {
		return V2KeyServiceMetadata{}, V2PublishPrekeyBundleBody{}, err
	}
	if _, err := PublishPrekeyBundleRequestV2(params.Meta, body); err != nil {
		return V2KeyServiceMetadata{}, V2PublishPrekeyBundleBody{}, err
	}
	return params.Meta, body, nil
}

func GetPrekeyBundleRequestV2(meta V2KeyServiceMetadata, body V2GetPrekeyBundleBody) (map[string]any, error) {
	if err := meta.Validate(); err != nil {
		return nil, err
	}
	if empty(body.TargetDID, body.TargetDeviceID) {
		return nil, invalidV2("get request requires exact target DID/device")
	}
	return requestMap("direct.e2ee.get_prekey_bundle", meta, body)
}

func ParseGetPrekeyBundleRequestV2(value any) (V2KeyServiceMetadata, V2GetPrekeyBundleBody, error) {
	request, params, err := parseKeyRequest(value)
	if err != nil {
		return V2KeyServiceMetadata{}, V2GetPrekeyBundleBody{}, err
	}
	if request.Method != "direct.e2ee.get_prekey_bundle" {
		return V2KeyServiceMetadata{}, V2GetPrekeyBundleBody{}, invalidV2("wrong get method")
	}
	var rawBody map[string]json.RawMessage
	if err := json.Unmarshal(params.Body, &rawBody); err != nil {
		return V2KeyServiceMetadata{}, V2GetPrekeyBundleBody{}, invalidV2("invalid get body")
	}
	if encoded, present := rawBody["preferred_suite"]; present {
		var preferredSuite string
		if err := json.Unmarshal(encoded, &preferredSuite); err != nil || preferredSuite == "" {
			return V2KeyServiceMetadata{}, V2GetPrekeyBundleBody{}, invalidV2("preferred_suite must be a non-empty string")
		}
	}
	if encoded, present := rawBody["require_opk"]; present && bytes.Equal(bytes.TrimSpace(encoded), []byte("null")) {
		return V2KeyServiceMetadata{}, V2GetPrekeyBundleBody{}, invalidV2("require_opk must be omitted rather than null")
	}
	var body V2GetPrekeyBundleBody
	if err := decodeRaw(params.Body, &body); err != nil {
		return V2KeyServiceMetadata{}, V2GetPrekeyBundleBody{}, err
	}
	if _, err := GetPrekeyBundleRequestV2(params.Meta, body); err != nil {
		return V2KeyServiceMetadata{}, V2GetPrekeyBundleBody{}, err
	}
	return params.Meta, body, nil
}

func DirectSendRequestV2(meta V2DirectMetadata, body any) (map[string]any, error) {
	if err := meta.Validate(); err != nil {
		return nil, err
	}
	switch typed := body.(type) {
	case V2DirectInitBody:
		if meta.ContentType != ContentTypeDirectInitV2 {
			return nil, invalidV2("init body/content_type mismatch")
		}
		if err := typed.Validate(); err != nil {
			return nil, err
		}
	case V2DirectCipherBody:
		if meta.ContentType != ContentTypeDirectCipherV2 {
			return nil, invalidV2("cipher body/content_type mismatch")
		}
		if err := typed.Validate(); err != nil {
			return nil, err
		}
	default:
		return nil, invalidV2("unsupported direct body")
	}
	return requestMap("direct.send", meta, body)
}

func ParseDirectSendRequestV2(value any) (V2DirectMetadata, any, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return V2DirectMetadata{}, nil, err
	}
	var request v2Request
	if err := decodeRaw(encoded, &request); err != nil {
		return V2DirectMetadata{}, nil, err
	}
	if request.Method != "direct.send" {
		return V2DirectMetadata{}, nil, invalidV2("wrong direct.send method")
	}
	var params v2DirectParams
	if err := decodeRaw(request.Params, &params); err != nil {
		return V2DirectMetadata{}, nil, err
	}
	if err := params.Meta.Validate(); err != nil {
		return V2DirectMetadata{}, nil, err
	}
	var body any
	if params.Meta.ContentType == ContentTypeDirectInitV2 {
		var rawBody map[string]json.RawMessage
		if err := json.Unmarshal(params.Body, &rawBody); err != nil {
			return V2DirectMetadata{}, nil, invalidV2("invalid direct init body")
		}
		if encoded, present := rawBody["recipient_one_time_prekey_id"]; present {
			var oneTimePrekeyID string
			if err := json.Unmarshal(encoded, &oneTimePrekeyID); err != nil || oneTimePrekeyID == "" {
				return V2DirectMetadata{}, nil, invalidV2("recipient_one_time_prekey_id must be omitted or a non-empty string")
			}
		}
		var typed V2DirectInitBody
		if err := decodeRaw(params.Body, &typed); err != nil {
			return V2DirectMetadata{}, nil, err
		}
		body = typed
	} else {
		var rawBody map[string]json.RawMessage
		if err := json.Unmarshal(params.Body, &rawBody); err != nil {
			return V2DirectMetadata{}, nil, invalidV2("invalid direct cipher body")
		}
		if encoded, present := rawBody["suite"]; present {
			var suite string
			if err := json.Unmarshal(encoded, &suite); err != nil || suite == "" {
				return V2DirectMetadata{}, nil, invalidV2("suite must be omitted or a non-empty string")
			}
		}
		var typed V2DirectCipherBody
		if err := decodeRaw(params.Body, &typed); err != nil {
			return V2DirectMetadata{}, nil, err
		}
		body = typed
	}
	if _, err := DirectSendRequestV2(params.Meta, body); err != nil {
		return V2DirectMetadata{}, nil, err
	}
	return params.Meta, body, nil
}

func parseKeyRequest(value any) (v2Request, v2KeyParams, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return v2Request{}, v2KeyParams{}, err
	}
	var request v2Request
	if err := decodeRaw(encoded, &request); err != nil {
		return v2Request{}, v2KeyParams{}, err
	}
	var params v2KeyParams
	if err := decodeRaw(request.Params, &params); err != nil {
		return v2Request{}, v2KeyParams{}, err
	}
	if err := params.Meta.Validate(); err != nil {
		return v2Request{}, v2KeyParams{}, err
	}
	return request, params, nil
}

func decodeRaw(value []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return invalidV2(err.Error())
	}
	return nil
}

func requestMap(method string, meta, body any) (map[string]any, error) {
	encoded, err := json.Marshal(map[string]any{"method": method, "params": map[string]any{"meta": meta, "body": body}})
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(encoded, &result); err != nil {
		return nil, err
	}
	return result, nil
}
