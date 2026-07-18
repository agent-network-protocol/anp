package groupe2ee

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

const (
	ProfileV2                                       = "anp.group.e2ee.v2"
	SecurityProfileV2                               = "group-e2ee"
	TransportSecurityProfileV2                      = "transport-protected"
	GroupCipherContentTypeV2                        = "application/anp-group-cipher+json"
	MTISuiteV2                                      = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
	DIDWBADeviceBindingExtensionDraftV2      uint16 = 0xF0A1
	DIDWBADeviceBindingExtensionRegisteredV2        = false
	RFC9421OriginProofSchemeV2                      = "anp-rfc9421-origin-proof-v1"
	MethodPublishKeyPackageV2                       = "group.e2ee.publish_key_package"
	MethodGetKeyPackageV2                           = "group.e2ee.get_key_package"
	MethodGroupCreateV2                             = "group.e2ee.create"
	MethodGroupAddV2                                = "group.e2ee.add"
	MethodGroupRemoveV2                             = "group.e2ee.remove"
	MethodGroupSendV2                               = "group.e2ee.send"
	MethodGroupNoticeV2                             = "group.e2ee.notice"
	MethodGroupIncomingV2                           = "group.incoming"
)

type V2GroupStateRef struct {
	GroupDID          string  `json:"group_did"`
	GroupStateVersion string  `json:"group_state_version"`
	PolicyHash        *string `json:"policy_hash,omitempty"`
	RosterHash        *string `json:"roster_hash,omitempty"`
}

func (value V2GroupStateRef) Validate() error {
	if empty(value.GroupDID) {
		return invalidV2("group_state_ref.group_did must be non-empty")
	}
	if empty(value.GroupStateVersion) {
		return invalidV2("group_state_ref.group_state_version must be non-empty")
	}
	if err := validateOptionalStringV2("group_state_ref.policy_hash", value.PolicyHash); err != nil {
		return err
	}
	return validateOptionalStringV2("group_state_ref.roster_hash", value.RosterHash)
}

type V2Target struct {
	Kind string `json:"kind"`
	DID  string `json:"did"`
}

func (value V2Target) validate(kind string) error {
	if value.Kind != kind {
		return invalidV2(fmt.Sprintf("meta.target.kind must equal %s", kind))
	}
	if empty(value.DID) {
		return invalidV2("meta.target.did must be non-empty")
	}
	return nil
}

type V2ServiceMetadata struct {
	ANPVersion      *string  `json:"anp_version,omitempty"`
	Profile         string   `json:"profile"`
	SecurityProfile string   `json:"security_profile"`
	SenderDID       string   `json:"sender_did"`
	SenderDeviceID  string   `json:"sender_device_id"`
	Target          V2Target `json:"target"`
	OperationID     string   `json:"operation_id"`
	CreatedAt       *string  `json:"created_at,omitempty"`
}

func (value V2ServiceMetadata) Validate(securityProfile string) error {
	return validateCommonMetaV2(value.ANPVersion, value.Profile, value.SecurityProfile, securityProfile,
		value.SenderDID, &value.SenderDeviceID, value.Target, "service", value.OperationID, value.CreatedAt)
}

type V2GroupControlMetadata struct {
	ANPVersion      *string  `json:"anp_version,omitempty"`
	Profile         string   `json:"profile"`
	SecurityProfile string   `json:"security_profile"`
	SenderDID       string   `json:"sender_did"`
	SenderDeviceID  string   `json:"sender_device_id"`
	Target          V2Target `json:"target"`
	OperationID     string   `json:"operation_id"`
	CreatedAt       *string  `json:"created_at,omitempty"`
}

func (value V2GroupControlMetadata) Validate() error {
	return validateCommonMetaV2(value.ANPVersion, value.Profile, value.SecurityProfile, SecurityProfileV2,
		value.SenderDID, &value.SenderDeviceID, value.Target, "group", value.OperationID, value.CreatedAt)
}

type V2GroupSendMetadata struct {
	ANPVersion      *string  `json:"anp_version,omitempty"`
	Profile         string   `json:"profile"`
	SecurityProfile string   `json:"security_profile"`
	SenderDID       string   `json:"sender_did"`
	SenderDeviceID  string   `json:"sender_device_id"`
	Target          V2Target `json:"target"`
	OperationID     string   `json:"operation_id"`
	MessageID       string   `json:"message_id"`
	ContentType     string   `json:"content_type"`
	CreatedAt       *string  `json:"created_at,omitempty"`
}

func (value V2GroupSendMetadata) Validate() error {
	if err := validateCommonMetaV2(value.ANPVersion, value.Profile, value.SecurityProfile, SecurityProfileV2,
		value.SenderDID, &value.SenderDeviceID, value.Target, "group", value.OperationID, value.CreatedAt); err != nil {
		return err
	}
	if empty(value.MessageID) {
		return invalidV2("meta.message_id must be non-empty")
	}
	if value.ContentType != GroupCipherContentTypeV2 {
		return invalidV2("meta.content_type must equal " + GroupCipherContentTypeV2)
	}
	return nil
}

type V2GroupNoticeMetadata struct {
	ANPVersion        *string  `json:"anp_version,omitempty"`
	Profile           string   `json:"profile"`
	SecurityProfile   string   `json:"security_profile"`
	SenderDID         string   `json:"sender_did"`
	Target            V2Target `json:"target"`
	RecipientDeviceID string   `json:"recipient_device_id"`
	OperationID       string   `json:"operation_id"`
	CreatedAt         *string  `json:"created_at,omitempty"`
}

func (value V2GroupNoticeMetadata) Validate() error {
	if err := validateCommonMetaV2(value.ANPVersion, value.Profile, value.SecurityProfile, TransportSecurityProfileV2,
		value.SenderDID, nil, value.Target, "agent", value.OperationID, value.CreatedAt); err != nil {
		return err
	}
	if empty(value.RecipientDeviceID) {
		return invalidV2("meta.recipient_device_id must be non-empty")
	}
	return nil
}

type V2GroupIncomingMetadata struct {
	ANPVersion        *string  `json:"anp_version,omitempty"`
	Profile           string   `json:"profile"`
	SecurityProfile   string   `json:"security_profile"`
	SenderDID         string   `json:"sender_did"`
	SenderDeviceID    string   `json:"sender_device_id"`
	Target            V2Target `json:"target"`
	RecipientDeviceID string   `json:"recipient_device_id"`
	OperationID       string   `json:"operation_id"`
	MessageID         string   `json:"message_id"`
	ContentType       string   `json:"content_type"`
	CreatedAt         *string  `json:"created_at,omitempty"`
}

func (value V2GroupIncomingMetadata) Validate() error {
	if err := validateCommonMetaV2(value.ANPVersion, value.Profile, value.SecurityProfile, SecurityProfileV2,
		value.SenderDID, &value.SenderDeviceID, value.Target, "agent", value.OperationID, value.CreatedAt); err != nil {
		return err
	}
	if empty(value.RecipientDeviceID, value.MessageID) {
		return invalidV2("incoming recipient_device_id and message_id must be non-empty")
	}
	if value.ContentType != GroupCipherContentTypeV2 {
		return invalidV2("meta.content_type must equal " + GroupCipherContentTypeV2)
	}
	return nil
}

type V2OriginProof struct {
	ContentDigest  string `json:"contentDigest"`
	SignatureInput string `json:"signatureInput"`
	Signature      string `json:"signature"`
}

type V2OriginAuth struct {
	Scheme      string        `json:"scheme"`
	OriginProof V2OriginProof `json:"origin_proof"`
}

func (value V2OriginAuth) Validate() error {
	if value.Scheme != RFC9421OriginProofSchemeV2 {
		return invalidV2("auth.scheme must equal " + RFC9421OriginProofSchemeV2)
	}
	if empty(value.OriginProof.ContentDigest, value.OriginProof.SignatureInput, value.OriginProof.Signature) {
		return invalidV2("auth.origin_proof fields must be non-empty")
	}
	return nil
}

type V2ObjectProof struct {
	Type               string `json:"type"`
	Cryptosuite        string `json:"cryptosuite"`
	Created            string `json:"created"`
	ProofPurpose       string `json:"proofPurpose"`
	VerificationMethod string `json:"verificationMethod"`
	ProofValue         string `json:"proofValue"`
}

func (value V2ObjectProof) Validate() error {
	if value.Type != "DataIntegrityProof" || value.Cryptosuite != "eddsa-jcs-2022" || value.ProofPurpose != "assertionMethod" {
		return invalidV2("proof must use the P1 Ed25519 Object Proof profile")
	}
	if _, err := time.Parse(time.RFC3339, value.Created); err != nil {
		return invalidV2("proof.created must be RFC3339")
	}
	if empty(value.VerificationMethod, value.ProofValue) {
		return invalidV2("proof verificationMethod and proofValue must be non-empty")
	}
	return nil
}

type V2DIDWBABinding struct {
	AgentDID             string        `json:"agent_did"`
	DeviceID             string        `json:"device_id"`
	VerificationMethod   string        `json:"verification_method"`
	LeafSignatureKeyB64U string        `json:"leaf_signature_key_b64u"`
	IssuedAt             string        `json:"issued_at"`
	ExpiresAt            string        `json:"expires_at"`
	Proof                V2ObjectProof `json:"proof"`
}

func (value V2DIDWBABinding) ValidateStructure() error {
	if empty(value.AgentDID, value.DeviceID, value.VerificationMethod) {
		return invalidV2("did_wba_binding identity fields must be non-empty")
	}
	if err := validateEd25519B64UV2("did_wba_binding.leaf_signature_key_b64u", value.LeafSignatureKeyB64U); err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339, value.IssuedAt); err != nil {
		return invalidV2("did_wba_binding.issued_at must be RFC3339")
	}
	if _, err := time.Parse(time.RFC3339, value.ExpiresAt); err != nil {
		return invalidV2("did_wba_binding.expires_at must be RFC3339")
	}
	if err := value.Proof.Validate(); err != nil {
		return err
	}
	if value.Proof.VerificationMethod != value.VerificationMethod {
		return invalidV2("proof.verificationMethod must equal did_wba_binding.verification_method")
	}
	return nil
}

type V2GroupKeyPackage struct {
	KeyPackageID      string          `json:"key_package_id"`
	OwnerDID          string          `json:"owner_did"`
	OwnerDeviceID     string          `json:"owner_device_id"`
	Suite             string          `json:"suite"`
	MLSKeyPackageB64U string          `json:"mls_key_package_b64u"`
	DIDWBABinding     V2DIDWBABinding `json:"did_wba_binding"`
	ExpiresAt         *string         `json:"expires_at,omitempty"`
}

func (value V2GroupKeyPackage) ValidateStructure() error {
	if empty(value.KeyPackageID, value.OwnerDID, value.OwnerDeviceID) {
		return invalidV2("group_key_package identifiers must be non-empty")
	}
	if value.Suite != MTISuiteV2 {
		return invalidV2("group_key_package.suite must equal the P6 v2 MTI suite")
	}
	if _, err := decodeB64UV2("group_key_package.mls_key_package_b64u", value.MLSKeyPackageB64U); err != nil {
		return err
	}
	if err := value.DIDWBABinding.ValidateStructure(); err != nil {
		return err
	}
	if value.OwnerDID != value.DIDWBABinding.AgentDID || value.OwnerDeviceID != value.DIDWBABinding.DeviceID {
		return invalidV2("group_key_package owner pair must equal did_wba_binding pair")
	}
	if value.ExpiresAt != nil {
		if _, err := time.Parse(time.RFC3339, *value.ExpiresAt); err != nil {
			return invalidV2("group_key_package.expires_at must be RFC3339")
		}
	}
	return nil
}

type V2GroupCipherObject struct {
	CryptoGroupIDB64U  string          `json:"crypto_group_id_b64u"`
	Epoch              string          `json:"epoch"`
	PrivateMessageB64U string          `json:"private_message_b64u"`
	GroupStateRef      V2GroupStateRef `json:"group_state_ref"`
	EpochAuthenticator *string         `json:"epoch_authenticator,omitempty"`
}

func (value V2GroupCipherObject) Validate() error {
	if _, err := decodeB64UV2("crypto_group_id_b64u", value.CryptoGroupIDB64U); err != nil {
		return err
	}
	if err := validateDecimalV2("epoch", value.Epoch); err != nil {
		return err
	}
	if _, err := decodeB64UV2("private_message_b64u", value.PrivateMessageB64U); err != nil {
		return err
	}
	if err := value.GroupStateRef.Validate(); err != nil {
		return err
	}
	if value.EpochAuthenticator != nil {
		if _, err := decodeB64UV2("epoch_authenticator", *value.EpochAuthenticator); err != nil {
			return err
		}
	}
	return nil
}

type V2GroupApplicationPlaintext struct {
	ApplicationContentType string          `json:"application_content_type"`
	ThreadID               *string         `json:"thread_id,omitempty"`
	ReplyToMessageID       *string         `json:"reply_to_message_id,omitempty"`
	Annotations            *map[string]any `json:"annotations,omitempty"`
	Text                   *string         `json:"text,omitempty"`
	Payload                *map[string]any `json:"payload,omitempty"`
	PayloadB64U            *string         `json:"payload_b64u,omitempty"`
}

func (value V2GroupApplicationPlaintext) Validate() error {
	if empty(value.ApplicationContentType) {
		return invalidV2("application_content_type must be non-empty")
	}
	if err := validateOptionalStringV2("thread_id", value.ThreadID); err != nil {
		return err
	}
	if err := validateOptionalStringV2("reply_to_message_id", value.ReplyToMessageID); err != nil {
		return err
	}
	present := 0
	if value.Text != nil {
		present++
	}
	if value.Payload != nil {
		present++
	}
	if value.PayloadB64U != nil {
		present++
	}
	if present != 1 {
		return invalidV2("exactly one of text, payload, or payload_b64u must be present")
	}
	if value.Text != nil && *value.Text == "" {
		return invalidV2("text must be non-empty")
	}
	if value.PayloadB64U != nil {
		if _, err := decodeB64UV2("payload_b64u", *value.PayloadB64U); err != nil {
			return err
		}
	}
	if value.ApplicationContentType == "text/plain" && value.Text == nil {
		return invalidV2("text/plain plaintext must use text")
	}
	if (value.ApplicationContentType == "application/json" || value.ApplicationContentType == "application/anp-attachment-manifest+json") && value.Payload == nil {
		return invalidV2("JSON group plaintext must use payload")
	}
	return nil
}

type V2E2EENotice struct {
	NoticeID           *string         `json:"notice_id,omitempty"`
	NoticeType         string          `json:"notice_type"`
	GroupDID           string          `json:"group_did"`
	GroupStateRef      V2GroupStateRef `json:"group_state_ref"`
	CryptoGroupIDB64U  string          `json:"crypto_group_id_b64u"`
	Epoch              string          `json:"epoch"`
	SubjectDID         string          `json:"subject_did"`
	SubjectDeviceID    string          `json:"subject_device_id"`
	SubjectStatus      string          `json:"subject_status"`
	CommitB64U         *string         `json:"commit_b64u,omitempty"`
	WelcomeB64U        *string         `json:"welcome_b64u,omitempty"`
	RatchetTreeB64U    *string         `json:"ratchet_tree_b64u,omitempty"`
	EpochAuthenticator *string         `json:"epoch_authenticator,omitempty"`
	GroupReceipt       any             `json:"group_receipt,omitempty"`
}

func (value V2E2EENotice) Validate() error {
	if empty(value.GroupDID, value.SubjectDID, value.SubjectDeviceID) {
		return invalidV2("notice identifiers must be non-empty")
	}
	if err := validateOptionalStringV2("notice_id", value.NoticeID); err != nil {
		return err
	}
	if err := value.GroupStateRef.Validate(); err != nil {
		return err
	}
	if value.GroupStateRef.GroupDID != value.GroupDID {
		return invalidV2("notice group_state_ref.group_did must equal group_did")
	}
	if _, err := decodeB64UV2("crypto_group_id_b64u", value.CryptoGroupIDB64U); err != nil {
		return err
	}
	if err := validateDecimalV2("epoch", value.Epoch); err != nil {
		return err
	}
	if value.SubjectStatus != "active" && value.SubjectStatus != "removed" {
		return invalidV2("subject_status must be active or removed")
	}
	switch value.NoticeType {
	case "commit-delivery":
		if value.CommitB64U == nil {
			return invalidV2("commit_b64u is required")
		}
		if _, err := decodeB64UV2("commit_b64u", *value.CommitB64U); err != nil {
			return err
		}
		if value.WelcomeB64U != nil || value.RatchetTreeB64U != nil {
			return invalidV2("commit-delivery must omit welcome material")
		}
	case "welcome-delivery":
		if value.WelcomeB64U == nil || value.RatchetTreeB64U == nil {
			return invalidV2("welcome-delivery requires welcome_b64u and ratchet_tree_b64u")
		}
		if _, err := decodeB64UV2("welcome_b64u", *value.WelcomeB64U); err != nil {
			return err
		}
		if _, err := decodeB64UV2("ratchet_tree_b64u", *value.RatchetTreeB64U); err != nil {
			return err
		}
		if value.CommitB64U != nil {
			return invalidV2("welcome-delivery must omit commit_b64u")
		}
	default:
		return invalidV2("notice_type must be commit-delivery or welcome-delivery")
	}
	if value.EpochAuthenticator != nil {
		if _, err := decodeB64UV2("epoch_authenticator", *value.EpochAuthenticator); err != nil {
			return err
		}
	}
	if value.GroupReceipt != nil && !isJSONObjectV2(value.GroupReceipt) {
		return invalidV2("group_receipt must be a JSON object")
	}
	return nil
}

type V2PublishKeyPackageBody struct {
	GroupKeyPackage V2GroupKeyPackage `json:"group_key_package"`
}

type V2GetKeyPackageBody struct {
	TargetDID      string  `json:"target_did"`
	TargetDeviceID string  `json:"target_device_id"`
	PreferredSuite *string `json:"preferred_suite,omitempty"`
	RequireFresh   *bool   `json:"require_fresh,omitempty"`
}

func (value V2GetKeyPackageBody) Validate() error {
	if empty(value.TargetDID, value.TargetDeviceID) {
		return invalidV2("target_did and target_device_id must be non-empty")
	}
	if value.PreferredSuite != nil && *value.PreferredSuite != MTISuiteV2 {
		return invalidV2("preferred_suite must equal the P6 v2 MTI suite")
	}
	return nil
}

type V2GroupCreateBody struct {
	GroupDID          string            `json:"group_did"`
	GroupStateRef     V2GroupStateRef   `json:"group_state_ref"`
	Suite             string            `json:"suite"`
	CreatorKeyPackage V2GroupKeyPackage `json:"creator_key_package"`
	CryptoGroupIDB64U string            `json:"crypto_group_id_b64u"`
	Epoch             string            `json:"epoch"`
}

func (value V2GroupCreateBody) Validate() error {
	if empty(value.GroupDID) {
		return invalidV2("group_did must be non-empty")
	}
	if err := value.GroupStateRef.Validate(); err != nil {
		return err
	}
	if value.GroupStateRef.GroupDID != value.GroupDID {
		return invalidV2("group_state_ref.group_did must equal group_did")
	}
	if value.Suite != MTISuiteV2 {
		return invalidV2("suite must equal the P6 v2 MTI suite")
	}
	if err := value.CreatorKeyPackage.ValidateStructure(); err != nil {
		return err
	}
	if _, err := decodeB64UV2("crypto_group_id_b64u", value.CryptoGroupIDB64U); err != nil {
		return err
	}
	return validateDecimalV2("epoch", value.Epoch)
}

type V2GroupAddBody struct {
	MemberDID         string            `json:"member_did"`
	MemberDeviceID    string            `json:"member_device_id"`
	GroupStateRef     V2GroupStateRef   `json:"group_state_ref"`
	GroupKeyPackage   V2GroupKeyPackage `json:"group_key_package"`
	CryptoGroupIDB64U string            `json:"crypto_group_id_b64u"`
	Epoch             string            `json:"epoch"`
	CommitB64U        string            `json:"commit_b64u"`
	WelcomeB64U       string            `json:"welcome_b64u"`
	RatchetTreeB64U   string            `json:"ratchet_tree_b64u"`
}

func (value V2GroupAddBody) Validate() error {
	if empty(value.MemberDID, value.MemberDeviceID) {
		return invalidV2("add member pair must be non-empty")
	}
	if err := value.GroupStateRef.Validate(); err != nil {
		return err
	}
	if err := value.GroupKeyPackage.ValidateStructure(); err != nil {
		return err
	}
	if value.GroupKeyPackage.OwnerDID != value.MemberDID || value.GroupKeyPackage.OwnerDeviceID != value.MemberDeviceID {
		return invalidV2("group_key_package owner must equal add member pair")
	}
	for field, encoded := range map[string]string{"crypto_group_id_b64u": value.CryptoGroupIDB64U, "commit_b64u": value.CommitB64U, "welcome_b64u": value.WelcomeB64U, "ratchet_tree_b64u": value.RatchetTreeB64U} {
		if _, err := decodeB64UV2(field, encoded); err != nil {
			return err
		}
	}
	return validateDecimalV2("epoch", value.Epoch)
}

type V2GroupRemoveBody struct {
	MemberDID         string          `json:"member_did"`
	MemberDeviceID    string          `json:"member_device_id"`
	GroupStateRef     V2GroupStateRef `json:"group_state_ref"`
	CryptoGroupIDB64U string          `json:"crypto_group_id_b64u"`
	Epoch             string          `json:"epoch"`
	CommitB64U        string          `json:"commit_b64u"`
}

func (value V2GroupRemoveBody) Validate() error {
	if empty(value.MemberDID, value.MemberDeviceID) {
		return invalidV2("remove member pair must be non-empty")
	}
	if err := value.GroupStateRef.Validate(); err != nil {
		return err
	}
	if _, err := decodeB64UV2("crypto_group_id_b64u", value.CryptoGroupIDB64U); err != nil {
		return err
	}
	if _, err := decodeB64UV2("commit_b64u", value.CommitB64U); err != nil {
		return err
	}
	return validateDecimalV2("epoch", value.Epoch)
}

type V2GroupIncomingBody struct {
	GroupDID          string              `json:"group_did"`
	GroupStateVersion string              `json:"group_state_version"`
	GroupEventSeq     string              `json:"group_event_seq"`
	AcceptedAt        string              `json:"accepted_at"`
	GroupReceipt      any                 `json:"group_receipt"`
	GroupCipherObject V2GroupCipherObject `json:"group_cipher_object"`
}

func (value V2GroupIncomingBody) Validate() error {
	if empty(value.GroupDID) {
		return invalidV2("group_did must be non-empty")
	}
	if empty(value.GroupStateVersion) {
		return invalidV2("group_state_version must be non-empty")
	}
	if err := validateDecimalV2("group_event_seq", value.GroupEventSeq); err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339, value.AcceptedAt); err != nil {
		return invalidV2("accepted_at must be RFC3339")
	}
	if !isJSONObjectV2(value.GroupReceipt) {
		return invalidV2("group_receipt must be a JSON object")
	}
	if err := value.GroupCipherObject.Validate(); err != nil {
		return err
	}
	if value.GroupCipherObject.GroupStateRef.GroupDID != value.GroupDID || value.GroupCipherObject.GroupStateRef.GroupStateVersion != value.GroupStateVersion {
		return invalidV2("incoming ordering fields must equal group_cipher_object.group_state_ref")
	}
	return nil
}

func validateCommonMetaV2(anpVersion *string, profile, actualSecurity, expectedSecurity, senderDID string, senderDeviceID *string, target V2Target, targetKind, operationID string, createdAt *string) error {
	if profile != ProfileV2 {
		return invalidV2("meta.profile must equal " + ProfileV2)
	}
	if actualSecurity != expectedSecurity {
		return invalidV2("meta.security_profile must equal " + expectedSecurity)
	}
	if empty(senderDID, operationID) {
		return invalidV2("meta sender_did and operation_id must be non-empty")
	}
	if senderDeviceID != nil && *senderDeviceID == "" {
		return invalidV2("meta.sender_device_id must be non-empty")
	}
	if err := target.validate(targetKind); err != nil {
		return err
	}
	if err := validateOptionalStringV2("meta.anp_version", anpVersion); err != nil {
		return err
	}
	if createdAt != nil {
		if _, err := time.Parse(time.RFC3339, *createdAt); err != nil {
			return invalidV2("meta.created_at must be RFC3339")
		}
	}
	return nil
}

func validateOptionalStringV2(field string, value *string) error {
	if value != nil && *value == "" {
		return invalidV2(field + " must be omitted or non-empty")
	}
	return nil
}

func validateDecimalV2(field, value string) error {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return invalidV2(field + " must be a canonical unsigned decimal string")
	}
	for _, char := range []byte(value) {
		if char < '0' || char > '9' {
			return invalidV2(field + " must be a canonical unsigned decimal string")
		}
	}
	return nil
}

func decodeB64UV2(field, value string) ([]byte, error) {
	if value == "" {
		return nil, invalidV2(field + " must be non-empty")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, invalidV2(field + " must be canonical unpadded base64url")
	}
	return decoded, nil
}

func validateEd25519B64UV2(field, value string) error {
	decoded, err := decodeB64UV2(field, value)
	if err != nil {
		return err
	}
	if len(decoded) != 32 {
		return invalidV2(field + " must encode a 32-byte Ed25519 public key")
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

func isJSONObjectV2(value any) bool {
	if value == nil {
		return false
	}
	encoded, err := json.Marshal(value)
	return err == nil && len(encoded) > 0 && encoded[0] == '{'
}
