package groupe2ee

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/authentication"
	"github.com/agent-network-protocol/anp/golang/internal/cjson"
	"github.com/agent-network-protocol/anp/golang/proof"
)

type V2DIDWBABindingUnsigned struct {
	AgentDID             string `json:"agent_did"`
	DeviceID             string `json:"device_id"`
	VerificationMethod   string `json:"verification_method"`
	LeafSignatureKeyB64U string `json:"leaf_signature_key_b64u"`
	IssuedAt             string `json:"issued_at"`
	ExpiresAt            string `json:"expires_at"`
}

func (value V2DIDWBABindingUnsigned) validate() error {
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
	return nil
}

type V2LeafExtension struct {
	ExtensionType uint16
	ExtensionData []byte
}

// V2LeafBindingEvidence is an MLS-parser projection. It does not let the JSON
// convenience object substitute for decoding and verifying a TLS KeyPackage.
type V2LeafBindingEvidence struct {
	CredentialIdentity       []byte
	LeafSignatureKeyB64U     string
	Extensions               []V2LeafExtension
	LeafCapabilityExtensions []uint16
}

// V2KeyPackageBindingEvidence is produced by a cryptographically verified MLS parser.
type V2KeyPackageBindingEvidence struct {
	TLSSerializedKeyPackage []byte
	Leaf                    V2LeafBindingEvidence
}

type V2LeafIdentity struct {
	AgentDID             string
	DeviceID             string
	LeafSignatureKeyB64U string
}

func GenerateDIDWBABindingV2(unsigned V2DIDWBABindingUnsigned, privateKey anp.PrivateKeyMaterial, created string) (V2DIDWBABinding, error) {
	if err := unsigned.validate(); err != nil {
		return V2DIDWBABinding{}, err
	}
	unsignedMap, err := objectMapV2(unsigned)
	if err != nil {
		return V2DIDWBABinding{}, err
	}
	signed, err := proof.GenerateObjectProof(unsignedMap, privateKey, unsigned.VerificationMethod, unsigned.AgentDID, created)
	if err != nil {
		return V2DIDWBABinding{}, err
	}
	encoded, err := json.Marshal(signed)
	if err != nil {
		return V2DIDWBABinding{}, err
	}
	var binding V2DIDWBABinding
	if err := decodeStrictV2(encoded, &binding); err != nil {
		return V2DIDWBABinding{}, err
	}
	if err := binding.ValidateStructure(); err != nil {
		return V2DIDWBABinding{}, err
	}
	return binding, nil
}

func VerifyDIDWBABindingV2(binding V2DIDWBABinding, issuerDocument map[string]any, evidence V2LeafBindingEvidence, groupRequiredExtensions []uint16, now string, p6ProfileNegotiated bool) error {
	if err := binding.ValidateStructure(); err != nil {
		return err
	}
	if !p6ProfileNegotiated {
		return invalidV2("draft MLS binding extension requires explicit anp.group.e2ee.v2 negotiation")
	}
	if documentDID, _ := issuerDocument["id"].(string); documentDID != binding.AgentDID {
		return invalidV2("did_wba_binding.agent_did must equal issuer DID document id")
	}
	device, err := authentication.FindEligibleDevice(issuerDocument, binding.DeviceID, authentication.ProfileGroupE2EEV2)
	if err != nil {
		return err
	}
	if device == nil {
		return invalidV2("did_wba_binding.device_id is not a current P6-eligible Manifest device")
	}
	if device.SigningKeyID != binding.VerificationMethod {
		return invalidV2("did_wba_binding.verification_method must equal Manifest signing_key_id")
	}
	bindingMap, err := objectMapV2(binding)
	if err != nil {
		return err
	}
	if _, err := proof.VerifyObjectProof(bindingMap, binding.AgentDID, issuerDocument); err != nil {
		return err
	}
	if err := validateBindingWindowV2(binding, now); err != nil {
		return err
	}
	if !bytes.Equal(evidence.CredentialIdentity, []byte(binding.AgentDID)) {
		return invalidV2("MLS credential.identity must equal UTF-8 agent_did")
	}
	if err := validateEd25519B64UV2("leaf_signature_key_b64u", evidence.LeafSignatureKeyB64U); err != nil {
		return err
	}
	if evidence.LeafSignatureKeyB64U != binding.LeafSignatureKeyB64U {
		return invalidV2("actual MLS leaf signature key must equal did_wba_binding leaf key")
	}
	var matching []V2LeafExtension
	for _, extension := range evidence.Extensions {
		if extension.ExtensionType == DIDWBADeviceBindingExtensionDraftV2 {
			matching = append(matching, extension)
		}
	}
	if len(matching) != 1 {
		return invalidV2("LeafNode must contain exactly one anp_did_wba_device_binding extension")
	}
	canonical, err := cjson.Marshal(binding)
	if err != nil {
		return err
	}
	if !bytes.Equal(matching[0].ExtensionData, canonical) {
		return invalidV2("embedded MLS binding extension must equal canonical did_wba_binding bytes")
	}
	if err := requireCapabilityOnceV2("LeafNode capabilities.extensions", evidence.LeafCapabilityExtensions); err != nil {
		return err
	}
	return ValidateGroupRequiredCapabilitiesV2(groupRequiredExtensions)
}

func ValidateGroupKeyPackageBindingV2(packageValue V2GroupKeyPackage, issuerDocument map[string]any, evidence V2KeyPackageBindingEvidence, groupRequiredExtensions []uint16, now string, p6ProfileNegotiated bool) error {
	if err := packageValue.ValidateStructure(); err != nil {
		return err
	}
	outerBytes, err := decodeB64UV2("group_key_package.mls_key_package_b64u", packageValue.MLSKeyPackageB64U)
	if err != nil {
		return err
	}
	if !bytes.Equal(outerBytes, evidence.TLSSerializedKeyPackage) {
		return invalidV2("verified TLS KeyPackage bytes must equal mls_key_package_b64u")
	}
	if err := VerifyDIDWBABindingV2(packageValue.DIDWBABinding, issuerDocument, evidence.Leaf, groupRequiredExtensions, now, p6ProfileNegotiated); err != nil {
		return err
	}
	if packageValue.ExpiresAt != nil {
		nowTime, err := time.Parse(time.RFC3339, now)
		if err != nil {
			return invalidV2("now must be RFC3339")
		}
		expires, err := time.Parse(time.RFC3339, *packageValue.ExpiresAt)
		if err != nil {
			return invalidV2("group_key_package.expires_at must be RFC3339")
		}
		if !nowTime.Before(expires) {
			return invalidV2("group_key_package is expired")
		}
	}
	return nil
}

func ValidateGroupRequiredCapabilitiesV2(extensions []uint16) error {
	return requireCapabilityOnceV2("GroupContext required_capabilities", extensions)
}

func ValidateLeafIdentitySetV2(leaves []V2LeafIdentity) error {
	pairs := make(map[string]struct{}, len(leaves))
	keys := make(map[string]struct{}, len(leaves))
	for _, leaf := range leaves {
		if empty(leaf.AgentDID, leaf.DeviceID) {
			return invalidV2("leaf identity fields must be non-empty")
		}
		if err := validateEd25519B64UV2("leaf.leaf_signature_key_b64u", leaf.LeafSignatureKeyB64U); err != nil {
			return err
		}
		pair := leaf.AgentDID + "\x00" + leaf.DeviceID
		if _, exists := pairs[pair]; exists {
			return invalidV2("each (agent_did, device_id) leaf identity must be unique")
		}
		pairs[pair] = struct{}{}
		if _, exists := keys[leaf.LeafSignatureKeyB64U]; exists {
			return invalidV2("each device leaf must use a distinct MLS signature key")
		}
		keys[leaf.LeafSignatureKeyB64U] = struct{}{}
	}
	return nil
}

func EnsureP6V2PublicReleaseReady() error {
	if DIDWBADeviceBindingExtensionRegisteredV2 {
		return nil
	}
	return ErrP6V2PublicReleaseBlocked
}

func validateBindingWindowV2(binding V2DIDWBABinding, now string) error {
	nowTime, err := time.Parse(time.RFC3339, now)
	if err != nil {
		return invalidV2("now must be RFC3339")
	}
	issued, err := time.Parse(time.RFC3339, binding.IssuedAt)
	if err != nil {
		return invalidV2("did_wba_binding.issued_at must be RFC3339")
	}
	expires, err := time.Parse(time.RFC3339, binding.ExpiresAt)
	if err != nil {
		return invalidV2("did_wba_binding.expires_at must be RFC3339")
	}
	if !issued.Before(expires) {
		return invalidV2("did_wba_binding issued_at must precede expires_at")
	}
	if nowTime.Before(issued) || !nowTime.Before(expires) {
		return invalidV2("did_wba_binding is not valid at the requested time")
	}
	return nil
}

func requireCapabilityOnceV2(field string, extensions []uint16) error {
	count := 0
	for _, extension := range extensions {
		if extension == DIDWBADeviceBindingExtensionDraftV2 {
			count++
		}
	}
	if count != 1 {
		return invalidV2(fmt.Sprintf("%s must list the draft binding extension exactly once", field))
	}
	return nil
}

func objectMapV2(value any) (map[string]any, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(encoded, &result); err != nil {
		return nil, err
	}
	return result, nil
}
