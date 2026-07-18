package directe2ee

import (
	"time"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/authentication"
	"github.com/agent-network-protocol/anp/golang/internal/cjson"
	"github.com/agent-network-protocol/anp/golang/proof"
)

func BuildPrekeyBundleV2(bundleID, ownerDID, ownerDeviceID, staticKeyAgreementID string, signedPrekey V2SignedPrekey, signingPrivateKey anp.PrivateKeyMaterial, verificationMethod, created string) (V2PrekeyBundle, error) {
	if err := signedPrekey.Validate(); err != nil {
		return V2PrekeyBundle{}, err
	}
	unsigned := map[string]any{
		"bundle_id": bundleID, "owner_did": ownerDID, "owner_device_id": ownerDeviceID,
		"suite": MTIDirectE2EESuiteV2, "static_key_agreement_id": staticKeyAgreementID,
		"signed_prekey": signedPrekey,
	}
	signed, err := proof.GenerateObjectProof(unsigned, signingPrivateKey, verificationMethod, ownerDID, created)
	if err != nil {
		return V2PrekeyBundle{}, err
	}
	proofValue, ok := signed["proof"].(map[string]any)
	if !ok {
		return V2PrekeyBundle{}, invalidV2("generated bundle has no proof")
	}
	bundle := V2PrekeyBundle{
		BundleID: bundleID, OwnerDID: ownerDID, OwnerDeviceID: ownerDeviceID,
		Suite: MTIDirectE2EESuiteV2, StaticKeyAgreementID: staticKeyAgreementID,
		SignedPrekey: signedPrekey, Proof: proofValue,
	}
	if err := bundle.ValidateStructure(); err != nil {
		return V2PrekeyBundle{}, err
	}
	return bundle, nil
}

func SignedBundleObjectJCSV2(bundle V2PrekeyBundle) ([]byte, error) {
	value := v2BundleMap(bundle)
	delete(value, "proof")
	return cjson.Marshal(value)
}

func VerifyPrekeyBundleV2(bundle V2PrekeyBundle, didDocument map[string]any, now time.Time) error {
	if err := bundle.ValidateStructure(); err != nil {
		return err
	}
	if stringValue(didDocument["id"]) != bundle.OwnerDID {
		return invalidV2("owner_did mismatch")
	}
	device, err := authentication.FindEligibleDevice(didDocument, bundle.OwnerDeviceID, authentication.ProfileDirectE2EEV2)
	if err != nil {
		return invalidV2("invalid owner Device Manifest")
	}
	if device == nil {
		return invalidV2("owner device is not P5 v2 eligible")
	}
	if device.E2EEKeyID != bundle.StaticKeyAgreementID {
		return invalidV2("static key does not match device e2ee_key_id")
	}
	if stringValue(bundle.Proof["verificationMethod"]) != device.SigningKeyID {
		return invalidV2("proof key does not match device signing_key_id")
	}
	expiresAt, err := time.Parse(time.RFC3339, bundle.SignedPrekey.ExpiresAt)
	if err != nil {
		return invalidV2("signed_prekey.expires_at must be RFC3339")
	}
	if !expiresAt.After(now) {
		return invalidV2("signed prekey is expired")
	}
	if _, err := proof.VerifyObjectProof(v2BundleMap(bundle), bundle.OwnerDID, didDocument); err != nil {
		return invalidV2("bundle Object Proof is invalid")
	}
	return nil
}

func V2KeyServiceMeta(senderDID, senderDeviceID, serviceDID, operationID string) V2KeyServiceMetadata {
	return V2KeyServiceMetadata{
		Profile: DirectE2EEProfileV2, SecurityProfile: TransportProtectedSecurityProfile,
		SenderDID: senderDID, SenderDeviceID: senderDeviceID,
		Target: V2Target{Kind: "service", DID: serviceDID}, OperationID: operationID,
	}
}

func v2BundleMap(bundle V2PrekeyBundle) map[string]any {
	return map[string]any{
		"bundle_id": bundle.BundleID, "owner_did": bundle.OwnerDID,
		"owner_device_id": bundle.OwnerDeviceID, "suite": bundle.Suite,
		"static_key_agreement_id": bundle.StaticKeyAgreementID,
		"signed_prekey":           bundle.SignedPrekey, "proof": bundle.Proof,
	}
}
