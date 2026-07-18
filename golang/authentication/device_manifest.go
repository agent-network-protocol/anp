package authentication

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strings"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/internal/base58util"
)

const (
	DeviceManifestType         = "ANPDeviceManifest"
	ProfileCoreBindingV2       = "anp.core.binding.v2"
	ProfileIdentityDiscoveryV2 = "anp.identity.discovery.v2"
	ProfileDirectBaseV2        = "anp.direct.base.v2"
	ProfileGroupBaseV2         = "anp.group.base.v2"
	ProfileDirectE2EEV2        = "anp.direct.e2ee.v2"
	ProfileGroupE2EEV2         = "anp.group.e2ee.v2"
)

var (
	manifestFields = map[string]struct{}{"type": {}, "devices": {}}
	entryFields    = map[string]struct{}{
		"device_id": {}, "signing_key_id": {}, "e2ee_key_id": {}, "profiles": {},
	}
	p5Dependencies = map[string]struct{}{
		ProfileCoreBindingV2: {}, ProfileIdentityDiscoveryV2: {},
		ProfileDirectBaseV2: {}, ProfileDirectE2EEV2: {},
	}
	p6Dependencies = map[string]struct{}{
		ProfileCoreBindingV2: {}, ProfileIdentityDiscoveryV2: {},
		ProfileGroupBaseV2: {}, ProfileGroupE2EEV2: {},
	}
	jsonNumberPattern = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$`)
)

type publicKeyAlgorithm string

const (
	publicKeyEd25519   publicKeyAlgorithm = "Ed25519"
	publicKeyX25519    publicKeyAlgorithm = "X25519"
	publicKeyP256      publicKeyAlgorithm = "P-256"
	publicKeySecp256k1 publicKeyAlgorithm = "secp256k1"
)

type publicKeyIdentity struct {
	algorithm    publicKeyAlgorithm
	rawPublicKey []byte
}

// DeviceManifestEntry is one public cryptographic device endpoint.
type DeviceManifestEntry struct {
	DeviceID     string   `json:"device_id"`
	SigningKeyID string   `json:"signing_key_id"`
	E2EEKeyID    string   `json:"e2ee_key_id"`
	Profiles     []string `json:"profiles"`
}

// DeviceManifest is the typed value of a DID document deviceManifest extension.
type DeviceManifest struct {
	Type    string                `json:"type"`
	Devices []DeviceManifestEntry `json:"devices"`
}

// ToMap serializes the closed Device Manifest without changing its DID document.
func (manifest DeviceManifest) ToMap() map[string]any {
	devices := make([]any, 0, len(manifest.Devices))
	for _, device := range manifest.Devices {
		profiles := make([]any, 0, len(device.Profiles))
		for _, profile := range device.Profiles {
			profiles = append(profiles, profile)
		}
		devices = append(devices, map[string]any{
			"device_id":      device.DeviceID,
			"signing_key_id": device.SigningKeyID,
			"e2ee_key_id":    device.E2EEKeyID,
			"profiles":       profiles,
		})
	}
	return map[string]any{"type": manifest.Type, "devices": devices}
}

// ParseDeviceManifest parses the optional, closed vNext Device Manifest schema.
// Unknown members elsewhere in didDocument are not interpreted or modified.
func ParseDeviceManifest(didDocument map[string]any) (*DeviceManifest, error) {
	rawManifest, exists := didDocument["deviceManifest"]
	if !exists {
		return nil, nil
	}
	manifestMap, err := cloneJSONObject(rawManifest, "deviceManifest")
	if err != nil {
		return nil, fmt.Errorf("deviceManifest must be an object")
	}
	if err := requireExactFields(manifestMap, manifestFields, "deviceManifest"); err != nil {
		return nil, err
	}
	manifestType, ok := manifestMap["type"].(string)
	if !ok || manifestType != DeviceManifestType {
		return nil, fmt.Errorf("deviceManifest.type must equal %s", DeviceManifestType)
	}

	rawDevices, err := jsonArray(manifestMap["devices"])
	if err != nil {
		return nil, fmt.Errorf("deviceManifest.devices must be an array")
	}
	devices := make([]DeviceManifestEntry, 0, len(rawDevices))
	for index, rawEntry := range rawDevices {
		entry, ok := rawEntry.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("deviceManifest.devices[%d] must be an object", index)
		}
		if err := requireExactFields(entry, entryFields, fmt.Sprintf("deviceManifest.devices[%d]", index)); err != nil {
			return nil, err
		}
		deviceID, deviceOK := entry["device_id"].(string)
		signingKeyID, signingOK := entry["signing_key_id"].(string)
		e2eeKeyID, e2eeOK := entry["e2ee_key_id"].(string)
		if !deviceOK || !signingOK || !e2eeOK {
			return nil, fmt.Errorf("deviceManifest.devices[%d] key fields must be strings", index)
		}
		rawProfiles, err := jsonArray(entry["profiles"])
		if err != nil {
			return nil, fmt.Errorf("deviceManifest.devices[%d].profiles must be an array", index)
		}
		profiles := make([]string, 0, len(rawProfiles))
		for profileIndex, rawProfile := range rawProfiles {
			profile, ok := rawProfile.(string)
			if !ok {
				return nil, fmt.Errorf(
					"deviceManifest.devices[%d].profiles[%d] must be a string",
					index,
					profileIndex,
				)
			}
			profiles = append(profiles, profile)
		}
		devices = append(devices, DeviceManifestEntry{
			DeviceID: deviceID, SigningKeyID: signingKeyID,
			E2EEKeyID: e2eeKeyID, Profiles: profiles,
		})
	}
	return &DeviceManifest{Type: manifestType, Devices: devices}, nil
}

// ValidateDeviceManifest parses and validates references, relationships, and dependencies.
func ValidateDeviceManifest(didDocument map[string]any) (*DeviceManifest, error) {
	manifest, err := ParseDeviceManifest(didDocument)
	if err != nil || manifest == nil {
		return manifest, err
	}
	did, ok := didDocument["id"].(string)
	if !ok || did == "" {
		return nil, fmt.Errorf("DID document id must be a non-empty string")
	}

	methods, err := jsonArray(didDocument["verificationMethod"])
	if err != nil {
		return nil, fmt.Errorf("DID document verificationMethod must be an array")
	}
	methodsByID := make(map[string][]map[string]any)
	for _, rawMethod := range methods {
		method, ok := rawMethod.(map[string]any)
		if !ok {
			continue
		}
		methodID, ok := method["id"].(string)
		if ok {
			methodsByID[methodID] = append(methodsByID[methodID], method)
		}
	}

	seenDevices := make(map[string]struct{})
	seenKeys := make(map[string]struct{})
	for index, device := range manifest.Devices {
		if device.DeviceID == "" || device.SigningKeyID == "" || device.E2EEKeyID == "" {
			return nil, fmt.Errorf("deviceManifest.devices[%d] string fields must be non-empty", index)
		}
		if len(device.Profiles) == 0 {
			return nil, fmt.Errorf("deviceManifest.devices[%d].profiles must be non-empty", index)
		}
		for _, profile := range device.Profiles {
			if profile == "" {
				return nil, fmt.Errorf("deviceManifest.devices[%d].profiles contains an empty value", index)
			}
		}
		if _, exists := seenDevices[device.DeviceID]; exists {
			return nil, fmt.Errorf("device_id must be unique")
		}
		seenDevices[device.DeviceID] = struct{}{}
		if device.SigningKeyID == device.E2EEKeyID {
			return nil, fmt.Errorf("signing_key_id and e2ee_key_id must be distinct")
		}
		for _, keyID := range []string{device.SigningKeyID, device.E2EEKeyID} {
			if _, exists := seenKeys[keyID]; exists {
				return nil, fmt.Errorf("a verification method can belong to only one device entry")
			}
			seenKeys[keyID] = struct{}{}
			if err := validateSameDocumentMethod(did, keyID, methodsByID); err != nil {
				return nil, err
			}
		}

		profiles := stringSet(device.Profiles)
		if _, supportsP5 := profiles[ProfileDirectE2EEV2]; supportsP5 {
			if err := requireDependencies(profiles, p5Dependencies, "P5"); err != nil {
				return nil, err
			}
			if !relationshipContains(didDocument, "assertionMethod", device.SigningKeyID) {
				return nil, fmt.Errorf("P5 signing key is not authorized by assertionMethod")
			}
		}
		if _, supportsP6 := profiles[ProfileGroupE2EEV2]; supportsP6 {
			if err := requireDependencies(profiles, p6Dependencies, "P6"); err != nil {
				return nil, err
			}
			if !relationshipContains(didDocument, "assertionMethod", device.SigningKeyID) {
				return nil, fmt.Errorf("P6 binding key is not authorized by assertionMethod")
			}
			if !relationshipContains(didDocument, "authentication", device.SigningKeyID) {
				return nil, fmt.Errorf("P6 origin-proof key is not authorized by authentication")
			}
		}
		if !relationshipContains(didDocument, "keyAgreement", device.E2EEKeyID) {
			return nil, fmt.Errorf("device E2EE key is not authorized by keyAgreement")
		}
	}
	return manifest, nil
}

// FindEligibleDevice returns a validated device that declares requiredProfile.
func FindEligibleDevice(didDocument map[string]any, deviceID string, requiredProfile string) (*DeviceManifestEntry, error) {
	manifest, err := ValidateDeviceManifest(didDocument)
	if err != nil || manifest == nil {
		return nil, err
	}
	if requiredProfile != ProfileDirectE2EEV2 && requiredProfile != ProfileGroupE2EEV2 {
		return nil, nil
	}
	for index := range manifest.Devices {
		device := &manifest.Devices[index]
		if device.DeviceID == deviceID && containsString(device.Profiles, requiredProfile) {
			return device, nil
		}
	}
	return nil, nil
}

func requireExactFields(value map[string]any, expected map[string]struct{}, subject string) error {
	if len(value) != len(expected) {
		return fmt.Errorf("%s has unexpected or missing members", subject)
	}
	for field := range value {
		if _, ok := expected[field]; !ok {
			return fmt.Errorf("%s has unexpected or missing members", subject)
		}
	}
	return nil
}

func jsonArray(value any) ([]any, error) {
	cloned, err := cloneStrictJSONValue(value, "JSON array")
	if err != nil {
		return nil, err
	}
	values, ok := cloned.([]any)
	if !ok || values == nil {
		return nil, fmt.Errorf("value is not an array")
	}
	return values, nil
}

func validateSameDocumentMethod(did string, keyID string, methodsByID map[string][]map[string]any) error {
	if !strings.HasPrefix(keyID, did+"#") || keyID == did+"#" {
		return fmt.Errorf("device key IDs must be DID URLs in the same DID document")
	}
	methods := methodsByID[keyID]
	if len(methods) != 1 {
		return fmt.Errorf("device key ID must resolve exactly once in verificationMethod")
	}
	return nil
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func requireDependencies(actual map[string]struct{}, required map[string]struct{}, name string) error {
	for dependency := range required {
		if _, ok := actual[dependency]; !ok {
			return fmt.Errorf("%s device profile dependencies are incomplete", name)
		}
	}
	return nil
}

func relationshipContains(didDocument map[string]any, relationship string, keyID string) bool {
	entries, err := jsonArray(didDocument[relationship])
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if value, ok := entry.(string); ok && value == keyID {
			return true
		}
		if value, ok := entry.(map[string]any); ok && value["id"] == keyID {
			return true
		}
	}
	return false
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

// BuildVNextDIDDocument builds an unsigned vNext DID document from public key
// material only. The caller must root-sign the result before publishing it.
func BuildVNextDIDDocument(
	baseDocument map[string]any,
	rootKeyID string,
	rootVerificationMethod map[string]any,
	device DeviceManifestEntry,
	deviceSigningVerificationMethod map[string]any,
	deviceE2EEVerificationMethod map[string]any,
) (map[string]any, error) {
	document, err := cloneDIDJSONObject(baseDocument)
	if err != nil {
		return nil, err
	}
	for _, field := range []string{
		"verificationMethod", "authentication", "assertionMethod",
		"keyAgreement", "deviceManifest", "proof",
	} {
		if _, exists := document[field]; exists {
			return nil, fmt.Errorf("base DID document must not contain managed field %s", field)
		}
	}
	did, err := documentDID(document)
	if err != nil {
		return nil, err
	}
	if _, err := validateRootMethod(did, rootKeyID, rootVerificationMethod); err != nil {
		return nil, err
	}
	if _, _, err := validateDeviceMethods(
		did,
		rootKeyID,
		device,
		deviceSigningVerificationMethod,
		deviceE2EEVerificationMethod,
	); err != nil {
		return nil, err
	}
	rootMethod, err := cloneJSONMapValue(rootVerificationMethod)
	if err != nil {
		return nil, err
	}
	signingMethod, err := cloneJSONMapValue(deviceSigningVerificationMethod)
	if err != nil {
		return nil, err
	}
	e2eeMethod, err := cloneJSONMapValue(deviceE2EEVerificationMethod)
	if err != nil {
		return nil, err
	}
	document["verificationMethod"] = []any{rootMethod, signingMethod, e2eeMethod}
	document["authentication"] = []any{device.SigningKeyID}
	document["assertionMethod"] = []any{rootKeyID, device.SigningKeyID}
	document["keyAgreement"] = []any{device.E2EEKeyID}
	document["deviceManifest"] = DeviceManifest{
		Type: DeviceManifestType, Devices: []DeviceManifestEntry{device},
	}.ToMap()
	if err := validateVNextDIDDocument(document, rootKeyID); err != nil {
		return nil, err
	}
	return document, nil
}

// AddDeviceToDIDDocument adds one device to a validated document and returns
// an unsigned copy.
func AddDeviceToDIDDocument(
	didDocument map[string]any,
	rootKeyID string,
	device DeviceManifestEntry,
	deviceSigningVerificationMethod map[string]any,
	deviceE2EEVerificationMethod map[string]any,
	retiredDeviceIDs []string,
) (map[string]any, error) {
	document, err := prepareDIDDocumentForMutation(didDocument, rootKeyID)
	if err != nil {
		return nil, err
	}
	manifest, err := ValidateDeviceManifest(document)
	if err != nil {
		return nil, err
	}
	if manifest == nil {
		return nil, fmt.Errorf("deviceManifest is required for device update")
	}
	for _, current := range manifest.Devices {
		if current.DeviceID == device.DeviceID {
			return nil, fmt.Errorf("device_id already exists")
		}
	}
	if err := validateRetiredDeviceIDs(retiredDeviceIDs); err != nil {
		return nil, err
	}
	for _, retiredDeviceID := range retiredDeviceIDs {
		if retiredDeviceID == device.DeviceID {
			return nil, fmt.Errorf("retired device_id cannot be reused")
		}
	}
	if err := appendDeviceMaterial(
		document,
		rootKeyID,
		device,
		deviceSigningVerificationMethod,
		deviceE2EEVerificationMethod,
	); err != nil {
		return nil, err
	}
	if err := validateVNextDIDDocument(document, rootKeyID); err != nil {
		return nil, err
	}
	return document, nil
}

// UpdateDeviceInDIDDocument replaces one device's public keys and Profile
// entry in an unsigned copy.
func UpdateDeviceInDIDDocument(
	didDocument map[string]any,
	rootKeyID string,
	device DeviceManifestEntry,
	deviceSigningVerificationMethod map[string]any,
	deviceE2EEVerificationMethod map[string]any,
) (map[string]any, error) {
	document, err := prepareDIDDocumentForMutation(didDocument, rootKeyID)
	if err != nil {
		return nil, err
	}
	manifest, err := ValidateDeviceManifest(document)
	if err != nil {
		return nil, err
	}
	if manifest == nil {
		return nil, fmt.Errorf("deviceManifest is required for device update")
	}
	var oldEntry *DeviceManifestEntry
	for index := range manifest.Devices {
		if manifest.Devices[index].DeviceID == device.DeviceID {
			entry := manifest.Devices[index]
			oldEntry = &entry
			break
		}
	}
	if oldEntry == nil {
		return nil, fmt.Errorf("device_id does not exist")
	}
	if err := removeDeviceMaterial(document, *oldEntry); err != nil {
		return nil, err
	}
	if err := appendDeviceMaterial(
		document,
		rootKeyID,
		device,
		deviceSigningVerificationMethod,
		deviceE2EEVerificationMethod,
	); err != nil {
		return nil, err
	}
	if err := validateVNextDIDDocument(document, rootKeyID); err != nil {
		return nil, err
	}
	return document, nil
}

// RemoveDeviceFromDIDDocument removes one device and its active key
// references from an unsigned copy.
func RemoveDeviceFromDIDDocument(
	didDocument map[string]any,
	rootKeyID string,
	deviceID string,
) (map[string]any, error) {
	document, err := prepareDIDDocumentForMutation(didDocument, rootKeyID)
	if err != nil {
		return nil, err
	}
	manifest, err := ValidateDeviceManifest(document)
	if err != nil {
		return nil, err
	}
	if manifest == nil {
		return nil, fmt.Errorf("deviceManifest is required for device update")
	}
	var oldEntry *DeviceManifestEntry
	for index := range manifest.Devices {
		if manifest.Devices[index].DeviceID == deviceID {
			entry := manifest.Devices[index]
			oldEntry = &entry
			break
		}
	}
	if oldEntry == nil {
		return nil, fmt.Errorf("device_id does not exist")
	}
	if err := removeDeviceMaterial(document, *oldEntry); err != nil {
		return nil, err
	}
	if err := validateVNextDIDDocument(document, rootKeyID); err != nil {
		return nil, err
	}
	return document, nil
}

func prepareDIDDocumentForMutation(didDocument map[string]any, rootKeyID string) (map[string]any, error) {
	if err := validateVNextDIDDocument(didDocument, rootKeyID); err != nil {
		return nil, err
	}
	document, err := cloneDIDJSONObject(didDocument)
	if err != nil {
		return nil, err
	}
	// Any existing proof is stale after mutation. Requiring the caller to sign
	// again is safer than returning a document that looks publishable.
	delete(document, "proof")
	return document, nil
}

func validateVNextDIDDocument(didDocument map[string]any, rootKeyID string) error {
	if err := rejectPrivateKeyMaterial(didDocument, "DID document"); err != nil {
		return err
	}
	did, err := documentDID(didDocument)
	if err != nil {
		return err
	}
	methods, err := jsonArray(didDocument["verificationMethod"])
	if err != nil {
		return fmt.Errorf("DID document verificationMethod must be an array")
	}
	rootMethods := make([]map[string]any, 0, 1)
	for _, rawMethod := range methods {
		method, ok := rawMethod.(map[string]any)
		if ok && method["id"] == rootKeyID {
			rootMethods = append(rootMethods, method)
		}
	}
	if len(rootMethods) != 1 {
		return fmt.Errorf("root key must resolve exactly once in verificationMethod")
	}
	rootIdentity, err := validateRootMethod(did, rootKeyID, rootMethods[0])
	if err != nil {
		return err
	}
	if !relationshipContains(didDocument, "assertionMethod", rootKeyID) {
		return fmt.Errorf("DID root key is not authorized by assertionMethod")
	}
	manifest, err := ValidateDeviceManifest(didDocument)
	if err != nil {
		return err
	}
	if manifest == nil {
		return fmt.Errorf("deviceManifest is required")
	}
	seenMaterial := [][]byte{rootIdentity.rawPublicKey}
	for _, device := range manifest.Devices {
		if device.SigningKeyID == rootKeyID || device.E2EEKeyID == rootKeyID {
			return fmt.Errorf("DID root key cannot be a device key")
		}
		signingMethod, err := uniqueVerificationMethod(didDocument, device.SigningKeyID)
		if err != nil {
			return err
		}
		e2eeMethod, err := uniqueVerificationMethod(didDocument, device.E2EEKeyID)
		if err != nil {
			return err
		}
		signingIdentity, e2eeIdentity, err := validateDeviceMethods(
			did,
			rootKeyID,
			device,
			signingMethod,
			e2eeMethod,
		)
		if err != nil {
			return err
		}
		for relationship, keyID := range map[string]string{
			"authentication":  device.SigningKeyID,
			"assertionMethod": device.SigningKeyID,
			"keyAgreement":    device.E2EEKeyID,
		} {
			if !relationshipContains(didDocument, relationship, keyID) {
				return fmt.Errorf("device key is not authorized by %s", relationship)
			}
		}
		if relationshipContains(didDocument, "keyAgreement", device.SigningKeyID) {
			return fmt.Errorf("device signing key must not be in keyAgreement")
		}
		if relationshipContains(didDocument, "authentication", device.E2EEKeyID) ||
			relationshipContains(didDocument, "assertionMethod", device.E2EEKeyID) {
			return fmt.Errorf("device E2EE key must not be a signing relationship")
		}
		for _, identity := range []publicKeyIdentity{signingIdentity, e2eeIdentity} {
			for _, existing := range seenMaterial {
				if bytes.Equal(existing, identity.rawPublicKey) {
					return fmt.Errorf("root and device public key material must be unique")
				}
			}
			seenMaterial = append(seenMaterial, identity.rawPublicKey)
		}
	}
	return nil
}

func documentDID(document map[string]any) (string, error) {
	did, ok := document["id"].(string)
	if !ok || did == "" {
		return "", fmt.Errorf("DID document id must be a non-empty string")
	}
	return did, nil
}

func validateRootMethod(
	did string,
	rootKeyID string,
	method map[string]any,
) (publicKeyIdentity, error) {
	identity, err := validatePublicMethod(did, rootKeyID, method, "DID root verification method")
	if err != nil {
		return publicKeyIdentity{}, err
	}
	if identity.algorithm == publicKeyX25519 {
		return publicKeyIdentity{}, fmt.Errorf("DID root verification method must be signing-capable")
	}
	return identity, nil
}

func validateDeviceMethods(
	did string,
	rootKeyID string,
	device DeviceManifestEntry,
	signingMethod map[string]any,
	e2eeMethod map[string]any,
) (publicKeyIdentity, publicKeyIdentity, error) {
	if device.SigningKeyID == rootKeyID || device.E2EEKeyID == rootKeyID {
		return publicKeyIdentity{}, publicKeyIdentity{}, fmt.Errorf("DID root key cannot be a device key")
	}
	signingIdentity, err := validatePublicMethod(
		did,
		device.SigningKeyID,
		signingMethod,
		"device signing verification method",
	)
	if err != nil {
		return publicKeyIdentity{}, publicKeyIdentity{}, err
	}
	requiresEdDSA := containsString(device.Profiles, ProfileDirectE2EEV2) ||
		containsString(device.Profiles, ProfileGroupE2EEV2)
	if signingIdentity.algorithm == publicKeyX25519 ||
		(requiresEdDSA && signingIdentity.algorithm != publicKeyEd25519) {
		return publicKeyIdentity{}, publicKeyIdentity{}, fmt.Errorf(
			"device signing verification method uses the wrong key algorithm",
		)
	}
	e2eeIdentity, err := validatePublicMethod(
		did,
		device.E2EEKeyID,
		e2eeMethod,
		"device E2EE verification method",
	)
	if err != nil {
		return publicKeyIdentity{}, publicKeyIdentity{}, err
	}
	if e2eeIdentity.algorithm != publicKeyX25519 {
		return publicKeyIdentity{}, publicKeyIdentity{}, fmt.Errorf(
			"device E2EE verification method uses the wrong key algorithm",
		)
	}
	if bytes.Equal(signingIdentity.rawPublicKey, e2eeIdentity.rawPublicKey) {
		return publicKeyIdentity{}, publicKeyIdentity{}, fmt.Errorf(
			"device key material must be unique across roles",
		)
	}
	return signingIdentity, e2eeIdentity, nil
}

func validatePublicMethod(
	did string,
	expectedKeyID string,
	method map[string]any,
	subject string,
) (publicKeyIdentity, error) {
	normalizedMethod, err := cloneJSONMapValue(method)
	if err != nil {
		return publicKeyIdentity{}, fmt.Errorf("%s contains a non-JSON value", subject)
	}
	method = normalizedMethod
	if method["id"] != expectedKeyID {
		return publicKeyIdentity{}, fmt.Errorf("%s id does not match its role", subject)
	}
	if method["controller"] != did {
		return publicKeyIdentity{}, fmt.Errorf("%s controller must match the DID", subject)
	}
	if err := validateSameDocumentKeyID(did, expectedKeyID); err != nil {
		return publicKeyIdentity{}, err
	}
	if err := rejectPrivateKeyMaterial(method, subject); err != nil {
		return publicKeyIdentity{}, err
	}
	methodType, ok := method["type"].(string)
	if !ok || methodType == "" {
		return publicKeyIdentity{}, fmt.Errorf("%s.type must be a non-empty string", subject)
	}
	materialFields := make([]string, 0, 3)
	for _, field := range []string{"publicKeyJwk", "publicKeyMultibase", "publicKeyBase58"} {
		if _, exists := method[field]; exists {
			materialFields = append(materialFields, field)
		}
	}
	if len(materialFields) != 1 {
		return publicKeyIdentity{}, fmt.Errorf(
			"%s must contain exactly one supported public key field",
			subject,
		)
	}
	switch materialFields[0] {
	case "publicKeyJwk":
		return decodePublicJWK(methodType, method["publicKeyJwk"], subject)
	case "publicKeyMultibase":
		return decodePublicMultikey(methodType, method["publicKeyMultibase"], subject)
	default:
		return publicKeyIdentity{}, fmt.Errorf(
			"%s publicKeyBase58 is not supported by vNext helpers",
			subject,
		)
	}
}

func validateSameDocumentKeyID(did string, keyID string) error {
	if !strings.HasPrefix(keyID, did+"#") || keyID == did+"#" {
		return fmt.Errorf("key id must be a DID URL in the same document")
	}
	return nil
}

func decodePublicJWK(methodType string, value any, subject string) (publicKeyIdentity, error) {
	switch methodType {
	case "JsonWebKey2020", "EcdsaSecp256k1VerificationKey2019", "EcdsaSecp256r1VerificationKey2019":
	default:
		return publicKeyIdentity{}, fmt.Errorf("%s type is incompatible with publicKeyJwk", subject)
	}
	jwk, err := cloneJSONObject(value, subject+".publicKeyJwk")
	if err != nil {
		return publicKeyIdentity{}, fmt.Errorf("%s.publicKeyJwk must be an object", subject)
	}
	kty, _ := jwk["kty"].(string)
	curve, _ := jwk["crv"].(string)
	if kty == "OKP" && (curve == "Ed25519" || curve == "X25519") {
		if methodType != "JsonWebKey2020" {
			return publicKeyIdentity{}, fmt.Errorf("%s type contradicts its JWK", subject)
		}
		raw, err := decodeCanonicalBase64URL32(jwk["x"], subject+".x")
		if err != nil {
			return publicKeyIdentity{}, err
		}
		algorithm := publicKeyEd25519
		if curve == "X25519" {
			algorithm = publicKeyX25519
		}
		return publicKeyIdentity{algorithm: algorithm, rawPublicKey: raw}, nil
	}
	if kty == "EC" && (curve == "P-256" || curve == "secp256k1") {
		expectedType := "EcdsaSecp256r1VerificationKey2019"
		algorithm := publicKeyP256
		if curve == "secp256k1" {
			expectedType = "EcdsaSecp256k1VerificationKey2019"
			algorithm = publicKeySecp256k1
		}
		if methodType != "JsonWebKey2020" && methodType != expectedType {
			return publicKeyIdentity{}, fmt.Errorf("%s type contradicts its JWK", subject)
		}
		x, err := decodeCanonicalBase64URL32(jwk["x"], subject+".x")
		if err != nil {
			return publicKeyIdentity{}, err
		}
		y, err := decodeCanonicalBase64URL32(jwk["y"], subject+".y")
		if err != nil {
			return publicKeyIdentity{}, err
		}
		if _, err := anp.PublicKeyFromJWK(jwk); err != nil {
			return publicKeyIdentity{}, fmt.Errorf("%s contains an invalid EC point", subject)
		}
		raw := make([]byte, 0, len(x)+len(y))
		raw = append(raw, x...)
		raw = append(raw, y...)
		return publicKeyIdentity{algorithm: algorithm, rawPublicKey: raw}, nil
	}
	return publicKeyIdentity{}, fmt.Errorf("%s contains an unsupported public JWK", subject)
}

func decodePublicMultikey(
	methodType string,
	value any,
	subject string,
) (publicKeyIdentity, error) {
	if methodType != "Multikey" && methodType != "X25519KeyAgreementKey2019" {
		return publicKeyIdentity{}, fmt.Errorf(
			"%s type is incompatible with publicKeyMultibase",
			subject,
		)
	}
	multibase, ok := value.(string)
	if !ok || len(multibase) <= 1 || multibase[0] != 'z' {
		return publicKeyIdentity{}, fmt.Errorf("%s.publicKeyMultibase must be base58btc", subject)
	}
	decoded, err := base58util.Decode(multibase[1:])
	if err != nil {
		return publicKeyIdentity{}, fmt.Errorf("%s.publicKeyMultibase is invalid", subject)
	}
	if "z"+base58util.Encode(decoded) != multibase {
		return publicKeyIdentity{}, fmt.Errorf("%s.publicKeyMultibase must be canonical", subject)
	}
	if len(decoded) != 34 {
		return publicKeyIdentity{}, fmt.Errorf(
			"%s.publicKeyMultibase must contain a 32-byte key",
			subject,
		)
	}
	var algorithm publicKeyAlgorithm
	switch {
	case decoded[0] == 0xed && decoded[1] == 0x01:
		algorithm = publicKeyEd25519
	case decoded[0] == 0xec && decoded[1] == 0x01:
		algorithm = publicKeyX25519
	default:
		return publicKeyIdentity{}, fmt.Errorf(
			"%s.publicKeyMultibase uses an unsupported codec",
			subject,
		)
	}
	if methodType == "X25519KeyAgreementKey2019" && algorithm != publicKeyX25519 {
		return publicKeyIdentity{}, fmt.Errorf("%s type contradicts its Multikey", subject)
	}
	return publicKeyIdentity{
		algorithm: algorithm, rawPublicKey: append([]byte(nil), decoded[2:]...),
	}, nil
}

func decodeCanonicalBase64URL32(value any, subject string) ([]byte, error) {
	encoded, ok := value.(string)
	if !ok || encoded == "" || strings.Contains(encoded, "=") {
		return nil, fmt.Errorf("%s must be unpadded base64url", subject)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%s is invalid base64url", subject)
	}
	if len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, fmt.Errorf("%s must canonically encode 32 bytes", subject)
	}
	return decoded, nil
}

func rejectPrivateKeyMaterial(value any, subject string) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			normalizedKey := strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(key))
			_, isJWK := typed["kty"]
			if strings.Contains(normalizedKey, "privatekey") || (key == "d" && isJWK) {
				return fmt.Errorf("%s must not contain private key material", subject)
			}
			if err := rejectPrivateKeyMaterial(nested, subject); err != nil {
				return err
			}
		}
	case []any:
		for _, nested := range typed {
			if err := rejectPrivateKeyMaterial(nested, subject); err != nil {
				return err
			}
		}
	}
	return nil
}

func uniqueVerificationMethod(didDocument map[string]any, keyID string) (map[string]any, error) {
	methods, err := jsonArray(didDocument["verificationMethod"])
	if err != nil {
		return nil, fmt.Errorf("DID document verificationMethod must be an array")
	}
	matches := make([]map[string]any, 0, 1)
	for _, rawMethod := range methods {
		method, ok := rawMethod.(map[string]any)
		if ok && method["id"] == keyID {
			matches = append(matches, method)
		}
	}
	if len(matches) != 1 {
		return nil, fmt.Errorf("key id must resolve exactly once in verificationMethod")
	}
	return matches[0], nil
}

func appendDeviceMaterial(
	document map[string]any,
	rootKeyID string,
	device DeviceManifestEntry,
	signingMethod map[string]any,
	e2eeMethod map[string]any,
) error {
	did, err := documentDID(document)
	if err != nil {
		return err
	}
	if _, _, err := validateDeviceMethods(
		did,
		rootKeyID,
		device,
		signingMethod,
		e2eeMethod,
	); err != nil {
		return err
	}
	signingCopy, err := cloneJSONMapValue(signingMethod)
	if err != nil {
		return err
	}
	e2eeCopy, err := cloneJSONMapValue(e2eeMethod)
	if err != nil {
		return err
	}
	methods, err := jsonArray(document["verificationMethod"])
	if err != nil {
		return fmt.Errorf("verificationMethod must be an array")
	}
	document["verificationMethod"] = append(methods, signingCopy, e2eeCopy)
	for relationship, keyID := range map[string]string{
		"authentication":  device.SigningKeyID,
		"assertionMethod": device.SigningKeyID,
		"keyAgreement":    device.E2EEKeyID,
	} {
		entries, arrayErr := jsonArray(document[relationship])
		if arrayErr != nil {
			return fmt.Errorf("%s must be an array", relationship)
		}
		document[relationship] = append(entries, keyID)
	}
	manifest, ok := document["deviceManifest"].(map[string]any)
	if !ok {
		return fmt.Errorf("deviceManifest must be an object")
	}
	devices, err := jsonArray(manifest["devices"])
	if err != nil {
		return fmt.Errorf("deviceManifest.devices must be an array")
	}
	manifest["devices"] = append(devices, deviceEntryMap(device))
	return nil
}

func removeDeviceMaterial(document map[string]any, device DeviceManifestEntry) error {
	methods, err := jsonArray(document["verificationMethod"])
	if err != nil {
		return fmt.Errorf("verificationMethod must be an array")
	}
	filteredMethods := make([]any, 0, len(methods)-2)
	for _, rawMethod := range methods {
		method, ok := rawMethod.(map[string]any)
		if ok && (method["id"] == device.SigningKeyID || method["id"] == device.E2EEKeyID) {
			continue
		}
		filteredMethods = append(filteredMethods, rawMethod)
	}
	document["verificationMethod"] = filteredMethods
	keyIDs := []string{device.SigningKeyID, device.E2EEKeyID}
	for _, relationship := range []string{"authentication", "assertionMethod", "keyAgreement"} {
		entries, arrayErr := jsonArray(document[relationship])
		if arrayErr != nil {
			return fmt.Errorf("%s must be an array", relationship)
		}
		filtered := make([]any, 0, len(entries))
		for _, entry := range entries {
			if relationshipEntryIsAny(entry, keyIDs) {
				continue
			}
			filtered = append(filtered, entry)
		}
		document[relationship] = filtered
	}
	manifest, ok := document["deviceManifest"].(map[string]any)
	if !ok {
		return fmt.Errorf("deviceManifest must be an object")
	}
	devices, err := jsonArray(manifest["devices"])
	if err != nil {
		return fmt.Errorf("deviceManifest.devices must be an array")
	}
	filteredDevices := make([]any, 0, len(devices)-1)
	for _, rawEntry := range devices {
		entry, ok := rawEntry.(map[string]any)
		if ok && entry["device_id"] == device.DeviceID {
			continue
		}
		filteredDevices = append(filteredDevices, rawEntry)
	}
	manifest["devices"] = filteredDevices
	return nil
}

func relationshipEntryIs(entry any, keyID string) bool {
	if reference, ok := entry.(string); ok {
		return reference == keyID
	}
	if embedded, ok := entry.(map[string]any); ok {
		return embedded["id"] == keyID
	}
	return false
}

func relationshipEntryIsAny(entry any, keyIDs []string) bool {
	for _, keyID := range keyIDs {
		if relationshipEntryIs(entry, keyID) {
			return true
		}
	}
	return false
}

func deviceEntryMap(device DeviceManifestEntry) map[string]any {
	profiles := make([]any, 0, len(device.Profiles))
	for _, profile := range device.Profiles {
		profiles = append(profiles, profile)
	}
	return map[string]any{
		"device_id":      device.DeviceID,
		"signing_key_id": device.SigningKeyID,
		"e2ee_key_id":    device.E2EEKeyID,
		"profiles":       profiles,
	}
}

func cloneDIDJSONObject(value map[string]any) (map[string]any, error) {
	return cloneJSONMapValue(value)
}

func cloneJSONMapValue(value map[string]any) (map[string]any, error) {
	return cloneJSONObject(value, "JSON object")
}

func cloneJSONObject(value any, subject string) (map[string]any, error) {
	cloned, err := cloneStrictJSONValue(value, subject)
	if err != nil {
		return nil, err
	}
	object, ok := cloned.(map[string]any)
	if !ok || object == nil {
		return nil, fmt.Errorf("%s must be an object", subject)
	}
	return object, nil
}

// cloneJSONValue recursively clones only values representable in the JSON data
// model. Unlike a marshal/unmarshal round trip, it preserves integer precision
// and rejects structs, functions, pointers, and non-finite numbers.
func cloneStrictJSONValue(value any, subject string) (any, error) {
	if value == nil {
		return nil, nil
	}
	if number, ok := value.(json.Number); ok {
		if !jsonNumberPattern.MatchString(string(number)) {
			return nil, fmt.Errorf("%s contains an invalid JSON number", subject)
		}
		return number, nil
	}

	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Bool, reflect.String,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return value, nil
	case reflect.Float32, reflect.Float64:
		if !math.IsNaN(reflected.Float()) && !math.IsInf(reflected.Float(), 0) {
			return value, nil
		}
		return nil, fmt.Errorf("%s contains a non-finite number", subject)
	case reflect.Map:
		if reflected.Type().Key().Kind() != reflect.String {
			return nil, fmt.Errorf("%s contains a non-string object key", subject)
		}
		if reflected.IsNil() {
			return nil, nil
		}
		cloned := make(map[string]any, reflected.Len())
		iterator := reflected.MapRange()
		for iterator.Next() {
			key := iterator.Key().String()
			nested, err := cloneStrictJSONValue(iterator.Value().Interface(), subject)
			if err != nil {
				return nil, err
			}
			cloned[key] = nested
		}
		return cloned, nil
	case reflect.Slice:
		if reflected.IsNil() {
			return []any(nil), nil
		}
		fallthrough
	case reflect.Array:
		cloned := make([]any, reflected.Len())
		for index := 0; index < reflected.Len(); index++ {
			nested, err := cloneStrictJSONValue(reflected.Index(index).Interface(), subject)
			if err != nil {
				return nil, err
			}
			cloned[index] = nested
		}
		return cloned, nil
	default:
		return nil, fmt.Errorf("%s contains a non-JSON value", subject)
	}
}

func validateRetiredDeviceIDs(retiredDeviceIDs []string) error {
	for _, deviceID := range retiredDeviceIDs {
		if deviceID == "" {
			return fmt.Errorf("retired device_id must be a non-empty string")
		}
	}
	return nil
}
