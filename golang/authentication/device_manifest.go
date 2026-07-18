package authentication

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
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
)

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
	manifestMap, ok := rawManifest.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("deviceManifest must be an object")
	}
	if err := requireExactFields(manifestMap, manifestFields, "deviceManifest"); err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(manifestMap)
	if err != nil {
		return nil, fmt.Errorf("encode deviceManifest: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var manifest DeviceManifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("parse deviceManifest: %w", err)
	}
	if manifest.Type != DeviceManifestType {
		return nil, fmt.Errorf("deviceManifest.type must equal %s", DeviceManifestType)
	}
	if manifest.Devices == nil {
		return nil, fmt.Errorf("deviceManifest.devices must be an array")
	}

	rawDevices, err := jsonArray(manifestMap["devices"])
	if err != nil {
		return nil, fmt.Errorf("deviceManifest.devices must be an array")
	}
	for index, rawEntry := range rawDevices {
		entry, ok := rawEntry.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("deviceManifest.devices[%d] must be an object", index)
		}
		if err := requireExactFields(entry, entryFields, fmt.Sprintf("deviceManifest.devices[%d]", index)); err != nil {
			return nil, err
		}
		for _, field := range []string{"device_id", "signing_key_id", "e2ee_key_id"} {
			if _, ok := entry[field].(string); !ok {
				return nil, fmt.Errorf("deviceManifest.devices[%d].%s must be a string", index, field)
			}
		}
		if _, err := jsonArray(entry["profiles"]); err != nil {
			return nil, fmt.Errorf("deviceManifest.devices[%d].profiles must be an array", index)
		}
	}
	return &manifest, nil
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
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var values []any
	if err := json.Unmarshal(encoded, &values); err != nil {
		return nil, err
	}
	if values == nil {
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
