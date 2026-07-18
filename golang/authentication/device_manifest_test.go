package authentication

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type deviceManifestFixtures struct {
	Version         string                    `json:"version"`
	ProtocolCommit  string                    `json:"protocol_commit"`
	BaseDIDDocument map[string]any            `json:"base_did_document"`
	Valid           []deviceManifestValidCase `json:"valid"`
	Invalid         []deviceManifestCase      `json:"invalid"`
}

type deviceManifestCase struct {
	Name           string         `json:"name"`
	DeviceManifest map[string]any `json:"device_manifest"`
	DocumentPatch  map[string]any `json:"document_patch"`
}

type deviceManifestValidCase struct {
	deviceManifestCase
	Lookup struct {
		DeviceID string `json:"device_id"`
		Profile  string `json:"profile"`
		Found    bool   `json:"found"`
	} `json:"lookup"`
}

func TestSharedDeviceManifestValidFixtures(t *testing.T) {
	fixtures := loadDeviceManifestFixtures(t)
	if fixtures.Version != "anp-device-manifest-vnext-fixtures-v1" {
		t.Fatalf("unexpected fixture version %q", fixtures.Version)
	}
	for _, testCase := range fixtures.Valid {
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			document := buildDeviceManifestDocument(t, fixtures.BaseDIDDocument, testCase.deviceManifestCase)
			before := cloneJSONMap(t, document)

			parsed, err := ParseDeviceManifest(document)
			if err != nil {
				t.Fatalf("ParseDeviceManifest failed: %v", err)
			}
			if parsed == nil || !reflect.DeepEqual(parsed.ToMap(), testCase.DeviceManifest) {
				t.Fatalf("parsed Manifest mismatch: %#v", parsed)
			}
			validated, err := ValidateDeviceManifest(document)
			if err != nil || validated == nil {
				t.Fatalf("ValidateDeviceManifest failed: manifest=%#v err=%v", validated, err)
			}
			device, err := FindEligibleDevice(document, testCase.Lookup.DeviceID, testCase.Lookup.Profile)
			if err != nil {
				t.Fatalf("FindEligibleDevice failed: %v", err)
			}
			if (device != nil) != testCase.Lookup.Found {
				t.Fatalf("lookup found=%v, want %v", device != nil, testCase.Lookup.Found)
			}
			if !reflect.DeepEqual(document, before) {
				t.Fatal("Manifest validation changed the DID document")
			}
		})
	}
}

func TestSharedDeviceManifestInvalidFixtures(t *testing.T) {
	fixtures := loadDeviceManifestFixtures(t)
	for _, testCase := range fixtures.Invalid {
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			document := buildDeviceManifestDocument(t, fixtures.BaseDIDDocument, testCase)
			if _, err := ValidateDeviceManifest(document); err == nil {
				t.Fatal("ValidateDeviceManifest unexpectedly accepted invalid fixture")
			}
		})
	}
}

func TestDeviceManifestAbsenceDoesNotCreateDefaultDevice(t *testing.T) {
	fixtures := loadDeviceManifestFixtures(t)
	document := cloneJSONMap(t, fixtures.BaseDIDDocument)
	manifest, err := ValidateDeviceManifest(document)
	if err != nil || manifest != nil {
		t.Fatalf("absent Manifest = %#v, %v; want nil, nil", manifest, err)
	}
	device, err := FindEligibleDevice(document, "dev-a-7N3KQ2", ProfileDirectE2EEV2)
	if err != nil || device != nil {
		t.Fatalf("absent Manifest lookup = %#v, %v; want nil, nil", device, err)
	}
}

func loadDeviceManifestFixtures(t *testing.T) deviceManifestFixtures {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "device_manifest", "vnext_device_manifest_fixtures.json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read shared fixture: %v", err)
	}
	var fixtures deviceManifestFixtures
	if err := json.Unmarshal(contents, &fixtures); err != nil {
		t.Fatalf("parse shared fixture: %v", err)
	}
	return fixtures
}

func buildDeviceManifestDocument(t *testing.T, base map[string]any, testCase deviceManifestCase) map[string]any {
	t.Helper()
	document := cloneJSONMap(t, base)
	for key, value := range testCase.DocumentPatch {
		document[key] = cloneJSONValue(t, value)
	}
	document["deviceManifest"] = cloneJSONValue(t, testCase.DeviceManifest)
	return document
}

func cloneJSONMap(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	clone, ok := cloneJSONValue(t, value).(map[string]any)
	if !ok {
		t.Fatal("cloned value is not an object")
	}
	return clone
}

func cloneJSONValue(t *testing.T, value any) any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode clone: %v", err)
	}
	var clone any
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatalf("decode clone: %v", err)
	}
	return clone
}
