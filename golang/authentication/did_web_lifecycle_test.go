package authentication

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func webLifecycleFixture(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile("../../fixtures/did-method-lifecycle-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]any
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestRootlessWebBuildJoinRevoke(t *testing.T) {
	f := webLifecycleFixture(t)
	docs := f["documents"].(map[string]any)
	single := docs["web_single_device"].(map[string]any)
	base := cloneMap(single)
	for _, key := range []string{"verificationMethod", "authentication", "assertionMethod", "keyAgreement", "deviceManifest", "proof"} {
		delete(base, key)
	}
	manifest, err := ValidateDeviceManifest(single)
	if err != nil {
		t.Fatal(err)
	}
	methods := single["verificationMethod"].([]any)
	built, err := BuildWebDIDDocument(base, manifest.Devices[0], methods[0].(map[string]any), methods[1].(map[string]any))
	if err != nil || !reflect.DeepEqual(built, single) {
		t.Fatalf("build differs from fixture: %v", err)
	}
	signed := cloneMap(built)
	signed["proof"] = map[string]any{"stale": "must disappear"}
	secondJSON, _ := json.Marshal(f["device_b"])
	var second DeviceManifestEntry
	if err := json.Unmarshal(secondJSON, &second); err != nil {
		t.Fatal(err)
	}
	secondMethods := f["device_b_verification_methods"].([]any)
	joined, err := AddDeviceToWebDIDDocument(signed, second, secondMethods[0].(map[string]any), secondMethods[1].(map[string]any), nil)
	if err != nil || !reflect.DeepEqual(joined, docs["web_two_devices"]) {
		t.Fatalf("join differs from fixture: %v", err)
	}
	if _, present := signed["proof"]; !present {
		t.Fatal("caller input mutated")
	}
	removed, err := RemoveDeviceFromWebDIDDocument(joined, "device-b")
	if err != nil || !reflect.DeepEqual(removed, single) {
		t.Fatalf("revoke differs from fixture: %v", err)
	}
	if _, err := AddDeviceToWebDIDDocument(single, second, secondMethods[0].(map[string]any), secondMethods[1].(map[string]any), []string{"device-b"}); err == nil {
		t.Fatal("retired ID reused")
	}
}

func TestWebMethodIndependentManifest(t *testing.T) {
	docs := webLifecycleFixture(t)["documents"].(map[string]any)
	for _, name := range []string{"web_single_device", "web_two_devices", "wba_two_devices"} {
		if !ValidateDIDDocumentMethod(docs[name].(map[string]any), true) {
			t.Fatalf("method validation failed for %s", name)
		}
		if m, err := ValidateDeviceManifest(docs[name].(map[string]any)); err != nil || m == nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for _, name := range []string{"web_api", "web_group_assertion_only"} {
		if m, err := ValidateDeviceManifest(docs[name].(map[string]any)); err != nil || m != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestCurrentWBAMultibaseProofProtectsContext(t *testing.T) {
	document := webLifecycleFixture(t)["documents"].(map[string]any)["wba_two_devices"].(map[string]any)
	if !ValidateDIDDocumentMethod(document, true) {
		t.Fatal("standard multibase root proof rejected")
	}
	document["@context"] = append(document["@context"].([]any), "https://changed.example/context")
	if ValidateDIDDocumentMethod(document, true) {
		t.Fatal("context tampering accepted")
	}
}

func TestWebMutationKeepsValidation(t *testing.T) {
	docs := webLifecycleFixture(t)["documents"].(map[string]any)
	for _, failure := range []string{"private", "purpose", "duplicate-material", "wrong-method", "dependency"} {
		document := cloneMap(docs["web_two_devices"].(map[string]any))
		methods := document["verificationMethod"].([]any)
		switch failure {
		case "private":
			methods[0].(map[string]any)["privateKeyMultibase"] = "not-public"
		case "purpose":
			document["authentication"] = []any{}
		case "duplicate-material":
			methods[2].(map[string]any)["publicKeyMultibase"] = methods[0].(map[string]any)["publicKeyMultibase"]
		case "wrong-method":
			document = cloneMap(docs["wba_two_devices"].(map[string]any))
		case "dependency":
			device := document["deviceManifest"].(map[string]any)["devices"].([]any)[0].(map[string]any)
			profiles := []any{}
			for _, profile := range device["profiles"].([]any) {
				if profile != "anp.core.binding.v1" {
					profiles = append(profiles, profile)
				}
			}
			device["profiles"] = profiles
		}
		if _, err := RemoveDeviceFromWebDIDDocument(document, "device-b"); err == nil {
			t.Errorf("accepted %s", failure)
		}
	}
}

func TestWebE2EELookupChecksKeyAlgorithm(t *testing.T) {
	document := webLifecycleFixture(t)["documents"].(map[string]any)["web_single_device"].(map[string]any)
	if device, err := FindEligibleDevice(document, "device-a", ProfileDirectE2EEV2); err != nil || device == nil {
		t.Fatalf("valid lookup: %v", err)
	}
	methods := document["verificationMethod"].([]any)
	methods[0].(map[string]any)["publicKeyMultibase"] = methods[1].(map[string]any)["publicKeyMultibase"]
	if _, err := FindEligibleDevice(document, "device-a", ProfileDirectE2EEV2); err == nil {
		t.Fatal("X25519 accepted for P5 assertion signing")
	}
}
