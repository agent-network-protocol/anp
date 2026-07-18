package authentication

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type vNextDIDBuilderFixture struct {
	RootKeyID                string                     `json:"root_key_id"`
	RetiredDeviceIDs         []string                   `json:"retired_device_ids"`
	BaseDocument             map[string]any             `json:"base_document"`
	RootVerificationMethod   map[string]any             `json:"root_verification_method"`
	DeviceA                  builderDevice              `json:"device_a"`
	DeviceB                  builderDevice              `json:"device_b"`
	DeviceBRotated           builderDevice              `json:"device_b_rotated"`
	X25519MultikeyMethod     map[string]any             `json:"x25519_multikey_verification_method"`
	ExpectedBuild            map[string]any             `json:"expected_build"`
	ExpectedAdd              map[string]any             `json:"expected_add"`
	ExpectedUpdate           map[string]any             `json:"expected_update"`
	ExpectedRemove           map[string]any             `json:"expected_remove"`
	InvalidPublicKeyCases    []invalidPublicKeyCase     `json:"invalid_public_key_cases"`
	DuplicateMaterialCases   []duplicateKeyMaterialCase `json:"duplicate_key_material_cases"`
	InvalidRelationshipCases []invalidRelationshipCase  `json:"invalid_relationship_cases"`
}

type invalidPublicKeyCase struct {
	Name               string         `json:"name"`
	Role               string         `json:"role"`
	VerificationMethod map[string]any `json:"verification_method"`
}

type duplicateKeyMaterialCase struct {
	Name                      string         `json:"name"`
	Operation                 string         `json:"operation"`
	RootVerificationMethod    map[string]any `json:"root_verification_method"`
	SigningVerificationMethod map[string]any `json:"signing_verification_method"`
	E2EEVerificationMethod    map[string]any `json:"e2ee_verification_method"`
}

type invalidRelationshipCase struct {
	Name         string `json:"name"`
	Relationship string `json:"relationship"`
	KeyID        string `json:"key_id"`
}

type builderDevice struct {
	Entry                     DeviceManifestEntry `json:"entry"`
	SigningVerificationMethod map[string]any      `json:"signing_verification_method"`
	E2EEVerificationMethod    map[string]any      `json:"e2ee_verification_method"`
}

func TestSharedVNextDIDBuildAddUpdateRemoveVectors(t *testing.T) {
	fixture := loadVNextDIDBuilderFixture(t)
	baseBefore := cloneMapForTest(t, fixture.BaseDocument)
	built, err := buildFixtureDocument(fixture)
	if err != nil {
		t.Fatalf("BuildVNextDIDDocument failed: %v", err)
	}
	if !reflect.DeepEqual(built, fixture.ExpectedBuild) {
		t.Fatalf("built document differs from fixture\nactual=%#v\nexpected=%#v", built, fixture.ExpectedBuild)
	}
	if !reflect.DeepEqual(fixture.BaseDocument, baseBefore) {
		t.Fatal("builder mutated base document")
	}
	if !reflect.DeepEqual(built["x-example"], fixture.BaseDocument["x-example"]) {
		t.Fatal("builder did not preserve unknown top-level extension")
	}

	withStaleProof := cloneMapForTest(t, built)
	withStaleProof["proof"] = map[string]any{"proofValue": "stale"}
	added, err := AddDeviceToDIDDocument(
		withStaleProof,
		fixture.RootKeyID,
		fixture.DeviceB.Entry,
		fixture.DeviceB.SigningVerificationMethod,
		fixture.DeviceB.E2EEVerificationMethod,
		fixture.RetiredDeviceIDs,
	)
	if err != nil {
		t.Fatalf("AddDeviceToDIDDocument failed: %v", err)
	}
	if !reflect.DeepEqual(added, fixture.ExpectedAdd) {
		t.Fatalf("added document differs from fixture")
	}
	if _, exists := added["proof"]; exists {
		t.Fatal("stale proof survived mutation")
	}
	if _, exists := withStaleProof["proof"]; !exists {
		t.Fatal("add mutated its input")
	}

	updated, err := UpdateDeviceInDIDDocument(
		added,
		fixture.RootKeyID,
		fixture.DeviceBRotated.Entry,
		fixture.DeviceBRotated.SigningVerificationMethod,
		fixture.DeviceBRotated.E2EEVerificationMethod,
	)
	if err != nil {
		t.Fatalf("UpdateDeviceInDIDDocument failed: %v", err)
	}
	if !reflect.DeepEqual(updated, fixture.ExpectedUpdate) {
		t.Fatalf("updated document differs from fixture")
	}

	removed, err := RemoveDeviceFromDIDDocument(
		updated,
		fixture.RootKeyID,
		fixture.DeviceBRotated.Entry.DeviceID,
	)
	if err != nil {
		t.Fatalf("RemoveDeviceFromDIDDocument failed: %v", err)
	}
	if !reflect.DeepEqual(removed, fixture.ExpectedRemove) {
		t.Fatalf("removed document differs from fixture")
	}
	if !reflect.DeepEqual(
		removed["deviceManifest"].(map[string]any)["devices"],
		built["deviceManifest"].(map[string]any)["devices"],
	) {
		t.Fatal("removing device B changed device A")
	}
	if _, err := ValidateDeviceManifest(removed); err != nil {
		t.Fatalf("removed document did not validate: %v", err)
	}

	multikeyBuilt, err := BuildVNextDIDDocument(
		fixture.BaseDocument,
		fixture.RootKeyID,
		fixture.RootVerificationMethod,
		fixture.DeviceA.Entry,
		fixture.DeviceA.SigningVerificationMethod,
		fixture.X25519MultikeyMethod,
	)
	if err != nil {
		t.Fatalf("X25519 Multikey build failed: %v", err)
	}
	methods := multikeyBuilt["verificationMethod"].([]any)
	if !reflect.DeepEqual(methods[2], fixture.X25519MultikeyMethod) {
		t.Fatal("X25519 Multikey method changed during build")
	}
}

func TestVNextBuilderRejectsRootAsDeviceKeyAndPrivateMaterial(t *testing.T) {
	fixture := loadVNextDIDBuilderFixture(t)
	device := fixture.DeviceA
	device.Entry.SigningKeyID = fixture.RootKeyID
	device.SigningVerificationMethod = cloneMapForTest(t, fixture.RootVerificationMethod)
	if _, err := BuildVNextDIDDocument(
		fixture.BaseDocument,
		fixture.RootKeyID,
		fixture.RootVerificationMethod,
		device.Entry,
		device.SigningVerificationMethod,
		device.E2EEVerificationMethod,
	); err == nil {
		t.Fatal("root key was accepted as a device key")
	}

	privateRoot := cloneMapForTest(t, fixture.RootVerificationMethod)
	privateRoot["publicKeyJwk"].(map[string]any)["d"] = "PRIVATE"
	if _, err := BuildVNextDIDDocument(
		fixture.BaseDocument,
		fixture.RootKeyID,
		privateRoot,
		fixture.DeviceA.Entry,
		fixture.DeviceA.SigningVerificationMethod,
		fixture.DeviceA.E2EEVerificationMethod,
	); err == nil {
		t.Fatal("private root material was accepted")
	}

	privateBase := cloneMapForTest(t, fixture.BaseDocument)
	privateBase["root_private_key"] = "PRIVATE"
	if _, err := BuildVNextDIDDocument(
		privateBase,
		fixture.RootKeyID,
		fixture.RootVerificationMethod,
		fixture.DeviceA.Entry,
		fixture.DeviceA.SigningVerificationMethod,
		fixture.DeviceA.E2EEVerificationMethod,
	); err == nil {
		t.Fatal("private material in the base document was accepted")
	}
}

func TestVNextMutationRejectsDuplicateForeignAndMissingRelationship(t *testing.T) {
	fixture := loadVNextDIDBuilderFixture(t)
	built, err := buildFixtureDocument(fixture)
	if err != nil {
		t.Fatalf("BuildVNextDIDDocument failed: %v", err)
	}
	if _, err := AddDeviceToDIDDocument(
		built,
		fixture.RootKeyID,
		fixture.DeviceA.Entry,
		fixture.DeviceA.SigningVerificationMethod,
		fixture.DeviceA.E2EEVerificationMethod,
		fixture.RetiredDeviceIDs,
	); err == nil {
		t.Fatal("duplicate device was accepted")
	}

	foreignSigning := cloneMapForTest(t, fixture.DeviceB.SigningVerificationMethod)
	foreignSigning["controller"] = "did:example:other"
	if _, err := AddDeviceToDIDDocument(
		built,
		fixture.RootKeyID,
		fixture.DeviceB.Entry,
		foreignSigning,
		fixture.DeviceB.E2EEVerificationMethod,
		fixture.RetiredDeviceIDs,
	); err == nil {
		t.Fatal("foreign signing method was accepted")
	}

	missingRelationship := cloneMapForTest(t, built)
	missingRelationship["keyAgreement"] = []any{}
	if _, err := AddDeviceToDIDDocument(
		missingRelationship,
		fixture.RootKeyID,
		fixture.DeviceB.Entry,
		fixture.DeviceB.SigningVerificationMethod,
		fixture.DeviceB.E2EEVerificationMethod,
		fixture.RetiredDeviceIDs,
	); err == nil {
		t.Fatal("document with missing relationship was accepted")
	}
}

func TestSharedInvalidPublicKeyCasesAreRejected(t *testing.T) {
	fixture := loadVNextDIDBuilderFixture(t)
	for _, testCase := range fixture.InvalidPublicKeyCases {
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			root := fixture.RootVerificationMethod
			signing := fixture.DeviceA.SigningVerificationMethod
			e2ee := fixture.DeviceA.E2EEVerificationMethod
			switch testCase.Role {
			case "root":
				root = testCase.VerificationMethod
			case "device_signing":
				signing = testCase.VerificationMethod
			case "device_e2ee":
				e2ee = testCase.VerificationMethod
			default:
				t.Fatalf("unknown fixture role %q", testCase.Role)
			}
			if _, err := BuildVNextDIDDocument(
				fixture.BaseDocument,
				fixture.RootKeyID,
				root,
				fixture.DeviceA.Entry,
				signing,
				e2ee,
			); err == nil {
				t.Fatal("invalid public key case was accepted")
			}
		})
	}
}

func TestSharedDuplicateKeyMaterialCasesAreRejected(t *testing.T) {
	fixture := loadVNextDIDBuilderFixture(t)
	for _, testCase := range fixture.DuplicateMaterialCases {
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			if testCase.Operation == "build" {
				if _, err := BuildVNextDIDDocument(
					fixture.BaseDocument,
					fixture.RootKeyID,
					testCase.RootVerificationMethod,
					fixture.DeviceA.Entry,
					fixture.DeviceA.SigningVerificationMethod,
					fixture.DeviceA.E2EEVerificationMethod,
				); err == nil {
					t.Fatal("duplicate root/device key material was accepted")
				}
				return
			}
			if testCase.Operation != "add" {
				t.Fatalf("unknown fixture operation %q", testCase.Operation)
			}
			signing := fixture.DeviceB.SigningVerificationMethod
			if testCase.SigningVerificationMethod != nil {
				signing = testCase.SigningVerificationMethod
			}
			e2ee := fixture.DeviceB.E2EEVerificationMethod
			if testCase.E2EEVerificationMethod != nil {
				e2ee = testCase.E2EEVerificationMethod
			}
			built, err := buildFixtureDocument(fixture)
			if err != nil {
				t.Fatalf("BuildVNextDIDDocument failed: %v", err)
			}
			if _, err := AddDeviceToDIDDocument(
				built,
				fixture.RootKeyID,
				fixture.DeviceB.Entry,
				signing,
				e2ee,
				fixture.RetiredDeviceIDs,
			); err == nil {
				t.Fatal("duplicate device key material was accepted")
			}
		})
	}
}

func TestSharedInvalidRelationshipCasesAreRejected(t *testing.T) {
	fixture := loadVNextDIDBuilderFixture(t)
	for _, testCase := range fixture.InvalidRelationshipCases {
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			document, err := buildFixtureDocument(fixture)
			if err != nil {
				t.Fatalf("BuildVNextDIDDocument failed: %v", err)
			}
			entries := document[testCase.Relationship].([]any)
			document[testCase.Relationship] = append(entries, testCase.KeyID)
			if _, err := AddDeviceToDIDDocument(
				document,
				fixture.RootKeyID,
				fixture.DeviceB.Entry,
				fixture.DeviceB.SigningVerificationMethod,
				fixture.DeviceB.E2EEVerificationMethod,
				fixture.RetiredDeviceIDs,
			); err == nil {
				t.Fatal("cross-role relationship was accepted")
			}
		})
	}
}

func TestRetiredDeviceIDAndRemovedRelationshipCleanup(t *testing.T) {
	fixture := loadVNextDIDBuilderFixture(t)
	built, err := buildFixtureDocument(fixture)
	if err != nil {
		t.Fatalf("BuildVNextDIDDocument failed: %v", err)
	}
	added, err := AddDeviceToDIDDocument(
		built,
		fixture.RootKeyID,
		fixture.DeviceB.Entry,
		fixture.DeviceB.SigningVerificationMethod,
		fixture.DeviceB.E2EEVerificationMethod,
		fixture.RetiredDeviceIDs,
	)
	if err != nil {
		t.Fatalf("AddDeviceToDIDDocument failed: %v", err)
	}
	added["authentication"] = append(
		added["authentication"].([]any),
		fixture.DeviceB.Entry.SigningKeyID,
	)
	added["assertionMethod"] = append(
		added["assertionMethod"].([]any),
		map[string]any{"id": fixture.DeviceB.Entry.SigningKeyID},
	)
	added["keyAgreement"] = append(
		added["keyAgreement"].([]any),
		fixture.DeviceB.Entry.E2EEKeyID,
	)
	updated, err := UpdateDeviceInDIDDocument(
		added,
		fixture.RootKeyID,
		fixture.DeviceBRotated.Entry,
		fixture.DeviceBRotated.SigningVerificationMethod,
		fixture.DeviceBRotated.E2EEVerificationMethod,
	)
	if err != nil {
		t.Fatalf("UpdateDeviceInDIDDocument failed: %v", err)
	}
	oldKeyIDs := []string{
		fixture.DeviceB.Entry.SigningKeyID,
		fixture.DeviceB.Entry.E2EEKeyID,
	}
	for _, relationship := range []string{"authentication", "assertionMethod", "keyAgreement"} {
		for _, entry := range updated[relationship].([]any) {
			if relationshipEntryIsAny(entry, oldKeyIDs) {
				t.Fatalf("old key survived in %s", relationship)
			}
		}
	}

	removed, err := RemoveDeviceFromDIDDocument(
		added,
		fixture.RootKeyID,
		fixture.DeviceB.Entry.DeviceID,
	)
	if err != nil {
		t.Fatalf("RemoveDeviceFromDIDDocument failed: %v", err)
	}
	if _, err := AddDeviceToDIDDocument(
		removed,
		fixture.RootKeyID,
		fixture.DeviceB.Entry,
		fixture.DeviceB.SigningVerificationMethod,
		fixture.DeviceB.E2EEVerificationMethod,
		[]string{fixture.DeviceB.Entry.DeviceID},
	); err == nil {
		t.Fatal("retired device_id was reused")
	}
	if _, err := AddDeviceToDIDDocument(
		removed,
		fixture.RootKeyID,
		fixture.DeviceB.Entry,
		fixture.DeviceB.SigningVerificationMethod,
		fixture.DeviceB.E2EEVerificationMethod,
		[]string{""},
	); err == nil {
		t.Fatal("empty retired device_id was accepted")
	}
}

func TestVNextBuilderRejectsNonJSONValuesAndPreservesLargeInteger(t *testing.T) {
	fixture := loadVNextDIDBuilderFixture(t)
	invalidValues := []any{
		time.Now(),
		func() {},
		math.NaN(),
		math.Inf(1),
		math.Inf(-1),
	}
	for index, invalidValue := range invalidValues {
		base := cloneMapForTest(t, fixture.BaseDocument)
		base["x-invalid"] = invalidValue
		if _, err := BuildVNextDIDDocument(
			base,
			fixture.RootKeyID,
			fixture.RootVerificationMethod,
			fixture.DeviceA.Entry,
			fixture.DeviceA.SigningVerificationMethod,
			fixture.DeviceA.E2EEVerificationMethod,
		); err == nil {
			t.Fatalf("non-JSON value %d was accepted", index)
		}
	}

	const largeInteger int64 = 9_007_199_254_740_993
	base := cloneMapForTest(t, fixture.BaseDocument)
	base["x-large-integer"] = largeInteger
	built, err := BuildVNextDIDDocument(
		base,
		fixture.RootKeyID,
		fixture.RootVerificationMethod,
		fixture.DeviceA.Entry,
		fixture.DeviceA.SigningVerificationMethod,
		fixture.DeviceA.E2EEVerificationMethod,
	)
	if err != nil {
		t.Fatalf("large integer build failed: %v", err)
	}
	if value, ok := built["x-large-integer"].(int64); !ok || value != largeInteger {
		t.Fatalf("large integer changed type or value: %#v", built["x-large-integer"])
	}
}

func buildFixtureDocument(fixture vNextDIDBuilderFixture) (map[string]any, error) {
	return BuildVNextDIDDocument(
		fixture.BaseDocument,
		fixture.RootKeyID,
		fixture.RootVerificationMethod,
		fixture.DeviceA.Entry,
		fixture.DeviceA.SigningVerificationMethod,
		fixture.DeviceA.E2EEVerificationMethod,
	)
}

func loadVNextDIDBuilderFixture(t *testing.T) vNextDIDBuilderFixture {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "device_manifest", "vnext_did_builder_fixtures.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture vNextDIDBuilderFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return fixture
}

func cloneMapForTest(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal map: %v", err)
	}
	var clone map[string]any
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatalf("unmarshal map: %v", err)
	}
	return clone
}
