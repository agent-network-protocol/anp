package groupe2ee

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/authentication"
	"github.com/agent-network-protocol/anp/golang/internal/cjson"
	"github.com/agent-network-protocol/anp/golang/proof"
)

func loadP6V2Vectors(t *testing.T) map[string]any {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "group_e2ee", "p6_v2_wire_vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestSharedP6V2WireObjectsRoundTrip(t *testing.T) {
	fixture := loadP6V2Vectors(t)
	if Profile != "anp.group.e2ee.v1" || ProfileV2 != "anp.group.e2ee.v2" {
		t.Fatal("v1/v2 profiles are not side-by-side")
	}

	metaPublish, bodyPublish, err := ParsePublishKeyPackageRequestV2(fixture["publish_request"])
	if err != nil {
		t.Fatal(err)
	}
	assertP6V2JSONEqual(t, mustP6V2(PublishKeyPackageRequestV2(metaPublish, bodyPublish)), fixture["publish_request"])

	metaGet, bodyGet, err := ParseGetKeyPackageRequestV2(fixture["get_request"])
	if err != nil {
		t.Fatal(err)
	}
	assertP6V2JSONEqual(t, mustP6V2(GetKeyPackageRequestV2(metaGet, bodyGet)), fixture["get_request"])

	metaCreate, bodyCreate, authCreate, err := ParseGroupCreateRequestV2(fixture["create_request"])
	if err != nil {
		t.Fatal(err)
	}
	assertP6V2JSONEqual(t, mustP6V2(GroupCreateRequestV2(metaCreate, bodyCreate, authCreate)), fixture["create_request"])

	metaAdd, bodyAdd, authAdd, err := ParseGroupAddRequestV2(fixture["add_request"])
	if err != nil {
		t.Fatal(err)
	}
	assertP6V2JSONEqual(t, mustP6V2(GroupAddRequestV2(metaAdd, bodyAdd, authAdd)), fixture["add_request"])

	metaRemove, bodyRemove, authRemove, err := ParseGroupRemoveRequestV2(fixture["remove_request"])
	if err != nil {
		t.Fatal(err)
	}
	assertP6V2JSONEqual(t, mustP6V2(GroupRemoveRequestV2(metaRemove, bodyRemove, authRemove)), fixture["remove_request"])

	metaSend, bodySend, authSend, err := ParseGroupSendRequestV2(fixture["send_request"])
	if err != nil {
		t.Fatal(err)
	}
	assertP6V2JSONEqual(t, mustP6V2(GroupSendRequestV2(metaSend, bodySend, authSend)), fixture["send_request"])

	metaNotice, bodyNotice, err := ParseGroupNoticeNotificationV2(fixture["notice_notification"])
	if err != nil {
		t.Fatal(err)
	}
	assertP6V2JSONEqual(t, mustP6V2(GroupNoticeNotificationV2(metaNotice, bodyNotice)), fixture["notice_notification"])

	metaIncoming, bodyIncoming, authIncoming, err := ParseGroupIncomingNotificationV2(fixture["incoming_notification"])
	if err != nil {
		t.Fatal(err)
	}
	assertP6V2JSONEqual(t, mustP6V2(GroupIncomingNotificationV2(metaIncoming, bodyIncoming, authIncoming)), fixture["incoming_notification"])

	if _, err := ParsePublishKeyPackageResultV2(fixture["publish_result"]); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseGetKeyPackageResultV2(fixture["get_result"]); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseGroupCreateResultV2(fixture["create_result"]); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseGroupMembershipResultV2(fixture["add_result"]); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseGroupSendResultV2(fixture["send_result"]); err != nil {
		t.Fatal(err)
	}
}

func TestSharedP6V2CanonicalVectorsMatch(t *testing.T) {
	fixture := loadP6V2Vectors(t)
	var binding V2DIDWBABinding
	encoded, _ := json.Marshal(fixture["member_key_package"].(map[string]any)["did_wba_binding"])
	if err := decodeStrictV2(encoded, &binding); err != nil {
		t.Fatal(err)
	}
	bindingJCS, err := cjson.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	if string(bindingJCS) != fixture["expected_member_binding_jcs"].(string) {
		t.Fatalf("binding mismatch: %s", bindingJCS)
	}
	metaSend, bodySend, _, err := ParseGroupSendRequestV2(fixture["send_request"])
	if err != nil {
		t.Fatal(err)
	}
	aad, err := GroupSendAuthenticatedDataV2(metaSend, bodySend)
	if err != nil {
		t.Fatal(err)
	}
	if string(aad) != fixture["expected_send_authenticated_data_jcs"].(string) {
		t.Fatalf("send AAD mismatch: %s", aad)
	}

	metaAdd, bodyAdd, _, err := ParseGroupAddRequestV2(fixture["add_request"])
	if err != nil {
		t.Fatal(err)
	}
	addBinding, err := GroupAddSubmissionBindingV2(metaAdd, bodyAdd)
	if err != nil {
		t.Fatal(err)
	}
	if string(addBinding) != fixture["expected_add_submission_binding_jcs"].(string) {
		t.Fatalf("add binding mismatch: %s", addBinding)
	}

	metaRemove, bodyRemove, _, err := ParseGroupRemoveRequestV2(fixture["remove_request"])
	if err != nil {
		t.Fatal(err)
	}
	removeBinding, err := GroupRemoveSubmissionBindingV2(metaRemove, bodyRemove)
	if err != nil {
		t.Fatal(err)
	}
	if string(removeBinding) != fixture["expected_remove_submission_binding_jcs"].(string) {
		t.Fatalf("remove binding mismatch: %s", removeBinding)
	}

	plaintext, err := ParseGroupApplicationPlaintextV2(fixture["application_plaintext"])
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalGroupApplicationPlaintextV2(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != fixture["expected_application_plaintext_jcs"].(string) {
		t.Fatalf("plaintext mismatch: %s", canonical)
	}
}

func TestP6V2WireIsClosedAndDeviceBound(t *testing.T) {
	fixture := loadP6V2Vectors(t)
	wire, _ := json.Marshal(fixture)
	for _, internal := range []string{"document_version", "document_hash", "registry_version", "auth_generation"} {
		if bytes.Contains(wire, []byte(internal)) {
			t.Fatalf("internal field leaked: %s", internal)
		}
	}
	request := cloneP6V2(t, fixture["send_request"])
	request["params"].(map[string]any)["meta"].(map[string]any)["unexpected"] = true
	if _, _, _, err := ParseGroupSendRequestV2(request); err == nil {
		t.Fatal("accepted unknown metadata")
	}

	request = cloneP6V2(t, fixture["send_request"])
	request["params"].(map[string]any)["meta"].(map[string]any)["sender_device_id"] = "dev-sibling"
	meta, body, _, err := ParseGroupSendRequestV2(request)
	if err != nil {
		t.Fatal(err)
	}
	tampered, err := GroupSendAuthenticatedDataV2(meta, body)
	if err != nil {
		t.Fatal(err)
	}
	if string(tampered) == fixture["expected_send_authenticated_data_jcs"].(string) {
		t.Fatal("device tamper did not change authenticated_data")
	}

	request = cloneP6V2(t, fixture["add_request"])
	request["params"].(map[string]any)["body"].(map[string]any)["member_device_id"] = "dev-sibling"
	if _, _, _, err := ParseGroupAddRequestV2(request); err == nil {
		t.Fatal("accepted cross-device KeyPackage replay")
	}

	request = cloneP6V2(t, fixture["get_request"])
	request["params"].(map[string]any)["body"].(map[string]any)["require_fresh"] = nil
	if _, _, err := ParseGetKeyPackageRequestV2(request); err == nil {
		t.Fatal("accepted explicit null")
	}
	request = cloneP6V2(t, fixture["send_request"])
	request["params"].(map[string]any)["body"].(map[string]any)["group_state_ref"].(map[string]any)["group_state_version"] = "state:opaque-v42"
	if _, _, _, err := ParseGroupSendRequestV2(request); err != nil {
		t.Fatalf("rejected opaque group_state_version: %v", err)
	}

	entry, ok := LookupV2ProtocolError(5002)
	if !ok || entry.ANPCode != "group.e2ee.did_binding_invalid" || len(V2ProtocolErrors) != 13 {
		t.Fatal("P6 error table mismatch")
	}
}

func TestP6V2BindingVerifiesManifestLeafAndExtensionChain(t *testing.T) {
	generated, err := authentication.CreateDidWBADocument("p6-v2.example", authentication.DidDocumentOptions{
		PathSegments: []string{"agents", "alice"}, DidProfile: authentication.DidProfileE1,
	})
	if err != nil {
		t.Fatal(err)
	}
	document := generated.DidDocument
	did := document["id"].(string)
	delete(document, "proof")
	document["deviceManifest"] = map[string]any{
		"type": "ANPDeviceManifest",
		"devices": []any{map[string]any{
			"device_id": "dev-a", "signing_key_id": did + "#key-1", "e2ee_key_id": did + "#key-3",
			"profiles": []any{"anp.core.binding.v2", "anp.identity.discovery.v2", "anp.group.base.v2", "anp.group.e2ee.v2"},
		}},
	}
	signingKey, err := anp.PrivateKeyFromPEM(generated.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	document, err = proof.GenerateW3CProof(document, signingKey, did+"#key-1", proof.GenerationOptions{
		ProofPurpose: "assertionMethod", ProofType: proof.ProofTypeDataIntegrity,
		Cryptosuite: proof.CryptosuiteEddsaJCS2022, Created: "2026-07-19T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	leafKey := base64.RawURLEncoding.EncodeToString(bytesOfP6V2(7, 32))
	binding, err := GenerateDIDWBABindingV2(V2DIDWBABindingUnsigned{
		AgentDID: did, DeviceID: "dev-a", VerificationMethod: did + "#key-1",
		LeafSignatureKeyB64U: leafKey, IssuedAt: "2026-07-19T00:00:00Z", ExpiresAt: "2026-08-19T00:00:00Z",
	}, signingKey, "2026-07-19T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	extensionData, err := cjson.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	evidence := V2LeafBindingEvidence{
		CredentialIdentity: []byte(did), LeafSignatureKeyB64U: leafKey,
		Extensions:               []V2LeafExtension{{ExtensionType: DIDWBADeviceBindingExtensionDraftV2, ExtensionData: extensionData}},
		LeafCapabilityExtensions: []uint16{DIDWBADeviceBindingExtensionDraftV2},
	}
	if err := VerifyDIDWBABindingV2(binding, document, evidence, []uint16{DIDWBADeviceBindingExtensionDraftV2}, "2026-07-20T00:00:00Z", true); err != nil {
		t.Fatal(err)
	}
	keyPackageBytes := []byte("verified-mls-key-package")
	expiresAt := "2026-08-19T00:00:00Z"
	packageValue := V2GroupKeyPackage{
		KeyPackageID: "kp-dev-a", OwnerDID: did, OwnerDeviceID: "dev-a", Suite: MTISuiteV2,
		MLSKeyPackageB64U: base64.RawURLEncoding.EncodeToString(keyPackageBytes),
		DIDWBABinding:     binding, ExpiresAt: &expiresAt,
	}
	packageEvidence := V2KeyPackageBindingEvidence{TLSSerializedKeyPackage: keyPackageBytes, Leaf: evidence}
	if err := ValidateGroupKeyPackageBindingV2(packageValue, document, packageEvidence, []uint16{DIDWBADeviceBindingExtensionDraftV2}, "2026-07-20T00:00:00Z", true); err != nil {
		t.Fatal(err)
	}
	wrongPackageEvidence := packageEvidence
	wrongPackageEvidence.TLSSerializedKeyPackage = append(append([]byte(nil), keyPackageBytes...), 0)
	if err := ValidateGroupKeyPackageBindingV2(packageValue, document, wrongPackageEvidence, []uint16{DIDWBADeviceBindingExtensionDraftV2}, "2026-07-20T00:00:00Z", true); err == nil {
		t.Fatal("accepted unrelated verified KeyPackage projection")
	}

	tampered := evidence
	tampered.CredentialIdentity = []byte("did:wba:other.example:mallory")
	if err := VerifyDIDWBABindingV2(binding, document, tampered, []uint16{DIDWBADeviceBindingExtensionDraftV2}, "2026-07-20T00:00:00Z", true); err == nil {
		t.Fatal("accepted credential replay")
	}
	tampered = evidence
	tampered.LeafSignatureKeyB64U = base64.RawURLEncoding.EncodeToString(bytesOfP6V2(9, 32))
	if err := VerifyDIDWBABindingV2(binding, document, tampered, []uint16{DIDWBADeviceBindingExtensionDraftV2}, "2026-07-20T00:00:00Z", true); err == nil {
		t.Fatal("accepted leaf-key substitution")
	}
	replayedBinding := binding
	replayedBinding.DeviceID = "dev-sibling"
	replayedExtension, err := cjson.Marshal(replayedBinding)
	if err != nil {
		t.Fatal(err)
	}
	replayedEvidence := evidence
	replayedEvidence.Extensions = []V2LeafExtension{{ExtensionType: DIDWBADeviceBindingExtensionDraftV2, ExtensionData: replayedExtension}}
	if err := VerifyDIDWBABindingV2(replayedBinding, document, replayedEvidence, []uint16{DIDWBADeviceBindingExtensionDraftV2}, "2026-07-20T00:00:00Z", true); err == nil {
		t.Fatal("accepted cross-device binding replay")
	}
	tampered = evidence
	tampered.Extensions = append([]V2LeafExtension(nil), evidence.Extensions...)
	tampered.Extensions[0].ExtensionData = append(append([]byte(nil), extensionData...), 0)
	if err := VerifyDIDWBABindingV2(binding, document, tampered, []uint16{DIDWBADeviceBindingExtensionDraftV2}, "2026-07-20T00:00:00Z", true); err == nil {
		t.Fatal("accepted extension tamper")
	}
	if err := VerifyDIDWBABindingV2(binding, document, evidence, []uint16{DIDWBADeviceBindingExtensionDraftV2}, "2026-07-20T00:00:00Z", false); err == nil {
		t.Fatal("accepted unnegotiated draft extension")
	}
	if err := EnsureP6V2PublicReleaseReady(); err == nil {
		t.Fatal("public release gate unexpectedly open")
	}

	if err := ValidateLeafIdentitySetV2([]V2LeafIdentity{
		{AgentDID: did, DeviceID: "dev-a", LeafSignatureKeyB64U: leafKey},
		{AgentDID: did, DeviceID: "dev-b", LeafSignatureKeyB64U: base64.RawURLEncoding.EncodeToString(bytesOfP6V2(8, 32))},
	}); err != nil {
		t.Fatalf("same DID sibling leaves rejected: %v", err)
	}
}

func mustP6V2(value map[string]any, err error) map[string]any {
	if err != nil {
		panic(err)
	}
	return value
}

func assertP6V2JSONEqual(t *testing.T, actual, expected any) {
	t.Helper()
	if !reflect.DeepEqual(actual, expected) {
		a, _ := json.Marshal(actual)
		e, _ := json.Marshal(expected)
		t.Fatalf("JSON mismatch\nactual: %s\nexpected: %s", a, e)
	}
}

func cloneP6V2(t *testing.T, value any) map[string]any {
	t.Helper()
	encoded, _ := json.Marshal(value)
	var result map[string]any
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func bytesOfP6V2(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}
