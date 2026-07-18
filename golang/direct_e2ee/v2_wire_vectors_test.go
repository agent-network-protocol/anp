package directe2ee

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/authentication"
	"github.com/agent-network-protocol/anp/golang/proof"
)

func loadV2Vectors(t *testing.T) map[string]any {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "direct_e2ee", "p5_v2_wire_vectors.json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(contents, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestV2SharedBundleAndRPCVectors(t *testing.T) {
	vectors := loadV2Vectors(t)
	var bundle V2PrekeyBundle
	if err := decodeV2(vectors["prekey_bundle"], &bundle); err != nil {
		t.Fatal(err)
	}
	canonical, err := SignedBundleObjectJCSV2(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != vectors["expected_signed_bundle_object_jcs"].(string) {
		t.Fatalf("bundle JCS mismatch: %s", canonical)
	}

	meta, body, err := ParsePublishPrekeyBundleRequestV2(vectors["publish_request"])
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := PublishPrekeyBundleRequestV2(meta, body)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rebuilt, vectors["publish_request"]) {
		t.Fatalf("publish request mismatch")
	}

	getMeta, getBody, err := ParseGetPrekeyBundleRequestV2(vectors["get_request"])
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err = GetPrekeyBundleRequestV2(getMeta, getBody)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rebuilt, vectors["get_request"]) {
		t.Fatalf("get request mismatch")
	}

	if _, err := ParsePublishPrekeyBundleResultV2(vectors["publish_result"]); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseGetPrekeyBundleResultV2(vectors["get_result"]); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseDirectSendResultV2(vectors["direct_send_result"]); err != nil {
		t.Fatal(err)
	}

	invalidGet := cloneV2Value(t, vectors["get_result"])
	invalidGet["target_device_id"] = "dev-sibling"
	if _, err := ParseGetPrekeyBundleResultV2(invalidGet); err == nil {
		t.Fatal("accepted mismatched get result device")
	}
	invalidDirect := cloneV2Value(t, vectors["direct_send_result"])
	invalidDirect["operation_id"] = "different-operation"
	if _, err := ParseDirectSendResultV2(invalidDirect); err == nil {
		t.Fatal("accepted mismatched direct.send result identifiers")
	}
	invalidPublish := cloneV2Value(t, vectors["publish_result"])
	invalidPublish["unexpected"] = true
	if _, err := ParsePublishPrekeyBundleResultV2(invalidPublish); err == nil {
		t.Fatal("accepted unknown publish result field")
	}
}

func TestV2SharedSignedBundleGoldenVerifies(t *testing.T) {
	vectors := loadV2Vectors(t)
	golden := vectors["signed_bundle_golden"].(map[string]any)
	var bundle V2PrekeyBundle
	if err := decodeV2(golden["prekey_bundle"], &bundle); err != nil {
		t.Fatal(err)
	}
	var didDocument map[string]any
	encoded, _ := json.Marshal(golden["did_document"])
	if err := json.Unmarshal(encoded, &didDocument); err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339, golden["now"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPrekeyBundleV2(bundle, didDocument, now); err != nil {
		t.Fatalf("cross-language signed bundle failed: %v", err)
	}
	bundle.SignedPrekey.KeyID = "spk-tampered"
	if err := VerifyPrekeyBundleV2(bundle, didDocument, now); err == nil {
		t.Fatal("accepted tampered signed bundle")
	}
}

func cloneV2Value(t *testing.T, value any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestV2SharedAADAndPlaintextVectors(t *testing.T) {
	vectors := loadV2Vectors(t)
	meta, rawBody, err := ParseDirectSendRequestV2(vectors["direct_init_request"])
	if err != nil {
		t.Fatal(err)
	}
	initBody := rawBody.(V2DirectInitBody)
	aad, err := BuildInitAADV2(meta, initBody)
	if err != nil {
		t.Fatal(err)
	}
	if string(aad) != vectors["expected_ad_init"].(string) {
		t.Fatalf("AD_init mismatch: %s", aad)
	}
	rebuilt, err := DirectSendRequestV2(meta, initBody)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rebuilt, vectors["direct_init_request"]) {
		t.Fatal("init request mismatch")
	}

	meta, rawBody, err = ParseDirectSendRequestV2(vectors["direct_cipher_request"])
	if err != nil {
		t.Fatal(err)
	}
	cipherBody := rawBody.(V2DirectCipherBody)
	aad, err = BuildMessageAADV2(meta, cipherBody)
	if err != nil {
		t.Fatal(err)
	}
	if string(aad) != vectors["expected_ad_msg"].(string) {
		t.Fatalf("AD_msg mismatch: %s", aad)
	}

	var plaintext V2ApplicationPlaintext
	if err := decodeV2(vectors["application_plaintext"], &plaintext); err != nil {
		t.Fatal(err)
	}
	plain, err := CanonicalApplicationPlaintextV2(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != vectors["expected_application_plaintext_jcs"].(string) {
		t.Fatalf("plaintext JCS mismatch: %s", plain)
	}
	if err := decodeV2(vectors["application_plaintext_numeric"], &plaintext); err != nil {
		t.Fatal(err)
	}
	plain, err = CanonicalApplicationPlaintextV2(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != vectors["expected_application_plaintext_numeric_jcs"].(string) {
		t.Fatalf("numeric plaintext JCS mismatch: %s", plain)
	}
}

func TestV2DeviceTamperAndForbiddenFields(t *testing.T) {
	vectors := loadV2Vectors(t)
	clone := func() map[string]any {
		encoded, _ := json.Marshal(vectors["direct_init_request"])
		var result map[string]any
		_ = json.Unmarshal(encoded, &result)
		return result
	}
	tampered := clone()
	tampered["params"].(map[string]any)["meta"].(map[string]any)["recipient_device_id"] = "dev-sibling"
	meta, rawBody, err := ParseDirectSendRequestV2(tampered)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := BuildInitAADV2(meta, rawBody.(V2DirectInitBody))
	if err != nil {
		t.Fatal(err)
	}
	if string(aad) == vectors["expected_ad_init"].(string) {
		t.Fatal("device tamper did not change AAD")
	}
	tampered = clone()
	tampered["params"].(map[string]any)["meta"].(map[string]any)["sender_device_id"] = "dev-sender-sibling"
	meta, rawBody, err = ParseDirectSendRequestV2(tampered)
	if err != nil {
		t.Fatal(err)
	}
	aad, err = BuildInitAADV2(meta, rawBody.(V2DirectInitBody))
	if err != nil {
		t.Fatal(err)
	}
	if string(aad) == vectors["expected_ad_init"].(string) {
		t.Fatal("sender device tamper did not change AAD")
	}

	for _, field := range []string{"auth", "deliveries", "root_private_key", "document_version"} {
		invalid := clone()
		invalid["params"].(map[string]any)[field] = map[string]any{}
		if _, _, err := ParseDirectSendRequestV2(invalid); err == nil {
			t.Fatalf("accepted forbidden field %s", field)
		}
	}
	invalid := clone()
	invalid["params"].(map[string]any)["meta"].(map[string]any)["logical_message_id"] = "outer"
	if _, _, err := ParseDirectSendRequestV2(invalid); err == nil {
		t.Fatal("accepted outer logical_message_id")
	}
	invalid = clone()
	invalid["params"].(map[string]any)["meta"].(map[string]any)["operation_id"] = "different-id"
	if _, _, err := ParseDirectSendRequestV2(invalid); err == nil {
		t.Fatal("accepted operation_id != message_id")
	}
}

func TestV2PublishRejectsEmptyOPKsAndBadPublicKey(t *testing.T) {
	vectors := loadV2Vectors(t)
	clone := func() map[string]any {
		encoded, _ := json.Marshal(vectors["publish_request"])
		var result map[string]any
		_ = json.Unmarshal(encoded, &result)
		return result
	}
	invalid := clone()
	invalid["params"].(map[string]any)["body"].(map[string]any)["one_time_prekeys"] = []any{}
	if _, _, err := ParsePublishPrekeyBundleRequestV2(invalid); err == nil {
		t.Fatal("accepted explicit empty one_time_prekeys")
	}
	invalid = clone()
	invalid["params"].(map[string]any)["body"].(map[string]any)["prekey_bundle"].(map[string]any)["signed_prekey"].(map[string]any)["public_key_b64u"] = "AA=="
	if _, _, err := ParsePublishPrekeyBundleRequestV2(invalid); err == nil {
		t.Fatal("accepted padded/non-X25519 public key")
	}
}

func TestV2SharedInvalidWireEncodings(t *testing.T) {
	vectors := loadV2Vectors(t)
	invalid := vectors["encoding_negative_values"].(map[string]any)

	request := cloneV2Value(t, vectors["direct_init_request"])
	request["params"].(map[string]any)["body"].(map[string]any)["session_id"] = invalid["session_id"]
	if _, _, err := ParseDirectSendRequestV2(request); err == nil {
		t.Fatal("accepted invalid session_id")
	}
	request = cloneV2Value(t, vectors["direct_init_request"])
	request["params"].(map[string]any)["body"].(map[string]any)["sender_ephemeral_pub_b64u"] = invalid["x25519_public_key"]
	if _, _, err := ParseDirectSendRequestV2(request); err == nil {
		t.Fatal("accepted invalid sender ephemeral key")
	}
	request = cloneV2Value(t, vectors["direct_init_request"])
	request["params"].(map[string]any)["body"].(map[string]any)["ciphertext_b64u"] = invalid["ciphertext_b64u"]
	if _, _, err := ParseDirectSendRequestV2(request); err == nil {
		t.Fatal("accepted invalid ciphertext")
	}
	request = cloneV2Value(t, vectors["direct_cipher_request"])
	request["params"].(map[string]any)["body"].(map[string]any)["ratchet_header"].(map[string]any)["dh_pub_b64u"] = invalid["x25519_public_key"]
	if _, _, err := ParseDirectSendRequestV2(request); err == nil {
		t.Fatal("accepted invalid ratchet public key")
	}
	request = cloneV2Value(t, vectors["direct_cipher_request"])
	request["params"].(map[string]any)["meta"].(map[string]any)["created_at"] = invalid["created_at"]
	if _, _, err := ParseDirectSendRequestV2(request); err == nil {
		t.Fatal("accepted invalid created_at")
	}
	payload := invalid["payload_b64u"].(string)
	plaintext := V2ApplicationPlaintext{
		ApplicationContentType: "application/octet-stream",
		PayloadB64U:            &payload,
	}
	if err := plaintext.Validate(); err == nil {
		t.Fatal("accepted invalid payload_b64u")
	}
}

func TestV2OptionalMetaDoesNotEnterAADAndErrorsAreExact(t *testing.T) {
	vectors := loadV2Vectors(t)
	meta, rawBody, err := ParseDirectSendRequestV2(vectors["direct_init_request"])
	if err != nil {
		t.Fatal(err)
	}
	original, _ := BuildInitAADV2(meta, rawBody.(V2DirectInitBody))
	meta.ANPVersion = "9.9"
	meta.CreatedAt = "2030-01-01T00:00:00Z"
	changed, _ := BuildInitAADV2(meta, rawBody.(V2DirectInitBody))
	if string(original) != string(changed) {
		t.Fatal("optional outer meta entered AAD")
	}

	errors := vectors["errors"].([]any)
	if len(errors) != len(V2ProtocolErrors) {
		t.Fatal("error table length mismatch")
	}
	for _, raw := range errors {
		expected := raw.(map[string]any)
		entry, ok := DirectE2EEV2ErrorByCode(int(expected["code"].(float64)))
		if !ok || entry.ANPCode != expected["anp_code"].(string) {
			t.Fatalf("error table mismatch: %#v", expected)
		}
	}
	if _, ok := DirectE2EEV2ErrorByCode(5000); ok {
		t.Fatal("accepted non-P5 code")
	}
}

func TestV2RejectsExplicitNullsAndContentBearerMismatches(t *testing.T) {
	vectors := loadV2Vectors(t)
	request := cloneV2Value(t, vectors["direct_init_request"])
	request["params"].(map[string]any)["body"].(map[string]any)["recipient_one_time_prekey_id"] = nil
	if _, _, err := ParseDirectSendRequestV2(request); err == nil {
		t.Fatal("accepted null recipient_one_time_prekey_id")
	}
	for _, field := range []string{"preferred_suite", "require_opk"} {
		request = cloneV2Value(t, vectors["get_request"])
		request["params"].(map[string]any)["body"].(map[string]any)[field] = nil
		if _, _, err := ParseGetPrekeyBundleRequestV2(request); err == nil {
			t.Fatalf("accepted null %s", field)
		}
	}

	invalidPlaintexts := []map[string]any{
		{"application_content_type": "text/plain", "payload": map[string]any{}},
		{"application_content_type": "application/json", "text": "wrong"},
		{"application_content_type": "application/json", "annotations": []any{}, "payload": map[string]any{}},
		{"application_content_type": "application/json", "annotations": nil, "payload": map[string]any{}},
	}
	for _, raw := range invalidPlaintexts {
		var plaintext V2ApplicationPlaintext
		if err := decodeV2(raw, &plaintext); err == nil {
			if err := plaintext.Validate(); err == nil {
				t.Fatalf("accepted invalid plaintext: %#v", raw)
			}
		}
	}
}

func TestV2BundleObjectProofCoversDeviceAndStaticFields(t *testing.T) {
	generated, err := authentication.CreateDidWBADocument("bundle-v2.example", authentication.DidDocumentOptions{
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
			"device_id": "dev-a", "signing_key_id": did + "#key-1",
			"e2ee_key_id": did + "#key-3",
			"profiles":    []any{"anp.core.binding.v2", "anp.identity.discovery.v2", "anp.direct.base.v2", "anp.direct.e2ee.v2"},
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
	bundle, err := BuildPrekeyBundleV2(
		"bundle-v2", did, "dev-a", did+"#key-3",
		V2SignedPrekey{KeyID: "spk-v2", PublicKeyB64U: "UKYUCbHd0DJemxa3AOcZ6XcsBwALG9d4bpB8ZT0gSV0", ExpiresAt: "2035-01-01T00:00:00Z"},
		signingKey, did+"#key-1", "2026-07-19T00:00:00Z",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPrekeyBundleV2(
		"bundle-invalid", did, "dev-a", did+"#key-3",
		V2SignedPrekey{KeyID: "spk-invalid", PublicKeyB64U: "AA==", ExpiresAt: "not-rfc3339"},
		signingKey, did+"#key-1", "2026-07-19T00:00:00Z",
	); err == nil {
		t.Fatal("builder accepted invalid signed prekey")
	}
	if err := VerifyPrekeyBundleV2(bundle, document, time.Date(2026, 7, 19, 0, 0, 1, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	tampered := bundle
	tampered.OwnerDeviceID = "dev-sibling"
	if err := VerifyPrekeyBundleV2(tampered, document, time.Date(2026, 7, 19, 0, 0, 1, 0, time.UTC)); err == nil {
		t.Fatal("owner_device_id tamper passed")
	}
	tampered = bundle
	tampered.StaticKeyAgreementID = did + "#other"
	if err := VerifyPrekeyBundleV2(tampered, document, time.Date(2026, 7, 19, 0, 0, 1, 0, time.UTC)); err == nil {
		t.Fatal("static key tamper passed")
	}
}
