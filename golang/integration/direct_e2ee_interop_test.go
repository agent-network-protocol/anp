package integration

import (
	"crypto/ecdh"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/authentication"
	directe2ee "github.com/agent-network-protocol/anp/golang/direct_e2ee"
)

func TestRustDirectE2EEFixtureDecryptsInGo(t *testing.T) {
	t.Skip("legacy pre-P5 direct_e2ee interop fixture; P5 shared-vector interop replaces this test")
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo is unavailable; skipping Rust direct_e2ee interop test")
	}
	fixture := runJSONCommand(t, filepath.Join(repoRoot(t), "rust"), "cargo", "run", "--quiet", "--example", "direct_e2ee_interop_cli", "--", "fixture")
	runGoDirectE2EEFixtureAssertions(t, fixture)
}

func TestPythonDirectE2EEFixtureDecryptsInGo(t *testing.T) {
	t.Skip("legacy pre-P5 direct_e2ee interop fixture; P5 shared-vector interop replaces this test")
	if _, err := exec.LookPath("uv"); err != nil {
		t.Skip("uv is unavailable; skipping Python direct_e2ee interop test")
	}
	fixture := runJSONCommand(t, repoRoot(t), "uv", "run", "--python", "3.13", "--with-editable", repoRoot(t), "python", filepath.Join(repoRoot(t), "golang", "integration", "python_direct_e2ee_fixture.py"))
	runGoDirectE2EEFixtureAssertions(t, fixture)
}

func TestGoDirectE2EEFixtureDecryptsInPython(t *testing.T) {
	t.Skip("legacy pre-P5 direct_e2ee interop fixture; P5 shared-vector interop replaces this test")
	if _, err := exec.LookPath("uv"); err != nil {
		t.Skip("uv is unavailable; skipping Python direct_e2ee interop verification")
	}
	fixturePath := filepath.Join(t.TempDir(), "go_direct_e2ee_fixture.json")
	fixture := buildGoDirectE2EEFixture(t)
	encoded, err := json.Marshal(fixture)
	if err != nil {
		t.Fatalf("Marshal fixture failed: %v", err)
	}
	if err := os.WriteFile(fixturePath, encoded, 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	result := runJSONCommand(t, repoRoot(t), "uv", "run", "--python", "3.13", "--with-editable", repoRoot(t), "python", filepath.Join(repoRoot(t), "golang", "integration", "python_verify_go_direct_e2ee_fixture.py"), fixturePath)
	if result["init_text"] != "hello bob" {
		t.Fatalf("unexpected Python init_text: %+v", result)
	}
	payload, ok := result["follow_up_payload"].(map[string]any)
	if !ok || payload["event"] != "wave" {
		t.Fatalf("unexpected Python follow_up_payload: %+v", result)
	}
}

func TestGoDirectE2EEFixtureDecryptsInRust(t *testing.T) {
	t.Skip("legacy pre-P5 direct_e2ee interop fixture; P5 shared-vector interop replaces this test")
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo is unavailable; skipping Rust direct_e2ee interop verification")
	}
	fixturePath := filepath.Join(t.TempDir(), "go_direct_e2ee_fixture.json")
	fixture := buildGoDirectE2EEFixture(t)
	encoded, err := json.Marshal(fixture)
	if err != nil {
		t.Fatalf("Marshal fixture failed: %v", err)
	}
	if err := os.WriteFile(fixturePath, encoded, 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	result := runJSONCommand(t, filepath.Join(repoRoot(t), "rust"), "cargo", "run", "--quiet", "--example", "direct_e2ee_verify_fixture", "--", "fixture", fixturePath)
	if verified, _ := result["verified"].(bool); !verified {
		t.Fatalf("rust verifier did not confirm Go direct_e2ee fixture: %+v", result)
	}
}

func TestRustDirectE2EETamperedCipherRejectedInGo(t *testing.T) {
	t.Skip("legacy pre-P5 direct_e2ee interop fixture; P5 shared-vector interop replaces this test")
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo is unavailable; skipping Rust direct_e2ee tamper test")
	}
	fixture := runJSONCommand(t, filepath.Join(repoRoot(t), "rust"), "cargo", "run", "--quiet", "--example", "direct_e2ee_interop_cli", "--", "fixture")
	var initMetadata directe2ee.DirectEnvelopeMetadata
	decodeStruct(t, fixture["init_metadata"], &initMetadata)
	var followUpMetadata directe2ee.DirectEnvelopeMetadata
	decodeStruct(t, fixture["follow_up_metadata"], &followUpMetadata)
	var initBody directe2ee.DirectInitBody
	decodeStruct(t, fixture["init_body"], &initBody)
	var cipherBody directe2ee.DirectCipherBody
	decodeStruct(t, fixture["cipher_body"], &cipherBody)
	cipherBody.CiphertextB64U = mutateBase64URL(cipherBody.CiphertextB64U)

	var aliceDoc map[string]any
	decodeStruct(t, fixture["alice_did_document"], &aliceDoc)
	var bobDoc map[string]any
	decodeStruct(t, fixture["bob_did_document"], &bobDoc)
	bobStatic := mustECDHPrivateKey(t, fixture["bob_static_private_key_b64u"].(string))
	bobSPK := mustECDHPrivateKey(t, fixture["bob_signed_prekey_private_key_b64u"].(string))
	senderStaticPublic, err := directe2ee.ExtractX25519PublicKey(aliceDoc, initBody.SenderStaticKeyAgreementID)
	if err != nil {
		t.Fatalf("ExtractX25519PublicKey failed: %v", err)
	}
	sessionBuilder := directe2ee.DirectE2eeSession{}
	session, _, err := sessionBuilder.AcceptIncomingInit(initMetadata, stringValue(bobDoc["id"])+"#"+authentication.VMKeyE2EEAgreement, bobStatic, bobSPK, senderStaticPublic, initBody)
	if err != nil {
		t.Fatalf("AcceptIncomingInit failed: %v", err)
	}
	if _, err := sessionBuilder.DecryptFollowUp(&session, followUpMetadata, cipherBody, "application/json"); err == nil {
		t.Fatalf("expected tampered cipher body to fail decryption")
	}
}

func TestPythonDirectE2EEReplayRejectedInGo(t *testing.T) {
	t.Skip("legacy pre-P5 direct_e2ee interop fixture; P5 shared-vector interop replaces this test")
	if _, err := exec.LookPath("uv"); err != nil {
		t.Skip("uv is unavailable; skipping Python direct_e2ee replay test")
	}
	fixture := runJSONCommand(t, repoRoot(t), "uv", "run", "--python", "3.13", "--with-editable", repoRoot(t), "python", filepath.Join(repoRoot(t), "golang", "integration", "python_direct_e2ee_fixture.py"))
	var aliceDoc map[string]any
	decodeStruct(t, fixture["alice_did_document"], &aliceDoc)
	var bobDoc map[string]any
	decodeStruct(t, fixture["bob_did_document"], &bobDoc)
	var initMetadata directe2ee.DirectEnvelopeMetadata
	decodeStruct(t, fixture["init_metadata"], &initMetadata)
	var followUpMetadata directe2ee.DirectEnvelopeMetadata
	decodeStruct(t, fixture["follow_up_metadata"], &followUpMetadata)
	var initBody directe2ee.DirectInitBody
	decodeStruct(t, fixture["init_body"], &initBody)
	var cipherBody directe2ee.DirectCipherBody
	decodeStruct(t, fixture["cipher_body"], &cipherBody)
	bobStatic := mustECDHPrivateKey(t, fixture["bob_static_private_key_b64u"].(string))
	bobSPK := mustECDHPrivateKey(t, fixture["bob_signed_prekey_private_key_b64u"].(string))
	senderStaticPublic, err := directe2ee.ExtractX25519PublicKey(aliceDoc, initBody.SenderStaticKeyAgreementID)
	if err != nil {
		t.Fatalf("ExtractX25519PublicKey failed: %v", err)
	}
	sessionBuilder := directe2ee.DirectE2eeSession{}
	session, _, err := sessionBuilder.AcceptIncomingInit(initMetadata, stringValue(bobDoc["id"])+"#"+authentication.VMKeyE2EEAgreement, bobStatic, bobSPK, senderStaticPublic, initBody)
	if err != nil {
		t.Fatalf("AcceptIncomingInit failed: %v", err)
	}
	if _, err := sessionBuilder.DecryptFollowUp(&session, followUpMetadata, cipherBody, "application/json"); err != nil {
		t.Fatalf("DecryptFollowUp first pass failed: %v", err)
	}
	if _, err := sessionBuilder.DecryptFollowUp(&session, followUpMetadata, cipherBody, "application/json"); err == nil {
		t.Fatalf("expected replay detection for duplicate follow-up message")
	}
}

func TestRustDirectE2EESkipOverflowRejectedInGo(t *testing.T) {
	t.Skip("legacy pre-P5 direct_e2ee interop fixture; P5 shared-vector interop replaces this test")
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo is unavailable; skipping Rust direct_e2ee skip overflow test")
	}
	fixture := runJSONCommand(t, filepath.Join(repoRoot(t), "rust"), "cargo", "run", "--quiet", "--example", "direct_e2ee_interop_cli", "--", "fixture")
	var aliceDoc map[string]any
	decodeStruct(t, fixture["alice_did_document"], &aliceDoc)
	var bobDoc map[string]any
	decodeStruct(t, fixture["bob_did_document"], &bobDoc)
	var initMetadata directe2ee.DirectEnvelopeMetadata
	decodeStruct(t, fixture["init_metadata"], &initMetadata)
	var followUpMetadata directe2ee.DirectEnvelopeMetadata
	decodeStruct(t, fixture["follow_up_metadata"], &followUpMetadata)
	var initBody directe2ee.DirectInitBody
	decodeStruct(t, fixture["init_body"], &initBody)
	var cipherBody directe2ee.DirectCipherBody
	decodeStruct(t, fixture["cipher_body"], &cipherBody)
	cipherBody.RatchetHeader.N = "1001"
	bobStatic := mustECDHPrivateKey(t, fixture["bob_static_private_key_b64u"].(string))
	bobSPK := mustECDHPrivateKey(t, fixture["bob_signed_prekey_private_key_b64u"].(string))
	senderStaticPublic, err := directe2ee.ExtractX25519PublicKey(aliceDoc, initBody.SenderStaticKeyAgreementID)
	if err != nil {
		t.Fatalf("ExtractX25519PublicKey failed: %v", err)
	}
	sessionBuilder := directe2ee.DirectE2eeSession{}
	session, _, err := sessionBuilder.AcceptIncomingInit(initMetadata, stringValue(bobDoc["id"])+"#"+authentication.VMKeyE2EEAgreement, bobStatic, bobSPK, senderStaticPublic, initBody)
	if err != nil {
		t.Fatalf("AcceptIncomingInit failed: %v", err)
	}
	if _, err := sessionBuilder.DecryptFollowUp(&session, followUpMetadata, cipherBody, "application/json"); err == nil {
		t.Fatalf("expected skip overflow to fail")
	}
}

func runGoDirectE2EEFixtureAssertions(t *testing.T, fixture map[string]any) {
	t.Helper()
	var bundle directe2ee.PrekeyBundle
	decodeStruct(t, fixture["bundle"], &bundle)
	var aliceDoc map[string]any
	decodeStruct(t, fixture["alice_did_document"], &aliceDoc)
	var bobDoc map[string]any
	decodeStruct(t, fixture["bob_did_document"], &bobDoc)
	if err := directe2ee.VerifyPrekeyBundle(bundle, bobDoc); err != nil {
		t.Fatalf("VerifyPrekeyBundle failed: %v", err)
	}
	bobStatic := mustECDHPrivateKey(t, fixture["bob_static_private_key_b64u"].(string))
	bobSPK := mustECDHPrivateKey(t, fixture["bob_signed_prekey_private_key_b64u"].(string))
	var initMetadata directe2ee.DirectEnvelopeMetadata
	decodeStruct(t, fixture["init_metadata"], &initMetadata)
	var followUpMetadata directe2ee.DirectEnvelopeMetadata
	decodeStruct(t, fixture["follow_up_metadata"], &followUpMetadata)
	var initBody directe2ee.DirectInitBody
	decodeStruct(t, fixture["init_body"], &initBody)
	var cipherBody directe2ee.DirectCipherBody
	decodeStruct(t, fixture["cipher_body"], &cipherBody)
	senderStaticPublic, err := directe2ee.ExtractX25519PublicKey(aliceDoc, initBody.SenderStaticKeyAgreementID)
	if err != nil {
		t.Fatalf("ExtractX25519PublicKey failed: %v", err)
	}
	sessionBuilder := directe2ee.DirectE2eeSession{}
	session, plaintext, err := sessionBuilder.AcceptIncomingInit(initMetadata, stringValue(bobDoc["id"])+"#"+authentication.VMKeyE2EEAgreement, bobStatic, bobSPK, senderStaticPublic, initBody)
	if err != nil {
		t.Fatalf("AcceptIncomingInit failed: %v", err)
	}
	if plaintext.Text != fixture["init_plaintext"].(map[string]any)["text"] {
		t.Fatalf("unexpected init plaintext: %+v", plaintext)
	}
	decrypted, err := sessionBuilder.DecryptFollowUp(&session, followUpMetadata, cipherBody, "application/json")
	if err != nil {
		t.Fatalf("DecryptFollowUp failed: %v", err)
	}
	if decrypted.Payload["event"] != fixture["follow_up_plaintext"].(map[string]any)["payload"].(map[string]any)["event"] {
		t.Fatalf("unexpected follow-up payload: %+v", decrypted.Payload)
	}
}

func buildGoDirectE2EEFixture(t *testing.T) map[string]any {
	t.Helper()
	aliceBundle, err := authentication.CreateDidWBADocument("a.example", authentication.DidDocumentOptions{PathSegments: []string{"agents", "alice"}, EnableE2EE: boolPtr(true)})
	if err != nil {
		t.Fatalf("alice CreateDidWBADocument failed: %v", err)
	}
	bobBundle, err := authentication.CreateDidWBADocument("b.example", authentication.DidDocumentOptions{PathSegments: []string{"agents", "bob"}, EnableE2EE: boolPtr(true)})
	if err != nil {
		t.Fatalf("bob CreateDidWBADocument failed: %v", err)
	}
	aliceDID := stringValue(aliceBundle.DidDocument["id"])
	bobDID := stringValue(bobBundle.DidDocument["id"])
	aliceStatic := loadECDHPrivateFromPEM(t, aliceBundle.Keys[authentication.VMKeyE2EEAgreement].PrivateKeyPEM)
	bobStatic := loadECDHPrivateFromPEM(t, bobBundle.Keys[authentication.VMKeyE2EEAgreement].PrivateKeyPEM)
	bobSPK, err := ecdh.X25519().GenerateKey(randReader())
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	bobSigning, err := anp.PrivateKeyFromPEM(bobBundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatalf("PrivateKeyFromPEM failed: %v", err)
	}
	bundle, err := directe2ee.BuildPrekeyBundle("bundle-001", bobDID, bobDID+"#"+authentication.VMKeyE2EEAgreement, directe2ee.SignedPrekeyFromPrivateKey("spk-001", bobSPK, "2026-04-07T00:00:00Z"), bobSigning, bobDID+"#"+authentication.VMKeyAuth, "2026-03-31T09:58:58Z")
	if err != nil {
		t.Fatalf("BuildPrekeyBundle failed: %v", err)
	}
	initMetadata := directe2ee.DirectEnvelopeMetadata{SenderDID: aliceDID, RecipientDID: bobDID, MessageID: "msg-init", Profile: "anp.direct.e2ee.v1", SecurityProfile: "direct-e2ee"}
	sessionBuilder := directe2ee.DirectE2eeSession{}
	aliceSession, _, initBody, err := sessionBuilder.InitiateSession(initMetadata, "op-init", aliceDID+"#"+authentication.VMKeyE2EEAgreement, aliceStatic, bundle, bytesTo32(t, bobStatic.PublicKey().Bytes()), bytesTo32(t, bobSPK.PublicKey().Bytes()), directe2ee.NewTextPlaintext("text/plain", "hello bob"))
	if err != nil {
		t.Fatalf("InitiateSession failed: %v", err)
	}
	followUpMetadata := directe2ee.DirectEnvelopeMetadata{SenderDID: aliceDID, RecipientDID: bobDID, MessageID: "msg-2", Profile: "anp.direct.e2ee.v1", SecurityProfile: "direct-e2ee"}
	_, cipherBody, err := sessionBuilder.EncryptFollowUp(&aliceSession, followUpMetadata, "op-2", directe2ee.NewJSONPlaintext("application/json", map[string]any{"event": "wave"}))
	if err != nil {
		t.Fatalf("EncryptFollowUp failed: %v", err)
	}
	return map[string]any{
		"alice_did_document":                 aliceBundle.DidDocument,
		"bob_did_document":                   bobBundle.DidDocument,
		"bundle":                             bundle,
		"bob_static_private_key_b64u":        anp.EncodeBase64URL(bobStatic.Bytes()),
		"bob_signed_prekey_private_key_b64u": anp.EncodeBase64URL(bobSPK.Bytes()),
		"init_metadata":                      initMetadata,
		"follow_up_metadata":                 followUpMetadata,
		"init_body":                          initBody,
		"cipher_body":                        cipherBody,
		"init_plaintext":                     map[string]any{"application_content_type": "text/plain", "text": "hello bob"},
		"follow_up_plaintext":                map[string]any{"application_content_type": "application/json", "payload": map[string]any{"event": "wave"}},
	}
}

func decodeStruct(t *testing.T, input any, target any) {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
}

func mustECDHPrivateKey(t *testing.T, value string) *ecdh.PrivateKey {
	t.Helper()
	bytes, err := anp.DecodeBase64URL(value)
	if err != nil {
		t.Fatalf("DecodeBase64URL failed: %v", err)
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(bytes)
	if err != nil {
		t.Fatalf("NewPrivateKey failed: %v", err)
	}
	return privateKey
}

func loadECDHPrivateFromPEM(t *testing.T, pemValue string) *ecdh.PrivateKey {
	t.Helper()
	privateKey, err := anp.PrivateKeyFromPEM(pemValue)
	if err != nil {
		t.Fatalf("PrivateKeyFromPEM failed: %v", err)
	}
	result, err := ecdh.X25519().NewPrivateKey(privateKey.Bytes)
	if err != nil {
		t.Fatalf("NewPrivateKey failed: %v", err)
	}
	return result
}

func bytesTo32(t *testing.T, input []byte) [32]byte {
	t.Helper()
	if len(input) != 32 {
		t.Fatalf("expected 32-byte value, got %d", len(input))
	}
	var result [32]byte
	copy(result[:], input)
	return result
}

func randReader() *zeroReader { return &zeroReader{} }

type zeroReader struct{}

func (*zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i + 1)
	}
	return len(p), nil
}

func boolPtr(value bool) *bool { return &value }

func stringValue(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func mutateBase64URL(value string) string {
	if value == "" {
		return value
	}
	last := value[len(value)-1]
	if last == 'A' {
		return value[:len(value)-1] + "B"
	}
	return value[:len(value)-1] + "A"
}
