package directe2ee

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"path/filepath"
	"testing"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/authentication"
)

func TestPrekeyBundleRoundTrip(t *testing.T) {
	bobBundle, err := authentication.CreateDidWBADocument("b.example", authentication.DidDocumentOptions{PathSegments: []string{"agents", "bob"}, EnableE2EE: boolPtr(true)})
	if err != nil {
		t.Fatalf("CreateDidWBADocument failed: %v", err)
	}
	bobDID := stringValue(bobBundle.DidDocument["id"])
	signingPrivateKey, err := anp.PrivateKeyFromPEM(bobBundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatalf("PrivateKeyFromPEM failed: %v", err)
	}
	store, err := NewFileSignedPrekeyStore(filepath.Join(t.TempDir(), "spk"))
	if err != nil {
		t.Fatalf("NewFileSignedPrekeyStore failed: %v", err)
	}
	manager := NewPrekeyManager(bobDID, bobDID+"#"+authentication.VMKeyE2EEAgreement, signingPrivateKey, bobDID+"#"+authentication.VMKeyAuth, store, nil)
	_, signedPrekey, err := manager.GenerateSignedPrekey("spk-bob-001", "2026-04-07T00:00:00Z")
	if err != nil {
		t.Fatalf("GenerateSignedPrekey failed: %v", err)
	}
	bundle, err := manager.BuildPrekeyBundle(signedPrekey, "bundle-bob-001", "2026-03-31T09:58:58Z")
	if err != nil {
		t.Fatalf("BuildPrekeyBundle failed: %v", err)
	}
	if err := VerifyPrekeyBundle(bundle, bobBundle.DidDocument); err != nil {
		t.Fatalf("VerifyPrekeyBundle failed: %v", err)
	}
}

func TestSessionInitAndFollowUpRoundTrip(t *testing.T) {
	aliceDoc, bobDoc, aliceStatic, bobStatic, bobSPK, bundle := buildSessionFixtures(t)
	aliceDID := stringValue(aliceDoc["id"])
	bobDID := stringValue(bobDoc["id"])
	sessionBuilder := DirectE2eeSession{}
	metadata := DirectEnvelopeMetadata{SenderDID: aliceDID, RecipientDID: bobDID, MessageID: "msg-init", Profile: "anp.direct.e2ee.v1", SecurityProfile: "direct-e2ee"}
	aliceSession, _, initBody, err := sessionBuilder.InitiateSession(metadata, "op-init", aliceDID+"#"+authentication.VMKeyE2EEAgreement, aliceStatic, bundle, bytesTo32(t, bobStatic.PublicKey().Bytes()), bytesTo32(t, bobSPK.PublicKey().Bytes()), NewTextPlaintext("text/plain", "hello bob"))
	if err != nil {
		t.Fatalf("InitiateSession failed: %v", err)
	}
	bobSession, plaintext, err := sessionBuilder.AcceptIncomingInit(metadata, bobDID+"#"+authentication.VMKeyE2EEAgreement, bobStatic, bobSPK, bytesTo32(t, aliceStatic.PublicKey().Bytes()), initBody)
	if err != nil {
		t.Fatalf("AcceptIncomingInit failed: %v", err)
	}
	if plaintext.Text != "hello bob" {
		t.Fatalf("unexpected init plaintext: %+v", plaintext)
	}
	followUpMetadata := DirectEnvelopeMetadata{SenderDID: aliceDID, RecipientDID: bobDID, MessageID: "msg-2", Profile: "anp.direct.e2ee.v1", SecurityProfile: "direct-e2ee"}
	_, cipherBody, err := sessionBuilder.EncryptFollowUp(&aliceSession, followUpMetadata, "op-2", NewJSONPlaintext("application/json", map[string]any{"event": "wave"}))
	if err != nil {
		t.Fatalf("EncryptFollowUp failed: %v", err)
	}
	decrypted, err := sessionBuilder.DecryptFollowUp(&bobSession, followUpMetadata, cipherBody, "application/json")
	if err != nil {
		t.Fatalf("DecryptFollowUp failed: %v", err)
	}
	if decrypted.Payload["event"] != "wave" {
		t.Fatalf("unexpected follow-up payload: %+v", decrypted.Payload)
	}
}

func TestClientSendAndPendingHistoryProcessing(t *testing.T) {
	aliceBundle, err := authentication.CreateDidWBADocument("a.example", authentication.DidDocumentOptions{PathSegments: []string{"agents", "alice"}, EnableE2EE: boolPtr(true)})
	if err != nil {
		t.Fatalf("alice CreateDidWBADocument failed: %v", err)
	}
	bobBundle, err := authentication.CreateDidWBADocument("b.example", authentication.DidDocumentOptions{PathSegments: []string{"agents", "bob"}, EnableE2EE: boolPtr(true)})
	if err != nil {
		t.Fatalf("bob CreateDidWBADocument failed: %v", err)
	}
	aliceDoc := aliceBundle.DidDocument
	bobDoc := bobBundle.DidDocument
	aliceStatic := loadECDHPrivateKey(t, aliceBundle.Keys[authentication.VMKeyE2EEAgreement].PrivateKeyPEM)
	bobStatic := loadECDHPrivateKey(t, bobBundle.Keys[authentication.VMKeyE2EEAgreement].PrivateKeyPEM)
	aliceDID := stringValue(aliceDoc["id"])
	bobDID := stringValue(bobDoc["id"])
	aliceSigning, err := anp.PrivateKeyFromPEM(aliceBundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatalf("alice signing key: %v", err)
	}
	bobSigning, err := anp.PrivateKeyFromPEM(bobBundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatalf("bob signing key: %v", err)
	}
	bobSPKStore, err := NewFileSignedPrekeyStore(filepath.Join(t.TempDir(), "bob-spk"))
	if err != nil {
		t.Fatalf("NewFileSignedPrekeyStore failed: %v", err)
	}
	bobManager := NewPrekeyManager(bobDID, bobDID+"#"+authentication.VMKeyE2EEAgreement, bobSigning, bobDID+"#"+authentication.VMKeyAuth, bobSPKStore, nil)
	_, signedPrekey, err := bobManager.GenerateSignedPrekey("spk-bob-001", "2026-04-07T00:00:00Z")
	if err != nil {
		t.Fatalf("GenerateSignedPrekey failed: %v", err)
	}
	bundle, err := bobManager.BuildPrekeyBundle(signedPrekey, "bundle-bob-001", "")
	if err != nil {
		t.Fatalf("BuildPrekeyBundle failed: %v", err)
	}
	rpc := &fakeRPCClient{prekeyBundle: bundleToMap(bundle)}
	aliceSessionStore, _ := NewFileSessionStore(filepath.Join(t.TempDir(), "alice-sessions"))
	aliceSPKStore, _ := NewFileSignedPrekeyStore(filepath.Join(t.TempDir(), "alice-spk"))
	aliceClient, err := NewMessageServiceDirectE2eeClient(aliceDID, aliceSigning, aliceDID+"#"+authentication.VMKeyAuth, fromECDHPrivateKey(t, aliceStatic), aliceDID+"#"+authentication.VMKeyE2EEAgreement, rpc.Call, resolverFor(aliceDoc, bobDoc), aliceSessionStore, aliceSPKStore)
	if err != nil {
		t.Fatalf("NewMessageServiceDirectE2eeClient failed: %v", err)
	}
	initResponse, err := aliceClient.SendText(context.Background(), bobDID, "hello bob", "op-init", "msg-init")
	if err != nil {
		t.Fatalf("SendText failed: %v", err)
	}
	followUpResponse, err := aliceClient.SendJSON(context.Background(), bobDID, map[string]any{"event": "wave"}, "op-2", "msg-2")
	if err != nil {
		t.Fatalf("SendJSON failed: %v", err)
	}
	bobSessionStore, _ := NewFileSessionStore(filepath.Join(t.TempDir(), "bob-sessions"))
	bobClient, err := NewMessageServiceDirectE2eeClient(bobDID, bobSigning, bobDID+"#"+authentication.VMKeyAuth, fromECDHPrivateKey(t, bobStatic), bobDID+"#"+authentication.VMKeyE2EEAgreement, rpc.Call, resolverFor(aliceDoc, bobDoc), bobSessionStore, bobSPKStore)
	if err != nil {
		t.Fatalf("NewMessageServiceDirectE2eeClient failed: %v", err)
	}
	pending, err := bobClient.ProcessIncoming(context.Background(), map[string]any{"meta": map[string]any{"sender_did": aliceDID, "target": map[string]any{"kind": "agent", "did": bobDID}, "message_id": "msg-2", "profile": "anp.direct.e2ee.v1", "security_profile": "direct-e2ee", "content_type": "application/anp-direct-cipher+json"}, "body": followUpResponse["body"], "server_seq": 2.0})
	if err != nil {
		t.Fatalf("ProcessIncoming pending failed: %v", err)
	}
	if pending["state"] != "pending" {
		t.Fatalf("expected pending state, got %+v", pending)
	}
	decrypted, err := bobClient.ProcessIncoming(context.Background(), map[string]any{"meta": map[string]any{"sender_did": aliceDID, "target": map[string]any{"kind": "agent", "did": bobDID}, "message_id": "msg-init", "profile": "anp.direct.e2ee.v1", "security_profile": "direct-e2ee", "content_type": "application/anp-direct-init+json"}, "body": initResponse["body"], "server_seq": 1.0})
	if err != nil {
		t.Fatalf("ProcessIncoming init failed: %v", err)
	}
	if decrypted["state"] != "decrypted" {
		t.Fatalf("unexpected decrypted state: %+v", decrypted)
	}
	plaintext := decrypted["plaintext"].(map[string]any)
	if plaintext["text"] != "hello bob" {
		t.Fatalf("unexpected plaintext: %+v", plaintext)
	}
	pendingResults := decrypted["pending_results"].([]any)
	if len(pendingResults) != 1 {
		t.Fatalf("unexpected pending results: %+v", pendingResults)
	}
}

type fakeRPCClient struct {
	prekeyBundle map[string]any
	calls        [][2]any
}

func (f *fakeRPCClient) Call(method string, params map[string]any) (map[string]any, error) {
	f.calls = append(f.calls, [2]any{method, params})
	switch method {
	case "direct.e2ee.publish_prekey_bundle":
		bundle := params["body"].(map[string]any)["prekey_bundle"].(map[string]any)
		return map[string]any{"published": true, "owner_did": bundle["owner_did"], "bundle_id": bundle["bundle_id"], "published_at": "2026-03-31T09:59:01Z"}, nil
	case "direct.e2ee.get_prekey_bundle":
		return map[string]any{"target_did": params["body"].(map[string]any)["target_did"], "prekey_bundle": f.prekeyBundle}, nil
	case "direct.send":
		meta := params["meta"].(map[string]any)
		return map[string]any{"accepted": true, "message_id": meta["message_id"], "operation_id": meta["operation_id"], "target_did": meta["target"].(map[string]any)["did"], "body": params["body"]}, nil
	default:
		return nil, invalidField("unexpected RPC method: " + method)
	}
}

func buildSessionFixtures(t *testing.T) (map[string]any, map[string]any, *ecdh.PrivateKey, *ecdh.PrivateKey, *ecdh.PrivateKey, PrekeyBundle) {
	t.Helper()
	aliceBundle, err := authentication.CreateDidWBADocument("a.example", authentication.DidDocumentOptions{PathSegments: []string{"agents", "alice"}, EnableE2EE: boolPtr(true)})
	if err != nil {
		t.Fatalf("alice CreateDidWBADocument failed: %v", err)
	}
	bobBundle, err := authentication.CreateDidWBADocument("b.example", authentication.DidDocumentOptions{PathSegments: []string{"agents", "bob"}, EnableE2EE: boolPtr(true)})
	if err != nil {
		t.Fatalf("bob CreateDidWBADocument failed: %v", err)
	}
	aliceStatic := loadECDHPrivateKey(t, aliceBundle.Keys[authentication.VMKeyE2EEAgreement].PrivateKeyPEM)
	bobStatic := loadECDHPrivateKey(t, bobBundle.Keys[authentication.VMKeyE2EEAgreement].PrivateKeyPEM)
	bobSPK, err := ecdh.X25519().GenerateKey(randReader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	bobSigning, err := anp.PrivateKeyFromPEM(bobBundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatalf("bob signing key failed: %v", err)
	}
	bundle, err := BuildPrekeyBundle("bundle-001", stringValue(bobBundle.DidDocument["id"]), stringValue(bobBundle.DidDocument["id"])+"#"+authentication.VMKeyE2EEAgreement, SignedPrekeyFromPrivateKey("spk-001", bobSPK, "2026-04-07T00:00:00Z"), bobSigning, stringValue(bobBundle.DidDocument["id"])+"#"+authentication.VMKeyAuth, "2026-03-31T09:58:58Z")
	if err != nil {
		t.Fatalf("BuildPrekeyBundle failed: %v", err)
	}
	return aliceBundle.DidDocument, bobBundle.DidDocument, aliceStatic, bobStatic, bobSPK, bundle
}

func loadECDHPrivateKey(t *testing.T, pemValue string) *ecdh.PrivateKey {
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

func fromECDHPrivateKey(t *testing.T, privateKey *ecdh.PrivateKey) anp.PrivateKeyMaterial {
	t.Helper()
	return anp.PrivateKeyMaterial{Type: anp.KeyTypeX25519, Bytes: append([]byte(nil), privateKey.Bytes()...)}
}

func resolverFor(aliceDoc map[string]any, bobDoc map[string]any) DIDResolver {
	aliceDID := stringValue(aliceDoc["id"])
	bobDID := stringValue(bobDoc["id"])
	return func(_ context.Context, did string) (map[string]any, error) {
		switch did {
		case aliceDID:
			return cloneMap(aliceDoc), nil
		case bobDID:
			return cloneMap(bobDoc), nil
		default:
			return nil, invalidField("unknown did: " + did)
		}
	}
}

func boolPtr(value bool) *bool { return &value }

func bytesTo32(t *testing.T, input []byte) [32]byte {
	t.Helper()
	if len(input) != 32 {
		t.Fatalf("expected 32-byte value, got %d bytes", len(input))
	}
	var result [32]byte
	copy(result[:], input)
	return result
}

func TestJSONRoundTripForPendingResult(t *testing.T) {
	payload := map[string]any{"event": "wave"}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if out["event"] != "wave" {
		t.Fatalf("unexpected payload: %+v", out)
	}
}
