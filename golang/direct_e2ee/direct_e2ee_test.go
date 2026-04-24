package directe2ee

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/authentication"
)

func TestPrekeyBundleRoundTrip(t *testing.T) {
	bobBundle, err := authentication.CreateDidWBADocument("b.example", didOptions("b.example", "bob"))
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
	serviceDID, err := messageServiceDIDFromDocument(bobBundle.DidDocument)
	if err != nil {
		t.Fatalf("messageServiceDIDFromDocument failed: %v", err)
	}
	manager := NewPrekeyManager(bobDID, serviceDID, bobDID+"#"+authentication.VMKeyE2EEAgreement, signingPrivateKey, bobDID+"#"+authentication.VMKeyAuth, store, nil)
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

func TestPublishPrekeyBundleIncludesTopLevelOneTimePrekeys(t *testing.T) {
	bobBundle, err := authentication.CreateDidWBADocument("b.example", didOptions("b.example", "bob"))
	if err != nil {
		t.Fatalf("CreateDidWBADocument failed: %v", err)
	}
	bobDID := stringValue(bobBundle.DidDocument["id"])
	signingPrivateKey, err := anp.PrivateKeyFromPEM(bobBundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatalf("PrivateKeyFromPEM failed: %v", err)
	}
	signedPrekeyStore, err := NewFileSignedPrekeyStore(filepath.Join(t.TempDir(), "spk"))
	if err != nil {
		t.Fatalf("NewFileSignedPrekeyStore failed: %v", err)
	}
	oneTimePrekeyStore, err := NewFileOneTimePrekeyStore(filepath.Join(t.TempDir(), "opk"))
	if err != nil {
		t.Fatalf("NewFileOneTimePrekeyStore failed: %v", err)
	}
	serviceDID, err := messageServiceDIDFromDocument(bobBundle.DidDocument)
	if err != nil {
		t.Fatalf("messageServiceDIDFromDocument failed: %v", err)
	}
	rpc := &fakeRPCClient{expectedServiceDID: serviceDID}
	manager := NewPrekeyManager(bobDID, serviceDID, bobDID+"#"+authentication.VMKeyE2EEAgreement, signingPrivateKey, bobDID+"#"+authentication.VMKeyAuth, signedPrekeyStore, rpc.Call, oneTimePrekeyStore)
	if _, err := manager.EnsureFreshOneTimePrekeys(2); err != nil {
		t.Fatalf("EnsureFreshOneTimePrekeys failed: %v", err)
	}
	_, signedPrekey, err := manager.GenerateSignedPrekey("spk-bob-001", "2026-04-07T00:00:00Z")
	if err != nil {
		t.Fatalf("GenerateSignedPrekey failed: %v", err)
	}
	bundle, err := manager.BuildPrekeyBundle(signedPrekey, "bundle-bob-001", "")
	if err != nil {
		t.Fatalf("BuildPrekeyBundle failed: %v", err)
	}
	if _, err := manager.PublishPrekeyBundle(bundle); err != nil {
		t.Fatalf("PublishPrekeyBundle failed: %v", err)
	}
	if rpc.lastPublishedOPKCount != 2 {
		t.Fatalf("lastPublishedOPKCount = %d, want 2", rpc.lastPublishedOPKCount)
	}
}

func TestPublishPrekeyBundleDoesNotStripOneTimePrekeysOnFailure(t *testing.T) {
	bobBundle, err := authentication.CreateDidWBADocument("b.example", didOptions("b.example", "bob"))
	if err != nil {
		t.Fatalf("CreateDidWBADocument failed: %v", err)
	}
	bobDID := stringValue(bobBundle.DidDocument["id"])
	signingPrivateKey, err := anp.PrivateKeyFromPEM(bobBundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatalf("PrivateKeyFromPEM failed: %v", err)
	}
	signedPrekeyStore, err := NewFileSignedPrekeyStore(filepath.Join(t.TempDir(), "spk"))
	if err != nil {
		t.Fatalf("NewFileSignedPrekeyStore failed: %v", err)
	}
	oneTimePrekeyStore, err := NewFileOneTimePrekeyStore(filepath.Join(t.TempDir(), "opk"))
	if err != nil {
		t.Fatalf("NewFileOneTimePrekeyStore failed: %v", err)
	}
	serviceDID, err := messageServiceDIDFromDocument(bobBundle.DidDocument)
	if err != nil {
		t.Fatalf("messageServiceDIDFromDocument failed: %v", err)
	}
	rpc := &fakeRPCClient{expectedServiceDID: serviceDID, failPublishWithOPK: true}
	manager := NewPrekeyManager(bobDID, serviceDID, bobDID+"#"+authentication.VMKeyE2EEAgreement, signingPrivateKey, bobDID+"#"+authentication.VMKeyAuth, signedPrekeyStore, rpc.Call, oneTimePrekeyStore)
	if _, err := manager.EnsureFreshOneTimePrekeys(2); err != nil {
		t.Fatalf("EnsureFreshOneTimePrekeys failed: %v", err)
	}
	_, signedPrekey, err := manager.GenerateSignedPrekey("spk-bob-001", "2026-04-07T00:00:00Z")
	if err != nil {
		t.Fatalf("GenerateSignedPrekey failed: %v", err)
	}
	bundle, err := manager.BuildPrekeyBundle(signedPrekey, "bundle-bob-001", "")
	if err != nil {
		t.Fatalf("BuildPrekeyBundle failed: %v", err)
	}
	if _, err := manager.PublishPrekeyBundle(bundle); err == nil {
		t.Fatalf("PublishPrekeyBundle should return the OPK publish error without retrying a different body")
	}
	if rpc.publishAttempts != 1 || rpc.lastPublishedOPKCount != 2 {
		t.Fatalf("publishAttempts=%d lastPublishedOPKCount=%d, want one publish attempt with OPKs preserved", rpc.publishAttempts, rpc.lastPublishedOPKCount)
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
	replyMetadata := DirectEnvelopeMetadata{SenderDID: bobDID, RecipientDID: aliceDID, MessageID: "msg-reply", Profile: "anp.direct.e2ee.v1", SecurityProfile: "direct-e2ee"}
	_, replyBody, err := sessionBuilder.EncryptFollowUp(&bobSession, replyMetadata, "msg-reply", NewJSONPlaintext("application/json", map[string]any{"ack": "ok"}))
	if err != nil {
		t.Fatalf("EncryptFollowUp(reply) failed: %v", err)
	}
	replyPlaintext, err := sessionBuilder.DecryptFollowUp(&aliceSession, replyMetadata, replyBody)
	if err != nil {
		t.Fatalf("DecryptFollowUp(reply) failed: %v", err)
	}
	if replyPlaintext.Payload["ack"] != "ok" || aliceSession.Status != SessionStatusEstablished {
		t.Fatalf("unexpected first reply result: plaintext=%+v session=%+v", replyPlaintext.Payload, aliceSession.Status)
	}
	followUpMetadata := DirectEnvelopeMetadata{SenderDID: aliceDID, RecipientDID: bobDID, MessageID: "msg-2", Profile: "anp.direct.e2ee.v1", SecurityProfile: "direct-e2ee"}
	_, cipherBody, err := sessionBuilder.EncryptFollowUp(&aliceSession, followUpMetadata, "msg-2", NewJSONPlaintext("application/json", map[string]any{"event": "wave"}))
	if err != nil {
		t.Fatalf("EncryptFollowUp failed: %v", err)
	}
	decrypted, err := sessionBuilder.DecryptFollowUp(&bobSession, followUpMetadata, cipherBody)
	if err != nil {
		t.Fatalf("DecryptFollowUp failed: %v", err)
	}
	if decrypted.Payload["event"] != "wave" {
		t.Fatalf("unexpected follow-up payload: %+v", decrypted.Payload)
	}
}

func TestSkippedMessageKeySurvivesFailedAuthentication(t *testing.T) {
	aliceDoc, bobDoc, aliceStatic, bobStatic, bobSPK, bundle := buildSessionFixtures(t)
	aliceDID := stringValue(aliceDoc["id"])
	bobDID := stringValue(bobDoc["id"])
	sessionBuilder := DirectE2eeSession{}
	initMetadata := DirectEnvelopeMetadata{SenderDID: aliceDID, RecipientDID: bobDID, MessageID: "msg-init", Profile: "anp.direct.e2ee.v1", SecurityProfile: "direct-e2ee"}
	aliceSession, _, initBody, err := sessionBuilder.InitiateSession(initMetadata, "op-init", aliceDID+"#"+authentication.VMKeyE2EEAgreement, aliceStatic, bundle, bytesTo32(t, bobStatic.PublicKey().Bytes()), bytesTo32(t, bobSPK.PublicKey().Bytes()), NewTextPlaintext("text/plain", "hello bob"))
	if err != nil {
		t.Fatalf("InitiateSession failed: %v", err)
	}
	bobSession, _, err := sessionBuilder.AcceptIncomingInit(initMetadata, bobDID+"#"+authentication.VMKeyE2EEAgreement, bobStatic, bobSPK, bytesTo32(t, aliceStatic.PublicKey().Bytes()), initBody)
	if err != nil {
		t.Fatalf("AcceptIncomingInit failed: %v", err)
	}
	replyMetadata := DirectEnvelopeMetadata{SenderDID: bobDID, RecipientDID: aliceDID, MessageID: "msg-reply", Profile: "anp.direct.e2ee.v1", SecurityProfile: "direct-e2ee"}
	_, replyBody, err := sessionBuilder.EncryptFollowUp(&bobSession, replyMetadata, "msg-reply", NewJSONPlaintext("application/json", map[string]any{"ack": "ok"}))
	if err != nil {
		t.Fatalf("EncryptFollowUp(reply) failed: %v", err)
	}
	if _, err := sessionBuilder.DecryptFollowUp(&aliceSession, replyMetadata, replyBody); err != nil {
		t.Fatalf("DecryptFollowUp(reply) failed: %v", err)
	}

	msg2Metadata := DirectEnvelopeMetadata{SenderDID: aliceDID, RecipientDID: bobDID, MessageID: "msg-2", Profile: "anp.direct.e2ee.v1", SecurityProfile: "direct-e2ee"}
	_, msg2Body, err := sessionBuilder.EncryptFollowUp(&aliceSession, msg2Metadata, "msg-2", NewJSONPlaintext("application/json", map[string]any{"seq": "two"}))
	if err != nil {
		t.Fatalf("EncryptFollowUp(msg-2) failed: %v", err)
	}
	msg3Metadata := DirectEnvelopeMetadata{SenderDID: aliceDID, RecipientDID: bobDID, MessageID: "msg-3", Profile: "anp.direct.e2ee.v1", SecurityProfile: "direct-e2ee"}
	_, msg3Body, err := sessionBuilder.EncryptFollowUp(&aliceSession, msg3Metadata, "msg-3", NewJSONPlaintext("application/json", map[string]any{"seq": "three"}))
	if err != nil {
		t.Fatalf("EncryptFollowUp(msg-3) failed: %v", err)
	}
	beforeFailedMsg3 := cloneDirectSessionState(&bobSession)
	corruptedMsg3 := msg3Body
	corruptedMsg3.CiphertextB64U = corruptB64UTail(corruptedMsg3.CiphertextB64U)
	if _, err := sessionBuilder.DecryptFollowUp(&bobSession, msg3Metadata, corruptedMsg3); err == nil {
		t.Fatalf("DecryptFollowUp(corrupted msg-3) unexpectedly succeeded")
	}
	if !reflect.DeepEqual(bobSession, beforeFailedMsg3) {
		t.Fatalf("bob session mutated after failed decrypt:\n got: %+v\nwant: %+v", bobSession, beforeFailedMsg3)
	}
	if _, err := sessionBuilder.DecryptFollowUp(&bobSession, msg3Metadata, msg3Body); err != nil {
		t.Fatalf("DecryptFollowUp(msg-3 out-of-order) failed: %v", err)
	}
	if got := len(bobSession.SkippedMessageKeys); got != 1 {
		t.Fatalf("len(SkippedMessageKeys) after out-of-order msg-3 = %d, want 1", got)
	}

	corruptedMsg2 := msg2Body
	corruptedMsg2.CiphertextB64U = corruptB64UTail(corruptedMsg2.CiphertextB64U)
	if _, err := sessionBuilder.DecryptFollowUp(&bobSession, msg2Metadata, corruptedMsg2); err == nil {
		t.Fatalf("DecryptFollowUp(corrupted msg-2) unexpectedly succeeded")
	}
	if got := len(bobSession.SkippedMessageKeys); got != 0 {
		t.Fatalf("len(SkippedMessageKeys) after failed skipped-key auth = %d, want 0", got)
	}

	if _, err := sessionBuilder.DecryptFollowUp(&bobSession, msg2Metadata, msg2Body); err == nil {
		t.Fatalf("DecryptFollowUp(valid retry msg-2) unexpectedly succeeded after skipped key was consumed")
	}
}

func TestClientSendAndPendingHistoryProcessing(t *testing.T) {
	aliceBundle, err := authentication.CreateDidWBADocument("a.example", didOptions("a.example", "alice"))
	if err != nil {
		t.Fatalf("alice CreateDidWBADocument failed: %v", err)
	}
	bobBundle, err := authentication.CreateDidWBADocument("b.example", didOptions("b.example", "bob"))
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
	bobOPKStore, err := NewFileOneTimePrekeyStore(filepath.Join(t.TempDir(), "bob-opk"))
	if err != nil {
		t.Fatalf("NewFileOneTimePrekeyStore failed: %v", err)
	}
	serviceDID, err := messageServiceDIDFromDocument(bobDoc)
	if err != nil {
		t.Fatalf("messageServiceDIDFromDocument failed: %v", err)
	}
	bobManager := NewPrekeyManager(bobDID, serviceDID, bobDID+"#"+authentication.VMKeyE2EEAgreement, bobSigning, bobDID+"#"+authentication.VMKeyAuth, bobSPKStore, nil, bobOPKStore)
	_, signedPrekey, err := bobManager.GenerateSignedPrekey("spk-bob-001", "2026-04-07T00:00:00Z")
	if err != nil {
		t.Fatalf("GenerateSignedPrekey failed: %v", err)
	}
	_, oneTimePrekey, err := bobManager.GenerateOneTimePrekey("opk-bob-001")
	if err != nil {
		t.Fatalf("GenerateOneTimePrekey failed: %v", err)
	}
	bundle, err := bobManager.BuildPrekeyBundle(signedPrekey, "bundle-bob-001", "")
	if err != nil {
		t.Fatalf("BuildPrekeyBundle failed: %v", err)
	}
	bobServiceDID, err := messageServiceDIDFromDocument(bobDoc)
	if err != nil {
		t.Fatalf("messageServiceDIDFromDocument(bob) failed: %v", err)
	}
	rpc := &fakeRPCClient{prekeyBundle: bundleToMap(bundle), oneTimePrekey: oneTimePrekeyToMap(oneTimePrekey), expectedServiceDID: bobServiceDID}
	aliceSessionStore, _ := NewFileSessionStore(filepath.Join(t.TempDir(), "alice-sessions"))
	aliceSPKStore, _ := NewFileSignedPrekeyStore(filepath.Join(t.TempDir(), "alice-spk"))
	aliceClient, err := NewMessageServiceDirectE2eeClient(aliceDID, aliceSigning, aliceDID+"#"+authentication.VMKeyAuth, fromECDHPrivateKey(t, aliceStatic), aliceDID+"#"+authentication.VMKeyE2EEAgreement, rpc.Call, resolverFor(aliceDoc, bobDoc), aliceSessionStore, aliceSPKStore)
	if err != nil {
		t.Fatalf("NewMessageServiceDirectE2eeClient failed: %v", err)
	}
	if _, err := aliceClient.SendText(context.Background(), bobDID, "bad ids", "op-mismatch", "msg-mismatch"); err == nil {
		t.Fatalf("SendText should reject operation_id/message_id mismatch")
	}
	initResponse, err := aliceClient.SendText(context.Background(), bobDID, "hello bob", "msg-init", "msg-init")
	if err != nil {
		t.Fatalf("SendText failed: %v", err)
	}
	if got := initResponse["body"].(map[string]any)["recipient_one_time_prekey_id"]; got != oneTimePrekey.KeyID {
		t.Fatalf("recipient_one_time_prekey_id = %#v, want %q", got, oneTimePrekey.KeyID)
	}
	if _, err := aliceClient.SendJSON(context.Background(), bobDID, map[string]any{"event": "blocked"}, "msg-blocked", "msg-blocked"); err == nil {
		t.Fatalf("SendJSON before first reply should fail while pending confirmation")
	}
	bobSessionStore, _ := NewFileSessionStore(filepath.Join(t.TempDir(), "bob-sessions"))
	bobClient, err := NewMessageServiceDirectE2eeClient(bobDID, bobSigning, bobDID+"#"+authentication.VMKeyAuth, fromECDHPrivateKey(t, bobStatic), bobDID+"#"+authentication.VMKeyE2EEAgreement, rpc.Call, resolverFor(aliceDoc, bobDoc), bobSessionStore, bobSPKStore, bobOPKStore)
	if err != nil {
		t.Fatalf("NewMessageServiceDirectE2eeClient failed: %v", err)
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
	if _, _, err := bobOPKStore.LoadOneTimePrekey(oneTimePrekey.KeyID); err == nil {
		t.Fatalf("one-time prekey %s should be consumed after init processing", oneTimePrekey.KeyID)
	}
	replyResponse, err := bobClient.SendJSON(context.Background(), aliceDID, map[string]any{"ack": "ok"}, "msg-reply", "msg-reply")
	if err != nil {
		t.Fatalf("Bob SendJSON reply failed: %v", err)
	}
	confirmed, err := aliceClient.ProcessIncoming(context.Background(), map[string]any{"meta": map[string]any{"sender_did": bobDID, "target": map[string]any{"kind": "agent", "did": aliceDID}, "message_id": "msg-reply", "profile": "anp.direct.e2ee.v1", "security_profile": "direct-e2ee", "content_type": "application/anp-direct-cipher+json"}, "body": replyResponse["body"], "server_seq": 2.0})
	if err != nil || confirmed["state"] != "decrypted" {
		t.Fatalf("Alice first reply processing failed: result=%+v err=%v", confirmed, err)
	}
	followUpResponse, err := aliceClient.SendJSON(context.Background(), bobDID, map[string]any{"event": "wave"}, "msg-2", "msg-2")
	if err != nil {
		t.Fatalf("Alice SendJSON after confirmation failed: %v", err)
	}
	followUp, err := bobClient.ProcessIncoming(context.Background(), map[string]any{"meta": map[string]any{"sender_did": aliceDID, "target": map[string]any{"kind": "agent", "did": bobDID}, "message_id": "msg-2", "profile": "anp.direct.e2ee.v1", "security_profile": "direct-e2ee", "content_type": "application/anp-direct-cipher+json"}, "body": followUpResponse["body"], "server_seq": 3.0})
	if err != nil || followUp["state"] != "decrypted" {
		t.Fatalf("Bob follow-up processing failed: result=%+v err=%v", followUp, err)
	}
}

func corruptB64UTail(value string) string {
	if value == "" {
		return "A"
	}
	replacement := byte('A')
	if value[len(value)-1] == replacement {
		replacement = 'B'
	}
	return value[:len(value)-1] + string(replacement)
}

func TestClientFallsBackToSignedPrekeyWhenOPKUnavailable(t *testing.T) {
	aliceBundle, err := authentication.CreateDidWBADocument("a.example", didOptions("a.example", "alice"))
	if err != nil {
		t.Fatalf("alice CreateDidWBADocument failed: %v", err)
	}
	bobBundle, err := authentication.CreateDidWBADocument("b.example", didOptions("b.example", "bob"))
	if err != nil {
		t.Fatalf("bob CreateDidWBADocument failed: %v", err)
	}
	aliceDoc := aliceBundle.DidDocument
	bobDoc := bobBundle.DidDocument
	aliceStatic := loadECDHPrivateKey(t, aliceBundle.Keys[authentication.VMKeyE2EEAgreement].PrivateKeyPEM)
	bobSigning, err := anp.PrivateKeyFromPEM(bobBundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatalf("bob signing key: %v", err)
	}
	bobSPKStore, err := NewFileSignedPrekeyStore(filepath.Join(t.TempDir(), "bob-spk"))
	if err != nil {
		t.Fatalf("NewFileSignedPrekeyStore failed: %v", err)
	}
	aliceDID := stringValue(aliceDoc["id"])
	bobDID := stringValue(bobDoc["id"])
	aliceSigning, err := anp.PrivateKeyFromPEM(aliceBundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatalf("alice signing key: %v", err)
	}
	serviceDID, err := messageServiceDIDFromDocument(bobDoc)
	if err != nil {
		t.Fatalf("messageServiceDIDFromDocument(bob) failed: %v", err)
	}
	bobManager := NewPrekeyManager(bobDID, serviceDID, bobDID+"#"+authentication.VMKeyE2EEAgreement, bobSigning, bobDID+"#"+authentication.VMKeyAuth, bobSPKStore, nil)
	_, signedPrekey, err := bobManager.GenerateSignedPrekey("spk-bob-001", "2026-04-07T00:00:00Z")
	if err != nil {
		t.Fatalf("GenerateSignedPrekey failed: %v", err)
	}
	bundle, err := bobManager.BuildPrekeyBundle(signedPrekey, "bundle-bob-001", "")
	if err != nil {
		t.Fatalf("BuildPrekeyBundle failed: %v", err)
	}
	bobServiceDID, err := messageServiceDIDFromDocument(bobDoc)
	if err != nil {
		t.Fatalf("messageServiceDIDFromDocument(bob) failed: %v", err)
	}
	rpc := &fakeRPCClient{prekeyBundle: bundleToMap(bundle), expectedServiceDID: bobServiceDID, failRequireOPK: true}
	aliceSessionStore, _ := NewFileSessionStore(filepath.Join(t.TempDir(), "alice-sessions"))
	aliceSPKStore, _ := NewFileSignedPrekeyStore(filepath.Join(t.TempDir(), "alice-spk"))
	aliceClient, err := NewMessageServiceDirectE2eeClient(aliceDID, aliceSigning, aliceDID+"#"+authentication.VMKeyAuth, fromECDHPrivateKey(t, aliceStatic), aliceDID+"#"+authentication.VMKeyE2EEAgreement, rpc.Call, resolverFor(aliceDoc, bobDoc), aliceSessionStore, aliceSPKStore)
	if err != nil {
		t.Fatalf("NewMessageServiceDirectE2eeClient failed: %v", err)
	}
	initResponse, err := aliceClient.SendText(context.Background(), bobDID, "hello without opk", "msg-init", "msg-init")
	if err != nil {
		t.Fatalf("SendText failed: %v", err)
	}
	if got := initResponse["body"].(map[string]any)["recipient_one_time_prekey_id"]; got != nil {
		t.Fatalf("recipient_one_time_prekey_id = %#v, want nil after fallback", got)
	}
	if rpc.requireOPKCalls != 1 || rpc.totalGetPrekeyCalls != 2 {
		t.Fatalf("requireOPKCalls=%d totalGetPrekeyCalls=%d, want 1/2 for OPK retry fallback", rpc.requireOPKCalls, rpc.totalGetPrekeyCalls)
	}
	if len(rpc.getPrekeyOperationIDs) != 2 {
		t.Fatalf("getPrekeyOperationIDs = %#v, want 2 operation ids", rpc.getPrekeyOperationIDs)
	}
	if rpc.getPrekeyOperationIDs[0] == rpc.getPrekeyOperationIDs[1] {
		t.Fatalf("get_prekey_bundle operation IDs were reused: %#v", rpc.getPrekeyOperationIDs)
	}
	for _, operationID := range rpc.getPrekeyOperationIDs {
		if !strings.HasPrefix(operationID, "op-get-prekey-") {
			t.Fatalf("get_prekey_bundle operation_id = %q, want op-get-prekey-*", operationID)
		}
	}
}

type fakeRPCClient struct {
	prekeyBundle          map[string]any
	oneTimePrekey         map[string]any
	expectedServiceDID    string
	lastPublishedOPKCount int
	failRequireOPK        bool
	requireOPKCalls       int
	totalGetPrekeyCalls   int
	failPublishWithOPK    bool
	publishAttempts       int
	getPrekeyOperationIDs []string
	calls                 [][2]any
}

func (f *fakeRPCClient) Call(method string, params map[string]any) (map[string]any, error) {
	f.calls = append(f.calls, [2]any{method, params})
	switch method {
	case "direct.e2ee.publish_prekey_bundle":
		f.publishAttempts++
		meta := params["meta"].(map[string]any)
		target := meta["target"].(map[string]any)
		if target["kind"] != "service" || target["did"] != f.expectedServiceDID {
			return nil, invalidField("publish_prekey_bundle target")
		}
		body := params["body"].(map[string]any)
		bundle := body["prekey_bundle"].(map[string]any)
		if published, ok := body["one_time_prekeys"].([]any); ok {
			f.lastPublishedOPKCount = len(published)
			if f.failPublishWithOPK {
				return nil, invalidField("one_time_prekeys not supported")
			}
		} else {
			f.lastPublishedOPKCount = 0
		}
		return map[string]any{"published": true, "owner_did": bundle["owner_did"], "bundle_id": bundle["bundle_id"], "published_at": "2026-03-31T09:59:01Z"}, nil
	case "direct.e2ee.get_prekey_bundle":
		f.totalGetPrekeyCalls++
		meta := params["meta"].(map[string]any)
		f.getPrekeyOperationIDs = append(f.getPrekeyOperationIDs, stringValue(meta["operation_id"]))
		target := meta["target"].(map[string]any)
		if target["kind"] != "service" || target["did"] != f.expectedServiceDID {
			return nil, invalidField("get_prekey_bundle target")
		}
		if requireOPK, _ := params["body"].(map[string]any)["require_opk"].(bool); requireOPK {
			f.requireOPKCalls++
			if f.failRequireOPK {
				return nil, &Error{Code: "opk_unavailable", Message: "4003 anp.direct.e2ee.opk_unavailable"}
			}
		}
		result := map[string]any{"target_did": params["body"].(map[string]any)["target_did"], "prekey_bundle": f.prekeyBundle}
		if f.oneTimePrekey != nil {
			result["one_time_prekey"] = f.oneTimePrekey
		}
		return result, nil
	case "direct.send":
		meta := params["meta"].(map[string]any)
		if meta["operation_id"] != meta["message_id"] {
			return nil, invalidField("direct.send operation_id/message_id mismatch")
		}
		return map[string]any{"accepted": true, "message_id": meta["message_id"], "operation_id": meta["operation_id"], "target_did": meta["target"].(map[string]any)["did"], "body": params["body"]}, nil
	default:
		return nil, invalidField("unexpected RPC method: " + method)
	}
}

func buildSessionFixtures(t *testing.T) (map[string]any, map[string]any, *ecdh.PrivateKey, *ecdh.PrivateKey, *ecdh.PrivateKey, PrekeyBundle) {
	t.Helper()
	aliceBundle, err := authentication.CreateDidWBADocument("a.example", didOptions("a.example", "alice"))
	if err != nil {
		t.Fatalf("alice CreateDidWBADocument failed: %v", err)
	}
	bobBundle, err := authentication.CreateDidWBADocument("b.example", didOptions("b.example", "bob"))
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

func didOptions(domain string, agent string) authentication.DidDocumentOptions {
	return authentication.DidDocumentOptions{
		PathSegments: []string{"agents", agent},
		EnableE2EE:   boolPtr(true),
		Services: []map[string]any{
			authentication.BuildANPMessageService(
				"did:wba:"+domain+":agents:"+agent,
				"https://"+domain+"/anp-im/rpc",
				authentication.AnpMessageServiceOptions{
					ServiceDID:       "did:wba:" + domain,
					Profiles:         []string{"anp.direct.base.v1"},
					SecurityProfiles: []string{"transport-protected"},
				},
			),
		},
	}
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
