package directe2ee

import (
	"crypto/ecdh"
	"encoding/json"
	"strconv"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/internal/cjson"
)

// DirectE2eeSession builds and processes P5 direct E2EE init and follow-up messages.
type DirectE2eeSession struct{}

// InitiateSession creates the initial encrypted session message without OPK.
func (DirectE2eeSession) InitiateSession(metadata DirectEnvelopeMetadata, operationID string, localStaticKeyID string, localStaticPrivate *ecdh.PrivateKey, recipientBundle PrekeyBundle, recipientStaticPublic [32]byte, recipientSignedPrekeyPublic [32]byte, plaintext ApplicationPlaintext) (DirectSessionState, PendingOutboundRecord, DirectInitBody, error) {
	return (DirectE2eeSession{}).InitiateSessionWithOPK(metadata, operationID, localStaticKeyID, localStaticPrivate, recipientBundle, recipientStaticPublic, recipientSignedPrekeyPublic, nil, "", plaintext)
}

// InitiateSessionWithOPK creates the initial encrypted session message with an optional OPK public key.
func (DirectE2eeSession) InitiateSessionWithOPK(metadata DirectEnvelopeMetadata, operationID string, localStaticKeyID string, localStaticPrivate *ecdh.PrivateKey, recipientBundle PrekeyBundle, recipientStaticPublic [32]byte, recipientSignedPrekeyPublic [32]byte, recipientOneTimePrekeyPublic *[32]byte, recipientOneTimePrekeyID string, plaintext ApplicationPlaintext) (DirectSessionState, PendingOutboundRecord, DirectInitBody, error) {
	if recipientBundle.Suite != MTIDirectE2EESuite {
		return DirectSessionState{}, PendingOutboundRecord{}, DirectInitBody{}, unsupportedSuite(recipientBundle.Suite)
	}
	senderEphemeralPrivate, err := ecdh.X25519().GenerateKey(randReader)
	if err != nil {
		return DirectSessionState{}, PendingOutboundRecord{}, DirectInitBody{}, err
	}
	initialMaterial, err := DeriveInitialMaterialForInitiatorWithOPK(localStaticPrivate, senderEphemeralPrivate, recipientStaticPublic, recipientSignedPrekeyPublic, recipientOneTimePrekeyPublic)
	if err != nil {
		return DirectSessionState{}, PendingOutboundRecord{}, DirectInitBody{}, err
	}
	body := DirectInitBody{
		SessionID:                  initialMaterial.SessionID,
		Suite:                      MTIDirectE2EESuite,
		SenderStaticKeyAgreementID: localStaticKeyID,
		RecipientBundleID:          recipientBundle.BundleID,
		RecipientSignedPrekeyID:    recipientBundle.SignedPrekey.KeyID,
		RecipientOneTimePrekeyID:   recipientOneTimePrekeyID,
		SenderEphemeralPubB64U:     anp.EncodeBase64URL(senderEphemeralPrivate.PublicKey().Bytes()),
	}
	aad, err := BuildInitAAD(metadata, body)
	if err != nil {
		return DirectSessionState{}, PendingOutboundRecord{}, DirectInitBody{}, err
	}
	initStep := DeriveChainStep(initialMaterial.ChainKey)
	plaintextBytes, err := marshalPlaintext(plaintext)
	if err != nil {
		return DirectSessionState{}, PendingOutboundRecord{}, DirectInitBody{}, err
	}
	ciphertext, err := EncryptWithStep(initStep, plaintextBytes, aad)
	if err != nil {
		return DirectSessionState{}, PendingOutboundRecord{}, DirectInitBody{}, err
	}
	body.CiphertextB64U = anp.EncodeBase64URL(ciphertext)
	session := DirectSessionState{
		SessionID:             initialMaterial.SessionID,
		Suite:                 MTIDirectE2EESuite,
		PeerDID:               metadata.RecipientDID,
		LocalKeyAgreementID:   localStaticKeyID,
		PeerKeyAgreementID:    recipientBundle.StaticKeyAgreementID,
		RootKeyB64U:           anp.EncodeBase64URL(initialMaterial.RootKey[:]),
		SendChainKeyB64U:      anp.EncodeBase64URL(initStep.NextChainKey[:]),
		RatchetPrivateKeyB64U: anp.EncodeBase64URL(senderEphemeralPrivate.Bytes()),
		RatchetPublicKeyB64U:  anp.EncodeBase64URL(senderEphemeralPrivate.PublicKey().Bytes()),
		SendN:                 1,
		RecvN:                 0,
		SkippedMessageKeys:    nil,
		IsInitiator:           true,
		Status:                SessionStatusPendingConfirmation,
	}
	bodyJSON := directInitBodyToMap(body)
	pending := PendingOutboundRecord{OperationID: operationID, MessageID: metadata.MessageID, WireContentType: ContentTypeDirectInit, BodyJSON: bodyJSON}
	return session, pending, body, nil
}

// AcceptIncomingInit processes an init message for the responder without OPK.
func (DirectE2eeSession) AcceptIncomingInit(metadata DirectEnvelopeMetadata, localStaticKeyID string, localStaticPrivate *ecdh.PrivateKey, localSignedPrekeyPrivate *ecdh.PrivateKey, senderStaticPublic [32]byte, body DirectInitBody) (DirectSessionState, ApplicationPlaintext, error) {
	return (DirectE2eeSession{}).AcceptIncomingInitWithOPK(metadata, localStaticKeyID, localStaticPrivate, localSignedPrekeyPrivate, nil, senderStaticPublic, body)
}

// AcceptIncomingInitWithOPK processes an init message for the responder with an optional OPK private key.
func (DirectE2eeSession) AcceptIncomingInitWithOPK(metadata DirectEnvelopeMetadata, localStaticKeyID string, localStaticPrivate *ecdh.PrivateKey, localSignedPrekeyPrivate *ecdh.PrivateKey, localOneTimePrekeyPrivate *ecdh.PrivateKey, senderStaticPublic [32]byte, body DirectInitBody) (DirectSessionState, ApplicationPlaintext, error) {
	senderEphemeralBytes, err := anp.DecodeBase64URL(body.SenderEphemeralPubB64U)
	if err != nil || len(senderEphemeralBytes) != 32 {
		return DirectSessionState{}, ApplicationPlaintext{}, invalidField("sender_ephemeral_pub_b64u")
	}
	var senderEphemeral [32]byte
	copy(senderEphemeral[:], senderEphemeralBytes)
	initialMaterial, err := DeriveInitialMaterialForResponderWithOPK(localStaticPrivate, localSignedPrekeyPrivate, localOneTimePrekeyPrivate, senderStaticPublic, senderEphemeral)
	if err != nil {
		return DirectSessionState{}, ApplicationPlaintext{}, err
	}
	if body.SessionID != initialMaterial.SessionID {
		return DirectSessionState{}, ApplicationPlaintext{}, invalidField("session_id does not match derived session")
	}
	aad, err := BuildInitAAD(metadata, body)
	if err != nil {
		return DirectSessionState{}, ApplicationPlaintext{}, err
	}
	initStep := DeriveChainStep(initialMaterial.ChainKey)
	ciphertext, err := anp.DecodeBase64URL(body.CiphertextB64U)
	if err != nil {
		return DirectSessionState{}, ApplicationPlaintext{}, invalidField("ciphertext_b64u")
	}
	plaintextBytes, err := DecryptWithStep(initStep, ciphertext, aad)
	if err != nil {
		return DirectSessionState{}, ApplicationPlaintext{}, err
	}
	var plaintext ApplicationPlaintext
	if err := json.Unmarshal(plaintextBytes, &plaintext); err != nil {
		return DirectSessionState{}, ApplicationPlaintext{}, invalidField("invalid plaintext json")
	}
	responderRatchetPrivate, err := ecdh.X25519().GenerateKey(randReader)
	if err != nil {
		return DirectSessionState{}, ApplicationPlaintext{}, err
	}
	peerRatchetPublic, err := ecdh.X25519().NewPublicKey(senderEphemeral[:])
	if err != nil {
		return DirectSessionState{}, ApplicationPlaintext{}, err
	}
	rootStep, err := deriveRootStepFromKeys(initialMaterial.RootKey, responderRatchetPrivate, peerRatchetPublic)
	if err != nil {
		return DirectSessionState{}, ApplicationPlaintext{}, err
	}
	session := DirectSessionState{
		SessionID:                body.SessionID,
		Suite:                    MTIDirectE2EESuite,
		PeerDID:                  metadata.SenderDID,
		LocalKeyAgreementID:      localStaticKeyID,
		PeerKeyAgreementID:       body.SenderStaticKeyAgreementID,
		RootKeyB64U:              anp.EncodeBase64URL(rootStep.RootKey[:]),
		SendChainKeyB64U:         anp.EncodeBase64URL(rootStep.ChainKey[:]),
		RecvChainKeyB64U:         anp.EncodeBase64URL(initStep.NextChainKey[:]),
		RatchetPrivateKeyB64U:    anp.EncodeBase64URL(responderRatchetPrivate.Bytes()),
		RatchetPublicKeyB64U:     anp.EncodeBase64URL(responderRatchetPrivate.PublicKey().Bytes()),
		PeerRatchetPublicKeyB64U: body.SenderEphemeralPubB64U,
		SendN:                    0,
		RecvN:                    1,
		PreviousSendChainLength:  0,
		SkippedMessageKeys:       nil,
		IsInitiator:              false,
		Status:                   SessionStatusEstablished,
	}
	return session, plaintext, nil
}

// EncryptFollowUp encrypts a follow-up direct message.
func (DirectE2eeSession) EncryptFollowUp(session *DirectSessionState, metadata DirectEnvelopeMetadata, operationID string, plaintext ApplicationPlaintext) (PendingOutboundRecord, DirectCipherBody, error) {
	if session.Status == SessionStatusPendingConfirmation {
		return PendingOutboundRecord{}, DirectCipherBody{}, invalidField("session pending confirmation")
	}
	sendChainKey, err := decodeFixed32(session.SendChainKeyB64U)
	if err != nil {
		return PendingOutboundRecord{}, DirectCipherBody{}, err
	}
	step := DeriveChainStep(sendChainKey)
	body := DirectCipherBody{SessionID: session.SessionID, Suite: MTIDirectE2EESuite, RatchetHeader: RatchetHeader{DHPubB64U: session.RatchetPublicKeyB64U, PN: strconv.FormatUint(uint64(session.PreviousSendChainLength), 10), N: strconv.FormatUint(uint64(session.SendN), 10)}}
	aad, err := BuildMessageAAD(metadata, body)
	if err != nil {
		return PendingOutboundRecord{}, DirectCipherBody{}, err
	}
	plaintextBytes, err := marshalPlaintext(plaintext)
	if err != nil {
		return PendingOutboundRecord{}, DirectCipherBody{}, err
	}
	ciphertext, err := EncryptWithStep(step, plaintextBytes, aad)
	if err != nil {
		return PendingOutboundRecord{}, DirectCipherBody{}, err
	}
	body.CiphertextB64U = anp.EncodeBase64URL(ciphertext)
	session.SendChainKeyB64U = anp.EncodeBase64URL(step.NextChainKey[:])
	session.SendN++
	pending := PendingOutboundRecord{OperationID: operationID, MessageID: metadata.MessageID, WireContentType: ContentTypeDirectCipher, BodyJSON: directCipherBodyToMap(body)}
	return pending, body, nil
}

// DecryptFollowUp decrypts a follow-up direct message.
func (DirectE2eeSession) DecryptFollowUp(session *DirectSessionState, metadata DirectEnvelopeMetadata, body DirectCipherBody, _ ...string) (ApplicationPlaintext, error) {
	if session.Status == SessionStatusPendingConfirmation {
		return decryptFirstReply(session, metadata, body)
	}
	nextSession := cloneDirectSessionState(session)
	if plaintext, ok, err := trySkippedMessageKey(&nextSession, metadata, body); ok || err != nil {
		if ok {
			*session = nextSession
		}
		return plaintext, err
	}
	if body.RatchetHeader.DHPubB64U != nextSession.PeerRatchetPublicKeyB64U {
		pn, err := parseUint32(body.RatchetHeader.PN, "ratchet_header.pn")
		if err != nil {
			return ApplicationPlaintext{}, err
		}
		if err := skipMessageKeys(&nextSession, pn); err != nil {
			return ApplicationPlaintext{}, err
		}
		if err := ratchetStep(&nextSession, body.RatchetHeader.DHPubB64U); err != nil {
			return ApplicationPlaintext{}, err
		}
	}
	n, err := parseUint32(body.RatchetHeader.N, "ratchet_header.n")
	if err != nil {
		return ApplicationPlaintext{}, err
	}
	if n < nextSession.RecvN {
		return ApplicationPlaintext{}, replayDetected("duplicate direct-e2ee message number")
	}
	if err := skipMessageKeys(&nextSession, n); err != nil {
		return ApplicationPlaintext{}, err
	}
	recvChainKey, err := decodeFixed32(nextSession.RecvChainKeyB64U)
	if err != nil {
		return ApplicationPlaintext{}, err
	}
	step := DeriveChainStep(recvChainKey)
	aad, err := BuildMessageAAD(metadata, body)
	if err != nil {
		return ApplicationPlaintext{}, err
	}
	ciphertext, err := anp.DecodeBase64URL(body.CiphertextB64U)
	if err != nil {
		return ApplicationPlaintext{}, invalidField("ciphertext_b64u")
	}
	plaintextBytes, err := DecryptWithStep(step, ciphertext, aad)
	if err != nil {
		return ApplicationPlaintext{}, err
	}
	var plaintext ApplicationPlaintext
	if err := json.Unmarshal(plaintextBytes, &plaintext); err != nil {
		return ApplicationPlaintext{}, invalidField("invalid plaintext json")
	}
	nextSession.RecvChainKeyB64U = anp.EncodeBase64URL(step.NextChainKey[:])
	nextSession.RecvN = n + 1
	*session = nextSession
	return plaintext, nil
}

func cloneDirectSessionState(session *DirectSessionState) DirectSessionState {
	clone := *session
	clone.SkippedMessageKeys = append([]SkippedMessageKey(nil), session.SkippedMessageKeys...)
	return clone
}

func decryptFirstReply(session *DirectSessionState, metadata DirectEnvelopeMetadata, body DirectCipherBody) (ApplicationPlaintext, error) {
	if body.RatchetHeader.PN != "0" || body.RatchetHeader.N != "0" {
		return ApplicationPlaintext{}, invalidField("bad first reply header")
	}
	rootKey, err := decodeFixed32(session.RootKeyB64U)
	if err != nil {
		return ApplicationPlaintext{}, err
	}
	localPrivate, err := privateKeyFromB64U(session.RatchetPrivateKeyB64U)
	if err != nil {
		return ApplicationPlaintext{}, err
	}
	peerPublic, err := publicKeyFromB64U(body.RatchetHeader.DHPubB64U)
	if err != nil {
		return ApplicationPlaintext{}, err
	}
	rootStep, err := deriveRootStepFromKeys(rootKey, localPrivate, peerPublic)
	if err != nil {
		return ApplicationPlaintext{}, err
	}
	newPrivate, err := ecdh.X25519().GenerateKey(randReader)
	if err != nil {
		return ApplicationPlaintext{}, err
	}
	sendRootStep, err := deriveRootStepFromKeys(rootStep.RootKey, newPrivate, peerPublic)
	if err != nil {
		return ApplicationPlaintext{}, err
	}
	step := DeriveChainStep(rootStep.ChainKey)
	aad, err := BuildMessageAAD(metadata, body)
	if err != nil {
		return ApplicationPlaintext{}, err
	}
	ciphertext, err := anp.DecodeBase64URL(body.CiphertextB64U)
	if err != nil {
		return ApplicationPlaintext{}, invalidField("ciphertext_b64u")
	}
	plaintextBytes, err := DecryptWithStep(step, ciphertext, aad)
	if err != nil {
		return ApplicationPlaintext{}, err
	}
	var plaintext ApplicationPlaintext
	if err := json.Unmarshal(plaintextBytes, &plaintext); err != nil {
		return ApplicationPlaintext{}, invalidField("invalid plaintext json")
	}
	session.RootKeyB64U = anp.EncodeBase64URL(sendRootStep.RootKey[:])
	session.RecvChainKeyB64U = anp.EncodeBase64URL(step.NextChainKey[:])
	session.SendChainKeyB64U = anp.EncodeBase64URL(sendRootStep.ChainKey[:])
	session.PeerRatchetPublicKeyB64U = body.RatchetHeader.DHPubB64U
	session.PreviousSendChainLength = session.SendN
	session.SendN = 0
	session.RecvN = 1
	session.RatchetPrivateKeyB64U = anp.EncodeBase64URL(newPrivate.Bytes())
	session.RatchetPublicKeyB64U = anp.EncodeBase64URL(newPrivate.PublicKey().Bytes())
	session.Status = SessionStatusEstablished
	return plaintext, nil
}

func ratchetStep(session *DirectSessionState, newPeerPubB64U string) error {
	rootKey, err := decodeFixed32(session.RootKeyB64U)
	if err != nil {
		return err
	}
	localPrivate, err := privateKeyFromB64U(session.RatchetPrivateKeyB64U)
	if err != nil {
		return err
	}
	peerPublic, err := publicKeyFromB64U(newPeerPubB64U)
	if err != nil {
		return err
	}
	recvRootStep, err := deriveRootStepFromKeys(rootKey, localPrivate, peerPublic)
	if err != nil {
		return err
	}
	newPrivate, err := ecdh.X25519().GenerateKey(randReader)
	if err != nil {
		return err
	}
	sendRootStep, err := deriveRootStepFromKeys(recvRootStep.RootKey, newPrivate, peerPublic)
	if err != nil {
		return err
	}
	session.RootKeyB64U = anp.EncodeBase64URL(sendRootStep.RootKey[:])
	session.RecvChainKeyB64U = anp.EncodeBase64URL(recvRootStep.ChainKey[:])
	session.SendChainKeyB64U = anp.EncodeBase64URL(sendRootStep.ChainKey[:])
	session.PeerRatchetPublicKeyB64U = newPeerPubB64U
	session.PreviousSendChainLength = session.SendN
	session.SendN = 0
	session.RecvN = 0
	session.RatchetPrivateKeyB64U = anp.EncodeBase64URL(newPrivate.Bytes())
	session.RatchetPublicKeyB64U = anp.EncodeBase64URL(newPrivate.PublicKey().Bytes())
	return nil
}

func trySkippedMessageKey(session *DirectSessionState, metadata DirectEnvelopeMetadata, body DirectCipherBody) (ApplicationPlaintext, bool, error) {
	n, err := parseUint32(body.RatchetHeader.N, "ratchet_header.n")
	if err != nil {
		return ApplicationPlaintext{}, false, err
	}
	for i, skipped := range session.SkippedMessageKeys {
		if skipped.DHPubB64U == body.RatchetHeader.DHPubB64U && skipped.N == n {
			session.SkippedMessageKeys = append(session.SkippedMessageKeys[:i], session.SkippedMessageKeys[i+1:]...)
			mk, err := decodeFixed32(skipped.MessageKeyB64U)
			if err != nil {
				return ApplicationPlaintext{}, true, err
			}
			nonceBytes, err := anp.DecodeBase64URL(skipped.NonceB64U)
			if err != nil || len(nonceBytes) != 12 {
				return ApplicationPlaintext{}, true, invalidField("skipped nonce")
			}
			var nonce [12]byte
			copy(nonce[:], nonceBytes)
			aad, err := BuildMessageAAD(metadata, body)
			if err != nil {
				return ApplicationPlaintext{}, true, err
			}
			ciphertext, err := anp.DecodeBase64URL(body.CiphertextB64U)
			if err != nil {
				return ApplicationPlaintext{}, true, invalidField("ciphertext_b64u")
			}
			plaintextBytes, err := DecryptWithStep(ChainStep{MessageKey: mk, Nonce: nonce}, ciphertext, aad)
			if err != nil {
				return ApplicationPlaintext{}, true, err
			}
			var plaintext ApplicationPlaintext
			if err := json.Unmarshal(plaintextBytes, &plaintext); err != nil {
				return ApplicationPlaintext{}, true, invalidField("invalid plaintext json")
			}
			return plaintext, true, nil
		}
	}
	return ApplicationPlaintext{}, false, nil
}

func skipMessageKeys(session *DirectSessionState, untilN uint32) error {
	if untilN < session.RecvN {
		return nil
	}
	if untilN-session.RecvN > MaxSkip {
		return replayDetected("message skip exceeded MAX_SKIP")
	}
	recvChainKey, err := decodeFixed32(session.RecvChainKeyB64U)
	if err != nil {
		return err
	}
	for session.RecvN < untilN {
		step := DeriveChainStep(recvChainKey)
		session.SkippedMessageKeys = append(session.SkippedMessageKeys, SkippedMessageKey{DHPubB64U: session.PeerRatchetPublicKeyB64U, N: session.RecvN, MessageKeyB64U: anp.EncodeBase64URL(step.MessageKey[:]), NonceB64U: anp.EncodeBase64URL(step.Nonce[:])})
		recvChainKey = step.NextChainKey
		session.RecvN++
	}
	session.RecvChainKeyB64U = anp.EncodeBase64URL(recvChainKey[:])
	return nil
}

func decodeFixed32(value string) ([32]byte, error) {
	bytes, err := anp.DecodeBase64URL(value)
	if err != nil || len(bytes) != 32 {
		return [32]byte{}, invalidField("expected 32-byte base64url value")
	}
	var result [32]byte
	copy(result[:], bytes)
	return result, nil
}

func privateKeyFromB64U(value string) (*ecdh.PrivateKey, error) {
	bytes, err := anp.DecodeBase64URL(value)
	if err != nil || len(bytes) != 32 {
		return nil, invalidField("expected 32-byte private key")
	}
	return ecdh.X25519().NewPrivateKey(bytes)
}

func publicKeyFromB64U(value string) (*ecdh.PublicKey, error) {
	bytes, err := anp.DecodeBase64URL(value)
	if err != nil || len(bytes) != 32 {
		return nil, invalidField("expected 32-byte public key")
	}
	return ecdh.X25519().NewPublicKey(bytes)
}

func parseUint32(value string, field string) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, invalidField(field)
	}
	return uint32(parsed), nil
}

func marshalPlaintext(plaintext ApplicationPlaintext) ([]byte, error) {
	carriers := 0
	if plaintext.Text != "" {
		carriers++
	}
	if len(plaintext.Payload) > 0 {
		carriers++
	}
	if plaintext.PayloadB64U != "" {
		carriers++
	}
	if plaintext.ApplicationContentType == "" || carriers != 1 {
		return nil, invalidField("application plaintext must include content type and exactly one payload carrier")
	}
	return cjson.Marshal(plaintext)
}

func directInitBodyToMap(body DirectInitBody) map[string]any {
	result := map[string]any{
		"session_id":                     body.SessionID,
		"suite":                          body.Suite,
		"sender_static_key_agreement_id": body.SenderStaticKeyAgreementID,
		"recipient_bundle_id":            body.RecipientBundleID,
		"recipient_signed_prekey_id":     body.RecipientSignedPrekeyID,
		"sender_ephemeral_pub_b64u":      body.SenderEphemeralPubB64U,
		"ciphertext_b64u":                body.CiphertextB64U,
	}
	if body.RecipientOneTimePrekeyID != "" {
		result["recipient_one_time_prekey_id"] = body.RecipientOneTimePrekeyID
	}
	return result
}

func directCipherBodyToMap(body DirectCipherBody) map[string]any {
	result := map[string]any{
		"session_id":      body.SessionID,
		"ratchet_header":  map[string]any{"dh_pub_b64u": body.RatchetHeader.DHPubB64U, "pn": body.RatchetHeader.PN, "n": body.RatchetHeader.N},
		"ciphertext_b64u": body.CiphertextB64U,
	}
	if body.Suite != "" {
		result["suite"] = body.Suite
	}
	return result
}
