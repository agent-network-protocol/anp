package directe2ee

import (
	"crypto/ecdh"
	"encoding/json"
	"strconv"

	anp "github.com/agent-network-protocol/anp/golang"
)

// DirectE2eeSession builds and processes direct E2EE init and follow-up messages.
type DirectE2eeSession struct{}

// InitiateSession creates the initial encrypted session message.
func (DirectE2eeSession) InitiateSession(metadata DirectEnvelopeMetadata, operationID string, localStaticKeyID string, localStaticPrivate *ecdh.PrivateKey, recipientBundle PrekeyBundle, recipientStaticPublic [32]byte, recipientSignedPrekeyPublic [32]byte, plaintext ApplicationPlaintext) (DirectSessionState, PendingOutboundRecord, DirectInitBody, error) {
	if recipientBundle.Suite != MTIDirectE2EESuite {
		return DirectSessionState{}, PendingOutboundRecord{}, DirectInitBody{}, unsupportedSuite(recipientBundle.Suite)
	}
	senderEphemeralPrivate, err := ecdh.X25519().GenerateKey(randReader)
	if err != nil {
		return DirectSessionState{}, PendingOutboundRecord{}, DirectInitBody{}, err
	}
	initialMaterial, err := DeriveInitialMaterialForInitiator(localStaticPrivate, senderEphemeralPrivate, recipientStaticPublic, recipientSignedPrekeyPublic)
	if err != nil {
		return DirectSessionState{}, PendingOutboundRecord{}, DirectInitBody{}, err
	}
	body := DirectInitBody{
		SessionID:                     initialMaterial.SessionID,
		Suite:                         MTIDirectE2EESuite,
		SenderStaticKeyAgreementID:    localStaticKeyID,
		RecipientBundleID:             recipientBundle.BundleID,
		RecipientStaticKeyAgreementID: recipientBundle.StaticKeyAgreementID,
		RecipientSignedPrekeyID:       recipientBundle.SignedPrekey.KeyID,
		SenderEphemeralPubB64U:        anp.EncodeBase64URL(senderEphemeralPrivate.PublicKey().Bytes()),
	}
	aad, err := BuildInitAAD(metadata, body)
	if err != nil {
		return DirectSessionState{}, PendingOutboundRecord{}, DirectInitBody{}, err
	}
	key, nonce, err := InitialSecretKeyAndNonce(initialMaterial.InitialSecret)
	if err != nil {
		return DirectSessionState{}, PendingOutboundRecord{}, DirectInitBody{}, err
	}
	plaintextBytes, err := json.Marshal(plaintext)
	if err != nil {
		return DirectSessionState{}, PendingOutboundRecord{}, DirectInitBody{}, invalidField("invalid plaintext")
	}
	ciphertext, err := encryptWithRawKey(key, nonce, plaintextBytes, aad)
	if err != nil {
		return DirectSessionState{}, PendingOutboundRecord{}, DirectInitBody{}, err
	}
	body.CiphertextB64U = anp.EncodeBase64URL(ciphertext)
	ratchetPrivate, err := ecdh.X25519().GenerateKey(randReader)
	if err != nil {
		return DirectSessionState{}, PendingOutboundRecord{}, DirectInitBody{}, err
	}
	session := DirectSessionState{
		SessionID:               initialMaterial.SessionID,
		Suite:                   MTIDirectE2EESuite,
		PeerDID:                 metadata.RecipientDID,
		LocalKeyAgreementID:     localStaticKeyID,
		PeerKeyAgreementID:      recipientBundle.StaticKeyAgreementID,
		RootKeyB64U:             anp.EncodeBase64URL(initialMaterial.RootKey[:]),
		SendChainKeyB64U:        anp.EncodeBase64URL(initialMaterial.InitiatorChainKey[:]),
		RecvChainKeyB64U:        anp.EncodeBase64URL(initialMaterial.ResponderChainKey[:]),
		RatchetPublicKeyB64U:    anp.EncodeBase64URL(ratchetPrivate.PublicKey().Bytes()),
		SendN:                   0,
		RecvN:                   0,
		PreviousSendChainLength: 0,
		SkippedMessageKeys:      nil,
		IsInitiator:             true,
	}
	bodyJSON := directInitBodyToMap(body)
	pending := PendingOutboundRecord{OperationID: operationID, MessageID: metadata.MessageID, WireContentType: "application/anp-direct-init+json", BodyJSON: bodyJSON}
	return session, pending, body, nil
}

// AcceptIncomingInit processes an init message for the responder.
func (DirectE2eeSession) AcceptIncomingInit(metadata DirectEnvelopeMetadata, localStaticKeyID string, localStaticPrivate *ecdh.PrivateKey, localSignedPrekeyPrivate *ecdh.PrivateKey, senderStaticPublic [32]byte, body DirectInitBody) (DirectSessionState, ApplicationPlaintext, error) {
	senderEphemeralBytes, err := anp.DecodeBase64URL(body.SenderEphemeralPubB64U)
	if err != nil || len(senderEphemeralBytes) != 32 {
		return DirectSessionState{}, ApplicationPlaintext{}, invalidField("sender_ephemeral_pub_b64u")
	}
	var senderEphemeral [32]byte
	copy(senderEphemeral[:], senderEphemeralBytes)
	initialMaterial, err := DeriveInitialMaterialForResponder(localStaticPrivate, localSignedPrekeyPrivate, senderStaticPublic, senderEphemeral)
	if err != nil {
		return DirectSessionState{}, ApplicationPlaintext{}, err
	}
	aad, err := BuildInitAAD(metadata, body)
	if err != nil {
		return DirectSessionState{}, ApplicationPlaintext{}, err
	}
	key, nonce, err := InitialSecretKeyAndNonce(initialMaterial.InitialSecret)
	if err != nil {
		return DirectSessionState{}, ApplicationPlaintext{}, err
	}
	ciphertext, err := anp.DecodeBase64URL(body.CiphertextB64U)
	if err != nil {
		return DirectSessionState{}, ApplicationPlaintext{}, invalidField("ciphertext_b64u")
	}
	plaintextBytes, err := decryptWithRawKey(key, nonce, ciphertext, aad)
	if err != nil {
		return DirectSessionState{}, ApplicationPlaintext{}, err
	}
	var plaintext ApplicationPlaintext
	if err := json.Unmarshal(plaintextBytes, &plaintext); err != nil {
		return DirectSessionState{}, ApplicationPlaintext{}, invalidField("invalid plaintext json")
	}
	ratchetPrivate, err := ecdh.X25519().GenerateKey(randReader)
	if err != nil {
		return DirectSessionState{}, ApplicationPlaintext{}, err
	}
	session := DirectSessionState{
		SessionID:               body.SessionID,
		Suite:                   MTIDirectE2EESuite,
		PeerDID:                 metadata.SenderDID,
		LocalKeyAgreementID:     localStaticKeyID,
		PeerKeyAgreementID:      body.SenderStaticKeyAgreementID,
		RootKeyB64U:             anp.EncodeBase64URL(initialMaterial.RootKey[:]),
		SendChainKeyB64U:        anp.EncodeBase64URL(initialMaterial.ResponderChainKey[:]),
		RecvChainKeyB64U:        anp.EncodeBase64URL(initialMaterial.InitiatorChainKey[:]),
		RatchetPublicKeyB64U:    anp.EncodeBase64URL(ratchetPrivate.PublicKey().Bytes()),
		SendN:                   0,
		RecvN:                   0,
		PreviousSendChainLength: 0,
		SkippedMessageKeys:      nil,
		IsInitiator:             false,
	}
	return session, plaintext, nil
}

// EncryptFollowUp encrypts a follow-up direct message.
func (DirectE2eeSession) EncryptFollowUp(session *DirectSessionState, metadata DirectEnvelopeMetadata, operationID string, plaintext ApplicationPlaintext) (PendingOutboundRecord, DirectCipherBody, error) {
	sendChainKey, err := decodeFixed32(session.SendChainKeyB64U)
	if err != nil {
		return PendingOutboundRecord{}, DirectCipherBody{}, err
	}
	step := DeriveChainStep(sendChainKey)
	body := DirectCipherBody{SessionID: session.SessionID, Suite: MTIDirectE2EESuite, RatchetHeader: RatchetHeader{DHPubB64U: session.RatchetPublicKeyB64U, PN: strconv.FormatUint(uint64(session.PreviousSendChainLength), 10), N: strconv.FormatUint(uint64(session.SendN), 10)}}
	aad, err := BuildMessageAAD(metadata, body, plaintext.ApplicationContentType)
	if err != nil {
		return PendingOutboundRecord{}, DirectCipherBody{}, err
	}
	plaintextBytes, err := json.Marshal(plaintext)
	if err != nil {
		return PendingOutboundRecord{}, DirectCipherBody{}, invalidField("invalid plaintext")
	}
	ciphertext, err := EncryptWithStep(step, plaintextBytes, aad)
	if err != nil {
		return PendingOutboundRecord{}, DirectCipherBody{}, err
	}
	body.CiphertextB64U = anp.EncodeBase64URL(ciphertext)
	session.SendChainKeyB64U = anp.EncodeBase64URL(step.NextChainKey[:])
	session.SendN++
	pending := PendingOutboundRecord{OperationID: operationID, MessageID: metadata.MessageID, WireContentType: "application/anp-direct-cipher+json", BodyJSON: directCipherBodyToMap(body)}
	return pending, body, nil
}

// DecryptFollowUp decrypts a follow-up direct message.
func (DirectE2eeSession) DecryptFollowUp(session *DirectSessionState, metadata DirectEnvelopeMetadata, body DirectCipherBody, applicationContentType string) (ApplicationPlaintext, error) {
	n, err := strconv.ParseUint(body.RatchetHeader.N, 10, 32)
	if err != nil {
		return ApplicationPlaintext{}, invalidField("ratchet_header.n")
	}
	messageNumber := uint32(n)
	if messageNumber < session.RecvN {
		return ApplicationPlaintext{}, replayDetected("duplicate direct-e2ee message number")
	}
	if messageNumber-session.RecvN > MaxSkip {
		return ApplicationPlaintext{}, replayDetected("message skip exceeded MAX_SKIP")
	}
	session.PeerRatchetPublicKeyB64U = body.RatchetHeader.DHPubB64U
	recvChainKey, err := decodeFixed32(session.RecvChainKeyB64U)
	if err != nil {
		return ApplicationPlaintext{}, err
	}
	for current := session.RecvN; current < messageNumber; current++ {
		skipped := DeriveChainStep(recvChainKey)
		recvChainKey = skipped.NextChainKey
	}
	step := DeriveChainStep(recvChainKey)
	aad, err := BuildMessageAAD(metadata, body, applicationContentType)
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
	session.RecvChainKeyB64U = anp.EncodeBase64URL(step.NextChainKey[:])
	session.RecvN = messageNumber + 1
	return plaintext, nil
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

func encryptWithRawKey(key [32]byte, nonce [12]byte, plaintext []byte, aad []byte) ([]byte, error) {
	step := ChainStep{MessageKey: key, Nonce: nonce, NextChainKey: key}
	return EncryptWithStep(step, plaintext, aad)
}

func decryptWithRawKey(key [32]byte, nonce [12]byte, ciphertext []byte, aad []byte) ([]byte, error) {
	step := ChainStep{MessageKey: key, Nonce: nonce, NextChainKey: key}
	return DecryptWithStep(step, ciphertext, aad)
}

func directInitBodyToMap(body DirectInitBody) map[string]any {
	return map[string]any{
		"session_id":                        body.SessionID,
		"suite":                             body.Suite,
		"sender_static_key_agreement_id":    body.SenderStaticKeyAgreementID,
		"recipient_bundle_id":               body.RecipientBundleID,
		"recipient_static_key_agreement_id": body.RecipientStaticKeyAgreementID,
		"recipient_signed_prekey_id":        body.RecipientSignedPrekeyID,
		"recipient_one_time_prekey_id":      emptyToNil(body.RecipientOneTimePrekeyID),
		"sender_ephemeral_pub_b64u":         body.SenderEphemeralPubB64U,
		"ciphertext_b64u":                   body.CiphertextB64U,
	}
}

func directCipherBodyToMap(body DirectCipherBody) map[string]any {
	return map[string]any{
		"session_id":      body.SessionID,
		"suite":           body.Suite,
		"ratchet_header":  map[string]any{"dh_pub_b64u": body.RatchetHeader.DHPubB64U, "pn": body.RatchetHeader.PN, "n": body.RatchetHeader.N},
		"ciphertext_b64u": body.CiphertextB64U,
	}
}
