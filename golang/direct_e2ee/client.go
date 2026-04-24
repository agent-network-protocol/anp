package directe2ee

import (
	"context"
	"crypto/ecdh"
	"errors"
	"sort"
	"strings"

	anp "github.com/agent-network-protocol/anp/golang"
)

// DIDResolver resolves a DID document.
type DIDResolver func(ctx context.Context, did string) (map[string]any, error)

// MessageServiceDirectE2eeClient is a reference direct E2EE client.
type MessageServiceDirectE2eeClient struct {
	localDID                  string
	localServiceDID           string
	rpcClient                 RPCClient
	didDocumentResolver       DIDResolver
	sessionStore              SessionStore
	signedPrekeyStore         SignedPrekeyStore
	oneTimePrekeyStore        OneTimePrekeyStore
	staticKeyAgreementPrivate *ecdh.PrivateKey
	staticKeyAgreementID      string
	prekeyManager             *PrekeyManager
	pendingByPeer             map[string][]map[string]any
}

// NewMessageServiceDirectE2eeClient creates a reference direct E2EE client.
func NewMessageServiceDirectE2eeClient(localDID string, signingPrivateKey anp.PrivateKeyMaterial, signingVerificationMethod string, staticKeyAgreementPrivate anp.PrivateKeyMaterial, staticKeyAgreementID string, rpcClient RPCClient, didDocumentResolver DIDResolver, sessionStore SessionStore, signedPrekeyStore SignedPrekeyStore, oneTimePrekeyStores ...OneTimePrekeyStore) (*MessageServiceDirectE2eeClient, error) {
	privateKey, err := ecdh.X25519().NewPrivateKey(staticKeyAgreementPrivate.Bytes)
	if err != nil {
		return nil, err
	}
	var oneTimePrekeyStore OneTimePrekeyStore
	if len(oneTimePrekeyStores) > 0 {
		oneTimePrekeyStore = oneTimePrekeyStores[0]
	}
	localDocument, err := didDocumentResolver(context.Background(), localDID)
	if err != nil {
		return nil, err
	}
	localServiceDID, err := messageServiceDIDFromDocument(localDocument)
	if err != nil {
		return nil, err
	}
	return &MessageServiceDirectE2eeClient{localDID: localDID, localServiceDID: localServiceDID, rpcClient: rpcClient, didDocumentResolver: didDocumentResolver, sessionStore: sessionStore, signedPrekeyStore: signedPrekeyStore, oneTimePrekeyStore: oneTimePrekeyStore, staticKeyAgreementPrivate: privateKey, staticKeyAgreementID: staticKeyAgreementID, prekeyManager: NewPrekeyManager(localDID, localServiceDID, staticKeyAgreementID, signingPrivateKey, signingVerificationMethod, signedPrekeyStore, rpcClient, oneTimePrekeyStore), pendingByPeer: map[string][]map[string]any{}}, nil
}

// PublishPrekeyBundle ensures and publishes a fresh prekey bundle.
func (c *MessageServiceDirectE2eeClient) PublishPrekeyBundle() (map[string]any, error) {
	bundle, err := c.prekeyManager.EnsureFreshPrekeyBundle()
	if err != nil {
		return nil, err
	}
	return c.prekeyManager.PublishPrekeyBundle(bundle)
}

// EnsureFreshPrekeyBundle ensures a fresh prekey bundle exists locally.
func (c *MessageServiceDirectE2eeClient) EnsureFreshPrekeyBundle() (PrekeyBundle, error) {
	return c.prekeyManager.EnsureFreshPrekeyBundle()
}

// VerifiedPrekeyBundle is a verified remote prekey bundle plus an optional leased OPK.
type VerifiedPrekeyBundle struct {
	Bundle        PrekeyBundle
	OneTimePrekey *OneTimePrekey
}

// GetVerifiedPrekeyBundle fetches and verifies a peer prekey bundle.
func (c *MessageServiceDirectE2eeClient) GetVerifiedPrekeyBundle(ctx context.Context, targetDID string) (VerifiedPrekeyBundle, error) {
	didDocument, err := c.didDocumentResolver(ctx, targetDID)
	if err != nil {
		return VerifiedPrekeyBundle{}, err
	}
	targetServiceDID, err := messageServiceDIDFromDocument(didDocument)
	if err != nil {
		return VerifiedPrekeyBundle{}, err
	}
	response, err := c.fetchPrekeyBundleResponse(targetDID, targetServiceDID, true)
	if err != nil {
		if shouldRetryWithoutOPK(err) {
			response, err = c.fetchPrekeyBundleResponse(targetDID, targetServiceDID, false)
		}
		if err != nil {
			return VerifiedPrekeyBundle{}, err
		}
	}
	bundleValue, ok := response["prekey_bundle"].(map[string]any)
	if !ok {
		return VerifiedPrekeyBundle{}, invalidField("prekey_bundle")
	}
	bundle, err := prekeyBundleFromMap(bundleValue)
	if err != nil {
		return VerifiedPrekeyBundle{}, err
	}
	if err := VerifyPrekeyBundle(bundle, didDocument); err != nil {
		return VerifiedPrekeyBundle{}, err
	}
	result := VerifiedPrekeyBundle{Bundle: bundle}
	if oneTimeValue, ok := response["one_time_prekey"].(map[string]any); ok {
		oneTimePrekey, err := oneTimePrekeyFromMap(oneTimeValue)
		if err != nil {
			return VerifiedPrekeyBundle{}, err
		}
		result.OneTimePrekey = &oneTimePrekey
	}
	return result, nil
}

// SendText sends a text payload.
func (c *MessageServiceDirectE2eeClient) SendText(ctx context.Context, peerDID string, text string, operationID string, messageID string) (map[string]any, error) {
	return c.sendApplicationPlaintext(ctx, peerDID, NewTextPlaintext("text/plain", text), operationID, messageID)
}

// SendJSON sends a JSON payload.
func (c *MessageServiceDirectE2eeClient) SendJSON(ctx context.Context, peerDID string, payload map[string]any, operationID string, messageID string) (map[string]any, error) {
	return c.sendApplicationPlaintext(ctx, peerDID, NewJSONPlaintext("application/json", payload), operationID, messageID)
}

func (c *MessageServiceDirectE2eeClient) sendApplicationPlaintext(ctx context.Context, peerDID string, plaintext ApplicationPlaintext, operationID string, messageID string) (map[string]any, error) {
	if operationID == "" || messageID == "" {
		return nil, missingField("operation_id/message_id")
	}
	if operationID != messageID {
		return nil, invalidField("direct-e2ee requires operation_id to equal message_id")
	}
	session, exists, err := c.sessionStore.FindByPeerDID(peerDID)
	if err != nil {
		return nil, err
	}
	metadata := DirectEnvelopeMetadata{SenderDID: c.localDID, RecipientDID: peerDID, MessageID: messageID, Profile: "anp.direct.e2ee.v1", SecurityProfile: "direct-e2ee"}
	sessionBuilder := DirectE2eeSession{}
	if !exists {
		verifiedBundle, err := c.GetVerifiedPrekeyBundle(ctx, peerDID)
		if err != nil {
			return nil, err
		}
		didDocument, err := c.didDocumentResolver(ctx, peerDID)
		if err != nil {
			return nil, err
		}
		recipientStaticPublic, err := ExtractX25519PublicKey(didDocument, verifiedBundle.Bundle.StaticKeyAgreementID)
		if err != nil {
			return nil, err
		}
		recipientSignedPrekeyBytes, err := anp.DecodeBase64URL(verifiedBundle.Bundle.SignedPrekey.PublicKeyB64U)
		if err != nil || len(recipientSignedPrekeyBytes) != 32 {
			return nil, invalidField("signed_prekey.public_key_b64u")
		}
		var recipientSignedPrekey [32]byte
		copy(recipientSignedPrekey[:], recipientSignedPrekeyBytes)
		var recipientOneTimePrekeyPublic *[32]byte
		recipientOneTimePrekeyID := ""
		if verifiedBundle.OneTimePrekey != nil {
			recipientOneTimePrekeyBytes, err := anp.DecodeBase64URL(verifiedBundle.OneTimePrekey.PublicKeyB64U)
			if err != nil || len(recipientOneTimePrekeyBytes) != 32 {
				return nil, invalidField("one_time_prekey.public_key_b64u")
			}
			recipientOneTimePrekeyPublic = new([32]byte)
			copy(recipientOneTimePrekeyPublic[:], recipientOneTimePrekeyBytes)
			recipientOneTimePrekeyID = verifiedBundle.OneTimePrekey.KeyID
		}
		nextSession, _, body, err := sessionBuilder.InitiateSessionWithOPK(metadata, operationID, c.staticKeyAgreementID, c.staticKeyAgreementPrivate, verifiedBundle.Bundle, recipientStaticPublic, recipientSignedPrekey, recipientOneTimePrekeyPublic, recipientOneTimePrekeyID, plaintext)
		if err != nil {
			return nil, err
		}
		if err := c.sessionStore.SaveSession(nextSession); err != nil {
			return nil, err
		}
		return c.rpcClient("direct.send", map[string]any{"meta": map[string]any{"anp_version": "1.0", "profile": "anp.direct.e2ee.v1", "security_profile": "direct-e2ee", "sender_did": c.localDID, "target": map[string]any{"kind": "agent", "did": peerDID}, "operation_id": operationID, "message_id": messageID, "content_type": ContentTypeDirectInit}, "body": directInitBodyToMap(body)})
	}
	pending, body, err := sessionBuilder.EncryptFollowUp(&session, metadata, operationID, plaintext)
	if err != nil {
		return nil, err
	}
	if err := c.sessionStore.SaveSession(session); err != nil {
		return nil, err
	}
	_ = pending
	return c.rpcClient("direct.send", map[string]any{"meta": map[string]any{"anp_version": "1.0", "profile": "anp.direct.e2ee.v1", "security_profile": "direct-e2ee", "sender_did": c.localDID, "target": map[string]any{"kind": "agent", "did": peerDID}, "operation_id": operationID, "message_id": messageID, "content_type": ContentTypeDirectCipher}, "body": directCipherBodyToMap(body)})
}

// ProcessIncoming processes an inbound message-service notification or message view.
func (c *MessageServiceDirectE2eeClient) ProcessIncoming(ctx context.Context, message map[string]any) (map[string]any, error) {
	meta, _ := message["meta"].(map[string]any)
	body, _ := message["body"].(map[string]any)
	senderDID := stringValue(meta["sender_did"])
	target, _ := meta["target"].(map[string]any)
	recipientDID := stringValue(target["did"])
	contentType := stringValue(meta["content_type"])
	metadata := DirectEnvelopeMetadata{SenderDID: senderDID, RecipientDID: recipientDID, MessageID: stringValue(meta["message_id"]), Profile: stringValue(meta["profile"]), SecurityProfile: stringValue(meta["security_profile"])}
	sessionBuilder := DirectE2eeSession{}
	if contentType == ContentTypeDirectInit {
		initBody, err := directInitBodyFromMap(body)
		if err != nil {
			return nil, err
		}
		senderDocument, err := c.didDocumentResolver(ctx, senderDID)
		if err != nil {
			return nil, err
		}
		senderStaticPublic, err := ExtractX25519PublicKey(senderDocument, initBody.SenderStaticKeyAgreementID)
		if err != nil {
			return nil, err
		}
		signedPrekeyMaterial, _, err := c.signedPrekeyStore.LoadSignedPrekey(initBody.RecipientSignedPrekeyID)
		if err != nil {
			return nil, err
		}
		signedPrekeyPrivate, err := ecdh.X25519().NewPrivateKey(signedPrekeyMaterial.Bytes)
		if err != nil {
			return nil, err
		}
		var oneTimePrekeyPrivate *ecdh.PrivateKey
		if initBody.RecipientOneTimePrekeyID != "" {
			if c.oneTimePrekeyStore == nil {
				return nil, missingField("one-time prekey store")
			}
			oneTimeMaterial, _, err := c.oneTimePrekeyStore.LoadOneTimePrekey(initBody.RecipientOneTimePrekeyID)
			if err != nil {
				return nil, err
			}
			oneTimePrekeyPrivate, err = ecdh.X25519().NewPrivateKey(oneTimeMaterial.Bytes)
			if err != nil {
				return nil, err
			}
		}
		nextSession, plaintext, err := sessionBuilder.AcceptIncomingInitWithOPK(metadata, c.staticKeyAgreementID, c.staticKeyAgreementPrivate, signedPrekeyPrivate, oneTimePrekeyPrivate, senderStaticPublic, initBody)
		if err != nil {
			return nil, err
		}
		if initBody.RecipientOneTimePrekeyID != "" {
			if err := c.oneTimePrekeyStore.DeleteOneTimePrekey(initBody.RecipientOneTimePrekeyID); err != nil {
				return nil, err
			}
		}
		if err := c.sessionStore.SaveSession(nextSession); err != nil {
			return nil, err
		}
		result := map[string]any{"state": "decrypted", "plaintext": plaintextToMap(plaintext)}
		if pending := c.pendingByPeer[senderDID]; len(pending) > 0 {
			pendingResults := []any{}
			for _, pendingMessage := range pending {
				pendingResult, pendingErr := c.ProcessIncoming(ctx, pendingMessage)
				if pendingErr == nil {
					pendingResults = append(pendingResults, pendingResult)
				}
			}
			delete(c.pendingByPeer, senderDID)
			result["pending_results"] = pendingResults
		}
		return result, nil
	}
	if contentType != ContentTypeDirectCipher {
		return nil, &Error{Code: "unsupported", Message: "unsupported content type: " + contentType}
	}
	cipherBody, err := directCipherBodyFromMap(body)
	if err != nil {
		return nil, err
	}
	session, err := c.sessionStore.LoadSession(cipherBody.SessionID)
	if err != nil {
		c.pendingByPeer[senderDID] = append(c.pendingByPeer[senderDID], message)
		return map[string]any{"state": "pending"}, nil
	}
	plaintext, decryptErr := sessionBuilder.DecryptFollowUp(&session, metadata, cipherBody)
	if decryptErr != nil {
		if err := c.sessionStore.SaveSession(session); err != nil {
			return nil, err
		}
		return map[string]any{"state": "undecryptable"}, nil
	}
	if err := c.sessionStore.SaveSession(session); err != nil {
		return nil, err
	}
	return map[string]any{"state": "decrypted", "plaintext": plaintextToMap(plaintext)}, nil
}

// DecryptHistoryPage processes a page of messages in server order.
func (c *MessageServiceDirectE2eeClient) DecryptHistoryPage(ctx context.Context, messages []map[string]any) ([]map[string]any, error) {
	sortedMessages := append([]map[string]any(nil), messages...)
	sort.SliceStable(sortedMessages, func(i, j int) bool {
		leftSeq, _ := sortedMessages[i]["server_seq"].(float64)
		rightSeq, _ := sortedMessages[j]["server_seq"].(float64)
		if leftSeq == rightSeq {
			leftMeta, _ := sortedMessages[i]["meta"].(map[string]any)
			rightMeta, _ := sortedMessages[j]["meta"].(map[string]any)
			return stringValue(leftMeta["message_id"]) < stringValue(rightMeta["message_id"])
		}
		return leftSeq < rightSeq
	})
	results := make([]map[string]any, 0, len(sortedMessages))
	for _, message := range sortedMessages {
		result, err := c.ProcessIncoming(ctx, message)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func prekeyBundleFromMap(value map[string]any) (PrekeyBundle, error) {
	signedPrekeyMap, _ := value["signed_prekey"].(map[string]any)
	proofValue, _ := value["proof"].(map[string]any)
	return PrekeyBundle{BundleID: stringValue(value["bundle_id"]), OwnerDID: stringValue(value["owner_did"]), Suite: stringValue(value["suite"]), StaticKeyAgreementID: stringValue(value["static_key_agreement_id"]), SignedPrekey: SignedPrekey{KeyID: stringValue(signedPrekeyMap["key_id"]), PublicKeyB64U: stringValue(signedPrekeyMap["public_key_b64u"]), ExpiresAt: stringValue(signedPrekeyMap["expires_at"])}, Proof: cloneMap(proofValue)}, nil
}

func oneTimePrekeyFromMap(value map[string]any) (OneTimePrekey, error) {
	keyID := stringValue(value["key_id"])
	publicKeyB64U := stringValue(value["public_key_b64u"])
	if keyID == "" {
		return OneTimePrekey{}, missingField("one_time_prekey.key_id")
	}
	if publicKeyB64U == "" {
		return OneTimePrekey{}, missingField("one_time_prekey.public_key_b64u")
	}
	return OneTimePrekey{KeyID: keyID, PublicKeyB64U: publicKeyB64U}, nil
}

func directInitBodyFromMap(value map[string]any) (DirectInitBody, error) {
	return DirectInitBody{SessionID: stringValue(value["session_id"]), Suite: stringValue(value["suite"]), SenderStaticKeyAgreementID: stringValue(value["sender_static_key_agreement_id"]), RecipientBundleID: stringValue(value["recipient_bundle_id"]), RecipientSignedPrekeyID: stringValue(value["recipient_signed_prekey_id"]), RecipientOneTimePrekeyID: stringValue(value["recipient_one_time_prekey_id"]), SenderEphemeralPubB64U: stringValue(value["sender_ephemeral_pub_b64u"]), CiphertextB64U: stringValue(value["ciphertext_b64u"])}, nil
}

func directCipherBodyFromMap(value map[string]any) (DirectCipherBody, error) {
	headerMap, _ := value["ratchet_header"].(map[string]any)
	return DirectCipherBody{SessionID: stringValue(value["session_id"]), Suite: stringValue(value["suite"]), RatchetHeader: RatchetHeader{DHPubB64U: stringValue(headerMap["dh_pub_b64u"]), PN: stringValue(headerMap["pn"]), N: stringValue(headerMap["n"])}, CiphertextB64U: stringValue(value["ciphertext_b64u"])}, nil
}

func plaintextToMap(value ApplicationPlaintext) map[string]any {
	result := map[string]any{"application_content_type": value.ApplicationContentType}
	if value.ConversationID != "" {
		result["conversation_id"] = value.ConversationID
	}
	if value.ReplyToMessageID != "" {
		result["reply_to_message_id"] = value.ReplyToMessageID
	}
	if len(value.Annotations) > 0 {
		result["annotations"] = value.Annotations
	}
	if value.Text != "" {
		result["text"] = value.Text
	}
	if len(value.Payload) > 0 {
		result["payload"] = value.Payload
	}
	if value.PayloadB64U != "" {
		result["payload_b64u"] = value.PayloadB64U
	}
	return result
}

func (c *MessageServiceDirectE2eeClient) fetchPrekeyBundleResponse(targetDID string, targetServiceDID string, requireOPK bool) (map[string]any, error) {
	operationID, err := freshOperationID("op-get-prekey-")
	if err != nil {
		return nil, err
	}
	return c.rpcClient("direct.e2ee.get_prekey_bundle", map[string]any{"meta": map[string]any{"anp_version": "1.0", "profile": "anp.direct.e2ee.v1", "security_profile": "transport-protected", "sender_did": c.localDID, "target": map[string]any{"kind": "service", "did": targetServiceDID}, "operation_id": operationID}, "body": map[string]any{"target_did": targetDID, "require_opk": requireOPK}})
}

func shouldRetryWithoutOPK(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "anp.direct.e2ee.opk_unavailable") {
		return true
	}
	if strings.Contains(err.Error(), "direct.e2ee_opk_unsupported") {
		return true
	}
	if strings.Contains(err.Error(), "4003") {
		return true
	}
	if strings.Contains(err.Error(), "3402") {
		return true
	}
	var directErr *Error
	if errors.As(err, &directErr) && (directErr.Code == "anp.direct.e2ee.opk_unavailable" || directErr.Code == "direct.e2ee_opk_unsupported") {
		return true
	}
	return false
}
