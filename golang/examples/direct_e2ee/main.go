package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/authentication"
	directe2ee "github.com/agent-network-protocol/anp/golang/direct_e2ee"
)

type inMemoryDirectService struct {
	bundles map[string]map[string]any
	inboxes map[string][]map[string]any
	nextSeq int
}

func newInMemoryDirectService() *inMemoryDirectService {
	return &inMemoryDirectService{
		bundles: map[string]map[string]any{},
		inboxes: map[string][]map[string]any{},
	}
}

func (s *inMemoryDirectService) rpc(method string, params map[string]any) (map[string]any, error) {
	switch method {
	case "direct.e2ee.publish_prekey_bundle":
		body := params["body"].(map[string]any)
		bundle := cloneMap(body["prekey_bundle"].(map[string]any))
		ownerDID := stringValue(bundle["owner_did"])
		s.bundles[ownerDID] = bundle
		return map[string]any{
			"published":    true,
			"owner_did":    ownerDID,
			"bundle_id":    bundle["bundle_id"],
			"published_at": "2026-03-31T09:59:01Z",
		}, nil
	case "direct.e2ee.get_prekey_bundle":
		body := params["body"].(map[string]any)
		targetDID := stringValue(body["target_did"])
		bundle, ok := s.bundles[targetDID]
		if !ok {
			return nil, fmt.Errorf("prekey bundle not found for %s", targetDID)
		}
		return map[string]any{
			"target_did":    targetDID,
			"prekey_bundle": cloneMap(bundle),
		}, nil
	case "direct.send":
		meta := cloneMap(params["meta"].(map[string]any))
		body := cloneMap(params["body"].(map[string]any))
		target := meta["target"].(map[string]any)
		targetDID := stringValue(target["did"])
		s.nextSeq++
		message := map[string]any{
			"server_seq": float64(s.nextSeq),
			"meta":       meta,
			"body":       body,
		}
		s.inboxes[targetDID] = append(s.inboxes[targetDID], message)
		return map[string]any{
			"accepted":     true,
			"message_id":   meta["message_id"],
			"operation_id": meta["operation_id"],
			"target_did":   targetDID,
			"body":         body,
		}, nil
	default:
		return nil, fmt.Errorf("unexpected RPC method: %s", method)
	}
}

func (s *inMemoryDirectService) drainInbox(did string) []map[string]any {
	messages := append([]map[string]any(nil), s.inboxes[did]...)
	delete(s.inboxes, did)
	return messages
}

func main() {
	ctx := context.Background()
	workspace, err := os.MkdirTemp("", "anp-direct-e2ee-example-")
	if err != nil {
		log.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(workspace)

	aliceBundle, err := authentication.CreateDidWBADocument(
		"a.example",
		authentication.DidDocumentOptions{
			DidProfile:   authentication.DidProfileE1,
			PathSegments: []string{"agents", "alice"},
			EnableE2EE:   boolPtr(true),
		},
	)
	if err != nil {
		log.Fatalf("CreateDidWBADocument(alice) failed: %v", err)
	}
	bobBundle, err := authentication.CreateDidWBADocument(
		"b.example",
		authentication.DidDocumentOptions{
			DidProfile:   authentication.DidProfileE1,
			PathSegments: []string{"agents", "bob"},
			EnableE2EE:   boolPtr(true),
		},
	)
	if err != nil {
		log.Fatalf("CreateDidWBADocument(bob) failed: %v", err)
	}

	resolver := didResolver(map[string]map[string]any{
		stringValue(aliceBundle.DidDocument["id"]): cloneMap(aliceBundle.DidDocument),
		stringValue(bobBundle.DidDocument["id"]):   cloneMap(bobBundle.DidDocument),
	})
	service := newInMemoryDirectService()

	aliceClient := mustClient(
		"alice",
		workspace,
		aliceBundle,
		service,
		resolver,
	)
	bobClient := mustClient(
		"bob",
		workspace,
		bobBundle,
		service,
		resolver,
	)

	published, err := bobClient.PublishPrekeyBundle()
	if err != nil {
		log.Fatalf("PublishPrekeyBundle failed: %v", err)
	}
	fmt.Printf("Bob published prekey bundle: %+v\n", published)

	aliceDID := stringValue(aliceBundle.DidDocument["id"])
	bobDID := stringValue(bobBundle.DidDocument["id"])

	initAck, err := aliceClient.SendText(ctx, bobDID, "Hello Bob, this is Alice.", "op-init", "msg-001")
	if err != nil {
		log.Fatalf("Alice SendText failed: %v", err)
	}
	fmt.Printf("Alice sent init message: %+v\n", initAck)

	followUpAck, err := aliceClient.SendJSON(ctx, bobDID, map[string]any{"event": "wave"}, "op-002", "msg-002")
	if err != nil {
		log.Fatalf("Alice SendJSON failed: %v", err)
	}
	fmt.Printf("Alice sent follow-up message: %+v\n", followUpAck)

	bobInbox := service.drainInbox(bobDID)
	pendingResult, err := bobClient.ProcessIncoming(ctx, bobInbox[1])
	if err != nil {
		log.Fatalf("Bob ProcessIncoming(follow-up first) failed: %v", err)
	}
	fmt.Printf("Bob processed second message first: %+v\n", pendingResult)

	initResult, err := bobClient.ProcessIncoming(ctx, bobInbox[0])
	if err != nil {
		log.Fatalf("Bob ProcessIncoming(init) failed: %v", err)
	}
	fmt.Printf("Bob decrypted init and pending follow-up: %+v\n", initResult)

	bobReplyAck, err := bobClient.SendText(ctx, aliceDID, "Hello Alice, Bob received your wave.", "op-003", "msg-003")
	if err != nil {
		log.Fatalf("Bob SendText failed: %v", err)
	}
	fmt.Printf("Bob replied over the established session: %+v\n", bobReplyAck)

	aliceInbox := service.drainInbox(aliceDID)
	aliceResults, err := aliceClient.DecryptHistoryPage(ctx, aliceInbox)
	if err != nil {
		log.Fatalf("Alice DecryptHistoryPage failed: %v", err)
	}
	for index, result := range aliceResults {
		encoded, _ := json.Marshal(result)
		fmt.Printf("Alice processed history item %d: %s\n", index+1, string(encoded))
	}
}

func mustClient(name string, workspace string, bundle authentication.DidDocumentBundle, service *inMemoryDirectService, resolver directe2ee.DIDResolver) *directe2ee.MessageServiceDirectE2eeClient {
	signingKey, err := anp.PrivateKeyFromPEM(bundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		log.Fatalf("PrivateKeyFromPEM(%s signing) failed: %v", name, err)
	}
	staticKey, err := anp.PrivateKeyFromPEM(bundle.Keys[authentication.VMKeyE2EEAgreement].PrivateKeyPEM)
	if err != nil {
		log.Fatalf("PrivateKeyFromPEM(%s static) failed: %v", name, err)
	}
	sessionStore, err := directe2ee.NewFileSessionStore(filepath.Join(workspace, name+"-sessions"))
	if err != nil {
		log.Fatalf("NewFileSessionStore(%s) failed: %v", name, err)
	}
	signedPrekeyStore, err := directe2ee.NewFileSignedPrekeyStore(filepath.Join(workspace, name+"-spk"))
	if err != nil {
		log.Fatalf("NewFileSignedPrekeyStore(%s) failed: %v", name, err)
	}
	client, err := directe2ee.NewMessageServiceDirectE2eeClient(
		stringValue(bundle.DidDocument["id"]),
		signingKey,
		stringValue(bundle.DidDocument["id"])+"#"+authentication.VMKeyAuth,
		staticKey,
		stringValue(bundle.DidDocument["id"])+"#"+authentication.VMKeyE2EEAgreement,
		service.rpc,
		resolver,
		sessionStore,
		signedPrekeyStore,
	)
	if err != nil {
		log.Fatalf("NewMessageServiceDirectE2eeClient(%s) failed: %v", name, err)
	}
	return client
}

func didResolver(documents map[string]map[string]any) directe2ee.DIDResolver {
	return func(_ context.Context, did string) (map[string]any, error) {
		document, ok := documents[did]
		if !ok {
			return nil, fmt.Errorf("unknown DID: %s", did)
		}
		return cloneMap(document), nil
	}
}

func cloneMap(input map[string]any) map[string]any {
	data, err := json.Marshal(input)
	if err != nil {
		panic(err)
	}
	var output map[string]any
	if err := json.Unmarshal(data, &output); err != nil {
		panic(err)
	}
	return output
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func boolPtr(value bool) *bool { return &value }
