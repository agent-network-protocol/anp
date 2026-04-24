package directe2ee

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
)

var randReader io.Reader = rand.Reader

const anpMessageServiceType = "ANPMessageService"

func hashProvider() hash.Hash { return sha256.New() }

func freshOperationID(prefix string) (string, error) {
	random := make([]byte, 16)
	if _, err := io.ReadFull(randReader, random); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(random), nil
}

func cloneMap(input map[string]any) map[string]any {
	data, _ := json.Marshal(input)
	var result map[string]any
	_ = json.Unmarshal(data, &result)
	if result == nil {
		result = map[string]any{}
	}
	return result
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func messageServiceDIDFromDocument(didDocument map[string]any) (string, error) {
	services, ok := didDocument["service"].([]any)
	if !ok {
		return "", missingField("service")
	}
	candidates := make([]string, 0, len(services))
	for _, entry := range services {
		service, ok := entry.(map[string]any)
		if !ok || stringValue(service["type"]) != anpMessageServiceType {
			continue
		}
		serviceDID := stringValue(service["serviceDid"])
		if serviceDID == "" {
			continue
		}
		candidates = append(candidates, serviceDID)
	}
	if len(candidates) == 0 {
		return "", missingField("serviceDid")
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	unique := map[string]struct{}{}
	for _, candidate := range candidates {
		unique[candidate] = struct{}{}
	}
	if len(unique) == 1 {
		return candidates[0], nil
	}
	return "", invalidField("ANPMessageService.serviceDid")
}
