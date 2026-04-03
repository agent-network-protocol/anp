package directe2ee

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
	"io"
)

var randReader io.Reader = rand.Reader

func hashProvider() hash.Hash { return sha256.New() }

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
