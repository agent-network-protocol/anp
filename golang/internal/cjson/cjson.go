package cjson

import (
	"encoding/json"

	"github.com/gowebpki/jcs"
)

// Marshal serializes a value using RFC 8785 JCS canonicalization.
func Marshal(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}
