package anp

import "github.com/agent-network-protocol/anp/golang/internal/base64util"

// EncodeBase64URL encodes bytes using raw URL-safe base64.
func EncodeBase64URL(value []byte) string {
	return base64util.EncodeURL(value)
}

// DecodeBase64URL decodes raw URL-safe base64.
func DecodeBase64URL(value string) ([]byte, error) {
	return base64util.DecodeURL(value)
}

// EncodeBase64 encodes bytes using standard base64.
func EncodeBase64(value []byte) string {
	return base64util.EncodeStd(value)
}

// DecodeBase64 decodes standard base64.
func DecodeBase64(value string) ([]byte, error) {
	return base64util.DecodeStd(value)
}
