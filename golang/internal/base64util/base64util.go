package base64util

import "encoding/base64"

// EncodeURL encodes bytes using raw URL-safe base64.
func EncodeURL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

// DecodeURL decodes raw URL-safe base64.
func DecodeURL(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

// EncodeStd encodes bytes using standard base64.
func EncodeStd(value []byte) string {
	return base64.StdEncoding.EncodeToString(value)
}

// DecodeStd decodes standard base64.
func DecodeStd(value string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(value)
}
