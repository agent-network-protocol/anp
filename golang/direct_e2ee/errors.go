package directe2ee

import "fmt"

// Error reports direct E2EE processing failures.
type Error struct {
	Code    string
	Message string
}

// Error implements error.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func unsupportedSuite(suite string) error {
	return &Error{Code: "unsupported_suite", Message: fmt.Sprintf("unsupported suite: %s", suite)}
}

func missingField(field string) error {
	return &Error{Code: "missing_field", Message: fmt.Sprintf("missing field: %s", field)}
}

func invalidField(field string) error {
	return &Error{Code: "invalid_field", Message: fmt.Sprintf("invalid field: %s", field)}
}

func cryptoError(message string) error {
	return &Error{Code: "crypto_error", Message: fmt.Sprintf("crypto error: %s", message)}
}

func sessionNotFound(sessionID string) error {
	return &Error{Code: "session_not_found", Message: fmt.Sprintf("session not found: %s", sessionID)}
}

func pendingNotFound(operationID string) error {
	return &Error{Code: "pending_outbound_not_found", Message: fmt.Sprintf("pending outbound not found: %s", operationID)}
}

func replayDetected(message string) error {
	return &Error{Code: "replay_detected", Message: fmt.Sprintf("replay detected: %s", message)}
}
