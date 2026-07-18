package directe2ee

import "fmt"

// V2ProtocolError is one normative P5 v2 JSON-RPC error allocation.
type V2ProtocolError struct {
	Code    int    `json:"code"`
	ANPCode string `json:"anp_code"`
}

var V2ProtocolErrors = []V2ProtocolError{
	{4000, "anp.direct.e2ee.bundle_not_found"},
	{4001, "anp.direct.e2ee.bundle_invalid"},
	{4002, "anp.direct.e2ee.bundle_expired"},
	{4003, "anp.direct.e2ee.opk_unavailable"},
	{4004, "anp.direct.e2ee.missing_key_agreement"},
	{4005, "anp.direct.e2ee.session_not_found"},
	{4006, "anp.direct.e2ee.session_conflict"},
	{4007, "anp.direct.e2ee.bad_init_message"},
	{4008, "anp.direct.e2ee.replay_detected"},
	{4009, "anp.direct.e2ee.decrypt_failed"},
	{4010, "anp.direct.e2ee.max_skip_exceeded"},
	{4011, "anp.direct.e2ee.reset_required"},
	{4012, "anp.direct.e2ee.invalid_security_binding"},
}

// DirectE2EEV2ErrorByCode resolves only the normative 4000-4012 table.
func DirectE2EEV2ErrorByCode(code int) (V2ProtocolError, bool) {
	for _, entry := range V2ProtocolErrors {
		if entry.Code == code {
			return entry, true
		}
	}
	return V2ProtocolError{}, false
}

func invalidV2(message string) error {
	return fmt.Errorf("invalid P5 v2 wire object: %s", message)
}
