package groupe2ee

import "fmt"

type V2ProtocolError struct {
	Code    int
	ANPCode string
}

var V2ProtocolErrors = []V2ProtocolError{
	{5000, "group.e2ee.key_package_not_found"},
	{5001, "group.e2ee.invalid_key_package"},
	{5002, "group.e2ee.did_binding_invalid"},
	{5003, "group.e2ee.controller_required"},
	{5004, "group.e2ee.state_not_ready"},
	{5005, "group.e2ee.epoch_conflict"},
	{5006, "group.e2ee.crypto_group_mismatch"},
	{5007, "group.e2ee.private_message_invalid"},
	{5008, "group.e2ee.commit_invalid"},
	{5009, "group.e2ee.welcome_invalid"},
	{5010, "group.e2ee.fork_suspected"},
	{5011, "group.e2ee.notice_type_unsupported"},
	{5012, "group.e2ee.key_package_consumed"},
}

func LookupV2ProtocolError(code int) (V2ProtocolError, bool) {
	for _, entry := range V2ProtocolErrors {
		if entry.Code == code {
			return entry, true
		}
	}
	return V2ProtocolError{}, false
}

type V2Error struct {
	Message string
}

func (err *V2Error) Error() string { return "invalid P6 v2 field: " + err.Message }

func invalidV2(message string) error { return &V2Error{Message: message} }

var ErrP6V2PublicReleaseBlocked = fmt.Errorf(
	"P6 v2 public release is blocked until the draft MLS extension has a stable registered codepoint",
)
