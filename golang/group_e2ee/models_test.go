package groupe2ee

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLeaveRequestWireModelsKeepControlPlaneOpaque(t *testing.T) {
	request := GroupLeaveRequestObject{
		LeaveRequestID: "leave-req-1",
		GroupDID:       "did:wba:example.com:groups:demo:e1",
		RequesterDID:   "did:wba:example.com:users:bob:e1",
		GroupStateRef: GroupStateRef{
			GroupDID:          "did:wba:example.com:groups:demo:e1",
			GroupStateVersion: "7",
		},
		ReasonText: "leaving this workspace",
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, token := range []string{"leave_request_id", "requester_did", "group_state_ref"} {
		if !strings.Contains(text, token) {
			t.Fatalf("leave request JSON missing %s: %s", token, text)
		}
	}
	for _, forbidden := range []string{"commit_b64u", "private", "plaintext"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("leave request JSON leaked lifecycle/private field %s: %s", forbidden, text)
		}
	}
}

func TestLeaveRequestProcessWireModelCarriesEpochAdvancingRemoveCommit(t *testing.T) {
	process := GroupLeaveRequestProcessObject{
		LeaveRequestID:    "leave-req-1",
		GroupDID:          "did:wba:example.com:groups:demo:e1",
		RequesterDID:      "did:wba:example.com:users:bob:e1",
		ProcessorDID:      "did:wba:example.com:users:alice:e1",
		CryptoGroupIDB64U: "Y3J5cHRv",
		Epoch:             "8",
		CommitB64U:        "Y29tbWl0",
		GroupStateRef: GroupStateRef{
			GroupDID:          "did:wba:example.com:groups:demo:e1",
			GroupStateVersion: "7",
		},
	}
	encoded, err := json.Marshal(process)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, token := range []string{"leave_request_id", "processor_did", "crypto_group_id_b64u", "epoch", "commit_b64u"} {
		if !strings.Contains(text, token) {
			t.Fatalf("leave request process JSON missing %s: %s", token, text)
		}
	}
	if MethodLeaveRequest != "group.e2ee.leave_request" {
		t.Fatalf("unexpected leave request method: %s", MethodLeaveRequest)
	}
	if MethodLeaveRequestProcess != "group.e2ee.leave_request.process" {
		t.Fatalf("unexpected leave request process method: %s", MethodLeaveRequestProcess)
	}
	if TransportSecurityProfile != "transport-protected" {
		t.Fatalf("unexpected leave request security profile: %s", TransportSecurityProfile)
	}
}
