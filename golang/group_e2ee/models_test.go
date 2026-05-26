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
	if MethodLeaveRequestProcess != "group.e2ee.process_leave_request" {
		t.Fatalf("unexpected leave request process method: %s", MethodLeaveRequestProcess)
	}
	if TransportSecurityProfile != "transport-protected" {
		t.Fatalf("unexpected leave request security profile: %s", TransportSecurityProfile)
	}
}

func TestRecoverMemberWireModelRequiresRecoveryBoundKeyPackage(t *testing.T) {
	recovery := RecoverMemberRequestObject{
		OperationID: "op-recover-bob",
		GroupDID:    "did:wba:example.com:groups:demo:e1",
		ActorDID:    "did:wba:example.com:users:alice:e1",
		Target: RecoverMemberTarget{
			AgentDID: "did:wba:example.com:users:bob:e1",
			DeviceID: "phone",
		},
		GroupStateRef: GroupStateRef{
			GroupDID:          "did:wba:example.com:groups:demo:e1",
			GroupStateVersion: "7",
		},
		GroupKeyPackage: &GroupKeyPackage{
			KeyPackageID:      "kp-recovery-bob",
			OwnerDID:          "did:wba:example.com:users:bob:e1",
			DeviceID:          "phone",
			Purpose:           "recovery",
			GroupDID:          "did:wba:example.com:groups:demo:e1",
			Suite:             MTISuite,
			MLSKeyPackageB64U: "bWxzLWtleS1wYWNrYWdl",
			DIDWBABinding: map[string]any{
				"agent_did": "did:wba:example.com:users:bob:e1",
				"device_id": "phone",
			},
		},
		CommitB64U:      "Y29tbWl0",
		WelcomeB64U:     "d2VsY29tZQ",
		RatchetTreeB64U: "cmF0Y2hldA",
		Epoch:           "8",
	}
	encoded, err := json.Marshal(recovery)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, token := range []string{"operation_id", "target", "purpose", "recovery", "group_key_package", "welcome_b64u"} {
		if !strings.Contains(text, token) {
			t.Fatalf("recover member JSON missing %s: %s", token, text)
		}
	}
	if MethodRecoverMember != "group.e2ee.recover_member" {
		t.Fatalf("unexpected recover member method: %s", MethodRecoverMember)
	}
	for _, forbidden := range []string{"plaintext", "private"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("recover member JSON leaked private field %s: %s", forbidden, text)
		}
	}
}

func TestRecoverMemberFinalizeAbortWireModelsCarryPendingCommitID(t *testing.T) {
	finalize := RecoverMemberFinalizeRequestObject{
		OperationID:     "op-finalize",
		PendingCommitID: "pc-recover",
	}
	abort := RecoverMemberAbortRequestObject{
		OperationID:     "op-abort",
		PendingCommitID: "pc-recover",
	}
	for name, value := range map[string]any{"finalize": finalize, "abort": abort} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("%s marshal: %v", name, err)
		}
		text := string(encoded)
		for _, token := range []string{"operation_id", "pending_commit_id", "pc-recover"} {
			if !strings.Contains(text, token) {
				t.Fatalf("%s JSON missing %s: %s", name, token, text)
			}
		}
	}
}

func TestUpdateMemberWireModelRequiresUpdateBoundKeyPackage(t *testing.T) {
	update := UpdateMemberRequestObject{
		OperationID: "op-update-bob",
		GroupDID:    "did:wba:example.com:groups:demo:e1",
		ActorDID:    "did:wba:example.com:users:alice:e1",
		Target: UpdateMemberTarget{
			AgentDID: "did:wba:example.com:users:bob:e1",
			DeviceID: "phone",
		},
		GroupStateRef: GroupStateRef{
			GroupDID:          "did:wba:example.com:groups:demo:e1",
			GroupStateVersion: "7",
		},
		UpdateKeyPackageID: "kp-update-bob",
		GroupKeyPackage: GroupKeyPackage{
			KeyPackageID:      "kp-update-bob",
			OwnerDID:          "did:wba:example.com:users:bob:e1",
			DeviceID:          "phone",
			Purpose:           "update",
			GroupDID:          "did:wba:example.com:groups:demo:e1",
			Suite:             MTISuite,
			MLSKeyPackageB64U: "bWxzLWtleS1wYWNrYWdl",
			DIDWBABinding: map[string]any{
				"agent_did": "did:wba:example.com:users:bob:e1",
				"device_id": "phone",
			},
		},
		CommitB64U:        "Y29tbWl0",
		WelcomeB64U:       "d2VsY29tZQ",
		RatchetTreeB64U:   "cmF0Y2hldA",
		CryptoGroupIDB64U: "Y3J5cHRv",
		Epoch:             "8",
	}
	encoded, err := json.Marshal(update)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, token := range []string{"operation_id", "target", "purpose", "update", "update_key_package_id", "welcome_b64u"} {
		if !strings.Contains(text, token) {
			t.Fatalf("update member JSON missing %s: %s", token, text)
		}
	}
	if MethodUpdate != "group.e2ee.update" {
		t.Fatalf("unexpected update method: %s", MethodUpdate)
	}
	for _, forbidden := range []string{"plaintext", "private"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("update member JSON leaked private field %s: %s", forbidden, text)
		}
	}
}

func TestUpdateMemberFinalizeAbortWireModelsCarryPendingCommitID(t *testing.T) {
	finalize := UpdateMemberFinalizeRequestObject{
		OperationID:     "op-finalize",
		PendingCommitID: "pc-update",
	}
	abort := UpdateMemberAbortRequestObject{
		OperationID:     "op-abort",
		PendingCommitID: "pc-update",
	}
	for name, value := range map[string]any{"finalize": finalize, "abort": abort} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("%s marshal: %v", name, err)
		}
		text := string(encoded)
		for _, token := range []string{"operation_id", "pending_commit_id", "pc-update"} {
			if !strings.Contains(text, token) {
				t.Fatalf("%s JSON missing %s: %s", name, token, text)
			}
		}
	}
}
