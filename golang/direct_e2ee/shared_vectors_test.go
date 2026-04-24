package directe2ee

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	anp "github.com/agent-network-protocol/anp/golang"
)

type sharedP5Vectors struct {
	Version string              `json:"version"`
	X3DH    []sharedX3DHVector  `json:"x3dh"`
	KDFCK   []sharedKDFCKVector `json:"kdf_ck"`
	KDFRK   []sharedKDFRKVector `json:"kdf_rk"`
	AAD     []sharedAADVector   `json:"aad"`
}

type sharedX3DHVector struct {
	Name                              string `json:"name"`
	SenderStaticPrivateB64U           string `json:"sender_static_private_b64u"`
	SenderEphemeralPrivateB64U        string `json:"sender_ephemeral_private_b64u"`
	RecipientStaticPrivateB64U        string `json:"recipient_static_private_b64u"`
	RecipientSignedPrekeyPrivateB64U  string `json:"recipient_signed_prekey_private_b64u"`
	RecipientOneTimePrekeyPrivateB64U string `json:"recipient_one_time_prekey_private_b64u"`
	RecipientStaticPublicB64U         string `json:"recipient_static_public_b64u"`
	RecipientSignedPrekeyPublicB64U   string `json:"recipient_signed_prekey_public_b64u"`
	RecipientOneTimePrekeyPublicB64U  string `json:"recipient_one_time_prekey_public_b64u"`
	InitialSecretB64U                 string `json:"initial_secret_b64u"`
	RootKeyB64U                       string `json:"root_key_b64u"`
	ChainKeyB64U                      string `json:"chain_key_b64u"`
	SessionID                         string `json:"session_id"`
}

type sharedKDFCKVector struct {
	Name             string `json:"name"`
	ChainKeyB64U     string `json:"chain_key_b64u"`
	NextChainKeyB64U string `json:"next_chain_key_b64u"`
	MessageKeyB64U   string `json:"message_key_b64u"`
	NonceB64U        string `json:"nonce_b64u"`
}

type sharedKDFRKVector struct {
	Name            string `json:"name"`
	RootKeyB64U     string `json:"root_key_b64u"`
	DHOutB64U       string `json:"dh_out_b64u"`
	NextRootKeyB64U string `json:"next_root_key_b64u"`
	ChainKeyB64U    string `json:"chain_key_b64u"`
}

type sharedAADVector struct {
	Name        string                 `json:"name"`
	Metadata    DirectEnvelopeMetadata `json:"metadata"`
	InitBody    *DirectInitBody        `json:"init_body,omitempty"`
	CipherBody  *DirectCipherBody      `json:"cipher_body,omitempty"`
	ExpectedAAD string                 `json:"expected_aad"`
}

func TestSharedP5Vectors(t *testing.T) {
	vectors := loadSharedP5Vectors(t)
	if vectors.Version != "anp-direct-e2ee-p5-shared-vectors-v1" {
		t.Fatalf("unexpected vector version %q", vectors.Version)
	}
	for _, vector := range vectors.X3DH {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			senderStatic := privateKeyFromVector(t, vector.SenderStaticPrivateB64U)
			senderEphemeral := privateKeyFromVector(t, vector.SenderEphemeralPrivateB64U)
			recipientStaticPublic := bytes32FromB64U(t, vector.RecipientStaticPublicB64U)
			recipientSignedPrekeyPublic := bytes32FromB64U(t, vector.RecipientSignedPrekeyPublicB64U)
			var recipientOPKPublic *[32]byte
			if vector.RecipientOneTimePrekeyPublicB64U != "" {
				opk := bytes32FromB64U(t, vector.RecipientOneTimePrekeyPublicB64U)
				recipientOPKPublic = &opk
			}
			initiator, err := DeriveInitialMaterialForInitiatorWithOPK(senderStatic, senderEphemeral, recipientStaticPublic, recipientSignedPrekeyPublic, recipientOPKPublic)
			if err != nil {
				t.Fatalf("DeriveInitialMaterialForInitiatorWithOPK failed: %v", err)
			}
			if got, want := anp.EncodeBase64URL(initiator.InitialSecret[:]), vector.InitialSecretB64U; got != want {
				t.Fatalf("initial_secret = %s, want %s", got, want)
			}
			if got, want := anp.EncodeBase64URL(initiator.RootKey[:]), vector.RootKeyB64U; got != want {
				t.Fatalf("root_key = %s, want %s", got, want)
			}
			if got, want := anp.EncodeBase64URL(initiator.ChainKey[:]), vector.ChainKeyB64U; got != want {
				t.Fatalf("chain_key = %s, want %s", got, want)
			}
			if initiator.SessionID != vector.SessionID {
				t.Fatalf("session_id = %s, want %s", initiator.SessionID, vector.SessionID)
			}

			recipientStatic := privateKeyFromVector(t, vector.RecipientStaticPrivateB64U)
			recipientSignedPrekey := privateKeyFromVector(t, vector.RecipientSignedPrekeyPrivateB64U)
			var recipientOPK *ecdh.PrivateKey
			if vector.RecipientOneTimePrekeyPrivateB64U != "" {
				recipientOPK = privateKeyFromVector(t, vector.RecipientOneTimePrekeyPrivateB64U)
			}
			responder, err := DeriveInitialMaterialForResponderWithOPK(recipientStatic, recipientSignedPrekey, recipientOPK, bytes32FromBytes(t, senderStatic.PublicKey().Bytes()), bytes32FromBytes(t, senderEphemeral.PublicKey().Bytes()))
			if err != nil {
				t.Fatalf("DeriveInitialMaterialForResponderWithOPK failed: %v", err)
			}
			if responder != initiator {
				t.Fatalf("responder material != initiator material: responder=%+v initiator=%+v", responder, initiator)
			}
		})
	}
	for _, vector := range vectors.KDFCK {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			step := DeriveChainStep(bytes32FromB64U(t, vector.ChainKeyB64U))
			assertB64U(t, "next_chain_key", step.NextChainKey[:], vector.NextChainKeyB64U)
			assertB64U(t, "message_key", step.MessageKey[:], vector.MessageKeyB64U)
			assertB64U(t, "nonce", step.Nonce[:], vector.NonceB64U)
		})
	}
	for _, vector := range vectors.KDFRK {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			rootStep, err := DeriveRootStep(bytes32FromB64U(t, vector.RootKeyB64U), decodeB64U(t, vector.DHOutB64U))
			if err != nil {
				t.Fatalf("DeriveRootStep failed: %v", err)
			}
			assertB64U(t, "root_key", rootStep.RootKey[:], vector.NextRootKeyB64U)
			assertB64U(t, "chain_key", rootStep.ChainKey[:], vector.ChainKeyB64U)
		})
	}
	for _, vector := range vectors.AAD {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			var got []byte
			var err error
			if vector.InitBody != nil {
				got, err = BuildInitAAD(vector.Metadata, *vector.InitBody)
			} else if vector.CipherBody != nil {
				got, err = BuildMessageAAD(vector.Metadata, *vector.CipherBody)
			} else {
				t.Fatalf("AAD vector missing body")
			}
			if err != nil {
				t.Fatalf("build AAD failed: %v", err)
			}
			if string(got) != vector.ExpectedAAD {
				t.Fatalf("AAD = %s, want %s", got, vector.ExpectedAAD)
			}
		})
	}
}

func TestDirectInitBodyOmitsAbsentOPKAndLegacyStaticField(t *testing.T) {
	vectors := loadSharedP5Vectors(t)
	for _, vector := range vectors.AAD {
		if vector.Name != "p5_aad_init_no_opk" || vector.InitBody == nil {
			continue
		}
		encoded, err := json.Marshal(vector.InitBody)
		if err != nil {
			t.Fatalf("Marshal DirectInitBody failed: %v", err)
		}
		if bytes.Contains(encoded, []byte("recipient_static_key_agreement_id")) {
			t.Fatalf("DirectInitBody serialized legacy recipient_static_key_agreement_id: %s", encoded)
		}
		if bytes.Contains(encoded, []byte("recipient_one_time_prekey_id")) || bytes.Contains(encoded, []byte(":null")) {
			t.Fatalf("DirectInitBody must omit absent OPK rather than serializing null: %s", encoded)
		}
		return
	}
	t.Fatalf("p5_aad_init_no_opk vector not found")
}

func loadSharedP5Vectors(t *testing.T) sharedP5Vectors {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "direct_e2ee", "p5_shared_vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) failed: %v", path, err)
	}
	var vectors sharedP5Vectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("Unmarshal shared P5 vectors failed: %v", err)
	}
	return vectors
}

func privateKeyFromVector(t *testing.T, value string) *ecdh.PrivateKey {
	t.Helper()
	privateKey, err := ecdh.X25519().NewPrivateKey(decodeB64U(t, value))
	if err != nil {
		t.Fatalf("NewPrivateKey failed: %v", err)
	}
	return privateKey
}

func bytes32FromB64U(t *testing.T, value string) [32]byte {
	t.Helper()
	return bytes32FromBytes(t, decodeB64U(t, value))
}

func bytes32FromBytes(t *testing.T, value []byte) [32]byte {
	t.Helper()
	if len(value) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(value))
	}
	var out [32]byte
	copy(out[:], value)
	return out
}

func decodeB64U(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := anp.DecodeBase64URL(value)
	if err != nil {
		t.Fatalf("DecodeBase64URL(%s) failed: %v", value, err)
	}
	return decoded
}

func assertB64U(t *testing.T, field string, got []byte, want string) {
	t.Helper()
	if encoded := anp.EncodeBase64URL(got); encoded != want {
		t.Fatalf("%s = %s, want %s", field, encoded, want)
	}
}

func TestSharedP5VectorAADDoesNotContainApplicationContentType(t *testing.T) {
	vectors := loadSharedP5Vectors(t)
	for _, vector := range vectors.AAD {
		if vector.Name == "p5_aad_msg" && strings.Contains(vector.ExpectedAAD, "application_content_type") {
			t.Fatalf("message AAD vector contains encrypted application_content_type: %s", vector.ExpectedAAD)
		}
	}
}
