package directe2ee

import (
	"crypto/ecdh"
	"fmt"
	"time"

	anp "github.com/agent-network-protocol/anp/golang"
)

// RPCClient invokes the remote message-service RPC boundary.
type RPCClient func(method string, params map[string]any) (map[string]any, error)

// PrekeyManager manages signed prekeys and bundle publication.
type PrekeyManager struct {
	localDID                  string
	staticKeyAgreementID      string
	signingPrivateKey         anp.PrivateKeyMaterial
	signingVerificationMethod string
	signedPrekeyStore         SignedPrekeyStore
	rpcClient                 RPCClient
}

// NewPrekeyManager creates a direct E2EE prekey manager.
func NewPrekeyManager(localDID string, staticKeyAgreementID string, signingPrivateKey anp.PrivateKeyMaterial, signingVerificationMethod string, signedPrekeyStore SignedPrekeyStore, rpcClient RPCClient) *PrekeyManager {
	return &PrekeyManager{localDID: localDID, staticKeyAgreementID: staticKeyAgreementID, signingPrivateKey: signingPrivateKey, signingVerificationMethod: signingVerificationMethod, signedPrekeyStore: signedPrekeyStore, rpcClient: rpcClient}
}

// GenerateSignedPrekey generates, stores, and returns a new signed prekey.
func (m *PrekeyManager) GenerateSignedPrekey(keyID string, expiresAt string) (*ecdh.PrivateKey, SignedPrekey, error) {
	if expiresAt == "" {
		expiresAt = defaultSignedPrekeyExpiry()
	}
	privateMaterial, publicMaterial, _, err := anp.GenerateKeyPairPEM(anp.KeyTypeX25519)
	if err != nil {
		return nil, SignedPrekey{}, err
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateMaterial.Bytes)
	if err != nil {
		return nil, SignedPrekey{}, err
	}
	metadata := SignedPrekey{KeyID: keyID, PublicKeyB64U: anp.EncodeBase64URL(publicMaterial.Bytes), ExpiresAt: expiresAt}
	if err := m.signedPrekeyStore.SaveSignedPrekey(keyID, privateMaterial, metadata); err != nil {
		return nil, SignedPrekey{}, err
	}
	return privateKey, metadata, nil
}

// BuildPrekeyBundle signs a prekey bundle.
func (m *PrekeyManager) BuildPrekeyBundle(signedPrekey SignedPrekey, bundleID string, created string) (PrekeyBundle, error) {
	if bundleID == "" {
		bundleID = fmt.Sprintf("spk-%d-%s", time.Now().Unix(), signedPrekey.KeyID)
	}
	return BuildPrekeyBundle(bundleID, m.localDID, m.staticKeyAgreementID, signedPrekey, m.signingPrivateKey, m.signingVerificationMethod, created)
}

// PublishPrekeyBundle publishes a prekey bundle over the RPC boundary.
func (m *PrekeyManager) PublishPrekeyBundle(bundle PrekeyBundle) (map[string]any, error) {
	if m.rpcClient == nil {
		return nil, &Error{Code: "rpc_unavailable", Message: "RPC client is not configured"}
	}
	return m.rpcClient("direct.e2ee.publish_prekey_bundle", map[string]any{"meta": map[string]any{"anp_version": "1.0", "profile": "anp.direct.e2ee.v1", "security_profile": "transport-protected", "sender_did": m.localDID, "operation_id": "op-publish-" + bundle.BundleID}, "body": map[string]any{"prekey_bundle": bundleToMap(bundle)}})
}

// EnsureFreshPrekeyBundle returns the latest prekey bundle or creates one.
func (m *PrekeyManager) EnsureFreshPrekeyBundle() (PrekeyBundle, error) {
	_, metadata, ok, err := m.signedPrekeyStore.LoadLatestSignedPrekey()
	if err != nil {
		return PrekeyBundle{}, err
	}
	if !ok {
		_, signedPrekey, err := m.GenerateSignedPrekey("spk-initial", "2030-01-01T00:00:00Z")
		if err != nil {
			return PrekeyBundle{}, err
		}
		bundle, err := m.BuildPrekeyBundle(signedPrekey, "", "")
		if err != nil {
			return PrekeyBundle{}, err
		}
		if m.rpcClient != nil {
			_, _ = m.PublishPrekeyBundle(bundle)
		}
		return bundle, nil
	}
	bundle, err := m.BuildPrekeyBundle(metadata, "", "")
	if err != nil {
		return PrekeyBundle{}, err
	}
	if m.rpcClient != nil {
		_, _ = m.PublishPrekeyBundle(bundle)
	}
	return bundle, nil
}

// VerifyRemotePrekeyBundle verifies a prekey bundle against a DID document.
func (m *PrekeyManager) VerifyRemotePrekeyBundle(bundle PrekeyBundle, didDocument map[string]any) error {
	return VerifyPrekeyBundle(bundle, didDocument)
}
