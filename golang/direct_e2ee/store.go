package directe2ee

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	anp "github.com/agent-network-protocol/anp/golang"
)

// IdentityKeyStore loads static identity keys.
type IdentityKeyStore interface {
	LoadStaticKey(keyID string) (anp.PrivateKeyMaterial, error)
}

// SignedPrekeyStore loads and stores signed prekeys.
type SignedPrekeyStore interface {
	SaveSignedPrekey(keyID string, privateKey anp.PrivateKeyMaterial, metadata SignedPrekey) error
	LoadSignedPrekey(keyID string) (anp.PrivateKeyMaterial, SignedPrekey, error)
	LoadLatestSignedPrekey() (anp.PrivateKeyMaterial, SignedPrekey, bool, error)
}

// SessionStore loads and stores direct E2EE sessions.
type SessionStore interface {
	SaveSession(session DirectSessionState) error
	LoadSession(sessionID string) (DirectSessionState, error)
	DeleteSession(sessionID string) error
	FindByPeerDID(peerDID string) (DirectSessionState, bool, error)
}

// PendingOutboundStore loads and stores pending outbound messages.
type PendingOutboundStore interface {
	SavePending(record PendingOutboundRecord) error
	LoadPending(operationID string) (PendingOutboundRecord, error)
	DeletePending(operationID string) error
}

// FileSessionStore persists session state as JSON files.
type FileSessionStore struct{ root string }

// NewFileSessionStore creates a file-backed session store.
func NewFileSessionStore(root string) (*FileSessionStore, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &FileSessionStore{root: root}, nil
}

func (s *FileSessionStore) SaveSession(session DirectSessionState) error {
	return writeJSON(filepath.Join(s.root, session.SessionID+".json"), session, 0o644)
}
func (s *FileSessionStore) LoadSession(sessionID string) (DirectSessionState, error) {
	var session DirectSessionState
	if err := readJSON(filepath.Join(s.root, sessionID+".json"), &session); err != nil {
		if os.IsNotExist(err) {
			return DirectSessionState{}, sessionNotFound(sessionID)
		}
		return DirectSessionState{}, err
	}
	return session, nil
}
func (s *FileSessionStore) DeleteSession(sessionID string) error {
	if err := os.Remove(filepath.Join(s.root, sessionID+".json")); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
func (s *FileSessionStore) FindByPeerDID(peerDID string) (DirectSessionState, bool, error) {
	entries, err := filepath.Glob(filepath.Join(s.root, "*.json"))
	if err != nil {
		return DirectSessionState{}, false, err
	}
	for _, path := range entries {
		var session DirectSessionState
		if err := readJSON(path, &session); err != nil {
			return DirectSessionState{}, false, err
		}
		if session.PeerDID == peerDID {
			return session, true, nil
		}
	}
	return DirectSessionState{}, false, nil
}

// FileSignedPrekeyStore persists signed prekeys and metadata to disk.
type FileSignedPrekeyStore struct{ root string }

// NewFileSignedPrekeyStore creates a file-backed signed prekey store.
func NewFileSignedPrekeyStore(root string) (*FileSignedPrekeyStore, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &FileSignedPrekeyStore{root: root}, nil
}
func (s *FileSignedPrekeyStore) SaveSignedPrekey(keyID string, privateKey anp.PrivateKeyMaterial, metadata SignedPrekey) error {
	if err := os.WriteFile(filepath.Join(s.root, keyID+".pem"), []byte(privateKey.ToPEM()), 0o600); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(s.root, keyID+".json"), metadata, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.root, "latest.txt"), []byte(keyID), 0o644)
}
func (s *FileSignedPrekeyStore) LoadSignedPrekey(keyID string) (anp.PrivateKeyMaterial, SignedPrekey, error) {
	data, err := os.ReadFile(filepath.Join(s.root, keyID+".pem"))
	if err != nil {
		if os.IsNotExist(err) {
			return anp.PrivateKeyMaterial{}, SignedPrekey{}, invalidField("signed prekey not found: " + keyID)
		}
		return anp.PrivateKeyMaterial{}, SignedPrekey{}, err
	}
	privateKey, err := anp.PrivateKeyFromPEM(string(data))
	if err != nil {
		return anp.PrivateKeyMaterial{}, SignedPrekey{}, err
	}
	var metadata SignedPrekey
	if err := readJSON(filepath.Join(s.root, keyID+".json"), &metadata); err != nil {
		return anp.PrivateKeyMaterial{}, SignedPrekey{}, err
	}
	return privateKey, metadata, nil
}
func (s *FileSignedPrekeyStore) LoadLatestSignedPrekey() (anp.PrivateKeyMaterial, SignedPrekey, bool, error) {
	data, err := os.ReadFile(filepath.Join(s.root, "latest.txt"))
	if err != nil {
		if os.IsNotExist(err) {
			return anp.PrivateKeyMaterial{}, SignedPrekey{}, false, nil
		}
		return anp.PrivateKeyMaterial{}, SignedPrekey{}, false, err
	}
	privateKey, metadata, err := s.LoadSignedPrekey(strings.TrimSpace(string(data)))
	if err != nil {
		return anp.PrivateKeyMaterial{}, SignedPrekey{}, false, err
	}
	return privateKey, metadata, true, nil
}

// FilePendingOutboundStore persists pending outbound messages as JSON files.
type FilePendingOutboundStore struct{ root string }

// NewFilePendingOutboundStore creates a file-backed pending outbound store.
func NewFilePendingOutboundStore(root string) (*FilePendingOutboundStore, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &FilePendingOutboundStore{root: root}, nil
}
func (s *FilePendingOutboundStore) SavePending(record PendingOutboundRecord) error {
	return writeJSON(filepath.Join(s.root, record.OperationID+".json"), record, 0o644)
}
func (s *FilePendingOutboundStore) LoadPending(operationID string) (PendingOutboundRecord, error) {
	var record PendingOutboundRecord
	if err := readJSON(filepath.Join(s.root, operationID+".json"), &record); err != nil {
		if os.IsNotExist(err) {
			return PendingOutboundRecord{}, pendingNotFound(operationID)
		}
		return PendingOutboundRecord{}, err
	}
	return record, nil
}
func (s *FilePendingOutboundStore) DeletePending(operationID string) error {
	if err := os.Remove(filepath.Join(s.root, operationID+".json")); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func writeJSON(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, mode)
}
func readJSON(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}
