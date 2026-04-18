package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/authentication"
)

func TestRustLegacyAuthFixtureVerifiesInGo(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo is unavailable; skipping Rust interop test")
	}
	fixture := runJSONCommand(t, filepath.Join(repoRoot(t), "rust"), "cargo", "run", "--quiet", "--example", "interop_cli", "--", "auth-fixture", "--profile", "k1", "--hostname", "example.com", "--scheme", "legacy", "--service-domain", "api.example.com")
	didDocument := fixture["did_document"].(map[string]any)
	headers := toStringMap(fixture["headers"].(map[string]any))
	assertStandardPEMFixtureKeysLoadInGo(t, fixture["keys"])
	if err := authentication.VerifyAuthHeaderSignature(headers["Authorization"], didDocument, "api.example.com"); err != nil {
		t.Fatalf("VerifyAuthHeaderSignature failed: %v", err)
	}
}

func TestRustHTTPSignatureFixtureVerifiesInGo(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo is unavailable; skipping Rust interop test")
	}
	fixture := runJSONCommand(t, filepath.Join(repoRoot(t), "rust"), "cargo", "run", "--quiet", "--example", "interop_cli", "--", "auth-fixture", "--profile", "e1", "--hostname", "example.com", "--scheme", "http", "--url", "https://api.example.com/orders", "--method", "POST", "--body", `{"item":"book"}`)
	didDocument := fixture["did_document"].(map[string]any)
	headers := toStringMap(fixture["headers"].(map[string]any))
	assertStandardPEMFixtureKeysLoadInGo(t, fixture["keys"])
	if _, err := authentication.VerifyHTTPMessageSignature(didDocument, "POST", "https://api.example.com/orders", headers, []byte(`{"item":"book"}`)); err != nil {
		t.Fatalf("VerifyHTTPMessageSignature failed: %v", err)
	}
}

func TestPythonHTTPSignatureFixtureVerifiesInGo(t *testing.T) {
	if _, err := exec.LookPath("uv"); err != nil {
		t.Skip("uv is unavailable; skipping Python interop test")
	}
	script := `import json
import tempfile
from pathlib import Path
from anp.authentication import DIDWbaAuthHeader, create_did_wba_document
body = '{"item":"book"}'
did_document, keys = create_did_wba_document('example.com', path_segments=['user', 'python-http'])
k1_document, k1_keys = create_did_wba_document('example.com', path_segments=['user', 'python-k1'], did_profile='k1', enable_e2ee=False)
with tempfile.TemporaryDirectory() as temp_dir:
    temp_path = Path(temp_dir)
    did_path = temp_path / 'did.json'
    key_path = temp_path / 'key-1.pem'
    did_path.write_text(json.dumps(did_document), encoding='utf-8')
    key_path.write_bytes(keys['key-1'][0])
    keys_json = {f'e1-{name}': {'private_key_pem': value[0].decode('ascii'), 'public_key_pem': value[1].decode('ascii')} for name, value in keys.items()}
    keys_json.update({f'k1-{name}': {'private_key_pem': value[0].decode('ascii'), 'public_key_pem': value[1].decode('ascii')} for name, value in k1_keys.items()})
    auth = DIDWbaAuthHeader(str(did_path), str(key_path))
    headers = auth.get_auth_header('https://api.example.com/orders', force_new=True, method='POST', headers={'Content-Type': 'application/json'}, body=body.encode('utf-8'))
    print(json.dumps({'did_document': did_document, 'keys': keys_json, 'headers': headers, 'request_url': 'https://api.example.com/orders', 'body': body}))`
	fixture := runJSONCommand(t, repoRoot(t), "uv", "run", "--python", "3.13", "--with-editable", repoRoot(t), "python", "-c", script)
	didDocument := fixture["did_document"].(map[string]any)
	headers := toStringMap(fixture["headers"].(map[string]any))
	body := fixture["body"].(string)
	assertStandardPEMFixtureKeysLoadInGo(t, fixture["keys"])
	if _, err := authentication.VerifyHTTPMessageSignature(didDocument, "POST", "https://api.example.com/orders", headers, []byte(body)); err != nil {
		t.Fatalf("VerifyHTTPMessageSignature failed: %v", err)
	}
}

func TestGoLegacyAuthFixtureVerifiesInPython(t *testing.T) {
	if _, err := exec.LookPath("uv"); err != nil {
		t.Skip("uv is unavailable; skipping Python interop test")
	}
	bundle, err := authentication.CreateDidWBADocument("example.com", authentication.DidDocumentOptions{PathSegments: []string{"user", "go-legacy"}, DidProfile: authentication.DidProfileK1})
	if err != nil {
		t.Fatalf("CreateDidWBADocument failed: %v", err)
	}
	privateKey, err := anp.PrivateKeyFromPEM(bundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatalf("PrivateKeyFromPEM failed: %v", err)
	}
	authorization, err := authentication.GenerateAuthHeader(bundle.DidDocument, "api.example.com", privateKey, "1.1")
	if err != nil {
		t.Fatalf("GenerateAuthHeader failed: %v", err)
	}
	tempDir := t.TempDir()
	fixturePath := filepath.Join(tempDir, "fixture.json")
	script := `import json, sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from anp.authentication import verify_auth_header_signature
fixture = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
for value in fixture['keys'].values():
    serialization.load_pem_private_key(value['private_key_pem'].encode('ascii'), password=None)
    serialization.load_pem_public_key(value['public_key_pem'].encode('ascii'))
verify_auth_header_signature(fixture['authorization'], fixture['did_document'], fixture['service_domain'])
print(json.dumps({'verified': True}))`
	data, _ := json.Marshal(map[string]any{"did_document": bundle.DidDocument, "keys": bundle.Keys, "authorization": authorization, "service_domain": "api.example.com"})
	if err := os.WriteFile(fixturePath, data, 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	fixture := runJSONCommand(t, repoRoot(t), "uv", "run", "--python", "3.13", "--with-editable", repoRoot(t), "python", "-c", script, fixturePath)
	if verified, _ := fixture["verified"].(bool); !verified {
		t.Fatalf("python verifier did not confirm Go legacy auth")
	}
}

func TestGoStandardPEMKeysLoadInRust(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo is unavailable; skipping Rust interop test")
	}
	e1, err := authentication.CreateDidWBADocument("example.com", authentication.DidDocumentOptions{PathSegments: []string{"user", "go-to-rust"}})
	if err != nil {
		t.Fatalf("CreateDidWBADocument(e1) failed: %v", err)
	}
	enableE2EE := false
	k1, err := authentication.CreateDidWBADocument("example.com", authentication.DidDocumentOptions{PathSegments: []string{"user", "go-to-rust-k1"}, DidProfile: authentication.DidProfileK1, EnableE2EE: &enableE2EE})
	if err != nil {
		t.Fatalf("CreateDidWBADocument(k1) failed: %v", err)
	}
	keys := map[string]anp.GeneratedKeyPairPEM{}
	for fragment, keyPair := range e1.Keys {
		keys["e1-"+fragment] = keyPair
	}
	keys["k1-key-1"] = k1.Keys[authentication.VMKeyAuth]

	tempDir := t.TempDir()
	fixturePath := filepath.Join(tempDir, "keys.json")
	data, _ := json.Marshal(map[string]any{"keys": keys})
	if err := os.WriteFile(fixturePath, data, 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	fixture := runJSONCommand(t, filepath.Join(repoRoot(t), "rust"), "cargo", "run", "--quiet", "--example", "interop_cli", "--", "verify-key-fixture", "--fixture", fixturePath)
	if verified, _ := fixture["verified"].(bool); !verified {
		t.Fatalf("Rust key fixture verifier did not confirm Go standard PEM keys")
	}
}

func runJSONCommand(t *testing.T, workdir string, name string, args ...string) map[string]any {
	t.Helper()
	command := exec.Command(name, args...)
	command.Dir = workdir
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %s %v\n%s", name, args, string(output))
	}
	raw := strings.TrimSpace(string(output))
	if newline := strings.LastIndex(raw, "\n"); newline >= 0 {
		raw = strings.TrimSpace(raw[newline+1:])
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("json unmarshal failed: %v\n%s", err, string(output))
	}
	return payload
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func toStringMap(value map[string]any) map[string]string {
	result := map[string]string{}
	for key, entry := range value {
		if text, ok := entry.(string); ok {
			result[key] = text
		}
	}
	return result
}

func assertStandardPEMFixtureKeysLoadInGo(t *testing.T, value any) {
	t.Helper()
	keys, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("fixture keys must be an object")
	}
	for fragment, rawPair := range keys {
		pair, ok := rawPair.(map[string]any)
		if !ok {
			t.Fatalf("%s key pair must be an object", fragment)
		}
		privatePEM, _ := pair["private_key_pem"].(string)
		publicPEM, _ := pair["public_key_pem"].(string)
		if !strings.HasPrefix(privatePEM, "-----BEGIN PRIVATE KEY-----") {
			t.Fatalf("%s private key must be PKCS#8 PEM", fragment)
		}
		if !strings.HasPrefix(publicPEM, "-----BEGIN PUBLIC KEY-----") {
			t.Fatalf("%s public key must be SPKI PEM", fragment)
		}
		if strings.Contains(privatePEM, "ANP ") || strings.Contains(publicPEM, "ANP ") {
			t.Fatalf("%s key pair must not use legacy ANP PEM labels", fragment)
		}
		privateKey, err := anp.PrivateKeyFromPEM(privatePEM)
		if err != nil {
			t.Fatalf("%s PrivateKeyFromPEM failed: %v", fragment, err)
		}
		publicKey, err := anp.PublicKeyFromPEM(publicPEM)
		if err != nil {
			t.Fatalf("%s PublicKeyFromPEM failed: %v", fragment, err)
		}
		if publicKey.Type != anp.KeyTypeX25519 {
			signature, err := privateKey.SignMessage([]byte("cross-language standard pem"))
			if err != nil {
				t.Fatalf("%s SignMessage failed: %v", fragment, err)
			}
			if err := publicKey.VerifyMessage([]byte("cross-language standard pem"), signature); err != nil {
				t.Fatalf("%s VerifyMessage failed: %v", fragment, err)
			}
		}
	}
}
