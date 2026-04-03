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
with tempfile.TemporaryDirectory() as temp_dir:
    temp_path = Path(temp_dir)
    did_path = temp_path / 'did.json'
    key_path = temp_path / 'key-1.pem'
    did_path.write_text(json.dumps(did_document), encoding='utf-8')
    key_path.write_bytes(keys['key-1'][0])
    auth = DIDWbaAuthHeader(str(did_path), str(key_path))
    headers = auth.get_auth_header('https://api.example.com/orders', force_new=True, method='POST', headers={'Content-Type': 'application/json'}, body=body.encode('utf-8'))
    print(json.dumps({'did_document': did_document, 'headers': headers, 'request_url': 'https://api.example.com/orders', 'body': body}))`
	fixture := runJSONCommand(t, repoRoot(t), "uv", "run", "--python", "3.13", "--with-editable", repoRoot(t), "python", "-c", script)
	didDocument := fixture["did_document"].(map[string]any)
	headers := toStringMap(fixture["headers"].(map[string]any))
	body := fixture["body"].(string)
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
	data, _ := json.Marshal(map[string]any{"did_document": bundle.DidDocument, "authorization": authorization, "service_domain": "api.example.com"})
	if err := os.WriteFile(fixturePath, data, 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	script := `import json, sys
from pathlib import Path
from anp.authentication import verify_auth_header_signature
fixture = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
verify_auth_header_signature(fixture['authorization'], fixture['did_document'], fixture['service_domain'])
print(json.dumps({'verified': True}))`
	fixture := runJSONCommand(t, repoRoot(t), "uv", "run", "--python", "3.13", "--with-editable", repoRoot(t), "python", "-c", script, fixturePath)
	if verified, _ := fixture["verified"].(bool); !verified {
		t.Fatalf("python verifier did not confirm Go legacy auth")
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
