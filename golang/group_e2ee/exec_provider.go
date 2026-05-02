package groupe2ee

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

type CommandRunner interface {
	Run(ctx context.Context, binary string, args []string, stdin []byte) (stdout []byte, stderr []byte, err error)
}

type OSCommandRunner struct{}

func (OSCommandRunner) Run(ctx context.Context, binary string, args []string, stdin []byte) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

type ExecProvider struct {
	BinaryPath string
	DataDir    string
	Timeout    time.Duration
	Runner     CommandRunner
}

func (p ExecProvider) Call(ctx context.Context, domain string, action string, req Request) (*Response, error) {
	if p.BinaryPath == "" {
		p.BinaryPath = "anp-mls"
	}
	if p.Timeout <= 0 {
		p.Timeout = 15 * time.Second
	}
	runner := p.Runner
	if runner == nil {
		runner = OSCommandRunner{}
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	args := []string{domain, action, "--json-in", "-"}
	if p.DataDir != "" {
		args = append(args, "--data-dir", p.DataDir)
	}
	stdout, stderr, err := runner.Run(ctx, p.BinaryPath, args, body)
	if err != nil && len(stdout) == 0 {
		return nil, fmt.Errorf("anp-mls exec failed: %w: %s", err, string(stderr))
	}
	var resp Response
	if decodeErr := json.Unmarshal(stdout, &resp); decodeErr != nil {
		return nil, fmt.Errorf("decode anp-mls response: %w: stderr=%s", decodeErr, string(stderr))
	}
	if !resp.OK {
		if resp.Error != nil {
			return &resp, fmt.Errorf("anp-mls error %s: %s", resp.Error.Code, resp.Error.Message)
		}
		return &resp, fmt.Errorf("anp-mls returned ok=false")
	}
	return &resp, nil
}
