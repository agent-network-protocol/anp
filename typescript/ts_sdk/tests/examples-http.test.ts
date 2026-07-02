import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { join, resolve } from 'node:path';

import { describe, expect, test } from 'vitest';

describe('DID-WBA HTTP examples', () => {
  test('TS and Python clients authenticate against the TS server example', async () => {
    const sdkDir = process.cwd();
    const repoRoot = resolve(sdkDir, '..', '..');
    const env = {
      ...process.env,
      ANP_TS_DEMO_PORT: '8091',
      ANP_TS_DEMO_HOST: '127.0.0.1',
    };
    const server = spawn(process.execPath, ['examples/did-wba-http-server.mjs'], {
      cwd: sdkDir,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const serverOutput: string[] = [];
    server.stdout.on('data', (chunk) => serverOutput.push(String(chunk)));
    server.stderr.on('data', (chunk) => serverOutput.push(String(chunk)));

    try {
      await waitForServer(serverOutput, 'DID-WBA TS server listening');

      const tsClient = await runCommand(
        process.execPath,
        ['examples/did-wba-http-client.mjs'],
        sdkDir,
        env
      );
      expect(tsClient.code).toBe(0);
      expect(tsClient.output).toContain(
        'TS client/server mutual DID-WBA authentication completed.'
      );
      expect(tsClient.output).toContain("authScheme: 'bearer'");
      expect(tsClient.output).toContain('Verified server DID response signature for:');

      const pythonEnv = {
        ...env,
        PYTHONPATH: repoRoot,
      };
      const pythonClient = await runCommand(
        'python3',
        [join('typescript', 'ts_sdk', 'examples', 'python_to_ts_did_wba_client.py')],
        repoRoot,
        pythonEnv
      );
      expect(pythonClient.code).toBe(0);
      expect(pythonClient.output).toContain(
        'Python client -> TS server mutual DID-WBA authentication completed.'
      );
      expect(pythonClient.output).toContain("'authScheme': 'bearer'");
      expect(pythonClient.output).toContain('Verified server DID response signature for:');
    } finally {
      server.kill('SIGTERM');
      await once(server, 'exit').catch(() => undefined);
    }
  }, 30_000);
});

async function waitForServer(output: string[], marker: string): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (output.join('').includes(marker)) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`Server did not start. Output:\n${output.join('')}`);
}

async function runCommand(
  command: string,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv
): Promise<{ code: number | null; output: string }> {
  const child = spawn(command, args, {
    cwd,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const chunks: string[] = [];
  child.stdout.on('data', (chunk) => chunks.push(String(chunk)));
  child.stderr.on('data', (chunk) => chunks.push(String(chunk)));
  const [code] = (await once(child, 'exit')) as [number | null];
  return {
    code,
    output: chunks.join(''),
  };
}
