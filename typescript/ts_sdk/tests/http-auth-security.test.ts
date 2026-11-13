import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Socket } from 'node:net';
import { beforeEach, afterEach, describe, expect, test, vi } from 'vitest';
import {
  authenticationOrigin,
  extractAuthHeaderParts,
  DidWbaVerifier,
  DidWbaVerifierError,
  MemoryHttpReplayStore,
  httpSignatureReplayContext,
  verifyHttpMessageSignature,
  verifyFederatedHttpRequest,
  type DidDocument,
  type HttpReplayContext,
} from '../src/authentication/index.js';

const corpus = JSON.parse(
  readFileSync(
    join(process.cwd(), '../../testdata/authentication/security_vectors_v1.json'),
    'utf8'
  )
) as {
  now: number;
  document: DidDocument;
  cases: Array<{
    id: string;
    method: string;
    url: string;
    body: string;
    headers: Record<string, string>;
    accepted: boolean;
  }>;
};
beforeEach(() => {
  vi.spyOn(Socket.prototype, 'connect').mockImplementation(() => {
    throw new Error('Unit test attempted real network');
  });
});
afterEach(() => {
  vi.restoreAllMocks();
});

describe('HTTP authentication security', () => {
  test.each(corpus.cases)('shared vector $id', (vector) => {
    const operation = () =>
      verifyHttpMessageSignature(
        corpus.document,
        vector.method,
        vector.url,
        vector.headers,
        vector.body,
        { now: corpus.now }
      );
    if (vector.accepted) expect(operation).not.toThrow();
    else expect(operation).toThrow();
  });
  test('default checks time; historical crypto verification requires an explicit option', () => {
    const vector = corpus.cases[2];
    expect(() =>
      verifyHttpMessageSignature(corpus.document, vector.method, vector.url, vector.headers)
    ).toThrow();
    expect(() =>
      verifyHttpMessageSignature(
        corpus.document,
        vector.method,
        vector.url,
        vector.headers,
        undefined,
        { policy: { cryptoOnly: true } }
      )
    ).not.toThrow();
  });
  test('ambiguous headers/params and unsigned extensions cannot be ignored', () => {
    const v = corpus.cases[0];
    const changes: Array<Record<string, string>> = [
      { 'signature-input': v.headers['Signature-Input'] },
      { 'Signature-Input': v.headers['Signature-Input'] + ';created=1' },
      { 'Signature-Input': v.headers['Signature-Input'] + ';tag="not-signed"' },
    ];
    for (const change of changes)
      expect(() =>
        verifyHttpMessageSignature(
          corpus.document,
          v.method,
          v.url,
          { ...v.headers, ...change },
          undefined,
          { now: corpus.now }
        )
      ).toThrow();
  });
  test('origin caches distinguish scheme and port while normalizing defaults', () => {
    expect(authenticationOrigin('https://EXAMPLE.com/a')).toBe(
      authenticationOrigin('https://example.com:443/b')
    );
    expect(authenticationOrigin('https://example.com:8443/b')).not.toBe(
      authenticationOrigin('https://example.com/a')
    );
    for (const url of [
      'https://user@example.com/',
      'https://example.com:0/',
      'https://example.com/#x',
      'file://example.com/a',
    ])
      expect(() => authenticationOrigin(url)).toThrow();
  });
  test('bounded memory store accepts once across concurrent consumers and keeps deadline', async () => {
    let now = corpus.now;
    const store = new MemoryHttpReplayStore(1, () => now);
    const context: HttpReplayContext = {
      signerDid: 'did:web:unit.example',
      verifierScope: 'receiver',
      replayKey: 'key',
      validUntil: now + 60,
    };
    const results = await Promise.all(Array.from({ length: 20 }, () => store.consumeOnce(context)));
    expect(results.filter(Boolean)).toHaveLength(1);
    now += 60;
    expect(store.consumeOnce(context)).toBe(false);
    const other = { ...context, replayKey: 'other', validUntil: now + 60 };
    expect(() => store.consumeOnce(other)).toThrow('capacity');
    now++;
    expect(store.consumeOnce(other)).toBe(true);
  });
  test('two verifiers share replay state; invalid signatures cannot poison it; no nonce is not a bypass', async () => {
    const vector = corpus.cases[1];
    const store = new MemoryHttpReplayStore(100, () => corpus.now);
    const make = () =>
      new DidWbaVerifier({
        clock: () => corpus.now,
        replayStore: store,
        requireNonceForHttpSignatures: false,
      });
    const first = make(),
      second = make();
    await expect(
      first.verifyRequestWithDidDocument(
        vector.method,
        vector.url,
        { ...vector.headers, Signature: 'sig1=:AA==:' },
        corpus.document
      )
    ).rejects.toThrow();
    const results = await Promise.allSettled(
      [first, second].map((v) =>
        v.verifyRequestWithDidDocument(vector.method, vector.url, vector.headers, corpus.document)
      )
    );
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    const meta = verifyHttpMessageSignature(
      corpus.document,
      vector.method,
      vector.url,
      vector.headers,
      undefined,
      { now: corpus.now }
    );
    const replay = httpSignatureReplayContext(meta, vector.method, vector.url, vector.headers);
    expect(replay.replayKey).toHaveLength(64);
    expect(replay.validUntil).toBe(corpus.now + 360);
  });
  test('unavailable stores fail closed before the token issuer', async () => {
    const vector = corpus.cases[0];
    const verifier = new DidWbaVerifier({
      clock: () => corpus.now,
      replayStore: async () => {
        throw new Error('unit unavailable');
      },
    });
    const issuer = vi.spyOn(
      verifier as unknown as { createAccessToken(did: string): Promise<string> },
      'createAccessToken'
    );
    await expect(
      verifier.verifyRequestWithDidDocument(
        vector.method,
        vector.url,
        vector.headers,
        corpus.document
      )
    ).rejects.toMatchObject({ statusCode: 503 });
    expect(issuer).not.toHaveBeenCalled();
  });
  test('federation applies time and atomic replay and refuses offline policy', async () => {
    const v = corpus.cases[0];
    const sender = {
      ...corpus.document,
      id: 'did:web:sender.example:agent',
      service: [
        {
          id: 'message',
          type: 'ANPMessageService',
          serviceDid: corpus.document.id,
          serviceEndpoint: 'https://receiver.example/rpc',
        },
      ],
    };
    const store = new MemoryHttpReplayStore(100, () => corpus.now);
    const options = { senderDidDocument: sender, serviceDidDocument: corpus.document };
    const security = { now: corpus.now, replayStore: store };
    await expect(
      verifyFederatedHttpRequest(
        sender.id,
        v.method,
        v.url,
        v.headers,
        undefined,
        options,
        security
      )
    ).resolves.toMatchObject({ serviceDid: corpus.document.id });
    await expect(
      verifyFederatedHttpRequest(
        sender.id,
        v.method,
        v.url,
        v.headers,
        undefined,
        options,
        security
      )
    ).rejects.toThrow('replay');
    await expect(
      verifyFederatedHttpRequest(sender.id, v.method, v.url, v.headers, undefined, options, {
        ...security,
        policy: { cryptoOnly: true },
      })
    ).rejects.toThrow('time validation');
  });
  test('error remains the established SDK verifier type', () => {
    expect(new DidWbaVerifierError('unit', 401).statusCode).toBe(401);
  });
});

test('frozen legacy authority serializers share canonical replay and never change signed target', () => {
  const compatibility = JSON.parse(
    readFileSync(
      join(process.cwd(), '../../testdata/authentication/authority_compatibility_v1.json'),
      'utf8'
    )
  ) as {
    now: number;
    document: DidDocument;
    cases: Array<{ url: string; headers: Record<string, string>; replay_key: string }>;
  };
  for (const vector of compatibility.cases) {
    const metadata = verifyHttpMessageSignature(
      compatibility.document,
      'GET',
      vector.url,
      vector.headers,
      undefined,
      { now: compatibility.now }
    );
    expect(httpSignatureReplayContext(metadata, 'GET', vector.url, vector.headers).replayKey).toBe(
      vector.replay_key
    );
    expect(() =>
      verifyHttpMessageSignature(
        compatibility.document,
        'GET',
        vector.url + 'tampered',
        vector.headers,
        undefined,
        { now: compatibility.now }
      )
    ).toThrow();
  }
});

test('bounded HTTP fields and duplicate-free Legacy parsing', () => {
  const legacy = JSON.parse(
    readFileSync(
      join(process.cwd(), '../../testdata/authentication/legacy_compatibility_v1.json'),
      'utf8'
    )
  ) as { header: string };
  expect(extractAuthHeaderParts(legacy.header).nonce).toBe('public-legacy-fixture');
  for (const tail of [', nonce="duplicate"', ', DID="duplicate"', ', v="1.0"', ' garbage'])
    expect(() => extractAuthHeaderParts(legacy.header + tail)).toThrow();
  const vector = corpus.cases[0];
  for (const value of [
    'sig1=:' + 'A'.repeat(20000) + ':',
    vector.headers.Signature + '\r\nInjected: value',
  ])
    expect(() =>
      verifyHttpMessageSignature(
        corpus.document,
        'GET',
        vector.url,
        { ...vector.headers, Signature: value },
        undefined,
        { now: corpus.now }
      )
    ).toThrow();
});

test('IPv6 origins use the same canonical host and reject mapped aliases', () => {
  expect(authenticationOrigin('https://[2001:4860:0000:0000:0000:0000:0000:8888]/')).toBe(
    'https://[2001:4860::8888]:443'
  );
  expect(() => authenticationOrigin('https://[::ffff:8.8.8.8]/')).toThrow();
});
