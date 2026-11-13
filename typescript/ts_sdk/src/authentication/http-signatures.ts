import { randomBytes } from 'node:crypto';

import { AuthenticationError } from '../errors/index.js';
import { encodeBase64, encodeBase64Url } from '../internal/base64.js';
import {
  normalizePrivateKeyMaterial,
  sha256,
  signMessage,
  verifyMessage,
  type PrivateKeyInput,
} from '../internal/keys.js';
import type { DidDocument, HttpSignatureOptions, SignatureMetadata } from './types.js';
import { findVerificationMethod } from './did-wba.js';
import { extractPublicKey } from './verification-methods.js';
import {
  authenticationOrigin,
  replayDigest,
  validateHttpSignatureTime,
  type HttpSignatureVerificationOptions,
  type HttpSignaturePolicy,
  type HttpReplayContext,
} from './http-auth-security.js';

export function buildContentDigest(body: Uint8Array | string): string {
  const digest = sha256(toBytes(body));
  return `sha-256=:${encodeBase64(digest)}:`;
}

export function verifyContentDigest(body: Uint8Array | string, contentDigest: string): boolean {
  return buildContentDigest(body) === contentDigest.trim();
}

export function generateHttpSignatureHeaders(
  didDocument: DidDocument,
  requestUrl: string,
  requestMethod: string,
  privateKeyInput: PrivateKeyInput,
  headers: Record<string, string> = {},
  body?: Uint8Array | string,
  options: HttpSignatureOptions = {}
): Record<string, string> {
  const keyid = options.keyid ?? selectDefaultKeyid(didDocument);
  const coveredComponents = options.coveredComponents ?? ['@method', '@target-uri', '@authority'];
  const headersToSign = { ...headers };
  const bodyBytes = body ? toBytes(body) : new Uint8Array(0);
  const covered = [...coveredComponents];

  if (bodyBytes.length > 0) {
    headersToSign['Content-Digest'] ??= buildContentDigest(bodyBytes);
    headersToSign['Content-Length'] ??= String(bodyBytes.length);
    if (!covered.some((component) => component.toLowerCase() === 'content-digest')) {
      covered.push('content-digest');
    }
  }

  if (!covered.includes('@method') || !covered.includes('@target-uri'))
    throw new AuthenticationError('Missing required signed component');
  const created = options.created ?? Math.floor(Date.now() / 1000);
  const expires = options.expires ?? created + 300;
  const nonce = options.nonce ?? encodeBase64Url(randomBytes(16));
  validateHttpSignatureTime(created, expires, { cryptoOnly: true }, created);
  if (!nonce || nonce.length > 1024 || /[^\x20-\x7e]/.test(nonce))
    throw new AuthenticationError('Invalid nonce parameter');
  const signatureBase = buildSignatureBase(
    covered,
    requestMethod,
    requestUrl,
    headersToSign,
    created,
    expires,
    nonce,
    keyid
  );

  const signature = signMessage(
    normalizePrivateKeyMaterial(privateKeyInput),
    new TextEncoder().encode(signatureBase)
  );

  const result: Record<string, string> = {
    'Signature-Input': `sig1=${serializeSignatureParams(covered, created, expires, nonce, keyid)}`,
    Signature: `sig1=:${Buffer.from(signature).toString('base64')}:`,
  };

  if (headersToSign['Content-Digest']) {
    result['Content-Digest'] = headersToSign['Content-Digest'];
  }
  return result;
}

export function extractSignatureMetadata(headers: Record<string, string>): SignatureMetadata {
  const signatureInput = getHeaderCaseInsensitive(headers, 'Signature-Input');
  const signatureHeader = getHeaderCaseInsensitive(headers, 'Signature');
  if (!signatureInput || !signatureHeader) {
    throw new AuthenticationError('Missing Signature-Input or Signature header');
  }

  const [labelInput, components, params] = parseSignatureInput(signatureInput);
  const [labelSignature] = parseSignatureHeader(signatureHeader);
  if (labelInput !== labelSignature) {
    throw new AuthenticationError('Invalid signature input');
  }

  const keyid = params.keyid;
  const created = Number(params.created);
  if (!keyid || Number.isNaN(created)) {
    throw new AuthenticationError('Invalid signature input');
  }

  return {
    label: labelInput,
    components,
    keyid,
    nonce: params.nonce,
    created,
    expires: params.expires ? Number(params.expires) : undefined,
  };
}

export function verifyHttpMessageSignature(
  didDocument: DidDocument,
  requestMethod: string,
  requestUrl: string,
  headers: Record<string, string>,
  body?: Uint8Array | string,
  options: HttpSignatureVerificationOptions = {}
): SignatureMetadata {
  const signatureInput = getHeaderCaseInsensitive(headers, 'Signature-Input');
  const signatureHeader = getHeaderCaseInsensitive(headers, 'Signature');
  if (!signatureInput || !signatureHeader) {
    throw new AuthenticationError('Missing Signature-Input or Signature header');
  }

  const [labelInput, components, params, serializedParams] = parseSignatureInput(signatureInput);
  const [labelSignature, signatureBytes] = parseSignatureHeader(signatureHeader);
  if (labelInput !== labelSignature) {
    throw new AuthenticationError('Invalid signature input');
  }

  const keyid = params.keyid;
  const created = Number(params.created);
  if (!keyid || Number.isNaN(created)) {
    throw new AuthenticationError('Invalid signature input');
  }

  if (
    !keyid.startsWith('did:') ||
    keyid.split('#').length !== 2 ||
    !keyid.split('#')[1] ||
    keyid.split('#')[0] !== didDocument.id
  )
    throw new AuthenticationError('Signature keyid DID mismatch');
  const expires = params.expires === undefined ? undefined : Number(params.expires);
  validateHttpSignatureTime(created, expires, options.policy, options.now);
  if (params.nonce !== undefined && (!params.nonce || params.nonce.length > 1024))
    throw new AuthenticationError('Invalid nonce parameter');
  if (!components.includes('@method') || !components.includes('@target-uri'))
    throw new AuthenticationError('Missing required signed component');
  const bodyBytes = body ? toBytes(body) : new Uint8Array(0);
  if (bodyBytes.length && !components.includes('content-digest'))
    throw new AuthenticationError('HTTP signature must cover content-digest for a body');
  if (
    bodyBytes.length > 0 ||
    components.some((component) => component.toLowerCase() === 'content-digest')
  ) {
    const contentDigest = getHeaderCaseInsensitive(headers, 'Content-Digest');
    if (!contentDigest) {
      throw new AuthenticationError('Missing Content-Digest header');
    }
    if (!verifyContentDigest(bodyBytes, contentDigest)) {
      throw new AuthenticationError('Content-Digest verification failed');
    }
  }

  const method = findVerificationMethod(didDocument, keyid);
  if (!method) {
    throw new AuthenticationError('Verification method not found');
  }

  const publicKey = extractPublicKey(method);
  const signatureBase = buildSignatureBaseWithParams(
    components,
    requestMethod,
    requestUrl,
    headers,
    serializedParams
  );
  const authorities = authorityCandidates(requestUrl);
  const bases = [
    signatureBase,
    ...(components.includes('@authority')
      ? authorities.map((authority) => replaceAuthority(signatureBase, authority))
      : []),
  ];
  if (
    !bases.some((base) => verifyMessage(publicKey, new TextEncoder().encode(base), signatureBytes))
  ) {
    throw new AuthenticationError('Signature verification failed');
  }

  return {
    label: labelInput,
    components,
    keyid,
    nonce: params.nonce,
    created,
    expires: params.expires ? Number(params.expires) : undefined,
  };
}

export function httpSignatureReplayContext(
  metadata: SignatureMetadata,
  method: string,
  url: string,
  headers: Record<string, string>,
  scope = authenticationOrigin(url),
  policy: HttpSignaturePolicy = {}
): HttpReplayContext {
  const input = getHeaderCaseInsensitive(headers, 'Signature-Input');
  if (!input) throw new AuthenticationError('Missing signature input');
  const [, components, , params] = parseSignatureInput(input);
  const base = replaceAuthority(
    buildSignatureBaseWithParams(components, method, url, headers, params),
    authenticationOrigin(url).split('://')[1]
  );
  const digest = Buffer.from(sha256(new TextEncoder().encode(base))).toString('hex');
  const signerDid = metadata.keyid.split('#')[0];
  const material = metadata.nonce === undefined ? `base:${digest}` : `nonce:${metadata.nonce}`;
  const deadline = validateHttpSignatureTime(
    metadata.created,
    metadata.expires,
    policy,
    metadata.created
  );
  return {
    signerDid,
    verifierScope: scope,
    replayKey: replayDigest(['anp.http-auth.replay.v1', scope, signerDid, material]),
    validUntil: deadline + (policy.futureSkewSeconds ?? 60),
  };
}

function buildSignatureBaseWithParams(
  components: string[],
  method: string,
  url: string,
  headers: Record<string, string>,
  params: string
): string {
  return [
    ...components.map(
      (component) => `"${component}": ${componentValue(component, method, url, headers)}`
    ),
    `"@signature-params": ${params}`,
  ].join('\n');
}

function buildSignatureBase(
  components: string[],
  method: string,
  url: string,
  headers: Record<string, string>,
  created: number,
  expires: number | undefined,
  nonce: string | undefined,
  keyid: string
): string {
  const lines = components.map(
    (component) => `"${component}": ${componentValue(component, method, url, headers)}`
  );
  lines.push(
    `"@signature-params": ${serializeSignatureParams(components, created, expires, nonce, keyid)}`
  );
  return lines.join('\n');
}

function replaceAuthority(base: string, authority: string): string {
  return base
    .split('\n')
    .map((line) => (line.startsWith('"@authority": ') ? `"@authority": ${authority}` : line))
    .join('\n');
}
function authorityCandidates(url: string): string[] {
  const origin = authenticationOrigin(url),
    suffix = url.startsWith('https://') ? ':443' : ':80';
  const values: string[] = [];
  for (const authority of [url.split('://')[1].split(/[/?]/)[0], origin.split('://')[1]]) {
    for (const value of [
      authority,
      authority.endsWith(suffix) ? authority.slice(0, -suffix.length) : authority,
    ])
      values.push(value, value.replace(/[\[\]]/g, ''));
  }
  return [...new Set(values)];
}

function componentValue(
  component: string,
  method: string,
  url: string,
  headers: Record<string, string>
): string {
  switch (component) {
    case '@method':
      return method.toUpperCase();
    case '@target-uri':
      return url;
    case '@authority': {
      const parsed = new URL(url);
      return parsed.port ? `${parsed.hostname}:${parsed.port}` : parsed.hostname;
    }
    default: {
      const value = getHeaderCaseInsensitive(headers, component);
      if (!value) {
        throw new AuthenticationError('Invalid signature input');
      }
      return value;
    }
  }
}

function serializeSignatureParams(
  components: string[],
  created: number,
  expires: number | undefined,
  nonce: string | undefined,
  keyid: string
): string {
  const quotedComponents = components.map((component) => `"${component}"`).join(' ');
  const parts = [`created=${created}`];
  if (expires !== undefined) {
    parts.push(`expires=${expires}`);
  }
  if (nonce) {
    parts.push(`nonce=${JSON.stringify(nonce)}`);
  }
  parts.push(`keyid=${JSON.stringify(keyid)}`);
  return `(${quotedComponents});${parts.join(';')}`;
}

const componentPattern = new RegExp(
  '^"[a-z0-9@!#$%&\'*+.^_`|~-]+"(?: +"[a-z0-9@!#$%&\'*+.^_`|~-]+")*$'
);
const parameterPattern = new RegExp(
  '^;([a-z*][a-z0-9_.*-]*)(?:=("(?:[\\x20-\\x21\\x23-\\x5b\\x5d-\\x7e]|\\\\["\\\\])*"|-?[0-9]{1,15}|\\?[01]|[A-Za-z*][A-Za-z0-9!#$%&\'*+.^_`|~:/-]*))?'
);
function parseSignatureInput(value: string): [string, string[], Record<string, string>, string] {
  const invalid = () => new AuthenticationError('Invalid or ambiguous signature input');
  if (value.length > 16384) throw invalid();
  const match = /^([A-Za-z0-9_-]+)=\(([^)]*)\)(.*)$/.exec(value.trim());
  if (!match || !componentPattern.test(match[2])) throw invalid();
  const components = match[2].split(/ +/).map((value) => value.slice(1, -1));
  if (components.length > 32 || new Set(components).size !== components.length) throw invalid();
  const params: Record<string, string> = Object.create(null) as Record<string, string>;
  let rest = match[3],
    serialized = '(' + components.map((c) => JSON.stringify(c)).join(' ') + ')';
  while (rest) {
    const part = parameterPattern.exec(rest);
    if (!part || Object.hasOwn(params, part[1]) || Object.keys(params).length >= 32)
      throw invalid();
    const name = part[1],
      raw = part[2];
    if (['created', 'expires'].includes(name) && (!raw || !/^-?[0-9]{1,15}$/.test(raw)))
      throw invalid();
    if (['keyid', 'nonce'].includes(name) && !raw?.startsWith('"')) throw invalid();
    params[name] = raw?.startsWith('"') ? (JSON.parse(raw) as string) : (raw ?? 'true');
    serialized += ';' + name;
    if (raw !== undefined && raw !== '?1') serialized += '=' + raw;
    rest = rest.slice(part[0].length);
  }
  return [match[1], components, params, serialized];
}

function parseSignatureHeader(value: string): [string, Uint8Array] {
  const separator = value.indexOf('=');
  if (separator < 0) {
    throw new AuthenticationError('Invalid signature header format');
  }
  const label = value.slice(0, separator);
  const raw = value.slice(separator + 1);
  if (!raw.startsWith(':') || !raw.endsWith(':')) {
    throw new AuthenticationError('Invalid signature header format');
  }
  const encoded = raw.slice(1, -1);
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded) || !encoded)
    throw new AuthenticationError('Invalid signature encoding');
  return [label, new Uint8Array(Buffer.from(encoded, 'base64'))];
}

function selectDefaultKeyid(didDocument: DidDocument): string {
  const first = didDocument.authentication[0];
  if (typeof first === 'string') {
    return first;
  }
  if (first?.id) {
    return first.id;
  }
  throw new AuthenticationError('Verification method not found');
}

function getHeaderCaseInsensitive(
  headers: Record<string, string>,
  name: string
): string | undefined {
  const target = name.toLowerCase();
  const values = Object.entries(headers).filter(([key]) => key.toLowerCase() === target);
  if (values.length > 1) throw new AuthenticationError('Ambiguous duplicate HTTP header');
  const value = values[0]?.[1];
  if (
    value !== undefined &&
    (typeof value !== 'string' || value.length > 16384 || /[\r\n\x00\x7f]/.test(value))
  )
    throw new AuthenticationError('Invalid or excessive HTTP authentication header');
  return value;
}

function toBytes(value: Uint8Array | string): Uint8Array {
  return typeof value === 'string' ? new TextEncoder().encode(value) : value;
}
