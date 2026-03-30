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

  const created = options.created ?? Math.floor(Date.now() / 1000);
  const expires = options.expires ?? created + 300;
  const nonce = options.nonce ?? encodeBase64Url(randomBytes(16));
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
  body?: Uint8Array | string
): SignatureMetadata {
  const signatureInput = getHeaderCaseInsensitive(headers, 'Signature-Input');
  const signatureHeader = getHeaderCaseInsensitive(headers, 'Signature');
  if (!signatureInput || !signatureHeader) {
    throw new AuthenticationError('Missing Signature-Input or Signature header');
  }

  const [labelInput, components, params] = parseSignatureInput(signatureInput);
  const [labelSignature, signatureBytes] = parseSignatureHeader(signatureHeader);
  if (labelInput !== labelSignature) {
    throw new AuthenticationError('Invalid signature input');
  }

  const keyid = params.keyid;
  const created = Number(params.created);
  if (!keyid || Number.isNaN(created)) {
    throw new AuthenticationError('Invalid signature input');
  }

  const bodyBytes = body ? toBytes(body) : new Uint8Array(0);
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
  const signatureBase = buildSignatureBase(
    components,
    requestMethod,
    requestUrl,
    headers,
    created,
    params.expires ? Number(params.expires) : undefined,
    params.nonce,
    keyid
  );
  if (!verifyMessage(publicKey, new TextEncoder().encode(signatureBase), signatureBytes)) {
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
    parts.push(`nonce="${nonce}"`);
  }
  parts.push(`keyid="${keyid}"`);
  return `(${quotedComponents});${parts.join(';')}`;
}

function parseSignatureInput(value: string): [string, string[], Record<string, string>] {
  const separator = value.indexOf('=');
  if (separator < 0) {
    throw new AuthenticationError('Invalid signature input');
  }
  const label = value.slice(0, separator);
  const remainder = value.slice(separator + 1);
  const openIndex = remainder.indexOf('(');
  const closeIndex = remainder.indexOf(')');
  if (openIndex < 0 || closeIndex < 0 || closeIndex <= openIndex) {
    throw new AuthenticationError('Invalid signature input');
  }

  const components = remainder
    .slice(openIndex + 1, closeIndex)
    .split(/\s+/)
    .map((component) => component.replaceAll('"', ''))
    .filter(Boolean);
  if (components.length === 0) {
    throw new AuthenticationError('Invalid signature input');
  }

  const params = remainder
    .slice(closeIndex + 1)
    .replace(/^;/, '')
    .split(';')
    .filter(Boolean)
    .reduce<Record<string, string>>((result, part) => {
      const [name, rawValue] = part.split('=', 2);
      if (!name || rawValue === undefined) {
        throw new AuthenticationError('Invalid signature input');
      }
      result[name] = rawValue.replace(/^"|"$/g, '');
      return result;
    }, {});

  return [label, components, params];
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
  return [label, new Uint8Array(Buffer.from(raw.slice(1, -1), 'base64'))];
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

function getHeaderCaseInsensitive(headers: Record<string, string>, name: string): string | undefined {
  const target = name.toLowerCase();
  return Object.entries(headers).find(([key]) => key.toLowerCase() === target)?.[1];
}

function toBytes(value: Uint8Array | string): Uint8Array {
  return typeof value === 'string' ? new TextEncoder().encode(value) : value;
}
