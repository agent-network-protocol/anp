/** WNS display-name lookup used by identity and conversation projection. */

import type { AwikiImTransport } from './protocol.js';

/** Split a Handle into the WNS local part and domain. */
export function parseHandle(
  value: string
): { local: string; domain: string; handle: string } | undefined {
  const trimmed = value
    .trim()
    .replace(/^@+/u, '')
    .replace(/^wba:\/\//u, '');
  const separator = trimmed.indexOf('.');
  if (separator <= 0 || separator === trimmed.length - 1) {
    return undefined;
  }
  const local = trimmed.slice(0, separator);
  const domain = trimmed.slice(separator + 1);
  if (!local || !domain) {
    return undefined;
  }
  return { local, domain, handle: `${local}.${domain}` };
}

/** Infer a Handle from a `did:wba` path when inbox rows omit one. */
export function handleCandidateFromDid(did: string): string | undefined {
  if (!did.startsWith('did:wba:')) {
    return undefined;
  }
  const parts = did.split(':');
  if (parts.length < 4) {
    return undefined;
  }
  const domain = parts[2];
  const path = parts.slice(3);
  const local = path[0] === 'user' ? path[1] : path[0];
  if (!domain || !local || /^(?:e1_|k1_)/u.test(local)) {
    return undefined;
  }
  return `${local}.${domain}`;
}

/** Read a public WNS profile and return its display-only name. */
export async function lookupDisplayName(
  transport: AwikiImTransport,
  handle: string,
  expectedDid?: string
): Promise<string | undefined> {
  const parsed = parseHandle(handle);
  if (!parsed) {
    return undefined;
  }
  try {
    const document = await transport.getJson(
      `https://${parsed.domain}/.well-known/handle/${encodeURIComponent(parsed.local)}`
    );
    if (stringValue(document.handle)?.toLowerCase() !== parsed.handle.toLowerCase()) {
      return undefined;
    }
    if (expectedDid && stringValue(document.did) !== expectedDid) {
      return undefined;
    }
    const profile = isRecord(document.profile) ? document.profile : undefined;
    const displayName = stringValue(document.display_name) ?? stringValue(profile?.display_name);
    if (!displayName) {
      return undefined;
    }
    if (profile) {
      const subjectDid = stringValue(profile.subject_did);
      const profileHandle = stringValue(profile.handle);
      if (subjectDid && expectedDid && subjectDid !== expectedDid) {
        return undefined;
      }
      if (profileHandle && profileHandle.toLowerCase() !== parsed.handle.toLowerCase()) {
        return undefined;
      }
    }
    return displayName;
  } catch {
    return undefined;
  }
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}
