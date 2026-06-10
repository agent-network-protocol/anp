import {
  HandleGoneError,
  HandleMovedError,
  HandleNotFoundError,
  HandleResolutionError,
} from '../errors/index.js';
import type { DIDSubjectProfile, HandleResolutionDocument, ResolveHandleOptions } from './types.js';
import { HandleStatus, SubjectType } from './types.js';
import { buildResolutionUrl, parseWbaUri, validateHandle } from './validator.js';

export async function resolveHandle(
  handle: string,
  options: ResolveHandleOptions = {}
): Promise<HandleResolutionDocument> {
  const bareHandle = stripWbaScheme(handle);
  const [localPart, domain] = validateHandle(bareHandle);
  const normalized = `${localPart}.${domain}`;
  const baseUrl = options.baseUrlOverride?.replace(/\/$/, '');
  const url = baseUrl
    ? `${baseUrl}/.well-known/handle/${localPart}`
    : buildResolutionUrl(localPart, domain);

  void options.verifySsl;
  const timeoutMs = Math.round((options.timeoutSeconds ?? 10) * 1000);
  const response = await fetch(url, {
    headers: { Accept: 'application/json' },
    redirect: 'manual',
    signal: AbortSignal.timeout(timeoutMs),
  }).catch((error) => {
    throw new HandleResolutionError(
      `Network error resolving handle '${normalized}': ${(error as Error).message}`,
      502,
      error as Error
    );
  });

  if (response.status === 301) {
    throw new HandleMovedError(
      `Handle '${normalized}' has been migrated`,
      response.headers.get('Location') ?? ''
    );
  }
  if (response.status === 404) {
    throw new HandleNotFoundError(`Handle '${normalized}' does not exist`);
  }
  if (response.status === 410) {
    throw new HandleGoneError(`Handle '${normalized}' has been permanently revoked`);
  }
  if (!response.ok) {
    throw new HandleResolutionError(
      `Unexpected status ${response.status} resolving '${normalized}'`,
      502
    );
  }

  const payload = (await response.json()) as Record<string, unknown>;
  const document: HandleResolutionDocument = {
    handle: String(payload.handle ?? ''),
    did: String(payload.did ?? ''),
    status: normalizeStatus(String(payload.status ?? '')),
    updated: payload.updated ? String(payload.updated) : undefined,
    versionId: payload.versionId ? String(payload.versionId) : undefined,
    ttl: typeof payload.ttl === 'number' ? payload.ttl : undefined,
    profile: normalizeProfile(payload.profile),
  };
  if (document.handle.toLowerCase() !== normalized) {
    throw new HandleResolutionError(
      `Handle mismatch: requested '${normalized}', got '${document.handle}'`,
      502
    );
  }
  dropInvalidProfileProjection(document);
  return document;
}

export async function resolveHandleFromUri(
  wbaUri: string,
  options: ResolveHandleOptions = {}
): Promise<HandleResolutionDocument> {
  const parsed = parseWbaUri(wbaUri);
  return resolveHandle(parsed.handle, options);
}

function stripWbaScheme(handleOrUri: string): string {
  return handleOrUri.startsWith('wba://') ? handleOrUri.slice('wba://'.length) : handleOrUri;
}

function normalizeStatus(value: string): HandleStatus {
  switch (value.toLowerCase()) {
    case HandleStatus.Active:
      return HandleStatus.Active;
    case HandleStatus.Suspended:
      return HandleStatus.Suspended;
    case HandleStatus.Revoked:
      return HandleStatus.Revoked;
    default:
      throw new HandleResolutionError(`Unexpected handle status '${value}'`, 502);
  }
}

function normalizeProfile(value: unknown): DIDSubjectProfile | undefined {
  if (!isRecord(value)) {
    return undefined;
  }
  return {
    type: value.type ? String(value.type) : undefined,
    subject_did: String(value.subject_did ?? ''),
    subject_type: normalizeSubjectType(value.subject_type),
    handle: value.handle ? String(value.handle) : undefined,
    display_name: value.display_name ? String(value.display_name) : undefined,
    description: value.description ? String(value.description) : undefined,
    avatar_uri: value.avatar_uri ? String(value.avatar_uri) : undefined,
    profile_uri: value.profile_uri ? String(value.profile_uri) : undefined,
    discoverability: value.discoverability ? String(value.discoverability) : undefined,
    labels: isRecord(value.labels) ? value.labels : undefined,
    updated: value.updated ? String(value.updated) : undefined,
    versionId: value.versionId ? String(value.versionId) : undefined,
    ttl: typeof value.ttl === 'number' ? value.ttl : undefined,
    proof: isRecord(value.proof) ? value.proof : undefined,
  };
}

function dropInvalidProfileProjection(document: HandleResolutionDocument): void {
  if (!document.profile) {
    return;
  }
  if (document.profile.subject_did !== document.did) {
    document.profile = undefined;
    return;
  }
  if (document.profile.handle && document.profile.handle !== document.handle) {
    document.profile = undefined;
  }
}

function normalizeSubjectType(value: unknown): SubjectType {
  if (!value) {
    return SubjectType.Unknown;
  }
  const normalized = String(value).toLowerCase();
  return Object.values(SubjectType).includes(normalized as SubjectType)
    ? (normalized as SubjectType)
    : SubjectType.Unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
