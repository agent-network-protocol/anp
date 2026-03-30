import {
  HandleGoneError,
  HandleMovedError,
  HandleNotFoundError,
  HandleResolutionError,
} from '../errors/index.js';
import type { HandleResolutionDocument, ResolveHandleOptions } from './types.js';
import { HandleStatus } from './types.js';
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
  };
  if (document.handle.toLowerCase() !== normalized) {
    throw new HandleResolutionError(
      `Handle mismatch: requested '${normalized}', got '${document.handle}'`,
      502
    );
  }
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
