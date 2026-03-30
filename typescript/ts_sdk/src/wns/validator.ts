import { HandleValidationError, WbaUriParseError } from '../errors/index.js';
import type { ParsedWbaUri } from './types.js';

const DOMAIN_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function validateLocalPart(localPart: string): boolean {
  const normalized = localPart.toLowerCase();
  if (!normalized || normalized.length > 63) {
    return false;
  }
  if (normalized.startsWith('-') || normalized.endsWith('-') || normalized.includes('--')) {
    return false;
  }
  return /^[a-z0-9-]+$/.test(normalized);
}

export function validateHandle(handle: string): [string, string] {
  const normalized = handle.trim().toLowerCase();
  if (!normalized) {
    throw new HandleValidationError('Handle must not be empty');
  }
  const dotIndex = normalized.indexOf('.');
  if (dotIndex < 0) {
    throw new HandleValidationError(`Handle must contain at least one dot: '${handle}'`);
  }
  const localPart = normalized.slice(0, dotIndex);
  const domain = normalized.slice(dotIndex + 1);
  if (!localPart) {
    throw new HandleValidationError(`Handle local-part is empty: '${handle}'`);
  }
  if (!domain) {
    throw new HandleValidationError(`Handle domain is empty: '${handle}'`);
  }
  if (!validateLocalPart(localPart)) {
    throw new HandleValidationError(
      `Invalid local-part '${localPart}': must be 1-63 chars of a-z, 0-9, hyphen; must start/end with alnum; no consecutive hyphens`
    );
  }
  if (!isValidDomain(domain)) {
    throw new HandleValidationError(`Invalid domain '${domain}'`);
  }
  return [localPart, domain];
}

export function normalizeHandle(handle: string): string {
  const [localPart, domain] = validateHandle(handle);
  return `${localPart}.${domain}`;
}

export function parseWbaUri(uri: string): ParsedWbaUri {
  if (!uri.startsWith('wba://')) {
    throw new WbaUriParseError(`URI must start with 'wba://': '${uri}'`);
  }
  const handlePart = uri.slice('wba://'.length);
  if (!handlePart) {
    throw new WbaUriParseError(`URI contains no handle after 'wba://': '${uri}'`);
  }
  try {
    const [localPart, domain] = validateHandle(handlePart);
    return {
      localPart,
      domain,
      handle: `${localPart}.${domain}`,
      originalUri: uri,
    };
  } catch (error) {
    throw new WbaUriParseError(`Invalid handle in URI '${uri}': ${(error as Error).message}`);
  }
}

export function buildResolutionUrl(localPart: string, domain: string): string {
  return `https://${domain}/.well-known/handle/${localPart}`;
}

export function buildWbaUri(localPart: string, domain: string): string {
  return `wba://${localPart}.${domain}`;
}

function isValidDomain(domain: string): boolean {
  const labels = domain.split('.');
  return labels.length >= 2 && labels.every((label) => DOMAIN_LABEL_RE.test(label));
}
