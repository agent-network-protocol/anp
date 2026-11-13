import { AuthenticationError } from '../errors/index.js';
import { authenticationOrigin } from './http-auth-security.js';

/** Build a method resource without DNS or network access. Override is host-only. */
export function buildDidResolutionUrl(did: string, baseUrlOverride?: string): string {
  const parts = did.split(':');
  if (parts.length < 3 || parts[0] !== 'did' || !['wba', 'web'].includes(parts[1])) {
    throw new AuthenticationError('Invalid DID method');
  }
  const authority = decodeURIComponent(parts[2]);
  if (!authority || /[/\\?#%@\x00-\x20\x7f]/.test(authority))
    throw new AuthenticationError('Invalid DID authority');
  authenticationOrigin(`https://${authority}`);
  const host = new URL(`https://${authority}`).hostname;
  if (parts[1] === 'web') {
    const labels = host.split('.');
    if (
      host.length > 253 ||
      labels.length < 2 ||
      !/[A-Za-z]/.test(labels.at(-1) ?? '') ||
      labels.some((label) => !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label))
    ) {
      throw new AuthenticationError('DID Web requires a DNS hostname');
    }
  }
  const segments = parts.slice(3).map((raw) => {
    const value = decodeURIComponent(raw);
    if (!value || value === '.' || value === '..' || /[/\\?#%\x00-\x1f\x7f]/.test(value))
      throw new AuthenticationError('Unsafe DID path component');
    return encodeURIComponent(value);
  });
  let base = `https://${authority}`;
  if (baseUrlOverride !== undefined) {
    authenticationOrigin(baseUrlOverride);
    const override = new URL(baseUrlOverride);
    if (override.search || baseUrlOverride.includes('#'))
      throw new AuthenticationError('Invalid trusted resolution override');
    base = baseUrlOverride.replace(/\/+$/, '');
  }
  return `${base}/${segments.length ? segments.join('/') + '/did.json' : '.well-known/did.json'}`;
}
