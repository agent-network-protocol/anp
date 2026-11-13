import { createHash } from 'node:crypto';
import { AuthenticationError } from '../errors/index.js';

export interface HttpSignaturePolicy {
  maxAgeSeconds?: number;
  futureSkewSeconds?: number;
  /** Explicit offline crypto checking only, never complete authentication. */
  cryptoOnly?: boolean;
}

export interface HttpSignatureVerificationOptions {
  policy?: HttpSignaturePolicy;
  /** UTC epoch seconds, not Date.now() milliseconds. */
  now?: number;
}

export const defaultAuthClock = (): number => Math.floor(Date.now() / 1000);

export function validateHttpSignatureTime(
  created: number,
  expires: number | undefined,
  policy: HttpSignaturePolicy = {},
  now = defaultAuthClock()
): number {
  const age = policy.maxAgeSeconds ?? 300;
  const skew = policy.futureSkewSeconds ?? 60;
  if (
    !Number.isSafeInteger(age) ||
    age < 1 ||
    age > 86400 ||
    !Number.isSafeInteger(skew) ||
    skew < 0 ||
    skew > 86400 ||
    !Number.isSafeInteger(created) ||
    created < 0 ||
    created > 999999999999999 ||
    !Number.isSafeInteger(now) ||
    now < 0 ||
    (expires !== undefined &&
      (!Number.isSafeInteger(expires) || expires < created || expires > 999999999999999))
  ) {
    throw new AuthenticationError('Invalid HTTP signature time parameter or policy');
  }
  const deadline = Math.min(created + age, expires ?? Infinity);
  if (!policy.cryptoOnly && (created > now + skew || now > deadline)) {
    throw new AuthenticationError('HTTP signature timestamp is expired or invalid');
  }
  return deadline;
}

export function authenticationOrigin(raw: string): string {
  const url = new URL(raw);
  if (
    !['http:', 'https:'].includes(url.protocol) ||
    !url.hostname ||
    url.username ||
    url.password ||
    /^[^:]+:\/\/([^/?#]*)/.exec(raw)?.[1].includes('@') ||
    raw.includes('#') ||
    /[\x00-\x20\x7f\\]/.test(raw) ||
    url.hostname.toLowerCase().startsWith('[::ffff:')
  ) {
    throw new AuthenticationError('Invalid authentication URL');
  }
  const port = url.port || (url.protocol === 'https:' ? '443' : '80');
  if (Number(port) === 0) throw new AuthenticationError('Invalid authentication port');
  return `${url.protocol}//${url.hostname.toLowerCase()}:${port}`;
}

export interface HttpReplayContext {
  signerDid: string;
  verifierScope: string;
  replayKey: string;
  validUntil: number;
}

export interface HttpReplayStore {
  /** Must atomically accept once and retain through validUntil, including skew. */
  consumeOnce(context: HttpReplayContext): boolean | Promise<boolean>;
}
export type HttpReplayConsumer = (context: HttpReplayContext) => boolean | Promise<boolean>;

export function replayDigest(parts: string[]): string {
  if (parts.some((part) => part.includes('\0')))
    throw new AuthenticationError('Invalid replay scope');
  return createHash('sha256').update(parts.join('\0'), 'utf8').digest('hex');
}

/** Bounded, event-loop-atomic store; NOT shared across processes or workers. */
export class MemoryHttpReplayStore implements HttpReplayStore {
  private readonly seen = new Map<string, number>();
  constructor(
    private readonly capacity = 10000,
    private readonly clock = defaultAuthClock
  ) {
    if (!Number.isSafeInteger(capacity) || capacity < 1)
      throw new AuthenticationError('Invalid replay capacity');
  }
  consumeOnce(context: HttpReplayContext): boolean {
    const now = this.clock();
    if (!Number.isSafeInteger(now) || !Number.isSafeInteger(context.validUntil)) {
      throw new AuthenticationError('Invalid replay clock');
    }
    for (const [key, deadline] of this.seen) if (deadline < now) this.seen.delete(key);
    if (context.validUntil < now || this.seen.has(context.replayKey)) return false;
    if (this.seen.size >= this.capacity)
      throw new AuthenticationError('Replay store capacity exhausted');
    this.seen.set(context.replayKey, context.validUntil);
    return true;
  }
}

export async function consumeHttpReplay(
  store: HttpReplayStore | HttpReplayConsumer,
  context: HttpReplayContext
): Promise<boolean> {
  const result = await (typeof store === 'function' ? store(context) : store.consumeOnce(context));
  if (typeof result !== 'boolean')
    throw new AuthenticationError('Replay store must return a boolean');
  return result;
}
