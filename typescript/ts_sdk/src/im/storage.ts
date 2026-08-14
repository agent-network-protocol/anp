import { chmod, mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';

import { AwikiImError } from './errors.js';
import { emptyState, STATE_VERSION, type PersistedImState } from './internal.js';

/** Atomic, process-local owner of the confidential AWiki identity state file. */
export class AwikiImStateStore {
  private state: PersistedImState = emptyState();
  private mutationTail: Promise<void> = Promise.resolve();

  public constructor(private readonly path: string) {}

  /** Load and minimally validate state from disk. */
  public async load(): Promise<void> {
    if (!this.path.trim()) {
      throw new AwikiImError('invalid-request', 'AWiki statePath is required');
    }
    try {
      const decoded: unknown = JSON.parse(await readFile(this.path, 'utf8'));
      if (!isPersistedState(decoded)) {
        throw new AwikiImError('invalid-request', 'AWiki identity state is invalid');
      }
      this.state = decoded;
    } catch (error) {
      if (isMissingFile(error)) {
        this.state = emptyState();
        return;
      }
      if (error instanceof AwikiImError) {
        throw error;
      }
      throw new AwikiImError('invalid-request', 'AWiki identity state cannot be read', undefined, {
        cause: error,
      });
    }
  }

  /** Return the current in-memory state. Callers must not mutate it directly. */
  public snapshot(): Readonly<PersistedImState> {
    return this.state;
  }

  /** Serialize one mutation and persist its complete result atomically. */
  public async mutate(mutator: (state: PersistedImState) => void): Promise<void> {
    const operation = this.mutationTail.then(async () => {
      const next = structuredClone(this.state);
      mutator(next);
      await this.persist(next);
      this.state = next;
    });
    this.mutationTail = operation.catch(() => undefined);
    await operation;
  }

  private async persist(state: PersistedImState): Promise<void> {
    const parent = dirname(this.path);
    await mkdir(parent, { recursive: true, mode: 0o700 });
    const temporaryPath = `${this.path}.${process.pid}.${randomUUID()}.tmp`;
    try {
      await writeFile(temporaryPath, `${JSON.stringify(state)}\n`, {
        encoding: 'utf8',
        mode: 0o600,
        flag: 'wx',
      });
      await rename(temporaryPath, this.path);
      await chmod(this.path, 0o600);
    } catch (error) {
      await unlink(temporaryPath).catch((unlinkError: unknown) => {
        if (!isMissingFile(unlinkError)) {
          throw unlinkError;
        }
      });
      throw new AwikiImError('remote', 'AWiki identity state cannot be persisted', undefined, {
        cause: error,
      });
    }
  }
}

function isPersistedState(value: unknown): value is PersistedImState {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    record.version === STATE_VERSION &&
    isRecord(record.conversations) &&
    isRecord(record.attachments) &&
    isRecord(record.sendOperations)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function isMissingFile(error: unknown): boolean {
  return (
    !!error &&
    typeof error === 'object' &&
    'code' in error &&
    (error as { code?: unknown }).code === 'ENOENT'
  );
}
