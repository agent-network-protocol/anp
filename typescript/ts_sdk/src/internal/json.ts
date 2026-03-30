import canonicalize from 'canonicalize';

export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export interface JsonObject {
  [key: string]: JsonValue;
}

export function canonicalizeJson(value: unknown): Uint8Array {
  const output = canonicalize(value as never);
  if (output === undefined) {
    throw new Error('Failed to canonicalize JSON value');
  }
  return new TextEncoder().encode(output);
}

export function cloneJson<T>(value: T): T {
  return structuredClone(value);
}
