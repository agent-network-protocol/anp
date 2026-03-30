export function encodeBase64Url(value: Uint8Array): string {
  return Buffer.from(value).toString('base64url');
}

export function decodeBase64Url(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'base64url'));
}

export function encodeBase64(value: Uint8Array): string {
  return Buffer.from(value).toString('base64');
}

export function decodeBase64(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'base64'));
}
