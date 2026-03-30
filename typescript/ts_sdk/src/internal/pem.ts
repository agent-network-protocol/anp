import { decodeBase64, encodeBase64 } from './base64.js';

const PEM_LINE_LENGTH = 64;

export interface DecodedPem {
  label: string;
  bytes: Uint8Array;
}

export function encodePem(label: string, bytes: Uint8Array): string {
  const encoded = encodeBase64(bytes);
  const lines: string[] = [];
  for (let index = 0; index < encoded.length; index += PEM_LINE_LENGTH) {
    lines.push(encoded.slice(index, index + PEM_LINE_LENGTH));
  }
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

export function decodePem(input: string): DecodedPem {
  const lines = input.trim().split(/\r?\n/);
  if (lines.length < 3) {
    throw new Error('Invalid PEM structure');
  }
  const beginLine = lines[0];
  const endLine = lines.at(-1);
  if (!beginLine.startsWith('-----BEGIN ') || !beginLine.endsWith('-----')) {
    throw new Error('Invalid PEM structure');
  }
  const label = beginLine.slice('-----BEGIN '.length, -'-----'.length);
  if (endLine !== `-----END ${label}-----`) {
    throw new Error('Invalid PEM structure');
  }
  const body = lines.slice(1, -1).join('');
  return {
    label,
    bytes: decodeBase64(body),
  };
}
