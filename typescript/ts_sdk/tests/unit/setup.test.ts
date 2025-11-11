import { describe, it, expect } from 'vitest';
import { VERSION } from '../../src/index.js';

describe('SDK Setup', () => {
  it('should export VERSION constant', () => {
    expect(VERSION).toBe('0.1.0');
  });

  it('should have correct version format', () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
