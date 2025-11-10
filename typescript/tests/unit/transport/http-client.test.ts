/**
 * Unit tests for HTTP Client
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { HTTPClient } from '../../../src/transport/http-client.js';
import { AuthenticationManager } from '../../../src/core/auth/authentication-manager.js';
import { DIDManager } from '../../../src/core/did/did-manager.js';
import { NetworkError } from '../../../src/errors/index.js';
import type { DIDIdentity } from '../../../src/types/index.js';

describe('HTTPClient', () => {
  let httpClient: HTTPClient;
  let authManager: AuthenticationManager;
  let didManager: DIDManager;
  let testIdentity: DIDIdentity;

  beforeEach(async () => {
    didManager = new DIDManager();
    authManager = new AuthenticationManager(didManager, {
      maxTokenAge: 3600000,
      nonceLength: 32,
      clockSkewTolerance: 60,
    });

    httpClient = new HTTPClient(authManager, {
      timeout: 5000,
      maxRetries: 3,
      retryDelay: 100,
    });

    testIdentity = await didManager.createDID({
      domain: 'example.com',
      path: 'user/alice',
    });

    // Clear all mocks before each test
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('GET requests', () => {
    it('should make successful GET request', async () => {
      const mockResponse = { data: 'test data' };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockResponse,
        text: async () => JSON.stringify(mockResponse),
        headers: new Headers(),
      });

      const response = await httpClient.get('https://api.example.com/data');

      expect(fetch).toHaveBeenCalledWith(
        'https://api.example.com/data',
        expect.objectContaining({
          method: 'GET',
        })
      );

      const data = await response.json();
      expect(data).toEqual(mockResponse);
    });

    it('should include timeout in request', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({}),
        headers: new Headers(),
      });

      await httpClient.get('https://api.example.com/data');

      expect(fetch).toHaveBeenCalledWith(
        'https://api.example.com/data',
        expect.objectContaining({
          signal: expect.any(AbortSignal),
        })
      );
    });

    it('should handle GET request with query parameters', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({}),
        headers: new Headers(),
      });

      await httpClient.get('https://api.example.com/data?param=value');

      expect(fetch).toHaveBeenCalledWith(
        'https://api.example.com/data?param=value',
        expect.any(Object)
      );
    });
  });

  describe('POST requests', () => {
    it('should make successful POST request', async () => {
      const requestBody = { message: 'test' };
      const mockResponse = { success: true };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockResponse,
        headers: new Headers(),
      });

      const response = await httpClient.post(
        'https://api.example.com/submit',
        requestBody
      );

      expect(fetch).toHaveBeenCalledWith(
        'https://api.example.com/submit',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify(requestBody),
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
        })
      );

      const data = await response.json();
      expect(data).toEqual(mockResponse);
    });

    it('should handle POST with empty body', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({}),
        headers: new Headers(),
      });

      await httpClient.post('https://api.example.com/submit', {});

      expect(fetch).toHaveBeenCalledWith(
        'https://api.example.com/submit',
        expect.objectContaining({
          method: 'POST',
          body: '{}',
        })
      );
    });
  });

  describe('authenticated requests', () => {
    it('should include auth header in authenticated GET request', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({}),
        headers: new Headers(),
      });

      await httpClient.get('https://api.example.com/protected', testIdentity);

      expect(fetch).toHaveBeenCalledWith(
        'https://api.example.com/protected',
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: expect.stringContaining('DIDWba'),
          }),
        })
      );
    });

    it('should include auth header in authenticated POST request', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({}),
        headers: new Headers(),
      });

      await httpClient.post(
        'https://api.example.com/protected',
        { data: 'test' },
        testIdentity
      );

      expect(fetch).toHaveBeenCalledWith(
        'https://api.example.com/protected',
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: expect.stringContaining('DIDWba'),
          }),
        })
      );
    });

    it('should extract domain from URL for auth header', async () => {
      const generateAuthSpy = vi.spyOn(authManager, 'generateAuthHeader');

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({}),
        headers: new Headers(),
      });

      await httpClient.get(
        'https://api.example.com:8080/protected',
        testIdentity
      );

      expect(generateAuthSpy).toHaveBeenCalledWith(
        testIdentity,
        'api.example.com',
        expect.any(String)
      );
    });

    it('should not include auth header for unauthenticated requests', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({}),
        headers: new Headers(),
      });

      await httpClient.get('https://api.example.com/public');

      const callArgs = (fetch as any).mock.calls[0][1];
      expect(callArgs.headers?.Authorization).toBeUndefined();
    });
  });

  describe('retry mechanism', () => {
    it('should retry on network error', async () => {
      let attemptCount = 0;

      global.fetch = vi.fn().mockImplementation(() => {
        attemptCount++;
        if (attemptCount < 3) {
          return Promise.reject(new Error('Network error'));
        }
        return Promise.resolve({
          ok: true,
          status: 200,
          json: async () => ({ success: true }),
          headers: new Headers(),
        });
      });

      const response = await httpClient.get('https://api.example.com/data');

      expect(attemptCount).toBe(3);
      expect(fetch).toHaveBeenCalledTimes(3);

      const data = await response.json();
      expect(data).toEqual({ success: true });
    });

    it('should retry on 5xx server errors', async () => {
      let attemptCount = 0;

      global.fetch = vi.fn().mockImplementation(() => {
        attemptCount++;
        if (attemptCount < 2) {
          return Promise.resolve({
            ok: false,
            status: 503,
            statusText: 'Service Unavailable',
            json: async () => ({}),
            headers: new Headers(),
          });
        }
        return Promise.resolve({
          ok: true,
          status: 200,
          json: async () => ({ success: true }),
          headers: new Headers(),
        });
      });

      const response = await httpClient.get('https://api.example.com/data');

      expect(attemptCount).toBe(2);
      const data = await response.json();
      expect(data).toEqual({ success: true });
    });

    it('should not retry on 4xx client errors', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        json: async () => ({ error: 'Not found' }),
        headers: new Headers(),
      });

      await expect(
        httpClient.get('https://api.example.com/notfound')
      ).rejects.toThrow(NetworkError);

      expect(fetch).toHaveBeenCalledTimes(1);
    });

    it('should use exponential backoff between retries', async () => {
      const timestamps: number[] = [];

      global.fetch = vi.fn().mockImplementation(() => {
        timestamps.push(Date.now());
        if (timestamps.length < 3) {
          return Promise.reject(new Error('Network error'));
        }
        return Promise.resolve({
          ok: true,
          status: 200,
          json: async () => ({}),
          headers: new Headers(),
        });
      });

      await httpClient.get('https://api.example.com/data');

      // Check that delays increase (exponential backoff)
      if (timestamps.length >= 3) {
        const delay1 = timestamps[1] - timestamps[0];
        const delay2 = timestamps[2] - timestamps[1];
        expect(delay2).toBeGreaterThanOrEqual(delay1);
      }
    });

    it('should fail after max retries exceeded', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Network error'));

      await expect(
        httpClient.get('https://api.example.com/data')
      ).rejects.toThrow();

      // Should try initial + 3 retries = 4 times
      expect(fetch).toHaveBeenCalledTimes(4);
    });
  });

  describe('timeout handling', () => {
    it('should pass abort signal to fetch', async () => {
      let receivedSignal: AbortSignal | undefined;

      global.fetch = vi.fn().mockImplementation((url, options) => {
        receivedSignal = options?.signal;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: async () => ({}),
          headers: new Headers(),
        });
      });

      await httpClient.get('https://api.example.com/data');

      expect(receivedSignal).toBeDefined();
      expect(receivedSignal).toBeInstanceOf(AbortSignal);
    });

    it('should use configured timeout value', async () => {
      const customClient = new HTTPClient(authManager, {
        timeout: 100, // Very short timeout
        maxRetries: 0,
        retryDelay: 0,
      });

      global.fetch = vi.fn().mockImplementation((url, options) => {
        return new Promise((resolve, reject) => {
          // Listen to abort signal
          if (options?.signal) {
            options.signal.addEventListener('abort', () => {
              reject(new Error('The operation was aborted'));
            });
          }

          // Never resolve - let the timeout trigger
          setTimeout(() => {
            resolve({
              ok: true,
              status: 200,
              json: async () => ({}),
              headers: new Headers(),
            });
          }, 1000); // Longer than timeout
        });
      });

      await expect(
        customClient.get('https://api.example.com/slow')
      ).rejects.toThrow(NetworkError);
    }, 1000); // Increase test timeout
  });

  describe('error handling', () => {
    it('should throw NetworkError on fetch failure', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Connection refused'));

      await expect(
        httpClient.get('https://api.example.com/data')
      ).rejects.toThrow(NetworkError);
    });

    it('should throw NetworkError with status code on HTTP error', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        json: async () => ({ error: 'Server error' }),
        headers: new Headers(),
      });

      try {
        await httpClient.get('https://api.example.com/data');
        expect.fail('Should have thrown NetworkError');
      } catch (error) {
        expect(error).toBeInstanceOf(NetworkError);
        expect((error as NetworkError).statusCode).toBe(500);
      }
    });

    it('should include error message in NetworkError', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 403,
        statusText: 'Forbidden',
        json: async () => ({ error: 'Access denied' }),
        headers: new Headers(),
      });

      try {
        await httpClient.get('https://api.example.com/data');
        expect.fail('Should have thrown NetworkError');
      } catch (error) {
        expect(error).toBeInstanceOf(NetworkError);
        expect((error as NetworkError).message).toContain('403');
      }
    });

    it('should handle malformed JSON responses', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => {
          throw new Error('Invalid JSON');
        },
        text: async () => 'not json',
        headers: new Headers(),
      });

      const response = await httpClient.get('https://api.example.com/data');

      // Should still return the response object
      expect(response).toBeDefined();
      await expect(response.json()).rejects.toThrow();
    });

    it('should handle network timeout errors', async () => {
      global.fetch = vi.fn().mockImplementation(() => {
        return Promise.reject(new Error('The operation was aborted'));
      });

      await expect(
        httpClient.get('https://api.example.com/data')
      ).rejects.toThrow(NetworkError);
    });
  });

  describe('request method', () => {
    it('should support custom HTTP methods', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({}),
        headers: new Headers(),
      });

      await httpClient.request('https://api.example.com/data', {
        method: 'PUT',
        body: JSON.stringify({ data: 'test' }),
      });

      expect(fetch).toHaveBeenCalledWith(
        'https://api.example.com/data',
        expect.objectContaining({
          method: 'PUT',
        })
      );
    });

    it('should support custom headers', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({}),
        headers: new Headers(),
      });

      await httpClient.request('https://api.example.com/data', {
        method: 'GET',
        headers: {
          'X-Custom-Header': 'custom-value',
        },
      });

      expect(fetch).toHaveBeenCalledWith(
        'https://api.example.com/data',
        expect.objectContaining({
          headers: expect.objectContaining({
            'X-Custom-Header': 'custom-value',
          }),
        })
      );
    });

    it('should merge custom headers with auth headers', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({}),
        headers: new Headers(),
      });

      await httpClient.request(
        'https://api.example.com/data',
        {
          method: 'GET',
          headers: {
            'X-Custom-Header': 'custom-value',
          },
        },
        testIdentity
      );

      expect(fetch).toHaveBeenCalledWith(
        'https://api.example.com/data',
        expect.objectContaining({
          headers: expect.objectContaining({
            'X-Custom-Header': 'custom-value',
            Authorization: expect.stringContaining('DIDWba'),
          }),
        })
      );
    });
  });
});
