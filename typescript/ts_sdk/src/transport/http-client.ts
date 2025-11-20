/**
 * HTTP Client for making authenticated requests
 */

import { AuthenticationManager } from '../core/auth/authentication-manager.js';
import { NetworkError } from '../errors/index.js';
import type { DIDIdentity } from '../types/index.js';

/**
 * Configuration for HTTP Client
 */
export interface HTTPClientConfig {
  timeout: number; // milliseconds
  maxRetries: number;
  retryDelay: number; // milliseconds
}

/**
 * Request options
 */
export interface RequestOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

/**
 * HTTP Client class
 */
export class HTTPClient {
  private readonly authManager: AuthenticationManager;
  private readonly config: HTTPClientConfig;

  constructor(authManager: AuthenticationManager, config: HTTPClientConfig) {
    this.authManager = authManager;
    this.config = config;
  }

  /**
   * Make an HTTP request with optional authentication
   *
   * @param url - The URL to request
   * @param options - Request options
   * @param identity - Optional DID identity for authentication
   * @returns Response object
   */
  async request(
    url: string,
    options: RequestOptions,
    identity?: DIDIdentity
  ): Promise<Response> {
    const headers: Record<string, string> = {
      ...options.headers,
    };

    // Add authentication header if identity is provided
    if (identity) {
      const domain = this.extractDomain(url);
      const verificationMethodId = `${identity.did}#auth-key`;

      const authHeader = await this.authManager.generateAuthHeader(
        identity,
        domain,
        verificationMethodId
      );

      headers['Authorization'] = authHeader;
    }

    // Add Content-Type for POST/PUT requests with body
    if (
      options.body &&
      (options.method === 'POST' || options.method === 'PUT') &&
      !headers['Content-Type']
    ) {
      headers['Content-Type'] = 'application/json';
    }

    // Create abort controller for timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const response = await this.retryWithBackoff(async () => {
        try {
          const fetchResponse = await fetch(url, {
            method: options.method || 'GET',
            headers,
            body: options.body,
            signal: controller.signal,
          });

          // Check if response is ok
          if (!fetchResponse.ok) {
            // Retry on 5xx errors, fail immediately on 4xx
            if (fetchResponse.status >= 500) {
              throw new NetworkError(
                `HTTP ${fetchResponse.status}: ${fetchResponse.statusText}`,
                fetchResponse.status
              );
            } else {
              // Don't retry 4xx errors
              throw new NetworkError(
                `HTTP ${fetchResponse.status}: ${fetchResponse.statusText}`,
                fetchResponse.status,
                new Error('Client error - no retry')
              );
            }
          }

          return fetchResponse;
        } catch (error) {
          // Handle abort/timeout errors
          if ((error as Error).name === 'AbortError') {
            throw new NetworkError('Request timeout', undefined, error as Error);
          }

          // Handle network errors
          if (error instanceof NetworkError) {
            // Check if it's a 4xx error (don't retry)
            if (
              error.statusCode &&
              error.statusCode >= 400 &&
              error.statusCode < 500
            ) {
              // Mark as non-retryable by re-throwing with special marker
              const nonRetryable = new NetworkError(
                error.message,
                error.statusCode,
                new Error('Client error - no retry')
              );
              throw nonRetryable;
            }
            throw error;
          }

          // Wrap other errors as NetworkError
          throw new NetworkError(
            `Network request failed: ${(error as Error).message}`,
            undefined,
            error as Error
          );
        }
      }, this.config.maxRetries);

      return response;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Make a GET request
   *
   * @param url - The URL to request
   * @param identity - Optional DID identity for authentication
   * @returns Response object
   */
  async get(url: string, identity?: DIDIdentity): Promise<Response> {
    return this.request(url, { method: 'GET' }, identity);
  }

  /**
   * Make a POST request
   *
   * @param url - The URL to request
   * @param body - Request body (will be JSON stringified)
   * @param identity - Optional DID identity for authentication
   * @returns Response object
   */
  async post(
    url: string,
    body: any,
    identity?: DIDIdentity
  ): Promise<Response> {
    return this.request(
      url,
      {
        method: 'POST',
        body: JSON.stringify(body),
      },
      identity
    );
  }

  /**
   * Extract domain from URL for authentication
   *
   * @param url - The URL to extract domain from
   * @returns The domain (without port)
   */
  private extractDomain(url: string): string {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname;
    } catch (error) {
      throw new NetworkError(
        `Invalid URL: ${url}`,
        undefined,
        error as Error
      );
    }
  }

  /**
   * Retry a function with exponential backoff
   *
   * @param fn - The function to retry
   * @param maxRetries - Maximum number of retries
   * @returns The result of the function
   */
  private async retryWithBackoff<T>(
    fn: () => Promise<T>,
    maxRetries: number
  ): Promise<T> {
    let lastError: Error | undefined;
    let attempt = 0;

    while (attempt <= maxRetries) {
      try {
        return await fn();
      } catch (error) {
        lastError = error as Error;

        // Don't retry if it's a client error (4xx)
        if (
          error instanceof NetworkError &&
          error.cause?.message === 'Client error - no retry'
        ) {
          throw error;
        }

        // If we've exhausted retries, throw the error
        if (attempt >= maxRetries) {
          throw error;
        }

        // Calculate exponential backoff delay
        const delay = this.config.retryDelay * Math.pow(2, attempt);

        // Wait before retrying
        await new Promise((resolve) => setTimeout(resolve, delay));

        attempt++;
      }
    }

    // This should never be reached, but TypeScript needs it
    throw lastError || new Error('Retry failed');
  }
}
