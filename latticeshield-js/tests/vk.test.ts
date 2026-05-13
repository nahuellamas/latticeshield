/**
 * vk.test.ts — Unit tests for fetchVK (SEC-H13-1).
 *
 * Tests verify that fetchVK:
 *   - Parses the bridge JSON response ({ server_vk, fingerprint }) correctly
 *   - Extracts and validates the server_vk field
 *   - Rejects non-JSON bodies, missing fields, wrong lengths, invalid hex
 *   - Rejects non-200 HTTP responses
 *   - Ignores extra JSON fields (e.g. fingerprint)
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { fetchVK } from '../src/vk.js';

// 3904 hex chars = 1952 bytes (valid VK length)
const VALID_VK_HEX = '00'.repeat(1952); // 3904 chars, all-zero
const VALID_FINGERPRINT_HEX = '00'.repeat(32); // 64 chars

function mockFetch(status: number, body: string): void {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue({
      ok: status >= 200 && status < 300,
      status,
      statusText: status === 200 ? 'OK' : 'Error',
      text: () => Promise.resolve(body),
    }),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('fetchVK', () => {
  it('returns decoded bytes when response is valid JSON with 3904-hex server_vk', async () => {
    const body = JSON.stringify({
      server_vk: VALID_VK_HEX,
      fingerprint: VALID_FINGERPRINT_HEX,
    });
    mockFetch(200, body);

    const result = await fetchVK('https://bridge.example.com', 'tok123');
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(1952);
    // All-zero VK
    expect(result.every((b) => b === 0)).toBe(true);
  });

  it('ignores extra fields (fingerprint) without throwing', async () => {
    const body = JSON.stringify({
      server_vk: VALID_VK_HEX,
      fingerprint: VALID_FINGERPRINT_HEX,
      extra_field: 'ignored',
    });
    mockFetch(200, body);

    await expect(fetchVK('https://bridge.example.com', 'tok')).resolves.toBeInstanceOf(Uint8Array);
  });

  it('throws on non-JSON response body', async () => {
    mockFetch(200, VALID_VK_HEX); // plain hex — pre-0.2 format
    await expect(fetchVK('https://bridge.example.com', 'tok')).rejects.toThrow(
      'fetchVK: response is not valid JSON',
    );
  });

  it('throws on JSON missing server_vk field', async () => {
    mockFetch(200, JSON.stringify({ fingerprint: VALID_FINGERPRINT_HEX }));
    await expect(fetchVK('https://bridge.example.com', 'tok')).rejects.toThrow(
      'fetchVK: missing server_vk field',
    );
  });

  it('throws on server_vk with wrong length (too short)', async () => {
    mockFetch(200, JSON.stringify({ server_vk: 'deadbeef' }));
    await expect(fetchVK('https://bridge.example.com', 'tok')).rejects.toThrow(
      'fetchVK: server_vk has wrong length',
    );
  });

  it('throws on server_vk with wrong length (3902 chars — one byte short)', async () => {
    const shortHex = '00'.repeat(1951); // 3902 chars
    mockFetch(200, JSON.stringify({ server_vk: shortHex }));
    await expect(fetchVK('https://bridge.example.com', 'tok')).rejects.toThrow(
      'fetchVK: server_vk has wrong length',
    );
  });

  it('throws on server_vk with non-hex characters', async () => {
    // 3904 chars but contains 'zz'
    const invalidHex = 'zz' + '00'.repeat(1951);
    mockFetch(200, JSON.stringify({ server_vk: invalidHex }));
    await expect(fetchVK('https://bridge.example.com', 'tok')).rejects.toThrow(
      'fetchVK: server_vk is not valid hex',
    );
  });

  it('throws on non-200 HTTP response', async () => {
    mockFetch(403, 'Forbidden');
    await expect(fetchVK('https://bridge.example.com', 'tok')).rejects.toThrow(
      'fetchVK: server returned 403',
    );
  });

  it('throws on non-200 HTTP response (500)', async () => {
    mockFetch(500, 'Internal Server Error');
    await expect(fetchVK('https://bridge.example.com', 'tok')).rejects.toThrow(
      'fetchVK: server returned 500',
    );
  });

  it('throws when baseUrl does not start with https://', async () => {
    await expect(fetchVK('http://bridge.example.com', 'tok')).rejects.toThrow(
      'fetchVK: baseUrl must start with https://',
    );
  });
});
