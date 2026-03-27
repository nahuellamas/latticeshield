/**
 * session.test.ts — Unit tests for PQCSession (main thread).
 *
 * Tests constructor validation, wss:// enforcement, and event emitter
 * behaviour. Full integration (WebSocket + Worker) is not tested here
 * since it requires a live bridge — that's Phase 8 (Rust integration tests).
 */

import { describe, it, expect } from 'vitest';
import { PQCSession } from '../src/session.js';
import {
  SERVER_HELLO_SIGNED_LEN,
  CLIENT_RESPONSE_LEN,
  VERIFYING_KEY_LEN,
  FRAME_DATA,
  FRAME_KEY_ROTATE,
  KEY_ROTATE_FRAME_LEN,
} from '../src/types.js';

// ── wss:// enforcement (EC-14) ────────────────────────────────────────────────

describe('PQCSession constructor — wss:// enforcement (EC-14)', () => {
  const vk = new Uint8Array(VERIFYING_KEY_LEN);

  it('throws immediately for ws:// URL', () => {
    expect(() => new PQCSession({ bridgeUrl: 'ws://localhost:8446', serverVkBytes: vk }))
      .toThrow('latticeshield-js requires wss://');
  });

  it('throws immediately for http:// URL', () => {
    expect(() => new PQCSession({ bridgeUrl: 'http://localhost:8446', serverVkBytes: vk }))
      .toThrow('latticeshield-js requires wss://');
  });

  it('throws for plain hostname (no scheme)', () => {
    expect(() => new PQCSession({ bridgeUrl: 'localhost:8446', serverVkBytes: vk }))
      .toThrow('latticeshield-js requires wss://');
  });

  it('accepts wss:// URL without throwing', () => {
    expect(() => new PQCSession({ bridgeUrl: 'wss://localhost:8446', serverVkBytes: vk }))
      .not.toThrow();
  });

  it('accepts wss:// with path', () => {
    expect(() =>
      new PQCSession({ bridgeUrl: 'wss://bridge.example.com:8446/pqc', serverVkBytes: vk }),
    ).not.toThrow();
  });
});

// ── Wire format constants ─────────────────────────────────────────────────────

describe('Wire format constants (spec alignment)', () => {
  it('SERVER_HELLO_SIGNED_LEN = 4557', () => {
    expect(SERVER_HELLO_SIGNED_LEN).toBe(4557);
  });

  it('CLIENT_RESPONSE_LEN = 1120', () => {
    expect(CLIENT_RESPONSE_LEN).toBe(1120);
  });

  it('VERIFYING_KEY_LEN = 1952', () => {
    expect(VERIFYING_KEY_LEN).toBe(1952);
  });

  it('FRAME_DATA = 0x01', () => {
    expect(FRAME_DATA).toBe(0x01);
  });

  it('FRAME_KEY_ROTATE = 0x02', () => {
    expect(FRAME_KEY_ROTATE).toBe(0x02);
  });

  it('KEY_ROTATE_FRAME_LEN = 61', () => {
    // tag(1) + nonce(12) + enc_rotation_nonce(32) + tag(16) = 61
    expect(KEY_ROTATE_FRAME_LEN).toBe(61);
  });
});

// ── Event emitter ─────────────────────────────────────────────────────────────

describe('PQCSession event emitter', () => {
  const vk = new Uint8Array(VERIFYING_KEY_LEN);

  it('on/off: registers and removes listener', () => {
    const session = new PQCSession({ bridgeUrl: 'wss://localhost:8446', serverVkBytes: vk });
    const calls: string[] = [];

    const handler = (err: Error): void => { calls.push(err.message); };
    session.on('error', handler);

    // Access private emit via type cast for testing
    (session as unknown as { emit: (e: string, ...a: unknown[]) => void }).emit('error', new Error('test-err'));
    expect(calls).toEqual(['test-err']);

    session.off('error', handler);
    (session as unknown as { emit: (e: string, ...a: unknown[]) => void }).emit('error', new Error('test-err-2'));
    // Should not be called again after off
    expect(calls).toEqual(['test-err']);
  });

  it('once: fires only one time', () => {
    const session = new PQCSession({ bridgeUrl: 'wss://localhost:8446', serverVkBytes: vk });
    const calls: string[] = [];

    session.once('error', (err) => { calls.push(err.message); });

    const emitter = session as unknown as { emit: (e: string, ...a: unknown[]) => void };
    emitter.emit('error', new Error('first'));
    emitter.emit('error', new Error('second'));

    expect(calls).toEqual(['first']);
  });

  it('on: multiple listeners all fire', () => {
    const session = new PQCSession({ bridgeUrl: 'wss://localhost:8446', serverVkBytes: vk });
    const calls: number[] = [];

    session.on('close', () => calls.push(1));
    session.on('close', () => calls.push(2));

    (session as unknown as { emit: (e: string) => void }).emit('close');
    expect(calls).toEqual([1, 2]);
  });
});

// ── send() in non-ready state ─────────────────────────────────────────────────

describe('PQCSession.send() guards', () => {
  it('rejects if called before connect()', async () => {
    const vk = new Uint8Array(VERIFYING_KEY_LEN);
    const session = new PQCSession({ bridgeUrl: 'wss://localhost:8446', serverVkBytes: vk });
    await expect(session.send(new Uint8Array([1]))).rejects.toThrow(
      'send() called in state "idle"',
    );
  });
});
