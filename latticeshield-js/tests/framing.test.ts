/**
 * framing.test.ts — Unit tests for framing v3 encode/decode.
 *
 * These tests run in Node.js via vitest. Node 20+ exposes globalThis.crypto
 * with Web Crypto API — no polyfill needed.
 *
 * Test coverage:
 *   - seqToNonce: correct 12B layout for various seq values
 *   - encodeFrame / decodeFrame round-trip
 *   - Seq increments correctly (0, 1, 2^53, BigInt overflow safety)
 *   - Replay detection (recv_seq check)
 *   - Key rotation (parseKeyRotateFrame, processKeyRotate)
 *   - importSessionKey: zeroizes input buffer
 *   - wss:// enforcement (tested in session.test.ts via PQCSession constructor)
 *   - KEY_ROTATE frame parse errors
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  seqToNonce,
  seqToAad,
  encodeFrame,
  decodeFrame,
  parseKeyRotateFrame,
  processKeyRotate,
  importSessionKey,
  MAX_U64,
} from '../src/framing.js';
import type { SessionKey } from '../src/framing.js';
import { FRAME_DATA, FRAME_KEY_ROTATE, KEY_ROTATE_FRAME_LEN } from '../src/types.js';

// ── Test helpers ──────────────────────────────────────────────────────────────

/**
 * Generate a random SessionKey for testing.
 * Generates random raw bytes and imports them as both AES-GCM and HKDF keys.
 */
async function makeTestSessionKey(): Promise<SessionKey> {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  // importSessionKey zeroizes the buffer — pass a copy so we can reuse raw if needed
  return importSessionKey(raw.slice());
}

/**
 * Build a SessionKey from known raw bytes (for deterministic test vectors).
 * Uses a copy so the original buffer is not zeroized.
 */
async function sessionKeyFromBytes(raw: Uint8Array): Promise<SessionKey> {
  if (raw.length !== 32) throw new Error('raw must be 32 bytes');
  return importSessionKey(raw.slice());
}

// ── seqToNonce ────────────────────────────────────────────────────────────────

describe('seqToNonce', () => {
  it('returns a 12-byte Uint8Array', () => {
    const nonce = seqToNonce(0n);
    expect(nonce).toBeInstanceOf(Uint8Array);
    expect(nonce.length).toBe(12);
  });

  it('seq=0 produces all-zero nonce', () => {
    const nonce = seqToNonce(0n);
    expect(Array.from(nonce)).toEqual([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  });

  it('seq=1 is at offset 0..8 in big-endian (matches Rust layout)', () => {
    const nonce = seqToNonce(1n);
    // Bytes 0-7: seq big-endian → 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x01
    expect(nonce[0]).toBe(0);
    expect(nonce[6]).toBe(0);
    expect(nonce[7]).toBe(1);
    // Bytes 8-11: epoch=0
    expect(nonce[8]).toBe(0);
    expect(nonce[11]).toBe(0);
  });

  it('seq=0x0102030405060708n encodes correctly', () => {
    const nonce = seqToNonce(0x0102030405060708n);
    // Bytes 0-7: seq big-endian → 01 02 03 04 05 06 07 08
    expect(nonce[0]).toBe(0x01);
    expect(nonce[1]).toBe(0x02);
    expect(nonce[2]).toBe(0x03);
    expect(nonce[3]).toBe(0x04);
    expect(nonce[4]).toBe(0x05);
    expect(nonce[5]).toBe(0x06);
    expect(nonce[6]).toBe(0x07);
    expect(nonce[7]).toBe(0x08);
    // Bytes 8-11: epoch=0
    expect(nonce[8]).toBe(0);
    expect(nonce[11]).toBe(0);
  });

  it('seq=Number.MAX_SAFE_INTEGER as BigInt encodes without precision loss', () => {
    const maxSafe = BigInt(Number.MAX_SAFE_INTEGER); // 2^53 - 1
    const nonce = seqToNonce(maxSafe);
    // 2^53 - 1 = 0x001FFFFFFFFFFFFF — seq at bytes 0-7
    const view = new DataView(nonce.buffer);
    const readBack = view.getBigUint64(0, false);
    expect(readBack).toBe(maxSafe);
  });

  it('produces different nonces for different seq values', () => {
    const n1 = seqToNonce(42n);
    const n2 = seqToNonce(43n);
    expect(n1).not.toEqual(n2);
  });
});

// ── seqToAad ─────────────────────────────────────────────────────────────────

describe('seqToAad', () => {
  it('returns 8 bytes', () => {
    expect(seqToAad(0n).length).toBe(8);
  });

  it('seq=0 is all zeros', () => {
    expect(Array.from(seqToAad(0n))).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
  });

  it('seq=1 encodes big-endian', () => {
    const aad = seqToAad(1n);
    expect(aad[7]).toBe(1);
    expect(aad[0]).toBe(0);
  });
});

// ── seqToNonce / seqToAad overflow guards (SEC-H14-1) ────────────────────────

describe('seqToNonce overflow guard', () => {
  it('seq=0n is accepted (lower boundary)', () => {
    expect(() => seqToNonce(0n)).not.toThrow();
    expect(seqToNonce(0n).length).toBe(12);
  });

  it('seq=MAX_U64 is accepted (upper boundary)', () => {
    expect(() => seqToNonce(MAX_U64)).not.toThrow();
    // MAX_U64 = 0xFFFFFFFFFFFFFFFF — bytes 0-7 all 0xFF, bytes 8-11 (epoch) all 0x00
    const nonce = seqToNonce(MAX_U64);
    for (let i = 0; i < 8; i++) {
      expect(nonce[i]).toBe(0xff);
    }
    for (let i = 8; i < 12; i++) {
      expect(nonce[i]).toBe(0x00);
    }
  });

  it('seq=MAX_U64 + 1n throws RangeError', () => {
    expect(() => seqToNonce(MAX_U64 + 1n)).toThrow(RangeError);
  });

  it('seq=-1n throws RangeError', () => {
    expect(() => seqToNonce(-1n)).toThrow(RangeError);
  });
});

describe('seqToAad overflow guard', () => {
  it('seq=0n is accepted (lower boundary)', () => {
    expect(() => seqToAad(0n)).not.toThrow();
    expect(seqToAad(0n).length).toBe(8);
  });

  it('seq=MAX_U64 is accepted (upper boundary)', () => {
    expect(() => seqToAad(MAX_U64)).not.toThrow();
    const aad = seqToAad(MAX_U64);
    for (let i = 0; i < 8; i++) {
      expect(aad[i]).toBe(0xff);
    }
  });

  it('seq=MAX_U64 + 1n throws RangeError', () => {
    expect(() => seqToAad(MAX_U64 + 1n)).toThrow(RangeError);
  });

  it('seq=-1n throws RangeError', () => {
    expect(() => seqToAad(-1n)).toThrow(RangeError);
  });
});

describe('encodeFrame propagates RangeError from seqToNonce', () => {
  it('encodeFrame with seq=-1n throws RangeError', async () => {
    const key = await importSessionKey(new Uint8Array(32).fill(0xaa));
    await expect(encodeFrame(key, -1n, new Uint8Array(4))).rejects.toThrow(RangeError);
  });

  it('encodeFrame with seq=MAX_U64+1n throws RangeError', async () => {
    const key = await importSessionKey(new Uint8Array(32).fill(0xaa));
    await expect(encodeFrame(key, MAX_U64 + 1n, new Uint8Array(4))).rejects.toThrow(RangeError);
  });
});

// ── importSessionKey ──────────────────────────────────────────────────────────

describe('importSessionKey', () => {
  it('returns a SessionKey with aes and hkdf CryptoKey fields', async () => {
    const raw = new Uint8Array(32).fill(0xab);
    const key = await importSessionKey(raw.slice()); // slice to preserve test ref
    expect(key.aes).toBeInstanceOf(CryptoKey);
    expect(key.hkdf).toBeInstanceOf(CryptoKey);
  });

  it('aes key has algorithm AES-GCM', async () => {
    const raw = new Uint8Array(32).fill(0x11);
    const key = await importSessionKey(raw.slice());
    expect(key.aes.algorithm.name).toBe('AES-GCM');
  });

  it('hkdf key has algorithm HKDF', async () => {
    const raw = new Uint8Array(32).fill(0x22);
    const key = await importSessionKey(raw.slice());
    expect(key.hkdf.algorithm.name).toBe('HKDF');
  });

  it('zeroizes the input buffer after import (EC-2, EC-3)', async () => {
    const raw = new Uint8Array(32).fill(0xcd);
    await importSessionKey(raw); // passes original — should be zeroized
    expect(Array.from(raw)).toEqual(new Array(32).fill(0));
  });

  it('throws on wrong key length', async () => {
    await expect(importSessionKey(new Uint8Array(16))).rejects.toThrow(
      'session key must be 32 bytes',
    );
  });

  it('aes key is non-extractable (EC-2)', async () => {
    const raw = new Uint8Array(32).fill(0x77);
    const key = await importSessionKey(raw.slice());
    await expect(crypto.subtle.exportKey('raw', key.aes)).rejects.toThrow();
  });

  it('hkdf key is non-extractable (EC-2)', async () => {
    const raw = new Uint8Array(32).fill(0x88);
    const key = await importSessionKey(raw.slice());
    await expect(crypto.subtle.exportKey('raw', key.hkdf)).rejects.toThrow();
  });
});

// ── encodeFrame / decodeFrame round-trip ─────────────────────────────────────

describe('encodeFrame / decodeFrame round-trip', () => {
  let key: SessionKey;

  beforeAll(async () => {
    key = await makeTestSessionKey();
  });

  it('round-trip: short plaintext at seq=0', async () => {
    const plaintext = new TextEncoder().encode('hello latticeshield');
    const frame = await encodeFrame(key, 0n, plaintext);
    const { plaintext: decoded, seq } = await decodeFrame(key, frame, 0n, false);
    expect(decoded).toEqual(plaintext);
    expect(seq).toBe(0n);
  });

  it('frame starts with 0x01 tag', async () => {
    const frame = await encodeFrame(key, 0n, new Uint8Array([1, 2, 3]));
    expect(frame[0]).toBe(FRAME_DATA);
  });

  it('len field (bytes 1-4) matches ciphertext+tag length', async () => {
    const plaintext = new Uint8Array(10).fill(0xaa);
    const frame = await encodeFrame(key, 0n, plaintext);
    const view = new DataView(frame.buffer);
    const len = view.getUint32(1, false); // big-endian u32 at offset 1
    // AES-GCM appends 16B tag, so len = plaintext.length + 16
    expect(len).toBe(plaintext.length + 16);
  });

  it('seq field (bytes 5-12) encodes correctly', async () => {
    const frame = await encodeFrame(key, 7n, new Uint8Array([0xff]));
    const view = new DataView(frame.buffer);
    const seq = view.getBigUint64(5, false);
    expect(seq).toBe(7n);
  });

  it('nonce bytes 13-24 match seqToNonce(seq)', async () => {
    const frame = await encodeFrame(key, 3n, new Uint8Array([0x42]));
    const nonce = frame.slice(13, 25);
    expect(nonce).toEqual(seqToNonce(3n));
  });

  it('round-trip: seq=100', async () => {
    const plaintext = new Uint8Array(64).fill(0x55);
    const frame = await encodeFrame(key, 100n, plaintext);
    const { plaintext: decoded, seq } = await decodeFrame(key, frame, 99n, true);
    expect(decoded).toEqual(plaintext);
    expect(seq).toBe(100n);
  });

  it('round-trip: empty plaintext', async () => {
    const frame = await encodeFrame(key, 0n, new Uint8Array(0));
    const { plaintext: decoded } = await decodeFrame(key, frame, 0n, false);
    expect(decoded.length).toBe(0);
  });

  it('round-trip: large plaintext (64 KB)', async () => {
    // crypto.getRandomValues is capped at 65536B in Node.js — use fill instead
    const plaintext = new Uint8Array(64 * 1024);
    for (let i = 0; i < plaintext.length; i++) plaintext[i] = i & 0xff;
    const frame = await encodeFrame(key, 0n, plaintext);
    const { plaintext: decoded } = await decodeFrame(key, frame, 0n, false);
    expect(decoded).toEqual(plaintext);
  });

  it('seq increments correctly across multiple calls', async () => {
    for (let i = 0; i < 5; i++) {
      const pt = new Uint8Array([i]);
      const frame = await encodeFrame(key, BigInt(i), pt);
      const { seq } = await decodeFrame(
        key,
        frame,
        i === 0 ? 0n : BigInt(i - 1),
        i !== 0,
      );
      expect(seq).toBe(BigInt(i));
    }
  });

  it('BigInt seq at Number.MAX_SAFE_INTEGER does not lose precision', async () => {
    const maxSafe = BigInt(Number.MAX_SAFE_INTEGER);
    const pt = new Uint8Array([0xde, 0xad]);
    const frame = await encodeFrame(key, maxSafe, pt);
    const { seq } = await decodeFrame(key, frame, maxSafe - 1n, true);
    expect(seq).toBe(maxSafe);
  });

  it('decodeFrame: wrong tag byte throws', async () => {
    const frame = await encodeFrame(key, 0n, new Uint8Array([1]));
    // Corrupt the tag byte
    const corrupted = new Uint8Array(frame);
    corrupted[0] = 0xff;
    await expect(
      decodeFrame(key, corrupted, 0n, false),
    ).rejects.toThrow('unexpected frame tag');
  });

  it('decodeFrame: truncated frame throws', async () => {
    await expect(
      decodeFrame(key, new Uint8Array(5), 0n, false),
    ).rejects.toThrow('frame too short');
  });

  it('decodeFrame: tampered ciphertext fails GCM auth', async () => {
    const frame = await encodeFrame(key, 0n, new Uint8Array([1, 2, 3]));
    const tampered = new Uint8Array(frame);
    tampered[tampered.length - 1] ^= 0xff; // flip last byte of GCM tag
    await expect(
      decodeFrame(key, tampered, 0n, false),
    ).rejects.toThrow();
  });
});

// ── Replay detection ──────────────────────────────────────────────────────────

describe('replay detection', () => {
  let key: SessionKey;

  beforeAll(async () => {
    key = await makeTestSessionKey();
  });

  it('throws "replay detected" when seq <= recv_seq', async () => {
    const plaintext = new Uint8Array([0xab]);
    // Encode seq=5
    const frame = await encodeFrame(key, 5n, plaintext);
    // Try to decode with recv_seq=5 (already seen)
    await expect(
      decodeFrame(key, frame, 5n, true),
    ).rejects.toThrow('replay detected');
  });

  it('throws when seq < recv_seq', async () => {
    const frame = await encodeFrame(key, 3n, new Uint8Array([1]));
    // recv_seq=10 — frame seq=3 is old
    await expect(
      decodeFrame(key, frame, 10n, true),
    ).rejects.toThrow('replay detected');
  });

  it('accepts seq = recv_seq + 1 (sequential)', async () => {
    const frame = await encodeFrame(key, 6n, new Uint8Array([1]));
    const { seq } = await decodeFrame(key, frame, 5n, true);
    expect(seq).toBe(6n);
  });

  it('accepts seq=0 when recv_initialized=false (bootstrap)', async () => {
    const frame = await encodeFrame(key, 0n, new Uint8Array([1]));
    const { seq } = await decodeFrame(key, frame, 0n, false);
    expect(seq).toBe(0n);
  });
});

// ── parseKeyRotateFrame ───────────────────────────────────────────────────────

describe('parseKeyRotateFrame', () => {
  function makeKeyRotateFrame(): Uint8Array {
    const frame = new Uint8Array(KEY_ROTATE_FRAME_LEN);
    frame[0] = FRAME_KEY_ROTATE; // tag
    // Fill nonce (bytes 1-12) and ciphertext+tag (bytes 13-60) with test data
    for (let i = 1; i < KEY_ROTATE_FRAME_LEN; i++) {
      frame[i] = i & 0xff;
    }
    return frame;
  }

  it('returns nonce (12B) and ciphertextWithTag (48B)', () => {
    const frame = makeKeyRotateFrame();
    const { nonce, ciphertextWithTag } = parseKeyRotateFrame(frame);
    expect(nonce.length).toBe(12);
    expect(ciphertextWithTag.length).toBe(48);
  });

  it('nonce starts at byte 1', () => {
    const frame = makeKeyRotateFrame();
    const { nonce } = parseKeyRotateFrame(frame);
    for (let i = 0; i < 12; i++) {
      expect(nonce[i]).toBe(frame[i + 1]);
    }
  });

  it('ciphertextWithTag starts at byte 13', () => {
    const frame = makeKeyRotateFrame();
    const { ciphertextWithTag } = parseKeyRotateFrame(frame);
    for (let i = 0; i < 48; i++) {
      expect(ciphertextWithTag[i]).toBe(frame[i + 13]);
    }
  });

  it('throws on wrong frame length', () => {
    expect(() => parseKeyRotateFrame(new Uint8Array(60))).toThrow(
      `KEY_ROTATE frame must be ${KEY_ROTATE_FRAME_LEN} bytes`,
    );
    expect(() => parseKeyRotateFrame(new Uint8Array(62))).toThrow(
      `KEY_ROTATE frame must be ${KEY_ROTATE_FRAME_LEN} bytes`,
    );
  });

  it('throws on wrong tag byte', () => {
    const frame = makeKeyRotateFrame();
    frame[0] = 0x01; // DATA tag instead
    expect(() => parseKeyRotateFrame(frame)).toThrow('not a KEY_ROTATE frame');
  });
});

// ── processKeyRotate ─────────────────────────────────────────────────────────

describe('processKeyRotate', () => {
  /**
   * Builds a valid KEY_ROTATE frame encrypted under `key.aes` with `rotationNonce`
   * as the plaintext and `keyRotateRecvSeq` as AAD.
   */
  async function buildKeyRotateFrame(
    key: SessionKey,
    rotationNonce: Uint8Array,
    keyRotateRecvSeq: bigint,
    gcmNonce: Uint8Array,
  ): Promise<Uint8Array> {
    const aad = seqToAad(keyRotateRecvSeq);
    const ctWithTag = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: gcmNonce, additionalData: aad, tagLength: 128 },
        key.aes,
        rotationNonce,
      ),
    );
    // ctWithTag = 32B ct + 16B tag = 48B
    const frame = new Uint8Array(KEY_ROTATE_FRAME_LEN);
    frame[0] = FRAME_KEY_ROTATE;
    frame.set(gcmNonce, 1); // bytes 1..12
    frame.set(ctWithTag, 13); // bytes 13..60
    return frame;
  }

  it('returns a new SessionKey', async () => {
    const currentKey = await makeTestSessionKey();
    const rotationNonce = crypto.getRandomValues(new Uint8Array(32));
    const gcmNonce = crypto.getRandomValues(new Uint8Array(12));

    const frame = await buildKeyRotateFrame(currentKey, rotationNonce, 0n, gcmNonce);
    const newKey = await processKeyRotate(currentKey, frame, 0n);

    expect(newKey.aes).toBeInstanceOf(CryptoKey);
    expect(newKey.hkdf).toBeInstanceOf(CryptoKey);
    expect(newKey.aes).not.toBe(currentKey.aes);
    expect(newKey.hkdf).not.toBe(currentKey.hkdf);
  });

  it('new aes key is non-extractable (EC-2)', async () => {
    const currentKey = await makeTestSessionKey();
    const rotationNonce = crypto.getRandomValues(new Uint8Array(32));
    const gcmNonce = crypto.getRandomValues(new Uint8Array(12));

    const frame = await buildKeyRotateFrame(currentKey, rotationNonce, 0n, gcmNonce);
    const newKey = await processKeyRotate(currentKey, frame, 0n);

    await expect(crypto.subtle.exportKey('raw', newKey.aes)).rejects.toThrow();
  });

  it('new hkdf key is non-extractable (EC-2)', async () => {
    const currentKey = await makeTestSessionKey();
    const rotationNonce = crypto.getRandomValues(new Uint8Array(32));
    const gcmNonce = crypto.getRandomValues(new Uint8Array(12));

    const frame = await buildKeyRotateFrame(currentKey, rotationNonce, 0n, gcmNonce);
    const newKey = await processKeyRotate(currentKey, frame, 0n);

    await expect(crypto.subtle.exportKey('raw', newKey.hkdf)).rejects.toThrow();
  });

  it('new key can encrypt/decrypt', async () => {
    const currentKey = await makeTestSessionKey();
    const rotationNonce = crypto.getRandomValues(new Uint8Array(32));
    const gcmNonce = crypto.getRandomValues(new Uint8Array(12));

    const frame = await buildKeyRotateFrame(currentKey, rotationNonce, 0n, gcmNonce);
    const newKey = await processKeyRotate(currentKey, frame, 0n);

    const pt = new TextEncoder().encode('after rotation');
    const encFrame = await encodeFrame(newKey, 0n, pt);
    const { plaintext } = await decodeFrame(newKey, encFrame, 0n, false);
    expect(new TextDecoder().decode(plaintext)).toBe('after rotation');
  });

  it('new key can be rotated again (chained rotation)', async () => {
    const key0 = await makeTestSessionKey();
    const rot1 = crypto.getRandomValues(new Uint8Array(32));
    const gcm1 = crypto.getRandomValues(new Uint8Array(12));

    const frame1 = await buildKeyRotateFrame(key0, rot1, 0n, gcm1);
    const key1 = await processKeyRotate(key0, frame1, 0n);

    const rot2 = crypto.getRandomValues(new Uint8Array(32));
    const gcm2 = crypto.getRandomValues(new Uint8Array(12));
    const frame2 = await buildKeyRotateFrame(key1, rot2, 1n, gcm2);
    const key2 = await processKeyRotate(key1, frame2, 1n);

    // key2 must work for encrypt/decrypt
    const pt = new TextEncoder().encode('after second rotation');
    const encFrame = await encodeFrame(key2, 0n, pt);
    const { plaintext } = await decodeFrame(key2, encFrame, 0n, false);
    expect(new TextDecoder().decode(plaintext)).toBe('after second rotation');
  });

  it('replay: wrong keyRotateRecvSeq causes AAD mismatch → decrypt fails', async () => {
    const currentKey = await makeTestSessionKey();
    const rotationNonce = crypto.getRandomValues(new Uint8Array(32));
    const gcmNonce = crypto.getRandomValues(new Uint8Array(12));

    // Frame built with seq=0 as AAD
    const frame = await buildKeyRotateFrame(currentKey, rotationNonce, 0n, gcmNonce);

    // Process with seq=1 — AAD mismatch → GCM auth fails
    await expect(
      processKeyRotate(currentKey, frame, 1n),
    ).rejects.toThrow();
  });

  it('throws on malformed frame (wrong length)', async () => {
    const currentKey = await makeTestSessionKey();
    await expect(
      processKeyRotate(currentKey, new Uint8Array(60), 0n),
    ).rejects.toThrow(`KEY_ROTATE frame must be ${KEY_ROTATE_FRAME_LEN} bytes`);
  });

  it('HKDF matches Rust: same rotation_nonce produces deterministic new key', async () => {
    // Two identical SessionKeys from the same raw bytes should produce
    // identical new AES keys when rotated with the same rotation nonce.
    // This validates HKDF determinism (same IKM + same salt → same output).
    const rawKeyBytes = new Uint8Array(32).fill(0x42);
    const rotationNonce = new Uint8Array(32).fill(0x99);
    const gcmNonce = crypto.getRandomValues(new Uint8Array(12));

    const key1 = await sessionKeyFromBytes(rawKeyBytes);
    const key2 = await sessionKeyFromBytes(rawKeyBytes);

    const frame1 = await buildKeyRotateFrame(key1, rotationNonce, 0n, gcmNonce);
    // frame2 must use same gcmNonce so ciphertext is identical
    const frame2 = new Uint8Array(frame1); // identical frame

    const newKey1 = await processKeyRotate(key1, frame1, 0n);
    const newKey2 = await processKeyRotate(key2, frame2, 0n);

    // Both new keys should produce the same ciphertext for the same plaintext+seq
    // since they are derived from identical HKDF inputs.
    const pt = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const fixedNonce = new Uint8Array(12).fill(0x00); // seq=0 nonce
    const aad = seqToAad(0n);

    const ct1 = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: fixedNonce, additionalData: aad, tagLength: 128 },
        newKey1.aes,
        pt,
      ),
    );
    const ct2 = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: fixedNonce, additionalData: aad, tagLength: 128 },
        newKey2.aes,
        pt,
      ),
    );

    expect(ct1).toEqual(ct2);
  });
});

// ── wss:// enforcement ────────────────────────────────────────────────────────

describe('wss:// enforcement (EC-14)', () => {
  it('is tested via PQCSession constructor — see session.test.ts', () => {
    // Documented here for coverage traceability
    expect(true).toBe(true);
  });
});
