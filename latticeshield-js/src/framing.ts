/**
 * framing.ts — Wire framing v3 encode/decode for latticeshield-js.
 *
 * Reimplements `latticeshield-crypto/src/channel.rs` in TypeScript using
 * `crypto.subtle` (AES-256-GCM) and BigInt for u64 sequence counters.
 *
 * DATA frame layout (sent/received per frame):
 *   [0x01][4B u32 BE len][8B u64 BE seq][12B nonce][ciphertext][16B GCM tag]
 *
 *   - len     = ciphertext.length + 16 (tag is included in the count)
 *   - seq     = monotonically increasing BigInt counter
 *   - nonce   = deterministic: seq padded to 12B (EC-7)
 *               layout: [0x00 0x00 0x00 0x00][seq as 8B BE]
 *   - AAD     = seq as 8B BE (authenticated but not encrypted)
 *
 * KEY_ROTATE frame layout (61 bytes total):
 *   [0x02][12B GCM nonce][32B encrypted rotation nonce][16B GCM tag]
 *   - AAD = key_rotate_recv_seq as 8B BE
 */

import { FRAME_DATA, FRAME_KEY_ROTATE, KEY_ROTATE_FRAME_LEN } from "./types";

// ── u64 range constant ────────────────────────────────────────────────────────

/** Maximum value of a u64: 2^64 - 1. Used for overflow guards in seqToNonce/seqToAad. */
export const MAX_U64 = (1n << 64n) - 1n;

// ── Session key type ──────────────────────────────────────────────────────────

/**
 * A session key pair: one AES-GCM key for encrypt/decrypt, and a companion
 * HKDF key imported from the same raw bytes for key derivation during rotation.
 *
 * Web Crypto requires the baseKey for HKDF.deriveKey to have algorithm.name
 * === 'HKDF'. Since an AES-GCM CryptoKey cannot be used as HKDF base material,
 * we import the same 32 raw bytes twice — once as AES-GCM, once as HKDF.
 * Both are non-extractable (EC-2). The raw bytes are zeroized after import.
 */
export interface SessionKey {
  /** AES-256-GCM key for encodeFrame / decodeFrame. Non-extractable. */
  aes: CryptoKey;
  /**
   * HKDF base key for key derivation during KEY_ROTATE. Non-extractable.
   * Algorithm: HKDF. keyUsages: ['deriveKey'].
   */
  hkdf: CryptoKey;
}

// ── Nonce helpers ─────────────────────────────────────────────────────────────

/**
 * Derives a deterministic 12-byte AES-GCM nonce from a u64 sequence number.
 *
 * Layout: [seq as 8B big-endian (bytes 0-7)][0x00 0x00 0x00 0x00 (epoch=0, bytes 8-11)]
 *
 * Matches the Rust EncryptedChannel wire format: nonce[0..8] = seq_be, nonce[8..12] = epoch_be.
 * epoch is always 0 on session start; the JS SDK does not track epoch across KEY_ROTATE.
 * This matches EC-7 (deterministic nonce derived from seq) and avoids the
 * birthday problem that random nonces would introduce with AES-GCM.
 */
export function seqToNonce(seq: bigint): Uint8Array {
  if (seq < 0n || seq > MAX_U64) {
    throw new RangeError(`seq out of u64 range: ${seq}`);
  }
  const nonce = new Uint8Array(12);
  const view = new DataView(nonce.buffer);
  // Bytes 0-7: seq as 8B big-endian (matches Rust nonce layout)
  view.setBigUint64(0, seq, false);
  return nonce;
}

/**
 * Encodes seq as an 8-byte big-endian Uint8Array — used as AEAD AAD.
 */
export function seqToAad(seq: bigint): Uint8Array {
  if (seq < 0n || seq > MAX_U64) {
    throw new RangeError(`seq out of u64 range: ${seq}`);
  }
  const aad = new Uint8Array(8);
  const view = new DataView(aad.buffer);
  view.setBigUint64(0, seq, false);
  return aad;
}

// ── DATA frame encode ─────────────────────────────────────────────────────────

/**
 * Encrypts `plaintext` with AES-256-GCM and encodes it as a v3 DATA frame.
 *
 * The caller is responsible for incrementing `send_seq` after each call.
 *
 * @param key       SessionKey (uses key.aes for encryption)
 * @param seq       Current send sequence number (BigInt)
 * @param plaintext Plaintext bytes to encrypt
 * @returns Full wire frame: [0x01][4B len][8B seq][12B nonce][ct+16B tag]
 */
export async function encodeFrame(
  key: SessionKey,
  seq: bigint,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const nonce = seqToNonce(seq);
  const aad = seqToAad(seq);

  // AES-256-GCM: returns ciphertext || 16B tag as a single buffer
  // Cast to Uint8Array<ArrayBuffer> — crypto.subtle expects ArrayBuffer-backed views
  const ctWithTag = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce as Uint8Array<ArrayBuffer>,
        additionalData: aad as Uint8Array<ArrayBuffer>,
        tagLength: 128,
      },
      key.aes,
      plaintext as Uint8Array<ArrayBuffer>,
    ),
  );

  // len field = ciphertext_len + tag_len (16) — tag is part of ctWithTag
  const len = ctWithTag.length; // already includes 16B tag from AES-GCM

  // Frame layout: tag(1) + len(4) + seq(8) + nonce(12) + ct+tag
  const frame = new Uint8Array(1 + 4 + 8 + 12 + ctWithTag.length);
  const view = new DataView(frame.buffer);

  let offset = 0;
  frame[offset] = FRAME_DATA;
  offset += 1;

  view.setUint32(offset, len, false); // big-endian u32
  offset += 4;

  view.setBigUint64(offset, seq, false); // big-endian u64
  offset += 8;

  frame.set(nonce, offset);
  offset += 12;

  frame.set(ctWithTag, offset);

  return frame;
}

// ── DATA frame decode ─────────────────────────────────────────────────────────

/**
 * Decodes and decrypts a v3 DATA frame.
 *
 * Validates:
 *   - Tag byte is 0x01
 *   - Frame is large enough to contain the declared payload
 *   - seq > recv_seq (replay protection — throws on violation)
 *
 * @param key       SessionKey (uses key.aes for decryption)
 * @param buf       Raw wire bytes (exactly one frame)
 * @param recvSeq   Current recv_seq counter value
 * @param recvInitialized  Whether any frame has been received yet (false = bootstrap)
 * @returns { plaintext, seq } — caller updates recv_seq to seq
 */
export async function decodeFrame(
  key: SessionKey,
  buf: Uint8Array,
  recvSeq: bigint,
  recvInitialized: boolean,
): Promise<{ plaintext: Uint8Array; seq: bigint }> {
  if (buf.length < 1 + 4 + 8 + 12) {
    throw new Error(`frame too short: ${buf.length} bytes`);
  }

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let offset = 0;

  const tag = buf[offset];
  offset += 1;

  if (tag !== FRAME_DATA) {
    throw new Error(`unexpected frame tag: 0x${tag?.toString(16) ?? "??"}`);
  }

  const len = view.getUint32(offset, false); // big-endian u32
  offset += 4;

  const seq = view.getBigUint64(offset, false); // big-endian u64
  offset += 8;

  const nonce = buf.slice(offset, offset + 12);
  offset += 12;

  // Minimum frame total: 1 + 4 + 8 + 12 + len bytes after the header
  const expectedTotal = 1 + 4 + 8 + 12 + len;
  if (buf.length < expectedTotal) {
    throw new Error(
      `frame body truncated: expected ${expectedTotal} bytes, got ${buf.length}`,
    );
  }

  const ctWithTag = buf.slice(offset, offset + len);

  // Replay check: seq must be strictly monotonically increasing
  if (recvInitialized && seq <= recvSeq) {
    throw new Error(
      `replay detected: received seq=${seq}, expected >${recvSeq}`,
    );
  }

  // Verify nonce matches deterministic derivation (EC-7)
  const expectedNonce = seqToNonce(seq);
  for (let i = 0; i < 12; i++) {
    if (nonce[i] !== expectedNonce[i]) {
      throw new Error(
        `nonce mismatch at byte ${i}: frame nonce does not match seq-derived nonce`,
      );
    }
  }

  const aad = seqToAad(seq);

  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce as Uint8Array<ArrayBuffer>,
        additionalData: aad as Uint8Array<ArrayBuffer>,
        tagLength: 128,
      },
      key.aes,
      ctWithTag as Uint8Array<ArrayBuffer>,
    ),
  );

  return { plaintext, seq };
}

// ── KEY_ROTATE frame parse ────────────────────────────────────────────────────

/**
 * Parses the header of a KEY_ROTATE frame without decrypting.
 *
 * KEY_ROTATE wire format (61 bytes):
 *   [0x02][12B GCM nonce][32B encrypted rotation nonce][16B GCM tag]
 *
 * @param buf  Raw wire bytes (must be exactly KEY_ROTATE_FRAME_LEN = 61 bytes)
 * @returns { nonce: Uint8Array(12), ciphertextWithTag: Uint8Array(48) }
 */
export function parseKeyRotateFrame(buf: Uint8Array): {
  nonce: Uint8Array;
  ciphertextWithTag: Uint8Array;
} {
  if (buf.length !== KEY_ROTATE_FRAME_LEN) {
    throw new Error(
      `KEY_ROTATE frame must be ${KEY_ROTATE_FRAME_LEN} bytes, got ${buf.length}`,
    );
  }

  if (buf[0] !== FRAME_KEY_ROTATE) {
    throw new Error(
      `not a KEY_ROTATE frame: tag=0x${buf[0]?.toString(16) ?? "??"}`,
    );
  }

  const nonce = buf.slice(1, 13); // 12 bytes
  const ciphertextWithTag = buf.slice(13, 61); // 32B ct + 16B tag = 48B

  return { nonce, ciphertextWithTag };
}

// ── KEY_ROTATE processing ─────────────────────────────────────────────────────

/**
 * Processes a KEY_ROTATE frame: decrypts the rotation nonce, then derives
 * the new session key via HKDF-SHA256.
 *
 * AAD = key_rotate_recv_seq as 8B BE (EC-8 compliance).
 *
 * HKDF parameters match Rust channel.rs rotate_key() exactly:
 *   Hkdf::<Sha256>::new(Some(rotation_nonce), self.key_bytes.as_ref())
 *   i.e. IKM = current_key_bytes, salt = rotation_nonce (32B)
 *        info = "latticeshield-v1-key-rotation"
 *
 * Web Crypto requires the HKDF base key to have algorithm.name === 'HKDF'.
 * We use currentKey.hkdf (imported from the same raw bytes as currentKey.aes
 * at session init) as base material — the raw bytes are never exposed (EC-2).
 *
 * After this function returns the new SessionKey, the caller MUST:
 *   - Replace the session key reference
 *   - Reset send_seq = 0n, recv_seq = 0n, recv_initialized = false
 *   - Increment key_rotate_recv_seq
 *
 * @param currentKey        Current SessionKey (uses currentKey.aes to decrypt, currentKey.hkdf for derivation)
 * @param frame             Raw KEY_ROTATE frame bytes (61B)
 * @param keyRotateRecvSeq  Current key_rotate_recv_seq counter
 * @returns New SessionKey
 */
export async function processKeyRotate(
  currentKey: SessionKey,
  frame: Uint8Array,
  keyRotateRecvSeq: bigint,
): Promise<SessionKey> {
  const { nonce, ciphertextWithTag } = parseKeyRotateFrame(frame);

  // AAD = key_rotate_recv_seq as 8B BE
  const aad = seqToAad(keyRotateRecvSeq);

  // Decrypt the rotation nonce with the current AES-GCM session key
  const rotationNonceBytes = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce as Uint8Array<ArrayBuffer>,
        additionalData: aad as Uint8Array<ArrayBuffer>,
        tagLength: 128,
      },
      currentKey.aes,
      ciphertextWithTag as Uint8Array<ArrayBuffer>,
    ),
  );

  if (rotationNonceBytes.length !== 32) {
    throw new Error(
      `rotation nonce must be 32 bytes, got ${rotationNonceBytes.length}`,
    );
  }

  // Derive new AES-256-GCM key via HKDF-SHA256.
  //
  // Matches Rust rotate_key() exactly:
  //   HKDF(ikm=current_key_bytes, salt=rotation_nonce, info="latticeshield-v1-key-rotation")
  //
  // currentKey.hkdf is a non-extractable CryptoKey with algorithm.name='HKDF'
  // imported from the same raw bytes as currentKey.aes — this lets Web Crypto
  // use the session key as HKDF IKM without ever exposing the raw bytes (EC-2).
  const info = new TextEncoder().encode("latticeshield-v1-key-rotation");
  const newAesKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: rotationNonceBytes as Uint8Array<ArrayBuffer>,
      info: info as Uint8Array<ArrayBuffer>,
    },
    currentKey.hkdf,
    { name: "AES-GCM", length: 256 },
    false, // non-extractable (EC-2)
    ["encrypt", "decrypt"],
  );

  // Derive the companion HKDF key for the new session key (needed for future rotations).
  // We derive 32B of HKDF output as raw bytes, then immediately import as HKDF key.
  // This mirrors the raw bytes that would have been the new AES key material.
  const newKeyRaw = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: rotationNonceBytes as Uint8Array<ArrayBuffer>,
        info: info as Uint8Array<ArrayBuffer>,
      },
      currentKey.hkdf,
      256, // 32 bytes
    ),
  );

  const newHkdfKey = await crypto.subtle.importKey(
    "raw",
    newKeyRaw as Uint8Array<ArrayBuffer>,
    { name: "HKDF" },
    false, // non-extractable (EC-2)
    ["deriveKey", "deriveBits"],
  );

  // Zeroize derived raw bytes and rotation nonce
  newKeyRaw.fill(0);
  rotationNonceBytes.fill(0);

  return { aes: newAesKey, hkdf: newHkdfKey };
}

// ── Session key import ────────────────────────────────────────────────────────

/**
 * Imports raw session key bytes as a non-extractable SessionKey pair.
 *
 * Imports the same 32 bytes twice:
 *   - As AES-256-GCM (for encrypt/decrypt in encodeFrame/decodeFrame)
 *   - As HKDF base key (for key derivation in processKeyRotate)
 *
 * Both keys are non-extractable (EC-2). The input buffer is zeroized
 * immediately after import (EC-3).
 *
 * @param keyBytes  32-byte session key from WASM handshake
 * @returns Non-extractable SessionKey
 */
export async function importSessionKey(
  keyBytes: Uint8Array,
): Promise<SessionKey> {
  if (keyBytes.length !== 32) {
    throw new Error(`session key must be 32 bytes, got ${keyBytes.length}`);
  }

  const [aes, hkdf] = await Promise.all([
    crypto.subtle.importKey(
      "raw",
      keyBytes as Uint8Array<ArrayBuffer>,
      { name: "AES-GCM", length: 256 },
      false, // non-extractable (EC-2)
      ["encrypt", "decrypt"],
    ),
    crypto.subtle.importKey(
      "raw",
      keyBytes as Uint8Array<ArrayBuffer>,
      { name: "HKDF" },
      false, // non-extractable (EC-2)
      ["deriveKey", "deriveBits"],
    ),
  ]);

  // Zeroize the raw bytes immediately after import (EC-3)
  keyBytes.fill(0);

  return { aes, hkdf };
}
