// ── Shared TypeScript types for latticeshield-js ─────────────────────────────

export type SessionState = 'idle' | 'connecting' | 'ready' | 'error' | 'closed';

export type PQCSessionStatus = SessionState;

export interface PQCSessionOptions {
  /** WebSocket URL to the bridge — MUST start with wss:// (EC-14) */
  bridgeUrl: string;
  /** Pre-shared ML-DSA-65 verifying key bytes (1952B) — pinned at build time (EC-1) */
  serverVkBytes: Uint8Array;
  /** If true, reject with an error instead of silently degrading (EC-4, default: false) */
  strict?: boolean;
  /**
   * URL to the Web Worker bundle.
   * Defaults to resolving the built-in worker at runtime.
   */
  workerUrl?: string;
}

// ── Worker message protocol (main thread → Worker) ────────────────────────────

export type WorkerInMessage =
  | { type: 'INIT'; serverHelloSigned: Uint8Array; serverVkBytes: Uint8Array }
  | { type: 'ENCRYPT'; id: string; plaintext: Uint8Array }
  | { type: 'DECRYPT'; id: string; ciphertext: Uint8Array }
  | { type: 'KEY_ROTATE'; frame: Uint8Array };

// ── Worker message protocol (Worker → main thread) ────────────────────────────

export type WorkerOutMessage =
  | { type: 'INIT_OK'; clientResponse: Uint8Array }
  | { type: 'INIT_ERR'; error: string }
  | { type: 'ENCRYPTED'; id: string; frame: Uint8Array }
  | { type: 'DECRYPTED'; id: string; plaintext: Uint8Array }
  | { type: 'CRYPTO_ERR'; id: string; error: string }
  | { type: 'KEY_ROTATED' }
  | { type: 'KEY_ROTATE_ERR'; error: string };

// ── Wire format constants (match latticeshield-crypto/src/channel.rs) ─────────

/** DATA frame tag byte */
export const FRAME_DATA = 0x01 as const;
/** KEY_ROTATE frame tag byte */
export const FRAME_KEY_ROTATE = 0x02 as const;
/** Size of a signed ServerHello from the bridge (bytes) */
export const SERVER_HELLO_SIGNED_LEN = 4557 as const;
/** Size of a ClientResponse sent to the bridge (bytes) */
export const CLIENT_RESPONSE_LEN = 1120 as const;
/** Size of a KEY_ROTATE frame (bytes): tag(1) + nonce(12) + enc_nonce(32) + tag(16) */
export const KEY_ROTATE_FRAME_LEN = 61 as const;
/** Size of a pre-shared ML-DSA-65 verifying key (bytes) */
export const VERIFYING_KEY_LEN = 1952 as const;

// ── Error classes ─────────────────────────────────────────────────────────────

/**
 * Thrown / rejected when an operation is attempted on a closed PQCSession,
 * or when in-flight operations are drained on unexpected close.
 * Use `err instanceof SessionClosedError` or `err.code === 'SESSION_CLOSED'` to discriminate.
 */
export class SessionClosedError extends Error {
  readonly code = 'SESSION_CLOSED' as const;
  constructor(message = 'PQCSession closed') {
    super(message);
    this.name = 'SessionClosedError';
  }
}
