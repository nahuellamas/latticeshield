/**
 * crypto.worker.ts — Web Worker entry point.
 *
 * ALL PQC and symmetric crypto runs inside this Worker (EC-10).
 * The main thread communicates ONLY via postMessage — no CryptoKey or
 * WASM linear memory ever crosses the Worker boundary.
 *
 * State held exclusively in this Worker:
 *   - WASM module instance
 *   - sessionKey: non-extractable CryptoKey
 *   - send_seq, recv_seq, key_rotate_recv_seq: BigInt counters
 *
 * Message protocol:
 *   Main → Worker: WorkerInMessage
 *   Worker → Main: WorkerOutMessage
 */

// NOTE: The WASM module path is resolved at build time (bundler replaces it).
// When the WASM pkg is not yet present the import is mocked for testing.
import type { WorkerInMessage, WorkerOutMessage } from '../types.js';
import type { SessionKey } from '../framing.js';
import {
  encodeFrame,
  decodeFrame,
  importSessionKey,
  processKeyRotate,
  seqToNonce,
} from '../framing.js';
import {
  FRAME_KEY_ROTATE,
  SERVER_HELLO_SIGNED_LEN,
  CLIENT_RESPONSE_LEN,
} from '../types.js';

// ── Worker state ─────────────────────────────────────────────────────────────

let sessionKey: SessionKey | null = null;
let sendSeq: bigint = 0n;
let recvSeq: bigint = 0n;
let recvInitialized: boolean = false;
let keyRotateRecvSeq: bigint = 0n;

// ── WASM loader (lazy, runs once) ─────────────────────────────────────────────

let wasmInit: (() => Promise<void>) | null = null;
let wasmGenerateClientResponse:
  | ((serverHelloSigned: Uint8Array, serverVkBytes: Uint8Array) => {
      client_response: Uint8Array;
      session_key: Uint8Array;
    })
  | null = null;

async function ensureWasm(): Promise<void> {
  if (wasmGenerateClientResponse !== null) return;

  // Dynamic import — the bundler (Vite) will resolve the WASM pkg path.
  // In test environments this is mocked via vitest/jest module mocking.
  try {
    const wasm = await import(
      /* @vite-ignore */
      'latticeshield-wasm'
    );
    if (typeof wasm.default === 'function') {
      await wasm.default(); // call the async init()
    }
    wasmGenerateClientResponse = wasm.wasm_generate_client_response;
  } catch (e) {
    throw new Error(
      `latticeshield-wasm not available: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
}

// ── Message handler ───────────────────────────────────────────────────────────

function post(msg: WorkerOutMessage): void {
  // Transfer ownership of Uint8Array buffers where possible to avoid copy
  const transferable: Transferable[] = [];

  if (msg.type === 'INIT_OK') {
    transferable.push(msg.clientResponse.buffer);
  } else if (msg.type === 'ENCRYPTED') {
    transferable.push(msg.frame.buffer);
  } else if (msg.type === 'DECRYPTED') {
    transferable.push(msg.plaintext.buffer);
  }

  // @ts-expect-error — postMessage is available in Worker global scope
  self.postMessage(msg, transferable);
}

self.addEventListener('message', (event: MessageEvent<WorkerInMessage>) => {
  const msg = event.data;

  switch (msg.type) {
    case 'INIT':
      handleInit(msg.serverHelloSigned, msg.serverVkBytes);
      break;

    case 'ENCRYPT':
      handleEncrypt(msg.id, msg.plaintext);
      break;

    case 'DECRYPT':
      handleDecrypt(msg.id, msg.ciphertext);
      break;

    case 'KEY_ROTATE':
      handleKeyRotate(msg.frame);
      break;

    default:
      // Unknown message type — ignore
      break;
  }
});

// ── INIT handler ─────────────────────────────────────────────────────────────

async function handleInit(
  serverHelloSigned: Uint8Array,
  serverVkBytes: Uint8Array,
): Promise<void> {
  try {
    await ensureWasm();

    if (serverHelloSigned.length !== SERVER_HELLO_SIGNED_LEN) {
      throw new Error(
        `serverHelloSigned must be ${SERVER_HELLO_SIGNED_LEN} bytes, got ${serverHelloSigned.length}`,
      );
    }

    const result = wasmGenerateClientResponse!(serverHelloSigned, serverVkBytes);

    // Import session key as non-extractable — zeroizes raw bytes (EC-2, EC-3)
    sessionKey = await importSessionKey(new Uint8Array(result.session_key));

    // Reset counters for fresh session
    sendSeq = 0n;
    recvSeq = 0n;
    recvInitialized = false;
    keyRotateRecvSeq = 0n;

    const clientResponse = new Uint8Array(result.client_response);

    if (clientResponse.length !== CLIENT_RESPONSE_LEN) {
      throw new Error(
        `WASM returned invalid client_response: expected ${CLIENT_RESPONSE_LEN} bytes, got ${clientResponse.length}`,
      );
    }

    post({ type: 'INIT_OK', clientResponse });
  } catch (e) {
    post({
      type: 'INIT_ERR',
      error: e instanceof Error ? e.message : String(e),
    });
  }
}

// ── ENCRYPT handler ───────────────────────────────────────────────────────────

async function handleEncrypt(id: string, plaintext: Uint8Array): Promise<void> {
  if (sessionKey === null) {
    post({ type: 'CRYPTO_ERR', id, error: 'session not initialized' });
    return;
  }

  try {
    const frame = await encodeFrame(sessionKey, sendSeq, plaintext);
    sendSeq += 1n;
    post({ type: 'ENCRYPTED', id, frame });
  } catch (e) {
    post({
      type: 'CRYPTO_ERR',
      id,
      error: e instanceof Error ? e.message : String(e),
    });
  }
}

// ── DECRYPT handler ───────────────────────────────────────────────────────────

async function handleDecrypt(id: string, ciphertext: Uint8Array): Promise<void> {
  if (sessionKey === null) {
    post({ type: 'CRYPTO_ERR', id, error: 'session not initialized' });
    return;
  }

  try {
    // Detect KEY_ROTATE frames routed here by mistake
    if (ciphertext.length > 0 && ciphertext[0] === FRAME_KEY_ROTATE) {
      post({
        type: 'CRYPTO_ERR',
        id,
        error: 'KEY_ROTATE frame must be handled via KEY_ROTATE message type',
      });
      return;
    }

    const { plaintext, seq } = await decodeFrame(
      sessionKey,
      ciphertext,
      recvSeq,
      recvInitialized,
    );

    recvSeq = seq;
    recvInitialized = true;

    post({ type: 'DECRYPTED', id, plaintext });
  } catch (e) {
    post({
      type: 'CRYPTO_ERR',
      id,
      error: e instanceof Error ? e.message : String(e),
    });
  }
}

// ── KEY_ROTATE handler ────────────────────────────────────────────────────────

async function handleKeyRotate(frame: Uint8Array): Promise<void> {
  if (sessionKey === null) {
    post({ type: 'KEY_ROTATE_ERR', error: 'session not initialized' });
    return;
  }

  try {
    const newKey = await processKeyRotate(sessionKey, frame, keyRotateRecvSeq);

    // Atomically replace session key
    sessionKey = newKey;

    // Reset per-epoch counters (EC-3)
    sendSeq = 0n;
    recvSeq = 0n;
    recvInitialized = false;
    keyRotateRecvSeq += 1n;

    post({ type: 'KEY_ROTATED' });
  } catch (e) {
    post({
      type: 'KEY_ROTATE_ERR',
      error: e instanceof Error ? e.message : String(e),
    });
  }
}

// Expose internal helpers for testing (only when not in production Worker)
export { handleInit, handleEncrypt, handleDecrypt, handleKeyRotate };
