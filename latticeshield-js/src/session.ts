/**
 * session.ts — PQCSession class (main thread).
 *
 * Manages the WebSocket connection and Worker lifecycle.
 * ALL crypto runs inside the Worker — this class only coordinates I/O.
 *
 * Security invariant: the session CryptoKey and WASM memory NEVER exist in
 * this context. The main thread only sees plaintext data.
 */

import type {
  PQCSessionOptions,
  WorkerInMessage,
  WorkerOutMessage,
  SessionState,
} from './types.js';
import {
  SERVER_HELLO_SIGNED_LEN,
  CLIENT_RESPONSE_LEN,
  FRAME_KEY_ROTATE,
  SessionClosedError,
} from './types.js';

type EventMap = {
  message: (data: Uint8Array) => void;
  error: (err: Error) => void;
  close: () => void;
  keyrotate: () => void;
};

type PendingOp = {
  resolve: (value: Uint8Array) => void;
  reject: (reason: unknown) => void;
};

interface ResolvedOptions {
  bridgeUrl: string;
  serverVkBytes: Uint8Array;
  strict: boolean;
  workerUrl: string | undefined;
}

export class PQCSession {
  private readonly options: ResolvedOptions;

  // Private copy of the VK — never transferred; each handshake sends a fresh slice
  // (ADR-2: constructor stores _vkCopy; performHandshake sends _vkCopy.slice())
  private _vkCopy: Uint8Array;

  // Set to true synchronously inside close() BEFORE calling ws?.close(),
  // so the resulting 'close' WS event does not re-trigger the unexpected-close path (ADR-4)
  private _intentionalClose = false;

  // Stable bound references for WS event listeners — required so removeEventListener works (ADR-3)
  private readonly _onWsClose = this.handleWsClose.bind(this);
  private readonly _onWsError = this.handleWsError.bind(this);
  private readonly _boundOnFrameMessage = this.onFrameMessage.bind(this);

  private worker: Worker | null = null;
  private ws: WebSocket | null = null;
  private state: SessionState = 'idle';

  // Pending ops keyed by correlation ID
  private pendingEncrypt = new Map<string, PendingOp>();
  private pendingDecrypt = new Map<string, PendingOp>();

  // Send queue — drained during key rotation
  private sendQueue: Array<() => void> = [];
  private rotating = false;

  // Correlation ID counter
  private opIdCounter = 0;

  // Event listeners
  private listeners: { [K in keyof EventMap]?: Array<EventMap[K]> } = {};

  constructor(options: PQCSessionOptions) {
    // EC-14: enforce wss:// at construction time
    if (!options.bridgeUrl.startsWith('wss://')) {
      throw new Error(
        `latticeshield-js requires wss:// — got: ${options.bridgeUrl}`,
      );
    }

    this.options = {
      bridgeUrl: options.bridgeUrl,
      serverVkBytes: options.serverVkBytes,
      strict: options.strict ?? false,
      workerUrl: options.workerUrl,
    };

    // ADR-2: defensive copy so the original Uint8Array can never be detached by a caller
    this._vkCopy = options.serverVkBytes.slice();
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Opens the WebSocket, performs the PQC handshake, and resolves when the
   * session is ready to send/receive encrypted frames.
   *
   * May be called from state 'idle' or 'closed' (reconnect scenario).
   */
  async connect(): Promise<void> {
    // ADR: reset flag FIRST so any previous intentional close doesn't bleed into this connect
    this._intentionalClose = false;

    if (this.state !== 'idle' && this.state !== 'closed') {
      throw new Error(`connect() called in state "${this.state}"`);
    }

    this.state = 'connecting';

    try {
      this.worker = this.spawnWorker();
      await this.performHandshake();
      this.state = 'ready';
    } catch (err) {
      this.state = 'error';
      this.emit('error', err instanceof Error ? err : new Error(String(err)));
      if (this.options.strict) {
        throw err;
      }
    }
  }

  /**
   * Sends plaintext data through the encrypted channel.
   * Enqueues if a key rotation is in progress.
   */
  async send(data: Uint8Array): Promise<void> {
    if (this.state !== 'ready') {
      throw new Error(`send() called in state "${this.state}"`);
    }

    // If rotating, queue this send until rotation is complete
    if (this.rotating) {
      await new Promise<void>((resolve) => {
        this.sendQueue.push(resolve);
      });
    }

    return this.encryptAndSend(data);
  }

  /**
   * Returns the next decrypted message from the bridge.
   * This is an alternative to the 'message' event for sequential reads.
   */
  recv(): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      const handler = (data: Uint8Array): void => {
        this.off('message', handler);
        resolve(data);
      };
      const errHandler = (err: Error): void => {
        this.off('message', handler);
        reject(err);
      };
      this.on('message', handler);
      this.once('error', errHandler);
    });
  }

  /**
   * Closes the WebSocket and terminates the Worker.
   * Idempotent — calling close() on an already-closed session is a no-op.
   * Path C from design (ADR-4).
   */
  close(): void {
    if (this.state === 'closed') return; // idempotent

    // Set flag synchronously BEFORE ws?.close() so the resulting 'close' WS event
    // is recognised as intentional by handleWsClose (ADR-4)
    this._intentionalClose = true;
    this.state = 'closed';

    this.drainPending(new SessionClosedError());

    this.ws?.close(1000, 'client requested');
    this.worker?.terminate();

    this.ws?.removeEventListener('close', this._onWsClose);
    this.ws?.removeEventListener('error', this._onWsError);
    this.ws?.removeEventListener('message', this._boundOnFrameMessage);

    this.ws = null;
    this.worker = null;

    this.emit('close');
  }

  // ── Event emitter helpers ──────────────────────────────────────────────────

  on<K extends keyof EventMap>(event: K, handler: EventMap[K]): void {
    if (!this.listeners[event]) {
      this.listeners[event] = [];
    }
    (this.listeners[event] as Array<EventMap[K]>).push(handler);
  }

  off<K extends keyof EventMap>(event: K, handler: EventMap[K]): void {
    const handlers = this.listeners[event] as Array<EventMap[K]> | undefined;
    if (!handlers) return;
    const idx = handlers.indexOf(handler);
    if (idx !== -1) handlers.splice(idx, 1);
  }

  /** Register a one-shot listener. */
  once<K extends keyof EventMap>(event: K, handler: EventMap[K]): void {
    const wrapper = (...args: Parameters<EventMap[K]>): void => {
      this.off(event, wrapper as EventMap[K]);
      // @ts-expect-error — spread over union args
      handler(...args);
    };
    this.on(event, wrapper as EventMap[K]);
  }

  private emit<K extends keyof EventMap>(event: K, ...args: Parameters<EventMap[K]>): void {
    const handlers = this.listeners[event] as Array<EventMap[K]> | undefined;
    if (!handlers) return;
    for (const h of [...handlers]) {
      // @ts-expect-error — spread over union args
      h(...args);
    }
  }

  // ── Internal: Worker lifecycle ─────────────────────────────────────────────

  private spawnWorker(): Worker {
    const workerUrl =
      this.options.workerUrl ??
      new URL('./worker/crypto.worker.js', import.meta.url).href;

    const worker = new Worker(workerUrl, { type: 'module' });

    worker.addEventListener('message', (e: MessageEvent<WorkerOutMessage>) => {
      this.onWorkerMessage(e.data);
    });

    worker.addEventListener('error', (e: ErrorEvent) => {
      this.emit('error', new Error(`Worker error: ${e.message}`));
    });

    return worker;
  }

  private onWorkerMessage(msg: WorkerOutMessage): void {
    switch (msg.type) {
      case 'ENCRYPTED': {
        const op = this.pendingEncrypt.get(msg.id);
        if (op) {
          this.pendingEncrypt.delete(msg.id);
          op.resolve(msg.frame);
        }
        break;
      }

      case 'DECRYPTED': {
        const op = this.pendingDecrypt.get(msg.id);
        if (op) {
          this.pendingDecrypt.delete(msg.id);
          op.resolve(msg.plaintext);
        }
        this.emit('message', msg.plaintext);
        break;
      }

      case 'CRYPTO_ERR': {
        const encOp = this.pendingEncrypt.get(msg.id);
        const decOp = this.pendingDecrypt.get(msg.id);
        const err = new Error(msg.error);
        if (encOp) {
          this.pendingEncrypt.delete(msg.id);
          encOp.reject(err);
        } else if (decOp) {
          this.pendingDecrypt.delete(msg.id);
          decOp.reject(err);
        }
        this.emit('error', err);
        break;
      }

      case 'KEY_ROTATED': {
        this.rotating = false;
        // Drain the send queue
        const queue = this.sendQueue.splice(0);
        for (const resume of queue) resume();
        this.emit('keyrotate');
        break;
      }

      case 'KEY_ROTATE_ERR': {
        this.rotating = false;
        const err = new Error(`KEY_ROTATE failed: ${msg.error}`);
        this.emit('error', err);
        // Drain queue with rejection is not practical here — just resume
        // (caller will get errors on subsequent encrypts if key is corrupt)
        const queue = this.sendQueue.splice(0);
        for (const resume of queue) resume();
        break;
      }

      // INIT_OK / INIT_ERR handled inline in performHandshake()
      default:
        break;
    }
  }

  // ── Internal: Handshake ────────────────────────────────────────────────────

  private performHandshake(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.worker) {
        reject(new Error('Worker not spawned'));
        return;
      }

      const ws = new WebSocket(this.options.bridgeUrl);
      ws.binaryType = 'arraybuffer';
      this.ws = ws;

      const timeout = setTimeout(() => {
        ws.close();
        reject(new Error('handshake timeout'));
      }, 30_000);

      const onOpen = (): void => {
        // WebSocket opened — wait for server_hello_signed (4557B)
      };

      const onMessage = (e: MessageEvent): void => {
        const data = new Uint8Array(e.data as ArrayBuffer);

        if (data.length === SERVER_HELLO_SIGNED_LEN) {
          // Got server_hello_signed — send to Worker for WASM processing
          // ADR-2: send _vkCopy.slice() — fresh copy each time, _vkCopy stays intact
          const initMsg: WorkerInMessage = {
            type: 'INIT',
            serverHelloSigned: data,
            serverVkBytes: this._vkCopy.slice(),
          };
          this.worker!.postMessage(initMsg, [
            data.buffer,
            initMsg.serverVkBytes.buffer,
          ]);

          // One-shot listener for Worker INIT response
          const workerHandler = (we: MessageEvent<WorkerOutMessage>): void => {
            const wMsg = we.data;
            if (wMsg.type === 'INIT_OK') {
              this.worker!.removeEventListener('message', workerHandler);
              clearTimeout(timeout);

              // Send ClientResponse (1120B) to bridge
              if (wMsg.clientResponse.length !== CLIENT_RESPONSE_LEN) {
                ws.close();
                reject(
                  new Error(
                    `unexpected clientResponse length: ${wMsg.clientResponse.length}`,
                  ),
                );
                return;
              }
              ws.send(wMsg.clientResponse);

              // Handshake complete — remove handshake-scoped message/error/close listeners
              ws.removeEventListener('message', onMessage);
              ws.removeEventListener('error', onError);
              ws.removeEventListener('close', onClose);
              ws.removeEventListener('open', onOpen);

              // Install permanent post-handshake listeners (ADR-3: stable bound refs)
              ws.addEventListener('message', this._boundOnFrameMessage);
              ws.addEventListener('close', this._onWsClose);
              ws.addEventListener('error', this._onWsError);

              resolve();
            } else if (wMsg.type === 'INIT_ERR') {
              this.worker!.removeEventListener('message', workerHandler);
              clearTimeout(timeout);
              ws.close();
              reject(new Error(wMsg.error));
            }
          };

          this.worker!.addEventListener('message', workerHandler);
        } else {
          clearTimeout(timeout);
          ws.close();
          reject(
            new Error(
              `unexpected message during handshake: expected ${SERVER_HELLO_SIGNED_LEN} bytes, got ${data.length}`,
            ),
          );
        }
      };

      const onError = (): void => {
        clearTimeout(timeout);
        reject(new Error('WebSocket error during handshake'));
      };

      const onClose = (): void => {
        clearTimeout(timeout);
        reject(new Error('WebSocket closed during handshake'));
      };

      ws.addEventListener('open', onOpen);
      ws.addEventListener('message', onMessage);
      ws.addEventListener('error', onError);
      ws.addEventListener('close', onClose);
    });
  }

  // ── Internal: Unexpected close handler (Path B, ADR-4) ────────────────────

  /**
   * Handles an unexpected WebSocket 'close' event (network drop, bridge crash).
   * Strict order per ADR-4: state → drain → terminate → cleanup → null → emit.
   */
  private handleWsClose(_ev: CloseEvent): void {
    if (this.state === 'closed') return;    // guard #1: already closed (idempotence)
    if (this._intentionalClose) return;    // guard #2: close() is in flight; it owns cleanup

    this.state = 'closed';                               // (1) block new public ops
    this.drainPending(new SessionClosedError());         // (2) reject in-flight promises

    this.worker?.terminate();                            // (3) destroy key material

    const ws = this.ws;
    if (ws) {
      ws.removeEventListener('close', this._onWsClose);
      ws.removeEventListener('error', this._onWsError);
      ws.removeEventListener('message', this._boundOnFrameMessage);
    }

    this.ws = null;                                      // (4) nullify refs
    this.worker = null;

    this.emit('close');                                  // (5) last — triggers hook reconnect
  }

  /**
   * Handles a WebSocket 'error' event post-handshake.
   * Only forwards to the session's error bus — cleanup is handled by the
   * following 'close' event which always fires after 'error'.
   */
  private handleWsError(_ev: Event): void {
    // Do not emit if already closed — avoid spurious errors after intentional close
    if (this.state !== 'closed') {
      this.emit('error', new Error('WebSocket error'));
    }
  }

  // ── Internal: Drain helper (ADR-4) ────────────────────────────────────────

  /**
   * Rejects all pending encrypt and decrypt operations with the given error,
   * clears both Maps, and resumes any sendQueue waiters (which will then fail
   * the subsequent state guard in send()/encryptAndSend()).
   */
  private drainPending(err: Error): void {
    for (const op of this.pendingEncrypt.values()) op.reject(err);
    for (const op of this.pendingDecrypt.values()) op.reject(err);
    this.pendingEncrypt.clear();
    this.pendingDecrypt.clear();
    // sendQueue contains resume() continuations from send() waiting on key rotation.
    // Resuming them with state='closed' causes send()/encryptAndSend() to throw early.
    const queue = this.sendQueue.splice(0);
    for (const resume of queue) resume();
  }

  // ── Internal: Frame routing ────────────────────────────────────────────────

  private onFrameMessage(e: MessageEvent): void {
    const data = new Uint8Array(e.data as ArrayBuffer);

    if (data.length === 0) return;

    const tag = data[0];

    if (tag === FRAME_KEY_ROTATE) {
      // KEY_ROTATE: pause sends, dispatch to Worker
      this.rotating = true;
      const rotMsg: WorkerInMessage = { type: 'KEY_ROTATE', frame: data };
      this.worker?.postMessage(rotMsg, [data.buffer]);
    } else {
      // DATA frame: dispatch to Worker for decryption
      const id = this.nextOpId();
      return void new Promise<Uint8Array>((resolve, reject) => {
        this.pendingDecrypt.set(id, { resolve, reject });
        const decMsg: WorkerInMessage = { type: 'DECRYPT', id, ciphertext: data };
        this.worker?.postMessage(decMsg, [data.buffer]);
      });
    }
  }

  private async encryptAndSend(data: Uint8Array): Promise<void> {
    const id = this.nextOpId();

    const frame = await new Promise<Uint8Array>((resolve, reject) => {
      this.pendingEncrypt.set(id, { resolve, reject });
      const encMsg: WorkerInMessage = { type: 'ENCRYPT', id, plaintext: data };
      this.worker?.postMessage(encMsg, [data.buffer]);
    });

    this.ws?.send(frame);
  }

  private nextOpId(): string {
    return `op-${this.opIdCounter++}`;
  }
}
