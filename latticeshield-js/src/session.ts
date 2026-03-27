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
import { SERVER_HELLO_SIGNED_LEN, CLIENT_RESPONSE_LEN, FRAME_KEY_ROTATE } from './types.js';

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
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Opens the WebSocket, performs the PQC handshake, and resolves when the
   * session is ready to send/receive encrypted frames.
   */
  async connect(): Promise<void> {
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

  /** Closes the WebSocket and terminates the Worker. */
  close(): void {
    this.state = 'closed';
    this.ws?.close();
    this.worker?.terminate();
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
          const initMsg: WorkerInMessage = {
            type: 'INIT',
            serverHelloSigned: data,
            serverVkBytes: this.options.serverVkBytes,
          };
          this.worker!.postMessage(initMsg, [
            data.buffer,
            this.options.serverVkBytes.buffer,
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

              // Handshake complete — install ongoing frame handler
              ws.removeEventListener('message', onMessage);
              ws.addEventListener('message', this.onFrameMessage.bind(this));

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
