/**
 * usePQCSession.ts — React hook for PQCSession.
 *
 * Manages the PQCSession lifecycle (connect on mount, close on unmount).
 * Implements exponential backoff reconnect (max 3 attempts, default).
 *
 * NOTE: This file uses React. It must be imported only in React applications.
 * The react peer dependency is optional — non-React callers use PQCSession directly.
 */

// We use a dynamic conditional import pattern so this module can be
// tree-shaken in non-React environments.
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore — react is an optional peer dependency; callers must install it
import { useCallback, useEffect, useRef, useState } from 'react';

import { PQCSession } from '../session.js';
import type { PQCSessionStatus, PQCSessionOptions } from '../types.js';

export interface UsePQCSessionOptions {
  /** WebSocket URL — must start with wss:// */
  bridgeUrl: string;
  /** Pre-shared ML-DSA-65 verifying key bytes (1952B, EC-1) */
  serverVkBytes: Uint8Array;
  /** If true, reject instead of silently failing (EC-4, default: false) */
  strict?: boolean;
  /** Automatically connect on mount (default: true) */
  autoConnect?: boolean;
  /** URL to the Worker bundle (optional — uses default build output) */
  workerUrl?: string;
  /** Maximum reconnect attempts before giving up (default: 3) */
  maxReconnectAttempts?: number;
}

export interface UsePQCSessionResult {
  status: PQCSessionStatus;
  send: (data: Uint8Array) => Promise<void>;
  lastMessage: Uint8Array | null;
  error: Error | null;
  connect: () => void;
  disconnect: () => void;
}

export function usePQCSession(options: UsePQCSessionOptions): UsePQCSessionResult {
  const {
    bridgeUrl,
    serverVkBytes,
    strict = false,
    autoConnect = true,
    workerUrl,
    maxReconnectAttempts = 3,
  } = options;

  const [status, setStatus] = useState<PQCSessionStatus>('idle');
  const [lastMessage, setLastMessage] = useState<Uint8Array | null>(null);
  const [error, setError] = useState<Error | null>(null);

  const sessionRef = useRef<PQCSession | null>(null);
  const reconnectAttempts = useRef(0);
  const isMounted = useRef(true);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearReconnectTimer = (): void => {
    if (reconnectTimerRef.current !== null) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
  };

  const doConnect = useCallback((): void => {
    if (!isMounted.current) return;

    // Close any existing session
    sessionRef.current?.close();
    sessionRef.current = null;

    setStatus('connecting');
    setError(null);

    let session: PQCSession;
    try {
      // Build options object — omit workerUrl if undefined (exactOptionalPropertyTypes)
      const sessionOpts: PQCSessionOptions = workerUrl !== undefined
        ? { bridgeUrl, serverVkBytes, strict, workerUrl }
        : { bridgeUrl, serverVkBytes, strict };
      session = new PQCSession(sessionOpts);
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      setStatus('error');
      setError(err);
      return;
    }

    sessionRef.current = session;

    session.on('message', (data) => {
      if (isMounted.current) setLastMessage(data);
    });

    session.on('close', () => {
      if (!isMounted.current) return;
      setStatus('disconnected');

      // Attempt reconnect with exponential backoff
      if (reconnectAttempts.current < maxReconnectAttempts) {
        const delay = Math.min(1000 * 2 ** reconnectAttempts.current, 30_000);
        reconnectAttempts.current += 1;

        reconnectTimerRef.current = setTimeout(() => {
          if (isMounted.current) doConnect();
        }, delay);
      }
    });

    session.on('error', (err) => {
      if (!isMounted.current) return;
      setError(err);
      setStatus('error');
    });

    session.connect().then(() => {
      if (isMounted.current) {
        setStatus('connected');
        reconnectAttempts.current = 0;
      }
    }).catch((err: unknown) => {
      if (!isMounted.current) return;
      const error = err instanceof Error ? err : new Error(String(err));
      setError(error);
      setStatus('error');
    });
  }, [bridgeUrl, serverVkBytes, strict, workerUrl, maxReconnectAttempts]);

  const disconnect = useCallback((): void => {
    clearReconnectTimer();
    reconnectAttempts.current = maxReconnectAttempts; // prevent auto-reconnect
    sessionRef.current?.close();
    sessionRef.current = null;
    setStatus('disconnected');
  }, [maxReconnectAttempts]);

  const send = useCallback(async (data: Uint8Array): Promise<void> => {
    if (!sessionRef.current) {
      throw new Error('PQCSession not connected');
    }
    return sessionRef.current.send(data);
  }, []);

  // Mount/unmount lifecycle
  useEffect(() => {
    isMounted.current = true;
    reconnectAttempts.current = 0;

    if (autoConnect) {
      doConnect();
    }

    return (): void => {
      isMounted.current = false;
      clearReconnectTimer();
      sessionRef.current?.close();
      sessionRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return {
    status,
    send,
    lastMessage,
    error,
    connect: doConnect,
    disconnect,
  };
}
