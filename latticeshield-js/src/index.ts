/**
 * index.ts — Public API barrel for @latticeshield/js
 */

// ── Core classes ──────────────────────────────────────────────────────────────
export { PQCSession } from './session.js';

// ── React hook (optional — requires react peer dependency) ────────────────────
export { usePQCSession } from './hooks/usePQCSession.js';
export type { UsePQCSessionOptions, UsePQCSessionResult } from './hooks/usePQCSession.js';

// ── Types ─────────────────────────────────────────────────────────────────────
export type { PQCSessionOptions, PQCSessionStatus, SessionState } from './types.js';
export { SessionClosedError } from './types.js';

// ── Wire format constants ─────────────────────────────────────────────────────
export {
  FRAME_DATA,
  FRAME_KEY_ROTATE,
  SERVER_HELLO_SIGNED_LEN,
  CLIENT_RESPONSE_LEN,
  KEY_ROTATE_FRAME_LEN,
  VERIFYING_KEY_LEN,
} from './types.js';

// ── VK bootstrap utility (explicit opt-in, never called autonomously, EC-1) ───
export { fetchVK } from './vk.js';
