/**
 * wasm.d.ts — Type declarations for the latticeshield-wasm package.
 *
 * The actual wasm-bindgen generated types live in
 * `../latticeshield-wasm/pkg/latticeshield_wasm.d.ts`.
 * This stub declaration satisfies the TypeScript compiler when the package
 * is not yet installed as a node_modules dependency (build-time resolution).
 */

declare module 'latticeshield-wasm' {
  /** Async WASM initializer — call once before using any wasm_* functions. */
  export default function init(
    input?: RequestInfo | URL | Response | BufferSource | WebAssembly.Module,
  ): Promise<unknown>;

  /**
   * Generates the client response for the PQC handshake.
   *
   * @param server_hello_signed  4557-byte signed ServerHello from bridge
   * @param server_vk_bytes      1952-byte pre-shared ML-DSA-65 verifying key
   * @returns Object with `client_response: Uint8Array(1120)` and `session_key: Uint8Array(32)`
   */
  export function wasm_generate_client_response(
    server_hello_signed: Uint8Array,
    server_vk_bytes: Uint8Array,
  ): { client_response: Uint8Array; session_key: Uint8Array };

  export function wasm_generate_keypair(): { sk: Uint8Array; vk: Uint8Array };
  export function wasm_sign(sk_bytes: Uint8Array, msg: Uint8Array): Uint8Array;
  export function wasm_verify(
    vk_bytes: Uint8Array,
    msg: Uint8Array,
    sig_bytes: Uint8Array,
  ): void;
}
