/**
 * vk.ts — VK bootstrap helper.
 *
 * Fetches the server VerifyingKey from the bridge's /vk/:token endpoint.
 * The SDK NEVER calls this autonomously — the caller must explicitly invoke it
 * to bootstrap the VK, then pass it as `serverVkBytes` to PQCSession (EC-1).
 */

/**
 * Fetches the ML-DSA-65 verifying key from the bridge over HTTPS.
 *
 * The base URL should point to the bridge's TLS listener (e.g. https://host:8440).
 * The install token is a one-time bootstrap token issued by the cloud API.
 *
 * @param baseUrl   HTTPS base URL of the bridge TLS listener
 * @param token     Install/registration token for /vk/:token
 * @returns         1952-byte verifying key as Uint8Array
 */
export async function fetchVK(baseUrl: string, token: string): Promise<Uint8Array> {
  if (!baseUrl.startsWith('https://')) {
    throw new Error('fetchVK: baseUrl must start with https://');
  }

  const url = `${baseUrl.replace(/\/$/, '')}/vk/${encodeURIComponent(token)}`;
  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(`fetchVK: server returned ${response.status} ${response.statusText}`);
  }

  const text = await response.text();

  // Response is JSON: { "server_vk": "<3904 hex chars>", "fingerprint": "..." }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error('fetchVK: response is not valid JSON');
  }

  if (typeof json !== 'object' || json === null || !('server_vk' in json)) {
    throw new Error('fetchVK: missing server_vk field');
  }

  const rawServerVk = (json as Record<string, unknown>)['server_vk'];
  if (typeof rawServerVk !== 'string') {
    throw new Error('fetchVK: missing server_vk field');
  }

  const hex: string = rawServerVk;

  // Validate hex encoding and exact VK length (1952 bytes = 3904 hex chars)
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error('fetchVK: server_vk is not valid hex');
  }

  if (hex.length !== 3904) {
    throw new Error(
      `fetchVK: server_vk has wrong length: expected 3904 hex chars (1952 bytes), got ${hex.length}`,
    );
  }

  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }

  return bytes;
}
