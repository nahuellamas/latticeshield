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

  const text = (await response.text()).trim();

  // Response is hex-encoded (64 hex chars per byte = 1952 * 2 = 3904 chars for VK)
  if (!/^[0-9a-fA-F]+$/.test(text)) {
    throw new Error('fetchVK: response is not valid hex');
  }

  if (text.length % 2 !== 0) {
    throw new Error('fetchVK: hex response has odd length');
  }

  const bytes = new Uint8Array(text.length / 2);
  for (let i = 0; i < text.length; i += 2) {
    bytes[i / 2] = parseInt(text.slice(i, i + 2), 16);
  }

  return bytes;
}
