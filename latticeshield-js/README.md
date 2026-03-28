# @latticeshield/js

Browser SDK for the LatticeShield PQC bridge. Gives any browser application a
post-quantum-safe encrypted channel to a backend service without writing any
crypto code.

- **Crypto runs in a Web Worker** — the main thread only sees plaintext.
- **WASM-backed** — ML-KEM-768, ML-DSA-65, and AES-256-GCM via
  `latticeshield-wasm` compiled from the same Rust codebase as the bridge.
- **React-optional** — `PQCSession` is framework-agnostic; `usePQCSession` is
  a convenience hook for React 18+.

---

## Quick start

```ts
import { PQCSession } from '@latticeshield/js';

// serverVkBytes is the 1952-byte ML-DSA-65 verifying key — pin this at
// build time, never fetch it at runtime (see Security section below).
const session = new PQCSession({
  bridgeUrl: 'wss://bridge.example.com:8446',
  serverVkBytes: MY_PINNED_VK_BYTES,   // Uint8Array, 1952 bytes
});

await session.connect();      // performs PQC handshake — resolves when ready

await session.send(new TextEncoder().encode('hello'));

session.on('message', (data) => {
  console.log('received:', new TextDecoder().decode(data));
});

session.close();
```

### React hook

```tsx
import { usePQCSession } from '@latticeshield/js';

function App() {
  const { status, send, lastMessage, error } = usePQCSession({
    bridgeUrl: 'wss://bridge.example.com:8446',
    serverVkBytes: MY_PINNED_VK_BYTES,
    autoConnect: true,           // connect on mount (default)
    maxReconnectAttempts: 3,     // exponential backoff (default)
  });

  return (
    <div>
      <p>Status: {status}</p>
      {lastMessage && <p>Last: {new TextDecoder().decode(lastMessage)}</p>}
      {error && <p>Error: {error.message}</p>}
      <button onClick={() => send(new TextEncoder().encode('ping'))}>
        Send
      </button>
    </div>
  );
}
```

**`wss://` is mandatory.** The constructor throws immediately if `bridgeUrl`
does not start with `wss://`.

---

## API

### `PQCSession`

| Method / Property | Description |
|---|---|
| `new PQCSession(options)` | Constructs a session — does not connect yet |
| `connect(): Promise<void>` | Opens the WebSocket and performs the PQC handshake |
| `send(data: Uint8Array): Promise<void>` | Encrypts and sends data; queues during key rotation |
| `recv(): Promise<Uint8Array>` | Awaits the next decrypted message (sequential reads) |
| `close(): void` | Closes the WebSocket and terminates the Worker |
| `on(event, handler)` | Subscribe: `'message'`, `'error'`, `'close'`, `'keyrotate'` |
| `off(event, handler)` | Unsubscribe |
| `once(event, handler)` | One-shot subscription |

#### `PQCSessionOptions`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `bridgeUrl` | `string` | yes | — | WebSocket URL — must start with `wss://` |
| `serverVkBytes` | `Uint8Array` | yes | — | Pre-shared ML-DSA-65 verifying key (1952 bytes) |
| `strict` | `boolean` | no | `false` | If `true`, `connect()` rejects on error instead of silently degrading |
| `workerUrl` | `string` | no | auto-resolved | Custom URL to the Worker bundle (advanced) |

### `usePQCSession`

| Field returned | Type | Description |
|---|---|---|
| `status` | `PQCSessionStatus` | `'idle'` \| `'connecting'` \| `'ready'` \| `'error'` \| `'closed'` |
| `send` | `(data: Uint8Array) => Promise<void>` | Send encrypted data |
| `lastMessage` | `Uint8Array \| null` | Most recent decrypted message |
| `error` | `Error \| null` | Last error, if any |
| `connect` | `() => void` | Manually trigger connect |
| `disconnect` | `() => void` | Close and disable auto-reconnect |

---

## Building the WASM module

`@latticeshield/js` imports from the `latticeshield-wasm` crate's build output.
You must compile it before building the npm package.

### Target: `web` (standalone, no bundler required)

```sh
wasm-pack build --target web latticeshield-wasm
```

Outputs to `latticeshield-wasm/pkg/`. Use this target when loading the WASM
module directly in a browser with `<script type="module">` or when the Worker
does not go through a bundler.

### Target: `bundler` (Vite / webpack)

```sh
wasm-pack build --target bundler latticeshield-wasm
```

Also outputs to `latticeshield-wasm/pkg/`. Use this target when importing from
the WASM module inside a Vite or webpack build — the bundler handles the
`import.meta.url`-based WASM initialization automatically.

**When in doubt, use `--target bundler` for Vite projects and `--target web`
for anything that loads modules directly in the browser.**

The `latticeshield-js` package imports from `../latticeshield-wasm/pkg/` at
build time. Run `wasm-pack` before `npm run build`:

```sh
wasm-pack build --target bundler latticeshield-wasm
cd latticeshield-js && npm run build   # outputs to dist/
```

---

## Content Security Policy

The WASM module requires `'wasm-unsafe-eval'` in your CSP — **not**
`'unsafe-eval'`.

### Why `wasm-unsafe-eval` instead of `'unsafe-eval'`

`'unsafe-eval'` allows the browser to execute arbitrary JavaScript strings
(e.g., `eval()`, `new Function()`), which opens XSS escalation paths.
`'wasm-unsafe-eval'` is a more targeted directive added in CSP Level 3 that
permits only WASM compilation — it does not enable JS string evaluation. Using
`'unsafe-eval'` to satisfy WASM is an over-permission; always prefer the
narrower directive.

### Browser support for `wasm-unsafe-eval`

| Browser | Minimum version |
|---|---|
| Chrome / Edge | 97+ |
| Firefox | 102+ |
| Safari | 16+ |

### Copy-paste CSP example

```http
Content-Security-Policy:
  default-src 'self';
  script-src  'self' 'wasm-unsafe-eval';
  connect-src 'self' wss://bridge.example.com:8446;
  worker-src  'self' blob:;
```

Add `worker-src 'self' blob:` because `PQCSession` spawns an inline Web Worker.
Adjust `connect-src` to match your bridge host and port.

---

## Subresource Integrity (SRI) for CDN deployments

If you serve the `.wasm` bundle from a CDN, pin it with an SRI hash to prevent
substitution attacks.

### Generate the SHA-384 hash

```sh
openssl dgst -sha384 -binary latticeshield_bg.wasm | openssl base64 -A
```

The file `latticeshield_bg.wasm` is produced by `wasm-pack` inside
`latticeshield-wasm/pkg/` and copied to `dist/` by `npm run build`.

### Use the hash in a script tag

```html
<script
  type="module"
  src="https://cdn.example.com/latticeshield/latticeshield_bg.wasm"
  integrity="sha384-<paste-hash-here>"
  crossorigin="anonymous"
></script>
```

The browser will refuse to execute the file if its content does not match the
pinned hash — even if the CDN is compromised.

---

## Security

### Server verifying key must be pinned at build time

`serverVkBytes` is the bridge's 1952-byte ML-DSA-65 public key. It
**must not** be fetched at runtime — a network fetch could be intercepted and
a different key substituted, defeating the handshake verification entirely.
Embed the key as a base64 constant in your application bundle, or bake it in
at CI time.

```ts
// Good: embedded at build time
const VK = Uint8Array.from(atob('AAEC...'), c => c.charCodeAt(0));

// Bad: runtime fetch — never do this
const VK = await fetch('/api/server-vk').then(r => r.arrayBuffer());
```

### wss:// only

Plain `ws://` is rejected at construction time. Sending the PQC handshake over
an unencrypted WebSocket would expose the session setup to a network observer.

---

## Wire format constants

These are re-exported from the package for advanced use:

| Constant | Value | Description |
|---|---|---|
| `FRAME_DATA` | `0x01` | DATA frame tag byte |
| `FRAME_KEY_ROTATE` | `0x02` | KEY_ROTATE frame tag byte |
| `SERVER_HELLO_SIGNED_LEN` | `4557` | Signed ServerHello size (bytes) |
| `CLIENT_RESPONSE_LEN` | `1120` | ClientResponse size (bytes) |
| `KEY_ROTATE_FRAME_LEN` | `61` | KEY_ROTATE frame size (bytes) |
| `VERIFYING_KEY_LEN` | `1952` | ML-DSA-65 verifying key size (bytes) |

---

## License

UNLICENSED — private project.
