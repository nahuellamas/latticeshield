# LatticeShield

<p align="center">
  <a href="README.md">🇺🇸 Read in English</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rust-1.75%2B-orange?style=for-the-badge&logo=rust&logoColor=white" alt="Rust 1.75+">
  <img src="https://img.shields.io/badge/tests-560_pasando-brightgreen?style=for-the-badge" alt="560 tests pasando">
  <img src="https://img.shields.io/badge/sin_FFI-Rust_puro-blue?style=for-the-badge" alt="Sin FFI — Rust puro">
  <img src="https://img.shields.io/badge/PQC-ML--KEM--768_%2B_ML--DSA--65-blueviolet?style=for-the-badge" alt="PQC: ML-KEM-768 + ML-DSA-65">
  <img src="https://img.shields.io/badge/licencia-Apache--2.0-blue?style=for-the-badge" alt="Apache-2.0">
</p>

> Un reverse proxy cuántico-resistente escrito en **Rust puro** — sin FFI, sin OpenSSL, sin `oqs-rs`.

Agregá cifrado post-cuántico a cualquier servicio TCP **sin tocar una sola línea de tu aplicación**. LatticeShield funciona como sidecar: tus clientes se conectan al bridge, el tráfico viaja cifrado con un canal híbrido **X25519 + ML-KEM-768 + AES-256-GCM**, se descifra en el bridge y se reenvía a tu backend por localhost. El bridge también se autentica ante los clientes con firmas **ML-DSA-65** para que puedan verificar criptográficamente que están hablando con el servidor real.

**[→ Ponerlo a funcionar en 10 minutos](QUICKSTART.md)**

---

## Tabla de contenidos

- [FAQ](#faq)
- [¿Por qué criptografía post-cuántica ahora?](#por-qué-criptografía-post-cuántica-ahora)
- [Cómo funciona](#cómo-funciona)
- [Inicio rápido](#inicio-rápido)
- [Listeners y puertos](#listeners-y-puertos)
- [Referencia de configuración](#referencia-de-configuración)
  - [\[server\]](#server)
  - [\[crypto\]](#crypto)
  - [\[auth\]](#auth)
  - [\[tls\]](#tls)
  - [\[quic\]](#quic)
  - [\[websocket\]](#websocket)
  - [\[admin\]](#admin)
  - [\[control\_plane\]](#control_plane)
  - [\[key\_rotation\]](#key_rotation)
  - [\[logging\]](#logging)
  - [\[metrics\]](#metrics)
  - [Variables de entorno](#variables-de-entorno)
- [Referencia de CLI](#referencia-de-cli)
- [SDK para browsers](#sdk-para-browsers-latticeshieldjs)
- [VK-share](#vk-share)
- [Diseño de seguridad](#diseño-de-seguridad)
- [Métricas Prometheus](#métricas-prometheus)
- [Estructura del workspace](#estructura-del-workspace)
- [Compilar desde el código fuente](#compilar-desde-el-código-fuente)
- [Tests](#tests)
- [Novedades](#novedades)
- [Contribuir](#contribuir)
- [Licencia](#licencia)

---

## FAQ

**¿Por qué no WireGuard?**

WireGuard usa Curve25519, que el algoritmo de Shor rompe en una computadora cuántica. Además requiere un módulo de kernel o dispositivo TUN — acceso root, restricciones de versión de kernel y reglas de firewall. LatticeShield corre completamente en userspace, no necesita root y se pone delante de cualquier servicio TCP sin tocar el stack de red del OS.

**¿Por qué no TLS 1.3 con extensiones post-cuánticas?**

Podés — Cloudflare, Chrome y algunos servidores ya negocian X25519Kyber768 en TLS 1.3. Pero eso solo protege el intercambio de clave, no la identidad del servidor (que sigue siendo ECDSA o RSA). LatticeShield reemplaza ambos: intercambio de clave (X25519 + ML-KEM-768) y autenticación del servidor (ML-DSA-65). Además funciona para TCP crudo, no solo HTTPS.

**¿Por qué no Cloudflare o un CDN que ya hace PQC?**

Porque tu tráfico pasa por su infraestructura y sus claves. LatticeShield es self-hosted — vos generás las claves, vos corrés el bridge, ningún tercero toca tu texto plano. El modelo de amenaza incluye a tu proveedor de CDN.

**¿Cómo se compara LatticeShield con las alternativas?**

| | LatticeShield | WireGuard | Cloudflare WARP | Nginx + BoringSSL PQ TLS | TLS 1.3 estándar |
|---|---|---|---|---|---|
| **Intercambio de clave** | X25519 + ML-KEM-768 (híbrido PQC) | Curve25519 | X25519 | X25519 + Kyber (borrador) | X25519 / ECDH |
| **Autenticación servidor** | ML-DSA-65 (firma PQC) | Claves públicas estáticas | ECDSA | ECDSA / RSA | ECDSA / RSA |
| **Transporte** | Cualquier servicio TCP | VPN capa IP | Proxy HTTPS | Solo HTTPS | Solo HTTPS |
| **Requiere root** | No | Sí (kernel / TUN) | No (app cliente) | No | No |
| **Seguro PQC hoy** | Sí — KEM + firma | No | Parcial — solo KEM | Parcial — solo KEM | No |
| **Self-hosted** | Sí | Sí | No (nube Cloudflare) | Sí | Sí |
| **Cambios en backend** | Cero | Cero | Cero | Cero | Cero |

**¿Está listo para producción?**

Las primitivas criptográficas usan crates auditadas upstream (`libcrux-ml-dsa`, `ml-kem`, `x25519-dalek`). El diseño del protocolo y el código de integración son self-reviewed — no se realizó ninguna auditoría de terceros. Tratalo como production-capable pero deployá con eso en mente: correlo detrás de un firewall, monitoreá `/metrics` y mantené `server.sk` fuera de internet.

---

## ¿Por qué criptografía post-cuántica ahora?

En 2024 el NIST finalizó tres estándares de criptografía post-cuántica (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA). El algoritmo de Shor rompe ECDH y RSA en una computadora cuántica suficientemente grande. Los ataques de "cosecha ahora, descifrado después" ya están ocurriendo: adversarios recopilan tráfico cifrado hoy para descifrarlo cuando llegue el hardware cuántico.

LatticeShield usa un **modelo híbrido** (X25519 + ML-KEM-768): cada sesión está protegida por algoritmos clásicos y post-cuánticos al mismo tiempo. Para romper la sesión hay que romper ambos. La criptografía clásica te protege hoy; la post-cuántica protege tu tráfico histórico cuando llegue el hardware cuántico.

---

## Cómo funciona

```
┌───────────────┐    cifrado (PQC)      ┌──────────────────┐    TCP plano    ┌─────────────┐
│    Cliente    │ ─────────────────────▶│  LatticeShield   │────────────────▶│   Backend   │
│  (tu app)     │◀───────────────────── │     Bridge       │◀────────────────│   Servicio  │
└───────────────┘                       └──────────────────┘                 └─────────────┘
              wss:// / TCP / TLS / QUIC                       127.0.0.1:8080
```

| Qué garantiza el bridge | Qué NO cambia |
|---|---|
| El tráfico entre cliente y bridge está cifrado con criptografía cuántico-resistente | Tu **backend** recibe TCP plano — sin cambios en el código |
| El servidor se autentica criptográficamente ante el cliente (ML-DSA-65) | Tu protocolo HTTP, gRPC o custom pasa sin modificaciones |
| Los clientes también pueden probar su identidad (autenticación mutua) | El bridge es transparente — reenvía bytes, no parsea HTTP |
| Cada sesión usa claves efímeras frescas (forward secrecy perfecta) | Sin módulos de kernel, sin eBPF, sin sidecars que necesiten root |

> **Nota**: los clientes se conectan via el SDK (`@latticeshield/js` para browsers, `latticeshield-client` para server-side) o cualquier cliente TCP que implemente el handshake PQC. Solo el backend no requiere cambios.

---

## Inicio rápido

La idea es simple: tu app sigue corriendo exactamente igual que antes. El bridge se pone adelante, maneja todo el cifrado y reenvía bytes planos a tu app por localhost. Los clientes hablan con el bridge en `:8443`; tu backend sigue en `:8080`. El backend no necesita cambios — los clientes usan el SDK o el proxy `latticeshield-client` para hablar el handshake PQC.

### 1. Instalar

```sh
curl -fsSL https://raw.githubusercontent.com/nahuellamas/latticeshield/main/install.sh | bash
```

Descarga el binario pre-compilado para tu plataforma (Linux x86_64/arm64 o macOS Intel/Apple Silicon).

### 2. Generar el par de claves

```sh
latticeshield-bridge keygen ./keys
```

Esto crea dos archivos: `server.sk` (clave privada, permisos 0600) y `server.vk` (clave pública, 1952 bytes). El bridge usa `server.sk` para firmar un mensaje de bienvenida al inicio de cada sesión. Los clientes usan `server.vk` para verificar esa firma — es lo único que impide que un impostor se haga pasar por tu bridge. Tratá `server.sk` como una contraseña: nunca lo comitees, nunca lo copies por HTTP.

### 3. Escribir la configuración

```sh
cat > config.toml << 'EOF'
[server]
listen_addr      = "0.0.0.0:8443"    # los clientes se conectan acá
backend_addr     = "127.0.0.1:8080"  # tu app ya está escuchando acá

[crypto]
signing_key_path = "./keys/server.sk"
EOF
```

`backend_addr` es donde tu app ya está escuchando. El bridge descifra el tráfico del cliente y reenvía bytes crudos a tu app — sin cambios de código ni dependencias nuevas del lado del backend.

### 4. Arrancar el bridge

```sh
latticeshield-bridge run --config config.toml
```

El bridge ya está aceptando conexiones en `:8443`. Cada cliente recibe un canal cifrado cuántico-resistente fresco. Tu app en `:8080` no ve nada diferente — solo bytes llegando desde localhost.

### 5. Distribuir la clave pública a los clientes

```sh
# Opción A — copiar a un host específico
scp ./keys/server.vk cliente-host:./keys/server.vk

# Opción B — incluir en una imagen Docker
COPY keys/server.vk /etc/latticeshield/server.vk

# Opción C — clientes de browser: usar VK-share (ver más abajo)
```

Cada cliente necesita `server.vk` antes de conectarse. Distribuila fuera de banda — SSH, gestión de configuración, imagen Docker, lo que encaje con tu deployment. Nunca la descargues en tiempo de conexión por el mismo canal que protege; eso anularía la autenticación. Un cliente con la VK incorrecta (o sin VK) rechazará el handshake.

> **La autenticación mutua de clientes** está desactivada por defecto — la configuración de arriba no incluye sección `[auth]` así que el bridge acepta cualquier cliente. Se registra un `WARN` al arrancar para recordártelo. Para deployments en producción con autenticación mutua habilitada consultá **[QUICKSTART.md](QUICKSTART.md)**.

---

## Listeners y puertos

| Protocolo | Puerto por defecto | Sección | Activar |
|---|---|---|---|
| PQC TCP | `0.0.0.0:8443` | `[server]` | Siempre activo |
| TLS/HTTPS | `0.0.0.0:8440` | `[tls]` | `tls.enabled = true` |
| QUIC (UDP) | `0.0.0.0:8441` | `[quic]` | `quic.enabled = true` |
| WebSocket (WSS) | `0.0.0.0:8446` | `[websocket]` | `websocket.enabled = true` |
| Métricas Prometheus | `0.0.0.0:8444` | `[metrics]` | Siempre activo (HTTP plano) |
| Admin PQC | `0.0.0.0:8445` | `[admin]` | `admin.enabled = true` |

Todos los puertos deben ser distintos. El bridge valida colisiones al iniciar y rechaza arrancar si dos listeners comparten un puerto.

---

## Referencia de configuración

Ejemplo completo con todas las secciones y sus valores por defecto:

```toml
[server]
listen_addr             = "0.0.0.0:8443"
backend_addr            = "127.0.0.1:8080"
max_frame_size          = 65536
handshake_timeout_secs  = 10
max_connections_per_ip  = 50

[crypto]
signing_key_path        = "./keys/server.sk"

[auth]
client_vk_path          = "./keys/client.vk"   # omitir para deshabilitar autenticación mutua
# require_client_auth   = false                 # por defecto: true

[tls]
enabled                 = false
listen_addr             = "0.0.0.0:8440"
cert_path               = "./keys/tls.crt"
key_path                = "./keys/tls.key"

[quic]
enabled                 = false
listen_addr             = "0.0.0.0:8441"
cert_path               = "./keys/tls.crt"
key_path                = "./keys/tls.key"

[websocket]
enabled                 = false
listen_addr             = "0.0.0.0:8446"
cert_path               = "./keys/tls.crt"
key_path                = "./keys/tls.key"
allowed_origins         = ["https://app.example.com"]
handshake_timeout_secs  = 10
max_connections_per_ip  = 100

[admin]
enabled                        = false
listen_addr                    = "127.0.0.1:8445"
control_plane_vk_path          = "./keys/admin.vk"
rate_limit_per_second          = 5
handshake_timeout_secs         = 10

[control_plane]
enabled                  = false
endpoint                 = "https://cp.example.com"
agent_name               = ""           # por defecto usa $HOSTNAME
heartbeat_interval_secs  = 30
install_token            = ""           # o usá la variable $INSTALL_TOKEN

[key_rotation]
enabled              = false
max_bytes_per_key    = 10737418240     # 10 GiB
max_seconds_per_key  = 86400           # 24 h

[logging]
level = "info"                          # trace | debug | info | warn | error

[metrics]
listen_addr             = "0.0.0.0:8444"
```

### [server]

| Campo | Por defecto | Validación | Descripción |
|---|---|---|---|
| `listen_addr` | `"0.0.0.0:8443"` | dirección válida | Dirección a la que se vincula el listener PQC TCP |
| `backend_addr` | `"127.0.0.1:8080"` | dirección válida | Backend destino — recibe TCP plano |
| `max_frame_size` | `65536` | 1024–16 777 216 | Tamaño máximo de frame AES-256-GCM en bytes |
| `handshake_timeout_secs` | `10` | ≥ 1 | Segundos permitidos para completar el handshake PQC. Solo aplica al handshake — el relay no tiene timeout |
| `max_connections_per_ip` | `50` | ≥ 1 | Límite de conexiones por IP de origen. Las conexiones en exceso se descartan para prevenir agotamiento de CPU bajo floods de conexiones |

### [crypto]

| Campo | Por defecto | Requerido | Descripción |
|---|---|---|---|
| `signing_key_path` | `"./keys/server.sk"` | sí | Ruta a la clave de firma ML-DSA-65 (binario, 4032 bytes). Generada por `keygen`. El archivo debe tener permisos `0600` — el bridge rechaza cargar una clave con permisos más abiertos |

La clave pública (`server.vk`) se carga automáticamente desde el mismo directorio que `signing_key_path`. Se distribuye a los clientes fuera de banda — nunca viaja por el wire. Ver [VK-share](#vk-share) para cómo distribuir la clave pública a clientes de browser automáticamente.

### [auth]

| Campo | Por defecto | Requerido | Descripción |
|---|---|---|---|
| `client_vk_path` | — | no | Ruta a la clave pública ML-DSA-65 del cliente (1952 bytes). Si está presente, el bridge exige que cada cliente pruebe su identidad durante el handshake PQC |
| `require_client_auth` | `true` | — | Si se omite `client_vk_path`, poner esto en `false` explícitamente para suprimir la advertencia de inicio. Omitir este campo y `client_vk_path` al mismo tiempo genera un `WARN` al arrancar |

Omitir la sección `[auth]` completamente deshabilita la autenticación mutua. El bridge emite un `WARN` al arrancar para recordar a los operadores que la identidad del cliente no está siendo verificada.

### [tls]

| Campo | Por defecto | Requerido | Descripción |
|---|---|---|---|
| `enabled` | `false` | — | Activar el listener TLS/HTTPS |
| `listen_addr` | `"0.0.0.0:8440"` | — | Dirección TCP del listener |
| `cert_path` | `"./keys/tls.crt"` | cuando enabled | Certificado PEM |
| `key_path` | `"./keys/tls.key"` | cuando enabled | Clave privada PEM |

Generá un certificado autofirmado para desarrollo: `latticeshield-bridge tls-keygen ./keys`

### [quic]

| Campo | Por defecto | Requerido | Descripción |
|---|---|---|---|
| `enabled` | `false` | — | Activar el listener QUIC (UDP) |
| `listen_addr` | `"0.0.0.0:8441"` | — | Dirección UDP del endpoint QUIC |
| `cert_path` | — | cuando enabled | Certificado PEM (puede reutilizarse del TLS) |
| `key_path` | — | cuando enabled | Clave privada PEM |

Cada stream QUIC bidireccional se mapea a una conexión TCP fresca al backend.

### [websocket]

| Campo | Por defecto | Requerido | Descripción |
|---|---|---|---|
| `enabled` | `false` | — | Activar el listener WSS para el SDK del browser |
| `listen_addr` | `"0.0.0.0:8446"` | — | Dirección TCP |
| `cert_path` | — | cuando enabled | Certificado PEM |
| `key_path` | — | cuando enabled | Clave privada PEM |
| `allowed_origins` | `[]` | — | Array de orígenes permitidos ej. `["https://app.example.com", "http://localhost:3000"]`. Array vacío acepta todos los orígenes y emite un log `WARN` — solo para desarrollo |
| `handshake_timeout_secs` | `10` | — | Timeout del handshake PQC para conexiones WebSocket |
| `max_connections_per_ip` | `100` | — | Límite de conexiones WebSocket por IP |

Los orígenes se normalizan según RFC 6454 (`scheme://host:port`). La comparación es exacta post-normalización — se rechazan paths, query strings y fragmentos.

### [admin]

El canal admin acepta una conexión TCP PQC-autenticada, lee un comando JSON, responde y cierra. La autenticación mutua ML-DSA-65 es obligatoria.

| Campo | Por defecto | Requerido | Descripción |
|---|---|---|---|
| `enabled` | `false` | — | Activar el listener admin |
| `listen_addr` | `"127.0.0.1:8445"` | — | Dirección TCP. Por defecto es loopback — cambialo solo si el control plane corre en un host separado, y configurá el firewall en consecuencia |
| `control_plane_vk_path` | — | cuando enabled | Clave pública ML-DSA-65 del control plane |
| `rate_limit_per_second` | `5` | — | Máximo comandos admin por segundo |
| `handshake_timeout_secs` | `10` | — | Timeout del handshake PQC |

Generá un par de claves admin: `latticeshield-bridge admin-keygen ./keys`  
Colocá `admin.vk` en `control_plane_vk_path` en el bridge; guardá `admin.sk` en el control plane.

### [control_plane]

| Campo | Por defecto | Descripción |
|---|---|---|
| `enabled` | `false` | Enviar heartbeats periódicos al control plane |
| `endpoint` | `""` | URL del control plane ej. `https://cp.example.com` |
| `agent_name` | `""` | Identificador del bridge. Por defecto usa `$HOSTNAME` si está vacío |
| `heartbeat_interval_secs` | `30` | Segundos entre heartbeats (mínimo: 5) |
| `install_token` | `""` | Token de registro. También se puede leer de `$INSTALL_TOKEN` |

Los fallos de heartbeat no son fatales — el bridge sigue sirviendo tráfico si el control plane no está disponible.

### [key_rotation]

| Campo | Por defecto | Validación | Descripción |
|---|---|---|---|
| `enabled` | `false` | — | Activar rotación automática de clave de sesión AES |
| `max_bytes_per_key` | `10737418240` | ≥ 1 MiB | Bytes cifrados antes de rotar (10 GiB por defecto) |
| `max_seconds_per_key` | `86400` | ≥ 60 | Segundos antes de forzar rotación (24 h por defecto) |

La rotación de clave usa ratcheting HKDF-SHA256: la nueva clave se deriva de la actual más un nonce aleatorio de 32 bytes. La clave anterior se zeroiza de inmediato. La rotación también puede dispararse manualmente via el canal admin (comando `Rotate`).

### [logging]

| Campo | Por defecto | Descripción |
|---|---|---|
| `level` | `"info"` | Nivel de log: `trace`, `debug`, `info`, `warn`, `error`. La variable `$RUST_LOG` tiene precedencia |

### [metrics]

| Campo | Por defecto | Descripción |
|---|---|---|
| `listen_addr` | `"0.0.0.0:8444"` | Dirección del servidor HTTP de métricas Prometheus. Siempre activo — no puede deshabilitarse |

El endpoint responde en `GET /metrics` con formato de texto Prometheus. Retorna headers de seguridad (`X-Content-Type-Options`, `X-Frame-Options`, `Cache-Control: no-store` y una CSP estricta). No expongas este puerto a internet sin un proxy de autenticación adelante.

### Variables de entorno

| Variable | Por defecto | Descripción |
|---|---|---|
| `RUST_LOG` | — | Reemplaza `[logging].level`. Soporta filtros por módulo ej. `RUST_LOG=latticeshield_bridge=debug` |
| `INSTALL_TOKEN` | — | Reemplaza `[control_plane].install_token` |
| `SHUTDOWN_TIMEOUT_SECS` | `30` | Segundos para drenar sesiones activas en SIGTERM/SIGINT antes de forzar el cierre |
| `LATTICE_VK_TOKEN_MAX` | `1000` | Máximo de entradas en el store in-memory de tokens VK-share |
| `HOSTNAME` | — | Se usa como `agent_name` cuando `[control_plane].agent_name` está vacío |

---

## Referencia de CLI

### `latticeshield-bridge` — el daemon proxy

```sh
# Iniciar el bridge
latticeshield-bridge run [--config <ruta>]          # por defecto: ./config.toml

# Generar par de claves ML-DSA-65 del servidor
latticeshield-bridge keygen <dir>
# → <dir>/server.sk  (permisos 0600)
# → <dir>/server.vk  (permisos 0644)

# Generar certificado TLS autofirmado (para desarrollo)
latticeshield-bridge tls-keygen <dir>
# → <dir>/tls.crt
# → <dir>/tls.key

# Generar par de claves ML-DSA-65 para el canal admin
latticeshield-bridge admin-keygen <dir>
# → <dir>/admin.sk  (permisos 0600)
# → <dir>/admin.vk  (permisos 0644)
```

### `latticeshield` — CLI unificado de gestión de claves

```sh
# Generar pares de claves
latticeshield keygen server <dir>   # server.sk (0600) + server.vk (0644)
latticeshield keygen client <dir>   # client.sk (0600) + client.vk (0644)
latticeshield keygen tls <dir>      # tls.crt + tls.key (autofirmado, solo dev)

# Inspeccionar una clave pública
latticeshield vk-info ./keys/server.vk
# → Archivo, Tamaño (1952 bytes), fingerprint SHA-256

# Solicitar una URL de descarga de VK de un solo uso via el canal admin PQC
latticeshield vk-share \
  --admin-addr 127.0.0.1:8445 \
  --bridge-vk  ./keys/server.vk \
  --admin-sk   ./keys/admin.sk
# → URL de descarga de VK de un solo uso + token + expiración
```

### `latticeshield-client` — proxy cliente PQC server-side

```sh
latticeshield-client --config ./latticeshield-client.toml
```

Acepta conexiones TCP locales y las reenvía al bridge usando el handshake PQC completo — para escenarios server-to-server donde no podés modificar el servicio originador.

**Reconexión automática** (opt-in): cuando el bridge cierra una sesión, el cliente reconecta silenciosamente con backoff exponencial. Cada reconexión realiza un handshake PQC completo y fresco — sin reutilización de sesión ni de claves.

```toml
[reconnect]
max_retries   = 5      # 0 = deshabilitado (por defecto)
base_delay_ms = 100
max_delay_ms  = 30000
```

Suscribite a los eventos de reconexión para re-inicializar el estado del protocolo (re-suscribirse a Redis, reintentar transacciones PostgreSQL, reabrir streams gRPC):

```rust
use latticeshield_client::{run, ReconnectEvent};
use tokio::sync::mpsc;

let (tx, mut rx) = mpsc::channel(16);
tokio::spawn(run(config, Some(tx)));

while let Some(event) = rx.recv().await {
    match event {
        ReconnectEvent::Reconnected { attempt, peer } => { /* re-init state */ }
        ReconnectEvent::Exhausted  { attempts, peer } => { /* give up    */ }
    }
}
```

---

## SDK para browsers (`@latticeshield/js`)

Los browsers pueden conectarse a LatticeShield directamente — sin plugin, sin agente nativo. El listener WebSocket del bridge (`:8446`) habla el mismo handshake PQC híbrido que el cliente Rust. Toda la criptografía corre dentro de un Web Worker respaldado por un módulo WASM para que las claves de sesión nunca toquen el hilo principal.

```sh
npm install @latticeshield/js
```

```ts
import { PQCSession } from '@latticeshield/js';

const session = new PQCSession({
  bridgeUrl:      'wss://bridge.ejemplo.com:8446',
  serverVkBytes:  SERVER_VK,   // Uint8Array(1952) — fijado en tiempo de build
});

await session.connect();
await session.send(new TextEncoder().encode('hola'));
session.on('message', (data) => console.log(data));
```

**Hook de React** con reconexión automática con backoff exponencial (1 s × 2ⁿ, máx 30 s, 3 intentos):

```ts
import { usePQCSession } from '@latticeshield/js';

const { status, send, lastMessage, error } = usePQCSession({
  bridgeUrl:     'wss://bridge.ejemplo.com:8446',
  serverVkBytes: SERVER_VK,
});
```

**Requisitos de CSP:**
```http
Content-Security-Policy:
  script-src  'self' 'wasm-unsafe-eval';
  worker-src  'self' blob:;
  connect-src 'self' wss://bridge.ejemplo.com:8446;
```

`serverVkBytes` debe estar fijado en tiempo de build — nunca debe ser descargado en runtime. Consultá [`latticeshield-js/README.md`](latticeshield-js/README.md) para la referencia completa de la API, hashing SRI y la guía de distribución de VK.

---

## VK-share

Los clientes de browser necesitan la clave pública del servidor (`server.vk`) antes de poder abrir una sesión. Lo más seguro es embeber los 1952 bytes en el build, pero LatticeShield también ofrece el mecanismo **VK-share** para distribución dinámica: el bridge genera una URL de un solo uso de corta duración que el cliente puede usar para recuperar la clave via HTTPS.

### Cómo funciona

1. Un operador del control plane envía el comando `GetVkToken` al canal admin (`:8445`). El bridge devuelve un token aleatorio.
2. El cliente descarga `GET https://bridge.ejemplo.com:8440/vk/<token>` — el listener TLS sirve los bytes crudos de la clave pública.
3. El token es de un solo uso y expira a los 10 minutos. Si el token es desconocido o expiró el bridge devuelve `404`. El store de tokens está limitado a 1000 entradas; las nuevas solicitudes reciben `429` cuando se alcanza el límite.

### Cuándo usar VK-share

VK-share está diseñado para escenarios donde embeber la clave en el build no es práctico — por ejemplo, un SaaS donde cada tenant tiene su propio bridge y la app de browser necesita descubrir la clave correcta en runtime. Para deployments fijos (tu propia infraestructura, tus propios clientes), distribuir `server.vk` fuera de banda y fijarlo en el build es más simple y tiene una superficie de ataque menor.

### Requisitos

El listener TLS (`[tls]`) debe estar habilitado — VK-share se sirve por HTTPS, no por HTTP plano.

```sh
# Solicitar una URL de descarga de VK de un solo uso via el canal admin PQC
# (requiere canal admin habilitado + par de claves admin generado)
latticeshield vk-share \
  --admin-addr 127.0.0.1:8445 \
  --bridge-vk  ./keys/server.vk \
  --admin-sk   ./keys/admin.sk
# URL de descarga de VK de un solo uso:
#   https://bridge.ejemplo.com:8440/vk/a3f8...
# Token: a3f8...
# Expira en: 10 minutos (600 segundos)

# El cliente descarga la clave pública
curl https://bridge.ejemplo.com:8440/vk/a3f8...
# → 1952 bytes crudos (application/octet-stream)
```

---

## Diseño de seguridad

### Primitivas criptográficas

| Rol | Algoritmo | Estándar |
|---|---|---|
| Encapsulación de clave | ML-KEM-768 | NIST FIPS 203 |
| Intercambio de clave clásico | X25519 | RFC 7748 |
| Derivación de clave | HKDF-SHA256 | RFC 5869 |
| Cifrado simétrico | AES-256-GCM | NIST SP 800-38D |
| Firmas servidor/cliente | ML-DSA-65 | NIST FIPS 204 |
| Separador de dominio de firma | `"latticeshield-v1"` | FIPS 204 §5.2 |

Todas las primitivas son Rust puro — sin FFI en C, sin OpenSSL, sin `oqs-rs`. Crates crypto: [`libcrux-ml-dsa`](https://crates.io/crates/libcrux-ml-dsa) (=0.0.8, ML-DSA-65), [`ml-kem`](https://crates.io/crates/ml-kem) (ML-KEM-768), [`x25519-dalek`](https://crates.io/crates/x25519-dalek), [`aes-gcm`](https://crates.io/crates/aes-gcm), [`hkdf`](https://crates.io/crates/hkdf).

> ⚠️ **No se realizó ninguna auditoría de seguridad de terceros.** Las primitivas criptográficas usan crates auditadas upstream; el diseño del protocolo y el código de integración son self-reviewed únicamente.

### Flujo del handshake (autenticación del servidor, sin autenticación mutua)

```
Servidor                                   Cliente
  │                                           │
  │  server_hello_signed (4557 B)             │
  │  = X25519_pub(32) + ML-KEM_EK(1184)       │
  │    + nonce(32) + firma_ML-DSA-65(3309)    │
  │ ─────────────────────────────────────────▶│
  │                                           │  verifica firma ML-DSA-65
  │                                           │  encapsula ML-KEM-768
  │                                           │  X25519 DH
  │                                           │  HKDF(x25519_secret || kem_secret, nonce)
  │  client_response (1120 B)                 │
  │  = X25519_pub(32) + ML-KEM_CT(1088)       │
  │◀─────────────────────────────────────────│
  │  desencapsula ML-KEM                      │
  │  X25519 DH                                │
  │  HKDF → misma SessionKey ─────────────────┤
  │                                           │
  │◀════ relay cifrado con AES-256-GCM ══════▶│
```

### Constantes del protocolo de wire

| Constante | Bytes | Descripción |
|---|---|---|
| `SERVER_HELLO_SIGNED_LEN` | 4557 | Server hello firmado (la VK **no** viaja en el wire — pre-compartida) |
| `CLIENT_RESPONSE_LEN` | 1120 | Respuesta de intercambio de clave del cliente |
| `VERIFYING_KEY_LEN` | 1952 | Clave pública ML-DSA-65 |
| `SIGNING_KEY_LEN` | 4032 | Clave privada ML-DSA-65 |
| `SIGNATURE_LEN` | 3309 | Firma ML-DSA-65 |
| `KEY_ROTATE_FRAME_LEN` | 61 | Frame de rotación de clave: tag(1)+nonce(12)+nonce_enc(32)+tag(16) |

### Frame DATA (v3)

```
[0x01][4B len][8B seq u64-BE][12B nonce AES-GCM][ciphertext][16B GCM tag]
```

El campo `seq` se incluye como AAD de AES-GCM — manipular el número de secuencia se detecta como fallo de autenticación. Los frames fuera de orden o repetidos se rechazan inmediatamente (`FrameError::Replay`).

### Restricciones de seguridad

| Restricción | Motivo |
|---|---|
| Rust puro, sin FFI | Elimina clases enteras de unsafety de memoria en el camino criptográfico |
| VK pre-compartida, no en wire | Previene MITM que sustituya la clave pública en el primer connect |
| `wss://` obligatorio en browsers | `ws://` plano expondría el handshake PQC a un atacante de red |
| `SigningKey` bloqueada en memoria | `mlock(2)` previene que la clave privada sea swapeada a disco |
| Contexto de firma `"latticeshield-v1"` | Separa dominios entre versiones e implementaciones |
| Límite de conexiones por IP | Limita el costo de CPU de la verificación ML-DSA-65 bajo floods de conexiones |
| Timeout solo en handshake | El relay no tiene timeout — los casos de uso de streaming no son penalizados |

---

## Métricas Prometheus

Expuestas en `http://<metrics_addr>/metrics` (HTTP plano, sin autenticación).

| Métrica | Tipo | Descripción |
|---|---|---|
| `latticeshield_connections_total` | Counter | Total de conexiones aceptadas |
| `latticeshield_connections_active` | Gauge | Sesiones actualmente abiertas |
| `latticeshield_handshake_duration_seconds` | Histogram | Latencia del handshake PQC |
| `latticeshield_bytes_transmitted_total` | Counter | Total de bytes cifrados transmitidos |
| `latticeshield_channel_errors_total` | Counter | Errores AES-GCM / framing |
| `latticeshield_key_rotations_total` | Counter | Eventos de rotación de clave de sesión |

El endpoint `/metrics` retorna `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store` y una `Content-Security-Policy` estricta.

---

## Estructura del workspace

```
latticeshield/
├── latticeshield-crypto/             # ML-KEM-768, X25519, ML-DSA-65, AES-256-GCM, HKDF
├── latticeshield-bridge/             # Binario del proxy inverso + todos los listeners + config
├── latticeshield-client/             # Proxy cliente PQC server-side (server-to-server)
├── latticeshield-cli/                # CLI unificado de gestión de claves (binario `latticeshield`)
├── latticeshield-wasm/               # latticeshield-crypto compilado a WASM (para browsers)
├── latticeshield-js/                 # Paquete npm @latticeshield/js (PQCSession, usePQCSession)
└── latticeshield-integration-tests/  # Tests de clasificación de reconexión por protocolo (solo dev)
```

---

## Compilar desde el código fuente

```sh
# Requiere Rust 1.75+
cargo build --release -p latticeshield-bridge   # daemon proxy inverso
cargo build --release -p latticeshield          # CLI de gestión de claves
cargo build --release -p latticeshield-client   # proxy cliente PQC server-side

# Compilar el módulo WASM del browser (requiere wasm-pack)
wasm-pack build --target bundler latticeshield-wasm

# Compilar el SDK de JavaScript
cd latticeshield-js && npm install && npm run build
```

---

## Tests

```sh
cargo test --workspace                    # 467 tests en Rust
cd latticeshield-js && npm test           # 93 tests en TypeScript
```

| Crate / Paquete | Tests | Cobertura destacada |
|---|---|---|
| `latticeshield-bridge` | 355 (135 unit lib + 209 unit main + 11 integración) | Validación de config, integración TCP/WebSocket/TLS, límite por IP, canal admin |
| `latticeshield-client` | 49 (47 unit + 2 integración) | Ciclo de vida del proxy cliente, handshake PQC, config, reconexión automática |
| `latticeshield-crypto` | 45 | Vectores de handshake, anti-replay, rotación de clave, separación de dominio de firma |
| `latticeshield-cli` | 7 | Integración CLI de gestión de claves |
| `latticeshield-wasm` | 1 | Paridad de wire format WASM↔Rust |
| `latticeshield-integration-tests` | 10 (2 gRPC + 2 HTTP + 1 matrix + 5 TCP raw) | Clasificación de reconexión por protocolo, invariante de claves efímeras PQC |
| `latticeshield-js` | 93 | Ciclo de vida de PQCSession, copia de VK, cierre inesperado, framing, layout de nonce |

---

## Novedades

### v0.3.3 — Parches de seguridad de dependencias + Builds reproducibles (2026-05-22)

`Cargo.lock` ahora se trackea en el control de versiones, habilitando que Dependabot resuelva versiones exactas y permitiendo builds bit-a-bit reproducibles entre máquinas. El lockfile estaba previamente gitignored como default de `cargo new --lib` — un residuo de cuando el workspace era solo lib y nunca se revisó después de que el bridge y el client se sumaran como binarios.

Cierra 5 alertas de Dependabot vía bumps transitivos de patch: `libcrux-ml-dsa` 0.0.8 → 0.0.9 (fix del `use_hint` en AVX2 — GHSA-fhvh-vw7h-9xf3), `rustls-webpki` 0.103.10 → 0.103.13 (panic en parsing de CRL + fixes de name constraints), y `rand` 0.8.5/0.9.2 → 0.8.6/0.9.4 (fix de soundness en `rng()`). El deployment de producción no era explotable en ningún caso (backend portable de ML-DSA, sin validación de CRL, sin URI name constraints, sin logger custom de `rand`), pero el upgrade reduce la superficie de riesgo y limpia cuatro ignores del `deny.toml`.

También limpia un backlog de 17 fixes de clippy 1.94 que tenía CI rojo en `main` desde el refresh del toolchain. Sin cambio de comportamiento.

### v0.3.2 — Reconexión PQC automática server-side (2026-05-15)

`latticeshield-client` ahora soporta reconexión automática transparente con backoff exponencial. Cuando el bridge cierra una sesión, el cliente re-establece la conexión silenciosamente realizando un handshake PQC completo y fresco en cada intento (ML-KEM-768 + X25519 + ML-DSA-65). Sin reutilización de sesión ni de claves, nunca.

Opt-in via la sección `[reconnect]` del TOML (`max_retries = 0` por defecto, preservando el comportamiento actual). Un canal `ReconnectEvent` le avisa a la app cuando ocurre una reconexión para que pueda re-inicializar el estado del protocolo (re-suscribirse a Redis, reintentar transacciones PostgreSQL, reabrir streams gRPC). Los fallos de autenticación (firma VK incorrecta) nunca se reintentan — se propagan de inmediato.

El nuevo crate `latticeshield-integration-tests` clasifica el comportamiento de reconexión por protocolo e incluye un test `reconnect_pqc_invariant` que verifica claves efímeras frescas en cada reconexión comparando dos payloads consecutivos del wire `ClientResponse`.

### v0.3.1 — Reconexión automática del SDK del browser + fixes de CLI (2026-05-14)

Se corrigieron dos bugs que hacían que la reconexión automática en `@latticeshield/js` estuviera permanentemente rota. La clave pública del servidor se zeroeaba silenciosamente después del primer handshake (detachment de buffer Transferable), y los cierres inesperados de WebSocket no se detectaban (no se emitía el evento `close`). El hook `usePQCSession` ya tenía lógica completa de reconexión — ahora se dispara correctamente. También se corrige un mismatch de layout en `seqToNonce` (bytes 4–11 en lugar de 0–7) que causaba fallos de descifrado desde el segundo frame en adelante.

`latticeshield vk-share` fue reescrito para usar el canal admin PQC real (`--admin-addr`, `--bridge-vk`, `--admin-sk`) en lugar de un endpoint HTTP Bearer que no existía. El bind por defecto del canal admin cambió de `0.0.0.0:8445` a `127.0.0.1:8445` — solo loopback por defecto, se necesita config explícita para acceso remoto.

### v0.3.0 — Hardening de seguridad (2026-05-13)

Cierra 9 hallazgos pendientes de auditoría de seguridad. Introduce separación de dominio ML-DSA-65 (contexto de firma `latticeshield-v1`), normalización de origen WebSocket (RFC 6454), protección contra DoS en el store de tokens VK (cap 1000, evicción, HTTP 429), headers de seguridad en `/metrics`, límite de conexiones TCP por IP, timeout dedicado para el handshake PQC, y corrección de una función de descarga de clave rota en el SDK JavaScript. Bump de versión 0.2.0 → 0.3.0 (breaking: cambio de contexto de firma).

---

## Contribuir

Los pull requests son bienvenidos. Antes de abrir uno:

1. `cargo test --workspace` — todos los tests de Rust deben pasar
2. `cd latticeshield-js && npm test` — todos los tests de TypeScript deben pasar
3. `cargo fmt --check` — el código debe estar formateado
4. `cargo clippy -- -D warnings` — sin nuevas advertencias

Para cambios más grandes que un bugfix, abrí un issue primero para discutir el enfoque antes de escribir código. El proyecto sigue [Conventional Commits](https://www.conventionalcommits.org/). No incluyas atribuciones de IA en los mensajes de commit.

---

## Licencia

Apache 2.0 — ver [LICENSE](LICENSE).
