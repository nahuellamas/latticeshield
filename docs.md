main.rs — El punto de entrada

Es el primer archivo que ejecuta Rust cuando arrancás el programa. Hace exactamente tres cosas:

1. Parsear los argumentos de línea de comandos (con la librería clap):
   latticeshield-bridge → arranca el proxy (modo normal)
   latticeshield-bridge --config mi.toml → usa un config custom
   latticeshield-bridge keygen ./keys → genera las claves ML-DSA-65 del servidor (DEPRECATED desde Mes 10)
   latticeshield-bridge tls-keygen ./keys → genera cert.pem + key.pem para el listener TLS/QUIC (DEPRECATED desde Mes 10)

   NOTA: los subcomandos keygen y tls-keygen del bridge imprimen un aviso de deprecación desde Mes 10. Usar el nuevo binario `latticeshield` en su lugar. Serán removidos en Mes 11.

clap genera automáticamente el --help, el --version, y valida que los argumentos sean correctos.

2. Si el comando es keygen: llama a identity::ServerIdentity::generate_and_save() y termina.
   Si el comando es tls-keygen: llama a tls::generate_self_signed() (requiere --features tls-keygen) y termina.
   Estos subcomandos no arrancan el proxy.

3. Si no hay subcomando: carga el config.toml, inicializa los logs, y llama a server::run(config) — que es el loop infinito del proxy.

El #[tokio::main] es una macro que le dice a Rust: "esta función main es async — iniciá el runtime de tokio antes de ejecutarla". Tokio es el motor que permite manejar miles de conexiones simultáneas sin
bloquear.

---

server.rs — El oído del sistema

Su responsabilidad es arrancar todos los listeners y despachar conexiones a tareas individuales.

server::run()
|
├── crea el canal de rotación: watch::channel(0u64)
├── carga identity (claves ML-DSA) desde disco
├── inicia servidor HTTP de métricas en :8444 (GET /metrics + POST /rotate)
├── si quic.enabled → spawn_quic_listener() en :8441 (UDP)
├── si tls.enabled  → spawn_tls_listener() en :8440 (TCP)
├── inicia heartbeat al control plane (si está configurado)
|
└── loop infinito en :8443:
    acepta conexión TCP → spawn(session::handle())

Hay tres listeners independientes corriendo en paralelo vía tokio::spawn():

1. spawn_quic_listener(): crea un quinn::Endpoint en UDP, acepta conexiones QUIC, y por cada conexión llama a QuicRelay::relay_connection(). Es opt-in: solo se inicia si [quic] enabled = true en config.toml.

2. spawn_tls_listener(): crea un TcpListener en :8440, hace el handshake TLS con rustls, y pasa el stream a HttpRelay::handle(). También opt-in: [tls] enabled = true.

3. Loop principal (PQC): el listener original en :8443. Siempre activo.

El tokio::spawn() es clave: crea una tarea async nueva para cada conexión. Esas tareas corren concurrentemente sin bloquear entre sí. Si hay 500 clientes conectados al mismo tiempo, hay 500 tareas corriendo en paralelo — pero sin crear 500 threads del sistema operativo (Tokio los multiplexa eficientemente).

Arc::clone(&identity) — el Arc es un "puntero con contador de referencias". Permite que las 500 tareas compartan el mismo objeto ServerIdentity en memoria sin copiarlo. Cuando todas las tareas terminan, el Arc se destruye automáticamente.

El canal de rotación usa tokio::sync::watch — un canal de broadcast de un solo valor:

let (rotate_tx, _) = watch::channel(0u64);
let rotate_tx = Arc::new(rotate_tx);

Cada sesión llama a rotate_tx.subscribe() para obtener su propio receiver. Cuando alguien hace POST /rotate, el handler incrementa el valor del canal. Todas las sesiones activas detectan el cambio via rotate_rx.changed() y rotan su clave de forma independiente.

POST /rotate responde con {"rotated": N} donde N es el número de sesiones activas en ese momento.

---

session.rs — El cerebro de cada conexión

Este es el archivo más importante. Cada vez que un cliente se conecta, server.rs crea una tarea que ejecuta session::handle(). Esta función:

Paso 1 — Handshake PQC:
Genera claves efímeras (X25519 + ML-KEM)
Firma el ServerHello con ML-DSA (la clave de largo plazo del servidor)
Envía el ServerHello firmado al cliente → espera ClientResponse
Deriva la SessionKey con HKDF sobre los dos secretos

Paso 2 — Conectar al backend:
Abre una segunda conexión TCP hacia tu aplicación (127.0.0.1:8080 por defecto).

Paso 3 — Relay bidireccional con rotación de clave:
loop {
select! {
cliente → backend: lee frame → si es DATA: descifra → forwarda al backend
                              → si es KEY_ROTATE: error (server-initiated only)
backend → cliente: lee plaintext → cifra → escribe frame al cliente
                                 → acumula bytes; si superó el umbral → rotar
timer de tiempo: si key_rotation_enabled y pasó el intervalo → rotar
señal manual:    si llegó POST /rotate → rotar
}
if should_rotate { do_rotate() }
}

El select! tiene cuatro brazos. Los tres triggers de rotación (bytes, tiempo, POST /rotate) devuelven true. Los brazos de datos devuelven false. El select! se usa como expresión que retorna bool — así podés hacer if should_rotate { ... } DESPUÉS de que el select! termine, cuando ya no hay borrows activos sobre el canal.

¿Por qué el if después y no dentro? AES-GCM necesita &mut self para rotar la clave (rotate_key modifica los internos del canal). Pero dentro del select!, el canal ya tiene un borrow &self por el read_frame() que está siendo polleado. Si intentás hacer &mut mientras &self está activo, el compilador de Rust te para. La solución: el select! devuelve un bool, y el &mut borrow solo se toma después de que el select! termina y libera todos sus borrows.

do_rotate() genera un nonce aleatorio, lo envía al cliente como KEY_ROTATE, y llama a channel.rotate_key(nonce). El cliente — que recibe el frame KEY_ROTATE — aplica el mismo HKDF con el mismo nonce y deriva la misma clave nueva. TCP garantiza el orden: el cliente siempre procesa el KEY_ROTATE antes que cualquier DATA frame cifrado con la clave nueva.

---

tls.rs — El constructor del listener HTTPS

Encapsula todo lo relacionado con rustls: cargar certificados, construir configuraciones, y generar certs de prueba.

Las tres funciones públicas principales:

load_certs(path) → carga un archivo PEM y retorna Vec<CertificateDer>. Usa rustls-pemfile.
load_private_key(path) → carga la clave privada PEM. Retorna error si el archivo no tiene ninguna clave.
build_server_config(cert_path, key_path) → construye un Arc<rustls::ServerConfig> con no_client_auth. Es la función base: tanto el listener TLS como el QUIC la usan para obtener su configuración criptográfica.
build_acceptor(cert_path, key_path) → envuelve build_server_config() en un TlsAcceptor (para tokio-rustls). Lo usa el listener TCP/TLS.
generate_self_signed(dir) → genera cert.pem + key.pem usando rcgen. Solo disponible con --features tls-keygen. Útil para desarrollo y tests.

¿Por qué build_server_config está separado de build_acceptor?

El listener TLS necesita un TlsAcceptor (tipo de tokio-rustls).
El listener QUIC necesita un rustls::ServerConfig crudo (quinn lo convierte internamente).
Ambos comparten la misma lógica de carga. Separar las funciones evita duplicar el código de cert/key loading.

---

http_relay.rs — El relay HTTP/1.1 para clientes estándar

Cuando un cliente se conecta al listener TLS (:8440), no habla el protocolo PQC custom — habla HTTP/1.1 normal. http_relay.rs se encarga de parsear ese request y forwardearlo al backend.

Flujo de handle(tls_stream, peer):

1. Lee bytes del stream TLS hasta encontrar \r\n\r\n (fin de los headers HTTP).
   Usa httparse para detectar cuándo los headers están completos.
   Si los headers superan 8 KiB → responde 400 Bad Request y cierra.

2. Conecta al backend por TCP.
   Si falla → responde 502 Bad Gateway y cierra.

3. Forwarda el buffer completo (headers + body inicial ya leído) al backend.

4. Relay bidireccional con tokio::select!:
   cliente → backend: tokio::io::copy(&mut client_read, &mut backend_write)
   backend → cliente: tokio::io::copy(&mut backend_read, &mut client_write)

¿Por qué select! acá y try_join! en el relay QUIC?

HTTP/1.1 sobre TCP tiene semántica de "una sola respuesta por conexión" en el caso básico. Cuando el backend termina de responder y cierra, el select! lo detecta y cierra también el lado del cliente. Es comportamiento correcto para HTTP/1.1.

QUIC tiene half-close por stream: cada stream se cierra independientemente en cada dirección. Usar select! en QUIC causaría data loss silencioso. Por eso quic.rs usa try_join! — espera que AMBAS direcciones terminen.

---

quic.rs — El relay QUIC (raw streams)

Implementa un relay de streams QUIC → TCP sin HTTP/3 framing. Cada stream QUIC bidi es independiente y se mapea a una conexión TCP fresca al backend.

Las dos funciones/tipos principales:

build_endpoint(cert_path, key_path, listen_addr) → construye un quinn::Endpoint. Internamente llama a tls::build_server_config() y lo convierte al formato que quinn espera (QuicServerConfig). Bindea un socket UDP.

QuicRelay { backend_addr } — struct con Clone (necesario para moverse dentro de tokio::spawn).

relay_connection(conn): loop que acepta streams bidi del cliente QUIC. Por cada stream, spawnea una tarea que llama a relay_stream(). Si la conexión se cierra normalmente (ApplicationClosed / LocallyClosed), el loop termina limpiamente.

relay_stream(send, recv): el corazón del relay.
1. Conecta al backend por TCP.
2. Usa tokio::try_join! para correr ambas direcciones concurrentemente:
   recv (QUIC) → backend_write (TCP)
   backend_read (TCP) → send (QUIC)
3. OBLIGATORIO: llama send.finish() después del try_join!.

¿Por qué send.finish() es obligatorio?

En quinn 0.11, el SendStream NO llama finish() al ser dropeado. Si no lo llamás explícitamente, el peer QUIC remoto queda esperando EOF para siempre — la conexión se cuelga. Este es el gotcha más importante de quinn 0.11.

¿Por qué try_join! y no select!?

QUIC soporta half-close: el cliente puede cerrar su lado del stream (dejar de enviar) sin cerrar el lado del servidor. select! cancela la dirección "perdedora" y dropea los bytes pendientes. try_join! espera que ambas terminen. quinn::RecvStream devuelve Ok(0) cuando recibe el FIN del peer, por lo que la copia termina naturalmente.

---

channel.rs — La caja fuerte del cable (latticeshield-crypto)

> Este módulo vivía en `latticeshield-bridge/src/channel.rs` hasta Mes 8. Se movió a `latticeshield-crypto/src/channel.rs` para que tanto el bridge como el client compartan la misma implementación sin duplicación.

EncryptedChannel encapsula el cifrado AES-256-GCM. Define cómo se ve un "frame" (paquete) en el wire. Hay dos tipos de frames:

DATA frame (tipo 0x01):
[1 byte: 0x01 — tipo DATA]
[4 bytes: longitud del ciphertext]
[12 bytes: nonce aleatorio]
[N bytes: datos cifrados + tag GCM de 16 bytes]

KEY_ROTATE frame (tipo 0x02):
[1 byte: 0x02 — tipo KEY_ROTATE]
[32 bytes: nonce de derivación]

El primer byte de cada frame indica qué tipo es. Si llega un 0x00 o cualquier valor desconocido, el canal cierra la sesión — un buffer de ceros accidentalmente enviado no se interpreta como datos válidos.

¿Por qué un nonce por frame? AES-GCM tiene una regla crítica: NUNCA reutilizar el mismo nonce con la misma clave. Si lo hacés, la seguridad colapsa completamente. Generamos un nonce aleatorio nuevo por cada frame — así es imposible repetirlo.

El tag GCM (16 bytes al final del ciphertext): es una firma criptográfica. Si alguien modifica los datos en el wire (un byte que sea), el tag no va a coincidir y el decrypt va a fallar. Esto garantiza integridad además de confidencialidad.

write_frame() → prepend 0x01 + cifra + escribe al socket.
read_frame() → lee el tipo → si es DATA: descifra → retorna FrameResult::Data(Vec<u8>).
                             → si es KEY_ROTATE: retorna FrameResult::KeyRotate([u8; 32]).
send_key_rotate() → escribe [0x02][32B nonce] al socket — sin cifrar.
rotate_key(nonce) → KDF ratchet: deriva una nueva clave via HKDF-SHA256 y reemplaza el cipher.

La rotación de clave usa un ratchet KDF:
new_key = HKDF-SHA256(ikm=current_key, salt=nonce, info="latticeshield-v1-key-rotation")

Para hacer ese ratchet, EncryptedChannel necesita los bytes raw de la clave actual. Problema: AES-256-GCM toma la clave en la construcción y no te la devuelve. Solución: guardamos la clave en un campo extra:

key_bytes: Zeroizing<[u8; 32]>

Zeroizing<T> es un wrapper que garantiza que cuando el campo es reemplazado (o cuando el struct se destruye), los bytes de la clave son sobreescritos con ceros en memoria. Así la clave vieja no queda flotando en RAM después de una rotación.

---

identity.rs — El guardián de las claves del servidor

El servidor tiene un par de claves ML-DSA-65 de largo plazo:

- server.sk — Signing Key (clave de firma, SECRETA, 4032 bytes)
- server.vk — Verifying Key (clave pública, se distribuye a los clientes, 1952 bytes)

ServerIdentity::load() hace varias cosas de seguridad que valen la pena entender:

1. Chequea los permisos del archivo:
   if mode != 0o600 {
   bail!("permisos inseguros")
   }
   0o600 en Unix significa "solo el dueño puede leer y escribir, nadie más". Si el archivo tiene permisos más abiertos (por ejemplo, 0o644 = "todos pueden leer"), el proxy rechaza arrancar. Una clave privada que puede leer cualquier usuario del sistema ya está comprometida.

2. Zeroiza el buffer de lectura:
   let mut sk_buf = [0u8; SIGNING_KEY_LEN];
   // ... lee el archivo en sk_buf ...
   let signing_key = SigningKey::from_bytes(&sk_buf)?;
   sk_buf.zeroize(); // ← borra los bytes del buffer
   Después de crear el SigningKey desde el buffer, borra el buffer. Así los bytes de la clave no quedan flotando en RAM en dos lugares — solo en el SigningKey (que además tiene mlock para no ir a swap).

ServerIdentity::generate_and_save() genera el par de claves y los guarda con los permisos correctos desde el momento de creación — sin window de vulnerabilidad donde el archivo existe con permisos incorrectos.

---

config.rs — El lector del config.toml

Implementa un patrón de dos pasos:

Paso 1 — Config (raw): lee el TOML y lo convierte en structs de Rust. Si el TOML está mal escrito, falla aquí con un error claro. Cada campo tiene un valor por defecto para no obligar al usuario a poner todo.

Paso 2 — ValidConfig (validado): convierte los strings en tipos reales y valida semántica:
// Convierte "0.0.0.0:8443" en un SocketAddr real
let listen_addr: SocketAddr = self.server.listen_addr.parse()?;

// Valida que max_frame_size esté en rango [1KB, 16MB]
if self.server.max_frame_size < 1024 || > 16*1024*1024 {
bail!("fuera de rango")
}

El resto del programa solo recibe ValidConfig — nunca toca los strings. Si llegaste a ValidConfig, sabés que todos los valores son correctos. Esto elimina una categoría entera de bugs de configuración en runtime.

La estructura del config.toml:
[server]
listen_addr = "0.0.0.0:8443"    # listener PQC custom (siempre activo)
backend_addr = "127.0.0.1:8080"

[crypto]
signing_key_path = "./keys/server.sk"

[metrics]
listen_addr = "0.0.0.0:8444"

[logging]
level = "info"

[tls]
enabled = false                   # listener HTTPS estándar (:8440)
listen_addr = "0.0.0.0:8440"
cert_path = "./keys/cert.pem"    # requerido si enabled = true
key_path = "./keys/key.pem"      # requerido si enabled = true

[quic]
enabled = false                   # listener QUIC/UDP (:8441)
listen_addr = "0.0.0.0:8441"
cert_path = "./keys/cert.pem"    # puede compartir cert con [tls]
key_path = "./keys/key.pem"

[control_plane]
enabled = false
endpoint = "http://tu-control-plane:9000"

[key_rotation]
enabled = false           # activar rotación automática de clave de sesión
max_bytes_per_key = 10737418240   # rotar después de 10 GB transmitidos
max_seconds_per_key = 86400       # rotar después de 24 horas

Las secciones [tls], [quic] y [key_rotation] son completamente opcionales — si no las ponés, los defaults se aplican (disabled) y esos listeners no se inician. La validación rechaza configuraciones inconsistentes: enabled = true sin cert_path/key_path falla al arrancar con un error claro. También detecta colisiones de puertos entre listeners.

---

metrics.rs — El tablero de instrumentos

Expone métricas de rendimiento en formato Prometheus (un estándar de monitoreo). Se consultan haciendo un HTTP GET a http://servidor:8444/metrics.

Las métricas actuales:
latticeshield_connections_total → cuántas conexiones recibió en total
latticeshield_connections_active → cuántas están activas ahora mismo
latticeshield_handshake_duration_secs → histograma de tiempo de handshake
latticeshield_bytes_transmitted_total → bytes de datos que pasaron por el proxy
latticeshield_channel_errors_total → errores de descifrado (posibles ataques)
latticeshield_key_rotations_total → cuántas rotaciones de clave de sesión se realizaron

El problema con metrics: la librería metrics solo permite escribir métricas (con macros como metrics::counter!(...).increment(1)). No tiene API de lectura. Esto es intencional — es una fachada para Prometheus.

El problema es que el heartbeat al control plane necesita leer esos valores para enviarlos. Solución: MetricsState, una struct con contadores AtomicU64 que escribimos en paralelo en los mismos lugares:

// En session.rs, cada vez que llega una conexión:
metrics::counter!(CONNECTIONS_TOTAL).increment(1); // → Prometheus
metrics_state.connections_total.fetch_add(1, Ordering::Relaxed); // → legible

AtomicU64 es un entero de 64 bits que puede ser leído y escrito desde múltiples tareas simultáneamente sin race conditions — sin locks, sin mutexes.

MetricsActiveGuard es un RAII guard: cuando se crea, incrementa connections_active. Cuando se destruye (al terminar la sesión), lo decrementa. Así no podés olvidarte de decrementar — Rust lo hace automáticamente.

---

---

# latticeshield-client

---

main.rs (client) — El punto de entrada del agente cliente

Hace tres cosas:

1. Parsear los argumentos de línea de comandos (con clap):
   latticeshield-client → arranca el proxy cliente (modo normal)
   latticeshield-client --config mi.toml → usa un config custom
   latticeshield-client vk-info ./keys/server.vk → imprime el fingerprint SHA-256 de la VerifyingKey

2. Si el comando es vk-info: carga la VK, imprime el fingerprint (hex de 64 chars) y el tamaño (1952 bytes). Termina sin arrancar ningún listener.

3. Si no hay subcomando: carga el config.toml del cliente, inicializa tracing, carga la VerifyingKey del servidor, y llama a server::run(config, vk).

---

config.rs (client) — El lector del config del cliente

Mismo patrón de dos pasos que el bridge:

Paso 1 — ClientConfig (raw): lee el TOML. Cada campo tiene defaults.
Paso 2 — ValidClientConfig (validado): convierte strings en tipos reales.

La estructura del latticeshield-client.toml:
[client]
listen_addr  = "127.0.0.1:9090"   # donde escucha el cliente (plain TCP local)
bridge_addr  = "127.0.0.1:8443"   # dirección del bridge (protocolo PQC)
max_frame_size = 65536             # tamaño máximo de frame AES-GCM (bytes)

[crypto]
server_vk_path = "./keys/server.vk"   # VerifyingKey ML-DSA-65 del servidor (pre-shared)

[logging]
level = "info"

Validaciones:
- listen_addr y bridge_addr deben ser SocketAddr válidos
- max_frame_size en [1024, 16 MiB]
- server_vk_path no puede estar vacío

---

identity.rs (client) — El lector de la VerifyingKey del servidor

load_verifying_key(path) carga el archivo server.vk:
1. Lee los bytes del archivo.
2. Valida que tenga exactamente VERIFYING_KEY_LEN = 1952 bytes. Si no, falla al startup.
3. Parsea a VerifyingKey. Si el archivo está corrupto, falla al startup.
4. No verifica permisos (la VK es pública — 0o644 es correcto).

fingerprint(vk) → SHA-256 de los bytes raw de la VK → string hex de 64 chars.
Útil para verificar que todos los clientes tienen la misma VK que el servidor.

A diferencia de identity.rs del bridge (que carga la clave PRIVADA con mlock y permisos 0o600),
el cliente solo carga la clave pública. No hay secreto que proteger, pero sí hay que validar la integridad del archivo.

---

server.rs (client) — El dispatcher

Responsabilidad: escuchar en listen_addr y despachar conexiones.

run(config, Arc<VerifyingKey>):
1. TcpListener::bind(config.listen_addr) → fatal si falla (proceso termina).
2. Log "LatticeShield Client listening" + "targeting bridge".
3. loop { listener.accept() → tokio::spawn(client_session::handle()) }

Un error en una sesión no detiene al listener — las otras sesiones siguen funcionando.

---

client_session.rs — El cerebro de cada conexión cliente

Es el simétrico de session.rs en el bridge. Cada vez que un usuario se conecta:

Paso 1 — Conectar al bridge:
TcpStream::connect(config.bridge_addr)
Si falla → shutdown del lado usuario → return Ok(()) (error de sesión, no fatal)

Paso 2 — Handshake PQC (lado cliente):
1. read_exact([u8; SERVER_HELLO_SIGNED_LEN=4557]) — lee el ServerHello firmado del bridge
2. parse_server_hello_signed(&bytes, &vk) — verifica la firma ML-DSA-65 con la VK pre-shared
   Si falla → log WARN "authentication failed" → shutdown usuario → return Ok(())
3. client_respond(&hello, &mut OsRng) → (ClientResponse, SessionKey)
4. write_all(&serialize_client_response(&response)) — envía los 1120 bytes al bridge
5. EncryptedChannel::new(session_key.as_bytes(), config.max_frame_size)

Paso 3 — Relay bidireccional con tokio::select!:
loop {
  select! {
    usuario → bridge: read plain bytes → channel.write_frame(bridge)
    bridge → usuario: channel.read_frame(bridge)
                     → Data(d): write plain to user
                     → KeyRotate(nonce): channel.rotate_key(nonce) [transparente al usuario]
                     → Err: log WARN + break
  }
}

La diferencia clave con session.rs del bridge:
- El bridge GENERA KEY_ROTATE (lo inicia).
- El cliente RECIBE KEY_ROTATE (lo aplica transparentemente, nunca lo genera).

¿Por qué la verificación de firma falla silenciosamente (Ok()) en vez de propagar el error?
Porque es un error de seguridad a nivel de sesión — posible ataque MITM o misconfiguration.
No es un bug del proceso. Cerramos esa conexión, loguemos, y seguimos aceptando otras.

---

control_plane.rs — El informante

Cuando la aplicación SaaS de LatticeShield (que todavía no existe, es roadmap) esté lista, el bridge necesita reportarle su estado. Esto es lo que hace control_plane.rs.

Flujo al arrancar:

1. POST /api/v1/agents/register
   → manda: nombre, versión, capabilities, listen_addr, backend_addr
   ← recibe: agent_id (un string único asignado por el control plane)

2. Si el registro falla → loguea advertencia → desactiva heartbeat → el proxy sigue funcionando normal

3. Loop infinito (cada N segundos, configurable):
   POST /api/v1/agents/{agent_id}/heartbeat
   → manda: timestamp, uptime, status, métricas actuales

Lo más importante: es completamente no-fatal. Si el control plane está caído, el proxy no se detiene. Solo loguea una advertencia y sigue. El tráfico de tus clientes no se ve afectado.

reqwest es el cliente HTTP que usamos para hacer esos POST. serde_json convierte las structs de Rust en JSON automáticamente.

Los tests de este módulo usan wiremock — un servidor HTTP falso que levanta en memoria durante el test. Podés programarle respuestas específicas y verificar que el código mandó exactamente lo que debía.

---

---

# Mes 9 — Autenticación Mutua y Reconexión Automática

---

## El problema que existía

Hasta Mes 9, LatticeShield tenía autenticación en una sola dirección: el bridge le demostraba al cliente que era legítimo (firmando el ServerHello con ML-DSA-65), pero el cliente era completamente anónimo para el bridge.

Es como un boliche donde el portero te muestra su credencial para que sepas que es el portero real, pero a vos no te pide documento. Cualquiera que sepa la dirección del bridge podía intentar conectarse.

Eso significa que si alguien descubre la IP y el puerto del bridge, puede golpear la puerta. No va a poder descifrar nada (no tiene las claves de sesión), pero puede generar tráfico ilegítimo, ocupar recursos, o en el futuro intentar explotar alguna vulnerabilidad del protocolo.

La solución es **autenticación mutua**: ambos lados se identifican criptográficamente. El bridge verifica quién es el cliente antes de completar el handshake.

---

## Cómo funciona una firma digital (en términos simples)

Antes de entrar al código, conviene entender el concepto.

Una firma digital es matemáticamente equivalente a firmar un documento con tu puño y letra, pero con una propiedad extra: es **imposible de falsificar** y **verificable por cualquiera que tenga tu clave pública**.

Funciona con dos claves que forman un par:

- **Clave privada (SK — Signing Key)**: la guardás vos, nunca sale de tu máquina. Es con la que firmás. Si alguien la obtiene, puede hacerse pasar por vos.
- **Clave pública (VK — Verifying Key)**: la compartís con quien necesite verificar tu firma. No es secreta. Compartirla no compromete nada.

El proceso de autenticación es:
1. Vos firmás un mensaje con tu SK → produce una firma (un bloque de bytes)
2. El receptor tiene tu VK, el mensaje original, y la firma
3. La verificación matemática dice: "¿esta firma fue producida por el SK correspondiente a esta VK?" → sí o no

Si la firma no es válida, la conexión se cierra. Sin excepciones.

En LatticeShield usamos **ML-DSA-65** (un algoritmo resistente a computadoras cuánticas) para estas firmas. La clave privada ocupa 4032 bytes, la pública 1952 bytes, y la firma resultante 3309 bytes.

---

## latticeshield-crypto/src/handshake.rs — la nueva constante y las nuevas funciones

Este es el archivo que define el protocolo de comunicación entre bridge y cliente. Los cambios de Mes 9 agregan tres cosas:

### Nueva constante

```rust
pub const CLIENT_RESPONSE_SIGNED_LEN: usize = CLIENT_RESPONSE_LEN + SIGNATURE_LEN;
// = 1120 + 3309 = 4429 bytes
```

Antes el cliente mandaba 1120 bytes (datos puros de criptografía de sesión). Ahora manda 4429: los mismos 1120 bytes más una firma de 3309 bytes. Ambos lados tienen que saber exactamente cuántos bytes leer — por eso la constante.

### nueva función del lado cliente: serialize_client_response_signed

```rust
pub fn serialize_client_response_signed(
    resp: &ClientResponse,
    sk: &SigningKey,
    server_hello: &[u8; SERVER_HELLO_LEN],
    rng: &mut impl CryptoRngCore,
) -> Result<[u8; CLIENT_RESPONSE_SIGNED_LEN], HandshakeError>
```

Qué hace paso a paso:
1. Serializa el `ClientResponse` a sus 1120 bytes de siempre
2. Construye el **mensaje a firmar**: `CR_bytes (1120) || server_hello_raw (1248)` = 2368 bytes
3. Firma ese mensaje con `sk` usando ML-DSA-65 → produce 3309 bytes de firma
4. Retorna `[CR_bytes (1120) || firma (3309)]` = 4429 bytes — esto es lo que viaja por el cable

### nuevo método del lado servidor: complete_from_wire_signed

```rust
impl ServerHandshake {
    pub fn complete_from_wire_signed(
        self,
        bytes: &[u8; CLIENT_RESPONSE_SIGNED_LEN],
        client_vk: &VerifyingKey,
    ) -> Result<SessionKey, HandshakeError>
}
```

Es el método que el bridge llama para completar el handshake cuando la autenticación está habilitada:
1. Divide los 4429 bytes: primeros 1120 son el CR, últimos 3309 son la firma
2. Reconstruye el mensaje firmado: `CR_bytes || self.server_hello_raw`
3. Verifica la firma con `client_vk` → si falla, retorna `Err(HandshakeError::ClientAuthFailed)`
4. Si la firma es válida, llama al decap KEM interno igual que antes y deriva la SessionKey

### Por qué server_hello_raw y no server_hello_signed

El ServerHello tiene dos versiones:
- `server_hello_raw` (1248 bytes): los datos crudos del handshake (clave X25519 + clave KEM + nonce)
- `server_hello_signed` (4557 bytes): los datos crudos + la firma del servidor

La firma del cliente cubre el `server_hello_raw` (1248 bytes), no el signed (4557 bytes). Razón: la firma del servidor ya está separada — el cliente la verifica en su propio paso. Incluir la firma del servidor en la firma del cliente sería reduntante e inflaría el mensaje innecesariamente. Los 1248 bytes del raw ya contienen el nonce único que ata la firma a esta sesión específica.

Para que el bridge pueda usar `server_hello_raw` al verificar, `ServerHandshake` ahora lo guarda en un campo interno desde el momento en que se construye:

```rust
pub struct ServerHandshake {
    x25519_secret: EphemeralSecret,
    decap_key: DecapsulationKey<MlKem768>,
    nonce: [u8; 32],
    server_hello_raw: [u8; SERVER_HELLO_LEN],  // ← nuevo en Mes 9
}
```

Se llena en `new()` serializando la clave X25519 pública + la clave de encapsulación KEM + el nonce. Así el bridge siempre tiene esos bytes disponibles sin recomputar nada.

---

## latticeshield-bridge/src/identity.rs — ClientVerifyingIdentity

El bridge necesita cargar la clave pública del cliente para verificar sus firmas. Se agregó un nuevo struct al lado de `ServerIdentity`:

```rust
pub struct ClientVerifyingIdentity {
    pub verifying_key: VerifyingKey,
}

impl ClientVerifyingIdentity {
    pub fn load(vk_path: &Path) -> Result<Self, IdentityError> {
        let bytes = std::fs::read(vk_path)?;
        if bytes.len() != VERIFYING_KEY_LEN {
            return Err(IdentityError::WrongSize { expected: VERIFYING_KEY_LEN, got: bytes.len() });
        }
        let verifying_key = VerifyingKey::from_bytes(&bytes)?;
        Ok(Self { verifying_key })
    }
}
```

Diferencias con `ServerIdentity`:
- Solo carga la **clave pública** (VK), no la privada
- No verifica permisos del archivo (una clave pública no es secreta — 0o644 es correcto)
- No hay `zeroize` ni `mlock` (no hay material secreto que proteger)
- No tiene `generate_and_save()` — las claves las genera el cliente con `--client-keygen`, el bridge solo recibe el archivo `client.vk`

---

## latticeshield-bridge/src/config.rs — la sección [auth]

Se agregó una nueva sección opcional al `config.toml` del bridge:

```toml
[auth]
client_vk_path = "./keys/client.vk"
```

Si la sección existe y tiene `client_vk_path`, la autenticación mutua está habilitada. Si no está, el bridge funciona igual que antes (sin verificar al cliente).

En código, el config tiene:

```rust
#[derive(Debug, Deserialize, Default)]
pub struct AuthConfig {
    pub client_vk_path: Option<PathBuf>,
}
```

Y en `ValidConfig` se deriva un bool conveniente:

```rust
pub struct ValidConfig {
    // ... campos existentes ...
    pub client_auth_enabled: bool,       // true si client_vk_path está configurado
    pub client_vk_path: Option<PathBuf>, // la ruta al archivo client.vk
}
```

Así el resto del código pregunta `if config.client_auth_enabled { ... }` sin tener que hacer el `.is_some()` en cada lugar.

---

## latticeshield-bridge/src/server.rs — cargar la VK al arrancar

Cuando el bridge arranca, si `client_auth_enabled` es true, carga la VK del cliente en memoria y la pasa a cada sesión:

```rust
// Al arrancar:
let client_auth: Option<Arc<ClientVerifyingIdentity>> = if config.client_auth_enabled {
    let path = config.client_vk_path.as_ref().unwrap();
    Some(Arc::new(ClientVerifyingIdentity::load(path)?))
} else {
    None
};

// Al spawnear cada sesión:
tokio::spawn(session::handle(
    stream,
    backend_addr,
    Arc::clone(&identity),
    client_auth.clone(), // ← Option<Arc<...>> — None si auth deshabilitada
    // ...
));
```

El `Arc` (puntero con contador de referencias) permite que todas las sesiones simultáneas compartan el mismo objeto `ClientVerifyingIdentity` en memoria sin copiarlo. Funciona igual que con `ServerIdentity`.

---

## latticeshield-bridge/src/session.rs — el branching autenticado

Este es el cambio más visible en el bridge. Después de enviar el ServerHello firmado, en vez de leer siempre 1120 bytes, ahora hace un branch:

```rust
// Antes (Mes 8 y anteriores):
let mut response_buf = [0u8; CLIENT_RESPONSE_LEN]; // 1120 bytes siempre
stream.read_exact(&mut response_buf).await?;
let session_key = server_handshake.complete_from_wire(&response_buf)?;

// Ahora (Mes 9):
let session_key = match &client_auth {
    Some(client_identity) => {
        // Auth habilitada: leer 4429 bytes y verificar firma
        let mut buf = [0u8; CLIENT_RESPONSE_SIGNED_LEN];
        stream.read_exact(&mut buf).await?;
        server_handshake.complete_from_wire_signed(&buf, &client_identity.verifying_key)?
    }
    None => {
        // Auth deshabilitada: comportamiento original
        let mut buf = [0u8; CLIENT_RESPONSE_LEN];
        stream.read_exact(&mut buf).await?;
        server_handshake.complete_from_wire(&buf)?
    }
};
```

Si `complete_from_wire_signed` retorna `Err(ClientAuthFailed)`, la sesión se cierra y se loguea. El bridge sigue aceptando otras conexiones — es un error de sesión, no del proceso.

**Advertencia de compatibilidad**: si el bridge tiene `client_auth_enabled = true` pero el cliente no está configurado para firmar, el bridge va a bloquear esperando 4429 bytes mientras el cliente mandó solo 1120. La conexión va a colgarse hasta timeout. Ambos lados tienen que estar en el mismo modo.

---

## latticeshield-client/src/identity.rs — ClientIdentity

En el cliente, el archivo `identity.rs` ya existía, pero solo se usaba para cargar la VK del **servidor**. Ahora tiene un nuevo struct: la identidad propia del cliente.

```rust
pub struct ClientIdentity {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}
```

### load() — cargar desde disco

```rust
impl ClientIdentity {
    pub fn load(sk_path: &Path) -> Result<Self, IdentityError> {
        // 1. Verificar permisos: solo 0o600 es aceptable
        let meta = std::fs::metadata(sk_path)?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(IdentityError::InsecurePermissions { mode });
        }

        // 2. Leer exactamente SIGNING_KEY_LEN bytes (4032)
        let mut sk_buf = [0u8; SIGNING_KEY_LEN];
        File::open(sk_path)?.read_exact(&mut sk_buf)?;

        // 3. Construir SigningKey y derivar VerifyingKey
        let signing_key = SigningKey::from_bytes(&sk_buf)?;
        sk_buf.zeroize(); // ← borrar el buffer: la clave ya está en signing_key
        let verifying_key = signing_key.verifying_key();

        Ok(Self { signing_key, verifying_key })
    }
}
```

El check de permisos es idéntico al de `ServerIdentity` en el bridge. Si el archivo `client.sk` tiene permisos más abiertos que 0o600 (por ejemplo, 0o644 que significa "todos pueden leer"), el cliente rechaza arrancar. Una clave privada legible por otros usuarios del sistema está comprometida.

### generate_and_save() — generar un par de claves nuevas

```rust
pub fn generate_and_save(dir: &Path) -> Result<(), IdentityError> {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let sk_path = dir.join("client.sk");
    let vk_path = dir.join("client.vk");

    // Guardar SK con permisos 0o600 (solo el dueño puede leer/escribir)
    let mut sk_file = OpenOptions::new()
        .write(true).create(true).truncate(true)
        .mode(0o600)
        .open(&sk_path)?;
    sk_file.write_all(signing_key.as_bytes())?;

    // Guardar VK con permisos 0o644 (pública, todos pueden leer)
    let mut vk_file = OpenOptions::new()
        .write(true).create(true).truncate(true)
        .mode(0o644)
        .open(&vk_path)?;
    vk_file.write_all(verifying_key.as_bytes())?;

    Ok(())
}
```

Genera dos archivos en el directorio especificado:
- `client.sk` — 4032 bytes, permisos 0o600. Guardalo con cuidado.
- `client.vk` — 1952 bytes, permisos 0o644. Copialo al bridge.

### Zeroize on drop — borrar la clave cuando el proceso termina

```rust
impl Drop for ClientIdentity {
    fn drop(&mut self) {
        // Cuando ClientIdentity se destruye (proceso termina, o la variable sale de scope),
        // los bytes de la signing_key se sobreescriben con ceros antes de liberar la memoria.
        self.signing_key.zeroize();
    }
}
```

Esto garantiza que los bytes de la clave privada no queden flotando en RAM después de que el proceso termina. Sin esto, la memoria podría ser inspeccionada por otro proceso o quedar en un core dump.

---

## latticeshield-client/src/config.rs — client_sk_path y [reconnect]

El config del cliente tiene dos adiciones en Mes 9:

### client_sk_path — ruta a la clave privada del cliente

```toml
[client]
listen_addr   = "127.0.0.1:9090"
bridge_addr   = "127.0.0.1:8443"
max_frame_size = 65536
client_sk_path = "./keys/client.sk"   # ← nuevo en Mes 9 (opcional)
```

Si está presente, el cliente carga su identidad y firma los mensajes. Si no está, el cliente funciona en modo anónimo (igual que Mes 8). El bridge y el cliente tienen que estar de acuerdo.

### [reconnect] — configuración de reintentos

```toml
[reconnect]
max_retries    = 3    # cuántas veces reintentar antes de rendirse
base_delay_ms  = 500  # tiempo base de espera entre intentos (en milisegundos)
```

Ambos campos tienen defaults — si no ponés la sección, el comportamiento es `max_retries = 3` y `base_delay_ms = 500`. La sección completa es opcional.

---

## latticeshield-client/src/client_session.rs — firmar y reconectar

Este es el archivo más modificado en el cliente. Recibe dos parámetros nuevos: la identidad opcional y la config de reconexión.

### El loop de reconexión

Antes de Mes 9, si el bridge no estaba disponible al momento de conectar, el usuario recibía un error inmediato. Ahora:

```rust
let mut bridge_stream = None;
for attempt in 0..=reconnect.max_retries {
    match TcpStream::connect(bridge_addr).await {
        Ok(stream) => {
            bridge_stream = Some(stream);
            break;
        }
        Err(_) if attempt < reconnect.max_retries => {
            // Calcular tiempo de espera con backoff exponencial + jitter
            let base = reconnect.base_delay_ms;
            let jitter = OsRng.next_u64() % base;
            let delay = base * (1u64 << attempt) + jitter;
            //
            // attempt=0: espera entre 500ms y 1000ms
            // attempt=1: espera entre 1000ms y 1500ms
            // attempt=2: espera entre 2000ms y 2500ms
            //
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        Err(e) => return Err(e.into()), // agotó los intentos
    }
}
let bridge_stream = bridge_stream.unwrap();
```

El **backoff exponencial** significa que cada intento espera el doble que el anterior. El **jitter** es un número aleatorio que se suma para que si hay 100 clientes intentando reconectarse al mismo tiempo, no lo hagan todos exactamente en el mismo milisegundo y colapsen el bridge con 100 conexiones simultáneas.

**Regla crítica de seguridad**: el loop solo reintenta en **errores de transporte** (el bridge no está prendido, el puerto está cerrado). Si el handshake falla (firma inválida, VK incorrecta), el error es inmediato sin reintentos. Reintentar una autenticación fallida no tiene sentido y podría enmascarar problemas de configuración.

### Firmar el ClientResponse

Después de recibir y verificar el ServerHello del bridge, el cliente ahora puede firmar su respuesta:

```rust
// Guardar los primeros 1248 bytes del ServerHello (el raw, no el firmado)
let server_hello_raw: [u8; SERVER_HELLO_LEN] = signed_buf[..SERVER_HELLO_LEN]
    .try_into()
    .unwrap();

// ... calcular response y session_key como siempre ...

// Enviar: firmado o sin firmar según configuración
match &client_identity {
    Some(identity) => {
        let signed = serialize_client_response_signed(
            &response,
            &identity.signing_key,
            &server_hello_raw,
            &mut OsRng,
        )?;
        bridge_stream.write_all(&signed).await?; // 4429 bytes
    }
    None => {
        bridge_stream.write_all(&serialize_client_response(&response)).await?; // 1120 bytes
    }
}
```

---

## latticeshield-client/src/main.rs — el subcomando --client-keygen

Así como el bridge tiene `--keygen` para generar su par de claves, el cliente ahora tiene `--client-keygen`:

```
latticeshield-client --client-keygen ./keys
```

NOTA: este subcomando está DEPRECATED desde Mes 10. Imprime un aviso de deprecación y será removido en Mes 11. Usar `latticeshield keygen client ./keys` en su lugar.

Esto llama a `ClientIdentity::generate_and_save("./keys")` y genera:
- `./keys/client.sk` — clave privada (guardala, no la compartas)
- `./keys/client.vk` — clave pública (copiala al bridge)

Workflow completo para habilitar mutual auth (usando el nuevo CLI unificado, ver Mes 10):

```sh
# En la máquina del cliente: generar las claves
latticeshield keygen client ./keys

# Copiar la clave pública al bridge (scp, rsync, lo que uses)
scp ./keys/client.vk usuario@servidor-bridge:/etc/latticeshield/keys/

# En el bridge: configurar [auth] en config.toml
echo '[auth]' >> config.toml
echo 'client_vk_path = "/etc/latticeshield/keys/client.vk"' >> config.toml

# En el cliente: configurar client_sk_path en el toml
echo 'client_sk_path = "./keys/client.sk"' >> latticeshield-client.toml
```

---

## Por qué la firma está atada a la sesión (el ataque de replay)

Este es el detalle de seguridad más importante de la implementación.

Imaginá que la firma cubriera solo los datos del cliente (1120 bytes). Un atacante podría:
1. Espiar una conexión legítima y capturar los 4429 bytes que manda el cliente
2. En otra sesión diferente, mandar esos mismos 4429 bytes → la firma sería válida porque cubre los mismos datos

Esto se llama **replay attack** — reutilizar datos válidos de una sesión para otra.

La solución: la firma cubre `CR_bytes (1120) || server_hello_raw (1248)`. El `server_hello_raw` contiene un **nonce aleatorio de 32 bytes** que el bridge genera nuevo en cada sesión. Es imposible predecir o reproducir.

Entonces si el atacante captura los 4429 bytes de una sesión A e intenta usarlos en una sesión B:
- El bridge de la sesión B generó un nonce diferente
- La firma fue calculada con el nonce de la sesión A
- La verificación falla: `Err(ClientAuthFailed)`

La firma no solo dice "yo soy el cliente autorizado", sino "yo soy el cliente autorizado **y estoy respondiendo a esta sesión específica**".

---

---

# Mes 10 — CLI Unificado (`latticeshield`)

---

## El problema que existía

Hasta Mes 9, generar claves requería conocer tres binarios diferentes y sus flags específicos:

```sh
latticeshield-bridge keygen ./keys          # claves del servidor
latticeshield-client --client-keygen ./keys # claves del cliente
latticeshield-bridge tls-keygen ./keys      # cert TLS/QUIC
```

No hay UI consistente, no hay help centralizado, y el nuevo usuario no tiene forma de saber qué binario hace qué. Además, el subcomando `vk-info` solo existía en el cliente, escondido entre opciones que no tienen nada que ver con inspección de claves.

La solución: un nuevo crate `latticeshield-cli` que expone un único binario `latticeshield` con todos los subcomandos de setup y utilidades. Los binarios específicos del bridge y del client quedan para su rol operacional (arrancar el proxy), no para el setup inicial.

---

## latticeshield-cli — El crate nuevo

`latticeshield-cli` es un crate independiente en el workspace:

```
latticeshield/
├── latticeshield-cli/
│   └── src/
│       └── main.rs   # binario latticeshield — subcomandos keygen + vk-info
```

Características:
- Es **sync** (sin tokio) — todas las operaciones de keygen son operaciones de disco y criptografía síncrona. No hay ninguna razón para tener un runtime async.
- Depende de `latticeshield-bridge` como librería (via el nuevo target `[lib]`) y de `latticeshield-crypto` para el fingerprint SHA-256.
- Muestra un **banner ASCII** al arrancar: logo cyan con forma de lattice+shield, borde doble, título en blanco negrita, y subtítulo.
- 7 integration tests via `assert_cmd`.

---

## El banner de bienvenida

Al ejecutar `latticeshield` (sin subcomandos) o `latticeshield --help`, se muestra:

```
╔══════════════════════════════════╗
║   ▓▓▓  ▓  ▓▓▓  ▓▓▓▓  ▓▓▓▓      ║
║   ▓  ▓ ▓ ▓      ▓   ▓           ║
║   ▓▓▓  ▓ ▓      ▓   ▓  ▓▓▓      ║
║   ▓    ▓ ▓      ▓   ▓    ▓      ║
║   ▓    ▓  ▓▓▓  ▓▓▓▓  ▓▓▓▓       ║
║                                  ║
║   ▓▓▓  ▓  ▓  ▓▓▓  ▓▓▓  ▓  ▓▓▓  ║
║  ▓     ▓  ▓ ▓     ▓    ▓  ▓  ▓  ║
║   ▓▓   ▓▓▓▓ ▓ ▓▓▓ ▓▓▓  ▓  ▓  ▓  ║
║     ▓  ▓  ▓ ▓   ▓ ▓    ▓  ▓  ▓  ║
║  ▓▓▓   ▓  ▓  ▓▓▓  ▓▓▓  ▓  ▓▓▓   ║
╚══════════════════════════════════╝
         LatticeShield
  Quantum-Safe Reverse Proxy
```

El logo es cyan, el título es blanco negrita. Se renderiza con `colored`.

---

## Subcomandos

### `latticeshield keygen server <dir>`

Genera el par de claves ML-DSA-65 del servidor.

```sh
latticeshield keygen server ./keys
```

Genera en `<dir>`:
- `server.sk` — Signing Key, 4032 bytes, permisos `0o600` (solo el dueño puede leer)
- `server.vk` — Verifying Key, 1952 bytes, permisos `0o644` (pública, todos pueden leer)

Internamente llama a `ServerIdentity::generate_and_save(dir)` del crate `latticeshield-bridge`.

Equivalente deprecated: `latticeshield-bridge keygen <dir>`

---

### `latticeshield keygen client <dir>`

Genera el par de claves ML-DSA-65 del cliente.

```sh
latticeshield keygen client ./keys
```

Genera en `<dir>`:
- `client.sk` — Signing Key, 4032 bytes, permisos `0o600`
- `client.vk` — Verifying Key, 1952 bytes, permisos `0o644`

Internamente llama a `ClientIdentity::generate_and_save(dir)` del crate `latticeshield-bridge` (expuesto via el `[lib]` target).

Equivalente deprecated: `latticeshield-client --client-keygen <dir>`

---

### `latticeshield keygen tls <dir>`

Genera el certificado TLS auto-firmado para los listeners TLS y QUIC.

```sh
latticeshield keygen tls ./keys
```

Genera en `<dir>`:
- `tls.crt` — certificado PEM (rcgen)
- `tls.key` — clave privada PEM

El mismo par de archivos sirve para el listener TLS (`:8440`) y para el listener QUIC (`:8441`) — ambos usan `tls::build_server_config(cert_path, key_path)`.

Internamente llama a `tls::generate_self_signed(dir)` del crate `latticeshield-bridge`.

Equivalente deprecated: `latticeshield-bridge tls-keygen <dir>` / `latticeshield-bridge quic-keygen <dir>`

---

### `latticeshield vk-info <path>`

Imprime información de diagnóstico sobre cualquier archivo `.vk` (server.vk o client.vk).

```sh
latticeshield vk-info ./keys/server.vk
```

Salida:

```
File:    ./keys/server.vk
Size:    1952 bytes
SHA-256: a3f1c2d4e5b6...  (64 hex chars)
```

El fingerprint SHA-256 es útil para verificar que el bridge y todos los clientes tienen **exactamente la misma VK** — un mismatch en la VK causa fallas de autenticación silenciosas.

El subcomando acepta cualquier `.vk` — detecta si es server.vk o client.vk solo por el tamaño (ambos son 1952 bytes en ML-DSA-65).

Anteriormente este subcomando solo existía en `latticeshield-client` como `latticeshield-client vk-info <path>`. Ahora vive en el CLI unificado y el de cliente está deprecated.

---

## El `[lib]` target en latticeshield-bridge

Para que `latticeshield-cli` pueda llamar a `ServerIdentity::generate_and_save()` y `ClientIdentity::generate_and_save()` sin duplicar código, `latticeshield-bridge` expone un target `[lib]` en su `Cargo.toml`:

```toml
[lib]
name = "latticeshield_bridge"
path = "src/lib.rs"
```

El `lib.rs` re-exporta solo dos módulos públicos:

```rust
pub mod identity;
pub mod tls;
```

El resto (server, session, config, metrics, etc.) no es público — son internos al binario del bridge. Esto evita que `latticeshield-cli` dependa de tokio o de la lógica de red del bridge.

---

## Workflow completo de setup con el nuevo CLI

```sh
# 1. Generar claves del servidor (en la máquina del bridge)
latticeshield keygen server ./keys
# → ./keys/server.sk (0600) + ./keys/server.vk (0644)

# 2. Generar certificado TLS/QUIC (en la máquina del bridge)
latticeshield keygen tls ./keys
# → ./keys/tls.crt + ./keys/tls.key

# 3. Verificar el fingerprint del server.vk
latticeshield vk-info ./keys/server.vk
# → File: ./keys/server.vk | Size: 1952 bytes | SHA-256: ...

# 4. Distribuir server.vk a los clientes (out-of-band)
scp ./keys/server.vk usuario@maquina-cliente:/etc/latticeshield/keys/

# 5. (Opcional) Generar claves del cliente para mutual auth
latticeshield keygen client ./keys
# → ./keys/client.sk (0600) + ./keys/client.vk (0644)

# 6. Distribuir client.vk al bridge
scp ./keys/client.vk usuario@servidor-bridge:/etc/latticeshield/keys/
```

---

## Deprecaciones en Mes 10

Los siguientes subcomandos imprimen un aviso de deprecación al ejecutarse:

| Binario | Subcomando deprecated | Reemplazo |
|---------|----------------------|-----------|
| `latticeshield-bridge` | `keygen <dir>` | `latticeshield keygen server <dir>` |
| `latticeshield-bridge` | `tls-keygen <dir>` | `latticeshield keygen tls <dir>` |
| `latticeshield-bridge` | `quic-keygen <dir>` | `latticeshield keygen tls <dir>` |
| `latticeshield-client` | `--client-keygen <dir>` | `latticeshield keygen client <dir>` |
| `latticeshield-client` | `vk-info <path>` | `latticeshield vk-info <path>` |

Serán removidos en Mes 11.

---

## Tests del CLI (7 integration tests via assert_cmd)

| Test | Qué verifica |
|------|-------------|
| `keygen_server_creates_files` | `keygen server` genera `server.sk` (4032B, 0o600) y `server.vk` (1952B, 0o644) |
| `keygen_client_creates_files` | `keygen client` genera `client.sk` (4032B, 0o600) y `client.vk` (1952B, 0o644) |
| `keygen_tls_creates_files` | `keygen tls` genera `tls.crt` y `tls.key` |
| `vk_info_server_vk` | `vk-info server.vk` imprime File, Size (1952), SHA-256 (64 hex chars) |
| `vk_info_client_vk` | `vk-info client.vk` imprime File, Size (1952), SHA-256 |
| `vk_info_nonexistent` | `vk-info` con archivo inexistente retorna código de salida no-cero |
| `help_shows_banner` | `--help` incluye "LatticeShield" en la salida |

---

---

# Mes 12 — VK Share (`vk-share`)

---

## The problem that existed

After Mes 10, operators had a solid key management CLI but no automated way to distribute the server's VerifyingKey (VK) to new clients. The only path was to manually `scp` the `server.vk` file out-of-band to every machine that needed it. This worked fine in small deployments, but it had two problems:

1. **No cloud visibility.** When the bridge registered with the control plane (added in earlier milestones), the registration POST body contained only metadata — name, version, capabilities, addresses. The cloud had no way to cryptographically identify which ML-DSA-65 identity a given bridge instance was using. If two bridge instances registered, the cloud could not distinguish them by their signing key.

2. **No programmatic distribution.** An operator managing dozens of client machines had no mechanism to fetch the current VK from a running bridge instance without SSH access to the bridge server's filesystem.

Mes 12 solves both problems:
- The bridge now includes its ML-DSA-65 VerifyingKey (hex-encoded) in every registration POST to the control plane.
- A new `vk-share` mechanism allows an authenticated admin to request a one-time HTTPS download URL for the VK. Clients can retrieve the VK over TLS without needing filesystem access to the bridge.

---

## latticeshield-bridge/src/vk_share.rs — One-time token store for VK distribution

This is a new module responsible for generating and validating single-use, time-limited tokens that grant access to the bridge's VerifyingKey via `GET /vk/:token` on the TLS port (:8440).

### VkShareStore — the in-memory token store

```rust
pub type VkShareStore = Arc<Mutex<HashMap<String, VkShareEntry>>>;

pub struct VkShareEntry {
    pub vk_hex: String,        // lowercase hex encoding of the raw VK bytes (3904 chars)
    pub fingerprint: String,   // SHA-256 hex digest of the raw VK bytes (64 chars)
    pub expires_at: Instant,   // wall-clock expiry computed at token creation
    pub used: bool,            // single-use flag — set to true on first successful redemption
}
```

`VkShareStore` is a type alias for `Arc<Mutex<HashMap<String, VkShareEntry>>>`. It is initialized once at bridge startup with `vk_share::new_store()` and shared via `Arc::clone` between two places: the admin endpoint handler (which creates tokens) and the TLS listener (which redeems them).

**Why `Mutex` and not `RwLock`?** The `GET /vk/:token` handler that "reads" a token actually writes — it sets `entry.used = true` to enforce single-use semantics. Under any realistic workload, a token is redeemed once. A `Mutex` is simpler, has less surface area, and performs identically for this access pattern.

**Why in-memory only?** Tokens are ephemeral by design. If the bridge restarts, a token that was issued but not yet redeemed is lost. The operator simply requests a new one. Persisting tokens to disk would add complexity (and a new attack surface) for no meaningful benefit — tokens have a 10-minute TTL and grant access only to public material.

### create_token() — generating a token

```rust
pub fn create_token(store: &VkShareStore, vk_bytes: &[u8], ttl: Duration) -> (String, String) {
    let token = uuid::Uuid::new_v4().to_string();
    let vk_hex = hex_encode(vk_bytes);
    let fingerprint = sha256_hex(vk_bytes);
    let entry = VkShareEntry {
        vk_hex,
        fingerprint: fingerprint.clone(),
        expires_at: Instant::now() + ttl,
        used: false,
    };
    store.lock().unwrap().insert(token.clone(), entry);
    (token, fingerprint)
}
```

Tokens are UUID v4 strings — 122 bits of entropy from the OS CSPRNG via the `uuid` crate. The function returns both the token and the SHA-256 fingerprint so the admin sees the fingerprint immediately without having to redeem the token.

The SHA-256 fingerprint matches exactly what `latticeshield vk-info <path>` prints. This is intentional: an operator can compare the fingerprint from `vk-share` with the fingerprint from `vk-info` on the bridge machine to verify the VK is the same without having the raw bytes.

**Why no `hex` crate?** The codebase already uses `format!("{b:02x}")` for hex encoding in `latticeshield-client/src/identity.rs`. Adding a `hex` crate would introduce a new dependency for functionality that is trivially implementable with stdlib. Consistency with the existing pattern was preferred.

### vk_response() — serving the token on the TLS port

```rust
pub fn vk_response(token: &str, store: &VkShareStore, peer: SocketAddr) -> Vec<u8> {
    let mut guard = store.lock().unwrap();
    match guard.get_mut(token) {
        None => http_json_response(404, r#"{"error":"token not found"}"#),
        Some(entry) if entry.expires_at < Instant::now() => {
            guard.remove(token);
            http_json_response(410, r#"{"error":"token expired"}"#)
        }
        Some(entry) if entry.used => {
            http_json_response(410, r#"{"error":"token already used"}"#)
        }
        Some(entry) => {
            entry.used = true;
            let body = format!(
                r#"{{"server_vk":"{}","fingerprint":"{}"}}"#,
                entry.vk_hex, entry.fingerprint
            );
            http_json_response(200, &body)
        }
    }
}
```

This function returns raw HTTP/1.1 response bytes (not axum/hyper). It is synchronous — it only touches in-memory state. The caller in `spawn_tls_listener` writes these bytes directly to the TLS stream.

The lazy expiry pattern (checking `expires_at` at redemption time, not via a background task) is intentional. There are never enough tokens in the store to justify a background cleanup goroutine. The entry is removed immediately when an expired token is accessed, which prevents indefinite memory growth.

The response contains **only** `server_vk` and `fingerprint` — two fields, nothing else. The bridge's signing key never appears in any response, log, or error message.

### Why intercept on the TLS port (:8440) and not a dedicated port?

Clients that want to download the VK via `GET /vk/:token` are using standard HTTPS. Putting a dedicated endpoint on the TLS port means clients do not need any LatticeShield-specific tooling — a plain `curl` command works. The TLS listener was already handling HTTPS traffic; adding VK routing to it is a natural fit.

The routing logic (`extract_vk_token`) intercepts `GET /vk/<token>` and handles it locally. Every other path, and every other HTTP method on `/vk/` paths, is forwarded to the backend unchanged. This "GET only" restriction is a security decision: if the backend happens to have a `POST /vk/` API, the bridge does not silently hijack it.

The HTTP head is read before routing (up to an 8192-byte hard cap to prevent memory exhaustion from malformed requests that never send `\r\n\r\n`). If the head exceeds 8KB, the bridge responds `400 Bad Request` and closes the connection.

---

## latticeshield-bridge/src/control_plane.rs — server_vk in RegistrationPayload

### RegistrationPayload — the bridge tells the cloud who it is

```rust
#[derive(Serialize)]
struct RegistrationPayload {
    name: String,
    version: String,
    capabilities: Vec<String>,
    listen_addr: String,
    backend_addr: String,
    server_vk: String,   // lowercase hex-encoded ML-DSA-65 VerifyingKey (3904 chars)
    #[serde(skip_serializing_if = "Option::is_none")]
    install_token: Option<String>,
}
```

The `server_vk` field is the lowercase hexadecimal encoding of the ML-DSA-65 VerifyingKey — 1952 raw bytes encoded as 3904 hex characters. The cloud stores this to identify the bridge instance cryptographically and to verify heartbeat signatures (added in Mes 14).

The encoding is computed at registration time with no extra crate:

```rust
let server_vk: String = identity.verifying_key.to_bytes()
    .iter()
    .map(|b| format!("{b:02x}"))
    .collect();
```

`control_plane::start()` now accepts `Arc<ServerIdentity>` as a parameter alongside the existing `ValidConfig` and `Arc<MetricsState>`. This makes the VK available inside `try_register` without any global state or env-var lookup.

### Why hex and not base64 for server_vk?

`server_vk` is sent once at registration, not in every heartbeat. Wire size is not a concern. Hex is consistent with the rest of the codebase's convention (the `fingerprint` field in `vk-share`, the `vk-info` output, the existing `identity.rs` hex encoding). Base64 encoding was introduced in Mes 14 specifically for the heartbeat `signature` field where the 3309-byte signature at hex would be 6618 characters vs 4412 base64 characters — size matters there. For the VK, hex is the right call.

---

## latticeshield-cli/src/main.rs — the vk-share subcommand

The CLI gains a new top-level `VkShare` command that automates the admin interaction:

```rust
VkShare {
    /// Bridge admin URL (e.g. http://127.0.0.1:8444)
    #[arg(long, default_value = "http://127.0.0.1:8444")]
    bridge: String,

    /// Admin bearer token (can also be set via LATTICESHIELD_ADMIN_TOKEN env var)
    #[arg(long, env = "LATTICESHIELD_ADMIN_TOKEN")]
    token: String,
},
```

The command POSTs to `{bridge}/vk-token` with a `Authorization: Bearer <token>` header, then prints the resulting one-time URL and fingerprint:

```
One-time VK download URL:
  https://bridge.example.com:8440/vk/f47ac10b-58cc-4372-a567-0e02b2c3d479
Fingerprint (SHA-256):
  a3f1c2d4e5b6...
Expires in: 10 minutes (600 seconds)
```

The CLI uses `reqwest::blocking` — the CLI binary has no `#[tokio::main]` runtime and does not need one for a single synchronous HTTP request. Using the async reqwest API would require a `tokio::Runtime::new().unwrap().block_on(...)` wrapper for zero benefit.

The bearer token on `:8444` was a conscious security placeholder. The admin endpoint was intentionally protected to prevent unauthenticated access on a trusted network (localhost, private VPC). Mes 13 replaces this with full PQC mutual authentication — the `LATTICESHIELD_ADMIN_TOKEN` env var and the bearer token infrastructure are removed entirely in that milestone.

### Test coverage (260 tests total after Mes 12)

| Test | What it verifies |
|------|-----------------|
| `create_token_returns_uuid_v4` | Token string parses as UUID v4 |
| `create_token_fingerprint_is_sha256_hex` | Fingerprint is 64 lowercase hex chars |
| `vk_response_valid_token_returns_200` | First redemption → HTTP 200 |
| `vk_response_marks_token_used` | After redemption, `entry.used == true` |
| `vk_response_second_use_returns_410` | Second redemption → HTTP 410 Gone |
| `vk_response_expired_token_returns_410` | TTL=1ns then wait → HTTP 410 Gone |
| `vk_response_unknown_token_returns_404` | Token not in store → HTTP 404 |
| `vk_response_body_contains_only_vk_and_fingerprint_fields` | Response JSON has exactly 2 keys (no SK leakage) |
| `registration_body_contains_server_vk` | `server_vk` field is 3904 lowercase hex chars |

---

---

# Mes 13 — Admin PQC Channel (`:8445`)

---

## The problem that existed

Mes 12 introduced a bearer token on `:8444` to guard the `POST /vk-token` admin endpoint. The route `POST /rotate` — which triggers key rotation across all active sessions — had no authentication at all. An attacker who could reach `:8444` on the network could trigger key rotations at will, causing session disruption.

More fundamentally, `:8444` spoke plain HTTP with a classical secret token. This has two security gaps:

1. **No quantum resistance.** The bearer token travels in plaintext HTTP. On a compromised network segment, it can be captured by a classical adversary today — and replayed. There is no forward secrecy, no identity binding, no replay protection.

2. **No mutual authentication.** A bearer token proves "you know the secret" but not "you are the expected control plane instance". An attacker who steals the token can impersonate the control plane indefinitely until the token is rotated.

Mes 13 replaces the entire `:8444` admin infrastructure with a new PQC-authenticated TCP channel on `:8445`. The new channel reuses the exact same `latticeshield-crypto` handshake primitives used for proxy clients on `:8443` — ML-KEM-768 hybrid key exchange for forward secrecy and ML-DSA-65 mutual authentication. Zero new cryptographic code was introduced.

The port layout after Mes 13:

| Port  | Protocol          | Authentication     | Purpose                               |
|-------|-------------------|--------------------|---------------------------------------|
| :8440 | TLS (rustls)      | none               | Standard HTTPS clients (optional)     |
| :8441 | QUIC (quinn)      | none               | Standard QUIC clients (optional)      |
| :8443 | PQC (raw TCP)     | ML-DSA-65 server   | LatticeShield proxy clients           |
| :8444 | HTTP (plain)      | none               | Prometheus scrape only                |
| :8445 | PQC (raw TCP)     | ML-DSA-65 mutual   | Control plane admin (NEW)             |

---

## latticeshield-bridge/src/admin.rs — the PQC admin channel

This is a new module. It owns everything related to the admin channel: protocol types, handshake, command dispatch, rate limiting, and the listener task.

### Protocol types — typed commands and responses

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct CommandFrame {
    pub seq: u64,
    #[serde(flatten)]
    pub cmd: AdminCommand,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum AdminCommand {
    GetMetrics,
    Rotate,
    GetVkToken,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AdminResponse {
    Metrics { data: String },
    Rotated { count: u64 },
    VkToken { token: String, url: String },
    Error { message: String },
}
```

Commands are serialized as JSON inside the AES-256-GCM encrypted `EncryptedChannel` frame. The `#[serde(tag = "cmd")]` internally-tagged representation produces a flat JSON object like `{"seq": 1, "cmd": "GetMetrics"}` — human-readable and self-describing. An unknown command variant fails deserialization (the `AdminCommand` enum has no `#[serde(other)]` catch-all), which causes the connection to be closed with no response.

**Why JSON and not a binary format?** The payload rides inside AES-256-GCM encryption so wire verbosity is irrelevant. `serde_json` is already a workspace dependency. JSON produces human-readable debug output when the encrypted channel is decrypted for testing. A binary format (postcard, bincode) would require a new crate dependency for no practical gain.

### Sequence numbers — anti-replay protection

```rust
pub fn is_seq_valid(seq: u64, last_seen: u64) -> bool {
    seq > last_seen
}
```

Every `CommandFrame` carries a monotonic `seq: u64`. The bridge initializes `last_seen_seq = 0` at the start of each connection. A valid first command must have `seq >= 1`. The check `seq > last_seen` rejects replays (same seq), old sequences, and the initial zero value.

**Why is this necessary if the handshake already uses an ephemeral ML-KEM key?** The ML-KEM handshake establishes a fresh session key for each TCP connection, which prevents cross-connection replays. The sequence number provides defense-in-depth within a connection: if the AES-256-GCM nonce counter ever wrapped (it doesn't in practice — 96-bit nonce, gigabytes of data before reuse), a sequence-number check would still catch replayed frames. More practically, the seq number is a guard against a future extension where multiple commands share one connection.

The sequence check is a pure function with no I/O, which makes it directly unit-testable:

```rust
#[test] fn seq_zero_rejected()      { assert!(!is_seq_valid(0, 0)); }
#[test] fn seq_one_accepted()       { assert!(is_seq_valid(1, 0)); }
#[test] fn seq_replay_same_rejected(){ assert!(!is_seq_valid(5, 5)); }
#[test] fn seq_old_rejected()       { assert!(!is_seq_valid(3, 5)); }
```

### One-command-per-connection model

Each TCP connection to `:8445` follows exactly this sequence: PQC handshake → one command frame → one response frame → TCP close. There is no persistent session with multiple commands over a single connection.

This simplicity is intentional. The admin channel is a machine-to-machine command protocol, not an interactive shell. Operations like "get metrics" or "trigger rotation" are fire-and-forget from the cloud's perspective. The cost of a new TCP connection + handshake (a few milliseconds) is acceptable for the simplicity it buys: no session state to manage, no command queuing, no half-open connection cleanup.

### The handshake — mutual ML-DSA-65 over the existing PQC protocol

```rust
async fn do_handshake(
    stream: &mut TcpStream,
    identity: &ServerIdentity,
    cp_vk: &ControlPlaneVerifyingIdentity,
) -> Result<SessionKey, HandshakeError> {
    let server = ServerHandshake::new(&mut OsRng);

    // Sign and send ServerHello (4557 bytes: X25519 + ML-KEM EK + nonce + ML-DSA sig)
    let hello_bytes = server.server_hello_signed_bytes(&identity.signing_key, &mut OsRng)?;
    stream.write_all(&hello_bytes).await
        .map_err(|_| HandshakeError::AuthenticationFailed)?;

    // Read signed ClientResponse (4429 bytes: X25519 + ML-KEM CT + ML-DSA sig)
    let mut buf = [0u8; CLIENT_RESPONSE_SIGNED_LEN];
    stream.read_exact(&mut buf).await
        .map_err(|_| HandshakeError::AuthenticationFailed)?;

    // Verify the control plane's signature against its pre-shared VK
    server.complete_from_wire_signed(&buf, &cp_vk.verifying_key)
}
```

This is identical to the mutual-auth path in `session.rs` — the same `server_hello_signed_bytes` and `complete_from_wire_signed` calls. The admin channel simply makes mutual auth mandatory: there is no unauthenticated fallback, unlike the proxy channel where client auth is opt-in.

**The bridge uses its existing `ServerIdentity`** to sign the ServerHello. The admin client authenticates the bridge using the same VK that proxy clients use — the one distributed at registration time. No separate bridge identity for the admin channel.

**The control plane authenticates with a dedicated `ControlPlaneVerifyingIdentity`** loaded from `admin.control_plane_vk_path`. This keypair is generated with the new `admin-keygen` subcommand. Having a separate keypair for the admin client (instead of reusing the proxy client keypair) isolates security boundaries: if the admin SK is compromised, the proxy client keys are unaffected.

### Rate limiting — no new crate

```rust
let mut rate_window_start = Instant::now();
let mut rate_count: u32 = 0;

loop {
    let (stream, peer) = listener.accept().await?;

    // Reset window every second
    if rate_window_start.elapsed() >= Duration::from_secs(1) {
        rate_window_start = Instant::now();
        rate_count = 0;
    }
    rate_count += 1;
    if rate_count > config.rate_limit_per_second {
        warn!(%peer, "admin: connection dropped — rate limit exceeded");
        drop(stream);
        continue;
    }
    // ... spawn handler ...
}
```

The rate limiter uses `(Instant, u32)` local state in the single accept-loop task. No mutex, no crate, no allocations. It resets the counter every second. The default limit is 5 connections per second — more than enough for any legitimate control plane, and low enough to limit the impact of a misconfigured or malicious client flooding the port.

### Command dispatch — three handlers

**`GetMetrics`**: calls `prometheus_handle.render()` and returns the full Prometheus text exposition format in `AdminResponse::Metrics { data }`. The same `PrometheusHandle` is shared with `GET /metrics` on `:8444`. The data is identical regardless of which channel is used to request it.

**`Rotate`**: sends a modification signal on `rotate_tx: Arc<watch::Sender<u64>>` (incrementing the counter by 1) and returns the number of currently active proxy connections. The `rotate_tx` channel is the same one used by `session.rs` to detect rotation requests — the admin command triggers the same rotation path as the now-removed `POST /rotate` on `:8444`.

**`GetVkToken`**: calls `vk_share::create_token()` and returns the one-time token URL in `AdminResponse::VkToken { token, url }`. The `vk_store` is the same `Arc<VkShareStore>` shared with the TLS listener — tokens created via the admin channel are redeemable at `GET /vk/:token` on `:8440`.

---

## latticeshield-bridge/src/identity.rs — ControlPlaneVerifyingIdentity

A new identity type was added alongside the existing `ServerIdentity` and `ClientVerifyingIdentity`:

```rust
#[derive(Debug)]
pub struct ControlPlaneVerifyingIdentity {
    pub verifying_key: VerifyingKey,
}

impl ControlPlaneVerifyingIdentity {
    pub fn load(vk_path: &Path) -> Result<Self, IdentityError> {
        let data = std::fs::read(vk_path)?;
        if data.len() != VERIFYING_KEY_LEN {
            return Err(IdentityError::InvalidSize {
                expected: VERIFYING_KEY_LEN,
                found: data.len(),
            });
        }
        let buf: &[u8; VERIFYING_KEY_LEN] = data.as_slice().try_into().expect("len ya validado");
        let verifying_key = VerifyingKey::from_bytes(buf)
            .map_err(|e| IdentityError::InvalidKey(e.to_string()))?;
        Ok(Self { verifying_key })
    }
}
```

**Why a distinct named type and not a type alias or reuse of `ClientVerifyingIdentity`?** Type safety. If `ControlPlaneVerifyingIdentity` were a type alias for `ClientVerifyingIdentity`, the compiler would not catch a bug where the proxy client VK and the admin VK are accidentally swapped. A distinct struct makes the semantic difference machine-enforced. The implementation is identical — that is fine. Duplication at the type level is preferable to a type alias that loses semantic meaning.

**No file-permission check.** Unlike `ServerIdentity::load()`, which enforces `0o600` on the signing key file, `ControlPlaneVerifyingIdentity::load()` performs no permission check. The VerifyingKey is public material — it is distributed out-of-band and does not need to be kept secret. This mirrors the `ClientVerifyingIdentity` behavior.

The key file convention: `admin-keygen <dir>` produces `admin.sk` (0o600, control plane signs with this) and `admin.vk` (0o644, bridge loads this as `ControlPlaneVerifyingIdentity`).

---

## latticeshield-bridge/src/config.rs — AdminConfig

```toml
[admin]
enabled = true
listen_addr = "0.0.0.0:8445"
control_plane_vk_path = "./keys/admin.vk"
rate_limit_per_second = 5
handshake_timeout_secs = 10
```

The `[admin]` section is opt-in. When `enabled = false` (the default), no port is allocated. When `enabled = true`, `control_plane_vk_path` is required — the bridge refuses to start if the file is missing or contains an invalid key.

Validation rejects port collisions between `admin.listen_addr` and all other configured listeners (`:8443`, `:8444`, `:8440`, `:8441`). Collision is detected at startup, before any socket is opened.

**Why is the admin channel opt-in?** Not every deployment needs a control plane. A self-hosted bridge running on a single machine can be operated entirely via the CLI without the admin channel. Making it opt-in means the default configuration has zero attack surface on `:8445`.

### Removing the bearer token from :8444

Mes 13 removes `POST /rotate` and `POST /vk-token` from `metrics_app()`. The `admin_token: String` field is removed from `MetricsAppState`. `server::run()` no longer accepts an `admin_token` parameter. The `LATTICESHIELD_ADMIN_TOKEN` environment variable is no longer read.

`GET /metrics` on `:8444` remains untouched — Prometheus scraping is unauthenticated by design, consistent with the standard Prometheus deployment model where `:8444` is firewalled from public access.

### Test coverage (285 tests total after Mes 13)

The bridge binary gained 29 new tests. Key scenarios:

| Test | What it verifies |
|------|-----------------|
| `command_frame_get_metrics_roundtrip` | JSON round-trip for GetMetrics command frame |
| `command_frame_unknown_cmd_fails` | Unknown `cmd` variant fails deserialization |
| `seq_zero_rejected` | `is_seq_valid(0, 0)` → false |
| `seq_replay_same_rejected` | `is_seq_valid(5, 5)` → false |
| `cp_vk_load_roundtrip_ok` | `ControlPlaneVerifyingIdentity::load` with valid VK |
| `cp_vk_load_wrong_size_rejected` | 16-byte file → `IdentityError::InvalidSize` |
| `post_rotate_returns_404_after_mes13` | `POST /rotate` on :8444 now returns 404 |
| Full handshake integration tests | Both sides (server + client) in the same process over an ephemeral port |

---

---

# Mes 14 — Cloud Integration (Signed Heartbeats + BridgeCommand)

---

## The problem that existed

The heartbeat channel between the bridge and the cloud was one-directional and unauthenticated. The bridge POSTed a JSON payload with metrics and status to the cloud control plane, but:

1. **The cloud could not verify the sender.** Any process that knew the registration endpoint URL could send fake heartbeats. There was no cryptographic proof that a heartbeat came from the specific bridge instance that had registered with that `agent_id`.

2. **The cloud could not send commands back.** The heartbeat response body was ignored. If the cloud needed to trigger a key rotation on a specific bridge, there was no mechanism — the `POST /rotate` admin route (now removed in Mes 13) was the only way, and it required direct network access to `:8444`.

3. **Registration was open.** Any process could POST to `POST /api/v1/agents/register` and obtain an `agent_id`. There was no one-time provisioning secret that the cloud could use to validate that a registering bridge was deployed intentionally by an operator.

Mes 14 closes all three gaps on the bridge side:
- Every heartbeat is now signed with the bridge's ML-DSA-65 signing key. The cloud can verify the signature against the `server_vk` registered in Mes 12.
- The cloud can include `BridgeCommand` values in the heartbeat response body. The bridge reads and dispatches them.
- A one-time `install_token` can be included in the registration payload to authenticate the initial provisioning.

---

## latticeshield-bridge/src/control_plane.rs — signed heartbeats and BridgeCommand dispatch

### The payload split: SignableHeartbeatPayload and SignedHeartbeatPayload

Before Mes 14, a single `HeartbeatPayload` struct was built and POSTed. Mes 14 introduces a clean two-struct pattern:

```rust
#[derive(Serialize)]
struct SignableHeartbeatPayload {
    timestamp_unix: u64,
    uptime_secs: u64,
    status: &'static str,
    version: &'static str,
    metrics: HeartbeatMetrics,
}

#[derive(Serialize)]
struct SignedHeartbeatPayload {
    timestamp_unix: u64,
    uptime_secs: u64,
    status: &'static str,
    version: &'static str,
    metrics: HeartbeatMetrics,
    signature: String,   // base64-encoded ML-DSA-65 signature (4412 chars)
}
```

`SignableHeartbeatPayload` contains exactly the fields that are signed. `SignedHeartbeatPayload` contains those same fields plus the `signature` field. The layout is flat (no nesting) — the cloud reconstructs the canonical body by extracting the five known fields into a matching struct and calling `serde_json::to_vec`, then verifies the signature against the bridge's pre-registered `server_vk`.

**Why flat and not nested?** If `SignedHeartbeatPayload` nested `SignableHeartbeatPayload` as a sub-object, the cloud would need to extract a `{"payload": {...}}` wrapper level before re-serializing. A flat layout means the cloud's canonical reconstruction mirrors the bridge's construction exactly — same field names, same JSON serialization order (serde_json preserves struct field declaration order).

### The signing process in send_heartbeat()

```rust
async fn send_heartbeat(
    client: &Client,
    config: &ValidConfig,
    agent_id: &str,
    signable: &SignableHeartbeatPayload,
    identity: &ServerIdentity,
    rng: &mut impl rand_core::CryptoRngCore,
) -> anyhow::Result<HeartbeatResponse> {
    // Step 1: canonical bytes (serde_json preserves field declaration order)
    let canonical = serde_json::to_vec(signable)?;

    // Step 2: ML-DSA-65 sign — produces a 3309-byte Signature
    let sig = latticeshield_crypto::signing::sign(&identity.signing_key, &canonical, rng)?;

    // Step 3: base64 standard encoding — 3309 bytes → 4412 chars
    let signature = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

    // Step 4: build flat POST body
    let signed = SignedHeartbeatPayload {
        timestamp_unix: signable.timestamp_unix,
        // ... copy fields ...
        metrics: signable.metrics.clone(),
        signature,
    };

    // Step 5: POST + parse response
    let resp = client.post(&url).json(&signed).timeout(Duration::from_secs(5)).send().await?;
    let hb_resp = resp.json::<HeartbeatResponse>().await.unwrap_or_default();
    Ok(hb_resp)
}
```

A single `OsRng` instance is created once before the loop in `start()` and reused across heartbeats. `OsRng` is a zero-sized type — constructing it has no cost — but keeping one instance avoids any per-heartbeat syscall overhead for RNG initialization on platforms that care.

**Why base64 for the signature and not hex?** The ML-DSA-65 signature is 3309 bytes. In hex that is 6618 characters; in base64 standard it is 4412 characters — 33% smaller. Since the heartbeat fires every 30 seconds and the signature rides in every POST body, base64 is the appropriate choice here. For the `server_vk` field (sent once at registration, 1952 bytes → 3904 hex chars), the wire-size argument does not apply and hex was kept for consistency with the rest of the codebase.

`base64 = "0.22"` was added as a direct dependency in `latticeshield-bridge/Cargo.toml`. It was not previously in the workspace.

### HeartbeatResponse and BridgeCommand

```rust
#[derive(Debug, Deserialize, Default)]
struct HeartbeatResponse {
    #[serde(default)]
    pending_commands: Option<Vec<BridgeCommand>>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum BridgeCommand {
    Rotate,
    #[serde(other)]
    Unknown,
}
```

`HeartbeatResponse` derives `Default` so that `resp.json().unwrap_or_default()` works when the cloud returns an empty body (`{}`) or the JSON parse fails for any non-fatal reason. `#[serde(default)]` on the `pending_commands` field ensures a missing key in the JSON is treated as `None` rather than a deserialization error.

`BridgeCommand` uses `#[serde(other)]` to absorb unknown variants as `Unknown` without erroring. This is forward-compatibility: when the cloud adds a new command type (e.g., `Reload`, `UpdateConfig`) in a future milestone, older bridge versions gracefully skip it with a warning log instead of crashing.

The dispatch loop in `start()`:

```rust
match send_heartbeat(&client, &config, &agent_id, &signable, &identity, &mut rng).await {
    Ok(hb_resp) => {
        for cmd in hb_resp.pending_commands.unwrap_or_default() {
            match cmd {
                BridgeCommand::Unknown => {
                    tracing::warn!("unknown BridgeCommand received, skipping");
                }
                cmd => {
                    if let Err(e) = cmd_tx.send(cmd).await {
                        tracing::warn!("BridgeCommand channel closed: {e}");
                    }
                }
            }
        }
    }
    Err(e) => tracing::warn!("heartbeat failed (will retry): {e:#}"),
}
```

`cmd_tx` is a `tokio::sync::mpsc::Sender<BridgeCommand>` with capacity 32. It is created in `server.rs` before the control-plane task is spawned. In Mes 14, the receiver is a stub drainer task that logs each received command. Mes 15 replaces it with the actual key rotation logic.

**Why not dispatch directly in the heartbeat loop?** Separation of concerns. The heartbeat loop is responsible for talking to the cloud, not for executing bridge operations. If the command execution is slow or blocks, it would delay subsequent heartbeats. The mpsc channel decouples reception from execution.

`control_plane::start()` gains a new parameter:

```rust
pub async fn start(
    config: ValidConfig,
    metrics: Arc<MetricsState>,
    identity: Arc<ServerIdentity>,
    cmd_tx: tokio::sync::mpsc::Sender<BridgeCommand>,
)
```

`BridgeCommand` is `pub` so that `server.rs` can name the type for the channel.

---

## latticeshield-bridge/src/config.rs — install_token

```toml
[control_plane]
enabled = true
endpoint = "https://cloud.example.com"
install_token = "one-time-secret-from-cloud"
```

`ControlPlaneConfig` gains `pub install_token: Option<String>`. `ValidConfig` gains `pub control_plane_install_token: Option<String>`. The resolution order in `validate()`:

1. `INSTALL_TOKEN` environment variable — if set and non-empty, takes precedence.
2. `control_plane.install_token` from TOML — used if env var is absent or empty.
3. `None` — allowed. A `warn!` is emitted when `control_plane_enabled = true` but no token is configured.

The warning is non-fatal. The bridge continues to start and register without a token. It is the operator's responsibility to provision the token before deployment; the warning is a reminder that without it, the cloud cannot authenticate the registration.

### Why the install_token must never appear in logs

`ValidConfig` previously derived `Debug`. With `control_plane_install_token` added as a field, a `#[derive(Debug)]` would print the token value in every debug-level log that prints the config. The `#[derive(Debug)]` was removed and replaced with a manual `impl Debug` that redacts the token:

```rust
impl std::fmt::Debug for ValidConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidConfig")
            // ... all other fields ...
            .field(
                "control_plane_install_token",
                &self.control_plane_install_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}
```

This outputs `control_plane_install_token: Some("[REDACTED]")` when set, `None` when absent. The raw token value never appears in any log, trace span, or debug output.

The pattern is the same one used for `SigningKey`'s manual `Debug` impl in `signing.rs`. Consistent across all sensitive values in the codebase.

### install_token in RegistrationPayload

```rust
#[serde(skip_serializing_if = "Option::is_none")]
install_token: Option<String>,
```

`#[serde(skip_serializing_if = "Option::is_none")]` means the field is absent from the JSON when `None`. The cloud receives no `install_token` key at all (not even `null`) when the operator has not configured one. This matches real-world API conventions and avoids the cloud having to distinguish between `null` and absent.

### Test coverage (+10 tests, 295 total after Mes 14)

| Test | What it verifies |
|------|-----------------|
| `heartbeat_body_contains_base64_signature` | `signature` field present; base64-decodes to exactly 3309 bytes (`SIGNATURE_LEN`) |
| `heartbeat_signature_verifies_with_verifying_key` | Full `signing::verify` round-trip against the bridge's verifying key |
| `heartbeat_response_empty_body_returns_default` | `{}` response → `pending_commands: None` without panic |
| `heartbeat_response_rotate_command_returned` | `{"pending_commands":[{"type":"Rotate"}]}` → `BridgeCommand::Rotate` |
| `heartbeat_response_unknown_command_does_not_error` | Unknown command type → `BridgeCommand::Unknown`, no error |
| `registration_body_contains_install_token_when_set` | `install_token` field present in registration body when configured |
| `registration_body_omits_install_token_when_none` | `install_token` key absent from body when `None` |
| `install_token_toml_field_accepted` | TOML `install_token` field parsed into `ValidConfig` |
| `install_token_env_var_takes_precedence_over_toml` | `INSTALL_TOKEN` env var overrides TOML value |
| `valid_config_debug_redacts_install_token` | `format!("{:?}", cfg)` does not contain the raw token value |

---

---

# Mes 15 — Hybrid TLS + Command Wiring

---

## El problema que existia

El transporte entre el bridge y el cloud control plane usaba `reqwest` con `native-tls` — la misma TLS clasica vulnerable a ataques cuanticos que LatticeShield existe para mitigar. Toda la seguridad PQC del canal cliente→bridge se anulaba si un atacante con una computadora cuantica podia interceptar el canal bridge→cloud y leer heartbeats, tokens de instalacion, o inyectar respuestas falsas con `BridgeCommand`.

Por otro lado, el pipeline de `BridgeCommand` estaba incompleto. Mes 14 introdujo la deserializacion de comandos desde la respuesta del heartbeat y un canal mpsc para despacharlos, pero el receptor era un stub que solo logueaba los comandos recibidos. Un `BridgeCommand::Rotate` enviado desde el cloud no generaba ninguna rotacion real de claves.

Mes 15 cierra ambos gaps:
1. El transporte HTTP saliente del bridge (heartbeats + registro) ahora usa rustls con X25519MLKEM768 — intercambio de claves hibrido post-cuantico.
2. El stub drainer se reemplaza con un handler real que ejecuta la rotacion de claves e incrementa las metricas.

---

## latticeshield-bridge/Cargo.toml — cambio de feature de reqwest

El cambio critico es una sola linea en las dependencias:

```toml
# Antes (Mes 14):
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls-native-roots"] }

# Despues (Mes 15):
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls-native-roots-no-provider"] }
```

La diferencia es el sufijo `-no-provider`. Esto le dice a reqwest: "usa rustls para TLS, confia en los certificados raiz del sistema operativo, pero NO instales tu propio CryptoProvider — usa el que ya esta instalado en el proceso".

### Por que `-no-provider` y no la variante normal?

El workspace ya usa `rustls` directamente (para los listeners TLS y QUIC) con `aws-lc-rs` como CryptoProvider. rustls tiene un mecanismo de "CryptoProvider global" que se instala una sola vez por proceso. Si reqwest instala su propio provider (ring, que es el default de la variante sin `-no-provider`), hay dos providers compitiendo y rustls hace panic.

La variante `-no-provider` delega al provider ya instalado (`aws-lc-rs`), que soporta la suite X25519MLKEM768. Esto significa que cuando reqwest negocia TLS con el cloud, si el servidor cloud soporta X25519MLKEM768, el handshake usa intercambio de claves hibrido post-cuantico automaticamente. Si el servidor no lo soporta, cae a X25519 clasico. El bridge no necesita saber — rustls negocia la mejor suite disponible.

### Por que `native-roots` y no `webpki-roots`?

`native-roots` usa los certificados raiz del sistema operativo (via `rustls-native-certs`). `webpki-roots` usa un bundle estatico embebido en el binario. El comportamiento anterior con `native-tls` usaba los certificados del OS, asi que `native-roots` mantiene la compatibilidad exacta — los mismos CAs que confiaba antes siguen siendo confiados. Ademas, si un operador agrega un CA interno al trust store del OS, el bridge lo reconoce sin recompilar.

### Eliminacion de ring como dependencia

Un efecto secundario positivo: con `-no-provider`, reqwest no trae `ring` como dependencia. El workspace queda con un unico proveedor criptografico (`aws-lc-rs`) en lugar de dos (`aws-lc-rs` + `ring`). Menos codigo compilado, menos superficie de ataque, menos binario.

---

## latticeshield-bridge/src/server.rs — BridgeCommand handler

El stub drainer de Mes 14 era esto:

```rust
// Mes 14 — stub: solo loguea
tokio::spawn(async move {
    while let Some(cmd) = cmd_rx.recv().await {
        tracing::info!(?cmd, "BridgeCommand received (stub — no action)");
    }
});
```

Mes 15 lo reemplaza con un handler real:

```rust
tokio::spawn(async move {
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            BridgeCommand::Rotate => {
                // Incrementa el watch channel — todas las sesiones activas detectan
                // el cambio via rotate_rx.changed() y rotan su clave
                rotate_tx.send_modify(|c| *c += 1);
                let active = metrics_state.connections_active
                    .load(std::sync::atomic::Ordering::Relaxed);
                metrics_state.key_rotations_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::info!(
                    active_sessions = active,
                    "BridgeCommand::Rotate executed — key rotation triggered"
                );
            }
            BridgeCommand::Unknown => {
                tracing::warn!("unknown BridgeCommand received, skipping");
            }
        }
    }
});
```

### Como funciona la rotacion

El patron es identico al que usa `admin.rs` para el comando `AdminCommand::Rotate`:

1. `rotate_tx.send_modify(|c| *c += 1)` — modifica el valor del watch channel atomicamente. Todas las sesiones PQC activas que llamaron a `rotate_tx.subscribe()` reciben una notificacion via `rotate_rx.changed()`.

2. Cada sesion (en `session.rs`) tiene un brazo en su `select!` que espera `rotate_rx.changed()`. Cuando detecta el cambio, genera un nonce aleatorio, envia un frame `KEY_ROTATE` al cliente, y llama a `channel.rotate_key(nonce)`. El cliente hace lo mismo. La clave de sesion queda renovada.

3. `metrics_state.key_rotations_total.fetch_add(1, ...)` incrementa el contador Prometheus `latticeshield_key_rotations_total`. Esto permite que el operador vea en Grafana cuantas rotaciones se dispararon desde el cloud vs. por tiempo vs. por bytes.

### Por que reutilizar el patron de admin.rs?

Porque es exactamente la misma operacion. El admin channel (`:8445`) ya tenia `handle_rotate()` que hacia `rotate_tx.send_modify(|c| *c += 1)` + `metrics.key_rotations_total.fetch_add(1)`. Duplicar el patron en lugar de extraer una funcion compartida fue una decision consciente: el handler del mpsc channel es un closure async dentro de `server::run()`, y el handler del admin es una funcion libre en `admin.rs`. Extraer una funcion compartida requeriria pasar `Arc<watch::Sender>` + `Arc<MetricsState>` como parametros, lo cual agrega complejidad sin beneficio real — el cuerpo es de 5 lineas.

---

## El flujo completo: cloud → bridge → sesiones

Con Mes 14 + 15, el ciclo completo de un `BridgeCommand::Rotate` originado en el cloud es:

```
Cloud API                  Bridge control_plane.rs        Bridge server.rs             Sessions
   |                              |                             |                         |
   |  HeartbeatResponse           |                             |                         |
   |  {pending_commands:          |                             |                         |
   |    [{"type":"Rotate"}]}      |                             |                         |
   |----------------------------->|                             |                         |
   |                              | deserializa BridgeCommand   |                         |
   |                              | filtra Unknown              |                         |
   |                              | cmd_tx.send(Rotate)         |                         |
   |                              |---------------------------->|                         |
   |                              |                             | rotate_tx.send_modify() |
   |                              |                             | key_rotations_total += 1|
   |                              |                             |------------------------>|
   |                              |                             |                         | rotate_rx.changed()
   |                              |                             |                         | KEY_ROTATE frame
   |                              |                             |                         | channel.rotate_key()
```

Todo el camino es asincrono y no-bloqueante. El heartbeat loop no espera a que la rotacion termine — el mpsc channel desacopla la recepcion de la ejecucion.

---

## Test coverage (+4 tests, 299 total despues de Mes 15)

Los 4 tests nuevos estan en `server.rs` y cubren el dispatch de `BridgeCommand`:

| Test | Que verifica |
|------|-------------|
| `bridge_command_rotate_increments_rotate_tx` | `BridgeCommand::Rotate` incrementa el watch channel a 1 |
| `bridge_command_rotate_increments_key_rotations_metric` | `BridgeCommand::Rotate` incrementa `key_rotations_total` a 1 |
| `bridge_command_unknown_does_not_touch_rotate_tx_or_metrics` | `BridgeCommand::Unknown` no modifica rotate_tx ni metricas |
| `bridge_command_multiple_rotates_increment_n_times` | 3 Rotates consecutivos → rotate_tx=3, key_rotations_total=3 |

---

---

# Mes 16 — Hardening pre-produccion

---

## El problema que existia

Tres problemas independientes habian quedado pendientes despues del audit de Mes 15. Ninguno era bloqueante para el desarrollo, pero los tres eran inaceptables para un deployment en produccion:

**El bridge no se apagaba limpiamente.** Cuando el proceso recibia SIGTERM (el mecanismo estandar de apagado en Linux y macOS, usado por systemd, Docker, Kubernetes), el runtime de Tokio terminaba abruptamente. Toda sesion PQC activa en ese instante quedaba con su conexion cortada a mitad de transferencia: el cliente recibia un EOF inesperado, el backend nunca recibia el cierre limpio de TCP, y las metricas quedaban desactualizadas. Esto haria que cualquier rolling update en Kubernetes o `systemctl restart` en produccion tuviera una ventana de errores proporcional al numero de conexiones activas en ese momento.

**El `Mutex` en `vk_share.rs` podia cascadear panics.** El store de tokens VK usa un `Arc<Mutex<HashMap>>`. Si un hilo panickea mientras sostiene ese lock — por ejemplo, una asercion que falla en algun codigo de respuesta — el `Mutex` queda en estado "envenenado". Con `.lock().unwrap()`, todos los llamados subsiguientes al store tambien panickean. Esto convierte un error puntual en un crash completo del servidor HTTP de metricas, inutilizando la capacidad de distribuir VKs hasta el proximo restart.

**Un test de integracion era intermitentemente flaky.** `full_session_records_connections_and_bytes` usaba `sleep(150ms)` para esperar que la sesion terminara antes de verificar las metricas. En maquinas lentas o bajo carga, 150ms no era suficiente y el test fallaba con valores incorrectos. Los tests flaky degradan la confianza en el CI y enmascaran regresiones reales.

---

## latticeshield-bridge/src/config.rs — shutdown_timeout

### El campo shutdown_timeout en ValidConfig

```rust
/// Graceful shutdown drain timeout. Sessions still active after this duration are forced.
pub shutdown_timeout: std::time::Duration,
```

`shutdown_timeout` controla cuanto tiempo espera el proceso a que las sesiones activas terminen antes de forzar la salida. El valor se resuelve desde la variable de entorno `SHUTDOWN_TIMEOUT_SECS` en el momento de validacion del config, con default de 30 segundos:

```rust
// En Config::validate():
let shutdown_timeout_secs = std::env::var("SHUTDOWN_TIMEOUT_SECS")
    .ok()
    .and_then(|v| v.parse::<u64>().ok())
    .unwrap_or(30);  // default: 30 segundos
let shutdown_timeout = std::time::Duration::from_secs(shutdown_timeout_secs);
```

### Por que una variable de entorno y no un campo TOML?

El timeout de shutdown es tipicamente un parametro de infraestructura, no de la aplicacion. En Kubernetes, el `terminationGracePeriodSeconds` del pod define cuanto tiempo tiene el proceso antes de recibir SIGKILL. Si ese valor es 60s, el bridge necesita un `shutdown_timeout` menor (digamos 45s) para tener margen de drain antes del SIGKILL forzado. Este tipo de tuning lo maneja el operador de infra en el manifest del pod, no el desarrollador en el config.toml. Una variable de entorno es el mecanismo idiomatico para parametros que cambian entre entornos de deployment sin tocar el config de la aplicacion.

---

## latticeshield-bridge/src/server.rs — canal de shutdown y drain loop

### El canal watch::channel<()>

El patron de shutdown se construye sobre `tokio::sync::watch::channel`:

```rust
// Un sender (productor) y un receiver (consumidor inicial)
let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
// _shutdown_tx se mantiene vivo hasta el final de run() — dropearlo cerraría el canal
let _shutdown_tx = shutdown_tx;
```

Un `watch::channel` almacena el ultimo valor publicado. Cuando el sender llama a `.send(())`, todos los receivers activos detectan el cambio via `.changed().await`. Los receivers se clonan gratis: cada listener (TLS, QUIC, admin, control_plane, sesiones individuales) recibe su propio `shutdown_rx.clone()` al ser creado.

### El handler de senales

Una tarea separada escucha SIGINT y SIGTERM y notifica al canal:

```rust
tokio::spawn(async move {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let ctrl_c = tokio::signal::ctrl_c();
        let mut sigterm = signal(SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c  => info!("shutdown: SIGINT received"),
            _ = sigterm.recv() => info!("shutdown: SIGTERM received"),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.ok();
        info!("shutdown: SIGINT received");
    }
    // Notifica a todos los receivers via el canal watch
    let _ = shutdown_tx_signal.send(());
});
```

El guard `#[cfg(unix)]` existe porque `tokio::signal::unix` solo compila en Unix. En Windows (o al correr tests sin soporte de señales), el codigo cae al bloque `#[cfg(not(unix))]` que solo escucha Ctrl-C.

### El loop de aceptacion PQC con select!

El loop principal ya no es simplemente `listener.accept().await`:

```rust
loop {
    tokio::select! {
        accept_result = listener.accept() => {
            // procesa nueva conexion, guarda el JoinHandle en session_handles
        }
        _ = shutdown_rx_pqc.changed() => {
            info!("shutdown: PQC listener stopping");
            break;
        }
    }
}
```

Cuando llega la senal de shutdown, el loop sale sin aceptar nuevas conexiones. Las sesiones ya activas (sus `JoinHandle`) estan en el vector `session_handles`.

### El drain loop con timeout

Una vez que el loop de aceptacion sale, el proceso espera a cada tarea activa con un timeout:

```rust
info!("shutdown: draining {} in-flight sessions", session_handles.len());
for handle in session_handles {
    if tokio::time::timeout(config.shutdown_timeout, handle).await.is_err() {
        warn!("shutdown: session drain timeout exceeded, forcing exit");
    }
}
```

El mismo patron se aplica a cada listener (TLS, QUIC, admin, control_plane, metrics):

```rust
if let Some(h) = tls_handle {
    if tokio::time::timeout(config.shutdown_timeout, h).await.is_err() {
        warn!("shutdown: TLS listener drain timeout exceeded, forcing exit");
    }
}
// ... idem para quic_handle, admin_handle, cp_handle, metrics_handle_task
```

Si una tarea no termina dentro del `shutdown_timeout`, el `warn!` lo registra y el proceso continua hacia el siguiente handle. Esto garantiza que el proceso eventualmente termina incluso si una sesion esta colgada — y el log permite distinguir un shutdown limpio de uno forzado.

### Por que watch::channel<()> y no CancellationToken o broadcast?

Tres alternativas fueron consideradas:

1. **`tokio_util::CancellationToken`**: semanticamente identico a `watch::channel<()>` para este caso de uso. La diferencia es que requiere una dependencia extra (`tokio-util`). Como el proyecto ya usa `watch` para la rotacion de claves, es consistente reusar el mismo primitivo.

2. **`tokio::sync::broadcast::channel`**: diseñado para distribuir *valores* a multiples consumidores donde cada uno recibe *todos* los mensajes. Para shutdown solo necesitamos que cada listener sepa que *ocurrio* el evento — no necesitamos el historial ni multiple mensajes. `watch` es mas simple: almacena el ultimo valor y notifica el cambio.

3. **`tokio::sync::oneshot`**: solo permite un receiver. Hay que clonarlo explicitamente antes de enviarlo, lo cual es menos ergonomico que `watch_rx.clone()`.

`watch::channel<()>` es la opcion idiomatica en el ecosistema Tokio para shutdown broadcast de un-a-muchos cuando el "valor" no importa, solo el evento de cambio.

---

## latticeshield-bridge/src/session.rs — shutdown_rx en handle()

`session::handle()` gana un nuevo parametro:

```rust
pub async fn handle(
    mut client: TcpStream,
    peer: SocketAddr,
    identity: Arc<ServerIdentity>,
    client_auth: Option<Arc<ClientVerifyingIdentity>>,
    metrics_state: Arc<MetricsState>,
    rotate_tx: Arc<watch::Sender<u64>>,
    config: ValidConfig,
    mut shutdown_rx: tokio::sync::watch::Receiver<()>,  // nuevo en Mes 16
) -> anyhow::Result<()> {
```

El relay loop ya tenia multiples brazos en un `select!` (datos del cliente, datos del backend, rotacion periodica, rotacion manual). Mes 16 agrega un brazo mas:

```rust
// ── Graceful shutdown signal ─────────────────────────────────────────────
_ = shutdown_rx.changed() => {
    info!(%peer, "session: shutdown signal, stopping relay");
    break;
}
```

Cuando el proceso recibe SIGTERM, el canal de shutdown notifica a todas las sesiones activas. El `select!` en cada sesion detecta el cambio y sale del loop de relay limpiamente: el TCP se cierra por drop, el backend recibe un FIN bien formado, y las metricas de sesion activa se decrementan correctamente via los `Drop` guards.

### Por que las sesiones necesitan una salida explicita?

Sin el brazo de shutdown, una sesion de larga duracion (por ejemplo, un cliente con una conexion persistente) bloquearia el drain loop en `server.rs` hasta que el cliente cerrara la conexion por su cuenta. Si ese cliente tiene un timeout de minutos, el proceso esperaria esos minutos antes de terminar. Con el brazo de shutdown, el servidor puede cerrar la sesion activamente en cuanto recibe la senal, sin esperar al cliente.

---

## latticeshield-bridge/src/admin.rs — shutdown_rx en spawn_admin_listener()

`spawn_admin_listener()` gana un parametro `shutdown_rx: watch::Receiver<()>` y el loop de aceptacion del listener admin sigue el mismo patron `select!` que el listener PQC:

```rust
loop {
    let (stream, peer) = tokio::select! {
        accept_result = listener.accept() => { /* ... */ }
        _ = shutdown_rx.changed() => {
            info!("shutdown: admin listener stopping");
            break;
        }
    };
    // ... procesamiento de la conexion
}
```

La funcion ahora retorna `tokio::task::JoinHandle<()>` en lugar de `()`. `server.rs` guarda ese handle y lo drena en el shutdown loop.

---

## latticeshield-bridge/src/control_plane.rs — shutdown_rx en start()

`control_plane::start()` gana un parametro `shutdown_rx: tokio::sync::watch::Receiver<()>`. El sleep entre heartbeats se reemplaza con un `select!`:

```rust
loop {
    tokio::select! {
        _ = tokio::time::sleep(config.heartbeat_interval) => { /* enviar heartbeat */ }
        _ = shutdown_rx.changed() => {
            info!("control_plane: shutdown signal, stopping heartbeat");
            break;
        }
    }
    // ... construir y enviar heartbeat
}
```

Antes de Mes 16, un heartbeat programado para dentro de 30 segundos bloqueaba el shutdown durante hasta 30 segundos. Con el `select!`, la tarea termina en cuanto llega la senal, sin esperar al proximo intervalo.

---

## latticeshield-bridge/src/vk_share.rs — recuperacion de Mutex envenenado

### El problema del Mutex poison

Cuando un hilo de Rust panickea mientras sostiene un `MutexGuard`, el `Mutex` queda marcado como "envenenado". La logica es conservadora: un panic puede haber dejado los datos en un estado inconsistente, y Rust quiere que el codigo que intente acceder esos datos lo sepa. La forma de saberlo es que `.lock()` retorna `Err(PoisonError)` en lugar de `Ok(guard)`.

Con `.lock().unwrap()`, ese `Err` se convierte en un segundo panic, que envenena el mutex de nuevo, que causa un tercer panic en la proxima llamada, y asi sucesivamente. Un unico panic en cualquier codigo que toque el store convierte todas las operaciones subsiguientes de VK share en crashes.

### La solucion: unwrap_or_else(|e| e.into_inner())

```rust
// Antes (vulnerable al cascade):
store.lock().unwrap().insert(token.clone(), entry);

// Ahora (recuperacion segura):
store.lock().unwrap_or_else(|e| e.into_inner()).insert(token.clone(), entry);
```

`PoisonError::into_inner()` retorna el `MutexGuard` que estaba activo cuando ocurrio el panic. La invariante del `HashMap` interno se mantiene: un `HashMap` no tiene invariantes de seguridad que puedan quedar violadas por un panic en codigo externo — el panic ocurrio despues de que el `HashMap` fue modificado (o sin tocarlo). Recuperar el guard y continuar es seguro porque el HashMap en si es un tipo seguro que no tiene estado corrupto observable.

El mismo patron se aplica en ambas funciones que acceden al store:

```rust
// create_token():
store.lock().unwrap_or_else(|e| e.into_inner()).insert(token.clone(), entry);

// vk_response():
let mut guard = store.lock().unwrap_or_else(|e| e.into_inner());
```

### Por que es seguro aqui pero no siempre?

`unwrap_or_else(|e| e.into_inner())` es seguro cuando la invariante del dato protegido no puede quedar violada por un panic en codigo externo. Para un `HashMap<String, VkShareEntry>`, no hay invariante que se pueda romper: insertar o leer del mapa son operaciones atomicas desde la perspectiva del mutex — o ocurrieron completamente antes del panic, o no ocurrieron. No hay estado intermedio observable.

Si el dato protegido fuera, por ejemplo, un `struct` con dos campos que deben estar sincronizados entre si, un panic a mitad de la actualizacion podria dejar un campo actualizado y el otro no. En ese caso, recuperar el guard podria exponer datos inconsistentes, y seria mas correcto dejar el mutex envenenado o reinicializar el estado.

---

## Confiabilidad de tests (G9)

Los cambios en la infraestructura de tests son internos y no afectan la API ni el protocolo. En resumen:

- `full_session_records_connections_and_bytes` ahora espera el `JoinHandle` de la sesion directamente en lugar de un `sleep(150ms)`, eliminando la condicion de carrera.
- Los 12 tests de `control_plane` que fallaban con "No provider set" ahora inicializan `rustls::crypto::aws_lc_rs::default_provider()` una sola vez via `std::sync::OnceLock` antes de ejecutar cualquier test que requiera TLS.
- Las aserciones de metricas usan snapshots antes/despues del evento en lugar de asumir valores absolutos, lo que hace los tests reproducibles independientemente del orden de ejecucion.

---

## Cobertura de tests (241 tests totales despues de Mes 16)

Los 39 tests de `latticeshield-crypto` permanecen sin cambios. Los 202 tests de `latticeshield-bridge` incluyen:

| Tests nuevos | Que verifican |
|-------------|--------------|
| `create_token_recovers_from_poisoned_mutex` | `create_token` no panickea con un mutex envenenado y el token queda insertado |
| `vk_response_recovers_from_poisoned_mutex` | `vk_response` no panickea con un mutex envenenado y retorna 200 para un token valido |
| `shutdown_timeout_env_var_resolution` (x2) | `SHUTDOWN_TIMEOUT_SECS` ausente → 30s; presente con valor 60 → 60s |

Los tests usan un helper `spawn_cmd_handler()` que replica exactamente el closure del handler de produccion. Cada test crea su propio `MetricsState` y `watch::channel` aislados — sin estado compartido entre tests.

---

---

# Mes 17 — Numeros de secuencia y Framing v3

---

## El problema que existia

El formato de framing v2 no tenia ningun contador en los DATA frames. Cada frame viajaba como una unidad independiente: tipo, longitud, nonce aleatorio, ciphertext. Eso significaba que si un atacante capturaba un frame cifrado y lo reenviaba mas tarde — quiza segundos despues, quiza horas — el receptor lo aceptaba sin ningun mecanismo de deteccion.

El escenario de ataque concreto (gap D4 del audit de seguridad): un attacker-in-the-middle captura un DATA frame cifrado en la sesion entre el cliente y el bridge. El AEAD con nonce aleatorio garantiza que no puede leer el contenido. Pero no necesita leerlo: puede reenviar ese frame exacto mas tarde, y el receptor lo descifrara y lo procesara como si fuera un mensaje nuevo. Si ese frame contenia, por ejemplo, una instruccion de "ejecutar accion X", el replay ejecuta esa accion dos veces.

La contramedida correcta no es cifrar el numero de secuencia dentro del ciphertext — eso seria circular: hay que descifrar para verificar, pero para descifrar hay que confiar en que el frame no es replay. La solucion es usar el numero de secuencia como AAD (Additional Authenticated Data): el GCM tag cubre el seq en claro, de modo que cualquier modificacion del campo seq invalida el tag. Y el receptor mantiene un contador monotono: si el seq del frame entrante no es estrictamente mayor que el ultimo seq aceptado, el frame es rechazado antes de intentar descifrar.

---

## latticeshield-crypto/src/channel.rs — Framing v3 y EncryptedChannel

### El nuevo formato de wire: v3

```
// v2 (antes de Mes 17):
// [0x01][4B u32 BE: ct_len][12B nonce][N bytes ciphertext + 16B GCM tag]
// header: 17 bytes

// v3 (Mes 17+):
// [0x01][4B u32 BE: ct_len][8B u64 BE: seq][12B nonce][N bytes ciphertext + 16B GCM tag]
// header: 25 bytes (+8 bytes)
```

El campo `seq` es un entero de 64 bits en big-endian, monotono, que empieza en 0 en cada epoca de clave. El rango maximo (2^64 - 1) es practicamente infinito: a un millon de frames por segundo, desbordaria en 584.000 anos.

El cambio es incompatible con v2. No existen clientes de produccion que usen el formato viejo, asi que el break es limpio y correcto.

### FrameError — error tipado en lugar de anyhow

```rust
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("replay detected: received seq {received} <= last accepted {last_seen}")]
    Replay { received: u64, last_seen: u64 },
    #[error("AEAD decrypt failed (tampered ciphertext or AAD)")]
    AeadFailure,
    #[error("invalid frame: {0}")]
    Invalid(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
```

Antes de Mes 17, los errores de `read_frame` y `write_frame` eran `anyhow::Error`. Eso obligaba a los callers a hacer pattern matching sobre strings para distinguir un replay de un error de red — fragil y propenso a regresiones silenciosas. El enum `FrameError` hace la distincion explicita en el tipo: el compilador obliga a tratar `Replay` de forma diferente a `Io`. La variant `Io(#[from] std::io::Error)` permite que el operador `?` propague automaticamente los errores de `read_exact` sin ningun `map_err` manual.

### Los nuevos campos de EncryptedChannel

```rust
pub struct EncryptedChannel {
    cipher: Aes256Gcm,
    key_bytes: Zeroizing<[u8; 32]>,  // para el ratchet HKDF
    max_frame_size: usize,
    send_seq: u64,          // contador de frames enviados, arranca en 0
    recv_seq: u64,          // ultimo seq aceptado, arranca en 0
    recv_initialized: bool, // distingue "nunca recibido" de "recibio seq=0"
}
```

El campo `recv_initialized` merece atencion especial. El problema del bootstrap: en el primer frame de una epoca de clave, `recv_seq == 0` y el frame tiene `seq == 0`. La condicion `wire_seq <= recv_seq` se evaluaria como `0 <= 0` → true → Replay. Eso es incorrecto: el primer frame siempre tiene seq=0 y debe ser aceptado.

Una primera idea es eximir el caso `recv_seq == 0 && wire_seq == 0`. Pero eso abre una ventana: despues de aceptar el primer frame, `recv_seq` sigue siendo 0 (todavia no fue actualizado). Un replay del mismo frame pasaria la condicion de nuevo. La solucion correcta es el flag `recv_initialized`: la validacion monotona solo se activa despues de que se haya aceptado al menos un frame. El primer frame siempre pasa; todos los siguientes deben tener `seq > recv_seq`.

### write_frame — AAD sobre el seq

```rust
pub async fn write_frame(
    &mut self,
    writer: &mut (impl AsyncWrite + Unpin),
    data: &[u8],
) -> Result<(), FrameError> {
    let seq_be = self.send_seq.to_be_bytes();

    let mut buf = data.to_vec();
    // seq_be es el AAD — el GCM tag lo cubre sin cifrarlo
    let tag = self
        .cipher
        .encrypt_in_place_detached(nonce, &seq_be, &mut buf)
        .map_err(|_| FrameError::AeadFailure)?;

    writer.write_all(&[FRAME_DATA]).await?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&seq_be).await?;   // se escribe en claro
    writer.write_all(&nonce_bytes).await?;
    writer.write_all(&buf).await?;
    writer.write_all(tag.as_slice()).await?;

    self.send_seq += 1;
    Ok(())
}
```

El seq se escribe en claro en el wire (los 8 bytes despues del `len`), pero la llamada `encrypt_in_place_detached(nonce, &seq_be, &mut buf)` usa `seq_be` como AAD. El GCM tag que se produce cubre tanto el ciphertext como el AAD. Si un atacante modifica el byte del seq en el wire, el tag no coincide con la nueva combinacion (seq_modificado, ciphertext), y `decrypt_in_place_detached` falla con `AeadFailure`.

### read_frame — validacion monotona y bootstrap

```rust
// Validacion monotonica:
if self.recv_initialized && wire_seq <= self.recv_seq {
    return Err(FrameError::Replay {
        received: wire_seq,
        last_seen: self.recv_seq,
    });
}

// ... leer nonce, ciphertext+tag ...

self.cipher
    .decrypt_in_place_detached(nonce, &seq_be, &mut plaintext_buf, tag)
    .map_err(|_| FrameError::AeadFailure)?;

// Actualizar recv_seq solo despues del decrypt exitoso
self.recv_seq = wire_seq;
self.recv_initialized = true;
```

El orden importa: primero se verifica el seq, despues se descifra. Si el seq falla la validacion monotona, el frame se rechaza antes de gastar ciclos de CPU descifrando. Si el seq pasa pero el AEAD falla (tag incorrecto), el plaintext nunca se entrega al caller. El `recv_seq` solo se actualiza despues de que ambas validaciones tienen exito.

### Por que AAD en lugar de cifrar el seq?

Cifrar el seq dentro del ciphertext seria circular: para verificar el seq habria que descifrar primero, pero para decidir si descifrar habria que verificar el seq. AAD resuelve exactamente ese problema: el GCM mode autentica los bytes de AAD junto con el ciphertext, pero los bytes de AAD no forman parte del plaintext — viajan en claro y se verifican antes de que el plaintext sea accesible. El costo computacional es identico: AAD se procesa en el mismo paso de GHASH que el ciphertext, sin operacion extra.

### Por que u64 y no u32?

Un contador u32 desbordaria en 4.294 millones de frames. A 1 MB por frame y 1 Gbps de throughput, eso equivale a unos 34 segundos de trafico continuo antes de reutilizar seq=0. Un desbordamiento silencioso abriria la ventana de replay de nuevo. u64 hace el overflow practicamente imposible sin necesidad de codigo de mitigacion.

### rotate_key() — reset de toda la epoca

```rust
pub fn rotate_key(&mut self, nonce: &[u8; 32]) {
    // ... derivar nueva clave via HKDF-SHA256 ...

    // Resetear contadores — nueva epoca de secuencia
    self.send_seq = 0;
    self.recv_seq = 0;
    self.recv_initialized = false;
}
```

Cuando se rota la clave, los contadores se resetean porque la nueva clave define una nueva epoca. Los seq de la epoca anterior no tienen significado bajo la nueva clave. Un replay de un frame de la epoca anterior bajo la nueva clave fallaria el AEAD (las claves son distintas), pero resetear los contadores es igualmente correcto y evita cualquier confusion sobre el orden relativo entre epocas.

---

## latticeshield-crypto/src/lib.rs — re-export de FrameError

```rust
pub use channel::{EncryptedChannel, FrameError, FrameResult};
```

`FrameError` se re-exporta desde el crate raiz para que los callers en `latticeshield-bridge` y `latticeshield-client` puedan hacer `use latticeshield_crypto::FrameError` sin conocer la estructura interna del modulo.

---

## Callers actualizados: admin.rs y tests.rs

`write_frame` y `read_frame` son ahora `&mut self` (antes eran `&self`). Esto requirio un cambio mecanico en los callers: `let channel` → `let mut channel` en los puntos de binding. Los archivos afectados:

- `latticeshield-bridge/src/admin.rs`: un binding en el handler de sesion admin
- `latticeshield-bridge/src/tests.rs`: siete o mas bindings en los tests de integracion
- `latticeshield-client/src/client_session.rs`: sin cambios (ya era `mut`)
- `latticeshield-client/tests/integration.rs`: sin cambios (ya era `let mut channel`)
- `latticeshield-crypto/src/channel.rs`: todos los tests actualizados a `mut`

La propagacion de `&mut self` es consecuencia directa de que `send_seq` y `recv_seq` son estado mutable dentro del canal. No fue posible mantener la firma `&self` sin introducir un `Mutex` interno, lo que agregaria contention innecesaria — cada canal vive en una sola tarea async, no hay concurrencia dentro del canal.

---

## Cobertura de tests (+107 tests, 309 totales despues de Mes 17)

Mes 17 agrego 6 tests unitarios nuevos en `channel.rs` y la expansion de tests de integracion llevo el total de 202 a 309.

### Tests nuevos en channel.rs

| Test | Que verifica |
|------|-------------|
| `seq_increments_monotonically` | El primer frame tiene seq=0 en wire (bytes 5..13); el segundo tiene seq=1; `send_seq` es 1 y 2 respectivamente |
| `replay_frame_rejected` | Un frame con seq=0 leido dos veces retorna `FrameError::Replay { received: 0, last_seen: 0 }` en la segunda lectura |
| `post_rotation_seq_resets` | Despues de `rotate_key()`, `send_seq==0`, `recv_seq==0`; el primer frame post-rotacion tiene seq=0 en wire |
| `tampered_seq_returns_aead_failure` | Flipear un byte del campo seq en wire retorna `FrameError::AeadFailure` (el GCM tag cubre el seq como AAD) |
| `normal_sequential_receive` | Canal A escribe 3 frames (seq 0, 1, 2), canal B los lee en orden; `recv_seq==2` al final |

Los tests de rotacion existentes (`rotate_key_produces_different_ciphertext`, `rotate_key_is_deterministic_same_nonce`, `hkdf_ratchet_chain_two_rotations`) fueron actualizados para usar `let mut channel` y siguen pasando sin cambios de logica.
