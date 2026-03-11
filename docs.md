main.rs — El punto de entrada

Es el primer archivo que ejecuta Rust cuando arrancás el programa. Hace exactamente tres cosas:

1. Parsear los argumentos de línea de comandos (con la librería clap):
   latticeshield-bridge → arranca el proxy (modo normal)
   latticeshield-bridge --config mi.toml → usa un config custom
   latticeshield-bridge keygen ./keys → genera las claves ML-DSA-65 del servidor
   latticeshield-bridge tls-keygen ./keys → genera cert.pem + key.pem para el listener TLS/QUIC

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
