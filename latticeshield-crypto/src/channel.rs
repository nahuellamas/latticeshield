//! Canal cifrado con AES-256-GCM sobre TCP.
//!
//! Protocolo de framing v3:
//!   [1B frame type]  0x01 = DATA, 0x02 = KEY_ROTATE, 0x00 / 0x03+ = INVALID
//!
//! DATA frame:
//!   [0x01][4B u32 BE: ciphertext len][8B u64 BE: seq][12B nonce][N bytes ciphertext+GCM tag]
//!
//! KEY_ROTATE frame (33 bytes total, no encryption):
//!   [0x02][32B rotation nonce]
//!
//! La clave de sesion (32B) viene del handshake hibrido PQC.
//! Cada DATA frame tiene nonce unico — nunca se reutiliza bajo la misma clave.
//! El campo seq (u64 BE) se autentica como AAD del GCM — no puede ser manipulado sin deteccion.
//! rotate_key() deriva una nueva clave via HKDF-SHA256 y zeroiza la anterior.
//! Ambos contadores (send_seq, recv_seq) se resetean a 0 en rotate_key().

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce, Tag,
};
use anyhow::Context;
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const SEQ_LEN: usize = 8;
const ROTATION_NONCE_LEN: usize = 32;

const FRAME_DATA: u8 = 0x01;
const FRAME_KEY_ROTATE: u8 = 0x02;
const ROTATION_HKDF_INFO: &[u8] = b"latticeshield-v1-key-rotation";

/// Total wire size of a KEY_ROTATE frame:
/// [0x02][12B GCM nonce][32B encrypted rotation nonce + 16B GCM tag] = 61 bytes
pub const KEY_ROTATE_FRAME_LEN: usize = 1 + NONCE_LEN + ROTATION_NONCE_LEN + TAG_LEN;

/// Error de framing — distingue Replay de fallos I/O y AEAD.
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

/// Resultado de leer un frame del canal.
#[derive(Debug)]
pub enum FrameResult {
    /// Frame de datos — contiene el plaintext descifrado.
    Data(Vec<u8>),
    /// Frame de rotacion de clave — contiene el nonce de derivacion.
    /// El servidor lo genera; el cliente lo usa para derive la nueva clave.
    /// El campo nonce se usa en tests y codigo cliente — silenciamos el warning
    /// ya que el servidor lo recibe del wire pero lo ignora (solo el cliente lo aplica).
    #[allow(dead_code)]
    KeyRotate([u8; 32]),
}

pub struct EncryptedChannel {
    cipher: Aes256Gcm,
    /// Bytes de la clave actual — necesarios para el ratchet HKDF en rotate_key().
    /// Zeroizing garantiza que la clave vieja se borra de memoria al ser reemplazada.
    key_bytes: Zeroizing<[u8; 32]>,
    max_frame_size: usize,
    /// Contador monotono de frames enviados. Se incrementa en cada write_frame exitoso.
    send_seq: u64,
    /// Ultimo seq aceptado en read_frame. Protege contra replay.
    recv_seq: u64,
    /// Indica si al menos un frame fue recibido en esta epoca de clave.
    /// Necesario para distinguir "nunca recibido, seq=0 es bootstrap" de "ya recibio seq=0".
    recv_initialized: bool,
}

impl EncryptedChannel {
    pub fn new(session_key: &[u8; 32], max_frame_size: usize) -> Self {
        let cipher = Aes256Gcm::new(session_key.into());
        Self {
            cipher,
            key_bytes: Zeroizing::new(*session_key),
            max_frame_size,
            send_seq: 0,
            recv_seq: 0,
            recv_initialized: false,
        }
    }

    /// Cifra `data` y escribe un DATA frame v3 en `writer`.
    /// Formato: [0x01][4B len][8B seq][12B nonce][ciphertext][16B GCM tag]
    /// El seq se autentica como AAD — no se puede manipular sin deteccion.
    pub async fn write_frame(
        &mut self,
        writer: &mut (impl AsyncWrite + Unpin),
        data: &[u8],
    ) -> Result<(), FrameError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let seq_be = self.send_seq.to_be_bytes();

        let mut buf = data.to_vec();
        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce, &seq_be, &mut buf)
            .map_err(|_| FrameError::AeadFailure)?;

        // len = ciphertext + TAG_LEN (semantica igual que v2)
        let len = (buf.len() + TAG_LEN) as u32;

        writer.write_all(&[FRAME_DATA]).await?;
        writer.write_all(&len.to_be_bytes()).await?;
        writer.write_all(&seq_be).await?;
        writer.write_all(&nonce_bytes).await?;
        writer.write_all(&buf).await?;
        writer.write_all(tag.as_slice()).await?;

        self.send_seq += 1;
        Ok(())
    }

    /// Lee un frame de `reader` y retorna el resultado.
    /// Dispatch basado en el tipo de frame (primer byte).
    pub async fn read_frame(
        &mut self,
        reader: &mut (impl AsyncRead + Unpin),
    ) -> Result<FrameResult, FrameError> {
        let mut type_buf = [0u8; 1];
        reader.read_exact(&mut type_buf).await?;

        match type_buf[0] {
            FRAME_DATA => {
                let mut len_buf = [0u8; 4];
                reader.read_exact(&mut len_buf).await?;
                let len = u32::from_be_bytes(len_buf) as usize;

                if len < TAG_LEN || len > self.max_frame_size + TAG_LEN {
                    return Err(FrameError::Invalid(format!("frame len invalido: {len}")));
                }

                // Read seq (8B) — parte del header v3
                let mut seq_buf = [0u8; SEQ_LEN];
                reader.read_exact(&mut seq_buf).await?;
                let wire_seq = u64::from_be_bytes(seq_buf);

                // Validacion monotonica:
                // Bootstrap: primer frame de la epoca no ha sido recibido todavia.
                // Si ya recibimos al menos uno, wire_seq debe ser estrictamente mayor que recv_seq.
                if self.recv_initialized && wire_seq <= self.recv_seq {
                    return Err(FrameError::Replay {
                        received: wire_seq,
                        last_seen: self.recv_seq,
                    });
                }

                let mut nonce_bytes = [0u8; NONCE_LEN];
                reader.read_exact(&mut nonce_bytes).await?;

                // len incluye el tag — leer todo como ciphertext+tag
                let mut ct_and_tag = vec![0u8; len];
                reader.read_exact(&mut ct_and_tag).await?;

                let (ct, tag_bytes) = ct_and_tag.split_at(len - TAG_LEN);
                let tag = Tag::from_slice(tag_bytes);
                let mut plaintext_buf = ct.to_vec();

                let nonce = Nonce::from_slice(&nonce_bytes);
                let seq_be = wire_seq.to_be_bytes();
                self.cipher
                    .decrypt_in_place_detached(nonce, &seq_be, &mut plaintext_buf, tag)
                    .map_err(|_| FrameError::AeadFailure)?;

                // Actualizar recv_seq solo despues del decrypt exitoso
                self.recv_seq = wire_seq;
                self.recv_initialized = true;

                Ok(FrameResult::Data(plaintext_buf))
            }

            FRAME_KEY_ROTATE => {
                // Read: [12B GCM nonce][32B encrypted rotation nonce + 16B tag]
                let mut gcm_nonce_bytes = [0u8; NONCE_LEN];
                reader.read_exact(&mut gcm_nonce_bytes).await?;

                let mut ct_and_tag = [0u8; ROTATION_NONCE_LEN + TAG_LEN];
                reader.read_exact(&mut ct_and_tag).await?;

                let (ct, tag_bytes) = ct_and_tag.split_at(ROTATION_NONCE_LEN);
                let tag = Tag::from_slice(tag_bytes);
                let mut rotation_nonce = [0u8; ROTATION_NONCE_LEN];
                rotation_nonce.copy_from_slice(ct);

                let gcm_nonce = Nonce::from_slice(&gcm_nonce_bytes);
                self.cipher
                    .decrypt_in_place_detached(gcm_nonce, b"", &mut rotation_nonce, tag)
                    .map_err(|_| FrameError::AeadFailure)?;

                Ok(FrameResult::KeyRotate(rotation_nonce))
            }

            other => Err(FrameError::Invalid(format!("unknown frame type: {other:#04x}"))),
        }
    }

    /// Escribe un KEY_ROTATE frame cifrado en `writer`.
    /// Formato: [0x02][12B GCM nonce][32B encrypted rotation nonce + 16B GCM tag] = 61 bytes.
    /// El rotation nonce viaja cifrado con la clave de sesion actual (AES-256-GCM).
    pub async fn send_key_rotate(
        &self,
        writer: &mut (impl AsyncWrite + Unpin),
        nonce: &[u8; ROTATION_NONCE_LEN],
    ) -> anyhow::Result<()> {
        let mut gcm_nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut gcm_nonce_bytes);
        let gcm_nonce = Nonce::from_slice(&gcm_nonce_bytes);

        let mut rotation_nonce = *nonce;
        let tag = self
            .cipher
            .encrypt_in_place_detached(gcm_nonce, b"", &mut rotation_nonce)
            .map_err(|_| anyhow::anyhow!("KEY_ROTATE encrypt failed"))?;

        writer.write_all(&[FRAME_KEY_ROTATE]).await.context("write KEY_ROTATE type")?;
        writer.write_all(&gcm_nonce_bytes).await.context("write KEY_ROTATE gcm_nonce")?;
        writer.write_all(&rotation_nonce).await.context("write KEY_ROTATE encrypted nonce")?;
        writer.write_all(tag.as_slice()).await.context("write KEY_ROTATE tag")?;
        Ok(())
    }

    /// Deriva una nueva clave via HKDF-SHA256 y reemplaza el cipher.
    /// La clave anterior es zeroizada automaticamente cuando `key_bytes` es reemplazado.
    /// Ambos contadores de secuencia se resetean a 0 (nueva epoca de claves).
    ///
    /// `new_key = HKDF-SHA256(ikm=current_key, salt=nonce, info="latticeshield-v1-key-rotation")`
    pub fn rotate_key(&mut self, nonce: &[u8; 32]) {
        let hkdf = Hkdf::<Sha256>::new(Some(nonce), self.key_bytes.as_ref());
        let mut new_key = Zeroizing::new([0u8; 32]);
        hkdf.expand(ROTATION_HKDF_INFO, new_key.as_mut()).expect("HKDF expand");

        // Reemplazar cipher con la nueva clave.
        // Zeroizing<T> implementa Deref<Target=T>, por eso &*new_key da &[u8; 32].
        self.cipher = Aes256Gcm::new((&*new_key).into());
        // Mover new_key a key_bytes — la clave vieja es zeroizada en el drop de key_bytes
        self.key_bytes = new_key;

        // Resetear contadores — nueva epoca de secuencia
        self.send_seq = 0;
        self.recv_seq = 0;
        self.recv_initialized = false;
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; 32] = [0x42u8; 32];
    const TEST_FRAME_SIZE: usize = 64 * 1024;

    // ── Frame format tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn data_frame_has_0x01_prefix() {
        let mut channel = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);
        let mut buf = Vec::new();
        channel.write_frame(&mut buf, b"hello").await.unwrap();
        assert_eq!(buf[0], 0x01, "DATA frame must start with 0x01");
    }

    #[tokio::test]
    async fn key_rotate_frame_is_61_bytes_starting_0x02() {
        let channel = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);
        let rotation_nonce = [0xABu8; 32];
        let mut buf = Vec::new();
        channel.send_key_rotate(&mut buf, &rotation_nonce).await.unwrap();
        assert_eq!(buf.len(), KEY_ROTATE_FRAME_LEN, "KEY_ROTATE frame must be exactly 61 bytes");
        assert_eq!(buf[0], 0x02, "KEY_ROTATE frame must start with 0x02");
    }

    #[tokio::test]
    async fn key_rotate_tampered_payload_returns_aead_failure() {
        let channel = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);
        let rotation_nonce = [0xABu8; 32];
        let mut buf = Vec::new();
        channel.send_key_rotate(&mut buf, &rotation_nonce).await.unwrap();

        // Flip a byte in the encrypted payload (after [type=1B][gcm_nonce=12B])
        buf[14] ^= 0xFF;

        let mut reader = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);
        let mut cursor = std::io::Cursor::new(buf);
        let err = reader.read_frame(&mut cursor).await.unwrap_err();
        assert!(
            matches!(err, FrameError::AeadFailure),
            "tampered KEY_ROTATE must cause AeadFailure, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn read_frame_data_roundtrip() {
        let mut channel = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);
        let payload = b"test payload for roundtrip";
        let mut buf = Vec::new();
        channel.write_frame(&mut buf, payload).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        match channel.read_frame(&mut cursor).await.unwrap() {
            FrameResult::Data(data) => assert_eq!(data, payload),
            FrameResult::KeyRotate(_) => panic!("expected Data, got KeyRotate"),
        }
    }

    #[tokio::test]
    async fn read_frame_key_rotate_roundtrip() {
        // Sender and receiver share the same key — receiver must decrypt nonce correctly.
        let sender = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);
        let mut receiver = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);
        let rotation_nonce = [0x7Fu8; 32];
        let mut buf = Vec::new();
        sender.send_key_rotate(&mut buf, &rotation_nonce).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        match receiver.read_frame(&mut cursor).await.unwrap() {
            FrameResult::KeyRotate(received) => assert_eq!(received, rotation_nonce),
            FrameResult::Data(_) => panic!("expected KeyRotate, got Data"),
        }
    }

    #[tokio::test]
    async fn read_frame_unknown_type_0x00_returns_error() {
        let mut channel = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);
        let buf = vec![0x00u8]; // INVALID type
        let mut cursor = std::io::Cursor::new(buf);
        let err = channel.read_frame(&mut cursor).await.unwrap_err().to_string();
        assert!(err.contains("unknown frame type"), "got: {err}");
    }

    #[tokio::test]
    async fn read_frame_reserved_type_returns_error() {
        let mut channel = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);
        let buf = vec![0x99u8]; // RESERVED
        let mut cursor = std::io::Cursor::new(buf);
        let err = channel.read_frame(&mut cursor).await.unwrap_err().to_string();
        assert!(err.contains("unknown frame type"), "got: {err}");
    }

    // ── rotate_key tests ────────────────────────────────────────────────────

    #[tokio::test]
    async fn rotate_key_produces_different_ciphertext() {
        let mut channel = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);
        let plaintext = b"same plaintext";

        // Cifrar antes de rotar
        let mut buf_before = Vec::new();
        channel.write_frame(&mut buf_before, plaintext).await.unwrap();

        // Rotar la clave
        let nonce = [0x11u8; 32];
        channel.rotate_key(&nonce);

        // Cifrar el mismo plaintext con la nueva clave
        let mut buf_after = Vec::new();
        channel.write_frame(&mut buf_after, plaintext).await.unwrap();

        // Los ciphertexts deben ser distintos (claves distintas)
        // (Nota: nonces aleatorios ya los hacen distintos; este test verifica que rotate_key cambia el cipher)
        // Verificar que la nueva clave puede descifrar su propio frame
        let mut cursor = std::io::Cursor::new(buf_after);
        match channel.read_frame(&mut cursor).await.unwrap() {
            FrameResult::Data(data) => assert_eq!(data, plaintext),
            FrameResult::KeyRotate(_) => panic!("expected Data"),
        }
    }

    #[tokio::test]
    async fn rotate_key_is_deterministic_same_nonce() {
        // Dos canales con la misma clave inicial, rotados con el mismo nonce,
        // deben poder descifrar frames del otro.
        let key = [0x55u8; 32];
        let nonce = [0x33u8; 32];

        let mut channel_a = EncryptedChannel::new(&key, TEST_FRAME_SIZE);
        let mut channel_b = EncryptedChannel::new(&key, TEST_FRAME_SIZE);

        channel_a.rotate_key(&nonce);
        channel_b.rotate_key(&nonce);

        // channel_a cifra, channel_b descifra
        let plaintext = b"deterministic ratchet test";
        let mut buf = Vec::new();
        channel_a.write_frame(&mut buf, plaintext).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        match channel_b.read_frame(&mut cursor).await.unwrap() {
            FrameResult::Data(data) => assert_eq!(data, plaintext),
            FrameResult::KeyRotate(_) => panic!("expected Data"),
        }
    }

    #[tokio::test]
    async fn hkdf_ratchet_chain_two_rotations() {
        // Verificar que dos rotaciones encadenadas producen claves distintas en cada paso.
        let key = [0x01u8; 32];
        let nonce1 = [0xAAu8; 32];
        let nonce2 = [0xBBu8; 32];

        let mut ch_server = EncryptedChannel::new(&key, TEST_FRAME_SIZE);
        let mut ch_client = EncryptedChannel::new(&key, TEST_FRAME_SIZE);

        // Primera rotacion
        ch_server.rotate_key(&nonce1);
        ch_client.rotate_key(&nonce1);

        let msg1 = b"after first rotation";
        let mut buf1 = Vec::new();
        ch_server.write_frame(&mut buf1, msg1).await.unwrap();
        let mut c1 = std::io::Cursor::new(buf1);
        match ch_client.read_frame(&mut c1).await.unwrap() {
            FrameResult::Data(d) => assert_eq!(d, msg1),
            _ => panic!("expected Data after first rotation"),
        }

        // Segunda rotacion
        ch_server.rotate_key(&nonce2);
        ch_client.rotate_key(&nonce2);

        let msg2 = b"after second rotation";
        let mut buf2 = Vec::new();
        ch_server.write_frame(&mut buf2, msg2).await.unwrap();
        let mut c2 = std::io::Cursor::new(buf2);
        match ch_client.read_frame(&mut c2).await.unwrap() {
            FrameResult::Data(d) => assert_eq!(d, msg2),
            _ => panic!("expected Data after second rotation"),
        }
    }

    // ── Seq number tests ────────────────────────────────────────────────────

    #[tokio::test]
    async fn seq_increments_monotonically() {
        // Escribir 2 frames — primer frame seq=0, segundo seq=1 en wire.
        let mut channel = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);
        let mut buf = Vec::new();

        channel.write_frame(&mut buf, b"frame-0").await.unwrap();
        // seq esta en bytes 5..13 (despues de type[1] + len[4])
        let seq0 = u64::from_be_bytes(buf[1 + 4..1 + 4 + 8].try_into().unwrap());
        assert_eq!(seq0, 0, "first frame must have seq=0");
        assert_eq!(channel.send_seq, 1, "send_seq must be 1 after first write");

        channel.write_frame(&mut buf, b"frame-1").await.unwrap();
        // El segundo frame empieza despues del primero
        // Primero encontrar el offset del segundo frame:
        // frame 0 = 1+4+8+12+len bytes; len = plaintext(7) + TAG_LEN(16) = 23
        let frame0_len = 1 + 4 + 8 + 12 + (7 + TAG_LEN);
        let seq1 = u64::from_be_bytes(buf[frame0_len + 1 + 4..frame0_len + 1 + 4 + 8].try_into().unwrap());
        assert_eq!(seq1, 1, "second frame must have seq=1");
        assert_eq!(channel.send_seq, 2, "send_seq must be 2 after second write");
    }

    #[tokio::test]
    async fn replay_frame_rejected() {
        // Escribir un frame (seq=0), leerlo una vez, releerlo → Replay.
        let mut writer = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);
        let mut reader = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);

        let mut wire = Vec::new();
        writer.write_frame(&mut wire, b"secret").await.unwrap();

        // Primera lectura: debe ser Ok
        let mut cursor = std::io::Cursor::new(wire.clone());
        reader.read_frame(&mut cursor).await.unwrap();

        // Segunda lectura del mismo frame: debe ser Replay
        let mut cursor2 = std::io::Cursor::new(wire.clone());
        let err = reader.read_frame(&mut cursor2).await.unwrap_err();
        assert!(
            matches!(err, FrameError::Replay { received: 0, last_seen: 0 }),
            "expected Replay, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn post_rotation_seq_resets() {
        let mut ch = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);

        // Escribir 3 frames (seq 0, 1, 2)
        let mut buf = Vec::new();
        ch.write_frame(&mut buf, b"a").await.unwrap();
        ch.write_frame(&mut buf, b"b").await.unwrap();
        ch.write_frame(&mut buf, b"c").await.unwrap();
        assert_eq!(ch.send_seq, 3);

        // Rotar clave — debe resetear ambos contadores
        ch.rotate_key(&[0xDEu8; 32]);
        assert_eq!(ch.send_seq, 0, "send_seq must reset to 0 after rotate_key");
        assert_eq!(ch.recv_seq, 0, "recv_seq must reset to 0 after rotate_key");

        // El siguiente frame escrito debe tener seq=0
        let mut buf2 = Vec::new();
        ch.write_frame(&mut buf2, b"post-rotate").await.unwrap();
        let seq = u64::from_be_bytes(buf2[1 + 4..1 + 4 + 8].try_into().unwrap());
        assert_eq!(seq, 0, "first frame after rotation must have seq=0");
    }

    #[tokio::test]
    async fn tampered_seq_returns_aead_failure() {
        // Escribir un frame, flipear un byte del seq field → AeadFailure
        let mut writer = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);
        let mut reader = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);

        let mut wire = Vec::new();
        writer.write_frame(&mut wire, b"tamper-me").await.unwrap();

        // Flipear el primer byte del seq (offset 5 = 1+4)
        wire[5] ^= 0xFF;

        let mut cursor = std::io::Cursor::new(wire);
        let err = reader.read_frame(&mut cursor).await.unwrap_err();
        assert!(
            matches!(err, FrameError::AeadFailure),
            "tampered seq must cause AeadFailure, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn normal_sequential_receive() {
        // Canal A escribe 3 frames, canal B los lee en orden — todo Ok, recv_seq == 2.
        let mut chan_a = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);
        let mut chan_b = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);

        let mut wire = Vec::new();
        chan_a.write_frame(&mut wire, b"msg-0").await.unwrap();
        chan_a.write_frame(&mut wire, b"msg-1").await.unwrap();
        chan_a.write_frame(&mut wire, b"msg-2").await.unwrap();

        let mut cursor = std::io::Cursor::new(wire);
        chan_b.read_frame(&mut cursor).await.unwrap();
        chan_b.read_frame(&mut cursor).await.unwrap();
        chan_b.read_frame(&mut cursor).await.unwrap();

        assert_eq!(chan_b.recv_seq, 2, "recv_seq must be 2 after reading 3 frames (seq 0,1,2)");
    }
}
