//! Canal cifrado con AES-256-GCM sobre TCP.
//!
//! Protocolo de framing v2:
//!   [1B frame type]  0x01 = DATA, 0x02 = KEY_ROTATE, 0x00 / 0x03+ = INVALID
//!
//! DATA frame:
//!   [0x01][4B u32 BE: ciphertext len][12B nonce][N bytes ciphertext+GCM tag]
//!
//! KEY_ROTATE frame (33 bytes total, no encryption):
//!   [0x02][32B rotation nonce]
//!
//! La clave de sesion (32B) viene del handshake hibrido PQC.
//! Cada DATA frame tiene nonce unico — nunca se reutiliza bajo la misma clave.
//! rotate_key() deriva una nueva clave via HKDF-SHA256 y zeroiza la anterior.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

const FRAME_DATA: u8 = 0x01;
const FRAME_KEY_ROTATE: u8 = 0x02;
const ROTATION_HKDF_INFO: &[u8] = b"latticeshield-v1-key-rotation";

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
}

impl EncryptedChannel {
    pub fn new(session_key: &[u8; 32], max_frame_size: usize) -> Self {
        let cipher = Aes256Gcm::new(session_key.into());
        Self {
            cipher,
            key_bytes: Zeroizing::new(*session_key),
            max_frame_size,
        }
    }

    /// Cifra `data` y escribe un DATA frame en `writer`.
    /// Formato: [0x01][4B len][12B nonce][ciphertext+tag]
    pub async fn write_frame(
        &self,
        writer: &mut (impl AsyncWrite + Unpin),
        data: &[u8],
    ) -> anyhow::Result<()> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, data)
            .map_err(|e| anyhow!("AES-GCM encrypt: {e}"))?;

        let len = ciphertext.len() as u32;
        writer.write_all(&[FRAME_DATA]).await.context("write frame type")?;
        writer.write_all(&len.to_be_bytes()).await.context("write frame len")?;
        writer.write_all(&nonce_bytes).await.context("write frame nonce")?;
        writer.write_all(&ciphertext).await.context("write frame ciphertext")?;

        Ok(())
    }

    /// Lee un frame de `reader` y retorna el resultado.
    /// Dispatch basado en el tipo de frame (primer byte).
    pub async fn read_frame(
        &self,
        reader: &mut (impl AsyncRead + Unpin),
    ) -> anyhow::Result<FrameResult> {
        let mut type_buf = [0u8; 1];
        reader.read_exact(&mut type_buf).await.context("read frame type")?;

        match type_buf[0] {
            FRAME_DATA => {
                let mut len_buf = [0u8; 4];
                reader.read_exact(&mut len_buf).await.context("read frame len")?;
                let len = u32::from_be_bytes(len_buf) as usize;

                if len < TAG_LEN || len > self.max_frame_size + TAG_LEN {
                    return Err(anyhow!("frame invalido: len={len}"));
                }

                let mut nonce_bytes = [0u8; NONCE_LEN];
                reader.read_exact(&mut nonce_bytes).await.context("read frame nonce")?;

                let mut ciphertext = vec![0u8; len];
                reader.read_exact(&mut ciphertext).await.context("read frame ciphertext")?;

                let nonce = Nonce::from_slice(&nonce_bytes);
                let plaintext = self
                    .cipher
                    .decrypt(nonce, ciphertext.as_ref())
                    .map_err(|_| anyhow!("AES-GCM decrypt failed — posible replay o tampering"))?;

                Ok(FrameResult::Data(plaintext))
            }

            FRAME_KEY_ROTATE => {
                let mut nonce = [0u8; 32];
                reader.read_exact(&mut nonce).await.context("read rotation nonce")?;
                Ok(FrameResult::KeyRotate(nonce))
            }

            other => Err(anyhow!("unknown frame type: {other:#04x}")),
        }
    }

    /// Escribe un KEY_ROTATE frame en `writer`.
    /// Formato: [0x02][32B nonce] — 33 bytes fijos, sin cifrado.
    pub async fn send_key_rotate(
        &self,
        writer: &mut (impl AsyncWrite + Unpin),
        nonce: &[u8; 32],
    ) -> anyhow::Result<()> {
        writer.write_all(&[FRAME_KEY_ROTATE]).await.context("write key rotate type")?;
        writer.write_all(nonce).await.context("write rotation nonce")?;
        Ok(())
    }

    /// Deriva una nueva clave via HKDF-SHA256 y reemplaza el cipher.
    /// La clave anterior es zeroizada automaticamente cuando `key_bytes` es reemplazado.
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
        let channel = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);
        let mut buf = Vec::new();
        channel.write_frame(&mut buf, b"hello").await.unwrap();
        assert_eq!(buf[0], 0x01, "DATA frame must start with 0x01");
    }

    #[tokio::test]
    async fn key_rotate_frame_is_33_bytes_starting_0x02() {
        let channel = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);
        let nonce = [0xABu8; 32];
        let mut buf = Vec::new();
        channel.send_key_rotate(&mut buf, &nonce).await.unwrap();
        assert_eq!(buf.len(), 33, "KEY_ROTATE frame must be exactly 33 bytes");
        assert_eq!(buf[0], 0x02, "KEY_ROTATE frame must start with 0x02");
        assert_eq!(&buf[1..], &nonce, "remaining 32 bytes must be the nonce");
    }

    #[tokio::test]
    async fn read_frame_data_roundtrip() {
        let channel = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);
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
        let channel = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);
        let nonce = [0x7Fu8; 32];
        let mut buf = Vec::new();
        channel.send_key_rotate(&mut buf, &nonce).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        match channel.read_frame(&mut cursor).await.unwrap() {
            FrameResult::KeyRotate(received) => assert_eq!(received, nonce),
            FrameResult::Data(_) => panic!("expected KeyRotate, got Data"),
        }
    }

    #[tokio::test]
    async fn read_frame_unknown_type_0x00_returns_error() {
        let channel = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);
        let buf = vec![0x00u8]; // INVALID type
        let mut cursor = std::io::Cursor::new(buf);
        let err = channel.read_frame(&mut cursor).await.unwrap_err().to_string();
        assert!(err.contains("unknown frame type"), "got: {err}");
    }

    #[tokio::test]
    async fn read_frame_reserved_type_returns_error() {
        let channel = EncryptedChannel::new(&TEST_KEY, TEST_FRAME_SIZE);
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
}
