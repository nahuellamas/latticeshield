//! Canal cifrado con AES-256-GCM sobre TCP.
//!
//! Protocolo de framing (data phase):
//!   [4B u32 BE]  longitud del ciphertext (incluye 16B tag GCM)
//!   [12B]        nonce aleatorio por frame
//!   [N bytes]    ciphertext + GCM tag
//!
//! La clave de sesion (32B) viene del handshake hibrido PQC.
//! Cada frame tiene nonce unico — nunca se reutiliza bajo la misma clave.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context};
use rand_core::{OsRng, RngCore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

pub struct EncryptedChannel {
    cipher: Aes256Gcm,
    max_frame_size: usize,
}

impl EncryptedChannel {
    pub fn new(session_key: &[u8; 32], max_frame_size: usize) -> Self {
        let cipher = Aes256Gcm::new(session_key.into());
        Self { cipher, max_frame_size }
    }

    /// Cifra `data` y escribe un frame en `writer`.
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
        writer.write_all(&len.to_be_bytes()).await.context("write frame len")?;
        writer.write_all(&nonce_bytes).await.context("write frame nonce")?;
        writer.write_all(&ciphertext).await.context("write frame ciphertext")?;

        Ok(())
    }

    /// Lee un frame de `reader` y retorna el plaintext descifrado.
    pub async fn read_frame(
        &self,
        reader: &mut (impl AsyncRead + Unpin),
    ) -> anyhow::Result<Vec<u8>> {
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

        Ok(plaintext)
    }
}
