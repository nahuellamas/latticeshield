//! Error types para el crate WASM.
//!
//! `WasmError` se convierte en `JsValue` (string de error) para cruzar el boundary WASM.

use wasm_bindgen::JsValue;

/// Errores del crate `latticeshield-wasm`.
#[derive(Debug)]
pub enum WasmError {
    /// Longitud de clave invalida.
    InvalidKeyLength { expected: usize, got: usize },
    /// Longitud de firma invalida.
    InvalidSignatureLength { expected: usize, got: usize },
    /// Error durante la operacion de firma ML-DSA-65.
    SignError,
    /// Error durante la verificacion ML-DSA-65.
    VerifyError,
    /// Error durante el handshake (parse, encapsulate, HKDF, autenticacion).
    HandshakeError(String),
    /// Error interno al operar con JsValue.
    JsError(String),
}

impl WasmError {
    /// Convierte en `JsValue` para retornar al caller JS.
    pub fn into_js(self) -> JsValue {
        JsValue::from_str(&self.to_string())
    }

    /// Wraps un JsValue generico (e.g. de js_sys::Reflect) en un WasmError.
    pub fn from_js(val: JsValue) -> Self {
        WasmError::JsError(
            val.as_string()
                .unwrap_or_else(|| "unknown JS error".to_string()),
        )
    }
}

impl std::fmt::Display for WasmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WasmError::InvalidKeyLength { expected, got } => {
                write!(
                    f,
                    "invalid key length: expected {} bytes, got {}",
                    expected, got
                )
            }
            WasmError::InvalidSignatureLength { expected, got } => {
                write!(
                    f,
                    "invalid signature length: expected {} bytes, got {}",
                    expected, got
                )
            }
            WasmError::SignError => write!(f, "ML-DSA-65 signing operation failed"),
            WasmError::VerifyError => write!(f, "ML-DSA-65 signature verification failed"),
            WasmError::HandshakeError(msg) => write!(f, "handshake error: {}", msg),
            WasmError::JsError(msg) => write!(f, "JS error: {}", msg),
        }
    }
}

impl From<WasmError> for JsValue {
    fn from(e: WasmError) -> Self {
        e.into_js()
    }
}
