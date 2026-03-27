#![forbid(unsafe_code)]

use wasm_bindgen::prelude::*;

pub mod error;
pub mod handshake;
pub mod signing;

use error::WasmError;
use signing::{
    generate_keypair as crypto_generate_keypair, sign_msg, verify_msg, SIGNING_KEY_LEN,
    VERIFYING_KEY_LEN,
};

// ── Signing exports ───────────────────────────────────────────────────────────

/// Genera un par de claves ML-DSA-65.
///
/// Retorna un objeto JS con propiedades `sk` (Uint8Array, 4032B) y `vk` (Uint8Array, 1952B).
#[wasm_bindgen]
pub fn wasm_generate_keypair() -> Result<JsValue, JsValue> {
    let mut rng = rand_core::OsRng;
    let (sk, vk) = crypto_generate_keypair(&mut rng);

    let obj = js_sys::Object::new();

    let sk_arr = js_sys::Uint8Array::from(sk.to_bytes().as_ref());
    let vk_arr = js_sys::Uint8Array::from(vk.to_bytes().as_ref());

    js_sys::Reflect::set(&obj, &JsValue::from_str("sk"), &sk_arr)
        .map_err(|e| WasmError::from_js(e).into_js())?;
    js_sys::Reflect::set(&obj, &JsValue::from_str("vk"), &vk_arr)
        .map_err(|e| WasmError::from_js(e).into_js())?;

    Ok(obj.into())
}

/// Firma `msg` con la clave de firma ML-DSA-65 provista.
///
/// `sk_bytes` debe ser exactamente 4032 bytes. Retorna la firma (3309 bytes).
#[wasm_bindgen]
pub fn wasm_sign(sk_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, JsValue> {
    if sk_bytes.len() != SIGNING_KEY_LEN {
        return Err(WasmError::InvalidKeyLength {
            expected: SIGNING_KEY_LEN,
            got: sk_bytes.len(),
        }
        .into_js());
    }
    sign_msg(sk_bytes, msg).map_err(|e| e.into_js())
}

/// Verifica `sig` sobre `msg` con la clave de verificacion ML-DSA-65 provista.
///
/// Retorna `Ok(())` si la firma es valida, `Err` en caso contrario.
#[wasm_bindgen]
pub fn wasm_verify(vk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<(), JsValue> {
    if vk_bytes.len() != VERIFYING_KEY_LEN {
        return Err(WasmError::InvalidKeyLength {
            expected: VERIFYING_KEY_LEN,
            got: vk_bytes.len(),
        }
        .into_js());
    }
    verify_msg(vk_bytes, msg, sig_bytes).map_err(|e| e.into_js())
}

// ── Handshake exports ─────────────────────────────────────────────────────────

/// Genera la respuesta del cliente dado un ServerHello firmado y la VerifyingKey pre-shared.
///
/// `server_hello_signed` debe ser 4557 bytes ([1248B hello][3309B sig]).
/// `server_vk_bytes` debe ser 1952 bytes.
///
/// Retorna un objeto JS con:
/// - `client_response`: Uint8Array(1120)
/// - `session_key`: Uint8Array(32)
#[wasm_bindgen]
pub fn wasm_generate_client_response(
    server_hello_signed: &[u8],
    server_vk_bytes: &[u8],
) -> Result<JsValue, JsValue> {
    let (cr_bytes, sk_bytes) =
        handshake::generate_client_response(server_hello_signed, server_vk_bytes)
            .map_err(|e| e.into_js())?;

    let obj = js_sys::Object::new();

    let cr_arr = js_sys::Uint8Array::from(cr_bytes.as_ref());
    let sk_arr = js_sys::Uint8Array::from(sk_bytes.as_ref());

    js_sys::Reflect::set(&obj, &JsValue::from_str("client_response"), &cr_arr)
        .map_err(|e| WasmError::from_js(e).into_js())?;
    js_sys::Reflect::set(&obj, &JsValue::from_str("session_key"), &sk_arr)
        .map_err(|e| WasmError::from_js(e).into_js())?;

    Ok(obj.into())
}
