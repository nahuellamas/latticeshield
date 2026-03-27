use wasm_bindgen_test::*;

// Run tests in Node.js (no chromedriver required — works in headless CI)
// wasm_bindgen_test_configure!(run_in_browser); // disabled — use --node runner

use latticeshield_wasm::handshake::{
    generate_client_response, CLIENT_RESPONSE_LEN, MLKEM768_EK_LEN, NONCE_LEN, SERVER_HELLO_LEN,
    SERVER_HELLO_SIGNED_LEN, SESSION_KEY_LEN, X25519_KEY_LEN,
};
use latticeshield_wasm::signing::{
    generate_keypair, sign_msg, verify_msg, SIGNATURE_LEN, SIGNING_KEY_LEN, VERIFYING_KEY_LEN,
};

// ── Task 4.1: sign+verify round-trip ─────────────────────────────────────────

#[wasm_bindgen_test]
fn sign_verify_round_trip() {
    let mut rng = rand_core::OsRng;
    let (sk, vk) = generate_keypair(&mut rng);
    let msg = b"latticeshield firmware v1.0";

    let sig = sign_msg(sk.to_bytes(), msg).expect("sign should succeed");
    assert_eq!(
        sig.len(),
        SIGNATURE_LEN,
        "signature must be {} bytes",
        SIGNATURE_LEN
    );

    verify_msg(vk.to_bytes(), msg, &sig).expect("verify should succeed for valid sig");
}

// ── Task 4.2: tampered message fails verify ───────────────────────────────────

#[wasm_bindgen_test]
fn tampered_message_fails_verify() {
    let mut rng = rand_core::OsRng;
    let (sk, vk) = generate_keypair(&mut rng);
    let msg = b"latticeshield firmware v1.0";
    let tampered = b"latticeshield firmware v2.0";

    let sig = sign_msg(sk.to_bytes(), msg).expect("sign should succeed");
    let result = verify_msg(vk.to_bytes(), tampered, &sig);
    assert!(result.is_err(), "tampered message must fail verification");
}

// ── Task 4.3: keypair byte lengths ───────────────────────────────────────────

#[wasm_bindgen_test]
fn keypair_byte_lengths() {
    let mut rng = rand_core::OsRng;
    let (sk, vk) = generate_keypair(&mut rng);

    assert_eq!(
        sk.to_bytes().len(),
        SIGNING_KEY_LEN,
        "SK must be {} bytes",
        SIGNING_KEY_LEN
    );
    assert_eq!(
        vk.to_bytes().len(),
        VERIFYING_KEY_LEN,
        "VK must be {} bytes",
        VERIFYING_KEY_LEN
    );
}

#[wasm_bindgen_test]
fn wrong_key_length_returns_err() {
    // sign with wrong-length key must return Err, not panic
    let result = sign_msg(&[0u8; 10], b"msg");
    assert!(result.is_err(), "wrong key length must return Err");

    // verify with wrong-length vk must return Err
    let result2 = verify_msg(&[0u8; 10], b"msg", &[0u8; SIGNATURE_LEN]);
    assert!(result2.is_err(), "wrong VK length must return Err");
}

// ── Task 4.4: ML-KEM client response round-trip ───────────────────────────────
//
// We build a synthetic server_hello_signed in pure Rust (no latticeshield-crypto dep):
// 1. Generate server ML-DSA-65 keypair
// 2. Construct SERVER_HELLO bytes: random X25519 pubkey + ML-KEM EK + nonce
// 3. Sign SERVER_HELLO with server SK → SERVER_HELLO_SIGNED
// 4. Call wasm_generate_client_response → get (client_response, session_key)
// 5. Assert sizes

#[wasm_bindgen_test]
fn ml_kem_client_response_round_trip() {
    use libcrux_ml_dsa::ml_dsa_65;
    use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
    use rand_core::RngCore;
    let mut rng = rand_core::OsRng;

    // 1. Server ML-DSA-65 keypair (for signing ServerHello)
    let mut seed = [0u8; libcrux_ml_dsa::KEY_GENERATION_RANDOMNESS_SIZE];
    rng.fill_bytes(&mut seed);
    let kp = ml_dsa_65::portable::generate_key_pair(seed);

    // 2. Build SERVER_HELLO: [32B X25519 pub] [1184B ML-KEM EK] [32B nonce]
    let mut server_hello = [0u8; SERVER_HELLO_LEN];

    // Random X25519 ephemeral key
    let mut x25519_sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut x25519_sk_bytes);
    let x25519_secret = x25519_dalek::StaticSecret::from(x25519_sk_bytes);
    let x25519_pub = x25519_dalek::PublicKey::from(&x25519_secret);
    server_hello[..X25519_KEY_LEN].copy_from_slice(x25519_pub.as_bytes());

    // ML-KEM-768 keypair (server generates DK + EK)
    let (_kem_dk, kem_ek) = MlKem768::generate(&mut rng);
    let ek_encoded = kem_ek.as_bytes();
    let ek_bytes: &[u8] = ek_encoded.as_ref();
    server_hello[X25519_KEY_LEN..X25519_KEY_LEN + MLKEM768_EK_LEN].copy_from_slice(ek_bytes);

    // Random nonce
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    server_hello[X25519_KEY_LEN + MLKEM768_EK_LEN..].copy_from_slice(&nonce);

    // 3. Sign SERVER_HELLO → SERVER_HELLO_SIGNED
    let sk_bytes: &[u8; latticeshield_wasm::signing::SIGNING_KEY_LEN] = kp.signing_key.as_ref();
    let vk_bytes: &[u8; latticeshield_wasm::signing::VERIFYING_KEY_LEN] =
        kp.verification_key.as_ref();

    let mut signing_randomness = [0u8; libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE];
    rng.fill_bytes(&mut signing_randomness);
    let sk_inner = ml_dsa_65::MLDSA65SigningKey::new(*sk_bytes);
    let sig = ml_dsa_65::portable::sign(&sk_inner, &server_hello, b"", signing_randomness)
        .expect("signing server_hello must succeed");
    let sig_bytes: &[u8; latticeshield_wasm::signing::SIGNATURE_LEN] = sig.as_ref();

    let mut server_hello_signed = [0u8; SERVER_HELLO_SIGNED_LEN];
    server_hello_signed[..SERVER_HELLO_LEN].copy_from_slice(&server_hello);
    server_hello_signed[SERVER_HELLO_LEN..].copy_from_slice(sig_bytes);

    // 4. Call generate_client_response
    let (cr_bytes, sk_session) = generate_client_response(&server_hello_signed, vk_bytes)
        .expect("generate_client_response must succeed");

    // 5. Assert output sizes
    assert_eq!(
        cr_bytes.len(),
        CLIENT_RESPONSE_LEN,
        "client_response must be {} bytes",
        CLIENT_RESPONSE_LEN
    );
    assert_eq!(
        sk_session.len(),
        SESSION_KEY_LEN,
        "session_key must be {} bytes",
        SESSION_KEY_LEN
    );

    // 6. Verify client_response is non-zero (real crypto ran)
    assert!(
        cr_bytes.iter().any(|&b| b != 0),
        "client_response must not be all zeros"
    );
    assert!(
        sk_session.iter().any(|&b| b != 0),
        "session_key must not be all zeros"
    );
}
