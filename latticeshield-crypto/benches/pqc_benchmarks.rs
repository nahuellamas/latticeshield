use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use latticeshield_crypto::{
    client_respond, generate_keypair, parse_server_hello, parse_server_hello_signed,
    serialize_client_response, serialize_client_response_signed, EncryptedChannel, ServerHandshake,
    SERVER_HELLO_LEN, SERVER_HELLO_SIGNED_LEN,
};
use rand_core::OsRng;
use std::io::Cursor;

/// Full unsigned PQC handshake round-trip (no ML-DSA-65 overhead).
///
/// WARNING: This benchmark measures the unauthenticated path (no server signing).
/// Without ML-DSA-65, the handshake is vulnerable to MITM. Do not deploy without
/// authentication. See bench_handshake_signed for the production-safe path.
///
/// Measures: ServerHandshake::new + server_hello_bytes + parse_server_hello +
///           client_respond + serialize_client_response + complete_from_wire.
///
/// iter_batched is required because complete_from_wire consumes ServerHandshake by value.
fn bench_handshake_unsigned(c: &mut Criterion) {
    let mut group = c.benchmark_group("unsigned_handshake");

    group.bench_function("unsigned", |b| {
        b.iter_batched(
            // Setup (untimed): build fresh server state + serialize the hello bytes
            || {
                let mut rng = OsRng;
                let server = ServerHandshake::new(&mut rng);
                let hello_bytes = server.server_hello_bytes();
                (server, hello_bytes, rng)
            },
            // Routine (timed): full client + server round-trip
            |(server, hello_bytes, mut rng)| {
                let hello = parse_server_hello(black_box(&hello_bytes));
                let (response, _client_key) = client_respond(&hello, &mut rng).unwrap();
                let cr_bytes = serialize_client_response(&response);
                let server_key = server.complete_from_wire(&cr_bytes).unwrap();
                black_box(server_key);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Full signed (mutual-auth) PQC handshake round-trip.
///
/// Keypair generation (ML-DSA-65) happens ONCE outside iter_batched — it is NOT timed.
/// Measures: server_hello_signed_bytes + parse_server_hello_signed + client_respond +
///           serialize_client_response_signed + complete_from_wire_signed.
fn bench_handshake_signed(c: &mut Criterion) {
    let mut rng = OsRng;
    // Generate long-term keypairs once — excluded from measurement.
    let (server_sk, server_vk) = generate_keypair(&mut rng);
    let (client_sk, client_vk) = generate_keypair(&mut rng);

    let mut group = c.benchmark_group("signed_handshake");

    group.bench_function("signed", |b| {
        b.iter_batched(
            // Setup (untimed): fresh ephemeral server state + signed hello
            || {
                let mut rng = OsRng;
                let server = ServerHandshake::new(&mut rng);
                let hello_signed = server
                    .server_hello_signed_bytes(&server_sk, &mut rng)
                    .unwrap();
                // Extract the raw (unsigned) hello from the signed wire format.
                // Wire layout: server_hello_raw[..SERVER_HELLO_LEN] || ML-DSA-65-sig[..SIGNATURE_LEN]
                // If the wire format ever changes, update this extraction accordingly.
                debug_assert_eq!(hello_signed.len(), SERVER_HELLO_SIGNED_LEN);
                let mut hello_raw = [0u8; SERVER_HELLO_LEN];
                hello_raw.copy_from_slice(&hello_signed[..SERVER_HELLO_LEN]);
                (server, hello_signed, hello_raw, rng)
            },
            // Routine (timed): full mutual-auth round-trip
            |(server, hello_signed, hello_raw, mut rng)| {
                let hello =
                    parse_server_hello_signed(black_box(&hello_signed), &server_vk).unwrap();
                let (response, _client_key) = client_respond(&hello, &mut rng).unwrap();
                let scr =
                    serialize_client_response_signed(&response, &client_sk, &hello_raw, &mut rng)
                        .unwrap();
                let server_key = server.complete_from_wire_signed(&scr, &client_vk).unwrap();
                black_box(server_key);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// AES-256-GCM frame throughput at three payload sizes.
///
/// A fixed [0u8; 32] session key is used — throughput is independent of key contents.
/// BENCHMARK ONLY: all-zeros key + seq=0 per iteration means the same nonce is reused
/// in every iteration. This is intentional for reproducibility; it must never appear in
/// production code (nonce+key reuse destroys AES-GCM confidentiality).
/// max_frame_size = 2 MiB to accommodate the 1 MiB payload without FrameError::Invalid.
/// Each iteration receives a fresh EncryptedChannel pair so seq counters start at 0.
fn bench_frame_throughput(c: &mut Criterion) {
    const SESSION_KEY: [u8; 32] = [0u8; 32]; // BENCHMARK ONLY — not a real key
    const MAX_FRAME: usize = 2 * 1024 * 1024;

    // Build the Tokio runtime once — NOT inside the closure.
    // current_thread is sufficient: write_frame/read_frame don't spawn tasks.
    // (rt-multi-thread is not in dev-dependencies, so Runtime::new() is unavailable.)
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("frame_throughput");

    for size in [1024usize, 64 * 1024, 1024 * 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.to_async(&runtime).iter_batched(
                // Setup (untimed): fresh channel pair + payload buffer
                || {
                    let writer_ch = EncryptedChannel::new(&SESSION_KEY, MAX_FRAME);
                    let reader_ch = EncryptedChannel::new(&SESSION_KEY, MAX_FRAME);
                    let payload = vec![0u8; size];
                    let buf: Vec<u8> = Vec::with_capacity(size + 64);
                    (writer_ch, reader_ch, payload, buf)
                },
                // Routine (timed): write_frame then read_frame over in-memory buffers
                |(mut writer_ch, mut reader_ch, payload, mut buf): (
                    EncryptedChannel,
                    EncryptedChannel,
                    Vec<u8>,
                    Vec<u8>,
                )| async move {
                    writer_ch.write_frame(&mut buf, &payload).await.unwrap();
                    let mut cursor = Cursor::new(buf);
                    let frame = reader_ch.read_frame(&mut cursor).await.unwrap();
                    black_box(frame);
                },
                BatchSize::LargeInput,
            );
        });
    }

    group.finish();
}

/// Reconnect — labeled alias of the unsigned handshake.
///
/// In latticeshield, a reconnect is a fresh PQC handshake. This group reports
/// the same numbers as unsigned_handshake under the "reconnect" label so that
/// HN readers / benchmark reports see the reconnect cost explicitly.
fn bench_reconnect(c: &mut Criterion) {
    let mut group = c.benchmark_group("reconnect");

    group.bench_function("reconnect", |b| {
        b.iter_batched(
            || {
                let mut rng = OsRng;
                let server = ServerHandshake::new(&mut rng);
                let hello_bytes = server.server_hello_bytes();
                (server, hello_bytes, rng)
            },
            |(server, hello_bytes, mut rng)| {
                let hello = parse_server_hello(black_box(&hello_bytes));
                let (response, _client_key) = client_respond(&hello, &mut rng).unwrap();
                let cr_bytes = serialize_client_response(&response);
                let server_key = server.complete_from_wire(&cr_bytes).unwrap();
                black_box(server_key);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_handshake_unsigned,
    bench_handshake_signed,
    bench_frame_throughput,
    bench_reconnect,
);
criterion_main!(benches);
