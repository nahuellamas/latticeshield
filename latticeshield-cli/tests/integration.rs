use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

// ── Phase 7.1 ───────────────────────────────────────────────────────────────

/// No args → exit 0 + banner contains "LatticeShield" and "COMMANDS:"
#[test]
fn no_args_shows_banner() {
    Command::cargo_bin("latticeshield")
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("LatticeShield"))
        .stdout(predicate::str::contains("COMMANDS:"));
}

// ── Phase 7.2 ───────────────────────────────────────────────────────────────

/// `keygen server <dir>` → exit 0, server.sk (0o600) + server.vk (0o644) created
#[test]
fn keygen_server_creates_files() {
    let dir = tempdir().unwrap();
    Command::cargo_bin("latticeshield")
        .unwrap()
        .args(["keygen", "server", dir.path().to_str().unwrap()])
        .assert()
        .success();

    let sk = dir.path().join("server.sk");
    let vk = dir.path().join("server.vk");

    assert!(sk.exists(), "server.sk must exist");
    assert!(vk.exists(), "server.vk must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let sk_mode = std::fs::metadata(&sk).unwrap().permissions().mode() & 0o777;
        let vk_mode = std::fs::metadata(&vk).unwrap().permissions().mode() & 0o777;
        assert_eq!(sk_mode, 0o600, "server.sk must have mode 0o600, got {:o}", sk_mode);
        assert_eq!(vk_mode, 0o644, "server.vk must have mode 0o644, got {:o}", vk_mode);
    }
}

// ── Phase 7.3 ───────────────────────────────────────────────────────────────

/// `keygen client <dir>` → exit 0, client.sk (0o600) + client.vk (0o644) created
#[test]
fn keygen_client_creates_files() {
    let dir = tempdir().unwrap();
    Command::cargo_bin("latticeshield")
        .unwrap()
        .args(["keygen", "client", dir.path().to_str().unwrap()])
        .assert()
        .success();

    let sk = dir.path().join("client.sk");
    let vk = dir.path().join("client.vk");

    assert!(sk.exists(), "client.sk must exist");
    assert!(vk.exists(), "client.vk must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let sk_mode = std::fs::metadata(&sk).unwrap().permissions().mode() & 0o777;
        let vk_mode = std::fs::metadata(&vk).unwrap().permissions().mode() & 0o777;
        assert_eq!(sk_mode, 0o600, "client.sk must have mode 0o600, got {:o}", sk_mode);
        assert_eq!(vk_mode, 0o644, "client.vk must have mode 0o644, got {:o}", vk_mode);
    }
}

// ── Phase 7.4 ───────────────────────────────────────────────────────────────

/// `keygen tls <dir>` → exit 0, tls.crt + tls.key created, cert starts with PEM header
#[test]
fn keygen_tls_creates_files() {
    let dir = tempdir().unwrap();
    Command::cargo_bin("latticeshield")
        .unwrap()
        .args(["keygen", "tls", dir.path().to_str().unwrap()])
        .assert()
        .success();

    let crt = dir.path().join("tls.crt");
    let key = dir.path().join("tls.key");

    assert!(crt.exists(), "tls.crt must exist");
    assert!(key.exists(), "tls.key must exist");

    let crt_content = std::fs::read_to_string(&crt).unwrap();
    assert!(
        crt_content.starts_with("-----BEGIN CERTIFICATE-----"),
        "tls.crt must be a PEM certificate, got: {:?}",
        &crt_content[..crt_content.len().min(50)]
    );
}

// ── Phase 7.5 ───────────────────────────────────────────────────────────────

/// `vk-info <server.vk>` → exit 0, stdout contains "SHA-256:" and "1952",
/// and the hex fingerprint is exactly 64 chars
#[test]
fn vk_info_server_vk() {
    let dir = tempdir().unwrap();
    // Set up: generate server.vk directly via the lib (no CLI spawn for setup)
    latticeshield_bridge::identity::ServerIdentity::generate_and_save(dir.path())
        .expect("generate_and_save must succeed");

    let vk_path = dir.path().join("server.vk");

    let output = Command::cargo_bin("latticeshield")
        .unwrap()
        .args(["vk-info", vk_path.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).unwrap();

    assert!(stdout.contains("SHA-256:"), "stdout must contain 'SHA-256:':\n{stdout}");
    assert!(stdout.contains("1952"), "stdout must contain '1952' (key size):\n{stdout}");

    // Verify a 64-char hex value follows SHA-256:
    let sha_line = stdout
        .lines()
        .find(|l| l.contains("SHA-256:"))
        .expect("SHA-256 line must be present");
    let hex_part = sha_line
        .split("SHA-256:")
        .nth(1)
        .expect("SHA-256: must have a value after it")
        .trim();
    assert_eq!(
        hex_part.len(),
        64,
        "SHA-256 fingerprint must be 64 hex chars, got {} chars: '{hex_part}'",
        hex_part.len()
    );
    assert!(
        hex_part.chars().all(|c| c.is_ascii_hexdigit()),
        "SHA-256 fingerprint must be all hex digits, got: '{hex_part}'"
    );
}

// ── Phase 7.6 ───────────────────────────────────────────────────────────────

/// `vk-info /nonexistent/path.vk` → non-zero exit, stdout is empty (error goes to stderr)
#[test]
fn vk_info_missing_file() {
    Command::cargo_bin("latticeshield")
        .unwrap()
        .args(["vk-info", "/tmp/absolutely-does-not-exist-latticeshield-12345.vk"])
        .assert()
        .failure()
        .stdout(predicate::str::is_empty());
}

// ── Phase 7.7 ───────────────────────────────────────────────────────────────

/// `keygen server <dir>` must NOT print the ASCII art banner to stdout
#[test]
fn banner_not_shown_on_subcommand() {
    let dir = tempdir().unwrap();
    Command::cargo_bin("latticeshield")
        .unwrap()
        .args(["keygen", "server", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\u{2554}\u{2550}\u{2550}\u{2566}\u{2550}\u{2550}\u{2566}\u{2550}\u{2550}\u{2557}").not());
}
