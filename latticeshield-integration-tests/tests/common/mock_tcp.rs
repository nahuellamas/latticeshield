use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};

/// Spawns a raw TCP echo backend on an OS-assigned port.
///
/// Each accepted connection is served bidirectionally with `tokio::io::copy_bidirectional`,
/// which echoes all incoming bytes back to the sender.
pub async fn spawn_echo_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                // Echo: read bytes and write them back until EOF
                echo_stream(stream).await;
            });
        }
    });

    addr
}

/// Spawns a TCP backend that reads exactly `n` bytes per connection, then
/// awaits the barrier before closing — useful for synchronizing a drop point.
#[allow(dead_code)]
pub async fn spawn_count_then_block(n: usize, barrier: Arc<tokio::sync::Barrier>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                break;
            };
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                let mut buf = vec![0u8; n];
                let _ = read_exactly_n(stream, &mut buf).await;
                barrier.wait().await;
            });
        }
    });

    addr
}

/// Echo all incoming bytes back to the sender until EOF.
async fn echo_stream(mut stream: TcpStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 4096];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if stream.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn read_exactly_n(mut stream: TcpStream, buf: &mut [u8]) -> std::io::Result<usize> {
    use tokio::io::AsyncReadExt;
    stream.read_exact(buf).await
}
