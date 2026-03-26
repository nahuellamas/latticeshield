use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::sync::{watch, Mutex};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::config::PoolConfig;

pub struct IdleConn {
    stream: TcpStream,
    created_at: Instant,
}

#[cfg(test)]
impl IdleConn {
    pub fn with_age(stream: TcpStream, created_at: Instant) -> Self {
        IdleConn { stream, created_at }
    }
}

pub struct PoolInner {
    pub idle: VecDeque<IdleConn>,
}

pub struct ConnectionPool {
    inner: Arc<Mutex<PoolInner>>,
    bridge_addr: SocketAddr,
    config: PoolConfig,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl ConnectionPool {
    pub fn new(bridge_addr: SocketAddr, config: PoolConfig) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            inner: Arc::new(Mutex::new(PoolInner {
                idle: VecDeque::new(),
            })),
            bridge_addr,
            config,
            shutdown_tx,
            shutdown_rx,
        }
    }

    pub async fn acquire(&self) -> anyhow::Result<TcpStream> {
        let timeout = std::time::Duration::from_secs(self.config.idle_timeout_secs);

        {
            let mut inner = self.inner.lock().await;
            while inner
                .idle
                .front()
                .map_or(false, |c| c.created_at.elapsed() >= timeout)
            {
                let evicted = inner.idle.pop_front().unwrap();
                debug!(bridge = %self.bridge_addr, "evicted stale idle connection");
                drop(evicted);
            }

            if let Some(idle) = inner.idle.pop_front() {
                return Ok(idle.stream);
            }
        }

        let stream = TcpStream::connect(self.bridge_addr)
            .await
            .map_err(|e| anyhow::anyhow!("bridge connect failed: {e}"))?;

        if let Err(e) = stream.set_nodelay(true) {
            warn!(bridge = %self.bridge_addr, "set_nodelay failed on fresh connect: {e}");
        }

        Ok(stream)
    }

    pub async fn warm_loop(&self) {
        let mut shutdown_rx = self.shutdown_rx.clone();
        let interval = std::time::Duration::from_secs(self.config.warm_interval_secs);

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {},
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        debug!("warm_loop: shutdown signal received, exiting");
                        return;
                    }
                }
            }

            if self.config.warm_size == 0 {
                continue;
            }

            let current_count = {
                let inner = self.inner.lock().await;
                inner.idle.len()
            };

            let to_add = self
                .config
                .warm_size
                .saturating_sub(current_count)
                .min(self.config.max_size.saturating_sub(current_count));

            if to_add == 0 {
                continue;
            }

            let mut join_set = tokio::task::JoinSet::new();
            for _ in 0..to_add {
                let addr = self.bridge_addr;
                join_set.spawn(async move { TcpStream::connect(addr).await });
            }

            let mut new_conns: Vec<IdleConn> = Vec::with_capacity(to_add);
            while let Some(result) = join_set.join_next().await {
                match result {
                    Ok(Ok(stream)) => {
                        if let Err(e) = stream.set_nodelay(true) {
                            warn!(bridge = %self.bridge_addr, "set_nodelay failed in warmer: {e}");
                        }
                        new_conns.push(IdleConn {
                            stream,
                            created_at: Instant::now(),
                        });
                        debug!(bridge = %self.bridge_addr, "pre-warmed connection added to pool");
                    }
                    Ok(Err(e)) => {
                        warn!(bridge = %self.bridge_addr, "warmer connect failed: {e}");
                    }
                    Err(join_err) => {
                        warn!("warmer task panicked: {join_err}");
                    }
                }
            }

            if !new_conns.is_empty() {
                let mut inner = self.inner.lock().await;
                for conn in new_conns {
                    if inner.idle.len() >= self.config.max_size {
                        drop(conn);
                        break;
                    }
                    inner.idle.push_back(conn);
                }
            }
        }
    }

    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);

        let mut inner = self.inner.lock().await;
        info!(
            count = inner.idle.len(),
            "ConnectionPool: draining idle connections on shutdown"
        );

        while let Some(mut conn) = inner.idle.pop_front() {
            use tokio::io::AsyncWriteExt;
            if let Err(e) = conn.stream.shutdown().await {
                warn!("shutdown of idle connection failed: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio::time::Duration;

    fn pool_with_config(bridge_addr: std::net::SocketAddr, config: PoolConfig) -> ConnectionPool {
        ConnectionPool::new(bridge_addr, config)
    }

    fn default_config() -> PoolConfig {
        PoolConfig {
            max_size: 4,
            idle_timeout_secs: 30,
            warm_size: 2,
            warm_interval_secs: 5,
        }
    }

    async fn start_listener() -> (TcpListener, std::net::SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, addr)
    }

    #[tokio::test]
    async fn acquire_from_empty_pool_connects_fresh() {
        let (listener, addr) = start_listener().await;
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let pool = pool_with_config(addr, default_config());
        let stream = pool.acquire().await.unwrap();
        assert!(stream.peer_addr().is_ok());
    }

    #[tokio::test]
    async fn acquire_from_warmed_pool_returns_idle() {
        let (listener, addr) = start_listener().await;

        // Pre-warm: connect a stream and push it into the pool manually.
        let accept_task = tokio::spawn(async move { listener.accept().await.unwrap() });
        let stream = TcpStream::connect(addr).await.unwrap();
        accept_task.await.unwrap();

        let pool = pool_with_config(addr, default_config());
        {
            let mut inner = pool.inner.lock().await;
            inner.idle.push_back(IdleConn {
                stream,
                created_at: Instant::now(),
            });
        }

        // Acquire should return the pooled stream, leaving pool empty.
        let acquired = pool.acquire().await.unwrap();
        assert!(acquired.peer_addr().is_ok());

        let inner = pool.inner.lock().await;
        assert_eq!(inner.idle.len(), 0);
    }

    #[tokio::test]
    async fn acquire_respects_max_size_in_warm_loop() {
        let (listener, addr) = start_listener().await;

        // Accept up to 10 connections so the warmer can connect.
        tokio::spawn(async move {
            for _ in 0..10 {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let config = PoolConfig {
            max_size: 2,
            idle_timeout_secs: 30,
            warm_size: 2,
            warm_interval_secs: 1,
        };
        let pool = Arc::new(pool_with_config(addr, config));
        let pool_for_warmer = Arc::clone(&pool);

        let warmer = tokio::spawn(async move { pool_for_warmer.warm_loop().await });

        // Let the warmer run one interval.
        tokio::time::sleep(Duration::from_millis(1200)).await;

        let inner = pool.inner.lock().await;
        assert!(
            inner.idle.len() <= 2,
            "pool exceeded max_size: {}",
            inner.idle.len()
        );
        drop(inner);

        let _ = pool.shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_millis(200), warmer).await;
    }

    #[tokio::test]
    async fn idle_connections_older_than_timeout_are_evicted() {
        let (listener, addr) = start_listener().await;

        // Accept two connections: one for the stale conn, one for the fresh connect fallback.
        tokio::spawn(async move {
            for _ in 0..2 {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let stale_stream = TcpStream::connect(addr).await.unwrap();
        // Backdate the created_at beyond the idle_timeout (30s) using real elapsed time.
        let stale_instant = Instant::now() - Duration::from_secs(60);
        let stale_conn = IdleConn::with_age(stale_stream, stale_instant);

        let pool = pool_with_config(addr, default_config());
        {
            let mut inner = pool.inner.lock().await;
            inner.idle.push_back(stale_conn);
        }

        // acquire() must evict the stale conn and fall back to a fresh connect.
        let result = pool.acquire().await;
        assert!(
            result.is_ok(),
            "acquire should succeed via fallback: {result:?}"
        );

        let inner = pool.inner.lock().await;
        assert_eq!(inner.idle.len(), 0, "pool should be empty after eviction");
    }

    #[tokio::test]
    async fn partial_eviction_leaves_fresh_connections() {
        let (listener, addr) = start_listener().await;
        tokio::spawn(async move {
            for _ in 0..2 {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let stale_stream = TcpStream::connect(addr).await.unwrap();
        let fresh_stream = TcpStream::connect(addr).await.unwrap();

        // Backdate the stale conn using real time subtraction.
        let stale_instant = Instant::now() - Duration::from_secs(60);
        let stale_conn = IdleConn::with_age(stale_stream, stale_instant);
        let fresh_conn = IdleConn {
            stream: fresh_stream,
            created_at: Instant::now(),
        };

        let pool = pool_with_config(addr, default_config());
        {
            let mut inner = pool.inner.lock().await;
            // Stale at front, fresh at back — eviction only removes from front.
            inner.idle.push_back(stale_conn);
            inner.idle.push_back(fresh_conn);
        }

        // acquire() evicts the stale front, returns the fresh one.
        let acquired = pool.acquire().await.unwrap();
        assert!(acquired.peer_addr().is_ok());

        let inner = pool.inner.lock().await;
        assert_eq!(inner.idle.len(), 0, "fresh conn should have been returned");
    }

    #[tokio::test]
    async fn warm_size_zero_disables_warming() {
        let (listener, addr) = start_listener().await;
        tokio::spawn(async move {
            // Should never be called — but accept if it is to avoid panics.
            let _ = listener.accept().await;
        });

        let config = PoolConfig {
            max_size: 4,
            idle_timeout_secs: 30,
            warm_size: 0,
            warm_interval_secs: 1,
        };
        let pool = Arc::new(pool_with_config(addr, config));
        let pool_for_warmer = Arc::clone(&pool);

        let warmer = tokio::spawn(async move { pool_for_warmer.warm_loop().await });

        tokio::time::sleep(Duration::from_millis(1200)).await;

        let inner = pool.inner.lock().await;
        assert_eq!(inner.idle.len(), 0, "warm_size=0 must not add connections");
        drop(inner);

        let _ = pool.shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_millis(200), warmer).await;
    }

    #[tokio::test]
    async fn shutdown_closes_all_idle_connections() {
        use tokio::io::AsyncReadExt;

        let (listener, addr) = start_listener().await;
        let pool = pool_with_config(addr, default_config());
        let mut server_sides: Vec<TcpStream> = Vec::new();

        for _ in 0..2 {
            let stream = TcpStream::connect(addr).await.unwrap();
            let (server_side, _) = listener.accept().await.unwrap();
            server_sides.push(server_side);
            let mut inner = pool.inner.lock().await;
            inner.idle.push_back(IdleConn {
                stream,
                created_at: Instant::now(),
            });
        }

        pool.shutdown().await;

        let inner = pool.inner.lock().await;
        assert_eq!(inner.idle.len(), 0, "pool must be empty after shutdown");
        drop(inner);

        for mut server_side in server_sides {
            let mut buf = [0u8; 1];
            let n = server_side.read(&mut buf).await.unwrap_or(0);
            assert_eq!(n, 0, "server side must receive EOF (FIN) after shutdown");
        }
    }

    #[tokio::test]
    async fn acquire_fallback_on_all_stale() {
        let (listener, addr) = start_listener().await;
        tokio::spawn(async move {
            for _ in 0..3 {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let pool = pool_with_config(addr, default_config());
        for _ in 0..2 {
            let stream = TcpStream::connect(addr).await.unwrap();
            let stale_instant = Instant::now() - Duration::from_secs(60);
            let conn = IdleConn::with_age(stream, stale_instant);
            let mut inner = pool.inner.lock().await;
            inner.idle.push_back(conn);
        }

        // Both stale → evict both → fresh connect fallback.
        let result = pool.acquire().await;
        assert!(
            result.is_ok(),
            "acquire should succeed via fallback after evicting all stale"
        );

        let inner = pool.inner.lock().await;
        assert_eq!(inner.idle.len(), 0);
    }

    #[tokio::test]
    async fn set_nodelay_applied_on_fresh_connect() {
        let (listener, addr) = start_listener().await;
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let pool = pool_with_config(addr, default_config());
        // Empty pool → fresh connect path.
        let stream = pool.acquire().await.unwrap();
        // nodelay() returns the current TCP_NODELAY setting.
        assert!(
            stream.nodelay().unwrap_or(false),
            "TCP_NODELAY must be set on fresh connect"
        );
    }

    #[tokio::test]
    async fn nodelay_applied_on_warmer_sourced_connections() {
        let (listener, addr) = start_listener().await;
        tokio::spawn(async move {
            for _ in 0..4 {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let config = PoolConfig {
            max_size: 2,
            idle_timeout_secs: 30,
            warm_size: 1,
            warm_interval_secs: 1,
        };
        let pool = Arc::new(pool_with_config(addr, config));
        let pool_for_warmer = Arc::clone(&pool);

        let warmer = tokio::spawn(async move { pool_for_warmer.warm_loop().await });

        let _ = tokio::time::timeout(Duration::from_millis(1200), async {
            loop {
                let count = pool.inner.lock().await.idle.len();
                if count >= 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;

        let stream = pool.acquire().await.unwrap();
        assert!(
            stream.nodelay().unwrap_or(false),
            "TCP_NODELAY must be set on warmer-sourced connection"
        );

        let _ = pool.shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_millis(200), warmer).await;
    }

    #[tokio::test]
    async fn warm_loop_shuts_down_on_signal() {
        // Use a closed address — warmer will fail to connect but must still exit on shutdown signal.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let config = PoolConfig {
            max_size: 4,
            idle_timeout_secs: 30,
            warm_size: 1,
            warm_interval_secs: 60, // long interval so we don't wait for it
        };
        let pool = Arc::new(pool_with_config(addr, config));
        let pool_for_warmer = Arc::clone(&pool);

        let warmer = tokio::spawn(async move { pool_for_warmer.warm_loop().await });

        // Give warmer a moment to start its select!, then signal shutdown.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = pool.shutdown_tx.send(true);

        let result = tokio::time::timeout(Duration::from_millis(500), warmer).await;
        assert!(
            result.is_ok(),
            "warm_loop must exit within timeout after shutdown signal"
        );
        assert!(result.unwrap().is_ok(), "warm_loop task must not panic");
    }

    #[tokio::test]
    async fn pool_empty_after_shutdown() {
        let (listener, addr) = start_listener().await;
        tokio::spawn(async move {
            for _ in 0..3 {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let pool = pool_with_config(addr, default_config());
        // Push one connection.
        let stream = TcpStream::connect(addr).await.unwrap();
        {
            let mut inner = pool.inner.lock().await;
            inner.idle.push_back(IdleConn {
                stream,
                created_at: Instant::now(),
            });
        }

        pool.shutdown().await;

        // After shutdown, pool is empty — acquire must fall back to fresh connect.
        let result = pool.acquire().await;
        assert!(
            result.is_ok(),
            "acquire after shutdown must succeed via fresh connect"
        );
    }
}
