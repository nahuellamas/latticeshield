/// Classification of reconnect behavior after a bridge drop.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Classification {
    /// The client library reconnects transparently; the application sees no error.
    Ok,
    /// The connection errors out but application-level state (transactions, subscriptions)
    /// is lost. A new connection succeeds.
    StateLoss,
    /// The socket is terminal; no reconnect is possible without application intervention.
    Broken,
}
