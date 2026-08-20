//! Per-connection traffic accounting.
//!
//! # Where the bytes are counted
//!
//! [`TrafficMeterStream`] wraps a connection at the very bottom of the stack, as
//! soon as it is accepted and before any protocol has looked at it. Everything the
//! client sends or receives therefore passes through it exactly once: TLS records,
//! WebSocket frames, protocol headers, padding, and the payload. That is the
//! "wire bytes" figure an operator bills on, not the smaller payload-only figure.
//!
//! Sitting at the bottom also means datagram protocols need no separate treatment.
//! VLESS UDP, Trojan UDP, and XUDP all tunnel their datagrams over the same
//! accepted connection, so their message streams are built *on top of* the meter
//! and their bytes are already counted, fragmentation headers included.
//!
//! Only the client side is metered. The stream this proxy opens to the target is
//! deliberately left alone: it is not the user's traffic, and counting both would
//! double every byte.
//!
//! # Why the user is bound late
//!
//! The meter has to be installed before the user is known -- the credential only
//! arrives partway into the handshake, and for TLS-wrapped protocols it arrives
//! after a handshake the meter is already counting. So a connection starts out
//! anonymous: bytes accumulate in the [`ConnContext`] itself, and the moment a
//! protocol handler authenticates, [`bind_connection_user`] hands over what has
//! accumulated so far and every subsequent byte goes straight to the user's
//! counters.
//!
//! The handler finds the context through a task local rather than through a
//! parameter. Threading an `Arc<ConnContext>` from the accept loop down to the
//! byte offset where a uuid appears would mean touching every handler signature in
//! between, including the ones that have nothing to do with users. The task local
//! costs one thread-local read per connection, once, and leaves those signatures
//! untouched.
//!
//! Task locals do not cross [`tokio::spawn`]. That is fine for every handler that
//! authenticates today, because authentication always happens inline on the task
//! that accepted the connection -- handlers only spawn *after* the credential has
//! been checked, and by then the meter is holding its own `Arc<ConnContext>` and no
//! longer needs the task local. A future protocol that authenticates inside a
//! spawned task has to pass the context explicitly; [`current_connection`] exists
//! for that.
//!
//! # Hot path cost
//!
//! One relaxed `fetch_add` per completed read and per completed write, on a cache
//! line that belongs to one user (see [`UserContext`]'s layout), plus one relaxed
//! atomic load to find that user. No locks, no allocation, and nothing that a
//! config reload or a user being added can contend with.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};

use super::user::UserContext;

tokio::task_local! {
    /// The connection being metered on this task, if it is metered at all.
    static METERED_CONNECTION: Arc<ConnContext>;
}

/// One metered connection's link to the user it turns out to belong to.
///
/// Shared between the [`TrafficMeterStream`] and the task local, so the count of
/// live connections falls only once both are gone -- which matters for handlers
/// that hand the stream to a spawned task and return.
pub struct ConnContext {
    /// Bytes seen before the user was known. Emptied into the user by [`bind`],
    /// and discarded if authentication never succeeds.
    ///
    /// [`bind`]: ConnContext::bind
    pending_tx: AtomicU64,
    pending_rx: AtomicU64,
    user: OnceLock<Arc<UserContext>>,
}

impl std::fmt::Debug for ConnContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnContext")
            .field("user", &self.user.get().map(|u| u.id().clone()))
            .field("pending", &self.pending())
            .finish()
    }
}

impl ConnContext {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            pending_tx: AtomicU64::new(0),
            pending_rx: AtomicU64::new(0),
            user: OnceLock::new(),
        })
    }

    /// The authenticated user, once a handler has bound one.
    #[inline]
    pub fn user(&self) -> Option<&Arc<UserContext>> {
        self.user.get()
    }

    /// Bytes counted so far that have not been attributed to anyone. Zero once the
    /// user is bound.
    pub fn pending(&self) -> (u64, u64) {
        (
            self.pending_tx.load(Ordering::Relaxed),
            self.pending_rx.load(Ordering::Relaxed),
        )
    }

    /// Attribute this connection, and everything it has already transferred, to
    /// `user`. Returns false if it was already bound.
    ///
    /// The handover is a `swap` to zero rather than a read, so a byte counted
    /// during the bind lands in the user's counters through exactly one of the two
    /// paths and never through both. It is still ordered rather than atomic: this
    /// is called from the handshake, on the same task that is doing the reads, so
    /// there is no concurrent metering to race with.
    pub fn bind(&self, user: Arc<UserContext>) -> bool {
        if self.user.set(user).is_err() {
            return false;
        }
        let user = self.user.get().expect("just set");
        user.open_conn();
        user.add_tx(self.pending_tx.swap(0, Ordering::Relaxed));
        user.add_rx(self.pending_rx.swap(0, Ordering::Relaxed));
        true
    }

    #[inline]
    fn add_tx(&self, n: u64) {
        if n == 0 {
            return;
        }
        match self.user.get() {
            Some(user) => user.add_tx(n),
            None => {
                self.pending_tx.fetch_add(n, Ordering::Relaxed);
            }
        }
    }

    #[inline]
    fn add_rx(&self, n: u64) {
        if n == 0 {
            return;
        }
        match self.user.get() {
            Some(user) => user.add_rx(n),
            None => {
                self.pending_rx.fetch_add(n, Ordering::Relaxed);
            }
        }
    }
}

impl Drop for ConnContext {
    fn drop(&mut self) {
        // Mirrors the `open_conn` in `bind`, which is the only place it happens, so
        // a connection that never authenticated is not counted down.
        if let Some(user) = self.user.get() {
            user.close_conn();
        }
    }
}

/// Run `future` with `conn` available to [`bind_connection_user`].
pub fn scope_connection<F: std::future::Future>(
    conn: Arc<ConnContext>,
    future: F,
) -> impl std::future::Future<Output = F::Output> {
    METERED_CONNECTION.scope(conn, future)
}

/// Attribute the connection being metered on this task to `user`.
///
/// Called from a protocol handler the instant it authenticates. Returns false when
/// the inbound is not metered, which is the normal case for a config-file inbound,
/// so handlers can ignore the result.
pub fn bind_connection_user(user: &Arc<UserContext>) -> bool {
    METERED_CONNECTION
        .try_with(|conn| conn.bind(Arc::clone(user)))
        .unwrap_or(false)
}

/// The connection being metered on this task, for code that has to carry the
/// context across a [`tokio::spawn`] boundary itself.
pub fn current_connection() -> Option<Arc<ConnContext>> {
    METERED_CONNECTION.try_with(Arc::clone).ok()
}

/// A stream that counts every byte that actually crosses it.
///
/// Reads and writes are forwarded unchanged; the only additions are a relaxed
/// `fetch_add` on each one that completes. Nothing is counted for a `Poll::Pending`
/// or an error, so the totals reflect bytes that reached the socket rather than
/// bytes that were offered to it.
pub struct TrafficMeterStream<T> {
    inner: T,
    conn: Arc<ConnContext>,
}

impl<T> TrafficMeterStream<T> {
    pub fn new(inner: T, conn: Arc<ConnContext>) -> Self {
        Self { inner, conn }
    }

    pub fn conn(&self) -> &Arc<ConnContext> {
        &self.conn
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for TrafficMeterStream<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrafficMeterStream")
            .field("inner", &self.inner)
            .field("conn", &self.conn)
            .finish()
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for TrafficMeterStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // `poll_read` reports success by having grown the filled region, so the
        // delta is the only way to learn how much arrived.
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if result.is_ready() {
            this.conn.add_rx((buf.filled().len() - before) as u64);
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for TrafficMeterStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            this.conn.add_tx(n as u64);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    // Forwarded rather than left to the default implementation, which would fall
    // back to writing a single buffer per poll and cost throughput on the TLS
    // record path.
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = result {
            this.conn.add_tx(n as u64);
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl<T: AsyncPing + Unpin> AsyncPing for TrafficMeterStream<T> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        // Deliberately not counted. A ping is written by the stream underneath this
        // one, which meters it on the way out.
        Pin::new(&mut self.get_mut().inner).poll_write_ping(cx)
    }
}

impl<T: AsyncStream> AsyncStream for TrafficMeterStream<T> {}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;

    fn metered(conn: &Arc<ConnContext>) -> (DuplexStream, TrafficMeterStream<DuplexStream>) {
        let (peer, local) = tokio::io::duplex(4096);
        (peer, TrafficMeterStream::new(local, Arc::clone(conn)))
    }

    #[tokio::test]
    async fn counts_bytes_in_both_directions_against_the_bound_user() {
        let user = UserContext::new("alice");
        let conn = ConnContext::new();
        assert!(conn.bind(Arc::clone(&user)));

        let (mut peer, mut stream) = metered(&conn);
        peer.write_all(b"0123456789").await.unwrap();
        let mut buf = [0u8; 10];
        stream.read_exact(&mut buf).await.unwrap();
        stream.write_all(b"abc").await.unwrap();

        assert_eq!((user.rx(), user.tx()), (10, 3));
        assert_eq!(conn.pending(), (0, 0));
    }

    #[tokio::test]
    async fn hands_the_handshake_bytes_over_when_the_user_is_bound() {
        let conn = ConnContext::new();
        let (mut peer, mut stream) = metered(&conn);

        // Stand in for the handshake: counted before anyone knows who this is.
        peer.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        stream.write_all(b"ok").await.unwrap();
        assert_eq!(conn.pending(), (2, 5));

        let user = UserContext::new("alice");
        assert!(conn.bind(Arc::clone(&user)));
        assert_eq!((user.rx(), user.tx()), (5, 2));
        assert_eq!(conn.pending(), (0, 0), "the handover must not leave a copy");

        // And from here on the bytes go straight to the user.
        stream.write_all(b"more").await.unwrap();
        assert_eq!(user.tx(), 6);
    }

    #[tokio::test]
    async fn traffic_from_a_client_that_never_authenticates_belongs_to_nobody() {
        let conn = ConnContext::new();
        let (mut peer, mut stream) = metered(&conn);
        peer.write_all(b"garbage").await.unwrap();
        let mut buf = [0u8; 7];
        stream.read_exact(&mut buf).await.unwrap();

        assert_eq!(conn.pending(), (0, 7));
        assert!(conn.user().is_none());
        // Dropping an unbound context must not touch any user's live count.
        drop(stream);
        drop(conn);
    }

    #[tokio::test]
    async fn the_connection_stays_live_until_the_last_holder_drops_it() {
        let user = UserContext::new("alice");
        let conn = ConnContext::new();
        conn.bind(Arc::clone(&user));
        assert_eq!(user.conns(), 1);

        // The stream holds its own clone, standing in for a handler that moved it
        // into a spawned task.
        let (_peer, stream) = metered(&conn);
        drop(conn);
        assert_eq!(user.conns(), 1, "the stream is still open");

        drop(stream);
        assert_eq!(user.conns(), 0);
        assert_eq!(user.total_conns(), 0, "counting an auth is the registry's job");
    }

    #[tokio::test]
    async fn a_second_bind_is_refused_rather_than_double_counted() {
        let alice = UserContext::new("alice");
        let bob = UserContext::new("bob");
        let conn = ConnContext::new();

        assert!(conn.bind(Arc::clone(&alice)));
        assert!(!conn.bind(Arc::clone(&bob)));

        assert_eq!(alice.conns(), 1);
        assert_eq!(bob.conns(), 0);
        assert_eq!(&**conn.user().unwrap().id(), "alice");
    }

    #[tokio::test]
    async fn binding_reaches_a_context_installed_further_up_the_call_stack() {
        // Stands in for a protocol handler several layers below the accept loop.
        async fn deep_inside_a_handshake(user: &Arc<UserContext>) -> bool {
            bind_connection_user(user)
        }

        let user = UserContext::new("alice");
        let conn = ConnContext::new();
        let bound = scope_connection(Arc::clone(&conn), async {
            assert!(current_connection().is_some());
            deep_inside_a_handshake(&user).await
        })
        .await;

        assert!(bound);
        assert_eq!(&**conn.user().unwrap().id(), "alice");
        assert_eq!(user.conns(), 1);
    }

    #[tokio::test]
    async fn binding_outside_a_metered_inbound_is_a_no_op() {
        let user = UserContext::new("alice");
        assert!(current_connection().is_none());
        assert!(!bind_connection_user(&user));
        assert_eq!(user.conns(), 0);
    }
}
