//! Per-user identity and traffic counters.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// A user's accounting record.
///
/// Exactly one of these exists per user. Every connection that authenticates as
/// that user shares the same `Arc`, so all of them accumulate into the same
/// counters, and a reader of the counters sees the sum across every inbound,
/// transport, and worker thread the user is currently using.
///
/// # Layout
///
/// The counters are placed first inside a 64 byte aligned type. `Arc` honours the
/// alignment of the value it stores, so each user's hot counters land on their own
/// cache line and two users being metered concurrently on different cores never
/// invalidate each other's line.
///
/// # Ordering
///
/// Counters use `Relaxed`. There is nothing to synchronise: the value is only ever
/// incremented by `fetch_add` and read for reporting, so the only guarantee needed
/// is that no increment is lost, which `Relaxed` already provides. Anything
/// stronger would put a memory barrier on the per-buffer I/O path for no benefit.
#[repr(align(64))]
pub struct UserContext {
    tx: AtomicU64,
    rx: AtomicU64,
    /// Connections currently open. Maintained by the traffic meter, which owns the
    /// only place that reliably observes a connection ending.
    conns: AtomicU64,
    /// Successful authentications since this record was created.
    total_conns: AtomicU64,
    /// Stable identity chosen by whoever registered the user. Never a credential.
    id: Arc<str>,
    enabled: AtomicBool,
}

impl std::fmt::Debug for UserContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserContext")
            .field("id", &self.id)
            .field("enabled", &self.is_enabled())
            .field("tx", &self.tx())
            .field("rx", &self.rx())
            .finish()
    }
}

impl UserContext {
    pub fn new(id: impl Into<Arc<str>>) -> Arc<Self> {
        Arc::new(Self {
            tx: AtomicU64::new(0),
            rx: AtomicU64::new(0),
            conns: AtomicU64::new(0),
            total_conns: AtomicU64::new(0),
            id: id.into(),
            enabled: AtomicBool::new(true),
        })
    }

    #[inline]
    pub fn id(&self) -> &Arc<str> {
        &self.id
    }

    /// Bytes sent to the client, counted as they go on the wire.
    #[inline]
    pub fn add_tx(&self, n: u64) {
        self.tx.fetch_add(n, Ordering::Relaxed);
    }

    /// Bytes received from the client, counted as they come off the wire.
    #[inline]
    pub fn add_rx(&self, n: u64) {
        self.rx.fetch_add(n, Ordering::Relaxed);
    }

    #[inline]
    pub fn tx(&self) -> u64 {
        self.tx.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn rx(&self) -> u64 {
        self.rx.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn conns(&self) -> u64 {
        self.conns.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn total_conns(&self) -> u64 {
        self.total_conns.load(Ordering::Relaxed)
    }

    /// Record a successful authentication. Called by registry implementations, so
    /// that a handler cannot forget to.
    #[inline]
    pub fn note_auth(&self) {
        self.total_conns.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn open_conn(&self) {
        self.conns.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn close_conn(&self) {
        // Saturate rather than wrap. An unbalanced close would otherwise report
        // billions of open connections, which is worse than reporting zero.
        let _ = self
            .conns
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(1))
            });
    }

    /// Whether the user may authenticate. Checked by registry lookups, so a
    /// disabled user is indistinguishable from an unknown one at the protocol
    /// level, including for probe-resistant fallbacks.
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Suspend or resume the user without discarding their counters. Established
    /// connections are deliberately left alone; this only affects new ones.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Zero the traffic counters, returning what they held. Used for billing
    /// periods; `conns` is left alone because it tracks live state, not a total.
    pub fn take_traffic(&self) -> (u64, u64) {
        (
            self.tx.swap(0, Ordering::Relaxed),
            self.rx.swap(0, Ordering::Relaxed),
        )
    }

    pub fn stats(&self) -> UserStats {
        UserStats {
            id: self.id.clone(),
            enabled: self.is_enabled(),
            tx: self.tx(),
            rx: self.rx(),
            conns: self.conns(),
            total_conns: self.total_conns(),
        }
    }
}

/// A point-in-time copy of a user's counters.
///
/// The counters are read one at a time, so a snapshot is not an atomic view of
/// the user. That is intentional: making it one would require a lock on the I/O
/// path. For reporting, slight skew between `tx` and `rx` is irrelevant.
#[derive(Debug, Clone)]
pub struct UserStats {
    pub id: Arc<str>,
    pub enabled: bool,
    pub tx: u64,
    pub rx: u64,
    pub conns: u64,
    pub total_conns: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulates_traffic_in_both_directions() {
        let user = UserContext::new("alice");
        user.add_tx(10);
        user.add_tx(5);
        user.add_rx(7);
        assert_eq!((user.tx(), user.rx()), (15, 7));
    }

    #[test]
    fn take_traffic_returns_and_zeroes_only_the_byte_counters() {
        let user = UserContext::new("alice");
        user.add_tx(120);
        user.add_rx(340);
        user.open_conn();
        user.note_auth();

        assert_eq!(user.take_traffic(), (120, 340));
        assert_eq!((user.tx(), user.rx()), (0, 0));
        // Live and lifetime connection counts are not part of a billing period.
        assert_eq!((user.conns(), user.total_conns()), (1, 1));

        // A second take with nothing in between reports zero rather than repeating.
        assert_eq!(user.take_traffic(), (0, 0));
    }

    #[test]
    fn tracks_live_connections_and_saturates_at_zero() {
        let user = UserContext::new("alice");
        user.open_conn();
        user.open_conn();
        assert_eq!(user.conns(), 2);

        user.close_conn();
        assert_eq!(user.conns(), 1);
        user.close_conn();
        assert_eq!(user.conns(), 0);

        // An unbalanced close must not wrap to u64::MAX.
        user.close_conn();
        assert_eq!(user.conns(), 0);
    }

    #[test]
    fn stats_snapshot_reports_the_current_values() {
        let user = UserContext::new("alice");
        user.add_tx(1);
        user.add_rx(2);
        user.note_auth();
        user.open_conn();
        user.set_enabled(false);

        let stats = user.stats();
        assert_eq!(&*stats.id, "alice");
        assert!(!stats.enabled);
        assert_eq!((stats.tx, stats.rx), (1, 2));
        assert_eq!((stats.conns, stats.total_conns), (1, 1));
    }

    #[test]
    fn counters_are_shared_through_the_arc() {
        let user = UserContext::new("alice");
        let clone = user.clone();
        clone.add_tx(4);
        user.add_tx(6);
        assert_eq!(user.tx(), 10);
        assert_eq!(clone.tx(), 10);
    }

    #[test]
    fn counters_sit_on_their_own_cache_line() {
        // The alignment is what keeps two users metered on different cores from
        // invalidating each other's line, so it is worth asserting rather than
        // trusting a comment.
        assert_eq!(std::mem::align_of::<UserContext>(), 64);
        let user = UserContext::new("alice");
        assert_eq!(Arc::as_ptr(&user) as usize % 64, 0);
    }
}
