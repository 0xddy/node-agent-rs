//! Bounded fan-out buffer behind ACP's remotely controlled log stream.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::time::SystemTime;

use rand::Rng as _;
use tokio::sync::Notify;

pub const REMOTE_QUEUE_MAX_LINES: usize = 1024;
pub const REMOTE_QUEUE_MAX_BYTES: usize = 1 << 20;
pub const REMOTE_LINE_MAX_BYTES: usize = 32 << 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteLine {
    pub sequence: u64,
    pub captured_at: SystemTime,
    pub text: String,
}

struct BrokerState {
    subscribers: HashMap<u64, Weak<SubscriptionInner>>,
}

/// A broker intentionally has no history of its own: only lines published after
/// a subscription starts are queued, matching the Go agent.
pub struct RemoteBroker {
    source_id: String,
    sequence: AtomicU64,
    next_subscription: AtomicU64,
    state: Mutex<BrokerState>,
    clock: Arc<dyn Fn() -> SystemTime + Send + Sync>,
}

struct SubscriptionState {
    queue: VecDeque<RemoteLine>,
    bytes: usize,
    dropped: u64,
    closed: bool,
}

struct SubscriptionInner {
    id: u64,
    broker: Weak<RemoteBroker>,
    state: Mutex<SubscriptionState>,
    notify: Notify,
}

pub struct RemoteSubscription {
    inner: Arc<SubscriptionInner>,
}

impl RemoteBroker {
    pub fn new(source_id: impl Into<String>) -> Arc<Self> {
        Self::with_clock(source_id, SystemTime::now)
    }

    pub fn with_clock(
        source_id: impl Into<String>,
        clock: impl Fn() -> SystemTime + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            source_id: source_id.into(),
            sequence: AtomicU64::new(0),
            next_subscription: AtomicU64::new(1),
            state: Mutex::new(BrokerState {
                subscribers: HashMap::new(),
            }),
            clock: Arc::new(clock),
        })
    }

    fn state(&self) -> MutexGuard<'_, BrokerState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub fn subscribe(self: &Arc<Self>) -> RemoteSubscription {
        let id = self.next_subscription.fetch_add(1, Ordering::Relaxed);
        let inner = Arc::new(SubscriptionInner {
            id,
            broker: Arc::downgrade(self),
            state: Mutex::new(SubscriptionState {
                queue: VecDeque::new(),
                bytes: 0,
                dropped: 0,
                closed: false,
            }),
            notify: Notify::new(),
        });
        self.state().subscribers.insert(id, Arc::downgrade(&inner));
        RemoteSubscription { inner }
    }

    pub fn publish(&self, text: impl Into<String>) {
        self.publish_lazy(|| text.into());
    }

    fn publish_lazy(&self, text: impl FnOnce() -> String) {
        let captured_at = (self.clock)();
        // Conversion is caller-controlled (Into<String> can itself log or
        // subscribe), so neither conversion nor its destructor may run under a
        // broker lock. A short first pass preserves allocation-free idle logs.
        let has_subscribers = {
            let mut state = self.state();
            state.subscribers.retain(|_, weak| {
                weak.upgrade()
                    .is_some_and(|subscription| !subscription.state().closed)
            });
            if state.subscribers.is_empty() {
                self.sequence.fetch_add(1, Ordering::Relaxed);
                false
            } else {
                true
            }
        };
        if !has_subscribers {
            return;
        }
        let mut text = Some(truncate_utf8(text(), REMOTE_LINE_MAX_BYTES));
        let mut pending: Option<(Arc<SubscriptionInner>, RemoteLine)> = None;

        // Go holds the broker lock while delivering to each subscriber. Preserve
        // that ordering: every live subscriber observes the same total sequence.
        let mut state = self.state();
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        state.subscribers.retain(|_, weak| {
            let Some(subscription) = weak.upgrade() else {
                return false;
            };
            if subscription.state().closed {
                return false;
            }

            // Delay one delivery so the last subscriber can own the original
            // text. A single subscriber therefore needs no copy at all.
            if let Some((previous, line)) = pending.as_mut() {
                previous.enqueue(line.clone());
                *previous = subscription;
            } else {
                let text = text
                    .take()
                    .expect("text is moved only to the first subscriber");
                pending = Some((
                    subscription,
                    RemoteLine {
                        sequence,
                        captured_at,
                        text,
                    },
                ));
            }
            true
        });
        if let Some((subscription, line)) = pending {
            subscription.enqueue(line);
        }
    }

    fn remove(&self, id: u64) {
        self.state().subscribers.remove(&id);
    }
}

impl SubscriptionInner {
    fn state(&self) -> MutexGuard<'_, SubscriptionState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn enqueue(&self, line: RemoteLine) {
        let mut state = self.state();
        if state.closed {
            return;
        }
        state.bytes += line.text.len();
        state.queue.push_back(line);
        while state.queue.len() > REMOTE_QUEUE_MAX_LINES || state.bytes > REMOTE_QUEUE_MAX_BYTES {
            let Some(removed) = state.queue.pop_front() else {
                break;
            };
            state.bytes -= removed.text.len();
            state.dropped = state.dropped.saturating_add(1);
        }
        drop(state);
        self.notify.notify_one();
    }

    fn close(&self) {
        if let Some(broker) = self.broker.upgrade() {
            broker.remove(self.id);
        }
        let mut state = self.state();
        if !state.closed {
            state.closed = true;
            state.queue.clear();
            state.bytes = 0;
            drop(state);
            // Retain a permit even when nobody is currently awaiting, matching
            // Go's capacity-one notification channel on Close.
            self.notify.notify_one();
        }
    }
}

impl RemoteSubscription {
    /// Waits until data is queued or the subscription closes. Notifications are
    /// coalesced like Go's capacity-one channel.
    pub async fn notified(&self) {
        self.inner.notify.notified().await;
    }

    /// Returns at most `max_lines` and normally at most `max_bytes` of UTF-8.
    /// A first oversized line is still returned so a queue can never deadlock.
    pub fn drain(&self, max_lines: usize, max_bytes: usize) -> (Vec<RemoteLine>, u64) {
        let mut state = self.inner.state();
        if state.queue.is_empty() || max_lines == 0 || max_bytes == 0 {
            return (Vec::new(), 0);
        }

        let available = state.queue.len().min(max_lines);
        let mut count = 0usize;
        let mut bytes_used = 0usize;
        for line in state.queue.iter().take(available) {
            if count > 0 && bytes_used + line.text.len() > max_bytes {
                break;
            }
            bytes_used += line.text.len();
            count += 1;
        }
        if count == 0 {
            count = 1;
            bytes_used = state.queue.front().map_or(0, |line| line.text.len());
        }

        let lines: Vec<_> = state.queue.drain(..count).collect();
        state.bytes -= bytes_used;
        let dropped = std::mem::take(&mut state.dropped);
        let has_more = !state.queue.is_empty();
        drop(state);
        if has_more {
            self.inner.notify.notify_one();
        }
        (lines, dropped)
    }

    pub fn len(&self) -> usize {
        self.inner.state().queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn close(&self) {
        self.inner.close();
    }
}

impl Drop for RemoteSubscription {
    fn drop(&mut self) {
        self.inner.close();
    }
}

fn default_broker() -> &'static Arc<RemoteBroker> {
    static BROKER: OnceLock<Arc<RemoteBroker>> = OnceLock::new();
    BROKER.get_or_init(|| RemoteBroker::new(new_source_id()))
}

pub fn remote_source_id() -> &'static str {
    default_broker().source_id()
}

pub fn subscribe_remote() -> RemoteSubscription {
    default_broker().subscribe()
}

/// Splits a log write into lines and applies the same source prefix as Go.
pub fn publish_remote(source: &str, message: &str) {
    let message = message.strip_suffix('\n').unwrap_or(message);
    let message = message.strip_suffix('\r').unwrap_or(message);
    for line in message.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        default_broker().publish_lazy(|| {
            if source.is_empty() {
                line.to_owned()
            } else {
                format!("[{source}] {line}")
            }
        });
    }
}

fn truncate_utf8(mut value: String, max_bytes: usize) -> String {
    if max_bytes != 0 && value.len() > max_bytes {
        let mut end = max_bytes;
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
    }
    // Queue limits account for text length. Discard unused capacity before
    // transferring this buffer so a short or truncated line cannot retain an
    // arbitrarily large original allocation.
    if value.capacity() > value.len() {
        value.into_boxed_str().into_string()
    } else {
        value
    }
}

fn new_source_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    acp_proto::hex::encode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn broker() -> Arc<RemoteBroker> {
        RemoteBroker::new("test-source")
    }

    #[test]
    fn only_lines_after_subscription_are_queued() {
        let broker = broker();
        broker.publish("before");
        let subscription = broker.subscribe();
        assert!(subscription.is_empty());
        broker.publish("after");
        let (lines, dropped) = subscription.drain(10, REMOTE_QUEUE_MAX_BYTES);
        assert_eq!(dropped, 0);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].text, "after");
    }

    #[test]
    fn publish_skips_text_without_live_subscribers() {
        let broker = broker();
        broker.publish_lazy(|| panic!("no subscriber needs text"));

        let closed = broker.subscribe();
        closed.close();
        // Include stale entries to check that neither a closed subscription nor
        // an expired weak reference triggers formatting.
        {
            let mut state = broker.state();
            state
                .subscribers
                .insert(closed.inner.id, Arc::downgrade(&closed.inner));
            state.subscribers.insert(u64::MAX, Weak::new());
        }
        broker.publish_lazy(|| panic!("closed subscribers do not need text"));
        assert!(broker.state().subscribers.is_empty());

        let subscription = broker.subscribe();
        broker.publish_lazy(|| "visible".to_owned());
        let (lines, dropped) = subscription.drain(1, 100);
        assert_eq!(dropped, 0);
        assert_eq!(lines[0].sequence, 3);
        assert_eq!(lines[0].text, "visible");
    }

    #[test]
    fn public_text_conversion_can_reenter_the_broker() {
        struct ReentrantText(Arc<RemoteBroker>);
        impl From<ReentrantText> for String {
            fn from(text: ReentrantText) -> Self {
                // Check before entering again: a regression fails instead of
                // hanging the test process on the old non-reentrant mutex.
                assert!(text.0.state.try_lock().is_ok());
                let subscription = text.0.subscribe();
                text.0.publish("nested");
                assert_eq!(subscription.drain(1, 100).0[0].text, "nested");
                String::from("outer")
            }
        }

        let broker = broker();
        let subscription = broker.subscribe();
        broker.publish(ReentrantText(Arc::clone(&broker)));
        let (lines, _) = subscription.drain(2, 100);
        assert_eq!(lines[0].text, "nested");
        assert_eq!(lines[1].text, "outer");
        assert_eq!((lines[0].sequence, lines[1].sequence), (1, 2));
    }

    #[test]
    fn single_subscriber_keeps_owned_text_buffer() {
        let broker = broker();
        let subscription = broker.subscribe();
        let text = String::from("owned remote log line");
        let pointer = text.as_ptr();
        let capacity = text.capacity();
        assert_eq!(capacity, text.len());

        broker.publish(text);

        let (lines, dropped) = subscription.drain(1, 100);
        assert_eq!(dropped, 0);
        assert_eq!(lines[0].text, "owned remote log line");
        assert_eq!(lines[0].text.as_ptr(), pointer);
        assert_eq!(lines[0].text.capacity(), capacity);
    }

    #[test]
    fn short_line_does_not_retain_oversized_capacity() {
        let broker = broker();
        let subscription = broker.subscribe();
        let mut text = String::with_capacity(REMOTE_QUEUE_MAX_BYTES);
        text.push_str("short");

        broker.publish(text);

        let (lines, dropped) = subscription.drain(1, 100);
        assert_eq!(dropped, 0);
        assert_eq!(lines[0].text, "short");
        assert_eq!(lines[0].text.capacity(), lines[0].text.len());
    }

    #[test]
    fn fan_out_preserves_lines_and_moves_one_original_buffer() {
        let broker = broker();
        let subscriptions = [broker.subscribe(), broker.subscribe(), broker.subscribe()];
        let text = String::from("shared remote log line");
        let pointer = text.as_ptr();
        let builds = std::cell::Cell::new(0);
        broker.publish_lazy(|| {
            builds.set(builds.get() + 1);
            text
        });
        broker.publish("next line");

        let batches = subscriptions.map(|subscription| {
            let (lines, dropped) = subscription.drain(2, 100);
            assert_eq!(dropped, 0);
            assert_eq!(lines.len(), 2);
            assert_eq!((lines[0].sequence, lines[1].sequence), (1, 2));
            lines
        });
        assert_eq!(builds.get(), 1);
        assert_eq!(batches[0], batches[1]);
        assert_eq!(batches[1], batches[2]);
        assert_eq!(
            batches
                .iter()
                .filter(|lines| lines[0].text.as_ptr() == pointer)
                .count(),
            1
        );
    }

    #[test]
    fn count_limit_drops_the_oldest_lines() {
        let broker = broker();
        let subscription = broker.subscribe();
        let extra = 16;
        for index in 0..REMOTE_QUEUE_MAX_LINES + extra {
            broker.publish(format!("line-{index:04}"));
        }
        let (lines, dropped) =
            subscription.drain(REMOTE_QUEUE_MAX_LINES + extra, REMOTE_QUEUE_MAX_BYTES);
        assert_eq!(dropped, extra as u64);
        assert_eq!(lines.len(), REMOTE_QUEUE_MAX_LINES);
        assert_eq!(lines.first().unwrap().text, "line-0016");
        assert_eq!(lines.last().unwrap().text, "line-1039");
    }

    #[test]
    fn byte_limit_truncates_utf8_and_drops_oldest() {
        let broker = broker();
        let subscription = broker.subscribe();
        for _ in 0..40 {
            broker.publish("界".repeat(REMOTE_LINE_MAX_BYTES));
        }
        let (lines, dropped) = subscription.drain(REMOTE_QUEUE_MAX_LINES, REMOTE_QUEUE_MAX_BYTES);
        assert_eq!(lines.len(), REMOTE_QUEUE_MAX_BYTES / REMOTE_LINE_MAX_BYTES);
        assert_eq!(dropped, 8);
        assert!(
            lines
                .iter()
                .all(|line| line.text.is_char_boundary(line.text.len()))
        );
        assert!(
            lines
                .iter()
                .all(|line| line.text.len() <= REMOTE_LINE_MAX_BYTES)
        );
        assert!(
            lines
                .iter()
                .all(|line| line.text.capacity() == line.text.len())
        );
    }

    #[test]
    fn drain_honours_both_batch_limits_and_reports_drops_once() {
        let broker = broker();
        let subscription = broker.subscribe();
        for text in ["1234", "5678", "longer"] {
            broker.publish(text);
        }
        let (first, dropped) = subscription.drain(3, 5);
        assert_eq!(dropped, 0);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].text, "1234");
        let (rest, dropped) = subscription.drain(2, 100);
        assert_eq!(dropped, 0);
        assert_eq!(rest.len(), 2);
    }

    #[test]
    fn close_detaches_and_wakes_waiters() {
        let broker = broker();
        let subscription = broker.subscribe();
        subscription.close();
        broker.publish("ignored");
        assert!(subscription.is_empty());
    }

    #[test]
    fn source_ids_and_sequences_have_the_wire_shape() {
        let broker = broker();
        assert_eq!(new_source_id().len(), 32);
        let subscription = broker.subscribe();
        broker.publish("one");
        broker.publish("two");
        let (lines, _) = subscription.drain(2, 100);
        assert_eq!((lines[0].sequence, lines[1].sequence), (1, 2));
    }
}
