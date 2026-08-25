//! Per-user traffic aggregation and report thresholds.
//!
//! Runtime counters are deltas, not cumulative snapshots.  This layer merges
//! those deltas by the ACP identity tuple, keeps low-volume traffic until it is
//! worth sending (or becomes old), and can add reports back after a full output
//! queue.  `restore` is additive so observations made during a failed enqueue
//! are never overwritten.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod stream;

pub use stream::{
    FINAL_TRAFFIC_FLUSH_LIMIT, TRAFFIC_FLUSH_INTERVAL, TRAFFIC_QUEUE_SIZE, TrafficQueue,
    collect_runtime_traffic, run_traffic_flusher, run_traffic_stream,
};

pub const DEFAULT_REPORT_DELTA_BYTES: u64 = 25 * 1024 * 1024;
pub const DEFAULT_MAX_REPORT_DELAY: Duration = Duration::from_secs(30 * 60);
const OBSERVATION_BUCKET_SECONDS: i64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficEvent {
    pub machine_id: String,
    pub node_id: String,
    pub user_id: String,
    pub protocol: String,
    pub uplink_bytes: u64,
    pub downlink_bytes: u64,
    /// `None` has Go's zero-time meaning and is replaced by the aggregator clock.
    pub observed_at: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub machine_id: String,
    pub node_id: String,
    pub user_id: String,
    pub protocol: String,
    pub uplink_bytes: u64,
    pub downlink_bytes: u64,
    pub observed_at: SystemTime,
}

impl Report {
    /// Unix seconds written to `TrafficReport.observed_at_unix`.
    pub fn observed_at_unix(&self) -> i64 {
        unix_seconds(self.observed_at)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CounterKey {
    machine_id: String,
    node_id: String,
    user_id: String,
    protocol: String,
}

struct CounterValue {
    uplink: u64,
    downlink: u64,
    first_observed_at: SystemTime,
    last_observed_at: SystemTime,
}

struct State {
    counters: HashMap<CounterKey, CounterValue>,
}

/// Thread-safe accumulator used by the 10-second traffic flusher.
pub struct Aggregator {
    min_report_delta_bytes: u64,
    /// Signed to preserve Go's `<= 0 disables the age fallback` behaviour.
    max_report_delay_seconds: i64,
    state: Mutex<State>,
    clock: Arc<dyn Fn() -> SystemTime + Send + Sync>,
}

impl Aggregator {
    pub fn new(min_report_delta_bytes: u64) -> Self {
        Self::with_clock(min_report_delta_bytes, SystemTime::now)
    }

    pub fn with_clock(
        min_report_delta_bytes: u64,
        clock: impl Fn() -> SystemTime + Send + Sync + 'static,
    ) -> Self {
        Self {
            min_report_delta_bytes,
            max_report_delay_seconds: DEFAULT_MAX_REPORT_DELAY.as_secs() as i64,
            state: Mutex::new(State {
                counters: HashMap::new(),
            }),
            clock: Arc::new(clock),
        }
    }

    /// Override the age fallback. A non-positive value disables it, matching Go.
    pub fn set_max_report_delay_seconds(&mut self, seconds: i64) {
        self.max_report_delay_seconds = seconds;
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn observe(&self, event: TrafficEvent) {
        let observed_at = event.observed_at.unwrap_or_else(|| (self.clock)());
        let key = CounterKey {
            machine_id: event.machine_id,
            node_id: event.node_id,
            user_id: event.user_id,
            protocol: event.protocol,
        };
        add_locked(
            &mut self.state().counters,
            key,
            event.uplink_bytes,
            event.downlink_bytes,
            observed_at,
        );
    }

    pub fn flush(&self) -> Vec<Report> {
        self.flush_inner(false)
    }

    /// Emits every non-zero counter, reserved for graceful shutdown.
    pub fn flush_all(&self) -> Vec<Report> {
        self.flush_inner(true)
    }

    pub fn restore(&self, reports: impl IntoIterator<Item = Report>) {
        let mut state = self.state();
        for report in reports {
            if report.uplink_bytes == 0 && report.downlink_bytes == 0 {
                continue;
            }
            add_locked(
                &mut state.counters,
                CounterKey {
                    machine_id: report.machine_id,
                    node_id: report.node_id,
                    user_id: report.user_id,
                    protocol: report.protocol,
                },
                report.uplink_bytes,
                report.downlink_bytes,
                report.observed_at,
            );
        }
    }

    fn flush_inner(&self, force: bool) -> Vec<Report> {
        let now = (self.clock)();
        let mut reports = {
            let mut state = self.state();
            let mut reports = Vec::with_capacity(state.counters.len());
            state.counters.retain(|key, value| {
                if value.uplink == 0 && value.downlink == 0 {
                    return false;
                }
                if !force && !self.should_report(value, now) {
                    return true;
                }
                reports.push(Report {
                    machine_id: key.machine_id.clone(),
                    node_id: key.node_id.clone(),
                    user_id: key.user_id.clone(),
                    protocol: key.protocol.clone(),
                    uplink_bytes: value.uplink,
                    downlink_bytes: value.downlink,
                    observed_at: observation_bucket_start(value.last_observed_at),
                });
                false
            });
            reports
        };

        reports.sort_by(|left, right| {
            left.observed_at
                .cmp(&right.observed_at)
                .then_with(|| left.machine_id.cmp(&right.machine_id))
                .then_with(|| left.node_id.cmp(&right.node_id))
                .then_with(|| left.user_id.cmp(&right.user_id))
                .then_with(|| left.protocol.cmp(&right.protocol))
        });
        reports
    }

    fn should_report(&self, value: &CounterValue, now: SystemTime) -> bool {
        let total = value.uplink.wrapping_add(value.downlink);
        if total == 0 {
            return false;
        }
        if self.min_report_delta_bytes == 0 || total >= self.min_report_delta_bytes {
            return true;
        }
        if self.max_report_delay_seconds <= 0 {
            return false;
        }
        let deadline = value
            .first_observed_at
            .checked_add(Duration::from_secs(self.max_report_delay_seconds as u64));
        deadline.is_some_and(|deadline| now >= deadline)
    }
}

fn add_locked(
    counters: &mut HashMap<CounterKey, CounterValue>,
    key: CounterKey,
    uplink: u64,
    downlink: u64,
    observed_at: SystemTime,
) {
    let value = counters.entry(key).or_insert(CounterValue {
        uplink: 0,
        downlink: 0,
        first_observed_at: observed_at,
        last_observed_at: observed_at,
    });
    // Go uint64 addition wraps. The real engine counter cannot approach this in
    // one process lifetime, but spelling it out keeps debug and release identical.
    value.uplink = value.uplink.wrapping_add(uplink);
    value.downlink = value.downlink.wrapping_add(downlink);
    value.first_observed_at = value.first_observed_at.min(observed_at);
    value.last_observed_at = value.last_observed_at.max(observed_at);
}

fn observation_bucket_start(observed_at: SystemTime) -> SystemTime {
    system_time_from_unix(
        unix_seconds(observed_at).div_euclid(OBSERVATION_BUCKET_SECONDS)
            * OBSERVATION_BUCKET_SECONDS,
    )
}

fn unix_seconds(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        Err(error) => {
            let duration = error.duration();
            let seconds = i64::try_from(duration.as_secs()).unwrap_or(i64::MAX);
            if duration.subsec_nanos() == 0 {
                -seconds
            } else {
                seconds.saturating_neg().saturating_sub(1)
            }
        }
    }
}

fn system_time_from_unix(seconds: i64) -> SystemTime {
    if seconds >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds as u64))
            .unwrap_or(UNIX_EPOCH)
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(seconds.unsigned_abs()))
            .unwrap_or(UNIX_EPOCH)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, Ordering};

    use super::*;

    fn time(seconds: i64) -> SystemTime {
        system_time_from_unix(seconds)
    }

    fn event(at: SystemTime, uplink: u64, downlink: u64) -> TrafficEvent {
        TrafficEvent {
            machine_id: "machine-1".into(),
            node_id: "node-1".into(),
            user_id: "user-1".into(),
            protocol: "vless".into(),
            uplink_bytes: uplink,
            downlink_bytes: downlink,
            observed_at: Some(at),
        }
    }

    fn clock(
        start: i64,
    ) -> (
        Arc<AtomicI64>,
        impl Fn() -> SystemTime + Send + Sync + 'static,
    ) {
        let now = Arc::new(AtomicI64::new(start));
        let read = Arc::clone(&now);
        (now, move || time(read.load(Ordering::SeqCst)))
    }

    #[test]
    fn emitted_window_is_a_delta_and_is_cleared() {
        let now = 1_774_441_230;
        let aggregator = Aggregator::with_clock(1, move || time(now));
        aggregator.observe(event(time(now), 10, 20));
        let first = aggregator.flush();
        assert_eq!((first[0].uplink_bytes, first[0].downlink_bytes), (10, 20));
        assert!(aggregator.flush().is_empty());

        aggregator.observe(event(time(now), 5, 7));
        let second = aggregator.flush();
        assert_eq!((second[0].uplink_bytes, second[0].downlink_bytes), (5, 7));
    }

    #[test]
    fn threshold_combines_both_directions_across_minutes() {
        let (now, read_clock) = clock(1_774_441_230);
        let aggregator = Aggregator::with_clock(100, read_clock);
        aggregator.observe(event(time(now.load(Ordering::SeqCst)), 40, 0));
        assert!(aggregator.flush().is_empty());

        now.fetch_add(60, Ordering::SeqCst);
        aggregator.observe(event(time(now.load(Ordering::SeqCst)), 30, 10));
        assert!(aggregator.flush().is_empty());

        now.fetch_add(60, Ordering::SeqCst);
        aggregator.observe(event(time(now.load(Ordering::SeqCst)), 10, 10));
        let reports = aggregator.flush();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].uplink_bytes + reports[0].downlink_bytes, 100);
        assert_eq!(
            reports[0].observed_at_unix(),
            now.load(Ordering::SeqCst).div_euclid(60) * 60
        );
    }

    #[test]
    fn age_fallback_and_shutdown_flush_preserve_low_volume_users() {
        let (now, read_clock) = clock(1_774_441_230);
        let aggregator = Aggregator::with_clock(DEFAULT_REPORT_DELTA_BYTES, read_clock);
        aggregator.observe(event(time(now.load(Ordering::SeqCst)), 10, 20));
        now.fetch_add(
            DEFAULT_MAX_REPORT_DELAY.as_secs() as i64 - 1,
            Ordering::SeqCst,
        );
        assert!(aggregator.flush().is_empty());
        now.fetch_add(2, Ordering::SeqCst);
        assert_eq!(aggregator.flush().len(), 1);

        aggregator.observe(event(time(now.load(Ordering::SeqCst)), 1, 2));
        assert_eq!(aggregator.flush_all().len(), 1);
        assert!(aggregator.flush_all().is_empty());
    }

    #[test]
    fn restore_is_additive_with_concurrent_observations() {
        let now = time(1_774_441_230);
        let aggregator = Aggregator::with_clock(1, move || now);
        aggregator.restore([Report {
            machine_id: "machine-1".into(),
            node_id: "node-1".into(),
            user_id: "user-1".into(),
            protocol: "vless".into(),
            uplink_bytes: 10,
            downlink_bytes: 20,
            observed_at: observation_bucket_start(now),
        }]);
        aggregator.observe(event(now, 5, 0));
        let reports = aggregator.flush();
        assert_eq!(reports.len(), 1);
        assert_eq!(
            (reports[0].uplink_bytes, reports[0].downlink_bytes),
            (15, 20)
        );
    }

    #[test]
    fn the_full_identity_tuple_is_distinct_and_sorted() {
        let now = time(1_774_441_230);
        let aggregator = Aggregator::with_clock(1, move || now);
        for user in ["user-2", "user-1"] {
            let mut item = event(now, 1, 0);
            item.user_id = user.into();
            aggregator.observe(item);
        }
        let mut other = event(now, 1, 0);
        other.node_id = "node-2".into();
        other.protocol = "hysteria2".into();
        aggregator.observe(other);

        let reports = aggregator.flush();
        assert_eq!(reports.len(), 3);
        assert_eq!(reports[0].user_id, "user-1");
        assert_eq!(reports[1].user_id, "user-2");
        assert_eq!(reports[2].node_id, "node-2");
    }

    #[test]
    fn zero_threshold_reports_immediately_and_zero_counters_disappear() {
        let now = time(1_774_441_230);
        let aggregator = Aggregator::with_clock(0, move || now);
        aggregator.observe(event(now, 0, 0));
        assert!(aggregator.flush().is_empty());
        aggregator.observe(event(now, 1, 0));
        assert_eq!(aggregator.flush().len(), 1);
    }

    #[test]
    fn observation_buckets_use_utc_floor_even_before_the_epoch() {
        assert_eq!(unix_seconds(observation_bucket_start(time(61))), 60);
        assert_eq!(unix_seconds(observation_bucket_start(time(-1))), -60);
    }
}
