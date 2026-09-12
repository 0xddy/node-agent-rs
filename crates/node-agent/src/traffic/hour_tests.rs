use std::sync::atomic::{AtomicI64, Ordering};

use super::*;

fn event(at: i64, uplink: u64, downlink: u64) -> TrafficEvent {
    TrafficEvent {
        machine_id: "machine-1".into(),
        node_id: "node-1".into(),
        user_id: "user-1".into(),
        protocol: "vless".into(),
        uplink_bytes: uplink,
        downlink_bytes: downlink,
        observed_at: Some(system_time_from_unix(at)),
    }
}

fn aggregator(start: i64, threshold: u64) -> (Arc<AtomicI64>, Aggregator) {
    let now = Arc::new(AtomicI64::new(start));
    let read = Arc::clone(&now);
    let aggregator = Aggregator::with_clock(threshold, move || {
        system_time_from_unix(read.load(Ordering::SeqCst))
    });
    (now, aggregator)
}

fn timestamp(value: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(value)
        .unwrap()
        .timestamp()
}

#[test]
fn morning_download_stays_separate_from_afternoon_traffic() {
    let morning = timestamp("2026-09-12T01:30:00+08:00");
    let afternoon = timestamp("2026-09-12T13:00:00+08:00");
    let download = 30 * 1024 * 1024 * 1024;
    for restore in [false, true] {
        let (now, aggregator) = aggregator(morning, DEFAULT_REPORT_DELTA_BYTES);
        aggregator.observe(event(morning, 0, download));
        let pending = restore.then(|| aggregator.flush());
        now.store(afternoon, Ordering::SeqCst);
        aggregator.observe(event(afternoon, 1, 0));
        if let Some(pending) = pending {
            assert_eq!(pending.len(), 1);
            aggregator.restore(pending);
        }
        now.store(afternoon + 1800, Ordering::SeqCst);
        let reports = aggregator.flush();
        assert_eq!(reports.len(), 2, "restore={restore}");
        assert_eq!(
            (
                reports[0].observed_at_unix(),
                reports[0].uplink_bytes,
                reports[0].downlink_bytes
            ),
            (morning, 0, download)
        );
        assert_eq!(
            (
                reports[1].observed_at_unix(),
                reports[1].uplink_bytes,
                reports[1].downlink_bytes
            ),
            (afternoon, 1, 0)
        );
        assert!(aggregator.flush_all().is_empty());
    }
}

#[test]
fn out_of_order_midnight_traffic_keeps_each_date_after_restore() {
    let before = timestamp("2026-09-12T23:59:59+08:00");
    let after = before + 1;
    let (_, aggregator) = aggregator(after, 1);
    aggregator.observe(event(after, 0, 20));
    aggregator.observe(event(before, 0, 10));
    let reports = aggregator.flush();
    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].observed_at_unix(), before - 59);
    assert_eq!(reports[0].downlink_bytes, 10);
    assert_eq!(reports[1].observed_at_unix(), after);
    assert_eq!(reports[1].downlink_bytes, 20);
    aggregator.restore(reports.clone());
    assert_eq!(aggregator.flush(), reports);
}

#[test]
fn overdue_small_traffic_remains_ready_after_each_restore() {
    let start = timestamp("2026-09-12T12:00:30Z");
    let (now, aggregator) = aggregator(start, 100);
    aggregator.observe(event(start, 10, 0));
    aggregator.observe(event(start + 29 * 60, 20, 0));
    now.store(start + 1800, Ordering::SeqCst);
    let mut reports = aggregator.flush();
    assert_eq!(reports.len(), 1);
    for retry in 1..=3 {
        let current = start + 1800 + retry * 10;
        now.store(current, Ordering::SeqCst);
        aggregator.observe(event(current, 1, 0));
        aggregator.restore(reports);
        reports = aggregator.flush();
        assert_eq!(reports.len(), 1, "retry {retry} reset the 30-minute delay");
        assert_eq!(reports[0].uplink_bytes, 30 + retry as u64);
    }
}

#[test]
fn restore_preserves_precise_age_despite_rounded_wire_timestamp() {
    let start = timestamp("2026-09-12T12:00:40Z");
    for concurrent in [false, true] {
        let (now, aggregator) = aggregator(start, 100);
        aggregator.observe(event(start, 10, 0));
        aggregator.observe(event(start + 5, 20, 0));
        let pending = aggregator.flush_all();
        if concurrent {
            aggregator.observe(event(start + 10, 1, 0));
        }
        aggregator.restore(pending);
        now.store(start + 1770, Ordering::SeqCst);
        assert!(aggregator.flush().is_empty());
        now.store(start + 1800, Ordering::SeqCst);
        let reports = aggregator.flush();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].uplink_bytes, 30 + u64::from(concurrent));
    }
}

#[test]
fn oldest_unreported_traffic_has_priority_over_fresh_traffic() {
    let start = timestamp("2026-09-12T12:00:01Z");
    let (_, aggregator) = aggregator(start, 1);
    let mut busy = event(start, 10, 0);
    busy.user_id = "a-busy".into();
    let mut waiting = event(start, 20, 0);
    waiting.user_id = "z-waiting".into();
    aggregator.observe(busy.clone());
    aggregator.observe(waiting.clone());
    let initial = aggregator.flush();
    assert_eq!(initial.len(), 2);
    assert_eq!(initial[0].user_id, "a-busy");
    aggregator.restore(initial[1..].iter().cloned());
    busy.observed_at = Some(system_time_from_unix(start + 10));
    busy.uplink_bytes = 30;
    waiting.observed_at = busy.observed_at;
    waiting.uplink_bytes = 40;
    aggregator.observe(busy);
    aggregator.observe(waiting);
    let reports = aggregator.flush();
    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].user_id, "z-waiting");
    assert_eq!(reports[0].uplink_bytes, 60);
    assert_eq!(reports[1].user_id, "a-busy");
    assert_eq!(reports[1].uplink_bytes, 30);
    assert_eq!(
        initial[0].uplink_bytes + reports[0].uplink_bytes + reports[1].uplink_bytes,
        100
    );
}

#[test]
fn hour_identity_uses_utc_and_floors_before_the_epoch() {
    let (_, aggregator) = aggregator(0, 1);
    for at in [
        "2026-09-12T05:45:00Z",
        "2026-09-12T13:45:00+08:00",
        "2026-09-12T11:30:00+05:45",
    ] {
        aggregator.observe(event(timestamp(at), 10, 0));
    }
    let reports = aggregator.flush();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].uplink_bytes, 30);
    aggregator.observe(event(-1, 1, 0));
    aggregator.observe(event(0, 2, 0));
    let reports = aggregator.flush();
    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].observed_at_unix(), -60);
    assert_eq!(reports[1].observed_at_unix(), 0);
}
