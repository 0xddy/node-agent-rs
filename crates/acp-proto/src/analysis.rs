//! Traffic-analysis defaults and allocation bounds shared with the Go agent.
//!
//! Keep these values in sync with `api/acp/v1/analysis.go`. Omitted fields take
//! defaults; explicit values are clamped before the forwarding process uses them.

use crate::TrafficAnalysisConfig;

#[must_use]
pub fn default_config(enabled: bool) -> TrafficAnalysisConfig {
    TrafficAnalysisConfig {
        enabled,
        sample_interval_seconds: 5,
        batch_max_entries: 1024,
        batch_max_bytes: 256 << 10,
        queue_max_bytes: 16 << 20,
        queue_max_age_seconds: 20,
        send_bytes_per_second: 256 << 10,
        send_burst_bytes: 512 << 10,
        send_timeout_millis: 1000,
        minute_max_domain_keys: 20_000,
        max_udp_targets: 40_000,
        max_udp_targets_per_session: 64,
        memory_max_bytes: 64 << 20,
    }
}

/// A missing configuration disables analysis and still returns bounded limits.
#[must_use]
pub fn normalize_config(config: Option<&TrafficAnalysisConfig>) -> TrafficAnalysisConfig {
    let Some(config) = config else {
        return default_config(false);
    };
    let mut out = default_config(config.enabled);
    out.sample_interval_seconds = bound(
        config.sample_interval_seconds,
        out.sample_interval_seconds,
        1,
        10,
    );
    out.batch_max_entries = bound(config.batch_max_entries, out.batch_max_entries, 1, 1024);
    out.batch_max_bytes = bound(config.batch_max_bytes, out.batch_max_bytes, 1024, 256 << 10);
    out.queue_max_bytes = bound(
        config.queue_max_bytes,
        out.queue_max_bytes,
        256 << 10,
        16 << 20,
    );
    out.queue_max_age_seconds = bound(
        config.queue_max_age_seconds,
        out.queue_max_age_seconds,
        1,
        20,
    );
    out.send_bytes_per_second = bound(
        config.send_bytes_per_second,
        out.send_bytes_per_second,
        1024,
        16 << 20,
    );
    out.send_burst_bytes = bound(
        config.send_burst_bytes,
        out.send_burst_bytes,
        u64::from(out.batch_max_bytes),
        16 << 20,
    );
    out.send_timeout_millis = bound(
        config.send_timeout_millis,
        out.send_timeout_millis,
        100,
        5000,
    );
    out.minute_max_domain_keys = bound(
        config.minute_max_domain_keys,
        out.minute_max_domain_keys,
        1,
        20_000,
    );
    out.max_udp_targets = bound(config.max_udp_targets, out.max_udp_targets, 1, 40_000);
    out.max_udp_targets_per_session = bound(
        config.max_udp_targets_per_session,
        out.max_udp_targets_per_session,
        1,
        64,
    );
    out.memory_max_bytes = bound(
        config.memory_max_bytes,
        out.memory_max_bytes,
        1 << 20,
        64 << 20,
    );
    out
}

fn bound<T: Ord + Copy + Default>(value: T, fallback: T, low: T, high: T) -> T {
    if value == T::default() {
        fallback
    } else {
        value.clamp(low, high)
    }
}

#[cfg(test)]
mod tests {
    use super::{default_config, normalize_config};
    use crate::TrafficAnalysisConfig;

    #[test]
    fn absent_limits_disable_analysis_and_enabled_only_uses_go_defaults() {
        assert_eq!(normalize_config(None), default_config(false));
        assert_eq!(
            normalize_config(Some(&TrafficAnalysisConfig {
                enabled: true,
                ..Default::default()
            })),
            default_config(true)
        );
    }

    #[test]
    fn excessive_config_cannot_allocate_beyond_go_limits() {
        let config = TrafficAnalysisConfig {
            enabled: true,
            sample_interval_seconds: u32::MAX,
            batch_max_entries: u32::MAX,
            batch_max_bytes: u32::MAX,
            queue_max_bytes: u64::MAX,
            queue_max_age_seconds: u32::MAX,
            send_bytes_per_second: u64::MAX,
            send_burst_bytes: u64::MAX,
            send_timeout_millis: u32::MAX,
            minute_max_domain_keys: u32::MAX,
            max_udp_targets: u32::MAX,
            max_udp_targets_per_session: u32::MAX,
            memory_max_bytes: u64::MAX,
        };
        let expected = TrafficAnalysisConfig {
            sample_interval_seconds: 10,
            send_bytes_per_second: 16 << 20,
            send_burst_bytes: 16 << 20,
            send_timeout_millis: 5000,
            ..default_config(true)
        };
        assert_eq!(normalize_config(Some(&config)), expected);
    }

    #[test]
    fn small_limits_preserve_a_sendable_batch_and_minimum_memory() {
        let config = TrafficAnalysisConfig {
            enabled: true,
            sample_interval_seconds: 1,
            batch_max_entries: 1,
            batch_max_bytes: 1,
            queue_max_bytes: 1,
            queue_max_age_seconds: 1,
            send_bytes_per_second: 1,
            send_burst_bytes: 1,
            send_timeout_millis: 1,
            minute_max_domain_keys: 1,
            max_udp_targets: 1,
            max_udp_targets_per_session: 1,
            memory_max_bytes: 1,
        };
        let normalized = normalize_config(Some(&config));
        assert_eq!(normalized.batch_max_bytes, 1024);
        assert_eq!(normalized.queue_max_bytes, 256 << 10);
        assert_eq!(normalized.send_bytes_per_second, 1024);
        assert_eq!(normalized.send_burst_bytes, 1024);
        assert_eq!(normalized.send_timeout_millis, 100);
        assert_eq!(normalized.memory_max_bytes, 1 << 20);
        assert_eq!(normalized.batch_max_entries, 1);
        assert_eq!(normalized.minute_max_domain_keys, 1);
        assert_eq!(normalized.max_udp_targets, 1);
        assert_eq!(normalized.max_udp_targets_per_session, 1);
        assert_eq!(normalize_config(Some(&normalized)), normalized);
    }

    #[test]
    fn burst_always_covers_the_normalized_maximum_batch() {
        let normalized = normalize_config(Some(&TrafficAnalysisConfig {
            batch_max_bytes: 128 << 10,
            send_burst_bytes: 1,
            ..Default::default()
        }));
        assert_eq!(normalized.send_burst_bytes, 128 << 10);
    }
}
