//! Reconnect delay used by the panel session and each auxiliary stream.

use std::time::Duration;

use rand::RngExt as _;

/// Exponential backoff with equal jitter in `[base / 2, base)`.
///
/// Jitter is not fed back into `current`, so the deterministic growth remains
/// 1s, 2s, 4s, ... even when every returned sleep differs.  This is the Go
/// agent's fleet-restart behaviour: retain a useful floor without making every
/// node reconnect to the panel in lockstep.
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    initial: Duration,
    max: Duration,
    current: Duration,
}

impl ExponentialBackoff {
    pub fn new(initial: Duration, max: Duration) -> Self {
        Self {
            initial,
            max,
            current: Duration::ZERO,
        }
    }

    pub fn reset(&mut self) {
        self.current = Duration::ZERO;
    }

    pub fn current(&self) -> Duration {
        self.current
    }

    pub fn next_delay(&mut self) -> Duration {
        self.advance();
        let half = self.current / 2;
        if half.is_zero() {
            return self.current;
        }

        // Production delays are at most 30 seconds. Saturation keeps this type
        // total for callers that construct a much larger custom backoff.
        let jitter_bound = u64::try_from(half.as_nanos()).unwrap_or(u64::MAX);
        if jitter_bound == 0 {
            return self.current;
        }
        half + Duration::from_nanos(rand::rng().random_range(0..jitter_bound))
    }

    fn advance(&mut self) {
        self.current = if self.current.is_zero() {
            self.initial
        } else {
            self.current.saturating_mul(2).min(self.max)
        };
    }

    #[cfg(test)]
    fn next_with_jitter(&mut self, jitter: impl FnOnce(u64) -> u64) -> Duration {
        self.advance();
        let half = self.current / 2;
        let bound = u64::try_from(half.as_nanos()).unwrap_or(u64::MAX);
        if bound == 0 {
            return self.current;
        }
        half + Duration::from_nanos(jitter(bound).min(bound - 1))
    }
}

impl Iterator for ExponentialBackoff {
    type Item = Duration;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.next_delay())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn growth_caps_and_reset_restarts_at_the_initial_base() {
        let mut backoff = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
        for base in [1, 2, 4, 8, 16, 30, 30].map(Duration::from_secs) {
            let delay = backoff.next_delay();
            assert!(delay >= base / 2 && delay < base);
            assert_eq!(backoff.current(), base);
        }

        backoff.reset();
        let delay = backoff.next_delay();
        assert!(delay >= Duration::from_millis(500) && delay < Duration::from_secs(1));
    }

    #[test]
    fn equal_jitter_spans_exactly_the_upper_half() {
        let mut backoff = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
        assert_eq!(backoff.next_with_jitter(|_| 0), Duration::from_millis(500));

        backoff.reset();
        assert_eq!(
            backoff.next_with_jitter(|bound| bound - 1),
            Duration::from_secs(1) - Duration::from_nanos(1)
        );
    }

    #[test]
    fn independent_agents_do_not_all_choose_one_capped_delay() {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..32 {
            let mut backoff =
                ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
            for _ in 0..5 {
                backoff.next_delay();
            }
            let delay = backoff.next_delay();
            assert!(delay >= Duration::from_secs(15) && delay < Duration::from_secs(30));
            seen.insert(delay);
        }
        assert!(seen.len() > 1, "jitter did not spread reconnect attempts");
    }
}
