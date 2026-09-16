//! Lossy domain analysis, isolated from billable traffic and the control transport.

pub mod collector;
mod stream;

pub use collector::{Collector, Flow, Metadata, Observation, QueuedBatch, Target};
pub(crate) use stream::{SendLimiter, run_analysis_stream};

use std::sync::Arc;

/// Cancelling or dropping any session owner immediately invalidates its counters.
/// Collector epochs make a late guard from an older session harmless.
pub(crate) struct SessionAnalysisGuard {
    collector: Arc<Collector>,
    epoch: u64,
}

impl SessionAnalysisGuard {
    pub(crate) fn new(collector: Arc<Collector>, epoch: u64) -> Self {
        Self { collector, epoch }
    }
}

impl Drop for SessionAnalysisGuard {
    fn drop(&mut self) {
        self.collector.pause(self.epoch);
    }
}

impl shoes_engine::AnalysisFlow for Flow {
    fn begin(&self) -> u64 {
        self.begin_token()
    }

    fn finish(
        &self,
        token: u64,
        upload: u64,
        download: u64,
        target: Option<&shoes_engine::AnalysisTarget>,
    ) {
        self.finish_token(token, upload, download, target);
    }

    fn cancel(&self, token: u64) {
        self.cancel_token(token);
    }

    fn finish_web(
        &self,
        token: u64,
        upload: u64,
        download: u64,
        target: Option<&Target>,
        identified: bool,
    ) {
        self.finish_web_token(token, upload, download, target, identified);
    }

    fn close(&self) {
        Flow::close(self);
    }

    fn classify_target(
        &self,
        token: u64,
        target: &Target,
        domain: Option<&str>,
        app_protocol: &str,
        ech_present: bool,
    ) -> bool {
        Flow::classify_target(self, token, target, domain, app_protocol, ech_present)
    }

    fn discard_target(&self, token: u64, target: &Target) {
        Flow::discard_target(self, token, target);
    }

    fn try_reserve_pending_storage(&self, bytes: usize) -> bool {
        Flow::try_reserve_pending_storage(self, bytes)
    }

    fn release_pending_storage(&self, bytes: usize) {
        Flow::release_pending_storage(self, bytes);
    }

    fn promote_pending_storage(&self, bytes: usize) {
        Flow::promote_pending_storage(self, bytes);
    }

    fn try_reserve_sniff(&self, bytes: usize) -> bool {
        Flow::try_reserve_sniff(self, bytes)
    }

    fn release_sniff(&self, bytes: usize) {
        Flow::release_sniff(self, bytes);
    }

    fn try_reserve_storage(&self, bytes: usize) -> bool {
        Flow::try_reserve_storage(self, bytes)
    }

    fn release_storage(&self, bytes: usize) {
        Flow::release_storage(self, bytes);
    }
}
