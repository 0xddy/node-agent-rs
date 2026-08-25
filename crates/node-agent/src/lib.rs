//! ACP node agent.
//!
//! The crate preserves the Go agent's ACP wire contract while replacing its
//! embedded sing-box data plane with shoes. [`agent`] owns process/session
//! orchestration; topology and runtime modules form the transactional boundary
//! between panel state, nftables port hopping, and the live shoes engine.

pub mod agent;
pub mod backoff;
pub mod cli;
pub mod compile;
pub mod config;
pub mod control;
pub mod logging;
pub mod outbound_adapter;
pub mod policy;
pub mod porthopping;
pub mod remote_control;
pub mod rule_set;
pub mod runtime;
pub mod session;
pub mod shutdown;
pub mod telemetry;
pub mod topology;
pub mod traffic;
