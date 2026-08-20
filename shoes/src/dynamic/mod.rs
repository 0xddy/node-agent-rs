//! Extension points for driving shoes from a control plane instead of a config file.
//!
//! Nothing in here is used when shoes runs as a plain CLI with a YAML config: the
//! protocol handlers fall back to a [`StaticUserRegistry`] built from the config's
//! own credentials, which behaves exactly like the hardcoded comparison it replaced.
//!
//! The point of the indirection is that an embedder can hand each inbound its own
//! [`UserRegistry`] implementation and then add, update, and remove users at
//! runtime without restarting the listener.
//!
//! ## Why a registry and not an interceptor
//!
//! Authentication cannot be wrapped from the outside, because each protocol
//! carries its credential differently and at a different point in its handshake:
//! VLESS puts a raw uuid at byte offset 1, Trojan sends a hex digest terminated by
//! CRLF, VMess hides an AEAD-sealed auth id that can only be found by trial
//! decryption. So the credential lookup itself is what gets abstracted, and it is
//! injected into the existing handlers rather than layered on top of them.
//!
//! ## Hot path cost
//!
//! Lookups happen once per connection, during the handshake, never per packet.
//! Implementations are expected to be lock free; both of the ones shipped here are
//! (an immutable map for static configs, a sharded concurrent map for dynamic
//! ones), so authentication never contends with a config reload.
//!
//! ## Accounting
//!
//! A registry lookup returns the user's [`UserContext`], which is also where their
//! traffic is counted. [`TrafficMeterStream`] does the counting; its own
//! documentation covers where it sits in the stack and why the user is attached to
//! a connection that is already being metered.
//!
//! ## Reloading
//!
//! Rules and protocol settings change the same way users do: in place, without
//! restarting the listener and without disturbing what is already connected. A
//! started inbound hands back a [`ServerHandle`], whose `reload` swaps the handler
//! every new connection is given and whose `shutdown` stops the accept loops while
//! leaving established sessions to finish. See the [`reload`] module docs for why
//! that is enough to make the swap safe.

pub mod credential;
mod meter;
mod registry;
mod reload;
mod static_registry;
mod user;

pub use meter::{
    ConnContext, TrafficMeterStream, bind_connection_user, current_connection, scope_connection,
};
pub use registry::{ShadowsocksIdentity, TuicIdentity, UserRegistry, VmessIdentity};
pub use reload::{HandlerSlot, ServerHandle};
pub use static_registry::StaticUserRegistry;
pub use user::{UserContext, UserStats};

/// Records the runtime's thread count, which QUIC needs before any config is parsed.
///
/// `main` calls this once at startup (`main.rs:305`) and everything downstream
/// assumes it happened: a QUIC server with `num_endpoints: 0` resolves the default
/// from it (`config/validate.rs:657`) and a QUIC client sizes its endpoint pool the
/// same way (`tcp/socket_connector_impl.rs:158`). Both `unwrap` the `OnceLock`, so an
/// embedder that never sets it gets a panic the first time somebody configures QUIC.
///
/// A library has no `main` to do this in, hence the shim. It lives here rather than
/// as a `pub mod thread_util` because publishing an upstream module wholesale is a
/// wider change than the one call an embedder needs, and repeat calls after the first
/// are ignored -- so bootstrapping twice, or bootstrapping inside a process that is
/// also running the CLI, is not an error.
pub fn set_num_threads(num_threads: usize) {
    crate::thread_util::set_num_threads(num_threads);
}
