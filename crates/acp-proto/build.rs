//! Compiles `proto/acp.proto` with protox, a pure-Rust protobuf compiler.
//!
//! Using protox rather than `protoc` keeps the build hermetic: no external
//! toolchain, no version skew between developer machines and CI. protox parses
//! into the same `FileDescriptorSet` that prost-build would otherwise get from
//! protoc, so the generated code is identical either way.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/acp.proto");

    let descriptors = protox::compile(["proto/acp.proto"], ["proto"])?;

    tonic_prost_build::configure()
        // Server stubs are used by node-agent's in-process tonic compatibility
        // tests.  This only expands the Rust API surface; it does not change the
        // descriptor or any bytes on the wire.
        .build_server(true)
        .build_client(true)
        .compile_fds(descriptors)?;

    Ok(())
}
