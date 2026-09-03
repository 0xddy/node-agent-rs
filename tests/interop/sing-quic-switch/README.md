# Official sing-quic direction-switch client

This local interoperability tool uses the official `hysteria2.NewClient` from
sing-quic `v0.7.0-beta.4`, quic-go `v0.61.0-sing-box-mod.7`, and sing
`v0.9.0-beta.4`. It starts no servers and generates only normal file transfers.

Build with Go 1.25 or later:

```sh
go build -o sing-quic-switch .
sing-quic-switch 127.0.0.1:HY2_PORT 127.0.0.1:TCP_PORT TEST_PASSWORD
```

Both addresses must be numeric loopback addresses with nonzero ports. Test TLS
certificate verification is disabled only in this local tool. The Rust harness
starts the HY2 server and TCP target and may select this executable through
`EXTERNAL_HY2_CLIENT`.

The target protocol is `UPLOAD_BYTES DOWNLOAD_BYTES\n`: consume the stated
number of `x` bytes, then return the stated number of `y` bytes. One HY2 client
performs four parallel 128 MiB downloads (`0 134217728\n`), followed immediately
by four parallel 32 MiB uploads (`33554432 1\n`). The one-byte reply confirms
each upload. All data is streamed in 64 KiB chunks and checked; no complete
file is allocated in memory. Each stream must then reach EOF within its deadline.

Finally a fresh logical stream over that client sends `who\n` and prints the
target's newline-terminated probe response (at most 4096 bytes). A SystemDialer
wrapper permits only one underlying UDP connection, so automatic HY2 reconnect
cannot silently hide a failed direction switch. The wrapper does not inject
loss, delays, or other faults.

Each logical connection has a 90-second deadline; the whole run is limited to
120 seconds. The HY2 client is closed on exit and on context cancellation.
Successful output includes `download ... bytes=536870912`,
`upload ... bytes=134217728`, elapsed times, and `probe=...`. Any data mismatch,
timeout, reconnect, or IO error exits with a nonzero status.

From the node-agent-rs workspace root, set `EXTERNAL_HY2_CLIENT` to the absolute
executable path and run the fixture (it supplies the addresses and test password):

```sh
cargo test --locked -p shoes-engine --test hysteria2_download official_go_client_download_then_upload -- --ignored --nocapture
```

The final probe must equal `bounded-peer`. The default Rust test run covers
the BBR and Brutal clients; this external Go test is opt-in and needs Go only
when building the standalone client.
