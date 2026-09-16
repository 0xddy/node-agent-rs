# Hysteria2 uploads closed before the TCP response

Follow-up (2026-09-16): cancellation after a successful TCP response exposed a
separate truncation window. See the [FTPS/TS Docker investigation](hysteria2-ftps-ts-integrity.md)
for the additional correction, before/after regression and real FTP/FTPS results.

The reported setup is current node-agent-rs behind an OpenClash client, with FTP
uploads leaving incomplete TS files. The exact observed file-size ceiling is
unknown. The reproduction below establishes an upload-loss defect in the current
core; it does not yet establish the cause of that particular size ceiling.

## Reproduction

An upload-only Hysteria2 client can enqueue its TCP request and file, send FIN,
and cancel the unused receive direction with STOP_SENDING without reading the
TCP response. The authenticated QUIC connection remains open. If the server is
still establishing the outbound connection, writing the success response then
fails with `quinn::WriteError::Stopped`.

Previously that failure returned from `process_tcp_stream` before replaying the
buffered request payload or copying the remaining upload. The target observed a
clean TCP EOF and an empty file even though the client had written 65,553 bytes.
This was reproduced on local loopback using the unmodified forwarding code.

`crates/shoes-engine/tests/ftp_upload.rs` checks destination byte counts, SHA-256
and clean EOF for files slightly larger than 64 KiB, 1 MiB and 4 MiB. It compares
FIN alone with FIN plus reverse STOP_SENDING, both after a response and with fast
open. A gated SOCKS5 outbound also holds setup until the client finishes and
cancels its read direction, exercising the setup race without relying on a fast
TCP connection to lose it.

The gated case uploads 4,194,493 bytes and includes both data buffered during
the SOCKS handshake and a later target banner. Those responses must not prevent
the target from receiving the complete file.

## Correction

The Hysteria2 success-response path distinguishes a stopped response direction
from connection failures. A stopped response does not authorize abandoning the
upload direction: buffered payload and remaining bytes must still reach the
target through FIN. The cancelled reverse direction is drained into a sink,
including target traffic arriving after setup, and the target's EOF is awaited.
Leaving unread TCP data at socket destruction could otherwise trigger a reset
while upload bytes were still in flight. Failed routing, rejection responses and
other transport errors retain their existing failure behavior.

The implementation is included in the sibling `shoes-plus` core at commit
`32e58642cab6c5b2e1c8fda24fdc3907ae6af112`. CI and release workflows pin this
revision so node-agent builds include the correction.

Local Windows validation: all 3 FTP upload tests, 7 existing Hysteria2 tests,
the fast-open suite (including a 16 MiB upload), and all 27 core Hysteria2 server
unit tests pass. The deterministic gated case failed on the original code with
a clean EOF and zero received bytes. The corrected case receives all 4,194,493
bytes with the expected SHA-256 and clean EOF. The reported OpenClash deployment
still needs to be retested with a build containing the correction.

Run from node-agent-rs:

```sh
cargo test --locked -p shoes-engine --test ftp_upload
```

Run from shoes-plus:

```sh
cargo test --locked --lib tcp_success_response
```
