# HY2 upload stalls: receive reassembly and ingress protection

## Reproduced failure

With server `up_mbps=0`, `down_mbps=0`, and `ignore_client_bandwidth=true`, a
normal upload can close the entire QUIC connection when its TCP destination
temporarily stops reading. This affects all streams sharing that connection,
while a separate connection and the node-agent process remain healthy.

The regression uses a TCP destination with a 16 KiB receive buffer that pauses
reading for one second. The client uses BBR and fast open and sends a 128 MiB
upload in 64 KiB chunks. It also downloads 1 MiB over the same connection and
an independent connection during the upload.

| Same test on local loopback | Before | After |
| --- | --- | --- |
| Upload | Fails after about 175 ms | All 134,217,728 bytes received |
| Error | `INTERNAL_ERROR: too many gaps in stream buffer` | None |
| Same-connection new stream | Fails | Works |
| Independent connection | Works | Works |
| QUIC packet loss in the backpressure case | 0 | 0 |

These timings are observations from a local regression, not WAN performance
claims. They prove a real defect and its correction; the affected deployment
still needs to be retested.

## Cause and correction

Stock `quinn-proto` 0.11.17 could retain more than 2,048 separate, nearly full
packet buffers without merging their contiguous contents. Its fragmentation
limit then rejected ordinary buffered data as excessive gaps. The trigger is
unread backlog, not the total file size, so the observed upload size can vary.

The local backport follows [Quinn PR #2814](https://github.com/quinn-rs/quinn/pull/2814)
and [issue #2809](https://github.com/quinn-rs/quinn/issues/2809). It coalesces small
contiguous chunks before enforcing the existing limits. It retains the 1,024
post-compaction chunk limit, 2,048 compaction trigger, and 8/20 MiB stream/connection
receive windows. Sparse hostile data is still rejected.

Changing congestion control can change how quickly backlog develops, but cannot
repair this reassembly error. The correction applies to both BBR and Brutal.
In the reviewed runtime configuration (`0/0` with `ignore_client_bandwidth=true`),
the existing negotiation selects BBR and returns `Hysteria-CC-RX: auto`. The
failure is therefore not evidence of an unlimited Brutal sender: the regression
reproduces it with BBR and zero packet loss.

## Comparison with the reference cores

| Control | Reference behavior | Rust implementation |
| --- | --- | --- |
| Application backpressure | Xray reads a batch then completes its write; bounded pipes wait when full. sing-box copies the two directions independently. | Already uses bounded 32 KiB copy buffers and waits for downstream writes. |
| Fragmentation accounting | quic-go tracks actual stream gaps separately from received packet buffers. | Backported contiguous-chunk coalescing fixes the false fragmentation failure. |
| Unprocessed packets | quic-go limits each connection to 256 pending packets and drops excess packets. | Added the same per-connection packet admission limit before decryption. |
| Failure visibility | Reference cores report connection/stream failures. | Unexpected authenticated HY2 closure now logs its reason and path counters at warning level, including release builds. |

Reference source: [Xray copy](https://github.com/XTLS/Xray-core/blob/main/common/buf/copy.go),
[Xray pipe](https://github.com/XTLS/Xray-core/blob/main/transport/pipe/impl.go),
[sing-box connection copy](https://github.com/SagerNet/sing-box/blob/v1.14.0/route/conn.go),
[sing buffered copy](https://github.com/SagerNet/sing/blob/v0.9.0-beta.4/common/bufio/copy.go),
[quic-go receive processing](https://github.com/quic-go/quic-go/blob/v0.61.0/connection.go),
and [quic-go frame sorter](https://github.com/quic-go/quic-go/blob/v0.61.0/frame_sorter.go).

Only network packets consume the new ingress permits. Local close, rebind and
protocol control events remain deliverable when a packet queue is full. Permits
are released on dequeue, failed sends and receiver destruction. The limit is a
packet count, not a fixed `256 * MTU` allocation bound, and does not establish
protection against unlimited concurrent connections or arbitrary denial of service.
Reliable stream data can recover from admission drops through QUIC loss recovery;
QUIC DATAGRAM payloads retain best-effort semantics and are not retransmitted.

## Regression commands

From node-agent-rs:

```sh
cargo test --locked -p shoes-engine --test hysteria2_upload --test brutal
```

From shoes-plus:

```sh
cargo test --locked --test quinn_ingress --test quinn_receive_reassembly
```

The latter compiles the patched private modules directly into test harnesses,
using the normal shoes-plus lockfile without copying their implementation.
Additional coverage checks 128 MiB uploads with mild deterministic loss and
reordering, explicit/default bandwidth behavior, and connection liveness.

Both workspace roots must select the vendored `quinn` and `quinn-proto` patches;
Cargo ignores dependency-local patch sections. The shoes-plus revision pinned
by CI/release must therefore include both vendor directories and their licenses.
Each directory contains a `PATCH.md` with its source and maintenance notes.
