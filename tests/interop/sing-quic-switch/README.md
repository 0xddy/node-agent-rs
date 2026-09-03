# Official sing-quic direction-switch client

This local interoperability tool uses the official `hysteria2.NewClient` from
sing-quic `v0.7.0-beta.4`, quic-go `v0.61.0-sing-box-mod.7`, and sing
`v0.9.0-beta.4`. It starts no servers and generates normal, bounded file
transfers. Build with Go 1.25 or later:

```sh
go build -o sing-quic-switch .
sing-quic-switch 127.0.0.1:HY2_PORT 127.0.0.1:TCP_PORT TEST_PASSWORD [options]
```

The original three-argument invocation remains valid: four parallel 128 MiB
downloads, immediately followed by four parallel 32 MiB uploads, then a final
`who` probe. By default, one main HY2 Client and one underlying UDP/QUIC
connection are reused across every phase and round. `--connections N` creates
N independent main clients, each with its own UDP/QUIC connection; `--streams`
is the number of parallel logical streams on **each** connection. Every client
is reused for all rounds. Automatic reconnection is rejected by a
SystemDialer wrapper, so a disconnected main connection cannot be silently
replaced. Bandwidth fields remain zero for automatic congestion control.

The official SDK's [`Client.DialConn`](https://github.com/SagerNet/sing-quic/blob/v0.7.0-beta.4/hysteria2/client.go#L612-L624)
calls `offer` and opens a new stream on `conn.quicConn`.
[`offer`](https://github.com/SagerNet/sing-quic/blob/v0.7.0-beta.4/hysteria2/client.go#L172-L213)
reuses its active connection and shares an in-progress connection attempt
among concurrent calls. Browser Speedtest's multiple application connections
therefore do not by themselves establish that the HY2 client uses multiple
QUIC connections. Test these layouts separately.

Both addresses must be numeric loopback addresses with nonzero ports; neither
hostnames nor external destinations are accepted. When testing Docker, publish
the HY2 UDP port on **host loopback only**. The TCP target address is interpreted
inside the server container and must also be loopback. Certificate verification
is disabled for these local test certificates. The tool does not manage Docker,
servers, network shaping, packet loss, or other fault injection.

| Option | Meaning | Default |
| --- | --- | --- |
| `--connections N` | Independent main HY2/QUIC clients/connections, 1 to 32 | `1` |
| `--streams N` | Parallel logical streams per connection, 1 to 32 | `4` |
| `--download SIZE` | Download bytes **per stream**; `0` skips this phase | `128MiB` |
| `--cancel-download-after DURATION` | Normally close the logical download streams this long after their start barrier; `0` keeps the normal EOF path | `0s` |
| `--upload SIZE` | Upload bytes **per stream**; `0` skips this phase | `32MiB` |
| `--rounds N` | Repeat download then upload, 1 to 1000 | `1` |
| `--timeout DURATION` | Whole run, including probes and setup | `120s` |
| `--stream-timeout DURATION` | Absolute deadline per logical transfer, including dial and EOF | `90s` |
| `--probe-password VALUE` | Another user's password on an independent HY2 Client/QUIC | disabled |
| `--probe-interval DURATION` | Interval between independent probe opportunities | `1s` |
| `--probe-timeout DURATION` | Absolute deadline per probe | `5s` |

Flags follow the three positional arguments. Sizes accept integer byte counts
or the suffixes `B`, `KiB`, `MiB`, and `GiB`; they do not accept fractional
sizes. Durations other than the disabled cancellation option must be positive,
and at least one transfer size must be
positive. Each transfer uses one 64 KiB data buffer regardless of file size;
`connections * streams` plus one stream for an enabled independent probe is
capped at 32. Phase byte totals include every connection and are checked for
integer overflow. Passwords are test credentials and are not printed by the tool.
With cancellation enabled, the capacity check reserves both the old downloads
and new uploads: `2 * connections * streams + independent_probe <= 32`.

Each phase has a common start barrier after all main QUIC handshakes, logical
stream allocations, and 64 KiB buffers are ready. The command and payload writes
start after that barrier. This reduces client-side start skew; it does not
guarantee simultaneous packet arrival or TCP target establishment. Any main
worker failure or timeout cancels the phase, closes every main client, releases
workers waiting at the barrier, and collects every worker's result.

The target protocol is `UPLOAD_BYTES DOWNLOAD_BYTES\n`: consume exactly the
stated number of `x` bytes, return exactly the stated number of `y` bytes, and
close the TCP connection. Uploads request a one-byte reply to confirm that the
target consumed the full upload. Download content is checked. Every transfer
must reach a clean EOF; truncation, extra data, reset, or missing EOF fails the
run, except for the explicitly enabled cancellation phase described below.
The command `who\n` must produce exactly `bounded-peer\n` followed by EOF.

With `--probe-password`, a separate client first completes a baseline `who`
probe before load, then runs one probe at a time during the main transfers.
It reuses its own single QUIC connection and also rejects automatic reconnects.
The password must differ from the primary password; the server fixture must
map it to a different user. A probe that takes longer than the interval never
creates overlapping probe workers. Completed probe errors are retained while
the main transfer continues, and make the final exit status nonzero. An
in-flight probe cancelled by this monitor's cleanup is logged as
`status=cancelled` and excluded from completed samples. The cancellation cause
and actual typed error must both identify that cleanup; successes, independent
deadlines, remote closes, and other IO errors are retained even when cleanup
starts concurrently with the returned result. The baseline prevents an empty probe summary
from being counted as success; a very short run may finish before any periodic
sample, so inspect the phase labels when assessing coverage during load.

Output includes:

- `config`: connection count, streams per connection, total streams, byte sizes
  per stream and per phase, rounds, and timeouts.
- `progress`: approximately once a second, phase byte count and average
  throughput in decimal megabits per second (`mbps`, 1 Mbps = 1,000,000 bit/s).
- `phase_summary`: the same metrics at the end of each phase, with status and
  the count of streams that reached clean EOF.
- `connection_summary`: each main QUIC connection's aggregate bytes, longest
  no-progress interval, and count of streams that reached clean EOF.
- `stream_summary`: each stream's connection number, payload byte count, longest
  no-progress interval, and EOF result. Connection and per-connection stream
  numbers start at one within each phase.
- `independent_probe`: round/phase at probe start, latency through EOF, and
  success/error/cancellation; `independent_probe_summary` groups completed
  sample counts, errors, and maximum latency by that label.
- `probe=bounded-peer user=main connection=N ... eof=ok`: one final stream over
  each original main QUIC connection also completed successfully. A failure on
  any connection closes all main clients and fails the run.

`max_no_progress` measures the largest interval without application payload
progress across all main connections in the active phase.
`max_connection_no_progress` is the largest interval for any single QUIC
connection. `max_stream_no_progress` is the largest
such interval for any one stream; completed streams stop accumulating idle
time. The intervals include initial dial and the tail waiting for upload
confirmation or EOF. Upload progress counts actual successful `Write` byte
returns, which can include data accepted into transport buffers; it is not a
wire-rate or remote ACK measurement. The reply and EOF separately confirm
completion at the TCP target. Download progress counts verified received bytes.
The command line, probe traffic, and one-byte upload confirmation are excluded
from phase payload totals. Statistics report observed pauses without imposing
an additional latency threshold beyond the configured deadlines.

For the Docker fixture (`alice` and `bob` are separately configured users), a
single-stream 2 GiB upload is:

```powershell
.\sing-quic-docker.exe 127.0.0.1:18443 127.0.0.1:19091 fixture-alice --streams 1 --download 0 --upload 2GiB --rounds 1 --timeout 10m --stream-timeout 8m --probe-password fixture-bob --probe-interval 500ms --probe-timeout 5s
```

Four streams total 2 GiB down then 1 GiB up, repeated three times on the same
main QUIC connection:

```powershell
.\sing-quic-docker.exe 127.0.0.1:18443 127.0.0.1:19091 fixture-alice --streams 4 --download 512MiB --upload 256MiB --rounds 3 --timeout 15m --stream-timeout 10m --probe-password fixture-bob --probe-interval 500ms --probe-timeout 5s
```

For an equal-size concurrency comparison, build as `sing-quic-multiconn.exe`
and use these layout/size options with the same three positional arguments,
timeouts, and Bob probe flags. Each row transfers **1 GiB per phase**:

| Layout | Options for download immediately followed by upload |
| --- | --- |
| One QUIC, one stream | `--connections 1 --streams 1 --download 1GiB --upload 1GiB` |
| One QUIC, sixteen streams | `--connections 1 --streams 16 --download 64MiB --upload 64MiB` |
| Eight QUIC connections, two streams each | `--connections 8 --streams 2 --download 64MiB --upload 64MiB` |

Set `--download 0` for upload-only comparisons. The two concurrent layouts
have 16 main streams, leaving capacity for Bob under the fixture's 32-stream
limit. They isolate different transport layouts while keeping transferred
bytes equal; neither models every internal behavior of the Speedtest website.

To test a normal interrupted download followed immediately by upload on the
same main QUIC connections, enable `--cancel-download-after`. Both download
and upload sizes must be positive, and the cancellation duration must be
shorter than the stream and whole-run timeouts. Each round then:

1. Prepares all download streams and 64 KiB buffers, releases their common
   barrier, and starts the cancellation timer at that point.
2. Sends ordinary download commands and verifies received payload while the
   timer runs. The configured download size is an upper bound, not the expected
   successfully transferred total.
3. Calls the official logical connection's normal `Close` concurrently on all
   downloads when the timer fires. In this SDK,
   [`clientConn.Close`](https://github.com/SagerNet/sing-quic/blob/v0.7.0-beta.4/hysteria2/client.go#L782-L788)
   cancels reading with error code zero and closes the send stream with FIN;
   it does not close the underlying QUIC connection.
4. Collects every read worker and every close operation, then starts the
   existing upload phase immediately. The final per-QUIC probes and independent
   Bob probes still run normally, with automatic reconnect prohibited.

Cancellation succeeds only when **every** download received some valid payload,
stayed below its byte cap, and ended with the typed local QUIC stream cancellation
caused by the requested `Close`. Premature EOF, a reached byte cap, remote reset,
connection error, zero received payload, deadline, or failed `Close` makes the
run fail. In particular, the SDK's `errors.Is(err, io.EOF)` mapping is not enough
to recognize a requested cancellation. If a download finishes too quickly,
increase its size or reduce the cancellation duration; a completed download
cannot stand in for an interrupted one.

The cancellation phase reports actual verified bytes in the ordinary progress
and stream/connection summaries, `status=cancelled` with no clean EOF expected,
and additional `cancel_stream_summary` / `cancel_download_summary` lines. The
latter include the cancelled count and elapsed time from the start barrier to
the close requests. Bob remains active throughout the transition. No sleep,
main-client recreation, fault injection, or malformed packet is added.

For one QUIC with fifteen download streams, each bounded by 128 MiB, cancellation
at three seconds, and a subsequent **total 240 MiB upload**, repeated three times:

```powershell
.\sing-quic-cancel.exe 127.0.0.1:18443 127.0.0.1:19091 fixture-alice --connections 1 --streams 15 --download 128MiB --upload 16MiB --cancel-download-after 3s --rounds 3 --timeout 10m --stream-timeout 4m --probe-password fixture-bob --probe-interval 500ms --probe-timeout 5s
```

The cancellation example deliberately uses fifteen main streams: old downloads
that have not yet been released remotely plus new uploads and Bob can briefly
need `15 + 15 + 1 = 31` TCP handlers, within the fixture's unchanged capacity of
32. Local `Close` completion does not guarantee that the remote target has
already reclaimed each old handler. This leaves room for the immediate switch
without an artificial recovery delay. All transfers remain bounded by their
byte caps and deadlines. For the corresponding one-stream comparison, use
`--streams 1 --upload 240MiB` so the total uploaded bytes match.

The Rust in-process fixture still supplies the original three arguments. From
the node-agent-rs workspace root, set `EXTERNAL_HY2_CLIENT` to the absolute
executable path and run:

```sh
cargo test --locked -p shoes-engine --test hysteria2_download official_go_client_download_then_upload -- --ignored --nocapture
```

`go test ./...` checks argument boundaries and statistics without generating
network traffic. All transfer workers are joined after success, error, or
timeout; cancellation closes the HY2 clients to unblock IO, and the periodic
probe worker and cancellation callbacks are joined before exit.
