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
`who` probe. One main HY2 Client and one underlying UDP/QUIC connection are
reused across every phase and round. Automatic reconnection is rejected by a
SystemDialer wrapper, so a disconnected main connection cannot be silently
replaced. Bandwidth fields remain zero for automatic congestion control.

Both addresses must be numeric loopback addresses with nonzero ports; neither
hostnames nor external destinations are accepted. When testing Docker, publish
the HY2 UDP port on **host loopback only**. The TCP target address is interpreted
inside the server container and must also be loopback. Certificate verification
is disabled for these local test certificates. The tool does not manage Docker,
servers, network shaping, packet loss, or other fault injection.

| Option | Meaning | Default |
| --- | --- | --- |
| `--streams N` | Parallel streams per phase, 1 to 64 | `4` |
| `--download SIZE` | Download bytes **per stream**; `0` skips this phase | `128MiB` |
| `--upload SIZE` | Upload bytes **per stream**; `0` skips this phase | `32MiB` |
| `--rounds N` | Repeat download then upload, 1 to 1000 | `1` |
| `--timeout DURATION` | Whole run, including probes and setup | `120s` |
| `--stream-timeout DURATION` | Absolute deadline per logical transfer, including dial and EOF | `90s` |
| `--probe-password VALUE` | Another user's password on an independent HY2 Client/QUIC | disabled |
| `--probe-interval DURATION` | Interval between independent probe opportunities | `1s` |
| `--probe-timeout DURATION` | Absolute deadline per probe | `5s` |

Flags follow the three positional arguments. Sizes accept integer byte counts
or the suffixes `B`, `KiB`, `MiB`, and `GiB`; they do not accept fractional
sizes. All durations must be positive and at least one transfer size must be
positive. Each transfer uses one 64 KiB data buffer regardless of file size;
concurrency is capped at 64 and phase byte totals are checked for integer
overflow. Passwords are test credentials and are not printed by the tool.

The target protocol is `UPLOAD_BYTES DOWNLOAD_BYTES\n`: consume exactly the
stated number of `x` bytes, return exactly the stated number of `y` bytes, and
close the TCP connection. Uploads request a one-byte reply to confirm that the
target consumed the full upload. Download content is checked. Every transfer
must reach a clean EOF; truncation, extra data, reset, or missing EOF fails the
run. The command `who\n` must produce exactly `bounded-peer\n` followed by EOF.

With `--probe-password`, a separate client first completes a baseline `who`
probe before load, then runs one probe at a time during the main transfers.
It reuses its own single QUIC connection and also rejects automatic reconnects.
The password must differ from the primary password; the server fixture must
map it to a different user. A probe that takes longer than the interval never
creates overlapping probe workers. Completed probe errors are retained while
the main transfer continues, and make the final exit status nonzero. An
in-flight probe cancelled during cleanup is logged as `status=cancelled` and
excluded from completed samples. The baseline prevents an empty probe summary
from being counted as success; a very short run may finish before any periodic
sample, so inspect the phase labels when assessing coverage during load.

Output includes:

- `config`: explicit per-stream byte sizes, stream count, rounds, and timeouts.
- `progress`: approximately once a second, phase byte count and average
  throughput in decimal megabits per second (`mbps`, 1 Mbps = 1,000,000 bit/s).
- `phase_summary`: the same metrics at the end of each phase, with status and
  the count of streams that reached clean EOF.
- `stream_summary`: each stream's payload byte count, longest no-progress
  interval, and EOF result. Stream numbers start at one within each phase.
- `independent_probe`: round/phase at probe start, latency through EOF, and
  success/error/cancellation; `independent_probe_summary` groups completed
  sample counts, errors, and maximum latency by that label.
- `probe=bounded-peer user=main ... eof=ok`: the final stream over the original
  main QUIC connection also completed successfully.

`max_no_progress` measures the largest interval without application payload
progress across the active main phase. `max_stream_no_progress` is the largest
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
