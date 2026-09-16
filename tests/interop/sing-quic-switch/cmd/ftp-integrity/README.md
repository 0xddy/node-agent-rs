# FTP integrity client

This loopback-only fixture exercises real FTP control and passive data sessions
with the Go module's pinned official `sing-quic` HY2 implementation. Every HY2
worker and round shares one QUIC connection; a second UDP transport dial is
rejected so an automatic reconnect cannot conceal a broken connection.

From `tests/interop/sing-quic-switch`:

```sh
go test ./cmd/ftp-integrity
go build -o ftp-integrity ./cmd/ftp-integrity
./ftp-integrity --mode hy2 --server 127.0.0.1:18443 \
  --target 127.0.0.1:2121 --password fixture-alice \
  --file sample.ts --output-dir retrieved \
  --rounds 20 --parallel 4 --timeout 10m --transfer-timeout 90s
```

Use `--mode direct` for the TCP baseline from the FTP server's network namespace.
The FTP credentials are always `fixture` / `fixture`, and transfer type is binary
(`TYPE I`). EPSV is preferred, with PASV fallback for unsupported EPSV. Both
control and data connections use HY2 in HY2 mode.

Add `--ftps` for explicit FTPS: the client sends `AUTH TLS`, waits for `234`,
secures the control connection before login, and enables private data channels
with `PBSZ 0` and `PROT P`. Each passive data connection performs a TLS handshake
after the server's `125`/`150` reply. Control and data TLS connections share a
session cache, support TLS 1.2 or newer, and accept the loopback fixture's
self-signed certificate. The default `--close-mode graceful` sends the upload
TLS `close_notify`, drains the peer's TLS shutdown response to clean EOF, and
then calls the underlying connection's normal `Close`. This avoids an unread
TLS session ticket or shutdown response causing a TCP reset on close, which
can discard buffered uploads even in direct mode. `--close-mode immediate`
retains immediate `tls.Close` as a deliberate shutdown stress case; a failure
in that mode alone does not establish a HY2 bug. These modes affect FTPS only;
plain FTP still calls the official HY2 connection's normal `Close` immediately
after `io.Copy`. JSONL records include `ftps` and `close_mode`.

Each round performs `STOR`, checks FTP `226`, queries `SIZE`, performs `RETR`,
checks its `226`, and compares the byte counts and SHA-256 digest against the
source. Plain FTP and immediate FTPS close after the upload's complete
`io.Copy`, including the official HY2 client's receive-side cancellation and
send-side FIN, without waiting for upload-side EOF. The receiver must therefore
finish draining the upload correctly. Graceful FTPS performs the TLS shutdown
exchange described above before closing the underlying transport.

`--fast-open` skips waiting for the HY2 TCP response on upload data streams. The
pinned SDK exposes lazy request/response processing rather than a `FastOpen`
configuration option. A zero-byte write starts the HY2 request in both modes,
because an FTP server may wait for the passive TCP connection before answering
`STOR`. With FTPS, the subsequent TLS handshake necessarily reads the HY2
response before application data can be sent. This option does not enable QUIC 0-RTT.

Stdout is JSONL, one record per attempted worker/round. Records include source,
upload, server `SIZE`, and downloaded byte counts, source/download SHA-256,
completion codes, durations, and errors. A failed worker stops without reconnect;
other workers finish their own rounds. Any failure makes the process exit 1.
An erroneous `226` with a shortened file still fails integrity validation, and
the actual retrieved bytes are retained for inspection.

Only the latest retrieved file per worker is retained as `retrieved-wNN.ts` in
the output directory. On the server, each worker overwrites its own uniquely
named `integrity-<run-id>-wNN.ts` across rounds. These remote files remain for
server-side hashing. Use separate output directories for independent runs.

The pinned SDK wraps a clean `io.EOF` in another error. The transport reader
below TLS and the application copy reader normalize only errors whose final
unwrapped cause is exactly `io.EOF`, which allows the TLS record decoder and
standard library copy loop to recognize clean completion. Normalization must
occur below TLS: the SDK may return final bytes and wrapped EOF together, which
otherwise makes Go's TLS decoder abandon a final record already received. It does
not use `errors.Is(err, io.EOF)`, because the SDK also matches locally cancelled
streams against that sentinel. Cancellation, resets, and unexpected EOF remain
errors and do not bypass byte/hash or FTP completion checks.
