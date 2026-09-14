# Telemetry compatibility in Docker

Run in PowerShell 7 from the repository:

```powershell
./tests/docker/telemetry/run.ps1 -PanelPath 'G:\Development\Project\国际机场\panel-api-server' -Offline
```

Omit `-Offline` when the Cargo registry cache is empty. The tool image installs
Rust 1.91.1 using `-BuildProxy` (default `http://host.docker.internal:10886`).
The build reuses the named Cargo registry and Linux target volumes but always
builds the mounted current source. `-SkipBuild` is for diagnosing the fixture;
its result explicitly does not establish current-source binary provenance.

The script compiles the actual panel `internal/grpcapi` test binary using Go's
overlay facility. The extra test file lives here; no panel file is changed.
The real panel `Server.TelemetryStream`, session signature verification,
monotonic sample clock, `runtimestatus.Service`, and `LiveRuntimeRepository`
handle the Rust probe. The Rust probe uses the production `TelemetryReporter`
and Linux host collectors, with deterministic runtime counts (7 connections,
3 online users); it does not start a proxy data plane or a control stream.

The fixture checks:

- A 1.2-second ready-header delay succeeds with the independent 10-second
  handshake deadline.
- 14 accepted samples span more than 36 seconds, with a 3-second cadence within
  each stream and no stream-wide 1-second or 10-second deadline.
- A forced `Unavailable` followed by a 7-second disconnected interval retains
  the process instance and increasing sequence; unsent samples are replaced,
  and the second ready header establishes a later monotonic baseline.
- The actual Redis-backed repository reports the node online/fresh and exposes
  the submitted runtime counts. Samples have collection validity, disk sample
  timestamps, and network interface indexes/counter validity.
- A terminal `Unauthenticated` status returns to the caller promptly.
- An 11-second blocked header is canceled at the 10-second handshake deadline,
  before sending a sample.
- Production telemetry unit tests run in Linux, including sender and collector
  edge cases present in the current source.

MySQL and Redis use temporary container filesystems and a fresh internal Docker
network, without publishing ports or accessing an existing database. All
containers/network created by a run are removed in `finally`; build caches and
`run/telemetry-docker-*` artifacts are retained. Results include container logs,
received protobuf fields, source SHA-256 manifests, and Linux binary SHA-256s.
The final source manifest must match the initial one so concurrent source edits
cannot be mistaken for a verified build.
