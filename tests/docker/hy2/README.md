# Real node-agent HY2 Docker transfer test

This runs the release Linux `node-agent` daemon in Docker Desktop and connects
from Windows through the official Go sing-quic client. A separate fixture acts
as an ACP panel and a bounded TCP transfer target. The daemon goes through its
normal authentication, configuration, user synchronization, and listener startup.
Readiness requires its applied configuration ACK, not just an open fixture port.

The fixture uses disposable local test users `fixture-alice` and `fixture-bob`.
Only `127.0.0.1:18443/udp` is published. ACP and the transfer target listen on
container loopback; no production panel settings or credentials are needed.

## Run from PowerShell 7

Docker Desktop must be using Linux containers. Supply an existing Linux build
image containing Rust, a linker, CMake, Bash, and Python 3. The default image name
is `shoes-linux-test:latest`; the script never silently pulls an image or installs
system software. Go 1.25 or later is needed if a prebuilt client is not supplied.

```powershell
./tests/docker/hy2/run.ps1 -BuildImage shoes-linux-test:latest `
  -BuildProxy http://host.docker.internal:10886
```

The node repository and sibling `shoes-plus` repository are mounted read-only
during the build. Override the sibling with `-CorePath`. Cargo output uses
`node-agent-hy2-docker-target`, and the registry cache uses
`shoes-r-cargo-registry`; both volume names are configurable. `-Offline` requests
an offline Cargo build and reports missing dependencies without retrying online.
The production daemon is built first, in a separate Cargo invocation from the
fixture, so fixture dev-dependencies do not enable extra daemon features.

To reuse release binaries in the target volume and an existing Windows client:

```powershell
./tests/docker/hy2/run.ps1 -SkipBuild `
  -GoClient G:/Development/Project/node-agent-rs/run/sing-quic-switch.exe
```

The default build limit is 8 CPUs / 12 GiB; the runtime limit is 4 CPUs / 2 GiB.
`-BuildCpus`, `-BuildMemory`, `-RuntimeCpus`, and `-RuntimeMemory` override these.
`-HostPort` changes the host UDP port while the container remains on port 18443.
With `-SkipBuild`, source commits in `run.json` describe the current checkout,
not proven binary provenance; the output explicitly records this distinction.

## Transfer sequence

1. A short download and upload check basic connectivity.
2. One stream uploads 2 GiB.
3. Four streams each download 512 MiB, immediately followed by four streams each
   uploading 256 MiB. Repeat this direction change three times on the same HY2
   connection, for 6 GiB downloaded and 3 GiB uploaded.
4. Leave the container idle for 30 seconds and make another small transfer.

Data is generated and checked in bounded chunks. Each Go invocation refuses
automatic transport reconnection, so a replacement QUIC connection cannot hide
a failed direction switch. An independent Bob user is probed during transfers;
each invocation also probes the main connection at the end. Transfer deadlines and a container memory
limit bound the run. These are normal TCP-over-HY2 transfers, with no artificial
packet loss or packet injection.

## Evidence and lifecycle

Results go under the repository's ignored `run/hy2-docker-*` directory:

- `run.json` records commits, working-tree status, image ID, container names, ports,
  and resource limits. `linux-binaries.sha256` and `client.json` identify binaries.
  `node-agent-version.json` captures the running binary's version.
- Stage logs report bytes, elapsed time, probe failures, and client errors;
  `stages.jsonl` records exit status and arguments.
- `telemetry.jsonl` samples Docker CPU/memory/network figures, process RSS/thread/FD
  state, Linux UDP counters and queues, cgroup limits/events, and fixture statistics.
  The requested sampling interval is 2 seconds plus the Docker command duration.
- `before.json` and `after.json` provide complete snapshots around the transfers
  and the idle interval, independent of background sampling.
  Before the final snapshot, the runner waits 12 seconds for the normal 10-second
  traffic report and 1-second fixture snapshot (`-FinalReportWaitSeconds` overrides
  this). ACP totals include protocol commands and probes as well as file payloads.
- `state/agent.log`, `state/agent-console.log`, and `state/fixture.log` preserve logs.
  `state/ready.json` and `state/stats.json` preserve control-plane and transfer state.
- `container-inspect.json`, `processes.txt`, and `container.log` capture the final
  container state. `result.json` records whether all client stages passed.
  With `-StopAfter`, `post-stop-inspect.json` records the separate controlled stop;
  its exit state is distinct from the transfer result and the earlier running state.
  `stop.json` distinguishes a successful requested stop from a container that had
  already exited before the stop request.

UDP counters belong to the test container network namespace. Docker Desktop's
host forwarding path and a real WAN are additional layers, so this result is not
a WAN stability guarantee. Compare counter changes between idle and active stages,
and use daemon logs to distinguish a transport closure from a process exit.

The script retains containers, volumes, and results, including on failure. Add
`-StopAfter` to stop only the new runtime container after verifying its test label;
the stopped container and its artifacts remain available. Build containers are
retained for inspection. There is no automatic removal, volume cleanup, or prune.
