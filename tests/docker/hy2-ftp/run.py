#!/usr/bin/env python3
"""Real FTP/FTPS TS integrity checks through a freshly built Linux node-agent.

Requires Docker Linux containers, a local Rust build image, Go and FFmpeg.
All containers and evidence are retained; only this run's containers are stopped.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone

REPO = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def now():
    return datetime.now(timezone.utc).isoformat()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def run(args, *, log=None, timeout=120, env=None, cwd=None, check=True):
    result = subprocess.run([str(x) for x in args], cwd=cwd, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace", timeout=timeout)
    if log:
        log.write_text(result.stdout, encoding="utf-8")
    if check and result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {result.stdout[-4000:]}")
    return result


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def run_build(args, **kwargs):
    try:
        return run(args, **kwargs)
    except subprocess.TimeoutExpired:
        name = args[args.index("--name") + 1]
        label = run(["docker", "inspect", "--format", '{{index .Config.Labels "io.node-agent.test"}}', name], check=False)
        if label.stdout.strip() == "hy2-ftp":
            run(["docker", "stop", "--time", "10", name], check=False)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, default=REPO.parent / "shoes-plus")
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--base-image", default="node-agent-telemetry-test:latest")
    parser.add_argument("--image", default="node-agent-ftp-test:20260916")
    parser.add_argument("--proxy", default="http://host.docker.internal:10886")
    parser.add_argument("--target-volume", default="node-agent-hy2-docker-target")
    parser.add_argument("--registry-volume", default="shoes-r-cargo-registry")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-image-build", action="store_true")
    parser.add_argument("--host-port", type=int, default=18443)
    options = parser.parse_args()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    output = (options.run_dir or REPO / "run" / f"hy2-ftp-{stamp}").resolve()
    output.mkdir(parents=True, exist_ok=True)
    # Existing samples/binaries are allowed for manual build handoff, results aren't.
    if (output / "stages.jsonl").exists():
        raise RuntimeError("This directory already contains transfer results; use a new directory")
    state = output / "state"
    if state.exists() and any(state.iterdir()):
        raise RuntimeError("This directory contains fixture state; use a new directory")
    state.mkdir(exist_ok=True)
    daemon = f"node-agent-ftp-{stamp}"
    created = []
    docker = ["docker"]
    label = "io.node-agent.test=hy2-ftp"
    core = options.core.resolve()
    evidence = {
        "started_at": now(), "node_commit": run(["git", "rev-parse", "HEAD"], cwd=REPO).stdout.strip(),
        "core_commit": run(["git", "rev-parse", "HEAD"], cwd=core).stdout.strip(),
        "node_worktree": run(["git", "status", "--porcelain"], cwd=REPO).stdout.splitlines(),
        "core_worktree": run(["git", "status", "--porcelain"], cwd=core).stdout.splitlines(),
        "binary_provenance": "preexisting volume; source revisions not verified" if options.skip_build else "compiled from mounted working trees in this run",
        "runtime_cpus": 4, "runtime_memory": "2g", "daemon": daemon,
        "host_port": options.host_port, "options": {k: str(v) for k, v in vars(options).items()},
    }
    save(output / "run.json", evidence)
    if run(docker + ["info", "--format", "{{.OSType}}" ]).stdout.strip() != "linux":
        raise RuntimeError("Docker must use Linux containers")
    if not options.skip_image_build:
        print("Building FTP test image", flush=True)
        run(docker + ["build", "--build-arg", f"BASE_IMAGE={options.base_image}", "--build-arg",
                      f"BUILD_PROXY={options.proxy}", "-t", options.image, "-f", HERE / "Dockerfile", HERE],
            log=output / "image-build.log", timeout=900)
    evidence["image_id"] = run(docker + ["image", "inspect", "--format", "{{.Id}}", options.image]).stdout.strip()
    save(output / "run.json", evidence)
    if not options.skip_build:
        print("Building release daemon and fixture; then running upload regressions", flush=True)
        commands = "\n".join([
            "cargo build --release --locked --offline -p node-agent --bin node-agent",
            "cargo build --release --locked --offline -p node-agent --example hy2_container_fixture",
            "cargo test --locked --offline -p shoes-engine --test ftp_upload --test ftp_upload_late_stop --test hysteria2_upload --test hysteria2_fast_open",
        ])
        run_build(docker + ["run", "--name", daemon + "-build", "--label", label, "--cpus", "8", "--memory", "12g",
                      "--mount", f"type=bind,source={REPO},target=/workspace/node-agent-rs,readonly",
                      "--mount", f"type=bind,source={core},target=/workspace/shoes-plus,readonly",
                      "--mount", f"type=volume,source={options.target_volume},target=/build",
                      "--mount", f"type=volume,source={options.registry_volume},target=/usr/local/cargo/registry",
                      "--env", "CARGO_TARGET_DIR=/build", "--env", "CARGO_INCREMENTAL=0", "--env", "CARGO_BUILD_JOBS=8",
                      "--workdir", "/workspace/node-agent-rs", options.image, "bash", "-euc", commands],
            log=output / "build.log", timeout=2400)
    go_dir = REPO / "tests/interop/sing-quic-switch"
    client = output / ("ftp-integrity.exe" if os.name == "nt" else "ftp-integrity")
    for target, goos in [(client, "windows" if os.name == "nt" else "linux"), (output / "ftp-integrity-linux", "linux")]:
        env = dict(os.environ, GOOS=goos, GOARCH="amd64", CGO_ENABLED="0")
        run(["go", "build", "-o", target, "./cmd/ftp-integrity"], env=env, cwd=go_dir, timeout=300)
    samples = [("segment-05.ts", 4, "640x360", "3M"), ("large.ts", 32, "1280x720", "8M")]
    for name, duration, resolution, rate in samples:
        path = output / name
        if not path.exists():
            run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-f", "lavfi", "-i", f"testsrc2=size={resolution}:rate=25",
                 "-f", "lavfi", "-i", "sine=frequency=997:sample_rate=48000", "-t", duration, "-c:v", "libx264",
                 "-preset", "veryfast", "-b:v", rate, "-g", "50", "-sc_threshold", "0", "-c:a", "aac", "-b:a", "128k", "-f", "mpegts", path])
        run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-xerror", "-i", path, "-f", "null", "-"], log=output / f"{name}.decode.log")
    save(output / "files.json", {p.name: {"bytes": p.stat().st_size, "sha256": sha(p)} for p in [client, output / "ftp-integrity-linux", *(output / s[0] for s in samples)]})
    ftp = None
    failed = None
    checked_transfers = []

    def snapshot(name):
        result = run(docker + ["exec", daemon, "python3", "/harness/observe.py", "--state-dir", "/fixture"])
        (output / name).write_text(result.stdout, encoding="utf-8")
        health = json.loads(result.stdout)
        if not health["agent"]["running"] or not health["fixture"]["running"] or not health["ready"]["agent_ready"]:
            raise RuntimeError(f"Unhealthy daemon snapshot: {name}")

    def start_ftp(suffix, rate=0, encrypted=False):
        name = daemon + "-ftp-" + suffix
        run(docker + ["run", "-d", "--name", name, "--label", label, "--cpus", "2", "--memory", "512m",
                      "--network", f"container:{daemon}", "--mount", f"type=bind,source={state},target=/fixture",
                      "--mount", f"type=bind,source={output},target=/evidence",
                      "--mount", f"type=bind,source={HERE},target=/ftp-harness,readonly",
                      options.image, "python3", "/ftp-harness/ftp_server.py", "--read-limit", str(rate)] + (["--ftps"] if encrypted else []))
        created.append(name)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            ready = run(docker + ["exec", name, "python3", "-c", "import socket; socket.create_connection(('127.0.0.1',2121),1).close()"], check=False)
            if ready.returncode == 0:
                return name
            time.sleep(0.2)
        raise RuntimeError("FTP server did not start")

    def stage(name, sample="segment-05.ts", rounds=1, parallel=1, direct=False, fast=False, encrypted=True):
        print(f"{name}: {parallel} workers x {rounds} files ({sample})", flush=True)
        target_dir = output / name
        args = ["--mode", "direct" if direct else "hy2", "--close-mode", "graceful", "--password", "fixture-alice", "--server", f"127.0.0.1:{options.host_port}",
                "--target", "127.0.0.1:2121", "--file", f"/evidence/{sample}" if direct else str(output / sample),
                "--output-dir", f"/evidence/{name}" if direct else str(target_dir), "--rounds", str(rounds), "--parallel", str(parallel)]
        if fast:
            args.append("--fast-open")
        if encrypted:
            args.append("--ftps")
        command = docker + ["exec", ftp, "/evidence/ftp-integrity-linux"] + args if direct else [str(client)] + args
        started = now()
        result = run(command, log=output / f"{name}.log", timeout=600, check=False)
        with (output / "stages.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"name": name, "started_at": started, "ended_at": now(), "exit_code": result.returncode,
                                     "rounds": rounds, "parallel": parallel, "sample": sample, "direct": direct, "fast_open": fast, "ftps": encrypted}) + "\n")
        if result.returncode:
            raise RuntimeError(f"{name} failed: {result.stdout[-4000:]}")
        rows = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        if Counter((r["worker"], r["round"]) for r in rows) != Counter((w, r) for w in range(1, parallel + 1) for r in range(1, rounds + 1)):
            raise RuntimeError(f"{name}: missing, duplicate or unexpected transfer results")
        expected_size, expected_hash = (output / sample).stat().st_size, sha(output / sample)
        for row in rows:
            if not (row["ok"] and row["ftps"] == encrypted and row["close_mode"] == "graceful" and row["stor_code"] == row["retr_code"] == 226
                    and row["expected_bytes"] == row["uploaded_bytes"] == row["remote_bytes"] == row["retrieved_bytes"] == expected_size
                    and row["expected_sha256"] == row["retrieved_sha256"] == expected_hash):
                raise RuntimeError(f"{name}: incomplete transfer or inconsistent evidence: {row}")
        checked_transfers.extend(rows)
        retained = list(target_dir.glob("retrieved-w*.ts"))
        if len(retained) != parallel:
            raise RuntimeError(f"{name}: expected {parallel} retained files, found {len(retained)}")
        for path in retained:
            if path.stat().st_size != expected_size or sha(path) != expected_hash:
                raise RuntimeError(f"{name}: retained file differs from source: {path}")
            run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-xerror", "-i", path, "-f", "null", "-"],
                log=path.with_suffix(".decode.log"))

    try:
        run(docker + ["run", "-d", "--name", daemon, "--label", label, "--cpus", "4", "--memory", "2g", "--cap-add", "NET_ADMIN",
                      "--publish", f"127.0.0.1:{options.host_port}:18443/udp",
                      "--mount", f"type=volume,source={options.target_volume},target=/build,readonly",
                      "--mount", f"type=bind,source={state},target=/fixture",
                      "--mount", f"type=bind,source={REPO / 'tests/docker/hy2'},target=/harness,readonly",
                      options.image, "bash", "/harness/start.sh"])
        created.append(daemon)
        deadline = time.monotonic() + 120
        while True:
            if run(docker + ["inspect", "--format", "{{.State.Running}}", daemon]).stdout.strip() != "true":
                raise RuntimeError("Daemon container exited before readiness")
            try:
                if json.loads((state / "ready.json").read_text()).get("agent_ready") is True:
                    break
            except (OSError, ValueError):
                pass
            if time.monotonic() > deadline:
                raise RuntimeError("Daemon did not ACK configuration")
            time.sleep(0.25)
        run(docker + ["exec", daemon, "sha256sum", "/build/release/node-agent", "/build/release/examples/hy2_container_fixture"], log=output / "linux-binaries.sha256")
        run(docker + ["exec", daemon, "/build/release/node-agent", "version", "--json"], log=output / "node-agent-version.json")
        snapshot("before.json")
        ftp = start_ftp("normal")
        stage("plain-ftp-control", rounds=2, encrypted=False)
        run(docker + ["stop", "--time", "10", ftp])
        ftp = start_ftp("tls", encrypted=True)
        stage("direct-small", direct=True, rounds=2)
        stage("direct-large", direct=True, sample="large.ts")
        stage("hy2-sequential", rounds=30)
        stage("hy2-parallel", rounds=10, parallel=4)
        stage("hy2-fast-open", rounds=20, fast=True)
        stage("hy2-large-parallel", sample="large.ts", rounds=2, parallel=4, fast=True)
        run(docker + ["stop", "--time", "10", ftp])
        ftp = start_ftp("slow", 2 * 1024 * 1024, encrypted=True)
        stage("hy2-slow-target", sample="large.ts", parallel=2, fast=True)
        # Impair only this disposable container's egress, including QUIC ACK/data.
        run(docker + ["exec", daemon, "tc", "qdisc", "add", "dev", "eth0", "root", "netem", "delay", "10ms", "loss", "0.5%"])
        try:
            stage("hy2-loss-delay", rounds=3, parallel=4, fast=True)
        finally:
            run(docker + ["exec", daemon, "tc", "qdisc", "del", "dev", "eth0", "root"], check=False)
        stage("hy2-after-impairment", rounds=1)
        snapshot("after.json")
        events = [json.loads(line) for line in (state / "ftp-events.jsonl").read_text().splitlines()]
        server_hashes = Counter((Path(e["path"]).name, e["bytes"], e["sha256"]) for e in events if e["event"] == "received")
        client_hashes = Counter((r["remote_file"], r["expected_bytes"], r["expected_sha256"]) for r in checked_transfers)
        if server_hashes != client_hashes or any(e["event"] == "incomplete" for e in events):
            raise RuntimeError("FTP server completion/hash evidence differs from client results")
        save(output / "result.json", {"success": True, "finished_at": now(), "transfers": len(checked_transfers),
                                      "uploaded_bytes": sum(r["uploaded_bytes"] for r in checked_transfers),
                                      "retrieved_bytes": sum(r["retrieved_bytes"] for r in checked_transfers),
                                      "server_sha256_checks": sum(server_hashes.values())})
    except Exception as error:
        failed = error
        save(output / "result.json", {"success": False, "finished_at": now(), "error": str(error)})
    finally:
        for container in reversed(created):
            run(docker + ["logs", "--timestamps", container], log=output / f"{container}.log", check=False)
            run(docker + ["inspect", container], log=output / f"{container}.inspect.json", check=False)
            owned = run(docker + ["inspect", "--format", '{{index .Config.Labels "io.node-agent.test"}}', container], check=False).stdout.strip()
            if owned == "hy2-ftp":
                run(docker + ["stop", "--time", "10", container], check=False)
                run(docker + ["logs", "--timestamps", container], log=output / f"{container}.post-stop.log", check=False)
                run(docker + ["inspect", container], log=output / f"{container}.post-stop.inspect.json", check=False)
        print(f"Evidence: {output}", flush=True)
    if failed:
        raise failed


if __name__ == "__main__":
    main()
