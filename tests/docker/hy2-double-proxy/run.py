#!/usr/bin/env python3
"""Compare real FileZilla FTPS uploads through one or two Mihomo HY2 layers."""

import argparse
from collections import Counter
from datetime import datetime
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import threading


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("filezilla_harness", HERE.parent / "hy2-filezilla" / "run.py")
fz = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fz)


def mihomo_config(nested):
    inner = {"name": "inner", "type": "hysteria2", "server": "127.0.0.1",
             "port": 18443, "password": "fixture-alice", "sni": "localhost",
             "skip-cert-verify": True, "udp": True}
    proxies = [inner]
    if nested:
        inner["dialer-proxy"] = "outer"
        proxies.append({"name": "outer", "type": "hysteria2", "server": "127.0.0.1",
                        "port": 18443, "password": "fixture-bob", "sni": "localhost",
                        "skip-cert-verify": True, "udp": True})
    return {"socks-port": 1080, "allow-lan": False, "bind-address": "127.0.0.1",
            "mode": "rule", "log-level": "debug", "ipv6": False,
            "external-controller": "127.0.0.1:19095", "secret": "",
            "dns": {"enable": False}, "proxies": proxies, "rules": ["MATCH,inner"]}


def controller(container, path):
    command = ("import urllib.request; "
               f"print(urllib.request.urlopen('http://127.0.0.1:19095/{path}', timeout=2).read().decode())")
    value = fz.run(["docker", "exec", container, "python3", "-c", command],
                   timeout=10, check=False)
    if value.returncode:
        raise RuntimeError(value.stdout[-1000:])
    return json.loads(value.stdout)


class ConnectionSampler:
    def __init__(self, container, path):
        self.container, self.path = container, path
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.sample, daemon=True)

    def sample(self):
        with self.path.open("w", encoding="utf-8") as stream:
            while not self.stop.is_set():
                sample = {"at": fz.now()}
                try:
                    sample["connections"] = controller(self.container, "connections")
                except Exception as error:
                    sample["error"] = str(error)
                stream.write(json.dumps(sample) + "\n")
                stream.flush()
                self.stop.wait(0.5)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(timeout=15)
        if self.thread.is_alive():
            raise RuntimeError("Mihomo controller sampler did not finish")


def traffic(state):
    try:
        return json.loads((state / "stats.json").read_text())["acp"]["traffic"]
    except (OSError, ValueError, KeyError, TypeError):
        return {}


def traffic_delta(before, after):
    return {user: {key: after.get(user, {}).get(key, 0) - before.get(user, {}).get(key, 0)
                   for key in ("uplink_bytes", "downlink_bytes", "reports")}
            for user in ("alice", "bob")}


def impose_loss(daemon, enabled):
    # The fresh fixture owns this network namespace. Only UDP to the HY2 port
    # is impaired; GUI, FTPS TCP and controller traffic use the unaffected band.
    commands = [
        ["tc", "qdisc", "add", "dev", "lo", "root", "handle", "1:", "prio",
         "bands", "3", "priomap", *(["0"] * 16)],
        ["tc", "qdisc", "add", "dev", "lo", "parent", "1:3", "handle", "30:",
         "netem", "delay", "10ms", "loss", "0.5%"],
        ["tc", "filter", "add", "dev", "lo", "protocol", "ip", "parent", "1:",
         "prio", "1", "u32", "match", "ip", "protocol", "17", "0xff",
         "match", "ip", "dport", "18443", "0xffff", "flowid", "1:3"],
    ] if enabled else [["tc", "qdisc", "del", "dev", "lo", "root"]]
    for command in commands:
        fz.run(["docker", "exec", daemon, *command])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mihomo", type=Path, required=True, help="Official Linux amd64 executable")
    parser.add_argument("--expected-binary-sha256", required=True, help="Expected node-agent release SHA256")
    parser.add_argument("--target-volume", default="node-agent-hy2-docker-target")
    parser.add_argument("--image", default="node-agent-filezilla-test:20260917")
    parser.add_argument("--proxy", default="http://host.docker.internal:10886")
    parser.add_argument("--skip-image-build", action="store_true")
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--modes", default="single,nested", help="Comma-separated single,nested modes")
    parser.add_argument("--read-limit", type=int, default=2 * 1024 * 1024,
                        help="FTPS bytes/second per data connection; 0 disables throttling")
    parser.add_argument("--with-impairment", action="store_true",
                        help="Add 5 large nested uploads with HY2 UDP-only delay/loss")
    options = parser.parse_args()
    modes = options.modes.split(",")
    if not modes or len(set(modes)) != len(modes) or any(mode not in ("single", "nested") for mode in modes):
        parser.error("--modes must contain single and/or nested without duplicates")
    if options.read_limit < 0:
        parser.error("--read-limit must be nonnegative")
    if options.with_impairment and "nested" not in modes:
        parser.error("--with-impairment requires nested mode")
    mihomo = options.mihomo.resolve(strict=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    output = (options.run_dir or REPO / "run" / f"hy2-double-proxy-{stamp}").resolve()
    if output.exists() and any(output.iterdir()):
        raise RuntimeError("run directory is not empty")
    output.mkdir(parents=True, exist_ok=True)
    state, sources, home = output / "state", output / "sources", output / "home"
    state.mkdir()
    sources.mkdir()
    (home / ".config" / "filezilla").mkdir(parents=True)
    shutil.copy2(fz.HERE / "filezilla.xml", home / ".config" / "filezilla" / "filezilla.xml")
    shutil.copy2(mihomo, output / "mihomo-linux")
    daemon = f"node-agent-double-{stamp}"
    label = "io.node-agent.test=hy2-double-proxy"
    created, completed, mode_results = [], [], []
    result = {"success": False, "started_at": fz.now(), "stages": completed,
              "topology_checks": mode_results}
    evidence = {"started_at": fz.now(), "workspace_commit_at_run": fz.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO).stdout.strip(),
        "workspace_changes_at_run": fz.run(["git", "status", "--porcelain"], cwd=REPO).stdout.splitlines(),
        "mihomo_source_path": str(mihomo), "mihomo_sha256": fz.sha(mihomo),
        "target_volume": options.target_volume, "image": options.image,
        "expected_binary_sha256": options.expected_binary_sha256,
        "binary_provenance": "Preexisting release from named Docker volume; workspace commit is not evidence of binary build commit",
        "modes": modes, "ftps_read_limit": options.read_limit,
        "scope": "Real Linux FileZilla; one Mihomo HY2 and hypothetical nested Mihomo HY2, not a full OpenClash/v2rayN reproduction",
        "outer_user": "bob", "inner_user": "alice"}
    failed = None
    try:
        fz.save(output / "run.json", evidence)
        if fz.run(["docker", "info", "--format", "{{.OSType}}"] ).stdout.strip() != "linux":
            raise RuntimeError("Docker must use Linux containers")
        if not options.skip_image_build:
            fz.run(["docker", "build", "--build-arg", f"BUILD_PROXY={options.proxy}", "-t", options.image,
                    "-f", HERE / "Dockerfile", HERE],
                   log=output / "image-build.log", timeout=900)
        evidence["image_id"] = fz.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", options.image]).stdout.strip()
        small, large = output / "small.ts", output / "large.ts"
        fz.generate_ts(small, seconds=4, resolution="640x360", bitrate="3M")
        fz.generate_ts(large, seconds=32, resolution="1280x720", bitrate="8M")
        stages = [fz.make_stage(sources, "direct-control", small, 2, 1, False)]
        for mode in modes:
            stages.extend([fz.make_stage(sources, f"{mode}-small", small, 10, 10, True),
                           fz.make_stage(sources, f"{mode}-large", large, 10, 10, True)])
        if options.with_impairment:
            stages.append(fz.make_stage(sources, "nested-impaired", large, 5, 10, True))
        fz.save(output / "files.json", {path.name: {"bytes": path.stat().st_size, "sha256": fz.sha(path)}
                                       for path in (small, large, output / "mihomo-linux")})
        print("Starting isolated node-agent, FTPS and FileZilla", flush=True)
        fz.docker_run(created, daemon, label,
                      ["--cpus", "4", "--memory", "2g", "--cap-add", "NET_ADMIN",
                       "--mount", f"type=volume,source={options.target_volume},target=/build,readonly",
                       "--mount", f"type=bind,source={state},target=/fixture",
                       "--mount", f"type=bind,source={fz.HY2_HARNESS},target=/harness,readonly"],
                      options.image, ["bash", "/harness/start.sh"])
        fz.wait_until("node-agent configuration", lambda: fz.read_ready(state), timeout=120)
        binary_sha = fz.run(["docker", "exec", daemon, "sha256sum", "/build/release/node-agent"]).stdout.split()[0]
        evidence["node_agent_binary_sha256"] = binary_sha
        if binary_sha.lower() != options.expected_binary_sha256.lower():
            raise RuntimeError("node-agent binary differs from --expected-binary-sha256")
        fz.snapshot(output, daemon, "before.json")
        # Per data connection; long enough to observe concurrent transfers and transport state.
        fz.start_ftp(created, daemon, label, output, state, options.image, "normal", rate=options.read_limit)
        gui = f"{daemon}-gui"
        fz.docker_run(created, gui, label,
                      ["--network", f"container:{daemon}",
                       "--mount", f"type=bind,source={output},target=/evidence",
                       "--env", "HOME=/evidence/home", "--env", "DISPLAY=:99"],
                      options.image, ["bash", "-lc", "Xvfb :99 -screen 0 1280x800x24 >/evidence/xvfb.log 2>&1 & "
                                      "sleep 1; openbox >/evidence/openbox.log 2>&1 & exec sleep infinity"])
        fz.wait_until("Xvfb", lambda: fz.run(["docker", "exec", "-e", "DISPLAY=:99", gui,
                                             "xdotool", "getdisplaygeometry"], check=False).returncode == 0)
        version_output = fz.run(
            ["docker", "exec", "-e", "DISPLAY=:99", gui, "filezilla", "--version"], check=False).stdout
        versions = [line for line in version_output.splitlines() if line.startswith("FileZilla ")]
        if not versions:
            raise RuntimeError(f"unable to read FileZilla version: {version_output[-1000:]}")
        evidence["filezilla_version"] = versions[-1]
        completed.append(fz.run_stage(output, state, home, gui, stages[0], accept_certificate=True))

        for mode in modes:
            config = output / f"mihomo-{mode}.json"
            fz.save(config, mihomo_config(mode == "nested"))
            client = f"{daemon}-{mode}"
            fz.docker_run(created, client, label,
                          ["--network", f"container:{daemon}",
                           "--mount", f"type=bind,source={output},target=/evidence,readonly"],
                          options.image, ["bash", "-lc", "cp /evidence/mihomo-linux /tmp/mihomo; chmod +x /tmp/mihomo; "
                                          f"/tmp/mihomo -v; exec /tmp/mihomo -d /tmp/mihomo-config -f /evidence/{config.name}"])
            def ready():
                try:
                    return controller(client, "version")
                except Exception:
                    return False
            evidence["mihomo_version"] = fz.wait_until("Mihomo controller", ready, timeout=30)
            fz.save(output / f"mihomo-{mode}-proxies.json", controller(client, "proxies"))
            before = traffic(state)
            with ConnectionSampler(client, output / f"mihomo-{mode}-connections.jsonl"):
                for stage in [item for item in stages if item["name"].startswith(f"{mode}-")]:
                    impaired = stage["name"].endswith("impaired")
                    print(f"{stage['name']}: {stage['count']} uploads, transfer limit 10", flush=True)
                    try:
                        if impaired:
                            impose_loss(daemon, True)
                        completed.append(fz.run_stage(output, state, home, gui, stage, accept_certificate=False))
                    finally:
                        if impaired:
                            fz.run(["docker", "exec", daemon, "tc", "-s", "qdisc", "show", "dev", "lo"],
                                   log=output / "impaired-qdisc.txt", check=False)
                            impose_loss(daemon, False)
            fz.stop_owned(client, label)
            expected_bytes = sum(item["bytes"] for stage in completed
                                 if stage["name"].startswith(f"{mode}-") for item in stage["files"])
            def reported():
                delta = traffic_delta(before, traffic(state))
                return (delta["alice"]["uplink_bytes"] >= expected_bytes and
                        (mode != "nested" or delta["bob"]["uplink_bytes"] >= expected_bytes))
            fz.wait_until(f"{mode} HY2 per-user traffic evidence", reported, timeout=45, interval=1)
            fz.wait_until("closed HY2 connections to settle", lambda: fz.connections_are_zero(daemon), timeout=45, interval=1)
            delta = traffic_delta(before, traffic(state))
            if mode == "single" and delta["bob"]["uplink_bytes"] != 0:
                raise RuntimeError("single-layer test unexpectedly used the outer HY2 user")
            mode_results.append({"mode": mode, "uploaded_bytes": expected_bytes, "traffic_delta": delta,
                                 "verified": True, "proof": "inner=alice; only outer uses bob; nested requires both users' upload counters >= uploaded bytes"})
            fz.snapshot(output, daemon, f"after-{mode}.json")
            fz.save(output / "run.json", evidence)
            fz.save(output / "stages.json", completed)

        events = fz.load_jsonl(state / "ftp-events.jsonl")
        received = [item for item in events if item.get("event") == "received"]
        incomplete = [item for item in events if item.get("event") == "incomplete"]
        expected = Counter((item["remote_name"], item["bytes"], item["sha256"])
                           for stage in completed for item in stage["files"])
        actual = Counter((Path(item["path"]).name, item["bytes"], item["sha256"]) for item in received)
        if incomplete or actual != expected:
            raise RuntimeError("FTPS completion records differ from uploaded files")
        debug = (output / "filezilla-debug.log").read_text(encoding="utf-8", errors="replace")
        success_count = sum("Status: File transfer successful" in line for line in debug.splitlines())
        if success_count != len(received):
            raise RuntimeError(f"FileZilla reported {success_count} successes for {len(received)} uploads")
        result.update(success=True, uploads=len(received), server_sha256_checks=len(received),
                      incomplete_uploads=0, uploaded_bytes=sum(item["bytes"] for item in received),
                      node_agent_binary_sha256=binary_sha, mihomo_sha256=evidence["mihomo_sha256"])
    except Exception as error:
        failed = error
        result["error"] = str(error)
    finally:
        result["finished_at"] = fz.now()
        fz.save(output / "result.json", result)
        fz.save(output / "run.json", evidence)
        fz.save(output / "stages.json", completed)
        for container in reversed(created):
            try:
                fz.run(["docker", "logs", "--timestamps", container],
                       log=output / f"{container}.log", check=False)
                fz.run(["docker", "inspect", container],
                       log=output / f"{container}.inspect.json", check=False)
                fz.stop_owned(container, label)
            except Exception as error:
                print(f"Cleanup {container}: {error}", flush=True)
        print(f"Evidence: {output}", flush=True)
    if failed:
        raise failed


if __name__ == "__main__":
    main()
