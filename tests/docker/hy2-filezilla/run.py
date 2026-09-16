#!/usr/bin/env python3
"""Drive the real Linux FileZilla GUI through FTPS over node-agent Hysteria2."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET


REPO = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
FTP_HARNESS = REPO / "tests" / "docker" / "hy2-ftp"
HY2_HARNESS = REPO / "tests" / "docker" / "hy2"
GO_MODULE = REPO / "tests" / "interop" / "sing-quic-switch"


def now():
    return datetime.now(timezone.utc).isoformat()


def run(args, *, log=None, timeout=120, env=None, cwd=None, check=True):
    result = subprocess.run([str(value) for value in args], cwd=cwd, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace", timeout=timeout)
    if log:
        Path(log).write_text(result.stdout, encoding="utf-8")
    if check and result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {result.stdout[-4000:]}")
    return result


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def sha(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def wait_until(description, predicate, timeout=60, interval=0.25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise RuntimeError(f"timed out waiting for {description}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--image", default="node-agent-filezilla-test:20260916")
    parser.add_argument("--base-image", default="node-agent-ftp-test:20260916")
    parser.add_argument("--proxy", default="http://host.docker.internal:10886")
    parser.add_argument("--target-volume", default="node-agent-hy2-docker-target")
    parser.add_argument("--skip-image-build", action="store_true")
    parser.add_argument("--expected-binary-sha256")
    options = parser.parse_args()

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    output = (options.run_dir or REPO / "run" / f"hy2-filezilla-{stamp}").resolve()
    if output.exists() and any(output.iterdir()):
        raise RuntimeError("run directory is not empty")
    output.mkdir(parents=True, exist_ok=True)
    state = output / "state"
    sources = output / "sources"
    home = output / "home"
    (home / ".config" / "filezilla").mkdir(parents=True)
    state.mkdir()
    sources.mkdir()
    shutil.copy2(HERE / "filezilla.xml", home / ".config" / "filezilla" / "filezilla.xml")

    daemon = f"node-agent-fz-{stamp}"
    label = "io.node-agent.test=hy2-filezilla"
    created = []
    failed = None
    ftp = None

    evidence = {
        "started_at": now(),
        "node_commit": run(["git", "rev-parse", "HEAD"], cwd=REPO).stdout.strip(),
        "node_worktree": run(["git", "status", "--porcelain"], cwd=REPO).stdout.splitlines(),
        "image": options.image,
        "target_volume": options.target_volume,
        "expected_binary_sha256": options.expected_binary_sha256,
        "topology": "FileZilla -> loopback SOCKS5 -> sing-quic HY2 -> node-agent -> loopback FTPS",
    }
    save(output / "run.json", evidence)

    try:
        if run(["docker", "info", "--format", "{{.OSType}}"]).stdout.strip() != "linux":
            raise RuntimeError("Docker must use Linux containers")
        if not options.skip_image_build:
            print("Building FileZilla image", flush=True)
            run(["docker", "build", "--build-arg", f"BASE_IMAGE={options.base_image}",
                 "--build-arg", f"BUILD_PROXY={options.proxy}", "-t", options.image,
                 "-f", HERE / "Dockerfile", HERE], log=output / "image-build.log", timeout=900)
        evidence["image_id"] = run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", options.image]
        ).stdout.strip()

        helper = output / "hy2-socks-linux"
        go_env = dict(os.environ, GOOS="linux", GOARCH="amd64", CGO_ENABLED="0")
        run(["go", "test", "./cmd/hy2-socks"], cwd=GO_MODULE,
            log=output / "hy2-socks-test.log", timeout=300)
        run(["go", "build", "-trimpath", "-o", helper, "./cmd/hy2-socks"],
            cwd=GO_MODULE, env=go_env, timeout=300)

        small = output / "small.ts"
        large = output / "large.ts"
        generate_ts(small, seconds=4, resolution="640x360", bitrate="3M")
        generate_ts(large, seconds=32, resolution="1280x720", bitrate="8M")
        stages = [
            make_stage(sources, "direct-control", small, 2, 1, False),
            make_stage(sources, "hy2-sequential", small, 10, 1, True),
            make_stage(sources, "hy2-parallel", small, 12, 4, True),
            make_stage(sources, "hy2-large-parallel", large, 4, 4, True),
            make_stage(sources, "hy2-slow-target", large, 2, 2, True),
        ]
        save(output / "files.json", {
            path.name: {"bytes": path.stat().st_size, "sha256": sha(path)}
            for path in [helper, small, large]
        })

        print("Starting node-agent, FTPS, HY2 SOCKS adapter and Xvfb", flush=True)
        docker_run(created, daemon, label,
                   ["--cpus", "4", "--memory", "2g", "--cap-add", "NET_ADMIN",
                    "--mount", f"type=volume,source={options.target_volume},target=/build,readonly",
                    "--mount", f"type=bind,source={state},target=/fixture",
                    "--mount", f"type=bind,source={HY2_HARNESS},target=/harness,readonly"],
                   options.image, ["bash", "/harness/start.sh"])
        wait_until("node-agent configuration", lambda: read_ready(state), timeout=120)
        binary_line = run(["docker", "exec", daemon, "sha256sum", "/build/release/node-agent"]).stdout.strip()
        binary_sha = binary_line.split()[0]
        evidence["node_agent_binary_sha256"] = binary_sha
        if options.expected_binary_sha256 and binary_sha.lower() != options.expected_binary_sha256.lower():
            raise RuntimeError(f"node-agent SHA256 {binary_sha} differs from expected value")
        snapshot(output, daemon, "before.json")

        ftp = start_ftp(created, daemon, label, output, state, options.image, "normal", rate=0)
        socks = f"{daemon}-socks"
        docker_run(created, socks, label,
                   ["--network", f"container:{daemon}",
                    "--mount", f"type=bind,source={helper},target=/source/hy2-socks,readonly"],
                   options.image,
                   ["bash", "-lc", "cp /source/hy2-socks /tmp/hy2-socks; chmod +x /tmp/hy2-socks; exec /tmp/hy2-socks"])
        wait_until("SOCKS adapter", lambda: "\"event\":\"ready\"" in docker_logs(socks), timeout=30)

        gui = f"{daemon}-gui"
        docker_run(created, gui, label,
                   ["--network", f"container:{daemon}",
                    "--mount", f"type=bind,source={output},target=/evidence",
                    "--env", "HOME=/evidence/home", "--env", "DISPLAY=:99"],
                   options.image,
                   ["bash", "-lc", "Xvfb :99 -screen 0 1280x800x24 >/evidence/xvfb.log 2>&1 & "
                    "sleep 1; openbox >/evidence/openbox.log 2>&1 & exec sleep infinity"])
        wait_until("Xvfb", lambda: run(["docker", "exec", "-e", "DISPLAY=:99", gui,
                                         "xdotool", "getdisplaygeometry"], check=False).returncode == 0,
                   timeout=30)
        version_output = run(
            ["docker", "exec", "-e", "DISPLAY=:99", gui, "filezilla", "--version"],
            check=False,
        ).stdout
        versions = [line for line in version_output.splitlines() if line.startswith("FileZilla ")]
        if not versions:
            raise RuntimeError(f"unable to read FileZilla version: {version_output[-1000:]}")
        evidence["filezilla_version"] = versions[-1]
        save(output / "run.json", evidence)

        completed = []
        for index, stage in enumerate(stages):
            if stage["name"] == "hy2-slow-target":
                stop_owned(ftp, label)
                ftp = start_ftp(created, daemon, label, output, state, options.image,
                                "slow", rate=2 * 1024 * 1024)
            print(f"{stage['name']}: {stage['count']} files, transfer limit {stage['transfers']}", flush=True)
            completed.append(run_stage(output, state, home, gui, stage,
                                       accept_certificate=index == 0))

        print("Waiting for traffic and connection telemetry to settle", flush=True)
        for _ in range(22):
            time.sleep(1)
        snapshot(output, daemon, "after-settle.json")

        stop_owned(socks, label)
        wait_until("closed HY2 client to disappear from telemetry",
                   lambda: connections_are_zero(daemon), timeout=30, interval=1)
        snapshot(output, daemon, "after-client-close.json")

        events = load_jsonl(state / "ftp-events.jsonl")
        received = [item for item in events if item.get("event") == "received"]
        incomplete = [item for item in events if item.get("event") == "incomplete"]
        expected = Counter((item["remote_name"], item["bytes"], item["sha256"])
                           for stage in completed for item in stage["files"])
        actual = Counter((Path(item["path"]).name, item["bytes"], item["sha256"])
                         for item in received)
        if incomplete or actual != expected:
            raise RuntimeError("FTPS server completion evidence differs from source files")

        filezilla_log = (output / "filezilla-debug.log").read_text(encoding="utf-8", errors="replace")
        success_lines = [line for line in filezilla_log.splitlines()
                         if "Status: File transfer successful" in line]
        if len(success_lines) != sum(stage["count"] for stage in stages):
            raise RuntimeError(f"FileZilla reported {len(success_lines)} successful transfers")

        socks_events = [json.loads(line) for line in docker_logs(socks).splitlines()
                        if line.startswith("{")]
        data_closes = [item for item in socks_events if item.get("event") == "closed" and
                       30000 <= int(item.get("target", "0:0").rsplit(":", 1)[-1]) <= 30100]
        if any(item.get("error") for item in data_closes):
            raise RuntimeError("SOCKS adapter reported an error on an FTP data stream")
        expected_hy2 = sum(stage["count"] for stage in stages if stage["hy2"])
        if len([item for item in data_closes if item.get("upload_bytes", 0) > 100000]) < expected_hy2:
            raise RuntimeError("not every HY2 upload has a completed SOCKS data stream")

        save(output / "stages.json", completed)
        save(output / "result.json", {
            "success": True, "finished_at": now(), "filezilla_version": evidence["filezilla_version"],
            "uploads": sum(stage["count"] for stage in stages), "hy2_uploads": expected_hy2,
            "uploaded_bytes": sum(item["bytes"] for stage in completed for item in stage["files"]),
            "server_sha256_checks": len(received), "incomplete_uploads": 0,
            "hy2_data_streams": len(data_closes), "hy2_data_stream_errors": 0,
            "node_agent_binary_sha256": binary_sha,
        })
    except Exception as error:
        failed = error
        save(output / "result.json", {"success": False, "finished_at": now(), "error": str(error)})
    finally:
        for container in reversed(created):
            run(["docker", "logs", "--timestamps", container],
                log=output / f"{container}.log", check=False)
            run(["docker", "inspect", container],
                log=output / f"{container}.inspect.json", check=False)
            stop_owned(container, label)
        print(f"Evidence: {output}", flush=True)
    if failed:
        raise failed


def generate_ts(path, *, seconds, resolution, bitrate):
    run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-f", "lavfi", "-i",
         f"testsrc2=size={resolution}:rate=25", "-f", "lavfi", "-i",
         "sine=frequency=997:sample_rate=48000", "-t", str(seconds), "-c:v", "libx264",
         "-preset", "veryfast", "-b:v", bitrate, "-g", "50", "-sc_threshold", "0",
         "-c:a", "aac", "-b:a", "128k", "-f", "mpegts", path], timeout=300)
    run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-xerror", "-i", path,
         "-f", "null", "-"], log=path.with_suffix(".decode.log"), timeout=300)


def make_stage(root, name, source, count, transfers, hy2):
    directory = root / name
    directory.mkdir()
    files = []
    for number in range(1, count + 1):
        target = directory / f"{name}-{number:03d}.ts"
        shutil.copy2(source, target)
        files.append({"remote_name": target.name, "bytes": target.stat().st_size, "sha256": sha(target)})
    return {"name": name, "directory": directory, "count": count,
            "transfers": transfers, "hy2": hy2, "files": files}


def docker_run(created, name, label, options, image, command):
    run(["docker", "run", "-d", "--name", name, "--label", label, *options, image, *command])
    created.append(name)


def read_ready(state):
    try:
        return json.loads((state / "ready.json").read_text()).get("agent_ready") is True
    except (OSError, ValueError):
        return False


def docker_logs(container):
    return run(["docker", "logs", container], check=False).stdout


def start_ftp(created, daemon, label, output, state, image, suffix, rate):
    name = f"{daemon}-ftp-{suffix}"
    docker_run(created, name, label,
               ["--network", f"container:{daemon}",
                "--mount", f"type=bind,source={output},target=/evidence",
                "--mount", f"type=bind,source={state},target=/fixture",
                "--mount", f"type=bind,source={FTP_HARNESS},target=/ftp-harness,readonly"],
               image, ["python3", "/ftp-harness/ftp_server.py", "--root", "/fixture/ftp",
                       "--events", "/fixture/ftp-events.jsonl", "--certfile", "/fixture/ftp.pem",
                       "--read-limit", str(rate), "--ftps"])
    wait_until("FTPS server", lambda: run(
        ["docker", "exec", daemon, "python3", "-c",
         "import socket; socket.create_connection(('127.0.0.1',2121),1).close()"],
        check=False).returncode == 0, timeout=30)
    return name


def set_filezilla_config(home, *, proxy, transfers):
    path = home / ".config" / "filezilla" / "filezilla.xml"
    tree = ET.parse(path)
    values = {
        "Proxy type": "2" if proxy else "0",
        "Proxy host": "127.0.0.1" if proxy else "",
        "Proxy port": "1080" if proxy else "0",
        "Number of Transfers": str(transfers),
        "Window position and size": "0 40 25 1198 636 ",
    }
    for setting in tree.getroot().find("Settings"):
        if setting.attrib.get("name") in values:
            setting.text = values[setting.attrib["name"]]
    tree.write(path, encoding="UTF-8", xml_declaration=True)


def run_stage(output, state, home, gui, stage, *, accept_certificate):
    set_filezilla_config(home, proxy=stage["hy2"], transfers=stage["transfers"])
    debug = output / "filezilla-debug.log"
    marker = debug.stat().st_size if debug.exists() else 0
    received_before = len([item for item in load_jsonl(state / "ftp-events.jsonl")
                           if item.get("event") == "received"])
    local_path = f"/evidence/sources/{stage['name']}"
    url = "ftpes://fixture:fixture@127.0.0.1:2121/"
    run(["docker", "exec", "-d", "-e", "HOME=/evidence/home", "-e", "DISPLAY=:99", gui,
         "bash", "-lc", f"exec dbus-run-session -- filezilla -a {local_path} {url} >>/evidence/filezilla.log 2>&1"])
    wait_until("FileZilla process", lambda: run(
        ["docker", "exec", gui, "pgrep", "-x", "filezilla"], check=False).returncode == 0)

    def new_debug():
        if not debug.exists():
            return ""
        with debug.open("rb") as stream:
            stream.seek(marker)
            return stream.read().decode("utf-8", errors="replace")

    wait_until("FileZilla TLS handshake", lambda: "Status: Initializing TLS" in new_debug(), timeout=60)
    if accept_certificate:
        run(["docker", "exec", "-e", "DISPLAY=:99", gui, "scrot",
             f"/evidence/{stage['name']}-certificate.png"])
        command = (
            "w=$(xdotool getactivewindow); "
            "test \"$(xdotool getwindowname $w)\" = \"Unknown certificate\"; "
            "xdotool mousemove 380 644 click 1; "
            "xdotool mousemove 896 706 click 1"
        )
        run(["docker", "exec", "-e", "DISPLAY=:99", gui, "bash", "-lc", command])
    wait_until("FileZilla remote listing",
               lambda: 'Status: Directory listing of "/" successful' in new_debug(), timeout=90)
    run(["docker", "exec", "-e", "DISPLAY=:99", gui, "scrot",
         f"/evidence/{stage['name']}-connected.png"])

    command = (
        "w=$(xdotool getactivewindow); "
        "xdotool windowmove $w 40 25 windowsize $w 1198 725; sleep 1; "
        "xdotool mousemove 150 376 click 1 key --clearmodifiers ctrl+a click 3; sleep 0.5; "
        "xdotool mousemove 220 392 click 1"
    )
    run(["docker", "exec", "-e", "DISPLAY=:99", gui, "bash", "-lc", command])
    expected_total = received_before + stage["count"]
    wait_until(f"{stage['name']} uploads", lambda: len([
        item for item in load_jsonl(state / "ftp-events.jsonl") if item.get("event") == "received"
    ]) >= expected_total, timeout=300, interval=0.3)
    run(["docker", "exec", "-e", "DISPLAY=:99", gui, "scrot",
         f"/evidence/{stage['name']}-complete.png"])

    events = load_jsonl(state / "ftp-events.jsonl")
    received = {Path(item["path"]).name: item for item in events if item.get("event") == "received"}
    for expected in stage["files"]:
        actual = received.get(expected["remote_name"])
        if not actual or actual["bytes"] != expected["bytes"] or actual["sha256"] != expected["sha256"]:
            raise RuntimeError(f"{stage['name']}: target differs: {expected['remote_name']}")
    representatives = list((state / "ftp").rglob(stage["files"][0]["remote_name"]))
    if len(representatives) != 1:
        raise RuntimeError(f"{stage['name']}: expected one retained representative, found {len(representatives)}")
    representative = representatives[0]
    run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-xerror", "-i", representative,
         "-f", "null", "-"], log=output / f"{stage['name']}.decode.log", timeout=300)

    run(["docker", "exec", "-e", "DISPLAY=:99", gui, "bash", "-lc",
         "w=$(xdotool getactivewindow); xdotool windowactivate $w key --clearmodifiers ctrl+q"])
    wait_until("FileZilla exit", lambda: run(
        ["docker", "exec", gui, "pgrep", "-x", "filezilla"], check=False).returncode != 0,
        timeout=30)
    return {key: value for key, value in stage.items() if key != "directory"}


def load_jsonl(path):
    try:
        return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line]
    except FileNotFoundError:
        return []


def snapshot(output, daemon, name):
    result = run(["docker", "exec", daemon, "python3", "/harness/observe.py",
                  "--state-dir", "/fixture"])
    (output / name).write_text(result.stdout, encoding="utf-8")
    value = json.loads(result.stdout)
    if not value["agent"]["running"] or not value["fixture"]["running"]:
        raise RuntimeError(f"unhealthy daemon snapshot: {name}")


def connections_are_zero(daemon):
    result = run(["docker", "exec", daemon, "python3", "/harness/observe.py",
                  "--state-dir", "/fixture"], check=False)
    if result.returncode:
        return False
    try:
        stats = json.loads(result.stdout)["stats"]["acp"]
        return stats["agent_active_connections"] == 0 and stats["agent_online_users"] == 0
    except (KeyError, TypeError, ValueError):
        return False


def stop_owned(container, label):
    owned = run(["docker", "inspect", "--format", '{{index .Config.Labels "io.node-agent.test"}}',
                 container], check=False).stdout.strip()
    if owned == label.split("=", 1)[1]:
        run(["docker", "stop", "--timeout", "10", container], check=False)


if __name__ == "__main__":
    main()
