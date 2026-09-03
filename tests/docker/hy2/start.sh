#!/usr/bin/env bash
set -euo pipefail

state_dir=/fixture
fixture_pid=
agent_pid=
log_pid=

stop_children() {
    trap - EXIT INT TERM
    for pid in "$agent_pid" "$fixture_pid" "$log_pid"; do
        if [[ -n "$pid" ]]; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
}
trap stop_children EXIT
# A requested container stop is successful; the EXIT handler still shuts down
# both children. Unexpected child exits retain the failure path below.
trap 'exit 0' INT TERM

mkdir -p "$state_dir"
/build/release/examples/hy2_container_fixture \
    --state-dir "$state_dir" \
    --panel 127.0.0.1:19090 \
    --target 127.0.0.1:19091 \
    --hy2-port 18443 > "$state_dir/fixture.log" 2>&1 &
fixture_pid=$!
printf '%s\n' "$fixture_pid" > "$state_dir/fixture.pid"

fixture_listening() {
    python3 - "$state_dir/ready.json" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as ready_file:
        ready = json.load(ready_file)
    sys.exit(0 if ready.get("fixture_listening") is True else 1)
except (OSError, ValueError, AttributeError):
    sys.exit(1)
PY
}

fixture_ready=false
ready_deadline=$((SECONDS + 60))
while ((SECONDS < ready_deadline)); do
    if ! kill -0 "$fixture_pid" 2>/dev/null; then
        cat "$state_dir/fixture.log" >&2
        exit 1
    fi
    if [[ -s "$state_dir/agent.toml" ]] && fixture_listening; then
        fixture_ready=true
        break
    fi
    sleep 0.2
done
if [[ "$fixture_ready" != true ]]; then
    printf 'Fixture did not become ready with agent.toml within 60 seconds\n' >&2
    exit 1
fi

# The daemon writes its own agent.log; keep console output in a separate file.
/build/release/node-agent "$state_dir/agent.toml" > "$state_dir/agent-console.log" 2>&1 &
agent_pid=$!
printf '%s\n' "$agent_pid" > "$state_dir/agent.pid"
tail -n +1 -F "$state_dir/fixture.log" "$state_dir/agent-console.log" &
log_pid=$!

# Either process exiting ends the container, so a surviving fixture cannot hide
# a failed daemon. The trap gives both processes a chance to flush their output.
set +e
wait -n "$fixture_pid" "$agent_pid"
status=$?
set -e
printf 'A test process exited (status=%s)\n' "$status" >&2
exit 1
