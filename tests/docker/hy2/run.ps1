#requires -Version 7.0
[CmdletBinding()]
param(
    [string] $BuildImage = 'shoes-linux-test:latest',
    [string] $TargetVolume = 'node-agent-hy2-docker-target',
    [string] $RegistryVolume = 'shoes-r-cargo-registry',
    [string] $CorePath,
    [string] $GoClient,
    [string] $RunDirectory,
    [string] $BuildProxy,
    [ValidateSet('transfer', 'concurrency', 'cancel')] [string] $Suite = 'transfer',
    [switch] $Offline,
    [switch] $SkipBuild,
    [ValidateRange(1, 65535)] [int] $HostPort = 18443,
    [ValidateRange(1, 64)] [int] $BuildCpus = 8,
    [string] $BuildMemory = '12g',
    [ValidateRange(1, 64)] [int] $RuntimeCpus = 4,
    [string] $RuntimeMemory = '2g',
    [ValidateRange(1, 60)] [int] $ObserveIntervalSeconds = 2,
    [ValidateRange(1, 600)] [int] $IdleSeconds = 30,
    [ValidateRange(0, 60)] [int] $FinalReportWaitSeconds = 12,
    [switch] $StopAfter
)

$ErrorActionPreference = 'Stop'
$repoPath = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
if (-not $CorePath) { $CorePath = Join-Path (Split-Path $repoPath) 'shoes-plus' }
$CorePath = (Resolve-Path -LiteralPath $CorePath).Path
$docker = (Get-Command docker -ErrorAction Stop).Source
$runId = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$containerName = "node-agent-hy2-$runId"
$buildName = "$containerName-build"
$label = 'io.node-agent.test=hy2-docker'
$observer = $null
$runtimeCreated = $false
$failed = $null

function Invoke-Docker {
    param([string[]] $Arguments)
    $output = & $docker @Arguments
    if ($LASTEXITCODE -ne 0) { throw "docker $($Arguments[0]) failed ($LASTEXITCODE)" }
    return $output
}

function Write-Json {
    param([string] $Path, [object] $Value)
    $Value | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $Path -Encoding utf8
}

function Save-ContainerArtifacts {
    if (-not $runtimeCreated) { return }
    & $docker inspect $containerName 2>&1 | Set-Content -LiteralPath (Join-Path $RunDirectory 'container-inspect.json')
    & $docker logs --timestamps $containerName 2>&1 | Set-Content -LiteralPath (Join-Path $RunDirectory 'container.log')
    & $docker top $containerName -eo pid,ppid,stat,pcpu,pmem,rss,args 2>&1 | Set-Content -LiteralPath (Join-Path $RunDirectory 'processes.txt')
}

function Assert-ContainerRunning {
    $running = Invoke-Docker @('inspect', '--format', '{{.State.Running}}', $containerName)
    if ($running -ne 'true') { throw "Test container exited; inspect $RunDirectory" }
}

function Run-ClientStage {
    param([string] $Name, [string[]] $Options)
    Assert-ContainerRunning
    $clientArgs = @("127.0.0.1:$HostPort", '127.0.0.1:19091', 'fixture-alice') + $Options + @(
        '--probe-password', 'fixture-bob', '--probe-interval', '500ms', '--probe-timeout', '5s'
    )
    $start = [DateTimeOffset]::UtcNow
    Write-Host "$Name started ($start)"
    & $GoClient @clientArgs 2>&1 | Tee-Object -FilePath (Join-Path $RunDirectory "$Name.log")
    $exitCode = $LASTEXITCODE
    [ordered]@{ name = $Name; started_at = $start; ended_at = [DateTimeOffset]::UtcNow; exit_code = $exitCode; arguments = $clientArgs } |
        ConvertTo-Json -Compress | Add-Content -LiteralPath (Join-Path $RunDirectory 'stages.jsonl') -Encoding utf8
    if ($exitCode -ne 0) { throw "$Name failed with exit code $exitCode" }
    Assert-ContainerRunning
}

if ((Invoke-Docker @('info', '--format', '{{.OSType}}')) -ne 'linux') {
    throw 'Select Linux containers in Docker Desktop before running this script.'
}
# Never pull an unknown image or install tools into an existing image implicitly.
$imageId = Invoke-Docker @('image', 'inspect', '--format', '{{.Id}}', $BuildImage)
if (-not $RunDirectory) { $RunDirectory = Join-Path $repoPath "run/hy2-docker-$runId" }
if (Test-Path -LiteralPath $RunDirectory) { throw "RunDirectory already exists: $RunDirectory" }
$RunDirectory = (New-Item -ItemType Directory -Path $RunDirectory).FullName
$statePath = (New-Item -ItemType Directory -Path (Join-Path $RunDirectory 'state')).FullName
$stopFile = Join-Path $RunDirectory 'observer.stop'

Write-Json (Join-Path $RunDirectory 'run.json') ([ordered]@{
    started_at = [DateTimeOffset]::UtcNow
    repository = $repoPath; core_repository = $CorePath
    node_commit = (& git -C $repoPath rev-parse HEAD); core_commit = (& git -C $CorePath rev-parse HEAD)
    node_worktree = @(& git -C $repoPath status --porcelain=v1); core_worktree = @(& git -C $CorePath status --porcelain=v1)
    build_image = $BuildImage; image_id = $imageId; target_volume = $TargetVolume
    registry_volume = $RegistryVolume; container = $containerName; build_container = $buildName
    build_cpus = $BuildCpus; build_memory = $BuildMemory; runtime_cpus = $RuntimeCpus; runtime_memory = $RuntimeMemory
    host_udp_address = "127.0.0.1:$HostPort"; skip_build = [bool]$SkipBuild; offline = [bool]$Offline
    idle_seconds = $IdleSeconds; observe_interval_seconds = $ObserveIntervalSeconds
    final_report_wait_seconds = $FinalReportWaitSeconds
    suite = $Suite
    binary_provenance = $(if ($SkipBuild) { 'preexisting volume; source revisions not verified' } else { 'compiled from mounted working trees in this run' })
})

try {
    if (-not $SkipBuild) {
        foreach ($volume in @($TargetVolume, $RegistryVolume)) {
            & $docker volume inspect $volume *> $null
            if ($LASTEXITCODE -ne 0) { Invoke-Docker @('volume', 'create', '--label', $label, $volume) | Out-Null }
        }
        $buildArgs = @(
            'run', '--detach', '--name', $buildName, '--label', $label,
            '--cpus', "$BuildCpus", '--memory', $BuildMemory,
            '--mount', "type=bind,source=$repoPath,target=/workspace/node-agent-rs,readonly",
            '--mount', "type=bind,source=$CorePath,target=/workspace/shoes-plus,readonly",
            '--mount', "type=volume,source=$TargetVolume,target=/build",
            '--mount', "type=volume,source=$RegistryVolume,target=/usr/local/cargo/registry",
            '--env', 'CARGO_TARGET_DIR=/build', '--env', 'CARGO_INCREMENTAL=0', '--env', "CARGO_BUILD_JOBS=$BuildCpus",
            '--workdir', '/workspace/node-agent-rs'
        )
        if ($BuildProxy) {
            foreach ($name in @('CARGO_HTTP_PROXY', 'HTTP_PROXY', 'HTTPS_PROXY')) { $buildArgs += @('--env', "$name=$BuildProxy") }
        }
        $offlineArg = if ($Offline) { ' --offline' } else { '' }
        # Separate invocations keep example-only dev-dependency features out of the production daemon.
        $buildCommand = "cargo build --release --locked$offlineArg -p node-agent --bin node-agent`ncargo build --release --locked$offlineArg -p node-agent --example hy2_container_fixture"
        Invoke-Docker ($buildArgs + @($BuildImage, 'bash', '-euc', $buildCommand)) | Out-Null
        Write-Host "Building in $buildName; follow with: docker logs -f $buildName"
        $buildDeadline = [DateTimeOffset]::UtcNow.AddMinutes(40)
        while ((Invoke-Docker @('inspect', '--format', '{{.State.Running}}', $buildName)) -eq 'true') {
            if ([DateTimeOffset]::UtcNow -gt $buildDeadline) { throw "Build exceeded 40 minutes; retained container $buildName" }
            Start-Sleep -Seconds 2
        }
        & $docker logs --timestamps $buildName 2>&1 | Set-Content -LiteralPath (Join-Path $RunDirectory 'build.log')
        if ((Invoke-Docker @('inspect', '--format', '{{.State.ExitCode}}', $buildName)) -ne '0') { throw 'Linux release build failed; see build.log' }
    } else {
        Invoke-Docker @('volume', 'inspect', $TargetVolume) | Out-Null
    }

    if (-not $GoClient) {
        $go = (Get-Command go -ErrorAction Stop).Source
        $GoClient = Join-Path $RunDirectory 'sing-quic-switch.exe'
        Push-Location (Join-Path $repoPath 'tests/interop/sing-quic-switch')
        try {
            & $go build -o $GoClient . 2>&1 | Tee-Object -FilePath (Join-Path $RunDirectory 'go-build.log')
            if ($LASTEXITCODE -ne 0) { throw 'Go interoperability client build failed' }
        } finally { Pop-Location }
    }
    $GoClient = (Resolve-Path -LiteralPath $GoClient).Path
    Write-Json (Join-Path $RunDirectory 'client.json') @{ path = $GoClient; sha256 = (Get-FileHash -LiteralPath $GoClient -Algorithm SHA256).Hash }

    $runtimeArgs = @(
        'run', '--detach', '--name', $containerName, '--label', $label,
        '--cpus', "$RuntimeCpus", '--memory', $RuntimeMemory,
        '--publish', "127.0.0.1:${HostPort}:18443/udp",
        '--mount', "type=volume,source=$TargetVolume,target=/build,readonly",
        '--mount', "type=bind,source=$statePath,target=/fixture",
        '--mount', "type=bind,source=$PSScriptRoot,target=/harness,readonly",
        $BuildImage, 'bash', '/harness/start.sh'
    )
    Invoke-Docker $runtimeArgs | Out-Null
    $runtimeCreated = $true
    $readyDeadline = [DateTimeOffset]::UtcNow.AddSeconds(120)
    while ($true) {
        Assert-ContainerRunning
        $ready = $null
        $readyFile = Join-Path $statePath 'ready.json'
        if (Test-Path -LiteralPath $readyFile) {
            try { $ready = Get-Content -LiteralPath $readyFile -Raw | ConvertFrom-Json } catch { }
        }
        # A listening fixture alone is insufficient: require the daemon's applied ACK.
        if ($ready.agent_ready -eq $true) { break }
        if ([DateTimeOffset]::UtcNow -gt $readyDeadline) { throw 'The daemon did not ACK the fixture configuration within 120 seconds' }
        Start-Sleep -Milliseconds 250
    }
    Write-Json (Join-Path $RunDirectory 'ready-before.json') $ready
    $before = Invoke-Docker @('exec', $containerName, 'python3', '/harness/observe.py', '--state-dir', '/fixture') | ConvertFrom-Json
    if (-not $before.agent.running -or -not $before.fixture.running) { throw 'The initial process snapshot is unhealthy' }
    Write-Json (Join-Path $RunDirectory 'before.json') $before
    Invoke-Docker @('exec', $containerName, 'sha256sum', '/build/release/node-agent', '/build/release/examples/hy2_container_fixture') |
        Set-Content -LiteralPath (Join-Path $RunDirectory 'linux-binaries.sha256')
    Invoke-Docker @('exec', $containerName, '/build/release/node-agent', 'version', '--json') |
        Set-Content -LiteralPath (Join-Path $RunDirectory 'node-agent-version.json')

    $observer = Start-Job -ArgumentList $docker, $containerName, $RunDirectory, $stopFile, $ObserveIntervalSeconds -ScriptBlock {
        param($DockerPath, $Container, $OutputDirectory, $StopPath, $Interval)
        $errorFile = Join-Path $OutputDirectory 'observer-errors.log'
        while (-not (Test-Path -LiteralPath $StopPath)) {
            $sample = [ordered]@{ at_utc = [DateTimeOffset]::UtcNow }
            foreach ($item in @(
                @{ key = 'docker_state'; args = @('inspect', '--format', '{{json .State}}', $Container) },
                @{ key = 'docker_stats'; args = @('stats', '--no-stream', '--format', '{{json .}}', $Container) },
                @{ key = 'linux'; args = @('exec', $Container, 'python3', '/harness/observe.py', '--state-dir', '/fixture') }
            )) {
                $arguments = $item.args
                $output = & $DockerPath @arguments 2>> $errorFile
                if ($LASTEXITCODE -eq 0) {
                    try { $sample[$item.key] = $output | ConvertFrom-Json } catch { $sample[$item.key] = @{ parse_error = "$output" } }
                } else { $sample[$item.key] = @{ exit_code = $LASTEXITCODE } }
            }
            $sample | ConvertTo-Json -Depth 30 -Compress | Add-Content -LiteralPath (Join-Path $OutputDirectory 'telemetry.jsonl') -Encoding utf8
            Start-Sleep -Seconds $Interval
        }
    }

    Run-ClientStage 'baseline' @('--streams', '1', '--download', '1KiB', '--upload', '1KiB', '--rounds', '1', '--timeout', '1m', '--stream-timeout', '30s')
    if ($Suite -eq 'cancel') {
        # Abort only the logical download streams, retaining each HY2/QUIC
        # transport for the following upload and final connectivity probe.
        Run-ClientStage 'cancel-one-stream-then-upload' @('--connections', '1', '--streams', '1', '--download', '1GiB', '--cancel-download-after', '3s', '--upload', '240MiB', '--rounds', '1', '--timeout', '5m', '--stream-timeout', '1m')
        # 15 old downloads + 15 new uploads + Bob fit the fixture's 32-task
        # cap even if remote cleanup overlaps the immediate direction switch.
        Run-ClientStage 'cancel-fifteen-streams-three-rounds' @('--connections', '1', '--streams', '15', '--download', '128MiB', '--cancel-download-after', '3s', '--upload', '16MiB', '--rounds', '3', '--timeout', '5m', '--stream-timeout', '1m')
    } elseif ($Suite -eq 'concurrency') {
        # Keep each direction at 1 GiB in every case. TCP stream concurrency
        # and the number of underlying QUIC connections are separate variables.
        Run-ClientStage 'one-connection-one-stream' @('--connections', '1', '--streams', '1', '--download', '1GiB', '--upload', '1GiB', '--rounds', '1', '--timeout', '15m', '--stream-timeout', '10m')
        Run-ClientStage 'one-connection-sixteen-streams' @('--connections', '1', '--streams', '16', '--download', '64MiB', '--upload', '64MiB', '--rounds', '1', '--timeout', '15m', '--stream-timeout', '10m')
        Run-ClientStage 'eight-connections-two-streams' @('--connections', '8', '--streams', '2', '--download', '64MiB', '--upload', '64MiB', '--rounds', '1', '--timeout', '15m', '--stream-timeout', '10m')
    } else {
        Run-ClientStage 'upload-2gib' @('--streams', '1', '--download', '0', '--upload', '2GiB', '--rounds', '1', '--timeout', '15m', '--stream-timeout', '10m')
        Run-ClientStage 'download-upload-three-rounds' @('--streams', '4', '--download', '512MiB', '--upload', '256MiB', '--rounds', '3', '--timeout', '30m', '--stream-timeout', '10m')
    }
    Write-Host "Observing idle resource recovery for $IdleSeconds seconds"
    Start-Sleep -Seconds $IdleSeconds
    Run-ClientStage 'after-idle' @('--streams', '1', '--download', '1KiB', '--upload', '1KiB', '--rounds', '1', '--timeout', '1m', '--stream-timeout', '30s')
    # Allow the normal 10-second traffic report and 1-second fixture snapshot to catch up.
    Start-Sleep -Seconds $FinalReportWaitSeconds
    $after = Invoke-Docker @('exec', $containerName, 'python3', '/harness/observe.py', '--state-dir', '/fixture') | ConvertFrom-Json
    Write-Json (Join-Path $RunDirectory 'after.json') $after
    if (-not $after.agent.running -or -not $after.fixture.running -or -not $after.ready.agent_ready) { throw 'The final process/control-plane snapshot is unhealthy' }
    if ($observer.State -ne 'Running' -or -not (Test-Path -LiteralPath (Join-Path $RunDirectory 'telemetry.jsonl'))) { throw 'The background observer did not remain active' }
    Write-Json (Join-Path $RunDirectory 'result.json') @{ success = $true; finished_at = [DateTimeOffset]::UtcNow }
} catch {
    $failed = $_
    Write-Json (Join-Path $RunDirectory 'result.json') @{ success = $false; finished_at = [DateTimeOffset]::UtcNow; error = $_.ToString() }
} finally {
    if ($observer) {
        New-Item -ItemType File -Path $stopFile -Force | Out-Null
        $observer | Wait-Job -Timeout 15 | Out-Null
        if ($observer.State -eq 'Running') { $observer | Stop-Job }
        $observer | Receive-Job -ErrorAction Continue | Out-File -LiteralPath (Join-Path $RunDirectory 'observer-job.log')
        $observer | Remove-Job
    }
    Save-ContainerArtifacts
    if ($StopAfter -and $runtimeCreated) {
        $owned = Invoke-Docker @('inspect', '--format', '{{index .Config.Labels "io.node-agent.test"}}', $containerName)
        if ($owned -ne 'hy2-docker') { throw "Refusing to stop container without the expected test label: $containerName" }
        $stopRequestedAt = [DateTimeOffset]::UtcNow
        $preStopState = Invoke-Docker @('inspect', '--format', '{{json .State}}', $containerName) | ConvertFrom-Json
        if ($preStopState.Running) { Invoke-Docker @('stop', '--time', '10', $containerName) | Out-Null }
        $postStop = Invoke-Docker @('inspect', $containerName) | ConvertFrom-Json
        Write-Json (Join-Path $RunDirectory 'post-stop-inspect.json') $postStop
        $postStopState = @($postStop)[0].State
        $cleanStop = -not $postStopState.Running -and $postStopState.ExitCode -eq 0
        Write-Json (Join-Path $RunDirectory 'stop.json') @{
            requested_at = $stopRequestedAt
            was_running = $preStopState.Running
            already_exited_before_request = -not $preStopState.Running
            previous_exit_code = $preStopState.ExitCode
            final_exit_code = $postStopState.ExitCode
            controlled_stop_succeeded = $preStopState.Running -and $cleanStop
        }
        if ($preStopState.Running -and -not $cleanStop) {
            Write-Warning "Controlled stop did not exit cleanly; inspect post-stop-inspect.json (exit=$($postStopState.ExitCode))"
        } elseif (-not $preStopState.Running) {
            Write-Host "Container had already exited before the stop request (exit=$($preStopState.ExitCode))"
        }
    }
    Write-Host "Results: $RunDirectory"
    if ($runtimeCreated -and -not $StopAfter) { Write-Host "Container retained: $containerName" }
}
if ($failed) { throw $failed }
