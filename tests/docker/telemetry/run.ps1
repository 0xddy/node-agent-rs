#requires -Version 7.0
[CmdletBinding()]
param(
    [string] $PanelPath = (Join-Path $PSScriptRoot '../../../../国际机场/panel-api-server'),
    [string] $BuildImage = 'node-agent-telemetry-test:latest',
    [string] $BuildProxy = 'http://host.docker.internal:10886',
    [string] $TargetVolume = 'node-agent-hy2-docker-target',
    [string] $RegistryVolume = 'shoes-r-cargo-registry',
    [string] $RunDirectory,
    [switch] $SkipBuild,
    [switch] $Offline
)

$ErrorActionPreference = 'Stop'
$repoPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../../..')).Path
$PanelPath = (Resolve-Path -LiteralPath $PanelPath).Path
$corePath = (Resolve-Path -LiteralPath (Join-Path $repoPath '../shoes-plus')).Path
$runId = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$prefix = "node-agent-telemetry-$runId"
$network = "$prefix-net"
$mysql = "$prefix-mysql"
$redis = "$prefix-redis"
$build = "$prefix-build"
$test = "$prefix-test"
$label = 'io.node-agent.test=telemetry-docker'
$createdContainers = [System.Collections.Generic.List[string]]::new()
$networkCreated = $false
if (-not $RunDirectory) { $RunDirectory = Join-Path $repoPath "run/telemetry-docker-$runId" }
if (Test-Path -LiteralPath $RunDirectory) { throw "RunDirectory already exists: $RunDirectory" }
$RunDirectory = (New-Item -ItemType Directory -Path $RunDirectory).FullName

function Invoke-Docker {
    param([string[]] $Arguments)
    $output = & docker @Arguments
    if ($LASTEXITCODE -ne 0) { throw "docker $($Arguments[0]) failed with exit $LASTEXITCODE" }
    return $output
}

function Wait-OwnedContainer {
    param([string] $Name, [int] $Seconds = 2400)
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    while ((Invoke-Docker @('inspect', '--format', '{{.State.Running}}', $Name)) -eq 'true') {
        if ([DateTimeOffset]::UtcNow -gt $deadline) { throw "$Name exceeded $Seconds seconds" }
        Start-Sleep -Seconds 2
    }
    & docker logs --timestamps $Name 2>&1 | Set-Content -LiteralPath (Join-Path $RunDirectory "$Name.log")
    if ((Invoke-Docker @('inspect', '--format', '{{.State.ExitCode}}', $Name)) -ne '0') {
        Get-Content -LiteralPath (Join-Path $RunDirectory "$Name.log") -Tail 80
        throw "$Name failed; logs in $RunDirectory"
    }
}

function Save-SourceManifest {
    param([string] $Path)
    $files = @(
        Get-ChildItem -LiteralPath (Join-Path $repoPath 'crates') -Recurse -File | Where-Object { $_.Extension -in '.rs', '.toml', '.proto' }
        Get-Item -LiteralPath (Join-Path $repoPath 'Cargo.toml'), (Join-Path $repoPath 'Cargo.lock')
        Get-Item -LiteralPath (Join-Path $corePath 'Cargo.toml'), (Join-Path $corePath 'Cargo.lock')
        Get-ChildItem -LiteralPath (Join-Path $corePath 'src'), (Join-Path $corePath 'vendor') -Recurse -File | Where-Object { $_.Extension -in '.rs', '.toml' }
        Get-ChildItem -LiteralPath $PSScriptRoot -File
        Get-ChildItem -LiteralPath (Join-Path $PanelPath 'internal/grpcapi'), (Join-Path $PanelPath 'internal/repository'), (Join-Path $PanelPath 'internal/service/runtimestatus') -File -Filter '*.go'
    )
    $manifest = @($files | Sort-Object -Property FullName -Unique | ForEach-Object {
        [ordered]@{ path = $_.FullName; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
    }) | ConvertTo-Json -Depth 4
    $manifest | Set-Content -LiteralPath $Path -Encoding utf8
    return $manifest
}

[ordered]@{
    started_at = [DateTimeOffset]::UtcNow
    repository = $repoPath; panel_repository = $PanelPath; core_repository = $corePath
    agent_commit = (& git -C $repoPath rev-parse HEAD)
    panel_commit = (& git -C $PanelPath rev-parse HEAD)
    agent_worktree = @(& git -C $repoPath status --porcelain=v1)
    panel_worktree = @(& git -C $PanelPath status --porcelain=v1)
    docker_version = (& docker version --format '{{.Server.Version}}')
    build_image = $BuildImage; target_volume = $TargetVolume
    source_built_this_run = -not [bool]$SkipBuild
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $RunDirectory 'run.json') -Encoding utf8

try {
    $sourceBefore = Save-SourceManifest (Join-Path $RunDirectory 'source-before.json')
    if ((Invoke-Docker @('info', '--format', '{{.OSType}}')) -ne 'linux') { throw 'Docker must use Linux containers' }
    if (-not $SkipBuild) {
        Invoke-Docker @('build', '--progress', 'plain', '--build-arg', "BUILD_PROXY=$BuildProxy", '-t', $BuildImage, $PSScriptRoot) | Out-Null
        foreach ($volume in @($TargetVolume, $RegistryVolume)) { Invoke-Docker @('volume', 'create', '--label', $label, $volume) | Out-Null }
        $offlineArg = if ($Offline) { ' --offline' } else { '' }
        $buildCommand = "cargo build --release --locked$offlineArg -p node-agent --bin node-agent --example telemetry_probe`ncargo test --release --locked$offlineArg -p node-agent --lib telemetry -- --nocapture"
        Invoke-Docker @(
            'run', '--detach', '--name', $build, '--label', $label, '--cpus', '8', '--memory', '12g',
            '--mount', "type=bind,source=$repoPath,target=/workspace/node-agent-rs,readonly",
            '--mount', "type=bind,source=$corePath,target=/workspace/shoes-plus,readonly",
            '--mount', "type=volume,source=$TargetVolume,target=/build",
            '--mount', "type=volume,source=$RegistryVolume,target=/usr/local/cargo/registry",
            '--env', 'CARGO_TARGET_DIR=/build', '--env', 'CARGO_BUILD_JOBS=8', '--env', 'CARGO_INCREMENTAL=0',
            '--env', "CARGO_HTTP_PROXY=$BuildProxy", '--env', "HTTPS_PROXY=$BuildProxy", '--env', "HTTP_PROXY=$BuildProxy",
            '--workdir', '/workspace/node-agent-rs', $BuildImage, 'bash', '-euc', $buildCommand
        ) | Out-Null
        $createdContainers.Add($build)
        Write-Host "Compiling Linux agent, probe and telemetry tests: docker logs -f $build"
        Wait-OwnedContainer $build
    }
    Invoke-Docker @('image', 'inspect', $BuildImage) | Set-Content -LiteralPath (Join-Path $RunDirectory 'build-image.json')
    $fixturePath = Join-Path $PSScriptRoot 'panel_telemetry_test.go'
    $overlayPath = Join-Path $RunDirectory 'panel-overlay.json'
    $virtualPath = Join-Path $PanelPath 'internal/grpcapi/telemetry_docker_external_test.go'
    @{ Replace = @{ $virtualPath = $fixturePath } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $overlayPath -Encoding utf8
    $previousGoos = $env:GOOS; $previousGoarch = $env:GOARCH; $previousCgo = $env:CGO_ENABLED
    Push-Location $PanelPath
    try {
        $env:GOOS = 'linux'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'
        & go test -overlay $overlayPath -c -o (Join-Path $RunDirectory 'panel-telemetry.test') ./internal/grpcapi 2>&1 | Tee-Object -FilePath (Join-Path $RunDirectory 'go-build.log')
        if ($LASTEXITCODE -ne 0) { throw 'Cross compiling actual panel gRPC test fixture failed' }
    } finally { $env:GOOS = $previousGoos; $env:GOARCH = $previousGoarch; $env:CGO_ENABLED = $previousCgo; Pop-Location }

    Invoke-Docker @('network', 'create', '--internal', '--label', $label, $network) | Out-Null
    $networkCreated = $true
    Invoke-Docker @('run', '--detach', '--name', $mysql, '--label', $label, '--network', $network, '--network-alias', 'mysql', '--memory', '768m', '--tmpfs', '/var/lib/mysql', '--env', 'MYSQL_ROOT_PASSWORD=fixture-only', '--env', 'MYSQL_DATABASE=telemetry_fixture', 'mysql:8.0.43', '--skip-log-bin', '--innodb-buffer-pool-size=64M') | Out-Null
    $createdContainers.Add($mysql)
    Invoke-Docker @('run', '--detach', '--name', $redis, '--label', $label, '--network', $network, '--network-alias', 'redis', '--memory', '128m', '--tmpfs', '/data', 'redis:7.4.5-bookworm', 'redis-server', '--save', '', '--appendonly', 'no') | Out-Null
    $createdContainers.Add($redis)
    $dbDeadline = [DateTimeOffset]::UtcNow.AddSeconds(90)
    do {
        & docker exec $mysql mysqladmin ping --host=127.0.0.1 --user=root --password=fixture-only --silent *> $null
        if ($LASTEXITCODE -eq 0) { break }
        if ([DateTimeOffset]::UtcNow -gt $dbDeadline) { throw 'Isolated MySQL did not become ready' }
        Start-Sleep -Seconds 1
    } while ($true)
    Invoke-Docker @(
        'run', '--detach', '--name', $test, '--label', $label, '--network', $network, '--cpus', '4', '--memory', '2g',
        '--mount', "type=volume,source=$TargetVolume,target=/build,readonly",
        '--mount', "type=bind,source=$RunDirectory,target=/artifacts",
        '--env', 'ACP_TELEMETRY_DOCKER=1', '--env', 'ACP_RUST_TELEMETRY_PROBE=/build/release/examples/telemetry_probe',
        '--env', 'ACP_TELEMETRY_ARTIFACTS=/artifacts', $BuildImage, '/artifacts/panel-telemetry.test',
        '-test.v', '-test.run', '^TestDockerRustTelemetry', '-test.timeout', '150s'
    ) | Out-Null
    $createdContainers.Add($test)
    Wait-OwnedContainer $test 160
    Invoke-Docker @('run', '--rm', '--mount', "type=volume,source=$TargetVolume,target=/build,readonly", $BuildImage, 'sha256sum', '/build/release/node-agent', '/build/release/examples/telemetry_probe') |
        Set-Content -LiteralPath (Join-Path $RunDirectory 'linux-binaries.sha256')
    $sourceAfter = Save-SourceManifest (Join-Path $RunDirectory 'source-after.json')
    if ($sourceBefore -ne $sourceAfter) { throw 'Sources changed during compilation/testing; rerun to verify one stable source revision' }
    @{ status = 'passed'; ended_at = [DateTimeOffset]::UtcNow } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $RunDirectory 'result.json')
    Write-Host "Docker telemetry compatibility tests passed. Artifacts: $RunDirectory"
} catch {
    @{ status = 'failed'; ended_at = [DateTimeOffset]::UtcNow; error = $_.ToString() } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $RunDirectory 'result.json')
    throw
} finally {
    foreach ($name in $createdContainers) {
        & docker logs --timestamps $name 2>&1 | Set-Content -LiteralPath (Join-Path $RunDirectory "$name.log")
        & docker inspect $name | Set-Content -LiteralPath (Join-Path $RunDirectory "$name-inspect.json")
        & docker rm --force $name *> $null
    }
    if ($networkCreated) { & docker network rm $network *> $null }
}
