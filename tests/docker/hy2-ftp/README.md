# HY2 FTP / FTPS / MPEG-TS Docker integrity test

该测试运行真实 Linux `node-agent`、Go `sing-quic` HY2 客户端和系统包提供的
`pyftpdlib` FTP 服务。FFmpeg 生成 H.264/AAC MPEG-TS 样本，客户端通过真实 FTP
控制连接及被动数据连接执行二进制上传、`SIZE` 查询和下载校验。主矩阵使用显式
FTPS：`AUTH TLS` 加密控制连接，`PBSZ 0` / `PROT P` 加密数据连接。

## 运行

从 `node-agent-rs` 仓库根目录执行：

```powershell
python tests/docker/hy2-ftp/run.py
```

默认流程构建测试镜像，并从当前挂载的 `node-agent-rs` / `shoes-plus` 工作树执行
release daemon、配置 fixture 构建和上传回归测试，再运行 FTP 矩阵。Cargo 会使用
缓存，但不会跳过构建步骤。默认读取相邻 `../shoes-plus` 仓库；其他位置使用
`--core PATH`。每次使用新的运行目录，证据默认写入 `run/hy2-ftp-时间戳/`。

若相邻核心是 CI 固定的原始 `32e5864` checkout，需先按 CI 顺序应用
`patches/shoes-plus-raw-observations.patch` 和 `patches/shoes-plus-hy2-late-stop.patch`。
已有对应修改的工作树不要重复应用。runner 只读挂载源代码，不会自动更改核心；
未包含修复时，新增截断回归应失败。

依赖：

- Docker Linux containers；构建配额为 8 CPU / 12 GiB，daemon 为 4 CPU / 2 GiB。
- 主机 Python 3.11+、满足 `tests/interop/sing-quic-switch/go.mod` 要求的 Go，
  以及支持 `libx264`、AAC 编码的 FFmpeg，均在 `PATH` 中。
- 本地基础镜像 `node-agent-telemetry-test:latest`。如不存在，可先构建：

```powershell
docker build --build-arg BUILD_PROXY=http://host.docker.internal:10886 -t node-agent-telemetry-test:latest -f tests/docker/telemetry/Dockerfile tests/docker/telemetry
```

Rust 命令使用 `--locked --offline`，默认注册表缓存位于 Docker volume
`shoes-r-cargo-registry`，构建产物位于 `node-agent-hy2-docker-target`。缓存必须事先
包含当前 `Cargo.lock` 的 Linux 依赖；空缓存需先在相同源码挂载和注册表 volume 下
运行联网的 `cargo fetch --locked --target x86_64-unknown-linux-gnu`。Go 模块也需已缓存，
或允许构建期间下载。外部 Git 操作按仓库要求使用本地 HTTP 代理；容器内代理地址
为 `http://host.docker.internal:10886`。`--proxy` 配置镜像 apt 构建代理。

## 默认矩阵

每个 round 都上传并下载同一份源样本。小样本为 4 秒、640×360；大样本为
32 秒、1280×720。实际字节数及 SHA256 写入 `files.json`。

| 阶段 | 样本 | 并发 × rounds | 附加条件 |
| --- | --- | ---: | --- |
| plain-ftp-control | 小 | 1 × 2 | 经 HY2 的明文 FTP 对照 |
| direct-small | 小 | 1 × 2 | 容器内直连 FTPS 基线 |
| direct-large | 大 | 1 × 1 | 容器内直连 FTPS 基线 |
| hy2-sequential | 小 | 1 × 30 | 普通 HY2 建流 |
| hy2-parallel | 小 | 4 × 10 | 共享 HY2 连接 |
| hy2-fast-open | 小 | 1 × 20 | STOR 数据流启用 fast-open |
| hy2-large-parallel | 大 | 4 × 2 | fast-open |
| hy2-slow-target | 大 | 2 × 1 | fast-open，FTP 每连接限读 2 MiB/s |
| hy2-loss-delay | 小 | 4 × 3 | fast-open、上述限读、daemon 出口 10 ms 延迟和 0.5% 丢包 |
| hy2-after-impairment | 小 | 1 × 1 | 移除网络故障后；FTP 仍限读 |

除 `plain-ftp-control` 外各阶段均使用 FTPS。总计 118 次上传及下载。客户端每轮同时
检查 STOR/RETR `226` 响应、上传字节数、
FTP `SIZE`、下载字节数及下载 SHA256 与源文件一致。`226` 本身不能证明文件完整。
客户端 JSONL 保留每轮结果；每个 worker 的下载文件被后续 round 覆盖，因此最终
保留 20 份 TS，供 FFmpeg 解码检查。服务端 `state/ftp-events.jsonl` 另记录收到文件的
大小、SHA256、完成/中断回调及上传期间文件大小变化，可用于观察提前读取风险。

## 范围与证据

这是 `TYPE I` 的显式 FTPS 及明文 FTP 对照、被动 EPSV（客户端支持 PASV 回退）
测试，包含并发加密数据连接和 `sing-quic` 的流关闭行为。它不运行 FileZilla，也不
覆盖隐式 FTPS、主动 FTP、ASCII 模式、播放器/CDN 缓存或真实公网链路。
文件一致且可解码不能单独排除播放端
问题；上传期间文件已可见也不表示实际播放器曾提前读取。

真实 Linux FileZilla 的独立矩阵见
[hy2-filezilla](../hy2-filezilla/README.md)，两套 runner 不混用客户端证据。

服务端 `ftp_server.py --ftps` 要求 TLS 控制连接及 `PROT P`；默认启动方式仍为
明文 FTP。`--certfile` 默认 `/fixture/ftp.pem`，不存在时生成仅供测试的自签证书
和私钥。测试客户端限定回环地址，允许此测试证书；这不验证生产服务端的证书配置。

`run.json` 记录源码 revision、工作树状态、镜像及构建来源；其他文件保留客户端、
FTP 和 daemon 日志、二进制 SHA256、网络/进程快照。容器保留供检查，测试只停止
本轮创建并带有测试标签的容器；网络故障限定在本轮 daemon 的网络命名空间。

`--skip-image-build` 使用已存在的测试镜像。`--skip-build` 使用 volume 中现有
daemon/fixture，且跳过 Rust 回归；`run.json` 会标明来源未验证。这种运行不能直接
作为当前工作树修复已构建生效的证明，需要另行保存构建日志和二进制对应关系。
