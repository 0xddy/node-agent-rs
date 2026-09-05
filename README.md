# node-agent-rs

[![CI](https://github.com/0xddy/node-agent-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/0xddy/node-agent-rs/actions/workflows/ci.yml)
![Rust Edition](https://img.shields.io/badge/Rust-2024-orange)
![License](https://img.shields.io/badge/license-MIT-blue)

`node-agent-rs` 是基于 Rust 和 `shoes-plus` 代理内核的 ACP 节点代理，负责接收面板配置、管理代理入站与用户，并上报流量和节点状态。项目同时提供可嵌入的 `shoes-engine`，适用于集中式节点管理和自定义控制面集成。

## 核心特性

- **ACP 面板集成**：通过 gRPC 完成节点认证、拓扑同步、控制指令、流量上报、遥测和日志传输，兼容现有 Go agent 的扁平 TOML 引导配置。
- **事务式配置应用**：将面板拓扑编译为内存中的运行配置，执行校验、应用和失败回滚；根据变更内容选择热更新或监听器重建。
- **动态用户管理**：支持在线添加、更新、停用和删除用户，提供用户级并发连接限制、上传及下载速率限制。
- **流量与运行观测**：按用户聚合流量增量，支持上报阈值、节点遥测、本地日志轮转和面板日志流。
- **路由与出站编排**：支持规则路由、DNS 策略、远程规则集、代理链和 URLTest 出站选择。
- **Hysteria2 端口跳跃**：在 Linux 上通过原生 netlink/nftables 后端管理端口重定向。

### 协议能力

| 使用入口 | 支持内容 |
| --- | --- |
| ACP 面板入站 | `vless-reality-vision@1`、`hysteria2-salamander@1` |
| `shoes-engine` 动态用户认证 | VLESS、VMess、Trojan、Shadowsocks 2022（AES-128-GCM / AES-256-GCM）、Hysteria2、TUIC、AnyTLS、NaiveProxy |

## 架构与技术栈

```text
ACP 面板
   │ gRPC / Protobuf
   ▼
node-agent        认证、会话、拓扑编译、事务应用、运行数据上报
   │ shoes-api
   ▼
shoes-engine      入站生命周期、用户注册表、连接控制、流量计量
   │
   ▼
shoes-plus        代理协议、传输、路由、DNS、出站拨号
```

| 组件 | 职责与技术 |
| --- | --- |
| `crates/node-agent` | 节点守护进程；Tokio 异步运行时、Tonic gRPC、TOML 引导配置 |
| `crates/acp-proto` | ACP Protobuf 定义、拓扑摘要、兼容 Go 的 HMAC 认证；Prost 与 protox 代码生成 |
| `crates/shoes-api` | 入站、用户、状态与流量报告的公共数据类型 |
| `crates/shoes-engine` | 可嵌入的 Rust 引擎；动态用户管理、配置更新与流量统计 |
| `../shoes-plus` | 同级仓库中的代理内核；rustls TLS、Quinn QUIC 及多协议数据面 |

工作区采用 Rust 2024 Edition，通过 Cargo 路径依赖引用 `../shoes-plus`。依赖版本由工作区 `Cargo.lock` 固定，CI 与发布流程使用固定的兼容内核提交。

## 安装与运行

### 环境准备

- Rust stable 工具链与 Cargo。
- Git，以及目标平台的 C/C++ 构建工具链和 CMake。
- ACP 面板地址，以及面板分配的 `machine_id`、`node_id` 和 `machine_secret`。
- 使用 Linux 端口跳跃功能时，准备 nftables 内核支持及 `CAP_NET_ADMIN` 权限。

### 从源码构建

将两个仓库放在同一父目录下，并将 `shoes-plus` 切换到当前 CI 使用的兼容提交：

```bash
git clone https://github.com/0xddy/node-agent-rs.git
git clone https://github.com/0xddy/shoes-plus.git
git -C shoes-plus checkout f010c624b063e6c4fb1a9702cc6ac564895ebb8a
cd node-agent-rs
cargo build --release --locked -p node-agent --bin node-agent
```

目录结构：

```text
workspace/
├── node-agent-rs/
│   ├── Cargo.toml
│   └── crates/
└── shoes-plus/
    ├── Cargo.toml
    └── vendor/
```

### 启动节点

在项目根目录创建下文所示的 `node-agent.toml`，填写面板连接信息后启动。

Linux / macOS：

```bash
./target/release/node-agent ./node-agent.toml
```

Windows PowerShell：

```powershell
.\target\release\node-agent.exe .\node-agent.toml
```

启动后，节点向面板认证并同步拓扑，由面板管理入站、用户和路由配置。

### 发布构建

`Release node-agent` 工作流生成各平台可执行文件及 `SHA256SUMS` 校验文件，发布入口为 [GitHub Releases](https://github.com/0xddy/node-agent-rs/releases)。

| 平台 | 架构 |
| --- | --- |
| Linux GNU | x86_64、aarch64 |
| Windows MSVC | x86_64 |
| macOS | x86_64、aarch64 |

## 配置与使用示例

### 引导配置

```toml
panel_grpc_endpoint = "grpcs://panel.example.com:443"
machine_id = "replace-with-machine-id"
node_id = "replace-with-node-id"
machine_secret = "replace-with-machine-secret"

ca_cert_path = ""
tls_insecure_skip_verify = false
debug = false
log_file_path = "runtime/node-agent.log"
traffic_report_min_delta_bytes = 26214400
```

| 字段 | 默认值 / 要求 | 说明 |
| --- | --- | --- |
| `panel_grpc_endpoint` | 必填 | 面板 gRPC 地址，格式为 `grpcs://主机:端口` 或 `grpc://主机:端口` |
| `machine_id` | 必填 | 面板分配的机器标识 |
| `node_id` | 必填 | 面板分配的节点标识 |
| `machine_secret` | 必填 | 节点与面板认证使用的共享密钥 |
| `ca_cert_path` | `""` | 使用 `grpcs://` 时可设置自定义 CA 证书路径；默认使用系统信任根 |
| `tls_insecure_skip_verify` | `false` | TLS 证书校验开关；`false` 表示执行证书校验 |
| `debug` | `false` | 启用调试日志 |
| `log_file_path` | `""` | 本地日志路径；留空时使用 `runtime/node-agent.log` |
| `traffic_report_min_delta_bytes` | `26214400` | 流量增量上报阈值，单位为字节，默认 25 MiB，取值为正整数 |

`grpcs://` 使用 TLS 连接。面板拓扑承载业务配置，TOML 用于设置面板连接、节点身份和本地运行参数。

### 查看版本

```bash
./target/release/node-agent version
./target/release/node-agent version --json
```

Windows 下使用 `.\target\release\node-agent.exe` 执行相同子命令。

### 集成动态引擎

自定义控制面可依赖 `shoes-api` 和 `shoes-engine`，通过以下接口管理运行中的代理服务：

| 操作 | 接口 |
| --- | --- |
| 初始化引擎 | `Engine::bootstrap().await` |
| 创建入站 | `engine.add_inbound(spec).await` |
| 添加或更新用户 | `engine.add_user(tag, user)` |
| 删除用户并关闭其连接 | `engine.remove_user(tag, id).await` |
| 提取用户流量增量 | `engine.take_inbound_traffic(tag)` |

`InboundSpec.users` 设置为 `Some(vec![])` 时启用动态用户注册表，随后通过用户接口添加凭据。`UserSpec` 的 `max_conns` 控制用户并发连接数，`upload_limit_bps` 和 `download_limit_bps` 分别控制客户端视角的上传与下载速率，单位为 bit/s。

## 开发与验证

在工作区根目录执行：

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked
cargo test --workspace --locked
```

同步修改 `shoes-plus` 时，对其运行独立检查：

```bash
cargo fmt --manifest-path ../shoes-plus/Cargo.toml --all -- --check
cargo clippy --manifest-path ../shoes-plus/Cargo.toml --all-targets --locked --no-deps
cargo test --manifest-path ../shoes-plus/Cargo.toml --all-targets --locked
```

## 相关文档

- [动态引擎设计](docs/dynamic-engine-design.md)
- [面板配置与拓扑支持矩阵](docs/node-agent-panel-compatibility.md)
