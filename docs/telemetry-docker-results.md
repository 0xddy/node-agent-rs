# 遥测上报 Docker 兼容测试

2026-09-14 14:56–15:02（UTC+8）从当前工作区重新构建并验证通过。环境为 Docker 29.1.2、Debian 12、Rust 1.91.1、MySQL 8.0.43、Redis 7.4.5。

## 实测结果

| 验证项 | 结果 |
| --- | --- |
| Linux release 构建 | `node-agent` 和 `telemetry_probe` 均成功 |
| Linux 遥测单测 | 26 项通过；覆盖采集失败/阻塞、有效性、缓存冻结、最新值替换、认证错误及 HTTP/2 流控下的 1 秒发送超时 |
| 真实 Go 面板集成 | 2 项通过；使用当前 `Server.TelemetryStream`、时钟校验、`runtimestatus.Service` 和 `LiveRuntimeRepository` |
| 持续上报 | 收到 14 条样本，首末跨度 44.996 秒；同一流内间隔 2.995–3.000 秒 |
| 握手独立超时 | 服务端首个 ready header 延迟 1.2 秒后正常上报；阻塞 11 秒时，客户端在 10.004 秒退出，未提前发送样本 |
| 断线重连 | 首流 4 条后强制断开，等待 7 秒后重连；实例 ID 不变，序号从 5 跳至 8，断线期间的 6、7 没有补发 |
| 单调时钟基线 | 重连后基线从 1205 ms 更新为 19002 ms；同一流内基线保持不变 |
| 面板在线状态 | 真实 Redis 存储返回 `Online`、`fresh=true`、7 个连接、3 个在线用户 |
| 采集字段 | CPU/内存/连接统计/网卡/磁盘有效性、网卡索引及计数器有效性、磁盘独立采集时间均通过校验 |
| 认证错误 | 服务端返回 `Unauthenticated` 后，调用方在最后一条样本后 2 秒以内退出 |

本轮复查后重新验证：超过 3 秒的动态采集结果不能把旧 CPU 值标成新鲜；Unix 无 IP 网卡通过原生枚举补齐索引与管理状态。两个原生枚举回归在 Linux 执行通过。本机 `node-agent` 和 `acp-proto` 完整测试共 370 项通过，格式检查与 Clippy 通过。

## 复现命令

在 `node-agent-rs` 根目录使用 PowerShell 7：

```powershell
./tests/docker/telemetry/run.ps1 -PanelPath 'G:\Development\Project\国际机场\panel-api-server' -Offline
```

首次缺少 Cargo 缓存时去掉 `-Offline`。脚本通过本地代理构建工具镜像，使用当前源码重新构建；Go 测试通过 overlay 注入，不修改面板生产代码。

## 证据

最终运行目录：[telemetry-docker-20260914-145631-114](../run/telemetry-docker-20260914-145631-114/)。

- [结果](../run/telemetry-docker-20260914-145631-114/result.json)：`passed`。
- [构建与 Linux 单测日志](../run/telemetry-docker-20260914-145631-114/node-agent-telemetry-20260914-145631-114-build.log)。
- [真实 Go 面板测试日志](../run/telemetry-docker-20260914-145631-114/node-agent-telemetry-20260914-145631-114-test.log)。
- [接收到的完整样本](../run/telemetry-docker-20260914-145631-114/received-frames.json)。
- [构建前源码清单](../run/telemetry-docker-20260914-145631-114/source-before.json)与[构建后源码清单](../run/telemetry-docker-20260914-145631-114/source-after.json)：519 个源文件哈希一致，包含本轮采集超时、Unix 网卡枚举和面板磁盘时间映射修复；清单 SHA-256 均为 `C95262E7345DFBD4FF80845530B8696D7A16B24CA71E1BC81B6132D78F1018B1`。
- [Linux 二进制 SHA-256](../run/telemetry-docker-20260914-145631-114/linux-binaries.sha256)：`node-agent` 为 `f1748af6c8b95627d22f2cbebb5d9e118649f4393ca8f663443c807bf531fb85`。

## 覆盖边界

探针使用生产 `TelemetryReporter`、Linux 操作系统采集器和真实 Go 面板上报/存储链路；预置合法测试会话后，生产会话签名校验照常执行。连接统计由测试提供器固定为 7 个连接、3 个用户，未启动代理数据面或控制流，因此本报告不验证代理吞吐、真实连接计数或完整登录配置流程。

macOS/BSD 网卡修复的共享 Unix 原生枚举逻辑已在 Linux 测试，未进行 macOS/BSD 实机验证。磁盘跨机器时钟偏差已由面板按相对采集年龄映射；磁盘采集与心跳之间发生系统时钟跳变时，仍可能暂时判为无效，待下一次磁盘刷新恢复。

MySQL、Redis 均为新建容器，数据位于临时文件系统，使用独立内部网络且未发布端口。未连接或修改已有数据库；本次容器和网络已清理，构建缓存与测试证据保留。未发布或部署此版本。
