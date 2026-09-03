# HY2 Docker 实测：Windows 客户端到 Linux node-agent

2026-09-03 17:59–18:02（北京时间）完成本机测试。**约 11 GiB 正常数据传输全部通过，未复现下载结束切换上传后客户端断网。** 此结论仅覆盖下列环境和流量。

## 实际运行环境

| 项目 | 本次设置 |
| --- | --- |
| 主机 | Windows，Docker Desktop 4.54.0，Linux Engine 29.1.2 |
| 服务端 | 真实 `node-agent` Linux release 二进制，Rust 1.91.1、opt-level 3、fat LTO |
| 生产代码 | node-agent-rs `1d1a8b8`，shoes-plus `d65b024`；本轮新增测试夹具不改变生产代码 |
| 容器额度 | 4 CPU、2 GiB 内存 |
| HY2 | `up_mbps=0`、`down_mbps=0`、`ignore_client_bandwidth=true`，自动拥塞控制 |
| 控制面 | 独立测试 ACP 面板；真实 daemon 完成认证、两用户同步、配置应用和 digest ACK |
| 客户端 | Windows 官方 sing-quic `v0.7.0-beta.4`，quic-go `v0.61.0-sing-box-mod.7` |
| 网络路径 | 主机 `127.0.0.1:18443/udp` → Docker Linux 容器 HY2 → 容器 TCP 目标 `127.0.0.1:19091` |

测试目标分块生成和校验数据，使用 64 KiB 缓冲。每条流校验完整字节数、数据内容和 EOF；上传完成还需要目标返回确认字节。同一客户端在三轮下载/上传之间保持原 QUIC 连接，拒绝 SDK 自动重连。

Bob 使用另一条 QUIC 连接，每 500 ms 发起一个小请求。主连接在负载期间记录字节进度，在每次客户端程序结束前另开逻辑流检查 `who` 响应与 EOF。

## 数据传输结果

并发阶段的大小是四条流的合计；Mbps 为十进制有效负载速率。

| 阶段 | 并发流数 | 数据量 | 耗时 | 平均速率 | 结果 |
| --- | ---: | ---: | ---: | ---: | --- |
| 单流上传 | 1 | 2 GiB | 36.90 s | 465.62 Mbps | 完整数据及 EOF |
| 第 1 轮下载 | 4 | 2 GiB | 24.08 s | 713.37 Mbps | 完整数据及 EOF |
| 第 1 轮随即上传 | 4 | 1 GiB | 19.49 s | 440.75 Mbps | 完整数据及 EOF |
| 第 2 轮下载 | 4 | 2 GiB | 24.50 s | 701.30 Mbps | 完整数据及 EOF |
| 第 2 轮随即上传 | 4 | 1 GiB | 19.52 s | 440.06 Mbps | 完整数据及 EOF |
| 第 3 轮下载 | 4 | 2 GiB | 24.72 s | 695.04 Mbps | 完整数据及 EOF |
| 第 3 轮随即上传 | 4 | 1 GiB | 19.52 s | 439.97 Mbps | 完整数据及 EOF |

测试前与空闲 30 秒后的小传输也通过，四个客户端程序退出码均为 0。目标共完成 29 次数据传输：上传 5 GiB + 2 KiB，下载 6 GiB + 2 KiB + 15 个上传确认字节。

独立 Bob 探针完成 **340 次，错误 0**，其中负载期间 336 次，其余为四次客户端启动基线；最大延迟 **98.19 ms**。四次主连接末尾探针也通过。服务端总计 344 次探针与 29 次传输，正好对应 373 个目标连接，失败、拒绝、超时均为 0。

各阶段内，整个主连接在应用层最长无字节进展约 **166.33 ms**，单条流最长约 **261.29 ms**。这些指标基于应用读写回调，不是逐个 UDP 包的时延测量。

## 内存、资源与错误计数

| 指标 | 负载前 | 峰值 | 结束并空闲后 |
| --- | ---: | ---: | ---: |
| node-agent 进程 RSS | 38.31 MiB | **83.54 MiB**，内核 `VmHWM` | **45.76 MiB** |
| node-agent 文件描述符 | 12 | 16，采样峰值 | 12 |
| 容器 cgroup 内存 | — | 142.50 MiB | 66.42 MiB |
| 活跃测试目标连接 | 0 | — | 0 |
| ACP 报告的活跃连接/在线用户 | 0/0 | — | 0/0 |

57 个周期快照全部正常。周期采样的 RSS 峰值为 76.68 MiB，表中采用内核高水位 83.54 MiB，避免漏掉采样间的峰值。容器内存还包含 fixture、采样进程、缓存和内核记账，不能当作 daemon RSS。容器 CPU 采样峰值约 1.45 个核；本次没有测到 4 核额度下的容量上限。

容器网络命名空间内 UDP 接收计数增加 5,451,385，发送增加 1,756,258。`InErrors`、`RcvbufErrors`、`SndbufErrors`、`NoPorts`、`MemErrors` 和 HY2 socket 的 drops 均未增长，末尾收发队列为空。未观察到 OOM 或内存限额事件。

启动日志确实提示：申请 8 MiB 的 UDP 收发缓冲，实际得到 425,984 字节。本次没有与之对应的 UDP 错误增长，不能单凭这条警告解释此前线上断网。

旧版 fixture 在本次原始快照中使用字段名 `agent_memory_used_bytes`；该值来自 `System::used_memory()`，实际是运行环境的系统内存。源代码现已改名 `system_memory_used_bytes`。本报告的进程内存全部取自 `/proc/<pid>/status`。

## 复用与证据

完整启动与构建说明见 [Docker 测试脚本](../tests/docker/hy2/README.md)，入口是：

```powershell
./tests/docker/hy2/run.ps1 -BuildImage shoes-linux-test:latest `
  -BuildProxy http://host.docker.internal:10886 -StopAfter
```

本机原始证据位于忽略目录 `run/hy2-docker-20260903-175017/transfer/`：阶段日志、`stages.jsonl`、`before.json`、`after.json`、`telemetry.jsonl`、`summary.json`、`state/agent.log`、构建日志及二进制 SHA256。容器在成功采集最终结果后受控停止，数据保留。

首次运行的 PID 1 测试脚本把主动停止也返回为容器退出码 1；负载期间 daemon 正常，所有成功结果均在主动停止前采集。现已修正脚本的信号处理，并用独立的启动/停止验证确认正常停止退出码为 0，记录在同级 `lifecycle/` 目录。真实子进程意外退出仍判失败。

本次 daemon SHA256：`a9595e528f934a0082a2d9271dc9643f0d74182a14eb8fb7c37b5ae466386dc9`。fixture SHA256：`97b3f13ab11e4c7f2479ea7ae2d0d8ad5e4e76196ac189afda784f35bea55cd8`。

[Docker Desktop 的网络路径](https://docs.docker.com/desktop/features/networking/)包含 Linux VM 与主机端口转发。容器内的零错误计数不能证明 Windows、Docker 转发、公网或 QUIC 端到端完全没有丢包。此次验证了这一环境中有限正常流量下的稳定性；此前真实 Speedtest 故障仍需结合实际客户端版本和故障日志对照。
