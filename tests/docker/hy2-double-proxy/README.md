# Real FileZilla / Mihomo / nested HY2 comparison

此测试复用 [Linux FileZilla harness](../hy2-filezilla/README.md)，使用真实 Linux
FileZilla、显式 FTPS 和 Mihomo HY2。它对比以下三种路径：

```text
direct: FileZilla -> FTPS
single: FileZilla -> SOCKS5 -> Mihomo HY2(alice) -> node-agent -> FTPS
nested: FileZilla -> SOCKS5 -> Mihomo inner HY2(alice)
                                -> outer HY2(bob) -> node-agent UDP relay
                                -> node-agent inner HY2 -> FTPS
```

内外层连接同一个测试 node-agent 地址，但外层负责传递内层 QUIC UDP 包，内层负责
承载 FTPS TCP 流。`inner.dialer-proxy=outer` 建立有限两层链；外层不再指定 dialer。
通过不同测试账户验证路径：单层阶段 bob 上行必须为零；嵌套阶段 alice、bob 的新增
上行字节数都必须不小于上传文件总字节数，避免把绕过外层误报为嵌套测试成功。
每轮保留 Mihomo 配置、版本、二进制 SHA-256、控制器连接采样和日志。

## 运行

准备已有 FileZilla 镜像及含 release node-agent/fixture 的 Docker volume；具体构建
步骤参见 [FTPS harness](../hy2-ftp/README.md)。从 Mihomo 官方 release 获取 Linux
amd64 可执行文件，在仓库根目录执行：

```powershell
python tests/docker/hy2-double-proxy/run.py --skip-image-build `
  --mihomo run/mihomo-linux-amd64 `
  --expected-binary-sha256 <node-agent-release-sha256>
```

`--target-volume` 可选择 release volume。默认使用
`node-agent-filezilla-test:20260917`，也可用 `--image` 指定已有兼容镜像。不加
`--skip-image-build` 时用本目录 Dockerfile 构建运行环境。可通过 `--modes single`
或 `--modes nested` 仅运行一种代理路径；默认 `--modes single,nested`。
容器、生成的 TS、上传文件、截图、SHA-256、解码日志、Mihomo 状态、node-agent 快照
和 `result.json` 都保留在 `run/hy2-double-proxy-时间戳/`。失败也保存结果及已完成阶段。
仅停止本次创建并带 `io.node-agent.test=hy2-double-proxy` 标签的容器。

| 阶段 | 文件数 | 最大同时传输 | 文件 |
| --- | ---: | ---: | --- |
| direct-control | 2 | 1 | 约 1.5 MiB TS |
| single-small / nested-small | 各 10 | 10 | 约 1.5 MiB TS |
| single-large / nested-large | 各 10 | 10 | 约 32 MiB TS |
| nested-impaired（可选） | 5 | 10 | 约 32 MiB TS |

默认 42 次上传。服务端每条连接限读 2 MiB/s，便于观察并发和连接状态；
`--read-limit 0` 关闭限速，其他数值为每连接每秒字节数。每个文件
核对源/目标大小及 SHA-256，每个阶段选一个目标 TS 严格解码；同时核对 FileZilla
成功次数、FTPS 完成/中断事件，并在客户端关闭后检查 node-agent active/online 归零。

客户端容器停止后，Mihomo 退出不一定先发送 QUIC `CONNECTION_CLOSE`。本轮缓存
node-agent 对应的核心设置为 30 秒 QUIC idle timeout、10 秒 keepalive；服务端可能
先等连接空闲超时，再由后续遥测反映 active/online 归零。runner 最多等待 45 秒，
这种停止后的 `TimedOut` 与上传期间的 FTPS 失败分别判断。UDP association 的 60 秒
空闲回收是另一个计时器，不能据此推断 QUIC 连接应立即消失。

加 `--with-impairment` 可执行额外 5 次嵌套上传。测试网络命名空间内的 `tc` 仅针对
回环上目的端口 18443 的 UDP，加入 10 ms 延迟和 0.5% 随机丢包；包括这个同命名空间
设计中的内外层 QUIC 包。FTPS TCP、GUI 和控制器不受此过滤器影响，保留 qdisc 计数。

## 与现场的关系

用户描述 v2rayN 使用 Windows 系统代理、未开 TUN；本机读取到的 FileZilla 通用代理
为关闭、并发数为 10。因此，仅凭两个程序同时运行不能认定 FileZilla 经历两层代理。
这里显式开启 FileZilla SOCKS5 的嵌套路径属于假设场景，用于检验 HY2 在该条件下的
完整性，不代表已经复现现场拓扑。OpenClash 的透明转发规则、路由器防火墙/资源限制、
真实 WAN/MTU、用户当时节点与 Windows FileZilla 均未在此 harness 中复现。

被测 node-agent 来自预先构建的 volume，必须显式提供期望 SHA-256。运行时记录的
工作区提交/改动只描述 harness 执行环境，不能据此推断缓存二进制由当前提交构建。

## 2026-09-17 实测

Mihomo v1.19.31、FileZilla 3.63.0：修复版完整矩阵（含网络故障）47 次上传通过；
修复前单层对照 22 次上传也通过，未复现现场截断。所有源/目标 SHA-256 一致。
完整版本、哈希、并发统计和结论边界见
[OpenClash / 系统代理调查](../../../docs/hysteria2-openclash-system-proxy.md)。
