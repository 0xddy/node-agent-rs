# Linux FileZilla / FTPS / HY2 Docker test

该测试在 Xvfb 中运行 Debian 官方 FileZilla Client，并通过它的 SOCKS5 设置将 FTP
控制连接和 EPSV 被动数据连接交给 `hy2-socks`。`hy2-socks` 使用仓库已锁定的官方
`sing-quic` HY2 客户端，共用一条 HY2 物理连接，将各个 SOCKS CONNECT 映射为
node-agent 的 HY2 逻辑流。目标是同一 Docker 网络命名空间内的显式 FTPS 服务：

```text
FileZilla -> SOCKS5 -> sing-quic HY2 -> node-agent -> pyftpdlib FTPS
```

直连阶段关闭 SOCKS 设置，用同一 FileZilla 和 FTPS 服务校准客户端、证书及 GUI
操作。HY2 阶段要求 `AUTH TLS`、`PBSZ 0`、`PROT P`、`TYPE I` 和 EPSV。服务端在
`received` 回调中独立计算落盘大小及 SHA-256；每个阶段另取一份目标 TS 用 FFmpeg
严格解码。

## 运行

先按 [HY2 FTP harness](../hy2-ftp/README.md) 构建 Linux release，使
`node-agent-hy2-docker-target` 中存在 `node-agent` 和配置 fixture。随后从仓库根目录
执行：

```powershell
python tests/docker/hy2-filezilla/run.py
```

首次运行构建包含 FileZilla、Xvfb 和 xdotool 的镜像。已有
`node-agent-filezilla-test:20260916` 时可跳过：

```powershell
python tests/docker/hy2-filezilla/run.py --skip-image-build
```

`--expected-binary-sha256 HASH` 可把被测 volume 中的 release 固定到已核对的二进制。
证据默认写入新的 `run/hy2-filezilla-时间戳/`。runner 只停止本轮创建且带有
`io.node-agent.test=hy2-filezilla` 标签的容器，并保留容器、日志、截图和目标文件。

## 默认矩阵

| 阶段 | FileZilla 上传数 | 最大同时传输 | 条件 |
| --- | ---: | ---: | --- |
| direct-control | 2 | 1 | FileZilla 直连 FTPS |
| hy2-sequential | 10 | 1 | 单路依次经 HY2 |
| hy2-parallel | 12 | 4 | 四路并发，共用 HY2 连接 |
| hy2-large-parallel | 4 | 4 | 四个约 32 MiB TS 并发 |
| hy2-slow-target | 2 | 2 | FTPS 每条连接限读 2 MiB/s |

共上传 30 个文件，其中 28 个经过 HY2。检查项包括 FileZilla 自身的成功记录、服务端
完成/中断事件、每个文件的字节数和 SHA-256、SOCKS 数据流错误、TS 解码、daemon
进程/FD/UDP 快照，以及关闭 HY2 客户端后的 active/online 归零。

## 自动化边界

Dockerfile 当前安装 Debian 12 的 FileZilla 3.63.0。GUI 使用固定的 1280×800 Xvfb
画面；首次自签证书确认和目录上传由 xdotool 操作。升级 FileZilla 或改变语言、字体、
分辨率后，应先核对证书和上传前后的截图，不能只相信点击命令的退出码。

`hy2-socks` 是为测试编写的受限适配器，只允许访问回环地址的 2121 和
30000–30100 端口。它验证真实 FileZilla 的 FTPS/TLS 行为，但不等同于用户现场可能
使用的 Mihomo、OpenClash 或其他 HY2 客户端。该矩阵也不覆盖 Windows FileZilla、
隐式 FTPS、主动 FTP、真实公网抖动、CDN 或播放端行为。
