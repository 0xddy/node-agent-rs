# FileZilla、v2rayN 系统代理与 OpenClash 的上传路径排查

日期：2026-09-17。接续 [FTPS 完整性排查](hysteria2-ftps-ts-integrity.md)。

## 当前现场证据

用户确认 v2rayN 仅启用“自动配置系统代理”，没有开启 TUN；FileZilla 的通用代理
选择“无”。OpenClash 的核心版本、运行模式、规则和实际选用协议仍未知。
用户报告调整 OpenClash 后覆盖上传完整；原话“管理 openclash”是否指关闭，尚未明确。
本机 `%APPDATA%/FileZilla/filezilla.xml` 亦显示 `Proxy type=0`、`FTP Proxy type=0`，
最大同时传输数为 10，超时为 20 秒。该文件最后修改日期为 2025-11-03，可能不是
另一份便携版 FileZilla 的活动配置；“无代理”以用户再次确认的信息为准。

该本地配置使用自动传输类型，ASCII 扩展名列表不包含 `ts`。没有证据表明 TS 被按
文本转换。未修改用户的 FileZilla、v2rayN 或路由器配置，也未访问生产 FTP 凭证。

## 为什么双开不等于双重代理

FileZilla 的 [官方连接实现](https://svn.filezilla-project.org/svn/FileZilla3/trunk/src/engine/controlsocket.cpp)
在 `CreateSocket()` 中读取自己的 `OPTION_PROXY_TYPE`，只有启用代理且站点没有
绕过代理时才建立代理层；否则直接通过 socket 连接目标。
[代理设置界面](https://svn.filezilla-project.org/svn/FileZilla3/trunk/src/interface/settings/optionspage_proxy.cpp)
提供 None、HTTP CONNECT、SOCKS4、SOCKS5。Windows 系统代理设置不会强制截获所有
程序的 socket 连接。

因此，在没有其他透明代理软件的前提下，当前更合理的假设是：

```text
FileZilla（不使用应用代理）
  → 路由器 OpenClash（是否接管由防火墙和规则决定）
  → 所选代理节点（如果为 HY2，则由其服务端建立 TCP）
  → FTPS 服务端
```

v2rayN 同时开启可能与其他网络负载有关，但不能由“双开”推出文件上传经过它。
真正的嵌套 HY2 则是内层 QUIC 的 UDP 被外层代理承载。两层连接同一服务器也不
自动形成回环；只有转发路径重新进入自身拦截并反复转发才构成回环。
[Mihomo dialer-proxy 文档](https://wiki.metacubex.one/config/proxies/dialer-proxy/)
描述了真正的链式传输及 UDP 协议兼容性限制。

## 与之前修复的关系

之前已由确定性测试证明：HY2 的反向 `STOP_SENDING` 不应导致尚未排空的上传被
整个双向复制任务终止。该缺陷不需要双重代理即可发生。

Mihomo v1.19.31 的 [Relay 实现](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/common/net/sing.go)
在一方向复制正常 EOF 后尝试 `CloseWrite`；不支持时调用 `Close`。HY2 客户端关闭
流时可能发送 FIN 并取消反向读取，因此 OpenClash/Mihomo 单层路径也值得检查相关
半关闭时序。源码关联不等于现场根因已经确认。

现有修复仅特殊处理明确的 `WriteError::Stopped`；整条 QUIC 连接丢失、上传 RESET、
超时仍会报错并结束该连接。它不承诺网络断开后依然完成上传。FTPS 的完整性校验
应比较源和落盘文件的 SHA-256；文件大小相等或 FTP 返回 `226` 都不足以证明相同。

## OpenClash 现场下一步应核查的证据

1. 同一批上传的控制连接与 EPSV/PASV 数据连接：分别命中什么规则、代理组、实际
   节点和出口 IP。FTPS 加密之后中间路由器看不到 FTP 命令，多个 TCP 连接仍会
   分别匹配规则。[OpenClash 防火墙脚本](https://github.com/vernesong/OpenClash/blob/master/luci-app-openclash/root/etc/init.d/openclash)
   存在按 `common_ports` 绕过非指定端口的分支，应检查实际模式和生成规则；不能
   仅由存在该选项就认定现场发生了分流。出口不一致通常首先造成连接失败，尚无
   证据能直接解释为静默截断。
2. FileZilla 10 并发时的失败队列、重试/续传、最后一次 STOR 的结束日志；与单并发
   以及关闭 OpenClash 的相同源文件对照。覆盖上传成功只说明那一次传输完整。
3. Mihomo/服务端的 QUIC 超时或重置、路由器 CPU、UDP 丢包和实际上行容量。
   若使用 Brutal，核对上行带宽配置；[Hysteria 官方带宽说明](https://v2.hysteria.network/docs/advanced/Full-Client-Config/#bandwidth)
   解释了带宽配置对拥塞控制的影响。

## Docker 对照

测试实现位于 [hy2-double-proxy](../tests/docker/hy2-double-proxy/README.md)。
使用真实 Linux FileZilla、官方 Mihomo 核心、真实 node-agent 和 pyftpdlib FTPS。
单层与刻意配置的双层 HY2 均测试 10 并发。双层属于假设对照，不能代表当前用户
已确认的实际上传链路。

测试通过 FileZilla 的显式 SOCKS 设置接入 Mihomo；覆盖内核 HY2/Relay 行为，尚未
模拟 OpenWrt 的 TPROXY/TUN、防火墙分流、硬件卸载或路由器的资源限制。
被测 node-agent 使用前次已校验的 Linux 二进制，SHA-256 为
`346f2c564ca98a9b8c04945cfedd9d4b43af1873fde12014b230a6845985618b`，
不是本日有其他改动的工作树的重新构建。

### 本轮结果

使用 FileZilla 3.63.0、Mihomo 官方发布版 v1.19.31；Mihomo Linux amd64 二进制
SHA-256 为 `b341a765412c192685264e038a6aad2ac1c67c12b8aceeb5c6f64955cf43f5ed`。
其下载压缩包的 SHA-256 与 GitHub release API 公布的 digest 一致。FTPS 每条数据
连接限读 2 MiB/s，小 TS 为 1,273,888 B，大 TS 为 33,162,636 B。

| 服务端版本 | 路径 | 上传数 | 实测上传并发峰值 | 大小及 SHA-256 |
| --- | --- | ---: | ---: | --- |
| 修复版 | 直连 | 2 | 1 | 全部一致 |
| 修复版 | Mihomo 单层 HY2，小/大文件 | 10 + 10 | 10 | 全部一致 |
| 修复版 | Mihomo 双层 HY2，小/大文件 | 10 + 10 | 10 | 全部一致 |
| 修复版 | 双层 HY2，10 ms 延迟、0.5% 丢包 | 5 | 5 | 全部一致 |
| 修复前基线 | 直连 | 2 | 1 | 全部一致 |
| 修复前基线 | Mihomo 单层 HY2，小/大文件 | 10 + 10 | 10 | 全部一致 |

并发峰值由 FTPS 服务端 STOR/完成事件的重叠统计得到，未仅凭设置中的上限推断。
修复版 47 次上传共 857,091,436 B，基线 22 次共 346,913,016 B。两轮均无
incomplete 事件、无 FileZilla Error 记录；所有文件 SHA-256 匹配，每阶段抽样 TS
严格解码通过。基线 SHA-256 为
`d89b813d60b4c361e600df53eac92f140d3e57a61e923c0267abd6d8005b6874`。

嵌套拓扑另有计量证据：单层外层账户 bob 上行为 0；双层中内层 alice 上行为
510,986,993 B，外层 bob 上行为 716,621,145 B，均超过该阶段总文件字节数
510,178,420 B。外层传递了内层 QUIC 数据，包括协议开销和重传，未把绕过外层
误当作成功。人工 netem 阶段确实丢弃 2,035 个 UDP 包；故障仅作用于该测试网络
命名空间目的端口 18443 的 UDP，同命名空间内的内外层 QUIC 都会受影响。

Mihomo 退出后的会话通过服务端空闲超时回收。修复版每组最终 active/online 均为
0/0，daemon FD 为 13→13，服务端 UDP socket drops 为 0。该 socket 计数与上述
netem 主动丢包是不同观察点。RSS 为 41,616→105,988→84,832 KiB，不能由短时
测试推出长期内存趋势。所有本轮容器均已停止。

证据目录：

- `run/hy2-double-proxy-20260917-fixed/`：修复版、单层/双层及网络故障。
- `run/hy2-double-proxy-20260917-baseline/`：修复前单层对照。

**这两轮均未复现现场截断。** 单层正常上传在修复前也通过，不能拿本轮结果证明
用户故障已定位或已消失；此前确定性 STOP 回归仍是那项缺陷的修复依据。当前最有
价值的现场信息是 OpenClash 实际配置、失败时的控制/数据连接出口，以及对应文件
的源/目标校验和与 FileZilla 结束日志。本轮只新增测试和调查文档，未追加服务端修复。
