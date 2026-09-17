# 常见连接事件日志

节点使用的 `../shoes-plus` 核心统一处理以下两类日志：

| 类别 | 级别 | 内容 |
| --- | --- | --- |
| `dns_no_addresses` | INFO | DNS 解析后没有可用地址，保留请求目标和原错误信息 |
| `hysteria2_timeout` | INFO | 已认证 HY2 连接超时，保留对端、关闭原因、流量、RTT、拥塞窗口、发送/丢包和对端流控统计 |

每个进程、每个类别首次立即输出，此后最多每 60 秒输出一条当前事件样本。
`suppressed_since_last_log` 表示该类别自上一条日志后省略的事件数量，不包含当前样本，
也不表示当前域名或客户端的次数。TCP/UDP 的空地址失败共用 DNS 类别。
下一次符合时间间隔的事件会带出省略计数；如果事件停止，不启动定时任务补发摘要。

示例：

```text
connection event: category=dns_no_addresses, suppressed_since_last_log=5, sample: TCP outbound setup to x.ss2.us:80 failed: DNS lookup returned no addresses for x.ss2.us
```

只有明确的空地址错误使用此规则，不按错误字符串匹配。DNS 上游超时、配置失败、
HY2 协议错误等其他异常保持原告警行为，正常关闭保持静默。
INFO 在 release 构建中仍然可用；日志过滤配置可进一步限制输出。

这项调整不改变解析、重试、连接超时或流量转发行为。`TimedOut` 的 INFO 级别也不表示
连接一定健康；若与正在使用时的断流对应，仍应结合客户端日志排查。
