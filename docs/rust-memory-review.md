# Rust 内存优化审查

审查基线：`ede30ab`，2026-09-03。范围为本工作区四个 crate 的生产 Rust 代码；对路径依赖 `../shoes-plus` 仅追踪 VMess、SS2022 和反序列化相关实现，未全面审查其数据包缓冲。下文审查位置和对照测量以该基线为准。

**第一批落地：优先收益明确且改动较小的项目**

- 流量聚合用 extract_if 移动身份字段，空结果不按全用户数预分配；入队先 reserve，再移动报告，取消时恢复未发送后缀。
- 流量采集在 apply 锁内借用发布配置，避免每 10 秒深拷贝全量配置；双零记录在构造归属字符串前过滤。
- update_spec 显式构造无用户配置，不再复制凭据后丢弃；compile_users 的校验/去重使用借用字符串。
- 新 registry 的批量注册只发布一次 VMess 快照，在线 upsert/remove 保持及时发布；用户列表使用原地不稳定排序。
- Entry 的 VMess 状态改为可选 Box，减少无 UUID 用户的内联空间；UUID 用户新增一次密钥分配，保持既有协议切换语义。
- 辅助会话流直接保存泛型闭包，去除额外 Arc/BoxFuture；大型事务 future 的装箱保留。
- 控制命令原始载荷移动给执行任务，ACK 仅保留必要元数据，不再复制 topology/delta/legacy payload。

第一批验证已完成（Windows 本地，锁定依赖、离线执行）：

- `cargo fmt --all --check`、`git diff --check` 通过。
- `cargo test --workspace --lib --offline --locked`：317 项通过。
- `cargo test --offline --locked -p node-agent -p shoes-engine --test topology_compile --test topology_manager_control --test agent_session --test users --test vmess --test governance --test reload --test traffic`：109 项通过。
- `cargo clippy --workspace --all-targets --offline --locked` 通过；仅有未修改的 `tests/hysteria2_rebind.rs:151` 的原有 collapsible_if 提示。
- 以实际修改后的聚合器和 HEAD 基线运行同一分配探针：1,000 条报告为 4,002 → 9 次分配请求；10,000 个未达阈值计数器的结果缓冲为 1,200,000 → 0 B。未将这些局部数值解释成进程 RSS 降幅。

**第二批落地：缩小周期采集、分页和指纹计算的临时数据**

| 优先级 | 已实现优化 | 直接收益与边界 |
| --- | --- | --- |
| P1 | 引擎新增 `take_nonzero_traffic` / `take_nonzero_inbound_traffic`，周期采集使用新接口 | 每个用户仍原子取走计数；只有非零记录才创建 `UserInfo` 和 ID 字符串。结果内存随活跃用户数增长，遍历仍为 O(U)。原全量接口保留。 |
| P1 | `loaded_users_page` 下推到 TopologyManager | 在同一次操作锁/读锁内取得总数和页切片，仅复制 P 条凭据；响应消费页内记录，不再先复制 U 条再复制 P 条。分页字段和默认页大小保持原协议。 |
| P1 | `refresh_owned` 先借用当前用户做 CAS/差异检查 | CAS 失败和无变化刷新不再深拷贝整个拓扑；仅推进 revision 的无变化刷新仍更新原始 protobuf revision 和 publication generation。实际变更时移动传入的用户 Vec。 |
| P2 | 5 处 JSON 指纹改为直接写入 SHA-256 | 覆盖全局 DNS 客户端、URLTest identity、DNS 拒绝规则状态、引擎内联 DNS 和探测 DNS；消除仅用于哈希的 JSON Vec。序列化顺序、前缀和错误消息不变；真实需要字节内容的 rule-set 资源缓冲保留。 |

这批继续使用借用和所有权转移，避免引入跨层生命周期或共享可变状态。哈希写入器的核心实现如下，JSON 字节只流经序列化器和哈希器：

```rust
struct JsonHashWriter<'a>(&'a mut Sha256);

impl std::io::Write for JsonHashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

serde_json::to_writer(JsonHashWriter(&mut hasher), &value)?;
```

第二批的局部分配探针直接调用本次构建的 `MemoryUserRegistry`：1,000 个闲置用户（10 字节 ID），原全量采集为 **1,137 次分配请求、209,296 B 累计请求**；新稀疏采集为 **128 次、3,072 B**，结果 Vec 容量从 1,024 变为 0。准备用户与预热不计入，探针使用 `System` 分配器；这不是生产 RSS 测量。剩余 128 次来自本机 DashMap 分片迭代的 Arc guard，因此不宣称闲置扫描完全零分配。

第二批验证已完成（Windows 本地，锁定依赖、离线执行）：

- `cargo test --workspace --lib --offline --locked`：325 项通过。
- `cargo test --offline --locked -p node-agent -p shoes-engine --test topology_compile --test topology_manager_control --test remote_control_adapter --test traffic`：97 项通过。
- 新增回归覆盖稀疏采集并发计数/下一周期、分页下推与极端边界、无变化刷新的 revision/generation 与 CAS/fence、流式哈希的字节兼容及序列化错误。
- `cargo fmt --all --check`、`git diff --check` 和 `cargo clippy --workspace --all-targets --offline --locked` 通过；Clippy 仅保留未修改的 `tests/hysteria2_rebind.rs:151` 的原有提示。

**第三批落地：按带宽受限节点的实际规模取舍**

- 规则集监听只在存在远程资源时复制 `RuntimeConfig`。成功应用本地/内联规则或无规则的配置时，仍在 apply 锁内推进 watcher generation 并取消旧任务；失败候选继续保留原监听器。
- 远程日志仅在有有效订阅时构造正文和 source 前缀；单订阅直接接收原 String，多订阅只复制 N−1 次。进入队列前收紧字符串容量，避免移动操作把截断后的巨大缓冲或过量预留容量长期保留。行数、字节、UTF-8 截断和丢弃计数语义保持。
- 7 个协议索引改为可选 DashMap，按不可变的 `CredentialKinds` 创建。常见单协议 registry 从 9 张表降至 3 张，AnyTLS 使用 4 张；使用中的默认分片数不变。用户主表、移除中的用户表和 VMess 兼容行为保留。

本机 32 个逻辑处理器、默认分片数下，直接比较本批修改前后的实际 `MemoryUserRegistry::new`（空入站，无活跃连接）：

| 协议能力 | 构造分配次数 | 累计请求字节 | 单入站减少 |
| --- | --- | --- | --- |
| UUID / Hysteria2 密码 | 12 → 6 | 147,936 → 49,632 B | 96 KiB |
| AnyTLS | 12 → 7 | 147,936 → 66,016 B | 80 KiB |
| UUID + Trojan + 明文密码 | 12 → 8 | 147,936 → 82,400 B | 64 KiB |

探针使用 System 分配器，不含预热，不是 RSS 测量；较少核心的节点默认分片更少，绝对收益也会更小。

同一份实际日志 broker 探针在初始化/队列预热后测得：无订阅的带前缀日志为 3 → 0 次分配；单订阅转交已拥有、容量恰好等于长度的正文为 1 → 0 次；双订阅为 2 → 1 次。这里不计调用方构造 owned String 或队列首次扩容；过量预留容量仍会收紧，以维持队列内存边界。

第三批验证已完成（Windows 本地，锁定依赖、离线执行）：

- `cargo test --workspace --lib --offline --locked`：332 项通过。
- `cargo test -p shoes-engine --offline --locked --test users --test vmess --test shadowsocks --test anytls --test naiveproxy --test tuic --test hysteria2 --test governance --test reload`：37 项通过。
- `cargo test -p node-agent -p shoes-engine --test agent_session --offline --locked`：完整会话集成测试通过。
- `cargo fmt --all --check`、`git diff --check`、`cargo clippy --workspace --all-targets --offline --locked` 通过；Clippy 仅保留原有的 `tests/hysteria2_rebind.rs:151` 提示。

用户确认节点受带宽约束，不以数千用户同时活跃作为优化前提。后续优先评估实际入站数量、已加载配置和日志量带来的成本；低收益微优化不再排期。共享凭据、Undo/拓扑共享及重复解析等较大改造，等实际测量证明存在明显瓶颈再处理。本轮未修改路径依赖或公开 wire DTO。

后续章节保留初审结论和设计示例，已落地范围以上述记录为准。

结论：优先解决回滚日志的整入站复制、用户条目的内联 VMess 状态、批量注册时重复重建索引，以及周期流量采集/上报的复制。字段重排和控制面动态分发的收益明显靠后。

以下“原位替换”指可在现有函数中替换的实现；“结构改造”需要同步修改调用方和类型，并非可直接粘贴的完整补丁。零拷贝主要指进程内部借用、移动或共享数据；protobuf 编码、加密输出等仍有必要的输出缓冲。

**实测方法与边界**

环境为 `rustc 1.91.1`、`x86_64-pc-windows-msvc`。布局结果仅针对该编译器/目标；生产 Linux 应再测。公共类型使用实际 crate，私有类型使用逐字段镜像。`size_of` 不包含指向的堆对象、分配器元数据或进程 RSS。

通过 `cargo build -p shoes-api --offline --locked` 构建当前 API。分配探针使用 `GlobalAlloc` 包装 `System`，仅计量待测操作，包含 realloc 请求，不包含输入准备；生产二进制使用 mimalloc，因此不能把这些字节数当作 RSS。

| 实验 | 当前实现 | 建议实现 |
| --- | ---: | ---: |
| 1,000 用户的入站快照复制 100 次 | 509,601 次分配请求；38,624,400 B 累计请求 | 预建 Arc 后复制 100 次：1 次结果 Vec 分配；800 B |
| `update_spec`，1,000 用户、config 为 Null | 2,002 次；174,009 B | 显式构造 `users: None`：1 次；9 B |
| 聚合器输出 1,000 条报告 | 4,002 次 | 移动 key + 原地排序：9 次，均为结果 Vec 分配/扩容 |
| 聚合器有 10,000 个未达阈值计数，输出 0 条 | 1 次；1,200,000 B | 0 次；0 B |
| 9 张默认空 DashMap，32 个可用逻辑处理器 | 9 次；147,456 B 分片数组 | 未使用索引不构造；具体节省取决于协议 |

聚合器替换版本在临时源码中通过原有全部 7 项单元测试；入队所有权转移通过“队列满后取消”“接收端关闭”“预先取消”3 个独立场景。其余结构改造尚未做整项目集成测试，也未开展真实负载/RSS profiling。

**1. 高优先级：每个用户变更都把整入站塞进回滚日志，峰值呈 O(K × U)**

位置：[Undo 定义](G:/Development/Project/node-agent-rs/crates/node-agent/src/runtime.rs:476)、[逐用户删除日志](G:/Development/Project/node-agent-rs/crates/node-agent/src/runtime.rs:1211)、[新增/更新日志](G:/Development/Project/node-agent-rs/crates/node-agent/src/runtime.rs:1245)、[重复保存用户](G:/Development/Project/node-agent-rs/crates/node-agent/src/runtime.rs:2350)。

`NormalizedInbound` 同时持有 `compiled.spec.users` 和 `BTreeMap<String, UserSpec>`。每个 `Undo::AddUser/RestoreUser` 都 clone 整个入站；`RemoveUser` 还 clone 新旧两份。U 个用户、K 个变更时，日志长期持有 O(K × U) 的用户记录和凭据副本，K 接近 U 时成为二次增长。回滚所需的数据必须保留，但可以共享同一不可变版本。

结构改造：在规范化时每个入站只分配一个 Arc，所有日志/恢复状态共享它；不能在每次 push 时执行 `Arc::new(old.clone())`，那仍会深拷贝。

```rust
type SharedInbound = Arc<NormalizedInbound>;

// NormalizedConfig.inbounds 改为：
// BTreeMap<String, SharedInbound>
// normalize 中：inbounds.insert(tag, Arc::new(normalized));

enum Undo {
    AddInbound { inbound: SharedInbound, replay: InboundReplayLease },
    RemoveInbound { live: SharedInbound, accounting: SharedInbound },
    RestoreHotConfig {
        current: SharedInbound,
        previous: SharedInbound,
        replay: InboundReplayLease,
    },
    AddUser { inbound: SharedInbound, user: UserSpec },
    RemoveUser {
        live: SharedInbound,
        accounting: SharedInbound,
        user_id: String,
    },
    RestoreUser { inbound: SharedInbound, user: UserSpec, kick: bool },
}

// old/new 为从 map 取得的 &Arc<NormalizedInbound>：
journal.push(Undo::RemoveUser {
    live: Arc::clone(new),
    accounting: Arc::clone(old),
    user_id: change.id.clone(),
});
```

`RetiringInbound`、`FailedTransaction`、recovery 状态需统一共享所有权。未提交候选的 `accounting` 仍须指向旧发布者，不能将 live/accounting 合并。修改 fallback 所有者时应使用独立的小型归属元数据，或在确需改变入站时执行一次 `Arc::make_mut`。

第二步可让用户 spec 只保存一份：将 `users` 改为 `BTreeMap<String, usize>` 索引到不可变 `compiled.spec.users`，或维护一份规范化用户表，在 Engine 边界构建所需 owned spec。不要直接删除 `compiled.spec.users`：完整重建入站仍依赖它，且 `None` 与 `Some(vec![])` 语义不同。

**2. 高优先级：所有用户条目内联预留 VMess 大状态**

位置：[Entry](G:/Development/Project/node-agent-rs/crates/shoes-engine/src/users.rs:288)、[VMess 构造](G:/Development/Project/node-agent-rs/crates/shoes-engine/src/users.rs:589)。

实测 `VmessAuthKey` 和 `Option<VmessAuthKey>` 都是 520 B；Entry 同字段镜像为 680 B。密码协议用户即使 `vmess == None` 也承担这一内联空间。最小改造是把稀疏大字段放到单独分配中：

```rust
// Entry 的字段：
vmess: Option<Box<VmessAuthKey>>,

// 对应构造：
vmess: credentials.uuid.as_ref()
    .map(|uuid| Box::new(VmessAuthKey::new(uuid))),
```

镜像 Entry 降到 168 B。无 UUID 用户每条省 512 B；10 万条约省 48.8 MiB 对象有效空间，不等于 RSS。已有 VMess 状态的用户会新增一次分配，Entry + key 总对象空间约增加 8 B，故不能宣传为所有协议都获益。

进一步可考虑只为确实需要 VMess 的入站创建密钥/候选表；目前 VLESS、VMess、TUIC 的 UUID 用户都会创建 VMess key。这些协议共享 UUID 凭据能力，不能仅从 `CredentialKinds::UUID` 区分实际协议。当前 VLESS → VMess 原地更新会因逻辑流安全要求而请求完整监听器替换（见 governance 集成测试），并非只满足相同 kinds 就能切换。进一步裁剪密钥需要联动混合协议、初始化和监听器替换流程，本批保留现有行为。

**3. 高优先级：批量注册 U 次全量重建 VMess 快照**

位置：[build_user_registry](G:/Development/Project/node-agent-rs/crates/shoes-engine/src/lib.rs:1195)、[upsert 发布](G:/Development/Project/node-agent-rs/crates/shoes-engine/src/users.rs:655)、[republish_vmess](G:/Development/Project/node-agent-rs/crates/shoes-engine/src/users.rs:1079)、[预校验再建 registry](G:/Development/Project/node-agent-rs/crates/shoes-engine/src/lib.rs:640)。

初始导入 U 个 UUID 用户会累计复制 U(U+1)/2 个 Arc 指针。10 万用户约 50 亿次引用计数增加，指针有效载荷累计约 40 GB，**这是累计复制量，不是同时驻留 40 GB**。非 UUID 入站也重复遍历表，并分配空快照的 Arc。初建返回的 `UserInfo` 被丢弃，还白分配了每个用户的 ID。

结构改造：将现有 upsert 的校验、索引修改和 Entry 构造提取到 `upsert_locked`；它不获取 writer、不发布快照、不构造报告，返回 `Arc<Entry>`。新建且尚未公开的 registry 完成全部用户插入后只发布一次：

```rust
pub fn upsert(&self, spec: UserSpec) -> EngineResult<UserInfo> {
    let _writer = self.lock_writer();
    let entry = self.upsert_locked(spec)?;
    self.republish_vmess();
    Ok(user_info(&entry.context))
}

pub(crate) fn from_users(
    kinds: CredentialKinds,
    users: Vec<UserSpec>,
) -> EngineResult<Arc<Self>> {
    let registry = Self::new(kinds);
    {
        let _writer = registry.lock_writer();
        for spec in users {
            let id = spec.resolved_id().ok_or_else(|| {
                EngineError::InvalidUser("a user needs an `id` or a `uuid`".into())
            })?;
            if registry.users.contains_key(id) {
                return Err(EngineError::InvalidUser(format!(
                    "user {id} is listed twice"
                )));
            }
            registry.upsert_locked(spec)?;
        }
        registry.republish_vmess();
    }
    Ok(registry)
}
```

在线单用户 upsert/remove 仍须及时发布快照；并发读者已经持有的旧快照继续通过原有 revoke/admission gate 保证移除安全。初始化失败直接丢弃未公开候选。预校验可进一步产出可消费的 PreparedInbound，成功启动时复用已验证资源，避免验证/启动分别构建全库。

**4. 中高优先级：未使用的 DashMap 索引也常驻分片数组**

位置：[9 张表](G:/Development/Project/node-agent-rs/crates/shoes-engine/src/users.rs:434)、[全部初始化](G:/Development/Project/node-agent-rs/crates/shoes-engine/src/users.rs:478)。

DashMap 6.2.1 默认分片数随可用 CPU 数增长。本机 32 个逻辑处理器，9 张空表的分片数组为 144 KiB；1,000 个空动态入站约 140.6 MiB，尚未包括用户和桶。建议首先不构造未启用的协议索引，已启用表继续保留现有并发参数。

```rust
// 以 Hysteria2 密码索引为例；同时应用第 9 项的共享凭据。
by_password: Option<DashMap<Arc<str>, Arc<Entry>>>,

// 初始化
by_password: kinds.plain_password.then(DashMap::new),

// find_password
let entry = self.by_password.as_ref()?.get(password)?;
let expected = entry.password.as_deref()?;
entry.accept(expected.as_bytes(), password.as_bytes())
```

写入、删除和冲突检测需同步适配 Option。VMess 与 UUID 的能力切换仍按第 2 项处理。`users` 必须保留；`draining` 可按首次删除懒初始化。4 分片的 9 表探针只有 4,608 B，但统一降低认证表分片数可能增加争用，应由负载测试决定。

**5. 中高优先级：每 10 秒采流量先深拷贝整个运行配置，并为零流量用户分配字符串**

位置：[drain_traffic_owned](G:/Development/Project/node-agent-rs/crates/node-agent/src/runtime.rs:2168)、[全用户流量](G:/Development/Project/node-agent-rs/crates/shoes-engine/src/users.rs:803)、[先生成所有 UserInfo](G:/Development/Project/node-agent-rs/crates/shoes-engine/src/users.rs:1193)、[构造 TrafficDrain](G:/Development/Project/node-agent-rs/crates/node-agent/src/runtime.rs:2466)、[零值过滤](G:/Development/Project/node-agent-rs/crates/node-agent/src/runtime.rs:327)。

`self.read_state().current.clone()` 会复制所有配置、两份用户表和 diagnostic YAML，采集只需入站元数据。最小方案是在取得 apply 锁后短期借用 current；该函数此后没有 await，但会延长读锁持有时间。更好的整体方案是让发布态保存 `Arc<NormalizedConfig>`：

```rust
// AppliedState.current / recovery 改为 Option<Arc<NormalizedConfig>>。
let current = {
    let state = self.read_state();
    state.current.as_ref().map(Arc::clone)
};
// 后续现有遍历使用 &current.inbounds，不深拷贝配置。
```

另外，idle 用户先分配 `UserInfo.id`，随后分配 TrafficDrain 的 tag/node/protocol，最后才因字节数为零丢弃。可新增仅供计费使用的非零 sweep，保留公共 `list/take_all_traffic` 的完整结果语义：

```rust
fn taken_nonzero_user_info(context: &UserContext) -> Option<UserInfo> {
    let (tx, rx) = context.take_traffic();
    if tx == 0 && rx == 0 {
        return None;
    }
    // 顺序同原函数：先 take counter，再读取观察时间。
    let mut info = user_info(context);
    info.tx = tx;
    info.rx = rx;
    Some(info)
}

// 新内部 sweep 使用 filter_map；Engine 的计费路径调用这个新 API。
// take 后发生的新流量仍留在 counter 中，归下一周期。
```

`list` 和非零 sweep 的 ID 唯一，排序可改为 `sort_unstable_by(|a, b| a.id.cmp(&b.id))`。运行时随后还按 BTreeMap key 排序，若专用计费 API 不要求中间结果排序，可直接省去中间排序。

**6. 中高优先级：流量聚合出队复制四个身份字符串，空 flush 也按全表预分配**

位置：[Aggregator::flush_inner](G:/Development/Project/node-agent-rs/crates/node-agent/src/traffic.rs:174)。

现有 `retain` 闭包拿不到 key 所有权，因此四次 clone 后删除原 key。`Vec::with_capacity(counters.len())` 还会在全部用户未达阈值时分配大型空结果。原位替换如下，使用 Rust 1.88 起稳定的 `HashMap::extract_if`：

```rust
fn flush_inner(&self, force: bool) -> Vec<Report> {
    let now = (self.clock)();
    let mut reports = Vec::new();
    {
        let mut state = self.state();
        for (key, value) in state.counters.extract_if(|_, value| {
            (value.uplink == 0 && value.downlink == 0)
                || force || self.should_report(value, now)
        }) {
            if value.uplink == 0 && value.downlink == 0 {
                continue;
            }
            reports.push(Report {
                machine_id: key.machine_id,
                node_id: key.node_id,
                user_id: key.user_id,
                protocol: key.protocol,
                uplink_bytes: value.uplink,
                downlink_bytes: value.downlink,
                observed_at: observation_bucket_start(value.last_observed_at),
            });
        }
    }
    reports.sort_unstable_by(|left, right| {
        left.observed_at.cmp(&right.observed_at)
            .then_with(|| left.machine_id.cmp(&right.machine_id))
            .then_with(|| left.node_id.cmp(&right.node_id))
            .then_with(|| left.user_id.cmp(&right.user_id))
            .then_with(|| left.protocol.cmp(&right.protocol))
    });
    reports
}
```

完整比较键包含唯一计数器身份，因此不需要稳定排序。该版本已验证 7 项原有聚合测试和分配对照。`extract_if` 本身不会释放 HashMap 已分配的桶；若经历高峰后需要降低常驻容量，可在长期低水位时有滞回地 shrink，而非每轮释放后重新分配。

另一处重复：[TrafficDrainKey](G:/Development/Project/node-agent-rs/crates/node-agent/src/runtime.rs:239) 与 [merge_traffic_entry](G:/Development/Project/node-agent-rs/crates/node-agent/src/runtime.rs:327) 将四个身份字段同时保存在 BTreeMap 的 key 和 value 中。可改成 `BTreeMap<TrafficDrainKey, TrafficAmounts>`，只在返回时把 key 的 String move 到 TrafficDrain：

```rust
struct TrafficAmounts {
    uplink_bytes: u64,
    downlink_bytes: u64,
    observed_at: Option<SystemTime>,
}

// 从 owned drain 拆出 key 和数值，不再 From<&TrafficDrain> 深拷贝。
let TrafficDrain {
    inbound_tag, node_id, protocol, user_id,
    uplink_bytes, downlink_bytes, observed_at,
} = drain;
let key = TrafficDrainKey { inbound_tag, node_id, protocol, user_id };
let amounts = TrafficAmounts { uplink_bytes, downlink_bytes, observed_at };
// entry(key) 中保留现有 saturating_add / max 时间合并规则。
```

此改造要同时修改 pending reservation 的校验/合并，保留 65,536 个 pending key 上限与计费所有权。它消除 key/value 双份数据，但跨轮次重复构造身份仍需共享 ID 或按入站组织聚合器进一步优化。

**7. 中高优先级：上报入队又 clone 四个字段，取消时再复制剩余批次**

位置：[enqueue](G:/Development/Project/node-agent-rs/crates/node-agent/src/traffic/stream.rs:107)、[report_to_proto](G:/Development/Project/node-agent-rs/crates/node-agent/src/traffic/stream.rs:363)。

enqueue 已拥有 `Vec<Report>`，却用 `.iter()`。成功发送的原始 String 仍保留至整轮结束，发送阻塞时尤其明显。不能简单 `.into_iter()` 后把 wire move 进 `select! send`：取消会销毁 send future 内的数据，使恢复失去报告。应先申请队列许可，再移动：

```rust
pub async fn enqueue(
    &self,
    cancel: &CancellationToken,
    aggregator: &Aggregator,
    reports: Vec<Report>,
) -> usize {
    let mut queued = 0;
    let mut reports = reports.into_iter();
    while let Some(report) = reports.next() {
        let permit = tokio::select! {
            biased;
            () = cancel.cancelled() => None,
            result = self.report_sender.reserve() => result.ok(),
        };
        let Some(permit) = permit else {
            aggregator.restore(std::iter::once(report).chain(reports));
            return queued;
        };
        permit.send(report_to_proto(report));
        queued += 1;
    }
    queued
}

fn report_to_proto(report: Report) -> TrafficReport {
    let observed_at_unix = report.observed_at_unix();
    TrafficReport {
        machine_id: report.machine_id,
        node_id: report.node_id,
        user_id: report.user_id,
        protocol: report.protocol,
        uplink_bytes: report.uplink_bytes,
        downlink_bytes: report.downlink_bytes,
        observed_at_unix,
    }
}
```

取消/队列关闭的 3 个局部场景已验证。IntoIter 仍持有整批 Vec 容量；若单轮报告数很大，应进一步分批 flush/enqueue，不能把这个改动说成结果缓冲也恒定大小。

[in_flight clone](G:/Development/Project/node-agent-rs/crates/node-agent/src/traffic/stream.rs:307) 是另一个深拷贝，但承担重连恢复语义：tonic 实际 poll 请求前必须保存报告。不能直接换成 `.take()`。后续可参照日志的 deferred stream，仅把“取数许可”放入出站队列，在 poll 时同步移动 durable slot，从而消除 clone/逐报告 oneshot；这是需要专门重连测试的独立改造。

**8. 中高优先级：完整拓扑重复保留，无变化刷新和分页仍复制全量**

位置：[model + snapshot](G:/Development/Project/node-agent-rs/crates/node-agent/src/topology/mod.rs:87)、[from_snapshot](G:/Development/Project/node-agent-rs/crates/node-agent/src/topology/proto.rs:68)、[应用副本](G:/Development/Project/node-agent-rs/crates/node-agent/src/topology/manager.rs:1516)、[无变化检查前 clone](G:/Development/Project/node-agent-rs/crates/node-agent/src/topology/manager.rs:1438)、[全量 loaded_users](G:/Development/Project/node-agent-rs/crates/node-agent/src/topology/manager.rs:1494)、[再次复制分页](G:/Development/Project/node-agent-rs/crates/node-agent/src/remote_control.rs:579)。

manager、adapter、PreparedReload 各持有/复制拓扑；`MachineTopology` 本身还同时保存模型和 protobuf 树。`RawJson` 已经共享字节，但用户 String 和 protobuf Vec 仍深拷贝。

结构改造：各发布者共享 `Arc<MachineTopology>`，任务 move/clone Arc；候选真正变更时才复制。将无变化比较提前到 clone 之前，保留 expected-current CAS、revision-only 更新和 generation 分支。已有 owned 用户列表更新模型时 move，而非 clone_from。

```rust
type SharedTopology = Arc<MachineTopology>;
// PublishedTopology / AdapterState / PreparedReload 同步使用 SharedTopology。
// TopologyRuntime::apply 接受 SharedTopology，内部异步任务 move 此 Arc。

// 在确认存在变更、保留既有 revision 处理之后：
replace_node_users(&mut next, &node_id, &users);
next.nodes[node_index].users = users;
```

不能删除原始 snapshot 并任意从模型重建：未指定/未知 protobuf 用户状态可能经模型转换成 ACTIVE，改变 ACP 摘要。

分页是独立且很值得先做的改造：目前最大页 500 条仍先复制全用户库。新增页 API，仅复制所需页，然后释放锁再网络发送：

```rust
pub async fn loaded_users_page(
    &self, node_id: &str, start: usize, limit: usize,
) -> Result<(usize, Vec<UserCredential>), TopologyError> {
    let _operation = self.operation.lock().await;
    let published = self.read_published();
    let node = published.topology.nodes.iter()
        .find(|node| node.node_id == node_id)
        .ok_or_else(|| TopologyError::new(
            TopologyErrorKind::InvalidMutation,
            format!("node {node_id} not found in loaded topology"),
        ))?;
    let total = node.users.len();
    let start = start.min(total);
    let end = start.saturating_add(limit).min(total);
    Ok((total, node.users[start..end].to_vec()))
}
```

RemoteTopology/handler 同步暴露页 API，返回值 `.into_iter().map(remote_user_credential)`。复制从 O(全库 + 页面) 降为 O(页面)。锁内引用不能直接作为跨异步任务的 `&[UserCredential]` 返回；共享快照可安全延长数据寿命。

**9. 中优先级：凭据 Box 深拷贝和 SS2022 握手分配**

位置：[凭据插入索引](G:/Development/Project/node-agent-rs/crates/shoes-engine/src/users.rs:635)、[PSK 查询](G:/Development/Project/node-agent-rs/crates/shoes-engine/src/users.rs:1129)。

Trojan/密码/Naive 的 `Box` 内容在 Entry 与 map key 中各复制一次；SS2022 每次查询还 clone 16/32 B PSK。共享 immutable 数据更符合连接生命周期：

```rust
struct ShadowsocksCredential {
    hash: [u8; 16],
    psk: Arc<[u8]>,
}
// 对应索引 key 和 Entry.password 一起使用 Arc<str>：
// DashMap<Arc<str>, Arc<Entry>>
self.by_password.insert(Arc::clone(password), Arc::clone(&entry));

// shoes-plus 的 ShadowsocksIdentity.psk 和 Blake3Key.key_bytes
// 也必须一起改为 Arc<[u8]>，否则下游转 Box 又会复制。
Some(ShadowsocksIdentity {
    user: Arc::clone(&entry.context),
    psk: Arc::clone(&credential.psk),
})
```

Arc 有计数头和原子操作；很短且只用一次的字符串未必省字节。此处收益是消除重复缓冲与每握手分配。不能借用 DashMap guard 内的 PSK 跨连接生命周期，用户删除后连接仍可能存在。

路径依赖的直接优化：[Blake3Key::create_session_key](G:/Development/Project/shoes-plus/src/shadowsocks/blake3_key.rs:29) 不需要 Vec 拼接 `key || salt`：

```rust
let mut hasher = blake3::Hasher::new_derive_key(CONTEXT_STR);
hasher.update(&self.key_bytes);
hasher.update(salt);
let mut output_reader = hasher.finalize_xof();
// 保留原长度断言和输出缓冲填充。
```

这样每次派生省一个 32/64 B 临时分配，哈希输入字节序列不变。

**10. 中优先级：日志在没有订阅者时仍分配，扇出重复复制正文**

位置：[logger 格式化](G:/Development/Project/node-agent-rs/crates/node-agent/src/logging/logger.rs:186)、[publish_remote](G:/Development/Project/node-agent-rs/crates/node-agent/src/logging/remote.rs:236)、[publish](G:/Development/Project/node-agent-rs/crates/node-agent/src/logging/remote.rs:100)。

logger 已创建完整 line；远程发布再创建带 source 前缀的 String；`publish` 对每个 subscriber clone 正文。默认单个订阅也复制一次，无订阅时远程格式化仍发生。应优先延迟构造远程正文：在 broker 锁内确认活跃订阅后才调用构造闭包，sequence 的递增和总顺序继续按原语义处理。

```rust
// 结构改造：publish_lazy 在同一排序锁范围内检查订阅并调用 make_text。
pub fn publish_lazy(&self, make_text: impl FnOnce() -> String) {
    let sequence = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
    let captured_at = (self.clock)();
    let mut state = self.state();
    state.subscribers.retain(|_, weak| weak.strong_count() != 0);
    if state.subscribers.is_empty() {
        return;
    }
    let line = RemoteLine {
        sequence, captured_at,
        text: truncate_utf8(make_text(), REMOTE_LINE_MAX_BYTES),
    };
    state.subscribers.retain(|_, weak| {
        let Some(subscription) = weak.upgrade() else { return false; };
        subscription.enqueue(line.clone());
        true
    });
}

// publish_remote 中：
// default_broker().publish_lazy(|| format!("[{source}] {line}"));
```

这个最小方向只消除无订阅构造，仍保留现有扇出 clone。单订阅可直接 move RemoteLine；多订阅再使用 `Arc<RemoteLine>` 或 `Arc<str>` 共享，并在 protobuf 边界构造 owned String。当前生产通常单订阅，不能不测就把所有日志改 Arc 后宣称更省分配。

目前截断发生在完整 format 之后，超长日志仍有瞬时大分配。需要严格峰值控制时，用限制 UTF-8 长度的 fmt::Write 在格式化期间截断，且从原始参数/切片构造，避免先创建完整远程 String。不能把已有 `truncate` 当成分配容量上限。

**11. 中优先级：控制命令只为 ACK 而复制整个 protobuf payload**

位置：[execution_command clone](G:/Development/Project/node-agent-rs/crates/node-agent/src/control/worker.rs:748)、[legacy_payload 再复制](G:/Development/Project/node-agent-rs/crates/node-agent/src/control/worker.rs:828)。

先保留轻量 ACK 元数据，再把原始 command move 给任务即可；保留 tokio::spawn 的取消隔离和 panic 捕获：

```rust
let generic = command_from_proto(&command);
// 先执行原幂等 replay 判断，再创建空结果的 ACK envelope。
let mut wire_ack = proto_ack(&command, AckStatus::Accepted, String::new());
let executor = executor.clone();
let execution_cancellation = cancellation.clone();
let joined = tokio::spawn(async move {
    executor.execute_with_cancel(command, execution_cancellation).await
}).await;
// 按原代码处理 joined / panic / cancellation / AckStore.complete。
// 最后仅写 wire_ack.status 和 wire_ack.message，并发送 wire_ack。
```

`command_from_proto` 在此仅供 AckStore 使用，而 AckStore 不读取 payload/command_type。可提取专用 AckEnvelope，避免复制 legacy_payload；不能全局删除其他执行接口真正要用的 payload。

**12. 中优先级：只为哈希或解析而创建大中间缓冲**

位置：[DNS 指纹](G:/Development/Project/node-agent-rs/crates/node-agent/src/compile.rs:192)、[URLTest 指纹](G:/Development/Project/node-agent-rs/crates/node-agent/src/compile.rs:1266)、[Engine JSON→YAML](G:/Development/Project/node-agent-rs/crates/shoes-engine/src/lib.rs:1509)、[ACP digest](G:/Development/Project/node-agent-rs/crates/acp-proto/src/digest.rs:44)、[反复算 current_digest](G:/Development/Project/node-agent-rs/crates/node-agent/src/topology/manager.rs:980)。

JSON 指纹可直接序列化到 hasher，省完整 `Vec<u8>`，保持相同 serializer 和顺序：

```rust
struct HashWriter<'a>(&'a mut Sha256);
impl std::io::Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

let mut hasher = Sha256::new();
serde_json::to_writer(
    HashWriter(&mut hasher),
    &(&topology.dns, &topology.route, &topology.outbounds),
)?; // 沿用调用点的错误转换
let dns_client_fingerprint: [u8; 32] = hasher.finalize().into();
```

Engine 已拥有 config Value，可尝试直接消费反序列化，省 JSON 文本往返：

```rust
let parsed: Config = serde_json::from_value(config)
    .map_err(|error| EngineError::InvalidConfig(error.to_string()))?;
```

依赖的手写 Deserialize 内仍会创建 YAML Value，所以这不是完整零分配解析；落地要用原 schema/alias/证书/DNS 测试验证兼容性。

ACP digest 还需 clone snapshot、稳定排序、encode_to_vec。最先可在不可变发布版本上缓存已算好的摘要：

```rust
struct PublishedTopology {
    topology: Arc<MachineTopology>,
    digest: Option<String>,
    generation: u64, // 保留原 publication token / CAS 的 generation。
}
// 发布候选时计算一次 digest；读取时借用缓存或复制小摘要。
// 仅 revision 变更可复用摘要，其余内容变化必须更新缓存。
```

这里要保留 Go 的稳定排序/golden vectors。不能把 HashWriter 直接传给 prost::Message::encode，后者需要 BufMut；彻底去掉 protobuf 输出缓冲需要专门的等价编码方案。

[规则集验证](G:/Development/Project/node-agent-rs/crates/node-agent/src/rule_set.rs:811) 还会为仅检查根对象而构建完整 JSON Value，之后 runtime 再解析，单资源允许 64 MiB。可用流式 JSON visitor 验证语法和根类型，并在资源流水线传递已验证状态：

```rust
struct ValidatedRuleSetBytes {
    format: RuleSetFormat,
    bytes: Arc<[u8]>,
}
// RuleSetFormat 为内部新增的 source/binary 枚举。
// 只允许完整 envelope + runtime 校验成功的构造函数创建此类型。
// builder 消费该类型，不再重复解析同一批 bytes。
```

这是结构方案；不能直接删除下载时验证，因为坏下载依靠它回退 last-good 缓存。也不能未经兼容测试就假定 `IgnoredAny` 与 Value 对极大数值等输入的接受范围完全相同。

**13. 低风险、可先做：clone 后丢弃字段，以及临时验证字符串**

[update_spec](G:/Development/Project/node-agent-rs/crates/node-agent/src/runtime.rs:2458) 先 clone 全量 users 再设 None；原位改为：

```rust
fn update_spec(inbound: &NormalizedInbound) -> InboundSpec {
    InboundSpec {
        tag: inbound.compiled.spec.tag.clone(),
        config: inbound.compiled.spec.config.clone(),
        users: None,
    }
}
```

[compile_users](G:/Development/Project/node-agent-rs/crates/node-agent/src/compile.rs:2391) 的临时 reported_id/identity/去重集合可借用输入；只在输出 UserSpec 时分配：

```rust
let reported_id = if user.user_id.is_empty() {
    user.name.as_str()
} else {
    user.user_id.as_str()
};
let identity = if reported_id.is_empty() && protocol == "vless" {
    user.credential.as_str()
} else {
    reported_id
};
// 保留原 empty 和重复错误分支；identities 推断为 BTreeSet<&str>。
if !identities.insert(identity) {
    return Err(CompileError::new(format!(
        "node {} lists user {:?} twice", node.node_id, identity
    )));
}
// UserSpec.id：(!reported_id.is_empty()).then(|| reported_id.to_owned())
```

[端口范围解析](G:/Development/Project/node-agent-rs/crates/node-agent/src/porthopping/port_ranges.rs:48) 不需要每个 item 创建 Vec<&str>：用 `let mut bounds = item.split('-')`，依次 `next()` 取首尾并检查第三个是否存在。`merge_port_ranges` 可在已排序 Vec 上用读写索引合并并 truncate，复用原存储；normalize 直接 `write!` 到一个 String，避免 `Vec<String>.join`。

**14. Cow 的合适用法：按需解码，保留常见分支的借用**

[decode_rfc6874_zone](G:/Development/Project/node-agent-rs/crates/node-agent/src/config.rs:361) 总创建 Vec/String，而大多数 zone 没有百分号。将原函数重命名为 `decode_rfc6874_zone_owned`，在外层加无转义快速路径：

```rust
use std::borrow::Cow;

fn decode_rfc6874_zone(encoded: &str) -> Option<Cow<'_, str>> {
    if !encoded.as_bytes().contains(&b'%') {
        if encoded.bytes().any(|byte| {
            byte.is_ascii() && !go_url_host_byte_is_allowed(byte)
        }) {
            return None;
        }
        return Some(Cow::Borrowed(encoded));
    }
    decode_rfc6874_zone_owned(encoded).map(Cow::Owned)
}
```

原 owned 解码逻辑完整保留，以维持非法 host 字节和 UTF-8 校验。调用方 format 可直接使用 Cow。这是启动/重连冷路径，优先级低于用户和流量数据。

`Cow<'static, str>` 并不能借用来自锁内或临时拓扑的动态字符串；一旦必须 `into_owned()`，通常不会减少最终分配。短期检查用 `&str`；跨任务共享用 Arc；向单一消费者交付用 move。

**15. 结构体布局结论：没有证据支持仅重新排列字段能产生主要收益**

自有 crates 未发现 `#[repr(C)]`、`#[repr(packed)]` 或自定义 alignment。默认 `repr(Rust)` 不保证声明顺序，编译器可以重排字段。[Rust Reference](https://doc.rust-lang.org/reference/type-layout.html#the-rust-representation)

| 类型 | 当前大小 | 优化实验 | 结论 |
| --- | ---: | ---: | --- |
| UserSpec，实际类型 | 128 B | 仅字段重排仍 128 B | 无重排收益 |
| UserSpec，三个 Option<u64> 改为 Option<NonZeroU64> 的镜像 | 128 B | 104 B | 省 24 B，来自类型表示 |
| Entry，同字段镜像 | 680 B | VMess 字段外置后 168 B | 稀疏大字段是重点，见第 2 项 |
| NormalizedInbound，同字段镜像 | 160 B | 改成被 Arc 引用 | 主要收益是避免复制其堆内容 |
| Undo，同字段镜像 | 368 B | 入站字段共享后 144 B | 减少 enum 最大 variant，见第 1 项 |
| Report / CounterKey，抽取当前源码 | 120 / 96 B | 移动身份字段 | 不需要靠 packed 压缩 |

UserSpec 的三个限制字段已将 None/0 定义为无限制。建议在内部规范化表示使用零值 u64 或 NonZero，外部 DTO 保持现有序列化兼容性：

```rust
use std::num::NonZeroU64;
fn finite_limit(value: Option<u64>) -> Option<NonZeroU64> {
    value.and_then(NonZeroU64::new)
}
struct UserLimits {
    max_conns: Option<NonZeroU64>,
    upload_bps: Option<NonZeroU64>,
    download_bps: Option<NonZeroU64>,
}
```

不能直接把现有可接受 0 的 serde 字段类型改成 NonZero：那会拒绝旧输入。`same_user` 对 None/Some(0) 的比较也需明确归一化边界。不建议使用 repr(packed) 处理含引用、String 和原子状态的普通运行期结构。

**16. 动态分发：有可删除的装箱，但应按路径频率排序**

| 位置 | 判断与收益 |
| --- | --- |
| [session.rs:779](G:/Development/Project/node-agent-rs/crates/node-agent/src/session.rs:779)、[820](G:/Development/Project/node-agent-rs/crates/node-agent/src/session.rs:820) | 本来已有 F/Fut 泛型，却变成 Arc<dyn Fn> + BoxFuture；每流可省一个 Arc，重连每次省一个 Future Box |
| [porthopping/manager.rs:19](G:/Development/Project/node-agent-rs/crates/node-agent/src/porthopping/manager.rs:19) | 平台已在编译时确定，可直接存 PlatformBackend 或使用 Manager<B>；通常仅初始化一次，低收益 |
| [backend_linux.rs:189](G:/Development/Project/node-agent-rs/crates/node-agent/src/porthopping/backend_linux.rs:189) | ConnectionFactory 可用 associated type 返回具体连接；每 open 少一个 Box，但只在控制面工作 |
| [runtime.rs:184](G:/Development/Project/node-agent-rs/crates/node-agent/src/runtime.rs:184) 与 TopologyRuntime/Fetcher 等 | async_trait 会返回 boxed future。仅把 Arc<dyn Trait> 改 Arc<R> 不会消除宏生成的 Box |
| [runtime.rs:588](G:/Development/Project/node-agent-rs/crates/node-agent/src/runtime.rs:588) 的 Box::pin | 明确用于限制大型事务 future 的嵌套体积；不建议统一去除 |
| 错误类型 Box<dyn Error>、构建脚本 Box | 错误/构建路径，不是主要常驻或高频成本 |
| Engine 的 Arc<dyn UserRegistry> | 共享且面向运行时协议接口；clone 只操作引用计数，不应当作复制 registry |

路径依赖还有一处更直接的嵌套分配：[shadowsocks_tcp_handler.rs:374](G:/Development/Project/shoes-plus/src/shadowsocks/shadowsocks_tcp_handler.rs:374) 创建 `Arc<Box<dyn ShadowsocksKey>>`。这里 DefaultKey/Blake3Key 存在运行时异构需求，但不需要两层堆所有权。TCP handler、UDP codec 和 stream 的字段/参数统一改为 `Arc<dyn ShadowsocksKey>`，即可省去每次创建 key 的一层分配：

```rust
fn shared_key<K: ShadowsocksKey + 'static>(key: K) -> Arc<dyn ShadowsocksKey> {
    Arc::new(key)
}
// 原 Arc::new(Box::new(Blake3Key::new(...))) 改为 shared_key(Blake3Key::new(...))。
```

这保留动态分发，省的是多余的 Box 分配；无须为了去虚调用把整个协议栈泛型化。

StreamGroup 可保留现有 JoinSet，直接让每个 spawned task 持有具体闭包。JoinSet 不要求所有 future 是同一类型：

```rust
pub fn start_auxiliary<F, Fut>(&mut self, name: impl Into<String>, runner: F)
where
    F: Fn(CancellationToken) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), SessionError>> + Send + 'static,
{
    let name = name.into();
    let cancel = self.cancel.clone();
    let policy = self.policy;
    self.tasks.spawn(async move {
        run_auxiliary_stream(cancel, runner, policy)
            .await
            .map_err(|error| SessionError::stream(name, error))
    });
}

async fn run_auxiliary_stream<F, Fut>(
    cancel: CancellationToken, runner: F, policy: RetryPolicy,
) -> Result<(), SessionError>
where
    F: Fn(CancellationToken) -> Fut + Send + Sync,
    Fut: Future<Output = Result<(), SessionError>> + Send,
{
    let mut backoff = ExponentialBackoff::new(policy.initial, policy.max);
    while !cancel.is_cancelled() {
        let started_at = Instant::now();
        let result = runner(cancel.clone()).await;
        if cancel.is_cancelled() || result.is_ok() { return Ok(()); }
        let error = result.expect_err("checked above");
        if error.is_unauthenticated() { return Err(error); }
        if started_at.elapsed() > policy.stable_after { backoff.reset(); }
        let delay = backoff.next_delay();
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            () = cancel.cancelled() => return Ok(()),
        }
    }
    Ok(())
}
```

删除不再使用的 BoxStreamFuture/StreamRunner 别名。Tokio 自身的任务分配仍然存在，具体 future 也会增大 task 大小；收益不是“所有异步堆分配归零”。

如果后续泛型化 NodeRuntime，还要同时改成原生返回 future 的 trait 方法，例如：

```rust
trait RuntimeTraffic: Send + Sync {
    fn drain_traffic(&self)
        -> impl Future<Output = Result<Vec<TrafficDrain>, RuntimeError>> + Send;
}
// 消费方使用 R: RuntimeTraffic；不能继续 dyn RuntimeTraffic。
```

只有同步移除 async_trait 的装箱边界才消除该分配；泛型单态化可能增加代码体积。[async-trait 的展开说明](https://docs.rs/async-trait/latest/async_trait/#explanation)

**建议落地顺序**

1. 先做原位修复：update_spec、聚合器 extract_if、reserve 后 move 入队、compile_users 借用、唯一 ID 的原地排序、StreamGroup 去擦除。
2. 优先治理大规模场景：共享入站/运行快照和 Undo、一次性构建 registry、稀疏 VMess 状态、按协议构造索引。
3. 再做接口联动：分页下推、非零计费 sweep、共享拓扑与凭据、PreparedInbound/ValidatedRuleSet 复用。
4. 用真实部署目标测量：稳定运行、无变化轮询、批量用户变更、全量重载、断网背压、失败回滚。记录峰值 live bytes、alloc 次数/速率、RSS 和认证延迟，保留现有计费/重连/撤销/Go digest 兼容性测试。

辅助标准库依据：[extract_if 的所有权转移](https://doc.rust-lang.org/std/collections/struct.HashMap.html#method.extract_if)、[Tokio reserve](https://docs.rs/tokio/latest/tokio/sync/mpsc/struct.Sender.html#method.reserve)、[无分配的不稳定排序](https://doc.rust-lang.org/std/primitive.slice.html#method.sort_unstable_by)、[Cow 的借用/拥有语义](https://doc.rust-lang.org/std/borrow/enum.Cow.html)。
