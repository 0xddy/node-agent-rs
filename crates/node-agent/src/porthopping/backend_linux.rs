// Linux nftables backend implemented directly on `NETLINK_NETFILTER`.
//
// Changes are submitted as one nftables batch. Before deleting anything the
// backend proves ownership from table/chain userdata and every rule marker.
// Deletes include the inspected table handle as a final guard against a
// same-name table being replaced between inspection and commit.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::io;
use std::os::fd::AsRawFd as _;
use std::sync::Arc;

use netlink_packet_core::{
    DefaultNla, Emitable as _, NLA_F_NESTED, NLM_F_ACK, NLM_F_APPEND, NLM_F_CREATE, NLM_F_DUMP,
    NLM_F_EXCL, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload, Nla as _, NlasIterator,
};
use netlink_packet_netfilter::nftables::{
    ChainAttribute, ChainMessage, Cmp, DataAttribute, ExpressionAttribute, Expressions, Hook,
    Immediate, InetHookNumber, ListAttribute, Meta, MetaKey, NfTablesMessage, Operator, Payload,
    Register, RuleAttribute, RuleMessage, TableAttribute, TableMessage, Verdict, VerdictAttribute,
};
use netlink_packet_netfilter::none::ControlMessage;
use netlink_packet_netfilter::{
    NetfilterHeader, NetfilterMessage, NetfilterMessageInner, NetfilterProtoFamily,
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_NETFILTER};
use sha2::{Digest as _, Sha256};

use super::errors::{
    BackendResult, BoxError, CapabilityError, OperationError, StateUncertainError,
};
use super::manager::Backend;
use super::plan::{Plan, Redirect, first_overlap, lower_hex};
use super::port_ranges::PortRange;

const TABLE_PREFIX: &str = "acp_hy2_";
const CHAIN_NAME: &str = "prerouting";
const RULE_MARKER_MAGIC: &[u8] = b"ACPHY2\x01";
const TABLE_MARKER_MAGIC: &[u8] = b"ACPHY2T\x01";
const CHAIN_MARKER_MAGIC: &[u8] = b"ACPHY2C\x01";
const MARKER_PROTOCOL: u8 = 1;
const MAX_NODE_ID_BYTES: usize = 128;
const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NF_ACCEPT: u32 = 1;
const NF_IP_PRI_NAT_DST: i32 = -100;
const IPPROTO_UDP: u8 = 17;
const PAYLOAD_BASE_TRANSPORT_HEADER: u32 = 2;
const NF_NAT_RANGE_PROTO_SPECIFIED: u32 = 2;
const NLA_TYPE_MASK: u16 = 0x3fff;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Family {
    Inet,
    Ipv4,
    Ipv6,
}

impl Family {
    const ALL: [Self; 3] = [Self::Inet, Self::Ipv4, Self::Ipv6];

    fn protocol(self) -> NetfilterProtoFamily {
        match self {
            Self::Inet => NetfilterProtoFamily::Inet,
            Self::Ipv4 => NetfilterProtoFamily::IPv4,
            Self::Ipv6 => NetfilterProtoFamily::IPv6,
        }
    }

    fn from_protocol(family: NetfilterProtoFamily) -> Option<Self> {
        match family {
            NetfilterProtoFamily::Inet => Some(Self::Inet),
            NetfilterProtoFamily::IPv4 => Some(Self::Ipv4),
            NetfilterProtoFamily::IPv6 => Some(Self::Ipv6),
            _ => None,
        }
    }
}

impl fmt::Display for Family {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Inet => "inet",
            Self::Ipv4 => "ip",
            Self::Ipv6 => "ip6",
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum FamilyMode {
    #[default]
    Unknown,
    Inet,
    Split,
}

impl FamilyMode {
    fn families(self) -> &'static [Family] {
        match self {
            Self::Unknown => &[],
            Self::Inet => &[Family::Inet],
            Self::Split => &[Family::Ipv4, Family::Ipv6],
        }
    }
}

impl fmt::Display for FamilyMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unknown => "unknown",
            Self::Inet => "inet",
            Self::Split => "ip+ip6",
        })
    }
}

#[derive(Debug, Clone)]
struct TableState {
    family: Family,
    name: String,
    handle: u64,
    user_data: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ChainState {
    family: Family,
    table: String,
    name: String,
    chain_type: Option<String>,
    hook: Option<u32>,
    priority: Option<i32>,
    policy: Option<u32>,
    user_data: Vec<u8>,
}

#[derive(Debug, Clone)]
struct RuleState {
    family: Family,
    table: String,
    chain: String,
    expressions: Vec<ListAttribute<ExpressionAttribute>>,
    user_data: Vec<u8>,
}

#[derive(Debug, Default, Clone)]
struct KernelSnapshot {
    tables: Vec<TableState>,
    chains: Vec<ChainState>,
    rules: Vec<RuleState>,
    unavailable: BTreeMap<Family, i32>,
}

#[derive(Debug, Clone)]
struct DeleteTable {
    family: Family,
    name: String,
    handle: u64,
}

#[derive(Debug, Clone)]
struct DesiredTable {
    family: Family,
    name: String,
    table_marker: Vec<u8>,
    chain_marker: Vec<u8>,
    rules: Vec<DesiredRule>,
}

#[derive(Debug, Clone)]
struct DesiredRule {
    expressions: Vec<ListAttribute<ExpressionAttribute>>,
    marker: Vec<u8>,
}

#[derive(Debug, Default, Clone)]
struct Batch {
    delete: Vec<DeleteTable>,
    create: Vec<DesiredTable>,
}

trait NftConnection: Send {
    fn snapshot(&mut self) -> io::Result<KernelSnapshot>;
    fn execute(&mut self, batch: &Batch) -> io::Result<()>;
}

trait ConnectionFactory: Send + Sync {
    fn open(&self) -> io::Result<Box<dyn NftConnection>>;
}

struct SystemFactory;

impl ConnectionFactory for SystemFactory {
    fn open(&self) -> io::Result<Box<dyn NftConnection>> {
        Ok(Box::new(NetlinkConnection::open()?))
    }
}

pub(super) struct NftBackend {
    table_name: String,
    owner: [u8; 6],
    factory: Arc<dyn ConnectionFactory>,
    managed: bool,
    mode: FamilyMode,
}

impl NftBackend {
    pub(super) fn new(machine_id: &str) -> Self {
        let owner = owner_hash(machine_id);
        Self {
            table_name: format!("{TABLE_PREFIX}{}", lower_hex(&owner)),
            owner,
            factory: Arc::new(SystemFactory),
            managed: false,
            mode: FamilyMode::Unknown,
        }
    }

    #[cfg(test)]
    fn with_factory(machine_id: &str, factory: Arc<dyn ConnectionFactory>) -> Self {
        let mut backend = Self::new(machine_id);
        backend.factory = factory;
        backend
    }

    fn open(&self) -> io::Result<Box<dyn NftConnection>> {
        self.factory.open()
    }

    fn inspect(&self, raw: KernelSnapshot) -> BackendResult<InspectedState> {
        inspect_snapshot(&self.table_name, self.owner, raw)
    }

    fn inspect_fresh(&self) -> BackendResult<InspectedState> {
        let mut connection = self
            .open()
            .map_err(|error| wrap_io("open nftables netlink connection for verification", error))?;
        let raw = connection
            .snapshot()
            .map_err(|error| wrap_io("inspect nftables state for verification", error))?;
        self.inspect(raw)
    }

    fn select_mode(&self, current: &InspectedState) -> FamilyMode {
        if current.complete {
            return current.mode;
        }
        if self.mode != FamilyMode::Unknown {
            return self.mode;
        }
        if current.mode != FamilyMode::Unknown {
            return current.mode;
        }
        if !current.exists && current.family_unavailable(Family::Inet) {
            return FamilyMode::Split;
        }
        FamilyMode::Inet
    }

    fn apply_state(
        &mut self,
        connection: &mut dyn NftConnection,
        current: &InspectedState,
        desired: &Plan,
        desired_digest: &str,
        mode: FamilyMode,
    ) -> Result<(), ApplyStateError> {
        let batch = build_batch(
            &self.table_name,
            self.owner,
            current,
            desired,
            desired_digest,
            mode,
        )
        .map_err(ApplyStateError::Certain)?;

        // From this point an error can mean either side of an atomic commit.
        self.managed = current.exists || !desired.is_empty();
        match connection.execute(&batch) {
            Ok(()) => {
                self.managed = !desired.is_empty();
                if !desired.is_empty() {
                    self.mode = mode;
                }
                Ok(())
            }
            Err(submit_error) => {
                let verification = self.inspect_fresh();
                if let Ok(fresh) = &verification
                    && fresh.matches(mode, desired_digest, desired.rule_count())
                {
                    self.managed = !desired.is_empty();
                    if !desired.is_empty() {
                        self.mode = mode;
                    }
                    return Ok(());
                }
                if !current.exists
                    && is_capability_errno(&submit_error)
                    && verification.as_ref().is_ok_and(|fresh| !fresh.exists)
                {
                    self.managed = false;
                    return Err(ApplyStateError::Unsupported {
                        mode,
                        source: submit_error,
                    });
                }

                let mut message = format!("apply nftables port hopping state: {submit_error}");
                if let Err(verify_error) = verification {
                    message.push_str("; verify state after failed acknowledgement: ");
                    message.push_str(&verify_error.to_string());
                }
                Err(ApplyStateError::Uncertain(Box::new(
                    StateUncertainError::new(OperationError::message(message)),
                )))
            }
        }
    }

    fn retry_split(
        &mut self,
        desired: &Plan,
        desired_digest: &str,
        inet_error: io::Error,
    ) -> BackendResult {
        let mut connection = self.open().map_err(|error| {
            boxed_operation(format!(
                "apply nftables inet port hopping state: {inet_error}; reopen before ip+ip6 fallback: {error}"
            ))
        })?;
        let raw = connection.snapshot().map_err(|error| {
            boxed_operation(format!(
                "apply nftables inet port hopping state: {inet_error}; inspect before ip+ip6 fallback: {error}"
            ))
        })?;
        let current = self.inspect(raw)?;
        if current.matches(FamilyMode::Inet, desired_digest, desired.rule_count()) {
            self.managed = true;
            self.mode = FamilyMode::Inet;
            return Ok(());
        }
        if current.exists {
            return Err(boxed_operation(format!(
                "apply nftables inet port hopping state: {inet_error}; cannot safely retry with ip+ip6 because nftables state changed after the rejected inet batch"
            )));
        }
        reject_external_conflicts(&current.raw, &self.table_name, desired)?;
        match self.apply_state(
            connection.as_mut(),
            &current,
            desired,
            desired_digest,
            FamilyMode::Split,
        ) {
            Ok(()) => Ok(()),
            Err(ApplyStateError::Unsupported { mode, source }) => {
                Err(capability_error(mode, source))
            }
            Err(ApplyStateError::Certain(error) | ApplyStateError::Uncertain(error)) => Err(error),
        }
    }
}

impl Backend for NftBackend {
    fn apply(&mut self, desired: &Plan) -> BackendResult {
        let mut connection = match self.open() {
            Ok(connection) => connection,
            Err(error)
                if desired.is_empty()
                    && !self.managed
                    && (is_permission_errno(&error) || is_capability_errno(&error)) =>
            {
                return Ok(());
            }
            Err(error) if is_capability_errno(&error) => {
                return Err(capability_error(self.mode, error));
            }
            Err(error) => return Err(wrap_io("open nftables netlink connection", error)),
        };
        let raw = match connection.snapshot() {
            Ok(raw) => raw,
            Err(error) if desired.is_empty() && !self.managed && is_permission_errno(&error) => {
                return Ok(());
            }
            Err(error) => return Err(wrap_io("inspect nftables state", error)),
        };
        let current = self.inspect(raw)?;
        if current.exists {
            self.managed = true;
        }
        if current.complete {
            self.mode = current.mode;
        }
        if desired.is_empty() && self.managed && current.unavailable_for(self.mode) {
            return Err(boxed_operation(format!(
                "cannot verify cleanup of previously managed nftables {} state because its kernel family is unavailable",
                self.mode
            )));
        }
        if !desired.is_empty() {
            reject_external_conflicts(&current.raw, &self.table_name, desired)?;
        }

        let digest = desired.digest();
        let mode = self.select_mode(&current);
        if current.matches(mode, &digest, desired.rule_count()) {
            return Ok(());
        }
        if desired.is_empty() && !current.exists {
            self.managed = false;
            return Ok(());
        }
        let can_fallback =
            !current.exists && self.mode == FamilyMode::Unknown && mode == FamilyMode::Inet;
        match self.apply_state(connection.as_mut(), &current, desired, &digest, mode) {
            Ok(()) => Ok(()),
            Err(ApplyStateError::Unsupported { mode, source }) if can_fallback => {
                debug_assert_eq!(mode, FamilyMode::Inet);
                self.retry_split(desired, &digest, source)
            }
            Err(ApplyStateError::Unsupported { mode, source }) => {
                Err(capability_error(mode, source))
            }
            Err(ApplyStateError::Certain(error) | ApplyStateError::Uncertain(error)) => Err(error),
        }
    }
}

enum ApplyStateError {
    Certain(BoxError),
    Unsupported { mode: FamilyMode, source: io::Error },
    Uncertain(BoxError),
}

fn capability_error(mode: FamilyMode, source: io::Error) -> BoxError {
    Box::new(
        CapabilityError::new(
            "linux",
            "nftables UDP destination-port redirect",
            format!(
                "kernel rejected the {mode} NAT representation: {source}; enable nf_tables, nft_nat and nft_redir support or use a supported kernel"
            ),
        )
        .with_source(source),
    )
}

fn is_capability_errno(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EOPNOTSUPP)
            | Some(libc::EAFNOSUPPORT)
            | Some(libc::EPROTONOSUPPORT)
            | Some(libc::ENOSYS)
            | Some(libc::ENOENT)
            | Some(libc::ENODEV)
    )
}

fn is_permission_errno(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES))
}

fn wrap_io(message: impl Into<String>, error: io::Error) -> BoxError {
    Box::new(OperationError::wrap(message, Box::new(error)))
}

fn boxed_operation(message: impl Into<String>) -> BoxError {
    Box::new(OperationError::message(message))
}

#[derive(Debug)]
struct InspectedState {
    raw: KernelSnapshot,
    tables: Vec<TableState>,
    exists: bool,
    mode: FamilyMode,
    complete: bool,
    digest: String,
    rule_count: usize,
}

impl InspectedState {
    fn family_unavailable(&self, family: Family) -> bool {
        self.raw.unavailable.contains_key(&family)
    }

    fn unavailable_for(&self, mode: FamilyMode) -> bool {
        let families: &[Family] = if mode == FamilyMode::Unknown {
            &Family::ALL
        } else {
            mode.families()
        };
        families
            .iter()
            .any(|family| self.family_unavailable(*family))
    }

    fn matches(&self, mode: FamilyMode, digest: &str, rule_count: usize) -> bool {
        if rule_count == 0 {
            return !self.exists;
        }
        self.exists
            && self.complete
            && self.mode == mode
            && self.digest == digest
            && self.rule_count == rule_count
    }
}

fn inspect_snapshot(
    table_name: &str,
    owner: [u8; 6],
    raw: KernelSnapshot,
) -> BackendResult<InspectedState> {
    let mut tables = Vec::new();
    for family in Family::ALL {
        let mut matching = raw
            .tables
            .iter()
            .filter(|table| table.family == family && table.name == table_name);
        if let Some(first) = matching.next() {
            if matching.next().is_some() {
                return Err(boxed_operation(format!(
                    "nftables table {table_name} is ambiguous: duplicate {family} tables"
                )));
            }
            tables.push(first.clone());
        }
    }
    if tables.is_empty() {
        return Ok(InspectedState {
            raw,
            tables,
            exists: false,
            mode: FamilyMode::Unknown,
            complete: false,
            digest: String::new(),
            rule_count: 0,
        });
    }

    let mut first_digest = None;
    let mut first_count = 0;
    let mut consistent = true;
    for table in &tables {
        let (digest, count) = inspect_managed_table(table_name, owner, table, &raw)?;
        if let Some(expected) = &first_digest {
            if expected != &digest || first_count != count {
                consistent = false;
            }
        } else {
            first_digest = Some(digest);
            first_count = count;
        }
    }
    let has_inet = tables.iter().any(|table| table.family == Family::Inet);
    let has_ipv4 = tables.iter().any(|table| table.family == Family::Ipv4);
    let has_ipv6 = tables.iter().any(|table| table.family == Family::Ipv6);
    let (mode, complete) = match (has_inet, has_ipv4, has_ipv6) {
        (true, false, false) => (FamilyMode::Inet, consistent),
        (false, true, true) => (FamilyMode::Split, consistent),
        (false, true, false) | (false, false, true) => (FamilyMode::Split, false),
        _ => (FamilyMode::Unknown, false),
    };
    Ok(InspectedState {
        raw,
        tables,
        exists: true,
        mode,
        complete,
        digest: if consistent {
            first_digest.unwrap_or_default()
        } else {
            String::new()
        },
        rule_count: if consistent { first_count } else { 0 },
    })
}

fn inspect_managed_table(
    table_name: &str,
    owner: [u8; 6],
    table: &TableState,
    raw: &KernelSnapshot,
) -> BackendResult<(String, usize)> {
    let label = format!("{}/{table_name}", table.family);
    let table_marker = decode_optional_container_marker(&table.user_data, TABLE_MARKER_MAGIC)
        .map_err(|error| {
            boxed_operation(format!(
                "nftables table {label} is not owned by this node-agent: {error}"
            ))
        })?;
    if table_marker
        .as_ref()
        .is_some_and(|marker| marker.owner != owner)
    {
        return Err(boxed_operation(format!(
            "nftables table {label} is not owned by this node-agent"
        )));
    }

    let chains: Vec<_> = raw
        .chains
        .iter()
        .filter(|chain| chain.family == table.family && chain.table == table_name)
        .collect();
    if chains.len() != 1 {
        return Err(boxed_operation(format!(
            "nftables table {label} is not owned by node-agent: expected one managed chain, found {}",
            chains.len()
        )));
    }
    let chain = chains[0];
    if chain.name != CHAIN_NAME {
        return Err(boxed_operation(format!(
            "nftables table {label} is not owned by node-agent: unexpected chain {}",
            chain.name
        )));
    }
    if !is_managed_chain(chain) {
        return Err(boxed_operation(format!(
            "nftables table {label} is not owned by node-agent: managed chain shape is invalid"
        )));
    }
    let chain_marker = decode_optional_container_marker(&chain.user_data, CHAIN_MARKER_MAGIC)
        .map_err(|error| {
            boxed_operation(format!(
                "nftables table {label} is not owned by this node-agent: {error}"
            ))
        })?;
    if chain_marker
        .as_ref()
        .is_some_and(|marker| marker.owner != owner)
    {
        return Err(boxed_operation(format!(
            "nftables table {label} is not owned by this node-agent"
        )));
    }

    let rules: Vec<_> = raw
        .rules
        .iter()
        .filter(|rule| {
            rule.family == table.family && rule.table == table_name && rule.chain == CHAIN_NAME
        })
        .collect();
    if rules.is_empty() {
        return Err(boxed_operation(format!(
            "nftables table {label} is not owned by node-agent: ownership marker is missing"
        )));
    }
    let digest = inspect_owned_rules(&label, owner, &rules)?;
    if table_marker
        .as_ref()
        .is_some_and(|marker| marker.digest != digest)
        || chain_marker
            .as_ref()
            .is_some_and(|marker| marker.digest != digest)
    {
        return Err(boxed_operation(format!(
            "nftables table {label} ownership metadata contains an inconsistent container marker"
        )));
    }
    Ok((digest, rules.len()))
}

fn is_managed_chain(chain: &ChainState) -> bool {
    chain.name == CHAIN_NAME
        && chain.chain_type.as_deref() == Some("nat")
        && chain.hook == Some(u32::from(InetHookNumber::PreRouting))
        && chain.priority == Some(NF_IP_PRI_NAT_DST)
        && chain.policy == Some(NF_ACCEPT)
}

fn inspect_owned_rules(
    table_label: &str,
    owner: [u8; 6],
    rules: &[&RuleState],
) -> BackendResult<String> {
    let mut digest: Option<String> = None;
    let mut redirects = BTreeMap::<String, Redirect>::new();
    for rule in rules {
        let marker = decode_rule_marker(&rule.user_data).map_err(|error| {
            boxed_operation(format!(
                "nftables table {table_label} is not owned by this node-agent: {error}"
            ))
        })?;
        if marker.owner != owner {
            return Err(boxed_operation(format!(
                "nftables table {table_label} is not owned by this node-agent"
            )));
        }
        if let Some(expected) = &digest {
            if expected != &marker.digest {
                return Err(boxed_operation(format!(
                    "nftables table {table_label} contains inconsistent ownership markers"
                )));
            }
        } else {
            digest = Some(marker.digest.clone());
        }
        let Some((source, target)) = managed_redirect_rule(&rule.expressions) else {
            return Err(boxed_operation(format!(
                "nftables table {table_label} contains a managed rule that does not match its ownership metadata"
            )));
        };
        if source != marker.ports || target != marker.listen_port {
            return Err(boxed_operation(format!(
                "nftables table {table_label} contains a managed rule that does not match its ownership metadata"
            )));
        }
        let redirect = redirects
            .entry(marker.node_id.clone())
            .or_insert_with(|| Redirect {
                node_id: marker.node_id.clone(),
                listen_port: marker.listen_port,
                ports: Vec::new(),
            });
        if redirect.listen_port != marker.listen_port {
            return Err(boxed_operation(format!(
                "nftables table {table_label} contains inconsistent listen ports for node {}",
                marker.node_id
            )));
        }
        redirect.ports.push(marker.ports);
    }
    let mut plan = Plan {
        redirects: redirects.into_values().collect(),
    };
    for redirect in &mut plan.redirects {
        redirect.ports.sort_unstable();
    }
    let digest = digest.unwrap_or_default();
    if plan.digest() != digest {
        return Err(boxed_operation(format!(
            "nftables table {table_label} ownership metadata does not match its plan digest"
        )));
    }
    Ok(digest)
}

fn build_batch(
    table_name: &str,
    owner: [u8; 6],
    current: &InspectedState,
    desired: &Plan,
    digest: &str,
    mode: FamilyMode,
) -> BackendResult<Batch> {
    let delete = current
        .tables
        .iter()
        .map(|table| DeleteTable {
            family: table.family,
            name: table.name.clone(),
            handle: table.handle,
        })
        .collect();
    let mut create = Vec::new();
    if !desired.is_empty() {
        if mode.families().is_empty() {
            return Err(boxed_operation(format!(
                "select nftables family for port hopping: mode is {mode}"
            )));
        }
        let table_marker = encode_container_marker(TABLE_MARKER_MAGIC, owner, digest)?;
        let chain_marker = encode_container_marker(CHAIN_MARKER_MAGIC, owner, digest)?;
        for family in mode.families() {
            let mut rules = Vec::with_capacity(desired.rule_count());
            for redirect in &desired.redirects {
                for ports in &redirect.ports {
                    rules.push(DesiredRule {
                        expressions: redirect_expressions(*ports, redirect.listen_port),
                        marker: encode_rule_marker(owner, digest, redirect, *ports)?,
                    });
                }
            }
            create.push(DesiredTable {
                family: *family,
                name: table_name.to_owned(),
                table_marker: table_marker.clone(),
                chain_marker: chain_marker.clone(),
                rules,
            });
        }
    }
    Ok(Batch { delete, create })
}

#[derive(Debug, Clone)]
struct ContainerMarker {
    owner: [u8; 6],
    digest: String,
}

fn encode_container_marker(magic: &[u8], owner: [u8; 6], digest: &str) -> BackendResult<Vec<u8>> {
    let digest = decode_digest(digest)?;
    let mut data = Vec::with_capacity(magic.len() + owner.len() + digest.len());
    data.extend_from_slice(magic);
    data.extend_from_slice(&owner);
    data.extend_from_slice(&digest);
    Ok(data)
}

fn decode_optional_container_marker(
    data: &[u8],
    magic: &[u8],
) -> Result<Option<ContainerMarker>, &'static str> {
    // Adopt Go-created tables whose ownership is proven by their rule markers.
    if data.is_empty() {
        return Ok(None);
    }
    if data.len() != magic.len() + 6 + 32 || !data.starts_with(magic) {
        return Err("container ownership marker is missing or invalid");
    }
    let mut owner = [0; 6];
    owner.copy_from_slice(&data[magic.len()..magic.len() + 6]);
    Ok(Some(ContainerMarker {
        owner,
        digest: lower_hex(&data[magic.len() + 6..]),
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleMarker {
    owner: [u8; 6],
    digest: String,
    node_id: String,
    listen_port: u16,
    ports: PortRange,
}

fn encode_rule_marker(
    owner: [u8; 6],
    digest: &str,
    redirect: &Redirect,
    ports: PortRange,
) -> BackendResult<Vec<u8>> {
    let node = redirect.node_id.as_bytes();
    if node.is_empty() {
        return Err(boxed_operation("encode nftables marker: node_id is empty"));
    }
    if node.len() > MAX_NODE_ID_BYTES {
        return Err(boxed_operation(format!(
            "encode nftables marker: node_id is {} bytes, maximum is {MAX_NODE_ID_BYTES}",
            node.len()
        )));
    }
    if redirect.listen_port == 0 || ports.start == 0 || ports.start > ports.end {
        return Err(boxed_operation(
            "encode nftables marker: invalid redirect metadata",
        ));
    }
    let digest = decode_digest(digest)?;
    let mut data = Vec::with_capacity(RULE_MARKER_MAGIC.len() + 6 + 32 + 8 + node.len());
    data.extend_from_slice(RULE_MARKER_MAGIC);
    data.extend_from_slice(&owner);
    data.extend_from_slice(&digest);
    data.push(MARKER_PROTOCOL);
    data.extend_from_slice(&redirect.listen_port.to_be_bytes());
    data.extend_from_slice(&ports.start.to_be_bytes());
    data.extend_from_slice(&ports.end.to_be_bytes());
    data.push(node.len() as u8);
    data.extend_from_slice(node);
    Ok(data)
}

fn decode_rule_marker(data: &[u8]) -> Result<RuleMarker, &'static str> {
    let fixed = RULE_MARKER_MAGIC.len() + 6 + 32 + 1 + 2 + 2 + 2 + 1;
    if data.len() < fixed || !data.starts_with(RULE_MARKER_MAGIC) {
        return Err("ownership marker is missing or invalid");
    }
    let mut offset = RULE_MARKER_MAGIC.len();
    let mut owner = [0; 6];
    owner.copy_from_slice(&data[offset..offset + 6]);
    offset += 6;
    let digest = lower_hex(&data[offset..offset + 32]);
    offset += 32;
    if data[offset] != MARKER_PROTOCOL {
        return Err("unknown protocol marker");
    }
    offset += 1;
    let listen_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    let start = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    let end = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    let node_len = usize::from(data[offset]);
    offset += 1;
    if node_len == 0 || node_len > MAX_NODE_ID_BYTES || data.len() != offset + node_len {
        return Err("invalid node_id length in ownership marker");
    }
    let node_id = std::str::from_utf8(&data[offset..])
        .map_err(|_| "invalid UTF-8 node_id in ownership marker")?
        .to_owned();
    if listen_port == 0 || start == 0 || start > end {
        return Err("invalid redirect values in ownership marker");
    }
    Ok(RuleMarker {
        owner,
        digest,
        node_id,
        listen_port,
        ports: PortRange::new(start, end),
    })
}

fn decode_digest(digest: &str) -> BackendResult<[u8; 32]> {
    if digest.len() != 64 {
        return Err(boxed_operation(format!("invalid plan digest {digest:?}")));
    }
    let mut bytes = [0; 32];
    for (index, pair) in digest.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])
            .ok_or_else(|| boxed_operation(format!("invalid plan digest {digest:?}")))?;
        let low = hex_nibble(pair[1])
            .ok_or_else(|| boxed_operation(format!("invalid plan digest {digest:?}")))?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn owner_hash(machine_id: &str) -> [u8; 6] {
    let digest = Sha256::digest(machine_id.as_bytes());
    let mut owner = [0; 6];
    owner.copy_from_slice(&digest[..6]);
    owner
}

fn redirect_expressions(ports: PortRange, target: u16) -> Vec<ListAttribute<ExpressionAttribute>> {
    let mut expressions = vec![
        Expressions::Meta(vec![
            Meta::Key(MetaKey::L4Proto),
            Meta::DestinationRegister(Register::Reg1),
        ])
        .into(),
        Expressions::Cmp(vec![
            Cmp::SourceRegister(Register::Reg1),
            Cmp::Op(Operator::Equal),
            Cmp::Data(DataAttribute::Value(vec![IPPROTO_UDP])),
        ])
        .into(),
        Expressions::Payload(vec![
            Payload::DestinationRegister(Register::Reg1),
            Payload::Base(PAYLOAD_BASE_TRANSPORT_HEADER),
            Payload::Offset(2),
            Payload::Len(2),
        ])
        .into(),
    ];
    if ports.start == ports.end {
        expressions.push(
            Expressions::Cmp(vec![
                Cmp::SourceRegister(Register::Reg1),
                Cmp::Op(Operator::Equal),
                Cmp::Data(DataAttribute::Value(ports.start.to_be_bytes().to_vec())),
            ])
            .into(),
        );
    } else {
        expressions.push(raw_expression(
            "range",
            vec![
                be_u32_attr(1, Register::Reg1.into()),
                be_u32_attr(2, Operator::Equal.into()),
                nested_data_attr(3, ports.start.to_be_bytes().to_vec()),
                nested_data_attr(4, ports.end.to_be_bytes().to_vec()),
            ],
        ));
    }
    expressions.push(
        Expressions::Immediate(vec![
            Immediate::DestinationRegister(Register::Reg2),
            Immediate::Data(DataAttribute::Value(target.to_be_bytes().to_vec())),
        ])
        .into(),
    );
    expressions.push(raw_expression(
        "redir",
        vec![be_u32_attr(1, Register::Reg2.into())],
    ));
    expressions
}

fn raw_expression(
    expression_type: &str,
    attributes: Vec<DefaultNla>,
) -> ListAttribute<ExpressionAttribute> {
    Expressions::Other {
        expression_type: expression_type.to_owned(),
        attributes,
    }
    .into()
}

fn be_u32_attr(kind: u16, value: u32) -> DefaultNla {
    DefaultNla::new(kind, value.to_be_bytes().to_vec())
}

fn nested_data_attr(kind: u16, value: Vec<u8>) -> DefaultNla {
    let data = DataAttribute::Value(value);
    let mut nested = vec![0; data.buffer_len()];
    data.emit(&mut nested);
    DefaultNla::new(kind | NLA_F_NESTED, nested)
}

fn expression_data(expression: &ListAttribute<ExpressionAttribute>) -> Option<&Expressions> {
    let ListAttribute::Element(attributes) = expression else {
        return None;
    };
    attributes.iter().find_map(|attribute| match attribute {
        ExpressionAttribute::Data(data) => Some(data),
        _ => None,
    })
}

fn managed_redirect_rule(
    expressions: &[ListAttribute<ExpressionAttribute>],
) -> Option<(PortRange, u16)> {
    if expressions.len() != 6 {
        return None;
    }
    if !meta_loads_l4proto(expression_data(&expressions[0])?, Register::Reg1)
        || !cmp_equals(
            expression_data(&expressions[1])?,
            Register::Reg1,
            &[IPPROTO_UDP],
        )
        || !payload_loads_dport(expression_data(&expressions[2])?, Register::Reg1)
    {
        return None;
    }
    let ports = port_match(expression_data(&expressions[3])?, Register::Reg1)?;
    let target = immediate_port(expression_data(&expressions[4])?, Register::Reg2)?;
    if target == 0 || !redir_uses(expression_data(&expressions[5])?, Register::Reg2) {
        return None;
    }
    Some((ports, target))
}

fn meta_loads_l4proto(expression: &Expressions, register: Register) -> bool {
    let Expressions::Meta(attributes) = expression else {
        return false;
    };
    let mut key = false;
    let mut destination = false;
    for attribute in attributes {
        match attribute {
            Meta::Key(MetaKey::L4Proto) => key = true,
            Meta::DestinationRegister(found) if *found == register => destination = true,
            _ => return false,
        }
    }
    key && destination
}

fn cmp_equals(expression: &Expressions, register: Register, expected: &[u8]) -> bool {
    let Expressions::Cmp(attributes) = expression else {
        return false;
    };
    let mut source = false;
    let mut equal = false;
    let mut data = None;
    for attribute in attributes {
        match attribute {
            Cmp::SourceRegister(found) if *found == register => source = true,
            Cmp::Op(Operator::Equal) => equal = true,
            Cmp::Data(DataAttribute::Value(value)) => data = Some(value.as_slice()),
            _ => return false,
        }
    }
    source && equal && data == Some(expected)
}

fn payload_loads_dport(expression: &Expressions, register: Register) -> bool {
    let Expressions::Payload(attributes) = expression else {
        return false;
    };
    let mut destination = false;
    let mut base = false;
    let mut offset = false;
    let mut length = false;
    for attribute in attributes {
        match attribute {
            Payload::DestinationRegister(found) if *found == register => destination = true,
            Payload::Base(PAYLOAD_BASE_TRANSPORT_HEADER) => base = true,
            Payload::Offset(2) => offset = true,
            Payload::Len(2) => length = true,
            _ => return false,
        }
    }
    destination && base && offset && length
}

fn port_match(expression: &Expressions, register: Register) -> Option<PortRange> {
    match expression {
        Expressions::Cmp(_) => {
            let data = cmp_equal_data(expression, register)?;
            if data.len() != 2 {
                return None;
            }
            let port = u16::from_be_bytes([data[0], data[1]]);
            (port != 0).then_some(PortRange::new(port, port))
        }
        Expressions::Other {
            expression_type,
            attributes,
        } if expression_type == "range" => {
            let (source, op, from, to) = parse_range_attributes(attributes)?;
            if source != register || op != Operator::Equal || from.len() != 2 || to.len() != 2 {
                return None;
            }
            let start = u16::from_be_bytes([from[0], from[1]]);
            let end = u16::from_be_bytes([to[0], to[1]]);
            (start != 0 && start <= end).then_some(PortRange::new(start, end))
        }
        _ => None,
    }
}

fn cmp_equal_data(expression: &Expressions, register: Register) -> Option<&[u8]> {
    let Expressions::Cmp(attributes) = expression else {
        return None;
    };
    let mut source = None;
    let mut op = None;
    let mut data = None;
    for attribute in attributes {
        match attribute {
            Cmp::SourceRegister(value) => source = Some(*value),
            Cmp::Op(value) => op = Some(*value),
            Cmp::Data(DataAttribute::Value(value)) => data = Some(value.as_slice()),
            _ => return None,
        }
    }
    (source == Some(register) && op == Some(Operator::Equal)).then_some(data?)
}

fn immediate_port(expression: &Expressions, register: Register) -> Option<u16> {
    let Expressions::Immediate(attributes) = expression else {
        return None;
    };
    let mut destination = None;
    let mut data = None;
    for attribute in attributes {
        match attribute {
            Immediate::DestinationRegister(value) => destination = Some(*value),
            Immediate::Data(DataAttribute::Value(value)) => data = Some(value.as_slice()),
            _ => return None,
        }
    }
    let bytes = data?;
    if destination != Some(register) || bytes.len() != 2 {
        return None;
    }
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn redir_uses(expression: &Expressions, register: Register) -> bool {
    let Expressions::Other {
        expression_type,
        attributes,
    } = expression
    else {
        return false;
    };
    if expression_type != "redir" {
        return false;
    }
    let mut minimum = None;
    let mut maximum = None;
    let mut flags = None;
    for attribute in attributes {
        let value = nla_value(attribute);
        match nla_kind(attribute) {
            1 => minimum = read_be_u32(&value).map(Register::from),
            2 => maximum = read_be_u32(&value).map(Register::from),
            3 => flags = read_be_u32(&value),
            _ => return false,
        }
    }
    minimum == Some(register)
        && maximum.is_none_or(|maximum| maximum == register)
        && flags.is_none_or(|flags| flags == 0 || flags == NF_NAT_RANGE_PROTO_SPECIFIED)
}

fn parse_range_attributes(
    attributes: &[DefaultNla],
) -> Option<(Register, Operator, Vec<u8>, Vec<u8>)> {
    let mut source = None;
    let mut operator = None;
    let mut from = None;
    let mut to = None;
    for attribute in attributes {
        let value = nla_value(attribute);
        match nla_kind(attribute) {
            1 => source = read_be_u32(&value).map(Register::from),
            2 => operator = read_be_u32(&value).map(Operator::from),
            3 => from = nested_data_value(&value),
            4 => to = nested_data_value(&value),
            _ => return None,
        }
    }
    Some((source?, operator?, from?, to?))
}

fn nla_kind(attribute: &DefaultNla) -> u16 {
    attribute.kind() & NLA_TYPE_MASK
}

fn nla_value(attribute: &DefaultNla) -> Vec<u8> {
    let mut value = vec![0; attribute.value_len()];
    attribute.emit_value(&mut value);
    value
}

fn nested_data_value(value: &[u8]) -> Option<Vec<u8>> {
    for nla in NlasIterator::new(value) {
        let nla = nla.ok()?;
        if nla.kind() == 1 {
            return Some(nla.value().to_vec());
        }
    }
    None
}

fn read_be_u32(value: &[u8]) -> Option<u32> {
    (value.len() == 4).then(|| u32::from_be_bytes(value.try_into().unwrap()))
}

fn reject_external_conflicts(
    snapshot: &KernelSnapshot,
    managed_table: &str,
    desired: &Plan,
) -> BackendResult {
    let mut tables: Vec<_> = snapshot
        .tables
        .iter()
        .filter(|table| table.name != managed_table)
        .collect();
    tables.sort_by_key(|table| (table.family, table.name.as_str()));
    for table in tables {
        let chains: BTreeMap<_, _> = snapshot
            .chains
            .iter()
            .filter(|chain| chain.family == table.family && chain.table == table.name)
            .map(|chain| (chain.name.as_str(), chain))
            .collect();
        let mut bases: Vec<_> = chains
            .values()
            .copied()
            .filter(|chain| {
                chain.chain_type.as_deref() == Some("nat")
                    && chain.hook == Some(u32::from(InetHookNumber::PreRouting))
            })
            .collect();
        bases.sort_by_key(|chain| chain.name.as_str());
        let mut visited = HashSet::new();
        for chain in bases {
            scan_external_chain(snapshot, table, chain, &chains, desired, &mut visited)?;
        }
    }
    Ok(())
}

fn scan_external_chain(
    snapshot: &KernelSnapshot,
    table: &TableState,
    chain: &ChainState,
    chains: &BTreeMap<&str, &ChainState>,
    desired: &Plan,
    visited: &mut HashSet<String>,
) -> BackendResult {
    if !visited.insert(chain.name.clone()) {
        return Ok(());
    }
    let rules: Vec<_> = snapshot
        .rules
        .iter()
        .filter(|rule| {
            rule.family == table.family && rule.table == table.name && rule.chain == chain.name
        })
        .collect();
    for (index, rule) in rules.iter().enumerate() {
        if let Some(existing) = direct_udp_redirect_range(&rule.expressions) {
            for redirect in &desired.redirects {
                if let Some(overlap) = first_overlap(&redirect.ports, &[existing]) {
                    return Err(boxed_operation(format!(
                        "node {} hysteria2 port_hopping {overlap} conflicts with existing UDP NAT rule at chain {} rule {index} on {existing}",
                        redirect.node_id, chain.name
                    )));
                }
            }
        }
        for expression in &rule.expressions {
            let Some(target) = jump_target(expression_data(expression)) else {
                continue;
            };
            let Some(next) = chains.get(target.as_str()) else {
                continue;
            };
            scan_external_chain(snapshot, table, next, chains, desired, visited)?;
        }
    }
    Ok(())
}

fn direct_udp_redirect_range(
    expressions: &[ListAttribute<ExpressionAttribute>],
) -> Option<PortRange> {
    let mut l4_registers = HashSet::new();
    let mut port_registers = HashSet::new();
    let mut has_redirect = false;
    for expression in expressions.iter().filter_map(expression_data) {
        match expression {
            Expressions::Meta(attributes) => {
                let mut key = false;
                let mut register = None;
                for attribute in attributes {
                    match attribute {
                        Meta::Key(MetaKey::L4Proto) => key = true,
                        Meta::DestinationRegister(value) => register = Some(*value),
                        _ => {}
                    }
                }
                if key && let Some(register) = register {
                    l4_registers.insert(register);
                }
            }
            Expressions::Payload(attributes) => {
                let mut register = None;
                let mut base = None;
                let mut offset = None;
                let mut len = None;
                for attribute in attributes {
                    match attribute {
                        Payload::DestinationRegister(value) => register = Some(*value),
                        Payload::Base(value) => base = Some(*value),
                        Payload::Offset(value) => offset = Some(*value),
                        Payload::Len(value) => len = Some(*value),
                        _ => {}
                    }
                }
                if base == Some(PAYLOAD_BASE_TRANSPORT_HEADER)
                    && offset == Some(2)
                    && len == Some(2)
                    && let Some(register) = register
                {
                    port_registers.insert(register);
                }
            }
            Expressions::Other {
                expression_type, ..
            } if expression_type == "redir" => has_redirect = true,
            Expressions::Other {
                expression_type,
                attributes,
            } if expression_type == "nat" => {
                has_redirect = attributes.iter().any(|attribute| {
                    nla_kind(attribute) == 1 && read_be_u32(&nla_value(attribute)) == Some(1)
                });
            }
            _ => {}
        }
    }
    if !has_redirect {
        return None;
    }

    let mut udp = false;
    let mut ports = None;
    for expression in expressions.iter().filter_map(expression_data) {
        match expression {
            Expressions::Cmp(_) => {
                for register in &l4_registers {
                    if cmp_equal_data(expression, *register) == Some([IPPROTO_UDP].as_slice()) {
                        udp = true;
                    }
                }
                for register in &port_registers {
                    let Some(data) = cmp_equal_data(expression, *register) else {
                        continue;
                    };
                    if data.len() == 2 {
                        let port = u16::from_be_bytes([data[0], data[1]]);
                        if port != 0 {
                            ports = Some(PortRange::new(port, port));
                        }
                    }
                }
            }
            Expressions::Other {
                expression_type,
                attributes,
            } if expression_type == "range" => {
                let Some((register, op, from, to)) = parse_range_attributes(attributes) else {
                    continue;
                };
                if op == Operator::Equal
                    && port_registers.contains(&register)
                    && from.len() == 2
                    && to.len() == 2
                {
                    let start = u16::from_be_bytes([from[0], from[1]]);
                    let end = u16::from_be_bytes([to[0], to[1]]);
                    if start != 0 && start <= end {
                        ports = Some(PortRange::new(start, end));
                    }
                }
            }
            _ => {}
        }
    }
    if udp { ports } else { None }
}

fn jump_target(expression: Option<&Expressions>) -> Option<String> {
    let Expressions::Immediate(attributes) = expression? else {
        return None;
    };
    let mut verdict_register = false;
    let mut verdict = false;
    let mut chain = None;
    for attribute in attributes {
        match attribute {
            Immediate::DestinationRegister(Register::Verdict) => verdict_register = true,
            Immediate::Data(DataAttribute::Verdict(verdicts)) => {
                for item in verdicts {
                    match item {
                        VerdictAttribute::Code(Verdict::Jump | Verdict::Goto) => verdict = true,
                        VerdictAttribute::Chain(value) => chain = Some(value.clone()),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    if verdict_register && verdict {
        chain
    } else {
        None
    }
}

struct NetlinkConnection {
    socket: Socket,
    port_id: u32,
    sequence: u32,
}

impl NetlinkConnection {
    fn open() -> io::Result<Self> {
        let mut socket = Socket::new(NETLINK_NETFILTER)?;
        let local = socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        let timeout = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        // SAFETY: `socket` owns a valid fd and `timeout` remains alive for each
        // setsockopt call with its exact `timeval` size.
        for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
            let result = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    std::ptr::from_ref(&timeout).cast(),
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self {
            socket,
            port_id: local.port_number(),
            sequence: 0,
        })
    }

    fn next_sequence(&mut self) -> u32 {
        self.sequence = self.sequence.wrapping_add(1).max(1);
        self.sequence
    }

    fn dump(
        &mut self,
        family: NetfilterProtoFamily,
        message: NfTablesMessage,
    ) -> io::Result<Vec<NetfilterMessage>> {
        let sequence = self.next_sequence();
        let mut request = nft_message(
            family,
            message,
            NLM_F_REQUEST | NLM_F_DUMP,
            sequence,
            self.port_id,
        );
        let bytes = serialize_message(&mut request);
        let written = self.socket.send(&bytes, 0)?;
        if written != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short NETLINK_NETFILTER dump request",
            ));
        }
        let mut output = Vec::new();
        loop {
            let (datagram, sender) = self.socket.recv_from_full()?;
            if sender.port_number() != 0 {
                continue;
            }
            for response in parse_datagram(&datagram)? {
                if response.header.sequence_number != sequence {
                    continue;
                }
                match response.payload {
                    NetlinkPayload::InnerMessage(message) => output.push(message),
                    NetlinkPayload::Done(done) => {
                        if done.code != 0 {
                            return Err(io::Error::from_raw_os_error(done.code.abs()));
                        }
                        return Ok(output);
                    }
                    NetlinkPayload::Error(error) => {
                        if error.code.is_some() {
                            return Err(error.to_io());
                        }
                        return Ok(output);
                    }
                    NetlinkPayload::Overrun(_) => {
                        return Err(io::Error::other("NETLINK_NETFILTER dump overrun"));
                    }
                    NetlinkPayload::Noop => {}
                    _ => {}
                }
            }
        }
    }

    fn push_message(
        &mut self,
        output: &mut Vec<u8>,
        family: NetfilterProtoFamily,
        inner: impl Into<NetfilterMessageInner>,
        flags: u16,
        expected_acks: &mut BTreeSet<u32>,
    ) {
        let sequence = self.next_sequence();
        let inner = inner.into();
        let resource_id = if matches!(
            &inner,
            NetfilterMessageInner::None(ControlMessage::BatchBegin | ControlMessage::BatchEnd)
        ) {
            NFNL_SUBSYS_NFTABLES
        } else {
            0
        };
        let mut message = NetlinkMessage::from(NetfilterMessage::new(
            NetfilterHeader::new(family, 0, resource_id),
            inner,
        ));
        message.header.flags = flags;
        message.header.sequence_number = sequence;
        message.header.port_number = self.port_id;
        if flags & NLM_F_ACK != 0 {
            expected_acks.insert(sequence);
        }
        output.extend_from_slice(&serialize_message(&mut message));
    }
}

impl NftConnection for NetlinkConnection {
    fn snapshot(&mut self) -> io::Result<KernelSnapshot> {
        let mut snapshot = KernelSnapshot::default();
        for family in Family::ALL {
            match self.dump(
                family.protocol(),
                NfTablesMessage::GetTable(TableMessage { attributes: vec![] }),
            ) {
                Ok(messages) => {
                    for message in messages {
                        if let Some(record) = table_from_message(message)? {
                            snapshot.tables.push(record);
                        }
                    }
                }
                Err(error) if is_capability_errno(&error) => {
                    snapshot
                        .unavailable
                        .insert(family, error.raw_os_error().unwrap_or(libc::EOPNOTSUPP));
                }
                Err(error) => return Err(error),
            }
        }
        if snapshot.tables.is_empty() {
            return Ok(snapshot);
        }
        for message in self.dump(
            NetfilterProtoFamily::Unspec,
            NfTablesMessage::GetChain(ChainMessage { attributes: vec![] }),
        )? {
            if let Some(record) = chain_from_message(message)? {
                snapshot.chains.push(record);
            }
        }
        for message in self.dump(
            NetfilterProtoFamily::Unspec,
            NfTablesMessage::GetRule(RuleMessage { attributes: vec![] }),
        )? {
            if let Some(record) = rule_from_message(message)? {
                snapshot.rules.push(record);
            }
        }
        Ok(snapshot)
    }

    fn execute(&mut self, batch: &Batch) -> io::Result<()> {
        let mut datagram = Vec::new();
        let mut expected_acks = BTreeSet::new();
        self.push_message(
            &mut datagram,
            NetfilterProtoFamily::Unspec,
            ControlMessage::BatchBegin,
            NLM_F_REQUEST,
            &mut expected_acks,
        );
        for table in &batch.delete {
            self.push_message(
                &mut datagram,
                table.family.protocol(),
                NfTablesMessage::DeleteTable(TableMessage {
                    attributes: vec![
                        TableAttribute::Name(table.name.clone()),
                        TableAttribute::Handle(table.handle),
                    ],
                }),
                NLM_F_REQUEST | NLM_F_ACK,
                &mut expected_acks,
            );
        }
        for table in &batch.create {
            self.push_message(
                &mut datagram,
                table.family.protocol(),
                NfTablesMessage::NewTable(TableMessage {
                    attributes: vec![
                        TableAttribute::Name(table.name.clone()),
                        TableAttribute::UserData(table.table_marker.clone()),
                    ],
                }),
                NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
                &mut expected_acks,
            );
            self.push_message(
                &mut datagram,
                table.family.protocol(),
                NfTablesMessage::NewChain(ChainMessage {
                    attributes: vec![
                        ChainAttribute::Table(table.name.clone()),
                        ChainAttribute::Name(CHAIN_NAME.to_owned()),
                        ChainAttribute::Policy(NF_ACCEPT),
                        ChainAttribute::Type("nat".to_owned()),
                        ChainAttribute::Hook(vec![
                            Hook::Number(InetHookNumber::PreRouting.into()),
                            Hook::Priority(NF_IP_PRI_NAT_DST as u32),
                        ]),
                        ChainAttribute::UserData(table.chain_marker.clone()),
                    ],
                }),
                NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
                &mut expected_acks,
            );
            for rule in &table.rules {
                self.push_message(
                    &mut datagram,
                    table.family.protocol(),
                    NfTablesMessage::NewRule(RuleMessage {
                        attributes: vec![
                            RuleAttribute::Table(table.name.clone()),
                            RuleAttribute::Chain(CHAIN_NAME.to_owned()),
                            RuleAttribute::Expressions(rule.expressions.clone()),
                            RuleAttribute::UserData(rule.marker.clone()),
                        ],
                    }),
                    NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
                    &mut expected_acks,
                );
            }
        }
        self.push_message(
            &mut datagram,
            NetfilterProtoFamily::Unspec,
            ControlMessage::BatchEnd,
            NLM_F_REQUEST,
            &mut expected_acks,
        );

        let written = self.socket.send(&datagram, 0)?;
        if written != datagram.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short NETLINK_NETFILTER atomic batch",
            ));
        }
        while !expected_acks.is_empty() {
            let (response, sender) = self.socket.recv_from_full()?;
            if sender.port_number() != 0 {
                continue;
            }
            for message in parse_datagram(&response)? {
                if !expected_acks.contains(&message.header.sequence_number) {
                    continue;
                }
                match message.payload {
                    NetlinkPayload::Error(error) if error.code.is_none() => {
                        expected_acks.remove(&message.header.sequence_number);
                    }
                    NetlinkPayload::Error(error) => return Err(error.to_io()),
                    NetlinkPayload::Overrun(_) => {
                        return Err(io::Error::other("NETLINK_NETFILTER batch overrun"));
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

fn nft_message(
    family: NetfilterProtoFamily,
    message: NfTablesMessage,
    flags: u16,
    sequence: u32,
    port_id: u32,
) -> NetlinkMessage<NetfilterMessage> {
    let mut message = NetlinkMessage::from(NetfilterMessage::new(
        NetfilterHeader::new(family, 0, 0),
        message,
    ));
    message.header.flags = flags;
    message.header.sequence_number = sequence;
    message.header.port_number = port_id;
    message
}

fn serialize_message(message: &mut NetlinkMessage<NetfilterMessage>) -> Vec<u8> {
    message.finalize();
    let mut bytes = vec![0; message.buffer_len()];
    message.serialize(&mut bytes);
    bytes.resize(align4(bytes.len()), 0);
    bytes
}

fn parse_datagram(datagram: &[u8]) -> io::Result<Vec<NetlinkMessage<NetfilterMessage>>> {
    let mut messages = Vec::new();
    let mut offset = 0;
    while offset < datagram.len() {
        if datagram.len() - offset < 16 {
            if datagram[offset..].iter().all(|byte| *byte == 0) {
                break;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated netlink header",
            ));
        }
        let length = u32::from_ne_bytes(datagram[offset..offset + 4].try_into().unwrap()) as usize;
        if length < 16 || offset + length > datagram.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid netlink message length",
            ));
        }
        messages.push(
            NetlinkMessage::deserialize(&datagram[offset..offset + length])
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?,
        );
        offset += align4(length);
    }
    Ok(messages)
}

const fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn table_from_message(message: NetfilterMessage) -> io::Result<Option<TableState>> {
    let Some(family) = Family::from_protocol(message.header.family) else {
        return Ok(None);
    };
    let NetfilterMessageInner::NfTables(
        NfTablesMessage::NewTable(TableMessage { attributes })
        | NfTablesMessage::GetTable(TableMessage { attributes }),
    ) = message.inner
    else {
        return Ok(None);
    };
    let mut name = None;
    let mut handle = None;
    let mut user_data = Vec::new();
    for attribute in attributes {
        match attribute {
            TableAttribute::Name(value) => name = Some(value),
            TableAttribute::Handle(value) => handle = Some(value),
            TableAttribute::UserData(value) => user_data = value,
            _ => {}
        }
    }
    Ok(Some(TableState {
        family,
        name: name.ok_or_else(|| io::Error::other("nftables table dump omitted name"))?,
        handle: handle.ok_or_else(|| io::Error::other("nftables table dump omitted handle"))?,
        user_data,
    }))
}

fn chain_from_message(message: NetfilterMessage) -> io::Result<Option<ChainState>> {
    let Some(family) = Family::from_protocol(message.header.family) else {
        return Ok(None);
    };
    let NetfilterMessageInner::NfTables(
        NfTablesMessage::NewChain(ChainMessage { attributes })
        | NfTablesMessage::GetChain(ChainMessage { attributes }),
    ) = message.inner
    else {
        return Ok(None);
    };
    let mut table = None;
    let mut name = None;
    let mut chain_type = None;
    let mut hook = None;
    let mut priority = None;
    let mut policy = None;
    let mut user_data = Vec::new();
    for attribute in attributes {
        match attribute {
            ChainAttribute::Table(value) => table = Some(value),
            ChainAttribute::Name(value) => name = Some(value),
            ChainAttribute::Type(value) => chain_type = Some(value),
            ChainAttribute::Hook(values) => {
                for value in values {
                    match value {
                        Hook::Number(number) => hook = Some(number.into()),
                        Hook::Priority(value) => priority = Some(value as i32),
                        _ => {}
                    }
                }
            }
            ChainAttribute::Policy(value) => policy = Some(value),
            ChainAttribute::UserData(value) => user_data = value,
            _ => {}
        }
    }
    Ok(Some(ChainState {
        family,
        table: table.ok_or_else(|| io::Error::other("nftables chain dump omitted table"))?,
        name: name.ok_or_else(|| io::Error::other("nftables chain dump omitted name"))?,
        chain_type,
        hook,
        priority,
        policy,
        user_data,
    }))
}

fn rule_from_message(message: NetfilterMessage) -> io::Result<Option<RuleState>> {
    let Some(family) = Family::from_protocol(message.header.family) else {
        return Ok(None);
    };
    let NetfilterMessageInner::NfTables(
        NfTablesMessage::NewRule(RuleMessage { attributes })
        | NfTablesMessage::GetRule(RuleMessage { attributes }),
    ) = message.inner
    else {
        return Ok(None);
    };
    let mut table = None;
    let mut chain = None;
    let mut expressions = Vec::new();
    let mut user_data = Vec::new();
    for attribute in attributes {
        match attribute {
            RuleAttribute::Table(value) => table = Some(value),
            RuleAttribute::Chain(value) => chain = Some(value),
            RuleAttribute::Expressions(value) => expressions = value,
            RuleAttribute::UserData(value) => user_data = value,
            _ => {}
        }
    }
    Ok(Some(RuleState {
        family,
        table: table.ok_or_else(|| io::Error::other("nftables rule dump omitted table"))?,
        chain: chain.ok_or_else(|| io::Error::other("nftables rule dump omitted chain"))?,
        expressions,
        user_data,
    }))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;
    use crate::porthopping::{is_capability_unsupported, is_state_uncertain};

    fn plan(start: u16, end: u16, target: u16) -> Plan {
        Plan {
            redirects: vec![Redirect {
                node_id: "node-hysteria".into(),
                listen_port: target,
                ports: vec![PortRange::new(start, end)],
            }],
        }
    }

    fn owned_snapshot(machine_id: &str, desired: &Plan, mode: FamilyMode) -> KernelSnapshot {
        let owner = owner_hash(machine_id);
        let table_name = format!("{TABLE_PREFIX}{}", lower_hex(&owner));
        let digest = desired.digest();
        let mut snapshot = KernelSnapshot::default();
        for (index, family) in mode.families().iter().enumerate() {
            snapshot.tables.push(TableState {
                family: *family,
                name: table_name.clone(),
                handle: index as u64 + 10,
                user_data: encode_container_marker(TABLE_MARKER_MAGIC, owner, &digest).unwrap(),
            });
            snapshot.chains.push(ChainState {
                family: *family,
                table: table_name.clone(),
                name: CHAIN_NAME.into(),
                chain_type: Some("nat".into()),
                hook: Some(u32::from(InetHookNumber::PreRouting)),
                priority: Some(NF_IP_PRI_NAT_DST),
                policy: Some(NF_ACCEPT),
                user_data: encode_container_marker(CHAIN_MARKER_MAGIC, owner, &digest).unwrap(),
            });
            for redirect in &desired.redirects {
                for ports in &redirect.ports {
                    snapshot.rules.push(RuleState {
                        family: *family,
                        table: table_name.clone(),
                        chain: CHAIN_NAME.into(),
                        expressions: redirect_expressions(*ports, redirect.listen_port),
                        user_data: encode_rule_marker(owner, &digest, redirect, *ports).unwrap(),
                    });
                }
            }
        }
        snapshot
    }

    #[test]
    fn markers_and_expressions_round_trip_go_wire_format() {
        let desired = plan(20_000, 21_000, 8_443);
        let owner = owner_hash("machine-a");
        let redirect = &desired.redirects[0];
        let marker =
            encode_rule_marker(owner, &desired.digest(), redirect, redirect.ports[0]).unwrap();
        let decoded = decode_rule_marker(&marker).unwrap();
        assert_eq!(decoded.owner, owner);
        assert_eq!(decoded.digest, desired.digest());
        assert_eq!(decoded.node_id, redirect.node_id);
        assert_eq!(decoded.ports, redirect.ports[0]);
        assert_eq!(
            managed_redirect_rule(&redirect_expressions(
                redirect.ports[0],
                redirect.listen_port
            )),
            Some((redirect.ports[0], redirect.listen_port))
        );
        assert_eq!(
            direct_udp_redirect_range(&redirect_expressions(
                redirect.ports[0],
                redirect.listen_port
            )),
            Some(redirect.ports[0])
        );
    }

    #[test]
    fn inspection_adopts_complete_and_repairs_partial_owned_state() {
        let machine = "machine-inspect";
        let desired = plan(20_000, 21_000, 8_443);
        let table_name = format!("{TABLE_PREFIX}{}", lower_hex(&owner_hash(machine)));
        let complete = inspect_snapshot(
            &table_name,
            owner_hash(machine),
            owned_snapshot(machine, &desired, FamilyMode::Split),
        )
        .unwrap();
        assert!(complete.matches(FamilyMode::Split, &desired.digest(), 1));

        let mut partial = owned_snapshot(machine, &desired, FamilyMode::Split);
        partial.tables.retain(|table| table.family == Family::Ipv4);
        partial.chains.retain(|chain| chain.family == Family::Ipv4);
        partial.rules.retain(|rule| rule.family == Family::Ipv4);
        let partial = inspect_snapshot(&table_name, owner_hash(machine), partial).unwrap();
        assert!(partial.exists);
        assert!(!partial.complete);
        assert_eq!(partial.mode, FamilyMode::Split);
    }

    #[test]
    fn legacy_rule_markers_are_adopted_but_foreign_state_is_never_deleted() {
        let machine = "machine-owner";
        let desired = plan(20_000, 21_000, 8_443);
        let table_name = format!("{TABLE_PREFIX}{}", lower_hex(&owner_hash(machine)));
        let mut legacy = owned_snapshot(machine, &desired, FamilyMode::Inet);
        legacy.tables[0].user_data.clear();
        legacy.chains[0].user_data.clear();
        assert!(
            inspect_snapshot(&table_name, owner_hash(machine), legacy)
                .unwrap()
                .complete
        );

        let mut foreign = owned_snapshot(machine, &desired, FamilyMode::Inet);
        foreign.rules[0].user_data = encode_rule_marker(
            owner_hash("foreign"),
            &desired.digest(),
            &desired.redirects[0],
            desired.redirects[0].ports[0],
        )
        .unwrap();
        let error = inspect_snapshot(&table_name, owner_hash(machine), foreign).unwrap_err();
        assert!(error.to_string().contains("not owned"));
    }

    #[derive(Default)]
    struct FakeState {
        connections: VecDeque<FakeConnectionState>,
        batches: Vec<Batch>,
    }

    struct FakeFactory(Arc<Mutex<FakeState>>);

    impl ConnectionFactory for FakeFactory {
        fn open(&self) -> io::Result<Box<dyn NftConnection>> {
            let connection = self
                .0
                .lock()
                .unwrap()
                .connections
                .pop_front()
                .ok_or_else(|| io::Error::other("unexpected fake connection"))?;
            Ok(Box::new(FakeConnection {
                shared: self.0.clone(),
                state: connection,
            }))
        }
    }

    struct FakeConnectionState {
        snapshot: io::Result<KernelSnapshot>,
        execute: io::Result<()>,
    }

    struct FakeConnection {
        shared: Arc<Mutex<FakeState>>,
        state: FakeConnectionState,
    }

    impl NftConnection for FakeConnection {
        fn snapshot(&mut self) -> io::Result<KernelSnapshot> {
            std::mem::replace(
                &mut self.state.snapshot,
                Err(io::Error::other("snapshot called twice")),
            )
        }

        fn execute(&mut self, batch: &Batch) -> io::Result<()> {
            self.shared.lock().unwrap().batches.push(batch.clone());
            std::mem::replace(
                &mut self.state.execute,
                Err(io::Error::other("execute called twice")),
            )
        }
    }

    fn fake_backend(
        machine: &str,
        states: Vec<FakeConnectionState>,
    ) -> (NftBackend, Arc<Mutex<FakeState>>) {
        let shared = Arc::new(Mutex::new(FakeState {
            connections: states.into(),
            batches: Vec::new(),
        }));
        let backend = NftBackend::with_factory(machine, Arc::new(FakeFactory(shared.clone())));
        (backend, shared)
    }

    #[test]
    fn apply_is_idempotent_and_atomic_ack_loss_is_verified() {
        let machine = "machine-apply";
        let desired = plan(20_000, 21_000, 8_443);
        let (mut backend, shared) = fake_backend(
            machine,
            vec![
                FakeConnectionState {
                    snapshot: Ok(KernelSnapshot::default()),
                    execute: Err(io::Error::from_raw_os_error(libc::ETIMEDOUT)),
                },
                FakeConnectionState {
                    snapshot: Ok(owned_snapshot(machine, &desired, FamilyMode::Inet)),
                    execute: Ok(()),
                },
                FakeConnectionState {
                    snapshot: Ok(owned_snapshot(machine, &desired, FamilyMode::Inet)),
                    execute: Ok(()),
                },
            ],
        );
        backend.apply(&desired).unwrap();
        backend.apply(&desired).unwrap();
        let state = shared.lock().unwrap();
        assert_eq!(state.batches.len(), 1);
        assert_eq!(state.batches[0].create.len(), 1);
        assert!(state.batches[0].delete.is_empty());
    }

    #[test]
    fn failed_ack_is_uncertain_unless_capability_failure_is_proven() {
        let desired = plan(20_000, 21_000, 8_443);
        let (mut uncertain, _) = fake_backend(
            "machine-uncertain",
            vec![
                FakeConnectionState {
                    snapshot: Ok(KernelSnapshot::default()),
                    execute: Err(io::Error::from_raw_os_error(libc::EINVAL)),
                },
                FakeConnectionState {
                    snapshot: Ok(KernelSnapshot::default()),
                    execute: Ok(()),
                },
            ],
        );
        let error = uncertain.apply(&desired).unwrap_err();
        assert!(is_state_uncertain(error.as_ref()));
        assert!(!is_capability_unsupported(error.as_ref()));

        let (mut unsupported, shared) = fake_backend(
            "machine-old-kernel",
            vec![
                FakeConnectionState {
                    snapshot: Ok(KernelSnapshot::default()),
                    execute: Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP)),
                },
                FakeConnectionState {
                    snapshot: Ok(KernelSnapshot::default()),
                    execute: Ok(()),
                },
                FakeConnectionState {
                    snapshot: Ok(KernelSnapshot::default()),
                    execute: Err(io::Error::from_raw_os_error(libc::EAFNOSUPPORT)),
                },
                FakeConnectionState {
                    snapshot: Ok(KernelSnapshot::default()),
                    execute: Ok(()),
                },
            ],
        );
        let error = unsupported.apply(&desired).unwrap_err();
        assert!(is_capability_unsupported(error.as_ref()));
        assert!(!is_state_uncertain(error.as_ref()));
        let state = shared.lock().unwrap();
        assert_eq!(state.batches.len(), 2);
        assert_eq!(state.batches[1].create.len(), 2);
    }

    #[test]
    fn replacement_and_cleanup_delete_only_owned_handles() {
        let machine = "machine-replace";
        let old = plan(20_000, 21_000, 8_443);
        let new = plan(30_000, 31_000, 9_443);
        let (mut backend, shared) = fake_backend(
            machine,
            vec![
                FakeConnectionState {
                    snapshot: Ok(owned_snapshot(machine, &old, FamilyMode::Split)),
                    execute: Ok(()),
                },
                FakeConnectionState {
                    snapshot: Ok(owned_snapshot(machine, &new, FamilyMode::Split)),
                    execute: Ok(()),
                },
            ],
        );
        backend.apply(&new).unwrap();
        backend.apply(&Plan::default()).unwrap();
        let state = shared.lock().unwrap();
        assert_eq!(state.batches.len(), 2);
        assert_eq!(state.batches[0].delete.len(), 2);
        assert_eq!(state.batches[0].create.len(), 2);
        assert_eq!(state.batches[1].delete.len(), 2);
        assert!(state.batches[1].create.is_empty());
        assert_eq!(state.batches[0].delete[0].handle, 10);
    }

    #[test]
    fn external_jump_chain_conflict_is_rejected_before_mutation() {
        let desired = plan(44_005, 44_020, 8_443);
        let mut snapshot = KernelSnapshot::default();
        snapshot.tables.push(TableState {
            family: Family::Inet,
            name: "foreign".into(),
            handle: 1,
            user_data: Vec::new(),
        });
        snapshot.chains.extend([
            ChainState {
                family: Family::Inet,
                table: "foreign".into(),
                name: "base".into(),
                chain_type: Some("nat".into()),
                hook: Some(u32::from(InetHookNumber::PreRouting)),
                priority: Some(0),
                policy: Some(NF_ACCEPT),
                user_data: Vec::new(),
            },
            ChainState {
                family: Family::Inet,
                table: "foreign".into(),
                name: "child".into(),
                chain_type: None,
                hook: None,
                priority: None,
                policy: None,
                user_data: Vec::new(),
            },
        ]);
        snapshot.rules.push(RuleState {
            family: Family::Inet,
            table: "foreign".into(),
            chain: "base".into(),
            expressions: vec![
                Expressions::Immediate(vec![
                    Immediate::DestinationRegister(Register::Verdict),
                    Immediate::Data(DataAttribute::Verdict(vec![
                        VerdictAttribute::Code(Verdict::Jump),
                        VerdictAttribute::Chain("child".into()),
                    ])),
                ])
                .into(),
            ],
            user_data: Vec::new(),
        });
        snapshot.rules.push(RuleState {
            family: Family::Inet,
            table: "foreign".into(),
            chain: "child".into(),
            expressions: redirect_expressions(PortRange::new(44_000, 44_010), 9_443),
            user_data: Vec::new(),
        });
        let error = reject_external_conflicts(&snapshot, "our-table", &desired).unwrap_err();
        assert!(error.to_string().contains("child"));
        assert!(error.to_string().contains("44005-44010"));
    }

    #[cfg(feature = "porthopping-linux-integration")]
    #[test]
    fn live_nftables_replace_and_cleanup() {
        if std::env::var("ACP_PORTHOPPING_LINUX_INTEGRATION").as_deref() != Ok("1") {
            eprintln!(
                "skipping: set ACP_PORTHOPPING_LINUX_INTEGRATION=1 in an isolated network namespace with CAP_NET_ADMIN"
            );
            return;
        }
        let machine = format!("rust-porthopping-integration-{}", std::process::id());
        let mut backend = NftBackend::new(&machine);
        backend.apply(&plan(42_000, 42_002, 8_443)).unwrap();
        backend.apply(&plan(43_000, 43_001, 9_443)).unwrap();
        backend.apply(&Plan::default()).unwrap();
    }
}
