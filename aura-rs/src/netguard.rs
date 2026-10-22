//! 本机地址识别与自引用（hairpin）出站改写。
//!
//! 行为基准：backend/netguard.py（只读，不修改）。
//!
//! 事故背景（2026-10-22 新加坡 arm-3）：58 个 socks5 节点的 server 全是
//! sg.lsp121.eu.org，该域名解析回本机公网 IP 168.107.71.181。sing-box 出站于是拨回
//! 自己的公网 IP，经云 NAT hairpin 绕一圈再进本机代理端口（宿主上的 nodetap_arm64）。
//! 上游端口挂掉或池子打满时，半开连接长期不释放：sing-box fd 涨到 1875、整机 load 224、
//! sshd 起不了新会话（面板看着 200，机器实际失联）。
//!
//! 两层修法中的第一层（本模块）：
//! - 目标端口不是本面板入站端口时，把 server 改写成 127.0.0.1 走回环——少一次云 NAT
//!   hairpin、省一半 socket 与 conntrack（Kind::Hairpin）；
//! - 目标端口正是本面板自己的入站端口时判定为回环自引用（Kind::Loop），由调用方
//!   跳过该节点（否则 sing-box 出站→自己入站→再出站，无限套娃）。
//!
//! 判定口径（三重条件，宁可不改写也不误改别人的节点）：
//!   ① 解析结果命中本机地址集合（本机网卡地址 ∪ 出口域名解析结果 ∪ 回环地址）；
//!   ② 该端口在本机 127.0.0.1 上可连（确实由本机服务承接）；
//!   ③ 该端口不是本面板的入站端口（否则是自引用回环，不改写而是跳过）。
//! 任何一步异常都退化为「不改写」，绝不让配置生成失败。
//!
//! 迁移口径：Python 用模块级全局缓存 + monkeypatch 注入，这里用 Guard 承载全部状态，
//! DNS 解析 / 网卡枚举 / 端口探测三者均可注入（Guard::with_backends），测试里用假解析器，
//! 绝不碰真实网络。全局单例由 with_global 提供，保持 Python 侧的调用形态
//! （begin_pass / apply_rewrite / self_domains_from_settings）。

use serde_json::{Map, Value};
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::utils::{is_ip_address, safe_int};

/// 回环 IPv4 地址（改写目标）。
pub const LOOPBACK: &str = "127.0.0.1";
/// 回环 IPv6 地址（已是回环，无需处理）。
pub const LOOPBACK_V6: &str = "::1";
/// 自引用回环：出站打到自己入站端口，必须跳过节点。
pub const LOOP: &str = "loop";
/// 解析到本机但不是入站端口：改写 127.0.0.1。
pub const HAIRPIN: &str = "hairpin";

/// 本机地址集合缓存（DNS 结果 + 网卡地址）。
pub const SELF_TTL: f64 = 300.0;
/// 端口本机可达性缓存。
pub const PROBE_TTL: f64 = 60.0;
/// 端口探测超时。
pub const PROBE_TIMEOUT: f64 = 0.3;
/// 单轮 build_config 默认探测预算。
pub const DEFAULT_PASS_BUDGET: f64 = 3.0;

/// DNS 解析器：(host, ttl) -> 解析出的 IP 列表（失败返回空）。
pub type Resolver = Arc<dyn Fn(&str, f64) -> Vec<String> + Send + Sync>;
/// 网卡地址枚举器：返回本机网卡 IP 列表。
pub type InterfaceIps = Arc<dyn Fn() -> Vec<String> + Send + Sync>;
/// 本机端口可达性探测：(port, timeout) -> 127.0.0.1:port 是否可连。
pub type ServeProbe = Arc<dyn Fn(u16, f64) -> bool + Send + Sync>;

/// 判定结果：None = 与本机无关或无法判定（保持原样）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// 与本机无关 / 无法判定，保持原样。
    None,
    /// 命中本面板入站端口，回环自引用，调用方必须跳过该节点。
    Loop,
    /// 指向本机自建服务，调用方把 server 改成 127.0.0.1。
    Hairpin,
}

impl Kind {
    /// 与 Python 版字符串常量对齐（"loop" / "hairpin" / ""）。
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::None => "",
            Kind::Loop => LOOP,
            Kind::Hairpin => HAIRPIN,
        }
    }
}

#[derive(Default)]
struct SelfCache {
    key: Vec<String>,
    ips: Option<BTreeSet<String>>,
    at: Option<Instant>,
}

/// 本机地址判定 + 自引用出站改写，全部可变状态都收在这里（Python 侧是模块级全局变量）。
pub struct Guard {
    resolver: Resolver,
    iface_ips: InterfaceIps,
    serve_probe: ServeProbe,
    /// 本机地址集合缓存 TTL。
    pub self_ttl: f64,
    /// 端口探测结果缓存 TTL。
    pub probe_ttl: f64,
    /// 端口探测默认超时。
    pub probe_timeout: f64,
    self_cache: SelfCache,
    dns_cache: HashMap<String, (Instant, Vec<String>)>,
    probe_cache: HashMap<u16, (Instant, bool)>,
    /// 单轮 build_config 的探测预算截止时刻（None = 不限）。
    pass_deadline: Option<Instant>,
}

fn age_secs(at: Instant, now: Instant) -> f64 {
    now.saturating_duration_since(at).as_secs_f64()
}

impl Default for Guard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard {
    /// 生产实现：真实 getaddrinfo / getifaddrs / TcpStream 探测。
    pub fn new() -> Self {
        Self::with_backends(
            Arc::new(real_resolve),
            Arc::new(real_interface_ips),
            Arc::new(real_serve_local),
        )
    }

    /// 注入式构造：测试用假解析器 / 假网卡 / 假探测，避免真实网络与真实 socket。
    pub fn with_backends(
        resolver: Resolver,
        iface_ips: InterfaceIps,
        serve_probe: ServeProbe,
    ) -> Self {
        Self {
            resolver,
            iface_ips,
            serve_probe,
            self_ttl: SELF_TTL,
            probe_ttl: PROBE_TTL,
            probe_timeout: PROBE_TIMEOUT,
            self_cache: SelfCache::default(),
            dns_cache: HashMap::new(),
            probe_cache: HashMap::new(),
            pass_deadline: None,
        }
    }

    /// 给一轮出站判定设时间预算。build_config 是同步逻辑，上百个不同域名的 getaddrinfo
    /// 叠加会让接口明显变卡；超预算后直接放弃未判定的节点（退化为「不改写」），
    /// 宁可少优化也不拖住事件循环。budget <= 0 = 不限。
    pub fn begin_pass(&mut self, budget: f64) {
        self.pass_deadline = if budget > 0.0 {
            Some(Instant::now() + Duration::from_secs_f64(budget))
        } else {
            None
        };
    }

    /// 预算是否已用尽。
    pub fn over_budget(&self) -> bool {
        self.pass_deadline
            .is_some_and(|deadline| Instant::now() > deadline)
    }

    /// 清空全部缓存（测试与网卡/域名变更后使用）。
    pub fn reset_cache(&mut self) {
        self.pass_deadline = None;
        self.self_cache = SelfCache::default();
        self.dns_cache.clear();
        self.probe_cache.clear();
    }

    /// 解析主机名（IP 字面量直接返回），带 TTL 缓存。失败返回空，绝不 panic。
    pub fn resolve(&mut self, host: &str) -> Vec<String> {
        self.resolve_with_ttl(host, self.self_ttl)
    }

    /// 同 Guard::resolve，可指定缓存 TTL。
    pub fn resolve_with_ttl(&mut self, host: &str, ttl: f64) -> Vec<String> {
        let host = host.trim().to_ascii_lowercase();
        if host.is_empty() {
            return Vec::new();
        }
        if is_ip_address(&host) {
            // 字面量 IP 不查缓存、不受预算限制（Python 同样在预算判断之前短路）。
            return vec![host];
        }
        let now = Instant::now();
        if let Some((at, ips)) = self.dns_cache.get(&host) {
            if age_secs(*at, now) < ttl {
                return ips.clone();
            }
        }
        if self.over_budget() {
            return Vec::new();
        }
        let mut ips = (self.resolver)(&host, ttl);
        ips.sort_unstable();
        ips.dedup();
        self.dns_cache.insert(host, (now, ips.clone()));
        ips
    }

    /// 本机地址集合 = 网卡地址 ∪ 自报域名（面板出口域名/中转域名）解析结果 ∪ 回环。
    pub fn self_ips(&mut self, self_domains: &[String]) -> BTreeSet<String> {
        self.self_ips_refresh(self_domains, false)
    }

    /// 同 Guard::self_ips，refresh = true 时强制重算（跳过缓存）。
    pub fn self_ips_refresh(&mut self, self_domains: &[String], refresh: bool) -> BTreeSet<String> {
        let key: Vec<String> = {
            let mut key: Vec<String> = self_domains
                .iter()
                .map(|domain| domain.trim().to_ascii_lowercase())
                .filter(|domain| !domain.is_empty())
                .collect();
            key.sort();
            key.dedup();
            key
        };
        let now = Instant::now();
        if !refresh {
            if let (Some(cached), Some(at)) = (&self.self_cache.ips, self.self_cache.at) {
                if self.self_cache.key == key && age_secs(at, now) < self.self_ttl {
                    return cached.clone();
                }
            }
        }
        let mut ips: BTreeSet<String> = (self.iface_ips)().into_iter().collect();
        ips.insert(LOOPBACK.to_string());
        ips.insert(LOOPBACK_V6.to_string());
        for domain in &key {
            for ip in self.resolve(domain) {
                ips.insert(ip);
            }
        }
        self.self_cache = SelfCache {
            key,
            ips: Some(ips.clone()),
            at: Some(now),
        };
        ips
    }

    /// 该端口是否由本机 127.0.0.1 承接（短超时 + TTL 缓存）。
    pub fn serve_local(&mut self, port: i64) -> bool {
        let timeout = self.probe_timeout;
        self.serve_local_with_timeout(port, timeout)
    }

    /// 同 Guard::serve_local，可指定探测超时。
    pub fn serve_local_with_timeout(&mut self, port: i64, timeout: f64) -> bool {
        if !(1..=65535).contains(&port) {
            return false;
        }
        let port = port as u16;
        let now = Instant::now();
        if let Some((at, ok)) = self.probe_cache.get(&port) {
            if age_secs(*at, now) < self.probe_ttl {
                return *ok;
            }
        }
        if self.over_budget() {
            return false;
        }
        let ok = (self.serve_probe)(port, timeout);
        self.probe_cache.insert(port, (now, ok));
        ok
    }

    /// 判定一个出站目标是否指向本机。返回 (kind, detail)：
    /// - (Kind::Loop, 说明)：命中本面板入站端口，调用方必须跳过该节点；
    /// - (Kind::Hairpin, 说明)：指向本机自建服务，调用方把 server 改成 127.0.0.1；
    /// - (Kind::None, "")：与本机无关或无法判定，保持原样。
    pub fn classify(
        &mut self,
        server: &str,
        server_port: i64,
        inbound_ports: &[i64],
        self_domains: &[String],
    ) -> (Kind, String) {
        let server = server.trim();
        if server.is_empty() || !(1..=65535).contains(&server_port) {
            return (Kind::None, String::new());
        }
        if server == LOOPBACK || server == LOOPBACK_V6 {
            return (Kind::None, String::new()); // 已经是回环，无需处理
        }
        let resolved = self.resolve(server);
        if resolved.is_empty() {
            return (Kind::None, String::new());
        }
        let own = self.self_ips(self_domains);
        let mut hit: Vec<&String> = resolved.iter().filter(|ip| own.contains(*ip)).collect();
        if hit.is_empty() {
            return (Kind::None, String::new());
        }
        hit.sort();
        if inbound_ports.iter().any(|p| *p != 0 && *p == server_port) {
            return (
                Kind::Loop,
                format!("{server}:{server_port} 命中本面板入站端口，回环自引用"),
            );
        }
        if !self.serve_local(server_port) {
            // 本机不承接该端口：可能是同域名下的另一台机器，保持原样。
            return (Kind::None, String::new());
        }
        (
            Kind::Hairpin,
            format!(
                "{server}:{server_port} 解析为本机 {}，出站改写 127.0.0.1 免 NAT hairpin",
                hit[0]
            ),
        )
    }

    /// 就地处理一个 outbound 字典：命中回环返回 Loop（调用方丢弃），命中 hairpin 则改写 server。
    pub fn apply_rewrite(
        &mut self,
        out_item: &mut Map<String, Value>,
        inbound_ports: &[i64],
        self_domains: &[String],
    ) -> (Kind, String) {
        let server = match field_str(out_item, "server").filter(|s| !s.is_empty()) {
            Some(server) => server,
            None => field_str(out_item, "address").unwrap_or_default(),
        };
        let server_port = safe_int(out_item.get("server_port").unwrap_or(&Value::Null), 0);
        let (kind, detail) = self.classify(&server, server_port, inbound_ports, self_domains);
        if kind == Kind::Hairpin {
            out_item.insert("server".to_string(), Value::String(LOOPBACK.to_string()));
        }
        (kind, detail)
    }

    /// 便捷入口：入站端口直接传集合（对齐 Python 侧 _plan_inbound_ports 的 Set[int] 形态）。
    pub fn classify_set(
        &mut self,
        server: &str,
        server_port: i64,
        inbound_ports: &BTreeSet<i64>,
        self_domains: &[String],
    ) -> (Kind, String) {
        let ports: Vec<i64> = inbound_ports.iter().copied().collect();
        self.classify(server, server_port, &ports, self_domains)
    }

    /// 便捷入口：入站端口直接传集合。
    pub fn apply_rewrite_set(
        &mut self,
        out_item: &mut Map<String, Value>,
        inbound_ports: &BTreeSet<i64>,
        self_domains: &[String],
    ) -> (Kind, String) {
        let ports: Vec<i64> = inbound_ports.iter().copied().collect();
        self.apply_rewrite(out_item, &ports, self_domains)
    }
}

/// 取 outbound 字典里某个字段的字符串形态（数字也转字符串，None/非标量视为缺失）。
fn field_str(item: &Map<String, Value>, key: &str) -> Option<String> {
    match item.get(key) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    }
}

/// 从系统设置里取出「代表本机身份」的域名：出口域名 + 各中转入口域名。
pub fn self_domains_from_settings(settings: &Value, relay_domains: &[Value]) -> Vec<String> {
    fn push(domains: &mut Vec<String>, raw: Option<&str>) {
        if let Some(domain) = raw {
            let domain = domain.trim();
            if !domain.is_empty() {
                domains.push(domain.to_string());
            }
        }
    }
    let mut domains: Vec<String> = Vec::new();
    push(
        &mut domains,
        settings.get("exportDomain").and_then(|v| v.as_str()),
    );
    for relay_domain in relay_domains {
        push(
            &mut domains,
            relay_domain.get("domain").and_then(|v| v.as_str()),
        );
    }
    domains
}

// ---------- 进程级单例（对齐 Python 模块级全局状态） ----------

static GLOBAL: OnceLock<Mutex<Guard>> = OnceLock::new();

fn global() -> &'static Mutex<Guard> {
    GLOBAL.get_or_init(|| Mutex::new(Guard::new()))
}

/// 在全局 Guard 上执行一段操作（锁中毒时照常取回内层状态，不让配置生成失败）。
pub fn with_global<R>(f: impl FnOnce(&mut Guard) -> R) -> R {
    let mut guard = match global().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    f(&mut guard)
}

/// 给一轮出站判定设时间预算。
pub fn begin_pass(budget: f64) {
    with_global(|g| g.begin_pass(budget))
}

/// 清空全部缓存（测试与网卡/域名变更后使用）。
pub fn reset_cache() {
    with_global(|g| g.reset_cache())
}

/// 解析主机名（带缓存）。
pub fn resolve(host: &str) -> Vec<String> {
    with_global(|g| g.resolve(host))
}

/// 本机地址集合。
pub fn self_ips(self_domains: &[String]) -> BTreeSet<String> {
    with_global(|g| g.self_ips(self_domains))
}

/// 该端口是否由本机 127.0.0.1 承接。
pub fn serve_local(port: i64) -> bool {
    with_global(|g| g.serve_local(port))
}

/// 判定一个出站目标是否指向本机。
pub fn classify(
    server: &str,
    server_port: i64,
    inbound_ports: &[i64],
    self_domains: &[String],
) -> (Kind, String) {
    with_global(|g| g.classify(server, server_port, inbound_ports, self_domains))
}

/// 就地处理一个 outbound 字典。
pub fn apply_rewrite(
    out_item: &mut Map<String, Value>,
    inbound_ports: &[i64],
    self_domains: &[String],
) -> (Kind, String) {
    with_global(|g| g.apply_rewrite(out_item, inbound_ports, self_domains))
}

/// 就地处理一个 outbound 字典（入站端口以集合传入）。
pub fn apply_rewrite_set(
    out_item: &mut Map<String, Value>,
    inbound_ports: &BTreeSet<i64>,
    self_domains: &[String],
) -> (Kind, String) {
    with_global(|g| g.apply_rewrite_set(out_item, inbound_ports, self_domains))
}

// ---------- 真实后端 ----------

/// 真实解析：getaddrinfo，去重并排序。
fn real_resolve(host: &str, _ttl: f64) -> Vec<String> {
    use std::net::ToSocketAddrs;
    let mut set: BTreeSet<String> = BTreeSet::new();
    if let Ok(addrs) = (host, 0u16).to_socket_addrs() {
        for addr in addrs {
            let ip = addr.ip().to_string();
            let ip = ip.split('%').next().unwrap_or(&ip).to_string();
            set.insert(ip);
        }
    }
    set.into_iter().collect()
}

/// 真实网卡枚举：getifaddrs，只取 IPv4（与 Python ioctl SIOCGIFADDR 口径一致；
/// IPv6 侧只认回环 ::1，由 self_ips 直接补入）。
#[cfg(unix)]
fn real_interface_ips() -> Vec<String> {
    let mut ips: Vec<String> = Vec::new();
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return ips;
        }
        let mut cursor = head;
        while !cursor.is_null() {
            let addr = (*cursor).ifa_addr;
            if !addr.is_null() && (*addr).sa_family == libc::AF_INET as libc::sa_family_t {
                let sin = addr as *const libc::sockaddr_in;
                let raw = u32::from_be((*sin).sin_addr.s_addr);
                ips.push(std::net::Ipv4Addr::from(raw).to_string());
            }
            cursor = (*cursor).ifa_next;
        }
        libc::freeifaddrs(head);
    }
    ips
}

#[cfg(not(unix))]
fn real_interface_ips() -> Vec<String> {
    Vec::new()
}

/// 真实探测：连 127.0.0.1:port，短超时。
fn real_serve_local(port: u16, timeout: f64) -> bool {
    let timeout = if timeout > 0.0 { timeout } else { 0.001 };
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    std::net::TcpStream::connect_timeout(&addr, Duration::from_secs_f64(timeout)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const SELF_IP: &str = "10.0.0.87";
    const SELF_DOMAIN: &str = "sg.lsp121.eu.org";

    struct Counters {
        resolve: Arc<AtomicUsize>,
        probe: Arc<AtomicUsize>,
        iface: Arc<AtomicUsize>,
    }

    /// 假后端：自报域名解析到 SELF_IP，其余域名解析为空；网卡只有 SELF_IP；
    /// 端口探测按 local_port 固定回答。所有调用计数，供「绝不该探测」类断言。
    fn guard_with(local_port: bool) -> (Guard, Counters) {
        let resolve_calls = Arc::new(AtomicUsize::new(0));
        let probe_calls = Arc::new(AtomicUsize::new(0));
        let rc = resolve_calls.clone();
        let pc = probe_calls.clone();
        let resolver: Resolver = Arc::new(move |host: &str, _ttl: f64| {
            rc.fetch_add(1, Ordering::SeqCst);
            if host == SELF_DOMAIN {
                vec![SELF_IP.to_string()]
            } else {
                Vec::new()
            }
        });
        let iface_calls = Arc::new(AtomicUsize::new(0));
        let ic = iface_calls.clone();
        let iface: InterfaceIps = Arc::new(move || {
            ic.fetch_add(1, Ordering::SeqCst);
            vec![SELF_IP.to_string()]
        });
        let probe: ServeProbe = Arc::new(move |_port: u16, _timeout: f64| {
            pc.fetch_add(1, Ordering::SeqCst);
            local_port
        });
        (
            Guard::with_backends(resolver, iface, probe),
            Counters {
                resolve: resolve_calls,
                probe: probe_calls,
                iface: iface_calls,
            },
        )
    }

    fn outbound(server: &str, server_port: i64) -> Map<String, Value> {
        match serde_json::from_value(json!({
            "type": "socks",
            "server": server,
            "server_port": server_port,
            "username": "u",
            "password": "p",
        })) {
            Ok(item) => item,
            Err(err) => panic!("测试 fixture 构造失败: {err}"),
        }
    }

    fn domains(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn hairpin_rewritten_to_loopback() {
        let (mut guard, counters) = guard_with(true);
        let mut item = outbound(SELF_DOMAIN, 40324);
        let (kind, detail) = guard.apply_rewrite(&mut item, &[51000, 2080], &[]);
        assert_eq!(kind, Kind::Hairpin);
        assert_eq!(item.get("server").and_then(|v| v.as_str()), Some(LOOPBACK));
        assert!(detail.contains("40324"), "detail 里要带端口: {detail}");
        // 改写说明里报的是解析命中的本机地址（sorted(own)[0] = 10.0.0.87，不是回环）。
        assert!(detail.contains(SELF_IP), "detail 里要带本机 IP: {detail}");
        assert!(
            detail.contains("hairpin"),
            "detail 要说明改写原因: {detail}"
        );
        assert_eq!(counters.probe.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn inbound_port_is_loop_and_untouched() {
        let (mut guard, _counters) = guard_with(true);
        let mut item = outbound(SELF_DOMAIN, 2080);
        let (kind, detail) = guard.apply_rewrite(&mut item, &[2080], &[]);
        assert_eq!(kind, Kind::Loop);
        // 回环自引用不能改写：改写后 sing-box 会自己拨自己的入站，出站→入站→出站。
        assert_eq!(
            item.get("server").and_then(|v| v.as_str()),
            Some(SELF_DOMAIN)
        );
        assert!(detail.contains("回环自引用"), "detail: {detail}");
        assert_eq!(kind.as_str(), LOOP);
    }

    #[test]
    fn loop_check_precedes_local_probe() {
        // 命中入站端口时不该再做端口探测。
        let (mut guard, counters) = guard_with(true);
        let (kind, _detail) = guard.classify(SELF_DOMAIN, 2080, &[2080], &[]);
        assert_eq!(kind, Kind::Loop);
        assert_eq!(counters.probe.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn port_not_served_locally_stays_untouched() {
        let (mut guard, _counters) = guard_with(false);
        let mut item = outbound(SELF_DOMAIN, 40324);
        let (kind, detail) = guard.apply_rewrite(&mut item, &[], &[]);
        assert_eq!(kind, Kind::None);
        assert_eq!(detail, "");
        assert_eq!(
            item.get("server").and_then(|v| v.as_str()),
            Some(SELF_DOMAIN)
        );
    }

    #[test]
    fn external_ip_never_touched() {
        // 外部地址不该触发任何探测：探测计数为 0 即证明没被调用。
        let (mut guard, counters) = guard_with(true);
        let mut item = outbound("203.0.113.7", 443);
        let (kind, _detail) = guard.apply_rewrite(&mut item, &[51000], &[]);
        assert_eq!(kind, Kind::None);
        assert_eq!(
            item.get("server").and_then(|v| v.as_str()),
            Some("203.0.113.7")
        );
        assert_eq!(counters.probe.load(Ordering::SeqCst), 0);
        // IP 字面量解析不查 DNS。
        assert_eq!(counters.resolve.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn unresolvable_host_is_safe() {
        let (mut guard, counters) = guard_with(true);
        let mut item = outbound("no-such-host.invalid", 443);
        let (kind, _detail) = guard.apply_rewrite(&mut item, &[], &[]);
        assert_eq!(kind, Kind::None);
        assert_eq!(counters.resolve.load(Ordering::SeqCst), 1);
        // 解析失败后不该继续探测端口。
        assert_eq!(counters.probe.load(Ordering::SeqCst), 0);
        assert_eq!(
            item.get("server").and_then(|v| v.as_str()),
            Some("no-such-host.invalid")
        );
    }

    #[test]
    fn self_ips_covers_declared_domain() {
        let (mut guard, _counters) = guard_with(true);
        let ips = guard.self_ips(&domains(&[SELF_DOMAIN]));
        assert!(
            ips.contains(SELF_IP),
            "self_ips 要含自报域名解析结果: {ips:?}"
        );
        assert!(ips.contains(LOOPBACK));
        assert!(ips.contains(LOOPBACK_V6));
    }

    #[test]
    fn self_ips_hits_cache_until_refresh() {
        let (mut guard, counters) = guard_with(true);
        let names = domains(&[SELF_DOMAIN]);
        guard.self_ips(&names);
        // 第二次命中 self 缓存：网卡枚举与 DNS 都不再做。
        guard.self_ips(&names);
        assert_eq!(counters.iface.load(Ordering::SeqCst), 1);
        assert_eq!(counters.resolve.load(Ordering::SeqCst), 1);
        // refresh 强制重算 self 集合（网卡重新枚举），但 DNS 结果仍在 TTL 内，不再查解析器。
        guard.self_ips_refresh(&names, true);
        assert_eq!(counters.iface.load(Ordering::SeqCst), 2);
        assert_eq!(counters.resolve.load(Ordering::SeqCst), 1);
        // 域名集合变了（缓存键不同）也要重算。
        guard.self_ips(&domains(&[SELF_DOMAIN, "a.example.com"]));
        assert_eq!(counters.iface.load(Ordering::SeqCst), 3);
        assert_eq!(counters.resolve.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn self_domains_from_settings_extracts_export_and_relay() {
        let settings = json!({"exportDomain": "sgp.zemeil.cyou"});
        let relay_domains = vec![
            json!({"domain": "a.example.com"}),
            json!({"domain": ""}),
            Value::Null,
        ];
        assert_eq!(
            self_domains_from_settings(&settings, &relay_domains),
            vec!["sgp.zemeil.cyou".to_string(), "a.example.com".to_string()]
        );
        // 空设置/空中转表不 panic。
        assert!(self_domains_from_settings(&Value::Null, &[]).is_empty());
        assert!(self_domains_from_settings(&json!({}), &[]).is_empty());
    }

    #[test]
    fn pass_budget_stops_new_lookups() {
        // 预算用尽后不再做任何 DNS/端口探测：留给接口的必须是不阻塞。
        let (mut guard, counters) = guard_with(true);
        guard.begin_pass(0.001);
        std::thread::sleep(Duration::from_millis(10));
        assert!(guard.over_budget());
        let mut item = outbound("slow.example.com", 443);
        let (kind, _detail) = guard.apply_rewrite(&mut item, &[], &[]);
        assert_eq!(kind, Kind::None);
        assert_eq!(counters.resolve.load(Ordering::SeqCst), 0);
        assert_eq!(counters.probe.load(Ordering::SeqCst), 0);
        // 预算内照常放行。
        guard.begin_pass(DEFAULT_PASS_BUDGET);
        assert!(!guard.over_budget());
    }

    #[test]
    fn empty_inputs_do_not_raise() {
        let (mut guard, counters) = guard_with(true);
        let mut empty: Map<String, Value> = Map::new();
        assert_eq!(
            guard.apply_rewrite(&mut empty, &[], &[]),
            (Kind::None, String::new())
        );
        assert_eq!(guard.classify("", 0, &[], &[]), (Kind::None, String::new()));
        assert_eq!(
            guard.classify(SELF_DOMAIN, 70000, &[], &[]),
            (Kind::None, String::new())
        );
        assert_eq!(guard.classify(SELF_DOMAIN, 0, &[], &[]).0, Kind::None);
        assert_eq!(counters.resolve.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn loopback_literal_short_circuits() {
        let (mut guard, counters) = guard_with(true);
        for literal in [LOOPBACK, LOOPBACK_V6] {
            assert_eq!(
                guard.classify(literal, 40324, &[], &[]),
                (Kind::None, String::new())
            );
        }
        assert_eq!(counters.resolve.load(Ordering::SeqCst), 0);
        assert_eq!(counters.probe.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn address_field_is_used_when_server_missing() {
        // wireguard 等出站用 address 承载目标；命中 hairpin 时 Python 也是补写 server 字段。
        let (mut guard, _counters) = guard_with(true);
        let mut item: Map<String, Value> =
            serde_json::from_value(json!({"type": "wireguard", "address": SELF_DOMAIN}))
                .expect("fixture");
        item.insert("server_port".to_string(), json!(40324));
        let (kind, _detail) = guard.apply_rewrite(&mut item, &[], &[]);
        assert_eq!(kind, Kind::Hairpin);
        assert_eq!(item.get("server").and_then(|v| v.as_str()), Some(LOOPBACK));
    }

    #[test]
    fn serve_local_validates_port_range() {
        let (mut guard, counters) = guard_with(true);
        assert!(!guard.serve_local(0));
        assert!(!guard.serve_local(70000));
        assert!(!guard.serve_local(-1));
        assert_eq!(counters.probe.load(Ordering::SeqCst), 0);
        assert!(guard.serve_local(40324));
        assert_eq!(counters.probe.load(Ordering::SeqCst), 1);
        // TTL 内重复查询走缓存。
        assert!(guard.serve_local(40324));
        assert_eq!(counters.probe.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dns_cache_and_reset() {
        let (mut guard, counters) = guard_with(true);
        assert_eq!(guard.resolve(SELF_DOMAIN), vec![SELF_IP.to_string()]);
        assert_eq!(guard.resolve(SELF_DOMAIN), vec![SELF_IP.to_string()]);
        assert_eq!(counters.resolve.load(Ordering::SeqCst), 1);
        // 大小写/空白归一后仍命中同一缓存项。
        assert_eq!(
            guard.resolve("  SG.LSP121.EU.ORG "),
            vec![SELF_IP.to_string()]
        );
        assert_eq!(counters.resolve.load(Ordering::SeqCst), 1);
        guard.reset_cache();
        assert_eq!(guard.resolve(SELF_DOMAIN), vec![SELF_IP.to_string()]);
        assert_eq!(counters.resolve.load(Ordering::SeqCst), 2);
        assert_eq!(guard.resolve(""), Vec::<String>::new());
    }

    /// 集成用例：对齐 tests/test_netguard_integration.py 的 build_config 出站循环。
    /// 三个节点：自引用但端口由本机 nodetap 承接 → 改 127.0.0.1；server_port 正是
    /// 另一个节点的入站端口 → 回环自引用整节点跳过；外部节点原样保留。
    #[test]
    fn build_config_dispatch_rewrites_hairpin_and_skips_loop() {
        let (mut guard, _counters) = guard_with(true);
        // 入站端口规划覆盖全部节点 + 面板总入口（对应 config_manager._plan_inbound_ports）。
        let inbound_ports = [51033_i64, 51013, 51014, 2080];
        let nodes = [
            ("英国h-04", 51033_i64, SELF_DOMAIN, 40324_i64),
            ("法国h-08", 51013, SELF_DOMAIN, 51033),
            ("外部节点", 51014, "203.0.113.7", 443),
        ];

        let mut outbounds: Vec<(String, Map<String, Value>)> = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        let mut notes: Vec<String> = Vec::new();
        let self_domains = self_domains_from_settings(
            &json!({"exportDomain": "sgp.zemeil.cyou", "inboundPort": 2080}),
            &[],
        );
        guard.begin_pass(DEFAULT_PASS_BUDGET);

        for (name, port, server, server_port) in nodes {
            let mut item = outbound(server, server_port);
            item.insert("node_port".to_string(), json!(port));
            let (kind, detail) = guard.apply_rewrite(&mut item, &inbound_ports, &self_domains);
            match kind {
                Kind::Loop => errors.push(format!("{name}: {detail}，已跳过")),
                Kind::Hairpin => {
                    notes.push(format!("{name}: {detail}"));
                    outbounds.push((name.to_string(), item));
                }
                Kind::None => outbounds.push((name.to_string(), item)),
            }
        }

        assert_eq!(outbounds.len(), 2, "回环自引用节点必须被丢弃");
        let hairpin = &outbounds[0].1;
        assert_eq!(
            hairpin.get("server").and_then(|v| v.as_str()),
            Some(LOOPBACK),
            "自引用节点要改写 127.0.0.1"
        );
        assert_eq!(
            hairpin.get("server_port").and_then(|v| v.as_i64()),
            Some(40324)
        );
        // 改写只动 server，端口保持原值（否则就打到别的节点去了）。
        assert_eq!(
            hairpin.get("node_port").and_then(|v| v.as_i64()),
            Some(51033)
        );
        let external = &outbounds[1].1;
        assert_eq!(
            external.get("server").and_then(|v| v.as_str()),
            Some("203.0.113.7"),
            "外部节点一个字节都不许动"
        );
        assert!(
            errors.iter().any(|e| e.contains("回环自引用")),
            "回环节点要留错误记录: {errors:?}"
        );
        assert!(
            errors.iter().any(|e| e.contains("法国h-08")),
            "错误记录要带节点名: {errors:?}"
        );
        assert_eq!(notes.len(), 1, "hairpin 要留 note: {notes:?}");
    }

    #[test]
    fn global_singleton_smoke() {
        // 全局单例只验证可调用与状态可重置，不触发真实网络：
        // 用 IP 字面量走短路路径，避免 getaddrinfo/socket。
        reset_cache();
        begin_pass(0.0); // 0 = 不限
        assert_eq!(resolve("203.0.113.7"), vec!["203.0.113.7".to_string()]);
        let mut item: Map<String, Value> =
            serde_json::from_value(json!({"server": "203.0.113.7", "server_port": 443}))
                .expect("fixture");
        assert_eq!(apply_rewrite(&mut item, &[], &[]).0, Kind::None);
        assert_eq!(
            item.get("server").and_then(|v| v.as_str()),
            Some("203.0.113.7")
        );
        assert_eq!(classify("", 0, &[], &[]), (Kind::None, String::new()));
        reset_cache();
    }

    #[test]
    fn set_entry_points_match_slice_entry_points() {
        // config_manager 的 _plan_inbound_ports 返回集合，两个入口必须给出同样的判定。
        let (mut guard, _counters) = guard_with(true);
        let inbound: BTreeSet<i64> = [51033_i64, 51013, 51014, 2080].into_iter().collect();
        assert_eq!(
            guard.classify_set(SELF_DOMAIN, 2080, &inbound, &[]),
            guard.classify(SELF_DOMAIN, 2080, &[2080], &[])
        );
        let mut item = outbound(SELF_DOMAIN, 40324);
        assert_eq!(
            guard.apply_rewrite_set(&mut item, &inbound, &[]).0,
            Kind::Hairpin
        );
        assert_eq!(item.get("server").and_then(|v| v.as_str()), Some(LOOPBACK));
        let mut item = outbound(SELF_DOMAIN, 51013);
        assert_eq!(
            guard.apply_rewrite_set(&mut item, &inbound, &[]).0,
            Kind::Loop
        );
    }

    #[test]
    fn kind_strings_match_python_constants() {
        assert_eq!(Kind::None.as_str(), "");
        assert_eq!(Kind::Loop.as_str(), "loop");
        assert_eq!(Kind::Hairpin.as_str(), "hairpin");
    }
}
