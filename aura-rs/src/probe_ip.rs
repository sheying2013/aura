//! 出口 IP 探测：经节点自身代理（socks5 / http）或本地 sing-box mixed 入站查真实公网出口 IP。
//!
//! 行为基准：backend/probe_ip.py（只读，不修改）—— 端点列表与顺序、Host / UA 缺失口径、
//! 超时、响应体上限、reason 取值全部逐字对齐。
//!
//! 不变量：任何路径都不得把入口 server 的地址当作出口 IP 返回 —— 出口 IP 只能来自
//! 经代理实际访问远端探测站点得到的响应体。
//!
//! 解耦口径：本模块不依赖 crate::subs_proxy（迁移并行期它会被反复改动）。调用方把节点
//! 端点收敛成 ProxyTarget 传进来；NodeProbe 只是把 Python 的 node dict 换成 struct，让
//! probe / diagnose 的语义与 Python 版一一对应：
//!   protocol -> NodeProbe::protocol，subs_proxy.proxy_endpoint(node) -> NodeProbe::endpoint，
//!   entryProto -> entry_proto，port -> inbound_port，authUser/authPass -> auth_user/auth_pass。
//!
//! 失败原因取值（与 Python 完全一致，组合结果用 "+" 连接）：
//!   native_unsupported / native_endpoint_missing / native_dial_failed /
//!   inbound_disabled / inbound_port_invalid / inbound_dial_failed。
//! 底层细节（连接被拒、认证被拒、响应体没有合法 IP…）放在 ProbeAttempt::detail，
//! 不污染 reason 取值：上层按 code 分支、按 detail 排障。

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::OnceLock;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use regex::Regex;

use crate::utils::is_ip_address;

/// 可不依赖本地 sing-box 入站、直接用协议原生拨号的代理类型。
pub const NATIVE_PROXY_PROTOS: &[&str] = &["socks5", "socks", "http"];
/// 单次连接 / 读写超时（秒），对应 Python 的 sock.settimeout(CONNECT_TIMEOUT)。
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(6);
/// 响应体上限，防异常上游无限灌数据。
pub const MAX_RESPONSE: usize = 65536;
/// 短 IPv4 串长度，够用即可提前结束读取。
pub const MIN_BODY: usize = 7;
/// 出口 IP 探测站点（按顺序取第一个可用结果）。
pub const TARGETS: &[&str] = &["api.ipify.org", "icanhazip.com"];
/// 探测请求固定打的明文 HTTP 端口。
pub const TARGET_HTTP_PORT: u16 = 80;
/// Python 侧 node.get("entryProto") or "mixed" 的缺省值。
pub const DEFAULT_ENTRY_PROTO: &str = "mixed";
/// 本地 sing-box 混合入站地址。
pub const INBOUND_HOST: &str = "127.0.0.1";
/// Python 侧 node.get("authUser") or "user" 的缺省值。
pub const DEFAULT_AUTH_USER: &str = "user";
/// Python 侧 node.get("authPass") or "pass" 的缺省值。
pub const DEFAULT_AUTH_PASS: &str = "pass";

/// reason：协议不支持原生直连探测。
pub const REASON_NATIVE_UNSUPPORTED: &str = "native_unsupported";
/// reason：节点缺少可用的 server/server_port。
pub const REASON_NATIVE_ENDPOINT_MISSING: &str = "native_endpoint_missing";
/// reason：原生直连拨号失败（含认证被拒、无合法 IP）。
pub const REASON_NATIVE_DIAL_FAILED: &str = "native_dial_failed";
/// reason：入口不是 mixed，没有混合入站可兜底。
pub const REASON_INBOUND_DISABLED: &str = "inbound_disabled";
/// reason：混合入站端口非法。
pub const REASON_INBOUND_PORT_INVALID: &str = "inbound_port_invalid";
/// reason：本地混合入站拨号失败。
pub const REASON_INBOUND_DIAL_FAILED: &str = "inbound_dial_failed";

/// 一个代理端点：只有拨号必需的最小字段，不引用任何节点结构体。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProxyTarget {
    /// 原生协议名：socks5 / socks / http。
    pub scheme: String,
    /// 代理主机（域名或 IP）。
    pub host: String,
    /// 代理端口。
    pub port: u16,
    /// SOCKS5 用户名 / HTTP Basic 用户名。
    pub user: Option<String>,
    /// SOCKS5 密码 / HTTP Basic 密码。
    pub pass: Option<String>,
}

impl ProxyTarget {
    pub fn new(scheme: impl Into<String>, host: impl Into<String>, port: u16) -> Self {
        Self {
            scheme: scheme.into(),
            host: host.into(),
            port,
            user: None,
            pass: None,
        }
    }

    /// socks5 端点（scheme 固定 socks5）。
    pub fn socks5(host: impl Into<String>, port: u16) -> Self {
        Self::new("socks5", host, port)
    }

    /// 明文 HTTP 代理端点。
    pub fn http(host: impl Into<String>, port: u16) -> Self {
        Self::new("http", host, port)
    }

    /// 挂上认证信息（None 视为空串，与 Python 的 user or "" 等价）。
    pub fn with_credentials(
        mut self,
        user: Option<impl Into<String>>,
        pass: Option<impl Into<String>>,
    ) -> Self {
        self.user = user.map(Into::into);
        self.pass = pass.map(Into::into);
        self
    }

    /// 是否明文 HTTP 代理（其余一律按 SOCKS5 拨）。
    pub fn is_http(&self) -> bool {
        self.scheme.eq_ignore_ascii_case("http")
    }

    /// 端点是否可用：host 非空且端口非 0。
    pub fn is_usable(&self) -> bool {
        !self.host.trim().is_empty() && self.port != 0
    }

    /// (user, pass)，缺省为空串。
    pub fn auth(&self) -> (&str, &str) {
        (
            self.user.as_deref().unwrap_or(""),
            self.pass.as_deref().unwrap_or(""),
        )
    }

    /// host:port 展示形式。
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// 一次探测的结果：ip 为 None 时 reason 说明是哪个环节断的，detail 给人类可读细节。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProbeAttempt {
    /// 解析出的出口 IP；None 表示失败。
    pub ip: Option<String>,
    /// 失败原因 code（Python 兼容取值，组合时用 "+" 连接）；成功时为空串。
    pub reason: String,
    /// 底层细节（连接被拒 / 认证被拒 / 响应体没有合法 IP…），不参与 reason 取值。
    pub detail: Option<String>,
}

impl ProbeAttempt {
    /// 成功。
    pub fn ok(ip: impl Into<String>) -> Self {
        Self {
            ip: Some(ip.into()),
            reason: String::new(),
            detail: None,
        }
    }

    /// 失败（只带 code）。
    pub fn fail(reason: impl Into<String>) -> Self {
        Self {
            ip: None,
            reason: reason.into(),
            detail: None,
        }
    }

    /// 追加细节（多次调用按 "；" 拼接；空串忽略）。
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        let d = detail.into();
        if !d.trim().is_empty() {
            self.detail = Some(match self.detail.take() {
                Some(prev) if !prev.is_empty() => format!("{prev}；{d}"),
                _ => d,
            });
        }
        self
    }

    pub fn is_ok(&self) -> bool {
        self.ip.is_some()
    }

    /// 把两次失败拼成 Python 的 "native+inbound" 形式（detail 一并合并）。
    pub fn chain(&self, other: &ProbeAttempt) -> ProbeAttempt {
        let mut out = ProbeAttempt::fail(format!("{}+{}", self.reason, other.reason));
        if let Some(d) = self.detail.as_deref() {
            out = out.with_detail(d);
        }
        if let Some(d) = other.detail.as_deref() {
            out = out.with_detail(d);
        }
        out
    }
}

/// 由协议名 + 可选端点构造原生直连目标；失败时给出 Python 兼容的 reason。
pub fn native_target(
    protocol: &str,
    endpoint: Option<ProxyTarget>,
) -> Result<ProxyTarget, &'static str> {
    let proto = protocol.trim().to_ascii_lowercase();
    if !NATIVE_PROXY_PROTOS.contains(&proto.as_str()) {
        return Err(REASON_NATIVE_UNSUPPORTED);
    }
    match endpoint {
        Some(mut t) if t.is_usable() => {
            t.scheme = proto;
            Ok(t)
        }
        _ => Err(REASON_NATIVE_ENDPOINT_MISSING),
    }
}

/// 由入口协议 + 端口构造本地 mixed 入站目标；失败时给出 Python 兼容的 reason。
pub fn inbound_target(
    entry_proto: &str,
    port: i64,
    user: Option<&str>,
    pass: Option<&str>,
) -> Result<ProxyTarget, &'static str> {
    let entry = normalize_entry_proto(entry_proto);
    if entry != DEFAULT_ENTRY_PROTO {
        return Err(REASON_INBOUND_DISABLED);
    }
    if !(1..=65535).contains(&port) {
        return Err(REASON_INBOUND_PORT_INVALID);
    }
    let user = user
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_AUTH_USER);
    let pass = pass
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_AUTH_PASS);
    Ok(ProxyTarget::socks5(INBOUND_HOST, port as u16).with_credentials(Some(user), Some(pass)))
}

/// entryProto or "mixed" 的 Rust 版。
pub fn normalize_entry_proto(entry_proto: &str) -> &str {
    let t = entry_proto.trim();
    if t.is_empty() {
        DEFAULT_ENTRY_PROTO
    } else {
        t
    }
}

/// 结构化诊断（不发网络）：返回空串表示至少存在一条可用路径，否则给出人类可读原因。
pub fn diagnose(
    protocol: &str,
    native_endpoint_present: bool,
    entry_proto: &str,
    inbound_port: i64,
) -> String {
    let proto = protocol.trim().to_ascii_lowercase();
    let native_supported = NATIVE_PROXY_PROTOS.contains(&proto.as_str());
    let native_ok = native_supported && native_endpoint_present;
    let entry = normalize_entry_proto(entry_proto);
    let inbound_ok = entry == DEFAULT_ENTRY_PROTO && (1..=65535).contains(&inbound_port);
    if native_ok || inbound_ok {
        return String::new();
    }
    let mut parts: Vec<String> = Vec::new();
    if !native_supported {
        let shown = if proto.is_empty() {
            "未知"
        } else {
            proto.as_str()
        };
        parts.push(format!("协议 {shown} 不支持直连探测"));
    } else {
        parts.push("节点 rawConfig 缺少可用的 server/server_port".to_string());
    }
    if entry != DEFAULT_ENTRY_PROTO {
        parts.push(format!("入口协议为 {entry}，没有混合入站可兜底"));
    } else {
        parts.push(format!("混合入站端口无效（{inbound_port}）"));
    }
    parts.join("；")
}

/// Python node dict 的解耦替身：只有探测真正需要的字段。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NodeProbe {
    /// 节点协议名（socks5 / socks / http / ss / vmess…）。
    pub protocol: String,
    /// 由调用方用 subs_proxy::proxy_endpoint 等构造的原生直连端点。
    pub endpoint: Option<ProxyTarget>,
    /// 入口协议，缺省 mixed。
    pub entry_proto: String,
    /// 混合入站端口（<=0 视为非法）。
    pub inbound_port: i64,
    /// 混合入站用户名，缺省 user。
    pub auth_user: Option<String>,
    /// 混合入站密码，缺省 pass。
    pub auth_pass: Option<String>,
}

impl NodeProbe {
    pub fn new(protocol: impl Into<String>) -> Self {
        Self {
            protocol: protocol.into(),
            endpoint: None,
            entry_proto: DEFAULT_ENTRY_PROTO.to_string(),
            inbound_port: 0,
            auth_user: None,
            auth_pass: None,
        }
    }

    pub fn endpoint(mut self, endpoint: Option<ProxyTarget>) -> Self {
        self.endpoint = endpoint;
        self
    }

    pub fn entry_proto(mut self, entry_proto: impl Into<String>) -> Self {
        self.entry_proto = entry_proto.into();
        self
    }

    pub fn inbound_port(mut self, port: i64) -> Self {
        self.inbound_port = port;
        self
    }

    pub fn auth(
        mut self,
        user: Option<impl Into<String>>,
        pass: Option<impl Into<String>>,
    ) -> Self {
        self.auth_user = user.map(Into::into);
        self.auth_pass = pass.map(Into::into);
        self
    }

    /// 先按原生协议直连，失败再走本地入站兜底，并带回断在哪一环。
    pub fn probe(&self) -> ProbeAttempt {
        self.probe_with_targets(TARGETS)
    }

    /// 同上，可指定探测站点（测试用，生产不要传）。
    pub fn probe_with_targets(&self, targets: &[&str]) -> ProbeAttempt {
        let native = native_target(&self.protocol, self.endpoint.clone());
        let inbound = inbound_target(
            &self.entry_proto,
            self.inbound_port,
            self.auth_user.as_deref(),
            self.auth_pass.as_deref(),
        );
        probe_targets(native, inbound, targets)
    }

    /// 结构性诊断：不发网络。
    pub fn diagnose(&self) -> String {
        diagnose(
            &self.protocol,
            self.endpoint.is_some(),
            &self.entry_proto,
            self.inbound_port,
        )
    }
}

/// 探测入口：native / inbound 两个端点任一可用即返回 IP，否则 reason 用 "+" 串起两段。
pub fn probe_attempt(native: Option<&ProxyTarget>, inbound: Option<&ProxyTarget>) -> ProbeAttempt {
    probe_attempt_with_targets(native, inbound, TARGETS)
}

/// 同上，可指定探测站点（测试用）。
pub fn probe_attempt_with_targets(
    native: Option<&ProxyTarget>,
    inbound: Option<&ProxyTarget>,
    targets: &[&str],
) -> ProbeAttempt {
    let n = native.ok_or(REASON_NATIVE_ENDPOINT_MISSING);
    let i = inbound.ok_or(REASON_INBOUND_DISABLED);
    probe_targets(n.cloned(), i.cloned(), targets)
}

/// 核心编排：先原生、后入站；两段都失败时把 reason 与 detail 都带上。
fn probe_targets(
    native: Result<ProxyTarget, &'static str>,
    inbound: Result<ProxyTarget, &'static str>,
    targets: &[&str],
) -> ProbeAttempt {
    let n = match native {
        Ok(t) => probe_native(&t, targets),
        Err(code) => ProbeAttempt::fail(code),
    };
    if n.is_ok() {
        return n;
    }
    let i = match inbound {
        Ok(t) => probe_inbound(&t, targets),
        Err(code) => ProbeAttempt::fail(code),
    };
    if i.is_ok() {
        return i;
    }
    n.chain(&i)
}

/// 按节点原生代理协议直连探测（不经过本地 sing-box 入站）。
pub fn probe_native(endpoint: &ProxyTarget, targets: &[&str]) -> ProbeAttempt {
    dial_sites(endpoint, targets, REASON_NATIVE_DIAL_FAILED)
}

/// 经本地 sing-box mixed 入站探测（原生代理探测失败或不适用时的兜底）。
pub fn probe_inbound(endpoint: &ProxyTarget, targets: &[&str]) -> ProbeAttempt {
    dial_sites(endpoint, targets, REASON_INBOUND_DIAL_FAILED)
}

fn dial_sites(endpoint: &ProxyTarget, targets: &[&str], fail_reason: &str) -> ProbeAttempt {
    let mut detail = String::new();
    for site in targets {
        match dial(endpoint, site) {
            Ok(ip) => return ProbeAttempt::ok(ip),
            Err(e) => detail.push_str(&format!("{site}({}) -> {e}；", endpoint.authority())),
        }
    }
    let d = if detail.is_empty() {
        "探测站点列表为空".to_string()
    } else {
        detail
    };
    ProbeAttempt::fail(fail_reason).with_detail(d)
}

/// 拨号并取回站点回显的出口 IP；按 scheme 选择 SOCKS5 / HTTP 代理路径。
pub fn dial(endpoint: &ProxyTarget, site: &str) -> Result<String, String> {
    if !endpoint.is_usable() {
        return Err("端点缺少 host/port".to_string());
    }
    if endpoint.is_http() {
        dial_http(endpoint, site)
    } else if endpoint.scheme.eq_ignore_ascii_case("socks5")
        || endpoint.scheme.eq_ignore_ascii_case("socks")
    {
        dial_socks5(endpoint, site)
    } else {
        Err(format!("不支持直连探测的协议: {}", endpoint.scheme))
    }
}

/// 经 SOCKS5 隧道（目标端口固定 80）取回站点回显 IP。
pub fn dial_socks5(endpoint: &ProxyTarget, site: &str) -> Result<String, String> {
    let mut stream = connect(&endpoint.host, endpoint.port)?;
    let (user, pass) = endpoint.auth();
    socks5_handshake(&mut stream, site, TARGET_HTTP_PORT, user, pass)?;
    read_ip(&mut stream, &origin_request(site))
}

/// 经明文 HTTP 代理（绝对 URI + 可选 Basic 认证）取回站点回显 IP。
pub fn dial_http(endpoint: &ProxyTarget, site: &str) -> Result<String, String> {
    let mut stream = connect(&endpoint.host, endpoint.port)?;
    let (user, pass) = endpoint.auth();
    read_ip(&mut stream, &proxy_request(site, user, pass))
}

/// 建立 TCP 连接并设置读写超时（Python 的 connect + settimeout 等价物）。
fn connect(host: &str, port: u16) -> Result<TcpStream, String> {
    let addrs: Vec<std::net::SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("解析 {host}:{port} 失败: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("{host}:{port} 无可用地址"));
    }
    let mut last = String::new();
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(s) => {
                let _ = s.set_read_timeout(Some(CONNECT_TIMEOUT));
                let _ = s.set_write_timeout(Some(CONNECT_TIMEOUT));
                return Ok(s);
            }
            Err(e) => last = format!("连接 {addr} 失败: {e}"),
        }
    }
    Err(last)
}

/// 读满 size 字节（SOCKS5 定长应答必须读净，否则污染后续 HTTP 流）。
fn recv_exact(stream: &mut TcpStream, size: usize) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::with_capacity(size);
    let mut buf = [0u8; 512];
    while out.len() < size {
        let want = (size - out.len()).min(buf.len());
        match stream.read(&mut buf[..want]) {
            Ok(0) => return Err("SOCKS5 响应提前结束".to_string()),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("读取 SOCKS5 响应失败: {e}")),
        }
    }
    Ok(out)
}

/// 直连目标站点用的请求（经 SOCKS5 隧道时用）；与 Python 版逐字一致：http/1.0、无 User-Agent。
pub fn origin_request(host: &str) -> Vec<u8> {
    format!("GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n").into_bytes()
}

/// HTTP 代理用的绝对 URI 请求，带可选 Basic 认证。
pub fn proxy_request(host: &str, user: &str, pass: &str) -> Vec<u8> {
    let mut lines = vec![
        format!("GET http://{host}/ HTTP/1.0"),
        format!("Host: {host}"),
        "Connection: close".to_string(),
    ];
    if !user.is_empty() || !pass.is_empty() {
        let cred = BASE64.encode(format!("{user}:{pass}").as_bytes());
        lines.push(format!("Proxy-Authorization: Basic {cred}"));
    }
    format!("{}\r\n\r\n", lines.join("\r\n")).into_bytes()
}

/// 发送请求、读取响应体并从中解析出合法 IP（socks5 / http 两条路径共用）。
pub fn read_ip(stream: &mut TcpStream, request: &[u8]) -> Result<String, String> {
    stream
        .write_all(request)
        .map_err(|e| format!("发送探测请求失败: {e}"))?;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > MAX_RESPONSE {
                    break;
                }
                if let Some(pos) = find_sub(&buf, b"\r\n\r\n") {
                    if buf.len() - (pos + 4) >= MIN_BODY {
                        break;
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("读取探测响应失败: {e}")),
        }
    }
    let pos = find_sub(&buf, b"\r\n\r\n").ok_or_else(|| "响应缺少 HTTP 头结束标记".to_string())?;
    let body = String::from_utf8_lossy(&buf[pos + 4..]);
    parse_ip(body.trim())
}

/// 从响应体里取第一个合法 IP：优先 IPv4 正则（与 Python 一致），再兜 IPv6 字面量。
pub fn parse_ip(body: &str) -> Result<String, String> {
    if let Some(caps) = ipv4_re().captures(body) {
        let cand = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        if is_ip_address(cand) {
            return Ok(cand.to_string());
        }
        return Err(format!("响应体 IPv4 不合法: {cand}"));
    }
    for token in body.split(|c: char| !(c.is_ascii_hexdigit() || c == ':' || c == '.')) {
        let t = token.trim_matches('.');
        if t.contains(':') && is_ip_address(t) {
            return Ok(t.to_string());
        }
    }
    Err(format!("响应体里没有合法 IP: {}", truncate(body, 60)))
}

/// 完成 SOCKS5 认证协商 + CONNECT（RFC 1928），并消费完整变长 BND.ADDR/BND.PORT。
///
/// 认证协商声明 0x00（无认证）与 0x02（用户名密码）两种方式；服务端选 0x00 则跳过子协商，
/// 选 0x02 则按 RFC 1929 提交用户名密码，其余（含 0xFF 全部拒绝）一律失败。
pub fn socks5_handshake(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
) -> Result<(), String> {
    if host.trim().is_empty() {
        return Err("SOCKS5 目标 host 为空".to_string());
    }
    stream
        .write_all(&[0x05, 0x02, 0x00, 0x02])
        .map_err(|e| format!("发送 SOCKS5 认证协商失败: {e}"))?;
    let method = recv_exact(stream, 2)?;
    if method[0] != 0x05 {
        return Err(format!("SOCKS5 版本非 0x05: 0x{:02x}", method[0]));
    }
    match method[1] {
        0x00 => {}
        0x02 => {
            let ub = user.as_bytes();
            let pb = pass.as_bytes();
            if ub.len() > 255 || pb.len() > 255 {
                return Err(format!(
                    "SOCKS5 用户名/密码超长（{} / {} 字节，上限 255）",
                    ub.len(),
                    pb.len()
                ));
            }
            let mut msg = Vec::with_capacity(3 + ub.len() + pb.len());
            msg.push(0x01);
            msg.push(ub.len() as u8);
            msg.extend_from_slice(ub);
            msg.push(pb.len() as u8);
            msg.extend_from_slice(pb);
            stream
                .write_all(&msg)
                .map_err(|e| format!("发送 SOCKS5 用户名密码失败: {e}"))?;
            let ack = recv_exact(stream, 2)?;
            if ack[1] != 0x00 {
                return Err(format!("SOCKS5 用户名/密码认证被拒(0x{:02x})", ack[1]));
            }
        }
        other => return Err(format!("SOCKS5 认证方式被拒(0x{other:02x})")),
    }

    // CONNECT：与 Python 版一致，一律按域名 ATYP=0x03 交给代理解析（探测目标都是域名）。
    let hb = host.as_bytes();
    if hb.len() > 255 {
        return Err(format!(
            "SOCKS5 目标域名超长（{} 字节，上限 255）",
            hb.len()
        ));
    }
    let mut req = Vec::with_capacity(5 + hb.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, hb.len() as u8]);
    req.extend_from_slice(hb);
    req.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&req)
        .map_err(|e| format!("发送 SOCKS5 CONNECT 失败: {e}"))?;

    let hdr = recv_exact(stream, 4)?;
    if hdr[0] != 0x05 {
        return Err(format!("SOCKS5 CONNECT 应答版本非 0x05: 0x{:02x}", hdr[0]));
    }
    if hdr[1] != 0x00 {
        return Err(socks5_reply_detail(hdr[1]));
    }
    if hdr[2] != 0x00 {
        return Err(format!("SOCKS5 CONNECT 应答保留位非 0: 0x{:02x}", hdr[2]));
    }
    match hdr[3] {
        0x01 => {
            recv_exact(stream, 6)?;
        }
        0x03 => {
            let n = recv_exact(stream, 1)?[0] as usize;
            recv_exact(stream, n + 2)?;
        }
        0x04 => {
            recv_exact(stream, 18)?;
        }
        other => return Err(format!("SOCKS5 CONNECT 应答地址类型未知: 0x{other:02x}")),
    }
    Ok(())
}

/// RFC 1928 REP 码 -> 人类可读原因。
fn socks5_reply_detail(rep: u8) -> String {
    let text = match rep {
        0x01 => "通用失败",
        0x02 => "规则不允许",
        0x03 => "网络不可达",
        0x04 => "主机不可达",
        0x05 => "连接被拒",
        0x06 => "TTL 过期",
        0x07 => "命令不支持",
        0x08 => "地址类型不支持",
        _ => "未知错误码",
    };
    format!("SOCKS5 CONNECT 失败(0x{rep:02x}): {text}")
}

fn ipv4_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").expect("IPv4 正则"))
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn truncate(s: &str, limit: usize) -> String {
    let t = s.trim();
    if t.chars().count() <= limit {
        return t.to_string();
    }
    let cut: String = t.chars().take(limit).collect();
    format!("{cut}…")
}

/// 同步探测（阻塞，仅供 spawn_blocking / to_thread 调用）。
pub fn fetch_exit_ip_sync(node: &NodeProbe) -> Option<String> {
    node.probe().ip
}

/// 异步探测节点真实出口 IP：先按原生协议直连，失败再走本地入站兜底。
///
/// Python 用 asyncio.to_thread 包住同步实现；这里用 spawn_blocking，语义相同：
/// 阻塞的 socket 读写绝不跑在 tokio 工作线程上。
pub async fn fetch_exit_ip(node: NodeProbe) -> Option<String> {
    match tokio::task::spawn_blocking(move || node.probe().ip).await {
        Ok(ip) => ip,
        Err(e) => {
            tracing::warn!(error = %e, "出口 IP 探测任务崩溃");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};

    const TEST_IP: &str = "203.0.113.7";
    const TEST_SITE: &str = "api.ipify.org";

    // ---- 假代理工厂 ----

    #[derive(Clone, Copy)]
    enum Auth {
        None,
        UserPass,
        RejectAll,
    }

    #[derive(Clone, Copy)]
    enum Bnd {
        V4,
        Domain,
        V6,
    }

    impl Bnd {
        fn reply(&self) -> Vec<u8> {
            match self {
                Bnd::V4 => {
                    let mut v = vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1];
                    v.extend_from_slice(&8080u16.to_be_bytes());
                    v
                }
                Bnd::Domain => {
                    let d = b"relay.local";
                    let mut v = vec![0x05, 0x00, 0x00, 0x03, d.len() as u8];
                    v.extend_from_slice(d);
                    v.extend_from_slice(&1080u16.to_be_bytes());
                    v
                }
                Bnd::V6 => {
                    let mut v = vec![0x05, 0x00, 0x00, 0x04];
                    v.extend_from_slice(&[0u8; 16]);
                    v.extend_from_slice(&0u16.to_be_bytes());
                    v
                }
            }
        }
    }

    fn read_until_headers(c: &mut TcpStream) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        let mut b = [0u8; 1024];
        loop {
            let n = c.read(&mut b).expect("读请求");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&b[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        buf
    }

    /// 起一个假 SOCKS5 代理：走完协商 + CONNECT，再回一段带 body 的 HTTP 响应。
    fn spawn_socks5(auth: Auth, bnd: Bnd, body: &'static str) -> (u16, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("绑定假代理");
        let port = listener.local_addr().expect("本地地址").port();
        let handle = thread::spawn(move || {
            let (mut c, _) = listener.accept().expect("接受连接");
            let mut head = [0u8; 2];
            c.read_exact(&mut head).expect("读协商头");
            assert_eq!(head[0], 0x05, "客户端必须声明 SOCKS5");
            let mut methods = vec![0u8; head[1] as usize];
            c.read_exact(&mut methods).expect("读认证方式");
            assert!(
                methods.contains(&0x00) && methods.contains(&0x02),
                "必须同时声明 0x00/0x02"
            );
            match auth {
                Auth::RejectAll => {
                    c.write_all(&[0x05, 0xFF]).expect("写拒绝");
                    return;
                }
                Auth::None => c.write_all(&[0x05, 0x00]).expect("写选 0x00"),
                Auth::UserPass => {
                    c.write_all(&[0x05, 0x02]).expect("写选 0x02");
                    let mut sub = [0u8; 2];
                    c.read_exact(&mut sub).expect("读用户名密码头");
                    assert_eq!(sub[0], 0x01, "RFC 1929 版本");
                    let mut u = vec![0u8; sub[1] as usize];
                    c.read_exact(&mut u).expect("读用户名");
                    let mut pl = [0u8; 1];
                    c.read_exact(&mut pl).expect("读密码长度");
                    let mut p = vec![0u8; pl[0] as usize];
                    c.read_exact(&mut p).expect("读密码");
                    assert_eq!(String::from_utf8_lossy(&u), "alice");
                    assert_eq!(String::from_utf8_lossy(&p), "secret");
                    c.write_all(&[0x01, 0x00]).expect("写认证通过");
                }
            }
            let mut hdr = [0u8; 4];
            c.read_exact(&mut hdr).expect("读 CONNECT 头");
            assert_eq!(hdr[0], 0x05);
            assert_eq!(hdr[1], 0x01, "必须是 CONNECT");
            assert_eq!(hdr[3], 0x03, "探测目标按域名下发");
            let mut hl = [0u8; 1];
            c.read_exact(&mut hl).expect("读域名长度");
            let mut host = vec![0u8; hl[0] as usize];
            c.read_exact(&mut host).expect("读域名");
            assert_eq!(String::from_utf8_lossy(&host), TEST_SITE);
            let mut portb = [0u8; 2];
            c.read_exact(&mut portb).expect("读目标端口");
            assert_eq!(u16::from_be_bytes(portb), 80);
            c.write_all(&bnd.reply()).expect("写 CONNECT 应答");
            let req = read_until_headers(&mut c);
            let text = String::from_utf8_lossy(&req);
            assert!(
                text.starts_with("GET / HTTP/1.0\r\n"),
                "隧道内必须用 origin-form 请求: {text:?}"
            );
            assert!(text.contains("Host: api.ipify.org\r\n"));
            let resp = format!("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n{body}");
            c.write_all(resp.as_bytes()).expect("写响应");
        });
        (port, handle)
    }

    /// 起一个假明文 HTTP 代理，记录收到的请求供断言。
    fn spawn_http_proxy(body: &'static str) -> (u16, Arc<Mutex<Vec<u8>>>, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("绑定假代理");
        let port = listener.local_addr().expect("本地地址").port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let handle = thread::spawn(move || {
            let (mut c, _) = listener.accept().expect("接受连接");
            let req = read_until_headers(&mut c);
            *sink.lock().expect("锁住请求记录") = req;
            let resp = format!("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n{body}");
            c.write_all(resp.as_bytes()).expect("写响应");
        });
        (port, seen, handle)
    }

    fn socks5_attempt(port: u16) -> ProbeAttempt {
        let ep = ProxyTarget::socks5("127.0.0.1", port);
        probe_attempt_with_targets(Some(&ep), None, &[TEST_SITE])
    }

    // ---- 1. 无认证 SOCKS5 成功 ----

    #[test]
    fn socks5_without_auth_returns_exit_ip() {
        let (port, handle) = spawn_socks5(Auth::None, Bnd::V4, TEST_IP);
        let a = socks5_attempt(port);
        handle.join().expect("假代理线程");
        assert_eq!(a.ip.as_deref(), Some(TEST_IP));
        assert_eq!(a.reason, "");
        assert!(a.is_ok());
    }

    // ---- 2. 用户名/密码认证 SOCKS5 成功 ----

    #[test]
    fn socks5_with_user_password_auth_returns_exit_ip() {
        let (port, handle) = spawn_socks5(Auth::UserPass, Bnd::V4, TEST_IP);
        let ep =
            ProxyTarget::socks5("127.0.0.1", port).with_credentials(Some("alice"), Some("secret"));
        let a = probe_attempt_with_targets(Some(&ep), None, &[TEST_SITE]);
        handle.join().expect("假代理线程");
        assert_eq!(a.ip.as_deref(), Some(TEST_IP), "认证链路必须跑通: {a:?}");
        assert!(a.reason.is_empty());
    }

    // ---- 3. BND.ADDR 变长（域名 / IPv6）必须按 RFC 1928 跳干净 ----

    #[test]
    fn socks5_variable_bnd_address_is_consumed() {
        for bnd in [Bnd::Domain, Bnd::V6] {
            let (port, handle) = spawn_socks5(Auth::None, bnd, TEST_IP);
            let a = socks5_attempt(port);
            handle.join().expect("假代理线程");
            assert_eq!(
                a.ip.as_deref(),
                Some(TEST_IP),
                "BND 变长地址没跳干净会污染后续 HTTP 流: {a:?}"
            );
        }
    }

    // ---- 4. 认证失败（0x05 0xFF）返回 reason 而不是 panic ----

    #[test]
    fn socks5_auth_rejected_returns_reason() {
        let (port, handle) = spawn_socks5(Auth::RejectAll, Bnd::V4, TEST_IP);
        let a = socks5_attempt(port);
        handle.join().expect("假代理线程");
        assert!(a.ip.is_none());
        assert_eq!(
            a.reason,
            format!("{REASON_NATIVE_DIAL_FAILED}+{REASON_INBOUND_DISABLED}")
        );
        let detail = a.detail.unwrap_or_default();
        assert!(
            detail.contains("认证方式被拒"),
            "detail 要能看出断在认证: {detail}"
        );
        assert!(
            detail.contains("0xff"),
            "detail 要带服务端返回的方式码: {detail}"
        );
    }

    // ---- 5. 连接被拒（端口无人监听）返回 None + reason ----

    #[test]
    fn connect_refused_returns_none_with_reason() {
        let probe = TcpListener::bind("127.0.0.1:0").expect("占位端口");
        let port = probe.local_addr().expect("本地地址").port();
        drop(probe); // 端口随即无人监听
        let a = socks5_attempt(port);
        assert!(a.ip.is_none(), "拒绝连接不得给出 IP: {a:?}");
        assert!(
            a.reason.contains(REASON_NATIVE_DIAL_FAILED),
            "reason 必须指向原生拨号失败: {}",
            a.reason
        );
        let detail = a.detail.unwrap_or_default();
        assert!(detail.contains("连接"), "detail 要保留底层错误: {detail}");
    }

    // ---- 6. 返回非 IP 文本时判定为失败 ----

    #[test]
    fn non_ip_body_is_failure() {
        let (port, handle) = spawn_socks5(Auth::None, Bnd::V4, "this is not an ip");
        let a = socks5_attempt(port);
        handle.join().expect("假代理线程");
        assert!(a.ip.is_none(), "非 IP 文本不得当出口 IP: {a:?}");
        assert!(a.detail.unwrap_or_default().contains("没有合法 IP"));
    }

    // ---- 附加：HTTP 代理 + Basic 认证 ----

    #[test]
    fn http_proxy_with_basic_auth_returns_exit_ip() {
        let (port, seen, handle) = spawn_http_proxy(TEST_IP);
        let ep =
            ProxyTarget::http("127.0.0.1", port).with_credentials(Some("alice"), Some("secret"));
        let a = probe_attempt_with_targets(Some(&ep), None, &[TEST_SITE]);
        handle.join().expect("假代理线程");
        assert_eq!(
            a.ip.as_deref(),
            Some(TEST_IP),
            "HTTP 代理链路必须跑通: {a:?}"
        );
        let req = String::from_utf8_lossy(&seen.lock().expect("读请求记录")).to_string();
        assert!(
            req.starts_with("GET http://api.ipify.org/ HTTP/1.0\r\n"),
            "必须用绝对 URI: {req:?}"
        );
        let cred = BASE64.encode(b"alice:secret");
        assert!(req.contains(&format!("Proxy-Authorization: Basic {cred}\r\n")));
    }

    // ---- 附加：原生失败后走本地 mixed 入站兜底 ----

    #[test]
    fn inbound_mixed_fallback_succeeds_after_native_failure() {
        let (port, handle) = spawn_socks5(Auth::UserPass, Bnd::Domain, TEST_IP);
        let inbound =
            ProxyTarget::socks5(INBOUND_HOST, port).with_credentials(Some("alice"), Some("secret"));
        let a = probe_attempt_with_targets(None, Some(&inbound), &[TEST_SITE]);
        handle.join().expect("假代理线程");
        assert_eq!(a.ip.as_deref(), Some(TEST_IP), "入站兜底必须生效: {a:?}");
    }

    // ---- 纯函数 / 编解码口径 ----

    #[test]
    fn origin_request_matches_python_wire_format() {
        assert_eq!(
            origin_request("api.ipify.org"),
            b"GET / HTTP/1.0\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n".to_vec()
        );
    }

    #[test]
    fn proxy_request_matches_python_wire_format() {
        let plain = proxy_request("api.ipify.org", "", "");
        assert_eq!(
            plain,
            b"GET http://api.ipify.org/ HTTP/1.0\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n"
                .to_vec()
        );
        let authed = String::from_utf8(proxy_request("icanhazip.com", "u", "p")).expect("utf8");
        let cred = BASE64.encode(b"u:p");
        assert!(authed.starts_with("GET http://icanhazip.com/ HTTP/1.0\r\n"));
        assert!(authed.contains(&format!("Proxy-Authorization: Basic {cred}\r\n")));
        assert!(authed.ends_with("\r\n\r\n"));
    }

    #[test]
    fn parse_ip_accepts_v4_and_v6_and_rejects_text() {
        assert_eq!(parse_ip("203.0.113.7").unwrap(), "203.0.113.7");
        assert_eq!(parse_ip("  203.0.113.7\n").unwrap(), "203.0.113.7");
        assert_eq!(parse_ip("2001:db8::1").unwrap(), "2001:db8::1");
        assert!(parse_ip("this is not an ip").is_err());
        assert!(parse_ip("").is_err());
        assert!(
            parse_ip("999.999.999.999").is_err(),
            "越界 IPv4 必须被校验掉"
        );
        assert!(parse_ip("{\"error\":\"rate limited\"}").is_err());
    }

    #[test]
    fn native_target_maps_protocols_like_python() {
        assert_eq!(
            native_target("ss", Some(ProxyTarget::socks5("h", 1))),
            Err(REASON_NATIVE_UNSUPPORTED)
        );
        assert_eq!(native_target("", None), Err(REASON_NATIVE_UNSUPPORTED));
        assert_eq!(
            native_target("socks5", None),
            Err(REASON_NATIVE_ENDPOINT_MISSING)
        );
        assert_eq!(
            native_target("socks5", Some(ProxyTarget::new("", "", 0))),
            Err(REASON_NATIVE_ENDPOINT_MISSING)
        );
        let t = native_target("SOCKS", Some(ProxyTarget::new("http", "1.2.3.4", 1080)))
            .expect("可用端点");
        assert_eq!(t.scheme, "socks", "协议名统一小写");
        assert_eq!(t.host, "1.2.3.4");
        assert_eq!(t.port, 1080);
    }

    #[test]
    fn inbound_target_uses_python_defaults() {
        let t = inbound_target("", 2080, None, None).expect("缺省 mixed 可用");
        assert_eq!(t.host, INBOUND_HOST);
        assert_eq!(t.port, 2080);
        assert_eq!(t.auth(), (DEFAULT_AUTH_USER, DEFAULT_AUTH_PASS));
        let t = inbound_target("mixed", 1, Some("bob"), Some("pw")).expect("边界端口 1 合法");
        assert_eq!(t.auth(), ("bob", "pw"));
        assert_eq!(
            inbound_target("tun", 2080, None, None),
            Err(REASON_INBOUND_DISABLED)
        );
        assert_eq!(
            inbound_target("mixed", 0, None, None),
            Err(REASON_INBOUND_PORT_INVALID)
        );
        assert_eq!(
            inbound_target("mixed", 65536, None, None),
            Err(REASON_INBOUND_PORT_INVALID)
        );
    }

    #[test]
    fn diagnose_reports_structural_dead_ends() {
        assert_eq!(diagnose("socks5", true, "tun", 0), "");
        assert_eq!(diagnose("ss", false, "mixed", 2080), "");
        assert_eq!(diagnose("", false, "", 2080), "");
        let d = diagnose("vmess", false, "tun", 2080);
        assert!(d.contains("协议 vmess 不支持直连探测"), "{d}");
        assert!(d.contains("没有混合入站可兜底"), "{d}");
        assert!(diagnose("", false, "tun", 0).contains("协议 未知 不支持直连探测"));
        let d = diagnose("http", false, "mixed", 0);
        assert!(d.contains("rawConfig 缺少可用的 server/server_port"), "{d}");
        assert!(d.contains("混合入站端口无效（0）"), "{d}");
    }

    #[test]
    fn probe_attempt_chains_both_reasons() {
        let a = ProbeAttempt::fail(REASON_NATIVE_DIAL_FAILED).with_detail("x");
        let b = ProbeAttempt::fail(REASON_INBOUND_DIAL_FAILED).with_detail("y");
        let c = a.chain(&b);
        assert_eq!(c.reason, "native_dial_failed+inbound_dial_failed");
        assert!(c.ip.is_none());
        assert_eq!(c.detail.as_deref(), Some("x；y"));
        assert_eq!(ProbeAttempt::ok("1.1.1.1").ip.as_deref(), Some("1.1.1.1"));
    }

    #[test]
    fn node_probe_defaults_mirror_python_node_dict() {
        let node = NodeProbe::new("ss");
        assert_eq!(node.entry_proto, DEFAULT_ENTRY_PROTO);
        assert_eq!(node.inbound_port, 0);
        assert_eq!(node.endpoint, None);
        let a = node.probe_with_targets(&[TEST_SITE]);
        assert_eq!(
            a.reason,
            format!("{REASON_NATIVE_UNSUPPORTED}+{REASON_INBOUND_PORT_INVALID}")
        );
        assert!(!node.diagnose().is_empty());
    }

    #[test]
    fn read_ip_rejects_response_without_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("绑定");
        let port = listener.local_addr().expect("本地地址").port();
        let handle = thread::spawn(move || {
            let (mut c, _) = listener.accept().expect("接受连接");
            read_until_headers(&mut c);
            c.write_all(b"no headers here at all").expect("写裸响应");
        });
        let mut s = connect("127.0.0.1", port).expect("连接");
        let err = read_ip(&mut s, &origin_request(TEST_SITE)).expect_err("缺头必须失败");
        handle.join().expect("线程");
        assert!(err.contains("HTTP 头结束标记"), "{err}");
    }

    #[tokio::test]
    async fn fetch_exit_ip_async_wrapper_returns_ip() {
        let (port, handle) = spawn_socks5(Auth::UserPass, Bnd::V6, TEST_IP);
        let ep =
            ProxyTarget::socks5("127.0.0.1", port).with_credentials(Some("alice"), Some("secret"));
        let node = NodeProbe::new("socks5").endpoint(Some(ep));
        let ip = fetch_exit_ip(node).await;
        handle.join().expect("假代理线程");
        assert_eq!(ip.as_deref(), Some(TEST_IP));
    }
}
