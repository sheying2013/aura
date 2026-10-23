//! 公网订阅拉取：DNS 结果按每次 HTTP 连接固定（对应 backend/subscription_fetch.py）。
//!
//! 语义要点（与 Python 版逐条对齐）：
//! - 只允许公网 http/https；字面量 IP 必须公网；hostname 解析后**每一个**答案都必须公网，
//!   任何一个不合法整体拒绝（不允许"挑一个公网的用"）。
//! - DNS 只解析一次，后续所有重试/重定向只能使用这份快照，杜绝 DNS rebinding。
//! - 每个 hop 单独选代理（按逻辑 scheme），显式传 proxy 且不继承环境代理（NO_PROXY 无法旁路）。
//! - 连接失败可在本次快照的其余地址间回退；证书错误、状态码错误、读体错误一律不回退。
//! - 总超时包住 DNS/重定向/读体；对外文案固定，绝不回显 URL 或传输异常原文（可能含 token）。
//!
//! 与 Python 的实现差异（Cargo.toml 未启用 gzip/charset feature）：
//! - 请求固定发送 Accept-Encoding: identity；若服务端仍返回压缩体，体积上限按收到的字节计。
//! - 字符集只支持 utf-8 与 latin-1 族，其余按 utf-8 错误替换。
//! - 连接目标通过 reqwest 的 resolve 钉死到快照 IP，逻辑 URL 不被改写成数字地址，
//!   因此 Host/SNI/证书校验名天然保持原样（Python 靠 sni_hostname 扩展达成同一效果）。
use crate::types::SubFetchResponse;
use reqwest::Url;
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::time::{Duration, Instant};

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";
pub const MAX_BYTES: usize = 10 * 1024 * 1024;
/// 默认总超时（Python 的 _TIMEOUT：既做总 deadline，也做单请求 I/O 超时）。
pub const TIMEOUT: Duration = Duration::from_secs(15);
/// 单地址连接预算上限（Python 的 min(3.0, remaining / 剩余地址数)）。
pub const CONNECT_BUDGET_MAX: f64 = 3.0;
pub const MAX_REDIRECTS: usize = 5;
pub const REDIRECT_STATUSES: [u16; 5] = [301, 302, 303, 307, 308];

pub const ERR_UNSAFE_URL: &str = "仅允许公网 http/https 订阅 URL";
pub const ERR_TIMEOUT: &str = "订阅请求超时";
pub const ERR_TRANSPORT: &str = "订阅请求失败";
pub const ERR_REDIRECT_NO_LOCATION: &str = "重定向缺少目标 URL";
pub const ERR_TOO_MANY_REDIRECTS: &str = "订阅重定向超过 5 次";
pub const ERR_TOO_LARGE: &str = "订阅内容超过 10 MiB";

// ---------- 结果与错误 ----------

/// fetch 的返回（对齐 Python 的 ok/status/content/error 字典）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchResult {
    Ok { status: u16, content: String },
    Err { status: Option<u16>, error: String },
}

impl FetchResult {
    pub fn err_with_status(status: u16, error: impl Into<String>) -> Self {
        FetchResult::Err {
            status: Some(status),
            error: error.into(),
        }
    }
    pub fn err(error: impl Into<String>) -> Self {
        FetchResult::Err {
            status: None,
            error: error.into(),
        }
    }
    pub fn is_ok(&self) -> bool {
        matches!(self, FetchResult::Ok { .. })
    }
    pub fn status(&self) -> Option<u16> {
        match self {
            FetchResult::Ok { status, .. } => Some(*status),
            FetchResult::Err { status, .. } => *status,
        }
    }
    pub fn content(&self) -> Option<&str> {
        match self {
            FetchResult::Ok { content, .. } => Some(content),
            _ => None,
        }
    }
    pub fn error(&self) -> Option<&str> {
        match self {
            FetchResult::Err { error, .. } => Some(error),
            _ => None,
        }
    }
    /// 转成 types::SubFetchResponse（HTTP/JSON 层直接复用）。
    pub fn to_response(&self) -> SubFetchResponse {
        match self {
            FetchResult::Ok { status, content } => SubFetchResponse {
                ok: true,
                status: Some(*status as i64),
                content: Some(content.clone()),
                error: None,
            },
            FetchResult::Err { status, error } => SubFetchResponse {
                ok: false,
                status: status.map(|s| s as i64),
                content: None,
                error: Some(error.clone()),
            },
        }
    }
}

/// 单次连接尝试的错误。context 只在进程内流转，对外一律被收敛成固定文案。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// 连接阶段失败（可回退到本快照的下一个地址）。
    Connect { message: String, certificate: bool },
    /// 连接超时（可回退）。
    ConnectTimeout { message: String },
    /// 响应体读取失败（绝不回退）。
    Read { message: String },
    /// 其他传输错误（绝不回退）。
    Other { message: String },
}

impl FetchError {
    pub fn connect(message: impl Into<String>) -> Self {
        FetchError::Connect {
            message: message.into(),
            certificate: false,
        }
    }
    pub fn certificate(message: impl Into<String>) -> Self {
        FetchError::Connect {
            message: message.into(),
            certificate: true,
        }
    }
    pub fn connect_timeout(message: impl Into<String>) -> Self {
        FetchError::ConnectTimeout {
            message: message.into(),
        }
    }
    pub fn read(message: impl Into<String>) -> Self {
        FetchError::Read {
            message: message.into(),
        }
    }
    pub fn other(message: impl Into<String>) -> Self {
        FetchError::Other {
            message: message.into(),
        }
    }
    pub fn message(&self) -> &str {
        match self {
            FetchError::Connect { message, .. }
            | FetchError::ConnectTimeout { message }
            | FetchError::Read { message }
            | FetchError::Other { message } => message,
        }
    }
    /// 是否属于"可以换下一个地址再试"的错误（证书错误不在内）。
    pub fn retryable_on_next_address(&self) -> bool {
        match self {
            FetchError::Connect { certificate, .. } => !*certificate,
            FetchError::ConnectTimeout { .. } => true,
            FetchError::Read { .. } | FetchError::Other { .. } => false,
        }
    }
}

/// 内部失败分类：只在 fetch_public_subscription 里映射成对外文案。
#[derive(Debug, Clone, PartialEq, Eq)]
enum Failure {
    UnsafeUrl,
    Timeout,
    Transport(FetchError),
}

// ---------- 抽象：DNS / 连接 / 响应体 ----------

pub trait DnsResolver: Send + Sync {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> BoxFut<'a, std::io::Result<Vec<IpAddr>>>;
}

/// 生产实现：走 spawn_blocking，DNS 绝不阻塞异步运行时线程。
pub struct SystemResolver;

impl DnsResolver for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> BoxFut<'a, std::io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            let target = format!("{host}:{port}");
            tokio::task::spawn_blocking(move || -> std::io::Result<Vec<IpAddr>> {
                Ok(target.to_socket_addrs()?.map(|sa| sa.ip()).collect())
            })
            .await
            .map_err(std::io::Error::other)?
        })
    }
}

/// 一次连接尝试的入参：逻辑 URL 保持原样（Host/SNI 由它决定），连接目标由 address 钉死。
#[derive(Debug, Clone)]
pub struct AttemptRequest {
    pub url: Url,
    pub address: IpAddr,
    pub host_header: String,
    pub sni_hostname: String,
    pub connect_timeout: Duration,
    pub proxy: Option<String>,
    pub user_agent: String,
}

pub trait BodyStream: Send {
    fn next_chunk<'a>(&'a mut self) -> BoxFut<'a, Result<Option<Vec<u8>>, FetchError>>;
    fn close<'a>(&'a mut self) -> BoxFut<'a, ()>;
}

pub struct AttemptResponse {
    pub status: u16,
    pub location: Option<String>,
    pub content_length: Option<String>,
    pub content_type: Option<String>,
    pub body: Box<dyn BodyStream>,
}

pub trait Transport: Send + Sync {
    fn send<'a>(
        &'a self,
        request: AttemptRequest,
    ) -> BoxFut<'a, Result<AttemptResponse, FetchError>>;
}

// ---------- 纯函数（便于单测） ----------

/// 由逻辑 URL 生成 Host 头：域名带非默认端口；IPv6 带方括号。
pub fn host_header_of(url: &Url) -> String {
    let host = url.host_str().unwrap_or("");
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

/// TLS SNI / 证书校验名：域名走 punycode，IPv6 去方括号（对齐 httpx raw_host）。
pub fn sni_hostname_of(url: &Url) -> String {
    let host = url.host_str().unwrap_or("");
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .to_string()
}

/// Python ipaddress.IPv4Address.is_global 语义（std 的 is_global 尚未稳定）。
pub fn ipv4_is_global(a: Ipv4Addr) -> bool {
    let octets = a.octets();
    let (a0, a1, a2, a3) = (octets[0], octets[1], octets[2], octets[3]);
    if a0 == 0 || a0 == 10 || a0 == 127 {
        return false;
    }
    if a0 == 100 && (64..=127).contains(&a1) {
        return false; // 100.64.0.0/10 CGNAT
    }
    if a0 == 169 && a1 == 254 {
        return false; // 链路本地 / 云元数据
    }
    if a0 == 172 && (16..=31).contains(&a1) {
        return false;
    }
    if a0 == 192 && a1 == 168 {
        return false;
    }
    if a0 == 192 && a1 == 0 && a2 == 0 {
        // 192.0.0.0/24 保留，但 .9/.10 是公网任播。
        return a3 == 9 || a3 == 10;
    }
    if a0 == 192 && a1 == 0 && a2 == 2 {
        return false; // TEST-NET-1
    }
    if a0 == 192 && a1 == 88 && a2 == 99 {
        return false; // 6to4 中继
    }
    if a0 == 198 && (a1 == 18 || a1 == 19) {
        return false; // benchmarking
    }
    if a0 == 198 && a1 == 51 && a2 == 100 {
        return false; // TEST-NET-2
    }
    if a0 == 203 && a1 == 0 && a2 == 113 {
        return false; // TEST-NET-3
    }
    if a0 >= 224 {
        return false; // 组播 / 保留 / 广播
    }
    true
}

pub fn ipv6_is_global(a: Ipv6Addr) -> bool {
    if a.is_unspecified() || a.is_loopback() || a.is_multicast() {
        return false;
    }
    let seg = a.segments();
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0 && seg[3] == 0 {
        return false; // 64:ff9b::/96
    }
    if seg[0] == 0x0100 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 {
        return false; // 100::/64
    }
    if seg[0] == 0x2001 && seg[1] <= 0x01ff {
        return false; // 2001::/23
    }
    if seg[0] == 0x2001 && seg[1] == 0x0db8 {
        return false; // 文档段
    }
    if seg[0] & 0xfe00 == 0xfc00 {
        return false; // fc00::/7 ULA
    }
    if seg[0] & 0xffc0 == 0xfe80 {
        return false; // fe80::/10 链路本地
    }
    true
}

/// 地址是否可用于对外拉取（IPv4-mapped 按内嵌 IPv4 判定）。
pub fn ip_is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => ipv4_is_global(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => ipv4_is_global(v4),
            None => ipv6_is_global(v6),
        },
    }
}

/// Python str.isdecimal 语义（只认十进制数字串）。
pub fn is_decimal(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

/// 按 Content-Type 的 charset 解码；未知/缺失回落 UTF-8（错误替换）。
pub fn decode_body(bytes: &[u8], content_type: Option<&str>) -> String {
    match charset_of(content_type) {
        Some(cs) if is_latin1(&cs) => bytes.iter().map(|b| *b as char).collect(),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

fn charset_of(content_type: Option<&str>) -> Option<String> {
    let ct = content_type?;
    for part in ct.split(';') {
        let part = part.trim();
        if part.len() >= 8 && part[..8].eq_ignore_ascii_case("charset=") {
            return Some(
                part[8..]
                    .trim()
                    .trim_matches('"')
                    .trim()
                    .to_ascii_lowercase(),
            );
        }
    }
    None
}

fn is_latin1(cs: &str) -> bool {
    matches!(
        cs,
        "iso-8859-1" | "iso8859-1" | "latin1" | "latin-1" | "l1" | "windows-1252" | "cp1252"
    )
}

/// 按逻辑 scheme 选部署出口代理；找不到就直连（不做环境自动代理）。
pub fn deployment_proxy(env: &HashMap<String, String>, scheme: &str) -> Option<String> {
    let upper = format!("{}_PROXY", scheme.to_ascii_uppercase());
    let lower = format!("{}_proxy", scheme.to_ascii_lowercase());
    for key in [upper.as_str(), lower.as_str(), "ALL_PROXY", "all_proxy"] {
        if let Some(value) = env.get(key) {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// 证书错误判定：扫一遍 cause 链的文案（rustls/webpki 的错误都在链上）。
pub fn looks_like_certificate_error(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(err);
    let mut depth = 0;
    while let Some(e) = current {
        let msg = e.to_string().to_ascii_lowercase();
        if msg.contains("certificate")
            || msg.contains("unknownissuer")
            || msg.contains("unknown issuer")
            || msg.contains("invalidcertificate")
            || msg.contains("notvalidforname")
        {
            return true;
        }
        current = e.source();
        depth += 1;
        if depth > 16 {
            break;
        }
    }
    false
}

/// 重定向目标一律重新做公网校验 + 重新解析 DNS（不允许沿用上一跳的地址）。
fn join_location(base: &Url, location: &str) -> Result<Url, ()> {
    base.join(location).map_err(|_| ())
}

// ---------- Fetcher ----------

/// 订阅拉取器：注入 transport / resolver / env，便于离线单测。
pub struct Fetcher {
    pub timeout: Duration,
    pub max_bytes: usize,
    pub env: HashMap<String, String>,
    transport: std::sync::Arc<dyn Transport>,
    resolver: std::sync::Arc<dyn DnsResolver>,
}

impl Fetcher {
    pub fn new(
        transport: std::sync::Arc<dyn Transport>,
        resolver: std::sync::Arc<dyn DnsResolver>,
    ) -> Self {
        Self {
            timeout: TIMEOUT,
            max_bytes: MAX_BYTES,
            env: HashMap::new(),
            transport,
            resolver,
        }
    }

    /// 生产默认：真实 reqwest 传输 + 系统 DNS + 进程环境变量。
    pub fn from_env() -> Self {
        let env: HashMap<String, String> = std::env::vars().collect();
        Self {
            timeout: TIMEOUT,
            max_bytes: MAX_BYTES,
            env,
            transport: std::sync::Arc::new(ReqwestTransport),
            resolver: std::sync::Arc::new(SystemResolver),
        }
    }

    pub fn with_env(mut self, env: HashMap<String, String>) -> Self {
        self.env = env;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// 对外入口：任何失败都收敛成固定文案，绝不回显 URL/异常原文。
    pub async fn fetch_public_subscription(&self, url: &str) -> FetchResult {
        match tokio::time::timeout(self.timeout, self.fetch_inner(url)).await {
            Err(_) => FetchResult::err(ERR_TIMEOUT),
            Ok(Ok(result)) => result,
            Ok(Err(Failure::UnsafeUrl)) => FetchResult::err(ERR_UNSAFE_URL),
            Ok(Err(Failure::Timeout)) => FetchResult::err(ERR_TIMEOUT),
            Ok(Err(Failure::Transport(_))) => FetchResult::err(ERR_TRANSPORT),
        }
    }

    async fn fetch_inner(&self, url: &str) -> Result<FetchResult, Failure> {
        let mut logical_value = url.to_string();
        let deadline = Instant::now() + self.timeout;
        for hop in 0..=MAX_REDIRECTS {
            let (logical, addresses) = self.resolve_public_url(&logical_value).await?;
            let host_header = host_header_of(&logical);
            let sni_hostname = sni_hostname_of(&logical);
            let proxy = deployment_proxy(&self.env, logical.scheme());
            let count = addresses.len();
            let mut redirected = false;
            for (index, address) in addresses.iter().enumerate() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(Failure::Timeout);
                }
                // 给后续地址留预算：min(3s, 剩余 / 尚未尝试的地址数)。
                let share = remaining.as_secs_f64() / (count - index) as f64;
                let connect_timeout = Duration::from_secs_f64(CONNECT_BUDGET_MAX.min(share));
                let request = AttemptRequest {
                    url: logical.clone(),
                    address: *address,
                    host_header: host_header.clone(),
                    sni_hostname: sni_hostname.clone(),
                    connect_timeout,
                    proxy: proxy.clone(),
                    user_agent: USER_AGENT.to_string(),
                };
                let mut response = match self.transport.send(request).await {
                    Ok(response) => response,
                    Err(error) => {
                        let last = index + 1 == count;
                        if error.retryable_on_next_address() && !last {
                            continue;
                        }
                        return Err(Failure::Transport(error));
                    }
                };
                let status = response.status;
                let location = response.location.clone();
                let content_length = response.content_length.clone();
                let content_type = response.content_type.clone();
                if REDIRECT_STATUSES.contains(&status) {
                    response.body.close().await;
                    let Some(location) = location else {
                        return Ok(FetchResult::err_with_status(
                            status,
                            ERR_REDIRECT_NO_LOCATION,
                        ));
                    };
                    if hop == MAX_REDIRECTS {
                        return Ok(FetchResult::err_with_status(status, ERR_TOO_MANY_REDIRECTS));
                    }
                    logical_value = join_location(&logical, &location)
                        .map_err(|_| Failure::UnsafeUrl)?
                        .to_string();
                    redirected = true;
                    break;
                }
                if status >= 300 {
                    response.body.close().await;
                    return Ok(FetchResult::err_with_status(
                        status,
                        format!("HTTP {status}"),
                    ));
                }
                if let Some(length) = content_length {
                    if is_decimal(&length)
                        && length.parse::<u64>().unwrap_or(0) > self.max_bytes as u64
                    {
                        response.body.close().await;
                        return Ok(FetchResult::err_with_status(status, ERR_TOO_LARGE));
                    }
                }
                let mut content: Vec<u8> = Vec::new();
                loop {
                    match response.body.next_chunk().await {
                        Ok(Some(chunk)) => {
                            if content.len() + chunk.len() > self.max_bytes {
                                response.body.close().await;
                                return Ok(FetchResult::err_with_status(status, ERR_TOO_LARGE));
                            }
                            content.extend_from_slice(&chunk);
                        }
                        Ok(None) => break,
                        Err(error) => {
                            response.body.close().await;
                            return Err(Failure::Transport(error));
                        }
                    }
                }
                response.body.close().await;
                return Ok(FetchResult::Ok {
                    status,
                    content: decode_body(&content, content_type.as_deref()),
                });
            }
            if !redirected {
                return Err(Failure::Transport(FetchError::other(
                    "no address available",
                )));
            }
        }
        Err(Failure::Transport(FetchError::other(
            "unreachable redirect loop",
        )))
    }

    /// 校验并钉死目标：返回 (去掉 fragment 的逻辑 URL, 公网地址快照)。
    async fn resolve_public_url(&self, value: &str) -> Result<(Url, Vec<IpAddr>), Failure> {
        // WHATWG 解析会把 "https:///host" 的多余斜杠吞掉、把 host 当成路径首段；
        // Python(httpx/rfc3986) 在这种写法下 host 为空 → 拒绝。这里显式对齐 Python。
        if let Some((_, rest)) = value.split_once("://") {
            if rest.starts_with('/') || rest.starts_with('\\') {
                return Err(Failure::UnsafeUrl);
            }
        }
        let mut logical = Url::parse(value).map_err(|_| Failure::UnsafeUrl)?;
        if !matches!(logical.scheme(), "http" | "https") {
            return Err(Failure::UnsafeUrl);
        }
        let host_str = logical.host_str().unwrap_or("").to_string();
        if host_str.is_empty() {
            return Err(Failure::UnsafeUrl);
        }
        // 带 zone id 的作用域 IPv6 会让连接绑定本机网卡，直接拒绝。
        if host_str.contains('%') {
            return Err(Failure::UnsafeUrl);
        }
        if !logical.username().is_empty() || logical.password().is_some() {
            return Err(Failure::UnsafeUrl);
        }
        // 不复用 url::Host：crate 只直接依赖 reqwest，字面量判定走 host_str 解析。
        let addresses: Vec<IpAddr> = if let Ok(v4) = host_str.parse::<Ipv4Addr>() {
            vec![IpAddr::V4(v4)]
        } else if let Some(inner) = host_str
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            match inner.parse::<Ipv6Addr>() {
                Ok(v6) => vec![IpAddr::V6(v6)],
                Err(_) => return Err(Failure::UnsafeUrl),
            }
        } else {
            {
                let port = logical.port_or_known_default().ok_or(Failure::UnsafeUrl)?;
                let domain = host_str.as_str();
                let answers = self
                    .resolver
                    .resolve(domain, port)
                    .await
                    .map_err(|_| Failure::UnsafeUrl)?;
                if answers.is_empty() {
                    return Err(Failure::UnsafeUrl);
                }
                // 先全部校验再规范化去重：坏答案不能被"去重"掩盖。
                let mut deduped: Vec<IpAddr> = Vec::new();
                for answer in answers {
                    if !ip_is_public(answer) {
                        return Err(Failure::UnsafeUrl);
                    }
                    if !deduped.contains(&answer) {
                        deduped.push(answer);
                    }
                }
                deduped
            }
        };
        if addresses.is_empty() || addresses.iter().any(|ip| !ip_is_public(*ip)) {
            return Err(Failure::UnsafeUrl);
        }
        logical.set_fragment(None);
        Ok((logical, addresses))
    }
}

/// 订阅拉取抽象：subs_proxy 的刷新流程只依赖这个 trait。
pub trait SubscriptionFetcher: Send + Sync {
    fn fetch<'a>(&'a self, url: &'a str) -> BoxFut<'a, FetchResult>;
}

impl SubscriptionFetcher for Fetcher {
    fn fetch<'a>(&'a self, url: &'a str) -> BoxFut<'a, FetchResult> {
        Box::pin(async move { self.fetch_public_subscription(url).await })
    }
}

// ---------- 真实传输层（reqwest 0.11 + rustls） ----------

pub struct ReqwestTransport;

struct ReqwestBody {
    response: reqwest::Response,
}

impl BodyStream for ReqwestBody {
    fn next_chunk<'a>(&'a mut self) -> BoxFut<'a, Result<Option<Vec<u8>>, FetchError>> {
        Box::pin(async move {
            match self.response.chunk().await {
                Ok(Some(chunk)) => Ok(Some(chunk.to_vec())),
                Ok(None) => Ok(None),
                Err(error) => Err(FetchError::read(format!("body read failed: {error}"))),
            }
        })
    }

    fn close<'a>(&'a mut self) -> BoxFut<'a, ()> {
        Box::pin(async move {})
    }
}

pub fn map_reqwest_error(error: reqwest::Error) -> FetchError {
    let message = error.to_string();
    if error.is_connect() {
        let certificate = looks_like_certificate_error(&error);
        return FetchError::Connect {
            message,
            certificate,
        };
    }
    if error.is_timeout() {
        return FetchError::connect_timeout(message);
    }
    if error.is_body() || error.is_decode() {
        return FetchError::read(message);
    }
    FetchError::other(message)
}

impl Transport for ReqwestTransport {
    fn send<'a>(
        &'a self,
        request: AttemptRequest,
    ) -> BoxFut<'a, Result<AttemptResponse, FetchError>> {
        Box::pin(async move {
            let port = request
                .url
                .port_or_known_default()
                .ok_or_else(|| FetchError::other("missing port"))?;
            let logical_host = request.url.host_str().unwrap_or("").to_string();
            let mut builder = reqwest::Client::builder()
                // 显式代理 + 关闭环境代理自动探测：NO_PROXY 不能旁路部署出口。
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(request.connect_timeout)
                .pool_max_idle_per_host(0)
                .user_agent(request.user_agent.clone());
            if let Some(proxy) = &request.proxy {
                let proxy = reqwest::Proxy::all(proxy.clone())
                    .map_err(|e| FetchError::other(format!("invalid proxy: {e}")))?;
                builder = builder.proxy(proxy);
            }
            // 关键：连接目标钉死到快照地址，逻辑域名/SNI/证书名保持原样。
            if logical_host.parse::<IpAddr>().is_err() {
                builder = builder.resolve(&logical_host, SocketAddr::new(request.address, port));
            }
            let client = builder
                .build()
                .map_err(|e| FetchError::other(format!("client build failed: {e}")))?;
            let response = client
                .get(request.url.clone())
                .header(reqwest::header::HOST, request.host_header.clone())
                .header(reqwest::header::ACCEPT_ENCODING, "identity")
                .send()
                .await
                .map_err(map_reqwest_error)?;
            let (status, location, content_length, content_type) = {
                let headers = response.headers();
                let header = |name: reqwest::header::HeaderName| {
                    headers
                        .get(name)
                        .and_then(|v| v.to_str().ok())
                        .map(|v| v.to_string())
                };
                (
                    response.status().as_u16(),
                    header(reqwest::header::LOCATION),
                    header(reqwest::header::CONTENT_LENGTH),
                    header(reqwest::header::CONTENT_TYPE),
                )
            };
            Ok(AttemptResponse {
                status,
                location,
                content_length,
                content_type,
                body: Box::new(ReqwestBody { response }),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    //! 契约对齐 tests/test_subscription_fetch.py：全部离线，DNS 与连接都可控。
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    // ---------- 记录型传输层 ----------

    #[derive(Debug, Clone)]
    struct Recorded {
        url: String,
        address: IpAddr,
        host_header: String,
        sni: String,
        connect_timeout: Duration,
        proxy: Option<String>,
    }

    type Handler = Arc<
        dyn Fn(AttemptRequest, usize) -> BoxFut<'static, Result<AttemptResponse, FetchError>>
            + Send
            + Sync,
    >;

    struct MockTransport {
        handler: Handler,
        requests: Mutex<Vec<Recorded>>,
    }

    impl MockTransport {
        fn new(handler: Handler) -> Arc<Self> {
            Arc::new(Self {
                handler,
                requests: Mutex::new(Vec::new()),
            })
        }

        fn recorded(&self) -> Vec<Recorded> {
            self.requests.lock().unwrap().clone()
        }

        fn count(&self) -> usize {
            self.requests.lock().unwrap().len()
        }
    }

    impl Transport for MockTransport {
        fn send<'a>(
            &'a self,
            request: AttemptRequest,
        ) -> BoxFut<'a, Result<AttemptResponse, FetchError>> {
            let index = {
                let mut guard = self.requests.lock().unwrap();
                guard.push(Recorded {
                    url: request.url.to_string(),
                    address: request.address,
                    host_header: request.host_header.clone(),
                    sni: request.sni_hostname.clone(),
                    connect_timeout: request.connect_timeout,
                    proxy: request.proxy.clone(),
                });
                guard.len()
            };
            let handler = self.handler.clone();
            Box::pin(async move { handler(request, index).await })
        }
    }

    // ---------- 响应体探针 ----------

    #[derive(Clone)]
    struct BodyProbe {
        reads: Arc<AtomicUsize>,
        closed: Arc<AtomicBool>,
    }

    impl BodyProbe {
        fn new() -> Self {
            Self {
                reads: Arc::new(AtomicUsize::new(0)),
                closed: Arc::new(AtomicBool::new(false)),
            }
        }
        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
        fn closed(&self) -> bool {
            self.closed.load(Ordering::SeqCst)
        }
    }

    struct VecBody {
        chunks: VecDeque<Vec<u8>>,
        error: Option<FetchError>,
        probe: BodyProbe,
    }

    impl BodyStream for VecBody {
        fn next_chunk<'a>(&'a mut self) -> BoxFut<'a, Result<Option<Vec<u8>>, FetchError>> {
            Box::pin(async move {
                self.probe.reads.fetch_add(1, Ordering::SeqCst);
                if let Some(chunk) = self.chunks.pop_front() {
                    return Ok(Some(chunk));
                }
                if let Some(error) = self.error.take() {
                    return Err(error);
                }
                Ok(None)
            })
        }

        fn close<'a>(&'a mut self) -> BoxFut<'a, ()> {
            Box::pin(async move {
                self.probe.closed.store(true, Ordering::SeqCst);
            })
        }
    }

    struct Resp {
        status: u16,
        location: Option<String>,
        content_length: Option<String>,
        content_type: Option<String>,
        chunks: Vec<Vec<u8>>,
        error: Option<FetchError>,
        probe: BodyProbe,
    }

    impl Resp {
        fn new(status: u16) -> Self {
            Self {
                status,
                location: None,
                content_length: None,
                content_type: None,
                chunks: Vec::new(),
                error: None,
                probe: BodyProbe::new(),
            }
        }
        fn text(mut self, value: &str) -> Self {
            self.chunks = vec![value.as_bytes().to_vec()];
            self
        }
        fn location(mut self, value: &str) -> Self {
            self.location = Some(value.to_string());
            self
        }
        fn content_length(mut self, value: usize) -> Self {
            self.content_length = Some(value.to_string());
            self
        }
        fn content_type(mut self, value: &str) -> Self {
            self.content_type = Some(value.to_string());
            self
        }
        fn chunks(mut self, values: Vec<&[u8]>) -> Self {
            self.chunks = values.into_iter().map(|value| value.to_vec()).collect();
            self
        }
        fn body_error(mut self, error: FetchError) -> Self {
            self.error = Some(error);
            self
        }
        fn build(self) -> (AttemptResponse, BodyProbe) {
            let probe = self.probe.clone();
            let response = AttemptResponse {
                status: self.status,
                location: self.location,
                content_length: self.content_length,
                content_type: self.content_type,
                body: Box::new(VecBody {
                    chunks: VecDeque::from(self.chunks),
                    error: self.error,
                    probe: self.probe,
                }),
            };
            (response, probe)
        }
    }

    fn scripted(responses: Vec<AttemptResponse>) -> Arc<MockTransport> {
        let queue = Arc::new(Mutex::new(VecDeque::from(responses)));
        MockTransport::new(Arc::new(move |_request: AttemptRequest, _index: usize| {
            let queue = queue.clone();
            Box::pin(async move {
                let next = {
                    let mut guard = queue.lock().unwrap();
                    guard.pop_front()
                };
                match next {
                    Some(response) => Ok(response),
                    None => Err(FetchError::other("no scripted response left")),
                }
            })
        }))
    }

    // ---------- 解析器 mock ----------

    type AnswerFn = Box<dyn Fn(&str, usize) -> std::io::Result<Vec<IpAddr>> + Send + Sync>;

    struct MockResolver {
        calls: Mutex<Vec<(String, u16)>>,
        answers: AnswerFn,
    }

    impl MockResolver {
        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
        fn hosts(&self) -> Vec<String> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .map(|(host, _)| host.clone())
                .collect()
        }
    }

    impl DnsResolver for MockResolver {
        fn resolve<'a>(
            &'a self,
            host: &'a str,
            port: u16,
        ) -> BoxFut<'a, std::io::Result<Vec<IpAddr>>> {
            Box::pin(async move {
                let index = {
                    let mut guard = self.calls.lock().unwrap();
                    guard.push((host.to_string(), port));
                    guard.len()
                };
                (self.answers)(host, index)
            })
        }
    }

    fn ips(values: &[&str]) -> Vec<IpAddr> {
        values
            .iter()
            .map(|value| value.parse::<IpAddr>().unwrap())
            .collect()
    }

    fn fixed(values: &[&str]) -> Arc<MockResolver> {
        let answers = ips(values);
        Arc::new(MockResolver {
            calls: Mutex::new(Vec::new()),
            answers: Box::new(move |_host, _index| Ok(answers.clone())),
        })
    }

    fn mapping(entries: Vec<(&'static str, Vec<IpAddr>)>) -> Arc<MockResolver> {
        Arc::new(MockResolver {
            calls: Mutex::new(Vec::new()),
            answers: Box::new(move |host, _index| {
                entries
                    .iter()
                    .find(|(name, _)| *name == host)
                    .map(|(_, answers)| Ok(answers.clone()))
                    .unwrap_or_else(|| {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "no answer",
                        ))
                    })
            }),
        })
    }

    fn sequence(steps: Vec<Vec<IpAddr>>) -> Arc<MockResolver> {
        Arc::new(MockResolver {
            calls: Mutex::new(Vec::new()),
            answers: Box::new(move |_host, index| {
                steps
                    .get(index.saturating_sub(1))
                    .cloned()
                    .map(Ok)
                    .unwrap_or_else(|| {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "no answer",
                        ))
                    })
            }),
        })
    }

    fn failing(message: &'static str) -> Arc<MockResolver> {
        Arc::new(MockResolver {
            calls: Mutex::new(Vec::new()),
            answers: Box::new(move |_host, _index| {
                Err(std::io::Error::new(std::io::ErrorKind::NotFound, message))
            }),
        })
    }

    fn fetcher(transport: Arc<MockTransport>, resolver: Arc<MockResolver>) -> Fetcher {
        Fetcher::new(transport, resolver)
    }

    fn env_of(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // ---------- 纯函数 ----------

    #[test]
    fn host_header_keeps_non_default_port_only() {
        let default = Url::parse("https://sub.example/sub").unwrap();
        assert_eq!(host_header_of(&default), "sub.example");
        let explicit = Url::parse("https://sub.example:8443/sub").unwrap();
        assert_eq!(host_header_of(&explicit), "sub.example:8443");
        let v6 = Url::parse("https://[2606:4700:4700::1111]:8443/sub").unwrap();
        assert_eq!(host_header_of(&v6), "[2606:4700:4700::1111]:8443");
        assert_eq!(sni_hostname_of(&v6), "2606:4700:4700::1111");
        assert_eq!(sni_hostname_of(&explicit), "sub.example");
    }

    #[test]
    fn public_address_table_matches_python() {
        for value in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "198.18.0.1",
            "192.0.2.10",
            "203.0.113.7",
        ] {
            assert!(
                !ip_is_public(value.parse().unwrap()),
                "{value} should not be public"
            );
        }
        for value in ["8.8.8.8", "1.1.1.1", "141.101.64.1", "192.0.0.9"] {
            assert!(
                ip_is_public(value.parse().unwrap()),
                "{value} should be public"
            );
        }
        for value in [
            "::1",
            "::",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "ff02::1",
            "2001:db8::1",
        ] {
            assert!(
                !ip_is_public(value.parse().unwrap()),
                "{value} should not be public"
            );
        }
        for value in ["2606:4700:4700::1111", "::ffff:8.8.8.8"] {
            assert!(
                ip_is_public(value.parse().unwrap()),
                "{value} should be public"
            );
        }
    }

    #[test]
    fn decimal_detection_matches_python() {
        assert!(is_decimal("98"));
        assert!(is_decimal("0"));
        assert!(!is_decimal(""));
        assert!(!is_decimal("+98"));
        assert!(!is_decimal("-1"));
        assert!(!is_decimal("9.8"));
        assert!(!is_decimal(" 98"));
        assert!(!is_decimal("98abc"));
    }

    #[test]
    fn deployment_proxy_prefers_scheme_variables_in_order() {
        let env = env_of(&[
            ("HTTPS_PROXY", "http://scheme-upper:8000"),
            ("https_proxy", "http://scheme-lower:8000"),
            ("ALL_PROXY", "socks5://all-upper:1080"),
            ("all_proxy", "socks5://all-lower:1080"),
        ]);
        assert_eq!(
            deployment_proxy(&env, "https").as_deref(),
            Some("http://scheme-upper:8000")
        );
        assert_eq!(
            deployment_proxy(&env, "http").as_deref(),
            Some("socks5://all-upper:1080")
        );
        let blank = env_of(&[("HTTP_PROXY", "   "), ("all_proxy", " socks5://only:1080 ")]);
        assert_eq!(
            deployment_proxy(&blank, "http").as_deref(),
            Some("socks5://only:1080")
        );
        assert_eq!(deployment_proxy(&HashMap::new(), "http"), None);
    }

    #[test]
    fn body_decoding_respects_charset() {
        assert_eq!(
            decode_body(b"\xe9x", Some("text/plain; charset=iso-8859-1")),
            "éx"
        );
        assert_eq!(decode_body("héllo".as_bytes(), None), "héllo");
        assert_eq!(
            decode_body("héllo".as_bytes(), Some("text/plain; charset=utf-8")),
            "héllo"
        );
        assert!(decode_body(&[0xff], Some("text/plain; charset=utf-8")).contains('\u{fffd}'));
    }

    #[derive(Debug)]
    struct InnerError;
    impl std::fmt::Display for InnerError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "invalid peer certificate: UnknownIssuer")
        }
    }
    impl std::error::Error for InnerError {}

    #[derive(Debug)]
    struct OuterError(InnerError);
    impl std::fmt::Display for OuterError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "error sending request for url")
        }
    }
    impl std::error::Error for OuterError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    #[derive(Debug)]
    struct PlainError;
    impl std::fmt::Display for PlainError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "connection refused")
        }
    }
    impl std::error::Error for PlainError {}

    #[test]
    fn certificate_errors_are_detected_through_the_cause_chain() {
        assert!(looks_like_certificate_error(&OuterError(InnerError)));
        assert!(!looks_like_certificate_error(&PlainError));
    }

    // ---------- 拉取契约 ----------

    #[tokio::test]
    async fn hostname_is_pinned_while_host_and_sni_are_preserved() {
        let (response, _) = Resp::new(200).text("subscription").build();
        let transport = scripted(vec![response]);
        let resolver = fixed(&["8.8.8.8"]);
        let result = fetcher(transport.clone(), resolver.clone())
            .fetch_public_subscription("https://sub.example:8443/sub?token=secret")
            .await;
        assert_eq!(
            result,
            FetchResult::Ok {
                status: 200,
                content: "subscription".into()
            }
        );
        let requests = transport.recorded();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://sub.example:8443/sub?token=secret");
        assert_eq!(requests[0].address, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(requests[0].host_header, "sub.example:8443");
        assert_eq!(requests[0].sni, "sub.example");
        assert_eq!(resolver.call_count(), 1);
        assert_eq!(resolver.calls.lock().unwrap()[0].1, 8443);
    }

    #[tokio::test]
    async fn proxy_is_selected_from_the_logical_scheme() {
        type ProxyCase = (
            Vec<(&'static str, &'static str)>,
            &'static str,
            Option<&'static str>,
        );
        let cases: Vec<ProxyCase> = vec![
            (
                vec![("HTTPS_PROXY", "http://upper:8000")],
                "https://sub.example/s",
                Some("http://upper:8000"),
            ),
            (
                vec![("https_proxy", "http://lower:8000")],
                "https://sub.example/s",
                Some("http://lower:8000"),
            ),
            (
                vec![("ALL_PROXY", "socks5://all:1080")],
                "http://sub.example/s",
                Some("socks5://all:1080"),
            ),
            (
                vec![("all_proxy", "socks5://all-lower:1080")],
                "https://sub.example/s",
                Some("socks5://all-lower:1080"),
            ),
            (
                vec![("HTTP_PROXY", "http://http-only:8000")],
                "https://sub.example/s",
                None,
            ),
            (
                vec![("HTTPS_PROXY", "http://https-only:8000")],
                "http://sub.example/s",
                None,
            ),
            (vec![("HTTPS_PROXY", "   ")], "https://sub.example/s", None),
        ];
        for (pairs, url, expected) in cases {
            let (response, _) = Resp::new(200).text("ok").build();
            let transport = scripted(vec![response]);
            let fetcher = fetcher(transport.clone(), fixed(&["8.8.8.8"])).with_env(env_of(&pairs));
            let result = fetcher.fetch_public_subscription(url).await;
            assert!(result.is_ok(), "{pairs:?} {url}");
            assert_eq!(
                transport.recorded()[0].proxy.as_deref(),
                expected,
                "{pairs:?} {url}"
            );
        }
    }

    #[tokio::test]
    async fn no_proxy_cannot_bypass_the_deployment_proxy() {
        let (response, _) = Resp::new(200).text("ok").build();
        let transport = scripted(vec![response]);
        let fetcher = fetcher(transport.clone(), fixed(&["8.8.8.8"])).with_env(env_of(&[
            ("HTTPS_PROXY", "http://deploy:8000"),
            ("NO_PROXY", "sub.example"),
        ]));
        assert!(fetcher
            .fetch_public_subscription("https://sub.example/s")
            .await
            .is_ok());
        assert_eq!(
            transport.recorded()[0].proxy.as_deref(),
            Some("http://deploy:8000")
        );
    }

    #[tokio::test]
    async fn redirects_reselect_the_proxy_and_revalidate_dns() {
        let (first, _) = Resp::new(302)
            .location("https://secure.example/sub")
            .build();
        let (second, _) = Resp::new(200).text("ok").build();
        let transport = scripted(vec![first, second]);
        let resolver = mapping(vec![
            ("sub.example", ips(&["8.8.8.8"])),
            ("secure.example", ips(&["1.1.1.1"])),
        ]);
        let fetcher = fetcher(transport.clone(), resolver.clone()).with_env(env_of(&[
            ("HTTP_PROXY", "http://plain:8000"),
            ("HTTPS_PROXY", "http://tls:8000"),
        ]));
        let result = fetcher
            .fetch_public_subscription("http://sub.example/sub")
            .await;
        assert!(result.is_ok());
        let requests = transport.recorded();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].proxy.as_deref(), Some("http://plain:8000"));
        assert_eq!(requests[1].proxy.as_deref(), Some("http://tls:8000"));
        assert_eq!(requests[1].host_header, "secure.example");
        assert_eq!(requests[1].sni, "secure.example");
        assert_eq!(
            resolver.hosts(),
            vec!["sub.example".to_string(), "secure.example".to_string()]
        );
    }

    #[tokio::test]
    async fn dns_rebinding_cannot_change_the_pinned_address() {
        let (response, _) = Resp::new(200).text("ok").build();
        let transport = scripted(vec![response]);
        let resolver = sequence(vec![ips(&["8.8.8.8"]), ips(&["127.0.0.1"])]);
        let result = fetcher(transport.clone(), resolver.clone())
            .fetch_public_subscription("https://sub.example/sub")
            .await;
        assert!(result.is_ok());
        assert_eq!(resolver.call_count(), 1);
        assert_eq!(
            transport.recorded()[0].address,
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn ipv6_connect_timeout_falls_back_to_ipv4() {
        let transport = MockTransport::new(Arc::new(|request: AttemptRequest, _index: usize| {
            Box::pin(async move {
                if request.address.is_ipv6() {
                    return Err(FetchError::connect_timeout("ipv6 connect timed out"));
                }
                Ok(Resp::new(200).text("ok").build().0)
            })
        }));
        let resolver = fixed(&["2606:4700:4700::1111", "8.8.8.8"]);
        let fetcher =
            fetcher(transport.clone(), resolver.clone()).with_timeout(Duration::from_millis(200));
        let result = fetcher
            .fetch_public_subscription("https://sub.example/sub")
            .await;
        assert!(result.is_ok());
        let requests = transport.recorded();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].address.is_ipv6());
        assert!(!requests[1].address.is_ipv6());
        assert_eq!(resolver.call_count(), 1);
        // 第一个地址只拿到总预算的一半，给后续地址留时间。
        assert!(
            requests[0].connect_timeout <= Duration::from_millis(110),
            "{:?}",
            requests[0].connect_timeout
        );
        assert!(requests[1].connect_timeout <= Duration::from_millis(200));
    }

    #[tokio::test]
    async fn same_family_connect_error_falls_back_without_a_second_lookup() {
        let transport = MockTransport::new(Arc::new(|request: AttemptRequest, _index: usize| {
            Box::pin(async move {
                if request.address == "8.8.8.8".parse::<IpAddr>().unwrap() {
                    return Err(FetchError::connect("connection refused"));
                }
                Ok(Resp::new(200).text("ok").build().0)
            })
        }));
        let resolver = fixed(&["8.8.8.8", "8.8.4.4"]);
        let result = fetcher(transport.clone(), resolver.clone())
            .fetch_public_subscription("https://sub.example/sub")
            .await;
        assert!(result.is_ok());
        assert_eq!(transport.count(), 2);
        assert_eq!(resolver.call_count(), 1);
    }

    #[tokio::test]
    async fn duplicate_addresses_are_not_retried() {
        let transport = MockTransport::new(Arc::new(|_request: AttemptRequest, _index: usize| {
            Box::pin(async move { Err(FetchError::connect("connection refused")) })
        }));
        let resolver = fixed(&["8.8.8.8", "8.8.8.8", "8.8.4.4", "8.8.4.4"]);
        let result = fetcher(transport.clone(), resolver)
            .fetch_public_subscription("https://sub.example/sub")
            .await;
        assert!(!result.is_ok());
        assert_eq!(result.error(), Some(ERR_TRANSPORT));
        assert_eq!(transport.count(), 2);
    }

    #[tokio::test]
    async fn equivalent_ipv6_answers_are_deduplicated() {
        let (response, _) = Resp::new(200).text("ok").build();
        let transport = scripted(vec![response]);
        let resolver = fixed(&["2606:4700:4700::1111", "2606:4700:4700:0:0:0:0:1111"]);
        let result = fetcher(transport.clone(), resolver)
            .fetch_public_subscription("https://sub.example/sub")
            .await;
        assert!(result.is_ok());
        assert_eq!(transport.count(), 1);
    }

    #[tokio::test]
    async fn any_private_answer_rejects_the_whole_lookup() {
        let transport = scripted(vec![Resp::new(200).text("ok").build().0]);
        let resolver = fixed(&["2606:4700:4700::1111", "8.8.8.8", "127.0.0.1"]);
        let result = fetcher(transport.clone(), resolver)
            .fetch_public_subscription("https://sub.example/sub")
            .await;
        assert_eq!(result.error(), Some(ERR_UNSAFE_URL));
        assert_eq!(transport.count(), 0);
    }

    #[tokio::test]
    async fn http_errors_do_not_switch_addresses() {
        for status in [400u16, 500, 503] {
            let (response, _) = Resp::new(status).text("boom").build();
            let transport = scripted(vec![response]);
            let result = fetcher(transport.clone(), fixed(&["8.8.8.8", "8.8.4.4"]))
                .fetch_public_subscription("https://sub.example/sub")
                .await;
            assert_eq!(
                result,
                FetchResult::Err {
                    status: Some(status),
                    error: format!("HTTP {status}")
                }
            );
            assert_eq!(transport.count(), 1);
        }
    }

    #[tokio::test]
    async fn certificate_errors_do_not_switch_addresses() {
        let transport = MockTransport::new(Arc::new(|_request: AttemptRequest, _index: usize| {
            Box::pin(async move { Err(FetchError::certificate("certificate verify failed")) })
        }));
        let result = fetcher(transport.clone(), fixed(&["8.8.8.8", "8.8.4.4"]))
            .fetch_public_subscription("https://sub.example/sub?token=SECRET")
            .await;
        assert_eq!(result.error(), Some(ERR_TRANSPORT));
        assert!(!result.error().unwrap().contains("SECRET"));
        assert_eq!(transport.count(), 1);
    }

    #[tokio::test]
    async fn body_read_failure_stops_after_the_first_address_and_hides_details() {
        let (response, probe) = Resp::new(200)
            .chunks(vec![b"partial".as_slice()])
            .body_error(FetchError::read("body read failed for token=SECRET"))
            .build();
        let transport = scripted(vec![response]);
        let result = fetcher(transport.clone(), fixed(&["8.8.8.8", "8.8.4.4"]))
            .fetch_public_subscription("https://sub.example/sub?token=SECRET")
            .await;
        assert_eq!(result.error(), Some(ERR_TRANSPORT));
        assert!(result.content().is_none());
        assert!(!result.error().unwrap().contains("SECRET"));
        assert_eq!(transport.count(), 1);
        assert!(probe.closed());
    }

    #[tokio::test]
    async fn connect_budget_leaves_time_for_later_addresses() {
        let transport = MockTransport::new(Arc::new(|request: AttemptRequest, _index: usize| {
            Box::pin(async move {
                if request.address == "8.8.8.8".parse::<IpAddr>().unwrap() {
                    return Err(FetchError::connect_timeout("slow"));
                }
                Ok(Resp::new(200).text("ok").build().0)
            })
        }));
        let fetcher = fetcher(transport.clone(), fixed(&["8.8.8.8", "8.8.4.4"]))
            .with_timeout(Duration::from_millis(200));
        assert!(fetcher
            .fetch_public_subscription("https://sub.example/sub")
            .await
            .is_ok());
        let requests = transport.recorded();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].connect_timeout <= Duration::from_millis(110));
        assert!(requests[0].connect_timeout < requests[1].connect_timeout);
    }

    #[tokio::test]
    async fn system_resolver_resolves_localhost_off_the_async_thread() {
        let resolved = SystemResolver
            .resolve("localhost", 80)
            .await
            .expect("localhost resolves");
        assert!(resolved.iter().any(|ip| ip.is_loopback()), "{resolved:?}");
    }

    #[tokio::test]
    async fn empty_or_private_lookups_are_rejected() {
        let cases: Vec<Vec<IpAddr>> = vec![
            vec![],
            ips(&["10.0.0.1"]),
            ips(&["127.0.0.1"]),
            ips(&["0.0.0.0"]),
            ips(&["::1"]),
            ips(&["100.64.0.1"]),
            ips(&["169.254.169.254"]),
        ];
        for answers in cases {
            let transport = scripted(vec![Resp::new(200).text("ok").build().0]);
            let resolver = Arc::new(MockResolver {
                calls: Mutex::new(Vec::new()),
                answers: {
                    let answers = answers.clone();
                    Box::new(move |_host: &str, _index: usize| Ok(answers.clone()))
                },
            });
            let result = fetcher(transport.clone(), resolver)
                .fetch_public_subscription("https://sub.example/sub")
                .await;
            assert_eq!(result.error(), Some(ERR_UNSAFE_URL), "{answers:?}");
            assert_eq!(transport.count(), 0, "{answers:?}");
        }
    }

    #[tokio::test]
    async fn dns_failures_are_reported_without_leaking_details() {
        let transport = scripted(vec![Resp::new(200).text("ok").build().0]);
        let result = fetcher(
            transport.clone(),
            failing("getaddrinfo failed for token=SECRET"),
        )
        .fetch_public_subscription("https://sub.example/sub?token=SECRET")
        .await;
        assert_eq!(result.error(), Some(ERR_UNSAFE_URL));
        assert!(!result.error().unwrap().contains("SECRET"));
        assert_eq!(transport.count(), 0);
    }

    #[tokio::test]
    async fn non_public_literals_and_bad_schemes_are_rejected() {
        let cases = [
            "https://user:pass@sub.example/sub",
            "ftp://sub.example/sub",
            "gopher://sub.example/",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "https:///no-host",
            "http://127.0.0.1/sub",
            "http://10.0.0.5/sub",
            "http://169.254.169.254/latest/meta-data/",
            "https://[::1]/sub",
            "https://[fd00::1]/sub",
            "https://[fe80::1%25eth0]/sub",
        ];
        for url in cases {
            let transport = scripted(vec![Resp::new(200).text("ok").build().0]);
            let resolver = failing("should not be consulted");
            let result = fetcher(transport.clone(), resolver.clone())
                .fetch_public_subscription(url)
                .await;
            assert_eq!(result.error(), Some(ERR_UNSAFE_URL), "{url}");
            assert_eq!(transport.count(), 0, "{url}");
            assert_eq!(resolver.call_count(), 0, "{url}");
            assert!(!result.error().unwrap().contains("SECRET"), "{url}");
        }
    }

    #[tokio::test]
    async fn public_literals_skip_dns_entirely() {
        let (response, _) = Resp::new(200).text("ok").build();
        let transport = scripted(vec![response]);
        let resolver = failing("literal must not be resolved");
        let result = fetcher(transport.clone(), resolver.clone())
            .fetch_public_subscription("http://8.8.8.8/sub")
            .await;
        assert!(result.is_ok());
        assert_eq!(resolver.call_count(), 0);
        let requests = transport.recorded();
        assert_eq!(requests[0].address, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(requests[0].host_header, "8.8.8.8");
    }

    #[tokio::test]
    async fn ipv6_answers_and_literal_authorities_keep_their_shape() {
        let (response, _) = Resp::new(200).text("ok").build();
        let transport = scripted(vec![response]);
        let result = fetcher(transport.clone(), fixed(&["2606:4700:4700::1111"]))
            .fetch_public_subscription("https://sub.example:8443/sub")
            .await;
        assert!(result.is_ok());
        let requests = transport.recorded();
        assert_eq!(requests[0].host_header, "sub.example:8443");
        assert_eq!(requests[0].sni, "sub.example");
        assert!(requests[0].address.is_ipv6());

        let (literal, _) = Resp::new(200).text("ok").build();
        let transport = scripted(vec![literal]);
        let resolver = failing("literal must not be resolved");
        let result = fetcher(transport.clone(), resolver.clone())
            .fetch_public_subscription("https://[2606:4700:4700::1111]:8443/sub")
            .await;
        assert!(result.is_ok());
        assert_eq!(resolver.call_count(), 0);
        let requests = transport.recorded();
        assert_eq!(requests[0].host_header, "[2606:4700:4700::1111]:8443");
        assert_eq!(requests[0].sni, "2606:4700:4700::1111");
    }

    #[tokio::test]
    async fn international_hostnames_are_punycoded() {
        let (response, _) = Resp::new(200).text("ok").build();
        let transport = scripted(vec![response]);
        let result = fetcher(transport.clone(), fixed(&["8.8.8.8"]))
            .fetch_public_subscription("https://bücher.example/sub")
            .await;
        assert!(result.is_ok());
        let requests = transport.recorded();
        assert_eq!(requests[0].host_header, "xn--bcher-kva.example");
        assert_eq!(requests[0].sni, "xn--bcher-kva.example");
    }

    #[tokio::test]
    async fn relative_redirects_resolve_against_the_logical_url() {
        let (first, _) = Resp::new(302).location("../next?token=x").build();
        let (second, _) = Resp::new(200).text("ok").build();
        let transport = scripted(vec![first, second]);
        let resolver = fixed(&["8.8.8.8"]);
        let result = fetcher(transport.clone(), resolver.clone())
            .fetch_public_subscription("https://sub.example/base/start")
            .await;
        assert!(result.is_ok());
        let requests = transport.recorded();
        assert_eq!(requests[1].url, "https://sub.example/next?token=x");
        assert_eq!(requests[1].host_header, "sub.example");
        assert_eq!(resolver.call_count(), 2);
    }

    #[tokio::test]
    async fn redirect_to_a_private_target_is_rejected() {
        let (first, _) = Resp::new(302)
            .location("http://internal.example/admin")
            .build();
        let transport = scripted(vec![first]);
        let resolver = mapping(vec![
            ("sub.example", ips(&["8.8.8.8"])),
            ("internal.example", ips(&["10.0.0.1"])),
        ]);
        let result = fetcher(transport.clone(), resolver.clone())
            .fetch_public_subscription("https://sub.example/sub")
            .await;
        assert_eq!(result.error(), Some(ERR_UNSAFE_URL));
        assert_eq!(transport.count(), 1);
        assert_eq!(resolver.call_count(), 2);
    }

    #[tokio::test]
    async fn same_host_redirects_revalidate_dns() {
        let (first, _) = Resp::new(302).location("/next").build();
        let (second, _) = Resp::new(200).text("ok").build();
        let transport = scripted(vec![first, second]);
        let resolver = sequence(vec![ips(&["8.8.8.8"]), ips(&["127.0.0.1"])]);
        let result = fetcher(transport.clone(), resolver.clone())
            .fetch_public_subscription("https://sub.example/sub")
            .await;
        assert_eq!(result.error(), Some(ERR_UNSAFE_URL));
        assert_eq!(transport.count(), 1);
        assert_eq!(resolver.call_count(), 2);
    }

    #[tokio::test]
    async fn redirects_are_capped_at_five_hops() {
        let mut responses = Vec::new();
        for hop in 0..MAX_REDIRECTS {
            let (response, _) = Resp::new(302).location(&format!("/hop-{hop}")).build();
            responses.push(response);
        }
        responses.push(Resp::new(200).text("final").build().0);
        let transport = scripted(responses);
        let result = fetcher(transport.clone(), fixed(&["8.8.8.8"]))
            .fetch_public_subscription("https://sub.example/start")
            .await;
        assert_eq!(
            result,
            FetchResult::Ok {
                status: 200,
                content: "final".into()
            }
        );
        assert_eq!(transport.count(), 6);

        let mut responses = Vec::new();
        for hop in 0..=MAX_REDIRECTS {
            let (response, _) = Resp::new(302).location(&format!("/hop-{hop}")).build();
            responses.push(response);
        }
        let transport = scripted(responses);
        let result = fetcher(transport.clone(), fixed(&["8.8.8.8"]))
            .fetch_public_subscription("https://sub.example/start")
            .await;
        assert_eq!(
            result,
            FetchResult::Err {
                status: Some(302),
                error: ERR_TOO_MANY_REDIRECTS.into()
            }
        );
        assert_eq!(transport.count(), 6);
    }

    #[tokio::test]
    async fn malformed_redirects_and_error_statuses_report_the_status() {
        let (missing, _) = Resp::new(302).build();
        for (response, status) in [(missing, 302u16), (Resp::new(304).build().0, 304)] {
            let transport = scripted(vec![response]);
            let result = fetcher(transport.clone(), fixed(&["8.8.8.8", "8.8.4.4"]))
                .fetch_public_subscription("https://sub.example/sub")
                .await;
            assert_eq!(result.status(), Some(status));
            assert!(!result.is_ok());
            assert_eq!(transport.count(), 1);
            if status == 302 {
                assert_eq!(result.error(), Some(ERR_REDIRECT_NO_LOCATION));
            } else {
                assert_eq!(result.error(), Some("HTTP 304"));
            }
        }
    }

    #[tokio::test]
    async fn oversized_body_closes_the_stream() {
        let big = vec![b'x'; 64 * 1024];
        let (response, probe) = Resp::new(200)
            .chunks(vec![big.as_slice(), big.as_slice(), b"never".as_slice()])
            .build();
        let transport = scripted(vec![response]);
        let result = fetcher(transport.clone(), fixed(&["8.8.8.8"]))
            .with_max_bytes(64 * 1024)
            .fetch_public_subscription("https://sub.example/sub")
            .await;
        assert_eq!(
            result,
            FetchResult::Err {
                status: Some(200),
                error: ERR_TOO_LARGE.into()
            }
        );
        assert!(probe.closed());
        assert_eq!(probe.reads(), 2);
    }

    #[tokio::test]
    async fn declared_oversize_is_rejected_without_reading() {
        let (response, probe) = Resp::new(200)
            .content_length(MAX_BYTES + 1)
            .text("body")
            .build();
        let transport = scripted(vec![response]);
        let result = fetcher(transport.clone(), fixed(&["8.8.8.8"]))
            .fetch_public_subscription("https://sub.example/sub")
            .await;
        assert_eq!(
            result,
            FetchResult::Err {
                status: Some(200),
                error: ERR_TOO_LARGE.into()
            }
        );
        assert!(probe.closed());
        assert_eq!(probe.reads(), 0);
    }

    #[tokio::test]
    async fn size_limit_is_inclusive_and_charset_is_honoured() {
        let (response, _) = Resp::new(200)
            .content_type("text/plain; charset=iso-8859-1")
            .chunks(vec![b"\xe9x".as_slice()])
            .build();
        let transport = scripted(vec![response]);
        let result = fetcher(transport.clone(), fixed(&["8.8.8.8"]))
            .with_max_bytes(2)
            .fetch_public_subscription("https://sub.example/sub")
            .await;
        assert_eq!(
            result,
            FetchResult::Ok {
                status: 200,
                content: "éx".into()
            }
        );
    }

    #[tokio::test]
    async fn transport_errors_never_leak_the_url() {
        let transport = MockTransport::new(Arc::new(|request: AttemptRequest, _index: usize| {
            Box::pin(async move {
                Err(FetchError::connect(format!(
                    "failed to connect to {}",
                    request.url
                )))
            })
        }));
        let result = fetcher(transport.clone(), fixed(&["8.8.8.8"]))
            .fetch_public_subscription("https://sub.example/sub?token=SECRET")
            .await;
        assert_eq!(result.error(), Some(ERR_TRANSPORT));
        assert!(!result.error().unwrap().contains("SECRET"));
        assert!(!result.error().unwrap().contains("sub.example"));
    }

    #[tokio::test]
    async fn whole_request_is_bounded_by_the_total_timeout() {
        let transport = MockTransport::new(Arc::new(|_request: AttemptRequest, _index: usize| {
            Box::pin(std::future::pending::<Result<AttemptResponse, FetchError>>())
        }));
        let fetcher =
            fetcher(transport.clone(), fixed(&["8.8.8.8"])).with_timeout(Duration::from_millis(30));
        let started = Instant::now();
        let result = fetcher
            .fetch_public_subscription("https://sub.example/sub")
            .await;
        assert_eq!(result.error(), Some(ERR_TIMEOUT));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn fragments_are_stripped_before_connecting() {
        let (response, _) = Resp::new(200).text("ok").build();
        let transport = scripted(vec![response]);
        let result = fetcher(transport.clone(), fixed(&["8.8.8.8"]))
            .fetch_public_subscription("https://sub.example/sub#fragment")
            .await;
        assert!(result.is_ok());
        assert_eq!(transport.recorded()[0].url, "https://sub.example/sub");
    }

    #[test]
    fn fetch_result_maps_onto_the_types_response() {
        let ok = FetchResult::Ok {
            status: 200,
            content: "abc".into(),
        }
        .to_response();
        assert!(ok.ok);
        assert_eq!(ok.status, Some(200));
        assert_eq!(ok.content.as_deref(), Some("abc"));
        assert_eq!(ok.error, None);

        let bad = FetchResult::Err {
            status: Some(500),
            error: "HTTP 500".into(),
        }
        .to_response();
        assert!(!bad.ok);
        assert_eq!(bad.status, Some(500));
        assert_eq!(bad.content, None);
        assert_eq!(bad.error.as_deref(), Some("HTTP 500"));
    }
}
