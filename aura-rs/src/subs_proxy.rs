//! 订阅解析与导入（对应 backend/subs_proxy.py）。
//!
//! 三条链路：
//! 1. 内容嗅探 → 解析：Base64 列表 / Clash YAML(proxies:) / JSON(outbounds|proxies|数组) / 明文链接。
//! 2. 单链接解析：ss(SIP002+legacy) / vmess / vless / trojan / hysteria2 / tuic / ssr / socks5 / http。
//! 3. 去重导入 + 刷新：last-good 快照兜底、pending_apply 持久化、配置应用失败降级。
//!
//! 行为约定（与 Python 版逐条对齐）：
//! - 单链接解析永不 panic：任何畸形输入返回 None，调用方过滤；未识别协议同样返回 None。
//! - 端口一律走 py_int / safe_int 容错，脏端口只丢该条节点，不影响整份订阅。
//! - DB 与配置应用通过 SubsStore / ConfigApplier 注入，本模块不直接依赖 db.rs。
use crate::subscription_fetch::{BoxFut, FetchResult, SubscriptionFetcher};
use crate::types::{
    Node, NodeBatchResponse, NodeCreate, SubParseNode, SubRefreshResult, Subscription,
};
use crate::utils::safe_int;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use regex::Regex;
use serde_json::{json, Map, Value};
use std::sync::OnceLock;

// ---------- 基础工具 ----------

/// base64 解码：URL-safe 变体归一化 + 自动补 padding + 丢弃非字母表字符。
/// 与 Python b64decode 的宽松行为对齐（允许非零尾位、padding 不敏感）。
const B64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

pub fn b64_decode(value: &str) -> Option<String> {
    let mut normalized: Vec<char> = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'))
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    if normalized.is_empty() {
        return None;
    }
    while !normalized.len().is_multiple_of(4) {
        normalized.push('=');
    }
    let payload: String = normalized.into_iter().collect();
    match B64.decode(payload.as_bytes()) {
        Ok(bytes) => Some(String::from_utf8_lossy(&bytes).into_owned()),
        Err(_) => None,
    }
}

/// 整份内容是否像 base64 订阅：长度 > 40 且只含 base64 字母表。
pub fn b64_detect(value: &str) -> bool {
    static ALPHABET: OnceLock<Regex> = OnceLock::new();
    let re =
        ALPHABET.get_or_init(|| Regex::new(r"^[A-Za-z0-9+/=_-]+$").expect("valid base64 pattern"));
    value.chars().count() > 40 && re.is_match(value.trim())
}

fn parse_base64_password(value: &str) -> String {
    match b64_decode(value) {
        Some(decoded) if !decoded.is_empty() => decoded,
        _ => value.to_string(),
    }
}

/// Python urllib.parse.unquote：解 %XX，失败保留原文（'+' 不转空格）。
fn unquote(value: &str) -> String {
    urlencoding::decode(value)
        .map(|decoded| decoded.into_owned())
        .unwrap_or_else(|_| value.to_string())
}

/// Python str() 语义（标量足够；容器退化成 JSON 文本）。
fn py_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Bool(flag) => (if *flag { "True" } else { "False" }).to_string(),
        Value::Null => "None".to_string(),
        Value::Number(number) => number.to_string(),
        other => other.to_string(),
    }
}

/// Python 真值语义：None/False/0/""/[]/{} 为假。
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().map(|n| n != 0.0).unwrap_or(true),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// Python int(str)：容忍首尾空白、正负号与数字间下划线。
fn py_int(value: &str) -> Option<i64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (negative, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    if digits.is_empty() {
        return None;
    }
    if digits.contains('_') {
        // 只允许出现在两位数字之间
        let parts: Vec<&str> = digits.split('_').collect();
        if parts
            .iter()
            .any(|part| part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()))
        {
            return None;
        }
    }
    if !digits.chars().all(|c| c.is_ascii_digit() || c == '_') {
        return None;
    }
    let cleaned: String = digits.chars().filter(|c| *c != '_').collect();
    let parsed = cleaned.parse::<i64>().ok()?;
    Some(if negative { -parsed } else { parsed })
}

/// Python int(value)：数字、布尔、数字字符串可用，其余返回 None（等价于抛异常）。
fn py_int_value(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => {
            if let Some(int) = number.as_i64() {
                Some(int)
            } else if let Some(float) = number.as_f64() {
                if float.is_finite() {
                    Some(float.trunc() as i64)
                } else {
                    None
                }
            } else {
                None
            }
        }
        Value::Bool(flag) => Some(if *flag { 1 } else { 0 }),
        Value::String(text) => py_int(text),
        _ => None,
    }
}

fn py_lower(value: &Value) -> String {
    py_str(value).to_lowercase()
}

/// Python rpartition：(前段, 是否找到分隔符, 后段)。
fn rpartition(value: &str, separator: char) -> (String, bool, String) {
    match value.rfind(separator) {
        Some(index) => (
            value[..index].to_string(),
            true,
            value[index + separator.len_utf8()..].to_string(),
        ),
        None => (String::new(), false, value.to_string()),
    }
}

fn leading_whitespace_len(line: &str) -> usize {
    line.chars().take_while(|c| c.is_whitespace()).count()
}

fn strip_quotes(value: &str) -> String {
    value
        .trim()
        .trim_matches(|c| c == '\'' || c == '"')
        .to_string()
}

/// 取可写的 tls 子对象（不存在或不是对象就新建）。
fn tls_mut(config: &mut Map<String, Value>) -> &mut Map<String, Value> {
    if !config
        .get("tls")
        .map(|value| value.is_object())
        .unwrap_or(false)
    {
        config.insert("tls".to_string(), json!({}));
    }
    config
        .get_mut("tls")
        .and_then(|value| value.as_object_mut())
        .expect("tls object")
}

/// 取可写的 transport 子对象。
fn transport_mut(config: &mut Map<String, Value>) -> &mut Map<String, Value> {
    if !config
        .get("transport")
        .map(|value| value.is_object())
        .unwrap_or(false)
    {
        config.insert("transport".to_string(), json!({}));
    }
    config
        .get_mut("transport")
        .and_then(|value| value.as_object_mut())
        .expect("transport object")
}

// ---------- 节点端点规范化 ----------

/// 节点原生代理（socks5/http）的可直连端点。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// 从 rawConfig 取 (host, port)，容忍 address/port 别名。
pub fn endpoint_of(config: &Map<String, Value>) -> (String, i64) {
    let host = config
        .get("server")
        .filter(|value| truthy(value))
        .or_else(|| config.get("address").filter(|value| truthy(value)))
        .map(py_str)
        .unwrap_or_default();
    let port_value = config
        .get("server_port")
        .filter(|value| truthy(value))
        .or_else(|| config.get("port").filter(|value| truthy(value)))
        .cloned()
        .unwrap_or_else(|| json!(0));
    (host.trim().to_string(), safe_int(&port_value, 0))
}

/// 解析节点的原生代理端点；rawConfig 不全时回落解析 `rawConfig.uri`。
///
/// rawConfig 是规范来源，但历史导入的节点可能只留了 uri。把补齐逻辑放在解析层，
/// 所有消费方（出口探测 / 配置生成）才能看到同一份规范化结果。
///
/// 入参既可以是完整节点 dict（含 rawConfig），也可以直接是 rawConfig 本身。
pub fn proxy_endpoint(node: &Value) -> Option<ProxyEndpoint> {
    if let Some(raw) = node.get("rawConfig").filter(|value| value.is_object()) {
        return proxy_endpoint_of_raw(Some(raw));
    }
    proxy_endpoint_of_raw(Some(node))
}

/// 强类型入口：从 types::Node 取 rawConfig 再规范化。
pub fn proxy_endpoint_of_node(node: &Node) -> Option<ProxyEndpoint> {
    proxy_endpoint_of_raw(node.base.raw_config.as_ref())
}

pub fn proxy_endpoint_of_raw(raw: Option<&Value>) -> Option<ProxyEndpoint> {
    let mut config: Map<String, Value> = raw
        .and_then(|value| value.as_object())
        .cloned()
        .unwrap_or_default();
    let (mut host, mut port) = endpoint_of(&config);
    let uri = config.get("uri").filter(|value| truthy(value)).map(py_str);
    if (host.is_empty() || !(1..=65535).contains(&port)) && uri.is_some() {
        // Python 用 try/except 包住：解析失败即返回 None。
        let parsed = parse_link(&uri.unwrap_or_default())?;
        let mut merged: Map<String, Value> =
            parsed.raw_config.as_object().cloned().unwrap_or_default();
        for (key, value) in config.clone() {
            merged.insert(key, value);
        }
        config = merged;
        let endpoint = endpoint_of(&config);
        host = endpoint.0;
        port = endpoint.1;
    }
    if host.is_empty() || !(1..=65535).contains(&port) {
        return None;
    }
    Some(ProxyEndpoint {
        host,
        port: u16::try_from(port).ok()?,
        username: config
            .get("username")
            .filter(|value| truthy(value))
            .map(py_str),
        password: config
            .get("password")
            .filter(|value| truthy(value))
            .map(py_str),
    })
}

// ---------- 单链接解析 ----------

fn ss_legacy_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN
        .get_or_init(|| Regex::new(r"^([^:]+):([^@]+)@([^:]+):(\d+)$").expect("ss legacy pattern"))
}

fn hysteria2_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"^([^@]*)@?([^:]+):(\d+)(.*)$").expect("hysteria2 pattern"))
}

fn tuic_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"^([^@]+)@([^:]+):(\d+)(.*)$").expect("tuic pattern"))
}

fn query_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"([^&=]+)=([^&]+)").expect("query pattern"))
}

/// hysteria2/tuic 的查询串解析：只按正则抓 k=v，value 不做 unquote。
fn scan_params(query: &str) -> Map<String, Value> {
    let mut params = Map::new();
    for caps in query_pattern().captures_iter(query) {
        params.insert(caps[1].to_string(), Value::String(caps[2].to_string()));
    }
    params
}

fn parse_port(value: &str) -> Option<i64> {
    py_int(value)
}

/// 解析一行订阅链接；任何畸形输入返回 None（绝不 panic）。
pub fn parse_link(line: &str) -> Option<SubParseNode> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut name = String::new();
    let mut line = line.to_string();
    if let Some(index) = line.find('#') {
        name = unquote(&line[index + 1..]);
        line.truncate(index);
    }

    // ss:// — SIP002 或 legacy
    if let Some(body) = line.strip_prefix("ss://") {
        if body.contains('@') {
            // SIP002: method:pass@host:port[?plugin=...]
            let (cred, _, hostport) = rpartition(body, '@');
            let hostport = match hostport.find('?') {
                Some(index) => hostport[..index].to_string(),
                None => hostport,
            };
            let (host, found, port_text) = rpartition(&hostport, ':');
            if !found {
                return None;
            }
            let (method, password) = if cred.contains(':') && !cred.starts_with("aes") {
                match cred.split_once(':') {
                    Some((method, password)) => (method.to_string(), password.to_string()),
                    None => return None,
                }
            } else {
                let decoded = b64_decode(&cred).unwrap_or_else(|| cred.clone());
                match decoded.split_once(':') {
                    Some((method, password)) => (method.to_string(), password.to_string()),
                    None => return None,
                }
            };
            let port = parse_port(&port_text)?;
            let node_name = if name.is_empty() {
                format!("ss-{host}")
            } else {
                name
            };
            return Some(SubParseNode {
                name: node_name,
                protocol: "shadowsocks".to_string(),
                raw_config: json!({
                    "server": host,
                    "server_port": port,
                    "method": method,
                    "password": password,
                }),
            });
        }
        // legacy: base64(method:pass@host:port)
        let mut decoded = b64_decode(body).unwrap_or_else(|| body.to_string());
        // 名字可能嵌在 base64 载荷内部（如 "...#ss-Test"），外部剥离不到 → 解码后切出
        let mut frag = String::new();
        if let Some(index) = decoded.find('#') {
            frag = decoded[index + 1..].to_string();
            decoded.truncate(index);
        }
        let caps = ss_legacy_pattern().captures(&decoded)?;
        let port = parse_port(&caps[4])?;
        let host = caps[3].to_string();
        let node_name = if !name.is_empty() {
            name
        } else if !frag.is_empty() {
            frag
        } else {
            format!("ss-{host}")
        };
        return Some(SubParseNode {
            name: node_name,
            protocol: "shadowsocks".to_string(),
            raw_config: json!({
                "server": host,
                "server_port": port,
                "method": caps[1].to_string(),
                "password": caps[2].to_string(),
            }),
        });
    }

    // vmess:// — base64 JSON
    if let Some(body) = line.strip_prefix("vmess://") {
        let decoded = b64_decode(body)?;
        if decoded.is_empty() {
            return None;
        }
        let data: Value = serde_json::from_str(&decoded).ok()?;
        let data = data.as_object()?;
        let port_value = data.get("port").cloned().unwrap_or_else(|| json!(0));
        let port = py_int_value(&port_value)?;
        let mut config = Map::new();
        config.insert(
            "server".to_string(),
            data.get("add").cloned().unwrap_or_else(|| json!("")),
        );
        config.insert("server_port".to_string(), json!(port));
        config.insert(
            "uuid".to_string(),
            data.get("id").cloned().unwrap_or_else(|| json!("")),
        );
        config.insert(
            "method".to_string(),
            data.get("method").cloned().unwrap_or_else(|| json!("auto")),
        );
        config.insert(
            "security".to_string(),
            data.get("security")
                .cloned()
                .unwrap_or_else(|| json!("auto")),
        );
        config.insert(
            "alterId".to_string(),
            data.get("aid").cloned().unwrap_or_else(|| json!(0)),
        );
        // vmess base64 JSON 标准字段：tls=over-tls, sni, net=ws/grpc, host, path, fp
        let tls_raw = data.get("tls").map(py_lower).unwrap_or_default();
        if matches!(tls_raw.as_str(), "tls" | "1" | "true") {
            tls_mut(&mut config).insert("enabled".to_string(), json!(true));
            if let Some(sni) = data.get("sni").filter(|value| truthy(value)) {
                tls_mut(&mut config).insert("server_name".to_string(), sni.clone());
            }
            if let Some(fingerprint) = data.get("fp").filter(|value| truthy(value)) {
                let lowered = py_lower(fingerprint);
                if !matches!(lowered.as_str(), "none" | "random") {
                    tls_mut(&mut config).insert(
                        "utls".to_string(),
                        json!({"enabled": true, "fingerprint": fingerprint.clone()}),
                    );
                }
            }
            let insecure_raw = data.get("allowInsecure").map(py_lower).unwrap_or_default();
            if matches!(insecure_raw.as_str(), "1" | "true") {
                tls_mut(&mut config).insert("insecure".to_string(), json!(true));
            }
        }
        let network = data
            .get("net")
            .filter(|value| truthy(value))
            .map(py_str)
            .unwrap_or_default();
        if !network.is_empty() && network != "tcp" {
            transport_mut(&mut config).insert("type".to_string(), json!(network.clone()));
            if let Some(path) = data.get("path").filter(|value| truthy(value)) {
                transport_mut(&mut config).insert("path".to_string(), path.clone());
            }
            if let Some(host) = data.get("host").filter(|value| truthy(value)) {
                if network == "grpc" {
                    transport_mut(&mut config).insert("service_name".to_string(), host.clone());
                } else {
                    transport_mut(&mut config)
                        .insert("headers".to_string(), json!({"Host": host.clone()}));
                }
            }
        }
        let node_name = if !name.is_empty() {
            name
        } else if let Some(ps) = data.get("ps").filter(|value| truthy(value)) {
            py_str(ps)
        } else {
            format!("vmess-{}", data.get("add").map(py_str).unwrap_or_default())
        };
        return Some(SubParseNode {
            name: node_name,
            protocol: "vmess".to_string(),
            raw_config: Value::Object(config),
        });
    }

    // vless:// / trojan:// — URI
    for proto in ["vless", "trojan"] {
        let prefix = format!("{proto}://");
        let Some(body) = line.strip_prefix(&prefix) else {
            continue;
        };
        let (cred, hostport) = if body.contains('@') {
            let (cred, _, hostport) = rpartition(body, '@');
            (cred, hostport)
        } else {
            (String::new(), body.to_string())
        };
        // P2-10：vless/trojan 无凭据（cred 为空）→ 跳过该行（垃圾 uuid 连不通只会迷惑用户）
        if cred.is_empty() || hostport.is_empty() {
            return None;
        }
        let (host, found, port_and_query) = rpartition(&hostport, ':');
        if !found {
            return None;
        }
        let mut params: Map<String, Value> = Map::new();
        let port_text = match port_and_query.split_once('?') {
            Some((port_text, query)) => {
                for kv in query.split('&') {
                    if let Some((key, value)) = kv.split_once('=') {
                        params.insert(key.to_string(), Value::String(unquote(value)));
                    }
                }
                port_text.to_string()
            }
            None => port_and_query,
        };
        let port = parse_port(&port_text)?;
        let mut config = Map::new();
        config.insert("server".to_string(), json!(host));
        config.insert("server_port".to_string(), json!(port));
        config.insert("uuid".to_string(), json!(cred));
        config.insert("password".to_string(), json!(cred));
        config.insert("tls".to_string(), json!({"enabled": true}));
        let text = |key: &str| params.get(key).filter(|value| truthy(value)).map(py_str);
        if let Some(sni) = text("sni") {
            tls_mut(&mut config).insert("server_name".to_string(), json!(sni));
        } else if let Some(server_name) = text("servername") {
            tls_mut(&mut config).insert("server_name".to_string(), json!(server_name));
        }
        if let Some(alpn) = text("alpn") {
            let items: Vec<Value> = alpn
                .split(',')
                .filter(|item| !item.is_empty())
                .map(|item| json!(item))
                .collect();
            tls_mut(&mut config).insert("alpn".to_string(), Value::Array(items));
        }
        if let Some(fingerprint) = text("fp") {
            tls_mut(&mut config).insert(
                "utls".to_string(),
                json!({"enabled": true, "fingerprint": fingerprint}),
            );
        }
        // vless/trojan 常见 allowInsecure / insecure 参数
        for key in ["allowInsecure", "insecure"] {
            if matches!(text(key).as_deref(), Some("1") | Some("true") | Some("yes")) {
                tls_mut(&mut config).insert("insecure".to_string(), json!(true));
            }
        }
        if let Some(flow) = text("flow") {
            config.insert("flow".to_string(), json!(flow));
        }
        let transport_type = text("type").unwrap_or_else(|| "tcp".to_string());
        if transport_type != "tcp" {
            transport_mut(&mut config).insert("type".to_string(), json!(transport_type.clone()));
            if let Some(path) = text("path") {
                transport_mut(&mut config).insert("path".to_string(), json!(path));
            }
            if let Some(transport_host) = text("host") {
                // ws 传输 host 在 headers.Host；http/h2 传输 host 在 host 数组
                if matches!(transport_type.as_str(), "http" | "h2") {
                    transport_mut(&mut config).insert("host".to_string(), json!([transport_host]));
                } else {
                    transport_mut(&mut config)
                        .insert("headers".to_string(), json!({"Host": transport_host}));
                }
            }
            if let Some(service_name) = text("serviceName") {
                transport_mut(&mut config).insert("service_name".to_string(), json!(service_name));
            }
        }
        if text("security").as_deref() == Some("reality") {
            let reality = json!({
                "enabled": true,
                "public_key": text("pbk").unwrap_or_default(),
                "short_id": text("sid").unwrap_or_default(),
            });
            tls_mut(&mut config).insert("reality".to_string(), reality);
            // sing-box reality client 强制要求 uTLS（无 fp 默认 chrome）
            let needs_utls = !tls_mut(&mut config).contains_key("utls");
            if needs_utls {
                let fingerprint = text("fp").unwrap_or_else(|| "chrome".to_string());
                tls_mut(&mut config).insert(
                    "utls".to_string(),
                    json!({"enabled": true, "fingerprint": fingerprint}),
                );
            }
        }
        let node_name = if name.is_empty() {
            format!("{proto}-{host}")
        } else {
            name
        };
        return Some(SubParseNode {
            name: node_name,
            protocol: proto.to_string(),
            raw_config: Value::Object(config),
        });
    }

    // hysteria2://
    if let Some(body) = line.strip_prefix("hysteria2://") {
        let caps = hysteria2_pattern().captures(body)?;
        let port = parse_port(&caps[3])?;
        let params = scan_params(caps[4].trim_start_matches('?'));
        let password = if caps[1].is_empty() {
            params
                .get("auth")
                .filter(|value| truthy(value))
                .map(py_str)
                .unwrap_or_default()
        } else {
            caps[1].to_string()
        };
        let mut config = Map::new();
        config.insert("server".to_string(), json!(caps[2].to_string()));
        config.insert("server_port".to_string(), json!(port));
        config.insert("password".to_string(), json!(password));
        config.insert(
            "sni".to_string(),
            json!(params
                .get("sni")
                .filter(|value| truthy(value))
                .map(py_str)
                .unwrap_or_default()),
        );
        if matches!(
            params.get("insecure").map(py_str).as_deref(),
            Some("1") | Some("true") | Some("yes")
        ) {
            config.insert("insecure".to_string(), json!(true));
        }
        if let Some(obfs) = params.get("obfs").filter(|value| truthy(value)) {
            config.insert("obfs".to_string(), obfs.clone());
            config.insert(
                "obfsPassword".to_string(),
                json!(params
                    .get("obfs-password")
                    .filter(|value| truthy(value))
                    .map(py_str)
                    .unwrap_or_default()),
            );
        }
        let node_name = if name.is_empty() {
            format!("hy2-{}", &caps[2])
        } else {
            name
        };
        return Some(SubParseNode {
            name: node_name,
            protocol: "hysteria2".to_string(),
            raw_config: Value::Object(config),
        });
    }

    // tuic://
    if let Some(body) = line.strip_prefix("tuic://") {
        let caps = tuic_pattern().captures(body)?;
        let port = parse_port(&caps[3])?;
        let credentials: Vec<&str> = caps[1].split(':').collect();
        let params = scan_params(caps[4].trim_start_matches('?'));
        let uuid = credentials.first().copied().unwrap_or_default().to_string();
        let password = credentials.get(1).copied().unwrap_or_default().to_string();
        let mut config = Map::new();
        config.insert("server".to_string(), json!(caps[2].to_string()));
        config.insert("server_port".to_string(), json!(port));
        config.insert("uuid".to_string(), json!(uuid));
        config.insert("password".to_string(), json!(password));
        config.insert(
            "sni".to_string(),
            json!(params
                .get("sni")
                .filter(|value| truthy(value))
                .map(py_str)
                .unwrap_or_default()),
        );
        let node_name = if name.is_empty() {
            format!("tuic-{}", &caps[2])
        } else {
            name
        };
        return Some(SubParseNode {
            name: node_name,
            protocol: "tuic".to_string(),
            raw_config: Value::Object(config),
        });
    }

    // ssr://
    if let Some(body) = line.strip_prefix("ssr://") {
        let decoded = b64_decode(body)?;
        if decoded.is_empty() {
            return None;
        }
        let base = decoded.split("/?").next().unwrap_or("").to_string();
        let parts: Vec<&str> = base.split(':').collect();
        if parts.len() < 6 {
            return None;
        }
        let port = parse_port(parts[1])?;
        let node_name = if name.is_empty() {
            format!("ssr-{}", parts[0])
        } else {
            name
        };
        return Some(SubParseNode {
            name: node_name,
            protocol: "ssr".to_string(),
            raw_config: json!({
                "server": parts[0],
                "server_port": port,
                "protocol": parts[2],
                "method": parts[3],
                "obfs": parts[4],
                "password": parse_base64_password(parts[5]),
            }),
        });
    }

    // socks5:// / http:// — user:pass@host:port（可省略认证）
    for (prefix, proto) in [("socks5://", "socks5"), ("http://", "http")] {
        let Some(body) = line.strip_prefix(prefix) else {
            continue;
        };
        let (cred, has_cred, hostport) = rpartition(body, '@');
        let (host, found, port_text) = rpartition(&hostport, ':');
        if !found {
            return None;
        }
        let port = parse_port(&port_text)?;
        let mut config = Map::new();
        config.insert("server".to_string(), json!(host));
        config.insert("server_port".to_string(), json!(port));
        if has_cred {
            let (username, password) = match cred.split_once(':') {
                Some((username, password)) => (username.to_string(), password.to_string()),
                None => (cred.clone(), String::new()),
            };
            if !username.is_empty() {
                config.insert("username".to_string(), json!(username));
                config.insert("password".to_string(), json!(password));
            }
        }
        let node_name = if name.is_empty() {
            format!("{proto}-{host}")
        } else {
            name
        };
        return Some(SubParseNode {
            name: node_name,
            protocol: proto.to_string(),
            raw_config: Value::Object(config),
        });
    }
    None
}

// ---------- 订阅内容形态探测 ----------

/// 明文链接列表（每行一条 ss:// / vmess:// ...）。
pub const TYPE_URLLIST: &str = "urllist";
/// Base64 包裹的链接列表。
pub const TYPE_B64: &str = "b64";
/// Clash / Mihomo 风格 YAML。
pub const TYPE_CLASH: &str = "clash";
/// sing-box / v2ray JSON。
pub const TYPE_JSON: &str = "json";
/// 无法识别。
pub const TYPE_UNKNOWN: &str = "unknown";

const PROTOCOL_ALTERNATION: &str = "ss|vmess|vless|trojan|ssr|hysteria2|tuic|socks5|http";

fn proxies_key_line() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"^\s*proxies:\s*$").expect("proxies key regex"))
}

fn proxies_inline_line() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"^\s*proxies:\s*\[").expect("proxies inline regex"))
}

fn urllist_multiline() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(&format!(r"(?m)^\s*({PROTOCOL_ALTERNATION})://"))
            .expect("urllist multiline regex")
    })
}

fn urllist_direct() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(&format!(r"^({PROTOCOL_ALTERNATION})://")).expect("urllist direct regex")
    })
}

fn top_level_key() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"^[a-zA-Z][\w-]*:\s*$").expect("top level key regex"))
}

fn list_item_prefix() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"^\s*-\s+").expect("list item regex"))
}

fn any_opts_key() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"^(\s*)[\w-]+-opts:\s*$").expect("opts key regex"))
}

fn opts_child_key() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"^\s*-?\s*([\w-]+)-opts:\s*$").expect("opts child regex"))
}

fn indented_key_value() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"^(\s+)([\w-]+):\s*(.*)$").expect("indented kv regex"))
}

fn top_level_key_value() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"^\s*([\w-]+):\s*(.*)$").expect("top level kv regex"))
}

fn leading_space_run() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"^(\s+)").expect("leading space regex"))
}

/// 判定订阅内容形态，与 Python \`_detect_type\` 完全同序。
pub fn detect_type(text: &str) -> &'static str {
    let trimmed = text.trim();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return TYPE_JSON;
    }
    let head: Vec<&str> = trimmed.lines().take(64).collect();
    let head_text = head.join("\n");
    let looks_clash = if trimmed.contains('\n') {
        trimmed
            .lines()
            .any(|line| proxies_key_line().is_match(line) || proxies_inline_line().is_match(line))
    } else {
        proxies_key_line().is_match(&head_text) || proxies_inline_line().is_match(&head_text)
    };
    if looks_clash {
        return TYPE_CLASH;
    }
    if trimmed.contains('\n') && urllist_multiline().is_match(trimmed) {
        return TYPE_URLLIST;
    }
    if urllist_direct().is_match(trimmed) {
        return TYPE_URLLIST;
    }
    if b64_detect(trimmed) {
        return TYPE_B64;
    }
    TYPE_UNKNOWN
}

/// Python \`_bool\`：真值集合 true/1/yes/on。
fn py_bool(value: &Value) -> bool {
    match value {
        Value::Bool(flag) => *flag,
        other => matches!(
            py_str(other).trim().to_lowercase().as_str(),
            "true" | "1" | "yes" | "on"
        ),
    }
}

/// 与 Python \`_truthy\` 等价的真值判定（用于 "有值才写字段" 的分支）。
fn value_is_truthy(value: &Value) -> bool {
    truthy(value)
}

// ---------- Clash / Mihomo YAML ----------

/// 解析 \`proxies:\` 列表。只做缩进感知的浅层 YAML，够用且无外部依赖。
pub fn parse_clash_yaml(content: &str) -> Vec<SubParseNode> {
    let lines: Vec<&str> = content.split('\n').collect();
    let mut start_index: Option<usize> = None;
    for (index, line) in lines.iter().enumerate() {
        if proxies_key_line().is_match(line) {
            start_index = Some(index + 1);
            break;
        }
    }
    let Some(start_index) = start_index else {
        return Vec::new();
    };

    // 先按 "- " 切块；遇到下一个顶层键就停止（proxies 列表结束）。
    let mut blocks: Vec<Vec<String>> = Vec::new();
    let mut current: Option<Vec<String>> = None;
    for (index, line) in lines.iter().enumerate().skip(start_index) {
        let line = *line;
        if index > start_index && top_level_key().is_match(line) {
            break;
        }
        if let Some(prefix) = list_item_prefix().find(line) {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
            current = Some(vec![line[prefix.end()..].to_string()]);
        } else if let Some(block) = current.as_mut() {
            block.push(line.to_string());
        }
    }
    if let Some(block) = current {
        blocks.push(block);
    }

    let mut nodes = Vec::new();
    for block in blocks {
        let mut obj: Map<String, Value> = Map::new();

        // 第一遍：定位所有 "*-opts:" 子块占用的行区间。
        let mut opts_ranges: Vec<(usize, usize)> = Vec::new();
        for (index, line) in block.iter().enumerate() {
            let Some(captures) = any_opts_key().captures(line) else {
                continue;
            };
            let base_indent = captures[1].chars().count();
            let mut end = index + 1;
            while end < block.len() {
                match leading_space_run().captures(&block[end]) {
                    Some(captures) if captures[1].chars().count() > base_indent => end += 1,
                    _ => break,
                }
            }
            opts_ranges.push((index, end));
        }

        // 第二遍：只收顶层 kv，跳过 opts 子块内的行。
        for (index, line) in block.iter().enumerate() {
            if opts_ranges
                .iter()
                .any(|(start, end)| *start <= index && index < *end)
            {
                continue;
            }
            if let Some(captures) = top_level_key_value().captures(line) {
                obj.insert(
                    captures[1].to_string(),
                    Value::String(strip_quotes(&captures[2])),
                );
            }
        }

        // 第三遍：把 opts 子块收成嵌套对象。
        for (index, line) in block.iter().enumerate() {
            let Some(captures) = opts_child_key().captures(line) else {
                continue;
            };
            let base_indent = leading_whitespace_len(line);
            let mut sub: Map<String, Value> = Map::new();
            let mut cursor = index + 1;
            while cursor < block.len() {
                let Some(entry) = indented_key_value().captures(&block[cursor]) else {
                    break;
                };
                let indent = entry[1].chars().count();
                if indent <= base_indent {
                    break;
                }
                let key = entry[2].to_string();
                let value = strip_quotes(&entry[3]);
                if key == "headers" && value.is_empty() {
                    let mut headers: Map<String, Value> = Map::new();
                    let mut inner = cursor + 1;
                    while inner < block.len() {
                        let Some(nested) = indented_key_value().captures(&block[inner]) else {
                            break;
                        };
                        if nested[1].chars().count() <= indent {
                            break;
                        }
                        headers.insert(
                            nested[2].to_string(),
                            Value::String(strip_quotes(&nested[3])),
                        );
                        inner += 1;
                    }
                    sub.insert("headers".to_string(), Value::Object(headers));
                } else {
                    sub.insert(key, Value::String(value));
                }
                cursor += 1;
            }
            obj.insert(format!("{}-opts", &captures[1]), Value::Object(sub));
        }

        let Some(name) = obj
            .get("name")
            .filter(|value| value_is_truthy(value))
            .map(py_str)
        else {
            continue;
        };
        let Some(protocol_key) = obj
            .get("type")
            .filter(|value| value_is_truthy(value))
            .map(py_str)
        else {
            continue;
        };
        let protocol = match protocol_key.as_str() {
            "ss" => "ss",
            "ssr" => "ssr",
            "vmess" => "vmess",
            "vless" => "vless",
            "trojan" => "trojan",
            "hysteria2" => "hysteria2",
            "wireguard" => "wireguard",
            "tuic" => "tuic",
            _ => continue,
        };

        // 端口能转成整数就存整数，否则原样保留（Python 版同样逻辑）。
        for key in ["port", "server_port"] {
            let Some(Value::String(text)) = obj.get(key).cloned() else {
                continue;
            };
            if let Some(port) = py_int(&text) {
                obj.insert(key.to_string(), json!(port));
            }
        }

        let tls_enabled = obj.get("tls").map(py_bool);
        let sni = obj
            .get("sni")
            .filter(|value| value_is_truthy(value))
            .or_else(|| {
                obj.get("server_name")
                    .filter(|value| value_is_truthy(value))
            })
            .map(py_str)
            .unwrap_or_default();
        let skip_verify = obj.get("skip-cert-verify").map(py_bool).unwrap_or(false);
        let explicit_tls = tls_enabled.is_some();
        if explicit_tls || !sni.is_empty() || skip_verify {
            let mut tls: Map<String, Value> = Map::new();
            tls.insert("enabled".to_string(), json!(tls_enabled.unwrap_or(true)));
            if !sni.is_empty() {
                tls.insert("server_name".to_string(), json!(sni));
            }
            if skip_verify {
                tls.insert("insecure".to_string(), json!(true));
            }
            let fingerprint = obj
                .get("fingerprint")
                .filter(|value| value_is_truthy(value))
                .or_else(|| {
                    obj.get("client-fingerprint")
                        .filter(|value| value_is_truthy(value))
                })
                .map(py_str);
            if let Some(fingerprint) = &fingerprint {
                tls.insert(
                    "utls".to_string(),
                    json!({ "enabled": true, "fingerprint": fingerprint }),
                );
            }
            if let Some(reality) = obj.get("reality-opts").and_then(|value| value.as_object()) {
                let public_key = reality
                    .get("public-key")
                    .filter(|value| value_is_truthy(value))
                    .or_else(|| {
                        reality
                            .get("public_key")
                            .filter(|value| value_is_truthy(value))
                    })
                    .map(py_str)
                    .unwrap_or_default();
                let short_id = reality
                    .get("short-id")
                    .filter(|value| value_is_truthy(value))
                    .or_else(|| {
                        reality
                            .get("short_id")
                            .filter(|value| value_is_truthy(value))
                    })
                    .map(py_str)
                    .unwrap_or_default();
                tls.insert(
                    "reality".to_string(),
                    json!({ "enabled": true, "public_key": public_key, "short_id": short_id }),
                );
                tls.entry("utls".to_string()).or_insert_with(|| {
                    json!({ "enabled": true, "fingerprint": fingerprint.clone().unwrap_or_else(|| "chrome".to_string()) })
                });
            }
            obj.insert("tls".to_string(), Value::Object(tls));
        }

        let network = match obj
            .get("network")
            .filter(|value| value_is_truthy(value))
            .map(py_str)
        {
            Some(network) => network.to_lowercase(),
            None => "tcp".to_string(),
        };
        if network != "tcp" {
            let mut transport: Map<String, Value> = Map::new();
            transport.insert("type".to_string(), json!(network));
            let opts_key = format!("{network}-opts");
            if let Some(opts) = obj
                .get(&opts_key)
                .and_then(|value| value.as_object())
                .cloned()
            {
                for (key, value) in opts.iter() {
                    if key == "headers" {
                        continue;
                    }
                    if matches!(
                        key.as_str(),
                        "tls" | "skip-cert-verify" | "servername" | "server_name" | "Host"
                    ) {
                        continue;
                    }
                    transport.insert(key.clone(), value.clone());
                }
                if let Some(headers) = opts.get("headers").and_then(|value| value.as_object()) {
                    if !headers.is_empty() {
                        transport.insert("headers".to_string(), Value::Object(headers.clone()));
                    }
                }
                if network == "ws" {
                    if let Some(path) = opts.get("path").and_then(|value| value.as_str()) {
                        let path = if path.is_empty() { "/" } else { path };
                        transport.insert("path".to_string(), json!(path));
                    }
                }
            }
            if network == "grpc"
                && !transport
                    .get("service_name")
                    .map(value_is_truthy)
                    .unwrap_or(false)
            {
                let service_name = obj
                    .get("serviceName")
                    .filter(|value| value_is_truthy(value))
                    .or_else(|| {
                        obj.get("service_name")
                            .filter(|value| value_is_truthy(value))
                    })
                    .map(py_str)
                    .unwrap_or_default();
                transport.insert("service_name".to_string(), json!(service_name));
            }
            obj.insert("transport".to_string(), Value::Object(transport));
        }

        if protocol == "hysteria2" {
            if let Some(obfs_password) = obj
                .get("obfs-password")
                .filter(|value| value_is_truthy(value))
                .cloned()
            {
                obj.insert("obfsPassword".to_string(), obfs_password);
            }
        }

        nodes.push(SubParseNode {
            name,
            protocol: protocol.to_string(),
            raw_config: Value::Object(obj),
        });
    }
    nodes
}

// ---------- sing-box / v2ray JSON ----------

fn flatten_json_items(items: Vec<Value>) -> Vec<Value> {
    let mut flat = Vec::new();
    for item in items {
        let nested = item.get("outbounds").filter(|value| value_is_truthy(value));
        match nested
            .and_then(|value| value.as_array())
            .and_then(|list| list.first())
        {
            Some(outbound) if nested.is_some() => {
                let name = item
                    .get("remarks")
                    .filter(|value| value_is_truthy(value))
                    .map(py_str)
                    .unwrap_or_else(|| outbound.get("tag").map(py_str).unwrap_or_default());
                flat.push(json!({
                    "name": name,
                    "type": outbound.get("protocol").cloned().unwrap_or(Value::Null),
                    "settings": outbound.get("settings").cloned().unwrap_or(Value::Null),
                    "streamSettings": outbound.get("streamSettings").cloned().unwrap_or(Value::Null),
                }));
            }
            _ => flat.push(item),
        }
    }
    flat
}

/// 解析 sing-box / v2ray 风格 JSON。
pub fn parse_json_content(content: &str) -> Vec<SubParseNode> {
    let Ok(parsed) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };
    let items = match parsed {
        Value::Object(ref map) => {
            if map.get("outbounds").map(value_is_truthy).unwrap_or(false) {
                map["outbounds"].clone()
            } else if map.get("proxies").map(value_is_truthy).unwrap_or(false) {
                map["proxies"].clone()
            } else {
                return Vec::new();
            }
        }
        Value::Array(items) => Value::Array(flatten_json_items(items)),
        _ => return Vec::new(),
    };
    let Value::Array(items) = items else {
        return Vec::new();
    };

    let mut nodes = Vec::new();
    for item in items {
        let Some(map) = item.as_object() else {
            continue;
        };
        let otype = map
            .get("type")
            .filter(|value| value_is_truthy(value))
            .or_else(|| map.get("protocol").filter(|value| value_is_truthy(value)))
            .map(py_str);
        let oname = ["name", "remark", "ps", "remarks"]
            .iter()
            .find_map(|key| {
                map.get(*key)
                    .filter(|value| value_is_truthy(value))
                    .map(py_str)
            })
            .unwrap_or_default();
        let Some(otype) = otype else { continue };
        if !matches!(
            otype.as_str(),
            "vmess"
                | "vless"
                | "trojan"
                | "shadowsocks"
                | "ss"
                | "hysteria2"
                | "tuic"
                | "wireguard"
        ) {
            continue;
        }
        let mut raw_config = map.clone();
        raw_config.remove("name");
        let name = if oname.is_empty() {
            let server = map.get("server").map(py_str).unwrap_or_default();
            let port = map
                .get("server_port")
                .filter(|value| value_is_truthy(value))
                .or_else(|| map.get("port").filter(|value| value_is_truthy(value)))
                .map(py_str)
                .unwrap_or_default();
            format!("{server}:{port}")
        } else {
            oname
        };
        let protocol = if otype == "shadowsocks" {
            "ss".to_string()
        } else {
            otype
        };
        nodes.push(SubParseNode {
            name,
            protocol,
            raw_config: Value::Object(raw_config),
        });
    }
    nodes
}

// ---------- 对外统一入口 ----------

fn parse_b64_content(content: &str) -> Vec<SubParseNode> {
    let Some(decoded) = b64_decode(content.trim()) else {
        return Vec::new();
    };
    if decoded.is_empty() {
        return Vec::new();
    }
    decoded.split('\n').filter_map(parse_link).collect()
}

fn parse_url_list(content: &str) -> Vec<SubParseNode> {
    content.split('\n').filter_map(parse_link).collect()
}

/// 按内容形态解析出节点，是 Python \`parse_content\` 的强类型版本。
pub fn parse_content_nodes(content: &str) -> Vec<SubParseNode> {
    match detect_type(content) {
        TYPE_B64 => parse_b64_content(content),
        TYPE_URLLIST => parse_url_list(content),
        TYPE_CLASH => parse_clash_yaml(content),
        TYPE_JSON => parse_json_content(content),
        _ => Vec::new(),
    }
}

/// 把解析结果转成 JSON 形态（name / protocol / rawConfig）。
pub fn node_to_value(node: &SubParseNode) -> Value {
    json!({
        "name": node.name,
        "protocol": node.protocol,
        "rawConfig": node.raw_config,
    })
}

/// 对外主入口：返回 \`{name, protocol, rawConfig}\` 列表，未识别形态返回空列表。
pub fn parse_content(content: &str) -> Vec<Value> {
    parse_content_nodes(content)
        .iter()
        .map(node_to_value)
        .collect()
}

// ---------- 导入与刷新：DB 与配置应用通过 trait 注入 ----------

/// 订阅记录 + 最近一次成功抓取的快照。
///
/// types::Subscription 是对外传输模型，没有 snapshot 字段；订阅刷新需要
/// “上次抓到什么”来在抓取失败时决定是否保留旧节点，所以这里单独承载。
#[derive(Debug, Clone, Default)]
pub struct SubRecord {
    pub sub: Subscription,
    pub snapshot: Option<String>,
}

/// 待写入 DB 的一条节点（Python 版 prepared dict 的强类型版本）。
#[derive(Debug, Clone, Default)]
pub struct PreparedNode {
    pub node: NodeCreate,
    pub stale: bool,
    pub selected: bool,
}

/// 订阅导入需要的最小 DB 能力。
///
/// 用 trait 而不是直接依赖 db.rs，一是 db.rs 还在迁移，二是单测可以用内存实现，
/// 不必碰真实的 data/panel.db。
pub trait SubsStore: Send + Sync {
    fn create_node_batch(
        &self,
        prepared: Vec<PreparedNode>,
        update_existing_sub: bool,
    ) -> NodeBatchResponse;
    fn random_auth(&self) -> (String, String);
    fn get_sub(&self, id: &str) -> Option<SubRecord>;
    /// 部分更新订阅；返回 None 表示订阅已被删除。
    fn update_sub(&self, id: &str, patch: Value) -> Option<SubRecord>;
    fn list_subs(&self) -> Vec<SubRecord>;
    fn mark_nodes_stale_by_sub(&self, id: &str);
    fn unmark_nodes_stale_by_sub(&self, id: &str);
}

/// 配置应用（sing-box 重载）需要的最小能力。
pub trait ConfigApplier: Send + Sync {
    fn apply<'a>(&'a self) -> BoxFut<'a, Result<Value, String>>;
}

fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_millis() as i64,
        Err(_) => 0,
    }
}

/// 把解析结果摊平成待落库节点。
///
/// port 固定 0：真正的端口由 create_node_batch 在批内从 52001 起统一分配，
/// 逐节点自己抢端口会撞车。
pub fn prepare_nodes(
    store: &dyn SubsStore,
    sub_id: &str,
    group: &str,
    sub_name: &str,
    nodes: &[SubParseNode],
    stale: bool,
) -> Vec<PreparedNode> {
    let mut prepared = Vec::with_capacity(nodes.len());
    for parsed in nodes {
        let (auth_user, auth_pass) = store.random_auth();
        let name = if parsed.name.is_empty() {
            "未命名".to_string()
        } else {
            parsed.name.clone()
        };
        let protocol = if parsed.protocol.is_empty() {
            "shadowsocks".to_string()
        } else {
            parsed.protocol.clone()
        };
        prepared.push(PreparedNode {
            node: NodeCreate {
                name,
                protocol,
                group: Some(group.to_string()),
                port: Some(0),
                segment: Some(52),
                auth_user: Some(auth_user),
                auth_pass: Some(auth_pass),
                raw_config: Some(parsed.raw_config.clone()),
                sub_id: Some(sub_id.to_string()),
                sub_name: Some(sub_name.to_string()),
                status: Some("offline".to_string()),
                ping: Some(0),
                exit_ip: Some("N/A".to_string()),
                up_traffic: Some(0),
                down_traffic: Some(0),
                entry_proto: Some("mixed".to_string()),
                ss_pass: None,
                ..Default::default()
            },
            stale,
            selected: false,
        });
    }
    prepared
}

/// 导入节点并落库。
pub fn import_nodes(
    store: &dyn SubsStore,
    sub_id: &str,
    group: &str,
    sub_name: &str,
    nodes: &[SubParseNode],
    stale: bool,
    update_existing: bool,
) -> NodeBatchResponse {
    let prepared = prepare_nodes(store, sub_id, group, sub_name, nodes, stale);
    store.create_node_batch(prepared, update_existing)
}

fn refresh_result(sub_id: &str, ok: bool, count: i64, error: Option<String>) -> SubRefreshResult {
    SubRefreshResult {
        id: sub_id.to_string(),
        ok,
        count,
        stale: false,
        degraded: false,
        imported: 0,
        updated: 0,
        error,
    }
}

/// 刷新单个订阅：抓取 → 解析 → 导入 → 回写元数据 → 按需重载配置。
///
/// 抓取失败不是灾难：只要还有上次成功的快照，就把已有节点标成 stale 并保留，
/// 这样面板不会因为上游抖动而掉光节点。
pub async fn refresh_sub(
    store: &dyn SubsStore,
    applier: &dyn ConfigApplier,
    fetcher: &dyn SubscriptionFetcher,
    sub: &Subscription,
) -> SubRefreshResult {
    let sub_id = sub.id.clone();
    let fetched = fetcher.fetch(&sub.url).await;
    let content = match fetched {
        FetchResult::Ok { content, .. } => content,
        FetchResult::Err { error, .. } => {
            let snapshot = store
                .get_sub(&sub_id)
                .and_then(|record| record.snapshot)
                .and_then(|snapshot| serde_json::from_str::<Value>(&snapshot).ok());
            if let Some(Value::Array(items)) = snapshot {
                if !items.is_empty() {
                    store.mark_nodes_stale_by_sub(&sub_id);
                    store.update_sub(&sub_id, json!({ "lastError": error.clone() }));
                    return SubRefreshResult {
                        id: sub_id,
                        ok: false,
                        count: items.len() as i64,
                        stale: true,
                        degraded: true,
                        imported: 0,
                        updated: 0,
                        error: Some(error),
                    };
                }
            }
            store.update_sub(&sub_id, json!({ "lastError": error.clone() }));
            return refresh_result(&sub_id, false, 0, Some(error));
        }
    };

    let nodes = parse_content_nodes(&content);
    if nodes.is_empty() {
        let message = "解析 0 个节点";
        let updated = store.update_sub(&sub_id, json!({ "lastError": message }));
        return if updated.is_none() {
            refresh_result(&sub_id, false, 0, Some("订阅已被删除".to_string()))
        } else {
            refresh_result(&sub_id, false, 0, Some(message.to_string()))
        };
    }

    let batch = import_nodes(store, &sub_id, &sub.group, &sub.name, &nodes, false, true);
    store.unmark_nodes_stale_by_sub(&sub_id);

    let current = store
        .get_sub(&sub_id)
        .map(|record| record.sub)
        .unwrap_or_else(|| sub.clone());
    let needs_apply = batch.created > 0 || batch.updated > 0 || current.pending_apply;
    let snapshot =
        serde_json::to_string(&parse_content(&content)).unwrap_or_else(|_| "[]".to_string());
    let updated = store.update_sub(
        &sub_id,
        json!({
            "lastRefresh": now_millis(),
            "nodeCount": nodes.len() as i64,
            "snapshot": snapshot,
            "pendingApply": if needs_apply { 1 } else { 0 },
        }),
    );
    if updated.is_none() {
        return refresh_result(
            &sub_id,
            false,
            0,
            Some("订阅元数据更新失败（已删除）".to_string()),
        );
    }

    let mut apply_error: Option<String> = None;
    if needs_apply {
        match applier.apply().await {
            Ok(applied) => {
                if !applied.get("ok").map(truthy).unwrap_or(false) {
                    let message = applied
                        .get("message")
                        .filter(|value| truthy(value))
                        .map(py_str)
                        .unwrap_or_else(|| "配置应用失败".to_string());
                    apply_error = Some(message);
                }
            }
            Err(message) => {
                apply_error = Some(if message.is_empty() {
                    "配置应用异常".to_string()
                } else {
                    message
                });
            }
        }
    }

    match apply_error {
        Some(error) => {
            store.update_sub(
                &sub_id,
                json!({ "pendingApply": 1, "lastError": format!("配置应用失败: {error}") }),
            );
            SubRefreshResult {
                id: sub_id,
                ok: true,
                count: nodes.len() as i64,
                stale: false,
                degraded: true,
                imported: batch.created,
                updated: batch.updated,
                error: Some(error),
            }
        }
        None => {
            store.update_sub(
                &sub_id,
                json!({ "pendingApply": 0, "lastError": Value::Null }),
            );
            SubRefreshResult {
                id: sub_id,
                ok: true,
                count: nodes.len() as i64,
                stale: false,
                degraded: false,
                imported: batch.created,
                updated: batch.updated,
                error: None,
            }
        }
    }
}

/// 批量刷新；all 为真时忽略 ids，否则只刷给定 id。
pub async fn refresh_subs(
    store: &dyn SubsStore,
    applier: &dyn ConfigApplier,
    fetcher: &dyn SubscriptionFetcher,
    ids: Option<&[String]>,
    all: bool,
) -> Vec<SubRefreshResult> {
    let mut results = Vec::new();
    for record in store.list_subs() {
        if !all {
            if let Some(ids) = ids {
                if !ids.contains(&record.sub.id) {
                    continue;
                }
            }
        }
        if !record.sub.enabled {
            continue;
        }
        results.push(refresh_sub(store, applier, fetcher, &record.sub).await);
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    // ---------- 测试替身 ----------

    #[derive(Default)]
    struct FakeStore {
        subs: Mutex<Vec<SubRecord>>,
        prepared: Mutex<Vec<PreparedNode>>,
        update_existing: Mutex<bool>,
        batch: Mutex<NodeBatchResponse>,
        marked_stale: Mutex<Vec<String>>,
        unmarked_stale: Mutex<Vec<String>>,
        deleted: Mutex<bool>,
        seq: Mutex<i64>,
    }

    impl FakeStore {
        fn with_sub(sub: Subscription, snapshot: Option<String>) -> Self {
            let store = FakeStore::default();
            store.subs.lock().unwrap().push(SubRecord { sub, snapshot });
            *store.batch.lock().unwrap() = NodeBatchResponse {
                created: 1,
                updated: 0,
                skipped: 0,
                duplicate: 0,
                failed: 0,
                items: Vec::new(),
            };
            store
        }

        fn snapshot(&self) -> SubRecord {
            self.subs
                .lock()
                .unwrap()
                .first()
                .cloned()
                .unwrap_or_default()
        }
    }

    impl SubsStore for FakeStore {
        fn create_node_batch(
            &self,
            prepared: Vec<PreparedNode>,
            update_existing: bool,
        ) -> NodeBatchResponse {
            *self.prepared.lock().unwrap() = prepared;
            *self.update_existing.lock().unwrap() = update_existing;
            self.batch.lock().unwrap().clone()
        }

        fn random_auth(&self) -> (String, String) {
            let mut seq = self.seq.lock().unwrap();
            *seq += 1;
            (format!("user-{seq}"), format!("pass-{seq}"))
        }

        fn get_sub(&self, id: &str) -> Option<SubRecord> {
            self.subs
                .lock()
                .unwrap()
                .iter()
                .find(|record| record.sub.id == id)
                .cloned()
        }

        fn update_sub(&self, id: &str, patch: Value) -> Option<SubRecord> {
            if *self.deleted.lock().unwrap() {
                return None;
            }
            let mut subs = self.subs.lock().unwrap();
            let record = subs.iter_mut().find(|record| record.sub.id == id)?;
            apply_patch(record, &patch);
            Some(record.clone())
        }

        fn list_subs(&self) -> Vec<SubRecord> {
            self.subs.lock().unwrap().clone()
        }

        fn mark_nodes_stale_by_sub(&self, id: &str) {
            self.marked_stale.lock().unwrap().push(id.to_string());
        }

        fn unmark_nodes_stale_by_sub(&self, id: &str) {
            self.unmarked_stale.lock().unwrap().push(id.to_string());
        }
    }

    fn apply_patch(record: &mut SubRecord, patch: &Value) {
        let Some(map) = patch.as_object() else { return };
        for (key, value) in map {
            match key.as_str() {
                "lastError" => {
                    record.sub.last_error = if value.is_null() {
                        None
                    } else {
                        Some(py_str(value))
                    }
                }
                "pendingApply" => record.sub.pending_apply = truthy(value),
                "nodeCount" => record.sub.node_count = py_int_value(value).unwrap_or(0),
                "lastRefresh" => record.sub.last_refresh = py_int_value(value),
                "snapshot" => record.snapshot = Some(py_str(value)),
                "stale" => record.sub.stale = truthy(value),
                _ => {}
            }
        }
    }

    struct FakeFetcher {
        results: Mutex<VecDeque<FetchResult>>,
        urls: Mutex<Vec<String>>,
    }

    impl FakeFetcher {
        fn ok(content: &str) -> Self {
            FakeFetcher::queue(vec![FetchResult::Ok {
                status: 200,
                content: content.to_string(),
            }])
        }

        fn queue(results: Vec<FetchResult>) -> Self {
            FakeFetcher {
                results: Mutex::new(results.into()),
                urls: Mutex::new(Vec::new()),
            }
        }
    }

    impl SubscriptionFetcher for FakeFetcher {
        fn fetch<'a>(&'a self, url: &'a str) -> BoxFut<'a, FetchResult> {
            self.urls.lock().unwrap().push(url.to_string());
            let result = self.results.lock().unwrap().pop_front();
            Box::pin(async move {
                result.unwrap_or(FetchResult::Err {
                    status: None,
                    error: "fake done".into(),
                })
            })
        }
    }

    struct FakeApplier {
        result: Mutex<Result<Value, String>>,
        calls: Mutex<i64>,
    }

    impl FakeApplier {
        fn ok() -> Self {
            FakeApplier {
                result: Mutex::new(Ok(json!({ "ok": true }))),
                calls: Mutex::new(0),
            }
        }
        fn reply(value: Value) -> Self {
            FakeApplier {
                result: Mutex::new(Ok(value)),
                calls: Mutex::new(0),
            }
        }
        fn fails(message: &str) -> Self {
            FakeApplier {
                result: Mutex::new(Err(message.to_string())),
                calls: Mutex::new(0),
            }
        }
    }

    impl ConfigApplier for FakeApplier {
        fn apply<'a>(&'a self) -> BoxFut<'a, Result<Value, String>> {
            *self.calls.lock().unwrap() += 1;
            let result = self.result.lock().unwrap().clone();
            Box::pin(async move { result })
        }
    }

    fn sub_record(id: &str) -> Subscription {
        Subscription {
            id: id.to_string(),
            url: "https://sub.example.com/x".to_string(),
            name: "我的订阅".to_string(),
            group: "订阅节点".to_string(),
            enabled: true,
            ..Default::default()
        }
    }

    fn config(node: &SubParseNode) -> &Map<String, Value> {
        node.raw_config.as_object().expect("rawConfig 必须是对象")
    }

    // ---------- 单链接解析 ----------

    #[test]
    fn parse_ss_sip002_base64_credentials() {
        let cred = B64.encode("chacha20-ietf-poly1305:pw-123");
        let link = format!("ss://{}@s1.example.com:8388#香港%2001", cred);
        let node = parse_link(&link).expect("SIP002 链接应可解析");
        assert_eq!(node.protocol, "shadowsocks");
        assert_eq!(node.name, "香港 01");
        assert_eq!(config(&node)["server"], json!("s1.example.com"));
        assert_eq!(config(&node)["server_port"], json!(8388));
        assert_eq!(config(&node)["method"], json!("chacha20-ietf-poly1305"));
        assert_eq!(config(&node)["password"], json!("pw-123"));
    }

    #[test]
    fn parse_ss_sip002_plain_credentials() {
        let link = "ss://chacha20-ietf-poly1305:p%40ss@s1.example.com:8388";
        let node = parse_link(link).expect("明文凭据也应支持");
        assert_eq!(config(&node)["password"], json!("p%40ss"));
        assert_eq!(node.name, "ss-s1.example.com");
    }

    #[test]
    fn parse_ss_legacy_base64_body() {
        let body = B64.encode("aes-256-cfb:pw@s2.example.com:8388");
        let node = parse_link(&format!("ss://{body}")).expect("legacy ss 应可解析");
        assert_eq!(config(&node)["server"], json!("s2.example.com"));
        assert_eq!(config(&node)["server_port"], json!(8388));
        assert_eq!(node.name, "ss-s2.example.com");
    }

    #[test]
    fn parse_ss_legacy_uses_fragment_as_name() {
        let inner = format!(
            "aes-256-cfb:pw@s3.example.com:8388#{}",
            unquote("%E6%97%A5%E6%9C%AC")
        );
        let node =
            parse_link(&format!("ss://{}", B64.encode(inner))).expect("带 fragment 的 legacy ss");
        assert_eq!(node.name, "日本");
    }

    #[test]
    fn parse_vmess_json_payload() {
        let payload = json!({
            "v": "2", "ps": "VM 节点", "add": "v.example.com", "port": "443",
            "id": "uuid-1", "aid": "0", "net": "ws", "path": "/v", "host": "h.example.com",
            "tls": "tls", "sni": "s.example.com", "allowInsecure": "1", "fp": "chrome"
        });
        let node =
            parse_link(&format!("vmess://{}", B64.encode(payload.to_string()))).expect("vmess");
        assert_eq!(node.protocol, "vmess");
        assert_eq!(node.name, "VM 节点");
        let raw = config(&node);
        assert_eq!(raw["server"], json!("v.example.com"));
        assert_eq!(raw["server_port"], json!(443));
        assert_eq!(raw["uuid"], json!("uuid-1"));
        assert_eq!(raw["method"], json!("auto"));
        assert_eq!(raw["alterId"], json!("0"), "aid 原样透传");
        assert_eq!(raw["tls"]["enabled"], json!(true));
        assert_eq!(raw["tls"]["server_name"], json!("s.example.com"));
        assert_eq!(raw["tls"]["insecure"], json!(true));
        assert_eq!(raw["tls"]["utls"]["fingerprint"], json!("chrome"));
        assert_eq!(raw["transport"]["type"], json!("ws"));
        assert_eq!(raw["transport"]["path"], json!("/v"));
        assert_eq!(raw["transport"]["headers"]["Host"], json!("h.example.com"));
    }

    #[test]
    fn parse_vmess_falls_back_to_add_name_and_skips_tcp_transport() {
        let payload = json!({ "add": "v2.example.com", "port": 443, "id": "u2", "net": "tcp" });
        let node =
            parse_link(&format!("vmess://{}", B64.encode(payload.to_string()))).expect("vmess");
        assert_eq!(node.name, "vmess-v2.example.com");
        assert!(config(&node).get("transport").is_none());
    }

    #[test]
    fn parse_vless_reality_and_grpc() {
        let link = "vless://uuid-9@v4.example.com:443?security=reality&pbk=PUBKEY&sid=abcd&fp=chrome&sni=sni.example.com&type=grpc&serviceName=svc&flow=xtls-rprx-vision#VLESS";
        let node = parse_link(link).expect("vless");
        assert_eq!(node.protocol, "vless");
        assert_eq!(node.name, "VLESS");
        let raw = config(&node);
        assert_eq!(raw["uuid"], json!("uuid-9"));
        assert_eq!(raw["flow"], json!("xtls-rprx-vision"));
        assert_eq!(raw["tls"]["enabled"], json!(true));
        assert_eq!(raw["tls"]["server_name"], json!("sni.example.com"));
        assert_eq!(raw["tls"]["reality"]["public_key"], json!("PUBKEY"));
        assert_eq!(raw["tls"]["reality"]["short_id"], json!("abcd"));
        assert_eq!(raw["tls"]["utls"]["fingerprint"], json!("chrome"));
        assert_eq!(raw["transport"]["type"], json!("grpc"));
        assert_eq!(raw["transport"]["service_name"], json!("svc"));
    }

    #[test]
    fn parse_vless_ws_transport_puts_host_into_headers() {
        let link = "vless://u@v5.example.com:443?type=ws&path=%2Fws&host=cdn.example.com&alpn=h2,http%2F1.1";
        let node = parse_link(link).expect("vless ws");
        let raw = config(&node);
        assert_eq!(raw["transport"]["type"], json!("ws"));
        assert_eq!(raw["transport"]["path"], json!("/ws"));
        assert_eq!(
            raw["transport"]["headers"]["Host"],
            json!("cdn.example.com")
        );
        assert_eq!(raw["tls"]["alpn"], json!(["h2", "http/1.1"]));
        assert_eq!(node.name, "vless-v5.example.com");
    }

    #[test]
    fn parse_trojan_basic() {
        let node =
            parse_link("trojan://pw@t.example.com:443?sni=t.example.com&allowInsecure=yes#TJ")
                .expect("trojan");
        assert_eq!(node.protocol, "trojan");
        assert_eq!(node.name, "TJ");
        let raw = config(&node);
        assert_eq!(raw["password"], json!("pw"));
        assert_eq!(raw["tls"]["server_name"], json!("t.example.com"));
        assert_eq!(raw["tls"]["insecure"], json!(true));
    }

    #[test]
    fn parse_hysteria2_with_obfs() {
        let link = "hysteria2://pw@hy.example.com:443?sni=hy.example.com&insecure=1&obfs=salamander&obfs-password=op#HY2";
        let node = parse_link(link).expect("hysteria2");
        assert_eq!(node.protocol, "hysteria2");
        assert_eq!(node.name, "HY2");
        let raw = config(&node);
        assert_eq!(raw["server"], json!("hy.example.com"));
        assert_eq!(raw["server_port"], json!(443));
        assert_eq!(raw["password"], json!("pw"));
        assert_eq!(raw["sni"], json!("hy.example.com"));
        assert_eq!(raw["insecure"], json!(true));
        assert_eq!(raw["obfs"], json!("salamander"));
        assert_eq!(raw["obfsPassword"], json!("op"));
    }

    #[test]
    fn parse_tuic_uuid_and_password() {
        let node = parse_link("tuic://uuid-7:pw-7@tu.example.com:8443?sni=tu.example.com#TUIC")
            .expect("tuic");
        assert_eq!(node.protocol, "tuic");
        let raw = config(&node);
        assert_eq!(raw["uuid"], json!("uuid-7"));
        assert_eq!(raw["password"], json!("pw-7"));
        assert_eq!(raw["sni"], json!("tu.example.com"));
        assert_eq!(raw["server_port"], json!(8443));
    }

    #[test]
    fn parse_ssr_base64_body() {
        let password = B64.encode("pw-ssr");
        let body = format!("ssr.example.com:8388:origin:aes-256-cfb:plain:{password}/?remarks=x");
        let node = parse_link(&format!("ssr://{}", B64.encode(body))).expect("ssr");
        assert_eq!(node.protocol, "ssr");
        assert_eq!(node.name, "ssr-ssr.example.com");
        let raw = config(&node);
        assert_eq!(raw["server_port"], json!(8388));
        assert_eq!(raw["protocol"], json!("origin"));
        assert_eq!(raw["method"], json!("aes-256-cfb"));
        assert_eq!(raw["obfs"], json!("plain"));
        assert_eq!(raw["password"], json!("pw-ssr"));
    }

    #[test]
    fn parse_socks5_and_http_links() {
        let socks = parse_link("socks5://user:pa%40ss@so.example.com:1080#S5").expect("socks5");
        assert_eq!(socks.protocol, "socks5");
        assert_eq!(config(&socks)["username"], json!("user"));
        assert_eq!(config(&socks)["password"], json!("pa%40ss"));
        assert_eq!(socks.name, "S5");

        let http = parse_link("http://ht.example.com:8080").expect("http");
        assert_eq!(http.protocol, "http");
        assert_eq!(http.name, "http-ht.example.com");
        assert!(config(&http).get("username").is_none());
    }

    #[test]
    fn unknown_or_malformed_links_never_panic() {
        assert!(parse_link("").is_none());
        assert!(parse_link("   ").is_none());
        assert!(parse_link("# 只是注释").is_none());
        assert!(parse_link("ftp://x.example.com:21").is_none());
        assert!(parse_link("hysteria://old.example.com:443").is_none());
        assert!(parse_link("ss://short").is_none());
        assert!(parse_link("ssr://not-base64!!").is_none());
        assert!(parse_link("vmess://").is_none());
        assert!(parse_link("vmess://bm90LWpzb24").is_none());
        assert!(parse_link("socks5://no-port").is_none());
        assert!(parse_link("tuic://missing-port").is_none());
        assert!(parse_link("hysteria2://still-bad").is_none());
        assert!(parse_link("trojan://pw@host:not-a-port").is_none());
        assert!(parse_link("ss://%%%@host:99999").is_none());
    }

    // ---------- 端点规范化 ----------

    #[test]
    fn proxy_endpoint_reads_raw_config() {
        let node = json!({
            "name": "s5",
            "rawConfig": { "server": "1.2.3.4", "server_port": "1080", "username": "u", "password": "p" }
        });
        let endpoint = proxy_endpoint(&node).expect("端点");
        assert_eq!(endpoint.host, "1.2.3.4");
        assert_eq!(endpoint.port, 1080);
        assert_eq!(endpoint.username.as_deref(), Some("u"));
        assert_eq!(endpoint.password.as_deref(), Some("p"));
    }

    #[test]
    fn proxy_endpoint_falls_back_to_uri_and_rejects_bad_ports() {
        let node = json!({ "rawConfig": { "uri": "socks5://u:p@5.6.7.8:1080" } });
        let endpoint = proxy_endpoint(&node).expect("回落解析 uri");
        assert_eq!(endpoint.host, "5.6.7.8");
        assert_eq!(endpoint.port, 1080);

        let bad = json!({ "rawConfig": { "server": "9.9.9.9", "server_port": 70000 } });
        assert!(proxy_endpoint(&bad).is_none());
        assert!(proxy_endpoint(&json!({})).is_none());
    }

    // ---------- 内容嗅探 ----------

    #[test]
    fn detect_type_covers_all_shapes() {
        assert_eq!(detect_type(r#"{"outbounds": []}"#), TYPE_JSON);
        assert_eq!(detect_type("  [ {} ]"), TYPE_JSON);
        assert_eq!(
            detect_type("proxies:\n  - name: a\n    type: ss"),
            TYPE_CLASH
        );
        assert_eq!(detect_type("port: 7890\nproxies:\n- name: a"), TYPE_CLASH);
        assert_eq!(detect_type("socks5://h:1080\nhttp://h:8080"), TYPE_URLLIST);
        assert_eq!(detect_type("vmess://abc"), TYPE_URLLIST);
        let long_b64 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2";
        assert_eq!(detect_type(long_b64), TYPE_B64);
        assert_eq!(detect_type("hello world"), TYPE_UNKNOWN);
        assert_eq!(detect_type(""), TYPE_UNKNOWN);
    }

    #[test]
    fn parse_content_dispatches_by_type() {
        let list = "socks5://u:p@a.example.com:1080#A\nhttp://b.example.com:8080#B\nftp://ignored";
        let nodes = parse_content_nodes(list);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].protocol, "socks5");
        assert_eq!(nodes[1].protocol, "http");

        let encoded = B64.encode("socks5://u:p@c.example.com:1080#C");
        let decoded_nodes = parse_content_nodes(&encoded);
        assert_eq!(decoded_nodes.len(), 1);
        assert_eq!(decoded_nodes[0].name, "C");

        let values = parse_content(list);
        assert_eq!(values.len(), 2);
        assert_eq!(values[0]["protocol"], json!("socks5"));
        assert!(values[0]["rawConfig"].is_object());
        assert!(parse_content("完全无法识别的内容").is_empty());
    }

    // ---------- Clash YAML ----------

    const CLASH_SAMPLE: &str = "port: 7890\n\
proxies:\n\
\x20 - name: ws-vmess\n\
\x20   type: vmess\n\
\x20   server: ws.example.com\n\
\x20   port: '443'\n\
\x20   uuid: uu-1\n\
\x20   tls: true\n\
\x20   sni: sni.example.com\n\
\x20   network: ws\n\
\x20   ws-opts:\n\
\x20     path: /ray\n\
\x20     headers:\n\
\x20       Host: cdn.example.com\n\
\x20 - name: grpc-trojan\n\
\x20   type: trojan\n\
\x20   server: grpc.example.com\n\
\x20   port: 443\n\
\x20   password: pw\n\
\x20   skip-cert-verify: true\n\
\x20   reality-opts:\n\
\x20     public-key: PK-1\n\
\x20     short-id: sid-1\n\
\x20   network: grpc\n\
\x20   grpc-opts:\n\
\x20     service_name: svc-grpc\n\
\x20 - name: weird\n\
\x20   type: made-up\n\
\x20   server: x.example.com\n\
\x20   port: 1\n";

    #[test]
    fn parse_clash_yaml_nodes() {
        let nodes = parse_clash_yaml(CLASH_SAMPLE);
        assert_eq!(nodes.len(), 2, "未知 type 必须跳过");
        assert_eq!(nodes[0].name, "ws-vmess");
        assert_eq!(nodes[0].protocol, "vmess");
        let first = config(&nodes[0]);
        assert_eq!(first["port"], json!(443), "字符串端口应转整数");
        assert_eq!(first["tls"]["enabled"], json!(true));
        assert_eq!(first["tls"]["server_name"], json!("sni.example.com"));
        assert_eq!(first["transport"]["type"], json!("ws"));
        assert_eq!(first["transport"]["path"], json!("/ray"));
        assert_eq!(
            first["transport"]["headers"]["Host"],
            json!("cdn.example.com")
        );
        assert!(first.get("ws-opts").is_some(), "opts 子块保留在原始配置里");

        assert_eq!(nodes[1].protocol, "trojan");
        let second = config(&nodes[1]);
        assert_eq!(second["tls"]["insecure"], json!(true));
        assert_eq!(second["tls"]["reality"]["public_key"], json!("PK-1"));
        assert_eq!(second["tls"]["reality"]["short_id"], json!("sid-1"));
        assert_eq!(second["tls"]["utls"]["fingerprint"], json!("chrome"));
        assert_eq!(second["transport"]["type"], json!("grpc"));
        assert_eq!(second["transport"]["service_name"], json!("svc-grpc"));
    }

    #[test]
    fn parse_clash_yaml_without_proxies_key_is_empty() {
        assert!(parse_clash_yaml("port: 7890\nmode: rule").is_empty());
        assert!(parse_clash_yaml("").is_empty());
    }

    #[test]
    fn clash_skips_node_missing_name_or_type() {
        let content = "proxies:\n  - type: ss\n    server: a\n  - name: ok\n    type: ss\n    server: b\n    port: 1\n";
        let nodes = parse_clash_yaml(content);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "ok");
    }

    // ---------- JSON ----------

    #[test]
    fn parse_json_outbounds() {
        let content = json!({
            "outbounds": [
                { "type": "vless", "tag": "sub-v1", "server": "sub.a.com", "server_port": 443, "uuid": "u111" },
                { "type": "shadowsocks", "tag": "sub-s1", "server": "sub.b.com", "server_port": 8388, "method": "aes-256-gcm", "password": "p222" },
                { "type": "direct", "tag": "direct" }
            ]
        })
        .to_string();
        let nodes = parse_json_content(&content);
        assert_eq!(nodes.len(), 2, "未知协议应跳过");
        assert_eq!(nodes[0].protocol, "vless");
        assert_eq!(nodes[0].name, "sub.a.com:443");
        assert_eq!(nodes[1].protocol, "ss");
        assert_eq!(config(&nodes[1])["method"], json!("aes-256-gcm"));
        assert!(config(&nodes[1]).get("name").is_none(), "name 已提到外层");
    }

    #[test]
    fn parse_json_flat_list_and_proxies_key() {
        let flat = json!([
            { "type": "trojan", "remark": "TJ", "server": "t.com", "server_port": 443, "password": "pw" },
            { "type": "vmess", "ps": "VM", "server": "v.com", "port": 80, "uuid": "u" }
        ])
        .to_string();
        let nodes = parse_json_content(&flat);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "TJ");
        assert_eq!(nodes[1].name, "VM");

        let wrapped = json!({ "proxies": [ { "type": "tuic", "server": "tu.com", "server_port": 443, "uuid": "u", "password": "p" } ] })
            .to_string();
        assert_eq!(parse_json_content(&wrapped).len(), 1);
        assert!(parse_json_content(r#"{"log": {}}"#).is_empty());
        assert!(parse_json_content("not json").is_empty());
    }

    // ---------- 导入与刷新 ----------

    #[test]
    fn prepare_nodes_fills_defaults() {
        let store = FakeStore::with_sub(sub_record("s1"), None);
        let parsed = vec![
            SubParseNode {
                name: String::new(),
                protocol: String::new(),
                raw_config: json!({"server": "a"}),
            },
            SubParseNode {
                name: "有名字".into(),
                protocol: "trojan".into(),
                raw_config: json!({"server": "b"}),
            },
        ];
        let prepared = prepare_nodes(&store, "s1", "订阅节点", "主订阅", &parsed, true);
        assert_eq!(prepared.len(), 2);
        assert_eq!(prepared[0].node.name, "未命名");
        assert_eq!(prepared[0].node.protocol, "shadowsocks");
        assert_eq!(prepared[0].node.port, Some(0), "端口交给批内统一分配");
        assert_eq!(prepared[0].node.segment, Some(52));
        assert_eq!(prepared[0].node.group.as_deref(), Some("订阅节点"));
        assert_eq!(prepared[0].node.sub_id.as_deref(), Some("s1"));
        assert_eq!(prepared[0].node.sub_name.as_deref(), Some("主订阅"));
        assert_eq!(prepared[0].node.entry_proto.as_deref(), Some("mixed"));
        assert_eq!(prepared[0].node.status.as_deref(), Some("offline"));
        assert_eq!(prepared[0].node.exit_ip.as_deref(), Some("N/A"));
        assert!(prepared[0].stale);
        assert!(!prepared[0].selected);
        assert_eq!(prepared[1].node.name, "有名字");
        assert_eq!(prepared[1].node.protocol, "trojan");
    }

    #[tokio::test]
    async fn refresh_sub_imports_and_applies_config() {
        let store = FakeStore::with_sub(sub_record("s1"), None);
        let fetcher =
            FakeFetcher::ok("socks5://u:p@a.example.com:1080#A\nhttp://b.example.com:8080#B");
        let applier = FakeApplier::ok();
        let result = refresh_sub(&store, &applier, &fetcher, &sub_record("s1")).await;
        assert!(result.ok);
        assert_eq!(result.count, 2);
        assert_eq!(result.imported, 1);
        assert!(!result.degraded);
        assert_eq!(result.error, None);
        assert_eq!(
            *applier.calls.lock().unwrap(),
            1,
            "有新节点必须触发配置应用"
        );
        let snapshot = store.snapshot();
        assert_eq!(snapshot.sub.node_count, 2);
        assert!(!snapshot.sub.pending_apply);
        assert_eq!(snapshot.sub.last_error, None);
        assert!(snapshot.sub.last_refresh.is_some());
        assert!(snapshot.snapshot.expect("快照落库").contains("socks5"));
    }

    #[tokio::test]
    async fn refresh_sub_zero_nodes_reports_parse_error() {
        let store = FakeStore::with_sub(sub_record("s1"), None);
        let fetcher = FakeFetcher::ok("完全无法识别");
        let applier = FakeApplier::ok();
        let result = refresh_sub(&store, &applier, &fetcher, &sub_record("s1")).await;
        assert!(!result.ok);
        assert_eq!(result.count, 0);
        assert_eq!(result.error.as_deref(), Some("解析 0 个节点"));
        assert_eq!(
            store.snapshot().sub.last_error.as_deref(),
            Some("解析 0 个节点")
        );
        assert_eq!(*applier.calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn refresh_sub_deleted_subscription_reports_deleted() {
        let store = FakeStore::with_sub(sub_record("s1"), None);
        *store.deleted.lock().unwrap() = true;
        let fetcher = FakeFetcher::ok("完全无法识别");
        let applier = FakeApplier::ok();
        let result = refresh_sub(&store, &applier, &fetcher, &sub_record("s1")).await;
        assert!(!result.ok);
        assert_eq!(result.error.as_deref(), Some("订阅已被删除"));
    }

    #[tokio::test]
    async fn refresh_sub_keeps_nodes_when_fetch_fails_with_snapshot() {
        let snapshot = json!([{ "name": "A", "protocol": "socks5", "rawConfig": {} }]).to_string();
        let store = FakeStore::with_sub(sub_record("s1"), Some(snapshot));
        let fetcher = FakeFetcher::queue(vec![FetchResult::Err {
            status: Some(500),
            error: "HTTP 500".into(),
        }]);
        let applier = FakeApplier::ok();
        let result = refresh_sub(&store, &applier, &fetcher, &sub_record("s1")).await;
        assert!(!result.ok);
        assert!(result.stale, "有快照时旧节点应标 stale");
        assert!(result.degraded);
        assert_eq!(result.count, 1);
        assert_eq!(result.error.as_deref(), Some("HTTP 500"));
        assert_eq!(
            store.marked_stale.lock().unwrap().as_slice(),
            ["s1".to_string()]
        );
        assert_eq!(store.snapshot().sub.last_error.as_deref(), Some("HTTP 500"));
    }

    #[tokio::test]
    async fn refresh_sub_fetch_fail_without_snapshot_is_plain_failure() {
        let store = FakeStore::with_sub(sub_record("s1"), None);
        let fetcher = FakeFetcher::queue(vec![FetchResult::Err {
            status: None,
            error: "订阅请求超时".into(),
        }]);
        let applier = FakeApplier::ok();
        let result = refresh_sub(&store, &applier, &fetcher, &sub_record("s1")).await;
        assert!(!result.ok);
        assert!(!result.stale);
        assert!(!result.degraded);
        assert_eq!(result.count, 0);
        assert_eq!(result.error.as_deref(), Some("订阅请求超时"));
        assert!(store.marked_stale.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn refresh_sub_marks_degraded_when_apply_fails() {
        let store = FakeStore::with_sub(sub_record("s1"), None);
        let fetcher = FakeFetcher::ok("socks5://u:p@a.example.com:1080#A");
        let applier = FakeApplier::reply(json!({ "ok": false, "message": "sing-box 未运行" }));
        let result = refresh_sub(&store, &applier, &fetcher, &sub_record("s1")).await;
        assert!(result.ok);
        assert_eq!(result.count, 1);
        assert!(result.degraded);
        assert_eq!(result.error.as_deref(), Some("sing-box 未运行"));
        let record = store.snapshot();
        assert!(record.sub.pending_apply, "应用失败必须持久化 pendingApply");
        assert_eq!(
            record.sub.last_error.as_deref(),
            Some("配置应用失败: sing-box 未运行")
        );
    }

    #[tokio::test]
    async fn refresh_sub_marks_degraded_when_apply_raises() {
        let store = FakeStore::with_sub(sub_record("s1"), None);
        let fetcher = FakeFetcher::ok("socks5://u:p@a.example.com:1080#A");
        let applier = FakeApplier::fails("io 异常");
        let result = refresh_sub(&store, &applier, &fetcher, &sub_record("s1")).await;
        assert!(result.degraded);
        assert_eq!(result.error.as_deref(), Some("io 异常"));
        assert!(store.snapshot().sub.pending_apply);
    }

    #[tokio::test]
    async fn refresh_sub_without_changes_skips_apply() {
        let store = FakeStore::with_sub(sub_record("s1"), None);
        *store.batch.lock().unwrap() = NodeBatchResponse {
            created: 0,
            updated: 0,
            ..Default::default()
        };
        let fetcher = FakeFetcher::ok("socks5://u:p@a.example.com:1080#A");
        let applier = FakeApplier::ok();
        let result = refresh_sub(&store, &applier, &fetcher, &sub_record("s1")).await;
        assert!(result.ok);
        assert_eq!(*applier.calls.lock().unwrap(), 0, "无变化不重载配置");
        assert_eq!(
            store.unmarked_stale.lock().unwrap().as_slice(),
            ["s1".to_string()]
        );
        assert!(!store.snapshot().sub.pending_apply);
    }

    #[tokio::test]
    async fn refresh_subs_respects_ids_and_enabled() {
        let store = FakeStore::default();
        {
            let mut subs = store.subs.lock().unwrap();
            subs.push(SubRecord {
                sub: sub_record("s1"),
                snapshot: None,
            });
            subs.push(SubRecord {
                sub: sub_record("s2"),
                snapshot: None,
            });
            let mut disabled = sub_record("s3");
            disabled.enabled = false;
            subs.push(SubRecord {
                sub: disabled,
                snapshot: None,
            });
        }
        *store.batch.lock().unwrap() = NodeBatchResponse {
            created: 1,
            ..Default::default()
        };
        let fetcher = FakeFetcher::queue(vec![
            FetchResult::Ok {
                status: 200,
                content: "http://a.example.com:8080#A".into(),
            },
            FetchResult::Ok {
                status: 200,
                content: "http://b.example.com:8080#B".into(),
            },
            FetchResult::Ok {
                status: 200,
                content: "http://c.example.com:8080#C".into(),
            },
        ]);
        let applier = FakeApplier::ok();
        let all = refresh_subs(&store, &applier, &fetcher, None, true).await;
        assert_eq!(all.len(), 2, "disabled 订阅跳过");
        assert_eq!(all[0].id, "s1");
        assert_eq!(all[1].id, "s2");

        let filtered =
            refresh_subs(&store, &applier, &fetcher, Some(&["s2".to_string()]), false).await;
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "s2");
        assert_eq!(fetcher.urls.lock().unwrap().len(), 3, "只抓取被选中的订阅");
    }

    // ---------- 仓库样例冒烟 ----------

    #[test]
    fn smoke_parse_repo_test_sub_json() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-sub.json");
        let Ok(content) = std::fs::read_to_string(path) else {
            eprintln!("跳过：{path} 不存在");
            return;
        };
        let nodes = parse_content(&content);
        assert_eq!(nodes.len(), 3, "test-sub.json 应解析出 3 个节点");
        let protocols: Vec<&str> = nodes
            .iter()
            .map(|node| node["protocol"].as_str().unwrap_or(""))
            .collect();
        assert_eq!(protocols, ["vless", "ss", "vmess"]);
        assert_eq!(nodes[0]["rawConfig"]["server"], json!("sub.a.com"));
        assert_eq!(nodes[1]["rawConfig"]["method"], json!("aes-256-gcm"));
        assert_eq!(nodes[2]["rawConfig"]["server_port"], json!(43754));
        for node in &nodes {
            assert!(node["rawConfig"].is_object());
            assert!(!node["name"].as_str().unwrap_or("").is_empty());
        }
        println!("支持协议清单冒烟：{protocols:?}");
    }
}
