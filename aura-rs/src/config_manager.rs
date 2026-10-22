//! sing-box 配置生成。
//!
//! 迁移进度：本文件先落地与 DB 无关的纯函数层（TLS / transport 归一化），
//! 与 backend/config_manager.py:66-143 逐行对齐。build_config / apply / 进程管理等
//! 依赖 db.rs 与 netguard.rs 的部分待那两个模块交付后补齐。

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

/// 前端 protocol 值 → sing-box outbound type；None = 不支持（跳过）
pub fn protocol_type_map(protocol: &str) -> Option<&'static str> {
    match protocol {
        "shadowsocks" | "ss" => Some("shadowsocks"),
        "vmess" => Some("vmess"),
        "vless" => Some("vless"),
        "trojan" => Some("trojan"),
        "hysteria2" => Some("hysteria2"),
        "tuic" => Some("tuic"),
        "wireguard" => Some("wireguard"),
        "socks" | "socks5" => Some("socks"),
        "http" | "https" => Some("http"),
        "ssr" => None, // sing-box >=1.6 已移除 ShadowsocksR
        _ => None,
    }
}

/// 类型安全地取 tls 配置。clash YAML 把 tls: true 存成字符串 "true"，
/// JSON 可能存 bool，必须兼容。返回启用时的 tls dict，否则 None。
pub fn tls_enabled_dict(cfg: &Value) -> Option<Value> {
    let tls = cfg.get("tls")?;
    match tls {
        Value::Object(o) => {
            if o.get("enabled").map(is_truthy).unwrap_or(false) {
                Some(tls.clone())
            } else {
                None
            }
        }
        Value::String(s) => {
            if s.eq_ignore_ascii_case("true") {
                Some(json!({ "enabled": true }))
            } else {
                None
            }
        }
        Value::Bool(b) => {
            if *b {
                Some(json!({ "enabled": true }))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// JSON 值的 Python 真值语义（None/False/0/""/[]/{} 为假）
pub fn is_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

const KNOWN_TRANSPORTS: [&str; 4] = ["ws", "http", "grpc", "httpupgrade"];

fn map_transport_type(t: &str) -> &str {
    match t {
        "h2" | "h2c" => "http",
        "httpupgrade" => "httpupgrade",
        other => other,
    }
}

/// transport 规范化：sing-box V2RayTransportOptions 必须是对象。
///
/// 老订阅节点 DB 里可能存字符串（如 "ws"），直接透传会让 check 失败
/// （json: cannot unmarshal string into ... transport）。字符串 → {type: str}。
/// tcp 是 sing-box 默认传输层，不生成 transport 字段（枚举无 tcp）。
/// 类型映射：h2→http（sing-box 无 h2，HTTP/2 由 http 类型承载）。
/// v2ray streamSettings 嵌套结构也在此转换。
/// 未知/不支持类型（kcp/quic/mkcp 等 sing-box 1.7.7 不支持）静默丢弃。
pub fn normalize_transport(tr: &Value) -> Option<Value> {
    match tr {
        Value::Object(m) => {
            if m.contains_key("network") {
                return match v2ray_stream_to_transport(tr) {
                    Some(mapped) => {
                        let t = mapped.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        if KNOWN_TRANSPORTS.contains(&t) {
                            Some(mapped)
                        } else {
                            None
                        }
                    }
                    None => None,
                };
            }
            let t = m
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if t.is_empty() || t == "tcp" {
                return None;
            }
            let mapped = map_transport_type(&t).to_string();
            if !KNOWN_TRANSPORTS.contains(&mapped.as_str()) {
                return None;
            }
            let mut out: Map<String, Value> = m.clone();
            out.insert("type".into(), Value::String(mapped));
            Some(Value::Object(out))
        }
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() || t == "tcp" {
                return None;
            }
            let mapped = map_transport_type(t);
            if !KNOWN_TRANSPORTS.contains(&mapped) {
                return None;
            }
            Some(json!({ "type": mapped }))
        }
        _ => None,
    }
}

/// v2ray streamSettings → sing-box V2RayTransportOptions
pub fn v2ray_stream_to_transport(stream: &Value) -> Option<Value> {
    let network = stream
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if network.is_empty() || network == "tcp" {
        return None;
    }
    let stype = match network.as_str() {
        "h2" => "http",
        "ws" => "ws",
        "grpc" => "grpc",
        "httpupgrade" => "httpupgrade",
        other => other,
    };
    let mut result = Map::new();
    result.insert("type".into(), Value::String(stype.to_string()));

    if let Some(ws) = stream.get("wsSettings").filter(|v| v.is_object()) {
        if let Some(p) = ws.get("path").filter(|v| is_truthy(v)) {
            result.insert("path".into(), p.clone());
        }
        if let Some(h) = ws.get("headers").filter(|v| v.is_object()) {
            result.insert("headers".into(), h.clone());
        }
    }
    if let Some(grpc) = stream.get("grpcSettings").filter(|v| v.is_object()) {
        if let Some(sn) = grpc.get("serviceName").filter(|v| is_truthy(v)) {
            result.insert("service_name".into(), sn.clone());
        }
    }
    if let Some(hs) = stream.get("httpSettings").filter(|v| v.is_object()) {
        if let Some(p) = hs.get("path").filter(|v| is_truthy(v)) {
            result.insert("path".into(), p.clone());
        }
        if let Some(host) = hs.get("host") {
            if host.is_array() && is_truthy(host) {
                result.insert("host".into(), host.clone());
            }
        }
    }
    if result
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .is_empty()
    {
        return None;
    }
    Some(Value::Object(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_map_matches_python() {
        assert_eq!(protocol_type_map("ss"), Some("shadowsocks"));
        assert_eq!(protocol_type_map("socks5"), Some("socks"));
        assert_eq!(protocol_type_map("https"), Some("http"));
        assert_eq!(protocol_type_map("ssr"), None);
        assert_eq!(protocol_type_map("unknown"), None);
    }

    #[test]
    fn tls_dict_accepts_bool_string_and_object() {
        assert_eq!(
            tls_enabled_dict(&json!({"tls": true})),
            Some(json!({"enabled": true}))
        );
        assert_eq!(
            tls_enabled_dict(&json!({"tls": "true"})),
            Some(json!({"enabled": true}))
        );
        assert_eq!(
            tls_enabled_dict(&json!({"tls": "TRUE"})),
            Some(json!({"enabled": true}))
        );
        assert_eq!(tls_enabled_dict(&json!({"tls": false})), None);
        assert_eq!(tls_enabled_dict(&json!({"tls": "false"})), None);
        assert_eq!(tls_enabled_dict(&json!({})), None);
        let obj = json!({"tls": {"enabled": true, "server_name": "a.com"}});
        assert_eq!(
            tls_enabled_dict(&obj),
            Some(json!({"enabled": true, "server_name": "a.com"}))
        );
        assert_eq!(tls_enabled_dict(&json!({"tls": {"enabled": false}})), None);
    }

    #[test]
    fn transport_string_normalization() {
        assert_eq!(
            normalize_transport(&json!("ws")),
            Some(json!({"type": "ws"}))
        );
        assert_eq!(
            normalize_transport(&json!("h2")),
            Some(json!({"type": "http"}))
        );
        assert_eq!(normalize_transport(&json!("tcp")), None);
        assert_eq!(normalize_transport(&json!("kcp")), None);
        assert_eq!(normalize_transport(&json!("")), None);
        assert_eq!(normalize_transport(&json!(null)), None);
    }

    #[test]
    fn transport_object_normalization() {
        assert_eq!(
            normalize_transport(&json!({"type": "h2", "path": "/x"})),
            Some(json!({"type": "http", "path": "/x"}))
        );
        assert_eq!(normalize_transport(&json!({"type": "tcp"})), None);
        assert_eq!(normalize_transport(&json!({"type": "quic"})), None);
        assert_eq!(normalize_transport(&json!({"type": ""})), None);
    }

    #[test]
    fn v2ray_stream_settings_conversion() {
        let ws =
            json!({"network": "ws", "wsSettings": {"path": "/ray", "headers": {"Host": "a.com"}}});
        assert_eq!(
            normalize_transport(&ws),
            Some(json!({"type": "ws", "path": "/ray", "headers": {"Host": "a.com"}}))
        );
        let grpc = json!({"network": "grpc", "grpcSettings": {"serviceName": "g1"}});
        assert_eq!(
            normalize_transport(&grpc),
            Some(json!({"type": "grpc", "service_name": "g1"}))
        );
        let h2 = json!({"network": "h2", "httpSettings": {"path": "/h", "host": ["a.com"]}});
        assert_eq!(
            normalize_transport(&h2),
            Some(json!({"type": "http", "path": "/h", "host": ["a.com"]}))
        );
        assert_eq!(normalize_transport(&json!({"network": "tcp"})), None);
        let kcp = json!({"network": "kcp"});
        assert_eq!(normalize_transport(&kcp), None);
    }
}

// ---------- 配置生成（对应 config_manager.build_config） ----------

/// clash API 监听地址（与 Python CLASH_HOST 一致）。
pub const CLASH_HOST: &str = "127.0.0.1";
/// clash API 默认端口（settings.system.clashPort 未配置时使用）。
pub const DEFAULT_CLASH_PORT: i64 = 9095;
/// 默认监听地址。
pub const DEFAULT_LISTEN_IP: &str = "0.0.0.0";
/// 默认测试 URL。
pub const DEFAULT_TEST_URL: &str = "https://www.gstatic.com/generate_204";
/// 合法日志等级白名单。
pub const LOG_LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error", "fatal"];
/// 无 ssPass/authPass 时的默认 SS 入站密码。
pub const DEFAULT_SS_PASS: &str = "relaypass";
/// 无 authUser 时的默认入站用户名。
pub const DEFAULT_AUTH_USER: &str = "user";
/// 无 authPass 时的默认入站密码。
pub const DEFAULT_AUTH_PASS: &str = "pass";
/// 中转域名无认证时的默认用户名。
pub const DEFAULT_RELAY_USER: &str = "relayuser";

/// build_config 的输入（由调用方从 DB 读出后传入，本层不做 IO）。
#[derive(Debug, Clone)]
pub struct BuildInput {
    pub nodes: Vec<Value>,
    pub relay_domains: Vec<Value>,
    pub settings: Value,
    pub clash_port: i64,
    pub clash_secret: String,
}

impl Default for BuildInput {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            relay_domains: Vec::new(),
            settings: json!({}),
            clash_port: DEFAULT_CLASH_PORT,
            clash_secret: String::new(),
        }
    }
}

/// build_config 的输出。`config` 可直接交给 sing-box。
#[derive(Debug, Clone)]
pub struct BuildResult {
    pub config: Value,
    /// 每项形如 `{"node": 名称, "reason": 中文原因}`，与前端展示格式一致。
    pub errors: Vec<Value>,
    /// 出站 hairpin 改写说明（仅用于日志）。
    pub notes: Vec<String>,
}

/// 取第一个「真值」字符串（Python `cfg.get(a) or cfg.get(b) or default` 语义）。
fn first_str(v: &Value, keys: &[&str], default: &str) -> String {
    for k in keys {
        match v.get(*k) {
            Some(Value::String(s)) if !s.is_empty() => return s.clone(),
            Some(Value::Number(n)) => return n.to_string(),
            _ => continue,
        }
    }
    default.to_string()
}

/// 取字符串值（空则用默认值），不做多键回落。
fn opt_str(v: &Value, key: &str, default: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => default.to_string(),
    }
}

/// 取整数（Python `_safe_int(cfg.get(a) or cfg.get(b) or 0)` 语义）。
fn first_int(v: &Value, keys: &[&str]) -> i64 {
    for k in keys {
        match v.get(*k) {
            Some(Value::String(s)) if s.is_empty() => continue,
            Some(x) if !x.is_null() => return crate::utils::safe_int(x, 0),
            _ => continue,
        }
    }
    0
}

/// 本次配置会占用的全部入站端口（节点 + 中转域名 + 面板总入口）。
///
/// 供 netguard 判定「出站是否打回自己的入站」用：命中即回环自引用，必须跳过该节点。
/// 手动停用与自动停用都不生成入站，故直接跳过全部 `status == "disabled"`。
pub fn plan_inbound_ports(
    nodes: &[Value],
    relay_domains: &[Value],
    settings: &Value,
) -> BTreeSet<i64> {
    let mut ports: BTreeSet<i64> = BTreeSet::new();
    for node in nodes {
        if node.get("status").and_then(|v| v.as_str()) == Some("disabled") {
            continue;
        }
        let port = crate::utils::safe_int(&node.get("port").cloned().unwrap_or(json!(0)), 0);
        if port != 0 {
            ports.insert(port);
        }
    }
    for rd in relay_domains {
        let port = crate::utils::safe_int(&rd.get("port").cloned().unwrap_or(json!(0)), 0);
        if port != 0 {
            ports.insert(port);
        }
    }
    let main_port = first_int(settings, &["inboundPort"]);
    if main_port > 0 {
        ports.insert(main_port);
    }
    ports
}

/// 给 outbound 字典补 TLS 推导（vless/vmess 共用）。返回 true 表示已写入 tls。
fn fill_vless_vmess_tls(
    out: &mut Map<String, Value>,
    cfg: &Value,
    tls: Option<Value>,
    sb_type: &str,
) {
    if let Some(mut tls_dict) = tls {
        let obj = tls_dict.as_object_mut().expect("tls_enabled_dict 返回对象");
        let has_reality = obj
            .get("reality")
            .map(|v| crate::config_manager::is_truthy(v))
            .unwrap_or(false);
        let has_sni = obj
            .get("server_name")
            .map(|v| !v.is_null())
            .unwrap_or(false);
        if has_reality && !has_sni {
            let sni = first_str(cfg, &["sni", "server_name", "server", "address"], "");
            obj.insert("server_name".to_string(), Value::String(sni));
        }
        if !has_sni && !has_reality {
            let sni = first_str(cfg, &["sni", "server_name", "server", "address"], "");
            obj.insert("server_name".to_string(), Value::String(sni));
            obj.insert("insecure".to_string(), Value::Bool(true));
        }
        out.insert("tls".to_string(), tls_dict);
        return;
    }
    if sb_type == "vless" {
        let has_reality = cfg.get("pbk").map(|v| !v.is_null()).unwrap_or(false)
            || cfg.get("spx").map(|v| !v.is_null()).unwrap_or(false)
            || cfg.get("public_key").map(|v| !v.is_null()).unwrap_or(false);
        if has_reality {
            let sni = first_str(cfg, &["sni", "server_name", "server", "address"], "");
            let public_key = first_str(cfg, &["pbk", "spx", "public_key"], "");
            let short_id = first_str(cfg, &["sid", "short_id"], "");
            let fingerprint = first_str(cfg, &["fp"], "chrome");
            out.insert(
                "tls".to_string(),
                json!({
                    "enabled": true,
                    "server_name": sni,
                    "reality": {
                        "enabled": true,
                        "public_key": public_key,
                        "short_id": short_id,
                    },
                    "utls": {
                        "enabled": true,
                        "fingerprint": fingerprint,
                    },
                }),
            );
        } else {
            let sni = first_str(cfg, &["sni", "server_name", "server"], "");
            out.insert(
                "tls".to_string(),
                json!({"enabled": true, "server_name": sni, "insecure": true}),
            );
        }
    }
}

/// 从 DB 数据生成完整 sing-box 配置（纯函数，无 IO）。
pub fn build_config(input: &BuildInput) -> BuildResult {
    let nodes = &input.nodes;
    let relay_domains = &input.relay_domains;
    let settings = &input.settings;
    let listen_ip = opt_str(settings, "listenIp", DEFAULT_LISTEN_IP);

    let inbound_ports = plan_inbound_ports(nodes, relay_domains, settings);
    let self_domains = crate::netguard::self_domains_from_settings(settings, relay_domains);

    let mut inbounds: Vec<Value> = Vec::new();
    let mut outbounds: Vec<Value> = Vec::new();
    let mut route_rules: Vec<Value> = Vec::new();
    let mut errors: Vec<Value> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut outbound_tag_set: BTreeSet<String> = BTreeSet::new();
    let mut used_inbound_ports: BTreeSet<i64> = BTreeSet::new();

    // build_config 在事件循环线程里跑：上百个域名的 DNS/端口探测必须限时，
    // 超预算的节点退化为「不改写」，宁可少一层优化也不能把接口拖卡（每轮重新计时）。
    crate::netguard::begin_pass(crate::netguard::DEFAULT_PASS_BUDGET);

    for node in nodes {
        let probe_only = node.get("status").and_then(|v| v.as_str()) == Some("disabled");
        let disabled_auto = node
            .get("disabledAuto")
            .map(crate::config_manager::is_truthy)
            .unwrap_or(false);
        if probe_only && !disabled_auto {
            continue;
        }
        let protocol = opt_str(node, "protocol", "");
        let sb_type = match crate::config_manager::protocol_type_map(&protocol) {
            Some(t) => t,
            None => {
                errors.push(json!({
                    "node": opt_str(node, "name", ""),
                    "reason": format!("协议 {} 不被 sing-box 1.7 支持，已跳过", protocol),
                }));
                continue;
            }
        };
        let port = crate::utils::safe_int(&node.get("port").cloned().unwrap_or(json!(0)), 0);
        let tag_in = format!("in-mixed-{}", port);
        let tag_out = crate::config_manager::outbound_tag(&protocol, port);
        let entry_proto = first_str(node, &["entryProto"], "mixed");
        if !probe_only {
            used_inbound_ports.insert(port);
        }
        if !probe_only && entry_proto == "ss" {
            let ss_pass = first_str(node, &["ssPass", "authPass"], DEFAULT_SS_PASS);
            inbounds.push(json!({
                "type": "shadowsocks",
                "tag": tag_in,
                "listen": listen_ip,
                "listen_port": port,
                "method": "aes-256-gcm",
                "password": ss_pass,
            }));
        } else if !probe_only {
            let user = first_str(node, &["authUser"], DEFAULT_AUTH_USER);
            let pass = first_str(node, &["authPass"], DEFAULT_AUTH_PASS);
            inbounds.push(json!({
                "type": "mixed",
                "tag": tag_in,
                "listen": listen_ip,
                "listen_port": port,
                "users": [{"username": user, "password": pass}],
            }));
        }
        let cfg = node.get("rawConfig").cloned().unwrap_or(json!({}));
        // 坏 server_port（脏字符串/缺失）：跳过该节点，不中断整份配置（P0 防瘫痪）
        let srv_port = first_int(&cfg, &["server_port", "port"]);
        if !(1..=65535).contains(&srv_port) {
            let raw = cfg
                .get("server_port")
                .cloned()
                .or_else(|| cfg.get("port").cloned());
            errors.push(json!({
                "node": opt_str(node, "name", ""),
                "reason": format!("server_port 非法（{}），已跳过", raw.map(|v| v.to_string()).unwrap_or_else(|| "None".to_string())),
            }));
            continue;
        }

        let mut out: Map<String, Value> = Map::new();
        out.insert("type".to_string(), Value::String(sb_type.to_string()));
        out.insert("tag".to_string(), Value::String(tag_out.clone()));
        let tls = crate::config_manager::tls_enabled_dict(&cfg);
        let server = first_str(&cfg, &["server", "address"], "");

        match sb_type {
            "shadowsocks" => {
                out.insert("server".to_string(), Value::String(server));
                out.insert("server_port".to_string(), json!(srv_port));
                out.insert(
                    "method".to_string(),
                    Value::String(first_str(&cfg, &["method", "cipher"], "aes-256-gcm")),
                );
                out.insert(
                    "password".to_string(),
                    Value::String(opt_str(&cfg, "password", "")),
                );
            }
            "vmess" | "vless" => {
                out.insert("server".to_string(), Value::String(server));
                out.insert("server_port".to_string(), json!(srv_port));
                out.insert("uuid".to_string(), Value::String(opt_str(&cfg, "uuid", "")));
                if sb_type == "vmess" {
                    out.insert(
                        "security".to_string(),
                        Value::String(opt_str(&cfg, "security", "auto")),
                    );
                }
                fill_vless_vmess_tls(&mut out, &cfg, tls, sb_type);
                if sb_type == "vless" {
                    if let Some(flow) = cfg.get("flow").filter(|v| !v.is_null()) {
                        out.insert("flow".to_string(), flow.clone());
                    }
                }
                let tr_src = cfg
                    .get("transport")
                    .cloned()
                    .or_else(|| cfg.get("streamSettings").cloned());
                if let Some(tr_src) = tr_src {
                    if let Some(tr) = crate::config_manager::normalize_transport(&tr_src) {
                        out.insert("transport".to_string(), tr);
                    }
                }
            }
            "trojan" => {
                out.insert("server".to_string(), Value::String(server));
                out.insert("server_port".to_string(), json!(srv_port));
                out.insert(
                    "password".to_string(),
                    Value::String(opt_str(&cfg, "password", "")),
                );
                match tls {
                    Some(tls_dict) => {
                        out.insert("tls".to_string(), tls_dict);
                    }
                    None => {
                        // trojan 协议强制 TLS；订阅未带 tls 时按 sni 推断，推断值必须 insecure
                        let sni = first_str(&cfg, &["sni", "server_name", "server"], "");
                        out.insert(
                            "tls".to_string(),
                            json!({"enabled": true, "server_name": sni, "insecure": true}),
                        );
                    }
                }
                let tr_src = cfg
                    .get("transport")
                    .cloned()
                    .or_else(|| cfg.get("streamSettings").cloned());
                if let Some(tr_src) = tr_src {
                    if let Some(tr) = crate::config_manager::normalize_transport(&tr_src) {
                        out.insert("transport".to_string(), tr);
                    }
                }
            }
            "socks" | "http" => {
                out.insert("server".to_string(), Value::String(server));
                out.insert("server_port".to_string(), json!(srv_port));
                // sing-box 的 http outbound 要求带 password（无认证代理也必须补空串）
                out.insert(
                    "username".to_string(),
                    Value::String(opt_str(&cfg, "username", "")),
                );
                out.insert(
                    "password".to_string(),
                    Value::String(opt_str(&cfg, "password", "")),
                );
                if let Some(tls_dict) = tls {
                    out.insert("tls".to_string(), tls_dict);
                }
            }
            "hysteria2" => {
                out.insert("server".to_string(), Value::String(server));
                out.insert("server_port".to_string(), json!(srv_port));
                out.insert(
                    "password".to_string(),
                    Value::String(first_str(&cfg, &["password", "auth"], "")),
                );
                // hysteria2 强制要求 tls.server_name，缺省用 server 兜底（否则整份配置 check 失败）
                let sni = first_str(&cfg, &["sni", "server_name", "server", "address"], "");
                let insecure = match cfg.get("insecure") {
                    Some(Value::Bool(false)) => false,
                    Some(Value::String(s)) if s == "0" || s == "false" => false,
                    _ => true,
                };
                let mut tls_dict = json!({"enabled": true, "server_name": sni});
                if insecure {
                    tls_dict["insecure"] = Value::Bool(true);
                }
                out.insert("tls".to_string(), tls_dict);
                if let Some(obfs) = cfg
                    .get("obfs")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                {
                    out.insert(
                        "obfs".to_string(),
                        json!({"type": obfs, "password": first_str(&cfg, &["obfsPassword", "obfs-password"], "")}),
                    );
                }
            }
            "tuic" => {
                out.insert("server".to_string(), Value::String(server));
                out.insert("server_port".to_string(), json!(srv_port));
                out.insert("uuid".to_string(), Value::String(opt_str(&cfg, "uuid", "")));
                out.insert(
                    "password".to_string(),
                    Value::String(opt_str(&cfg, "password", "")),
                );
                // sing-box 的 tuic outbound 强制 TLS
                let tls_dict = match cfg
                    .get("sni")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                {
                    Some(sni) => json!({"enabled": true, "server_name": sni}),
                    None => json!({"enabled": true}),
                };
                out.insert("tls".to_string(), tls_dict);
            }
            "wireguard" => {
                out.insert("server".to_string(), Value::String(server));
                out.insert("server_port".to_string(), json!(srv_port));
                // sing-box wireguard outbound: private_key + peer_public_key + local_address
                out.insert(
                    "private_key".to_string(),
                    Value::String(first_str(&cfg, &["private_key", "local_private_key"], "")),
                );
                out.insert(
                    "peer_public_key".to_string(),
                    Value::String(first_str(&cfg, &["peer_public_key", "public_key"], "")),
                );
                let local_address = match cfg.get("local_address") {
                    Some(Value::Array(a)) => Value::Array(a.clone()),
                    Some(Value::String(s)) if !s.is_empty() => json!([s]),
                    _ => json!(["10.0.0.2/32"]),
                };
                out.insert("local_address".to_string(), local_address);
            }
            _ => {}
        }

        // 自引用防护：出站拨回本机公网 IP 会走云 NAT hairpin（多一个 socket + conntrack），
        // 上游挂掉时半开连接不释放会把 fd 吃光。命中本机时改写 127.0.0.1；
        // 命中本面板入站端口则是回环自引用，直接跳过该节点。
        let (kind, detail) =
            crate::netguard::apply_rewrite_set(&mut out, &inbound_ports, &self_domains);
        if kind == crate::netguard::Kind::Loop {
            errors.push(json!({
                "node": opt_str(node, "name", ""),
                "reason": format!("{}，已跳过", detail),
            }));
            continue;
        }
        if kind == crate::netguard::Kind::Hairpin {
            notes.push(format!("{}: {}", opt_str(node, "name", ""), detail));
        }

        outbounds.push(Value::Object(out));
        outbound_tag_set.insert(tag_out.clone());
        if !probe_only {
            route_rules.push(json!({"inbound": [tag_in], "outbound": tag_out}));
        }
    }
    // ---------- 多域名轮询入口 ----------
    for rd in relay_domains {
        let rd_id = opt_str(rd, "id", "");
        let rd_port = crate::utils::safe_int(&rd.get("port").cloned().unwrap_or(json!(0)), 0);
        let rd_in_tag = format!("in-relay-{}", rd_id);
        let rd_out_tag = format!("relay-auto-{}", rd_id);
        let selected_groups: Vec<String> = match rd.get("groups") {
            Some(Value::Array(a)) if !a.is_empty() => a
                .iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect(),
            _ => vec!["ALL".to_string()],
        };
        let rd_nodes: Vec<&Value> = nodes
            .iter()
            .filter(|n| n.get("status").and_then(|v| v.as_str()) != Some("disabled"))
            .filter(|n| {
                selected_groups.iter().any(|g| g == "ALL")
                    || n.get("group")
                        .and_then(|v| v.as_str())
                        .map(|g| selected_groups.iter().any(|x| x == g))
                        .unwrap_or(false)
            })
            .collect();
        used_inbound_ports.insert(rd_port);
        let rd_user = first_str(rd, &["authUser"], DEFAULT_RELAY_USER);
        let rd_pass = first_str(rd, &["authPass"], DEFAULT_SS_PASS);
        inbounds.push(json!({
            "type": "mixed",
            "tag": rd_in_tag,
            "listen": listen_ip,
            "listen_port": rd_port,
            "users": [{"username": rd_user, "password": rd_pass}],
        }));
        let rd_targets: Vec<String> = rd_nodes
            .iter()
            .map(|n| {
                crate::config_manager::outbound_tag(
                    &opt_str(n, "protocol", ""),
                    crate::utils::safe_int(&n.get("port").cloned().unwrap_or(json!(0)), 0),
                )
            })
            .filter(|t| outbound_tag_set.contains(t))
            .collect();
        // 用 selector 代替 urltest：轮询切换走 clash API PUT /proxies 运行时切换，
        // 只影响新连接、不断已有连接（热重载会全局断连，urltest 无法随机切换）。
        let mut rd_selector = json!({
            "type": "selector",
            "tag": rd_out_tag,
            "outbounds": if rd_targets.is_empty() { json!(["direct"]) } else { json!(rd_targets) },
        });
        // 随机轮询：启动时选中上次的节点，之后由定时器随机 PUT 切换
        let random_on = is_truthy(
            &settings
                .get("randomRotateEnabled")
                .cloned()
                .unwrap_or(json!(false)),
        );
        if random_on {
            if let Some(cur) = settings.get("randomRotateCurrent").and_then(|v| v.as_str()) {
                if rd_targets.iter().any(|t| t == cur) {
                    rd_selector["default"] = Value::String(cur.to_string());
                }
            }
        }
        outbounds.push(rd_selector);
        route_rules.push(json!({"inbound": [rd_in_tag], "outbound": rd_out_tag}));
    }

    // ---------- 面板总入口（系统设置「入站监听端口」） ----------
    // 全局 mixed 入口 + main-auto selector，出口由探活/粘滞/随机轮询调度。
    // 端口为 0/冲突/未配置时不生成（避免占用端口和启动失败）。
    let main_port = first_int(settings, &["inboundPort"]);
    if main_port > 0 && !used_inbound_ports.contains(&main_port) {
        let main_targets: Vec<String> = nodes
            .iter()
            .filter(|n| n.get("status").and_then(|v| v.as_str()) != Some("disabled"))
            .map(|n| {
                crate::config_manager::outbound_tag(
                    &opt_str(n, "protocol", ""),
                    crate::utils::safe_int(&n.get("port").cloned().unwrap_or(json!(0)), 0),
                )
            })
            .filter(|t| outbound_tag_set.contains(t))
            .collect::<Vec<String>>();
        if !main_targets.is_empty() {
            let mut main_selector = json!({
                "type": "selector",
                "tag": "main-auto",
                "outbounds": main_targets,
            });
            // 随机轮询开启时沿用当前选中（与 relay 一致，重启后不丢出口）
            let random_on = is_truthy(
                &settings
                    .get("randomRotateEnabled")
                    .cloned()
                    .unwrap_or(json!(false)),
            );
            if random_on {
                if let Some(cur) = settings.get("randomRotateCurrent").and_then(|v| v.as_str()) {
                    let hit = main_selector["outbounds"]
                        .as_array()
                        .map(|a| a.iter().any(|t| t.as_str() == Some(cur)))
                        .unwrap_or(false);
                    if hit {
                        main_selector["default"] = Value::String(cur.to_string());
                    }
                }
            }
            outbounds.push(main_selector);
            let mu = first_str(settings, &["mainAuthUser"], DEFAULT_AUTH_USER);
            let mp = first_str(settings, &["mainAuthPass"], DEFAULT_AUTH_PASS);
            inbounds.push(json!({
                "type": "mixed",
                "tag": "in-main",
                "listen": listen_ip,
                "listen_port": main_port,
                "users": [{"username": mu, "password": mp}],
            }));
            route_rules.push(json!({"inbound": ["in-main"], "outbound": "main-auto"}));
        }
    }

    outbounds.push(json!({"type": "direct", "tag": "direct"}));
    outbounds.push(json!({"type": "block", "tag": "block"}));

    // 日志等级可配置（系统设置「日志等级」）；白名单校验防误配
    let mut log_level = opt_str(settings, "logLevel", "info").to_lowercase();
    if !LOG_LEVELS.contains(&log_level.as_str()) {
        log_level = "info".to_string();
    }

    let config = json!({
        "log": {"level": log_level, "timestamp": true},
        "experimental": {
            "clash_api": {
                "external_controller": format!("{}:{}", CLASH_HOST, input.clash_port),
                "secret": input.clash_secret,
                "default_mode": "rule",
            }
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": route_rules, "auto_detect_interface": true},
    });
    BuildResult {
        config,
        errors,
        notes,
    }
}

/// 节点/中转域名的 outbound tag（唯一实现，stats 与配置生成共用）。
pub fn outbound_tag(protocol: &str, port: i64) -> String {
    format!("out-{}-{}", protocol, port)
}
#[cfg(test)]
mod build_tests {
    use super::*;

    fn node(id: &str, port: i64, protocol: &str, cfg: Value) -> Value {
        json!({
            "id": id, "name": format!("n-{}", port), "protocol": protocol, "port": port,
            "status": "online", "group": "ALL", "rawConfig": cfg
        })
    }

    fn socks5_node(port: i64) -> Value {
        node(
            "n-1",
            port,
            "socks5",
            json!({"server": "198.51.100.7", "server_port": 40136, "username": "u", "password": "p"}),
        )
    }

    fn input(nodes: Vec<Value>) -> BuildInput {
        BuildInput {
            nodes,
            relay_domains: vec![],
            settings: json!({"listenIp": "0.0.0.0"}),
            clash_port: 9095,
            clash_secret: "sec".to_string(),
        }
    }

    fn find_tag(arr: &Value, tag: &str) -> Option<Value> {
        arr.as_array()?
            .iter()
            .find(|x| x.get("tag").and_then(|t| t.as_str()) == Some(tag))
            .cloned()
    }

    #[test]
    fn socks5_node_generates_mixed_inbound_and_outbound() {
        let r = build_config(&input(vec![socks5_node(51000)]));
        assert!(r.errors.is_empty(), "errors={:?}", r.errors);
        let ib = find_tag(&r.config["inbounds"], "in-mixed-51000").expect("入站应生成");
        assert_eq!(ib["type"], "mixed");
        assert_eq!(ib["listen_port"], 51000);
        assert_eq!(ib["users"][0]["username"], "user");
        let ob = find_tag(&r.config["outbounds"], "out-socks5-51000").expect("出站应生成");
        assert_eq!(ob["type"], "socks");
        assert_eq!(ob["server"], "198.51.100.7");
        assert_eq!(ob["server_port"], 40136);
        assert_eq!(ob["username"], "u");
        assert_eq!(ob["password"], "p");
        let rules = r.config["route"]["rules"].as_array().unwrap();
        assert!(rules
            .iter()
            .any(|x| x["inbound"][0] == "in-mixed-51000" && x["outbound"] == "out-socks5-51000"));
    }

    #[test]
    fn ss_entry_proto_generates_shadowsocks_inbound() {
        let mut n = socks5_node(51001);
        n["entryProto"] = json!("ss");
        n["ssPass"] = json!("secret-ss");
        let r = build_config(&input(vec![n]));
        let ib = find_tag(&r.config["inbounds"], "in-mixed-51001").unwrap();
        assert_eq!(ib["type"], "shadowsocks");
        assert_eq!(ib["method"], "aes-256-gcm");
        assert_eq!(ib["password"], "secret-ss");
    }

    #[test]
    fn disabled_auto_keeps_outbound_only() {
        let mut n = socks5_node(51002);
        n["status"] = json!("disabled");
        n["disabledAuto"] = json!(true);
        let r = build_config(&input(vec![n]));
        assert!(
            find_tag(&r.config["outbounds"], "out-socks5-51002").is_some(),
            "自动停用保留出站供复查"
        );
        assert!(
            find_tag(&r.config["inbounds"], "in-mixed-51002").is_none(),
            "自动停用不生成入站"
        );
        let rules = r.config["route"]["rules"].as_array().unwrap();
        assert!(!rules.iter().any(|x| x["inbound"][0] == "in-mixed-51002"));
    }

    #[test]
    fn manual_disabled_node_is_skipped_entirely() {
        let mut n = socks5_node(51003);
        n["status"] = json!("disabled");
        let r = build_config(&input(vec![n]));
        assert!(find_tag(&r.config["outbounds"], "out-socks5-51003").is_none());
        assert!(find_tag(&r.config["inbounds"], "in-mixed-51003").is_none());
    }

    #[test]
    fn invalid_server_port_is_reported_not_fatal() {
        let bad = node(
            "n-bad",
            51004,
            "socks5",
            json!({"server": "198.51.100.7", "server_port": "abc"}),
        );
        let good = socks5_node(51005);
        let r = build_config(&input(vec![bad, good]));
        assert_eq!(r.errors.len(), 1);
        assert!(r.errors[0]["reason"]
            .as_str()
            .unwrap()
            .contains("server_port 非法"));
        assert!(
            find_tag(&r.config["outbounds"], "out-socks5-51005").is_some(),
            "其余节点不受影响"
        );
    }

    #[test]
    fn unsupported_protocol_is_reported() {
        let n = node(
            "n-x",
            51006,
            "unknownproto",
            json!({"server": "198.51.100.7", "server_port": 1}),
        );
        let r = build_config(&input(vec![n]));
        assert_eq!(r.errors.len(), 1);
        assert!(r.errors[0]["reason"]
            .as_str()
            .unwrap()
            .contains("不被 sing-box 1.7 支持"));
    }

    #[test]
    fn relay_domain_generates_selector_and_route() {
        let mut inp = input(vec![socks5_node(51000), socks5_node(51001)]);
        inp.relay_domains =
            vec![json!({"id": "r1", "port": 40136, "domain": "jp.example.com", "groups": ["ALL"]})];
        let r = build_config(&inp);
        let sel = find_tag(&r.config["outbounds"], "relay-auto-r1").expect("selector 应生成");
        assert_eq!(sel["type"], "selector");
        assert_eq!(sel["outbounds"].as_array().unwrap().len(), 2);
        let ib = find_tag(&r.config["inbounds"], "in-relay-r1").unwrap();
        assert_eq!(ib["listen_port"], 40136);
        assert_eq!(ib["users"][0]["username"], "relayuser");
    }

    #[test]
    fn relay_group_filter_excludes_other_groups() {
        let mut a = socks5_node(51000);
        a["group"] = json!("HK");
        let b = socks5_node(51001);
        let mut inp = input(vec![a, b]);
        inp.relay_domains = vec![json!({"id": "r2", "port": 40137, "groups": ["HK"]})];
        let r = build_config(&inp);
        let sel = find_tag(&r.config["outbounds"], "relay-auto-r2").unwrap();
        let outs: Vec<&str> = sel["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|x| x.as_str())
            .collect();
        assert_eq!(outs, vec!["out-socks5-51000"]);
    }

    #[test]
    fn main_inbound_generates_main_auto_selector() {
        let mut inp = input(vec![socks5_node(51000)]);
        inp.settings = json!({"inboundPort": 2080, "mainAuthUser": "mu", "mainAuthPass": "mp"});
        let r = build_config(&inp);
        let sel = find_tag(&r.config["outbounds"], "main-auto").expect("main-auto 应生成");
        assert_eq!(sel["outbounds"][0], "out-socks5-51000");
        let ib = find_tag(&r.config["inbounds"], "in-main").unwrap();
        assert_eq!(ib["listen_port"], 2080);
        assert_eq!(ib["users"][0]["username"], "mu");
    }

    #[test]
    fn main_port_conflicting_with_node_port_is_skipped() {
        let mut inp = input(vec![socks5_node(2080)]);
        inp.settings = json!({"inboundPort": 2080});
        let r = build_config(&inp);
        assert!(
            find_tag(&r.config["inbounds"], "in-main").is_none(),
            "端口冲突时不生成总入口"
        );
    }

    #[test]
    fn log_level_whitelist_and_clash_api() {
        let mut inp = input(vec![]);
        inp.settings = json!({"logLevel": "TRACE"});
        let r = build_config(&inp);
        assert_eq!(r.config["log"]["level"], "trace");
        assert_eq!(r.config["log"]["timestamp"], true);
        assert_eq!(
            r.config["experimental"]["clash_api"]["external_controller"],
            "127.0.0.1:9095"
        );
        assert_eq!(r.config["experimental"]["clash_api"]["secret"], "sec");
        inp.settings = json!({"logLevel": "verbose"});
        assert_eq!(build_config(&inp).config["log"]["level"], "info");
    }

    #[test]
    fn direct_and_block_appended_last() {
        let r = build_config(&input(vec![]));
        let outs = r.config["outbounds"].as_array().unwrap();
        assert_eq!(outs[outs.len() - 2]["tag"], "direct");
        assert_eq!(outs[outs.len() - 1]["tag"], "block");
    }

    #[test]
    fn plan_inbound_ports_collects_node_relay_and_main() {
        let nodes = vec![socks5_node(51000), {
            let mut n = socks5_node(51001);
            n["status"] = json!("disabled");
            n
        }];
        let relays = vec![json!({"id": "r1", "port": 40136})];
        let ports = plan_inbound_ports(&nodes, &relays, &json!({"inboundPort": 2080}));
        assert!(ports.contains(&51000));
        assert!(!ports.contains(&51001), "停用节点不占入站端口");
        assert!(ports.contains(&40136));
        assert!(ports.contains(&2080));
        let empty = plan_inbound_ports(&[], &[], &json!({}));
        assert!(empty.is_empty());
    }

    #[test]
    fn vless_reality_tls_is_derived_from_flat_keys() {
        let n = node(
            "n-v",
            51007,
            "vless",
            json!({
                "server": "198.51.100.7", "server_port": 443, "uuid": "uuid-1",
                "pbk": "PUBKEY", "sid": "abcd", "fp": "chrome", "sni": "cdn.example.com"
            }),
        );
        let r = build_config(&input(vec![n]));
        let ob = find_tag(&r.config["outbounds"], "out-vless-51007").unwrap();
        assert_eq!(ob["tls"]["enabled"], true);
        assert_eq!(ob["tls"]["server_name"], "cdn.example.com");
        assert_eq!(ob["tls"]["reality"]["public_key"], "PUBKEY");
        assert_eq!(ob["tls"]["reality"]["short_id"], "abcd");
        assert_eq!(ob["tls"]["utls"]["fingerprint"], "chrome");
    }

    #[test]
    fn vless_without_reality_falls_back_to_insecure_tls() {
        let n = node(
            "n-v2",
            51008,
            "vless",
            json!({
                "server": "198.51.100.7", "server_port": 443, "uuid": "u"
            }),
        );
        let r = build_config(&input(vec![n]));
        let ob = find_tag(&r.config["outbounds"], "out-vless-51008").unwrap();
        assert_eq!(ob["tls"]["insecure"], true);
        assert_eq!(ob["tls"]["server_name"], "198.51.100.7");
    }

    #[test]
    fn hysteria2_defaults_to_insecure_and_honours_explicit_false() {
        let a = node(
            "n-h1",
            51009,
            "hysteria2",
            json!({"server": "198.51.100.7", "server_port": 443, "password": "pw"}),
        );
        let r = build_config(&input(vec![a]));
        let ob = find_tag(&r.config["outbounds"], "out-hysteria2-51009").unwrap();
        assert_eq!(ob["tls"]["insecure"], true);
        assert_eq!(ob["tls"]["server_name"], "198.51.100.7");
        let b = node(
            "n-h2",
            51010,
            "hysteria2",
            json!({"server": "198.51.100.7", "server_port": 443, "password": "pw", "insecure": false}),
        );
        let r2 = build_config(&input(vec![b]));
        let ob2 = find_tag(&r2.config["outbounds"], "out-hysteria2-51010").unwrap();
        assert!(
            ob2["tls"].get("insecure").is_none(),
            "显式关闭时不得写 insecure"
        );
    }

    #[test]
    fn wireguard_local_address_is_normalised_to_array() {
        let n = node(
            "n-w",
            51011,
            "wireguard",
            json!({
                "server": "198.51.100.7", "server_port": 51820,
                "private_key": "pk", "peer_public_key": "pub", "local_address": "10.0.0.9/32"
            }),
        );
        let r = build_config(&input(vec![n]));
        let ob = find_tag(&r.config["outbounds"], "out-wireguard-51011").unwrap();
        assert_eq!(ob["local_address"][0], "10.0.0.9/32");
        assert_eq!(ob["private_key"], "pk");
        assert_eq!(ob["peer_public_key"], "pub");
    }

    #[test]
    fn hyperlink_self_reference_loop_is_skipped() {
        // 出站指向本面板入站端口 → 回环自引用，必须跳过并报错。
        // netguard 对 127.0.0.1 字面量直接放行（已是回环无需处理），
        // 真正的回环自引用场景是「节点 server 解析回本机网卡 IP」。这里用本机非回环 IPv4 复现。
        let own = crate::netguard::self_ips(&[]);
        let local_ip = match own
            .iter()
            .find(|ip| ip.as_str() != "127.0.0.1" && !ip.contains(':'))
        {
            Some(ip) => ip.clone(),
            None => return, // 无网卡 IPv4 的隔离环境，无法构造该场景
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 测试端口");
        let port = listener.local_addr().unwrap().port() as i64;
        crate::netguard::reset_cache();
        let self_node = socks5_node(port);
        let loop_node = node(
            "n-loop",
            port + 1,
            "socks5",
            json!({"server": local_ip, "server_port": port}),
        );
        let r = build_config(&input(vec![self_node, loop_node]));
        assert!(
            find_tag(&r.config["outbounds"], &format!("out-socks5-{}", port + 1)).is_none(),
            "回环自引用出站必须跳过"
        );
        assert!(
            find_tag(&r.config["outbounds"], &format!("out-socks5-{}", port)).is_some(),
            "正常节点仍应生成"
        );
        assert!(
            r.errors
                .iter()
                .any(|e| e["reason"].as_str().unwrap().contains("已跳过")),
            "errors={:?}",
            r.errors
        );
    }
}
