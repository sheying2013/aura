//! IP 归属地 + 纯净度情报模块（对应 backend/ipinfo.py，310 行）。
//!
//! 数据源：
//! - ipinfo.io/{ip}/json        归属地（country/region/city/org），timeout 4s
//! - sg.ipapi.is/?q={ip}        数据中心/代理/VPN/Tor/滥用判断，timeout 6s
//! - my.ippure.com/v1/info      经节点 HTTP 代理查调用方出口的 fraudScore/是否住宅，timeout 10s
//! - ping0.cc/ip/{ip}           经节点 HTTP 代理查风控值/原生 IP，timeout 10s
//!
//! 返回字段与前端约定（键名与 Python 版逐字一致）：
//! - lookup:        exitIp / exitCountry(中文) / exitFlag / exitCity / exitType / exitScore / exitOrg / exitAsn
//! - lookup_ippure: exitRisk / exitResidential / exitCountry / exitFlag / exitCity / exitAsn / exitIp
//! - lookup_ping0:  exitRisk / exitRiskLabel / exitIpType / exitNativeIp
//!
//! 说明：serde_json 默认 Map 为 BTreeMap，键集合与 Python 完全一致但序列化顺序按字典序，不做顺序保证。

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use regex::Regex;
use reqwest::Client;
use serde_json::{json, Map, Value};

// ---------- 常量 ----------

pub const IPINFO_BASE: &str = "https://ipinfo.io";
pub const IPAPI_BASE: &str = "https://sg.ipapi.is";
pub const IPPURE_URL: &str = "https://my.ippure.com/v1/info";
pub const PING0_BASE: &str = "https://ping0.cc";

/// ipinfo.io 超时（Python _fetch 默认 4.0s）
pub const IPINFO_TIMEOUT: Duration = Duration::from_secs(4);
/// sg.ipapi.is 超时
pub const IPAPI_TIMEOUT: Duration = Duration::from_secs(6);
/// my.ippure.com 超时（Python _fetch_ippure_via_proxy 默认 10.0s）
pub const IPPURE_TIMEOUT: Duration = Duration::from_secs(10);
/// ping0.cc 超时（Python _fetch_ping0_via_proxy 默认 10.0s）
pub const PING0_TIMEOUT: Duration = Duration::from_secs(10);

/// lookup 缓存 24h
pub const CACHE_TTL: Duration = Duration::from_secs(24 * 3600);
/// ippure/ping0 缓存 7 天
pub const ENRICH_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

pub const CACHE_MAX: usize = 5000;
pub const CACHE_EVICT: usize = 1000;
pub const ENRICH_MAX: usize = 2000;
pub const ENRICH_EVICT: usize = 400;

/// ping0.cc 被 Cloudflare 拦截时页面很小（Python: len(body) < 5000）
pub const PING0_MIN_BODY: usize = 5000;

/// 区域指示符偏移：0x1F1E6 - ord('A')
pub const FLAG_OFFSET: u32 = 0x1F1E6 - b'A' as u32;

const UA: &str = "Mozilla/5.0";

/// 国家代码 -> 中文名（ISO 3166 两字母；GB=英国，HK/TW/MO=中国）
pub const COUNTRY_CN: &[(&str, &str)] = &[
    ("US", "美国"),
    ("JP", "日本"),
    ("KR", "韩国"),
    ("HK", "中国香港"),
    ("TW", "中国台湾"),
    ("SG", "新加坡"),
    ("DE", "德国"),
    ("FR", "法国"),
    ("GB", "英国"),
    ("NL", "荷兰"),
    ("CA", "加拿大"),
    ("AU", "澳大利亚"),
    ("RU", "俄罗斯"),
    ("CN", "中国大陆"),
    ("UA", "乌克兰"),
    ("MY", "马来西亚"),
    ("TH", "泰国"),
    ("VN", "越南"),
    ("IN", "印度"),
    ("BR", "巴西"),
    ("TR", "土耳其"),
    ("PL", "波兰"),
    ("RO", "罗马尼亚"),
    ("BG", "保加利亚"),
    ("CZ", "捷克"),
    ("ES", "西班牙"),
    ("IT", "意大利"),
    ("SE", "瑞典"),
    ("CH", "瑞士"),
    ("BE", "比利时"),
    ("IE", "爱尔兰"),
    ("FI", "芬兰"),
    ("NO", "挪威"),
    ("DK", "丹麦"),
    ("IL", "以色列"),
    ("AE", "阿联酋"),
    ("ZA", "南非"),
    ("MX", "墨西哥"),
    ("AR", "阿根廷"),
    ("NZ", "新西兰"),
    ("PT", "葡萄牙"),
    ("GR", "希腊"),
    ("AT", "奥地利"),
    ("HU", "匈牙利"),
    ("PH", "菲律宾"),
    ("ID", "印度尼西亚"),
    ("MO", "中国澳门"),
    ("PA", "巴拿马"),
    ("KZ", "哈萨克斯坦"),
    ("LT", "立陶宛"),
    ("LV", "拉脱维亚"),
    ("EE", "爱沙尼亚"),
    ("LU", "卢森堡"),
    ("CY", "塞浦路斯"),
    ("MT", "马耳他"),
    ("IS", "冰岛"),
    ("PK", "巴基斯坦"),
    ("BD", "孟加拉"),
    ("NG", "尼日利亚"),
    ("EG", "埃及"),
    ("SA", "沙特阿拉伯"),
    ("QA", "卡塔尔"),
    ("KW", "科威特"),
];

fn cn_table() -> &'static HashMap<&'static str, &'static str> {
    static TABLE: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    TABLE.get_or_init(|| COUNTRY_CN.iter().copied().collect())
}

// ---------- 纯解析工具 ----------

/// 国家代码 -> 国旗 emoji（区域指示符）。非 2 个字符返回空串。
pub fn country_flag(cc: &str) -> String {
    if cc.chars().count() != 2 {
        return String::new();
    }
    let up = cc.to_uppercase();
    let mut chars = up.chars();
    let (a, b) = match (chars.next(), chars.next()) {
        (Some(a), Some(b)) => (a, b),
        _ => return String::new(),
    };
    let fa = char::from_u32(a as u32 + FLAG_OFFSET);
    let fb = char::from_u32(b as u32 + FLAG_OFFSET);
    match (fa, fb) {
        (Some(x), Some(y)) => {
            let mut s = String::new();
            s.push(x);
            s.push(y);
            s
        }
        _ => String::new(),
    }
}

/// 国家代码 -> 中文名；未知码回退大写原码；空则空串。
pub fn country_cn(cc: Option<&str>) -> String {
    let cc = match cc {
        Some(c) if !c.is_empty() => c,
        _ => return String::new(),
    };
    let up = cc.to_uppercase();
    match cn_table().get(up.as_str()) {
        Some(v) => (*v).to_string(),
        None => up,
    }
}

/// Python 真值语义：None/False/0/0.0/""/[]/{} 为假。
pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

fn field_truthy(v: &Value, key: &str) -> bool {
    truthy(v.get(key))
}

/// Python isinstance(x, (int, float)) -> int(x)：bool 按 int 处理，字符串不算数字，浮点向零截断。
pub fn py_int(v: &Value) -> Option<i64> {
    match v {
        Value::Bool(b) => Some(if *b { 1 } else { 0 }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(i)
            } else {
                n.as_f64().map(|f| f as i64)
            }
        }
        _ => None,
    }
}

/// Python f-string 插值形态（用于 "AS" + asn）。
fn py_repr(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else {
                n.to_string()
            }
        }
        Value::Bool(b) => {
            if *b {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        Value::Null => "None".to_string(),
        other => other.to_string(),
    }
}

/// 取字符串字段；非字符串按空串（Python 版此处会抛 AttributeError，这里降级不 panic）。
pub fn str_field(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    }
}

fn truncate_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// 纯净度评分：未知 0 / bogon 0 / abuser 10 / 数据中心 40 / VPN-代理-Tor 30 / 住宅 100。
pub fn exit_score(ipapis: Option<&Value>) -> i64 {
    let v = match ipapis {
        Some(v) if truthy(Some(v)) => v,
        _ => return 0,
    };
    if field_truthy(v, "is_bogon") {
        return 0;
    }
    if field_truthy(v, "is_abuser") {
        return 10;
    }
    if field_truthy(v, "is_datacenter") {
        return 40;
    }
    if field_truthy(v, "is_vpn") || field_truthy(v, "is_proxy") || field_truthy(v, "is_tor") {
        return 30;
    }
    100
}

/// IP 类型：unknown / hosting / proxy / residential。
pub fn ip_type(ipapis: Option<&Value>) -> String {
    let v = match ipapis {
        Some(v) if truthy(Some(v)) => v,
        _ => return "unknown".to_string(),
    };
    if field_truthy(v, "is_bogon") {
        return "unknown".to_string();
    }
    if field_truthy(v, "is_datacenter") {
        return "hosting".to_string();
    }
    if field_truthy(v, "is_vpn") || field_truthy(v, "is_proxy") || field_truthy(v, "is_tor") {
        return "proxy".to_string();
    }
    if field_truthy(v, "is_abuser") {
        return "hosting".to_string();
    }
    "residential".to_string()
}

/// 由 ipinfo + ipapi 原始响应组装 lookup 结果（纯函数，无网络）。
pub fn build_lookup_result(ip: &str, info: Option<&Value>, ipapis: Option<&Value>) -> Value {
    let mut out = Map::new();
    out.insert("exitIp".to_string(), json!(ip));

    let mut cc = String::new();
    let mut city = String::new();
    let mut org = String::new();
    let mut asn = String::new();
    if let Some(info) = info {
        if truthy(Some(info)) {
            cc = str_field(info, "country").to_uppercase();
            city = str_field(info, "city");
            org = str_field(info, "org");
            if !org.is_empty() && org.contains(' ') {
                if let Some(first) = org.split(' ').next() {
                    asn = first.to_string();
                }
            }
        }
    }
    out.insert(
        "exitCountry".to_string(),
        if cc.is_empty() {
            json!("")
        } else {
            json!(country_cn(Some(cc.as_str())))
        },
    );
    out.insert(
        "exitFlag".to_string(),
        if cc.is_empty() {
            json!("")
        } else {
            json!(country_flag(cc.as_str()))
        },
    );
    out.insert("exitCity".to_string(), json!(city));
    out.insert("exitType".to_string(), json!(ip_type(ipapis)));
    out.insert("exitScore".to_string(), json!(exit_score(ipapis)));
    out.insert("exitOrg".to_string(), json!(org));
    out.insert("exitAsn".to_string(), json!(asn));
    Value::Object(out)
}

// ---------- ping0.cc HTML 解析 ----------

fn re_risk() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?s)riskcurrent.*?value">(\d+)%</span><span class="lab">\s*([^<]+)"#)
            .expect("risk regex")
    })
}

fn re_iptype() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?s)line-iptype.*?content">(.*?)</div>"#).expect("iptype regex")
    })
}

fn re_nativeip() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?s)line-nativeip.*?content">(.*?)</div>"#).expect("nativeip regex")
    })
}

fn re_tag() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"<[^>]+>"#).expect("tag regex"))
}

fn re_pipe() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\|+"#).expect("pipe regex"))
}

/// 是否被 Cloudflare 风控挡下：正文过短或含 turnstile。
pub fn ping0_blocked(body: &str) -> bool {
    body.chars().count() < PING0_MIN_BODY || body.to_lowercase().contains("turnstile")
}

/// 从 ping0.cc HTML 提取字段（不做拦截判断，纯正则，便于单测）。
pub fn extract_ping0(body: &str) -> Value {
    let mut out = Map::new();
    if let Some(c) = re_risk().captures(body) {
        if let Some(num) = c.get(1).and_then(|m| m.as_str().parse::<i64>().ok()) {
            out.insert("exitRisk".to_string(), json!(num));
        }
        if let Some(lab) = c.get(2) {
            out.insert(
                "exitRiskLabel".to_string(),
                json!(lab.as_str().trim().to_string()),
            );
        }
    }
    if let Some(c) = re_iptype().captures(body) {
        if let Some(g) = c.get(1) {
            let piped = re_tag().replace_all(g.as_str(), "|").to_string();
            let collapsed = re_pipe().replace_all(&piped, "|").to_string();
            let t = collapsed.trim_matches('|').trim();
            if !t.is_empty() {
                out.insert("exitIpType".to_string(), json!(truncate_chars(t, 40)));
            }
        }
    }
    if let Some(c) = re_nativeip().captures(body) {
        if let Some(g) = c.get(1) {
            let t = re_tag().replace_all(g.as_str(), "").to_string();
            let t = t.trim();
            if !t.is_empty() {
                out.insert("exitNativeIp".to_string(), json!(truncate_chars(t, 20)));
            }
        }
    }
    Value::Object(out)
}

/// 解析 ping0.cc 页面：被拦截返回 None，否则返回（可能为空的）对象。
pub fn parse_ping0(body: &str) -> Option<Value> {
    if ping0_blocked(body) {
        None
    } else {
        Some(extract_ping0(body))
    }
}

// ---------- ippure 解析 ----------

/// 解析 my.ippure.com/v1/info 响应体（纯函数）。
pub fn parse_ippure(d: &Value) -> Value {
    let mut out = Map::new();
    if let Some(fs) = d.get("fraudScore") {
        if let Some(n) = py_int(fs) {
            out.insert("exitRisk".to_string(), json!(n));
        }
    }
    out.insert(
        "exitResidential".to_string(),
        json!(field_truthy(d, "isResidential")),
    );
    let cc = str_field(d, "countryCode").to_uppercase();
    if cc.chars().count() == 2 {
        out.insert(
            "exitCountry".to_string(),
            json!(country_cn(Some(cc.as_str()))),
        );
        out.insert("exitFlag".to_string(), json!(country_flag(cc.as_str())));
    }
    if let Some(city) = d.get("city") {
        if truthy(Some(city)) {
            out.insert("exitCity".to_string(), city.clone());
        }
    }
    if let Some(asn) = d.get("asn") {
        if truthy(Some(asn)) {
            out.insert("exitAsn".to_string(), json!(format!("AS{}", py_repr(asn))));
        }
    }
    Value::Object(out)
}

// ---------- 缓存 ----------

#[derive(Clone, Debug)]
struct Entry {
    ts: Instant,
    data: Value,
}

type Store = OnceLock<Mutex<HashMap<String, Entry>>>;

static CACHE: Store = OnceLock::new();
static PING0_CACHE: Store = OnceLock::new();
static IPPURE_CACHE: Store = OnceLock::new();

fn lock(store: &Store) -> MutexGuard<'_, HashMap<String, Entry>> {
    match store.get_or_init(|| Mutex::new(HashMap::new())).lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn cached(store: &Store, key: &str, ttl: Duration) -> Option<Value> {
    let mut g = lock(store);
    let expired = {
        let e = g.get(key)?;
        e.ts.elapsed() > ttl
    };
    if expired {
        g.remove(key);
        return None;
    }
    g.get(key).map(|e| e.data.clone())
}

fn store_entry(store: &Store, key: &str, data: &Value, max: usize, evict: usize, ts: Instant) {
    let mut g = lock(store);
    g.insert(
        key.to_string(),
        Entry {
            ts,
            data: data.clone(),
        },
    );
    if g.len() > max {
        let mut keys: Vec<(Instant, String)> = g.iter().map(|(k, v)| (v.ts, k.clone())).collect();
        keys.sort_by_key(|(ts, _)| *ts);
        for (_, k) in keys.into_iter().take(evict) {
            g.remove(&k);
        }
    }
}

fn store(store: &Store, key: &str, data: &Value, max: usize, evict: usize) {
    store_entry(store, key, data, max, evict, Instant::now());
}

/// 清空全部缓存（测试与热更新用）。
pub fn clear_caches() {
    lock(&CACHE).clear();
    lock(&PING0_CACHE).clear();
    lock(&IPPURE_CACHE).clear();
}

/// 当前缓存条数（诊断用）：0=lookup, 1=ping0, 2=ippure。
pub fn cache_len(kind: u8) -> usize {
    match kind {
        0 => lock(&CACHE).len(),
        1 => lock(&PING0_CACHE).len(),
        _ => lock(&IPPURE_CACHE).len(),
    }
}

// ---------- HTTP ----------

fn build_proxied_client(proxy: &str, timeout: Duration) -> Option<Client> {
    let p = reqwest::Proxy::all(proxy).ok()?;
    Client::builder().proxy(p).timeout(timeout).build().ok()
}

async fn fetch_text(
    client: &Client,
    url: &str,
    timeout: Duration,
    proxy: Option<&str>,
) -> Option<String> {
    let owned;
    let c: &Client = match proxy {
        Some(p) => {
            owned = build_proxied_client(p, timeout)?;
            &owned
        }
        None => client,
    };
    let resp = c
        .get(url)
        .header(reqwest::header::USER_AGENT, UA)
        .timeout(timeout)
        .send()
        .await
        .ok()?;
    if resp.status().as_u16() != 200 {
        return None;
    }
    resp.text().await.ok()
}

async fn fetch_json(
    client: &Client,
    url: &str,
    timeout: Duration,
    proxy: Option<&str>,
) -> Option<Value> {
    let body = fetch_text(client, url, timeout, proxy).await?;
    serde_json::from_str::<Value>(&body).ok()
}

// ---------- 节点代理 ----------

/// 一个 sing-box 入站节点（取其 127.0.0.1 端口与 http 代理凭据）。
#[derive(Clone, Debug, Default)]
pub struct ProxyNode {
    pub port: u16,
    pub auth_user: Option<String>,
    pub auth_pass: Option<String>,
}

impl ProxyNode {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            auth_user: None,
            auth_pass: None,
        }
    }

    pub fn with_auth(port: u16, user: Option<&str>, pass: Option<&str>) -> Self {
        Self {
            port,
            auth_user: user.map(|s| s.to_string()),
            auth_pass: pass.map(|s| s.to_string()),
        }
    }

    /// 从节点配置对象解析；port 缺失或非法返回 None。
    pub fn from_value(v: &Value) -> Option<Self> {
        let port = v.get("port").and_then(|p| match p {
            Value::Number(n) => n.as_u64().or_else(|| n.as_f64().map(|f| f as u64)),
            Value::String(s) => s.trim().parse::<u64>().ok(),
            _ => None,
        })?;
        if port == 0 || port > u16::MAX as u64 {
            return None;
        }
        let auth_user = v
            .get("authUser")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let auth_pass = v
            .get("authPass")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        Some(Self {
            port: port as u16,
            auth_user,
            auth_pass,
        })
    }

    /// http://user:pass@127.0.0.1:port（Python: authUser or "user" / authPass or "pass"）
    pub fn http_proxy(&self) -> String {
        proxy_url(
            self.port,
            self.auth_user.as_deref(),
            self.auth_pass.as_deref(),
        )
    }
}

/// 拼节点 http 代理 URL；user/pass 空则回退 "user"/"pass"。
pub fn proxy_url(port: u16, user: Option<&str>, pass: Option<&str>) -> String {
    let u = match user {
        Some(s) if !s.is_empty() => s,
        _ => "user",
    };
    let p = match pass {
        Some(s) if !s.is_empty() => s,
        _ => "pass",
    };
    format!("http://{}:{}@127.0.0.1:{}", u, p, port)
}

// ---------- 对外接口：归属地 ----------

/// 可注入的数据源端点（默认指向真实服务）。
#[derive(Clone, Debug)]
pub struct Endpoints {
    pub ipinfo: String,
    pub ipapi: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            ipinfo: IPINFO_BASE.to_string(),
            ipapi: IPAPI_BASE.to_string(),
        }
    }
}

impl Endpoints {
    pub fn new(ipinfo: &str, ipapi: &str) -> Self {
        Self {
            ipinfo: ipinfo.to_string(),
            ipapi: ipapi.to_string(),
        }
    }
}

/// 查 IP 情报并缓存 24h。空 IP / "N/A" / "1.1.1.1" 直接短路，不发请求。
pub async fn lookup(client: &Client, ip: &str) -> Value {
    lookup_with_endpoints(client, ip, &Endpoints::default()).await
}

/// 同 lookup，但数据源端点可注入（测试用）。
pub async fn lookup_with_endpoints(client: &Client, ip: &str, ep: &Endpoints) -> Value {
    if ip.is_empty() || ip == "N/A" || ip == "1.1.1.1" {
        return json!({ "exitIp": ip });
    }
    if let Some(hit) = cached(&CACHE, ip, CACHE_TTL) {
        return hit;
    }
    let base_i = ep.ipinfo.trim_end_matches('/');
    let base_a = ep.ipapi.trim_end_matches('/');
    let info = fetch_json(
        client,
        &format!("{}/{}/json", base_i, ip),
        IPINFO_TIMEOUT,
        None,
    )
    .await;
    let ipapis = fetch_json(
        client,
        &format!("{}/?q={}", base_a, ip),
        IPAPI_TIMEOUT,
        None,
    )
    .await;
    let result = build_lookup_result(ip, info.as_ref(), ipapis.as_ref());
    store(&CACHE, ip, &result, CACHE_MAX, CACHE_EVICT);
    result
}

// ---------- 对外接口：ping0.cc ----------

/// 经节点代理查 ping0.cc 风控情报（单代理）。被拦截或失败返回空对象。
pub async fn lookup_ping0(client: &Client, ip: &str, proxy: Option<&str>) -> Value {
    lookup_ping0_with_base(client, ip, proxy, PING0_BASE).await
}

/// 同 lookup_ping0，base 可注入（测试用）；base 为 "https://ping0.cc" 形态。
pub async fn lookup_ping0_with_base(
    client: &Client,
    ip: &str,
    proxy: Option<&str>,
    base: &str,
) -> Value {
    if ip.is_empty() {
        return json!({});
    }
    if let Some(hit) = cached(&PING0_CACHE, ip, ENRICH_TTL) {
        return hit;
    }
    let url = format!("{}/ip/{}", base.trim_end_matches('/'), ip);
    let body = match fetch_text(client, &url, PING0_TIMEOUT, proxy).await {
        Some(b) => b,
        None => return json!({}),
    };
    match parse_ping0(&body) {
        Some(v) if truthy(Some(&v)) => {
            store(&PING0_CACHE, ip, &v, ENRICH_MAX, ENRICH_EVICT);
            v
        }
        _ => json!({}),
    }
}

/// 逐节点重试（Python lookup_ping0(ip, nodes)）：任一节点拿到有效数据即返回并缓存。
pub async fn lookup_ping0_nodes(client: &Client, ip: &str, nodes: &[ProxyNode]) -> Value {
    if ip.is_empty() || nodes.is_empty() {
        return json!({});
    }
    if let Some(hit) = cached(&PING0_CACHE, ip, ENRICH_TTL) {
        return hit;
    }
    for n in nodes {
        let proxy = n.http_proxy();
        let data = lookup_ping0_with_base(client, ip, Some(proxy.as_str()), PING0_BASE).await;
        if truthy(Some(&data)) {
            return data;
        }
    }
    json!({})
}

// ---------- 对外接口：ippure ----------

/// 经节点代理查 IPPure 出口情报。ip 为预期出口 IP（缓存键 + 返回体校验参考）。
pub async fn lookup_ippure(client: &Client, ip: &str, proxy: Option<&str>) -> Value {
    lookup_ippure_with_url(client, ip, proxy, IPPURE_URL).await
}

/// 同 lookup_ippure，URL 可注入（测试用）。
pub async fn lookup_ippure_with_url(
    client: &Client,
    ip: &str,
    proxy: Option<&str>,
    url: &str,
) -> Value {
    if let Some(hit) = cached(&IPPURE_CACHE, ip, ENRICH_TTL) {
        return hit;
    }
    let d = match fetch_json(client, url, IPPURE_TIMEOUT, proxy).await {
        Some(v) if truthy(Some(&v)) => v,
        _ => return json!({}),
    };
    let ret_ip = match d.get("ip") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return json!({}),
    };
    if let Some(hit) = cached(&IPPURE_CACHE, &ret_ip, ENRICH_TTL) {
        return hit;
    }
    let mut data = parse_ippure(&d);
    if let Some(obj) = data.as_object_mut() {
        obj.insert("exitIp".to_string(), json!(ret_ip));
    }
    store(&IPPURE_CACHE, &ret_ip, &data, ENRICH_MAX, ENRICH_EVICT);
    data
}

/// 逐节点重试（Python lookup_ippure(nodes)）：返回第一个拿到数据的节点的出口情报。
pub async fn lookup_ippure_nodes(client: &Client, ip: &str, nodes: &[ProxyNode]) -> Value {
    if nodes.is_empty() {
        return json!({});
    }
    for n in nodes {
        let proxy = n.http_proxy();
        let data = lookup_ippure_with_url(client, ip, Some(proxy.as_str()), IPPURE_URL).await;
        if truthy(Some(&data)) {
            return data;
        }
    }
    json!({})
}

#[cfg(test)]
#[allow(clippy::await_holding_lock)] // 测试用全局缓存串行锁，跨 await 持锁是有意的
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// 全局缓存是所有用例共享的静态量，凡碰缓存的用例串行执行，避免互相清空。
    fn test_lock() -> MutexGuard<'static, ()> {
        static M: OnceLock<Mutex<()>> = OnceLock::new();
        match M.get_or_init(|| Mutex::new(())).lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    // ---------- 纯函数：国旗 / 中文名 / 评分 / 类型 ----------

    #[test]
    fn flag_uses_regional_indicators() {
        assert_eq!(country_flag("US"), "\u{1F1FA}\u{1F1F8}");
        assert_eq!(country_flag("us"), "\u{1F1FA}\u{1F1F8}");
        assert_eq!(country_flag("jp"), "\u{1F1EF}\u{1F1F5}");
        assert_eq!(country_flag("SG"), "\u{1F1F8}\u{1F1EC}");
        // 与 Python ord('U')+0x1F1E6-ord('A') 对齐
        assert_eq!(
            country_flag("US"),
            char::from_u32('U' as u32 + FLAG_OFFSET)
                .unwrap()
                .to_string()
                + &char::from_u32('S' as u32 + FLAG_OFFSET)
                    .unwrap()
                    .to_string()
        );
    }

    #[test]
    fn flag_edge_cases() {
        assert_eq!(country_flag(""), "");
        assert_eq!(country_flag("U"), "");
        assert_eq!(country_flag("USA"), "");
        // 非字母的 2 字符：Python chr(ord+offset) 同样成功，只求 2 个码点
        assert_eq!(country_flag("1A").chars().count(), 2);
    }

    #[test]
    fn country_cn_maps_and_falls_back() {
        assert_eq!(country_cn(Some("US")), "美国");
        assert_eq!(country_cn(Some("hk")), "中国香港");
        assert_eq!(country_cn(Some("MO")), "中国澳门");
        assert_eq!(country_cn(Some("ZZ")), "ZZ");
        assert_eq!(country_cn(Some("zz")), "ZZ");
        assert_eq!(country_cn(None), "");
        assert_eq!(country_cn(Some("")), "");
    }

    #[test]
    fn score_follows_python_rules() {
        assert_eq!(exit_score(None), 0);
        assert_eq!(exit_score(Some(&json!({}))), 0);
        assert_eq!(exit_score(Some(&json!({"is_bogon": true}))), 0);
        assert_eq!(exit_score(Some(&json!({"is_abuser": true}))), 10);
        assert_eq!(exit_score(Some(&json!({"is_datacenter": true}))), 40);
        assert_eq!(exit_score(Some(&json!({"is_vpn": true}))), 30);
        assert_eq!(exit_score(Some(&json!({"is_proxy": true}))), 30);
        assert_eq!(exit_score(Some(&json!({"is_tor": true}))), 30);
        assert_eq!(exit_score(Some(&json!({"is_datacenter": false}))), 100);
        // 优先级：bogon > abuser > datacenter > vpn/proxy/tor
        assert_eq!(
            exit_score(Some(&json!({"is_bogon": true, "is_datacenter": true}))),
            0
        );
        assert_eq!(
            exit_score(Some(&json!({"is_abuser": true, "is_datacenter": true}))),
            10
        );
        assert_eq!(
            exit_score(Some(&json!({"is_datacenter": true, "is_vpn": true}))),
            40
        );
        // Python 真值语义：空串/0 为假
        assert_eq!(exit_score(Some(&json!({"is_vpn": ""}))), 100);
        assert_eq!(exit_score(Some(&json!({"is_vpn": 0}))), 100);
    }

    #[test]
    fn ip_type_follows_python_rules() {
        assert_eq!(ip_type(None), "unknown");
        assert_eq!(ip_type(Some(&json!({}))), "unknown");
        assert_eq!(ip_type(Some(&json!({"is_bogon": true}))), "unknown");
        assert_eq!(ip_type(Some(&json!({"is_datacenter": true}))), "hosting");
        assert_eq!(ip_type(Some(&json!({"is_proxy": true}))), "proxy");
        assert_eq!(ip_type(Some(&json!({"is_abuser": true}))), "hosting");
        assert_eq!(ip_type(Some(&json!({"is_abuser": false}))), "residential");
        // 优先级：datacenter 先于 vpn/proxy/tor
        assert_eq!(
            ip_type(Some(&json!({"is_datacenter": true, "is_tor": true}))),
            "hosting"
        );
    }

    // ---------- 纯函数：lookup 结果组装 ----------

    #[test]
    fn build_result_maps_fields_like_python() {
        let info = json!({"country": "us", "city": "Ashburn", "org": "AS14618 Amazon.com, Inc."});
        let ipapis = json!({"is_datacenter": true});
        let r = build_lookup_result("1.2.3.4", Some(&info), Some(&ipapis));
        assert_eq!(r["exitIp"], json!("1.2.3.4"));
        assert_eq!(r["exitCountry"], json!("美国"));
        assert_eq!(r["exitFlag"], json!("\u{1F1FA}\u{1F1F8}"));
        assert_eq!(r["exitCity"], json!("Ashburn"));
        assert_eq!(r["exitType"], json!("hosting"));
        assert_eq!(r["exitScore"], json!(40));
        assert_eq!(r["exitOrg"], json!("AS14618 Amazon.com, Inc."));
        assert_eq!(r["exitAsn"], json!("AS14618"));
        assert_eq!(r.as_object().map(|o| o.len()), Some(8));
    }

    #[test]
    fn build_result_degrades_when_sources_missing() {
        let r = build_lookup_result("9.9.9.9", None, None);
        assert_eq!(r["exitIp"], json!("9.9.9.9"));
        assert_eq!(r["exitCountry"], json!(""));
        assert_eq!(r["exitFlag"], json!(""));
        assert_eq!(r["exitCity"], json!(""));
        assert_eq!(r["exitType"], json!("unknown"));
        assert_eq!(r["exitScore"], json!(0));
        assert_eq!(r["exitOrg"], json!(""));
        assert_eq!(r["exitAsn"], json!(""));
        // 空对象与 Python 的 not ipapis 等价
        let r2 = build_lookup_result("9.9.9.9", Some(&json!({})), Some(&json!({})));
        assert_eq!(r2["exitType"], json!("unknown"));
        assert_eq!(r2["exitScore"], json!(0));
    }

    #[test]
    fn build_result_asn_needs_space_in_org() {
        let r = build_lookup_result("1.2.3.4", Some(&json!({"org": "NoSpaceOrg"})), None);
        assert_eq!(r["exitOrg"], json!("NoSpaceOrg"));
        assert_eq!(r["exitAsn"], json!(""));
        // 类型异常降级不 panic（Python 版此处 AttributeError）
        let r2 = build_lookup_result("1.2.3.4", Some(&json!({"country": 42, "city": 7})), None);
        assert_eq!(r2["exitCountry"], json!(""));
        assert_eq!(r2["exitCity"], json!(""));
    }

    // ---------- 纯函数：ping0 解析 ----------

    const PING0_HTML: &str = concat!(
        "<html><body>",
        "<div class=\"riskcurrent\"><span class=\"value\">",
        "17%</span><span class=\"lab\"> 纯净 </span></div>",
        "<div class=\"line-iptype\"><div class=\"content\">",
        "<span class=\"tag\">IDC</span>|<b>机房</b>|美国 加州",
        "</div></div>",
        "<div class=\"line-nativeip\"><div class=\"content\">",
        "<i>原生 IP</i> <em>103.152.2.9</em>",
        "</div></div>",
        "</body></html>"
    );

    #[test]
    fn ping0_extracts_risk_label_type_and_native_ip() {
        let v = extract_ping0(PING0_HTML);
        assert_eq!(v["exitRisk"], json!(17));
        assert_eq!(v["exitRiskLabel"], json!("纯净"));
        assert_eq!(v["exitIpType"], json!("IDC|机房|美国 加州"));
        assert_eq!(v["exitNativeIp"], json!("原生 IP 103.152.2.9"));
    }

    #[test]
    fn ping0_missing_sections_yield_empty_object() {
        let v = extract_ping0("<html><body>nothing here</body></html>");
        assert_eq!(v, json!({}));
        assert_eq!(v.as_object().map(|o| o.len()), Some(0));
    }

    #[test]
    fn ping0_truncates_type_40_and_native_20_chars() {
        let long_type = "A".repeat(60);
        let long_ip = "B".repeat(40);
        let html = format!(
            "<div class=\"riskcurrent\"><span class=\"value\">9%</span><span class=\"lab\">bad</span></div>\
             <div class=\"line-iptype\"><div class=\"content\">{}</div></div>\
             <div class=\"line-nativeip\"><div class=\"content\">{}</div></div>",
            long_type, long_ip
        );
        let v = extract_ping0(&html);
        assert_eq!(v["exitIpType"], json!("A".repeat(40)));
        assert_eq!(v["exitNativeIp"], json!("B".repeat(20)));
    }

    #[test]
    fn ping0_leaves_pipe_only_wrapper_empty() {
        // 内容全是标签时，折叠后 strip('|') 为空 -> 不写 exitIpType
        let html = "<div class=\"line-iptype\"><div class=\"content\"><span></span></div></div>";
        let v = extract_ping0(html);
        assert!(v.get("exitIpType").is_none());
    }

    #[test]
    fn ping0_gate_blocks_short_or_turnstile_pages() {
        assert!(ping0_blocked(PING0_HTML), "短页面应判定为拦截");
        assert_eq!(parse_ping0(PING0_HTML), None);
        let padded = format!("{}{}", PING0_HTML, "x".repeat(PING0_MIN_BODY));
        assert!(!ping0_blocked(&padded));
        assert!(parse_ping0(&padded).is_some());
        let cf = format!(
            "{}{}",
            "y".repeat(PING0_MIN_BODY),
            "<script>Turnstile</script>"
        );
        assert!(ping0_blocked(&cf), "含 turnstile 应判定为拦截");
        assert_eq!(parse_ping0(&cf), None);
    }

    // ---------- 纯函数：ippure 解析 ----------

    #[test]
    fn ippure_parse_maps_fields() {
        let d = json!({
            "ip": "103.152.2.9",
            "fraudScore": 42,
            "isResidential": true,
            "countryCode": "hk",
            "city": "Hong Kong",
            "asn": 138421
        });
        let v = parse_ippure(&d);
        assert_eq!(v["exitRisk"], json!(42));
        assert_eq!(v["exitResidential"], json!(true));
        assert_eq!(v["exitCountry"], json!("中国香港"));
        assert_eq!(v["exitFlag"], json!("\u{1F1ED}\u{1F1F0}"));
        assert_eq!(v["exitCity"], json!("Hong Kong"));
        assert_eq!(v["exitAsn"], json!("AS138421"));
        assert!(v.get("exitIp").is_none(), "exitIp 由 lookup_ippure 补");
    }

    #[test]
    fn ippure_parse_omits_absent_and_keeps_python_int_semantics() {
        let v = parse_ippure(&json!({}));
        assert_eq!(v["exitResidential"], json!(false));
        assert!(v.get("exitRisk").is_none());
        assert!(v.get("exitCountry").is_none());
        // fraudScore 为字符串：Python isinstance 不认，跳过
        let v2 = parse_ippure(&json!({"fraudScore": "42"}));
        assert!(v2.get("exitRisk").is_none());
        // 浮点向零截断 int(3.9)=3
        let v3 = parse_ippure(&json!({"fraudScore": 3.9}));
        assert_eq!(v3["exitRisk"], json!(3));
        // 越界值不做裁剪（Python 同样不裁剪）
        let v4 = parse_ippure(&json!({"fraudScore": 250}));
        assert_eq!(v4["exitRisk"], json!(250));
        let v5 = parse_ippure(&json!({"fraudScore": -5}));
        assert_eq!(v5["exitRisk"], json!(-5));
    }

    #[test]
    fn ippure_country_code_needs_two_chars() {
        let v = parse_ippure(&json!({"countryCode": "USA"}));
        assert!(v.get("exitCountry").is_none());
        let v2 = parse_ippure(&json!({"countryCode": ""}));
        assert!(v2.get("exitCountry").is_none());
        let v3 = parse_ippure(&json!({"countryCode": "zz"}));
        assert_eq!(v3["exitCountry"], json!("ZZ"));
    }

    // ---------- 代理拼接 ----------

    #[test]
    fn proxy_url_uses_python_defaults() {
        assert_eq!(
            proxy_url(51033, Some("alice"), Some("s3cret")),
            "http://alice:s3cret@127.0.0.1:51033"
        );
        assert_eq!(
            proxy_url(51033, None, None),
            "http://user:pass@127.0.0.1:51033"
        );
        assert_eq!(
            proxy_url(51033, Some(""), Some("")),
            "http://user:pass@127.0.0.1:51033"
        );
        let n = ProxyNode::from_value(&json!({"port": 51013, "authUser": "u", "authPass": "p"}))
            .expect("node");
        assert_eq!(n.http_proxy(), "http://u:p@127.0.0.1:51013");
        assert!(ProxyNode::from_value(&json!({})).is_none());
        assert!(ProxyNode::from_value(&json!({"port": 0})).is_none());
        assert!(ProxyNode::from_value(&json!({"port": 70000})).is_none());
    }

    // ---------- 缓存 ----------

    #[test]
    fn cache_hit_and_expiry() {
        let _g = test_lock();
        clear_caches();
        let v = json!({"exitIp": "5.5.5.5"});
        store(&CACHE, "5.5.5.5", &v, CACHE_MAX, CACHE_EVICT);
        assert_eq!(cached(&CACHE, "5.5.5.5", CACHE_TTL), Some(v.clone()));
        assert_eq!(cached(&CACHE, "6.6.6.6", CACHE_TTL), None);
        // 写入 25 小时前的条目视为过期
        store_entry(
            &CACHE,
            "7.7.7.7",
            &v,
            CACHE_MAX,
            CACHE_EVICT,
            Instant::now() - Duration::from_secs(25 * 3600),
        );
        assert_eq!(cached(&CACHE, "7.7.7.7", CACHE_TTL), None);
        assert_eq!(cache_len(0), 1, "过期条目应被删除");
    }

    #[test]
    fn cache_evicts_oldest_on_overflow() {
        let _g = test_lock();
        clear_caches();
        let v = json!({"exitIp": "x"});
        for i in 0..=CACHE_MAX {
            let key = format!("10.0.{}.{}", i / 256, i % 256);
            store_entry(
                &CACHE,
                &key,
                &v,
                CACHE_MAX,
                CACHE_EVICT,
                Instant::now() + Duration::from_millis(i as u64),
            );
        }
        assert_eq!(cache_len(0), CACHE_MAX + 1 - CACHE_EVICT);
        // 最旧的 1000 条被清掉
        assert_eq!(cached(&CACHE, "10.0.0.0", CACHE_TTL), None);
        assert!(cached(&CACHE, "10.0.4.0", CACHE_TTL).is_some());
    }

    // ---------- 本地假端点 ----------

    #[derive(Clone)]
    struct FakeRoute {
        prefix: &'static str,
        status: u16,
        body: String,
        delay_ms: u64,
    }

    async fn spawn_fake(routes: Vec<FakeRoute>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let routes = routes.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = match sock.read(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_string();
                    let hit = routes.iter().find(|r| path.starts_with(r.prefix));
                    let (status, body, delay) = match hit {
                        Some(r) => (r.status, r.body.clone(), r.delay_ms),
                        None => (404u16, String::from("{}"), 0u64),
                    };
                    if delay > 0 {
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }
                    let resp = format!(
                        "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status,
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.flush().await;
                });
            }
        });
        format!("http://{}", addr)
    }

    fn client() -> Client {
        Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("client")
    }

    #[tokio::test]
    async fn lookup_short_circuits_without_network() {
        let _g = test_lock();
        clear_caches();
        // 指向必然拒绝连接的端口：若真发请求会返回空字段而非 exitIp-only
        let ep = Endpoints::new("http://127.0.0.1:1", "http://127.0.0.1:1");
        for ip in ["", "N/A", "1.1.1.1"] {
            let v = lookup_with_endpoints(&client(), ip, &ep).await;
            assert_eq!(v, json!({"exitIp": ip}));
            assert_eq!(v.as_object().map(|o| o.len()), Some(1));
        }
        assert_eq!(cache_len(0), 0, "短路不得写缓存");
    }

    #[tokio::test]
    async fn lookup_maps_real_endpoint_payloads() {
        let _g = test_lock();
        clear_caches();
        let base = spawn_fake(vec![
            FakeRoute {
                prefix: "/1.2.3.4/json",
                status: 200,
                body: json!({"ip":"1.2.3.4","country":"JP","city":"Tokyo","org":"AS2516 KDDI CORPORATION"}).to_string(),
                delay_ms: 0,
            },
            FakeRoute {
                prefix: "/?q=1.2.3.4",
                status: 200,
                body: json!({"is_vpn": true, "is_datacenter": false}).to_string(),
                delay_ms: 0,
            },
        ])
        .await;
        let ep = Endpoints::new(&base, &base);
        let v = lookup_with_endpoints(&client(), "1.2.3.4", &ep).await;
        assert_eq!(v["exitIp"], json!("1.2.3.4"));
        assert_eq!(v["exitCountry"], json!("日本"));
        assert_eq!(v["exitFlag"], json!("\u{1F1EF}\u{1F1F5}"));
        assert_eq!(v["exitCity"], json!("Tokyo"));
        assert_eq!(v["exitType"], json!("proxy"));
        assert_eq!(v["exitScore"], json!(30));
        assert_eq!(v["exitAsn"], json!("AS2516"));
        assert_eq!(v["exitOrg"], json!("AS2516 KDDI CORPORATION"));
        assert_eq!(cache_len(0), 1);
    }

    #[tokio::test]
    async fn lookup_degrades_on_missing_fields_non_200_and_non_json() {
        let _g = test_lock();
        clear_caches();
        let base = spawn_fake(vec![
            FakeRoute {
                prefix: "/1.1.1.2/json",
                status: 200,
                body: json!({"city": "Nowhere"}).to_string(),
                delay_ms: 0,
            },
            FakeRoute {
                prefix: "/?q=1.1.1.2",
                status: 429,
                body: json!({"is_datacenter": true}).to_string(),
                delay_ms: 0,
            },
            FakeRoute {
                prefix: "/1.1.1.3/json",
                status: 200,
                body: "<html>not json</html>".to_string(),
                delay_ms: 0,
            },
            FakeRoute {
                prefix: "/?q=1.1.1.3",
                status: 200,
                body: json!({"is_datacenter": true}).to_string(),
                delay_ms: 0,
            },
        ])
        .await;
        let ep = Endpoints::new(&base, &base);

        // 缺字段 + ipapi 非 200 -> 只有 city 有值，评分为 0
        let v = lookup_with_endpoints(&client(), "1.1.1.2", &ep).await;
        assert_eq!(v["exitCity"], json!("Nowhere"));
        assert_eq!(v["exitCountry"], json!(""));
        assert_eq!(v["exitType"], json!("unknown"));
        assert_eq!(v["exitScore"], json!(0));

        // ipinfo 返回非 JSON -> 归属地字段全空，ipapi 正常
        let v2 = lookup_with_endpoints(&client(), "1.1.1.3", &ep).await;
        assert_eq!(v2["exitCountry"], json!(""));
        assert_eq!(v2["exitType"], json!("hosting"));
        assert_eq!(v2["exitScore"], json!(40));
    }

    #[tokio::test]
    async fn lookup_uses_cache_on_second_call() {
        let _g = test_lock();
        clear_caches();
        let base = spawn_fake(vec![FakeRoute {
            prefix: "/8.8.4.4/json",
            status: 200,
            body: json!({"country": "SG", "city": "Singapore", "org": "AS13335 CLOUDFLARENET"})
                .to_string(),
            delay_ms: 0,
        }])
        .await;
        let ep = Endpoints::new(&base, &base);
        let first = lookup_with_endpoints(&client(), "8.8.4.4", &ep).await;
        assert_eq!(first["exitCountry"], json!("新加坡"));
        // 换到不可达端点；命中缓存则仍返回首次结果
        let dead = Endpoints::new("http://127.0.0.1:1", "http://127.0.0.1:1");
        let second = lookup_with_endpoints(&client(), "8.8.4.4", &dead).await;
        assert_eq!(first, second);
        assert_eq!(cache_len(0), 1);
    }

    #[tokio::test]
    async fn fetch_json_returns_none_on_timeout() {
        let base = spawn_fake(vec![FakeRoute {
            prefix: "/slow",
            status: 200,
            body: json!({"ok": true}).to_string(),
            delay_ms: 400,
        }])
        .await;
        let url = format!("{}/slow", base);
        let got = fetch_json(&client(), &url, Duration::from_millis(80), None).await;
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn ping0_via_proxy_endpoint_parses_page() {
        let _g = test_lock();
        clear_caches();
        let body = format!(
            "{}{}",
            "<div class=\"riskcurrent\"><span class=\"value\">23%</span><span class=\"lab\"> 中风险 </span></div>\
             <div class=\"line-iptype\"><div class=\"content\"><b>住宅</b> IP</div></div>\
             <div class=\"line-nativeip\"><div class=\"content\">1.2.3.4</div></div>",
            "z".repeat(PING0_MIN_BODY)
        );
        let base = spawn_fake(vec![FakeRoute {
            prefix: "/ip/2.2.2.2",
            status: 200,
            body,
            delay_ms: 0,
        }])
        .await;
        let v = lookup_ping0_with_base(&client(), "2.2.2.2", None, &base).await;
        assert_eq!(v["exitRisk"], json!(23));
        assert_eq!(v["exitRiskLabel"], json!("中风险"));
        // Python: 标签替换成 "|"，折叠后 strip("|") 而内部 "|" 保留
        assert_eq!(v["exitIpType"], json!("住宅| IP"));
        assert_eq!(v["exitNativeIp"], json!("1.2.3.4"));
        assert_eq!(cache_len(1), 1);
        // 缓存命中：换死端点仍返回
        let v2 = lookup_ping0_with_base(&client(), "2.2.2.2", None, "http://127.0.0.1:1").await;
        assert_eq!(v, v2);
    }

    #[tokio::test]
    async fn ping0_cloudflare_page_yields_empty() {
        let _g = test_lock();
        clear_caches();
        let base = spawn_fake(vec![FakeRoute {
            prefix: "/ip/3.3.3.3",
            status: 200,
            body: "<html>turnstile challenge</html>".to_string(),
            delay_ms: 0,
        }])
        .await;
        let v = lookup_ping0_with_base(&client(), "3.3.3.3", None, &base).await;
        assert_eq!(v, json!({}));
        assert_eq!(cache_len(1), 0, "拦截结果不缓存");
    }

    #[tokio::test]
    async fn ippure_lookup_adds_exit_ip_and_caches() {
        let _g = test_lock();
        clear_caches();
        let base = spawn_fake(vec![FakeRoute {
            prefix: "/v1/info",
            status: 200,
            body: json!({"ip":"4.4.4.4","fraudScore":7,"isResidential":false,"countryCode":"US","city":"LA","asn":"AS999"}).to_string(),
            delay_ms: 0,
        }])
        .await;
        let url = format!("{}/v1/info", base);
        let v = lookup_ippure_with_url(&client(), "4.4.4.4", None, &url).await;
        assert_eq!(v["exitIp"], json!("4.4.4.4"));
        assert_eq!(v["exitRisk"], json!(7));
        assert_eq!(v["exitResidential"], json!(false));
        assert_eq!(v["exitCountry"], json!("美国"));
        assert_eq!(v["exitAsn"], json!("ASAS999"));
        assert_eq!(cache_len(2), 1);
        let v2 = lookup_ippure_with_url(&client(), "4.4.4.4", None, "http://127.0.0.1:1").await;
        assert_eq!(v, v2);
    }

    #[tokio::test]
    async fn ippure_lookup_requires_ip_in_body() {
        let _g = test_lock();
        clear_caches();
        let base = spawn_fake(vec![FakeRoute {
            prefix: "/v1/info",
            status: 200,
            body: json!({"fraudScore": 11}).to_string(),
            delay_ms: 0,
        }])
        .await;
        let url = format!("{}/v1/info", base);
        let v = lookup_ippure_with_url(&client(), "", None, &url).await;
        assert_eq!(v, json!({}));
        assert_eq!(cache_len(2), 0);
    }

    #[tokio::test]
    async fn node_loops_return_empty_without_nodes() {
        let _g = test_lock();
        clear_caches();
        let c = client();
        assert_eq!(lookup_ping0_nodes(&c, "5.5.5.5", &[]).await, json!({}));
        assert_eq!(lookup_ippure_nodes(&c, "5.5.5.5", &[]).await, json!({}));
        assert_eq!(
            lookup_ping0(&c, "", Some("http://user:pass@127.0.0.1:1")).await,
            json!({})
        );
    }
}
