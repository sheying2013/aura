//! 流量统计与 SSE 广播。对应 backend/stats.py。
//!
//! 三条数据通路：
//! 1. `/traffic` 流式读数 → 全局上下行速率（`set_global_rate`）
//! 2. `/connections` 周期采样 → 按 outbound tag 归属到节点/中转域名，累加写库
//! 3. 1s 广播快照 → 所有 SSE 订阅者
//!
//! DB 与内核控制通过 trait 注入，本模块不直接依赖 aura::db / aura::config_manager。

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde_json::{json, Value};

pub const SAMPLE_INTERVAL: f64 = 5.0;
pub const RATE_HALF_LIFE: f64 = 5.0;
pub const TAG_MAP_REFRESH_SECS: u64 = 15;
pub const BROADCAST_SECS: u64 = 1;
pub const SSE_CHANNEL_CAPACITY: usize = 100;
pub const OUT_TAG_PREFIX: &str = "out-";
pub const RELAY_TAG_PREFIX: &str = "relay-auto-";

/// 统计需要的 DB 能力。
pub trait StatsStore: Send + Sync {
    /// 节点列表：每项须含 id/port/protocol/upTraffic/downTraffic/status/ping。
    fn list_nodes(&self) -> Vec<Value>;
    /// 中转域名列表：每项须含 id/port。
    fn list_relay_domains(&self) -> Vec<Value>;
    /// 批量累加流量（node_id → (up, down) 增量）。
    fn add_traffic_batch(&self, deltas: &HashMap<String, (u64, u64)>);
}

/// 内核控制能力（clash API / sing-box 运行态）。
pub trait ClashAccess: Send + Sync {
    fn clash_base(&self) -> String;
    fn clash_secret(&self) -> String;
    fn is_running(&self) -> bool;
}

/// outbound tag 构造函数（唯一实现在 config_manager）。
pub use crate::config_manager::outbound_tag;

#[derive(Debug, Clone, Default)]
pub struct Rate {
    pub up: f64,
    pub down: f64,
    pub ts: f64,
}

#[derive(Debug, Clone)]
pub struct ConnState {
    pub up: u64,
    pub down: u64,
    pub tag: Option<String>,
    pub node_id: Option<String>,
}

fn monotonic() -> f64 {
    use std::sync::OnceLock;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_secs_f64()
}

fn as_str(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

fn as_u64(v: &Value, k: &str) -> u64 {
    match v.get(k) {
        Some(Value::Number(n)) => n
            .as_u64()
            .or_else(|| n.as_i64().map(|i| i.max(0) as u64))
            .unwrap_or(0),
        Some(Value::String(s)) => s
            .trim()
            .parse::<f64>()
            .map(|f| if f > 0.0 { f as u64 } else { 0 })
            .unwrap_or(0),
        _ => 0,
    }
}

fn as_i64(v: &Value, k: &str) -> i64 {
    match v.get(k) {
        Some(Value::Number(n)) => n
            .as_i64()
            .or_else(|| n.as_u64().map(|u| u as i64))
            .unwrap_or(0),
        Some(Value::String(s)) => s.trim().parse::<i64>().unwrap_or(0),
        _ => 0,
    }
}

/// 从连接 chains 里找叶子 outbound tag。
/// 优先 `out-<proto>-<port>`；若叶子是 `relay-auto-<id>`，用 urltest now 兜底。
pub fn resolve_leaf_tag(
    chains: &[String],
    relay_now_cache: &HashMap<String, String>,
) -> Option<String> {
    for tag in chains.iter().rev() {
        if tag.starts_with(OUT_TAG_PREFIX) {
            return Some(tag.clone());
        }
    }
    for tag in chains.iter().rev() {
        if tag.starts_with(RELAY_TAG_PREFIX) {
            if let Some(now) = relay_now_cache.get(tag) {
                if now.starts_with(OUT_TAG_PREFIX) {
                    return Some(now.clone());
                }
            }
        }
    }
    None
}

/// 速率衰减：自上次 delta 起按 5s 半衰期衰减，无流量时趋近 0。
pub fn decayed_rate(rate: &Rate, now: f64) -> (f64, f64) {
    let age = (now - rate.ts).max(0.0);
    let decay = 0.5f64.powf(age / RATE_HALF_LIFE);
    (rate.up * decay, rate.down * decay)
}

#[derive(Debug, Default)]
struct Inner {
    global_up_rate: f64,
    global_down_rate: f64,
    conn_sample_ts: Option<f64>,
    conn_state: HashMap<String, ConnState>,
    tag_to_node: HashMap<String, String>,
    relay_tags: HashSet<String>,
    node_rate: HashMap<String, Rate>,
    relay_rate: HashMap<String, Rate>,
    relay_now_cache: HashMap<String, String>,
}

/// 一帧 /connections 采样算出的流量增量：节点 key -> (上行字节, 下行字节)。
pub type ConnDeltas = HashMap<String, (u64, u64)>;

pub struct Stats {
    inner: Mutex<Inner>,
    store: Arc<dyn StatsStore>,
    sender: tokio::sync::broadcast::Sender<String>,
}

impl Stats {
    pub fn new(store: Arc<dyn StatsStore>) -> Self {
        let (sender, _) = tokio::sync::broadcast::channel(SSE_CHANNEL_CAPACITY);
        Self {
            inner: Mutex::new(Inner::default()),
            store,
            sender,
        }
    }

    /// SSE 订阅；返回的 receiver 会自动在 drop 时注销。
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<String> {
        self.sender.subscribe()
    }

    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }

    pub fn set_global_rate(&self, up: u64, down: u64) {
        let mut g = self.inner.lock().unwrap();
        g.global_up_rate = up as f64;
        g.global_down_rate = down as f64;
    }

    pub fn reset_global_rate(&self) {
        let mut g = self.inner.lock().unwrap();
        g.global_up_rate = 0.0;
        g.global_down_rate = 0.0;
    }

    /// 重建 outbound tag → node id 映射，并清理已删除节点/域名的残留速率条目。
    pub fn refresh_tag_maps(&self) {
        let nodes = self.store.list_nodes();
        let relays = self.store.list_relay_domains();
        let mut g = self.inner.lock().unwrap();
        let mut tag_to_node = HashMap::new();
        let mut valid: HashSet<String> = HashSet::new();
        for n in &nodes {
            let id = as_str(n, "id");
            let proto = as_str(n, "protocol");
            let port = as_i64(n, "port");
            if id.is_empty() {
                continue;
            }
            tag_to_node.insert(outbound_tag(&proto, port), id.clone());
            valid.insert(id);
        }
        g.tag_to_node = tag_to_node;
        g.node_rate.retain(|k, _| valid.contains(k));
        let relay_tags: HashSet<String> = relays
            .iter()
            .map(|r| format!("{}{}", RELAY_TAG_PREFIX, as_str(r, "id")))
            .collect();
        g.relay_rate.retain(|k, _| relay_tags.contains(k));
        g.relay_now_cache.retain(|k, _| relay_tags.contains(k));
        g.relay_tags = relay_tags;
    }

    /// 写入 urltest 当前选中出口（`relay-auto-<id>` → 叶子 tag）。
    pub fn set_relay_now(&self, tag: &str, now: &str) {
        let mut g = self.inner.lock().unwrap();
        if g.relay_tags.contains(tag) {
            g.relay_now_cache.insert(tag.to_string(), now.to_string());
        }
    }

    /// 处理一帧 `/connections` 快照。返回 (节点增量, 中转增量)，调用方负责写库。
    pub fn process_connections(&self, conns: &[Value]) -> (ConnDeltas, ConnDeltas) {
        self.process_connections_at(conns, monotonic())
    }

    pub fn process_connections_at(&self, conns: &[Value], now: f64) -> (ConnDeltas, ConnDeltas) {
        let mut g = self.inner.lock().unwrap();
        let mut dt = match g.conn_sample_ts {
            Some(t) => now - t,
            None => SAMPLE_INTERVAL,
        };
        if dt <= 0.0 {
            dt = SAMPLE_INTERVAL;
        }
        let mut node_deltas: HashMap<String, (u64, u64)> = HashMap::new();
        let mut relay_deltas: HashMap<String, (u64, u64)> = HashMap::new();
        let mut next_state: HashMap<String, ConnState> = HashMap::new();
        let prev_map = std::mem::take(&mut g.conn_state);
        for c in conns {
            let cid = as_str(c, "id");
            if cid.is_empty() || next_state.contains_key(&cid) {
                continue;
            }
            let up = as_u64(c, "upload");
            let down = as_u64(c, "download");
            let chains: Vec<String> = c
                .get("chains")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let prev = prev_map.get(&cid).cloned();
            // 已建立连接的出口不会随 selector now 的轮询切换；保留已知真实叶子。
            let leaf = match prev.as_ref().and_then(|p| p.tag.clone()) {
                Some(t) => Some(t),
                None => resolve_leaf_tag(&chains, &g.relay_now_cache),
            };
            let mut node_id = leaf.as_ref().and_then(|t| g.tag_to_node.get(t).cloned());
            if let Some(p) = prev.as_ref() {
                if p.node_id.is_some() && node_id != p.node_id {
                    // 删除节点/复用端口后，不把旧连接字节记到新节点。
                    node_id = None;
                }
            }
            let dup = match prev.as_ref() {
                Some(p) if up >= p.up => up - p.up,
                _ => up,
            };
            let ddown = match prev.as_ref() {
                Some(p) if down >= p.down => down - p.down,
                _ => down,
            };
            let keep_node = prev
                .as_ref()
                .and_then(|p| p.node_id.clone())
                .or_else(|| node_id.clone());
            next_state.insert(
                cid.clone(),
                ConnState {
                    up,
                    down,
                    tag: leaf,
                    node_id: keep_node,
                },
            );
            if dup == 0 && ddown == 0 {
                continue;
            }
            if let Some(nid) = node_id {
                let e = node_deltas.entry(nid).or_insert((0, 0));
                e.0 += dup;
                e.1 += ddown;
            }
            // relay 标签与真实 leaf 是两种统计维度，不互斥；同链重复标签只记一次。
            let mut seen: HashSet<&String> = HashSet::new();
            for tag in chains.iter() {
                if !g.relay_tags.contains(tag) || !seen.insert(tag) {
                    continue;
                }
                let e = relay_deltas.entry(tag.clone()).or_insert((0, 0));
                e.0 += dup;
                e.1 += ddown;
            }
        }
        // 先按节点聚合再除一次采样周期；不叠加上一窗口，避免恒定流量速率虚增。
        g.node_rate = node_deltas
            .iter()
            .map(|(k, (u, d))| {
                (
                    k.clone(),
                    Rate {
                        up: *u as f64 / dt,
                        down: *d as f64 / dt,
                        ts: now,
                    },
                )
            })
            .collect();
        g.relay_rate = relay_deltas
            .iter()
            .map(|(k, (u, d))| {
                (
                    k.clone(),
                    Rate {
                        up: *u as f64 / dt,
                        down: *d as f64 / dt,
                        ts: now,
                    },
                )
            })
            .collect();
        g.conn_state = next_state;
        g.conn_sample_ts = Some(now);
        (node_deltas, relay_deltas)
    }

    /// 采样并写库（DB 写失败不影响内存速率）。
    pub fn sample_and_persist(&self, conns: &[Value]) -> usize {
        let (node_deltas, _relay) = self.process_connections(conns);
        if !node_deltas.is_empty() {
            self.store.add_traffic_batch(&node_deltas);
        }
        node_deltas.len()
    }

    pub fn active_connections(&self) -> usize {
        self.inner.lock().unwrap().conn_state.len()
    }

    /// 对外快照。结构对齐 stats.get_stats()：global/activeConnections/nodes/relayDomains。
    pub fn get_stats(&self) -> Value {
        self.get_stats_at(monotonic())
    }

    pub fn get_stats_at(&self, now: f64) -> Value {
        let nodes = self.store.list_nodes();
        let relays = self.store.list_relay_domains();
        let g = self.inner.lock().unwrap();
        let mut node_stats = Vec::with_capacity(nodes.len());
        let zero = Rate::default();
        for n in &nodes {
            let id = as_str(n, "id");
            let rate = g.node_rate.get(&id).unwrap_or(&zero);
            let (up_rate, down_rate) = decayed_rate(rate, now);
            node_stats.push(json!({
                "id": id,
                "port": as_i64(n, "port"),
                "upTraffic": as_u64(n, "upTraffic"),
                "downTraffic": as_u64(n, "downTraffic"),
                "upRate": up_rate,
                "downRate": down_rate,
                "status": as_str(n, "status"),
                "ping": n.get("ping").cloned().unwrap_or(Value::Null),
            }));
        }
        let mut relay_stats = Vec::with_capacity(relays.len());
        for rd in &relays {
            let id = as_str(rd, "id");
            let tag = format!("{}{}", RELAY_TAG_PREFIX, id);
            let rate = g.relay_rate.get(&tag).unwrap_or(&zero);
            let (up_rate, down_rate) = decayed_rate(rate, now);
            relay_stats.push(json!({
                "id": id,
                "port": as_i64(rd, "port"),
                "upRate": up_rate,
                "downRate": down_rate,
            }));
        }
        let up_total: u64 = nodes.iter().map(|n| as_u64(n, "upTraffic")).sum();
        let down_total: u64 = nodes.iter().map(|n| as_u64(n, "downTraffic")).sum();
        json!({
            "global": {
                "upRate": g.global_up_rate,
                "downRate": g.global_down_rate,
                "upTotal": up_total,
                "downTotal": down_total,
            },
            "activeConnections": g.conn_state.len(),
            "nodes": node_stats,
            "relayDomains": relay_stats,
        })
    }

    /// 构造一帧 SSE payload（1s 广播用）。
    pub fn broadcast_payload(&self, now_epoch: f64) -> String {
        let snap = self.get_stats();
        let g = &snap["global"];
        json!({
            "type": "traffic",
            "time": now_epoch,
            "up": g["upRate"],
            "down": g["downRate"],
            "upRate": g["upRate"],
            "downRate": g["downRate"],
            "activeConnections": snap["activeConnections"],
            "nodes": snap["nodes"],
            "relayDomains": snap["relayDomains"],
        })
        .to_string()
    }

    pub fn broadcast_once(&self, now_epoch: f64) -> usize {
        if self.sender.receiver_count() == 0 {
            return 0;
        }
        let payload = self.broadcast_payload(now_epoch);
        self.sender.send(payload).unwrap_or(0)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    struct MemStore {
        nodes: Mutex<Vec<Value>>,
        relays: Mutex<Vec<Value>>,
        batches: Mutex<Vec<HashMap<String, (u64, u64)>>>,
    }

    impl MemStore {
        fn new(nodes: Vec<Value>, relays: Vec<Value>) -> Arc<Self> {
            Arc::new(Self {
                nodes: Mutex::new(nodes),
                relays: Mutex::new(relays),
                batches: Mutex::new(Vec::new()),
            })
        }
    }

    impl StatsStore for MemStore {
        fn list_nodes(&self) -> Vec<Value> {
            self.nodes.lock().unwrap().clone()
        }
        fn list_relay_domains(&self) -> Vec<Value> {
            self.relays.lock().unwrap().clone()
        }
        fn add_traffic_batch(&self, deltas: &HashMap<String, (u64, u64)>) {
            self.batches.lock().unwrap().push(deltas.clone());
        }
    }

    fn node(id: &str, port: i64, proto: &str) -> Value {
        json!({"id": id, "port": port, "protocol": proto, "upTraffic": 10, "downTraffic": 20, "status": "online", "ping": 88})
    }

    fn conn(id: &str, up: u64, down: u64, chains: &[&str]) -> Value {
        json!({"id": id, "upload": up, "download": down, "chains": chains})
    }

    fn mk(nodes: Vec<Value>, relays: Vec<Value>) -> (Arc<MemStore>, Stats) {
        let store = MemStore::new(nodes, relays);
        let stats = Stats::new(store.clone());
        stats.refresh_tag_maps();
        (store, stats)
    }

    #[test]
    fn outbound_tag_matches_config_manager_format() {
        assert_eq!(outbound_tag("socks5", 51000), "out-socks5-51000");
        assert_eq!(outbound_tag("ss", 19001), "out-ss-19001");
    }

    #[test]
    fn resolve_leaf_tag_prefers_out_prefix() {
        let cache = HashMap::new();
        let chains = vec![
            "GLOBAL".to_string(),
            "relay-auto-1".to_string(),
            "out-socks5-51000".to_string(),
        ];
        assert_eq!(
            resolve_leaf_tag(&chains, &cache).as_deref(),
            Some("out-socks5-51000")
        );
        // 反向优先：最后一个 out- 胜出
        let chains = vec!["out-socks5-1".to_string(), "out-socks5-2".to_string()];
        assert_eq!(
            resolve_leaf_tag(&chains, &cache).as_deref(),
            Some("out-socks5-2")
        );
    }

    #[test]
    fn resolve_leaf_tag_falls_back_to_relay_now() {
        let mut cache = HashMap::new();
        cache.insert("relay-auto-7".to_string(), "out-socks5-52000".to_string());
        let chains = vec!["GLOBAL".to_string(), "relay-auto-7".to_string()];
        assert_eq!(
            resolve_leaf_tag(&chains, &cache).as_deref(),
            Some("out-socks5-52000")
        );
        // now 指向非 out- 时不采纳
        let mut cache2 = HashMap::new();
        cache2.insert("relay-auto-7".to_string(), "DIRECT".to_string());
        assert_eq!(resolve_leaf_tag(&chains, &cache2), None);
        let empty: Vec<String> = vec![];
        assert_eq!(resolve_leaf_tag(&empty, &cache), None);
    }

    #[test]
    fn decayed_rate_halves_every_five_seconds() {
        let r = Rate {
            up: 100.0,
            down: 40.0,
            ts: 1000.0,
        };
        let (u0, d0) = decayed_rate(&r, 1000.0);
        assert!((u0 - 100.0).abs() < 1e-9);
        assert!((d0 - 40.0).abs() < 1e-9);
        let (u5, d5) = decayed_rate(&r, 1005.0);
        assert!((u5 - 50.0).abs() < 1e-9, "u5={}", u5);
        assert!((d5 - 20.0).abs() < 1e-9);
        let (u10, _) = decayed_rate(&r, 1010.0);
        assert!((u10 - 25.0).abs() < 1e-9);
        // 未来时间戳不放大速率
        let (uf, _) = decayed_rate(&r, 900.0);
        assert!((uf - 100.0).abs() < 1e-9);
    }

    #[test]
    fn first_sample_counts_full_bytes() {
        let (_store, stats) = mk(vec![node("n1", 51000, "socks5")], vec![]);
        let conns = vec![conn("c1", 100, 200, &["GLOBAL", "out-socks5-51000"])];
        let (node_deltas, relay_deltas) = stats.process_connections_at(&conns, 100.0);
        assert_eq!(node_deltas.get("n1"), Some(&(100, 200)));
        assert!(relay_deltas.is_empty());
        // 首次 dt 用 SAMPLE_INTERVAL=5s
        let snap = stats.get_stats_at(100.0);
        assert_eq!(snap["activeConnections"], 1);
        let n0 = &snap["nodes"][0];
        assert_eq!(n0["id"], "n1");
        assert!((n0["upRate"].as_f64().unwrap() - 20.0).abs() < 1e-9);
        assert!((n0["downRate"].as_f64().unwrap() - 40.0).abs() < 1e-9);
        assert_eq!(n0["upTraffic"], 10);
    }

    #[test]
    fn subsequent_sample_counts_delta_only() {
        let (_store, stats) = mk(vec![node("n1", 51000, "socks5")], vec![]);
        stats.process_connections_at(&[conn("c1", 100, 200, &["out-socks5-51000"])], 100.0);
        let (d2, _) =
            stats.process_connections_at(&[conn("c1", 150, 260, &["out-socks5-51000"])], 105.0);
        assert_eq!(d2.get("n1"), Some(&(50, 60)));
        let snap = stats.get_stats_at(105.0);
        assert!((snap["nodes"][0]["upRate"].as_f64().unwrap() - 10.0).abs() < 1e-9);
    }

    #[test]
    fn reset_counter_lower_than_prev_counts_full() {
        let (_store, stats) = mk(vec![node("n1", 51000, "socks5")], vec![]);
        stats.process_connections_at(&[conn("c1", 500, 900, &["out-socks5-51000"])], 100.0);
        let (d2, _) =
            stats.process_connections_at(&[conn("c1", 120, 300, &["out-socks5-51000"])], 105.0);
        assert_eq!(d2.get("n1"), Some(&(120, 300)));
    }

    #[test]
    fn node_removed_mid_connection_is_not_credited_elsewhere() {
        let store = MemStore::new(vec![node("n1", 51000, "socks5")], vec![]);
        let stats = Stats::new(store.clone());
        stats.refresh_tag_maps();
        stats.process_connections_at(&[conn("c1", 100, 100, &["out-socks5-51000"])], 100.0);
        // 端口被新节点 n2 复用
        *store.nodes.lock().unwrap() = vec![node("n2", 51000, "socks5")];
        stats.refresh_tag_maps();
        let (d2, _) =
            stats.process_connections_at(&[conn("c1", 180, 180, &["out-socks5-51000"])], 105.0);
        assert!(d2.is_empty(), "旧连接不得记到新节点: {:?}", d2);
    }

    #[test]
    fn relay_tags_accumulate_once_per_connection() {
        let relays = vec![json!({"id": "r1", "port": 40136})];
        let (_store, stats) = mk(vec![node("n1", 51000, "socks5")], relays);
        // 同一帧里 chains 重复出现同一 relay 标签，只记一次
        let conns = vec![conn(
            "c1",
            100,
            100,
            &["relay-auto-r1", "relay-auto-r1", "out-socks5-51000"],
        )];
        let (_, relay_deltas) = stats.process_connections_at(&conns, 100.0);
        assert_eq!(relay_deltas.get("relay-auto-r1"), Some(&(100, 100)));
        let snap = stats.get_stats_at(100.0);
        assert_eq!(snap["relayDomains"][0]["id"], "r1");
        assert!((snap["relayDomains"][0]["upRate"].as_f64().unwrap() - 20.0).abs() < 1e-9);
    }

    #[test]
    fn duplicate_connection_id_in_snapshot_is_ignored() {
        let (_store, stats) = mk(vec![node("n1", 51000, "socks5")], vec![]);
        let conns = vec![
            conn("c1", 100, 100, &["out-socks5-51000"]),
            conn("c1", 999, 999, &["out-socks5-51000"]),
        ];
        let (d, _) = stats.process_connections_at(&conns, 100.0);
        assert_eq!(d.get("n1"), Some(&(100, 100)));
    }

    #[test]
    fn connections_without_id_are_skipped() {
        let (_store, stats) = mk(vec![node("n1", 51000, "socks5")], vec![]);
        let conns = vec![json!({"upload": 5, "download": 5, "chains": ["out-socks5-51000"]})];
        let (d, _) = stats.process_connections_at(&conns, 100.0);
        assert!(d.is_empty());
        assert_eq!(stats.active_connections(), 0);
    }

    #[test]
    fn refresh_tag_maps_prunes_deleted_entries() {
        let store = MemStore::new(
            vec![node("n1", 51000, "socks5")],
            vec![json!({"id": "r1", "port": 40136})],
        );
        let stats = Stats::new(store.clone());
        stats.refresh_tag_maps();
        stats.set_relay_now("relay-auto-r1", "out-socks5-51000");
        stats.process_connections_at(
            &[conn("c1", 10, 10, &["relay-auto-r1", "out-socks5-51000"])],
            100.0,
        );
        assert_eq!(stats.get_stats_at(100.0)["relayDomains"][0]["id"], "r1");
        // 删除节点与 relay 后速率条目必须被清理
        *store.nodes.lock().unwrap() = vec![];
        *store.relays.lock().unwrap() = vec![];
        stats.refresh_tag_maps();
        let snap = stats.get_stats_at(100.0);
        assert_eq!(snap["nodes"].as_array().unwrap().len(), 0);
        assert_eq!(snap["relayDomains"].as_array().unwrap().len(), 0);
        assert!(stats.inner.lock().unwrap().node_rate.is_empty());
        assert!(stats.inner.lock().unwrap().relay_now_cache.is_empty());
    }

    #[test]
    fn set_relay_now_ignores_unknown_tags() {
        let (_store, stats) = mk(vec![], vec![json!({"id": "r1", "port": 1})]);
        stats.set_relay_now("relay-auto-unknown", "out-socks5-1");
        assert!(stats.inner.lock().unwrap().relay_now_cache.is_empty());
    }

    #[test]
    fn global_rate_and_totals_are_reported() {
        let (_store, stats) = mk(vec![node("n1", 1, "socks5"), node("n2", 2, "ss")], vec![]);
        stats.set_global_rate(1024, 2048);
        let snap = stats.get_stats_at(100.0);
        assert_eq!(snap["global"]["upRate"], 1024.0);
        assert_eq!(snap["global"]["downRate"], 2048.0);
        assert_eq!(snap["global"]["upTotal"], 20);
        assert_eq!(snap["global"]["downTotal"], 40);
        stats.reset_global_rate();
        assert_eq!(stats.get_stats_at(100.0)["global"]["upRate"], 0.0);
    }

    #[test]
    fn sample_and_persist_writes_batch_once() {
        let (store, stats) = mk(vec![node("n1", 51000, "socks5")], vec![]);
        let n = stats.sample_and_persist(&[conn("c1", 7, 9, &["out-socks5-51000"])]);
        assert_eq!(n, 1);
        let batches = store.batches.lock().unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].get("n1"), Some(&(7, 9)));
        // 无增量时不再写库
        drop(batches);
        let n2 = stats.sample_and_persist(&[conn("c1", 7, 9, &["out-socks5-51000"])]);
        assert_eq!(n2, 0);
        assert_eq!(store.batches.lock().unwrap().len(), 1);
    }

    #[test]
    fn broadcast_payload_shape_matches_frontend() {
        let (_store, stats) = mk(
            vec![node("n1", 51000, "socks5")],
            vec![json!({"id": "r1", "port": 2})],
        );
        stats.set_global_rate(11, 22);
        let payload = stats.broadcast_payload(1700000000.0);
        let v: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(v["type"], "traffic");
        assert_eq!(v["time"], 1700000000.0);
        assert_eq!(v["up"], 11.0);
        assert_eq!(v["upRate"], 11.0);
        assert_eq!(v["down"], 22.0);
        assert_eq!(v["activeConnections"], 0);
        assert_eq!(v["nodes"].as_array().unwrap().len(), 1);
        assert_eq!(v["relayDomains"].as_array().unwrap().len(), 1);
        assert!(v.get("global").is_none());
    }

    #[test]
    fn broadcast_without_subscribers_is_noop() {
        let (_store, stats) = mk(vec![], vec![]);
        assert_eq!(stats.broadcast_once(1.0), 0);
        let _rx = stats.subscribe();
        assert_eq!(stats.subscriber_count(), 1);
        assert_eq!(stats.broadcast_once(1.0), 1);
    }

    #[test]
    fn subscriber_receives_payload() {
        let (_store, stats) = mk(vec![node("n1", 5, "socks5")], vec![]);
        let mut rx = stats.subscribe();
        stats.broadcast_once(1234.0);
        let got = rx.try_recv().expect("应收到一帧");
        let v: Value = serde_json::from_str(&got).unwrap();
        assert_eq!(v["type"], "traffic");
        assert_eq!(v["time"], 1234.0);
    }
}
