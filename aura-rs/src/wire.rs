//! 桥接层：把 Db 与基础设施适配成 auth / stats / subs_proxy 需要的 trait，
//! 以及 app 层依赖的服务抽象（ConfigService / Prober）。
//!
//! 设计原则：app.rs 只依赖本模块的 trait，不直接依赖 db / config_apply 的具体实现，
//! 便于用内存 fake 做端点级测试。
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::Value;

use crate::auth::AuthStore;
use crate::db::{self, Db, SubRow};
use crate::stats::StatsStore;
use crate::subs_proxy::{PreparedNode, SubRecord, SubsStore};
use crate::types::{NodeBatchResponse, NodeCreate, RelayDomain};

/// 箱装 future 别名，与 scheduler 的 BoxFuture 同义。
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// ---------------------------------------------------------------------------
// auth
// ---------------------------------------------------------------------------

/// 认证存储：settings 走 DB，用户名走 panel.conf。
#[derive(Clone)]
pub struct AppAuthStore {
    db: Arc<Db>,
    username: String,
}

impl AppAuthStore {
    pub fn new(db: Arc<Db>, username: impl Into<String>) -> Self {
        Self {
            db,
            username: username.into(),
        }
    }
}

impl AuthStore for AppAuthStore {
    fn get_setting(&self, key: &str) -> Option<Value> {
        match Db::get_setting(&self.db, key) {
            Ok(v) if !v.is_null() => Some(v),
            _ => None,
        }
    }

    fn set_setting(&self, key: &str, value: Value) -> Result<(), String> {
        Db::set_setting(&self.db, key, &value).map_err(|e| e.to_string())
    }

    fn username(&self) -> String {
        self.username.clone()
    }
}

// ---------------------------------------------------------------------------
// stats
// ---------------------------------------------------------------------------

impl StatsStore for Db {
    fn list_nodes(&self) -> Vec<Value> {
        Db::list_nodes(self, None, None, None)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|n| serde_json::to_value(n).ok())
            .collect()
    }

    fn list_relay_domains(&self) -> Vec<Value> {
        Db::list_relay_domains(self)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|r| serde_json::to_value(r).ok())
            .collect()
    }

    fn add_traffic_batch(&self, deltas: &HashMap<String, (u64, u64)>) {
        let mapped: HashMap<String, (i64, i64)> = deltas
            .iter()
            .map(|(k, (up, down))| (k.clone(), (*up as i64, *down as i64)))
            .collect();
        let _ = Db::add_traffic_batch(self, &mapped);
    }
}

// ---------------------------------------------------------------------------
// 订阅
// ---------------------------------------------------------------------------

fn row_to_record(row: SubRow) -> SubRecord {
    SubRecord {
        sub: row.to_subscription(),
        snapshot: row.snapshot.clone(),
    }
}

impl SubsStore for Db {
    fn create_node_batch(
        &self,
        prepared: Vec<PreparedNode>,
        update_existing_sub: bool,
    ) -> NodeBatchResponse {
        let stale = prepared.iter().any(|p| p.stale);
        let sub_id = prepared.iter().find_map(|p| p.node.sub_id.clone());
        let nodes: Vec<NodeCreate> = prepared.into_iter().map(|p| p.node).collect();
        match Db::create_node_batch(self, nodes, update_existing_sub) {
            Ok(r) => {
                if stale {
                    if let Some(sid) = sub_id {
                        let _ = Db::mark_nodes_stale_by_sub(self, &sid);
                    }
                }
                NodeBatchResponse {
                    created: r.created as i64,
                    updated: r.updated as i64,
                    skipped: r.skipped as i64,
                    duplicate: r.duplicate as i64,
                    failed: 0,
                    items: r.items,
                }
            }
            Err(e) => {
                tracing::error!("create_node_batch 失败: {e}");
                NodeBatchResponse::default()
            }
        }
    }

    fn random_auth(&self) -> (String, String) {
        db::random_auth()
    }

    fn get_sub(&self, id: &str) -> Option<SubRecord> {
        Db::get_sub_row(self, id).ok().flatten().map(row_to_record)
    }

    fn update_sub(&self, id: &str, patch: Value) -> Option<SubRecord> {
        Db::update_sub(self, id, &patch).ok().flatten()?;
        Db::get_sub_row(self, id).ok().flatten().map(row_to_record)
    }

    fn list_subs(&self) -> Vec<SubRecord> {
        Db::list_subs(self)
            .unwrap_or_default()
            .into_iter()
            .map(|sub| {
                let snapshot = Db::get_sub_snapshot(self, &sub.id).ok().flatten();
                SubRecord { sub, snapshot }
            })
            .collect()
    }

    fn mark_nodes_stale_by_sub(&self, id: &str) {
        let _ = Db::mark_nodes_stale_by_sub(self, id);
    }

    fn unmark_nodes_stale_by_sub(&self, id: &str) {
        let _ = Db::unmark_nodes_stale_by_sub(self, id);
    }
}

// ---------------------------------------------------------------------------
// 服务抽象（app 层依赖，生产实现见 config_apply / scheduler）
// ---------------------------------------------------------------------------

/// 配置生成与应用。实现方负责 build -> 落盘 -> 重启 sing-box。
pub trait ConfigService: Send + Sync {
    /// 只生成不落盘：返回 (config, errors)。
    fn build(&self) -> (Value, Vec<Value>);
    fn is_running(&self) -> bool;
    /// config.json 是否已存在（对齐 Python 的 os.path.exists(CONFIG_PATH)）。
    fn config_exists(&self) -> bool;
    /// 应用当前 DB 的配置；传入 Some 表示直接应用外部配置。
    fn apply(&self, config: Option<Value>) -> BoxFut<'_, Result<Value, String>>;
    fn start(&self) -> BoxFut<'_, Result<bool, String>>;
    fn stop(&self) -> BoxFut<'_, Result<(), String>>;
    fn status(&self) -> BoxFut<'_, Value>;
    fn clash_base(&self) -> String;
    fn clash_secret(&self) -> Option<String>;
    /// settings 里配置的 clash 端口（无则默认 9095）。
    fn clash_port(&self) -> i64;
    /// relay selector 当前出口：(relay_id, tag, name)。
    fn relay_exits(&self) -> Vec<(String, String, String)>;
}

/// 探活。生产实现见 scheduler 的 probe_nodes 批次。
pub trait Prober: Send + Sync {
    fn probe(
        &self,
        ids: Option<Vec<String>>,
        all: bool,
        include_disabled: bool,
        manual: bool,
    ) -> BoxFut<'_, Vec<Value>>;
    fn fetch_exit_ip(&self, node: &Value) -> BoxFut<'_, Option<String>>;
    /// 探测失败原因（probe_ip::diagnose）。
    fn diagnose(&self, node: &Value) -> String;
}

/// 未接生产实现时的空探活器：让 app 端点可独立编译与测试。
#[derive(Default)]
pub struct NoopProber;

impl Prober for NoopProber {
    fn probe(
        &self,
        _ids: Option<Vec<String>>,
        _all: bool,
        _include_disabled: bool,
        _manual: bool,
    ) -> BoxFut<'_, Vec<Value>> {
        Box::pin(async { Vec::new() })
    }
    fn fetch_exit_ip(&self, _node: &Value) -> BoxFut<'_, Option<String>> {
        Box::pin(async { None })
    }
    fn diagnose(&self, node: &Value) -> String {
        let protocol = node
            .get("protocol")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let entry_proto = node
            .get("entryProto")
            .and_then(|v| v.as_str())
            .unwrap_or("mixed")
            .to_string();
        let inbound_port = node.get("port").and_then(|v| v.as_i64()).unwrap_or(0);
        let endpoint_present =
            crate::subs_proxy::proxy_endpoint_of_raw(node.get("rawConfig")).is_some();
        crate::probe_ip::diagnose(&protocol, endpoint_present, &entry_proto, inbound_port)
    }
}

// ---------------------------------------------------------------------------
// 端口占用检查（create_node 用）
// ---------------------------------------------------------------------------

/// nodes + relay_domains + settings.system.reservedPorts 的全部已占用端口。
// ---------------------------------------------------------------------------
// 生产用 ConfigService 适配层
// ---------------------------------------------------------------------------

/// 生产用 `ConfigService`：把 `config_apply::ConfigManager` 适配成 app 层接口。
///
/// 对齐 Python `config_manager` 的 build / apply / start / stop / status 语义。
pub struct ConfigAdapter {
    mgr: Arc<crate::config_apply::ConfigManager>,
    db: Arc<Db>,
    /// sing-box 开始运行的时间戳（epoch 秒），用于 status.uptime。
    started_at: std::sync::Mutex<Option<f64>>,
}

impl ConfigAdapter {
    pub fn new(mgr: Arc<crate::config_apply::ConfigManager>, db: Arc<Db>) -> Self {
        Self {
            mgr,
            db,
            started_at: std::sync::Mutex::new(None),
        }
    }

    pub fn manager(&self) -> &Arc<crate::config_apply::ConfigManager> {
        &self.mgr
    }

    /// 组装一次构建输入（口径同 Python `build_config()`：nodes ∪ relayDomains ∪ settings.system）。
    fn build_input(&self) -> crate::config_manager::BuildInput {
        let nodes = match self.db.list_nodes(None, None, None) {
            Ok(list) => list
                .iter()
                .filter_map(|n| serde_json::to_value(n).ok())
                .collect(),
            Err(_) => Vec::new(),
        };
        let relay_domains = match self.db.list_relay_domains() {
            Ok(list) => list
                .iter()
                .filter_map(|d| serde_json::to_value(d).ok())
                .collect(),
            Err(_) => Vec::new(),
        };
        let settings = self
            .db
            .get_setting_or("system", serde_json::json!({}))
            .unwrap_or_else(|_| serde_json::json!({}));
        crate::config_manager::BuildInput {
            nodes,
            relay_domains,
            settings,
            clash_port: self.mgr.clash_port(),
            clash_secret: self.mgr.get_clash_secret().unwrap_or_default(),
        }
    }

    fn mark_started(&self) {
        let mut guard = self.started_at.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            *guard = Some(crate::scheduler::epoch_now());
        }
    }

    fn clear_started(&self) {
        *self.started_at.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    fn uptime(&self) -> Option<f64> {
        let guard = self.started_at.lock().unwrap_or_else(|e| e.into_inner());
        guard.map(|t| (crate::scheduler::epoch_now() - t).max(0.0))
    }

    fn clash_ok(&self, running: bool) -> bool {
        if !running {
            return false;
        }
        let port = self.mgr.clash_port().clamp(1, 65535) as u16;
        crate::singbox_proc::clash_api_alive(port, std::time::Duration::from_millis(1500))
    }
}

impl ConfigService for ConfigAdapter {
    fn build(&self) -> (Value, Vec<Value>) {
        let result = crate::config_manager::build_config(&self.build_input());
        (result.config, result.errors)
    }

    fn is_running(&self) -> bool {
        self.mgr.is_running()
    }

    fn config_exists(&self) -> bool {
        self.mgr.paths().config_path().exists()
    }

    fn apply(&self, config: Option<Value>) -> BoxFut<'_, Result<Value, String>> {
        Box::pin(async move {
            // 外部传入的配置视为「强制应用」，不走「未变即跳过」的 reconcile 快路径。
            let result = match config {
                Some(cfg) => self.mgr.apply_value(cfg, true).await,
                None => self.mgr.apply_config(false).await,
            };
            match result {
                Ok(report) => {
                    let running = self.mgr.is_running();
                    if running {
                        self.mark_started();
                    } else {
                        self.clear_started();
                    }
                    let clash_api_ok = self.clash_ok(running);
                    Ok(serde_json::json!({
                        "ok": report.ok(),
                        "message": report.message(),
                        "running": running,
                        "clashApiOk": clash_api_ok,
                        "errors": report.errors,
                    }))
                }
                Err(err) => Err(err.to_string()),
            }
        })
    }

    fn start(&self) -> BoxFut<'_, Result<bool, String>> {
        Box::pin(async move {
            let config = match self.mgr.load_config_from_disk() {
                Some(cfg) => cfg,
                None => self.build().0,
            };
            self.mgr.start(&config).await.map_err(|e| e.to_string())?;
            let running = self.mgr.is_running();
            if running {
                self.mark_started();
            }
            Ok(running)
        })
    }

    fn stop(&self) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async move {
            self.mgr.stop().await.map_err(|e| e.to_string())?;
            self.clear_started();
            Ok(())
        })
    }

    fn status(&self) -> BoxFut<'_, Value> {
        Box::pin(async move {
            let running = self.mgr.is_running();
            let version = if running {
                crate::singbox_proc::singbox_version(self.mgr.paths())
            } else {
                None
            };
            let clash_api_ok = self.clash_ok(running);
            if running {
                self.mark_started();
            } else {
                self.clear_started();
            }
            serde_json::json!({
                "running": running,
                "pid": self.mgr.get_proc().map(|p| p.pid),
                "uptime": if running { self.uptime() } else { None },
                "version": version,
                "clashApiOk": clash_api_ok,
                "controller": format!("127.0.0.1:{}", self.mgr.clash_port()),
                "fdCount": if running { self.mgr.singbox_fd_count() } else { 0 },
            })
        })
    }

    fn clash_base(&self) -> String {
        self.mgr.clash_base()
    }

    fn clash_secret(&self) -> Option<String> {
        self.mgr.get_clash_secret()
    }

    fn clash_port(&self) -> i64 {
        self.mgr.clash_port()
    }

    fn relay_exits(&self) -> Vec<(String, String, String)> {
        // app 层的 /api/settings 直接异步读 clash /proxies，这里不再重复实现。
        Vec::new()
    }
}

pub fn used_ports(db: &Db, relay_domains: &[RelayDomain]) -> Vec<i64> {
    let mut ports: Vec<i64> = Vec::new();
    if let Ok(nodes) = Db::list_nodes(db, None, None, None) {
        for n in nodes {
            if let Some(p) = n.base.port {
                ports.push(p);
            }
        }
    }
    for rd in relay_domains {
        ports.push(rd.port);
    }
    let settings =
        Db::get_setting_or(db, "system", Value::Object(Default::default())).unwrap_or(Value::Null);
    if let Some(list) = settings.get("reservedPorts").and_then(|v| v.as_array()) {
        for v in list {
            if let Some(p) = v.as_i64() {
                ports.push(p);
            } else if let Some(s) = v.as_str() {
                if let Ok(p) = s.trim().parse::<i64>() {
                    ports.push(p);
                }
            }
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mem_db() -> Db {
        let db = Db::open_in_memory().expect("内存库");
        db.init_db().expect("建表");
        db
    }

    #[test]
    fn auth_store_reads_and_writes_settings() {
        let db = Arc::new(mem_db());
        let store = AppAuthStore::new(db.clone(), "admin");
        assert_eq!(store.username(), "admin");
        assert!(store.get_setting("auth").is_none());
        store
            .set_setting("auth", json!({"password_hash": "x$y"}))
            .unwrap();
        assert_eq!(store.get_setting("auth").unwrap()["password_hash"], "x$y");
    }

    #[test]
    fn stats_store_lists_nodes_and_relay_domains() {
        let db = mem_db();
        let node = NodeCreate {
            name: "n1".into(),
            protocol: "socks5".into(),
            port: Some(52001),
            ..Default::default()
        };
        Db::create_node(&db, &node).unwrap();
        Db::upsert_relay_domains(
            &db,
            &[RelayDomain {
                id: "r1".into(),
                domain: "a.example".into(),
                port: 52002,
                auth_user: None,
                auth_pass: None,
                groups: vec!["ALL".into()],
            }],
        )
        .unwrap();

        let nodes = StatsStore::list_nodes(&db);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0]["port"], 52001);
        assert_eq!(nodes[0]["protocol"], "socks5");
        let relays = StatsStore::list_relay_domains(&db);
        assert_eq!(relays.len(), 1);
        assert_eq!(relays[0]["port"], 52002);
    }

    #[test]
    fn stats_store_accumulates_traffic() {
        let db = mem_db();
        let node = Db::create_node(
            &db,
            &NodeCreate {
                name: "n".into(),
                protocol: "socks5".into(),
                port: Some(52010),
                ..Default::default()
            },
        )
        .unwrap();
        let mut deltas = HashMap::new();
        deltas.insert(node.id.clone(), (10u64, 20u64));
        StatsStore::add_traffic_batch(&db, &deltas);
        let after = Db::get_node(&db, &node.id).unwrap().unwrap();
        assert_eq!(after.base.up_traffic, Some(10));
        assert_eq!(after.base.down_traffic, Some(20));
    }

    #[test]
    fn subs_store_batch_marks_stale_and_returns_counts() {
        let store = mem_db();
        let prepared = vec![PreparedNode {
            node: NodeCreate {
                name: "subnode".into(),
                protocol: "shadowsocks".into(),
                group: Some("订阅节点".into()),
                port: Some(0),
                sub_id: Some("s1".into()),
                sub_name: Some("sub".into()),
                ..Default::default()
            },
            stale: true,
            selected: false,
        }];
        let res = SubsStore::create_node_batch(&store, prepared, false);
        assert_eq!(res.created, 1);
        assert_eq!(res.failed, 0);
        let node = Db::get_node(&store, &res.items[0].id).unwrap().unwrap();
        assert!(node.stale, "stale=true 必须落库");
    }

    #[test]
    fn subs_store_roundtrips_subscription() {
        let db = mem_db();
        let row = Db::create_sub(&db, "https://example.com/s", Some("名字"), None)
            .unwrap()
            .unwrap();
        let rec = SubsStore::get_sub(&db, &row.id).unwrap();
        assert_eq!(rec.sub.name, "名字");
        assert_eq!(SubsStore::list_subs(&db).len(), 1);
        let updated = SubsStore::update_sub(&db, &row.id, json!({"name": "改名"})).unwrap();
        assert_eq!(updated.sub.name, "改名");
        assert!(SubsStore::get_sub(&db, "nope").is_none());
    }

    #[test]
    fn used_ports_unions_nodes_relays_and_reserved() {
        let db = mem_db();
        Db::create_node(
            &db,
            &NodeCreate {
                name: "n".into(),
                protocol: "socks5".into(),
                port: Some(52001),
                ..Default::default()
            },
        )
        .unwrap();
        Db::set_setting(&db, "system", &json!({"reservedPorts": [2090, "8080"]})).unwrap();
        let relays = vec![RelayDomain {
            id: "r".into(),
            domain: "a.b".into(),
            port: 52002,
            auth_user: None,
            auth_pass: None,
            groups: vec![],
        }];
        let ports = used_ports(&db, &relays);
        assert_eq!(ports, vec![2090, 8080, 52001, 52002]);
    }

    #[test]
    fn noop_prober_returns_empty() {
        let p = NoopProber;
        let out = block_on(p.probe(Some(vec!["a".into()]), false, false, true));
        assert!(out.is_empty());
    }

    /// 极简阻塞执行器（测试专用，避免为单测引入额外依赖）。
    fn block_on<F: Future>(fut: F) -> F::Output {
        use std::task::{Context, Poll, Waker};
        let mut fut = Box::pin(fut);
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }
}
