//! 传输模型：字段名统一 camelCase（与前端 nodeState/systemSettings 一致）。
//! DB 层负责 camelCase ↔ snake_case 映射，Rust 侧用 serde rename_all 直达。
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

fn default_entry_proto() -> Option<String> {
    Some("mixed".into())
}

// ---------- 节点 ----------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NodeCreate {
    pub name: String,
    pub protocol: String,
    pub group: Option<String>,
    pub port: Option<i64>,
    pub segment: Option<i64>,
    pub auth_user: Option<String>,
    pub auth_pass: Option<String>,
    pub raw_config: Option<Value>,
    pub sub_id: Option<String>,
    pub sub_name: Option<String>,
    pub status: Option<String>,
    pub ping: Option<i64>,
    pub exit_ip: Option<String>,
    pub up_traffic: Option<i64>,
    pub down_traffic: Option<i64>,
    #[serde(default = "default_entry_proto")]
    pub entry_proto: Option<String>,
    pub ss_pass: Option<String>,
    pub exit_country: Option<String>,
    pub exit_flag: Option<String>,
    pub exit_city: Option<String>,
    pub exit_type: Option<String>,
    pub exit_score: Option<i64>,
    pub exit_risk: Option<i64>,
    pub consecutive_fails: Option<i64>,
    pub disabled_auto: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Node {
    #[serde(flatten)]
    pub base: NodeCreate,
    pub id: String,
    pub stale: bool,
    pub selected: bool,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NodePatch {
    pub name: Option<String>,
    pub group: Option<String>,
    pub port: Option<i64>,
    pub segment: Option<i64>,
    pub auth_user: Option<String>,
    pub auth_pass: Option<String>,
    pub raw_config: Option<Value>,
    pub sub_id: Option<String>,
    pub status: Option<String>,
    pub ping: Option<i64>,
    pub exit_ip: Option<String>,
    pub up_traffic: Option<i64>,
    pub down_traffic: Option<i64>,
    pub stale: Option<bool>,
    pub entry_proto: Option<String>,
    pub ss_pass: Option<String>,
    pub selected: Option<bool>,
    pub consecutive_fails: Option<i64>,
    pub disabled_auto: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NodeListResponse {
    pub items: Vec<Node>,
    pub total: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NodeBatchRequest {
    pub nodes: Vec<NodeCreate>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NodeBatchResponse {
    pub created: i64,
    pub updated: i64,
    pub skipped: i64,
    pub duplicate: i64,
    pub failed: i64,
    pub items: Vec<Node>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EntryConvertRequest {
    pub ids: Vec<String>,
    pub entry_proto: String,
    pub ss_pass: Option<String>,
    pub method: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EntryConvertResponse {
    pub ok: bool,
    pub converted: i64,
    pub failed: i64,
    pub errors: Vec<BTreeMap<String, String>>,
    pub items: Vec<Node>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PortUpdateRequest {
    pub port: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PingRequest {
    pub ids: Option<Vec<String>>,
    pub all: bool,
    pub include_disabled: bool,
    pub manual: bool,
}
impl Default for PingRequest {
    fn default() -> Self {
        Self {
            ids: None,
            all: true,
            include_disabled: false,
            manual: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PingResultItem {
    pub id: String,
    pub tag: String,
    pub ping: i64,
    pub status: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeleteBatchRequest {
    pub ids: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeleteBatchResponse {
    pub deleted: i64,
}

// ---------- 多域名轮询 ----------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RelayDomain {
    pub id: String,
    pub domain: String,
    pub port: i64,
    pub auth_user: Option<String>,
    pub auth_pass: Option<String>,
    pub groups: Vec<String>,
}

// ---------- 订阅 ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SubCreate {
    pub url: String,
    pub name: Option<String>,
    pub group: Option<String>,
    pub enabled: bool,
}
impl Default for SubCreate {
    fn default() -> Self {
        Self {
            url: String::new(),
            name: None,
            group: None,
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Subscription {
    pub id: String,
    pub url: String,
    pub name: String,
    pub group: String,
    pub enabled: bool,
    pub last_refresh: Option<i64>,
    pub node_count: i64,
    pub last_error: Option<String>,
    pub stale: bool,
    pub degraded: bool,
    pub pending_apply: bool,
}
impl Default for Subscription {
    fn default() -> Self {
        Self {
            id: String::new(),
            url: String::new(),
            name: String::new(),
            group: "订阅节点".into(),
            enabled: true,
            last_refresh: None,
            node_count: 0,
            last_error: None,
            stale: false,
            degraded: false,
            pending_apply: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SubToggleRequest {
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SubFetchRequest {
    pub url: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SubFetchResponse {
    pub ok: bool,
    pub status: Option<i64>,
    pub content: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SubParseRequest {
    pub content: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SubParseNode {
    pub name: String,
    pub protocol: String,
    pub raw_config: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SubParseResponse {
    pub nodes: Vec<SubParseNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SubRefreshRequest {
    pub ids: Option<Vec<String>>,
    pub all: bool,
}
impl Default for SubRefreshRequest {
    fn default() -> Self {
        Self {
            ids: None,
            all: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SubRefreshResult {
    pub id: String,
    pub ok: bool,
    pub count: i64,
    pub stale: bool,
    pub degraded: bool,
    pub imported: i64,
    pub updated: i64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SubRefreshResponse {
    pub results: Vec<SubRefreshResult>,
}

// ---------- 配置 ----------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ConfigStatus {
    pub running: bool,
    pub pid: Option<i64>,
    pub uptime: Option<f64>,
    pub version: Option<String>,
    pub clash_api_ok: bool,
    pub controller: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ConfigApplyResponse {
    pub ok: bool,
    pub message: String,
    pub running: bool,
    pub clash_api_ok: bool,
    pub errors: Vec<BTreeMap<String, String>>,
}

// ---------- 统计 ----------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GlobalStats {
    pub up_rate: f64,
    pub down_rate: f64,
    pub up_total: i64,
    pub down_total: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NodeStats {
    pub id: String,
    pub port: Option<i64>,
    pub up_traffic: i64,
    pub down_traffic: i64,
    pub up_rate: f64,
    pub down_rate: f64,
    pub status: String,
    pub ping: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RelayStats {
    pub id: String,
    pub port: i64,
    pub up_rate: f64,
    pub down_rate: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct StatsResponse {
    #[serde(rename = "global")]
    pub global_stats: GlobalStats,
    pub active_connections: i64,
    pub nodes: Vec<NodeStats>,
    pub relay_domains: Vec<RelayStats>,
}
