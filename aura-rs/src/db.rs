//! SQLite 持久化层：建表、迁移、CRUD、端口分配、settings KV。
//!
//! 逐条对齐 backend/db.py 的行为契约：
//! - 表结构 / 索引 / 老库迁移（ALTER TABLE 补列）与 Python 版 SQL 文本一致；
//! - Python 模型是 camelCase，DB 列是 snake_case，映射只在本层做，列名不许改；
//! - 所有 db.xxx 公共 API 都提供同名 snake_case 自由函数（另附 Db 结构体方法，便于测试与多实例）；
//! - 并发语义与 Python 版一致：单连接 + Mutex，读写都串行（Python 也是把整条连接锁住），
//!   不会出现多条连接的 WAL 写冲突。
//!
//! 调用约定：需要精确结果 / 错误传播时用 Db 的方法（返回 Result）；迁移期各模块
//! （app / scheduler / subs_proxy ...）直接用模块级自由函数，与 Python 版同名同参，
//! 失败时记录 tracing::error 并返回安全默认值。

use anyhow::{Context, Result};
use rand::Rng;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, Row};
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::types::{Node, NodeCreate, NodePatch, RelayDomain, Subscription};

/// 自动端口分配起点（Python 版 _next_available_port_locked 里的 base）。
pub const DEFAULT_PORT_BASE: i64 = 52001;
/// 端口上界。
pub const MAX_PORT: i64 = 65535;
/// 连续失败多少次后允许探活自动停用（Python 版 disable_node_after_probe 的 20）。
pub const DISABLE_FAILS_THRESHOLD: i64 = 20;
/// 节点默认分组。
pub const DEFAULT_GROUP: &str = "默认分组";
/// 订阅默认分组。
pub const DEFAULT_SUB_GROUP: &str = "订阅节点";

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS nodes (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  protocol      TEXT NOT NULL,
  "group"       TEXT DEFAULT '默认分组',
  port          INTEGER NOT NULL UNIQUE,
  segment       INTEGER,
  auth_user     TEXT,
  auth_pass     TEXT,
  status        TEXT DEFAULT 'offline',
  ping          INTEGER DEFAULT 0,
  exit_ip       TEXT DEFAULT 'N/A',
  up_traffic    INTEGER DEFAULT 0,
  down_traffic  INTEGER DEFAULT 0,
  raw_config    TEXT NOT NULL DEFAULT '{}',
  sub_id        TEXT,
  stale         INTEGER DEFAULT 0,
  selected      INTEGER DEFAULT 0,
  sub_name      TEXT,
  entry_proto   TEXT DEFAULT 'mixed',
  ss_pass       TEXT,
  created_at    INTEGER,
  updated_at    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_nodes_sub ON nodes(sub_id);
CREATE INDEX IF NOT EXISTS idx_nodes_port ON nodes(port);

CREATE TABLE IF NOT EXISTS relay_domains (
  id         TEXT PRIMARY KEY,
  domain     TEXT NOT NULL,
  port       INTEGER NOT NULL UNIQUE,
  auth_user  TEXT,
  auth_pass  TEXT,
  groups     TEXT NOT NULL DEFAULT '["ALL"]'
);

CREATE TABLE IF NOT EXISTS subscriptions (
  id            TEXT PRIMARY KEY,
  url           TEXT NOT NULL UNIQUE,
  name          TEXT,
  "group"       TEXT DEFAULT '订阅节点',
  enabled       INTEGER DEFAULT 1,
  last_refresh  INTEGER,
  node_count    INTEGER DEFAULT 0,
  last_error    TEXT,
  snapshot      TEXT,
  pending_apply INTEGER DEFAULT 0,
  created_at    INTEGER
);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS deleted_fingerprints (
  fingerprint TEXT PRIMARY KEY,
  created_at  INTEGER
);
"#;

const INSERT_NODE_SQL: &str = r#"INSERT INTO nodes
   (id,name,protocol,"group",port,segment,auth_user,auth_pass,status,ping,
    exit_ip,up_traffic,down_traffic,raw_config,sub_id,sub_name,stale,selected,
    entry_proto,ss_pass,disabled_auto,created_at,updated_at)
   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"#;

// ---------------------------------------------------------------- 基础工具

/// 毫秒时间戳。
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn rand_alnum(n: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..n)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

/// 节点 ID：node- + 16 位十六进制（对齐 Python uuid4().hex[:16]）。
pub fn new_node_id() -> String {
    format!("node-{:016x}", rand::random::<u64>())
}

/// 订阅 ID：sub-毫秒-0..999（对齐 Python new_sub_id）。
pub fn new_sub_id() -> String {
    let suffix: u32 = rand::thread_rng().gen_range(0..1000);
    format!("sub-{}-{}", now_ms(), suffix)
}

/// 随机认证账号密码（对齐 Python random_auth，port 参数在 Python 版也没用）。
pub fn random_auth() -> (String, String) {
    (rand_alnum(8), rand_alnum(12))
}

/// SS 入口密码：16 位十六进制（对齐 Python secrets.token_hex(8)）。
pub fn gen_ss_pass() -> String {
    format!("{:016x}", rand::random::<u64>())
}

/// Python 风格真值判断（None/False/0/空串/空容器为假）。
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(m) => !m.is_empty(),
    }
}

/// 取 JSON 的字符串形态（数字/布尔按 Python str() 近似）。
fn val_str(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(if *b { "True".into() } else { "False".into() }),
        Value::Number(n) => Some(match n.as_i64() {
            Some(i) => i.to_string(),
            None => n.to_string(),
        }),
        other => Some(other.to_string()),
    }
}

/// 取 JSON 的整数形态（对齐 Python int()：字符串可转、浮点截断、布尔 1/0）。
fn val_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Null => None,
        Value::Bool(b) => Some(*b as i64),
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Value::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
}

/// 端口规范化的 JSON 版，逐条对齐 Python _parse_port：
/// None → allow_auto 时 0、否则 None；bool 一律拒；浮点/字典/数组拒；
/// 字符串必须整串是整数；allow_auto 下 0 合法（表示自动分配），其余必须落在 1..=65535。
pub fn parse_port(v: Option<&Value>, allow_auto: bool) -> Option<i64> {
    match v {
        None | Some(Value::Null) => {
            if allow_auto {
                Some(0)
            } else {
                None
            }
        }
        Some(Value::Bool(_)) => None,
        Some(Value::Number(n)) => {
            let p = n.as_i64()?;
            if allow_auto && p == 0 {
                return Some(0);
            }
            if (1..=MAX_PORT).contains(&p) {
                Some(p)
            } else {
                None
            }
        }
        Some(Value::String(s)) => {
            let p: i64 = s.trim().parse().ok()?;
            if allow_auto && p == 0 {
                return Some(0);
            }
            if (1..=MAX_PORT).contains(&p) {
                Some(p)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// 端口规范化的 i64 版（Rust 调用方直接传 Option<i64>）。
pub fn parse_port_i64(v: Option<i64>, allow_auto: bool) -> Option<i64> {
    match v {
        None => {
            if allow_auto {
                Some(0)
            } else {
                None
            }
        }
        Some(p) => {
            if allow_auto && p == 0 {
                Some(0)
            } else if (1..=MAX_PORT).contains(&p) {
                Some(p)
            } else {
                None
            }
        }
    }
}

fn raw_config_string(v: Option<&Value>) -> String {
    match v {
        Some(Value::Null) | None => "{}".to_string(),
        Some(other) => serde_json::to_string(other).unwrap_or_else(|_| "{}".to_string()),
    }
}

/// camelCase / snake_case 归一：NodePatch 走 serde 出来是 camelCase，
/// 但 update_sub 的 Python 调用方用的是 snake_case，两种都收。
fn normalize_key(k: &str) -> String {
    match k {
        "auth_user" => "authUser".into(),
        "auth_pass" => "authPass".into(),
        "raw_config" => "rawConfig".into(),
        "sub_id" => "subId".into(),
        "sub_name" => "subName".into(),
        "exit_ip" => "exitIp".into(),
        "up_traffic" => "upTraffic".into(),
        "down_traffic" => "downTraffic".into(),
        "entry_proto" => "entryProto".into(),
        "ss_pass" => "ssPass".into(),
        "consecutive_fails" => "consecutiveFails".into(),
        "disabled_auto" => "disabledAuto".into(),
        "exit_country" => "exitCountry".into(),
        "exit_flag" => "exitFlag".into(),
        "exit_city" => "exitCity".into(),
        "exit_type" => "exitType".into(),
        "exit_score" => "exitScore".into(),
        "exit_risk" => "exitRisk".into(),
        "created_at" => "createdAt".into(),
        "updated_at" => "updatedAt".into(),
        other => other.to_string(),
    }
}

fn is_constraint(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(err, _) if err.code == rusqlite::ErrorCode::ConstraintViolation)
}

// ---------------------------------------------------------------- 行映射

fn row_to_node(row: &Row<'_>) -> rusqlite::Result<Node> {
    let raw = row.get::<_, Option<String>>("raw_config")?;
    let raw_config = raw
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .unwrap_or_else(|| Value::Object(Map::new()));
    Ok(Node {
        id: row.get("id")?,
        stale: row.get::<_, Option<i64>>("stale")?.unwrap_or(0) != 0,
        selected: row.get::<_, Option<i64>>("selected")?.unwrap_or(0) != 0,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
        base: NodeCreate {
            name: row.get::<_, Option<String>>("name")?.unwrap_or_default(),
            protocol: row
                .get::<_, Option<String>>("protocol")?
                .unwrap_or_default(),
            group: row.get("group")?,
            port: row.get("port")?,
            segment: row.get("segment")?,
            auth_user: row.get("auth_user")?,
            auth_pass: row.get("auth_pass")?,
            raw_config: Some(raw_config),
            sub_id: row.get("sub_id")?,
            sub_name: row.get("sub_name")?,
            status: row.get("status")?,
            ping: row.get("ping")?,
            exit_ip: row.get("exit_ip")?,
            up_traffic: row.get("up_traffic")?,
            down_traffic: row.get("down_traffic")?,
            entry_proto: Some(
                row.get::<_, Option<String>>("entry_proto")?
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "mixed".into()),
            ),
            ss_pass: row.get("ss_pass")?,
            exit_country: row.get("exit_country")?,
            exit_flag: row.get("exit_flag")?,
            exit_city: row.get("exit_city")?,
            exit_type: row.get("exit_type")?,
            exit_score: row.get("exit_score")?,
            exit_risk: row.get("exit_risk")?,
            consecutive_fails: Some(row.get::<_, Option<i64>>("consecutive_fails")?.unwrap_or(0)),
            disabled_auto: Some(row.get::<_, Option<i64>>("disabled_auto")?.unwrap_or(0) != 0),
        },
    })
}

/// Node → camelCase JSON map（update_node 的 merge 基底，与 Python _row_to_node 输出对齐）。
fn node_to_map(n: &Node) -> Map<String, Value> {
    match serde_json::to_value(n) {
        Ok(Value::Object(m)) => m,
        _ => Map::new(),
    }
}

fn table_columns(conn: &Connection, table: &str) -> Result<HashSet<String>> {
    let mut st = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = st.query_map([], |r| r.get::<_, String>(1))?;
    let mut out = HashSet::new();
    for r in rows {
        out.insert(r?);
    }
    Ok(out)
}

fn setting_raw(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row("SELECT value FROM settings WHERE key = ?", [key], |r| {
            r.get::<_, Option<String>>(0)
        })
        .optional()?
        .flatten())
}

fn fetch_node(conn: &Connection, id: &str) -> Result<Option<Node>> {
    let mut st = conn.prepare("SELECT * FROM nodes WHERE id = ?")?;
    let mut rows = st.query([id])?;
    match rows.next()? {
        Some(row) => Ok(Some(row_to_node(row)?)),
        None => Ok(None),
    }
}

/// 已用端口 = nodes ∪ relay_domains ∪ settings.system.reservedPorts（Python _used_ports）。
fn used_ports(conn: &Connection) -> Result<HashSet<i64>> {
    let mut used: HashSet<i64> = HashSet::new();
    for sql in ["SELECT port FROM nodes", "SELECT port FROM relay_domains"] {
        let mut st = conn.prepare(sql)?;
        let rows = st.query_map([], |r| r.get::<_, Option<i64>>(0))?;
        for r in rows {
            if let Some(p) = r? {
                used.insert(p);
            }
        }
    }
    if let Some(raw) = setting_raw(conn, "system")? {
        if let Ok(Value::Object(s)) = serde_json::from_str::<Value>(&raw) {
            if let Some(arr) = s.get("reservedPorts").and_then(|v| v.as_array()) {
                for p in arr {
                    if let Some(p) = parse_port(Some(p), false) {
                        used.insert(p);
                    }
                }
            }
        }
    }
    Ok(used)
}

/// 端口分配内核：preferred 生效则用之，否则 52001 起跳过占用；池耗尽返回 None。
fn next_available_port(conn: &Connection, preferred: Option<i64>) -> Result<Option<i64>> {
    let used = used_ports(conn)?;
    let Some(pref) = parse_port_i64(preferred, true) else {
        return Ok(None);
    };
    if pref != 0 && !used.contains(&pref) {
        return Ok(Some(pref));
    }
    let mut p = DEFAULT_PORT_BASE;
    while used.contains(&p) {
        p += 1;
        if p > MAX_PORT {
            return Ok(None);
        }
    }
    Ok(Some(p))
}

struct InsertRow<'a> {
    id: &'a str,
    name: &'a str,
    protocol: &'a str,
    group: &'a str,
    port: i64,
    segment: Option<i64>,
    auth_user: Option<&'a str>,
    auth_pass: Option<&'a str>,
    status: &'a str,
    ping: i64,
    exit_ip: &'a str,
    up_traffic: i64,
    down_traffic: i64,
    raw_config: &'a str,
    sub_id: Option<&'a str>,
    sub_name: Option<&'a str>,
    stale: bool,
    selected: bool,
    entry_proto: &'a str,
    ss_pass: Option<&'a str>,
    disabled_auto: bool,
    created_at: i64,
    updated_at: i64,
}

fn insert_row(conn: &Connection, r: &InsertRow<'_>) -> rusqlite::Result<usize> {
    conn.execute(
        INSERT_NODE_SQL,
        params![
            r.id,
            r.name,
            r.protocol,
            r.group,
            r.port,
            r.segment,
            r.auth_user,
            r.auth_pass,
            r.status,
            r.ping,
            r.exit_ip,
            r.up_traffic,
            r.down_traffic,
            r.raw_config,
            r.sub_id,
            r.sub_name,
            if r.stale { 1 } else { 0 },
            if r.selected { 1 } else { 0 },
            r.entry_proto,
            r.ss_pass,
            if r.disabled_auto { 1 } else { 0 },
            r.created_at,
            r.updated_at,
        ],
    )
}

/// 删除节点时记录指纹（sub_id|server|server_port），订阅刷新不再重复导入。
fn record_deleted(conn: &Connection, raw_config: &Value, sub_id: &str) -> Result<()> {
    let empty = Map::new();
    let rc = raw_config.as_object().unwrap_or(&empty);
    let pick = |keys: [&str; 2]| -> Option<String> {
        for k in keys {
            if let Some(v) = rc.get(k) {
                if truthy(v) {
                    return val_str(v);
                }
            }
        }
        None
    };
    let (Some(srv), Some(sp)) = (pick(["server", "address"]), pick(["server_port", "port"])) else {
        return Ok(());
    };
    if sub_id.is_empty() {
        return Ok(());
    }
    let fp = format!("{sub_id}|{srv}|{sp}");
    conn.execute(
        "INSERT OR IGNORE INTO deleted_fingerprints (fingerprint, created_at) VALUES (?, ?)",
        params![fp, now_ms()],
    )?;
    Ok(())
}

// ---------------------------------------------------------------- 结果类型

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchResult {
    pub created: i64,
    pub updated: i64,
    pub skipped: i64,
    pub duplicate: i64,
    pub items: Vec<Node>,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenameGroupResult {
    pub updated: usize,
    pub relay_updated: usize,
}

/// subscriptions 原始行（含 snapshot，Python get_sub 会带出该列）。
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubRow {
    pub id: String,
    pub url: String,
    pub name: Option<String>,
    pub group: Option<String>,
    pub enabled: bool,
    pub last_refresh: Option<i64>,
    pub node_count: i64,
    pub last_error: Option<String>,
    pub snapshot: Option<String>,
    pub pending_apply: bool,
    pub created_at: Option<i64>,
}

impl SubRow {
    pub fn to_subscription(&self) -> Subscription {
        let url40: String = self.url.chars().take(40).collect();
        let name = self.name.clone().filter(|s| !s.is_empty()).unwrap_or(url40);
        let err = self.last_error.clone().filter(|s| !s.is_empty());
        let has_snapshot = self
            .snapshot
            .as_deref()
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        Subscription {
            id: self.id.clone(),
            url: self.url.clone(),
            name,
            group: self
                .group
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_SUB_GROUP.to_string()),
            enabled: self.enabled,
            last_refresh: self.last_refresh,
            node_count: self.node_count,
            stale: err.is_some() && !has_snapshot,
            degraded: err.is_some() && has_snapshot,
            last_error: self.last_error.clone(),
            pending_apply: self.pending_apply,
        }
    }
}

fn row_to_sub_row(row: &Row<'_>) -> rusqlite::Result<SubRow> {
    Ok(SubRow {
        id: row.get("id")?,
        url: row.get("url")?,
        name: row.get("name")?,
        group: row.get("group")?,
        enabled: row.get::<_, Option<i64>>("enabled")?.unwrap_or(0) != 0,
        last_refresh: row.get("last_refresh")?,
        node_count: row.get::<_, Option<i64>>("node_count")?.unwrap_or(0),
        last_error: row.get("last_error")?,
        snapshot: row.get("snapshot")?,
        pending_apply: row.get::<_, Option<i64>>("pending_apply")?.unwrap_or(0) != 0,
        created_at: row.get("created_at")?,
    })
}

// ---------------------------------------------------------------- Db

/// 单连接 + Mutex 的 DB 句柄（与 Python 版 threading.Lock 语义一致：整连接串行）。
pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("创建数据目录失败: {}", dir.display()))?;
            }
        }
        let conn = Connection::open(path)
            .with_context(|| format!("打开数据库失败: {}", path.display()))?;
        Self::from_conn(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::from_conn(Connection::open_in_memory()?)
    }

    fn from_conn(conn: Connection) -> Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))?;
        // journal_mode 会返回一行，用 execute() 会直接报错，必须 query_row。
        let mode: String = conn
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .unwrap_or_else(|_| "memory".to_string());
        let _ = mode;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.init_db()?;
        Ok(db)
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 裸 SQL 入口（同一把锁，写入自动串行）。
    pub fn execute(&self, sql: &str, args: &[&dyn rusqlite::ToSql]) -> Result<usize> {
        let conn = self.lock();
        Ok(conn.execute(sql, args)?)
    }

    /// 只读 / 自定义访问连接（同一把锁）。
    pub fn with_conn<R>(&self, f: impl FnOnce(&Connection) -> R) -> R {
        let conn = self.lock();
        f(&conn)
    }

    // ---------- 建表 / 迁移 ----------

    pub fn init_db(&self) -> Result<()> {
        let conn = self.lock();
        conn.execute_batch(SCHEMA_SQL)?;
        let node_cols = table_columns(&conn, "nodes")?;
        for (col, ddl) in [
            ("entry_proto", "TEXT DEFAULT 'mixed'"),
            ("ss_pass", "TEXT"),
            ("sub_name", "TEXT"),
            ("consecutive_fails", "INTEGER DEFAULT 0"),
            // 停用来源标记：1 = 探活自动停用（可被自动复活复查捞回），0 = 用户手动停用。
            // 历史数据无法可靠判定来源 → default 0（保守保留为手动停用，禁止自动复活）。
            ("disabled_auto", "INTEGER DEFAULT 0"),
        ] {
            if !node_cols.contains(col) {
                conn.execute(&format!("ALTER TABLE nodes ADD COLUMN {col} {ddl}"), [])?;
            }
        }
        let sub_cols = table_columns(&conn, "subscriptions")?;
        if !sub_cols.contains("pending_apply") {
            conn.execute(
                "ALTER TABLE subscriptions ADD COLUMN pending_apply INTEGER DEFAULT 0",
                [],
            )?;
        }
        // IP 情报列（探活成功后落库归属地/类型/评分）。
        for (col, ddl) in [
            ("exit_country", "TEXT"),
            ("exit_flag", "TEXT"),
            ("exit_city", "TEXT"),
            ("exit_type", "TEXT"),
            ("exit_score", "INTEGER"),
            ("exit_risk", "INTEGER"),
        ] {
            if !node_cols.contains(col) {
                conn.execute(&format!("ALTER TABLE nodes ADD COLUMN {col} {ddl}"), [])?;
            }
        }
        Ok(())
    }

    // ---------- 端口分配 ----------

    pub fn get_next_available_port(&self, preferred: Option<i64>) -> Result<Option<i64>> {
        let conn = self.lock();
        next_available_port(&conn, preferred)
    }

    pub fn get_next_available_port_json(&self, preferred: &Value) -> Result<Option<i64>> {
        let p = parse_port(Some(preferred), true);
        let Some(p) = p else { return Ok(None) };
        let conn = self.lock();
        next_available_port(&conn, Some(p))
    }

    /// 分组重命名：批量更新节点分组 + relay_domains 的 groups 引用 + settings.system.relayDomains。
    pub fn rename_group(&self, old_name: &str, new_name: &str) -> Result<RenameGroupResult> {
        if old_name.is_empty() || new_name.is_empty() || old_name == new_name {
            return Ok(RenameGroupResult::default());
        }
        let conn = self.lock();
        let now = now_ms();
        let updated = conn.execute(
            "UPDATE nodes SET \"group\"=?, updated_at=? WHERE \"group\"=?",
            params![new_name, now, old_name],
        )?;
        let mut relay_updated = 0usize;
        let rows: Vec<(String, Option<String>)> = {
            let mut st = conn.prepare("SELECT id, groups FROM relay_domains")?;
            let it = st.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
            })?;
            it.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let parse_groups = |raw: Option<&str>| -> Vec<String> {
            match serde_json::from_str::<Value>(raw.unwrap_or("")) {
                Ok(Value::Array(a)) => a.iter().filter_map(val_str).collect(),
                _ => vec!["ALL".to_string()],
            }
        };
        for (id, groups_raw) in rows {
            let mut groups = parse_groups(groups_raw.as_deref());
            if groups.iter().any(|g| g == old_name) && !groups.iter().any(|g| g == "ALL") {
                for g in groups.iter_mut() {
                    if g == old_name {
                        *g = new_name.to_string();
                    }
                }
                conn.execute(
                    "UPDATE relay_domains SET groups=? WHERE id=?",
                    params![serde_json::to_string(&groups)?, id],
                )?;
                relay_updated += 1;
            }
        }
        // settings.relayDomains 同步更新（否则前端下次全量保存会用旧分组名回退）。
        if relay_updated > 0 {
            if let Some(raw) = setting_raw(&conn, "system")? {
                let mut s: Value =
                    serde_json::from_str(&raw).unwrap_or_else(|_| Value::Object(Map::new()));
                let mut changed = false;
                if let Some(list) = s.get_mut("relayDomains").and_then(|v| v.as_array_mut()) {
                    for rd in list.iter_mut() {
                        let Some(obj) = rd.as_object_mut() else {
                            continue;
                        };
                        let mut gs: Vec<String> = match obj.get("groups").and_then(|v| v.as_array())
                        {
                            Some(a) if !a.is_empty() => a.iter().filter_map(val_str).collect(),
                            _ => vec!["ALL".to_string()],
                        };
                        if gs.iter().any(|g| g == old_name) && !gs.iter().any(|g| g == "ALL") {
                            for g in gs.iter_mut() {
                                if g == old_name {
                                    *g = new_name.to_string();
                                }
                            }
                            obj.insert("groups".into(), serde_json::to_value(&gs)?);
                            changed = true;
                        }
                    }
                }
                if changed {
                    conn.execute(
                        "UPDATE settings SET value=? WHERE key='system'",
                        params![serde_json::to_string(&s)?],
                    )?;
                }
            }
        }
        Ok(RenameGroupResult {
            updated,
            relay_updated,
        })
    }

    // ---------- 节点 CRUD ----------

    pub fn list_nodes(
        &self,
        q: Option<&str>,
        group: Option<&str>,
        sub_id: Option<&str>,
    ) -> Result<Vec<Node>> {
        let conn = self.lock();
        let mut sql = String::from("SELECT * FROM nodes");
        let mut where_parts: Vec<String> = Vec::new();
        let mut params_v: Vec<String> = Vec::new();
        if let Some(g) = group {
            if !g.is_empty() && g != "ALL" {
                where_parts.push("\"group\" = ?".to_string());
                params_v.push(g.to_string());
            }
        }
        if let Some(qs) = q {
            if !qs.is_empty() {
                where_parts.push("(name LIKE ? OR CAST(port AS TEXT) LIKE ?)".to_string());
                let like = format!("%{qs}%");
                params_v.push(like.clone());
                params_v.push(like);
            }
        }
        if let Some(s) = sub_id {
            if !s.is_empty() {
                where_parts.push("sub_id = ?".to_string());
                params_v.push(s.to_string());
            }
        }
        if !where_parts.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&where_parts.join(" AND "));
        }
        sql.push_str(" ORDER BY port ASC");
        let mut st = conn.prepare(&sql)?;
        let rows = st.query_map(
            params_from_iter(params_v.iter().map(|s| s.as_str())),
            row_to_node,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn get_node(&self, node_id: &str) -> Result<Option<Node>> {
        let conn = self.lock();
        fetch_node(&conn, node_id)
    }

    /// 单节点插入（Python create_node）：id 自动生成，port 必填（1..=65535）。
    pub fn create_node(&self, node: &NodeCreate) -> Result<Node> {
        self.create_node_with_id(&new_node_id(), node)
    }

    pub fn create_node_with_id(&self, node_id: &str, node: &NodeCreate) -> Result<Node> {
        let port = parse_port_i64(node.port, false).context("节点端口非法或缺失（1..=65535）")?;
        let now = now_ms();
        let raw = raw_config_string(node.raw_config.as_ref());
        let group = node
            .group
            .clone()
            .unwrap_or_else(|| DEFAULT_GROUP.to_string());
        let status = node.status.clone().unwrap_or_else(|| "offline".to_string());
        let exit_ip = node.exit_ip.clone().unwrap_or_else(|| "N/A".to_string());
        let entry = node
            .entry_proto
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "mixed".to_string());
        let created_at = now;
        let name = if node.name.is_empty() {
            "未命名".to_string()
        } else {
            node.name.clone()
        };
        let protocol = if node.protocol.is_empty() {
            "shadowsocks".to_string()
        } else {
            node.protocol.clone()
        };
        {
            let conn = self.lock();
            insert_row(
                &conn,
                &InsertRow {
                    id: node_id,
                    name: &name,
                    protocol: &protocol,
                    group: &group,
                    port,
                    segment: node.segment,
                    auth_user: node.auth_user.as_deref(),
                    auth_pass: node.auth_pass.as_deref(),
                    status: &status,
                    ping: node.ping.unwrap_or(0),
                    exit_ip: &exit_ip,
                    up_traffic: node.up_traffic.unwrap_or(0),
                    down_traffic: node.down_traffic.unwrap_or(0),
                    raw_config: &raw,
                    sub_id: node.sub_id.as_deref(),
                    sub_name: node.sub_name.as_deref(),
                    stale: false,
                    selected: false,
                    entry_proto: &entry,
                    ss_pass: node.ss_pass.as_deref(),
                    disabled_auto: node.disabled_auto.unwrap_or(false),
                    created_at,
                    updated_at: now,
                },
            )?;
        }
        self.get_node(node_id)?
            .context("节点插入后读取失败（并发删除？）")
    }

    /// 批量创建 + 去重（按 server:server_port），逐条对齐 Python create_node_batch。
    pub fn create_node_batch(
        &self,
        nodes: Vec<NodeCreate>,
        update_existing_sub: bool,
    ) -> Result<BatchResult> {
        let values: Vec<Value> = nodes
            .iter()
            .map(|n| serde_json::to_value(n).unwrap_or(Value::Null))
            .collect();
        self.create_node_batch_json(&values, update_existing_sub)
    }

    pub fn create_node_batch_json(
        &self,
        nodes: &[Value],
        update_existing_sub: bool,
    ) -> Result<BatchResult> {
        let conn = self.lock();
        let mut result = BatchResult::default();
        let mut batch_ports: HashSet<i64> = HashSet::new();

        // 一次性预载：现有 server 指纹 + 已删指纹 + 已用端口（避免逐节点 O(N^2) 扫表）。
        let mut existing_servers: HashSet<(String, i64)> = HashSet::new();
        let mut existing_by_key: HashMap<(String, String, i64), String> = HashMap::new();
        {
            let mut st = conn.prepare("SELECT raw_config, id, sub_id FROM nodes")?;
            let it = st.query_map([], |r| {
                Ok((
                    r.get::<_, Option<String>>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            })?;
            for row in it {
                let (raw, id, sub_id) = row?;
                let Ok(rc) = serde_json::from_str::<Value>(raw.as_deref().unwrap_or("{}")) else {
                    continue;
                };
                let Some(rc) = rc.as_object() else { continue };
                let mut srv: Option<String> = None;
                for k in ["server", "address"] {
                    if let Some(v) = rc.get(k) {
                        if truthy(v) {
                            srv = val_str(v);
                            break;
                        }
                    }
                }
                let mut sp: Option<i64> = None;
                if let Some(v) = rc.get("server_port").filter(|v| truthy(v)) {
                    sp = parse_port(Some(v), false);
                } else if let Some(v) = rc.get("port") {
                    sp = parse_port(Some(v), false);
                }
                if let (Some(srv), Some(sp)) = (srv, sp) {
                    existing_servers.insert((srv.clone(), sp));
                    if let Some(sub) = sub_id.filter(|s| !s.is_empty()) {
                        existing_by_key.insert((sub, srv, sp), id);
                    }
                }
            }
        }
        let deleted_fps: HashSet<String> = {
            let mut st = conn.prepare("SELECT fingerprint FROM deleted_fingerprints")?;
            let it = st.query_map([], |r| r.get::<_, String>(0))?;
            it.collect::<rusqlite::Result<HashSet<_>>>()?
        };
        let mut db_used = used_ports(&conn)?;

        for nd in nodes {
            let mut nd = nd.clone();
            if nd
                .get("id")
                .and_then(val_str)
                .filter(|s| !s.is_empty())
                .is_none()
            {
                if let Some(obj) = nd.as_object_mut() {
                    obj.insert("id".into(), Value::String(new_node_id()));
                }
            }
            let node_id = nd.get("id").and_then(val_str).unwrap_or_default();
            let rc = nd
                .get("rawConfig")
                .cloned()
                .unwrap_or_else(|| Value::Object(Map::new()));
            let rc_obj: Map<String, Value> = rc.as_object().cloned().unwrap_or_default();
            let mut srv: Option<String> = None;
            for k in ["server", "address"] {
                if let Some(v) = rc_obj.get(k) {
                    if truthy(v) {
                        srv = val_str(v);
                        break;
                    }
                }
            }
            let mut sp: Option<i64> = None;
            if let Some(v) = rc_obj.get("server_port").filter(|v| truthy(v)) {
                sp = parse_port(Some(v), false);
            } else if let Some(v) = rc_obj.get("port") {
                sp = parse_port(Some(v), false);
            }
            let sub_id = nd.get("subId").and_then(val_str).filter(|s| !s.is_empty());
            if let Some(srv) = srv.clone() {
                if sp.is_none() {
                    result.skipped += 1;
                    continue;
                }
                let sp = sp.unwrap();
                // 订阅刷新：同 subId 已存在 → 只更新上游来源字段，本地运维字段不可被机场覆盖。
                if update_existing_sub {
                    if let Some(sub) = sub_id.as_deref() {
                        if let Some(existing_id) = existing_by_key
                            .get(&(sub.to_string(), srv.clone(), sp))
                            .cloned()
                        {
                            let current = fetch_node(&conn, &existing_id)?;
                            let incoming_raw = serde_json::to_string(&rc)?;
                            let incoming_name = nd
                                .get("name")
                                .and_then(val_str)
                                .filter(|s| !s.is_empty())
                                .unwrap_or_else(|| "未命名".into());
                            let incoming_protocol = nd
                                .get("protocol")
                                .and_then(val_str)
                                .filter(|s| !s.is_empty())
                                .unwrap_or_else(|| "shadowsocks".into());
                            let incoming_sub_name = nd.get("subName").and_then(val_str);
                            let incoming_stale = truthy(nd.get("stale").unwrap_or(&Value::Null));
                            let changed = match &current {
                                None => true,
                                Some(cur) => {
                                    cur.base.name != incoming_name
                                        || cur.base.protocol != incoming_protocol
                                        || cur.base.sub_name != incoming_sub_name
                                        || cur.stale != incoming_stale
                                        || cur.base.raw_config.as_ref() != Some(&rc)
                                }
                            };
                            if changed {
                                conn.execute(
                                    "UPDATE nodes SET name=?,protocol=?,raw_config=?,sub_name=?,stale=?,updated_at=? WHERE id=?",
                                    params![
                                        incoming_name,
                                        incoming_protocol,
                                        incoming_raw,
                                        incoming_sub_name,
                                        if incoming_stale { 1 } else { 0 },
                                        now_ms(),
                                        existing_id,
                                    ],
                                )?;
                                result.updated += 1;
                                if let Some(row) = fetch_node(&conn, &existing_id)? {
                                    result.items.push(row);
                                }
                            } else {
                                result.duplicate += 1;
                            }
                            continue;
                        }
                    }
                } else if existing_servers.contains(&(srv.clone(), sp)) {
                    result.duplicate += 1;
                    result.skipped += 1;
                    continue;
                }
                // 已删除节点指纹：订阅刷新时不重复导入（只算 skipped，不算 duplicate）。
                if let Some(sub) = sub_id.as_deref() {
                    if deleted_fps.contains(&format!("{sub}|{srv}|{sp}")) {
                        result.skipped += 1;
                        continue;
                    }
                }
                existing_servers.insert((srv, sp));
            }

            // 端口冲突则顺位分配；非法显式端口直接跳过。
            let Some(requested) = parse_port(nd.get("port"), true) else {
                result.skipped += 1;
                continue;
            };
            // 显式端口冲突时从该端口向上顺位（Python 语义）；0 从 52001 起扫；溢出即跳过
            let mut port = requested;
            if port == 0 {
                port = DEFAULT_PORT_BASE;
                while db_used.contains(&port) || batch_ports.contains(&port) {
                    port += 1;
                    if port > MAX_PORT {
                        port = 0;
                        break;
                    }
                }
            } else if db_used.contains(&port) || batch_ports.contains(&port) {
                while db_used.contains(&port) || batch_ports.contains(&port) {
                    port += 1;
                    if port > MAX_PORT {
                        port = 0;
                        break;
                    }
                }
            }
            if port == 0 {
                result.skipped += 1;
                continue;
            }
            batch_ports.insert(port);
            db_used.insert(port);

            let name = nd
                .get("name")
                .and_then(val_str)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "未命名".into());
            let protocol = nd
                .get("protocol")
                .and_then(val_str)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "shadowsocks".into());
            let group = nd
                .get("group")
                .and_then(val_str)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_GROUP.into());
            let status = nd
                .get("status")
                .and_then(val_str)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "offline".into());
            let exit_ip = nd
                .get("exitIp")
                .and_then(val_str)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "N/A".into());
            let entry = nd
                .get("entryProto")
                .and_then(val_str)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "mixed".into());
            let raw = raw_config_string(Some(&rc));
            let now = now_ms();
            let segment = nd.get("segment").and_then(val_i64);
            let auth_user = nd.get("authUser").and_then(val_str);
            let auth_pass = nd.get("authPass").and_then(val_str);
            let sub_name = nd.get("subName").and_then(val_str);
            let ss_pass = nd.get("ssPass").and_then(val_str);
            let ping = nd.get("ping").and_then(val_i64).unwrap_or(0);
            let up = nd.get("upTraffic").and_then(val_i64).unwrap_or(0);
            let down = nd.get("downTraffic").and_then(val_i64).unwrap_or(0);
            let stale = truthy(nd.get("stale").unwrap_or(&Value::Null));
            let selected = truthy(nd.get("selected").unwrap_or(&Value::Null));
            let disabled_auto = truthy(nd.get("disabledAuto").unwrap_or(&Value::Null));
            let created_at = nd.get("createdAt").and_then(val_i64).unwrap_or(now);
            let inserted = insert_row(
                &conn,
                &InsertRow {
                    id: &node_id,
                    name: &name,
                    protocol: &protocol,
                    group: &group,
                    port,
                    segment,
                    auth_user: auth_user.as_deref(),
                    auth_pass: auth_pass.as_deref(),
                    status: &status,
                    ping,
                    exit_ip: &exit_ip,
                    up_traffic: up,
                    down_traffic: down,
                    raw_config: &raw,
                    sub_id: sub_id.as_deref(),
                    sub_name: sub_name.as_deref(),
                    stale,
                    selected,
                    entry_proto: &entry,
                    ss_pass: ss_pass.as_deref(),
                    disabled_auto,
                    created_at,
                    updated_at: now,
                },
            );
            match inserted {
                Ok(_) => {
                    if let Some(row) = fetch_node(&conn, &node_id)? {
                        result.items.push(row);
                    }
                    result.created += 1;
                }
                Err(e) if is_constraint(&e) => {
                    result.skipped += 1;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(result)
    }

    /// 按 camelCase patch 合并更新（Python update_node）。
    pub fn update_node(&self, node_id: &str, patch: &NodePatch) -> Result<Option<Node>> {
        let value = patch_to_value(patch);
        self.update_node_json(node_id, &value)
    }

    pub fn update_node_json(&self, node_id: &str, patch: &Value) -> Result<Option<Node>> {
        let conn = self.lock();
        let Some(cur) = fetch_node(&conn, node_id)? else {
            return Ok(None);
        };
        let patch_obj: Map<String, Value> = match patch {
            Value::Object(m) => m
                .iter()
                .map(|(k, v)| (normalize_key(k), v.clone()))
                .collect(),
            _ => Map::new(),
        };
        let mut merged = node_to_map(&cur);
        for (k, v) in &patch_obj {
            merged.insert(k.clone(), v.clone());
        }
        // 如果传入了 rawConfig 且为 Object，浅合并已有 rawConfig，保留未传入的凭据与拓展参数
        if let Some(Value::Object(new_raw)) = patch_obj.get("rawConfig") {
            let mut cur_raw = cur
                .base
                .raw_config
                .as_ref()
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();
            for (rk, rv) in new_raw {
                cur_raw.insert(rk.clone(), rv.clone());
            }
            merged.insert("rawConfig".into(), Value::Object(cur_raw));
        }

        // 如果原始上游服务器地址、端口或协议改变，且 patch 未显式指定 exitIp，重置 exitIp 为 N/A、ping 归零，清理过期的地理/风控标记
        let cur_raw_obj = cur.base.raw_config.as_ref().and_then(|v| v.as_object());
        let cur_server = cur_raw_obj
            .and_then(|o| o.get("server").or_else(|| o.get("address")))
            .and_then(|v| v.as_str());
        let cur_sport = cur_raw_obj
            .and_then(|o| o.get("server_port").or_else(|| o.get("port")))
            .and_then(val_i64);

        let new_raw_obj = merged.get("rawConfig").and_then(|v| v.as_object());
        let new_server = new_raw_obj
            .and_then(|o| o.get("server").or_else(|| o.get("address")))
            .and_then(|v| v.as_str());
        let new_sport = new_raw_obj
            .and_then(|o| o.get("server_port").or_else(|| o.get("port")))
            .and_then(val_i64);

        let proto_changed = patch_obj
            .get("protocol")
            .and_then(val_str)
            .map(|p| p != cur.base.protocol)
            .unwrap_or(false);
        let upstream_changed = (new_server.is_some() && new_server != cur_server)
            || (new_sport.is_some() && new_sport != cur_sport)
            || proto_changed;

        if upstream_changed && !patch_obj.contains_key("exitIp") {
            merged.insert("exitIp".into(), Value::String("N/A".into()));
            merged.insert("ping".into(), Value::from(0));
            merged.insert("exitCountry".into(), Value::Null);
            merged.insert("exitFlag".into(), Value::Null);
            merged.insert("exitCity".into(), Value::Null);
            merged.insert("exitType".into(), Value::Null);
            merged.insert("exitScore".into(), Value::Null);
            merged.insert("exitRisk".into(), Value::Null);
        }

        // 显式 status 变更是管理动作：清零失败计数；自动停用必须显式传 disabledAuto=True。
        if patch_obj.contains_key("status") {
            merged.insert("consecutiveFails".into(), Value::from(0));
            let target = merged.get("status").and_then(val_str).unwrap_or_default();
            let auto = target == "disabled"
                && truthy(patch_obj.get("disabledAuto").unwrap_or(&Value::Null));
            merged.insert("disabledAuto".into(), Value::Bool(auto));
        }
        // 端口冲突自动重分配；非法输入或池耗尽返回 None，不写入非法端口。
        if let Some(raw) = patch_obj.get("port") {
            let Some(target) = parse_port(Some(raw), true) else {
                return Ok(None);
            };
            let mut used = used_ports(&conn)?;
            if let Some(p) = cur.base.port {
                used.remove(&p);
            }
            let target = if target == 0 || used.contains(&target) {
                match next_available_port(&conn, None)? {
                    Some(p) => p,
                    None => return Ok(None),
                }
            } else {
                target
            };
            merged.insert("port".into(), Value::from(target));
        }

        let name = merged
            .get("name")
            .and_then(val_str)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| cur.base.name.clone());
        let protocol = merged
            .get("protocol")
            .and_then(val_str)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| cur.base.protocol.clone());
        let group = merged
            .get("group")
            .and_then(val_str)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_GROUP.to_string());
        let port = merged
            .get("port")
            .and_then(val_i64)
            .or(cur.base.port)
            .unwrap_or(DEFAULT_PORT_BASE);
        let raw_config = raw_config_string(merged.get("rawConfig"));
        conn.execute(
            "UPDATE nodes SET name=?,protocol=?,\"group\"=?,port=?,segment=?,auth_user=?,
               auth_pass=?,status=?,ping=?,exit_ip=?,up_traffic=?,down_traffic=?,raw_config=?,
               sub_id=?,sub_name=?,stale=?,selected=?,entry_proto=?,ss_pass=?,consecutive_fails=?,
               disabled_auto=?,exit_country=?,exit_flag=?,exit_city=?,exit_type=?,exit_score=?,
               exit_risk=?,updated_at=?
               WHERE id=?",
            params![
                name,
                protocol,
                group,
                port,
                merged.get("segment").and_then(val_i64).or(cur.base.segment),
                merged.get("authUser").and_then(val_str),
                merged.get("authPass").and_then(val_str),
                merged
                    .get("status")
                    .and_then(val_str)
                    .unwrap_or_else(|| "offline".into()),
                merged.get("ping").and_then(val_i64).unwrap_or(0),
                merged
                    .get("exitIp")
                    .and_then(val_str)
                    .unwrap_or_else(|| "N/A".into()),
                merged.get("upTraffic").and_then(val_i64).unwrap_or(0),
                merged.get("downTraffic").and_then(val_i64).unwrap_or(0),
                raw_config,
                merged.get("subId").and_then(val_str),
                merged.get("subName").and_then(val_str),
                if truthy(merged.get("stale").unwrap_or(&Value::Null)) {
                    1
                } else {
                    0
                },
                if truthy(merged.get("selected").unwrap_or(&Value::Null)) {
                    1
                } else {
                    0
                },
                merged
                    .get("entryProto")
                    .and_then(val_str)
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "mixed".into()),
                merged.get("ssPass").and_then(val_str),
                merged
                    .get("consecutiveFails")
                    .and_then(val_i64)
                    .unwrap_or(0),
                if truthy(merged.get("disabledAuto").unwrap_or(&Value::Null)) {
                    1
                } else {
                    0
                },
                merged.get("exitCountry").and_then(val_str),
                merged.get("exitFlag").and_then(val_str),
                merged.get("exitCity").and_then(val_str),
                merged.get("exitType").and_then(val_str),
                merged.get("exitScore").and_then(val_i64),
                merged.get("exitRisk").and_then(val_i64),
                now_ms(),
                node_id,
            ],
        )?;
        drop(conn);
        self.get_node(node_id)
    }

    /// 切换节点对外入口协议（mixed = ss|http；ss = Shadowsocks 单协议）。
    pub fn update_node_entry(
        &self,
        node_id: &str,
        entry_proto: &str,
        ss_pass: Option<&str>,
    ) -> Result<Option<Node>> {
        {
            let conn = self.lock();
            let Some(cur) = fetch_node(&conn, node_id)? else {
                return Ok(None);
            };
            let new_pass = ss_pass
                .map(|s| s.to_string())
                .or_else(|| cur.base.ss_pass.clone())
                .unwrap_or_else(gen_ss_pass);
            conn.execute(
                "UPDATE nodes SET entry_proto=?, ss_pass=?, updated_at=? WHERE id=?",
                params![entry_proto, new_pass, now_ms(), node_id],
            )?;
        }
        self.get_node(node_id)
    }

    /// 更新端口；port 缺省/0 时按 52001 起重新分配。
    pub fn update_node_port(&self, node_id: &str, port: Option<i64>) -> Result<Option<Node>> {
        let conn = self.lock();
        let Some(cur) = fetch_node(&conn, node_id)? else {
            return Ok(None);
        };
        let Some(target) = parse_port_i64(port, true) else {
            return Ok(None);
        };
        let mut used = used_ports(&conn)?;
        if let Some(p) = cur.base.port {
            used.remove(&p);
        }
        // 与 Python 一致：冲突/0 一律从 52001 起重扫（不沿用被占用的目标端口）
        let target = if target == 0 || used.contains(&target) {
            match next_available_port(&conn, None)? {
                Some(p) => p,
                None => return Ok(None),
            }
        } else {
            target
        };
        conn.execute(
            "UPDATE nodes SET port=?, updated_at=? WHERE id=?",
            params![target, now_ms(), node_id],
        )?;
        drop(conn);
        self.get_node(node_id)
    }

    pub fn delete_node(&self, node_id: &str) -> Result<bool> {
        let conn = self.lock();
        let row: Option<(Option<String>, Option<String>)> = conn
            .query_row(
                "SELECT raw_config, sub_id FROM nodes WHERE id = ?",
                [node_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let cur = conn.execute("DELETE FROM nodes WHERE id = ?", [node_id])?;
        if cur > 0 {
            if let Some((raw, sub_id)) = row {
                let rc: Value =
                    serde_json::from_str(raw.as_deref().unwrap_or("{}")).unwrap_or(Value::Null);
                record_deleted(&conn, &rc, sub_id.as_deref().unwrap_or(""))?;
            }
        }
        Ok(cur > 0)
    }

    /// 批量更新节点分组；空 ids 返回 0。
    pub fn update_nodes_group(&self, ids: &[String], group: &str) -> Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let conn = self.lock();
        let marks = vec!["?"; ids.len()].join(",");
        let sql = format!("UPDATE nodes SET \"group\"=?, updated_at=? WHERE id IN ({marks})");
        let g = group.to_string();
        let now = now_ms();
        let mut bound: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(g), Box::new(now)];
        for id in ids {
            bound.push(Box::new(id.clone()));
        }
        let refs: Vec<&dyn rusqlite::ToSql> = bound.iter().map(|b| b.as_ref()).collect();
        Ok(conn.execute(&sql, refs.as_slice())?)
    }

    pub fn delete_node_batch(&self, ids: &[String]) -> Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let conn = self.lock();
        let mut marks: Vec<(Option<String>, Option<String>)> = Vec::new();
        for nid in ids {
            let row: Option<(Option<String>, Option<String>)> = conn
                .query_row(
                    "SELECT raw_config, sub_id FROM nodes WHERE id = ?",
                    [nid],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some(r) = row {
                marks.push(r);
            }
        }
        let placeholders = vec!["?"; ids.len()].join(",");
        let sql = format!("DELETE FROM nodes WHERE id IN ({placeholders})");
        let bound: Vec<Box<dyn rusqlite::ToSql>> = ids
            .iter()
            .map(|s| Box::new(s.clone()) as Box<dyn rusqlite::ToSql>)
            .collect();
        let refs: Vec<&dyn rusqlite::ToSql> = bound.iter().map(|b| b.as_ref()).collect();
        let cur = conn.execute(&sql, refs.as_slice())?;
        for (raw, sub_id) in marks {
            let rc: Value =
                serde_json::from_str(raw.as_deref().unwrap_or("{}")).unwrap_or(Value::Null);
            record_deleted(&conn, &rc, sub_id.as_deref().unwrap_or(""))?;
        }
        Ok(cur)
    }

    /// 累计流量（增量，负数按 0 截断）。
    pub fn add_traffic(&self, node_id: &str, up_delta: i64, down_delta: i64) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE nodes SET up_traffic = up_traffic + ?, down_traffic = down_traffic + ?, updated_at = ? WHERE id = ?",
            params![up_delta.max(0), down_delta.max(0), now_ms(), node_id],
        )?;
        Ok(())
    }

    /// 批量累计流量：整批只持锁。
    pub fn add_traffic_batch(&self, deltas: &HashMap<String, (i64, i64)>) -> Result<()> {
        if deltas.is_empty() {
            return Ok(());
        }
        let conn = self.lock();
        let now = now_ms();
        let mut st = conn.prepare(
            "UPDATE nodes SET up_traffic=up_traffic+?, down_traffic=down_traffic+?, updated_at=? WHERE id=?",
        )?;
        for (nid, (up, down)) in deltas {
            let upv: i64 = (*up).max(0);
            let downv: i64 = (*down).max(0);
            st.execute(params![upv, downv, now, nid.as_str()])?;
        }
        Ok(())
    }

    pub fn reset_node_traffic(&self, node_id: &str) -> Result<Option<Node>> {
        {
            let conn = self.lock();
            conn.execute(
                "UPDATE nodes SET up_traffic=0, down_traffic=0, updated_at=? WHERE id=?",
                params![now_ms(), node_id],
            )?;
        }
        self.get_node(node_id)
    }

    pub fn reset_all_traffic(&self) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE nodes SET up_traffic=0, down_traffic=0, updated_at=?",
            params![now_ms()],
        )?;
        Ok(())
    }

    pub fn mark_nodes_stale_by_sub(&self, sub_id: &str) -> Result<usize> {
        let conn = self.lock();
        Ok(conn.execute(
            "UPDATE nodes SET stale=1, updated_at=? WHERE sub_id=?",
            params![now_ms(), sub_id],
        )?)
    }

    pub fn unmark_nodes_stale_by_sub(&self, sub_id: &str) -> Result<usize> {
        let conn = self.lock();
        Ok(conn.execute(
            "UPDATE nodes SET stale=0, updated_at=? WHERE sub_id=? AND stale=1",
            params![now_ms(), sub_id],
        )?)
    }

    // ---------- 探活落库（全部是 CAS，过期结果必须丢弃） ----------

    /// 原子落库探活结果；手动失败不计数，成功清零。
    /// 节点已停用/删除/tag 变化时返回 None，调用方必须丢弃过期结果。
    pub fn update_node_probe(
        &self,
        node_id: &str,
        ping: i64,
        status: &str,
        count_failure: bool,
        expected_port: Option<i64>,
        expected_protocol: Option<&str>,
    ) -> Result<Option<i64>> {
        let conn = self.lock();
        let mut sql = String::from("UPDATE nodes SET ping=?, status=?, consecutive_fails=");
        if status == "online" {
            sql.push('0');
        } else if count_failure {
            sql.push_str("consecutive_fails+1");
        } else {
            sql.push_str("consecutive_fails");
        }
        sql.push_str(", updated_at=? WHERE id=? AND status!='disabled'");
        let mut bound: Vec<Box<dyn rusqlite::ToSql>> = vec![
            Box::new(ping),
            Box::new(status.to_string()),
            Box::new(now_ms()),
            Box::new(node_id.to_string()),
        ];
        if let Some(p) = expected_port {
            sql.push_str(" AND port=?");
            bound.push(Box::new(p));
        }
        if let Some(pr) = expected_protocol {
            sql.push_str(" AND protocol=?");
            bound.push(Box::new(pr.to_string()));
        }
        let refs: Vec<&dyn rusqlite::ToSql> = bound.iter().map(|b| b.as_ref()).collect();
        let changed = conn.execute(&sql, refs.as_slice())?;
        if changed == 0 {
            return Ok(None);
        }
        Ok(conn
            .query_row(
                "SELECT consecutive_fails FROM nodes WHERE id=?",
                [node_id],
                |r| r.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten())
    }

    /// 仅复活 tag 未变的自动停用节点；手动停用/过期探活不得改状态。
    pub fn revive_node_probe(
        &self,
        node_id: &str,
        ping: i64,
        expected_port: i64,
        expected_protocol: &str,
    ) -> Result<Option<i64>> {
        let conn = self.lock();
        let changed = conn.execute(
            "UPDATE nodes SET ping=?,status='online',consecutive_fails=0,disabled_auto=0,updated_at=?
               WHERE id=? AND status='disabled' AND disabled_auto=1 AND port=? AND protocol=?",
            params![ping, now_ms(), node_id, expected_port, expected_protocol],
        )?;
        Ok(if changed > 0 { Some(0) } else { None })
    }

    /// 失败阈值达到且当前 tag/计数仍匹配时，原子标记自动停用。
    pub fn disable_node_after_probe(
        &self,
        node_id: &str,
        expected_port: i64,
        expected_protocol: &str,
        expected_fails: i64,
    ) -> Result<bool> {
        if expected_fails < DISABLE_FAILS_THRESHOLD {
            return Ok(false);
        }
        let conn = self.lock();
        let changed = conn.execute(
            "UPDATE nodes SET status='disabled',disabled_auto=1,updated_at=?
               WHERE id=? AND status!='disabled' AND port=? AND protocol=? AND consecutive_fails=?",
            params![
                now_ms(),
                node_id,
                expected_port,
                expected_protocol,
                expected_fails
            ],
        )?;
        Ok(changed > 0)
    }

    // ---------- 多域名轮询 ----------

    pub fn list_relay_domains(&self) -> Result<Vec<RelayDomain>> {
        let conn = self.lock();
        let mut st = conn.prepare("SELECT * FROM relay_domains ORDER BY port")?;
        let it = st.query_map([], |r| {
            let groups_raw: Option<String> = r.get("groups")?;
            let groups: Vec<String> =
                match serde_json::from_str::<Value>(groups_raw.as_deref().unwrap_or("")) {
                    Ok(Value::Array(a)) => a.iter().filter_map(val_str).collect(),
                    _ => vec!["ALL".to_string()],
                };
            Ok(RelayDomain {
                id: r.get("id")?,
                domain: r.get("domain")?,
                port: r.get::<_, Option<i64>>("port")?.unwrap_or(0),
                auth_user: r.get("auth_user")?,
                auth_pass: r.get("auth_pass")?,
                groups,
            })
        })?;
        Ok(it.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 整表替换（settings 是唯一真源）。必须全删再插：只删「列表内 id」会残留旧行，
    /// 导致 config 生成用旧凭据/旧端口。端口 UNIQUE 冲突时跳过新行（不覆盖已有行）。
    pub fn upsert_relay_domains(&self, domains: &[RelayDomain]) -> Result<()> {
        let conn = self.lock();
        conn.execute("DELETE FROM relay_domains", [])?;
        for d in domains {
            let groups = if d.groups.is_empty() {
                vec!["ALL".to_string()]
            } else {
                d.groups.clone()
            };
            let res = conn.execute(
                "INSERT INTO relay_domains (id,domain,port,auth_user,auth_pass,groups) VALUES (?,?,?,?,?,?)",
                params![
                    d.id,
                    d.domain,
                    d.port,
                    d.auth_user,
                    d.auth_pass,
                    serde_json::to_string(&groups)?,
                ],
            );
            match res {
                Ok(_) => {}
                Err(e) if is_constraint(&e) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// settings.relayDomains（JSON 数组）直接落 relay_domains 表。
    pub fn upsert_relay_domains_json(&self, domains: &Value) -> Result<()> {
        let list: Vec<RelayDomain> = match domains {
            Value::Array(a) => a
                .iter()
                .map(|d| RelayDomain {
                    id: d.get("id").and_then(val_str).unwrap_or_default(),
                    domain: d.get("domain").and_then(val_str).unwrap_or_default(),
                    port: d.get("port").and_then(val_i64).unwrap_or(0),
                    auth_user: d
                        .get("authUser")
                        .and_then(val_str)
                        .or_else(|| d.get("auth_user").and_then(val_str)),
                    auth_pass: d
                        .get("authPass")
                        .and_then(val_str)
                        .or_else(|| d.get("auth_pass").and_then(val_str)),
                    groups: d
                        .get("groups")
                        .and_then(|v| v.as_array())
                        .map(|a| a.iter().filter_map(val_str).collect())
                        .unwrap_or_else(|| vec!["ALL".to_string()]),
                })
                .collect(),
            _ => Vec::new(),
        };
        self.upsert_relay_domains(&list)
    }

    // ---------- 订阅 ----------

    pub fn list_subs(&self) -> Result<Vec<Subscription>> {
        let conn = self.lock();
        let mut st = conn.prepare("SELECT * FROM subscriptions ORDER BY created_at")?;
        let it = st.query_map([], row_to_sub_row)?;
        let rows = it.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows.iter().map(|r| r.to_subscription()).collect())
    }

    pub fn get_sub(&self, sub_id: &str) -> Result<Option<Subscription>> {
        Ok(self.get_sub_row(sub_id)?.map(|r| r.to_subscription()))
    }

    pub fn get_sub_row(&self, sub_id: &str) -> Result<Option<SubRow>> {
        let conn = self.lock();
        let mut st = conn.prepare("SELECT * FROM subscriptions WHERE id = ?")?;
        let mut rows = st.query([sub_id])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_to_sub_row(row)?)),
            None => Ok(None),
        }
    }

    /// 订阅 last-good 快照（刷新失败兜底用）。
    pub fn get_sub_snapshot(&self, sub_id: &str) -> Result<Option<String>> {
        Ok(self.get_sub_row(sub_id)?.and_then(|r| r.snapshot))
    }

    pub fn create_sub(
        &self,
        url: &str,
        name: Option<&str>,
        group: Option<&str>,
    ) -> Result<Option<Subscription>> {
        let sub_id = new_sub_id();
        {
            let conn = self.lock();
            let url40: String = url.chars().take(40).collect();
            let name = name
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .unwrap_or(url40);
            let group = group.filter(|s| !s.is_empty()).unwrap_or(DEFAULT_SUB_GROUP);
            let res = conn.execute(
                "INSERT INTO subscriptions (id,url,name,\"group\",enabled,created_at) VALUES (?,?,?,?,1,?)",
                params![sub_id, url, name, group, now_ms()],
            );
            match res {
                Ok(_) => {}
                Err(e) if is_constraint(&e) => return Ok(None),
                Err(e) => return Err(e.into()),
            }
        }
        self.get_sub(&sub_id)
    }

    /// 只允许白名单字段；key 接受 snake_case 与 camelCase；
    /// last_error 传 null/空串表示清空（写 NULL），其余字段传 null 视为不修改。
    pub fn update_sub(&self, sub_id: &str, patch: &Value) -> Result<Option<Subscription>> {
        let conn = self.lock();
        let exists: Option<String> = conn
            .query_row("SELECT id FROM subscriptions WHERE id = ?", [sub_id], |r| {
                r.get(0)
            })
            .optional()?;
        if exists.is_none() {
            return Ok(None);
        }
        let patch_obj = match patch {
            Value::Object(m) => m.clone(),
            _ => Map::new(),
        };
        // 每个 set 片段对应一个待绑定参数（写 NULL 的语句不带参数）。
        enum Arg {
            Int(i64),
            Text(String),
            None,
        }
        let mut sets: Vec<String> = Vec::new();
        let mut args: Vec<Arg> = Vec::new();
        for (raw_key, v) in &patch_obj {
            let key = match raw_key.as_str() {
                "lastRefresh" => "last_refresh",
                "nodeCount" => "node_count",
                "lastError" => "last_error",
                "pendingApply" => "pending_apply",
                other => other,
            };
            let column = match key {
                "name" => "name",
                "group" => "\"group\"",
                "enabled" => "enabled",
                "url" => "url",
                "last_refresh" => "last_refresh",
                "node_count" => "node_count",
                "last_error" => "last_error",
                "snapshot" => "snapshot",
                "pending_apply" => "pending_apply",
                _ => continue,
            };
            if key == "last_error" {
                let empty = match v {
                    Value::Null => true,
                    Value::String(s) => s.is_empty(),
                    _ => false,
                };
                if empty {
                    sets.push("last_error = NULL".to_string());
                    args.push(Arg::None);
                } else {
                    sets.push("last_error = ?".to_string());
                    args.push(Arg::Text(val_str(v).unwrap_or_default()));
                }
                continue;
            }
            if v.is_null() {
                continue;
            }
            sets.push(format!("{column} = ?"));
            if matches!(
                key,
                "enabled" | "last_refresh" | "node_count" | "pending_apply"
            ) {
                let n = val_i64(v).context("订阅字段需要整数")?;
                args.push(Arg::Int(n));
            } else {
                args.push(Arg::Text(val_str(v).unwrap_or_default()));
            }
        }
        if !sets.is_empty() {
            let sql = format!("UPDATE subscriptions SET {} WHERE id = ?", sets.join(", "));
            let mut bound: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
            for a in args {
                match a {
                    Arg::Int(n) => bound.push(Box::new(n)),
                    Arg::Text(s) => bound.push(Box::new(s)),
                    Arg::None => {}
                }
            }
            bound.push(Box::new(sub_id.to_string()));
            let refs: Vec<&dyn rusqlite::ToSql> = bound.iter().map(|b| b.as_ref()).collect();
            conn.execute(&sql, refs.as_slice())?;
        }
        drop(conn);
        self.get_sub(sub_id)
    }

    pub fn delete_sub(&self, sub_id: &str) -> Result<bool> {
        let conn = self.lock();
        Ok(conn.execute("DELETE FROM subscriptions WHERE id = ?", [sub_id])? > 0)
    }

    // ---------- settings KV ----------

    pub fn get_setting(&self, key: &str) -> Result<Value> {
        self.get_setting_or(key, Value::Null)
    }

    pub fn get_setting_or(&self, key: &str, default: Value) -> Result<Value> {
        let conn = self.lock();
        let Some(raw) = setting_raw(&conn, key)? else {
            return Ok(default);
        };
        Ok(serde_json::from_str::<Value>(&raw).unwrap_or(Value::String(raw)))
    }

    pub fn set_setting(&self, key: &str, value: &Value) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            params![key, serde_json::to_string(value)?],
        )?;
        Ok(())
    }
}

/// NodePatch → 只含 Some 字段的 camelCase JSON（对齐 Python exclude_unset=True 语义）。
pub fn patch_to_value(p: &NodePatch) -> Value {
    let mut m = Map::new();
    if let Some(v) = &p.name {
        m.insert("name".into(), Value::String(v.clone()));
    }
    if let Some(v) = &p.protocol {
        m.insert("protocol".into(), Value::String(v.clone()));
    }
    if let Some(v) = &p.group {
        m.insert("group".into(), Value::String(v.clone()));
    }
    if let Some(v) = p.port {
        m.insert("port".into(), Value::from(v));
    }
    if let Some(v) = p.segment {
        m.insert("segment".into(), Value::from(v));
    }
    if let Some(v) = &p.auth_user {
        m.insert("authUser".into(), Value::String(v.clone()));
    }
    if let Some(v) = &p.auth_pass {
        m.insert("authPass".into(), Value::String(v.clone()));
    }
    if let Some(v) = &p.raw_config {
        m.insert("rawConfig".into(), v.clone());
    }
    if let Some(v) = &p.sub_id {
        m.insert("subId".into(), Value::String(v.clone()));
    }
    if let Some(v) = &p.status {
        m.insert("status".into(), Value::String(v.clone()));
    }
    if let Some(v) = p.ping {
        m.insert("ping".into(), Value::from(v));
    }
    if let Some(v) = &p.exit_ip {
        m.insert("exitIp".into(), Value::String(v.clone()));
    }
    if let Some(v) = p.up_traffic {
        m.insert("upTraffic".into(), Value::from(v));
    }
    if let Some(v) = p.down_traffic {
        m.insert("downTraffic".into(), Value::from(v));
    }
    if let Some(v) = p.stale {
        m.insert("stale".into(), Value::Bool(v));
    }
    if let Some(v) = &p.entry_proto {
        m.insert("entryProto".into(), Value::String(v.clone()));
    }
    if let Some(v) = &p.ss_pass {
        m.insert("ssPass".into(), Value::String(v.clone()));
    }
    if let Some(v) = p.selected {
        m.insert("selected".into(), Value::Bool(v));
    }
    if let Some(v) = p.consecutive_fails {
        m.insert("consecutiveFails".into(), Value::from(v));
    }
    if let Some(v) = p.disabled_auto {
        m.insert("disabledAuto".into(), Value::Bool(v));
    }
    Value::Object(m)
}

// ---------------------------------------------------------------- 全局实例 / 自由函数

static GLOBAL: OnceLock<Db> = OnceLock::new();

/// 默认数据库路径：AURA_DB_PATH > AURA_DATA_DIR/panel.db > data/panel.db。
pub fn default_db_path() -> PathBuf {
    if let Ok(p) = std::env::var("AURA_DB_PATH") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    if let Ok(d) = std::env::var("AURA_DATA_DIR") {
        if !d.is_empty() {
            return PathBuf::from(d).join("panel.db");
        }
    }
    PathBuf::from("data").join("panel.db")
}

/// 全局 DB 句柄（首次访问时建连并建表）。
pub fn global() -> &'static Db {
    GLOBAL.get_or_init(|| match Db::open(default_db_path()) {
        Ok(db) => db,
        Err(e) => {
            tracing::error!(error = %e, "打开数据库失败");
            panic!("打开数据库失败: {e}");
        }
    })
}

/// 用指定路径初始化全局 DB（已被初始化时忽略）。
pub fn init_at(path: impl AsRef<Path>) -> Result<()> {
    if GLOBAL.get().is_some() {
        return Ok(());
    }
    let db = Db::open(path)?;
    let _ = GLOBAL.set(db);
    Ok(())
}

pub fn init_db() {
    if let Err(e) = global().init_db() {
        tracing::error!(error = %e, "初始化数据库失败");
    }
}

macro_rules! plain {
    ($call:expr, $fallback:expr, $what:literal) => {
        match $call {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, $what);
                $fallback
            }
        }
    };
}

pub fn get_next_available_port(preferred: Option<i64>) -> Option<i64> {
    plain!(
        global().get_next_available_port(preferred),
        None,
        "端口分配失败"
    )
}

pub fn get_next_available_port_json(preferred: &Value) -> Option<i64> {
    plain!(
        global().get_next_available_port_json(preferred),
        None,
        "端口分配失败"
    )
}

pub fn rename_group(old_name: &str, new_name: &str) -> RenameGroupResult {
    plain!(
        global().rename_group(old_name, new_name),
        RenameGroupResult::default(),
        "分组重命名失败"
    )
}

pub fn list_nodes(q: Option<&str>, group: Option<&str>, sub_id: Option<&str>) -> Vec<Node> {
    plain!(
        global().list_nodes(q, group, sub_id),
        Vec::new(),
        "查询节点失败"
    )
}

pub fn get_node(node_id: &str) -> Option<Node> {
    plain!(global().get_node(node_id), None, "查询节点失败")
}

pub fn create_node(node: &NodeCreate) -> Option<Node> {
    match global().create_node(node) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::error!(error = %e, "创建节点失败");
            None
        }
    }
}

pub fn create_node_with_id(node_id: &str, node: &NodeCreate) -> Option<Node> {
    match global().create_node_with_id(node_id, node) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::error!(error = %e, "创建节点失败");
            None
        }
    }
}

pub fn create_node_batch(nodes: Vec<NodeCreate>, update_existing_sub: bool) -> BatchResult {
    plain!(
        global().create_node_batch(nodes, update_existing_sub),
        BatchResult::default(),
        "批量创建节点失败"
    )
}

pub fn create_node_batch_json(nodes: &[Value], update_existing_sub: bool) -> BatchResult {
    plain!(
        global().create_node_batch_json(nodes, update_existing_sub),
        BatchResult::default(),
        "批量创建节点失败"
    )
}

pub fn update_node(node_id: &str, patch: &NodePatch) -> Option<Node> {
    plain!(global().update_node(node_id, patch), None, "更新节点失败")
}

pub fn update_node_json(node_id: &str, patch: &Value) -> Option<Node> {
    plain!(
        global().update_node_json(node_id, patch),
        None,
        "更新节点失败"
    )
}

pub fn update_node_entry(node_id: &str, entry_proto: &str, ss_pass: Option<&str>) -> Option<Node> {
    plain!(
        global().update_node_entry(node_id, entry_proto, ss_pass),
        None,
        "更新节点入口失败"
    )
}

pub fn update_node_port(node_id: &str, port: Option<i64>) -> Option<Node> {
    plain!(
        global().update_node_port(node_id, port),
        None,
        "更新节点端口失败"
    )
}

pub fn delete_node(node_id: &str) -> bool {
    plain!(global().delete_node(node_id), false, "删除节点失败")
}

pub fn update_nodes_group(ids: &[String], group: &str) -> usize {
    plain!(global().update_nodes_group(ids, group), 0, "批量改分组失败")
}

pub fn delete_node_batch(ids: &[String]) -> usize {
    plain!(global().delete_node_batch(ids), 0, "批量删除节点失败")
}

pub fn add_traffic(node_id: &str, up_delta: i64, down_delta: i64) {
    if let Err(e) = global().add_traffic(node_id, up_delta, down_delta) {
        tracing::error!(error = %e, "累计流量失败");
    }
}

pub fn add_traffic_batch(deltas: &HashMap<String, (i64, i64)>) {
    if let Err(e) = global().add_traffic_batch(deltas) {
        tracing::error!(error = %e, "批量累计流量失败");
    }
}

pub fn reset_node_traffic(node_id: &str) -> Option<Node> {
    plain!(
        global().reset_node_traffic(node_id),
        None,
        "重置节点流量失败"
    )
}

pub fn reset_all_traffic() {
    if let Err(e) = global().reset_all_traffic() {
        tracing::error!(error = %e, "重置全部流量失败");
    }
}

pub fn mark_nodes_stale_by_sub(sub_id: &str) -> usize {
    plain!(
        global().mark_nodes_stale_by_sub(sub_id),
        0,
        "标记 stale 失败"
    )
}

pub fn unmark_nodes_stale_by_sub(sub_id: &str) -> usize {
    plain!(
        global().unmark_nodes_stale_by_sub(sub_id),
        0,
        "清除 stale 失败"
    )
}

pub fn update_node_probe(
    node_id: &str,
    ping: i64,
    status: &str,
    count_failure: bool,
    expected_port: Option<i64>,
    expected_protocol: Option<&str>,
) -> Option<i64> {
    plain!(
        global().update_node_probe(
            node_id,
            ping,
            status,
            count_failure,
            expected_port,
            expected_protocol
        ),
        None,
        "探活落库失败"
    )
}

pub fn revive_node_probe(
    node_id: &str,
    ping: i64,
    expected_port: i64,
    expected_protocol: &str,
) -> Option<i64> {
    plain!(
        global().revive_node_probe(node_id, ping, expected_port, expected_protocol),
        None,
        "复活节点失败"
    )
}

pub fn disable_node_after_probe(
    node_id: &str,
    expected_port: i64,
    expected_protocol: &str,
    expected_fails: i64,
) -> bool {
    plain!(
        global().disable_node_after_probe(
            node_id,
            expected_port,
            expected_protocol,
            expected_fails
        ),
        false,
        "自动停用节点失败"
    )
}

pub fn list_relay_domains() -> Vec<RelayDomain> {
    plain!(
        global().list_relay_domains(),
        Vec::new(),
        "查询 relay 域名失败"
    )
}

pub fn upsert_relay_domains(domains: &[RelayDomain]) {
    if let Err(e) = global().upsert_relay_domains(domains) {
        tracing::error!(error = %e, "写入 relay 域名失败");
    }
}

pub fn upsert_relay_domains_json(domains: &Value) {
    if let Err(e) = global().upsert_relay_domains_json(domains) {
        tracing::error!(error = %e, "写入 relay 域名失败");
    }
}

pub fn list_subs() -> Vec<Subscription> {
    plain!(global().list_subs(), Vec::new(), "查询订阅失败")
}

pub fn get_sub(sub_id: &str) -> Option<Subscription> {
    plain!(global().get_sub(sub_id), None, "查询订阅失败")
}

pub fn get_sub_row(sub_id: &str) -> Option<SubRow> {
    plain!(global().get_sub_row(sub_id), None, "查询订阅失败")
}

pub fn get_sub_snapshot(sub_id: &str) -> Option<String> {
    plain!(global().get_sub_snapshot(sub_id), None, "查询订阅快照失败")
}

pub fn create_sub(url: &str, name: Option<&str>, group: Option<&str>) -> Option<Subscription> {
    plain!(global().create_sub(url, name, group), None, "创建订阅失败")
}

pub fn update_sub(sub_id: &str, patch: &Value) -> Option<Subscription> {
    plain!(global().update_sub(sub_id, patch), None, "更新订阅失败")
}

pub fn delete_sub(sub_id: &str) -> bool {
    plain!(global().delete_sub(sub_id), false, "删除订阅失败")
}

pub fn get_setting(key: &str) -> Value {
    plain!(global().get_setting(key), Value::Null, "读取设置失败")
}

pub fn get_setting_or(key: &str, default: Value) -> Value {
    plain!(
        global().get_setting_or(key, default),
        Value::Null,
        "读取设置失败"
    )
}

pub fn set_setting(key: &str, value: &Value) {
    if let Err(e) = global().set_setting(key, value) {
        tracing::error!(error = %e, "写入设置失败");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn db() -> Db {
        Db::open_in_memory().expect("内存库")
    }

    fn node_json(name: &str, port: i64) -> Value {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(1);
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        json!({
            "name": name,
            "protocol": "shadowsocks",
            "port": port,
            "rawConfig": {
                "server": format!("10.{}.{}.7", n / 250, n % 250),
                "server_port": 8388,
                "password": "pw"
            }
        })
    }

    fn j(n: &Node) -> Value {
        serde_json::to_value(n).unwrap()
    }

    fn ports(items: &[Node]) -> Vec<i64> {
        let mut v: Vec<i64> = items.iter().filter_map(|n| n.base.port).collect();
        v.sort_unstable();
        v
    }

    fn set_fails(d: &Db, id: &str, n: i64) {
        d.execute(
            &format!("UPDATE nodes SET consecutive_fails={n} WHERE id='{id}'"),
            &[],
        )
        .unwrap();
    }

    // 1. 23 列 INSERT 与 camelCase 字段落库
    #[test]
    fn batch_insert_uses_full_schema() {
        let d = db();
        let n = json!({
            "name": "n1", "protocol": "shadowsocks", "group": "G", "port": 0,
            "segment": 2, "authUser": "u", "authPass": "p",
            "rawConfig": {"server": "2.2.2.2", "server_port": 8443},
            "subId": "sub-1", "subName": "订阅A", "status": "online", "ping": 12,
            "exitIp": "9.9.9.9", "upTraffic": 1, "downTraffic": 2,
            "entryProto": "mixed", "ssPass": "abcd",
            "exitCountry": "US", "exitFlag": "flag", "exitCity": "SF", "exitType": "res",
            "exitScore": 90, "exitRisk": 1, "disabledAuto": true
        });
        let r = d.create_node_batch_json(&[n], false).unwrap();
        assert_eq!((r.created, r.updated, r.skipped, r.duplicate), (1, 0, 0, 0));
        let node = &r.items[0];
        assert_eq!(node.base.port, Some(52001));
        assert!(node.created_at.unwrap_or(0) > 0);
        assert_eq!(node.base.disabled_auto, Some(true));
        // 批量 INSERT 不含 exit_* 列（与 Python 版 SQL 一致），只落库 23 列
        assert_eq!(node.base.exit_country, None);
        assert_eq!(node.base.sub_name.as_deref(), Some("订阅A"));
        assert_eq!(node.base.status.as_deref(), Some("online"));
    }

    // 2. 自动分配跳过 reservedPorts
    #[test]
    fn auto_port_skips_reserved() {
        let d = db();
        d.set_setting("system", &json!({"reservedPorts": ["bad", "52001", 52003]}))
            .unwrap();
        let batch = vec![node_json("a", 0), node_json("b", 0), node_json("c", 0)];
        let r = d.create_node_batch_json(&batch, false).unwrap();
        assert_eq!(r.created, 3);
        assert_eq!(ports(&r.items), vec![52002, 52004, 52005]);
    }

    // 3. 非法监听端口一律跳过
    #[test]
    fn invalid_listen_port_rejected() {
        for bad in [
            json!(-1),
            json!(65536),
            json!("broken"),
            json!(4.5),
            json!(true),
        ] {
            let d = db();
            let mut n = node_json("bad", 0);
            n["port"] = bad.clone();
            let r = d.create_node_batch_json(&[n], false).unwrap();
            assert_eq!(r.created, 0, "created for {bad}");
            assert_eq!(r.skipped, 1, "skipped for {bad}");
            assert!(d.list_nodes(None, None, None).unwrap().is_empty());
        }
    }

    // 4. 上游端口非法不阻塞同批好行
    #[test]
    fn bad_upstream_port_only_skips_that_row() {
        let d = db();
        let mut bad = node_json("bad", 0);
        bad["rawConfig"] = json!({"server": "3.3.3.3", "server_port": "oops"});
        let good = node_json("good", 0);
        let r = d.create_node_batch_json(&[bad, good], false).unwrap();
        assert_eq!((r.created, r.skipped), (1, 1));
        let all = d.list_nodes(None, None, None).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].base.name, "good");
    }

    // 5. 端口池耗尽
    #[test]
    fn port_pool_exhausted() {
        let d = db();
        let reserved: Vec<Value> = (DEFAULT_PORT_BASE..=MAX_PORT).map(Value::from).collect();
        d.set_setting("system", &json!({ "reservedPorts": reserved }))
            .unwrap();
        let r = d
            .create_node_batch_json(&[node_json("a", 0)], false)
            .unwrap();
        assert_eq!((r.created, r.skipped), (0, 1));
        assert_eq!(d.get_next_available_port(None).unwrap(), None);
    }

    // 6. 显式 65535 冲突
    #[test]
    fn explicit_port_conflict_skips() {
        let d = db();
        let r = d
            .create_node_batch_json(&[node_json("a", MAX_PORT)], false)
            .unwrap();
        assert_eq!(r.created, 1);
        let r2 = d
            .create_node_batch_json(&[node_json("b", MAX_PORT)], false)
            .unwrap();
        assert_eq!((r2.created, r2.skipped), (0, 1));
    }

    // 7. 非法端口 update 全 noop
    #[test]
    fn invalid_port_updates_are_noops() {
        let d = db();
        let node = d
            .create_node_batch_json(&[node_json("a", 52001)], false)
            .unwrap()
            .items[0]
            .clone();
        assert!(d.update_node_port(&node.id, Some(-1)).unwrap().is_none());
        assert!(d
            .update_node_json(&node.id, &json!({"port": "broken"}))
            .unwrap()
            .is_none());
        assert_eq!(d.get_next_available_port(Some(-1)).unwrap(), None);
        let after = d.get_node(&node.id).unwrap().unwrap();
        assert_eq!(j(&after), j(&node));
    }

    // 8. 池耗尽时 update 端口返回 None 且不改
    #[test]
    fn exhausted_pool_update_is_noop() {
        let d = db();
        let node = d
            .create_node_batch_json(&[node_json("a", 52001)], false)
            .unwrap()
            .items[0]
            .clone();
        let reserved: Vec<Value> = (DEFAULT_PORT_BASE..=MAX_PORT).map(Value::from).collect();
        d.set_setting("system", &json!({ "reservedPorts": reserved }))
            .unwrap();
        assert!(d.update_node_port(&node.id, None).unwrap().is_none());
        assert!(d
            .update_node_json(&node.id, &json!({"port": 0}))
            .unwrap()
            .is_none());
        let after = d.get_node(&node.id).unwrap().unwrap();
        assert_eq!(after.base.port, Some(52001));
    }

    // 9. 显式 status 变更清零计数并清除自动停用标记
    #[test]
    fn explicit_status_change_resets_counters() {
        let d = db();
        let node = d
            .create_node_batch_json(&[node_json("a", 52001)], false)
            .unwrap()
            .items[0]
            .clone();
        set_fails(&d, &node.id, 24);
        d.execute(
            &format!("UPDATE nodes SET disabled_auto=1 WHERE id='{}'", node.id),
            &[],
        )
        .unwrap();
        for status in ["disabled", "offline", "online"] {
            let after = d
                .update_node_json(&node.id, &json!({"status": status}))
                .unwrap()
                .unwrap();
            assert_eq!(after.base.status.as_deref(), Some(status));
            assert_eq!(after.base.consecutive_fails, Some(0));
            assert_eq!(after.base.disabled_auto, Some(false));
        }
    }

    // 10. 非 status patch 保留探活状态
    #[test]
    fn non_status_patch_keeps_probe_state() {
        let d = db();
        let node = d
            .create_node_batch_json(&[node_json("a", 52001)], false)
            .unwrap()
            .items[0]
            .clone();
        set_fails(&d, &node.id, 24);
        d.execute(
            &format!(
                "UPDATE nodes SET status='disabled', disabled_auto=1 WHERE id='{}'",
                node.id
            ),
            &[],
        )
        .unwrap();
        let after = d
            .update_node_json(&node.id, &json!({"exitIp": "1.2.3.4", "name": "renamed"}))
            .unwrap()
            .unwrap();
        assert_eq!(after.base.status.as_deref(), Some("disabled"));
        assert_eq!(after.base.consecutive_fails, Some(24));
        assert_eq!(after.base.disabled_auto, Some(true));
        assert_eq!(after.base.exit_ip.as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn update_node_json_upstream_raw_config_merge_and_exit_ip_reset() {
        let d = db();
        let mut initial_node = node_json("test-upstream", 52002);
        initial_node["rawConfig"] = json!({
            "server": "1.1.1.1",
            "server_port": 1080,
            "username": "user1",
            "password": "pass1",
            "method": "aes-256-gcm"
        });
        initial_node["exitIp"] = json!("1.1.1.1");
        initial_node["ping"] = json!(88);
        initial_node["exitCountry"] = json!("HK");

        let node = d
            .create_node_batch_json(&[initial_node], false)
            .unwrap()
            .items[0]
            .clone();

        // 1. 只改 server，验证浅合并（保留 password、username 等）且 exit_ip 重置为 N/A、ping 归零、exitCountry 清空
        let updated = d
            .update_node_json(
                &node.id,
                &json!({
                    "rawConfig": {
                        "server": "2.2.2.2"
                    }
                }),
            )
            .unwrap()
            .unwrap();

        assert_eq!(updated.base.exit_ip.as_deref(), Some("N/A"));
        assert_eq!(updated.base.ping, Some(0));
        assert_eq!(updated.base.exit_country, None);

        let raw = updated.base.raw_config.unwrap();
        assert_eq!(raw["server"], json!("2.2.2.2"));
        assert_eq!(raw["server_port"], json!(1080));
        assert_eq!(raw["username"], json!("user1"));
        assert_eq!(raw["password"], json!("pass1"));

        // 2. 改原始端口 server_port，同样触发 reset
        d.update_node_json(
            &node.id,
            &json!({"exitIp": "9.9.9.9", "ping": 50, "exitCountry": "US"}),
        )
        .unwrap();

        let updated2 = d
            .update_node_json(
                &node.id,
                &json!({
                    "rawConfig": {
                        "server_port": 2080
                    }
                }),
            )
            .unwrap()
            .unwrap();

        assert_eq!(updated2.base.exit_ip.as_deref(), Some("N/A"));
        assert_eq!(updated2.base.ping, Some(0));
        assert_eq!(updated2.base.exit_country, None);
        let raw2 = updated2.base.raw_config.unwrap();
        assert_eq!(raw2["server"], json!("2.2.2.2"));
        assert_eq!(raw2["server_port"], json!(2080));

        // 3. 改协议（从 shadowsocks 改为 vless），同样触发 reset
        d.update_node_json(&node.id, &json!({"exitIp": "9.9.9.9", "ping": 50}))
            .unwrap();
        let updated3 = d
            .update_node_json(&node.id, &json!({"protocol": "vless"}))
            .unwrap()
            .unwrap();
        assert_eq!(updated3.base.protocol, "vless");
        assert_eq!(updated3.base.exit_ip.as_deref(), Some("N/A"));
        assert_eq!(updated3.base.ping, Some(0));

        // 4. 只改 remark 名称，不应重置 exit_ip 与 ping
        d.update_node_json(&node.id, &json!({"exitIp": "9.9.9.9", "ping": 50}))
            .unwrap();
        let updated4 = d
            .update_node_json(&node.id, &json!({"name": "renamed-upstream"}))
            .unwrap()
            .unwrap();
        assert_eq!(updated4.base.name, "renamed-upstream");
        assert_eq!(updated4.base.exit_ip.as_deref(), Some("9.9.9.9"));
        assert_eq!(updated4.base.ping, Some(50));
    }

    // 11. 老库迁移补回 disabled_auto
    #[test]
    fn migration_readds_disabled_auto() {
        let d = db();
        let node = d
            .create_node_batch_json(&[node_json("a", 52001)], false)
            .unwrap()
            .items[0]
            .clone();
        d.execute("ALTER TABLE nodes DROP COLUMN disabled_auto", &[])
            .unwrap();
        d.init_db().unwrap();
        let after = d.get_node(&node.id).unwrap().unwrap();
        assert_eq!(after.base.disabled_auto, Some(false));
        d.execute("UPDATE nodes SET disabled_auto=1", &[]).unwrap();
        d.init_db().unwrap();
        let after2 = d.get_node(&node.id).unwrap().unwrap();
        assert_eq!(after2.base.disabled_auto, Some(true));
    }

    // 12. 探活计数语义
    #[test]
    fn probe_failure_counting() {
        let d = db();
        let node = d
            .create_node_batch_json(&[node_json("a", 52001)], false)
            .unwrap()
            .items[0]
            .clone();
        let port = node.base.port.unwrap();
        assert_eq!(
            d.update_node_probe(
                &node.id,
                0,
                "offline",
                true,
                Some(port),
                Some("shadowsocks")
            )
            .unwrap(),
            Some(1)
        );
        assert_eq!(
            d.update_node_probe(
                &node.id,
                0,
                "offline",
                false,
                Some(port),
                Some("shadowsocks")
            )
            .unwrap(),
            Some(1)
        );
        assert_eq!(
            d.update_node_probe(
                &node.id,
                24,
                "online",
                true,
                Some(port),
                Some("shadowsocks")
            )
            .unwrap(),
            Some(0)
        );
        let after = d.get_node(&node.id).unwrap().unwrap();
        assert_eq!(after.base.status.as_deref(), Some("online"));
        assert_eq!(after.base.ping, Some(24));
    }

    // 13. 手动停用后迟到结果被丢弃
    #[test]
    fn late_probe_result_dropped_when_disabled() {
        let d = db();
        let node = d
            .create_node_batch_json(&[node_json("a", 52001)], false)
            .unwrap()
            .items[0]
            .clone();
        let port = node.base.port.unwrap();
        let before = d
            .update_node_json(&node.id, &json!({"status": "disabled"}))
            .unwrap()
            .unwrap();
        assert_eq!(
            d.update_node_probe(
                &node.id,
                24,
                "online",
                true,
                Some(port),
                Some("shadowsocks")
            )
            .unwrap(),
            None
        );
        assert_eq!(
            d.update_node_probe(
                &node.id,
                0,
                "offline",
                false,
                Some(port),
                Some("shadowsocks")
            )
            .unwrap(),
            None
        );
        let after = d.get_node(&node.id).unwrap().unwrap();
        assert_eq!(j(&after), j(&before));
    }

    // 14. tag 变化（端口/协议）后迟到结果被丢弃
    #[test]
    fn stale_tag_probe_dropped() {
        let d = db();
        let node = d
            .create_node_batch_json(&[node_json("a", 52001)], false)
            .unwrap()
            .items[0]
            .clone();
        let port = node.base.port.unwrap();
        assert_eq!(
            d.update_node_probe(
                &node.id,
                24,
                "online",
                true,
                Some(port + 1),
                Some("shadowsocks")
            )
            .unwrap(),
            None
        );
        assert_eq!(
            d.update_node_probe(&node.id, 24, "online", true, Some(port), Some("vless"))
                .unwrap(),
            None
        );
        let after = d.get_node(&node.id).unwrap().unwrap();
        assert_eq!(j(&after), j(&node));
    }

    // 15. 不存在的节点
    #[test]
    fn missing_node_probe_returns_none() {
        let d = db();
        assert_eq!(
            d.update_node_probe("node-dead", 12, "online", true, None, None)
                .unwrap(),
            None
        );
        assert_eq!(
            d.revive_node_probe("node-dead", 12, 52001, "shadowsocks")
                .unwrap(),
            None
        );
    }

    // 16. 自动停用 CAS
    #[test]
    fn disable_after_probe_cas() {
        let d = db();
        let node = d
            .create_node_batch_json(&[node_json("a", 52001)], false)
            .unwrap()
            .items[0]
            .clone();
        let port = node.base.port.unwrap();
        set_fails(&d, &node.id, 20);
        assert!(!d
            .disable_node_after_probe(&node.id, port, "shadowsocks", 19)
            .unwrap());
        assert!(!d
            .disable_node_after_probe(&node.id, port, "shadowsocks", 21)
            .unwrap());
        assert!(!d
            .disable_node_after_probe(&node.id, port + 1, "shadowsocks", 20)
            .unwrap());
        assert!(!d
            .disable_node_after_probe(&node.id, port, "vless", 20)
            .unwrap());
        assert!(d
            .disable_node_after_probe(&node.id, port, "shadowsocks", 20)
            .unwrap());
        let after = d.get_node(&node.id).unwrap().unwrap();
        assert_eq!(after.base.status.as_deref(), Some("disabled"));
        assert_eq!(after.base.disabled_auto, Some(true));
        assert_eq!(after.base.consecutive_fails, Some(20));
        assert!(!d
            .disable_node_after_probe(&node.id, port, "shadowsocks", 20)
            .unwrap());
    }

    // 17. 手动停用节点永不被自动停用覆盖
    #[test]
    fn manual_disable_never_auto_disabled() {
        let d = db();
        let node = d
            .create_node_batch_json(&[node_json("a", 52001)], false)
            .unwrap()
            .items[0]
            .clone();
        let port = node.base.port.unwrap();
        d.update_node_json(&node.id, &json!({"status": "disabled"}))
            .unwrap();
        set_fails(&d, &node.id, 20);
        assert!(!d
            .disable_node_after_probe(&node.id, port, "shadowsocks", 20)
            .unwrap());
        let after = d.get_node(&node.id).unwrap().unwrap();
        assert_eq!(after.base.disabled_auto, Some(false));
    }

    // 18. 自动复活只认 tag 匹配的自动停用节点
    #[test]
    fn revive_only_auto_disabled_matching_tag() {
        let d = db();
        let node = d
            .create_node_batch_json(&[node_json("a", 52001)], false)
            .unwrap()
            .items[0]
            .clone();
        let port = node.base.port.unwrap();
        d.update_node_json(
            &node.id,
            &json!({"status": "disabled", "disabledAuto": true}),
        )
        .unwrap();
        assert_eq!(
            d.revive_node_probe(&node.id, 24, port + 1, "shadowsocks")
                .unwrap(),
            None
        );
        assert_eq!(
            d.revive_node_probe(&node.id, 24, port, "vless").unwrap(),
            None
        );
        assert_eq!(
            d.revive_node_probe(&node.id, 24, port, "shadowsocks")
                .unwrap(),
            Some(0)
        );
        let after = d.get_node(&node.id).unwrap().unwrap();
        assert_eq!(after.base.status.as_deref(), Some("online"));
        assert_eq!(after.base.ping, Some(24));
        assert_eq!(after.base.consecutive_fails, Some(0));
        assert_eq!(after.base.disabled_auto, Some(false));
        assert_eq!(
            d.revive_node_probe(&node.id, 24, port, "shadowsocks")
                .unwrap(),
            None
        );
    }

    // 19. 手动停用节点不被自动复活
    #[test]
    fn manual_disabled_never_revived() {
        let d = db();
        let node = d
            .create_node_batch_json(&[node_json("a", 52001)], false)
            .unwrap()
            .items[0]
            .clone();
        let port = node.base.port.unwrap();
        let before = d
            .update_node_json(&node.id, &json!({"status": "disabled"}))
            .unwrap()
            .unwrap();
        assert_eq!(
            d.revive_node_probe(&node.id, 24, port, "shadowsocks")
                .unwrap(),
            None
        );
        let after = d.get_node(&node.id).unwrap().unwrap();
        assert_eq!(j(&after), j(&before));
    }

    // 20. 订阅刷新只覆盖上游字段
    #[test]
    fn sub_refresh_only_updates_upstream_fields() {
        let d = db();
        let mut created = node_json("old-name", 53001);
        created["subId"] = json!("sub-x");
        created["subName"] = json!("旧订阅名");
        created["rawConfig"] = json!({"server": "5.5.5.5", "server_port": 443, "password": "p1"});
        let node = d.create_node_batch_json(&[created], false).unwrap().items[0].clone();
        // 本地运维字段（刷新绝不允许覆盖）
        d.update_node_json(
            &node.id,
            &json!({"exitCountry": "JP", "exitScore": 77, "upTraffic": 111, "disabledAuto": true}),
        )
        .unwrap();
        let before = d.get_node(&node.id).unwrap().unwrap();

        let mut incoming = node_json("new-name", 0);
        incoming["protocol"] = json!("vless");
        incoming["subId"] = json!("sub-x");
        incoming["subName"] = json!("新订阅名");
        incoming["stale"] = json!(true);
        incoming["rawConfig"] = json!({"server": "5.5.5.5", "server_port": 443, "password": "p2"});
        let r = d.create_node_batch_json(&[incoming.clone()], true).unwrap();
        assert_eq!((r.created, r.updated, r.skipped, r.duplicate), (0, 1, 0, 0));
        assert_eq!(r.items.len(), 1);
        let after = d.get_node(&node.id).unwrap().unwrap();
        assert_eq!(j(&r.items[0]), j(&after));
        assert_eq!(after.base.name, "new-name");
        assert_eq!(after.base.protocol, "vless");
        assert_eq!(after.base.sub_name.as_deref(), Some("新订阅名"));
        assert!(after.stale);
        assert_eq!(after.base.port, before.base.port);
        assert_eq!(after.base.exit_country.as_deref(), Some("JP"));
        assert_eq!(after.base.exit_score, Some(77));
        assert_eq!(after.base.up_traffic, Some(111));
        assert_eq!(after.base.disabled_auto, Some(true));
        assert_eq!(
            after.base.raw_config.as_ref().unwrap()["password"],
            json!("p2")
        );

        // 键序变化不算变化
        let mut reordered = incoming.clone();
        reordered["rawConfig"] = json!({"password": "p2", "server_port": 443, "server": "5.5.5.5"});
        let r2 = d.create_node_batch_json(&[reordered], true).unwrap();
        assert_eq!(
            (r2.created, r2.updated, r2.skipped, r2.duplicate),
            (0, 0, 0, 1)
        );
        assert_eq!(j(&d.get_node(&node.id).unwrap().unwrap()), j(&after));
    }

    // 21. 非刷新路径重复导入
    #[test]
    fn non_refresh_duplicate_import() {
        let d = db();
        let n = node_json("a", 52001);
        assert_eq!(
            d.create_node_batch_json(std::slice::from_ref(&n), false)
                .unwrap()
                .created,
            1
        );
        let r = d.create_node_batch_json(&[n], false).unwrap();
        assert_eq!((r.created, r.updated, r.skipped, r.duplicate), (0, 0, 1, 1));
    }

    // 22. 批量流量整批提交、负数截断
    #[test]
    fn traffic_batch_truncates_negatives() {
        let d = db();
        let a = d
            .create_node_batch_json(&[node_json("a", 52001)], false)
            .unwrap()
            .items[0]
            .clone();
        let b = d
            .create_node_batch_json(&[node_json("b", 52002)], false)
            .unwrap()
            .items[0]
            .clone();
        d.execute(
            &format!(
                "UPDATE nodes SET up_traffic=10, down_traffic=20 WHERE id='{}'",
                a.id
            ),
            &[],
        )
        .unwrap();
        let mut deltas: HashMap<String, (i64, i64)> = HashMap::new();
        deltas.insert(a.id.clone(), (4, 7));
        deltas.insert(b.id.clone(), (-9, 3));
        deltas.insert("missing".into(), (10, 20));
        d.add_traffic_batch(&deltas).unwrap();
        let a2 = d.get_node(&a.id).unwrap().unwrap();
        let b2 = d.get_node(&b.id).unwrap().unwrap();
        assert_eq!(
            (a2.base.up_traffic, a2.base.down_traffic),
            (Some(14), Some(27))
        );
        assert_eq!(
            (b2.base.up_traffic, b2.base.down_traffic),
            (Some(0), Some(3))
        );
        d.reset_node_traffic(&a.id).unwrap();
        assert_eq!(d.get_node(&a.id).unwrap().unwrap().base.up_traffic, Some(0));
        d.reset_all_traffic().unwrap();
        assert_eq!(
            d.get_node(&b.id).unwrap().unwrap().base.down_traffic,
            Some(0)
        );
    }

    // 节点 CRUD / 分组 / stale / 删除指纹
    #[test]
    fn node_crud_and_group_ops() {
        let d = db();
        let a = d
            .create_node_batch_json(&[node_json("a", 52001)], false)
            .unwrap()
            .items[0]
            .clone();
        let b = d
            .create_node_batch_json(&[node_json("b", 52002)], false)
            .unwrap()
            .items[0]
            .clone();
        assert_eq!(d.list_nodes(None, None, None).unwrap().len(), 2);
        assert_eq!(d.list_nodes(Some("b"), None, None).unwrap().len(), 1);
        assert_eq!(
            d.update_nodes_group(&[a.id.clone(), b.id.clone()], "G2")
                .unwrap(),
            2
        );
        assert_eq!(d.list_nodes(None, Some("G2"), None).unwrap().len(), 2);
        assert_eq!(d.update_nodes_group(&[], "x").unwrap(), 0);
        assert_eq!(d.mark_nodes_stale_by_sub("sub-none").unwrap(), 0);
        assert_eq!(d.unmark_nodes_stale_by_sub("sub-none").unwrap(), 0);
        // 单节点创建 / 删除
        let one = d
            .create_node(&NodeCreate {
                name: "solo".into(),
                protocol: "ss".into(),
                port: Some(53100),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(one.base.port, Some(53100));
        assert!(d.delete_node(&one.id).unwrap());
        assert!(!d.delete_node(&one.id).unwrap());
        // 删除指纹阻止订阅刷新重复导入
        let mut sub_node = node_json("z", 0);
        sub_node["subId"] = json!("sub-z");
        let z = d
            .create_node_batch_json(&[sub_node.clone()], true)
            .unwrap()
            .items[0]
            .clone();
        assert_eq!(d.delete_node_batch(std::slice::from_ref(&z.id)).unwrap(), 1);
        let again = d.create_node_batch_json(&[sub_node], true).unwrap();
        assert_eq!((again.created, again.skipped), (0, 1));
    }

    // settings KV
    #[test]
    fn settings_roundtrip() {
        let d = db();
        assert_eq!(d.get_setting("missing").unwrap(), Value::Null);
        d.set_setting("auth", &json!({"password": "pw", "用户名": "根"}))
            .unwrap();
        assert_eq!(d.get_setting("auth").unwrap()["password"], json!("pw"));
        // 非 JSON 值原样返回
        d.execute(
            "INSERT OR REPLACE INTO settings (key,value) VALUES ('raw','not-json')",
            &[],
        )
        .unwrap();
        assert_eq!(d.get_setting("raw").unwrap(), json!("not-json"));
        assert_eq!(d.get_setting_or("missing", json!(5)).unwrap(), json!(5));
    }

    // 订阅 CRUD
    #[test]
    fn subscription_crud() {
        let d = db();
        let s = d
            .create_sub(
                "https://example.com/sub/very-long-url-0123456789",
                None,
                None,
            )
            .unwrap()
            .unwrap();
        assert_eq!(s.group, DEFAULT_SUB_GROUP);
        assert_eq!(s.name, "https://example.com/sub/very-long-url-01");
        assert_eq!(s.name.chars().count(), 40);
        assert!(s.enabled);
        assert!(!s.stale && !s.degraded);
        assert!(d
            .create_sub(
                "https://example.com/sub/very-long-url-0123456789",
                None,
                None
            )
            .unwrap()
            .is_none());

        let updated = d
            .update_sub(&s.id, &json!({"last_refresh": 123, "node_count": 7, "snapshot": "{}", "pending_apply": 1}))
            .unwrap()
            .unwrap();
        assert_eq!(updated.last_refresh, Some(123));
        assert_eq!(updated.node_count, 7);
        assert!(updated.pending_apply);
        assert!(d.get_sub_snapshot(&s.id).unwrap().is_some());

        let alarmed = d
            .update_sub(&s.id, &json!({"last_error": "boom"}))
            .unwrap()
            .unwrap();
        assert!(alarmed.degraded);
        assert!(!alarmed.stale);
        // 从未抓过快照的订阅：last_error 有值 -> stale
        let fresh = d
            .create_sub("https://example.com/sub/fresh-no-snapshot", None, None)
            .unwrap()
            .unwrap();
        let alerted = d
            .update_sub(&fresh.id, &json!({"last_error": "boom"}))
            .unwrap()
            .unwrap();
        assert!(alerted.stale);
        assert!(!alerted.degraded);
        let cleared = d
            .update_sub(&s.id, &json!({"last_error": null}))
            .unwrap()
            .unwrap();
        assert_eq!(cleared.last_error, None);
        assert!(!cleared.stale && !cleared.degraded);
        assert_eq!(d.list_subs().unwrap().len(), 2);
        assert!(d
            .update_sub("sub-missing", &json!({"name": "x"}))
            .unwrap()
            .is_none());
        assert!(d.delete_sub(&s.id).unwrap());
        assert!(!d.delete_sub(&s.id).unwrap());
    }

    // relay 域名 CRUD：整表替换 + 端口冲突跳过
    #[test]
    fn relay_domain_replace() {
        let d = db();
        d.upsert_relay_domains(&[
            RelayDomain {
                id: "1".into(),
                domain: "a.example".into(),
                port: 30001,
                auth_user: Some("u".into()),
                auth_pass: Some("p".into()),
                groups: vec![],
            },
            RelayDomain {
                id: "2".into(),
                domain: "b.example".into(),
                port: 30002,
                auth_user: None,
                auth_pass: None,
                groups: vec!["G".into()],
            },
        ])
        .unwrap();
        let list = d.list_relay_domains().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].groups, vec!["ALL".to_string()]);
        assert_eq!(list[1].groups, vec!["G".to_string()]);
        // 同端口冲突：保留先插入的行，跳过后来的
        d.upsert_relay_domains(&[
            RelayDomain {
                id: "3".into(),
                domain: "c.example".into(),
                port: 30003,
                auth_user: None,
                auth_pass: None,
                groups: vec![],
            },
            RelayDomain {
                id: "4".into(),
                domain: "d.example".into(),
                port: 30003,
                auth_user: None,
                auth_pass: None,
                groups: vec![],
            },
        ])
        .unwrap();
        let list2 = d.list_relay_domains().unwrap();
        assert_eq!(list2.len(), 1);
        assert_eq!(list2[0].domain, "c.example");
        // JSON 入口（settings 保存时使用 camelCase）
        d.upsert_relay_domains_json(&json!([
            {"id": "9", "domain": "e.example", "port": 30009, "authUser": "uu", "authPass": "pp", "groups": ["ALL"]}
        ]))
        .unwrap();
        let list3 = d.list_relay_domains().unwrap();
        assert_eq!(list3.len(), 1);
        assert_eq!(list3[0].auth_user.as_deref(), Some("uu"));
    }

    // 分组重命名联动 relay_domains 与 settings
    #[test]
    fn rename_group_cascades() {
        let d = db();
        let mut n = node_json("a", 52001);
        n["group"] = json!("旧组");
        d.create_node_batch_json(&[n], false).unwrap();
        d.upsert_relay_domains(&[RelayDomain {
            id: "r1".into(),
            domain: "x.example".into(),
            port: 30001,
            auth_user: None,
            auth_pass: None,
            groups: vec!["旧组".into()],
        }])
        .unwrap();
        d.set_setting(
            "system",
            &json!({"relayDomains": [{"id": "r1", "groups": ["旧组"]}], "reservedPorts": []}),
        )
        .unwrap();
        let r = d.rename_group("旧组", "新组").unwrap();
        assert_eq!((r.updated, r.relay_updated), (1, 1));
        assert_eq!(d.list_nodes(None, Some("新组"), None).unwrap().len(), 1);
        assert_eq!(
            d.list_relay_domains().unwrap()[0].groups,
            vec!["新组".to_string()]
        );
        assert_eq!(
            d.get_setting("system").unwrap()["relayDomains"][0]["groups"][0],
            json!("新组")
        );
        // 空/同名 noop
        assert_eq!(d.rename_group("", "x").unwrap().updated, 0);
        assert_eq!(d.rename_group("新组", "新组").unwrap().updated, 0);
        // ALL 组不参与替换
        d.upsert_relay_domains(&[RelayDomain {
            id: "r2".into(),
            domain: "y.example".into(),
            port: 30002,
            auth_user: None,
            auth_pass: None,
            groups: vec!["ALL".into()],
        }])
        .unwrap();
        assert_eq!(d.rename_group("ALL", "Z").unwrap().relay_updated, 0);
    }

    // 节点入口切换：保持已有密码或新生成
    #[test]
    fn entry_proto_switch_keeps_or_sets_pass() {
        let d = db();
        let node = d
            .create_node_batch_json(&[node_json("a", 52001)], false)
            .unwrap()
            .items[0]
            .clone();
        let a = d.update_node_entry(&node.id, "ss", None).unwrap().unwrap();
        let pass = a.base.ss_pass.clone().expect("自动生成密码");
        assert_eq!(pass.len(), 16);
        let b = d
            .update_node_entry(&node.id, "mixed", None)
            .unwrap()
            .unwrap();
        assert_eq!(b.base.ss_pass, Some(pass.clone()));
        let c = d
            .update_node_entry(&node.id, "ss", Some("manual"))
            .unwrap()
            .unwrap();
        assert_eq!(c.base.entry_proto.as_deref(), Some("ss"));
        assert_eq!(c.base.ss_pass.as_deref(), Some("manual"));
        assert!(d
            .update_node_entry("node-missing", "ss", None)
            .unwrap()
            .is_none());
    }

    // 单节点 update 端口重分配 / 单节点累计流量
    #[test]
    fn port_reassign_and_traffic() {
        let d = db();
        let a = d
            .create_node_batch_json(&[node_json("a", 52001)], false)
            .unwrap()
            .items[0]
            .clone();
        let b = d
            .create_node_batch_json(&[node_json("b", 52002)], false)
            .unwrap()
            .items[0]
            .clone();
        // 撞别人的端口 -> 自动顺位
        let moved = d.update_node_port(&b.id, Some(52001)).unwrap().unwrap();
        // Python _next_available_port_locked 重算 used（含本行旧端口）-> 52003
        assert_eq!(moved.base.port, Some(52003));
        // 改自己的端口 -> 允许
        let same = d.update_node_port(&a.id, Some(52001)).unwrap().unwrap();
        assert_eq!(same.base.port, Some(52001));
        d.add_traffic(&a.id, 3, 4).unwrap();
        d.add_traffic(&a.id, -5, -6).unwrap();
        let after = d.get_node(&a.id).unwrap().unwrap();
        assert_eq!(
            (after.base.up_traffic, after.base.down_traffic),
            (Some(3), Some(4))
        );
        assert!(d
            .update_node_port("node-missing", Some(52010))
            .unwrap()
            .is_none());
    }

    // parse_port 边界
    #[test]
    fn parse_port_rules() {
        assert_eq!(parse_port(None, true), Some(0));
        assert_eq!(parse_port(None, false), None);
        assert_eq!(parse_port(Some(&json!(0)), true), Some(0));
        assert_eq!(parse_port(Some(&json!(0)), false), None);
        assert_eq!(parse_port(Some(&json!("52001")), false), Some(52001));
        assert_eq!(parse_port(Some(&json!(4.5)), true), None);
        assert_eq!(parse_port(Some(&json!(true)), false), None);
        assert_eq!(parse_port(Some(&json!(65535)), false), Some(65535));
        assert_eq!(parse_port(Some(&json!(65536)), false), None);
        assert_eq!(parse_port_i64(Some(-1), true), None);
    }

    // 初始化幂等 + 表/索引齐全
    #[test]
    fn init_db_is_idempotent_and_creates_schema() {
        let d = db();
        d.init_db().unwrap();
        d.init_db().unwrap();
        let names: Vec<String> = d.with_conn(|c| {
            let mut st = c
                .prepare(
                    "SELECT name FROM sqlite_master WHERE type IN ('table','index') ORDER BY name",
                )
                .unwrap();
            st.query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .map(|r| r.unwrap())
                .collect()
        });
        for want in [
            "nodes",
            "relay_domains",
            "subscriptions",
            "settings",
            "deleted_fingerprints",
            "idx_nodes_sub",
            "idx_nodes_port",
        ] {
            assert!(
                names.iter().any(|n| n == want),
                "缺少 {want}，实际 {:?}",
                names
            );
        }
        // 新增列齐全（含 exit_* / disabled_auto / consecutive_fails）
        let cols: Vec<String> = d.with_conn(|c| {
            let mut st = c.prepare("PRAGMA table_info(nodes)").unwrap();
            st.query_map([], |r| r.get::<_, String>(1))
                .unwrap()
                .map(|r| r.unwrap())
                .collect()
        });
        for want in [
            "consecutive_fails",
            "disabled_auto",
            "exit_country",
            "exit_score",
            "entry_proto",
            "ss_pass",
            "sub_name",
        ] {
            assert!(cols.iter().any(|c| c == want), "nodes 缺少列 {want}");
        }
        // 重复 init 不丢数据
        let n = d
            .create_node_batch_json(&[node_json("keep", 0)], false)
            .unwrap();
        assert_eq!(n.created, 1);
        d.init_db().unwrap();
        assert_eq!(d.list_nodes(None, None, None).unwrap().len(), 1);
    }

    // list_nodes 的 q / group / sub_id 过滤与端口排序
    #[test]
    fn list_nodes_filters() {
        let d = db();
        let mut a = node_json("东京-1", 52010);
        a["group"] = json!("A组");
        a["subId"] = json!("sub-1");
        let mut b = node_json("首尔-2", 52005);
        b["group"] = json!("B组");
        b["subId"] = json!("sub-2");
        let mut c = node_json("东京-3", 52030);
        c["group"] = json!("A组");
        c["subId"] = json!("sub-1");
        d.create_node_batch_json(&[a, b, c], false).unwrap();

        let all = d.list_nodes(None, None, None).unwrap();
        let order: Vec<i64> = all.iter().filter_map(|n| n.base.port).collect();
        assert_eq!(order, vec![52005, 52010, 52030]);

        assert_eq!(d.list_nodes(Some("东京"), None, None).unwrap().len(), 2);
        assert_eq!(d.list_nodes(Some("52005"), None, None).unwrap().len(), 1);
        assert_eq!(d.list_nodes(None, Some("A组"), None).unwrap().len(), 2);
        assert_eq!(d.list_nodes(None, Some("ALL"), None).unwrap().len(), 3);
        assert_eq!(d.list_nodes(None, None, Some("sub-1")).unwrap().len(), 2);
        assert_eq!(
            d.list_nodes(Some("东京"), Some("A组"), Some("sub-1"))
                .unwrap()
                .len(),
            2
        );
        assert!(d.list_nodes(None, None, Some("sub-x")).unwrap().is_empty());
    }
}
