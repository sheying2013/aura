//! HTTP 层：把 backend/app.py 的 39 个端点搬到 axum，保持请求/响应逐字一致。
//!
//! 设计要点：
//! - 鉴权走 middleware（等价 FastAPI 的 Depends(require_auth)），AUTH_DISABLED=1 时全放行；
//! - 错误统一用 ApiError，输出 {"detail": ...}，detail 允许是字符串或对象（与 FastAPI 一致）；
//! - 静态站点挂到 PANEL_PATH，根路径与 PANEL_PATH 都 307 到 PANEL_PATH/；
//! - 统计流用 SSE，帧格式 data: <payload> 加两个换行。

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{ConnectInfo, Path, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{get, post, put},
    Json, Router,
};
use futures_util::stream;
use serde_json::{json, Map, Value};
use tower_http::services::ServeDir;

use crate::auth::Auth;
use crate::db::Db;
use crate::stats::Stats;
use crate::subs_proxy::{self, ConfigApplier, SubsStore};
use crate::subscription_fetch::SubscriptionFetcher;
use crate::types::{
    DeleteBatchRequest, EntryConvertRequest, NodeBatchRequest, NodeBatchResponse, NodeCreate,
    NodeListResponse, PingRequest, RelayDomain, SubCreate, SubFetchRequest, SubParseRequest,
    SubParseResponse, SubRefreshRequest, SubRefreshResponse, SubToggleRequest,
};
use crate::wire::{used_ports, BoxFut, ConfigService, Prober};

/// 默认面板路径（与 Python panel_path 缺省一致）。
pub const DEFAULT_PANEL_PATH: &str = "/admin";
/// clash API 查询连接列表的超时。
pub const CONNECTIONS_TIMEOUT: Duration = Duration::from_secs(3);
/// clash API 查询代理当前的超时。
pub const PROXIES_TIMEOUT: Duration = Duration::from_secs(2);
/// 原生代理协议：这些协议的节点不需要 sing-box 在跑也能直连探测。
pub const NATIVE_PROXY_PROTOS: [&str; 3] = ["socks5", "socks", "http"];
/// 密码修改前允许访问的 (method, path)。
const SETUP_ROUTES: [(Method, &str); 4] = [
    (Method::GET, "/api/auth/check"),
    (Method::GET, "/api/auth/status"),
    (Method::POST, "/api/auth/change-password"),
    (Method::POST, "/api/auth/logout"),
];

pub type ApiResult<T> = Result<T, ApiError>;

/// 与 FastAPI HTTPException 等价的错误：状态码 + detail。
#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: StatusCode,
    pub detail: Value,
}

impl ApiError {
    pub fn new(status: StatusCode, detail: Value) -> Self {
        Self { status, detail }
    }

    pub fn message(status: StatusCode, msg: impl Into<String>) -> Self {
        Self {
            status,
            detail: Value::String(msg.into()),
        }
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::message(StatusCode::BAD_REQUEST, msg)
    }

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::message(StatusCode::UNAUTHORIZED, msg)
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::message(StatusCode::FORBIDDEN, msg)
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::message(StatusCode::NOT_FOUND, msg)
    }

    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::message(StatusCode::CONFLICT, msg)
    }

    pub fn conflict_detail(detail: Value) -> Self {
        Self::new(StatusCode::CONFLICT, detail)
    }

    pub fn unprocessable(msg: impl Into<String>) -> Self {
        Self::message(StatusCode::UNPROCESSABLE_ENTITY, msg)
    }

    pub fn bad_gateway(msg: impl Into<String>) -> Self {
        Self::message(StatusCode::BAD_GATEWAY, msg)
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::message(StatusCode::INTERNAL_SERVER_ERROR, msg)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "detail": self.detail }))).into_response()
    }
}

/// 把 ConfigService 适配成 subs_proxy 需要的 ConfigApplier（refresh 后重载内核）。
pub struct CfgApplier(pub Arc<dyn ConfigService>);

impl ConfigApplier for CfgApplier {
    fn apply<'a>(&'a self) -> BoxFut<'a, Result<Value, String>> {
        self.0.apply(None)
    }
}

/// 全局状态。所有依赖都以 trait object 注入，便于端点级单测替换。
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub auth: Arc<Auth>,
    pub stats: Arc<Stats>,
    pub cfg: Arc<dyn ConfigService>,
    pub prober: Arc<dyn Prober>,
    pub fetcher: Arc<dyn SubscriptionFetcher>,
    pub subs_store: Arc<dyn SubsStore>,
    pub applier: Arc<dyn ConfigApplier>,
    pub http: reqwest::Client,
    pub panel_path: String,
    pub static_dir: PathBuf,
    pub auth_disabled: bool,
}

impl AppState {
    pub fn new(
        db: Arc<Db>,
        auth: Arc<Auth>,
        stats: Arc<Stats>,
        cfg: Arc<dyn ConfigService>,
        prober: Arc<dyn Prober>,
        fetcher: Arc<dyn SubscriptionFetcher>,
    ) -> Self {
        let subs_store: Arc<dyn SubsStore> = db.clone();
        let applier: Arc<dyn ConfigApplier> = Arc::new(CfgApplier(cfg.clone()));
        Self {
            db,
            auth,
            stats,
            cfg,
            prober,
            fetcher,
            subs_store,
            applier,
            http: reqwest::Client::new(),
            panel_path: DEFAULT_PANEL_PATH.to_string(),
            static_dir: PathBuf::from("static"),
            auth_disabled: false,
        }
    }

    pub fn with_panel_path(mut self, path: impl Into<String>) -> Self {
        let raw = path.into();
        let trimmed = raw.trim();
        self.panel_path = if trimmed.is_empty() {
            DEFAULT_PANEL_PATH.to_string()
        } else {
            trimmed.trim_end_matches('/').to_string()
        };
        self
    }

    pub fn with_static_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.static_dir = dir.into();
        self
    }

    pub fn with_auth_disabled(mut self, disabled: bool) -> Self {
        self.auth_disabled = disabled;
        self
    }
}

/// 当前毫秒时间戳（对齐 Python 的 int(time.time() * 1000)）。
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 取 token：优先 Authorization: Bearer；
/// 仅针对 SSE 流端点（/api/stats/stream）兼容 ?token=（浏览器 EventSource 无法自定义 Request Headers）。
fn extract_token(headers: &HeaderMap, uri: &axum::http::Uri) -> Option<String> {
    if let Some(raw) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        let t = raw.trim();
        if let Some(rest) = t
            .strip_prefix("Bearer ")
            .or_else(|| t.strip_prefix("bearer "))
        {
            let token = rest.trim();
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    if uri.path() != "/api/stats/stream" {
        return None;
    }
    let query = uri.query()?;
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix("token=") {
            let decoded = urlencoding::decode(v)
                .map(|c| c.into_owned())
                .unwrap_or_else(|_| v.to_string());
            if !decoded.is_empty() {
                return Some(decoded);
            }
        }
    }
    None
}

fn is_setup_route(method: &Method, path: &str) -> bool {
    SETUP_ROUTES.iter().any(|(m, p)| m == method && *p == path)
}

/// 鉴权中间件：等价 FastAPI 的 require_auth 依赖。
pub async fn require_auth(State(st): State<AppState>, req: Request, next: Next) -> Response {
    if st.auth_disabled {
        return next.run(req).await;
    }
    let token = extract_token(req.headers(), req.uri());
    let ok = token
        .as_deref()
        .map(|t| st.auth.verify_token(t))
        .unwrap_or(false);
    if !ok {
        return ApiError::unauthorized("未登录或登录已过期").into_response();
    }
    if st.auth.is_password_change_required() && !is_setup_route(req.method(), req.uri().path()) {
        return ApiError::forbidden("请先修改初始密码").into_response();
    }
    next.run(req).await
}

/// 从 Bearer 头里取原始 token（logout 需要）。
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    let rest = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?
        .trim();
    if rest.is_empty() {
        None
    } else {
        Some(rest.to_string())
    }
}

/// 把 JSON body 解成结构体，失败给 422（FastAPI 同款）。
fn parse_body<T: serde::de::DeserializeOwned>(body: Value) -> ApiResult<T> {
    serde_json::from_value(body).map_err(|e| ApiError::unprocessable(e.to_string()))
}

// ===================== 鉴权 =====================

async fn auth_status(State(st): State<AppState>) -> Json<Value> {
    Json(json!({
        "authenticated": true,
        "username": st.auth.get_username(),
        "passwordChangeRequired": if st.auth_disabled {
            false
        } else {
            st.auth.is_password_change_required()
        },
    }))
}

async fn auth_login(
    State(st): State<AppState>,
    connect: Option<ConnectInfo<SocketAddr>>,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let username = body
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let password = body
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let ip = connect
        .map(|c| c.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let result = st.auth.login(&username, &password, &ip).await;
    if !result.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
        let msg = result
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("登录失败")
            .to_string();
        return Err(ApiError::unauthorized(msg));
    }
    Ok(Json(result).into_response())
}

async fn auth_logout(State(st): State<AppState>, headers: HeaderMap) -> Json<Value> {
    if let Some(token) = bearer_token(&headers) {
        st.auth.logout_token(&token);
    }
    Json(json!({ "ok": true }))
}

async fn auth_change_password(
    State(st): State<AppState>,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let old = body
        .get("oldPassword")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let new = body
        .get("newPassword")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let result = st.auth.change_password(&old, &new);
    if !result.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
        let msg = result
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("修改密码失败")
            .to_string();
        return Err(ApiError::bad_request(msg));
    }
    Ok(Json(result).into_response())
}

async fn auth_check() -> Json<Value> {
    Json(json!({ "ok": true }))
}

// ===================== 节点 =====================

#[derive(Debug, Default, serde::Deserialize)]
struct NodeQuery {
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default, rename = "subId")]
    sub_id: Option<String>,
}

fn db_err(e: anyhow::Error) -> ApiError {
    tracing::error!("db error: {e}");
    ApiError::internal(e.to_string())
}

/// 判断错误链里是否有 sqlite 唯一约束冲突（端口/主键被并发抢占）。
///
/// 用于把「并发创建撞端口」和其它真实故障区分开：只有唯一约束冲突才该映射成
/// 409，磁盘满、库损坏、序列化失败等必须如实回 500。Python 参考实现同样只
/// 捕获 `sqlite3.IntegrityError` 映射 409（`backend/app.py:192-194`），其余异常
/// 直接冒泡成 500。
fn is_unique_violation(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<rusqlite::Error>(),
            Some(rusqlite::Error::SqliteFailure(_, Some(msg)))
                if msg.contains("UNIQUE constraint failed") || msg.contains("PRIMARY KEY")
        )
    })
}

async fn list_nodes(State(st): State<AppState>, Query(q): Query<NodeQuery>) -> ApiResult<Response> {
    let items = st
        .db
        .list_nodes(q.q.as_deref(), q.group.as_deref(), q.sub_id.as_deref())
        .map_err(db_err)?;
    let total = items.len() as i64;
    Ok(Json(NodeListResponse { items, total }).into_response())
}

async fn create_node(State(st): State<AppState>, Json(body): Json<Value>) -> ApiResult<Response> {
    let mut node: NodeCreate = parse_body(body)?;
    let relays = st.db.list_relay_domains().unwrap_or_default();
    let used = used_ports(&st.db, &relays);
    let port = match node.port {
        Some(p) => Some(p),
        None => st.db.get_next_available_port(None).ok().flatten(),
    };
    if let Some(p) = port {
        if used.contains(&p) {
            return Err(ApiError::conflict_detail(json!({
                "port": p,
                "reason": "端口已被占用（节点/域名/保留段）",
            })));
        }
    }
    node.port = port;
    match st.db.create_node(&node) {
        Ok(created) => Ok((StatusCode::CREATED, Json(created)).into_response()),
        Err(e) if is_unique_violation(&e) => {
            tracing::warn!("create_node 端口被并发抢占: {e}");
            Err(ApiError::conflict_detail(json!({
                "port": port,
                "reason": "端口已被占用（并发创建）",
            })))
        }
        Err(e) => Err(db_err(e)),
    }
}

fn set_field(v: &mut Value, key: &str, value: Value) {
    if let Some(obj) = v.as_object_mut() {
        obj.insert(key.to_string(), value);
    }
}

async fn batch_create_nodes(
    State(st): State<AppState>,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let req: NodeBatchRequest = parse_body(body)?;
    let mut values: Vec<Value> = Vec::new();
    let mut skipped_unparsable: i64 = 0;
    for node in req.nodes {
        let mut v = serde_json::to_value(&node).unwrap_or(Value::Null);
        let uri = v
            .get("rawConfig")
            .and_then(|rc| rc.get("uri"))
            .and_then(|u| u.as_str())
            .map(|s| s.to_string());
        let has_server = v
            .get("rawConfig")
            .and_then(|rc| rc.get("server"))
            .map(|s| !s.is_null())
            .unwrap_or(false);
        if let Some(uri) = uri {
            if !has_server {
                match subs_proxy::parse_link(&uri) {
                    Some(parsed) => {
                        let mut merged = parsed.raw_config.clone();
                        set_field(&mut merged, "uri", Value::String(uri));
                        set_field(&mut v, "rawConfig", merged);
                        set_field(&mut v, "name", Value::String(parsed.name));
                        set_field(&mut v, "protocol", Value::String(parsed.protocol));
                    }
                    None => {
                        skipped_unparsable += 1;
                        continue;
                    }
                }
            }
        }
        values.push(v);
    }
    let r = st
        .db
        .create_node_batch_json(&values, false)
        .map_err(db_err)?;
    let resp = NodeBatchResponse {
        created: r.created,
        updated: r.updated,
        skipped: r.skipped,
        duplicate: r.duplicate,
        failed: skipped_unparsable,
        items: r.items,
    };
    Ok(Json(resp).into_response())
}

async fn patch_node(
    State(st): State<AppState>,
    Path(node_id): Path<String>,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let node = st.db.update_node_json(&node_id, &body).map_err(db_err)?;
    match node {
        Some(n) => Ok(Json(n).into_response()),
        None => Err(ApiError::not_found("节点不存在")),
    }
}

async fn update_node_port(
    State(st): State<AppState>,
    Path(node_id): Path<String>,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let req: crate::types::PortUpdateRequest = parse_body(body)?;
    let node = st.db.update_node_port(&node_id, req.port).map_err(db_err)?;
    match node {
        Some(n) => Ok(Json(n).into_response()),
        None => Err(ApiError::not_found("节点不存在")),
    }
}

async fn convert_entry(State(st): State<AppState>, Json(body): Json<Value>) -> ApiResult<Response> {
    let req: EntryConvertRequest = parse_body(body)?;
    let entry = req.entry_proto.trim().to_string();
    if entry != "mixed" && entry != "ss" {
        return Err(ApiError::bad_request("entryProto 仅支持 mixed | ss"));
    }
    let mut errors: Vec<Value> = Vec::new();
    let mut items: Vec<crate::types::Node> = Vec::new();
    let mut converted: i64 = 0;
    let mut failed: i64 = 0;
    let all = st.db.list_nodes(None, None, None).map_err(db_err)?;
    let targets: Vec<crate::types::Node> = if req.ids.is_empty() {
        all
    } else {
        let mut picked = Vec::new();
        for id in &req.ids {
            match all.iter().find(|n| &n.id == id) {
                Some(n) => picked.push(n.clone()),
                None => {
                    failed += 1;
                    errors.push(json!({ "node": id, "reason": "节点不存在" }));
                }
            }
        }
        picked
    };
    for node in targets {
        let entry_raw = node.base.entry_proto.clone().unwrap_or_default();
        let current = crate::probe_ip::normalize_entry_proto(&entry_raw).to_string();
        if current == entry {
            items.push(node);
            continue;
        }
        match st
            .db
            .update_node_entry(&node.id, &entry, req.ss_pass.as_deref())
        {
            Ok(Some(n)) => {
                converted += 1;
                items.push(n);
            }
            _ => {
                failed += 1;
                errors.push(json!({ "node": node.base.name, "reason": "更新失败" }));
            }
        }
    }
    let _ = st.cfg.apply(None).await;
    Ok(Json(json!({
        "ok": true,
        "converted": converted,
        "failed": failed,
        "errors": errors,
        "items": items,
    }))
    .into_response())
}

async fn delete_node(
    State(st): State<AppState>,
    Path(node_id): Path<String>,
) -> ApiResult<Response> {
    let ok = st.db.delete_node(&node_id).map_err(db_err)?;
    if ok {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Err(ApiError::not_found("节点不存在"))
    }
}

async fn delete_nodes_batch(
    State(st): State<AppState>,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let req: DeleteBatchRequest = parse_body(body)?;
    if req.ids.is_empty() {
        return Err(ApiError::bad_request("ids 不能为空"));
    }
    let deleted = st.db.delete_node_batch(&req.ids).map_err(db_err)?;
    Ok(Json(json!({ "deleted": deleted })).into_response())
}

async fn batch_group(State(st): State<AppState>, Json(body): Json<Value>) -> ApiResult<Response> {
    let ids: Vec<String> = body
        .get("ids")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    if ids.is_empty() {
        return Err(ApiError::bad_request("ids 不能为空"));
    }
    let group = body
        .get("group")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if group.is_empty() {
        return Err(ApiError::bad_request("group 不能为空"));
    }
    let updated = st.db.update_nodes_group(&ids, &group).map_err(db_err)?;
    match st.cfg.apply(None).await {
        Ok(applied) => {
            let ok = applied.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
            let message = applied
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(Json(json!({
                "ok": true,
                "updated": updated,
                "configApplied": ok,
                "configMessage": message,
            }))
            .into_response())
        }
        Err(_) => Ok(Json(json!({})).into_response()),
    }
}

async fn rename_group(State(st): State<AppState>, Json(body): Json<Value>) -> ApiResult<Response> {
    let old = body
        .get("oldName")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let new = body
        .get("newName")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if old.is_empty() || new.is_empty() {
        return Err(ApiError::bad_request("oldName/newName 不能为空"));
    }
    let r = st.db.rename_group(&old, &new).map_err(db_err)?;
    if r.updated == 0 && r.relay_updated == 0 {
        return Err(ApiError::not_found(format!("分组 [{}] 不存在", old)));
    }
    let _ = st.cfg.apply(None).await;
    Ok(Json(json!({
        "ok": true,
        "updated": r.updated,
        "relayUpdated": r.relay_updated,
    }))
    .into_response())
}

async fn reset_node_traffic(
    State(st): State<AppState>,
    Path(node_id): Path<String>,
) -> ApiResult<Response> {
    let node = st.db.reset_node_traffic(&node_id).map_err(db_err)?;
    match node {
        Some(n) => Ok(Json(n).into_response()),
        None => Err(ApiError::not_found("节点不存在")),
    }
}

async fn reset_all_traffic(State(st): State<AppState>) -> ApiResult<Response> {
    st.db.reset_all_traffic().map_err(db_err)?;
    Ok(Json(json!({ "ok": true })).into_response())
}

// ===================== 探活 =====================

async fn ping_nodes(State(st): State<AppState>, Json(body): Json<Value>) -> ApiResult<Response> {
    let req: PingRequest = parse_body(body)?;
    let items = st
        .prober
        .probe(req.ids, req.all, req.include_disabled, true)
        .await;
    // 契约（API_CONTRACT.md:22 / backend/app.py:372 response_model=List[PingResultItem]）：
    // 直接返回结果数组，不能包成 {"items": [...]}，否则前端 reportProbeResults 会抛
    // 「探活响应格式错误」导致所有探活按钮失效。
    Ok(Json(items).into_response())
}

async fn node_exit_ip(
    State(st): State<AppState>,
    Path(node_id): Path<String>,
) -> ApiResult<Response> {
    let node = st
        .db
        .get_node(&node_id)
        .map_err(db_err)?
        .ok_or_else(|| ApiError::not_found("节点不存在"))?;
    let proto = node.base.protocol.trim().to_ascii_lowercase();
    if !NATIVE_PROXY_PROTOS.contains(&proto.as_str()) && !st.cfg.is_running() {
        return Err(ApiError::conflict("sing-box 未运行"));
    }
    let node_value = serde_json::to_value(&node).unwrap_or(Value::Null);
    let ip = st.prober.fetch_exit_ip(&node_value).await;
    let Some(ip) = ip.filter(|s| !s.is_empty()) else {
        let reason = st.prober.diagnose(&node_value);
        let msg = if reason.is_empty() {
            "出口 IP 探测失败".to_string()
        } else {
            format!("出口 IP 探测失败：{}", reason)
        };
        return Err(ApiError::bad_gateway(msg));
    };
    let mut patch = json!({ "exitIp": ip });
    let info = crate::ipinfo::lookup(&st.http, &ip).await;
    for key in [
        "exitCountry",
        "exitFlag",
        "exitCity",
        "exitType",
        "exitScore",
    ] {
        if let Some(v) = info.get(key) {
            if !v.is_null() {
                set_field(&mut patch, key, v.clone());
            }
        }
    }
    let updated = st.db.update_node_json(&node_id, &patch).map_err(db_err)?;
    let mut out = patch.clone();
    if let Some(n) = updated {
        set_field(&mut out, "ping", json!(n.base.ping));
    }
    Ok(Json(out).into_response())
}

// ===================== 配置 =====================

async fn get_config(State(st): State<AppState>) -> ApiResult<Response> {
    let (config, errors) = st.cfg.build();
    Ok(Json(json!({
        "config": config,
        "errors": errors,
        "applied": st.cfg.config_exists(),
        "singboxRunning": st.cfg.is_running(),
        "generatedAt": now_ms(),
    }))
    .into_response())
}

async fn apply_config(
    State(st): State<AppState>,
    body: Option<Json<Value>>,
) -> ApiResult<Response> {
    let cfg = body.and_then(|Json(v)| v.get("config").cloned());
    let res = st.cfg.apply(cfg).await.map_err(ApiError::internal)?;
    Ok(Json(res).into_response())
}

async fn config_status(State(st): State<AppState>) -> ApiResult<Response> {
    let status = st.cfg.status().await;
    Ok(Json(status).into_response())
}

async fn config_start(State(st): State<AppState>) -> ApiResult<Response> {
    let running = st.cfg.start().await.map_err(ApiError::internal)?;
    Ok(Json(json!({ "running": running })).into_response())
}

async fn config_stop(State(st): State<AppState>) -> ApiResult<Response> {
    let _ = st.cfg.stop().await;
    Ok(Json(json!({ "running": false })).into_response())
}

async fn config_restart(State(st): State<AppState>) -> ApiResult<Response> {
    let _ = st.cfg.stop().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let running = st.cfg.start().await.map_err(ApiError::internal)?;
    Ok(Json(json!({ "running": running })).into_response())
}

// ===================== 订阅 =====================

async fn list_subs(State(st): State<AppState>) -> ApiResult<Response> {
    let subs = st.db.list_subs().map_err(db_err)?;
    Ok(Json(subs).into_response())
}

async fn create_sub(State(st): State<AppState>, Json(body): Json<Value>) -> ApiResult<Response> {
    let req: SubCreate = parse_body(body)?;
    let url = req.url.trim().to_string();
    if url.is_empty() {
        return Err(ApiError::bad_request("订阅 URL 不能为空"));
    }
    let created = st
        .db
        .create_sub(&url, req.name.as_deref(), req.group.as_deref())
        .map_err(db_err)?;
    match created {
        Some(sub) => Ok((StatusCode::CREATED, Json(sub)).into_response()),
        None => Err(ApiError::conflict("订阅 URL 已存在")),
    }
}

async fn delete_sub(State(st): State<AppState>, Path(sub_id): Path<String>) -> ApiResult<Response> {
    let ok = st.db.delete_sub(&sub_id).map_err(db_err)?;
    if ok {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Err(ApiError::not_found("订阅不存在"))
    }
}

async fn patch_sub(
    State(st): State<AppState>,
    Path(sub_id): Path<String>,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let mut patch = Map::new();
    if let Some(obj) = body.as_object() {
        for key in ["name", "url", "group"] {
            if let Some(v) = obj.get(key) {
                if !v.is_null() {
                    patch.insert(key.to_string(), v.clone());
                }
            }
        }
    }
    if patch.is_empty() {
        return Err(ApiError::bad_request("无可更新字段"));
    }
    let updated = st
        .db
        .update_sub(&sub_id, &Value::Object(patch))
        .map_err(db_err)?;
    match updated {
        Some(sub) => Ok(Json(sub).into_response()),
        None => Err(ApiError::not_found("订阅不存在")),
    }
}

async fn toggle_sub(
    State(st): State<AppState>,
    Path(sub_id): Path<String>,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let req: SubToggleRequest = parse_body(body)?;
    let patch = json!({ "enabled": req.enabled });
    let updated = st.db.update_sub(&sub_id, &patch).map_err(db_err)?;
    match updated {
        Some(sub) => Ok(Json(sub).into_response()),
        None => Err(ApiError::not_found("订阅不存在")),
    }
}

async fn fetch_sub(State(st): State<AppState>, Json(body): Json<Value>) -> ApiResult<Response> {
    let req: SubFetchRequest = parse_body(body)?;
    let result = st.fetcher.fetch(&req.url).await;
    Ok(Json(result.to_response()).into_response())
}

async fn refresh_subs(State(st): State<AppState>, Json(body): Json<Value>) -> ApiResult<Response> {
    let req: SubRefreshRequest = parse_body(body)?;
    let ids_vec = req.ids.unwrap_or_default();
    let ids = if ids_vec.is_empty() {
        None
    } else {
        Some(ids_vec.as_slice())
    };
    let results = subs_proxy::refresh_subs(
        st.subs_store.as_ref(),
        st.applier.as_ref(),
        st.fetcher.as_ref(),
        ids,
        req.all,
    )
    .await;
    Ok(Json(SubRefreshResponse { results }).into_response())
}

async fn parse_sub_content(
    State(_st): State<AppState>,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let req: SubParseRequest = parse_body(body)?;
    let nodes = subs_proxy::parse_content_nodes(&req.content);
    Ok(Json(SubParseResponse { nodes }).into_response())
}

// ===================== 统计 =====================

async fn get_stats(State(st): State<AppState>) -> Json<Value> {
    Json(st.stats.get_stats())
}

async fn stats_stream(State(st): State<AppState>) -> Response {
    let rx = st.stats.subscribe();
    let s = stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(msg) => {
                    return Some((
                        Ok::<Event, std::convert::Infallible>(Event::default().data(msg)),
                        rx,
                    ))
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => return None,
            }
        }
    });
    let mut resp = Sse::new(s).keep_alive(KeepAlive::default()).into_response();
    let headers = resp.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    headers.insert(
        axum::http::HeaderName::from_static("x-accel-buffering"),
        HeaderValue::from_static("no"),
    );
    resp
}

async fn stats_connections(State(st): State<AppState>) -> Json<Value> {
    if !st.cfg.is_running() {
        return Json(json!({ "connections": [] }));
    }
    let url = format!("{}/connections", st.cfg.clash_base().trim_end_matches('/'));
    let secret = st.cfg.clash_secret().unwrap_or_default();
    let resp = st
        .http
        .get(&url)
        .header("authorization", format!("Bearer {}", secret))
        .timeout(CONNECTIONS_TIMEOUT)
        .send()
        .await;
    let Ok(resp) = resp else {
        return Json(json!({ "connections": [] }));
    };
    if !resp.status().is_success() {
        return Json(json!({ "connections": [] }));
    }
    match resp.json::<Value>().await {
        Ok(v) => {
            let conns = v.get("connections").cloned().unwrap_or_else(|| json!([]));
            Json(json!({ "connections": conns }))
        }
        Err(_) => Json(json!({ "connections": [] })),
    }
}

// ===================== 设置 =====================

fn json_to_int(v: &Value) -> Option<i64> {
    if let Some(n) = v.as_i64() {
        return Some(n);
    }
    if let Some(f) = v.as_f64() {
        if f.fract() == 0.0 {
            return Some(f as i64);
        }
        return None;
    }
    if let Some(s) = v.as_str() {
        return s.trim().parse::<i64>().ok();
    }
    if let Some(b) = v.as_bool() {
        return Some(if b { 1 } else { 0 });
    }
    None
}

fn domain_label_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$").expect("label regex")
    })
}

/// 与 Python _normalize_export_domain 逐字对齐。非 ASCII 直接判格式无效（Python 走 idna 转 punycode）。
pub fn normalize_export_domain(raw: &Value) -> ApiResult<String> {
    let Some(s) = raw.as_str() else {
        return Err(ApiError::unprocessable("节点导出域名必须是字符串"));
    };
    let mut t = s.trim().to_string();
    if let Some(stripped) = t.strip_suffix('.') {
        t = stripped.to_string();
    }
    if t.is_empty() {
        if s.is_empty() {
            return Ok(String::new());
        }
        return Err(ApiError::unprocessable("节点导出域名格式无效"));
    }
    if !t.is_ascii() {
        return Err(ApiError::unprocessable("节点导出域名格式无效"));
    }
    let lower = t.to_ascii_lowercase();
    let labels: Vec<&str> = lower.split('.').collect();
    if lower.len() > 253
        || labels.len() < 2
        || labels.iter().any(|l| !domain_label_re().is_match(l))
    {
        return Err(ApiError::unprocessable(
            "请填写裸域名，不含协议、端口或路径",
        ));
    }
    if lower.parse::<std::net::IpAddr>().is_ok() {
        return Err(ApiError::unprocessable("请填写域名而非 IP 地址"));
    }
    Ok(lower)
}

async fn relay_current_exits(st: &AppState) -> Value {
    let mut out = Map::new();
    let relays = st.db.list_relay_domains().unwrap_or_default();
    if relays.is_empty() {
        return Value::Object(out);
    }
    let url = format!("{}/proxies", st.cfg.clash_base().trim_end_matches('/'));
    let secret = st.cfg.clash_secret().unwrap_or_default();
    let resp = st
        .http
        .get(&url)
        .header("authorization", format!("Bearer {}", secret))
        .timeout(PROXIES_TIMEOUT)
        .send()
        .await;
    let Ok(resp) = resp else {
        return Value::Object(out);
    };
    if !resp.status().is_success() {
        return Value::Object(out);
    }
    let Ok(data) = resp.json::<Value>().await else {
        return Value::Object(out);
    };
    let proxies = data.get("proxies").and_then(|v| v.as_object());
    let nodes = st.db.list_nodes(None, None, None).unwrap_or_default();
    let mut name_map: HashMap<String, String> = HashMap::new();
    for n in &nodes {
        let key = format!("out-{}-{}", n.base.protocol, n.base.port.unwrap_or(0));
        name_map.insert(key, n.base.name.clone());
    }
    for rd in relays {
        let tag = format!("relay-auto-{}", rd.id);
        let now = proxies
            .and_then(|p| p.get(&tag))
            .and_then(|v| v.get("now"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let name = name_map.get(&now).cloned().unwrap_or_else(|| now.clone());
        out.insert(rd.id.clone(), json!({ "tag": now, "name": name }));
    }
    Value::Object(out)
}

const ALLOWED_SETTING_KEYS: &[&str] = &[
    "inboundPort",
    "clashPort",
    "probeInterval",
    "logLevel",
    "listenIp",
    "exportDomain",
    "testUrl",
    "reservedPorts",
    "stickyEnabled",
    "stickyTimeout",
    "randomRotateEnabled",
    "randomRotateInterval",
    "randomRotateCurrent",
    "autoRefresh",
    "relayDomains",
];

async fn get_settings(State(st): State<AppState>) -> Json<Value> {
    let mut system = st
        .db
        .get_setting_or("system", json!({}))
        .unwrap_or_else(|_| json!({}));
    if !system.is_object() {
        system = json!({});
    }
    if let Some(obj) = system.as_object_mut() {
        if !obj.contains_key("clashPort") {
            if let Some(legacy) = obj.get("clash_port").cloned() {
                obj.insert("clashPort".to_string(), legacy);
            }
        }
        obj.retain(|key, _| ALLOWED_SETTING_KEYS.contains(&key.as_str()));
    }
    let exits = relay_current_exits(&st).await;
    set_field(&mut system, "relayExits", exits);
    Json(system)
}

async fn put_settings(State(st): State<AppState>, Json(raw): Json<Value>) -> ApiResult<Response> {
    if !raw.is_object() {
        return Err(ApiError::unprocessable("设置必须是对象"));
    }
    let mut body = raw;
    let obj = body
        .as_object_mut()
        .ok_or_else(|| ApiError::unprocessable("设置必须是对象"))?;
    obj.remove("relayExits");

    // 白名单预检：拒绝未知配置项，防止脏数据注入
    for k in obj.keys() {
        if !ALLOWED_SETTING_KEYS.contains(&k.as_str()) {
            return Err(ApiError::unprocessable(format!("未知配置项: {}", k)));
        }
    }

    if let Some(v) = obj.get("exportDomain").cloned() {
        let normalized = normalize_export_domain(&v)?;
        obj.insert("exportDomain".to_string(), Value::String(normalized));
    }
    if let Some(v) = obj.get("testUrl") {
        if !v.is_null() && !v.is_string() {
            return Err(ApiError::unprocessable("testUrl 必须是字符串"));
        }
    }
    if let Some(Value::String(u)) = obj.get("testUrl").cloned() {
        if let Some(rest) = u.strip_prefix("http://") {
            obj.insert(
                "testUrl".to_string(),
                Value::String(format!("https://{}", rest)),
            );
        }
    }
    for key in ["logLevel", "listenIp", "stickyTimeout"] {
        if let Some(v) = obj.get(key) {
            if !v.is_null() && !v.is_string() {
                return Err(ApiError::unprocessable(format!("{} 必须是字符串", key)));
            }
        }
    }
    for key in ["stickyEnabled", "randomRotateEnabled", "autoRefresh"] {
        if let Some(v) = obj.get(key) {
            if !v.is_null() && !v.is_boolean() {
                return Err(ApiError::unprocessable(format!("{} 必须是布尔值", key)));
            }
        }
    }
    if let Some(v) = obj.get("randomRotateCurrent") {
        if !v.is_null() && !v.is_string() {
            return Err(ApiError::unprocessable("randomRotateCurrent 必须是字符串"));
        }
    }
    if let Some(v) = obj.get("reservedPorts") {
        if !v.is_null() && !v.is_array() {
            return Err(ApiError::unprocessable("reservedPorts 必须是列表"));
        }
    }
    let previous = st
        .db
        .get_setting_or("system", json!({}))
        .unwrap_or_else(|_| json!({}));
    let mut current = previous.clone();
    if !current.is_object() {
        current = json!({});
    }
    if let (Some(src), Some(dst)) = (body.as_object(), current.as_object_mut()) {
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }
    }
    if let Some(obj) = current.as_object_mut() {
        obj.remove("relayExits");
    }
    for key in [
        "clashPort",
        "inboundPort",
        "probeInterval",
        "randomRotateInterval",
    ] {
        let Some(v) = current.get(key).cloned() else {
            continue;
        };
        if v.is_null() {
            continue;
        }
        let n = json_to_int(&v)
            .ok_or_else(|| ApiError::unprocessable(format!("{} 必须是整数", key)))?;
        let n = match key {
            "clashPort" => {
                if !(1..=65535).contains(&n) {
                    return Err(ApiError::unprocessable(format!("{} 端口无效", key)));
                }
                n
            }
            "inboundPort" => {
                if !(0..=65535).contains(&n) {
                    return Err(ApiError::unprocessable(format!("{} 端口无效", key)));
                }
                n
            }
            "probeInterval" => {
                if n < 10 {
                    return Err(ApiError::unprocessable(format!("{} 间隔过短", key)));
                }
                n
            }
            _ => {
                if n < 5 {
                    return Err(ApiError::unprocessable(format!("{} 间隔过短", key)));
                }
                n
            }
        };
        set_field(&mut current, key, json!(n));
    }
    let nodes = st.db.list_nodes(None, None, None).unwrap_or_default();
    let mut occupied: HashSet<i64> = HashSet::new();
    for n in &nodes {
        if let Some(p) = n.base.port {
            occupied.insert(p);
        }
    }
    for key in ["clashPort", "inboundPort"] {
        if let Some(p) = current.get(key).and_then(|v| v.as_i64()) {
            if p > 0 {
                occupied.insert(p);
            }
        }
    }
    if let Some(rd) = current.get("relayDomains").cloned() {
        if !rd.is_null() {
            let arr = rd
                .as_array()
                .ok_or_else(|| ApiError::unprocessable("relayDomains 必须是列表"))?;
            let mut seen_ids: HashSet<String> = HashSet::new();
            let mut seen_ports: HashSet<i64> = HashSet::new();
            for item in arr {
                let id = item
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let domain = item
                    .get("domain")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let port = item.get("port").and_then(json_to_int).unwrap_or(0);
                if id.is_empty() || domain.is_empty() || !(1024..=65535).contains(&port) {
                    return Err(ApiError::unprocessable("轮询入口域名或端口无效"));
                }
                if !seen_ids.insert(id) || !seen_ports.insert(port) || occupied.contains(&port) {
                    return Err(ApiError::conflict("轮询入口 ID 重复或端口冲突"));
                }
            }
        }
    }
    let mut changed: BTreeSet<String> = BTreeSet::new();
    let prev_obj = previous.as_object().cloned().unwrap_or_default();
    let cur_obj = current.as_object().cloned().unwrap_or_default();
    let mut keys: BTreeSet<String> = prev_obj.keys().cloned().collect();
    keys.extend(cur_obj.keys().cloned());
    for k in keys {
        if prev_obj.get(&k) != cur_obj.get(&k) {
            changed.insert(k);
        }
    }
    st.db.set_setting("system", &current).map_err(db_err)?;
    let export_domain = current
        .get("exportDomain")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if changed.len() == 1 && changed.contains("exportDomain") {
        return Ok(Json(json!({
            "ok": true,
            "configApplied": true,
            "configReloaded": false,
            "configMessage": "节点导出域名已保存，无需重载内核",
            "exportDomain": export_domain,
        }))
        .into_response());
    }
    if let Some(arr) = current.get("relayDomains").and_then(|v| v.as_array()) {
        if let Ok(domains) = serde_json::from_value::<Vec<RelayDomain>>(Value::Array(arr.clone())) {
            if let Err(e) = st.db.upsert_relay_domains(&domains) {
                tracing::error!("upsert_relay_domains 失败: {e}");
            }
        }
    }
    match st.cfg.apply(None).await {
        Ok(applied) => {
            let ok = applied.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
            let message = applied
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(Json(json!({
                "ok": true,
                "configApplied": ok,
                "configReloaded": ok,
                "configMessage": message,
                "exportDomain": export_domain,
            }))
            .into_response())
        }
        Err(_) => Ok(Json(json!({})).into_response()),
    }
}

// ===================== 路由 =====================

async fn root_redirect(State(st): State<AppState>) -> Response {
    let target = format!("{}/", st.panel_path.trim_end_matches('/'));
    let mut resp = StatusCode::TEMPORARY_REDIRECT.into_response();
    match HeaderValue::from_str(&target) {
        Ok(v) => {
            resp.headers_mut().insert(header::LOCATION, v);
        }
        Err(_) => {
            resp.headers_mut()
                .insert(header::LOCATION, HeaderValue::from_static("/"));
        }
    }
    resp
}

fn protected_routes() -> Router<AppState> {
    Router::new()
        .route("/api/auth/status", get(auth_status))
        .route("/api/auth/logout", post(auth_logout))
        .route("/api/auth/change-password", post(auth_change_password))
        .route("/api/auth/check", get(auth_check))
        .route("/api/nodes", get(list_nodes).post(create_node))
        .route("/api/nodes/batch", post(batch_create_nodes))
        .route("/api/nodes/batch-group", post(batch_group))
        .route("/api/nodes/convert-entry", post(convert_entry))
        .route("/api/nodes/delete-batch", post(delete_nodes_batch))
        .route("/api/nodes/ping", post(ping_nodes))
        .route(
            "/api/nodes/:node_id",
            axum::routing::patch(patch_node).delete(delete_node),
        )
        .route("/api/nodes/:node_id/port", put(update_node_port))
        .route("/api/nodes/:node_id/exit-ip", get(node_exit_ip))
        .route(
            "/api/nodes/:node_id/traffic/reset",
            post(reset_node_traffic),
        )
        .route("/api/traffic/reset", post(reset_all_traffic))
        .route("/api/groups/rename", post(rename_group))
        .route("/api/config", get(get_config))
        .route("/api/config/apply", post(apply_config))
        .route("/api/config/status", get(config_status))
        .route("/api/config/start", post(config_start))
        .route("/api/config/stop", post(config_stop))
        .route("/api/config/restart", post(config_restart))
        .route("/api/subs", get(list_subs).post(create_sub))
        .route("/api/subs/fetch", post(fetch_sub))
        .route("/api/subs/refresh", post(refresh_subs))
        .route("/api/subs/parse", post(parse_sub_content))
        .route(
            "/api/subs/:sub_id",
            axum::routing::patch(patch_sub).delete(delete_sub),
        )
        .route("/api/subs/:sub_id/toggle", post(toggle_sub))
        .route("/api/stats", get(get_stats))
        .route("/api/stats/stream", get(stats_stream))
        .route("/api/stats/connections", get(stats_connections))
        .route("/api/settings", get(get_settings).put(put_settings))
}

/// 组装完整 Router：公共登录 + 受保护 API + 静态站点。
pub fn build_router(st: AppState) -> Router {
    let panel_path = st.panel_path.clone();
    let static_dir = st.static_dir.clone();
    let state_for_auth = st.clone();
    let protected = protected_routes()
        .route_layer(middleware::from_fn_with_state(state_for_auth, require_auth));
    let public = Router::new().route("/api/auth/login", post(auth_login));
    let api = public.merge(protected);
    let static_service = ServeDir::new(static_dir).append_index_html_on_directories(true);
    // WebUI由本Router同源提供；省略CORS层，避免管理API向任意Origin开放。
    Router::new()
        .route("/", get(root_redirect))
        .route(&panel_path, get(root_redirect))
        .merge(api)
        .nest_service(
            &format!("{}/", panel_path.trim_end_matches('/')),
            static_service,
        )
        .with_state(st)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthStore;
    use crate::stats::StatsStore;
    use crate::subscription_fetch::FetchResult;
    use axum::body::{to_bytes, Body};
    use std::collections::HashMap as StdHashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    use tower::util::ServiceExt;

    #[derive(Default)]
    struct FakeAuthStore {
        username: String,
        settings: Mutex<StdHashMap<String, Value>>,
    }

    impl FakeAuthStore {
        fn new(username: &str) -> Self {
            Self {
                username: username.to_string(),
                settings: Mutex::new(StdHashMap::new()),
            }
        }
    }

    impl AuthStore for FakeAuthStore {
        fn get_setting(&self, key: &str) -> Option<Value> {
            self.settings.lock().unwrap().get(key).cloned()
        }
        fn set_setting(&self, key: &str, value: Value) -> Result<(), String> {
            self.settings.lock().unwrap().insert(key.to_string(), value);
            Ok(())
        }
        fn username(&self) -> String {
            self.username.clone()
        }
    }

    #[derive(Default)]
    struct FakeStatsStore;

    impl StatsStore for FakeStatsStore {
        fn list_nodes(&self) -> Vec<Value> {
            Vec::new()
        }
        fn list_relay_domains(&self) -> Vec<Value> {
            Vec::new()
        }
        fn add_traffic_batch(&self, _deltas: &StdHashMap<String, (u64, u64)>) {}
    }

    #[derive(Default)]
    struct FakeConfig {
        running: AtomicBool,
        applied: Mutex<Vec<Option<Value>>>,
        fail_apply: AtomicBool,
    }

    impl ConfigService for FakeConfig {
        fn build(&self) -> (Value, Vec<Value>) {
            (json!({ "log": { "level": "warn" } }), Vec::new())
        }
        fn is_running(&self) -> bool {
            self.running.load(Ordering::SeqCst)
        }
        fn config_exists(&self) -> bool {
            true
        }
        fn apply(&self, config: Option<Value>) -> BoxFut<'_, Result<Value, String>> {
            Box::pin(async move {
                self.applied.lock().unwrap().push(config);
                if self.fail_apply.load(Ordering::SeqCst) {
                    return Err("apply failed".to_string());
                }
                Ok(
                    json!({ "ok": true, "message": "已应用", "running": true, "clashApiOk": true, "errors": [] }),
                )
            })
        }
        fn start(&self) -> BoxFut<'_, Result<bool, String>> {
            Box::pin(async move {
                self.running.store(true, Ordering::SeqCst);
                Ok(true)
            })
        }
        fn stop(&self) -> BoxFut<'_, Result<(), String>> {
            Box::pin(async move {
                self.running.store(false, Ordering::SeqCst);
                Ok(())
            })
        }
        fn status(&self) -> BoxFut<'_, Value> {
            Box::pin(async move {
                json!({
                    "running": self.is_running(),
                    "pid": Value::Null,
                    "uptime": 0,
                    "version": "1.7.7",
                    "clashApiOk": true,
                    "controller": "127.0.0.1:9095",
                })
            })
        }
        fn clash_base(&self) -> String {
            "http://127.0.0.1:9095".to_string()
        }
        fn clash_secret(&self) -> Option<String> {
            Some("secret".to_string())
        }
        fn clash_port(&self) -> i64 {
            9095
        }
        fn relay_exits(&self) -> Vec<(String, String, String)> {
            Vec::new()
        }
    }

    struct FakeProber;

    impl Prober for FakeProber {
        fn probe(
            &self,
            _ids: Option<Vec<String>>,
            _all: bool,
            _include_disabled: bool,
            _manual: bool,
        ) -> BoxFut<'_, Vec<Value>> {
            Box::pin(async move {
                vec![
                    json!({ "id": "n1", "tag": "t", "ping": 12, "status": "online", "error": null }),
                ]
            })
        }
        fn fetch_exit_ip(&self, _node: &Value) -> BoxFut<'_, Option<String>> {
            Box::pin(async move { Some("203.0.113.9".to_string()) })
        }
        fn diagnose(&self, _node: &Value) -> String {
            String::new()
        }
    }

    struct FakeFetcher;

    impl SubscriptionFetcher for FakeFetcher {
        fn fetch<'a>(&'a self, _url: &'a str) -> BoxFut<'a, FetchResult> {
            Box::pin(async move { FetchResult::err("not used") })
        }
    }

    fn build_with_auth(auth_disabled: bool) -> (Router, Arc<Db>, Arc<FakeConfig>, Arc<Auth>) {
        let db = Arc::new(Db::open_in_memory().expect("mem db"));
        db.init_db().expect("init_db");
        let auth = Arc::new(Auth::new(Arc::new(FakeAuthStore::new("admin"))));
        let stats = Arc::new(Stats::new(Arc::new(FakeStatsStore)));
        let cfg = Arc::new(FakeConfig::default());
        let state = AppState::new(
            db.clone(),
            auth.clone(),
            stats,
            cfg.clone(),
            Arc::new(FakeProber),
            Arc::new(FakeFetcher),
        )
        .with_panel_path("/admin")
        .with_static_dir("static")
        .with_auth_disabled(auth_disabled);
        (build_router(state), db, cfg, auth)
    }

    fn build() -> (Router, Arc<Db>, Arc<FakeConfig>) {
        let (router, db, cfg, _) = build_with_auth(true);
        (router, db, cfg)
    }

    async fn call(
        router: Router,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let req = match body {
            Some(v) => Request::builder()
                .method(method)
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(v.to_string()))
                .unwrap(),
            None => Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        };
        let resp = router.oneshot(req).await.expect("router");
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 4 * 1024 * 1024)
            .await
            .expect("body");
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, value)
    }

    fn node_body(name: &str, port: i64) -> Value {
        json!({ "name": name, "protocol": "socks5", "port": port })
    }

    // ---------- normalize_export_domain ----------

    #[test]
    fn export_domain_accepts_and_normalizes() {
        assert_eq!(
            normalize_export_domain(&json!("Example.COM.")).unwrap(),
            "example.com"
        );
        assert_eq!(normalize_export_domain(&json!("")).unwrap(), "");
        assert_eq!(
            normalize_export_domain(&json!(" a.b-c.example ")).unwrap(),
            "a.b-c.example"
        );
    }

    #[test]
    fn export_domain_rejects_bad_inputs() {
        let err = normalize_export_domain(&json!(123)).unwrap_err();
        assert_eq!(err.detail, json!("节点导出域名必须是字符串"));
        let err = normalize_export_domain(&json!("   ")).unwrap_err();
        assert_eq!(err.detail, json!("节点导出域名格式无效"));
        let err = normalize_export_domain(&json!("https://a.example/x")).unwrap_err();
        assert_eq!(err.detail, json!("请填写裸域名，不含协议、端口或路径"));
        let err = normalize_export_domain(&json!("localhost")).unwrap_err();
        assert_eq!(err.detail, json!("请填写裸域名，不含协议、端口或路径"));
        let err = normalize_export_domain(&json!("1.2.3.4")).unwrap_err();
        assert_eq!(err.detail, json!("请填写域名而非 IP 地址"));
    }

    // ---------- 路由基础 ----------

    #[tokio::test]
    async fn root_and_panel_path_redirect() {
        let (router, _db, _cfg) = build();
        let resp = router
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/admin/");
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/admin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    }

    #[tokio::test]
    async fn auth_status_reports_username() {
        let (router, _db, _cfg) = build();
        let (status, body) = call(router, "GET", "/api/auth/status", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["username"], json!("admin"));
        assert_eq!(body["authenticated"], json!(true));
    }

    // ---------- 节点端点 ----------

    #[tokio::test]
    async fn list_nodes_returns_items_and_total() {
        let (router, db, _cfg) = build();
        let node: NodeCreate = serde_json::from_value(node_body("n1", 52101)).unwrap();
        db.create_node(&node).unwrap();
        let (status, body) = call(router, "GET", "/api/nodes", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], json!(1));
        assert_eq!(body["items"][0]["name"], json!("n1"));
    }

    #[tokio::test]
    async fn create_node_rejects_used_port_with_detail() {
        let (router, db, _cfg) = build();
        let node: NodeCreate = serde_json::from_value(node_body("n1", 52102)).unwrap();
        db.create_node(&node).unwrap();
        let (status, body) = call(router, "POST", "/api/nodes", Some(node_body("n2", 52102))).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["detail"]["port"], json!(52102));
        assert_eq!(
            body["detail"]["reason"],
            json!("端口已被占用（节点/域名/保留段）")
        );
    }

    #[tokio::test]
    async fn create_node_assigns_port_when_omitted() {
        let (router, _db, _cfg) = build();
        let (status, body) = call(
            router,
            "POST",
            "/api/nodes",
            Some(json!({ "name": "auto", "protocol": "socks5" })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(body["port"].as_i64().unwrap() >= 52001);
    }

    #[tokio::test]
    async fn patch_missing_node_returns_404() {
        let (router, _db, _cfg) = build();
        let (status, body) = call(
            router,
            "PATCH",
            "/api/nodes/nope",
            Some(json!({ "name": "x" })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["detail"], json!("节点不存在"));
    }

    #[tokio::test]
    async fn delete_batch_rejects_empty_ids() {
        let (router, _db, _cfg) = build();
        let (status, body) = call(
            router,
            "POST",
            "/api/nodes/delete-batch",
            Some(json!({ "ids": [] })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["detail"], json!("ids 不能为空"));
    }

    #[tokio::test]
    async fn convert_entry_rejects_unknown_proto() {
        let (router, _db, _cfg) = build();
        let (status, body) = call(
            router,
            "POST",
            "/api/nodes/convert-entry",
            Some(json!({ "ids": [], "entryProto": "vmess" })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["detail"], json!("entryProto 仅支持 mixed | ss"));
    }

    #[tokio::test]
    async fn convert_entry_skips_already_converted_nodes() {
        let (router, db, _cfg) = build();
        let node: NodeCreate = serde_json::from_value(json!({
            "name": "n1", "protocol": "ss", "port": 52110, "entryProto": "ss"
        }))
        .unwrap();
        db.create_node(&node).unwrap();
        let (status, body) = call(
            router,
            "POST",
            "/api/nodes/convert-entry",
            Some(json!({ "ids": [], "entryProto": "ss" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["converted"], json!(0));
        assert_eq!(body["failed"], json!(0));
        assert_eq!(body["items"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn unique_violation_is_distinguished_from_other_db_errors() {
        // sqlite 唯一约束冲突（并发抢占端口）→ 只有当 409 处理。
        let unique = anyhow::Error::new(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(2067), // SQLITE_CONSTRAINT_UNIQUE
            Some("UNIQUE constraint failed: nodes.port".into()),
        ));
        assert!(is_unique_violation(&unique));
        // anyhow context 包裹后仍要能识别（db 层常常带 context 上抛）。
        assert!(is_unique_violation(&unique.context("insert node")));
        // 其它故障（磁盘满、库损坏、序列化失败）不得被伪装成端口冲突。
        assert!(!is_unique_violation(&anyhow::anyhow!("disk I/O error")));
        assert!(!is_unique_violation(&anyhow::Error::new(
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(10),
                Some("disk I/O error".into())
            )
        )));
    }

    #[tokio::test]
    async fn ping_nodes_returns_bare_result_array() {
        let (router, _db, _cfg) = build();
        let (status, body) = call(router, "POST", "/api/nodes/ping", Some(json!({}))).await;
        assert_eq!(status, StatusCode::OK);
        // 契约是裸数组：前端 reportProbeResults 严格校验 Array.isArray(results)。
        assert!(body.is_array(), "探活响应必须是数组，实际: {}", body);
        assert!(body.get("items").is_none(), "探活响应不得再包 items 字段");
        assert_eq!(body[0]["ping"], json!(12));
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // 复用 ipinfo 的缓存串行锁，跨 await 持锁是有意的
    async fn exit_ip_returns_probed_ip() {
        // 这个用例会真的走 ipinfo::lookup 并写进程级缓存，必须与 ipinfo 的用例串行。
        let _serial = crate::ipinfo::test_serial_lock();
        let (router, db, _cfg) = build();
        let node: NodeCreate = serde_json::from_value(json!({
            "name": "n1", "protocol": "socks5", "port": 52120,
            "rawConfig": { "server": "1.2.3.4", "server_port": 1080 }
        }))
        .unwrap();
        let created = db.create_node(&node).unwrap();
        let uri = format!("/api/nodes/{}/exit-ip", created.id);
        let (status, body) = call(router, "GET", &uri, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["exitIp"], json!("203.0.113.9"));
    }

    // ---------- 设置端点 ----------

    #[tokio::test]
    async fn settings_get_attaches_relay_exits() {
        let (router, db, _cfg) = build();
        db.set_setting("system", &json!({ "inboundPort": 2080 }))
            .unwrap();
        let (status, body) = call(router, "GET", "/api/settings", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["inboundPort"], json!(2080));
        assert_eq!(body["relayExits"], json!({}));
    }

    #[tokio::test]
    async fn settings_put_export_domain_only_skips_reload() {
        let (router, db, cfg) = build();
        db.set_setting("system", &json!({ "exportDomain": "old.example" }))
            .unwrap();
        let (status, body) = call(
            router,
            "PUT",
            "/api/settings",
            Some(json!({ "exportDomain": "New.Example." })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["configReloaded"], json!(false));
        assert_eq!(
            body["configMessage"],
            json!("节点导出域名已保存，无需重载内核")
        );
        assert_eq!(body["exportDomain"], json!("new.example"));
        assert!(cfg.applied.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn settings_put_rejects_short_probe_interval() {
        let (router, _db, _cfg) = build();
        let (status, body) = call(
            router,
            "PUT",
            "/api/settings",
            Some(json!({ "probeInterval": 5 })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["detail"], json!("probeInterval 间隔过短"));
    }

    #[tokio::test]
    async fn settings_put_rejects_relay_port_conflict() {
        let (router, db, _cfg) = build();
        let node: NodeCreate = serde_json::from_value(node_body("n1", 52130)).unwrap();
        db.create_node(&node).unwrap();
        let (status, body) = call(
            router,
            "PUT",
            "/api/settings",
            Some(json!({
                "relayDomains": [
                    { "id": "r1", "domain": "a.example", "port": 52130 }
                ]
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["detail"], json!("轮询入口 ID 重复或端口冲突"));
    }

    #[tokio::test]
    async fn settings_put_normalizes_http_test_url_and_applies() {
        let (router, db, cfg) = build();
        db.set_setting("system", &json!({ "probeInterval": 30 }))
            .unwrap();
        let (status, body) = call(
            router,
            "PUT",
            "/api/settings",
            Some(json!({ "testUrl": "http://www.gstatic.com/generate_204", "probeInterval": 60 })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["configApplied"], json!(true));
        let saved = db.get_setting_or("system", json!({})).unwrap();
        assert_eq!(
            saved["testUrl"],
            json!("https://www.gstatic.com/generate_204")
        );
        assert_eq!(saved["probeInterval"], json!(60));
        assert_eq!(cfg.applied.lock().unwrap().len(), 1);
    }

    // ---------- 统计 / 配置 ----------

    #[tokio::test]
    async fn stats_connections_empty_when_not_running() {
        let (router, _db, _cfg) = build();
        let (status, body) = call(router, "GET", "/api/stats/connections", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["connections"], json!([]));
    }

    #[tokio::test]
    async fn config_status_and_start_stop() {
        let (router, _db, cfg) = build();
        let (status, body) = call(router.clone(), "GET", "/api/config/status", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["running"], json!(false));
        let (status, body) = call(router.clone(), "POST", "/api/config/start", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["running"], json!(true));
        assert!(cfg.is_running());
        let (status, body) = call(router, "POST", "/api/config/stop", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["running"], json!(false));
    }

    #[tokio::test]
    async fn config_apply_forwards_body_config() {
        let (router, _db, cfg) = build();
        let (status, body) = call(
            router,
            "POST",
            "/api/config/apply",
            Some(json!({ "config": { "log": { "level": "debug" } } })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], json!(true));
        let applied = cfg.applied.lock().unwrap().clone();
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].as_ref().unwrap()["log"]["level"], json!("debug"));
    }

    #[tokio::test]
    async fn token_query_param_allowed_only_for_sse() {
        let (router, _db, _cfg, auth) = build_with_auth(false);
        let token = auth.issue_token();

        // 1. 常规接口（如 GET /api/nodes）通过 ?token= 访问应被拒绝（401）
        let req_query = Request::builder()
            .method("GET")
            .uri(format!("/api/nodes?token={}", token))
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req_query).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // 2. 常规接口通过 Authorization: Bearer <token> 正常放行（200）
        let req_bearer = Request::builder()
            .method("GET")
            .uri("/api/nodes")
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req_bearer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // 3. SSE 端点（GET /api/stats/stream）通过 ?token= 允许放行
        let req_sse = Request::builder()
            .method("GET")
            .uri(format!("/api/stats/stream?token={}", token))
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req_sse).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn cross_origin_requests_do_not_receive_cors_permission() {
        let (router, _db, _cfg) = build();
        for method in ["OPTIONS", "GET"] {
            let req = Request::builder()
                .method(method)
                .uri("/api/nodes")
                .header("Origin", "http://evil.example")
                .header("Access-Control-Request-Method", "GET")
                .header(
                    "Access-Control-Request-Headers",
                    "authorization,content-type",
                )
                .body(Body::empty())
                .unwrap();
            let resp = router.clone().oneshot(req).await.unwrap();
            assert!(!resp.headers().contains_key("access-control-allow-origin"));
            assert!(!resp
                .headers()
                .contains_key("access-control-allow-credentials"));
        }
    }

    #[tokio::test]
    async fn settings_put_rejects_unknown_and_nested_keys() {
        let (router, _db, _cfg) = build();

        // 1. 拒绝未知标量键
        let (status, body) = call(
            router.clone(),
            "PUT",
            "/api/settings",
            Some(json!({ "unknownKey": "malicious" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["detail"].as_str().unwrap().contains("未知配置项"));

        // 2. 拒绝未知嵌套键
        let (status, body) = call(
            router.clone(),
            "PUT",
            "/api/settings",
            Some(json!({ "nested": { "deep": 123 } })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["detail"].as_str().unwrap().contains("未知配置项"));

        // 3. 拒绝类型不合法的字段（如 logLevel 传入数字）
        let (status, body) = call(
            router.clone(),
            "PUT",
            "/api/settings",
            Some(json!({ "logLevel": 12345 })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["detail"]
            .as_str()
            .unwrap()
            .contains("logLevel 必须是字符串"));

        // 4. 拒绝类型不合法的布尔字段
        let (status, body) = call(
            router.clone(),
            "PUT",
            "/api/settings",
            Some(json!({ "stickyEnabled": "not-bool" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["detail"]
            .as_str()
            .unwrap()
            .contains("stickyEnabled 必须是布尔值"));

        // 5. 拒绝 reservedPorts 非数组
        let (status, body) = call(
            router.clone(),
            "PUT",
            "/api/settings",
            Some(json!({ "reservedPorts": 8080 })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["detail"]
            .as_str()
            .unwrap()
            .contains("reservedPorts 必须是列表"));
    }

    #[tokio::test]
    async fn settings_put_accepts_whitelisted_keys() {
        let (router, db, _cfg) = build();
        let payload = json!({
            "inboundPort": 2080,
            "clashPort": 9095,
            "probeInterval": 30,
            "logLevel": "info",
            "listenIp": "0.0.0.0",
            "stickyEnabled": true,
            "stickyTimeout": "5m",
            "randomRotateEnabled": false,
            "randomRotateInterval": 30,
            "autoRefresh": true,
            "reservedPorts": [2080, 9095],
            "relayExits": { "fake": "should_be_stripped" }
        });
        let (status, body) = call(router, "PUT", "/api/settings", Some(payload)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["configApplied"], json!(true));
        let saved = db.get_setting_or("system", json!({})).unwrap();
        assert_eq!(saved["logLevel"], json!("info"));
        assert_eq!(saved["stickyEnabled"], json!(true));
        assert!(saved.get("relayExits").is_none());
    }

    #[tokio::test]
    async fn settings_get_normalizes_legacy_port_and_roundtrips_cleanly() {
        let (router, db, _cfg) = build();
        db.set_setting(
            "system",
            &json!({
                "clash_port": 9096,
                "probeInterval": 30,
                "legacyOption": "preserve-in-storage-but-hide"
            }),
        )
        .unwrap();

        let (status, settings) = call(router.clone(), "GET", "/api/settings", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(settings["clashPort"], json!(9096));
        assert!(settings.get("clash_port").is_none());
        assert!(settings.get("legacyOption").is_none());
        assert_eq!(settings["probeInterval"], json!(30));

        let (status, body) = call(router, "PUT", "/api/settings", Some(settings)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let stored = db.get_setting_or("system", json!({})).unwrap();
        assert_eq!(
            stored["legacyOption"],
            json!("preserve-in-storage-but-hide")
        );
        assert_eq!(stored["clash_port"], json!(9096));
    }
}
