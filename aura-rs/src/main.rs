//! Aura 面板后端启动装配。
//!
//! 对齐 Python backend/app.py 的 lifespan：
//! 建目录 → init_db → relayDomains 落库 → 应用并拉起内核 → 起后台任务 → 监听端口。
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use aura::app::{build_router, AppState};
use aura::auth::Auth;
use aura::config_apply::{ConfigManager, DbSettings};
use aura::db::Db;
use aura::panel_config::PanelConfig;
use aura::scheduler::{self, epoch_now, GuardConfig, OpState, ProbeEngine};
use aura::singbox_proc::ProcPaths;
use aura::stats::{Stats, StatsStore};
use aura::subscription_fetch::Fetcher;
use aura::types::RelayDomain;
use aura::wire::{AppAuthStore, ConfigAdapter, ConfigService, Prober};

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!("aura 启动失败: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> anyhow::Result<()> {
    // Python 侧是 backend/data 与 backend/static，容器里对应 /app/backend/data。
    let data_dir = std::env::var("AURA_DATA_DIR").unwrap_or_else(|_| "data".to_string());
    let data_path = std::path::PathBuf::from(&data_dir);
    std::fs::create_dir_all(&data_path)?;
    let static_dir = std::env::var("AURA_STATIC_DIR").unwrap_or_else(|_| "static".to_string());
    let panel = PanelConfig::load_from(&data_path.join("panel.conf"));

    let db = Arc::new(Db::open(data_path.join("panel.db"))?);
    db.init_db()?;

    // lifespan: settings.system.relayDomains 同步进 relay_domains 表（失败忽略）。
    if let Ok(system) = db.get_setting_or("system", json!({})) {
        if let Some(list) = system.get("relayDomains").and_then(|v| v.as_array()) {
            match serde_json::from_value::<Vec<RelayDomain>>(json!(list)) {
                Ok(domains) => {
                    let _ = db.upsert_relay_domains(&domains);
                }
                Err(err) => tracing::warn!("relayDomains 解析失败: {err}"),
            }
        }
    }

    let paths = ProcPaths::from_env();
    let mgr = Arc::new(ConfigManager::production(
        paths,
        Arc::clone(&db) as Arc<dyn DbSettings>,
    ));
    let cfg: Arc<dyn ConfigService> =
        Arc::new(ConfigAdapter::new(Arc::clone(&mgr), Arc::clone(&db)));

    // lifespan: 已有配置就应用并拉起内核（配置不存在则等用户创建节点后再启动）。
    //
    // 失败必须重试、用尽后退出，不能只 warn 降级：一旦降级，容器是 running、
    // 面板是 200，但 sing-box 没起来，节点静默全断，从外部完全看不出故障
    // （2026-10-23 日本机「端口被占用: 33444」事故就是这个形态）。
    // 退出后由 --restart always 重新拉起，形成可见、可自愈的失败。
    if cfg.config_exists() || mgr.paths().config_bak_path().exists() {
        const STARTUP_APPLY_ATTEMPTS: u32 = 3;
        let mut last_err: Option<anyhow::Error> = None;
        for attempt in 1..=STARTUP_APPLY_ATTEMPTS {
            match mgr.apply_config(false).await {
                Ok(report) => {
                    tracing::info!(
                        ok = report.ok(),
                        written = report.written,
                        restarted = report.restarted,
                        message = %report.message(),
                        "启动时应用配置"
                    );
                    last_err = None;
                    break;
                }
                Err(err) => {
                    tracing::warn!(
                        attempt = attempt,
                        attempts = STARTUP_APPLY_ATTEMPTS,
                        "启动时应用配置失败: {err:#}"
                    );
                    last_err = Some(err);
                    if attempt < STARTUP_APPLY_ATTEMPTS {
                        tokio::time::sleep(Duration::from_secs(3)).await;
                    }
                }
            }
        }
        if let Some(err) = last_err {
            return Err(anyhow::anyhow!(
                "启动时应用配置重试用尽，节点内核未启动: {err:#}"
            ));
        }
    }

    let auth = Arc::new(Auth::new(Arc::new(AppAuthStore::new(
        Arc::clone(&db),
        panel.username.clone(),
    ))));
    let stats = Arc::new(Stats::new(Arc::clone(&db) as Arc<dyn StatsStore>));
    let fetcher = Arc::new(Fetcher::from_env());

    // 探活引擎：clash API + 出口 IP 直连探测 + 出口情报补查，全部走生产实现。
    let op: Arc<dyn OpState> = mgr.clone();
    let engine = Arc::new(
        ProbeEngine::new(
            Arc::clone(&db),
            Arc::clone(&cfg),
            reqwest::Client::builder()
                .timeout(Duration::from_secs(12))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        )
        .with_op(op),
    );
    let prober: Arc<dyn Prober> = Arc::clone(&engine) as Arc<dyn Prober>;

    let auth_disabled = std::env::var("AUTH_DISABLED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);
    let state = AppState::new(
        Arc::clone(&db),
        auth,
        Arc::clone(&stats),
        Arc::clone(&cfg),
        prober,
        fetcher,
    )
    .with_panel_path(panel.panel_path.clone())
    .with_static_dir(static_dir)
    .with_auth_disabled(auth_disabled);

    spawn_stats_loops(Arc::clone(&stats), Arc::clone(&cfg), Arc::clone(&db));
    spawn_scheduler_loops(Arc::clone(&engine), Arc::clone(&mgr));

    let port = panel.port.clamp(1, 65535) as u16;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("aura 面板已监听 http://{addr}{}", panel.panel_path);
    axum::serve(
        listener,
        build_router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// 后台任务，逐一对齐 Python backend/scheduler.py 里的守护与探活循环。
fn spawn_scheduler_loops(engine: Arc<ProbeEngine>, mgr: Arc<ConfigManager>) {
    // fast loop：进程守护 + fd 泄漏回收（Python _guard_loop）
    let guard_cfg = GuardConfig::default();
    tokio::spawn(async move {
        scheduler::guard_loop(mgr, guard_cfg).await;
    });

    let stop = Arc::new(tokio::sync::Notify::new());
    tokio::spawn(scheduler::probe_loop(
        Arc::clone(&engine),
        Arc::clone(&stop),
    ));
    tokio::spawn(scheduler::revive_loop(
        Arc::clone(&engine),
        Arc::clone(&stop),
    ));
    tokio::spawn(scheduler::relay_rotate_loop(
        Arc::clone(&engine),
        Arc::clone(&stop),
    ));
    tokio::spawn(scheduler::enrich_loop(Arc::clone(&engine), stop));
}

/// 后台任务，逐一对齐 Python backend/stats.py 里的四个循环。
fn spawn_stats_loops(stats: Arc<Stats>, cfg: Arc<dyn ConfigService>, db: Arc<Db>) {
    // 1s：向 SSE 客户端推送快照（Python _broadcast）
    {
        let stats = Arc::clone(&stats);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tick.tick().await;
                stats.broadcast_once(epoch_now());
            }
        });
    }

    // 5s：采样 /connections 并把流量归属写库（Python _connections_sampler）
    {
        let stats = Arc::clone(&stats);
        let cfg = Arc::clone(&cfg);
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            loop {
                tick.tick().await;
                if !cfg.is_running() {
                    continue;
                }
                let secret = cfg.clash_secret();
                let conns = fetch_connections(&client, &cfg.clash_base(), secret.as_deref()).await;
                stats.sample_and_persist(&conns);
            }
        });
    }

    // 15s：刷新 clash tag → 节点映射（Python _tag_map_refresh_loop）
    {
        let stats = Arc::clone(&stats);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(15));
            loop {
                tick.tick().await;
                stats.refresh_tag_maps();
            }
        });
    }

    // 2s：刷新 relay selector 当前出口（Python _update_relay_now）
    {
        let stats = Arc::clone(&stats);
        let cfg = Arc::clone(&cfg);
        let db = Arc::clone(&db);
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let mut tick = tokio::time::interval(Duration::from_secs(2));
            loop {
                tick.tick().await;
                if !cfg.is_running() {
                    continue;
                }
                let Ok(domains) = db.list_relay_domains() else {
                    continue;
                };
                let base = cfg.clash_base();
                let secret = cfg.clash_secret();
                for rd in domains {
                    let tag = format!("relay-auto-{}", rd.id);
                    let url = format!("{}/proxies/{}", base.trim_end_matches('/'), tag);
                    let mut req = client.get(url).timeout(Duration::from_secs(2));
                    if let Some(secret) = secret.as_deref() {
                        req = req.header("authorization", format!("Bearer {secret}"));
                    }
                    let Ok(resp) = req.send().await else { continue };
                    if !resp.status().is_success() {
                        continue;
                    }
                    let Ok(body) = resp.json::<Value>().await else {
                        continue;
                    };
                    if let Some(now) = body.get("now").and_then(|v| v.as_str()) {
                        stats.set_relay_now(&tag, now);
                    }
                }
            }
        });
    }
}

/// 读 clash /connections；任何异常都收敛成空列表（对齐 Python 的容错口径）。
async fn fetch_connections(
    client: &reqwest::Client,
    base: &str,
    secret: Option<&str>,
) -> Vec<Value> {
    let url = format!("{}/connections", base.trim_end_matches('/'));
    let mut req = client.get(url).timeout(Duration::from_secs(3));
    if let Some(secret) = secret {
        req = req.header("authorization", format!("Bearer {secret}"));
    }
    let Ok(resp) = req.send().await else {
        return Vec::new();
    };
    if !resp.status().is_success() {
        return Vec::new();
    }
    match resp.json::<Value>().await {
        Ok(body) => body
            .get("connections")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}
