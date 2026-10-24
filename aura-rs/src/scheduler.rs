//! 后台任务编排：60s 批量探活、3h 订阅刷新、10s sing-box 崩溃守护、relay 随机轮询。
//!
//! 对应 backend/scheduler.py（742 行）。本文件第一批交付的是**不依赖 db / config_manager
//! 内部实现**的调度核心：崩溃守护、fd 泄漏看门狗、自动停用判定、出口 IP 情报补查决策、
//! 探活并发/重试参数、任务集幂等启停。
//!
//! 设计约定：
//! * 所有判定逻辑都是**纯状态机**（接收 now: f64，不读时钟、不做 I/O），
//!   便于用虚拟时钟复现历史事故。
//! * 与 sing-box 进程交互、读 fd、写库等副作用统一走 GuardHost trait，
//!   由 app 层对 config_manager 适配（见文件末尾「等待上游符号」清单）。
//!
//! 历史事故锚点（回归测试逐条钉死）：
//! 1. 2026-10-22 日本机瘫痪 43 分钟：_restart_times 在判断前无条件 append，
//!    冷却期内每轮续期一条时间戳 → 60s 窗口恒有 6 条 > 3 → 永久冷却 → sing-box
//!    FATAL 退出后再也没被拉起。见 GuardCore::request_restart。
//! 2. 2026-10-22 新加坡机整机失联：hairpin 连接半开不释放，fd 1875 / load 224，
//!    崩溃守护只认「进程退出」。见 recycle_if_fd_leak / FdWatchdog。
//! 3. 历史脏数据：server 是域名而 exitIp 恰等于该域名解析 IP（入口 IP 被当成出口 IP
//!    落库）。见 is_historical_entry_ip / EnrichGate::plan。

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use tokio::sync::Semaphore;

use crate::db::{ProbeUpdateRow, UpdateNodeProbeOutcome};
use crate::types::{Node, PingResultItem};
use crate::utils::is_ip_address;

// ---------- 周期常量（与 Python 版逐一对应） ----------

/// 后台探活默认间隔（秒）；系统设置 probeInterval 可覆盖，下限 10s。
pub const PING_INTERVAL: f64 = 60.0;
/// 订阅刷新间隔（秒，3 小时）。
pub const SUB_REFRESH_INTERVAL: f64 = 3.0 * 60.0 * 60.0;
/// 崩溃守护巡检间隔（秒）。
pub const GUARD_INTERVAL: f64 = 10.0;
/// 崩溃重启的滑动统计窗口（秒）。
pub const GUARD_WINDOW: f64 = 60.0;
/// 窗口内允许的重启次数上限。
pub const MAX_RESTARTS_PER_MIN: usize = 3;
/// 探活间隔下限（秒），防系统设置误配成 1s。
pub const MIN_PROBE_INTERVAL: f64 = 10.0;

/// fd 泄漏阈值：健康态约 20 个 fd，58 个入站节点时 1200 已是 20 倍余量。
pub const FD_LIMIT: u64 = 1200;
/// 两次 fd 重启之间至少间隔（秒），避免反复重启抖动。
pub const FD_RESTART_COOLDOWN: f64 = 300.0;

/// 连续失败次数达到该值才考虑自动停用。
pub const DISABLE_AFTER_FAILS: i64 = 20;
/// 后台连续失败至少持续（秒），避免短周期误停。
pub const MIN_FAILURE_SECONDS: f64 = 20.0 * 60.0;
/// 探活滑窗长度；窗口未填满时不惩罚（重启面板不背锅）。
pub const PROBE_WINDOW: usize = 30;
/// 滑窗存活率阈值，低于/等于该值才允许停用。
pub const PROBE_DISABLE_RATE_FAST: f64 = 0.3;
/// 后台探活并发上限。
pub const PROBE_CONCURRENCY: usize = 16;
/// 手动探活并发（缩短批量等待，不改变后台节奏）。
pub const MANUAL_PROBE_CONCURRENCY: usize = 32;
/// 每轮 delay 失败重试次数（共 3 次机会）。
pub const PROBE_DELAY_RETRY: usize = 2;
/// 探活超时：常规尝试 / 后台重确认（最后一次）的毫秒值。
pub const PROBE_TIMEOUT_MS: u64 = 5000;
pub const PROBE_CONFIRM_TIMEOUT_MS: u64 = 8000;
/// 重试退避基数与封顶：0.5 * min(attempt, 2)。
pub const PROBE_RETRY_BACKOFF_BASE: f64 = 0.5;
pub const PROBE_RETRY_BACKOFF_CAP: f64 = 2.0;

/// 停用节点自动复查周期（秒）。
pub const REVIVE_INTERVAL: f64 = 600.0;
/// relay 随机轮询默认间隔（秒）。
pub const RANDOM_ROTATE_DEFAULT_INTERVAL: f64 = 30.0;

/// IP 情报补查并发上限（对应 asyncio.Semaphore(8)）。
pub const ENRICH_CONCURRENCY: usize = 8;
/// 补查冷却（秒）：补查后即使情报不全也不重查，避免每轮 curl 所有节点。
pub const ENRICH_COOLDOWN: f64 = 300.0;
/// 补查时间表的 LRU 容量与单次淘汰数量（防全清后冷却重置风暴）。
pub const ENRICH_LRU_CAP: usize = 5000;
pub const ENRICH_LRU_EVICT: usize = 1000;

/// 探活目标 URL 默认值；非 https:// 一律回落。
pub const DEFAULT_TEST_URL: &str = "https://www.gstatic.com/generate_204";
/// 用户手动停用的节点被要求探活时的提示（前端直接展示）。
pub const MANUAL_DISABLED_HINT: &str = "用户手动停用，请先启用节点再测活";
/// 探活途中节点状态/端口/协议被改时的跳过原因。
pub const STALE_PROBE_HINT: &str = "节点状态或探活 tag 已变，本轮结果已跳过";
/// sticky 超时解析失败时的默认值（秒）。
pub const DEFAULT_STICKY_SECONDS: f64 = 300.0;
/// sticky 超时下限（秒）。
pub const MIN_STICKY_SECONDS: f64 = 5.0;

/// 当前 epoch 秒（守护/冷却用的 now 唯一来源，测试可注入虚拟时钟）。
pub fn epoch_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

// ---------- 崩溃守护 ----------

/// 守护时间参数（默认取常量；测试可缩小窗口复现事故）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GuardConfig {
    pub interval: f64,
    pub window: f64,
    pub max_restarts: usize,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            interval: GUARD_INTERVAL,
            window: GUARD_WINDOW,
            max_restarts: MAX_RESTARTS_PER_MIN,
        }
    }
}

impl GuardConfig {
    pub fn new(interval: f64, window: f64, max_restarts: usize) -> Self {
        Self {
            interval,
            window,
            max_restarts,
        }
    }
}

/// 单轮守护结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardTick {
    /// 进程对象不存在（从未启动 / 已正常停止）→ 不干预。
    Absent,
    /// 进程活着；recycled 表示本轮顺带做过 fd 回收。
    Healthy { recycled: bool },
    /// 进程已退出且本轮机重启。
    Restarted,
    /// 进程已退出但处于重启限流窗口内。
    Cooldown,
}

/// 崩溃守护状态机。
///
/// 关键不变量：restart_times **只在真正发起重启前** push；判断阶段只清理过期时间戳，
/// 绝不续期。旧实现无条件 append，冷却期内 60s 窗口恒有 6 条 > 3 → 永久冷却。
#[derive(Debug, Clone)]
pub struct GuardCore {
    cfg: GuardConfig,
    restart_times: Vec<f64>,
    paused: bool,
}

impl Default for GuardCore {
    fn default() -> Self {
        Self::new(GuardConfig::default())
    }
}

impl GuardCore {
    pub fn new(cfg: GuardConfig) -> Self {
        Self {
            cfg,
            restart_times: Vec::new(),
            paused: false,
        }
    }

    pub fn cfg(&self) -> GuardConfig {
        self.cfg
    }

    /// 进程健康：清空重启历史、解除冷却。返回此前是否处于冷却态。
    pub fn note_running(&mut self) -> bool {
        let was_paused = self.paused;
        self.paused = false;
        self.restart_times.clear();
        was_paused
    }

    /// 进程已退出：判断本轮能否重启。
    ///
    /// 返回 true 表示已登记一次重启（调用方必须真的去 start()）。
    /// 返回 false 表示处于限流冷却，本轮不重启且**不登记**时间戳
    /// （这正是历史事故的修复点：冷却不能自我续期）。
    pub fn request_restart(&mut self, now: f64) -> bool {
        let window = self.cfg.window;
        self.restart_times.retain(|t| now - *t < window);
        if self.restart_times.len() >= self.cfg.max_restarts {
            self.paused = true;
            return false;
        }
        self.paused = false;
        self.restart_times.push(now);
        true
    }

    /// 当前窗口内已登记的重启时间戳（只读，测试与日志用）。
    pub fn restart_times(&self) -> &[f64] {
        &self.restart_times
    }

    /// 是否处于重启限流冷却。
    pub fn paused(&self) -> bool {
        self.paused
    }
}

// ---------- fd 泄漏看门狗 ----------

/// fd 看门狗：连接泄漏时进程仍「活着」，崩溃守护永远等不到退出信号。
#[derive(Debug, Clone)]
pub struct FdWatchdog {
    pub limit: u64,
    pub cooldown: f64,
    last_restart_at: f64,
}

impl Default for FdWatchdog {
    fn default() -> Self {
        Self {
            limit: FD_LIMIT,
            cooldown: FD_RESTART_COOLDOWN,
            last_restart_at: 0.0,
        }
    }
}

impl FdWatchdog {
    pub fn new(limit: u64, cooldown: f64) -> Self {
        Self {
            limit,
            cooldown,
            last_restart_at: 0.0,
        }
    }

    /// 超限且不在冷却期 → 应当回收。纯判定，不改状态。
    pub fn should_recycle(&self, fds: u64, now: f64) -> bool {
        fds > self.limit && now - self.last_restart_at >= self.cooldown
    }

    /// 登记一次回收（在真正 stop/start 之前调用，失败也计冷却）。
    pub fn mark_restart(&mut self, now: f64) {
        self.last_restart_at = now;
    }

    pub fn last_restart_at(&self) -> f64 {
        self.last_restart_at
    }
}

// ---------- 宿主适配层（等 db/config_manager 就绪后由 app 层实现） ----------

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// sing-box 进程与 fd 的宿主接口。
///
/// app 层实现要点（与 Python 版语义一一对应）：
/// * proc_present ← config_manager.get_proc() is not None
///   （手动 stop / 从未启动 → false，守护不干预）
/// * is_running ← config_manager.is_running()
///   （基于收割任务，不能直接读 Process::returncode）
/// * fd_count ← config_manager.singbox_fd_count()（读 /proc/<pid>/fd 计数）
/// * start / stop ← 对应 config_manager 的进程管理
pub trait GuardHost {
    fn proc_present(&self) -> bool;
    fn is_running(&self) -> bool;
    fn fd_count(&self) -> Result<u64, String>;
    fn start(&self) -> BoxFuture<'_, bool>;
    fn stop(&self) -> BoxFuture<'_, ()>;
}

/// Arc 透传：app 层通常持有 Arc<ConfigManager>。
impl<T: GuardHost + ?Sized> GuardHost for Arc<T> {
    fn proc_present(&self) -> bool {
        self.as_ref().proc_present()
    }

    fn is_running(&self) -> bool {
        self.as_ref().is_running()
    }

    fn fd_count(&self) -> Result<u64, String> {
        self.as_ref().fd_count()
    }

    fn start(&self) -> BoxFuture<'_, bool> {
        self.as_ref().start()
    }

    fn stop(&self) -> BoxFuture<'_, ()> {
        self.as_ref().stop()
    }
}

/// fd 超限就重启 sing-box 回收泄漏的 socket。返回是否真的重启了。
///
/// fd 统计异常**不得**打断守护循环（/proc 读不到时直接跳过本轮）。
/// 冷却时间戳在 stop/start 之前登记：即便重启失败也计冷却，避免抖动式连环重启。
pub async fn recycle_if_fd_leak<H>(host: &H, wd: &mut FdWatchdog, now: f64) -> bool
where
    H: GuardHost + ?Sized,
{
    let fds = match host.fd_count() {
        Ok(v) => v,
        Err(_) => return false,
    };
    if !wd.should_recycle(fds, now) {
        return false;
    }
    wd.mark_restart(now);
    host.stop().await;
    let _ = host.start().await;
    true
}

/// 单轮守护：进程不存在 → 不干预；活着 → 顺带 fd 体检；已退出 → 限流重启。
pub async fn guard_tick<H>(
    host: &H,
    core: &mut GuardCore,
    wd: &mut FdWatchdog,
    now: f64,
) -> GuardTick
where
    H: GuardHost + ?Sized,
{
    if !host.proc_present() {
        return GuardTick::Absent;
    }
    if host.is_running() {
        core.note_running();
        let recycled = recycle_if_fd_leak(host, wd, now).await;
        return GuardTick::Healthy { recycled };
    }
    if core.request_restart(now) {
        let _ = host.start().await;
        GuardTick::Restarted
    } else {
        GuardTick::Cooldown
    }
}

/// 守护主循环（永不返回，由 TaskSet 取消）。
pub async fn guard_loop<H>(host: H, cfg: GuardConfig)
where
    H: GuardHost + Send + Sync + 'static,
{
    let mut core = GuardCore::new(cfg);
    let mut wd = FdWatchdog::default();
    let interval = cfg.interval.max(0.001);
    loop {
        tokio::time::sleep(std::time::Duration::from_secs_f64(interval)).await;
        let _ = guard_tick(&host, &mut core, &mut wd, epoch_now()).await;
    }
}

// ---------- 探活参数 ----------

/// 探活发起方：手动（接口层）或后台（定时/自动复查）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeMode {
    Manual,
    Background,
}

impl ProbeMode {
    /// 并发上限：手动 32 / 后台 16。
    pub fn concurrency(self) -> usize {
        match self {
            ProbeMode::Manual => MANUAL_PROBE_CONCURRENCY,
            ProbeMode::Background => PROBE_CONCURRENCY,
        }
    }

    /// 只有后台探活才累计连败与窗口（手动失败只展示）。
    pub fn counts_failures(self) -> bool {
        matches!(self, ProbeMode::Background)
    }
}

/// 单个节点的有效模式：手动请求里遇到「已停用」节点（自动停用复查触发的探活）
/// 一律按后台处理——它需要后台重确认预算，且不得把停用节点当成手动观测。
pub fn effective_probe_mode(requested: ProbeMode, node_status: &str) -> ProbeMode {
    if node_status == "disabled" {
        ProbeMode::Background
    } else {
        requested
    }
}

/// 每轮 delay 尝试次数：手动 3 次（重试 2），后台 4 次（多一次重确认，吸收抖动）。
pub fn probe_attempts(mode: ProbeMode) -> usize {
    PROBE_DELAY_RETRY + 1 + if mode.counts_failures() { 1 } else { 0 }
}

/// 结合节点连续失败次数获取有效探活尝试次数（判据只认 consecutive_fails，不看 status）：
/// 后台探活对已连续失败 >= 3 次的节点熔断为仅 1 次，严禁在死节点上高频重复重试引发连接风暴与挂起 socket 堆积；
/// 其余情况（手动测活、或后台连败 < 3 次的在线/抖动节点）给予完整重试机会，防抖动误杀。
pub fn probe_attempts_for_node(mode: ProbeMode, fails: i64) -> usize {
    if !mode.counts_failures() {
        // 手动测活：始终按完整尝试次数，快速反馈
        probe_attempts(mode)
    } else if fails >= 3 {
        // 顽固死节点熔断限流：已连续失败 >= 3 次的节点，每轮只做 1 次探活尝试，
        // 彻底根绝死节点每轮 4 次重试叠加挂起 socket 造成的 TCP 堵塞与连接风暴
        1
    } else {
        // 正常在线或初次偶发抖动节点：给予 4 次重试机会（含 8s 缓冲），防误杀
        probe_attempts(mode)
    }
}

/// 第 attempt 次尝试的 delay 超时毫秒：后台最后一次用 8s 重确认，其余 5s。
pub fn probe_delay_timeout_ms(attempt: usize) -> u64 {
    if attempt > PROBE_DELAY_RETRY {
        PROBE_CONFIRM_TIMEOUT_MS
    } else {
        PROBE_TIMEOUT_MS
    }
}

/// 重试前退避（秒）：0.5 * min(attempt, 2)，第 0 次不退避。
pub fn probe_retry_backoff(attempt: usize) -> f64 {
    if attempt == 0 {
        return 0.0;
    }
    (attempt as f64).min(PROBE_RETRY_BACKOFF_CAP) * PROBE_RETRY_BACKOFF_BASE
}

/// 探活间隔：取系统设置并夹到下限 10s；未设置回落默认 60s。
pub fn probe_interval(configured: Option<i64>) -> f64 {
    match configured {
        Some(v) => (v as f64).max(MIN_PROBE_INTERVAL),
        None => PING_INTERVAL,
    }
}

/// 测试 URL 归一化：非 https:// 一律回落默认值
/// （sing-box 对 http:// 置空会回退 gstatic，必须强制 https 语义）。
pub fn normalize_test_url(raw: Option<&str>) -> String {
    match raw.map(str::trim) {
        Some(u) if u.starts_with("https://") => u.to_string(),
        _ => DEFAULT_TEST_URL.to_string(),
    }
}

/// sticky 粘滞时长解析：30s / 5m / 10m / 1h；非法回落 300s，且不低于 5s。
pub fn parse_sticky_timeout(raw: Option<&str>) -> f64 {
    let text = raw.unwrap_or("").trim().to_lowercase();
    let parsed = (|| -> Option<f64> {
        let unit = text.chars().last()?;
        if unit.is_ascii_digit() {
            return None;
        }
        let value: f64 = text[..text.len() - 1].trim().parse().ok()?;
        match unit {
            's' => Some(value),
            'm' => Some(value * 60.0),
            'h' => Some(value * 3600.0),
            _ => None,
        }
    })();
    parsed
        .unwrap_or(DEFAULT_STICKY_SECONDS)
        .max(MIN_STICKY_SECONDS)
}

// ---------- 探活目标选择 ----------

/// 探活所需的最小节点视图。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTargetNode {
    pub id: String,
    pub status: String,
    pub disabled_auto: bool,
    pub port: i64,
    pub protocol: String,
    pub consecutive_fails: i64,
}

impl ProbeTargetNode {
    pub fn new(id: &str, status: &str, disabled_auto: bool, port: i64, protocol: &str) -> Self {
        Self {
            id: id.to_string(),
            status: status.to_string(),
            disabled_auto,
            port,
            protocol: protocol.to_string(),
            consecutive_fails: 0,
        }
    }

    pub fn with_fails(mut self, fails: i64) -> Self {
        self.consecutive_fails = fails;
        self
    }

    pub fn is_disabled(&self) -> bool {
        self.status == "disabled"
    }
}

/// 被跳过的节点（前端结果里原样返回，附提示）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedProbe {
    pub id: String,
    pub status: String,
    pub error: String,
}

/// 探活目标与被跳过节点。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeSelection {
    pub targets: Vec<ProbeTargetNode>,
    pub skipped: Vec<SkippedProbe>,
}

/// 目标筛选：启用节点全测；include_disabled 时自动停用的节点也测（后台复查），
/// 用户手动停用的一律跳过并提示——绝不临时启用。
pub fn select_probe_targets(
    nodes: &[ProbeTargetNode],
    include_disabled: bool,
    ids: Option<&HashSet<String>>,
) -> ProbeSelection {
    let mut out = ProbeSelection::default();
    for node in nodes {
        if let Some(ids) = ids {
            if !ids.contains(&node.id) {
                continue;
            }
        }
        // 正常节点一律探；disabled 节点只有「自动停用」且调用方要求包含时才探。
        if !node.is_disabled() || (include_disabled && node.disabled_auto) {
            out.targets.push(node.clone());
        } else if include_disabled {
            out.skipped.push(SkippedProbe {
                id: node.id.clone(),
                status: "disabled".into(),
                error: MANUAL_DISABLED_HINT.into(),
            });
        }
    }
    out
}

// ---------- 自动停用判定 ----------

/// 探活观测滑窗 + 连败计时 + 探活 tag 快照。
///
/// 只有同时满足四项才停用：连败 >= 20、窗口已填满 30、存活率 <= 0.3、
/// 后台连续失败已持续 >= 20 分钟。窗口不完整或刚重启（历史被清）都不惩罚。
#[derive(Debug, Clone)]
pub struct ProbeTracker {
    window: usize,
    disable_after_fails: i64,
    min_failure_seconds: f64,
    disable_rate: f64,
    hist: HashMap<String, VecDeque<bool>>,
    failure_since: HashMap<String, f64>,
    tags: HashMap<String, (i64, String)>,
}

impl Default for ProbeTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ProbeTracker {
    pub fn new() -> Self {
        Self {
            window: PROBE_WINDOW,
            disable_after_fails: DISABLE_AFTER_FAILS,
            min_failure_seconds: MIN_FAILURE_SECONDS,
            disable_rate: PROBE_DISABLE_RATE_FAST,
            hist: HashMap::new(),
            failure_since: HashMap::new(),
            tags: HashMap::new(),
        }
    }

    pub fn with_limits(
        window: usize,
        disable_after_fails: i64,
        min_failure_seconds: f64,
        disable_rate: f64,
    ) -> Self {
        let mut t = Self::new();
        t.window = window.max(1);
        t.disable_after_fails = disable_after_fails;
        t.min_failure_seconds = min_failure_seconds;
        t.disable_rate = disable_rate;
        t
    }

    pub fn window(&self) -> usize {
        self.window
    }

    /// 记录一轮探活结果到滑窗（固定长度，自动淘汰最旧）。
    pub fn record(&mut self, id: &str, ok: bool) {
        let window = self.window;
        let d = self
            .hist
            .entry(id.to_string())
            .or_insert_with(|| VecDeque::with_capacity(window));
        if d.len() == window {
            d.pop_front();
        }
        d.push_back(ok);
    }

    /// 返回 (窗口内探活次数, 存活率)。无记录 → (0, 1.0)，没观察过的节点按不罚处理。
    pub fn window_rate(&self, id: &str) -> (usize, f64) {
        match self.hist.get(id) {
            Some(d) if !d.is_empty() => {
                let ok = d.iter().filter(|v| **v).count();
                (d.len(), ok as f64 / d.len() as f64)
            }
            _ => (0, 1.0),
        }
    }

    /// 清空该节点的滑窗、连败起点与 tag 快照。
    pub fn reset(&mut self, id: &str) {
        self.hist.remove(id);
        self.failure_since.remove(id);
        self.tags.remove(id);
    }

    /// 清理已删节点的记录（hist / failure_since / tags 三个 map 一起 retain）。
    ///
    /// 无条件做增量 retain：节点规模只有几百，一轮 O(n) 的 retain 开销可忽略；
    /// 早先的"超出存活节点数 500 才清"阈值会让已删节点的陈旧条目长期滞留。
    pub fn prune(&mut self, valid: &HashSet<String>) {
        self.hist.retain(|k, _| valid.contains(k));
        self.failure_since.retain(|k, _| valid.contains(k));
        self.tags.retain(|k, _| valid.contains(k));
    }

    /// 探活 tag 快照（端口 + 协议）。tag 变化 → 旧观测作废。返回是否发生了重置。
    pub fn observe_tag(&mut self, id: &str, port: i64, protocol: &str) -> bool {
        let tag = (port, protocol.to_string());
        let changed = self.tags.get(id).is_some_and(|old| *old != tag);
        if changed {
            self.reset(id);
        }
        self.tags.insert(id.to_string(), tag);
        changed
    }

    pub fn tag_of(&self, id: &str) -> Option<(i64, String)> {
        self.tags.get(id).cloned()
    }

    /// 记录/读取后台连续失败的起点（首次失败时写入 now）。
    pub fn note_failure(&mut self, id: &str, now: f64) -> f64 {
        *self.failure_since.entry(id.to_string()).or_insert(now)
    }

    pub fn clear_failure(&mut self, id: &str) {
        self.failure_since.remove(id);
    }

    pub fn failure_since(&self, id: &str) -> Option<f64> {
        self.failure_since.get(id).copied()
    }

    pub fn hist_len(&self, id: &str) -> usize {
        self.hist.get(id).map(|d| d.len()).unwrap_or(0)
    }

    pub fn hist_snapshot(&self, id: &str) -> Vec<bool> {
        self.hist
            .get(id)
            .map(|d| d.iter().copied().collect())
            .unwrap_or_default()
    }

    /// 是否满足自动停用条件（不含 CAS 校验）。
    pub fn should_disable(&self, id: &str, fails: i64, now: f64) -> bool {
        if fails < self.disable_after_fails {
            return false;
        }
        let (total, rate) = self.window_rate(id);
        if total < self.window {
            return false;
        }
        if rate > self.disable_rate {
            return false;
        }
        match self.failure_since(id) {
            Some(since) => now - since >= self.min_failure_seconds,
            None => false,
        }
    }
}

/// 停用前的库内快照（CAS 前置条件）：状态/连败/端口/协议都必须是本轮观测到的那份。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeProbeSnapshot {
    pub status: String,
    pub consecutive_fails: i64,
    pub port: i64,
    pub protocol: String,
}

/// 停用写库的前置校验：任何一项对不上（用户中途启用/改端口/换协议）都放弃停用。
pub fn disable_cas_ok(
    current: &NodeProbeSnapshot,
    observed_port: i64,
    observed_protocol: &str,
    fails: i64,
) -> bool {
    current.status == "offline"
        && current.consecutive_fails == fails
        && current.port == observed_port
        && current.protocol == observed_protocol
}

// ---------- 出口 IP 情报补查 ----------

/// 节点出口情报视图（统一 JSON 与 types::Node 两条来源）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeIntel {
    pub exit_ip: Option<String>,
    pub exit_country: Option<String>,
    pub exit_type: Option<String>,
    pub exit_risk: Option<i64>,
    pub entry_host: String,
}

impl NodeIntel {
    /// 从 API/DB 的 camelCase JSON 节点构造（rawConfig 里的 server/address 为入口）。
    pub fn from_json(v: &Value) -> Self {
        fn text(v: &Value, keys: &[&str]) -> Option<String> {
            keys.iter()
                .find_map(|k| v.get(*k).and_then(|x| x.as_str()))
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        }
        let raw = v
            .get("rawConfig")
            .or_else(|| v.get("raw_config"))
            .cloned()
            .unwrap_or(Value::Null);
        Self {
            exit_ip: text(v, &["exitIp", "exit_ip"]),
            exit_country: text(v, &["exitCountry", "exit_country"]),
            exit_type: text(v, &["exitType", "exit_type"]),
            exit_risk: v
                .get("exitRisk")
                .or_else(|| v.get("exit_risk"))
                .and_then(|x| x.as_i64()),
            entry_host: entry_host(&raw),
        }
    }

    /// 从类型化节点构造（db.rs 交付后由 app 层直接复用）。
    pub fn from_node(n: &crate::types::Node) -> Self {
        let raw = n.base.raw_config.clone().unwrap_or(Value::Null);
        Self {
            exit_ip: n.base.exit_ip.clone(),
            exit_country: n.base.exit_country.clone(),
            exit_type: n.base.exit_type.clone(),
            exit_risk: n.base.exit_risk,
            entry_host: entry_host(&raw),
        }
    }

    /// 出口情报是否齐全（国家/类型/风控值任缺一项都要补查）。
    pub fn has_full_intel(&self) -> bool {
        has_full_intel(
            self.exit_country.as_deref(),
            self.exit_type.as_deref(),
            self.exit_risk,
        )
    }
}

/// 出口情报是否齐全（国家/类型/风控值任缺一项都要补查）。
pub fn has_full_intel(country: Option<&str>, kind: Option<&str>, risk: Option<i64>) -> bool {
    let filled = |v: Option<&str>| v.map(|s| !s.trim().is_empty()).unwrap_or(false);
    filled(country) && filled(kind) && risk.is_some()
}

/// 入口服务器 host（只有域名才可能被误当成出口 IP 存下来）。
pub fn entry_host(raw_config: &Value) -> String {
    let pick = |key: &str| {
        raw_config
            .get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    pick("server")
        .or_else(|| pick("address"))
        .unwrap_or_default()
}

/// 可用的出口 IP：占位值（空 / N/A / 1.1.1.1）与非 IP（域名）都视为「需重探」。
pub fn usable_exit_ip(exit_ip: Option<&str>) -> Option<String> {
    let ip = exit_ip?.trim();
    if ip.is_empty() || ip == "N/A" || ip == "1.1.1.1" {
        return None;
    }
    if !is_ip_address(ip) {
        return None;
    }
    Some(ip.to_string())
}

/// exitIp 是否是「入口域名解析出来的 IP」这类历史脏数据。
///
/// 入口是域名时才可能脏；解析失败（None）时无法判定，按干净处理（与 Python 一致）。
pub fn is_historical_entry_ip(
    exit_ip: &str,
    entry_host: &str,
    resolved_entry_ip: Option<&str>,
) -> bool {
    !entry_host.is_empty() && !is_ip_address(entry_host) && resolved_entry_ip == Some(exit_ip)
}

/// 补查决策。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrichPlan {
    /// 情报齐全且不可能脏 → 直接跳过（最常见快路径，零 I/O）。
    Skip,
    /// 同一节点已有补查在跑。
    InFlight,
    /// 冷却期内（上次补查不足 5 分钟）。
    Cooling,
    /// 需要干活；fetch_exit_ip 为 true 表示必须先经节点自身代理重探出口 IP。
    Run {
        fetch_exit_ip: bool,
        dirty_risk: bool,
    },
}

/// 补查闸门：在途去重 + 冷却 + LRU 淘汰。
#[derive(Debug, Clone)]
pub struct EnrichGate {
    cooldown: f64,
    lru_cap: usize,
    lru_evict: usize,
    pending: HashSet<String>,
    last: HashMap<String, f64>,
}

impl Default for EnrichGate {
    fn default() -> Self {
        Self::new(ENRICH_COOLDOWN, ENRICH_LRU_CAP, ENRICH_LRU_EVICT)
    }
}

impl EnrichGate {
    pub fn new(cooldown: f64, lru_cap: usize, lru_evict: usize) -> Self {
        Self {
            cooldown,
            lru_cap,
            lru_evict,
            pending: HashSet::new(),
            last: HashMap::new(),
        }
    }

    /// 判定该节点是否需要补查；返回 Run 时已登记在途标记（调用方必须最终 finish/abort）。
    pub fn plan(&mut self, id: &str, intel: &NodeIntel, now: f64) -> EnrichPlan {
        let ip = usable_exit_ip(intel.exit_ip.as_deref());
        let entry_is_domain = !intel.entry_host.is_empty() && !is_ip_address(&intel.entry_host);
        let dirty_risk = ip.is_some() && entry_is_domain;
        if ip.is_some() && !dirty_risk && intel.has_full_intel() {
            return EnrichPlan::Skip;
        }
        if self.pending.contains(id) {
            return EnrichPlan::InFlight;
        }
        if now - self.last.get(id).copied().unwrap_or(0.0) < self.cooldown {
            return EnrichPlan::Cooling;
        }
        self.pending.insert(id.to_string());
        EnrichPlan::Run {
            fetch_exit_ip: ip.is_none(),
            dirty_risk,
        }
    }

    /// 补查收尾：清除在途标记、记录时间（冷却用），并在超容量时淘汰最旧 20%。
    pub fn finish(&mut self, id: &str, now: f64) {
        self.pending.remove(id);
        self.last.insert(id.to_string(), now);
        if self.last.len() > self.lru_cap {
            let mut pairs: Vec<(String, f64)> =
                self.last.iter().map(|(k, v)| (k.clone(), *v)).collect();
            pairs.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
            for (key, _) in pairs.into_iter().take(self.lru_evict) {
                self.last.remove(&key);
            }
        }
    }

    /// 放弃在途标记（不写冷却），用于任务被取消的场景。
    pub fn abort(&mut self, id: &str) {
        self.pending.remove(id);
    }

    pub fn is_pending(&self, id: &str) -> bool {
        self.pending.contains(id)
    }

    pub fn last_at(&self, id: &str) -> Option<f64> {
        self.last.get(id).copied()
    }

    pub fn tracked(&self) -> usize {
        self.last.len()
    }
}

/// ippure 风控值是否可用：必须与当前出口 IP 一致且给出非空 exitRisk。
pub fn ippure_risk_usable(
    ippure_exit_ip: Option<&str>,
    cur_ip: &str,
    ippure_risk: Option<i64>,
) -> bool {
    ippure_exit_ip == Some(cur_ip) && ippure_risk.is_some()
}

/// 补查并发闸门（对应 asyncio.Semaphore(8)：ipinfo 免费额度有限，仅补缺情报的节点）。
#[derive(Debug, Clone)]
pub struct ConcurrencyGate {
    limit: usize,
    running: usize,
}

impl ConcurrencyGate {
    pub fn new(limit: usize) -> Self {
        Self {
            limit: limit.max(1),
            running: 0,
        }
    }

    pub fn for_enrich() -> Self {
        Self::new(ENRICH_CONCURRENCY)
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn running(&self) -> usize {
        self.running
    }

    /// 有空位则占用并返回 true。
    pub fn try_acquire(&mut self) -> bool {
        if self.running >= self.limit {
            return false;
        }
        self.running += 1;
        true
    }

    pub fn release(&mut self) {
        self.running = self.running.saturating_sub(1);
    }
}

// ---------- 任务集（幂等启停） ----------

/// 后台任务集：整批启停，重复调用幂等，停止时全部取消并 join。
#[derive(Debug, Default)]
pub struct TaskSet {
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl TaskSet {
    pub fn new() -> Self {
        Self { tasks: Vec::new() }
    }

    /// 整批启动；只要还有存活任务就跳过（幂等）。返回是否真的启动了。
    pub fn spawn_batch<F, I>(&mut self, futs: I) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
        I: IntoIterator<Item = F>,
    {
        self.tasks.retain(|t| !t.is_finished());
        if !self.tasks.is_empty() {
            return false;
        }
        for f in futs {
            self.tasks.push(tokio::spawn(f));
        }
        !self.tasks.is_empty()
    }

    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// 取消并 join 所有任务，清空任务集。
    pub async fn shutdown(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
        for t in self.tasks.drain(..) {
            let _ = t.await;
        }
    }
}

// ===========================================================================
// 第三批：探测编排 + 生产 Prober 实现
//
// 对应 backend/scheduler.py 的 probe_nodes / _probe_one /
// _sync_relay_exits_after_probe / _rotate_random_relay / _probe_loop /
// _disabled_revive_loop / _relay_random_loop / _lazy_enrich_ip。
//
// 设计：所有外部依赖（clash API / 出口 IP 探测 / DNS / 情报源）都收在 trait 后面，
// 生产走 HttpClashApi / ProbeIpFetcher / SystemResolver / IpinfoLookup，
// 单测走内存桩，绝不启动 sing-box、绝不打外网。
// ===========================================================================

/// clash API 的 delay 探测请求参数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelayRequest {
    pub base: String,
    pub secret: Option<String>,
    pub tag: String,
    pub url: String,
    /// clash API 的 timeout 查询参数（毫秒）。
    pub timeout_ms: u64,
}

/// delay 探测结果分类：决定重试还是立即判 unknown。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelayOutcome {
    /// 200 且 delay 合法（非负整数）。
    Ok(i64),
    /// 代理本轮不通但 clash 回了 message，允许重试。
    Retry(String),
    /// 结果不可信（401/403/404、非法 JSON、非法 delay），立即 unknown 不重试。
    Unknown(String),
    /// clash API 本身不可达，立即 unknown 不重试。
    Unreachable(String),
}

/// clash API 最小面：探活 / 读 selector 当前出口 / 运行时切换出口。
pub trait ClashApi: Send + Sync {
    /// GET /proxies/{tag}/delay
    fn delay(&self, req: DelayRequest) -> BoxFuture<'_, DelayOutcome>;
    /// GET /proxies/{tag} 的 now 字段；为空或等于 tag 自身都视为 None。
    fn current(
        &self,
        base: String,
        secret: Option<String>,
        tag: String,
    ) -> BoxFuture<'_, Option<String>>;
    /// PUT /proxies/{tag} 切换 selector 出口。
    fn select(
        &self,
        base: String,
        secret: Option<String>,
        tag: String,
        name: String,
    ) -> BoxFuture<'_, Result<(), String>>;
}

/// 组装 Bearer 头；空 secret 视为未配置。
pub fn bearer(secret: Option<&str>) -> Option<String> {
    secret
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| format!("Bearer {s}"))
}

/// 生产实现：reqwest 直连本机 clash API。
#[derive(Clone, Debug)]
pub struct HttpClashApi {
    client: reqwest::Client,
}

impl HttpClashApi {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }
}

impl ClashApi for HttpClashApi {
    fn delay(&self, req: DelayRequest) -> BoxFuture<'_, DelayOutcome> {
        Box::pin(async move {
            let timeout = req.timeout_ms.to_string();
            let mut rb = self
                .client
                .get(format!("{}/proxies/{}/delay", req.base, req.tag))
                .query(&[("url", req.url.as_str()), ("timeout", timeout.as_str())])
                .timeout(Duration::from_millis(req.timeout_ms + 1500));
            if let Some(h) = bearer(req.secret.as_deref()) {
                rb = rb.header("Authorization", h);
            }
            let resp = match rb.send().await {
                Ok(r) => r,
                Err(e) => return DelayOutcome::Unreachable(format!("clash API 不可达: {e}")),
            };
            let code = resp.status().as_u16();
            if matches!(code, 401 | 403 | 404) {
                return DelayOutcome::Unknown(format!("clash API HTTP {code}"));
            }
            let body = match resp.text().await {
                Ok(b) => b,
                Err(e) => return DelayOutcome::Unreachable(format!("clash API 不可达: {e}")),
            };
            let data: Value = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(_) => return DelayOutcome::Unknown("clash API 返回无效 JSON".to_string()),
            };
            let Some(obj) = data.as_object() else {
                return DelayOutcome::Unknown("clash API 返回无效结果".to_string());
            };
            if code == 200 {
                if let Some(d) = obj.get("delay").filter(|v| !v.is_null()) {
                    let parsed = d.as_i64().or_else(|| d.as_f64().map(|f| f as i64));
                    return match parsed {
                        Some(n) if n >= 0 => DelayOutcome::Ok(n),
                        _ => DelayOutcome::Unknown("clash API 返回无效 delay".to_string()),
                    };
                }
            }
            match obj
                .get("message")
                .and_then(|m| m.as_str())
                .filter(|m| !m.is_empty())
            {
                Some(msg) => DelayOutcome::Retry(msg.to_string()),
                None => DelayOutcome::Unknown(format!("clash API HTTP {code} 无探活结果")),
            }
        })
    }

    fn current(
        &self,
        base: String,
        secret: Option<String>,
        tag: String,
    ) -> BoxFuture<'_, Option<String>> {
        Box::pin(async move {
            let mut rb = self.client.get(format!("{base}/proxies/{tag}"));
            if let Some(h) = bearer(secret.as_deref()) {
                rb = rb.header("Authorization", h);
            }
            let resp = rb.send().await.ok()?;
            if resp.status().as_u16() != 200 {
                return None;
            }
            let data: Value = resp.json().await.ok()?;
            let now = data
                .get("now")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if now.is_empty() || now == tag {
                None
            } else {
                Some(now)
            }
        })
    }

    fn select(
        &self,
        base: String,
        secret: Option<String>,
        tag: String,
        name: String,
    ) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            let mut rb = self
                .client
                .put(format!("{base}/proxies/{tag}"))
                .json(&serde_json::json!({ "name": name }));
            if let Some(h) = bearer(secret.as_deref()) {
                rb = rb.header("Authorization", h);
            }
            let resp = rb
                .send()
                .await
                .map_err(|e| format!("clash API 不可达: {e}"))?;
            let code = resp.status().as_u16();
            if code == 200 || code == 204 {
                Ok(())
            } else {
                Err(format!("clash API HTTP {code}"))
            }
        })
    }
}

/// 出口 IP 探测抽象（对齐 Python 的 probe_ip.fetch_exit_ip）。
pub trait ExitIpFetcher: Send + Sync {
    fn fetch_exit_ip(&self, node: Value) -> BoxFuture<'_, Option<String>>;
}

/// 生产实现：把节点 JSON 还原成 NodeProbe，走 probe_ip 的原生代理/入站探测。
/// 关键：探测失败一律返回 None，绝不回落到 server 域名的解析地址。
#[derive(Debug, Default, Clone, Copy)]
pub struct ProbeIpFetcher;

impl ExitIpFetcher for ProbeIpFetcher {
    fn fetch_exit_ip(&self, node: Value) -> BoxFuture<'_, Option<String>> {
        Box::pin(async move { crate::probe_ip::fetch_exit_ip(node_probe(&node)).await })
    }
}

/// 节点 JSON -> probe_ip::NodeProbe（rawConfig 缺 server 但有 uri 时由
/// subs_proxy::proxy_endpoint 负责补全）。
pub fn node_probe(node: &Value) -> crate::probe_ip::NodeProbe {
    let protocol = node
        .get("protocol")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let entry_proto = node
        .get("entryProto")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(crate::probe_ip::DEFAULT_ENTRY_PROTO)
        .to_string();
    let inbound_port = node.get("port").and_then(|v| v.as_i64()).unwrap_or(0);
    let auth_user = node
        .get("authUser")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let auth_pass = node
        .get("authPass")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let raw = node.get("rawConfig");
    let endpoint = crate::subs_proxy::proxy_endpoint(node)
        .or_else(|| crate::subs_proxy::proxy_endpoint_of_raw(raw));
    let mut probe = crate::probe_ip::NodeProbe::new(&protocol)
        .entry_proto(&entry_proto)
        .inbound_port(inbound_port);
    if let Some(ep) = endpoint {
        let target = crate::probe_ip::ProxyTarget::new(&protocol, &ep.host, ep.port)
            .with_credentials(ep.username, ep.password);
        probe = probe.endpoint(Some(target));
    }
    if auth_user.is_some() || auth_pass.is_some() {
        probe = probe.auth(auth_user, auth_pass);
    }
    probe
}

/// 域名解析抽象（只用于判定历史脏数据，绝不用于产出出口 IP）。
pub trait HostResolver: Send + Sync {
    fn resolve(&self, host: String) -> BoxFuture<'_, Option<String>>;
}

/// 生产实现：tokio 内置解析。
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl HostResolver for SystemResolver {
    fn resolve(&self, host: String) -> BoxFuture<'_, Option<String>> {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((host.as_str(), 0)).await.ok()?;
            addrs.map(|a| a.ip().to_string()).next()
        })
    }
}

/// 出口情报源抽象（生产转发 crate::ipinfo，测试用内存桩）。
pub trait IntelLookup: Send + Sync {
    fn lookup(&self, ip: String) -> BoxFuture<'_, Value>;
    fn ippure(&self, ip: String, nodes: Vec<crate::ipinfo::ProxyNode>) -> BoxFuture<'_, Value>;
    fn ping0(&self, ip: String, nodes: Vec<crate::ipinfo::ProxyNode>) -> BoxFuture<'_, Value>;
}

/// 生产实现：转发 ipinfo 的三个查询入口。
#[derive(Clone, Debug)]
pub struct IpinfoLookup {
    client: reqwest::Client,
}

impl IpinfoLookup {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

impl IntelLookup for IpinfoLookup {
    fn lookup(&self, ip: String) -> BoxFuture<'_, Value> {
        Box::pin(async move { crate::ipinfo::lookup(&self.client, &ip).await })
    }

    fn ippure(&self, ip: String, nodes: Vec<crate::ipinfo::ProxyNode>) -> BoxFuture<'_, Value> {
        Box::pin(async move { crate::ipinfo::lookup_ippure_nodes(&self.client, &ip, &nodes).await })
    }

    fn ping0(&self, ip: String, nodes: Vec<crate::ipinfo::ProxyNode>) -> BoxFuture<'_, Value> {
        Box::pin(async move { crate::ipinfo::lookup_ping0_nodes(&self.client, &ip, &nodes).await })
    }
}

// ===========================================================================
// 出口情报补查（对齐 scheduler.py 的 _lazy_enrich_ip）
// ===========================================================================

fn node_id_of(node: &Value) -> String {
    node.get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn node_str<'a>(node: &'a Value, key: &str) -> Option<&'a str> {
    node.get(key).and_then(|v| v.as_str())
}

/// 惰性补查的编排器：决策层复用第一批的 EnrichGate，I/O 层全部可注入。
pub struct Enricher {
    db: Arc<crate::db::Db>,
    fetcher: Arc<dyn ExitIpFetcher>,
    resolver: Arc<dyn HostResolver>,
    lookup: Arc<dyn IntelLookup>,
    gate: Mutex<EnrichGate>,
    sem: Arc<Semaphore>,
}

impl Enricher {
    pub fn new(
        db: Arc<crate::db::Db>,
        http: reqwest::Client,
        fetcher: Arc<dyn ExitIpFetcher>,
    ) -> Self {
        Self {
            db,
            fetcher,
            resolver: Arc::new(SystemResolver),
            lookup: Arc::new(IpinfoLookup::new(http)),
            gate: Mutex::new(EnrichGate::default()),
            sem: Arc::new(Semaphore::new(ENRICH_CONCURRENCY)),
        }
    }

    pub fn with_resolver(mut self, resolver: Arc<dyn HostResolver>) -> Self {
        self.resolver = resolver;
        self
    }

    pub fn with_lookup(mut self, lookup: Arc<dyn IntelLookup>) -> Self {
        self.lookup = lookup;
        self
    }

    pub fn with_gate(mut self, gate: EnrichGate) -> Self {
        self.gate = Mutex::new(gate);
        self
    }

    pub fn with_concurrency(mut self, limit: usize) -> Self {
        self.sem = Arc::new(Semaphore::new(limit.max(1)));
        self
    }

    pub fn fetcher(&self) -> Arc<dyn ExitIpFetcher> {
        self.fetcher.clone()
    }

    pub fn db(&self) -> &Arc<crate::db::Db> {
        &self.db
    }

    /// 纯决策：这一轮该跳过、在飞、冷却，还是真的去抓。
    pub fn plan(&self, node: &Value, now: f64) -> EnrichPlan {
        let intel = NodeIntel::from_json(node);
        let id = node_id_of(node);
        self.gate.lock().unwrap().plan(&id, &intel, now)
    }

    /// 惰性触发（对齐 Python 的 asyncio.create_task）：不阻塞调用方。
    pub fn lazy_enrich(self: &Arc<Self>, node: Value) {
        if !matches!(self.plan(&node, epoch_now()), EnrichPlan::Run { .. }) {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            me.enrich_planned(node).await;
        });
    }

    /// 走完整流程（自己做 plan，Run 才干活）；测试与 enrich_loop 直接调用。
    pub async fn enrich(&self, node: Value) {
        if !matches!(self.plan(&node, epoch_now()), EnrichPlan::Run { .. }) {
            return;
        }
        self.enrich_planned(node).await;
    }

    async fn enrich_planned(&self, node: Value) {
        let id = node_id_of(&node);
        if let Err(e) = self.enrich_inner(&node, &id).await {
            tracing::debug!(node = %id, error = %e, "出口情报补查失败");
        }
        // 无论成败都必须解掉 pending 并记时间戳，否则该节点会永久卡在 InFlight。
        self.gate.lock().unwrap().finish(&id, epoch_now());
    }

    async fn enrich_inner(&self, node: &Value, id: &str) -> Result<(), String> {
        let intel = NodeIntel::from_json(node);
        let mut cur_ip = usable_exit_ip(intel.exit_ip.as_deref());
        let entry_is_domain = !intel.entry_host.is_empty() && !is_ip_address(&intel.entry_host);
        if let Some(ip) = cur_ip.clone() {
            if entry_is_domain {
                let resolved = self.resolver.resolve(intel.entry_host.clone()).await;
                if is_historical_entry_ip(&ip, &intel.entry_host, resolved.as_deref()) {
                    // 历史脏数据：入口 IP 被当成出口 IP 落库，必须重探。
                    cur_ip = None;
                }
            }
        }
        if cur_ip.is_some() && intel.has_full_intel() {
            return Ok(());
        }
        if cur_ip.is_none() {
            let fetched = {
                let _permit = self.sem.acquire().await.map_err(|e| e.to_string())?;
                self.fetcher.fetch_exit_ip(node.clone()).await
            };
            let Some(ip) = fetched else {
                // 探测失败就地放弃，绝不回落到入口域名解析地址。
                return Ok(());
            };
            self.db
                .update_node_json(id, &json!({ "exitIp": ip }))
                .map_err(|e| format!("exitIp 落库失败: {e}"))?;
            cur_ip = Some(ip);
        }
        let Some(ip) = cur_ip else {
            return Ok(());
        };
        let online: Vec<Value> = match intel.exit_risk {
            Some(_) => Vec::new(),
            None => self.online_mixed_nodes()?,
        };
        let info = {
            let _permit = self.sem.acquire().await.map_err(|e| e.to_string())?;
            self.lookup.lookup(ip.clone()).await
        };
        let mut patch = serde_json::Map::new();
        for key in [
            "exitCountry",
            "exitFlag",
            "exitCity",
            "exitType",
            "exitScore",
        ] {
            if let Some(v) = info.get(key).filter(|v| !v.is_null()) {
                patch.insert(key.to_string(), v.clone());
            }
        }
        patch.insert("exitIp".to_string(), json!(ip));
        if intel.exit_risk.is_none() {
            let mut risk: Option<i64> = None;
            if let Some(proxy) = ippure_proxy(node, &online) {
                let data = {
                    let _permit = self.sem.acquire().await.map_err(|e| e.to_string())?;
                    self.lookup.ippure(ip.clone(), vec![proxy]).await
                };
                let claimed = data.get("exitIp").and_then(|v| v.as_str());
                let r = data.get("exitRisk").and_then(|v| v.as_i64());
                if ippure_risk_usable(claimed, &ip, r) {
                    risk = r;
                }
            }
            if risk.is_none() {
                let pool: Vec<crate::ipinfo::ProxyNode> = online
                    .iter()
                    .filter_map(crate::ipinfo::ProxyNode::from_value)
                    .take(10)
                    .collect();
                if !pool.is_empty() {
                    let data = {
                        let _permit = self.sem.acquire().await.map_err(|e| e.to_string())?;
                        self.lookup.ping0(ip.clone(), pool).await
                    };
                    risk = data.get("exitRisk").and_then(|v| v.as_i64());
                }
            }
            if let Some(r) = risk {
                patch.insert("exitRisk".to_string(), json!(r));
            }
        }
        if !patch.is_empty() {
            self.db
                .update_node_json(id, &Value::Object(patch))
                .map_err(|e| format!("出口情报落库失败: {e}"))?;
        }
        Ok(())
    }

    /// 自身节点里 online 且 entryProto=mixed 的快照（ippure/ping0 都要借它当代理）。
    fn online_mixed_nodes(&self) -> Result<Vec<Value>, String> {
        let nodes = self
            .db
            .list_nodes(None, None, None)
            .map_err(|e| e.to_string())?;
        Ok(nodes
            .iter()
            .filter(|n| n.base.status.as_deref() == Some("online"))
            .filter(|n| {
                n.base
                    .entry_proto
                    .as_deref()
                    .unwrap_or(crate::probe_ip::DEFAULT_ENTRY_PROTO)
                    == crate::probe_ip::DEFAULT_ENTRY_PROTO
            })
            .filter_map(|n| serde_json::to_value(n).ok())
            .collect())
    }
}

/// 找出同一个节点在 online 快照里的那份 JSON（ippure 需要它自己的入站代理）。
fn ippure_proxy(node: &Value, online: &[Value]) -> Option<crate::ipinfo::ProxyNode> {
    let id = node_str(node, "id")?;
    online
        .iter()
        .find(|n| n.get("id").and_then(|v| v.as_str()) == Some(id))
        .and_then(crate::ipinfo::ProxyNode::from_value)
}

// ===========================================================================
// 操作窗口状态（对齐 Python 的 _op_lock / operation_generation）
// ===========================================================================

/// 判定「此刻是不是有配置操作在跑」以及「配置代次是否已变」。
pub trait OpState: Send + Sync {
    fn locked(&self) -> bool {
        false
    }

    fn generation(&self) -> u64 {
        0
    }
}

/// 无锁占位（只有探活、没有配置编排的场景）。
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopOpState;

impl OpState for NoopOpState {}

/// 生产适配：直接读 ConfigManager 的操作锁与代次，config_apply 无需改动。
impl OpState for crate::config_apply::ConfigManager {
    fn locked(&self) -> bool {
        self.op_lock().try_lock().is_err()
    }

    fn generation(&self) -> u64 {
        self.operation_generation()
    }
}

// ===========================================================================
// 探活引擎（对齐 scheduler.py 的 probe_nodes / _probe_one / _probe_nodes_inner）
// ===========================================================================

/// 探活引擎：crate::wire::Prober 的生产实现。
pub struct ProbeEngine {
    db: Arc<crate::db::Db>,
    cfg: Arc<dyn crate::wire::ConfigService>,
    clash: Arc<dyn ClashApi>,
    enricher: Arc<Enricher>,
    op: Arc<dyn OpState>,
    tracker: Mutex<ProbeTracker>,
    inflight: AtomicBool,
    retry_scale: f64,
    switch_at: Mutex<HashMap<String, f64>>,
}

impl ProbeEngine {
    pub fn new(
        db: Arc<crate::db::Db>,
        cfg: Arc<dyn crate::wire::ConfigService>,
        http: reqwest::Client,
    ) -> Self {
        let enricher = Arc::new(Enricher::new(
            db.clone(),
            http.clone(),
            Arc::new(ProbeIpFetcher),
        ));
        Self {
            db,
            cfg,
            clash: Arc::new(HttpClashApi::new(http)),
            enricher,
            op: Arc::new(NoopOpState),
            tracker: Mutex::new(ProbeTracker::new()),
            inflight: AtomicBool::new(false),
            retry_scale: 1.0,
            switch_at: Mutex::new(HashMap::new()),
        }
    }

    pub fn with_clash(mut self, clash: Arc<dyn ClashApi>) -> Self {
        self.clash = clash;
        self
    }

    pub fn with_op(mut self, op: Arc<dyn OpState>) -> Self {
        self.op = op;
        self
    }

    pub fn with_tracker(mut self, tracker: ProbeTracker) -> Self {
        self.tracker = Mutex::new(tracker);
        self
    }

    pub fn with_enricher(mut self, enricher: Arc<Enricher>) -> Self {
        self.enricher = enricher;
        self
    }

    /// 重试退避倍率：测试传 0.0 免等待，生产固定 1.0。
    pub fn with_retry_scale(mut self, scale: f64) -> Self {
        self.retry_scale = scale.max(0.0);
        self
    }

    pub fn db(&self) -> &Arc<crate::db::Db> {
        &self.db
    }

    pub fn cfg(&self) -> &Arc<dyn crate::wire::ConfigService> {
        &self.cfg
    }

    pub fn clash(&self) -> &Arc<dyn ClashApi> {
        &self.clash
    }

    pub fn enricher(&self) -> &Arc<Enricher> {
        &self.enricher
    }

    pub fn op(&self) -> &Arc<dyn OpState> {
        &self.op
    }

    pub fn tracker(&self) -> std::sync::MutexGuard<'_, ProbeTracker> {
        self.tracker.lock().unwrap()
    }

    /// 是否有一轮探活在飞（Python 的 _probe_running）。
    pub fn probing(&self) -> bool {
        self.inflight.load(Ordering::SeqCst)
    }

    /// relay 上次被自动切换的时刻（粘滞判定用）。
    pub fn switch_at(&self, relay_id: &str) -> Option<f64> {
        self.switch_at.lock().unwrap().get(relay_id).copied()
    }

    /// 本轮结果是否还有效（进程在跑、没被配置操作抢走、代次没变）。
    fn round_valid(&self, generation: u64) -> bool {
        self.cfg.is_running() && !self.op.locked() && self.op.generation() == generation
    }

    /// 自动停用最后一关：库里状态必须仍是 offline 且失败次数/tag 都没变。
    fn try_disable(&self, id: &str, target: &ProbeTargetNode, fails: i64) -> bool {
        let current = match self.db.get_node(id) {
            Ok(Some(n)) => n,
            _ => return false,
        };
        let snapshot = NodeProbeSnapshot {
            status: current.base.status.clone().unwrap_or_default(),
            consecutive_fails: current.base.consecutive_fails.unwrap_or(0),
            port: current.base.port.unwrap_or(0),
            protocol: current.base.protocol.clone(),
        };
        if !disable_cas_ok(&snapshot, target.port, &target.protocol, fails) {
            return false;
        }
        match self
            .db
            .disable_node_after_probe(id, target.port, &target.protocol, fails)
        {
            Ok(true) => {
                tracing::warn!(node = %id, fails, "连续探活失败，自动停用节点");
                true
            }
            _ => false,
        }
    }

    /// 批量落库失败时的退路：逐条写，行为等价于修复前的逐节点同步写库。
    fn write_probe_rows_one_by_one(&self, rows: &[ProbeUpdateRow]) -> Vec<UpdateNodeProbeOutcome> {
        rows.iter()
            .map(|r| {
                self.db
                    .update_node_probe(
                        &r.node_id,
                        r.ping,
                        &r.status,
                        r.count_failure,
                        r.expected_port,
                        r.expected_protocol.as_deref(),
                    )
                    .ok()
                    .flatten()
            })
            .collect()
    }

    async fn probe_inner(
        &self,
        ids: Option<Vec<String>>,
        all: bool,
        include_disabled: bool,
        manual: bool,
    ) -> Vec<Value> {
        if self.inflight.swap(true, Ordering::SeqCst) {
            // 上一轮还没结束：重叠调用直接返回空，避免双写探活历史。
            return Vec::new();
        }
        let _guard = InflightGuard(&self.inflight);
        if !self.cfg.is_running() || self.op.locked() {
            return Vec::new();
        }
        let generation = self.op.generation();
        let nodes = match self.db.list_nodes(None, None, None) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "探活读取节点列表失败");
                return Vec::new();
            }
        };
        let valid: HashSet<String> = nodes.iter().map(|n| n.id.clone()).collect();
        self.tracker.lock().unwrap().prune(&valid);
        let settings = self.db.get_setting("system").unwrap_or_else(|_| json!({}));
        let test_url = normalize_test_url(settings.get("testUrl").and_then(|v| v.as_str()));
        let base = self.cfg.clash_base();
        let secret = self.cfg.clash_secret();
        let idset: Option<HashSet<String>> = if all {
            None
        } else {
            ids.map(|v| v.into_iter().collect())
        };
        let views: Vec<ProbeTargetNode> = nodes
            .iter()
            .map(|n| {
                ProbeTargetNode::new(
                    &n.id,
                    n.base.status.as_deref().unwrap_or(""),
                    n.base.disabled_auto.unwrap_or(false),
                    n.base.port.unwrap_or(0),
                    &n.base.protocol,
                )
                .with_fails(n.base.consecutive_fails.unwrap_or(0))
            })
            .collect();
        let by_id: HashMap<String, ProbeTargetNode> =
            views.iter().map(|v| (v.id.clone(), v.clone())).collect();
        let selection = select_probe_targets(&views, include_disabled, idset.as_ref());
        let mut skipped: Vec<Value> = Vec::new();
        for s in &selection.skipped {
            let tag = by_id
                .get(&s.id)
                .map(|v| crate::config_manager::outbound_tag(&v.protocol, v.port))
                .unwrap_or_default();
            skipped.push(json!({
                "id": s.id,
                "tag": tag,
                "ping": 0,
                "status": s.status,
                "error": s.error,
            }));
        }
        if selection.targets.is_empty() {
            return skipped;
        }
        let requested = if manual {
            ProbeMode::Manual
        } else {
            ProbeMode::Background
        };
        let sem = Arc::new(Semaphore::new(requested.concurrency()));
        let mut set = tokio::task::JoinSet::new();
        for (index, target) in selection.targets.iter().enumerate() {
            let clash = self.clash.clone();
            let base = base.clone();
            let secret = secret.clone();
            let url = test_url.clone();
            let node = target.clone();
            let mode = effective_probe_mode(requested, &node.status);
            let scale = self.retry_scale;
            let slot = sem.clone();
            set.spawn(async move {
                let _permit = slot.acquire().await;
                let item = probe_one(clash, base, secret, url, node, mode, scale).await;
                (index, item)
            });
        }
        let mut ordered: Vec<Option<PingResultItem>> =
            (0..selection.targets.len()).map(|_| None).collect();
        while let Some(joined) = set.join_next().await {
            if let Ok((index, item)) = joined {
                ordered[index] = Some(item);
            }
        }
        let results: Vec<PingResultItem> = ordered.into_iter().flatten().collect();
        if !self.round_valid(generation) {
            return Vec::new();
        }
        let nodes_json: HashMap<String, Value> = nodes
            .iter()
            .filter_map(|n| serde_json::to_value(n).ok().map(|v| (n.id.clone(), v)))
            .collect();
        let mut need_rebuild = false;
        let mut to_enrich: Vec<Value> = Vec::new();
        let mut out: Vec<Value> = Vec::new();
        // 待落库项：循环里只算内存侧 tracker 与占位，循环后一次性批量写库（FIX-B1）。
        let mut pending: Vec<PendingProbeWrite> = Vec::new();
        for (target, mut item) in selection.targets.iter().zip(results) {
            if self.op.locked() || self.op.generation() != generation {
                break;
            }
            if item.status == "unknown" {
                out.push(json!(item));
                continue;
            }
            let mode = effective_probe_mode(requested, &target.status);
            self.tracker
                .lock()
                .unwrap()
                .observe_tag(&target.id, target.port, &target.protocol);
            if target.is_disabled() {
                if item.status != "online" {
                    // 手动停用的节点探不通：保持 disabled，不写探活历史。
                    item.status = "disabled".to_string();
                } else {
                    match self.db.revive_node_probe(
                        &target.id,
                        item.ping,
                        target.port,
                        &target.protocol,
                    ) {
                        Ok(Some(_)) => {
                            let mut tracker = self.tracker.lock().unwrap();
                            tracker.reset(&target.id);
                            tracker.record(&target.id, true);
                            drop(tracker);
                            need_rebuild = true;
                        }
                        _ => {
                            item.status = "unknown".to_string();
                            item.error = Some(STALE_PROBE_HINT.to_string());
                        }
                    }
                }
                if item.status == "online" {
                    if let Some(mut value) = nodes_json.get(&target.id).cloned() {
                        value["status"] = json!("online");
                        to_enrich.push(value);
                    }
                }
                out.push(json!(item));
            } else {
                // 先占位，等批量落库后按结果回填 status / error。
                let enrich = if item.status == "online" {
                    nodes_json.get(&target.id).cloned().map(|mut value| {
                        value["status"] = json!("online");
                        value
                    })
                } else {
                    None
                };
                out.push(json!(item));
                pending.push(PendingProbeWrite {
                    out_idx: out.len() - 1,
                    row: ProbeUpdateRow::new(
                        &target.id,
                        item.ping,
                        &item.status,
                        mode.counts_failures(),
                        Some(target.port),
                        Some(&target.protocol),
                    ),
                    target: target.clone(),
                    count_failure: mode.counts_failures(),
                    enrich,
                });
            }
        }
        // 一轮探活结果一次批量落库（单事务）；批量失败才退回逐条写，保持原有容错语义。
        if !pending.is_empty() {
            let rows: Vec<ProbeUpdateRow> = pending.iter().map(|p| p.row.clone()).collect();
            let outcomes: Vec<UpdateNodeProbeOutcome> = match self.db.update_node_probe_batch(&rows)
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "批量写入探活结果失败，退回逐条写入");
                    self.write_probe_rows_one_by_one(&rows)
                }
            };
            for (p, outcome) in pending.iter().zip(outcomes) {
                match outcome {
                    Some(fails) => {
                        if p.row.status == "online" {
                            let mut tracker = self.tracker.lock().unwrap();
                            tracker.clear_failure(&p.row.node_id);
                            if p.count_failure {
                                tracker.record(&p.row.node_id, true);
                            }
                            drop(tracker);
                            if let Some(value) = p.enrich.clone() {
                                to_enrich.push(value);
                            }
                        } else if p.count_failure {
                            let now = epoch_now();
                            let disable = {
                                let mut tracker = self.tracker.lock().unwrap();
                                tracker.record(&p.row.node_id, false);
                                tracker.note_failure(&p.row.node_id, now);
                                tracker.should_disable(&p.row.node_id, fails, now)
                            };
                            // try_disable 的 CAS 依赖刚写入的 consecutive_fails，
                            // 因此必须放在批量写之后。
                            if disable && self.try_disable(&p.row.node_id, &p.target, fails) {
                                out[p.out_idx]["status"] = json!("disabled");
                                need_rebuild = true;
                            }
                        }
                    }
                    None => {
                        // CAS 落空/落库失败：节点状态或 tag 在本轮内被改过，本轮结果作废。
                        out[p.out_idx]["status"] = json!("unknown");
                        out[p.out_idx]["error"] = json!(STALE_PROBE_HINT);
                    }
                }
            }
        }
        if need_rebuild {
            if let Err(e) = self.cfg.apply(None).await {
                tracing::warn!(error = %e, "探活结果应用配置失败");
            }
        }
        let _ = self.sync_relay_exits_after_probe(&out).await;
        for node in to_enrich {
            self.enricher.lazy_enrich(node);
        }
        out.extend(skipped);
        out
    }
}

/// 一轮探活里待落库的单条结果（FIX-B1：循环内只收集，循环后一次性批量写）。
struct PendingProbeWrite {
    /// 在 out 里的下标：落库后要按结果回填 status/error。
    out_idx: usize,
    row: ProbeUpdateRow,
    target: ProbeTargetNode,
    count_failure: bool,
    /// 探活成功时预取的 enrich 快照（最终仍是 online 才推入 to_enrich）。
    enrich: Option<Value>,
}

/// inflight 标志的 RAII 复位（含提前 return / panic 路径）。
struct InflightGuard<'a>(&'a AtomicBool);

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// 单节点探活（对齐 scheduler.py 的 _probe_one）。
pub async fn probe_one(
    clash: Arc<dyn ClashApi>,
    base: String,
    secret: Option<String>,
    url: String,
    node: ProbeTargetNode,
    mode: ProbeMode,
    retry_scale: f64,
) -> PingResultItem {
    let tag = crate::config_manager::outbound_tag(&node.protocol, node.port);
    let mut item = PingResultItem {
        id: node.id.clone(),
        tag: tag.clone(),
        ping: 0,
        status: "offline".to_string(),
        error: None,
    };
    let attempts = probe_attempts_for_node(mode, node.consecutive_fails);
    for attempt in 0..attempts {
        let backoff = probe_retry_backoff(attempt) * retry_scale;
        if backoff > 0.0 {
            tokio::time::sleep(Duration::from_secs_f64(backoff)).await;
        }
        let req = DelayRequest {
            base: base.clone(),
            secret: secret.clone(),
            tag: tag.clone(),
            url: url.clone(),
            timeout_ms: probe_delay_timeout_ms(attempt),
        };
        match clash.delay(req).await {
            DelayOutcome::Ok(delay) => {
                item.status = "online".to_string();
                item.ping = delay;
                item.error = None;
                return item;
            }
            DelayOutcome::Unknown(err) | DelayOutcome::Unreachable(err) => {
                // 内部错误与 clash API 不可达都不值得重试。
                item.status = "unknown".to_string();
                item.error = Some(err);
                return item;
            }
            DelayOutcome::Retry(msg) => {
                item.error = Some(msg);
            }
        }
    }
    item
}

impl crate::wire::Prober for ProbeEngine {
    fn probe(
        &self,
        ids: Option<Vec<String>>,
        all: bool,
        include_disabled: bool,
        manual: bool,
    ) -> crate::wire::BoxFut<'_, Vec<Value>> {
        Box::pin(async move { self.probe_inner(ids, all, include_disabled, manual).await })
    }

    fn fetch_exit_ip(&self, node: &Value) -> crate::wire::BoxFut<'_, Option<String>> {
        let fetcher = self.enricher.fetcher();
        let node = node.clone();
        Box::pin(async move { fetcher.fetch_exit_ip(node).await })
    }

    fn diagnose(&self, node: &Value) -> String {
        node_probe(node).diagnose()
    }
}

// ===========================================================================
// relay 出口同步与随机轮询（对齐 _sync_relay_exits_after_probe / _rotate_random_relay）
// ===========================================================================

/// relay 随机轮询的候选探活超时（毫秒，Python 里是字符串 "2000"）。
/// 随机轮询里并发探测候选的上限（FIX-B3）。
pub const RANDOM_ROTATE_CONCURRENCY: usize = 8;

/// 随机轮询整轮的探测预算（秒）：超预算就用已经拿到的存活结果（FIX-B3）。
pub const RANDOM_ROTATE_BUDGET: f64 = 30.0;

/// sync_relay_exits_after_probe 里并发拉取各 relay 当前出口的上限（FIX-B2）。
pub const RELAY_SYNC_CONCURRENCY: usize = 8;

pub const RANDOM_ROTATE_PROBE_TIMEOUT_MS: u64 = 2000;
/// relay 随机轮询最多试几个候选。
pub const RANDOM_ROTATE_CANDIDATES: usize = 10;
/// relay 随机轮询间隔下限（秒）。
pub const RANDOM_ROTATE_MIN_INTERVAL: f64 = 5.0;

/// 单个 relay 在一轮出口同步里的决策输入（FIX-B2：节点快照只读一次，全部内存过滤）。
struct RelaySyncPlan {
    /// 在 relays 里的下标，用于按 relay 原顺序执行切换。
    idx: usize,
    rd_tag: String,
    /// 粘滞期判定用的原始候选（刷新前）。
    raw_targets: Vec<String>,
    /// 刷新后（仍合法且仍属该分组）的候选，用于挑最优出口。
    fresh_targets: Vec<String>,
}

/// 一轮 relay 出口同步的结果。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelaySyncReport {
    /// 本轮为了比较延迟而临时补探的候选数。
    pub measured: usize,
    /// 真正切换的 relay 数。
    pub switched: usize,
}

/// relay 的分组选择器（Python 里 rd.groups or ["ALL"]）。
fn relay_groups(rd: &crate::types::RelayDomain) -> Vec<String> {
    if rd.groups.is_empty() {
        vec!["ALL".to_string()]
    } else {
        rd.groups.clone()
    }
}

/// 节点是否属于该 relay 的分组。
fn group_matches(rd: &crate::types::RelayDomain, node: &Node) -> bool {
    let groups = relay_groups(rd);
    if groups.iter().any(|g| g == "ALL") {
        return true;
    }
    match node.base.group.as_deref() {
        Some(g) => groups.iter().any(|s| s == g),
        None => false,
    }
}

impl ProbeEngine {
    /// 探活后按粘滞超时刷新 relay 出口（对齐 _sync_relay_exits_after_probe）。
    pub async fn sync_relay_exits_after_probe(&self, probe_results: &[Value]) -> RelaySyncReport {
        let mut report = RelaySyncReport::default();
        let settings = self.db.get_setting("system").unwrap_or_else(|_| json!({}));
        let sticky_enabled = crate::ipinfo::truthy(settings.get("stickyEnabled"));
        let sticky_sec =
            parse_sticky_timeout(settings.get("stickyTimeout").and_then(|v| v.as_str()));
        let test_url = normalize_test_url(settings.get("testUrl").and_then(|v| v.as_str()));
        let relays = match self.db.list_relay_domains() {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "读取 relay 列表失败，跳过出口同步");
                return report;
            }
        };
        // FIX-B5：switch_at 只增不减，删掉的 relay 会把陈旧记录一直留着。
        {
            let live: HashSet<&str> = relays.iter().map(|rd| rd.id.as_str()).collect();
            self.switch_at
                .lock()
                .unwrap()
                .retain(|relay_id, _| live.contains(relay_id.as_str()));
        }
        if relays.is_empty() {
            return report;
        }
        let base = self.cfg.clash_base();
        let secret = self.cfg.clash_secret();
        let mut node_by_tag: HashMap<String, Node> = HashMap::new();
        match self.db.list_nodes(None, None, None) {
            Ok(nodes) => {
                for n in nodes {
                    if n.base.status.as_deref() == Some("disabled") {
                        continue;
                    }
                    let tag = crate::config_manager::outbound_tag(
                        &n.base.protocol,
                        n.base.port.unwrap_or(0),
                    );
                    node_by_tag.insert(tag, n);
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "读取节点失败，跳过出口同步");
                return report;
            }
        }
        if node_by_tag.is_empty() {
            return report;
        }
        let mut delay: HashMap<String, Option<i64>> = HashMap::new();
        for r in probe_results {
            let Some(tag) = r.get("tag").and_then(|v| v.as_str()) else {
                continue;
            };
            if tag.is_empty() {
                continue;
            }
            let online = r.get("status").and_then(|v| v.as_str()) == Some("online");
            let ping = if online {
                r.get("ping").and_then(|v| v.as_i64())
            } else {
                None
            };
            delay.insert(tag.to_string(), ping);
        }
        // 本轮没探到、但确实被某个 relay 选中的节点，临时补探一次。
        let missing: Vec<String> = node_by_tag
            .iter()
            .filter(|(tag, node)| {
                !delay.contains_key(*tag) && relays.iter().any(|rd| group_matches(rd, node))
            })
            .map(|(tag, _)| tag.clone())
            .collect();
        if !missing.is_empty() {
            let generation = self.op.generation();
            let sem = Arc::new(Semaphore::new(PROBE_CONCURRENCY));
            let mut set = tokio::task::JoinSet::new();
            for tag in missing {
                let Some(node) = node_by_tag.get(&tag) else {
                    continue;
                };
                let target = ProbeTargetNode::new(
                    &node.id,
                    node.base.status.as_deref().unwrap_or(""),
                    node.base.disabled_auto.unwrap_or(false),
                    node.base.port.unwrap_or(0),
                    &node.base.protocol,
                )
                .with_fails(node.base.consecutive_fails.unwrap_or(0));
                let clash = self.clash.clone();
                let base = base.clone();
                let secret = secret.clone();
                let url = test_url.clone();
                let scale = self.retry_scale;
                let slot = sem.clone();
                set.spawn(async move {
                    let _permit = slot.acquire().await;
                    let item =
                        probe_one(clash, base, secret, url, target, ProbeMode::Manual, scale).await;
                    (tag, item)
                });
            }
            while let Some(joined) = set.join_next().await {
                if let Ok((tag, item)) = joined {
                    report.measured += 1;
                    let ping = if item.status == "online" {
                        Some(item.ping)
                    } else {
                        None
                    };
                    delay.insert(tag, ping);
                }
            }
            if !self.round_valid(generation) {
                return report;
            }
        }
        let generation = self.op.generation();
        // FIX-B2：候选集合全部基于本轮唯一一次节点快照在内存里算好，循环内不再读库。
        let mut plans: Vec<RelaySyncPlan> = Vec::new();
        for (idx, rd) in relays.iter().enumerate() {
            let rd_tag = format!("relay-auto-{}", rd.id);
            let raw_targets: Vec<String> = node_by_tag
                .iter()
                .filter(|(_, node)| group_matches(rd, node))
                .map(|(tag, _)| tag.clone())
                .collect();
            if raw_targets.is_empty() {
                continue;
            }
            // 快照里已过滤过 disabled，这里只需再看一眼分组归属。
            let fresh_targets = Self::latest_relay_targets(rd, &raw_targets, &node_by_tag);
            if fresh_targets.is_empty() {
                continue;
            }
            plans.push(RelaySyncPlan {
                idx,
                rd_tag,
                raw_targets,
                fresh_targets,
            });
        }
        // FIX-B2：各 relay 的当前出口有界并发拉取（串行时单个最长约 12s，R 个会叠加）。
        let sem = Arc::new(Semaphore::new(RELAY_SYNC_CONCURRENCY));
        let mut set = tokio::task::JoinSet::new();
        for (slot_idx, plan) in plans.iter().enumerate() {
            let clash = self.clash.clone();
            let base = base.clone();
            let secret = secret.clone();
            let rd_tag = plan.rd_tag.clone();
            let slot = sem.clone();
            set.spawn(async move {
                let _permit = slot.acquire().await;
                (slot_idx, clash.current(base, secret, rd_tag).await)
            });
        }
        let mut currents: Vec<Option<String>> = vec![None; plans.len()];
        while let Some(joined) = set.join_next().await {
            if let Ok((slot_idx, current)) = joined {
                currents[slot_idx] = current;
            }
        }
        // 决策与切换仍按 relay 原顺序执行，语义与串行版一致。
        for (slot_idx, plan) in plans.iter().enumerate() {
            let rd = &relays[plan.idx];
            let rd_tag = plan.rd_tag.clone();
            let current = currents[slot_idx].clone();
            if sticky_enabled {
                if let Some(cur) = current.as_deref() {
                    let in_targets = plan.raw_targets.iter().any(|t| t == cur);
                    let last = self
                        .switch_at
                        .lock()
                        .unwrap()
                        .get(&rd.id)
                        .copied()
                        .unwrap_or(0.0);
                    if in_targets && epoch_now() - last < sticky_sec {
                        // 粘滞期内不折腾：保持当前出口。
                        continue;
                    }
                }
            }
            if self.op.locked() || self.op.generation() != generation {
                return report;
            }
            let targets = &plan.fresh_targets;
            let mut best: Option<(String, i64)> = None;
            for tag in targets {
                if let Some(Some(d)) = delay.get(tag) {
                    if best.as_ref().map(|(_, bd)| d < bd).unwrap_or(true) {
                        best = Some((tag.clone(), *d));
                    }
                }
            }
            let Some((best_tag, best_delay)) = best else {
                tracing::info!(relay = %rd_tag, current = ?current, "候选全部不通，维持当前出口");
                continue;
            };
            if current.as_deref() == Some(best_tag.as_str()) {
                continue;
            }
            match self
                .clash
                .select(
                    base.clone(),
                    secret.clone(),
                    rd_tag.clone(),
                    best_tag.clone(),
                )
                .await
            {
                Ok(()) => {
                    self.switch_at
                        .lock()
                        .unwrap()
                        .insert(rd.id.clone(), epoch_now());
                    report.switched += 1;
                    tracing::info!(relay = %rd_tag, target = %best_tag, delay = best_delay, "relay 出口已切换");
                }
                Err(e) => tracing::warn!(relay = %rd_tag, error = %e, "relay 出口切换失败"),
            }
        }
        report
    }

    /// 用本轮已加载的节点快照过滤候选，只保留仍属于该 relay 分组的 tag。
    ///
    /// FIX-B2：原来每个 relay 都会重新全表 list_nodes（O(R×N)），改为接收内存快照。
    fn latest_relay_targets(
        rd: &crate::types::RelayDomain,
        targets: &[String],
        fresh: &HashMap<String, Node>,
    ) -> Vec<String> {
        targets
            .iter()
            .filter(|t| fresh.get(*t).map(|n| group_matches(rd, n)).unwrap_or(false))
            .cloned()
            .collect()
    }

    /// 手动/定时随机轮询 relay 出口（对齐 _rotate_random_relay）。
    /// 返回本次选中的节点 tag（对齐 Python 的 randomRotateCurrent）。
    pub async fn rotate_random_relay(&self) -> Option<String> {
        self.rotate_random_relay_with(RANDOM_ROTATE_CONCURRENCY, RANDOM_ROTATE_BUDGET)
            .await
    }

    /// rotate 的实现体：并发上限与探测预算可注入（测试用很小的常量收紧）。
    async fn rotate_random_relay_with(
        &self,
        concurrency: usize,
        budget_secs: f64,
    ) -> Option<String> {
        let nodes = match self.db.list_nodes(None, None, None) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "轮询读取节点失败");
                return None;
            }
        };
        let pool: Vec<Node> = nodes
            .into_iter()
            .filter(|n| n.base.status.as_deref() != Some("disabled"))
            .collect();
        if pool.is_empty() {
            return None;
        }
        let online: Vec<Node> = pool
            .iter()
            .filter(|n| n.base.status.as_deref() == Some("online"))
            .cloned()
            .collect();
        let candidates_pool: Vec<Node> = if online.is_empty() {
            pool.clone()
        } else {
            online
        };
        let settings = self.db.get_setting("system").unwrap_or_else(|_| json!({}));
        let test_url = normalize_test_url(settings.get("testUrl").and_then(|v| v.as_str()));
        let relays = self.db.list_relay_domains().unwrap_or_default();
        let base = self.cfg.clash_base();
        let secret = self.cfg.clash_secret();
        // 整轮共用一份探测预算：超预算就直接用已经拿到的存活结果。
        let deadline = tokio::time::Instant::now() + Duration::from_secs_f64(budget_secs.max(0.0));
        // 全局段：洗牌取前 RANDOM_ROTATE_CANDIDATES 个后批量并发探测，
        // 仍按原顺序取第一个存活的（与串行 break 的语义一致）。
        let global_tags: Vec<String> = shuffled(&candidates_pool)
            .iter()
            .take(RANDOM_ROTATE_CANDIDATES)
            .map(|n| {
                crate::config_manager::outbound_tag(&n.base.protocol, n.base.port.unwrap_or(0))
            })
            .collect();
        let global_alive = self
            .probe_alive_batch(
                &global_tags,
                &AliveProbeCtx {
                    base: &base,
                    secret: &secret,
                    url: &test_url,
                    timeout_ms: RANDOM_ROTATE_PROBE_TIMEOUT_MS,
                    concurrency,
                    deadline,
                },
            )
            .await;
        let chosen = global_tags
            .into_iter()
            .zip(global_alive)
            .find(|(_, alive)| *alive)
            .map(|(tag, _)| tag);
        let Some(chosen_tag) = chosen else {
            tracing::info!("随机轮询没有任何可用候选，保持当前出口");
            return None;
        };
        // per-relay 段：先把每个 relay 的候选算好，再把所有候选去重后一次性批量并发探测；
        // 每个 relay 仍按自己的候选顺序取第一个存活的，否则回退全局 chosen_tag。
        let mut relay_cands: Vec<(String, Vec<String>)> = Vec::new();
        let mut all_tags: Vec<String> = Vec::new();
        for rd in &relays {
            let rd_tag = format!("relay-auto-{}", rd.id);
            let tags: Vec<String> = candidates_pool
                .iter()
                .filter(|n| group_matches(rd, n))
                .map(|n| {
                    crate::config_manager::outbound_tag(&n.base.protocol, n.base.port.unwrap_or(0))
                })
                .collect();
            let cands: Vec<String> = shuffled(&tags)
                .into_iter()
                .take(RANDOM_ROTATE_CANDIDATES)
                .collect();
            for tag in &cands {
                if !all_tags.iter().any(|t| t == tag) {
                    all_tags.push(tag.clone());
                }
            }
            relay_cands.push((rd_tag, cands));
        }
        let alive = self
            .probe_alive_batch(
                &all_tags,
                &AliveProbeCtx {
                    base: &base,
                    secret: &secret,
                    url: &test_url,
                    timeout_ms: RANDOM_ROTATE_PROBE_TIMEOUT_MS,
                    concurrency,
                    deadline,
                },
            )
            .await;
        let alive: HashMap<String, bool> = all_tags.into_iter().zip(alive).collect();
        for (rd_tag, cands) in relay_cands {
            let mut target = chosen_tag.clone();
            for tag in &cands {
                if alive.get(tag).copied().unwrap_or(false) {
                    target = tag.clone();
                    break;
                }
            }
            if let Err(e) = self
                .clash
                .select(base.clone(), secret.clone(), rd_tag.clone(), target.clone())
                .await
            {
                tracing::warn!(relay = %rd_tag, error = %e, "随机轮询切换失败");
            }
        }
        let mut settings = settings;
        if let Some(obj) = settings.as_object_mut() {
            obj.insert("randomRotateCurrent".to_string(), json!(chosen_tag));
        }
        if let Err(e) = self.db.set_setting("system", &settings) {
            tracing::warn!(error = %e, "写入 randomRotateCurrent 失败");
        }
        Some(chosen_tag)
    }

    /// 批量探测一批候选是否活着（对齐 _is_alive：只看 delay 是否返回有效值）。
    ///
    /// FIX-B3：有界并发（concurrency）+ 整轮共享 deadline；超预算的候选直接算不活，
    /// 调用方据此使用已经拿到的存活结果。
    async fn probe_alive_batch(&self, tags: &[String], ctx: &AliveProbeCtx<'_>) -> Vec<bool> {
        let mut out = vec![false; tags.len()];
        if tags.is_empty() {
            return out;
        }
        let deadline = ctx.deadline;
        let timeout_ms = ctx.timeout_ms;
        let sem = Arc::new(Semaphore::new(ctx.concurrency.max(1)));
        let mut set = tokio::task::JoinSet::new();
        for (idx, tag) in tags.iter().enumerate() {
            let clash = self.clash.clone();
            let req = DelayRequest {
                base: ctx.base.to_string(),
                secret: ctx.secret.clone(),
                tag: tag.clone(),
                url: ctx.url.to_string(),
                timeout_ms,
            };
            let slot = sem.clone();
            set.spawn(async move {
                if tokio::time::Instant::now() >= deadline {
                    return (idx, false);
                }
                let Ok(_permit) = slot.acquire().await else {
                    return (idx, false);
                };
                if tokio::time::Instant::now() >= deadline {
                    return (idx, false);
                }
                let outcome = tokio::time::timeout_at(deadline, clash.delay(req)).await;
                (idx, matches!(outcome, Ok(DelayOutcome::Ok(_))))
            });
        }
        while let Some(joined) = set.join_next().await {
            if let Ok((idx, alive)) = joined {
                out[idx] = alive;
            }
        }
        out
    }
}

/// 批量探活的公共参数：把固定 6 项收成一个上下文，避免参数过多的告警。
struct AliveProbeCtx<'a> {
    base: &'a str,
    secret: &'a Option<String>,
    url: &'a str,
    timeout_ms: u64,
    concurrency: usize,
    deadline: tokio::time::Instant,
}

/// 洗牌（Python 的 random.shuffle）；用 rand::seq::SliceRandom 保持同一语义。
fn shuffled<T: Clone>(items: &[T]) -> Vec<T> {
    use rand::seq::SliceRandom;
    let mut out = items.to_vec();
    let mut rng = rand::thread_rng();
    out.shuffle(&mut rng);
    out
}

// ===========================================================================
// 后台循环（每个都可被 Notify 优雅打断）
// ===========================================================================

/// 出口情报兜底扫荡间隔（秒）。Python 没有这个 loop，补查只靠探活成功后触发，
/// 进程重启后历史节点会长期缺情报，所以这里补一个低频扫荡。
pub const ENRICH_SWEEP_INTERVAL: f64 = 300.0;

/// 睡 secs 秒；返回 false 表示收到停止信号。
pub async fn sleep_or_stop(stop: &tokio::sync::Notify, secs: f64) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs_f64(secs.max(0.0))) => true,
        _ = stop.notified() => false,
    }
}

/// 对应 scheduler.py 的 _probe_loop：按 probeInterval 周期批量探活（不计失败）。
pub async fn probe_loop(engine: Arc<ProbeEngine>, stop: Arc<tokio::sync::Notify>) {
    loop {
        let settings = engine
            .db()
            .get_setting("system")
            .unwrap_or_else(|_| json!({}));
        let interval = probe_interval(settings.get("probeInterval").and_then(|v| v.as_i64()));
        if !sleep_or_stop(&stop, interval).await {
            return;
        }
        if !engine.cfg().is_running() {
            continue;
        }
        let results =
            <ProbeEngine as crate::wire::Prober>::probe(&engine, None, true, false, false).await;
        let has_offline = results
            .iter()
            .any(|r| r.get("status").and_then(|v| v.as_str()) == Some("offline"));
        if has_offline && engine.op().locked() {
            // 配置正在重载，给 sing-box 一点稳定期再继续。
            if !sleep_or_stop(&stop, GUARD_INTERVAL).await {
                return;
            }
        }
    }
}

/// 对应 scheduler.py 的 _disabled_revive_loop：周期性重试自动停用节点。
pub async fn revive_loop(engine: Arc<ProbeEngine>, stop: Arc<tokio::sync::Notify>) {
    loop {
        if !sleep_or_stop(&stop, REVIVE_INTERVAL).await {
            return;
        }
        if !engine.cfg().is_running() || engine.op().locked() {
            continue;
        }
        let nodes = match engine.db().list_nodes(None, None, None) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let ids: Vec<String> = nodes
            .iter()
            .filter(|n| n.base.status.as_deref() == Some("disabled"))
            .filter(|n| n.base.disabled_auto.unwrap_or(false))
            .map(|n| n.id.clone())
            .collect();
        if ids.is_empty() {
            continue;
        }
        let results =
            <ProbeEngine as crate::wire::Prober>::probe(&engine, Some(ids), false, true, false)
                .await;
        let revived = results
            .iter()
            .filter(|r| r.get("status").and_then(|v| v.as_str()) == Some("online"))
            .count();
        if revived > 0 {
            tracing::info!(revived, "自动停用节点已复活");
        }
    }
}

/// 对应 scheduler.py 的 _relay_random_loop：按 randomRotateInterval 随机轮询 relay 出口。
pub async fn relay_rotate_loop(engine: Arc<ProbeEngine>, stop: Arc<tokio::sync::Notify>) {
    loop {
        let settings = engine
            .db()
            .get_setting("system")
            .unwrap_or_else(|_| json!({}));
        let raw = settings
            .get("randomRotateInterval")
            .and_then(|v| v.as_i64())
            .map(|v| v as f64)
            .unwrap_or(RANDOM_ROTATE_DEFAULT_INTERVAL);
        let interval = raw.max(RANDOM_ROTATE_MIN_INTERVAL);
        if !sleep_or_stop(&stop, interval).await {
            return;
        }
        let settings = engine
            .db()
            .get_setting("system")
            .unwrap_or_else(|_| json!({}));
        if !crate::ipinfo::truthy(settings.get("randomRotateEnabled")) {
            continue;
        }
        let _ = engine.rotate_random_relay().await;
    }
}

/// Rust 侧新增的兜底扫荡（Python 无对应函数）：把缺情报的节点补一遍。
pub async fn enrich_loop(engine: Arc<ProbeEngine>, stop: Arc<tokio::sync::Notify>) {
    loop {
        if !sleep_or_stop(&stop, ENRICH_SWEEP_INTERVAL).await {
            return;
        }
        if !engine.cfg().is_running() || engine.op().locked() {
            continue;
        }
        enrich_sweep(&engine).await;
    }
}

/// 一轮补充查（FIX-B4）：有界并发（ENRICH_CONCURRENCY），不再逐节点串行 await。
///
/// 每个节点仍然先过 Enricher::plan：冷却期内 / 已有在飞补查都会被跳过，
/// 且 Run 已经登记 pending，所以任务里直接走 enrich_planned（不会二次 plan 变成 InFlight）。
pub async fn enrich_sweep(engine: &Arc<ProbeEngine>) {
    let nodes = match engine.db().list_nodes(None, None, None) {
        Ok(v) => v,
        Err(_) => return,
    };
    let mut pending: Vec<Value> = Vec::new();
    for node in nodes {
        if node.base.status.as_deref() == Some("disabled") {
            continue;
        }
        let Ok(value) = serde_json::to_value(&node) else {
            continue;
        };
        let intel = NodeIntel::from_json(&value);
        if intel.has_full_intel() {
            continue;
        }
        let now = epoch_now();
        if !matches!(engine.enricher().plan(&value, now), EnrichPlan::Run { .. }) {
            continue;
        }
        pending.push(value);
    }
    if pending.is_empty() {
        return;
    }
    let enricher = engine.enricher().clone();
    let sem = Arc::new(Semaphore::new(ENRICH_CONCURRENCY));
    let mut set = tokio::task::JoinSet::new();
    for value in pending {
        let enricher = enricher.clone();
        let slot = sem.clone();
        set.spawn(async move {
            let _permit = slot.acquire().await;
            enricher.enrich_planned(value).await;
        });
    }
    while set.join_next().await.is_some() {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering as AtomicOrdering};

    // ---------- 崩溃守护 ----------

    #[derive(Default)]
    struct FakeHost {
        proc_present: AtomicBool,
        running: AtomicBool,
        fd_error: AtomicBool,
        fds: AtomicI64,
        starts: AtomicUsize,
        stops: AtomicUsize,
        start_ok: AtomicBool,
    }

    impl FakeHost {
        fn new(proc_present: bool, running: bool) -> Arc<Self> {
            let host = FakeHost::default();
            host.proc_present
                .store(proc_present, AtomicOrdering::SeqCst);
            host.running.store(running, AtomicOrdering::SeqCst);
            host.fds.store(20, AtomicOrdering::SeqCst);
            host.start_ok.store(true, AtomicOrdering::SeqCst);
            Arc::new(host)
        }

        fn starts(&self) -> usize {
            self.starts.load(AtomicOrdering::SeqCst)
        }

        fn stops(&self) -> usize {
            self.stops.load(AtomicOrdering::SeqCst)
        }
    }

    impl GuardHost for FakeHost {
        fn proc_present(&self) -> bool {
            self.proc_present.load(AtomicOrdering::SeqCst)
        }

        fn is_running(&self) -> bool {
            self.running.load(AtomicOrdering::SeqCst)
        }

        fn fd_count(&self) -> Result<u64, String> {
            if self.fd_error.load(AtomicOrdering::SeqCst) {
                return Err("/proc 不可读".into());
            }
            Ok(self.fds.load(AtomicOrdering::SeqCst).max(0) as u64)
        }

        fn start(&self) -> BoxFuture<'_, bool> {
            self.starts.fetch_add(1, AtomicOrdering::SeqCst);
            let ok = self.start_ok.load(AtomicOrdering::SeqCst);
            // 只有启动成功才真正进入 running；失败场景用于复现「进程一直起不来」
            if ok {
                self.running.store(true, AtomicOrdering::SeqCst);
            }
            Box::pin(async move { ok })
        }

        fn stop(&self) -> BoxFuture<'_, ()> {
            self.stops.fetch_add(1, AtomicOrdering::SeqCst);
            self.running.store(false, AtomicOrdering::SeqCst);
            Box::pin(async {})
        }
    }

    /// 历史事故回归：冷却期内不得续期，冷却过期后必须恢复重启。
    #[tokio::test]
    async fn guard_cooldown_expires_and_restarts_again() {
        let host = FakeHost::new(true, false);
        host.start_ok.store(false, AtomicOrdering::SeqCst);
        let cfg = GuardConfig::new(0.01, 0.05, 3);
        let task = tokio::spawn(guard_loop(host.clone(), cfg));
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        task.abort();
        let _ = task.await;
        // 旧实现（判断前无条件 append）在 0.05s 窗口内恒满 → 全程只有 3 次。
        assert!(
            host.starts() > 6,
            "冷却结束后未能恢复重启，实际只有 {} 次",
            host.starts()
        );
    }

    /// 进程对象不存在（手动停止 / 从未启动）时守护不得干预。
    #[tokio::test]
    async fn guard_never_restarts_when_process_absent() {
        let host = FakeHost::new(false, false);
        let cfg = GuardConfig::new(0.01, 0.05, 3);
        let task = tokio::spawn(guard_loop(host.clone(), cfg));
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        task.abort();
        let _ = task.await;
        assert_eq!(host.starts(), 0, "进程未启动时守护不应干预");
        assert_eq!(host.stops(), 0);
    }

    /// 冷却期内反复巡检不能登记时间戳（否则冷却自我续期，正是事故根因）。
    #[test]
    fn cooldown_polls_do_not_extend_restart_window() {
        let mut core = GuardCore::new(GuardConfig::new(10.0, 60.0, 3));
        assert!(core.request_restart(0.0));
        assert!(core.request_restart(10.0));
        assert!(core.request_restart(20.0));
        assert!(!core.request_restart(30.0), "第 4 次必须进入冷却");
        assert!(core.paused());
        for t in [35.0, 40.0, 45.0, 50.0, 55.0, 59.0] {
            assert!(!core.request_restart(t), "t={t} 仍在 60s 窗口内，不得重启");
        }
        assert_eq!(
            core.restart_times().len(),
            3,
            "冷却期间的巡检不得续期时间戳"
        );
        assert_eq!(
            core.restart_times(),
            &[0.0, 10.0, 20.0],
            "时间戳必须保持原值"
        );
        // 最早那一条滑出 60s 窗口 → 必须恢复重启（旧实现会永久卡死在这里）
        assert!(core.request_restart(60.0), "冷却窗口滑过后必须恢复重启");
        assert!(!core.paused());
        assert_eq!(core.restart_times(), &[10.0, 20.0, 60.0]);
    }

    /// 恢复运行后清空历史、解除冷却。
    #[test]
    fn running_clears_restart_history_and_pause() {
        let mut core = GuardCore::new(GuardConfig::default());
        core.request_restart(0.0);
        core.request_restart(1.0);
        core.request_restart(2.0);
        assert!(!core.request_restart(3.0));
        assert!(core.paused());
        assert!(core.note_running(), "此前应在冷却态");
        assert!(!core.paused());
        assert!(core.restart_times().is_empty());
    }

    #[tokio::test]
    async fn guard_tick_reports_states() {
        let absent = FakeHost::new(false, false);
        let mut core = GuardCore::new(GuardConfig::default());
        let mut wd = FdWatchdog::default();
        assert_eq!(
            guard_tick(&*absent, &mut core, &mut wd, 1000.0).await,
            GuardTick::Absent
        );

        let alive = FakeHost::new(true, true);
        assert_eq!(
            guard_tick(&*alive, &mut core, &mut wd, 1000.0).await,
            GuardTick::Healthy { recycled: false }
        );

        let dead = FakeHost::new(true, false);
        dead.start_ok.store(false, AtomicOrdering::SeqCst);
        let mut core2 = GuardCore::new(GuardConfig::new(10.0, 60.0, 1));
        let mut wd2 = FdWatchdog::default();
        assert_eq!(
            guard_tick(&*dead, &mut core2, &mut wd2, 1000.0).await,
            GuardTick::Restarted
        );
        assert_eq!(
            guard_tick(&*dead, &mut core2, &mut wd2, 1001.0).await,
            GuardTick::Cooldown
        );
        assert_eq!(dead.starts(), 1);
    }

    // ---------- fd 泄漏看门狗 ----------

    #[tokio::test]
    async fn fd_leak_triggers_recycle() {
        let host = FakeHost::new(true, true);
        host.fds.store(1875, AtomicOrdering::SeqCst);
        let mut wd = FdWatchdog::new(100, 300.0);
        assert!(recycle_if_fd_leak(&*host, &mut wd, 1000.0).await);
        assert_eq!(host.stops(), 1);
        assert_eq!(host.starts(), 1);
        assert_eq!(wd.last_restart_at(), 1000.0);
    }

    #[tokio::test]
    async fn fd_under_limit_does_not_recycle() {
        let host = FakeHost::new(true, true);
        host.fds.store(20, AtomicOrdering::SeqCst);
        let mut wd = FdWatchdog::new(1200, 300.0);
        assert!(!recycle_if_fd_leak(&*host, &mut wd, 1000.0).await);
        assert_eq!(host.stops(), 0);
        assert_eq!(host.starts(), 0);
    }

    #[tokio::test]
    async fn fd_cooldown_prevents_restart_loop() {
        let host = FakeHost::new(true, true);
        host.fds.store(5000, AtomicOrdering::SeqCst);
        let mut wd = FdWatchdog::new(100, 300.0);
        assert!(recycle_if_fd_leak(&*host, &mut wd, 1000.0).await);
        // 泄漏没修好：下一轮仍看到 5000 个 fd，冷却期内必须忍住
        assert!(!recycle_if_fd_leak(&*host, &mut wd, 1100.0).await);
        assert_eq!(host.stops(), 1);
        assert_eq!(host.starts(), 1);
        // 冷却过期后允许再回收
        assert!(recycle_if_fd_leak(&*host, &mut wd, 1300.0).await);
        assert_eq!(host.stops(), 2);
    }

    #[tokio::test]
    async fn fd_counter_failure_does_not_break_guard() {
        let host = FakeHost::new(true, true);
        host.fd_error.store(true, AtomicOrdering::SeqCst);
        let mut wd = FdWatchdog::new(100, 300.0);
        assert!(!recycle_if_fd_leak(&*host, &mut wd, 1000.0).await);
        assert_eq!(host.stops(), 0);
        let mut core = GuardCore::new(GuardConfig::default());
        assert_eq!(
            guard_tick(&*host, &mut core, &mut wd, 1000.0).await,
            GuardTick::Healthy { recycled: false }
        );
    }

    // ---------- 自动停用 ----------

    #[test]
    fn short_interval_cannot_disable_before_twenty_minutes() {
        let mut tracker = ProbeTracker::new();
        let mut fails: i64 = 0;
        let mut disabled_at = None;
        // 10s 一轮、连败 20 次只过去约 200s，远不到 20 分钟
        for i in 0..=120 {
            let now = 10_000.0 + (i as f64) * 10.0;
            fails += 1;
            tracker.record("n", false);
            tracker.note_failure("n", now);
            if tracker.should_disable("n", fails, now) {
                disabled_at = Some(now);
                break;
            }
        }
        let at = disabled_at.expect("20 分钟持续失败后应当停用");
        assert!(
            at - 10_000.0 >= MIN_FAILURE_SECONDS,
            "停用时间点必须满足 20 分钟下限，实际 {}s",
            at - 10_000.0
        );
    }

    #[test]
    fn incomplete_window_and_restart_history_are_not_punished() {
        let mut tracker = ProbeTracker::new();
        for _ in 0..28 {
            tracker.record("n", false);
        }
        let now = 10_000.0;
        tracker.note_failure("n", now - 1300.0);
        tracker.record("n", false);
        assert_eq!(tracker.window_rate("n"), (29, 0.0));
        assert!(
            !tracker.should_disable("n", 20, now),
            "窗口未填满 30 次不得停用"
        );

        // 重启后历史被清（只剩 1 条）→ 依旧不罚
        tracker.reset("n");
        tracker.record("n", false);
        assert!(!tracker.should_disable("n", 20, now));
    }

    #[test]
    fn low_window_rate_alone_does_not_disable() {
        let mut tracker = ProbeTracker::new();
        for _ in 0..30 {
            tracker.record("n", false);
        }
        let now = 10_000.0;
        tracker.note_failure("n", now - 1300.0);
        assert!(!tracker.should_disable("n", 1, now), "连败次数不足不得停用");
        assert!(tracker.should_disable("n", 20, now), "四项条件齐了才停用");
    }

    #[test]
    fn changed_tag_drops_old_failure_elapsed_and_window() {
        let mut tracker = ProbeTracker::new();
        for _ in 0..30 {
            tracker.record("n", false);
        }
        let now = 10_000.0;
        tracker.note_failure("n", now - 1300.0);
        assert!(
            !tracker.observe_tag("n", 52001, "socks"),
            "首次观测不算变更"
        );
        assert!(
            tracker.observe_tag("n", 53001, "socks"),
            "端口变更必须判定为 tag 变更"
        );
        assert_eq!(tracker.hist_len("n"), 0);
        assert_eq!(tracker.failure_since("n"), None);
        tracker.record("n", false);
        tracker.note_failure("n", now);
        assert_eq!(tracker.hist_snapshot("n"), vec![false]);
        assert_eq!(tracker.failure_since("n"), Some(now));
        assert!(
            !tracker.should_disable("n", 20, now),
            "重启后的观测不能背旧账"
        );
    }

    #[test]
    fn disable_requires_matching_cas_snapshot() {
        let current = NodeProbeSnapshot {
            status: "offline".into(),
            consecutive_fails: 20,
            port: 52001,
            protocol: "socks".into(),
        };
        assert!(disable_cas_ok(&current, 52001, "socks", 20));
        assert!(!disable_cas_ok(&current, 52001, "socks", 19), "连败已变");
        let enabled = NodeProbeSnapshot {
            status: "online".into(),
            ..current.clone()
        };
        assert!(!disable_cas_ok(&enabled, 52001, "socks", 20), "用户已启用");
        let moved = NodeProbeSnapshot {
            port: 53001,
            ..current.clone()
        };
        assert!(!disable_cas_ok(&moved, 52001, "socks", 20), "用户已改端口");
    }

    #[test]
    fn probe_tracker_prune_clears_stale_entries_in_all_maps() {
        let mut tracker = ProbeTracker::new();
        for i in 0..1000 {
            let id = format!("n{i}");
            tracker.record(&id, true);
            tracker.note_failure(&id, 1.0);
            tracker.observe_tag(&id, 52001, "shadowsocks");
        }
        assert_eq!(tracker.hist.len(), 1000);
        assert_eq!(tracker.failure_since.len(), 1000);
        assert_eq!(tracker.tags.len(), 1000);

        // 只有 n999 被删：差值 1 远小于旧的 500 阈值，也必须立刻清掉（旧实现会整轮跳过）
        let valid999: HashSet<String> = (0..999).map(|i| format!("n{i}")).collect();
        tracker.prune(&valid999);
        assert_eq!(tracker.hist.len(), 999, "hist 必须清掉已删节点");
        assert_eq!(
            tracker.failure_since.len(),
            999,
            "failure_since 必须同步清理"
        );
        assert_eq!(tracker.tags.len(), 999, "tags 必须同步清理");
        assert_eq!(tracker.hist_len("n0"), 1, "存活节点的滑窗必须保留");
        assert_eq!(tracker.failure_since("n0"), Some(1.0));
        assert_eq!(
            tracker.tag_of("n0"),
            Some((52001, "shadowsocks".to_string()))
        );
        assert_eq!(tracker.tag_of("n999"), None);
        assert_eq!(tracker.failure_since("n999"), None);

        // 只剩 1 个有效节点：三个 map 都应收敛到 1 条
        let valid1: HashSet<String> = std::iter::once("n0".to_string()).collect();
        tracker.prune(&valid1);
        assert_eq!(tracker.hist.len(), 1);
        assert_eq!(tracker.failure_since.len(), 1);
        assert_eq!(tracker.tags.len(), 1);
        assert_eq!(tracker.hist_len("n0"), 1);
        assert_eq!(tracker.hist_len("n1"), 0);

        // 空 valid（节点全删）：三个 map 都清空
        tracker.prune(&HashSet::new());
        assert!(tracker.hist.is_empty());
        assert!(tracker.failure_since.is_empty());
        assert!(tracker.tags.is_empty());
    }

    // ---------- 探活参数 ----------

    #[test]
    fn probe_attempt_and_timeout_budget() {
        assert_eq!(probe_attempts(ProbeMode::Manual), 3);
        assert_eq!(probe_attempts(ProbeMode::Background), 4);
        assert_eq!(probe_delay_timeout_ms(0), PROBE_TIMEOUT_MS);
        assert_eq!(probe_delay_timeout_ms(2), PROBE_TIMEOUT_MS);
        assert_eq!(probe_delay_timeout_ms(3), PROBE_CONFIRM_TIMEOUT_MS);
        assert_eq!(probe_retry_backoff(0), 0.0);
        assert_eq!(probe_retry_backoff(1), 0.5);
        assert_eq!(probe_retry_backoff(2), 1.0);
        assert_eq!(probe_retry_backoff(3), 1.0);
        assert_eq!(ProbeMode::Manual.concurrency(), 32);
        assert_eq!(ProbeMode::Background.concurrency(), 16);
        assert!(!ProbeMode::Manual.counts_failures());
        assert!(ProbeMode::Background.counts_failures());
        assert_eq!(
            effective_probe_mode(ProbeMode::Manual, "disabled"),
            ProbeMode::Background
        );
        assert_eq!(
            effective_probe_mode(ProbeMode::Manual, "online"),
            ProbeMode::Manual
        );
    }

    #[test]
    fn probe_interval_and_test_url_normalization() {
        assert_eq!(probe_interval(None), PING_INTERVAL);
        assert_eq!(probe_interval(Some(1)), MIN_PROBE_INTERVAL);
        assert_eq!(probe_interval(Some(120)), 120.0);
        assert_eq!(normalize_test_url(Some("http://a.com")), DEFAULT_TEST_URL);
        assert_eq!(normalize_test_url(None), DEFAULT_TEST_URL);
        assert_eq!(
            normalize_test_url(Some(" https://a.com/x ")),
            "https://a.com/x"
        );
    }

    #[test]
    fn sticky_timeout_parsing() {
        assert_eq!(parse_sticky_timeout(Some("30s")), 30.0);
        assert_eq!(parse_sticky_timeout(Some("5m")), 300.0);
        assert_eq!(parse_sticky_timeout(Some("10m")), 600.0);
        assert_eq!(parse_sticky_timeout(Some("1h")), 3600.0);
        assert_eq!(
            parse_sticky_timeout(Some("garbage")),
            DEFAULT_STICKY_SECONDS
        );
        assert_eq!(parse_sticky_timeout(None), DEFAULT_STICKY_SECONDS);
        assert_eq!(
            parse_sticky_timeout(Some("1s")),
            MIN_STICKY_SECONDS,
            "不得小于 5s"
        );
    }

    #[test]
    fn manual_disabled_node_is_skipped_not_temporarily_enabled() {
        let nodes = vec![
            ProbeTargetNode::new("live", "online", false, 52001, "socks"),
            ProbeTargetNode::new("auto", "disabled", true, 52002, "socks"),
            ProbeTargetNode::new("manual", "disabled", false, 52003, "socks"),
        ];
        let sel = select_probe_targets(&nodes, true, None);
        let ids: Vec<&str> = sel.targets.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["live", "auto"],
            "自动停用可复查，手动停用不得临时启用"
        );
        assert_eq!(sel.skipped.len(), 1);
        assert_eq!(sel.skipped[0].id, "manual");
        assert_eq!(sel.skipped[0].status, "disabled");
        assert!(sel.skipped[0].error.contains("先启用"));

        let only: HashSet<String> = ["manual".to_string()].into_iter().collect();
        let narrowed = select_probe_targets(&nodes, true, Some(&only));
        assert!(narrowed.targets.is_empty());
        assert_eq!(narrowed.skipped.len(), 1);

        let no_disabled = select_probe_targets(&nodes, false, None);
        assert_eq!(no_disabled.targets.len(), 1);
        assert!(no_disabled.skipped.is_empty());
    }

    // ---------- 出口 IP 情报补查 ----------

    #[test]
    fn full_intel_and_entry_host_extraction() {
        assert!(has_full_intel(Some("HK"), Some("business"), Some(10)));
        assert!(!has_full_intel(Some("HK"), Some("business"), None));
        assert!(!has_full_intel(Some("  "), Some("business"), Some(1)));
        assert!(!has_full_intel(None, Some("business"), Some(1)));

        let raw = json!({"server": " hk.lsp121.eu.org ", "server_port": 39955});
        assert_eq!(entry_host(&raw), "hk.lsp121.eu.org");
        assert_eq!(entry_host(&json!({"address": "1.2.3.4"})), "1.2.3.4");
        assert_eq!(entry_host(&json!({})), "");
        assert_eq!(entry_host(&json!({"server": ""})), "");
    }

    #[test]
    fn usable_exit_ip_rejects_placeholders_and_hostnames() {
        assert_eq!(
            usable_exit_ip(Some("203.0.113.7")),
            Some("203.0.113.7".into())
        );
        assert_eq!(usable_exit_ip(Some(" N/A ")), None);
        assert_eq!(usable_exit_ip(Some("1.1.1.1")), None);
        assert_eq!(usable_exit_ip(Some("")), None);
        assert_eq!(usable_exit_ip(None), None);
        assert_eq!(usable_exit_ip(Some("rooster465.autos")), None);
    }

    /// 历史脏数据：server 是域名且 exitIp 恰等于该域名解析 IP → 必须重探。
    #[test]
    fn historical_entry_ip_is_detected_as_dirty() {
        let host = "hk.lsp121.eu.org";
        assert!(is_historical_entry_ip(
            "154.83.85.63",
            host,
            Some("154.83.85.63")
        ));
        // 解析失败时无法判定 → 按干净处理
        assert!(!is_historical_entry_ip("154.83.85.63", host, None));
        // 解析得到的 IP 与 exitIp 不同 → 不是脏数据
        assert!(!is_historical_entry_ip(
            "223.19.34.101",
            host,
            Some("154.83.85.63")
        ));
        // 入口本身就是 IP → 不存在这类脏数据
        assert!(!is_historical_entry_ip(
            "1.2.3.4",
            "1.2.3.4",
            Some("1.2.3.4")
        ));
    }

    #[test]
    fn enrich_plan_handles_dirty_history_and_cooldown() {
        let mut gate = EnrichGate::new(ENRICH_COOLDOWN, ENRICH_LRU_CAP, ENRICH_LRU_EVICT);
        let dirty = NodeIntel {
            exit_ip: Some("154.83.85.63".into()),
            exit_country: Some("HK".into()),
            exit_type: Some("business".into()),
            exit_risk: Some(10),
            entry_host: "hk.lsp121.eu.org".into(),
        };
        // 情报齐全但入口是域名 → 仍要校验是否脏
        assert_eq!(
            gate.plan("n", &dirty, 1_000.0),
            EnrichPlan::Run {
                fetch_exit_ip: false,
                dirty_risk: true
            }
        );
        assert!(gate.is_pending("n"));
        assert_eq!(gate.plan("n", &dirty, 1_000.0), EnrichPlan::InFlight);

        gate.finish("n", 1_000.0);
        assert!(!gate.is_pending("n"));
        // 冷却期内不再查
        assert_eq!(gate.plan("n", &dirty, 1_100.0), EnrichPlan::Cooling);
        // 冷却过期后允许复查
        assert_eq!(
            gate.plan("n", &dirty, 1_400.0),
            EnrichPlan::Run {
                fetch_exit_ip: false,
                dirty_risk: true
            }
        );
    }

    #[test]
    fn enrich_skips_clean_full_intel_and_fetches_when_missing_ip() {
        let mut gate = EnrichGate::default();
        let clean = NodeIntel {
            exit_ip: Some("203.0.113.7".into()),
            exit_country: Some("JP".into()),
            exit_type: Some("hosting".into()),
            exit_risk: Some(3),
            entry_host: "203.0.113.7".into(),
        };
        assert_eq!(gate.plan("clean", &clean, 1_000.0), EnrichPlan::Skip);
        assert!(!gate.is_pending("clean"));

        let missing = NodeIntel {
            exit_ip: None,
            exit_country: None,
            exit_type: None,
            exit_risk: None,
            entry_host: "203.0.113.7".into(),
        };
        assert_eq!(
            gate.plan("new", &missing, 1_000.0),
            EnrichPlan::Run {
                fetch_exit_ip: true,
                dirty_risk: false
            }
        );
        gate.abort("new");
        assert!(!gate.is_pending("new"));
        assert_eq!(gate.last_at("new"), None, "取消的在途任务不写冷却");
    }

    #[test]
    fn enrich_gate_evicts_oldest_entries_over_capacity() {
        let mut gate = EnrichGate::new(0.0, 3, 1);
        for (i, id) in ["a", "b", "c", "d"].iter().enumerate() {
            gate.finish(id, 1_000.0 + i as f64);
        }
        assert_eq!(gate.tracked(), 3, "超容量后淘汰最旧的 1 条");
        assert_eq!(gate.last_at("a"), None);
        assert!(gate.last_at("d").is_some());
    }

    #[test]
    fn node_intel_reads_json_and_typed_node() {
        let v = json!({
            "id": "n", "exitIp": "203.0.113.7", "exitCountry": "HK", "exitType": "business",
            "exitRisk": 12,
            "rawConfig": {"server": "hk.lsp121.eu.org", "server_port": 39955}
        });
        let intel = NodeIntel::from_json(&v);
        assert_eq!(intel.exit_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(intel.exit_risk, Some(12));
        assert_eq!(intel.entry_host, "hk.lsp121.eu.org");
        assert!(intel.has_full_intel());

        let mut node = crate::types::Node::default();
        node.base.exit_ip = Some("198.51.100.9".into());
        node.base.exit_country = Some("JP".into());
        node.base.raw_config = Some(json!({"server": "jp.lsp121.eu.org"}));
        let typed = NodeIntel::from_node(&node);
        assert_eq!(typed.exit_ip.as_deref(), Some("198.51.100.9"));
        assert_eq!(typed.entry_host, "jp.lsp121.eu.org");
        assert!(!typed.has_full_intel(), "缺 exitType/exitRisk 仍需补查");
    }

    #[test]
    fn ippure_risk_requires_matching_exit_ip() {
        assert!(ippure_risk_usable(
            Some("203.0.113.7"),
            "203.0.113.7",
            Some(99)
        ));
        assert!(!ippure_risk_usable(
            Some("203.0.113.99"),
            "203.0.113.7",
            Some(99)
        ));
        assert!(!ippure_risk_usable(
            Some("203.0.113.7"),
            "203.0.113.7",
            None
        ));
        assert!(!ippure_risk_usable(None, "203.0.113.7", Some(1)));
    }

    #[test]
    fn enrich_concurrency_gate_caps_at_eight() {
        let mut gate = ConcurrencyGate::for_enrich();
        assert_eq!(gate.limit(), ENRICH_CONCURRENCY);
        for _ in 0..ENRICH_CONCURRENCY {
            assert!(gate.try_acquire());
        }
        assert!(!gate.try_acquire(), "超过 8 并发必须排队");
        gate.release();
        assert!(gate.try_acquire());
        assert_eq!(gate.running(), ENRICH_CONCURRENCY);
    }

    // ---------- 任务集 ----------

    #[tokio::test]
    async fn task_set_spawn_is_idempotent_and_shutdown_joins() {
        let mut set = TaskSet::new();
        let batch = || {
            (0..5).map(|_| async {
                std::future::pending::<()>().await;
            })
        };
        assert!(set.spawn_batch(batch()));
        assert_eq!(set.len(), 5);
        assert!(!set.spawn_batch(batch()), "已有一轮在跑时必须幂等跳过");
        assert_eq!(set.len(), 5);
        set.shutdown().await;
        assert!(set.is_empty());
        // 收尾后可以再次启动
        assert!(set.spawn_batch(batch()));
        set.shutdown().await;
    }

    // ---------- 常量契约 ----------

    #[test]
    fn constants_match_python_contract() {
        assert_eq!(PING_INTERVAL, 60.0);
        assert_eq!(SUB_REFRESH_INTERVAL, 10800.0);
        assert_eq!(GUARD_INTERVAL, 10.0);
        assert_eq!(GUARD_WINDOW, 60.0);
        assert_eq!(MAX_RESTARTS_PER_MIN, 3);
        assert_eq!(FD_LIMIT, 1200);
        assert_eq!(FD_RESTART_COOLDOWN, 300.0);
        assert_eq!(DISABLE_AFTER_FAILS, 20);
        assert_eq!(MIN_FAILURE_SECONDS, 1200.0);
        assert_eq!(PROBE_WINDOW, 30);
        assert_eq!(PROBE_DISABLE_RATE_FAST, 0.3);
        assert_eq!(PROBE_CONCURRENCY, 16);
        assert_eq!(MANUAL_PROBE_CONCURRENCY, 32);
        assert_eq!(PROBE_DELAY_RETRY, 2);
        assert_eq!(ENRICH_CONCURRENCY, 8);
        assert_eq!(ENRICH_COOLDOWN, 300.0);
        assert_eq!(REVIVE_INTERVAL, 600.0);
        assert_eq!(RANDOM_ROTATE_DEFAULT_INTERVAL, 30.0);
    }
}

// ===========================================================================
// 第三批单测：探活编排 / 出口情报 / relay 出口同步 / 循环
// 全部走内存桩，不启动 sing-box、不访问外网。
// ===========================================================================

#[cfg(test)]
mod probe_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize};

    // ---------- 桩件 ----------

    #[derive(Default)]
    struct FakeClash {
        delays: Mutex<Vec<DelayOutcome>>,
        requests: Mutex<Vec<DelayRequest>>,
        current: Mutex<Option<String>>,
        selects: Mutex<Vec<(String, String)>>,
    }

    impl FakeClash {
        fn with(delays: Vec<DelayOutcome>) -> Arc<Self> {
            Arc::new(Self {
                delays: Mutex::new(delays),
                ..Default::default()
            })
        }

        fn request_count(&self) -> usize {
            self.requests.lock().unwrap().len()
        }

        fn timeouts(&self) -> Vec<u64> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .map(|r| r.timeout_ms)
                .collect()
        }

        fn selects(&self) -> Vec<(String, String)> {
            self.selects.lock().unwrap().clone()
        }
    }

    impl ClashApi for FakeClash {
        fn delay(&self, req: DelayRequest) -> BoxFuture<'_, DelayOutcome> {
            Box::pin(async move {
                self.requests.lock().unwrap().push(req);
                let mut q = self.delays.lock().unwrap();
                if q.is_empty() {
                    DelayOutcome::Ok(120)
                } else {
                    q.remove(0)
                }
            })
        }

        fn current(
            &self,
            _base: String,
            _secret: Option<String>,
            tag: String,
        ) -> BoxFuture<'_, Option<String>> {
            Box::pin(async move {
                let cur = self.current.lock().unwrap().clone();
                match cur {
                    Some(c) if c == tag => None,
                    other => other,
                }
            })
        }

        fn select(
            &self,
            _base: String,
            _secret: Option<String>,
            tag: String,
            name: String,
        ) -> BoxFuture<'_, Result<(), String>> {
            Box::pin(async move {
                self.selects.lock().unwrap().push((tag, name));
                Ok(())
            })
        }
    }

    struct FakeCfg {
        running: AtomicBool,
        applies: AtomicUsize,
    }

    impl FakeCfg {
        fn new(running: bool) -> Arc<Self> {
            Arc::new(Self {
                running: AtomicBool::new(running),
                applies: AtomicUsize::new(0),
            })
        }

        fn applies(&self) -> usize {
            self.applies.load(Ordering::SeqCst)
        }
    }

    impl crate::wire::ConfigService for FakeCfg {
        fn build(&self) -> (Value, Vec<Value>) {
            (json!({}), Vec::new())
        }

        fn is_running(&self) -> bool {
            self.running.load(Ordering::SeqCst)
        }

        fn config_exists(&self) -> bool {
            true
        }

        fn apply(&self, _config: Option<Value>) -> crate::wire::BoxFut<'_, Result<Value, String>> {
            Box::pin(async move {
                self.applies.fetch_add(1, Ordering::SeqCst);
                Ok(json!({ "ok": true }))
            })
        }

        fn start(&self) -> crate::wire::BoxFut<'_, Result<bool, String>> {
            Box::pin(async move { Ok(true) })
        }

        fn stop(&self) -> crate::wire::BoxFut<'_, Result<(), String>> {
            Box::pin(async move { Ok(()) })
        }

        fn status(&self) -> crate::wire::BoxFut<'_, Value> {
            Box::pin(async move { json!({ "running": true }) })
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

    #[derive(Default)]
    struct FakeOp {
        locked: AtomicBool,
        generation: AtomicU64,
    }

    impl FakeOp {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }
    }

    impl OpState for FakeOp {
        fn locked(&self) -> bool {
            self.locked.load(Ordering::SeqCst)
        }

        fn generation(&self) -> u64 {
            self.generation.load(Ordering::SeqCst)
        }
    }

    #[derive(Default)]
    struct FakeFetcher {
        result: Mutex<Option<String>>,
        calls: AtomicUsize,
    }

    impl FakeFetcher {
        fn returning(ip: Option<&str>) -> Arc<Self> {
            Arc::new(Self {
                result: Mutex::new(ip.map(str::to_string)),
                calls: AtomicUsize::new(0),
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl ExitIpFetcher for FakeFetcher {
        fn fetch_exit_ip(&self, _node: Value) -> BoxFuture<'_, Option<String>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.result.lock().unwrap().clone()
            })
        }
    }

    struct FakeResolver(Option<String>);

    impl HostResolver for FakeResolver {
        fn resolve(&self, _host: String) -> BoxFuture<'_, Option<String>> {
            let v = self.0.clone();
            Box::pin(async move { v })
        }
    }

    #[derive(Default)]
    struct FakeIntel {
        lookup: Value,
        ippure: Value,
        ping0: Value,
    }

    impl IntelLookup for FakeIntel {
        fn lookup(&self, _ip: String) -> BoxFuture<'_, Value> {
            let v = self.lookup.clone();
            Box::pin(async move { v })
        }

        fn ippure(
            &self,
            _ip: String,
            _nodes: Vec<crate::ipinfo::ProxyNode>,
        ) -> BoxFuture<'_, Value> {
            let v = self.ippure.clone();
            Box::pin(async move { v })
        }

        fn ping0(
            &self,
            _ip: String,
            _nodes: Vec<crate::ipinfo::ProxyNode>,
        ) -> BoxFuture<'_, Value> {
            let v = self.ping0.clone();
            Box::pin(async move { v })
        }
    }

    // ---------- 工具 ----------

    fn mem_db() -> Arc<crate::db::Db> {
        let db = crate::db::Db::open_in_memory().expect("open in memory");
        db.init_db().expect("init db");
        Arc::new(db)
    }

    fn node_create(id: &str, port: i64, protocol: &str, status: &str) -> crate::types::NodeCreate {
        crate::types::NodeCreate {
            name: id.to_string(),
            protocol: protocol.to_string(),
            port: Some(port),
            status: Some(status.to_string()),
            ..Default::default()
        }
    }

    fn add_node(db: &crate::db::Db, id: &str, port: i64, status: &str) {
        db.create_node_with_id(id, &node_create(id, port, "trojan", status))
            .expect("create node");
    }

    fn engine_with(
        db: Arc<crate::db::Db>,
        cfg: Arc<FakeCfg>,
        clash: Arc<FakeClash>,
        op: Arc<FakeOp>,
    ) -> ProbeEngine {
        let enricher = Arc::new(Enricher::new(
            db.clone(),
            reqwest::Client::new(),
            FakeFetcher::returning(None),
        ));
        ProbeEngine::new(db, cfg, reqwest::Client::new())
            .with_clash(clash)
            .with_op(op)
            .with_enricher(enricher)
            .with_retry_scale(0.0)
    }

    fn status_of(results: &[Value], id: &str) -> String {
        results
            .iter()
            .find(|r| r.get("id").and_then(|v| v.as_str()) == Some(id))
            .and_then(|r| r.get("status"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }

    // ---------- 探活编排 ----------

    #[tokio::test]
    async fn probe_round_marks_online_and_writes_db() {
        let db = mem_db();
        add_node(&db, "n1", 10001, "offline");
        let cfg = FakeCfg::new(true);
        let clash = FakeClash::with(vec![DelayOutcome::Ok(88)]);
        let engine = engine_with(db.clone(), cfg, clash.clone(), FakeOp::new());
        let out = crate::wire::Prober::probe(&engine, None, true, false, true).await;
        assert_eq!(status_of(&out, "n1"), "online");
        assert_eq!(out[0]["ping"], json!(88));
        assert_eq!(out[0]["tag"], json!("out-trojan-10001"));
        let node = db.get_node("n1").unwrap().unwrap();
        assert_eq!(node.base.status.as_deref(), Some("online"));
        assert_eq!(node.base.ping, Some(88));
    }

    #[tokio::test]
    async fn probe_round_skips_manually_disabled_with_hint() {
        let db = mem_db();
        add_node(&db, "n1", 10001, "disabled");
        let cfg = FakeCfg::new(true);
        let clash = FakeClash::with(vec![]);
        let engine = engine_with(db, cfg, clash.clone(), FakeOp::new());
        let out = crate::wire::Prober::probe(&engine, None, true, true, true).await;
        assert_eq!(out.len(), 1);
        assert_eq!(status_of(&out, "n1"), "disabled");
        assert_eq!(out[0]["error"], json!(MANUAL_DISABLED_HINT));
        assert_eq!(clash.request_count(), 0);
    }

    #[tokio::test]
    async fn probe_round_retries_three_times_manual_and_four_background() {
        let db = mem_db();
        add_node(&db, "n1", 10001, "offline");
        let cfg = FakeCfg::new(true);
        let clash = FakeClash::with(vec![
            DelayOutcome::Retry("timeout".into()),
            DelayOutcome::Retry("timeout".into()),
            DelayOutcome::Retry("timeout".into()),
            DelayOutcome::Retry("timeout".into()),
            DelayOutcome::Retry("timeout".into()),
            DelayOutcome::Retry("timeout".into()),
            DelayOutcome::Retry("timeout".into()),
        ]);
        let engine = engine_with(db, cfg, clash.clone(), FakeOp::new());
        let out = crate::wire::Prober::probe(&engine, None, true, false, true).await;
        assert_eq!(status_of(&out, "n1"), "offline");
        assert_eq!(clash.request_count(), probe_attempts(ProbeMode::Manual));
        let out = crate::wire::Prober::probe(&engine, None, true, false, false).await;
        assert_eq!(status_of(&out, "n1"), "offline");
        assert_eq!(
            clash.request_count(),
            probe_attempts(ProbeMode::Background) + 3
        );
    }

    #[tokio::test]
    async fn probe_round_uses_8000ms_only_on_fourth_attempt() {
        let db = mem_db();
        add_node(&db, "n1", 10001, "offline");
        let cfg = FakeCfg::new(true);
        let clash = FakeClash::with(vec![
            DelayOutcome::Retry("timeout".into()),
            DelayOutcome::Retry("timeout".into()),
            DelayOutcome::Retry("timeout".into()),
            DelayOutcome::Ok(10),
        ]);
        let engine = engine_with(db, cfg, clash.clone(), FakeOp::new());
        let out = crate::wire::Prober::probe(&engine, None, true, false, false).await;
        assert_eq!(status_of(&out, "n1"), "online");
        assert_eq!(clash.timeouts(), vec![5000, 5000, 5000, 8000]);
        assert_eq!(clash.request_count(), probe_attempts(ProbeMode::Background));
    }

    #[tokio::test]
    async fn probe_round_reports_unknown_without_retry() {
        let db = mem_db();
        add_node(&db, "n1", 10001, "offline");
        let cfg = FakeCfg::new(true);
        let clash = FakeClash::with(vec![DelayOutcome::Unknown("clash API HTTP 401".into())]);
        let engine = engine_with(db, cfg, clash.clone(), FakeOp::new());
        let out = crate::wire::Prober::probe(&engine, None, true, false, true).await;
        assert_eq!(status_of(&out, "n1"), "unknown");
        assert_eq!(clash.request_count(), 1);
    }

    #[tokio::test]
    async fn probe_round_is_skipped_when_process_not_running() {
        let db = mem_db();
        add_node(&db, "n1", 10001, "offline");
        let cfg = FakeCfg::new(false);
        let clash = FakeClash::with(vec![]);
        let engine = engine_with(db, cfg, clash.clone(), FakeOp::new());
        let out = crate::wire::Prober::probe(&engine, None, true, false, true).await;
        assert!(out.is_empty());
        assert_eq!(clash.request_count(), 0);
    }

    #[tokio::test]
    async fn probe_round_is_skipped_when_config_operation_holds_lock() {
        let db = mem_db();
        add_node(&db, "n1", 10001, "offline");
        let cfg = FakeCfg::new(true);
        let clash = FakeClash::with(vec![]);
        let op = FakeOp::new();
        op.locked.store(true, Ordering::SeqCst);
        let engine = engine_with(db, cfg, clash.clone(), op);
        let out = crate::wire::Prober::probe(&engine, None, true, false, true).await;
        assert!(out.is_empty());
        assert_eq!(clash.request_count(), 0);
    }

    #[tokio::test]
    async fn overlapping_probe_round_returns_empty() {
        let db = mem_db();
        add_node(&db, "n1", 10001, "offline");
        let cfg = FakeCfg::new(true);
        let clash = FakeClash::with(vec![]);
        let engine = engine_with(db, cfg, clash.clone(), FakeOp::new());
        engine.inflight.store(true, Ordering::SeqCst);
        let out = crate::wire::Prober::probe(&engine, None, true, false, true).await;
        assert!(out.is_empty());
        assert_eq!(clash.request_count(), 0);
    }

    #[tokio::test]
    async fn background_failures_disable_node_after_threshold() {
        let db = mem_db();
        add_node(&db, "n1", 10001, "offline");
        // db 层自带 20 次连败硬闸，这里先垫到 19 次，让本轮探活刚好越线。
        for _ in 0..19 {
            db.update_node_probe("n1", 0, "offline", true, Some(10001), Some("trojan"))
                .expect("seed failure");
        }
        assert_eq!(
            db.get_node("n1").unwrap().unwrap().base.consecutive_fails,
            Some(19)
        );
        let cfg = FakeCfg::new(true);
        let clash = FakeClash::with(vec![
            DelayOutcome::Retry("timeout".into()),
            DelayOutcome::Retry("timeout".into()),
            DelayOutcome::Retry("timeout".into()),
            DelayOutcome::Retry("timeout".into()),
        ]);
        // 窗口压到 1 条、连败阈值仍用生产值，避开与 db 层硬闸的语义差。
        let tracker = ProbeTracker::with_limits(1, DISABLE_AFTER_FAILS, 0.0, 1.0);
        let engine =
            engine_with(db.clone(), cfg.clone(), clash, FakeOp::new()).with_tracker(tracker);
        let out = crate::wire::Prober::probe(&engine, None, true, false, false).await;
        assert_eq!(status_of(&out, "n1"), "disabled");
        let node = db.get_node("n1").unwrap().unwrap();
        assert_eq!(node.base.status.as_deref(), Some("disabled"));
        assert_eq!(node.base.disabled_auto, Some(true));
        assert!(cfg.applies() > 0, "停用后必须重新应用配置");
    }

    #[tokio::test]
    async fn auto_disabled_node_is_revived_when_probe_recovers() {
        let db = mem_db();
        let mut create = node_create("n1", 10001, "trojan", "disabled");
        create.disabled_auto = Some(true);
        db.create_node_with_id("n1", &create).unwrap();
        let cfg = FakeCfg::new(true);
        let clash = FakeClash::with(vec![DelayOutcome::Ok(41)]);
        let engine = engine_with(db.clone(), cfg.clone(), clash, FakeOp::new());
        let out =
            crate::wire::Prober::probe(&engine, Some(vec!["n1".into()]), false, true, false).await;
        assert_eq!(status_of(&out, "n1"), "online");
        let node = db.get_node("n1").unwrap().unwrap();
        assert_eq!(node.base.status.as_deref(), Some("online"));
        assert!(cfg.applies() > 0);
    }

    #[test]
    fn probe_attempts_for_node_logic() {
        // 手动测活始终保持 3 次尝试（不论连败次数）
        assert_eq!(probe_attempts_for_node(ProbeMode::Manual, 0), 3);
        assert_eq!(probe_attempts_for_node(ProbeMode::Manual, 10), 3);

        // 后台测活：连败 < 3 的节点（在线或初次抖动），提供完整的 4 次尝试机会（防误杀）
        assert_eq!(probe_attempts_for_node(ProbeMode::Background, 0), 4);
        assert_eq!(probe_attempts_for_node(ProbeMode::Background, 2), 4);

        // 后台测活：顽固死节点（连败 >= 3），熔断限制为 1 次，防止连接风暴和 TCP 堵塞
        assert_eq!(probe_attempts_for_node(ProbeMode::Background, 3), 1);
        assert_eq!(probe_attempts_for_node(ProbeMode::Background, 20), 1);
    }

    #[tokio::test]
    async fn persistent_failing_node_throttles_to_single_attempt() {
        let db = mem_db();
        add_node(&db, "n1", 10001, "offline");
        // 垫入 3 次失败，使其达到顽固死节点阈值
        for _ in 0..3 {
            db.update_node_probe("n1", 0, "offline", true, Some(10001), Some("trojan"))
                .expect("seed failure");
        }
        let cfg = FakeCfg::new(true);
        let clash = FakeClash::with(vec![
            DelayOutcome::Retry("timeout".into()),
            DelayOutcome::Retry("timeout".into()),
            DelayOutcome::Retry("timeout".into()),
            DelayOutcome::Retry("timeout".into()),
        ]);
        let engine = engine_with(db, cfg, clash.clone(), FakeOp::new());
        // 后台测活
        let out = crate::wire::Prober::probe(&engine, None, true, false, false).await;
        assert_eq!(status_of(&out, "n1"), "offline");
        // 顽固死节点仅消耗 1 次请求，不再发起 4 倍连接风暴
        assert_eq!(clash.request_count(), 1);
    }

    // ---------- 出口情报 ----------

    fn engine_with_enricher(db: Arc<crate::db::Db>, enricher: Enricher) -> ProbeEngine {
        ProbeEngine::new(db, FakeCfg::new(true), reqwest::Client::new())
            .with_enricher(Arc::new(enricher))
            .with_retry_scale(0.0)
    }

    /// 桩：抓出口 IP 时记在飞数并睡一会儿（FIX-B4 观测补查并发度）。
    #[derive(Default)]
    struct SlowFetcher {
        inflight: AtomicUsize,
        max_inflight: AtomicUsize,
        calls: AtomicUsize,
    }

    impl ExitIpFetcher for SlowFetcher {
        fn fetch_exit_ip(&self, _node: Value) -> BoxFuture<'_, Option<String>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let now = self.inflight.fetch_add(1, Ordering::SeqCst) + 1;
                self.max_inflight.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(60)).await;
                self.inflight.fetch_sub(1, Ordering::SeqCst);
                None
            })
        }
    }

    #[tokio::test]
    async fn enrich_sweep_runs_with_bounded_concurrency() {
        let db = mem_db();
        for i in 0..12 {
            add_node(&db, &format!("n{i}"), 10001 + i, "online");
        }
        let fetcher = Arc::new(SlowFetcher::default());
        let enricher = Enricher::new(db.clone(), reqwest::Client::new(), fetcher.clone())
            .with_lookup(Arc::new(FakeIntel::default()));
        let engine = Arc::new(engine_with_enricher(db.clone(), enricher));
        enrich_sweep(&engine).await;
        assert_eq!(
            fetcher.calls.load(Ordering::SeqCst),
            12,
            "缺情报节点都要补一次"
        );
        let max = fetcher.max_inflight.load(Ordering::SeqCst);
        assert!(max > 1, "补查应当并发进行，实际最大在飞数 {max}");
        assert!(
            max <= ENRICH_CONCURRENCY,
            "在飞数 {max} 超过并发上限 {ENRICH_CONCURRENCY}"
        );
    }

    #[tokio::test]
    async fn fetch_exit_ip_uses_injected_fetcher() {
        let db = mem_db();
        let enricher = Enricher::new(
            db.clone(),
            reqwest::Client::new(),
            FakeFetcher::returning(Some("5.6.7.8")),
        );
        let engine = engine_with_enricher(db, enricher);
        let node = json!({ "id": "n1", "protocol": "socks5", "port": 10001, "rawConfig": { "server": "1.2.3.4", "server_port": 1080 } });
        let ip = crate::wire::Prober::fetch_exit_ip(&engine, &node).await;
        assert_eq!(ip.as_deref(), Some("5.6.7.8"));
    }

    #[tokio::test]
    async fn failed_exit_ip_probe_never_falls_back_to_entry_dns() {
        let db = mem_db();
        let mut create = node_create("n1", 10001, "trojan", "offline");
        create.raw_config = Some(json!({ "server": "entry.example.com", "server_port": 443 }));
        create.exit_ip = Some("N/A".to_string());
        db.create_node_with_id("n1", &create).unwrap();
        let enricher = Enricher::new(
            db.clone(),
            reqwest::Client::new(),
            FakeFetcher::returning(None),
        )
        .with_resolver(Arc::new(FakeResolver(Some("1.2.3.4".to_string()))));
        let node = serde_json::to_value(db.get_node("n1").unwrap().unwrap()).unwrap();
        enricher.enrich(node).await;
        let after = db.get_node("n1").unwrap().unwrap();
        assert_eq!(after.base.exit_ip.as_deref(), Some("N/A"));
        assert_eq!(after.base.exit_country, None);
    }

    #[tokio::test]
    async fn dirty_entry_ip_is_reprobed_and_replaced() {
        let db = mem_db();
        let mut create = node_create("n1", 10001, "trojan", "online");
        create.raw_config = Some(json!({ "server": "entry.example.com", "server_port": 443 }));
        create.exit_ip = Some("1.2.3.4".to_string());
        db.create_node_with_id("n1", &create).unwrap();
        let enricher = Enricher::new(
            db.clone(),
            reqwest::Client::new(),
            FakeFetcher::returning(Some("9.9.9.9")),
        )
        .with_resolver(Arc::new(FakeResolver(Some("1.2.3.4".to_string()))))
        .with_lookup(Arc::new(FakeIntel {
            lookup: json!({ "exitCountry": "JP", "exitType": "idc", "exitScore": 10 }),
            ippure: json!({}),
            ping0: json!({ "exitRisk": 12 }),
        }));
        let node = serde_json::to_value(db.get_node("n1").unwrap().unwrap()).unwrap();
        enricher.enrich(node).await;
        let after = db.get_node("n1").unwrap().unwrap();
        assert_eq!(after.base.exit_ip.as_deref(), Some("9.9.9.9"));
        assert_eq!(after.base.exit_country.as_deref(), Some("JP"));
        assert_eq!(after.base.exit_risk, Some(12));
    }

    #[tokio::test]
    async fn full_intel_node_is_not_probed_again() {
        let db = mem_db();
        let mut create = node_create("n1", 10001, "trojan", "online");
        create.raw_config = Some(json!({ "server": "1.2.3.4", "server_port": 443 }));
        create.exit_ip = Some("8.8.8.8".to_string());
        create.exit_country = Some("US".to_string());
        create.exit_type = Some("idc".to_string());
        create.exit_risk = Some(3);
        db.create_node_with_id("n1", &create).unwrap();
        let fetcher = FakeFetcher::returning(Some("7.7.7.7"));
        let enricher = Enricher::new(db.clone(), reqwest::Client::new(), fetcher.clone());
        let node = serde_json::to_value(db.get_node("n1").unwrap().unwrap()).unwrap();
        enricher.enrich(node).await;
        assert_eq!(fetcher.calls(), 0);
        assert_eq!(
            db.get_node("n1").unwrap().unwrap().base.exit_ip.as_deref(),
            Some("8.8.8.8")
        );
    }

    #[tokio::test]
    async fn enrich_records_cooldown_after_run() {
        let db = mem_db();
        let mut create = node_create("n1", 10001, "trojan", "offline");
        create.raw_config = Some(json!({ "server": "1.2.3.4", "server_port": 443 }));
        db.create_node_with_id("n1", &create).unwrap();
        let fetcher = FakeFetcher::returning(Some("9.9.9.9"));
        let enricher = Enricher::new(db.clone(), reqwest::Client::new(), fetcher.clone())
            .with_lookup(Arc::new(FakeIntel::default()));
        let value = serde_json::to_value(db.get_node("n1").unwrap().unwrap()).unwrap();
        enricher.enrich(value.clone()).await;
        assert_eq!(fetcher.calls(), 1);
        let after = serde_json::to_value(db.get_node("n1").unwrap().unwrap()).unwrap();
        assert!(matches!(
            enricher.plan(&after, epoch_now()),
            EnrichPlan::Cooling
        ));
        // 冷却期内再触发一次不得重复抓取
        enricher.enrich(after.clone()).await;
        assert_eq!(fetcher.calls(), 1);
        assert!(matches!(
            enricher.plan(&after, epoch_now() + ENRICH_COOLDOWN + 1.0),
            EnrichPlan::Run { .. }
        ));
    }

    // ---------- relay 出口同步 ----------

    fn relay(id: &str, groups: Vec<&str>) -> crate::types::RelayDomain {
        crate::types::RelayDomain {
            id: id.to_string(),
            domain: "relay.example.com".to_string(),
            port: 443,
            auth_user: None,
            auth_pass: None,
            groups: groups.into_iter().map(str::to_string).collect(),
        }
    }

    #[tokio::test]
    async fn relay_sync_switches_to_lowest_delay_candidate() {
        let db = mem_db();
        add_node(&db, "n1", 10001, "online");
        add_node(&db, "n2", 10002, "online");
        db.upsert_relay_domains(&[relay("rc1", vec!["ALL"])])
            .unwrap();
        let cfg = FakeCfg::new(true);
        let clash = FakeClash::with(vec![]);
        let engine = engine_with(db.clone(), cfg, clash.clone(), FakeOp::new());
        let results = vec![
            json!({ "id": "n1", "tag": "out-trojan-10001", "ping": 300, "status": "online" }),
            json!({ "id": "n2", "tag": "out-trojan-10002", "ping": 40, "status": "online" }),
        ];
        let report = engine.sync_relay_exits_after_probe(&results).await;
        assert_eq!(report.measured, 0);
        assert_eq!(report.switched, 1);
        assert_eq!(
            clash.selects(),
            vec![("relay-auto-rc1".to_string(), "out-trojan-10002".to_string())]
        );
        assert!(engine.switch_at("rc1").is_some());
    }

    #[tokio::test]
    async fn relay_sync_keeps_current_inside_sticky_window() {
        let db = mem_db();
        add_node(&db, "n1", 10001, "online");
        add_node(&db, "n2", 10002, "online");
        db.upsert_relay_domains(&[relay("rc1", vec!["ALL"])])
            .unwrap();
        db.set_setting(
            "system",
            &json!({ "stickyEnabled": true, "stickyTimeout": "5m" }),
        )
        .unwrap();
        let cfg = FakeCfg::new(true);
        let clash = FakeClash::with(vec![]);
        *clash.current.lock().unwrap() = Some("out-trojan-10001".to_string());
        let engine = engine_with(db.clone(), cfg, clash.clone(), FakeOp::new());
        engine
            .switch_at
            .lock()
            .unwrap()
            .insert("rc1".to_string(), epoch_now());
        let results = vec![
            json!({ "id": "n1", "tag": "out-trojan-10001", "ping": 300, "status": "online" }),
            json!({ "id": "n2", "tag": "out-trojan-10002", "ping": 40, "status": "online" }),
        ];
        let report = engine.sync_relay_exits_after_probe(&results).await;
        assert_eq!(report.switched, 0);
        assert!(clash.selects().is_empty());
    }

    #[tokio::test]
    async fn relay_sync_measures_nodes_missing_from_probe_round() {
        let db = mem_db();
        add_node(&db, "n1", 10001, "online");
        db.upsert_relay_domains(&[relay("rc1", vec!["ALL"])])
            .unwrap();
        let cfg = FakeCfg::new(true);
        let clash = FakeClash::with(vec![DelayOutcome::Ok(20)]);
        let engine = engine_with(db.clone(), cfg, clash.clone(), FakeOp::new());
        let report = engine.sync_relay_exits_after_probe(&[]).await;
        assert_eq!(report.measured, 1);
        assert_eq!(report.switched, 1);
        assert_eq!(clash.request_count(), 1);
    }

    /// 唯一域名/端口/id 的 relay（relay_domains 的 port 是 UNIQUE，同端口行会被跳过）。
    fn relay_n(i: usize) -> crate::types::RelayDomain {
        let mut rd = relay(&format!("rc{i}"), vec!["ALL"]);
        rd.domain = format!("relay{i}.example.com");
        rd.port = 44000 + i as i64;
        rd
    }

    /// 建一个带自定义 ClashApi 桩的引擎（FIX-B2 测试要可观测的 current 实现）。
    fn engine_with_clash(db: Arc<crate::db::Db>, clash: Arc<dyn ClashApi>) -> ProbeEngine {
        let enricher = Arc::new(Enricher::new(
            db.clone(),
            reqwest::Client::new(),
            FakeFetcher::returning(None),
        ));
        ProbeEngine::new(db, FakeCfg::new(true), reqwest::Client::new())
            .with_clash(clash)
            .with_op(FakeOp::new())
            .with_enricher(enricher)
            .with_retry_scale(0.0)
    }

    /// 桩：第一次 current 时把低延迟节点 n2 停用，模拟同步期间库被改。
    /// 三个 relay 仍然都选中 n2 → 证明循环里没有重新 list_nodes（快照只读了一次）。
    ///
    /// 说明：Db 是具体类型，没有注入计数桩的入口，也不允许改 Cargo.toml 打开
    /// rusqlite 的 hooks/trace 特性，因此用「循环内改库对后续 relay 不可见」等价证明
    /// list_nodes 不再是每个 relay 一次（修复前是 O(R) 次）。
    struct SnapshotProbeClash {
        db: Arc<crate::db::Db>,
        current_calls: AtomicUsize,
        selects: Mutex<Vec<(String, String)>>,
    }

    impl ClashApi for SnapshotProbeClash {
        fn delay(&self, _req: DelayRequest) -> BoxFuture<'_, DelayOutcome> {
            Box::pin(async move { DelayOutcome::Ok(20) })
        }

        fn current(
            &self,
            _base: String,
            _secret: Option<String>,
            _tag: String,
        ) -> BoxFuture<'_, Option<String>> {
            Box::pin(async move {
                if self.current_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    self.db
                        .with_conn(|c| {
                            c.execute("UPDATE nodes SET status='disabled' WHERE id='n2'", [])
                        })
                        .expect("disable n2");
                }
                None
            })
        }

        fn select(
            &self,
            _base: String,
            _secret: Option<String>,
            tag: String,
            name: String,
        ) -> BoxFuture<'_, Result<(), String>> {
            Box::pin(async move {
                self.selects.lock().unwrap().push((tag, name));
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn relay_sync_uses_single_node_snapshot_for_all_relays() {
        let db = mem_db();
        add_node(&db, "n1", 10001, "online");
        add_node(&db, "n2", 10002, "online");
        db.upsert_relay_domains(&[relay_n(1), relay_n(2), relay_n(3)])
            .unwrap();
        let clash = Arc::new(SnapshotProbeClash {
            db: db.clone(),
            current_calls: AtomicUsize::new(0),
            selects: Mutex::new(Vec::new()),
        });
        let engine = engine_with_clash(db.clone(), clash.clone());
        let results = vec![
            json!({ "id": "n1", "tag": "out-trojan-10001", "ping": 300, "status": "online" }),
            json!({ "id": "n2", "tag": "out-trojan-10002", "ping": 40, "status": "online" }),
        ];
        let report = engine.sync_relay_exits_after_probe(&results).await;
        assert_eq!(report.switched, 3);
        assert_eq!(clash.current_calls.load(Ordering::SeqCst), 3);
        let selects = clash.selects.lock().unwrap().clone();
        assert_eq!(selects.len(), 3);
        for (tag, name) in selects {
            assert!(tag.starts_with("relay-auto-rc"), "意外的 relay tag: {tag}");
            assert_eq!(name, "out-trojan-10002");
        }
    }

    #[tokio::test]
    async fn relay_sync_drops_switch_at_entries_of_deleted_relays() {
        let db = mem_db();
        add_node(&db, "n1", 10001, "online");
        db.upsert_relay_domains(&[relay("rc1", vec!["ALL"])])
            .unwrap();
        let clash = FakeClash::with(vec![]);
        let engine = engine_with(db.clone(), FakeCfg::new(true), clash.clone(), FakeOp::new());
        {
            let mut map = engine.switch_at.lock().unwrap();
            map.insert("rc1".to_string(), 1.0);
            map.insert("gone-1".to_string(), 2.0);
            map.insert("gone-2".to_string(), 3.0);
            assert_eq!(map.len(), 3);
        }
        let results =
            vec![json!({ "id": "n1", "tag": "out-trojan-10001", "ping": 30, "status": "online" })];
        let report = engine.sync_relay_exits_after_probe(&results).await;
        assert_eq!(report.switched, 1);
        let map = engine.switch_at.lock().unwrap();
        assert_eq!(map.len(), 1, "只应保留仍存在的 relay");
        assert!(map.contains_key("rc1"));
    }

    /// 桩：记录 current 的最大在飞数。
    struct ConcurrentClash {
        inflight: AtomicUsize,
        max_inflight: AtomicUsize,
    }

    impl ClashApi for ConcurrentClash {
        fn delay(&self, _req: DelayRequest) -> BoxFuture<'_, DelayOutcome> {
            Box::pin(async move { DelayOutcome::Ok(20) })
        }

        fn current(
            &self,
            _base: String,
            _secret: Option<String>,
            _tag: String,
        ) -> BoxFuture<'_, Option<String>> {
            Box::pin(async move {
                let now = self.inflight.fetch_add(1, Ordering::SeqCst) + 1;
                self.max_inflight.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(40)).await;
                self.inflight.fetch_sub(1, Ordering::SeqCst);
                None
            })
        }

        fn select(
            &self,
            _base: String,
            _secret: Option<String>,
            _tag: String,
            _name: String,
        ) -> BoxFuture<'_, Result<(), String>> {
            Box::pin(async move { Ok(()) })
        }
    }

    #[tokio::test]
    async fn relay_sync_fetches_current_concurrently() {
        let db = mem_db();
        add_node(&db, "n1", 10001, "online");
        let relays: Vec<crate::types::RelayDomain> = (1..=6).map(relay_n).collect();
        db.upsert_relay_domains(&relays).unwrap();
        let clash = Arc::new(ConcurrentClash {
            inflight: AtomicUsize::new(0),
            max_inflight: AtomicUsize::new(0),
        });
        let engine = engine_with_clash(db.clone(), clash.clone());
        let results =
            vec![json!({ "id": "n1", "tag": "out-trojan-10001", "ping": 30, "status": "online" })];
        let report = engine.sync_relay_exits_after_probe(&results).await;
        assert_eq!(report.switched, 6);
        let max = clash.max_inflight.load(Ordering::SeqCst);
        assert!(max >= 2, "current 应当并发发起，实际最大在飞数 {max}");
        assert!(
            max <= RELAY_SYNC_CONCURRENCY,
            "在飞数 {max} 超过并发上限 {RELAY_SYNC_CONCURRENCY}"
        );
    }

    #[tokio::test]
    async fn rotate_random_relay_persists_current_tag() {
        let db = mem_db();
        add_node(&db, "n1", 10001, "online");
        db.upsert_relay_domains(&[relay("rc1", vec!["ALL"])])
            .unwrap();
        db.set_setting("system", &json!({ "randomRotateEnabled": true }))
            .unwrap();
        let cfg = FakeCfg::new(true);
        let clash = FakeClash::with(vec![DelayOutcome::Ok(15)]);
        let engine = engine_with(db.clone(), cfg, clash.clone(), FakeOp::new());
        let chosen = engine.rotate_random_relay().await;
        assert_eq!(chosen.as_deref(), Some("out-trojan-10001"));
        assert_eq!(
            clash.selects(),
            vec![("relay-auto-rc1".to_string(), "out-trojan-10001".to_string())]
        );
        let settings = db.get_setting("system").unwrap();
        assert_eq!(settings["randomRotateCurrent"], json!("out-trojan-10001"));
    }

    /// 桩：所有 delay 都挂住 5s 再按超时返回，用来验证整轮探测预算。
    struct HangingClash {
        calls: AtomicUsize,
    }

    impl ClashApi for HangingClash {
        fn delay(&self, _req: DelayRequest) -> BoxFuture<'_, DelayOutcome> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                DelayOutcome::Unreachable("hang".to_string())
            })
        }

        fn current(
            &self,
            _base: String,
            _secret: Option<String>,
            _tag: String,
        ) -> BoxFuture<'_, Option<String>> {
            Box::pin(async move { None })
        }

        fn select(
            &self,
            _base: String,
            _secret: Option<String>,
            _tag: String,
            _name: String,
        ) -> BoxFuture<'_, Result<(), String>> {
            Box::pin(async move { Ok(()) })
        }
    }

    #[tokio::test]
    async fn rotate_random_relay_probes_are_bounded_by_budget_and_concurrency() {
        let db = mem_db();
        for i in 0..6 {
            add_node(&db, &format!("n{i}"), 10001 + i, "online");
        }
        db.upsert_relay_domains(&(1..=5).map(relay_n).collect::<Vec<_>>())
            .unwrap();
        let clash = Arc::new(HangingClash {
            calls: AtomicUsize::new(0),
        });
        let engine = engine_with_clash(db.clone(), clash.clone());
        let started = std::time::Instant::now();
        // 并发 3、预算 0.2s 注入：不这样做测试要等 30s。
        let chosen = engine.rotate_random_relay_with(3, 0.2).await;
        let elapsed = started.elapsed();
        assert!(chosen.is_none(), "候选全超时应当返回 None");
        let calls = clash.calls.load(Ordering::SeqCst);
        assert!(
            calls <= 4,
            "delay 调用次数 {calls} 应受并发上限(3)约束，超预算的候选不该再发请求"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "整轮耗时 {elapsed:?} 超出预算约束"
        );
    }

    /// 桩：只有指定 tag 活着。
    struct OneAliveClash {
        alive_tag: String,
        selects: Mutex<Vec<(String, String)>>,
    }

    impl ClashApi for OneAliveClash {
        fn delay(&self, req: DelayRequest) -> BoxFuture<'_, DelayOutcome> {
            let alive = req.tag == self.alive_tag;
            Box::pin(async move {
                if alive {
                    DelayOutcome::Ok(15)
                } else {
                    DelayOutcome::Unreachable("down".to_string())
                }
            })
        }

        fn current(
            &self,
            _base: String,
            _secret: Option<String>,
            _tag: String,
        ) -> BoxFuture<'_, Option<String>> {
            Box::pin(async move { None })
        }

        fn select(
            &self,
            _base: String,
            _secret: Option<String>,
            tag: String,
            name: String,
        ) -> BoxFuture<'_, Result<(), String>> {
            Box::pin(async move {
                self.selects.lock().unwrap().push((tag, name));
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn rotate_random_relay_picks_the_alive_candidate() {
        let db = mem_db();
        for i in 0..3 {
            add_node(&db, &format!("n{i}"), 10001 + i, "online");
        }
        db.upsert_relay_domains(&[relay_n(1)]).unwrap();
        let clash = Arc::new(OneAliveClash {
            alive_tag: "out-trojan-10002".to_string(),
            selects: Mutex::new(Vec::new()),
        });
        let engine = engine_with_clash(db.clone(), clash.clone());
        let chosen = engine.rotate_random_relay().await;
        assert_eq!(chosen.as_deref(), Some("out-trojan-10002"));
        assert_eq!(
            clash.selects.lock().unwrap().clone(),
            vec![("relay-auto-rc1".to_string(), "out-trojan-10002".to_string())]
        );
    }

    // ---------- 循环与接口 ----------

    #[tokio::test]
    async fn sleep_or_stop_returns_false_when_notified() {
        let stop = Arc::new(tokio::sync::Notify::new());
        let stop2 = stop.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            stop2.notify_one();
        });
        assert!(!sleep_or_stop(&stop, 30.0).await);
    }

    #[tokio::test]
    async fn diagnose_delegates_to_probe_ip_for_unusable_endpoint() {
        let db = mem_db();
        let engine = engine_with(
            db,
            FakeCfg::new(true),
            FakeClash::with(vec![]),
            FakeOp::new(),
        );
        let broken = json!({ "id": "n1", "protocol": "trojan", "port": 0, "entryProto": "mixed" });
        assert!(!crate::wire::Prober::diagnose(&engine, &broken).is_empty());
        let usable =
            json!({ "id": "n2", "protocol": "trojan", "port": 10001, "entryProto": "mixed" });
        assert!(crate::wire::Prober::diagnose(&engine, &usable).is_empty());
    }
}
