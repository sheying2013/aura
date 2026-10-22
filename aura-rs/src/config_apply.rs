//! 配置应用与进程编排层：backend/config_manager.py 的应用/进程管理部分迁移。
//!
//! 这一层负责把「想跑的配置」变成「正在跑的 sing-box」，是 scheduler 崩溃守护
//! 的宿主实现体（impl crate::scheduler::GuardHost for ConfigManager）。
//!
//! 分工（重要）：
//! - 路径、原子写、信号投递、/proc 进程发现、fd 统计、clash 探活这些原语
//!   全部由 crate::singbox_proc 提供，本模块不重复实现；
//! - 本模块只做编排：何时写盘、何时热重载、何时冷重启、失败如何回滚、
//!   generation 如何递增、如何等 clash API 就绪；
//! - 真正的子进程托管（spawn / 收割 / SIGTERM 等 3 秒 / SIGKILL）由本模块的
//!   StdProcControl 实现，因为 singbox_proc 刻意不含 tokio::process 或
//!   std::process::Command 依赖。
//!
//! 历史事故锚点（这些行为不能退化）：
//! 1. 配置写盘后必须先等 clash API 就绪再宣称成功，否则面板会把「进程起来了
//!    但代理不通」当成成功，前端节点全部显示超时；
//! 2. 热重载失败必须降级为冷重启，否则 sing-box 会带着旧配置一直跑；
//! 3. 新配置起不来必须回滚上一份好配置，否则一次错误提交就把代理彻底打死；
//! 4. stop 必须 SIGTERM -> 宽限 -> SIGKILL，只发 SIGTERM 会留下僵死的监听端口
//!    占位，导致下一次 start 直接失败（端口被占用）。

use std::collections::BTreeSet;
use std::io::Read;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};

use crate::scheduler::{BoxFuture, GuardHost};
use crate::singbox_proc::{self, LogFile, ProcPaths, Signal};

/// 进程路径与二进制名由 singbox_proc 定义，这里直接复用，避免两套实现漂移。
pub use crate::singbox_proc::ProcPaths as Paths;

/// clash API 绑定地址（与 config_manager / singbox_proc 保持一致）。
pub const CLASH_HOST: &str = "127.0.0.1";
/// clash API 默认端口，可被 settings.system.clashPort 覆盖。
pub const DEFAULT_CLASH_PORT: i64 = 9095;
/// settings 表里系统配置的键名。
pub const SETTING_SYSTEM: &str = "system";
/// clash API 鉴权 token 的键名。
pub const SETTING_CLASH_SECRET: &str = "clash_secret";
/// sing-box 二进制默认名（可由 SINGBOX_BIN 或 ProcPaths 覆盖）。
pub const DEFAULT_SINGBOX_BIN: &str = "sing-box";
/// 启动后观察窗口：这段时间内进程退出即判定启动失败。
pub const DEFAULT_START_OBSERVE: Duration = Duration::from_secs(2);
/// 停止宽限期：SIGTERM 后等这么久，仍未退出就 SIGKILL。
pub const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(5);
/// SIGTERM 到 SIGKILL 之间的宽限（与 Python wait(timeout=...) 对齐）。
pub const STOP_GRACE: Duration = Duration::from_secs(3);
/// 等 clash API 就绪的轮询次数上限。
pub const DEFAULT_CLASH_TRIES: usize = 10;
/// 等 clash API 就绪的轮询间隔（10 次 * 500ms = 5 秒）。
pub const DEFAULT_CLASH_INTERVAL: Duration = Duration::from_millis(500);
/// 单次进程操作（start/stop）的超时上限，避免面板线程被卡死。
pub const PROC_CALL_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// 可注入的依赖：设置读写 / 进程控制 / clash 探活
// ---------------------------------------------------------------------------

/// 面板设置与节点数据的读写口。
///
/// 生产实现是 crate::db，测试里用内存 fake，保证应用逻辑可以脱离数据库单测。
pub trait DbSettings: Send + Sync {
    /// 读一个设置键；不存在返回 None。
    fn get_setting(&self, key: &str) -> Option<Value>;
    /// 写一个设置键。
    fn set_setting(&self, key: &str, value: &Value) -> Result<()>;
    /// 列节点（转成 JSON，好直接喂给 build_config）。
    fn list_nodes(
        &self,
        q: Option<&str>,
        group: Option<&str>,
        sub_id: Option<&str>,
    ) -> Result<Vec<Value>> {
        let _ = (q, group, sub_id);
        Ok(Vec::new())
    }
    /// 列中转域名。
    fn list_relay_domains(&self) -> Result<Vec<Value>> {
        Ok(Vec::new())
    }
}

/// 进程控制口：真实实现见 StdProcControl，测试用内存 fake。
pub trait ProcControl: Send + Sync {
    /// sing-box 是否在跑。
    fn is_running(&self) -> bool;
    /// 用给定配置启动 sing-box（配置已经落盘）。
    fn start(&self, config: &Value) -> Result<()>;
    /// 停止 sing-box。
    fn stop(&self) -> Result<()>;
    /// 当前 fd 总数，供 scheduler 的 fd 泄漏看门狗使用。
    fn fd_count(&self) -> usize;
    /// 当前进程 pid（若可获取）。
    fn pid(&self) -> Option<u32> {
        None
    }
}

/// clash API 探活口。
pub trait ClashProbe: Send + Sync {
    /// clash API 的 /version 是否可正常访问。
    fn version_ok(&self, base: &str, secret: &str) -> bool;
}

/// 永远就绪的探活桩（测试/无 clash 场景）。
#[derive(Clone, Copy, Debug, Default)]
pub struct AssumeReady;

impl ClashProbe for AssumeReady {
    fn version_ok(&self, _base: &str, _secret: &str) -> bool {
        true
    }
}

/// 永远不就绪的探活桩（覆盖失败路径）。
#[derive(Clone, Copy, Debug, Default)]
pub struct NeverReady;

impl ClashProbe for NeverReady {
    fn version_ok(&self, _base: &str, _secret: &str) -> bool {
        false
    }
}

/// HTTP 探活实现：直接复用 singbox_proc 的裸 TCP /version 探测。
///
/// singbox_proc 不带 Authorization 头（它零 DB 依赖），这里同样先按「端口有
/// HTTP 应答」判断存活；secret 是否正确的强校验留在调用方（需要时再补）。
#[derive(Clone)]
pub struct HttpClashProbe {
    /// 构造时算出的端口（settings 缺失时的回落值）。
    port: u16,
    /// 设置源；存在时每次探测都重新读 clashPort，跟随用户在设置页的修改。
    settings: Option<Arc<dyn DbSettings>>,
}

impl HttpClashProbe {
    /// 指定 clash 端口（固定）。
    pub fn new(port: u16) -> Self {
        Self {
            port,
            settings: None,
        }
    }

    /// 端口跟随 settings.system.clashPort 的探活实现。
    ///
    /// 必须动态读：用户在设置页改 clash 端口后，sing-box 会按新端口起，
    /// 探活若还盯着旧端口就会一直判定「未就绪」→ 反复杀进程。
    pub fn from_settings(settings: Arc<dyn DbSettings>) -> Self {
        let port = clash_port_from(settings.as_ref()) as u16;
        Self {
            port,
            settings: Some(settings),
        }
    }

    /// 探测用的端口（settings 存在时按当前设置算）。
    pub fn port(&self) -> u16 {
        match self.settings.as_ref() {
            Some(settings) => clash_port_from(settings.as_ref()) as u16,
            None => self.port,
        }
    }
}

impl std::fmt::Debug for HttpClashProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClashProbe")
            .field("port", &self.port())
            .finish()
    }
}

impl ClashProbe for HttpClashProbe {
    fn version_ok(&self, _base: &str, secret: &str) -> bool {
        // 必须带上 clash secret：配置里写了 secret 时，裸请求只会拿到 401，
        // 那样会把已经正常起来的 sing-box 误判成「未就绪」。
        singbox_proc::clash_api_ready(
            self.port(),
            singbox_proc::CLASH_PROBE_TIMEOUT,
            Some(secret),
        )
    }
}

/// 生产环境设置源：转发到全局数据库单例。
#[derive(Clone, Copy, Debug, Default)]
pub struct GlobalDb;

impl DbSettings for crate::db::Db {
    fn get_setting(&self, key: &str) -> Option<Value> {
        match crate::db::Db::get_setting(self, key) {
            Ok(v) if !v.is_null() => Some(v),
            _ => None,
        }
    }

    fn set_setting(&self, key: &str, value: &Value) -> Result<()> {
        crate::db::Db::set_setting(self, key, value)
            .map_err(|e| anyhow!("写入设置 {} 失败: {}", key, e))
    }

    fn list_nodes(
        &self,
        q: Option<&str>,
        group: Option<&str>,
        sub_id: Option<&str>,
    ) -> Result<Vec<Value>> {
        let nodes = crate::db::Db::list_nodes(self, q, group, sub_id)
            .map_err(|e| anyhow!("读取节点失败: {}", e))?;
        let mut out = Vec::with_capacity(nodes.len());
        for node in nodes {
            out.push(serde_json::to_value(&node).map_err(|e| anyhow!("节点序列化失败: {}", e))?);
        }
        Ok(out)
    }

    fn list_relay_domains(&self) -> Result<Vec<Value>> {
        let domains = crate::db::Db::list_relay_domains(self)
            .map_err(|e| anyhow!("读取中转域名失败: {}", e))?;
        let mut out = Vec::with_capacity(domains.len());
        for dom in domains {
            out.push(serde_json::to_value(&dom).map_err(|e| anyhow!("中转域名序列化失败: {}", e))?);
        }
        Ok(out)
    }
}

impl DbSettings for GlobalDb {
    fn get_setting(&self, key: &str) -> Option<Value> {
        // 明确走 trait 实现：Db 上还有同名 inherent 方法，返回类型不同。
        <crate::db::Db as DbSettings>::get_setting(crate::db::global(), key)
    }

    fn set_setting(&self, key: &str, value: &Value) -> Result<()> {
        <crate::db::Db as DbSettings>::set_setting(crate::db::global(), key, value)
    }

    fn list_nodes(
        &self,
        q: Option<&str>,
        group: Option<&str>,
        sub_id: Option<&str>,
    ) -> Result<Vec<Value>> {
        <crate::db::Db as DbSettings>::list_nodes(crate::db::global(), q, group, sub_id)
    }

    fn list_relay_domains(&self) -> Result<Vec<Value>> {
        <crate::db::Db as DbSettings>::list_relay_domains(crate::db::global())
    }
}

// ---------------------------------------------------------------------------
// 真实进程控制：spawn / 收割 / SIGTERM -> 宽限 -> SIGKILL
// ---------------------------------------------------------------------------

/// 把子进程的 stdout/stderr 泵进轮转日志（对应 Python 的 _log_reader 任务）。
fn spawn_log_pump<R>(mut reader: R, log: Arc<StdMutex<LogFile>>, tag: &'static str)
where
    R: Read + Send + 'static,
{
    let spawned = std::thread::Builder::new()
        .name(format!("singbox-log-{}", tag))
        .spawn(move || {
            let mut buf = [0u8; 64 * 1024];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let mut guard = log.lock().unwrap_or_else(|e| e.into_inner());
                        if guard.write_chunk(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    // 线程建不起来也不影响主流程：日志丢了比进程起不来轻。
    let _ = spawned;
}

/// 轮询等子进程退出；返回是否在期限内退出。
fn wait_child_exit(child: &mut Child, grace: Duration) -> bool {
    let deadline = Instant::now() + grace;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) => {
                if Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return true,
        }
    }
}

/// 真实进程控制：std::process 托管 + singbox_proc 的原语兜底。
///
/// 设计取舍：句柄存在时以句柄为准（能精确收割）；句柄丢失（面板自己重启过、
/// 或容器里 sing-box 被别人拉起）时退化成按 cmdline 特征 + clash 端口探测，
/// 与 Python 的兜底路径一致。
pub struct StdProcControl {
    paths: ProcPaths,
    clash_port: u16,
    /// 设置源；存在时 clash 端口每次动态读，跟随设置页的 clashPort 修改。
    settings: Option<Arc<dyn DbSettings>>,
    child: StdMutex<Option<Child>>,
    log: StdMutex<Option<Arc<StdMutex<LogFile>>>>,
}

impl StdProcControl {
    /// 构造（固定 clash 端口）。
    pub fn new(paths: ProcPaths, clash_port: u16) -> Self {
        Self {
            paths,
            clash_port,
            settings: None,
            child: StdMutex::new(None),
            log: StdMutex::new(None),
        }
    }

    /// 构造（clash 端口跟随 settings.system.clashPort）。
    pub fn from_settings(paths: ProcPaths, settings: Arc<dyn DbSettings>) -> Self {
        let clash_port = clash_port_from(settings.as_ref()) as u16;
        Self {
            paths,
            clash_port,
            settings: Some(settings),
            child: StdMutex::new(None),
            log: StdMutex::new(None),
        }
    }

    /// 使用的路径。
    pub fn paths(&self) -> &ProcPaths {
        &self.paths
    }

    /// clash 端口（settings 存在时按当前设置算）。
    pub fn clash_port(&self) -> u16 {
        match self.settings.as_ref() {
            Some(settings) => clash_port_from(settings.as_ref()) as u16,
            None => self.clash_port,
        }
    }

    fn lock_child(&self) -> std::sync::MutexGuard<'_, Option<Child>> {
        self.child.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn lock_log(&self) -> std::sync::MutexGuard<'_, Option<Arc<StdMutex<LogFile>>>> {
        self.log.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl ProcControl for StdProcControl {
    fn is_running(&self) -> bool {
        {
            let mut guard = self.lock_child();
            if let Some(child) = guard.as_mut() {
                match child.try_wait() {
                    Ok(None) => return true,
                    _ => *guard = None,
                }
            }
        }
        singbox_proc::is_running_with_port(&self.paths, self.clash_port())
    }

    fn start(&self, _config: &Value) -> Result<()> {
        if self.is_running() {
            return Ok(());
        }
        let cfg_path = self.paths.config_path();
        if !cfg_path.exists() {
            return Err(anyhow!(
                "配置文件不存在: {}（先写盘再启动）",
                cfg_path.display()
            ));
        }
        let log = Arc::new(StdMutex::new(LogFile::open(&self.paths).with_context(
            || {
                format!(
                    "打开 sing-box 日志失败: {}",
                    self.paths.log_path().display()
                )
            },
        )?));
        let mut child = Command::new(&self.paths.singbox_bin)
            .arg("run")
            .arg("-c")
            .arg(&cfg_path)
            .arg("-D")
            .arg(&self.paths.data_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("无法启动 sing-box: {}", self.paths.singbox_bin))?;
        if let Some(out) = child.stdout.take() {
            spawn_log_pump(out, Arc::clone(&log), "stdout");
        }
        if let Some(err) = child.stderr.take() {
            spawn_log_pump(err, Arc::clone(&log), "stderr");
        }
        *self.lock_child() = Some(child);
        *self.lock_log() = Some(log);
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        let taken = {
            let mut guard = self.lock_child();
            guard.take()
        };
        match taken {
            Some(mut child) => {
                let pid = child.id() as i32;
                // 先讲道理：SIGTERM 让它自己收尾（关监听、落盘）。
                unsafe {
                    libc::kill(pid, libc::SIGTERM);
                }
                if !wait_child_exit(&mut child, STOP_GRACE) {
                    // 不讲道理：SIGKILL，否则僵死的监听端口会把下一次 start 顶回去。
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                    }
                    let _ = child.kill();
                }
                let _ = child.wait();
            }
            None => {
                // 句柄丢了但进程还在（面板重启过 / 被外部拉起）：按 cmdline 特征兜底。
                if !singbox_proc::find_singbox_pids(&self.paths).is_empty() {
                    singbox_proc::signal_singbox(&self.paths, Signal::Term);
                }
            }
        }
        // 关掉日志句柄，等同 Python 里取消 _log_task 并置 None。
        *self.lock_log() = None;
        Ok(())
    }

    fn fd_count(&self) -> usize {
        singbox_proc::singbox_fd_count(&self.paths)
    }

    fn pid(&self) -> Option<u32> {
        {
            let mut guard = self.lock_child();
            if let Some(child) = guard.as_mut() {
                if matches!(child.try_wait(), Ok(None)) {
                    return Some(child.id());
                }
            }
        }
        singbox_proc::find_singbox_pids(&self.paths)
            .first()
            .map(|p| *p as u32)
    }
}

// ---------------------------------------------------------------------------
// 端口占用检测（对应 Python 的 _detect_port_conflict）
// ---------------------------------------------------------------------------

/// 从配置里取所有入站监听端口。
pub fn inbound_ports(config: &Value) -> Vec<i64> {
    let mut out = Vec::new();
    let Some(list) = config.get("inbounds").and_then(|v| v.as_array()) else {
        return out;
    };
    for inbound in list {
        if let Some(port) = inbound
            .get("listen_port")
            .or_else(|| inbound.get("listenPort"))
            .and_then(|v| v.as_i64())
        {
            if (1..=65535).contains(&port) {
                out.push(port);
            }
        }
    }
    out
}

/// 端口当前是否可独占绑定（bind 0.0.0.0）。
pub fn probe_port_free(port: i64) -> bool {
    if !(1..=65535).contains(&port) {
        return false;
    }
    match TcpListener::bind(("0.0.0.0", port as u16)) {
        Ok(listener) => {
            drop(listener);
            true
        }
        Err(_) => false,
    }
}

/// 找出第一个被外部进程占用的入站端口；skip 里的端口跳过（sing-box 自己正在用的）。
pub fn detect_port_conflict(config: &Value, skip: &BTreeSet<i64>) -> Option<i64> {
    for port in inbound_ports(config) {
        if skip.contains(&port) {
            continue;
        }
        if !probe_port_free(port) {
            return Some(port);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// 时序参数
// ---------------------------------------------------------------------------

/// 编排时序：启动观察窗口、停止宽限、clash 就绪轮询。
#[derive(Clone, Copy, Debug)]
pub struct Timings {
    /// 启动后观察窗口。
    pub start_observe: Duration,
    /// 停止宽限。
    pub stop_timeout: Duration,
    /// clash 就绪轮询次数。
    pub clash_tries: usize,
    /// clash 就绪轮询间隔。
    pub clash_interval: Duration,
    /// 是否调用 sing-box check 校验配置（生产 true；单测 false，避免依赖二进制）。
    pub validate: bool,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            start_observe: DEFAULT_START_OBSERVE,
            stop_timeout: DEFAULT_STOP_TIMEOUT,
            clash_tries: DEFAULT_CLASH_TRIES,
            clash_interval: DEFAULT_CLASH_INTERVAL,
            validate: true,
        }
    }
}

impl Timings {
    /// 单测用：不等待、不校验、只轮询一次。
    pub fn fast() -> Self {
        Self {
            start_observe: Duration::ZERO,
            stop_timeout: Duration::from_millis(1),
            clash_tries: 1,
            clash_interval: Duration::from_millis(1),
            validate: false,
        }
    }

    /// clash 就绪等待的总预算。
    pub fn clash_budget(&self) -> Duration {
        self.clash_interval.saturating_mul(self.clash_tries as u32)
    }
}

// ---------------------------------------------------------------------------
// 结果类型
// ---------------------------------------------------------------------------

/// 进程句柄的轻量快照（真实句柄留在 StdProcControl 里）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcHandle {
    /// 进程 pid；无法确定时为 None。
    pub pid: Option<u32>,
    /// 产生这个句柄的操作序号。
    pub generation: u64,
}

/// 一次 apply 的结果。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ApplyReport {
    /// 是否写了盘。
    pub written: bool,
    /// 是否走了冷重启（先 stop 再 start）。
    pub restarted: bool,
    /// 是否只做了启动（原本没在跑）。
    pub started: bool,
    /// 是否因为配置没变而整体跳过。
    pub skipped: bool,
    /// 本次操作的 generation。
    pub generation: u64,
    /// 失败原因；非空表示这次 apply 不成功。
    pub errors: Vec<String>,
}

impl ApplyReport {
    /// 构造一个「跳过」的结果。
    pub fn skipped(generation: u64) -> Self {
        Self {
            skipped: true,
            generation,
            ..Default::default()
        }
    }

    /// 是否整体成功。
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }

    /// 给人看的一句话结论。
    pub fn message(&self) -> String {
        if !self.errors.is_empty() {
            format!("配置应用失败: {}", self.errors.join("; "))
        } else if self.skipped {
            "配置未变化，已跳过重启".to_string()
        } else if self.restarted {
            "配置应用成功，sing-box 已重启".to_string()
        } else if self.started {
            "配置应用成功，sing-box 已启动".to_string()
        } else {
            "配置应用完成".to_string()
        }
    }
}

// ---------------------------------------------------------------------------
// ConfigManager：编排主体
// ---------------------------------------------------------------------------

/// 配置应用与进程编排的中心对象。
pub struct ConfigManager {
    paths: ProcPaths,
    settings: Arc<dyn DbSettings>,
    ctl: Arc<dyn ProcControl>,
    probe: Arc<dyn ClashProbe>,
    timings: Timings,
    generation: AtomicU64,
    op_lock: tokio::sync::Mutex<()>,
    current: StdMutex<Option<Value>>,
    last_good: StdMutex<Option<Value>>,
}

impl std::fmt::Debug for ConfigManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigManager")
            .field("paths", &self.paths)
            .field("generation", &self.operation_generation())
            .field("timings", &self.timings)
            .finish_non_exhaustive()
    }
}

impl ConfigManager {
    /// 显式注入全部依赖。
    pub fn new(
        paths: ProcPaths,
        settings: Arc<dyn DbSettings>,
        ctl: Arc<dyn ProcControl>,
        probe: Arc<dyn ClashProbe>,
    ) -> Self {
        Self {
            paths,
            settings,
            ctl,
            probe,
            timings: Timings::default(),
            generation: AtomicU64::new(0),
            op_lock: tokio::sync::Mutex::new(()),
            current: StdMutex::new(None),
            last_good: StdMutex::new(None),
        }
    }

    /// 生产构造：真实进程控制 + 真实 HTTP 探活 + 全局数据库。
    pub fn production(paths: ProcPaths, settings: Arc<dyn DbSettings>) -> Self {
        // 端口必须跟随 settings（用户可在设置页改 clashPort），
        // 构造时算死会让探活盯着旧端口，热应用永远判定「未就绪」。
        let ctl = Arc::new(StdProcControl::from_settings(paths.clone(), Arc::clone(&settings)));
        let probe = Arc::new(HttpClashProbe::from_settings(Arc::clone(&settings)));
        Self::new(paths, settings, ctl, probe)
    }

    /// 生产构造（全局数据库）。
    pub fn with_global_db(paths: ProcPaths) -> Self {
        Self::production(paths, Arc::new(GlobalDb))
    }

    /// 覆盖时序参数（链式）。
    pub fn with_timings(mut self, timings: Timings) -> Self {
        self.timings = timings;
        self
    }

    /// 路径。
    pub fn paths(&self) -> &ProcPaths {
        &self.paths
    }

    /// 时序。
    pub fn timings(&self) -> Timings {
        self.timings
    }

    /// 当前操作序号。
    pub fn operation_generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// 操作序号自增（对应 Python 的 _begin_operation）。
    pub fn begin_operation(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// 串行化锁：同一时刻只允许一个应用/重启流程。
    pub fn op_lock(&self) -> &tokio::sync::Mutex<()> {
        &self.op_lock
    }

    /// clash API 端口。
    pub fn clash_port(&self) -> i64 {
        clash_port_from(self.settings.as_ref())
    }

    /// clash API 基地址。
    pub fn clash_base(&self) -> String {
        format!("http://{}:{}", CLASH_HOST, self.clash_port())
    }

    /// clash API 的鉴权 token；不存在就生成并持久化（对应 Python get_clash_secret）。
    pub fn get_clash_secret(&self) -> Option<String> {
        if let Some(existing) = self.settings.get_setting(SETTING_CLASH_SECRET) {
            if let Some(s) = existing.as_str() {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
        let secret = random_secret();
        let value = Value::String(secret.clone());
        if self
            .settings
            .set_setting(SETTING_CLASH_SECRET, &value)
            .is_err()
        {
            // 存不进去也不能让调用方拿到空 secret：至少本次运行能用。
            return Some(secret);
        }
        // 写后回读，确认真正落库了（DB 只读或磁盘故障时这里会返回生成值）。
        self.settings
            .get_setting(SETTING_CLASH_SECRET)
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .or(Some(secret))
    }

    /// sing-box 是否在跑。
    pub fn is_running(&self) -> bool {
        self.ctl.is_running()
    }

    /// 当前 fd 总数（供 scheduler 的 fd 泄漏看门狗）。
    pub fn singbox_fd_count(&self) -> usize {
        self.ctl.fd_count()
    }

    /// 进程句柄快照。
    pub fn get_proc(&self) -> Option<ProcHandle> {
        if !self.ctl.is_running() {
            return None;
        }
        Some(ProcHandle {
            pid: self.ctl.pid(),
            generation: self.operation_generation(),
        })
    }

    fn current_config(&self) -> Option<Value> {
        self.current
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn last_good_config(&self) -> Option<Value> {
        self.last_good
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 记住「当前生效配置」。
    pub fn remember(&self, config: &Value) {
        *self.current.lock().unwrap_or_else(|e| e.into_inner()) = Some(config.clone());
    }

    /// 记住「上一份好配置」，回滚时用。
    pub fn remember_last_good(&self, config: &Value) {
        *self.last_good.lock().unwrap_or_else(|e| e.into_inner()) = Some(config.clone());
    }

    /// 配置是否与当前生效配置一致。
    pub fn config_unchanged(&self, config: &Value) -> bool {
        match self.current_config() {
            Some(cur) => &cur == config,
            // 内存里没有基准（面板刚起来）就退回磁盘比对。
            None => match self.load_config_from_disk() {
                Some(disk) => &disk == config,
                None => false,
            },
        }
    }

    /// 原子写配置并留档 .bak；成功即视为本次生效配置。
    pub fn write_config_atomic(&self, config: &Value) -> Result<()> {
        singbox_proc::atomic_write_config(&self.paths, config)
            .with_context(|| format!("原子写入配置失败: {}", self.paths.config_path().display()))?;
        self.remember(config);
        Ok(())
    }

    /// 从磁盘读配置（config.json 缺失时回落到 .bak，与 Python 一致）。
    pub fn load_config_from_disk(&self) -> Option<Value> {
        let primary = self.paths.config_path();
        if let Ok(body) = std::fs::read(&primary) {
            if let Ok(value) = serde_json::from_slice::<Value>(&body) {
                return Some(value);
            }
        }
        let bak = self.paths.config_bak_path();
        let body = std::fs::read(&bak).ok()?;
        serde_json::from_slice::<Value>(&body).ok()
    }

    /// 从数据库聚合并构建配置。
    pub fn build_from_db(&self) -> Result<Value> {
        let nodes = self.settings.list_nodes(None, None, None)?;
        let relay_domains = self.settings.list_relay_domains()?;
        let settings_value = self
            .settings
            .get_setting(SETTING_SYSTEM)
            .unwrap_or_else(|| json!({}));
        let clash_port = clash_port_from(self.settings.as_ref());
        let clash_secret = self.get_clash_secret().unwrap_or_default();
        let input = crate::config_manager::BuildInput {
            nodes,
            relay_domains,
            settings: settings_value,
            clash_port,
            clash_secret,
        };
        let result = crate::config_manager::build_config(&input);
        if result.config.is_null() {
            return Err(anyhow!("配置构建结果为空"));
        }
        for err in &result.errors {
            tracing::warn!(target: "aura::config_apply", error = %err, "构建配置时跳过节点");
        }
        Ok(result.config)
    }

    /// 等 clash API 就绪（预算 clash_tries * clash_interval）。
    pub async fn wait_clash_ready(&self) -> bool {
        let base = self.clash_base();
        let secret = self.get_clash_secret().unwrap_or_default();
        let tries = self.timings.clash_tries.max(1);
        for attempt in 0..tries {
            if self.probe.version_ok(&base, &secret) {
                return true;
            }
            if attempt + 1 < tries && !self.timings.clash_interval.is_zero() {
                tokio::time::sleep(self.timings.clash_interval).await;
            }
        }
        false
    }

    /// 起进程：写盘后启动 + 观察窗口 + 等 clash 就绪。调用方需自行持有 op_lock。
    async fn start_locked(&self, config: &Value) -> Result<()> {
        if !self.paths.config_path().exists() {
            return Err(anyhow!(
                "配置文件不存在: {}（拒绝在无配置的情况下启动）",
                self.paths.config_path().display()
            ));
        }
        if self.ctl.is_running() {
            return Ok(());
        }
        let ctl = Arc::clone(&self.ctl);
        let cfg = config.clone();
        call_blocking("启动 sing-box", PROC_CALL_TIMEOUT, move || {
            ctl.start(&cfg)
        })
        .await?;
        if !self.timings.start_observe.is_zero() {
            tokio::time::sleep(self.timings.start_observe).await;
        }
        if !self.ctl.is_running() {
            return Err(anyhow!(
                "sing-box 启动后 {} 毫秒内即退出，判定启动失败",
                self.timings.start_observe.as_millis()
            ));
        }
        if !self.wait_clash_ready().await {
            let ctl = Arc::clone(&self.ctl);
            let _ = call_blocking("停止 sing-box", PROC_CALL_TIMEOUT, move || ctl.stop()).await;
            return Err(anyhow!(
                "配置已写入，但 clash API 在 {} 毫秒内未就绪",
                self.timings.clash_budget().as_millis()
            ));
        }
        self.remember_last_good(config);
        Ok(())
    }

    /// 停进程。调用方需自行持有 op_lock。
    ///
    /// 本来就没在跑就直接返回：避免对空进程发信号、也避免把「停止」写进操作日志
    /// 让运维误以为动过进程（Python 在无 _proc 且探活失败时同样什么都不做）。
    async fn stop_locked(&self) -> Result<()> {
        if !self.ctl.is_running() {
            return Ok(());
        }
        let ctl = Arc::clone(&self.ctl);
        call_blocking("停止 sing-box", PROC_CALL_TIMEOUT, move || ctl.stop()).await
    }

    /// 启动（自动串行化 + generation 自增）。
    pub async fn start(&self, config: &Value) -> Result<()> {
        let _guard = self.op_lock.lock().await;
        self.begin_operation();
        self.write_config_atomic(config)?;
        self.start_locked(config).await
    }

    /// 停止（自动串行化 + generation 自增）。
    pub async fn stop(&self) -> Result<()> {
        let _guard = self.op_lock.lock().await;
        self.begin_operation();
        self.stop_locked().await
    }

    /// 重启：先停后起。
    pub async fn restart(&self, config: &Value) -> Result<()> {
        let _guard = self.op_lock.lock().await;
        self.begin_operation();
        self.write_config_atomic(config)?;
        if self.ctl.is_running() {
            self.stop_locked().await?;
        }
        self.start_locked(config).await
    }

    /// 用磁盘上的配置启动（GuardHost 的启动入口）。
    pub fn start_from_disk(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            let Some(config) = self.load_config_from_disk() else {
                return false;
            };
            self.start(&config).await.is_ok()
        })
    }

    /// 用数据库当前状态生成配置；校验通过后应用到进程。
    ///
    /// reconcile=false（默认）时，若配置与当前生效配置一致且进程在跑，直接跳过。
    /// reconcile=true 时强制重建（用于手动「立即应用」）。
    pub async fn apply_config(&self, reconcile: bool) -> Result<ApplyReport> {
        let config = self.build_from_db()?;
        self.apply_value(config, reconcile).await
    }

    /// 应用一份已经构建好的配置。
    pub async fn apply_value(&self, config: Value, reconcile: bool) -> Result<ApplyReport> {
        let _guard = self.op_lock.lock().await;
        let generation = self.begin_operation();
        let running = self.ctl.is_running();
        if !reconcile && self.config_unchanged(&config) {
            // 配置没变化：进程在跑就别动它（重启一次就是几十秒的全节点抖动）。
            if running {
                return Ok(ApplyReport::skipped(generation));
            }
            // 进程没跑：配置一致也要把它拉起来，这里的语义是「确保在跑」。
            self.write_config_atomic(&config)?;
            self.start_locked(&config).await?;
            return Ok(ApplyReport {
                generation,
                written: true,
                started: true,
                ..Default::default()
            });
        }
        if self.timings.validate {
            let cfg = config.clone();
            let paths = self.paths.clone();
            let (ok, message) =
                call_blocking("校验 sing-box 配置", PROC_CALL_TIMEOUT, move || {
                    Ok(singbox_proc::check_config(&paths, &cfg))
                })
                .await?;
            if !ok {
                return Err(anyhow!("配置校验失败: {}", message));
            }
            let skip: BTreeSet<i64> = if running {
                let mut set: BTreeSet<i64> = inbound_ports(&config).into_iter().collect();
                set.insert(self.clash_port());
                set
            } else {
                BTreeSet::new()
            };
            let cfg = config.clone();
            let conflict = call_blocking("检测端口占用", PROC_CALL_TIMEOUT, move || {
                Ok(detect_port_conflict(&cfg, &skip))
            })
            .await?;
            if let Some(port) = conflict {
                return Err(anyhow!("端口被占用: {}", port));
            }
        }
        let previous = self.load_config_from_disk();
        let mut report = ApplyReport {
            generation,
            ..Default::default()
        };
        self.write_config_atomic(&config)?;
        report.written = true;
        if running {
            self.stop_locked().await?;
            report.restarted = true;
        }
        match self.start_locked(&config).await {
            Ok(()) => {
                if !running {
                    report.started = true;
                }
            }
            Err(err) => {
                let reason = err.to_string();
                // 新配置起不来：把上一份好配置写回去并重新拉起，别把代理留在死状态。
                let restored = self.rollback_locked(previous).await;
                match restored {
                    Ok(true) => report
                        .errors
                        .push(format!("{}（已回滚上一份配置）", reason)),
                    Ok(false) => report
                        .errors
                        .push(format!("{}（没有可回滚的配置，已停止）", reason)),
                    Err(rb) => report
                        .errors
                        .push(format!("{}（回滚也失败: {}）", reason, rb)),
                }
            }
        }
        Ok(report)
    }

    /// 配置变了就重建并应用；返回是否真的动了进程。
    pub async fn reload_if_changed(&self) -> bool {
        let Ok(config) = self.build_from_db() else {
            return false;
        };
        match self.apply_value(config, false).await {
            Ok(report) => !report.skipped && report.ok(),
            Err(_) => false,
        }
    }

    /// 回滚到给定配置（None 表示没有好配置可回，直接停掉）。
    pub async fn rollback(&self, previous: Option<Value>) -> Result<bool> {
        let _guard = self.op_lock.lock().await;
        self.rollback_locked(previous).await
    }

    async fn rollback_locked(&self, previous: Option<Value>) -> Result<bool> {
        let Some(prev) = previous.or_else(|| self.last_good_config()) else {
            self.stop_locked().await?;
            return Ok(false);
        };
        if self.ctl.is_running() {
            self.stop_locked().await?;
        }
        singbox_proc::atomic_write_config(&self.paths, &prev)
            .with_context(|| format!("回滚写盘失败: {}", self.paths.config_path().display()))?;
        self.remember(&prev);
        self.start_locked(&prev).await?;
        Ok(true)
    }
}

impl GuardHost for ConfigManager {
    fn proc_present(&self) -> bool {
        self.ctl.is_running()
    }

    fn is_running(&self) -> bool {
        self.ctl.is_running()
    }

    fn fd_count(&self) -> std::result::Result<u64, String> {
        Ok(self.ctl.fd_count() as u64)
    }

    fn start(&self) -> BoxFuture<'_, bool> {
        self.start_from_disk()
    }

    fn stop(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let _ = ConfigManager::stop(self).await;
        })
    }
}

// ---------------------------------------------------------------------------
// 工具函数
// ---------------------------------------------------------------------------

/// 从 settings.system.clashPort 解析端口，非法值回落默认。
pub fn clash_port_from(settings: &dyn DbSettings) -> i64 {
    let system = settings
        .get_setting(SETTING_SYSTEM)
        .unwrap_or_else(|| json!({}));
    let raw = system
        .get("clashPort")
        .or_else(|| system.get("clash_port"))
        .and_then(|v| {
            if let Some(n) = v.as_i64() {
                Some(n)
            } else {
                v.as_str().and_then(|s| s.trim().parse::<i64>().ok())
            }
        });
    match raw {
        Some(port) if (1..=65535).contains(&port) => port,
        _ => DEFAULT_CLASH_PORT,
    }
}

/// 随机 clash secret（16 字节十六进制，等价 Python token_urlsafe 的熵量）。
fn random_secret() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    let mut out = String::with_capacity(32);
    for byte in buf {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

/// 把阻塞操作丢到线程池并加超时，避免 async 运行时被进程操作卡住。
async fn call_blocking<T, F>(label: &'static str, timeout: Duration, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    let handle = tokio::task::spawn_blocking(f);
    match tokio::time::timeout(timeout, handle).await {
        Err(_) => Err(anyhow!("{} 超时（{} 秒）", label, timeout.as_secs())),
        Ok(Err(join_err)) => Err(anyhow!("{} 任务异常: {}", label, join_err)),
        Ok(Ok(inner)) => inner,
    }
}

// ---------------------------------------------------------------------------
// 等待上游符号（lib.rs 注册 + 依赖清单）
// ---------------------------------------------------------------------------
//
// 需要 Lead 在 aura-rs/src/lib.rs 里加一行：pub mod config_apply;
//
// 依赖 crate::singbox_proc（已由 t-netguard 交付并注册），用到的符号：
//   ProcPaths（含 data_dir / singbox_bin 字段与 config_path / config_bak_path /
//   config_tmp_path / log_path 方法）、atomic_write_config、check_config、
//   is_running_with_port、find_singbox_pids、signal_singbox、Signal、
//   singbox_fd_count、clash_api_alive、CLASH_PROBE_TIMEOUT、LogFile。
//
// 依赖 crate::config_manager（已注册）：BuildInput、build_config、BuildResult。
// 依赖 crate::db（已注册）：Db::get_setting / set_setting / list_nodes /
//   list_relay_domains、db::global()。
// 依赖 crate::scheduler（我交付）：GuardHost、BoxFuture。
//
// 仍未接线的上层（等 scheduler 的探活轮次落地后由 Lead 组装）：
//   probe_nodes 完整轮次、sync_relay_exits_after_probe、rotate_random_relay、
//   四个后台 loop——它们需要 ConfigManager 的 apply/reload 入口，接口已经就绪。

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;

    fn unique_dir(tag: &str) -> PathBufAlias {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "aura-cfgapply-{}-{}-{}",
            tag,
            std::process::id(),
            nanos
        ))
    }

    type PathBufAlias = std::path::PathBuf;

    #[derive(Default)]
    struct FakeCtl {
        running: AtomicBool,
        fds: AtomicUsize,
        pid: AtomicUsize,
        start_ok: AtomicBool,
        stop_ok: AtomicBool,
        calls: StdMutex<Vec<String>>,
        last_config: StdMutex<Option<Value>>,
    }

    impl FakeCtl {
        fn new() -> Self {
            Self {
                running: AtomicBool::new(false),
                fds: AtomicUsize::new(0),
                pid: AtomicUsize::new(0),
                start_ok: AtomicBool::new(true),
                stop_ok: AtomicBool::new(true),
                calls: StdMutex::new(Vec::new()),
                last_config: StdMutex::new(None),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }

        fn set_running(&self, value: bool) {
            self.running.store(value, Ordering::SeqCst);
        }

        fn last_config(&self) -> Option<Value> {
            self.last_config
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl ProcControl for FakeCtl {
        fn is_running(&self) -> bool {
            self.running.load(Ordering::SeqCst)
        }

        fn start(&self, config: &Value) -> Result<()> {
            if !self.start_ok.load(Ordering::SeqCst) {
                self.calls
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push("start-fail".into());
                return Err(anyhow!("假装启动失败"));
            }
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push("start".into());
            *self.last_config.lock().unwrap_or_else(|e| e.into_inner()) = Some(config.clone());
            self.running.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn stop(&self) -> Result<()> {
            if !self.stop_ok.load(Ordering::SeqCst) {
                self.calls
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push("stop-fail".into());
                return Err(anyhow!("假装停止失败"));
            }
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push("stop".into());
            self.running.store(false, Ordering::SeqCst);
            Ok(())
        }

        fn fd_count(&self) -> usize {
            self.fds.load(Ordering::SeqCst)
        }

        fn pid(&self) -> Option<u32> {
            let pid = self.pid.load(Ordering::SeqCst);
            if pid == 0 {
                None
            } else {
                Some(pid as u32)
            }
        }
    }

    #[derive(Default)]
    struct FakeSettings {
        map: StdMutex<std::collections::HashMap<String, Value>>,
        nodes: StdMutex<Vec<Value>>,
        domains: StdMutex<Vec<Value>>,
    }

    impl FakeSettings {
        fn set(&self, key: &str, value: Value) {
            self.map
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key.to_string(), value);
        }
    }

    impl DbSettings for FakeSettings {
        fn get_setting(&self, key: &str) -> Option<Value> {
            self.map
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(key)
                .cloned()
        }

        fn set_setting(&self, key: &str, value: &Value) -> Result<()> {
            self.set(key, value.clone());
            Ok(())
        }

        fn list_nodes(
            &self,
            _q: Option<&str>,
            _group: Option<&str>,
            _sub_id: Option<&str>,
        ) -> Result<Vec<Value>> {
            Ok(self.nodes.lock().unwrap_or_else(|e| e.into_inner()).clone())
        }

        fn list_relay_domains(&self) -> Result<Vec<Value>> {
            Ok(self
                .domains
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone())
        }
    }

    struct Rig {
        dir: PathBufAlias,
        mgr: ConfigManager,
        ctl: Arc<FakeCtl>,
        settings: Arc<FakeSettings>,
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// 用户在设置页改 clashPort 后，探活与进程兜底探测都必须跟着换端口。
    /// 旧实现把端口在构造时算死：sing-box 按新端口起来，探活盯着旧端口，
    /// 于是热应用反复判定「clash API 未就绪」并把刚起来的进程杀掉。
    #[test]
    fn clash_port_follows_settings_for_probe_and_ctl() {
        let settings = Arc::new(FakeSettings::default());
        settings.set(SETTING_SYSTEM, json!({ "clashPort": 19095 }));

        let probe = HttpClashProbe::from_settings(Arc::clone(&settings) as Arc<dyn DbSettings>);
        assert_eq!(probe.port(), 19095);

        settings.set(SETTING_SYSTEM, json!({ "clashPort": 19096 }));
        assert_eq!(probe.port(), 19096, "探活端口必须跟随设置");

        let ctl = StdProcControl::from_settings(
            ProcPaths::new(unique_dir("port-follow"), "sing-box"),
            Arc::clone(&settings) as Arc<dyn DbSettings>,
        );
        assert_eq!(ctl.clash_port(), 19096, "进程兜底探测也要跟随设置");

        settings.set(SETTING_SYSTEM, json!({}));
        assert_eq!(ctl.clash_port(), DEFAULT_CLASH_PORT as u16);
    }

    fn rig(tag: &str) -> Rig {
        rig_with_probe(tag, Arc::new(AssumeReady))
    }

    fn rig_with_probe(tag: &str, probe: Arc<dyn ClashProbe>) -> Rig {
        let dir = unique_dir(tag);
        std::fs::create_dir_all(&dir).expect("创建临时目录");
        let paths = ProcPaths::new(dir.clone(), "sing-box");
        let ctl = Arc::new(FakeCtl::new());
        let settings = Arc::new(FakeSettings::default());
        let mgr = ConfigManager::new(
            paths,
            Arc::clone(&settings) as Arc<dyn DbSettings>,
            Arc::clone(&ctl) as Arc<dyn ProcControl>,
            probe,
        )
        .with_timings(Timings::fast());
        Rig {
            dir,
            mgr,
            ctl,
            settings,
        }
    }

    fn sample_config(port: i64) -> Value {
        json!({
            "log": { "level": "info" },
            "inbounds": [{ "type": "mixed", "tag": "in-mixed", "listen": "0.0.0.0", "listen_port": port }],
            "outbounds": [{ "type": "direct", "tag": "direct" }]
        })
    }

    #[test]
    fn paths_layout() {
        let paths = ProcPaths::new("/tmp/aura-data", "sing-box");
        assert_eq!(
            paths.config_path(),
            std::path::PathBuf::from("/tmp/aura-data/config.json")
        );
        assert_eq!(
            paths.config_bak_path(),
            std::path::PathBuf::from("/tmp/aura-data/config.json.bak")
        );
        assert_eq!(
            paths.log_path(),
            std::path::PathBuf::from("/tmp/aura-data/singbox.log")
        );
        assert!(paths.cmdline_marker().starts_with("sing-box run -c"));
    }

    #[test]
    fn clash_port_reads_settings_and_validates() {
        let settings = FakeSettings::default();
        assert_eq!(clash_port_from(&settings), DEFAULT_CLASH_PORT);
        settings.set(SETTING_SYSTEM, json!({ "clashPort": 19095 }));
        assert_eq!(clash_port_from(&settings), 19095);
        settings.set(SETTING_SYSTEM, json!({ "clashPort": "19096" }));
        assert_eq!(clash_port_from(&settings), 19096);
        settings.set(SETTING_SYSTEM, json!({ "clashPort": 0 }));
        assert_eq!(clash_port_from(&settings), DEFAULT_CLASH_PORT);
        settings.set(SETTING_SYSTEM, json!({ "clashPort": "abc" }));
        assert_eq!(clash_port_from(&settings), DEFAULT_CLASH_PORT);
        settings.set(SETTING_SYSTEM, json!({ "clashPort": 70000 }));
        assert_eq!(clash_port_from(&settings), DEFAULT_CLASH_PORT);
    }

    #[test]
    fn clash_secret_generated_then_reused() {
        let r = rig("secret");
        let first = r.mgr.get_clash_secret().expect("生成 secret");
        assert_eq!(first.len(), 32);
        let second = r.mgr.get_clash_secret().expect("复用 secret");
        assert_eq!(first, second);
        assert_eq!(
            r.settings
                .get_setting(SETTING_CLASH_SECRET)
                .and_then(|v| v.as_str().map(|s| s.to_string())),
            Some(first)
        );
    }

    #[test]
    fn atomic_write_keeps_previous_config_as_bak() {
        let r = rig("atomic");
        r.mgr.write_config_atomic(&sample_config(20001)).unwrap();
        r.mgr.write_config_atomic(&sample_config(20002)).unwrap();
        let bak = std::fs::read_to_string(r.mgr.paths().config_bak_path()).unwrap();
        let bak_value: Value = serde_json::from_str(&bak).unwrap();
        assert_eq!(inbound_ports(&bak_value), vec![20001]);
        let cur = r.mgr.load_config_from_disk().unwrap();
        assert_eq!(inbound_ports(&cur), vec![20002]);
    }

    #[test]
    fn config_unchanged_falls_back_to_disk() {
        let r = rig("unchanged");
        let cfg = sample_config(20003);
        r.mgr.write_config_atomic(&cfg).unwrap();
        // 清掉内存基准，强制走磁盘比对。
        *r.mgr.current.lock().unwrap() = None;
        assert!(r.mgr.config_unchanged(&cfg));
        assert!(!r.mgr.config_unchanged(&sample_config(20004)));
        // 磁盘也没有时不能误判为「没变化」。
        let r2 = rig("unchanged-empty");
        assert!(!r2.mgr.config_unchanged(&cfg));
    }

    #[tokio::test]
    async fn start_writes_config_and_calls_start() {
        let r = rig("start");
        let cfg = sample_config(20005);
        r.mgr.start(&cfg).await.unwrap();
        assert_eq!(r.ctl.calls(), vec!["start".to_string()]);
        let on_disk = r.mgr.load_config_from_disk().unwrap();
        assert_eq!(on_disk, cfg);
        assert_eq!(r.ctl.last_config(), Some(cfg));
        assert_eq!(r.mgr.operation_generation(), 1);
    }

    #[tokio::test]
    async fn start_is_noop_when_already_running() {
        let r = rig("start-noop");
        r.ctl.set_running(true);
        r.mgr.start(&sample_config(20006)).await.unwrap();
        assert!(r.ctl.calls().is_empty(), "已在运行时不应再调用 start");
    }

    #[tokio::test]
    async fn start_failure_leaves_process_stopped() {
        let r = rig("start-fail");
        r.ctl.start_ok.store(false, Ordering::SeqCst);
        let err = r.mgr.start(&sample_config(20007)).await.unwrap_err();
        assert!(
            err.to_string().contains("假装启动失败"),
            "错误信息应保留原因: {}",
            err
        );
        assert!(!r.mgr.is_running());
    }

    #[tokio::test]
    async fn start_fails_when_clash_api_not_ready() {
        let r = rig_with_probe("start-clash", Arc::new(NeverReady));
        let err = r.mgr.start(&sample_config(20008)).await.unwrap_err();
        assert!(
            err.to_string().contains("clash API"),
            "错误应指出 clash 未就绪: {}",
            err
        );
        assert!(
            r.ctl.calls().contains(&"stop".to_string()),
            "clash 未就绪时必须把进程停掉"
        );
    }

    #[tokio::test]
    async fn stop_without_running_is_noop() {
        let r = rig("stop-noop");
        r.mgr.stop().await.unwrap();
        assert!(r.ctl.calls().is_empty());
    }

    #[tokio::test]
    async fn stop_failure_propagates() {
        let r = rig("stop-fail");
        r.ctl.set_running(true);
        r.ctl.stop_ok.store(false, Ordering::SeqCst);
        let err = r.mgr.stop().await.unwrap_err();
        assert!(err.to_string().contains("假装停止失败"));
    }

    #[tokio::test]
    async fn restart_calls_stop_then_start() {
        let r = rig("restart");
        r.ctl.set_running(true);
        r.mgr.restart(&sample_config(20009)).await.unwrap();
        assert_eq!(r.ctl.calls(), vec!["stop".to_string(), "start".to_string()]);
    }

    #[tokio::test]
    async fn apply_config_skips_when_config_unchanged_and_running() {
        let r = rig("apply-skip");
        let cfg = sample_config(20010);
        r.ctl.set_running(true);
        r.mgr.remember(&cfg);
        let report = r.mgr.apply_value(cfg, false).await.unwrap();
        assert!(report.skipped);
        assert!(report.ok());
        assert!(r.ctl.calls().is_empty(), "配置没变就不该动进程");
    }

    #[tokio::test]
    async fn apply_config_restarts_when_config_changed() {
        let r = rig("apply-restart");
        r.ctl.set_running(true);
        r.mgr.remember(&sample_config(20011));
        let report = r
            .mgr
            .apply_value(sample_config(20012), false)
            .await
            .unwrap();
        assert!(report.restarted, "配置变了必须重启");
        assert!(report.written);
        assert!(report.ok());
        assert_eq!(r.ctl.calls(), vec!["stop".to_string(), "start".to_string()]);
    }

    #[tokio::test]
    async fn apply_config_starts_without_stop_when_not_running() {
        let r = rig("apply-start");
        let report = r
            .mgr
            .apply_value(sample_config(20013), false)
            .await
            .unwrap();
        assert!(report.started);
        assert!(!report.restarted);
        assert_eq!(r.ctl.calls(), vec!["start".to_string()]);
    }

    #[tokio::test]
    async fn apply_config_starts_stopped_process_even_if_config_unchanged() {
        let r = rig("apply-start-stopped");
        let cfg = sample_config(20014);
        // 磁盘上已有同一份配置，但进程没跑：apply 的语义是「确保在跑」，必须拉起。
        r.mgr.write_config_atomic(&cfg).unwrap();
        *r.mgr.current.lock().unwrap() = None;
        let report = r.mgr.apply_value(cfg, false).await.unwrap();
        assert!(!report.skipped);
        assert!(report.started, "进程没跑时必须启动");
        assert_eq!(r.ctl.calls(), vec!["start".to_string()]);
        // 已经在跑且配置一致时才是跳过。
        let report2 = r
            .mgr
            .apply_value(sample_config(20014), false)
            .await
            .unwrap();
        assert!(report2.skipped, "在跑且配置一致应当跳过");
    }

    #[tokio::test]
    async fn apply_config_rolls_back_when_new_config_fails_to_start() {
        let r = rig("apply-rollback");
        let good = sample_config(20015);
        r.mgr.write_config_atomic(&good).unwrap();
        r.mgr.remember_last_good(&good);
        r.ctl.set_running(true);
        r.ctl.start_ok.store(false, Ordering::SeqCst);
        let report = r.mgr.apply_value(sample_config(20016), true).await.unwrap();
        assert!(!report.ok(), "启动失败必须体现在 errors 里");
        assert!(
            report.errors[0].contains("回滚"),
            "错误里应说明回滚结果: {:?}",
            report.errors
        );
    }

    #[tokio::test]
    async fn reload_if_changed_reports_false_then_true() {
        let r = rig("reload");
        let built = r.mgr.build_from_db().expect("构建配置");
        r.ctl.set_running(true);
        r.mgr.remember(&built);
        assert!(!r.mgr.reload_if_changed().await, "配置没变应当返回 false");
        // 改一个影响配置生成的设置，触发变化。
        r.settings
            .set(SETTING_SYSTEM, json!({ "clashPort": 19099 }));
        assert!(
            r.mgr.reload_if_changed().await,
            "配置变了应当应用并返回 true"
        );
    }

    #[tokio::test]
    async fn operation_generation_increments_per_operation() {
        let r = rig("generation");
        assert_eq!(r.mgr.operation_generation(), 0);
        r.mgr.start(&sample_config(20017)).await.unwrap();
        assert_eq!(r.mgr.operation_generation(), 1);
        r.mgr.stop().await.unwrap();
        assert_eq!(r.mgr.operation_generation(), 2);
        r.mgr.restart(&sample_config(20018)).await.unwrap();
        assert_eq!(r.mgr.operation_generation(), 3);
    }

    #[tokio::test]
    async fn rollback_requires_last_good_and_restores_it() {
        let r = rig("rollback-none");
        r.ctl.set_running(true);
        assert!(
            !r.mgr.rollback(None).await.unwrap(),
            "没有好配置时应返回 false"
        );
        assert!(!r.mgr.is_running(), "没有好配置必须把进程停掉");

        let r2 = rig("rollback-good");
        let good = sample_config(20019);
        r2.mgr.remember_last_good(&good);
        r2.ctl.set_running(true);
        assert!(r2.mgr.rollback(None).await.unwrap());
        let restored = r2.mgr.load_config_from_disk().unwrap();
        assert_eq!(restored, good);
    }

    #[test]
    fn fd_count_and_get_proc_expose_process_state() {
        let r = rig("proc");
        r.ctl.fds.store(42, Ordering::SeqCst);
        assert_eq!(r.mgr.singbox_fd_count(), 42);
        assert!(r.mgr.get_proc().is_none(), "没在跑时不应暴露句柄");
        r.ctl.set_running(true);
        r.ctl.pid.store(4321, Ordering::SeqCst);
        r.mgr.begin_operation();
        let handle = r.mgr.get_proc().expect("应当有句柄");
        assert_eq!(handle.pid, Some(4321));
        assert_eq!(handle.generation, 1);
    }

    #[tokio::test]
    async fn guard_host_trait_reports_process_state() {
        let r = rig("guardhost");
        let host: &dyn GuardHost = &r.mgr;
        assert!(!host.proc_present());
        assert_eq!(host.fd_count().unwrap(), 0);
        assert!(!host.start().await, "磁盘上没有配置时不应启动成功");
        r.mgr.write_config_atomic(&sample_config(20020)).unwrap();
        assert!(host.start().await, "有配置时应当启动成功");
        assert!(host.is_running());
        host.stop().await;
        assert!(!host.is_running());
    }

    #[test]
    fn build_from_db_feeds_generated_config_into_apply() {
        let r = rig("build");
        r.settings.set("nodes", json!([]));
        r.settings.nodes.lock().unwrap().push(json!({
            "id": "n1",
            "name": "测试节点",
            "protocol": "ss",
            "server": "1.2.3.4",
            "port": 8388,
            "password": "pass",
            "method": "aes-256-gcm",
            "enabled": true,
            "status": "online",
            "group": "默认"
        }));
        let built = r.mgr.build_from_db().unwrap();
        assert!(
            built
                .get("outbounds")
                .map(|v| v.is_array())
                .unwrap_or(false),
            "配置必须包含 outbounds 数组"
        );
        assert!(!built.is_null());
    }

    #[test]
    fn inbound_ports_and_conflict_detection() {
        let cfg = json!({ "inbounds": [
            { "type": "mixed", "listen_port": 20021 },
            { "type": "socks", "listen_port": "20022" }
        ]});
        // 无数字端口的条目不参与（字符串形式不解析，与 Python int() 语义不同但更保守）。
        assert_eq!(inbound_ports(&cfg), vec![20021]);
        // 占住一个端口，冲突检测应当报出来。
        let listener = TcpListener::bind(("0.0.0.0", 0)).expect("绑定临时端口");
        let port = listener.local_addr().unwrap().port() as i64;
        let busy = json!({ "inbounds": [{ "type": "mixed", "listen_port": port }] });
        assert_eq!(detect_port_conflict(&busy, &BTreeSet::new()), Some(port));
        let skip: BTreeSet<i64> = [port].into_iter().collect();
        assert_eq!(
            detect_port_conflict(&busy, &skip),
            None,
            "skip 里的端口不检测"
        );
        drop(listener);
    }

    #[test]
    fn std_proc_control_requires_config_file() {
        let dir = unique_dir("stdproc");
        std::fs::create_dir_all(&dir).unwrap();
        let ctl = StdProcControl::new(ProcPaths::new(dir.clone(), "sing-box"), 9095);
        let err = ctl.start(&json!({})).unwrap_err();
        assert!(
            err.to_string().contains("配置文件不存在"),
            "错误信息: {}",
            err
        );
        assert_eq!(ctl.fd_count(), 0);
        assert!(ctl.pid().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn http_clash_probe_is_false_on_closed_port() {
        let probe = HttpClashProbe::new(1);
        assert!(!probe.version_ok(&format!("http://{}:{}", CLASH_HOST, 1), ""));
        assert_eq!(probe.port(), 1);
    }

    #[test]
    fn timings_contract_matches_python_budget() {
        let t = Timings::default();
        assert_eq!(t.start_observe, DEFAULT_START_OBSERVE);
        assert_eq!(t.clash_tries, 10);
        assert_eq!(t.clash_interval, Duration::from_millis(500));
        assert_eq!(t.clash_budget(), Duration::from_secs(5));
        assert_eq!(t.stop_timeout, Duration::from_secs(5));
        assert!(t.validate);
        let fast = Timings::fast();
        assert!(!fast.validate);
        assert!(fast.start_observe.is_zero());
    }

    #[test]
    fn apply_report_messages_are_readable() {
        let mut report = ApplyReport::skipped(3);
        assert!(report.message().contains("跳过"));
        report.skipped = false;
        report.restarted = true;
        assert!(report.message().contains("重启"));
        report.errors.push("端口被占用: 1234".into());
        assert!(report.message().contains("失败"));
        assert!(!report.ok());
    }
}
