//! sing-box 子进程与配置文件的托管层。
//!
//! 对应 backend/config_manager.py 里与 sing-box 进程/文件相关的那一组函数：
//! - 进程发现（扫 /proc/*/cmdline）、fd 计数、信号投递
//! - 配置校验（sing-box check）、原子写、.bak 留档
//! - 运行状态探测（/proc + clash API 兜底）
//! - 日志文件打开与轮转（单文件 20MiB，保留 2 份副本）
//! - 版本号读取
//!
//! 设计约束：
//! 1) 一切外部命令都带超时，失败/超时返回明确错误，绝不 panic；
//! 2) 路径与二进制名由 ProcPaths 注入，便于测试（测试不许真的调用 sing-box）；
//! 3) 日志轮转的阈值与副本数都是参数，便于单测。

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

/// 覆盖 sing-box 二进制名的环境变量（与 Python 版同名）。
pub const SINGBOX_BIN_ENV: &str = "SINGBOX_BIN";
/// 覆盖数据目录的环境变量（Python 版写死 backend/data，这里允许注入）。
pub const DATA_DIR_ENV: &str = "AURA_DATA_DIR";
/// 默认 sing-box 二进制名（走 PATH 查找）。
pub const DEFAULT_SINGBOX_BIN: &str = "sing-box";
/// 默认数据目录（相对当前工作目录）。
pub const DEFAULT_DATA_DIR: &str = "data";
/// clash API 绑定地址（host 网络下容器内外一致）。
pub const CLASH_HOST: &str = "127.0.0.1";
/// clash API 默认端口（面板设置里的 clashPort 可覆盖，这里只给默认值）。
pub const CLASH_PORT: u16 = 9095;
/// 单个日志文件的上限：20MiB。
pub const LOG_MAX_BYTES: u64 = 20 * 1024 * 1024;
/// 日志轮转副本数：singbox.log.1 / singbox.log.2。
pub const LOG_BACKUP_COUNT: usize = 2;
/// sing-box check 超时（与 Python subprocess.run(timeout=20) 一致）。
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(20);
/// sing-box version 超时（与 Python timeout=10 一致）。
pub const VERSION_TIMEOUT: Duration = Duration::from_secs(10);
/// pkill 兜底超时（与 Python timeout=5 一致）。
pub const PKILL_TIMEOUT: Duration = Duration::from_secs(5);
/// clash API 探活超时（与 Python urllib timeout=1 一致）。
pub const CLASH_PROBE_TIMEOUT: Duration = Duration::from_secs(1);
/// procfs 挂载点；无 /proc 的平台（macOS）扫不到任何进程，返回空。
pub const PROC_ROOT: &str = "/proc";
/// 命令行特征前缀：进程发现与信号投递都靠它（不依赖 pkill/ps，slim 镜像也能用）。
pub const CMDLINE_PREFIX: &str = "sing-box run -c";

// ---------------------------------------------------------------------------
// 路径与二进制名
// ---------------------------------------------------------------------------

/// 进程/文件层用到的所有路径与二进制名。全部通过它注入，测试里指向临时目录。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcPaths {
    /// 数据目录，配置与日志都落在这里。
    pub data_dir: PathBuf,
    /// sing-box 二进制名或绝对路径（对应 Python 的 SINGBOX_BIN）。
    pub singbox_bin: String,
}

impl ProcPaths {
    /// 显式构造。
    pub fn new(data_dir: impl Into<PathBuf>, singbox_bin: impl Into<String>) -> Self {
        Self {
            data_dir: data_dir.into(),
            singbox_bin: singbox_bin.into(),
        }
    }

    /// 从环境变量读取：SINGBOX_BIN 覆盖二进制名，AURA_DATA_DIR 覆盖数据目录。
    pub fn from_env() -> Self {
        let bin = std::env::var(SINGBOX_BIN_ENV)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_SINGBOX_BIN.to_string());
        let data_dir = std::env::var(DATA_DIR_ENV)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR));
        Self::new(data_dir, bin)
    }

    /// data/config.json
    pub fn config_path(&self) -> PathBuf {
        self.data_dir.join("config.json")
    }

    /// data/config.json.bak
    pub fn config_bak_path(&self) -> PathBuf {
        self.data_dir.join("config.json.bak")
    }

    /// data/config.json.tmp（原子写的中转文件）
    pub fn config_tmp_path(&self) -> PathBuf {
        self.data_dir.join("config.json.tmp")
    }

    /// data/.check.json（sing-box check 的临时校验文件）
    pub fn check_tmp_path(&self) -> PathBuf {
        self.data_dir.join(".check.json")
    }

    /// data/singbox.log
    pub fn log_path(&self) -> PathBuf {
        self.data_dir.join("singbox.log")
    }

    /// data/singbox.log.<index>
    pub fn log_backup_path(&self, index: usize) -> PathBuf {
        PathBuf::from(format!("{}.{}", self.log_path().to_string_lossy(), index))
    }

    /// 进程命令行特征：sing-box run -c <绝对/注入的 config.json 路径>。
    ///
    /// 与 Python 一致：前缀固定是字面量 sing-box run -c，即使 SINGBOX_BIN 是
    /// 绝对路径，实际 cmdline 里同样包含这段子串，所以照样能命中。
    pub fn cmdline_marker(&self) -> String {
        format!(
            "{} {}",
            CMDLINE_PREFIX,
            self.config_path().to_string_lossy()
        )
    }
}

// ---------------------------------------------------------------------------
// 外部命令执行（带超时，不 panic）
// ---------------------------------------------------------------------------

/// 一次外部命令的执行结果。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CmdOutput {
    /// 退出码；被超时杀掉时为 None。
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    /// 是否因为超时被杀。
    pub timed_out: bool,
}

impl CmdOutput {
    /// 命令是否正常退出（未被超时杀掉且退出码为 0）。
    pub fn is_success(&self) -> bool {
        !self.timed_out && self.code == Some(0)
    }
}

/// 外部命令无法启动/执行时的错误。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CmdError {
    /// 无法启动进程（二进制不存在、权限不足等），内含可读原因。
    Spawn(String),
    /// 启动后与子进程交互出错。
    Io(String),
}

impl std::fmt::Display for CmdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CmdError::Spawn(msg) => write!(f, "{}", msg),
            CmdError::Io(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for CmdError {}

/// 执行外部命令并等待，超时则杀掉子进程。
///
/// stdout/stderr 由独立线程排空，避免子进程写满管道后卡死（Python 用
/// subprocess.run(capture_output=True) 是内部同一套逻辑）。
pub fn run_with_timeout(
    bin: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<CmdOutput, CmdError> {
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| CmdError::Spawn(format!("{}: {}", bin, e)))?;

    let stdout_thread = child.stdout.take().map(spawn_drain);
    let stderr_thread = child.stderr.take().map(spawn_drain);

    let started = Instant::now();
    let mut timed_out = false;
    let code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break None;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(CmdError::Io(e.to_string())),
        }
    };

    Ok(CmdOutput {
        code,
        stdout: join_drain(stdout_thread),
        stderr: join_drain(stderr_thread),
        timed_out,
    })
}

fn spawn_drain<R: Read + Send + 'static>(mut pipe: R) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        buf
    })
}

fn join_drain(handle: Option<std::thread::JoinHandle<Vec<u8>>>) -> String {
    match handle.and_then(|h| h.join().ok()) {
        Some(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        None => String::new(),
    }
}

// ---------------------------------------------------------------------------
// 进程发现 / fd 计数 / 信号
// ---------------------------------------------------------------------------

/// 找出本面板的 sing-box 进程 pid。
///
/// 与 Python 一致：直接扫 /proc/<pid>/cmdline，按命令行特征匹配；无 /proc 的
/// 平台（macOS）返回空列表。
pub fn find_singbox_pids(paths: &ProcPaths) -> Vec<i32> {
    find_singbox_pids_in(Path::new(PROC_ROOT), &paths.cmdline_marker())
}

/// find_singbox_pids 的可测版本：proc_root 可注入。
pub fn find_singbox_pids_in(proc_root: &Path, marker: &str) -> Vec<i32> {
    let mut pids = Vec::new();
    let entries = match std::fs::read_dir(proc_root) {
        Ok(entries) => entries,
        Err(_) => return pids,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy().to_string();
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid: i32 = match name.parse() {
            Ok(pid) => pid,
            Err(_) => continue,
        };
        let raw = match std::fs::read(proc_root.join(&name).join("cmdline")) {
            Ok(raw) => raw,
            Err(_) => continue,
        };
        let cmd = cmdline_to_string(&raw);
        if cmd.contains(marker) {
            pids.push(pid);
        }
    }
    pids
}

/// /proc/<pid>/cmdline 是 NUL 分隔的字节串：先换成分隔空格再按 UTF-8 有损解码，
/// 等价于 Python 的 replace(b"\x00", b" ").decode(errors="ignore")。
fn cmdline_to_string(raw: &[u8]) -> String {
    let spaced: Vec<u8> = raw
        .iter()
        .map(|b| if *b == 0 { b' ' } else { *b })
        .collect();
    String::from_utf8_lossy(&spaced).into_owned()
}

/// 单个 pid 打开的 fd 数；进程已消失/无权限时返回 0。
pub fn fd_count_of(proc_root: &Path, pid: i32) -> usize {
    match std::fs::read_dir(proc_root.join(pid.to_string()).join("fd")) {
        Ok(entries) => entries.flatten().count(),
        Err(_) => 0,
    }
}

/// 本面板 sing-box 当前打开的 fd 总数（正常约 20；连接泄漏时会涨到上千）。
pub fn singbox_fd_count(paths: &ProcPaths) -> usize {
    singbox_fd_count_in(Path::new(PROC_ROOT), paths)
}

/// singbox_fd_count 的可测版本：proc_root 可注入。
pub fn singbox_fd_count_in(proc_root: &Path, paths: &ProcPaths) -> usize {
    find_singbox_pids_in(proc_root, &paths.cmdline_marker())
        .into_iter()
        .map(|pid| fd_count_of(proc_root, pid))
        .sum()
}

/// 投递给 sing-box 的信号（只暴露实际会用到的几种）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    /// 热重载配置。
    Hup,
    /// 中断。
    Int,
    /// 正常终止。
    Term,
    /// 强制终止。
    Kill,
}

impl Signal {
    /// 数值信号（与 libc 定义一致）。
    pub fn as_i32(self) -> i32 {
        match self {
            Signal::Hup => 1,
            Signal::Int => 2,
            Signal::Term => 15,
            Signal::Kill => 9,
        }
    }

    /// Python 侧的写法（日志/错误信息里用）。
    pub fn py_name(self) -> &'static str {
        match self {
            Signal::Hup => "SIGHUP",
            Signal::Int => "SIGINT",
            Signal::Term => "SIGTERM",
            Signal::Kill => "SIGKILL",
        }
    }

    /// pkill 的短信号名参数。Python 里 f"-{signal.Signals(sig).name}" 实际拼出
    /// -SIGHUP，注释意图是 -HUP；短名在 procps 与 BSD 上都更稳，这里用短名。
    pub fn pkill_flag(self) -> &'static str {
        match self {
            Signal::Hup => "-HUP",
            Signal::Int => "-INT",
            Signal::Term => "-TERM",
            Signal::Kill => "-KILL",
        }
    }
}

/// 向本面板的 sing-box 进程投递信号，返回命中数。
///
/// Linux 走 /proc 扫描 + libc::kill；一个都没命中（或无 /proc 的 macOS）时用
/// pkill -f 按完整命令行兜底。命中数 0 时调用方应降级处理（如冷重启）。
pub fn signal_singbox(paths: &ProcPaths, sig: Signal) -> usize {
    let mut hits = 0usize;
    for pid in find_singbox_pids(paths) {
        if send_signal(pid, sig) {
            hits += 1;
        }
    }
    if hits > 0 {
        return hits;
    }
    pkill_fallback(&paths.cmdline_marker(), sig)
}

fn send_signal(pid: i32, sig: Signal) -> bool {
    #[cfg(unix)]
    {
        // SAFETY: kill(2) 只读取两个整型参数，不涉及指针，失败返回 -1。
        unsafe { libc::kill(pid as libc::pid_t, sig.as_i32()) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = (pid, sig);
        false
    }
}

/// pkill 兜底：退出码 0 视为命中 1 个。
pub fn pkill_fallback(marker: &str, sig: Signal) -> usize {
    match run_with_timeout("pkill", &[sig.pkill_flag(), "-f", marker], PKILL_TIMEOUT) {
        Ok(out) if out.is_success() => 1,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// 运行状态探测
// ---------------------------------------------------------------------------

/// sing-box 是否在跑：先看 /proc（本机可见），再用 clash API 探活兜底。
///
/// Python 版先看托管进程对象 + wait 任务，再探 clash API；Rust 侧没有托管句柄，
/// 进程发现即等价于「进程对象存在」。
pub fn is_running(paths: &ProcPaths) -> bool {
    is_running_with_port(paths, CLASH_PORT)
}

/// is_running 的可测版本：clash 端口可注入。
pub fn is_running_with_port(paths: &ProcPaths, clash_port: u16) -> bool {
    if !find_singbox_pids(paths).is_empty() {
        return true;
    }
    clash_api_alive(clash_port, CLASH_PROBE_TIMEOUT)
}

/// 粗粒度 clash API 探活：连上并发出 GET /version，收到任意 HTTP 响应即视为活着。
///
/// 只用来判断「端口后面有个 HTTP 服务」，不校验响应码，也不带 Authorization
/// （secret 存在 DB 里，本模块保持零 DB 依赖）。服务端的 clash API 一旦配了
/// secret，裸请求会拿到 401 —— 那也是活着，所以这里是宽松判据。
pub fn clash_api_alive(port: u16, timeout: Duration) -> bool {
    clash_probe(port, timeout, None, false)
}

/// 严格就绪探测：带 clash secret 请求 /version，必须拿到 200 才算就绪。
///
/// 面板生成的 sing-box 配置必带 `experimental.clash_api.secret`，此时不带
/// Authorization 的裸请求会被回 401；用裸请求判「未就绪」会把刚起来、实际已经
/// 正常的 sing-box 进程杀掉，表现为「配置已写入，但 clash API 在 5000 毫秒内未就绪」。
pub fn clash_api_ready(port: u16, timeout: Duration, secret: Option<&str>) -> bool {
    clash_probe(port, timeout, secret, true)
}

fn clash_probe(port: u16, timeout: Duration, secret: Option<&str>, require_200: bool) -> bool {
    let Some(addr) = (CLASH_HOST, port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
    else {
        return false;
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, timeout) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let auth = match secret {
        Some(s) if !s.is_empty() => format!("Authorization: Bearer {}\r\n", s),
        _ => String::new(),
    };
    let request = format!(
        "GET /version HTTP/1.1\r\nHost: {}:{}\r\n{}Connection: close\r\n\r\n",
        CLASH_HOST, port, auth
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 128];
    match stream.read(&mut buf) {
        Ok(n) if n > 0 => {
            let head = String::from_utf8_lossy(&buf[..n]).into_owned();
            if !head.starts_with("HTTP/") {
                return false;
            }
            !require_200 || head.contains(" 200")
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// 配置校验 / 原子写
// ---------------------------------------------------------------------------

/// sing-box check 校验。返回 (ok, message)。
///
/// 流程与 Python 一致：写临时 .check.json → sing-box check -c <tmp> → 删临时文件。
/// 二进制不存在、超时、非 0 退出都返回 (false, 可读原因)，不 panic。
pub fn check_config(paths: &ProcPaths, config: &Value) -> (bool, String) {
    let tmp = paths.check_tmp_path();
    let result = match write_check_tmp(&tmp, config) {
        Err(e) => (
            false,
            format!("写入临时配置失败: {} ({})", tmp.display(), e),
        ),
        Ok(()) => {
            let tmp_arg = tmp.to_string_lossy().into_owned();
            match run_with_timeout(
                &paths.singbox_bin,
                &["check", "-c", tmp_arg.as_str()],
                CHECK_TIMEOUT,
            ) {
                Err(e) => (false, format!("sing-box check 无法执行: {}", e)),
                Ok(out) if out.timed_out => (
                    false,
                    format!("sing-box check 超时（{} 秒）", CHECK_TIMEOUT.as_secs()),
                ),
                Ok(out) if out.code == Some(0) => (true, "OK".to_string()),
                Ok(out) => (false, first_text(&out.stderr, &out.stdout, "check failed")),
            }
        }
    };
    // Python 用 finally 保证删除临时文件；这里同样无论成败都删。
    let _ = std::fs::remove_file(&tmp);
    result
}

fn write_check_tmp(tmp: &Path, config: &Value) -> std::io::Result<()> {
    if let Some(parent) = tmp.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let body = serde_json::to_vec(config)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    std::fs::write(tmp, body)
}

/// Python 的 (a or b or fallback).strip()。
fn first_text(a: &str, b: &str, fallback: &str) -> String {
    let picked = if !a.is_empty() {
        a
    } else if !b.is_empty() {
        b
    } else {
        fallback
    };
    picked.trim().to_string()
}

/// 原子写 config.json，并把旧配置留档为 config.json.bak。
///
/// 顺序：旧内容同步写 .bak → 新内容写 config.json.tmp 并 fsync → rename 覆盖
/// config.json → fsync 目录。任何一步失败都返回 io::Error，不 panic。
pub fn atomic_write_config(paths: &ProcPaths, config: &Value) -> std::io::Result<()> {
    std::fs::create_dir_all(&paths.data_dir)?;
    let body = serde_json::to_vec_pretty(config)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let config_path = paths.config_path();
    if config_path.exists() {
        let previous = std::fs::read(&config_path)?;
        write_synced(&paths.config_bak_path(), &previous)?;
    }
    let tmp = paths.config_tmp_path();
    write_synced(&tmp, &body)?;
    std::fs::rename(&tmp, &config_path)?;
    sync_dir(&paths.data_dir);
    Ok(())
}

fn write_synced(path: &Path, body: &[u8]) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(body)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

/// 目录项也要落盘，否则 rename 在掉电后可能丢（尽力而为，失败不算错）。
fn sync_dir(dir: &Path) {
    if let Ok(handle) = File::open(dir) {
        let _ = handle.sync_all();
    }
}

// ---------------------------------------------------------------------------
// 日志文件与轮转
// ---------------------------------------------------------------------------

/// 带轮转的 sing-box 日志句柄（对应 Python 的全局 _logf）。
///
/// 写入后若文件达到上限即滚动：singbox.log → singbox.log.1 → ...，
/// 只保留 backup_count 份副本。
#[derive(Debug)]
pub struct LogFile {
    path: PathBuf,
    file: Option<File>,
    max_bytes: u64,
    backup_count: usize,
}

impl LogFile {
    /// 用默认阈值打开 data/singbox.log。
    pub fn open(paths: &ProcPaths) -> std::io::Result<Self> {
        Self::open_with(paths.log_path(), LOG_MAX_BYTES, LOG_BACKUP_COUNT)
    }

    /// 指定路径、阈值和副本数打开（测试用）。
    ///
    /// 与 Python 一致：历史遗留的超大日志在打开时直接截断，不保留超大旧副本。
    pub fn open_with(
        path: impl Into<PathBuf>,
        max_bytes: u64,
        backup_count: usize,
    ) -> std::io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.len() > max_bytes {
                let _ = std::fs::write(&path, b"");
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            file: Some(file),
            max_bytes,
            backup_count,
        })
    }

    /// 当前日志路径。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 当前文件是否还持有句柄。
    pub fn is_open(&self) -> bool {
        self.file.is_some()
    }

    /// 写入一块输出；写完后若达到阈值就轮转（对应 Python _log_reader 的循环）。
    pub fn write_chunk(&mut self, chunk: &[u8]) -> std::io::Result<()> {
        let Some(file) = self.file.as_mut() else {
            return Ok(());
        };
        file.write_all(chunk)?;
        let written = file.stream_position()?;
        if written >= self.max_bytes {
            self.rotate()?;
        }
        Ok(())
    }

    /// 立即轮转：关闭当前文件 → 依次挪动副本 → 重新打开新文件。
    ///
    /// 挪副本失败（权限/只读挂载等）时也要把句柄重新打开再返回错误，
    /// 与 Python _rotate_log 的 except OSError 分支一致——否则后续日志会静默丢失。
    pub fn rotate(&mut self) -> std::io::Result<()> {
        self.file = None;
        let rotated = rotate_log_with(&self.path, self.backup_count);
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .ok();
        rotated
    }
}

/// 纯文件层轮转：path → path.1 → ... → path.backup_count。
///
/// 与 Python _rotate_log 的 for index in range(count-1, 0, -1) 一致：先从最老的
/// 副本开始往后挪，最后才把当前文件挪到 .1，因此恰好保留 backup_count 份。
pub fn rotate_log_with(path: &Path, backup_count: usize) -> std::io::Result<()> {
    let base = path.to_string_lossy().into_owned();
    let mut index = backup_count.saturating_sub(1);
    while index > 0 {
        let source = PathBuf::from(format!("{}.{}", base, index));
        let target = PathBuf::from(format!("{}.{}", base, index + 1));
        if source.exists() {
            std::fs::rename(&source, &target)?;
        }
        index -= 1;
    }
    if path.exists() {
        std::fs::rename(path, PathBuf::from(format!("{}.1", base)))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 版本号
// ---------------------------------------------------------------------------

/// sing-box version 输出解析（纯函数，可单独测）。
///
/// 与 Python 一致：取 strip 后第一行；输出为空或全空白时返回 None。
pub fn parse_version_output(stdout: &str) -> Option<String> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.lines().next().map(|line| line.trim().to_string())
}

/// 读取 sing-box 版本（第一行，如 sing-box version 1.9.3）。失败返回 None。
pub fn singbox_version(paths: &ProcPaths) -> Option<String> {
    let out = run_with_timeout(&paths.singbox_bin, &["version"], VERSION_TIMEOUT).ok()?;
    if out.timed_out {
        return None;
    }
    parse_version_output(&out.stdout)
}

/// 便捷封装：用默认路径解析一次版本。
pub fn version_from_env() -> Option<String> {
    singbox_version(&ProcPaths::from_env())
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// 每个测试一个独立临时目录，drop 时清掉。
    struct TmpDir {
        path: PathBuf,
    }

    impl TmpDir {
        fn new(tag: &str) -> Self {
            static SEQ: AtomicUsize = AtomicUsize::new(0);
            let seq = SEQ.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!(
                "aura-sbp-{}-{}-{}",
                std::process::id(),
                tag,
                seq
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("创建临时目录失败");
            Self { path }
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }

        fn paths(&self, bin: &str) -> ProcPaths {
            ProcPaths::new(self.path.clone(), bin)
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }

    // ---- 路径推导 ----

    #[test]
    fn paths_derive_all_files_from_data_dir() {
        let paths = ProcPaths::new("/srv/aura/data", "sing-box");
        assert_eq!(
            paths.config_path(),
            PathBuf::from("/srv/aura/data/config.json")
        );
        assert_eq!(
            paths.config_bak_path(),
            PathBuf::from("/srv/aura/data/config.json.bak")
        );
        assert_eq!(
            paths.config_tmp_path(),
            PathBuf::from("/srv/aura/data/config.json.tmp")
        );
        assert_eq!(
            paths.check_tmp_path(),
            PathBuf::from("/srv/aura/data/.check.json")
        );
        assert_eq!(
            paths.log_path(),
            PathBuf::from("/srv/aura/data/singbox.log")
        );
        assert_eq!(
            paths.log_backup_path(2),
            PathBuf::from("/srv/aura/data/singbox.log.2")
        );
        assert_eq!(
            paths.cmdline_marker(),
            "sing-box run -c /srv/aura/data/config.json"
        );
    }

    #[test]
    fn from_env_uses_overrides_and_defaults() {
        std::env::set_var(SINGBOX_BIN_ENV, "/opt/sing-box");
        std::env::set_var(DATA_DIR_ENV, "/srv/aura/data");
        let paths = ProcPaths::from_env();
        assert_eq!(paths.singbox_bin, "/opt/sing-box");
        assert_eq!(paths.data_dir, PathBuf::from("/srv/aura/data"));

        std::env::remove_var(SINGBOX_BIN_ENV);
        std::env::remove_var(DATA_DIR_ENV);
        let defaults = ProcPaths::from_env();
        assert_eq!(defaults.singbox_bin, DEFAULT_SINGBOX_BIN);
        assert_eq!(defaults.data_dir, PathBuf::from(DEFAULT_DATA_DIR));
    }

    #[test]
    fn constants_match_python_baseline() {
        assert_eq!(CLASH_PORT, 9095);
        assert_eq!(LOG_MAX_BYTES, 20 * 1024 * 1024);
        assert_eq!(LOG_BACKUP_COUNT, 2);
        assert_eq!(CHECK_TIMEOUT, Duration::from_secs(20));
        assert_eq!(VERSION_TIMEOUT, Duration::from_secs(10));
    }

    // ---- 进程发现 / fd 计数 ----

    /// 造一个假 procfs：<root>/<pid>/cmdline 与 <root>/<pid>/fd/0..n。
    fn fake_proc_entry(root: &Path, pid: i32, cmdline: &str, fd_count: usize) {
        let dir = root.join(pid.to_string());
        std::fs::create_dir_all(dir.join("fd")).expect("mkdir fd");
        let mut raw = Vec::new();
        for (i, part) in cmdline.split_whitespace().enumerate() {
            if i > 0 {
                raw.push(0u8);
            }
            raw.extend_from_slice(part.as_bytes());
        }
        raw.push(0u8);
        std::fs::write(dir.join("cmdline"), raw).expect("write cmdline");
        for fd in 0..fd_count {
            std::fs::write(dir.join("fd").join(fd.to_string()), b"").expect("write fd");
        }
    }

    #[test]
    fn find_pids_matches_only_our_config_path() {
        let tmp = TmpDir::new("pids");
        let proc_root = tmp.join("proc");
        let paths = tmp.paths("sing-box");
        let marker = paths.cmdline_marker();
        let ours = format!("{} run", marker);
        fake_proc_entry(&proc_root, 4242, &ours, 1);
        fake_proc_entry(&proc_root, 5151, "sing-box run -c /other/config.json", 1);
        fake_proc_entry(&proc_root, 6161, "/usr/bin/nginx -g daemon off;", 1);
        // 非数字目录（/proc/self、/proc/meminfo 之类）必须被跳过
        std::fs::create_dir_all(proc_root.join("self")).expect("mkdir self");
        std::fs::create_dir_all(proc_root.join("sys")).expect("mkdir sys");

        let mut pids = find_singbox_pids_in(&proc_root, &marker);
        pids.sort_unstable();
        assert_eq!(pids, vec![4242]);
    }

    #[test]
    fn find_pids_missing_proc_root_is_empty() {
        let tmp = TmpDir::new("noproc");
        let paths = tmp.paths("sing-box");
        assert!(
            find_singbox_pids_in(&tmp.join("does-not-exist"), &paths.cmdline_marker()).is_empty()
        );
    }

    #[test]
    fn fd_count_of_unknown_pid_is_zero() {
        // 不存在的 pid：/proc/<pid>/fd 读不到，必须是 0 而不是 panic
        assert_eq!(fd_count_of(Path::new(PROC_ROOT), 4_000_000), 0);
        let tmp = TmpDir::new("fd0");
        assert_eq!(fd_count_of(&tmp.join("proc"), 4_000_000), 0);
    }

    #[test]
    fn fd_count_sums_hits_and_ignores_missing() {
        let tmp = TmpDir::new("fds");
        let proc_root = tmp.join("proc");
        let paths = tmp.paths("sing-box");
        let cmd = paths.cmdline_marker();
        fake_proc_entry(&proc_root, 700, &cmd, 3);
        fake_proc_entry(&proc_root, 701, &cmd, 4);
        fake_proc_entry(&proc_root, 702, "sing-box run -c /other/config.json", 9);
        // 命中但 fd 目录缺失：计 0，不 panic
        let orphan = proc_root.join("703");
        std::fs::create_dir_all(&orphan).expect("mkdir orphan");
        std::fs::write(orphan.join("cmdline"), cmd.replace(' ', "\u{0}")).expect("write cmdline");

        assert_eq!(singbox_fd_count_in(&proc_root, &paths), 7);
    }

    // ---- 信号 ----

    #[test]
    fn signal_mapping_matches_libc_numbers() {
        assert_eq!(Signal::Hup.as_i32(), 1);
        assert_eq!(Signal::Int.as_i32(), 2);
        assert_eq!(Signal::Term.as_i32(), 15);
        assert_eq!(Signal::Kill.as_i32(), 9);
        assert_eq!(Signal::Hup.py_name(), "SIGHUP");
        assert_eq!(Signal::Term.pkill_flag(), "-TERM");
    }

    #[test]
    fn signal_without_match_returns_zero() {
        // 临时数据目录的 cmdline 特征不可能命中真实进程；
        // pkill 也匹配不到，因此命中数必须是 0（不得 panic）
        let tmp = TmpDir::new("signal");
        let paths = tmp.paths("/nonexistent/sing-box-for-test");
        assert_eq!(signal_singbox(&paths, Signal::Hup), 0);
    }

    // ---- 运行状态 ----

    #[test]
    fn is_running_false_when_no_proc_and_no_api() {
        let tmp = TmpDir::new("running");
        let paths = tmp.paths("sing-box");
        // 端口 1 上不会有 clash API
        assert!(!is_running_with_port(&paths, 1));
    }

    #[test]
    fn clash_probe_detects_200() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let handle = std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 256];
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
            }
        });
        assert!(clash_api_alive(port, Duration::from_millis(500)));
        let _ = handle.join();
    }

    /// 服务端配了 secret 时会回 401：宽松探活仍算活着，严格就绪必须带上 secret。
    #[test]
    fn clash_probe_handles_401_and_uses_secret() {
        use std::net::TcpListener;
        use std::sync::mpsc;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = mpsc::channel::<String>();
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                let Ok((mut sock, _)) = listener.accept() else {
                    return;
                };
                let mut buf = [0u8; 512];
                let n = sock.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                let authed = req.contains("Authorization: Bearer s3cret");
                let _ = tx.send(req);
                if authed {
                    let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
                } else {
                    let _ = sock.write_all(
                        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 27\r\n\r\n{\"message\":\"unauthorized\"}",
                    );
                }
            }
        });

        assert!(
            clash_api_alive(port, Duration::from_millis(500)),
            "401 说明端口后面有 HTTP 服务，宽松探活应判活着"
        );
        assert!(
            clash_api_ready(port, Duration::from_millis(500), Some("s3cret")),
            "带正确 secret 时严格探活必须通过"
        );
        let _ = handle.join();

        let first = rx.recv().unwrap_or_default();
        let second = rx.recv().unwrap_or_default();
        assert!(
            !first.to_lowercase().contains("authorization"),
            "宽松探活不应带 Authorization 头"
        );
        assert!(second.contains("Authorization: Bearer s3cret"));
    }

    /// 没有 secret 时严格探活必须失败，不能把 401 当成就绪。
    #[test]
    fn clash_ready_false_when_secret_missing() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let handle = std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(
                    b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 27\r\n\r\n{\"message\":\"unauthorized\"}",
                );
            }
        });

        assert!(!clash_api_ready(port, Duration::from_millis(500), None));
        let _ = handle.join();
    }

    // ---- 原子写 ----

    #[test]
    fn atomic_write_first_time_leaves_no_bak() {
        let tmp = TmpDir::new("atomic1");
        let paths = tmp.paths("sing-box");
        let cfg = serde_json::json!({"log": {"level": "info"}});
        atomic_write_config(&paths, &cfg).expect("write");
        assert!(!paths.config_bak_path().exists());
        let written: Value = serde_json::from_str(&read(&paths.config_path())).expect("json");
        assert_eq!(written, cfg);
        assert!(
            !paths.config_tmp_path().exists(),
            "临时文件必须被 rename 掉"
        );
    }

    #[test]
    fn atomic_write_keeps_previous_config_as_bak() {
        let tmp = TmpDir::new("atomic2");
        let paths = tmp.paths("sing-box");
        let first = serde_json::json!({"version": 1});
        let second = serde_json::json!({"version": 2});
        atomic_write_config(&paths, &first).expect("write 1");
        atomic_write_config(&paths, &second).expect("write 2");

        let bak: Value = serde_json::from_str(&read(&paths.config_bak_path())).expect("bak json");
        assert_eq!(bak, first, ".bak 必须是上一版配置");
        let current: Value = serde_json::from_str(&read(&paths.config_path())).expect("json");
        assert_eq!(current, second);
    }

    #[test]
    fn atomic_write_uses_two_space_indent() {
        let tmp = TmpDir::new("atomic3");
        let paths = tmp.paths("sing-box");
        atomic_write_config(&paths, &serde_json::json!({"a": {"b": 1}})).expect("write");
        let text = read(&paths.config_path());
        assert!(
            text.contains("\n  \"a\""),
            "缩进应为 2 空格，实际: {}",
            text
        );
        assert!(
            text.contains("\n    \"b\""),
            "嵌套缩进应为 4 空格，实际: {}",
            text
        );
    }

    // ---- 日志轮转 ----

    #[test]
    fn rotate_keeps_only_n_backups() {
        let tmp = TmpDir::new("rotate");
        let log = tmp.join("singbox.log");
        std::fs::write(&log, b"gen0").expect("write log");
        std::fs::write(format!("{}.1", log.to_string_lossy()), b"gen-1").expect("write .1");
        std::fs::write(format!("{}.2", log.to_string_lossy()), b"gen-2").expect("write .2");

        rotate_log_with(&log, 2).expect("rotate");

        assert!(!log.exists(), "轮转后当前文件应由调用方重建");
        assert_eq!(
            read(&PathBuf::from(format!("{}.1", log.to_string_lossy()))),
            "gen0"
        );
        assert_eq!(
            read(&PathBuf::from(format!("{}.2", log.to_string_lossy()))),
            "gen-1"
        );
        assert!(
            !PathBuf::from(format!("{}.3", log.to_string_lossy())).exists(),
            "副本数必须严格等于 backup_count"
        );
    }

    #[test]
    fn log_write_rotates_once_threshold_reached() {
        let tmp = TmpDir::new("logwrite");
        let log = tmp.join("singbox.log");
        let mut handle = LogFile::open_with(&log, 32, 2).expect("open log");
        handle.write_chunk(b"aaaa").expect("write a");
        handle.write_chunk(b"bbbb").expect("write b");
        assert!(!PathBuf::from(format!("{}.1", log.to_string_lossy())).exists());

        // 第三次写入后累计 12 字节，仍未到 32 字节阈值
        handle.write_chunk(b"cccc").expect("write c");
        assert!(!PathBuf::from(format!("{}.1", log.to_string_lossy())).exists());

        // 一次性写满阈值，触发轮转（Python 是先写再判 tell()，所以超阈值那块
        // 留在轮转出去的旧文件里，新文件从空开始——行为必须一致）
        handle.write_chunk(&[b'd'; 40]).expect("write big");
        let backup = PathBuf::from(format!("{}.1", log.to_string_lossy()));
        assert!(backup.exists(), "达到阈值必须轮转出 .1");
        let rolled = read(&backup);
        assert!(
            rolled.starts_with("aaaabbbbccccdddd"),
            ".1 应包含轮转前全部内容，实际: {}",
            rolled
        );
        assert_eq!(rolled.len(), 52);
        assert!(handle.is_open(), "轮转后必须重新打开新文件");
        assert_eq!(read(&log), "", "新文件从空开始");
    }

    #[test]
    fn open_truncates_oversized_history_log() {
        let tmp = TmpDir::new("logtrunc");
        let log = tmp.join("singbox.log");
        std::fs::write(&log, [b'x'; 200]).expect("write");
        let handle = LogFile::open_with(&log, 64, 2).expect("open");
        assert!(handle.is_open());
        assert_eq!(std::fs::metadata(&log).expect("meta").len(), 0);
    }

    #[test]
    fn log_write_after_drop_is_noop() {
        let tmp = TmpDir::new("logclosed");
        let mut handle = LogFile::open_with(tmp.join("singbox.log"), 1024, 2).expect("open");
        handle.rotate().expect("rotate");
        assert!(handle.is_open());
        handle.write_chunk(b"after-rotate").expect("write");
        assert_eq!(read(&tmp.join("singbox.log")), "after-rotate");
    }

    // ---- check_config ----

    #[test]
    fn check_config_missing_binary_reports_error_and_cleans_tmp() {
        let tmp = TmpDir::new("check-nobin");
        let paths = tmp.paths("/nonexistent/sing-box-does-not-exist");
        let (ok, message) = check_config(&paths, &serde_json::json!({"log": {}}));
        assert!(!ok, "二进制不存在时必须返回 false");
        assert!(
            message.contains("sing-box check") || message.contains("no such file"),
            "错误文案要能定位问题，实际: {}",
            message
        );
        assert!(!paths.check_tmp_path().exists(), "临时校验文件必须被删除");
    }

    #[test]
    fn check_config_success_uses_exit_code_zero() {
        let tmp = TmpDir::new("check-ok");
        // 用 /bin/echo 顶替 sing-box：必定退出 0，用来验证成功分支
        let paths = tmp.paths("/bin/echo");
        let (ok, message) = check_config(&paths, &serde_json::json!({"log": {}}));
        assert!(ok, "退出码 0 必须判为通过，实际: {}", message);
        assert_eq!(message, "OK");
        assert!(!paths.check_tmp_path().exists());
    }

    /// 写一个退出码固定、可选输出指定内容的假 sing-box 脚本。
    fn fake_binary(tmp: &TmpDir, name: &str, body: &str) -> String {
        let path = tmp.join(name);
        std::fs::write(&path, body).expect("write fake binary");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path).expect("meta").permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).expect("chmod");
        }
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn check_config_failure_falls_back_to_default_message() {
        let tmp = TmpDir::new("check-fail");
        // 退出 1 且无任何输出 → 文案回退 check failed
        let bin = fake_binary(
            &tmp,
            "silent-singbox.sh",
            "#!/bin/sh
exit 1
",
        );
        let paths = tmp.paths(&bin);
        let (ok, message) = check_config(&paths, &serde_json::json!({"log": {}}));
        assert!(!ok);
        assert_eq!(message, "check failed");
    }

    #[test]
    fn check_config_reports_stderr_first() {
        let tmp = TmpDir::new("check-stderr");
        // /bin/sh -c 不行（本模块不接受自定义参数），改用写入 stderr 的脚本
        let script = tmp.join("fake-singbox.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\necho 'decode config: unknown field' >&2\nexit 1\n",
        )
        .expect("write script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script).expect("meta").permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script, perms).expect("chmod");
        }
        let paths = tmp.paths(script.to_string_lossy().into_owned().as_str());
        let (ok, message) = check_config(&paths, &serde_json::json!({"log": {}}));
        assert!(!ok);
        assert_eq!(message, "decode config: unknown field");
    }

    // ---- 外部命令执行 ----

    #[test]
    fn run_with_timeout_kills_slow_command() {
        let out =
            run_with_timeout("/bin/sleep", &["5"], Duration::from_millis(150)).expect("spawn");
        assert!(out.timed_out, "必须被超时杀掉");
        assert_eq!(out.code, None);
        assert!(!out.is_success());
    }

    #[test]
    fn run_with_timeout_reports_missing_binary() {
        let err = run_with_timeout(
            "/nonexistent/definitely-not-here",
            &[],
            Duration::from_millis(200),
        )
        .expect_err("必须报错");
        assert!(matches!(err, CmdError::Spawn(_)));
        assert!(err.to_string().contains("/nonexistent/definitely-not-here"));
    }

    // ---- 版本号 ----

    #[test]
    fn parse_version_takes_first_line() {
        assert_eq!(
            parse_version_output("sing-box version 1.9.3\nEnvironment: go1.22\n"),
            Some("sing-box version 1.9.3".to_string())
        );
        assert_eq!(
            parse_version_output("  sing-box version 1.10.0  \n"),
            Some("sing-box version 1.10.0".to_string())
        );
    }

    #[test]
    fn parse_version_empty_is_none() {
        assert_eq!(parse_version_output(""), None);
        assert_eq!(parse_version_output("   \n\t\n"), None);
    }

    #[test]
    fn singbox_version_missing_binary_is_none() {
        let tmp = TmpDir::new("version");
        let paths = tmp.paths("/nonexistent/sing-box-does-not-exist");
        assert_eq!(singbox_version(&paths), None);
    }
}
