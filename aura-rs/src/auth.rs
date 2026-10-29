//! 认证模块：密码哈希、token 签发/校验、首次改密强制。
//!
//! 与 backend/auth.py 逐行对齐。安全要点：
//! - 密码用 PBKDF2-HMAC-SHA256 加盐哈希（100_000 轮），存储格式 salt + "$" + hexhash
//! - token 用 32 字节随机数生成 hex，服务端只存 SHA256(token) 防泄漏
//! - 登录失败限流（60s 内 10 次 / 最近失败后 5s 内），失败计数在内存
//! - 默认密码 admin，首次登录强制改密（password_change_required）
//!
//! 依赖注入：DB 读写通过 AuthStore trait，不直接依赖 aura::db。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub const TOKEN_TTL: f64 = 7.0 * 24.0 * 60.0 * 60.0;
pub const FAIL_LOCKOUT_SECONDS: f64 = 5.0;
pub const FAILURE_WINDOW_SECONDS: f64 = 60.0;
pub const MAX_FAILURES_PER_KEY: usize = 10;
pub const MAX_FAILURE_KEYS: usize = 1000;
pub const PBKDF2_ITERATIONS: u32 = 100_000;
pub const MIN_PASSWORD_LEN: usize = 6;
pub const DEFAULT_PASSWORD: &str = "admin";

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// PBKDF2-HMAC-SHA256（RFC 8018）。手写实现以避免额外依赖，行为与 Python
/// hashlib.pbkdf2_hmac("sha256", ...) 逐字节一致。
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, dklen: usize) -> Vec<u8> {
    let iters = iterations.max(1);
    let mut out = Vec::with_capacity(dklen);
    let mut block_index: u32 = 1;
    while out.len() < dklen {
        let mut mac = HmacSha256::new_from_slice(password).expect("hmac accepts any key length");
        mac.update(salt);
        mac.update(&block_index.to_be_bytes());
        let mut u = mac.finalize().into_bytes().to_vec();
        let mut t = u.clone();
        for _ in 1..iters {
            let mut mac =
                HmacSha256::new_from_slice(password).expect("hmac accepts any key length");
            mac.update(&u);
            u = mac.finalize().into_bytes().to_vec();
            for (a, b) in t.iter_mut().zip(u.iter()) {
                *a ^= *b;
            }
        }
        out.extend_from_slice(&t);
        block_index = block_index.wrapping_add(1);
    }
    out.truncate(dklen);
    out
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn random_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex_lower(&buf)
}

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex_lower(&h.finalize())
}

/// 常量时间字符串比较（对齐 Python hmac.compare_digest）
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// PBKDF2-SHA256 哈希。salt 为空时自动生成（返回 salt + "$" + hash）。
pub fn hash_password(password: &str, salt: &str) -> String {
    let salt = if salt.is_empty() {
        random_hex(16)
    } else {
        salt.to_string()
    };
    let dk = pbkdf2_hmac_sha256(password.as_bytes(), salt.as_bytes(), PBKDF2_ITERATIONS, 32);
    format!("{}{}{}", salt, "$", hex_lower(&dk))
}

pub fn verify_password(password: &str, stored: &str) -> bool {
    match stored.split_once('$') {
        Some((salt, _)) => constant_time_eq(&hash_password(password, salt), stored),
        None => false,
    }
}

/// DB 读写抽象，便于测试与解耦 aura::db。
pub trait AuthStore: Send + Sync {
    fn get_setting(&self, key: &str) -> Option<Value>;
    fn set_setting(&self, key: &str, value: Value) -> Result<(), String>;
    fn username(&self) -> String;
}

struct TokenEntry {
    exp_at: f64,
}

#[derive(Default)]
struct State {
    tokens: HashMap<String, TokenEntry>,
    failures: HashMap<String, Vec<f64>>,
}

pub struct Auth {
    store: Arc<dyn AuthStore>,
    state: Mutex<State>,
}

impl Auth {
    pub fn new(store: Arc<dyn AuthStore>) -> Self {
        Self {
            store,
            state: Mutex::new(State::default()),
        }
    }

    pub fn get_username(&self) -> String {
        let u = self.store.username();
        if u.is_empty() {
            "admin".to_string()
        } else {
            u
        }
    }

    fn get_auth(&self) -> Value {
        let auth = self.store.get_setting("auth").unwrap_or(Value::Null);
        let has_hash = auth
            .get("password_hash")
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if has_hash {
            return auth;
        }
        let fresh = json!({
            "password_hash": hash_password(DEFAULT_PASSWORD, ""),
            "password_change_required": true,
            "created_at": now_millis(),
        });
        if let Err(e) = self.store.set_setting("auth", fresh.clone()) {
            tracing::warn!("初始化默认 auth 设置失败: {}", e);
        }
        fresh
    }

    fn prune_failures(state: &mut State, now: f64) {
        state.failures.retain(|_, ts| {
            ts.retain(|t| now - t < FAILURE_WINDOW_SECONDS);
            !ts.is_empty()
        });
    }

    /// 跟踪表满时逐出「最久没有新失败」的 key，而不是拒绝登记新 key。
    ///
    /// 旧实现直接 return 会让新 key 永远拿不到失败记录，于是
    /// `failures.len() >= MAX_FAILURE_KEYS` 长期成立，is_rate_limited 对任何
    /// 未见过的 key 都返回 true —— 攻击者用 1000 个来源（伪造 X-Forwarded-For 即可）
    /// 在 60s 内刷满表，就能把管理员一起锁在门外，形成全站登录 DoS。
    fn record_failure_locked(state: &mut State, key: &str) {
        let now = now_secs();
        Self::prune_failures(state, now);
        if !state.failures.contains_key(key) && state.failures.len() >= MAX_FAILURE_KEYS {
            let oldest = state
                .failures
                .iter()
                .min_by(|a, b| {
                    let la = a.1.last().copied().unwrap_or(f64::MIN);
                    let lb = b.1.last().copied().unwrap_or(f64::MIN);
                    la.partial_cmp(&lb).unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|(k, _)| k.clone());
            if let Some(oldest) = oldest {
                state.failures.remove(&oldest);
            }
        }
        let entry = state.failures.entry(key.to_string()).or_default();
        entry.push(now);
        if entry.len() > MAX_FAILURES_PER_KEY {
            let drain = entry.len() - MAX_FAILURES_PER_KEY;
            entry.drain(0..drain);
        }
    }

    pub fn is_rate_limited(&self, key: &str) -> bool {
        let key = if key.is_empty() { "unknown" } else { key };
        let mut state = self.state.lock().unwrap();
        let now = now_secs();
        Self::prune_failures(&mut state, now);
        let recent = state.failures.get(key).cloned().unwrap_or_default();
        // 只按本 key 的失败次数判定：跟踪表容量是被逐出策略约束的内存上限，
        // 绝不作为「全站限流」的依据（否则表一满就把所有人锁死）。
        if recent.len() >= MAX_FAILURES_PER_KEY {
            return true;
        }
        match recent.last() {
            Some(last) => now - last < FAIL_LOCKOUT_SECONDS,
            None => false,
        }
    }

    fn issue_token_locked(state: &mut State) -> String {
        let token = random_hex(32);
        let token_hash = sha256_hex(&token);
        let now = now_secs();
        state.tokens.insert(
            token_hash,
            TokenEntry {
                exp_at: now + TOKEN_TTL,
            },
        );
        state.tokens.retain(|_, v| v.exp_at >= now);
        token
    }

    pub fn login_blocking(&self, username: &str, password: &str, key: &str) -> (Value, bool) {
        let key = if key.is_empty() { "unknown" } else { key };
        let mut state = self.state.lock().unwrap();
        let now = now_secs();
        Self::prune_failures(&mut state, now);
        let recent = state.failures.get(key).cloned().unwrap_or_default();
        // 只按本 key 的失败次数判定（key 总数上限只用于约束内存，见 record_failure_locked 的逐出策略）。
        let limited = if recent.len() >= MAX_FAILURES_PER_KEY {
            true
        } else {
            recent
                .last()
                .map(|t| now - t < FAIL_LOCKOUT_SECONDS)
                .unwrap_or(false)
        };
        if limited {
            return (
                json!({"ok": false, "error": "尝试过于频繁，请稍后再试"}),
                false,
            );
        }
        let auth = self.get_auth();
        let stored = auth
            .get("password_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if username != self.get_username() || !verify_password(password, &stored) {
            Self::record_failure_locked(&mut state, key);
            return (json!({"ok": false, "error": "用户名或密码错误"}), true);
        }
        let token = Self::issue_token_locked(&mut state);
        let change_required = auth
            .get("password_change_required")
            .map(crate::config_manager::is_truthy)
            .unwrap_or(false);
        (
            json!({"ok": true, "token": token, "passwordChangeRequired": change_required}),
            false,
        )
    }

    pub async fn login(&self, username: &str, password: &str, client_ip: &str) -> Value {
        let (res, delay) = self.login_blocking(username, password, client_ip);
        if delay {
            tokio::time::sleep(std::time::Duration::from_secs_f64(FAIL_LOCKOUT_SECONDS)).await;
        }
        res
    }

    pub fn verify_token(&self, token: &str) -> bool {
        if token.is_empty() {
            return false;
        }
        let token_hash = sha256_hex(token);
        let mut state = self.state.lock().unwrap();
        match state.tokens.get(&token_hash) {
            None => false,
            Some(entry) => {
                if entry.exp_at < now_secs() {
                    state.tokens.remove(&token_hash);
                    false
                } else {
                    true
                }
            }
        }
    }

    pub fn change_password(&self, old_password: &str, new_password: &str) -> Value {
        let mut state = self.state.lock().unwrap();
        let mut auth = self.get_auth();
        let stored = auth
            .get("password_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if !verify_password(old_password, &stored) {
            return json!({"ok": false, "error": "旧密码错误"});
        }
        if new_password.chars().count() < MIN_PASSWORD_LEN {
            return json!({"ok": false, "error": "新密码至少 6 位"});
        }
        if new_password == old_password {
            return json!({"ok": false, "error": "新密码不能与旧密码相同"});
        }
        if let Some(obj) = auth.as_object_mut() {
            obj.insert(
                "password_hash".into(),
                Value::String(hash_password(new_password, "")),
            );
            obj.insert("password_change_required".into(), Value::Bool(false));
            obj.insert("changed_at".into(), json!(now_millis()));
        }
        if let Err(e) = self.store.set_setting("auth", auth) {
            return json!({"ok": false, "error": format!("保存失败：{}", e)});
        }
        state.tokens.clear();
        let token = Self::issue_token_locked(&mut state);
        json!({"ok": true, "message": "密码修改成功", "token": token})
    }

    pub fn is_password_change_required(&self) -> bool {
        let _guard = self.state.lock().unwrap();
        self.store
            .get_setting("auth")
            .and_then(|v| v.get("password_change_required").cloned())
            .map(|v| crate::config_manager::is_truthy(&v))
            .unwrap_or(false)
    }

    /// 便捷断言用：当前存储的密码是否等于给定明文（测试与 CLI 自检用）。
    pub fn verify_password_default(&self, plain: &str) -> bool {
        let stored = self
            .get_auth()
            .get("password_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        verify_password(plain, &stored)
    }

    pub fn logout_token(&self, token: &str) {
        let token_hash = sha256_hex(token);
        let mut state = self.state.lock().unwrap();
        state.tokens.remove(&token_hash);
    }

    /// 签发有效内存令牌（测试与内部通道共用）。
    pub fn issue_token(&self) -> String {
        let mut state = self.state.lock().unwrap();
        Self::issue_token_locked(&mut state)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    struct MemStore {
        settings: StdMutex<HashMap<String, Value>>,
        user: String,
    }

    impl MemStore {
        fn new() -> Self {
            Self {
                settings: StdMutex::new(HashMap::new()),
                user: "admin".to_string(),
            }
        }
    }

    impl AuthStore for MemStore {
        fn get_setting(&self, key: &str) -> Option<Value> {
            self.settings.lock().unwrap().get(key).cloned()
        }
        fn set_setting(&self, key: &str, value: Value) -> Result<(), String> {
            self.settings.lock().unwrap().insert(key.to_string(), value);
            Ok(())
        }
        fn username(&self) -> String {
            self.user.clone()
        }
    }

    fn mk() -> (Arc<MemStore>, Auth) {
        let store = Arc::new(MemStore::new());
        let auth = Auth::new(store.clone());
        (store, auth)
    }

    fn hex_of(bytes: &[u8]) -> String {
        hex_lower(bytes)
    }

    #[test]
    fn pbkdf2_matches_python_hashlib_vectors() {
        // 向量来自 Python hashlib.pbkdf2_hmac('sha256', b'password', b'salt', N, 32).hex()
        let p = b"password";
        let s = b"salt";
        assert_eq!(
            hex_of(&pbkdf2_hmac_sha256(p, s, 1, 32)),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
        assert_eq!(
            hex_of(&pbkdf2_hmac_sha256(p, s, 2, 32)),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
        );
        assert_eq!(
            hex_of(&pbkdf2_hmac_sha256(p, s, 4096, 32)),
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
        );
    }

    #[test]
    fn pbkdf2_partial_block_truncates() {
        let dk = pbkdf2_hmac_sha256(b"password", b"salt", 1, 20);
        assert_eq!(dk.len(), 20);
        assert_eq!(hex_of(&dk), "120fb6cffcf8b32c43e7225256c4f837a86548c9");
    }

    #[test]
    fn hash_and_verify_roundtrip() {
        let stored = hash_password("secret123", "");
        assert_eq!(stored.matches('$').count(), 1);
        let (salt, hash) = stored.split_once('$').unwrap();
        assert_eq!(salt.len(), 32);
        assert_eq!(hash.len(), 64);
        assert!(verify_password("secret123", &stored));
        assert!(!verify_password("secret124", &stored));
        assert!(!verify_password("secret123", "garbage"));
    }

    #[test]
    fn hash_uses_given_salt_and_is_deterministic() {
        let a = hash_password("pw", "abcd");
        let b = hash_password("pw", "abcd");
        assert_eq!(a, b);
        assert!(a.starts_with("abcd$"));
    }

    #[test]
    fn get_auth_bootstraps_default_admin() {
        let (store, auth) = mk();
        let a = auth.get_auth();
        assert_eq!(
            a.get("password_change_required").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert!(a.get("created_at").is_some());
        let stored = store.get_setting("auth").unwrap();
        assert!(stored
            .get("password_hash")
            .and_then(|v| v.as_str())
            .unwrap()
            .contains('$'));
        assert!(auth.verify_password_default("admin"));
    }

    #[test]
    fn login_success_and_token_lifecycle() {
        let (_store, auth) = mk();
        let (res, delay) = auth.login_blocking("admin", "admin", "1.2.3.4");
        assert!(!delay);
        assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            res.get("passwordChangeRequired").and_then(|v| v.as_bool()),
            Some(true)
        );
        let token = res
            .get("token")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        assert_eq!(token.len(), 64);
        assert!(auth.verify_token(&token));
        auth.logout_token(&token);
        assert!(!auth.verify_token(&token));
        assert!(!auth.verify_token(""));
        assert!(!auth.verify_token(&token));
    }

    #[test]
    fn login_wrong_password_then_rate_limited() {
        let (_store, auth) = mk();
        let (res, delay) = auth.login_blocking("admin", "wrong", "9.9.9.9");
        assert!(delay);
        assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(
            res.get("error").and_then(|v| v.as_str()),
            Some("用户名或密码错误")
        );
        assert!(auth.is_rate_limited("9.9.9.9"));
        let (res2, _) = auth.login_blocking("admin", "admin", "9.9.9.9");
        assert_eq!(
            res2.get("error").and_then(|v| v.as_str()),
            Some("尝试过于频繁，请稍后再试")
        );
        assert!(!auth.is_rate_limited("8.8.8.8"));
    }

    #[test]
    fn failure_table_saturation_does_not_lock_out_new_keys() {
        let (_store, auth) = mk();
        {
            let mut st = auth.state.lock().unwrap();
            for i in 0..MAX_FAILURE_KEYS {
                Auth::record_failure_locked(&mut st, &format!("flood-{i}"));
            }
            assert_eq!(st.failures.len(), MAX_FAILURE_KEYS);
            // 满表后新 key 必须能登记：逐出最久未失败的 key，而不是被静默丢弃。
            Auth::record_failure_locked(&mut st, "fresh-key");
            assert!(st.failures.len() <= MAX_FAILURE_KEYS);
            assert!(st.failures.contains_key("fresh-key"));
        }
        // 未见过的来源不被限流，管理员不会被别人刷满表锁在门外。
        assert!(!auth.is_rate_limited("admin-home-ip"));
        let (res, delay) = auth.login_blocking("admin", "admin", "admin-home-ip");
        assert!(!delay);
        assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn per_key_failures_still_rate_limited_when_table_full() {
        let (_store, auth) = mk();
        {
            let mut st = auth.state.lock().unwrap();
            for i in 0..MAX_FAILURE_KEYS {
                Auth::record_failure_locked(&mut st, &format!("flood-{i}"));
            }
        }
        for _ in 0..MAX_FAILURES_PER_KEY {
            let _ = auth.login_blocking("admin", "wrong", "9.9.9.9");
        }
        // 表满不影响单 key 的暴力破解封锁。
        assert!(auth.is_rate_limited("9.9.9.9"));
    }

    #[test]
    fn login_wrong_username_rejected() {
        let (_store, auth) = mk();
        let (res, _) = auth.login_blocking("root", "admin", "7.7.7.7");
        assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(false));
    }

    #[test]
    fn change_password_rules() {
        let (_store, auth) = mk();
        let r = auth.change_password("wrong", "newpass");
        assert_eq!(r.get("error").and_then(|v| v.as_str()), Some("旧密码错误"));
        let r = auth.change_password("admin", "abc");
        assert_eq!(
            r.get("error").and_then(|v| v.as_str()),
            Some("新密码至少 6 位")
        );
        let r = auth.change_password("admin", "newpass123");
        assert_eq!(r.get("ok").and_then(|v| v.as_bool()), Some(true));
        let r = auth.change_password("newpass123", "newpass123");
        assert_eq!(
            r.get("error").and_then(|v| v.as_str()),
            Some("新密码不能与旧密码相同")
        );
        let r = auth.change_password("newpass123", "newpass1234");
        assert_eq!(r.get("ok").and_then(|v| v.as_bool()), Some(true));
        let tok = r.get("token").and_then(|v| v.as_str()).unwrap().to_string();
        assert!(auth.verify_token(&tok));
        assert!(!auth.is_password_change_required());
        assert!(auth.verify_password_default("newpass1234"));
        assert!(!auth.verify_password_default("admin"));
    }

    #[test]
    fn change_password_invalidates_old_tokens() {
        let (_store, auth) = mk();
        let (res, _) = auth.login_blocking("admin", "admin", "5.5.5.5");
        let old = res
            .get("token")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        assert!(auth.verify_token(&old));
        let r = auth.change_password("admin", "anotherpass");
        assert!(r.get("ok").and_then(|v| v.as_bool()).unwrap());
        assert!(!auth.verify_token(&old));
    }

    #[test]
    fn username_falls_back_to_admin() {
        struct EmptyStore;
        impl AuthStore for EmptyStore {
            fn get_setting(&self, _k: &str) -> Option<Value> {
                None
            }
            fn set_setting(&self, _k: &str, _v: Value) -> Result<(), String> {
                Ok(())
            }
            fn username(&self) -> String {
                String::new()
            }
        }
        let auth = Auth::new(Arc::new(EmptyStore));
        assert_eq!(auth.get_username(), "admin");
        let (res, _) = auth.login_blocking("admin", "admin", "6.6.6.6");
        assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(true));
    }
}
