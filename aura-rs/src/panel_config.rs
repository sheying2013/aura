//! 面板级配置：端口 / 网页登录路径 / 登录用户名，持久化到 data/panel.conf（JSON）。
//! 密码不在此文件——存 db settings 表（auth.password_hash）。
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const DEFAULT_PORT: i64 = 19001;
pub const DEFAULT_PANEL_PATH: &str = "/admin";
pub const DEFAULT_USERNAME: &str = "admin";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelConfig {
    #[serde(default = "d_port")]
    pub port: i64,
    #[serde(default = "d_panel_path")]
    pub panel_path: String,
    #[serde(default = "d_username")]
    pub username: String,
}

fn d_port() -> i64 {
    DEFAULT_PORT
}
fn d_panel_path() -> String {
    DEFAULT_PANEL_PATH.into()
}
fn d_username() -> String {
    DEFAULT_USERNAME.into()
}

impl Default for PanelConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_PORT,
            panel_path: DEFAULT_PANEL_PATH.into(),
            username: DEFAULT_USERNAME.into(),
        }
    }
}

impl PanelConfig {
    /// 从指定路径读取；文件缺失/损坏时回落默认值（与 Python 版行为一致）。
    pub fn load_from(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(s) => Self::parse(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// 解析JSON配置，并按默认配置补齐缺失字段，与Python panel_config._load保持一致。
    pub fn parse(raw: &str) -> Option<Self> {
        let value: serde_json::Value = serde_json::from_str(raw).ok()?;
        if !value.is_object() {
            return None;
        }
        let mut out = Self::default();
        let obj = value.as_object()?;
        if let Some(v) = obj.get("port").filter(|v| !v.is_null()) {
            out.port = v.as_i64()?;
        }
        if let Some(v) = obj.get("panel_path").filter(|v| !v.is_null()) {
            out.panel_path = v.as_str()?.to_string();
        }
        if let Some(v) = obj.get("username").filter(|v| !v.is_null()) {
            out.username = v.as_str()?.to_string();
        }
        Some(out)
    }

    /// 原子写入：先写 .tmp 再 rename，避免半截文件。
    pub fn save_to(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = PathBuf::from(format!("{}.tmp", path.display()));
        let body = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_python() {
        let c = PanelConfig::default();
        assert_eq!(c.port, 19001);
        assert_eq!(c.panel_path, "/admin");
        assert_eq!(c.username, "admin");
    }

    #[test]
    fn roundtrip_and_atomic_write() {
        let dir = std::env::temp_dir().join(format!("aura-panelcfg-{}", std::process::id()));
        let path = dir.join("panel.conf");
        let c = PanelConfig {
            port: 19123,
            ..PanelConfig::default()
        };
        c.save_to(&path).unwrap();
        let back = PanelConfig::load_from(&path);
        assert_eq!(back.port, 19123);
        assert!(!dir.join("panel.conf.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_defaults_null_missing_fields_and_ignores_unknown_fields() {
        let c =
            PanelConfig::parse(r#"{"port":19123,"panel_path":null,"unknown":"ignored"}"#).unwrap();
        assert_eq!(c.port, 19123);
        assert_eq!(c.panel_path, DEFAULT_PANEL_PATH);
        assert_eq!(c.username, DEFAULT_USERNAME);
    }

    #[test]
    fn parse_rejects_wrong_types_for_known_fields() {
        assert!(PanelConfig::parse(r#"{"port":"19123"}"#).is_none());
        assert!(PanelConfig::parse(r#"{"panel_path":123}"#).is_none());
        assert!(PanelConfig::parse(r#"{"username":false}"#).is_none());
    }

    #[test]
    fn corrupt_file_falls_back_to_defaults() {
        let dir = std::env::temp_dir().join(format!("aura-panelcfg-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("panel.conf");
        std::fs::write(&path, "not json").unwrap();
        assert_eq!(PanelConfig::load_from(&path).port, 19001);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
