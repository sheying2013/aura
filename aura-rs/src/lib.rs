//! Aura 面板后端（Rust 版）。
//! 模块边界固定，实现按迁移阶段填充；lib.rs 由 Lead 独占维护，其他人不要改。
pub mod app;
pub mod auth;
pub mod config_apply;
pub mod config_manager;
pub mod db;
pub mod ipinfo;
pub mod netguard;
pub mod panel_config;
pub mod probe_ip;
pub mod scheduler;
pub mod singbox_proc;
pub mod stats;
pub mod subs_proxy;
pub mod subscription_fetch;
pub mod types;
pub mod utils;
pub mod wire;
