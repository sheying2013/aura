//! 跨模块共享纯函数（唯一实现，禁止各模块复制同等逻辑）。
use serde_json::Value;
use std::str::FromStr;

/// 安全转 int：订阅里的端口可能是 "443abc" 等脏串，失败返回 default。
pub fn safe_int(v: &Value, default: i64) -> i64 {
    match v {
        Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_f64().map(|f| f as i64))
            .unwrap_or(default),
        Value::String(s) => s.trim().parse::<i64>().unwrap_or(default),
        Value::Bool(b) => *b as i64,
        _ => default,
    }
}

/// 判断字符串是否为 IP 地址（v4/v6），即非 hostname。
pub fn is_ip_address(s: &str) -> bool {
    std::net::IpAddr::from_str(s).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn safe_int_handles_dirty_port_strings() {
        assert_eq!(safe_int(&json!("443"), 0), 443);
        assert_eq!(safe_int(&json!("443abc"), 0), 0);
        assert_eq!(safe_int(&json!(null), 7), 7);
        assert_eq!(safe_int(&json!(51000), 0), 51000);
        assert_eq!(safe_int(&json!(""), 9), 9);
    }

    #[test]
    fn is_ip_address_rejects_hostnames() {
        assert!(is_ip_address("168.107.71.181"));
        assert!(is_ip_address("::1"));
        assert!(!is_ip_address("sg.lsp121.eu.org"));
        assert!(!is_ip_address(""));
    }
}
