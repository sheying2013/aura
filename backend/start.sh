#!/bin/bash
# Aura 面板启动脚本：从 panel.conf 读取面板端口启动 uvicorn
# 供 systemd 服务 / 手动启动 / aura CLI 重启 统一使用
set -e
cd "$(dirname "$0")"
PORT=$(python3 -c "import panel_config; print(panel_config.get('port') or 19001)" 2>/dev/null || echo 19001)
mkdir -p data static/js
# 同步前端文件（编辑源在仓库根，启动时刷新副本）
[ -f ../index.html ]          && cp -f ../index.html          static/index.html
[ -f ../subs.js ]                && cp -f ../subs.js                static/subs.js
[ -f ../static/js/main.js ]   && cp -f ../static/js/main.js   static/js/main.js

exec uvicorn app:app --host 0.0.0.0 --port "$PORT"
