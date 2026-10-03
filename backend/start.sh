#!/bin/bash
# Aura 面板启动脚本：从 panel.conf 读取面板端口启动 uvicorn
# 供 systemd 服务 / 手动启动 / aura CLI 重启 统一使用
set -e
cd "$(dirname "$0")"
PORT=$(python3 -c "import panel_config; print(panel_config.get('port') or 19001)" 2>/dev/null || echo 19001)
mkdir -p data static/js
# 仓库根的前端资源为权威源；Docker 已在构建时复制，容器内无需根文件。
if [ -f ../index.html ]; then
  cp -f ../index.html static/index.html
fi
if [ -d ../static/js ]; then
  cp -R ../static/js/. static/js/
fi

exec uvicorn app:app --host 0.0.0.0 --port "$PORT"
