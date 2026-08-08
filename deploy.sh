#!/usr/bin/env bash
# Aura 面板 VPS 一键更新脚本
# 镜像在 GitHub Actions 云端构建（ghcr.io），本机严禁编译，只拉取+重启
#
# 用法：curl -fsSL https://raw.githubusercontent.com/sheying2013/aura/main/deploy.sh | bash
# 或：  bash deploy.sh
set -euo pipefail

# 镜像地址（GitHub Actions docker-publish workflow 推送）
IMAGE="ghcr.io/sheying2013/aura:latest"
PORT="${AURA_PORT:-19001}"
DATA_DIR="${AURA_DATA_DIR:-$(pwd)/data}"
CONTAINER="aura-panel"

echo "=== Aura 面板更新 ==="
echo "  镜像: $IMAGE"
echo "  端口: $PORT"
echo "  数据: $DATA_DIR"

# 1. 拉取最新镜像（云端已构建好，本地不编译）
echo "=== 拉取镜像 ==="
docker pull "$IMAGE"

# 2. 停旧容器（保留数据卷）
echo "=== 重启容器 ==="
docker rm -f "$CONTAINER" 2>/dev/null || true

mkdir -p "$DATA_DIR"
docker run -d --name "$CONTAINER" \
  -p "$PORT:$PORT" \
  -v "$DATA_DIR:/app/backend/data" \
  --restart unless-stopped \
  "$IMAGE"

echo "=== 验证 ==="
sleep 5
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "http://127.0.0.1:$PORT/admin/" || echo 000)
echo "WebUI: HTTP $code"
[ "$code" = "200" ] || { echo "!!! 面板未就绪，查看日志:"; docker logs --tail 20 "$CONTAINER"; exit 1; }

echo ""
echo "✓ 更新完成，访问: http://<服务器IP>:$PORT/admin"
echo "  容器: docker logs -f $CONTAINER"
