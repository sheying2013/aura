#!/usr/bin/env bash
# Aura 面板 VPS 一键更新脚本
# 镜像在 GitHub Actions 云端构建（ghcr.io），本机严禁编译，只拉取+重启
#
# 用法：curl -fsSL https://raw.githubusercontent.com/sheying2013/aura/main/deploy.sh | bash
# 或：  bash deploy.sh
set -euo pipefail

# 镜像地址（GitHub Actions docker-publish workflow 推送）
IMAGE="ghcr.io/sheying2013/aura:latest"
PORT_OVERRIDE="${AURA_PORT:-}"
# 数据目录固定路径（不随执行目录变化，避免更新时挂错卷丢数据/丢密码）
DATA_DIR="${AURA_DATA_DIR:-/opt/aura/data}"
CONTAINER="aura-panel"

echo "=== Aura 面板更新 ==="
echo "  镜像: $IMAGE"
echo "  数据: $DATA_DIR"

# 旧数据迁移：历史版本曾在 $(pwd)/data 或 /root/aura/data 落库，
# 若新固定路径无 db 而旧位置有，先迁移（保住节点库与密码）
if [ ! -f "$DATA_DIR/panel.db" ]; then
  for old in "$(pwd)/data" "/root/aura/data" "$(dirname "$0")/data"; do
    if [ -f "$old/panel.db" ]; then
      echo "  检测到旧数据目录: $old，迁移到 $DATA_DIR"
      mkdir -p "$DATA_DIR"
      cp -a "$old/." "$DATA_DIR/"
      break
    fi
  done
fi

# 1. 拉取最新镜像（云端已构建好，本地不编译）
echo "=== 拉取镜像 ==="
docker pull "$IMAGE"

# 2. 用镜像内的 Python 读取持久配置；仅显式 AURA_PORT 改写端口。
# panel_config.set_many 使用临时文件 + os.replace，保留登录路径和用户名。
mkdir -p "$DATA_DIR"
PANEL_CONFIG=$(docker run --rm --entrypoint python \
  -v "$DATA_DIR:/app/backend/data" \
  -e "AURA_PORT=$PORT_OVERRIDE" \
  "$IMAGE" -c '
import os
import panel_config

override = os.environ.get("AURA_PORT", "")
config = panel_config.show()
port_value = override if override else config.get("port") or 19001
port_text = str(port_value)
if not port_text.isascii() or not port_text.isdecimal() or not 1 <= int(port_text) <= 65535:
    raise SystemExit("面板端口不合法，应为 1-65535 的整数")
port = int(port_text)
path = config.get("panel_path") or "/admin"
if not isinstance(path, str) or not path.startswith("/") or any(c.isspace() for c in path):
    raise SystemExit("面板登录路径不合法")
if override:
    panel_config.set_many({"port": port})
print(port)
print(path)
')
PORT="${PANEL_CONFIG%%$'\n'*}"
PANEL_PATH="${PANEL_CONFIG#*$'\n'}"
echo "  端口: $PORT"
echo "  登录路径: $PANEL_PATH"

# 3. 配置检查通过后停旧容器（保留数据卷）
echo "=== 重启容器 ==="
docker rm -f "$CONTAINER" 2>/dev/null || true

# host 网络：sing-box 的所有入站端口（面板 + 节点端口 + 域名轮询入口如 33440）
# 直接监听宿主机，无需为每个端口手动映射；任意新增 relay 域名端口即时生效
docker run -d --name "$CONTAINER" \
  --network host \
  --log-driver json-file \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  -v "$DATA_DIR:/app/backend/data" \
  --restart unless-stopped \
  "$IMAGE"

echo "=== 验证 ==="
sleep 5
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "http://127.0.0.1:$PORT$PANEL_PATH/" || echo 000)
echo "WebUI: HTTP $code"
[ "$code" = "200" ] || { echo "!!! 面板未就绪，查看日志:"; docker logs --tail 20 "$CONTAINER"; exit 1; }

echo ""
echo "✓ 更新完成，访问: http://<服务器IP>:$PORT$PANEL_PATH"
echo "  容器: docker logs -f $CONTAINER"
