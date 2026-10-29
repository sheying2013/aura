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

# 2. 备份现有 panel.conf（保留权限/字节）并用镜像内的 Rust 二进制读取配置；显式 AURA_PORT 通过原子写入更新。
mkdir -p "$DATA_DIR"
CONF_FILE="$DATA_DIR/panel.conf"
CONF_BAK=""
CONF_EXISTED=0
KEEP_CONF_BAK=0
if [ -f "$CONF_FILE" ]; then
  CONF_EXISTED=1
  CONF_BAK=$(mktemp "$DATA_DIR/.panel.conf.bak.XXXXXX")
  if ! cp -p "$CONF_FILE" "$CONF_BAK"; then
    echo "!!! panel.conf 备份失败，未更改配置或停止旧容器" >&2
    if rm -f "$CONF_BAK"; then
      CONF_BAK=""
    else
      echo "!!! 备份残留于 $CONF_BAK" >&2
      KEEP_CONF_BAK=1
    fi
    exit 1
  fi
fi

NEED_ROLLBACK=0
CONFIG_TOUCHED=0
DEPLOY_SUCCEEDED=0
OLD_IMAGE_ID=""

DOCKER_RUN_OPTS=(
  --network host
  --log-driver json-file
  --log-opt max-size=10m
  --log-opt max-file=3
  -v "$DATA_DIR:/app/backend/data"
  --restart unless-stopped
)

ROLLBACK_FAILED=0
restore_panel_conf() {
  if [ "$CONF_EXISTED" -eq 1 ]; then
    if [ ! -f "$CONF_BAK" ]; then
      echo "!!! panel.conf 备份缺失，无法恢复原配置" >&2
      KEEP_CONF_BAK=1
      ROLLBACK_FAILED=1
      return 1
    fi
    local restore_tmp
    if ! restore_tmp=$(mktemp "${CONF_FILE}.restore.XXXXXX"); then
      echo "!!! 无法创建 panel.conf 恢复临时文件；备份保留于 $CONF_BAK" >&2
      KEEP_CONF_BAK=1
      ROLLBACK_FAILED=1
      return 1
    fi
    if cp -p "$CONF_BAK" "$restore_tmp" && mv -f "$restore_tmp" "$CONF_FILE"; then
      if rm -f "$CONF_BAK"; then
        CONF_BAK=""
      else
        echo "!!! 原配置已恢复，但备份清理失败：$CONF_BAK" >&2
        KEEP_CONF_BAK=1
      fi
      CONFIG_TOUCHED=0
      echo "  已恢复原 panel.conf"
    else
      rm -f "$restore_tmp" || true
      echo "!!! panel.conf 恢复失败；备份保留于 $CONF_BAK" >&2
      KEEP_CONF_BAK=1
      ROLLBACK_FAILED=1
      return 1
    fi
  else
    if rm -f "$CONF_FILE"; then
      CONFIG_TOUCHED=0
      echo "  已移除本次新建的 panel.conf"
    else
      echo "!!! 无法移除本次新建的 panel.conf" >&2
      ROLLBACK_FAILED=1
      return 1
    fi
  fi
}

rollback() {
  local active="$NEED_ROLLBACK"
  local cleanup_ok=1
  NEED_ROLLBACK=0
  echo "=== 执行回滚 ==="
  if [ "$active" -eq 1 ]; then
    local cleanup_error
    if ! cleanup_error=$(docker rm -f "$CONTAINER" 2>&1); then
      echo "ROLLBACK_FAILED container_cleanup" >&2
      if [ -n "$cleanup_error" ]; then
        printf 'docker rm error: %s\n' "$cleanup_error" >&2
      fi
      cleanup_ok=0
      ROLLBACK_FAILED=1
    fi
  fi
  restore_panel_conf || ROLLBACK_FAILED=1
  if [ -n "$OLD_IMAGE_ID" ]; then
    echo "  正在用原镜像 $OLD_IMAGE_ID 恢复旧容器..."
    if docker run -d --name "$CONTAINER" "${DOCKER_RUN_OPTS[@]}" "$OLD_IMAGE_ID"; then
      if [ "$ROLLBACK_FAILED" -eq 0 ]; then
        echo "ROLLBACK_DONE old_image=$OLD_IMAGE_ID"
      else
        echo "ROLLBACK_PARTIAL old_image=$OLD_IMAGE_ID" >&2
      fi
    else
      echo "ROLLBACK_FAILED old_image=$OLD_IMAGE_ID" >&2
      ROLLBACK_FAILED=1
    fi
  elif [ "$cleanup_ok" -eq 1 ]; then
    echo "  无可回滚版本（此前未运行面板容器，已清理失败容器）"
  else
    echo "  无可回滚版本；失败容器清理失败" >&2
  fi
  [ "$ROLLBACK_FAILED" -eq 0 ]
}

on_exit() {
  local exit_code=$?
  trap - EXIT
  # Ignore repeated signals while restoring the original config/container.
  trap ':' INT TERM HUP
  if [ "${NEED_ROLLBACK:-0}" -eq 1 ]; then
    rollback || true
  elif [ "${CONFIG_TOUCHED:-0}" -eq 1 ] && [ "${DEPLOY_SUCCEEDED:-0}" -eq 0 ]; then
    restore_panel_conf || true
  fi
  if [ "$KEEP_CONF_BAK" -eq 0 ] && [ -n "${CONF_BAK:-}" ]; then
    rm -f "$CONF_BAK"
  fi
  exit "$exit_code"
}
trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

panel_args=(panel-config)
if [ -n "$PORT_OVERRIDE" ]; then
  CONFIG_TOUCHED=1
  panel_args+=("$PORT_OVERRIDE")
fi
PANEL_CONFIG=$(docker run --rm --entrypoint /app/backend/aura \
  -v "$DATA_DIR:/app/backend/data" \
  -e AURA_DATA_DIR=/app/backend/data \
  "$IMAGE" "${panel_args[@]}")
PORT="${PANEL_CONFIG%%$'\n'*}"
PANEL_PATH="${PANEL_CONFIG#*$'\n'}"
echo "  端口: $PORT"
echo "  登录路径: $PANEL_PATH"

# 3. 配置检查通过后记录不可变镜像 ID 并重启容器
echo "=== 重启容器 ==="
OLD_CONTAINER_ID=$(docker ps -aq --filter "name=^/${CONTAINER}$")
if [ -n "$OLD_CONTAINER_ID" ]; then
  OLD_IMAGE_ID=$(docker inspect -f '{{.Image}}' "$OLD_CONTAINER_ID")
  OLD_IMAGE_ID=$(printf '%s' "$OLD_IMAGE_ID" | tr -d '[:space:]')
  if [ -z "$OLD_IMAGE_ID" ]; then
    echo "!!! 无法读取旧容器镜像 ID；保留旧容器并取消更新" >&2
    exit 1
  fi
fi
NEED_ROLLBACK=1
docker rm -f "$CONTAINER" 2>/dev/null || true

# host 网络：sing-box 的所有入站端口（面板 + 节点端口 + 域名轮询入口如 33440）
# 直接监听宿主机，无需为每个端口手动映射；任意新增 relay 域名端口即时生效
if ! docker run -d --name "$CONTAINER" "${DOCKER_RUN_OPTS[@]}" "$IMAGE"; then
  echo "!!! 新容器启动失败"
  rollback
  exit 1
fi

echo "=== 验证 ==="
sleep 5
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "http://127.0.0.1:$PORT$PANEL_PATH/" || echo 000)
echo "WebUI: HTTP $code"
if [ "$code" != "200" ]; then
  echo "!!! 面板未就绪，查看日志:"
  docker logs --tail 20 "$CONTAINER" 2>/dev/null || true
  rollback
  exit 1
fi

DEPLOY_SUCCEEDED=1
NEED_ROLLBACK=0
rm -f "$CONF_BAK"
trap - EXIT

echo ""
echo "✓ 更新完成，访问: http://<服务器IP>:$PORT$PANEL_PATH"
echo "  容器: docker logs -f $CONTAINER"
