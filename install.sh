#!/usr/bin/env bash
# ============================================================
#  Aura · SingBox 中转节点管理面板 一键安装脚本
#  Linux (systemd 守护) / macOS (前台启动)
#
#  用法：
#    1) 已克隆仓库（推荐）：
#         git clone <你的仓库地址> aura && cd aura && bash install.sh
#    2) 全自动（仓库公开后）：
#         curl -fsSL https://raw.githubusercontent.com/<USER>/aura/main/install.sh | bash
#         （脚本会从 AURA_REPO_URL 克隆代码）
#
#  可调环境变量：
#    AURA_REPO_URL   仓库地址（默认 GitHub sheying2013/aura）
#    AURA_DIR        安装目录（默认 $HOME/aura）
#    AURA_PORT       面板端口（默认 19001）
#    SINGBOX_VERSION sing-box 内核版本（默认 1.7.7）
# ============================================================
set -euo pipefail

# ---------- 配置 ----------
REPO_URL="${AURA_REPO_URL:-https://github.com/sheying2013/aura.git}"
INSTALL_DIR="${AURA_DIR:-$HOME/aura}"
PORT="${AURA_PORT:-19001}"
SINGBOX_VERSION="${SINGBOX_VERSION:-1.7.7}"

# ---------- 输出工具 ----------
color() { printf "\033[%sm%s\033[0m" "$1" "$2"; }
info()  { color "36" "[*] $1\n"; }
ok()    { color "32" "[✔] $1\n"; }
warn()  { color "33" "[!] $1\n"; }
fail()  { color "31" "[✘] $1\n"; exit 1; }

# ---------- 系统检测 ----------
detect_os() {
  case "$(uname -s)" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "darwin" ;;
    *)       fail "不支持的系统: $(uname -s)" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) fail "不支持的架构: $(uname -m)" ;;
  esac
}

OS=$(detect_os)
ARCH=$(detect_arch)
info "系统: $OS / 架构: $ARCH / 端口: $PORT"

# ---------- 就位源码 ----------
# 判断是否在仓库目录内运行（存在 backend/app.py）
if [ -f "backend/app.py" ]; then
  SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
  info "检测到源码目录: $SRC_DIR"
elif command -v git >/dev/null 2>&1; then
  info "未检测到源码，从仓库克隆..."
  SRC_DIR="$INSTALL_DIR"
  mkdir -p "$(dirname "$INSTALL_DIR")"
  if [ ! -d "$INSTALL_DIR/.git" ]; then
    git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
  fi
else
  fail "请先安装 git（或在本仓库目录内运行本脚本）"
fi

# ---------- 安装 sing-box 内核 ----------
install_singbox() {
  if command -v sing-box >/dev/null 2>&1; then
    ver=$(sing-box version 2>/dev/null | head -n1 | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" || echo "?")
    info "检测到 sing-box $ver，跳过安装（可用 SINGBOX_BIN 指定路径）"
    export SINGBOX_BIN="$(command -v sing-box)"
    return
  fi
  BIN_DIR="$HOME/.local/bin"
  mkdir -p "$BIN_DIR"
  SB_BIN="$BIN_DIR/sing-box"
  if [ -x "$SB_BIN" ]; then
    info "已存在 $SB_BIN，跳过下载"
    export SINGBOX_BIN="$SB_BIN"
    return
  fi
  info "下载 sing-box v$SINGBOX_VERSION ($OS-$ARCH)..."
  TARBALL="sing-box-${SINGBOX_VERSION}-${OS}-${ARCH}.tar.gz"
  curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/${TARBALL}" -o /tmp/singbox.tar.gz
  tar -xzf /tmp/singbox.tar.gz -C /tmp
  cp "/tmp/sing-box-${SINGBOX_VERSION}-${OS}-${ARCH}/sing-box" "$SB_BIN"
  chmod +x "$SB_BIN"
  rm -rf /tmp/singbox.tar.gz /tmp/sing-box-*
  export SINGBOX_BIN="$SB_BIN"
  ok "sing-box 已安装到 $SB_BIN"
}

install_singbox

# ---------- Python 依赖 ----------
setup_python() {
  command -v python3 >/dev/null 2>&1 || fail "未找到 python3，请先安装 Python 3.11+"
  PY=$(command -v python3)
  info "Python: $($PY --version 2>&1)"
  cd "$SRC_DIR/backend"

  if command -v pip3 >/dev/null 2>&1; then
    PIP="pip3"
  else
    $PY -m venv .venv
    PIP="$SRC_DIR/backend/.venv/bin/pip"
    export PATH="$SRC_DIR/backend/.venv/bin:$PATH"
  fi
  info "安装 Python 依赖..."
  $PIP install --quiet --upgrade pip
  $PIP install --quiet -r requirements.txt
  ok "依赖安装完成"
}

setup_python

# ---------- 同步前端到 static ----------
sync_frontend() {
  mkdir -p "$SRC_DIR/backend/static"
  [ -f "$SRC_DIR/index.html" ] && cp -f "$SRC_DIR/index.html" "$SRC_DIR/backend/static/index.html"
  [ -f "$SRC_DIR/subs.js" ]    && cp -f "$SRC_DIR/subs.js"    "$SRC_DIR/backend/static/subs.js"
  ok "前端资源已同步"
}

sync_frontend

# ---------- 启动 ----------
start_linux() {
  if [ "$(id -u)" -ne 0 ]; then
    warn "非 root 用户，跳过 systemd 服务安装，改为前台启动"
    cd "$SRC_DIR/backend"
    exec uvicorn app:app --host 0.0.0.0 --port "$PORT"
  fi
  cat > /etc/systemd/system/aura.service <<EOF
[Unit]
Description=Aura - SingBox Relay Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=$SRC_DIR/backend
Environment=SINGBOX_BIN=${SINGBOX_BIN:-sing-box}
ExecStart=$(command -v uvicorn || echo "$SRC_DIR/backend/.venv/bin/uvicorn") app:app --host 0.0.0.0 --port $PORT
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable aura.service >/dev/null 2>&1
  systemctl start aura.service
  ok "systemd 服务已启动（aura.service）"
}

start_mac() {
  warn "macOS 暂不注册后台服务，请保持本窗口运行："
  warn "  cd $SRC_DIR/backend && SINGBOX_BIN=${SINGBOX_BIN:-sing-box} uvicorn app:app --host 0.0.0.0 --port $PORT"
  cd "$SRC_DIR/backend"
  export SINGBOX_BIN="${SINGBOX_BIN:-sing-box}"
  exec uvicorn app:app --host 0.0.0.0 --port "$PORT"
}

echo
ok "安装完成！"
echo
echo "  ┌────────────────────────────────────────────┐"
echo "  │  Aura · SingBox 中转节点管理面板            │"
echo "  │  访问地址:  http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo <服务器IP>):$PORT/admin"
echo "  │  默认账号:  admin（首次登录请修改密码）     │"
echo "  └────────────────────────────────────────────┘"
echo

if [ "$OS" = "linux" ]; then
  start_linux
else
  start_mac
fi
