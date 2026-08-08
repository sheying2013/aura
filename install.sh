#!/usr/bin/env bash
# ============================================================
#  Aura · SingBox 中转节点管理面板 一键安装脚本
#  Linux (systemd 守护 + 开机自启) / macOS (前台启动)
#
#  用法：
#    1) 已克隆仓库（推荐）：
#         git clone https://github.com/sheying2013/aura.git aura && cd aura && bash install.sh
#    2) 远程执行：
#         curl -fsSL https://raw.githubusercontent.com/sheying2013/aura/main/install.sh | bash
#         （脚本会从 AURA_REPO_URL 克隆代码）
#
#  安装过程交互式引导设置：面板端口 / 网页登录路径 / 登录账号 / 登录密码
#  安装完成后：
#    - 注册 systemd 服务（Linux root）并开机自启
#    - 安装 `aura` 命令，终端输入 aura 调出交互式配置界面
#
#  可调环境变量（跳过交互，全部默认）：
#    AURA_REPO_URL   仓库地址（默认 https://github.com/sheying2013/aura.git）
#    AURA_DIR        安装目录（默认 $HOME/aura）
#    AURA_PORT       面板端口（默认 19001）
#    AURA_PATH       网页登录路径（默认 /admin）
#    AURA_USERNAME   登录账号（默认 admin）
#    AURA_PASSWORD   登录密码（默认随机生成）
#    AURA_SKIP_INPUT 1=完全非交互，全部用默认/环境变量
# ============================================================
set -euo pipefail

# ---------- 配置 ----------
REPO_URL="${AURA_REPO_URL:-https://github.com/sheying2013/aura.git}"
INSTALL_DIR="${AURA_DIR:-$HOME/aura}"
PORT="${AURA_PORT:-}"
PATH_PREFIX="${AURA_PATH:-}"
USERNAME="${AURA_USERNAME:-}"
PASSWORD="${AURA_PASSWORD:-}"
SKIP_INPUT="${AURA_SKIP_INPUT:-0}"
SINGBOX_VERSION="${SINGBOX_VERSION:-1.7.7}"

# ---------- 输出工具 ----------
color() { printf "\033[%sm%s\033[0m" "$1" "$2"; }
info()  { color "36" "[*] $1\n"; }
ok()    { color "32" "[✔] $1\n"; }
warn()  { color "33" "[!] $1\n"; }
fail()  { color "31" "[✘] $1\n"; exit 1; }

prompt_input() {
  local p="$1" default="$2"
  local val=""
  printf "%s" "$p"
  if [ -n "$default" ]; then
    printf " [%s]" "$default"
  fi
  printf ": "
  read -r val
  if [ -z "$val" ]; then
    val="$default"
  fi
  printf "%s" "$val"
}

# ---------- 系统检测 ----------
detect_os() {
  case "$(uname -s)" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "darwin" ;;
    *)       fail "不支持的系统: $(uname -s)" ;;
  esac
}

detect_arch() {
  local m
  m="$(uname -m)"
  case "$m" in
    x86_64|amd64|x64|intel)      echo "amd64" ;;
    aarch64|arm64|armv8|armv8l)  echo "arm64" ;;
    armv7l|armv7|armhf)          echo "armv7" ;;
    *) fail "不支持的架构: $m" ;;
  esac
}

OS=$(detect_os)
ARCH=$(detect_arch)
info "系统: $OS / 架构: $ARCH"

# ---------- 就位源码 ----------
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
    info "检测到 sing-box $ver，跳过安装"
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
  info "下载 sing-box v${SINGBOX_VERSION:-1.7.7} ($OS-$ARCH)..."
  if [ "$ARCH" = "armv7" ]; then
    fail "sing-box 不提供 32 位 ARM 资产，请用 64 位系统（arm64/amd64）"
  fi
  TARBALL="sing-box-${SINGBOX_VERSION:-1.7.7}-${OS}-${ARCH}.tar.gz"
  curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION:-1.7.7}/${TARBALL}" -o /tmp/singbox.tar.gz
  tar -xzf /tmp/singbox.tar.gz -C /tmp
  cp "/tmp/sing-box-${SINGBOX_VERSION:-1.7.7}-${OS}-${ARCH}/sing-box" "$SB_BIN"
  chmod +x "$SB_BIN"
  # macOS：解除 Gatekeeper 隔离，否则直接运行报"来自身份不明的开发者"
  if [ "$OS" = "darwin" ]; then
    xattr -d com.apple.quarantine "$SB_BIN" 2>/dev/null || true
  fi
  rm -rf /tmp/singbox.tar.gz /tmp/sing-box-*
  # 确保 BIN_DIR 在 PATH 中（macOS 默认不含 ~/.local/bin）
  if ! echo ":$PATH:" | grep -q ":$BIN_DIR:"; then
    export PATH="$BIN_DIR:$PATH"
    if [ -f "$HOME/.zshrc" ]; then
      echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc" 2>/dev/null || true
    fi
    if [ -f "$HOME/.bashrc" ]; then
      echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc" 2>/dev/null || true
    fi
  fi
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

# ---------- 交互引导配置 ----------
configure_panel() {
  echo
  info "面板配置引导（直接回车使用默认值，随时 Ctrl+C 取消）"
  echo

  if [ -z "$PORT" ] && [ "$SKIP_INPUT" != "1" ]; then
    PORT=$(prompt_input "面板端口" "19001")
  fi
  PORT="${PORT:-19001}"
  case "$PORT" in
    ''|*[!0-9]*) fail "端口不合法: $PORT" ;;
    *) ;;
  esac

  if [ -z "$PATH_PREFIX" ] && [ "$SKIP_INPUT" != "1" ]; then
    PATH_PREFIX=$(prompt_input "网页登录路径" "/admin")
  fi
  PATH_PREFIX="${PATH_PREFIX:-/admin}"
  case "$PATH_PREFIX" in
    /*) ;;
    *) fail "路径必须以 / 开头: $PATH_PREFIX" ;;
  esac

  if [ -z "$USERNAME" ] && [ "$SKIP_INPUT" != "1" ]; then
    USERNAME=$(prompt_input "登录账号" "admin")
  fi
  USERNAME="${USERNAME:-admin}"
  case "$USERNAME" in
    *[[:space:]]*|*/*) fail "账号不能含空格或斜杠: $USERNAME" ;;
    *) ;;
  esac

  # 密码：用户显式提供（交互输入或 AURA_PASSWORD）才算"想改密码"；
  # 自动生成的随机密码只在首次安装时用，重跑/更新时不得覆盖已有密码
  PASSWORD_EXPLICIT="0"
  if [ -n "$AURA_PASSWORD" ]; then
    PASSWORD="$AURA_PASSWORD"
    PASSWORD_EXPLICIT="1"
  fi
  if [ -z "$PASSWORD" ] && [ "$SKIP_INPUT" != "1" ]; then
    PASSWORD=$(prompt_input "登录密码（至少6位，留空保持当前密码）" "")
    if [ -n "$PASSWORD" ]; then
      PASSWORD_EXPLICIT="1"
    fi
  fi
  if [ -z "$PASSWORD" ] && [ "$PASSWORD_EXPLICIT" = "0" ]; then
    # 无显式密码：生成一个候选（若 db 已有密码，python 端会保留旧的，此候选被忽略）
    PASSWORD="$(head -c 12 /dev/urandom | base64 | tr -d '/+=' | head -c 12)"
  fi

  # 写入 panel.conf + 数据库密码（用 base64 传参避免特殊字符破坏 shell）
  # 密码持久化：db 已有 password_hash 时保留（不覆盖），除非用户显式输入新密码
  local pass_b64 force_pw PW_RESULT
  pass_b64="$(printf '%s' "$PASSWORD" | base64 | tr -d '\n')"
  force_pw="$PASSWORD_EXPLICIT"
  info "写入面板配置..."
  PW_RESULT="$( cd "$SRC_DIR/backend" && \
    PORT="$PORT" PANEL_PATH="$PATH_PREFIX" PANEL_USER="$USERNAME" \
    PASS_B64="$pass_b64" FORCE_PW="$force_pw" \
    "$PY" -c "
import os, base64, time
import panel_config, db
from auth import hash_password
panel_config.set_many({
    'port': int(os.environ['PORT']),
    'panel_path': os.environ['PANEL_PATH'],
    'username': os.environ['PANEL_USER'],
})
db.init_db()
auth = db.get_setting('auth', {}) or {}
existing = auth.get('password_hash')
force = os.environ.get('FORCE_PW') == '1'
if existing and not force:
    # 密码持久化：已有密码则保留（更新/重装不重置密码）
    print('PW_KEPT')
else:
    passwd = base64.b64decode(os.environ['PASS_B64']).decode()
    db.set_setting('auth', {
        'password_hash': hash_password(passwd),
        'password_change_required': False,
        'changed_at': int(time.time() * 1000),
    })
    print('PW_SET')
" 2>/dev/null | grep -oE 'PW_(KEPT|SET)' | head -1 )"
  case "$PW_RESULT" in
    PW_KEPT) ok "配置已保存（已保留现有登录密码）" ;;
    PW_SET)  ok "配置已保存（登录密码已设置，请牢记！）" ;;
    *)       ok "配置已保存" ;;
  esac
}

# 无 db.init_db 的 python 直接写 panel.conf（轻量场景由 aura_cli 兜底）
configure_panel

# ---------- 同步前端 ----------
sync_frontend() {
  mkdir -p "$SRC_DIR/backend/static"
  [ -f "$SRC_DIR/index.html" ] && cp -f "$SRC_DIR/index.html" "$SRC_DIR/backend/static/index.html"
  [ -f "$SRC_DIR/subs.js" ]    && cp -f "$SRC_DIR/subs.js"    "$SRC_DIR/backend/static/subs.js"
  ok "前端资源已同步"
}

sync_frontend

# ---------- 安装 aura 命令 ----------
link_aura_cmd() {
  local BINDIR
  if [ "$(id -u)" -eq 0 ]; then
    BINDIR="/usr/local/bin"
  else
    BINDIR="$HOME/.local/bin"
    mkdir -p "$BINDIR"
  fi
  chmod +x "$SRC_DIR/backend/aura_cli.py"
  ln -sf "$SRC_DIR/backend/aura_cli.py" "$BINDIR/aura"
  ok "aura 命令已安装: $BINDIR/aura（终端输入 aura 进入配置界面）"
}

link_aura_cmd

# ---------- 启动 ----------
start_linux() {
  if [ "$(id -u)" -ne 0 ]; then
    warn "非 root 用户，跳过 systemd 服务安装，改为前台启动"
    cd "$SRC_DIR/backend"
    exec bash start.sh
  fi
  cat > /etc/systemd/system/aura.service <<EOF
[Unit]
Description=Aura - SingBox Relay Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=$SRC_DIR/backend
Environment=SINGBOX_BIN=${SINGBOX_BIN:-sing-box}
ExecStart=$SRC_DIR/backend/start.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable aura.service >/dev/null 2>&1
  systemctl start aura.service
  ok "systemd 服务已启动并设置开机自启（aura.service）"
}

start_mac() {
  # 询问是否注册 launchd 后台服务（开机自启）
  if [ "${AURA_SKIP_INPUT}" != "1" ]; then
    local ans
    printf "注册 macOS 后台服务（launchd，开机自启）？[y/N] "
    read -r ans
    if [ "${ans:-N}" = "y" ] || [ "${ans:-N}" = "Y" ]; then
      PLIST="$HOME/Library/LaunchAgents/com.aura.panel.plist"
      mkdir -p "$HOME/Library/LaunchAgents"
      cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.aura.panel</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>$SRC_DIR/backend/start.sh</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$SRC_DIR/backend</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>SINGBOX_BIN</key>
        <string>${SINGBOX_BIN:-sing-box}</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$SRC_DIR/backend/data/panel-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>$SRC_DIR/backend/data/panel-stderr.log</string>
</dict>
</plist>
EOF
      launchctl unload "$PLIST" 2>/dev/null || true
      launchctl load "$PLIST"
      ok "已注册 launchd 服务（开机自启 + 崩溃自动重启）"
      echo "  http://127.0.0.1:${PORT}${PATH_PREFIX}"
      return
    fi
  fi
  warn "前台运行（后台服务未注册），保持本窗口即可："
  warn "  $SRC_DIR/backend/start.sh"
  cd "$SRC_DIR/backend"
  exec bash start.sh
}

echo
ok "安装完成！"
echo
echo "  ┌────────────────────────────────────────────┐"
echo "  │  Aura · SingBox 中转节点管理面板            │"
echo "  │  访问地址: http://<服务器IP>:$PORT$PATH_PREFIX"
echo "  │  登录账号: $USERNAME"
echo "  │  配置工具: 终端输入 aura                     │"
echo "  └────────────────────────────────────────────┘"
echo

if [ "$OS" = "linux" ]; then
  start_linux
else
  start_mac
fi
