<div align="center">

# 🌅 Aura

**SingBox 中转节点管理面板** — 专做 socks5 / http 出站中转

一个域名入口 · 多个节点出口 · 极速节点中转

[快速开始](#-快速开始) · [Docker 安装](#-docker-安装) · [一键脚本安装](#-一键脚本安装) · [手动安装](#-手动安装) · [功能特性](#-功能特性) · [FAQ](#-faq)

</div>

---

## ✨ 简介

Aura 是一个基于 **sing-box 内核** 的节点中转管理面板。它把外部 ss / vmess / vless / trojan 等节点，转成本机可直连的 **socks5 / http 代理端口**，并支持**域名解析轮询入口**——对外一个固定地址，后端按分组自动轮询所选节点作为出口。

**核心卖点**：所有入站端口对外统一，出口节点可随时在面板里切换、探活、分组，无需改动客户端。

> 分组约定：**高质量**（住宅/原生/家宽 ISP IP）、**普通**（机房/转发）、**代理池**（独立第三组，按节点分组名「代理池」统计）。

---

## 🚀 快速开始

| 方式 | 适合场景 |
|---|---|
| [Docker 安装](#-docker-安装) | 有 Docker 的服务器，最省事 |
| [一键脚本安装](#-一键脚本安装) | Linux / macOS，自动装内核 + 依赖 |
| [手动安装](#-手动安装) | 想自己掌控每一步 |

安装后访问：`http://<服务器IP>:19001/admin`

### 默认值

| 项目 | 默认值 | 修改方式 |
|---|---|---|
| 面板端口 | `19001` | 一键脚本安装时交互设置，或终端输入 `aura` 配置 |
| 网页登录路径 | `/admin` | 一键脚本安装时交互设置，或终端输入 `aura` 配置 |
| 登录账号 | `admin` | 一键脚本安装时交互设置，或终端输入 `aura` 配置 |
| 登录密码 | `admin` | **首次登录强制修改**，或终端输入 `aura` 配置 |

> **一键脚本安装时全部交互式引导设置**（端口/路径/账号/密码），并配置开机自启。安装后终端输入 `aura` 可随时调出交互式配置界面（改端口/路径/账号/密码/更新面板/服务控制）。

---

## 🐳 Docker 安装

需要 Docker 19.03+（`docker compose` 命令，或 `docker-compose`）。

### 1. 获取代码

```bash
git clone https://github.com/sheying2013/aura.git aura
cd aura
```

### 2. 启动

```bash
docker compose up -d --build
```

> **架构**：Dockerfile 自动探测架构（amd64 / arm64），x86_64 与 ARM 服务器（Oracle ARM、Apple Silicon）均可直接构建。

### 3. 验证

```bash
docker compose ps          # 容器状态
docker compose logs -f aura  # 实时日志
```

数据（节点库 / 生成配置 / 运行日志）持久化在宿主机 `./data` 目录，容器重建不丢失。

### 单独用 Dockerfile

```bash
docker build -t aura-panel .
docker run -d --name aura-panel \
  -p 19001:19001 \
  -v "$(pwd)/data:/app/backend/data" \
  --restart unless-stopped \
  aura-panel
```

---

## 🖥️ 一键脚本安装

适合没有 Docker 的 Linux 服务器（自动装 sing-box 内核 + Python 依赖 + **交互式设置面板端口/路径/账号/密码** + systemd 开机自启 + 安装 `aura` 配置命令）。

> **架构支持**：x86_64/amd64 与 arm64/aarch64（Apple Silicon、Oracle ARM、树莓派 64 位等）全支持。macOS 也支持（Intel 和 Apple Silicon），自动下载对应架构的 sing-box，并解除 macOS Gatekeeper 隔离。

### 方式 A：克隆后执行

```bash
git clone https://github.com/sheying2013/aura.git aura
cd aura
bash install.sh
```

### 方式 B：远程执行

```bash
curl -fsSL https://raw.githubusercontent.com/sheying2013/aura/main/install.sh | bash
```

### 安装过程

脚本交互式引导（直接回车用默认值）：

```
面板端口 [19001]:
网页登录路径 [/admin]:
登录账号 [admin]:
登录密码（至少6位，留空自动生成）:
```

### 安装后

- **开机自启**：Linux root 下自动注册 `aura.service` systemd 服务（开机自启 + 崩溃重启）；macOS 安装时可选择注册 launchd 后台服务（同样开机自启 + 崩溃重启）
- **aura 命令**：终端输入 `aura` 调出交互式配置界面，随时改端口/路径/账号/密码、更新面板、重启服务
- 访问 `http://<服务器IP>:<端口>/<路径>` 登录

### 可调环境变量（完全非交互安装）

| 变量 | 默认值 | 说明 |
|---|---|---|
| `AURA_PORT` | `19001` | 面板端口 |
| `AURA_PATH` | `/admin` | 网页登录路径 |
| `AURA_USERNAME` | `admin` | 登录账号 |
| `AURA_PASSWORD` | 随机生成 | 登录密码 |
| `AURA_DIR` | `$HOME/aura` | 安装目录 |
| `AURA_SKIP_INPUT` | `0` | `1`=跳过交互，全部用默认/环境变量 |

```bash
AURA_PORT=8080 AURA_USERNAME=mine AURA_PASSWORD='x9Kd@w' AURA_SKIP_INPUT=1 bash install.sh
```

---

## 🛠️ 手动安装

### 前置要求

- Python 3.11+
- sing-box 内核（1.7.x，[下载地址](https://github.com/SagerNet/sing-box/releases)）
- git

### 1. 获取代码

```bash
git clone https://github.com/sheying2013/aura.git aura
cd aura
```

### 2. 安装 sing-box

将 `sing-box` 二进制放入 `PATH`（如 `/usr/local/bin/`），并验证：

```bash
sing-box version
```

### 3. 安装 Python 依赖

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 4. 同步前端资源

```bash
mkdir -p static
cp ../index.html static/index.html
cp ../subs.js    static/subs.js
```

### 5. 启动

```bash
# 推荐：start.sh 自动读取面板端口（data/panel.conf）并同步前端
cd backend && bash start.sh
```

或手动指定端口：

```bash
uvicorn app:app --host 0.0.0.0 --port 19001
```

### 5.1 配置默认账号密码

首次启动后默认账号 `admin` / 密码 `admin`，**登录后强制修改密码**。也可以在启动前直接设置：

```bash
cd backend && python3 -c "import panel_config, db; from auth import hash_password; panel_config.set_many({'port': 19001, 'panel_path': '/admin', 'username': 'admin'}); db.init_db(); db.set_setting('auth', {'password_hash': hash_password('你的密码'), 'password_change_required': False, 'changed_at': 0}); print('ok')"
```

### 6. systemd 守护（可选）

```ini
# /etc/systemd/system/aura.service
[Unit]
Description=Aura - SingBox Relay Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=/path/to/aura/backend
Environment=SINGBOX_BIN=/usr/local/bin/sing-box
ExecStart=/path/to/aura/backend/.venv/bin/uvicorn app:app --host 0.0.0.0 --port 19001
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aura.service
```

---

## 📦 功能特性

- **多协议入站**：socks5 / http 双协议统一入站（mixed），或 Shadowsocks 单协议入站
- **多协议出站**：ss / vmess / vless / trojan / hysteria2 / tuic / wireguard / socks / http 节点全部支持
- **域名解析轮询入口**：多个独立域名入口，每个域名独立监听端口 + 独立分组，自动 urltest 轮询出口
- **真实探活**：通过 sing-box clash_api 对每个节点做真实延迟探测，离线节点自动标记
- **实时流量统计**：全局速率 + 每节点归属流量，SSE 推送前端
- **订阅管理**：URL 拉取、多格式解析（Base64 / Clash YAML / JSON / 明文）、6 小时自动刷新、last-good 快照兜底
- **批量导入**：订阅一键导入，自动按名称判定高质量/普通分组，去重 + 分组继承
- **三组分组**：高质量（ISP IP）/ 普通 / 代理池（独立分组名），一键重新分配端口
- **面板认证**：登录门 + token 鉴权 + 强制首次改密 + 登录限流
- **配置回滚**：配置校验失败自动回滚上一份好配置，sing-box 崩溃 10s 守护重启

---

## ❓ FAQ

**Q: 高质量 / 普通 / 代理池 怎么分？**
节点名称包含住宅/ISP/原生/家宽/residential 等关键词自动归入高质量，否则归入普通。「代理池」是独立第三组——分组名为「代理池」的节点，与端口段无关。

**Q: 默认账号密码 / 端口 / 路径是什么？**
默认账号 `admin`、密码 `admin`、端口 `19001`、路径 `/admin`。首次登录强制修改密码。一键脚本安装时会交互式引导设置，装完后终端输入 `aura` 可随时改。

**Q: 数据存在哪？**
`backend/data/panel.db`（SQLite）。Docker 部署则映射在宿主 `./data` 目录。

**Q: 如何关闭认证（仅本地调试）？**
启动时设置环境变量 `AUTH_DISABLED=1`。

**Q: sing-box 内核装不上怎么办？**
确认架构（`uname -m`，arm64 需选 aarch64 包）与版本号，可手动下载后放到 `PATH`，用 `SINGBOX_BIN` 环境变量指定路径。

---

## 📄 License

MIT License — 自由使用，欢迎二次开发。

---

<div align="center">

**Aura Relay Management WebUI © 2026 · socks5/http outbound relay panel**

</div>
