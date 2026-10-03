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
  --network host \
  -v "$(pwd)/data:/app/backend/data" \
  --restart unless-stopped \
  aura-panel
```

> **必须使用 `--network host`**（host 网络）：面板端口 + 每个节点端口 + 域名轮询入口端口（如 33440）都直接监听宿主机，任意新增 relay 域名端口即时生效，无需逐个映射端口。

### 生产更新（GitHub Actions 云端构建 + 一键部署）

镜像在 GitHub Actions 云端多架构构建（amd64 + arm64）并推送到 GHCR，**服务器上不编译**，只拉取 + 重启：

```bash
curl -fsSL https://raw.githubusercontent.com/sheying2013/aura/main/deploy.sh | bash
```

- 数据目录固定 `/opt/aura/data`（旧位置自动迁移，**更新不丢节点库/密码**）
- 更新后保留现有登录密码（install.sh / deploy.sh 均不覆盖已有密码）
- 环境变量：`AURA_PORT`（默认 19001）、`AURA_DATA_DIR`（默认 /opt/aura/data）

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
登录密码（至少6位，留空保持当前密码）:
```

首次安装留空密码会自动生成；重跑安装时留空会保留已有密码，只有交互输入或 `AURA_PASSWORD` 显式提供新密码才覆盖。

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
mkdir -p static/js
cp ../index.html static/index.html
cp -R ../static/js/. static/js/
```

### 5. 启动

```bash
# 当前已在 backend 目录；start.sh 读取面板端口（data/panel.conf）并同步前端
bash start.sh
```

或手动指定端口：

```bash
uvicorn app:app --host 0.0.0.0 --port 19001
```

### 5.1 配置默认账号密码

首次启动后默认账号 `admin` / 密码 `admin`，**登录后强制修改密码**。也可以在启动前直接设置：

```bash
python3 -c "import panel_config, db; from auth import hash_password; panel_config.set_many({'port': 19001, 'panel_path': '/admin', 'username': 'admin'}); db.init_db(); db.set_setting('auth', {'password_hash': hash_password('你的密码'), 'password_change_required': False, 'changed_at': 0}); print('ok')"
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
- **域名解析轮询入口**：多个独立域名入口，每个域名独立监听端口 + 独立分组，自动 urltest 轮询出口；入口保存后即时生效（自动热重载）
- **真实探活**：通过 sing-box clash_api 对每个节点做真实延迟探测，离线节点自动标记
- **实时流量统计**：全局速率 + 每节点归属流量，SSE 推送前端
- **订阅管理**：URL 拉取、多格式解析（Base64 / Clash YAML / JSON / 明文）、3 小时自动刷新、last-good 快照兜底
- **自动去重**：所有导入路径（批量导入 / 订阅导入 / 订阅刷新）按 server:port 自动去重，重复节点跳过并计数，不产生重复条目
- **批量导入**：订阅一键导入，自动按名称判定高质量/普通分组，去重 + 分组继承
- **三组分组**：高质量（ISP IP）/ 普通 / 代理池（独立分组名），一键重新分配端口
- **面板认证**：登录门 + token 鉴权 + 强制首次改密 + 登录限流
- **密码持久化**：更新 / 重跑安装脚本不重置已有密码，仅显式输入新密码才覆盖
- **配置回滚 + 崩溃守护**：配置校验失败自动回滚上一份好配置；sing-box 进程崩溃 10s 内自动拉起（进程状态实时感知，不死锁）
- **端口冲突检测**：应用配置前预检所有入站端口 + clash API 端口（9090），被占用时明确报错，不会静默启动失败

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

**Q: 新增节点/域名入口端口需要手动放行吗？**
系统层不需要——面板用 host 网络模式运行，任何入站端口直接监听宿主机。唯一例外是**云服务商安全组**（如 Oracle Cloud Security List）：如果安全组是白名单模式，需要在控制台放行新端口；若安全组全放行（或未启用防火墙）则无需任何操作，新增端口即时可用。

**Q: 节点重复导入会怎样？**
自动去重。所有导入路径（批量导入 / 订阅导入 / 订阅刷新）按 `server:port` 判重，重复节点自动跳过并计数（前端提示「忽略 N 个（含重复）」），不会产生重复条目。

**Q: sing-box 内核装不上怎么办？**
确认架构（`uname -m`，arm64 需选 aarch64 包）与版本号，可手动下载后放到 `PATH`，用 `SINGBOX_BIN` 环境变量指定路径。

---

## 项目结构与本地开发

```text
index.html                 页面编辑源
static/js/main.js          前端逻辑编辑源（含订阅界面）
backend/static/            后端托管副本
backend/app.py             API 与静态文件入口
backend/auth.py            登录认证
backend/db.py              SQLite 存储
backend/config_manager.py  sing-box 配置与进程管理
backend/scheduler.py       探活、自动复活与每 3 小时订阅刷新
backend/subs_proxy.py      服务端订阅解析与导入
backend/subscription_fetch.py 订阅下载与目标地址检查
backend/stats.py           流量采集
backend/start.sh           统一启动入口
install.sh                 Linux/macOS 安装入口
Dockerfile                 镜像打包入口
tests/                     离线回归测试
```

前端以仓库根的 `index.html` 与 `static/js/` 为权威源，修改这两处即可。`install.sh` 和 `backend/start.sh` 会刷新 `backend/static/` 副本；Dockerfile 直接复制根目录前端资源到镜像里的 `backend/static/`，容器无需保留根目录前端源文件。

在仓库根执行离线检查（Python 依赖需已安装）：

```bash
bash -n install.sh
bash -n backend/start.sh
python3 -m unittest discover -s tests -v
```

本地开发启动使用 `bash backend/start.sh`；直接运行 uvicorn 时，需要先按手动安装步骤同步前端资源。

---

## 📄 License

MIT License — 自由使用，欢迎二次开发。

---

<div align="center">

**Aura Relay Management WebUI © 2026 · socks5/http outbound relay panel**

</div>
