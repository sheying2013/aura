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

> 端口段约定：`51` 开头端口 = 高质量 ISP IP（住宅/原生/家宽），`52` 开头端口 = 普通 IP（机房/转发）。

---

## 🚀 快速开始

| 方式 | 适合场景 |
|---|---|
| [Docker 安装](#-docker-安装) | 有 Docker 的服务器，最省事 |
| [一键脚本安装](#-一键脚本安装) | Linux / macOS，自动装内核 + 依赖 |
| [手动安装](#-手动安装) | 想自己掌控每一步 |

安装后访问：`http://<服务器IP>:19001/admin`

默认账号 `admin`，**首次登录强制修改密码**。

---

## 🐳 Docker 安装

需要 Docker 19.03+（`docker compose` 命令，或 `docker-compose`）。

### 1. 获取代码

```bash
git clone <你的仓库地址> aura
cd aura
```

### 2. 启动

```bash
docker compose up -d --build
```

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

适合没有 Docker 的 Linux 服务器（自动装 sing-box 内核 + Python 依赖 + systemd 守护）。

### 方式 A：克隆后执行

```bash
git clone <你的仓库地址> aura
cd aura
bash install.sh
```

### 方式 B：远程执行（仓库公开后）

```bash
curl -fsSL https://raw.githubusercontent.com/<USER>/aura/main/install.sh | bash
```

### 可调环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `AURA_DIR` | `$HOME/aura` | 安装目录 |
| `AURA_PORT` | `19001` | 面板端口 |
| `SINGBOX_VERSION` | `1.7.7` | sing-box 内核版本 |

```bash
AURA_PORT=8080 bash install.sh
```

Linux 下以 root 运行会自动注册 `aura.service` systemd 服务（开机自启 + 崩溃重启）；非 root 或 macOS 退化为前台运行。

---

## 🛠️ 手动安装

### 前置要求

- Python 3.11+
- sing-box 内核（1.7.x，[下载地址](https://github.com/SagerNet/sing-box/releases)）
- git

### 1. 获取代码

```bash
git clone <你的仓库地址> aura
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
uvicorn app:app --host 0.0.0.0 --port 19001
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
- **批量导入**：订阅一键导入，自动按名称判定 51/52 端口段，去重 + 分组继承
- **端口段铁律**：`51` 段 = 高质量 ISP IP，`52` 段 = 普通 IP，一键重新分配
- **面板认证**：登录门 + token 鉴权 + 强制首次改密 + 登录限流
- **配置回滚**：配置校验失败自动回滚上一份好配置，sing-box 崩溃 10s 守护重启

---

## ❓ FAQ

**Q: 端口段「高质量」和「普通」怎么判定？**
节点名称包含住宅/ISP/原生/家宽/residential 等关键词自动归入 `51` 段（高质量），否则归入 `52` 段（普通）。「代理池」是独立于端口段的第三分组，按节点分组名统计。

**Q: 默认密码是什么？**
`admin`。首次登录强制修改密码，改密后 token 自动刷新。

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
