# Aura · SingBox 中转节点管理面板
# 基于 Python + sing-box 内核的 socks5/http 出站中转面板
# 构建：docker build -t aura-panel .
# 多架构：amd64 / arm64 自动检测（buildx 或原生 docker 均可）
FROM python:3.13-slim

ARG SINGBOX_VERSION=1.7.7
# sing-box 发布包架构名：amd64 | arm64（Apple Silicon/ARM 服务器自动匹配）
ARG TARGETARCH

# 映射 Docker TARGETARCH -> sing-box 发布架构名
RUN if [ -z "$TARGETARCH" ]; then \
      case "$(uname -m)" in \
        x86_64|amd64)   echo "amd64" > /tmp/sbarch ;; \
        aarch64|arm64)  echo "arm64" > /tmp/sbarch ;; \
        *) echo "unsupported arch: $(uname -m)"; exit 1 ;; \
      esac; \
    else \
      echo "$TARGETARCH" > /tmp/sbarch; \
    fi \
    && echo "sing-box arch: $(cat /tmp/sbarch)"

ENV DEBIAN_FRONTEND=noninteractive \
    SINGBOX_BIN=/usr/local/bin/sing-box \
    PYTHONUNBUFFERED=1

# 安装 sing-box 内核（GitHub Release，按架构下载）
RUN SBARCH=$(cat /tmp/sbarch) \
    && apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${SBARCH}.tar.gz" -o /tmp/singbox.tar.gz \
    && tar -xzf /tmp/singbox.tar.gz -C /tmp \
    && cp /tmp/sing-box-${SINGBOX_VERSION}-linux-${SBARCH}/sing-box /usr/local/bin/ \
    && chmod +x /usr/local/bin/sing-box \
    && rm -rf /tmp/singbox.tar.gz /tmp/sing-box-* \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* \
    && sing-box version

WORKDIR /app

# 后端源码
COPY backend/ /app/backend/
# 前端（编辑源在仓库根，同步副本进 static 供后端托管）
COPY index.html subs.js /app/backend/static/
COPY backend/requirements.txt /app/backend/requirements.txt

WORKDIR /app/backend

# 依赖 + 数据目录
RUN pip install --no-cache-dir -r requirements.txt \
    && mkdir -p data static

# 数据卷（节点库 / 生成配置 / 运行日志）
VOLUME ["/app/backend/data"]

EXPOSE 19001

# sing-box 管理 API（clash_api，默认 9090）仅在宿主机内部使用，无需对外暴露
# start.sh 自动读取 data/panel.conf 的面板端口启动
CMD ["bash", "start.sh"]
