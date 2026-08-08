# Aura · SingBox 中转节点管理面板
# 基于 Python + sing-box 内核的 socks5/http 出站中转面板
# 构建：docker build -t aura-panel .
FROM python:3.13-slim

ARG SINGBOX_VERSION=1.7.7
ARG SINGBOX_ARCH=amd64

ENV DEBIAN_FRONTEND=noninteractive \
    SINGBOX_BIN=/usr/local/bin/sing-box \
    PYTHONUNBUFFERED=1

# 安装 sing-box 内核（GitHub Release）
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${SINGBOX_ARCH}.tar.gz" -o /tmp/singbox.tar.gz \
    && tar -xzf /tmp/singbox.tar.gz -C /tmp \
    && cp /tmp/sing-box-${SINGBOX_VERSION}-linux-${SINGBOX_ARCH}/sing-box /usr/local/bin/ \
    && chmod +x /usr/local/bin/sing-box \
    && rm -rf /tmp/singbox.tar.gz /tmp/sing-box-* \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

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
