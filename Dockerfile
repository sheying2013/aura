# Aura · SingBox 中转节点管理面板（Rust 版）
# 单二进制 + sing-box 内核；构建：docker build -t aura-panel .
# 多架构：docker buildx build --platform linux/amd64,linux/arm64 .

FROM rust:1-slim-bookworm AS builder
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY aura-rs/Cargo.toml aura-rs/Cargo.lock* ./
COPY aura-rs/src ./src
RUN cargo build --release --locked 2>/dev/null || cargo build --release

FROM debian:bookworm-slim AS runtime
ARG SINGBOX_VERSION=1.7.7
# sing-box 发布包架构名：amd64 | arm64（Apple Silicon/ARM 服务器自动匹配）
ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && SBARCH="${TARGETARCH:-$(dpkg --print-architecture)}" \
 && curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${SBARCH}.tar.gz" -o /tmp/sb.tgz \
 && tar -xzf /tmp/sb.tgz -C /tmp \
 && install -m 0755 "/tmp/sing-box-${SINGBOX_VERSION}-linux-${SBARCH}/sing-box" /usr/local/bin/sing-box \
 && rm -rf /tmp/sb.tgz "/tmp/sing-box-${SINGBOX_VERSION}-linux-${SBARCH}" \
 && apt-get purge -y curl \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* \
 && sing-box version

# 服务端单二进制
COPY --from=builder /src/target/release/aura /app/backend/aura
# 前端（编辑源在仓库根，副本进 static 供后端托管）
COPY index.html /app/backend/static/
COPY static/js/ /app/backend/static/js/

ENV AURA_DATA_DIR=/app/backend/data \
    AURA_STATIC_DIR=/app/backend/static \
    SINGBOX_BIN=/usr/local/bin/sing-box \
    RUST_LOG=info

VOLUME ["/app/backend/data"]
EXPOSE 19001
WORKDIR /app/backend
CMD ["/app/backend/aura"]
