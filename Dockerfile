# Aura · SingBox 中转节点管理面板（Rust 版）
# 单二进制 + sing-box 内核；构建：docker build -t aura-panel .
# 多架构：docker buildx build --platform linux/amd64,linux/arm64 .
#
# 交叉编译说明：builder 固定跑在构建机平台（BUILDPLATFORM），arm64 产物用
# aarch64-linux-gnu-gcc 交叉链接，而不是在 QEMU 里模拟 rustc —— 后者编一次
# 全量依赖要 30 分钟，交叉编译把它压到几分钟。

ARG BUILDPLATFORM=linux/amd64
FROM --platform=$BUILDPLATFORM rust:1-slim-bookworm AS builder
ARG TARGETARCH=amd64

ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar \
    CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
    CC_aarch64-linux-gnu=aarch64-linux-gnu-gcc

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      pkg-config gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
 && rm -rf /var/lib/apt/lists/* \
 && if [ "$TARGETARCH" = "arm64" ]; then rustup target add aarch64-unknown-linux-gnu; fi

WORKDIR /src
COPY aura-rs/Cargo.toml aura-rs/Cargo.lock* ./
COPY aura-rs/src ./src
RUN set -eux; \
    if [ "$TARGETARCH" = "arm64" ]; then \
      cargo build --release --locked --target aarch64-unknown-linux-gnu 2>/dev/null \
        || cargo build --release --target aarch64-unknown-linux-gnu; \
      cp target/aarch64-unknown-linux-gnu/release/aura /src/aura-bin; \
    else \
      cargo build --release --locked 2>/dev/null || cargo build --release; \
      cp target/release/aura /src/aura-bin; \
    fi; \
    file /src/aura-bin || true

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

# 服务端单二进制（交叉编译产物统一落在 /src/aura-bin）
COPY --from=builder /src/aura-bin /app/backend/aura
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
