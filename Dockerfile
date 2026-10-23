# Aura · SingBox 中转节点管理面板（Rust 版）
# 单二进制 + sing-box 内核；构建：docker build -t aura-panel .
# 多架构：docker buildx build --platform linux/amd64,linux/arm64 .
#
# 交叉编译说明：builder 固定跑在构建机平台（BUILDPLATFORM），一次产出
# amd64 与 arm64 两个二进制（非宿主架构用 aarch64-linux-gnu-gcc /
# x86_64-linux-gnu-gcc 交叉链接），runtime 阶段按 TARGETARCH 各取所需。
# 这样 arm64 镜像不再靠 QEMU 模拟 rustc —— 后者编一次全量依赖约 30 分钟。

ARG BUILDPLATFORM=linux/amd64
FROM --platform=$BUILDPLATFORM rust:1-slim-bookworm AS builder

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends pkg-config; \
    if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
      apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu g++-aarch64-linux-gnu; \
      rustup target add aarch64-unknown-linux-gnu; \
    else \
      apt-get install -y --no-install-recommends gcc-x86-64-linux-gnu g++-x86-64-linux-gnu; \
      rustup target add x86_64-unknown-linux-gnu; \
    fi; \
    rm -rf /var/lib/apt/lists/*

ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar \
    CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
    CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc \
    AR_x86_64_unknown_linux_gnu=x86_64-linux-gnu-ar \
    CXX_x86_64_unknown_linux_gnu=x86_64-linux-gnu-g++

WORKDIR /src
COPY aura-rs/Cargo.toml aura-rs/Cargo.lock* ./
COPY aura-rs/src ./src

# 两个架构各编一次，产物落在固定文件名上，供 runtime 按 TARGETARCH 取用。
RUN set -eux; \
    if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
      HOST_ARCH=amd64; HOST_TRIPLE=x86_64-unknown-linux-gnu; \
      CROSS_ARCH=arm64; CROSS_TRIPLE=aarch64-unknown-linux-gnu; \
    else \
      HOST_ARCH=arm64; HOST_TRIPLE=aarch64-unknown-linux-gnu; \
      CROSS_ARCH=amd64; CROSS_TRIPLE=x86_64-unknown-linux-gnu; \
    fi; \
    build() { \
      triple="$1"; \
      cargo build --release --locked --target "$triple" 2>/dev/null \
        || cargo build --release --target "$triple"; \
    }; \
    build "$HOST_TRIPLE"; cp "target/$HOST_TRIPLE/release/aura" "/src/aura-$HOST_ARCH"; \
    build "$CROSS_TRIPLE"; cp "target/$CROSS_TRIPLE/release/aura" "/src/aura-$CROSS_ARCH"; \
    ls -l /src/aura-*

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

# 服务端单二进制：按目标平台取对应交叉编译产物
COPY --from=builder /src/aura-${TARGETARCH:-amd64} /app/backend/aura
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
