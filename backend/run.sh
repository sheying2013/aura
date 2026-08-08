#!/bin/bash
# 兼容入口：委托 start.sh（读取 panel.conf 端口启动）
exec bash "$(dirname "$0")/start.sh" "$@"
