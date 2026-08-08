#!/bin/bash
set -e
cd "$(dirname "$0")"
mkdir -p data static
# 同步前端文件（编辑源在项目根，启动时刷新副本）
[ -f ../index.html ] && cp -f ../index.html static/index.html
[ -f ../subs.js ]    && cp -f ../subs.js    static/subs.js
exec uvicorn app:app --host 0.0.0.0 --port 19001
