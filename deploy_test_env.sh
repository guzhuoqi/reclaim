#!/usr/bin/env bash
set -euo pipefail

# Minimal deploy script for test env (mitmproxy + attestor addon + main-flow)
# Defaults can be overridden via environment variables before running.

BASE_DIR=${BASE_DIR:-/opt/reclaim}
ATTESTOR_DIR="$BASE_DIR/attestor-core"
ADDONS_DIR="$BASE_DIR/mitmproxy2swagger/mitmproxy_addons"
MAIN_FLOW_DIR="$BASE_DIR/mitmproxy2swagger/main-flow"
LOG_DIR="$BASE_DIR/logs"

# Ports and hosts
MITM_LISTEN_HOST=${MITM_LISTEN_HOST:-0.0.0.0}
MITM_LISTEN_PORT=${MITM_LISTEN_PORT:-8080}
MITM_WEB_HOST=${MITM_WEB_HOST:-0.0.0.0}
MITM_WEB_PORT=${MITM_WEB_PORT:-8082}
API_SERVER_HOST=${API_SERVER_HOST:-0.0.0.0}
API_SERVER_PORT=${API_SERVER_PORT:-8000}

# attestor-core
ATTESTOR_PORT=${ATTESTOR_PORT:-8001}

# main-flow to mitmweb binding
MF_MITM_HOST=${MF_MITM_HOST:-127.0.0.1}
MF_MITM_PORT=${MF_MITM_PORT:-$MITM_WEB_PORT}

mkdir -p "$LOG_DIR"

echo "[1/3] 构建 attestor-core (无需启动常驻进程)"
cd "$ATTESTOR_DIR"
npm ci >> "$LOG_DIR/attestor_build.log" 2>&1
npm run build >> "$LOG_DIR/attestor_build.log" 2>&1
if [ ! -f lib/scripts/generate-receipt-for-python.js ]; then
  echo "缺少关键脚本: lib/scripts/generate-receipt-for-python.js" >&2
  exit 1
fi
echo "attestor-core 构建完成，日志: $LOG_DIR/attestor_build.log"

# 启动 attestor-core WebSocket 服务（后台）
echo "[1b] 启动 attestor-core WebSocket 服务 于 0.0.0.0:${ATTESTOR_PORT}"
export DISABLE_BGP_CHECKS=${DISABLE_BGP_CHECKS:-1}
export PRIVATE_KEY=${PRIVATE_KEY:-0x0123788edad59d7c013cdc85e4372f350f828e2cec62d9a2de4560e69aec7f89}

# 若已有实例，先停止
EXISTING_PIDS=$(lsof -nP -iTCP:${ATTESTOR_PORT} -sTCP:LISTEN -t 2>/dev/null | xargs || true)
if [ -n "${EXISTING_PIDS}" ]; then
  echo "发现已运行的 attestor-core 进程: ${EXISTING_PIDS}，尝试结束"
  kill ${EXISTING_PIDS} 2>/dev/null || true
  sleep 1
fi

nohup npm run start > "$LOG_DIR/attestor_core_background.log" 2>&1 &
ATTESTOR_PID=$!
echo $ATTESTOR_PID > /tmp/attestor_core.pid
echo "attestor-core 已后台运行，PID: ${ATTESTOR_PID}，日志: $LOG_DIR/attestor_core_background.log"

# 健康检查
for i in $(seq 1 20); do
  if curl -sf "http://127.0.0.1:${ATTESTOR_PORT}/browser-rpc/" >/dev/null; then
    echo "attestor-core 健康检查通过"
    break
  fi
  sleep 0.5
done

echo "[2/3] 启动 mitmweb + attestor addon 于 ${MITM_LISTEN_HOST}:${MITM_LISTEN_PORT} (web: ${MITM_WEB_HOST}:${MITM_WEB_PORT})"
cd "$ADDONS_DIR"
mkdir -p logs
pip3 install --upgrade mitmproxy >/dev/null
nohup mitmweb \
  -s attestor_forwarding_addon.py \
  --listen-host "$MITM_LISTEN_HOST" \
  --listen-port "$MITM_LISTEN_PORT" \
  --set web_host="$MITM_WEB_HOST" \
  --set web_port="$MITM_WEB_PORT" \
  --set web_open_browser=false \
  >> logs/mitmweb.log 2>&1 &
echo "mitmweb 已后台运行，日志: $ADDONS_DIR/logs/mitmweb.log"

echo "[3/3] 启动 main-flow API 于 ${API_SERVER_HOST}:${API_SERVER_PORT} (MITM: ${MF_MITM_HOST}:${MF_MITM_PORT})"
cd "$MAIN_FLOW_DIR"
mkdir -p logs
if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
"$MAIN_FLOW_DIR/.venv/bin/pip" install -r requirements.txt >/dev/null
nohup bash -lc "source .venv/bin/activate; \
  MITM_HOST='${MF_MITM_HOST}' MITM_PORT='${MF_MITM_PORT}' \
  API_SERVER_HOST='${API_SERVER_HOST}' API_SERVER_PORT='${API_SERVER_PORT}' \
  python3 independent_api_server.py" \
  >> logs/api_server.log 2>&1 &
echo "main-flow 已后台运行，日志: $MAIN_FLOW_DIR/logs/api_server.log"

echo "完成。"

# 结束提示
echo "\n服务概览:" 
echo "- Attestor WS: ws://$(hostname -I | awk '{print $1}'):${ATTESTOR_PORT}/ws"
echo "- Browser RPC: http://$(hostname -I | awk '{print $1}'):${ATTESTOR_PORT}/browser-rpc/"


