## 远端测试环境手工部署指南（mitmproxy + attestor addon 与 main-flow）

本指南面向测试环境部署，刻意不涉及生产合规配置（如密钥管理、访问控制、审计等）。目标是在一台远端服务器上同时运行：
- attestor-core WebSocket 服务（供 addon/客户端通过 ws/wss 连接）
- mitm 代理 + `attestor_forwarding_addon.py`（可调用本地 `attestor-core` 或远端地址）
- `main-flow` 独立 API 服务（FastAPI），用于触发与管理主流程

### 环境与前置条件
- Linux 服务器（或等价环境），Python 3.10+，Node.js 18.x
- 放行端口（或限内网）：8080（代理），8082（mitmweb 管理/API），8000（main-flow API）
- 客户端（浏览器/设备）可安装并信任 mitmproxy 根证书（测试环境也需要）

### 目录结构（建议）
建议将两个项目置于同级目录，便于 addon 通过相对路径定位 `attestor-core`：
```
/opt/reclaim/
├─ attestor-core/
└─ mitmproxy2swagger/
   ├─ mitmproxy_addons/
   └─ main-flow/
```

### 端口与配置（测试环境的简单约定）
- mitm 代理监听端口：`8080`（浏览器/设备代理使用）
- mitmweb 管理/API 端口：`8082`（main-flow 通过此端口读取流量）
- main-flow API 端口：`8000`

main-flow 显式通过环境变量覆盖自动发现（更稳定）：
- `MITM_HOST=内网ip`（与 mitm 部署在同机时）
- `MITM_PORT=8082`（注意：这里必须是 mitmweb 的 web_port，而非 8080 代理端口）
- `API_SERVER_HOST=内网ip`，`API_SERVER_PORT=8000`

后端部署后，前端也可以一起部署，内网ip、端口，前端可以访问即可。



如需临时改端口：
- mitm：启动命令里调整 `--listen-port` 与 `--set web_port=...`
- main-flow：改 `MITM_HOST/MITM_PORT` 与 `API_SERVER_HOST/API_SERVER_PORT`



### 注意事项

其中，上文的：mitm 代理监听端口：`8080`（浏览器/设备代理使用）

这里需要提供一个公网访问的ip、端口（考虑到开端口的安全性，可以配置开了公司的VPN才能访问），给用户打开浏览器的时候做绑定，这样浏览器访问的流量才能打到代理。



---

## 部署步骤

### 1. 准备并启动 attestor-core（WebSocket 服务）
```bash
cd /opt/reclaim/attestor-core
npm ci
npm run build
# 可选：npm run download:zk-files

# 验证关键脚本已生成
test -f lib/scripts/generate-receipt-for-python.js && echo OK || echo MISSING

# 启动 attestor-core WebSocket 服务（后台）
export ATTESTOR_PORT=${ATTESTOR_PORT:-8001}
# 测试环境：关闭 BGP 检查，使用测试私钥（勿用于生产）
export DISABLE_BGP_CHECKS=${DISABLE_BGP_CHECKS:-1}
export PRIVATE_KEY=${PRIVATE_KEY:-0x0123788edad59d7c013cdc85e4372f350f828e2cec62d9a2de4560e69aec7f89}
nohup npm run start > /opt/reclaim/logs/attestor_core_background.log 2>&1 &
echo $! > /tmp/attestor_core.pid

# 健康检查（等待最多 10 秒）
for i in $(seq 1 20); do
  curl -sf "http://127.0.0.1:${ATTESTOR_PORT}/browser-rpc/" >/dev/null && echo "attestor-core ready" && break
  sleep 0.5
done
```
说明：本步骤会启动本地 attestor-core WS 服务，默认地址：
- WS: `ws://<server-ip>:8001/ws`
- Browser RPC: `http://<server-ip>:8001/browser-rpc/`
测试环境下使用仓库内置测试私钥；生产前需改为环境变量/安全配置。

### 2. 启动 mitm 代理 + attestor addon（固定端口）
```bash
cd /opt/reclaim/mitmproxy2swagger/mitmproxy_addons
pip3 install --upgrade mitmproxy
mkdir -p logs

# 代理监听 8080，管理/API 8082；不自动开浏览器
mitmweb \
  -s attestor_forwarding_addon.py \
  --listen-host 0.0.0.0 \
  --listen-port 8080 \
  --set web_host=0.0.0.0 \
  --set web_port=8082 \
  --set web_open_browser=false \
  | tee -a logs/mitmweb.log
```
校验：
- 管理页 `http://<server-ip>:8082/` 可访问
- 客户端代理应指向 `<server-ip>:8080`

证书（客户端侧）：
- 首次运行后，服务器上生成 `~/.mitmproxy/mitmproxy-ca-cert.pem`
- 将证书导入需要走代理的客户端（或访问 `http://mitm.it` 下载）

### 3. 启动 main-flow 独立 API 服务（FastAPI）
```bash
cd /opt/reclaim/mitmproxy2swagger/main-flow
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 显式覆盖自动发现，绑定端口
export MITM_HOST=127.0.0.1
export MITM_PORT=8082
export API_SERVER_HOST=0.0.0.0
export API_SERVER_PORT=8000

python3 independent_api_server.py
# 访问：
# - 健康检查: http://<server-ip>:8000/health
# - API 文档:  http://<server-ip>:8000/docs
```

### 使用 Docker 一键本地启动（测试环境）

如需本地快速体验，也可使用 docker-compose（基于本仓库新增的 `docker-compose.test-env.yml`）。该编排会：
- 构建并启动 `attestor-core`（容器内 8001）
- 启动 mitmweb + `attestor_forwarding_addon.py`（容器内 8080/8082）
- 启动 `main-flow` 独立 API 服务（容器内 8000）

其中 addon 采用“本地 Node.js 脚本”模式，直接调用容器内的 `attestor-core/lib/scripts/generate-receipt-for-python.js`，不走远端 WSS。

```bash
# 在仓库根目录执行
docker compose -f docker-compose.test-env.yml build
docker compose -f docker-compose.test-env.yml up -d

# 访问：
# - mitmweb:   http://127.0.0.1:8082/
# - 代理设置:  <本机IP>:8080
# - main-flow: http://127.0.0.1:8000/health  http://127.0.0.1:8000/docs
```

容器之间网络：
- addon 通过挂载的仓库路径访问 `attestor-core/lib/scripts/generate-receipt-for-python.js`
- `attestor_forwarding_config.json` 中 `use_wss_attestor=false` 且 `attestor_host_port=local`，即强制走本地脚本

停止与清理：
```bash
docker compose -f docker-compose.test-env.yml down
```

### 4. 快速验证
```bash
# 在服务器上：
curl -s http://127.0.0.1:8082/ | head -n 1   # 应返回 HTML 片段
curl -s http://127.0.0.1:8000/health          # 应返回 {"status":"healthy", ...}
```
客户端（浏览器/设备）设置系统代理为 `<server-ip>:8080` 并安装 mitm CA 后，访问银行站点。addon 命中规则时会触发 attestor 调用（可直连本地 WS 或远端 WS），输出记录位于：
- `mitmproxy_addons/logs/attestor_forwarding.log`
- `mitmproxy_addons/data/attestor_db/`（请求/响应 JSONL）
- `main-flow/logs/api_server_YYYYMMDD.log`

---

## 简化点（已为测试环境做的取舍）
- 不引入额外的端口配置文件；统一使用固定默认端口 + 环境变量覆盖，降低心智负担
- 禁用一切“自动发现/扫描”作为决定性配置来源：main-flow 强制用 `MITM_HOST/MITM_PORT`
- `attestor-core` 仅执行 `npm ci && npm run build`，无需启动常驻进程；可跳过可选的 zk 文件下载（测试可不必）
- 不涉及守护/系统服务管理，建议在 tmux/nohup/screen 中前台运行，便于调试
- 证书仅做最基本安装指引，不展开企业合规

如需进一步精简：
- 使用单脚本一键部署（测试环境）
  ```bash
  # 赋予执行权限（首次）
  chmod +x /opt/reclaim/deploy_test_env.sh
  
  # 默认按 /opt/reclaim 目录布局部署（后台启动 mitmweb 与 main-flow）
  BASE_DIR=/opt/reclaim /opt/reclaim/deploy_test_env.sh
  
  # 如使用自定义目录：
  BASE_DIR=/your/reclaim /your/reclaim/deploy_test_env.sh
  ```

---

## 常见问题排查（测试环境）
- 端口冲突：`lsof -i :8080` / `:8082` / `:8000` 找到并停止占用进程，或换端口
- main-flow 提示无法发现 mitm：确保 `MITM_HOST/MITM_PORT` 已设置，且 `MITM_PORT` 指向 8082（mitmweb），不是 8080
- addon 找不到 `attestor-core`：确认目录同级，且 `npm run build` 已生成 `lib/scripts/generate-receipt-for-python.js`
- 证书问题：在客户端安装 mitm 根证书；若仍红锁，确认代理设置已生效且访问的确走代理

