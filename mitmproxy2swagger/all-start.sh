#!/bin/bash

# 一键启动所有服务的脚本

# 获取脚本所在目录的绝对路径
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "🚀 一键启动所有服务脚本"
echo "================================="
echo "📁 项目根目录: $PROJECT_ROOT"
echo "📁 脚本目录: $SCRIPT_DIR"

# 动态获取本机IP地址
get_local_ip() {
    # 方法1: 通过连接外部服务获取本地IP
    local ip=$(python3 -c "
import socket
try:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(('8.8.8.8', 80))
        print(s.getsockname()[0])
except:
    pass
" 2>/dev/null)

    if [ ! -z "$ip" ]; then
        echo "$ip"
        return
    fi

    # 方法2: 通过ifconfig获取活跃网络接口的IP
    ip=$(ifconfig | grep "inet " | grep -v 127.0.0.1 | grep broadcast | head -1 | awk '{print $2}')
    if [ ! -z "$ip" ]; then
        echo "$ip"
        return
    fi

    # 方法3: 获取所有非localhost的IP，优先返回内网IP
    local all_ips=$(ifconfig | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}')
    for ip in $all_ips; do
        if [[ $ip =~ ^192\.168\. ]] || [[ $ip =~ ^10\. ]] || [[ $ip =~ ^172\. ]]; then
            echo "$ip"
            return
        fi
    done

    # 备用：返回第一个非localhost IP
    echo "$all_ips" | head -1
}

# 获取本机IP
LOCAL_IP=$(get_local_ip)

if [ -z "$LOCAL_IP" ]; then
    echo "❌ 无法获取本机IP地址，使用localhost"
    LOCAL_IP="127.0.0.1"
fi

echo "📍 检测到本机IP: $LOCAL_IP"

# 端口占用检查函数（打印详细占用信息与解决建议）
check_port_free() {
    local label="$1"   # 描述，如 "Mitm Web" 或 "代理"
    local port="$2"

    # 只检查监听状态的端口，避免误判客户端连接
    local listening_pids
    listening_pids=$(lsof -nP -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null | sort -u | xargs)
    
    if [ -n "$listening_pids" ]; then
        echo ""
        echo "❌ ${label} 端口被占用: ${port}"
        echo "—— 占用详情 (监听进程) ——"
        lsof -nP -iTCP:"$port" -sTCP:LISTEN || true
        echo "—— 进程详情 (ps) ——"
        ps -p $listening_pids -o pid,ppid,user,etime,stat,command || true
        echo "—— 处理建议 ——"
        for pid in $listening_pids; do
            echo "  • 结束进程: kill $pid    (必要时: kill -9 $pid)"
        done
        echo "💡 如需改用其他端口，可设置环境变量（示例）："
        echo "   ${label} 示例: ${label} 为 'Mitm Web' 则: WEB_PORT=8083 bash all-start.sh"
        echo ""
        exit 1
    fi
}

# 后台启动 attestor-core（Node 服务）函数
start_attestor_core_background() {
    echo "🚀 启动 attestor-core（Node 服务）..."

    # 默认端口与可选覆盖
    export ATTESTOR_PORT="${ATTESTOR_PORT:-8001}"
    # 本地默认关闭 BGP 检查以减少资源占用
    export DISABLE_BGP_CHECKS="${DISABLE_BGP_CHECKS:-1}"
    # 本地开发默认私钥（仅本地使用，勿用于生产）
    export PRIVATE_KEY="${PRIVATE_KEY:-0x0123788edad59d7c013cdc85e4372f350f828e2cec62d9a2de4560e69aec7f89}"

    # 创建日志目录
    mkdir -p "$SCRIPT_DIR/logs"

    # 切换到 attestor-core
    cd "$PROJECT_ROOT/attestor-core" || return 1

    # 停止已占用端口/历史进程
    echo "🛑 清理已存在的 attestor-core 实例..."
    # 通过端口查找监听进程
    EXISTING_PIDS=$(lsof -nP -iTCP:$ATTESTOR_PORT -sTCP:LISTEN -t 2>/dev/null | sort -u | xargs)
    # 通过命令关键词查找
    if [ -z "$EXISTING_PIDS" ]; then
        EXISTING_PIDS=$(ps aux | grep -E "lib/scripts/start-server|node lib/scripts/start-server" | grep -v grep | awk '{print $2}')
    fi
    if [ -n "$EXISTING_PIDS" ]; then
        echo "📍 发现已运行的进程: $EXISTING_PIDS"
        for pid in $EXISTING_PIDS; do
            kill $pid 2>/dev/null || true
        done
        sleep 2
    fi

    # 若端口仍被占用，打印详细信息并退出
    check_port_free "Attestor" "$ATTESTOR_PORT"

    # 启动
    echo "🎯 后台启动时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "📦 日志: $SCRIPT_DIR/logs/attestor_core_background.log"
    if command -v nvm >/dev/null 2>&1; then
        nvm use 18 >/dev/null 2>&1 || true
    fi
    PORT=$ATTESTOR_PORT nohup npm run start > "$SCRIPT_DIR/logs/attestor_core_background.log" 2>&1 &
    ATTESTOR_PID=$!
    echo "✅ attestor-core 已后台启动，PID: $ATTESTOR_PID (PORT=$ATTESTOR_PORT)"

    # 保存 PID
    echo $ATTESTOR_PID > /tmp/attestor_core.pid

    # 等待健康检查
    echo "⏳ 等待 attestor-core 就绪..."
    for i in $(seq 1 20); do
        if curl -s -f "http://127.0.0.1:$ATTESTOR_PORT/browser-rpc/" > /dev/null 2>&1; then
            echo "✅ attestor-core 健康检查通过"
            break
        fi
        sleep 0.5
    done

    # 返回脚本目录
    cd "$SCRIPT_DIR"
}

# 后台启动API服务器函数
start_api_server_background() {
    echo "🚀 后台启动API服务器..."

    # 切换到main-flow目录
    cd "$SCRIPT_DIR/main-flow"

    # 检查核心文件
    if [ ! -f "independent_api_server.py" ]; then
        echo "❌ 错误: 未找到 independent_api_server.py"
        return 1
    fi

    # 停止现有的API服务器进程
    echo "🛑 停止现有API服务器进程..."
    API_PIDS=$(ps aux | grep -E "independent_api_server\.py" | grep -v grep | awk '{print $2}')
    if [ -n "$API_PIDS" ]; then
        echo "📍 发现运行中的API服务器进程: $API_PIDS"
        for pid in $API_PIDS; do
            kill $pid 2>/dev/null
        done
        sleep 2
    fi

    # 设置环境变量（显式覆盖 mitm 自动发现）
    export PYTHONPATH="${PYTHONPATH}:$(pwd)"
    export API_SERVER_HOST="0.0.0.0"
    export API_SERVER_PORT="8000"
    export API_SERVER_LOCAL_IP="$LOCAL_IP"
    export MITM_HOST="127.0.0.1"
    export MITM_PORT="${WEB_PORT:-8082}"

    # 创建必要目录
    mkdir -p data temp uploads logs

    # 显示API服务器配置信息
    echo "📋 API服务器配置:"
    echo "   🌐 绑定地址: $API_SERVER_HOST:$API_SERVER_PORT"
    echo "   📍 本机IP: $API_SERVER_LOCAL_IP"
    echo "   🔗 访问地址: http://$API_SERVER_LOCAL_IP:$API_SERVER_PORT"
    echo "   📖 API文档: http://$API_SERVER_LOCAL_IP:$API_SERVER_PORT/docs"
    echo "   🔍 健康检查: http://$API_SERVER_LOCAL_IP:$API_SERVER_PORT/health"
    echo ""

    # 后台启动API服务器
    echo "🎯 后台启动时间: $(date '+%Y-%m-%d %H:%M:%S')"
    nohup python3 independent_api_server.py > logs/api_server_background.log 2>&1 &
    API_SERVER_PID=$!
    echo "✅ API服务器已后台启动，PID: $API_SERVER_PID"

    # 保存PID到文件
    echo $API_SERVER_PID > /tmp/api_server.pid

    # 等待服务器启动
    echo "⏳ 等待API服务器启动..."
    sleep 5

    # 检查服务器是否正常启动
    if kill -0 $API_SERVER_PID 2>/dev/null; then
        echo "✅ API服务器启动成功"

        # 测试连接
        if curl -s -f "http://$API_SERVER_LOCAL_IP:$API_SERVER_PORT/health" > /dev/null 2>&1; then
            echo "✅ API服务器健康检查通过"
        else
            echo "⚠️  API服务器健康检查失败，但进程正在运行"
        fi
    else
        echo "❌ API服务器启动失败"
        echo "💡 请检查日志: logs/api_server_background.log"
        return 1
    fi

    # 返回到脚本目录
    cd "$SCRIPT_DIR"
}

# 准备并启动 attestor-core
echo ""
echo "🚀 准备 attestor-core（编译并启动服务）..."
cd "$PROJECT_ROOT/attestor-core" || exit 1
if [ ! -f "lib/scripts/generate-receipt-for-python.js" ]; then
    echo "📦 未检测到编译产物，开始编译..."
    if command -v nvm >/dev/null 2>&1; then
        # 优先使用 Node 18
        nvm install 18 >/dev/null 2>&1 || true
        nvm use 18 >/dev/null 2>&1 || true
    fi
    npm ci && npm run build || { echo "❌ attestor-core 编译失败"; exit 1; }
else
    echo "✅ 已检测到编译产物"
fi
cd "$SCRIPT_DIR"

# 启动 attestor-core
start_attestor_core_background

# 启动 API 服务器 (第二个服务)
echo "🚀 启动 API 服务器..."
start_api_server_background

# 启动 mitmproxy attestor proxy (第三个服务)
echo "🚀 启动 mitmproxy attestor proxy..."
# 固定端口：代理 8080，Web 8082（可用环境变量覆盖，但默认不改动）
PROXY_PORT=${PROXY_PORT:-8080}
WEB_PORT=${WEB_PORT:-8082}

# 若被占用则直接报错，打印详细占用信息
check_port_free "代理" "$PROXY_PORT"
check_port_free "Mitm Web" "$WEB_PORT"

echo "   代理地址: $LOCAL_IP:$PROXY_PORT"
echo "   Web界面: http://$LOCAL_IP:$WEB_PORT"
cd "$SCRIPT_DIR/mitmproxy_addons" && \
    python3 start_attestor_proxy.py --mode web --host "$LOCAL_IP" --web-port "$WEB_PORT" --listen-port "$PROXY_PORT" &
PROXY_PID=$!

echo "✅ 所有服务已启动"
echo "================================="
echo "📊 attestor-core PID: ${ATTESTOR_PID:-$(cat /tmp/attestor_core.pid 2>/dev/null || echo '')}"
echo "📊 API服务器 PID: $API_SERVER_PID"
echo "📊 mitmproxy proxy PID: $PROXY_PID"
echo ""
echo "🌐 服务地址:"
echo "   • Attestor WS: ws://$LOCAL_IP:${ATTESTOR_PORT:-8001}/ws"
echo "   • Attestor Browser RPC: http://$LOCAL_IP:${ATTESTOR_PORT:-8001}/browser-rpc/"
echo "   • API服务器: http://$LOCAL_IP:8000"
echo "   • API文档: http://$LOCAL_IP:8000/docs"
echo "   • Mitmproxy Web: http://$LOCAL_IP:8082"
echo "   • 代理服务器: $LOCAL_IP:8080"
echo ""
echo "🔧 浏览器代理配置:"
echo "   • HTTP代理: $LOCAL_IP:8080"
echo "   • HTTPS代理: $LOCAL_IP:8080"
echo ""
echo "💡 使用 Ctrl+C 停止所有服务"
echo "================================="

# 捕获中断信号，优雅关闭服务
cleanup() {
    echo ""
    echo "🛑 正在停止所有服务..."

    # 停止后台进程
    if [ ! -z "$ATTESTOR_PID" ]; then
        echo "   停止 attestor-core (PID: $ATTESTOR_PID)"
        kill $ATTESTOR_PID 2>/dev/null
    fi
    if [ -f "/tmp/attestor_core.pid" ]; then
        pid=$(cat /tmp/attestor_core.pid)
        if kill -0 $pid 2>/dev/null; then
            echo "   停止 attestor-core (PID: $pid)"
            kill $pid 2>/dev/null
            sleep 2
            if kill -0 $pid 2>/dev/null; then
                kill -9 $pid 2>/dev/null
            fi
        fi
        rm -f /tmp/attestor_core.pid
    fi

    # 停止API服务器
    if [ -f "/tmp/api_server.pid" ]; then
        local api_pid=$(cat /tmp/api_server.pid)
        if kill -0 $api_pid 2>/dev/null; then
            echo "   停止 API服务器 (PID: $api_pid)"
            kill $api_pid 2>/dev/null
            sleep 2
            if kill -0 $api_pid 2>/dev/null; then
                kill -9 $api_pid 2>/dev/null
            fi
        fi
        rm -f /tmp/api_server.pid
    fi

    if [ ! -z "$PROXY_PID" ]; then
        echo "   停止 mitmproxy proxy (PID: $PROXY_PID)"
        kill $PROXY_PID 2>/dev/null
    fi

    echo "✅ 所有服务已停止"
    exit 0
}

# 注册信号处理
trap cleanup INT TERM

# 等待用户中断
wait