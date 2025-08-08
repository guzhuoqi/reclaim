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

# 启动 attestor-core 服务
echo ""
echo "🚀 启动 attestor-core 服务..."
cd "$PROJECT_ROOT/attestor-core" && PRIVATE_KEY=0x0123788edad59d7c013cdc85e4372f350f828e2cec62d9a2de4560e69aec7f89 npm run start:tsc &
ATTESTOR_PID=$!

# 等待attestor-core服务启动
echo "⏳ 等待 attestor-core 服务启动..."
sleep 3

# 启动 mitmproxy attestor proxy 
echo "🚀 启动 mitmproxy attestor proxy..."
echo "   代理地址: $LOCAL_IP:8080"
echo "   Web界面: http://$LOCAL_IP:8081"
cd "$SCRIPT_DIR/mitmproxy_addons" && python3 start_attestor_proxy.py --mode web --host "$LOCAL_IP" --web-port 8081 --listen-port 8080 &
PROXY_PID=$!

echo "✅ 所有服务已启动"
echo "================================="
echo "📊 attestor-core PID: $ATTESTOR_PID"
echo "📊 mitmproxy proxy PID: $PROXY_PID"
echo ""
echo "🌐 服务地址:"
echo "   • Attestor Core: http://localhost:3000"
echo "   • Mitmproxy Web: http://$LOCAL_IP:8081"
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