#!/bin/bash

# 动态获取本机IP的mitmweb启动脚本

echo "🚀 启动mitmweb代理服务器"
echo "=========================="

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

# 设置端口
WEB_PORT=8082
LISTEN_PORT=9999

echo "🌐 Web界面端口: $WEB_PORT"
echo "🔗 代理监听端口: $LISTEN_PORT" 
echo "=========================="

# 检查mitmweb是否可用
MITMWEB_PATH=""
if command -v mitmweb &> /dev/null; then
    MITMWEB_PATH="mitmweb"
elif [ -f "/Users/gu/Library/Python/3.9/bin/mitmweb" ]; then
    MITMWEB_PATH="/Users/gu/Library/Python/3.9/bin/mitmweb"
else
    echo "❌ 未找到mitmweb命令"
    echo "请安装mitmproxy: pip3 install mitmproxy"
    exit 1
fi

echo "✅ 使用mitmweb: $MITMWEB_PATH"
echo ""

# 启动mitmweb
echo "🚀 启动命令:"
echo "$MITMWEB_PATH --set web_port=$WEB_PORT --set listen_port=$LISTEN_PORT --set web_open_browser=false --listen-host $LOCAL_IP --set web_host=$LOCAL_IP"
echo ""
echo "📱 访问地址:"
echo "   🌐 Web界面: http://$LOCAL_IP:$WEB_PORT"
echo "   🔧 代理设置: $LOCAL_IP:$LISTEN_PORT"
echo ""
echo "💡 按 Ctrl+C 停止服务"
echo "=========================="

# 执行启动命令
exec $MITMWEB_PATH \
    --set web_port=$WEB_PORT \
    --set listen_port=$LISTEN_PORT \
    --set web_open_browser=false \
    --listen-host $LOCAL_IP \
    --set web_host=$LOCAL_IP