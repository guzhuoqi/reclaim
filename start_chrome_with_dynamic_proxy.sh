#!/bin/zsh

# Chrome浏览器动态代理启动脚本
# 自动获取本机IP并通过代理服务器启动Chrome

echo "🚀 Chrome浏览器动态代理启动脚本"
echo "================================="

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

# 自动检测代理端口
detect_proxy_port() {
    echo "🔍 自动检测代理端口..." >&2

    # 常用的代理端口列表
    local common_ports=(9999 8080 8081 8888 3128 8000 9000)

    # 首先检查是否有mitmproxy相关进程
    local mitm_ports=$(ps aux | grep -E "(mitmproxy|mitmweb|mitmdump)" | grep -v grep | grep -oE "listen-port [0-9]+" | awk '{print $2}' | head -1)
    if [ ! -z "$mitm_ports" ]; then
        echo "📡 发现mitmproxy进程使用端口: $mitm_ports" >&2
        common_ports=($mitm_ports "${common_ports[@]}")
    fi

    # 检查netstat输出中的监听端口
    local listening_ports=$(netstat -an | grep LISTEN | grep -E ":(8080|8081|8888|9999|3128|8000|9000)" | awk -F: '{print $NF}' | awk '{print $1}' | sort -u)
    if [ ! -z "$listening_ports" ]; then
        echo "📡 发现监听的代理端口: $listening_ports" >&2
        for port in $listening_ports; do
            common_ports=($port "${common_ports[@]}")
        done
    fi

    # 逐个测试端口
    for port in "${common_ports[@]}"; do
        echo "   测试端口 $port..." >&2
        if nc -z $LOCAL_IP $port 2>/dev/null; then
            echo "✅ 找到可用的代理端口: $port" >&2
            echo "$port"
            return
        fi
    done

    # 如果都没找到，返回默认端口
    echo "⚠️  未找到可用的代理端口，使用默认端口 9999" >&2
    echo "9999"
}

# 检测代理端口
PROXY_PORT=$(detect_proxy_port)
PROXY_URL="http://${LOCAL_IP}:${PROXY_PORT}"

echo "🔗 代理服务器地址: $PROXY_URL"

# 最终验证代理服务器是否可用
echo "🔍 验证代理服务器连接..."
if nc -z $LOCAL_IP $PROXY_PORT 2>/dev/null; then
    echo "✅ 代理服务器 $LOCAL_IP:$PROXY_PORT 可访问"
else
    echo "⚠️  警告: 代理服务器 $LOCAL_IP:$PROXY_PORT 可能未启动"
    echo "请先启动mitmproxy: ./start_mitmweb_with_legacy_ssl.sh"
    echo ""
    echo "继续启动Chrome..."
fi

# 检查Chrome路径
CHROME_PATH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
if [ ! -f "$CHROME_PATH" ]; then
    echo "❌ 未找到Chrome浏览器: $CHROME_PATH"
    echo "请检查Chrome是否已安装"
    exit 1
fi

echo "✅ 找到Chrome浏览器: $CHROME_PATH"

# 清理旧的Chrome会话
CHROME_DATA_DIR="/tmp/chrome_dev_session"
if [ -d "$CHROME_DATA_DIR" ]; then
    echo "🧹 清理旧的Chrome会话数据..."
    rm -rf "$CHROME_DATA_DIR"
fi

echo ""
echo "🚀 启动Chrome浏览器..."
echo "================================="
echo "代理服务器: $PROXY_URL"
echo "用户数据目录: $CHROME_DATA_DIR"
echo "================================="

# 启动Chrome
"$CHROME_PATH" \
    --proxy-server="$PROXY_URL" \
    --host-resolver-rules="MAP bind.reclaim.local 127.0.0.1,MAP *.reclaim.local 127.0.0.1" \
    --ignore-certificate-errors \
    --ignore-certificate-errors-spki-list \
    --ignore-ssl-errors \
    --disable-quic \
    --disable-web-security \
    --allow-running-insecure-content \
    --disable-features=VizDisplayCompositor \
    --user-data-dir="$CHROME_DATA_DIR" &

CHROME_PID=$!

echo "✅ Chrome已在后台启动"
echo "🆔 进程ID: $CHROME_PID"
echo ""
echo "🌐 推荐测试网站:"
echo "   工商银行: https://mybank.icbc.com.cn/"
echo "   中国银行: https://ebsnew.boc.cn/"
echo "   mitmproxy证书: http://mitm.it"
echo ""
echo "💡 提示:"
echo "   - 如果遇到证书错误，点击 '高级' → '继续前往'"
echo "   - 访问 http://mitm.it 可安装mitmproxy证书"
echo "   - 使用 Ctrl+C 可停止代理服务器"
echo ""
echo "🔧 代理配置信息:"
echo "   HTTP代理: $LOCAL_IP:$PROXY_PORT"
echo "   HTTPS代理: $LOCAL_IP:$PROXY_PORT"