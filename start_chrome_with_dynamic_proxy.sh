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

# 设置代理端口
PROXY_PORT=9999
PROXY_URL="http://${LOCAL_IP}:${PROXY_PORT}"

echo "🔗 代理服务器地址: $PROXY_URL"

# 检查代理服务器是否可用
echo "🔍 检查代理服务器连接..."
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
    --ignore-certificate-errors \
    --ignore-certificate-errors-spki-list \
    --ignore-ssl-errors \
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