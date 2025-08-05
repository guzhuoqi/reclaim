#!/bin/bash

# 支持传统SSL重新协商的mitmweb启动脚本
# 解决访问银行网站时的OpenSSL错误："unsafe legacy renegotiation disabled"

echo "🚀 启动支持传统SSL的mitmweb代理服务器"
echo "================================================="

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
    
    # 备用：返回localhost
    echo "127.0.0.1"
}

# 获取本机IP
LOCAL_IP=$(get_local_ip)
echo "📍 检测到本机IP: $LOCAL_IP"

# 设置端口
WEB_PORT=8082
LISTEN_PORT=9999

echo "🌐 Web界面端口: $WEB_PORT"
echo "🔗 代理监听端口: $LISTEN_PORT" 
echo "================================================="

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

# 设置OpenSSL环境变量以支持传统SSL重新协商
echo "🔧 配置OpenSSL支持传统SSL重新协商..."
export OPENSSL_CONF=""
export OPENSSL_ALLOW_UNSAFE_LEGACY_RENEGOTIATION=1

# 创建临时OpenSSL配置文件
TEMP_OPENSSL_CONF="/tmp/openssl_legacy.conf"
cat > "$TEMP_OPENSSL_CONF" << 'EOF'
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
ssl_conf = ssl_sect

[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
Options = UnsafeLegacyRenegotiation
CipherString = DEFAULT@SECLEVEL=1
EOF

export OPENSSL_CONF="$TEMP_OPENSSL_CONF"

echo "✅ OpenSSL配置文件已创建: $TEMP_OPENSSL_CONF"
echo ""

# 启动mitmweb
echo "🚀 启动命令:"
echo "OPENSSL_CONF=$TEMP_OPENSSL_CONF OPENSSL_ALLOW_UNSAFE_LEGACY_RENEGOTIATION=1 \\"
echo "$MITMWEB_PATH --set web_port=$WEB_PORT --set listen_port=$LISTEN_PORT \\"
echo "    --set web_open_browser=false --listen-host $LOCAL_IP --set web_host=$LOCAL_IP \\"
echo "    --set ssl_insecure=true --set tls_version_client_min=TLSV1 \\"
echo "    --set tls_version_server_min=TLSV1"

echo ""
echo "📱 访问地址:"
echo "   🌐 Web界面: http://$LOCAL_IP:$WEB_PORT"
echo "   🔧 代理设置: $LOCAL_IP:$LISTEN_PORT"
echo ""
echo "🏦 银行网站测试:"
echo "   工商银行: https://mybank.icbc.com.cn/"
echo "   中国银行: https://ebsnew.boc.cn/"
echo ""
echo "💡 按 Ctrl+C 停止服务"
echo "🧹 退出时会自动清理临时配置文件"
echo "================================================="

# 清理函数
cleanup() {
    echo ""
    echo "🧹 清理临时文件..."
    [ -f "$TEMP_OPENSSL_CONF" ] && rm -f "$TEMP_OPENSSL_CONF"
    echo "✅ 清理完成"
    exit 0
}

# 设置信号处理
trap cleanup INT TERM

# 执行启动命令
exec $MITMWEB_PATH \
    --set web_port=$WEB_PORT \
    --set listen_port=$LISTEN_PORT \
    --set web_open_browser=false \
    --listen-host $LOCAL_IP \
    --set web_host=$LOCAL_IP \
    --set ssl_insecure=true