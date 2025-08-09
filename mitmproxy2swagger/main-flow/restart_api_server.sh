#!/bin/bash

# 重启 independent_api_server.py 脚本
# Restart script for independent_api_server.py

echo "🔄 重启独立API服务器"
echo "===================="

# 获取本机IP地址
get_local_ip() {
    # 方法1: 通过连接外部地址获取本地IP
    LOCAL_IP=$(python3 -c "
import socket
try:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(('8.8.8.8', 80))
        print(s.getsockname()[0])
except:
    print('127.0.0.1')
" 2>/dev/null)

    # 如果方法1失败，尝试方法2
    if [ -z "$LOCAL_IP" ] || [ "$LOCAL_IP" = "127.0.0.1" ]; then
        # 方法2: 通过ifconfig获取
        LOCAL_IP=$(ifconfig | grep -E "inet ([0-9]{1,3}\.){3}[0-9]{1,3}" | grep -v 127.0.0.1 | awk '{print $2}' | head -n1)
    fi

    # 如果方法2也失败，尝试方法3
    if [ -z "$LOCAL_IP" ]; then
        # 方法3: 通过ip命令获取
        LOCAL_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7}' | head -n1)
    fi

    # 如果所有方法都失败，使用localhost
    if [ -z "$LOCAL_IP" ]; then
        LOCAL_IP="127.0.0.1"
    fi

    echo "$LOCAL_IP"
}

# 检测网络配置
check_network_config() {
    echo "🌐 检测网络配置..."

    LOCAL_IP=$(get_local_ip)
    echo "📍 检测到本机IP: $LOCAL_IP"

    # 检查端口是否被占用
    PORT=${API_SERVER_PORT:-8000}
    if lsof -i :$PORT >/dev/null 2>&1; then
        echo "⚠️  端口 $PORT 已被占用"
        OCCUPYING_PID=$(lsof -ti :$PORT)
        echo "📍 占用进程PID: $OCCUPYING_PID"

        # 检查是否是我们的API服务器 (兼容macOS和Linux)
        if ps -p $OCCUPYING_PID -o comm= 2>/dev/null | grep -q "python" && \
           ps -p $OCCUPYING_PID -o args= 2>/dev/null | grep -q "independent_api_server"; then
            echo "🔍 发现是我们的API服务器进程，将在后续步骤中停止"
        else
            echo "⚠️  端口被其他进程占用，请手动处理或更改端口"
        fi
    else
        echo "✅ 端口 $PORT 可用"
    fi

    # 设置全局变量
    export DETECTED_LOCAL_IP="$LOCAL_IP"
    export API_SERVER_PORT="$PORT"
}

# 检查Python版本
check_python() {
    if ! command -v python3 &> /dev/null; then
        echo "❌ 错误: 未找到python3命令"
        exit 1
    fi

    PYTHON_VERSION=$(python3 --version 2>&1 | cut -d ' ' -f 2 | cut -d '.' -f 1,2)
    MIN_VERSION="3.8"

    if [ "$(printf '%s\n' "$MIN_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$MIN_VERSION" ]; then
        echo "❌ 错误: 需要Python 3.8或更高版本，当前版本: $PYTHON_VERSION"
        exit 1
    fi

    echo "✅ Python版本检查通过: $PYTHON_VERSION"
}

# 停止现有进程
stop_existing_server() {
    echo "🛑 停止现有API服务器进程..."

    # 查找并停止 independent_api_server.py 进程
    API_PIDS=$(ps aux | grep -E "independent_api_server\.py" | grep -v grep | awk '{print $2}')

    if [ -n "$API_PIDS" ]; then
        echo "📍 发现运行中的API服务器进程: $API_PIDS"

        # 优雅停止进程
        for pid in $API_PIDS; do
            echo "⏳ 停止进程: $pid"
            kill $pid
        done

        # 等待进程停止
        echo "⏳ 等待进程完全停止..."
        sleep 3

        # 检查是否还有残留进程
        REMAINING_PIDS=$(ps aux | grep -E "independent_api_server\.py" | grep -v grep | awk '{print $2}')
        if [ -n "$REMAINING_PIDS" ]; then
            echo "💀 强制停止残留进程: $REMAINING_PIDS"
            for pid in $REMAINING_PIDS; do
                kill -9 $pid
                echo "🔥 强制终止进程: $pid"
            done
            sleep 1
        fi

        echo "✅ 现有服务器已停止"
    else
        echo "📝 未发现运行中的API服务器进程"
    fi
}

# 检查核心文件
check_required_files() {
    echo "🔍 检查核心文件..."

    REQUIRED_FILES=(
        "independent_api_server.py"
        "integrated_main_pipeline.py"
        "dynamic_config.py"
    )

    for file in "${REQUIRED_FILES[@]}"; do
        if [ ! -f "$file" ]; then
            echo "❌ 缺少核心文件: $file"
            exit 1
        fi
    done

    echo "✅ 核心文件检查通过"
}

# 检查并创建必要目录
setup_directories() {
    echo "📁 检查并创建必要目录..."

    REQUIRED_DIRS=(
        "data"
        "temp"
        "uploads"
        "logs"
    )

    for dir in "${REQUIRED_DIRS[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            echo "📂 创建目录: $dir"
        fi
    done

    echo "✅ 目录检查完成"
}

# 检查依赖包
check_dependencies() {
    echo "📦 检查依赖包..."

    # 检查关键依赖
    REQUIRED_PACKAGES=("fastapi" "uvicorn" "pydantic")

    for package in "${REQUIRED_PACKAGES[@]}"; do
        if ! python3 -c "import $package" 2>/dev/null; then
            echo "⚠️  缺少依赖包: $package"
            if [ -f "requirements.txt" ]; then
                echo "🔧 正在安装依赖包..."
                pip3 install -r requirements.txt
                if [ $? -ne 0 ]; then
                    echo "❌ 依赖包安装失败"
                    exit 1
                fi
                echo "✅ 依赖包安装成功"
                break
            else
                echo "❌ 未找到requirements.txt文件"
                exit 1
            fi
        fi
    done

    echo "✅ 依赖包检查通过"
}

# 启动服务器
start_server() {
    echo "===================="
    echo "🚀 启动API服务器..."
    echo "💡 按 Ctrl+C 停止服务"
    echo "===================="

    # 设置环境变量
    export PYTHONPATH="${PYTHONPATH}:$(pwd)"

    # 设置服务器配置环境变量
    export API_SERVER_HOST="${BIND_HOST:-0.0.0.0}"
    export API_SERVER_PORT="${API_SERVER_PORT:-8000}"
    export API_SERVER_LOCAL_IP="${DETECTED_LOCAL_IP:-127.0.0.1}"

    # 显示服务器配置信息
    echo "📋 服务器配置:"
    echo "   🌐 绑定地址: $API_SERVER_HOST:$API_SERVER_PORT"
    echo "   📍 本机IP: $API_SERVER_LOCAL_IP"
    echo "   🔗 访问地址: http://$API_SERVER_LOCAL_IP:$API_SERVER_PORT"
    echo "   📖 API文档: http://$API_SERVER_LOCAL_IP:$API_SERVER_PORT/docs"
    echo "   🔍 健康检查: http://$API_SERVER_LOCAL_IP:$API_SERVER_PORT/health"
    echo "   📁 工作目录: $(pwd)"
    echo ""

    # 启动服务器
    echo "🎯 启动时间: $(date '+%Y-%m-%d %H:%M:%S')"

    # 检查是否需要自定义启动参数
    if [ -n "$CUSTOM_ARGS" ]; then
        echo "🔧 使用自定义参数: $CUSTOM_ARGS"
        python3 independent_api_server.py $CUSTOM_ARGS
    else
        python3 independent_api_server.py
    fi

    # 如果服务器意外退出，显示退出信息
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        echo ""
        echo "❌ API服务器异常退出 (退出码: $EXIT_CODE)"
        echo "💡 请检查日志文件: logs/api_server_*.log"
        echo "💡 检查端口是否被占用: lsof -i :$API_SERVER_PORT"
        echo "💡 检查防火墙设置是否允许端口 $API_SERVER_PORT"
        exit $EXIT_CODE
    fi
}

# 后台启动API服务器
start_api_server_background() {
    echo "🚀 后台启动API服务器..."

    # 设置环境变量
    export PYTHONPATH="${PYTHONPATH}:$(pwd)"
    export API_SERVER_HOST="${BIND_HOST:-0.0.0.0}"
    export API_SERVER_PORT="${API_SERVER_PORT:-8000}"
    export API_SERVER_LOCAL_IP="${DETECTED_LOCAL_IP:-127.0.0.1}"

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

    if [ -n "$CUSTOM_ARGS" ]; then
        echo "🔧 使用自定义参数: $CUSTOM_ARGS"
        nohup python3 independent_api_server.py $CUSTOM_ARGS > logs/api_server_background.log 2>&1 &
    else
        nohup python3 independent_api_server.py > logs/api_server_background.log 2>&1 &
    fi

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
        if curl -s -f "http://$API_SERVER_LOCAL_IP:$API_SERVER_PORT/health" > /dev/null; then
            echo "✅ API服务器健康检查通过"
        else
            echo "⚠️  API服务器健康检查失败，但进程正在运行"
        fi
    else
        echo "❌ API服务器启动失败"
        echo "💡 请检查日志: logs/api_server_background.log"
        return 1
    fi

    # 设置清理函数
    cleanup_api_server() {
        if [ -f "/tmp/api_server.pid" ]; then
            local pid=$(cat /tmp/api_server.pid)
            if kill -0 $pid 2>/dev/null; then
                echo "🛑 停止后台API服务器 (PID: $pid)..."
                kill $pid 2>/dev/null
                sleep 2
                if kill -0 $pid 2>/dev/null; then
                    kill -9 $pid 2>/dev/null
                fi
            fi
            rm -f /tmp/api_server.pid
        fi
    }

    # 注册清理函数
    trap cleanup_api_server EXIT INT TERM
}

# 显示使用帮助
show_help() {
    echo "使用方法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help              显示此帮助信息"
    echo "  -p, --port PORT         指定端口号 (默认: 8000)"
    echo "  -b, --bind HOST         指定绑定地址 (默认: 0.0.0.0)"
    echo "  --host-only             仅绑定到本机IP，不监听所有接口"
    echo "  --localhost-only        仅绑定到localhost (127.0.0.1)"
    echo "  --background            后台运行API服务器"
    echo "  --check-only            仅检查配置，不启动服务器"
    echo "  --args ARGS             传递自定义参数给API服务器"
    echo ""
    echo "环境变量:"
    echo "  API_SERVER_PORT         服务器端口"
    echo "  BIND_HOST               绑定地址"
    echo "  CUSTOM_ARGS             自定义启动参数"
    echo ""
    echo "示例:"
    echo "  $0                      # 前台启动API服务器 (默认端口)"
    echo "  $0 -p 8080              # 指定API服务器端口8080"
    echo "  $0 --host-only          # 仅绑定本机IP"
    echo "  $0 --localhost-only     # 仅绑定localhost"
    echo "  $0 --background         # 后台运行API服务器"
    echo "  $0 --check-only         # 仅检查配置"
}

# 解析命令行参数
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -p|--port)
                API_SERVER_PORT="$2"
                shift 2
                ;;
            -b|--bind)
                BIND_HOST="$2"
                shift 2
                ;;
            --host-only)
                BIND_HOST="$DETECTED_LOCAL_IP"
                shift
                ;;
            --localhost-only)
                BIND_HOST="127.0.0.1"
                shift
                ;;
            --background)
                BACKGROUND_MODE=true
                shift
                ;;
            --check-only)
                CHECK_ONLY=true
                shift
                ;;
            --args)
                CUSTOM_ARGS="$2"
                shift 2
                ;;
            *)
                echo "❌ 未知参数: $1"
                echo "使用 $0 --help 查看帮助信息"
                exit 1
                ;;
        esac
    done
}

# 显示配置摘要
show_config_summary() {
    echo "📋 配置摘要"
    echo "===================="
    if [ "$BACKGROUND_MODE" = true ]; then
        echo "🔧 模式: API服务器 (后台运行)"
    else
        echo "🔧 模式: API服务器 (前台运行)"
    fi
    echo "🌐 绑定地址: ${BIND_HOST:-0.0.0.0}"
    echo "🔌 端口号: ${API_SERVER_PORT:-8000}"
    echo "📍 本机IP: ${DETECTED_LOCAL_IP:-未检测}"
    echo "🎯 访问地址: http://${DETECTED_LOCAL_IP:-localhost}:${API_SERVER_PORT:-8000}"
    echo "📁 工作目录: $(pwd)"

    if [ -n "$CUSTOM_ARGS" ]; then
        echo "🔧 自定义参数: $CUSTOM_ARGS"
    fi

    echo "===================="
}

# 主函数
main() {
    # 检查是否在正确的目录
    if [ ! -f "independent_api_server.py" ]; then
        echo "❌ 错误: 请在包含 independent_api_server.py 的目录中运行此脚本"
        exit 1
    fi

    # 初始化变量
    CHECK_ONLY=false
    BACKGROUND_MODE=false

    # 检测网络配置 (需要在参数解析前进行，以便--host-only使用)
    check_network_config

    # 解析命令行参数
    parse_arguments "$@"

    # 显示配置摘要
    show_config_summary

    # 如果只是检查配置，则退出
    if [ "$CHECK_ONLY" = true ]; then
        echo "✅ 配置检查完成"
        exit 0
    fi

    # 执行基础检查
    check_python
    stop_existing_server
    check_required_files
    setup_directories
    check_dependencies

    # 根据模式启动服务器
    if [ "$BACKGROUND_MODE" = true ]; then
        echo "🚀 启动模式: API服务器 (后台运行)"
        start_api_server_background
        
        echo ""
        echo "✅ API服务器已在后台启动"
        echo "💡 查看日志: tail -f logs/api_server_background.log"
        echo "💡 停止服务器: pkill -f independent_api_server.py"
        echo "💡 检查进程: ps aux | grep independent_api_server"
    else
        echo "🚀 启动模式: API服务器 (前台运行)"
        start_server
    fi
}

# 运行主函数
main "$@"