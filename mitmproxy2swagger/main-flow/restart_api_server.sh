#!/bin/bash

# 重启 independent_api_server.py 脚本
# Restart script for independent_api_server.py

echo "🔄 重启独立API服务器"
echo "===================="

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
    echo "🚀 启动新的API服务器..."
    echo "💡 按 Ctrl+C 停止服务"
    echo "===================="
    
    # 设置环境变量
    export PYTHONPATH="${PYTHONPATH}:$(pwd)"
    
    # 启动服务器
    echo "🎯 启动时间: $(date '+%Y-%m-%d %H:%M:%S')"
    python3 independent_api_server.py
    
    # 如果服务器意外退出，显示退出信息
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        echo ""
        echo "❌ API服务器异常退出 (退出码: $EXIT_CODE)"
        echo "💡 请检查日志文件: logs/api_server_*.log"
        exit $EXIT_CODE
    fi
}

# 主函数
main() {
    # 检查是否在正确的目录
    if [ ! -f "independent_api_server.py" ]; then
        echo "❌ 错误: 请在包含 independent_api_server.py 的目录中运行此脚本"
        exit 1
    fi
    
    # 执行各个步骤
    check_python
    stop_existing_server
    check_required_files
    setup_directories
    check_dependencies
    start_server
}

# 运行主函数
main "$@"
