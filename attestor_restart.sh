#!/bin/bash

# Attestor 重启脚本
# 从 all-start.sh 中提取的 attestor-core 重启逻辑

# 获取脚本所在目录的绝对路径
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

echo "🔄 Attestor 重启脚本"
echo "================================="
echo "📁 项目根目录: $PROJECT_ROOT"

# 端口占用检查函数（打印详细占用信息与解决建议）
check_port_free() {
    local label="$1"   # 描述，如 "Attestor"
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
        echo "💡 如需改用其他端口，可设置环境变量："
        echo "   示例: ATTESTOR_PORT=8002 bash attestor_restart.sh"
        echo ""
        exit 1
    fi
}

# 停止现有的 attestor 实例
stop_attestor() {
    echo "🛑 停止现有的 attestor-core 实例..."

    # 默认端口
    local ATTESTOR_PORT="${ATTESTOR_PORT:-8001}"

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
        
        # 检查是否还有顽固进程
        for pid in $EXISTING_PIDS; do
            if kill -0 $pid 2>/dev/null; then
                echo "🔨 强制终止进程: $pid"
                kill -9 $pid 2>/dev/null || true
            fi
        done
    fi

    # 清理PID文件
    if [ -f "/tmp/attestor_core.pid" ]; then
        local saved_pid=$(cat /tmp/attestor_core.pid)
        if kill -0 $saved_pid 2>/dev/null; then
            echo "📍 停止保存的进程 PID: $saved_pid"
            kill $saved_pid 2>/dev/null || true
            sleep 2
            if kill -0 $saved_pid 2>/dev/null; then
                kill -9 $saved_pid 2>/dev/null || true
            fi
        fi
        rm -f /tmp/attestor_core.pid
    fi

    echo "✅ 现有 attestor-core 实例已停止"
}

# 启动 attestor-core
start_attestor() {
    echo "🚀 启动 attestor-core（Node 服务）..."

    # 默认端口与可选覆盖
    export ATTESTOR_PORT="${ATTESTOR_PORT:-8001}"
    # 本地默认关闭 BGP 检查以减少资源占用
    export DISABLE_BGP_CHECKS="${DISABLE_BGP_CHECKS:-1}"
    # 本地开发默认私钥（仅本地使用，勿用于生产）
    export PRIVATE_KEY="${PRIVATE_KEY:-0x0123788edad59d7c013cdc85e4372f350f828e2cec62d9a2de4560e69aec7f89}"

    # 创建日志目录
    mkdir -p "$PROJECT_ROOT/logs"

    # 切换到 attestor-core
    cd "$PROJECT_ROOT/attestor-core" || {
        echo "❌ 错误: 未找到 attestor-core 目录"
        exit 1
    }

    # 若端口仍被占用，打印详细信息并退出
    check_port_free "Attestor" "$ATTESTOR_PORT"

    # 检查编译产物
    if [ ! -f "lib/scripts/generate-receipt-for-python.js" ]; then
        echo "📦 未检测到编译产物，开始编译..."
        if command -v nvm >/dev/null 2>&1; then
            # 优先使用 Node 18
            nvm install 18 >/dev/null 2>&1 || true
            nvm use 18 >/dev/null 2>&1 || true
        fi
        npm ci && npm run build || { 
            echo "❌ attestor-core 编译失败"; 
            exit 1; 
        }
    else
        echo "✅ 已检测到编译产物"
    fi

    # 启动
    echo "🎯 启动时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "📦 日志: $PROJECT_ROOT/logs/attestor_core.log"
    
    if command -v nvm >/dev/null 2>&1; then
        nvm use 18 >/dev/null 2>&1 || true
    fi
    
    PORT=$ATTESTOR_PORT nohup npm run start > "$PROJECT_ROOT/logs/attestor_core.log" 2>&1 &
    ATTESTOR_PID=$!
    echo "✅ attestor-core 已启动，PID: $ATTESTOR_PID (PORT=$ATTESTOR_PORT)"

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

    # 最终验证
    if kill -0 $ATTESTOR_PID 2>/dev/null; then
        echo "✅ attestor-core 重启成功"
        echo ""
        echo "🌐 服务地址:"
        echo "   • Attestor WS: ws://127.0.0.1:$ATTESTOR_PORT/ws"
        echo "   • Attestor Browser RPC: http://127.0.0.1:$ATTESTOR_PORT/browser-rpc/"
        echo ""
        echo "📊 实时日志: tail -f $PROJECT_ROOT/logs/attestor_core.log"
    else
        echo "❌ attestor-core 启动失败"
        echo "💡 请检查日志: $PROJECT_ROOT/logs/attestor_core.log"
        exit 1
    fi
}

# 主执行流程
echo "🔄 开始重启 attestor-core..."
stop_attestor
sleep 1
start_attestor

echo "================================="
echo "✅ Attestor 重启完成"
