#!/bin/bash

# Attestor代理管理脚本
# Attestor Proxy Management Script

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# 获取脚本目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 显示帮助信息
show_help() {
    echo -e "${CYAN}🚀 Attestor集成代理管理脚本${NC}"
    echo -e "${CYAN}============================${NC}"
    echo ""
    echo "用法: $0 [命令] [选项]"
    echo ""
    echo "命令:"
    echo "  start     启动代理服务"
    echo "  stop      停止代理服务"
    echo "  restart   重启代理服务"
    echo "  status    检查服务状态"
    echo "  install   安装依赖"
    echo "  help      显示此帮助信息"
    echo ""
    echo "选项:"
    echo "  -p, --port PORT     代理端口 (默认: 8080)"
    echo "  -w, --web-port PORT Web界面端口 (默认: 8081)"
    echo "  -d, --debug         启用调试模式"
    echo ""
    echo "示例:"
    echo "  $0 start              # 启动代理"
    echo "  $0 restart            # 重启代理"
    echo "  $0 start -p 8090      # 使用自定义端口启动"
    echo "  $0 status             # 检查状态"
    echo ""
}

# 检查依赖
check_dependencies() {
    local quiet=${1:-false}

    if [[ "$quiet" != "true" ]]; then
        echo -e "${BLUE}🔍 检查环境依赖...${NC}"
    fi

    # 检查Python
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}❌ 错误: 未找到python3${NC}"
        echo "请运行: $0 install"
        return 1
    fi

    # 检查mitmproxy
    if ! python3 -c "import mitmproxy" 2>/dev/null; then
        echo -e "${RED}❌ 错误: 未找到mitmproxy${NC}"
        echo "请运行: $0 install"
        return 1
    fi

    # 检查必要文件
    if [[ ! -f "attestor_forwarding_addon.py" ]]; then
        echo -e "${RED}❌ 错误: 未找到 attestor_forwarding_addon.py${NC}"
        return 1
    fi

    if [[ ! -f "http_to_attestor_converter.py" ]]; then
        echo -e "${RED}❌ 错误: 未找到 http_to_attestor_converter.py${NC}"
        return 1
    fi

    if [[ "$quiet" != "true" ]]; then
        echo -e "${GREEN}✅ 环境检查通过${NC}"
    fi
    return 0
}

# 查找运行中的进程
find_proxy_processes() {
    local pids=""

    # 查找attestor相关的mitmproxy进程
    pids=$(pgrep -f "attestor_forwarding_addon.py" 2>/dev/null || true)

    # 如果没找到，查找所有mitmproxy进程
    if [[ -z "$pids" ]]; then
        pids=$(pgrep -f "mitmweb.*8081" 2>/dev/null || true)
    fi

    echo "$pids"
}

# 停止代理服务
stop_proxy() {
    echo -e "${BLUE}🛑 停止Attestor代理服务...${NC}"

    local pids=$(find_proxy_processes)

    if [[ -z "$pids" ]]; then
        echo -e "${YELLOW}⚠️  没有找到运行中的代理进程${NC}"
        return 0
    fi

    echo -e "${GREEN}📋 找到进程: $pids${NC}"

    # 优雅停止
    for pid in $pids; do
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "   停止进程 ${YELLOW}$pid${NC}..."
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done

    # 等待进程停止
    sleep 2

    # 检查是否还有进程运行
    local remaining_pids=$(find_proxy_processes)
    if [[ -n "$remaining_pids" ]]; then
        echo -e "${YELLOW}⚠️  强制停止剩余进程...${NC}"
        for pid in $remaining_pids; do
            kill -KILL "$pid" 2>/dev/null || true
        done
    fi

    echo -e "${GREEN}✅ 代理服务已停止${NC}"
}

# 检查端口占用
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        return 0  # 端口被占用
    else
        return 1  # 端口空闲
    fi
}

# 启动代理服务
start_proxy() {
    local proxy_port=${1:-8080}
    local web_port=${2:-8081}
    local debug_mode=${3:-false}

    echo -e "${BLUE}🚀 启动Attestor代理服务...${NC}"

    # 检查依赖
    if ! check_dependencies true; then
        return 1
    fi

    # 检查端口占用
    if check_port $proxy_port; then
        echo -e "${YELLOW}⚠️  代理端口 $proxy_port 已被占用${NC}"
        local port_pid=$(lsof -Pi :$proxy_port -sTCP:LISTEN -t)
        echo -e "   占用进程: $port_pid"
        read -p "是否停止占用进程并继续？(y/N): " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            kill -TERM $port_pid 2>/dev/null || kill -KILL $port_pid 2>/dev/null
            sleep 1
        else
            return 1
        fi
    fi

    if check_port $web_port; then
        echo -e "${YELLOW}⚠️  Web端口 $web_port 已被占用${NC}"
        local port_pid=$(lsof -Pi :$web_port -sTCP:LISTEN -t)
        echo -e "   占用进程: $port_pid"
        read -p "是否停止占用进程并继续？(y/N): " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            kill -TERM $port_pid 2>/dev/null || kill -KILL $port_pid 2>/dev/null
            sleep 1
        else
            return 1
        fi
    fi

    # 创建日志目录
    mkdir -p logs

    # 确定启动命令
    local MITMWEB_CMD
    if command -v mitmweb &> /dev/null; then
        MITMWEB_CMD="mitmweb"
    else
        MITMWEB_CMD="python3 -m mitmproxy.tools.web"
    fi

    echo -e "${GREEN}📋 启动配置:${NC}"
    echo -e "   🌐 Web界面: ${BLUE}http://localhost:$web_port${NC}"
    echo -e "   🔗 代理端口: ${BLUE}$proxy_port${NC}"
    echo -e "   📁 日志目录: ${YELLOW}./logs/${NC}"
    echo ""

    echo -e "${GREEN}💡 浏览器代理设置:${NC}"
    echo -e "   HTTP代理: ${BLUE}127.0.0.1:$proxy_port${NC}"
    echo -e "   HTTPS代理: ${BLUE}127.0.0.1:$proxy_port${NC}"
    echo ""

    echo -e "${GREEN}🎯 支持的网站:${NC}"
    echo -e "   • 招商永隆银行: ${BLUE}*.cmbwinglungbank.com${NC}"
    echo ""

    echo -e "${YELLOW}按 Ctrl+C 停止代理${NC}"
    echo -e "${BLUE}🚀 启动命令: $MITMWEB_CMD${NC}"
    echo ""

    # 构建启动参数
    local cmd_args=(
        "-s" "attestor_forwarding_addon.py"
        "--web-port" "$web_port"
        "--listen-port" "$proxy_port"
        "--web-open-browser" "false"
    )

    if [[ "$debug_mode" == "true" ]]; then
        cmd_args+=("--set" "confdir=./logs")
    fi

    # 启动服务
    exec $MITMWEB_CMD "${cmd_args[@]}"
}

# 检查服务状态
check_status() {
    echo -e "${BLUE}📊 Attestor代理服务状态${NC}"
    echo -e "${BLUE}=====================${NC}"

    local pids=$(find_proxy_processes)

    if [[ -n "$pids" ]]; then
        echo -e "${GREEN}✅ 服务运行中${NC}"
        echo -e "   进程ID: ${YELLOW}$pids${NC}"

        for pid in $pids; do
            if kill -0 "$pid" 2>/dev/null; then
                local process_info=$(ps -p "$pid" -o pid,ppid,etime,cmd --no-headers 2>/dev/null || echo "进程信息获取失败")
                echo -e "   $process_info"
            fi
        done

        # 检查端口
        echo ""
        echo -e "${BLUE}🔗 端口状态:${NC}"
        if check_port 8080; then
            echo -e "   ✅ 代理端口 8080 正在使用"
        else
            echo -e "   ❌ 代理端口 8080 未使用"
        fi

        if check_port 8081; then
            echo -e "   ✅ Web端口 8081 正在使用"
            echo -e "   🌐 Web界面: ${BLUE}http://localhost:8081${NC}"
        else
            echo -e "   ❌ Web端口 8081 未使用"
        fi

    else
        echo -e "${RED}❌ 服务未运行${NC}"
        return 1
    fi
}

# 安装依赖
install_dependencies() {
    echo -e "${BLUE}📦 安装Attestor代理依赖${NC}"
    echo -e "${BLUE}=====================${NC}"

    # 检查Python
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}❌ 未找到python3，请先安装Python 3.7+${NC}"
        return 1
    fi

    # 检查pip
    if ! command -v pip3 &> /dev/null; then
        echo -e "${RED}❌ 未找到pip3${NC}"
        return 1
    fi

    # 安装mitmproxy
    echo -e "${BLUE}📥 安装mitmproxy...${NC}"
    if pip3 install mitmproxy; then
        echo -e "${GREEN}✅ mitmproxy安装成功${NC}"
    else
        echo -e "${RED}❌ mitmproxy安装失败${NC}"
        return 1
    fi

    # 验证安装
    if python3 -c "import mitmproxy" 2>/dev/null; then
        echo -e "${GREEN}✅ 依赖安装完成${NC}"
        echo ""
        echo -e "${BLUE}💡 现在可以运行:${NC}"
        echo -e "   $0 start    # 启动服务"
    else
        echo -e "${RED}❌ 安装验证失败${NC}"
        return 1
    fi
}

# 主函数
main() {
    local command=""
    local proxy_port=8080
    local web_port=8081
    local debug_mode=false

    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            start|stop|restart|status|install|help)
                command="$1"
                shift
                ;;
            -p|--port)
                proxy_port="$2"
                shift 2
                ;;
            -w|--web-port)
                web_port="$2"
                shift 2
                ;;
            -d|--debug)
                debug_mode=true
                shift
                ;;
            -h|--help)
                command="help"
                shift
                ;;
            *)
                echo -e "${RED}❌ 未知参数: $1${NC}"
                show_help
                exit 1
                ;;
        esac
    done

    # 如果没有指定命令，默认为start
    if [[ -z "$command" ]]; then
        command="start"
    fi

    # 执行相应命令
    case "$command" in
        "start")
            echo -e "${CYAN}🚀 Attestor集成代理 - 启动服务${NC}"
            echo -e "${CYAN}==============================${NC}"
            echo ""
            start_proxy "$proxy_port" "$web_port" "$debug_mode"
            ;;
        "stop")
            echo -e "${CYAN}🛑 Attestor集成代理 - 停止服务${NC}"
            echo -e "${CYAN}==============================${NC}"
            echo ""
            stop_proxy
            ;;
        "restart")
            echo -e "${CYAN}🔄 Attestor集成代理 - 重启服务${NC}"
            echo -e "${CYAN}==============================${NC}"
            echo ""
            stop_proxy
            sleep 2
            start_proxy "$proxy_port" "$web_port" "$debug_mode"
            ;;
        "status")
            check_status
            ;;
        "install")
            install_dependencies
            ;;
        "help")
            show_help
            ;;
        *)
            echo -e "${RED}❌ 未知命令: $command${NC}"
            show_help
            exit 1
            ;;
    esac
}

# 运行主函数
main "$@"
