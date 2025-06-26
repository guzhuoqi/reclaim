#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 显示标题
echo -e "${CYAN}================================================${NC}"
echo -e "${CYAN}        MeChain Attestor 调用管理工具${NC}"
echo -e "${CYAN}================================================${NC}"
echo ""

# 检查是否在正确的目录
if [ ! -f "../package.json" ]; then
    echo -e "${RED}❌ 错误: 请在 attestor-calls 目录下运行此脚本${NC}"
    exit 1
fi

# 检查Node.js是否安装
if ! command -v node &> /dev/null; then
    echo -e "${RED}❌ 错误: 未找到 Node.js，请先安装 Node.js${NC}"
    exit 1
fi

# 检查npm依赖是否安装
if [ ! -d "../node_modules" ]; then
    echo -e "${YELLOW}⚠️  未找到 node_modules，正在安装依赖...${NC}"
    cd .. && npm install && cd attestor-calls
fi

# 检查是否有任务数据
if [ ! -f "../task-management/data/latest-attestors.json" ]; then
    echo -e "${RED}❌ 错误: 未找到任务数据文件${NC}"
    echo -e "${YELLOW}💡 请先在 task-management 目录下创建一个任务${NC}"
    echo ""
    read -p "是否现在创建任务? (y/n): " create_task
    if [ "$create_task" = "y" ] || [ "$create_task" = "Y" ]; then
        echo -e "${YELLOW}🚀 正在创建新任务...${NC}"
        cd ../task-management && ./quick-create-task.sh && cd ../attestor-calls
        echo ""
    else
        exit 1
    fi
fi

# 显示菜单
echo -e "${BLUE}请选择要执行的操作:${NC}"
echo ""
echo -e "${GREEN}🔄 Attestor调用${NC}"
echo -e "${GREEN}1.${NC} 调用所有Attestors (使用最新任务)"
echo -e "${GREEN}2.${NC} 调用所有Attestors (指定任务ID)"
echo -e "${GREEN}3.${NC} 测试Binance API连接"
echo ""
echo -e "${GREEN}📊 结果查看${NC}"
echo -e "${GREEN}4.${NC} 查看最新Proof结果"
echo -e "${GREEN}5.${NC} 查看Proof历史记录"
echo -e "${GREEN}6.${NC} 查看详细Proof信息"
echo -e "${GREEN}7.${NC} 导出Proofs用于验证"
echo ""
echo -e "${GREEN}🔧 其他操作${NC}"
echo -e "${GREEN}8.${NC} 查看任务信息"
echo -e "${GREEN}9.${NC} 退出"
echo ""

read -p "请输入选项 (1-9): " choice

case $choice in
    1)
        echo -e "${YELLOW}🔄 正在调用所有Attestors (使用最新任务)...${NC}"
        echo ""
        node call-attestors.js
        ;;
    2)
        read -p "请输入任务ID: " task_id
        if [ -z "$task_id" ]; then
            echo -e "${RED}❌ 错误: 任务ID不能为空${NC}"
            exit 1
        fi
        echo -e "${YELLOW}🔄 正在调用所有Attestors (任务ID: $task_id)...${NC}"
        echo ""
        node call-attestors.js "$task_id"
        ;;
    3)
        echo -e "${YELLOW}🔍 正在测试Binance API连接...${NC}"
        echo ""
        # 创建临时测试脚本
        cat > temp_test_api.js << EOF
const { testBinanceAPI } = require('./call-attestors.js');

async function main() {
  try {
    await testBinanceAPI();
    console.log('\\n✅ Binance API测试完成!');
  } catch (error) {
    console.error('\\n❌ Binance API测试失败:', error.message);
  }
}

main().catch(console.error);
EOF
        node temp_test_api.js
        rm temp_test_api.js
        ;;
    4)
        echo -e "${YELLOW}📊 正在查看最新Proof结果...${NC}"
        echo ""
        node view-proofs.js
        ;;
    5)
        echo -e "${YELLOW}📚 正在查看Proof历史记录...${NC}"
        echo ""
        node view-proofs.js history
        ;;
    6)
        read -p "请输入要查看的记录编号: " record_num
        if [ -z "$record_num" ]; then
            echo -e "${RED}❌ 错误: 记录编号不能为空${NC}"
            exit 1
        fi
        echo -e "${YELLOW}📋 正在查看记录 $record_num 的详细信息...${NC}"
        echo ""
        node view-proofs.js detail "$record_num"
        ;;
    7)
        echo -e "${YELLOW}📤 正在导出Proofs用于验证...${NC}"
        echo ""
        node view-proofs.js export
        ;;
    8)
        echo -e "${YELLOW}📋 正在查看任务信息...${NC}"
        echo ""
        cd ../task-management && node view-tasks.js local && cd ../attestor-calls
        ;;
    9)
        echo -e "${GREEN}👋 再见!${NC}"
        exit 0
        ;;
    *)
        echo -e "${RED}❌ 无效选项，请选择 1-9${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}✅ 操作完成${NC}"
echo ""
echo -e "${YELLOW}💡 提示：${NC}"
echo "   - Proof结果已保存到 data/ 目录"
echo "   - 最新结果保存在 data/latest-proofs.json"
echo "   - 历史记录保存在 data/attestor-proofs.json"
echo "   - 导出的验证文件保存在 data/proofs-for-verification.json"
echo "   - 可以使用这些文件进行下一步的合约验证"
