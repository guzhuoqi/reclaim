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
echo -e "${CYAN}        MeChain ReclaimTask 任务管理工具${NC}"
echo -e "${CYAN}================================================${NC}"
echo ""

# 检查是否在正确的目录
if [ ! -f "../package.json" ]; then
    echo -e "${RED}❌ 错误: 请在 task-management 目录下运行此脚本${NC}"
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
    cd .. && npm install && cd task-management
fi

# 显示菜单
echo -e "${BLUE}请选择要执行的操作:${NC}"
echo ""
echo -e "${GREEN}📋 任务创建${NC}"
echo -e "${GREEN}1.${NC} 创建新任务 (自动生成参数)"
echo -e "${GREEN}2.${NC} 创建新任务 (自定义参数)"
echo ""
echo -e "${GREEN}📊 任务查看${NC}"
echo -e "${GREEN}3.${NC} 查看当前任务"
echo -e "${GREEN}4.${NC} 查看指定任务"
echo -e "${GREEN}5.${NC} 查看本地保存的Attestors"
echo -e "${GREEN}6.${NC} 查看任务历史记录"
echo ""
echo -e "${GREEN}🔧 其他操作${NC}"
echo -e "${GREEN}7.${NC} 使用 Hardhat 创建任务"
echo -e "${GREEN}8.${NC} 退出"
echo ""

read -p "请输入选项 (1-8): " choice

case $choice in
    1)
        echo -e "${YELLOW}🚀 正在创建新任务 (自动生成参数)...${NC}"
        echo ""
        node create-task.js
        ;;
    2)
        echo -e "${YELLOW}🎲 请输入自定义参数:${NC}"
        echo ""
        
        read -p "请输入自定义种子 (留空使用随机生成): " custom_seed
        read -p "请输入时间戳 (留空使用当前时间): " custom_timestamp
        
        if [ -z "$custom_seed" ] && [ -z "$custom_timestamp" ]; then
            echo -e "${YELLOW}🚀 使用默认参数创建任务...${NC}"
            node create-task.js
        else
            echo -e "${YELLOW}🚀 使用自定义参数创建任务...${NC}"
            # 创建临时脚本处理自定义参数
            cat > temp_create_custom_task.js << EOF
const { createNewTask, generateRandomSeed, getCurrentTimestamp } = require('./create-task.js');

async function main() {
  const seed = '$custom_seed' || generateRandomSeed();
  const timestamp = '$custom_timestamp' ? parseInt('$custom_timestamp') : getCurrentTimestamp();
  
  console.log('使用参数:');
  console.log('Seed:', seed);
  console.log('Timestamp:', timestamp);
  console.log('');
  
  await createNewTask(seed, timestamp);
}

main().catch(console.error);
EOF
            node temp_create_custom_task.js
            rm temp_create_custom_task.js
        fi
        ;;
    3)
        echo -e "${YELLOW}📊 正在查看当前任务...${NC}"
        echo ""
        node view-tasks.js
        ;;
    4)
        read -p "请输入任务ID: " task_id
        if [ -z "$task_id" ]; then
            echo -e "${RED}❌ 错误: 任务ID不能为空${NC}"
            exit 1
        fi
        echo -e "${YELLOW}📊 正在查看任务 $task_id...${NC}"
        echo ""
        node view-tasks.js task "$task_id"
        ;;
    5)
        echo -e "${YELLOW}💾 正在查看本地保存的Attestors...${NC}"
        echo ""
        node view-tasks.js local
        ;;
    6)
        echo -e "${YELLOW}📚 正在查看任务历史记录...${NC}"
        echo ""
        node view-tasks.js history
        ;;
    7)
        echo -e "${YELLOW}🔧 使用 Hardhat 创建任务...${NC}"
        echo ""
        cd .. && npx hardhat create-task-request --network mechain-testnet
        ;;
    8)
        echo -e "${GREEN}👋 再见!${NC}"
        exit 0
        ;;
    *)
        echo -e "${RED}❌ 无效选项，请选择 1-8${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}✅ 操作完成${NC}"
echo ""
echo -e "${YELLOW}💡 提示：${NC}"
echo "   - 创建的任务信息已保存到 data/ 目录"
echo "   - 最新的Attestors信息保存在 data/latest-attestors.json"
echo "   - 任务历史记录保存在 data/tasks-history.json"
echo "   - 可以使用这些文件进行下一步的Attestors调用"
