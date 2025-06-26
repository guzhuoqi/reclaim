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
echo -e "${CYAN}        MeChain Proof 验证管理工具${NC}"
echo -e "${CYAN}================================================${NC}"
echo ""

# 检查是否在正确的目录
if [ ! -f "../package.json" ]; then
    echo -e "${RED}❌ 错误: 请在 proof-verification 目录下运行此脚本${NC}"
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
    cd .. && npm install && cd proof-verification
fi

# 检查是否有attestor proofs数据
if [ ! -f "../attestor-calls/data/proofs-for-verification.json" ]; then
    echo -e "${RED}❌ 错误: 未找到Attestor生成的Proofs文件${NC}"
    echo -e "${YELLOW}💡 请先在 attestor-calls 目录下调用Attestors生成Proofs${NC}"
    echo ""
    read -p "是否现在调用Attestors? (y/n): " call_attestors
    if [ "$call_attestors" = "y" ] || [ "$call_attestors" = "Y" ]; then
        echo -e "${YELLOW}🔄 正在调用Attestors...${NC}"
        cd ../attestor-calls && ./quick-call-attestors.sh && cd ../proof-verification
        echo ""
    else
        exit 1
    fi
fi

# 显示菜单
echo -e "${BLUE}请选择要执行的操作:${NC}"
echo ""
echo -e "${GREEN}🔐 Proof验证${NC}"
echo -e "${GREEN}1.${NC} 验证Proofs (使用最新任务)"
echo -e "${GREEN}2.${NC} 验证Proofs (指定任务ID)"
echo -e "${GREEN}3.${NC} 检查验证费用"
echo ""
echo -e "${GREEN}📊 结果查看${NC}"
echo -e "${GREEN}4.${NC} 查看最新验证结果"
echo -e "${GREEN}5.${NC} 查看验证历史记录"
echo -e "${GREEN}6.${NC} 查看详细验证信息"
echo -e "${GREEN}7.${NC} 导出验证数据"
echo ""
echo -e "${GREEN}🔧 其他操作${NC}"
echo -e "${GREEN}8.${NC} 查看Attestor Proofs"
echo -e "${GREEN}9.${NC} 使用 Hardhat 验证"
echo -e "${GREEN}10.${NC} 退出"
echo ""

read -p "请输入选项 (1-10): " choice

case $choice in
    1)
        echo -e "${YELLOW}🔐 正在验证Proofs (使用最新任务)...${NC}"
        echo ""
        node verify-proofs.js
        ;;
    2)
        read -p "请输入任务ID: " task_id
        if [ -z "$task_id" ]; then
            echo -e "${RED}❌ 错误: 任务ID不能为空${NC}"
            exit 1
        fi
        echo -e "${YELLOW}🔐 正在验证Proofs (任务ID: $task_id)...${NC}"
        echo ""
        node verify-proofs.js "$task_id"
        ;;
    3)
        echo -e "${YELLOW}💰 正在检查验证费用...${NC}"
        echo ""
        # 创建临时脚本检查验证费用
        cat > temp_check_cost.js << EOF
const { getVerificationCost } = require('./verify-proofs.js');
const { ethers } = require('ethers');

async function main() {
  try {
    const provider = new ethers.JsonRpcProvider('https://testnet-rpc.mechain.tech');
    const cost = await getVerificationCost(provider);
    console.log('✅ 验证费用检查完成!');
  } catch (error) {
    console.error('❌ 检查验证费用失败:', error.message);
  }
}

main().catch(console.error);
EOF
        node temp_check_cost.js
        rm temp_check_cost.js
        ;;
    4)
        echo -e "${YELLOW}📊 正在查看最新验证结果...${NC}"
        echo ""
        node view-verification-results.js
        ;;
    5)
        echo -e "${YELLOW}📚 正在查看验证历史记录...${NC}"
        echo ""
        node view-verification-results.js history
        ;;
    6)
        read -p "请输入要查看的记录编号: " record_num
        if [ -z "$record_num" ]; then
            echo -e "${RED}❌ 错误: 记录编号不能为空${NC}"
            exit 1
        fi
        echo -e "${YELLOW}📋 正在查看记录 $record_num 的详细信息...${NC}"
        echo ""
        node view-verification-results.js detail "$record_num"
        ;;
    7)
        echo -e "${YELLOW}📤 正在导出验证数据...${NC}"
        echo ""
        node view-verification-results.js export
        ;;
    8)
        echo -e "${YELLOW}👥 正在查看Attestor Proofs...${NC}"
        echo ""
        cd ../attestor-calls && node view-proofs.js && cd ../proof-verification
        ;;
    9)
        echo -e "${YELLOW}🔧 使用 Hardhat 验证...${NC}"
        echo ""
        echo -e "${YELLOW}💡 注意: 需要先准备好proof数据${NC}"
        cd .. && npx hardhat verify-proofs --network mechain-testnet
        ;;
    10)
        echo -e "${GREEN}👋 再见!${NC}"
        exit 0
        ;;
    *)
        echo -e "${RED}❌ 无效选项，请选择 1-10${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}✅ 操作完成${NC}"
echo ""
echo -e "${YELLOW}💡 提示：${NC}"
echo "   - 验证结果已保存到 data/ 目录"
echo "   - 最新结果保存在 data/latest-verification.json"
echo "   - 历史记录保存在 data/verification-results.json"
echo "   - 分析数据保存在 data/verification-analysis.json"
echo "   - 验证成功后任务状态会更新为已达成共识"
