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
echo -e "${CYAN}        MeChain Governance 节点查询工具${NC}"
echo -e "${CYAN}================================================${NC}"
echo ""

# 检查是否在正确的目录
if [ ! -f "../package.json" ]; then
    echo -e "${RED}❌ 错误: 请在 node-query 目录下运行此脚本${NC}"
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
    cd .. && npm install && cd node-query
fi

# 显示菜单
echo -e "${BLUE}请选择要执行的操作:${NC}"
echo ""
echo -e "${GREEN}1.${NC} 查看所有已注册节点 (推荐)"
echo -e "${GREEN}2.${NC} 查看特定节点信息"
echo -e "${GREEN}3.${NC} 使用 Hardhat 查看所有节点"
echo -e "${GREEN}4.${NC} 使用 Hardhat 查看特定节点"
echo -e "${GREEN}5.${NC} 退出"
echo ""

read -p "请输入选项 (1-5): " choice

case $choice in
    1)
        echo -e "${YELLOW}🔍 正在查看所有已注册节点...${NC}"
        echo ""
        node view-registered-nodes.js
        ;;
    2)
        read -p "请输入节点的Key: " node_key
        if [ -z "$node_key" ]; then
            echo -e "${RED}❌ 错误: 节点Key不能为空${NC}"
            exit 1
        fi
        echo -e "${YELLOW}🔍 正在查看节点 '$node_key' 的信息...${NC}"
        echo ""
        # 创建临时脚本查看特定节点
        cat > temp_get_single_node.js << EOF
const { ethers } = require('ethers');

const CONFIG = {
  contractAddress: '0x0d113bDe369DC8Df8e24760473bB3C4965a17078',
  networkURL: 'https://testnet-rpc.mechain.tech',
  privateKey: 'd716026fb6fce2b47a911ef44d36d7e07fd6b09037c0b3d7121f20061388cba6'
};

const GOVERNANCE_ABI = [
  "function getAttestor(string memory _key) external view returns (address)",
  "function stakedAmounts(address) external view returns (uint256)",
  "function pendingRewards(address) external view returns (uint256)",
  "function minimumStake() external view returns (uint256)"
];

async function main() {
  try {
    const provider = new ethers.JsonRpcProvider(CONFIG.networkURL);
    const wallet = new ethers.Wallet(CONFIG.privateKey, provider);
    const contract = new ethers.Contract(CONFIG.contractAddress, GOVERNANCE_ABI, wallet);
    
    console.log('='.repeat(50));
    console.log('🔍 节点信息查询');
    console.log('='.repeat(50));
    console.log(\`节点Key: $node_key\`);
    
    const address = await contract.getAttestor('$node_key');
    
    if (address === '0x0000000000000000000000000000000000000000') {
      console.log('❌ 未找到该节点');
    } else {
      console.log(\`节点地址: \${address}\`);
      
      const stakedAmount = await contract.stakedAmounts(address);
      const pendingRewards = await contract.pendingRewards(address);
      const minimumStake = await contract.minimumStake();
      
      console.log(\`质押金额: \${ethers.formatEther(stakedAmount)} ETH\`);
      console.log(\`待领取奖励: \${ethers.formatEther(pendingRewards)} ETH\`);
      console.log(\`状态: \${stakedAmount >= minimumStake ? '✅ 符合要求' : '❌ 质押不足'}\`);
    }
    
    console.log('='.repeat(50));
  } catch (error) {
    console.error('❌ 发生错误:', error.message);
  }
}

main().catch(console.error);
EOF
        node temp_get_single_node.js
        rm temp_get_single_node.js
        ;;
    3)
        echo -e "${YELLOW}🔍 使用 Hardhat 查看所有节点...${NC}"
        echo ""
        cd .. && npx hardhat run scripts/get-attestors.ts --network mechain-testnet
        ;;
    4)
        read -p "请输入节点的Key: " node_key
        if [ -z "$node_key" ]; then
            echo -e "${RED}❌ 错误: 节点Key不能为空${NC}"
            exit 1
        fi
        echo -e "${YELLOW}🔍 使用 Hardhat 查看节点 '$node_key' 的信息...${NC}"
        echo ""
        cd .. && npx hardhat run scripts/get-attestor.ts --network mechain-testnet -- "$node_key"
        ;;
    5)
        echo -e "${GREEN}👋 再见!${NC}"
        exit 0
        ;;
    *)
        echo -e "${RED}❌ 无效选项，请选择 1-5${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}✅ 操作完成${NC}"
