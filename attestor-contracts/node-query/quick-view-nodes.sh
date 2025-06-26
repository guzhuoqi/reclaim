#!/bin/bash

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}🔍 正在查看 MeChain Governance 合约中的已注册节点...${NC}"
echo ""

# 直接运行查看节点的脚本
node view-registered-nodes.js

echo ""
echo -e "${GREEN}✅ 查询完成！${NC}"
echo ""
echo -e "${YELLOW}💡 提示：${NC}"
echo "   - 如需查看特定节点，请运行: ./view-nodes.sh"
echo "   - 如需使用 Hardhat，请运行: npx hardhat run scripts/get-attestors.ts --network mechain-testnet"
