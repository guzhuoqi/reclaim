#!/bin/bash

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}🔄 正在调用Attestors创建Proofs...${NC}"
echo ""

# 直接运行调用attestors的脚本
node call-attestors.js

echo ""
echo -e "${GREEN}✅ Attestor调用完成！${NC}"
echo ""
echo -e "${YELLOW}💡 提示：${NC}"
echo "   - Proof结果已保存到 data/latest-proofs.json"
echo "   - 历史记录已保存到 data/attestor-proofs.json"
echo "   - 如需查看详细结果，请运行: ./attestor-manager.sh"
echo "   - 如需导出验证文件，请运行: node view-proofs.js export"
