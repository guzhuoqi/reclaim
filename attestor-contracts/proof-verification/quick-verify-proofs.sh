#!/bin/bash

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}🔐 正在验证Proofs...${NC}"
echo ""

# 直接运行验证proofs的脚本
node verify-proofs.js

echo ""
echo -e "${GREEN}✅ Proof验证完成！${NC}"
echo ""
echo -e "${YELLOW}💡 提示：${NC}"
echo "   - 验证结果已保存到 data/latest-verification.json"
echo "   - 历史记录已保存到 data/verification-results.json"
echo "   - 如需查看详细结果，请运行: ./verification-manager.sh"
echo "   - 如需导出分析数据，请运行: node view-verification-results.js export"
