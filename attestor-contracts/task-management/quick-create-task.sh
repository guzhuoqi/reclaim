#!/bin/bash

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}🚀 正在创建新的 ReclaimTask 任务...${NC}"
echo ""

# 直接运行创建任务的脚本
node create-task.js

echo ""
echo -e "${GREEN}✅ 任务创建完成！${NC}"
echo ""
echo -e "${YELLOW}💡 提示：${NC}"
echo "   - Attestors信息已保存到 data/latest-attestors.json"
echo "   - 任务历史记录已保存到 data/tasks-history.json"
echo "   - 如需查看任务详情，请运行: ./task-manager.sh"
echo "   - 如需查看本地保存的数据，请运行: node view-tasks.js local"
