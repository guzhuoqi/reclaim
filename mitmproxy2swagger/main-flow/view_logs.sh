#!/bin/bash

# 日志查看和管理脚本

echo "📋 日志管理工具"
echo "===================="

# 检查logs目录
if [ ! -d "logs" ]; then
    echo "❌ logs目录不存在"
    exit 1
fi

# 显示日志文件列表
echo "📁 可用的日志文件:"
echo ""
ls -la logs/*.log 2>/dev/null | awk '{print NR-1 ". " $9 " (" $5 " bytes, " $6 " " $7 " " $8 ")"}'

echo ""
echo "🔧 操作选项:"
echo "1. 查看最新的API服务器日志"
echo "2. 查看最新的主流程日志" 
echo "3. 查看最新的智能提取器日志"
echo "4. 实时跟踪最新日志"
echo "5. 清理旧日志文件 (保留最近5个)"
echo "6. 查看日志目录大小"
echo "0. 退出"

echo ""
read -p "请选择操作 (0-6): " choice

case $choice in
    1)
        latest_api_log=$(ls -t logs/api_server_*.log 2>/dev/null | head -1)
        if [ -n "$latest_api_log" ]; then
            echo "📖 查看最新API服务器日志: $latest_api_log"
            tail -50 "$latest_api_log"
        else
            echo "❌ 未找到API服务器日志文件"
        fi
        ;;
    2)
        latest_pipeline_log=$(ls -t logs/main_pipeline_*.log 2>/dev/null | head -1)
        if [ -n "$latest_pipeline_log" ]; then
            echo "📖 查看最新主流程日志: $latest_pipeline_log"
            tail -50 "$latest_pipeline_log"
        else
            echo "❌ 未找到主流程日志文件"
        fi
        ;;
    3)
        latest_extractor_log=$(ls -t logs/intelligent_extractor_*.log 2>/dev/null | head -1)
        if [ -n "$latest_extractor_log" ]; then
            echo "📖 查看最新智能提取器日志: $latest_extractor_log"
            tail -50 "$latest_extractor_log"
        else
            echo "❌ 未找到智能提取器日志文件"
        fi
        ;;
    4)
        latest_log=$(ls -t logs/*.log 2>/dev/null | head -1)
        if [ -n "$latest_log" ]; then
            echo "🔄 实时跟踪最新日志: $latest_log"
            echo "按 Ctrl+C 退出"
            tail -f "$latest_log"
        else
            echo "❌ 未找到日志文件"
        fi
        ;;
    5)
        echo "🧹 清理旧日志文件 (保留最近5个)..."
        
        # 清理API服务器日志
        api_logs=($(ls -t logs/api_server_*.log 2>/dev/null))
        if [ ${#api_logs[@]} -gt 5 ]; then
            for ((i=5; i<${#api_logs[@]}; i++)); do
                rm "${api_logs[i]}"
                echo "删除: ${api_logs[i]}"
            done
        fi
        
        # 清理主流程日志
        pipeline_logs=($(ls -t logs/main_pipeline_*.log 2>/dev/null))
        if [ ${#pipeline_logs[@]} -gt 5 ]; then
            for ((i=5; i<${#pipeline_logs[@]}; i++)); do
                rm "${pipeline_logs[i]}"
                echo "删除: ${pipeline_logs[i]}"
            done
        fi
        
        # 清理智能提取器日志
        extractor_logs=($(ls -t logs/intelligent_extractor_*.log 2>/dev/null))
        if [ ${#extractor_logs[@]} -gt 5 ]; then
            for ((i=5; i<${#extractor_logs[@]}; i++)); do
                rm "${extractor_logs[i]}"
                echo "删除: ${extractor_logs[i]}"
            done
        fi
        
        echo "✅ 日志清理完成"
        ;;
    6)
        echo "📊 日志目录大小:"
        du -sh logs/
        echo ""
        echo "📈 各类日志文件统计:"
        echo "API服务器日志: $(ls logs/api_server_*.log 2>/dev/null | wc -l) 个文件"
        echo "主流程日志: $(ls logs/main_pipeline_*.log 2>/dev/null | wc -l) 个文件"
        echo "智能提取器日志: $(ls logs/intelligent_extractor_*.log 2>/dev/null | wc -l) 个文件"
        echo "其他日志: $(ls logs/*.log 2>/dev/null | grep -v -E "(api_server_|main_pipeline_|intelligent_extractor_)" | wc -l) 个文件"
        ;;
    0)
        echo "👋 退出日志管理工具"
        exit 0
        ;;
    *)
        echo "❌ 无效选择"
        exit 1
        ;;
esac