#!/usr/bin/env python3
"""
Provider查询工具
Provider Query Tool

支持通过各种条件查询provider配置
"""

import os
import sys
import json
import argparse
from datetime import datetime
from pathlib import Path

# 添加项目路径
sys.path.append(str(Path(__file__).parent))

from provider_builder import ReclaimProviderBuilder


def list_available_dates(data_dir: str = "data") -> list:
    """列出可用的日期"""
    dates = []
    
    if not os.path.exists(data_dir):
        return dates
        
    for filename in os.listdir(data_dir):
        if filename.startswith("reclaim_providers_") and filename.endswith(".json"):
            # 提取日期部分
            date_part = filename.replace("reclaim_providers_", "").replace(".json", "")
            if len(date_part) == 8 and date_part.isdigit():
                dates.append(date_part)
    
    return sorted(dates, reverse=True)  # 最新的在前


def format_provider_summary(provider_id: str, metadata: dict, config: dict = None) -> str:
    """格式化provider摘要信息"""
    institution = metadata.get('institution', 'N/A')
    api_type = metadata.get('api_type', 'N/A')
    confidence = metadata.get('confidence_score', 0)
    priority = metadata.get('priority_level', 'medium')
    
    summary = f"🆔 {provider_id[:12]}...\n"
    summary += f"   🏦 机构: {institution}\n"
    summary += f"   🔧 类型: {api_type}\n"
    summary += f"   ⭐ 置信度: {confidence:.2f}\n"
    summary += f"   📊 优先级: {priority}"
    
    if config:
        provider_config = config.get('providerConfig', {}).get('providerConfig', {})
        request_data = provider_config.get('requestData', [])
        if request_data:
            url = request_data[0].get('url', 'N/A')
            summary += f"\n   🌐 URL: {url[:50]}..."
    
    return summary


def cmd_list_dates(args):
    """列出可用日期"""
    print("📅 可用的provider数据日期:")
    
    dates = list_available_dates(args.data_dir)
    
    if not dates:
        print("❌ 未找到任何provider数据文件")
        return
    
    for i, date in enumerate(dates, 1):
        # 格式化日期显示
        formatted_date = f"{date[:4]}-{date[4:6]}-{date[6:8]}"
        
        # 加载文件获取统计信息
        providers_data = ReclaimProviderBuilder.load_providers_by_date(date, args.data_dir)
        if providers_data:
            total = providers_data['metadata']['total_providers']
            print(f"   {i}. {formatted_date} ({date}) - {total} providers")
        else:
            print(f"   {i}. {formatted_date} ({date}) - 加载失败")


def cmd_list_providers(args):
    """列出providers"""
    print(f"📋 列出 {args.date} 的所有providers:")
    
    providers_data = ReclaimProviderBuilder.load_providers_by_date(args.date, args.data_dir)
    
    if not providers_data:
        print(f"❌ 未找到日期 {args.date} 的provider数据")
        return
    
    provider_index = providers_data.get('provider_index', {})
    providers = providers_data.get('providers', {})
    
    print(f"📊 总计: {len(provider_index)} providers")
    print()
    
    for i, (provider_id, metadata) in enumerate(provider_index.items(), 1):
        config = providers.get(provider_id) if args.verbose else None
        print(f"{i}. {format_provider_summary(provider_id, metadata, config)}")
        print()


def cmd_query_by_id(args):
    """通过ID查询provider"""
    print(f"🔍 查询provider: {args.provider_id}")
    
    provider_config = ReclaimProviderBuilder.query_provider_by_id(args.provider_id, args.date, args.data_dir)
    
    if not provider_config:
        print(f"❌ 未找到provider: {args.provider_id}")
        return
    
    print("✅ 找到provider配置:")
    
    if args.output_file:
        # 保存到文件
        with open(args.output_file, 'w', encoding='utf-8') as f:
            json.dump(provider_config, f, indent=2, ensure_ascii=False)
        print(f"💾 配置已保存到: {args.output_file}")
    else:
        # 显示摘要信息
        provider_config_inner = provider_config.get('providerConfig', {}).get('providerConfig', {})
        metadata = provider_config_inner.get('metadata', {})
        
        print(f"   🏦 机构: {metadata.get('institution', 'N/A')}")
        print(f"   🔧 API类型: {metadata.get('api_type', 'N/A')}")
        print(f"   ⭐ 置信度: {metadata.get('confidence_score', 0):.2f}")
        print(f"   📊 优先级: {metadata.get('priority_level', 'medium')}")
        
        request_data = provider_config_inner.get('requestData', [])
        if request_data:
            print(f"   🌐 URL: {request_data[0].get('url', 'N/A')}")
            print(f"   📝 HTTP方法: {request_data[0].get('method', 'N/A')}")
            
            response_matches = request_data[0].get('responseMatches', [])
            response_redactions = request_data[0].get('responseRedactions', [])
            print(f"   ✅ 响应匹配规则: {len(response_matches)} 条")
            print(f"   🔒 响应提取规则: {len(response_redactions)} 条")


def cmd_query_by_institution(args):
    """通过机构查询providers"""
    print(f"🏦 查询机构: {args.institution}")
    
    matching_providers = ReclaimProviderBuilder.query_providers_by_institution(args.institution, args.date, args.data_dir)
    
    if not matching_providers:
        print(f"❌ 未找到机构 '{args.institution}' 的providers")
        return
    
    print(f"✅ 找到 {len(matching_providers)} 个providers:")
    print()
    
    for i, provider_info in enumerate(matching_providers, 1):
        provider_id = provider_info['provider_id']
        metadata = provider_info['metadata']
        config = provider_info['config'] if args.verbose else None
        
        print(f"{i}. {format_provider_summary(provider_id, metadata, config)}")
        print()


def main():
    """命令行接口"""
    parser = argparse.ArgumentParser(description='Provider查询工具')
    parser.add_argument('--data-dir', '-d', default='data', help='数据目录')
    parser.add_argument('--date', default=datetime.now().strftime("%Y%m%d"), help='日期 (YYYYMMDD)')
    parser.add_argument('--verbose', '-v', action='store_true', help='显示详细信息')
    
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # 列出日期命令
    parser_dates = subparsers.add_parser('dates', help='列出可用日期')
    
    # 列出providers命令
    parser_list = subparsers.add_parser('list', help='列出所有providers')
    
    # 通过ID查询命令
    parser_get = subparsers.add_parser('get', help='通过ID查询provider')
    parser_get.add_argument('provider_id', help='Provider ID')
    parser_get.add_argument('--output', '-o', dest='output_file', help='输出文件路径')
    
    # 通过机构查询命令
    parser_institution = subparsers.add_parser('institution', help='通过机构查询providers')
    parser_institution.add_argument('institution', help='机构名称')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'dates':
            cmd_list_dates(args)
        elif args.command == 'list':
            cmd_list_providers(args)
        elif args.command == 'get':
            cmd_query_by_id(args)
        elif args.command == 'institution':
            cmd_query_by_institution(args)
    except Exception as e:
        print(f"❌ 执行失败: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
