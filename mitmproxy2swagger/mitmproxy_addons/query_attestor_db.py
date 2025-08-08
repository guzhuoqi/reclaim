#!/usr/bin/env python3
"""
Attestor 数据库查询工具
提供命令行接口来查询和管理 attestor 数据
"""

import argparse
import json
import sys
from datetime import datetime, timedelta
from attestor_db import get_attestor_db


def format_timestamp(timestamp):
    """格式化时间戳"""
    if timestamp is None:
        return "N/A"
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def print_record_summary(record):
    """打印记录摘要"""
    print(f"📋 请求ID: {record['request_id']}")
    print(f"📅 日期: {record['date']}")
    print(f"⏰ 请求时间: {format_timestamp(record.get('request_timestamp'))}")
    print(f"⏰ 响应时间: {format_timestamp(record.get('response_timestamp'))}")
    print(f"📊 状态: {record.get('status', 'unknown')}")
    print(f"✅ 成功: {record.get('success', 'N/A')}")
    print("-" * 50)


def cmd_list(args):
    """列出请求"""
    db = get_attestor_db()
    
    if args.date:
        date_str = args.date
    else:
        # 默认使用今天
        date_str = datetime.now().strftime("%Y-%m-%d")
    
    print(f"📋 列出 {date_str} 的请求 (最多 {args.limit} 条):")
    print("=" * 60)
    
    records = db.list_requests_by_date(date_str, args.limit)
    
    if not records:
        print("❌ 没有找到记录")
        return
    
    for record in records:
        print_record_summary(record)
    
    print(f"📊 总计: {len(records)} 条记录")


def cmd_get(args):
    """获取特定请求"""
    db = get_attestor_db()
    
    print(f"🔍 查找请求: {args.request_id}")
    print("=" * 60)
    
    complete_record = db.get_complete_record(args.request_id)
    
    if not complete_record:
        print("❌ 未找到记录")
        return
    
    print(f"📋 请求ID: {complete_record['request_id']}")
    print(f"📥 有响应: {complete_record['has_response']}")
    print(f"✅ 成功: {complete_record['success']}")
    print()
    
    # 显示请求详情
    if complete_record['request']:
        req = complete_record['request']
        print("📤 请求详情:")
        print(f"   时间: {req['datetime']}")
        print(f"   状态: {req['status']}")
        if args.verbose:
            print(f"   数据: {json.dumps(req['data'], indent=2, ensure_ascii=False)}")
        print()
    
    # 显示响应详情
    if complete_record['response']:
        resp = complete_record['response']
        print("📥 响应详情:")
        print(f"   时间: {resp['datetime']}")
        print(f"   执行时间: {resp['execution_time']:.2f}秒")
        print(f"   成功: {resp['success']}")
        
        if args.verbose:
            print(f"   数据: {json.dumps(resp['data'], indent=2, ensure_ascii=False)}")
        elif resp['success'] and 'extractedParameters' in resp['data']:
            print(f"   提取的参数: {resp['data']['extractedParameters']}")


def cmd_stats(args):
    """显示统计信息"""
    db = get_attestor_db()
    
    print("📊 Attestor 数据库统计")
    print("=" * 60)
    
    stats = db.get_statistics(args.date)
    
    print(f"📋 总请求数: {stats['total_requests']}")
    print(f"✅ 已完成: {stats['completed_requests']}")
    print(f"🎉 成功: {stats['successful_requests']}")
    print(f"❌ 失败: {stats['failed_requests']}")
    print(f"⏳ 待处理: {stats['pending_requests']}")
    
    if stats['total_requests'] > 0:
        success_rate = (stats['successful_requests'] / stats['total_requests']) * 100
        print(f"📈 成功率: {success_rate:.1f}%")
    
    print()
    print("📅 可用日期:")
    for date in stats['dates'][:10]:  # 显示最近10天
        print(f"   {date}")
    
    if len(stats['dates']) > 10:
        print(f"   ... 还有 {len(stats['dates']) - 10} 天")


def cmd_cleanup(args):
    """清理旧文件"""
    db = get_attestor_db()
    
    print(f"🗑️  清理 {args.days} 天前的文件...")
    print("=" * 60)
    
    db.cleanup_old_files(args.days)
    print("✅ 清理完成")


def cmd_export(args):
    """导出数据"""
    db = get_attestor_db()
    
    print(f"📤 导出 {args.date} 的数据到 {args.output}")
    print("=" * 60)
    
    records = db.list_requests_by_date(args.date, limit=10000)  # 导出所有记录
    
    export_data = []
    for record in records:
        complete_record = db.get_complete_record(record['request_id'])
        if complete_record:
            export_data.append(complete_record)
    
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)
    
    print(f"✅ 已导出 {len(export_data)} 条记录")


def main():
    parser = argparse.ArgumentParser(description="Attestor 数据库查询工具")
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # list 命令
    list_parser = subparsers.add_parser('list', help='列出请求')
    list_parser.add_argument('--date', help='日期 (YYYY-MM-DD)，默认今天')
    list_parser.add_argument('--limit', type=int, default=20, help='最大显示数量')
    
    # get 命令
    get_parser = subparsers.add_parser('get', help='获取特定请求')
    get_parser.add_argument('request_id', help='请求ID')
    get_parser.add_argument('-v', '--verbose', action='store_true', help='显示详细信息')
    
    # stats 命令
    stats_parser = subparsers.add_parser('stats', help='显示统计信息')
    stats_parser.add_argument('--date', help='特定日期的统计 (YYYY-MM-DD)')
    
    # cleanup 命令
    cleanup_parser = subparsers.add_parser('cleanup', help='清理旧文件')
    cleanup_parser.add_argument('--days', type=int, default=30, help='保留天数')
    
    # export 命令
    export_parser = subparsers.add_parser('export', help='导出数据')
    export_parser.add_argument('date', help='导出日期 (YYYY-MM-DD)')
    export_parser.add_argument('-o', '--output', required=True, help='输出文件')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'list':
            cmd_list(args)
        elif args.command == 'get':
            cmd_get(args)
        elif args.command == 'stats':
            cmd_stats(args)
        elif args.command == 'cleanup':
            cmd_cleanup(args)
        elif args.command == 'export':
            cmd_export(args)
    except KeyboardInterrupt:
        print("\n👋 用户中断")
    except Exception as e:
        print(f"❌ 错误: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
