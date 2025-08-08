#!/usr/bin/env python3
"""
Session管理命令行工具
用于管理task session记录
"""

import argparse
import json
import sys
from datetime import datetime
from task_session_db import get_task_session_db, SessionStatus
from session_based_matcher import get_session_matcher


def cmd_list_sessions(args):
    """列出sessions"""
    db = get_task_session_db()
    
    if args.date:
        sessions = db.list_sessions_by_date(args.date)
        print(f"📅 {args.date} 的sessions:")
    else:
        sessions = db.get_pending_sessions(max_days_back=args.days)
        print(f"📋 最近{args.days}天的Pending sessions:")
    
    if not sessions:
        print("❌ 没有找到sessions")
        return
    
    print(f"总计: {len(sessions)} 个sessions")
    print("-" * 80)
    
    for i, session in enumerate(sessions, 1):
        status_emoji = {
            "Pending": "⏳",
            "Finished": "✅", 
            "Failed": "❌"
        }.get(session.get('status'), "❓")
        
        print(f"{i:2d}. {status_emoji} {session['id']}")
        print(f"     Task ID: {session.get('taskId', 'N/A')}")
        print(f"     Provider ID: {session.get('providerId', 'N/A')}")
        print(f"     状态: {session.get('status', 'N/A')}")
        print(f"     创建时间: {session.get('created_at', 'N/A')}")
        
        if args.verbose:
            print(f"     更新时间: {session.get('updated_at', 'N/A')}")
            if 'url' in session:
                print(f"     URL: {session['url']}")
            if 'method' in session:
                print(f"     方法: {session['method']}")
        
        print()


def cmd_get_session(args):
    """获取特定session"""
    db = get_task_session_db()
    session = db.get_session(args.session_id)
    
    if not session:
        print(f"❌ 未找到session: {args.session_id}")
        return
    
    print(f"📋 Session详情: {args.session_id}")
    print("-" * 50)
    print(json.dumps(session, indent=2, ensure_ascii=False))


def cmd_create_session(args):
    """创建新session"""
    db = get_task_session_db()
    
    additional_data = {}
    if args.url:
        additional_data['url'] = args.url
    if args.method:
        additional_data['method'] = args.method
    if args.data:
        try:
            additional_data.update(json.loads(args.data))
        except json.JSONDecodeError as e:
            print(f"❌ 无效的JSON数据: {e}")
            return
    
    session_id = db.create_session(
        task_id=args.task_id,
        provider_id=args.provider_id,
        additional_data=additional_data
    )
    
    if session_id:
        print(f"✅ 创建session成功: {session_id}")
    else:
        print(f"❌ 创建session失败")


def cmd_update_session(args):
    """更新session状态"""
    db = get_task_session_db()
    
    try:
        status = SessionStatus(args.status)
    except ValueError:
        print(f"❌ 无效的状态: {args.status}")
        print(f"有效状态: {[s.value for s in SessionStatus]}")
        return
    
    additional_data = {}
    if args.data:
        try:
            additional_data = json.loads(args.data)
        except json.JSONDecodeError as e:
            print(f"❌ 无效的JSON数据: {e}")
            return
    
    success = db.update_session_status(args.session_id, status, additional_data)
    
    if success:
        print(f"✅ 更新session状态成功: {args.session_id} -> {status.value}")
    else:
        print(f"❌ 更新session状态失败")


def cmd_check_matching(args):
    """检查匹配状态"""
    matcher = get_session_matcher()
    
    print("🔍 运行session匹配检查...")
    result = matcher.run_periodic_check()
    
    print(f"✅ 检查完成:")
    print(f"   更新的sessions: {result['updated_sessions']}")
    print(f"   Pending sessions: {result['statistics']['pending_sessions_count']}")
    print(f"   Provider文件数: {result['statistics']['provider_files_count']}")
    print(f"   总Provider数: {result['statistics']['total_providers_count']}")


def cmd_stats(args):
    """显示统计信息"""
    db = get_task_session_db()
    matcher = get_session_matcher()
    
    # Session统计
    dates = db.get_available_dates()
    total_sessions = 0
    status_counts = {"Pending": 0, "Finished": 0, "Failed": 0}
    
    for date in dates:
        sessions = db.list_sessions_by_date(date)
        total_sessions += len(sessions)
        for session in sessions:
            status = session.get('status', 'Unknown')
            if status in status_counts:
                status_counts[status] += 1
    
    # 匹配统计
    match_stats = matcher.get_matching_statistics()
    
    print("📊 Session统计信息")
    print("-" * 50)
    print(f"总Session数: {total_sessions}")
    print(f"  ⏳ Pending: {status_counts['Pending']}")
    print(f"  ✅ Finished: {status_counts['Finished']}")
    print(f"  ❌ Failed: {status_counts['Failed']}")
    print(f"数据文件数: {len(dates)}")
    print(f"可用日期: {', '.join(dates[:5])}{'...' if len(dates) > 5 else ''}")
    
    print("\n📊 Provider统计信息")
    print("-" * 50)
    print(f"Provider文件数: {match_stats['provider_files_count']}")
    print(f"总Provider数: {match_stats['total_providers_count']}")
    print(f"匹配阈值: {match_stats['matcher_threshold']}")


def cmd_cleanup(args):
    """清理过期数据"""
    print("🧹 清理功能暂未实现")
    print("💡 可以手动删除过期的session文件")


def main():
    parser = argparse.ArgumentParser(description="Session管理工具")
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # list命令
    list_parser = subparsers.add_parser('list', help='列出sessions')
    list_parser.add_argument('--date', help='指定日期 (YYYY-MM-DD)')
    list_parser.add_argument('--days', type=int, default=3, help='搜索天数 (默认3天)')
    list_parser.add_argument('--verbose', '-v', action='store_true', help='显示详细信息')
    
    # get命令
    get_parser = subparsers.add_parser('get', help='获取特定session')
    get_parser.add_argument('session_id', help='Session ID')
    
    # create命令
    create_parser = subparsers.add_parser('create', help='创建新session')
    create_parser.add_argument('task_id', help='Task ID')
    create_parser.add_argument('provider_id', help='Provider ID')
    create_parser.add_argument('--url', help='URL')
    create_parser.add_argument('--method', help='HTTP方法')
    create_parser.add_argument('--data', help='额外数据 (JSON格式)')
    
    # update命令
    update_parser = subparsers.add_parser('update', help='更新session状态')
    update_parser.add_argument('session_id', help='Session ID')
    update_parser.add_argument('status', choices=['Pending', 'Finished', 'Failed'], help='新状态')
    update_parser.add_argument('--data', help='额外数据 (JSON格式)')
    
    # check命令
    check_parser = subparsers.add_parser('check', help='检查匹配状态')
    
    # stats命令
    stats_parser = subparsers.add_parser('stats', help='显示统计信息')
    
    # cleanup命令
    cleanup_parser = subparsers.add_parser('cleanup', help='清理过期数据')
    cleanup_parser.add_argument('--days', type=int, default=30, help='保留天数')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # 执行对应命令
    command_map = {
        'list': cmd_list_sessions,
        'get': cmd_get_session,
        'create': cmd_create_session,
        'update': cmd_update_session,
        'check': cmd_check_matching,
        'stats': cmd_stats,
        'cleanup': cmd_cleanup
    }
    
    try:
        command_map[args.command](args)
    except Exception as e:
        print(f"❌ 执行命令失败: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
