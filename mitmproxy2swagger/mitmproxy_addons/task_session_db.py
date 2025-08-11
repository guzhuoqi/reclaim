#!/usr/bin/env python3
"""
Task Session 数据库模块
用于维护task session记录，支持按日期分割和ID索引
"""

import json
import os
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import threading
import time
from enum import Enum


class SessionStatus(Enum):
    """Session状态枚举"""
    PENDING = "Pending"
    VERIFYING = "Verifying"
    FINISHED = "Finished"
    FAILED = "Failed"


class TaskSessionDB:
    """Task Session数据库，用于存储session记录"""

    def __init__(self, base_dir: str = "data/task_sessions"):
        """
        初始化数据库

        Args:
            base_dir: 数据库根目录
        """
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

        # 线程锁，确保并发安全
        self._lock = threading.Lock()

        # 内存索引缓存
        self._index_cache = {}
        self._cache_last_update = 0
        self._cache_ttl = 300  # 5分钟缓存

    def _get_date_str(self, timestamp: Optional[float] = None) -> str:
        """获取日期字符串，用于文件分割"""
        if timestamp is None:
            timestamp = time.time()
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d")

    def _get_session_file_path(self, date_str: str) -> Path:
        """获取指定日期的session文件路径"""
        return self.base_dir / f"sessions_{date_str}.json"

    def _load_sessions_for_date(self, date_str: str) -> Dict[str, Any]:
        """加载指定日期的session数据"""
        file_path = self._get_session_file_path(date_str)

        if not file_path.exists():
            return {
                "metadata": {
                    "date": date_str,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "total_sessions": 0
                },
                "sessions": {}
            }

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"❌ 加载session文件失败 {file_path}: {e}")
            return {
                "metadata": {
                    "date": date_str,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "total_sessions": 0,
                    "error": str(e)
                },
                "sessions": {}
            }

    def _save_sessions_for_date(self, date_str: str, data: Dict[str, Any]) -> bool:
        """保存指定日期的session数据"""
        file_path = self._get_session_file_path(date_str)

        try:
            # 在写入前清理：Pending 状态超过10分钟的记录
            try:
                sessions = data.get("sessions", {}) or {}
                if isinstance(sessions, dict) and sessions:
                    now_utc = datetime.now(timezone.utc)
                    cutoff = now_utc - timedelta(minutes=10)
                    to_delete = []
                    for sid, record in sessions.items():
                        try:
                            if record.get("status") == SessionStatus.PENDING.value:
                                created_at = record.get("created_at")
                                if created_at:
                                    created_dt = datetime.fromisoformat(created_at)
                                    # 若为naive，则视为UTC
                                    if created_dt.tzinfo is None:
                                        created_dt = created_dt.replace(tzinfo=timezone.utc)
                                    if created_dt < cutoff:
                                        to_delete.append(sid)
                        except Exception:
                            # 单条异常不影响整体清理
                            continue
                    if to_delete:
                        for sid in to_delete:
                            sessions.pop(sid, None)
                        print(f"🧹 清理过期Pending sessions: {len(to_delete)} (date={date_str})")
            except Exception as _e:
                # 清理异常不阻断写入
                print(f"⚠️ 清理过期Pending sessions时出现异常（已忽略）: {_e}")

            # 更新元数据
            data["metadata"]["last_updated"] = datetime.now(timezone.utc).isoformat()
            data["metadata"]["total_sessions"] = len(data.get("sessions", {}))

            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"❌ 保存session文件失败 {file_path}: {e}")
            return False

    def create_session(self, task_id: str, provider_id: str,
                      additional_data: Optional[Dict[str, Any]] = None) -> str:
        """
        创建新的session记录

        Args:
            task_id: 任务ID，用于索引到attestor_db
            provider_id: Provider ID
            additional_data: 额外数据

        Returns:
            session_id: 生成的session ID
        """
        session_id = str(uuid.uuid4())
        current_time = time.time()
        date_str = self._get_date_str(current_time)

        session_record = {
            "id": session_id,
            "taskId": task_id,
            "providerId": provider_id,
            "status": SessionStatus.PENDING.value,
            "created_at": datetime.fromtimestamp(current_time, tz=timezone.utc).isoformat(),
            "updated_at": datetime.fromtimestamp(current_time, tz=timezone.utc).isoformat()
        }

        # 添加额外数据
        if additional_data:
            session_record.update(additional_data)

        with self._lock:
            # 加载当天的数据
            data = self._load_sessions_for_date(date_str)

            # 添加新session
            data["sessions"][session_id] = session_record

            # 保存数据
            if self._save_sessions_for_date(date_str, data):
                print(f"✅ 创建session成功: {session_id} (taskId: {task_id}, providerId: {provider_id})")
                return session_id
            else:
                print(f"❌ 创建session失败: {session_id}")
                return None

    def update_session_status(self, session_id: str, status: SessionStatus,
                             additional_data: Optional[Dict[str, Any]] = None) -> bool:
        """
        更新session状态

        Args:
            session_id: Session ID
            status: 新状态
            additional_data: 额外数据

        Returns:
            bool: 是否更新成功
        """
        # 查找session所在的日期文件
        session_record = self.get_session(session_id)
        if not session_record:
            print(f"❌ 未找到session: {session_id}")
            return False

        # 从created_at推断日期
        created_at = session_record.get("created_at")
        if created_at:
            try:
                dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                date_str = dt.strftime("%Y-%m-%d")
            except:
                date_str = self._get_date_str()
        else:
            date_str = self._get_date_str()

        with self._lock:
            # 加载数据
            data = self._load_sessions_for_date(date_str)

            if session_id not in data["sessions"]:
                print(f"❌ Session不存在于日期文件中: {session_id}")
                return False

            # 更新session
            if status is not None:  # 🎯 修复：只有status不为None时才更新状态
                data["sessions"][session_id]["status"] = status.value
            data["sessions"][session_id]["updated_at"] = datetime.now(timezone.utc).isoformat()

            if additional_data:
                data["sessions"][session_id].update(additional_data)

            # 保存数据
            if self._save_sessions_for_date(date_str, data):
                status_msg = status.value if status is not None else "数据更新"
                print(f"✅ 更新session成功: {session_id} -> {status_msg}")
                return True
            else:
                print(f"❌ 更新session失败: {session_id}")
                return False

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        获取session记录

        Args:
            session_id: Session ID

        Returns:
            session记录或None
        """
        # 搜索最近几天的文件
        for days_back in range(7):  # 搜索最近7天
            timestamp = time.time() - (days_back * 24 * 60 * 60)
            date_str = self._get_date_str(timestamp)

            data = self._load_sessions_for_date(date_str)
            if session_id in data.get("sessions", {}):
                return data["sessions"][session_id]

        return None

    def get_pending_sessions(self, max_days_back: int = 3) -> List[Dict[str, Any]]:
        """
        获取所有Pending状态的session

        Args:
            max_days_back: 最多搜索几天前的数据

        Returns:
            Pending状态的session列表
        """
        pending_sessions = []

        for days_back in range(max_days_back + 1):
            timestamp = time.time() - (days_back * 24 * 60 * 60)
            date_str = self._get_date_str(timestamp)

            data = self._load_sessions_for_date(date_str)
            for session_id, session_record in data.get("sessions", {}).items():
                if session_record.get("status") == SessionStatus.PENDING.value:
                    pending_sessions.append(session_record)

        return pending_sessions

    def get_latest_pending_session_by_provider(self, provider_id: str, max_days_back: int = 7) -> Optional[Dict[str, Any]]:
        """获取指定 provider 的最新 Pending session

        Args:
            provider_id: Provider ID
            max_days_back: 向前搜索的天数范围（包含当天）

        Returns:
            最新的 Pending session 记录，若不存在返回 None
        """
        if not provider_id:
            return None

        latest_record: Optional[Dict[str, Any]] = None
        latest_ts: float = float('-inf')

        def _parse_iso_to_ts(dt_val: Any) -> float:
            try:
                if dt_val is None:
                    return float('-inf')
                # 支持数值型时间戳
                if isinstance(dt_val, (int, float)):
                    return float(dt_val)
                dt_str = str(dt_val)
                # 兼容Z结尾
                dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
                if dt.tzinfo is None:
                    # 视为UTC
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.timestamp()
            except Exception:
                return float('-inf')

        # 遍历最近几天的分片文件（与 get_pending_sessions 一致的策略）
        for days_back in range(max_days_back + 1):
            timestamp = time.time() - (days_back * 24 * 60 * 60)
            date_str = self._get_date_str(timestamp)

            data = self._load_sessions_for_date(date_str)
            for _sid, session_record in (data.get("sessions", {}) or {}).items():
                try:
                    if session_record.get("status") != SessionStatus.PENDING.value:
                        continue
                    if str(session_record.get("providerId")) != str(provider_id):
                        continue

                    # 以 created_at 优先，退化到 updated_at
                    ts = _parse_iso_to_ts(session_record.get("created_at"))
                    if ts == float('-inf'):
                        ts = _parse_iso_to_ts(session_record.get("updated_at"))

                    if ts > latest_ts:
                        latest_ts = ts
                        latest_record = session_record
                except Exception:
                    # 单条异常不影响整体
                    continue

        return latest_record

    def list_sessions_by_date(self, date_str: str) -> List[Dict[str, Any]]:
        """
        列出指定日期的所有session

        Args:
            date_str: 日期字符串 (YYYY-MM-DD)

        Returns:
            session列表
        """
        data = self._load_sessions_for_date(date_str)
        return list(data.get("sessions", {}).values())

    def get_available_dates(self) -> List[str]:
        """获取有数据的日期列表"""
        dates = []
        for file_path in self.base_dir.glob("sessions_*.json"):
            # 从文件名提取日期
            filename = file_path.stem
            if filename.startswith("sessions_"):
                date_part = filename[9:]  # 去掉 "sessions_" 前缀
                dates.append(date_part)

        return sorted(dates, reverse=True)


# 全局实例
_task_session_db = None


def get_task_session_db() -> TaskSessionDB:
    """获取全局TaskSessionDB实例"""
    global _task_session_db
    if _task_session_db is None:
        _task_session_db = TaskSessionDB()
    return _task_session_db


if __name__ == "__main__":
    # 测试代码
    db = get_task_session_db()

    # 创建测试session
    session_id = db.create_session("test_task_123", "test_provider_456", {
        "url": "https://example.com/api/test",
        "method": "GET"
    })

    print(f"创建的session ID: {session_id}")

    # 获取pending sessions
    pending = db.get_pending_sessions()
    print(f"Pending sessions: {len(pending)}")

    # 更新状态
    if session_id:
        db.update_session_status(session_id, SessionStatus.FINISHED)
