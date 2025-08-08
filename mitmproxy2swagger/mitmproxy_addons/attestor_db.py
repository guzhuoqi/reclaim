#!/usr/bin/env python3
"""
Attestor 数据库模块
提供简单的文件数据库功能，用于存储 attestor 请求和响应数据
支持按天分割文件，异步索引查询
"""

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
import threading
import time


class AttestorDB:
    """简单的文件数据库，用于存储 attestor 数据"""

    def __init__(self, base_dir: str = "data/attestor_db"):
        """
        初始化数据库

        Args:
            base_dir: 数据库根目录
        """
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

        # 创建子目录
        self.requests_dir = self.base_dir / "requests"
        self.responses_dir = self.base_dir / "responses"
        self.index_dir = self.base_dir / "index"

        for dir_path in [self.requests_dir, self.responses_dir, self.index_dir]:
            dir_path.mkdir(exist_ok=True)

        # 线程锁，确保并发安全
        self._lock = threading.Lock()

        # 内存索引缓存（可选优化）
        self._index_cache = {}
        self._cache_last_update = 0
        self._cache_ttl = 300  # 5分钟缓存

    def _get_date_str(self, timestamp: Optional[float] = None) -> str:
        """获取日期字符串，用于文件分割"""
        if timestamp is None:
            timestamp = time.time()
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d")

    def _get_datetime_str(self, timestamp: Optional[float] = None) -> str:
        """获取完整的日期时间字符串"""
        if timestamp is None:
            timestamp = time.time()
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def generate_request_id(self) -> str:
        """生成唯一的请求ID"""
        return str(uuid.uuid4())

    def save_request(self, request_id: str, request_data: Dict[str, Any]) -> bool:
        """
        保存请求数据

        Args:
            request_id: 唯一请求ID
            request_data: 请求数据

        Returns:
            bool: 保存是否成功
        """
        try:
            with self._lock:
                timestamp = time.time()
                date_str = self._get_date_str(timestamp)

                # 构建请求记录
                request_record = {
                    "request_id": request_id,
                    "timestamp": timestamp,
                    "datetime": self._get_datetime_str(timestamp),
                    "date": date_str,
                    "data": request_data,
                    "status": "pending"
                }

                # 保存到按日期分割的文件
                request_file = self.requests_dir / f"requests_{date_str}.jsonl"
                with open(request_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(request_record, ensure_ascii=False) + "\n")

                # 更新索引
                self._update_index(request_id, "request", date_str, timestamp)

                return True

        except Exception as e:
            print(f"❌ 保存请求失败: {e}")
            return False

    def save_response(self, request_id: str, response_data: Dict[str, Any],
                     execution_time: float = 0) -> bool:
        """
        保存响应数据

        Args:
            request_id: 对应的请求ID
            response_data: 响应数据
            execution_time: 执行时间（秒）

        Returns:
            bool: 保存是否成功
        """
        try:
            with self._lock:
                timestamp = time.time()
                date_str = self._get_date_str(timestamp)

                # 构建响应记录
                response_record = {
                    "request_id": request_id,
                    "timestamp": timestamp,
                    "datetime": self._get_datetime_str(timestamp),
                    "date": date_str,
                    "execution_time": execution_time,
                    "success": response_data.get("success", False),
                    "data": response_data
                }

                # 保存到按日期分割的文件
                response_file = self.responses_dir / f"responses_{date_str}.jsonl"
                with open(response_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(response_record, ensure_ascii=False) + "\n")

                # 更新索引
                self._update_index(request_id, "response", date_str, timestamp,
                                 response_data.get("success", False))

                return True

        except Exception as e:
            print(f"❌ 保存响应失败: {e}")
            return False

    def _update_index(self, request_id: str, record_type: str, date_str: str,
                     timestamp: float, success: Optional[bool] = None):
        """更新索引文件"""
        try:
            index_file = self.index_dir / f"index_{date_str}.jsonl"

            # 读取现有索引
            index_data = {}
            if index_file.exists():
                with open(index_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            record = json.loads(line)
                            index_data[record["request_id"]] = record

            # 更新或创建索引记录
            if request_id not in index_data:
                index_data[request_id] = {
                    "request_id": request_id,
                    "date": date_str,
                    "request_timestamp": None,
                    "response_timestamp": None,
                    "success": None,
                    "status": "pending"
                }

            # 更新相应字段
            if record_type == "request":
                index_data[request_id]["request_timestamp"] = timestamp
            elif record_type == "response":
                index_data[request_id]["response_timestamp"] = timestamp
                index_data[request_id]["success"] = success
                index_data[request_id]["status"] = "completed" if success else "failed"

            # 重写索引文件
            with open(index_file, "w", encoding="utf-8") as f:
                for record in index_data.values():
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")

        except Exception as e:
            print(f"❌ 更新索引失败: {e}")

    def get_request(self, request_id: str, date_str: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        根据请求ID获取请求数据

        Args:
            request_id: 请求ID
            date_str: 可选的日期字符串，用于优化查找

        Returns:
            Dict: 请求数据，如果未找到返回 None
        """
        try:
            # 如果没有指定日期，从索引中查找
            if date_str is None:
                date_str = self._find_date_by_request_id(request_id)
                if date_str is None:
                    return None

            request_file = self.requests_dir / f"requests_{date_str}.jsonl"
            if not request_file.exists():
                return None

            with open(request_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        record = json.loads(line)
                        if record["request_id"] == request_id:
                            return record

            return None

        except Exception as e:
            print(f"❌ 获取请求失败: {e}")
            return None

    def get_response(self, request_id: str, date_str: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        根据请求ID获取响应数据

        Args:
            request_id: 请求ID
            date_str: 可选的日期字符串，用于优化查找

        Returns:
            Dict: 响应数据，如果未找到返回 None
        """
        try:
            # 如果没有指定日期，从索引中查找
            if date_str is None:
                date_str = self._find_date_by_request_id(request_id)
                if date_str is None:
                    return None

            response_file = self.responses_dir / f"responses_{date_str}.jsonl"
            if not response_file.exists():
                return None

            with open(response_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        record = json.loads(line)
                        if record["request_id"] == request_id:
                            return record

            return None

        except Exception as e:
            print(f"❌ 获取响应失败: {e}")
            return None

    def _find_date_by_request_id(self, request_id: str) -> Optional[str]:
        """从索引中查找请求ID对应的日期"""
        try:
            # 遍历索引文件（从最新的开始）
            index_files = sorted(self.index_dir.glob("index_*.jsonl"), reverse=True)

            for index_file in index_files:
                with open(index_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            record = json.loads(line)
                            if record["request_id"] == request_id:
                                return record["date"]

            return None

        except Exception as e:
            print(f"❌ 查找日期失败: {e}")
            return None

    def get_complete_record(self, request_id: str) -> Optional[Dict[str, Any]]:
        """
        获取完整的请求-响应记录

        Args:
            request_id: 请求ID

        Returns:
            Dict: 包含请求和响应的完整记录
        """
        try:
            date_str = self._find_date_by_request_id(request_id)
            if date_str is None:
                return None

            request_data = self.get_request(request_id, date_str)
            response_data = self.get_response(request_id, date_str)

            if request_data is None:
                return None

            return {
                "request_id": request_id,
                "request": request_data,
                "response": response_data,
                "has_response": response_data is not None,
                "success": response_data.get("success") if response_data else None
            }

        except Exception as e:
            print(f"❌ 获取完整记录失败: {e}")
            return None

    def list_requests_by_date(self, date_str: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        按日期列出请求

        Args:
            date_str: 日期字符串 (YYYY-MM-DD)
            limit: 最大返回数量

        Returns:
            List: 请求列表
        """
        try:
            index_file = self.index_dir / f"index_{date_str}.jsonl"
            if not index_file.exists():
                return []

            records = []
            with open(index_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        record = json.loads(line)
                        records.append(record)
                        if len(records) >= limit:
                            break

            # 按时间戳排序（最新的在前）
            records.sort(key=lambda x: x.get("request_timestamp", 0), reverse=True)
            return records

        except Exception as e:
            print(f"❌ 列出请求失败: {e}")
            return []

    def get_statistics(self, date_str: Optional[str] = None) -> Dict[str, Any]:
        """
        获取统计信息

        Args:
            date_str: 可选的日期字符串，如果为 None 则统计所有数据

        Returns:
            Dict: 统计信息
        """
        try:
            stats = {
                "total_requests": 0,
                "completed_requests": 0,
                "successful_requests": 0,
                "failed_requests": 0,
                "pending_requests": 0,
                "dates": []
            }

            if date_str:
                # 统计指定日期
                index_files = [self.index_dir / f"index_{date_str}.jsonl"]
            else:
                # 统计所有日期
                index_files = list(self.index_dir.glob("index_*.jsonl"))

            for index_file in index_files:
                if not index_file.exists():
                    continue

                date = index_file.stem.replace("index_", "")
                stats["dates"].append(date)

                with open(index_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            record = json.loads(line)
                            stats["total_requests"] += 1

                            status = record.get("status", "pending")
                            if status == "completed":
                                stats["completed_requests"] += 1
                                if record.get("success"):
                                    stats["successful_requests"] += 1
                                else:
                                    stats["failed_requests"] += 1
                            else:
                                stats["pending_requests"] += 1

            stats["dates"] = sorted(set(stats["dates"]), reverse=True)
            return stats

        except Exception as e:
            print(f"❌ 获取统计信息失败: {e}")
            return {}

    def cleanup_old_files(self, days_to_keep: int = 30):
        """
        清理旧文件

        Args:
            days_to_keep: 保留的天数
        """
        try:
            cutoff_timestamp = time.time() - (days_to_keep * 24 * 60 * 60)
            cutoff_date = self._get_date_str(cutoff_timestamp)

            # 清理请求文件
            for file_path in self.requests_dir.glob("requests_*.jsonl"):
                date_part = file_path.stem.replace("requests_", "")
                if date_part < cutoff_date:
                    file_path.unlink()
                    print(f"🗑️  删除旧请求文件: {file_path.name}")

            # 清理响应文件
            for file_path in self.responses_dir.glob("responses_*.jsonl"):
                date_part = file_path.stem.replace("responses_", "")
                if date_part < cutoff_date:
                    file_path.unlink()
                    print(f"🗑️  删除旧响应文件: {file_path.name}")

            # 清理索引文件
            for file_path in self.index_dir.glob("index_*.jsonl"):
                date_part = file_path.stem.replace("index_", "")
                if date_part < cutoff_date:
                    file_path.unlink()
                    print(f"🗑️  删除旧索引文件: {file_path.name}")

        except Exception as e:
            print(f"❌ 清理文件失败: {e}")


# 全局数据库实例
_db_instance = None

def get_attestor_db() -> AttestorDB:
    """获取全局数据库实例"""
    global _db_instance
    if _db_instance is None:
        _db_instance = AttestorDB()
    return _db_instance
