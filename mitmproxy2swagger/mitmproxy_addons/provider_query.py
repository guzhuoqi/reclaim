#!/usr/bin/env python3
"""
Provider查询模块
用于从reclaim_providers文件中检索provider配置信息
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime


class ProviderQuery:
    """Provider查询器"""

    def __init__(self, data_dir: str = None):
        """
        初始化Provider查询器

        Args:
            data_dir: 数据目录路径，如果为None则自动检测
        """
        if data_dir is None:
            data_dir = self._detect_data_dir()
        self.data_dir = Path(data_dir)
        self._provider_cache = {}
        self._cache_timestamp = {}

    def _detect_data_dir(self) -> str:
        """
        自动检测数据目录路径
        
        Returns:
            数据目录路径
        """
        # 优先使用环境变量
        env_data_dir = os.getenv('MAIN_FLOW_DATA_DIR')
        if env_data_dir and os.path.exists(env_data_dir):
            return env_data_dir
        
        # Docker 容器内的绝对路径
        container_data_dir = "/app/main-flow/data"
        if os.path.exists(container_data_dir):
            return container_data_dir
            
        # 相对路径（本地开发环境）
        relative_data_dir = "../main-flow/data"
        relative_path = Path(relative_data_dir)
        if relative_path.exists():
            return relative_data_dir
            
        # 当前目录下的 data 目录
        current_data_dir = "data"
        if os.path.exists(current_data_dir):
            return current_data_dir
            
        # 默认返回相对路径
        print(f"⚠️  未找到有效的数据目录，使用默认路径: {relative_data_dir}")
        return relative_data_dir

    def _get_provider_files(self) -> List[Path]:
        """获取所有provider文件"""
        if not self.data_dir.exists():
            return []

        provider_files = []
        for file_path in self.data_dir.glob("reclaim_providers_*.json"):
            provider_files.append(file_path)

        # 按文件名排序，最新的在前
        return sorted(provider_files, reverse=True)

    def _load_provider_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """
        加载provider文件

        Args:
            file_path: 文件路径

        Returns:
            provider数据或None
        """
        try:
            # 检查缓存
            file_key = str(file_path)
            file_mtime = file_path.stat().st_mtime

            if (file_key in self._provider_cache and
                file_key in self._cache_timestamp and
                self._cache_timestamp[file_key] >= file_mtime):
                return self._provider_cache[file_key]

            # 加载文件
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # 更新缓存
            self._provider_cache[file_key] = data
            self._cache_timestamp[file_key] = file_mtime

            return data
        except Exception as e:
            print(f"❌ 加载provider文件失败 {file_path}: {e}")
            return None

    def get_provider_by_id(self, provider_id: str) -> Optional[Dict[str, Any]]:
        """
        根据provider ID获取provider配置

        Args:
            provider_id: Provider ID

        Returns:
            provider配置或None
        """
        provider_files = self._get_provider_files()

        for file_path in provider_files:
            data = self._load_provider_file(file_path)
            if not data:
                continue

            providers = data.get('providers', {})

            # 支持新的索引格式（providers是对象）
            if isinstance(providers, dict):
                if provider_id in providers:
                    return providers[provider_id]
            # 支持旧的数组格式
            elif isinstance(providers, list):
                for provider in providers:
                    if (provider.get('providerConfig', {}).get('providerId') == provider_id or
                        provider.get('providerId') == provider_id):
                        return provider

        return None

    def get_provider_urls(self, provider_id: str) -> List[str]:
        """
        获取provider中的所有URL

        Args:
            provider_id: Provider ID

        Returns:
            URL列表
        """
        provider = self.get_provider_by_id(provider_id)
        if not provider:
            return []

        urls = []

        # 从providerConfig中提取URL（支持嵌套结构）
        # 注意：只提取requestData中的URL，loginUrl不参与匹配
        provider_config = provider.get('providerConfig', {})
        if isinstance(provider_config, dict):
            # 检查是否有嵌套的providerConfig
            inner_config = provider_config.get('providerConfig', provider_config)

            # 只检查requestData中的URL（loginUrl不参与匹配）
            request_data = inner_config.get('requestData', [])
            if isinstance(request_data, list):
                for request in request_data:
                    if isinstance(request, dict):
                        url = request.get('url')
                        if url:
                            urls.append(url)

        return urls

    def find_providers_by_url_pattern(self, target_url: str,
                                     similarity_threshold: float = 0.8) -> List[Dict[str, Any]]:
        """
        根据URL模式查找匹配的providers

        Args:
            target_url: 目标URL
            similarity_threshold: 相似度阈值

        Returns:
            匹配的provider列表，包含相似度信息
        """
        from url_matcher import URLMatcher

        matcher = URLMatcher()
        matcher.set_similarity_threshold(similarity_threshold)

        matching_providers = []
        provider_files = self._get_provider_files()

        for file_path in provider_files:
            data = self._load_provider_file(file_path)
            if not data:
                continue

            providers = data.get('providers', {})

            # 处理新的索引格式
            if isinstance(providers, dict):
                provider_items = providers.items()
            # 处理旧的数组格式
            elif isinstance(providers, list):
                provider_items = [(p.get('providerConfig', {}).get('providerId', f'unknown_{i}'), p)
                                for i, p in enumerate(providers)]
            else:
                continue

            for provider_id, provider in provider_items:
                # 获取provider的所有URL
                provider_urls = self.get_provider_urls(provider_id)

                # 检查每个URL的匹配度
                for provider_url in provider_urls:
                    similarity_result = matcher.calculate_url_similarity(target_url, provider_url)

                    if similarity_result['is_match']:
                        matching_providers.append({
                            'provider_id': provider_id,
                            'provider': provider,
                            'matched_url': provider_url,
                            'similarity_result': similarity_result,
                            'source_file': str(file_path)
                        })

        # 按相似度排序
        matching_providers.sort(key=lambda x: x['similarity_result']['composite_score'], reverse=True)

        return matching_providers

    def get_all_providers(self) -> Dict[str, Dict[str, Any]]:
        """
        获取所有providers

        Returns:
            所有providers的字典，key为provider_id
        """
        all_providers = {}
        provider_files = self._get_provider_files()

        for file_path in provider_files:
            data = self._load_provider_file(file_path)
            if not data:
                continue

            providers = data.get('providers', {})

            # 处理新的索引格式
            if isinstance(providers, dict):
                all_providers.update(providers)
            # 处理旧的数组格式
            elif isinstance(providers, list):
                for provider in providers:
                    provider_id = (provider.get('providerConfig', {}).get('providerId') or
                                 provider.get('providerId'))
                    if provider_id:
                        all_providers[provider_id] = provider

        return all_providers

    def get_provider_statistics(self) -> Dict[str, Any]:
        """
        获取provider统计信息

        Returns:
            统计信息字典
        """
        provider_files = self._get_provider_files()
        total_providers = 0
        files_info = []

        for file_path in provider_files:
            data = self._load_provider_file(file_path)
            if not data:
                continue

            providers = data.get('providers', {})
            provider_count = len(providers) if isinstance(providers, (dict, list)) else 0
            total_providers += provider_count

            files_info.append({
                'file': file_path.name,
                'provider_count': provider_count,
                'metadata': data.get('metadata', {})
            })

        return {
            'total_files': len(provider_files),
            'total_providers': total_providers,
            'files_info': files_info
        }

    def clear_cache(self):
        """清除缓存"""
        self._provider_cache.clear()
        self._cache_timestamp.clear()


# 全局实例
_provider_query = None


def get_provider_query() -> ProviderQuery:
    """获取全局ProviderQuery实例"""
    global _provider_query
    if _provider_query is None:
        _provider_query = ProviderQuery()
    return _provider_query


if __name__ == "__main__":
    # 测试代码
    query = get_provider_query()

    print("🔍 Provider查询测试")
    print("=" * 50)

    # 获取统计信息
    stats = query.get_provider_statistics()
    print(f"总文件数: {stats['total_files']}")
    print(f"总Provider数: {stats['total_providers']}")
    print()

    # 测试URL匹配
    test_url = "https://www.cmbwinglungbank.com/ibanking/McpCSReqServlet?test=123"
    matches = query.find_providers_by_url_pattern(test_url, similarity_threshold=0.7)

    print(f"URL匹配测试: {test_url}")
    print(f"找到 {len(matches)} 个匹配的providers:")

    for i, match in enumerate(matches[:3]):  # 只显示前3个
        print(f"  {i+1}. Provider ID: {match['provider_id']}")
        print(f"     匹配URL: {match['matched_url']}")
        print(f"     相似度: {match['similarity_result']['composite_score']:.3f}")
        print(f"     基础URL匹配: {match['similarity_result']['base_exact_match']}")
        print()
