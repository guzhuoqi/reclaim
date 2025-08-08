#!/usr/bin/env python3
"""
基于Session的匹配器
实现第一个功能点：通过task session记录匹配API到attestor
"""

import json
import time
import time
from typing import Dict, List, Optional, Any, Tuple
from mitmproxy import http
from task_session_db import get_task_session_db, SessionStatus
from provider_query import get_provider_query
from url_matcher import URLMatcher
from attestor_db import get_attestor_db


class SessionBasedMatcher:
    """基于Session的API匹配器"""

    def __init__(self):
        self.task_session_db = get_task_session_db()
        self.provider_query = get_provider_query()
        self.url_matcher = URLMatcher()
        self.attestor_db = get_attestor_db()

        # 设置匹配参数
        self.url_matcher.set_similarity_threshold(0.8)  # 80%相似度阈值

        print("✅ SessionBasedMatcher 初始化完成")

    def check_pending_sessions_and_match(self, flow: http.HTTPFlow) -> Optional[Dict[str, Any]]:
        """
        检查pending sessions并尝试匹配当前请求

        Args:
            flow: HTTP请求流

        Returns:
            匹配结果字典，如果匹配成功返回匹配信息，否则返回None
        """
        request_url = flow.request.pretty_url

        # 1. 获取所有pending状态的sessions
        pending_sessions = self.task_session_db.get_pending_sessions(max_days_back=3)

        if not pending_sessions:
            # 没有pending sessions时不打印日志，避免噪音
            return None

        # 先不打印日志，只有匹配成功时才打印

        # 2. 遍历pending sessions，尝试匹配
        for session in pending_sessions:
            session_id = session.get('id')
            provider_id = session.get('providerId')
            task_id = session.get('taskId')

            if not provider_id:
                print(f"⚠️  Session {session_id} 缺少providerId，跳过")
                continue

            # 3. 通过providerId检索provider配置
            provider_urls = self.provider_query.get_provider_urls(provider_id)

            if not provider_urls:
                # 只在调试模式下打印这些信息
                # print(f"⚠️  Provider {provider_id} 没有找到URL配置")
                continue

            # 4. 尝试匹配URL
            match_result = self._match_url_with_provider_urls(request_url, provider_urls)

            if match_result:
                # 只有匹配成功时才打印所有日志
                print(f"🔍 检查pending sessions匹配: {request_url}")
                print(f"📋 找到 {len(pending_sessions)} 个pending sessions")
                print(f"✅ 匹配成功！Session: {session_id}, Provider: {provider_id}")
                print(f"   请求URL: {request_url}")
                print(f"   匹配URL: {match_result['matched_url']}")
                print(f"   相似度: {match_result['similarity_score']:.3f}")
                print(f"   基础URL匹配: {match_result['base_exact_match']}")

                # 5. 构建attestor入参
                attestor_params = self._build_attestor_params(flow, session, provider_id, match_result)

                # 5.1 将attestor入参保存到session记录中
                self._save_attestor_params_to_session(session['id'], attestor_params)

                # 6. 检查attestor_db中是否已有响应
                attestor_response = self._check_attestor_response(task_id)

                return {
                    'session': session,
                    'provider_id': provider_id,
                    'task_id': task_id,
                    'match_result': match_result,
                    'attestor_params': attestor_params,
                    'attestor_response': attestor_response,
                    'should_call_attestor': attestor_response is None
                }

        # 没有匹配时不打印日志，避免噪音
        return None

    def _build_attestor_params(self, flow, session: Dict, provider_id: str, match_result: Dict) -> Dict:
        """
        根据provider的requestData配置和实际请求构建attestor入参

        Args:
            flow: mitmproxy的flow对象
            session: session信息
            provider_id: provider ID
            match_result: URL匹配结果

        Returns:
            Dict: attestor入参
        """
        print(f"🔧 构建attestor入参...")

        # 1. 获取provider配置
        provider = self.provider_query.get_provider_by_id(provider_id)
        if not provider:
            print(f"❌ 无法获取provider配置: {provider_id}")
            return {}

        # 2. 获取requestData配置
        provider_config = provider.get('providerConfig', {})
        inner_config = provider_config.get('providerConfig', provider_config)
        request_data_list = inner_config.get('requestData', [])

        # 3. 找到匹配的requestData
        matched_request_data = None
        matched_url = match_result['matched_url']

        for request_data in request_data_list:
            if request_data.get('url') == matched_url:
                matched_request_data = request_data
                break

        if not matched_request_data:
            print(f"❌ 无法找到匹配的requestData配置")
            return {}

        # 4. 构建基础参数 - 🎯 修复：按照参考配置格式，Host和Connection放在params.headers中
        params = {
            'url': flow.request.pretty_url,  # 使用实际请求的URL
            'method': flow.request.method,
            'geoLocation': 'HK',  # 🎯 添加地理位置
            'headers': {
                'Host': flow.request.host,
                'Connection': 'close'
            },  # 🎯 修复：按照参考配置，只放Host和Connection
            'body': '',
            'responseMatches': self._convert_response_matches_format(matched_request_data.get('responseMatches', [])),
            'responseRedactions': self._convert_redactions_format(matched_request_data.get('responseRedactions', []))
        }

        # 构建attestor_params的正确结构 - 🎯 添加必要的顶层字段
        attestor_params = {
            'name': 'http',  # 🎯 添加name字段
            'params': params,
            'secretParams': {
                'headers': {}
            }
        }

        # 5. 处理headers - 从实际请求中提取
        request_headers = dict(flow.request.headers)

        # 5.1 基础headers（总是需要的）- 🎯 确保关键headers不被redacted
        essential_headers = [
            'host', 'user-agent', 'accept', 'accept-language',
            'accept-encoding', 'connection', 'cookie', 'referer',
            'content-type', 'content-length', 'authorization',
            'origin', 'x-requested-with', 'sec-fetch-site',
            'sec-fetch-mode', 'sec-fetch-dest', 'sec-ch-ua',
            'sec-ch-ua-mobile', 'sec-ch-ua-platform'
        ]



        for header_name in essential_headers:
            header_value = request_headers.get(header_name) or request_headers.get(header_name.title())
            if header_value:
                attestor_params['secretParams']['headers'][header_name] = header_value

        # 5.2 动态补充其他headers - 🎯 所有headers都放在secretParams中
        for header_name, header_value in request_headers.items():
            header_lower = header_name.lower()
            if header_lower not in attestor_params['secretParams']['headers'] and not header_lower.startswith(':'):
                attestor_params['secretParams']['headers'][header_name] = header_value

        # 6. 处理body - 🎯 修复：确保body与Content-Length一致
        if flow.request.content and len(flow.request.content) > 0:
            try:
                # 使用实际的body内容，确保与Content-Length header一致
                params['body'] = flow.request.get_text()
                print(f"🔍 使用实际body: 长度={len(params['body'])}")
            except:
                params['body'] = flow.request.content.decode('utf-8', errors='ignore')
                print(f"🔍 使用解码body: 长度={len(params['body'])}")
        else:
            params['body'] = ""
            print(f"🔍 使用空body: 长度=0")

        # 6.1 🎯 修复：动态更新Content-Length以匹配实际body长度
        actual_body_length = len(params['body'].encode('utf-8'))
        attestor_params['secretParams']['headers']['content-length'] = str(actual_body_length)
        print(f"🔍 更新Content-Length: {actual_body_length}")

        # 7. 添加cookieStr字段（attestor-core需要）
        cookie_header = request_headers.get('cookie') or request_headers.get('Cookie')
        if cookie_header:
            attestor_params['secretParams']['cookieStr'] = cookie_header

        # 8. 添加session相关信息到secretParams（保持headers不被覆盖）
        attestor_params['secretParams'].update({
            'session_id': session.get('id'),
            'task_id': session.get('taskId'),
            'provider_id': provider_id
        })



        print(f"✅ 构建完成: URL={params['url'][:100]}...")
        print(f"   方法: {params['method']}")
        print(f"   Params Headers: {len(params['headers'])}")
        print(f"   SecretParams Headers: {len(attestor_params['secretParams']['headers'])}")
        print(f"   Body长度: {len(params['body'])}")
        print(f"   ResponseMatches数量: {len(params['responseMatches'])}")
        print(f"   ResponseRedactions数量: {len(params['responseRedactions'])}")
        print(f"   SecretParams: {list(attestor_params['secretParams'].keys())}")

        # 🔍 详细记录responseRedactions，用于分析extractedParameters问题
        print(f"🔍 详细的ResponseRedactions配置:")
        for i, redaction in enumerate(params['responseRedactions'], 1):
            regex = redaction.get('regex', '')
            print(f"   {i}. Regex: {regex}")

            # 检查命名捕获组
            import re
            named_groups = re.findall(r'\(\?P<([^>]+)>', regex)
            if named_groups:
                print(f"      命名捕获组: {named_groups}")
                print(f"      这些字段应该出现在extractedParameters中")
            else:
                print(f"      ⚠️ 没有命名捕获组，不会提取数据")

        print(f"🎯 如果attestor成功但extractedParameters为空，说明正则表达式没有匹配到响应内容")

        return attestor_params

    def _convert_redactions_format(self, redactions: List[Dict]) -> List[Dict]:
        """
        转换responseRedactions格式，移除不兼容的字段

        Args:
            redactions: 原始redactions列表

        Returns:
            List[Dict]: 转换后的redactions列表
        """
        converted = []
        for redaction in redactions:
            # 只保留attestor-core需要的字段
            converted_redaction = {
                'regex': redaction.get('regex', '')
            }

            # 如果有其他attestor-core支持的字段，可以在这里添加
            if 'jsonPath' in redaction and redaction['jsonPath']:
                converted_redaction['jsonPath'] = redaction['jsonPath']
            if 'xPath' in redaction and redaction['xPath']:
                converted_redaction['xPath'] = redaction['xPath']

            converted.append(converted_redaction)

        return converted

    def _convert_response_matches_format(self, response_matches: List[Dict]) -> List[Dict]:
        """
        转换responseMatches格式，移除不兼容的字段

        Args:
            response_matches: 原始responseMatches列表

        Returns:
            List[Dict]: 转换后的responseMatches列表
        """
        converted = []
        for match in response_matches:
            # 只保留attestor-core支持的字段
            converted_match = {
                'type': match.get('type', 'regex'),
                'value': match.get('value', '')
            }

            # 如果有invert字段，保留它
            if 'invert' in match:
                converted_match['invert'] = match['invert']

            converted.append(converted_match)

        return converted

    def _save_attestor_params_to_session(self, session_id: str, attestor_params: Dict) -> None:
        """
        将attestor入参保存到session记录中

        Args:
            session_id: session ID
            attestor_params: attestor入参
        """
        try:
            # 更新session记录，添加attestor_params
            success = self.task_session_db.update_session_status(
                session_id,
                None,  # 不改变状态
                {
                    'attestor_params': attestor_params,
                    'attestor_params_saved_at': time.time()
                }
            )

            if success:
                print(f"✅ Attestor入参已保存到session: {session_id}")
            else:
                print(f"❌ 保存attestor入参失败: {session_id}")

        except Exception as e:
            print(f"❌ 保存attestor入参异常: {e}")

    def _match_url_with_provider_urls(self, request_url: str, provider_urls: List[str]) -> Optional[Dict[str, Any]]:
        """
        将请求URL与provider URLs进行匹配

        Args:
            request_url: 请求URL
            provider_urls: Provider中的URL列表

        Returns:
            匹配结果或None
        """
        best_match = None
        best_score = 0.0

        for provider_url in provider_urls:
            # 计算URL相似度
            similarity_result = self.url_matcher.calculate_url_similarity(request_url, provider_url)

            # 匹配规则：只有综合相似度达到阈值才算匹配
            if similarity_result['is_match'] and similarity_result['composite_score'] > best_score:
                # 只在找到匹配时才打印详细信息
                print(f"  🔗 比较URL: {provider_url}")
                print(f"     相似度: {similarity_result['composite_score']:.3f}")
                print(f"     基础URL匹配: {similarity_result['base_exact_match']}")

                best_match = {
                    'matched_url': provider_url,
                    'similarity_score': similarity_result['composite_score'],
                    'base_exact_match': similarity_result['base_exact_match'],
                    'similarity_details': similarity_result
                }
                best_score = similarity_result['composite_score']

        return best_match

    def _check_attestor_response(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        检查attestor_db中是否已有对应task_id的响应

        Args:
            task_id: 任务ID

        Returns:
            attestor响应数据或None
        """
        try:
            # 查询attestor_db
            response_data = self.attestor_db.get_response(task_id)

            if response_data:
                print(f"✅ 在attestor_db中找到task_id {task_id} 的响应")
                return response_data
            else:
                print(f"📝 attestor_db中没有找到task_id {task_id} 的响应")
                return None

        except Exception as e:
            print(f"❌ 查询attestor_db失败: {e}")
            return None

    def update_session_status_based_on_attestor_db(self):
        """
        根据attestor_db的数据更新session状态
        将有attestor响应的pending sessions标记为finished
        """
        print("🔄 检查并更新session状态...")

        pending_sessions = self.task_session_db.get_pending_sessions(max_days_back=7)
        updated_count = 0

        for session in pending_sessions:
            session_id = session.get('id')
            task_id = session.get('taskId')

            if not task_id:
                continue

            # 检查attestor_db中是否有响应
            attestor_response = self._check_attestor_response(task_id)

            if attestor_response:
                # 🎯 从attestor响应中提取taskId
                attestor_task_id = attestor_response.get('task_id') or attestor_response.get('taskId')

                # 构建更新数据
                update_data = {
                    'attestor_response_found': True,
                    'attestor_response_timestamp': attestor_response.get('response_timestamp'),
                    'updated_by': 'session_based_matcher'
                }

                # 如果有attestor taskId，更新session的taskId
                if attestor_task_id:
                    update_data['taskId'] = attestor_task_id
                    print(f"🔄 更新session taskId (周期检查): {task_id} -> {attestor_task_id}")

                # 更新session状态为Finished
                success = self.task_session_db.update_session_status(
                    session_id,
                    SessionStatus.FINISHED,
                    update_data
                )

                if success:
                    updated_count += 1
                    print(f"✅ 更新session {session_id} 状态为Finished")

        print(f"🔄 状态更新完成，共更新 {updated_count} 个sessions")
        return updated_count

    def create_session_for_provider_match(self, provider_id: str, task_id: str,
                                        additional_data: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """
        为匹配的provider创建新的session记录

        Args:
            provider_id: Provider ID
            task_id: 任务ID
            additional_data: 额外数据

        Returns:
            创建的session ID或None
        """
        try:
            session_id = self.task_session_db.create_session(
                task_id=task_id,
                provider_id=provider_id,
                additional_data=additional_data
            )

            if session_id:
                print(f"✅ 为provider {provider_id} 创建session: {session_id}")
                return session_id
            else:
                print(f"❌ 创建session失败")
                return None

        except Exception as e:
            print(f"❌ 创建session异常: {e}")
            return None

    def get_matching_statistics(self) -> Dict[str, Any]:
        """
        获取匹配统计信息

        Returns:
            统计信息字典
        """
        # 获取session统计
        pending_sessions = self.task_session_db.get_pending_sessions(max_days_back=7)

        # 获取provider统计
        provider_stats = self.provider_query.get_provider_statistics()

        # 计算匹配率等统计信息
        total_sessions = len(pending_sessions)

        return {
            'pending_sessions_count': total_sessions,
            'provider_files_count': provider_stats['total_files'],
            'total_providers_count': provider_stats['total_providers'],
            'matcher_threshold': self.url_matcher.similarity_threshold,
            'last_check_time': time.time()
        }

    def run_periodic_check(self):
        """
        运行周期性检查
        1. 更新session状态
        2. 清理过期数据等
        """
        print("🔄 开始周期性检查...")

        # 1. 更新session状态
        updated_count = self.update_session_status_based_on_attestor_db()

        # 2. 清理缓存
        self.provider_query.clear_cache()

        # 3. 输出统计信息
        stats = self.get_matching_statistics()
        print(f"📊 当前统计:")
        print(f"   Pending Sessions: {stats['pending_sessions_count']}")
        print(f"   Provider文件数: {stats['provider_files_count']}")
        print(f"   总Provider数: {stats['total_providers_count']}")

        print(f"✅ 周期性检查完成，更新了 {updated_count} 个sessions")

        return {
            'updated_sessions': updated_count,
            'statistics': stats
        }



# 全局实例
_session_matcher = None


def get_session_matcher() -> SessionBasedMatcher:
    """获取全局SessionBasedMatcher实例"""
    global _session_matcher
    if _session_matcher is None:
        _session_matcher = SessionBasedMatcher()
    return _session_matcher



if __name__ == "__main__":
    # 测试代码
    matcher = get_session_matcher()

    print("🔧 SessionBasedMatcher 测试")
    print("=" * 50)

    # 运行周期性检查
    result = matcher.run_periodic_check()
    print(f"周期性检查结果: {result}")

    # 获取统计信息
    stats = matcher.get_matching_statistics()
    print(f"统计信息: {stats}")
