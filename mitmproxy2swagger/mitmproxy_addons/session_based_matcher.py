#!/usr/bin/env python3
"""
基于Session的匹配器
实现第一个功能点：通过task session记录匹配API到attestor
"""

import json
import time
import time
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse
import importlib.util
from pathlib import Path
from mitmproxy import http
from task_session_db import get_task_session_db, SessionStatus
from provider_query import get_provider_query
from url_matcher import URLMatcher
from attestor_db import get_attestor_db
from http_to_attestor_converter import HttpToAttestorConverter


class SessionBasedMatcher:
    """基于Session的API匹配器"""

    def __init__(self):
        self.task_session_db = get_task_session_db()
        self.provider_query = get_provider_query()
        self.url_matcher = URLMatcher()
        self.attestor_db = get_attestor_db()
        self.api_value_filter = self._load_api_value_filter()

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
        # 0. 优先按 session_id 直连（来自代理绑定）
        try:
            sid = flow.metadata.get('session_id') if hasattr(flow, 'metadata') else None
            if sid:
                session = self.task_session_db.get_session(str(sid))
                if session and session.get('providerId'):
                    provider_id = session['providerId']
                    task_id = session.get('taskId') or ''
                    # 构建attestor入参（此时无需再做URL相似度匹配）
                    match_result = {
                        'matched_url': flow.request.pretty_url,
                        'similarity_score': 1.0,
                        'base_exact_match': True
                    }
                    attestor_params = self._build_attestor_params(flow, session, provider_id, match_result)
                    attestor_response = self._check_attestor_response(task_id) if task_id else None
                    print(f"🎯 Session直连: session_id={sid}, provider_id={provider_id}, url={flow.request.pretty_url}")
                    return {
                        'session': session,
                        'provider_id': provider_id,
                        'task_id': task_id,
                        'match_result': match_result,
                        'attestor_params': attestor_params,
                        'attestor_response': attestor_response,
                        'should_call_attestor': attestor_response is None
                    }
        except Exception as _e:
            # 直连失败时继续走老路径
            print(f"⚠️ Session直连失败，回退URL匹配: {getattr(_e, 'message', _e)} | url={flow.request.pretty_url}")

        # 1. 前置清洗：调用 feature-library 过滤低价值/静态资源 API
        try:
            url_for_filter = flow.request.pretty_url
            filter_result = self.api_value_filter.filter_and_score_api(url_for_filter, original_score=20)
            if filter_result.get('should_exclude') or filter_result.get('final_recommendation') == 'exclude':
                return None
        except Exception:
            # 过滤异常时，不阻塞后续流程
            pass

        request_url = flow.request.pretty_url

        # 2. 获取所有pending状态的sessions
        pending_sessions = self.task_session_db.get_pending_sessions(max_days_back=3)

        if not pending_sessions:
            # 没有pending sessions时不打印日志，避免噪音
            return None

        # 先不打印日志，只有匹配成功时才打印

        # 3. 遍历pending sessions，尝试匹配
        for session in pending_sessions:
            session_id = session.get('id')
            provider_id = session.get('providerId')
            task_id = session.get('taskId')

            if not provider_id:
                print(f"⚠️  Session {session_id} 缺少providerId，跳过")
                continue

            # 4. 尝试匹配URL（结合provider的method信息）
            match_result = self._match_url_with_provider(request_url, flow, provider_id)

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

        # 4. 构建基础参数 - 分离认证头部和普通头部
        request_headers_dict = dict(flow.request.headers)
        basic_headers, sensitive_headers = self._split_headers(request_headers_dict)

        params = {
            'url': flow.request.pretty_url,  # 使用实际请求的URL
            'method': flow.request.method,
            'geoLocation': 'HK',
            'headers': basic_headers,  # 普通请求头放入 params.headers
            'body': '',
            'responseMatches': self._convert_response_matches_format(matched_request_data.get('responseMatches', [])),
            'responseRedactions': self._convert_redactions_format(matched_request_data.get('responseRedactions', []))
        }

        # 构建secretParams - 按照attestor-core的期望格式，不包含headers字段
        secret_params = {}

        # 特殊处理Cookie和Authorization
        for key, value in sensitive_headers.items():
            key_lower = key.lower()
            if key_lower == 'cookie':
                secret_params['cookieStr'] = value
            elif key_lower == 'authorization':
                secret_params['authorisationHeader'] = value

        # 构建attestor_params的正确结构 - 🎯 添加必要的顶层字段
        attestor_params = {
            'name': 'http',  # 🎯 添加name字段
            'params': params,
            'secretParams': secret_params
        }

        # 5. headers 已放入 params.headers

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

        # 6.1 动态更新Content-Length以匹配实际body长度（更新到 params.headers）
        actual_body_length = len(params['body'].encode('utf-8'))
        params_headers_lower = {k.lower(): k for k in params['headers'].keys()}
        key_in_headers = params_headers_lower.get('content-length')
        if key_in_headers:
            params['headers'][key_in_headers] = str(actual_body_length)
        else:
            # 默认使用小写键名以保持与实际请求一致
            params['headers']['content-length'] = str(actual_body_length)
        print(f"🔍 更新Content-Length到 params.headers: {actual_body_length}")

        # 7. 规范化 headers 以满足 attestor-core http provider 的要求（强制 Connection: close 等）
        try:
            _converter = HttpToAttestorConverter()
            _converter._enforce_attestor_header_requirements(params['headers'], params['body'])  # noqa: SLF001 私有方法，受控调用
        except Exception as _e:
            # 规范化失败不应阻塞流程，打印一次调试信息
            print(f"⚠️ headers规范化失败（忽略）：{_e}")

        # 8. Cookie 等认证信息已放入 secretParams.headers 中



        print(f"✅ 构建完成: URL={params['url'][:100]}...")
        print(f"   方法: {params['method']}")
        print(f"   普通Headers: {len(params['headers'])}")
        print(f"   SecretParams: {list(attestor_params['secretParams'].keys())}")
        print(f"   Body长度: {len(params['body'])}")
        print(f"   ResponseMatches数量: {len(params['responseMatches'])}")
        print(f"   ResponseRedactions数量: {len(params['responseRedactions'])}")

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
                best_match = {
                    'matched_url': provider_url,
                    'similarity_score': similarity_result['composite_score'],
                    'base_exact_match': similarity_result['base_exact_match'],
                    'similarity_details': similarity_result
                }
                best_score = similarity_result['composite_score']

        return best_match

    def _diagnose_best_similarity_any(self, request_url: str, provider_urls: List[str]) -> Optional[Dict[str, Any]]:
        """不考虑阈值，返回最高分的相似度结果用于诊断日志"""
        best_url = None
        best_res = None
        best_score = -1.0
        for provider_url in provider_urls:
            res = self.url_matcher.calculate_url_similarity(request_url, provider_url)
            if res['composite_score'] > best_score:
                best_score = res['composite_score']
                best_url = provider_url
                best_res = res
        if best_res is None:
            return None
        return {
            'matched_url': best_url,
            'similarity_score': best_res['composite_score'],
            'base_exact_match': best_res['base_exact_match'],
            'similarity_details': best_res
        }

    def _is_static_resource(self, flow: http.HTTPFlow) -> bool:
        """基于URL路径快速识别静态资源请求（css/js/图片/字体/视频等）"""
        try:
            path = urlparse(flow.request.pretty_url).path.lower()
        except Exception:
            return False

        # 常见静态资源后缀
        static_exts = (
            '.css', '.js', '.mjs', '.map',
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico',
            '.woff', '.woff2', '.ttf', '.eot',
            '.mp4', '.webm', '.avi', '.mov',
            '.pdf', '.apk', '.exe', '.dmg',
            '.zip', '.tar', '.gz', '.7z', '.rar'
        )

        if any(path.endswith(ext) for ext in static_exts):
            return True

        # 常见静态目录关键词
        static_dirs = (
            '/static/', '/assets/', '/images/', '/imgs/', '/img/', '/fonts/', '/media/', '/styles/', '/scripts/'
        )
        if any(seg in path for seg in static_dirs):
            return True

        return False

    def _load_api_value_filter(self):
        """动态加载 feature-library 的 APIValueFilter（feature-library 目录含连字符，不能直接import）"""
        try:
            current_dir = Path(__file__).resolve().parent  # mitmproxy_addons
            project_root = current_dir.parent  # mitmproxy2swagger
            filter_py = project_root / "feature-library" / "filter_features" / "api_value_filter.py"
            spec = importlib.util.spec_from_file_location("api_value_filter", str(filter_py))
            module = importlib.util.module_from_spec(spec)
            assert spec and spec.loader
            spec.loader.exec_module(module)  # type: ignore
            APIValueFilter = getattr(module, "APIValueFilter")
            return APIValueFilter()
        except Exception:
            # 失败时返回一个简易兜底对象，始终不过滤
            class _NoopFilter:
                def filter_and_score_api(self, url: str, original_score: int, response_content: str = ""):
                    return {
                        'url': url,
                        'original_score': original_score,
                        'should_exclude': False,
                        'final_recommendation': 'keep'
                    }
            return _NoopFilter()

    def _match_url_with_provider(self, request_url: str, flow, provider_id: str) -> Optional[Dict[str, Any]]:
        """综合URL、HTTP方法、消息体长度进行匹配，命中则给高分"""
        provider = self.provider_query.get_provider_by_id(provider_id)
        if not provider:
            return None

        # 提取requestData
        provider_config = provider.get('providerConfig', {})
        inner_config = provider_config.get('providerConfig', provider_config)
        request_data_list = inner_config.get('requestData', []) or []

        # 收集所有候选URL
        provider_urls = []
        for rd in request_data_list:
            if isinstance(rd, dict) and rd.get('url'):
                provider_urls.append(rd['url'])

        if not provider_urls:
            return None

        # 先用原有URL相似度找最佳匹配（受阈值影响）
        best = self._match_url_with_provider_urls(request_url, provider_urls)
        if not best:
            # 阈值下未命中时，尝试使用“增强判定”直接拉升分数（基于 base_exact/method/cookie/body）
            diag = self._diagnose_best_similarity_any(request_url, provider_urls)
            if diag:
                matched_url_diag = diag['matched_url']
                # 找到对应的requestData
                matched_request_data_diag = None
                for rd in request_data_list:
                    if isinstance(rd, dict) and rd.get('url') == matched_url_diag:
                        matched_request_data_diag = rd
                        break

                details = diag.get('similarity_details', {})
                base_exact = bool(details.get('base_exact_match'))

                req_method = (flow.request.method or '').upper()
                cfg_method = (matched_request_data_diag.get('method') or '').upper() if isinstance(matched_request_data_diag, dict) else ''
                method_ok = True if not cfg_method else (req_method == cfg_method)

                headers_lower = {k.lower(): v for k, v in dict(flow.request.headers).items()}
                has_cookie_or_auth = ('cookie' in headers_lower) or ('authorization' in headers_lower)

                body_bytes = flow.request.content or b''
                body_empty = (len(body_bytes) == 0)

                if base_exact and method_ok and (body_empty or has_cookie_or_auth):
                    score = max(diag['similarity_score'], 0.95)
                    try:
                        reason = "空body" if body_empty else "有cookie/auth"
                        print("  🔎 URL比对:")
                        print(f"     请求: {request_url}")
                        print(f"     配置: {matched_url_diag}")
                        print(f"     分数: {score:.3f} | base_exact=True | method匹配 | {reason} -> 提升为高分")
                    except Exception:
                        pass
                    return {
                        'matched_url': matched_url_diag,
                        'similarity_score': score,
                        'base_exact_match': True,
                        'similarity_details': details
                    }

                # 若仍不满足增强判定，只对中高分(>=0.5)输出诊断日志，避免大量低分噪音
                if diag['similarity_score'] >= 0.5:
                    try:
                        print("  🔎 URL比对:")
                        print(f"     请求: {request_url}")
                        print(f"     配置: {matched_url_diag}")
                        print(f"     分数: {diag['similarity_score']:.3f} | base_exact={details.get('base_exact_match')} | query_similarity={details.get('query_similarity')}")
                        if details.get('base_exact_match') and details.get('query_similarity') == 0:
                            print("     说明: 基础URL完全匹配，query为空 -> 使用公式 0.3 + 0.7*0 = 0.3")
                    except Exception:
                        pass
            return None

        matched_url = best['matched_url']
        score = best['similarity_score']

        # 找到对应的requestData，检查method与body
        matched_request_data = None
        for rd in request_data_list:
            if isinstance(rd, dict) and rd.get('url') == matched_url:
                matched_request_data = rd
                break

        # 判定条件：URL基础一致、method一致且拦截请求体为空
        try:
            base_exact = self.url_matcher.match_base_url_exact(request_url, matched_url)
        except Exception:
            base_exact = False

        method_ok = True
        req_method = (flow.request.method or '').upper()
        cfg_method = (matched_request_data.get('method') or '').upper() if isinstance(matched_request_data, dict) else ''
        if cfg_method:
            method_ok = (req_method == cfg_method)

        # 请求体是否为空
        body_bytes = flow.request.content or b''
        body_empty = (len(body_bytes) == 0)

        headers_lower = {k.lower(): v for k, v in dict(flow.request.headers).items()}
        has_cookie_or_auth = ('cookie' in headers_lower) or ('authorization' in headers_lower)

        # 如果条件满足（空body 或 cookie/auth 证明为会话请求），直接提升为高分，确保通过
        if base_exact and method_ok and (body_empty or has_cookie_or_auth):
            score = max(score, 0.95)
            boosted = {
                'matched_url': matched_url,
                'similarity_score': score,
                'base_exact_match': True,
                'similarity_details': best.get('similarity_details', {})
            }
            try:
                reason = "空body" if body_empty else "有cookie/auth"
                print("  🔎 URL比对:")
                print(f"     请求: {request_url}")
                print(f"     配置: {matched_url}")
                print(f"     分数: {score:.3f} | base_exact=True | method匹配 | {reason} -> 提升为高分")
            except Exception:
                pass
            return boosted

        # 正常命中，打印一次最终比对日志
        try:
            details = best.get('similarity_details', {})
            print("  🔎 URL比对:")
            print(f"     请求: {request_url}")
            print(f"     配置: {matched_url}")
            print(f"     分数: {score:.3f} | base_exact={details.get('base_exact_match')} | query_similarity={details.get('query_similarity'):.3f}")
        except Exception:
            pass
        return best

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

    def _split_headers(self, headers: Dict[str, str]) -> Tuple[Dict[str, str], Dict[str, str]]:
        """
        分离基础headers和敏感headers

        Args:
            headers: 原始headers字典

        Returns:
            (basic_headers, sensitive_headers) 元组
        """
        # 敏感headers，需要放到secretParams中
        sensitive_header_names = {
            'cookie', 'authorization', 'x-auth-token', 'x-api-key',
            'x-session-token', 'x-csrf-token', 'x-nonce'
        }

        basic_headers = {}
        sensitive_headers = {}

        for key, value in headers.items():
            key_lower = key.lower()
            if key_lower in sensitive_header_names:
                sensitive_headers[key] = value
            else:
                basic_headers[key] = value

        return basic_headers, sensitive_headers



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
