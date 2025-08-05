#!/usr/bin/env python3
"""
Reclaim Provider构建器
Reclaim Provider Builder

基于特征库分析结果和抓包数据，自动构建Reclaim标准的provider配置
重点分析responseMatches、responseRedactions等关键字段

核心功能：
1. 读取integrate_with_mitmproxy2swagger.py的分析结果
2. 回溯原始抓包数据，提取完整的请求/响应信息
3. 分析HTTP headers中的认证信息
4. 构建responseMatches和responseRedactions
5. 生成完整的provider配置
6. 质量检查，将信息不足的API输出到存疑文件
"""

import os
import sys
import json
import re
import hashlib
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict
from urllib.parse import urlparse, parse_qs

# 添加项目路径
sys.path.append(str(Path(__file__).parent.parent))
sys.path.append(str(Path(__file__).parent.parent / "mitmproxy2swagger"))

from mitmproxy2swagger.mitmproxy_capture_reader import MitmproxyCaptureReader


@dataclass
class ProviderQualityCheck:
    """Provider质量检查结果"""
    has_authentication: bool = False
    has_response_data: bool = False
    has_financial_patterns: bool = False
    has_sufficient_headers: bool = False
    missing_fields: List[str] = None
    confidence_score: float = 0.0

    def __post_init__(self):
        if self.missing_fields is None:
            self.missing_fields = []


class ReclaimProviderBuilder:
    """Reclaim Provider构建器"""

    def __init__(self, mitm_file_path: str, analysis_result_file: str):
        """初始化构建器

        Args:
            mitm_file_path: 原始mitm文件路径
            analysis_result_file: 特征库分析结果文件路径
        """
        self.mitm_file_path = mitm_file_path
        self.analysis_result_file = analysis_result_file

        # 加载分析结果
        self.analysis_data = self.load_analysis_result()

        # 创建mitm读取器
        self.capture_reader = MitmproxyCaptureReader(mitm_file_path)

        # 存储原始流数据的映射
        self.flow_data_map = {}
        self.build_flow_data_map()

        # 认证相关的header模式
        self.auth_header_patterns = [
            'authorization', 'x-auth-token', 'x-api-key', 'x-session-token',
            'x-csrf-token', 'x-nonce', 'x-requested-with', 'x-target-unit',
            'cookie', 'set-cookie', 'session-id', 'jsessionid'
        ]

        # 重要的header模式
        self.important_header_patterns = [
            'content-type', 'accept', 'user-agent', 'referer', 'origin',
            'sec-ch-ua', 'sec-fetch-', 'x-'
        ]

    def load_analysis_result(self) -> Dict[str, Any]:
        """加载特征库分析结果"""
        try:
            with open(self.analysis_result_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            raise Exception(f"无法加载分析结果文件: {e}")

    def build_flow_data_map(self):
        """构建流数据映射，用于快速查找原始请求/响应数据"""
        print("🔍 构建流数据映射...")

        for flow_wrapper in self.capture_reader.captured_requests():
            url = flow_wrapper.get_url()

            # 🎯 安全地获取响应体，处理编码问题
            try:
                response_body = flow_wrapper.get_response_body()
            except ValueError as e:
                if "Invalid Content-Encoding" in str(e):
                    print(f"⚠️  跳过编码有问题的响应: {url}")
                    continue
                else:
                    raise

            # 提取完整的请求/响应数据
            flow_data = {
                'url': url,
                'method': flow_wrapper.get_method(),
                'request_headers': dict(flow_wrapper.get_request_headers()),
                'response_headers': dict(flow_wrapper.get_response_headers()),
                'request_body': flow_wrapper.get_request_body(),
                'response_body': response_body,
                'status_code': flow_wrapper.get_response_status_code()
            }

            self.flow_data_map[url] = flow_data

        print(f"✅ 构建完成，共映射 {len(self.flow_data_map)} 个流")

    def extract_authentication_info(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """提取认证信息

        Args:
            headers: HTTP headers

        Returns:
            认证信息字典
        """
        auth_info = {
            'has_auth': False,
            'auth_headers': [],
            'session_info': [],
            'csrf_tokens': [],
            'api_keys': []
        }

        for header_name, header_value in headers.items():
            header_lower = header_name.lower()

            # 检查认证相关header
            for pattern in self.auth_header_patterns:
                if pattern in header_lower:
                    auth_info['has_auth'] = True
                    auth_info['auth_headers'].append({
                        'name': header_name,
                        'value': header_value,
                        'type': self.classify_auth_header(header_name, header_value)
                    })
                    break

        return auth_info

    def classify_auth_header(self, name: str, value: str) -> str:
        """分类认证header类型"""
        name_lower = name.lower()

        if 'authorization' in name_lower:
            return 'bearer_token' if 'bearer' in value.lower() else 'basic_auth'
        elif 'session' in name_lower or 'jsessionid' in name_lower:
            return 'session'
        elif 'csrf' in name_lower or 'xsrf' in name_lower:
            return 'csrf_token'
        elif 'nonce' in name_lower:
            return 'nonce'
        elif 'api-key' in name_lower:
            return 'api_key'
        elif 'cookie' in name_lower:
            return 'cookie'
        else:
            return 'custom'

    def extract_response_patterns(self, response_content: str, url: str, api_data: Dict = None) -> Tuple[List[Dict], List[Dict]]:
        """从响应内容中提取模式，用于构建responseMatches和responseRedactions

        Args:
            response_content: 响应内容
            url: API URL
            api_data: API分析数据（包含matched_patterns）

        Returns:
            Tuple[List[Dict], List[Dict]]: (responseMatches, responseRedactions)
        """
        response_matches = []
        response_redactions = []

        if not response_content:
            return response_matches, response_redactions

        # 🎯 正确方案：基于每个API的实际匹配模式生成对应的正则表达式
        if api_data and 'matched_patterns' in api_data:
            matched_patterns = api_data['matched_patterns']
            print(f"🔍 基于特征库匹配结果生成响应模式: {len(matched_patterns)} 个模式")
            print(f"🔍 匹配模式: {matched_patterns}")

            order_counter = 1

            # 🎯 根据实际匹配的模式生成对应的正则表达式
            for pattern in matched_patterns:
                if pattern.startswith("field:"):
                    # 字段匹配 - 生成字段验证和提取规则
                    field_name = pattern.replace("field:", "")

                    response_matches.append({
                        "value": f'"{field_name}"',
                        "type": "contains",
                        "invert": False,
                        "description": f"验证{field_name}字段存在",
                        "order": order_counter,
                        "isOptional": False
                    })

                    response_redactions.append({
                        "xPath": "",
                        "jsonPath": f"$.{field_name}",
                        "regex": f'"{field_name}":\\s*"?([^",\\}}]+)"?',
                        "hash": "sha256" if self._is_sensitive_field(field_name) else "",
                        "order": order_counter
                    })
                    order_counter += 1

                elif "content:balance" in pattern:
                    # 余额相关API - 生成余额验证和提取规则
                    response_matches.append({
                        "value": "\"balance\":\\s*[0-9]+",
                        "type": "regex",
                        "invert": False,
                        "description": "验证余额数据格式",
                        "order": order_counter,
                        "isOptional": False
                    })

                    response_redactions.append({
                        "xPath": "",
                        "jsonPath": "$.balance",
                        "regex": "\"balance\":\\s*([0-9]+)",
                        "hash": "",
                        "order": order_counter
                    })
                    order_counter += 1

                elif "content:account" in pattern or "content:acc" in pattern:
                    # 账户相关API - 生成账户验证规则
                    response_matches.append({
                        "value": "account",
                        "type": "contains",
                        "invert": False,
                        "description": "验证响应包含账户信息",
                        "order": order_counter,
                        "isOptional": True
                    })
                    order_counter += 1

                elif "content:login" in pattern or "content:logon" in pattern:
                    # 登录相关API - 生成登录验证规则
                    response_matches.append({
                        "value": "session|token|login|success",
                        "type": "regex",
                        "invert": False,
                        "description": "验证登录响应包含会话信息",
                        "order": order_counter,
                        "isOptional": True
                    })

                    response_redactions.append({
                        "xPath": "",
                        "jsonPath": "",
                        "regex": "(session[^\\s]*|token[^\\s]*)",
                        "hash": "sha256",
                        "order": order_counter
                    })
                    order_counter += 1

                elif pattern.startswith("core_banking:"):
                    # 核心银行业务 - 生成金融数据验证规则
                    response_matches.append({
                        "value": "\"amount\":\\s*[0-9]+|\"balance\":\\s*[0-9]+|\"value\":\\s*[0-9]+",
                        "type": "regex",
                        "invert": False,
                        "description": "验证核心银行业务数据",
                        "order": order_counter,
                        "isOptional": False
                    })

                    response_redactions.append({
                        "xPath": "",
                        "jsonPath": "",
                        "regex": "\"(?:amount|balance|value)\":\\s*([0-9]+)",
                        "hash": "",
                        "order": order_counter
                    })
                    order_counter += 1

            if response_matches or response_redactions:
                print(f"✅ 成功生成: {len(response_matches)} 个验证规则, {len(response_redactions)} 个提取规则")
                return response_matches, response_redactions
            else:
                print(f"⚠️  未找到可转换的模式，使用通用规则")
                # 生成通用的验证规则
                response_matches.append({
                    "value": "200",
                    "type": "contains",
                    "invert": False,
                    "description": "验证HTTP响应成功",
                    "order": 1,
                    "isOptional": True
                })
                return response_matches, response_redactions

        # 🔄 回退：使用传统方法
        print(f"⚠️  回退到传统方法生成响应模式")
        try:
            # 尝试解析JSON响应
            response_json = json.loads(response_content)

            # 分析JSON结构，提取关键字段
            financial_patterns = self.analyze_json_financial_patterns(response_json)

            for pattern in financial_patterns:
                # 构建responseMatches
                if pattern['type'] == 'amount':
                    response_matches.append({
                        "value": f'"{pattern["field"]}":{pattern["pattern"]}',
                        "type": "contains",
                        "invert": False,
                        "description": f"匹配{pattern['description']}",
                        "order": None,
                        "isOptional": False
                    })

                    # 构建responseRedactions
                    response_redactions.append({
                        "xPath": "",
                        "jsonPath": pattern['json_path'],
                        "regex": f'"{pattern["field"]}":(.*)',
                        "hash": "",
                        "order": None
                    })

                elif pattern['type'] == 'account':
                    response_matches.append({
                        "value": f'"{pattern["field"]}":"{pattern["pattern"]}"',
                        "type": "contains",
                        "invert": False,
                        "description": f"匹配{pattern['description']}",
                        "order": None,
                        "isOptional": False
                    })

                    response_redactions.append({
                        "xPath": "",
                        "jsonPath": pattern['json_path'],
                        "regex": f'"{pattern["field"]}":"(.*)"',
                        "hash": "",
                        "order": None
                    })

        except json.JSONDecodeError:
            # 非JSON响应，使用文本模式分析
            text_patterns = self.analyze_text_financial_patterns(response_content)

            for pattern in text_patterns:
                response_matches.append({
                    "value": pattern['regex'],
                    "type": "regex",
                    "invert": False,
                    "description": pattern['description'],
                    "order": None,
                    "isOptional": False
                })

        return response_matches, response_redactions

    def analyze_json_financial_patterns(self, json_data: Any, path: str = "$") -> List[Dict]:
        """分析JSON数据中的金融模式"""
        patterns = []

        if isinstance(json_data, dict):
            for key, value in json_data.items():
                current_path = f"{path}.{key}"

                # 检查金额字段
                if self.is_amount_field(key, value):
                    patterns.append({
                        'field': key,
                        'type': 'amount',
                        'pattern': '{{credit_amount}}' if 'credit' in key.lower() else '{{amount}}',
                        'json_path': current_path,
                        'description': '金额字段'
                    })

                # 检查账户字段
                elif self.is_account_field(key, value):
                    patterns.append({
                        'field': key,
                        'type': 'account',
                        'pattern': '{{account_number}}',
                        'json_path': current_path,
                        'description': '账户字段'
                    })

                # 检查交易ID字段
                elif self.is_transaction_field(key, value):
                    patterns.append({
                        'field': key,
                        'type': 'transaction',
                        'pattern': '{{trans_id}}',
                        'json_path': current_path,
                        'description': '交易ID字段'
                    })

                # 递归处理嵌套对象
                if isinstance(value, (dict, list)):
                    patterns.extend(self.analyze_json_financial_patterns(value, current_path))

        elif isinstance(json_data, list):
            for i, item in enumerate(json_data):
                current_path = f"{path}[{i}]"
                patterns.extend(self.analyze_json_financial_patterns(item, current_path))

        return patterns

    def is_amount_field(self, key: str, value: Any) -> bool:
        """判断是否为金额字段"""
        amount_keywords = ['amount', 'balance', 'value', 'total', 'sum', '金额', '余额', '总额']
        key_lower = key.lower()

        # 检查字段名
        if any(keyword in key_lower for keyword in amount_keywords):
            # 检查值是否为数字
            if isinstance(value, (int, float)) or (isinstance(value, str) and value.replace('.', '').replace(',', '').isdigit()):
                return True

        return False

    def is_account_field(self, key: str, value: Any) -> bool:
        """判断是否为账户字段"""
        account_keywords = ['account', 'acct', 'number', 'id', '账户', '账号']
        key_lower = key.lower()

        if any(keyword in key_lower for keyword in account_keywords):
            if isinstance(value, str) and len(value) > 5:  # 账户号通常较长
                return True

        return False

    def is_transaction_field(self, key: str, value: Any) -> bool:
        """判断是否为交易字段"""
        transaction_keywords = ['transaction', 'trans', 'txn', 'reference', 'cheque', '交易', '流水']
        key_lower = key.lower()

        if any(keyword in key_lower for keyword in transaction_keywords):
            if isinstance(value, str):
                return True

        return False

    def analyze_text_financial_patterns(self, text: str) -> List[Dict]:
        """分析文本中的金融模式"""
        patterns = []

        # 金额模式
        amount_patterns = [
            (r'余额[：:]\s*([0-9,]+\.?\d*)', '余额匹配'),
            (r'金额[：:]\s*([0-9,]+\.?\d*)', '金额匹配'),
            (r'账户余额[：:]\s*([0-9,]+\.?\d*)', '账户余额匹配')
        ]

        for pattern, description in amount_patterns:
            if re.search(pattern, text):
                patterns.append({
                    'regex': pattern,
                    'description': description,
                    'type': 'amount'
                })

        return patterns

    def calculate_request_hash(self, url: str, method: str, headers: Dict[str, str]) -> str:
        """计算请求哈希"""
        # 构建用于哈希的字符串
        hash_string = f"{method}:{url}:{json.dumps(sorted(headers.items()))}"

        # 计算SHA256哈希
        hash_object = hashlib.sha256(hash_string.encode())
        return f"0x{hash_object.hexdigest()}"

    def filter_important_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """过滤出重要的headers"""
        important_headers = {}

        for name, value in headers.items():
            name_lower = name.lower()

            # 检查是否为重要header
            is_important = False

            # 认证相关header
            for pattern in self.auth_header_patterns:
                if pattern in name_lower:
                    is_important = True
                    break

            # 其他重要header
            if not is_important:
                for pattern in self.important_header_patterns:
                    if pattern in name_lower:
                        is_important = True
                        break

            if is_important:
                important_headers[name] = value

        return important_headers

    def perform_quality_check(self, api_data: Dict[str, Any], flow_data: Dict[str, Any]) -> ProviderQualityCheck:
        """执行质量检查"""
        check = ProviderQualityCheck()

        # 检查认证信息
        auth_info = self.extract_authentication_info(flow_data['request_headers'])
        check.has_authentication = auth_info['has_auth']
        if not check.has_authentication:
            check.missing_fields.append('authentication_headers')

        # 检查响应数据
        response_body = flow_data.get('response_body')
        if response_body:
            try:
                response_content = response_body.decode('utf-8', errors='ignore')
                check.has_response_data = len(response_content) > 100  # 至少100字符

                # 检查是否包含金融模式
                financial_keywords = ['balance', 'amount', 'account', 'transaction', '余额', '金额', '账户']
                check.has_financial_patterns = any(keyword in response_content.lower() for keyword in financial_keywords)
            except:
                check.has_response_data = False

        if not check.has_response_data:
            check.missing_fields.append('response_data')
        if not check.has_financial_patterns:
            check.missing_fields.append('financial_patterns')

        # 检查header数量
        important_headers = self.filter_important_headers(flow_data['request_headers'])
        check.has_sufficient_headers = len(important_headers) >= 3
        if not check.has_sufficient_headers:
            check.missing_fields.append('sufficient_headers')

        # 计算置信度分数
        score = 0
        if check.has_authentication:
            score += 30
        if check.has_response_data:
            score += 25
        if check.has_financial_patterns:
            score += 25
        if check.has_sufficient_headers:
            score += 20

        check.confidence_score = score / 100.0

        return check

    def build_provider_for_api(self, api_data: Dict[str, Any]) -> Tuple[Optional[Dict], Optional[ProviderQualityCheck]]:
        """为单个API构建provider配置

        Args:
            api_data: API分析数据

        Returns:
            Tuple[Optional[Dict], Optional[ProviderQualityCheck]]: (provider配置, 质量检查结果)
        """
        url = api_data['url']

        # 获取原始流数据
        flow_data = self.flow_data_map.get(url)
        if not flow_data:
            print(f"⚠️  未找到URL的流数据: {url}")
            return None, None

        # 执行质量检查
        quality_check = self.perform_quality_check(api_data, flow_data)

        # 如果质量检查不通过，返回检查结果用于存疑文件
        if quality_check.confidence_score < 0.6:  # 60%置信度阈值
            return None, quality_check

        # 解析响应内容
        response_content = ""
        if flow_data['response_body']:
            try:
                response_content = flow_data['response_body'].decode('utf-8', errors='ignore')
            except:
                response_content = ""

        # 🎯 提取响应模式 - 传入API数据以利用特征库匹配结果
        response_matches, response_redactions = self.extract_response_patterns(response_content, url, api_data)

        # 如果没有找到有效的响应模式，降级处理
        if not response_matches and not response_redactions:
            print(f"⚠️  未找到有效的响应模式: {url}")
            quality_check.missing_fields.append('response_patterns')
            quality_check.confidence_score *= 0.7  # 降低置信度

            if quality_check.confidence_score < 0.6:
                return None, quality_check

        # 提取重要的headers
        important_headers = self.filter_important_headers(flow_data['request_headers'])

        # 计算请求哈希
        request_hash = self.calculate_request_hash(url, flow_data['method'], important_headers)

        # 构建provider配置
        provider_config = {
            "providerConfig": {
                "id": str(uuid.uuid4()).replace('-', '')[:24],  # 24字符ID
                "createdAt": None,
                "providerId": str(uuid.uuid4()),
                "version": {
                    "major": 1,
                    "minor": 0,
                    "patch": 0,
                    "prereleaseTag": None,
                    "prereleaseNumber": None
                },
                "providerConfig": {
                    "loginUrl": self.extract_login_url(url),
                    "customInjection": self.generate_custom_injection(api_data, flow_data),
                    "userAgent": {
                        "ios": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
                        "android": None
                    },
                    "geoLocation": self.extract_geo_location(flow_data),
                    "injectionType": "NONE",
                    "disableRequestReplay": True,
                    "verificationType": "WITNESS",
                    "requestData": [
                        {
                            "url": url,
                            "expectedPageUrl": "",
                            "urlType": "CONSTANT",
                            "method": flow_data['method'],
                            "responseMatches": response_matches,
                            "responseRedactions": response_redactions,
                            "bodySniff": {
                                "enabled": False,
                                "template": ""
                            },
                            "requestHash": request_hash,
                            "responseVariables": self.extract_response_variables(response_matches, response_redactions)
                        }
                    ],
                    "pageTitle": None,
                    "metadata": {
                        "institution": api_data.get('institution', ''),
                        "api_type": self.classify_api_type(url, response_content),
                        "value_score": api_data.get('value_score', 0),
                        "priority_level": api_data.get('priority_level', 'medium'),
                        "generated_at": datetime.now().isoformat(),
                        "confidence_score": quality_check.confidence_score
                    },
                    "stepsToFollow": None,
                    "useIncognitoWebview": None
                },
                "createdBy": "auto_generated_provider_builder"
            }
        }

        return provider_config, quality_check

    def extract_login_url(self, api_url: str) -> str:
        """通过上下文分析提取真实的登录URL

        Args:
            api_url: 当前API的URL

        Returns:
            str: 登录URL或提示信息
        """
        parsed = urlparse(api_url)
        domain = parsed.netloc

        # 🎯 上下文分析：在同域名的认证类API中查找真实登录URL
        real_login_url = self._find_real_login_url_from_context(domain)

        if real_login_url:
            return real_login_url

        # 🎯 如果没有找到真实登录URL，返回提示信息
        return f"[需要上下文分析] 未在抓包数据中找到 {domain} 的登录URL，请手动确认"

    def _find_real_login_url_from_context(self, domain: str) -> Optional[str]:
        """从上下文中查找真实的登录URL

        Args:
            domain: 目标域名

        Returns:
            Optional[str]: 找到的登录URL，如果没有找到返回None
        """
        # 从分析数据中查找同域名的认证类API
        if not hasattr(self, 'analysis_data') or not self.analysis_data:
            return None

        extracted_data = self.analysis_data.get('extracted_data', [])

        login_candidates = []

        for api_data in extracted_data:
            api_url = api_data.get('url', '')
            api_category = api_data.get('api_category', 'unknown')

            # 🎯 第一步：识别登录提交页（优先级高）
            if domain in api_url and api_category == 'auth':
                flow_data = self.flow_data_map.get(api_url)
                if flow_data:
                    # 评分登录提交页
                    submit_score = self._score_login_submit_api(api_url, flow_data)
                    if submit_score > 20:  # 只有高分的才认为是登录提交页
                        login_candidates.append({
                            'url': api_url,
                            'score': submit_score,
                            'type': 'submit',
                            'flow_data': flow_data
                        })
                        print(f"🔍 发现登录提交页候选: {api_url} (评分: {submit_score})")

        # 🎯 第二步：基于登录提交页找对应的登录页
        if login_candidates:
            # 选择评分最高的登录提交页
            best_submit = max(login_candidates, key=lambda x: x['score'])
            print(f"🎯 最佳登录提交页: {best_submit['url']} (评分: {best_submit['score']})")

            # 尝试找到对应的登录页面
            login_page = self._find_corresponding_login_page(domain, best_submit)
            if login_page:
                print(f"🔍 找到对应的登录页面: {login_page}")
                return login_page
            else:
                # 如果找不到登录页面，返回登录提交页的URL（去掉参数）
                submit_url = best_submit['url'].split('?')[0]
                print(f"⚠️  未找到登录页面，使用登录提交页: {submit_url}")
                return submit_url

        if login_candidates:
            # 选择得分最高的登录URL
            best_candidate = max(login_candidates, key=lambda x: x['score'])
            print(f"🔍 通过上下文分析找到登录URL: {best_candidate['url']}")
            return best_candidate['url']

        # 🎯 如果没有找到登录提交页，使用全量流数据分析
        print(f"⚠️  特征库未识别到登录提交页，启用全量流数据分析...")
        discovered_submit = self._discover_login_submit_by_behavior(domain)
        if discovered_submit:
            print(f"🎯 通过行为分析发现登录提交页: {discovered_submit['url']} (评分: {discovered_submit['score']})")

            # 尝试找到对应的登录页面
            login_page = self._find_corresponding_login_page(domain, discovered_submit)
            if login_page:
                print(f"🔍 找到对应的登录页面: {login_page}")
                return login_page
            else:
                # 返回登录提交页的URL（去掉参数）
                submit_url = discovered_submit['url'].split('?')[0]
                print(f"⚠️  未找到登录页面，使用登录提交页: {submit_url}")
                return submit_url

        return None

    def _discover_login_submit_by_behavior(self, domain: str) -> Optional[Dict]:
        """通过行为特征发现登录提交页（绕过特征库限制）

        Args:
            domain: 目标域名

        Returns:
            Optional[Dict]: 发现的登录提交页信息
        """
        if not hasattr(self, 'flow_data_map'):
            return None

        candidates = []

        # 🎯 遍历所有流数据，寻找登录提交的行为特征
        for url, flow_data in self.flow_data_map.items():
            # 必须是同域名
            if domain not in url:
                continue

            # 🎯 核心算法：POST + 认证字段 = 登录提交
            method = flow_data.get('method', '').upper()
            if method != 'POST':
                continue

            # 检查请求体是否包含认证字段
            request_body = flow_data.get('request_body', '')
            if not request_body:
                continue

            # 处理bytes类型
            if isinstance(request_body, bytes):
                try:
                    request_body = request_body.decode('utf-8', errors='ignore')
                except:
                    request_body = str(request_body)

            request_body_lower = request_body.lower()

            # 🎯 检测认证字段（更全面的关键字）
            auth_indicators = [
                'loginid', 'userid', 'username', 'user', 'login',
                'password', 'passwd', 'pwd', 'pass',
                'vercode', 'captcha', 'verify'
            ]

            auth_field_count = 0
            for indicator in auth_indicators:
                if indicator in request_body_lower:
                    auth_field_count += 1

            # 至少包含2个认证相关字段才认为是登录提交
            if auth_field_count >= 2:
                score = self._score_login_submit_api(url, flow_data)
                candidates.append({
                    'url': url,
                    'score': score,
                    'auth_field_count': auth_field_count,
                    'flow_data': flow_data
                })
                print(f"🔍 发现登录提交候选: {url} (认证字段: {auth_field_count}, 评分: {score})")

        if candidates:
            # 选择评分最高的候选
            best_candidate = max(candidates, key=lambda x: x['score'])
            return best_candidate

        return None

    def _score_login_url(self, url: str) -> int:
        """为登录URL打分，用于选择最佳候选

        Args:
            url: 登录URL

        Returns:
            int: 得分（越高越好）
        """
        score = 0
        url_lower = url.lower()

        # 明确的登录关键字得分更高
        if 'logon' in url_lower:
            score += 10
        elif 'login' in url_lower:
            score += 8
        elif 'lgn' in url_lower:  # 中银香港的缩写
            score += 9
        elif 'signin' in url_lower:
            score += 6
        elif 'auth' in url_lower:
            score += 4
        elif 'default' in url_lower and any(x in url_lower for x in ['lgn', 'login']):
            score += 7  # lgn.default.do 这种模式

        # 特定的登录文件扩展名
        if url_lower.endswith('.do'):  # 中银香港使用的Struts框架
            score += 5
        elif 'servlet' in url_lower:  # 永隆银行使用的Servlet
            score += 5
        elif url_lower.endswith('.jsp'):  # JSP页面
            score += 3

        # 路径特征
        if '/lgn/' in url_lower or '/login/' in url_lower:
            score += 4

        # 路径越短通常越是主要登录入口
        path_segments = url.split('/')
        if len(path_segments) <= 5:
            score += 3
        elif len(path_segments) <= 3:
            score += 5  # 非常短的路径，可能是主入口

        # 避免明显的非登录URL
        if any(exclude in url_lower for exclude in ['overview', 'balance', 'account', 'transaction']):
            score -= 5

        return score

    def _score_login_submit_api(self, url: str, flow_data: Dict[str, Any]) -> int:
        """评分登录提交页API（第一优先级）

        Args:
            url: API URL
            flow_data: 流数据

        Returns:
            int: 登录提交页评分
        """
        score = 0
        url_lower = url.lower()

        # 🎯 URL关键字评分
        submit_keywords = ['login', 'logon', 'authenticate', 'signin', 'submit', 'dologin']
        for keyword in submit_keywords:
            if keyword in url_lower:
                score += 10
                break

        # 🎯 HTTP方法评分（POST通常是提交）
        method = flow_data.get('method', '').upper()
        if method == 'POST':
            score += 15

        # 🎯 请求体分析（包含认证信息）
        request_body = flow_data.get('request_body', '')
        if request_body:
            if isinstance(request_body, bytes):
                try:
                    request_body = request_body.decode('utf-8', errors='ignore')
                except:
                    request_body = str(request_body)

            auth_fields = ['username', 'password', 'userid', 'pwd', 'user', 'pass']
            for field in auth_fields:
                if field in request_body.lower():
                    score += 20  # 包含认证字段，很可能是登录提交
                    break

        # 🎯 响应头分析（设置认证信息）
        response_headers = flow_data.get('response_headers', {})
        set_cookie = response_headers.get('Set-Cookie', '')
        if isinstance(set_cookie, list):
            set_cookie = '; '.join(set_cookie) if set_cookie else ''

        if set_cookie:
            auth_cookie_keywords = ['session', 'jsessionid', 'token', 'auth']
            for keyword in auth_cookie_keywords:
                if keyword.lower() in set_cookie.lower():
                    score += 15
                    break

        # 🎯 响应内容分析（简短关键字）
        response_body = flow_data.get('response_body', '')
        if response_body:
            if isinstance(response_body, bytes):
                try:
                    response_body = response_body.decode('utf-8', errors='ignore')
                except:
                    response_body = str(response_body)

            response_lower = response_body.lower()
            auth_response_keywords = ['token', 'authority', 'code', 'session', 'redirect', 'success']
            for keyword in auth_response_keywords:
                if keyword in response_lower:
                    score += 8

        # 🎯 状态码分析
        status_code = flow_data.get('status_code', 0)
        if status_code in [302, 301]:  # 重定向，可能是登录成功
            score += 10
        elif status_code == 200:
            score += 5

        return score

    def _score_login_api_by_flow_data(self, url: str, flow_data: Dict[str, Any]) -> int:
        """基于实际的请求/应答流数据来评分登录API

        Args:
            url: API URL
            flow_data: 流数据（包含请求和应答信息）

        Returns:
            int: 得分（越高越好）
        """
        score = 0

        # 基础URL评分
        url_lower = url.lower()
        if 'lgn' in url_lower:
            score += 5
        elif 'login' in url_lower or 'logon' in url_lower:
            score += 3

        # 🎯 请求特征分析
        method = flow_data.get('method', '').upper()
        request_headers = flow_data.get('request_headers', {})
        request_body = flow_data.get('request_body', '')

        # POST方法通常是登录提交
        if method == 'POST':
            score += 10
        elif method == 'GET':
            score += 2  # 可能是登录页面

        # 请求体特征
        if request_body:
            # 处理bytes类型的请求体
            if isinstance(request_body, bytes):
                try:
                    request_body = request_body.decode('utf-8', errors='ignore')
                except:
                    request_body = str(request_body)
            request_body_lower = str(request_body).lower()

            # 检查是否包含登录相关字段
            login_fields = ['username', 'password', 'userid', 'pwd', 'user', 'pass', 'account']
            for field in login_fields:
                if field in request_body_lower:
                    score += 8
                    break

        # Content-Type检查
        content_type = request_headers.get('Content-Type', '')
        if isinstance(content_type, list):
            content_type = content_type[0] if content_type else ''
        content_type = str(content_type).lower()

        if 'application/x-www-form-urlencoded' in content_type:
            score += 5  # 表单提交
        elif 'application/json' in content_type:
            score += 3  # JSON提交

        # 🎯 应答特征分析
        response_headers = flow_data.get('response_headers', {})
        response_body = flow_data.get('response_body', '')
        status_code = flow_data.get('status_code', 0)

        # 状态码分析
        if status_code == 302 or status_code == 301:
            score += 8  # 重定向，可能是登录成功后跳转
        elif status_code == 200:
            score += 5  # 正常响应
        elif status_code >= 400:
            score -= 5  # 错误响应，可能不是真正的登录API

        # 检查Set-Cookie头（登录通常会设置session cookie）
        set_cookie = response_headers.get('Set-Cookie', '')
        if isinstance(set_cookie, list):
            set_cookie = '; '.join(set_cookie) if set_cookie else ''
        set_cookie = str(set_cookie)

        if set_cookie:
            cookie_lower = set_cookie.lower()
            if any(keyword in cookie_lower for keyword in ['session', 'jsessionid', 'token', 'auth']):
                score += 10
            else:
                score += 3  # 任何cookie都可能是登录相关

        # 检查Location头（重定向目标）
        location = response_headers.get('Location', '')
        if isinstance(location, list):
            location = location[0] if location else ''
        location = str(location)

        if location:
            location_lower = location.lower()
            if any(keyword in location_lower for keyword in ['main', 'home', 'index', 'welcome', 'dashboard']):
                score += 8  # 重定向到主页，很可能是登录成功

        # 🎯 应答内容分析
        if response_body:
            # 处理bytes类型的响应体
            if isinstance(response_body, bytes):
                try:
                    response_body = response_body.decode('utf-8', errors='ignore')
                except:
                    response_body = str(response_body)
            response_body_lower = str(response_body).lower()

            # 检查是否包含登录成功的标识
            success_indicators = ['welcome', 'dashboard', 'logout', 'account', 'balance']
            for indicator in success_indicators:
                if indicator in response_body_lower:
                    score += 5
                    break

            # 检查是否包含错误信息（可能是登录失败）
            error_indicators = ['error', 'invalid', 'incorrect', 'failed', 'wrong']
            for indicator in error_indicators:
                if indicator in response_body_lower:
                    score += 3  # 有错误信息也说明是登录API
                    break

        print(f"🔍 登录API评分 {url}: {score}分")
        return score

    def _find_corresponding_login_page(self, domain: str, submit_api: Dict) -> Optional[str]:
        """基于登录提交页找到对应的登录页面

        Args:
            domain: 目标域名
            submit_api: 登录提交页信息

        Returns:
            Optional[str]: 找到的登录页面URL
        """
        if not hasattr(self, 'analysis_data') or not self.analysis_data:
            return None

        extracted_data = self.analysis_data.get('extracted_data', [])
        submit_url = submit_api['url']

        # 🎯 查找候选的登录页面
        page_candidates = []

        for api_data in extracted_data:
            api_url = api_data.get('url', '')

            # 必须是同域名
            if domain not in api_url:
                continue

            # 🎯 简单的登录页面关键字匹配（尽量短，提高成功率）
            url_lower = api_url.lower()
            page_keywords = ['login', 'logon', 'signin']

            has_page_keyword = any(keyword in url_lower for keyword in page_keywords)
            if not has_page_keyword:
                continue

            # 🎯 排除明显的提交页面
            if any(exclude in url_lower for exclude in ['servlet', 'submit', 'authenticate']):
                continue

            # 🎯 优先选择页面文件
            page_score = 0
            if any(ext in url_lower for ext in ['.jsp', '.html', '.htm', '.php']):
                page_score += 10
            elif url_lower.endswith('/login') or url_lower.endswith('/logon'):
                page_score += 8

            # 🎯 URL相似度评分
            similarity_score = self._calculate_url_similarity(submit_url, api_url)
            page_score += similarity_score

            if page_score > 5:  # 基本门槛
                page_candidates.append({
                    'url': api_url,
                    'score': page_score
                })

        if page_candidates:
            # 选择评分最高的登录页面
            best_page = max(page_candidates, key=lambda x: x['score'])
            return best_page['url']

        return None

    def _calculate_url_similarity(self, url1: str, url2: str) -> int:
        """计算两个URL的相似度评分

        Args:
            url1: URL1
            url2: URL2

        Returns:
            int: 相似度评分
        """
        from urllib.parse import urlparse

        parsed1 = urlparse(url1)
        parsed2 = urlparse(url2)

        score = 0

        # 域名必须相同（已在上层检查）
        if parsed1.netloc == parsed2.netloc:
            score += 5

        # 路径相似度
        path1_parts = parsed1.path.strip('/').split('/')
        path2_parts = parsed2.path.strip('/').split('/')

        # 共同的路径段
        common_parts = set(path1_parts) & set(path2_parts)
        if common_parts:
            score += len(common_parts) * 2

        # 路径长度相似
        if abs(len(path1_parts) - len(path2_parts)) <= 1:
            score += 3

        return score

    def extract_geo_location(self, flow_data: Dict[str, Any]) -> str:
        """提取地理位置"""
        # 根据域名推断地理位置
        url = flow_data['url']

        if '.hk' in url or 'hong' in url.lower():
            return "HK"
        elif '.cn' in url or 'china' in url.lower():
            return "CN"
        elif '.in' in url or 'india' in url.lower():
            return "IN"
        else:
            return "US"  # 默认

    def classify_api_type(self, url: str, response_content: str) -> str:
        """分类API类型"""
        url_lower = url.lower()
        content_lower = response_content.lower()

        if 'account' in url_lower or 'acc' in url_lower:
            return "account_management"
        elif 'transaction' in url_lower or 'txn' in url_lower:
            return "transaction_history"
        elif 'balance' in url_lower or 'balance' in content_lower:
            return "balance_inquiry"
        elif 'login' in url_lower or 'logon' in url_lower:
            return "authentication"
        else:
            return "general_banking"

    def extract_response_variables(self, response_matches: List[Dict], response_redactions: List[Dict]) -> List[str]:
        """提取响应变量"""
        variables = set()

        # 从responseMatches中提取变量
        for match in response_matches:
            value = match.get('value', '')
            # 查找{{variable}}模式
            var_matches = re.findall(r'\{\{(\w+)\}\}', value)
            variables.update(var_matches)

        # 从responseRedactions中提取变量
        for redaction in response_redactions:
            json_path = redaction.get('jsonPath', '')
            regex = redaction.get('regex', '')

            # 查找变量模式
            var_matches = re.findall(r'\{\{(\w+)\}\}', json_path + regex)
            variables.update(var_matches)

        return list(variables)

    def _is_sensitive_field(self, field_name: str) -> bool:
        """判断字段是否为敏感字段，需要哈希处理

        Args:
            field_name: 字段名

        Returns:
            bool: 是否为敏感字段
        """
        sensitive_keywords = [
            'account', 'password', 'token', 'id', 'number', 'card',
            'phone', 'email', 'name', 'address', '账号', '密码', '姓名'
        ]
        field_lower = field_name.lower()
        return any(keyword in field_lower for keyword in sensitive_keywords)

    def generate_custom_injection(self, api_data: Dict[str, Any], flow_data: Dict[str, Any]) -> str:
        """生成自定义注入代码"""
        # 预处理变量以避免f-string语法问题
        institution = api_data.get('institution', 'Unknown')
        url = flow_data['url']
        method = flow_data['method']
        timestamp = datetime.now().isoformat()

        important_headers = self.filter_important_headers(flow_data['request_headers'])
        headers_json = json.dumps(important_headers, indent=16)
        headers_json_compact = json.dumps(important_headers, indent=12)
        geo_location = self.extract_geo_location(flow_data)

        # 基础的注入模板
        injection_template = f"""
// Auto-generated injection for {institution} API
// API: {url}
// Generated at: {timestamp}

const extractData = async () => {{
    try {{
        const response = await fetch("{url}", {{
            method: "{method}",
            headers: {headers_json},
            credentials: "include",
            mode: "cors"
        }});

        if (!response.ok) {{
            throw new Error(`HTTP error! status: ${{response.status}}`);
        }}

        const data = await response.json();

        // Extract relevant data based on response patterns
        const extractedData = {{
            url: "{url}",
            method: "{method}",
            headers: {headers_json_compact},
            responseBody: data,
            extractedParams: {{}},
            geoLocation: "{geo_location}",
            responseRedactions: [],
            responseMatches: [],
            witnessParameters: {{}}
        }};

        // Send extracted data
        if (window.flutter_inappwebview) {{
            window.flutter_inappwebview.callHandler("extractedData", JSON.stringify(extractedData));
        }}

    }} catch (error) {{
        console.error('Data extraction failed:', error);
    }}
}};

// Auto-trigger extraction when page is ready
if (document.readyState === 'loading') {{
    document.addEventListener('DOMContentLoaded', extractData);
}} else {{
    extractData();
}}
"""

        return injection_template.strip()

    def build_all_providers(self) -> Tuple[List[Dict], List[Dict]]:
        """构建所有API的provider配置

        Returns:
            Tuple[List[Dict], List[Dict]]: (成功的providers, 存疑的APIs)
        """
        print("🚀 开始构建Reclaim Providers...")

        successful_providers = []
        questionable_apis = []

        # 获取分析结果中的API数据
        extracted_data = self.analysis_data.get('extracted_data', [])

        print(f"📊 共发现 {len(extracted_data)} 个有价值的API")

        # 🎯 新增：用于去重的字典，key为URL，value为最佳的API数据
        best_apis_by_url = {}

        # 🎯 第一步：收集所有值得构建provider的API，并选择最佳版本
        print("🔍 第一步：API去重和最佳版本选择...")

        for i, api_data in enumerate(extracted_data, 1):
            api_category = api_data.get('api_category', 'unknown')
            provider_worthy = api_data.get('provider_worthy', False)

            if not provider_worthy:
                questionable_api = {
                    'api_data': api_data,
                    'reason': f'API分类为{api_category}，不适合生成provider',
                    'api_category': api_category,
                    'confidence_score': 0.0
                }
                questionable_apis.append(questionable_api)
                continue

            url = api_data['url']

            # 🎯 去重逻辑：选择最佳版本
            if url in best_apis_by_url:
                current_best = best_apis_by_url[url]
                if self._is_better_api_version(api_data, current_best):
                    print(f"🔄 发现更佳版本: {url[:60]}...")
                    print(f"   替换版本: {len(current_best.get('matched_patterns', []))}模式 → {len(api_data.get('matched_patterns', []))}模式")
                    best_apis_by_url[url] = api_data
                else:
                    print(f"⚠️  跳过重复API (已有更佳版本): {url[:60]}...")
            else:
                best_apis_by_url[url] = api_data

        print(f"📊 去重后剩余 {len(best_apis_by_url)} 个唯一API")

        # 🎯 第二步：为选中的最佳API构建provider
        print("🔍 第二步：构建providers...")

        for i, (url, api_data) in enumerate(best_apis_by_url.items(), 1):
            print(f"\n🔍 处理API {i}/{len(best_apis_by_url)}: {api_data['url']}")

            try:
                provider_config, quality_check = self.build_provider_for_api(api_data)

                if provider_config:
                    successful_providers.append(provider_config)
                    print(f"✅ 成功构建provider (置信度: {quality_check.confidence_score:.2f})")
                else:
                    # 添加到存疑列表
                    questionable_api = {
                        'api_data': api_data,
                        'quality_check': asdict(quality_check) if quality_check else None,
                        'reason': '质量检查未通过',
                        'missing_fields': quality_check.missing_fields if quality_check else ['unknown'],
                        'confidence_score': quality_check.confidence_score if quality_check else 0.0
                    }
                    questionable_apis.append(questionable_api)
                    print(f"⚠️  添加到存疑列表 (置信度: {quality_check.confidence_score if quality_check else 0:.2f})")

            except Exception as e:
                print(f"❌ 处理失败: {e}")
                questionable_api = {
                    'api_data': api_data,
                    'quality_check': None,
                    'reason': f'处理异常: {str(e)}',
                    'missing_fields': ['processing_error'],
                    'confidence_score': 0.0
                }
                questionable_apis.append(questionable_api)

        print(f"\n📈 构建完成:")
        print(f"   ✅ 成功构建: {len(successful_providers)} 个providers")
        print(f"   ⚠️  存疑API: {len(questionable_apis)} 个")

        return successful_providers, questionable_apis

    def _is_better_api_version(self, new_api: Dict, current_best: Dict) -> bool:
        """判断新的API版本是否比当前最佳版本更好

        Args:
            new_api: 新的API数据
            current_best: 当前最佳API数据

        Returns:
            bool: 新版本是否更好
        """
        # 🎯 评判标准（按优先级排序）

        # 1. 匹配模式数量（更多模式 = 更丰富的特征）
        new_patterns = len(new_api.get('matched_patterns', []))
        current_patterns = len(current_best.get('matched_patterns', []))

        if new_patterns != current_patterns:
            return new_patterns > current_patterns

        # 2. 价值评分（更高评分 = 更有价值）
        new_score = new_api.get('value_score', 0)
        current_score = current_best.get('value_score', 0)

        if new_score != current_score:
            return new_score > current_score

        # 3. 数据类型数量（更多数据类型 = 更丰富的内容）
        new_data_types = len(new_api.get('data_types', []))
        current_data_types = len(current_best.get('data_types', []))

        if new_data_types != current_data_types:
            return new_data_types > current_data_types

        # 4. 优先级级别（critical > high > medium > low）
        priority_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unknown': 0}
        new_priority = priority_order.get(new_api.get('priority_level', 'unknown'), 0)
        current_priority = priority_order.get(current_best.get('priority_level', 'unknown'), 0)

        if new_priority != current_priority:
            return new_priority > current_priority

        # 5. 如果所有指标都相同，保持当前版本（先到先得）
        return False

    def save_results(self, successful_providers: List[Dict], questionable_apis: List[Dict],
                    output_dir: str = "data") -> Tuple[str, str]:
        """保存构建结果

        Args:
            successful_providers: 成功的providers
            questionable_apis: 存疑的APIs
            output_dir: 输出目录

        Returns:
            Tuple[str, str]: (providers文件路径, 存疑文件路径)
        """
        # 确保输出目录存在
        os.makedirs(output_dir, exist_ok=True)

        # 使用日期作为文件名后缀（覆盖写）
        date_str = datetime.now().strftime("%Y%m%d")

        # 保存成功的providers
        providers_file = os.path.join(output_dir, f"reclaim_providers_{date_str}.json")
        providers_output = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_providers": len(successful_providers),
                "source_mitm_file": self.mitm_file_path,
                "source_analysis_file": self.analysis_result_file,
                "generator_version": "1.0.0"
            },
            "providers": successful_providers
        }

        with open(providers_file, 'w', encoding='utf-8') as f:
            json.dump(providers_output, f, indent=2, ensure_ascii=False)

        # 保存存疑的APIs
        questionable_file = os.path.join(output_dir, f"questionable_apis_{date_str}.json")
        questionable_output = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_questionable": len(questionable_apis),
                "reasons_summary": self.analyze_questionable_reasons(questionable_apis),
                "source_mitm_file": self.mitm_file_path,
                "source_analysis_file": self.analysis_result_file
            },
            "questionable_apis": questionable_apis
        }

        with open(questionable_file, 'w', encoding='utf-8') as f:
            json.dump(questionable_output, f, indent=2, ensure_ascii=False)

        return providers_file, questionable_file

    def analyze_questionable_reasons(self, questionable_apis: List[Dict]) -> Dict[str, int]:
        """分析存疑API的原因统计"""
        reasons = {}

        for api in questionable_apis:
            missing_fields = api.get('missing_fields', [])
            for field in missing_fields:
                reasons[field] = reasons.get(field, 0) + 1

        return reasons


def run_integration_and_build_providers(mitm_file: str, output_dir: str = "data") -> Tuple[str, str, str]:
    """运行完整的集成流程：分析 + 构建providers

    Args:
        mitm_file: mitm文件路径
        output_dir: 输出目录

    Returns:
        Tuple[str, str, str]: (分析结果文件, providers文件, 存疑文件)
    """
    print("🚀 开始完整的Provider构建流程...")

    # 第一步：运行integrate_with_mitmproxy2swagger.py进行分析
    print("\n📊 第一步：运行特征库分析...")

    import subprocess
    import sys

    # 构建固定的分析结果文件名
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    analysis_result_file = os.path.join(output_dir, f"provider_analysis_result_{timestamp}.json")

    # 运行分析脚本
    script_dir = Path(__file__).parent.parent / "feature-library" / "plugins"
    cmd = [
        sys.executable,
        str(script_dir / "integrate_with_mitmproxy2swagger.py"),
        "--mode", "direct",
        "--input", mitm_file,
        "--output", analysis_result_file
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print("✅ 特征库分析完成")
    except subprocess.CalledProcessError as e:
        print(f"❌ 特征库分析失败: {e}")
        print(f"错误输出: {e.stderr}")
        raise

    # 第二步：构建providers
    print("\n🏗️  第二步：构建Reclaim Providers...")

    builder = ReclaimProviderBuilder(mitm_file, analysis_result_file)
    successful_providers, questionable_apis = builder.build_all_providers()

    # 第三步：保存结果
    print("\n💾 第三步：保存构建结果...")

    providers_file, questionable_file = builder.save_results(
        successful_providers, questionable_apis, output_dir
    )

    print(f"\n🎉 完整流程完成!")
    print(f"📁 分析结果: {analysis_result_file}")
    print(f"📁 Providers: {providers_file}")
    print(f"📁 存疑APIs: {questionable_file}")

    return analysis_result_file, providers_file, questionable_file


def main():
    """命令行接口"""
    import argparse

    parser = argparse.ArgumentParser(description='Reclaim Provider构建器')
    parser.add_argument('--mitm-file', '-i', required=True, help='输入的mitm文件路径')
    parser.add_argument('--analysis-file', '-a', help='特征库分析结果文件路径（可选，如果不提供会自动运行分析）')
    parser.add_argument('--output-dir', '-o', default='data', help='输出目录')
    parser.add_argument('--run-full-pipeline', '-f', action='store_true',
                       help='运行完整流程（分析+构建）')

    args = parser.parse_args()

    try:
        if args.run_full_pipeline or not args.analysis_file:
            # 运行完整流程
            analysis_file, providers_file, questionable_file = run_integration_and_build_providers(
                args.mitm_file, args.output_dir
            )
        else:
            # 只构建providers
            print("🏗️  构建Reclaim Providers...")

            builder = ReclaimProviderBuilder(args.mitm_file, args.analysis_file)
            successful_providers, questionable_apis = builder.build_all_providers()

            providers_file, questionable_file = builder.save_results(
                successful_providers, questionable_apis, args.output_dir
            )

            print(f"\n🎉 构建完成!")
            print(f"📁 Providers: {providers_file}")
            print(f"📁 存疑APIs: {questionable_file}")

    except Exception as e:
        print(f"❌ 构建失败: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
