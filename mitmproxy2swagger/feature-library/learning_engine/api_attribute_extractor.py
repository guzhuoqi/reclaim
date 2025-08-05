#!/usr/bin/env python3
"""
API属性提取器
API Attribute Extractor

对学习到的金融API进行深度属性提取，包括请求特征、响应特征、业务特征等，
并将提取的属性补充到特征库的指定位置，增强特征库的识别能力。

核心功能：
1. 请求属性提取 - URL模式、参数模式、HTTP方法、请求头特征
2. 响应属性提取 - 数据结构、字段模式、数据类型、业务指标
3. 业务属性提取 - API类别、业务流程、数据敏感度、价值评估
4. 特征库更新 - 将提取的属性补充到特征库的对应位置
5. 质量验证 - 确保新属性的准确性和一致性
"""

import json
import re
import sys
import logging
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from collections import defaultdict, Counter
import difflib

# 添加路径以导入现有模块
sys.path.append('mitmproxy2swagger/mitmproxy2swagger')
sys.path.append('mitmproxy2swagger/feature-library/ai_analysis_features')


@dataclass
class RequestAttributes:
    """请求属性"""
    url_pattern: str
    path_segments: List[str]
    query_parameters: Dict[str, str]
    http_method: str
    content_type: str
    authentication_headers: List[str]
    session_indicators: List[str]
    api_version: Optional[str] = None
    endpoint_category: Optional[str] = None


@dataclass
class ResponseAttributes:
    """响应属性"""
    content_type: str
    data_structure: str  # json_object, json_array, html, xml, text
    json_schema: Dict[str, Any]
    field_patterns: List[str]
    data_types: List[str]
    financial_indicators: List[str]
    sensitive_fields: List[str]
    pagination_indicators: List[str]
    error_patterns: List[str]


@dataclass
class BusinessAttributes:
    """业务属性"""
    api_category: str  # account, transaction, authentication, portfolio, etc.
    business_function: str  # query, update, create, delete
    data_sensitivity: str  # public, internal, confidential, restricted
    value_score: float
    priority_level: str  # low, medium, high, critical
    compliance_indicators: List[str]
    risk_level: str  # low, medium, high
    integration_complexity: str  # simple, medium, complex


@dataclass
class ExtractedAPIAttributes:
    """完整的API属性"""
    url: str
    institution: str
    request_attrs: RequestAttributes
    response_attrs: ResponseAttributes
    business_attrs: BusinessAttributes
    extraction_confidence: float
    extraction_timestamp: str


class APIAttributeExtractor:
    """API属性提取器"""

    def __init__(self, feature_library_path: str = None):
        """初始化属性提取器"""
        self.logger = logging.getLogger(__name__)

        # 加载特征库
        if feature_library_path is None:
            feature_library_path = 'mitmproxy2swagger/feature-library/ai_analysis_features/financial_api_features.json'

        self.feature_library_path = feature_library_path
        self.feature_library = self._load_feature_library()

        # 初始化提取规则
        self._init_extraction_rules()

    def _load_feature_library(self) -> Dict[str, Any]:
        """加载特征库"""
        try:
            with open(self.feature_library_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"加载特征库失败: {e}")
            return {}

    def _init_extraction_rules(self):
        """初始化提取规则"""
        # 金融业务类别模式
        self.business_category_patterns = {
            'account': [
                r'account', r'acc\b', r'balance', r'overview', r'summary',
                r'portfolio', r'wealth', r'asset', r'deposit', r'saving'
            ],
            'transaction': [
                r'transaction', r'txn', r'transfer', r'payment', r'history',
                r'statement', r'movement', r'activity', r'record'
            ],
            'authentication': [
                r'login', r'auth', r'authenticate', r'signin', r'logon',
                r'verify', r'token', r'session', r'otp', r'security'
            ],
            'investment': [
                r'investment', r'trading', r'stock', r'bond', r'fund',
                r'mutual', r'etf', r'portfolio', r'market', r'quote'
            ],
            'loan': [
                r'loan', r'credit', r'mortgage', r'lending', r'borrow',
                r'installment', r'repayment', r'interest'
            ],
            'card': [
                r'card', r'credit.*card', r'debit.*card', r'atm',
                r'pos', r'merchant', r'cashback'
            ]
        }

        # 金融数据字段模式
        self.financial_field_patterns = {
            'balance': [
                r'balance', r'amount', r'total', r'available', r'current',
                r'outstanding', r'limit', r'credit.*limit'
            ],
            'currency': [
                r'currency', r'ccy', r'curr', r'hkd', r'usd', r'cny', r'eur',
                r'gbp', r'jpy', r'aud', r'cad', r'sgd'
            ],
            'account_info': [
                r'account.*number', r'account.*id', r'iban', r'swift',
                r'routing.*number', r'sort.*code', r'bsb'
            ],
            'personal_info': [
                r'customer.*name', r'first.*name', r'last.*name', r'email',
                r'phone', r'address', r'ssn', r'id.*number'
            ],
            'transaction_info': [
                r'transaction.*id', r'reference', r'description', r'memo',
                r'merchant', r'category', r'date', r'time'
            ]
        }

        # 敏感度评估规则
        self.sensitivity_rules = {
            'restricted': [
                r'password', r'pin', r'ssn', r'tax.*id', r'account.*number',
                r'card.*number', r'cvv', r'security.*code'
            ],
            'confidential': [
                r'balance', r'salary', r'income', r'credit.*score',
                r'transaction.*history', r'investment.*portfolio'
            ],
            'internal': [
                r'customer.*id', r'session.*id', r'token', r'api.*key',
                r'user.*profile', r'preferences'
            ],
            'public': [
                r'exchange.*rate', r'interest.*rate', r'market.*data',
                r'branch.*location', r'contact.*info'
            ]
        }

    def extract_request_attributes(self, url: str, method: str, headers: Dict[str, str],
                                 body: str) -> RequestAttributes:
        """提取请求属性"""
        parsed_url = urlparse(url)

        # URL模式提取
        url_pattern = self._extract_url_pattern(parsed_url.path)

        # 路径分段
        path_segments = [seg for seg in parsed_url.path.split('/') if seg]

        # 查询参数
        query_params = parse_qs(parsed_url.query)
        query_params_flat = {k: v[0] if v else '' for k, v in query_params.items()}

        # 认证头信息
        auth_headers = self._extract_auth_headers(headers)

        # 会话指标
        session_indicators = self._extract_session_indicators(url, headers)

        # API版本
        api_version = self._extract_api_version(url, headers)

        # 端点类别
        endpoint_category = self._classify_endpoint(url, method)

        return RequestAttributes(
            url_pattern=url_pattern,
            path_segments=path_segments,
            query_parameters=query_params_flat,
            http_method=method,
            content_type=headers.get('Content-Type', ''),
            authentication_headers=auth_headers,
            session_indicators=session_indicators,
            api_version=api_version,
            endpoint_category=endpoint_category
        )

    def extract_response_attributes(self, content: str, headers: Dict[str, str]) -> ResponseAttributes:
        """提取响应属性"""
        content_type = headers.get('Content-Type', '')

        # 数据结构识别
        data_structure = self._identify_data_structure(content)

        # JSON模式提取
        json_schema = {}
        if data_structure.startswith('json'):
            json_schema = self._extract_json_schema(content)

        # 字段模式
        field_patterns = self._extract_field_patterns(content, data_structure)

        # 数据类型
        data_types = self._identify_data_types(content, field_patterns)

        # 金融指标
        financial_indicators = self._extract_financial_indicators(content)

        # 敏感字段
        sensitive_fields = self._identify_sensitive_fields(content)

        # 分页指标
        pagination_indicators = self._extract_pagination_indicators(content)

        # 错误模式
        error_patterns = self._extract_error_patterns(content)

        return ResponseAttributes(
            content_type=content_type,
            data_structure=data_structure,
            json_schema=json_schema,
            field_patterns=field_patterns,
            data_types=data_types,
            financial_indicators=financial_indicators,
            sensitive_fields=sensitive_fields,
            pagination_indicators=pagination_indicators,
            error_patterns=error_patterns
        )

    def extract_business_attributes(self, url: str, request_attrs: RequestAttributes,
                                  response_attrs: ResponseAttributes) -> BusinessAttributes:
        """提取业务属性"""
        # API类别
        api_category = self._classify_api_category(url, request_attrs, response_attrs)

        # 业务功能
        business_function = self._identify_business_function(request_attrs.http_method, url)

        # 数据敏感度
        data_sensitivity = self._assess_data_sensitivity(response_attrs.sensitive_fields,
                                                       response_attrs.financial_indicators)

        # 价值评分
        value_score = self._calculate_value_score(api_category, response_attrs.financial_indicators,
                                                request_attrs.authentication_headers)

        # 优先级等级
        priority_level = self._determine_priority_level(value_score, data_sensitivity)

        # 合规指标
        compliance_indicators = self._identify_compliance_indicators(response_attrs.sensitive_fields)

        # 风险等级
        risk_level = self._assess_risk_level(data_sensitivity, response_attrs.sensitive_fields)

        # 集成复杂度
        integration_complexity = self._assess_integration_complexity(request_attrs, response_attrs)

        return BusinessAttributes(
            api_category=api_category,
            business_function=business_function,
            data_sensitivity=data_sensitivity,
            value_score=value_score,
            priority_level=priority_level,
            compliance_indicators=compliance_indicators,
            risk_level=risk_level,
            integration_complexity=integration_complexity
        )

    def extract_complete_attributes(self, url: str, method: str, request_headers: Dict[str, str],
                                  request_body: str, response_content: str,
                                  response_headers: Dict[str, str], institution: str) -> ExtractedAPIAttributes:
        """提取完整的API属性"""
        try:
            # 提取各类属性
            request_attrs = self.extract_request_attributes(url, method, request_headers, request_body)
            response_attrs = self.extract_response_attributes(response_content, response_headers)
            business_attrs = self.extract_business_attributes(url, request_attrs, response_attrs)

            # 计算提取置信度
            confidence = self._calculate_extraction_confidence(request_attrs, response_attrs, business_attrs)

            return ExtractedAPIAttributes(
                url=url,
                institution=institution,
                request_attrs=request_attrs,
                response_attrs=response_attrs,
                business_attrs=business_attrs,
                extraction_confidence=confidence,
                extraction_timestamp=datetime.now().isoformat()
            )

        except Exception as e:
            self.logger.error(f"属性提取失败 {url}: {e}")
            return None

    def _extract_url_pattern(self, path: str) -> str:
        """提取URL模式"""
        # 替换数字为占位符
        pattern = re.sub(r'\d+', '{id}', path)
        # 替换UUID为占位符
        pattern = re.sub(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '{uuid}', pattern)
        # 替换长字符串为占位符
        pattern = re.sub(r'[a-zA-Z0-9]{20,}', '{token}', pattern)
        return pattern

    def _extract_auth_headers(self, headers: Dict[str, str]) -> List[str]:
        """提取认证头信息"""
        auth_headers = []
        auth_keywords = ['authorization', 'cookie', 'token', 'session', 'x-auth', 'x-api-key']

        for header, value in headers.items():
            if any(keyword in header.lower() for keyword in auth_keywords):
                auth_headers.append(header)

        return auth_headers

    def _extract_session_indicators(self, url: str, headers: Dict[str, str]) -> List[str]:
        """提取会话指标"""
        indicators = []

        # URL中的会话参数
        session_params = ['sessionid', 'session_id', 'jsessionid', 'sid', 'token']
        for param in session_params:
            if param in url.lower():
                indicators.append(f'url:{param}')

        # 头信息中的会话指标
        for header, value in headers.items():
            if 'session' in header.lower() or 'cookie' in header.lower():
                indicators.append(f'header:{header}')

        return indicators

    def _extract_api_version(self, url: str, headers: Dict[str, str]) -> Optional[str]:
        """提取API版本"""
        # URL中的版本
        version_match = re.search(r'/v(\d+(?:\.\d+)?)', url)
        if version_match:
            return version_match.group(1)

        # 头信息中的版本
        for header, value in headers.items():
            if 'version' in header.lower():
                return value

        return None

    def _classify_endpoint(self, url: str, method: str) -> Optional[str]:
        """分类端点类别"""
        url_lower = url.lower()

        for category, patterns in self.business_category_patterns.items():
            for pattern in patterns:
                if re.search(pattern, url_lower):
                    return category

        return None

    def _identify_data_structure(self, content: str) -> str:
        """识别数据结构"""
        if not content.strip():
            return 'empty'

        content_stripped = content.strip()

        if content_stripped.startswith('{'):
            return 'json_object'
        elif content_stripped.startswith('['):
            return 'json_array'
        elif content_stripped.startswith('<'):
            return 'xml' if '<?xml' in content_stripped else 'html'
        else:
            return 'text'

    def _extract_json_schema(self, content: str) -> Dict[str, Any]:
        """提取JSON模式"""
        try:
            data = json.loads(content)
            return self._analyze_json_structure(data)
        except:
            return {}

    def _analyze_json_structure(self, data: Any, max_depth: int = 3) -> Dict[str, Any]:
        """分析JSON结构"""
        if max_depth <= 0:
            return {'type': 'max_depth_reached'}

        if isinstance(data, dict):
            schema = {'type': 'object', 'properties': {}}
            for key, value in data.items():
                schema['properties'][key] = self._analyze_json_structure(value, max_depth - 1)
            return schema
        elif isinstance(data, list):
            schema = {'type': 'array'}
            if data:
                schema['items'] = self._analyze_json_structure(data[0], max_depth - 1)
            return schema
        elif isinstance(data, str):
            return {'type': 'string'}
        elif isinstance(data, (int, float)):
            return {'type': 'number'}
        elif isinstance(data, bool):
            return {'type': 'boolean'}
        else:
            return {'type': 'null'}

    def _extract_field_patterns(self, content: str, data_structure: str) -> List[str]:
        """提取字段模式"""
        patterns = []

        if data_structure.startswith('json'):
            try:
                data = json.loads(content)
                patterns.extend(self._extract_json_field_patterns(data))
            except:
                pass

        # 通用字段模式
        for category, field_patterns in self.financial_field_patterns.items():
            for pattern in field_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    patterns.append(f'{category}:{pattern}')

        return patterns

    def _extract_json_field_patterns(self, data: Any, prefix: str = '') -> List[str]:
        """提取JSON字段模式"""
        patterns = []

        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f'{prefix}.{key}' if prefix else key
                patterns.append(full_key)

                if isinstance(value, (dict, list)):
                    patterns.extend(self._extract_json_field_patterns(value, full_key))
        elif isinstance(data, list) and data:
            patterns.extend(self._extract_json_field_patterns(data[0], prefix))

        return patterns

    def _identify_data_types(self, content: str, field_patterns: List[str]) -> List[str]:
        """识别数据类型"""
        data_types = []

        # 基于字段模式推断数据类型
        for pattern in field_patterns:
            if any(keyword in pattern.lower() for keyword in ['balance', 'amount', 'total']):
                data_types.append('financial_amount')
            elif any(keyword in pattern.lower() for keyword in ['account', 'number', 'id']):
                data_types.append('account_identifier')
            elif any(keyword in pattern.lower() for keyword in ['name', 'customer']):
                data_types.append('personal_info')
            elif any(keyword in pattern.lower() for keyword in ['transaction', 'history']):
                data_types.append('transaction_data')

        return list(set(data_types))

    def _extract_financial_indicators(self, content: str) -> List[str]:
        """提取金融指标"""
        indicators = []
        content_lower = content.lower()

        # 货币指标
        currencies = ['hkd', 'usd', 'cny', 'eur', 'gbp', 'jpy', 'aud', 'cad', 'sgd']
        for currency in currencies:
            if currency in content_lower:
                indicators.append(f'currency:{currency}')

        # 金额模式
        amount_patterns = [
            r'\d+\.\d{2}',  # 小数金额
            r'\$\d+',       # 美元符号
            r'¥\d+',        # 人民币符号
            r'€\d+',        # 欧元符号
        ]

        for pattern in amount_patterns:
            if re.search(pattern, content):
                indicators.append(f'amount_pattern:{pattern}')

        # 金融术语
        financial_terms = ['balance', 'portfolio', 'investment', 'asset', 'liability', 'equity']
        for term in financial_terms:
            if term in content_lower:
                indicators.append(f'financial_term:{term}')

        return indicators

    def _identify_sensitive_fields(self, content: str) -> List[str]:
        """识别敏感字段"""
        sensitive_fields = []
        content_lower = content.lower()

        for sensitivity_level, patterns in self.sensitivity_rules.items():
            for pattern in patterns:
                if re.search(pattern, content_lower):
                    sensitive_fields.append(f'{sensitivity_level}:{pattern}')

        return sensitive_fields

    def _extract_pagination_indicators(self, content: str) -> List[str]:
        """提取分页指标"""
        indicators = []
        content_lower = content.lower()

        pagination_keywords = ['page', 'limit', 'offset', 'size', 'total', 'count', 'next', 'prev']
        for keyword in pagination_keywords:
            if keyword in content_lower:
                indicators.append(f'pagination:{keyword}')

        return indicators

    def _extract_error_patterns(self, content: str) -> List[str]:
        """提取错误模式"""
        patterns = []
        content_lower = content.lower()

        error_keywords = ['error', 'exception', 'fail', 'invalid', 'unauthorized', 'forbidden']
        for keyword in error_keywords:
            if keyword in content_lower:
                patterns.append(f'error:{keyword}')

        return patterns

    def _classify_api_category(self, url: str, request_attrs: RequestAttributes,
                             response_attrs: ResponseAttributes) -> str:
        """分类API类别"""
        url_lower = url.lower()

        # 基于URL模式分类
        for category, patterns in self.business_category_patterns.items():
            for pattern in patterns:
                if re.search(pattern, url_lower):
                    return category

        # 基于响应内容分类
        for indicator in response_attrs.financial_indicators:
            if 'balance' in indicator or 'amount' in indicator:
                return 'account'
            elif 'transaction' in indicator:
                return 'transaction'

        # 基于认证信息分类
        if request_attrs.authentication_headers:
            return 'authentication'

        return 'unknown'

    def _identify_business_function(self, method: str, url: str) -> str:
        """识别业务功能"""
        method_upper = method.upper()
        url_lower = url.lower()

        if method_upper == 'GET':
            if any(keyword in url_lower for keyword in ['list', 'search', 'query']):
                return 'query_list'
            else:
                return 'query'
        elif method_upper == 'POST':
            if any(keyword in url_lower for keyword in ['create', 'add', 'new']):
                return 'create'
            else:
                return 'update'
        elif method_upper == 'PUT':
            return 'update'
        elif method_upper == 'DELETE':
            return 'delete'
        else:
            return 'unknown'

    def _assess_data_sensitivity(self, sensitive_fields: List[str],
                               financial_indicators: List[str]) -> str:
        """评估数据敏感度"""
        if any('restricted' in field for field in sensitive_fields):
            return 'restricted'
        elif any('confidential' in field for field in sensitive_fields):
            return 'confidential'
        elif financial_indicators or any('internal' in field for field in sensitive_fields):
            return 'internal'
        else:
            return 'public'

    def _calculate_value_score(self, api_category: str, financial_indicators: List[str],
                             auth_headers: List[str]) -> float:
        """计算价值评分"""
        score = 0.0

        # 基础分类分数
        category_scores = {
            'account': 80,
            'transaction': 75,
            'investment': 70,
            'loan': 65,
            'card': 60,
            'authentication': 40,
            'unknown': 20
        }
        score += category_scores.get(api_category, 20)

        # 金融指标加分
        score += len(financial_indicators) * 5

        # 认证信息加分
        if auth_headers:
            score += 15

        return min(score, 100.0)

    def _determine_priority_level(self, value_score: float, data_sensitivity: str) -> str:
        """确定优先级等级"""
        if value_score >= 80 or data_sensitivity == 'restricted':
            return 'critical'
        elif value_score >= 60 or data_sensitivity == 'confidential':
            return 'high'
        elif value_score >= 40 or data_sensitivity == 'internal':
            return 'medium'
        else:
            return 'low'

    def _identify_compliance_indicators(self, sensitive_fields: List[str]) -> List[str]:
        """识别合规指标"""
        indicators = []

        compliance_patterns = {
            'PCI_DSS': ['card.*number', 'cvv', 'security.*code'],
            'GDPR': ['personal.*data', 'email', 'phone', 'address'],
            'SOX': ['financial.*statement', 'audit', 'internal.*control'],
            'KYC': ['customer.*id', 'identity', 'verification']
        }

        for compliance, patterns in compliance_patterns.items():
            for pattern in patterns:
                if any(pattern in field for field in sensitive_fields):
                    indicators.append(compliance)
                    break

        return indicators

    def _assess_risk_level(self, data_sensitivity: str, sensitive_fields: List[str]) -> str:
        """评估风险等级"""
        if data_sensitivity == 'restricted' or len(sensitive_fields) > 5:
            return 'high'
        elif data_sensitivity == 'confidential' or len(sensitive_fields) > 2:
            return 'medium'
        else:
            return 'low'

    def _assess_integration_complexity(self, request_attrs: RequestAttributes,
                                     response_attrs: ResponseAttributes) -> str:
        """评估集成复杂度"""
        complexity_score = 0

        # 认证复杂度
        if len(request_attrs.authentication_headers) > 2:
            complexity_score += 2
        elif request_attrs.authentication_headers:
            complexity_score += 1

        # 参数复杂度
        if len(request_attrs.query_parameters) > 5:
            complexity_score += 2
        elif len(request_attrs.query_parameters) > 2:
            complexity_score += 1

        # 响应结构复杂度
        if response_attrs.data_structure == 'json_object':
            if len(response_attrs.field_patterns) > 10:
                complexity_score += 2
            elif len(response_attrs.field_patterns) > 5:
                complexity_score += 1

        if complexity_score >= 4:
            return 'complex'
        elif complexity_score >= 2:
            return 'medium'
        else:
            return 'simple'

    def _calculate_extraction_confidence(self, request_attrs: RequestAttributes,
                                       response_attrs: ResponseAttributes,
                                       business_attrs: BusinessAttributes) -> float:
        """计算提取置信度"""
        confidence = 0.0

        # 请求属性置信度
        if request_attrs.url_pattern:
            confidence += 0.2
        if request_attrs.authentication_headers:
            confidence += 0.2
        if request_attrs.endpoint_category:
            confidence += 0.1

        # 响应属性置信度
        if response_attrs.data_structure != 'empty':
            confidence += 0.2
        if response_attrs.financial_indicators:
            confidence += 0.2
        if response_attrs.field_patterns:
            confidence += 0.1

        return min(confidence, 1.0)

    def update_feature_library_with_attributes(self, extracted_attributes: List[ExtractedAPIAttributes]) -> Dict[str, Any]:
        """将提取的属性更新到特征库"""
        update_report = {
            'total_apis': len(extracted_attributes),
            'successful_updates': 0,
            'failed_updates': 0,
            'new_patterns_added': 0,
            'institutions_updated': [],
            'update_details': []
        }

        try:
            for api_attrs in extracted_attributes:
                try:
                    success = self._update_single_api_attributes(api_attrs)
                    if success:
                        update_report['successful_updates'] += 1
                        if api_attrs.institution not in update_report['institutions_updated']:
                            update_report['institutions_updated'].append(api_attrs.institution)
                    else:
                        update_report['failed_updates'] += 1

                    update_report['update_details'].append({
                        'url': api_attrs.url,
                        'institution': api_attrs.institution,
                        'success': success,
                        'confidence': api_attrs.extraction_confidence
                    })

                except Exception as e:
                    update_report['failed_updates'] += 1
                    self.logger.error(f"更新API属性失败 {api_attrs.url}: {e}")

            # 保存更新后的特征库
            if update_report['successful_updates'] > 0:
                self._save_feature_library()
                self.logger.info(f"特征库更新完成: {update_report['successful_updates']} 个API成功更新")

            return update_report

        except Exception as e:
            self.logger.error(f"特征库更新失败: {e}")
            update_report['error'] = str(e)
            return update_report

    def _update_single_api_attributes(self, api_attrs: ExtractedAPIAttributes) -> bool:
        """更新单个API的属性到特征库"""
        try:
            institution_key = self._find_or_create_institution_entry(api_attrs.institution)
            if not institution_key:
                return False

            # 更新API模式
            self._update_api_patterns(institution_key, api_attrs)

            # 更新价值指标
            self._update_value_indicators(institution_key, api_attrs)

            # 更新响应模式
            self._update_response_patterns(institution_key, api_attrs)

            # 更新认证指标
            self._update_authentication_indicators(institution_key, api_attrs)

            # 添加示例
            self._add_api_example(institution_key, api_attrs)

            return True

        except Exception as e:
            self.logger.error(f"更新单个API属性失败: {e}")
            return False

    def _find_or_create_institution_entry(self, institution: str) -> Optional[str]:
        """查找或创建机构条目"""
        # 查找现有机构
        for category_key, category in self.feature_library.items():
            if isinstance(category, dict) and 'institutions' in category:
                for inst_key, inst_data in category['institutions'].items():
                    if inst_data.get('name') == institution:
                        return f"{category_key}.institutions.{inst_key}"

        # 创建新机构条目
        if 'learned_institutions' not in self.feature_library:
            self.feature_library['learned_institutions'] = {
                'description': '通过增强学习发现的新金融机构',
                'institutions': {}
            }

        # 生成机构键
        inst_key = institution.lower().replace(' ', '_').replace('银行', '_bank').replace('(', '').replace(')', '')

        self.feature_library['learned_institutions']['institutions'][inst_key] = {
            'name': institution,
            'domains': [],
            'api_patterns': {},
            'value_indicators': {
                'high_value_keywords': [],
                'response_patterns': [],
                'bonus_weight': 15
            },
            'authentication_indicators': {
                'url_auth_params': [],
                'response_auth_fields': []
            },
            'learned_examples': [],
            'learning_metadata': {
                'first_discovered': datetime.now().isoformat(),
                'last_updated': datetime.now().isoformat(),
                'confidence_score': 0.0,
                'api_count': 0
            }
        }

        return f"learned_institutions.institutions.{inst_key}"

    def _update_api_patterns(self, institution_key: str, api_attrs: ExtractedAPIAttributes):
        """更新API模式"""
        inst_data = self._get_institution_data(institution_key)
        if not inst_data:
            return

        category = api_attrs.business_attrs.api_category
        if category and category != 'unknown':
            if category not in inst_data['api_patterns']:
                inst_data['api_patterns'][category] = []

            # 添加URL模式
            url_pattern = api_attrs.request_attrs.url_pattern
            if url_pattern and url_pattern not in inst_data['api_patterns'][category]:
                inst_data['api_patterns'][category].append(url_pattern)

    def _update_value_indicators(self, institution_key: str, api_attrs: ExtractedAPIAttributes):
        """更新价值指标"""
        inst_data = self._get_institution_data(institution_key)
        if not inst_data:
            return

        # 更新高价值关键字
        for indicator in api_attrs.response_attrs.financial_indicators:
            if 'financial_term:' in indicator:
                term = indicator.split(':', 1)[1]
                if term not in inst_data['value_indicators']['high_value_keywords']:
                    inst_data['value_indicators']['high_value_keywords'].append(term)

        # 更新响应模式
        for pattern in api_attrs.response_attrs.field_patterns:
            if pattern not in inst_data['value_indicators']['response_patterns']:
                inst_data['value_indicators']['response_patterns'].append(pattern)

    def _update_response_patterns(self, institution_key: str, api_attrs: ExtractedAPIAttributes):
        """更新响应模式"""
        inst_data = self._get_institution_data(institution_key)
        if not inst_data:
            return

        # 添加响应结构信息
        if 'response_structures' not in inst_data:
            inst_data['response_structures'] = {}

        category = api_attrs.business_attrs.api_category
        if category:
            if category not in inst_data['response_structures']:
                inst_data['response_structures'][category] = {
                    'data_structure': [],
                    'field_patterns': [],
                    'data_types': []
                }

            structure_info = inst_data['response_structures'][category]

            # 添加数据结构
            data_structure = api_attrs.response_attrs.data_structure
            if data_structure not in structure_info['data_structure']:
                structure_info['data_structure'].append(data_structure)

            # 添加字段模式
            for pattern in api_attrs.response_attrs.field_patterns:
                if pattern not in structure_info['field_patterns']:
                    structure_info['field_patterns'].append(pattern)

            # 添加数据类型
            for data_type in api_attrs.response_attrs.data_types:
                if data_type not in structure_info['data_types']:
                    structure_info['data_types'].append(data_type)

    def _update_authentication_indicators(self, institution_key: str, api_attrs: ExtractedAPIAttributes):
        """更新认证指标"""
        inst_data = self._get_institution_data(institution_key)
        if not inst_data:
            return

        # 更新认证头信息
        for header in api_attrs.request_attrs.authentication_headers:
            if header not in inst_data['authentication_indicators']['response_auth_fields']:
                inst_data['authentication_indicators']['response_auth_fields'].append(header)

        # 更新会话指标
        for indicator in api_attrs.request_attrs.session_indicators:
            if indicator.startswith('url:'):
                param = indicator.split(':', 1)[1]
                if param not in inst_data['authentication_indicators']['url_auth_params']:
                    inst_data['authentication_indicators']['url_auth_params'].append(param)

    def _add_api_example(self, institution_key: str, api_attrs: ExtractedAPIAttributes):
        """添加API示例"""
        inst_data = self._get_institution_data(institution_key)
        if not inst_data:
            return

        example = {
            'url': api_attrs.url,
            'api_category': api_attrs.business_attrs.api_category,
            'business_function': api_attrs.business_attrs.business_function,
            'value_score': api_attrs.business_attrs.value_score,
            'priority_level': api_attrs.business_attrs.priority_level,
            'data_sensitivity': api_attrs.business_attrs.data_sensitivity,
            'extraction_confidence': api_attrs.extraction_confidence,
            'learned_timestamp': api_attrs.extraction_timestamp,
            'financial_indicators': api_attrs.response_attrs.financial_indicators,
            'data_types': api_attrs.response_attrs.data_types
        }

        inst_data['learned_examples'].append(example)

        # 更新学习元数据
        metadata = inst_data['learning_metadata']
        metadata['last_updated'] = datetime.now().isoformat()
        metadata['api_count'] = len(inst_data['learned_examples'])

        # 更新平均置信度
        total_confidence = sum(ex['extraction_confidence'] for ex in inst_data['learned_examples'])
        metadata['confidence_score'] = total_confidence / len(inst_data['learned_examples'])

    def _get_institution_data(self, institution_key: str) -> Optional[Dict[str, Any]]:
        """获取机构数据"""
        try:
            keys = institution_key.split('.')
            data = self.feature_library
            for key in keys:
                data = data[key]
            return data
        except (KeyError, TypeError):
            return None

    def _save_feature_library(self) -> bool:
        """保存特征库"""
        try:
            # 备份原文件
            backup_path = f"{self.feature_library_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            with open(self.feature_library_path, 'r', encoding='utf-8') as f:
                backup_content = f.read()
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(backup_content)

            # 保存更新后的特征库
            with open(self.feature_library_path, 'w', encoding='utf-8') as f:
                json.dump(self.feature_library, f, indent=2, ensure_ascii=False)

            self.logger.info(f"特征库已更新，备份保存至: {backup_path}")
            return True
        except Exception as e:
            self.logger.error(f"保存特征库失败: {e}")
            return False
