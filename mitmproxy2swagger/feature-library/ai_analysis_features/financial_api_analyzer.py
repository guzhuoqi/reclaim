#!/usr/bin/env python3
"""
金融API特征分析器
Financial API Feature Analyzer

基于特征库识别有价值的金融API端点
用于分析抓包文件中的金融机构API，重点识别账户信息、资产信息、余额信息等核心数据API

核心功能：
1. 基于域名识别金融机构
2. 基于URL模式匹配有价值的API端点
3. 检测认证信息的存在
4. 分析响应内容中的金融数据
5. 综合评分和优先级排序
"""

import json
import re
import logging
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from urllib.parse import urlparse
from dataclasses import dataclass
from html.parser import HTMLParser
import html


class FinancialHTMLParser(HTMLParser):
    """专门用于解析HTML中金融数据的解析器"""

    def __init__(self):
        super().__init__()
        self.financial_data = []
        self.current_tag = None
        self.current_attrs = {}
        self.text_content = []

        # 金融数据相关的标签和属性
        self.financial_indicators = {
            'currency_codes': ['HKD', 'USD', 'CNY', 'EUR', 'GBP', 'JPY', 'AUD', 'CAD', 'SGD'],
            'amount_patterns': [
                r'\$[\d,]+\.?\d*',  # $1,234.56
                r'[\d,]+\.?\d*\s*(HKD|USD|CNY|EUR|GBP|JPY)',  # 1,234.56 HKD
                r'(HKD|USD|CNY|EUR|GBP|JPY)\s*[\d,]+\.?\d*',  # HKD 1,234.56
                r'[\d,]+\.?\d{2}',  # 1,234.56
            ],
            'account_patterns': [
                r'\d{4,20}',  # 账户号码
                r'[A-Z]{2,4}\d{6,16}',  # 银行账户格式
            ],
            'financial_keywords': [
                'balance', 'amount', 'value', 'total', 'available', 'current',
                'account', 'portfolio', 'investment', 'asset', 'equity',
                '余额', '金额', '总额', '可用', '当前', '账户', '投资组合', '资产'
            ]
        }

    def handle_starttag(self, tag, attrs):
        self.current_tag = tag
        self.current_attrs = dict(attrs)

        # 检查属性中的金融数据
        for attr_name, attr_value in attrs:
            if attr_value:
                self._analyze_text_for_financial_data(attr_value, f"attr:{attr_name}")

    def handle_data(self, data):
        if data.strip():
            self.text_content.append(data.strip())
            self._analyze_text_for_financial_data(data.strip(), f"tag:{self.current_tag}")

    def _analyze_text_for_financial_data(self, text, source):
        """分析文本中的金融数据"""
        text_lower = text.lower()

        # 检查货币代码
        for currency in self.financial_indicators['currency_codes']:
            if currency.lower() in text_lower or currency in text:
                self.financial_data.append({
                    'type': 'currency',
                    'value': currency,
                    'source': source,
                    'context': text[:100]
                })

        # 检查金额模式
        for pattern in self.financial_indicators['amount_patterns']:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                self.financial_data.append({
                    'type': 'amount',
                    'value': match,
                    'source': source,
                    'context': text[:100]
                })

        # 检查账户模式
        for pattern in self.financial_indicators['account_patterns']:
            matches = re.findall(pattern, text)
            for match in matches:
                # 过滤掉明显不是账户号的数字（如年份、电话等）
                if len(match) >= 6 and not match.startswith(('19', '20')):
                    self.financial_data.append({
                        'type': 'account',
                        'value': match,
                        'source': source,
                        'context': text[:100]
                    })

        # 检查金融关键字
        for keyword in self.financial_indicators['financial_keywords']:
            if keyword in text_lower:
                self.financial_data.append({
                    'type': 'keyword',
                    'value': keyword,
                    'source': source,
                    'context': text[:100]
                })

    def get_financial_data(self):
        """获取解析出的金融数据"""
        return self.financial_data

    def get_text_content(self):
        """获取所有文本内容"""
        return ' '.join(self.text_content)


@dataclass
class APIAnalysisResult:
    """API分析结果"""
    url: str
    institution: str = ""
    institution_type: str = ""
    matched_patterns: List[str] = None
    value_score: int = 0
    priority_level: str = "low"
    data_types: List[str] = None
    authentication_detected: bool = False
    response_contains_financial_data: bool = False
    analysis_details: Dict[str, Any] = None
    # 🎯 新增：API分类字段
    api_category: str = "unknown"  # query, auth, resource, unknown
    provider_worthy: bool = False  # 是否值得生成provider

    def __post_init__(self):
        if self.matched_patterns is None:
            self.matched_patterns = []
        if self.data_types is None:
            self.data_types = []
        if self.analysis_details is None:
            self.analysis_details = {}


class FinancialAPIAnalyzer:
    """金融API特征分析器"""

    def __init__(self, features_config_path: str = None):
        """初始化分析器

        Args:
            features_config_path: 特征库配置文件路径
        """
        if features_config_path is None:
            features_config_path = Path(__file__).parent / "financial_api_features.json"

        self.features_config_path = Path(features_config_path)
        self.features_config = {}

        # 设置日志
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        # 加载特征配置
        self.load_features_config()

    def load_features_config(self) -> bool:
        """加载特征配置"""
        try:
            if not self.features_config_path.exists():
                self.logger.error(f"特征配置文件不存在: {self.features_config_path}")
                return False

            with open(self.features_config_path, 'r', encoding='utf-8') as f:
                self.features_config = json.load(f)

            self.logger.info(f"特征配置加载成功: {self.features_config_path}")
            return True

        except Exception as e:
            self.logger.error(f"加载特征配置失败: {e}")
            return False

    def identify_institution(self, url: str) -> Tuple[str, str, str]:
        """识别金融机构

        Args:
            url: API URL

        Returns:
            Tuple[str, str, str]: (机构名称, 机构类型, 匹配的域名)
        """
        parsed_url = urlparse(url.lower())
        domain = parsed_url.netloc

        # 检查各类金融机构
        institution_categories = [
            ("hong_kong_banks", "香港银行"),
            ("us_european_banks", "欧美银行"),
            ("china_mainland_banks", "中国大陆银行"),
            ("global_investment_banks", "全球投资银行"),
            ("brokerage_firms", "券商"),
            ("cryptocurrency_exchanges", "加密货币交易所"),
            ("payment_platforms", "支付平台"),
            ("insurance_companies", "保险公司"),
            ("fintech_companies", "金融科技公司")
        ]

        for category_key, category_name in institution_categories:
            category_data = self.features_config.get(category_key, {})
            institutions = category_data.get("institutions", {})

            for inst_key, inst_data in institutions.items():
                domains = inst_data.get("domains", [])
                for inst_domain in domains:
                    if inst_domain.lower() in domain:
                        return inst_data.get("name", inst_key), category_name, inst_domain

        return "", "", ""

    def match_api_patterns(self, url: str, institution_data: Dict[str, Any]) -> Tuple[List[str], int]:
        """匹配API模式

        Args:
            url: API URL
            institution_data: 机构数据

        Returns:
            Tuple[List[str], int]: (匹配的模式列表, 加分值)
        """
        matched_patterns = []
        total_bonus = 0

        api_patterns = institution_data.get("api_patterns", {})
        value_indicators = institution_data.get("value_indicators", {})

        for pattern_category, patterns in api_patterns.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, url, re.IGNORECASE):
                        matched_patterns.append(f"{pattern_category}:{pattern}")
                        break  # 每个类别只匹配一次
                except re.error:
                    continue

        # 严格计算加分：需要匹配多个模式才给高分
        if matched_patterns:
            bonus_weight = value_indicators.get("bonus_weight", 0)

            # 根据匹配的模式数量调整分数
            pattern_count = len(matched_patterns)
            if pattern_count >= 3:  # 匹配3个或以上模式，给满分
                total_bonus = bonus_weight
            elif pattern_count == 2:  # 匹配2个模式，给70%分数
                total_bonus = int(bonus_weight * 0.7)
            elif pattern_count == 1:  # 只匹配1个模式，给40%分数
                total_bonus = int(bonus_weight * 0.4)
            else:
                total_bonus = 0

        return matched_patterns, total_bonus

    def match_universal_patterns(self, url: str) -> Tuple[List[str], int]:
        """匹配通用模式

        Args:
            url: API URL

        Returns:
            Tuple[List[str], int]: (匹配的模式列表, 加分值)
        """
        matched_patterns = []
        total_bonus = 0

        universal_patterns = self.features_config.get("universal_financial_patterns", {})

        for pattern_type, pattern_data in universal_patterns.items():
            if pattern_type == "description":
                continue

            patterns = pattern_data.get("patterns", [])
            bonus_weight = pattern_data.get("bonus_weight", 0)

            for pattern in patterns:
                try:
                    if re.search(pattern, url, re.IGNORECASE):
                        matched_patterns.append(f"universal:{pattern_type}:{pattern}")
                        break  # 每个类型只匹配一次
                except re.error:
                    continue

        # 严格计算通用模式加分：需要匹配多个类型才给分
        if len(matched_patterns) >= 2:  # 至少匹配2个不同类型的模式
            # 计算总加分，但限制最大值
            for pattern_type, pattern_data in universal_patterns.items():
                if pattern_type == "description":
                    continue
                bonus_weight = pattern_data.get("bonus_weight", 0)
                # 检查是否有该类型的匹配
                if any(pattern_type in pattern for pattern in matched_patterns):
                    total_bonus += min(bonus_weight, 15)  # 限制单个类型最大加分

        return matched_patterns, total_bonus

    def check_strict_financial_keywords(self, url: str, response_content: str = "") -> Tuple[bool, List[str], int]:
        """检查严格的金融关键字组合

        Args:
            url: API URL
            response_content: 响应内容

        Returns:
            Tuple[bool, List[str], int]: (是否满足严格条件, 匹配的关键字, 加分值)
        """
        # 定义严格的金融关键字组合
        strict_keywords = {
            "account_operations": {
                "url_keywords": ["account", "acc", "balance", "overview", "summary"],
                "path_keywords": ["banking", "ibanking", "ebanking"],
                "tech_keywords": ["servlet", "api", "service"],
                "required_count": 2,  # 至少需要匹配2个不同类别
                "bonus": 40
            },
            "transaction_operations": {
                "url_keywords": ["transaction", "txn", "transfer", "payment", "history"],
                "path_keywords": ["banking", "ibanking", "ebanking"],
                "tech_keywords": ["servlet", "api", "service"],
                "required_count": 2,
                "bonus": 35
            },
            "authentication_operations": {
                "url_keywords": ["login", "logon", "auth", "verify", "token"],
                "path_keywords": ["banking", "ibanking", "ebanking", "security"],
                "tech_keywords": ["servlet", "api", "service"],
                "required_count": 2,
                "bonus": 30
            }
        }

        matched_keywords = []
        total_bonus = 0
        url_lower = url.lower()
        content_lower = response_content.lower() if response_content else ""

        for operation_type, criteria in strict_keywords.items():
            matched_categories = 0
            operation_matches = []

            # 检查URL关键字
            url_matches = [kw for kw in criteria["url_keywords"] if kw in url_lower]
            if url_matches:
                matched_categories += 1
                operation_matches.extend([f"url:{kw}" for kw in url_matches])

            # 检查路径关键字
            path_matches = [kw for kw in criteria["path_keywords"] if kw in url_lower]
            if path_matches:
                matched_categories += 1
                operation_matches.extend([f"path:{kw}" for kw in path_matches])

            # 检查技术关键字
            tech_matches = [kw for kw in criteria["tech_keywords"] if kw in url_lower]
            if tech_matches:
                matched_categories += 1
                operation_matches.extend([f"tech:{kw}" for kw in tech_matches])

            # 检查响应内容关键字（如果有）
            if content_lower:
                content_matches = [kw for kw in criteria["url_keywords"] if kw in content_lower]
                if content_matches:
                    matched_categories += 1
                    operation_matches.extend([f"content:{kw}" for kw in content_matches])

            # 如果满足最低要求，给予加分
            if matched_categories >= criteria["required_count"]:
                matched_keywords.extend([f"{operation_type}:{match}" for match in operation_matches])
                total_bonus += criteria["bonus"]

        is_strict_match = len(matched_keywords) > 0
        return is_strict_match, matched_keywords, total_bonus

    def detect_authentication(self, headers: Dict[str, str] = None,
                            cookies: Dict[str, str] = None,
                            url_params: Dict[str, str] = None) -> Tuple[bool, List[str]]:
        """检测认证信息

        Args:
            headers: HTTP头部
            cookies: Cookie信息
            url_params: URL参数

        Returns:
            Tuple[bool, List[str]]: (是否检测到认证, 检测到的认证类型)
        """
        auth_indicators = self.features_config.get("authentication_indicators", {})
        detected_auth = []

        if headers:
            auth_headers = auth_indicators.get("auth_headers", [])
            for header_name in auth_headers:
                if header_name.lower() in [h.lower() for h in headers.keys()]:
                    detected_auth.append(f"header:{header_name}")

        if cookies:
            session_patterns = auth_indicators.get("session_patterns", [])
            for cookie_name in cookies.keys():
                for pattern in session_patterns:
                    if pattern.lower() in cookie_name.lower():
                        detected_auth.append(f"cookie:{pattern}")

        if url_params:
            auth_parameters = auth_indicators.get("auth_parameters", [])
            for param_name in url_params.keys():
                for auth_param in auth_parameters:
                    if auth_param.lower() in param_name.lower():
                        detected_auth.append(f"param:{auth_param}")

        return len(detected_auth) > 0, detected_auth

    def analyze_response_content(self, response_content: str) -> Tuple[bool, List[str]]:
        """分析响应内容（支持JSON和HTML）

        Args:
            response_content: 响应内容

        Returns:
            Tuple[bool, List[str]]: (是否包含金融数据, 匹配的字段列表)
        """
        if not response_content:
            return False, []

        content_indicators = self.features_config.get("response_content_indicators", {})
        matched_fields = []

        # 1. 检查高价值字段（原有逻辑）
        high_value_fields = content_indicators.get("high_value_fields", [])
        for field in high_value_fields:
            if field.lower() in response_content.lower():
                matched_fields.append(f"field:{field}")

        # 2. 检查金融数据模式（原有逻辑）
        financial_patterns = content_indicators.get("financial_data_patterns", [])
        for pattern in financial_patterns:
            try:
                if re.search(pattern, response_content, re.IGNORECASE):
                    matched_fields.append(f"pattern:{pattern}")
            except re.error:
                continue

        # 3. 🎯 新增：HTML内容解析
        html_financial_data = self.analyze_html_content(response_content)
        matched_fields.extend(html_financial_data)

        # 4. 🎯 新增：JSON内容深度解析
        json_financial_data = self.analyze_json_content(response_content)
        matched_fields.extend(json_financial_data)

        return len(matched_fields) > 0, matched_fields

    def analyze_html_content(self, content: str) -> List[str]:
        """分析HTML内容中的金融数据 - 🎯 精确验证实际内容

        Args:
            content: HTML内容

        Returns:
            List[str]: 匹配的金融数据模式列表
        """
        matched_patterns = []

        # 检查是否为HTML内容
        if not (content.strip().startswith('<') or '<html' in content.lower() or '<body' in content.lower()):
            return matched_patterns

        try:
            # 🎯 精确验证：只有真实存在且有意义的数据才生成模式
            verified_data = self._verify_html_financial_data(content)

            # 根据验证结果生成精确的模式
            if verified_data['currencies']:
                for currency in verified_data['currencies']:
                    matched_patterns.append(f"html_currency:{currency}")
                matched_patterns.append(f"html_content:currency")

            if verified_data['amounts']:
                matched_patterns.append(f"html_content:amount")

            if verified_data['accounts']:
                matched_patterns.append(f"html_content:account")

            if verified_data['balance_indicators']:
                matched_patterns.append(f"html_content:balance")

            if verified_data['asset_indicators']:
                matched_patterns.append(f"html_content:asset")

            if verified_data['name_indicators']:
                matched_patterns.append(f"html_content:customer_name")

            print(f"🔍 HTML精确验证结果: 货币{len(verified_data['currencies'])}个, 金额{len(verified_data['amounts'])}个, 账户{len(verified_data['accounts'])}个")

        except Exception as e:
            print(f"⚠️ HTML解析失败: {e}")

        return matched_patterns

    def _verify_html_financial_data(self, content: str) -> dict:
        """精确验证HTML内容中的金融数据

        Args:
            content: HTML内容

        Returns:
            dict: 验证后的金融数据
        """
        import re

        verified_data = {
            'currencies': set(),
            'amounts': set(),
            'accounts': set(),
            'balance_indicators': False,
            'asset_indicators': False,
            'name_indicators': False
        }

        # 🎯 精确验证货币代码 - 必须在表格或明确的金融上下文中
        currency_codes = ['HKD', 'USD', 'CNY', 'EUR', 'GBP', 'JPY', 'AUD', 'CAD', 'SGD']
        for currency in currency_codes:
            # 检查货币代码是否在表格单元格中或与金额相关的上下文中
            currency_patterns = [
                rf'<td[^>]*>{currency}</td>',  # 表格单元格中
                rf'<span[^>]*>{currency}</span>',  # span标签中
                rf'{currency}\s*[0-9,]+\.?\d*',  # 货币代码后跟数字
                rf'[0-9,]+\.?\d*\s*{currency}',  # 数字后跟货币代码
            ]

            for pattern in currency_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    verified_data['currencies'].add(currency)
                    break

        # 🎯 精确验证金额格式 - 必须是真实的金额格式
        amount_patterns = [
            r'\$[0-9,]+\.[0-9]{2}',  # $1,234.56
            r'[0-9,]+\.[0-9]{2}\s*(HKD|USD|CNY|EUR|GBP|JPY)',  # 1,234.56 HKD
            r'(HKD|USD|CNY|EUR|GBP|JPY)\s*[0-9,]+\.[0-9]{2}',  # HKD 1,234.56
        ]

        for pattern in amount_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                verified_data['amounts'].update(matches[:5])  # 最多记录5个

        # 🎯 精确验证账户号码 - 排除明显的日期、电话等
        account_patterns = [
            r'\b\d{8,20}\b',  # 8-20位数字
            r'\b[A-Z]{2,4}\d{8,16}\b',  # 字母+数字格式
        ]

        for pattern in account_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                # 排除明显的日期格式
                if not (match.startswith('20') and len(match) == 8):  # 排除20140715这样的日期
                    if not (match.startswith('19') and len(match) == 8):  # 排除19xx年份
                        verified_data['accounts'].add(match)

        # 🎯 精确验证余额指示器 - 必须在金融上下文中
        balance_keywords = ['balance', 'available', 'current', '余额', '可用', '当前']
        balance_context_patterns = [
            r'(balance|available|current|余额|可用|当前)[^<]*[0-9,]+\.?\d*',
            r'<td[^>]*>(balance|available|current|余额|可用|当前)</td>',
        ]

        for pattern in balance_context_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                verified_data['balance_indicators'] = True
                break

        # 🎯 精确验证资产指示器
        asset_keywords = ['asset', 'portfolio', 'investment', 'equity', '资产', '投资组合', '净值']
        for keyword in asset_keywords:
            if keyword in content.lower() and re.search(rf'{keyword}[^<]*[0-9,]+\.?\d*', content, re.IGNORECASE):
                verified_data['asset_indicators'] = True
                break

        # 🎯 精确验证姓名指示器
        name_keywords = ['customer', 'holder', 'name', '客户', '持有人', '姓名']
        for keyword in name_keywords:
            if keyword in content.lower():
                verified_data['name_indicators'] = True
                break

        return verified_data

    def analyze_json_content(self, content: str) -> List[str]:
        """深度分析JSON内容中的金融数据

        Args:
            content: JSON内容

        Returns:
            List[str]: 匹配的金融数据模式列表
        """
        matched_patterns = []

        # 检查是否为JSON内容
        content_stripped = content.strip()
        if not (content_stripped.startswith('{') or content_stripped.startswith('[')):
            return matched_patterns

        try:
            # 解析JSON
            if content_stripped.startswith('{'):
                data = json.loads(content_stripped)
            elif content_stripped.startswith('['):
                data = json.loads(content_stripped)
                # 如果是数组，取第一个元素进行分析
                if data and isinstance(data, list) and len(data) > 0:
                    data = data[0]
                else:
                    return matched_patterns
            else:
                return matched_patterns

            # 递归分析JSON结构
            self._analyze_json_object(data, matched_patterns, "")

            print(f"🔍 JSON解析结果: 发现{len(matched_patterns)}个金融数据模式")

        except (json.JSONDecodeError, Exception) as e:
            # 不是有效的JSON，忽略
            pass

        return matched_patterns

    def _analyze_json_object(self, obj, matched_patterns: List[str], path: str):
        """递归分析JSON对象"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key

                # 分析键名
                self._analyze_json_key(key, matched_patterns)

                # 分析值
                if isinstance(value, (str, int, float)):
                    self._analyze_json_value(key, value, matched_patterns)
                elif isinstance(value, (dict, list)):
                    self._analyze_json_object(value, matched_patterns, current_path)

        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, (dict, list)):
                    self._analyze_json_object(item, matched_patterns, f"{path}[{i}]")

    def _analyze_json_key(self, key: str, matched_patterns: List[str]):
        """分析JSON键名"""
        key_lower = key.lower()

        # 货币相关 - 🎯 JSON专用模式
        if any(currency_kw in key_lower for currency_kw in ['currency', 'curr', 'ccy']):
            if "json_content:currency" not in matched_patterns:
                matched_patterns.append("json_content:currency")

        # 金额相关
        if any(amount_kw in key_lower for amount_kw in ['amount', 'value', 'price', 'cost']):
            if "json_content:amount" not in matched_patterns:
                matched_patterns.append("json_content:amount")

        # 余额相关
        if any(balance_kw in key_lower for balance_kw in ['balance', 'available', 'current']):
            if "json_content:balance" not in matched_patterns:
                matched_patterns.append("json_content:balance")

        # 账户相关
        if any(account_kw in key_lower for account_kw in ['account', 'acc', 'acct']):
            if "json_content:account" not in matched_patterns:
                matched_patterns.append("json_content:account")

        # 用户信息相关
        if any(name_kw in key_lower for name_kw in ['name', 'customer', 'holder', 'user']):
            if "json_content:customer_name" not in matched_patterns:
                matched_patterns.append("json_content:customer_name")

        # 资产相关
        if any(asset_kw in key_lower for asset_kw in ['asset', 'portfolio', 'investment', 'equity']):
            if "json_content:asset" not in matched_patterns:
                matched_patterns.append("json_content:asset")

    def _analyze_json_value(self, key: str, value, matched_patterns: List[str]):
        """分析JSON值"""
        if isinstance(value, str):
            value_upper = value.upper()

            # 检查货币代码 - 🎯 JSON专用模式
            currency_codes = ['HKD', 'USD', 'CNY', 'EUR', 'GBP', 'JPY', 'AUD', 'CAD', 'SGD']
            if value_upper in currency_codes:
                if "json_content:currency" not in matched_patterns:
                    matched_patterns.append("json_content:currency")
                matched_patterns.append(f"json_currency:{value_upper}")

        elif isinstance(value, (int, float)):
            # 检查是否为金额（通过键名判断）
            key_lower = key.lower()
            if any(money_kw in key_lower for money_kw in ['amount', 'balance', 'value', 'price', 'cost']):
                if "json_content:amount" not in matched_patterns:
                    matched_patterns.append("json_content:amount")
                if "json_content:balance" not in matched_patterns and 'balance' in key_lower:
                    matched_patterns.append("json_content:balance")

    def calculate_priority_level(self, score: int) -> str:
        """计算优先级等级"""
        thresholds = self.features_config.get("analysis_configuration", {}).get("thresholds", {})

        critical_score = thresholds.get("critical_value_score", 80)
        high_score = thresholds.get("high_value_score", 50)
        min_score = thresholds.get("minimum_score", 20)

        if score >= critical_score:
            return "critical"
        elif score >= high_score:
            return "high"
        elif score >= min_score:
            return "medium"
        else:
            return "low"

    def analyze_api(self, url: str, headers: Dict[str, str] = None,
                   cookies: Dict[str, str] = None, url_params: Dict[str, str] = None,
                   response_content: str = "") -> APIAnalysisResult:
        """分析单个API

        Args:
            url: API URL
            headers: HTTP头部
            cookies: Cookie信息
            url_params: URL参数
            response_content: 响应内容

        Returns:
            APIAnalysisResult: 分析结果
        """
        result = APIAnalysisResult(url=url)

        # 1. 识别金融机构
        institution_name, institution_type, matched_domain = self.identify_institution(url)
        result.institution = institution_name
        result.institution_type = institution_type

        # 2. 计算基础分数
        scoring_weights = self.features_config.get("analysis_configuration", {}).get("scoring_weights", {})
        total_score = 0

        # 域名匹配记录（但不直接加分）
        domain_matched = False
        if institution_name:
            domain_matched = True
            result.matched_patterns.append(f"domain:{matched_domain}")

        # 3. API模式匹配
        if institution_name:
            # 查找机构数据
            institution_data = None
            for category_key in ["hong_kong_banks", "us_european_banks", "china_mainland_banks",
                               "global_investment_banks", "brokerage_firms", "cryptocurrency_exchanges",
                               "payment_platforms", "insurance_companies", "fintech_companies"]:
                category_data = self.features_config.get(category_key, {})
                institutions = category_data.get("institutions", {})
                for inst_key, inst_data in institutions.items():
                    if inst_data.get("name") == institution_name:
                        institution_data = inst_data
                        break
                if institution_data:
                    break

            if institution_data:
                patterns, pattern_bonus = self.match_api_patterns(url, institution_data)
                result.matched_patterns.extend(patterns)

                # 严格匹配：必须同时满足域名匹配 AND API模式匹配
                if domain_matched and patterns:
                    domain_score = scoring_weights.get("domain_match", 30)
                    total_score += domain_score + pattern_bonus

        # 4. 通用模式匹配（只有在域名匹配的情况下才加分）
        universal_patterns, universal_bonus = self.match_universal_patterns(url)
        result.matched_patterns.extend(universal_patterns)

        # 严格匹配：通用模式只有在域名匹配时才有效
        if domain_matched and universal_patterns:
            total_score += universal_bonus

        # 5. 严格金融关键字检查（新增）
        is_strict_match, strict_keywords, strict_bonus = self.check_strict_financial_keywords(url, response_content)
        if is_strict_match:
            result.matched_patterns.extend(strict_keywords)
            total_score += strict_bonus

        # 5. 认证检测
        has_auth, auth_types = self.detect_authentication(headers, cookies, url_params)
        result.authentication_detected = has_auth
        if has_auth:
            auth_score = scoring_weights.get("authentication_present", 15)
            total_score += auth_score
            result.matched_patterns.extend(auth_types)

        # 6. 响应内容分析
        has_financial_data, financial_fields = self.analyze_response_content(response_content)
        result.response_contains_financial_data = has_financial_data
        if has_financial_data:
            content_score = scoring_weights.get("response_content_match", 20)
            total_score += content_score
            result.matched_patterns.extend(financial_fields)

        # 7. 最终严格评分：只有满足多个条件的API才能获得高分
        final_score = 0

        # 基础条件：必须有域名匹配
        if domain_matched:
            # 条件1：有API模式匹配或通用模式匹配
            has_pattern_match = len([p for p in result.matched_patterns if not p.startswith("domain:")]) > 0

            # 条件2：有严格关键字匹配
            has_strict_match = is_strict_match

            # 条件3：有认证信息
            has_auth = has_auth if 'has_auth' in locals() else False

            # 条件4：有金融数据内容
            has_financial_content = has_financial_data if 'has_financial_data' in locals() else False

            # 严格评分逻辑
            if has_strict_match and has_pattern_match:
                final_score = total_score  # 满足严格条件，给予完整分数
            elif has_strict_match or (has_pattern_match and len(result.matched_patterns) >= 3):
                final_score = int(total_score * 0.7)  # 部分满足，给予70%分数
            elif has_pattern_match:
                final_score = int(total_score * 0.4)  # 只有模式匹配，给予40%分数
            else:
                final_score = 0  # 不满足条件，不给分

        result.value_score = final_score
        result.priority_level = self.calculate_priority_level(final_score)

        # 8. 推断数据类型
        if "account" in url.lower() or "balance" in url.lower():
            result.data_types.append("account_data")
        if "transaction" in url.lower() or "history" in url.lower():
            result.data_types.append("transaction_data")
        if "investment" in url.lower() or "portfolio" in url.lower():
            result.data_types.append("investment_data")
        if "trading" in url.lower() or "order" in url.lower():
            result.data_types.append("trading_data")

        # 🎯 鉴权信息检测（作为评分因子，不是门槛）
        has_auth_context = self.check_authentication_context(url, response_content, result)

        # 🎯 API分类逻辑（移除硬性鉴权门槛）
        result.api_category, result.provider_worthy = self.classify_api(url, result.matched_patterns)

        # 🎯 基于鉴权信息调整评分
        if has_auth_context and result.api_category == "query":
            result.value_score += 10  # 有鉴权信息的查询API加分
        elif not has_auth_context and result.api_category == "query":
            result.value_score -= 5   # 无鉴权信息的查询API减分，但不淘汰

        result.analysis_details = {
            "domain_matched": bool(institution_name),
            "patterns_matched": len(result.matched_patterns),
            "auth_detected": has_auth,
            "financial_content": has_financial_data,
            "api_category": result.api_category,
            "provider_worthy": result.provider_worthy,
            "auth_context_detected": has_auth_context,  # 🎯 鉴权上下文检测（评分因子）
            "scoring_breakdown": {
                "domain_score": scoring_weights.get("domain_match", 30) if institution_name else 0,
                "pattern_score": pattern_bonus if 'pattern_bonus' in locals() else universal_bonus,
                "auth_score": scoring_weights.get("authentication_present", 15) if has_auth else 0,
                "content_score": scoring_weights.get("response_content_match", 20) if has_financial_data else 0,
                "auth_context_bonus": 10 if has_auth_context and result.api_category == "query" else 0
            }
        }

        return result

    def classify_api(self, url: str, matched_patterns: List[str]) -> Tuple[str, bool]:
        """分类API类型，判断是否值得生成provider

        Args:
            url: API URL
            matched_patterns: 匹配的模式列表

        Returns:
            Tuple[str, bool]: (api_category, provider_worthy)
        """
        classification_config = self.features_config.get("analysis_configuration", {}).get("api_classification", {})

        provider_worthy_patterns = classification_config.get("provider_worthy_patterns", [])
        auth_only_patterns = classification_config.get("authentication_only_patterns", [])
        resource_patterns = classification_config.get("resource_patterns", [])

        url_lower = url.lower()

        # 1. 🎯 重新设计：区分真正的认证操作和路径认证
        has_strong_auth_pattern = False
        has_weak_auth_pattern = False
        has_path_auth_only = False  # 仅路径认证（如/ibanking/）

        for pattern in matched_patterns:
            # 强认证模式：明确的登录操作
            if any(strong_auth in pattern for strong_auth in [
                'url:logon', 'content:login', 'content:logon', 'Logon',
                'url:login', 'url:auth', 'url:signin', 'content:auth', 'content:signin'
            ]):
                has_strong_auth_pattern = True
                break
            # 🎯 区分路径认证和真正的认证操作
            elif 'authentication_operations:path:' in pattern:
                has_path_auth_only = True
            # 其他认证模式
            elif any(weak_auth in pattern for weak_auth in auth_only_patterns):
                has_weak_auth_pattern = True

        # 3. 检查是否包含真正的查询模式（排除通用的account关键字）
        has_strong_query_pattern = False
        has_weak_query_pattern = False

        for pattern in matched_patterns:
            # 强查询模式：明确的数据查询
            if any(strong_query in pattern for strong_query in ['core_banking:', 'content:balance', 'content:overview', 'field:']):
                has_strong_query_pattern = True
                break
            # 弱查询模式：可能的查询相关（如通用的account）
            elif any(weak_query in pattern for weak_query in ['content:account', 'url:acc']):
                has_weak_query_pattern = True

        # 4. 检查URL中的明确指示
        auth_keywords = [
            'login', 'logon', 'auth', 'signin', 'sign-in',
            'lgn',  # 中银香港可能使用的缩写
            'default',  # 如 lgn.default.do
            'verify', 'validation',  # 验证相关
            'session', 'token'  # 会话相关
        ]
        url_indicates_auth = any(auth_keyword in url_lower for auth_keyword in auth_keywords)

        query_keywords = [
            'overview', 'balance', 'account', 'detail', 'info',
            'acc.overview',  # 中银香港的账户概览
            'transaction', 'history', 'statement'
        ]
        url_indicates_query = any(query_keyword in url_lower for query_keyword in query_keywords)

        # 5. 🎯 重新设计的智能分类决策（业务优先）

        # 🎯 最高优先级：强查询模式（核心业务API）
        # 即使有认证路径，如果有明确的业务查询特征，优先分类为query
        if has_strong_query_pattern:
            return "query", True

        # 🎯 第二优先级：弱查询模式 + URL指示查询
        # 业务API优先于路径认证
        if has_weak_query_pattern and url_indicates_query:
            return "query", True

        # 🎯 第三优先级：强认证模式（明确的登录操作）
        if has_strong_auth_pattern or url_indicates_auth:
            # 进一步区分登录页面和登录提交
            if 'POST' in str(matched_patterns) or any('submit' in p.lower() for p in matched_patterns):
                return "auth", False  # 登录提交，不构建provider，但有上下文价值
            else:
                return "auth", False  # 登录页面，不构建provider，但可作为loginUrl

        # 🎯 第四优先级：弱查询模式（即使只有路径认证）
        # 如果有任何查询特征，优先考虑为业务API
        if has_weak_query_pattern:
            return "query", True

        # 🎯 第五优先级：弱认证模式但没有查询模式
        if has_weak_auth_pattern and not has_weak_query_pattern:
            return "auth", False

        # 🎯 第六优先级：仅路径认证（如/ibanking/）但没有其他特征
        if has_path_auth_only and not has_weak_query_pattern:
            return "auth", False

        # 🎯 第七优先级：检查是否为资源类API
        if self._is_resource_api(url_lower, resource_patterns):
            return "resource", False

        return "unknown", False

    def _is_resource_api(self, url_lower: str, resource_patterns: List[str]) -> bool:
        """更精确的资源API检测，避免误杀认证页面"""

        # 🎯 排除明显的认证页面（即使包含资源关键字）
        auth_indicators = ['/login/', '/logon/', '/signin/', '/auth/']
        if any(indicator in url_lower for indicator in auth_indicators):
            return False

        # 🎯 更精确的资源模式匹配
        for pattern in resource_patterns:
            if pattern == 'js':
                # 只匹配真正的JS文件，不匹配.jsp
                if url_lower.endswith('.js') or '/js/' in url_lower:
                    return True
            elif pattern == 'css':
                # 只匹配真正的CSS文件
                if url_lower.endswith('.css') or '/css/' in url_lower:
                    return True
            else:
                # 其他模式保持原有逻辑
                if pattern in url_lower:
                    return True

        return False

    def analyze_login_apis(self, all_flows: List[Dict]) -> Dict:
        """完整的登录API分析算法（在清洗阶段执行）

        Args:
            all_flows: 所有流数据

        Returns:
            Dict: 登录API分析结果
        """
        print("🔍 开始完整的登录API分析...")

        # 第一部分：通过行为特征发现登录提交页
        login_submits = self._discover_login_submits_by_behavior(all_flows)
        print(f"📤 发现 {len(login_submits)} 个登录提交页候选")

        # 第二部分：通过关键字匹配发现登录页面
        login_pages = self._discover_login_pages_by_keywords(all_flows)
        print(f"🏠 发现 {len(login_pages)} 个登录页面候选")

        # 第三部分：建立关联关系和综合评分
        login_pairs = self._match_login_pages_and_submits(login_pages, login_submits)
        print(f"🔗 建立 {len(login_pairs)} 个登录页面-提交页关联")

        # 第四部分：为每个域名推荐最佳登录URL
        recommendations = self._recommend_login_urls(login_pairs, login_pages, login_submits)

        return {
            'login_submits': login_submits,
            'login_pages': login_pages,
            'login_pairs': login_pairs,
            'recommendations': recommendations
        }

    def _discover_login_submits_by_behavior(self, all_flows: List[Dict]) -> List[Dict]:
        """第一部分：通过行为特征发现登录提交页"""
        candidates = []

        for flow in all_flows:
            url = flow.get('url', '')
            method = flow.get('method', '').upper()
            request_body = flow.get('request_body', '')

            # 必须是POST请求
            if method != 'POST':
                continue

            if not request_body:
                continue

            # 处理bytes类型
            if isinstance(request_body, bytes):
                try:
                    request_body = request_body.decode('utf-8', errors='ignore')
                except:
                    request_body = str(request_body)

            request_body_lower = request_body.lower()

            # 🎯 检测认证字段
            auth_indicators = [
                'loginid', 'userid', 'username', 'user', 'login',
                'password', 'passwd', 'pwd', 'pass',
                'vercode', 'captcha', 'verify'
            ]

            auth_field_count = sum(1 for indicator in auth_indicators if indicator in request_body_lower)

            # 至少包含2个认证相关字段
            if auth_field_count >= 2:
                score = self._score_login_submit_by_behavior(url, flow)
                candidates.append({
                    'url': url,
                    'type': 'submit',
                    'score': score,
                    'auth_field_count': auth_field_count,
                    'method': method,
                    'domain': self._extract_domain(url)
                })

        return candidates

    def _discover_login_pages_by_keywords(self, all_flows: List[Dict]) -> List[Dict]:
        """第二部分：通过关键字匹配发现登录页面"""
        candidates = []

        for flow in all_flows:
            url = flow.get('url', '')
            method = flow.get('method', '').upper()

            # 通常是GET请求
            if method != 'GET':
                continue

            url_lower = url.lower()

            # 🎯 扩展登录页面关键字，包含lgn缩写
            page_keywords = ['login', 'logon', 'signin', 'lgn']

            has_keyword = any(keyword in url_lower for keyword in page_keywords)
            if not has_keyword:
                continue

            # 🎯 修改排除逻辑：不排除.jsp文件，因为它们通常是真正的登录页面
            exclude_patterns = ['servlet', 'submit', 'authenticate', '.css', '.png', '.jpg', '.gif']
            # 移除了 '.js' 避免误杀 .jsp 文件
            if any(pattern in url_lower for pattern in exclude_patterns):
                continue

            score = self._score_login_page_by_keywords(url, flow)
            candidates.append({
                'url': url,
                'type': 'page',
                'score': score,
                'method': method,
                'domain': self._extract_domain(url)
            })

        return candidates

    def check_authentication_context(self, url: str, response_content: str, analysis_result) -> bool:
        """检查API是否具有鉴权上下文（评分因子，不是门槛）

        Args:
            url: API URL
            response_content: 响应内容
            analysis_result: 分析结果对象

        Returns:
            bool: 是否检测到鉴权上下文
        """
        auth_config = self.features_config.get("analysis_configuration", {}).get("api_classification", {}).get("authentication_indicators", {})

        if not auth_config:
            return False  # 如果没有配置，返回False（不影响准入）

        url_auth_params = auth_config.get("url_auth_params", [])
        response_auth_fields = auth_config.get("response_auth_fields", [])

        url_lower = url.lower()

        # 🎯 检查URL中的鉴权参数
        for auth_param in url_auth_params:
            if auth_param.lower() in url_lower:
                return True

        # 🎯 检查响应内容中的鉴权字段
        if response_content:
            response_lower = response_content.lower()
            for auth_field in response_auth_fields:
                if auth_field.lower() in response_lower:
                    return True

        # 🎯 不再进行推定，只检测明确的鉴权信息
        return False

    def _score_login_submit_by_behavior(self, url: str, flow: Dict) -> int:
        """为登录提交页评分（行为特征）"""
        score = 0
        url_lower = url.lower()

        # URL关键字评分
        submit_keywords = ['login', 'logon', 'authenticate', 'signin', 'submit', 'default']
        for keyword in submit_keywords:
            if keyword in url_lower:
                score += 10
                break

        # POST方法基础分
        score += 15

        # 请求体认证字段评分
        request_body = flow.get('request_body', '')
        if request_body:
            if isinstance(request_body, bytes):
                try:
                    request_body = request_body.decode('utf-8', errors='ignore')
                except:
                    request_body = str(request_body)

            auth_fields = ['username', 'password', 'userid', 'pwd', 'loginid']
            for field in auth_fields:
                if field in request_body.lower():
                    score += 20
                    break

        # 响应特征评分
        response_headers = flow.get('response_headers', {})
        set_cookie = response_headers.get('Set-Cookie', '')
        if set_cookie and any(keyword in str(set_cookie).lower() for keyword in ['session', 'jsessionid', 'token']):
            score += 15

        status_code = flow.get('status_code', 0)
        if status_code in [302, 301]:
            score += 10
        elif status_code == 200:
            score += 5

        return score

    def _score_login_page_by_keywords(self, url: str, flow: Dict) -> int:
        """为登录页面评分（关键字匹配）"""
        score = 0
        url_lower = url.lower()

        # 🎯 URL关键字评分（增加lgn支持）
        if 'lgn' in url_lower and ('index' in url_lower or '.jsp' in url_lower):
            score += 20  # lgn + 具体页面文件，很可能是真正的登录页
        elif 'login' in url_lower:
            score += 15
        elif 'logon' in url_lower:
            score += 12
        elif 'signin' in url_lower:
            score += 10

        # 🎯 文件类型评分（提高具体页面文件的分数）
        if url_lower.endswith('.jsp'):
            score += 15  # JSP页面通常是具体的功能页面
        elif any(ext in url_lower for ext in ['.html', '.htm', '.php']):
            score += 12
        elif url_lower.endswith('/login') or url_lower.endswith('/logon'):
            score += 8  # 简单路径分数降低

        # 🎯 路径深度评分（更深的路径可能更具体）
        path_depth = url.count('/') - 2  # 减去协议部分
        if path_depth >= 2:
            score += 5  # 深层路径加分

        # 🎯 具体性评分
        if any(keyword in url_lower for keyword in ['index', 'main', 'form']):
            score += 8  # 包含具体功能关键字

        # GET方法基础分
        score += 5

        # 响应状态评分
        status_code = flow.get('status_code', 0)
        if status_code == 200:
            score += 5

        return score

    def _match_login_pages_and_submits(self, login_pages: List[Dict], login_submits: List[Dict]) -> List[Dict]:
        """第三部分：建立登录页面和提交页的关联关系"""
        pairs = []

        for submit in login_submits:
            submit_domain = submit['domain']
            submit_url = submit['url']

            # 寻找同域名的登录页面
            domain_pages = [page for page in login_pages if page['domain'] == submit_domain]

            if domain_pages:
                # 🎯 计算URL相似度，选择最匹配的页面（优先考虑距离）
                best_page = None
                best_similarity = 0
                best_combined_score = 0

                for page in domain_pages:
                    similarity = self._calculate_url_similarity(submit_url, page['url'])
                    # 🎯 综合考虑相似度和页面评分，但相似度权重更高
                    combined_score = similarity * 2 + page['score'] * 0.5

                    if combined_score > best_combined_score:
                        best_combined_score = combined_score
                        best_similarity = similarity
                        best_page = page

                if best_page:
                    # 综合评分：提交页评分 + 页面评分 + 相似度
                    combined_score = submit['score'] + best_page['score'] + best_similarity

                    pairs.append({
                        'domain': submit_domain,
                        'login_page': best_page,
                        'login_submit': submit,
                        'similarity': best_similarity,
                        'combined_score': combined_score
                    })

        return pairs

    def _recommend_login_urls(self, login_pairs: List[Dict], login_pages: List[Dict], login_submits: List[Dict]) -> Dict:
        """第四部分：为每个域名推荐最佳登录URL"""
        recommendations = {}

        # 按域名分组
        domains = set()
        for item in login_pairs + login_pages + login_submits:
            domains.add(item['domain'])

        for domain in domains:
            domain_pairs = [pair for pair in login_pairs if pair['domain'] == domain]
            domain_pages = [page for page in login_pages if page['domain'] == domain]
            domain_submits = [submit for submit in login_submits if submit['domain'] == domain]

            best_url = None
            best_score = 0
            recommendation_type = 'none'

            # 优先选择有配对的登录页面
            if domain_pairs:
                best_pair = max(domain_pairs, key=lambda x: x['combined_score'])
                best_url = best_pair['login_page']['url']
                best_score = best_pair['combined_score']
                recommendation_type = 'paired_page'

            # 其次选择独立的登录页面
            elif domain_pages:
                best_page = max(domain_pages, key=lambda x: x['score'])
                best_url = best_page['url']
                best_score = best_page['score']
                recommendation_type = 'standalone_page'

            # 最后选择登录提交页（去掉参数）
            elif domain_submits:
                best_submit = max(domain_submits, key=lambda x: x['score'])
                best_url = best_submit['url'].split('?')[0]
                best_score = best_submit['score']
                recommendation_type = 'submit_fallback'

            if best_url:
                recommendations[domain] = {
                    'login_url': best_url,
                    'score': best_score,
                    'type': recommendation_type,
                    'confidence': min(best_score / 100.0, 1.0)  # 转换为0-1的置信度
                }

        return recommendations

    def _extract_domain(self, url: str) -> str:
        """提取域名"""
        from urllib.parse import urlparse
        return urlparse(url).netloc

    def _calculate_url_similarity(self, url1: str, url2: str) -> int:
        """计算URL相似度评分"""
        from urllib.parse import urlparse

        parsed1 = urlparse(url1)
        parsed2 = urlparse(url2)

        score = 0

        # 路径相似度
        path1_parts = parsed1.path.strip('/').split('/')
        path2_parts = parsed2.path.strip('/').split('/')

        common_parts = set(path1_parts) & set(path2_parts)
        if common_parts:
            score += len(common_parts) * 3

        # 路径长度相似
        if abs(len(path1_parts) - len(path2_parts)) <= 1:
            score += 5

        return score


def main():
    """命令行测试接口"""
    import argparse

    parser = argparse.ArgumentParser(description='金融API特征分析器测试')
    parser.add_argument('--test-url', '-u', help='测试单个URL')
    parser.add_argument('--config', '-c', help='特征配置文件路径')

    args = parser.parse_args()

    # 创建分析器
    analyzer = FinancialAPIAnalyzer(args.config)

    if args.test_url:
        # 测试单个URL
        result = analyzer.analyze_api(args.test_url)
        print(f"URL: {args.test_url}")
        print(f"机构: {result.institution} ({result.institution_type})")
        print(f"价值评分: {result.value_score}")
        print(f"优先级: {result.priority_level}")
        print(f"匹配模式: {result.matched_patterns}")
        print(f"数据类型: {result.data_types}")
        print(f"认证检测: {result.authentication_detected}")
    else:
        # 测试示例URL列表
        test_urls = [
            "https://its.bochk.com/acc.overview.do",
            "https://www.cmbwinglungbank.com/ibanking/McpCSReqServlet",
            "https://api.binance.com/api/v3/account",
            "https://chase.com/api/authentication/login",
            "https://www.hsbc.com.hk/css/styles.css"
        ]

        print("🔍 金融API特征分析测试")
        print("=" * 50)

        for url in test_urls:
            result = analyzer.analyze_api(url)
            print(f"\nURL: {url}")
            print(f"机构: {result.institution or '未识别'} ({result.institution_type or 'N/A'})")
            print(f"评分: {result.value_score} | 优先级: {result.priority_level}")
            print(f"匹配: {len(result.matched_patterns)}个模式")


if __name__ == "__main__":
    main()
