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

        关键原则：
        1. responseMatches数组：一定是能匹配成功，才能纳入
        2. responseRedactions数组：是要能提取出用户的金融信息

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

        # 🎯 首先判断响应内容的格式类型
        content_type = self._detect_content_type(response_content)
        print(f"🔍 响应内容类型: {content_type}, 长度: {len(response_content)}")

        # 🎯 根据实际内容和特征分析结果生成匹配规则
        if api_data and 'matched_patterns' in api_data:
            matched_patterns = api_data['matched_patterns']
            print(f"🔍 特征分析识别的模式: {matched_patterns}")

            order_counter = 1
            processed_patterns = set()  # 防止重复处理相同模式

            # 🎯 根据实际匹配的模式生成对应的正则表达式
            for pattern in matched_patterns:
                # 跳过已处理的模式
                if pattern in processed_patterns:
                    print(f"🔄 跳过重复模式: {pattern}")
                    continue
                processed_patterns.add(pattern)
                print(f"🔍 处理模式: {pattern}")
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

                    # 🎯 根据响应类型决定是否使用jsonPath
                    json_path = "" if self._is_html_response(matched_patterns) else f"$.{field_name}"

                    response_redactions.append({
                        "xPath": "",
                        "jsonPath": json_path,
                        "regex": f'"{field_name}":\\s*"?(?P<field_value>[^",\\}}]+)"?',
                        "hash": "sha256" if self._is_sensitive_field(field_name) else "",
                        "order": order_counter
                    })
                    order_counter += 1

                elif ("html_content:balance" in pattern or ("content:balance" in pattern and content_type == "html") or
                      ("html_currency:" in pattern and any("html_currency:" in p for p in matched_patterns))):
                    # 🎯 HTML余额相关API - 应用优先级匹配规则：从严格到宽松
                    print(f"🎯 DEBUG: 触发HTML余额优先级匹配规则! pattern={pattern}, matched_patterns={matched_patterns}")
                    balance_rules = self._generate_priority_balance_rules(matched_patterns, response_content)
                    print(f"🎯 DEBUG: 生成的优先级规则数量: {len(balance_rules)}")

                    if balance_rules:
                        # 添加所有优先级规则到responseMatches和responseRedactions
                        for rule in balance_rules:
                            response_matches.append({
                                "value": rule["regex"],
                                "type": "regex",
                                "invert": False,
                                "description": rule["description"],
                                "order": order_counter,
                                "isOptional": rule.get("isOptional", False)
                            })

                            response_redactions.append({
                                "xPath": "",
                                "jsonPath": "",
                                "regex": rule["regex"],
                                "hash": "",
                                "order": order_counter
                            })
                            order_counter += 1
                    else:
                        # 降级使用原有的简单余额匹配规则
                        print(f"⚠️ DEBUG: 优先级规则生成失败，使用降级规则")
                        response_matches.append({
                            "value": "balance|Balance|余额|可用|available|current",
                            "type": "contains",
                            "invert": False,
                            "description": "验证HTML中包含余额相关文本",
                            "order": order_counter,
                            "isOptional": False
                        })

                        response_redactions.append({
                            "xPath": "",
                            "jsonPath": "",
                            "regex": "(?P<balance_keyword>balance|Balance|余额|可用|available|current)",
                            "hash": "",
                            "order": order_counter
                        })
                        order_counter += 1



                elif "html_content:account" in pattern or ("content:account" in pattern and content_type == "html"):
                    # HTML账户相关API - 🎯 只生成实际能匹配的规则
                    actual_accounts = self._extract_actual_accounts(response_content)

                    if actual_accounts:
                        # 🎯 验证账户号码正则表达式的有效性（修复单词边界问题）
                        account_regex = "(?P<account_number>\\d{8,20}(?=[A-Z])|[A-Z]{2,4}\\d{8,16})"
                        if self._validate_regex_effectiveness(response_content, account_regex, "账户号码"):
                            # 为实际存在的账户号码生成匹配规则
                            response_matches.append({
                                "value": "\\d{8,20}(?=[A-Z])|[A-Z]{2,4}\\d{8,16}",
                                "type": "regex",
                                "invert": False,
                                "description": f"验证HTML中的实际账户号码",
                                "order": order_counter,
                                "isOptional": False
                            })

                            response_redactions.append({
                                "xPath": "",
                                "jsonPath": "",
                                "regex": account_regex,
                                "hash": "sha256",
                                "order": order_counter
                            })
                            order_counter += 1
                            print(f"✅ 生成账户匹配规则: {len(actual_accounts)}个实际账户")
                        else:
                            print(f"⚠️ 跳过生成账户号码匹配规则 - 质量评估未通过")
                    else:
                        print(f"⚠️ 跳过账户模式 - 响应中未找到实际账户号码")

                    # 🎯 二次判断：检查账户关键字的上下文是否符合用户信息格式
                    if self._validate_account_context(response_content):
                        response_matches.append({
                            "value": "account|Account|账户|账号",
                            "type": "contains",
                            "invert": False,
                            "description": "验证HTML中包含账户相关文本",
                            "order": order_counter,
                            "isOptional": True  # 🎯 设为可选，避免运行时验证失败
                        })

                        response_redactions.append({
                            "xPath": "",
                            "jsonPath": "",
                            "regex": "(?P<account_keyword>account|Account|账户|账号)",  # 🎯 添加命名捕获组
                            "hash": "",
                            "order": order_counter
                        })
                        order_counter += 1
                        print(f"✅ 生成账户关键字匹配规则（通过上下文验证）")
                    else:
                        print(f"⚠️ 跳过账户关键字匹配 - 上下文不符合用户信息格式")

                elif "json_content:account" in pattern or (("content:account" in pattern or "content:acc" in pattern or "account" in pattern or "acc" in pattern) and content_type == "json"):
                    # 账户相关API - 生成多种账户信息验证规则
                    account_patterns = [
                        {
                            "value": self._get_account_regex(matched_patterns),  # 🎯 根据响应类型动态生成
                            "type": "regex",
                            "description": "验证账户号码字段",
                            "jsonPath": "" if self._is_html_response(matched_patterns) else "$.account*",
                            "regex": self._get_account_regex(matched_patterns),  # 🎯 根据响应类型动态生成
                            "hash": "sha256"
                        },
                        {
                            "value": self._get_account_type_regex(matched_patterns),  # 🎯 根据响应类型动态生成
                            "type": "regex",
                            "description": "验证账户类型和状态",
                            "jsonPath": "" if self._is_html_response(matched_patterns) else "$.accountType,$.accountStatus",
                            "regex": self._get_account_type_regex(matched_patterns),  # 🎯 根据响应类型动态生成
                            "hash": ""
                        }
                    ]

                    for acc_pattern in account_patterns:
                        response_matches.append({
                            "value": acc_pattern["value"],
                            "type": acc_pattern["type"],
                            "invert": False,
                            "description": acc_pattern["description"],
                            "order": order_counter,
                            "isOptional": False
                        })

                        response_redactions.append({
                            "xPath": "",
                            "jsonPath": acc_pattern["jsonPath"],
                            "regex": acc_pattern["regex"],
                            "hash": acc_pattern["hash"],
                            "order": order_counter
                        })
                        order_counter += 1

                elif "content:login" in pattern or "content:logon" in pattern:
                    # 🚫 跳过登录态相关的匹配 - 不是为了构建provider的
                    print(f"🚫 跳过登录态模式: {pattern} - 登录态不是用户金融数据")
                    continue

                elif "html_content:currency" in pattern or "html_currency:" in pattern or ("content:currency" in pattern and content_type == "html"):
                    # HTML货币相关API - 🎯 只生成实际能匹配的规则
                    # 先验证响应中实际包含的货币代码
                    actual_currencies = self._extract_actual_currencies(response_content)

                    if actual_currencies:
                        # 只为实际存在的货币代码生成匹配规则
                        currency_regex = "|".join(actual_currencies)
                        response_matches.append({
                            "value": f"(?P<currency>{currency_regex})",  # 🎯 添加命名捕获组
                            "type": "regex",
                            "invert": False,
                            "description": f"验证HTML中的货币代码: {', '.join(actual_currencies)}",
                            "order": order_counter,
                            "isOptional": False
                        })

                        response_redactions.append({
                            "xPath": "",
                            "jsonPath": "",
                            "regex": f"(?P<currency>{currency_regex})",  # 🎯 添加命名捕获组
                            "hash": "",
                            "order": order_counter
                        })
                        order_counter += 1
                        print(f"✅ 生成货币匹配规则: {actual_currencies}")
                    else:
                        print(f"⚠️ 跳过货币模式 - 响应中未找到实际货币代码")

                elif "json_content:currency" in pattern or "json_currency:" in pattern:
                    # JSON货币相关API - 生成JSON货币验证和提取规则
                    json_currency_patterns = [
                        {
                            "value": self._get_currency_regex(matched_patterns),  # 🎯 根据响应类型动态生成
                            "type": "regex",
                            "description": "验证货币代码字段",
                            "jsonPath": "" if self._is_html_response(matched_patterns) else "$.currency,$.currencyCode",
                            "regex": self._get_currency_regex(matched_patterns),  # 🎯 根据响应类型动态生成
                            "hash": ""
                        },
                        {
                            "value": self._get_major_currency_regex(matched_patterns),  # 🎯 根据响应类型动态生成
                            "type": "regex",
                            "description": "验证主要货币类型",
                            "jsonPath": "" if self._is_html_response(matched_patterns) else "$..*",
                            "regex": self._get_major_currency_regex(matched_patterns),  # 🎯 根据响应类型动态生成
                            "hash": ""
                        }
                    ]

                    for currency_pattern in json_currency_patterns:
                        response_matches.append({
                            "value": currency_pattern["value"],
                            "type": currency_pattern["type"],
                            "invert": False,
                            "description": currency_pattern["description"],
                            "order": order_counter,
                            "isOptional": False
                        })

                        response_redactions.append({
                            "xPath": "",
                            "jsonPath": currency_pattern["jsonPath"],
                            "regex": currency_pattern["regex"],
                            "hash": currency_pattern["hash"],
                            "order": order_counter
                        })
                        order_counter += 1

                elif "html_content:amount" in pattern or ("content:amount" in pattern and content_type == "html"):
                    # HTML金额相关API - 🎯 只生成实际能匹配的规则
                    actual_amounts = self._extract_actual_amounts(response_content)

                    if actual_amounts:
                        # 为实际存在的金额格式生成匹配规则
                        response_matches.append({
                            "value": self._get_formatted_amount_regex(matched_patterns),  # 🎯 根据响应类型动态生成
                            "type": "regex",
                            "invert": False,
                            "description": f"验证HTML中的实际金额格式",
                            "order": order_counter,
                            "isOptional": False
                        })

                        response_redactions.append({
                            "xPath": "",
                            "jsonPath": "",
                            "regex": self._get_formatted_amount_regex(matched_patterns),  # 🎯 根据响应类型动态生成
                            "hash": "",
                            "order": order_counter
                        })
                        order_counter += 1
                        print(f"✅ 生成金额匹配规则: {len(actual_amounts)}个实际金额")
                    else:
                        print(f"⚠️ 跳过金额模式 - 响应中未找到实际金额格式")

                elif "json_content:amount" in pattern or "amount" in pattern or "金额" in pattern:
                    # 金额相关API - 生成金额验证和提取规则
                    amount_patterns = [
                        {
                            "value": self._get_amount_regex(matched_patterns),  # 🎯 根据响应类型动态生成
                            "type": "regex",
                            "description": "验证金额数值字段",
                            "jsonPath": "" if self._is_html_response(matched_patterns) else "$.amount,$.value",
                            "regex": self._get_amount_regex(matched_patterns),  # 🎯 根据响应类型动态生成
                            "hash": ""
                        },
                        {
                            "value": self._get_formatted_amount_regex(matched_patterns),  # 🎯 根据响应类型动态生成
                            "type": "regex",
                            "description": "验证格式化金额",
                            "jsonPath": "" if self._is_html_response(matched_patterns) else "$..*",
                            "regex": self._get_formatted_amount_regex(matched_patterns),  # 🎯 根据响应类型动态生成
                            "hash": ""
                        }
                    ]

                    for amount_pattern in amount_patterns:
                        response_matches.append({
                            "value": amount_pattern["value"],
                            "type": amount_pattern["type"],
                            "invert": False,
                            "description": amount_pattern["description"],
                            "order": order_counter,
                            "isOptional": False
                        })

                        response_redactions.append({
                            "xPath": "",
                            "jsonPath": amount_pattern["jsonPath"],
                            "regex": amount_pattern["regex"],
                            "hash": amount_pattern["hash"],
                            "order": order_counter
                        })
                        order_counter += 1

                elif "content:user_info" in pattern or "content:customer" in pattern or "content:name" in pattern:
                    # 用户信息相关API - 生成用户信息验证和提取规则
                    # 🎯 生成用户姓名模式前先验证有效性
                    potential_user_patterns = [
                        {
                            "value": self._get_user_name_regex(matched_patterns),
                            "type": "regex",
                            "description": "验证用户姓名字段",
                            "jsonPath": "" if self._is_html_response(matched_patterns) else "$.user_name,$.customer_name,$.holder_name,$.full_name",
                            "regex": self._get_user_name_regex(matched_patterns),
                            "hash": "sha256",
                            "field_name": "用户姓名"
                        },
                        {
                            "value": self._get_name_component_regex(matched_patterns),
                            "type": "regex",
                            "description": "验证姓名组件字段",
                            "jsonPath": "" if self._is_html_response(matched_patterns) else "$.first_name,$.last_name,$.display_name",
                            "regex": self._get_name_component_regex(matched_patterns),
                            "hash": "sha256",
                            "field_name": "姓名组件"
                        }
                    ]

                    # 🎯 验证每个用户姓名模式的有效性
                    user_patterns = []
                    for pattern in potential_user_patterns:
                        if self._validate_regex_effectiveness(response_content, pattern["regex"], pattern["field_name"]):
                            user_patterns.append(pattern)
                        else:
                            print(f"⚠️ 跳过生成 {pattern['field_name']} 的匹配规则")

                    for user_pattern in user_patterns:
                        response_matches.append({
                            "value": user_pattern["value"],
                            "type": user_pattern["type"],
                            "invert": False,
                            "description": user_pattern["description"],
                            "order": order_counter,
                            "isOptional": False
                        })

                        response_redactions.append({
                            "xPath": "",
                            "jsonPath": user_pattern["jsonPath"],
                            "regex": user_pattern["regex"],
                            "hash": user_pattern["hash"],
                            "order": order_counter
                        })
                        order_counter += 1

                elif "content:asset" in pattern or "content:wealth" in pattern:
                    # 资产相关API - 生成资产信息验证和提取规则
                    asset_patterns = [
                        {
                            "value": self._get_total_asset_regex(matched_patterns),  # 🎯 根据响应类型动态生成
                            "type": "regex",
                            "description": "验证总资产字段",
                            "jsonPath": "" if self._is_html_response(matched_patterns) else "$.total_asset,$.net_worth,$.portfolio_value",
                            "regex": self._get_total_asset_regex(matched_patterns),  # 🎯 根据响应类型动态生成
                            "hash": ""
                        },
                        {
                            "value": self._get_market_value_regex(matched_patterns),  # 🎯 根据响应类型动态生成
                            "type": "regex",
                            "description": "验证市值字段",
                            "jsonPath": "" if self._is_html_response(matched_patterns) else "$.market_value,$.book_value,$.investment_value",
                            "regex": self._get_market_value_regex(matched_patterns),  # 🎯 根据响应类型动态生成
                            "hash": ""
                        }
                    ]

                    for asset_pattern in asset_patterns:
                        response_matches.append({
                            "value": asset_pattern["value"],
                            "type": asset_pattern["type"],
                            "invert": False,
                            "description": asset_pattern["description"],
                            "order": order_counter,
                            "isOptional": False
                        })

                        response_redactions.append({
                            "xPath": "",
                            "jsonPath": asset_pattern["jsonPath"],
                            "regex": asset_pattern["regex"],
                            "hash": asset_pattern["hash"],
                            "order": order_counter
                        })
                        order_counter += 1

                elif pattern.startswith("core_banking:"):
                    # 核心银行业务 - 生成金融数据验证规则
                    response_matches.append({
                        "value": self._get_core_banking_regex(matched_patterns),  # 🎯 根据响应类型动态生成
                        "type": "regex",
                        "invert": False,
                        "description": "验证核心银行业务数据",
                        "order": order_counter,
                        "isOptional": False
                    })

                    response_redactions.append({
                        "xPath": "",
                        "jsonPath": "",
                        "regex": self._get_core_banking_regex(matched_patterns),  # 🎯 根据响应类型动态生成
                        "hash": "",
                        "order": order_counter
                    })
                    order_counter += 1

            if response_matches or response_redactions:
                print(f"✅ 成功生成: {len(response_matches)} 个验证规则, {len(response_redactions)} 个提取规则")

                # 🎯 去重处理：移除重复的responseMatches和responseRedactions
                response_matches = self._deduplicate_response_matches(response_matches)
                response_redactions = self._deduplicate_response_redactions(response_redactions)

                print(f"🔧 去重后: responseMatches {len(response_matches)}个, responseRedactions {len(response_redactions)}个")

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
                        "regex": f'"{pattern["field"]}":(?P<field_value>.*)',  # 🎯 添加命名捕获组
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
                        "regex": f'"{pattern["field"]}":"(?P<field_value>.*)"',  # 🎯 添加命名捕获组
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
                    "customInjection": None,
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

    def _detect_content_type(self, content: str) -> str:
        """检测内容类型

        Args:
            content: 响应内容

        Returns:
            str: 内容类型 ('json', 'html', 'text')
        """
        if not content:
            return 'text'

        content_stripped = content.strip()

        # 检查JSON格式
        if (content_stripped.startswith('{') and content_stripped.endswith('}')) or \
           (content_stripped.startswith('[') and content_stripped.endswith(']')):
            try:
                json.loads(content_stripped)
                return 'json'
            except json.JSONDecodeError:
                pass

        # 检查HTML格式
        if content_stripped.startswith('<') or \
           '<html' in content.lower() or \
           '<body' in content.lower() or \
           '<!doctype html' in content.lower():
            return 'html'

        # 默认为文本
        return 'text'

    def _extract_actual_currencies(self, content: str) -> List[str]:
        """从响应内容中提取实际存在的货币代码

        Args:
            content: 响应内容

        Returns:
            List[str]: 实际存在的货币代码列表
        """
        import re

        currencies = ['HKD', 'USD', 'CNY', 'EUR', 'GBP', 'JPY', 'AUD', 'CAD', 'SGD']
        found_currencies = []

        for currency in currencies:
            # 检查货币代码是否在有意义的上下文中出现
            currency_patterns = [
                rf'<td[^>]*>{currency}</td>',  # 表格单元格中
                rf'<span[^>]*>{currency}</span>',  # span标签中
                rf'{currency}\s*[0-9,]+\.?\d*',  # 货币代码后跟数字
                rf'[0-9,]+\.?\d*\s*{currency}',  # 数字后跟货币代码
            ]

            for pattern in currency_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    found_currencies.append(currency)
                    break

        return found_currencies

    def _extract_actual_amounts(self, content: str) -> List[str]:
        """从响应内容中提取实际存在的金额格式

        Args:
            content: 响应内容

        Returns:
            List[str]: 实际存在的金额格式列表
        """
        import re

        amount_patterns = [
            r'\$[0-9,]+\.[0-9]{2}',  # $1,234.56
            r'[0-9,]+\.[0-9]{2}\s*(HKD|USD|CNY|EUR|GBP|JPY)',  # 1,234.56 HKD
            r'(HKD|USD|CNY|EUR|GBP|JPY)\s*[0-9,]+\.[0-9]{2}',  # HKD 1,234.56
        ]

        found_amounts = []
        for pattern in amount_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                found_amounts.extend(matches[:3])  # 最多记录3个示例

        return found_amounts

    def _extract_actual_accounts(self, content: str) -> List[str]:
        """从响应内容中提取实际存在的账户号码

        Args:
            content: 响应内容

        Returns:
            List[str]: 实际存在的账户号码列表
        """
        import re

        account_patterns = [
            r'\b\d{8,20}\b',  # 8-20位数字
            r'\b[A-Z]{2,4}\d{8,16}\b',  # 字母+数字格式
        ]

        found_accounts = []
        for pattern in account_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                # 排除明显的日期格式
                if not (match.startswith('20') and len(match) == 8):  # 排除20140715这样的日期
                    if not (match.startswith('19') and len(match) == 8):  # 排除19xx年份
                        found_accounts.append(match)

        return found_accounts[:5]  # 最多返回5个

    def _deduplicate_response_matches(self, response_matches: List[Dict]) -> List[Dict]:
        """去除重复的responseMatches规则

        Args:
            response_matches: 原始的responseMatches列表

        Returns:
            List[Dict]: 去重后的responseMatches列表
        """
        seen = set()
        deduplicated = []

        for match in response_matches:
            # 创建唯一标识符：基于value和type
            identifier = (match['value'], match['type'])

            if identifier not in seen:
                seen.add(identifier)
                # 重新分配order，确保连续
                match['order'] = len(deduplicated) + 1
                deduplicated.append(match)
            else:
                print(f"🔄 去除重复的responseMatch: {match['description']}")

        return deduplicated

    def _deduplicate_response_redactions(self, response_redactions: List[Dict]) -> List[Dict]:
        """去除重复的responseRedactions规则

        Args:
            response_redactions: 原始的responseRedactions列表

        Returns:
            List[Dict]: 去重后的responseRedactions列表
        """
        seen = set()
        deduplicated = []

        for redaction in response_redactions:
            # 创建唯一标识符：基于regex和jsonPath
            identifier = (redaction.get('regex', ''), redaction.get('jsonPath', ''))

            if identifier not in seen:
                seen.add(identifier)
                # 重新分配order，确保连续
                redaction['order'] = len(deduplicated) + 1
                deduplicated.append(redaction)
            else:
                print(f"🔄 去除重复的responseRedaction: regex={redaction.get('regex', '')[:50]}...")

        return deduplicated

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

    def _is_html_response(self, matched_patterns: List[str]) -> bool:
        """判断是否为HTML响应

        Args:
            matched_patterns: 匹配的模式列表

        Returns:
            bool: 是否为HTML响应
        """
        return any("html_content:" in pattern for pattern in matched_patterns)

    def _is_json_response(self, matched_patterns: List[str]) -> bool:
        """判断是否为JSON响应

        Args:
            matched_patterns: 匹配的模式列表

        Returns:
            bool: 是否为JSON响应
        """
        return any("json_content:" in pattern for pattern in matched_patterns)

    def _get_user_name_regex(self, matched_patterns: List[str]) -> str:
        """根据响应类型生成用户姓名的正则表达式

        Args:
            matched_patterns: 匹配的模式列表

        Returns:
            str: 适合的正则表达式
        """
        if self._is_json_response(matched_patterns):
            # JSON格式：匹配JSON字段
            return "\"(?:user_?name|customer_?name|holder_?name|full_?name)\":\\s*\"(?P<user_name>[^\"]+)\""
        elif self._is_html_response(matched_patterns):
            # HTML格式：更精确的匹配，避免匹配HTML标签和无关文本
            # 匹配表格单元格或特定上下文中的姓名
            return "(?:姓名|客户|持有人|用户)[^>]*>\\s*(?P<user_name>[\\u4e00-\\u9fff]{2,4}|[A-Z][a-z]+\\s+[A-Z][a-z]+)"
        else:
            # 默认：尝试JSON格式
            return "\"(?:user_?name|customer_?name|holder_?name|full_?name)\":\\s*\"(?P<user_name>[^\"]+)\""

    def _get_name_component_regex(self, matched_patterns: List[str]) -> str:
        """根据响应类型生成姓名组件的正则表达式

        Args:
            matched_patterns: 匹配的模式列表

        Returns:
            str: 适合的正则表达式
        """
        if self._is_json_response(matched_patterns):
            # JSON格式：匹配JSON字段
            return "\"(?:first_?name|last_?name|display_?name)\":\\s*\"(?P<name_component>[^\"]+)\""
        elif self._is_html_response(matched_patterns):
            # HTML格式：更精确的匹配，在特定上下文中查找姓名组件
            # 匹配表格或表单中的姓名字段
            return "(?:名|姓)[^>]*>\\s*(?P<name_component>[\\u4e00-\\u9fff]{1,3}|[A-Z][a-z]+)"
        else:
            # 默认：尝试JSON格式
            return "\"(?:first_?name|last_?name|display_?name)\":\\s*\"(?P<name_component>[^\"]+)\""

    def _generate_priority_balance_rules(self, matched_patterns: List[str], response_content: str) -> List[Dict]:
        """🎯 生成优先级余额匹配规则：从严格到宽松

        Args:
            matched_patterns: 匹配的模式列表
            response_content: 响应内容

        Returns:
            List[Dict]: 按优先级排序的匹配规则列表
        """
        rules = []

        if self._is_html_response(matched_patterns):
            # 🎯 HTML响应：优先级匹配规则

            # 优先级1：严格规则 - 精确匹配纯净金额（HKD、USD、CNY）
            strict_rules = [
                {
                    "regex": "HKD.*?(?P<hkd_balance>\\d{1,3}(?:,\\d{3})*\\.\\d{2})",
                    "description": "严格规则：HKD精确匹配纯净金额",
                    "priority": 1,
                    "isOptional": True
                },
                {
                    "regex": "USD.*?(?P<usd_balance>\\d{1,3}(?:,\\d{3})*\\.\\d{2})",
                    "description": "严格规则：USD精确匹配纯净金额",
                    "priority": 1,
                    "isOptional": True
                },
                {
                    "regex": "CNY.*?(?P<cny_balance>\\d{1,3}(?:,\\d{3})*\\.\\d{2})",
                    "description": "严格规则：CNY精确匹配纯净金额",
                    "priority": 1,
                    "isOptional": True
                }
            ]

            # 优先级2：宽松规则 - 包含HTML结构的匹配（降级使用）
            loose_rules = [
                {
                    "regex": "(?P<hkd_balance>HKD.*?>([\\d,]+\\.\\d{2}))",
                    "description": "宽松规则：HKD包含HTML结构",
                    "priority": 2,
                    "isOptional": True
                },
                {
                    "regex": "(?P<usd_balance>USD.*?>([\\d,]+\\.\\d{2}))",
                    "description": "宽松规则：USD包含HTML结构",
                    "priority": 2,
                    "isOptional": True
                },
                {
                    "regex": "(?P<cny_balance>CNY.*?>([\\d,]+\\.\\d{2}))",
                    "description": "宽松规则：CNY包含HTML结构",
                    "priority": 2,
                    "isOptional": True
                }
            ]

            # 🎯 优先级匹配逻辑：严格规则优先，成功则跳过对应的宽松规则
            print(f"🔍 DEBUG: 测试严格规则，响应内容长度: {len(response_content)}")
            print(f"🔍 DEBUG: 响应内容前200字符: {repr(response_content[:200])}")

            # 记录已成功匹配的货币类型，避免重复
            matched_currencies = set()

            # 优先级1：测试严格规则
            for rule in strict_rules:
                print(f"🔍 DEBUG: 测试严格规则: {rule['description']}")
                print(f"🔍 DEBUG: 正则表达式: {rule['regex']}")
                if self._test_regex_match(response_content, rule["regex"]):
                    rules.append(rule)
                    print(f"✅ 严格规则有效: {rule['description']}")

                    # 记录已匹配的货币类型
                    if 'hkd_balance' in rule['regex']:
                        matched_currencies.add('hkd')
                    elif 'usd_balance' in rule['regex']:
                        matched_currencies.add('usd')
                    elif 'cny_balance' in rule['regex']:
                        matched_currencies.add('cny')
                else:
                    print(f"❌ 严格规则无效: {rule['description']}")

            # 优先级2：测试宽松规则（只测试严格规则未匹配的货币类型）
            for rule in loose_rules:
                currency_type = None
                if 'hkd_balance' in rule['regex']:
                    currency_type = 'hkd'
                elif 'usd_balance' in rule['regex']:
                    currency_type = 'usd'
                elif 'cny_balance' in rule['regex']:
                    currency_type = 'cny'

                # 🎯 关键：如果严格规则已经匹配了这个货币类型，跳过宽松规则
                if currency_type and currency_type in matched_currencies:
                    print(f"⏭️ 跳过宽松规则（严格规则已匹配）: {rule['description']}")
                    continue

                print(f"🔍 DEBUG: 测试宽松规则: {rule['description']}")
                print(f"🔍 DEBUG: 正则表达式: {rule['regex']}")
                if self._test_regex_match(response_content, rule["regex"]):
                    rules.append(rule)
                    print(f"⚠️ 宽松规则有效: {rule['description']}")
                else:
                    print(f"❌ 宽松规则无效: {rule['description']}")

        else:
            # JSON响应：使用标准规则
            rules.append({
                "regex": "\"balance\":\\s*(?P<balance>[0-9]+)",
                "description": "JSON余额标准规则",
                "priority": 1,
                "isOptional": False
            })

        return rules

    def _test_regex_match(self, content: str, regex_pattern: str) -> bool:
        """测试正则表达式是否能匹配内容"""
        try:
            import re
            # 🎯 使用DOTALL标志，让.匹配换行符，并添加详细调试
            match = re.search(regex_pattern, content, re.DOTALL)
            if match:
                print(f"✅ 正则匹配成功: {regex_pattern}")
                print(f"   匹配内容: {match.group()[:100]}...")
                if hasattr(match, 'groupdict') and match.groupdict():
                    print(f"   命名组: {match.groupdict()}")
                return True
            else:
                print(f"❌ 正则匹配失败: {regex_pattern}")
                return False
        except Exception as e:
            print(f"❌ 正则表达式测试失败: {regex_pattern}, 错误: {e}")
            return False

    def _get_balance_regex(self, matched_patterns: List[str]) -> str:
        """根据响应类型生成余额的正则表达式

        🎯 优先级匹配规则：从严格到宽松
        1. 严格规则：精确匹配纯净金额数字
        2. 宽松规则：包含HTML结构的匹配（降级使用）
        """
        if self._is_json_response(matched_patterns):
            return "\"balance\":\\s*(?P<balance>[0-9]+)"
        elif self._is_html_response(matched_patterns):
            # 🎯 HTML响应：返回宽松规则，后续在主流程中应用优先级清洗
            return "(?P<balance>\\d{1,10}(?:\\.\\d{2})?)"
        else:
            return "\"balance\":\\s*(?P<balance>[0-9]+)"

    def _get_account_regex(self, matched_patterns: List[str]) -> str:
        """根据响应类型生成账户的正则表达式"""
        if self._is_json_response(matched_patterns):
            return "\"(?:account[^\"]*|acc[^\"]*?)\":\\s*\"(?P<account_info>[^\"]+)\""
        elif self._is_html_response(matched_patterns):
            return "(?P<account_info>\\d{8,20}(?=[A-Z])|[A-Z]{2,4}\\d{8,16})"
        else:
            return "\"(?:account[^\"]*|acc[^\"]*?)\":\\s*\"(?P<account_info>[^\"]+)\""

    def _get_currency_regex(self, matched_patterns: List[str]) -> str:
        """根据响应类型生成货币的正则表达式"""
        if self._is_json_response(matched_patterns):
            return "\"(?:currency|currencyCode)\":\\s*\"(?P<currency>[A-Z]{3})\""
        elif self._is_html_response(matched_patterns):
            return "(?P<currency>HKD|USD|CNY|EUR|GBP|JPY|AUD|CAD|SGD)"
        else:
            return "\"(?:currency|currencyCode)\":\\s*\"(?P<currency>[A-Z]{3})\""

    def _get_amount_regex(self, matched_patterns: List[str]) -> str:
        """根据响应类型生成金额的正则表达式"""
        if self._is_json_response(matched_patterns):
            return "\"(?:amount|value)\":\\s*(?P<amount>[0-9.]+)"
        elif self._is_html_response(matched_patterns):
            return "(?P<amount>\\$?[0-9,]+(?:\\.\\d{2})?)"
        else:
            return "\"(?:amount|value)\":\\s*(?P<amount>[0-9.]+)"

    def _get_account_type_regex(self, matched_patterns: List[str]) -> str:
        """根据响应类型生成账户类型的正则表达式"""
        if self._is_json_response(matched_patterns):
            return "\"(?:accountType|accountStatus)\":\\s*\"(?P<account_type>[^\"]+)\""
        elif self._is_html_response(matched_patterns):
            return "(?P<account_type>储蓄|支票|定期|活期|Savings|Checking|Fixed|Current)"
        else:
            return "\"(?:accountType|accountStatus)\":\\s*\"(?P<account_type>[^\"]+)\""

    def _get_major_currency_regex(self, matched_patterns: List[str]) -> str:
        """根据响应类型生成主要货币的正则表达式"""
        if self._is_json_response(matched_patterns):
            return "\"(?P<major_currency>HKD|USD|CNY|EUR|GBP|JPY|AUD|CAD|SGD)\""
        elif self._is_html_response(matched_patterns):
            return "(?P<major_currency>HKD|USD|CNY|EUR|GBP|JPY|AUD|CAD|SGD)"
        else:
            return "\"(?P<major_currency>HKD|USD|CNY|EUR|GBP|JPY|AUD|CAD|SGD)\""

    def _get_formatted_amount_regex(self, matched_patterns: List[str]) -> str:
        """根据响应类型生成格式化金额的正则表达式"""
        if self._is_json_response(matched_patterns):
            return "(?P<formatted_amount>\\$[0-9,]+\\.\\d{2}|[0-9,]+\\.\\d{2}\\s*(?:HKD|USD|CNY))"
        elif self._is_html_response(matched_patterns):
            return "(?P<formatted_amount>\\$[0-9,]+\\.\\d{2}|[0-9,]+\\.\\d{2}\\s*(?:HKD|USD|CNY))"
        else:
            return "(?P<formatted_amount>\\$[0-9,]+\\.\\d{2}|[0-9,]+\\.\\d{2}\\s*(?:HKD|USD|CNY))"

    def _get_total_asset_regex(self, matched_patterns: List[str]) -> str:
        """根据响应类型生成总资产的正则表达式"""
        if self._is_json_response(matched_patterns):
            return "\"(?:total_?asset|net_?worth|portfolio_?value)\":\\s*(?P<total_asset>[0-9.]+)"
        elif self._is_html_response(matched_patterns):
            return "(?P<total_asset>[0-9,]+(?:\\.\\d{2})?)"
        else:
            return "\"(?:total_?asset|net_?worth|portfolio_?value)\":\\s*(?P<total_asset>[0-9.]+)"

    def _get_market_value_regex(self, matched_patterns: List[str]) -> str:
        """根据响应类型生成市值的正则表达式"""
        if self._is_json_response(matched_patterns):
            return "\"(?:market_?value|book_?value|investment_?value)\":\\s*(?P<market_value>[0-9.]+)"
        elif self._is_html_response(matched_patterns):
            return "(?P<market_value>[0-9,]+(?:\\.\\d{2})?)"
        else:
            return "\"(?:market_?value|book_?value|investment_?value)\":\\s*(?P<market_value>[0-9.]+)"

    def _get_core_banking_regex(self, matched_patterns: List[str]) -> str:
        """根据响应类型生成核心银行业务的正则表达式"""
        if self._is_json_response(matched_patterns):
            return "\"(?:amount|balance|value)\":\\s*(?P<balance_value>[0-9]+)"
        elif self._is_html_response(matched_patterns):
            return "(?P<balance_value>[0-9,]+(?:\\.\\d{2})?)"
        else:
            return "\"(?:amount|balance|value)\":\\s*(?P<balance_value>[0-9]+)"

    def _get_negative_patterns(self, keywords: List[str]) -> List[tuple]:
        """
        生成通用的负面指标规则

        Args:
            keywords: 要检查的关键字列表

        Returns:
            List[tuple]: (pattern, description, penalty) 的列表
        """
        patterns = []
        keyword_pattern = '|'.join(re.escape(kw) for kw in keywords)

        base_patterns = [
            (rf'<!--.*?(?:{keyword_pattern}).*?-->', 'HTML注释', -3),
            (rf'<script[^>]*>.*?(?:{keyword_pattern}).*?</script>', 'JavaScript', -3),
            (rf'<style[^>]*>.*?(?:{keyword_pattern}).*?</style>', 'CSS', -2),
            (rf'/\*.*?(?:{keyword_pattern}).*?\*/', 'CSS/JS注释', -2),
            (rf'console\.log.*?(?:{keyword_pattern})', 'Console日志', -2),
            (rf'//.*?(?:{keyword_pattern})', '单行注释', -1),
            (rf'function.*?(?:{keyword_pattern}).*?\{{', 'JavaScript函数', -2),
            (rf'var\s+.*?(?:{keyword_pattern}).*?=', 'JavaScript变量', -1),
            (rf'class.*?(?:{keyword_pattern}).*?\{{', 'CSS类', -1)
        ]

        return base_patterns

    def _validate_regex_effectiveness(self, content: str, regex: str, field_name: str) -> bool:
        """
        验证正则表达式的有效性，实际测试是否能匹配到有价值的内容

        Args:
            content: 响应内容
            regex: 正则表达式
            field_name: 字段名称

        Returns:
            bool: 是否应该保留这个正则表达式
        """
        import re

        try:
            matches = re.findall(regex, content)

            if not matches:
                print(f"⚠️ {field_name} 正则表达式无法匹配任何内容，跳过生成")
                return False

            # 规则1：账户号码 - 多个匹配时按质量筛选
            if 'account' in field_name.lower():
                return self._validate_account_matches(matches, field_name)

            # 规则2：用户姓名 - 匹配过多时放弃
            elif 'name' in field_name.lower():
                return self._validate_name_matches(matches, field_name)

            # 其他字段的基本验证
            else:
                if len(matches) > 100:
                    print(f"⚠️ {field_name} 匹配过多({len(matches)}个)，可能不准确，跳过生成")
                    return False
                return True

        except Exception as e:
            print(f"❌ {field_name} 正则表达式测试失败: {e}")
            return False

    def _validate_account_matches(self, matches: List[str], field_name: str) -> bool:
        """
        规则1：对账户号码匹配进行质量评估
        """
        if len(matches) == 0:
            return False

        print(f"🔍 {field_name} 找到 {len(matches)} 个匹配，进行质量评估")

        # 对每个匹配进行打分
        scored_matches = []
        for match in matches:
            score = 0

            # 长度评分：8-20位最佳
            if 8 <= len(match) <= 20:
                score += 3
            elif 6 <= len(match) <= 25:
                score += 1

            # 字符类型评分：包含数字和字母/连字符
            if re.search(r'\d', match):
                score += 2
            if re.search(r'[A-Z]', match):
                score += 1
            if '-' in match:
                score += 1

            # 紧凑性评分：避免过多空白字符
            if match.count(' ') <= 1:
                score += 1

            # 避免明显的日期格式
            if not re.match(r'^\d{8}$', match):  # 避免20140715这种日期
                score += 2

            scored_matches.append((match, score))

        # 排序并选择最佳匹配
        scored_matches.sort(key=lambda x: x[1], reverse=True)
        best_matches = [m for m, s in scored_matches if s >= 4]  # 至少4分

        print(f"   质量评估结果: {len(best_matches)} 个高质量匹配")
        if best_matches:
            print(f"   最佳匹配: {best_matches[:3]}")
            return True
        else:
            print(f"   没有高质量匹配，跳过生成")
            return False

    def _validate_name_matches(self, matches: List[str], field_name: str) -> bool:
        """
        规则2：对用户姓名匹配进行数量控制
        """
        print(f"🔍 {field_name} 找到 {len(matches)} 个匹配")

        # 如果匹配过多，说明正则表达式过于宽泛
        if len(matches) > 50:
            print(f"   匹配过多({len(matches)}个)，可能包含大量无关内容，跳过生成")
            return False

        # 检查匹配质量
        valid_matches = []
        for match in matches:
            # 过滤明显的无关内容
            if (len(match.strip()) < 2 or          # 太短
                '\n' in match or                   # 包含换行符
                'DOCTYPE' in match or              # HTML标签
                match.isspace() or                 # 只有空白字符
                len(match) > 20):                  # 太长
                continue
            valid_matches.append(match)

        print(f"   过滤后有效匹配: {len(valid_matches)} 个")
        if len(valid_matches) > 0 and len(valid_matches) <= 10:
            print(f"   有效匹配示例: {valid_matches[:3]}")
            return True
        else:
            print(f"   有效匹配数量不合理，跳过生成")
            return False

    def _validate_account_context(self, content: str) -> bool:
        """
        验证账户关键字的上下文是否符合真实的用户信息格式

        Args:
            content: 响应内容

        Returns:
            bool: 是否通过上下文验证
        """
        import re

        # 检查是否包含账户关键字
        account_keywords = ['account', 'Account', '账户', '账号']
        if not any(keyword in content for keyword in account_keywords):
            return False

        # 上下文验证规则
        validation_score = 0

        # 1. 检查是否有账户号码模式（8-20位数字或带字母前缀的账号）
        account_number_patterns = [
            r'\b\d{8,20}\b',  # 8-20位纯数字
            r'\b[A-Z]{2,4}\d{8,16}\b',  # 字母前缀+数字
            r'\b\d{4}[-\s]\d{4}[-\s]\d{4,12}\b'  # 分段账号
        ]

        for pattern in account_number_patterns:
            if re.search(pattern, content):
                validation_score += 2
                break

        # 2. 检查是否有金融相关字段
        financial_keywords = [
            'balance', 'Balance', '余额', '可用', 'available',
            'currency', 'Currency', '货币', 'HKD', 'USD', 'CNY',
            'amount', 'Amount', '金额', '数量'
        ]

        financial_count = sum(1 for keyword in financial_keywords if keyword in content)
        validation_score += min(financial_count, 3)  # 最多加3分

        # 3. 检查是否在表格或表单结构中
        structure_patterns = [
            r'<table[^>]*>.*?account.*?</table>',
            r'<form[^>]*>.*?account.*?</form>',
            r'<tr[^>]*>.*?account.*?</tr>',
            r'<div[^>]*class[^>]*account[^>]*>',
            r'"account[^"]*":\s*"[^"]*"'  # JSON格式
        ]

        for pattern in structure_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                validation_score += 2
                break

        # 4. 检查是否有用户信息相关字段
        user_info_keywords = [
            'name', 'Name', '姓名', '用户', 'customer', 'Customer',
            'holder', 'Holder', '持有人', 'owner', 'Owner'
        ]

        user_info_count = sum(1 for keyword in user_info_keywords if keyword in content)
        validation_score += min(user_info_count, 2)  # 最多加2分

        # 5. 负面指标：使用通用的负面指标规则
        negative_patterns = self._get_negative_patterns(account_keywords)

        for pattern, desc, penalty in negative_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                validation_score += penalty  # penalty是负数
                print(f"❌ 发现负面指标: {desc} (扣{abs(penalty)}分)")

        # 判断阈值：总分>=4分认为是有效的用户信息上下文
        threshold = 4
        is_valid = validation_score >= threshold

        print(f"🔍 账户上下文验证: 得分={validation_score}, 阈值={threshold}, 结果={'通过' if is_valid else '不通过'}")

        return is_valid

    def _validate_user_info_context(self, content: str) -> bool:
        """
        验证用户信息关键字的上下文是否符合真实的用户信息格式

        Args:
            content: 响应内容

        Returns:
            bool: 是否通过上下文验证
        """
        import re

        # 检查是否包含用户信息关键字
        user_keywords = ['name', 'Name', '姓名', '用户', 'customer', 'Customer', 'holder', 'Holder']
        if not any(keyword in content for keyword in user_keywords):
            return False

        validation_score = 0

        # 1. 检查是否有真实姓名模式
        name_patterns = [
            r'[\u4e00-\u9fff]{2,4}',  # 中文姓名
            r'[A-Z][a-z]+\s+[A-Z][a-z]+',  # 英文姓名
        ]

        for pattern in name_patterns:
            if re.search(pattern, content):
                validation_score += 2
                break

        # 2. 检查是否有用户信息相关字段
        user_fields = ['phone', 'email', 'address', 'id', 'card']
        user_field_count = sum(1 for field in user_fields if field in content)
        validation_score += min(user_field_count, 2)

        # 3. 负面指标：使用通用的负面指标规则
        negative_patterns = self._get_negative_patterns(user_keywords)

        for pattern, desc, penalty in negative_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                validation_score += penalty

        threshold = 3
        is_valid = validation_score >= threshold

        print(f"🔍 用户信息上下文验证: 得分={validation_score}, 阈值={threshold}, 结果={'通过' if is_valid else '不通过'}")

        return is_valid

    def _validate_financial_context(self, content: str) -> bool:
        """
        验证金融信息关键字的上下文是否符合真实的金融数据格式

        Args:
            content: 响应内容

        Returns:
            bool: 是否通过上下文验证
        """
        import re

        # 检查是否包含金融关键字
        financial_keywords = ['balance', 'Balance', '余额', 'amount', 'Amount', '金额', 'currency', 'Currency', '货币']
        if not any(keyword in content for keyword in financial_keywords):
            return False

        validation_score = 0

        # 1. 检查是否有金额数字模式
        amount_patterns = [
            r'\d+\.\d{2}',  # 小数金额
            r'\d{1,3}(,\d{3})*',  # 千分位格式
        ]

        for pattern in amount_patterns:
            if re.search(pattern, content):
                validation_score += 2
                break

        # 2. 检查是否有货币符号
        currency_symbols = ['$', '¥', '€', '£', 'HKD', 'USD', 'CNY']
        currency_count = sum(1 for symbol in currency_symbols if symbol in content)
        validation_score += min(currency_count, 2)

        # 3. 负面指标：使用通用的负面指标规则
        negative_patterns = self._get_negative_patterns(financial_keywords)

        for pattern, desc, penalty in negative_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                validation_score += penalty

        threshold = 3
        is_valid = validation_score >= threshold

        print(f"🔍 金融信息上下文验证: 得分={validation_score}, 阈值={threshold}, 结果={'通过' if is_valid else '不通过'}")

        return is_valid

    def _is_json_response(self, matched_patterns: List[str]) -> bool:
        """判断是否为JSON响应

        Args:
            matched_patterns: 匹配的模式列表

        Returns:
            bool: 是否为JSON响应
        """
        return any("json_content:" in pattern for pattern in matched_patterns)

    def _get_user_name_regex(self, matched_patterns: List[str]) -> str:
        """根据响应类型生成用户姓名的正则表达式

        Args:
            matched_patterns: 匹配的模式列表

        Returns:
            str: 适合的正则表达式
        """
        if self._is_json_response(matched_patterns):
            # JSON格式：匹配JSON字段
            return "\"(?:user_?name|customer_?name|holder_?name|full_?name)\":\\s*\"(?P<user_name>[^\"]+)\""
        elif self._is_html_response(matched_patterns):
            # HTML格式：匹配HTML中的姓名文本
            return "(?P<user_name>[\\u4e00-\\u9fff]{2,4}|[A-Za-z\\s]{2,20})"
        else:
            # 默认：尝试JSON格式
            return "\"(?:user_?name|customer_?name|holder_?name|full_?name)\":\\s*\"(?P<user_name>[^\"]+)\""

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

        # 🎯 构建可索引的provider结构
        providers_indexed = {}
        provider_index = {}

        for provider in successful_providers:
            provider_config = provider.get('providerConfig', {})
            provider_id = provider_config.get('providerId')

            if not provider_id:
                print(f"⚠️  跳过没有providerId的provider")
                continue

            # 添加到索引结构
            providers_indexed[provider_id] = provider

            # 构建索引元数据
            metadata = provider_config.get('providerConfig', {}).get('metadata', {})
            provider_index[provider_id] = {
                "institution": metadata.get('institution', ''),
                "api_type": metadata.get('api_type', ''),
                "priority_level": metadata.get('priority_level', 'medium'),
                "value_score": metadata.get('value_score', 0),
                "confidence_score": metadata.get('confidence_score', 0.0),
                "created_at": metadata.get('generated_at', ''),
                "config_id": provider_config.get('id', '')
            }

        # 保存成功的providers（新的可索引结构）
        providers_file = os.path.join(output_dir, f"reclaim_providers_{date_str}.json")
        providers_output = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "date": date_str,
                "total_providers": len(providers_indexed),
                "source_mitm_file": self.mitm_file_path,
                "source_analysis_file": self.analysis_result_file,
                "generator_version": "1.0.0",
                "index_structure": "providerId_based",
                "description": "Daily provider configurations indexed by providerId for efficient lookup"
            },
            "provider_index": provider_index,
            "providers": providers_indexed,
            "query_helpers": {
                "get_provider_by_id": "providers[providerId]",
                "get_provider_metadata": "provider_index[providerId]",
                "list_all_provider_ids": "Object.keys(providers)",
                "filter_by_institution": "Object.entries(provider_index).filter(([id, meta]) => meta.institution === institutionName)",
                "filter_by_api_type": "Object.entries(provider_index).filter(([id, meta]) => meta.api_type === apiType)",
                "filter_by_priority": "Object.entries(provider_index).filter(([id, meta]) => meta.priority_level === priority)"
            }
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

    @staticmethod
    def load_providers_by_date(date_str: str, data_dir: str = "data") -> Optional[Dict]:
        """按日期加载provider配置文件

        Args:
            date_str: 日期字符串，格式为YYYYMMDD
            data_dir: 数据目录

        Returns:
            Optional[Dict]: 加载的provider数据，如果文件不存在返回None
        """
        providers_file = os.path.join(data_dir, f"reclaim_providers_{date_str}.json")

        if not os.path.exists(providers_file):
            return None

        try:
            with open(providers_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"❌ 加载provider文件失败: {e}")
            return None

    @staticmethod
    def query_provider_by_id(provider_id: str, date_str: str, data_dir: str = "data") -> Optional[Dict]:
        """通过providerId查询provider配置

        Args:
            provider_id: Provider ID
            date_str: 日期字符串
            data_dir: 数据目录

        Returns:
            Optional[Dict]: Provider配置，如果不存在返回None
        """
        providers_data = ReclaimProviderBuilder.load_providers_by_date(date_str, data_dir)

        if not providers_data:
            return None

        return providers_data.get('providers', {}).get(provider_id)

    @staticmethod
    def query_providers_by_institution(institution: str, date_str: str, data_dir: str = "data") -> List[Dict]:
        """通过机构名查询providers

        Args:
            institution: 机构名
            date_str: 日期字符串
            data_dir: 数据目录

        Returns:
            List[Dict]: 匹配的providers列表
        """
        providers_data = ReclaimProviderBuilder.load_providers_by_date(date_str, data_dir)

        if not providers_data:
            return []

        provider_index = providers_data.get('provider_index', {})
        providers = providers_data.get('providers', {})

        matching_providers = []
        for provider_id, metadata in provider_index.items():
            if metadata.get('institution', '').lower() == institution.lower():
                provider_config = providers.get(provider_id)
                if provider_config:
                    matching_providers.append({
                        'provider_id': provider_id,
                        'metadata': metadata,
                        'config': provider_config
                    })

        return matching_providers

    @staticmethod
    def list_all_provider_ids(date_str: str, data_dir: str = "data") -> List[str]:
        """列出所有provider IDs

        Args:
            date_str: 日期字符串
            data_dir: 数据目录

        Returns:
            List[str]: Provider IDs列表
        """
        providers_data = ReclaimProviderBuilder.load_providers_by_date(date_str, data_dir)

        if not providers_data:
            return []

        return list(providers_data.get('providers', {}).keys())



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

