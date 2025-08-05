#!/usr/bin/env python3
"""
通用银行余额提取规则引擎
Universal Balance Extraction Rules Engine

基于7条核心规则的通用银行数据提取系统，不再按银行维度区分，
而是按照数据特征和提取模式进行统一处理。

核心设计理念：
- 规则1：银行识别规则 - 通用域名和API模式识别
- 规则2：货币识别规则 - 多语言货币符号和标识
- 规则3：金额格式规则 - 国际化数字格式处理
- 规则4：数据定位规则 - 多种数据结构适配
- 规则5：认证参数规则 - 通用session和token处理
- 规则6：上下文关联规则 - 智能数据关联分析
- 规则7：数据验证规则 - 通用数据质量保证
"""

import re
import json
import logging
from typing import Dict, List, Any, Optional, Tuple, Pattern
from dataclasses import dataclass
from enum import Enum
from abc import ABC, abstractmethod


class DataFormat(Enum):
    """数据格式类型"""
    HTML_TABLE = "html_table"
    JSON_API = "json_api" 
    JAVASCRIPT_VAR = "javascript_var"
    XML_DATA = "xml_data"
    FORM_DATA = "form_data"


class CurrencyRegion(Enum):
    """货币区域"""
    HONG_KONG = "HK"
    MAINLAND_CHINA = "CN"
    UNITED_STATES = "US"
    EUROPEAN_UNION = "EU"
    SINGAPORE = "SG"
    JAPAN = "JP"
    UNIVERSAL = "UNIVERSAL"


@dataclass
class ExtractionContext:
    """提取上下文"""
    url: str
    content: str
    headers: Dict[str, str]
    detected_format: Optional[DataFormat] = None
    detected_region: Optional[CurrencyRegion] = None
    confidence_score: float = 0.0


@dataclass
class BalanceData:
    """余额数据结构"""
    amount: str
    currency: str
    account_type: Optional[str] = None
    confidence: float = 0.0
    extraction_method: str = ""
    raw_context: str = ""


class Rule(ABC):
    """规则基类"""
    
    @abstractmethod
    def apply(self, context: ExtractionContext) -> Dict[str, Any]:
        """应用规则"""
        pass
    
    @abstractmethod
    def get_confidence(self, context: ExtractionContext) -> float:
        """获取规则置信度"""
        pass


class Rule1_BankIdentification(Rule):
    """规则1：银行识别规则 - 基于余额数据动态识别银行特征"""
    
    def __init__(self):
        # 通用地理区域识别模式（基于TLD和域名结构）
        self.geographic_indicators = {
            'hk_banks': {
                'tld_patterns': [r'\.com\.hk$', r'\.hk$'],
                'domain_keywords': ['hongkong', 'hk'],
                'typical_currencies': ['HKD', 'USD']
            },
            'cn_banks': {
                'tld_patterns': [r'\.com\.cn$', r'\.cn$'],
                'domain_keywords': ['china', 'cn', 'chinese'],
                'typical_currencies': ['CNY', 'RMB']
            },
            'sg_banks': {
                'tld_patterns': [r'\.com\.sg$', r'\.sg$'],
                'domain_keywords': ['singapore', 'sg'],
                'typical_currencies': ['SGD']
            },
            'us_banks': {
                'tld_patterns': [r'\.com$', r'\.us$'],
                'domain_keywords': ['america', 'usa', 'us'],
                'typical_currencies': ['USD']
            },
            'eu_banks': {
                'tld_patterns': [r'\.eu$', r'\.de$', r'\.fr$', r'\.it$'],
                'domain_keywords': ['europe', 'euro'],
                'typical_currencies': ['EUR']
            }
        }
        
        # 通用银行API特征词（不针对特定银行）
        self.generic_banking_keywords = [
            'balance', 'account', 'banking', 'finance', 'transaction',
            'overview', 'summary', 'wallet', 'deposit', 'credit',
            'servlet', 'api', 'service', 'query', 'proc'
        ]
    
    def apply(self, context: ExtractionContext) -> Dict[str, Any]:
        """基于地理特征和内容特征动态识别银行类型"""
        result = {
            'bank_region': None,
            'bank_type': 'unknown',
            'api_category': 'unknown',
            'confidence': 0.0,
            'geographic_confidence': 0.0,
            'banking_keyword_confidence': 0.0
        }
        
        url_lower = context.url.lower()
        max_confidence = 0.0
        best_region = None
        
        # 1. 基于地理特征识别区域
        for region, indicators in self.geographic_indicators.items():
            geo_confidence = 0.0
            
            # 检查TLD模式
            tld_matches = sum(1 for pattern in indicators['tld_patterns'] 
                             if re.search(pattern, url_lower))
            if tld_matches > 0:
                geo_confidence += 0.7  # TLD是强指标
            
            # 检查域名关键词
            domain_keyword_matches = sum(1 for keyword in indicators['domain_keywords']
                                       if keyword in url_lower)
            geo_confidence += domain_keyword_matches * 0.2
            
            # 检查内容中的货币类型是否匹配该区域
            content_lower = context.content.lower()
            currency_matches = sum(1 for currency in indicators['typical_currencies']
                                 if currency.lower() in content_lower)
            if currency_matches > 0:
                geo_confidence += 0.3  # 货币匹配是很强的指标
            
            if geo_confidence > max_confidence:
                max_confidence = geo_confidence
                best_region = region
                result['geographic_confidence'] = geo_confidence
        
        # 2. 检查通用银行关键词
        banking_keyword_score = 0.0
        for keyword in self.generic_banking_keywords:
            if keyword in url_lower:
                banking_keyword_score += 0.1
            if keyword in context.content.lower():
                banking_keyword_score += 0.05
        
        result['banking_keyword_confidence'] = min(banking_keyword_score, 1.0)
        
        # 3. 综合置信度
        # 地理置信度 * 0.6 + 银行关键词置信度 * 0.4 
        combined_confidence = (max_confidence * 0.6 + result['banking_keyword_confidence'] * 0.4)
        
        if combined_confidence > 0.1:  # 最低阈值
            result['bank_region'] = best_region
            result['confidence'] = combined_confidence
            result['api_category'] = self._determine_api_category(url_lower)
            result['bank_type'] = 'financial_institution'  # 通用类型
        
        return result
    
    def _determine_api_category(self, url_lower: str) -> str:
        """基于URL特征确定API类别"""
        if any(word in url_lower for word in ['balance', 'overview', 'summary']):
            return 'balance_query'
        elif any(word in url_lower for word in ['login', 'auth', 'logon']):
            return 'authentication'
        elif any(word in url_lower for word in ['transfer', 'payment']):
            return 'transaction'
        elif any(word in url_lower for word in ['history', 'statement']):
            return 'history'
        else:
            return 'general_banking'
    
    def get_confidence(self, context: ExtractionContext) -> float:
        return self.apply(context)['confidence']


class Rule2_CurrencyIdentification(Rule):
    """规则2：货币识别规则 - 多语言货币符号和标识"""
    
    def __init__(self):
        self.currency_patterns = {
            'HKD': {
                'symbols': ['HK$', 'HKD', '港币', '港元', '港幣'],
                'patterns': [
                    r'HKD?\s*\$?\s*(\d[\d,]*\.?\d*)',
                    r'港[币元幣]\s*[：:]\s*(\d[\d,]*\.?\d*)',
                    r'HK\$\s*(\d[\d,]*\.?\d*)'
                ],
                'region': CurrencyRegion.HONG_KONG
            },
            'USD': {
                'symbols': ['$', 'USD', '美元', '美金'],
                'patterns': [
                    r'USD?\s*\$?\s*(\d[\d,]*\.?\d*)',
                    r'美[元金]\s*[：:]\s*(\d[\d,]*\.?\d*)',
                    r'\$\s*(\d[\d,]*\.?\d*)'
                ],
                'region': CurrencyRegion.UNITED_STATES
            },
            'CNY': {
                'symbols': ['¥', 'CNY', '人民币', '元', 'RMB'],
                'patterns': [
                    r'CNY?\s*¥?\s*(\d[\d,]*\.?\d*)',
                    r'人民币\s*[：:]\s*(\d[\d,]*\.?\d*)',
                    r'¥\s*(\d[\d,]*\.?\d*)',
                    r'RMB\s*(\d[\d,]*\.?\d*)'
                ],
                'region': CurrencyRegion.MAINLAND_CHINA
            },
            'EUR': {
                'symbols': ['€', 'EUR', '欧元'],
                'patterns': [
                    r'EUR?\s*€?\s*(\d[\d,]*\.?\d*)',
                    r'€\s*(\d[\d,]*\.?\d*)'
                ],
                'region': CurrencyRegion.EUROPEAN_UNION
            },
            'SGD': {
                'symbols': ['S$', 'SGD', '新币'],
                'patterns': [
                    r'SGD?\s*S?\$?\s*(\d[\d,]*\.?\d*)',
                    r'S\$\s*(\d[\d,]*\.?\d*)'
                ],
                'region': CurrencyRegion.SINGAPORE
            }
        }
    
    def apply(self, context: ExtractionContext) -> Dict[str, Any]:
        """识别内容中的货币类型"""
        detected_currencies = []
        
        for currency, config in self.currency_patterns.items():
            # 检查货币符号
            symbol_found = any(symbol.lower() in context.content.lower() 
                             for symbol in config['symbols'])
            
            # 检查货币模式
            pattern_matches = []
            for pattern in config['patterns']:
                matches = re.findall(pattern, context.content, re.IGNORECASE)
                pattern_matches.extend(matches)
            
            if symbol_found or pattern_matches:
                detected_currencies.append({
                    'currency': currency,
                    'region': config['region'].value,
                    'symbol_found': symbol_found,
                    'amounts_found': len(pattern_matches),
                    'sample_amounts': pattern_matches[:3]  # 最多3个样本
                })
        
        return {
            'detected_currencies': detected_currencies,
            'primary_currency': detected_currencies[0]['currency'] if detected_currencies else None,
            'confidence': len(detected_currencies) / len(self.currency_patterns)
        }
    
    def get_confidence(self, context: ExtractionContext) -> float:
        return self.apply(context)['confidence']


class Rule3_AmountFormat(Rule):
    """规则3：金额格式规则 - 国际化数字格式处理"""
    
    def __init__(self):
        # 高质量金额模式 - 更严格的匹配
        self.amount_patterns = {
            # 标准银行格式：1,234.56 (必须有小数点后两位)
            'bank_standard': r'\b\d{1,3}(?:,\d{3})*\.\d{2}\b',
            # 中等金额：123.45 (至少100以上的金额)
            'medium_amount': r'\b[1-9]\d{2,}\.\d{2}\b',
            # 欧洲格式：1.234,56
            'european': r'\b\d{1,3}(?:\.\d{3})*,\d{2}\b',
            # 整数千位：12,345 (必须有逗号)
            'integer_thousands': r'\b\d{1,3}(?:,\d{3})+\b'
        }
        
        # 银行上下文关键词 - 提高匹配精度
        self.bank_context_keywords = [
            # 中文
            '余额', '结余', '可用余额', '账户余额', '当前余额',
            '港币', '美元', '人民币', '总计',
            # 英文
            'balance', 'available', 'current', 'total',
            'HKD', 'USD', 'CNY', 'EUR', 'GBP',
            # HTML类名 (银行常用)
            'balance', 'amount', 'currency', 'account',
            'data_table', 'swap', 'subtotal'
        ]
        
        # 无效金额过滤 - 更严格
        self.invalid_patterns = [
            r'^0*\.0+$',      # 全零
            r'^\d{10,}$',     # 过长ID
            r'^(19|20)\d{2}$', # 年份
            r'^0+\.0[01]$',   # 过小金额
            r'^\d{1,2}\.\d{2}$',  # 过小金额(小于100)
        ]
    
    def apply(self, context: ExtractionContext) -> Dict[str, Any]:
        """提取和标准化金额格式"""
        extracted_amounts = {}
        content_lower = context.content.lower()
        
        # 检查银行上下文密度
        context_score = 0
        for keyword in self.bank_context_keywords:
            context_score += content_lower.count(keyword.lower())
        
        for format_name, pattern in self.amount_patterns.items():
            matches = re.findall(pattern, context.content)
            if matches:
                # 标准化金额
                standardized = []
                for match in matches:
                    # 检查是否为无效格式
                    is_invalid = any(re.match(invalid_pattern, match) for invalid_pattern in self.invalid_patterns)
                    if is_invalid:
                        continue
                        
                    try:
                        # 转换为标准格式
                        if format_name == 'european':
                            # 1.234,56 -> 1234.56
                            standard = match.replace('.', '').replace(',', '.')
                        else:
                            # 1,234.56 -> 1234.56
                            standard = match.replace(',', '')
                        
                        # 验证是否为有效数字
                        float_val = float(standard)
                        if 1.00 <= float_val <= 9999999999.99:  # 更严格的余额范围
                            # 计算上下文相关性
                            context_relevance = self._calculate_context_relevance(match, context.content)
                            
                            standardized.append({
                                'original': match,
                                'standardized': standard,
                                'numeric': float_val,
                                'context_relevance': context_relevance,
                                'format_confidence': self._get_format_confidence(format_name)
                            })
                    except ValueError:
                        continue
                
                if standardized:
                    # 按相关性和置信度排序
                    standardized.sort(key=lambda x: (x['context_relevance'], x['format_confidence']), reverse=True)
                    extracted_amounts[format_name] = standardized
        
        return {
            'extracted_amounts': extracted_amounts,
            'total_patterns_matched': len(extracted_amounts),
            'context_score': context_score,
            'confidence': min(len(extracted_amounts) / len(self.amount_patterns), 1.0) * min(context_score / 5, 1.0)
        }
    
    def _calculate_context_relevance(self, amount: str, content: str) -> float:
        """计算金额在上下文中的相关性"""
        relevance_score = 0.0
        amount_position = content.find(amount)
        
        if amount_position == -1:
            return 0.0
        
        # 检查前后50个字符的上下文
        start = max(0, amount_position - 50)
        end = min(len(content), amount_position + len(amount) + 50)
        context_window = content[start:end].lower()
        
        # 银行相关关键词权重
        for keyword in self.bank_context_keywords:
            if keyword.lower() in context_window:
                relevance_score += 0.2
        
        # HTML表格上下文加分
        if any(tag in context_window for tag in ['<td', '</td>', '<tr', '</tr>']):
            relevance_score += 0.3
        
        # CSS类名加分
        if any(css_class in context_window for css_class in ['data_table', 'balance', 'amount', 'currency']):
            relevance_score += 0.4
        
        # 货币符号邻近性加分
        currency_symbols = ['HKD', 'USD', 'CNY', 'EUR', '港币', '美元', '人民币']
        for symbol in currency_symbols:
            if symbol in context_window:
                relevance_score += 0.5
                break
        
        return min(relevance_score, 1.0)
    
    def _get_format_confidence(self, format_name: str) -> float:
        """获取格式的置信度"""
        confidence_map = {
            'bank_standard': 0.9,  # 标准银行格式最高
            'medium_amount': 0.7,
            'european': 0.8,
            'integer_thousands': 0.6
        }
        return confidence_map.get(format_name, 0.5)
    
    def get_confidence(self, context: ExtractionContext) -> float:
        return self.apply(context)['confidence']


class Rule4_DataLocation(Rule):
    """规则4：数据定位规则 - 多种数据结构适配"""
    
    def __init__(self):
        self.locators = {
            'html_table': {
                'patterns': [
                    r'<td[^>]*class="[^"]*balance[^"]*"[^>]*>([^<]+)</td>',
                    r'<td[^>]*class="[^"]*amount[^"]*"[^>]*>([^<]+)</td>',
                    r'<td[^>]*class="data_table_[^"]*"[^>]*>(\d[\d,]*\.\d{2})</td>',
                    r'<span[^>]*class="[^"]*balance[^"]*"[^>]*>([^<]+)</span>'
                ],
                'format': DataFormat.HTML_TABLE
            },
            'json_api': {
                'patterns': [
                    r'"balance":\s*"?(\d[\d,]*\.?\d*)"?',
                    r'"amount":\s*"?(\d[\d,]*\.?\d*)"?',
                    r'"value":\s*"?(\d[\d,]*\.?\d*)"?',
                    r'"available_balance":\s*"?(\d[\d,]*\.?\d*)"?'
                ],
                'format': DataFormat.JSON_API
            },
            'javascript_var': {
                'patterns': [
                    r'var\s+\w*[Bb]alance\w*\s*=\s*["\']?(\d[\d,]*\.?\d*)["\']?',
                    r'balance\s*:\s*["\']?(\d[\d,]*\.?\d*)["\']?',
                    r'amount\s*:\s*["\']?(\d[\d,]*\.?\d*)["\']?'
                ],
                'format': DataFormat.JAVASCRIPT_VAR
            }
        }
    
    def apply(self, context: ExtractionContext) -> Dict[str, Any]:
        """定位数据在不同结构中的位置"""
        located_data = {}
        
        for locator_name, config in self.locators.items():
            matches = []
            for pattern in config['patterns']:
                found = re.findall(pattern, context.content, re.IGNORECASE | re.DOTALL)
                matches.extend(found)
            
            if matches:
                located_data[locator_name] = {
                    'format': config['format'].value,
                    'matches': matches,
                    'count': len(matches)
                }
        
        # 确定最可能的数据格式
        best_format = None
        max_matches = 0
        
        for locator_name, data in located_data.items():
            if data['count'] > max_matches:
                max_matches = data['count']
                best_format = data['format']
        
        return {
            'located_data': located_data,
            'detected_format': best_format,
            'confidence': min(len(located_data) / len(self.locators), 1.0)
        }
    
    def get_confidence(self, context: ExtractionContext) -> float:
        return self.apply(context)['confidence']


class Rule5_AuthenticationParameters(Rule):
    """规则5：认证参数规则 - 通用session和token处理"""
    
    def __init__(self):
        self.auth_patterns = {
            'session_id': [
                r'[Ss]essionId[=:]\s*([A-Za-z0-9]+)',
                r'JSESSIONID[=:]\s*([A-Za-z0-9\-]+)',
                r'dse_sessionId[=:]\s*([A-Za-z0-9]+)'
            ],
            'csrf_token': [
                r'csrf[_-]?token["\']?\s*[:=]\s*["\']?([A-Za-z0-9\-_]+)',
                r'_token["\']?\s*[:=]\s*["\']?([A-Za-z0-9\-_]+)'
            ],
            'auth_token': [
                r'[Aa]uthorization:\s*Bearer\s+([A-Za-z0-9\.\-_]+)',
                r'[Aa]uth[_-]?[Tt]oken["\']?\s*[:=]\s*["\']?([A-Za-z0-9\.\-_]+)'
            ]
        }
    
    def apply(self, context: ExtractionContext) -> Dict[str, Any]:
        """提取认证相关参数"""
        auth_params = {}
        
        # 从URL中提取
        url_str = str(context.url) if context.url else ""
        for param_type, patterns in self.auth_patterns.items():
            for pattern in patterns:
                try:
                    matches = re.findall(pattern, url_str, re.IGNORECASE)
                    if matches:
                        auth_params[param_type] = matches[0]
                        break
                except Exception:
                    continue
        
        # 从headers中提取cookie信息
        cookie_header = context.headers.get('Cookie', '') or context.headers.get('cookie', '')
        if cookie_header:
            # 提取JSESSIONID
            jsession_match = re.search(r'JSESSIONID=([^;]+)', cookie_header)
            if jsession_match:
                auth_params['jsessionid'] = jsession_match.group(1)
        
        return {
            'auth_parameters': auth_params,
            'has_session': 'session_id' in auth_params or 'jsessionid' in auth_params,
            'has_token': 'auth_token' in auth_params,
            'confidence': len(auth_params) / len(self.auth_patterns)
        }
    
    def get_confidence(self, context: ExtractionContext) -> float:
        return self.apply(context)['confidence']


class Rule6_ContextualRelations(Rule):
    """规则6：上下文关联规则 - 智能数据关联分析"""
    
    def apply(self, context: ExtractionContext) -> Dict[str, Any]:
        """分析数据间的上下文关系"""
        relations = {
            'currency_amount_pairs': [],
            'account_balance_pairs': [],
            'total_summaries': []
        }
        
        # 查找货币和金额的配对关系
        currency_amount_pattern = r'([A-Z]{3}|港币|美元|人民币)[^\d]*(\d[\d,]*\.\d{2})'
        matches = re.findall(currency_amount_pattern, context.content, re.IGNORECASE)
        
        for currency, amount in matches:
            relations['currency_amount_pairs'].append({
                'currency': currency,
                'amount': amount,
                'context': f"{currency} {amount}"
            })
        
        # 查找账户类型和余额的关系
        account_balance_pattern = r'(储蓄|活期|定期|信用卡|借记卡|往来)[^\d]*(\d[\d,]*\.\d{2})'
        matches = re.findall(account_balance_pattern, context.content, re.IGNORECASE)
        
        for account_type, balance in matches:
            relations['account_balance_pairs'].append({
                'account_type': account_type,
                'balance': balance
            })
        
        # 查找总计信息
        total_patterns = [
            r'(总计|合计|总额|Total)[^\d]*(\d[\d,]*\.\d{2})',
            r'data_table_subtotal[^>]*>(\d[\d,]*\.\d{2})</td>'
        ]
        
        for pattern in total_patterns:
            matches = re.findall(pattern, context.content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    relations['total_summaries'].append({
                        'label': match[0] if len(match) > 1 else 'Total',
                        'amount': match[1] if len(match) > 1 else match[0]
                    })
                else:
                    relations['total_summaries'].append({
                        'label': 'Total',
                        'amount': match
                    })
        
        total_relations = (len(relations['currency_amount_pairs']) + 
                         len(relations['account_balance_pairs']) + 
                         len(relations['total_summaries']))
        
        return {
            'contextual_relations': relations,
            'relation_count': total_relations,
            'confidence': min(total_relations / 10, 1.0)  # 假设10个关系为满分
        }
    
    def get_confidence(self, context: ExtractionContext) -> float:
        return self.apply(context)['confidence']


class Rule7_DataValidation(Rule):
    """规则7：数据验证规则 - 通用数据质量保证"""
    
    def __init__(self):
        self.validation_criteria = {
            'amount_range': {'min': 1.00, 'max': 9999999999.99},  # 更严格的范围
            'currency_codes': ['HKD', 'USD', 'CNY', 'EUR', 'SGD', 'JPY', 'GBP'],
            'decimal_places': 2,
            'max_accounts_per_user': 20,
            'min_context_relevance': 0.5,  # 最低上下文相关性
            'min_format_confidence': 0.6   # 最低格式置信度
        }
        
        # 通用银行API特征（基于功能而非具体银行）
        self.bank_api_indicators = [
            'balance', 'account', 'banking', 'finance', 'wallet',
            'overview', 'summary', 'transaction', 'deposit', 'credit',
            'servlet', 'api', 'service', 'query', 'proc'
        ]
    
    def apply(self, context: ExtractionContext) -> Dict[str, Any]:
        """验证提取数据的质量和合理性"""
        validation_results = {
            'high_quality_amounts': [],
            'medium_quality_amounts': [], 
            'low_quality_amounts': [],
            'invalid_amounts': [],
            'is_bank_api': False,
            'quality_score': 0.0,
            'currency_validation': {},
            'suspicious_patterns': []
        }
        
        # 检查是否为银行API
        url_lower = context.url.lower() if context.url else ""
        validation_results['is_bank_api'] = any(
            indicator in url_lower for indicator in self.bank_api_indicators
        )
        
        # 提取高质量金额（标准银行格式）
        high_quality_pattern = r'\b(\d{1,3}(?:,\d{3})*\.\d{2})\b'
        amounts = re.findall(high_quality_pattern, context.content)
        
        for amount_str in amounts:
            try:
                # 转换为数值
                numeric_amount = float(amount_str.replace(',', ''))
                
                # 验证范围
                if not (self.validation_criteria['amount_range']['min'] <= 
                       numeric_amount <= 
                       self.validation_criteria['amount_range']['max']):
                    validation_results['invalid_amounts'].append({
                        'original': amount_str,
                        'reason': 'out_of_range',
                        'numeric': numeric_amount
                    })
                    continue
                
                # 计算上下文相关性
                context_relevance = self._calculate_context_relevance(amount_str, context.content)
                
                amount_data = {
                    'original': amount_str,
                    'numeric': numeric_amount,
                    'context_relevance': context_relevance,
                    'in_bank_api': validation_results['is_bank_api']
                }
                
                # 按质量分类
                if context_relevance >= 0.8 and validation_results['is_bank_api']:
                    validation_results['high_quality_amounts'].append(amount_data)
                elif context_relevance >= 0.5 or validation_results['is_bank_api']:
                    validation_results['medium_quality_amounts'].append(amount_data)
                else:
                    validation_results['low_quality_amounts'].append(amount_data)
                    
            except ValueError:
                validation_results['invalid_amounts'].append({
                    'original': amount_str,
                    'reason': 'invalid_format'
                })
        
        # 验证货币代码
        for currency in self.validation_criteria['currency_codes']:
            if currency in context.content.upper():
                validation_results['currency_validation'][currency] = True
        
        # 计算质量得分
        total_amounts = (len(validation_results['high_quality_amounts']) + 
                        len(validation_results['medium_quality_amounts']) +
                        len(validation_results['low_quality_amounts']) + 
                        len(validation_results['invalid_amounts']))
        
        if total_amounts > 0:
            high_weight = len(validation_results['high_quality_amounts']) * 1.0
            medium_weight = len(validation_results['medium_quality_amounts']) * 0.7
            low_weight = len(validation_results['low_quality_amounts']) * 0.3
            
            quality_score = (high_weight + medium_weight + low_weight) / total_amounts
            
            # 银行API加成
            if validation_results['is_bank_api']:
                quality_score *= 1.2
                
        else:
            quality_score = 0.0
        
        validation_results['quality_score'] = min(quality_score, 1.0)
        
        return {
            'validation_results': validation_results,
            'quality_score': validation_results['quality_score'],
            'confidence': validation_results['quality_score']
        }
    
    def _calculate_context_relevance(self, amount: str, content: str) -> float:
        """计算金额在上下文中的相关性 - 复用Rule3中的逻辑"""
        relevance_score = 0.0
        amount_position = content.find(amount)
        
        if amount_position == -1:
            return 0.0
        
        # 检查前后50个字符的上下文
        start = max(0, amount_position - 50)
        end = min(len(content), amount_position + len(amount) + 50)
        context_window = content[start:end].lower()
        
        # 银行相关关键词权重
        bank_keywords = ['余额', '结余', '账户', '港币', '美元', '人民币', 'balance', 'account', 'HKD', 'USD', 'CNY']
        for keyword in bank_keywords:
            if keyword.lower() in context_window:
                relevance_score += 0.15
        
        # HTML表格上下文加分
        if any(tag in context_window for tag in ['<td', '</td>', '<tr', '</tr>']):
            relevance_score += 0.25
        
        # CSS类名加分
        if any(css_class in context_window for css_class in ['data_table', 'balance', 'amount', 'currency']):
            relevance_score += 0.35
        
        # 货币符号邻近性加分
        currency_symbols = ['HKD', 'USD', 'CNY', 'EUR', '港币', '美元', '人民币']
        for symbol in currency_symbols:
            if symbol in context_window:
                relevance_score += 0.4
                break
        
        return min(relevance_score, 1.0)
    
    def get_confidence(self, context: ExtractionContext) -> float:
        return self.apply(context)['confidence']


class UniversalBalanceRulesEngine:
    """通用银行余额规则引擎"""
    
    def __init__(self):
        self.rules = [
            Rule1_BankIdentification(),
            Rule2_CurrencyIdentification(), 
            Rule3_AmountFormat(),
            Rule4_DataLocation(),
            Rule5_AuthenticationParameters(),
            Rule6_ContextualRelations(),
            Rule7_DataValidation()
        ]
        
        self.logger = logging.getLogger(__name__)
    
    def extract_balance_data(self, url: str, content: str, headers: Dict[str, str] = None) -> Dict[str, Any]:
        """使用所有规则提取余额数据"""
        if headers is None:
            headers = {}
            
        context = ExtractionContext(
            url=url,
            content=content,
            headers=headers
        )
        
        # 应用所有规则
        rule_results = {}
        total_confidence = 0.0
        
        for i, rule in enumerate(self.rules, 1):
            try:
                rule_name = f"rule_{i}_{rule.__class__.__name__}"
                result = rule.apply(context)
                confidence = rule.get_confidence(context)
                
                rule_results[rule_name] = {
                    'result': result,
                    'confidence': confidence
                }
                total_confidence += confidence
                
            except Exception as e:
                self.logger.error(f"Error applying {rule.__class__.__name__}: {str(e)}")
                rule_results[f"rule_{i}_{rule.__class__.__name__}"] = {
                    'result': {'error': str(e)},
                    'confidence': 0.0
                }
        
        # 综合分析结果
        final_result = self._synthesize_results(rule_results, context)
        final_result['overall_confidence'] = total_confidence / len(self.rules)
        
        return final_result
    
    def _synthesize_results(self, rule_results: Dict[str, Any], context: ExtractionContext) -> Dict[str, Any]:
        """综合所有规则的结果 - 优先使用高质量数据"""
        synthesis = {
            'extracted_balances': [],
            'bank_info': {},
            'technical_details': {},
            'quality_metrics': {}
        }
        
        # 从规则1获取银行信息
        rule1_result = rule_results.get('rule_1_Rule1_BankIdentification', {}).get('result', {})
        synthesis['bank_info'] = {
            'region': rule1_result.get('bank_region'),
            'type': rule1_result.get('bank_type'),
            'api_category': rule1_result.get('api_category')
        }
        
        # 从规则7获取质量分类的金额数据
        rule7_result = rule_results.get('rule_7_Rule7_DataValidation', {}).get('result', {})
        validation_results = rule7_result.get('validation_results', {})
        
        # 优先使用高质量数据，然后是中等质量数据
        high_quality = validation_results.get('high_quality_amounts', [])
        medium_quality = validation_results.get('medium_quality_amounts', [])
        
        # 从规则2获取货币信息来分类金额
        rule2_result = rule_results.get('rule_2_Rule2_CurrencyIdentification', {}).get('result', {})
        detected_currencies = [c['currency'] for c in rule2_result.get('detected_currencies', [])]
        
        # 按货币分组高质量金额
        currency_amounts = {}
        for amount_data in high_quality + medium_quality[:5]:  # 最多取5个中等质量数据
            amount_str = amount_data['original']
            numeric_val = amount_data['numeric']
            
            # 尝试匹配货币
            matched_currency = None
            for currency in detected_currencies:
                # 检查货币是否在金额附近出现
                amount_pos = context.content.find(amount_str)
                if amount_pos != -1:
                    window_start = max(0, amount_pos - 100)
                    window_end = min(len(context.content), amount_pos + len(amount_str) + 100)
                    context_window = context.content[window_start:window_end]
                    
                    if currency in context_window.upper():
                        matched_currency = currency
                        break
            
            # 如果没有匹配到货币，使用第一个检测到的货币，或默认使用HKD
            if not matched_currency:
                matched_currency = detected_currencies[0] if detected_currencies else 'HKD'
            
            if matched_currency not in currency_amounts:
                currency_amounts[matched_currency] = []
            
            currency_amounts[matched_currency].append({
                'amount': amount_str,
                'numeric': numeric_val,
                'currency': matched_currency,
                'confidence': amount_data['context_relevance'],
                'extraction_method': 'universal_rules_engine',
                'account_type': 'unknown'
            })
        
        # 转换为最终格式
        for currency, amounts in currency_amounts.items():
            # 去重并排序（按数值大小）
            unique_amounts = {}
            for amt in amounts:
                if amt['numeric'] not in unique_amounts or unique_amounts[amt['numeric']]['confidence'] < amt['confidence']:
                    unique_amounts[amt['numeric']] = amt
            
            # 按置信度排序，取置信度最高的1-2个
            sorted_amounts = sorted(unique_amounts.values(), key=lambda x: x['confidence'], reverse=True)
            synthesis['extracted_balances'].extend(sorted_amounts[:2])  # 每种货币最多2个余额
        
        # 质量指标
        synthesis['quality_metrics'] = {
            'quality_score': rule7_result.get('quality_score', 0.0),
            'high_quality_count': len(high_quality),
            'medium_quality_count': len(medium_quality),
            'is_bank_api': validation_results.get('is_bank_api', False)
        }
        
        # 技术细节
        rule3_result = rule_results.get('rule_3_Rule3_AmountFormat', {}).get('result', {})
        synthesis['technical_details'] = {
            'detected_format': 'enhanced_universal_rules',
            'context_score': rule3_result.get('context_score', 0),
            'patterns_matched': rule3_result.get('total_patterns_matched', 0)
        }
        
        return synthesis


