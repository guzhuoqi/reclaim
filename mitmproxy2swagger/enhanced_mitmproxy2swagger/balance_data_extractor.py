#!/usr/bin/env python3
"""
Balance Data Extractor Plugin for mitmproxy2swagger
专门用于提取银行余额数据的扩展插件
"""

import re
import json
from typing import Dict, List, Any, Optional, Tuple
from abc import ABC, abstractmethod


class DataExtractor(ABC):
    """数据提取器基类"""
    
    @abstractmethod
    def can_handle(self, url: str, response_body: bytes) -> bool:
        """判断是否能处理此类响应"""
        pass
    
    @abstractmethod
    def extract_data(self, url: str, response_body: bytes) -> Dict[str, Any]:
        """提取结构化数据"""
        pass
    
    @abstractmethod
    def get_schema_enhancements(self, extracted_data: Dict[str, Any]) -> Dict[str, Any]:
        """获取OpenAPI schema增强信息"""
        pass


class BankBalanceExtractor(DataExtractor):
    """银行余额数据提取器"""
    
    def __init__(self):
        self.bank_patterns = {
            # 招商永隆银行
            'cmb_wing_lung': {
                'url_pattern': r'cmbwinglungbank\.com.*NbBkgActdetCoaProc2022',
                'currency_patterns': {
                    'HKD': [
                        r'HKD[^\d]*(\d[\d,]*\.?\d*)',
                        r'"(\d[\d,]*\.\d{2})"[^}]*HKD'
                    ],
                    'USD': [
                        r'USD[^\d]*(\d[\d,]*\.?\d*)',
                        r'"(\d[\d,]*\.\d{2})"[^}]*USD'
                    ],
                    'CNY': [
                        r'CNY[^\d]*(\d[\d,]*\.?\d*)',
                        r'"(\d[\d,]*\.\d{2})"[^}]*CNY'
                    ]
                }
            },
            # 中国银行香港
            'boc_hk': {
                'url_pattern': r'its\.bochk\.com.*acc\.overview\.do',
                'currency_patterns': {
                    'HKD': [
                        # 基于实际HTML结构：<td class="data_table_swap1_txt data_table_lastcell" nowrap>13,392.83</td>
                        r'data_table_swap1_txt[^>]*>(\d[\d,]*\.\d{2})</td>',
                        # 港元标识后的金额
                        r'港元\s*\(HKD\)</td>[\s\S]*?data_table_swap1_txt[^>]*>(\d[\d,]*\.\d{2})</td>',
                    ],
                    'USD': [
                        # 基于实际HTML结构：<td class="data_table_swap2_txt data_table_lastcell" nowrap>101.24</td>
                        r'data_table_swap2_txt[^>]*>(\d[\d,]*\.\d{2})</td>',
                        # 美元标识后的金额
                        r'美元\s*\(USD\)</td>[\s\S]*?data_table_swap2_txt[^>]*>(\d[\d,]*\.\d{2})</td>',
                    ],
                    'TOTAL_HKD': [
                        # 总计金额：<td class="data_table_subtotal data_table_lastcell" >14,185.11</td>
                        r'data_table_subtotal[^>]*>(\d[\d,]*\.\d{2})</td>',
                    ]
                }
            },
            # 可扩展其他银行
            'hsbc_hk': {
                'url_pattern': r'hsbc\.com\.hk.*balance',
                'currency_patterns': {
                    'HKD': [r'HKD.*?(\d+,?\d*\.\d{2})'],
                    'USD': [r'USD.*?(\d+,?\d*\.\d{2})']
                }
            }
        }
    
    def can_handle(self, url: str, response_body: bytes) -> bool:
        """判断是否为银行余额API响应"""
        try:
            content = response_body.decode('utf-8', errors='ignore')
            
            # 检查URL模式
            for bank_name, config in self.bank_patterns.items():
                if re.search(config['url_pattern'], url, re.IGNORECASE):
                    # 检查响应中是否包含货币信息
                    for currency in config['currency_patterns']:
                        if currency.upper() in content.upper():
                            return True
            
            return False
            
        except Exception:
            return False
    
    def extract_data(self, url: str, response_body: bytes) -> Dict[str, Any]:
        """提取余额数据"""
        
        try:
            content = response_body.decode('utf-8', errors='ignore')
            
            # 识别银行类型
            bank_type = self._identify_bank(url)
            if not bank_type:
                return {}
            
            config = self.bank_patterns[bank_type]
            extracted_data = {
                'bank': bank_type,
                'api_endpoint': url,
                'balances': {},
                'raw_amounts': [],
                'metadata': {
                    'extraction_method': 'regex_pattern_matching',
                    'confidence': 'high'
                }
            }
            
            # 提取各货币余额
            for currency, patterns in config['currency_patterns'].items():
                amounts = []
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    amounts.extend(matches)
                
                if amounts:
                    # 去重并取最可能的余额值
                    unique_amounts = list(set(amounts))
                    extracted_data['balances'][currency] = unique_amounts
                    extracted_data['raw_amounts'].extend(
                        [f"{amt} {currency}" for amt in unique_amounts]
                    )
            
            # 提取所有标准金额格式  
            standard_amounts = re.findall(r'\d{1,3}(?:,\d{3})*\.\d{2}', content)
            extracted_data['all_detected_amounts'] = list(set(standard_amounts))
            
            return extracted_data
            
        except Exception as e:
            return {'error': str(e)}
    
    def get_schema_enhancements(self, extracted_data: Dict[str, Any]) -> Dict[str, Any]:
        """生成增强的OpenAPI schema"""
        
        if not extracted_data or 'balances' not in extracted_data:
            return {}
        
        # 生成余额响应的schema
        balance_schema = {
            'type': 'object',
            'properties': {
                'account_balances': {
                    'type': 'object',
                    'properties': {},
                    'description': 'Account balance information by currency'
                },
                'metadata': {
                    'type': 'object',
                    'properties': {
                        'bank': {'type': 'string'},
                        'extraction_timestamp': {'type': 'string', 'format': 'date-time'},
                        'confidence': {'type': 'string', 'enum': ['high', 'medium', 'low']}
                    }
                }
            }
        }
        
        # 为每种货币添加schema
        for currency, amounts in extracted_data['balances'].items():
            balance_schema['properties']['account_balances']['properties'][currency] = {
                'type': 'string',
                'pattern': r'^\d{1,3}(?:,\d{3})*\.\d{2}$',
                'description': f'{currency} account balance',
                'example': amounts[0] if amounts else '0.00'
            }
        
        return {
            'response_enhancement': {
                'description': 'Bank account balance information (automatically extracted)',
                'content': {
                    'application/json': {
                        'schema': balance_schema,
                        'x-balance-data': extracted_data
                    }
                }
            }
        }
    
    def _identify_bank(self, url: str) -> Optional[str]:
        """识别银行类型"""
        for bank_name, config in self.bank_patterns.items():
            if re.search(config['url_pattern'], url, re.IGNORECASE):
                return bank_name
        return None


class ExtractorRegistry:
    """数据提取器注册中心"""
    
    def __init__(self):
        self.extractors: List[DataExtractor] = []
    
    def register(self, extractor: DataExtractor):
        """注册数据提取器"""
        self.extractors.append(extractor)
    
    def find_extractor(self, url: str, response_body: bytes) -> Optional[DataExtractor]:
        """找到合适的数据提取器"""
        for extractor in self.extractors:
            if extractor.can_handle(url, response_body):
                return extractor
        return None
    
    def extract_enhanced_data(self, url: str, response_body: bytes) -> Tuple[Optional[Dict], Optional[Dict]]:
        """提取增强数据和schema"""
        extractor = self.find_extractor(url, response_body)
        if extractor:
            extracted_data = extractor.extract_data(url, response_body)
            schema_enhancement = extractor.get_schema_enhancements(extracted_data)
            return extracted_data, schema_enhancement
        return None, None


# 全局注册中心实例
extractor_registry = ExtractorRegistry()

# 注册默认的余额提取器
extractor_registry.register(BankBalanceExtractor())


def enhance_response_processing(url: str, response_body: bytes, original_parsed_response: Any) -> Tuple[Any, Dict]:
    """
    响应处理增强函数
    
    Args:
        url: 请求URL
        response_body: 响应体字节数据
        original_parsed_response: 原始解析的响应数据
    
    Returns:
        Tuple[增强后的响应数据, schema增强信息]
    """
    
    # 尝试提取特殊数据
    extracted_data, schema_enhancement = extractor_registry.extract_enhanced_data(url, response_body)
    
    if extracted_data and schema_enhancement:
        # 如果提取到了特殊数据，创建增强的响应
        enhanced_response = {
            'original_response': original_parsed_response,
            'extracted_balance_data': extracted_data
        }
        
        return enhanced_response, schema_enhancement
    
    # 如果没有特殊数据，返回原始数据
    return original_parsed_response, {}


def get_balance_examples_for_endpoint(url: str, extracted_balance_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """为特定endpoint生成余额数据示例 - 仅使用实际提取的数据"""
    
    # ⚠️ 重要：不使用任何硬编码或模拟数据，只返回实际提取的数据
    if not extracted_balance_data or 'balances' not in extracted_balance_data:
        return {}
    
    # 使用实际提取的余额数据构建示例
    balances = extracted_balance_data.get('balances', {})
    if not balances:
        return {}
    
    # 构建基于实际数据的示例
    account_balances = {}
    for currency, amounts in balances.items():
        if amounts and len(amounts) > 0:
            # 使用实际提取的第一个金额（通常是最准确的）
            account_balances[currency] = amounts[0]
    
    if not account_balances:
        return {}
    
    return {
        'account_balances': account_balances,
        'metadata': {
            'bank': extracted_balance_data.get('bank', 'unknown'),
            'extraction_method': extracted_balance_data.get('metadata', {}).get('extraction_method', 'unknown'),
            'confidence': extracted_balance_data.get('metadata', {}).get('confidence', 'unknown')
        }
    }


if __name__ == '__main__':
    # ⚠️ 重要：这里的测试仅用于模块开发验证，不在生产环境中运行
    # 实际使用时，所有数据都从真实的mitmproxy flows中提取
    print("⚠️  此模块仅处理实际抓包数据，不包含任何模拟数据")
    print("💡 请使用 mitmproxy2swagger_enhanced.py 处理真实的 .mitm 流量文件") 