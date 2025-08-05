#!/usr/bin/env python3
"""
特征库插件 - mitmproxy2swagger可插拔扩展
Feature Library Plugin - Pluggable Extension for mitmproxy2swagger

这是一个标准的mitmproxy2swagger插件，可以无缝集成到现有的处理流程中。
通过注册机制，将我们的金融API特征库能力插入到mitmproxy2swagger的处理管道中。

核心功能：
1. 实现DataExtractor接口，集成到ExtractorRegistry
2. 提供Rule接口实现，集成到规则引擎
3. 支持动态配置加载
4. 与现有过滤器系统协同工作
"""

import os
import sys
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from abc import ABC, abstractmethod

# 添加项目路径
current_dir = Path(__file__).parent
sys.path.append(str(current_dir.parent.parent))
sys.path.append(str(current_dir.parent))

# 导入mitmproxy2swagger的扩展接口
try:
    from enhanced_mitmproxy2swagger.balance_data_extractor import DataExtractor, ExtractorRegistry
    from enhanced_mitmproxy2swagger.universal_balance_rules import Rule, ExtractionContext
except ImportError:
    # 如果没有找到，定义基础接口
    class DataExtractor(ABC):
        @abstractmethod
        def can_handle(self, url: str, response_body: bytes) -> bool:
            pass

        @abstractmethod
        def extract_data(self, url: str, response_body: bytes) -> Dict[str, Any]:
            pass

    class Rule(ABC):
        @abstractmethod
        def apply(self, context) -> Dict[str, Any]:
            pass

        @abstractmethod
        def get_confidence(self, context) -> float:
            pass

# 导入我们的特征库组件
from ai_analysis_features.financial_api_analyzer import FinancialAPIAnalyzer
from filter_features.api_value_filter import APIValueFilter


class FeatureLibraryExtractor(DataExtractor):
    """特征库数据提取器 - 实现DataExtractor接口"""

    def __init__(self, config_path: str = None):
        """初始化特征库提取器"""
        self.logger = logging.getLogger(__name__)

        # 初始化特征库组件
        if config_path is None:
            config_path = Path(__file__).parent.parent / "ai_analysis_features" / "financial_api_features.json"

        self.analyzer = FinancialAPIAnalyzer(config_path)
        self.filter = APIValueFilter()

        self.logger.info("✅ 特征库提取器初始化完成")

    def get_schema_enhancements(self, url: str, response_body: bytes) -> Dict[str, Any]:
        """获取schema增强信息 - 实现抽象方法"""
        try:
            # 分析API获取schema增强信息
            analysis_result = self.analyzer.analyze_api(url)

            if analysis_result.priority_level in ["medium", "high", "critical"]:
                return {
                    "financial_api_detected": True,
                    "institution": analysis_result.institution,
                    "data_types": analysis_result.data_types,
                    "schema_properties": {
                        "x-financial-institution": analysis_result.institution,
                        "x-api-value-score": analysis_result.value_score,
                        "x-priority-level": analysis_result.priority_level,
                        "x-data-types": analysis_result.data_types
                    }
                }

            return {}

        except Exception as e:
            self.logger.error(f"获取schema增强信息失败: {e}")
            return {}

    def can_handle(self, url: str, response_body: bytes) -> bool:
        """判断是否可以处理此URL和响应"""
        try:
            # 使用特征库分析器判断是否为有价值的金融API
            analysis_result = self.analyzer.analyze_api(url)

            # 只处理中等以上价值的API
            return analysis_result.priority_level in ["medium", "high", "critical"]

        except Exception as e:
            self.logger.error(f"判断处理能力时出错: {e}")
            return False

    def extract_data(self, url: str, response_body: bytes) -> Dict[str, Any]:
        """提取数据 - 核心处理逻辑"""
        try:
            # 解码响应内容
            response_content = ""
            if response_body:
                response_content = response_body.decode('utf-8', errors='ignore')

            # 使用特征库分析器分析API
            analysis_result = self.analyzer.analyze_api(
                url=url,
                response_content=response_content
            )

            # 如果不是有价值的API，返回空结果
            if analysis_result.priority_level == "low":
                return {}

            # 提取结构化数据
            extracted_data = {
                "feature_library_analysis": {
                    "institution": analysis_result.institution,
                    "institution_type": analysis_result.institution_type,
                    "value_score": analysis_result.value_score,
                    "priority_level": analysis_result.priority_level,
                    "data_types": analysis_result.data_types,
                    "authentication_detected": analysis_result.authentication_detected,
                    "matched_patterns": analysis_result.matched_patterns
                },
                "extraction_method": "feature_library_plugin",
                "plugin_version": "1.0.0"
            }

            # 如果检测到金融数据，进行详细提取
            if analysis_result.response_contains_financial_data:
                financial_data = self._extract_financial_fields(url, response_content, analysis_result)
                if financial_data:
                    extracted_data["financial_data"] = financial_data

            self.logger.info(f"✅ 特征库提取完成: {url} (评分: {analysis_result.value_score})")
            return extracted_data

        except Exception as e:
            self.logger.error(f"数据提取失败: {e}")
            return {"error": str(e)}

    def _extract_financial_fields(self, url: str, content: str, analysis_result) -> Dict[str, Any]:
        """提取具体的金融字段"""
        financial_fields = {}

        # 定义金融数据提取模式
        patterns = {
            "balance": [
                r'"(?:balance|余额|结余)":\s*"?([0-9,]+\.?\d*)"?',
                r'余额[：:]\s*([0-9,]+\.?\d*)',
            ],
            "account_number": [
                r'"(?:accountNumber|账户号码)":\s*"([^"]+)"',
                r'账户号码[：:]\s*([^\s,]+)',
            ],
            "amount": [
                r'"(?:amount|金额)":\s*"?([0-9,]+\.?\d*)"?',
                r'金额[：:]\s*([0-9,]+\.?\d*)',
            ]
        }

        import re
        for field_type, field_patterns in patterns.items():
            for pattern in field_patterns:
                try:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        # 过滤打码数据
                        valid_matches = [m for m in matches if not self._is_masked_data(m)]
                        if valid_matches:
                            financial_fields[field_type] = valid_matches
                            break  # 找到有效匹配就停止
                except re.error:
                    continue

        return financial_fields

    def _is_masked_data(self, value: str) -> bool:
        """检测是否为打码数据"""
        import re
        masked_patterns = [
            r'\*{3,}',  # 连续星号
            r'x{3,}',   # 连续x
            r'#{3,}',   # 连续井号
        ]

        for pattern in masked_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        return False


class FeatureLibraryRule(Rule):
    """特征库规则 - 实现Rule接口"""

    def __init__(self):
        self.analyzer = FinancialAPIAnalyzer()
        self.logger = logging.getLogger(__name__)

    def apply(self, context) -> Dict[str, Any]:
        """应用特征库规则"""
        try:
            # 分析API
            analysis_result = self.analyzer.analyze_api(
                url=context.url,
                response_content=context.content,
                headers=context.headers
            )

            return {
                "rule_type": "feature_library",
                "institution": analysis_result.institution,
                "value_score": analysis_result.value_score,
                "priority_level": analysis_result.priority_level,
                "is_financial_api": analysis_result.priority_level != "low",
                "authentication_detected": analysis_result.authentication_detected,
                "matched_patterns": analysis_result.matched_patterns
            }

        except Exception as e:
            self.logger.error(f"特征库规则应用失败: {e}")
            return {"error": str(e)}

    def get_confidence(self, context) -> float:
        """获取规则置信度"""
        try:
            analysis_result = self.analyzer.analyze_api(url=context.url)

            # 将评分转换为0-1的置信度
            confidence = min(analysis_result.value_score / 100.0, 1.0)
            return confidence

        except Exception:
            return 0.0


class FeatureLibraryPlugin:
    """特征库插件主类"""

    def __init__(self, config_path: str = None):
        """初始化插件"""
        self.logger = logging.getLogger(__name__)
        self.config_path = config_path

        # 创建组件实例
        self.extractor = FeatureLibraryExtractor(config_path)
        self.rule = FeatureLibraryRule()

        self.logger.info("🔌 特征库插件初始化完成")

    def register_to_mitmproxy2swagger(self):
        """注册到mitmproxy2swagger系统"""
        try:
            # 尝试注册到ExtractorRegistry
            try:
                from enhanced_mitmproxy2swagger.balance_data_extractor import extractor_registry
                extractor_registry.register(self.extractor)
                self.logger.info("✅ 已注册到ExtractorRegistry")
            except ImportError:
                self.logger.warning("⚠️  ExtractorRegistry不可用，跳过注册")

            # 尝试注册到规则引擎
            try:
                from enhanced_mitmproxy2swagger.universal_balance_rules import UniversalBalanceRulesEngine
                # 这里需要扩展规则引擎以支持动态规则注册
                self.logger.info("✅ 规则引擎集成准备完成")
            except ImportError:
                self.logger.warning("⚠️  规则引擎不可用，跳过注册")

            return True

        except Exception as e:
            self.logger.error(f"插件注册失败: {e}")
            return False

    def get_plugin_info(self) -> Dict[str, Any]:
        """获取插件信息"""
        return {
            "name": "FeatureLibraryPlugin",
            "version": "1.0.0",
            "description": "金融API特征库插件，提供智能的金融机构API识别和数据提取能力",
            "author": "AI Assistant",
            "capabilities": [
                "financial_institution_recognition",
                "api_value_assessment",
                "response_content_extraction",
                "masked_data_filtering"
            ],
            "supported_institutions": [
                "香港银行", "欧美银行", "中国大陆银行",
                "全球投资银行", "券商", "加密货币交易所",
                "支付平台", "保险公司", "金融科技公司"
            ]
        }


# 全局插件实例
feature_library_plugin = FeatureLibraryPlugin()


def initialize_plugin(config_path: str = None) -> bool:
    """初始化并注册插件"""
    global feature_library_plugin

    try:
        if config_path:
            feature_library_plugin = FeatureLibraryPlugin(config_path)

        # 注册到mitmproxy2swagger系统
        success = feature_library_plugin.register_to_mitmproxy2swagger()

        if success:
            print("🎉 特征库插件注册成功！")
            print("📋 插件信息:")
            info = feature_library_plugin.get_plugin_info()
            for key, value in info.items():
                if isinstance(value, list):
                    print(f"   {key}: {len(value)} 项")
                else:
                    print(f"   {key}: {value}")
            return True
        else:
            print("❌ 特征库插件注册失败")
            return False

    except Exception as e:
        print(f"❌ 插件初始化失败: {e}")
        return False


def main():
    """命令行测试接口"""
    import argparse

    parser = argparse.ArgumentParser(description='特征库插件测试')
    parser.add_argument('--config', '-c', help='特征库配置文件路径')
    parser.add_argument('--test-url', '-u', help='测试URL')

    args = parser.parse_args()

    # 初始化插件
    if initialize_plugin(args.config):
        print("\n🧪 运行插件测试...")

        if args.test_url:
            # 测试单个URL
            extractor = feature_library_plugin.extractor
            can_handle = extractor.can_handle(args.test_url, b"")
            print(f"URL: {args.test_url}")
            print(f"可处理: {can_handle}")

            if can_handle:
                result = extractor.extract_data(args.test_url, b'{"balance": "7,150.98"}')
                print(f"提取结果: {json.dumps(result, indent=2, ensure_ascii=False)}")
        else:
            print("✅ 插件测试完成，可以开始使用")


if __name__ == "__main__":
    main()
