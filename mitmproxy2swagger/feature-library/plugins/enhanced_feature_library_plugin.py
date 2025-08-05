#!/usr/bin/env python3
"""
增强版特征库插件 - 集成filter_features过滤库
Enhanced Feature Library Plugin - Integrated with filter_features

这是一个增强版的特征库插件，完全集成了filter_features过滤库的能力。
提供更精确的API价值评估和过滤功能。

核心功能：
1. 集成APIValueFilter进行静态资源过滤
2. 结合金融API特征库进行智能识别
3. 多层过滤机制确保结果准确性
4. 支持动态权重调整和评分优化
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

# 导入特征库组件
from ai_analysis_features.financial_api_analyzer import FinancialAPIAnalyzer
from filter_features.api_value_filter import APIValueFilter

# 导入mitmproxy2swagger接口（如果可用）
try:
    from enhanced_mitmproxy2swagger.balance_data_extractor import DataExtractor, ExtractorRegistry
    from enhanced_mitmproxy2swagger.universal_balance_rules import Rule, ExtractionContext
except ImportError:
    # 定义基础接口
    class DataExtractor(ABC):
        @abstractmethod
        def can_handle(self, url: str, response_body: bytes) -> bool:
            pass

        @abstractmethod
        def extract_data(self, url: str, response_body: bytes) -> Dict[str, Any]:
            pass

        @abstractmethod
        def get_schema_enhancements(self, url: str, response_body: bytes) -> Dict[str, Any]:
            pass

    class Rule(ABC):
        @abstractmethod
        def apply(self, context) -> Dict[str, Any]:
            pass

        @abstractmethod
        def get_confidence(self, context) -> float:
            pass


class EnhancedFeatureLibraryExtractor(DataExtractor):
    """增强版特征库数据提取器 - 集成过滤库"""

    def __init__(self, features_config_path: str = None, filter_config_path: str = None):
        """初始化增强版提取器"""
        self.logger = logging.getLogger(__name__)

        # 初始化特征库分析器
        if features_config_path is None:
            features_config_path = Path(__file__).parent.parent / "ai_analysis_features" / "financial_api_features.json"

        self.analyzer = FinancialAPIAnalyzer(features_config_path)

        # 初始化过滤器
        if filter_config_path is None:
            filter_config_path = Path(__file__).parent.parent / "filter_features" / "static_resource_filters.json"

        self.filter = APIValueFilter(filter_config_path)

        self.logger.info("✅ 增强版特征库提取器初始化完成")

    def can_handle(self, url: str, response_body: bytes) -> bool:
        """判断是否可以处理此URL和响应 - 集成过滤逻辑"""
        try:
            # 第一步：使用特征库分析器判断价值
            analysis_result = self.analyzer.analyze_api(url)

            # 第二步：使用过滤器进行评估
            base_score = analysis_result.value_score
            filter_result = self.filter.filter_and_score_api(url, base_score)

            # 第三步：综合评估
            final_score = filter_result.get("adjusted_score", base_score)
            should_exclude = filter_result.get("final_recommendation") == "exclude"

            # 只处理未被排除且评分达到阈值的API
            return not should_exclude and final_score >= 20 and analysis_result.priority_level in ["medium", "high", "critical"]

        except Exception as e:
            self.logger.error(f"判断处理能力时出错: {e}")
            return False

    def extract_data(self, url: str, response_body: bytes) -> Dict[str, Any]:
        """提取数据 - 增强版处理逻辑"""
        try:
            # 解码响应内容
            response_content = ""
            if response_body:
                response_content = response_body.decode('utf-8', errors='ignore')

            # 第一步：特征库分析
            analysis_result = self.analyzer.analyze_api(
                url=url,
                response_content=response_content
            )

            # 第二步：过滤器分析
            base_score = analysis_result.value_score
            filter_result = self.filter.filter_and_score_api(url, base_score, response_content)

            # 第三步：综合评分
            final_score = filter_result.get("adjusted_score", base_score)
            filter_adjustment = final_score - base_score

            # 第四步：重新评估优先级
            final_priority = self._calculate_final_priority(final_score, filter_result, analysis_result)

            # 如果最终评分过低，返回空结果
            if final_score < 15:
                return {}

            # 构建增强的提取结果
            extracted_data = {
                "enhanced_analysis": {
                    "institution": analysis_result.institution,
                    "institution_type": analysis_result.institution_type,
                    "base_value_score": base_score,
                    "filter_adjustment": filter_adjustment,
                    "final_value_score": final_score,
                    "original_priority": analysis_result.priority_level,
                    "final_priority": final_priority,
                    "data_types": analysis_result.data_types,
                    "authentication_detected": analysis_result.authentication_detected,
                    "matched_patterns": analysis_result.matched_patterns
                },
                "filter_analysis": {
                    "resource_type": filter_result.get("resource_type", "unknown"),
                    "should_exclude": filter_result.get("should_exclude", False),
                    "exclusion_reasons": filter_result.get("exclusion_reasons", []),
                    "enhancement_reasons": filter_result.get("enhancement_reasons", []),
                    "filter_confidence": filter_result.get("confidence", 0.0)
                },
                "extraction_method": "enhanced_feature_library_plugin",
                "plugin_version": "2.0.0"
            }

            # 如果检测到金融数据，进行详细提取
            if analysis_result.response_contains_financial_data:
                financial_data = self._extract_financial_fields(url, response_content, analysis_result)
                if financial_data:
                    extracted_data["financial_data"] = financial_data

            self.logger.info(f"✅ 增强版提取完成: {url} (最终评分: {final_score})")
            return extracted_data

        except Exception as e:
            self.logger.error(f"增强版数据提取失败: {e}")
            return {"error": str(e)}

    def get_schema_enhancements(self, url: str, response_body: bytes) -> Dict[str, Any]:
        """获取schema增强信息"""
        try:
            # 获取分析器和过滤器的结果
            analysis_result = self.analyzer.analyze_api(url)
            base_score = analysis_result.value_score
            filter_result = self.filter.filter_and_score_api(url, base_score)

            final_score = filter_result.get("adjusted_score", base_score)

            if final_score >= 20:
                return {
                    "financial_api_detected": True,
                    "institution": analysis_result.institution,
                    "data_types": analysis_result.data_types,
                    "resource_type": filter_result.get("resource_type", "api"),
                    "schema_properties": {
                        "x-financial-institution": analysis_result.institution,
                        "x-api-value-score": final_score,
                        "x-priority-level": self._calculate_final_priority(final_score, filter_result, analysis_result),
                        "x-data-types": analysis_result.data_types,
                        "x-resource-type": filter_result.get("resource_type", "api"),
                        "x-filter-applied": True
                    }
                }

            return {}

        except Exception as e:
            self.logger.error(f"获取schema增强信息失败: {e}")
            return {}

    def _calculate_final_priority(self, final_score: int, filter_result: Dict, analysis_result) -> str:
        """计算最终优先级"""
        # 如果被过滤器严格排除，降级
        if filter_result.get("should_exclude", False):
            return "low"

        # 根据最终评分重新计算优先级
        if final_score >= 80:
            return "critical"
        elif final_score >= 50:
            return "high"
        elif final_score >= 20:
            return "medium"
        else:
            return "low"

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
                            break
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


class EnhancedFeatureLibraryRule(Rule):
    """增强版特征库规则 - 集成过滤逻辑"""

    def __init__(self):
        self.analyzer = FinancialAPIAnalyzer()
        self.filter = APIValueFilter()
        self.logger = logging.getLogger(__name__)

    def apply(self, context) -> Dict[str, Any]:
        """应用增强版特征库规则"""
        try:
            # 特征库分析
            analysis_result = self.analyzer.analyze_api(
                url=context.url,
                response_content=context.content,
                headers=context.headers
            )

            # 过滤器分析
            base_score = analysis_result.value_score
            filter_result = self.filter.filter_and_score_api(context.url, base_score, context.content)

            # 综合评分
            final_score = filter_result.get("adjusted_score", base_score)

            return {
                "rule_type": "enhanced_feature_library",
                "institution": analysis_result.institution,
                "base_value_score": analysis_result.value_score,
                "filter_adjustment": filter_result.get("weight_adjustment", 0),
                "final_value_score": final_score,
                "priority_level": self._calculate_priority(final_score),
                "is_financial_api": final_score >= 20,
                "authentication_detected": analysis_result.authentication_detected,
                "matched_patterns": analysis_result.matched_patterns,
                "filter_applied": True,
                "resource_type": filter_result.get("resource_type", "unknown")
            }

        except Exception as e:
            self.logger.error(f"增强版规则应用失败: {e}")
            return {"error": str(e)}

    def get_confidence(self, context) -> float:
        """获取规则置信度"""
        try:
            analysis_result = self.analyzer.analyze_api(url=context.url)
            base_score = analysis_result.value_score
            filter_result = self.filter.filter_and_score_api(context.url, base_score)

            # 综合置信度计算
            base_confidence = min(analysis_result.value_score / 100.0, 1.0)
            filter_confidence = 0.8 if filter_result.get("final_recommendation") == "keep" else 0.3

            # 加权平均
            final_confidence = (base_confidence * 0.7) + (filter_confidence * 0.3)
            return min(final_confidence, 1.0)

        except Exception:
            return 0.0

    def _calculate_priority(self, score: int) -> str:
        """计算优先级"""
        if score >= 80:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 20:
            return "medium"
        else:
            return "low"


class EnhancedFeatureLibraryPlugin:
    """增强版特征库插件主类"""

    def __init__(self, features_config_path: str = None, filter_config_path: str = None):
        """初始化增强版插件"""
        self.logger = logging.getLogger(__name__)
        self.features_config_path = features_config_path
        self.filter_config_path = filter_config_path

        # 创建组件实例
        self.extractor = EnhancedFeatureLibraryExtractor(features_config_path, filter_config_path)
        self.rule = EnhancedFeatureLibraryRule()

        self.logger.info("🔌 增强版特征库插件初始化完成")

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

            return True

        except Exception as e:
            self.logger.error(f"插件注册失败: {e}")
            return False

    def get_plugin_info(self) -> Dict[str, Any]:
        """获取插件信息"""
        return {
            "name": "EnhancedFeatureLibraryPlugin",
            "version": "2.0.0",
            "description": "增强版金融API特征库插件，集成filter_features过滤库，提供更精确的API识别和过滤",
            "author": "AI Assistant",
            "capabilities": [
                "financial_institution_recognition",
                "api_value_assessment",
                "static_resource_filtering",
                "response_content_extraction",
                "masked_data_filtering",
                "multi_layer_filtering",
                "dynamic_weight_adjustment"
            ],
            "integrated_components": [
                "FinancialAPIAnalyzer",
                "APIValueFilter",
                "StaticResourceFilters"
            ],
            "supported_institutions": [
                "香港银行", "欧美银行", "中国大陆银行",
                "全球投资银行", "券商", "加密货币交易所",
                "支付平台", "保险公司", "金融科技公司"
            ]
        }


# 全局插件实例
enhanced_feature_library_plugin = EnhancedFeatureLibraryPlugin()


def initialize_enhanced_plugin(features_config_path: str = None, filter_config_path: str = None) -> bool:
    """初始化并注册增强版插件"""
    global enhanced_feature_library_plugin

    try:
        enhanced_feature_library_plugin = EnhancedFeatureLibraryPlugin(features_config_path, filter_config_path)

        # 注册到mitmproxy2swagger系统
        success = enhanced_feature_library_plugin.register_to_mitmproxy2swagger()

        if success:
            print("🎉 增强版特征库插件注册成功！")
            print("📋 插件信息:")
            info = enhanced_feature_library_plugin.get_plugin_info()
            for key, value in info.items():
                if isinstance(value, list):
                    print(f"   {key}: {len(value)} 项")
                else:
                    print(f"   {key}: {value}")
            return True
        else:
            print("❌ 增强版特征库插件注册失败")
            return False

    except Exception as e:
        print(f"❌ 增强版插件初始化失败: {e}")
        return False


def main():
    """命令行测试接口"""
    import argparse

    parser = argparse.ArgumentParser(description='增强版特征库插件测试')
    parser.add_argument('--features-config', '-f', help='特征库配置文件路径')
    parser.add_argument('--filter-config', '-c', help='过滤器配置文件路径')
    parser.add_argument('--test-url', '-u', help='测试URL')

    args = parser.parse_args()

    # 初始化插件
    if initialize_enhanced_plugin(args.features_config, args.filter_config):
        print("\n🧪 运行增强版插件测试...")

        if args.test_url:
            # 测试单个URL
            extractor = enhanced_feature_library_plugin.extractor
            can_handle = extractor.can_handle(args.test_url, b"")
            print(f"URL: {args.test_url}")
            print(f"可处理: {can_handle}")

            if can_handle:
                result = extractor.extract_data(args.test_url, b'{"balance": "7,150.98"}')
                print(f"提取结果: {json.dumps(result, indent=2, ensure_ascii=False)}")
        else:
            print("✅ 增强版插件测试完成，可以开始使用")


if __name__ == "__main__":
    main()
