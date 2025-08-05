#!/usr/bin/env python3
"""
增强学习管道
Enhanced Learning Pipeline

集成增强学习引擎和API属性提取器，提供完整的金融API学习和特征库更新流程。

核心功能：
1. 集成学习流程 - 结合宽松扫描、邻居分析、模式学习和属性提取
2. 深度属性提取 - 对学习到的API进行细致的属性分析
3. 智能特征库更新 - 将提取的属性补充到特征库的指定位置
4. 质量验证 - 确保学习质量和特征库一致性
5. 学习报告 - 生成详细的学习和更新报告
"""

import json
import sys
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

# 添加路径以导入现有模块
sys.path.append('mitmproxy2swagger/mitmproxy2swagger')
sys.path.append('mitmproxy2swagger/feature-library/ai_analysis_features')
sys.path.append('mitmproxy2swagger/feature-library/learning_engine')

from financial_api_learner import FinancialAPILearner, APICandidate
from api_attribute_extractor import APIAttributeExtractor, ExtractedAPIAttributes


class EnhancedLearningPipeline:
    """增强学习管道"""

    def __init__(self, feature_library_path: str = None):
        """初始化增强学习管道"""
        self.logger = logging.getLogger(__name__)

        # 初始化组件
        self.learner = FinancialAPILearner(feature_library_path)
        self.extractor = APIAttributeExtractor(feature_library_path)

        # 管道配置
        self.config = {
            'min_extraction_confidence': 0.6,  # 最小提取置信度
            'max_apis_per_institution': 20,    # 每个机构最大API数量
            'enable_feature_library_update': True,  # 是否更新特征库
            'backup_before_update': True,      # 更新前是否备份
            'quality_validation': True         # 是否进行质量验证
        }

        # 管道状态
        self.pipeline_stats = {
            'total_flows_processed': 0,
            'candidates_discovered': 0,
            'attributes_extracted': 0,
            'feature_library_updates': 0,
            'quality_issues': 0
        }

    def run_complete_pipeline(self, flows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """运行完整的增强学习管道"""
        self.logger.info("🚀 开始增强学习管道...")

        try:
            # 第一阶段：基础学习
            self.logger.info("第一阶段：基础学习（宽松扫描 + 邻居分析 + 模式学习）")
            learning_report = self.learner.learn_from_flows(flows)

            if not learning_report['success']:
                return {
                    'success': False,
                    'error': 'Basic learning failed',
                    'learning_report': learning_report
                }

            self.pipeline_stats['total_flows_processed'] = learning_report['stats']['total_scanned']
            self.pipeline_stats['candidates_discovered'] = learning_report['stats']['candidates_found']

            # 第二阶段：深度属性提取
            self.logger.info("第二阶段：深度属性提取")
            extracted_attributes = self._extract_attributes_from_candidates(
                self.learner.api_candidates, flows
            )

            self.pipeline_stats['attributes_extracted'] = len(extracted_attributes)

            # 第三阶段：质量验证
            if self.config['quality_validation']:
                self.logger.info("第三阶段：质量验证")
                validated_attributes = self._validate_extracted_attributes(extracted_attributes)
            else:
                validated_attributes = extracted_attributes

            # 第四阶段：特征库更新
            update_report = {}
            if self.config['enable_feature_library_update'] and validated_attributes:
                self.logger.info("第四阶段：特征库更新")
                update_report = self.extractor.update_feature_library_with_attributes(validated_attributes)
                self.pipeline_stats['feature_library_updates'] = update_report['successful_updates']

            # 生成完整报告
            complete_report = self._generate_complete_report(
                learning_report, extracted_attributes, validated_attributes, update_report
            )

            self.logger.info("🎉 增强学习管道完成")
            return complete_report

        except Exception as e:
            self.logger.error(f"增强学习管道失败: {e}")
            return {
                'success': False,
                'error': str(e),
                'pipeline_stats': self.pipeline_stats
            }

    def _extract_attributes_from_candidates(self, candidates: List[APICandidate],
                                          flows: List[Dict[str, Any]]) -> List[ExtractedAPIAttributes]:
        """从候选API中提取属性"""
        extracted_attributes = []

        # 创建URL到flow的映射
        url_to_flow = {flow['url']: flow for flow in flows}

        for candidate in candidates:
            try:
                # 查找对应的flow数据
                flow_data = url_to_flow.get(candidate.url)
                if not flow_data:
                    continue

                # 提取完整属性
                attributes = self.extractor.extract_complete_attributes(
                    url=candidate.url,
                    method=candidate.method,
                    request_headers={},  # 从flow_data中获取
                    request_body=flow_data.get('request_body', ''),
                    response_content=candidate.response_content,
                    response_headers={},  # 从flow_data中获取
                    institution=self._identify_institution_from_candidate(candidate)
                )

                if attributes and attributes.extraction_confidence >= self.config['min_extraction_confidence']:
                    extracted_attributes.append(attributes)

            except Exception as e:
                self.logger.warning(f"提取API属性失败 {candidate.url}: {e}")
                continue

        self.logger.info(f"成功提取 {len(extracted_attributes)} 个API的属性")
        return extracted_attributes

    def _identify_institution_from_candidate(self, candidate: APICandidate) -> str:
        """从候选API识别机构"""
        domain = candidate.domain

        # 基于域名识别机构
        if 'hsbc.com' in domain:
            return 'HSBC'
        elif 'bochk.com' in domain:
            return '中银香港'
        elif 'hangseng.com' in domain:
            return '恒生银行'
        elif 'dbs.com' in domain:
            return 'DBS'
        elif 'cmbwinglungbank.com' in domain:
            return '永隆银行'
        else:
            return f'Unknown_{domain}'

    def _validate_extracted_attributes(self, attributes: List[ExtractedAPIAttributes]) -> List[ExtractedAPIAttributes]:
        """验证提取的属性"""
        validated = []
        quality_issues = 0

        for attr in attributes:
            try:
                # 基本质量检查
                if self._validate_single_attribute(attr):
                    validated.append(attr)
                else:
                    quality_issues += 1

            except Exception as e:
                self.logger.warning(f"验证属性时出错 {attr.url}: {e}")
                quality_issues += 1

        self.pipeline_stats['quality_issues'] = quality_issues
        self.logger.info(f"质量验证完成: {len(validated)} 个通过验证, {quality_issues} 个存在问题")

        return validated

    def _validate_single_attribute(self, attr: ExtractedAPIAttributes) -> bool:
        """验证单个属性"""
        # 检查基本字段
        if not attr.url or not attr.institution:
            return False

        # 检查提取置信度
        if attr.extraction_confidence < self.config['min_extraction_confidence']:
            return False

        # 检查业务属性
        if attr.business_attrs.api_category == 'unknown':
            return False

        # 检查响应属性
        if attr.response_attrs.data_structure == 'empty':
            return False

        return True

    def _generate_complete_report(self, learning_report: Dict[str, Any],
                                extracted_attributes: List[ExtractedAPIAttributes],
                                validated_attributes: List[ExtractedAPIAttributes],
                                update_report: Dict[str, Any]) -> Dict[str, Any]:
        """生成完整报告"""

        # 统计分析
        institution_stats = {}
        category_stats = {}

        for attr in validated_attributes:
            # 机构统计
            inst = attr.institution
            if inst not in institution_stats:
                institution_stats[inst] = {
                    'api_count': 0,
                    'avg_confidence': 0.0,
                    'categories': set()
                }
            institution_stats[inst]['api_count'] += 1
            institution_stats[inst]['categories'].add(attr.business_attrs.api_category)

            # 类别统计
            category = attr.business_attrs.api_category
            category_stats[category] = category_stats.get(category, 0) + 1

        # 计算平均置信度
        for inst_data in institution_stats.values():
            inst_apis = [attr for attr in validated_attributes if attr.institution == inst]
            if inst_apis:
                inst_data['avg_confidence'] = sum(attr.extraction_confidence for attr in inst_apis) / len(inst_apis)
                inst_data['categories'] = list(inst_data['categories'])

        return {
            'success': True,
            'timestamp': datetime.now().isoformat(),
            'pipeline_config': self.config,
            'pipeline_stats': self.pipeline_stats,
            'learning_report': learning_report,
            'extraction_summary': {
                'total_extracted': len(extracted_attributes),
                'validated_count': len(validated_attributes),
                'validation_rate': len(validated_attributes) / len(extracted_attributes) if extracted_attributes else 0,
                'institution_stats': institution_stats,
                'category_stats': category_stats
            },
            'feature_library_update': update_report,
            'quality_metrics': {
                'avg_extraction_confidence': sum(attr.extraction_confidence for attr in validated_attributes) / len(validated_attributes) if validated_attributes else 0,
                'high_confidence_apis': len([attr for attr in validated_attributes if attr.extraction_confidence > 0.8]),
                'critical_priority_apis': len([attr for attr in validated_attributes if attr.business_attrs.priority_level == 'critical'])
            },
            'detailed_results': [
                {
                    'url': attr.url,
                    'institution': attr.institution,
                    'api_category': attr.business_attrs.api_category,
                    'value_score': attr.business_attrs.value_score,
                    'priority_level': attr.business_attrs.priority_level,
                    'extraction_confidence': attr.extraction_confidence,
                    'data_sensitivity': attr.business_attrs.data_sensitivity
                }
                for attr in validated_attributes
            ]
        }

    def export_pipeline_results(self, report: Dict[str, Any], output_path: str) -> bool:
        """导出管道结果"""
        try:
            # 处理datetime序列化问题
            serializable_report = self._make_json_serializable(report)

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(serializable_report, f, indent=2, ensure_ascii=False)

            self.logger.info(f"管道结果已导出到: {output_path}")
            return True

        except Exception as e:
            self.logger.error(f"导出管道结果失败: {e}")
            return False

    def _make_json_serializable(self, obj):
        """使对象可JSON序列化"""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, dict):
            return {key: self._make_json_serializable(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._make_json_serializable(item) for item in obj]
        elif isinstance(obj, set):
            return list(obj)
        else:
            return obj


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description='增强学习管道')
    parser.add_argument('--input', '-i', required=True, help='输入的mitm文件路径')
    parser.add_argument('--output', '-o', default='enhanced_learning_report.json', help='输出报告文件')
    parser.add_argument('--feature-lib', '-f', help='特征库文件路径')
    parser.add_argument('--no-update', action='store_true', help='不更新特征库')
    parser.add_argument('--verbose', '-v', action='store_true', help='详细输出')

    args = parser.parse_args()

    # 配置日志
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # 初始化管道
    pipeline = EnhancedLearningPipeline(args.feature_lib)

    if args.no_update:
        pipeline.config['enable_feature_library_update'] = False

    # 读取mitm文件
    sys.path.append('mitmproxy2swagger/mitmproxy2swagger')
    from mitmproxy_capture_reader import MitmproxyCaptureReader

    try:
        print(f"🔍 读取mitm文件: {args.input}")
        capture_reader = MitmproxyCaptureReader(args.input)

        # 转换为流数据格式
        flows = []
        for flow_wrapper in capture_reader.captured_requests():
            try:
                flow_data = {
                    'url': flow_wrapper.get_url(),
                    'method': flow_wrapper.get_method(),
                    'status_code': flow_wrapper.get_response_status_code(),
                    'response_body': flow_wrapper.get_response_body().decode('utf-8', errors='ignore') if flow_wrapper.get_response_body() else '',
                    'request_body': flow_wrapper.get_request_body().decode('utf-8', errors='ignore') if flow_wrapper.get_request_body() else ''
                }
                flows.append(flow_data)
            except Exception as e:
                continue

        print(f"✅ 成功读取 {len(flows)} 个流数据")

        # 运行增强学习管道
        print("🚀 开始增强学习管道...")
        report = pipeline.run_complete_pipeline(flows)

        # 输出结果
        if report['success']:
            print("🎉 增强学习管道完成！")

            stats = report['pipeline_stats']
            extraction = report['extraction_summary']
            quality = report['quality_metrics']

            print(f"📊 处理统计:")
            print(f"  流数据: {stats['total_flows_processed']}")
            print(f"  候选API: {stats['candidates_discovered']}")
            print(f"  属性提取: {stats['attributes_extracted']}")
            print(f"  验证通过: {extraction['validated_count']}")
            print(f"  特征库更新: {stats['feature_library_updates']}")

            print(f"🎯 质量指标:")
            print(f"  平均置信度: {quality['avg_extraction_confidence']:.3f}")
            print(f"  高置信度API: {quality['high_confidence_apis']}")
            print(f"  关键优先级API: {quality['critical_priority_apis']}")

            print(f"🏦 机构分布:")
            for inst, data in extraction['institution_stats'].items():
                print(f"  {inst}: {data['api_count']} 个API (置信度: {data['avg_confidence']:.3f})")

            # 导出结果
            if pipeline.export_pipeline_results(report, args.output):
                print(f"💾 详细报告已保存到: {args.output}")
        else:
            print(f"❌ 增强学习管道失败: {report.get('error', 'Unknown error')}")

    except Exception as e:
        print(f"❌ 处理失败: {e}")
        return 1

    return 0


if __name__ == '__main__':
    exit(main())
