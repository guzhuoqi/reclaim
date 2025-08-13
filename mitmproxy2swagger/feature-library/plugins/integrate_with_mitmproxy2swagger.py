#!/usr/bin/env python3
"""
特征库与mitmproxy2swagger集成脚本
Feature Library Integration with mitmproxy2swagger

这个脚本展示了如何将特征库插件无缝集成到现有的mitmproxy2swagger工作流中。
支持多种集成方式，包括直接集成、插件模式和扩展模式。

使用方式：
1. 直接集成模式：python3 integrate_with_mitmproxy2swagger.py --mode direct --input flows.mitm
2. 插件模式：python3 integrate_with_mitmproxy2swagger.py --mode plugin --input flows.mitm
3. 扩展模式：python3 integrate_with_mitmproxy2swagger.py --mode extension --input flows.mitm
"""

import os
import sys
import json
import argparse
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

# 添加项目路径
current_dir = Path(__file__).parent
sys.path.append(str(current_dir.parent.parent))
sys.path.append(str(current_dir.parent))
sys.path.append(str(current_dir))

# 导入mitmproxy2swagger核心模块
from mitmproxy2swagger.mitmproxy_capture_reader import MitmproxyCaptureReader

# 导入我们的插件系统
from plugin_manager import initialize_plugin_system, plugin_manager
from feature_library_plugin import FeatureLibraryPlugin


class MitmproxySwaggerIntegrator:
    """mitmproxy2swagger集成器"""

    def __init__(self, integration_mode: str = "plugin"):
        """初始化集成器

        Args:
            integration_mode: 集成模式 (direct, plugin, extension)
        """
        self.integration_mode = integration_mode
        self.logger = logging.getLogger(__name__)

        # 设置日志
        self.setup_logging()

        # 根据模式初始化组件
        self.initialize_components()

    def setup_logging(self):
        """设置日志配置 - 只输出到控制台"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler()
            ]
        )

    def initialize_components(self):
        """根据集成模式初始化组件"""
        if self.integration_mode == "direct":
            # 直接集成模式：直接使用特征库组件
            from ai_analysis_features.financial_api_analyzer import FinancialAPIAnalyzer
            from filter_features.api_value_filter import APIValueFilter

            self.analyzer = FinancialAPIAnalyzer()
            self.filter = APIValueFilter()
            self.logger.info("✅ 直接集成模式初始化完成")

        elif self.integration_mode == "plugin":
            # 插件模式：使用插件管理器
            success = initialize_plugin_system(str(current_dir))
            if success:
                self.plugin_manager = plugin_manager
                self.logger.info("✅ 插件模式初始化完成")
            else:
                raise Exception("插件系统初始化失败")

        elif self.integration_mode == "extension":
            # 扩展模式：尝试集成到现有的mitmproxy2swagger扩展点
            self.initialize_extension_mode()

        else:
            raise ValueError(f"不支持的集成模式: {self.integration_mode}")

    def initialize_extension_mode(self):
        """初始化扩展模式"""
        try:
            # 尝试集成到现有的ExtractorRegistry
            from enhanced_mitmproxy2swagger.balance_data_extractor import extractor_registry
            from feature_library_plugin import FeatureLibraryExtractor

            # 注册我们的提取器
            feature_extractor = FeatureLibraryExtractor()
            extractor_registry.register(feature_extractor)

            self.extractor_registry = extractor_registry
            self.logger.info("✅ 扩展模式初始化完成 - 已注册到ExtractorRegistry")

        except ImportError:
            self.logger.warning("⚠️  ExtractorRegistry不可用，回退到插件模式")
            self.integration_mode = "plugin"
            self.initialize_components()

    def process_mitm_file(self, mitm_file_path: str, output_file: str = None) -> Dict[str, Any]:
        """处理mitm文件

        Args:
            mitm_file_path: mitm文件路径
            output_file: 输出文件路径

        Returns:
            处理结果
        """
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"integrated_results_{timestamp}.json"

        self.logger.info(f"🚀 开始处理mitm文件: {mitm_file_path}")
        self.logger.info(f"📊 集成模式: {self.integration_mode}")

        # 根据集成模式选择处理方法
        if self.integration_mode == "direct":
            return self._process_direct_mode(mitm_file_path, output_file)
        elif self.integration_mode == "plugin":
            return self._process_plugin_mode(mitm_file_path, output_file)
        elif self.integration_mode == "extension":
            return self._process_extension_mode(mitm_file_path, output_file)

    def _process_direct_mode(self, mitm_file_path: str, output_file: str) -> Dict[str, Any]:
        """直接集成模式处理"""
        results = {
            "mode": "direct",
            "input_file": mitm_file_path,
            "output_file": output_file,
            "processed_flows": 0,
            "valuable_apis": 0,
            "extracted_data": []
        }

        try:
            # 读取mitm文件
            capture_reader = MitmproxyCaptureReader(mitm_file_path)

            # 🎯 第一遍：收集所有流数据用于登录分析
            all_flows = []
            for flow_wrapper in capture_reader.captured_requests():
                results["processed_flows"] += 1

                # 获取完整的流信息
                url = flow_wrapper.get_url()

                # 安全地获取响应体，处理编码问题
                try:
                    response_body = flow_wrapper.get_response_body()
                except ValueError as e:
                    if 'Invalid Content-Encoding' in str(e):
                        self.logger.warning(f"⚠️  跳过编码有问题的响应: {url}")
                        continue
                    else:
                        raise

                # 构建流数据
                flow_data = {
                    'url': url,
                    'method': flow_wrapper.get_method(),
                    'request_headers': flow_wrapper.get_request_headers(),
                    'request_body': flow_wrapper.get_request_body(),
                    'response_headers': flow_wrapper.get_response_headers(),
                    'response_body': response_body,
                    'status_code': flow_wrapper.get_response_status_code()
                }
                all_flows.append(flow_data)

            # 🎯 执行完整的登录API分析
            login_analysis = self.analyzer.analyze_login_apis(all_flows)
            results["login_analysis"] = login_analysis

            # 🎯 第二遍：对有价值的API进行特征分析
            for flow_data in all_flows:
                url = flow_data['url']
                response_body = flow_data['response_body']

                if not response_body:
                    continue

                # 解码响应内容
                response_content = response_body.decode('utf-8', errors='ignore')

                # 使用特征库分析
                analysis_result = self.analyzer.analyze_api(
                    url=url,
                    response_content=response_content
                )

                # 只处理有价值的API
                if analysis_result.priority_level in ["medium", "high", "critical"]:
                    results["valuable_apis"] += 1

                    # 提取数据
                    extracted_item = {
                        "url": url,
                        "institution": analysis_result.institution,
                        "value_score": analysis_result.value_score,
                        "priority_level": analysis_result.priority_level,
                        "data_types": analysis_result.data_types,
                        "matched_patterns": analysis_result.matched_patterns,
                        # 🎯 新增：API分类信息
                        "api_category": analysis_result.api_category,
                        "provider_worthy": analysis_result.provider_worthy,
                        # 🎯 新增：响应数据信息
                        "response_data": {
                            "status_code": flow_data.get('status_code'),
                            "content_type": flow_data.get('response_headers', {}).get('content-type', ''),
                            "content_length": len(response_body) if response_body else 0,
                            "content": response_content[:30000] if response_content else '',  # 保存前30000字符用于分析 [VERSION-FIX-20250813]
                            "has_content": bool(response_content and len(response_content.strip()) > 0)
                        }
                    }

                    results["extracted_data"].append(extracted_item)

            # 保存结果
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)

            self.logger.info(f"✅ 直接模式处理完成: {results['valuable_apis']}/{results['processed_flows']} 有价值API")
            return results

        except Exception as e:
            self.logger.error(f"❌ 直接模式处理失败: {e}")
            results["error"] = str(e)
            return results

    def _process_plugin_mode(self, mitm_file_path: str, output_file: str) -> Dict[str, Any]:
        """插件模式处理"""
        results = {
            "mode": "plugin",
            "input_file": mitm_file_path,
            "output_file": output_file,
            "plugins_used": [],
            "processed_flows": 0,
            "plugin_results": {}
        }

        try:
            # 获取已加载的插件
            loaded_plugins = self.plugin_manager.list_plugins()
            results["plugins_used"] = list(loaded_plugins.keys())

            # 读取mitm文件
            capture_reader = MitmproxyCaptureReader(mitm_file_path)

            for flow_wrapper in capture_reader.captured_requests():
                results["processed_flows"] += 1

                url = flow_wrapper.get_url()

                # 安全地获取响应体，处理编码问题
                try:
                    response_body = flow_wrapper.get_response_body()
                except ValueError as e:
                    if 'Invalid Content-Encoding' in str(e):
                        self.logger.warning(f"⚠️  跳过编码有问题的响应: {url}")
                        continue
                    else:
                        raise

                if not response_body:
                    continue

                # 对每个插件执行处理
                for plugin_name, plugin_instance in self.plugin_manager.plugins.items():
                    if hasattr(plugin_instance, 'extractor'):
                        extractor = plugin_instance.extractor

                        # 检查是否可以处理
                        if extractor.can_handle(url, response_body):
                            # 提取数据
                            extracted_data = extractor.extract_data(url, response_body)

                            if extracted_data:
                                if plugin_name not in results["plugin_results"]:
                                    results["plugin_results"][plugin_name] = []

                                results["plugin_results"][plugin_name].append({
                                    "url": url,
                                    "data": extracted_data
                                })

            # 保存结果
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)

            total_extractions = sum(len(data) for data in results["plugin_results"].values())
            self.logger.info(f"✅ 插件模式处理完成: {total_extractions} 次数据提取")
            return results

        except Exception as e:
            self.logger.error(f"❌ 插件模式处理失败: {e}")
            results["error"] = str(e)
            return results

    def _process_extension_mode(self, mitm_file_path: str, output_file: str) -> Dict[str, Any]:
        """扩展模式处理"""
        results = {
            "mode": "extension",
            "input_file": mitm_file_path,
            "output_file": output_file,
            "processed_flows": 0,
            "enhanced_responses": 0,
            "extraction_results": []
        }

        try:
            # 使用现有的ExtractorRegistry处理
            capture_reader = MitmproxyCaptureReader(mitm_file_path)

            for flow_wrapper in capture_reader.captured_requests():
                results["processed_flows"] += 1

                url = flow_wrapper.get_url()

                # 安全地获取响应体，处理编码问题
                try:
                    response_body = flow_wrapper.get_response_body()
                except ValueError as e:
                    if 'Invalid Content-Encoding' in str(e):
                        self.logger.warning(f"⚠️  跳过编码有问题的响应: {url}")
                        continue
                    else:
                        raise

                if not response_body:
                    continue

                # 使用ExtractorRegistry查找合适的提取器
                extractor = self.extractor_registry.find_extractor(url, response_body)

                if extractor:
                    # 提取增强数据
                    extracted_data, schema_enhancement = self.extractor_registry.extract_enhanced_data(url, response_body)

                    if extracted_data:
                        results["enhanced_responses"] += 1
                        results["extraction_results"].append({
                            "url": url,
                            "extractor_type": extractor.__class__.__name__,
                            "extracted_data": extracted_data,
                            "schema_enhancement": schema_enhancement
                        })

            # 保存结果
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)

            self.logger.info(f"✅ 扩展模式处理完成: {results['enhanced_responses']}/{results['processed_flows']} 增强响应")
            return results

        except Exception as e:
            self.logger.error(f"❌ 扩展模式处理失败: {e}")
            results["error"] = str(e)
            return results

    def get_integration_status(self) -> Dict[str, Any]:
        """获取集成状态"""
        status = {
            "integration_mode": self.integration_mode,
            "timestamp": datetime.now().isoformat()
        }

        if self.integration_mode == "plugin":
            status["plugin_manager_status"] = self.plugin_manager.get_status_report()
        elif self.integration_mode == "extension":
            status["extractor_registry_available"] = hasattr(self, 'extractor_registry')

        return status


def main():
    """命令行接口"""
    parser = argparse.ArgumentParser(description='特征库与mitmproxy2swagger集成')
    parser.add_argument('--mode', '-m', choices=['direct', 'plugin', 'extension'],
                       default='plugin', help='集成模式')
    parser.add_argument('--input', '-i', required=True, help='输入的mitm文件路径')
    parser.add_argument('--output', '-o', help='输出文件路径')
    parser.add_argument('--status', '-s', action='store_true', help='显示集成状态')

    args = parser.parse_args()

    try:
        # 创建集成器
        integrator = MitmproxySwaggerIntegrator(args.mode)

        if args.status:
            # 显示状态
            status = integrator.get_integration_status()
            print("📊 集成状态:")
            print(json.dumps(status, indent=2, ensure_ascii=False))

        # 处理文件
        result = integrator.process_mitm_file(args.input, args.output)

        if "error" not in result:
            print(f"✅ 处理成功!")
            print(f"📊 模式: {result['mode']}")
            print(f"📁 输出文件: {result['output_file']}")

            if result['mode'] == 'direct':
                print(f"🎯 有价值API: {result['valuable_apis']}/{result['processed_flows']}")
            elif result['mode'] == 'plugin':
                total_extractions = sum(len(data) for data in result['plugin_results'].values())
                print(f"🔌 插件提取: {total_extractions} 次")
            elif result['mode'] == 'extension':
                print(f"🚀 增强响应: {result['enhanced_responses']}/{result['processed_flows']}")
        else:
            print(f"❌ 处理失败: {result['error']}")

    except Exception as e:
        print(f"❌ 集成失败: {e}")


if __name__ == "__main__":
    main()
