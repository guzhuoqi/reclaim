#!/usr/bin/env python3
"""
集成主流程脚本
Integrated Main Pipeline Script

集成特征库分析和Provider构建的完整主流程
从mitm抓包文件到最终Reclaim Provider配置的一站式解决方案

核心功能：
1. 检测mitm代理服务状态
2. 导出抓包文件（可选）
3. 运行严格特征库分析（integrate_with_mitmproxy2swagger.py）
4. 构建Reclaim Provider配置（provider_builder.py）
5. 生成完整的执行报告

使用方式：
- 在线模式：python3 integrated_main_pipeline.py
- 离线模式：python3 integrated_main_pipeline.py --offline --input-file flows.mitm
- 指定配置：python3 integrated_main_pipeline.py --mitm-host 10.10.10.146 --mitm-port 8082
"""

import os
import sys
import json
import time
import requests
import argparse
import subprocess
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from math import floor

# 添加项目路径
current_dir = Path(__file__).parent
sys.path.append(str(current_dir.parent / "feature-library" / "plugins"))

# 确保logs和data目录存在
os.makedirs('logs', exist_ok=True)
os.makedirs('data', exist_ok=True)

# 配置日志 - 只输出到控制台，不创建日志文件
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class IntegratedMainPipeline:
    """集成主流程管道器"""

    def __init__(self, config: Dict[str, Any] = None):
        """初始化集成流程

        Args:
            config: 配置字典
        """
        self.config = config or {}

        # 默认配置
        self.default_config = {
            'mitm_host': '127.0.0.1',
            'mitm_port': 8080,
            'output_dir': 'data',
            'temp_dir': 'temp'
        }

        # 合并配置
        for key, value in self.default_config.items():
            if key not in self.config:
                self.config[key] = value

        # 确保目录存在
        self.ensure_directories()

        # 流程状态跟踪
        self.pipeline_state = {
            'mitm_status': 'unknown',
            'export_file': None,
            'analysis_result': None,
            'provider_result': None,
            'steps_completed': [],
            'errors': [],
            'start_time': datetime.now(),
            'output_files': {}
        }

        logger.info(f"集成主流程初始化完成，配置: {self.config}")

    def ensure_directories(self):
        """确保必要的目录存在"""
        for dir_key in ['output_dir', 'temp_dir']:
            dir_path = self.config[dir_key]
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
                print(f"✅ 创建目录: {dir_path}")

    def check_mitm_proxy_status(self) -> Tuple[bool, str]:
        """检测mitmproxy服务状态

        Returns:
            Tuple[bool, str]: (是否运行, 状态消息)
        """
        mitm_host = self.config['mitm_host']
        mitm_port = self.config['mitm_port']

        try:
            base = f"http://{mitm_host}:{mitm_port}"
            url = f"{base}/flows/dump"
            print(f"🔍 检测mitm代理状态: {mitm_host}:{mitm_port}")

            # 兼容 mitmweb CSRF 保护：先访问首页拿 csrftoken，再携带头部访问 /flows/dump
            session = requests.Session()
            try:
                r0 = session.get(base + "/", timeout=5)
                csrf_token = session.cookies.get('csrftoken') or session.cookies.get('csrf_token')
                headers = {
                    'X-CSRFToken': csrf_token
                } if csrf_token else {}
                # 补充Referer与XHR头，兼容严格模式
                headers['Referer'] = base + "/"
                headers['X-Requested-With'] = 'XMLHttpRequest'
                response = session.get(url, headers=headers, timeout=5)
            except Exception:
                # 回退到直接请求
                response = requests.get(url, timeout=5)

            if response.status_code == 200:
                content_length = len(response.content)
                self.pipeline_state['mitm_status'] = 'running'
                status_msg = f"✅ mitm代理运行正常，当前流量数据: {content_length} bytes"
                print(status_msg)
                logger.info(f"mitm代理状态正常: {content_length} bytes")
                return True, status_msg
            else:
                error_msg = f"❌ mitm代理响应异常: HTTP {response.status_code}"
                print(error_msg)
                logger.error(error_msg)
                return False, error_msg

        except requests.exceptions.ConnectionError:
            error_msg = f"❌ 无法连接到mitm代理: {mitm_host}:{mitm_port}"
            print(error_msg)
            logger.error(error_msg)
            self.pipeline_state['mitm_status'] = 'connection_failed'
            return False, error_msg

        except Exception as e:
            error_msg = f"❌ mitm代理检测失败: {e}"
            print(error_msg)
            logger.error(error_msg)
            self.pipeline_state['mitm_status'] = 'error'
            return False, error_msg

    def export_mitm_flows(self, output_file: str = None, max_download_bytes: Optional[int] = None) -> Optional[str]:
        """从mitmproxy导出流量数据

        Args:
            output_file: 输出文件路径，如果为None则自动生成
            max_download_bytes: 最大下载字节数，通过curl --max-filesize限制或mitmproxy API查询参数间接控制

        Returns:
            导出的文件路径，失败返回None
        """
        if not output_file:
            date_str = datetime.now().strftime("%Y%m%d")
            output_file = os.path.join(self.config['temp_dir'], f"flows_export_{date_str}.mitm")

        mitm_host = self.config['mitm_host']
        mitm_port = self.config['mitm_port']
        
        # 构建API URL，如果指定了大小限制，尝试通过查询参数间接控制
        base = f"http://{mitm_host}:{mitm_port}"
        base_url = f"{base}/flows/dump"
        if max_download_bytes:
            # 估算流量条数限制（假设平均每条流量约10KB）
            estimated_flows = max(1, max_download_bytes // (10 * 1024))
            # 注意：mitmproxy可能不支持limit参数，这里作为尝试
            url = f"{base_url}?limit={estimated_flows}"
            print(f"   尝试限制流量条数: {estimated_flows} (基于{max_download_bytes}字节估算)")
        else:
            url = base_url

        try:
            print(f"📥 开始导出流量数据...")
            print(f"   源地址: {url}")
            print(f"   目标文件: {output_file}")

            # 获取 CSRF token（如果有）
            csrf_token = None
            try:
                s = requests.Session()
                s.get(base + "/", timeout=5)
                csrf_token = s.cookies.get('csrftoken') or s.cookies.get('csrf_token')
            except Exception:
                csrf_token = None

            # 使用curl命令导出，可选限制下载大小（携带 CSRF/Referer/XHR）
            curl_cmd = ['curl', '-s', url, '-H', f'Referer: {base}/', '-H', 'X-Requested-With: XMLHttpRequest']
            if csrf_token:
                curl_cmd.extend(['-H', f'X-CSRFToken: {csrf_token}', '-b', f'csrftoken={csrf_token}'])
            if max_download_bytes:
                curl_cmd.extend(['--max-filesize', str(max_download_bytes)])
                print(f"   限制下载大小: {max_download_bytes} bytes ({max_download_bytes / 1024 / 1024:.1f}MB)")

            with open(output_file, 'wb') as f:
                result = subprocess.run(curl_cmd, stdout=f, stderr=subprocess.PIPE)

            if result.returncode == 0:
                file_size = os.path.getsize(output_file)
                if file_size > 0:
                    print(f"✅ 成功导出流量数据: {file_size} bytes")
                    logger.info(f"流量数据导出成功: {output_file}, {file_size} bytes")

                    # 若文件超过5MB，按规则裁剪
                    MAX_SIZE = 5 * 1024 * 1024
                    if file_size > MAX_SIZE:
                        print("⚠️  导出文件大于5MB，开始按规则裁剪（最近30分钟，且最终不超过5MB）...")
                        trimmed_file = self._trim_mitm_file(output_file, max_size_bytes=MAX_SIZE, window_minutes=30)
                        if trimmed_file and os.path.exists(trimmed_file):
                            output_file = trimmed_file
                            file_size = os.path.getsize(output_file)
                            print(f"✅ 裁剪完成: {file_size} bytes -> {output_file}")
                            logger.info(f"流量数据已裁剪至<=5MB: {output_file}, {file_size} bytes")
                        else:
                            print("⚠️  裁剪失败或无可用数据，继续使用原始导出文件")

                    self.pipeline_state['export_file'] = output_file
                    self.pipeline_state['steps_completed'].append('export')
                    return output_file
                else:
                    print(f"⚠️  导出的文件为空")
                    logger.warning("导出的文件为空")
                    return None
            else:
                error_msg = result.stderr.decode() if result.stderr else "未知错误"
                # curl返回码63表示文件大小超过--max-filesize限制
                if result.returncode == 63:
                    print(f"⚠️  下载被中断：文件大小超过限制 ({max_download_bytes} bytes)")
                    # 检查是否有部分数据被下载
                    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                        file_size = os.path.getsize(output_file)
                        print(f"✅ 已下载部分数据: {file_size} bytes，继续使用")
                        logger.info(f"部分下载完成: {output_file}, {file_size} bytes")
                        self.pipeline_state['export_file'] = output_file
                        self.pipeline_state['steps_completed'].append('export')
                        return output_file
                    else:
                        print(f"❌ 未获取到有效数据")
                        return None
                else:
                    print(f"❌ curl导出失败: {error_msg}")
                    logger.error(f"curl导出失败: {error_msg}")
                    return None

        except Exception as e:
            print(f"❌ 导出流量数据失败: {e}")
            logger.error(f"导出流量数据失败: {e}")
            self.pipeline_state['errors'].append(f"导出失败: {e}")
            return None

    def _trim_mitm_file(self, input_file: str, max_size_bytes: int = 5 * 1024 * 1024, window_minutes: int = 30) -> Optional[str]:
        """将mitm抓包文件按规则裁剪：超过阈值时，仅保留最近window_minutes分钟内的流量；
        如仍超过阈值，则仅保留最近的部分流量，使文件不大于阈值。

        Returns: 新文件路径，失败返回None
        """
        try:
            from mitmproxy import io as mitm_io
            from mitmproxy import http as mitm_http
            import time as _time

            input_size = os.path.getsize(input_file)
            if input_size <= max_size_bytes:
                return input_file

            # 读取全部flows并附带时间戳
            flows: List[Tuple[float, Any]] = []
            with open(input_file, 'rb') as f:
                reader = mitm_io.FlowReader(f)
                for obj in reader.stream():
                    if isinstance(obj, mitm_http.HTTPFlow) and obj.response is not None:
                        ts = getattr(obj.request, 'timestamp_start', None)
                        if ts is None:
                            # 退化到响应结束时间或当前时间
                            ts = getattr(obj.response, 'timestamp_end', _time.time())
                        flows.append((float(ts), obj))

            if not flows:
                return None

            # 仅在原始文件超限时应用时间窗口
            latest_ts = max(ts for ts, _ in flows)
            threshold = latest_ts - window_minutes * 60
            recent_flows = [flow for ts, flow in flows if ts >= threshold]

            # 若时间窗口无数据，则不应用窗口，使用全部flows
            candidate_flows = recent_flows if recent_flows else [flow for _, flow in flows]

            # 如候选写出后仍可能超限，估算每flow大小，确定最大N
            temp_dir = self.config['temp_dir']
            os.makedirs(temp_dir, exist_ok=True)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            sample_path = os.path.join(temp_dir, f"_trim_sample_{timestamp}.mitm")

            # 采样前K条计算平均size
            sample_count = min(50, len(candidate_flows))
            if sample_count == 0:
                return None
            with open(sample_path, 'wb') as wf:
                writer = mitm_io.FlowWriter(wf)
                for flow in candidate_flows[:sample_count]:
                    writer.add(flow)
            sample_size = os.path.getsize(sample_path)
            try:
                os.remove(sample_path)
            except Exception:
                pass

            avg_per_flow = max(1, sample_size // sample_count)
            max_flows = max(1, max_size_bytes // avg_per_flow)

            # 选择最近的max_flows条
            candidate_flows_sorted = sorted(candidate_flows, key=lambda fl: getattr(fl.request, 'timestamp_start', 0.0) or getattr(fl.response, 'timestamp_end', 0.0) or 0.0, reverse=True)
            selected = candidate_flows_sorted[:max_flows]

            # 写入最终文件（按时间升序写入更贴近原始顺序）
            final_flows = list(reversed(selected))
            out_path = os.path.join(temp_dir, f"flows_recent_{timestamp}.mitm")
            with open(out_path, 'wb') as wf:
                writer = mitm_io.FlowWriter(wf)
                for flow in final_flows:
                    writer.add(flow)

            # 若估算失误导致仍超限，做1-2次缩减重写
            retries = 2
            while os.path.getsize(out_path) > max_size_bytes and len(final_flows) > 1 and retries > 0:
                shrink_to = max(1, int(len(final_flows) * 0.85))
                final_flows = final_flows[-shrink_to:]
                with open(out_path, 'wb') as wf:
                    writer = mitm_io.FlowWriter(wf)
                    for flow in final_flows:
                        writer.add(flow)
                retries -= 1

            # 最终保障不超过阈值，若仍超限，返回None
            if os.path.getsize(out_path) <= max_size_bytes:
                return out_path
            return None
        except Exception as e:
            logger.warning(f"裁剪mitm文件失败: {e}")
            return None

    def run_feature_analysis(self, mitm_file: str) -> Optional[Dict[str, Any]]:
        """运行严格特征库分析

        Args:
            mitm_file: mitm文件路径

        Returns:
            分析结果字典，失败返回None
        """
        try:
            print(f"🔍 开始运行严格特征库分析...")
            print(f"   输入文件: {mitm_file}")

            # 构建分析结果文件名（使用日期，覆盖写）
            date_str = datetime.now().strftime("%Y%m%d")
            analysis_file = os.path.join(self.config['output_dir'], f"feature_analysis_{date_str}.json")

            # 运行integrate_with_mitmproxy2swagger.py脚本
            script_path = current_dir.parent / "feature-library" / "plugins" / "integrate_with_mitmproxy2swagger.py"

            cmd = [
                sys.executable,
                str(script_path),
                "--mode", "direct",
                "--input", mitm_file,
                "--output", analysis_file
            ]

            print(f"   执行命令: {' '.join(cmd)}")
            logger.info(f"执行特征库分析: {' '.join(cmd)}")

            # 提高超时时间，避免大流量或复杂分析导致的误判失败
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)

            if result.returncode == 0:
                # 检查分析结果文件
                if os.path.exists(analysis_file):
                    with open(analysis_file, 'r', encoding='utf-8') as f:
                        analysis_data = json.load(f)

                    valuable_apis = analysis_data.get('valuable_apis', 0)
                    processed_flows = analysis_data.get('processed_flows', 0)

                    print(f"✅ 特征库分析完成:")
                    print(f"   - 处理流量: {processed_flows}")
                    print(f"   - 有价值API: {valuable_apis}")
                    print(f"   - 分析文件: {analysis_file}")

                    logger.info(f"特征库分析成功: {valuable_apis}/{processed_flows} APIs")

                    self.pipeline_state['analysis_result'] = {
                        'success': True,
                        'analysis_file': analysis_file,
                        'valuable_apis': valuable_apis,
                        'processed_flows': processed_flows,
                        'analysis_data': analysis_data
                    }
                    self.pipeline_state['output_files']['analysis'] = analysis_file
                    self.pipeline_state['steps_completed'].append('analysis')

                    return self.pipeline_state['analysis_result']
                else:
                    print(f"❌ 分析结果文件未生成: {analysis_file}")
                    logger.error(f"分析结果文件未生成: {analysis_file}")
                    return None
            else:
                error_msg = result.stderr if result.stderr else result.stdout
                print(f"❌ 特征库分析失败:")
                print(f"   返回码: {result.returncode}")
                print(f"   错误信息: {error_msg}")
                logger.error(f"特征库分析失败: {result.returncode}, {error_msg}")
                return None

        except subprocess.TimeoutExpired:
            # 超时兜底：若输出文件已生成且可读，则按成功处理
            print(f"❌ 特征库分析超时（15分钟）")
            logger.error("特征库分析超时")
            try:
                date_str = datetime.now().strftime("%Y%m%d")
                analysis_file = os.path.join(self.config['output_dir'], f"feature_analysis_{date_str}.json")
                if os.path.exists(analysis_file) and os.path.getsize(analysis_file) > 0:
                    with open(analysis_file, 'r', encoding='utf-8') as f:
                        analysis_data = json.load(f)

                    valuable_apis = analysis_data.get('valuable_apis', 0)
                    processed_flows = analysis_data.get('processed_flows', 0)

                    print(f"⚠️  使用超时前已生成的分析结果继续流程")
                    print(f"   - 处理流量: {processed_flows}")
                    print(f"   - 有价值API: {valuable_apis}")
                    print(f"   - 分析文件: {analysis_file}")

                    self.pipeline_state['analysis_result'] = {
                        'success': True,
                        'analysis_file': analysis_file,
                        'valuable_apis': valuable_apis,
                        'processed_flows': processed_flows,
                        'analysis_data': analysis_data
                    }
                    self.pipeline_state['output_files']['analysis'] = analysis_file
                    self.pipeline_state['steps_completed'].append('analysis')
                    return self.pipeline_state['analysis_result']
            except Exception as _:
                pass
            return None
        except Exception as e:
            print(f"❌ 特征库分析异常: {e}")
            logger.error(f"特征库分析异常: {e}")
            self.pipeline_state['errors'].append(f"特征库分析异常: {e}")
            return None

    def run_simple_enhanced_learning(self, mitm_file: str) -> Optional[Dict[str, Any]]:
        """运行简化的增强学习

        Args:
            mitm_file: mitm文件路径

        Returns:
            增强学习结果
        """
        try:
            print(f"🧠 开始增强学习: {mitm_file}")

            # 构建增强学习命令
            learning_script = os.path.join(
                os.path.dirname(__file__),
                "..",
                "feature-library",
                "learning_engine",
                "enhanced_learning_pipeline.py"
            )

            # 生成输出文件名
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            learning_output = os.path.join(
                self.config['output_dir'],
                f"enhanced_learning_report_{timestamp}.json"
            )

            # 构建命令
            cmd = [
                sys.executable,
                learning_script,
                "--input", mitm_file,
                "--output", learning_output
            ]

            print(f"🔧 执行增强学习...")

            # 执行增强学习
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180  # 3分钟超时
            )

            execution_time = time.time() - start_time

            if result.returncode == 0:
                print(f"✅ 增强学习完成，耗时: {execution_time:.1f}秒")

                # 读取学习结果
                if os.path.exists(learning_output):
                    with open(learning_output, 'r', encoding='utf-8') as f:
                        learning_data = json.load(f)

                    # 提取关键统计信息
                    stats = learning_data.get('pipeline_stats', {})
                    extraction = learning_data.get('extraction_summary', {})

                    learning_summary = {
                        'success': True,
                        'execution_time': execution_time,
                        'api_count': extraction.get('validated_count', 0),
                        'institution_count': len(extraction.get('institution_stats', {})),
                        'feature_library_updates': stats.get('feature_library_updates', 0),
                        'output_file': learning_output
                    }

                    print(f"📊 学习统计: {stats.get('candidates_discovered', 0)} 个候选API")
                    print(f"📊 验证通过: {extraction.get('validated_count', 0)} 个API")
                    print(f"📊 特征库更新: {stats.get('feature_library_updates', 0)} 项")

                    return learning_summary
                else:
                    print("⚠️  增强学习输出文件未生成")
                    return None
            else:
                print(f"⚠️  增强学习执行失败: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            print("⚠️  增强学习执行超时（3分钟）")
            return None

        except Exception as e:
            print(f"⚠️  增强学习异常: {e}")
            return None

    def run_provider_builder(self, mitm_file: str, analysis_file: str) -> Optional[Dict[str, Any]]:
        """运行Provider构建器

        Args:
            mitm_file: mitm文件路径
            analysis_file: 分析结果文件路径

        Returns:
            构建结果字典，失败返回None
        """
        try:
            print(f"🏗️  开始运行Provider构建器...")
            print(f"   mitm文件: {mitm_file}")
            print(f"   分析文件: {analysis_file}")

            # 运行provider_builder.py脚本
            script_path = current_dir / "provider_builder.py"

            cmd = [
                sys.executable,
                str(script_path),
                "--mitm-file", mitm_file,
                "--analysis-file", analysis_file,
                "--output-dir", self.config['output_dir']
            ]

            print(f"   执行命令: {' '.join(cmd)}")
            logger.info(f"执行Provider构建: {' '.join(cmd)}")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                # 解析输出，查找生成的文件
                output_lines = result.stdout.split('\n')
                providers_file = None
                questionable_file = None

                for line in output_lines:
                    if 'Providers:' in line and '.json' in line:
                        providers_file = line.split('Providers:')[-1].strip()
                    elif '存疑APIs:' in line and '.json' in line:
                        questionable_file = line.split('存疑APIs:')[-1].strip()

                # 验证文件存在
                providers_count = 0
                questionable_count = 0

                if providers_file and os.path.exists(providers_file):
                    try:
                        with open(providers_file, 'r', encoding='utf-8') as f:
                            providers_data = json.load(f)
                        providers_count = providers_data.get('metadata', {}).get('total_providers', 0)
                    except Exception as e:
                        logger.warning(f"读取providers文件失败: {e}")

                if questionable_file and os.path.exists(questionable_file):
                    try:
                        with open(questionable_file, 'r', encoding='utf-8') as f:
                            questionable_data = json.load(f)
                        questionable_count = questionable_data.get('metadata', {}).get('total_questionable', 0)
                    except Exception as e:
                        logger.warning(f"读取questionable文件失败: {e}")

                print(f"✅ Provider构建完成:")
                print(f"   - 成功构建: {providers_count} 个providers")
                print(f"   - 存疑API: {questionable_count} 个")
                print(f"   - Providers文件: {providers_file}")
                print(f"   - 存疑文件: {questionable_file}")

                logger.info(f"Provider构建成功: {providers_count} providers, {questionable_count} questionable")

                self.pipeline_state['provider_result'] = {
                    'success': True,
                    'providers_file': providers_file,
                    'questionable_file': questionable_file,
                    'providers_count': providers_count,
                    'questionable_count': questionable_count
                }

                if providers_file:
                    self.pipeline_state['output_files']['providers'] = providers_file
                if questionable_file:
                    self.pipeline_state['output_files']['questionable'] = questionable_file

                self.pipeline_state['steps_completed'].append('provider_build')

                return self.pipeline_state['provider_result']
            else:
                error_msg = result.stderr if result.stderr else result.stdout
                print(f"❌ Provider构建失败:")
                print(f"   返回码: {result.returncode}")
                print(f"   错误信息: {error_msg}")
                logger.error(f"Provider构建失败: {result.returncode}, {error_msg}")
                return None

        except subprocess.TimeoutExpired:
            print(f"❌ Provider构建超时（5分钟）")
            logger.error("Provider构建超时")
            return None
        except Exception as e:
            print(f"❌ Provider构建异常: {e}")
            logger.error(f"Provider构建异常: {e}")
            self.pipeline_state['errors'].append(f"Provider构建异常: {e}")
            return None

    def generate_pipeline_report(self) -> Dict[str, Any]:
        """生成完整的流程执行报告"""
        end_time = datetime.now()
        execution_duration = (end_time - self.pipeline_state['start_time']).total_seconds()

        # 基础报告信息
        report = {
            "pipeline_metadata": {
                "execution_start": self.pipeline_state['start_time'].isoformat(),
                "execution_end": end_time.isoformat(),
                "execution_duration_seconds": execution_duration,
                "pipeline_version": "2.0.0",
                "integrated_scripts": [
                    "integrate_with_mitmproxy2swagger.py",
                    "provider_builder.py"
                ]
            },
            "configuration": {
                "mitm_host": self.config['mitm_host'],
                "mitm_port": self.config['mitm_port'],
                "output_dir": self.config['output_dir'],
                "temp_dir": self.config['temp_dir']
            },
            "execution_status": {
                "mitm_status": self.pipeline_state['mitm_status'],
                "steps_completed": self.pipeline_state['steps_completed'],
                "steps_total": ["export", "analysis", "provider_build"],
                "success_rate": len(self.pipeline_state['steps_completed']) / 3,
                "errors": self.pipeline_state['errors']
            },
            "results": {
                "export_file": self.pipeline_state['export_file'],
                "output_files": self.pipeline_state['output_files']
            }
        }

        # 添加分析结果 - 安全检查
        if self.pipeline_state and self.pipeline_state.get('analysis_result'):
            analysis = self.pipeline_state['analysis_result']
            report["analysis_results"] = {
                "success": analysis.get('success', False),
                "processed_flows": analysis.get('processed_flows', 0),
                "valuable_apis": analysis.get('valuable_apis', 0),
                "analysis_file": analysis.get('analysis_file', ''),
                "identification_rate": (analysis.get('valuable_apis', 0) / max(analysis.get('processed_flows', 1), 1)) * 100
            }

        # 添加Provider构建结果 - 安全检查
        if self.pipeline_state and self.pipeline_state.get('provider_result'):
            provider = self.pipeline_state['provider_result']
            report["provider_results"] = {
                "success": provider.get('success', False),
                "providers_count": provider.get('providers_count', 0),
                "questionable_count": provider.get('questionable_count', 0),
                "providers_file": provider.get('providers_file', ''),
                "questionable_file": provider.get('questionable_file', ''),
                "success_rate": provider.get('providers_count', 0) / max(
                    provider.get('providers_count', 0) + provider.get('questionable_count', 0), 1
                ) * 100
            }

        # 计算整体成功状态 - 安全检查pipeline_state
        if self.pipeline_state:
            steps_completed = len(self.pipeline_state.get('steps_completed', []))
            errors_count = len(self.pipeline_state.get('errors', []))
            provider_result = self.pipeline_state.get('provider_result', {})
            provider_success = provider_result.get('success', False) if provider_result else False

            overall_success = (
                steps_completed >= 2 and  # 至少完成分析和构建
                errors_count == 0 and
                provider_success
            )

            completion_percentage = (steps_completed / 3) * 100
            final_providers_generated = provider_result.get('providers_count', 0) if provider_result else 0
        else:
            overall_success = False
            completion_percentage = 0
            final_providers_generated = 0

        report["overall_status"] = {
            "success": overall_success,
            "completion_percentage": completion_percentage,
            "final_providers_generated": final_providers_generated
        }

        return report

    def save_pipeline_report(self, report: Dict[str, Any]) -> str:
        """保存流程报告到文件"""
        date_str = datetime.now().strftime("%Y%m%d")
        report_file = os.path.join(self.config['output_dir'], f"integrated_pipeline_report_{date_str}.json")

        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

            print(f"📊 流程报告已保存: {report_file}")
            logger.info(f"流程报告保存成功: {report_file}")
            return report_file

        except Exception as e:
            print(f"⚠️  保存流程报告失败: {e}")
            logger.error(f"保存流程报告失败: {e}")
            return ""

    def print_final_summary(self, report: Dict[str, Any]):
        """打印最终执行摘要"""
        print("\n" + "=" * 80)
        print("🎉 集成主流程执行完成!")
        print("=" * 80)

        # 执行状态
        overall = report.get('overall_status', {})
        if overall.get('success'):
            print(f"✅ 整体状态: 成功")
        else:
            print(f"⚠️  整体状态: 部分成功或失败")

        print(f"📊 完成度: {overall.get('completion_percentage', 0):.1f}%")
        print(f"⏱️  执行时间: {report.get('pipeline_metadata', {}).get('execution_duration_seconds', 0):.1f}秒")

        # 分析结果
        analysis = report.get('analysis_results', {})
        if analysis:
            print(f"\n🔍 特征库分析结果:")
            print(f"   - 处理流量: {analysis.get('processed_flows', 0)}")
            print(f"   - 有价值API: {analysis.get('valuable_apis', 0)}")
            print(f"   - 识别率: {analysis.get('identification_rate', 0):.1f}%")

        # Provider构建结果
        provider = report.get('provider_results', {})
        if provider:
            print(f"\n🏗️  Provider构建结果:")
            print(f"   - 成功构建: {provider.get('providers_count', 0)} 个")
            print(f"   - 存疑API: {provider.get('questionable_count', 0)} 个")
            print(f"   - 成功率: {provider.get('success_rate', 0):.1f}%")

        # 输出文件
        output_files = report.get('results', {}).get('output_files', {})
        if output_files:
            print(f"\n📁 输出文件:")
            for file_type, file_path in output_files.items():
                print(f"   - {file_type}: {file_path}")

        # 错误信息
        errors = report.get('execution_status', {}).get('errors', [])
        if errors:
            print(f"\n⚠️  执行过程中的错误:")
            for error in errors:
                print(f"   - {error}")

        print("=" * 80)

    def run_full_pipeline(self, offline_mode: bool = False, input_file: str = None) -> Dict[str, Any]:
        """运行完整的集成主流程

        Args:
            offline_mode: 离线模式，不检测mitm代理
            input_file: 指定输入文件（离线模式）

        Returns:
            流程执行结果
        """
        print("🚀 启动集成主流程 - 特征库分析 + Provider构建")
        print(f"📁 输出目录: {self.config['output_dir']}")
        print("=" * 80)

        logger.info("集成主流程开始执行")

        # 步骤1: 检测mitm代理和导出数据（如果不是离线模式）
        mitm_file = None

        if not offline_mode:
            print("📡 步骤1: 检测mitm代理状态")
            mitm_running, status_msg = self.check_mitm_proxy_status()

            if not mitm_running:
                print(f"💡 提示: 如需离线模式，请使用 --offline --input-file <file>")
                return {
                    "success": False,
                    "message": "mitm代理未运行，无法导出数据",
                    "report": self.generate_pipeline_report()
                }

            print("\n📥 步骤2: 导出流量数据")
            mitm_file = self.export_mitm_flows()
            if not mitm_file:
                return {
                    "success": False,
                    "message": "流量数据导出失败",
                    "report": self.generate_pipeline_report()
                }
        else:
            # 离线模式，使用指定的输入文件
            if not input_file or not os.path.exists(input_file):
                return {
                    "success": False,
                    "message": f"离线模式下找不到输入文件: {input_file}",
                    "report": self.generate_pipeline_report()
                }

            mitm_file = input_file
            print(f"📄 离线模式，使用输入文件: {mitm_file}")
            self.pipeline_state['export_file'] = mitm_file
            self.pipeline_state['steps_completed'].append('export')

        print("\n" + "-" * 80)

        # 步骤2.5: 前置增强学习（新增）
        print("🧠 步骤2.5: 前置增强学习 - 学习抓包文件中的API模式")
        learning_result = self.run_simple_enhanced_learning(mitm_file)
        if learning_result and learning_result.get('success'):
            print(f"✅ 增强学习完成: 发现 {learning_result.get('api_count', 0)} 个API，更新特征库")
        else:
            print("⚠️  增强学习失败，继续使用原有特征库")

        print("\n" + "-" * 80)

        # 步骤3: 运行特征库分析
        print("🔍 步骤3: 运行严格特征库分析")
        analysis_result = self.run_feature_analysis(mitm_file)
        if not analysis_result:
            return {
                "success": False,
                "message": "特征库分析失败",
                "report": self.generate_pipeline_report()
            }

        print("\n" + "-" * 80)

        # 步骤3/4: 运行Provider构建
        print("🏗️  步骤4: 运行Provider构建器")
        provider_result = self.run_provider_builder(mitm_file, analysis_result['analysis_file'])
        if not provider_result:
            return {
                "success": False,
                "message": "Provider构建失败",
                "report": self.generate_pipeline_report()
            }

        # 生成最终报告
        final_report = self.generate_pipeline_report()
        report_file = self.save_pipeline_report(final_report)

        # 添加报告文件到输出文件列表
        if report_file:
            self.pipeline_state['output_files']['report'] = report_file
            final_report['results']['output_files']['report'] = report_file

        # 打印最终摘要
        self.print_final_summary(final_report)

        logger.info("集成主流程执行完成")

        return {
            "success": True,
            "message": "集成主流程执行成功",
            "report": final_report,
            "output_files": self.pipeline_state['output_files']
        }


def main():
    """命令行接口"""
    parser = argparse.ArgumentParser(
        description='集成主流程 - 特征库分析 + Provider构建',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 在线模式（自动检测mitm代理并导出数据）
  python3 integrated_main_pipeline.py

  # 指定mitm代理地址
  python3 integrated_main_pipeline.py --mitm-host 10.10.10.146 --mitm-port 8082

  # 离线模式（使用现有的mitm文件）
  python3 integrated_main_pipeline.py --offline --input-file flows.mitm

  # 指定输出目录
  python3 integrated_main_pipeline.py --output-dir ./results
        """
    )

    # 基础参数
    parser.add_argument('--mitm-host', default='127.0.0.1',
                       help='mitmproxy主机地址 (默认: 127.0.0.1)')
    parser.add_argument('--mitm-port', type=int, default=8080,
                       help='mitmproxy端口 (默认: 8080)')
    parser.add_argument('--output-dir', default='data',
                       help='输出目录 (默认: data)')
    parser.add_argument('--temp-dir', default='temp',
                       help='临时目录 (默认: temp)')

    # 离线模式参数
    parser.add_argument('--offline', action='store_true',
                       help='离线模式，不检测mitm代理')
    parser.add_argument('--input-file', '-i',
                       help='离线模式下的输入mitm文件路径')

    # 其他选项
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='详细输出模式')

    args = parser.parse_args()

    # 验证参数
    if args.offline and not args.input_file:
        print("❌ 离线模式下必须指定 --input-file 参数")
        parser.print_help()
        sys.exit(1)

    if args.offline and args.input_file and not os.path.exists(args.input_file):
        print(f"❌ 输入文件不存在: {args.input_file}")
        sys.exit(1)

    # 构建配置
    config = {
        'mitm_host': args.mitm_host,
        'mitm_port': args.mitm_port,
        'output_dir': args.output_dir,
        'temp_dir': args.temp_dir
    }

    # 设置日志级别
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # 创建并运行集成流程
        pipeline = IntegratedMainPipeline(config)
        result = pipeline.run_full_pipeline(
            offline_mode=args.offline,
            input_file=args.input_file
        )

        # 根据结果设置退出码
        if result['success']:
            print(f"\n🎉 集成主流程执行成功!")
            if 'output_files' in result:
                print(f"📁 生成的文件:")
                for file_type, file_path in result['output_files'].items():
                    print(f"   - {file_type}: {file_path}")
            sys.exit(0)
        else:
            print(f"\n❌ 集成主流程执行失败: {result['message']}")
            sys.exit(1)

    except KeyboardInterrupt:
        print(f"\n⚠️  用户中断执行")
        sys.exit(130)
    except Exception as e:
        print(f"\n💥 执行过程中发生异常: {e}")
        logger.error(f"执行异常: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
