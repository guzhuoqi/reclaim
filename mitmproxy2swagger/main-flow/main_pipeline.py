#!/usr/bin/env python3
"""
主流程管道器
完整的银行Provider生成主流程：从mitmproxy导出 -> 分析提取 -> 构建Provider

主要功能：
1. 检测mitm代理服务状态
2. 导出抓包文件
3. 分析抓包文件并提取银行参数
4. 构建标准Reclaim协议Provider配置
5. 输出完整的Provider对象列表

使用方式：
- 自动模式：python3 main_pipeline.py
- 指定配置：python3 main_pipeline.py --mitm-host 10.10.10.146 --mitm-port 8082
- 离线模式：python3 main_pipeline.py --offline --input-file flows.mitm
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
from urllib.parse import urljoin
from pathlib import Path

# 确保logs目录存在
os.makedirs('logs', exist_ok=True)

# 配置日志 - 写入logs目录
log_filename = f'logs/main_pipeline_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_filename),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 导入我们的模块  
from feature_library_pipeline import FeatureLibraryPipeline
from dynamic_config import dynamic_config



class MainPipeline:
    """主流程管道器"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # 默认配置 - 使用动态配置管理器
        self.default_config = {
            'mitm_host': dynamic_config.get_mitm_host(),
            'mitm_port': dynamic_config.get_mitm_port(),
            'output_dir': 'data',
            'temp_dir': 'temp',
            'testdata_dir': '../testdata'
        }
        
        # 合并配置
        for key, value in self.default_config.items():
            if key not in self.config:
                self.config[key] = value
        
        # 与 provider_query 一致的 data 目录检测
        def detect_data_dir() -> str:
            env_dir = os.getenv('MAIN_FLOW_DATA_DIR')
            if env_dir and os.path.exists(env_dir):
                return os.path.abspath(env_dir)
            container_dir = "/app/main-flow/data"
            if os.path.exists(container_dir):
                return container_dir
            relative_dir = str((Path(__file__).resolve().parent.parent / "main-flow" / "data").resolve())
            if os.path.exists(relative_dir):
                return relative_dir
            fallback = str((Path(__file__).resolve().parent / "data").resolve())
            return fallback

        if 'output_dir' not in self.config or self.config.get('output_dir') in ('data', './data'):
            self.config['output_dir'] = detect_data_dir()

        # 归一化目录为绝对路径
        base_dir = Path(__file__).resolve().parent
        for dir_key in ['output_dir', 'temp_dir']:
            dir_path = self.config.get(dir_key)
            if isinstance(dir_path, str) and not os.path.isabs(dir_path):
                self.config[dir_key] = str((base_dir / dir_path).resolve())

        # 确保目录存在
        self.ensure_directories()
        
        # 流程状态
        self.pipeline_state = {
            'mitm_status': 'unknown',
            'export_file': None,
            'extracted_providers': None,
            'final_providers': None,
            'steps_completed': [],
            'errors': []
        }
    
    def ensure_directories(self):
        """确保必要的目录存在"""
        for dir_key in ['output_dir', 'temp_dir']:
            dir_path = self.config[dir_key]
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
                print(f"✅ 创建目录: {dir_path}")
    
    def check_mitm_proxy_status(self) -> Tuple[bool, str]:
        """
        检测mitmproxy服务状态
        
        Returns:
            (is_running: bool, status_message: str)
        """
        mitm_host = self.config['mitm_host']
        mitm_port = self.config['mitm_port']
        
        try:
            # 检查流量导出接口
            url = f"http://{mitm_host}:{mitm_port}/flows/dump"
            
            print(f"🔍 检测mitm代理状态: {mitm_host}:{mitm_port}")
            
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                # 检查响应内容长度
                content_length = len(response.content)
                self.pipeline_state['mitm_status'] = 'running'
                status_msg = f"✅ mitm代理运行正常，当前流量数据: {content_length} bytes"
                print(status_msg)
                return True, status_msg
            else:
                error_msg = f"❌ mitm代理响应异常: HTTP {response.status_code}"
                print(error_msg)
                return False, error_msg
                
        except requests.exceptions.ConnectionError:
            error_msg = f"❌ 无法连接到mitm代理: {mitm_host}:{mitm_port}"
            print(error_msg)
            self.pipeline_state['mitm_status'] = 'connection_failed'
            return False, error_msg
            
        except requests.exceptions.Timeout:
            error_msg = f"❌ mitm代理连接超时: {mitm_host}:{mitm_port}"
            print(error_msg)
            self.pipeline_state['mitm_status'] = 'timeout'
            return False, error_msg
            
        except Exception as e:
            error_msg = f"❌ mitm代理检测失败: {e}"
            print(error_msg)
            self.pipeline_state['mitm_status'] = 'error'
            return False, error_msg
    
    def export_mitm_flows(self, output_file: str = None) -> Optional[str]:
        """
        从mitmproxy导出流量数据
        
        Args:
            output_file: 输出文件路径，如果为None则自动生成
            
        Returns:
            导出的文件路径，失败返回None
        """
        if not output_file:
            timestamp = int(time.time())
            # 与 Docker 卷挂载保持一致：默认导出到绝对的 output_dir (data)
            output_file = os.path.join(self.config.get('output_dir', str((Path(__file__).resolve().parent / 'data').resolve())), f"flows_export_{timestamp}.mitm")
        else:
            output_file = os.path.abspath(output_file)
        
        mitm_host = self.config['mitm_host']
        mitm_port = self.config['mitm_port']
        url = f"http://{mitm_host}:{mitm_port}/flows/dump"
        
        try:
            print(f"📥 开始导出流量数据...")
            print(f"   源地址: {url}")
            print(f"   目标文件: {output_file}")
            
            # 使用curl命令导出（更稳定）
            curl_cmd = [
                'curl', '-s', 
                f'http://{mitm_host}:{mitm_port}/flows/dump'
            ]
            
            with open(output_file, 'wb') as f:
                result = subprocess.run(curl_cmd, stdout=f, stderr=subprocess.PIPE)
            
            if result.returncode == 0:
                # 检查文件大小
                file_size = os.path.getsize(output_file)
                if file_size > 0:
                    print(f"✅ 成功导出流量数据: {file_size} bytes")
                    self.pipeline_state['export_file'] = os.path.abspath(output_file)
                    self.pipeline_state['steps_completed'].append('export')
                    return output_file
                else:
                    print(f"⚠️  导出的文件为空")
                    return None
            else:
                error_msg = result.stderr.decode() if result.stderr else "未知错误"
                print(f"❌ curl导出失败: {error_msg}")
                return None
                
        except Exception as e:
            print(f"❌ 导出流量数据失败: {e}")
            self.pipeline_state['errors'].append(f"导出失败: {e}")
            return None
    
    def extract_bank_parameters(self, mitm_file: str) -> Optional[Dict]:
        """
        提取银行参数 - 使用特征库应用2.0流程
        
        Args:
            mitm_file: mitmproxy文件路径
            
        Returns:
            提取结果字典，失败返回None
        """
        try:
            print(f"🔄 开始特征库应用2.0流程 (三轮完整处理)...")
            
            # 创建特征库应用2.0流程管道器
            pipeline = FeatureLibraryPipeline(mitm_file, self.config['output_dir'])
            
            # 运行完整的三轮流程 (跳过AI分析以提高速度)
            result = pipeline.run_full_pipeline(skip_ai_analysis=True)
            
            if result['success']:
                # 转换结果格式以兼容现有接口
                output_files = result.get('output_files', {})
                providers_file = output_files.get('providers', '')
                
                # 从Provider文件中读取统计信息
                provider_count = 0
                if providers_file and os.path.exists(providers_file):
                    try:
                        with open(providers_file, 'r', encoding='utf-8') as f:
                            provider_data = json.load(f)
                            provider_count = provider_data.get('metadata', {}).get('total_providers', 0)
                    except Exception as e:
                        logger.warning(f"读取Provider统计失败: {e}")
                
                # 构建兼容的返回格式
                compatible_result = {
                    'success': True,
                    'reclaim_providers_count': provider_count,
                    'attestor_providers_count': 0,  # 当前版本主要生成Reclaim Provider
                    'output_files': output_files,
                    'pipeline_report': result.get('report', {}),
                    'message': '特征库应用2.0流程执行成功'
                }
                
                print(f"✅ 特征库应用2.0流程成功:")
                print(f"   Reclaim Provider: {provider_count} 个")
                print(f"   输出文件: {len(output_files)} 个")
                logger.info(f"特征库应用2.0成功 - Provider: {provider_count}, 文件: {len(output_files)}")
                
                self.pipeline_state['extracted_providers'] = compatible_result
                self.pipeline_state['steps_completed'].append('extract')
                return compatible_result
            else:
                error_msg = result.get('message', '未知错误')
                print(f"❌ 特征库应用2.0流程失败: {error_msg}")
                logger.error(f"特征库应用2.0失败: {error_msg}")
                return None
                
        except Exception as e:
            print(f"❌ 特征库应用2.0流程异常: {e}")
            logger.error(f"特征库应用2.0异常: {e}")
            self.pipeline_state['errors'].append(f"特征库流程异常: {e}")
            return None
    
    def build_providers(self, extract_result: Dict = None) -> Optional[Dict]:
        """
        构建Reclaim Provider配置
        
        Args:
            extract_result: 提取结果，如果为None则查找最新的配置文件
            
        Returns:
            构建结果字典，失败返回None
        """
        try:
            print(f"🏗️  开始构建Reclaim Provider配置...")
            
            print(f"💡 使用特征库应用2.0的输出作为最终结果")
            
            # 使用智能提取结果作为构建结果
            if extract_result and extract_result.get('success'):
                result = {
                    'success': True,
                    'reclaim_providers_count': extract_result.get('reclaim_providers_count', 0),
                    'attestor_providers_count': extract_result.get('attestor_providers_count', 0),
                    'output_files': extract_result.get('output_files', {}),
                    'message': '使用提取结果作为最终Provider配置'
                }
                
                print(f"✅ 使用提取的Provider配置:")
                print(f"   Reclaim: {result['reclaim_providers_count']} 个")
                print(f"   Attestor: {result['attestor_providers_count']} 个")
                self.pipeline_state['final_providers'] = result
                self.pipeline_state['steps_completed'].append('build')
                return result
            else:
                print(f"❌ 无法获取提取结果进行构建")
                return None
                
        except Exception as e:
            print(f"❌ Provider配置构建异常: {e}")
            self.pipeline_state['errors'].append(f"Provider构建异常: {e}")
            return None
    
    def generate_pipeline_report(self) -> Dict:
        """生成流程执行报告"""
        report = {
            "pipeline_report": {
                "execution_time": datetime.now().isoformat(),
                "mitm_config": {
                    "host": self.config['mitm_host'],
                    "port": self.config['mitm_port'],
                    "status": self.pipeline_state['mitm_status']
                },
                "steps_completed": self.pipeline_state['steps_completed'],
                "steps_total": ["export", "extract", "build"],
                "success_rate": len(self.pipeline_state['steps_completed']) / 3,
                "errors": self.pipeline_state['errors']
            },
            "results": {
                "export_file": self.pipeline_state['export_file'],
                "reclaim_providers_extracted": self.pipeline_state['extracted_providers']['reclaim_providers_count'] if self.pipeline_state['extracted_providers'] else 0,
            "attestor_providers_extracted": self.pipeline_state['extracted_providers']['attestor_providers_count'] if self.pipeline_state['extracted_providers'] else 0,
                "reclaim_providers_built": self.pipeline_state['final_providers']['reclaim_providers_count'] if self.pipeline_state['final_providers'] else 0,
            "attestor_providers_built": self.pipeline_state['final_providers']['attestor_providers_count'] if self.pipeline_state['final_providers'] else 0,
                "final_output_files": self.pipeline_state['final_providers']['output_files'] if self.pipeline_state['final_providers'] else {}
            }
        }
        
        return report
    
    def save_pipeline_report(self, report: Dict) -> str:
        """保存流程报告"""
        timestamp = int(time.time())
        report_file = os.path.join(self.config['output_dir'], f"pipeline_report_{timestamp}.json")
        
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            print(f"📊 流程报告已保存: {report_file}")
            return report_file
            
        except Exception as e:
            print(f"⚠️  保存流程报告失败: {e}")
            return ""
    
    def run_full_pipeline(self, offline_mode: bool = False, input_file: str = None) -> Dict:
        """
        运行完整的主流程
        
        Args:
            offline_mode: 离线模式，不检测mitm代理
            input_file: 指定输入文件（离线模式）
            
        Returns:
            流程执行结果
        """
        print("🚀 启动银行Provider生成主流程...")
        print(f"📁 输出目录: {self.config['output_dir']}")
        print("=" * 70)
        
        # 步骤1: 检测mitm代理和导出数据（如果不是离线模式）
        if not offline_mode:
            # 检测mitm代理
            mitm_running, status_msg = self.check_mitm_proxy_status()
            
            if not mitm_running:
                print(f"💡 提示: 如需离线模式，请使用 --offline --input-file <file>")
                return {
                    "success": False,
                    "message": "mitm代理未运行",
                    "report": self.generate_pipeline_report()
                }
            
            # 导出流量数据
            export_file = self.export_mitm_flows()
            if not export_file:
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
            
            export_file = input_file
            print(f"📄 离线模式，使用输入文件: {export_file}")
            self.pipeline_state['export_file'] = export_file
            self.pipeline_state['steps_completed'].append('export')
        
        print("-" * 70)
        
        # 步骤2: 提取银行参数 - 使用原始输入文件而不是导出文件
        original_input_file = input_file if input_file else None
        if not original_input_file:
            # 如果没有原始文件，则使用导出文件，但这不是最优的
            print("⚠️  警告: 使用导出文件而非原始文件，可能影响性能")
            original_input_file = export_file
        
        extract_result = self.extract_bank_parameters(original_input_file)
        if not extract_result:
            return {
                "success": False,
                "message": "银行参数提取失败",
                "report": self.generate_pipeline_report()
            }
        
        print("-" * 70)
        
        # 步骤3: 构建Provider配置
        build_result = self.build_providers(extract_result)
        if not build_result:
            return {
                "success": False,
                "message": "Provider配置构建失败",
                "report": self.generate_pipeline_report()
            }
        
        print("=" * 70)
        print("🎉 主流程执行完成!")
        
        # 生成最终报告
        final_report = self.generate_pipeline_report()
        report_file = self.save_pipeline_report(final_report)
        
        print(f"📊 处理结果:")
        print(f"   🏦 Reclaim Provider: {final_report['results']['reclaim_providers_extracted']}")
        print(f"   🏦 Attestor Provider: {final_report['results']['attestor_providers_extracted']}")
        print(f"   📄 Reclaim 生成: {final_report['results']['reclaim_providers_built']}")
        print(f"   📄 Attestor 生成: {final_report['results']['attestor_providers_built']}")
        print(f"   📁 输出文件: {final_report['results']['final_output_files']}")
        print(f"   📋 执行报告: {report_file}")
        
        return {
            "success": True,
            "message": "主流程执行成功",
            "report": final_report,
            "output_files": final_report['results']['final_output_files']
        }


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="银行Provider生成主流程")
    
    # mitm配置
    parser.add_argument('--mitm-host', default=dynamic_config.get_mitm_host(),
                       help=f'mitmproxy主机地址 (默认: {dynamic_config.get_mitm_host()})')
    parser.add_argument('--mitm-port', type=int, default=dynamic_config.get_mitm_port(),
                       help=f'mitmproxy端口号 (默认: {dynamic_config.get_mitm_port()})')
    
    # 离线模式
    parser.add_argument('--offline', action='store_true',
                       help='离线模式，不检测mitm代理')
    parser.add_argument('--input-file', 
                       help='离线模式的输入文件路径')
    
    # 输出配置
    parser.add_argument('--output-dir', default='data',
                       help='输出目录 (默认: data)')
    
    # 调试选项
    parser.add_argument('--verbose', action='store_true',
                       help='详细输出模式')
    
    args = parser.parse_args()
    
    # 验证离线模式参数
    if args.offline and not args.input_file:
        print("❌ 错误: 离线模式需要指定 --input-file 参数")
        return
    
    # 构建配置
    config = {
        'mitm_host': args.mitm_host,
        'mitm_port': args.mitm_port,
        'output_dir': args.output_dir
    }
    
    # 创建并运行主流程
    pipeline = MainPipeline(config)
    result = pipeline.run_full_pipeline(
        offline_mode=args.offline,
        input_file=args.input_file
    )
    
    # 输出结果
    if result['success']:
        print(f"\n✅ 主流程执行成功")
        if result.get('output_file'):
            print(f"🎯 最终输出文件: {result['output_file']}")
    else:
        print(f"\n❌ 主流程执行失败: {result['message']}")
        sys.exit(1)


if __name__ == "__main__":
    main()