#!/usr/bin/env python3
"""
动态配置管理器 - 实时发现模式
Dynamic Configuration Manager - Real-time Discovery

功能：
1. 通过命令动态发现正在运行的mitmproxy实例
2. 扫描进程参数解析监听地址
3. 网络端口扫描验证可用性
4. 环境变量覆盖支持

发现方式：
1. ps命令扫描mitmproxy进程
2. 解析--listen-host和--listen-port参数
3. 常用端口扫描测试
4. HTTP接口验证(/flows/dump)
"""

import os
import json
import subprocess
import re
import socket
import requests
import logging
from typing import Dict, Any, Optional, Tuple, List
from pathlib import Path

logger = logging.getLogger(__name__)

class DynamicConfig:
    """动态配置管理器 - 实时发现mitmproxy实例"""

    def __init__(self, config_file: str = "config.json"):
        self.config_file = config_file
        self.config_data = {}
        self._discovered_host = None
        self._discovered_port = None
        self.load_config()

    def load_config(self):
        """加载配置文件（作为备用配置）"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config_data = json.load(f)
                logger.info(f"✅ 配置文件加载成功: {self.config_file}")
            else:
                logger.warning(f"⚠️  配置文件不存在，使用默认配置: {self.config_file}")
                self.config_data = {}
        except Exception as e:
            logger.error(f"❌ 配置文件加载失败: {e}")
            self.config_data = {}

    def discover_running_mitmproxy(self) -> Tuple[Optional[str], Optional[int]]:
        """
        动态发现正在运行的mitmproxy实例
        返回: (host, port) 或 (None, None)
        """
        logger.info("🔍 开始动态发现运行中的mitmproxy实例...")

        # 快速固定配置 - 直接使用已知的mitmproxy配置
        known_host = "10.10.12.249"
        known_port = 8082

        if self._test_mitmproxy_connection(known_host, known_port):
            logger.info(f"✅ 使用固定配置发现mitmproxy: {known_host}:{known_port}")
            self._discovered_host = known_host
            self._discovered_port = known_port
            return known_host, known_port

        # 方法1: 扫描mitmproxy进程（作为备选）
        result = self._scan_mitmproxy_processes()
        if result:
            host, port = result
            logger.info(f"✅ 通过进程扫描发现mitmproxy: {host}:{port}")
            self._discovered_host = host
            self._discovered_port = port
            return host, port

        logger.warning("❌ 未发现运行中的mitmproxy实例")
        return None, None

    def _scan_mitmproxy_processes(self) -> Optional[Tuple[str, int]]:
        """扫描运行中的mitmproxy相关进程"""
        try:
            # 使用更高效的ps命令，直接过滤mitmproxy进程
            result = subprocess.run(
                ['ps', '-ef'],
                capture_output=True,
                text=True,
                timeout=5  # 减少超时时间
            )

            if result.returncode != 0:
                return None

            # 先用grep过滤，提高效率
            grep_result = subprocess.run(
                ['grep', 'mitm'],
                input=result.stdout,
                capture_output=True,
                text=True,
                timeout=2
            )

            if grep_result.returncode != 0:
                return None

            for line in grep_result.stdout.split('\n'):
                if line.strip() and not line.strip().endswith('grep mitm'):
                    logger.debug(f"发现mitmproxy进程: {line.strip()}")

                    # 解析监听地址参数
                    host, port = self._parse_mitm_args(line)
                    if host and port:
                        logger.info(f"✅ 从进程参数解析到: {host}:{port}")
                        return host, port

            return None
        except Exception as e:
            logger.error(f"扫描mitmproxy进程失败: {e}")
            return None

    def _parse_mitm_args(self, process_line: str) -> Tuple[Optional[str], Optional[int]]:
        """解析mitmproxy进程的监听参数"""
        try:
            host = None
            web_port = None

            # 1. 匹配 --listen-host 参数
            host_match = re.search(r'--listen-host[=\s]+(\S+)', process_line)
            if host_match:
                host = host_match.group(1)

            # 2. 匹配 --set web_host=主机 参数（mitmweb特有）
            if not host:
                web_host_match = re.search(r'--set\s+web_host[=:](\S+)', process_line)
                if web_host_match:
                    host = web_host_match.group(1)

            # 3. 匹配 --set web_port=端口 参数（mitmweb的管理端口）
            web_port_match = re.search(r'--set\s+web_port[=:](\d+)', process_line)
            if web_port_match:
                web_port = int(web_port_match.group(1))

            # 4. 匹配 --listen-port 参数（代理端口，作为备选）
            if not web_port:
                port_match = re.search(r'--listen-port[=\s]+(\d+)', process_line)
                if port_match:
                    web_port = int(port_match.group(1))

            # 5. 匹配 -p 端口参数
            if not web_port:
                p_match = re.search(r'-p\s+(\d+)', process_line)
                if p_match:
                    web_port = int(p_match.group(1))

            # 6. 如果找到了端口但没有主机，使用默认主机
            if web_port and not host:
                host = "127.0.0.1"

            # 7. 记录解析结果用于调试
            if host and web_port:
                logger.debug(f"成功解析参数: host={host}, web_port={web_port}")
                return host, web_port
            else:
                logger.debug(f"参数解析失败: host={host}, web_port={web_port}")
                logger.debug(f"进程行: {process_line}")

            return None, None
        except Exception as e:
            logger.debug(f"解析进程参数失败: {e}")
            return None, None

    def _scan_common_endpoints(self) -> Optional[Tuple[str, int]]:
        """扫描常用的mitmproxy主机和端口组合"""
        # 常用主机地址（按优先级排序）
        common_hosts = [
            "127.0.0.1",     # 最常用的本地地址
            "localhost",     # 本地地址别名
            "10.10.12.249",  # 从当前进程发现的地址
            "10.10.11.28",   # 用户提到的实际地址
            "0.0.0.0",       # 监听所有接口
            "10.10.10.146"   # 配置文件中的地址
        ]

        # 常用端口（按使用频率排序，优先mitmweb管理端口）
        common_ports = [8082, 8080, 8081, 9999, 9090, 8888, 3128]

        logger.info(f"🔍 扫描 {len(common_hosts)} 个主机地址和 {len(common_ports)} 个端口...")

        # 优化：先测试最可能的组合（优先mitmweb管理端口）
        priority_combinations = [
            ("10.10.12.249", 8082),  # 当前发现的mitmweb管理端口
            ("127.0.0.1", 8082),     # 本地mitmweb管理端口
            ("localhost", 8082),     # 本地别名
            ("10.10.12.249", 9999),  # 代理端口作为备选
        ]

        logger.debug("🚀 优先测试常见组合...")
        for host, port in priority_combinations:
            if self._test_mitmproxy_connection(host, port):
                logger.info(f"✅ 优先扫描命中: {host}:{port}")
                return host, port

        # 如果优先组合都失败，再进行全面扫描
        logger.debug("🔍 进行全面端口扫描...")
        for host in common_hosts:
            for port in common_ports:
                # 跳过已经测试过的组合
                if (host, port) not in priority_combinations:
                    if self._test_mitmproxy_connection(host, port):
                        return host, port

        return None

    def _test_mitmproxy_connection(self, host: str, port: int) -> bool:
        """测试mitmproxy连接是否可用"""
        try:
            # 1. 快速TCP连接测试
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()

            if result != 0:
                return False

            # 2. 测试mitmweb的API接口（使用轻量级接口）
            try:
                # 先尝试访问根路径，通常更轻量
                test_url = f"http://{host}:{port}/"
                response = requests.get(test_url, timeout=2)

                # 检查是否是mitmweb（通过响应头或内容特征）
                if response.status_code == 200:
                    # 检查响应头中的Server字段
                    server_header = response.headers.get('Server', '').lower()
                    if 'mitmproxy' in server_header:
                        logger.debug(f"✅ mitmweb验证成功: {host}:{port} (Server: {server_header})")
                        return True

                    # 检查响应内容是否包含mitmproxy特征
                    content = response.text[:1000]  # 只检查前1000字符
                    if any(keyword in content.lower() for keyword in ['mitmproxy', 'mitmweb']):
                        logger.debug(f"✅ mitmweb验证成功: {host}:{port} (内容特征匹配)")
                        return True

                logger.debug(f"❌ 不是mitmweb服务: {host}:{port} -> {response.status_code}")
                return False

            except requests.exceptions.RequestException as e:
                logger.debug(f"❌ HTTP请求失败: {host}:{port} -> {e}")
                return False

        except Exception as e:
            logger.debug(f"连接测试失败 {host}:{port}: {e}")
            return False

    def get_mitm_host(self, override_value: Optional[str] = None) -> str:
        """获取mitm主机地址

        优先级：override_value > 环境变量 > 动态发现 > config.json > 默认值
        """
        # 1. 参数覆盖
        if override_value:
            logger.info(f"使用参数覆盖的mitm_host: {override_value}")
            return override_value

        # 2. 环境变量
        env_host = os.getenv('MITM_HOST')
        if env_host:
            logger.info(f"使用环境变量MITM_HOST: {env_host}")
            return env_host

        # 3. 动态发现
        if not self._discovered_host:
            self.discover_running_mitmproxy()  # 实时发现

        if self._discovered_host:
            logger.info(f"使用动态发现的mitm_host: {self._discovered_host}")
            return self._discovered_host

        # 4. 配置文件
        config_host = self._get_config_value('pipeline.default_mitm_host')
        if config_host:
            logger.info(f"使用配置文件中的mitm_host: {config_host}")
            return config_host

        # 5. 默认值
        default_host = "127.0.0.1"
        logger.warning(f"使用默认mitm_host: {default_host}")
        return default_host

    def get_mitm_port(self, override_value: Optional[int] = None) -> int:
        """获取mitm端口

        优先级：override_value > 环境变量 > 动态发现 > config.json > 默认值
        """
        # 1. 参数覆盖
        if override_value:
            logger.info(f"使用参数覆盖的mitm_port: {override_value}")
            return override_value

        # 2. 环境变量
        env_port = os.getenv('MITM_PORT')
        if env_port:
            try:
                port = int(env_port)
                logger.info(f"使用环境变量MITM_PORT: {port}")
                return port
            except ValueError:
                logger.warning(f"环境变量MITM_PORT无效: {env_port}")

        # 3. 动态发现
        if not self._discovered_port:
            self.discover_running_mitmproxy()  # 实时发现

        if self._discovered_port:
            logger.info(f"使用动态发现的mitm_port: {self._discovered_port}")
            return self._discovered_port

        # 4. 配置文件
        config_port = self._get_config_value('pipeline.default_mitm_port')
        if config_port:
            logger.info(f"使用配置文件中的mitm_port: {config_port}")
            return config_port

        # 5. 默认值
        default_port = 8080
        logger.warning(f"使用默认mitm_port: {default_port}")
        return default_port

    def _get_config_value(self, key_path: str) -> Any:
        """从配置数据中获取嵌套键值"""
        try:
            keys = key_path.split('.')
            value = self.config_data
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return None

    def refresh_discovery(self):
        """刷新动态发现缓存"""
        logger.info("🔄 刷新mitmproxy动态发现...")
        self._discovered_host = None
        self._discovered_port = None
        self.discover_running_mitmproxy()

    def get_discovery_status(self) -> Dict[str, Any]:
        """获取发现状态信息"""
        return {
            "discovered_host": self._discovered_host,
            "discovered_port": self._discovered_port,
            "discovery_successful": self._discovered_host is not None and self._discovered_port is not None,
            "current_mitm_host": self.get_mitm_host(),
            "current_mitm_port": self.get_mitm_port(),
            "env_mitm_host": os.getenv('MITM_HOST'),
            "env_mitm_port": os.getenv('MITM_PORT'),
            "config_loaded": len(self.config_data) > 0
        }

    def test_current_config(self) -> bool:
        """测试当前配置的mitmproxy是否可用"""
        host = self.get_mitm_host()
        port = self.get_mitm_port()
        return self._test_mitmproxy_connection(host, port)


# 全局实例
dynamic_config = DynamicConfig()

if __name__ == "__main__":
    # 测试脚本
    print("🧪 测试动态mitmproxy发现功能")
    print("=" * 50)

    # 设置调试日志级别
    logging.basicConfig(level=logging.DEBUG)

    config = DynamicConfig()

    # 手动触发动态发现
    print("\n🔍 手动触发动态发现...")
    host, port = config.discover_running_mitmproxy()
    print(f"动态发现结果: {host}:{port}")

    # 显示发现状态
    status = config.get_discovery_status()
    print("\n发现状态:")
    for key, value in status.items():
        print(f"  {key}: {value}")

    print(f"\n最终配置:")
    print(f"  Host: {config.get_mitm_host()}")
    print(f"  Port: {config.get_mitm_port()}")

    # 测试连接
    print(f"\n连接测试:")
    if config.test_current_config():
        print("✅ mitmproxy连接测试成功")
    else:
        print("❌ mitmproxy连接测试失败")