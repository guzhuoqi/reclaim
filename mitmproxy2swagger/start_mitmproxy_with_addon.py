#!/usr/bin/env python3
"""
启动带有定制化转发Addon的mitmproxy
Start mitmproxy with Custom Forwarding Addon

功能特性：
1. 自动检测mitmproxy安装路径
2. 配置验证和优化建议
3. 支持多种启动模式（mitmproxy, mitmweb, mitmdump）
4. 集成转发管理工具
5. 实时日志监控

使用方式：
    python3 start_mitmproxy_with_addon.py --mode web
    python3 start_mitmproxy_with_addon.py --mode proxy --port 8080
    python3 start_mitmproxy_with_addon.py --mode dump --output flows.mitm
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional


class MitmproxyLauncher:
    """mitmproxy启动器"""
    
    def __init__(self):
        self.addon_path = Path(__file__).parent / "mitmproxy_addons" / "custom_forwarding_addon.py"
        self.config_path = Path(__file__).parent / "mitmproxy_addons" / "forwarding_config.json"
        self.mitmproxy_paths = self._find_mitmproxy_paths()
    
    def _find_mitmproxy_paths(self) -> dict:
        """查找mitmproxy安装路径"""
        paths = {}
        
        # 常见的安装路径
        common_paths = [
            "/usr/local/bin",
            "/usr/bin",
            "/opt/homebrew/bin",
            os.path.expanduser("~/Library/Python/3.9/bin"),
            os.path.expanduser("~/Library/Python/3.10/bin"),
            os.path.expanduser("~/Library/Python/3.11/bin"),
            os.path.expanduser("~/.local/bin")
        ]
        
        # 检查PATH环境变量
        path_dirs = os.environ.get("PATH", "").split(os.pathsep)
        common_paths.extend(path_dirs)
        
        for tool in ["mitmproxy", "mitmweb", "mitmdump"]:
            for path_dir in common_paths:
                tool_path = Path(path_dir) / tool
                if tool_path.exists() and tool_path.is_file():
                    paths[tool] = str(tool_path)
                    break
            
            # 如果在常见路径中没找到，尝试使用which命令
            if tool not in paths:
                try:
                    result = subprocess.run(["which", tool], capture_output=True, text=True)
                    if result.returncode == 0:
                        paths[tool] = result.stdout.strip()
                except:
                    pass
        
        return paths
    
    def validate_setup(self) -> bool:
        """验证设置"""
        print("🔍 验证mitmproxy设置...")
        
        # 检查addon文件
        if not self.addon_path.exists():
            print(f"❌ Addon文件不存在: {self.addon_path}")
            return False
        print(f"✅ Addon文件: {self.addon_path}")
        
        # 检查配置文件
        if not self.config_path.exists():
            print(f"❌ 配置文件不存在: {self.config_path}")
            return False
        print(f"✅ 配置文件: {self.config_path}")
        
        # 验证配置文件格式
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            print("✅ 配置文件格式正确")
        except Exception as e:
            print(f"❌ 配置文件格式错误: {e}")
            return False
        
        # 检查mitmproxy工具
        if not self.mitmproxy_paths:
            print("❌ 未找到mitmproxy工具")
            print("💡 请安装mitmproxy: pip install mitmproxy")
            return False
        
        print("✅ 找到mitmproxy工具:")
        for tool, path in self.mitmproxy_paths.items():
            print(f"   {tool}: {path}")
        
        # 创建必要的目录
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        print(f"✅ 日志目录: {log_dir}")
        
        return True
    
    def start_mitmweb(self, web_port: int = 8082, listen_port: int = 8080, host: str = "127.0.0.1") -> bool:
        """启动mitmweb"""
        if "mitmweb" not in self.mitmproxy_paths:
            print("❌ 未找到mitmweb")
            return False
        
        cmd = [
            self.mitmproxy_paths["mitmweb"],
            "-s", str(self.addon_path),
            "--set", f"web_port={web_port}",
            "--set", f"listen_port={listen_port}",
            "--set", "web_open_browser=false",
            "--listen-host", host,
            "--set", f"web_host={host}"
        ]
        
        print(f"🚀 启动mitmweb...")
        print(f"   Web界面: http://{host}:{web_port}")
        print(f"   代理地址: {host}:{listen_port}")
        print(f"   命令: {' '.join(cmd)}")
        print("\n💡 按 Ctrl+C 停止服务")
        
        try:
            subprocess.run(cmd)
            return True
        except KeyboardInterrupt:
            print("\n⚠️  用户中断服务")
            return True
        except Exception as e:
            print(f"❌ 启动失败: {e}")
            return False
    
    def start_mitmproxy(self, listen_port: int = 8080) -> bool:
        """启动mitmproxy命令行版"""
        if "mitmproxy" not in self.mitmproxy_paths:
            print("❌ 未找到mitmproxy")
            return False
        
        cmd = [
            self.mitmproxy_paths["mitmproxy"],
            "-s", str(self.addon_path),
            "--set", f"listen_port={listen_port}"
        ]
        
        print(f"🚀 启动mitmproxy...")
        print(f"   代理地址: 127.0.0.1:{listen_port}")
        print(f"   命令: {' '.join(cmd)}")
        print("\n💡 按 q 退出")
        
        try:
            subprocess.run(cmd)
            return True
        except KeyboardInterrupt:
            print("\n⚠️  用户中断服务")
            return True
        except Exception as e:
            print(f"❌ 启动失败: {e}")
            return False
    
    def start_mitmdump(self, listen_port: int = 8080, output_file: Optional[str] = None) -> bool:
        """启动mitmdump"""
        if "mitmdump" not in self.mitmproxy_paths:
            print("❌ 未找到mitmdump")
            return False
        
        cmd = [
            self.mitmproxy_paths["mitmdump"],
            "-s", str(self.addon_path),
            "--set", f"listen_port={listen_port}"
        ]
        
        if output_file:
            cmd.extend(["-w", output_file])
        
        print(f"🚀 启动mitmdump...")
        print(f"   代理地址: 127.0.0.1:{listen_port}")
        if output_file:
            print(f"   输出文件: {output_file}")
        print(f"   命令: {' '.join(cmd)}")
        print("\n💡 按 Ctrl+C 停止服务")
        
        try:
            subprocess.run(cmd)
            return True
        except KeyboardInterrupt:
            print("\n⚠️  用户中断服务")
            return True
        except Exception as e:
            print(f"❌ 启动失败: {e}")
            return False
    
    def show_config_summary(self):
        """显示配置摘要"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            print("\n📋 当前配置摘要:")
            print("="*50)
            
            # 全局设置
            global_settings = config.get("global_settings", {})
            print(f"🌐 日志: {'启用' if global_settings.get('enable_logging') else '禁用'}")
            print(f"🌐 指标: {'启用' if global_settings.get('enable_metrics') else '禁用'}")
            
            # URL过滤
            url_filtering = config.get("url_filtering", {})
            static_enabled = url_filtering.get("static_resources", {}).get("enabled", False)
            print(f"🔍 静态资源过滤: {'启用' if static_enabled else '禁用'}")
            
            # 转发规则
            bank_rules = config.get("forwarding_rules", {}).get("bank_apis", {})
            bank_enabled = bank_rules.get("enabled", False)
            bank_count = len(bank_rules.get("rules", []))
            print(f"🔄 银行API转发: {'启用' if bank_enabled else '禁用'} ({bank_count} 规则)")
            
            # 安全设置
            security = config.get("security", {})
            rate_enabled = security.get("rate_limiting", {}).get("enabled", False)
            print(f"🔒 速率限制: {'启用' if rate_enabled else '禁用'}")
            
        except Exception as e:
            print(f"❌ 读取配置失败: {e}")
    
    def show_usage_examples(self):
        """显示使用示例"""
        print("\n📚 使用示例:")
        print("="*50)
        print("1. 启动Web界面 (推荐):")
        print("   python3 start_mitmproxy_with_addon.py --mode web")
        print("")
        print("2. 启动命令行版本:")
        print("   python3 start_mitmproxy_with_addon.py --mode proxy")
        print("")
        print("3. 启动并保存流量:")
        print("   python3 start_mitmproxy_with_addon.py --mode dump --output flows.mitm")
        print("")
        print("4. 自定义端口:")
        print("   python3 start_mitmproxy_with_addon.py --mode web --web-port 8082 --listen-port 8080")
        print("")
        print("5. 配置管理:")
        print("   python3 mitmproxy_addons/forwarding_manager.py --config")
        print("   python3 mitmproxy_addons/forwarding_manager.py --test-url 'https://bochk.com/api/balance'")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="启动带有定制化转发Addon的mitmproxy")
    
    parser.add_argument("--mode", choices=["web", "proxy", "dump"], default="web",
                       help="启动模式 (默认: web)")
    parser.add_argument("--web-port", type=int, default=8082,
                       help="Web界面端口 (默认: 8082)")
    parser.add_argument("--listen-port", type=int, default=8080,
                       help="代理监听端口 (默认: 8080)")
    parser.add_argument("--host", default="127.0.0.1",
                       help="监听主机 (默认: 127.0.0.1)")
    parser.add_argument("--output", "-o",
                       help="输出文件 (仅dump模式)")
    parser.add_argument("--validate-only", action="store_true",
                       help="仅验证设置，不启动")
    parser.add_argument("--show-config", action="store_true",
                       help="显示配置摘要")
    parser.add_argument("--examples", action="store_true",
                       help="显示使用示例")
    
    args = parser.parse_args()
    
    launcher = MitmproxyLauncher()
    
    if args.examples:
        launcher.show_usage_examples()
        return
    
    if args.show_config:
        launcher.show_config_summary()
        return
    
    # 验证设置
    if not launcher.validate_setup():
        sys.exit(1)
    
    if args.validate_only:
        print("✅ 验证完成，设置正确")
        return
    
    # 显示配置摘要
    launcher.show_config_summary()
    
    # 启动相应模式
    success = False
    if args.mode == "web":
        success = launcher.start_mitmweb(args.web_port, args.listen_port, args.host)
    elif args.mode == "proxy":
        success = launcher.start_mitmproxy(args.listen_port)
    elif args.mode == "dump":
        success = launcher.start_mitmdump(args.listen_port, args.output)
    
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
