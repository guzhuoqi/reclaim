#!/usr/bin/env python3
"""
mitmproxy转发管理工具
Forwarding Manager for mitmproxy Custom Addon

功能特性：
1. 配置管理 - 动态修改转发规则
2. 实时监控 - 查看转发状态和指标
3. 规则测试 - 测试URL匹配和转发规则
4. 日志分析 - 分析转发日志和性能

使用方式：
    python3 forwarding_manager.py --config
    python3 forwarding_manager.py --monitor
    python3 forwarding_manager.py --test-url "https://bochk.com/api/balance"
"""

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import re


class ForwardingManager:
    """转发管理器"""

    def __init__(self, config_path: str = None):
        self.config_path = config_path or str(Path(__file__).parent / "forwarding_config.json")
        self.config: Dict[str, Any] = {}
        self.load_config()

    def load_config(self) -> bool:
        """加载配置文件"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
            print(f"✅ 加载配置文件: {self.config_path}")
            return True
        except Exception as e:
            print(f"❌ 加载配置文件失败: {e}")
            return False

    def save_config(self) -> bool:
        """保存配置文件"""
        try:
            # 更新时间戳
            self.config["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            print(f"✅ 保存配置文件: {self.config_path}")
            return True
        except Exception as e:
            print(f"❌ 保存配置文件失败: {e}")
            return False

    def show_config(self):
        """显示当前配置"""
        print("\n" + "="*60)
        print("📋 当前转发配置")
        print("="*60)

        # 全局设置
        global_settings = self.config.get("global_settings", {})
        print(f"🌐 全局设置:")
        print(f"   日志启用: {global_settings.get('enable_logging', False)}")
        print(f"   日志级别: {global_settings.get('log_level', 'INFO')}")
        print(f"   指标启用: {global_settings.get('enable_metrics', False)}")

        # URL过滤
        url_filtering = self.config.get("url_filtering", {})
        print(f"\n🔍 URL过滤:")
        for filter_type, filter_config in url_filtering.items():
            enabled = filter_config.get("enabled", False)
            action = filter_config.get("action", "unknown")
            pattern_count = len(filter_config.get("patterns", []))
            print(f"   {filter_type}: {'启用' if enabled else '禁用'} | 动作: {action} | 模式数: {pattern_count}")

        # 转发规则
        forwarding_rules = self.config.get("forwarding_rules", {})
        print(f"\n🔄 转发规则:")
        for rule_group, rule_config in forwarding_rules.items():
            enabled = rule_config.get("enabled", False)
            rule_count = len(rule_config.get("rules", []))
            print(f"   {rule_group}: {'启用' if enabled else '禁用'} | 规则数: {rule_count}")

            if enabled and rule_count > 0:
                for rule in rule_config.get("rules", []):
                    name = rule.get("name", "未命名")
                    source_domains = rule.get("source_domains", [])
                    target_host = rule.get("target_host", "未设置")
                    print(f"     - {name}: {source_domains} -> {target_host}")

        # 安全设置
        security = self.config.get("security", {})
        print(f"\n🔒 安全设置:")
        rate_limiting = security.get("rate_limiting", {})
        print(f"   速率限制: {'启用' if rate_limiting.get('enabled', False) else '禁用'}")
        if rate_limiting.get("enabled", False):
            print(f"   每分钟请求数: {rate_limiting.get('requests_per_minute', 100)}")

        blocked_count = len(security.get("blocked_domains", []))
        allowed_count = len(security.get("allowed_domains", []))
        print(f"   黑名单域名: {blocked_count} 个")
        print(f"   白名单域名: {allowed_count} 个")

    def test_url(self, url: str):
        """测试URL匹配规则"""
        print(f"\n🧪 测试URL: {url}")
        print("="*60)

        from urllib.parse import urlparse
        import re

        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path

        # 测试URL过滤
        print("🔍 URL过滤测试:")
        url_filtering = self.config.get("url_filtering", {})

        for filter_type, filter_config in url_filtering.items():
            if not filter_config.get("enabled", False):
                continue

            patterns = filter_config.get("patterns", [])
            action = filter_config.get("action", "unknown")

            matched = False
            for pattern in patterns:
                try:
                    if re.search(pattern, path, re.IGNORECASE):
                        matched = True
                        print(f"   ✅ {filter_type}: 匹配模式 '{pattern}' -> 动作: {action}")
                        break
                except re.error:
                    continue

            if not matched:
                print(f"   ❌ {filter_type}: 无匹配")

        # 测试转发规则
        print("\n🔄 转发规则测试:")
        forwarding_rules = self.config.get("forwarding_rules", {})

        matched_rule = None
        matched_rule_group = None

        for rule_group, rule_config in forwarding_rules.items():
            if not rule_config.get("enabled", False):
                continue

            matching_mode = rule_config.get("matching_mode", "domain_only")
            print(f"   检查规则组: {rule_group} (模式: {matching_mode})")

            for rule in rule_config.get("rules", []):
                source_domains = rule.get("source_domains", [])

                # 首先检查域名匹配
                domain_matched = False
                for domain in source_domains:
                    if domain.startswith("*."):
                        base_domain = domain[2:]
                        if host.endswith(base_domain):
                            domain_matched = True
                            break
                    elif host == domain:
                        domain_matched = True
                        break

                if not domain_matched:
                    continue

                # 如果是域名+路径匹配模式，还需要检查API路径
                if matching_mode == "domain_and_path":
                    api_paths = rule.get("api_paths", [])
                    if not api_paths:
                        print(f"     规则 '{rule.get('name', '未命名')}': 域名匹配但无API路径配置")
                        continue

                    path_matched = False
                    for api_path_pattern in api_paths:
                        try:
                            if re.search(api_path_pattern, path, re.IGNORECASE):
                                path_matched = True
                                print(f"     路径匹配: '{path}' 匹配模式 '{api_path_pattern}'")
                                break
                        except re.error:
                            if path.startswith(api_path_pattern):
                                path_matched = True
                                print(f"     路径匹配: '{path}' 以 '{api_path_pattern}' 开头")
                                break

                    if path_matched:
                        matched_rule = rule
                        matched_rule_group = rule_group
                        break
                else:
                    # 原有的域名匹配模式
                    matched_rule = rule
                    matched_rule_group = rule_group
                    break

            if matched_rule:
                break

        if matched_rule:
            print(f"   ✅ 匹配规则: {matched_rule.get('name', '未命名')} (来自: {matched_rule_group})")
            print(f"   目标主机: {matched_rule.get('target_host', '未设置')}")
            print(f"   目标端口: {matched_rule.get('target_port', 443)}")

            # 显示API路径信息（如果有）
            api_paths = matched_rule.get("api_paths", [])
            if api_paths:
                print(f"   API路径模式: {api_paths}")

            preserve_headers = matched_rule.get("preserve_headers", [])
            add_headers = matched_rule.get("add_headers", {})
            print(f"   保留Headers: {preserve_headers}")
            print(f"   添加Headers: {list(add_headers.keys())}")
        else:
            print("   ❌ 无匹配的转发规则")

        # 测试安全检查
        print("\n🔒 安全检查测试:")
        security = self.config.get("security", {})

        blocked_domains = security.get("blocked_domains", [])
        allowed_domains = security.get("allowed_domains", [])

        is_blocked = any(domain in host for domain in blocked_domains)
        is_allowed = not allowed_domains or any(domain in host for domain in allowed_domains)

        print(f"   黑名单检查: {'❌ 被阻止' if is_blocked else '✅ 通过'}")
        print(f"   白名单检查: {'✅ 允许' if is_allowed else '❌ 拒绝'}")

        rate_limiting = security.get("rate_limiting", {})
        if rate_limiting.get("enabled", False):
            limit = rate_limiting.get("requests_per_minute", 100)
            print(f"   速率限制: 每分钟最多 {limit} 请求")
        else:
            print("   速率限制: 禁用")

    def monitor_metrics(self):
        """监控转发指标"""
        metrics_file = self.config.get("global_settings", {}).get("metrics_file", "logs/forwarding_metrics.json")

        print(f"\n📊 监控转发指标")
        print("="*60)
        print(f"指标文件: {metrics_file}")

        try:
            with open(metrics_file, 'r', encoding='utf-8') as f:
                metrics_data = json.load(f)

            timestamp = metrics_data.get("timestamp", "未知")
            runtime = metrics_data.get("runtime_seconds", 0)
            metrics = metrics_data.get("metrics", {})

            print(f"📅 时间戳: {timestamp}")
            print(f"⏱️  运行时间: {runtime:.2f} 秒")
            print(f"\n📈 处理统计:")

            for key, value in metrics.items():
                print(f"   {key}: {value}")

        except FileNotFoundError:
            print("❌ 指标文件不存在，可能addon未运行或未启用指标收集")
        except Exception as e:
            print(f"❌ 读取指标文件失败: {e}")

    def add_forwarding_rule(self, name: str, source_domains: List[str], api_paths: List[str], target_host: str, target_port: int = 443):
        """添加转发规则（新格式：域名+API路径）"""
        bank_rules = self.config.setdefault("forwarding_rules", {}).setdefault("bank_apis", {})
        bank_rules.setdefault("enabled", True)
        bank_rules.setdefault("matching_mode", "domain_and_path")
        rules = bank_rules.setdefault("rules", [])

        new_rule = {
            "name": name,
            "source_domains": source_domains,
            "api_paths": api_paths,
            "target_host": target_host,
            "target_port": target_port,
            "preserve_headers": ["Authorization", "Cookie", "X-CSRF-Token"],
            "add_headers": {
                "X-Proxy-Source": "mitmproxy-addon",
                "X-Custom-Rule": name
            }
        }

        rules.append(new_rule)

        if self.save_config():
            print(f"✅ 添加转发规则: {name}")
            print(f"   域名: {source_domains}")
            print(f"   API路径: {api_paths}")
            print(f"   目标: {target_host}:{target_port}")
        else:
            print(f"❌ 添加转发规则失败")

    def remove_forwarding_rule(self, name: str):
        """删除转发规则"""
        bank_rules = self.config.get("forwarding_rules", {}).get("bank_apis", {})
        rules = bank_rules.get("rules", [])

        original_count = len(rules)
        rules[:] = [rule for rule in rules if rule.get("name") != name]

        if len(rules) < original_count:
            if self.save_config():
                print(f"✅ 删除转发规则: {name}")
            else:
                print(f"❌ 删除转发规则失败")
        else:
            print(f"❌ 未找到转发规则: {name}")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="mitmproxy转发管理工具")

    parser.add_argument("--config", "-c", action="store_true", help="显示当前配置")
    parser.add_argument("--monitor", "-m", action="store_true", help="监控转发指标")
    parser.add_argument("--test-url", "-t", help="测试URL匹配规则")
    parser.add_argument("--config-file", help="指定配置文件路径")

    # 规则管理
    parser.add_argument("--add-rule", help="添加转发规则名称")
    parser.add_argument("--source-domains", nargs="+", help="源域名列表")
    parser.add_argument("--api-paths", nargs="+", help="API路径模式列表（正则表达式）")
    parser.add_argument("--target-host", help="目标主机")
    parser.add_argument("--target-port", type=int, default=443, help="目标端口")
    parser.add_argument("--remove-rule", help="删除转发规则名称")

    args = parser.parse_args()

    # 创建管理器实例
    manager = ForwardingManager(args.config_file)

    if args.config:
        manager.show_config()
    elif args.monitor:
        manager.monitor_metrics()
    elif args.test_url:
        manager.test_url(args.test_url)
    elif args.add_rule:
        if not args.source_domains or not args.api_paths or not args.target_host:
            print("❌ 添加规则需要指定 --source-domains、--api-paths 和 --target-host")
            print("💡 示例: --source-domains 'bochk.com' '*.bochk.com' --api-paths '/api/.*' '/rest/.*'")
            sys.exit(1)
        manager.add_forwarding_rule(args.add_rule, args.source_domains, args.api_paths, args.target_host, args.target_port)
    elif args.remove_rule:
        manager.remove_forwarding_rule(args.remove_rule)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
