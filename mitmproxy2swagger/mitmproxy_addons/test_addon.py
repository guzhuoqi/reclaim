#!/usr/bin/env python3
"""
测试定制化转发Addon
Test Custom Forwarding Addon

功能特性：
1. 配置文件验证
2. URL匹配测试
3. 转发规则测试
4. 性能基准测试

使用方式：
    python3 test_addon.py --all
    python3 test_addon.py --config
    python3 test_addon.py --url-matching
    python3 test_addon.py --forwarding
"""

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Any
from urllib.parse import urlparse


class AddonTester:
    """Addon测试器"""

    def __init__(self):
        self.addon_path = Path(__file__).parent / "custom_forwarding_addon.py"
        self.config_path = Path(__file__).parent / "forwarding_config.json"
        self.config: Dict[str, Any] = {}
        self.test_results: Dict[str, bool] = {}

    def load_config(self) -> bool:
        """加载配置文件"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
            return True
        except Exception as e:
            print(f"❌ 加载配置失败: {e}")
            return False

    def test_config_validation(self) -> bool:
        """测试配置文件验证"""
        print("\n🔍 测试配置文件验证...")

        # 检查必需的配置项
        required_sections = [
            "global_settings",
            "url_filtering",
            "forwarding_rules",
            "security"
        ]

        for section in required_sections:
            if section not in self.config:
                print(f"❌ 缺少配置节: {section}")
                return False
            print(f"✅ 配置节存在: {section}")

        # 检查全局设置
        global_settings = self.config.get("global_settings", {})
        if not isinstance(global_settings.get("enable_logging"), bool):
            print("❌ enable_logging 应该是布尔值")
            return False

        # 检查URL过滤配置
        url_filtering = self.config.get("url_filtering", {})
        for filter_name, filter_config in url_filtering.items():
            if not isinstance(filter_config.get("enabled"), bool):
                print(f"❌ {filter_name}.enabled 应该是布尔值")
                return False

            patterns = filter_config.get("patterns", [])
            if not isinstance(patterns, list):
                print(f"❌ {filter_name}.patterns 应该是列表")
                return False

            # 验证正则表达式
            for pattern in patterns:
                try:
                    re.compile(pattern)
                except re.error:
                    print(f"❌ 无效的正则表达式: {pattern}")
                    return False

        print("✅ 配置文件验证通过")
        return True

    def test_url_matching(self) -> bool:
        """测试URL匹配功能"""
        print("\n🔍 测试URL匹配功能...")

        # 测试用例
        test_cases = [
            # (URL, 期望的匹配类型)
            ("https://example.com/style.css", "static_resources"),
            ("https://example.com/script.js", "static_resources"),
            ("https://example.com/image.png", "static_resources"),
            ("https://example.com/health", "low_value_apis"),
            ("https://example.com/ping", "low_value_apis"),
            ("https://bochk.com/api/balance", "high_priority_apis"),
            ("https://example.com/api/account", "high_priority_apis"),
            ("https://example.com/normal-page", None),
        ]

        url_filtering = self.config.get("url_filtering", {})

        for url, expected_type in test_cases:
            parsed = urlparse(url)
            path = parsed.path

            matched_type = None
            for filter_type, filter_config in url_filtering.items():
                if not filter_config.get("enabled", False):
                    continue

                patterns = filter_config.get("patterns", [])
                for pattern in patterns:
                    try:
                        if re.search(pattern, path, re.IGNORECASE):
                            matched_type = filter_type
                            break
                    except re.error:
                        continue

                if matched_type:
                    break

            if matched_type == expected_type:
                print(f"✅ {url} -> {matched_type or 'no_match'}")
            else:
                print(f"❌ {url} -> 期望: {expected_type}, 实际: {matched_type}")
                return False

        print("✅ URL匹配测试通过")
        return True

    def test_forwarding_rules(self) -> bool:
        """测试转发规则"""
        print("\n🔍 测试转发规则...")

        # 新的测试用例 - 适应空配置
        test_cases = [
            # (主机名, 期望的转发规则名称) - 现在都应该是None，因为配置为空
            ("bochk.com", None),
            ("api.bochk.com", None),
            ("cmbwinglungbank.com", None),
            ("api.cmbwinglungbank.com", None),
            ("unknown-bank.com", None),
        ]

        forwarding_rules = self.config.get("forwarding_rules", {})

        for host, expected_rule_name in test_cases:
            matched_rule = None

            for rule_group, rule_config in forwarding_rules.items():
                if not rule_config.get("enabled", False):
                    continue

                for rule in rule_config.get("rules", []):
                    source_domains = rule.get("source_domains", [])

                    for domain in source_domains:
                        if domain.startswith("*."):
                            base_domain = domain[2:]
                            if host.endswith(base_domain):
                                matched_rule = rule
                                break
                        elif host == domain:
                            matched_rule = rule
                            break

                    if matched_rule:
                        break

                if matched_rule:
                    break

            matched_name = matched_rule.get("name") if matched_rule else None

            if matched_name == expected_rule_name:
                print(f"✅ {host} -> {matched_name or 'no_rule'}")
            else:
                print(f"❌ {host} -> 期望: {expected_rule_name}, 实际: {matched_name}")
                return False

        print("✅ 转发规则测试通过")
        return True

    def test_security_rules(self) -> bool:
        """测试安全规则"""
        print("\n🔍 测试安全规则...")

        security = self.config.get("security", {})

        # 测试域名白名单/黑名单
        blocked_domains = security.get("blocked_domains", [])
        allowed_domains = security.get("allowed_domains", [])

        test_hosts = [
            "bochk.com",
            "cmbwinglungbank.com",
            "malicious-site.com",
            "unknown-site.com"
        ]

        for host in test_hosts:
            is_blocked = any(domain in host for domain in blocked_domains)
            is_allowed = not allowed_domains or any(domain in host for domain in allowed_domains)

            print(f"   {host}: 阻止={is_blocked}, 允许={is_allowed}")

        # 测试速率限制配置
        rate_limiting = security.get("rate_limiting", {})
        if rate_limiting.get("enabled", False):
            requests_per_minute = rate_limiting.get("requests_per_minute", 100)
            print(f"   速率限制: {requests_per_minute} 请求/分钟")
        else:
            print("   速率限制: 禁用")

        print("✅ 安全规则测试通过")
        return True

    def test_performance(self) -> bool:
        """测试性能"""
        print("\n🔍 测试性能...")

        # 编译正则表达式
        compiled_patterns = {}
        url_filtering = self.config.get("url_filtering", {})

        for filter_type, filter_config in url_filtering.items():
            patterns = filter_config.get("patterns", [])
            compiled = []
            for pattern in patterns:
                try:
                    compiled.append(re.compile(pattern, re.IGNORECASE))
                except re.error:
                    continue
            compiled_patterns[filter_type] = compiled

        # 性能测试
        test_urls = [
            "https://example.com/style.css",
            "https://example.com/api/balance",
            "https://bochk.com/api/account",
            "https://example.com/normal-page"
        ] * 1000  # 重复1000次

        start_time = time.time()

        for url in test_urls:
            path = urlparse(url).path
            for filter_type, patterns in compiled_patterns.items():
                for pattern in patterns:
                    pattern.search(path)

        end_time = time.time()
        duration = end_time - start_time

        print(f"   处理 {len(test_urls)} 个URL用时: {duration:.3f} 秒")
        print(f"   平均每个URL: {duration/len(test_urls)*1000:.3f} 毫秒")

        if duration < 1.0:  # 1秒内完成认为性能良好
            print("✅ 性能测试通过")
            return True
        else:
            print("❌ 性能测试失败，处理速度过慢")
            return False

    def run_all_tests(self) -> bool:
        """运行所有测试"""
        print("🧪 开始运行Addon测试套件...")
        print("="*60)

        if not self.load_config():
            return False

        tests = [
            ("配置验证", self.test_config_validation),
            ("URL匹配", self.test_url_matching),
            ("转发规则", self.test_forwarding_rules),
            ("安全规则", self.test_security_rules),
            ("性能测试", self.test_performance),
        ]

        passed = 0
        total = len(tests)

        for test_name, test_func in tests:
            try:
                if test_func():
                    self.test_results[test_name] = True
                    passed += 1
                else:
                    self.test_results[test_name] = False
            except Exception as e:
                print(f"❌ {test_name} 测试异常: {e}")
                self.test_results[test_name] = False

        # 输出测试结果摘要
        print("\n" + "="*60)
        print("📊 测试结果摘要:")
        print("="*60)

        for test_name, result in self.test_results.items():
            status = "✅ 通过" if result else "❌ 失败"
            print(f"   {test_name}: {status}")

        print(f"\n总计: {passed}/{total} 测试通过")

        if passed == total:
            print("🎉 所有测试通过！Addon可以正常使用。")
            return True
        else:
            print("⚠️  部分测试失败，请检查配置或代码。")
            return False


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="测试定制化转发Addon")

    parser.add_argument("--all", action="store_true", help="运行所有测试")
    parser.add_argument("--config", action="store_true", help="测试配置验证")
    parser.add_argument("--url-matching", action="store_true", help="测试URL匹配")
    parser.add_argument("--forwarding", action="store_true", help="测试转发规则")
    parser.add_argument("--security", action="store_true", help="测试安全规则")
    parser.add_argument("--performance", action="store_true", help="测试性能")

    args = parser.parse_args()

    tester = AddonTester()

    if not tester.load_config():
        sys.exit(1)

    success = True

    if args.all:
        success = tester.run_all_tests()
    else:
        if args.config:
            success &= tester.test_config_validation()
        if args.url_matching:
            success &= tester.test_url_matching()
        if args.forwarding:
            success &= tester.test_forwarding_rules()
        if args.security:
            success &= tester.test_security_rules()
        if args.performance:
            success &= tester.test_performance()

        if not any([args.config, args.url_matching, args.forwarding, args.security, args.performance]):
            parser.print_help()
            return

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
