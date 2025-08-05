#!/usr/bin/env python3
"""
mitmproxy定制化转发Addon
Custom Forwarding Addon for mitmproxy

功能特性：
1. 智能URL过滤 - 自动过滤静态资源和低价值API
2. 定制化转发 - 支持银行API的智能转发
3. 响应增强 - 对银行余额等关键数据进行增强处理
4. 安全控制 - 域名白名单、速率限制等安全机制
5. 实时监控 - 详细的日志记录和性能指标

使用方式：
    mitmproxy -s custom_forwarding_addon.py
    mitmweb -s custom_forwarding_addon.py
"""

import json
import logging
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse

from mitmproxy import http, ctx
from mitmproxy.addonmanager import Loader


class CustomForwardingAddon:
    """定制化转发Addon主类"""

    def __init__(self):
        self.config: Dict[str, Any] = {}
        self.logger: Optional[logging.Logger] = None
        self.metrics: Dict[str, Any] = defaultdict(int)
        self.rate_limiter: Dict[str, deque] = defaultdict(deque)
        self.start_time = time.time()

        # 编译正则表达式缓存
        self.compiled_patterns: Dict[str, List[re.Pattern]] = {}

        # 加载配置
        self._load_config()
        self._setup_logging()
        self._compile_patterns()

    def _load_config(self):
        """加载配置文件"""
        config_path = Path(__file__).parent / "forwarding_config.json"
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
            print(f"✅ 加载配置文件: {config_path}")
        except Exception as e:
            print(f"❌ 加载配置文件失败: {e}")
            # 使用默认配置
            self.config = self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """获取默认配置"""
        return {
            "global_settings": {
                "enable_logging": True,
                "log_level": "INFO"
            },
            "url_filtering": {
                "static_resources": {
                    "enabled": True,
                    "action": "block",
                    "patterns": ["\\.(css|js|jpg|jpeg|png|gif|ico|svg)$"]
                }
            },
            "forwarding_rules": {"bank_apis": {"enabled": False, "rules": []}},
            "security": {"rate_limiting": {"enabled": False}}
        }

    def _setup_logging(self):
        """设置日志"""
        if not self.config.get("global_settings", {}).get("enable_logging", True):
            return

        log_level = self.config.get("global_settings", {}).get("log_level", "INFO")
        log_file = self.config.get("global_settings", {}).get("log_file", "logs/forwarding_addon.log")

        # 确保日志目录存在
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger("CustomForwardingAddon")
        self.logger.setLevel(getattr(logging, log_level))

        # 文件处理器
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, log_level))

        # 格式化器
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)
        self.logger.info("CustomForwardingAddon 初始化完成")

    def _compile_patterns(self):
        """编译正则表达式模式"""
        pattern_groups = [
            ("static_resources", self.config.get("url_filtering", {}).get("static_resources", {}).get("patterns", [])),
            ("low_value_apis", self.config.get("url_filtering", {}).get("low_value_apis", {}).get("patterns", [])),
            ("high_priority_apis", self.config.get("url_filtering", {}).get("high_priority_apis", {}).get("patterns", []))
        ]

        for group_name, patterns in pattern_groups:
            compiled = []
            for pattern in patterns:
                try:
                    compiled.append(re.compile(pattern, re.IGNORECASE))
                except re.error as e:
                    if self.logger:
                        self.logger.warning(f"无效的正则表达式 {pattern}: {e}")
            self.compiled_patterns[group_name] = compiled

    def load(self, loader: Loader):
        """mitmproxy加载时调用"""
        loader.add_option(
            name="forwarding_config",
            typespec=str,
            default="",
            help="自定义转发配置文件路径"
        )

        loader.add_option(
            name="forwarding_enabled",
            typespec=bool,
            default=True,
            help="是否启用定制化转发功能"
        )

    def configure(self, updates):
        """配置更新时调用"""
        if "forwarding_config" in updates and ctx.options.forwarding_config:
            # 重新加载配置
            try:
                with open(ctx.options.forwarding_config, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
                self._compile_patterns()
                if self.logger:
                    self.logger.info(f"重新加载配置: {ctx.options.forwarding_config}")
            except Exception as e:
                if self.logger:
                    self.logger.error(f"重新加载配置失败: {e}")

    def request(self, flow: http.HTTPFlow) -> None:
        """处理HTTP请求"""
        if not ctx.options.forwarding_enabled:
            return

        url = flow.request.pretty_url
        host = flow.request.host

        # 更新指标
        self.metrics["total_requests"] += 1

        # 1. 安全检查
        if not self._security_check(flow):
            return

        # 2. URL过滤
        filter_result = self._apply_url_filtering(flow)
        if filter_result == "block":
            return

        # 3. 应用转发规则
        self._apply_forwarding_rules(flow)

        # 4. 记录日志
        if self.logger:
            self.logger.info(f"处理请求: {flow.request.method} {url}")

    def response(self, flow: http.HTTPFlow) -> None:
        """处理HTTP响应"""
        if not ctx.options.forwarding_enabled:
            return

        # 更新指标
        self.metrics["total_responses"] += 1

        # 应用响应修改规则
        self._apply_response_modifications(flow)

        # 记录响应日志
        if self.logger and flow.response:
            self.logger.info(
                f"响应: {flow.request.method} {flow.request.pretty_url} -> {flow.response.status_code}"
            )

    def _security_check(self, flow: http.HTTPFlow) -> bool:
        """安全检查"""
        host = flow.request.host

        # 检查域名黑名单
        blocked_domains = self.config.get("security", {}).get("blocked_domains", [])
        if any(domain in host for domain in blocked_domains):
            flow.response = http.Response.make(
                403, b"Blocked by security policy", {"Content-Type": "text/plain"}
            )
            self.metrics["blocked_requests"] += 1
            return False

        # 检查域名白名单
        allowed_domains = self.config.get("security", {}).get("allowed_domains", [])
        if allowed_domains and not any(domain in host for domain in allowed_domains):
            flow.response = http.Response.make(
                403, b"Domain not in whitelist", {"Content-Type": "text/plain"}
            )
            self.metrics["blocked_requests"] += 1
            return False

        # 速率限制
        if self._is_rate_limited(host):
            flow.response = http.Response.make(
                429, b"Rate limit exceeded", {"Content-Type": "text/plain"}
            )
            self.metrics["rate_limited_requests"] += 1
            return False

        return True

    def _is_rate_limited(self, host: str) -> bool:
        """检查速率限制"""
        rate_config = self.config.get("security", {}).get("rate_limiting", {})
        if not rate_config.get("enabled", False):
            return False

        requests_per_minute = rate_config.get("requests_per_minute", 100)
        now = time.time()
        minute_ago = now - 60

        # 清理过期记录
        while self.rate_limiter[host] and self.rate_limiter[host][0] < minute_ago:
            self.rate_limiter[host].popleft()

        # 检查是否超过限制
        if len(self.rate_limiter[host]) >= requests_per_minute:
            return True

        # 记录当前请求
        self.rate_limiter[host].append(now)
        return False

    def _apply_url_filtering(self, flow: http.HTTPFlow) -> str:
        """应用URL过滤规则"""
        url = flow.request.pretty_url
        path = urlparse(url).path

        # 检查静态资源
        if self._match_patterns("static_resources", path):
            action = self.config.get("url_filtering", {}).get("static_resources", {}).get("action", "block")
            if action == "block":
                flow.response = http.Response.make(
                    404, b"Static resource filtered", {"Content-Type": "text/plain"}
                )
                self.metrics["filtered_static_resources"] += 1
                if self.logger:
                    self.logger.debug(f"过滤静态资源: {url}")
                return "block"

        # 检查低价值API
        if self._match_patterns("low_value_apis", path):
            action = self.config.get("url_filtering", {}).get("low_value_apis", {}).get("action", "log_only")
            if action == "log_only":
                self.metrics["low_value_apis"] += 1
                if self.logger:
                    self.logger.debug(f"低价值API: {url}")
            elif action == "block":
                flow.response = http.Response.make(
                    404, b"Low value API filtered", {"Content-Type": "text/plain"}
                )
                return "block"

        # 检查高优先级API
        if self._match_patterns("high_priority_apis", path):
            self.metrics["high_priority_apis"] += 1
            if self.logger:
                self.logger.info(f"高优先级API: {url}")

        return "allow"

    def _match_patterns(self, pattern_group: str, text: str) -> bool:
        """匹配正则表达式模式"""
        patterns = self.compiled_patterns.get(pattern_group, [])
        return any(pattern.search(text) for pattern in patterns)

    def _apply_forwarding_rules(self, flow: http.HTTPFlow) -> None:
        """应用转发规则"""
        host = flow.request.host
        path = urlparse(flow.request.pretty_url).path

        # 检查银行API转发规则
        bank_rules = self.config.get("forwarding_rules", {}).get("bank_apis", {})
        if bank_rules.get("enabled", False):
            matching_mode = bank_rules.get("matching_mode", "domain_only")

            for rule in bank_rules.get("rules", []):
                if matching_mode == "domain_and_path":
                    # 新的精确匹配模式：域名+API路径
                    if self._match_domain_and_path_rule(host, path, rule):
                        self._apply_forwarding_rule(flow, rule)
                        return
                else:
                    # 原有的域名匹配模式（向后兼容）
                    if self._match_domain_rule(host, rule.get("source_domains", [])):
                        self._apply_forwarding_rule(flow, rule)
                        return

        # 检查开发环境转发规则
        dev_rules = self.config.get("forwarding_rules", {}).get("development_rules", {})
        if dev_rules.get("enabled", False):
            for rule in dev_rules.get("rules", []):
                if self._match_domain_rule(host, rule.get("source_domains", [])):
                    self._apply_forwarding_rule(flow, rule)
                    return

    def _match_domain_rule(self, host: str, domains: List[str]) -> bool:
        """匹配域名规则"""
        for domain in domains:
            if domain.startswith("*."):
                # 通配符匹配
                base_domain = domain[2:]
                if host.endswith(base_domain):
                    return True
            elif host == domain:
                return True
        return False

    def _match_domain_and_path_rule(self, host: str, path: str, rule: Dict[str, Any]) -> bool:
        """匹配域名+API路径规则"""
        # 首先检查域名是否匹配
        source_domains = rule.get("source_domains", [])
        if not self._match_domain_rule(host, source_domains):
            return False

        # 然后检查API路径是否匹配
        api_paths = rule.get("api_paths", [])
        if not api_paths:
            # 如果没有指定API路径，则不匹配（避免误转发）
            return False

        # 检查路径是否匹配任何一个API路径模式
        for api_path_pattern in api_paths:
            try:
                if re.search(api_path_pattern, path, re.IGNORECASE):
                    return True
            except re.error:
                # 如果正则表达式无效，尝试精确匹配
                if path.startswith(api_path_pattern):
                    return True

        return False

    def _apply_forwarding_rule(self, flow: http.HTTPFlow, rule: Dict[str, Any]) -> None:
        """应用具体的转发规则"""
        target_host = rule.get("target_host")
        target_port = rule.get("target_port", 443)

        if target_host:
            # 修改目标主机
            original_host = flow.request.host
            flow.request.host = target_host
            flow.request.port = target_port

            # 保留指定的headers
            preserve_headers = rule.get("preserve_headers", [])
            for header in preserve_headers:
                if header in flow.request.headers:
                    # 保持原有header值
                    pass

            # 添加新的headers
            add_headers = rule.get("add_headers", {})
            for header, value in add_headers.items():
                flow.request.headers[header] = value

            # 更新Host header
            flow.request.headers["Host"] = target_host

            self.metrics["forwarded_requests"] += 1
            if self.logger:
                self.logger.info(f"转发请求: {original_host} -> {target_host}:{target_port} ({rule.get('name', 'Unknown')})")

    def _apply_response_modifications(self, flow: http.HTTPFlow) -> None:
        """应用响应修改规则"""
        if not flow.response:
            return

        url = flow.request.pretty_url
        response_rules = self.config.get("response_modification", {})

        if not response_rules.get("enabled", False):
            return

        for rule in response_rules.get("rules", []):
            url_patterns = rule.get("url_patterns", [])
            if any(re.search(pattern, url, re.IGNORECASE) for pattern in url_patterns):
                self._execute_response_actions(flow, rule.get("actions", []))

    def _execute_response_actions(self, flow: http.HTTPFlow, actions: List[Dict[str, Any]]) -> None:
        """执行响应动作"""
        for action in actions:
            action_type = action.get("type")

            if action_type == "add_header":
                header = action.get("header")
                value = action.get("value")
                if header and value:
                    flow.response.headers[header] = value

            elif action_type == "log_response":
                level = action.get("level", "INFO")
                if self.logger:
                    log_method = getattr(self.logger, level.lower(), self.logger.info)
                    log_method(f"响应修改: {flow.request.pretty_url} -> {flow.response.status_code}")

    def done(self):
        """Addon结束时调用"""
        if self.logger:
            self.logger.info("CustomForwardingAddon 结束运行")
            self.logger.info(f"运行时间: {time.time() - self.start_time:.2f}秒")
            self.logger.info(f"处理统计: {dict(self.metrics)}")

        # 保存指标到文件
        self._save_metrics()

    def _save_metrics(self):
        """保存指标到文件"""
        metrics_file = self.config.get("global_settings", {}).get("metrics_file", "logs/forwarding_metrics.json")

        try:
            Path(metrics_file).parent.mkdir(parents=True, exist_ok=True)

            metrics_data = {
                "timestamp": datetime.now().isoformat(),
                "runtime_seconds": time.time() - self.start_time,
                "metrics": dict(self.metrics)
            }

            with open(metrics_file, 'w', encoding='utf-8') as f:
                json.dump(metrics_data, f, indent=2, ensure_ascii=False)

        except Exception as e:
            if self.logger:
                self.logger.error(f"保存指标失败: {e}")


# 全局addon实例
addons = [CustomForwardingAddon()]
