#!/usr/bin/env python3
"""
HTTP请求到Attestor参数转换器
HTTP Request to Attestor Parameters Converter

将mitmproxy抓包得到的HTTP请求转换为attestor node的调用参数格式
"""

import json
import re
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs
from mitmproxy import http


class HttpToAttestorConverter:
    """HTTP请求到Attestor参数转换器"""

    def __init__(self):
        # 预定义的响应匹配规则模板
        self.response_patterns = {
            "bank_balance_hkd": {
                "pattern": r"HKD[^\\d]*(\\d[\\d,]*\\.\\d{2})",
                "description": "港币余额匹配"
            },
            "bank_balance_usd": {
                "pattern": r"USD[^\\d]*(\\d[\\d,]*\\.\\d{2})",
                "description": "美元余额匹配"
            },
            "bank_balance_cny": {
                "pattern": r"CNY[^\\d]*(\\d[\\d,]*\\.\\d{2})",
                "description": "人民币余额匹配"
            },
            "account_number": {
                "pattern": r"账户[^\\d]*(\\d{10,20})",
                "description": "账户号码匹配"
            },
            "transaction_amount": {
                "pattern": r"金额[^\\d]*(\\d[\\d,]*\\.\\d{2})",
                "description": "交易金额匹配"
            }
        }

        # 敏感headers识别规则（名称部分匹配 + 精确名），需要放到secretParams中
        # - 精确名：保留最关键的两个，单独映射到 cookieStr / authorisationHeader
        # - 关键词：采用“部分匹配”（contains），覆盖更多供应商私有头
        self.sensitive_exact_headers = {'cookie', 'authorization'}
        self.sensitive_name_keywords = [
            # 用户指明的关键变体
            'x-bridge-token', 'x-access-token', 'x-session-id', 'x-csrf-token', 'x-xsrf-token', 'x-authorization', 'x-api-key',
            # 通用关键词（部分匹配）
            'token', 'auth', 'session', 'csrf', 'xsrf', 'api-key', 'bridge', 'credential'
        ]

        # 基础headers，保留在params中
        self.basic_headers = {
            'host', 'connection', 'content-type', 'content-length',
            'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
            'user-agent', 'accept', 'accept-encoding', 'accept-language',
            'origin', 'referer', 'sec-fetch-site', 'sec-fetch-mode',
            'sec-fetch-dest', 'x-requested-with'
        }

    def convert_flow_to_attestor_params(
        self,
        flow: http.HTTPFlow,
        geo_location: str = "HK",
        response_patterns: Optional[List[str]] = None,
        custom_patterns: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        将mitmproxy的HTTPFlow转换为attestor参数格式

        Args:
            flow: mitmproxy的HTTPFlow对象
            geo_location: 地理位置，默认"HK"
            response_patterns: 要使用的响应匹配模式名称列表
            custom_patterns: 自定义的响应匹配模式

        Returns:
            attestor调用参数字典
        """
        request = flow.request

        # 分离基础headers和敏感headers
        headers_all = dict(request.headers)
        basic_headers, sensitive_headers = self._split_headers(headers_all)

        # 构建基础参数
        params = {
            "url": request.pretty_url,
            "method": request.method,
            "geoLocation": geo_location,
            "body": request.content.decode('utf-8', errors='ignore') if request.content else "",
            "headers": basic_headers
        }

        # 强制满足 attestor-http provider 的要求：Connection 必须为 close
        self._enforce_attestor_header_requirements(params["headers"], params["body"])

        # 添加响应匹配规则
        response_matches, response_redactions = self._build_response_rules(
            response_patterns, custom_patterns
        )
        if response_matches:
            params["responseMatches"] = response_matches
        if response_redactions:
            params["responseRedactions"] = response_redactions

        # 构建secretParams - 按照attestor-core的期望格式
        secret_params: Dict[str, Any] = {}

        # 特殊处理Cookie和Authorization；其余敏感头统一放到 secretParams.headers
        secret_headers: Dict[str, str] = {}
        for key, value in sensitive_headers.items():
            key_lower = key.lower()
            if key_lower == 'cookie':
                secret_params['cookieStr'] = value
            elif key_lower == 'authorization':
                secret_params['authorisationHeader'] = value
            else:
                secret_headers[key] = value

        if secret_headers:
            secret_params['headers'] = secret_headers

        # 构建最终结果
        result = {
            "name": "http",
            "params": params,
            "secretParams": secret_params
        }

        return result

    def _split_headers(self, headers: Dict[str, str]) -> Tuple[Dict[str, str], Dict[str, str]]:
        """
        分离基础headers和敏感headers

        Args:
            headers: 原始headers字典

        Returns:
            (basic_headers, sensitive_headers) 元组
        """
        basic_headers: Dict[str, str] = {}
        sensitive_headers: Dict[str, str] = {}

        def _is_sensitive_header(name: str, value: str) -> bool:
            nl = (name or '').lower()
            # 精确命中
            if nl in self.sensitive_exact_headers:
                return True
            # 名称关键词部分匹配
            for kw in self.sensitive_name_keywords:
                if kw in nl:
                    return True
            return False

        for key, value in headers.items():
            if _is_sensitive_header(key, value):
                sensitive_headers[key] = value
            else:
                basic_headers[key] = value

        return basic_headers, sensitive_headers

    def _build_response_rules(
        self,
        pattern_names: Optional[List[str]] = None,
        custom_patterns: Optional[Dict[str, str]] = None
    ) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
        """
        构建响应匹配和编辑规则

        Args:
            pattern_names: 要使用的预定义模式名称列表
            custom_patterns: 自定义模式字典 {name: pattern}

        Returns:
            (response_matches, response_redactions) 元组
        """
        response_matches = []
        response_redactions = []

        # 添加预定义模式
        if pattern_names:
            for pattern_name in pattern_names:
                if pattern_name in self.response_patterns:
                    pattern_info = self.response_patterns[pattern_name]
                    match_rule = {
                        "type": "regex",
                        "value": pattern_info["pattern"]
                    }
                    response_matches.append(match_rule)

                    # 同时添加到redactions中
                    redaction_rule = {
                        "regex": pattern_info["pattern"]
                    }
                    response_redactions.append(redaction_rule)

        # 添加自定义模式
        if custom_patterns:
            for name, pattern in custom_patterns.items():
                match_rule = {
                    "type": "regex",
                    "value": pattern
                }
                response_matches.append(match_rule)

                redaction_rule = {
                    "regex": pattern
                }
                response_redactions.append(redaction_rule)

        return response_matches, response_redactions

    def convert_raw_request_to_attestor_params(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        geo_location: str = "HK",
        response_patterns: Optional[List[str]] = None,
        custom_patterns: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        直接从原始请求数据转换为attestor参数格式

        Args:
            url: 请求URL
            method: HTTP方法
            headers: 请求headers
            body: 请求体
            geo_location: 地理位置
            response_patterns: 响应匹配模式名称列表
            custom_patterns: 自定义响应匹配模式

        Returns:
            attestor调用参数字典
        """
        headers = headers or {}

        # 分离基础headers和敏感headers
        basic_headers, sensitive_headers = self._split_headers(headers)

        # 构建基础参数
        params = {
            "url": url,
            "method": method.upper(),
            "geoLocation": geo_location,
            "body": body,
            "headers": basic_headers
        }

        # 强制满足 attestor-http provider 的要求：Connection 必须为 close
        self._enforce_attestor_header_requirements(params["headers"], params["body"])

        # 添加响应匹配规则
        response_matches, response_redactions = self._build_response_rules(
            response_patterns, custom_patterns
        )
        if response_matches:
            params["responseMatches"] = response_matches
        if response_redactions:
            params["responseRedactions"] = response_redactions

        # 构建secretParams - 按照attestor-core的期望格式
        secret_params: Dict[str, Any] = {}

        secret_headers: Dict[str, str] = {}
        for key, value in sensitive_headers.items():
            key_lower = key.lower()
            if key_lower == 'cookie':
                secret_params['cookieStr'] = value
            elif key_lower == 'authorization':
                secret_params['authorisationHeader'] = value
            else:
                secret_headers[key] = value

        if secret_headers:
            secret_params['headers'] = secret_headers

        # 构建最终结果
        result = {
            "name": "http",
            "params": params,
            "secretParams": secret_params
        }

        return result

    def _enforce_attestor_header_requirements(self, headers: Dict[str, str], body: str) -> None:
        """
        规范化并强制设置满足 attestor-core http provider 的头部要求：
        - Connection 必须是 close
        - 消除大小写重复键（优先使用标准首字母大写）
        - 当 body 为空时，移除不必要的 Content-Length 或设为 0（可选，保持稳妥）
        """
        if not headers:
            return

        # 统一 Connection
        # 如果存在任意形式的 connection 头，最终强制为 'close'
        value_connection = 'close'
        keys_to_delete = []
        has_standard_key = False
        for k in list(headers.keys()):
            if k.lower() == 'connection':
                if k != 'Connection':
                    keys_to_delete.append(k)
                else:
                    has_standard_key = True
        for k in keys_to_delete:
            # 删除非标准大小写键，避免重复
            headers.pop(k, None)
        headers['Connection'] = value_connection

        # 移除 Transfer-Encoding，避免与 Content-Length 冲突
        for k in list(headers.keys()):
            if k.lower() == 'transfer-encoding':
                headers.pop(k, None)

        # 同步 Content-Length 策略
        body_str = body or ""
        body_len = len(body_str.encode('utf-8'))
        # 规范化 Content-Length 大小写，并根据 body 设置
        cl_keys = [k for k in list(headers.keys()) if k.lower() == 'content-length']
        for k in cl_keys:
            if k != 'Content-Length':
                headers.pop(k, None)
        # 为空体，强制为 0；非空体，如存在不一致则更新
        if body_len == 0:
            headers['Content-Length'] = '0'
        else:
            existing = headers.get('Content-Length')
            if existing != str(body_len):
                headers['Content-Length'] = str(body_len)

        # 强制请求服务端返回未压缩内容，便于 attestor-core 做字符串匹配
        ae_keys = [k for k in list(headers.keys()) if k.lower() == 'accept-encoding']
        for k in ae_keys:
            if k != 'Accept-Encoding':
                headers.pop(k, None)
        headers['Accept-Encoding'] = 'identity'

    def add_response_pattern(self, name: str, pattern: str, description: str = ""):
        """
        添加新的响应匹配模式

        Args:
            name: 模式名称
            pattern: 正则表达式模式
            description: 模式描述
        """
        self.response_patterns[name] = {
            "pattern": pattern,
            "description": description
        }

    def get_available_patterns(self) -> Dict[str, str]:
        """
        获取所有可用的响应匹配模式

        Returns:
            {pattern_name: description} 字典
        """
        return {
            name: info["description"]
            for name, info in self.response_patterns.items()
        }

    def format_for_command_line(self, attestor_params: Dict[str, Any]) -> Tuple[str, str, str]:
        """
        将attestor参数格式化为命令行参数

        Args:
            attestor_params: attestor参数字典

        Returns:
            (name, params_json, secret_params_json) 元组
        """
        name = attestor_params.get("name", "http")
        params_json = json.dumps(attestor_params.get("params", {}), ensure_ascii=False)
        secret_params_json = json.dumps(attestor_params.get("secretParams", {}), ensure_ascii=False)

        return name, params_json, secret_params_json

    def generate_command_line(
        self,
        attestor_params: Dict[str, Any],
        private_key: str = "0x0123788edad59d7c013cdc85e4372f350f828e2cec62d9a2de4560e69aec7f89",
        attestor: str = "local"
    ) -> str:
        """
        生成完整的命令行调用字符串

        Args:
            attestor_params: attestor参数字典
            private_key: 私钥
            attestor: attestor类型

        Returns:
            完整的命令行字符串
        """
        name, params_json, secret_params_json = self.format_for_command_line(attestor_params)

        command = (
            f'PRIVATE_KEY={private_key} npm run create:claim -- '
            f'--name "{name}" '
            f'--params \'{params_json}\' '
            f'--secretParams \'{secret_params_json}\' '
            f'--attestor {attestor}'
        )

        return command


def demo_usage():
    """演示用法"""
    converter = HttpToAttestorConverter()

    # 示例1：使用预定义模式
    print("=== 示例1：银行余额查询（使用预定义模式） ===")

    attestor_params = converter.convert_raw_request_to_attestor_params(
        url="https://www.cmbwinglungbank.com/ibanking/McpCSReqServlet?dse_operationName=NbBkgActdetCoaProc2022",
        method="POST",
        headers={
            "Host": "www.cmbwinglungbank.com",
            "Connection": "close",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Cookie": "JSESSIONID=0000VLZZZd-gvZlRZzjVUeBIcuv:1a1068cds; dse_sessionId=BGGLECBCDJHDDUINAXGRELAVAPJJEFJSFXAIBGBT",
            "X-Requested-With": "XMLHttpRequest"
        },
        body="",
        response_patterns=["bank_balance_hkd"]
    )

    print("转换结果:")
    print(json.dumps(attestor_params, indent=2, ensure_ascii=False))

    print("\n生成的命令行:")
    command = converter.generate_command_line(attestor_params)
    print(command)

    # 示例2：使用自定义模式
    print("\n=== 示例2：自定义响应匹配模式 ===")

    custom_patterns = {
        "custom_balance": r"余额[^\\d]*(\\d[\\d,]*\\.\\d{2})",
        "account_info": r"账户信息.*?(\\w+)"
    }

    attestor_params2 = converter.convert_raw_request_to_attestor_params(
        url="https://api.example.com/account/balance",
        method="GET",
        headers={
            "Authorization": "Bearer token123",
            "Content-Type": "application/json"
        },
        custom_patterns=custom_patterns
    )

    print("转换结果:")
    print(json.dumps(attestor_params2, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    demo_usage()
