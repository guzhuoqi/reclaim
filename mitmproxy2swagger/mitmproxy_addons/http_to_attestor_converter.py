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
from cookie_handler import CookieHandler, process_sensitive_headers_for_converter


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
            },
            # HSBC HK - accounts/domestic JSON 响应中的 ledgerBalance(HKD) 金额提取
            "hsbc_accounts_domestic_balance": {
                # 粗略匹配 JSON 文本中的 HKD 余额数字，兼容空白/换行
                "pattern": r"\"ledgerBalance\"\s*:\s*\{[^}]*\"currency\"\s*:\s*\"HKD\"[^}]*\"amount\"\s*:\s*(\d+(?:\.\d+)?)",
                "description": "HSBC HK accounts/domestic 响应中的 HKD ledgerBalance"
            }
        }

        # 敏感headers识别规则（名称部分匹配 + 精确名），需要放到secretParams中
        # - 精确名：保留最关键的两个，单独映射到 cookieStr / authorisationHeader
        # - 关键词：采用“部分匹配”（contains），覆盖更多供应商私有头
        self.sensitive_exact_headers = {'cookie', 'authorization'}
        # 明确的非敏感白名单（即使名称包含敏感关键词，也保留在 params.headers）
        self.nonsensitive_header_allowlist = {
            'token_type',           # 这是请求类型标识，不是认证信息
            'content-type',         # 内容类型
            'accept',              # 接受类型
            'user-agent',          # 用户代理
            'referer',             # 引用页面
            'origin',              # 来源
            'host'                 # 主机名
        }
        # 敏感关键词 - 只匹配真正的认证相关headers
        self.sensitive_name_keywords = [
            # 会话相关
            'session', 'sessionid', 'jsessionid',
            # 认证令牌相关
            'x-access-token', 'x-auth-token', 'x-session-token',
            'x-csrf-token', 'x-xsrf-token', 'x-api-key',
            # 银行特定认证headers
            'x-bridge-token', 'dxp-pep-token', 'aws-waf-token'
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

        # 🍪 关键修复：使用headers.fields获取独立cookie（学习001.json成功模式）
        headers_all = {}
        cookie_headers = []  # 存储独立的cookie headers
        
        # 使用headers.fields获取原始字段列表，避免cookie合并
        for k, v in request.headers.fields:
            key_str = k.decode('latin-1')
            value_str = v.decode('latin-1')
            
            if key_str.lower() == 'cookie':
                # 收集所有独立的cookie headers
                cookie_headers.append(value_str)
                print(f"🍪 HttpToAttestorConverter发现独立cookie #{len(cookie_headers)}: {value_str[:50]}...")
            else:
                # 非cookie headers正常处理
                headers_all[key_str] = value_str
        
        print(f"🍪 HttpToAttestorConverter总共找到 {len(cookie_headers)} 个独立cookie headers")
        
        # 分离基础headers和敏感headers（排除cookie）
        basic_headers, sensitive_headers = self._split_headers(headers_all)
        
        # 确保cookie不在分离后的headers中，因为我们要独立处理
        basic_headers = {k: v for k, v in basic_headers.items() if k.lower() != 'cookie'}
        sensitive_headers = {k: v for k, v in sensitive_headers.items() if k.lower() != 'cookie'}

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

        # 🔧 根据环境变量和银行URL添加TLS配置
        additional_client_options = self._build_additional_client_options(params["url"])
        if additional_client_options:
            params["additionalClientOptions"] = additional_client_options

        # 构建secretParams - 按照attestor-core的期望格式
        secret_params: Dict[str, Any] = {}
        secret_headers: Dict[str, str] = {}  # 存放其他认证headers

        # 🍪 关键修复：处理独立的cookie headers（模仿001.json成功模式）
        if cookie_headers:
            print(f"🍪 convert_flow_to_attestor_params开始处理 {len(cookie_headers)} 个独立cookie headers...")
            
            # 为每个独立cookie创建单独的header entry
            for i, cookie_value in enumerate(cookie_headers):
                cookie_key = f"cookie-{i}" if i > 0 else "cookie"  # 第一个保持原key，其他加索引
                secret_headers[cookie_key] = cookie_value.strip()
                print(f"🍪 secretParams.headers[{cookie_key}]: {cookie_value[:50]}... (长度: {len(cookie_value)})")
            
            print(f"🍪 ✅ convert_flow_to_attestor_params成功设置 {len(cookie_headers)} 个独立cookie")

        # 🔧 处理其他敏感headers
        for key, value in sensitive_headers.items():
            key_lower = key.lower()
            if key_lower == 'authorization':
                secret_params['authorisationHeader'] = value
                print(f"🔧 设置 secretParams.authorisationHeader: {value[:50]}...")
            else:
                # 🔧 修复：其他认证headers保留在secretParams的headers字段中，不再移回params
                secret_headers[key] = value
                print(f"🔧 认证header归类到secretParams: {key}")

        # 如果有认证headers（包括cookie），添加到secretParams
        if secret_headers:
            secret_params['headers'] = secret_headers
            print(f"🔧 secretParams.headers包含 {len(secret_headers)} 个认证headers: {list(secret_headers.keys())}")

        # 构建最终结果
        result = {
            "name": "http",
            "params": params,
            "secretParams": secret_params
        }

        return result

    def _build_additional_client_options(self, url: str) -> Dict[str, Any]:
        """
        🔧 根据环境变量和银行URL构建additionalClientOptions

        Args:
            url: 请求URL

        Returns:
            additionalClientOptions配置字典，如果不需要特殊配置则返回空字典
        """
        import os

        # 🏦 银行检测
        is_hsbc_bank = 'hsbc' in url.lower()  # 支持hsbc.com, hsbc.edge.sdk.awswaf.com等
        is_cmb_wing_lung_bank = 'cmbwinglungbank.com' in url.lower()

        # 🔧 环境变量配置
        hsbc_http_version = os.environ.get('HSBC_HTTP_VERSION', 'http1.1')
        cmb_http_version = os.environ.get('CMB_HTTP_VERSION', 'auto')
        default_http_version = os.environ.get('DEFAULT_HTTP_VERSION', 'auto')

        additional_options = {}

        if is_hsbc_bank:
            print(f"🏦 HSBC汇丰银行 - 环境变量配置: HSBC_HTTP_VERSION={hsbc_http_version}")
            protocols = self._parse_http_version_to_protocols(hsbc_http_version)
            if protocols:
                additional_options['applicationLayerProtocols'] = protocols
                print(f"🔧 使用协议: {protocols}")
            else:
                print(f"🔧 自动协商HTTP协议版本")
        elif is_cmb_wing_lung_bank:
            print(f"🏦 CMB永隆银行 - 环境变量配置: CMB_HTTP_VERSION={cmb_http_version}")
            protocols = self._parse_http_version_to_protocols(cmb_http_version)
            if protocols:
                additional_options['applicationLayerProtocols'] = protocols
                print(f"🔧 使用协议: {protocols}")
            else:
                print(f"🔧 自动协商HTTP协议版本")
        else:
            print(f"🌐 其他银行 - 环境变量配置: DEFAULT_HTTP_VERSION={default_http_version}")
            protocols = self._parse_http_version_to_protocols(default_http_version)
            if protocols:
                additional_options['applicationLayerProtocols'] = protocols
                print(f"🔧 使用协议: {protocols}")
            else:
                print(f"🔧 自动协商HTTP协议版本")

        return additional_options

    def _parse_http_version_to_protocols(self, version_config: str) -> List[str]:
        """
        解析HTTP版本配置字符串为协议列表

        Args:
            version_config: 环境变量值，如 'h2', 'http1.1', 'h2,http/1.1', 'auto'

        Returns:
            协议列表，如 ['h2', 'http/1.1']，如果是auto则返回None
        """
        if not version_config or version_config.lower() == 'auto':
            return None

        # 支持逗号分隔的多协议配置
        protocols = []
        for protocol in version_config.split(','):
            protocol = protocol.strip().lower()

            # 标准化协议名称
            if protocol in ['h2', 'http2', 'http/2']:
                protocols.append('h2')
            elif protocol in ['http1.1', 'http/1.1', 'http1', 'http/1']:
                protocols.append('http/1.1')
            else:
                # 保持原始值，让TLS库处理
                protocols.append(protocol)

        return protocols if protocols else None

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

        # 🔧 修复：使用_is_authentication_header方法识别所有认证相关headers
        for key, value in headers.items():
            key_lower = key.lower()
            if key_lower in {'cookie', 'authorization'} or self._is_authentication_header(key):
                sensitive_headers[key] = value
            else:
                basic_headers[key] = value

        return basic_headers, sensitive_headers

    def _is_authentication_header(self, header_name: str) -> bool:
        """
        判断header是否为真正的认证相关header

        Args:
            header_name: header名称

        Returns:
            是否为认证header
        """
        name_lower = header_name.lower()

        # 明确的认证headers
        auth_headers = {
            'dxp-pep-token',        # 银行JWT令牌
            'aws-waf-token',        # AWS WAF令牌
            'x-bridge-token',       # 桥接令牌
            'x-access-token',       # 访问令牌
            'x-auth-token',         # 认证令牌
            'x-session-token',      # 会话令牌
            'x-csrf-token',         # CSRF令牌
            'x-xsrf-token',         # XSRF令牌
            'x-api-key',           # API密钥
            # 🔧 修复：增加HSBC银行特有认证headers（基于001.json分析）
            'x-hsbc-jsc-data',     # HSBC加密认证数据（关键）
            'x-hsbc-client-id',    # HSBC客户端ID
            'token_type',          # 令牌类型（SESSION_TOKEN等）
        }

        # 会话相关headers
        session_headers = {
            'jsessionid',
            'sessionid',
        }

        # 精确匹配
        if name_lower in auth_headers or name_lower in session_headers:
            return True

        # 包含session关键词的headers
        if 'session' in name_lower and name_lower not in {'session-idle-hint', 'session-expiry-hint'}:
            return True

        return False

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
        custom_patterns: Optional[Dict[str, str]] = None,
        normalize_headers: bool = True,
        explicit_host: Optional[str] = None
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

        # 确保 Host 头与 URL 主机一致（或使用显示指定的 Host）
        try:
            parsed = urlparse(url)
            desired_host = explicit_host or parsed.netloc.split(':')[0]
            # 仅当未设置 Host 时注入；如需强制覆盖，可通过 explicit_host 设置
            if not any(k.lower() == 'host' for k in params["headers"].keys()):
                params["headers"]["Host"] = desired_host
        except Exception:
            pass

        # 强制满足 attestor-http provider 的要求（可禁用）
        if normalize_headers:
            self._enforce_attestor_header_requirements(params["headers"], params["body"])

        # 添加响应匹配规则
        response_matches, response_redactions = self._build_response_rules(
            response_patterns, custom_patterns
        )
        if response_matches:
            params["responseMatches"] = response_matches
        if response_redactions:
            params["responseRedactions"] = response_redactions

        # 🔧 根据环境变量和银行URL添加TLS配置
        additional_client_options = self._build_additional_client_options(params["url"])
        if additional_client_options:
            params["additionalClientOptions"] = additional_client_options

        # 构建secretParams - 按照attestor-core的期望格式
        secret_params: Dict[str, Any] = {}
        secret_headers: Dict[str, str] = {}  # 存放其他认证headers

        # 🔧 修复：正确处理所有敏感headers
        for key, value in sensitive_headers.items():
            key_lower = key.lower()
            if key_lower == 'cookie':
                # 🍪 使用统一的cookie处理方法
                CookieHandler.process_cookie_for_secret_headers(key, value, secret_headers)
            elif key_lower == 'authorization':
                secret_params['authorisationHeader'] = value
            else:
                # 🔧 修复：其他认证headers保留在secretParams的headers字段中，不再移回params
                secret_headers[key] = value
                print(f"🔧 认证header归类到secretParams: {key}")

        # 如果有其他认证headers，添加到secretParams
        if secret_headers:
            secret_params['headers'] = secret_headers
            print(f"🔧 secretParams.headers包含 {len(secret_headers)} 个认证headers: {list(secret_headers.keys())}")

        # 构建最终结果
        result = {
            "name": "http",
            "params": params,
            "secretParams": secret_params
        }

        return result

    def convert_request_params_json_to_attestor_params(
        self,
        request_params: Dict[str, Any],
        geo_location: str = "HK",
        response_patterns: Optional[List[str]] = None,
        custom_patterns: Optional[Dict[str, str]] = None,
        normalize_headers: bool = True,
        explicit_host: Optional[str] = None,
    ) -> Dict[str, Any]:
        """从类似 hsbc_accounts_domestic_request_params.json 的结构转换为 attestor 参数"""
        url = request_params.get("full_url") or request_params.get("url")
        method = request_params.get("method", "GET")
        headers = request_params.get("headers", {})
        body = ""
        return self.convert_raw_request_to_attestor_params(
            url=url,
            method=method,
            headers=headers,
            body=body,
            geo_location=geo_location,
            response_patterns=response_patterns,
            custom_patterns=custom_patterns,
            normalize_headers=normalize_headers,
            explicit_host=explicit_host,
        )

    def _enforce_attestor_header_requirements(self, headers: Dict[str, str], body: str, host: str = None) -> None:
        """
        🚫 临时禁用自动添加headers，用于403错误排查
        规范化并强制设置满足 attestor-core http provider 的头部要求：
        - 根据银行类型设置不同的headers策略
        - 确保HTTP协议必需的headers存在
        - 消除大小写重复键（优先使用标准首字母大写）

        Args:
            headers: 请求头字典
            body: 请求体
            host: 目标主机名（从flow中获取）
        """
        if not headers:
            return

        # 🔧 参考pretest实现，只添加HTTP协议必需的标准headers
        print(f"🔍 _enforce_attestor_header_requirements 被调用（仅添加必需标准headers）")
        print(f"🔍 处理前headers: {list(headers.keys())}")
        
        # 🏠 添加Host header - HTTP/1.1协议必需
        if 'Host' not in headers and 'host' not in headers:
            if host:
                headers['Host'] = host
                print(f"🏠 添加必需的Host头: {host}")
            else:
                print(f"⚠️ 无法添加Host头：host参数为空")
        
        # 🔗 添加Connection header - 确保连接行为一致
        connection_keys = [k for k in headers.keys() if k.lower() == 'connection']
        if not connection_keys:
            headers['Connection'] = 'close'
            print(f"🔗 添加Connection头: close")
        else:
            # 规范化为标准大小写
            for k in connection_keys:
                if k != 'Connection':
                    value = headers.pop(k)
                    headers['Connection'] = value
                    print(f"🔗 规范化Connection头: {value}")
        
        # 📏 添加Content-Length header - 指定body长度
        body_str = body or ""
        body_len = len(body_str.encode('utf-8'))
        cl_keys = [k for k in headers.keys() if k.lower() == 'content-length']
        
        # 移除所有现有的content-length变体
        for k in cl_keys:
            headers.pop(k, None)
        
        # 添加标准的Content-Length
        headers['Content-Length'] = str(body_len)
        print(f"📏 添加Content-Length头: {body_len}")
        
        print(f"🔍 处理后headers: {list(headers.keys())}")
        print(f"✅ 标准headers添加完成")

        # 以下代码暂时禁用，用于403错误排查
        # print(f"🔍 _enforce_attestor_header_requirements 被调用")
        # print(f"🔍 当前headers: {list(headers.keys())}")

        # # 🏦 检测银行类型
        # bank_type = self._detect_bank_type(headers)

        # # 🔧 处理 Host 头部 - HTTP协议必需
        # if 'Host' not in headers and 'host' not in headers:
        #     if host:
        #         headers['Host'] = host
        #         print(f"🏠 添加必需的Host头: {host}")
        #     else:
        #         print(f"⚠️ 警告: 无法获取Host信息，跳过添加Host头")

        # # 🔧 处理 Connection 头部
        # # 删除所有不同大小写的 connection 头
        # keys_to_delete = []
        # for k in list(headers.keys()):
        #     if k.lower() == 'connection' and k != 'Connection':
        #         keys_to_delete.append(k)
        # for k in keys_to_delete:
        #     headers.pop(k, None)

        # # 根据银行类型设置 Connection
        # if 'Connection' not in headers:
        #     if bank_type == 'cmb_wing_lung':
        #         headers['Connection'] = 'keep-alive'
        #         print(f"🏦 招商永隆银行，设置 Connection: keep-alive")
        #     else:
        #         headers['Connection'] = 'close'
        #         print(f"🌐 其他银行，设置 Connection: close")

        # 🚫 以下代码暂时禁用，用于403错误排查
        # # 移除 Transfer-Encoding，避免与 Content-Length 冲突
        # for k in list(headers.keys()):
        #     if k.lower() == 'transfer-encoding':
        #         headers.pop(k, None)

        # # 同步 Content-Length 策略
        # body_str = body or ""
        # body_len = len(body_str.encode('utf-8'))
        # # 规范化 Content-Length 大小写，并根据 body 设置
        # cl_keys = [k for k in list(headers.keys()) if k.lower() == 'content-length']
        # for k in cl_keys:
        #     if k != 'Content-Length':
        #         headers.pop(k, None)
        # # 为空体，强制为 0；非空体，如存在不一致则更新
        # if body_len == 0:
        #     headers['Content-Length'] = '0'
        # else:
        #     existing = headers.get('Content-Length')
        #     if existing != str(body_len):
        #         headers['Content-Length'] = str(body_len)

        # # 🔧 处理 Accept-Encoding 头部
        # ae_keys = [k for k in list(headers.keys()) if k.lower() == 'accept-encoding']

        # # 规范化大小写，删除重复的 accept-encoding 头
        # original_value = None
        # for k in ae_keys:
        #     if original_value is None:
        #         original_value = headers[k]
        #     if k != 'Accept-Encoding':
        #         headers.pop(k, None)

        # # 根据银行类型设置 Accept-Encoding
        # if 'Accept-Encoding' not in headers:
        #     if bank_type == 'cmb_wing_lung':
        #         headers['Accept-Encoding'] = 'gzip, deflate, br, zstd'
        #         print(f"🏦 招商永隆银行，设置 Accept-Encoding: gzip, deflate, br, zstd")
        #     elif bank_type == 'hsbc':
        #         # HSBC 保留原始值，如果没有原始值则不设置
        #         if original_value:
        #             headers['Accept-Encoding'] = original_value
        #             print(f"🏦 HSBC 银行，保留原始 Accept-Encoding: {original_value}")
        #         else:
        #             print(f"🏦 HSBC 银行，没有原始 Accept-Encoding，不设置默认值")
        #     else:
        #         headers['Accept-Encoding'] = 'identity'
        #         print(f"🌐 其他银行，设置 Accept-Encoding: identity")
        # else:
        #     # 如果已存在，根据银行类型决定是否保留
        #     if bank_type == 'hsbc':
        #         print(f"🏦 HSBC 银行，保留现有 Accept-Encoding: {headers['Accept-Encoding']}")
        #     else:
        #         print(f"🌐 其他银行，保留现有 Accept-Encoding: {headers['Accept-Encoding']}")

    def _detect_bank_type(self, headers: Dict[str, str]) -> str:
        """
        检测银行类型，用于应用不同的headers策略

        Returns:
            'hsbc': 汇丰银行
            'cmb_wing_lung': 招商永隆银行
            'default': 其他银行
        """
        # 检查 Host 头
        host_value = None
        for key, value in headers.items():
            if key.lower() == 'host':
                host_value = value.lower()
                break

        # 通过 Host 头判断
        if host_value:
            if 'hsbc' in host_value:
                print(f"🏦 检测到 HSBC 银行 (Host: {host_value})")
                return 'hsbc'
            elif 'cmb' in host_value or 'winglungbank' in host_value:
                print(f"🏦 检测到招商永隆银行 (Host: {host_value})")
                return 'cmb_wing_lung'

        # 如果没有Host头，尝试从其他headers中推断
        if not host_value:
            for key, value in headers.items():
                if 'hsbc' in key.lower() or 'hsbc' in str(value).lower():
                    print(f"🏦 通过header检测到 HSBC 银行 ({key}: {str(value)[:50]}...)")
                    return 'hsbc'
                elif 'cmb' in key.lower() or 'cmb' in str(value).lower():
                    print(f"🏦 通过header检测到招商永隆银行 ({key}: {str(value)[:50]}...)")
                    return 'cmb_wing_lung'

        print(f"🌐 检测到其他银行 (Host: {host_value})")
        return 'default'

    def _should_preserve_original_accept_encoding(self, headers: Dict[str, str]) -> bool:
        """
        判断是否应该保留原始的 Accept-Encoding 头部

        Args:
            headers: 请求头字典

        Returns:
            True: 保留原始 Accept-Encoding
            False: 强制设置为 identity
        """
        bank_type = self._detect_bank_type(headers)

        # HSBC 保留原始 Accept-Encoding
        if bank_type == 'hsbc':
            print(f"🏦 HSBC 银行，保留原始 Accept-Encoding")
            return True

        # 其他银行强制设置为 identity
        print(f"🌐 非 HSBC 银行，强制设置 Accept-Encoding: identity")
        return False

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
        # 🔧 修复JSON转义问题：确保不会对cookie中的JSON进行过度转义
        params_json = json.dumps(attestor_params.get("params", {}), ensure_ascii=False, separators=(',', ':'))
        secret_params_json = json.dumps(attestor_params.get("secretParams", {}), ensure_ascii=False, separators=(',', ':'))

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
    import argparse, sys, json
    parser = argparse.ArgumentParser(description="HTTP→Attestor 参数转换器")
    parser.add_argument("--from-request-json", dest="from_request_json", default=None, help="从请求参数JSON文件读取（如 hsbc_accounts_domestic_request_params.json）")
    parser.add_argument("--geo", dest="geo", default="HK", help="geoLocation，默认 HK")
    parser.add_argument("--no-normalize", dest="no_normalize", action="store_true", help="不强制规范化为 attestor http provider 头部要求")
    parser.add_argument("--patterns", dest="patterns", default="hsbc_accounts_domestic_balance", help="逗号分隔的内置响应匹配模式名称")
    parser.add_argument("--print-command", dest="print_command", action="store_true", help="打印可执行的 attestor 命令行")
    parser.add_argument("--host", dest="host", default=None, help="显式设置 Host 头，默认与 URL 主机一致")
    args = parser.parse_args()

    conv = HttpToAttestorConverter()
    normalize = not args.no_normalize
    patterns = [p.strip() for p in (args.patterns or '').split(',') if p.strip()]

    if args.from_request_json:
        with open(args.from_request_json, 'r', encoding='utf-8') as f:
            req = json.load(f)
        attestor_params = conv.convert_request_params_json_to_attestor_params(
            request_params=req,
            geo_location=args.geo,
            response_patterns=patterns or None,
            normalize_headers=normalize,
            explicit_host=args.host,
        )
        print(json.dumps(attestor_params, indent=2, ensure_ascii=False))
        if args.print_command:
            cmd = conv.generate_command_line(attestor_params)
            print("\nCommand:")
            print(cmd)
        sys.exit(0)

    # fallback to demo
    demo_usage()
