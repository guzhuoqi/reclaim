#!/usr/bin/env python3
"""
Cookie处理工具类
统一处理cookie在attestor参数中的转换逻辑，避免多处重复代码
"""

from typing import Dict, Any, Optional
import base64


class CookieHandler:
    """统一的Cookie处理器"""

    @staticmethod
    def process_cookie_for_secret_params(
        key: str,
        value: str,
        secret_params: Dict[str, Any],
        use_legacy_format: bool = False
    ) -> None:
        """
        将cookie添加到secretParams中
        
        Args:
            key: cookie header的key (通常是'Cookie')
            value: cookie的值（可能是mitmproxy合并后的多cookie字符串）
            secret_params: 要填充的secretParams字典
            use_legacy_format: 是否使用旧的cookieStr格式(Base64编码)
        """
        if use_legacy_format:
            # 兼容旧格式：Base64编码合并cookie
            encoded_cookie = base64.b64encode(value.encode('utf-8')).decode('ascii')
            secret_params['cookieStr'] = encoded_cookie
            print(f"🍪 Legacy格式 - Cookie Base64编码: {len(value)} -> {len(encoded_cookie)} 字符")
            print(f"🍪 Legacy格式 - Base64编码后前100字符: {encoded_cookie[:100]}...")
        else:
            # 🔧 修复：检测并分拆mitmproxy合并的cookie字符串
            # mitmproxy使用`, `来合并多个同名headers
            if ', ' in value and '=' in value:
                # 这是合并后的cookie字符串，需要拆分为独立的cookie values
                cookie_values = value.split(', ')
                print(f"🍪 检测到合并cookie，拆分为 {len(cookie_values)} 个独立cookie")
                
                if 'headers' not in secret_params:
                    secret_params['headers'] = {}
                
                # 为每个cookie创建独立的header
                for i, cookie_value in enumerate(cookie_values):
                    cookie_key = f"cookie-{i}" if i > 0 else "cookie"  # 第一个保持原key，其他加索引
                    secret_params['headers'][cookie_key] = cookie_value.strip()
                    print(f"🍪 独立cookie #{i+1}: {cookie_key} = {cookie_value[:50]}... (长度: {len(cookie_value)})")
                    
                print(f"🍪 ✅ 成功拆分为 {len(cookie_values)} 个独立cookie headers（学习001.json成功模式）")
            else:
                # 单个cookie，直接保存
                if 'headers' not in secret_params:
                    secret_params['headers'] = {}
                secret_params['headers'][key] = value
                print(f"🍪 保留单个cookie header: {key}: {value[:50]}...")
                print(f"🍪 Cookie长度: {len(value)} 字符")

    @staticmethod
    def process_cookie_for_secret_headers(
        key: str,
        value: str,
        secret_headers: Dict[str, str]
    ) -> None:
        """
        将cookie添加到secret_headers中 (用于http_to_attestor_converter)
        
        Args:
            key: cookie header的key
            value: cookie的值（可能是mitmproxy合并后的多cookie字符串）
            secret_headers: 要填充的secret_headers字典
        """
        # 🔧 修复：检测并分拆mitmproxy合并的cookie字符串
        if ', ' in value and '=' in value:
            # 这是合并后的cookie字符串，需要拆分为独立的cookie values
            cookie_values = value.split(', ')
            print(f"🍪 检测到合并cookie，拆分为 {len(cookie_values)} 个独立cookie")
            
            # 为每个cookie创建独立的header
            for i, cookie_value in enumerate(cookie_values):
                cookie_key = f"cookie-{i}" if i > 0 else "cookie"  # 第一个保持原key，其他加索引
                secret_headers[cookie_key] = cookie_value.strip()
                print(f"🍪 独立cookie #{i+1}: {cookie_key} = {cookie_value[:50]}... (长度: {len(cookie_value)})")
                
            print(f"🍪 ✅ 成功拆分为 {len(cookie_values)} 个独立cookie headers（学习001.json成功模式）")
        else:
            # 单个cookie，直接保存
            secret_headers[key] = value
            print(f"🍪 保留单个cookie header: {key}: {value[:50]}...")

    @staticmethod
    def has_cookies_in_secret_params(secret_params: Dict[str, Any]) -> bool:
        """
        检查secretParams中是否包含cookie信息
        
        Args:
            secret_params: 要检查的secretParams字典
            
        Returns:
            bool: 是否包含cookie信息
        """
        # 检查旧格式cookieStr
        if secret_params.get('cookieStr'):
            return True
            
        # 检查新格式独立cookie headers
        headers = secret_params.get('headers', {})
        return any(k.lower() == 'cookie' for k in headers.keys())

    @staticmethod
    def get_cookie_debug_info(secret_params: Dict[str, Any]) -> str:
        """
        获取cookie的调试信息
        
        Args:
            secret_params: secretParams字典
            
        Returns:
            str: 调试信息字符串
        """
        info_parts = []
        
        # 检查cookieStr
        if secret_params.get('cookieStr'):
            cookie_str = secret_params['cookieStr']
            info_parts.append(f"cookieStr(Base64): {len(cookie_str)} chars")
            
        # 检查独立cookie headers
        headers = secret_params.get('headers', {})
        cookie_headers = [k for k in headers.keys() if k.lower() == 'cookie']
        if cookie_headers:
            info_parts.append(f"独立cookie headers: {len(cookie_headers)}个")
            for cookie_key in cookie_headers:
                cookie_value = headers[cookie_key]
                info_parts.append(f"  - {cookie_key}: {len(cookie_value)} chars")
        
        return "; ".join(info_parts) if info_parts else "无cookie信息"

    @staticmethod
    def migrate_legacy_to_independent(secret_params: Dict[str, Any]) -> bool:
        """
        将旧的cookieStr格式迁移到独立headers格式
        
        Args:
            secret_params: 要迁移的secretParams字典
            
        Returns:
            bool: 是否进行了迁移
        """
        cookie_str = secret_params.get('cookieStr')
        if not cookie_str:
            return False
            
        try:
            # Base64解码
            decoded_cookie = base64.b64decode(cookie_str).decode('utf-8')
            
            # 移除旧格式
            secret_params.pop('cookieStr')
            
            # 添加到新格式
            if 'headers' not in secret_params:
                secret_params['headers'] = {}
            secret_params['headers']['Cookie'] = decoded_cookie
            
            print(f"🔄 Cookie格式迁移: cookieStr -> 独立headers")
            print(f"🔄 解码后cookie长度: {len(decoded_cookie)} 字符")
            return True
            
        except Exception as e:
            print(f"⚠️ Cookie格式迁移失败: {e}")
            return False


# 便利函数，用于快速处理常见场景
def process_sensitive_headers_cookies(
    sensitive_headers: Dict[str, str],
    secret_params: Dict[str, Any],
    use_legacy_format: bool = False
) -> None:
    """
    从sensitive_headers中提取所有cookie并添加到secret_params
    
    Args:
        sensitive_headers: 包含敏感headers的字典
        secret_params: 要填充的secretParams字典
        use_legacy_format: 是否使用旧的cookieStr格式
    """
    for key, value in sensitive_headers.items():
        if key.lower() == 'cookie':
            CookieHandler.process_cookie_for_secret_params(
                key, value, secret_params, use_legacy_format
            )


def process_sensitive_headers_for_converter(
    sensitive_headers: Dict[str, str],
    secret_headers: Dict[str, str]
) -> None:
    """
    从sensitive_headers中提取所有cookie并添加到secret_headers (用于converter)
    
    Args:
        sensitive_headers: 包含敏感headers的字典
        secret_headers: 要填充的secret_headers字典
    """
    for key, value in sensitive_headers.items():
        if key.lower() == 'cookie':
            CookieHandler.process_cookie_for_secret_headers(key, value, secret_headers)
