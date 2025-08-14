#!/usr/bin/env python3
"""
本地自测：验证 http_to_attestor_converter.py 能将 flows 中的 HSBC 请求转换为 attestor 入参
不会调用 attestor，只打印转换后的 params/secretParams 关键字段，确保可复用。
"""

import json
from pathlib import Path
from urllib.parse import urlparse

from mitmproxy import io, http
from mitmproxy.exceptions import FlowReadException

from http_to_attestor_converter import HttpToAttestorConverter


REPO = Path('/Users/gu/IdeaProjects/reclaim')
FLOWS_CANDIDATES = [
    REPO / 'mitmproxy2swagger' / 'flows (7)',
    REPO / 'mitmproxy2swagger' / 'flows (6)'
]

TARGET_HOST = 'www.hsbc.com.hk'
TARGET_PREFIX = '/api/mmf-cust-accounts--hk-hbap-banking-prod-proxy/v1/accounts/domestic'


def load_flows(file_path: Path):
    flows = []
    try:
        with open(file_path, 'rb') as f:
            reader = io.FlowReader(f)
            for flow in reader.stream():
                if isinstance(flow, http.HTTPFlow):
                    flows.append(flow)
    except (FileNotFoundError, FlowReadException):
        return []
    return flows


def find_target_flow():
    for p in FLOWS_CANDIDATES:
        flows = load_flows(p)
        for fl in flows:
            try:
                req = fl.request
                if not req or not req.pretty_url:
                    continue
                u = urlparse(req.pretty_url)
                if u.netloc == TARGET_HOST and u.path.startswith(TARGET_PREFIX):
                    return fl, str(p)
            except Exception:
                continue
    return None, None


def main():
    flow, src = find_target_flow()
    if flow is None:
        print('❌ 未在 flows (7)/(6) 中找到目标 HSBC 请求')
        return

    print(f'✅ 命中 flow 来源: {src}')
    conv = HttpToAttestorConverter()

    # 从 flow 直接转换（保持原貌，不做规范化），并显式设置 Host
    attestor_params = conv.convert_flow_to_attestor_params(
        flow,
        geo_location='HK',
        response_patterns=['hsbc_accounts_domestic_balance'],
        custom_patterns=None
    )

    # 手动应用与 convert_raw 一致的 host 注入与规范化控制
    # 为对齐测试目的，这里显式覆盖 host 并不规范化
    attestor_params['params'].setdefault('headers', {})
    attestor_params['params']['headers'].setdefault('Host', TARGET_HOST)

    # 输出关键信息，便于核对映射是否可复用
    params = attestor_params.get('params', {})
    secret = attestor_params.get('secretParams', {})

    summary = {
        'url': params.get('url'),
        'method': params.get('method'),
        'has_token_type_header': 'token_type' in {k.lower(): v for k, v in params.get('headers', {}).items()},
        'has_x_hsbc_jsc_data': 'x-hsbc-jsc-data' in {k.lower(): v for k, v in params.get('headers', {}).items()},
        'has_cookieStr': bool(secret.get('cookieStr')),
        'headers_sample': {k: params.get('headers', {}).get(k) for k in ['Host', 'referer', 'x-hsbc-chnl-countrycode', 'x-hsbc-channel-id', 'x-hsbc-jsc-data'] if k in params.get('headers', {})},
        'cookie_prefix': (secret.get('cookieStr') or '')[:120]
    }

    print('\n=== 转换摘要 ===')
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    print('\n=== 完整 attestor 入参（截断预览）===')
    print(json.dumps(attestor_params, ensure_ascii=False, indent=2)[:2000])


if __name__ == '__main__':
    main()


