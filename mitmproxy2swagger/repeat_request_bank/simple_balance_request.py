#!/usr/bin/env python3
"""
简化版银行余额请求脚本
专注于单个HTTPS请求获取活期HKD账户余额
"""

import json
import requests
import urllib3
import re
import time
import os
import base64
from mitmproxy import io, http

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def save_mitm_analysis_to_file(flow):
    """将mitmproxy抓包的原始数据和解密分析保存到文件"""
    timestamp = int(time.time())
    filename = f"/Users/gu/IdeaProjects/reclaim/mitmproxy2swagger/repeat_request_bank/mitm_https_analysis_{timestamp}.json"
    
    # 分析flow对象的详细信息
    mitm_analysis = {
        "timestamp": timestamp,
        "time_human": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp)),
        "flow_info": {
            "flow_id": str(flow.id) if hasattr(flow, 'id') else "N/A",
            "flow_type": str(type(flow)),
            "client_conn": {
                "address": flow.client_conn.address if hasattr(flow, 'client_conn') and hasattr(flow.client_conn, 'address') else "N/A",
                "tls_established": flow.client_conn.tls_established if hasattr(flow, 'client_conn') and hasattr(flow.client_conn, 'tls_established') else False,
                "sni": flow.client_conn.sni if hasattr(flow, 'client_conn') and hasattr(flow.client_conn, 'sni') else "N/A",
                "cipher": flow.client_conn.cipher if hasattr(flow, 'client_conn') and hasattr(flow.client_conn, 'cipher') else "N/A",
                "tls_version": flow.client_conn.tls_version if hasattr(flow, 'client_conn') and hasattr(flow.client_conn, 'tls_version') else "N/A"
            },
            "server_conn": {
                "address": flow.server_conn.address if hasattr(flow, 'server_conn') and hasattr(flow.server_conn, 'address') else "N/A",
                "tls_established": flow.server_conn.tls_established if hasattr(flow, 'server_conn') and hasattr(flow.server_conn, 'tls_established') else False,
                "sni": flow.server_conn.sni if hasattr(flow, 'server_conn') and hasattr(flow.server_conn, 'sni') else "N/A",
                "cipher": flow.server_conn.cipher if hasattr(flow, 'server_conn') and hasattr(flow.server_conn, 'cipher') else "N/A",
                "tls_version": flow.server_conn.tls_version if hasattr(flow, 'server_conn') and hasattr(flow.server_conn, 'tls_version') else "N/A"
            }
        },
        "request_analysis": {
            "url": flow.request.pretty_url,
            "method": flow.request.method,
            "http_version": flow.request.http_version,
            "headers_count": len(flow.request.headers),
            "headers": dict(flow.request.headers),
            "content_length": len(flow.request.content) if flow.request.content else 0,
            "content_raw": base64.b64encode(flow.request.content).decode() if flow.request.content else None,
            "content_text": flow.request.content.decode('utf-8', errors='ignore') if flow.request.content else None,
            "timestamp_start": flow.request.timestamp_start if hasattr(flow.request, 'timestamp_start') else None,
            "timestamp_end": flow.request.timestamp_end if hasattr(flow.request, 'timestamp_end') else None
        },
        "response_analysis": {
            "status_code": flow.response.status_code if flow.response else None,
            "reason": flow.response.reason if flow.response else None,
            "http_version": flow.response.http_version if flow.response else None,
            "headers_count": len(flow.response.headers) if flow.response else 0,
            "headers": dict(flow.response.headers) if flow.response else {},
            "content_length": len(flow.response.content) if flow.response and flow.response.content else 0,
            "content_raw": base64.b64encode(flow.response.content).decode() if flow.response and flow.response.content else None,
            "content_text": flow.response.content.decode('utf-8', errors='ignore') if flow.response and flow.response.content else None,
            "timestamp_start": flow.response.timestamp_start if flow.response and hasattr(flow.response, 'timestamp_start') else None,
            "timestamp_end": flow.response.timestamp_end if flow.response and hasattr(flow.response, 'timestamp_end') else None,
            "content_encoding": flow.response.headers.get('content-encoding', 'none') if flow.response else None
        },
        "https_decryption_info": {
            "description": "mitmproxy作为中间人代理，能够解密HTTPS流量的原理",
            "process": [
                "1. mitmproxy生成自己的CA证书并安装到客户端",
                "2. 客户端发起HTTPS请求时，与mitmproxy建立TLS连接",
                "3. mitmproxy再与目标服务器建立另一个TLS连接",
                "4. mitmproxy解密客户端请求，记录明文数据，然后重新加密发送给服务器",
                "5. 服务器响应经过类似过程：服务器→mitmproxy(解密)→记录→mitmproxy(重新加密)→客户端",
                "6. 这样mitmproxy就能看到完整的明文HTTP请求和响应"
            ],
            "tls_info": {
                "client_cipher": flow.client_conn.cipher if hasattr(flow, 'client_conn') and hasattr(flow.client_conn, 'cipher') else "N/A",
                "server_cipher": flow.server_conn.cipher if hasattr(flow, 'server_conn') and hasattr(flow.server_conn, 'cipher') else "N/A",
                "client_tls_version": flow.client_conn.tls_version if hasattr(flow, 'client_conn') and hasattr(flow.client_conn, 'tls_version') else "N/A",
                "server_tls_version": flow.server_conn.tls_version if hasattr(flow, 'server_conn') and hasattr(flow.server_conn, 'tls_version') else "N/A"
            }
        },
        "content_analysis": {
            "request_is_encrypted_originally": True,
            "response_is_encrypted_originally": True,
            "response_content_encoding": flow.response.headers.get('content-encoding', 'none') if flow.response else None,
            "response_may_be_compressed": flow.response.headers.get('content-encoding') in ['gzip', 'deflate', 'br'] if flow.response else False,
            "decrypted_content_preview": flow.response.text[:500] if flow.response else None
        }
    }
    
    # 保存到文件
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(mitm_analysis, f, indent=2, ensure_ascii=False)
        print(f"📁 HTTPS解密分析已保存到: {filename}")
        
        # 打印关键的HTTPS解密信息
        print(f"🔐 HTTPS解密分析:")
        print(f"   客户端TLS版本: {mitm_analysis['https_decryption_info']['tls_info']['client_tls_version']}")
        print(f"   服务端TLS版本: {mitm_analysis['https_decryption_info']['tls_info']['server_tls_version']}")
        print(f"   客户端加密套件: {mitm_analysis['https_decryption_info']['tls_info']['client_cipher']}")
        print(f"   服务端加密套件: {mitm_analysis['https_decryption_info']['tls_info']['server_cipher']}")
        print(f"   响应内容编码: {mitm_analysis['content_analysis']['response_content_encoding']}")
        print(f"   响应是否压缩: {mitm_analysis['content_analysis']['response_may_be_compressed']}")
        print(f"   解密后内容长度: {mitm_analysis['response_analysis']['content_length']} 字节")
        
        return filename
    except Exception as e:
        print(f"❌ 保存HTTPS分析失败: {e}")
        return None


def get_balance_request_from_mitm(mitm_file_path):
    """从.mitm文件中提取银行余额请求"""
    try:
        with open(mitm_file_path, "rb") as logfile:
            freader = io.FlowReader(logfile)
            for flow in freader.stream():
                if isinstance(flow, http.HTTPFlow):
                    url = flow.request.pretty_url.lower()
                    # 查找招商永隆银行余额API
                    if 'cmbwinglungbank.com' in url and 'nbBkgActdetCoaProc2022'.lower() in url:
                        # 保存HTTPS解密分析
                        save_mitm_analysis_to_file(flow)
                        return flow
        return None
    except Exception as e:
        print(f"❌ 读取文件出错: {e}")
        return None


def flow_to_request_data(flow):
    """提取请求数据"""
    request = flow.request
    
    # 提取headers和cookies
    headers = {}
    cookies_info = {}
    session_id = None
    
    for name, value in request.headers.items():
        if name.lower() not in ['content-length', 'transfer-encoding']:
            headers[name] = value
            
        # 提取Cookie信息
        if name.lower() == 'cookie':
            cookie_pairs = value.split(';')
            for pair in cookie_pairs:
                if '=' in pair:
                    key, val = pair.strip().split('=', 1)
                    cookies_info[key] = val
                    # 寻找session ID
                    if 'session' in key.lower() or key == 'dse_sessionId':
                        session_id = val
    
    # 解析请求体参数
    body_params = {}
    if request.content:
        try:
            body_str = request.content.decode('utf-8')
            if 'dse_sessionId=' in body_str:
                # 解析URL编码的参数
                from urllib.parse import parse_qs
                parsed = parse_qs(body_str)
                for key, values in parsed.items():
                    body_params[key] = values[0] if values else ''
                    if key == 'dse_sessionId':
                        session_id = values[0]
        except:
            pass
    
    return {
        'url': request.pretty_url,
        'method': request.method,
        'headers': headers,
        'cookies': cookies_info,
        'session_id': session_id,
        'body_params': body_params,
        'data': request.content if request.content else None
    }


def extract_hkd_balance(response_text):
    """从响应中提取HKD余额"""
    # 多种HKD余额提取模式
    patterns = [
        r'HKD[^\d]*(\d[\d,]*\.\d{2})',
        r'"(\d[\d,]*\.\d{2})"[^}]*HKD',
        r'港币.*?(\d[\d,]*\.\d{2})',
        r'HK\$.*?(\d[\d,]*\.\d{2})',
        r'balance.*?(\d[\d,]*\.\d{2})',
        r'余额.*?(\d[\d,]*\.\d{2})'
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, response_text, re.IGNORECASE)
        if matches:
            return matches[0]  # 返回第一个匹配的金额
    
    return None


def save_request_details_to_file(req_data, response, balance):
    """将完整的请求详细信息保存到文件中"""
    timestamp = int(time.time())
    filename = f"/Users/gu/IdeaProjects/reclaim/mitmproxy2swagger/repeat_request_bank/bank_request_details_{timestamp}.json"
    
    # 分析响应内容中的余额位置
    balance_analysis = {}
    if response and balance:
        response_text = response.text
        balance_pos = response_text.find(balance)
        if balance_pos >= 0:
            # 提取余额周围的内容 (前后各200字符)
            start_pos = max(0, balance_pos - 200)
            end_pos = min(len(response_text), balance_pos + 200)
            balance_context = response_text[start_pos:end_pos]
            
            balance_analysis = {
                "balance_value": balance,
                "balance_position": balance_pos,
                "balance_context": balance_context,
                "context_start": start_pos,
                "context_end": end_pos,
                "total_response_length": len(response_text)
            }
    
    # 构建完整的请求信息
    request_details = {
        "timestamp": timestamp,
        "time_human": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp)),
        "success": True,
        "balance_found": balance,
        "request": {
            "method": req_data['method'],
            "url": req_data['url'],
            "headers": req_data['headers'],
            "cookies": req_data['cookies'],
            "session_id": req_data['session_id'],
            "body_params": req_data['body_params'],
            "body_raw": req_data['data'].decode('utf-8') if req_data['data'] else None
        },
        "response": {
            "status_code": response.status_code if response else None,
            "headers": dict(response.headers) if response else None,
            "content_length": len(response.text) if response else 0,
            "content_preview": response.text[:500] if response else None,
            "content_full": response.text if response else None,  # 完整响应内容
            "contains_balance": balance is not None
        },
        "balance_analysis": balance_analysis,  # 余额分析信息
        "attestor_config": {
            "provider": "http",
            "params": {
                "url": req_data['url'],
                "method": req_data['method'],
                "geoLocation": "HK",
                "body": req_data['data'].decode('utf-8') if req_data['data'] else "",
                "responseMatches": [
                    {
                        "type": "regex",
                        "value": "HKD[^\\d]*(\\d[\\d,]*\\.\\d{2})"
                    }
                ],
                "responseRedactions": [
                    {
                        "regex": "HKD[^\\d]*(\\d[\\d,]*\\.\\d{2})"
                    }
                ]
            },
            "secretParams": {
                "cookieStr": "; ".join([f"{k}={v}" for k, v in req_data['cookies'].items()]),
                "headers": req_data['headers']
            }
        }
    }
    
    # 保存到文件
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(request_details, f, indent=2, ensure_ascii=False)
        print(f"📁 完整请求详情已保存到: {filename}")
        
        # 额外打印余额分析信息
        if balance_analysis:
            print(f"💰 余额信息分析:")
            print(f"   余额值: {balance_analysis['balance_value']}")
            print(f"   在响应中的位置: {balance_analysis['balance_position']}")
            print(f"   响应总长度: {balance_analysis['total_response_length']}")
            print(f"   余额周围内容:")
            print("   " + "="*60)
            print("   " + balance_analysis['balance_context'].replace('\n', '\n   '))
            print("   " + "="*60)
        
        return filename
    except Exception as e:
        print(f"❌ 保存文件失败: {e}")
        return None


def send_balance_request():
    """发送银行余额请求"""
    mitm_file = "/Users/gu/IdeaProjects/reclaim/mitmproxy2swagger/testdata/flows_with_balance.mitm"
    
    print("🏦 获取活期HKD账户余额")
    print("-" * 40)
    
    # 1. 从.mitm文件提取请求
    print("📂 读取抓包数据...")
    flow = get_balance_request_from_mitm(mitm_file)
    if not flow:
        print("❌ 未找到银行余额请求")
        return None
    
    # 2. 提取请求参数
    req_data = flow_to_request_data(flow)
    print(f"🎯 目标API: {req_data['url'][:80]}...")
    
    # 输出详细的API调用信息
    print("\n" + "="*80)
    print("📋 银行API详细信息 (用于Attestor调用)")
    print("="*80)
    print(f"🌐 完整URL: {req_data['url']}")
    print(f"📤 请求方法: {req_data['method']}")
    print(f"🔑 会话ID: {req_data['session_id']}")
    
    print(f"\n📋 关键请求参数:")
    for key, value in req_data['body_params'].items():
        if key in ['dse_operationName', 'dse_sessionId', 'AcctTypeId', 'RequestType', 'mcp_timestamp']:
            print(f"   {key}: {value}")
    
    print(f"\n🍪 Cookie信息:")
    for key, value in req_data['cookies'].items():
        display_val = value[:20] + "..." if len(value) > 20 else value
        print(f"   {key}: {display_val}")
    
    print(f"\n📤 关键请求头:")
    important_headers = ['User-Agent', 'Accept', 'Content-Type', 'Accept-Language', 'Cache-Control']
    for key, value in req_data['headers'].items():
        if key in important_headers:
            print(f"   {key}: {value}")
    
    print("\n" + "="*80)
    
    # 3. 发送HTTPS请求
    print("🚀 发送请求...")
    response = None
    try:
        response = requests.request(
            method=req_data['method'],
            url=req_data['url'],
            headers=req_data['headers'],
            data=req_data['data'],
            verify=False,
            timeout=30
        )
        
        print(f"📊 响应状态: {response.status_code}")
        print(f"📦 响应长度: {len(response.text)} 字符")
        
        # 4. 提取HKD余额
        hkd_balance = extract_hkd_balance(response.text)
        
        # 5. 保存完整请求详情到文件
        saved_file = save_request_details_to_file(req_data, response, hkd_balance)
        
        if hkd_balance:
            print(f"💰 HKD活期余额: {hkd_balance}")
            
            # 输出Attestor调用所需的关键信息
            print("\n" + "="*80)
            print("🤖 Attestor调用信息总结")
            print("="*80)
            print("✅ 成功验证: 银行API可以正常获取余额数据")
            print(f"✅ 余额数据: HKD {hkd_balance}")
            print(f"✅ 会话ID: {req_data['session_id'][:10]}...{req_data['session_id'][-10:] if req_data['session_id'] else 'N/A'}")
            print("✅ API端点: www.cmbwinglungbank.com/ibanking/McpCSReqServlet")
            print("✅ 操作类型: NbBkgActdetCoaProc2022 (余额查询)")
            print("✅ 账户类型: CON (活期账户)")
            print(f"✅ 详细请求信息已保存到: {os.path.basename(saved_file) if saved_file else 'N/A'}")
            print("="*80)
            
            return {
                'balance': hkd_balance,
                'session_id': req_data['session_id'],
                'api_data': req_data,
                'saved_file': saved_file
            }
        else:
            print("⚠️  未找到HKD余额数据")
            # 保存失败的请求详情
            save_request_details_to_file(req_data, response, None)
            # 打印响应的前500字符用于调试
            print("📝 响应内容预览:")
            print(response.text[:500])
            print("..." if len(response.text) > 500 else "")
            return None
            
    except Exception as e:
        print(f"❌ 请求失败: {e}")
        # 保存失败的请求详情
        save_request_details_to_file(req_data, None, None)
        return None


if __name__ == "__main__":
    result = send_balance_request()
    
    if result and isinstance(result, dict):
        print(f"\n✅ 成功获取余额: HKD {result['balance']}")
        print(f"\n🔗 接下来可以使用以下信息调用Attestor:")
        print(f"   Session ID: {result['session_id']}")
        print(f"   余额验证: HKD {result['balance']}")
        if result.get('saved_file'):
            print(f"   详细配置文件: {result['saved_file']}")
    elif result:
        # 兼容旧版本返回值
        print(f"\n✅ 成功获取余额: HKD {result}")
    else:
        print(f"\n❌ 无法获取余额 (可能session已过期)") 